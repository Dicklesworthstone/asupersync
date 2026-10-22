//! Debug HTTP server for runtime inspection.
//!
//! Provides a lightweight HTTP server that serves a debug dashboard and
//! runtime snapshot data. The server runs in a background thread using
//! `std::net::TcpListener` — no async runtime required.
//!
//! ubs:ignore — synchronous debug server; TcpStreams are short-lived
//! (one request/response cycle) and close-on-drop is acceptable here.
//!
//! # Endpoints
//!
//! - `GET /debug` — HTML dashboard with auto-refresh
//! - `GET /debug/snapshot` — Current runtime snapshot as JSON
//! - `GET /debug/memory-residency` — Memory-residency accounting snapshot as JSON
//! - `GET /debug/trace` — Recent trace events as JSON
//! - `GET /debug/ws` — WebSocket endpoint (upgrade + one-shot JSON push)
//! - `GET /inspector` (also `/debug/inspector`) — Versioned core-model snapshot
//!   when an inspector provider is installed, otherwise JSON `503`
//!
//! Inspector exports default to [`InspectorProfile::Shareable`]. Diagnostic text
//! requires explicit server-side configuration; request parameters cannot enable
//! it. Responses are not cacheable, and serialized inspector bodies are limited
//! to 16 MiB by default. This limit bounds serialized bytes, not the runtime state
//! captured by a provider. The existing connection cap and socket timeouts apply.
//! The default listener is loopback-only; this development server provides no
//! authentication or TLS when configured to bind to other interfaces.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::web::debug::{DebugServer, DebugServerConfig};
//! use asupersync::runtime::RuntimeSnapshot;
//! use parking_lot::Mutex;
//! use std::sync::Arc;
//!
//! let state = Arc::new(Mutex::new(runtime_state));
//! let st = Arc::clone(&state);
//! let mut server = DebugServer::new(
//!     9999,
//!     Arc::new(move || st.lock().snapshot()),
//! );
//! server.start().expect("failed to start debug server");
//! println!("Dashboard: {}", server.url());
//! ```
//!
//! To expose a live native runtime, including its external task and obligation
//! tables, add `.with_runtime_inspector(runtime.handle())` before `start()`.
//! Custom or lab-state providers can use [`DebugServer::with_inspector_snapshot_fn`].

use std::io::{BufRead, BufReader, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;

use crate::observability::{InspectorProfile, InspectorSnapshot, TaskInspectorConfig};
use crate::runtime::{MemoryResidencyAccountingSnapshot, RuntimeHandle, RuntimeSnapshot};
use crate::tracing_compat::info;
use base64::Engine as _;
use sha1::{Digest, Sha1};

/// Function that produces a runtime snapshot on demand.
pub type SnapshotFn = Arc<dyn Fn() -> RuntimeSnapshot + Send + Sync>;

/// Function that produces a memory-residency accounting snapshot on demand.
pub type MemoryResidencySnapshotFn =
    Arc<dyn Fn() -> MemoryResidencyAccountingSnapshot + Send + Sync>;

/// Captures a versioned inspector snapshot with the requested text policy.
///
/// Return `None` if the source is unavailable. Capture runs on a connection
/// thread; it must finish promptly and must not drive or wait for runtime work.
/// The server applies shareable scrubbing again before serialization, even if a
/// provider returns a full snapshot or labels diagnostic text as shareable.
pub type InspectorSnapshotFn =
    Arc<dyn Fn(InspectorProfile) -> Option<InspectorSnapshot> + Send + Sync>;

/// Default upper bound on a serialized inspector response body (16 MiB).
pub const DEFAULT_INSPECTOR_MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone)]
struct InspectorEndpoint {
    snapshot_fn: Option<InspectorSnapshotFn>,
    profile: InspectorProfile,
    max_response_bytes: usize,
}

impl Default for InspectorEndpoint {
    fn default() -> Self {
        Self {
            snapshot_fn: None,
            profile: InspectorProfile::Shareable,
            max_response_bytes: DEFAULT_INSPECTOR_MAX_RESPONSE_BYTES,
        }
    }
}

/// Configuration for the debug server.
#[derive(Debug, Clone)]
pub struct DebugServerConfig {
    /// Whether to print the URL on startup.
    pub print_url: bool,
    /// Bind address (default: `127.0.0.1`).
    pub bind_addr: String,
    /// Auto-refresh interval for the dashboard in seconds.
    pub refresh_interval_secs: u32,
    /// Maximum number of concurrent connections.
    pub max_connections: usize,
}

impl Default for DebugServerConfig {
    fn default() -> Self {
        Self {
            print_url: true,
            bind_addr: "127.0.0.1".to_string(),
            refresh_interval_secs: 2,
            max_connections: 16,
        }
    }
}

/// Debug HTTP server handle.
///
/// Serves a debug dashboard and JSON endpoints for runtime inspection.
/// The server runs in a background thread and stops when this handle
/// is dropped.
pub struct DebugServer {
    port: u16,
    snapshot_fn: SnapshotFn,
    memory_residency_snapshot_fn: MemoryResidencySnapshotFn,
    inspector: InspectorEndpoint,
    config: DebugServerConfig,
    running: Arc<AtomicBool>,
    local_addr: Option<SocketAddr>,
}

impl DebugServer {
    /// Creates a new debug server on the given port.
    #[must_use]
    pub fn new(port: u16, snapshot_fn: SnapshotFn) -> Self {
        Self {
            port,
            snapshot_fn,
            memory_residency_snapshot_fn: Self::default_memory_residency_snapshot_fn(),
            inspector: InspectorEndpoint::default(),
            config: DebugServerConfig::default(),
            running: Arc::new(AtomicBool::new(false)),
            local_addr: None,
        }
    }

    /// Creates a new debug server with custom configuration.
    #[must_use]
    pub fn with_config(port: u16, snapshot_fn: SnapshotFn, config: DebugServerConfig) -> Self {
        Self {
            port,
            snapshot_fn,
            memory_residency_snapshot_fn: Self::default_memory_residency_snapshot_fn(),
            inspector: InspectorEndpoint::default(),
            config,
            running: Arc::new(AtomicBool::new(false)),
            local_addr: None,
        }
    }

    /// Installs an additive memory-residency snapshot provider.
    #[must_use]
    pub fn with_memory_residency_snapshot_fn(
        mut self,
        snapshot_fn: MemoryResidencySnapshotFn,
    ) -> Self {
        self.memory_residency_snapshot_fn = snapshot_fn;
        self
    }

    /// Installs the provider for `GET /inspector` and `GET /debug/inspector`.
    ///
    /// With no provider, or when it returns `None`, these routes return JSON
    /// `503 Service Unavailable`. Existing dashboard routes keep their providers.
    #[must_use]
    pub fn with_inspector_snapshot_fn(mut self, snapshot_fn: InspectorSnapshotFn) -> Self {
        self.inspector.snapshot_fn = Some(snapshot_fn);
        self
    }

    /// Binds inspector requests to a native runtime's live record tables.
    ///
    /// Each request acquires the runtime's state, task, and obligation tables
    /// through [`RuntimeHandle::task_inspector`] in their canonical lock order.
    /// The owned snapshot is serialized only after those locks are released.
    /// The supplied handle retains its ordinary strong or weak lifetime semantics.
    #[must_use]
    pub fn with_runtime_inspector(self, runtime: RuntimeHandle) -> Self {
        self.with_inspector_snapshot_fn(Arc::new(move |profile| {
            runtime
                .task_inspector(TaskInspectorConfig::default())
                .map(|inspector| inspector.runtime_snapshot(profile))
        }))
    }

    /// Sets the inspector text policy at server setup time.
    ///
    /// The default is [`InspectorProfile::Shareable`]. Choosing
    /// [`InspectorProfile::Full`] permits descriptions, source locations, and
    /// checkpoint messages in HTTP responses. Query parameters never change the
    /// policy. A provider may still return a more restrictive snapshot.
    #[must_use]
    pub fn with_inspector_profile(mut self, profile: InspectorProfile) -> Self {
        self.inspector.profile = profile;
        self
    }

    /// Bounds the serialized inspector body, without truncating its schema.
    ///
    /// Oversized snapshots return JSON `503` instead of partial snapshot data.
    /// The default is [`DEFAULT_INSPECTOR_MAX_RESPONSE_BYTES`]. A zero limit
    /// rejects every snapshot. This does not limit provider capture allocations.
    #[must_use]
    pub fn with_inspector_max_response_bytes(mut self, max_bytes: usize) -> Self {
        self.inspector.max_response_bytes = max_bytes;
        self
    }

    fn default_memory_residency_snapshot_fn() -> MemoryResidencySnapshotFn {
        Arc::new(|| MemoryResidencyAccountingSnapshot::unavailable(0))
    }

    /// Returns the dashboard URL.
    #[must_use]
    pub fn url(&self) -> String {
        let addr = self.local_addr.map_or_else(
            || format!("{}:{}", self.config.bind_addr, self.port),
            |a| a.to_string(),
        );
        format!(
            "http://{addr}/debug?refresh={}",
            self.config.refresh_interval_secs.saturating_mul(1000)
        )
    }

    /// Returns whether the server is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Returns the bound local address after the server starts.
    #[must_use]
    pub const fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Starts the debug server in a background thread.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP listener cannot bind.
    pub fn start(&mut self) -> std::io::Result<()> {
        let bind = format!("{}:{}", self.config.bind_addr, self.port);
        let listener = TcpListener::bind(&bind)?;
        listener.set_nonblocking(true)?;

        let local_addr = listener.local_addr()?;
        self.local_addr = Some(local_addr);
        self.running.store(true, Ordering::Relaxed);

        if self.config.print_url {
            info!(url = %self.url(), "debug dashboard started");
        }

        let snapshot_fn = Arc::clone(&self.snapshot_fn);
        let memory_residency_snapshot_fn = Arc::clone(&self.memory_residency_snapshot_fn);
        let inspector = self.inspector.clone();
        let running = Arc::clone(&self.running);
        let active_connections = Arc::new(AtomicUsize::new(0));
        let max_connections = self.config.max_connections;

        thread::Builder::new()
            .name("asupersync-debug-server".to_string())
            .spawn(move || {
                serve_loop(
                    &listener,
                    &snapshot_fn,
                    &memory_residency_snapshot_fn,
                    &inspector,
                    &running,
                    max_connections,
                    &active_connections,
                );
            })?;

        Ok(())
    }

    /// Stops the debug server.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

impl Drop for DebugServer {
    fn drop(&mut self) {
        self.stop();
    }
}

// =========================================================================
// HTTP server loop
// =========================================================================

fn serve_loop(
    listener: &TcpListener,
    snapshot_fn: &SnapshotFn,
    memory_residency_snapshot_fn: &MemoryResidencySnapshotFn,
    inspector: &InspectorEndpoint,
    running: &AtomicBool,
    max_connections: usize,
    active_connections: &Arc<AtomicUsize>,
) {
    while running.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _peer)) => {
                // BSD/macOS inherit O_NONBLOCK from the listener on accepted
                // sockets (Linux does not). Without clearing it, the handler's
                // first read returns WouldBlock instantly, the connection is
                // torn down before its guard can hold a slot, and the
                // max_connections limiter never trips. Restore blocking mode;
                // the timeouts below bound each phase instead.
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));

                // Atomically increment-then-check to prevent TOCTOU race
                // where multiple threads pass the limit check simultaneously.
                let prev = active_connections.fetch_add(1, Ordering::Relaxed);
                if prev >= max_connections {
                    active_connections.fetch_sub(1, Ordering::Relaxed);
                    let _ = write_response(&mut stream, 503, "text/plain", b"Debug server busy");
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }

                let snapshot_fn = Arc::clone(snapshot_fn);
                let memory_residency_snapshot_fn = Arc::clone(memory_residency_snapshot_fn);
                let inspector = inspector.clone();
                let active_connections_for_thread = Arc::clone(active_connections);
                let _ = thread::Builder::new()
                    .name("asupersync-debug-connection".to_string())
                    .spawn(move || {
                        let _active_connection =
                            ActiveConnectionGuard::new(Arc::clone(&active_connections_for_thread));
                        let _ = panic::catch_unwind(AssertUnwindSafe(|| {
                            handle_connection(
                                stream,
                                &snapshot_fn,
                                &memory_residency_snapshot_fn,
                                &inspector,
                            );
                        }));
                    })
                    .map(crate::runtime::spawn_blocking::reap_spawned_thread)
                    .map_err(|_| active_connections.fetch_sub(1, Ordering::Relaxed));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Nonblocking accept lets stop() terminate promptly even with no traffic.
                thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                thread::sleep(std::time::Duration::from_millis(25));
            }
        }
    }
}

struct ActiveConnectionGuard {
    active_connections: Arc<AtomicUsize>,
}

impl ActiveConnectionGuard {
    fn new(active_connections: Arc<AtomicUsize>) -> Self {
        Self { active_connections }
    }
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

fn handle_connection(
    mut stream: TcpStream,
    snapshot_fn: &SnapshotFn,
    memory_residency_snapshot_fn: &MemoryResidencySnapshotFn,
    inspector: &InspectorEndpoint,
) {
    let mut reader = if let Ok(read_half) = stream.try_clone() {
        BufReader::new(read_half)
    } else {
        let _ = stream.shutdown(Shutdown::Both);
        return;
    };
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        let _ = stream.shutdown(Shutdown::Both);
        return;
    }

    // Parse method and path from the request line.
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        let _ = stream.shutdown(Shutdown::Both);
        return;
    }
    let method = parts[0];
    let request_target = parts[1];
    let path = request_target
        .split_once('?')
        .map_or(request_target, |(path, _query)| path);
    let headers = read_headers(&mut reader);

    // Only handle GET requests.
    if method != "GET" {
        let _ = write_response(&mut stream, 405, "text/plain", b"Method Not Allowed");
        let _ = stream.shutdown(Shutdown::Both);
        return;
    }

    match path {
        "/inspector" | "/debug/inspector" => {
            handle_inspector_request(&mut stream, inspector);
        }
        "/debug" | "/debug/" => {
            let _ = write_response(
                &mut stream,
                200,
                "text/html; charset=utf-8",
                DASHBOARD_HTML.as_bytes(),
            );
        }
        "/debug/snapshot" => {
            let snapshot = snapshot_fn();
            match serde_json::to_string_pretty(&snapshot) {
                Ok(json) => {
                    let _ = write_response(&mut stream, 200, "application/json", json.as_bytes());
                }
                Err(e) => {
                    let body = format!("{{\"error\":\"{e}\"}}");
                    let _ = write_response(&mut stream, 500, "application/json", body.as_bytes());
                }
            }
        }
        "/debug/memory-residency" => {
            let snapshot = memory_residency_snapshot_fn();
            match serde_json::to_string_pretty(&snapshot) {
                Ok(json) => {
                    let _ = write_response(&mut stream, 200, "application/json", json.as_bytes());
                }
                Err(e) => {
                    let body = format!("{{\"error\":\"{e}\"}}");
                    let _ = write_response(&mut stream, 500, "application/json", body.as_bytes());
                }
            }
        }
        "/debug/trace" => {
            let snapshot = snapshot_fn();
            match serde_json::to_string_pretty(&snapshot.recent_events) {
                Ok(json) => {
                    let _ = write_response(&mut stream, 200, "application/json", json.as_bytes());
                }
                Err(e) => {
                    let body = format!("{{\"error\":\"{e}\"}}");
                    let _ = write_response(&mut stream, 500, "application/json", body.as_bytes());
                }
            }
        }
        "/debug/ws" => {
            if let Err(err) = handle_websocket(&mut stream, &headers, snapshot_fn) {
                let body = format!("{{\"error\":\"websocket upgrade failed: {err}\"}}");
                let _ = write_response(&mut stream, 400, "application/json", body.as_bytes());
            }
        }
        _ => {
            let _ = write_response(&mut stream, 404, "text/plain", b"Not Found");
        }
    }

    let _ = stream.shutdown(Shutdown::Both);
}

fn handle_inspector_request(stream: &mut TcpStream, inspector: &InspectorEndpoint) {
    let Some(snapshot_fn) = &inspector.snapshot_fn else {
        let _ = write_inspector_response(stream, 503, br#"{"error":"inspector_unavailable"}"#);
        return;
    };
    let snapshot = match panic::catch_unwind(AssertUnwindSafe(|| snapshot_fn(inspector.profile))) {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => {
            let _ = write_inspector_response(stream, 503, br#"{"error":"inspector_unavailable"}"#);
            return;
        }
        Err(payload) => {
            // A custom panic payload can itself panic on drop. Do not let it
            // prevent the error response or the connection slot's release.
            std::mem::forget(payload);
            let _ =
                write_inspector_response(stream, 500, br#"{"error":"inspector_capture_failed"}"#);
            return;
        }
    };
    let snapshot = if inspector.profile == InspectorProfile::Shareable {
        snapshot.into_shareable()
    } else {
        snapshot
    };
    let mut body = InspectorJsonBuffer {
        bytes: Vec::new(),
        max_bytes: inspector.max_response_bytes,
        limit_exceeded: false,
    };
    // Serialize before sending headers so a limit failure cannot produce a
    // successful HTTP response containing truncated JSON.
    match serde_json::to_writer(&mut body, &snapshot) {
        Ok(()) => {
            let _ = write_inspector_response(stream, 200, &body.bytes);
        }
        Err(_) if body.limit_exceeded => {
            let _ = write_inspector_response(
                stream,
                503,
                br#"{"error":"inspector_response_too_large"}"#,
            );
        }
        Err(_) => {
            let _ = write_inspector_response(
                stream,
                500,
                br#"{"error":"inspector_serialization_failed"}"#,
            );
        }
    }
}

struct InspectorJsonBuffer {
    bytes: Vec<u8>,
    max_bytes: usize,
    limit_exceeded: bool,
}

impl Write for InspectorJsonBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.max_bytes.saturating_sub(self.bytes.len()) {
            self.limit_exceeded = true;
            return Err(std::io::Error::other(
                "inspector response exceeds byte limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn write_inspector_response(
    stream: &mut TcpStream,
    status: u16,
    body: &[u8],
) -> std::io::Result<()> {
    write_response_with_headers(
        stream,
        status,
        "application/json",
        body,
        "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n",
    )
}

fn read_headers<R: BufRead>(reader: &mut R) -> Vec<(String, String)> {
    let mut headers = Vec::with_capacity(16);
    let mut total_bytes = 0;
    loop {
        if headers.len() >= 64 {
            break;
        }
        let mut line = String::new();
        // Use a generic limit by borrowing the reader by reference into take,
        // but take() consumes the reference. Instead we just check the line length.
        // It's a local debug server, but we should at least bound it.
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                total_bytes += n;
                if total_bytes > 65536 {
                    break;
                }
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if trimmed.is_empty() {
                    break;
                }
                if let Some((key, value)) = trimmed.split_once(':') {
                    headers.push((key.trim().to_ascii_lowercase(), value.trim().to_string()));
                }
            }
        }
    }
    headers
}

fn header_value<'a>(headers: &'a [(String, String)], key: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn websocket_accept_key(client_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(client_key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let digest = hasher.finalize();
    base64::engine::general_purpose::STANDARD.encode(digest)
}

fn write_ws_text_frame(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    let len = payload.len();
    let mut header = [0u8; 10];
    header[0] = 0x81; // FIN + text

    let header_len = if len < 126 {
        header[1] = len as u8;
        2
    } else if u16::try_from(len).is_ok() {
        header[1] = 126;
        header[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        4
    } else {
        header[1] = 127;
        header[2..10].copy_from_slice(&(len as u64).to_be_bytes());
        10
    };

    stream.write_all(&header[..header_len])?;
    stream.write_all(payload)?;
    Ok(())
}

fn handle_websocket(
    stream: &mut TcpStream,
    headers: &[(String, String)],
    snapshot_fn: &SnapshotFn,
) -> std::io::Result<()> {
    let upgrade = header_value(headers, "upgrade").unwrap_or_default();
    let connection = header_value(headers, "connection").unwrap_or_default();
    let key = header_value(headers, "sec-websocket-key")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing key"))?;
    let version = header_value(headers, "sec-websocket-version").unwrap_or_default();

    if !upgrade.eq_ignore_ascii_case("websocket")
        || !connection
            .split(',')
            .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "missing websocket upgrade headers",
        ));
    }
    if version != "13" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unsupported websocket version",
        ));
    }
    // A browser sends Origin on every WebSocket upgrade and enforces no
    // same-origin policy on the result. Only the dashboard this server
    // serves may read the runtime snapshot; a page on any other origin
    // could otherwise reach it over loopback.
    if let Some(origin) = header_value(headers, "origin") {
        let host = header_value(headers, "host").unwrap_or_default();
        let same_origin = origin
            .trim()
            .strip_prefix("http://")
            .is_some_and(|authority| authority.eq_ignore_ascii_case(host.trim()));
        if !same_origin {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "cross-origin websocket upgrade refused",
            ));
        }
    }

    let accept = websocket_accept_key(key.trim());
    write!(
        stream,
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\
         \r\n"
    )?;

    let snapshot = snapshot_fn();
    let payload = serde_json::to_vec(&snapshot).map_err(std::io::Error::other)?;
    write_ws_text_frame(stream, &payload)?;
    // Normal closure after one push keeps this debug endpoint lightweight.
    stream.write_all(&[0x88, 0x00])?;
    stream.flush()
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    write_response_with_headers(stream, status, content_type, body, "")
}

fn write_response_with_headers(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    extra_headers: &str,
) -> std::io::Result<()> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        501 => "Not Implemented",
        _ => "Unknown",
    };

    write!(
        stream,
        "HTTP/1.1 {status} {status_text}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         {extra_headers}Connection: close\r\n\
         \r\n",
        body.len(),
    )?;
    stream.write_all(body)?;
    stream.flush()
}

// =========================================================================
// Dashboard HTML — loaded from assets/dashboard.html at compile time.
// The HTML is self-contained (CSS/JS inlined, no external deps) and handles
// both live mode (polling /debug/snapshot) and file mode (post-mortem).
// Refresh interval is configured via ?refresh=<ms> URL parameter.
// =========================================================================

const DASHBOARD_HTML: &str = include_str!("../../assets/dashboard.html");

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
#[path = "debug_inline_tests.rs"]
mod tests;
