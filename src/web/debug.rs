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
//! - `GET /debug/trace` — Recent trace events as JSON
//! - `GET /debug/ws` — WebSocket endpoint (upgrade + one-shot JSON push)
//!
//! # Example
//!
//! ```ignore
//! use asupersync::web::debug::{DebugServer, DebugServerConfig};
//! use asupersync::runtime::RuntimeSnapshot;
//! use std::sync::{Arc, Mutex};
//!
//! let state = Arc::new(Mutex::new(runtime_state));
//! let st = Arc::clone(&state);
//! let server = DebugServer::new(
//!     9999,
//!     Arc::new(move || st.lock().unwrap().snapshot()),
//! );
//! server.start().expect("failed to start debug server");
//! println!("Dashboard: {}", server.url());
//! ```

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use crate::runtime::RuntimeSnapshot;
use crate::tracing_compat::info;
use base64::Engine as _;
use sha1::{Digest, Sha1};

/// Function that produces a runtime snapshot on demand.
pub type SnapshotFn = Arc<dyn Fn() -> RuntimeSnapshot + Send + Sync>;

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
            config,
            running: Arc::new(AtomicBool::new(false)),
            local_addr: None,
        }
    }

    /// Returns the dashboard URL.
    #[must_use]
    pub fn url(&self) -> String {
        let addr = self.local_addr.map_or_else(
            || format!("{}:{}", self.config.bind_addr, self.port),
            |a| a.to_string(),
        );
        format!("http://{addr}/debug")
    }

    /// Returns whether the server is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
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
            info!(
                url = %format!("http://{local_addr}/debug"),
                "debug dashboard started"
            );
        }

        let snapshot_fn = Arc::clone(&self.snapshot_fn);
        let running = Arc::clone(&self.running);

        thread::Builder::new()
            .name("asupersync-debug-server".to_string())
            .spawn(move || {
                serve_loop(&listener, &snapshot_fn, &running);
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

fn serve_loop(listener: &TcpListener, snapshot_fn: &SnapshotFn, running: &AtomicBool) {
    while running.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
                handle_connection(stream, snapshot_fn);
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

fn handle_connection(mut stream: TcpStream, snapshot_fn: &SnapshotFn) {
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }

    // Parse method and path from the request line.
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0];
    let path = parts[1];
    let headers = read_headers(&mut reader);

    // Only handle GET requests.
    if method != "GET" {
        let _ = write_response(&mut stream, 405, "text/plain", b"Method Not Allowed");
        return;
    }

    match path {
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
}

fn read_headers(reader: &mut BufReader<&TcpStream>) -> Vec<(String, String)> {
    let mut headers = Vec::with_capacity(16);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
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
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        _ => "Unknown",
    };

    write!(
        stream,
        "HTTP/1.1 {status} {status_text}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Access-Control-Allow-Origin: *\r\n\
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
mod tests {
    use super::*;
    use std::io::Read;

    fn test_snapshot() -> RuntimeSnapshot {
        RuntimeSnapshot {
            timestamp: 12345,
            regions: vec![],
            tasks: vec![],
            obligations: vec![],
            recent_events: vec![],
        }
    }

    #[test]
    fn server_starts_and_serves_snapshot() {
        let snapshot_fn: SnapshotFn = Arc::new(test_snapshot);
        let mut server = DebugServer::with_config(
            0, // OS-assigned port
            snapshot_fn,
            DebugServerConfig {
                print_url: false,
                ..Default::default()
            },
        );
        server.start().expect("server should start");
        assert!(server.is_running());

        let url = server.url();
        assert!(url.contains("/debug"));

        // Fetch snapshot endpoint.
        let addr = server.local_addr.unwrap();
        let mut stream = TcpStream::connect(addr).unwrap();
        write!(
            stream,
            "GET /debug/snapshot HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();
        stream.flush().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(&stream);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => response.push_str(&line),
            }
        }

        assert!(response.contains("200 OK"));
        // serde_json pretty-printing adds spaces: "timestamp": 12345
        assert!(response.contains("12345"));
        assert!(response.contains("timestamp"));

        server.stop();
    }

    #[test]
    fn server_serves_dashboard_html() {
        let snapshot_fn: SnapshotFn = Arc::new(test_snapshot);
        let mut server = DebugServer::with_config(
            0,
            snapshot_fn,
            DebugServerConfig {
                print_url: false,
                ..Default::default()
            },
        );
        server.start().unwrap();

        let addr = server.local_addr.unwrap();
        let mut stream = TcpStream::connect(addr).unwrap();
        write!(stream, "GET /debug HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        stream.flush().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(&stream);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => response.push_str(&line),
            }
        }

        assert!(response.contains("200 OK"));
        assert!(response.contains("Asupersync Debug Dashboard"));

        server.stop();
    }

    #[test]
    fn server_returns_404_for_unknown_path() {
        let snapshot_fn: SnapshotFn = Arc::new(test_snapshot);
        let mut server = DebugServer::with_config(
            0,
            snapshot_fn,
            DebugServerConfig {
                print_url: false,
                ..Default::default()
            },
        );
        server.start().unwrap();

        let addr = server.local_addr.unwrap();
        let mut stream = TcpStream::connect(addr).unwrap();
        write!(
            stream,
            "GET /nonexistent HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();
        stream.flush().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(&stream);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => response.push_str(&line),
            }
        }

        assert!(response.contains("404"));

        server.stop();
    }

    #[test]
    fn server_returns_trace_json() {
        let snapshot_fn: SnapshotFn = Arc::new(test_snapshot);
        let mut server = DebugServer::with_config(
            0,
            snapshot_fn,
            DebugServerConfig {
                print_url: false,
                ..Default::default()
            },
        );
        server.start().unwrap();

        let addr = server.local_addr.unwrap();
        let mut stream = TcpStream::connect(addr).unwrap();
        write!(
            stream,
            "GET /debug/trace HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();
        stream.flush().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(&stream);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => response.push_str(&line),
            }
        }

        assert!(response.contains("200 OK"));
        assert!(response.contains("[]")); // empty events list

        server.stop();
    }

    #[test]
    fn websocket_upgrade_and_frame_push() {
        let snapshot_fn: SnapshotFn = Arc::new(test_snapshot);
        let mut server = DebugServer::with_config(
            0,
            snapshot_fn,
            DebugServerConfig {
                print_url: false,
                ..Default::default()
            },
        );
        server.start().unwrap();

        let addr = server.local_addr.unwrap();
        let mut stream = TcpStream::connect(addr).unwrap();
        write!(
            stream,
            "GET /debug/ws HTTP/1.1\r\n\
             Host: localhost\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n"
        )
        .unwrap();
        stream.flush().unwrap();

        let mut buf = Vec::new();
        let n = stream.read_to_end(&mut buf).unwrap();
        let resp = &buf[..n];
        let text = String::from_utf8_lossy(resp);
        assert!(text.contains("101 Switching Protocols"), "response: {text}");
        assert!(text.contains("Sec-WebSocket-Accept"), "response: {text}");
        let header_end = resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("websocket header terminator should exist");
        assert!(
            n > header_end + 4 + 2,
            "expected frame bytes after websocket upgrade"
        );

        server.stop();
    }

    #[test]
    fn stop_eventually_closes_listener() {
        let snapshot_fn: SnapshotFn = Arc::new(test_snapshot);
        let mut server = DebugServer::with_config(
            0,
            snapshot_fn,
            DebugServerConfig {
                print_url: false,
                ..Default::default()
            },
        );
        server.start().unwrap();

        let addr = server.local_addr.unwrap();
        server.stop();

        let mut listener_closed = false;
        for _ in 0..20 {
            if TcpStream::connect(addr).is_err() {
                listener_closed = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }

        assert!(
            listener_closed,
            "listener should close shortly after stop()"
        );
    }

    #[test]
    fn default_config_values() {
        let config = DebugServerConfig::default();
        assert!(config.print_url);
        assert_eq!(config.bind_addr, "127.0.0.1");
        assert_eq!(config.refresh_interval_secs, 2);
        assert_eq!(config.max_connections, 16);
    }

    #[test]
    fn dashboard_html_content() {
        assert!(DASHBOARD_HTML.contains("Asupersync Debug Dashboard"));
        assert!(DASHBOARD_HTML.contains("/debug/snapshot"));
        assert!(DASHBOARD_HTML.contains("CONFIG"));
    }

    #[test]
    fn debug_server_config_debug_clone() {
        let c = DebugServerConfig::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("DebugServerConfig"));
        assert!(dbg.contains("127.0.0.1"));

        let c2 = c;
        assert_eq!(c2.bind_addr, "127.0.0.1");
        assert_eq!(c2.max_connections, 16);
        assert_eq!(c2.refresh_interval_secs, 2);
        assert!(c2.print_url);
    }
}
