//! gRPC server implementation.
//!
//! Provides the server-side infrastructure for hosting gRPC services.

use parking_lot::{Mutex, RwLock};
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
#[cfg(not(target_arch = "wasm32"))]
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::bytes::Bytes;
#[cfg(not(target_arch = "wasm32"))]
use crate::bytes::BytesMut;
use crate::cx::{Cx, cap};
#[cfg(not(target_arch = "wasm32"))]
use crate::http::h1::server::HostPolicy;
#[cfg(not(target_arch = "wasm32"))]
use crate::http::h1::types::{Request as HttpRequest, Response as HttpResponse};
#[cfg(not(target_arch = "wasm32"))]
use crate::http::h2::listener::{Http2Listener, Http2ListenerConfig};
#[cfg(not(target_arch = "wasm32"))]
use crate::http::h2::settings::Settings;
#[cfg(not(target_arch = "wasm32"))]
use crate::runtime::RuntimeHandle;
#[cfg(not(target_arch = "wasm32"))]
use crate::server::shutdown::ShutdownStats;
#[cfg(not(target_arch = "wasm32"))]
use base64::Engine as _;

use super::client::CompressionEncoding;
pub use super::codec::RequestBodyMeter;
use super::codec::{Codec, FramedCodec};
use super::reflection::ReflectionService;
use super::service::{NamedService, ServiceHandler};
use super::status::{GrpcError, Status, TransportErrorKind};
use super::streaming::{Metadata, Request, Response};

fn wall_clock_instant_now() -> Instant {
    Instant::now()
}

/// Poll `future` with the caller-provided capability context installed.
///
/// A guard held across `.await` would be tied to the constructing thread and
/// become incorrect after work stealing. Installing it for each individual
/// poll keeps explicit capability restrictions and cancellation authoritative
/// on whichever worker is driving the request.
async fn poll_with_current_cx<F: Future>(cx: Cx, future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|task_cx| {
        let _guard = Cx::set_current(Some(cx.clone()));
        future.as_mut().poll(task_cx)
    })
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InclusiveDeadlineElapsed;

/// Poll `future` only while `now()` is strictly before `deadline`.
///
/// The runtime's general timeout combinator deliberately lets ready work win
/// at its exact boundary. gRPC uses the stricter `now >= deadline` contract,
/// so dispatch wraps handlers with this per-poll guard instead of changing the
/// crate-wide timeout policy.
async fn poll_before_inclusive_deadline<F: Future>(
    future: F,
    deadline: crate::types::Time,
    now: fn() -> crate::types::Time,
) -> Result<F::Output, InclusiveDeadlineElapsed> {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|task_cx| {
        if now() >= deadline {
            std::task::Poll::Ready(Err(InclusiveDeadlineElapsed))
        } else {
            future.as_mut().poll(task_cx).map(Ok)
        }
    })
    .await
}

/// Lazily invoke `handler`, then enforce the inclusive deadline while polling
/// its returned future.
///
/// Because this is an `async fn`, neither the handler closure nor its future is
/// touched until the wrapper itself is polled. The first check therefore gates
/// synchronous `FnOnce` setup; the nested guard checks again after setup and
/// before every poll of the returned future.
async fn invoke_and_poll_before_inclusive_deadline<H, A, F>(
    handler: H,
    argument: A,
    deadline: crate::types::Time,
    now: fn() -> crate::types::Time,
) -> Result<F::Output, InclusiveDeadlineElapsed>
where
    H: FnOnce(A) -> F,
    F: Future,
{
    if now() >= deadline {
        return Err(InclusiveDeadlineElapsed);
    }
    let future = handler(argument);
    poll_before_inclusive_deadline(future, deadline, now).await
}

/// Tracks a stream registration's last recorded activity timestamp.
#[derive(Debug, Clone)]
struct StreamState {
    /// Last activity timestamp (when the stream last sent data).
    last_activity: Instant,
    /// Registration timestamp (when the stream was first registered).
    /// Used to prevent race conditions in cleanup operations.
    registered_at: Instant,
}

/// br-asupersync-8vn9iu: Per-connection registration accounting.
///
/// The helper enforces an in-memory stream-count limit and can discard stale
/// accounting entries when explicitly invoked. Discarding an entry does not
/// itself cancel or close the corresponding transport stream or handler.
///
/// br-asupersync-tnvxx3: Uses internal Mutex for thread-safe access to
/// active_streams, allowing concurrent operations from ConnectionRegistry.
#[derive(Debug)]
pub struct ConnectionState {
    /// Stream-registration entries keyed by stream ID. The legacy field name
    /// does not imply transport liveness; stale entries remain until purged.
    /// Protected by Mutex to allow thread-safe concurrent access.
    active_streams: Mutex<HashMap<u32, StreamState>>,
}

impl ConnectionState {
    /// Create new connection state.
    pub fn new() -> Self {
        Self {
            active_streams: Mutex::new(HashMap::new()),
        }
    }

    /// Register a new stream on this connection.
    ///
    /// Returns `Err` if the connection already has too many registration entries.
    /// Returns the registration timestamp on success for race condition protection.
    /// br-asupersync-tnvxx3: Thread-safe method using internal Mutex.
    pub fn add_stream(&self, stream_id: u32, max_concurrent: u32) -> Result<Instant, String> {
        let mut active_streams = self.active_streams.lock();
        if active_streams.len() >= max_concurrent as usize {
            return Err(format!(
                "connection exceeds max_concurrent_streams: {} >= {}",
                active_streams.len(),
                max_concurrent
            ));
        }

        let now = wall_clock_instant_now();
        active_streams.insert(
            stream_id,
            StreamState {
                last_activity: now,
                registered_at: now,
            },
        );
        Ok(now)
    }

    /// Update the last activity time for a stream.
    /// br-asupersync-tnvxx3: Thread-safe method using internal Mutex.
    pub fn update_stream_activity(&self, stream_id: u32) {
        let mut active_streams = self.active_streams.lock();
        if let Some(stream) = active_streams.get_mut(&stream_id) {
            stream.last_activity = wall_clock_instant_now();
        }
    }

    /// Remove a stream from this connection (when it completes normally).
    /// br-asupersync-tnvxx3: Thread-safe method using internal Mutex.
    pub fn remove_stream(&self, stream_id: u32) {
        let mut active_streams = self.active_streams.lock();
        active_streams.remove(&stream_id);
    }

    /// Remove registration entries whose activity timestamp is older than the
    /// supplied threshold.
    ///
    /// Returns the stream IDs removed from this accounting map. This helper
    /// does not signal or cancel the associated transport streams.
    /// br-asupersync-tnvxx3: Thread-safe method using internal Mutex.
    pub fn cleanup_idle_streams(&self, idle_timeout: Duration) -> Vec<u32> {
        let now = wall_clock_instant_now();
        let mut removed = Vec::new();

        let mut active_streams = self.active_streams.lock();
        active_streams.retain(|&stream_id, stream| {
            let idle_duration = now.duration_since(stream.last_activity);
            if idle_duration > idle_timeout {
                removed.push(stream_id);
                false
            } else {
                true
            }
        });

        removed
    }

    /// Get the number of registration entries currently in the map.
    /// Entries remain until explicit removal or a later stale-entry purge.
    /// br-asupersync-tnvxx3: Thread-safe method using internal Mutex.
    pub fn active_stream_count(&self) -> usize {
        let active_streams = self.active_streams.lock();
        active_streams.len()
    }

    /// Remove a stream only if it was registered at the specified timestamp.
    /// br-asupersync-tnvxx3: Thread-safe method for timestamp-validated removal.
    pub fn remove_stream_if_owned(&self, stream_id: u32, registered_at: Instant) {
        let mut active_streams = self.active_streams.lock();
        if let Some(stream_state) = active_streams.get(&stream_id) {
            if stream_state.registered_at == registered_at {
                active_streams.remove(&stream_id);
            }
            // If timestamps don't match, the registration was already removed
            // by a stale-entry sweep or replaced by a new registration.
        }
    }
}

/// Global registry for connection/stream accounting helpers.
///
/// br-asupersync-8vn9iu: this type can limit registered streams within a
/// registered connection and purge stale entries during explicit admission.
/// It does not cap connection count, schedule idle sweeps, or close transport
/// streams by itself.
///
/// br-asupersync-tnvxx3: Uses RwLock instead of Mutex to allow concurrent
/// reads and reduce lock contention under high load. Write locks only needed
/// for connection add/remove; read locks sufficient for stream operations.
#[derive(Debug)]
pub struct ConnectionRegistry {
    /// Connection states keyed by connection identifier.
    /// Uses RwLock to allow concurrent reads and per-connection modifications.
    connections: RwLock<HashMap<String, ConnectionState>>,
}

impl ConnectionRegistry {
    /// Create a new connection registry.
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new connection.
    /// br-asupersync-tnvxx3: Uses write lock since we're modifying the HashMap.
    pub fn add_connection(&self, connection_id: String) {
        let mut connections = self.connections.write();
        connections.insert(connection_id, ConnectionState::new());
    }

    /// Remove a connection and all its streams.
    /// br-asupersync-tnvxx3: Uses write lock since we're modifying the HashMap.
    pub fn remove_connection(&self, connection_id: &str) {
        let mut connections = self.connections.write();
        connections.remove(connection_id);
    }

    /// Enforce the registration-count limit for a specific connection and,
    /// when configured, purge stale accounting entries before admission.
    ///
    /// Returns the registration timestamp on success, or an error if the stream
    /// cannot be added due to limits. The registry read lock stabilizes the
    /// connection-map entry, while the stale-entry purge and add each lock the
    /// per-connection map separately; they are not one atomic transaction. The
    /// purge does not cancel live handlers/transport streams and runs only when
    /// this method is called; it is not a timer-driven idle timeout.
    ///
    /// br-asupersync-tnvxx3: Uses read lock since we only modify connection state,
    /// not the HashMap structure. This allows concurrent stream operations on
    /// different connections.
    pub fn enforce_stream_limits(
        &self,
        connection_id: &str,
        stream_id: u32,
        max_concurrent: u32,
        idle_timeout: Option<Duration>,
    ) -> Result<Instant, String> {
        let connections = self.connections.read();
        let connection = connections
            .get(connection_id)
            .ok_or_else(|| format!("connection not registered: {}", connection_id))?;

        // Purge stale accounting entries before addition. Each helper locks
        // the per-connection map separately; the pair is not one transaction.
        // There is intentionally no stderr output from this library surface;
        // callers that need observability can compare registry statistics.
        if let Some(timeout) = idle_timeout {
            connection.cleanup_idle_streams(timeout);
        }

        // Try to add the new stream (returns registration timestamp)
        connection.add_stream(stream_id, max_concurrent)
    }

    /// Update stream activity timestamp.
    /// br-asupersync-tnvxx3: Uses read lock since ConnectionState is internally synchronized.
    pub fn update_stream_activity(&self, connection_id: &str, stream_id: u32) {
        let connections = self.connections.read();
        if let Some(connection) = connections.get(connection_id) {
            connection.update_stream_activity(stream_id);
        }
    }

    /// Remove a stream registration when its caller completes normally.
    /// br-asupersync-tnvxx3: Uses read lock since ConnectionState is internally synchronized.
    pub fn remove_stream(&self, connection_id: &str, stream_id: u32) {
        let connections = self.connections.read();
        if let Some(connection) = connections.get(connection_id) {
            connection.remove_stream(stream_id);
        }
    }

    /// Remove a stream only if it was registered at the specified timestamp.
    ///
    /// This prevents race conditions where cleanup operations and Drop guards
    /// could both attempt to remove the same stream ID. The timestamp validation
    /// ensures we only remove the stream if it matches the specific registration
    /// we're responsible for.
    /// br-asupersync-tnvxx3: Uses read lock since ConnectionState is internally synchronized.
    pub fn remove_stream_if_owned(
        &self,
        connection_id: &str,
        stream_id: u32,
        registered_at: Instant,
    ) {
        let connections = self.connections.read();
        if let Some(connection) = connections.get(connection_id) {
            connection.remove_stream_if_owned(stream_id, registered_at);
        }
    }

    /// Get registration-accounting statistics for debugging/monitoring.
    /// br-asupersync-tnvxx3: Uses read lock for read-only operation, allowing
    /// concurrent stats collection without blocking stream operations.
    pub fn get_stats(&self) -> (usize, usize) {
        let connections = self.connections.read();
        let connection_count = connections.len();
        let total_streams: usize = connections
            .values()
            .map(|conn| conn.active_stream_count())
            .sum();
        (connection_count, total_streams)
    }
}

/// br-asupersync-wix48k: RAII guard that removes a stream registration
/// from a [`ConnectionRegistry`] when dropped.
///
/// `dispatch_unary_with_stream_enforcement` previously cleaned up the
/// registered stream by calling `registry.remove_stream(...)` *after*
/// awaiting the inner handler. If a caller dropped that wrapper before the
/// handler resolved, the cleanup line was never reached and the registration
/// stayed in `active_streams`. A transport adapter that maps a peer reset to
/// dropping this future receives the same accounting cleanup, but this guard
/// does not claim that transport wiring exists automatically. The guard
/// removes the registration from its `Drop`, so cleanup runs whether the
/// dispatch returns, panics, or is cancelled mid-await.
///
/// SECURITY: The guard tracks registration timestamp to prevent
/// double-removal races where a stale-entry purge and Drop
/// could both attempt to remove the same stream ID.
struct StreamRegistrationGuard {
    registry: Arc<ConnectionRegistry>,
    connection_id: String,
    stream_id: u32,
    /// Timestamp when this stream was registered, used to validate
    /// removal against race conditions with cleanup operations.
    registered_at: Instant,
}

impl Drop for StreamRegistrationGuard {
    fn drop(&mut self) {
        self.registry.remove_stream_if_owned(
            &self.connection_id,
            self.stream_id,
            self.registered_at,
        );
    }
}

/// gRPC server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Maximum message size for receiving, in bytes.
    ///
    /// Supplied to codecs created through [`Server::framed_codec`]
    /// (the canonical helper for transport adapters). The production native
    /// H2 path returned by [`Server::bind_http2`] calls that helper
    /// automatically. Other adapters that construct their own codec must pass this value to
    /// [`super::codec::FramedCodec::with_message_size_limits`]
    /// or call the helper. The client-side analog at
    /// [`super::client::ChannelConfig::max_recv_message_size`]
    /// follows the same contract.
    ///
    /// Defaults to 4 MiB (matches gRPC ecosystem convention and the
    /// codec's own `DEFAULT_MAX_MESSAGE_SIZE`).
    pub max_recv_message_size: usize,
    /// Maximum message size for sending, in bytes.
    ///
    /// Supplied to codecs created through [`Server::framed_codec`]
    /// (see [`Self::max_recv_message_size`] for the integration boundary).
    pub max_send_message_size: usize,
    /// Optional aggregate decoded-body limit for a unary or
    /// client-streaming call.
    ///
    /// `None` preserves the pre-fix unlimited aggregate behavior. `Some(cap)`
    /// configures the per-call [`RequestBodyMeter`] attached by
    /// [`Server::framed_codec`]. Every successfully decoded, decompressed
    /// request message is charged exactly once; the first message that pushes
    /// the total above `cap` is rejected with `Status::resource_exhausted` and
    /// poisons the request stream before delivery.
    ///
    /// Defaults to `None`. The limit is independent of the per-message
    /// cap — a 256 KiB per-message cap with a 4 MiB aggregate
    /// cap means each message ≤ 256 KiB AND total bytes across
    /// all messages on the call ≤ 4 MiB.
    ///
    /// The configuration and helper seam originated in the tick #203
    /// follow-up (br-asupersync-woj18e); production decode wiring is
    /// br-asupersync-s5e129.
    pub max_request_body_bytes: Option<usize>,
    /// Initial H2 connection receive window. [`Server::bind_http2`] advertises
    /// values above the protocol baseline with an initial stream-0
    /// WINDOW_UPDATE and replenishes receive credit to this target.
    pub initial_connection_window_size: u32,
    /// Initial H2 stream receive window advertised through
    /// SETTINGS_INITIAL_WINDOW_SIZE by [`Server::bind_http2`].
    pub initial_stream_window_size: u32,
    /// Per-connection stream limit advertised and enforced by the native H2
    /// connection used by [`Server::bind_http2`]. It is also supplied to
    /// [`ConnectionRegistry::enforce_stream_limits`] for non-H2 adapters that
    /// opt into the legacy accounting helper.
    pub max_concurrent_streams: u32,
    /// Keep-alive interval.
    pub keepalive_interval_ms: Option<u64>,
    /// Keep-alive timeout.
    pub keepalive_timeout_ms: Option<u64>,
    /// Default timeout applied when the client omits `grpc-timeout` or sends
    /// a malformed value.
    pub default_timeout: Option<Duration>,
    /// br-asupersync-9oxmqv-followup (tick #139): server-side maximum
    /// request deadline. When `Some(cap)`, every parseable peer-supplied
    /// `grpc-timeout` is clamped to `min(peer_timeout, cap)` so a
    /// hostile peer cannot choose an impractically distant representable
    /// deadline such as `grpc-timeout: 99999999H` (≈11,400 years). When `None`, the
    /// peer's value is used subject to the parser's 8-digit cap and
    /// fail-closed `Instant` representability check.
    ///
    /// This cap does NOT affect the absent- or malformed-header fallback to
    /// [`Self::default_timeout`] — that path still applies the configured
    /// default. Callers that want a tighter ceiling on the default should set
    /// `default_timeout` itself.
    pub max_request_deadline: Option<Duration>,
    /// Compression used for outbound response messages.
    pub send_compression: Option<CompressionEncoding>,
    /// Compression encodings accepted by this server.
    pub accept_compression: Vec<CompressionEncoding>,
    /// Maximum aggregate size, in bytes, of the supplied [`Metadata`] block.
    /// Each entry contributes `key.len() + value.byte_len()` bytes.
    /// Defaults to 8 KiB — matches the gRPC ecosystem convention used
    /// by `grpc-go`'s `MaxHeaderListSize` and the per-RFC-9113 §6.5.2
    /// `SETTINGS_MAX_HEADER_LIST_SIZE` advisory cap.
    ///
    /// [`Server::dispatch_unary`] applies this to already-decoded request
    /// metadata and returns `Status::resource_exhausted` when it is too large.
    /// The native HTTP/2 adapter applies the same limit to the combined decoded
    /// initial-header and request-trailer metadata retained for a call.
    ///
    /// This is a post-decode dispatch/retention limit. It does not bound HPACK
    /// decoder allocation; an H2 transport must enforce its wire/header-list
    /// limit before constructing [`Metadata`].
    ///
    /// br-asupersync-i2bae8.
    pub max_metadata_size: usize,
    /// Maximum inactivity interval for a request stream. The production H2
    /// listener resets the deadline on request HEADERS/DATA and resets only
    /// the expired stream with CANCEL, dropping a pending handler future. The
    /// same value remains the stale-registration threshold for non-H2 adapters
    /// using [`ConnectionRegistry::enforce_stream_limits`]. Defaults to 60
    /// seconds; `None` disables both behaviors.
    ///
    /// br-asupersync-8vn9iu: helper seam for limiting stale registration
    /// residency when transport adapters wire the accounting path.
    pub stream_idle_timeout: Option<Duration>,
}

/// Default max-metadata-size in bytes (8 KiB) — matches the gRPC
/// ecosystem convention. See [`ServerConfig::max_metadata_size`].
pub const DEFAULT_MAX_METADATA_SIZE: usize = 8 * 1024;

/// Compute the total byte size of a [`Metadata`] block.
///
/// Sums `key.len() + value.byte_len()` over every entry. Used by
/// [`enforce_metadata_size_limit`] to bound metadata accepted by dispatch after
/// decoding and before longer-lived retention.
#[must_use]
pub fn metadata_byte_size(metadata: &super::streaming::Metadata) -> usize {
    let mut total = 0usize;
    for (key, value) in metadata.iter() {
        let value_len = match value {
            super::streaming::MetadataValue::Ascii(s) => s.len(),
            super::streaming::MetadataValue::Binary(b) => b.len(),
        };
        total = total.saturating_add(key.len()).saturating_add(value_len);
    }
    total
}

fn metadata_key_uses_grpc_prefix(key: &str) -> bool {
    key.get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("grpc-"))
}

fn grpc_request_header_is_allowed(key: &str) -> bool {
    key.eq_ignore_ascii_case("grpc-timeout")
        || key.eq_ignore_ascii_case("grpc-encoding")
        || key.eq_ignore_ascii_case("grpc-accept-encoding")
        || key.eq_ignore_ascii_case("grpc-message-type")
}

fn matches_media_type_prefix(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix)
        && matches!(value.as_bytes().get(prefix.len()), None | Some(b'+' | b';'))
}

fn grpc_content_type_is_allowed(value: &str) -> bool {
    matches_media_type_prefix(value.trim(), "application/grpc")
}

fn grpc_te_header_is_allowed(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("trailers")
}

/// br-asupersync-60vn7x: RFC 7230 compliant header name validation.
/// Header names must be tokens as defined in RFC 7230 section 3.2.6:
/// token = 1*tchar
/// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
///         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
fn is_valid_header_name_rfc7230(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    for byte in name.bytes() {
        match byte {
            // ALPHA (A-Z, a-z)
            b'A'..=b'Z' | b'a'..=b'z' => {}
            // DIGIT (0-9)
            b'0'..=b'9' => {}
            // tchar special characters
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_'
            | b'`' | b'|' | b'~' => {}
            // Invalid character for header name
            _ => return false,
        }
    }
    true
}

/// br-asupersync-60vn7x: RFC 7230 compliant header value validation.
/// Header values must not contain CRLF sequences (prevents injection attacks)
/// and should only contain visible characters, spaces, and horizontal tabs.
/// RFC 7230 section 3.2: field-value = *( field-content / obs-fold )
/// field-content = field-vchar [ 1*( SP / HTAB ) field-vchar ]
/// field-vchar = VCHAR / obs-text
fn is_valid_header_value_rfc7230(value: &str) -> bool {
    let bytes = value.as_bytes();

    // Check for CRLF injection attacks
    if value.contains('\r') || value.contains('\n') {
        return false;
    }

    for &byte in bytes {
        match byte {
            // VCHAR (visible characters)
            0x21..=0x7E => {}
            // SP (space) and HTAB (horizontal tab) - allowed in field values
            b' ' | b'\t' => {}
            // obs-text (0x80-0xFF) - technically allowed but we reject for safety
            // Control characters (0x00-0x1F, 0x7F) - forbidden
            _ => return false,
        }
    }
    true
}

/// br-asupersync-60vn7x: Maximum allowed length for individual header names and values
/// to prevent memory exhaustion attacks via oversized headers.
const MAX_HEADER_NAME_LEN: usize = 256; // 256 bytes
const MAX_HEADER_VALUE_LEN: usize = 8192; // 8 KB

fn validate_inbound_metadata(metadata: &super::streaming::Metadata) -> Result<(), Status> {
    for (key, value) in metadata.iter() {
        // br-asupersync-60vn7x: RFC 7230 header name validation
        if !is_valid_header_name_rfc7230(key) {
            return Err(Status::invalid_argument(format!(
                "metadata key '{key}' contains invalid characters (RFC 7230 violation)"
            )));
        }

        // br-asupersync-60vn7x: Header name length limit
        if key.len() > MAX_HEADER_NAME_LEN {
            return Err(Status::invalid_argument(format!(
                "metadata key '{key}' exceeds maximum length ({} > {})",
                key.len(),
                MAX_HEADER_NAME_LEN
            )));
        }

        // br-asupersync-60vn7x: RFC 7230 header value validation
        match value {
            super::streaming::MetadataValue::Ascii(text) => {
                if !is_valid_header_value_rfc7230(text) {
                    return Err(Status::invalid_argument(format!(
                        "metadata value for '{key}' contains disallowed CRLF or invalid characters (RFC 7230 violation)"
                    )));
                }
                if text.len() > MAX_HEADER_VALUE_LEN {
                    return Err(Status::invalid_argument(format!(
                        "metadata value for '{key}' exceeds maximum length ({} > {})",
                        text.len(),
                        MAX_HEADER_VALUE_LEN
                    )));
                }
            }
            super::streaming::MetadataValue::Binary(bytes) => {
                if bytes.len() > MAX_HEADER_VALUE_LEN {
                    return Err(Status::invalid_argument(format!(
                        "binary metadata value for '{key}' exceeds maximum length ({} > {})",
                        bytes.len(),
                        MAX_HEADER_VALUE_LEN
                    )));
                }
            }
        }

        if metadata_key_uses_grpc_prefix(key) && !grpc_request_header_is_allowed(key) {
            return Err(Status::invalid_argument(format!(
                "client metadata key uses reserved grpc-* prefix: {key}"
            )));
        }

        if let super::streaming::MetadataValue::Ascii(text) = value {
            if super::streaming::sanitize_metadata_ascii_value(text).as_ref() != text {
                return Err(Status::invalid_argument(format!(
                    "metadata value for {key} contains disallowed control or non-ASCII bytes"
                )));
            }
        }

        if key.eq_ignore_ascii_case("content-type") {
            match value {
                super::streaming::MetadataValue::Ascii(text)
                    if !grpc_content_type_is_allowed(text) =>
                {
                    return Err(Status::invalid_argument(format!(
                        "content-type must be application/grpc(+proto|+json), got {text}"
                    )));
                }
                super::streaming::MetadataValue::Binary(_) => {
                    return Err(Status::invalid_argument(
                        "content-type must be an ASCII gRPC media type",
                    ));
                }
                super::streaming::MetadataValue::Ascii(_) => {}
            }
        } else if key.eq_ignore_ascii_case("te") {
            match value {
                super::streaming::MetadataValue::Ascii(text)
                    if !grpc_te_header_is_allowed(text) =>
                {
                    return Err(Status::invalid_argument(format!(
                        "te must be trailers for gRPC over HTTP/2, got {text}"
                    )));
                }
                super::streaming::MetadataValue::Binary(_) => {
                    return Err(Status::invalid_argument(
                        "te must be an ASCII trailers header",
                    ));
                }
                super::streaming::MetadataValue::Ascii(_) => {}
            }
        }
    }
    Ok(())
}

/// Reject inbound `metadata` when it violates the gRPC header-content rules or
/// when its aggregate byte size exceeds `limit`.
///
/// Call this after wire/header decoding and before dispatch or longer-lived
/// `CallContext` retention. Because the [`Metadata`] values already exist, this
/// helper cannot bound HPACK decoder allocation; an H2 adapter needs a separate
/// pre-decode/header-list limit for that guarantee.
///
/// `limit` is typically [`ServerConfig::max_metadata_size`]
/// (default 8 KiB via [`DEFAULT_MAX_METADATA_SIZE`]). A `limit` of
/// 0 disables enforcement (matches the convention used elsewhere in
/// this crate where 0 means "no cap").
///
/// Returns `Ok(())` when the metadata is valid and within bounds, or
/// `Err(Status::invalid_argument(...))` for invalid header content or reserved
/// client metadata, or `Err(Status::resource_exhausted(...))` carrying both the
/// actual and the configured limit so SREs can diagnose size-based rejections.
///
/// br-asupersync-i2bae8.
pub fn enforce_metadata_size_limit(
    metadata: &super::streaming::Metadata,
    limit: usize,
) -> Result<(), Status> {
    validate_inbound_metadata(metadata)?;
    if limit == 0 {
        return Ok(());
    }
    let actual = metadata_byte_size(metadata);
    if actual > limit {
        return Err(Status::resource_exhausted(format!(
            "metadata exceeds max_metadata_size: {actual} bytes > {limit} bytes \
             (gRPC equivalent of HTTP 431 Request Header Fields Too Large; \
             see ServerConfig::max_metadata_size)"
        )));
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn grpc_request_trailer_key_is_reserved(key: &str) -> bool {
    // gRPC owns every grpc-* field. The remainder mirrors the RFC 9110
    // trailer restrictions enforced by the HTTP/1 codec so routing, framing,
    // authentication, and payload semantics cannot be introduced late.
    metadata_key_uses_grpc_prefix(key)
        || [
            "age",
            "authorization",
            "cache-control",
            "connection",
            "content-encoding",
            "content-length",
            "content-range",
            "content-type",
            "cookie",
            "date",
            "expect",
            "expires",
            "host",
            "keep-alive",
            "max-forwards",
            "pragma",
            "proxy-authenticate",
            "proxy-authorization",
            "proxy-connection",
            "range",
            "retry-after",
            "set-cookie",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "vary",
            "warning",
            "www-authenticate",
        ]
        .iter()
        .any(|reserved| key.eq_ignore_ascii_case(reserved))
}

#[cfg(not(target_arch = "wasm32"))]
fn insert_http2_metadata_entry(
    metadata: &mut Metadata,
    key: &str,
    value: &str,
) -> Result<(), Status> {
    let binary = key
        .get(key.len().saturating_sub(4)..)
        .is_some_and(|suffix| suffix.eq_ignore_ascii_case("-bin"));
    let inserted = if binary {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(value)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value))
            .map_err(|_| {
                Status::invalid_argument(format!(
                    "binary metadata value for '{key}' is not valid base64"
                ))
            })?;
        metadata.insert_bin(key, Bytes::from(decoded))
    } else {
        metadata.insert(key, value)
    };
    if inserted {
        Ok(())
    } else {
        Err(Status::invalid_argument(format!(
            "invalid gRPC metadata entry '{key}'"
        )))
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn enforce_http2_metadata_blocks(
    headers: &Metadata,
    trailers: &Metadata,
    limit: usize,
) -> Result<(), Status> {
    // br-asupersync-2rnlb0: both retained blocks share one request budget.
    validate_inbound_metadata(headers)?;
    validate_inbound_metadata(trailers)?;
    if limit == 0 {
        return Ok(());
    }

    let actual = metadata_byte_size(headers).saturating_add(metadata_byte_size(trailers));
    if actual > limit {
        return Err(Status::resource_exhausted(format!(
            "combined request headers and trailers exceed max_metadata_size: \
             {actual} bytes > {limit} bytes"
        )));
    }
    Ok(())
}

impl RequestBodyMeter {
    /// Construct a meter from a [`ServerConfig`].
    #[must_use]
    pub fn from_config(config: &ServerConfig) -> Self {
        Self::new(config.max_request_body_bytes)
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_recv_message_size: 4 * 1024 * 1024, // 4 MB
            max_send_message_size: 4 * 1024 * 1024, // 4 MB
            // Default None preserves pre-fix behavior. Server::framed_codec
            // wires configured limits into a per-call RequestBodyMeter at the
            // decoded-message boundary (br-asupersync-s5e129).
            max_request_body_bytes: None,
            initial_connection_window_size: 1024 * 1024,
            initial_stream_window_size: 1024 * 1024,
            max_concurrent_streams: 100,
            keepalive_interval_ms: None,
            keepalive_timeout_ms: None,
            default_timeout: None,
            // tick #139: opt-in. Default is the historic
            // pre-fix behavior (no server-side max deadline).
            max_request_deadline: None,
            send_compression: None,
            accept_compression: vec![CompressionEncoding::Identity],
            // 8 KiB matches the gRPC ecosystem convention (grpc-go
            // MaxHeaderListSize default) for post-decode metadata accepted by
            // dispatch (br-asupersync-i2bae8). This is not an HPACK allocation cap.
            max_metadata_size: DEFAULT_MAX_METADATA_SIZE,
            // Stored helper threshold for adapters that wire stream admission
            // and idle cleanup (br-asupersync-8vn9iu).
            stream_idle_timeout: Some(Duration::from_secs(60)),
        }
    }
}

/// Builder for configuring a gRPC server.
#[derive(Default)]
pub struct ServerBuilder {
    /// Server configuration.
    config: ServerConfig,
    /// Registered services.
    services: BTreeMap<String, Arc<dyn ServiceHandler>>,
    /// Optional reflection registry.
    reflection: Option<ReflectionService>,
    /// br-asupersync-mfk14i: interceptor chain. Each registered
    /// interceptor's `intercept_request` runs in registration order
    /// before the user handler executes; `intercept_response` runs
    /// in REVERSE order after the handler returns. Pre-fix this
    /// field did not exist and AuthInterceptor / BearerAuthValidator
    /// / RateLimitInterceptor were dead code from the dispatch
    /// path. Transport adapters MUST route requests through
    /// [`Server::dispatch_unary`] (or the analogous streaming
    /// dispatch) to ensure the chain actually fires.
    interceptors: Vec<Arc<dyn Interceptor>>,
}

impl std::fmt::Debug for ServerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerBuilder")
            .field("config", &self.config)
            .field("services", &format!("[{} services]", self.services.len()))
            .field("reflection_enabled", &self.reflection.is_some())
            .finish()
    }
}

impl ServerBuilder {
    /// Create a new server builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: ServerConfig::default(),
            services: BTreeMap::new(),
            reflection: None,
            interceptors: Vec::new(),
        }
    }

    /// Append an interceptor to the chain (br-asupersync-mfk14i).
    ///
    /// Interceptors are invoked in registration order on the
    /// request side and in REVERSE order on the response side, so
    /// later layers wrap earlier ones (the standard middleware
    /// onion). Without at least one call to `interceptor()`, the
    /// dispatch path runs the user handler unguarded — pre-fix this
    /// was the ONLY behavior because no wiring existed.
    #[must_use]
    pub fn interceptor<I>(mut self, interceptor: I) -> Self
    where
        I: Interceptor + 'static,
    {
        self.interceptors.push(Arc::new(interceptor));
        self
    }

    /// Append an already-Arc'd interceptor to the chain
    /// (br-asupersync-mfk14i). Convenience for callers that already
    /// hold a shared interceptor (e.g. a single `RateLimitInterceptor`
    /// shared across multiple servers).
    #[must_use]
    pub fn interceptor_arc(mut self, interceptor: Arc<dyn Interceptor>) -> Self {
        self.interceptors.push(interceptor);
        self
    }

    /// Set the maximum receive message size.
    #[must_use]
    pub fn max_recv_message_size(mut self, size: usize) -> Self {
        self.config.max_recv_message_size = size;
        self
    }

    /// Set the maximum aggregate size of decoded request metadata checked by
    /// [`Server::dispatch_unary`]. Defaults to 8 KiB
    /// ([`DEFAULT_MAX_METADATA_SIZE`]). The native HTTP/2 adapter applies this
    /// cap to initial and trailing metadata combined. This remains a
    /// post-decode retention limit, not an HPACK allocation bound. A value of
    /// `0` disables the check. (br-asupersync-i2bae8.)
    #[must_use]
    pub fn max_metadata_size(mut self, size: usize) -> Self {
        self.config.max_metadata_size = size;
        self
    }

    /// Set the stream idle timeout.
    ///
    /// The native H2 listener returned by [`Server::bind_http2`] resets this
    /// deadline on inbound HEADERS/DATA and cancels only the expired stream.
    /// Non-H2 adapters using [`ConnectionRegistry::enforce_stream_limits`]
    /// consume the same value as a stale-registration threshold.
    #[must_use]
    pub fn stream_idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.config.stream_idle_timeout = timeout;
        self
    }

    /// Set the maximum send message size.
    #[must_use]
    pub fn max_send_message_size(mut self, size: usize) -> Self {
        self.config.max_send_message_size = size;
        self
    }

    /// Configure the aggregate decoded-body limit for each inbound call.
    ///
    /// [`Server::framed_codec`] binds this value to the codec's per-call
    /// [`RequestBodyMeter`], so unary and client-streaming decoders enforce
    /// the same cumulative byte ceiling. `None` (the default) is unlimited.
    /// (br-asupersync-woj18e, br-asupersync-s5e129)
    #[must_use]
    pub fn max_request_body_bytes(mut self, size: usize) -> Self {
        self.config.max_request_body_bytes = Some(size);
        self
    }

    /// Set the native H2 connection receive window. Values must be within
    /// `65_535..=2^31-1`; [`Server::bind_http2`] rejects invalid values before
    /// binding.
    #[must_use]
    pub fn initial_connection_window_size(mut self, size: u32) -> Self {
        self.config.initial_connection_window_size = size;
        self
    }

    /// Set SETTINGS_INITIAL_WINDOW_SIZE for the native H2 transport. Values
    /// above the 31-bit HTTP/2 maximum are rejected before binding.
    #[must_use]
    pub fn initial_stream_window_size(mut self, size: u32) -> Self {
        self.config.initial_stream_window_size = size;
        self
    }

    /// Configure native H2 per-connection stream admission and the equivalent
    /// limit used by the optional non-H2 accounting helper.
    #[must_use]
    pub fn max_concurrent_streams(mut self, max: u32) -> Self {
        self.config.max_concurrent_streams = max;
        self
    }

    /// Set the keep-alive interval.
    #[must_use]
    pub fn keepalive_interval(mut self, ms: u64) -> Self {
        self.config.keepalive_interval_ms = Some(ms);
        self
    }

    /// Set the keep-alive timeout.
    #[must_use]
    pub fn keepalive_timeout(mut self, ms: u64) -> Self {
        self.config.keepalive_timeout_ms = Some(ms);
        self
    }

    /// Set the default timeout used when the client omits `grpc-timeout` or
    /// sends a malformed value.
    #[must_use]
    pub fn default_timeout(mut self, timeout: Duration) -> Self {
        self.config.default_timeout = Some(timeout);
        self
    }

    /// tick #139: set the server-side maximum request deadline.
    ///
    /// When set, every parseable peer-supplied `grpc-timeout` is clamped to
    /// `min(peer_timeout, cap)`. Without this cap a hostile peer can request
    /// an impractically distant representable deadline such as
    /// `grpc-timeout: 99999999H` (≈11,400 years).
    ///
    /// Recommended value: the longest legitimate RPC the server is
    /// prepared to host (typically minutes to hours, NOT years).
    /// Callsites that need a tighter ceiling on the absent- or
    /// malformed-header fallback should ALSO set [`Self::default_timeout`] —
    /// the cap does NOT affect the fallback path.
    #[must_use]
    pub fn max_request_deadline(mut self, max: Duration) -> Self {
        self.config.max_request_deadline = Some(max);
        self
    }

    /// Set the outbound compression encoding for responses.
    #[must_use]
    pub fn send_compression(mut self, encoding: CompressionEncoding) -> Self {
        self.config.send_compression = Some(encoding);
        self
    }

    /// Add one accepted compression encoding.
    #[must_use]
    pub fn accept_compression(mut self, encoding: CompressionEncoding) -> Self {
        self.config.accept_compression.push(encoding);
        self
    }

    /// Replace accepted compression encodings.
    #[must_use]
    pub fn accept_compressions(
        mut self,
        encodings: impl IntoIterator<Item = CompressionEncoding>,
    ) -> Self {
        self.config.accept_compression.clear();
        self.config.accept_compression.extend(encodings);
        self
    }

    /// Add a service to the server.
    #[must_use]
    pub fn add_service<S>(mut self, service: S) -> Self
    where
        S: NamedService + ServiceHandler + 'static,
    {
        let service_name = S::NAME.to_string();
        let service: Arc<dyn ServiceHandler> = Arc::new(service);
        if let Some(reflection) = self.reflection.as_ref()
            && service_name != ReflectionService::NAME
        {
            reflection.register_handler(service.as_ref());
        }
        self.services.insert(service_name, service);
        self
    }

    /// Enable the built-in reflection service with authentication callback.
    ///
    /// SECURITY: This method requires an explicit authentication callback to gate
    /// reflection access. The callback receives the current Cx and method name
    /// and should return Ok(()) to allow access or Err(Status) to deny.
    ///
    /// The reflection registry captures descriptors for all currently
    /// registered services and continues to track additional services added to
    /// this builder after reflection is enabled.
    ///
    /// Test-only unauthenticated reflection should construct a
    /// [`ReflectionService`] and opt into [`ReflectionService::allow_anonymous`]
    /// inside the `#[cfg(test)]` harness that needs it.
    #[must_use]
    pub fn enable_reflection_with_auth<F>(mut self, auth_callback: F) -> Self
    where
        F: Fn(&Cx, &str) -> Result<(), Status> + Send + Sync + 'static,
    {
        let reflection = self
            .reflection
            .take()
            .unwrap_or_default()
            .with_auth(auth_callback);
        for service in self.services.values() {
            if service.descriptor().full_name() != ReflectionService::NAME {
                reflection.register_handler(service.as_ref());
            }
        }
        self.services.insert(
            ReflectionService::NAME.to_string(),
            Arc::new(reflection.clone()),
        );
        self.reflection = Some(reflection);
        self
    }

    /// Enable the built-in reflection service (DEPRECATED).
    ///
    /// DEPRECATED: This method creates a reflection service in Locked mode that
    /// rejects all requests. Use `enable_reflection_with_auth()` for production.
    ///
    /// This method will be removed in a future version.
    #[deprecated(
        since = "0.3.3",
        note = "Use enable_reflection_with_auth() to install production reflection auth explicitly"
    )]
    #[must_use]
    pub fn enable_reflection(mut self) -> Self {
        let reflection = self.reflection.take().unwrap_or_default(); // Defaults to Locked mode
        for service in self.services.values() {
            if service.descriptor().full_name() != ReflectionService::NAME {
                reflection.register_handler(service.as_ref());
            }
        }
        self.services.insert(
            ReflectionService::NAME.to_string(),
            Arc::new(reflection.clone()),
        );
        self.reflection = Some(reflection);
        self
    }

    /// Build the server.
    #[must_use]
    pub fn build(self) -> Server {
        Server {
            config: self.config,
            services: self.services,
            interceptors: self.interceptors,
            connection_registry: Arc::new(ConnectionRegistry::new()),
        }
    }
}

/// A gRPC server.
pub struct Server {
    /// Server configuration.
    config: ServerConfig,
    /// Registered services.
    services: BTreeMap<String, Arc<dyn ServiceHandler>>,
    /// br-asupersync-mfk14i: interceptor chain. See
    /// [`ServerBuilder::interceptor`] and [`Server::dispatch_unary`].
    interceptors: Vec<Arc<dyn Interceptor>>,
    /// br-asupersync-8vn9iu: optional connection/stream registration
    /// accounting used by the wrapped dispatch helper.
    connection_registry: Arc<ConnectionRegistry>,
}

/// One decoded unary gRPC request admitted from the production HTTP/2
/// listener.
///
/// The transport adapter has already validated the HTTP method/media type,
/// decoded exactly one gRPC message through [`Server::framed_codec`], applied
/// inbound header and trailer metadata validation, and run the server
/// interceptor/deadline path. Request trailers stay separate from initial
/// metadata so callers can preserve their wire-level ordering and semantics.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
pub struct GrpcTransportRequest {
    path: String,
    request: Request<Bytes>,
    trailing_metadata: Metadata,
}

#[cfg(not(target_arch = "wasm32"))]
impl GrpcTransportRequest {
    /// Fully qualified RPC path (for example `/package.Service/Method`).
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Borrow the decoded request and its validated metadata.
    #[must_use]
    pub fn request(&self) -> &Request<Bytes> {
        &self.request
    }

    /// Borrow the validated request trailer metadata.
    #[must_use]
    pub fn trailing_metadata(&self) -> &Metadata {
        &self.trailing_metadata
    }

    /// Consume this envelope into `(path, request, trailing_metadata)`.
    #[must_use]
    pub fn into_parts(self) -> (String, Request<Bytes>, Metadata) {
        (self.path, self.request, self.trailing_metadata)
    }
}

#[cfg(not(target_arch = "wasm32"))]
type GrpcHttp2Future = Pin<Box<dyn Future<Output = HttpResponse> + Send>>;

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("config", &self.config)
            .field("services", &format!("[{} services]", self.services.len()))
            .finish()
    }
}

impl Server {
    /// Create a new server builder.
    #[must_use]
    pub fn builder() -> ServerBuilder {
        ServerBuilder::new()
    }

    /// Get the server configuration.
    #[must_use]
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Construct a per-call [`FramedCodec`] wired with the server's message
    /// size limits and aggregate decoded request-body limit.
    ///
    /// The returned codec owns one [`RequestBodyMeter`] for the call. Reusing
    /// it across a client-streaming request charges each successfully decoded,
    /// decompressed message exactly once. Constructing `FramedCodec` directly
    /// intentionally does not inherit server policy.
    ///
    /// The compression hooks remain the adapter's responsibility:
    /// the adapter parses `grpc-encoding` from request metadata,
    /// looks up the matching compressor/decompressor via
    /// [`CompressionEncoding::frame_compressor`] /
    /// [`CompressionEncoding::frame_decompressor`], and chains them
    /// onto the returned codec via
    /// [`FramedCodec::with_frame_hooks`].
    #[must_use]
    pub fn framed_codec<C: Codec>(&self, inner: C) -> FramedCodec<C> {
        FramedCodec::with_message_size_limits(
            inner,
            self.config.max_send_message_size,
            self.config.max_recv_message_size,
        )
        .with_request_body_limit(self.config.max_request_body_bytes)
    }

    /// Build the production HTTP/2 listener configuration for this gRPC
    /// server.
    ///
    /// This is the single bridge from [`ServerConfig`] into the native H2
    /// transport: stream and connection receive windows, concurrent-stream
    /// admission, header-list bounds, unary request buffering, and per-stream
    /// inactivity cancellation all derive from the server configuration.
    /// Message send/receive limits are applied by the decoded adapter returned
    /// from [`Self::bind_http2`], not approximated at the HTTP body boundary.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn http2_listener_config(&self, host_policy: HostPolicy) -> Http2ListenerConfig {
        let mut settings = Settings::server();
        settings.initial_window_size = self.config.initial_stream_window_size;
        settings.max_concurrent_streams = self.config.max_concurrent_streams;
        settings.max_header_list_size = if self.config.max_metadata_size == 0 {
            u32::MAX
        } else {
            u32::try_from(self.config.max_metadata_size).unwrap_or(u32::MAX)
        };

        // The production adapter currently admits exactly one unary message,
        // so the maximum legal wire body is one five-byte gRPC prefix plus the
        // configured maximum wire payload. The decoded aggregate meter remains
        // authoritative after decompression.
        let max_body_size = self
            .config
            .max_recv_message_size
            .saturating_add(super::codec::MESSAGE_HEADER_SIZE);

        Http2ListenerConfig::default()
            .settings(settings)
            .initial_connection_window_size(self.config.initial_connection_window_size)
            .max_body_size(max_body_size)
            .host_policy(host_policy)
            .stream_idle_timeout(self.config.stream_idle_timeout)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn validate_http2_transport_config(&self) -> io::Result<()> {
        if self.config.initial_stream_window_size > 0x7fff_ffff {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "gRPC initial stream window exceeds the HTTP/2 31-bit maximum",
            ));
        }
        if !(65_535..=0x7fff_ffff).contains(&self.config.initial_connection_window_size) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "gRPC initial connection window must be within 65535..=2^31-1",
            ));
        }
        Ok(())
    }

    /// Bind the production native HTTP/2 transport and decode unary gRPC
    /// requests before invoking `handler`.
    ///
    /// The returned listener must be run with
    /// [`Http2Listener::run`](crate::http::h2::listener::Http2Listener::run).
    /// It advertises this server's flow-control settings, enforces H2 stream
    /// admission and inactivity cancellation, decodes exactly one framed
    /// message through [`Self::framed_codec`], applies interceptors/deadlines,
    /// and encodes the handler result with the configured outbound limit.
    ///
    /// `host_policy` is mandatory so a production caller cannot accidentally
    /// inherit an allow-all authority policy.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn bind_http2<A, F, Fut>(
        self: &Arc<Self>,
        addr: A,
        host_policy: HostPolicy,
        handler: F,
    ) -> io::Result<Http2Listener<impl Fn(HttpRequest) -> GrpcHttp2Future + Send + Sync + 'static>>
    where
        A: std::net::ToSocketAddrs + Send + 'static,
        F: Fn(GrpcTransportRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Response<Bytes>, Status>> + Send + 'static,
    {
        self.validate_http2_transport_config()?;
        let config = self.http2_listener_config(host_policy);
        let server = Arc::clone(self);
        let handler = Arc::new(handler);
        let transport_handler = move |request: HttpRequest| -> GrpcHttp2Future {
            let server = Arc::clone(&server);
            let handler = Arc::clone(&handler);
            Box::pin(async move { server.dispatch_http2_unary(request, handler).await })
        };
        Http2Listener::bind_with_config(addr, transport_handler, config).await
    }

    /// Bind the production native HTTP/2 transport to this server's registered
    /// [`ServiceHandler`] implementations.
    ///
    /// Unlike [`Self::bind_http2`], this path does not accept an unrelated
    /// catch-all closure. It resolves the request path against the service and
    /// method descriptors installed through [`ServerBuilder::add_service`],
    /// invokes [`ServiceHandler::call_unary`], and returns gRPC
    /// `UNIMPLEMENTED` for malformed, unknown, streaming-only, or legacy
    /// metadata-only routes. The normal decoded dispatch path still owns
    /// metadata limits, interceptors, deadlines, response framing, and status
    /// trailers.
    ///
    /// The returned listener exposes its shutdown signal and connection
    /// manager and must be driven with [`Http2Listener::run`]. Use
    /// [`Self::serve_http2`] when the caller wants this method to bind and run
    /// the listener in one operation.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn bind_registered_http2<A>(
        self: &Arc<Self>,
        addr: A,
        host_policy: HostPolicy,
    ) -> io::Result<Http2Listener<impl Fn(HttpRequest) -> GrpcHttp2Future + Send + Sync + 'static>>
    where
        A: std::net::ToSocketAddrs + Send + 'static,
    {
        if self.services.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot bind registered gRPC routing without a service",
            ));
        }
        self.validate_http2_transport_config()?;
        let config = self.http2_listener_config(host_policy);
        let server = Arc::clone(self);
        let transport_handler = move |request: HttpRequest| -> GrpcHttp2Future {
            let server = Arc::clone(&server);
            Box::pin(async move { server.dispatch_http2_registered_unary(request).await })
        };
        Http2Listener::bind_with_config(addr, transport_handler, config).await
    }

    /// Bind and run the registered-service native HTTP/2 listener.
    ///
    /// This is the callable serving counterpart to the legacy [`Self::serve`]
    /// bind probe. It owns the listener until graceful drain completes and
    /// returns the transport's shutdown statistics. Run it inside a structured
    /// runtime task or region so cancellation of the owning task also drops the
    /// listener and its request subtree.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn serve_http2<A>(
        self: &Arc<Self>,
        runtime: &RuntimeHandle,
        addr: A,
        host_policy: HostPolicy,
    ) -> io::Result<ShutdownStats>
    where
        A: std::net::ToSocketAddrs + Send + 'static,
    {
        self.bind_registered_http2(addr, host_policy)
            .await?
            .run(runtime)
            .await
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn dispatch_http2_unary<F, Fut>(
        &self,
        request: HttpRequest,
        handler: Arc<F>,
    ) -> HttpResponse
    where
        F: Fn(GrpcTransportRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Response<Bytes>, Status>> + Send + 'static,
    {
        let (path, request, trailing_metadata) = match self.decode_http2_unary_request(request) {
            Ok(decoded) => decoded,
            Err(status) => return Self::http2_status_response(&status),
        };
        let result = self
            .dispatch_unary(request, move |request| {
                handler(GrpcTransportRequest {
                    path,
                    request,
                    trailing_metadata,
                })
            })
            .await;
        match result {
            Ok(response) => match self.encode_http2_unary_response(&response) {
                Ok(response) => response,
                Err(status) => Self::http2_status_response(&status),
            },
            Err(status) => Self::http2_status_response(&status),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn dispatch_http2_registered_unary(&self, request: HttpRequest) -> HttpResponse {
        let (path, request, trailing_metadata) = match self.decode_http2_unary_request(request) {
            Ok(decoded) => decoded,
            Err(status) => return Self::http2_status_response(&status),
        };
        let Some(cx) = Cx::current() else {
            return Self::http2_status_response(&Status::internal(
                "registered gRPC HTTP/2 dispatch requires a runtime Cx",
            ));
        };
        let result = self
            .dispatch_registered_unary_with_trailers(&cx, &path, request, trailing_metadata)
            .await;
        match result {
            Ok(response) => match self.encode_http2_unary_response(&response) {
                Ok(response) => response,
                Err(status) => Self::http2_status_response(&status),
            },
            Err(status) => Self::http2_status_response(&status),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn decode_http2_unary_request(
        &self,
        request: HttpRequest,
    ) -> Result<(String, Request<Bytes>, Metadata), Status> {
        if request.method != crate::http::h1::types::Method::Post {
            return Err(Status::invalid_argument(
                "gRPC over HTTP/2 requires the POST method",
            ));
        }
        let content_type = request
            .content_type()
            .ok_or_else(|| Status::invalid_argument("missing gRPC content-type"))?;
        if !grpc_content_type_is_allowed(content_type) {
            return Err(Status::invalid_argument(format!(
                "content-type must be application/grpc(+proto|+json), got {content_type}"
            )));
        }

        let mut metadata = Metadata::new();
        metadata.reserve(request.headers.len());
        for (key, value) in &request.headers {
            insert_http2_metadata_entry(&mut metadata, key, value)?;
        }

        let mut trailing_metadata = Metadata::new();
        trailing_metadata.reserve(request.trailers.len());
        let mut trailer_keys = std::collections::BTreeSet::new();
        for (key, value) in &request.trailers {
            let normalized_key = key.to_ascii_lowercase();
            if grpc_request_trailer_key_is_reserved(key) {
                return Err(Status::invalid_argument(format!(
                    "gRPC request trailer uses reserved transport key '{key}'"
                )));
            }
            if !trailer_keys.insert(normalized_key) || metadata.get(key).is_some() {
                return Err(Status::invalid_argument(format!(
                    "duplicate gRPC request trailer metadata key '{key}'"
                )));
            }
            insert_http2_metadata_entry(&mut trailing_metadata, key, value)?;
        }
        enforce_http2_metadata_blocks(
            &metadata,
            &trailing_metadata,
            self.config.max_metadata_size,
        )?;

        let grpc_encoding = request.header_value("grpc-encoding");
        let encoding = match grpc_encoding {
            Some(value) => CompressionEncoding::from_header_value(value).ok_or_else(|| {
                Status::unimplemented(format!("unsupported grpc-encoding: {value}"))
            })?,
            None => CompressionEncoding::Identity,
        };
        if !self.config.accept_compression.contains(&encoding) {
            return Err(Status::unimplemented(format!(
                "grpc-encoding is not accepted by this server: {}",
                grpc_encoding.unwrap_or("identity")
            )));
        }

        let mut codec = self.framed_codec(super::codec::IdentityCodec);
        if encoding != CompressionEncoding::Identity {
            let decompressor = encoding.frame_decompressor().ok_or_else(|| {
                Status::unimplemented(format!(
                    "grpc-encoding support is not compiled in: {}",
                    grpc_encoding.unwrap_or("identity")
                ))
            })?;
            codec = codec.with_frame_hooks(None, Some(decompressor));
        }

        let mut body = BytesMut::from(request.body.as_slice());
        let message = codec
            .decode_message_with_encoding(&mut body, grpc_encoding)
            .map_err(GrpcError::into_status)?
            .ok_or_else(|| Status::invalid_argument("incomplete gRPC message frame"))?;
        if !body.is_empty() {
            match codec.decode_message_with_encoding(&mut body, grpc_encoding) {
                Ok(Some(_)) => {
                    return Err(Status::invalid_argument(
                        "unary gRPC request contains more than one message",
                    ));
                }
                Ok(None) => {
                    return Err(Status::invalid_argument(
                        "unary gRPC request has a truncated trailing frame",
                    ));
                }
                Err(error) => return Err(error.into_status()),
            }
        }

        Ok((
            request.uri,
            Request::with_metadata(message, metadata),
            trailing_metadata,
        ))
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn encode_http2_unary_response(
        &self,
        response: &Response<Bytes>,
    ) -> Result<HttpResponse, Status> {
        let mut codec = self.framed_codec(super::codec::IdentityCodec);
        let mut grpc_encoding = None;
        if let Some(encoding) = self.config.send_compression {
            if encoding != CompressionEncoding::Identity {
                let compressor = encoding.frame_compressor().ok_or_else(|| {
                    Status::unimplemented("configured response compression is not compiled in")
                })?;
                codec = codec.with_frame_hooks(Some(compressor), None);
                grpc_encoding = Some(match encoding {
                    CompressionEncoding::Identity => "identity",
                    CompressionEncoding::Gzip => "gzip",
                });
            }
        }

        let mut body = BytesMut::new();
        codec
            .encode_message(response.get_ref(), &mut body)
            .map_err(GrpcError::into_status)?;
        let mut http = HttpResponse::new(200, "OK", body.to_vec())
            .with_header("content-type", "application/grpc");
        if let Some(encoding) = grpc_encoding {
            http.headers
                .push(("grpc-encoding".to_owned(), encoding.to_owned()));
        }
        for (key, value) in response.metadata().iter() {
            if key.eq_ignore_ascii_case("content-type")
                || key.eq_ignore_ascii_case("grpc-status")
                || key.eq_ignore_ascii_case("grpc-message")
            {
                return Err(Status::internal(format!(
                    "response metadata uses transport-reserved key '{key}'"
                )));
            }
            let value = match value {
                super::streaming::MetadataValue::Ascii(value) => value.clone(),
                super::streaming::MetadataValue::Binary(value) => {
                    base64::engine::general_purpose::STANDARD_NO_PAD.encode(value)
                }
            };
            http.headers.push((key.to_owned(), value));
        }
        http.trailers
            .push(("grpc-status".to_owned(), "0".to_owned()));
        Ok(http)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn http2_status_response(status: &Status) -> HttpResponse {
        let mut response = HttpResponse::new(200, "OK", Vec::new())
            .with_header("content-type", "application/grpc");
        if !status.message().is_empty() {
            response.trailers.push((
                "grpc-message".to_owned(),
                super::status::percent_encode_grpc_message(status.message()),
            ));
        }
        if let Some(details) = status.details() {
            response.trailers.push((
                "grpc-status-details-bin".to_owned(),
                base64::engine::general_purpose::STANDARD_NO_PAD.encode(details),
            ));
        }
        response
            .trailers
            .push(("grpc-status".to_owned(), status.code().as_i32().to_string()));
        response
    }

    /// Get the registered services.
    #[must_use]
    pub fn services(&self) -> &BTreeMap<String, Arc<dyn ServiceHandler>> {
        &self.services
    }

    /// Get the connection/stream registration-accounting helper.
    #[must_use]
    pub fn connection_registry(&self) -> &Arc<ConnectionRegistry> {
        &self.connection_registry
    }

    /// Register a connection in the optional accounting helper.
    ///
    /// An adapter that uses the wrapped dispatch path calls this when a gRPC
    /// connection is established. Registration alone does not impose a
    /// connection-count limit, schedule cleanup, or close idle streams.
    /// (br-asupersync-8vn9iu.)
    pub fn register_connection(&self, connection_id: String) {
        self.connection_registry.add_connection(connection_id);
    }

    /// Unregister a connection when it closes.
    ///
    /// Transport layers should call this when a gRPC connection closes
    /// to clean up tracking state. (br-asupersync-8vn9iu.)
    pub fn unregister_connection(&self, connection_id: &str) {
        self.connection_registry.remove_connection(connection_id);
    }

    /// Clear the typed authentication context from request extensions.
    ///
    /// The dispatch error and timeout paths call this while they still retain a
    /// request snapshot. It removes only [`super::interceptor::AuthContext`];
    /// other extension types remain owned by the request and are released when
    /// that request is dropped. External cancellation by dropping the dispatch
    /// future does not invoke this helper, but dropping the owned request still
    /// releases its extension map.
    fn clear_auth_context_from_request(request: &mut Request<Bytes>) {
        let _ = request
            .extensions_mut()
            .remove_typed::<super::interceptor::AuthContext>();
    }

    /// Returns the registered interceptor chain (br-asupersync-mfk14i).
    ///
    /// Transport adapters that build their own dispatch loop (rather
    /// than calling [`Self::dispatch_unary`]) MUST iterate this slice
    /// in the documented order — registration-order on requests,
    /// reverse-order on responses — or the chain is silently bypassed.
    #[must_use]
    pub fn interceptors(&self) -> &[Arc<dyn Interceptor>] {
        &self.interceptors
    }

    /// Dispatch an inbound unary request through the interceptor
    /// chain and the supplied user handler.
    ///
    /// br-asupersync-mfk14i: this is the canonical entry point that
    /// transport adapters MUST call so the configured interceptors
    /// (auth, rate-limit, tracing, etc.) actually fire. The dispatch
    /// order is:
    ///
    /// 1. Run every interceptor's `intercept_request` in registration
    ///    order. The first error short-circuits the chain — neither
    ///    the remaining request-side interceptors nor the user
    ///    handler run. Request-aware `intercept_error_with_request`
    ///    hooks then unwind in REVERSE order across the interceptors
    ///    that already saw the request so they can inspect
    ///    `AuthContext` and release request-scoped resources before
    ///    the error returns.
    /// 2. Invoke the user handler with the (possibly mutated)
    ///    request.
    /// 3. If the handler succeeds, run every interceptor's
    ///    `intercept_response_with_request` in REVERSE order so
    ///    later layers see the response before earlier ones —
    ///    standard onion semantics. The first response-side error
    ///    aborts further response unwinding, then the
    ///    `intercept_error_with_request` hooks run in REVERSE order
    ///    before the final status is returned.
    /// 4. If the handler errors, the response interceptors do NOT
    ///    run — there is no response to transform. Instead the
    ///    `intercept_error_with_request` hooks run in REVERSE order
    ///    so error-side interceptors still receive the originating
    ///    request context.
    ///
    /// # Errors
    ///
    /// Returns the final error status after reverse-order error hooks run.
    /// Forward request/response processing stops at its first error, but the
    /// applicable `intercept_error_with_request` hooks are still invoked and
    /// may replace that status.
    pub async fn dispatch_unary<H, F>(
        &self,
        mut request: Request<Bytes>,
        handler: H,
    ) -> Result<Response<Bytes>, Status>
    where
        H: FnOnce(Request<Bytes>) -> F,
        F: Future<Output = Result<Response<Bytes>, Status>>,
    {
        // br-asupersync-7u4r72: enforce ServerConfig::max_metadata_size
        // BEFORE the interceptor chain runs. Pre-fix the
        // enforce_metadata_size_limit helper existed (see line ~106)
        // and was documented as 'Transport adapters MUST call this on
        // inbound HEADERS and TRAILERS frames before storing them in
        // long-lived CallContexts', but no callsite within the
        // dispatch path actually invoked it — a transport adapter
        // wired straight into dispatch_unary silently bypassed the
        // 8 KiB cap. Same anti-pattern as the closed asupersync-mfk14i
        // (interceptor chain not invoked in production). Now the cap
        // is the FIRST gate before any per-request work.
        enforce_metadata_size_limit(request.metadata(), self.config.max_metadata_size)?;

        // br-asupersync-s5e129: direct dispatch receives an already-decoded
        // unary body, so enforce the same configured aggregate limit before
        // any interceptor or handler sees it. Transport paths constructed via
        // Server::framed_codec already enforce at the decompressed message
        // boundary; this gate prevents direct dispatch adapters from silently
        // bypassing the policy.
        RequestBodyMeter::from_config(&self.config)
            .record_message_bytes(request.get_ref().len())?;

        // ── Phase 1: request-side chain (registration order). ────────
        // The first error short-circuits without invoking the
        // handler or the response-side chain.
        for (index, interceptor) in self.interceptors.iter().enumerate() {
            if let Err(mut status) = interceptor.intercept_request(&mut request) {
                for cleanup in self.interceptors[..=index].iter().rev() {
                    if let Err(replacement) =
                        cleanup.intercept_error_with_request(&request, &mut status)
                    {
                        status = replacement;
                    }
                }
                // asupersync-gqbtfc: Clear AuthContext to prevent state leakage
                Self::clear_auth_context_from_request(&mut request);
                return Err(status);
            }
        }

        let call_context = CallContext::from_metadata_at_with_max_deadline(
            request.metadata().clone(),
            self.config.default_timeout,
            self.config.max_request_deadline,
            None, // peer_addr
            wall_clock_instant_now(),
        );

        // We retain a borrow of the original request for
        // intercept_response_with_request; the handler consumes the
        // request by value, so we capture the metadata snapshot
        // BEFORE invoking. This matches the AuthInterceptor contract
        // where downstream response-side interceptors may need to
        // read the request that produced the response.
        let mut request_snapshot = request.snapshot(Bytes::new());

        // ── Phase 2: invoke the user handler with deadline enforcement. ─
        // Enforce the effective deadline derived from a parseable peer header or
        // the server fallback. Parseable peer values are capped when configured.
        // Per gRPC spec, an expired client deadline returns DEADLINE_EXCEEDED;
        // the same enforcement path applies to the operator fallback.
        //
        // SECURITY NOTE: This enforcement only works for async operations that yield
        // control. Handlers that perform blocking operations (thread::sleep,
        // blocking I/O, CPU-intensive loops without yield points) cannot be
        // cancelled and will continue running past the deadline. Service
        // implementations should use async APIs and yield regularly to respect
        // client deadlines and prevent resource exhaustion.
        let response_result = if call_context.deadline().is_some() {
            // Sample the runtime clock before the wall clock so translating the
            // wall deadline by its remaining duration cannot shift the runtime
            // deadline later by the sampling overhead.
            let time_now = crate::time::wall_now();
            let now = wall_clock_instant_now();
            let Some(remaining_duration) = call_context.remaining_at(now) else {
                // asupersync-gqbtfc: Clear AuthContext on deadline expiry
                Self::clear_auth_context_from_request(&mut request_snapshot);
                return Err(Status::deadline_exceeded(
                    "Request deadline already expired",
                ));
            };
            // Translate once into the runtime timer's domain and use this
            // exact absolute deadline for both the outer TimeoutFuture and
            // the inclusive inner poll gate. Mixing this virtual/Lab clock
            // with std::Instant would let ready work win at a virtual exact
            // boundary while real wall time was still before std_deadline.
            let runtime_deadline = time_now + remaining_duration;

            // br-asupersync-server-stack-hardening-eeexl1.1.1: install a
            // per-request Cx whose budget carries the effective call deadline,
            // so handlers observe the deadline through
            // `Cx::current().budget()` and request-scoped children see the
            // cancel when the deadline fires. The h2/gRPC hop keeps its
            // existing timeout race and DEADLINE_EXCEEDED mapping.
            let base_budget =
                Cx::current().map_or(crate::types::Budget::INFINITE, |ambient| ambient.budget());
            let source = if grpc_timeout_from_metadata(request.metadata()).is_some() {
                crate::web::request_region::RequestBudgetSource::HeaderClamped
            } else {
                crate::web::request_region::RequestBudgetSource::ServerConfig
            };
            let budget = base_budget.tightened_by_timeout(time_now, remaining_duration);
            let region =
                crate::web::request_region::ServerRequestRegion::mint("h2-grpc", budget, time_now);

            // Race handler vs deadline using the runtime timeout primitive.
            let handler_future = invoke_and_poll_before_inclusive_deadline(
                handler,
                request,
                runtime_deadline,
                crate::time::wall_now,
            );
            match region {
                Some(region) => {
                    let scoped = region.instrumented(source, handler_future);
                    match crate::time::timeout_at(runtime_deadline, scoped).await {
                        Ok(Ok(result)) => {
                            region.finish(if result.is_ok() { "ok" } else { "err" });
                            result
                        }
                        Ok(Err(_)) | Err(_) => {
                            // Deadline exceeded during handler execution:
                            // cancel the request region (children observe it)
                            // before the drop backstop, then map to status.
                            region.cancel_timeout("grpc request deadline exceeded");
                            region.finish("deadline_exceeded");
                            // asupersync-gqbtfc: Clear AuthContext on timeout
                            // to prevent state leakage
                            Self::clear_auth_context_from_request(&mut request_snapshot);
                            return Err(Status::deadline_exceeded("Request deadline exceeded"));
                        }
                    }
                }
                None => {
                    match crate::time::timeout_at(runtime_deadline, handler_future).await {
                        Ok(Ok(result)) => result,
                        Ok(Err(_)) | Err(_) => {
                            // Deadline exceeded during handler execution
                            // asupersync-gqbtfc: Clear AuthContext on timeout to prevent state leakage
                            Self::clear_auth_context_from_request(&mut request_snapshot);
                            return Err(Status::deadline_exceeded("Request deadline exceeded"));
                        }
                    }
                }
            }
        } else {
            // No deadline set, run handler normally
            handler(request).await
        };

        // ── Phase 3: response-side chain (REVERSE order on success). ─
        // On handler error, the response-side chain is NOT invoked
        // (no response object to transform). The handler error seeds
        // the reverse error-hook chain, which may replace the status.
        let mut response = match response_result {
            Ok(response) => response,
            Err(mut status) => {
                for interceptor in self.interceptors.iter().rev() {
                    if let Err(replacement) =
                        interceptor.intercept_error_with_request(&request_snapshot, &mut status)
                    {
                        status = replacement;
                    }
                }
                // asupersync-gqbtfc: Clear AuthContext after handler error to prevent state leakage
                Self::clear_auth_context_from_request(&mut request_snapshot);
                return Err(status);
            }
        };
        for interceptor in self.interceptors.iter().rev() {
            if let Err(mut status) =
                interceptor.intercept_response_with_request(&request_snapshot, &mut response)
            {
                for cleanup in self.interceptors.iter().rev() {
                    if let Err(replacement) =
                        cleanup.intercept_error_with_request(&request_snapshot, &mut status)
                    {
                        status = replacement;
                    }
                }
                // asupersync-gqbtfc: Clear AuthContext after response error to prevent state leakage
                Self::clear_auth_context_from_request(&mut request_snapshot);
                return Err(status);
            }
        }
        Ok(response)
    }

    /// Dispatch a unary request with stream-registration accounting.
    ///
    /// This wrapper registers the stream, enforces the configured in-memory
    /// registration count, and purges stale accounting entries during admission.
    /// It does not close an idle transport stream or schedule a periodic sweep, and
    /// is intended for non-H2 adapters that need this accounting seam. The native
    /// transport returned by [`Server::bind_http2`] instead uses the H2 connection's
    /// authoritative stream state, SETTINGS admission, and timer-driven
    /// RST_STREAM cancellation; duplicating those streams in this registry would
    /// create two competing sources of liveness truth.
    /// (br-asupersync-8vn9iu.)
    ///
    /// # Parameters
    /// - `connection_id`: Unique identifier for the connection (e.g., peer address + port)
    /// - `stream_id`: Unique identifier for the stream within the connection
    /// - `request`: The gRPC request to process
    /// - `handler`: The service handler function
    ///
    /// # Errors
    /// Returns `Status::resource_exhausted` if:
    /// - The connection has too many registration entries (exceeds
    ///   `max_concurrent_streams`)
    /// - Stream registration accounting fails for any other reason
    pub async fn dispatch_unary_with_stream_enforcement<H, F>(
        &self,
        connection_id: String,
        stream_id: u32,
        request: Request<Bytes>,
        handler: H,
    ) -> Result<Response<Bytes>, Status>
    where
        H: FnOnce(Request<Bytes>) -> F,
        F: Future<Output = Result<Response<Bytes>, Status>>,
    {
        // ── Phase 0: stream registration (br-asupersync-8vn9iu). ─────────
        // Enforce the in-memory registration count and purge stale accounting
        // entries BEFORE metadata validation and interceptor execution.
        let registered_at = match self.connection_registry.enforce_stream_limits(
            &connection_id,
            stream_id,
            self.config.max_concurrent_streams,
            self.config.stream_idle_timeout,
        ) {
            Ok(timestamp) => timestamp,
            Err(limit_error) => {
                return Err(Status::resource_exhausted(format!(
                    "stream limit enforcement failed: {}",
                    limit_error
                )));
            }
        };

        // br-asupersync-wix48k: cleanup runs on Drop, not after the
        // await. A pre-fix `registry.remove_stream(...)` placed AFTER
        // `dispatch_unary(...).await` was unreachable when the
        // awaiting future was cancelled mid-handler, leaking the stream
        // registration into active_streams
        // until the next admission-triggered stale-entry purge — a registry
        // exhaustion primitive.
        //
        // SECURITY FIX: The guard now tracks the registration timestamp
        // to prevent race conditions where multiple cleanup operations
        // could attempt to remove the same stream ID.
        let _stream_guard = StreamRegistrationGuard {
            registry: Arc::clone(&self.connection_registry),
            connection_id: connection_id.clone(),
            stream_id,
            registered_at,
        };

        // Dispatch the actual request using the existing logic.
        // Cleanup is performed by `_stream_guard` on Drop, regardless
        // of whether dispatch_unary returns, errors, panics, or is
        // cancelled mid-await.
        self.dispatch_unary(request, handler).await
    }

    /// Update a stream registration's activity timestamp.
    ///
    /// Adapters using the accounting helper may call this when they receive a
    /// frame. It updates state inspected by a later explicit stale-entry purge;
    /// it does not reset a scheduled timer or cancel a transport stream. Native
    /// H2 adapters do not call it because [`Server::bind_http2`] owns activity
    /// deadlines in the transport driver itself.
    /// (br-asupersync-8vn9iu.)
    pub fn update_stream_activity(&self, connection_id: &str, stream_id: u32) {
        self.connection_registry
            .update_stream_activity(connection_id, stream_id);
    }

    /// Get connection/stream registration-accounting statistics.
    ///
    /// Returns `(registered_connections, total_stream_registration_entries)`.
    pub fn get_connection_stats(&self) -> (usize, usize) {
        self.connection_registry.get_stats()
    }

    fn resolve_registered_unary(&self, path: &str) -> Result<Arc<dyn ServiceHandler>, Status> {
        let Some(route) = path.strip_prefix('/') else {
            return Err(Status::unimplemented(format!(
                "unknown gRPC method path '{path}'"
            )));
        };
        let mut segments = route.split('/');
        let (Some(service_name), Some(method_name), None) =
            (segments.next(), segments.next(), segments.next())
        else {
            return Err(Status::unimplemented(format!(
                "unknown gRPC method path '{path}'"
            )));
        };
        if service_name.is_empty() || method_name.is_empty() {
            return Err(Status::unimplemented(format!(
                "unknown gRPC method path '{path}'"
            )));
        }

        let service = self.services.get(service_name).ok_or_else(|| {
            Status::unimplemented(format!("gRPC service '{service_name}' is not registered"))
        })?;
        let method = service
            .descriptor()
            .methods
            .iter()
            .find(|method| method.path == path && method.name == method_name)
            .ok_or_else(|| {
                Status::unimplemented(format!("gRPC method '{path}' is not registered"))
            })?;
        if !method.is_unary() {
            return Err(Status::unimplemented(format!(
                "gRPC method '{path}' is streaming and cannot use unary dispatch"
            )));
        }
        Ok(Arc::clone(service))
    }

    /// Dispatch a decoded unary request to a registered service.
    ///
    /// This is the in-process equivalent of [`Self::bind_registered_http2`].
    /// Route resolution is descriptor-driven and fails closed with gRPC
    /// `UNIMPLEMENTED`; successfully resolved calls pass through the same
    /// metadata, interceptor, deadline, deadline-derived request-region, and
    /// response pipeline as [`Self::dispatch_unary`]. The supplied `cx` is
    /// installed for every poll, so its cancellation and capability
    /// restrictions remain authoritative even when the future moves between
    /// runtime workers.
    pub async fn dispatch_registered_unary(
        &self,
        cx: &Cx,
        path: &str,
        request: Request<Bytes>,
    ) -> Result<Response<Bytes>, Status> {
        self.dispatch_registered_unary_with_trailers(cx, path, request, Metadata::new())
            .await
    }

    /// Dispatch a decoded unary request while preserving its separate request
    /// trailer metadata block.
    pub async fn dispatch_registered_unary_with_trailers(
        &self,
        cx: &Cx,
        path: &str,
        request: Request<Bytes>,
        trailing_metadata: Metadata,
    ) -> Result<Response<Bytes>, Status> {
        if cx.checkpoint().is_err() {
            let status = match cx.cancel_reason().map(|reason| reason.kind) {
                Some(crate::types::CancelKind::Timeout | crate::types::CancelKind::Deadline) => {
                    Status::deadline_exceeded(
                        "registered gRPC request deadline elapsed before dispatch",
                    )
                }
                Some(
                    crate::types::CancelKind::PollQuota | crate::types::CancelKind::CostBudget,
                ) => Status::resource_exhausted(
                    "registered gRPC request budget was exhausted before dispatch",
                ),
                _ => Status::cancelled("registered gRPC request was cancelled before dispatch"),
            };
            return Err(status);
        }
        let service = self.resolve_registered_unary(path)?;
        let path = path.to_owned();
        let base_cx = cx.clone();
        let dispatch = self.dispatch_unary(request, move |request| async move {
            // The outer poll scope below guarantees an explicit context. If a
            // gRPC deadline is present, `dispatch_unary` temporarily installs
            // its tighter child request region before this future is polled.
            let call_cx = Cx::current().unwrap_or_else(|| base_cx.clone());
            service
                .call_unary(&call_cx, &path, request, trailing_metadata)
                .await
        });
        poll_with_current_cx(cx.clone(), dispatch).await
    }

    /// Get a service by name.
    #[must_use]
    pub fn get_service(&self, name: &str) -> Option<&Arc<dyn ServiceHandler>> {
        self.services.get(name)
    }

    /// Returns the list of service names.
    pub fn service_names(&self) -> Vec<&str> {
        self.services.keys().map(String::as_str).collect()
    }

    /// Validate server readiness and perform a bind-probe on the given address.
    ///
    /// This verifies that:
    /// - At least one service is registered
    /// - The listen address parses as a socket address
    /// - The process can bind a listener at that address
    ///
    /// The listener is immediately dropped after validation. Use
    /// [`Self::serve_http2`] to bind, route registered services, and run the
    /// production native HTTP/2 listener, or [`Self::bind_registered_http2`]
    /// when the caller needs its shutdown handle before running it. This
    /// legacy probe remains functional for v0.4.3 compatibility but does not
    /// accept or dispatch requests.
    #[allow(clippy::unused_async)]
    pub async fn serve(self, addr: &str) -> Result<(), GrpcError> {
        if self.services.is_empty() {
            return Err(GrpcError::protocol(
                "cannot serve gRPC server without registered services",
            ));
        }
        // Accept both numeric socket addresses and hostname forms like localhost:50051.
        let listener = std::net::TcpListener::bind(addr).map_err(|error| {
            GrpcError::transport_kind(
                TransportErrorKind::from_io_error_kind(error.kind()),
                format!("bind failed: {error}"),
            )
        })?;
        listener.set_nonblocking(true).map_err(|error| {
            GrpcError::transport_kind(
                TransportErrorKind::from_io_error_kind(error.kind()),
                format!("nonblocking setup failed: {error}"),
            )
        })?;
        Ok(())
    }
}

/// Parse a gRPC timeout header value into a [`Duration`].
///
/// The gRPC timeout format is `<value><unit>` where unit is one of:
/// - `H` = hours
/// - `M` = minutes
/// - `S` = seconds
/// - `m` = milliseconds
/// - `u` = microseconds
/// - `n` = nanoseconds
///
/// Returns `None` for malformed values.
#[must_use]
pub fn parse_grpc_timeout(header: &str) -> Option<Duration> {
    if header.is_empty() {
        return None;
    }
    // Prevent panic on non-ASCII characters by checking if it's purely ASCII.
    // The gRPC spec requires digits followed by an ASCII unit character.
    if !header.is_ascii() {
        return None;
    }
    let (digits, unit) = header.split_at(header.len() - 1);
    // gRPC TimeoutValue is 1..=8 ASCII DIGIT bytes. `u64::from_str` also
    // accepts a leading `+`, so validate the grammar before parsing instead
    // of treating `+1S` as a legitimate peer deadline.
    if digits.is_empty() || digits.len() > 8 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let value: u64 = digits.parse().ok()?;
    match unit {
        "H" => Some(Duration::from_secs(value.checked_mul(3600)?)),
        "M" => Some(Duration::from_secs(value.checked_mul(60)?)),
        "S" => Some(Duration::from_secs(value)),
        "m" => Some(Duration::from_millis(value)),
        "u" => Some(Duration::from_micros(value)),
        "n" => Some(Duration::from_nanos(value)),
        _ => None,
    }
}

fn grpc_timeout_from_metadata(metadata: &Metadata) -> Option<Duration> {
    match metadata.get("grpc-timeout") {
        Some(super::streaming::MetadataValue::Ascii(value)) => parse_grpc_timeout(value),
        Some(super::streaming::MetadataValue::Binary(_)) | None => None,
    }
}

/// Format a [`Duration`] as a gRPC timeout header value.
///
/// Selects the most appropriate unit to preserve precision while
/// staying within the gRPC 8-digit limit.
#[must_use]
pub fn format_grpc_timeout(duration: Duration) -> String {
    const MAX_VALUE: u128 = 99_999_999;
    let ns = duration.as_nanos();
    if ns == 0 {
        return "0n".to_string();
    }
    // Prefer the largest lossless unit that fits within the 8-digit limit.
    // This matches gRPC convention (Go/Java prefer coarser units).
    let secs = u128::from(duration.as_secs());
    if duration.subsec_nanos() == 0 {
        let hours = secs / 3600;
        if hours <= MAX_VALUE && secs % 3600 == 0 {
            return format!("{hours}H");
        }
        let mins = secs / 60;
        if mins <= MAX_VALUE && secs % 60 == 0 {
            return format!("{mins}M");
        }
        if secs <= MAX_VALUE {
            return format!("{secs}S");
        }
    }
    let ms = duration.as_millis();
    if ms <= MAX_VALUE && ns.is_multiple_of(1_000_000) {
        return format!("{ms}m");
    }
    let us = duration.as_micros();
    if us <= MAX_VALUE && ns.is_multiple_of(1_000) {
        return format!("{us}u");
    }
    if ns <= MAX_VALUE {
        return format!("{ns}n");
    }
    // Fallback: truncate to the largest unit that fits.
    if us <= MAX_VALUE {
        return format!("{us}u");
    }
    if ms <= MAX_VALUE {
        return format!("{ms}m");
    }
    if secs <= MAX_VALUE {
        return format!("{secs}S");
    }
    let mins = secs / 60;
    if mins <= MAX_VALUE {
        return format!("{mins}M");
    }
    let hours = (mins / 60).min(MAX_VALUE);
    format!("{hours}H")
}

/// A gRPC call context.
///
/// Use [`CallContext::with_cx`] to attach a capability context for
/// effect-safe handlers.
#[derive(Debug)]
pub struct CallContext {
    /// Request metadata.
    metadata: Metadata,
    /// Deadline for the call.
    deadline: Option<Instant>,
    /// Peer address.
    peer_addr: Option<String>,
    /// Clock source used by deadline helpers that do not take an explicit time.
    time_getter: fn() -> Instant,
}

impl CallContext {
    /// Create a new call context.
    #[must_use]
    pub fn new() -> Self {
        Self {
            metadata: Metadata::new(),
            deadline: None,
            peer_addr: None,
            time_getter: wall_clock_instant_now,
        }
    }

    /// Create a call context from incoming request metadata.
    ///
    /// Parses the `grpc-timeout` header to derive the deadline. If a
    /// timeout header is present and parseable, it determines the deadline.
    /// Otherwise, `default_timeout` is used when provided. This prevents a
    /// malformed peer value from disabling the server's configured bound.
    #[must_use]
    pub fn from_metadata(
        metadata: Metadata,
        default_timeout: Option<Duration>,
        peer_addr: Option<String>,
    ) -> Self {
        Self::from_metadata_with_time_getter(
            metadata,
            default_timeout,
            peer_addr,
            wall_clock_instant_now,
        )
    }

    /// Create a call context from incoming request metadata with a custom time source.
    ///
    /// This preserves the default ergonomics while allowing deterministic callers to
    /// control deadline helpers like [`Self::remaining`] and [`Self::is_expired`].
    #[must_use]
    pub fn from_metadata_with_time_getter(
        metadata: Metadata,
        default_timeout: Option<Duration>,
        peer_addr: Option<String>,
        time_getter: fn() -> Instant,
    ) -> Self {
        Self::from_metadata_at(metadata, default_timeout, peer_addr, time_getter())
            .with_time_getter(time_getter)
    }

    /// Create a call context from incoming request metadata using an explicit
    /// clock sample.
    ///
    /// br-asupersync-02f7vx: callers in replay/test harnesses MUST chain
    /// [`Self::with_time_getter`] after this constructor to install a
    /// deterministic time source. Pre-fix the docstring claimed this was
    /// "useful for deterministic tests and replay harnesses that need to
    /// avoid ambient wall-clock reads", but the returned `CallContext`'s
    /// `time_getter` was hardcoded to `wall_clock_instant_now` — the
    /// `now` parameter pinned the deadline computation but every
    /// subsequent `is_expired` / `remaining` / `timeout_header_value`
    /// call read the ambient wall clock. Replays of the same recorded
    /// scenario produced divergent expiry verdicts.
    ///
    /// The fix: the returned `CallContext` now retains
    /// `wall_clock_instant_now` ONLY as a fall-through default —
    /// **callers in replay paths MUST chain `.with_time_getter(getter)`**
    /// to install their virtual-clock closure (function-pointer
    /// `fn() -> Instant`). The companion constructor
    /// [`Self::from_metadata_with_time_getter`] does this composition
    /// correctly and is the preferred entry point for replay harnesses.
    #[must_use]
    pub fn from_metadata_at(
        metadata: Metadata,
        default_timeout: Option<Duration>,
        peer_addr: Option<String>,
        now: Instant,
    ) -> Self {
        // Back-compat: no server-side max-deadline cap. Forwards
        // to the new `_with_max_deadline` variant with cap=None.
        Self::from_metadata_at_with_max_deadline(metadata, default_timeout, None, peer_addr, now)
    }

    /// tick #139: variant of [`Self::from_metadata_at`] that accepts a
    /// server-side maximum request deadline. When `max_request_deadline`
    /// is `Some(cap)`, every parseable peer-supplied `grpc-timeout` is clamped
    /// via `min(peer_timeout, cap)` so a hostile peer cannot choose an
    /// impractically distant representable deadline such as
    /// `grpc-timeout: 99999999H` (≈11,400 years).
    ///
    /// The cap does NOT affect the absent- or malformed-header fallback to
    /// `default_timeout` — that path still applies the configured default.
    /// Callers that want a tighter ceiling on the default should set
    /// `default_timeout` itself.
    ///
    /// A timeout that cannot be represented as `now + timeout` expires at
    /// `now`; arithmetic overflow never disables deadline enforcement.
    ///
    /// Wired from [`ServerConfig::max_request_deadline`].
    #[must_use]
    pub fn from_metadata_at_with_max_deadline(
        metadata: Metadata,
        default_timeout: Option<Duration>,
        max_request_deadline: Option<Duration>,
        peer_addr: Option<String>,
        now: Instant,
    ) -> Self {
        let peer_timeout = grpc_timeout_from_metadata(&metadata);
        // Clamp only a valid peer timeout. Absent or malformed peer metadata
        // falls back to the operator-selected default, which is deliberately
        // independent of the peer-timeout cap.
        let timeout = peer_timeout
            .map(|peer| max_request_deadline.map_or(peer, |cap| peer.min(cap)))
            .or(default_timeout);
        // Treat an unrepresentable timeout as already expired. Falling back to
        // `None` here would turn an oversized configured bound into no bound.
        let deadline = timeout.map(|t| now.checked_add(t).unwrap_or(now));
        Self {
            metadata,
            deadline,
            peer_addr,
            // br-asupersync-02f7vx: default; replay callers MUST chain
            // `.with_time_getter(...)`. Production callers without a
            // virtual clock are correct to use wall-clock here.
            time_getter: wall_clock_instant_now,
        }
    }

    /// Create a call context with an explicit deadline.
    #[must_use]
    pub fn with_deadline(deadline: Instant) -> Self {
        Self {
            metadata: Metadata::new(),
            deadline: Some(deadline),
            peer_addr: None,
            time_getter: wall_clock_instant_now,
        }
    }

    /// Override the time source used by [`Self::remaining`] and [`Self::is_expired`].
    #[must_use]
    pub const fn with_time_getter(mut self, time_getter: fn() -> Instant) -> Self {
        self.time_getter = time_getter;
        self
    }

    /// Returns the time source used by deadline helpers that do not take an explicit time.
    #[must_use]
    pub const fn time_getter(&self) -> fn() -> Instant {
        self.time_getter
    }

    /// Get the request metadata.
    #[must_use]
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Get the deadline.
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Get the peer address.
    #[must_use]
    pub fn peer_addr(&self) -> Option<&str> {
        self.peer_addr.as_deref()
    }

    /// Returns the remaining time until the deadline, or `None` if no
    /// deadline is set or it has already expired.
    #[must_use]
    pub fn remaining(&self) -> Option<Duration> {
        self.remaining_at((self.time_getter)())
    }

    /// Returns remaining time to deadline using an explicit clock sample.
    #[must_use]
    pub fn remaining_at(&self, now: Instant) -> Option<Duration> {
        self.deadline.and_then(|deadline| {
            deadline
                .checked_duration_since(now)
                .filter(|remaining| !remaining.is_zero())
        })
    }

    /// Formats the remaining deadline as a `grpc-timeout` header value.
    ///
    /// Expired deadlines propagate as `0n` so downstream calls fail fast
    /// instead of silently running unbounded.
    #[must_use]
    pub fn timeout_header_value(&self) -> Option<String> {
        self.timeout_header_value_at((self.time_getter)())
    }

    /// Formats the remaining deadline as a `grpc-timeout` header value using
    /// an explicit clock sample.
    #[must_use]
    pub fn timeout_header_value_at(&self, now: Instant) -> Option<String> {
        self.deadline
            .map(|deadline| format_grpc_timeout(deadline.saturating_duration_since(now)))
    }

    /// Attenuates and writes the effective `grpc-timeout` into outbound metadata.
    ///
    /// If outbound metadata already contains a `grpc-timeout`, the effective
    /// propagated value is the tighter of the existing timeout and this call's
    /// remaining deadline.
    ///
    /// Returns `true` when a timeout header was written.
    pub fn propagate_timeout_to(&self, metadata: &mut Metadata) -> bool {
        self.propagate_timeout_to_at(metadata, (self.time_getter)())
    }

    /// Attenuates and writes the effective `grpc-timeout` into outbound metadata
    /// using an explicit clock sample.
    ///
    /// Expired deadlines are forwarded as `0n`.
    pub fn propagate_timeout_to_at(&self, metadata: &mut Metadata, now: Instant) -> bool {
        let Some(parent_remaining) = self
            .deadline
            .map(|deadline| deadline.saturating_duration_since(now))
        else {
            return false;
        };

        let effective = match metadata.get("grpc-timeout") {
            Some(super::streaming::MetadataValue::Ascii(existing)) => parse_grpc_timeout(existing)
                .map_or(parent_remaining, |child| child.min(parent_remaining)),
            Some(super::streaming::MetadataValue::Binary(_)) | None => parent_remaining,
        };
        let _ = metadata.insert_or_replace("grpc-timeout", format_grpc_timeout(effective));
        true
    }

    /// Check if the deadline has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.is_expired_at((self.time_getter)())
    }

    /// Check if deadline is expired using an explicit clock sample.
    #[must_use]
    pub fn is_expired_at(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
    }

    /// Attach a capability context to this call.
    ///
    /// This is a lightweight wrapper that exposes `Cx` access without
    /// granting additional authority beyond what the caller provides.
    #[must_use]
    pub fn with_cx<'a>(&'a self, cx: &'a Cx) -> CallContextWithCx<'a> {
        CallContextWithCx { call: self, cx }
    }
}

impl Default for CallContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Call context with an attached capability context.
///
/// This wrapper is intended for framework integrations that need to thread
/// `Cx` through gRPC handlers while retaining the base call metadata.
///
/// ```ignore
/// use asupersync::cx::cap::CapSet;
/// use asupersync::grpc::CallContext;
///
/// type GrpcCaps = CapSet<true, true, false, false, false>;
///
/// fn handle(ctx: &CallContext, cx: &asupersync::Cx) {
///     let ctx = ctx.with_cx(cx);
///     let limited = ctx.cx_narrow::<GrpcCaps>();
///     limited.checkpoint().ok();
/// }
/// ```
pub struct CallContextWithCx<'a> {
    call: &'a CallContext,
    cx: &'a Cx,
}

impl CallContextWithCx<'_> {
    /// Returns the underlying call context.
    #[must_use]
    pub fn call(&self) -> &CallContext {
        self.call
    }
    /// Returns the underlying call metadata.
    #[must_use]
    pub fn metadata(&self) -> &Metadata {
        self.call.metadata()
    }

    /// Returns the call deadline, if set.
    #[must_use]
    pub fn deadline(&self) -> Option<std::time::Instant> {
        self.call.deadline()
    }

    /// Returns the peer address, if available.
    #[must_use]
    pub fn peer_addr(&self) -> Option<&str> {
        self.call.peer_addr()
    }

    /// Returns true if the call deadline has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.call.is_expired()
    }

    /// Returns the remaining time until the deadline, or `None` if no
    /// deadline is set or it has already expired.
    #[must_use]
    pub fn remaining(&self) -> Option<Duration> {
        self.call.remaining()
    }

    /// Formats the remaining deadline as a `grpc-timeout` header value.
    #[must_use]
    pub fn timeout_header_value(&self) -> Option<String> {
        self.call.timeout_header_value()
    }

    /// Attenuates and writes the effective `grpc-timeout` into outbound metadata.
    pub fn propagate_timeout_to(&self, metadata: &mut Metadata) -> bool {
        self.call.propagate_timeout_to(metadata)
    }

    /// Returns the full capability context.
    #[must_use]
    pub fn cx(&self) -> &Cx {
        self.cx
    }

    /// Returns a narrowed capability context (least privilege).
    #[must_use]
    pub fn cx_narrow<Caps>(&self) -> Cx<Caps>
    where
        Caps: cap::SubsetOf<cap::All>,
    {
        self.cx.restrict::<Caps>()
    }

    /// Returns a fully restricted context (no capabilities).
    #[must_use]
    pub fn cx_readonly(&self) -> Cx<cap::None> {
        self.cx.restrict::<cap::None>()
    }
}

/// Interceptor for processing requests and responses.
pub trait Interceptor: Send + Sync {
    /// Intercept a request before it is processed.
    fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status>;

    /// Intercept a response before it is sent.
    fn intercept_response(&self, response: &mut Response<Bytes>) -> Result<(), Status>;

    /// Intercept a response when the originating request metadata is available.
    ///
    /// Interceptors that need request context for response shaping can override
    /// this method. The default behavior preserves the existing response-only
    /// interception contract.
    fn intercept_response_with_request(
        &self,
        request: &Request<Bytes>,
        response: &mut Response<Bytes>,
    ) -> Result<(), Status> {
        let _ = request;
        self.intercept_response(response)
    }

    /// Observe or rewrite an error status when the originating request
    /// is available.
    ///
    /// This runs on request-rejection, handler-error, and response-hook
    /// error paths after the request-side chain has already populated any
    /// typed extensions such as `AuthContext`. Interceptors that need to
    /// release request-scoped resources or inspect auth context on failures
    /// override this hook.
    ///
    /// **SECURITY NOTE**: Implementations MUST NOT retain references to
    /// sensitive data from request extensions (like AuthContext) beyond
    /// the scope of this method. The framework automatically clears auth
    /// state after all error interceptors complete to prevent state leakage.
    ///
    /// Returning `Err(new_status)` replaces the current status and
    /// continues unwinding through the remaining interceptors.
    fn intercept_error_with_request(
        &self,
        request: &Request<Bytes>,
        status: &mut Status,
    ) -> Result<(), Status> {
        let _ = (request, status);
        Ok(())
    }
}

/// A no-op interceptor that passes through all requests.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopInterceptor;

impl Interceptor for NoopInterceptor {
    fn intercept_request(&self, _request: &mut Request<Bytes>) -> Result<(), Status> {
        Ok(())
    }

    fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
        Ok(())
    }
}

/// Authentication interceptor.
#[derive(Debug)]
pub struct AuthInterceptor<F> {
    /// The validation function.
    validator: F,
}

impl<F> AuthInterceptor<F>
where
    F: Fn(&Metadata) -> Result<(), Status> + Send + Sync,
{
    /// Create a new authentication interceptor.
    #[must_use]
    pub fn new(validator: F) -> Self {
        Self { validator }
    }
}

impl<F> Interceptor for AuthInterceptor<F>
where
    F: Fn(&Metadata) -> Result<(), Status> + Send + Sync,
{
    fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        (self.validator)(request.metadata())
    }

    fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
        Ok(())
    }
}

/// Unary service handler function type.
pub type UnaryHandler<Req, Resp> =
    Box<dyn Fn(Request<Req>) -> UnaryFuture<Resp> + Send + Sync + 'static>;

/// Future type for unary handlers.
pub type UnaryFuture<Resp> =
    Pin<Box<dyn Future<Output = Result<Response<Resp>, Status>> + Send + 'static>>;

/// Utility function to create an OK response.
pub fn ok<T>(message: T) -> Result<Response<T>, Status> {
    Ok(Response::new(message))
}

/// Utility function to create a status error.
pub fn err<T>(status: Status) -> Result<Response<T>, Status> {
    Err(status)
}

#[cfg(test)]
include!("server_tests.rs");
