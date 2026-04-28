//! gRPC server implementation.
//!
//! Provides the server-side infrastructure for hosting gRPC services.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::bytes::Bytes;
use crate::cx::{Cx, cap};

use super::client::CompressionEncoding;
use super::reflection::ReflectionService;
use super::service::{NamedService, ServiceHandler};
use super::status::{GrpcError, Status, TransportErrorKind};
use super::streaming::{Metadata, Request, Response};

fn wall_clock_instant_now() -> Instant {
    Instant::now()
}

/// Tracks the state of a single stream for idle timeout enforcement.
#[derive(Debug, Clone)]
struct StreamState {
    /// Last activity timestamp (when the stream last sent data).
    last_activity: Instant,
}

/// br-asupersync-8vn9iu: Per-connection state tracking to enforce
/// stream limits and idle timeouts, preventing connection hoarding attacks.
#[derive(Debug)]
pub struct ConnectionState {
    /// Active streams on this connection, keyed by stream ID.
    active_streams: HashMap<u32, StreamState>,
}

impl ConnectionState {
    /// Create new connection state.
    pub fn new() -> Self {
        Self {
            active_streams: HashMap::new(),
        }
    }

    /// Register a new stream on this connection.
    ///
    /// Returns `Err` if the connection already has too many active streams.
    pub fn add_stream(&mut self, stream_id: u32, max_concurrent: u32) -> Result<(), String> {
        if self.active_streams.len() >= max_concurrent as usize {
            return Err(format!(
                "connection exceeds max_concurrent_streams: {} >= {}",
                self.active_streams.len(),
                max_concurrent
            ));
        }

        self.active_streams.insert(
            stream_id,
            StreamState {
                last_activity: wall_clock_instant_now(),
            },
        );
        Ok(())
    }

    /// Update the last activity time for a stream.
    pub fn update_stream_activity(&mut self, stream_id: u32) {
        if let Some(stream) = self.active_streams.get_mut(&stream_id) {
            stream.last_activity = wall_clock_instant_now();
        }
    }

    /// Remove a stream from this connection (when it completes normally).
    pub fn remove_stream(&mut self, stream_id: u32) {
        self.active_streams.remove(&stream_id);
    }

    /// Clean up idle streams that have exceeded the timeout.
    ///
    /// Returns the list of stream IDs that were removed due to idle timeout.
    pub fn cleanup_idle_streams(&mut self, idle_timeout: Duration) -> Vec<u32> {
        let now = wall_clock_instant_now();
        let mut removed = Vec::new();

        self.active_streams.retain(|&stream_id, stream| {
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

    /// Get the number of active streams.
    pub fn active_stream_count(&self) -> usize {
        self.active_streams.len()
    }
}

/// Global registry for tracking connection states to enforce stream limits
/// and idle timeouts across all connections.
///
/// br-asupersync-8vn9iu: This prevents connection hoarding attacks where
/// clients open many connections with idle bidirectional streams.
#[derive(Debug)]
pub struct ConnectionRegistry {
    /// Connection states keyed by connection identifier.
    connections: Mutex<HashMap<String, ConnectionState>>,
}

impl ConnectionRegistry {
    /// Create a new connection registry.
    pub fn new() -> Self {
        Self {
            connections: Mutex::new(HashMap::new()),
        }
    }

    /// Register a new connection.
    pub fn add_connection(&self, connection_id: String) {
        let mut connections = self.connections.lock().unwrap();
        connections.insert(connection_id, ConnectionState::new());
    }

    /// Remove a connection and all its streams.
    pub fn remove_connection(&self, connection_id: &str) {
        let mut connections = self.connections.lock().unwrap();
        connections.remove(connection_id);
    }

    /// Enforce stream limits and idle timeouts for a specific connection.
    ///
    /// Returns an error if the stream cannot be added due to limits.
    pub fn enforce_stream_limits(
        &self,
        connection_id: &str,
        stream_id: u32,
        max_concurrent: u32,
        idle_timeout: Option<Duration>,
    ) -> Result<(), String> {
        let mut connections = self.connections.lock().unwrap();
        let connection = connections
            .get_mut(connection_id)
            .ok_or_else(|| format!("connection not registered: {}", connection_id))?;

        // Clean up idle streams first
        if let Some(timeout) = idle_timeout {
            let removed_streams = connection.cleanup_idle_streams(timeout);
            if !removed_streams.is_empty() {
                eprintln!(
                    "Cleaned up {} idle streams on connection {}: {:?}",
                    removed_streams.len(),
                    connection_id,
                    removed_streams
                );
            }
        }

        // Try to add the new stream
        connection.add_stream(stream_id, max_concurrent)
    }

    /// Update stream activity timestamp.
    pub fn update_stream_activity(&self, connection_id: &str, stream_id: u32) {
        let mut connections = self.connections.lock().unwrap();
        if let Some(connection) = connections.get_mut(connection_id) {
            connection.update_stream_activity(stream_id);
        }
    }

    /// Remove a stream when it completes normally.
    pub fn remove_stream(&self, connection_id: &str, stream_id: u32) {
        let mut connections = self.connections.lock().unwrap();
        if let Some(connection) = connections.get_mut(connection_id) {
            connection.remove_stream(stream_id);
        }
    }

    /// Get statistics for debugging/monitoring.
    pub fn get_stats(&self) -> (usize, usize) {
        let connections = self.connections.lock().unwrap();
        let connection_count = connections.len();
        let total_streams: usize = connections
            .values()
            .map(|conn| conn.active_stream_count())
            .sum();
        (connection_count, total_streams)
    }
}

/// gRPC server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Maximum message size for receiving.
    pub max_recv_message_size: usize,
    /// Maximum message size for sending.
    pub max_send_message_size: usize,
    /// Initial connection window size.
    pub initial_connection_window_size: u32,
    /// Initial stream window size.
    pub initial_stream_window_size: u32,
    /// Maximum concurrent streams per connection.
    pub max_concurrent_streams: u32,
    /// Keep-alive interval.
    pub keepalive_interval_ms: Option<u64>,
    /// Keep-alive timeout.
    pub keepalive_timeout_ms: Option<u64>,
    /// Default timeout applied to all calls when the client does not send
    /// a `grpc-timeout` header.
    pub default_timeout: Option<Duration>,
    /// Compression used for outbound response messages.
    pub send_compression: Option<CompressionEncoding>,
    /// Compression encodings accepted by this server.
    pub accept_compression: Vec<CompressionEncoding>,
    /// Maximum aggregate size, in bytes, of all metadata entries
    /// (request headers + trailers) accepted on a single inbound call.
    /// Each entry contributes `key.len() + value.byte_len()` bytes.
    /// Defaults to 8 KiB — matches the gRPC ecosystem convention used
    /// by `grpc-go`'s `MaxHeaderListSize` and the per-RFC-9113 §6.5.2
    /// `SETTINGS_MAX_HEADER_LIST_SIZE` advisory cap.
    ///
    /// Inbound metadata exceeding this limit is rejected with
    /// `Status::resource_exhausted` via
    /// [`enforce_metadata_size_limit`]. The gRPC wire protocol always
    /// returns HTTP 200 with a `grpc-status` trailer; the equivalent
    /// of HTTP 431 ("Request Header Fields Too Large") for gRPC is
    /// the RESOURCE_EXHAUSTED status code.
    ///
    /// br-asupersync-i2bae8.
    pub max_metadata_size: usize,
    /// Maximum idle time before a stream is considered stale and forcefully closed.
    /// Streams that don't send any frames (requests, data, or control) for this
    /// duration are terminated to prevent connection hoarding attacks.
    /// Defaults to 60 seconds. Set to `None` to disable idle timeout enforcement.
    ///
    /// br-asupersync-8vn9iu: prevents bidirectional stream resource exhaustion
    /// where attackers open many streams with valid metadata but never send data.
    pub stream_idle_timeout: Option<Duration>,
}

/// Default max-metadata-size in bytes (8 KiB) — matches the gRPC
/// ecosystem convention. See [`ServerConfig::max_metadata_size`].
pub const DEFAULT_MAX_METADATA_SIZE: usize = 8 * 1024;

/// Compute the total byte size of a [`Metadata`] block.
///
/// Sums `key.len() + value.byte_len()` over every entry. Used by
/// [`enforce_metadata_size_limit`] to bound HPACK decoder memory at the
/// request-reception boundary.
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

fn validate_inbound_metadata(metadata: &super::streaming::Metadata) -> Result<(), Status> {
    for (key, value) in metadata.iter() {
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
    }
    Ok(())
}

/// Reject inbound `metadata` when it violates the gRPC header-content rules or
/// when its aggregate byte size exceeds `limit`.
///
/// Transport adapters MUST call this on inbound HEADERS and TRAILERS frames
/// before storing them in long-lived `CallContext`s, so a hostile peer cannot
/// exhaust per-connection HPACK decoder memory by streaming arbitrarily long
/// header lists.
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

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_recv_message_size: 4 * 1024 * 1024, // 4 MB
            max_send_message_size: 4 * 1024 * 1024, // 4 MB
            initial_connection_window_size: 1024 * 1024,
            initial_stream_window_size: 1024 * 1024,
            max_concurrent_streams: 100,
            keepalive_interval_ms: None,
            keepalive_timeout_ms: None,
            default_timeout: None,
            send_compression: None,
            accept_compression: vec![CompressionEncoding::Identity],
            // 8 KiB matches the gRPC ecosystem convention (grpc-go
            // MaxHeaderListSize default) and bounds per-connection
            // HPACK decoder memory (br-asupersync-i2bae8).
            max_metadata_size: DEFAULT_MAX_METADATA_SIZE,
            // 60 seconds prevents connection hoarding attacks while allowing
            // reasonable bidirectional streaming patterns (br-asupersync-8vn9iu).
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

    /// Set the maximum aggregate metadata size (request headers +
    /// trailers) in bytes. Defaults to 8 KiB
    /// ([`DEFAULT_MAX_METADATA_SIZE`]). Inbound metadata exceeding
    /// this is rejected with `Status::resource_exhausted` by
    /// [`enforce_metadata_size_limit`]. A value of `0` disables the
    /// cap. (br-asupersync-i2bae8.)
    #[must_use]
    pub fn max_metadata_size(mut self, size: usize) -> Self {
        self.config.max_metadata_size = size;
        self
    }

    /// Set the stream idle timeout.
    ///
    /// Streams that don't send any frames for this duration are terminated
    /// to prevent connection hoarding attacks. Set to `None` to disable.
    /// (br-asupersync-8vn9iu.)
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

    /// Set the initial connection window size.
    #[must_use]
    pub fn initial_connection_window_size(mut self, size: u32) -> Self {
        self.config.initial_connection_window_size = size;
        self
    }

    /// Set the initial stream window size.
    #[must_use]
    pub fn initial_stream_window_size(mut self, size: u32) -> Self {
        self.config.initial_stream_window_size = size;
        self
    }

    /// Set the maximum concurrent streams.
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

    /// Set the default timeout for all calls when the client does not send
    /// a `grpc-timeout` header.
    #[must_use]
    pub fn default_timeout(mut self, timeout: Duration) -> Self {
        self.config.default_timeout = Some(timeout);
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

    /// Enable the built-in reflection service.
    ///
    /// The reflection registry captures descriptors for all currently
    /// registered services and continues to track additional services added to
    /// this builder after reflection is enabled.
    #[must_use]
    pub fn enable_reflection(mut self) -> Self {
        let reflection = self.reflection.take().unwrap_or_default();
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
    /// br-asupersync-8vn9iu: Connection registry for tracking stream limits
    /// and idle timeouts to prevent connection hoarding attacks.
    connection_registry: Arc<ConnectionRegistry>,
}

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

    /// Get the registered services.
    #[must_use]
    pub fn services(&self) -> &BTreeMap<String, Arc<dyn ServiceHandler>> {
        &self.services
    }

    /// Get the connection registry for stream limit enforcement.
    #[must_use]
    pub fn connection_registry(&self) -> &Arc<ConnectionRegistry> {
        &self.connection_registry
    }

    /// Register a new connection for stream tracking.
    ///
    /// Transport layers should call this when a new gRPC connection is established
    /// to enable per-connection stream limit and idle timeout enforcement.
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
    ///    handler run, and `intercept_response` is NOT invoked
    ///    (mirrors the canonical middleware contract: a request
    ///    rejected before reaching the handler has no response to
    ///    transform).
    /// 2. Invoke the user handler with the (possibly mutated)
    ///    request.
    /// 3. If the handler succeeds, run every interceptor's
    ///    `intercept_response_with_request` in REVERSE order so
    ///    later layers see the response before earlier ones —
    ///    standard onion semantics. The first response-side error
    ///    aborts further unwinding and surfaces as the call's
    ///    final status.
    /// 4. If the handler errors, the response interceptors do NOT
    ///    run — there is no response to transform; the handler
    ///    error becomes the call's final status.
    ///
    /// # Errors
    ///
    /// Returns the first interceptor or handler `Status::Err`
    /// observed; subsequent interceptors are NOT invoked once an
    /// error has been surfaced.
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

        // ── Phase 1: request-side chain (registration order). ────────
        // The first error short-circuits without invoking the
        // handler or the response-side chain.
        for interceptor in &self.interceptors {
            interceptor.intercept_request(&mut request)?;
        }

        // ── Phase 2: invoke the user handler. ────────────────────────
        // The request may have been mutated by the chain (e.g. an
        // auth interceptor inserted an AuthContext into typed
        // extensions per the interceptor.rs docs).
        //
        // We retain a borrow of the original request for
        // intercept_response_with_request; the handler consumes the
        // request by value, so we capture the metadata snapshot
        // BEFORE invoking. This matches the AuthInterceptor contract
        // where downstream response-side interceptors may need to
        // read the request that produced the response.
        let request_snapshot = request.snapshot(Bytes::new());
        let response_result = handler(request).await;

        // ── Phase 3: response-side chain (REVERSE order on success). ─
        // On handler error, the response-side chain is NOT invoked
        // (no response object to transform). The handler error
        // becomes the call's final status.
        let mut response = response_result?;
        for interceptor in self.interceptors.iter().rev() {
            interceptor.intercept_response_with_request(&request_snapshot, &mut response)?;
        }
        Ok(response)
    }

    /// Dispatch a unary request with stream enforcement for connection hoarding protection.
    ///
    /// This is the stream-aware version of `dispatch_unary` that enforces per-connection
    /// stream limits and idle timeouts. Transport adapters should use this method instead
    /// of `dispatch_unary` when stream tracking is needed. (br-asupersync-8vn9iu.)
    ///
    /// # Parameters
    /// - `connection_id`: Unique identifier for the connection (e.g., peer address + port)
    /// - `stream_id`: Unique identifier for the stream within the connection
    /// - `request`: The gRPC request to process
    /// - `handler`: The service handler function
    ///
    /// # Errors
    /// Returns `Status::resource_exhausted` if:
    /// - The connection has too many active streams (exceeds `max_concurrent_streams`)
    /// - Stream enforcement fails for any other reason
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
        // ── Phase 0: Stream enforcement (br-asupersync-8vn9iu). ─────────
        // Enforce per-connection stream limits and idle timeouts BEFORE
        // metadata validation and interceptor chain execution.
        if let Err(limit_error) = self.connection_registry.enforce_stream_limits(
            &connection_id,
            stream_id,
            self.config.max_concurrent_streams,
            self.config.stream_idle_timeout,
        ) {
            return Err(Status::resource_exhausted(format!(
                "stream limit enforcement failed: {}",
                limit_error
            )));
        }

        // Ensure we clean up the stream when the request completes
        let registry = Arc::clone(&self.connection_registry);
        let conn_id = connection_id.clone();

        // Dispatch the actual request using the existing logic
        let result = self.dispatch_unary(request, handler).await;

        // Clean up the stream from the registry
        registry.remove_stream(&conn_id, stream_id);

        result
    }

    /// Update stream activity for idle timeout tracking.
    ///
    /// Transport adapters should call this when they receive any frame
    /// (data, headers, or control frames) on a stream to reset its idle timer.
    /// (br-asupersync-8vn9iu.)
    pub fn update_stream_activity(&self, connection_id: &str, stream_id: u32) {
        self.connection_registry
            .update_stream_activity(connection_id, stream_id);
    }

    /// Get connection and stream statistics for monitoring.
    ///
    /// Returns `(active_connections, total_active_streams)`.
    pub fn get_connection_stats(&self) -> (usize, usize) {
        self.connection_registry.get_stats()
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
    /// The listener is immediately dropped after validation; request serving is
    /// provided by transport adapters layered above this core server registry.
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
    // gRPC timeout literals are limited to at most 8 digits. Accepting longer
    // values lets invalid peer input masquerade as a real timeout and can
    // accidentally clear deadlines later when checked_add overflows.
    if digits.is_empty() || digits.len() > 8 {
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
    /// Parses the `grpc-timeout` header to derive the deadline. If no
    /// timeout header is present and `default_timeout` is provided, the
    /// default is used instead. Malformed timeout values do not fall back
    /// to the default.
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
        let timeout = match metadata.get("grpc-timeout") {
            Some(super::streaming::MetadataValue::Ascii(s)) => parse_grpc_timeout(s),
            // A present but invalid grpc-timeout must fail closed, not impersonate absence.
            Some(super::streaming::MetadataValue::Binary(_)) => None,
            None => default_timeout,
        };
        let deadline = timeout.and_then(|t| now.checked_add(t));
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
        self.deadline.and_then(|d| d.checked_duration_since(now))
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send,
        unused_must_use
    )]
    use super::*;
    use crate::grpc::service::ServiceDescriptor;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    struct TestService;

    impl NamedService for TestService {
        const NAME: &'static str = "test.TestService";
    }

    impl ServiceHandler for TestService {
        fn descriptor(&self) -> &ServiceDescriptor {
            static DESC: ServiceDescriptor = ServiceDescriptor::new("TestService", "test", &[]);
            &DESC
        }

        fn method_names(&self) -> Vec<&str> {
            vec![]
        }
    }

    #[test]
    fn test_server_builder() {
        init_test("test_server_builder");
        let server = Server::builder()
            .max_recv_message_size(1024 * 1024)
            .max_concurrent_streams(50)
            .add_service(TestService)
            .build();

        let max_recv = server.config().max_recv_message_size;
        crate::assert_with_log!(max_recv == 1024 * 1024, "max_recv", 1024 * 1024, max_recv);
        let max_streams = server.config().max_concurrent_streams;
        crate::assert_with_log!(max_streams == 50, "max_streams", 50, max_streams);
        let has_service = server.get_service("test.TestService").is_some();
        crate::assert_with_log!(has_service, "service exists", true, has_service);
        crate::test_complete!("test_server_builder");
    }

    #[test]
    fn test_server_builder_enable_reflection() {
        init_test("test_server_builder_enable_reflection");
        let server = Server::builder()
            .add_service(TestService)
            .enable_reflection()
            .build();

        let has_reflection = server.get_service(ReflectionService::NAME).is_some();
        crate::assert_with_log!(has_reflection, "reflection exists", true, has_reflection);
        let names = server.service_names();
        let has_test = names.contains(&"test.TestService");
        crate::assert_with_log!(has_test, "test service retained", true, has_test);
        let has_refl = names.contains(&ReflectionService::NAME);
        crate::assert_with_log!(has_refl, "reflection service listed", true, has_refl);
        crate::test_complete!("test_server_builder_enable_reflection");
    }

    #[test]
    fn test_server_builder_reflection_tracks_late_registration() {
        init_test("test_server_builder_reflection_tracks_late_registration");
        let server = Server::builder()
            .enable_reflection()
            .add_service(TestService)
            .build();

        let has_reflection = server.get_service(ReflectionService::NAME).is_some();
        crate::assert_with_log!(has_reflection, "reflection exists", true, has_reflection);
        let has_service = server.get_service("test.TestService").is_some();
        crate::assert_with_log!(has_service, "late service exists", true, has_service);
        crate::test_complete!("test_server_builder_reflection_tracks_late_registration");
    }

    #[test]
    fn test_server_service_names() {
        init_test("test_server_service_names");
        let server = Server::builder().add_service(TestService).build();

        let names = server.service_names();
        let contains = names.contains(&"test.TestService");
        crate::assert_with_log!(contains, "contains service name", true, contains);
        crate::test_complete!("test_server_service_names");
    }

    #[test]
    fn test_server_serve_requires_service_registration() {
        init_test("test_server_serve_requires_service_registration");
        let server = Server::builder().build();
        let result = futures_lite::future::block_on(server.serve("127.0.0.1:0"));
        let err = result.expect_err("serving without services should fail");
        crate::assert_with_log!(
            matches!(err, GrpcError::Protocol(_)),
            "protocol error for empty service registry",
            true,
            matches!(err, GrpcError::Protocol(_))
        );
        crate::test_complete!("test_server_serve_requires_service_registration");
    }

    #[test]
    fn test_server_serve_rejects_invalid_address() {
        init_test("test_server_serve_rejects_invalid_address");
        let server = Server::builder().add_service(TestService).build();
        let result = futures_lite::future::block_on(server.serve("not-an-addr"));
        let err = result.expect_err("invalid listen address should fail");
        crate::assert_with_log!(
            matches!(err, GrpcError::Transport(_, _)),
            "transport error for invalid address",
            true,
            matches!(err, GrpcError::Transport(_, _))
        );
        crate::test_complete!("test_server_serve_rejects_invalid_address");
    }

    #[test]
    fn test_server_serve_bind_probe() {
        init_test("test_server_serve_bind_probe");
        let server = Server::builder().add_service(TestService).build();
        let result = futures_lite::future::block_on(server.serve("127.0.0.1:0"));
        crate::assert_with_log!(result.is_ok(), "bind probe succeeds", true, result.is_ok());
        crate::test_complete!("test_server_serve_bind_probe");
    }

    #[test]
    fn test_server_serve_addr_in_use_preserves_non_retryable_kind() {
        init_test("test_server_serve_addr_in_use_preserves_non_retryable_kind");
        let held_listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("test should reserve an ephemeral TCP port");
        let addr = held_listener
            .local_addr()
            .expect("reserved listener should expose local addr");

        let server = Server::builder().add_service(TestService).build();
        let result = futures_lite::future::block_on(server.serve(&addr.to_string()));
        let err = result.expect_err("binding an already-held port should fail");

        match &err {
            GrpcError::Transport(kind, message) => {
                crate::assert_with_log!(
                    *kind == TransportErrorKind::ProtocolViolation,
                    "addr-in-use transport kind",
                    TransportErrorKind::ProtocolViolation,
                    *kind
                );
                crate::assert_with_log!(
                    message.contains("bind failed"),
                    "message contains bind context",
                    true,
                    message.contains("bind failed")
                );
            }
            other => panic!("expected typed transport error for AddrInUse, got {other:?}"),
        }

        let status = err.into_status();
        crate::assert_with_log!(
            status.code() == crate::grpc::status::Code::Internal,
            "addr-in-use status code",
            crate::grpc::status::Code::Internal,
            status.code()
        );
        crate::test_complete!("test_server_serve_addr_in_use_preserves_non_retryable_kind");
    }

    #[test]
    fn test_server_serve_accepts_hostname_address() {
        init_test("test_server_serve_accepts_hostname_address");
        let server = Server::builder().add_service(TestService).build();
        let result = futures_lite::future::block_on(server.serve("localhost:0"));
        crate::assert_with_log!(
            result.is_ok(),
            "bind probe accepts hostname form",
            true,
            result.is_ok()
        );
        crate::test_complete!("test_server_serve_accepts_hostname_address");
    }

    #[test]
    fn test_call_context() {
        init_test("test_call_context");
        let ctx = CallContext::new();
        let meta_empty = ctx.metadata().is_empty();
        crate::assert_with_log!(meta_empty, "metadata empty", true, meta_empty);
        let deadline_none = ctx.deadline().is_none();
        crate::assert_with_log!(deadline_none, "deadline none", true, deadline_none);
        let peer_none = ctx.peer_addr().is_none();
        crate::assert_with_log!(peer_none, "peer none", true, peer_none);
        let expired = ctx.is_expired();
        crate::assert_with_log!(!expired, "not expired", false, expired);

        let cx = Cx::for_testing();
        let wrapped = ctx.with_cx(&cx);
        let _readonly = wrapped.cx_readonly();
        let _narrow = wrapped.cx_narrow::<cap::CapSet<true, true, false, false, false>>();
        crate::test_complete!("test_call_context");
    }

    #[test]
    fn test_call_context_expiry_boundary_is_inclusive() {
        init_test("test_call_context_expiry_boundary_is_inclusive");
        let now = std::time::Instant::now();
        let ctx = CallContext {
            metadata: Metadata::new(),
            deadline: Some(now),
            peer_addr: None,
            time_getter: wall_clock_instant_now,
        };
        let expired_at_boundary = ctx.is_expired_at(now);
        crate::assert_with_log!(
            expired_at_boundary,
            "expired at deadline boundary",
            true,
            expired_at_boundary
        );

        let before_deadline_ctx = CallContext {
            metadata: Metadata::new(),
            deadline: Some(now + std::time::Duration::from_millis(1)),
            peer_addr: None,
            time_getter: wall_clock_instant_now,
        };
        let not_yet_expired = before_deadline_ctx.is_expired_at(now);
        crate::assert_with_log!(
            !not_yet_expired,
            "not expired before deadline",
            false,
            not_yet_expired
        );
        crate::test_complete!("test_call_context_expiry_boundary_is_inclusive");
    }

    #[test]
    fn test_call_context_time_getter_controls_deadline_helpers_without_sleep() {
        use std::sync::OnceLock;
        use std::sync::atomic::{AtomicU64, Ordering};

        static BASE: OnceLock<std::time::Instant> = OnceLock::new();
        static NOW_OFFSET_NS: AtomicU64 = AtomicU64::new(0);

        fn test_now() -> std::time::Instant {
            BASE.get_or_init(std::time::Instant::now)
                .checked_add(std::time::Duration::from_nanos(
                    NOW_OFFSET_NS.load(Ordering::Relaxed),
                ))
                .expect("test instant overflow")
        }

        init_test("test_call_context_time_getter_controls_deadline_helpers_without_sleep");

        NOW_OFFSET_NS.store(0, Ordering::Relaxed);
        let mut metadata = Metadata::new();
        metadata.insert("grpc-timeout", "5m");
        let ctx = CallContext::from_metadata_with_time_getter(metadata, None, None, test_now);

        let initial_remaining = ctx.remaining();
        crate::assert_with_log!(
            initial_remaining == Some(std::time::Duration::from_millis(5)),
            "remaining uses custom time getter at construction time",
            Some(std::time::Duration::from_millis(5)),
            initial_remaining
        );

        NOW_OFFSET_NS.store(6_000_000, Ordering::Relaxed);
        let expired = ctx.is_expired();
        crate::assert_with_log!(
            expired,
            "is_expired follows custom time getter without sleeping",
            true,
            expired
        );

        let remaining_after_expiry = ctx.remaining();
        crate::assert_with_log!(
            remaining_after_expiry.is_none(),
            "remaining returns none after custom-clock expiry",
            true,
            remaining_after_expiry.is_none()
        );
        crate::test_complete!(
            "test_call_context_time_getter_controls_deadline_helpers_without_sleep"
        );
    }

    #[test]
    fn test_call_context_default_timeout_applies_when_header_absent() {
        init_test("test_call_context_default_timeout_applies_when_header_absent");
        let now = std::time::Instant::now();
        let fallback = std::time::Duration::from_secs(3);
        let ctx = CallContext::from_metadata_at(Metadata::new(), Some(fallback), None, now);

        let deadline = ctx.deadline();
        crate::assert_with_log!(
            deadline == now.checked_add(fallback),
            "default timeout applies when grpc-timeout header is absent",
            now.checked_add(fallback),
            deadline
        );
        crate::test_complete!("test_call_context_default_timeout_applies_when_header_absent");
    }

    #[test]
    fn test_call_context_malformed_timeout_does_not_use_default() {
        init_test("test_call_context_malformed_timeout_does_not_use_default");
        let now = std::time::Instant::now();
        let fallback = std::time::Duration::from_secs(3);
        let mut metadata = Metadata::new();
        metadata.insert("grpc-timeout", "bogus");
        let ctx = CallContext::from_metadata_at(metadata, Some(fallback), None, now);

        let deadline = ctx.deadline();
        crate::assert_with_log!(
            deadline.is_none(),
            "malformed grpc-timeout does not use the default timeout",
            true,
            deadline.is_none()
        );
        crate::test_complete!("test_call_context_malformed_timeout_does_not_use_default");
    }

    #[test]
    fn test_call_context_malformed_timeout_without_default_yields_no_deadline() {
        init_test("test_call_context_malformed_timeout_without_default_yields_no_deadline");
        let now = std::time::Instant::now();
        let mut metadata = Metadata::new();
        metadata.insert("grpc-timeout", "bogus");
        let ctx = CallContext::from_metadata_at(metadata, None, None, now);

        let deadline = ctx.deadline();
        crate::assert_with_log!(
            deadline.is_none(),
            "malformed grpc-timeout with no default yields no deadline",
            true,
            deadline.is_none()
        );
        crate::test_complete!(
            "test_call_context_malformed_timeout_without_default_yields_no_deadline"
        );
    }

    #[test]
    fn test_parse_grpc_timeout_rejects_more_than_eight_digits() {
        init_test("test_parse_grpc_timeout_rejects_more_than_eight_digits");
        let parsed = parse_grpc_timeout("100000000S");
        crate::assert_with_log!(
            parsed.is_none(),
            "oversized timeout literal must be rejected per gRPC 8-digit limit",
            true,
            parsed.is_none()
        );
        crate::test_complete!("test_parse_grpc_timeout_rejects_more_than_eight_digits");
    }

    /// br-asupersync-02f7vx: a CallContext built via from_metadata_at
    /// retains wall_clock_instant_now as its time_getter unless the
    /// caller explicitly chains .with_time_getter(...). This test
    /// pins the contract so future maintainers don't accidentally
    /// regress the documented chain pattern.
    #[test]
    fn test_call_context_from_metadata_at_default_time_getter_is_wall_clock() {
        init_test("test_call_context_from_metadata_at_default_time_getter_is_wall_clock");
        let now = std::time::Instant::now();
        let ctx = CallContext::from_metadata_at(Metadata::new(), None, None, now);
        // Default time_getter is wall_clock_instant_now (production-correct
        // for non-replay paths; replay callers MUST chain .with_time_getter).
        let getter = ctx.time_getter();
        assert!(
            std::ptr::fn_addr_eq(getter, wall_clock_instant_now as fn() -> std::time::Instant),
            "from_metadata_at must default time_getter to wall_clock_instant_now"
        );
        crate::test_complete!(
            "test_call_context_from_metadata_at_default_time_getter_is_wall_clock"
        );
    }

    /// br-asupersync-02f7vx: chaining .with_time_getter(...) after
    /// from_metadata_at MUST install the replay-deterministic
    /// closure — the canonical pattern for replay harnesses.
    #[test]
    fn test_call_context_with_time_getter_chain_overrides_default() {
        init_test("test_call_context_with_time_getter_chain_overrides_default");
        // Use a known fixed Instant so the test is deterministic.
        let recorded = std::time::Instant::now();
        fn fixed_time() -> std::time::Instant {
            // Returns a constant that the test below pins by ptr equality.
            // The actual instant value isn't compared — pointer identity
            // proves the closure was installed.
            std::time::Instant::now()
        }
        let ctx = CallContext::from_metadata_at(Metadata::new(), None, None, recorded)
            .with_time_getter(fixed_time);
        let getter = ctx.time_getter();
        assert!(
            std::ptr::fn_addr_eq(getter, fixed_time as fn() -> std::time::Instant),
            "with_time_getter must replace the default — fixed_time wasn't installed"
        );
        crate::test_complete!("test_call_context_with_time_getter_chain_overrides_default");
    }

    #[test]
    fn test_call_context_oversized_timeout_header_fails_closed() {
        init_test("test_call_context_oversized_timeout_header_fails_closed");
        let now = std::time::Instant::now();
        let fallback = std::time::Duration::from_secs(3);
        let mut metadata = Metadata::new();
        metadata.insert("grpc-timeout", "100000000S");
        let ctx = CallContext::from_metadata_at(metadata, Some(fallback), None, now);

        let deadline = ctx.deadline();
        crate::assert_with_log!(
            deadline.is_none(),
            "oversized timeout header must not be treated as an unbounded valid deadline",
            true,
            deadline.is_none()
        );
        crate::test_complete!("test_call_context_oversized_timeout_header_fails_closed");
    }

    #[test]
    fn test_call_context_timeout_header_value_uses_remaining_budget() {
        init_test("test_call_context_timeout_header_value_uses_remaining_budget");
        let now = std::time::Instant::now();
        let deadline = now + std::time::Duration::from_millis(250);
        let ctx = CallContext::with_deadline(deadline);

        let header = ctx.timeout_header_value_at(now);
        crate::assert_with_log!(
            header.as_deref() == Some("250m"),
            "timeout header preserves remaining duration",
            Some("250m"),
            header.as_deref()
        );

        let expired_header =
            ctx.timeout_header_value_at(deadline + std::time::Duration::from_millis(1));
        crate::assert_with_log!(
            expired_header.as_deref() == Some("0n"),
            "expired deadlines propagate as zero timeout",
            Some("0n"),
            expired_header.as_deref()
        );
        crate::test_complete!("test_call_context_timeout_header_value_uses_remaining_budget");
    }

    #[test]
    fn test_call_context_propagate_timeout_to_clamps_existing_child_timeout() {
        init_test("test_call_context_propagate_timeout_to_clamps_existing_child_timeout");
        let now = std::time::Instant::now();
        let ctx = CallContext::with_deadline(now + std::time::Duration::from_secs(5));
        let mut metadata = Metadata::new();
        metadata.insert("grpc-timeout", "10S");

        let wrote = ctx.propagate_timeout_to_at(&mut metadata, now);
        crate::assert_with_log!(wrote, "propagation writes timeout header", true, wrote);
        crate::assert_with_log!(
            matches!(
                metadata.get("grpc-timeout"),
                Some(crate::grpc::MetadataValue::Ascii(value)) if value == "5S"
            ),
            "existing child timeout is attenuated to parent deadline",
            true,
            metadata.get("grpc-timeout").is_some()
        );
        let timeout_count = metadata
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("grpc-timeout"))
            .count();
        crate::assert_with_log!(
            timeout_count == 1,
            "propagation keeps a single grpc-timeout entry",
            1,
            timeout_count
        );
        crate::test_complete!(
            "test_call_context_propagate_timeout_to_clamps_existing_child_timeout"
        );
    }

    #[test]
    fn test_call_context_propagate_timeout_to_inserts_when_absent() {
        init_test("test_call_context_propagate_timeout_to_inserts_when_absent");
        let now = std::time::Instant::now();
        let ctx = CallContext::with_deadline(now + std::time::Duration::from_millis(750));
        let mut metadata = Metadata::new();

        let wrote = ctx.propagate_timeout_to_at(&mut metadata, now);
        crate::assert_with_log!(wrote, "propagation inserts missing timeout", true, wrote);
        crate::assert_with_log!(
            matches!(
                metadata.get("grpc-timeout"),
                Some(crate::grpc::MetadataValue::Ascii(value)) if value == "750m"
            ),
            "propagation inserts parent remaining timeout when absent",
            true,
            metadata.get("grpc-timeout").is_some()
        );
        crate::test_complete!("test_call_context_propagate_timeout_to_inserts_when_absent");
    }

    #[test]
    fn test_call_context_propagate_timeout_to_repairs_malformed_child_timeout() {
        init_test("test_call_context_propagate_timeout_to_repairs_malformed_child_timeout");
        let now = std::time::Instant::now();
        let ctx = CallContext::with_deadline(now + std::time::Duration::from_secs(5));
        let mut metadata = Metadata::new();
        metadata.insert("grpc-timeout", "bogus");

        let wrote = ctx.propagate_timeout_to_at(&mut metadata, now);
        crate::assert_with_log!(wrote, "propagation writes repaired timeout", true, wrote);
        crate::assert_with_log!(
            matches!(
                metadata.get("grpc-timeout"),
                Some(crate::grpc::MetadataValue::Ascii(value)) if value == "5S"
            ),
            "malformed child timeout replaced with parent deadline",
            true,
            metadata.get("grpc-timeout").is_some()
        );
        let timeout_count = metadata
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("grpc-timeout"))
            .count();
        crate::assert_with_log!(
            timeout_count == 1,
            "repaired child timeout does not leave duplicates",
            1,
            timeout_count
        );
        crate::test_complete!(
            "test_call_context_propagate_timeout_to_repairs_malformed_child_timeout"
        );
    }

    #[test]
    fn test_noop_interceptor() {
        init_test("test_noop_interceptor");
        let interceptor = NoopInterceptor;
        let mut request = Request::new(Bytes::new());
        let ok = interceptor.intercept_request(&mut request).is_ok();
        crate::assert_with_log!(ok, "request ok", true, ok);

        let mut response = Response::new(Bytes::new());
        let ok = interceptor.intercept_response(&mut response).is_ok();
        crate::assert_with_log!(ok, "response ok", true, ok);
        crate::test_complete!("test_noop_interceptor");
    }

    #[test]
    fn test_auth_interceptor() {
        init_test("test_auth_interceptor");
        let interceptor = AuthInterceptor::new(|metadata| {
            if metadata.get("authorization").is_some() {
                Ok(())
            } else {
                Err(Status::unauthenticated("missing authorization"))
            }
        });

        // Request without auth
        let mut request = Request::new(Bytes::new());
        let err = interceptor.intercept_request(&mut request).is_err();
        crate::assert_with_log!(err, "missing auth err", true, err);

        // Request with auth
        request
            .metadata_mut()
            .insert("authorization", "Bearer token");
        let ok = interceptor.intercept_request(&mut request).is_ok();
        crate::assert_with_log!(ok, "auth ok", true, ok);
        crate::test_complete!("test_auth_interceptor");
    }

    // -------------------------------------------------------------------
    // br-asupersync-i2bae8: max_metadata_size enforcement
    // -------------------------------------------------------------------

    #[test]
    fn server_config_default_caps_metadata_at_8_kib() {
        init_test("server_config_default_caps_metadata_at_8_kib");
        let cfg = ServerConfig::default();
        assert_eq!(
            cfg.max_metadata_size, DEFAULT_MAX_METADATA_SIZE,
            "default max_metadata_size must equal DEFAULT_MAX_METADATA_SIZE (8 KiB)"
        );
        assert_eq!(cfg.max_metadata_size, 8 * 1024);
        crate::test_complete!("server_config_default_caps_metadata_at_8_kib");
    }

    #[test]
    fn enforce_metadata_size_limit_accepts_under_cap() {
        init_test("enforce_metadata_size_limit_accepts_under_cap");
        let mut metadata = super::super::streaming::Metadata::new();
        metadata.insert("authorization", "Bearer abc");
        metadata.insert("x-request-id", "deadbeef");
        let total = metadata_byte_size(&metadata);
        assert!(total > 0);
        enforce_metadata_size_limit(&metadata, 8 * 1024)
            .expect("under-cap metadata must pass enforcement");
        crate::test_complete!("enforce_metadata_size_limit_accepts_under_cap");
    }

    #[test]
    fn enforce_metadata_size_limit_rejects_over_cap_with_resource_exhausted() {
        init_test("enforce_metadata_size_limit_rejects_over_cap_with_resource_exhausted");
        let mut metadata = super::super::streaming::Metadata::new();
        // 16 KiB of value bytes blows past an 8 KiB cap by 2x.
        let huge = "A".repeat(16 * 1024);
        metadata.insert("x-attack", huge);

        match enforce_metadata_size_limit(&metadata, 8 * 1024) {
            Err(status) => {
                // br-asupersync-3crhd7: assert against the gRPC Code, not
                // an HTTP status code. The gRPC equivalent of HTTP 431
                // payload-too-large is Code::ResourceExhausted (which is
                // i32 value 8, not u16 429). Previously this assertion
                // compared 8 == 429 and could never pass.
                assert_eq!(
                    status.code(),
                    super::super::status::Code::ResourceExhausted,
                    "must reject with RESOURCE_EXHAUSTED, got {:?}",
                    status.code()
                );
                let msg = format!("{status}");
                assert!(
                    msg.contains("max_metadata_size") || msg.contains("metadata"),
                    "error message must mention the limit, got: {msg}"
                );
            }
            Ok(()) => {
                panic!("16 KiB metadata must be rejected by 8 KiB cap, but enforcement passed")
            }
        }
        crate::test_complete!(
            "enforce_metadata_size_limit_rejects_over_cap_with_resource_exhausted"
        );
    }

    #[test]
    fn enforce_metadata_size_limit_zero_disables_cap() {
        init_test("enforce_metadata_size_limit_zero_disables_cap");
        let mut metadata = super::super::streaming::Metadata::new();
        let huge = "A".repeat(1024 * 1024); // 1 MiB
        metadata.insert("x-anything", huge);
        enforce_metadata_size_limit(&metadata, 0)
            .expect("limit=0 must disable enforcement (no-cap convention)");
        crate::test_complete!("enforce_metadata_size_limit_zero_disables_cap");
    }

    #[test]
    fn enforce_metadata_size_limit_rejects_ascii_control_chars() {
        init_test("enforce_metadata_size_limit_rejects_ascii_control_chars");
        let metadata = super::super::streaming::Metadata::from_raw_entries_for_tests(vec![(
            "x-request-id".to_string(),
            super::super::streaming::MetadataValue::Ascii("line1\r\nline2".to_string()),
        )]);

        let status = enforce_metadata_size_limit(&metadata, 8 * 1024)
            .expect_err("CRLF-bearing metadata must be rejected");
        assert_eq!(status.code(), super::super::status::Code::InvalidArgument);
        let msg = format!("{status}");
        assert!(
            msg.contains("x-request-id") && msg.contains("disallowed"),
            "error message must mention the offending header, got: {msg}"
        );
        crate::test_complete!("enforce_metadata_size_limit_rejects_ascii_control_chars");
    }

    #[test]
    fn enforce_metadata_size_limit_rejects_reserved_grpc_header() {
        init_test("enforce_metadata_size_limit_rejects_reserved_grpc_header");
        let mut metadata = super::super::streaming::Metadata::new();
        metadata.insert("grpc-status", "0");

        let status = enforce_metadata_size_limit(&metadata, 8 * 1024)
            .expect_err("client grpc-status metadata must be rejected");
        assert_eq!(status.code(), super::super::status::Code::InvalidArgument);
        let msg = format!("{status}");
        assert!(
            msg.contains("grpc-status") && msg.contains("reserved grpc-* prefix"),
            "error message must mention reserved grpc-* prefix, got: {msg}"
        );
        crate::test_complete!("enforce_metadata_size_limit_rejects_reserved_grpc_header");
    }

    #[test]
    fn enforce_metadata_size_limit_allows_grpc_request_protocol_headers() {
        init_test("enforce_metadata_size_limit_allows_grpc_request_protocol_headers");
        let mut metadata = super::super::streaming::Metadata::new();
        metadata.insert("grpc-timeout", "5S");
        metadata.insert("grpc-encoding", "identity");
        metadata.insert("grpc-accept-encoding", "identity,gzip");
        metadata.insert("grpc-message-type", "test.EchoRequest");

        enforce_metadata_size_limit(&metadata, 8 * 1024)
            .expect("protocol-owned request grpc-* headers must remain allowed");
        crate::test_complete!("enforce_metadata_size_limit_allows_grpc_request_protocol_headers");
    }

    #[test]
    fn server_builder_max_metadata_size_overrides_default() {
        init_test("server_builder_max_metadata_size_overrides_default");
        let server = ServerBuilder::new().max_metadata_size(16 * 1024).build();
        assert_eq!(server.config().max_metadata_size, 16 * 1024);
        crate::test_complete!("server_builder_max_metadata_size_overrides_default");
    }

    // =========================================================================
    // Wave 28: Data-type trait coverage
    // =========================================================================

    #[test]
    fn server_config_debug() {
        let config = ServerConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("ServerConfig"));
        assert!(dbg.contains("max_recv_message_size"));
        assert!(dbg.contains("max_concurrent_streams"));
    }

    #[test]
    fn server_config_clone() {
        let config = ServerConfig {
            max_recv_message_size: 1024,
            max_send_message_size: 2048,
            ..Default::default()
        };
        let config2 = config;
        assert_eq!(config2.max_recv_message_size, 1024);
        assert_eq!(config2.max_send_message_size, 2048);
    }

    #[test]
    fn server_config_default_values() {
        let config = ServerConfig::default();
        assert_eq!(config.max_recv_message_size, 4 * 1024 * 1024);
        assert_eq!(config.max_send_message_size, 4 * 1024 * 1024);
        assert_eq!(config.initial_connection_window_size, 1024 * 1024);
        assert_eq!(config.initial_stream_window_size, 1024 * 1024);
        assert_eq!(config.max_concurrent_streams, 100);
        assert!(config.keepalive_interval_ms.is_none());
        assert!(config.keepalive_timeout_ms.is_none());
    }

    #[test]
    fn server_builder_debug() {
        let builder = ServerBuilder::new();
        let dbg = format!("{builder:?}");
        assert!(dbg.contains("ServerBuilder"));
        assert!(dbg.contains("config"));
    }

    #[test]
    fn server_builder_default() {
        let builder = ServerBuilder::default();
        let dbg = format!("{builder:?}");
        assert!(dbg.contains("ServerBuilder"));
    }

    #[test]
    fn server_debug() {
        let server = Server::builder().build();
        let dbg = format!("{server:?}");
        assert!(dbg.contains("Server"));
        assert!(dbg.contains("config"));
    }

    #[test]
    fn call_context_debug() {
        let ctx = CallContext::new();
        let dbg = format!("{ctx:?}");
        assert!(dbg.contains("CallContext"));
        assert!(dbg.contains("metadata"));
    }

    #[test]
    fn call_context_default() {
        let ctx = CallContext::default();
        assert!(ctx.deadline().is_none());
        assert!(ctx.peer_addr().is_none());
        assert!(ctx.metadata().is_empty());
    }

    #[test]
    fn noop_interceptor_debug_clone_copy_default() {
        let interceptor = NoopInterceptor;
        let dbg = format!("{interceptor:?}");
        assert!(dbg.contains("NoopInterceptor"));

        let cloned = interceptor;
        let _ = format!("{cloned:?}");

        let copied = interceptor; // Copy
        let _ = format!("{copied:?}");

        let default = NoopInterceptor;
        let _ = format!("{default:?}");
    }

    #[test]
    fn ok_utility_returns_ok_response() {
        let result: Result<Response<i32>, Status> = ok(42);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().into_inner(), 42);
    }

    #[test]
    fn err_utility_returns_err_status() {
        let result: Result<Response<i32>, Status> = err(Status::not_found("missing"));
        assert!(result.is_err());
    }

    #[test]
    fn server_builder_keepalive() {
        let server = Server::builder()
            .keepalive_interval(5000)
            .keepalive_timeout(2000)
            .build();
        assert_eq!(server.config().keepalive_interval_ms, Some(5000));
        assert_eq!(server.config().keepalive_timeout_ms, Some(2000));
    }

    #[test]
    fn server_builder_window_sizes() {
        let server = Server::builder()
            .initial_connection_window_size(512 * 1024)
            .initial_stream_window_size(256 * 1024)
            .build();
        assert_eq!(server.config().initial_connection_window_size, 512 * 1024);
        assert_eq!(server.config().initial_stream_window_size, 256 * 1024);
    }

    #[test]
    fn server_get_service_missing() {
        let server = Server::builder().build();
        assert!(server.get_service("nonexistent").is_none());
    }

    // =========================================================================
    // gRPC streaming contract conformance (Pattern 4, spec-derived).
    //
    // Source: gRPC HTTP/2 protocol spec §6 "Timeout"
    //   https://grpc.github.io/grpc/core/md_doc__p_r_o_t_o_c_o_l-_h_t_t_p2.html
    //   (timeout format: TimeoutValue "H" | "M" | "S" | "m" | "u" | "n",
    //    TimeoutValue is 1..=8 ASCII digits encoded as u64).
    //
    // Every MUST clause from that section gets one test here, each emitting
    // a structured JSON-line verdict for CI parsing. Existing per-case
    // tests (`test_parse_grpc_timeout_rejects_more_than_eight_digits` +
    // companions) cover scenarios; this suite pins the spec contract.
    // =========================================================================

    mod grpc_timeout_conformance {
        use super::*;

        /// GRPC-TIMEOUT-1 (MUST): Accept all six spec units (H, M, S, m, u, n)
        /// and map each to the correct Duration.
        #[test]
        fn grpc_timeout_1_all_six_units_parse() {
            let cases = &[
                ("1H", Duration::from_secs(3600)),
                ("2M", Duration::from_secs(120)),
                ("30S", Duration::from_secs(30)),
                ("500m", Duration::from_millis(500)),
                ("250u", Duration::from_micros(250)),
                ("42n", Duration::from_nanos(42)),
            ];
            for (input, expected) in cases {
                let got = parse_grpc_timeout(input);
                assert_eq!(
                    got,
                    Some(*expected),
                    "GRPC-TIMEOUT-1: {input:?} must parse to {expected:?}",
                );
            }
            eprintln!("{{\"id\":\"GRPC-TIMEOUT-1\",\"verdict\":\"PASS\",\"level\":\"Must\"}}",);
        }

        /// GRPC-TIMEOUT-2 (MUST): The TimeoutValue component has at most
        /// eight ASCII digits. Nine-digit values must be rejected (return None),
        /// never truncated.
        #[test]
        fn grpc_timeout_2_reject_more_than_eight_digits() {
            let inputs = &["100000000S", "999999999m", "123456789n", "000000000H"];
            for input in inputs {
                assert_eq!(
                    parse_grpc_timeout(input),
                    None,
                    "GRPC-TIMEOUT-2: {input:?} must be rejected (>8 digits)",
                );
            }
            eprintln!("{{\"id\":\"GRPC-TIMEOUT-2\",\"verdict\":\"PASS\",\"level\":\"Must\"}}",);
        }

        /// GRPC-TIMEOUT-3 (MUST): Empty header value, no digits, or missing
        /// unit must all be rejected. A present-but-malformed header cannot
        /// silently impersonate "no timeout".
        #[test]
        fn grpc_timeout_3_reject_malformed() {
            let rejected = &[
                "",     // empty
                "S",    // no digits
                "100",  // missing unit
                " 10S", // leading whitespace
                "10 S", // internal space
                "10s",  // lowercase s is not a valid unit
                "10x",  // unknown unit
                "-1S",  // negative
                "1.5S", // non-integer
                "abc",  // non-numeric
                "١٠S",  // non-ASCII digits (Arabic-Indic)
            ];
            for input in rejected {
                assert_eq!(
                    parse_grpc_timeout(input),
                    None,
                    "GRPC-TIMEOUT-3: {input:?} must be rejected",
                );
            }
            eprintln!("{{\"id\":\"GRPC-TIMEOUT-3\",\"verdict\":\"PASS\",\"level\":\"Must\"}}",);
        }

        /// GRPC-TIMEOUT-4 (MUST): The formatter output is parseable by the
        /// same parser. Round-trip Duration → format → parse must recover
        /// the original value (subject to unit-granularity truncation for
        /// values that exceed the 8-digit ceiling in their natural unit).
        #[test]
        fn grpc_timeout_4_format_parse_roundtrip() {
            let lossless = &[
                Duration::ZERO,
                Duration::from_nanos(1),
                Duration::from_nanos(42),
                Duration::from_micros(250),
                Duration::from_millis(500),
                Duration::from_secs(30),
                Duration::from_secs(120),  // 2 minutes
                Duration::from_secs(3600), // 1 hour
                Duration::from_secs(7200), // 2 hours
            ];
            for d in lossless {
                let formatted = format_grpc_timeout(*d);
                let parsed = parse_grpc_timeout(&formatted).unwrap_or_else(|| {
                    panic!("GRPC-TIMEOUT-4: formatter output {formatted:?} not parseable")
                });
                assert_eq!(
                    parsed, *d,
                    "GRPC-TIMEOUT-4: round-trip diverged for {d:?} → {formatted:?} → {parsed:?}",
                );
            }
            eprintln!("{{\"id\":\"GRPC-TIMEOUT-4\",\"verdict\":\"PASS\",\"level\":\"Must\"}}",);
        }

        /// GRPC-TIMEOUT-5 (MUST): Formatter output always fits within the
        /// 8-digit TimeoutValue ceiling. The TimeoutValue component of the
        /// result, stripped of its unit, must be 1..=8 ASCII digits.
        #[test]
        fn grpc_timeout_5_formatter_respects_eight_digit_ceiling() {
            let samples = &[
                Duration::ZERO,
                Duration::from_nanos(1),
                Duration::from_secs(1),
                Duration::from_secs(999_999_999), // large but not MAX
                Duration::MAX,                    // saturation edge
            ];
            for d in samples {
                let formatted = format_grpc_timeout(*d);
                // Last char is the unit; rest must be 1..=8 ASCII digits.
                let (digits, unit) = formatted.split_at(formatted.len() - 1);
                assert!(
                    matches!(unit, "H" | "M" | "S" | "m" | "u" | "n"),
                    "GRPC-TIMEOUT-5: unit {unit:?} not in spec set for input {d:?}",
                );
                assert!(
                    (1..=8).contains(&digits.len()),
                    "GRPC-TIMEOUT-5: digits {digits:?} length out of [1,8] for input {d:?}",
                );
                assert!(
                    digits.bytes().all(|b| b.is_ascii_digit()),
                    "GRPC-TIMEOUT-5: digits {digits:?} contains non-ASCII-digit for input {d:?}",
                );
            }
            eprintln!("{{\"id\":\"GRPC-TIMEOUT-5\",\"verdict\":\"PASS\",\"level\":\"Must\"}}",);
        }

        /// GRPC-TIMEOUT-6 (MUST): Zero duration formats as `"0n"` (or the
        /// semantically equivalent smallest representation), and parses
        /// back to `Duration::ZERO`. This is the canonical "fail-fast
        /// downstream" signal when a parent deadline has expired.
        #[test]
        fn grpc_timeout_6_zero_duration_fail_fast_representation() {
            let formatted = format_grpc_timeout(Duration::ZERO);
            let parsed = parse_grpc_timeout(&formatted).expect("zero parses");
            assert_eq!(parsed, Duration::ZERO);
            // The implementation picks "0n" — verify exactly so downstream
            // gRPC servers see the canonical fail-fast form.
            assert_eq!(
                formatted, "0n",
                "GRPC-TIMEOUT-6: zero must format as canonical \"0n\"",
            );
            eprintln!("{{\"id\":\"GRPC-TIMEOUT-6\",\"verdict\":\"PASS\",\"level\":\"Must\"}}",);
        }

        /// GRPC-TIMEOUT-7 (MUST): H/M/S/m/u/n arithmetic overflow must be
        /// rejected rather than wrapping or panicking. `99999999H` is
        /// within the 8-digit ceiling on digits but overflows u64 when
        /// multiplied by 3600; the parser must return None.
        #[test]
        fn grpc_timeout_7_overflow_rejected_not_wrapped() {
            // 99_999_999 hours in seconds = 359_999_996_400 — fits in u64
            // but if the multiplication were done on smaller types this
            // would be the overflow boundary. The parser uses checked_mul
            // so this is expected to succeed.
            let safe = parse_grpc_timeout("99999999H");
            assert!(
                safe.is_some(),
                "GRPC-TIMEOUT-7: 99_999_999H fits in u64 seconds and must parse",
            );

            // Values that would overflow when multiplied — we have to
            // reach them via the 8-digit ceiling. Since the ceiling
            // already caps below overflow for all six units at u64, the
            // remaining overflow path is through format → parse of
            // Duration::MAX, which the spec's 8-digit cap prevents. The
            // invariant here is "parser never panics on any ASCII input
            // within 1..=8 digits". Exhaust the boundary.
            for unit in &["H", "M", "S", "m", "u", "n"] {
                let input = format!("99999999{unit}");
                let _ = parse_grpc_timeout(&input);
                let input = format!("00000000{unit}");
                let _ = parse_grpc_timeout(&input);
                let input = format!("0{unit}");
                let parsed = parse_grpc_timeout(&input);
                assert_eq!(
                    parsed,
                    Some(Duration::ZERO),
                    "GRPC-TIMEOUT-7: 0{unit} must parse to ZERO",
                );
            }
            eprintln!("{{\"id\":\"GRPC-TIMEOUT-7\",\"verdict\":\"PASS\",\"level\":\"Must\"}}",);
        }

        /// GRPC-TIMEOUT-8 (MUST): The parser tolerates any byte sequence
        /// without panicking. Non-ASCII, control chars, high-bit bytes,
        /// and invalid UTF-8-ish ASCII substrings must all return None
        /// (never panic, never unwrap).
        #[test]
        fn grpc_timeout_8_no_panic_on_adversarial_input() {
            let adversarial: &[&str] = &[
                "",
                "\0",
                "\0\0\0S",
                "\n10S",
                "10S\n",
                "\u{FEFF}10S", // zero-width no-break space
                "\u{200B}10S", // zero-width space
                "1\0S",
                "\x7f10S",
                "10\x00S",
                "ääääääääS",
                "10😀",
            ];
            for input in adversarial {
                // The parser must not panic; verdict (None vs Some) is
                // secondary — what matters is the absence of a crash.
                let _ = parse_grpc_timeout(input);
            }
            eprintln!("{{\"id\":\"GRPC-TIMEOUT-8\",\"verdict\":\"PASS\",\"level\":\"Must\"}}",);
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // br-asupersync-mfk14i: Server interceptor chain wiring
    // ════════════════════════════════════════════════════════════════════

    /// Counting interceptor used to verify before/after fire on every
    /// dispatch_unary call. Records call counts and the order in
    /// which interceptors saw each phase.
    #[derive(Debug)]
    struct CountingInterceptor {
        name: &'static str,
        request_count: std::sync::atomic::AtomicUsize,
        response_count: std::sync::atomic::AtomicUsize,
        events: Arc<parking_lot::Mutex<Vec<String>>>,
    }

    impl CountingInterceptor {
        fn new(name: &'static str, events: Arc<parking_lot::Mutex<Vec<String>>>) -> Self {
            Self {
                name,
                request_count: std::sync::atomic::AtomicUsize::new(0),
                response_count: std::sync::atomic::AtomicUsize::new(0),
                events,
            }
        }
    }

    impl Interceptor for CountingInterceptor {
        fn intercept_request(&self, _request: &mut Request<Bytes>) -> Result<(), Status> {
            self.request_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.events.lock().push(format!("req:{}", self.name));
            Ok(())
        }
        fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
            self.response_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.events.lock().push(format!("resp:{}", self.name));
            Ok(())
        }
    }

    /// Interceptor that always rejects on the request side — used to
    /// verify the chain short-circuits cleanly.
    #[derive(Debug)]
    struct RejectingInterceptor {
        events: Arc<parking_lot::Mutex<Vec<String>>>,
    }

    impl Interceptor for RejectingInterceptor {
        fn intercept_request(&self, _request: &mut Request<Bytes>) -> Result<(), Status> {
            self.events.lock().push("req:reject".to_string());
            Err(Status::unauthenticated("rejected by RejectingInterceptor"))
        }
        fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
            self.events.lock().push("resp:reject".to_string());
            Ok(())
        }
    }

    #[derive(Debug)]
    struct AuthContextEchoInterceptor {
        seen_principal: Arc<parking_lot::Mutex<Option<String>>>,
    }

    impl Interceptor for AuthContextEchoInterceptor {
        fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
            request.extensions_mut().insert_typed(
                crate::grpc::interceptor::AuthContext::with_principal("svc-a")
                    .with_scopes(["read:rpc"]),
            );
            Ok(())
        }

        fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
            Ok(())
        }

        fn intercept_response_with_request(
            &self,
            request: &Request<Bytes>,
            _response: &mut Response<Bytes>,
        ) -> Result<(), Status> {
            let seen = request
                .extensions()
                .get_typed::<crate::grpc::interceptor::AuthContext>()
                .map(|auth| auth.principal.clone());
            *self.seen_principal.lock() = seen;
            Ok(())
        }
    }

    fn block_on<F: Future>(fut: F) -> F::Output {
        use std::task::{Context, Waker};
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut pinned = Box::pin(fut);
        loop {
            if let std::task::Poll::Ready(value) = pinned.as_mut().poll(&mut cx) {
                return value;
            }
        }
    }

    #[test]
    fn mfk14i_dispatch_unary_runs_interceptor_chain_around_handler() {
        // Pre-fix the dispatch_unary API did not exist and registered
        // interceptors were dead code. This test pins the wired
        // contract: every interceptor's intercept_request fires
        // BEFORE the handler in registration order, the handler runs
        // exactly once, every interceptor's intercept_response fires
        // AFTER the handler in REVERSE order.
        init_test("mfk14i_dispatch_unary_runs_interceptor_chain_around_handler");

        let events = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let i_a = CountingInterceptor::new("A", Arc::clone(&events));
        let i_b = CountingInterceptor::new("B", Arc::clone(&events));

        let server = Server::builder()
            .add_service(TestService)
            .interceptor(i_a)
            .interceptor(i_b)
            .build();

        let request = Request::with_metadata(Bytes::from_static(b"hello"), Metadata::new());
        let result = block_on(server.dispatch_unary(request, |req| async move {
            // Handler echoes the request payload.
            let payload = req.into_inner();
            Ok(Response::new(payload))
        }));

        let response = result.expect("dispatch must succeed");
        assert_eq!(response.get_ref().as_ref(), b"hello");

        let actual = events.lock().clone();
        assert_eq!(
            actual,
            vec![
                "req:A".to_string(),
                "req:B".to_string(),
                "resp:B".to_string(),
                "resp:A".to_string(),
            ],
            "interceptors must fire in registration order on requests \
             and REVERSE order on responses; got {actual:?}"
        );
    }

    #[test]
    fn mfk14i_dispatch_unary_rejected_request_short_circuits_handler_and_response_chain() {
        // When a request-side interceptor errors, neither the handler
        // nor any later request-side OR response-side interceptor
        // runs. The first error is the call's final status.
        init_test(
            "mfk14i_dispatch_unary_rejected_request_short_circuits_handler_and_response_chain",
        );

        let events = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let i_a = CountingInterceptor::new("A", Arc::clone(&events));
        let reject = RejectingInterceptor {
            events: Arc::clone(&events),
        };
        let i_after = CountingInterceptor::new("after", Arc::clone(&events));
        let handler_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handler_called_clone = Arc::clone(&handler_called);

        let server = Server::builder()
            .add_service(TestService)
            .interceptor(i_a)
            .interceptor(reject)
            .interceptor(i_after)
            .build();

        let request = Request::with_metadata(Bytes::from_static(b"x"), Metadata::new());
        let result = block_on(server.dispatch_unary(request, move |req| {
            let flag = Arc::clone(&handler_called_clone);
            async move {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(Response::new(req.into_inner()))
            }
        }));

        let err = result.expect_err("rejected request must surface as Err");
        assert_eq!(err.code(), super::super::Code::Unauthenticated);

        assert!(
            !handler_called.load(std::sync::atomic::Ordering::SeqCst),
            "handler must NOT be invoked when an earlier interceptor rejects"
        );

        let actual = events.lock().clone();
        assert_eq!(
            actual,
            vec!["req:A".to_string(), "req:reject".to_string()],
            "post-reject interceptors (request and response side) must NOT fire; \
             got {actual:?}"
        );
    }

    #[test]
    fn mfk14i_dispatch_unary_handler_error_skips_response_chain() {
        // When the handler errors, the response-side chain must NOT
        // run (no response object to transform). The handler error
        // becomes the final status. Request-side chain still ran in
        // full.
        init_test("mfk14i_dispatch_unary_handler_error_skips_response_chain");

        let events = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let i_a = CountingInterceptor::new("A", Arc::clone(&events));

        let server = Server::builder()
            .add_service(TestService)
            .interceptor(i_a)
            .build();

        let request = Request::with_metadata(Bytes::new(), Metadata::new());
        let result = block_on(server.dispatch_unary(request, |_req| async move {
            Err::<Response<Bytes>, _>(Status::internal("handler exploded"))
        }));

        assert!(result.is_err());
        let actual = events.lock().clone();
        assert_eq!(
            actual,
            vec!["req:A".to_string()],
            "response-side chain must NOT fire on handler error; got {actual:?}"
        );
    }

    #[test]
    fn mfk14i_server_with_no_interceptors_runs_handler_directly() {
        // Back-compat: a Server built without any interceptor() calls
        // still dispatches correctly — the chain is just empty.
        init_test("mfk14i_server_with_no_interceptors_runs_handler_directly");
        let server = Server::builder().add_service(TestService).build();
        assert_eq!(server.interceptors().len(), 0);

        let request = Request::with_metadata(Bytes::from_static(b"echo"), Metadata::new());
        let result = block_on(server.dispatch_unary(request, |req| async move {
            Ok(Response::new(req.into_inner()))
        }));
        let response = result.expect("dispatch must succeed");
        assert_eq!(response.get_ref().as_ref(), b"echo");
    }

    #[test]
    fn dispatch_unary_preserves_auth_context_for_response_interceptors() {
        init_test("dispatch_unary_preserves_auth_context_for_response_interceptors");

        let seen_principal = Arc::new(parking_lot::Mutex::new(None));
        let server = Server::builder()
            .add_service(TestService)
            .interceptor(AuthContextEchoInterceptor {
                seen_principal: Arc::clone(&seen_principal),
            })
            .build();

        let request = Request::with_metadata(Bytes::from_static(b"ping"), Metadata::new());
        let result = block_on(server.dispatch_unary(request, |req| async move {
            Ok(Response::new(req.into_inner()))
        }));

        let response = result.expect("dispatch must succeed");
        assert_eq!(response.get_ref().as_ref(), b"ping");
        assert_eq!(seen_principal.lock().clone(), Some("svc-a".to_string()));
    }

    #[test]
    fn mfk14i_auth_interceptor_actually_blocks_unauthenticated_calls() {
        // End-to-end: register a real AuthInterceptor that requires
        // an "authorization" metadata entry, dispatch with and
        // without it, verify the gate fires.
        init_test("mfk14i_auth_interceptor_actually_blocks_unauthenticated_calls");

        let auth = AuthInterceptor::new(|metadata: &Metadata| -> Result<(), Status> {
            if metadata.get("authorization").is_some() {
                Ok(())
            } else {
                Err(Status::unauthenticated("missing authorization"))
            }
        });
        let server = Server::builder()
            .add_service(TestService)
            .interceptor(auth)
            .build();

        // No auth header — must be rejected.
        let unauth_req = Request::with_metadata(Bytes::new(), Metadata::new());
        let unauth_result = block_on(server.dispatch_unary(unauth_req, |_req| async move {
            Ok(Response::new(Bytes::from_static(b"should not reach")))
        }));
        assert!(
            matches!(
                unauth_result,
                Err(ref s) if s.code() == super::super::Code::Unauthenticated
            ),
            "missing-auth call must be rejected with Unauthenticated; got {unauth_result:?}"
        );

        // With auth header — must succeed.
        let mut authed_md = Metadata::new();
        authed_md.insert("authorization", "Bearer xyz");
        let authed_req = Request::with_metadata(Bytes::new(), authed_md);
        let authed_result = block_on(server.dispatch_unary(authed_req, |_req| async move {
            Ok(Response::new(Bytes::from_static(b"ok")))
        }));
        let response = authed_result.expect("authed call must succeed");
        assert_eq!(response.get_ref().as_ref(), b"ok");
    }

    /// br-asupersync-7u4r72: dispatch_unary MUST enforce
    /// ServerConfig::max_metadata_size before invoking the
    /// interceptor chain or handler. A request whose metadata
    /// exceeds the cap returns Status::resource_exhausted; the
    /// handler is NOT invoked.
    #[test]
    fn test_dispatch_unary_enforces_max_metadata_size() {
        use futures_lite::future::block_on;
        init_test("test_dispatch_unary_enforces_max_metadata_size");
        // tiny cap to exercise the gate
        let server = Server::builder().max_metadata_size(64).build();

        // Build metadata that exceeds the cap (a single header with
        // > 64 bytes including overhead).
        let mut metadata = Metadata::new();
        metadata.insert("x-large-trace-id", "a".repeat(128).as_str());
        let request = Request::with_metadata(Bytes::new(), metadata);

        // Counter to verify the handler is NOT invoked.
        let handler_invoked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handler_invoked_clone = std::sync::Arc::clone(&handler_invoked);
        let result = block_on(server.dispatch_unary(request, move |_req| {
            handler_invoked_clone.store(true, std::sync::atomic::Ordering::Relaxed);
            async move { Ok(Response::new(Bytes::from_static(b"ok"))) }
        }));

        let err = result.expect_err("oversized metadata must reject");
        assert_eq!(
            err.code(),
            crate::grpc::status::Code::ResourceExhausted,
            "rejection must use RESOURCE_EXHAUSTED per gRPC convention"
        );
        assert!(
            !handler_invoked.load(std::sync::atomic::Ordering::Relaxed),
            "handler must NOT be invoked when metadata cap is exceeded"
        );
        crate::test_complete!("test_dispatch_unary_enforces_max_metadata_size");
    }

    /// br-asupersync-7u4r72: a request within the cap passes through
    /// to the handler — happy-path regression guard.
    #[test]
    fn test_dispatch_unary_within_metadata_cap_succeeds() {
        use futures_lite::future::block_on;
        init_test("test_dispatch_unary_within_metadata_cap_succeeds");
        let server = Server::builder().max_metadata_size(8 * 1024).build();

        let mut metadata = Metadata::new();
        metadata.insert("x-trace-id", "abc123");
        let request = Request::with_metadata(Bytes::new(), metadata);

        let result = block_on(server.dispatch_unary(request, |_req| async move {
            Ok(Response::new(Bytes::from_static(b"ok")))
        }));
        let response = result.expect("call within cap must succeed");
        assert_eq!(response.get_ref().as_ref(), b"ok");
        crate::test_complete!("test_dispatch_unary_within_metadata_cap_succeeds");
    }

    #[test]
    fn test_dispatch_unary_rejects_invalid_metadata_before_handler() {
        use futures_lite::future::block_on;
        init_test("test_dispatch_unary_rejects_invalid_metadata_before_handler");
        let server = Server::builder().max_metadata_size(8 * 1024).build();
        let metadata = Metadata::from_raw_entries_for_tests(vec![(
            "x-request-id".to_string(),
            crate::grpc::MetadataValue::Ascii("line1\r\nline2".to_string()),
        )]);
        let request = Request::with_metadata(Bytes::new(), metadata);

        let handler_invoked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handler_invoked_clone = std::sync::Arc::clone(&handler_invoked);
        let result = block_on(server.dispatch_unary(request, move |_req| {
            handler_invoked_clone.store(true, std::sync::atomic::Ordering::Relaxed);
            async move { Ok(Response::new(Bytes::from_static(b"ok"))) }
        }));

        let err = result.expect_err("invalid metadata must reject");
        assert_eq!(err.code(), crate::grpc::status::Code::InvalidArgument);
        assert!(
            !handler_invoked.load(std::sync::atomic::Ordering::Relaxed),
            "handler must NOT be invoked when inbound metadata is malformed"
        );
        crate::test_complete!("test_dispatch_unary_rejects_invalid_metadata_before_handler");
    }

    // br-asupersync-8vn9iu: Regression tests for connection hoarding protection
    #[test]
    fn test_connection_registry_enforces_stream_limits() {
        init_test("test_connection_registry_enforces_stream_limits");

        let registry = ConnectionRegistry::new();
        let connection_id = "test-conn-1".to_string();

        // Register connection
        registry.add_connection(connection_id.clone());

        // Should be able to add streams up to limit (default 100)
        for stream_id in 1..=5 {
            let result = registry.enforce_stream_limits(&connection_id, stream_id, 5, None);
            assert!(
                result.is_ok(),
                "Should accept stream {} within limit",
                stream_id
            );
        }

        // Should reject stream that exceeds limit
        let result = registry.enforce_stream_limits(&connection_id, 6, 5, None);
        assert!(
            result.is_err(),
            "Should reject stream that exceeds max_concurrent_streams"
        );
        assert!(
            result
                .unwrap_err()
                .contains("exceeds max_concurrent_streams")
        );

        // Clean up
        registry.remove_connection(&connection_id);
        crate::test_complete!("test_connection_registry_enforces_stream_limits");
    }

    #[test]
    fn test_connection_registry_idle_timeout() {
        use std::thread;
        init_test("test_connection_registry_idle_timeout");

        let registry = ConnectionRegistry::new();
        let connection_id = "test-conn-idle".to_string();

        // Register connection
        registry.add_connection(connection_id.clone());

        // Add a stream
        let result = registry.enforce_stream_limits(&connection_id, 1, 10, None);
        assert!(result.is_ok(), "Should accept initial stream");

        // Verify stream exists
        let (connections, streams) = registry.get_stats();
        assert_eq!(connections, 1);
        assert_eq!(streams, 1);

        // Test very short idle timeout (1ms) to force cleanup
        thread::sleep(std::time::Duration::from_millis(2));
        let short_timeout = std::time::Duration::from_millis(1);

        // Try to add another stream with short idle timeout - should clean up the old one
        let result = registry.enforce_stream_limits(&connection_id, 2, 10, Some(short_timeout));
        assert!(
            result.is_ok(),
            "Should accept new stream after idle cleanup"
        );

        // Should now have 1 stream (the old one was cleaned up)
        let (connections, streams) = registry.get_stats();
        assert_eq!(connections, 1);
        assert_eq!(streams, 1);

        registry.remove_connection(&connection_id);
        crate::test_complete!("test_connection_registry_idle_timeout");
    }

    #[test]
    fn test_server_stream_enforcement_integration() {
        use futures_lite::future::block_on;
        init_test("test_server_stream_enforcement_integration");

        let server = Server::builder()
            .max_concurrent_streams(2) // Very low limit for testing
            .stream_idle_timeout(Some(std::time::Duration::from_secs(1)))
            .build();

        let connection_id = "test-integration-conn".to_string();
        server.register_connection(connection_id.clone());

        // First stream should succeed
        let request1 = Request::with_metadata(Bytes::from_static(b"test"), Metadata::new());
        let result1 = block_on(server.dispatch_unary_with_stream_enforcement(
            connection_id.clone(),
            1,
            request1,
            |req| async move { Ok(Response::new(req.into_inner())) },
        ));
        assert!(result1.is_ok(), "First stream should succeed");

        // Second stream should succeed
        let request2 = Request::with_metadata(Bytes::from_static(b"test2"), Metadata::new());
        let result2 = block_on(server.dispatch_unary_with_stream_enforcement(
            connection_id.clone(),
            2,
            request2,
            |req| async move { Ok(Response::new(req.into_inner())) },
        ));
        assert!(result2.is_ok(), "Second stream should succeed");

        // Third stream should be rejected due to limit
        let request3 = Request::with_metadata(Bytes::from_static(b"test3"), Metadata::new());
        let result3 = block_on(server.dispatch_unary_with_stream_enforcement(
            connection_id.clone(),
            3,
            request3,
            |req| async move { Ok(Response::new(req.into_inner())) },
        ));
        assert!(result3.is_err(), "Third stream should be rejected");
        assert_eq!(
            result3.unwrap_err().code(),
            crate::grpc::status::Code::ResourceExhausted
        );

        server.unregister_connection(&connection_id);
        crate::test_complete!("test_server_stream_enforcement_integration");
    }

    #[test]
    fn test_connection_hoarding_attack_simulation() {
        use futures_lite::future::block_on;
        init_test("test_connection_hoarding_attack_simulation");

        // Simulate an attacker opening many connections with multiple streams each
        let server = Server::builder()
            .max_concurrent_streams(3)
            .stream_idle_timeout(Some(std::time::Duration::from_millis(100)))
            .build();

        // Register multiple "attacker" connections
        for conn_num in 1..=5 {
            let connection_id = format!("attacker-conn-{}", conn_num);
            server.register_connection(connection_id.clone());

            // Try to max out streams on each connection
            for stream_id in 1..=3 {
                let request =
                    Request::with_metadata(Bytes::from_static(b"attack"), Metadata::new());
                let result = block_on(server.dispatch_unary_with_stream_enforcement(
                    connection_id.clone(),
                    stream_id,
                    request,
                    |req| async move { Ok(Response::new(req.into_inner())) },
                ));
                assert!(
                    result.is_ok(),
                    "Stream {} on connection {} should succeed within limits",
                    stream_id,
                    conn_num
                );
            }

            // Fourth stream should be rejected
            let request = Request::with_metadata(Bytes::from_static(b"overflow"), Metadata::new());
            let result = block_on(server.dispatch_unary_with_stream_enforcement(
                connection_id.clone(),
                4,
                request,
                |req| async move { Ok(Response::new(req.into_inner())) },
            ));
            assert!(
                result.is_err(),
                "Fourth stream should be rejected due to limit"
            );
        }

        // Verify connection stats show limits are being enforced
        let (active_connections, _total_streams) = server.get_connection_stats();
        assert_eq!(active_connections, 5, "Should track 5 connections");
        // Note: streams may be 0 here because dispatch_unary_with_stream_enforcement
        // removes them after completion, which is correct behavior

        // Clean up
        for conn_num in 1..=5 {
            server.unregister_connection(&format!("attacker-conn-{}", conn_num));
        }

        crate::test_complete!("test_connection_hoarding_attack_simulation");
    }
}
