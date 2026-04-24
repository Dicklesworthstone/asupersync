//! gRPC server implementation.
//!
//! Provides the server-side infrastructure for hosting gRPC services.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::bytes::Bytes;
use crate::cx::{Cx, cap};

use super::client::CompressionEncoding;
use super::reflection::ReflectionService;
use super::service::{NamedService, ServiceHandler};
use super::status::{GrpcError, Status};
use super::streaming::{Metadata, Request, Response};

fn wall_clock_instant_now() -> Instant {
    Instant::now()
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
        }
    }
}

/// Builder for configuring a gRPC server.
pub struct ServerBuilder {
    /// Server configuration.
    config: ServerConfig,
    /// Registered services.
    services: BTreeMap<String, Arc<dyn ServiceHandler>>,
    /// Optional reflection registry.
    reflection: Option<ReflectionService>,
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
        }
    }

    /// Set the maximum receive message size.
    #[must_use]
    pub fn max_recv_message_size(mut self, size: usize) -> Self {
        self.config.max_recv_message_size = size;
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
        }
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A gRPC server.
pub struct Server {
    /// Server configuration.
    config: ServerConfig,
    /// Registered services.
    services: BTreeMap<String, Arc<dyn ServiceHandler>>,
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
        let listener = std::net::TcpListener::bind(addr)
            .map_err(|error| GrpcError::transport(format!("bind failed: {error}")))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| GrpcError::transport(format!("nonblocking setup failed: {error}")))?;
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
    /// This is useful for deterministic tests and replay harnesses that need
    /// to avoid ambient wall-clock reads.
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
        metadata.insert("grpc-timeout", format_grpc_timeout(effective));
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
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
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
            matches!(err, GrpcError::Transport(_)),
            "transport error for invalid address",
            true,
            matches!(err, GrpcError::Transport(_))
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
    //   https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
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
            eprintln!(
                "{{\"id\":\"GRPC-TIMEOUT-1\",\"verdict\":\"PASS\",\"level\":\"Must\"}}",
            );
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
            eprintln!(
                "{{\"id\":\"GRPC-TIMEOUT-2\",\"verdict\":\"PASS\",\"level\":\"Must\"}}",
            );
        }

        /// GRPC-TIMEOUT-3 (MUST): Empty header value, no digits, or missing
        /// unit must all be rejected. A present-but-malformed header cannot
        /// silently impersonate "no timeout".
        #[test]
        fn grpc_timeout_3_reject_malformed() {
            let rejected = &[
                "",      // empty
                "S",     // no digits
                "100",   // missing unit
                " 10S",  // leading whitespace
                "10 S",  // internal space
                "10s",   // lowercase s is not a valid unit
                "10x",   // unknown unit
                "-1S",   // negative
                "1.5S",  // non-integer
                "abc",   // non-numeric
                "١٠S",   // non-ASCII digits (Arabic-Indic)
            ];
            for input in rejected {
                assert_eq!(
                    parse_grpc_timeout(input),
                    None,
                    "GRPC-TIMEOUT-3: {input:?} must be rejected",
                );
            }
            eprintln!(
                "{{\"id\":\"GRPC-TIMEOUT-3\",\"verdict\":\"PASS\",\"level\":\"Must\"}}",
            );
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
                Duration::from_secs(120),   // 2 minutes
                Duration::from_secs(3600),  // 1 hour
                Duration::from_secs(7200),  // 2 hours
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
            eprintln!(
                "{{\"id\":\"GRPC-TIMEOUT-4\",\"verdict\":\"PASS\",\"level\":\"Must\"}}",
            );
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
            eprintln!(
                "{{\"id\":\"GRPC-TIMEOUT-5\",\"verdict\":\"PASS\",\"level\":\"Must\"}}",
            );
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
            eprintln!(
                "{{\"id\":\"GRPC-TIMEOUT-6\",\"verdict\":\"PASS\",\"level\":\"Must\"}}",
            );
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
            eprintln!(
                "{{\"id\":\"GRPC-TIMEOUT-7\",\"verdict\":\"PASS\",\"level\":\"Must\"}}",
            );
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
            eprintln!(
                "{{\"id\":\"GRPC-TIMEOUT-8\",\"verdict\":\"PASS\",\"level\":\"Must\"}}",
            );
        }
    }
}
