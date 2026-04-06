//! gRPC client implementation.
//!
//! Provides client-side infrastructure for calling gRPC services.

use std::any::Any;
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use crate::bytes::Bytes;

use super::codec::{Codec, FramedCodec, IdentityCodec};
use super::status::{GrpcError, Status};
use super::streaming::{MAX_STREAM_BUFFERED, Metadata, Request, Response, Streaming};

/// Supported gRPC message compression encodings for channel negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionEncoding {
    /// No compression.
    Identity,
    /// Gzip compression.
    Gzip,
}

impl CompressionEncoding {
    fn as_header_value(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Gzip => "gzip",
        }
    }

    /// Parse a compression encoding from the `grpc-encoding` header value.
    #[must_use]
    pub fn from_header_value(value: &str) -> Option<Self> {
        match value {
            "identity" => Some(Self::Identity),
            "gzip" => Some(Self::Gzip),
            _ => None,
        }
    }

    /// Return the frame compressor for this encoding, if any.
    ///
    /// Returns `None` for `Identity` (no compression needed).
    /// Requires the `compression` feature for `Gzip`.
    #[must_use]
    pub fn frame_compressor(self) -> Option<super::codec::FrameCompressor> {
        match self {
            Self::Identity => None,
            #[cfg(feature = "compression")]
            Self::Gzip => Some(super::codec::gzip_frame_compress),
            #[cfg(not(feature = "compression"))]
            Self::Gzip => None,
        }
    }

    /// Return the frame decompressor for this encoding, if any.
    ///
    /// Returns `None` for `Identity` (no decompression needed).
    /// Requires the `compression` feature for `Gzip`.
    #[must_use]
    pub fn frame_decompressor(self) -> Option<super::codec::FrameDecompressor> {
        match self {
            Self::Identity => None,
            #[cfg(feature = "compression")]
            Self::Gzip => Some(super::codec::gzip_frame_decompress),
            #[cfg(not(feature = "compression"))]
            Self::Gzip => None,
        }
    }
}

fn effective_send_compression(config: &ChannelConfig) -> Option<CompressionEncoding> {
    match config.send_compression {
        Some(CompressionEncoding::Identity) => Some(CompressionEncoding::Identity),
        Some(encoding) if encoding.frame_compressor().is_some() => Some(encoding),
        _ => None,
    }
}

fn effective_accept_compressions(config: &ChannelConfig) -> Vec<CompressionEncoding> {
    let mut encodings = Vec::new();
    for encoding in &config.accept_compression {
        let supported = matches!(encoding, CompressionEncoding::Identity)
            || encoding.frame_decompressor().is_some();
        if supported && !encodings.contains(encoding) {
            encodings.push(*encoding);
        }
    }
    encodings
}

fn client_framed_codec<C: Codec>(channel: &Channel, codec: C) -> FramedCodec<C> {
    let send_compression = effective_send_compression(channel.config());
    let compressor = send_compression.and_then(CompressionEncoding::frame_compressor);
    let decompressor = effective_accept_compressions(channel.config())
        .into_iter()
        .find(|encoding| *encoding != CompressionEncoding::Identity)
        .and_then(CompressionEncoding::frame_decompressor);

    FramedCodec::new(codec).with_frame_hooks(compressor, decompressor)
}

/// gRPC channel configuration.
#[derive(Debug, Clone)]
pub struct ChannelConfig {
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Request timeout (deadline).
    pub timeout: Option<Duration>,
    /// Maximum message size for receiving.
    pub max_recv_message_size: usize,
    /// Maximum message size for sending.
    pub max_send_message_size: usize,
    /// Initial connection window size.
    pub initial_connection_window_size: u32,
    /// Initial stream window size.
    pub initial_stream_window_size: u32,
    /// Keep-alive interval.
    pub keepalive_interval: Option<Duration>,
    /// Keep-alive timeout.
    pub keepalive_timeout: Option<Duration>,
    /// Whether to use TLS.
    pub use_tls: bool,
    /// Compression used for outbound messages.
    pub send_compression: Option<CompressionEncoding>,
    /// Compression encodings accepted by this client.
    pub accept_compression: Vec<CompressionEncoding>,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            timeout: None,
            max_recv_message_size: 4 * 1024 * 1024,
            max_send_message_size: 4 * 1024 * 1024,
            initial_connection_window_size: 1024 * 1024,
            initial_stream_window_size: 1024 * 1024,
            keepalive_interval: None,
            keepalive_timeout: None,
            use_tls: false,
            send_compression: None,
            accept_compression: vec![CompressionEncoding::Identity],
        }
    }
}

/// Builder for creating a loopback gRPC channel.
#[derive(Debug)]
pub struct ChannelBuilder {
    /// The target URI.
    uri: String,
    /// Channel configuration.
    config: ChannelConfig,
}

impl ChannelBuilder {
    /// Create a new channel builder for the given URI.
    ///
    /// The current client transport is loopback-only, so successful connects
    /// require the URI host to be `loopback`.
    #[must_use]
    pub fn new(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            config: ChannelConfig::default(),
        }
    }

    /// Set the connection timeout.
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.config.connect_timeout = timeout;
        self
    }

    /// Set the request timeout (deadline).
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = Some(timeout);
        self
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

    /// Set the keep-alive interval.
    #[must_use]
    pub fn keepalive_interval(mut self, interval: Duration) -> Self {
        self.config.keepalive_interval = Some(interval);
        self
    }

    /// Set the keep-alive timeout.
    #[must_use]
    pub fn keepalive_timeout(mut self, timeout: Duration) -> Self {
        self.config.keepalive_timeout = Some(timeout);
        self
    }

    /// Set the outbound compression encoding.
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

    /// Enable TLS.
    #[must_use]
    pub fn tls(mut self) -> Self {
        self.config.use_tls = true;
        self
    }

    /// Build the channel.
    pub async fn connect(self) -> Result<Channel, GrpcError> {
        Channel::connect_with_config(&self.uri, self.config).await
    }
}

/// A gRPC channel representing the current loopback-only client transport.
#[derive(Debug, Clone)]
pub struct Channel {
    /// The target URI.
    uri: String,
    /// Channel configuration.
    config: ChannelConfig,
}

impl Channel {
    /// Create a channel builder for the given URI.
    #[must_use]
    pub fn builder(uri: impl Into<String>) -> ChannelBuilder {
        ChannelBuilder::new(uri)
    }

    /// Connect to the loopback gRPC client transport at the given URI.
    ///
    /// The current implementation is an in-memory loopback transport rather
    /// than a network HTTP/2 client, so the URI host must be `loopback`.
    pub async fn connect(uri: impl Into<String>) -> Result<Self, GrpcError> {
        Self::connect_with_config(&uri.into(), ChannelConfig::default()).await
    }

    /// Connect with custom configuration.
    ///
    /// The current implementation is an in-memory loopback transport rather
    /// than a network HTTP/2 client, so the URI host must be `loopback`.
    #[allow(clippy::unused_async)]
    pub async fn connect_with_config(uri: &str, config: ChannelConfig) -> Result<Self, GrpcError> {
        validate_channel_uri(uri)?;
        Ok(Self {
            uri: uri.to_string(),
            config,
        })
    }

    /// Get the target URI.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Get the channel configuration.
    #[must_use]
    pub fn config(&self) -> &ChannelConfig {
        &self.config
    }
}

/// A gRPC client for making RPC calls.
pub struct GrpcClient<C = IdentityCodec> {
    /// The underlying channel.
    channel: Channel,
    /// The codec for message serialization.
    codec: FramedCodec<C>,
    /// Client interceptor chain.
    client_interceptors: Vec<Arc<dyn ClientInterceptor>>,
}

impl<C: fmt::Debug> fmt::Debug for GrpcClient<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrpcClient")
            .field("channel", &self.channel)
            .field("codec", &self.codec)
            .field(
                "client_interceptors",
                &format!("[{} interceptors]", self.client_interceptors.len()),
            )
            .finish()
    }
}

impl GrpcClient<IdentityCodec> {
    /// Create a new client with an identity codec.
    #[must_use]
    pub fn new(channel: Channel) -> Self {
        let framed_codec = client_framed_codec(&channel, IdentityCodec);
        Self {
            channel,
            codec: framed_codec,
            client_interceptors: Vec::new(),
        }
    }
}

impl<C: Codec> GrpcClient<C> {
    /// Create a new client with a custom codec.
    #[must_use]
    pub fn with_codec(channel: Channel, codec: C) -> Self {
        let framed_codec = client_framed_codec(&channel, codec);
        Self {
            channel,
            codec: framed_codec,
            client_interceptors: Vec::new(),
        }
    }

    /// Get the underlying channel.
    pub fn channel(&self) -> &Channel {
        &self.channel
    }

    /// Add one client interceptor and return the updated client.
    #[must_use]
    pub fn with_interceptor<I>(mut self, interceptor: I) -> Self
    where
        I: ClientInterceptor + 'static,
    {
        self.client_interceptors.push(Arc::new(interceptor));
        self
    }

    /// Add multiple client interceptors and return the updated client.
    #[must_use]
    pub fn with_interceptors<I>(mut self, interceptors: impl IntoIterator<Item = I>) -> Self
    where
        I: ClientInterceptor + 'static,
    {
        let interceptors = interceptors.into_iter();
        let (lower, upper) = interceptors.size_hint();
        self.client_interceptors.reserve(upper.unwrap_or(lower));
        for interceptor in interceptors {
            self.client_interceptors.push(Arc::new(interceptor));
        }
        self
    }

    /// Register one client interceptor in place.
    pub fn add_interceptor<I>(&mut self, interceptor: I)
    where
        I: ClientInterceptor + 'static,
    {
        self.client_interceptors.push(Arc::new(interceptor));
    }

    /// Returns the number of registered client interceptors.
    #[must_use]
    pub fn interceptor_count(&self) -> usize {
        self.client_interceptors.len()
    }

    fn build_outbound_metadata<Req>(
        &self,
        request: &Request<Req>,
        path: &str,
    ) -> Result<Metadata, Status> {
        let mut metadata_request = Request::with_metadata(Bytes::new(), request.metadata().clone());
        self.apply_channel_metadata_defaults(metadata_request.metadata_mut());
        self.apply_client_interceptors(&mut metadata_request)?;

        let mut metadata = metadata_request.metadata().clone();
        metadata.insert("x-asupersync-grpc-path", path);
        metadata.insert("x-asupersync-grpc-transport", "loopback");
        Ok(metadata)
    }

    fn apply_channel_metadata_defaults(&self, metadata: &mut Metadata) {
        if metadata.get("grpc-timeout").is_none()
            && let Some(timeout) = self.channel.config.timeout
        {
            metadata.insert("grpc-timeout", encode_grpc_timeout(timeout));
        }

        if metadata.get("grpc-encoding").is_none()
            && let Some(encoding) = effective_send_compression(self.channel.config())
        {
            metadata.insert("grpc-encoding", encoding.as_header_value());
        }

        let accept_compression = effective_accept_compressions(self.channel.config());
        if metadata.get("grpc-accept-encoding").is_none() && !accept_compression.is_empty() {
            let encodings = accept_compression
                .iter()
                .map(|encoding| encoding.as_header_value())
                .collect::<Vec<_>>()
                .join(",");
            metadata.insert("grpc-accept-encoding", encodings);
        }
    }

    fn apply_client_interceptors(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        for interceptor in &self.client_interceptors {
            interceptor.intercept(request)?;
        }
        Ok(())
    }

    /// Make a unary RPC call.
    #[allow(clippy::unused_async)]
    pub async fn unary<Req, Resp>(
        &mut self,
        path: &str,
        request: Request<Req>,
    ) -> Result<Response<Resp>, Status>
    where
        Req: Send + 'static,
        Resp: Send + 'static,
    {
        validate_rpc_path(path)?;
        enforce_deadline_budget(self.channel.config.timeout)?;

        let metadata = self.build_outbound_metadata(&request, path)?;
        let payload = convert_message::<Req, Resp>(request.into_inner(), "unary call")?;
        Ok(Response::with_metadata(payload, metadata))
    }

    /// Start a server streaming RPC call.
    #[allow(clippy::unused_async)]
    pub async fn server_streaming<Req, Resp>(
        &mut self,
        path: &str,
        request: Request<Req>,
    ) -> Result<Response<ResponseStream<Resp>>, Status>
    where
        Req: Send + 'static,
        Resp: Send + 'static,
    {
        validate_rpc_path(path)?;
        enforce_deadline_budget(self.channel.config.timeout)?;

        let metadata = self.build_outbound_metadata(&request, path)?;
        let mut stream = ResponseStream::open();
        let payload = convert_message::<Req, Resp>(request.into_inner(), "server streaming call")?;
        stream.push(Ok(payload))?;
        stream.close();

        Ok(Response::with_metadata(stream, metadata))
    }

    /// Start a client streaming RPC call.
    #[allow(clippy::unused_async)]
    pub async fn client_streaming<Req, Resp>(
        &mut self,
        path: &str,
    ) -> Result<(RequestSink<Req>, ResponseFuture<Resp>), Status>
    where
        Req: Send + 'static,
        Resp: Send + 'static,
    {
        validate_rpc_path(path)?;
        enforce_deadline_budget(self.channel.config.timeout)?;

        let request = Request::new(Bytes::new());
        let metadata = self.build_outbound_metadata(&request, path)?;
        let state = Arc::new(Mutex::new(RequestSinkState::new()));
        let sink = RequestSink::from_state(state.clone());
        let future = ResponseFuture::with_resolver(state, move |state| {
            let Some(last) = state.last_message.take() else {
                return Err(Status::invalid_argument(
                    "client stream closed without any request messages",
                ));
            };
            let response =
                downcast_boxed_message::<Resp>(last, "client streaming response conversion")?;
            Ok(Response::with_metadata(response, metadata.clone()))
        });
        Ok((sink, future))
    }

    /// Start a bidirectional streaming RPC call.
    #[allow(clippy::unused_async)]
    pub async fn bidi_streaming<Req, Resp>(
        &mut self,
        path: &str,
    ) -> Result<(RequestSink<Req>, ResponseStream<Resp>), Status>
    where
        Req: Send + 'static,
        Resp: Send + 'static,
    {
        validate_rpc_path(path)?;
        enforce_deadline_budget(self.channel.config.timeout)?;

        let stream = ResponseStream::open();
        let mut send_stream = stream.clone();
        let close_stream = stream.clone();
        let sink = RequestSink::with_hooks(
            Some(Box::new(move |message: Req| {
                let response =
                    convert_message::<Req, Resp>(message, "bidirectional streaming conversion")?;
                send_stream.push(Ok(response))
            })),
            Some(Box::new(move || {
                close_stream.close();
                Ok(())
            })),
        );
        Ok((sink, stream))
    }
}

fn validate_channel_uri(uri: &str) -> Result<(), GrpcError> {
    if uri.is_empty() {
        return Err(GrpcError::transport("channel URI cannot be empty"));
    }
    if !(uri.starts_with("http://") || uri.starts_with("https://")) {
        return Err(GrpcError::transport(
            "channel URI must start with http:// or https://",
        ));
    }
    let (_, remainder) = uri
        .split_once("://")
        .ok_or_else(|| GrpcError::transport("channel URI is missing a scheme separator"))?;
    let authority = remainder
        .split(['/', '?', '#'])
        .next()
        .ok_or_else(|| GrpcError::transport("channel URI is missing an authority"))?;
    // Strip userinfo (RFC 3986 §3.2: authority = [userinfo "@"] host [":" port])
    // before extracting the host, so "loopback:pw@evil.com" doesn't pass.
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, hp)| hp);
    let host = host_port
        .split_once(':')
        .map_or(host_port, |(host, _)| host)
        .trim();
    if host.is_empty() {
        return Err(GrpcError::transport("channel URI is missing a host"));
    }
    if !host.eq_ignore_ascii_case("loopback") {
        return Err(GrpcError::transport(
            "gRPC client transport is loopback-only today; use a URI with host `loopback`",
        ));
    }
    Ok(())
}

fn validate_rpc_path(path: &str) -> Result<(), Status> {
    if path.is_empty() {
        return Err(Status::invalid_argument("RPC path cannot be empty"));
    }
    if !path.starts_with('/') {
        return Err(Status::invalid_argument(
            "RPC path must start with '/' (for example: /pkg.Service/Method)",
        ));
    }
    let mut segments = path.split('/');
    let _ = segments.next();
    let service = segments.next();
    let method = segments.next();
    if service.is_none_or(str::is_empty)
        || method.is_none_or(str::is_empty)
        || segments.next().is_some()
    {
        return Err(Status::invalid_argument(
            "RPC path must include service and method segments",
        ));
    }
    Ok(())
}

fn enforce_deadline_budget(timeout: Option<Duration>) -> Result<(), Status> {
    if timeout.is_some_and(|value| value.is_zero()) {
        return Err(Status::deadline_exceeded(
            "configured timeout is zero duration",
        ));
    }
    Ok(())
}

fn encode_grpc_timeout(timeout: Duration) -> String {
    const MAX_GRPC_TIMEOUT_VALUE: u128 = 99_999_999;
    const GRPC_TIMEOUT_UNITS: [(u128, char); 6] = [
        (3_600_000_000_000, 'H'),
        (60_000_000_000, 'M'),
        (1_000_000_000, 'S'),
        (1_000_000, 'm'),
        (1_000, 'u'),
        (1, 'n'),
    ];

    let timeout_nanos = timeout.as_nanos().max(1);

    for &(unit_nanos, suffix) in &GRPC_TIMEOUT_UNITS {
        if timeout_nanos.is_multiple_of(unit_nanos) {
            let value = timeout_nanos / unit_nanos;
            if value <= MAX_GRPC_TIMEOUT_VALUE {
                return format!("{value}{suffix}");
            }
        }
    }

    for &(unit_nanos, suffix) in GRPC_TIMEOUT_UNITS.iter().rev() {
        let value = timeout_nanos.div_ceil(unit_nanos);
        if value <= MAX_GRPC_TIMEOUT_VALUE {
            return format!("{value}{suffix}");
        }
    }
    "99999999H".to_owned()
}

fn convert_message<Req, Resp>(request: Req, context: &str) -> Result<Resp, Status>
where
    Req: Send + 'static,
    Resp: Send + 'static,
{
    downcast_boxed_message::<Resp>(Box::new(request), context)
}

fn downcast_boxed_message<T>(message: Box<dyn Any + Send>, context: &str) -> Result<T, Status>
where
    T: Send + 'static,
{
    message.downcast::<T>().map_or_else(
        |_| {
            Err(Status::failed_precondition(format!(
                "{context} requires matching request/response message types in loopback mode"
            )))
        },
        |value| Ok(*value),
    )
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Debug)]
struct ResponseStreamState<T> {
    items: VecDeque<Result<T, Status>>,
    closed: bool,
    waiters: Vec<Waker>,
}

impl<T> ResponseStreamState<T> {
    fn closed() -> Self {
        Self {
            items: VecDeque::new(),
            closed: true,
            waiters: Vec::new(),
        }
    }

    fn open() -> Self {
        Self {
            items: VecDeque::new(),
            closed: false,
            waiters: Vec::new(),
        }
    }

    fn take_waiters(&mut self) -> Vec<Waker> {
        std::mem::take(&mut self.waiters)
    }

    fn register_waiter(&mut self, waker: &Waker) {
        if !self
            .waiters
            .iter()
            .any(|existing| existing.will_wake(waker))
        {
            self.waiters.push(waker.clone());
        }
    }
}

/// A stream of responses from the server.
#[derive(Debug)]
pub struct ResponseStream<T> {
    state: Arc<Mutex<ResponseStreamState<T>>>,
}

impl<T> Clone for ResponseStream<T> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl<T> ResponseStream<T> {
    /// Create a new response stream.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ResponseStreamState::closed())),
        }
    }

    /// Create an open response stream that can receive additional items.
    #[must_use]
    pub fn open() -> Self {
        Self {
            state: Arc::new(Mutex::new(ResponseStreamState::open())),
        }
    }

    /// Push a response item into the stream.
    ///
    /// Returns an error if the stream has already been closed.
    pub fn push(&mut self, item: Result<T, Status>) -> Result<(), Status> {
        let waiters = {
            let mut state = lock_unpoisoned(&self.state);
            if state.closed {
                return Err(Status::failed_precondition(
                    "cannot push to a closed response stream",
                ));
            }
            if state.items.len() >= MAX_STREAM_BUFFERED {
                return Err(Status::resource_exhausted(
                    "response stream buffer full — apply backpressure",
                ));
            }
            state.items.push_back(item);
            state.take_waiters()
        };
        for waker in waiters {
            waker.wake();
        }
        Ok(())
    }

    /// Close the stream.
    pub fn close(&self) {
        let waiters = {
            let mut state = lock_unpoisoned(&self.state);
            state.closed = true;
            state.take_waiters()
        };
        for waker in waiters {
            waker.wake();
        }
    }
}

impl<T> Default for ResponseStream<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Send> Streaming for ResponseStream<T> {
    type Message = T;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Message, Status>>> {
        let mut state = lock_unpoisoned(&self.state);
        if let Some(item) = state.items.pop_front() {
            return Poll::Ready(Some(item));
        }
        if state.closed {
            return Poll::Ready(None);
        }
        state.register_waiter(cx.waker());
        Poll::Pending
    }
}

type SendHook<T> = Box<dyn FnMut(T) -> Result<(), Status> + Send>;
type CloseHook = Box<dyn FnMut() -> Result<(), Status> + Send>;

#[derive(Default)]
struct RequestSinkState {
    closed: bool,
    sent_count: usize,
    last_message: Option<Box<dyn Any + Send>>,
    waiter: Option<Waker>,
}

impl RequestSinkState {
    fn new() -> Self {
        Self::default()
    }
}

/// A sink for sending requests to the server.
pub struct RequestSink<T> {
    state: Arc<Mutex<RequestSinkState>>,
    on_send: Option<SendHook<T>>,
    on_close: Option<CloseHook>,
}

impl<T> RequestSink<T> {
    /// Create a new request sink.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(RequestSinkState::new())),
            on_send: None,
            on_close: None,
        }
    }

    fn from_state(state: Arc<Mutex<RequestSinkState>>) -> Self {
        Self {
            state,
            on_send: None,
            on_close: None,
        }
    }

    fn with_hooks(on_send: Option<SendHook<T>>, on_close: Option<CloseHook>) -> Self {
        Self {
            state: Arc::new(Mutex::new(RequestSinkState::new())),
            on_send,
            on_close,
        }
    }

    /// Send a request message.
    #[allow(clippy::unused_async)]
    pub async fn send(&mut self, message: T) -> Result<(), Status>
    where
        T: Send + 'static,
    {
        if self.on_send.is_none() {
            let closed = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let closed = state.closed;
                if !closed {
                    state.last_message = Some(Box::new(message));
                    state.sent_count = state.sent_count.saturating_add(1);
                }
                drop(state);
                closed
            };
            if closed {
                return Err(Status::failed_precondition(
                    "cannot send after request sink is closed",
                ));
            }
            return Ok(());
        }

        let closed = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.closed
        };
        if closed {
            return Err(Status::failed_precondition(
                "cannot send after request sink is closed",
            ));
        }
        if let Some(hook) = self.on_send.as_mut() {
            hook(message)?;
        }
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.sent_count = state.sent_count.saturating_add(1);
        }
        Ok(())
    }

    /// Close the sink, signaling no more requests.
    #[allow(clippy::unused_async)]
    pub async fn close(&mut self) -> Result<(), Status> {
        let waiter = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.closed {
                return Ok(());
            }
            state.closed = true;
            state.waiter.take()
        };
        if let Some(waiter) = waiter {
            waiter.wake();
        }
        if let Some(hook) = self.on_close.as_mut() {
            hook()?;
        }
        Ok(())
    }
}

impl<T> Drop for RequestSink<T> {
    fn drop(&mut self) {
        let (waiter, invoke_close_hook) = {
            let mut state = lock_unpoisoned(&self.state);
            if state.closed {
                (None, false)
            } else {
                state.closed = true;
                (state.waiter.take(), true)
            }
        };

        if let Some(waiter) = waiter {
            waiter.wake();
        }

        if invoke_close_hook {
            if let Some(hook) = self.on_close.as_mut() {
                let _ = hook();
            }
        }
    }
}

impl<T> fmt::Debug for RequestSink<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f.debug_struct("RequestSink")
            .field("closed", &state.closed)
            .field("sent_count", &state.sent_count)
            .field("has_send_hook", &self.on_send.is_some())
            .field("has_close_hook", &self.on_close.is_some())
            .finish()
    }
}

impl<T> Default for RequestSink<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// A future that resolves to a response.
pub struct ResponseFuture<T> {
    state: Arc<Mutex<RequestSinkState>>,
    resolver: Option<ResponseResolver<T>>,
}

type ResponseResolver<T> =
    Box<dyn FnMut(&mut RequestSinkState) -> Result<Response<T>, Status> + Send>;

impl<T> fmt::Debug for ResponseFuture<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f.debug_struct("ResponseFuture")
            .field("sink_closed", &state.closed)
            .field("sink_sent_count", &state.sent_count)
            .field("has_resolver", &self.resolver.is_some())
            .finish()
    }
}

impl<T> ResponseFuture<T> {
    /// Create a new response future.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(RequestSinkState {
                closed: true,
                ..RequestSinkState::new()
            })),
            resolver: Some(Box::new(|_| {
                Err(Status::failed_precondition(
                    "response future is not linked to a request sink",
                ))
            })),
        }
    }

    fn with_resolver<F>(state: Arc<Mutex<RequestSinkState>>, resolver: F) -> Self
    where
        F: FnMut(&mut RequestSinkState) -> Result<Response<T>, Status> + Send + 'static,
    {
        Self {
            state,
            resolver: Some(Box::new(resolver)),
        }
    }
}

impl<T> Default for ResponseFuture<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Send> Future for ResponseFuture<T> {
    type Output = Result<Response<T>, Status>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut state = lock_unpoisoned(&this.state);
        if !state.closed {
            if !state
                .waiter
                .as_ref()
                .is_some_and(|w| w.will_wake(cx.waker()))
            {
                state.waiter = Some(cx.waker().clone());
            }
            drop(state);
            return Poll::Pending;
        }
        let Some(mut resolver) = this.resolver.take() else {
            drop(state);
            return Poll::Ready(Err(Status::failed_precondition(
                "response future has already completed",
            )));
        };
        let output = resolver(&mut state);
        drop(state);
        Poll::Ready(output)
    }
}

/// Client interceptor for modifying requests.
pub trait ClientInterceptor: Send + Sync {
    /// Intercept a request before it is sent.
    fn intercept(&self, request: &mut Request<Bytes>) -> Result<(), Status>;
}

impl<T> ClientInterceptor for T
where
    T: super::server::Interceptor,
{
    fn intercept(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        self.intercept_request(request)
    }
}

/// A client interceptor that adds metadata to requests.
#[derive(Debug, Clone)]
pub struct MetadataInterceptor {
    /// Metadata to add.
    metadata: Metadata,
}

impl MetadataInterceptor {
    /// Create a new metadata interceptor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            metadata: Metadata::new(),
        }
    }

    /// Add an ASCII metadata value.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

impl Default for MetadataInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientInterceptor for MetadataInterceptor {
    fn intercept(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        let request_metadata = request.metadata_mut();
        request_metadata.reserve(self.metadata.len());
        for (key, value) in self.metadata.iter() {
            match value {
                super::streaming::MetadataValue::Ascii(v) => {
                    request_metadata.insert(key, v.clone());
                }
                super::streaming::MetadataValue::Binary(v) => {
                    request_metadata.insert_bin(key, v.clone());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    struct CountWaker(Arc<AtomicUsize>);

    impl Wake for CountWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counting_waker(counter: &Arc<AtomicUsize>) -> Waker {
        Waker::from(Arc::new(CountWaker(Arc::clone(counter))))
    }

    fn poll_stream<T: Send>(
        stream: &mut ResponseStream<T>,
        waker: &Waker,
    ) -> Poll<Option<Result<T, Status>>> {
        let mut cx = Context::from_waker(waker);
        Streaming::poll_next(Pin::new(stream), &mut cx)
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_channel_builder() {
        init_test("test_channel_builder");
        let builder = Channel::builder("http://loopback:50051")
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .max_recv_message_size(8 * 1024 * 1024);

        crate::assert_with_log!(
            builder.config.connect_timeout == Duration::from_secs(10),
            "connect_timeout",
            Duration::from_secs(10),
            builder.config.connect_timeout
        );
        crate::assert_with_log!(
            builder.config.timeout == Some(Duration::from_secs(30)),
            "timeout",
            Some(Duration::from_secs(30)),
            builder.config.timeout
        );
        crate::assert_with_log!(
            builder.config.max_recv_message_size == 8 * 1024 * 1024,
            "max_recv_message_size",
            8 * 1024 * 1024,
            builder.config.max_recv_message_size
        );
        crate::test_complete!("test_channel_builder");
    }

    #[test]
    fn test_channel_config_default() {
        init_test("test_channel_config_default");
        let config = ChannelConfig::default();
        crate::assert_with_log!(
            config.connect_timeout == Duration::from_secs(5),
            "connect_timeout",
            Duration::from_secs(5),
            config.connect_timeout
        );
        let timeout_none = config.timeout.is_none();
        crate::assert_with_log!(timeout_none, "timeout none", true, timeout_none);
        crate::assert_with_log!(!config.use_tls, "use_tls", false, config.use_tls);
        crate::assert_with_log!(
            config.send_compression.is_none(),
            "send compression default",
            true,
            config.send_compression.is_none()
        );
        crate::assert_with_log!(
            config.accept_compression == vec![CompressionEncoding::Identity],
            "accept compression default",
            vec![CompressionEncoding::Identity],
            config.accept_compression
        );
        crate::test_complete!("test_channel_config_default");
    }

    #[test]
    fn test_metadata_interceptor() {
        init_test("test_metadata_interceptor");
        let interceptor = MetadataInterceptor::new()
            .with_metadata("x-custom-header", "value")
            .with_metadata("x-another", "value2");

        let mut request = Request::new(Bytes::new());
        interceptor.intercept(&mut request).unwrap();

        let has_custom = request.metadata().get("x-custom-header").is_some();
        crate::assert_with_log!(has_custom, "custom header", true, has_custom);
        let has_another = request.metadata().get("x-another").is_some();
        crate::assert_with_log!(has_another, "another header", true, has_another);
        crate::test_complete!("test_metadata_interceptor");
    }

    // Pure data-type tests (wave 14 – CyanBarn)

    #[test]
    fn channel_config_debug_clone() {
        let cfg = ChannelConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("ChannelConfig"));

        let cloned = cfg;
        assert_eq!(cloned.connect_timeout, Duration::from_secs(5));
    }

    #[test]
    fn channel_config_default_values() {
        let cfg = ChannelConfig::default();
        assert_eq!(cfg.connect_timeout, Duration::from_secs(5));
        assert!(cfg.timeout.is_none());
        assert_eq!(cfg.max_recv_message_size, 4 * 1024 * 1024);
        assert_eq!(cfg.max_send_message_size, 4 * 1024 * 1024);
        assert_eq!(cfg.initial_connection_window_size, 1024 * 1024);
        assert_eq!(cfg.initial_stream_window_size, 1024 * 1024);
        assert!(cfg.keepalive_interval.is_none());
        assert!(cfg.keepalive_timeout.is_none());
        assert!(!cfg.use_tls);
        assert!(cfg.send_compression.is_none());
        assert_eq!(cfg.accept_compression, vec![CompressionEncoding::Identity]);
    }

    #[test]
    fn channel_builder_debug() {
        let builder = Channel::builder("http://loopback:50051");
        let dbg = format!("{builder:?}");
        assert!(dbg.contains("ChannelBuilder"));
        assert!(dbg.contains("loopback"));
    }

    #[test]
    fn channel_builder_all_setters() {
        let builder = Channel::builder("http://host:443")
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(60))
            .max_recv_message_size(1024)
            .max_send_message_size(2048)
            .initial_connection_window_size(512)
            .initial_stream_window_size(256)
            .keepalive_interval(Duration::from_secs(10))
            .keepalive_timeout(Duration::from_secs(5))
            .send_compression(CompressionEncoding::Gzip)
            .accept_compressions([CompressionEncoding::Identity, CompressionEncoding::Gzip])
            .tls();

        assert_eq!(builder.config.connect_timeout, Duration::from_secs(30));
        assert_eq!(builder.config.timeout, Some(Duration::from_secs(60)));
        assert_eq!(builder.config.max_recv_message_size, 1024);
        assert_eq!(builder.config.max_send_message_size, 2048);
        assert_eq!(builder.config.initial_connection_window_size, 512);
        assert_eq!(builder.config.initial_stream_window_size, 256);
        assert_eq!(
            builder.config.keepalive_interval,
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            builder.config.keepalive_timeout,
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            builder.config.send_compression,
            Some(CompressionEncoding::Gzip)
        );
        assert_eq!(
            builder.config.accept_compression,
            vec![CompressionEncoding::Identity, CompressionEncoding::Gzip]
        );
        assert!(builder.config.use_tls);
    }

    fn make_channel(uri: &str) -> Channel {
        futures_lite::future::block_on(Channel::connect(uri)).unwrap()
    }

    #[test]
    fn channel_debug_clone() {
        let channel = make_channel("http://loopback:8080");
        let dbg = format!("{channel:?}");
        assert!(dbg.contains("Channel"));

        let cloned = channel;
        assert_eq!(cloned.uri(), "http://loopback:8080");
    }

    #[test]
    fn channel_uri_accessor() {
        let channel = make_channel("http://loopback:9090");
        assert_eq!(channel.uri(), "http://loopback:9090");
        assert_eq!(channel.config().connect_timeout, Duration::from_secs(5));
    }

    #[test]
    fn grpc_client_debug() {
        let channel = make_channel("http://loopback:50051");
        let client = GrpcClient::new(channel);
        let dbg = format!("{client:?}");
        assert!(dbg.contains("GrpcClient"));
    }

    #[test]
    fn grpc_client_channel_accessor() {
        let channel = make_channel("http://loopback:80");
        let client = GrpcClient::new(channel);
        assert_eq!(client.channel().uri(), "http://loopback:80");
    }

    #[test]
    fn grpc_client_applies_deadline_metadata_by_default() {
        let channel = futures_lite::future::block_on(
            Channel::builder("http://loopback:80")
                .timeout(Duration::from_secs(2))
                .connect(),
        )
        .expect("channel");
        let mut client = GrpcClient::new(channel);
        let response: Response<String> = futures_lite::future::block_on(
            client.unary("/pkg.Service/Method", Request::new("hello".to_owned())),
        )
        .expect("unary");

        match response.metadata().get("grpc-timeout") {
            Some(super::super::streaming::MetadataValue::Ascii(value)) => {
                assert_eq!(value, "2S");
            }
            other => panic!("expected grpc-timeout metadata, got: {other:?}"),
        }
    }

    #[test]
    fn grpc_client_interceptors_and_compression_metadata_are_applied() {
        use crate::grpc::timeout_interceptor;

        let channel = futures_lite::future::block_on(
            Channel::builder("http://loopback:80")
                .send_compression(CompressionEncoding::Gzip)
                .accept_compressions([CompressionEncoding::Identity, CompressionEncoding::Gzip])
                .connect(),
        )
        .expect("channel");

        let mut client = GrpcClient::new(channel)
            .with_interceptor(timeout_interceptor(777))
            .with_interceptor(MetadataInterceptor::new().with_metadata("x-client-id", "cobalt"));

        let response: Response<String> = futures_lite::future::block_on(
            client.unary("/pkg.Service/Method", Request::new("hello".to_owned())),
        )
        .expect("unary");

        let metadata = response.metadata();
        match metadata.get("grpc-timeout") {
            Some(super::super::streaming::MetadataValue::Ascii(value)) => {
                assert_eq!(value, "777m");
            }
            other => panic!("expected interceptor timeout metadata, got: {other:?}"),
        }
        match metadata.get("grpc-encoding") {
            #[cfg(feature = "compression")]
            Some(super::super::streaming::MetadataValue::Ascii(value)) => {
                assert_eq!(value, "gzip");
            }
            #[cfg(not(feature = "compression"))]
            None => {}
            other => panic!("unexpected grpc-encoding metadata: {other:?}"),
        }
        match metadata.get("grpc-accept-encoding") {
            #[cfg(feature = "compression")]
            Some(super::super::streaming::MetadataValue::Ascii(value)) => {
                assert_eq!(value, "identity,gzip");
            }
            #[cfg(not(feature = "compression"))]
            Some(super::super::streaming::MetadataValue::Ascii(value)) => {
                assert_eq!(value, "identity");
            }
            other => panic!("unexpected grpc-accept-encoding metadata: {other:?}"),
        }
        match metadata.get("x-client-id") {
            Some(super::super::streaming::MetadataValue::Ascii(value)) => {
                assert_eq!(value, "cobalt");
            }
            other => panic!("expected interceptor metadata, got: {other:?}"),
        }
    }

    #[test]
    fn grpc_client_identity_send_compression_keeps_uncompressed_frames() {
        let channel = futures_lite::future::block_on(
            Channel::builder("http://loopback:80")
                .send_compression(CompressionEncoding::Identity)
                .connect(),
        )
        .expect("channel");

        let mut client = GrpcClient::new(channel);
        let mut framed = crate::bytes::BytesMut::new();
        client
            .codec
            .encode_message(&Bytes::from_static(b"hello"), &mut framed)
            .expect("identity framing must encode");

        assert_eq!(
            framed[0], 0,
            "identity send compression must not set compressed flag"
        );
        let buf = framed
            .split_off(crate::grpc::codec::MESSAGE_HEADER_SIZE)
            .freeze();
        assert_eq!(buf.as_ref(), b"hello");
    }

    #[test]
    #[cfg(not(feature = "compression"))]
    fn grpc_client_unsupported_gzip_send_compression_stays_uncompressed() {
        let channel = futures_lite::future::block_on(
            Channel::builder("http://loopback:80")
                .send_compression(CompressionEncoding::Gzip)
                .accept_compression(CompressionEncoding::Gzip)
                .connect(),
        )
        .expect("channel");

        let mut client = GrpcClient::new(channel);
        let mut framed = crate::bytes::BytesMut::new();
        client
            .codec
            .encode_message(&Bytes::from_static(b"hello"), &mut framed)
            .expect("unsupported gzip must fall back to uncompressed framing");

        assert_eq!(
            framed[0], 0,
            "unsupported gzip config must not set compressed flag"
        );
    }

    #[test]
    #[cfg(feature = "compression")]
    fn grpc_client_gzip_send_compression_uses_gzip_frames() {
        let channel = futures_lite::future::block_on(
            Channel::builder("http://loopback:80")
                .send_compression(CompressionEncoding::Gzip)
                .accept_compression(CompressionEncoding::Gzip)
                .connect(),
        )
        .expect("channel");

        let mut client = GrpcClient::new(channel);
        let mut framed = crate::bytes::BytesMut::new();
        client
            .codec
            .encode_message(&Bytes::from_static(b"hello gzip"), &mut framed)
            .expect("gzip framing must encode");

        assert_eq!(
            framed[0], 1,
            "gzip send compression must set compressed flag"
        );
        assert_eq!(
            &framed[crate::grpc::codec::MESSAGE_HEADER_SIZE
                ..crate::grpc::codec::MESSAGE_HEADER_SIZE + 2],
            &[0x1f, 0x8b]
        );
    }

    #[test]
    fn encode_grpc_timeout_prefers_largest_unit_with_eight_digit_limit() {
        assert_eq!(encode_grpc_timeout(Duration::from_secs(2)), "2S");
        assert_eq!(encode_grpc_timeout(Duration::from_millis(1)), "1m");
        assert_eq!(encode_grpc_timeout(Duration::from_nanos(1)), "1n");
        assert_eq!(encode_grpc_timeout(Duration::from_micros(1500)), "1500u");
    }

    #[test]
    fn validate_rpc_path_rejects_empty_or_extra_segments() {
        for path in ["/test.Svc/", "//Method", "/test.Svc/Method/Extra"] {
            let status = validate_rpc_path(path).expect_err("path should be rejected");
            assert_eq!(status.code(), crate::grpc::Code::InvalidArgument);
        }
        assert!(validate_rpc_path("/test.Svc/Method").is_ok());
    }

    #[test]
    fn metadata_interceptor_debug() {
        let interceptor = MetadataInterceptor::new();
        let dbg = format!("{interceptor:?}");
        assert!(dbg.contains("MetadataInterceptor"));
    }

    #[test]
    fn metadata_interceptor_empty() {
        let interceptor = MetadataInterceptor::new();
        let mut request = Request::new(Bytes::new());
        interceptor.intercept(&mut request).unwrap();
        // No headers added - request should still have empty metadata
        assert!(request.metadata().get("nonexistent").is_none());
    }

    // Pure data-type tests (wave 34 – CyanBarn)

    #[test]
    fn response_stream_debug() {
        let stream = ResponseStream::<u8>::new();
        let dbg = format!("{stream:?}");
        assert!(dbg.contains("ResponseStream"));
    }

    #[test]
    fn response_stream_default() {
        let stream = ResponseStream::<i32>::default();
        let dbg = format!("{stream:?}");
        assert!(dbg.contains("ResponseStream"));
    }

    #[test]
    fn response_stream_supports_non_unpin_messages() {
        use std::marker::PhantomPinned;

        struct NonUnpin {
            _pin: PhantomPinned,
        }

        let mut stream = ResponseStream::open();
        stream
            .push(Ok(NonUnpin {
                _pin: PhantomPinned,
            }))
            .unwrap();
        stream.close();

        let first = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        assert!(first.is_some());

        let second = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        assert!(second.is_none());
    }

    #[test]
    fn response_stream_push_rejects_when_buffer_full_and_recovers_after_drain() {
        init_test("response_stream_push_rejects_when_buffer_full_and_recovers_after_drain");
        let mut stream = ResponseStream::<u32>::open();
        for i in 0..MAX_STREAM_BUFFERED as u32 {
            stream.push(Ok(i)).expect("push before saturation succeeds");
        }

        let err = stream
            .push(Ok(MAX_STREAM_BUFFERED as u32))
            .expect_err("push past cap must fail");
        assert_eq!(err.code(), crate::grpc::Code::ResourceExhausted);

        let first = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        assert!(matches!(first, Some(Ok(0))));

        stream
            .push(Ok(MAX_STREAM_BUFFERED as u32))
            .expect("push should succeed after draining one slot");
    }

    #[test]
    fn response_stream_clones_keep_all_pending_readers_wakeable() {
        let mut stream = ResponseStream::<u32>::open();
        let mut first_reader = stream.clone();
        let mut second_reader = stream.clone();
        let first_wake_count = Arc::new(AtomicUsize::new(0));
        let second_wake_count = Arc::new(AtomicUsize::new(0));
        let first_reader_waker = counting_waker(&first_wake_count);
        let second_reader_waker = counting_waker(&second_wake_count);

        assert!(poll_stream(&mut first_reader, &first_reader_waker).is_pending());
        assert!(poll_stream(&mut second_reader, &second_reader_waker).is_pending());

        stream
            .push(Ok(7))
            .expect("push should wake pending readers");
        assert_eq!(
            first_wake_count.load(Ordering::SeqCst),
            1,
            "first cloned reader lost its wakeup",
        );
        assert_eq!(
            second_wake_count.load(Ordering::SeqCst),
            1,
            "second cloned reader should also be notified",
        );

        assert!(matches!(
            poll_stream(&mut first_reader, &first_reader_waker),
            Poll::Ready(Some(Ok(7)))
        ));
        assert!(poll_stream(&mut second_reader, &second_reader_waker).is_pending());

        stream.close();
        assert_eq!(
            second_wake_count.load(Ordering::SeqCst),
            2,
            "close should wake the still-pending cloned reader",
        );
        assert!(matches!(
            poll_stream(&mut second_reader, &second_reader_waker),
            Poll::Ready(None)
        ));
    }

    #[test]
    fn request_sink_debug() {
        let sink = RequestSink::<u8>::new();
        let dbg = format!("{sink:?}");
        assert!(dbg.contains("RequestSink"));
    }

    #[test]
    fn request_sink_default() {
        let sink = RequestSink::<i32>::default();
        let dbg = format!("{sink:?}");
        assert!(dbg.contains("RequestSink"));
    }

    #[test]
    fn request_sink_close_hook_runs_once_when_closed_then_dropped() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let close_count = Arc::new(AtomicUsize::new(0));
        let hook_count = Arc::clone(&close_count);
        let mut sink: RequestSink<u32> = RequestSink::with_hooks(
            None,
            Some(Box::new(move || {
                hook_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })),
        );

        futures_lite::future::block_on(sink.close()).expect("close should succeed");
        drop(sink);

        assert_eq!(
            close_count.load(Ordering::SeqCst),
            1,
            "close hook should run exactly once"
        );
    }

    #[test]
    fn request_sink_failed_send_hook_does_not_increment_sent_count() {
        let mut sink = RequestSink::with_hooks(
            Some(Box::new(|_: u32| {
                Err(Status::internal("send hook rejected the message"))
            })),
            None,
        );

        let error = futures_lite::future::block_on(sink.send(7))
            .expect_err("failing send hook must reject the message");
        assert_eq!(error.code(), crate::grpc::Code::Internal);

        {
            let state = lock_unpoisoned(&sink.state);
            assert_eq!(
                state.sent_count, 0,
                "failed sends must not be counted as successfully sent",
            );
            drop(state);
        }
    }

    #[test]
    fn request_sink_successful_send_hook_increments_sent_count() {
        let mut sink = RequestSink::with_hooks(Some(Box::new(|_: u32| Ok(()))), None);

        futures_lite::future::block_on(sink.send(7))
            .expect("successful send hook should accept the message");

        assert_eq!(
            lock_unpoisoned(&sink.state).sent_count,
            1,
            "successful sends must be counted"
        );
    }

    #[test]
    fn response_future_default() {
        let _fut = ResponseFuture::<i32>::default();
        // ResponseFuture does not derive Debug, but Default is implemented
    }

    #[test]
    fn response_future_new_fails_fast() {
        let response = futures_lite::future::block_on(ResponseFuture::<u8>::new())
            .expect_err("unlinked response future must fail immediately");
        assert_eq!(response.code(), crate::grpc::Code::FailedPrecondition);
    }

    #[test]
    fn metadata_interceptor_clone() {
        let interceptor = MetadataInterceptor::new().with_metadata("x-key", "val");
        let cloned = interceptor;
        let mut request = Request::new(Bytes::new());
        cloned.intercept(&mut request).unwrap();
        assert!(request.metadata().get("x-key").is_some());
    }

    #[test]
    fn metadata_interceptor_default() {
        let interceptor = MetadataInterceptor::default();
        let dbg = format!("{interceptor:?}");
        assert!(dbg.contains("MetadataInterceptor"));
    }

    #[test]
    fn client_streaming_future_resolves_when_sink_is_dropped() {
        let channel = make_channel("http://loopback:50051");
        let mut client = GrpcClient::new(channel);

        let (sink, future) = futures_lite::future::block_on(
            client.client_streaming::<u32, u32>("/pkg.Service/Method"),
        )
        .expect("client streaming setup");

        // Dropping the sink should close the stream and wake the response future.
        drop(sink);
        let result = futures_lite::future::block_on(future);
        assert!(
            result.is_err(),
            "empty dropped stream should resolve with an error"
        );
    }

    #[test]
    fn bidi_stream_closes_when_sink_is_dropped() {
        let channel = make_channel("http://loopback:50051");
        let mut client = GrpcClient::new(channel);

        let (sink, mut stream) = futures_lite::future::block_on(
            client.bidi_streaming::<u32, u32>("/pkg.Service/Method"),
        )
        .expect("bidi streaming setup");

        drop(sink);
        let first = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        assert!(first.is_none(), "drop should close bidi response stream");
    }

    #[test]
    fn channel_connect_rejects_non_loopback_host() {
        let error = futures_lite::future::block_on(Channel::connect("http://localhost:50051"))
            .expect_err("non-loopback target should fail closed");
        match error {
            GrpcError::Transport(message) => {
                assert!(message.contains("loopback-only"));
            }
            other => panic!("expected transport error, got: {other:?}"),
        }
    }

    #[test]
    fn channel_connect_rejects_userinfo_bypass() {
        // Regression: "loopback" in userinfo must not fool the host check.
        // RFC 3986 §3.2: authority = [userinfo "@"] host [":" port]
        for uri in [
            "http://loopback:pw@evil.com:80",
            "http://loopback@evil.com",
            "http://user:loopback@attacker.io:443/path",
        ] {
            let error = futures_lite::future::block_on(Channel::connect(uri))
                .expect_err(&format!("userinfo bypass must fail: {uri}"));
            match error {
                GrpcError::Transport(msg) => {
                    assert!(
                        msg.contains("loopback-only"),
                        "expected loopback-only error for {uri}, got: {msg}"
                    );
                }
                other => panic!("expected transport error for {uri}, got: {other:?}"),
            }
        }
    }
}
