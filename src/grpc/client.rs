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

use crate::bytes::{Bytes, BytesMut};

#[cfg(not(target_arch = "wasm32"))]
use std::io;
#[cfg(not(target_arch = "wasm32"))]
use std::net::{IpAddr, SocketAddr};

#[cfg(not(target_arch = "wasm32"))]
use base64::Engine as _;

#[cfg(not(target_arch = "wasm32"))]
use crate::codec::Decoder as _;
#[cfg(not(target_arch = "wasm32"))]
use crate::http::h2::connection::{CLIENT_PREFACE, ReceivedFrame};
#[cfg(not(target_arch = "wasm32"))]
use crate::http::h2::{Connection, ConnectionState, ErrorCode, FrameCodec, Header, SettingsBuilder};
#[cfg(not(target_arch = "wasm32"))]
use crate::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
#[cfg(not(target_arch = "wasm32"))]
use crate::net::TcpStream;
use crate::tls::TlsConnector;
#[cfg(all(not(target_arch = "wasm32"), feature = "tls"))]
use crate::tls::TlsStream;

use super::codec::{Codec, FramedCodec, IdentityCodec};
#[cfg(not(target_arch = "wasm32"))]
use super::native_stream::{
    CallDeadline, DialedStream, KeepaliveBackoff, NativeDuplexStream, NativeServerStream,
    NativeStreamConfig, NativeStreamEndpoint, NativeStreamKeepalive, NativeStreamWindows,
};
use super::status::{Code, GrpcError, Status, TransportErrorKind};
use super::streaming::{
    MAX_STREAM_BUFFERED, Metadata, MetadataValue, Request, Response, Streaming,
};

#[cfg(not(target_arch = "wasm32"))]
mod legacy_native;
#[cfg(not(target_arch = "wasm32"))]
use legacy_native::{
    LegacyNativeCall, LegacyResponseHandle, LegacyShape, downcast_native_response,
};

/// The client's codec, shared with the native calls started by the legacy
/// `&mut self` streaming methods. Each call owns a clone for its lifetime; the
/// lock is held only while one message is encoded or decoded.
struct SharedCodec<C> {
    inner: Arc<Mutex<C>>,
}

impl<C> SharedCodec<C> {
    fn new(codec: C) -> Self {
        Self {
            inner: Arc::new(Mutex::new(codec)),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn share(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Recover the codec for a consuming native call. Fails while a legacy
    /// streaming call started by this client is still alive.
    #[cfg(not(target_arch = "wasm32"))]
    fn into_owned(self) -> Result<C, Status> {
        Arc::try_unwrap(self.inner)
            .map(|codec| codec.into_inner().unwrap_or_else(PoisonError::into_inner))
            .map_err(|_| {
                Status::failed_precondition(
                    "the client's codec is still used by a streaming call it started; drop that call first",
                )
            })
    }
}

impl<C: fmt::Debug> fmt::Debug for SharedCodec<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&*lock_unpoisoned(&self.inner), f)
    }
}

impl<C: Codec> Codec for SharedCodec<C> {
    type Encode = C::Encode;
    type Decode = C::Decode;
    type Error = C::Error;

    fn encode(&mut self, item: &Self::Encode) -> Result<Bytes, Self::Error> {
        lock_unpoisoned(&self.inner).encode(item)
    }

    fn decode(&mut self, buf: &Bytes) -> Result<Self::Decode, Self::Error> {
        lock_unpoisoned(&self.inner).decode(buf)
    }

    fn set_max_encode_message_size(&mut self, max_size: usize) {
        lock_unpoisoned(&self.inner).set_max_encode_message_size(max_size);
    }

    fn set_max_decode_message_size(&mut self, max_size: usize) {
        lock_unpoisoned(&self.inner).set_max_decode_message_size(max_size);
    }

    fn map_encode_error(error: Self::Error) -> GrpcError {
        C::map_encode_error(error)
    }

    fn map_decode_error(error: Self::Error) -> GrpcError {
        C::map_decode_error(error)
    }
}

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

    FramedCodec::with_message_size_limits(
        codec,
        channel.config().max_send_message_size,
        channel.config().max_recv_message_size,
    )
    .with_frame_hooks(compressor, decompressor)
}

/// Connection policy for native gRPC hostname destinations.
///
/// The policy controls TCP connection attempts only. It does not change DNS
/// resolution, HTTP/2 authority, TLS authentication, or RPC retry behavior.
/// A literal IP or explicit dial address still opens only one TCP connection.
/// Unix sockets and deterministic loopback channels keep their existing paths.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConnectPolicy {
    /// Try resolved addresses in order under the existing connection deadline.
    ///
    /// This is the compatibility default. An unreachable first address can
    /// consume the entire connection budget before another address is tried.
    #[default]
    Sequential,
    /// Stagger connection attempts using the shared Happy Eyeballs connector.
    ///
    /// The resolver's first address family keeps its lead, with families then
    /// interleaved and attempts normally staggered by 250 milliseconds. The
    /// first successful TCP connection wins; pending attempts are dropped.
    /// All attempts remain bounded by the original connection/setup deadline,
    /// including the time spent resolving the hostname.
    HappyEyeballs,
}

#[cfg(not(target_arch = "wasm32"))]
impl ConnectPolicy {
    pub(crate) async fn connect_host(
        self,
        host: String,
        port: u16,
        timeout: Duration,
    ) -> io::Result<TcpStream> {
        match self {
            Self::Sequential => TcpStream::connect_timeout((host, port), timeout).await,
            Self::HappyEyeballs => {
                crate::net::happy_eyeballs::connect_resolved((host, port), Some(timeout)).await
            }
        }
    }
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
    /// Keep-alive interval: HTTP/2 PINGs while the stream owner is polled.
    /// Only `GrpcClient::into_native_server_streaming` and
    /// `GrpcClient::into_native_duplex` apply it; other calls, unary
    /// included, send no PINGs.
    pub keepalive_interval: Option<Duration>,
    /// Keep-alive timeout, applied by the same two calls as
    /// `keepalive_interval`.
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

/// Builder for creating a gRPC channel.
#[derive(Debug)]
pub struct ChannelBuilder {
    /// The target URI.
    uri: String,
    /// Channel configuration.
    config: ChannelConfig,
    /// Explicit TLS authority for HTTPS channels.
    tls_connector: Option<TlsConnector>,
    /// Optional certificate identity when it differs from the logical URI host.
    tls_server_name: Option<String>,
    /// Explicit native TCP destination, separate from the logical authority.
    #[cfg(not(target_arch = "wasm32"))]
    dial_addr: Option<SocketAddr>,
    /// Policy for native hostname connection attempts.
    #[cfg(not(target_arch = "wasm32"))]
    connect_policy: ConnectPolicy,
    /// Idle unary connections to keep for reuse; 0 keeps none.
    #[cfg(not(target_arch = "wasm32"))]
    reuse_connections: usize,
    /// Whether peer keepalive rejections increase intervals for future connections.
    #[cfg(not(target_arch = "wasm32"))]
    keepalive_backoff: bool,
    /// Whether native streaming probes recover already-readable acknowledgements.
    #[cfg(not(target_arch = "wasm32"))]
    progress_aware_keepalive: bool,
}

impl ChannelBuilder {
    /// Create a new channel builder for the given URI.
    ///
    /// The client accepts deterministic in-memory `loopback` targets and
    /// native HTTP/2 DNS names, IPv4 literals and bracketed IPv6 literals.
    /// Network I/O, including hostname resolution, is lazy:
    /// [`ChannelBuilder::connect`] validates and stores the target, while an
    /// RPC method establishes its transport.
    #[must_use]
    pub fn new(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            config: ChannelConfig::default(),
            tls_connector: None,
            tls_server_name: None,
            #[cfg(not(target_arch = "wasm32"))]
            dial_addr: None,
            #[cfg(not(target_arch = "wasm32"))]
            connect_policy: ConnectPolicy::default(),
            #[cfg(not(target_arch = "wasm32"))]
            reuse_connections: 0,
            #[cfg(not(target_arch = "wasm32"))]
            keepalive_backoff: false,
            #[cfg(not(target_arch = "wasm32"))]
            progress_aware_keepalive: false,
        }
    }

    /// Set the connection timeout.
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.config.connect_timeout = timeout;
        self
    }

    /// Select how native RPCs connect to a hostname's resolved addresses.
    ///
    /// [`ConnectPolicy::Sequential`] is the default. Opting into
    /// [`ConnectPolicy::HappyEyeballs`] lets another address connect while an
    /// earlier attempt is still waiting. The policy applies to unary and all
    /// native streaming calls, including fresh connections after pool reuse.
    /// It preserves the configured timeout, HTTP authority, and TLS identity.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn connect_policy(mut self, policy: ConnectPolicy) -> Self {
        self.connect_policy = policy;
        self
    }

    /// Opt into staggered Happy Eyeballs connection attempts for hostnames.
    ///
    /// Equivalent to `connect_policy(ConnectPolicy::HappyEyeballs)`.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn happy_eyeballs(self) -> Self {
        self.connect_policy(ConnectPolicy::HappyEyeballs)
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

    /// Set the keep-alive interval (applied only to native server-streaming
    /// and duplex calls; see [`ChannelConfig::keepalive_interval`]).
    #[must_use]
    pub fn keepalive_interval(mut self, interval: Duration) -> Self {
        self.config.keepalive_interval = Some(interval);
        self
    }

    /// Set the keep-alive timeout (applied only to native server-streaming
    /// and duplex calls; see [`ChannelConfig::keepalive_timeout`]).
    #[must_use]
    pub fn keepalive_timeout(mut self, timeout: Duration) -> Self {
        self.config.keepalive_timeout = Some(timeout);
        self
    }

    /// Use progress-aware timeouts for native streaming keepalive.
    ///
    /// A buffered-message consumer may pause without timing out a PING that
    /// has not entered the outbound cursor. An expired probe gets one bounded
    /// read pass for an already-available matching ACK or terminal response.
    /// See [`NativeStreamKeepalive::with_progress_aware_timeout`] for the write
    /// stall and receive-bound limits. This does not enable keepalive without
    /// a configured interval, alter unary calls, or retry a failed call.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn progress_aware_keepalive(mut self) -> Self {
        self.progress_aware_keepalive = true;
        self
    }

    /// Back off native streaming keepalive when the peer rejects its frequency.
    ///
    /// An HTTP/2 GOAWAY with ENHANCE_YOUR_CALM and exactly `too_many_pings`
    /// doubles the interval for future connections on this channel and its
    /// clones. Each connection can increase it once, saturating at
    /// `Duration::MAX`. Active connections keep their interval and timeout.
    /// This does not enable keepalive without a configured interval or retry
    /// the rejected call.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn keepalive_backoff(mut self) -> Self {
        self.keepalive_backoff = true;
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

    /// Require a TLS-backed gRPC transport.
    ///
    /// This only marks the transport requirement. Callers must also provide
    /// an explicit [`TlsConnector`] with [`Self::tls_connector`]; channels
    /// fail closed rather than selecting ambient trust roots.
    #[must_use]
    pub fn tls(mut self) -> Self {
        self.config.use_tls = true;
        self
    }

    /// Supply the TLS connector used by HTTPS unary calls.
    ///
    /// The connector should advertise HTTP/2 (normally via
    /// [`crate::tls::TlsConnectorBuilder::alpn_grpc`]). The gRPC transport
    /// independently verifies that the peer actually negotiated `h2` before
    /// writing the connection preface.
    #[must_use]
    pub fn tls_connector(mut self, connector: TlsConnector) -> Self {
        self.config.use_tls = true;
        self.tls_connector = Some(connector);
        self
    }

    /// Override the DNS name authenticated by TLS.
    ///
    /// This changes only certificate authentication. It never changes the URI
    /// `:authority` or the native socket selected by resolving the URI host or
    /// [`Self::dial_addr`].
    #[must_use]
    pub fn tls_server_name(mut self, server_name: impl Into<String>) -> Self {
        self.config.use_tls = true;
        self.tls_server_name = Some(server_name.into());
        self
    }

    /// Dial one explicit native TCP address while retaining the URI authority.
    ///
    /// This bypasses hostname resolution. An explicit address is accepted only
    /// for an HTTPS channel with a caller-supplied [`TlsConnector`]. The URI
    /// still supplies HTTP/2 `:authority` and, unless
    /// [`Self::tls_server_name`] overrides it, the certificate identity.
    /// Deterministic `loopback` channels cannot use this native transport.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn dial_addr(mut self, address: SocketAddr) -> Self {
        self.dial_addr = Some(address);
        self
    }

    /// Keep up to `max_idle` HTTP/2 connections open after unary calls, so
    /// later unary calls on this channel, or any clone of it, reuse them
    /// instead of dialing (and TLS-handshaking) again. `0`, the default,
    /// keeps the original behavior: each unary call owns a fresh connection.
    ///
    /// A pooled connection carries one call at a time; concurrent calls use
    /// separate connections, and at most `max_idle` are kept between calls.
    /// Before reuse, whatever the server sent while the connection was idle
    /// is processed: a connection the server closed or sent GOAWAY on, or one
    /// idle for over 30 seconds, is dropped instead. If a reused connection
    /// turns out to be gone before the server could act on the call (the
    /// request could not be written, the stream was refused, or GOAWAY
    /// excludes it), the call is retried once on a fresh connection. A close
    /// after the request was sent is reported as `UNAVAILABLE`, as it is
    /// without reuse. Streaming calls are unaffected.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn reuse_connections(mut self, max_idle: usize) -> Self {
        self.reuse_connections = max_idle;
        self
    }

    /// Build the channel.
    pub async fn connect(self) -> Result<Channel, GrpcError> {
        #[cfg_attr(target_arch = "wasm32", allow(unused_mut))]
        let mut channel = Channel::connect_with_transport(
            &self.uri,
            self.config,
            self.tls_connector,
            self.tls_server_name,
            #[cfg(not(target_arch = "wasm32"))]
            self.dial_addr,
        )
        .await?;
        #[cfg(not(target_arch = "wasm32"))]
        {
            channel.connect_policy = self.connect_policy;
            channel.progress_aware_keepalive = self.progress_aware_keepalive;
            if self.keepalive_backoff {
                channel = channel.with_keepalive_backoff();
            }
            if self.reuse_connections > 0 {
                channel.unary_pool = Some(Arc::new(UnaryConnectionPool::new(self.reuse_connections)));
            }
        }
        Ok(channel)
    }
}

/// A gRPC channel representing an explicit client transport capability.
///
/// `loopback` selects deterministic in-memory behavior. DNS names, IPv4 and
/// bracketed IPv6 literals select native HTTP/2 over TCP, optionally protected
/// by a caller-supplied TLS connector. `ChannelBuilder::dial_addr` can instead
/// select one explicit native socket for an authenticated HTTPS authority.
/// The channel is intentionally lazy: constructing it performs validation but
/// does not resolve a hostname or open a socket. Each native unary call owns
/// its connection. Hostname resolution uses the runtime's offloaded system
/// resolver under the caller's I/O capability and connection deadline. Resolved
/// addresses are tried in order by default. `ChannelBuilder::happy_eyeballs`
/// opts native hostname calls into staggered connection attempts.
#[derive(Debug, Clone)]
pub struct Channel {
    /// The target URI.
    uri: String,
    /// Channel configuration.
    config: ChannelConfig,
    /// Explicit TLS authority for HTTPS unary calls.
    #[cfg(not(target_arch = "wasm32"))]
    tls_connector: Option<TlsConnector>,
    /// Optional certificate identity distinct from the logical URI host.
    #[cfg(not(target_arch = "wasm32"))]
    tls_server_name: Option<String>,
    /// Explicit native TCP destination distinct from the logical authority.
    #[cfg(not(target_arch = "wasm32"))]
    dial_addr: Option<SocketAddr>,
    /// Policy for native hostname connection attempts.
    #[cfg(not(target_arch = "wasm32"))]
    connect_policy: ConnectPolicy,
    /// Idle unary connections kept for reuse, shared by clones
    /// ([`ChannelBuilder::reuse_connections`]).
    #[cfg(not(target_arch = "wasm32"))]
    unary_pool: Option<Arc<UnaryConnectionPool>>,
    /// Future connection intervals, shared only by clones of an opted-in channel.
    #[cfg(not(target_arch = "wasm32"))]
    keepalive_backoff: Option<Arc<KeepaliveBackoff>>,
    /// Timeout policy copied into each subsequently created native stream owner.
    #[cfg(not(target_arch = "wasm32"))]
    progress_aware_keepalive: bool,
}

impl Channel {
    /// Create a channel builder for the given URI.
    #[must_use]
    pub fn builder(uri: impl Into<String>) -> ChannelBuilder {
        ChannelBuilder::new(uri)
    }

    /// Connect to a gRPC client transport at the given URI.
    ///
    /// Supports in-memory loopback transport (host: `loopback`) and native
    /// HTTP/2 connections to DNS names, IPv4 and bracketed IPv6 literals.
    /// Network-backed RPCs perform hostname resolution and TCP connection.
    /// `unix:path` and `unix:///absolute/path` targets dial a Unix-domain
    /// socket with cleartext HTTP/2 and the `localhost` authority.
    pub async fn connect(uri: impl Into<String>) -> Result<Self, GrpcError> {
        Self::connect_with_config(&uri.into(), ChannelConfig::default()).await
    }

    /// Connect with custom configuration.
    ///
    /// Supports in-memory loopback transport (host: `loopback`) and native
    /// HTTP/2 connections to DNS names, IPv4 and bracketed IPv6 literals.
    /// Network-backed RPCs perform hostname resolution and TCP connection.
    #[allow(clippy::unused_async)]
    pub async fn connect_with_config(uri: &str, config: ChannelConfig) -> Result<Self, GrpcError> {
        Self::connect_with_transport(
            uri,
            config,
            None,
            None,
            #[cfg(not(target_arch = "wasm32"))]
            None,
        )
        .await
    }

    #[allow(clippy::unused_async)]
    async fn connect_with_transport(
        uri: &str,
        config: ChannelConfig,
        tls_connector: Option<TlsConnector>,
        tls_server_name: Option<String>,
        #[cfg(not(target_arch = "wasm32"))] dial_addr: Option<SocketAddr>,
    ) -> Result<Self, GrpcError> {
        #[cfg(not(target_arch = "wasm32"))]
        let has_explicit_dial_addr = dial_addr.is_some();
        #[cfg(target_arch = "wasm32")]
        let has_explicit_dial_addr = false;
        let target = parse_channel_uri(uri)?;
        validate_channel_security(
            uri,
            &config,
            tls_connector.is_some(),
            has_explicit_dial_addr,
        )?;
        if target.use_tls || config.use_tls {
            let server_name = tls_server_name.as_deref().unwrap_or(target.host);
            TlsConnector::validate_domain(server_name).map_err(|error| {
                GrpcError::transport_kind(
                    TransportErrorKind::ProtocolViolation,
                    format!("invalid gRPC TLS server name: {error}"),
                )
            })?;
        }
        #[cfg(target_arch = "wasm32")]
        let _ = (&tls_connector, &tls_server_name);
        Ok(Self {
            uri: uri.to_string(),
            config,
            #[cfg(not(target_arch = "wasm32"))]
            tls_connector,
            #[cfg(not(target_arch = "wasm32"))]
            tls_server_name,
            #[cfg(not(target_arch = "wasm32"))]
            dial_addr,
            #[cfg(not(target_arch = "wasm32"))]
            connect_policy: ConnectPolicy::default(),
            #[cfg(not(target_arch = "wasm32"))]
            unary_pool: None,
            #[cfg(not(target_arch = "wasm32"))]
            keepalive_backoff: None,
            #[cfg(not(target_arch = "wasm32"))]
            progress_aware_keepalive: false,
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

    /// Opt into peer-directed backoff for future native streaming connections.
    ///
    /// Enable this before cloning the channel to share subsequent interval
    /// increases. Re-enabling an opted-in channel preserves its learned
    /// interval. Only GOAWAY with ENHANCE_YOUR_CALM and exactly `too_many_pings`
    /// triggers a saturating doubling, at most once per connection. Existing
    /// connections, acknowledgement timeouts and call deadlines stay fixed;
    /// the rejected call is not retried.
    ///
    /// Keepalive remains disabled without a configured interval.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn with_keepalive_backoff(mut self) -> Self {
        if self.keepalive_backoff.is_none() {
            self.keepalive_backoff = self.config.keepalive_interval
                .map(|interval| Arc::new(KeepaliveBackoff::new(interval)));
        }
        self
    }

    /// Let future native streaming owners resume with progress-aware keepalive.
    ///
    /// This selects [`NativeStreamKeepalive::with_progress_aware_timeout`] for
    /// subsequent calls on this channel and its later clones. Existing stream
    /// owners and earlier channel clones retain their own timeout policy.
    /// Keepalive remains disabled without a configured interval.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn with_progress_aware_keepalive(mut self) -> Self {
        self.progress_aware_keepalive = true;
        self
    }

    /// The keepalive interval a new native streaming call will use.
    ///
    /// This includes peer-directed backoff when enabled; `config()` retains
    /// the original interval. Active connections retain their own snapshot.
    /// Returns `None` when keepalive is disabled.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn effective_keepalive_interval(&self) -> Option<Duration> {
        self.keepalive_backoff.as_ref().map_or(self.config.keepalive_interval, |backoff| {
            Some(backoff.interval())
        })
    }

    /// Get the policy used for native hostname connection attempts.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn connect_policy(&self) -> ConnectPolicy {
        self.connect_policy
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn tls_connector(&self) -> Option<&TlsConnector> {
        self.tls_connector.as_ref()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn tls_server_name(&self) -> Option<&str> {
        self.tls_server_name.as_deref()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn dial_addr(&self) -> Option<SocketAddr> {
        self.dial_addr
    }
}

/// A gRPC client for making RPC calls.
pub struct GrpcClient<C = IdentityCodec> {
    /// The underlying channel.
    channel: Channel,
    /// The codec for message serialization, shared with streaming calls.
    codec: FramedCodec<SharedCodec<C>>,
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
        let framed_codec = client_framed_codec(&channel, SharedCodec::new(IdentityCodec));
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
        let framed_codec = client_framed_codec(&channel, SharedCodec::new(codec));
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
        let _ = metadata.insert("x-asupersync-grpc-path", path);
        let transport = if channel_target_is_loopback(self.channel.uri()) {
            "loopback"
        } else {
            "native-h2"
        };
        let _ = metadata.insert("x-asupersync-grpc-transport", transport);
        Ok(metadata)
    }

    fn apply_channel_metadata_defaults(&self, metadata: &mut Metadata) {
        /// br-asupersync-20occs: classification of an existing
        /// `grpc-timeout` entry for the scrub-vs-replace decision.
        enum ExistingTimeoutState {
            Parseable(String),
            Malformed,
            Absent,
        }

        // br-asupersync-20occs: classify the existing entry into one of three
        // states — present-and-parseable, present-but-malformed, or absent.
        // If malformed, scrub it before deciding whether to insert the
        // channel default; previously the malformed value rode through to the
        // wire when channel.config.timeout was None.
        let existing_state = match metadata.get("grpc-timeout") {
            Some(super::streaming::MetadataValue::Ascii(existing))
                if super::server::parse_grpc_timeout(existing).is_some() =>
            {
                ExistingTimeoutState::Parseable(existing.clone())
            }
            Some(_) => ExistingTimeoutState::Malformed,
            None => ExistingTimeoutState::Absent,
        };
        let (timeout_value, base_source) = match existing_state {
            ExistingTimeoutState::Parseable(v) => (Some(v), "override"),
            ExistingTimeoutState::Malformed => {
                // Scrub the malformed entry; fall back to the channel default
                // (which may also be None, in which case no grpc-timeout is
                // sent — equivalent to "no deadline").
                metadata.remove("grpc-timeout");
                (
                    self.channel.config.timeout.map(encode_grpc_timeout),
                    "channel",
                )
            }
            ExistingTimeoutState::Absent => (
                self.channel.config.timeout.map(encode_grpc_timeout),
                "channel",
            ),
        };

        // br-asupersync-server-stack-hardening-eeexl1.1.3: meet the base
        // timeout (per-request override or channel default) with the
        // remaining ambient Cx budget, so an outbound call can never
        // outlive its caller's deadline. Meet semantics: the budget can
        // only tighten the base; with no base, the remaining budget alone
        // becomes the wire deadline; with neither, no grpc-timeout is
        // sent. The original header string is preserved verbatim unless
        // the budget actually tightens it.
        let base_source = if timeout_value.is_some() {
            base_source
        } else {
            "none"
        };
        let ambient_remaining = ambient_remaining_budget();
        let timeout_value = match (timeout_value, ambient_remaining) {
            (Some(base), Some(remaining)) => {
                let base_duration = super::server::parse_grpc_timeout(&base)
                    .expect("base grpc-timeout was validated or encoded above");
                if remaining < base_duration {
                    Some(encode_grpc_timeout(remaining))
                } else {
                    Some(base)
                }
            }
            (None, Some(remaining)) => Some(encode_grpc_timeout(remaining)),
            (base, None) => base,
        };
        if let Some(timeout_value) = timeout_value {
            // Forwarded-budget trace event at the client hop: which base
            // applied (per-request override / channel default / none),
            // the remaining ambient budget, and the wire value sent.
            if let Some(cx) = crate::cx::Cx::current() {
                let remaining = ambient_remaining
                    .map_or_else(|| "none".to_string(), |r| r.as_nanos().to_string());
                cx.trace(&format!(
                    "client.budget_forwarded proto=grpc base={base_source} remaining_ns={remaining} grpc_timeout={timeout_value}",
                ));
            }
            let _ = metadata.insert_or_replace("grpc-timeout", timeout_value);
        }

        if metadata.get("grpc-encoding").is_none()
            && let Some(encoding) = effective_send_compression(self.channel.config())
        {
            let _ = metadata.insert("grpc-encoding", encoding.as_header_value());
        }

        let accept_compression = effective_accept_compressions(self.channel.config());
        if metadata.get("grpc-accept-encoding").is_none() && !accept_compression.is_empty() {
            let encodings = accept_compression
                .iter()
                .map(|encoding| encoding.as_header_value())
                .collect::<Vec<_>>()
                .join(",");
            let _ = metadata.insert("grpc-accept-encoding", encodings);
        }
    }

    fn apply_client_interceptors(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        for interceptor in &self.client_interceptors {
            interceptor.intercept(request)?;
        }
        Ok(())
    }

    /// Transfer this client and its codec into a native server-streaming call.
    ///
    /// The channel selects DNS/IP dialing, TLS identity and trust, message
    /// limits, compression, receive windows, and setup/call timeouts. Client
    /// interceptors run once under the supplied `cx` before network I/O.
    /// Initial and trailing metadata remain separate on the returned owner.
    /// Consume `message()` through `Ok(None)` to verify terminal gRPC status.
    ///
    /// Consuming the client transfers even a non-Clone codec into the stream;
    /// another call can use a new client built from a cloned [`Channel`].
    /// The stream owns one connection and has no background task. Dropping it
    /// closes that connection. Dropping a borrowing `message()` wait preserves
    /// progress. Cancellation and deadlines use the explicit context.
    ///
    /// Configured keepalive is driven by polling the returned owner, without a
    /// background task. An interval enables HTTP/2 PINGs; an omitted timeout
    /// defaults to twenty seconds. A timeout without an interval is invalid.
    /// Neither probes nor reads progress while the owner is unpolled. Setup
    /// remains covered by its existing deadline before keepalive is enabled.
    /// Metadata is bounded to 16 KiB per header block.
    /// Deterministic loopback is supported by [`Self::server_streaming`], not
    /// this native method. Missing I/O/timer authority, invalid configuration,
    /// unavailable compression and transport metadata overrides refuse before
    /// dialing. Setup, bounded by the channel's connect timeout, includes DNS,
    /// TCP, TLS, encoding, writing the request and the server's HTTP/2
    /// SETTINGS. It does not include response headers, which grpc-go and
    /// grpc-java servers send with the first message: a Watch whose first
    /// event is slow waits under the call deadline and keepalive only.
    ///
    /// ```no_run
    /// use asupersync::{Cx, bytes::Bytes};
    /// use asupersync::grpc::{Channel, GrpcClient, Request, Status};
    ///
    /// async fn watch(cx: &Cx) -> Result<(), Status> {
    ///     let channel = Channel::connect("http://localhost:50051")
    ///         .await.map_err(|error| error.into_status())?;
    ///     let mut responses = GrpcClient::new(channel)
    ///         .into_native_server_streaming(
    ///             cx, "/example.Service/Watch", Request::new(Bytes::new()),
    ///         ).await?;
    ///     while let Some(message) = responses.message().await? {
    ///         cx.trace(&format!("received {} bytes", message.len()));
    ///     }
    ///     Ok(())
    /// }
    /// ```
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn into_native_server_streaming(
        self,
        cx: &crate::cx::Cx,
        path: &str,
        request: Request<C::Encode>,
    ) -> Result<NativeServerStream<impl AsyncRead + AsyncWrite + Unpin + Send + 'static, C>, Status>
    {
        let setup = self.prepare_native_stream(cx, path, &request)?;
        let connector = self.channel.tls_connector().cloned();
        let request = Request::with_metadata(request.into_inner(), setup.metadata);
        let stream = setup.endpoint.connect_with_transport(
            cx,
            path,
            request,
            self.codec.into_inner().into_owned()?,
            setup.config,
            setup.windows,
            Some(setup.deadline),
            |dialed| native_h2_transport(dialed, &setup.target, connector),
        ).await?;
        match setup.keepalive {
            Some(keepalive) => stream.with_keepalive(keepalive),
            None => Ok(stream),
        }
    }

    /// Transfer this client into a native client-streaming or bidirectional RPC.
    ///
    /// The unit request carries metadata; messages are supplied with the
    /// returned owner's `queue_message()`. `next_event()` drives both network
    /// directions and yields either a response or `RequestFlushed`, which
    /// releases the single bounded request slot. Always consume responses
    /// while uploading: a peer may reply before granting more upload credit.
    /// After the last request is flushed, call `close_requests()` and consume
    /// events through terminal `Ok(None)` (or its exact error status).
    ///
    /// For client-streaming RPCs the peer normally sends one response after
    /// half-close; bidirectional RPCs can reply before upload finishes. The
    /// owner exposes both forms without collecting an unbounded response list.
    /// It does not infer an RPC's cardinality from its path.
    ///
    /// Channel configuration, interceptors, explicit capabilities, ownership
    /// and demand-driven keepalive match [`Self::into_native_server_streaming`].
    /// Setup flushes the initial request headers without waiting for response
    /// headers, so a server waiting for the upload cannot deadlock setup.
    /// Dropping `next_event()` preserves progress; do not requeue a message
    /// already accepted by `queue_message()`. Dropping the owner closes its
    /// connection without spawning cleanup work or cancelling the parent.
    ///
    /// ```no_run
    /// use asupersync::{Cx, bytes::Bytes};
    /// use asupersync::grpc::{Channel, GrpcClient, NativeDuplexEvent, Request, Status};
    ///
    /// async fn upload(cx: &Cx, messages: Vec<Bytes>) -> Result<(), Status> {
    ///     let channel = Channel::connect("http://localhost:50051")
    ///         .await.map_err(|error| error.into_status())?;
    ///     let mut call = GrpcClient::new(channel)
    ///         .into_native_duplex(cx, "/example.Service/Upload", Request::new(()))
    ///         .await?;
    ///     let mut messages = messages.into_iter();
    ///     let mut closed = false;
    ///     while let Some(event) = call.next_event().await? {
    ///         match event {
    ///             NativeDuplexEvent::RequestFlushed if !closed => {
    ///                 if let Some(message) = messages.next() {
    ///                     call.queue_message(&message)?;
    ///                 } else {
    ///                     call.close_requests()?;
    ///                     closed = true;
    ///                 }
    ///             }
    ///             NativeDuplexEvent::Message(response) => {
    ///                 cx.trace(&format!("received {} bytes", response.len()));
    ///             }
    ///             NativeDuplexEvent::RequestFlushed => {}
    ///         }
    ///     }
    ///     Ok(())
    /// }
    /// ```
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn into_native_duplex(
        self,
        cx: &crate::cx::Cx,
        path: &str,
        request: Request<()>,
    ) -> Result<NativeDuplexStream<impl AsyncRead + AsyncWrite + Unpin + Send + 'static, C>, Status>
    {
        let setup = self.prepare_native_stream(cx, path, &request)?;
        let connector = self.channel.tls_connector().cloned();
        let request = Request::with_metadata((), setup.metadata);
        let stream = setup.endpoint.connect_duplex_with_transport(
            cx,
            path,
            request,
            self.codec.into_inner().into_owned()?,
            setup.config,
            setup.windows,
            Some(setup.deadline),
            |dialed| native_h2_transport(dialed, &setup.target, connector),
        ).await?;
        match setup.keepalive {
            Some(keepalive) => stream.with_keepalive(keepalive),
            None => Ok(stream),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn prepare_native_stream<T>(
        &self,
        cx: &crate::cx::Cx,
        path: &str,
        request: &Request<T>,
    ) -> Result<NativeClientSetup, Status> {
        // Metadata defaults and application interceptors use the same context
        // that the native owner installs for every subsequent I/O poll.
        let _ambient = crate::cx::Cx::set_current(Some(cx.clone()));
        super::native_stream::check_cancellation(cx)?;
        validate_rpc_path(path)?;
        enforce_deadline_budget(self.channel.config.timeout)?;
        if channel_target_is_loopback(self.channel.uri()) {
            return Err(Status::failed_precondition(
                "native streaming requires a network channel, not deterministic loopback",
            ));
        }
        let config = self.channel.config();
        let deadline = CallDeadline::capture(cx, request.metadata(), config.timeout)?;
        let keepalive = match (
            self.channel.effective_keepalive_interval(),
            config.keepalive_timeout,
        ) {
            (Some(interval), timeout) => {
                let policy = NativeStreamKeepalive::new(
                    interval, timeout.unwrap_or(Duration::from_secs(20)),
                )?;
                let policy = if self.channel.progress_aware_keepalive {
                    policy.with_progress_aware_timeout()
                } else {
                    policy
                };
                if cx.timer_driver().is_none() {
                    return Err(Status::failed_precondition(
                        "native gRPC keepalive requires an explicit timer",
                    ));
                }
                Some(policy)
            }
            (None, Some(_)) => return Err(Status::invalid_argument(
                "native gRPC keepalive timeout requires an interval",
            )),
            (None, None) => None,
        };
        let target = NativeH2Target::from_channel(&self.channel)?;
        #[cfg(not(feature = "tls"))]
        if target.use_tls {
            return Err(Status::unavailable(
                "gRPC TLS support is disabled; rebuild with --features tls",
            ));
        }
        let endpoint = match &target.destination {
            NativeH2Destination::Address(address) => {
                NativeStreamEndpoint::new(*address, target.authority.clone(), config.connect_timeout)?
            }
            NativeH2Destination::Host(host, port) => NativeStreamEndpoint::from_host(
                host.clone(), *port, target.authority.clone(), config.connect_timeout,
            )?,
            #[cfg(unix)]
            NativeH2Destination::Unix(path) => NativeStreamEndpoint::unix(
                path.clone(),
                target.authority.clone(),
                config.connect_timeout,
            )?,
        }
        .with_connect_policy(target.connect_policy)
        .with_keepalive_backoff(self.channel.keepalive_backoff.clone());
        let stream_config = NativeStreamConfig {
            max_send_message_size: config.max_send_message_size,
            max_recv_message_size: config.max_recv_message_size,
            timeout: config.timeout,
            scheme: target.scheme,
            send_compression: config.send_compression.unwrap_or(CompressionEncoding::Identity),
            accept_gzip: config.accept_compression.contains(&CompressionEncoding::Gzip),
            ..NativeStreamConfig::default()
        };
        let mut metadata = self.build_outbound_metadata(request, path)?;
        // The native owner generates compression fields from its codec policy.
        // Admit the channel's exact defaults, then remove only those fields so
        // they are emitted once. A request/interceptor may not select a codec
        // policy different from the one used to encode/decode message bytes.
        let send_encoding = effective_send_compression(config)
            .map(CompressionEncoding::as_header_value);
        let accept_encoding = effective_accept_compressions(config)
            .into_iter()
            .map(CompressionEncoding::as_header_value)
            .collect::<Vec<_>>()
            .join(",");
        for (key, expected) in [
            ("grpc-encoding", send_encoding),
            ("grpc-accept-encoding", Some(accept_encoding.as_str())),
        ] {
            if metadata.iter().any(|(name, value)| {
                name == key
                    && !matches!(value, MetadataValue::Ascii(value) if Some(value.as_str()) == expected)
            }) {
                return Err(Status::invalid_argument(
                    "native streaming metadata cannot override channel compression",
                ));
            }
            metadata.remove(key);
        }
        super::native_stream::check_cancellation(cx)?;
        deadline.check()?;
        Ok(NativeClientSetup {
            target,
            endpoint,
            config: stream_config,
            windows: NativeStreamWindows {
                connection: Some(config.initial_connection_window_size),
                stream: Some(config.initial_stream_window_size),
            },
            metadata,
            deadline,
            keepalive,
        })
    }

    /// Make a unary RPC call.
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
        if channel_target_is_loopback(self.channel.uri()) {
            let payload = convert_message::<Req, Resp>(request.into_inner(), "unary call")?;
            return Ok(Response::with_metadata(payload, metadata));
        }

        #[cfg(target_arch = "wasm32")]
        {
            let _ = request;
            return Err(Status::unimplemented(
                "native HTTP/2 gRPC client transport is unavailable on wasm32",
            ));
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let typed_request = downcast_boxed_message::<C::Encode>(
                Box::new(request.into_inner()),
                "native HTTP/2 unary request encoding",
            )?;
            let mut framed_request = BytesMut::new();
            self.codec
                .encode_message(&typed_request, &mut framed_request)
                .map_err(GrpcError::into_status)?;

            let wire_response =
                native_h2_unary(&self.channel, path, metadata, framed_request.freeze()).await?;

            if let Some(encoding) = wire_response.grpc_encoding.as_deref() {
                let selected = CompressionEncoding::from_header_value(encoding)
                    .ok_or_else(|| Status::internal("unsupported gRPC response encoding"))?;
                if selected != CompressionEncoding::Identity
                    && !effective_accept_compressions(&self.channel.config).contains(&selected)
                {
                    return Err(Status::internal("gRPC response encoding was not accepted"));
                }
            }

            let mut framed_response = BytesMut::from(wire_response.body.as_ref());
            let decoded = self
                .codec
                .decode_message_with_negotiated_encoding(
                    &mut framed_response,
                    wire_response.grpc_encoding.as_deref(),
                )
                .map_err(GrpcError::into_status)?
                .ok_or_else(|| Status::internal("gRPC unary response contained no message"))?;
            if !framed_response.is_empty() {
                return Err(Status::internal(
                    "gRPC unary response contained multiple or trailing message bytes",
                ));
            }
            let payload = downcast_boxed_message::<Resp>(
                Box::new(decoded),
                "native HTTP/2 unary response decoding",
            )?;
            Ok(Response::with_metadata(payload, wire_response.metadata))
        }
    }

    /// Start a server streaming RPC call.
    ///
    /// On a network channel this dials the server over native HTTP/2, sends
    /// the request (`Req` must be the codec's `Encode` type), and waits for
    /// the response headers, which become the returned metadata. The stream
    /// yields each decoded response (`Resp` must be the codec's `Decode`
    /// type), then the terminal error if the call failed; after the end,
    /// [`ResponseStream::terminal_metadata`] holds the trailers. The call must
    /// run inside a runtime task: its `Cx`, current at this call, supplies I/O
    /// authority, cancellation and the deadline (which, with the channel's
    /// connect timeout, covers setup and every later read). The stream has no
    /// background task; polling it drives the connection, and dropping it
    /// cancels the call. Channel configuration (TLS, limits, compression,
    /// windows, keepalive) and interceptors apply as in
    /// [`Self::into_native_server_streaming`], which offers the same call as
    /// one owner without type erasure.
    ///
    /// On a channel whose host is `loopback` no server is contacted: the
    /// stream holds the request itself as the single response, which needs
    /// `Req` and `Resp` to be the same type (`FAILED_PRECONDITION` otherwise).
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

        if !channel_target_is_loopback(self.channel.uri()) {
            #[cfg(target_arch = "wasm32")]
            {
                let _ = request;
                return Err(Status::unimplemented(
                    "native HTTP/2 gRPC client transport is unavailable on wasm32",
                ));
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                let (call, metadata) = self.start_legacy_server_stream(path, request).await?;
                return Ok(Response::with_metadata(ResponseStream::native(call), metadata));
            }
        }

        let metadata = self.build_outbound_metadata(&request, path)?;
        let mut stream = ResponseStream::open();
        let payload = convert_message::<Req, Resp>(request.into_inner(), "server streaming call")?;
        stream.push(Ok(payload))?;
        stream.close();

        Ok(Response::with_metadata(stream, metadata))
    }

    /// Start a client streaming RPC call.
    ///
    /// On a network channel this dials the server over native HTTP/2 and
    /// flushes the request headers; it does not wait for response headers.
    /// Each [`RequestSink::send`] waits until the previous message has left
    /// the local write queues, then queues the next one (`Req` must be the
    /// codec's `Encode` type). [`RequestSink::close`] half-closes the request
    /// stream. The [`ResponseFuture`] resolves to the single response (`Resp`
    /// must be the codec's `Decode` type) with the response headers and
    /// trailers as metadata, or to the call's error. The handles have no
    /// background task: whichever is polled drives the connection in both
    /// directions. Dropping the sink before `close`, or the future before it
    /// resolves, cancels the call. The `Cx` current at this call supplies I/O
    /// authority, cancellation and the deadline. Channel configuration and
    /// interceptors apply as in [`Self::into_native_duplex`], which offers the
    /// same call as one owner without type erasure.
    ///
    /// On a channel whose host is `loopback` no server is contacted: the
    /// response is the one message sent through the sink, which needs `Req`
    /// and `Resp` to be the same type; more than one message is
    /// `FAILED_PRECONDITION`.
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

        if !channel_target_is_loopback(self.channel.uri()) {
            #[cfg(target_arch = "wasm32")]
            {
                return Err(Status::unimplemented(
                    "native HTTP/2 gRPC client transport is unavailable on wasm32",
                ));
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                let call = self
                    .start_legacy_duplex(path, LegacyShape::ClientStreaming)
                    .await?;
                return Ok((
                    RequestSink::native(Arc::clone(&call)),
                    ResponseFuture::native(call),
                ));
            }
        }

        let request = Request::new(Bytes::new());
        let metadata = self.build_outbound_metadata(&request, path)?;
        let state = Arc::new(Mutex::new(RequestSinkState::new()));
        let sink = RequestSink::from_state(state.clone());
        let future = ResponseFuture::with_resolver(state, move |state| {
            if state.sent_count > 1 {
                return Err(Status::failed_precondition(
                    "loopback client streaming does not support multiple request messages yet",
                ));
            }
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
    ///
    /// On a network channel this dials the server over native HTTP/2 and
    /// flushes the request headers. Messages sent through the sink (`Req`
    /// must be the codec's `Encode` type) and responses read from the stream
    /// (`Resp` must be the codec's `Decode` type) flow independently: the
    /// server may answer before the request side is closed. A sink waits for
    /// each message to leave the local write queues before queuing the next,
    /// and for the response side to drain once `MAX_STREAM_BUFFERED` unread
    /// responses are held. The stream ends with the terminal error, if any;
    /// its trailers are then in [`ResponseStream::terminal_metadata`]. The
    /// handles may live in different tasks and have no background task:
    /// whichever is polled drives the connection. Dropping the sink before
    /// `close`, or the last clone of the stream, cancels the call. The `Cx`
    /// current at this call supplies I/O authority, cancellation and the
    /// deadline. Channel configuration and interceptors apply as in
    /// [`Self::into_native_duplex`].
    ///
    /// On a channel whose host is `loopback` no server is contacted: every
    /// message sent through the sink comes back on the response stream,
    /// which needs `Req` and `Resp` to be the same type.
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

        if !channel_target_is_loopback(self.channel.uri()) {
            #[cfg(target_arch = "wasm32")]
            {
                return Err(Status::unimplemented(
                    "native HTTP/2 gRPC client transport is unavailable on wasm32",
                ));
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                let call = self.start_legacy_duplex(path, LegacyShape::Bidi).await?;
                return Ok((
                    RequestSink::native(Arc::clone(&call)),
                    ResponseStream::native(call),
                ));
            }
        }

        let request = Request::new(Bytes::new());
        let _metadata = self.build_outbound_metadata(&request, path)?;
        let request_state = Arc::new(Mutex::new(RequestSinkState::new()));
        let cancel_request_state = Arc::clone(&request_state);
        let stream = ResponseStream::open_with_cancel_hook(Box::new(move || {
            cancel_request_sink_state(
                &cancel_request_state,
                Status::cancelled("response stream cancelled by client"),
            );
            Ok(())
        }));
        let mut send_stream = stream.clone();
        let close_stream = stream.clone();
        let cancel_stream = stream.clone();
        let sink = RequestSink::with_state_and_hooks(
            request_state,
            Some(Box::new(move |message: Req| {
                let response =
                    convert_message::<Req, Resp>(message, "bidirectional streaming conversion")?;
                send_stream.push(Ok(response))
            })),
            Some(Box::new(move || {
                close_stream.close();
                Ok(())
            })),
            Some(Box::new(move || {
                cancel_stream.cancel(Status::cancelled("request stream cancelled by client"));
                Ok(())
            })),
        );
        Ok((sink, stream))
    }

    /// Dial a native server-streaming call for [`Self::server_streaming`] and
    /// wait for its response headers.
    #[cfg(not(target_arch = "wasm32"))]
    async fn start_legacy_server_stream<Req: Send + 'static>(
        &mut self,
        path: &str,
        request: Request<Req>,
    ) -> Result<(Arc<LegacyNativeCall>, Metadata), Status> {
        let cx = legacy_native_cx()?;
        let metadata = request.metadata().clone();
        let message = legacy_native::downcast_native_request::<C::Encode>(Box::new(
            request.into_inner(),
        ))?;
        let request = Request::with_metadata(message, metadata);
        let setup = self.prepare_native_stream(&cx, path, &request)?;
        let connector = self.channel.tls_connector().cloned();
        let request = Request::with_metadata(request.into_inner(), setup.metadata);
        let mut stream = setup
            .endpoint
            .connect_with_transport(
                &cx,
                path,
                request,
                self.codec.inner().share(),
                setup.config,
                setup.windows,
                Some(setup.deadline),
                |dialed| native_h2_transport(dialed, &setup.target, connector),
            )
            .await?;
        if let Some(keepalive) = setup.keepalive {
            stream = stream.with_keepalive(keepalive)?;
        }
        let initial = stream.headers().await?.clone();
        Ok((
            LegacyNativeCall::new(Box::new(stream), LegacyShape::ServerStreaming),
            initial,
        ))
    }

    /// Dial a native duplex call for [`Self::client_streaming`] or
    /// [`Self::bidi_streaming`]. Only the request headers are flushed.
    #[cfg(not(target_arch = "wasm32"))]
    async fn start_legacy_duplex(
        &mut self,
        path: &str,
        shape: LegacyShape,
    ) -> Result<Arc<LegacyNativeCall>, Status> {
        let cx = legacy_native_cx()?;
        let setup = self.prepare_native_stream(&cx, path, &Request::new(()))?;
        let connector = self.channel.tls_connector().cloned();
        let mut stream = setup
            .endpoint
            .connect_duplex_with_transport(
                &cx,
                path,
                Request::with_metadata((), setup.metadata),
                self.codec.inner().share(),
                setup.config,
                setup.windows,
                Some(setup.deadline),
                |dialed| native_h2_transport(dialed, &setup.target, connector),
            )
            .await?;
        if let Some(keepalive) = setup.keepalive {
            stream = stream.with_keepalive(keepalive)?;
        }
        Ok(LegacyNativeCall::new(Box::new(stream), shape))
    }
}

/// The `Cx` a legacy streaming call runs under: the caller's ambient one.
#[cfg(not(target_arch = "wasm32"))]
fn legacy_native_cx() -> Result<crate::cx::Cx, Status> {
    crate::cx::Cx::current().ok_or_else(|| {
        Status::failed_precondition(
            "native HTTP/2 gRPC calls require an ambient runtime Cx capability",
        )
    })
}

fn channel_target_is_loopback(uri: &str) -> bool {
    parse_channel_uri(uri).is_ok_and(|target| target.host.eq_ignore_ascii_case("loopback"))
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
struct NativeH2Target {
    authority: String,
    destination: NativeH2Destination,
    server_name: String,
    scheme: &'static str,
    use_tls: bool,
    connect_policy: ConnectPolicy,
}

#[cfg(not(target_arch = "wasm32"))]
struct NativeClientSetup {
    target: NativeH2Target,
    endpoint: NativeStreamEndpoint,
    config: NativeStreamConfig,
    windows: NativeStreamWindows,
    metadata: Metadata,
    deadline: CallDeadline,
    keepalive: Option<NativeStreamKeepalive>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, PartialEq, Eq)]
enum NativeH2Destination {
    Address(SocketAddr),
    Host(String, u16),
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

#[cfg(not(target_arch = "wasm32"))]
impl NativeH2Target {
    fn from_channel(channel: &Channel) -> Result<Self, Status> {
        let mut target = Self::parse(
            channel.uri(),
            channel.config().use_tls,
            channel.tls_server_name(),
            channel.dial_addr(),
        )?;
        target.connect_policy = channel.connect_policy();
        Ok(target)
    }

    fn parse(
        uri: &str,
        use_tls: bool,
        tls_server_name: Option<&str>,
        dial_addr: Option<SocketAddr>,
    ) -> Result<Self, Status> {
        let target = parse_channel_uri(uri)
            .map_err(|error| Status::unavailable(format!("invalid gRPC channel target: {error}")))?;
        if let Some(path) = target.unix_path {
            return Self::unix(&path, use_tls, dial_addr);
        }
        let use_tls = use_tls || target.use_tls;
        let host = target.host;
        let port = target.port.unwrap_or(if use_tls { 443 } else { 80 });
        let destination = if let Some(address) = dial_addr {
            if host.eq_ignore_ascii_case("loopback") {
                return Err(Status::failed_precondition(
                    "deterministic loopback channels cannot use an explicit native dial address",
                ));
            }
            if !use_tls {
                return Err(Status::failed_precondition(
                    "an explicit gRPC dial address requires authenticated HTTPS",
                ));
            }
            NativeH2Destination::Address(address)
        } else if let Ok(address) = host.parse::<IpAddr>() {
            NativeH2Destination::Address(SocketAddr::new(address, port))
        } else {
            NativeH2Destination::Host(host.to_ascii_lowercase(), port)
        };
        Ok(Self {
            authority: target.authority.to_ascii_lowercase(),
            destination,
            server_name: tls_server_name.map_or_else(
                || host.to_ascii_lowercase(),
                |name| name.to_ascii_lowercase(),
            ),
            scheme: if use_tls { "https" } else { "http" },
            use_tls,
            connect_policy: ConnectPolicy::default(),
        })
    }

    /// A `unix:` target: cleartext HTTP/2 with the `localhost` authority.
    fn unix(path: &str, use_tls: bool, dial_addr: Option<SocketAddr>) -> Result<Self, Status> {
        if use_tls || dial_addr.is_some() {
            return Err(Status::failed_precondition(
                "unix: gRPC channel targets support neither TLS nor an explicit dial address",
            ));
        }
        #[cfg(unix)]
        {
            Ok(Self {
                authority: "localhost".to_owned(),
                destination: NativeH2Destination::Unix(std::path::PathBuf::from(path)),
                server_name: "localhost".to_owned(),
                scheme: "http",
                use_tls: false,
                connect_policy: ConnectPolicy::default(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(Status::unavailable(
                "unix: gRPC channel targets need a Unix platform",
            ))
        }
    }

    async fn connect(&self, timeout: Duration) -> Result<DialedStream, Status> {
        // Share the same offloaded, cancellation-aware system resolver used by
        // NativeStreamEndpoint. The caller's outer setup timeout also covers
        // resolution and TLS, so neither can restart the connection budget.
        match &self.destination {
            NativeH2Destination::Address(address) => TcpStream::connect_timeout(*address, timeout)
                .await
                .map(DialedStream::Tcp),
            NativeH2Destination::Host(host, port) => {
                self.connect_policy
                    .connect_host(host.clone(), *port, timeout)
                    .await
                    .map(DialedStream::Tcp)
            }
            #[cfg(unix)]
            NativeH2Destination::Unix(path) => crate::net::unix::UnixStream::connect(path)
                .await
                .map(DialedStream::Unix),
        }
        .map_err(|error| transport_status("connect", error))
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
enum NativeH2Io {
    Plain(TcpStream),
    #[cfg(unix)]
    Unix(crate::net::unix::UnixStream),
    #[cfg(feature = "tls")]
    Tls(TlsStream<TcpStream>),
}

#[cfg(not(target_arch = "wasm32"))]
impl AsyncRead for NativeH2Io {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl AsyncWrite for NativeH2Io {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, data),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_write(cx, data),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, data),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
struct NativeUnaryWireResponse {
    body: Bytes,
    metadata: Metadata,
    grpc_encoding: Option<String>,
}

#[cfg(not(target_arch = "wasm32"))]
async fn native_h2_unary(
    channel: &Channel,
    path: &str,
    metadata: Metadata,
    body: Bytes,
) -> Result<NativeUnaryWireResponse, Status> {
    let cx = crate::cx::Cx::current().ok_or_else(|| {
        Status::failed_precondition(
            "native HTTP/2 gRPC calls require an ambient runtime Cx capability",
        )
    })?;
    // A native driver is not the optional virtual IoCap, and its raw accessor
    // does not enforce capability attenuation. Refuse before hostname lookup
    // or socket creation when the current task has no native I/O authority.
    if !cx.runtime_mask.has(crate::cx::cap::CapMask::IO) || cx.io_driver_handle().is_none() {
        return Err(Status::failed_precondition(
            "native HTTP/2 gRPC calls require runtime I/O authority",
        ));
    }
    // A cancelled caller fails before it dials or takes a pooled connection:
    // its reads are interrupted, so each connection it took would be dropped
    // as broken, until the pool was empty.
    super::native_stream::check_cancellation(&cx)?;
    let target = NativeH2Target::from_channel(channel)?;
    let config = channel.config().clone();
    let tls_connector = channel.tls_connector().cloned();
    let pool = channel.unary_pool.clone();
    let io = native_h2_unary_io(target, config, tls_connector, pool, path, &metadata, body);
    let Some(timeout) = effective_native_call_timeout(&metadata) else {
        return io.await;
    };
    let now = cx
        .timer_driver()
        .map_or_else(crate::time::wall_now, |timer| timer.now());
    match crate::time::timeout(now, timeout, io).await {
        Ok(result) => result,
        Err(_) => Err(Status::deadline_exceeded(format!(
            "native HTTP/2 gRPC call exceeded its {timeout:?} deadline"
        ))),
    }
}

/// The call's local deadline is the one sent on the wire: the final
/// `grpc-timeout` (the per-request override or the channel default, already
/// met with the caller's budget), or the budget alone. Without either the
/// call has no deadline. `connect_timeout` bounds only connecting and the TLS
/// handshake; it used to cut off every unary call that had no timeout of its
/// own at 5 s, and a longer per-request `grpc-timeout` at the channel's.
#[cfg(not(target_arch = "wasm32"))]
fn effective_native_call_timeout(metadata: &Metadata) -> Option<Duration> {
    let wire = match metadata.get("grpc-timeout") {
        Some(super::streaming::MetadataValue::Ascii(value)) => {
            super::server::parse_grpc_timeout(value)
        }
        _ => None,
    };
    match (wire, ambient_remaining_budget()) {
        (Some(wire), Some(remaining)) => Some(wire.min(remaining)),
        (wire, remaining) => wire.or(remaining),
    }
}

/// How long a pooled unary connection may sit idle before it is dropped
/// instead of reused. Shorter than common proxy and load-balancer idle
/// timeouts (60 s and up), so a reused connection is rarely one a middlebox
/// has silently forgotten.
#[cfg(not(target_arch = "wasm32"))]
const UNARY_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Idle HTTP/2 connections a channel keeps for later unary calls
/// ([`ChannelBuilder::reuse_connections`]). Shared by the channel's clones.
#[cfg(not(target_arch = "wasm32"))]
struct UnaryConnectionPool {
    max_idle: usize,
    idle: Mutex<Vec<NativeH2Conn>>,
}

#[cfg(not(target_arch = "wasm32"))]
impl fmt::Debug for UnaryConnectionPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnaryConnectionPool")
            .field("max_idle", &self.max_idle)
            .field("idle", &lock_unpoisoned(&self.idle).len())
            .finish()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl UnaryConnectionPool {
    fn new(max_idle: usize) -> Self {
        Self {
            max_idle,
            idle: Mutex::new(Vec::new()),
        }
    }

    /// The most recently used connection that has not idled too long.
    fn take(&self, now: crate::types::Time) -> Option<NativeH2Conn> {
        let mut expired = Vec::new();
        let taken = {
            let mut idle = lock_unpoisoned(&self.idle);
            loop {
                let Some(conn) = idle.pop() else { break None };
                let idle_nanos = now.as_nanos().saturating_sub(conn.idle_since.as_nanos());
                if u128::from(idle_nanos) <= UNARY_POOL_IDLE_TIMEOUT.as_nanos() {
                    break Some(conn);
                }
                expired.push(conn);
            }
        };
        // Close expired transports outside the lock.
        drop(expired);
        taken
    }

    fn put(&self, mut conn: NativeH2Conn, now: crate::types::Time) {
        conn.idle_since = now;
        let mut idle = lock_unpoisoned(&self.idle);
        if idle.len() < self.max_idle {
            idle.push(conn);
        }
    }
}

/// A unary attempt that failed. `unprocessed` means the server provably did
/// not act on the request (it refused the stream, sent GOAWAY below it, or
/// never received it), so the call may be retried on another connection.
#[cfg(not(target_arch = "wasm32"))]
struct UnaryFailure {
    status: Status,
    unprocessed: bool,
}

#[cfg(not(target_arch = "wasm32"))]
impl UnaryFailure {
    fn processed(status: Status) -> Self {
        Self {
            status,
            unprocessed: false,
        }
    }

    fn unprocessed(status: Status) -> Self {
        Self {
            status,
            unprocessed: true,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn native_now() -> crate::types::Time {
    crate::cx::Cx::with_current(|cx| {
        cx.timer_driver()
            .map_or_else(crate::time::wall_now, |timer| timer.now())
    })
    .unwrap_or_else(crate::time::wall_now)
}

/// One client HTTP/2 connection used for unary calls, one call at a time.
#[cfg(not(target_arch = "wasm32"))]
struct NativeH2Conn {
    io: NativeH2Io,
    connection: Connection,
    codec: FrameCodec,
    inbound: BytesMut,
    idle_since: crate::types::Time,
}

#[cfg(not(target_arch = "wasm32"))]
impl NativeH2Conn {
    /// Connect (and TLS-handshake) within the channel's connect timeout, then
    /// write the client preface. SETTINGS go out with the first request.
    async fn dial(
        target: &NativeH2Target,
        config: &ChannelConfig,
        tls_connector: Option<TlsConnector>,
    ) -> Result<Self, Status> {
        let connect_timeout = config.connect_timeout;
        let mut io = match crate::time::timeout(native_now(), connect_timeout, async {
            let stream = target.connect(connect_timeout).await?;
            native_h2_transport(stream, target, tls_connector).await
        })
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                return Err(Status::unavailable(format!(
                    "native gRPC connection establishment exceeded its {connect_timeout:?} timeout"
                )));
            }
        };

        let settings = SettingsBuilder::client()
            .initial_window_size(config.initial_stream_window_size)
            .build();
        let mut connection = Connection::client(settings);
        // RFC 9113 requires the connection preface's first frame to be SETTINGS.
        // Queue it before expanding the connection receive window, because the
        // latter emits WINDOW_UPDATE when the configured window exceeds 65,535.
        connection.queue_initial_settings();
        connection
            .set_initial_connection_recv_window(config.initial_connection_window_size)
            .map_err(|error| Status::internal(format!("invalid HTTP/2 receive window: {error}")))?;
        io.write_all(CLIENT_PREFACE)
            .await
            .map_err(|error| transport_status("write HTTP/2 client preface", error))?;
        Ok(Self {
            io,
            connection,
            codec: FrameCodec::new(),
            inbound: BytesMut::new(),
            idle_since: native_now(),
        })
    }

    /// Before reuse: take in whatever the server sent while the connection
    /// sat idle, without waiting, and answer it (PING, SETTINGS). Fails when
    /// the server closed the connection or announced GOAWAY.
    async fn refresh(&mut self) -> Result<(), Status> {
        let mut chunk = [0_u8; 4 * 1024];
        loop {
            while let Some(frame) = self
                .codec
                .decode(&mut self.inbound)
                .map_err(|error| Status::internal(format!("decode HTTP/2 frame: {error}")))?
            {
                self.connection
                    .process_frame(frame)
                    .map_err(|error| Status::internal(format!("process HTTP/2 frame: {error}")))?;
            }
            if !self.reusable() {
                return Err(Status::unavailable("pooled HTTP/2 connection is draining"));
            }
            let io = &mut self.io;
            let read = std::future::poll_fn(|task| {
                let mut buf = ReadBuf::new(&mut chunk);
                match Pin::new(&mut *io).poll_read(task, &mut buf) {
                    Poll::Ready(Ok(())) => Poll::Ready(Some(Ok(buf.filled().len()))),
                    Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
                    Poll::Pending => Poll::Ready(None),
                }
            })
            .await;
            match read {
                None => break,
                Some(Ok(0)) => return Err(Status::unavailable("pooled HTTP/2 connection closed")),
                Some(Ok(read)) => self.inbound.extend_from_slice(&chunk[..read]),
                Some(Err(error)) => return Err(transport_status("read pooled HTTP/2", error)),
            }
        }
        flush_native_h2_frames(&mut self.connection, &mut self.io).await
    }

    /// Whether another call may open a stream here.
    fn reusable(&self) -> bool {
        self.connection.state() == ConnectionState::Open
            && !self.connection.goaway_received()
            && !self.connection.goaway_sent()
    }

    /// Run one unary call on a new stream of this connection. `Ok` carries a
    /// call whose stream completed, with its outcome: the response, or the
    /// status a completed call ended with (a non-OK grpc-status, a non-gRPC
    /// HTTP answer). The connection is intact either way and may be reused.
    async fn exchange(
        &mut self,
        headers: Vec<Header>,
        request_body: Bytes,
        max_recv_message_size: usize,
    ) -> Result<(Result<NativeUnaryWireResponse, Status>, u32), UnaryFailure> {
        // A stream refused locally (GOAWAY seen, identifiers exhausted) never
        // reached the server.
        let stream_id = self.connection.open_stream(headers, false).map_err(|error| {
            UnaryFailure::unprocessed(Status::unavailable(format!(
                "open HTTP/2 request stream: {error}"
            )))
        })?;
        self.connection
            .send_data(stream_id, request_body, true)
            .map_err(|error| {
                UnaryFailure::processed(Status::internal(format!(
                    "queue HTTP/2 request body: {error}"
                )))
            })?;
        // A unary handler runs only on the complete request, so a write that
        // fails cannot have reached one.
        flush_native_h2_frames(&mut self.connection, &mut self.io)
            .await
            .map_err(UnaryFailure::unprocessed)?;

        let mut accumulator = NativeUnaryAccumulator::new(max_recv_message_size);
        let mut chunk = [0_u8; 16 * 1024];
        loop {
            while let Some(frame) = self
                .codec
                .decode(&mut self.inbound)
                .map_err(|error| {
                    UnaryFailure::processed(Status::internal(format!(
                        "decode HTTP/2 frame: {error}"
                    )))
                })?
            {
                let received = self.connection.process_frame(frame).map_err(|error| {
                    UnaryFailure::processed(Status::internal(format!(
                        "process HTTP/2 frame: {error}"
                    )))
                })?;
                if let Some(received) = received {
                    let refused = match &received {
                        ReceivedFrame::Reset {
                            stream_id: reset,
                            error_code,
                        } => *reset == stream_id && *error_code == ErrorCode::RefusedStream,
                        ReceivedFrame::GoAway { last_stream_id, .. } => {
                            *last_stream_id < stream_id
                        }
                        _ => false,
                    };
                    accumulator.observe(stream_id, received).map_err(|status| {
                        if refused {
                            UnaryFailure::unprocessed(status)
                        } else {
                            UnaryFailure::processed(status)
                        }
                    })?;
                }
                flush_native_h2_frames(&mut self.connection, &mut self.io)
                    .await
                    .map_err(UnaryFailure::processed)?;
                if accumulator.is_complete() {
                    return Ok((accumulator.finish(), stream_id));
                }
            }

            let read = self.io.read(&mut chunk).await.map_err(|error| {
                UnaryFailure::processed(transport_status("read HTTP/2 response", error))
            })?;
            if read == 0 {
                return Err(UnaryFailure::processed(Status::unavailable(
                    "HTTP/2 peer closed before the unary gRPC response completed",
                )));
            }
            self.inbound.extend_from_slice(&chunk[..read]);
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn native_h2_unary_io(
    target: NativeH2Target,
    config: ChannelConfig,
    tls_connector: Option<TlsConnector>,
    pool: Option<Arc<UnaryConnectionPool>>,
    path: &str,
    metadata: &Metadata,
    request_body: Bytes,
) -> Result<NativeUnaryWireResponse, Status> {
    let headers = native_h2_request_headers(&target.authority, target.scheme, path, metadata)?;
    let max_recv = config.max_recv_message_size;
    if let Some(pool) = &pool {
        // Stale idle connections are dropped; a call the server provably did
        // not process on a reused connection is retried once, on a fresh one.
        // A caller cancelled meanwhile stops: it neither drops the other
        // pooled connections nor dials.
        let cancelled = || ambient_cancellation_status("native gRPC unary call");
        while let Some(mut conn) = pool.take(native_now()) {
            if conn.refresh().await.is_err() {
                if let Some(status) = cancelled() {
                    return Err(status);
                }
                continue;
            }
            match conn
                .exchange(headers.clone(), request_body.clone(), max_recv)
                .await
            {
                Ok((outcome, stream_id)) => {
                    pool_after_success(pool, conn, stream_id);
                    return outcome;
                }
                Err(failure) if failure.unprocessed && cancelled().is_none() => break,
                Err(failure) => return Err(failure.status),
            }
        }
    }
    let mut conn = NativeH2Conn::dial(&target, &config, tls_connector).await?;
    let (outcome, stream_id) = conn
        .exchange(headers, request_body, max_recv)
        .await
        .map_err(|failure| failure.status)?;
    if let Some(pool) = &pool {
        pool_after_success(pool, conn, stream_id);
    }
    outcome
}

/// Keep a connection whose call completed cleanly, with any grpc-status, for
/// the next unary call.
#[cfg(not(target_arch = "wasm32"))]
fn pool_after_success(pool: &UnaryConnectionPool, conn: NativeH2Conn, stream_id: u32) {
    if conn.reusable() && !conn.connection.has_pending_frames_for_stream(stream_id) {
        pool.put(conn, native_now());
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn native_h2_transport(
    stream: DialedStream,
    target: &NativeH2Target,
    tls_connector: Option<TlsConnector>,
) -> Result<NativeH2Io, Status> {
    let stream = match stream {
        DialedStream::Tcp(stream) => stream,
        // `unix:` targets never use TLS (NativeH2Target::unix).
        #[cfg(unix)]
        DialedStream::Unix(stream) => return Ok(NativeH2Io::Unix(stream)),
    };
    if !target.use_tls {
        return Ok(NativeH2Io::Plain(stream));
    }
    let connector = tls_connector.ok_or_else(|| {
        Status::failed_precondition(
            "HTTPS gRPC transport requires an explicit caller-supplied TLS connector",
        )
    })?;

    #[cfg(feature = "tls")]
    {
        let tls = connector
            .connect(&target.server_name, stream)
            .await
            .map_err(|error| {
                ambient_cancellation_status("gRPC TLS handshake").unwrap_or_else(|| {
                    Status::unavailable(format!("gRPC TLS handshake failed: {error}"))
                })
            })?;
        if tls.alpn_protocol() != Some(b"h2".as_slice()) {
            return Err(Status::unavailable(
                "gRPC TLS peer did not negotiate the required h2 ALPN protocol",
            ));
        }
        Ok(NativeH2Io::Tls(tls))
    }

    #[cfg(not(feature = "tls"))]
    {
        let _ = (stream, connector, target.server_name.as_str());
        Err(Status::unavailable(
            "gRPC TLS support is disabled; rebuild with --features tls",
        ))
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn native_h2_request_headers(
    authority: &str,
    scheme: &str,
    path: &str,
    metadata: &Metadata,
) -> Result<Vec<Header>, Status> {
    let mut headers = vec![
        Header::new(":method", "POST"),
        Header::new(":scheme", scheme),
        Header::new(":path", path),
        Header::new(":authority", authority),
        Header::new("content-type", "application/grpc"),
        Header::new("te", "trailers"),
    ];
    for (name, value) in metadata.iter() {
        if name.starts_with(':')
            || [
                "content-type",
                "te",
                "host",
                "grpc-status",
                "grpc-message",
                "grpc-status-details-bin",
            ]
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
        {
            return Err(Status::invalid_argument(format!(
                "outbound metadata uses transport-reserved key '{name}'"
            )));
        }
        let value = match value {
            MetadataValue::Ascii(value) => value.clone(),
            MetadataValue::Binary(value) => {
                base64::engine::general_purpose::STANDARD_NO_PAD.encode(value)
            }
        };
        headers.push(Header::new(name, value));
    }
    Ok(headers)
}

#[cfg(not(target_arch = "wasm32"))]
async fn flush_native_h2_frames<IO>(
    connection: &mut Connection,
    stream: &mut IO,
) -> Result<(), Status>
where
    IO: AsyncWrite + Unpin,
{
    let mut outbound = BytesMut::new();
    while let Some(frame) = connection.next_frame() {
        frame
            .encode(&mut outbound)
            .map_err(|error| Status::internal(format!("encode HTTP/2 frame: {error}")))?;
    }
    if !outbound.is_empty() {
        stream
            .write_all(&outbound)
            .await
            .map_err(|error| transport_status("write HTTP/2 frames", error))?;
        stream
            .flush()
            .await
            .map_err(|error| transport_status("flush HTTP/2 frames", error))?;
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn transport_status(context: &str, error: std::io::Error) -> Status {
    if error.kind() == std::io::ErrorKind::Interrupted
        && let Some(status) = ambient_cancellation_status(context)
    {
        return status;
    }
    let kind = TransportErrorKind::from_io_error_kind(error.kind());
    GrpcError::transport_kind(kind, format!("{context}: {error}")).into_status()
}

#[cfg(not(target_arch = "wasm32"))]
fn ambient_cancellation_status(context: &str) -> Option<Status> {
    crate::cx::Cx::with_current(|cx| cx.checkpoint().is_err())
        .unwrap_or(false)
        .then(|| Status::cancelled(format!("{context} cancelled by the caller")))
}

#[cfg(not(target_arch = "wasm32"))]
struct NativeUnaryAccumulator {
    max_body_bytes: usize,
    body: BytesMut,
    metadata: Metadata,
    http_status: Option<u16>,
    content_type_valid: bool,
    grpc_encoding: Option<String>,
    grpc_status: Option<Code>,
    grpc_message: Option<String>,
    grpc_details: Option<Bytes>,
    stream_ended: bool,
}

#[cfg(not(target_arch = "wasm32"))]
impl NativeUnaryAccumulator {
    fn new(max_message_size: usize) -> Self {
        Self {
            max_body_bytes: max_message_size.saturating_add(5),
            body: BytesMut::new(),
            metadata: Metadata::new(),
            http_status: None,
            content_type_valid: false,
            grpc_encoding: None,
            grpc_status: None,
            grpc_message: None,
            grpc_details: None,
            stream_ended: false,
        }
    }

    fn observe(&mut self, stream_id: u32, frame: ReceivedFrame) -> Result<(), Status> {
        match frame {
            ReceivedFrame::Headers {
                stream_id: received_stream,
                headers,
                end_stream,
            } if received_stream == stream_id => {
                self.observe_headers(headers)?;
                self.stream_ended |= end_stream;
            }
            ReceivedFrame::Data {
                stream_id: received_stream,
                data,
                end_stream,
            } if received_stream == stream_id => {
                if self.body.len().saturating_add(data.len()) > self.max_body_bytes {
                    return Err(Status::resource_exhausted(
                        "gRPC unary response exceeds configured receive-message limit",
                    ));
                }
                self.body.extend_from_slice(&data);
                self.stream_ended |= end_stream;
            }
            ReceivedFrame::Reset {
                stream_id: received_stream,
                error_code,
            } if received_stream == stream_id => {
                return Err(Status::from_h2_rst_stream_code(error_code));
            }
            ReceivedFrame::GoAway {
                last_stream_id,
                error_code,
                ..
            } if error_code != crate::http::h2::ErrorCode::NoError
                || last_stream_id < stream_id =>
            {
                return Err(Status::unavailable(format!(
                    "HTTP/2 peer sent GOAWAY before unary response completion: {error_code}"
                )));
            }
            _ => {}
        }
        Ok(())
    }

    fn observe_headers(&mut self, headers: Vec<Header>) -> Result<(), Status> {
        for Header { name, value } in headers {
            if name == ":status" {
                let status = value
                    .parse::<u16>()
                    .map_err(|_| Status::internal("HTTP/2 response has malformed :status"))?;
                if status >= 200 {
                    if self.http_status.replace(status).is_some() {
                        return Err(Status::internal(
                            "HTTP/2 response contains duplicate final :status",
                        ));
                    }
                }
                continue;
            }
            if name.eq_ignore_ascii_case("content-type") {
                self.content_type_valid =
                    value.to_ascii_lowercase().starts_with("application/grpc");
                continue;
            }
            if name.eq_ignore_ascii_case("grpc-encoding") {
                self.grpc_encoding = Some(value);
                continue;
            }
            if name.eq_ignore_ascii_case("grpc-status") {
                if self.grpc_status.is_some() {
                    return Err(Status::internal(
                        "gRPC response contains duplicate grpc-status",
                    ));
                }
                let raw = value
                    .parse::<i32>()
                    .map_err(|_| Status::internal("gRPC response has malformed grpc-status"))?;
                if !(0..=16).contains(&raw) {
                    return Err(Status::internal("gRPC response has unknown grpc-status"));
                }
                self.grpc_status = Some(Code::from_i32(raw));
                continue;
            }
            if name.eq_ignore_ascii_case("grpc-message") {
                if self.grpc_message.is_some() {
                    return Err(Status::internal(
                        "gRPC response contains duplicate grpc-message",
                    ));
                }
                self.grpc_message = Some(
                    super::status::percent_decode_grpc_message(&value)
                        .map_err(GrpcError::into_status)?,
                );
                continue;
            }
            if name.eq_ignore_ascii_case("grpc-status-details-bin") {
                if self.grpc_details.is_some() {
                    return Err(Status::internal(
                        "gRPC response contains duplicate grpc-status-details-bin",
                    ));
                }
                let details = base64::engine::general_purpose::STANDARD
                    .decode(&value)
                    .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&value))
                    .map_err(|_| Status::internal("gRPC response details are not valid base64"))?;
                self.grpc_details = Some(Bytes::from(details));
                continue;
            }
            if name.starts_with(':') || name.eq_ignore_ascii_case("te") {
                continue;
            }
            let inserted = if name.ends_with("-bin") {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(&value)
                    .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&value))
                    .map_err(|_| {
                        Status::internal(format!(
                            "binary response metadata '{name}' is not valid base64"
                        ))
                    })?;
                self.metadata.insert_bin(name, Bytes::from(decoded))
            } else {
                self.metadata.insert(name, value)
            };
            if !inserted {
                return Err(Status::internal("gRPC response contains invalid metadata"));
            }
        }
        Ok(())
    }

    /// END_STREAM ends the call whether or not it carried grpc-status. A
    /// proxy's 404 or 503 has none, and waiting for one hung the call until
    /// its deadline.
    fn is_complete(&self) -> bool {
        self.stream_ended
    }

    fn finish(self) -> Result<NativeUnaryWireResponse, Status> {
        match (self.http_status, self.grpc_status) {
            // A trailers-only grpc-status takes precedence over the HTTP
            // status, as on the streaming lanes.
            (Some(200), _) | (Some(_), Some(_)) => {}
            (Some(status), None) => return Err(super::native_stream::http_fallback(status)),
            (None, _) => return Err(Status::internal("gRPC response is missing HTTP status")),
        }
        if !self.content_type_valid {
            return Err(Status::internal(
                "gRPC response is missing a valid application/grpc content-type",
            ));
        }
        let status = self
            .grpc_status
            .ok_or_else(|| Status::internal("gRPC response is missing grpc-status"))?;
        if status != Code::Ok {
            let message = self.grpc_message.unwrap_or_default();
            return Err(match self.grpc_details {
                Some(details) => Status::with_details(status, message, details),
                None => Status::new(status, message),
            });
        }
        Ok(NativeUnaryWireResponse {
            body: self.body.freeze(),
            metadata: self.metadata,
            grpc_encoding: self.grpc_encoding,
        })
    }
}

#[derive(Debug)]
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
struct ChannelUri<'a> {
    authority: &'a str,
    host: &'a str,
    port: Option<u16>,
    use_tls: bool,
    /// The socket path of a `unix:` target.
    unix_path: Option<std::borrow::Cow<'a, str>>,
}

fn parse_channel_uri(uri: &str) -> Result<ChannelUri<'_>, GrpcError> {
    if uri.is_empty() {
        return Err(GrpcError::transport("channel URI cannot be empty"));
    }
    // A Unix-domain socket carries HTTP/2 with the `localhost` authority, as
    // grpc-go and grpc-java send for these targets.
    if let Some(path) = unix_target_path(uri) {
        return Ok(ChannelUri {
            authority: "localhost",
            host: "localhost",
            port: None,
            use_tls: false,
            unix_path: Some(path?),
        });
    }
    let (scheme, remainder) = uri
        .split_once("://")
        .ok_or_else(|| GrpcError::transport("channel URI is missing a scheme separator"))?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(GrpcError::transport(
            "channel URI must start with http:// or https://",
        ));
    }
    let authority = remainder
        .split(['/', '?', '#'])
        .next()
        .ok_or_else(|| GrpcError::transport("channel URI is missing an authority"))?;
    if authority
        .chars()
        .any(|ch| ch.is_ascii_whitespace() || ch.is_control())
    {
        return Err(GrpcError::transport(
            "channel URI authority cannot contain whitespace or control characters",
        ));
    }
    // Legacy deterministic loopback URIs accept userinfo. Parse the actual
    // host first so credentials cannot disguise a native network destination.
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host_port)| host_port);
    let (host, port) = if let Some(bracketed) = host_port.strip_prefix('[') {
        let (host, suffix) = bracketed.split_once(']').ok_or_else(|| {
            GrpcError::transport_kind(
                TransportErrorKind::ProtocolViolation,
                "channel URI IPv6 host must have matching brackets",
            )
        })?;
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(GrpcError::transport_kind(
                TransportErrorKind::ProtocolViolation,
                "channel URI brackets must contain an IPv6 address",
            ));
        }
        let port = if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':').ok_or_else(|| {
                GrpcError::transport_kind(
                    TransportErrorKind::ProtocolViolation,
                    "channel URI IPv6 brackets may only be followed by a port",
                )
            })?)
        };
        (host, port)
    } else {
        let (host, port) = host_port
            .rsplit_once(':')
            .map_or((host_port, None), |(host, port)| (host, Some(port)));
        if host.contains([':', '[', ']']) {
            return Err(GrpcError::transport_kind(
                TransportErrorKind::ProtocolViolation,
                "channel URI must contain one host and at most one port; bracket IPv6 addresses",
            ));
        }
        (host, port)
    };
    if host.is_empty() {
        return Err(GrpcError::transport("channel URI is missing a host"));
    }
    let is_loopback = host.eq_ignore_ascii_case("loopback");
    if authority.contains('@') && !is_loopback {
        return Err(GrpcError::transport_kind(
            TransportErrorKind::ProtocolViolation,
            "userinfo is not supported by native gRPC channel URIs",
        ));
    }
    // Match NativeStreamEndpoint's DNS contract. ASCII/IDNA names preserve
    // system resolver hosts-file and search-domain behavior; URI delimiters,
    // percent escapes and empty labels must never become resolver input.
    let dns = host.strip_suffix('.').unwrap_or(host);
    if host.parse::<std::net::IpAddr>().is_err()
        && (dns.is_empty()
            || dns.len() > 253
            || !dns.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            }))
    {
        return Err(GrpcError::transport_kind(
            TransportErrorKind::ProtocolViolation,
            "channel URI host must be an ASCII DNS name or IP address",
        ));
    }
    let port = port
        .map(|port| {
            // Retain the legacy integer syntax for deterministic loopback;
            // native authorities must use the HTTP port grammar on the wire.
            if !is_loopback
                && (port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()))
            {
                return Err(GrpcError::transport_kind(
                    TransportErrorKind::ConnectFailed,
                    "channel URI port must be an unsigned 16-bit integer written in ASCII digits",
                ));
            }
            port.parse::<u16>().map_err(|_| {
                GrpcError::transport_kind(
                    TransportErrorKind::ConnectFailed,
                    "channel URI port must be an unsigned 16-bit integer",
                )
            })
        })
        .transpose()?;
    Ok(ChannelUri {
        authority,
        host,
        port,
        use_tls: scheme.eq_ignore_ascii_case("https"),
        unix_path: None,
    })
}

/// The socket path of a gRPC `unix:` target: `unix:path` (relative or
/// absolute) or `unix:///absolute/path`, as gRPC's naming documentation
/// spells them. `None` for any other URI.
///
/// As in grpc-go, whose resolver reads the parsed URL: a query or fragment is
/// not part of the path, and an absolute path is percent-decoded
/// (`unix:///tmp/my%20app.sock` is `/tmp/my app.sock`), while a relative
/// `unix:path` is used as written (br-asupersync-mu5yhv finding 6).
fn unix_target_path(uri: &str) -> Option<Result<std::borrow::Cow<'_, str>, GrpcError>> {
    let rest = uri
        .get(..5)
        .filter(|scheme| scheme.eq_ignore_ascii_case("unix:"))
        .map(|_| &uri[5..])?;
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    let path = match rest.strip_prefix("//") {
        Some(absolute) if absolute.starts_with('/') => absolute,
        Some(_) => {
            return Some(Err(GrpcError::transport(
                "unix:// channel URIs need an absolute path (unix:///path/to/socket)",
            )));
        }
        None => rest,
    };
    let path = if path.starts_with('/') {
        let Some(decoded) = percent_decode_socket_path(path) else {
            return Some(Err(GrpcError::transport(
                "unix: channel URI has an invalid percent escape in its socket path",
            )));
        };
        decoded
    } else {
        std::borrow::Cow::Borrowed(path)
    };
    if path.is_empty() || path.contains('\0') {
        return Some(Err(GrpcError::transport(
            "unix: channel URI needs a socket path without NUL bytes",
        )));
    }
    Some(Ok(path))
}

/// Whether this platform can dial the socket `path`. A target it never can
/// is refused when the channel is built, instead of failing every call with
/// an UNAVAILABLE that callers retry (d0's LOW 3 on br-asupersync-x4kh5w).
fn unix_target_dialable(path: &str) -> Result<(), GrpcError> {
    if !cfg!(unix) {
        return Err(GrpcError::transport_kind(
            TransportErrorKind::ProtocolViolation,
            "unix: gRPC channel targets need a Unix platform",
        ));
    }
    // sockaddr_un's sun_path, which also holds the terminating NUL: 108
    // bytes on Linux, 104 on macOS and the BSDs.
    let sun_path = if cfg!(any(target_os = "linux", target_os = "android")) {
        108
    } else {
        104
    };
    if path.len() >= sun_path {
        return Err(GrpcError::transport_kind(
            TransportErrorKind::ProtocolViolation,
            format!(
                "unix: channel socket path is {} bytes; a socket path here must be shorter \
                 than {sun_path}",
                path.len()
            ),
        ));
    }
    Ok(())
}

/// `path` with its `%XX` escapes decoded; `None` for an incomplete or
/// non-hex escape, or bytes that are not UTF-8.
fn percent_decode_socket_path(path: &str) -> Option<std::borrow::Cow<'_, str>> {
    if !path.contains('%') {
        return Some(std::borrow::Cow::Borrowed(path));
    }
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let escape = bytes.get(index + 1..index + 3)?;
            if !escape.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            decoded.push(u8::from_str_radix(std::str::from_utf8(escape).ok()?, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok().map(std::borrow::Cow::Owned)
}

fn validate_channel_security(
    uri: &str,
    config: &ChannelConfig,
    has_tls_connector: bool,
    has_explicit_dial_addr: bool,
) -> Result<(), GrpcError> {
    if let Some(path) = unix_target_path(uri) {
        if config.use_tls || has_tls_connector {
            return Err(GrpcError::transport_kind(
                TransportErrorKind::ProtocolViolation,
                "gRPC TLS is not available on unix: channel targets",
            ));
        }
        if has_explicit_dial_addr {
            return Err(GrpcError::transport_kind(
                TransportErrorKind::ProtocolViolation,
                "unix: channel targets cannot use an explicit dial address",
            ));
        }
        return unix_target_dialable(&path?);
    }
    let (scheme, _) = uri
        .split_once("://")
        .ok_or_else(|| GrpcError::transport("channel URI is missing a scheme separator"))?;
    let tls_requested = scheme.eq_ignore_ascii_case("https") || config.use_tls;
    if has_explicit_dial_addr && !scheme.eq_ignore_ascii_case("https") {
        return Err(GrpcError::transport_kind(
            TransportErrorKind::ProtocolViolation,
            "an explicit gRPC dial address requires an https URI",
        ));
    }
    if has_explicit_dial_addr && channel_target_is_loopback(uri) {
        return Err(GrpcError::transport_kind(
            TransportErrorKind::ProtocolViolation,
            "deterministic loopback channels cannot use an explicit native dial address",
        ));
    }
    if tls_requested && channel_target_is_loopback(uri) {
        return Err(GrpcError::transport_kind(
            TransportErrorKind::ProtocolViolation,
            "gRPC TLS is available only on the native transport; \
             deterministic loopback channels do not negotiate TLS",
        ));
    }
    if tls_requested && !has_tls_connector {
        return Err(GrpcError::transport_kind(
            TransportErrorKind::ProtocolViolation,
            "gRPC TLS channel requested without an explicit TLS connector; \
             configure ChannelBuilder::tls_connector so trust roots and ALPN \
             policy remain caller-controlled",
        ));
    }
    if has_tls_connector && !tls_requested {
        return Err(GrpcError::transport_kind(
            TransportErrorKind::ProtocolViolation,
            "gRPC TLS connector supplied for a cleartext channel",
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
    // br-asupersync-server-stack-hardening-eeexl1.1.3: an outbound call
    // whose caller has already exhausted its budget deadline fails fast
    // locally instead of sending a doomed request.
    if ambient_remaining_budget().is_some_and(|remaining| remaining.is_zero()) {
        return Err(Status::deadline_exceeded(
            "ambient budget deadline already expired",
        ));
    }
    Ok(())
}

/// Remaining time until the ambient [`Cx`](crate::cx::Cx) budget deadline,
/// read against the ambient timer driver (exact under lab virtual time)
/// with a wall-clock fallback (br-asupersync-server-stack-hardening-eeexl1.1.3).
///
/// `None` when no ambient context is installed or its budget carries no
/// deadline; `Some(Duration::ZERO)` when the deadline has already passed.
fn ambient_remaining_budget() -> Option<Duration> {
    crate::cx::Cx::with_current(|cx| {
        let deadline = cx.budget().deadline?;
        let now = cx
            .timer_driver()
            .map_or_else(crate::time::wall_now, |timer| timer.now());
        Some(Duration::from_nanos(deadline.duration_since(now)))
    })
    .flatten()
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

struct ResponseStreamState<T> {
    items: VecDeque<Result<T, Status>>,
    closed: bool,
    terminal_status: Option<Status>,
    terminal_metadata: Metadata,
    waiters: Vec<Waker>,
    /// Producer wakers parked on [`ResponseStream::poll_reserve`] while the
    /// bounded buffer is full; woken on the next consumer drain or on close.
    producer_waiters: Vec<Waker>,
}

impl<T> fmt::Debug for ResponseStreamState<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseStreamState")
            .field("items_len", &self.items.len())
            .field("closed", &self.closed)
            .field("terminal_status", &self.terminal_status)
            .field("terminal_metadata", &self.terminal_metadata)
            .field("waiters_len", &self.waiters.len())
            .field("producer_waiters_len", &self.producer_waiters.len())
            .finish()
    }
}

impl<T> ResponseStreamState<T> {
    fn closed() -> Self {
        Self {
            items: VecDeque::new(),
            closed: true,
            terminal_status: None,
            terminal_metadata: Metadata::new(),
            waiters: Vec::new(),
            producer_waiters: Vec::new(),
        }
    }

    fn open() -> Self {
        Self {
            items: VecDeque::new(),
            closed: false,
            terminal_status: None,
            terminal_metadata: Metadata::new(),
            waiters: Vec::new(),
            producer_waiters: Vec::new(),
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
            if self.waiters.len() >= 32 {
                let evicted = self.waiters.remove(0);
                evicted.wake();
            }
            self.waiters.push(waker.clone());
        }
    }

    fn take_producer_waiters(&mut self) -> Vec<Waker> {
        std::mem::take(&mut self.producer_waiters)
    }

    fn register_producer_waiter(&mut self, waker: &Waker) {
        if !self
            .producer_waiters
            .iter()
            .any(|existing| existing.will_wake(waker))
        {
            if self.producer_waiters.len() >= 32 {
                let evicted = self.producer_waiters.remove(0);
                evicted.wake();
            }
            self.producer_waiters.push(waker.clone());
        }
    }
}

/// A stream of responses from the server.
pub struct ResponseStream<T> {
    state: Arc<Mutex<ResponseStreamState<T>>>,
    on_cancel: Option<Arc<Mutex<CloseHook>>>,
    /// The network call this stream reads, for a legacy streaming call.
    #[cfg(not(target_arch = "wasm32"))]
    native: Option<NativeResponses<T>>,
}

/// The response side of a native legacy call, typed for one response type.
#[cfg(not(target_arch = "wasm32"))]
struct NativeResponses<T> {
    handle: Arc<LegacyResponseHandle>,
    convert: fn(Box<dyn Any + Send>) -> Result<T, Status>,
    /// This handle's id on the call; each clone gets its own, so clones
    /// parked in different tasks are each woken.
    responder: u64,
}

#[cfg(not(target_arch = "wasm32"))]
impl<T> Clone for NativeResponses<T> {
    fn clone(&self) -> Self {
        Self {
            handle: Arc::clone(&self.handle),
            convert: self.convert,
            responder: self.handle.call().new_responder(),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<T> Drop for NativeResponses<T> {
    fn drop(&mut self) {
        // The waker this handle may have left parked on the call goes with it.
        self.handle.call().forget_responder(self.responder);
    }
}

impl<T> Clone for ResponseStream<T> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            on_cancel: self.on_cancel.as_ref().map(Arc::clone),
            #[cfg(not(target_arch = "wasm32"))]
            native: self.native.clone(),
        }
    }
}

impl<T> fmt::Debug for ResponseStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseStream")
            .field("state", &self.state)
            .field("has_cancel_hook", &self.on_cancel.is_some())
            .finish()
    }
}

impl<T> ResponseStream<T> {
    /// Create a new response stream.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ResponseStreamState::closed())),
            on_cancel: None,
            #[cfg(not(target_arch = "wasm32"))]
            native: None,
        }
    }

    /// Create an open response stream that can receive additional items.
    #[must_use]
    pub fn open() -> Self {
        Self {
            state: Arc::new(Mutex::new(ResponseStreamState::open())),
            on_cancel: None,
            #[cfg(not(target_arch = "wasm32"))]
            native: None,
        }
    }

    fn open_with_cancel_hook(on_cancel: CloseHook) -> Self {
        Self {
            state: Arc::new(Mutex::new(ResponseStreamState::open())),
            on_cancel: Some(Arc::new(Mutex::new(on_cancel))),
            #[cfg(not(target_arch = "wasm32"))]
            native: None,
        }
    }

    /// A stream reading the responses of a native legacy call. Cancelling
    /// the stream cancels the call; dropping its last clone does too.
    #[cfg(not(target_arch = "wasm32"))]
    fn native(call: Arc<LegacyNativeCall>) -> Self
    where
        T: Send + 'static,
    {
        let cancel_call = Arc::clone(&call);
        let mut stream = Self::open_with_cancel_hook(Box::new(move || {
            cancel_call.cancel(Status::cancelled("response stream cancelled by client"));
            Ok(())
        }));
        stream.native = Some(NativeResponses {
            handle: Arc::new(LegacyResponseHandle::new(call)),
            convert: downcast_native_response::<T>,
            responder: 0,
        });
        stream
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

    /// Number of queued response items currently waiting to be consumed.
    #[must_use]
    pub fn buffer_len(&self) -> usize {
        lock_unpoisoned(&self.state).items.len()
    }

    /// Maximum number of response items this stream will buffer before applying
    /// sender backpressure.
    #[must_use]
    pub fn buffer_capacity(&self) -> usize {
        MAX_STREAM_BUFFERED
    }

    /// Remaining enqueue slots before the stream applies sender backpressure.
    #[must_use]
    pub fn remaining_capacity(&self) -> usize {
        let len = lock_unpoisoned(&self.state).items.len();
        MAX_STREAM_BUFFERED.saturating_sub(len)
    }

    /// Whether the stream has reached its bounded buffer cap.
    #[must_use]
    pub fn is_full(&self) -> bool {
        lock_unpoisoned(&self.state).items.len() >= MAX_STREAM_BUFFERED
    }

    /// Polls for outbound buffer capacity, *suspending* the producer at the
    /// bounded-buffer window when it is exhausted.
    ///
    /// This is the suspend/resume counterpart to [`push`](Self::push): where
    /// `push` fails fast with
    /// [`Code::ResourceExhausted`]
    /// once the buffer is full, `poll_reserve` instead parks the producer until
    /// the consumer drains an item (the "window update"), then wakes it so the
    /// next `push` is guaranteed a free slot. A server-streaming handler that
    /// gates each `push` behind `poll_reserve` is flow-controlled: it cannot
    /// outrun a slow consumer, and the buffer never exceeds
    /// [`MAX_STREAM_BUFFERED`].
    ///
    /// Returns:
    /// - `Poll::Ready(Ok(()))` when at least one slot is free,
    /// - `Poll::Pending` (registering `cx`'s waker) when the buffer is full,
    /// - `Poll::Ready(Err(_))` when the stream is closed — the producer should
    ///   stop rather than spin.
    pub fn poll_reserve(&self, cx: &mut Context<'_>) -> Poll<Result<(), Status>> {
        let mut state = lock_unpoisoned(&self.state);
        if state.closed {
            return Poll::Ready(Err(Status::failed_precondition(
                "cannot reserve capacity on a closed response stream",
            )));
        }
        if state.items.len() < MAX_STREAM_BUFFERED {
            return Poll::Ready(Ok(()));
        }
        state.register_producer_waiter(cx.waker());
        Poll::Pending
    }

    /// Close the stream.
    pub fn close(&self) {
        let (waiters, producers) = {
            let mut state = lock_unpoisoned(&self.state);
            state.closed = true;
            (state.take_waiters(), state.take_producer_waiters())
        };
        for waker in waiters {
            waker.wake();
        }
        // Wake parked producers so they re-poll, observe the close, and stop.
        for waker in producers {
            waker.wake();
        }
    }

    /// Close the stream with a terminal status.
    pub fn cancel(&self, status: Status) {
        self.cancel_with_metadata(status, Metadata::new());
    }

    fn set_terminal_status(
        &self,
        status: Status,
        metadata: Metadata,
        discard_buffered: bool,
    ) -> bool {
        let (waiters, producers, inserted) = {
            let mut state = lock_unpoisoned(&self.state);
            state.closed = true;
            let inserted = state.terminal_status.is_none();
            if state.terminal_status.is_none() {
                if discard_buffered {
                    state.items.clear();
                }
                state.terminal_status = Some(status);
                state.terminal_metadata = metadata;
            }
            (
                state.take_waiters(),
                state.take_producer_waiters(),
                inserted,
            )
        };
        for waker in waiters {
            waker.wake();
        }
        // Wake parked producers so they re-poll, observe the close, and stop.
        for waker in producers {
            waker.wake();
        }
        inserted
    }

    /// Cancel the stream immediately with a terminal status and trailing metadata.
    ///
    /// Cancellation is abrupt: queued response items are discarded so the
    /// caller observes the terminal status before any stale buffered payloads.
    pub fn cancel_with_metadata(&self, status: Status, metadata: Metadata) {
        if self.set_terminal_status(status, metadata, true)
            && let Some(on_cancel) = &self.on_cancel
        {
            let mut hook = lock_unpoisoned(on_cancel);
            let _ = hook();
        }
    }

    /// Finish the stream with a terminal status after draining queued items.
    ///
    /// This models the gRPC trailers path where already-received response data
    /// remains visible before the final status/trailers are observed.
    pub fn finish_with_metadata(&self, status: Status, metadata: Metadata) {
        self.set_terminal_status(status, metadata, false);
    }

    /// Returns the terminal trailing metadata captured for the stream.
    #[must_use]
    pub fn terminal_metadata(&self) -> Metadata {
        lock_unpoisoned(&self.state).terminal_metadata.clone()
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
            // A buffer slot just freed: wake any producer parked on
            // `poll_reserve` so it observes the window update and resumes.
            let producers = state.take_producer_waiters();
            drop(state);
            for waker in producers {
                waker.wake();
            }
            return Poll::Ready(Some(item));
        }
        if let Some(status) = state.terminal_status.take() {
            return Poll::Ready(Some(Err(status)));
        }
        if state.closed {
            return Poll::Ready(None);
        }
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(native) = &self.native {
            drop(state);
            return self.poll_native(native, cx);
        }
        state.register_waiter(cx.waker());
        Poll::Pending
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<T> ResponseStream<T> {
    /// Read the next response of a native call. Its end closes this stream
    /// (sharing the end with every clone) and records the trailers.
    fn poll_native(
        &self,
        native: &NativeResponses<T>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<T, Status>>> {
        let call = native.handle.call();
        let end = match call.poll_message(cx, native.responder) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Some(Ok(message))) => return Poll::Ready(Some((native.convert)(message))),
            Poll::Ready(Some(Err(status))) => Some(Err(status)),
            Poll::Ready(None) => None,
        };
        let trailers = call.trailers().unwrap_or_default();
        let waiters = {
            let mut state = lock_unpoisoned(&self.state);
            state.closed = true;
            state.terminal_metadata = trailers;
            state.take_waiters()
        };
        for waker in waiters {
            waker.wake();
        }
        Poll::Ready(end)
    }
}

type SendHook<T> = Box<dyn FnMut(T) -> Result<(), Status> + Send>;
type CloseHook = Box<dyn FnMut() -> Result<(), Status> + Send>;

#[derive(Debug, Clone, Default)]
enum RequestSinkCloseState {
    #[default]
    Open,
    Graceful,
    Cancelled(Status),
    Failed(Status),
}

impl RequestSinkCloseState {
    fn is_open(&self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Default)]
struct RequestSinkState {
    close_state: RequestSinkCloseState,
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
    on_cancel: Option<CloseHook>,
    /// The network call this sink writes, for a legacy streaming call.
    #[cfg(not(target_arch = "wasm32"))]
    native: Option<Arc<LegacyNativeCall>>,
}

fn send_closed_error(close_state: &RequestSinkCloseState) -> Option<Status> {
    match close_state {
        RequestSinkCloseState::Open => None,
        RequestSinkCloseState::Graceful => Some(Status::failed_precondition(
            "cannot send after request sink is closed",
        )),
        RequestSinkCloseState::Cancelled(status) | RequestSinkCloseState::Failed(status) => {
            Some(status.clone())
        }
    }
}

fn cancel_request_sink_state(state: &Arc<Mutex<RequestSinkState>>, status: Status) {
    let waiter = {
        let mut state = lock_unpoisoned(state);
        if !state.close_state.is_open() {
            None
        } else {
            state.close_state = RequestSinkCloseState::Cancelled(status);
            state.waiter.take()
        }
    };
    if let Some(waiter) = waiter {
        waiter.wake();
    }
}

impl<T> RequestSink<T> {
    /// Create a new request sink.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(RequestSinkState::new())),
            on_send: None,
            on_close: None,
            on_cancel: None,
            #[cfg(not(target_arch = "wasm32"))]
            native: None,
        }
    }

    /// Return the number of request messages accepted by this sink.
    #[must_use]
    pub fn sent_count(&self) -> usize {
        lock_unpoisoned(&self.state).sent_count
    }

    fn from_state(state: Arc<Mutex<RequestSinkState>>) -> Self {
        Self {
            state,
            on_send: None,
            on_close: None,
            on_cancel: None,
            #[cfg(not(target_arch = "wasm32"))]
            native: None,
        }
    }

    /// A sink writing the request side of a native legacy call.
    #[cfg(not(target_arch = "wasm32"))]
    fn native(call: Arc<LegacyNativeCall>) -> Self {
        let mut sink = Self::from_state(Arc::new(Mutex::new(RequestSinkState::new())));
        sink.native = Some(call);
        sink
    }

    #[cfg(test)]
    fn with_hooks(
        on_send: Option<SendHook<T>>,
        on_close: Option<CloseHook>,
        on_cancel: Option<CloseHook>,
    ) -> Self {
        Self::with_state_and_hooks(
            Arc::new(Mutex::new(RequestSinkState::new())),
            on_send,
            on_close,
            on_cancel,
        )
    }

    fn with_state_and_hooks(
        state: Arc<Mutex<RequestSinkState>>,
        on_send: Option<SendHook<T>>,
        on_close: Option<CloseHook>,
        on_cancel: Option<CloseHook>,
    ) -> Self {
        Self {
            state,
            on_send,
            on_close,
            on_cancel,
            #[cfg(not(target_arch = "wasm32"))]
            native: None,
        }
    }

    /// Send a request message.
    ///
    /// For a network call this waits until the previous message has left
    /// the local write queues (and, for a bidirectional call, until unread
    /// responses fall below the stream's buffer), then queues `message`.
    #[allow(clippy::unused_async)]
    pub async fn send(&mut self, message: T) -> Result<(), Status>
    where
        T: Send + 'static,
    {
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(call) = self.native.clone() {
            let closed_error = send_closed_error(&lock_unpoisoned(&self.state).close_state);
            if let Some(status) = closed_error {
                return Err(status);
            }
            let mut message = Some(Box::new(message) as Box<dyn Any + Send>);
            std::future::poll_fn(|task| call.poll_send(task, &mut message)).await?;
            let mut state = lock_unpoisoned(&self.state);
            state.sent_count = state.sent_count.saturating_add(1);
            return Ok(());
        }
        if self.on_send.is_none() {
            let closed_error = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let closed_error = send_closed_error(&state.close_state);
                if closed_error.is_none() {
                    if state.sent_count > 0 {
                        return Err(Status::failed_precondition(
                            "loopback client streaming does not support multiple request messages yet",
                        ));
                    }
                    state.last_message = Some(Box::new(message));
                    state.sent_count = state.sent_count.saturating_add(1);
                }
                drop(state);
                closed_error
            };
            if let Some(status) = closed_error {
                return Err(status);
            }
            return Ok(());
        }

        let closed_error = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            send_closed_error(&state.close_state)
        };
        if let Some(status) = closed_error {
            return Err(status);
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
    ///
    /// For a network call this half-closes the request stream once the last
    /// queued message has left the local write queues.
    #[allow(clippy::unused_async)]
    pub async fn close(&mut self) -> Result<(), Status> {
        {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match &state.close_state {
                RequestSinkCloseState::Open => {}
                RequestSinkCloseState::Graceful => return Ok(()),
                RequestSinkCloseState::Cancelled(status)
                | RequestSinkCloseState::Failed(status) => {
                    return Err(status.clone());
                }
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(call) = self.native.clone() {
            let result = std::future::poll_fn(|task| call.poll_close(task)).await;
            lock_unpoisoned(&self.state).close_state = match &result {
                Ok(()) => RequestSinkCloseState::Graceful,
                Err(status) => RequestSinkCloseState::Failed(status.clone()),
            };
            return result;
        }
        if let Some(hook) = self.on_close.as_mut() {
            if let Err(status) = hook() {
                let waiter = {
                    let mut state = self
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    state.close_state = RequestSinkCloseState::Failed(status.clone());
                    state.waiter.take()
                };
                if let Some(waiter) = waiter {
                    waiter.wake();
                }
                return Err(status);
            }
        }
        let waiter = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.close_state = RequestSinkCloseState::Graceful;
            state.waiter.take()
        };
        if let Some(waiter) = waiter {
            waiter.wake();
        }
        Ok(())
    }
}

impl<T> Drop for RequestSink<T> {
    fn drop(&mut self) {
        let cancel_status = Status::cancelled("request stream cancelled by client");
        let (waiter, invoke_cancel_hook, invoke_close_hook) = {
            let mut state = lock_unpoisoned(&self.state);
            if !state.close_state.is_open() {
                (None, false, false)
            } else {
                #[cfg(not(target_arch = "wasm32"))]
                if let Some(call) = &self.native {
                    call.cancel(cancel_status.clone());
                }
                state.close_state = RequestSinkCloseState::Cancelled(cancel_status);
                (
                    state.waiter.take(),
                    self.on_cancel.is_some(),
                    self.on_close.is_some(),
                )
            }
        };

        if let Some(waiter) = waiter {
            waiter.wake();
        }

        if invoke_cancel_hook {
            if let Some(hook) = self.on_cancel.as_mut() {
                let _ = hook();
            }
        } else if invoke_close_hook {
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
            .field("close_state", &state.close_state)
            .field("sent_count", &state.sent_count)
            .field("has_send_hook", &self.on_send.is_some())
            .field("has_close_hook", &self.on_close.is_some())
            .field("has_cancel_hook", &self.on_cancel.is_some())
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
    /// The network call this future awaits, for a legacy streaming call.
    #[cfg(not(target_arch = "wasm32"))]
    native: Option<NativeResponses<T>>,
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
            .field("sink_close_state", &state.close_state)
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
                close_state: RequestSinkCloseState::Graceful,
                ..RequestSinkState::new()
            })),
            resolver: Some(Box::new(|_| {
                Err(Status::failed_precondition(
                    "response future is not linked to a request sink",
                ))
            })),
            #[cfg(not(target_arch = "wasm32"))]
            native: None,
        }
    }

    fn with_resolver<F>(state: Arc<Mutex<RequestSinkState>>, resolver: F) -> Self
    where
        F: FnMut(&mut RequestSinkState) -> Result<Response<T>, Status> + Send + 'static,
    {
        Self {
            state,
            resolver: Some(Box::new(resolver)),
            #[cfg(not(target_arch = "wasm32"))]
            native: None,
        }
    }

    /// A future for the single response of a native client-streaming call.
    /// Once it resolves, polling again reports that it already completed.
    #[cfg(not(target_arch = "wasm32"))]
    fn native(call: Arc<LegacyNativeCall>) -> Self
    where
        T: Send + 'static,
    {
        Self {
            state: Arc::new(Mutex::new(RequestSinkState {
                close_state: RequestSinkCloseState::Graceful,
                ..RequestSinkState::new()
            })),
            resolver: None,
            native: Some(NativeResponses {
                handle: Arc::new(LegacyResponseHandle::new(call)),
                convert: downcast_native_response::<T>,
                responder: 0,
            }),
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
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(native) = &this.native {
            let call = native.handle.call();
            let output = match call.poll_single_response(cx, native.responder) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok((message, metadata))) => (native.convert)(message)
                    .map(|message| Response::with_metadata(message, metadata)),
                Poll::Ready(Err(status)) => Err(status),
            };
            this.native = None;
            return Poll::Ready(output);
        }
        let mut state = lock_unpoisoned(&this.state);
        if state.close_state.is_open() {
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
        let output = match state.close_state.clone() {
            RequestSinkCloseState::Graceful => resolver(&mut state),
            RequestSinkCloseState::Cancelled(status) | RequestSinkCloseState::Failed(status) => {
                Err(status)
            }
            RequestSinkCloseState::Open => unreachable!("open sinks must have returned Pending"),
        };
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
        let _ = self.metadata.insert(key, value);
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
                    let _ = request_metadata.insert(key, v.clone());
                }
                super::streaming::MetadataValue::Binary(v) => {
                    let _ = request_metadata.insert_bin(key, v.clone());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "client_inline_tests.rs"]
mod tests;
