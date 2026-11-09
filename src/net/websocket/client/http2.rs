//! WebSocket clients over owned HTTP/2 extended CONNECT tunnels.

use super::{Message, WebSocket, WebSocketConfig, WebSocketConnectOptions, WsConnectError};
use crate::bytes::Bytes;
use crate::cx::Cx;
use crate::http::Method;
use crate::http::h2::{
    Http2Client, Http2ClientError, Http2ClientIo, Http2RequestBuilder, Http2Tunnel,
    Http2TunnelConfig, Http2TunnelError,
};
use crate::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::net::websocket::{CloseReason, HandshakeError, WsError, WsUrl};
use std::fmt;
use std::io;

const MAX_URL_BYTES: usize = 8192;
const MAX_PROTOCOLS: usize = 32;
const MAX_PROTOCOL_BYTES: usize = 256;

/// A native RFC 8441 WebSocket with an owned HTTP/2 connection.
///
/// This uses the existing WebSocket framing, masking, message limits, heartbeat,
/// compression, and Close state machine. It owns a single HTTP/2 tunnel and
/// drives both directions while polled; no background driver, shared-connection
/// multiplexing, retry, redirect, or HTTP/1 fallback is implicit.
///
/// Setup waits for the peer to enable extended CONNECT, then validates its 2xx
/// response and negotiated WebSocket parameters. The client and WebSocket setup
/// timeouts bound only connection establishment. Afterwards the original Cx
/// authority/deadlines, WebSocket timers, and explicit tunnel DATA limits apply.
///
/// Reads and writes remain bounded and flow controlled. Applications must read
/// to replenish receive credit; bounded duplex buffering cannot promise that
/// two peers both sending unbounded messages before reading will make progress.
///
/// Close completion requires a real peer Close, server END_STREAM, and a flushed
/// client END_STREAM, in that order. The original Close budget survives a
/// dropped recv or close future. Dropping the socket retires the owned transport.
#[must_use = "an HTTP/2 WebSocket makes progress only while polled"]
pub struct Http2ClientWebSocket<T = Http2ClientIo> {
    inner: WebSocket<Http2Tunnel<T>>,
    pending_close: Option<Option<CloseReason>>,
    clean: bool,
    failed: bool,
}

impl<T> fmt::Debug for Http2ClientWebSocket<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http2ClientWebSocket")
            .field("clean", &self.clean)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl Http2ClientWebSocket<Http2ClientIo> {
    /// Connect to a ws:// or wss:// URL through a native HTTP/2 tunnel.
    ///
    /// Cleartext uses HTTP/2 prior knowledge. TLS uses the Http2Client's supplied
    /// connector, authenticates the URL host, and requires h2 ALPN. Origin,
    /// Authorization, Cookie, and tracing metadata use the bounded/redacted
    /// WebSocketConnectOptions. Proxy credentials are never origin metadata.
    /// No credentials are sent before the peer enables extended CONNECT.
    pub async fn connect(
        cx: &Cx,
        client: &Http2Client,
        url: &str,
        options: WebSocketConnectOptions,
        tunnel: Http2TunnelConfig,
    ) -> Result<Self, WsConnectError> {
        let (request, config, compression) = prepare(client, url, options)?;
        let io = request
            .connect_tunnel(cx, "websocket", tunnel)
            .await
            .map_err(map_tunnel_error)?;
        Self::from_tunnel(cx, io, config, compression)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Http2ClientWebSocket<T> {
    /// Connect using an owned caller-supplied HTTP/2 transport.
    ///
    /// The URL supplies routing metadata only. The caller verifies any TLS
    /// certificate and h2 ALPN; no connection, retry, or fallback is performed.
    /// Borrowed and non-Send transports are accepted. The future owns the
    /// transport immediately, so dropping it before its first poll retires it.
    pub async fn connect_on(
        cx: &Cx,
        client: &Http2Client,
        url: &str,
        transport: T,
        options: WebSocketConnectOptions,
        tunnel: Http2TunnelConfig,
    ) -> Result<Self, WsConnectError> {
        let (request, config, compression) = prepare(client, url, options)?;
        let io = request
            .connect_tunnel_on(cx, transport, "websocket", tunnel)
            .await
            .map_err(map_tunnel_error)?;
        Self::from_tunnel(cx, io, config, compression)
    }

    fn from_tunnel(
        cx: &Cx,
        io: Http2Tunnel<T>,
        config: WebSocketConfig,
        compression: bool,
    ) -> Result<Self, WsConnectError> {
        let mut selected = None;
        let mut extensions = None;
        for header in io.headers() {
            match header.name.as_str() {
                "sec-websocket-protocol" => {
                    if selected.is_some()
                        || !token(&header.value)
                        || !config.protocols.iter().any(|p| p == &header.value)
                    {
                        return Err(handshake("invalid HTTP/2 WebSocket subprotocol selection"));
                    }
                    selected = Some(header.value.clone());
                }
                "sec-websocket-extensions" => {
                    if extensions.is_some() || !compression {
                        return Err(handshake("invalid HTTP/2 WebSocket extension selection"));
                    }
                    extensions = Some(
                        header
                            .value
                            .split(',')
                            .map(|value| value.trim().to_owned())
                            .collect::<Vec<_>>(),
                    );
                }
                // RFC 8441 removes the H1 key/accept exchange. These fields
                // carry no authority and are neither required nor processed.
                "sec-websocket-key" | "sec-websocket-accept" => {}
                _ => {}
            }
        }
        let extensions = extensions.unwrap_or_default();
        let mut inner =
            WebSocket::from_upgraded_with_extensions(io, config, &extensions, cx.entropy_handle())
                .map_err(|error| super::connect_options::redact_connect_error(error.into()))?;
        inner.protocol = selected;
        Ok(Self {
            inner,
            pending_close: None,
            clean: false,
            failed: false,
        })
    }

    /// Negotiated subprotocol, if any.
    #[must_use]
    pub fn protocol(&self) -> Option<&str> {
        self.inner.protocol()
    }

    /// Whether permessage-deflate was negotiated.
    #[must_use]
    pub fn compression_enabled(&self) -> bool {
        self.inner.compression_enabled()
    }

    /// Whether the WebSocket still admits ordinary messages.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.failed && !self.clean && self.inner.is_open()
    }

    /// Whether normal completion or failure retired this socket.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.clean || self.failed
    }

    /// Send a bounded, client-masked WebSocket message.
    ///
    /// A dropped future may have committed part of its frame. The existing
    /// write buffer and tunnel retain that progress; a subsequent operation
    /// resumes it. An actual error retires the transport.
    pub async fn send(&mut self, cx: &Cx, message: Message) -> Result<(), WsError> {
        self.check_live()?;
        if let Err(error) = self.inner.send(cx, message).await {
            self.abort();
            return Err(error);
        }
        Ok(())
    }

    /// Receive a message while advancing accepted output and H2 control frames.
    ///
    /// A peer Close is delivered exactly once, after both END_STREAM directions
    /// complete. Dropping this future retains its Close receipt and original
    /// deadline for the next recv, close, or finish call. Raw EOF is an error.
    pub async fn recv(&mut self, cx: &Cx) -> Result<Option<Message>, WsError> {
        if self.clean {
            return Ok(None);
        }
        self.check_live()?;
        if self.pending_close.is_none() {
            match self.inner.recv(cx).await {
                Ok(Some(Message::Close(reason))) => self.pending_close = Some(reason),
                Ok(Some(message)) => return Ok(Some(message)),
                Ok(None) => {
                    let error = if self.inner.close_handshake.timed_out() {
                        crate::net::websocket::close::close_timeout_error()
                    } else {
                        abnormal_eof()
                    };
                    self.abort();
                    return Err(error);
                }
                Err(error) => {
                    self.abort();
                    return Err(error);
                }
            }
        }
        self.complete_close(cx).await?;
        Ok(self.pending_close.take().map(Message::Close))
    }

    /// Send a Ping using the existing WebSocket heartbeat/write machinery.
    pub async fn ping(&mut self, cx: &Cx, payload: impl Into<Bytes>) -> Result<(), WsError> {
        self.check_live()?;
        if let Err(error) = self.inner.ping(cx, payload).await {
            self.abort();
            return Err(error);
        }
        Ok(())
    }

    /// Initiate or resume Close and wait for both HTTP/2 halves to retire.
    ///
    /// The peer must send a real WebSocket Close and server END_STREAM before
    /// this client publishes END_STREAM. Timeout, cancellation, reset, and raw
    /// EOF are errors; none can be reported as clean completion.
    pub async fn close(&mut self, cx: &Cx, reason: CloseReason) -> Result<(), WsError> {
        if self.clean {
            return Ok(());
        }
        self.check_live()?;
        if self.pending_close.is_none() {
            if let Err(error) = self.inner.initiate_close_with_cx(Some(cx), reason).await {
                self.abort();
                return Err(error);
            }
        }
        loop {
            match self.recv(cx).await? {
                Some(Message::Close(_)) | None => return Ok(()),
                Some(_) => {}
            }
        }
    }

    /// Consume the socket after a complete Close exchange and transport drain.
    ///
    /// An open socket starts a normal Close. A previously started exchange
    /// resumes its retained deadline; this method never grants a fresh budget.
    pub async fn finish(mut self, cx: &Cx) -> Result<(), WsError> {
        self.close(cx, CloseReason::normal()).await
    }

    fn check_live(&self) -> Result<(), WsError> {
        if self.failed || self.clean {
            Err(WsError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "HTTP/2 WebSocket is closed",
            )))
        } else {
            Ok(())
        }
    }

    fn abort(&mut self) {
        self.failed = true;
        self.inner.io.abort();
        self.pending_close = None;
    }

    async fn complete_close(&mut self, cx: &Cx) -> Result<(), WsError> {
        let Some(deadline) = self.inner.close_handshake.deadline() else {
            self.abort();
            return Err(abnormal_eof());
        };
        if self.inner.close_handshake.peer_reason().is_none()
            || !self.inner.close_handshake.is_closed()
        {
            self.abort();
            return Err(abnormal_eof());
        }
        let result = deadline
            .wait(Some(cx), async {
                // A buffered suffix after Close is not transport EOF. Never turn
                // unconsumed WebSocket payload into a clean half-close receipt.
                if !self.inner.read_buf.is_empty() {
                    return Err(abnormal_eof());
                }
                self.inner.flush_write_buf_with_cx(Some(cx)).await?;
                let mut byte = [0u8; 1];
                if self.inner.io.read(&mut byte).await.map_err(WsError::Io)? != 0 {
                    return Err(abnormal_eof());
                }
                self.inner.io.shutdown().await.map_err(WsError::Io)?;
                if !self.inner.io.is_closed() {
                    return Err(abnormal_eof());
                }
                Ok(())
            })
            .await;
        match result {
            Ok(Some(())) => {
                self.clean = true;
                Ok(())
            }
            Ok(None) => {
                self.abort();
                Err(crate::net::websocket::close::close_timeout_error())
            }
            Err(error) => {
                self.abort();
                Err(error)
            }
        }
    }
}

fn prepare(
    client: &Http2Client,
    url: &str,
    options: WebSocketConnectOptions,
) -> Result<(Http2RequestBuilder, WebSocketConfig, bool), WsConnectError> {
    if url.len() > MAX_URL_BYTES {
        return Err(handshake("WebSocket URL exceeds 8 KiB"));
    }
    let parsed = WsUrl::parse(url).map_err(|error| {
        super::connect_options::redact_connect_error(WsConnectError::InvalidUrl(error))
    })?;
    let (config, headers, compression) = options.into_parts();
    if config.protocols.len() > MAX_PROTOCOLS {
        return Err(handshake("too many WebSocket subprotocols"));
    }
    for (index, protocol) in config.protocols.iter().enumerate() {
        if protocol.len() > MAX_PROTOCOL_BYTES
            || !token(protocol)
            || config.protocols[..index].contains(protocol)
        {
            return Err(handshake("invalid WebSocket subprotocol list"));
        }
    }
    let scheme = if parsed.tls { "https" } else { "http" };
    let mut request = client
        .request(
            Method::Connect,
            format!("{scheme}://{}{}", parsed.host_header(), parsed.path),
        )
        .header("sec-websocket-version", "13");
    if let Some(timeout) = config.connect_timeout {
        request = request.timeout(timeout);
    }
    if !config.protocols.is_empty() {
        request = request.header("sec-websocket-protocol", config.protocols.join(", "));
    }
    if compression {
        request = request.header(
            "sec-websocket-extensions",
            crate::net::websocket::compression::OFFER,
        );
    }
    for (name, value) in headers {
        request = request.header(name, value);
    }
    Ok((request, config, compression))
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_\x60|~".contains(&b))
}

fn handshake(reason: &'static str) -> WsConnectError {
    WsConnectError::Handshake(HandshakeError::InvalidRequest(reason.to_owned()))
}

fn abnormal_eof() -> WsError {
    WsError::Io(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "HTTP/2 WebSocket did not complete its Close and END_STREAM exchange",
    ))
}

fn map_tunnel_error(error: Http2TunnelError) -> WsConnectError {
    match error {
        Http2TunnelError::NotNegotiated => {
            handshake("peer did not enable HTTP/2 extended CONNECT before the setup deadline")
        }
        Http2TunnelError::Rejected(status) => WsConnectError::Handshake(HandshakeError::Rejected {
            status,
            reason: "HTTP/2 WebSocket CONNECT rejected".to_owned(),
        }),
        Http2TunnelError::Client(Http2ClientError::Cancelled(_)) => WsConnectError::Cancelled,
        Http2TunnelError::Client(Http2ClientError::DeadlineExceeded) => {
            WsConnectError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP/2 WebSocket setup deadline elapsed",
            ))
        }
        Http2TunnelError::Client(Http2ClientError::MissingIoCapability) => {
            WsConnectError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "HTTP/2 WebSocket lacks native I/O authority",
            ))
        }
        Http2TunnelError::Client(Http2ClientError::Io(error)) => WsConnectError::Io(
            io::Error::new(error.kind(), "HTTP/2 WebSocket transport failed"),
        ),
        Http2TunnelError::Client(Http2ClientError::Tls(_)) => WsConnectError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "HTTP/2 WebSocket TLS authentication or h2 ALPN failed",
        )),
        Http2TunnelError::Client(_) => {
            handshake("HTTP/2 WebSocket request or peer protocol failed")
        }
    }
}

#[cfg(test)]
#[path = "http2_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "http2_protocol_tests.rs"]
mod protocol_tests;
