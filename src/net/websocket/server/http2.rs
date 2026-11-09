//! Request-owned RFC 8441 WebSockets over the native HTTP/2 duplex lane.

use super::{CloseReason, Message, ServerWebSocket, WebSocketAcceptor, WsAcceptError, WsError};
use crate::bytes::{Buf, Bytes, BytesCursor};
use crate::cx::Cx;
use crate::http::body::{Body, Frame};
use crate::http::h1::stream::{IncomingBodyError, IncomingRequestBody, StreamingServerRequest};
use crate::http::h1::{HttpError, Method, Response, Version};
use crate::http::h2::listener::{Http2BodySender, Http2ProducedResponse};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::sync::atomic::{AtomicBool, Ordering};
use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

const OUTPUT_FRAME_BYTES: usize = 16 * 1024;
const OUTPUT_FRAME_CAPACITY: usize = 8;
const DRAIN_FRAMES_PER_POLL: usize = 16;

/// A server WebSocket carried by one negotiated HTTP/2 stream.
///
/// The native listener's actual request task owns its input, bounded output,
/// cancellation, and close handshake. Other streams on the same connection
/// remain independent. Dropping this socket aborts only this response; it does
/// not detach work or transfer ownership to a connection-global task.
///
/// Finish the handler with [`Self::finish`] to return its completion receipt.
/// A clean receipt requires the WebSocket close exchange, flushed output, and
/// the peer's HTTP/2 `END_STREAM`, all within the retained close deadline.
pub struct Http2WebSocket {
    inner: ServerWebSocket<TunnelIo>,
    identity: Arc<AtomicBool>,
}

impl std::fmt::Debug for Http2WebSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http2WebSocket")
            .field("open", &self.inner.is_open())
            .field("closed", &self.inner.is_closed())
            .finish_non_exhaustive()
    }
}

/// Proof that one HTTP/2 WebSocket finished its own bounded response channel.
///
/// Only [`Http2WebSocket::finish`] constructs this value. Return it from the
/// callback passed to [`WebSocketAcceptor::accept_http2`]. The listener sends
/// its verified transport half-close during the close exchange, then retains
/// request ownership until this receipt and child/finalizer retirement.
#[must_use = "return the receipt from the HTTP/2 WebSocket handler"]
pub struct Http2WebSocketCompletion {
    sender: Http2BodySender,
    identity: Arc<AtomicBool>,
}

impl std::fmt::Debug for Http2WebSocketCompletion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http2WebSocketCompletion")
            .field("total_bytes", &self.sender.total_bytes())
            .finish_non_exhaustive()
    }
}

impl Http2WebSocket {
    /// The negotiated subprotocol, if one was selected.
    #[must_use]
    pub fn protocol(&self) -> Option<&str> {
        self.inner.protocol()
    }

    /// The negotiated WebSocket extensions.
    #[must_use]
    pub fn extensions(&self) -> &[String] {
        self.inner.extensions()
    }

    /// Whether permessage-deflate was negotiated.
    #[must_use]
    pub fn compression_enabled(&self) -> bool {
        self.inner.compression_enabled()
    }

    /// Whether application messages may still be exchanged.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.inner.is_open()
    }

    /// Whether the WebSocket close state is terminal.
    ///
    /// A timeout or protocol failure can also make this true. Only
    /// [`Self::finish`] certifies a clean HTTP/2 completion.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Send one message using the existing bounded WebSocket codec.
    ///
    /// Cancellation can interrupt a partially committed frame. The request
    /// remains responsible for the accepted bytes until completion or drop.
    pub async fn send(&mut self, cx: &Cx, message: Message) -> Result<(), WsError> {
        self.inner.send(cx, message).await
    }

    /// Receive one message, automatically responding to Ping and Close.
    ///
    /// A Close receipt is delivered only after the echoed Close has flushed
    /// and the peer has ended its HTTP/2 input half. The existing close
    /// timeout and request cancellation bound that wait.
    pub async fn recv(&mut self, cx: &Cx) -> Result<Option<Message>, WsError> {
        let message = self.inner.recv(cx).await?;
        if matches!(message, Some(Message::Close(_))) && !self.inner.io.shutdown_complete {
            return Err(WsError::Io(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "HTTP/2 WebSocket close did not finish its transport",
            )));
        }
        Ok(message)
    }

    /// Send a Ping using the request-owned output channel.
    pub async fn ping(&mut self, cx: &Cx, payload: impl Into<Bytes>) -> Result<(), WsError> {
        self.inner.ping(cx, payload).await
    }

    /// Exchange Close frames and retire both HTTP/2 halves within the
    /// original WebSocket close deadline.
    pub async fn close(&mut self, cx: &Cx, reason: CloseReason) -> Result<(), WsError> {
        if self.inner.is_closed()
            && !self.inner.close_handshake.has_pending_peer_close()
            && !self.inner.io.shutdown_complete
        {
            return Err(WsError::Io(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "HTTP/2 WebSocket close was aborted",
            )));
        }
        if self.inner.io.shutdown_complete {
            cx.checkpoint().map_err(|_| cancelled())?;
            return self.inner.io.check_owner().map_err(WsError::Io);
        }
        self.inner.close(cx, reason).await?;
        if !self.inner.io.shutdown_complete || !self.identity.load(Ordering::Acquire) {
            return Err(WsError::Io(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "HTTP/2 WebSocket close did not finish its transport",
            )));
        }
        Ok(())
    }

    /// Finish this session and return its channel-bound completion receipt.
    ///
    /// If still open, initiate a normal close. A peer that has sent Close
    /// may wait for the server's `END_STREAM` before ending its input half.
    /// The request stays owned throughout that bounded wait. A timeout,
    /// cancellation, incomplete close, or a failed flush returns an error;
    /// it cannot be reported as a successful response EOF.
    pub async fn finish(mut self, cx: &Cx) -> Result<Http2WebSocketCompletion, WsError> {
        cx.checkpoint().map_err(|_| cancelled())?;
        if self.inner.close_handshake.has_pending_peer_close() {
            let _ = self.inner.finish_peer_close(cx).await?;
        } else if !self.inner.is_closed() {
            self.inner.close(cx, CloseReason::normal()).await?;
        }
        cx.checkpoint().map_err(|_| cancelled())?;
        if self.inner.close_handshake.peer_reason().is_none()
            || self.inner.close_handshake.timed_out()
            || !self.identity.load(Ordering::Acquire)
        {
            return Err(WsError::Io(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "HTTP/2 WebSocket has no completed peer Close exchange",
            )));
        }
        let io = &mut self.inner.io;
        io.check_owner().map_err(WsError::Io)?;
        if !io.shutdown_complete || io.pending.is_some() || io.failed.is_some() {
            return Err(WsError::Io(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "HTTP/2 WebSocket did not complete its bounded close",
            )));
        }
        let sender = io.sender.take().ok_or_else(|| {
            WsError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "HTTP/2 WebSocket output is unavailable",
            ))
        })?;
        if !sender.is_finished() {
            return Err(WsError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "HTTP/2 WebSocket output is unfinished",
            )));
        }
        Ok(Http2WebSocketCompletion {
            sender,
            identity: self.identity,
        })
    }
}

impl WebSocketAcceptor {
    /// Accept a negotiated RFC 8441 WebSocket on a native HTTP/2 listener.
    ///
    /// Enable `Http2StreamingListenerConfig::with_extended_connect` and use
    /// the listener's produced streaming-response lane. This method validates
    /// the transport-minted protocol and WebSocket version, then returns a
    /// deferred `200` response. It never writes HTTP/1 Upgrade, key, or accept
    /// headers. Existing subprotocol, compression, frame, message, pending
    /// write, heartbeat, and close settings apply.
    /// HTTP/1 upgrade/key/accept headers and Content-Length are rejected;
    /// tunnel DATA has no ordinary HTTP request-body length.
    ///
    /// Check application authorization and Origin policy on `request.head`
    /// before calling this method. No network connection is opened and
    /// `:authority` is never interpreted as a proxy destination.
    ///
    /// The callback runs in the actual request region. Return
    /// `socket.finish(&cx).await` after handling messages. Its private receipt
    /// is bound to this stream. The server publishes its verified transport
    /// half-close first, then keeps the request, child tasks, finalizers and
    /// ingress reservation owned until the peer's bounded half-close drain
    /// and final receipt complete. Ordinary HTTP response ordering is unchanged.
    ///
    /// ```ignore
    /// let acceptor = WebSocketAcceptor::new().protocol("chat");
    /// let response = acceptor.accept_http2(request, |cx, mut socket| async move {
    ///     while let Some(message) = socket.recv(&cx).await? {
    ///         if matches!(message, Message::Close(_)) { break; }
    ///         socket.send(&cx, message).await?;
    ///     }
    ///     socket.finish(&cx).await
    /// })?;
    /// ```
    pub fn accept_http2<F, Fut>(
        &self,
        request: StreamingServerRequest,
        handler: F,
    ) -> Result<Http2ProducedResponse, WsAcceptError>
    where
        F: FnOnce(Cx, Http2WebSocket) -> Fut + Send + 'static,
        Fut: Future<Output = Result<Http2WebSocketCompletion, WsError>> + Send + 'static,
    {
        if request.head.version != Version::Http2
            || request.head.method != Method::Connect
            || request.extended_connect_protocol() != Some("websocket")
            || !matches!(request.extended_connect_scheme(), Some("http" | "https"))
            || !request.head.uri.starts_with('/')
            || request.head.uri.contains('#')
        {
            return Err(WsAcceptError::InvalidRequest(
                "a negotiated HTTP/2 websocket extended CONNECT is required".to_owned(),
            ));
        }
        let accept = self.handshake.accept_http2(&request.head.headers)?;
        let mut response = Response::new(200, "OK", Vec::new());
        if let Some(protocol) = &accept.protocol {
            response = response.with_header("sec-websocket-protocol", protocol);
        }
        if !accept.extensions.is_empty() {
            response =
                response.with_header("sec-websocket-extensions", accept.extensions.join(", "));
        }
        let config = self.config.clone();
        let identity = Arc::new(AtomicBool::new(false));
        let StreamingServerRequest { body, .. } = request;
        Ok(Http2ProducedResponse::streaming(
            response,
            NonZeroUsize::new(OUTPUT_FRAME_CAPACITY).expect("positive output capacity"),
            NonZeroUsize::new(OUTPUT_FRAME_BYTES).expect("positive output frame size"),
            move |cx, sender| async move {
                let io = TunnelIo::new(body, sender, cx.clone(), Arc::clone(&identity));
                let mut inner = ServerWebSocket::from_upgraded(io, config, accept, &[]);
                inner.http2_close_authorization = Some(Arc::clone(&identity));
                let socket = Http2WebSocket {
                    inner,
                    identity: Arc::clone(&identity),
                };
                let completion = handler(cx, socket).await.map_err(session_error)?;
                if !Arc::ptr_eq(&identity, &completion.identity) {
                    return Err(HttpError::BodyChannelClosed);
                }
                Ok(completion.sender)
            },
        ))
    }
}

fn cancelled() -> WsError {
    WsError::Io(io::Error::new(
        io::ErrorKind::Interrupted,
        "HTTP/2 WebSocket cancelled",
    ))
}

fn session_error(error: WsError) -> HttpError {
    match error {
        WsError::Io(error) if error.kind() == io::ErrorKind::Interrupted => {
            HttpError::BodyCancelled
        }
        WsError::Io(error) => HttpError::Io(error),
        _ => HttpError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP/2 WebSocket session failed",
        )),
    }
}

type PendingWrite = Pin<Box<dyn Future<Output = (Http2BodySender, Result<(), HttpError>)> + Send>>;

// One inbound DATA cursor and one accepted outbound frame remain owned by
// this request. Returning Ready(n) when accepting a write is essential: a
// dropped write future may later supply a different source buffer, so the
// adapter must never return an earlier write's receipt against that buffer.
struct TunnelIo {
    body: IncomingRequestBody,
    cursor: Option<BytesCursor>,
    incoming_eof: bool,
    owner: Cx,
    close_authorization: Arc<AtomicBool>,
    sender: Option<Http2BodySender>,
    pending: Option<PendingWrite>,
    max_frame_bytes: usize,
    failed: Option<io::ErrorKind>,
    shutdown_started: bool,
    shutdown_complete: bool,
}

impl TunnelIo {
    fn new(
        body: IncomingRequestBody,
        sender: Http2BodySender,
        owner: Cx,
        close_authorization: Arc<AtomicBool>,
    ) -> Self {
        let max_frame_bytes = sender.max_frame_bytes().get();
        Self {
            body,
            cursor: None,
            incoming_eof: false,
            owner,
            close_authorization,
            sender: Some(sender),
            pending: None,
            max_frame_bytes,
            failed: None,
            shutdown_started: false,
            shutdown_complete: false,
        }
    }

    fn check_owner(&self) -> io::Result<()> {
        if self.owner.checkpoint().is_err() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "HTTP/2 WebSocket cancelled",
            ));
        }
        if let Some(kind) = self.failed {
            return Err(io::Error::new(kind, "HTTP/2 WebSocket transport failed"));
        }
        Ok(())
    }

    fn fail(&mut self, kind: io::ErrorKind) -> io::Error {
        self.failed.get_or_insert(kind);
        io::Error::new(kind, "HTTP/2 WebSocket transport failed")
    }

    fn body_error(&mut self, error: IncomingBodyError) -> io::Error {
        let kind = match error {
            IncomingBodyError::Cancelled { .. } => io::ErrorKind::Interrupted,
            IncomingBodyError::ClientAborted | IncomingBodyError::SourceDisconnected => {
                io::ErrorKind::ConnectionReset
            }
            _ => io::ErrorKind::InvalidData,
        };
        self.fail(kind)
    }

    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.check_owner() {
            return Poll::Ready(Err(error));
        }
        let Some(pending) = self.pending.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let (sender, result) = match pending.as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        self.pending = None;
        self.sender = Some(sender);
        match result {
            Ok(()) => Poll::Ready(Ok(())),
            Err(error) => {
                let kind = match error {
                    HttpError::BodyCancelled => io::ErrorKind::Interrupted,
                    HttpError::Io(error) => error.kind(),
                    _ => io::ErrorKind::BrokenPipe,
                };
                Poll::Ready(Err(self.fail(kind)))
            }
        }
    }
}

impl AsyncRead for TunnelIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if let Err(error) = this.check_owner() {
            return Poll::Ready(Err(error));
        }
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // A send dropped in its final flush can leave accepted output here
        // even when ServerWebSocket's own write buffer is empty. Reading must
        // resume that exact owned write. Still poll input when output parks,
        // so independent duplex progress is not serialized behind backpressure.
        if let Poll::Ready(Err(error)) = this.poll_flush_pending(cx) {
            return Poll::Ready(Err(error));
        }
        for _ in 0..DRAIN_FRAMES_PER_POLL {
            if let Some(cursor) = this.cursor.as_mut() {
                let count = cursor.remaining().min(output.remaining());
                output.put_slice(&cursor.chunk()[..count]);
                cursor.advance(count);
                if cursor.remaining() == 0 {
                    this.cursor = None;
                }
                if count != 0 {
                    return Poll::Ready(Ok(()));
                }
            }
            if this.incoming_eof {
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut this.body).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => this.incoming_eof = true,
                Poll::Ready(Some(Ok(Frame::Data(data)))) => this.cursor = Some(data),
                Poll::Ready(Some(Ok(Frame::Trailers(_)))) => {
                    return Poll::Ready(Err(this.fail(io::ErrorKind::InvalidData)));
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(this.body_error(error))),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for TunnelIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if let Err(error) = this.check_owner() {
            return Poll::Ready(Err(error));
        }
        if this.shutdown_started {
            return Poll::Ready(Err(this.fail(io::ErrorKind::BrokenPipe)));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match this.poll_flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        let Some(mut sender) = this.sender.take() else {
            return Poll::Ready(Err(this.fail(io::ErrorKind::BrokenPipe)));
        };
        let accepted = data.len().min(this.max_frame_bytes);
        let bytes = Bytes::copy_from_slice(&data[..accepted]);
        let owner = this.owner.clone();
        this.pending = Some(Box::pin(async move {
            let result = sender.send_bytes(&owner, bytes).await;
            (sender, result)
        }));
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush_pending(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match this.poll_flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        if this.shutdown_complete {
            return Poll::Ready(Ok(()));
        }
        if !this.shutdown_started {
            if !this.close_authorization.load(Ordering::Acquire) {
                return Poll::Ready(Err(this.fail(io::ErrorKind::ConnectionAborted)));
            }
            let Some(sender) = this.sender.as_mut() else {
                return Poll::Ready(Err(this.fail(io::ErrorKind::BrokenPipe)));
            };
            if let Err(error) = sender.finish(&this.owner) {
                let kind = if matches!(error, HttpError::BodyCancelled) {
                    io::ErrorKind::Interrupted
                } else {
                    io::ErrorKind::BrokenPipe
                };
                return Poll::Ready(Err(this.fail(kind)));
            }
            this.shutdown_started = true;
            this.cursor = None;
        }
        // Flushed Close DATA is already readable by the peer. Hold the clean
        // terminal receipt until its half-close arrives. The trusted tunnel
        // driver verifies the sender's explicit byte-bound finish and sends
        // server END_STREAM now, while retaining the request owner. The
        // original CloseDeadline bounds peer drain, including always-ready
        // extra DATA. A final receipt still controls ownership retirement.
        for _ in 0..DRAIN_FRAMES_PER_POLL {
            if this.incoming_eof {
                this.shutdown_complete = true;
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut this.body).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => this.incoming_eof = true,
                Poll::Ready(Some(Ok(Frame::Data(_)))) => {}
                Poll::Ready(Some(Ok(Frame::Trailers(_)))) => {
                    return Poll::Ready(Err(this.fail(io::ErrorKind::InvalidData)));
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(this.body_error(error))),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

#[cfg(test)]
#[path = "http2_tests.rs"]
mod tests;
