//! Demand-driven native HTTP/2 client for unary-input/server-streaming RPCs.
//!
//! This additive API owns one **already connected, dedicated** transport. It
//! reuses the HTTP/2 connection and gRPC message codecs; it does not spawn a
//! reader, fabricate loopback responses, or change `GrpcClient`'s legacy APIs.
//! The transport may be `TcpStream` or a caller-authenticated TLS stream. The
//! caller must verify TLS identity and negotiate `h2` before passing TLS here;
//! setting `scheme = "https"` is not authentication. DNS, connect and TLS time
//! are outside this call's deadline because they precede construction.
//!
//! Polling [`NativeServerStream::message`] supplies receive demand. Dropping
//! that borrowing future preserves partial request writes, frame decoding and
//! message bytes in the stream. Dropping the **stream** closes its dedicated
//! transport; there is no detached work or implicit asynchronous drain. The
//! same is true for [`NativeServerStream::cancel`]. Neither promises RST_STREAM
//! delivery or remote-task quiescence. Use the server's owned drain facilities
//! when remote cleanup must be observed.
//!
//! A slow consumer causes no background reads or WINDOW_UPDATE emission. H2
//! still replenishes credit while a demanded message is being assembled, so
//! messages larger than a window can complete. This is bounded demand-driven
//! prefetch, not a new consumption-credit mode or a multiplexed channel.
//!
//! # Example
//!
//! ```no_run
//! use asupersync::{Cx, bytes::Bytes, net::TcpStream};
//! use asupersync::grpc::{Request, Status, codec::IdentityCodec};
//! use asupersync::grpc::native_stream::{NativeServerStream, NativeStreamConfig};
//!
//! async fn watch(cx: &Cx, io: TcpStream, bearer: &str) -> Result<(), Status> {
//!     let mut request = Request::new(Bytes::from_static(b"\x0a\x03svc"));
//!     if !request.metadata_mut().insert("authorization", format!("Bearer {bearer}")) {
//!         return Err(Status::invalid_argument("invalid authentication metadata"));
//!     }
//!     let mut stream = NativeServerStream::new(
//!         cx, io, "localhost", "/grpc.health.v1.Health/Watch",
//!         request, IdentityCodec, NativeStreamConfig::default(),
//!     )?;
//!     while let Some(protobuf_status) = stream.message().await? {
//!         // Decode or forward the protobuf payload; this example observes it.
//!         assert!(protobuf_status.len() <= 2);
//!     }
//!     Ok(())
//! }
//! ```

use crate::bytes::{Bytes, BytesMut};
use crate::codec::Decoder as _;
use crate::cx::{CancelWakerToken, Cx};
use crate::grpc::client::CompressionEncoding;
use crate::grpc::codec::{Codec, FramedCodec};
use crate::grpc::server::{format_grpc_timeout, parse_grpc_timeout};
use crate::grpc::status::{Code, GrpcError, Status, TransportErrorKind};
use crate::grpc::streaming::{Metadata, MetadataValue, Request, Streaming};
use crate::http::h2::connection::{CLIENT_PREFACE, ReceivedFrame};
use crate::http::h2::{Connection, FrameCodec, Header, Settings};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::{CancelKind, Time};
use base64::Engine as _;
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

mod response;
use response::ResponseHead;

const FRAME_BYTES: usize = 16 * 1024;
const POLL_STEPS: usize = 32;
// Reading while writes are parked is necessary for full-duplex progress, but
// each peer control frame may enqueue a reply. Do not let a non-reading peer
// turn a demanded response into an unbounded SETTINGS/PING acknowledgement queue.
const MAX_UNFLUSHED_READ_FRAMES: usize = 32;

/// Independent bounds and wire policy for one native response stream.
#[derive(Debug, Clone)]
pub struct NativeStreamConfig {
    /// Maximum serialized outbound message, before and after compression.
    pub max_send_message_size: usize,
    /// Maximum inbound message, on the wire and after decompression.
    pub max_recv_message_size: usize,
    /// Per-header-block name/value bytes plus 32 bytes per field (H2 accounting).
    /// Also applied to the complete outbound request header block.
    pub max_metadata_bytes: usize,
    /// Whole-call timeout, tightened by request metadata and the explicit Cx.
    /// `None` allows a long-lived watch unless another deadline applies.
    pub timeout: Option<Duration>,
    /// HTTP pseudo-header scheme; only `http` and `https` are accepted.
    /// The supplied transport, not this label, establishes TLS security.
    pub scheme: &'static str,
    /// Outbound message compression. Unavailable gzip is rejected before I/O.
    pub send_compression: CompressionEncoding,
    /// Advertise and accept gzip responses; requires the `compression` feature.
    pub accept_gzip: bool,
}

impl Default for NativeStreamConfig {
    fn default() -> Self {
        Self {
            max_send_message_size: crate::grpc::DEFAULT_MAX_MESSAGE_SIZE,
            max_recv_message_size: crate::grpc::DEFAULT_MAX_MESSAGE_SIZE,
            max_metadata_bytes: 16 * 1024,
            timeout: None,
            scheme: "http",
            send_compression: CompressionEncoding::Identity,
            accept_gzip: false,
        }
    }
}

/// One typed, cancellation-aware response stream over an owned native transport.
///
/// Initial metadata and terminal trailers are separate. Complete messages are
/// delivered in order, then either `Ok(None)` or one terminal error. Later
/// `message()` calls return `Ok(None)`; inspect [`Self::status`] to retain the
/// exact final error. EOF without terminal gRPC status is never success.
/// Deadlines are observed when this object is polled. They do not start a
/// background task that closes the transport while the object is unpolled.
///
/// Retained DATA is bounded by the receive-message limit plus its five-byte
/// prefix and one H2 frame; undecoded transport bytes are bounded by two H2
/// frames. The outbound request and one encoded H2 frame have their own send
/// limit. H2 header/HPACK state and the configured metadata limit are additional.
/// Values already returned to the application and codec-owned allocations are
/// outside those byte counts. No bound on memory internal to an arbitrary
/// user-supplied codec or transport is implied.
///
/// A parked write or flush does not prevent response reads: an early refusal
/// or a flow-control update can arrive before the whole request is accepted.
/// At most 32 peer frames are processed without flushing queued output. At
/// that limit, read demand parks behind the writer instead of growing control
/// replies without bound. This accounting survives interrupted borrowing waits.
///
/// The object is movable because it never exposes a structurally pinned field;
/// the I/O trait implementation requires the transport to be `Unpin`.
pub struct NativeServerStream<IO, C> {
    io: Option<IO>,
    connection: Option<Connection>,
    frames: FrameCodec,
    codec: FramedCodec<C>,
    cx: Cx,
    cancel_waker: Option<CancelWakerToken>,
    clock: Option<TimerDriverHandle>,
    deadline: Option<Time>,
    timer: Option<Pin<Box<Sleep>>>,
    inbound: BytesMut,
    outbound: BytesMut,
    body: BytesMut,
    response: ResponseHead,
    body_limit: usize,
    stream_id: u32,
    final_status: Option<Status>,
    ready_messages: usize,
    unflushed_read_frames: usize,
}

impl<IO: Unpin, C> Unpin for NativeServerStream<IO, C> {}

impl<IO, C> fmt::Debug for NativeServerStream<IO, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeServerStream")
            .field("stream_id", &self.stream_id)
            .field("buffered_data_bytes", &self.body.len())
            .field("headers_received", &self.response.initial.is_some())
            .field("finished", &self.final_status.is_some())
            .finish_non_exhaustive()
    }
}

impl<IO, C> NativeServerStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: Codec,
{
    /// Construct a call without reading or writing the supplied transport.
    ///
    /// The transport must be fresh: this writes the client connection preface
    /// and owns its only request stream. The request is encoded synchronously
    /// and is never retransmitted after an interrupted borrowing wait. Header
    /// metadata cannot override transport framing or compression fields.
    ///
    /// Request `grpc-timeout`, `config.timeout`, and the explicit Cx deadline
    /// are combined by minimum. Malformed/duplicate request timeouts refuse
    /// before I/O. A deadline requires a timer attached to this Cx; an unrelated
    /// ambient timer cannot supply authority or change its time domain.
    ///
    /// # Errors
    /// Refuses invalid configuration, cancellation, exhausted deadlines,
    /// unsupported compression, invalid metadata, or request encoding failure.
    /// A refusal drops the supplied transport; it does not return it for reuse.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cx: &Cx,
        io: IO,
        authority: &str,
        path: &str,
        request: Request<C::Encode>,
        codec: C,
        config: NativeStreamConfig,
    ) -> Result<Self, Status> {
        // Codec setup/encoding is user code too. Never let a different ambient
        // task silently supply its capabilities during synchronous construction.
        let _ambient = Cx::set_current(Some(cx.clone()));
        check_cancellation(cx)?;
        if !matches!(config.scheme, "http" | "https")
            || config.max_metadata_bytes < 128
            || u32::try_from(config.max_metadata_bytes).is_err()
            || u32::try_from(config.max_send_message_size).is_err()
            || u32::try_from(config.max_recv_message_size).is_err()
        {
            return Err(Status::invalid_argument("invalid native gRPC stream limits or scheme"));
        }
        let body_limit = config.max_recv_message_size.checked_add(5 + FRAME_BYTES)
            .ok_or_else(|| Status::invalid_argument("native receive limit overflows address space"))?;
        if config.max_send_message_size.checked_add(5).is_none() {
            return Err(Status::invalid_argument("native send limit overflows address space"));
        }
        let compressor = match config.send_compression {
            CompressionEncoding::Identity => None,
            CompressionEncoding::Gzip => Some(CompressionEncoding::Gzip.frame_compressor()
                .ok_or_else(|| Status::unimplemented("gzip compression is not compiled in"))?),
        };
        let decompressor = if config.accept_gzip {
            Some(CompressionEncoding::Gzip.frame_decompressor()
                .ok_or_else(|| Status::unimplemented("gzip decompression is not compiled in"))?)
        } else { None };
        let clock = cx.timer_driver();
        let timeout = request_timeout(request.metadata(), config.timeout)?;
        if (timeout.is_some() || cx.budget().deadline.is_some()) && clock.is_none() {
            return Err(Status::failed_precondition("native gRPC deadline requires an explicit timer"));
        }
        let now = clock.as_ref().map(TimerDriverHandle::now);
        let deadline = earlier(cx.budget().deadline, timeout.zip(now).map(|(timeout, now)| now + timeout));
        if deadline.zip(now).is_some_and(|(deadline, now)| now >= deadline) {
            return Err(Status::deadline_exceeded("native gRPC deadline expired before admission"));
        }
        let headers = request_headers(authority, path, request.metadata(), &config, deadline.zip(now))?;
        let mut codec = FramedCodec::with_message_size_limits(
            codec, config.max_send_message_size, config.max_recv_message_size,
        ).with_frame_hooks(compressor, decompressor);
        let mut request_body = BytesMut::new();
        codec.encode_message(&request.into_inner(), &mut request_body)
            .map_err(GrpcError::into_status)?;
        check_cancellation(cx)?;
        let settings = Settings {
            max_header_list_size: u32::try_from(config.max_metadata_bytes)
                .map_err(|_| Status::invalid_argument("metadata limit exceeds H2 representation"))?,
            ..Settings::client()
        };
        let mut connection = Connection::client(settings);
        connection.queue_initial_settings();
        let stream_id = connection.open_stream(headers, false)
            .map_err(|error| Status::invalid_argument(format!("open native gRPC request: {error}")))?;
        connection.send_data(stream_id, request_body.freeze(), true)
            .map_err(|error| Status::internal(format!("queue native gRPC request: {error}")))?;
        let timer = deadline.zip(clock.as_ref()).map(|(at, clock)| {
            Box::pin(Sleep::with_timer_driver(at, clock.clone()))
        });
        Ok(Self {
            io: Some(io), connection: Some(connection), frames: FrameCodec::new(), codec,
            cx: cx.clone(), cancel_waker: None, clock, deadline, timer,
            inbound: BytesMut::new(), outbound: BytesMut::from(CLIENT_PREFACE),
            body: BytesMut::new(), response: ResponseHead::new(config.max_metadata_bytes, config.accept_gzip),
            body_limit, stream_id, final_status: None, ready_messages: 0,
            unflushed_read_frames: 0,
        })
    }

    /// Wait for initial response headers, without consuming a message.
    /// Dropping this borrowing wait preserves all transport progress.
    pub async fn headers(&mut self) -> Result<&Metadata, Status> {
        poll_fn(|task| self.poll_headers(task)).await?;
        self.response.initial.as_ref()
            .ok_or_else(|| Status::internal("native gRPC response lacks initial metadata"))
    }

    /// Read one typed message, or the call's terminal result.
    /// A dropped borrowing wait can be resumed; no background work continues.
    pub async fn message(&mut self) -> Result<Option<C::Decode>, Status> {
        poll_fn(|task| self.poll_message(task)).await.transpose()
    }

    /// Initial metadata once received; distinct from terminal trailers.
    #[must_use]
    pub fn initial_metadata(&self) -> Option<&Metadata> { self.response.initial.as_ref() }

    /// Terminal trailer metadata once received, including for non-OK calls.
    #[must_use]
    pub fn trailers(&self) -> Option<&Metadata> { self.response.trailers.as_ref() }

    /// Exact terminal result after the stream has finished or been cancelled.
    /// `Some(OK)` is only recorded after the required terminal status is read.
    #[must_use]
    pub fn status(&self) -> Option<&Status> { self.final_status.as_ref() }

    /// Current retained application DATA bytes, not allocator capacity or HPACK.
    #[must_use]
    pub fn buffered_data_bytes(&self) -> usize { self.body.len() }

    /// Close the dedicated transport immediately. No asynchronous write occurs.
    /// A final result already observed is preserved; otherwise records CANCELLED.
    pub fn cancel(&mut self) {
        if self.final_status.is_none() {
            self.finish(Status::cancelled("native gRPC stream cancelled by its owner"));
        }
    }

    fn gate(&mut self, task: &mut Context<'_>) -> Result<(), Status> {
        check_cancellation(&self.cx)?;
        self.cancel_waker = Some(self.cx.refresh_cancel_waker(self.cancel_waker, task.waker()));
        check_cancellation(&self.cx)?;
        if self.deadline.zip(self.clock.as_ref())
            .is_some_and(|(at, clock)| clock.now() >= at)
            || self.timer.as_mut().is_some_and(|timer| timer.as_mut().poll(task).is_ready())
        {
            return Err(Status::deadline_exceeded("native gRPC stream deadline exceeded"));
        }
        Ok(())
    }

    fn poll_headers(&mut self, task: &mut Context<'_>) -> Poll<Result<(), Status>> {
        let _ambient = Cx::set_current(Some(self.cx.clone()));
        if let Some(status) = &self.final_status {
            return Poll::Ready(if status.code() == Code::Ok { Ok(()) } else { Err(status.clone()) });
        }
        for _ in 0..POLL_STEPS {
            if let Err(error) = self.gate(task) { return Poll::Ready(Err(self.finish(error))); }
            if self.response.initial.is_some() { return Poll::Ready(Ok(())); }
            match self.poll_received(task) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(self.finish(error))),
                Poll::Pending => return Poll::Pending,
            }
        }
        task.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_message(&mut self, task: &mut Context<'_>) -> Poll<Option<Result<C::Decode, Status>>> {
        let _ambient = Cx::set_current(Some(self.cx.clone()));
        if self.final_status.is_some() { return Poll::Ready(None); }
        if self.ready_messages == POLL_STEPS {
            self.ready_messages = 0;
            task.waker().wake_by_ref();
            return Poll::Pending;
        }
        for _ in 0..POLL_STEPS {
            if let Err(error) = self.gate(task) {
                return Poll::Ready(Some(Err(self.finish(error))));
            }
            if self.response.initial.is_some() {
                match self.codec.decode_message_with_encoding(&mut self.body, self.response.encoding.as_deref()) {
                    Ok(Some(value)) => {
                        // User codecs can do synchronous work. Do not publish
                        // a late value after that work exhausts the deadline.
                        if let Err(error) = self.gate(task) {
                            return Poll::Ready(Some(Err(self.finish(error))));
                        }
                        self.ready_messages += 1;
                        return Poll::Ready(Some(Ok(value)));
                    }
                    Ok(None) => {}
                    Err(error) => return Poll::Ready(Some(Err(self.finish(error.into_status())))),
                }
            }
            if self.response.ended {
                let status = if self.body.is_empty() {
                    self.response.terminal.take().unwrap_or_else(|| Status::internal("missing gRPC terminal status"))
                } else {
                    Status::internal("truncated gRPC message before stream termination")
                };
                let ok = status.code() == Code::Ok;
                let status = self.finish(status);
                return Poll::Ready(if ok { None } else { Some(Err(status)) });
            }
            match self.poll_received(task) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Some(Err(self.finish(error)))),
                Poll::Pending => return Poll::Pending,
            }
        }
        task.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_received(&mut self, task: &mut Context<'_>) -> Poll<Result<(), Status>> {
        // Keep attempting writes first, but never require a socket/TLS write
        // to finish before looking for the peer's response. Both peers may be
        // waiting for the other direction to drain. The write cursor remains
        // in `outbound`, including across a dropped headers()/message() wait.
        match self.poll_outbound(task) {
            Poll::Ready(Ok(())) => self.unflushed_read_frames = 0,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending if self.unflushed_read_frames >= MAX_UNFLUSHED_READ_FRAMES => {
                // poll_outbound registered the write/flush waker (or requested
                // a cooperative continuation). Do not self-wake a parked writer.
                return Poll::Pending;
            }
            Poll::Pending => {}
        }
        for _ in 0..POLL_STEPS {
            match self.frames.decode(&mut self.inbound) {
                Ok(Some(frame)) => {
                    self.unflushed_read_frames += 1;
                    let received = self.connection.as_mut().expect("live connection")
                        .process_frame(frame)
                        .map_err(|error| Status::internal(format!("invalid HTTP/2 response: {error}")));
                    return Poll::Ready(received.and_then(|frame| self.observe(frame)));
                }
                Ok(None) => {}
                Err(error) => return Poll::Ready(Err(Status::internal(format!("decode HTTP/2 response: {error}")))),
            }
            let mut bytes = [0_u8; FRAME_BYTES];
            let mut read = ReadBuf::new(&mut bytes);
            match Pin::new(self.io.as_mut().expect("live transport")).poll_read(task, &mut read) {
                Poll::Ready(Ok(())) => {
                    if read.filled().is_empty() {
                        return Poll::Ready(Err(Status::unavailable("HTTP/2 EOF before terminal gRPC status")));
                    }
                    if self.inbound.len().saturating_add(read.filled().len()) > 2 * FRAME_BYTES {
                        return Poll::Ready(Err(Status::resource_exhausted("native HTTP/2 input buffer bound exceeded")));
                    }
                    self.inbound.extend_from_slice(read.filled());
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(self.transport_status(error))),
                Poll::Pending => return Poll::Pending,
            }
        }
        task.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_outbound(&mut self, task: &mut Context<'_>) -> Poll<Result<(), Status>> {
        for _ in 0..POLL_STEPS {
            if self.outbound.is_empty() {
                match self.connection.as_mut().expect("live connection").next_frame() {
                    Some(frame) => {
                        if let Err(error) = frame.encode(&mut self.outbound) {
                            return Poll::Ready(Err(Status::internal(format!("encode HTTP/2 request: {error}"))));
                        }
                    }
                    None => {
                        return match Pin::new(self.io.as_mut().expect("live transport")).poll_flush(task) {
                            Poll::Ready(result) => Poll::Ready(result.map_err(|error| self.transport_status(error))),
                            Poll::Pending => Poll::Pending,
                        };
                    }
                }
            }
            match Pin::new(self.io.as_mut().expect("live transport")).poll_write(task, &self.outbound) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(Status::unavailable("zero progress writing HTTP/2 request"))),
                Poll::Ready(Ok(written)) if written > self.outbound.len() => {
                    return Poll::Ready(Err(Status::internal("transport overreported HTTP/2 write progress")));
                }
                Poll::Ready(Ok(written)) => self.outbound.advance(written),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(self.transport_status(error))),
                Poll::Pending => return Poll::Pending,
            }
        }
        task.waker().wake_by_ref();
        Poll::Pending
    }

    fn observe(&mut self, frame: Option<ReceivedFrame>) -> Result<(), Status> {
        match frame {
            Some(ReceivedFrame::Headers { stream_id, headers, end_stream }) if stream_id == self.stream_id => {
                self.response.headers(headers, end_stream)
            }
            Some(ReceivedFrame::Data { stream_id, data, end_stream }) if stream_id == self.stream_id => {
                self.response.data(end_stream)?;
                if self.body.len().saturating_add(data.len()) > self.body_limit {
                    return Err(Status::resource_exhausted("gRPC DATA retention bound exceeded"));
                }
                self.body.extend_from_slice(&data);
                Ok(())
            }
            Some(ReceivedFrame::Reset { stream_id, error_code }) if stream_id == self.stream_id => {
                Err(Status::from_h2_rst_stream_code(error_code))
            }
            Some(ReceivedFrame::GoAway { last_stream_id, error_code, .. })
                if last_stream_id < self.stream_id || error_code != crate::http::h2::ErrorCode::NoError => {
                Err(Status::unavailable("HTTP/2 GOAWAY refused the active gRPC stream"))
            }
            _ => Ok(()),
        }
    }

    fn transport_status(&self, error: std::io::Error) -> Status {
        check_cancellation(&self.cx).err().unwrap_or_else(|| io_status(error))
    }

    fn finish(&mut self, status: Status) -> Status {
        self.final_status = Some(status.clone());
        if let Some(token) = self.cancel_waker.take() { self.cx.clear_cancel_waker(token); }
        self.timer = None;
        self.io = None;
        self.connection = None;
        self.inbound = BytesMut::new();
        self.outbound = BytesMut::new();
        self.body = BytesMut::new();
        self.unflushed_read_frames = 0;
        status
    }
}

impl<IO, C> Drop for NativeServerStream<IO, C> {
    fn drop(&mut self) {
        if let Some(token) = self.cancel_waker.take() { self.cx.clear_cancel_waker(token); }
    }
}

impl<IO, C> Streaming for NativeServerStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    C: Codec,
{
    type Message = C::Decode;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<C::Decode, Status>>> {
        self.get_mut().poll_message(cx)
    }
}

fn earlier(first: Option<Time>, second: Option<Time>) -> Option<Time> {
    match (first, second) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    }
}

fn check_cancellation(cx: &Cx) -> Result<(), Status> {
    cx.checkpoint().map_err(|_| match cx.cancel_reason().map(|reason| reason.kind) {
        Some(CancelKind::Deadline | CancelKind::Timeout) => Status::deadline_exceeded("native gRPC caller deadline elapsed"),
        Some(CancelKind::PollQuota | CancelKind::CostBudget) => Status::resource_exhausted("native gRPC caller budget exhausted"),
        _ => Status::cancelled("native gRPC caller cancelled"),
    })
}

fn io_status(error: std::io::Error) -> Status {
    GrpcError::transport_kind(TransportErrorKind::from_io_error_kind(error.kind()),
        format!("native gRPC transport: {error}")).into_status()
}

fn request_timeout(metadata: &Metadata, configured: Option<Duration>) -> Result<Option<Duration>, Status> {
    let mut peer = None;
    for (_, value) in metadata.iter().filter(|(key, _)| *key == "grpc-timeout") {
        if peer.is_some() { return Err(Status::invalid_argument("duplicate grpc-timeout")); }
        let MetadataValue::Ascii(value) = value else { return Err(Status::invalid_argument("binary grpc-timeout")); };
        peer = Some(parse_grpc_timeout(value).ok_or_else(|| Status::invalid_argument("malformed grpc-timeout"))?);
    }
    Ok(match (configured, peer) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    })
}

fn request_headers(
    authority: &str, path: &str, metadata: &Metadata, config: &NativeStreamConfig,
    deadline: Option<(Time, Time)>,
) -> Result<Vec<Header>, Status> {
    let valid_path = path.strip_prefix('/').and_then(|path| path.split_once('/'))
        .is_some_and(|(service, method)| !service.is_empty() && !method.is_empty() && !method.contains('/'));
    if authority.len() > config.max_metadata_bytes || path.len() > config.max_metadata_bytes {
        return Err(Status::resource_exhausted("outbound gRPC route exceeds metadata bound"));
    }
    if !valid_path || path.bytes().any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'?' | b'#' | b'\\'))
        || authority.is_empty() || authority.bytes().any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'/' | b'\\' | b'?' | b'#' | b'@'))
    {
        return Err(Status::invalid_argument("invalid native gRPC authority or method path"));
    }
    let mut headers = vec![
        Header::new(":method", "POST"), Header::new(":scheme", config.scheme),
        Header::new(":authority", authority), Header::new(":path", path),
        Header::new("content-type", "application/grpc"), Header::new("te", "trailers"),
    ];
    if config.send_compression == CompressionEncoding::Gzip { headers.push(Header::new("grpc-encoding", "gzip")); }
    headers.push(Header::new("grpc-accept-encoding", if config.accept_gzip { "identity,gzip" } else { "identity" }));
    if let Some((at, now)) = deadline {
        headers.push(Header::new("grpc-timeout", format_grpc_timeout(Duration::from_nanos(at.duration_since(now)))));
    }
    let mut used = headers.iter().try_fold(0usize, |sum, header| {
        sum.checked_add(header.name.len())?.checked_add(header.value.len())?.checked_add(32)
    }).ok_or_else(|| Status::resource_exhausted("outbound metadata size overflow"))?;
    if used > config.max_metadata_bytes {
        return Err(Status::resource_exhausted("outbound gRPC metadata exceeds its byte limit"));
    }
    for (key, value) in metadata.iter() {
        if key == "grpc-timeout" { continue; }
        if key.starts_with(':') || matches!(key,
            "content-type" | "content-length" | "te" | "host" | "connection" | "keep-alive"
            | "proxy-connection" | "transfer-encoding" | "upgrade" | "grpc-status" | "grpc-message"
            | "grpc-status-details-bin" | "grpc-encoding" | "grpc-accept-encoding")
        {
            return Err(Status::invalid_argument("outbound metadata overrides a transport field"));
        }
        // Account for expansion before cloning/encoding user metadata.
        let value_len = match value {
            MetadataValue::Ascii(value) => Some(value.len()),
            MetadataValue::Binary(value) => (value.len() / 3).checked_mul(4)
                .and_then(|len| len.checked_add(match value.len() % 3 { 0 => 0, 1 => 2, _ => 3 })),
        };
        used = value_len.and_then(|len| used.checked_add(len))
            .and_then(|len| len.checked_add(key.len()))
            .and_then(|len| len.checked_add(32))
            .ok_or_else(|| Status::resource_exhausted("outbound metadata size overflow"))?;
        if used > config.max_metadata_bytes {
            return Err(Status::resource_exhausted("outbound gRPC metadata exceeds its byte limit"));
        }
        let value = match value {
            MetadataValue::Ascii(value) => value.clone(),
            MetadataValue::Binary(value) => base64::engine::general_purpose::STANDARD_NO_PAD.encode(value),
        };
        headers.push(Header::new(key, value));
    }
    Ok(headers)
}

#[cfg(test)]
mod tests;
