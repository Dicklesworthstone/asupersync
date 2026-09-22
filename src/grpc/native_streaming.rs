//! Pull-driven native gRPC response streams on explicitly supplied connections.
//!
//! This additive lane leaves `GrpcClient::server_streaming` and its loopback
//! behavior unchanged. It owns one fresh connection per call, not a multiplexed
//! channel or a background reader. The caller authenticates a supplied TLS
//! transport and negotiates h2 before handing it to `server_streaming_on`.

use super::client::{Channel, ChannelConfig, CompressionEncoding};
use super::codec::{Codec, FramedCodec};
use super::server::{format_grpc_timeout, parse_grpc_timeout};
use super::status::{Code, GrpcError, Status, TransportErrorKind};
use super::streaming::{Metadata, MetadataValue, Request, Streaming};
use crate::bytes::{Bytes, BytesMut};
use crate::codec::Decoder as _;
use crate::cx::Cx;
use crate::http::h2::connection::{CLIENT_PREFACE, ReceivedFrame};
use crate::http::h2::{Connection, ErrorCode, FrameCodec, Header, Settings};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::{CancelKind, Time};
use base64::Engine as _;
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

const FRAME_BYTES: usize = 16 * 1024;
const METADATA_BYTES: usize = 64 * 1024;
const POLL_STEPS: usize = 16;
const BLOCKED_WRITE_EVENTS: usize = 32;

/// A single native server-streaming call and its owned transport.
///
/// `message()` returns each decoded message without collecting the response.
/// Initial and trailing metadata remain separate. Remote errors follow already
/// delivered complete messages; missing status, truncated framing and malformed
/// metadata never become successful EOF. A terminal error is returned once,
/// followed by `Ok(None)`. `terminal_status()` retains the final classification.
///
/// A dropped borrowing `message()` future retains all partial reads and writes
/// in this owner. Dropping the owner closes its dedicated connection; it does
/// not cancel the parent Cx or promise an asynchronously transmitted RST_STREAM.
/// No task is spawned. Cancellation/deadlines are observed on the next poll;
/// a caller holding an unpolled stream still owns its resources.
///
/// Reads stop between consumer polls. Existing H2 window replenishment occurs
/// as frames are processed, not as a separate per-message release-capacity API.
/// Retention is bounded by one message plus an inbound frame/read fragment,
/// bounded metadata and H2 control state, and the bounded unary request. Socket,
/// TLS and application codec allocations have their own independent bounds.
/// This is bounded read-ahead, not exact zero-prefetch byte-credit admission.
pub struct NativeServerStream<IO, C: Codec> {
    io: Option<Pin<Box<IO>>>,
    connection: Connection,
    frames: FrameCodec,
    inbound: BytesMut,
    outbound: BytesMut,
    written: usize,
    body: BytesMut,
    codec: Box<FramedCodec<C>>,
    response: ResponseState,
    stream_id: u32,
    owner: Cx,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    clock: TimerDriverHandle,
    deadline: Option<Time>,
    timer: Option<Sleep>,
    header_deadline: Time,
    header_timer: Option<Sleep>,
    ended: bool,
    terminal: Option<Status>,
    unflushed_events: usize,
    max_buffer: usize,
}

impl<IO, C: Codec> fmt::Debug for NativeServerStream<IO, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeServerStream")
            .field("stream_id", &self.stream_id)
            .field("buffered_body_bytes", &self.body.len())
            .field("ended", &self.ended)
            .field("terminal_code", &self.terminal.as_ref().map(Status::code))
            .finish_non_exhaustive()
    }
}

impl Channel {
    /// Start a server-streaming call on a fresh, caller-owned HTTP/2 transport.
    ///
    /// The connection must not already contain an H2 preface or other streams.
    /// URI authority is used for the request, not to authenticate `transport`.
    /// For HTTPS the caller MUST supply an already authenticated TLS connection
    /// with h2 ALPN. No DNS, TLS setup or ambient networking authority is created
    /// by this method. It installs the supplied Cx for every transport poll.
    ///
    /// Returns after final response headers, before collecting messages. Call
    /// `message()` until `None` to verify the mandatory terminal gRPC status.
    /// The channel timeout, request timeout and caller deadline are met once;
    /// connect_timeout bounds this lane's initial-header wait, not the lifetime
    /// of an otherwise unbounded stream. Metadata is supplied directly: this
    /// Channel API does not run a GrpcClient's separately registered interceptors.
    /// Keepalive configuration is rejected rather than silently ignored; this
    /// lane does not provide a background heartbeat or connection pool.
    ///
    /// # Errors
    /// Rejects invalid configuration, paths, reserved metadata and unavailable
    /// compression before I/O. Refuses an absent explicit timer driver. Setup
    /// errors close the supplied connection without changing its parent's Cx.
    pub async fn server_streaming_on<IO, C>(
        &self,
        cx: &Cx,
        transport: IO,
        path: &str,
        request: Request<C::Encode>,
        codec: C,
    ) -> Result<NativeServerStream<IO, C>, Status>
    where
        IO: AsyncRead + AsyncWrite + Send + 'static,
        C: Codec,
    {
        let mut stream = NativeServerStream::prepare(cx, transport, self, path, request, codec)?;
        poll_fn(|task| stream.poll_headers(task)).await?;
        Ok(stream)
    }
}

impl<IO, C> NativeServerStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Send + 'static,
    C: Codec,
{
    fn prepare(
        cx: &Cx,
        transport: IO,
        channel: &Channel,
        path: &str,
        request: Request<C::Encode>,
        codec: C,
    ) -> Result<Self, Status> {
        let _ambient = Cx::set_current(Some(cx.clone()));
        caller_status(cx)?;
        let config = channel.config();
        validate_config(config)?;
        validate_path(path)?;
        let (scheme, authority) = authority(channel.uri())?;
        let scheme = if config.use_tls { "https" } else { scheme };
        let clock = cx.timer_driver().ok_or_else(|| {
            Status::failed_precondition("native gRPC streaming requires an explicit timer driver")
        })?;
        let now = clock.now();
        let deadline = call_deadline(cx, request.metadata(), config, now)?;
        if deadline.is_some_and(|at| now >= at) {
            return Err(Status::deadline_exceeded("gRPC call expired before dispatch"));
        }
        let (mut codec, accepted) = configured_codec(codec, config)?;
        let mut body = BytesMut::new();
        codec.encode_message(request.get_ref(), &mut body).map_err(GrpcError::into_status)?;
        // Encoding is synchronous user code and can consume the remaining time.
        caller_status(cx)?;
        if deadline.is_some_and(|at| clock.now() >= at) {
            return Err(Status::deadline_exceeded("gRPC call expired during encoding"));
        }
        let headers = request_headers(
            scheme, authority, path, request.metadata(), config, deadline, clock.now(),
        )?;
        let mut settings = Settings::client();
        settings.initial_window_size = config.initial_stream_window_size;
        settings.max_header_list_size = METADATA_BYTES as u32;
        settings.max_concurrent_streams = 1;
        let mut connection = Connection::client(settings);
        connection.queue_initial_settings();
        connection.set_initial_connection_recv_window(config.initial_connection_window_size)
            .map_err(|_| Status::invalid_argument("invalid gRPC connection receive window"))?;
        let stream_id = connection.open_stream(headers, false)
            .map_err(|_| Status::internal("cannot open gRPC response stream"))?;
        connection.send_data(stream_id, body.freeze(), true)
            .map_err(|_| Status::internal("cannot queue gRPC request"))?;
        let owner = cx.clone();
        let cancel_owner = owner.clone();
        let header_deadline = now + config.connect_timeout;
        let max_buffer = config.max_recv_message_size.checked_add(5 + FRAME_BYTES)
            .ok_or_else(|| Status::invalid_argument("gRPC receive limit overflows"))?;
        owner.trace("grpc.client_stream.request_queued");
        Ok(Self {
            io: Some(Box::pin(transport)),
            connection,
            frames: FrameCodec::new(),
            inbound: BytesMut::new(),
            outbound: BytesMut::from(&CLIENT_PREFACE[..]),
            written: 0,
            body: BytesMut::new(),
            codec: Box::new(codec),
            response: ResponseState::new(accepted),
            stream_id,
            owner,
            cancelled: Box::pin(async move { let _ = cancel_owner.cancelled().await; }),
            timer: deadline.map(|at| Sleep::with_timer_driver(at, clock.clone())),
            header_timer: Some(Sleep::with_timer_driver(header_deadline, clock.clone())),
            header_deadline,
            clock,
            deadline,
            ended: false,
            terminal: None,
            unflushed_events: 0,
            max_buffer,
        })
    }

    /// Initial response metadata, separate from the eventual trailers.
    #[must_use]
    pub fn initial_metadata(&self) -> &Metadata { &self.response.initial }

    /// Trailers after their HEADERS block was received. An error or early EOF
    /// can terminate without a trailer block; absence is not an OK status.
    #[must_use]
    pub fn trailing_metadata(&self) -> Option<&Metadata> {
        self.response.trailers_received.then_some(&self.response.trailers)
    }

    /// Final observed status, including local cancellation or protocol failure.
    /// `None` means the caller has not yet collected a terminal observation.
    #[must_use]
    pub fn terminal_status(&self) -> Option<&Status> { self.terminal.as_ref() }

    /// Receive one message. Dropping this borrowing wait preserves transport
    /// progress; the next call resumes instead of replaying request bytes.
    pub async fn message(&mut self) -> Result<Option<C::Decode>, Status> {
        match poll_fn(|task| Pin::new(&mut *self).poll_next(task)).await {
            Some(result) => result.map(Some),
            None => Ok(None),
        }
    }

    /// Immediately retire this dedicated transport. No parent is cancelled.
    /// The terminal classification is retained and further reads return None.
    pub fn cancel(&mut self) {
        if !self.ended {
            self.retire(Status::cancelled("gRPC stream cancelled by its consumer"));
        }
    }

    fn retire(&mut self, status: Status) {
        if self.ended { return; }
        self.ended = true;
        self.owner.trace(&format!("grpc.client_stream.terminal code={:?}", status.code()));
        self.terminal = Some(status);
        drop(self.io.take());
        self.inbound = BytesMut::new();
        self.outbound = BytesMut::new();
        self.body = BytesMut::new();
        self.timer = None;
        self.header_timer = None;
        // Retire queued request bytes and all stream/control state now, rather
        // than retaining them until the caller drops an already-finished owner.
        self.connection = Connection::client(Settings::client());
        self.cancelled = Box::pin(std::future::ready(()));
    }

    fn check_stop(&mut self, task: &mut Context<'_>) -> Result<(), Status> {
        caller_status(&self.owner)?;
        if self.cancelled.as_mut().poll(task).is_ready() {
            return Err(cancel_status(&self.owner));
        }
        if self.deadline.is_some_and(|at| self.clock.now() >= at)
            || self.timer.as_mut().is_some_and(|timer| Pin::new(timer).poll(task).is_ready())
        {
            return Err(Status::deadline_exceeded("gRPC stream deadline exceeded"));
        }
        if !self.response.headers_received
            && (self.clock.now() >= self.header_deadline
                || self.header_timer.as_mut().is_some_and(|timer| Pin::new(timer).poll(task).is_ready()))
        {
            return Err(Status::deadline_exceeded("gRPC response headers timed out"));
        }
        Ok(())
    }

    fn poll_headers(&mut self, task: &mut Context<'_>) -> Poll<Result<(), Status>> {
        let _ambient = Cx::set_current(Some(self.owner.clone()));
        let result = self.poll_progress(task, true);
        if let Poll::Ready(Err(status)) = &result {
            self.retire(status.clone());
        }
        result
    }

    // Every byte not yet accepted by AsyncWrite remains in `outbound` across
    // Pending. Connection::next_frame may return None for flow-blocked DATA:
    // that is the signal to read WINDOW_UPDATE, not end the RPC.
    fn poll_writes(&mut self, task: &mut Context<'_>) -> Poll<Result<(), Status>> {
        for _ in 0..POLL_STEPS {
            let io = self.io.as_mut().expect("live transport");
            if self.written < self.outbound.len() {
                let remaining = &self.outbound[self.written..];
                match io.as_mut().poll_write(task, remaining) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(io_status(error))),
                    Poll::Ready(Ok(n)) if n == 0 || n > remaining.len() => {
                        return Poll::Ready(Err(Status::unavailable("invalid transport write progress")));
                    }
                    Poll::Ready(Ok(n)) => self.written += n,
                }
                continue;
            }
            self.outbound.clear();
            self.written = 0;
            if let Some(frame) = self.connection.next_frame() {
                frame.encode(&mut self.outbound)
                    .map_err(|_| Status::internal("cannot encode outbound HTTP/2 frame"))?;
            } else {
                return io.as_mut().poll_flush(task).map(|result| result.map_err(io_status));
            }
        }
        task.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_progress(&mut self, task: &mut Context<'_>, headers_only: bool) -> Poll<Result<(), Status>> {
        for _ in 0..POLL_STEPS {
            self.check_stop(task)?;
            if headers_only && self.response.headers_received {
                return Poll::Ready(Ok(()));
            }
            // Let the caller decode before reading further frames. Incomplete
            // envelopes return here only after new DATA, avoiding a busy loop.
            let writes_pending = match self.poll_writes(task) {
                Poll::Ready(Ok(())) => { self.unflushed_events = 0; false }
                Poll::Ready(Err(status)) => return Poll::Ready(Err(status)),
                Poll::Pending => true,
            };
            // Allow bounded full-duplex progress, but do not let a peer flood
            // PING/SETTINGS replies into Connection while never reading ours.
            if writes_pending && self.unflushed_events >= BLOCKED_WRITE_EVENTS {
                return Poll::Pending;
            }
            if let Some(frame) = self.frames.decode(&mut self.inbound)
                .map_err(|_| Status::internal("invalid HTTP/2 response frame"))?
            {
                self.unflushed_events += 1;
                if let Some(event) = self.connection.process_frame(frame)
                    .map_err(|_| Status::internal("invalid HTTP/2 response state"))?
                {
                    self.observe(event)?;
                    if self.response.headers_received && (headers_only || !self.body.is_empty() || self.response.ended) {
                        return Poll::Ready(Ok(()));
                    }
                }
                continue;
            }
            let mut chunk = [0_u8; 8192];
            let mut read = ReadBuf::new(&mut chunk);
            match self.io.as_mut().expect("live transport").as_mut().poll_read(task, &mut read) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(io_status(error))),
                Poll::Ready(Ok(())) if read.filled().is_empty() => {
                    return Poll::Ready(Err(Status::unavailable("HTTP/2 EOF before gRPC terminal status")));
                }
                Poll::Ready(Ok(())) => self.inbound.extend_from_slice(read.filled()),
            }
        }
        task.waker().wake_by_ref();
        Poll::Pending
    }

    fn observe(&mut self, event: ReceivedFrame) -> Result<(), Status> {
        match event {
            ReceivedFrame::Headers { stream_id, headers, end_stream } if stream_id == self.stream_id => {
                self.response.headers(headers, end_stream)?;
                if self.response.headers_received { self.header_timer = None; }
                Ok(())
            }
            ReceivedFrame::Data { stream_id, data, end_stream } if stream_id == self.stream_id => {
                if !self.response.headers_received || self.response.ended {
                    return Err(Status::internal("gRPC DATA outside response body"));
                }
                if self.body.len().saturating_add(data.len()) > self.max_buffer {
                    return Err(Status::resource_exhausted("gRPC response buffer limit exceeded"));
                }
                self.body.extend_from_slice(&data);
                self.response.ended = end_stream;
                Ok(())
            }
            ReceivedFrame::Reset { stream_id, error_code } if stream_id == self.stream_id => {
                Err(Status::from_h2_rst_stream_code(error_code))
            }
            ReceivedFrame::GoAway { last_stream_id, error_code, .. }
                if last_stream_id < self.stream_id || error_code != ErrorCode::NoError => {
                    Err(Status::unavailable("HTTP/2 GOAWAY rejected this gRPC call"))
                }
            _ => Ok(()),
        }
    }
}

impl<IO, C> Streaming for NativeServerStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Send + 'static,
    C: Codec,
{
    type Message = C::Decode;

    fn poll_next(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<Result<C::Decode, Status>>> {
        let this = self.get_mut();
        if this.ended { return Poll::Ready(None); }
        let _ambient = Cx::set_current(Some(this.owner.clone()));
        for _ in 0..POLL_STEPS {
            let result = (|| {
                this.check_stop(task)?;
                match this.codec.decode_message_with_encoding(&mut this.body, this.response.encoding.as_deref())
                    .map_err(GrpcError::into_status)?
                {
                    Some(message) => return Ok(Some(message)),
                    None if this.response.ended => {
                        if !this.body.is_empty() { return Err(Status::internal("truncated terminal gRPC message")); }
                        let status = this.response.status.clone()
                            .ok_or_else(|| Status::internal("gRPC response omitted terminal grpc-status"))?;
                        this.retire(status.clone());
                        if status.code() != Code::Ok { return Err(status); }
                    }
                    None => {}
                }
                Ok(None)
            })();
            match result {
                Err(status) => {
                    this.retire(status.clone());
                    return Poll::Ready(Some(Err(status)));
                }
                Ok(Some(message)) => return Poll::Ready(Some(Ok(message))),
                Ok(None) if this.ended => return Poll::Ready(None),
                Ok(None) => {}
            }
            match this.poll_progress(task, false) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(status)) => {
                    this.retire(status.clone());
                    return Poll::Ready(Some(Err(status)));
                }
                Poll::Ready(Ok(())) => {}
            }
        }
        task.waker().wake_by_ref();
        Poll::Pending
    }
}

struct ResponseState {
    headers_received: bool,
    trailers_received: bool,
    initial: Metadata,
    trailers: Metadata,
    encoding: Option<String>,
    accepted: Vec<CompressionEncoding>,
    status: Option<Status>,
    ended: bool,
    informational: usize,
}

impl ResponseState {
    fn new(accepted: Vec<CompressionEncoding>) -> Self {
        Self {
            headers_received: false, trailers_received: false,
            initial: Metadata::new(), trailers: Metadata::new(), encoding: None,
            accepted, status: None, ended: false, informational: 0,
        }
    }

    fn headers(&mut self, headers: Vec<Header>, end_stream: bool) -> Result<(), Status> {
        if self.ended { return Err(Status::internal("headers after gRPC completion")); }
        let mut size = 0usize;
        for header in &headers {
            size = size.checked_add(header.name.len()).and_then(|n| n.checked_add(header.value.len()))
                .and_then(|n| n.checked_add(32))
                .ok_or_else(|| Status::resource_exhausted("gRPC metadata length overflow"))?;
        }
        if size > METADATA_BYTES { return Err(Status::resource_exhausted("gRPC metadata limit exceeded")); }
        let initial = !self.headers_received;
        if initial {
            let status = unique(&headers, ":status")?.ok_or_else(|| Status::internal("missing HTTP status"))?;
            let code = status.parse::<u16>().map_err(|_| Status::internal("malformed HTTP status"))?;
            if (100..200).contains(&code) && code != 101 {
                self.informational += 1;
                if end_stream || self.informational > 8 || headers.iter().any(|h| h.name.starts_with("grpc-")) {
                    return Err(Status::internal("invalid informational gRPC response"));
                }
                return Ok(());
            }
            if code != 200 { return Err(http_status(code)); }
            let content = unique(&headers, "content-type")?.unwrap_or("");
            let media = content.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
            if media != "application/grpc" && !media.strip_prefix("application/grpc+").is_some_and(|suffix| !suffix.is_empty()) {
                return Err(Status::internal("response is not native gRPC"));
            }
            if let Some(encoding) = unique(&headers, "grpc-encoding")? {
                let selected = CompressionEncoding::from_header_value(encoding)
                    .ok_or_else(|| Status::unimplemented("unsupported gRPC response compression"))?;
                if selected != CompressionEncoding::Identity && !self.accepted.contains(&selected) {
                    return Err(Status::unimplemented("unnegotiated gRPC response compression"));
                }
                self.encoding = Some(encoding.to_owned());
            }
            self.headers_received = true;
        } else if !end_stream || headers.iter().any(|h| h.name.starts_with(':') || h.name == "content-type" || h.name == "grpc-encoding") {
            return Err(Status::internal("invalid gRPC trailing header block"));
        }
        let code = unique(&headers, "grpc-status")?;
        let message = unique(&headers, "grpc-message")?;
        let details = unique(&headers, "grpc-status-details-bin")?;
        if !end_stream && (code.is_some() || message.is_some() || details.is_some()) {
            return Err(Status::internal("gRPC status before END_STREAM"));
        }
        if end_stream {
            let raw = code.ok_or_else(|| Status::internal("gRPC trailers omitted grpc-status"))?;
            if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Status::internal("malformed grpc-status"));
            }
            let code = raw.parse::<i32>().ok().and_then(Code::from_i32)
                .ok_or_else(|| Status::internal("unknown grpc-status"))?;
            let message = message.map(super::status::percent_decode_grpc_message).transpose()?.unwrap_or_default();
            self.status = Some(match details {
                Some(details) => Status::with_details(code, message, decode_binary(details)?),
                None => Status::new(code, message),
            });
            self.trailers_received = true;
            self.ended = true;
        }
        let metadata = if end_stream { &mut self.trailers } else { &mut self.initial };
        let mut retained = 0usize;
        for header in headers {
            if header.name.starts_with(':') || matches!(header.name.as_str(), "content-type" | "grpc-encoding" | "grpc-status" | "grpc-message" | "grpc-status-details-bin") {
                continue;
            }
            if header.name.ends_with("-bin") {
                for value in header.value.split(',') {
                    // Joined binary values become separate owned entries.
                    // Charge the repeated name and entry overhead before
                    // cloning it, not just the compressed wire field once.
                    charge_metadata(&mut retained, &header.name, value)?;
                    if !metadata.insert_bin(header.name.clone(), decode_binary(value.trim())?) {
                        return Err(Status::internal("invalid binary gRPC metadata key"));
                    }
                }
            } else {
                charge_metadata(&mut retained, &header.name, &header.value)?;
                if !metadata.insert(header.name, header.value) {
                    return Err(Status::internal("invalid ASCII gRPC metadata"));
                }
            }
        }
        Ok(())
    }
}

fn unique<'a>(headers: &'a [Header], name: &str) -> Result<Option<&'a str>, Status> {
    let mut values = headers.iter().filter(|h| h.name == name);
    let value = values.next().map(|h| h.value.as_str());
    if values.next().is_some() { return Err(Status::internal("duplicate gRPC transport header")); }
    Ok(value)
}

fn charge_metadata(total: &mut usize, name: &str, value: &str) -> Result<(), Status> {
    *total = total.checked_add(name.len()).and_then(|n| n.checked_add(value.len()))
        .and_then(|n| n.checked_add(32)).filter(|n| *n <= METADATA_BYTES)
        .ok_or_else(|| Status::resource_exhausted("expanded gRPC metadata limit exceeded"))?;
    Ok(())
}

fn decode_binary(value: &str) -> Result<Bytes, Status> {
    base64::engine::general_purpose::STANDARD.decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value))
        .map(Bytes::from).map_err(|_| Status::internal("malformed binary gRPC metadata"))
}

fn http_status(code: u16) -> Status {
    let mapped = match code {
        401 => Code::Unauthenticated,
        403 => Code::PermissionDenied,
        404 => Code::Unimplemented,
        429 | 502 | 503 | 504 => Code::Unavailable,
        400 => Code::Internal,
        _ => Code::Unknown,
    };
    Status::new(mapped, "non-200 HTTP response to gRPC call")
}

fn caller_status(cx: &Cx) -> Result<(), Status> {
    cx.checkpoint().map_err(|_| cancel_status(cx))
}

fn cancel_status(cx: &Cx) -> Status {
    match cx.cancel_reason().map(|reason| reason.kind) {
        Some(CancelKind::Timeout | CancelKind::Deadline) => Status::deadline_exceeded("gRPC caller deadline exceeded"),
        Some(CancelKind::PollQuota | CancelKind::CostBudget) => Status::resource_exhausted("gRPC caller budget exhausted"),
        _ => Status::cancelled("gRPC caller cancelled"),
    }
}

fn io_status(error: std::io::Error) -> Status {
    GrpcError::transport_kind(TransportErrorKind::from_io_error_kind(error.kind()), "gRPC stream transport failed").into_status()
}

fn validate_config(config: &ChannelConfig) -> Result<(), Status> {
    if config.keepalive_interval.is_some() || config.keepalive_timeout.is_some() {
        return Err(Status::unimplemented("native gRPC stream keepalive is not configured by this lane"));
    }
    if config.connect_timeout.is_zero() || config.initial_stream_window_size == 0
        || config.initial_stream_window_size > 0x7fff_ffff
        || !(65_535..=0x7fff_ffff).contains(&config.initial_connection_window_size)
        || config.max_recv_message_size.checked_add(5 + FRAME_BYTES).is_none()
    {
        return Err(Status::invalid_argument("invalid native gRPC streaming limits"));
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), Status> {
    let mut parts = path.strip_prefix('/').unwrap_or("").split('/');
    let valid = matches!((parts.next(), parts.next(), parts.next()), (Some(s), Some(m), None) if !s.is_empty() && !m.is_empty());
    if !valid || path.len() > 4096 || !path.bytes().all(|b| b.is_ascii_graphic() && !matches!(b, b'?' | b'#')) {
        return Err(Status::invalid_argument("invalid gRPC method path"));
    }
    Ok(())
}

fn authority(uri: &str) -> Result<(&str, &str), Status> {
    let (scheme, rest) = uri.split_once("://").ok_or_else(|| Status::invalid_argument("invalid gRPC URI"))?;
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if !matches!(scheme, "http" | "https") || authority.is_empty() || authority.len() > 4096
        || !authority.bytes().all(|b| b.is_ascii_graphic() && !matches!(b, b'/' | b'?' | b'#' | b'@'))
    {
        return Err(Status::invalid_argument("invalid native gRPC authority"));
    }
    Ok((scheme, authority))
}

fn call_deadline(cx: &Cx, metadata: &Metadata, config: &ChannelConfig, now: Time) -> Result<Option<Time>, Status> {
    let mut timeouts = metadata.iter().filter(|(key, _)| *key == "grpc-timeout");
    let timeout = timeouts.next();
    if timeouts.next().is_some() { return Err(Status::invalid_argument("duplicate grpc-timeout")); }
    let requested = match timeout {
        Some((_, MetadataValue::Ascii(value))) => Some(parse_grpc_timeout(value)
            .ok_or_else(|| Status::invalid_argument("malformed grpc-timeout"))?),
        Some(_) => return Err(Status::invalid_argument("binary grpc-timeout")),
        None => None,
    };
    let mut deadline = cx.budget().deadline;
    for timeout in [config.timeout, requested].into_iter().flatten() {
        let at = now + timeout;
        deadline = Some(deadline.map_or(at, |old| old.min(at)));
    }
    Ok(deadline)
}

fn configured_codec<C: Codec>(codec: C, config: &ChannelConfig) -> Result<(FramedCodec<C>, Vec<CompressionEncoding>), Status> {
    let compressor = match config.send_compression {
        None | Some(CompressionEncoding::Identity) => None,
        Some(encoding) => Some(encoding.frame_compressor()
            .ok_or_else(|| Status::unimplemented("configured gRPC compression is unavailable"))?),
    };
    let mut accepted = vec![CompressionEncoding::Identity];
    for encoding in &config.accept_compression {
        if *encoding != CompressionEncoding::Identity && encoding.frame_decompressor().is_none() {
            return Err(Status::unimplemented("configured gRPC decompression is unavailable"));
        }
        if !accepted.contains(encoding) { accepted.push(*encoding); }
    }
    let decompressor = accepted.iter().find_map(|encoding| encoding.frame_decompressor());
    Ok((FramedCodec::with_message_size_limits(codec, config.max_send_message_size, config.max_recv_message_size)
        .with_frame_hooks(compressor, decompressor), accepted))
}

fn request_headers(
    scheme: &str, authority: &str, path: &str, metadata: &Metadata,
    config: &ChannelConfig, deadline: Option<Time>, now: Time,
) -> Result<Vec<Header>, Status> {
    let mut headers = vec![
        Header::new(":method", "POST"), Header::new(":scheme", scheme),
        Header::new(":authority", authority), Header::new(":path", path),
        Header::new("content-type", "application/grpc"), Header::new("te", "trailers"),
    ];
    if let Some(at) = deadline {
        if now >= at { return Err(Status::deadline_exceeded("gRPC deadline expired before headers")); }
        headers.push(Header::new("grpc-timeout", format_grpc_timeout(Duration::from_nanos(at.duration_since(now)))));
    }
    if matches!(config.send_compression, Some(CompressionEncoding::Gzip)) {
        headers.push(Header::new("grpc-encoding", "gzip"));
    }
    headers.push(Header::new("grpc-accept-encoding", if config.accept_compression.contains(&CompressionEncoding::Gzip) { "identity,gzip" } else { "identity" }));
    let mut bytes = headers.iter().map(|h| h.name.len() + h.value.len()).sum::<usize>();
    for (name, value) in metadata.iter() {
        if name == "grpc-timeout" { continue; }
        if name.starts_with(':') || name.starts_with("grpc-") || matches!(name,
            "content-type" | "content-length" | "te" | "host" | "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade")
        {
            return Err(Status::invalid_argument("transport-reserved gRPC request metadata"));
        }
        // Charge conservative base64 expansion before allocating its String.
        let length = match value {
            MetadataValue::Ascii(value) => value.len(),
            MetadataValue::Binary(value) => value.len().checked_add(2).and_then(|n| n.checked_div(3)).and_then(|n| n.checked_mul(4))
                .ok_or_else(|| Status::resource_exhausted("request metadata length overflow"))?,
        };
        bytes = bytes.checked_add(name.len()).and_then(|n| n.checked_add(length))
            .filter(|n| *n <= METADATA_BYTES).ok_or_else(|| Status::resource_exhausted("request metadata limit exceeded"))?;
        let value = match value {
            MetadataValue::Ascii(value) => value.clone(),
            MetadataValue::Binary(value) => base64::engine::general_purpose::STANDARD_NO_PAD.encode(value),
        };
        headers.push(Header::new(name, value));
    }
    Ok(headers)
}

#[cfg(test)]
mod tests;
