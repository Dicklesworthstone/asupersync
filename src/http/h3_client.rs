//! One bounded HTTP exchange on an owned authenticated native QUIC connection.

use std::fmt;
use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::bytes::Bytes;
use crate::cx::Cx;
use crate::io::AsyncWrite;
use crate::net::quic_native::{
    ConnectionRouterError, ManagedEndpointConfig, ManagedEndpointError, NativeQuicConnectionError,
    NativeQuicUdpConnection, QuicConnection, StreamId, StreamRole,
};

use super::h3_native::{
    H3RequestHead, H3ResponseHead, H3Settings, validate_request_head_with_settings,
    validate_response_head,
};
use super::h3_quic::{
    H3_REQUEST_CANCELLED, NativeH3Event, NativeH3RequestWriter, NativeH3Session,
    NativeH3SessionError,
};

const IO_CHUNK_BYTES: usize = 16 * 1024;
const POLL_STEPS: usize = 32;
const MAX_CLIENT_FIELD_SECTION_SIZE: usize = 64 * 1024;

/// Memory and time bounds for one owned native HTTP/3 exchange.
///
/// Field sizes use the HTTP/3 field-section accounting rule: the UTF-8 byte
/// lengths of each name and value, plus 32 bytes per field. Pseudo fields count
/// too. The response header budget covers all informational heads, the final
/// head, and trailers together. Body limits count decoded HTTP DATA payloads;
/// this adapter does not decompress content encodings.
#[derive(Debug, Clone)]
pub struct NativeH3ClientConfig {
    /// Maximum buffered request payload. Zero allows only empty bodies.
    pub max_request_body_bytes: usize,
    /// Maximum total response payload, buffered or streamed to a sink.
    /// Zero allows only empty bodies.
    pub max_response_body_bytes: usize,
    /// Maximum individual request, response, or trailer field section.
    /// Must be nonzero and at most 64 KiB.
    pub max_field_section_size: usize,
    /// Maximum total decoded response fields, including informational heads.
    pub max_response_header_bytes: usize,
    /// Maximum retained informational responses, from zero through 64.
    pub max_informational_responses: usize,
    /// Deadline measured from the first poll of `execute` or `execute_to`,
    /// including sink backpressure, flush and cleanup.
    /// Must be nonzero. An already completed response survives cleanup errors
    /// or expiry of this deadline.
    pub timeout: Duration,
}

impl Default for NativeH3ClientConfig {
    fn default() -> Self {
        Self {
            max_request_body_bytes: 16 * 1024 * 1024,
            max_response_body_bytes: 16 * 1024 * 1024,
            max_field_section_size: 64 * 1024,
            max_response_header_bytes: 256 * 1024,
            max_informational_responses: 8,
            timeout: Duration::from_secs(30),
        }
    }
}

impl NativeH3ClientConfig {
    fn validate(&self) -> Result<(), NativeH3ClientError> {
        if self.timeout.is_zero() {
            return Err(NativeH3ClientError::InvalidConfig(
                "timeout must be nonzero",
            ));
        }
        if self.max_field_section_size == 0
            || self.max_field_section_size > MAX_CLIENT_FIELD_SECTION_SIZE
        {
            return Err(NativeH3ClientError::InvalidConfig(
                "field section limit must be between one byte and 64 KiB",
            ));
        }
        if self.max_response_header_bytes < 42 {
            return Err(NativeH3ClientError::InvalidConfig(
                "response header budget must accommodate :status",
            ));
        }
        if self.max_informational_responses > 64 {
            return Err(NativeH3ClientError::InvalidConfig(
                "informational response limit exceeds 64",
            ));
        }
        if self.max_request_body_bytes > isize::MAX as usize
            || self.max_response_body_bytes > isize::MAX as usize
        {
            return Err(NativeH3ClientError::InvalidConfig(
                "body limits exceed the platform allocation bound",
            ));
        }
        Ok(())
    }
}

/// A complete response, returned only after its stream FIN and length checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeH3ClientResponse {
    /// Final response head, with status at least 200.
    pub head: H3ResponseHead,
    /// Collected DATA payload, bounded by the configured response body limit.
    pub body: Bytes,
    /// Ordinary trailing fields; these never replace the final head.
    pub trailers: Vec<(String, String)>,
    /// Informational heads in wire order. Status 101 is invalid in HTTP/3.
    pub informational: Vec<H3ResponseHead>,
}

/// Validated response metadata after all DATA reached and flushed the sink.
///
/// Unlike [`NativeH3ClientResponse`], this value does not retain the response
/// body. Its byte count covers the complete response, including across chunks
/// and partial sink writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeH3ClientResponseSummary {
    /// Final response head, with status at least 200.
    pub head: H3ResponseHead,
    /// Total DATA bytes successfully written to the supplied sink.
    pub body_bytes: usize,
    /// Ordinary trailing fields; these never replace the final head.
    pub trailers: Vec<(String, String)>,
    /// Informational heads in wire order.
    pub informational: Vec<H3ResponseHead>,
}

/// Admission, transport, or HTTP message failure in an owned exchange.
#[derive(Debug)]
#[non_exhaustive]
pub enum NativeH3ClientError {
    /// Invalid local resource limits.
    InvalidConfig(&'static str),
    /// Connection role, negotiated protocol, or stream ownership is unsuitable.
    Admission(&'static str),
    /// This bounded request/response adapter does not implement a tunnel.
    UnsupportedRequest(&'static str),
    /// Invalid HTTP message ordering or field semantics.
    InvalidMessage(&'static str),
    /// A configured memory or informational response bound was reached.
    LimitExceeded {
        /// Resource whose bound was exceeded.
        resource: &'static str,
        /// Configured maximum.
        limit: usize,
    },
    /// Actual message content disagreed with Content-Length.
    ContentLengthMismatch {
        /// Declared number of content bytes.
        expected: u64,
        /// Number of actual content bytes.
        actual: usize,
    },
    /// The request was not accepted before the peer's GOAWAY boundary.
    Goaway {
        /// First request stream the peer refuses.
        first_rejected_stream: u64,
    },
    /// The response stream was reset, including local message rejection.
    StreamReset {
        /// HTTP/3 or peer application error code.
        error_code: u64,
        /// Peer-declared final stream size.
        final_size: u64,
    },
    /// Native HTTP/3 framing or stream failure.
    Session(NativeH3SessionError),
    /// Owned UDP driver or connection-routing failure.
    Transport(ManagedEndpointError),
    /// The response sink failed to write or flush accepted DATA.
    Sink(io::Error),
    /// The owning task was cancelled before response completion.
    Cancelled,
    /// The response and, for `execute_to`, its sink flush did not complete
    /// before the configured deadline.
    TimedOut,
}

impl fmt::Display for NativeH3ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(f, "invalid HTTP/3 client config: {message}"),
            Self::Admission(message) => write!(f, "HTTP/3 connection refused: {message}"),
            Self::UnsupportedRequest(message) => write!(f, "unsupported HTTP/3 request: {message}"),
            Self::InvalidMessage(message) => write!(f, "invalid HTTP/3 message: {message}"),
            Self::LimitExceeded { resource, limit } => {
                write!(f, "HTTP/3 {resource} exceeds limit {limit}")
            }
            Self::ContentLengthMismatch { expected, actual } => {
                write!(
                    f,
                    "HTTP/3 content-length is {expected}, but received {actual} bytes"
                )
            }
            Self::Goaway {
                first_rejected_stream,
            } => {
                write!(
                    f,
                    "HTTP/3 GOAWAY refuses streams from {first_rejected_stream}"
                )
            }
            Self::StreamReset {
                error_code,
                final_size,
            } => {
                write!(
                    f,
                    "HTTP/3 response reset with code {error_code}, final size {final_size}"
                )
            }
            Self::Session(error) => error.fmt(f),
            Self::Transport(error) => error.fmt(f),
            Self::Sink(error) => write!(f, "HTTP/3 response sink failed: {error}"),
            Self::Cancelled => f.write_str("HTTP/3 exchange cancelled"),
            Self::TimedOut => f.write_str("HTTP/3 exchange timed out before response completion"),
        }
    }
}

impl std::error::Error for NativeH3ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Session(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::Sink(error) => Some(error),
            _ => None,
        }
    }
}

impl From<NativeH3SessionError> for NativeH3ClientError {
    fn from(error: NativeH3SessionError) -> Self {
        match error {
            NativeH3SessionError::Transport(NativeQuicConnectionError::Cancelled) => {
                Self::Cancelled
            }
            other => Self::Session(other),
        }
    }
}

impl From<ManagedEndpointError> for NativeH3ClientError {
    fn from(error: ManagedEndpointError) -> Self {
        if matches!(
            error,
            ManagedEndpointError::Cancelled
                | ManagedEndpointError::ConnectionRouter(ConnectionRouterError::Cancelled)
        ) {
            Self::Cancelled
        } else {
            Self::Transport(error)
        }
    }
}

/// One ordinary HTTP/3 exchange owning its authenticated QUIC socket.
///
/// Construct a [`NativeQuicUdpConnection`] with the desired TLS trust roots,
/// server name and required ALPN `h3`, then transfer that fresh client owner
/// here. The constructor verifies the negotiated ALPN and client role; it
/// never substitutes a synthetic connection or bypasses TLS verification.
///
/// [`Self::execute`] consumes the connection. It drives upload, response reads,
/// ACKs, flow control and recovery together through the native managed event
/// loop. There is no detached I/O task. Dropping the client or its execution
/// future releases the owned socket, routes and retained application bytes.
/// A complete early response can finish before the upload does; peer
/// STOP_SENDING retires only the upload and leaves response reads active.
///
/// This adapter buffers one bounded response or writes it incrementally through
/// [`Self::execute_to`]. It does not pool, reconnect,
/// retry, follow redirects, multiplex, or implement CONNECT tunnels. Use
/// [`NativeH3Session`] with an explicitly owned transport for streaming uploads
/// or multi-request compositions. Existing streams must not be shared with
/// this consuming adapter.
/// The session uses static QPACK, a 1 MiB maximum wire-frame payload, and
/// 16 KiB receive chunks; response collection remains bounded independently.
#[derive(Debug)]
pub struct NativeH3Client {
    connection: NativeQuicUdpConnection,
    config: NativeH3ClientConfig,
}

impl NativeH3Client {
    /// Take ownership of an authenticated, fresh `h3` client connection.
    ///
    /// Refusal drops the supplied owner; no socket or background task remains.
    pub fn new(
        connection: NativeQuicUdpConnection,
        config: NativeH3ClientConfig,
    ) -> Result<Self, NativeH3ClientError> {
        config.validate()?;
        if connection.connection().role() != StreamRole::Client {
            return Err(NativeH3ClientError::Admission(
                "a client connection is required",
            ));
        }
        if connection.negotiated_alpn() != b"h3" {
            return Err(NativeH3ClientError::Admission("negotiated ALPN must be h3"));
        }
        if !connection.connection().can_send_app_data() {
            return Err(NativeH3ClientError::Admission(
                "authenticated application keys are required",
            ));
        }
        if !connection.connection().inner().streams().is_empty() {
            return Err(NativeH3ClientError::Admission(
                "the connection already owns application streams",
            ));
        }
        Ok(Self { connection, config })
    }

    /// Send one bounded request and collect a complete response.
    ///
    /// Request fields and Content-Length are checked before opening a stream.
    /// An absent Content-Length is valid: the final request FIN delimits its
    /// known body. Response success requires final HEADERS, permitted DATA and
    /// trailers, correct Content-Length, and response FIN. A response head
    /// alone never counts as success, even for a bodyless response.
    ///
    /// On success, endpoint shutdown is attempted within the remaining total
    /// deadline. Cleanup failure or late cancellation cannot replace that
    /// already completed response. On failure or drop, transport ownership is
    /// retired locally; network delivery of cancellation is not guaranteed.
    pub async fn execute(
        self,
        cx: &Cx,
        head: H3RequestHead,
        body: Bytes,
    ) -> Result<NativeH3ClientResponse, NativeH3ClientError> {
        let mut collected = Vec::new();
        let summary = self.execute_to(cx, head, body, &mut collected).await?;
        Ok(NativeH3ClientResponse {
            head: summary.head,
            body: Bytes::from(collected),
            trailers: summary.trailers,
            informational: summary.informational,
        })
    }

    /// Send one bounded request and download its response into an async sink.
    ///
    /// The same protocol validation, total body limit and deadline as
    /// [`Self::execute`] apply. The client retains at most one accepted DATA
    /// chunk while the sink is pending, in addition to the bounded QUIC and
    /// HTTP/3 parser buffers. It does not collect the complete response body.
    /// Each chunk is validated before any of its bytes reach the sink; body
    /// limits and Content-Length count bytes across the entire response.
    ///
    /// Sink backpressure pauses further response consumption while packet
    /// handling, recovery timers and request upload continue. Success requires
    /// response FIN, exact Content-Length when applicable, all accepted DATA
    /// written, and a successful sink flush within the total deadline. The
    /// borrowed sink is never shut down. Endpoint cleanup after that completed
    /// result cannot revoke it.
    ///
    /// Errors, cancellation or a dropped future can leave a valid response
    /// prefix in the sink. These writes cannot be rolled back; callers needing
    /// atomic publication should write into their own staging destination and
    /// publish it only after this method succeeds.
    pub async fn execute_to<W: AsyncWrite + Unpin + ?Sized>(
        self,
        cx: &Cx,
        head: H3RequestHead,
        body: Bytes,
        sink: &mut W,
    ) -> Result<NativeH3ClientResponseSummary, NativeH3ClientError> {
        let started = cx.now();
        cx.checkpoint()
            .map_err(|_| NativeH3ClientError::Cancelled)?;
        validate_request(&head, &body, &self.config)?;
        let Self { connection, config } = self;
        let connection_id = connection.local_connection_id();
        let mut endpoint = connection
            .into_managed(
                cx,
                ManagedEndpointConfig {
                    max_connections: 1,
                    ..ManagedEndpointConfig::default()
                },
            )
            .map_err(|error| NativeH3ClientError::from(error.into_parts().0))?;
        let mut exchange = endpoint.with_connection_mut(cx, connection_id, |connection| {
            Exchange::new(cx, connection, &head, body, config.clone())
        })??;
        let operation = crate::time::timeout(
            started,
            config.timeout,
            endpoint.run_event_loop_with_application(cx, |cx, endpoint, task| {
                // Once FIN was validated, only the borrowed destination can
                // remain pending. A normal peer close may retire the QUIC
                // route during that flush; it cannot invalidate the response.
                if let Some(completed) = exchange.poll_completed(cx, task, sink) {
                    return completed.map(Ok);
                }
                match endpoint.with_connection_mut(cx, connection_id, |connection| {
                    exchange.poll(cx, connection, task, sink)
                }) {
                    Ok(poll) => poll.map(Ok),
                    Err(error) => Poll::Ready(Err(error)),
                }
            }),
        );
        let deadline = operation.deadline();
        let response = poll_with_context(cx, operation)
            .await
            .map_err(|_| NativeH3ClientError::TimedOut)???;
        // Completion is already established. Shutdown retains its own cleanup
        // guard across awaits; neither cancellation nor a deadline can revoke
        // this result or leave a detached transport behind.
        let _ =
            poll_with_context(cx, crate::time::timeout_at(deadline, endpoint.shutdown(cx))).await;
        Ok(response)
    }
}

/// The timeout and driver must see the same explicit caller clock. A future
/// can be polled outside that caller's ambient task; install its context only
/// for each poll, never across a suspension or on a detached task.
async fn poll_with_context<F: Future>(cx: &Cx, future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|task| {
        let _current = Cx::set_current(Some(cx.clone()));
        future.as_mut().poll(task)
    })
    .await
}

fn validate_request(
    head: &H3RequestHead,
    body: &Bytes,
    config: &NativeH3ClientConfig,
) -> Result<(), NativeH3ClientError> {
    if head.pseudo.method.as_deref() == Some("CONNECT") {
        return Err(NativeH3ClientError::UnsupportedRequest(
            "CONNECT needs a duplex session owner",
        ));
    }
    validate_request_head_with_settings(head, false).map_err(NativeH3SessionError::from)?;
    let mut size = fields_size(&head.headers)?;
    for (name, value) in [
        (":method", head.pseudo.method.as_deref()),
        (":scheme", head.pseudo.scheme.as_deref()),
        (":authority", head.pseudo.authority.as_deref()),
        (":path", head.pseudo.path.as_deref()),
    ] {
        if let Some(value) = value {
            size = add_field_size(size, name, value)?;
        }
    }
    check_limit(size, config.max_field_section_size, "request fields")?;
    check_limit(body.len(), config.max_request_body_bytes, "request body")?;
    if let Some(expected) = content_length(&head.headers)? {
        check_length(expected, body.len())?;
    }
    Ok(())
}

struct Exchange {
    session: NativeH3Session,
    writer: NativeH3RequestWriter,
    body: Bytes,
    offset: usize,
    upload_stopped: bool,
    response: ResponseCollector,
    pending_data: Bytes,
    completed: Option<NativeH3ClientResponseSummary>,
}

impl Exchange {
    fn new(
        cx: &Cx,
        connection: &mut QuicConnection,
        head: &H3RequestHead,
        body: Bytes,
        config: NativeH3ClientConfig,
    ) -> Result<Self, NativeH3ClientError> {
        let mut session = NativeH3Session::client();
        session
            .enable_streaming_receive(NonZeroUsize::new(IO_CHUNK_BYTES).expect("nonzero chunk"))?;
        session.initialize(
            cx,
            connection,
            H3Settings {
                max_field_section_size: Some(config.max_field_section_size as u64),
                ..H3Settings::default()
            },
        )?;
        let writer = session.start_request_writer(cx, connection, head, body.is_empty())?;
        let response = ResponseCollector::new(
            writer.stream_id(),
            head.pseudo.method.as_deref() == Some("HEAD"),
            config,
        );
        Ok(Self {
            session,
            writer,
            body,
            offset: 0,
            upload_stopped: false,
            response,
            pending_data: Bytes::new(),
            completed: None,
        })
    }

    fn poll<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        task: &mut Context<'_>,
        sink: &mut W,
    ) -> Poll<Result<NativeH3ClientResponseSummary, NativeH3ClientError>> {
        if let Some(completed) = self.poll_completed(cx, task, sink) {
            return completed;
        }
        if cx.checkpoint().is_err() {
            return Poll::Ready(Err(NativeH3ClientError::Cancelled));
        }
        // Read before writing so a reset or an early final response can retire
        // pending upload work. Both halves get a bounded turn on every poll.
        for step in 0..POLL_STEPS {
            if !self.pending_data.is_empty() {
                match poll_sink_write(sink, &mut self.pending_data, task) {
                    // Do not read another response chunk, but let the upload
                    // advance below. A full-duplex peer can require request
                    // progress before the consumer can accept its response.
                    Poll::Pending => break,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {}
                }
            } else {
                let event = match self.session.poll_event(cx, connection, task) {
                    Poll::Pending => break,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Ready(Ok(event)) => event,
                };
                match self.response.accept(event) {
                    Err(error) => return Poll::Ready(Err(error)),
                    Ok(ResponseProgress::Finished(response)) => {
                        // FIN retires only the upload, even if flushing the
                        // sink now parks. Retain the validated metadata so a
                        // resumed flush never consumes FIN twice.
                        if !self.upload_stopped && !self.writer.is_finished() {
                            let _ = self.stop_upload_after_response(cx, connection);
                        }
                        self.completed = Some(response);
                        // A ready sink flush establishes success in this poll,
                        // preserving execute's existing terminal semantics.
                        // A pending flush remains cancellable on the next poll.
                        return self.poll_sink_flush(task, sink);
                    }
                    Ok(ResponseProgress::Data(bytes)) => self.pending_data = bytes,
                    Ok(ResponseProgress::Continue) => {}
                }
            }
            if cx.checkpoint().is_err() {
                return Poll::Ready(Err(NativeH3ClientError::Cancelled));
            }
            if step + 1 == POLL_STEPS {
                // Only self-wake after actual bounded application progress.
                task.waker().wake_by_ref();
            }
        }
        if !self.upload_stopped && !self.writer.is_finished() {
            match self.writer.retire_stopped_upload(connection) {
                Ok(true) => {
                    self.upload_stopped = true;
                    self.body = Bytes::new();
                }
                Ok(false) => {}
                Err(error) => return Poll::Ready(Err(error.into())),
            }
        }
        if self.upload_stopped || self.writer.is_finished() {
            self.body = Bytes::new();
            return Poll::Pending;
        }
        for step in 0..POLL_STEPS {
            match self.writer.poll_flush(cx, connection, task) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Ready(Ok(_)) => {}
            }
            if self.writer.is_finished() {
                self.body = Bytes::new();
                return Poll::Pending;
            }
            let queued = if self.offset < self.body.len() {
                let count = (self.body.len() - self.offset)
                    .min(IO_CHUNK_BYTES)
                    .min(self.writer.max_frame_payload_size());
                let end = self.offset + count;
                let result = self.writer.queue_data(self.body.slice(self.offset..end));
                self.offset = end;
                result
            } else {
                self.writer.finish()
            };
            if let Err(error) = queued {
                return Poll::Ready(Err(error.into()));
            }
            if step + 1 == POLL_STEPS {
                task.waker().wake_by_ref();
            }
        }
        Poll::Pending
    }

    fn poll_completed<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        cx: &Cx,
        task: &mut Context<'_>,
        sink: &mut W,
    ) -> Option<Poll<Result<NativeH3ClientResponseSummary, NativeH3ClientError>>> {
        self.completed.as_ref()?;
        Some(if cx.checkpoint().is_err() {
            Poll::Ready(Err(NativeH3ClientError::Cancelled))
        } else {
            self.poll_sink_flush(task, sink)
        })
    }

    fn poll_sink_flush<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        task: &mut Context<'_>,
        sink: &mut W,
    ) -> Poll<Result<NativeH3ClientResponseSummary, NativeH3ClientError>> {
        for _ in 0..POLL_STEPS {
            match Pin::new(&mut *sink).poll_flush(task) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {}
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(NativeH3ClientError::Sink(error)));
                }
                Poll::Ready(Ok(())) => {
                    return Poll::Ready(Ok(self.completed.take().expect("validated response")));
                }
            }
        }
        task.waker().wake_by_ref();
        Poll::Pending
    }

    fn stop_upload_after_response(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
    ) -> Result<(), NativeH3ClientError> {
        if !self.writer.retire_stopped_upload(connection)? {
            // Preserve a peer's existing STOP_SENDING error code. Otherwise
            // explicitly reset only our upload after the validated response FIN.
            cx.masked(|| {
                connection.reset_stream(cx, self.writer.stream_id(), H3_REQUEST_CANCELLED)
            })
            .map_err(NativeH3SessionError::from)?;
            if !self.writer.retire_stopped_upload(connection)? {
                return Err(NativeH3ClientError::InvalidMessage(
                    "upload reset was not retained",
                ));
            }
        }
        self.upload_stopped = true;
        self.body = Bytes::new();
        Ok(())
    }
}

/// Attempt one sink write, retaining its exact unwritten suffix. The enclosing
/// exchange bounds repeated Interrupted or short writes and supplies its own
/// application waker, so a sink can park without losing transport progress.
fn poll_sink_write<W: AsyncWrite + Unpin + ?Sized>(
    sink: &mut W,
    pending: &mut Bytes,
    task: &mut Context<'_>,
) -> Poll<Result<(), NativeH3ClientError>> {
    if pending.is_empty() {
        return Poll::Ready(Ok(()));
    }
    match Pin::new(sink).poll_write(task, pending) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {
            Poll::Ready(Ok(()))
        }
        Poll::Ready(Err(error)) => Poll::Ready(Err(NativeH3ClientError::Sink(error))),
        Poll::Ready(Ok(0)) => Poll::Ready(Err(NativeH3ClientError::Sink(io::Error::new(
            io::ErrorKind::WriteZero,
            "response sink accepted no bytes from nonempty DATA",
        )))),
        Poll::Ready(Ok(count)) if count > pending.len() => {
            Poll::Ready(Err(NativeH3ClientError::Sink(io::Error::new(
                io::ErrorKind::InvalidData,
                "response sink reported more bytes than supplied",
            ))))
        }
        Poll::Ready(Ok(count)) => {
            *pending = pending.slice(count..);
            Poll::Ready(Ok(()))
        }
    }
}

enum ResponseProgress {
    Continue,
    Data(Bytes),
    Finished(NativeH3ClientResponseSummary),
}

struct ResponseCollector {
    stream_id: StreamId,
    is_head: bool,
    config: NativeH3ClientConfig,
    head: Option<H3ResponseHead>,
    informational: Vec<H3ResponseHead>,
    trailers: Vec<(String, String)>,
    saw_trailers: bool,
    header_bytes: usize,
    body_bytes: usize,
    content_length: Option<u64>,
    body_forbidden: bool,
}

impl ResponseCollector {
    fn new(stream_id: StreamId, is_head: bool, config: NativeH3ClientConfig) -> Self {
        Self {
            stream_id,
            is_head,
            config,
            head: None,
            informational: Vec::new(),
            trailers: Vec::new(),
            saw_trailers: false,
            header_bytes: 0,
            body_bytes: 0,
            content_length: None,
            body_forbidden: false,
        }
    }

    fn account_fields(
        &mut self,
        fields: &[(String, String)],
        status: bool,
    ) -> Result<(), NativeH3ClientError> {
        let size = fields_size(fields)?;
        let size = if status {
            add_field_size(size, ":status", "200")?
        } else {
            size
        };
        check_limit(
            size,
            self.config.max_field_section_size,
            "response field section",
        )?;
        self.header_bytes =
            self.header_bytes
                .checked_add(size)
                .ok_or(NativeH3ClientError::InvalidMessage(
                    "response field size overflow",
                ))?;
        check_limit(
            self.header_bytes,
            self.config.max_response_header_bytes,
            "response fields",
        )
    }

    fn accept(&mut self, event: NativeH3Event) -> Result<ResponseProgress, NativeH3ClientError> {
        match event {
            NativeH3Event::ResponseHeaders { stream_id, head } => {
                self.check_stream(stream_id)?;
                validate_response_head(&head).map_err(NativeH3SessionError::from)?;
                if self.head.is_some() {
                    return Err(NativeH3ClientError::InvalidMessage(
                        "duplicate final response head",
                    ));
                }
                self.account_fields(&head.headers, true)?;
                let length = content_length(&head.headers)?;
                if head.status < 200 {
                    if head.status == 101 || length.is_some() {
                        return Err(NativeH3ClientError::InvalidMessage(
                            "invalid informational response",
                        ));
                    }
                    check_limit(
                        self.informational.len() + 1,
                        self.config.max_informational_responses,
                        "informational responses",
                    )?;
                    self.informational.push(head);
                } else {
                    if head.status == 204 && length.is_some() {
                        return Err(NativeH3ClientError::InvalidMessage(
                            "204 forbids content-length",
                        ));
                    }
                    if head.status == 205 && length.is_some_and(|value| value != 0) {
                        return Err(NativeH3ClientError::InvalidMessage(
                            "205 cannot declare response content",
                        ));
                    }
                    self.body_forbidden = self.is_head || matches!(head.status, 204 | 205 | 304);
                    if !self.body_forbidden
                        && length
                            .is_some_and(|value| value > self.config.max_response_body_bytes as u64)
                    {
                        return Err(NativeH3ClientError::LimitExceeded {
                            resource: "response body",
                            limit: self.config.max_response_body_bytes,
                        });
                    }
                    self.content_length = length;
                    self.head = Some(head);
                }
            }
            NativeH3Event::Data { stream_id, bytes } => {
                self.check_stream(stream_id)?;
                if self.head.is_none() || self.saw_trailers || self.body_forbidden {
                    return Err(NativeH3ClientError::InvalidMessage(
                        "DATA is not permitted in this response",
                    ));
                }
                let size = self.body_bytes.checked_add(bytes.len()).ok_or(
                    NativeH3ClientError::InvalidMessage("response body size overflow"),
                )?;
                check_limit(size, self.config.max_response_body_bytes, "response body")?;
                if let Some(expected) = self.content_length {
                    if size as u64 > expected {
                        return Err(NativeH3ClientError::ContentLengthMismatch {
                            expected,
                            actual: size,
                        });
                    }
                }
                self.body_bytes = size;
                return Ok(ResponseProgress::Data(bytes));
            }
            NativeH3Event::Trailers { stream_id, fields } => {
                self.check_stream(stream_id)?;
                if self.head.is_none() || self.saw_trailers || self.body_forbidden {
                    return Err(NativeH3ClientError::InvalidMessage(
                        "trailers are not permitted in this response",
                    ));
                }
                if fields
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                {
                    return Err(NativeH3ClientError::InvalidMessage(
                        "content-length is forbidden in trailers",
                    ));
                }
                self.account_fields(&fields, false)?;
                self.saw_trailers = true;
                self.trailers = fields;
            }
            NativeH3Event::Finished { stream_id } => {
                self.check_stream(stream_id)?;
                let head = self.head.take().ok_or(NativeH3ClientError::InvalidMessage(
                    "response FIN before final headers",
                ))?;
                if !self.body_forbidden {
                    if let Some(expected) = self.content_length {
                        check_length(expected, self.body_bytes)?;
                    }
                }
                return Ok(ResponseProgress::Finished(NativeH3ClientResponseSummary {
                    head,
                    body_bytes: self.body_bytes,
                    trailers: std::mem::take(&mut self.trailers),
                    informational: std::mem::take(&mut self.informational),
                }));
            }
            NativeH3Event::StreamReset {
                stream_id,
                error_code,
                final_size,
            } => {
                self.check_stream(stream_id)?;
                return Err(NativeH3ClientError::StreamReset {
                    error_code,
                    final_size,
                });
            }
            NativeH3Event::Goaway(first_rejected_stream) => {
                if self.stream_id.0 >= first_rejected_stream {
                    return Err(NativeH3ClientError::Goaway {
                        first_rejected_stream,
                    });
                }
            }
            NativeH3Event::RequestHeaders { .. } => {
                return Err(NativeH3ClientError::InvalidMessage(
                    "a client received request headers",
                ));
            }
            NativeH3Event::Settings(_) | NativeH3Event::Frame { .. } => {}
        }
        Ok(ResponseProgress::Continue)
    }

    fn check_stream(&self, stream_id: StreamId) -> Result<(), NativeH3ClientError> {
        if stream_id == self.stream_id {
            Ok(())
        } else {
            Err(NativeH3ClientError::InvalidMessage(
                "response belongs to another stream",
            ))
        }
    }
}

fn content_length(fields: &[(String, String)]) -> Result<Option<u64>, NativeH3ClientError> {
    let mut length = None;
    for (name, value) in fields {
        if !name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        for value in value.split(',') {
            let value = value.trim_matches([' ', '\t']);
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(NativeH3ClientError::InvalidMessage(
                    "invalid content-length",
                ));
            }
            let parsed = value
                .parse::<u64>()
                .map_err(|_| NativeH3ClientError::InvalidMessage("content-length overflows u64"))?;
            if length.is_some_and(|previous| previous != parsed) {
                return Err(NativeH3ClientError::InvalidMessage(
                    "conflicting content-length fields",
                ));
            }
            length = Some(parsed);
        }
    }
    Ok(length)
}

fn check_length(expected: u64, actual: usize) -> Result<(), NativeH3ClientError> {
    if expected == actual as u64 {
        Ok(())
    } else {
        Err(NativeH3ClientError::ContentLengthMismatch { expected, actual })
    }
}

fn check_limit(
    size: usize,
    limit: usize,
    resource: &'static str,
) -> Result<(), NativeH3ClientError> {
    if size <= limit {
        Ok(())
    } else {
        Err(NativeH3ClientError::LimitExceeded { resource, limit })
    }
}

fn fields_size(fields: &[(String, String)]) -> Result<usize, NativeH3ClientError> {
    fields
        .iter()
        .try_fold(0, |size, (name, value)| add_field_size(size, name, value))
}

fn add_field_size(size: usize, name: &str, value: &str) -> Result<usize, NativeH3ClientError> {
    size.checked_add(name.len())
        .and_then(|size| size.checked_add(value.len()))
        .and_then(|size| size.checked_add(32))
        .ok_or(NativeH3ClientError::InvalidMessage(
            "field section size overflow",
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::h3_native::H3PseudoHeaders;

    fn fields(name: &str, value: &str) -> Vec<(String, String)> {
        vec![(name.to_owned(), value.to_owned())]
    }

    fn request(method: &str) -> H3RequestHead {
        H3RequestHead::new(
            H3PseudoHeaders {
                method: Some(method.to_owned()),
                scheme: Some("https".to_owned()),
                authority: Some("localhost".to_owned()),
                path: Some("/resource".to_owned()),
                ..H3PseudoHeaders::default()
            },
            Vec::new(),
        )
        .unwrap()
    }

    fn collector() -> ResponseCollector {
        ResponseCollector::new(StreamId(0), false, NativeH3ClientConfig::default())
    }

    fn response(status: u16, headers: Vec<(String, String)>) -> NativeH3Event {
        NativeH3Event::ResponseHeaders {
            stream_id: StreamId(0),
            head: H3ResponseHead::new(status, headers).unwrap(),
        }
    }

    fn data(bytes: &'static [u8]) -> NativeH3Event {
        NativeH3Event::Data {
            stream_id: StreamId(0),
            bytes: Bytes::from_static(bytes),
        }
    }

    fn fin() -> NativeH3Event {
        NativeH3Event::Finished {
            stream_id: StreamId(0),
        }
    }

    #[test]
    fn client_limits_are_finite_and_zero_body_limits_are_useful() {
        NativeH3ClientConfig::default().validate().unwrap();
        for config in [
            NativeH3ClientConfig {
                timeout: Duration::ZERO,
                ..Default::default()
            },
            NativeH3ClientConfig {
                max_field_section_size: 65_537,
                ..Default::default()
            },
            NativeH3ClientConfig {
                max_field_section_size: 0,
                ..Default::default()
            },
            NativeH3ClientConfig {
                max_response_header_bytes: 41,
                ..Default::default()
            },
            NativeH3ClientConfig {
                max_informational_responses: 65,
                ..Default::default()
            },
        ] {
            assert!(matches!(
                config.validate(),
                Err(NativeH3ClientError::InvalidConfig(_))
            ));
        }
        let config = NativeH3ClientConfig {
            max_request_body_bytes: 0,
            max_response_body_bytes: 0,
            max_informational_responses: 0,
            ..Default::default()
        };
        config.validate().unwrap();
        validate_request(&request("GET"), &Bytes::new(), &config).unwrap();
        assert!(matches!(
            validate_request(&request("POST"), &Bytes::from_static(b"x"), &config),
            Err(NativeH3ClientError::LimitExceeded {
                resource: "request body",
                limit: 0
            })
        ));
    }

    #[test]
    fn request_preflight_checks_public_head_fields_and_exact_length() {
        let config = NativeH3ClientConfig::default();
        let mut head = request("POST");
        head.headers = fields("content-length", "3, 3");
        validate_request(&head, &Bytes::from_static(b"abc"), &config).unwrap();
        assert!(matches!(
            validate_request(&head, &Bytes::from_static(b"ab"), &config),
            Err(NativeH3ClientError::ContentLengthMismatch {
                expected: 3,
                actual: 2
            })
        ));
        head.pseudo.method = Some("CONNECT".to_owned());
        assert!(matches!(
            validate_request(&head, &Bytes::new(), &config),
            Err(NativeH3ClientError::UnsupportedRequest(_))
        ));
        head.pseudo.method = Some("GET\r\n".to_owned());
        assert!(matches!(
            validate_request(&head, &Bytes::new(), &config),
            Err(NativeH3ClientError::Session(_))
        ));
        let config = NativeH3ClientConfig {
            max_field_section_size: 32,
            ..config
        };
        assert!(matches!(
            validate_request(&request("GET"), &Bytes::new(), &config),
            Err(NativeH3ClientError::LimitExceeded {
                resource: "request fields",
                ..
            })
        ));
    }

    #[test]
    fn content_length_rejects_conflicts_signs_empty_members_and_overflow() {
        assert_eq!(
            content_length(&fields("content-length", " 03,\t3 ")).unwrap(),
            Some(3)
        );
        let mut repeated = fields("content-length", "3");
        repeated.extend(fields("content-length", "3"));
        assert_eq!(content_length(&repeated).unwrap(), Some(3));
        for value in [
            "",
            "3,",
            ",3",
            "3,4",
            "+3",
            "-3",
            "3 0",
            "18446744073709551616",
        ] {
            assert!(
                content_length(&fields("content-length", value)).is_err(),
                "{value:?}"
            );
        }
        repeated.push(("content-length".to_owned(), "4".to_owned()));
        assert!(content_length(&repeated).is_err());
    }

    #[test]
    fn response_retains_informational_heads_body_and_trailers_until_fin() {
        let mut collected = collector();
        assert!(matches!(
            collected
                .accept(response(103, fields("link", "</style.css>")))
                .unwrap(),
            ResponseProgress::Continue
        ));
        assert!(matches!(
            collected
                .accept(response(200, fields("content-length", "6")))
                .unwrap(),
            ResponseProgress::Continue
        ));
        let mut body = Vec::new();
        for chunk in [b"abc", b"def"] {
            let ResponseProgress::Data(bytes) = collected.accept(data(chunk)).unwrap() else {
                panic!("validated DATA must be handed to the sink");
            };
            body.extend_from_slice(&bytes);
        }
        assert!(matches!(
            collected
                .accept(NativeH3Event::Trailers {
                    stream_id: StreamId(0),
                    fields: fields("x-check", "complete"),
                })
                .unwrap(),
            ResponseProgress::Continue
        ));
        let ResponseProgress::Finished(result) = collected.accept(fin()).unwrap() else {
            panic!("valid FIN must complete the response");
        };
        assert_eq!(result.head.status, 200);
        assert_eq!(result.body_bytes, 6);
        assert_eq!(body, b"abcdef");
        assert_eq!(result.informational[0].status, 103);
        assert_eq!(result.trailers, fields("x-check", "complete"));
    }

    #[test]
    fn final_headers_and_exact_content_length_are_required_at_fin() {
        let mut collected = collector();
        collected.accept(response(103, Vec::new())).unwrap();
        assert!(matches!(
            collected.accept(fin()),
            Err(NativeH3ClientError::InvalidMessage(_))
        ));
        let mut collected = collector();
        collected
            .accept(response(200, fields("content-length", "4")))
            .unwrap();
        collected.accept(data(b"abc")).unwrap();
        assert!(matches!(
            collected.accept(fin()),
            Err(NativeH3ClientError::ContentLengthMismatch {
                expected: 4,
                actual: 3
            })
        ));
        let mut collected = collector();
        collected
            .accept(response(200, fields("content-length", "2")))
            .unwrap();
        assert!(matches!(
            collected.accept(data(b"abc")),
            Err(NativeH3ClientError::ContentLengthMismatch {
                expected: 2,
                actual: 3
            })
        ));
        assert_eq!(
            collected.body_bytes, 0,
            "oversized DATA is rejected before admission"
        );
    }

    #[test]
    fn response_body_limits_cover_declared_and_undeclared_content() {
        let config = NativeH3ClientConfig {
            max_response_body_bytes: 4,
            ..Default::default()
        };
        let mut collected = ResponseCollector::new(StreamId(0), false, config.clone());
        assert!(matches!(
            collected.accept(response(200, fields("content-length", "5"))),
            Err(NativeH3ClientError::LimitExceeded {
                resource: "response body",
                limit: 4
            })
        ));
        let mut collected = ResponseCollector::new(StreamId(0), false, config);
        collected.accept(response(200, Vec::new())).unwrap();
        collected.accept(data(b"abc")).unwrap();
        assert!(matches!(
            collected.accept(data(b"de")),
            Err(NativeH3ClientError::LimitExceeded {
                resource: "response body",
                limit: 4
            })
        ));
        assert_eq!(collected.body_bytes, 3);
    }

    #[test]
    fn header_budget_accumulates_informational_final_and_trailer_fields() {
        let config = NativeH3ClientConfig {
            max_response_header_bytes: 84,
            ..Default::default()
        };
        let mut collected = ResponseCollector::new(StreamId(0), false, config);
        collected.accept(response(103, Vec::new())).unwrap();
        collected.accept(response(200, Vec::new())).unwrap();
        assert_eq!(collected.header_bytes, 84);
        assert!(matches!(
            collected.accept(NativeH3Event::Trailers {
                stream_id: StreamId(0),
                fields: fields("x", "y")
            }),
            Err(NativeH3ClientError::LimitExceeded {
                resource: "response fields",
                limit: 84
            })
        ));
        let config = NativeH3ClientConfig {
            max_informational_responses: 1,
            ..Default::default()
        };
        let mut collected = ResponseCollector::new(StreamId(0), false, config);
        collected.accept(response(103, Vec::new())).unwrap();
        assert!(matches!(
            collected.accept(response(100, Vec::new())),
            Err(NativeH3ClientError::LimitExceeded {
                resource: "informational responses",
                limit: 1
            })
        ));
        assert_eq!(collected.informational.len(), 1);
    }

    #[test]
    fn bodyless_response_metadata_does_not_declare_actual_content() {
        for (is_head, status) in [(true, 200), (false, 304)] {
            let mut collected = ResponseCollector::new(StreamId(0), is_head, Default::default());
            collected
                .accept(response(status, fields("content-length", "999999999")))
                .unwrap();
            let ResponseProgress::Finished(result) = collected.accept(fin()).unwrap() else {
                panic!("bodyless response must finish");
            };
            assert_eq!(result.body_bytes, 0);
            let mut collected = ResponseCollector::new(StreamId(0), is_head, Default::default());
            collected.accept(response(status, Vec::new())).unwrap();
            assert!(matches!(
                collected.accept(data(b"")),
                Err(NativeH3ClientError::InvalidMessage(_))
            ));
        }
        for (status, value) in [(100, "0"), (103, "0"), (204, "0"), (205, "1")] {
            assert!(matches!(
                collector().accept(response(status, fields("content-length", value))),
                Err(NativeH3ClientError::InvalidMessage(_))
            ));
        }
        // Public fields may be mutated after construction; the adapter must
        // revalidate even a head the normal constructor would refuse.
        assert!(
            collector()
                .accept(NativeH3Event::ResponseHeaders {
                    stream_id: StreamId(0),
                    head: H3ResponseHead {
                        status: 101,
                        headers: Vec::new()
                    },
                })
                .is_err()
        );
        for status in [204, 205] {
            let mut collected = collector();
            collected.accept(response(status, Vec::new())).unwrap();
            let ResponseProgress::Finished(result) = collected.accept(fin()).unwrap() else {
                panic!("bodyless response must finish");
            };
            assert_eq!(result.body_bytes, 0);
        }
    }

    #[test]
    fn malformed_sequence_resets_and_refusing_goaway_are_terminal() {
        assert!(collector().accept(data(b"early")).is_err());
        let mut collected = collector();
        collected.accept(response(200, Vec::new())).unwrap();
        assert!(collected.accept(response(201, Vec::new())).is_err());
        assert!(matches!(
            collector().accept(NativeH3Event::StreamReset {
                stream_id: StreamId(0),
                error_code: 0x10c,
                final_size: 123,
            }),
            Err(NativeH3ClientError::StreamReset {
                error_code: 0x10c,
                final_size: 123
            })
        ));
        assert!(matches!(
            collector().accept(NativeH3Event::Goaway(4)).unwrap(),
            ResponseProgress::Continue
        ));
        assert!(matches!(
            collector().accept(NativeH3Event::Goaway(0)),
            Err(NativeH3ClientError::Goaway {
                first_rejected_stream: 0
            })
        ));
        assert!(
            collector()
                .accept(NativeH3Event::Finished {
                    stream_id: StreamId(4)
                })
                .is_err()
        );
        let mut collected = collector();
        collected.accept(response(200, Vec::new())).unwrap();
        assert!(
            collected
                .accept(NativeH3Event::Trailers {
                    stream_id: StreamId(0),
                    fields: fields("content-length", "0"),
                })
                .is_err()
        );
    }

    #[test]
    fn upload_retirement_requires_send_reset_and_preserves_response_direction() {
        let cx = Cx::for_testing();
        let mut connection = QuicConnection::client(Default::default());
        connection.begin_handshake(&cx).unwrap();
        connection.mark_handshake_keys_available(&cx).unwrap();
        connection.mark_app_keys_available(&cx).unwrap();
        connection.record_verified_server_identity();
        connection.confirm_handshake(&cx).unwrap();
        let mut session = NativeH3Session::client();
        session
            .initialize(&cx, &mut connection, H3Settings::default())
            .unwrap();
        let mut writer = session
            .start_request_writer(&cx, &mut connection, &request("POST"), false)
            .unwrap();
        let stream = writer.stream_id();
        assert!(!writer.retire_stopped_upload(&connection).unwrap());
        assert!(writer.has_pending_write());
        connection.reset_stream(&cx, stream, 0x10c).unwrap();
        assert!(writer.retire_stopped_upload(&connection).unwrap());
        assert!(!writer.has_pending_write());
        drop(writer);
        assert!(session.next_event(&cx, &mut connection).unwrap().is_none());
        let stream = connection.inner().streams().stream(stream).unwrap();
        assert_eq!(stream.send_reset.map(|(code, _)| code), Some(0x10c));
        assert!(stream.receive_stopped_error_code.is_none());
        assert!(stream.recv_reset.is_none());
    }

    #[test]
    fn invalid_sink_counts_are_errors_without_losing_the_pending_chunk() {
        struct WrongCount(usize);
        impl AsyncWrite for WrongCount {
            fn poll_write(
                self: Pin<&mut Self>,
                _task: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                assert!(!bytes.is_empty(), "empty chunks must not invoke the sink");
                Poll::Ready(Ok(self.0))
            }

            fn poll_flush(self: Pin<&mut Self>, _task: &mut Context<'_>) -> Poll<io::Result<()>> {
                unreachable!("this test exercises write admission only")
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                _task: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                unreachable!("borrowed sinks must not be shut down")
            }
        }
        let mut task = Context::from_waker(std::task::Waker::noop());
        for (count, expected) in [
            (0, io::ErrorKind::WriteZero),
            (4, io::ErrorKind::InvalidData),
        ] {
            let mut pending = Bytes::from_static(b"abc");
            let result = poll_sink_write(&mut WrongCount(count), &mut pending, &mut task);
            assert!(
                matches!(result, Poll::Ready(Err(NativeH3ClientError::Sink(error))) if error.kind() == expected)
            );
            assert_eq!(&pending[..], b"abc");
        }
        let mut empty = Bytes::new();
        assert!(matches!(
            poll_sink_write(&mut WrongCount(0), &mut empty, &mut task),
            Poll::Ready(Ok(()))
        ));
    }
}
