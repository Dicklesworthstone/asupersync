//! Caller-driven CONNECT ownership over the native HTTP/3 session.

use super::{
    Bytes, Context, Cx, Future, H3RequestHead, H3ResponseHead, H3Settings, IO_CHUNK_BYTES,
    ManagedEndpointConfig, ManagedEndpointError, ManagedQuicEndpoint, NativeH3Client,
    NativeH3ClientConfig, NativeH3ClientError, NativeH3Event, NativeH3RequestWriter,
    NativeH3Session, NativeH3SessionError, NativeQuicConnectionError, NativeQuicUdpConnection,
    NonZeroUsize, POLL_STEPS, Pin, Poll, QuicConnection, StreamId, add_field_size, check_limit,
    content_length, fields_size, fmt, validate_request_head_with_settings, validate_response_head,
};
use crate::cx::CancelWakerToken;
use crate::http::h3_native::H3Frame;
use crate::net::quic_core::ConnectionId;
use crate::time::Sleep;
use crate::types::Time;
use std::sync::Arc;

/// Establishment or lifetime failure of an owned HTTP/3 CONNECT tunnel.
#[derive(Debug)]
#[non_exhaustive]
pub enum NativeH3TunnelError {
    /// Configuration, message, resource, transport, cancellation, or deadline failure.
    Client(NativeH3ClientError),
    /// Peer SETTINGS did not authorize the requested extended CONNECT protocol.
    NotNegotiated,
    /// The final HTTP response did not accept CONNECT. No response body is retained.
    Rejected(u16),
    /// The owner was retired, or application writes were already half-closed.
    Closed,
}

impl fmt::Display for NativeH3TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(error) => error.fmt(f),
            Self::NotNegotiated => f.write_str("HTTP/3 peer did not enable extended CONNECT"),
            Self::Rejected(status) => write!(f, "HTTP/3 CONNECT was rejected with status {status}"),
            Self::Closed => f.write_str("HTTP/3 tunnel is closed for this operation"),
        }
    }
}

impl std::error::Error for NativeH3TunnelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Client(error) => Some(error),
            _ => None,
        }
    }
}

impl From<NativeH3ClientError> for NativeH3TunnelError {
    fn from(error: NativeH3ClientError) -> Self {
        Self::Client(error)
    }
}

impl From<NativeH3SessionError> for NativeH3TunnelError {
    fn from(error: NativeH3SessionError) -> Self {
        Self::Client(error.into())
    }
}

impl From<ManagedEndpointError> for NativeH3TunnelError {
    fn from(error: ManagedEndpointError) -> Self {
        Self::Client(error.into())
    }
}

/// Progress in either direction of one owned CONNECT tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeH3TunnelEvent {
    /// Initial HEADERS or the preceding DATA left the local transport queues.
    /// A new DATA prefix can be admitted. This is not a peer acknowledgement.
    SendReady,
    /// At most 16 KiB of tunneled bytes. DATA frame boundaries are not preserved.
    Data(Bytes),
    /// The peer sent response FIN. The application may continue sending.
    ReadClosed,
    /// Accepted application bytes and request FIN left the local transport queues.
    /// The application may continue receiving, and QUIC recovery remains owned.
    WriteClosed,
}

/// One bounded CONNECT stream owning its authenticated QUIC socket.
///
/// Call [`Self::next_event`] until `SendReady`, queue a byte prefix with
/// [`Self::queue_data`], and continue consuming events in both directions.
/// A queued write never prevents receiving peer DATA or servicing flow control.
/// [`Self::finish_send`] closes only the request direction; `ReadClosed` closes
/// only the response direction. `Ok(None)` requires both halves and all pending
/// or unacknowledged transport output to finish. Keep polling after both close
/// events so packet-loss recovery can complete.
///
/// One DATA frame of at most 16 KiB and one received chunk are retained, in
/// addition to the existing bounded QUIC and HTTP/3 parser buffers. Cumulative
/// send and receive limits come from the client's request/response body limits.
/// The client's timeout covers setup only. The constructor's Cx cancellation
/// and deadlines, its ambient authority, and the polling task's restrictions
/// continue to apply for the entire lifetime.
///
/// Dropping a borrowing `next_event` wait preserves accepted bytes, pending
/// events, and exact transport cursors. Dropping or aborting the owner retires
/// its socket immediately, with no detached task or drain. Errors from
/// `next_event` also retire it; subsequent waits return `Ok(None)`. Neither
/// abort nor drop promises delivery of a reset or connection-close packet.
///
/// ```no_run
/// use asupersync::{Cx, http::h3::{
///     H3RequestHead, NativeH3Client, NativeH3TunnelError, NativeH3TunnelEvent,
/// }};
///
/// async fn exchange(
///     client: NativeH3Client,
///     cx: &Cx,
///     connect_head: H3RequestHead,
///     bytes: &[u8],
/// ) -> Result<Vec<u8>, NativeH3TunnelError> {
///     let mut tunnel = client.connect_tunnel(cx, connect_head).await?;
///     let mut sent = 0;
///     let mut received = Vec::new();
///     while let Some(event) = tunnel.next_event().await? {
///         match event {
///             NativeH3TunnelEvent::SendReady => {
///                 sent += tunnel.queue_data(&bytes[sent..])?;
///                 if sent == bytes.len() {
///                     tunnel.finish_send()?;
///                 }
///             }
///             NativeH3TunnelEvent::Data(bytes) => received.extend_from_slice(&bytes),
///             _ => {} // Continue driving after either independent half-close.
///         }
///     }
///     Ok(received)
/// }
/// ```
#[must_use = "an HTTP/3 tunnel makes progress only while next_event is polled"]
pub struct NativeH3Tunnel {
    // The transport must retire before cancellation registrations or session
    // writers can drop arbitrary Waker owners.
    transport: TunnelTransport,
    control: Option<TunnelControl>,
    core: TunnelCore,
    connection_id: ConnectionId,
    completed: bool,
    failed: bool,
}

impl fmt::Debug for NativeH3Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeH3Tunnel")
            .field("stream_id", &self.core.stream_id())
            .field("response", &self.core.response)
            .field("sent_bytes", &self.core.sent_bytes)
            .field("received_bytes", &self.core.received_bytes)
            .field("read_closed", &self.core.read_closed)
            .field("write_closed", &self.core.write_closed)
            .field("completed", &self.completed)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl NativeH3Client {
    /// Establish an ordinary or extended CONNECT tunnel on this owned socket.
    ///
    /// Ordinary CONNECT uses only `:method = CONNECT` and an `:authority` with
    /// an explicit port. Extended CONNECT additionally uses a valid `:protocol`,
    /// `:scheme`, and `:path`; it waits for peer
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` before opening a request stream
    /// or transmitting the target and credentials. No request body,
    /// Content-Length, TE, or Trailer field is accepted during setup.
    ///
    /// A final 2xx accepts the tunnel; other final statuses return `Rejected`.
    /// Response Content-Length does not delimit tunneled bytes. Subsequent
    /// HEADERS/trailers are refused, and each stream FIN is an independent
    /// half-close, as in RFC 9114 section 4.4 and RFC 9220 section 3.
    ///
    /// Configuration and request metadata are checked before network I/O.
    /// The finite client timeout ends at accepted response headers. There is
    /// no retry, redirect, pool, background task, or fallback on rejection.
    /// Dropping even an unpolled setup future releases the supplied transport.
    pub fn connect_tunnel(
        self,
        cx: &Cx,
        head: H3RequestHead,
    ) -> impl Future<Output = Result<NativeH3Tunnel, NativeH3TunnelError>> + use<> {
        let owner = cx.clone();
        let connection_id = self.connection.local_connection_id();
        let tunnel = NativeH3Tunnel {
            transport: TunnelTransport {
                raw: Some(self.connection),
                endpoint: None,
                owner: owner.clone(),
            },
            control: Some(TunnelControl::new(owner)),
            core: TunnelCore::new(head, self.config),
            connection_id,
            completed: false,
            failed: false,
        };
        tunnel.open()
    }
}

impl NativeH3Tunnel {
    async fn open(mut self) -> Result<Self, NativeH3TunnelError> {
        self.core.config.validate()?;
        validate_connect(
            self.core.request.as_ref().expect("initial request"),
            &self.core.config,
        )?;
        self.control
            .as_mut()
            .expect("live setup control")
            .check(None)?;
        let cx = self.transport.owner.clone();
        let started = cx.now();
        {
            let _owner = cx.clone().set_current_restricted();
            let connection = self.transport.raw.take().expect("fresh transport owner");
            self.transport.endpoint = Some(
                connection
                    .into_managed(
                        &cx,
                        ManagedEndpointConfig {
                            max_connections: 1,
                            ..ManagedEndpointConfig::default()
                        },
                    )
                    .map_err(|error| NativeH3ClientError::from(error.into_parts().0))?,
            );
            self.transport
                .endpoint
                .as_mut()
                .expect("managed owner")
                .with_connection_mut(&cx, self.connection_id, |connection| {
                    self.core.initialize(&cx, connection)
                })??;
        }
        let result = {
            let Self {
                transport,
                control,
                core,
                connection_id,
                ..
            } = &mut self;
            let endpoint = transport.endpoint.as_mut().expect("managed owner");
            let operation = crate::time::timeout(
                started,
                core.config.timeout,
                endpoint.run_event_loop_with_application(&cx, |cx, endpoint, task| {
                    poll_managed(core, *connection_id, cx, endpoint, task)
                }),
            );
            drive_controlled(control.as_mut().expect("live setup control"), operation)
                .await?
                .map_err(|_| NativeH3ClientError::TimedOut)??
        }?;
        debug_assert!(matches!(result, TunnelProgress::Opened));
        Ok(self)
    }

    /// Successful final response metadata. Content-Length is ignored for CONNECT.
    #[must_use]
    pub fn response_head(&self) -> &H3ResponseHead {
        self.core.response.as_ref().expect("established tunnel")
    }

    /// Informational responses received before acceptance, in wire order.
    #[must_use]
    pub fn informational(&self) -> &[H3ResponseHead] {
        &self.core.informational
    }

    /// The single client-initiated bidirectional request stream.
    #[must_use]
    pub fn stream_id(&self) -> StreamId {
        self.core.stream_id().expect("established tunnel")
    }

    /// Whether the application may queue DATA without first driving another event.
    #[must_use]
    pub fn send_ready(&self) -> bool {
        !self.failed && !self.completed && self.core.send_ready && !self.core.finish_requested
    }

    /// Cumulative application bytes accepted by `queue_data`, including pending bytes.
    #[must_use]
    pub fn sent_bytes(&self) -> usize {
        self.core.sent_bytes
    }

    /// Cumulative peer DATA bytes accepted, including a retained delivery event.
    #[must_use]
    pub fn received_bytes(&self) -> usize {
        self.core.received_bytes
    }

    /// Whether both halves and transport recovery completed successfully.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.completed && !self.failed
    }

    /// Admit a prefix of borrowed bytes into the single bounded send slot.
    ///
    /// The returned length is at most 16 KiB, the remaining lifetime send
    /// allowance, and `bytes.len()`. `Ok(0)` for nonempty input means the slot
    /// is busy; consume `next_event` until `SendReady` and retry the same input.
    /// Neither backpressure nor an error consumes caller bytes. After a
    /// nonzero return, resume `next_event` if its future is dropped; do not
    /// resubmit the accepted prefix. This method performs no network I/O.
    /// Exhausting the lifetime limit refuses further DATA but still permits FIN.
    pub fn queue_data(&mut self, bytes: &[u8]) -> Result<usize, NativeH3TunnelError> {
        self.check_live()?;
        self.core.queue_data(bytes)
    }

    /// Request FIN after all accepted bytes, without closing the receive half.
    ///
    /// This is idempotent and may be called while a DATA frame is pending.
    /// `next_event` drives that frame before FIN and emits `WriteClosed` after
    /// both leave the local queues. No later DATA is accepted.
    pub fn finish_send(&mut self) -> Result<(), NativeH3TunnelError> {
        self.check_live()?;
        self.core.finish_requested = true;
        self.core.send_ready = false;
        Ok(())
    }

    /// Drive upload, receive, flow control, ACKs, and recovery to the next event.
    ///
    /// Every delivery gives the managed transport a service turn, so an
    /// immediately readable response cannot starve pending writes. One error
    /// retires the socket; later waits return `Ok(None)`. Borrowing waits may
    /// be dropped and resumed without losing DATA or duplicating a write.
    pub async fn next_event(&mut self) -> Result<Option<NativeH3TunnelEvent>, NativeH3TunnelError> {
        if self.failed || self.completed {
            return Ok(None);
        }
        let cx = self.transport.owner.clone();
        let result = {
            let Self {
                transport,
                control,
                core,
                connection_id,
                ..
            } = self;
            let operation = transport
                .endpoint
                .as_mut()
                .expect("live managed owner")
                .run_event_loop_with_application(&cx, |cx, endpoint, task| {
                    poll_managed(core, *connection_id, cx, endpoint, task)
                });
            drive_controlled(control.as_mut().expect("live session control"), operation).await
        };
        let result = result
            .and_then(|result| result.map_err(Into::into))
            .and_then(|result| result);
        match result {
            Ok(TunnelProgress::Event(event)) => Ok(Some(event)),
            Ok(TunnelProgress::Complete) => {
                self.completed = true;
                self.retire();
                Ok(None)
            }
            Ok(TunnelProgress::Opened) => {
                self.abort();
                Err(invalid("duplicate tunnel acceptance"))
            }
            Err(error) => {
                self.abort();
                Err(error)
            }
        }
    }

    /// Immediately release the entire owned transport and retained DATA.
    pub fn abort(&mut self) {
        self.failed = true;
        self.retire();
    }

    fn retire(&mut self) {
        self.transport.retire();
        self.control = None;
        self.core.pending_delivery = None;
        self.core.pending_read = None;
        self.core.writer = None;
    }

    fn check_live(&mut self) -> Result<(), NativeH3TunnelError> {
        if self.failed || self.completed {
            return Err(NativeH3TunnelError::Closed);
        }
        if let Err(error) = self
            .control
            .as_mut()
            .expect("live session control")
            .check(None)
        {
            self.abort();
            return Err(error);
        }
        Ok(())
    }
}

struct TunnelTransport {
    raw: Option<NativeQuicUdpConnection>,
    endpoint: Option<ManagedQuicEndpoint>,
    owner: Cx,
}

impl TunnelTransport {
    fn retire(&mut self) {
        let _owner = self.owner.clone().set_current_restricted();
        drop(self.raw.take());
        drop(self.endpoint.take());
    }
}

impl Drop for TunnelTransport {
    fn drop(&mut self) {
        self.retire();
    }
}

enum TunnelProgress {
    Opened,
    Event(NativeH3TunnelEvent),
    Complete,
}

struct TunnelCore {
    session: NativeH3Session,
    writer: Option<NativeH3RequestWriter>,
    request_stream: Option<StreamId>,
    request: Option<H3RequestHead>,
    config: NativeH3ClientConfig,
    response: Option<H3ResponseHead>,
    informational: Vec<H3ResponseHead>,
    header_bytes: usize,
    sent_bytes: usize,
    received_bytes: usize,
    send_ready: bool,
    finish_requested: bool,
    read_closed: bool,
    write_closed: bool,
    prefer_send_event: bool,
    pending_read: Option<NativeH3TunnelEvent>,
    pending_delivery: Option<TunnelProgress>,
}

impl TunnelCore {
    fn new(head: H3RequestHead, config: NativeH3ClientConfig) -> Self {
        Self {
            session: NativeH3Session::client(),
            writer: None,
            request_stream: None,
            request: Some(head),
            config,
            response: None,
            informational: Vec::new(),
            header_bytes: 0,
            sent_bytes: 0,
            received_bytes: 0,
            send_ready: false,
            finish_requested: false,
            read_closed: false,
            write_closed: false,
            prefer_send_event: true,
            pending_read: None,
            pending_delivery: None,
        }
    }

    fn stream_id(&self) -> Option<StreamId> {
        self.request_stream
    }

    fn initialize(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
    ) -> Result<(), NativeH3TunnelError> {
        self.session
            .enable_streaming_receive(NonZeroUsize::new(IO_CHUNK_BYTES).expect("nonzero chunk"))?;
        self.session.initialize(
            cx,
            connection,
            H3Settings {
                max_field_section_size: Some(self.config.max_field_section_size as u64),
                ..H3Settings::default()
            },
        )?;
        if self
            .request
            .as_ref()
            .expect("initial request")
            .pseudo
            .protocol
            .is_none()
        {
            self.start_request(cx, connection)?;
        }
        Ok(())
    }

    fn start_request(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
    ) -> Result<(), NativeH3TunnelError> {
        self.writer = Some(self.session.start_request_writer(
            cx,
            connection,
            self.request.as_ref().expect("pending CONNECT head"),
            false,
        )?);
        self.request_stream = self.writer.as_ref().map(NativeH3RequestWriter::stream_id);
        self.request = None;
        Ok(())
    }

    fn queue_data(&mut self, bytes: &[u8]) -> Result<usize, NativeH3TunnelError> {
        if self.finish_requested {
            return Err(NativeH3TunnelError::Closed);
        }
        if bytes.is_empty() || !self.send_ready {
            return Ok(0);
        }
        let remaining = self.config.max_request_body_bytes - self.sent_bytes;
        if remaining == 0 {
            return Err(NativeH3ClientError::LimitExceeded {
                resource: "tunnel send bytes",
                limit: self.config.max_request_body_bytes,
            }
            .into());
        }
        let writer = self.writer.as_mut().expect("established writer");
        let accepted = bytes
            .len()
            .min(IO_CHUNK_BYTES)
            .min(remaining)
            .min(writer.max_frame_payload_size());
        writer.queue_data(Bytes::copy_from_slice(&bytes[..accepted]))?;
        self.sent_bytes += accepted;
        self.send_ready = false;
        Ok(accepted)
    }

    fn poll(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        task: &mut Context<'_>,
        pending_datagrams: usize,
    ) -> Poll<Result<TunnelProgress, NativeH3TunnelError>> {
        // Read first to observe rejection/reset before admitting further bytes.
        // Retain at most one DATA event while alternating read/write delivery.
        if self.pending_read.is_none() {
            for step in 0..POLL_STEPS {
                let event = match self.session.poll_event(cx, connection, task) {
                    Poll::Pending => break,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Ready(Ok(event)) => event,
                };
                if let Some(progress) = self.accept(cx, connection, event)? {
                    match progress {
                        TunnelProgress::Opened => return Poll::Ready(Ok(TunnelProgress::Opened)),
                        TunnelProgress::Event(event) => self.pending_read = Some(event),
                        TunnelProgress::Complete => unreachable!("FIN closes only one direction"),
                    }
                    break;
                }
                if step + 1 == POLL_STEPS {
                    task.waker().wake_by_ref();
                }
            }
        }
        if let Some(writer) = &mut self.writer {
            if !writer.is_finished() {
                let stream = connection
                    .inner()
                    .streams()
                    .stream(writer.stream_id())
                    .map_err(NativeQuicConnectionError::from)
                    .map_err(NativeH3SessionError::from)?;
                if let Some((error_code, final_size)) = stream.send_reset {
                    return Poll::Ready(Err(NativeH3ClientError::StreamReset {
                        error_code,
                        final_size,
                    }
                    .into()));
                }
            }
            for _ in 0..2 {
                if writer.has_pending_write() {
                    match writer.poll_flush(cx, connection, task) {
                        Poll::Pending => break,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                        Poll::Ready(Ok(_)) => {}
                    }
                }
                if self.finish_requested && !writer.is_finished() {
                    writer.finish()?;
                } else {
                    break;
                }
            }
        }
        let flush_ready = self.response.is_some()
            && self.writer.as_ref().is_some_and(|writer| {
                !writer.has_pending_write()
                    && !connection.has_pending_stream_frames(writer.stream_id())
                    && pending_datagrams == 0
                    && if writer.is_finished() {
                        !self.write_closed
                    } else {
                        !self.send_ready && !self.finish_requested
                    }
            });
        if flush_ready && (self.prefer_send_event || self.pending_read.is_none()) {
            self.prefer_send_event = false;
            let event = if self.writer.as_ref().expect("ready writer").is_finished() {
                self.write_closed = true;
                NativeH3TunnelEvent::WriteClosed
            } else {
                NativeH3TunnelEvent::SendReady
            };
            return Poll::Ready(Ok(TunnelProgress::Event(event)));
        }
        if let Some(event) = self.pending_read.take() {
            self.prefer_send_event = true;
            return Poll::Ready(Ok(TunnelProgress::Event(event)));
        }
        Poll::Pending
    }

    fn accept(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        event: NativeH3Event,
    ) -> Result<Option<TunnelProgress>, NativeH3TunnelError> {
        match event {
            NativeH3Event::Settings(settings) => {
                if self.writer.is_none() {
                    if settings.enable_connect_protocol != Some(true) {
                        return Err(NativeH3TunnelError::NotNegotiated);
                    }
                    self.start_request(cx, connection)?;
                }
            }
            NativeH3Event::ResponseHeaders { stream_id, head } => {
                self.check_stream(stream_id)?;
                validate_response_head(&head).map_err(NativeH3SessionError::from)?;
                if self.response.is_some() {
                    return Err(invalid("HEADERS after CONNECT acceptance"));
                }
                let size = add_field_size(fields_size(&head.headers)?, ":status", "200")?;
                check_limit(
                    size,
                    self.config.max_field_section_size,
                    "response field section",
                )?;
                self.header_bytes = self
                    .header_bytes
                    .checked_add(size)
                    .ok_or_else(|| invalid("response field size overflow"))?;
                check_limit(
                    self.header_bytes,
                    self.config.max_response_header_bytes,
                    "response fields",
                )?;
                if head.status < 200 {
                    if head.status == 101 || content_length(&head.headers)?.is_some() {
                        return Err(invalid("invalid informational CONNECT response"));
                    }
                    check_limit(
                        self.informational.len() + 1,
                        self.config.max_informational_responses,
                        "informational responses",
                    )?;
                    self.informational.push(head);
                } else if head.status >= 300 {
                    return Err(NativeH3TunnelError::Rejected(head.status));
                } else {
                    // CONNECT changes the DATA semantics even for 204/205.
                    // RFC 9110 section 9.3.6 requires ignoring Content-Length.
                    self.response = Some(head);
                    return Ok(Some(TunnelProgress::Opened));
                }
            }
            NativeH3Event::Data { stream_id, bytes } => {
                self.check_stream(stream_id)?;
                if self.response.is_none() || self.read_closed {
                    return Err(invalid(
                        "DATA outside the accepted CONNECT receive direction",
                    ));
                }
                let received = self
                    .received_bytes
                    .checked_add(bytes.len())
                    .ok_or_else(|| invalid("tunnel receive byte count overflow"))?;
                check_limit(
                    received,
                    self.config.max_response_body_bytes,
                    "tunnel receive bytes",
                )?;
                self.received_bytes = received;
                if !bytes.is_empty() {
                    return Ok(Some(TunnelProgress::Event(NativeH3TunnelEvent::Data(
                        bytes,
                    ))));
                }
            }
            NativeH3Event::Finished { stream_id } => {
                self.check_stream(stream_id)?;
                if self.response.is_none() || self.read_closed {
                    return Err(invalid(
                        "response FIN outside the accepted CONNECT receive direction",
                    ));
                }
                self.read_closed = true;
                return Ok(Some(TunnelProgress::Event(NativeH3TunnelEvent::ReadClosed)));
            }
            NativeH3Event::Trailers { .. } => {
                return Err(invalid("CONNECT does not permit trailers"));
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
                }
                .into());
            }
            NativeH3Event::Goaway(first_rejected_stream) => {
                if self.stream_id().map_or(0, |id| id.0) >= first_rejected_stream {
                    return Err(NativeH3ClientError::Goaway {
                        first_rejected_stream,
                    }
                    .into());
                }
            }
            NativeH3Event::RequestHeaders { .. } => {
                return Err(invalid("a CONNECT client received request HEADERS"));
            }
            NativeH3Event::Frame { stream_id, frame } => {
                if self.stream_id() == Some(stream_id) && !matches!(frame, H3Frame::Unknown { .. })
                {
                    return Err(invalid("unexpected known frame on CONNECT stream"));
                }
            }
        }
        Ok(None)
    }

    fn check_stream(&self, stream_id: StreamId) -> Result<(), NativeH3TunnelError> {
        if self.stream_id() == Some(stream_id) {
            Ok(())
        } else {
            Err(invalid("CONNECT response belongs to another stream"))
        }
    }
}

fn poll_managed(
    core: &mut TunnelCore,
    connection_id: ConnectionId,
    cx: &Cx,
    endpoint: &mut ManagedQuicEndpoint,
    task: &mut Context<'_>,
) -> Poll<Result<Result<TunnelProgress, NativeH3TunnelError>, ManagedEndpointError>> {
    if let Some(event) = core.pending_delivery.take() {
        if matches!(event, TunnelProgress::Event(NativeH3TunnelEvent::SendReady)) {
            if !core.finish_requested {
                core.send_ready = true;
                return Poll::Ready(Ok(Ok(event)));
            }
        } else {
            return Poll::Ready(Ok(Ok(event)));
        }
    }
    let queued = endpoint.pending_datagram_count_for(connection_id);
    match endpoint.with_connection_mut(cx, connection_id, |connection| {
        core.poll(cx, connection, task, queued)
    }) {
        Err(error) => Poll::Ready(Err(error)),
        Ok(Poll::Pending)
            if core.read_closed && core.write_closed && core.pending_read.is_none() =>
        {
            // Continue polling critical HTTP/3 streams above during the final
            // recovery drain. Do not discard retransmission ownership after
            // merely sending FIN: the existing helper refuses while output
            // remains buffered or in flight.
            match endpoint.request_authenticated_close(cx, connection_id, 0x100, false) {
                Ok(true) => Poll::Ready(Ok(Ok(TunnelProgress::Complete))),
                Ok(false) => Poll::Pending,
                Err(error) => Poll::Ready(Err(error)),
            }
        }
        Ok(Poll::Pending) => Poll::Pending,
        Ok(Poll::Ready(Err(error))) => Poll::Ready(Ok(Err(error))),
        Ok(Poll::Ready(Ok(TunnelProgress::Opened))) => Poll::Ready(Ok(Ok(TunnelProgress::Opened))),
        Ok(Poll::Ready(Ok(event))) => {
            // Managed self-wakes always offer UDP send/receive a service turn
            // before repolling the application. Keep the event in the owner,
            // not in the borrowing future, across that cooperative boundary.
            core.pending_delivery = Some(event);
            task.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

fn validate_connect(
    head: &H3RequestHead,
    config: &NativeH3ClientConfig,
) -> Result<(), NativeH3TunnelError> {
    if head.pseudo.method.as_deref() != Some("CONNECT") {
        return Err(
            NativeH3ClientError::UnsupportedRequest("connect_tunnel requires CONNECT").into(),
        );
    }
    validate_request_head_with_settings(head, true).map_err(NativeH3SessionError::from)?;
    if head.pseudo.protocol.is_none() {
        let authority = head
            .pseudo
            .authority
            .as_deref()
            .expect("validated authority");
        let port = if authority.starts_with('[') {
            authority
                .rsplit_once(']')
                .and_then(|(_, suffix)| suffix.strip_prefix(':'))
        } else {
            authority.rsplit_once(':').map(|(_, port)| port)
        };
        if port.is_none_or(|port| port.is_empty() || port.parse::<u16>().is_err()) {
            return Err(invalid(
                "ordinary CONNECT authority requires an explicit port",
            ));
        }
    }
    if head.headers.iter().any(|(name, _)| {
        ["content-length", "te", "trailer"]
            .iter()
            .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
    }) {
        return Err(invalid(
            "CONNECT setup does not accept content-length, te, or trailer",
        ));
    }
    let mut size = fields_size(&head.headers)?;
    for (name, value) in [
        (":method", head.pseudo.method.as_deref()),
        (":scheme", head.pseudo.scheme.as_deref()),
        (":authority", head.pseudo.authority.as_deref()),
        (":path", head.pseudo.path.as_deref()),
        (":protocol", head.pseudo.protocol.as_deref()),
    ] {
        if let Some(value) = value {
            size = add_field_size(size, name, value)?;
        }
    }
    check_limit(size, config.max_field_section_size, "request fields")?;
    Ok(())
}

fn invalid(message: &'static str) -> NativeH3TunnelError {
    NativeH3ClientError::InvalidMessage(message).into()
}

// Each deadline wake is bound to its own context's clock. Do not translate a
// lab or restricted caller's budget through a foreign poller's wall clock.
struct ContextGuard {
    cx: Cx,
    token: Option<CancelWakerToken>,
    deadline: Option<Time>,
    sleep: Option<Sleep>,
}

impl ContextGuard {
    fn new(cx: Cx) -> Self {
        let deadline = cx.budget().deadline;
        let sleep = cx.budget_deadline_sleep();
        Self {
            cx,
            token: None,
            deadline,
            sleep,
        }
    }

    fn check(&mut self, task: Option<&mut Context<'_>>) -> Result<(), NativeH3TunnelError> {
        if !self.cx.runtime_mask.has(crate::cx::cap::CapMask::IO)
            || self.cx.io_driver_handle().is_none()
        {
            return Err(NativeH3ClientError::Admission(
                "CONNECT requires native I/O authority from owner and poller",
            )
            .into());
        }
        if let Some(deadline) = self.cx.budget().deadline
            && self.deadline.is_none_or(|previous| deadline < previous)
        {
            self.deadline = Some(deadline);
            self.sleep = Some(self.cx.sleep_until_on_clock(deadline));
        }
        if let Some(task) = task {
            self.token = Some(self.cx.refresh_cancel_waker(self.token, task.waker()));
            if let Some(sleep) = &mut self.sleep {
                if Pin::new(sleep).poll_deadline(task).is_ready() {
                    return Err(NativeH3ClientError::TimedOut.into());
                }
            }
        }
        let _owner = (!self.cx.has_timer()).then(|| self.cx.clone().set_current_restricted());
        if self
            .deadline
            .is_some_and(|deadline| self.cx.now_for_observability() >= deadline)
        {
            return Err(NativeH3ClientError::TimedOut.into());
        }
        self.cx
            .checkpoint()
            .map_err(|_| NativeH3ClientError::Cancelled)?;
        Ok(())
    }
}

impl Drop for ContextGuard {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            self.cx.clear_cancel_waker(token);
        }
    }
}

struct TunnelControl {
    caller: ContextGuard,
    ambient: Option<ContextGuard>,
    poller: Option<ContextGuard>,
    deadline: Option<Time>,
    sleep: Option<Sleep>,
}

impl TunnelControl {
    fn new(owner: Cx) -> Self {
        // Preserve even a same-task constructor view: its capability mask may
        // be narrower than the explicit owner's and must survive future moves.
        let ambient = Cx::current().map(ContextGuard::new);
        Self {
            caller: ContextGuard::new(owner),
            ambient,
            poller: None,
            deadline: None,
            sleep: None,
        }
    }

    fn check(&mut self, mut task: Option<&mut Context<'_>>) -> Result<(), NativeH3TunnelError> {
        // A matching task may still be a narrower capability view. Check its
        // mask before deduplicating the cancellation/budget registration.
        let current = Cx::current().ok_or(NativeH3ClientError::Admission(
            "CONNECT requires an active I/O context",
        ))?;
        if !current.runtime_mask.has(crate::cx::cap::CapMask::IO)
            || current.io_driver_handle().is_none()
        {
            return Err(NativeH3ClientError::Admission(
                "CONNECT poller lacks native I/O authority",
            )
            .into());
        }
        let distinct = !Arc::ptr_eq(&current.inner, &self.caller.cx.inner)
            && !self
                .ambient
                .as_ref()
                .is_some_and(|guard| Arc::ptr_eq(&current.inner, &guard.cx.inner));
        if distinct {
            if self
                .poller
                .as_ref()
                .is_none_or(|guard| !Arc::ptr_eq(&current.inner, &guard.cx.inner))
            {
                self.poller = Some(ContextGuard::new(current));
            }
        } else {
            self.poller = None;
        }
        // A poller's budget may tighten a session, but moving the owner to a
        // later task must not extend an already inherited deadline. Map only
        // the remaining duration into the original owner's enforcement clock.
        let now = context_now(&self.caller.cx);
        for guard in std::iter::once(&self.caller)
            .chain(self.ambient.iter())
            .chain(self.poller.iter())
        {
            if let Some(deadline) = guard.cx.budget().deadline {
                let candidate = if Arc::ptr_eq(&guard.cx.inner, &self.caller.cx.inner) {
                    deadline
                } else {
                    let remaining = deadline
                        .as_nanos()
                        .saturating_sub(context_now(&guard.cx).as_nanos());
                    now.saturating_add_nanos(remaining)
                };
                if self.deadline.is_none_or(|previous| candidate < previous) {
                    self.deadline = Some(candidate);
                    self.sleep = Some(self.caller.cx.sleep_until_on_clock(candidate));
                }
            }
        }
        if let (Some(task), Some(sleep)) = (task.as_deref_mut(), self.sleep.as_mut()) {
            if Pin::new(sleep).poll_deadline(task).is_ready() {
                return Err(NativeH3ClientError::TimedOut.into());
            }
        }
        if self.deadline.is_some_and(|deadline| now >= deadline) {
            return Err(NativeH3ClientError::TimedOut.into());
        }
        self.caller.check(task.as_deref_mut())?;
        if let Some(ambient) = &mut self.ambient {
            ambient.check(task.as_deref_mut())?;
        }
        if let Some(poller) = &mut self.poller {
            poller.check(task)?;
        }
        Ok(())
    }
}

fn context_now(cx: &Cx) -> Time {
    let _owner = (!cx.has_timer()).then(|| cx.clone().set_current_restricted());
    cx.now_for_observability()
}

async fn drive_controlled<F: Future>(
    control: &mut TunnelControl,
    future: F,
) -> Result<F::Output, NativeH3TunnelError> {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|task| {
        control.check(Some(task))?;
        let _owner = control.caller.cx.clone().set_current_restricted();
        future.as_mut().poll(task).map(Ok)
    })
    .await
}

#[cfg(test)]
mod tests;
