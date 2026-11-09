//! An owned RFC 8441 tunnel, driven only by its caller.

use super::{
    Cancellation, DATA_CHUNK, Http2ClientError, Http2ClientIo, Http2Conn, Http2RequestBuilder,
    MIN_RECEIVE_WINDOW, POLL_STEPS, RequestControl, ResponseState, budget_now, context_now,
    invalid, is_overhead_frame, protocol, require_native_io,
};
use crate::bytes::Bytes;
use crate::cx::Cx;
use crate::http::h2::connection::ReceivedFrame;
use crate::http::h2::{ConnectionState, ErrorCode, Header};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::stream::Stream;
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::Time;
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Finite lifetime DATA limits for an extended CONNECT tunnel.
///
/// These limits count application bytes in each direction, including protocol
/// framing carried inside DATA. They do not allocate buffers of the given size.
/// The transport retains at most 65,535 unread DATA bytes, one accepted 16 KiB
/// write, and bounded HTTP/2 framing/header buffers. A sender blocked by peer
/// flow control still processes connection control frames and bounded inbound
/// DATA; applications must consume input to replenish its stream credit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http2TunnelConfig {
    max_send_bytes: NonZeroU64,
    max_receive_bytes: NonZeroU64,
}

impl Http2TunnelConfig {
    /// Set explicit, nonzero maximum cumulative DATA bytes in each direction.
    #[must_use]
    pub fn new(max_send_bytes: NonZeroU64, max_receive_bytes: NonZeroU64) -> Self {
        Self {
            max_send_bytes,
            max_receive_bytes,
        }
    }

    /// Maximum cumulative DATA bytes accepted from the application.
    #[must_use]
    pub fn max_send_bytes(&self) -> u64 {
        self.max_send_bytes.get()
    }

    /// Maximum cumulative DATA bytes accepted from the peer.
    #[must_use]
    pub fn max_receive_bytes(&self) -> u64 {
        self.max_receive_bytes.get()
    }
}

/// Failure to establish an owned extended CONNECT tunnel.
#[derive(Debug)]
#[non_exhaustive]
pub enum Http2TunnelError {
    /// Request validation, transport, protocol, cancellation, or setup deadline.
    Client(Http2ClientError),
    /// The peer did not enable extended CONNECT before the setup deadline.
    NotNegotiated,
    /// Final HTTP status did not accept the tunnel. No response body is retained.
    Rejected(u16),
}

impl fmt::Display for Http2TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(error) => error.fmt(f),
            Self::NotNegotiated => f.write_str("HTTP/2 peer did not enable extended CONNECT"),
            Self::Rejected(status) => write!(f, "HTTP/2 CONNECT was rejected with status {status}"),
        }
    }
}

impl std::error::Error for Http2TunnelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Client(error) => Some(error),
            _ => None,
        }
    }
}

impl From<Http2ClientError> for Http2TunnelError {
    fn from(error: Http2ClientError) -> Self {
        Self::Client(error)
    }
}

/// An owned, bounded, bidirectional HTTP/2 extended CONNECT stream.
///
/// The tunnel owns its entire connection and drives it during reads, writes,
/// flushes, and shutdown. It does not spawn a driver, retry, redirect, or use the
/// client's idle pool. Other calls on the client own independent connections.
///
/// The setup timeout ends when the successful response headers are accepted.
/// The original caller and polling task cancellation, inherited Cx deadlines,
/// and explicit lifetime DATA limits continue to apply. Dropping the tunnel
/// immediately drops its transport; no background drain survives it.
///
/// A successful write accepts its bytes into a bounded owned buffer. Dropping
/// the corresponding future cannot attribute those bytes to a later write.
/// Reading also advances accepted writes. Shutdown flushes all accepted bytes
/// and sends request END_STREAM; response END_STREAM independently completes
/// the read half. Both halves must complete before normal transport retirement.
///
/// The supplied-transport API accepts borrowed and non-Send transports. A
/// native tunnel requires native I/O authority from both owner and poller.
#[must_use = "an HTTP/2 tunnel makes progress only while polled"]
pub struct Http2Tunnel<T> {
    // Transport retirement precedes cancellation-Waker and metadata destruction.
    conn: Option<Http2Conn<T>>,
    control: Option<SessionControl>,
    owner: Cx,
    native: bool,
    config: Http2TunnelConfig,
    stream_id: u32,
    status: u16,
    headers: Vec<Header>,
    incoming: Vec<u8>,
    read_offset: usize,
    credit_due: u32,
    pending: Option<Bytes>,
    pending_offset: usize,
    sent_bytes: u64,
    received_bytes: u64,
    remote_eof: bool,
    shutdown_requested: bool,
    local_eof_queued: bool,
    local_eof_flushed: bool,
    failed: bool,
    poisoned: bool,
}

impl<T> fmt::Debug for Http2Tunnel<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http2Tunnel")
            .field("stream_id", &self.stream_id)
            .field("status", &self.status)
            .field("sent_bytes", &self.sent_bytes)
            .field("received_bytes", &self.received_bytes)
            .field("read_closed", &self.remote_eof)
            .field("write_closed", &self.local_eof_flushed)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl<T> Drop for Http2Tunnel<T> {
    fn drop(&mut self) {
        let _owner = self.owner.clone().set_current_restricted();
        drop(self.conn.take());
        drop(self.control.take());
    }
}

impl<T> Http2Tunnel<T> {
    /// The successful final HTTP status.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Final response fields, excluding the :status pseudoheader.
    #[must_use]
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    /// First final response field with this case-insensitive name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    /// DATA bytes accepted by successful writes, including bytes awaiting flush.
    #[must_use]
    pub fn sent_bytes(&self) -> u64 {
        self.sent_bytes
    }

    /// DATA bytes received from the peer, including unread bytes.
    #[must_use]
    pub fn received_bytes(&self) -> u64 {
        self.received_bytes
    }

    /// Whether both END_STREAM directions completed and the transport retired.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        !self.failed && self.remote_eof && self.local_eof_flushed && self.conn.is_none()
    }

    /// Immediately retire the owned transport without a graceful drain.
    ///
    /// This has the same transport ownership effect as dropping the tunnel.
    /// It does not claim delivery of a reset frame after cancellation.
    pub fn abort(&mut self) {
        self.failed = true;
        let _owner = self.owner.clone().set_current_restricted();
        drop(self.conn.take());
        drop(self.control.take());
        self.pending = None;
        self.incoming.clear();
        self.read_offset = 0;
        self.credit_due = 0;
    }
}

impl Http2RequestBuilder {
    /// Establish a native RFC 8441 extended CONNECT tunnel.
    ///
    /// The builder must use CONNECT and have no buffered body, Content-Length,
    /// TE, or Trailer field. Protocol and regular headers are validated before
    /// dialing. Initial SETTINGS are processed before :protocol is sent. A peer
    /// may enable the protocol in a later SETTINGS within the setup deadline.
    /// A 2xx response must leave the stream open. Its Content-Length is ignored
    /// as required for CONNECT; subsequent trailers are refused. No fallback,
    /// replay, idle pooling, or background task occurs.
    ///
    /// DNS, happy-eyeballs TCP, TLS/h2 ALPN, settings, and response headers share
    /// the existing client/request timeout. That timeout is retired on success;
    /// only Cx budgets/cancellation and the supplied DATA limits remain.
    pub fn connect_tunnel(
        self,
        cx: &Cx,
        protocol_name: &str,
        config: Http2TunnelConfig,
    ) -> impl Future<Output = Result<Http2Tunnel<Http2ClientIo>, Http2TunnelError>> + use<> {
        let owner = cx.clone();
        let protocol_name = bounded_protocol_name(protocol_name);
        async move {
            let request = self.prepare_tunnel(&protocol_name?)?;
            require_native_io(&owner)?;
            let timeout = self
                .timeout
                .unwrap_or(self.client.timeout)
                .min(self.client.timeout);
            let mut control = RequestControl::new(&owner, timeout);
            let mut conn = {
                let setup = owner.with_ambient(async {
                    self.client.validate_native_target(&owner, &request.url)?;
                    let transport = self.client.connect_transport(&request.url).await?;
                    Http2Conn::start(
                        transport,
                        MIN_RECEIVE_WINDOW as usize,
                        self.client.max_overhead_frames,
                    )
                    .await
                });
                let mut setup = std::pin::pin!(setup);
                control
                    .drive(poll_fn(|task| {
                        require_native_io(&owner)?;
                        setup.as_mut().poll(task)
                    }))
                    .await?
            };
            let (stream_id, response) =
                open(&mut conn, &mut control, request.headers, true).await?;
            Ok(Http2Tunnel::new(
                conn, control, owner, true, config, stream_id, response,
            ))
        }
    }

    /// Establish a tunnel on an owned caller-supplied transport.
    ///
    /// Starts with the HTTP/2 client preface. The URL is routing metadata and
    /// is never dialed. The caller validates any TLS identity and h2 ALPN.
    /// Dropping even an unpolled future drops the supplied transport. The
    /// limits, negotiation, setup budget, and independent halves are identical
    /// to connect_tunnel.
    pub fn connect_tunnel_on<T>(
        self,
        cx: &Cx,
        transport: T,
        protocol_name: &str,
        config: Http2TunnelConfig,
    ) -> impl Future<Output = Result<Http2Tunnel<T>, Http2TunnelError>> + use<T>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let owner = cx.clone();
        let protocol_name = bounded_protocol_name(protocol_name);
        async move {
            let request = self.prepare_tunnel(&protocol_name?)?;
            let timeout = self
                .timeout
                .unwrap_or(self.client.timeout)
                .min(self.client.timeout);
            let mut control = RequestControl::new(&owner, timeout);
            let mut conn = control
                .drive(owner.with_ambient(Http2Conn::start(
                    transport,
                    MIN_RECEIVE_WINDOW as usize,
                    self.client.max_overhead_frames,
                )))
                .await?;
            let (stream_id, response) =
                open(&mut conn, &mut control, request.headers, false).await?;
            Ok(Http2Tunnel::new(
                conn, control, owner, false, config, stream_id, response,
            ))
        }
    }

    fn prepare_tunnel(
        &self,
        protocol_name: &str,
    ) -> Result<super::PreparedRequest, Http2ClientError> {
        if !self.body.is_empty() {
            return Err(invalid("extended CONNECT cannot contain a buffered body"));
        }
        let mut parts = protocol_name.split('/');
        let token = |part: &str| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_\x60|~".contains(&b))
        };
        if protocol_name.len() > 256
            || !parts.next().is_some_and(token)
            || parts.next().is_some_and(|part| !token(part))
            || parts.next().is_some()
        {
            return Err(invalid("invalid extended CONNECT protocol"));
        }
        self.prepare_request(None, Some(protocol_name))
    }
}

fn bounded_protocol_name(name: &str) -> Result<String, Http2ClientError> {
    if name.len() > 256 {
        Err(invalid("extended CONNECT protocol exceeds 256 bytes"))
    } else {
        Ok(name.to_owned())
    }
}

async fn open<T>(
    conn: &mut Http2Conn<T>,
    control: &mut RequestControl,
    headers: Vec<Header>,
    native: bool,
) -> Result<(u32, ResponseState), Http2TunnelError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut headers = Some(headers);
    let mut stream_id = None;
    // Only metadata is retained during opening; no response body is collected.
    let mut response = ResponseState::new(false, usize::MAX);
    poll_fn(|task| {
        if native {
            require_native_io(&control.caller.cx)?;
        }
        if let Err(error) = control.check(task) {
            return Poll::Ready(Err(
                if matches!(error, Http2ClientError::DeadlineExceeded)
                    && conn.connection.state() == ConnectionState::Open
                    && !conn.wire.codec().peer_supports_extended_connect()
                {
                    Http2TunnelError::NotNegotiated
                } else {
                    error.into()
                },
            ));
        }
        let _owner = control.caller.cx.clone().set_current_restricted();
        for _ in 0..POLL_STEPS {
            let mut progress = false;
            match Pin::new(&mut conn.wire).poll_next(task) {
                Poll::Ready(Some(Ok(frame))) => {
                    progress = true;
                    account_overhead(conn, &frame)?;
                    match conn
                        .connection
                        .process_frame(frame)
                        .map_err(Http2ClientError::from)?
                    {
                        Some(ReceivedFrame::Headers {
                            stream_id: id,
                            headers,
                            end_stream,
                        }) if Some(id) == stream_id => {
                            response.headers_with_connect_semantics(headers, end_stream, true)?;
                            if response.response.status != 0 {
                                let status = response.response.status;
                                if !(200..300).contains(&status) {
                                    return Poll::Ready(Err(Http2TunnelError::Rejected(status)));
                                }
                                if end_stream {
                                    return Poll::Ready(Err(protocol(
                                        "successful CONNECT must leave the stream open",
                                    )
                                    .into()));
                                }
                                conn.connection
                                    .defer_stream_receive_window(id)
                                    .map_err(Http2ClientError::from)?;
                                control.check(task)?;
                                return Poll::Ready(Ok(()));
                            }
                        }
                        Some(ReceivedFrame::Reset {
                            stream_id: id,
                            error_code,
                        }) if Some(id) == stream_id => {
                            return Poll::Ready(Err(Http2ClientError::Reset(error_code).into()));
                        }
                        Some(ReceivedFrame::GoAway {
                            last_stream_id,
                            error_code,
                            ..
                        }) => {
                            return Poll::Ready(Err(Http2ClientError::GoAway {
                                last_stream_id,
                                error_code,
                            }
                            .into()));
                        }
                        Some(_) => {
                            return Poll::Ready(Err(protocol(
                                "unexpected frame during extended CONNECT opening",
                            )
                            .into()));
                        }
                        None => {}
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    let error = conn
                        .wire
                        .get_mut()
                        .read_error
                        .take()
                        .map_or_else(|| error.into(), Http2ClientError::Io);
                    return Poll::Ready(Err(error.into()));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(Http2ClientError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "peer closed during extended CONNECT opening",
                    ))
                    .into()));
                }
                Poll::Pending => {}
            }
            if stream_id.is_none()
                && conn.connection.state() == ConnectionState::Open
                && conn.wire.codec().peer_supports_extended_connect()
                && conn.connection.remote_settings().max_concurrent_streams != 0
            {
                stream_id = Some(
                    conn.connection
                        .open_extended_connect(
                            headers.take().expect("opening headers retained"),
                            conn.wire.codec(),
                        )
                        .map_err(Http2ClientError::from)?,
                );
                progress = true;
            }
            progress |= flush_one(conn, task)?.0;
            if !progress {
                return Poll::Pending;
            }
        }
        task.waker().wake_by_ref();
        Poll::Pending
    })
    .await?;
    Ok((stream_id.expect("accepted response has a stream"), response))
}

fn account_overhead<T>(
    conn: &mut Http2Conn<T>,
    frame: &crate::http::h2::Frame,
) -> Result<(), Http2ClientError> {
    if is_overhead_frame(frame, &conn.connection, &mut conn.settings_acked) {
        if conn.overhead_frames >= conn.max_overhead_frames {
            return Err(crate::http::h2::H2Error::connection(
                ErrorCode::EnhanceYourCalm,
                "HTTP/2 connection frame overhead limit exceeded",
            )
            .into());
        }
        conn.overhead_frames += 1;
    }
    Ok(())
}

fn flush_one<T>(
    conn: &mut Http2Conn<T>,
    task: &mut Context<'_>,
) -> Result<(bool, bool), Http2ClientError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut progress = false;
    if conn.connection.has_pending_frames() {
        match conn.wire.poll_ready(task) {
            Poll::Ready(Ok(())) => {
                if let Some(frame) = conn.connection.next_frame() {
                    conn.wire.start_send(frame)?;
                    progress = true;
                }
            }
            Poll::Ready(Err(error)) => return Err(error.into()),
            Poll::Pending => {}
        }
    }
    let buffered = !conn.wire.write_buffer().is_empty();
    match conn.wire.poll_flush(task) {
        Poll::Ready(Ok(())) => Ok((progress || buffered, true)),
        Poll::Ready(Err(error)) => Err(error.into()),
        Poll::Pending => Ok((progress, false)),
    }
}

/// The original authority survives opening; the setup timer does not.
struct SessionControl {
    caller: Cancellation,
    ambient: Option<Cancellation>,
    poller: Option<Cancellation>,
    driver: Option<TimerDriverHandle>,
    deadline: Option<Time>,
    sleep: Option<Sleep>,
}

impl SessionControl {
    fn from_setup(control: RequestControl) -> Self {
        let RequestControl {
            caller,
            ambient,
            driver,
            sleep,
            ..
        } = control;
        drop(sleep);
        let mut session = Self {
            caller,
            ambient,
            driver,
            poller: None,
            deadline: None,
            sleep: None,
        };
        session.tighten_budgets();
        session
    }

    fn now(&self) -> Time {
        self.driver
            .as_ref()
            .map_or_else(|| context_now(&self.caller.cx), TimerDriverHandle::now)
    }

    fn tighten_budgets(&mut self) {
        let now = self.now();
        let mut deadline = self.deadline;
        for guard in std::iter::once(&self.caller)
            .chain(self.ambient.iter())
            .chain(self.poller.iter())
        {
            if let Some(budget) = guard.cx.budget().deadline {
                let remaining = budget
                    .as_nanos()
                    .saturating_sub(budget_now(&guard.cx).as_nanos());
                let candidate = now.saturating_add_nanos(remaining);
                deadline = Some(deadline.map_or(candidate, |existing| existing.min(candidate)));
            }
        }
        if deadline != self.deadline {
            self.deadline = deadline;
            if let Some(deadline) = deadline {
                if let Some(sleep) = &mut self.sleep {
                    sleep.reset(deadline);
                } else {
                    self.sleep = Some(self.driver.as_ref().map_or_else(
                        || Sleep::new(deadline),
                        |driver| Sleep::with_timer_driver(deadline, driver.clone()),
                    ));
                }
            }
        }
    }

    fn check(&mut self, task: &mut Context<'_>, native: bool) -> Result<(), Http2ClientError> {
        if native {
            require_native_io(&self.caller.cx)?;
        }
        let current = Cx::current().filter(|current| {
            !Arc::ptr_eq(&current.inner, &self.caller.cx.inner)
                && !self
                    .ambient
                    .as_ref()
                    .is_some_and(|a| Arc::ptr_eq(&current.inner, &a.cx.inner))
        });
        if let Some(current) = current {
            if self
                .poller
                .as_ref()
                .is_none_or(|p| !Arc::ptr_eq(&p.cx.inner, &current.inner))
            {
                self.poller = Some(Cancellation::new(current));
            }
        } else {
            self.poller = None;
        }
        self.caller.register(task.waker());
        if let Some(guard) = &mut self.ambient {
            guard.register(task.waker());
        }
        if let Some(guard) = &mut self.poller {
            guard.register(task.waker());
        }
        self.tighten_budgets();
        if self.deadline.is_some_and(|deadline| self.now() >= deadline) {
            return Err(Http2ClientError::DeadlineExceeded);
        }
        self.caller.check()?;
        if let Some(guard) = &self.ambient {
            guard.check()?;
        }
        if let Some(guard) = &self.poller {
            guard.check()?;
        }
        if let Some(sleep) = &mut self.sleep {
            let _owner = self
                .driver
                .is_none()
                .then(|| self.caller.cx.clone().set_current_restricted());
            if Pin::new(&mut *sleep).poll_deadline(task).is_ready() {
                sleep.reset(self.deadline.expect("timer has an explicit deadline"));
                task.waker().wake_by_ref();
            }
        }
        Ok(())
    }
}

impl<T> Http2Tunnel<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[allow(clippy::too_many_arguments)]
    fn new(
        conn: Http2Conn<T>,
        control: RequestControl,
        owner: Cx,
        native: bool,
        config: Http2TunnelConfig,
        stream_id: u32,
        mut response: ResponseState,
    ) -> Self {
        Self {
            conn: Some(conn),
            control: Some(SessionControl::from_setup(control)),
            owner,
            native,
            config,
            stream_id,
            status: response.response.status,
            headers: std::mem::take(&mut response.response.headers),
            incoming: Vec::with_capacity(MIN_RECEIVE_WINDOW as usize),
            read_offset: 0,
            credit_due: 0,
            pending: None,
            pending_offset: 0,
            sent_bytes: 0,
            received_bytes: 0,
            remote_eof: false,
            shutdown_requested: false,
            local_eof_queued: false,
            local_eof_flushed: false,
            failed: false,
            poisoned: false,
        }
    }

    fn check(&mut self, task: &mut Context<'_>) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "HTTP/2 tunnel retired",
            ));
        }
        if self.poisoned {
            self.abort();
            return Err(io::Error::other("HTTP/2 tunnel resumed after a panic"));
        }
        if let Some(control) = &mut self.control
            && let Err(error) = control.check(task, self.native)
        {
            self.abort();
            return Err(tunnel_io_error(error));
        }
        Ok(())
    }

    fn poll_drive(&mut self, task: &mut Context<'_>) -> io::Result<bool> {
        self.check(task)?;
        if self.conn.is_none() {
            return Ok(true);
        }
        self.poisoned = true;
        let _owner = self.owner.clone().set_current_restricted();
        let result = self.drive_inner(task);
        self.poisoned = false;
        match result {
            Ok(flushed) => {
                if self.remote_eof && self.local_eof_flushed {
                    drop(self.conn.take());
                    drop(self.control.take());
                }
                Ok(flushed)
            }
            Err(error) => {
                self.abort();
                Err(tunnel_io_error(error))
            }
        }
    }

    fn drive_inner(&mut self, task: &mut Context<'_>) -> Result<bool, Http2ClientError> {
        let mut transport_flushed = false;
        for _ in 0..POLL_STEPS {
            let conn = self.conn.as_mut().expect("live tunnel");
            let mut progress = false;
            if self.credit_due != 0 {
                conn.connection
                    .release_stream_receive_capacity(self.stream_id, self.credit_due)?;
                self.credit_due = 0;
                progress = true;
            }
            match Pin::new(&mut conn.wire).poll_next(task) {
                Poll::Ready(Some(Ok(frame))) => {
                    progress = true;
                    account_overhead(conn, &frame)?;
                    match conn.connection.process_frame(frame)? {
                        Some(ReceivedFrame::Data {
                            stream_id,
                            data,
                            end_stream,
                        }) if stream_id == self.stream_id => {
                            if data.len() as u64
                                > self
                                    .config
                                    .max_receive_bytes()
                                    .saturating_sub(self.received_bytes)
                            {
                                return Err(protocol("HTTP/2 tunnel receive byte limit exceeded"));
                            }
                            if data.len()
                                > (MIN_RECEIVE_WINDOW as usize)
                                    .saturating_sub(self.incoming.len() - self.read_offset)
                            {
                                return Err(protocol(
                                    "HTTP/2 tunnel receive staging limit exceeded",
                                ));
                            }
                            if self.read_offset != 0 {
                                let unread = self.incoming.len() - self.read_offset;
                                self.incoming.copy_within(self.read_offset.., 0);
                                self.incoming.truncate(unread);
                                self.read_offset = 0;
                            }
                            self.received_bytes += data.len() as u64;
                            self.incoming.extend_from_slice(&data);
                            self.remote_eof |= end_stream;
                        }
                        Some(ReceivedFrame::Headers { stream_id, .. })
                            if stream_id == self.stream_id =>
                        {
                            return Err(protocol("HTTP/2 tunnel trailers are forbidden"));
                        }
                        Some(ReceivedFrame::Reset {
                            stream_id,
                            error_code,
                        }) if stream_id == self.stream_id => {
                            return Err(Http2ClientError::Reset(error_code));
                        }
                        Some(ReceivedFrame::GoAway {
                            last_stream_id,
                            error_code,
                            ..
                        }) => {
                            if error_code != ErrorCode::NoError || self.stream_id > last_stream_id {
                                return Err(Http2ClientError::GoAway {
                                    last_stream_id,
                                    error_code,
                                });
                            }
                        }
                        Some(_) => return Err(protocol("unexpected HTTP/2 tunnel stream")),
                        None => {}
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    return Err(conn
                        .wire
                        .get_mut()
                        .read_error
                        .take()
                        .map_or_else(|| error.into(), Http2ClientError::Io));
                }
                Poll::Ready(None) => {
                    if !(self.remote_eof && self.local_eof_flushed) {
                        return Err(Http2ClientError::Io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "HTTP/2 connection closed before both tunnel halves",
                        )));
                    }
                }
                Poll::Pending => {}
            }
            let (wrote, flushed) = flush_one(conn, task)?;
            transport_flushed = flushed;
            progress |= wrote;
            if flushed
                && !conn.connection.has_pending_frames()
                && conn.wire.write_buffer().is_empty()
            {
                if let Some(pending) = &self.pending {
                    let capacity = conn
                        .connection
                        .available_send_capacity(self.stream_id)
                        .min(DATA_CHUNK);
                    if capacity != 0 {
                        let length = capacity.min(pending.len() - self.pending_offset);
                        conn.connection.send_data(
                            self.stream_id,
                            pending.slice(self.pending_offset..self.pending_offset + length),
                            false,
                        )?;
                        self.pending_offset += length;
                        if self.pending_offset == pending.len() {
                            self.pending = None;
                            self.pending_offset = 0;
                        }
                        progress = true;
                    }
                } else if self.shutdown_requested && !self.local_eof_queued {
                    // Empty END_STREAM spends no DATA flow-control credit.
                    conn.connection
                        .send_data(self.stream_id, Bytes::new(), true)?;
                    self.local_eof_queued = true;
                    progress = true;
                } else if self.local_eof_queued {
                    self.local_eof_flushed = true;
                }
            }
            let drained = flushed
                && self.pending.is_none()
                && !conn.connection.has_pending_frames()
                && conn.wire.write_buffer().is_empty();
            if self.remote_eof && self.local_eof_flushed {
                return Ok(true);
            }
            if !progress {
                return Ok(drained);
            }
        }
        task.waker().wake_by_ref();
        let conn = self.conn.as_ref().expect("live tunnel");
        Ok(transport_flushed
            && self.pending.is_none()
            && !conn.connection.has_pending_frames()
            && conn.wire.write_buffer().is_empty())
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for Http2Tunnel<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        task: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        self.poll_drive(task)?;
        let available = self.incoming.len() - self.read_offset;
        if available != 0 {
            let length = available.min(buf.remaining());
            buf.put_slice(&self.incoming[self.read_offset..self.read_offset + length]);
            self.read_offset += length;
            self.credit_due += length as u32;
            if self.read_offset == self.incoming.len() {
                self.incoming.clear();
                self.read_offset = 0;
            }
            return Poll::Ready(Ok(()));
        }
        if self.remote_eof {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Http2Tunnel<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        task: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check(task)?;
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.shutdown_requested {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "HTTP/2 write half closed",
            )));
        }
        self.poll_drive(task)?;
        if self.pending.is_some() {
            return Poll::Pending;
        }
        let remaining = self.config.max_send_bytes().saturating_sub(self.sent_bytes);
        if remaining == 0 {
            self.abort();
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP/2 tunnel send byte limit exceeded",
            )));
        }
        let length = bytes
            .len()
            .min(DATA_CHUNK)
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        self.pending = Some(Bytes::copy_from_slice(&bytes[..length]));
        self.sent_bytes += length as u64;
        // The byte receipt is published with ownership; later polls only flush.
        Poll::Ready(Ok(length))
    }

    fn poll_flush(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drive(task) {
            Ok(true) => Poll::Ready(Ok(())),
            Ok(false) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check(task)?;
        self.shutdown_requested = true;
        self.poll_drive(task)?;
        if self.local_eof_flushed {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

fn tunnel_io_error(error: Http2ClientError) -> io::Error {
    let (kind, message) = match error {
        Http2ClientError::Cancelled(_) => (io::ErrorKind::Interrupted, "HTTP/2 tunnel cancelled"),
        Http2ClientError::DeadlineExceeded => {
            (io::ErrorKind::TimedOut, "HTTP/2 tunnel deadline elapsed")
        }
        Http2ClientError::MissingIoCapability => (
            io::ErrorKind::PermissionDenied,
            "HTTP/2 tunnel lacks I/O authority",
        ),
        Http2ClientError::Io(error) => (error.kind(), "HTTP/2 tunnel transport failed"),
        Http2ClientError::Reset(_) => (
            io::ErrorKind::ConnectionReset,
            "HTTP/2 tunnel reset by peer",
        ),
        Http2ClientError::GoAway { .. } => (
            io::ErrorKind::ConnectionAborted,
            "HTTP/2 tunnel refused by GOAWAY",
        ),
        _ => (
            io::ErrorKind::InvalidData,
            "HTTP/2 tunnel protocol or byte limit failed",
        ),
    };
    io::Error::new(kind, message)
}
