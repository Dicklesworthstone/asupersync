//! Owned, authenticated HTTP/3 service over the native managed UDP endpoint.

use std::net::SocketAddr;
use std::num::NonZeroUsize;

use super::*;
use crate::bytes::BytesCursor;
use crate::channel::oneshot;
use crate::cx::{ChildRegion, ChildRegionError, ChildRegionOpening, ChildRegionSpec};
use crate::http::body::{Frame, HeaderMap, HeaderName, HeaderValue};
use crate::http::h1::stream::{
    FramedIncomingRequestBodyWriter, IncomingBodyError, IncomingRequestBody,
};
use crate::http::h3::NativeH3SessionError;
use crate::net::quic_core::{ConnectionId, TransportParameters};
use crate::net::quic_native::{ManagedEndpointConfig, ManagedEndpointError, ManagedQuicEndpoint};
use crate::runtime::TaskHandle;
use crate::types::{CancelReason, Outcome};
use crate::web::request_region::ServerRequestDeadline;

/// Resource and lifetime limits for [`NativeH3Listener`].
///
/// Incomplete request bodies are bounded by `router` on each connection;
/// `max_concurrent_requests` additionally bounds scheduler-owned request work
/// across every peer. A request retains that global slot through region close.
/// These body budgets exclude QUIC reassembly and H3 parser storage, which are
/// separately bounded by negotiated stream counts, receive windows and the
/// native session's frame-size limit.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NativeH3ListenerConfig {
    /// Managed UDP/QUIC limits. `bind` always selects the server role.
    pub endpoint: ManagedEndpointConfig,
    /// Per-connection request assembly and dispatch limits.
    pub router: NativeH3RouterConfig,
    /// Maximum admitted request regions across all connections.
    pub max_concurrent_requests: usize,
    /// Concurrent TLS handshakes, further capped by `endpoint.max_connections`.
    pub max_pending_handshakes: usize,
    /// Finite request-stream lifetime per connection (at most 4096). The
    /// advertised bidirectional stream count is clamped to this ceiling.
    /// Reaching it sends GOAWAY and retires the connection after its work drains.
    pub max_requests_per_connection: u64,
    /// Sliding receive window for each observed peer stream. Previously
    /// advertised initial credit cannot be retracted; this controls growth.
    pub receive_window_bytes: u64,
    /// Maximum ingress and produced-response events per connection per poll.
    /// Every connection and admitted request receives a turn before repolling.
    pub application_batch_size: usize,
    /// Deadline from the first request-stream bytes through response completion,
    /// including partial HEADERS, body assembly, handlers and produced bodies.
    pub request_timeout: Duration,
    /// Cancellation grace for request work and its region finalizers.
    pub request_drain_timeout: Duration,
    /// Maximum time to drain requests after the shutdown future completes.
    pub drain_timeout: Duration,
    /// Maximum buffered response body retained after a handler returns.
    /// Larger responses should use [`crate::web::Http3StreamResponder`].
    pub max_buffered_response_bytes: usize,
    /// Opt in to live request bodies dispatched after validated HEADERS.
    ///
    /// This bounds queued body bytes per request. The listener also retains
    /// at most one pending DATA chunk or trailer map of `min(bytes, 16 KiB)`;
    /// their sum is reserved against `router`'s aggregate body budget before
    /// admission. Trailer accounting includes each name, value, and four
    /// bytes of internal per-field accounting. One trailer map is supported.
    /// The per-request body-size limit and matched Router policy still apply
    /// to the entire upload, independently of this queue size.
    ///
    /// Handlers consume [`crate::web::StreamingRawBody`]. Buffered body
    /// extractors fail closed in this mode. `None` preserves complete-body
    /// dispatch and the existing buffered extractor behavior.
    pub streaming_request_body_buffer_bytes: Option<NonZeroUsize>,
}

impl Default for NativeH3ListenerConfig {
    fn default() -> Self {
        Self {
            endpoint: ManagedEndpointConfig {
                is_server: true,
                max_connections: 64,
                ..ManagedEndpointConfig::default()
            },
            router: NativeH3RouterConfig::default(),
            max_concurrent_requests: 128,
            max_pending_handshakes: 16,
            max_requests_per_connection: 128,
            receive_window_bytes: 64 * 1024,
            application_batch_size: 8,
            request_timeout: Duration::from_secs(30),
            request_drain_timeout: Duration::from_millis(100),
            drain_timeout: Duration::from_secs(5),
            max_buffered_response_bytes: 16 * 1024 * 1024,
            streaming_request_body_buffer_bytes: None,
        }
    }
}

/// Final accounting after every admitted request region has closed.
///
/// Completed responses have left QUIC stream packet assembly. Successful
/// graceful shutdown also empties the endpoint's UDP staging queue; neither
/// condition is an acknowledgement that the peer application consumed data.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct NativeH3ListenerReport {
    /// Authenticated peers for which an H3 session was initialized.
    pub accepted_connections: u64,
    /// Failed admissions or connection-local protocol/transport failures.
    pub failed_connections: u64,
    /// Responses drained and request regions successfully closed.
    pub completed_requests: u64,
    /// Requests refused before scheduler admission.
    pub refused_requests: u64,
    /// Admitted requests cancelled, failed, or reset before completion.
    pub cancelled_requests: u64,
    /// The graceful deadline forced cancellation of remaining work.
    pub drain_timed_out: bool,
}

/// Failure to configure, drive, or close the owned H3 service.
#[derive(Debug)]
#[non_exhaustive]
pub enum NativeH3ListenerError {
    /// UDP, QUIC, TLS admission, or listener configuration failure.
    Endpoint(ManagedEndpointError),
    /// The runtime could not close an admitted request region.
    Ownership(ChildRegionError),
    /// A region finalizer failed or exhausted its shutdown budget.
    CleanupFailed,
}

impl std::fmt::Display for NativeH3ListenerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Endpoint(error) => write!(formatter, "HTTP/3 listener: {error}"),
            Self::Ownership(error) => write!(formatter, "HTTP/3 request ownership: {error}"),
            Self::CleanupFailed => formatter.write_str("HTTP/3 request region cleanup failed"),
        }
    }
}

impl std::error::Error for NativeH3ListenerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Endpoint(error) => Some(error),
            Self::Ownership(error) => Some(error),
            Self::CleanupFailed => None,
        }
    }
}

impl From<ManagedEndpointError> for NativeH3ListenerError {
    fn from(error: ManagedEndpointError) -> Self {
        Self::Endpoint(error)
    }
}

/// A bound native UDP listener that authenticates peers and serves a [`Router`].
///
/// This surface requires `http3` and `tls`. It owns the TLS/H3 session pump,
/// concurrent request tasks, buffered and produced responses, cancellation,
/// and bounded graceful shutdown. Every handler and body producer receives an
/// actual scheduler-admitted request [`Cx`], with its spawn gateway intact.
/// There are no background tasks detached from the caller's region.
///
/// Request bodies are assembled within explicit limits by default. Enabling
/// [`NativeH3ListenerConfig::streaming_request_body_buffer_bytes`] dispatches
/// validated HEADERS before FIN and passes live bounded input to
/// [`crate::web::StreamingRawBody`]. Streaming request trailers are delivered
/// as one bounded ordinary header map; successful input EOF still requires
/// FIN. CONNECT and buffered-mode request trailers retain the bridge's
/// explicit refusal behavior. Response producers may send DATA and response
/// trailers. Buffered response limits are applied before listener retention
/// and encoding, after application code creates them.
pub struct NativeH3Listener {
    endpoint: ManagedQuicEndpoint,
    router: Arc<Router>,
    config: NativeH3ListenerConfig,
    max_peer_uni_streams: u64,
}

impl NativeH3Listener {
    /// Bind a socket and configure autonomous, certificate-authenticated H3.
    ///
    /// TLS must advertise `h3`. Transport parameters use the native QUIC wire
    /// representation and are validated by the authenticated endpoint. The
    /// context must carry both runtime spawning and timer capabilities.
    pub async fn bind(
        cx: &Cx,
        address: SocketAddr,
        router: Router,
        tls: Arc<rustls::ServerConfig>,
        transport_parameters: Vec<u8>,
        mut config: NativeH3ListenerConfig,
    ) -> Result<Self, NativeH3ListenerError> {
        if config.max_concurrent_requests == 0
            || config.max_pending_handshakes == 0
            || !(1..=4096).contains(&config.max_requests_per_connection)
            || config.receive_window_bytes == 0
            || config.receive_window_bytes > (1_u64 << 62) - 1
            || config.application_batch_size == 0
            || config.endpoint.max_connections == 0
            || config.request_timeout.is_zero()
            || config.request_drain_timeout.is_zero()
            || config.drain_timeout.is_zero()
            || config
                .streaming_request_body_buffer_bytes
                .is_some_and(|bytes| {
                    bytes
                        .get()
                        .checked_add(streaming_chunk_bytes(bytes))
                        .is_none()
                })
        {
            return Err(ManagedEndpointError::InvalidConfig(
                "HTTP/3 listener counts and lifetime limits must be nonzero".to_string(),
            )
            .into());
        }
        if cx.spawn_gateway_handle().is_none() || cx.timer_driver().is_none() {
            return Err(ManagedEndpointError::InvalidConfig(
                "HTTP/3 listener requires a runtime-owned Cx with spawning and timers".to_string(),
            )
            .into());
        }
        let mut parameters =
            TransportParameters::decode(&transport_parameters).map_err(|error| {
                ManagedEndpointError::InvalidConfig(format!("HTTP/3 transport parameters: {error}"))
            })?;
        let max_peer_uni_streams = parameters.initial_max_streams_uni.unwrap_or(0);
        config.max_requests_per_connection = config
            .max_requests_per_connection
            .min(parameters.initial_max_streams_bidi.unwrap_or(0));
        if config.max_requests_per_connection == 0
            || !(3..=128).contains(&max_peer_uni_streams)
            || parameters.initial_max_data.unwrap_or(0) == 0
            || parameters.initial_max_stream_data_bidi_remote.unwrap_or(0) == 0
            || parameters.initial_max_stream_data_uni.unwrap_or(0) == 0
        {
            return Err(ManagedEndpointError::InvalidConfig(
                "HTTP/3 requires positive request/data credit and 3..=128 peer unidirectional streams".to_string(),
            ).into());
        }
        // Clamp the authenticated wire contract as well as the application
        // cap, so high stream IDs cannot allocate states beyond this profile.
        parameters.initial_max_streams_bidi = Some(config.max_requests_per_connection);
        let mut transport_parameters = Vec::new();
        parameters
            .encode(&mut transport_parameters)
            .map_err(|error| {
                ManagedEndpointError::InvalidConfig(format!("HTTP/3 transport parameters: {error}"))
            })?;
        config.endpoint.is_server = true;
        let mut endpoint = ManagedQuicEndpoint::bind(cx, address, config.endpoint.clone()).await?;
        endpoint.set_authenticated_accept_limit(
            config
                .max_pending_handshakes
                .min(config.endpoint.max_connections),
        )?;
        endpoint.configure_authenticated_server(cx, tls, transport_parameters, b"h3")?;
        Ok(Self {
            endpoint,
            router: Arc::new(router),
            config,
            max_peer_uni_streams,
        })
    }

    /// The bound UDP address, including its assigned ephemeral port.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.endpoint.local_addr()
    }

    /// Serve until the owning context is cancelled.
    pub async fn serve(self, cx: &Cx) -> Result<NativeH3ListenerReport, NativeH3ListenerError> {
        self.serve_with_shutdown(cx, std::future::pending()).await
    }

    /// Serve concurrent authenticated peers until shutdown or cancellation.
    ///
    /// A completed shutdown future stops admissions, sends GOAWAY, and lets
    /// existing handlers/producers drain. The graceful deadline then requests
    /// cancellation. Request regions and their finalizers are always joined
    /// before this method returns, including on endpoint errors. Dropping the
    /// serve future requests close for opened regions; pending admissions
    /// remain owned by the caller's parent region. Await this method to obtain
    /// a receipt covering both pending admissions and opened request regions.
    pub async fn serve_with_shutdown<F>(
        mut self,
        cx: &Cx,
        shutdown: F,
    ) -> Result<NativeH3ListenerReport, NativeH3ListenerError>
    where
        F: Future<Output = ()>,
    {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut state = ListenerState::new(self.router, self.config, self.max_peer_uni_streams);
        let driver_result = self
            .endpoint
            .run_event_loop_with_application(cx, |cx, endpoint, task_cx| {
                if !state.draining && shutdown.as_mut().poll(task_cx).is_ready() {
                    state.start_draining(cx, endpoint);
                }
                state.poll(cx, endpoint, task_cx)
            })
            .await;

        // The transport future may exit directly on owner cancellation. Keep
        // polling owned task/region completion independently of cancelled I/O.
        self.endpoint.stop_authenticated_accepts();
        state.cancel_all(cx);
        std::future::poll_fn(|task_cx| state.poll_cleanup(cx, task_cx)).await;
        let shutdown_result = self.endpoint.shutdown(cx).await;
        if let Some(error) = state.failure {
            return Err(error);
        }
        driver_result?;
        shutdown_result?;
        Ok(state.report)
    }
}

type RequestReply = (Cx, NativeH3RouterProducedDispatch);
type RegionClose = Pin<Box<dyn Future<Output = Result<bool, ChildRegionError>> + Send>>;
type RequestBodySource = (Cx, FramedIncomingRequestBodyWriter);

const STREAMING_REQUEST_FRAME_CAPACITY: usize = 8;
const MAX_STREAMING_REQUEST_CHUNK_BYTES: usize = 16 * 1024;
const H3_NO_ERROR: u64 = 0x100;
const H3_FRAME_ERROR: u64 = 0x106;
const H3_REQUEST_CANCELLED: u64 = 0x10c;
const H3_MESSAGE_ERROR: u64 = 0x10e;

fn streaming_chunk_bytes(queue_bytes: NonZeroUsize) -> usize {
    queue_bytes.get().min(MAX_STREAMING_REQUEST_CHUNK_BYTES)
}

/// The request task creates this source with its actual admitted Cx. Until
/// publication, the session keeps this stream paused at HEADERS. Afterwards
/// the framed writer owns at most one pending DATA or trailer frame while its
/// queue is full, and its capacity waiter wakes the UDP callback directly.
struct RequestBodyWork {
    publication: Option<oneshot::Receiver<RequestBodySource>>,
    source: Option<RequestBodySource>,
    paused: bool,
    finished: bool,
    stopped: bool,
    clean_receive_stop: bool,
}

impl RequestBodyWork {
    fn new(publication: oneshot::Receiver<RequestBodySource>) -> Self {
        Self {
            publication: Some(publication),
            source: None,
            paused: true,
            finished: false,
            stopped: false,
            clean_receive_stop: false,
        }
    }

    fn fail(&mut self, error: IncomingBodyError) {
        self.publication.take();
        if let Some((_, writer)) = &mut self.source {
            writer.fail(error);
        }
        self.stopped = true;
    }

    /// Returns whether publication or a previously blocked frame advanced.
    /// No socket event is required for either progress edge.
    fn poll(&mut self, task_cx: &mut TaskContext<'_>) -> Result<bool, IncomingBodyError> {
        if self.stopped {
            return Ok(false);
        }
        let mut progress = false;
        if let Some(publication) = &mut self.publication {
            match publication.poll_recv_uninterruptible(task_cx) {
                Poll::Pending => return Ok(false),
                Poll::Ready(Err(_)) => {
                    self.publication = None;
                    return Err(IncomingBodyError::SourceDisconnected);
                }
                Poll::Ready(Ok(source)) => {
                    self.publication = None;
                    self.source = Some(source);
                    progress = true;
                }
            }
        }
        let Some((request_cx, writer)) = &mut self.source else {
            return Err(IncomingBodyError::SourceDisconnected);
        };
        // Register even while the queue is empty, so a handler that rejects
        // the request without another peer packet still retires receive state.
        match writer.poll_consumer_dropped(task_cx) {
            Poll::Ready(Ok(())) => return Err(IncomingBodyError::ConsumerDropped),
            Poll::Ready(Err(error)) => return Err(error),
            Poll::Pending => {}
        }
        if writer.has_pending_frame() {
            match writer.poll_send_frame(request_cx, task_cx, &mut None) {
                Poll::Pending => return Ok(progress),
                Poll::Ready(Err(error)) => return Err(error),
                Poll::Ready(Ok(())) => progress = true,
            }
        }
        Ok(progress)
    }

    fn consumer_failure(&mut self, task_cx: &mut TaskContext<'_>) -> Option<IncomingBodyError> {
        let (_, writer) = self.source.as_mut()?;
        match writer.poll_consumer_dropped(task_cx) {
            Poll::Ready(Err(error)) => Some(error),
            Poll::Ready(Ok(())) | Poll::Pending => None,
        }
    }

    fn ready_to_receive(&self) -> bool {
        !self.finished
            && !self.stopped
            && self
                .source
                .as_ref()
                .is_some_and(|(_, writer)| !writer.has_pending_frame())
    }

    fn send_data(
        &mut self,
        data: Bytes,
        task_cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), IncomingBodyError>> {
        let Some((request_cx, writer)) = &mut self.source else {
            return Poll::Ready(Err(IncomingBodyError::SourceDisconnected));
        };
        let mut frame = Some(Frame::Data(BytesCursor::new(data)));
        writer.poll_send_frame(request_cx, task_cx, &mut frame)
    }

    fn finish(&mut self) -> Result<(), IncomingBodyError> {
        let Some((request_cx, writer)) = &mut self.source else {
            return Err(IncomingBodyError::SourceDisconnected);
        };
        writer.finish(request_cx)?;
        self.finished = true;
        self.paused = false;
        Ok(())
    }

    fn send_trailers(
        &mut self,
        fields: Vec<(String, String)>,
        max_bytes: usize,
        task_cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), IncomingBodyError>> {
        let Some((request_cx, writer)) = &mut self.source else {
            return Poll::Ready(Err(IncomingBodyError::SourceDisconnected));
        };
        // The native session has already validated and decoded these fields.
        // Bound their retained size before allocating the handler-side map.
        // This is the same accounting used by the body queue's byte permits.
        let mut retained_bytes = 0_usize;
        for (name, value) in &fields {
            let next = name
                .len()
                .checked_add(value.len())
                .and_then(|bytes| bytes.checked_add(4))
                .and_then(|bytes| retained_bytes.checked_add(bytes));
            let Some(next) = next.filter(|bytes| *bytes <= max_bytes) else {
                return Poll::Ready(Err(IncomingBodyError::TrailersTooLarge));
            };
            retained_bytes = next;
        }
        let mut trailers = HeaderMap::with_capacity(fields.len());
        for (name, value) in fields {
            trailers.append(
                HeaderName::from_string(&name),
                HeaderValue::from_bytes(value.as_bytes()),
            );
        }
        let mut frame = Some(Frame::Trailers(trailers));
        writer.poll_send_frame(request_cx, task_cx, &mut frame)
    }
}

struct RequestWork {
    token: NativeH3RouterDispatchToken,
    opening: Option<ChildRegionOpening>,
    region: Option<ChildRegion>,
    dispatch: Option<NativeH3RouterDispatch>,
    body: Option<RequestBodyWork>,
    body_publisher: Option<oneshot::Sender<RequestBodySource>>,
    task: Option<TaskHandle<ServerHopOutcome<bool>>>,
    reply: Option<oneshot::Receiver<RequestReply>>,
    command: Option<oneshot::Sender<Option<NativeH3RouterProducer>>>,
    completion: Option<oneshot::Sender<()>>,
    buffered: Option<BufferedResponse>,
    close: Option<RegionClose>,
    deadline: Option<ServerRequestDeadline>,
    terminal: Option<bool>,
    task_completed: bool,
    response_started: bool,
    reset_applied: bool,
    input_error_code: Option<u64>,
}

impl RequestWork {
    fn new(
        cx: &Cx,
        dispatch: NativeH3RouterDispatch,
        config: &NativeH3ListenerConfig,
        assembly_deadline: Option<Time>,
    ) -> Self {
        let mut budget = cx
            .budget()
            .tightened_by_timeout(cx.now(), config.request_timeout);
        if let Some(deadline) = assembly_deadline {
            budget = budget.meet(Budget::new().with_deadline(deadline));
        }
        let (body_publisher, body) = if config.streaming_request_body_buffer_bytes.is_some() {
            let (sender, receiver) = oneshot::channel();
            (Some(sender), Some(RequestBodyWork::new(receiver)))
        } else {
            (None, None)
        };
        Self {
            token: dispatch.cancellation_token(),
            opening: Some(cx.open_child_region(ChildRegionSpec::inherit().with_budget(budget))),
            region: None,
            dispatch: Some(dispatch),
            body,
            body_publisher,
            task: None,
            reply: None,
            command: None,
            completion: None,
            buffered: None,
            close: None,
            deadline: cx
                .timer_driver()
                .zip(budget.deadline)
                .map(|(timer, deadline)| ServerRequestDeadline::new(timer, deadline)),
            terminal: None,
            task_completed: false,
            response_started: false,
            reset_applied: false,
            input_error_code: None,
        }
    }

    fn cancel(&mut self, cx: &Cx, grace: Duration) {
        self.cancel_for(cx, grace, CancelKind::ParentCancelled);
    }

    fn cancel_for(&mut self, cx: &Cx, grace: Duration, kind: CancelKind) {
        if self.terminal.is_some() {
            return;
        }
        self.terminal = Some(false);
        self.dispatch.take();
        self.body_publisher.take();
        if let Some(body) = &mut self.body {
            body.fail(IncomingBodyError::Cancelled { kind });
        }
        self.command.take();
        self.completion.take();
        self.buffered.take();
        let reason = CancelReason::with_origin(kind, cx.region_id(), cx.now());
        if let Some(task) = &self.task {
            task.abort_with_reason(reason.clone());
        }
        if let Some(region) = &self.region {
            let _ = region.cancel_with_budget(reason, shutdown_budget(cx, grace));
        }
    }

    fn poll_deadline(&mut self, cx: &Cx, grace: Duration, task_cx: &mut TaskContext<'_>) -> bool {
        if !self
            .deadline
            .as_mut()
            .is_some_and(|deadline| Pin::new(deadline).poll(task_cx).is_ready())
        {
            return false;
        }
        self.deadline = None;
        // This independent owner timer survives handler/producer completion
        // and registers even while child-region admission is still pending.
        // A region already closing has its separate bounded cleanup budget.
        if self.terminal.is_none() || !self.task_completed {
            self.terminal = None;
            self.cancel_for(cx, grace, CancelKind::Deadline);
        }
        true
    }

    fn complete(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        stream_id: StreamId,
    ) -> Result<(), NativeH3SessionError> {
        if self.terminal.is_none() {
            if let Some(body) = &mut self.body
                && !body.finished
                && !body.stopped
            {
                // The response can finish while a descendant still owns an
                // unread body. Stop network input immediately; the existing
                // request-region close below joins that descendant and keeps
                // its final body-failure observer alive through cleanup.
                body.fail(IncomingBodyError::Cancelled {
                    kind: CancelKind::ParentCancelled,
                });
                connection.stop_stream_receiving(cx, stream_id, H3_NO_ERROR)?;
                body.clean_receive_stop = true;
            }
            self.terminal = Some(true);
            if let Some(command) = self.command.take() {
                let _ = command.send_blocking(None);
            }
            if let Some(completion) = self.completion.take() {
                let _ = completion.send_blocking(());
            }
        }
        Ok(())
    }

    /// Drive only runtime ownership. Application code executes in the spawned
    /// body task; the UDP callback never polls a handler or producer directly.
    fn poll_owner(
        &mut self,
        cx: &Cx,
        config: &NativeH3ListenerConfig,
        task_cx: &mut TaskContext<'_>,
    ) -> Poll<Result<bool, NativeH3ListenerError>> {
        // A consumer can reject a queued frame after wire FIN, for example
        // after middleware tightens the body policy. Preserve that failure
        // even if its handler catches the error and returns a response in the
        // same driver turn. The observer lives through task/region completion.
        if let Some(error) = self
            .body
            .as_mut()
            .and_then(|body| body.consumer_failure(task_cx))
            && self.terminal != Some(false)
        {
            self.input_error_code = Some(request_body_error_code(&error));
            self.body
                .as_mut()
                .expect("body observer exists")
                .fail(error);
            self.terminal = None;
            self.cancel(cx, config.request_drain_timeout);
        }
        self.poll_deadline(cx, config.request_drain_timeout, task_cx);
        if let Some(opening) = &mut self.opening {
            match Pin::new(opening).poll(task_cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => {
                    self.opening = None;
                    self.dispatch.take();
                    self.terminal = Some(false);
                    self.task_completed = true;
                    return Poll::Ready(Ok(true));
                }
                Poll::Ready(Ok(region)) => {
                    self.opening = None;
                    self.region = Some(region);
                    // The new publication receiver is polled on the next
                    // driver turn, even if the handler publishes immediately.
                    task_cx.waker().wake_by_ref();
                    if self.terminal.is_none() {
                        let dispatch = self.dispatch.take().expect("opening request owns dispatch");
                        let body_publisher = self.body_publisher.take();
                        let body_queue_bytes = config.streaming_request_body_buffer_bytes;
                        let (reply_tx, reply_rx) = oneshot::channel();
                        let (command_tx, mut command_rx) = oneshot::channel();
                        let (completion_tx, mut completion_rx) = oneshot::channel();
                        let connection_cx = cx.clone();
                        let grace = config.request_drain_timeout;
                        let spawned = self
                            .region
                            .as_ref()
                            .expect("region just admitted")
                            .cx()
                            .spawn(move |request_cx| async move {
                                let hop = ServerRequestRegion::from_body_cx(
                                    "h3",
                                    request_cx.clone(),
                                    request_cx.now(),
                                );
                                let work = async {
                                    let prepared = if let Some(body_publisher) = body_publisher {
                                        let queue_bytes = body_queue_bytes
                                            .expect("streaming request has a queue budget")
                                            .get();
                                        let (writer, body) =
                                            IncomingRequestBody::framed_channel_with_limits(
                                                &request_cx,
                                                dispatch.declared_content_length(),
                                                STREAMING_REQUEST_FRAME_CAPACITY,
                                                queue_bytes,
                                            );
                                        let writer = writer
                                            .max_body_size(dispatch.max_request_body_size())
                                            .max_trailers_size(
                                                queue_bytes.min(MAX_STREAMING_REQUEST_CHUNK_BYTES),
                                            );
                                        if body_publisher
                                            .send_blocking((request_cx.clone(), writer))
                                            .is_err()
                                        {
                                            return false;
                                        }
                                        dispatch.run_produced_streaming(&request_cx, body).await
                                    } else {
                                        dispatch.run_produced(&request_cx).await
                                    };
                                    if reply_tx
                                        .send_blocking((request_cx.clone(), prepared))
                                        .is_ok()
                                    {
                                        match command_rx.recv(&request_cx).await {
                                            Ok(Some(producer)) => producer.await,
                                            Ok(None) => {}
                                            Err(_) => return false,
                                        }
                                        // A producer can finish while final
                                        // DATA/trailers remain flow-blocked.
                                        // Retain the task and its absolute
                                        // deadline until transport drain.
                                        return completion_rx.recv(&request_cx).await.is_ok();
                                    }
                                    false
                                };
                                hop.run_with_protocol_drain(
                                    RequestBudgetSource::ServerConfig,
                                    Some(connection_cx),
                                    grace,
                                    work,
                                )
                                .await
                            });
                        match spawned {
                            Ok(task) => {
                                self.task = Some(task);
                                self.reply = Some(reply_rx);
                                self.command = Some(command_tx);
                                self.completion = Some(completion_tx);
                            }
                            Err(_) => {
                                self.terminal = Some(false);
                                self.task_completed = true;
                            }
                        }
                    } else {
                        self.task_completed = true;
                    }
                }
            }
        }
        if let Some(task) = &mut self.task
            && let Poll::Ready(result) = task.poll_join(task_cx)
        {
            self.task = None;
            self.task_completed = true;
            if !matches!(result, Ok(ServerHopOutcome::Ok(true)))
                || !self.response_started
                || self.terminal != Some(true)
            {
                // Queuing FIN does not certify successful task completion.
                // A failed body task still changes the eventual close receipt.
                self.terminal = None;
                self.cancel(cx, config.request_drain_timeout);
            }
        }
        if self.terminal.is_some() && self.task_completed && self.close.is_none() {
            if let Some(region) = self.region.take() {
                // Region exit also bounds spawned descendants and finalizers;
                // do not silently treat an exhausted cleanup as success.
                if let Err(error) = region.cancel_with_budget(
                    cancel_reason(cx),
                    shutdown_budget(cx, config.request_drain_timeout),
                ) {
                    return Poll::Ready(Err(NativeH3ListenerError::Ownership(error)));
                }
                self.close = Some(Box::pin(async move {
                    let outcome = region.close_with_outcome().await?;
                    Ok(outcome
                        .cleanup_outcome
                        .is_none_or(|outcome| matches!(outcome, Outcome::Ok(()))))
                }));
            } else {
                return Poll::Ready(Ok(true));
            }
        }
        if let Some(close) = &mut self.close {
            match close.as_mut().poll(task_cx) {
                Poll::Ready(Ok(true)) => {
                    if let Some(error) = self
                        .body
                        .as_mut()
                        .and_then(|body| body.consumer_failure(task_cx))
                    {
                        self.input_error_code = Some(request_body_error_code(&error));
                        self.body
                            .as_mut()
                            .expect("body observer exists")
                            .fail(error);
                        self.terminal = Some(false);
                    }
                    return Poll::Ready(Ok(true));
                }
                Poll::Ready(Ok(false)) => {
                    return Poll::Ready(Err(NativeH3ListenerError::CleanupFailed));
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(NativeH3ListenerError::Ownership(error)));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}

fn cancel_reason(cx: &Cx) -> CancelReason {
    CancelReason::with_origin(CancelKind::ParentCancelled, cx.region_id(), cx.now())
}

fn shutdown_budget(cx: &Cx, grace: Duration) -> Budget {
    // The cleanup ceiling is independent of an already expired request budget.
    Budget::new().with_timeout(cx.now(), grace)
}

fn retire_request_input(
    cx: &Cx,
    bridge: &mut NativeH3Router,
    connection: &mut QuicConnection,
    stream_id: StreamId,
    request: &mut RequestWork,
    config: &NativeH3ListenerConfig,
    error: IncomingBodyError,
) -> Result<(), NativeH3SessionError> {
    let consumer_dropped = error == IncomingBodyError::ConsumerDropped;
    let error_code = request_body_error_code(&error);
    if let Some(body) = &mut request.body {
        let need_receive_stop = !body.finished && !body.stopped;
        body.fail(error);
        if consumer_dropped && need_receive_stop {
            // A handler may legitimately reject a request from its HEADERS
            // or a body prefix. Abandon input without resetting the response
            // half that carries that rejection.
            connection.stop_stream_receiving(cx, stream_id, H3_NO_ERROR)?;
            body.clean_receive_stop = true;
        }
    }
    if !consumer_dropped {
        // Publish the exact body failure before owner cancellation. The body
        // observer and eventual request receipt must not turn a length/policy
        // failure into a successful response merely because it was caught.
        request.cancel(cx, config.request_drain_timeout);
        request.input_error_code = Some(error_code);
        bridge.cancel_streaming_dispatch_with_error(cx, connection, &request.token, error_code)?;
        request.reset_applied = true;
    }
    Ok(())
}

fn request_body_error_code(error: &IncomingBodyError) -> u64 {
    match error {
        IncomingBodyError::BadContentLength
        | IncomingBodyError::BadHeader
        | IncomingBodyError::InvalidHeaderName
        | IncomingBodyError::InvalidHeaderValue => H3_MESSAGE_ERROR,
        _ => H3_REQUEST_CANCELLED,
    }
}

struct BufferedResponse {
    writer: NativeH3ResponseWriter,
    body: Bytes,
    offset: usize,
}

impl BufferedResponse {
    fn poll(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        task_cx: &mut TaskContext<'_>,
    ) -> Poll<Result<bool, NativeH3SessionError>> {
        if self.writer.has_pending_write() {
            return self
                .writer
                .poll_flush_one(cx, connection, task_cx)
                .map(|result| result.map(|_| false));
        }
        if self.writer.is_finished() {
            return connection
                .poll_stream_queue_drained(cx, self.writer.stream_id(), task_cx)
                .map(|result| {
                    result
                        .map(|()| true)
                        .map_err(NativeH3SessionError::Transport)
                });
        }
        if self.offset == self.body.len() {
            self.writer.finish()?;
            return Poll::Ready(Ok(false));
        }
        let capacity =
            match connection.poll_stream_write_ready(cx, self.writer.stream_id(), 3, task_cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Ready(Ok(capacity)) => capacity,
            };
        // Fit DATA framing as well as payload under both flow-control scopes.
        // Small windows must not wait for a fixed-size chunk they cannot grant.
        let upper = (self.body.len() - self.offset)
            .min(self.writer.max_frame_payload_size())
            .min(16 * 1024);
        let mut low = 0;
        let mut high = upper;
        while low < high {
            let middle = low + (high - low).div_ceil(2);
            if h3_data_frame_wire_len(middle)? <= capacity {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        if low == 0 {
            return Poll::Ready(Err(NativeH3SessionError::InvalidState(
                "HTTP/3 response DATA frame has no payload capacity",
            )));
        }
        self.writer
            .queue_data(self.body.slice(self.offset..self.offset + low))?;
        self.offset += low;
        Poll::Ready(Ok(false))
    }
}

struct ListenerConnection {
    id: ConnectionId,
    session: NativeH3Session,
    bridge: NativeH3Router,
    control: StreamId,
    requests: BTreeMap<StreamId, RequestWork>,
    seen_requests: BTreeSet<StreamId>,
    assembly: BTreeMap<StreamId, (Time, ServerRequestDeadline)>,
    initial_receive_window: u64,
    retiring: bool,
    retirement_forced: bool,
    retirement_deadline: Option<ServerRequestDeadline>,
    next_request: u64,
    live: bool,
    goaway_sent: bool,
    drained: bool,
}

struct ListenerState {
    router: Arc<Router>,
    config: NativeH3ListenerConfig,
    max_peer_uni_streams: u64,
    connections: Vec<ListenerConnection>,
    report: NativeH3ListenerReport,
    draining: bool,
    deadline: Option<ServerRequestDeadline>,
    failure: Option<NativeH3ListenerError>,
}

impl ListenerState {
    fn new(router: Arc<Router>, config: NativeH3ListenerConfig, max_peer_uni_streams: u64) -> Self {
        Self {
            router,
            config,
            max_peer_uni_streams,
            connections: Vec::new(),
            report: NativeH3ListenerReport::default(),
            draining: false,
            deadline: None,
            failure: None,
        }
    }

    fn start_draining(&mut self, cx: &Cx, endpoint: &mut ManagedQuicEndpoint) {
        endpoint.stop_authenticated_accepts();
        self.draining = true;
        self.deadline = cx
            .timer_driver()
            .map(|timer| ServerRequestDeadline::new(timer, cx.now() + self.config.drain_timeout));
    }

    fn cancel_all(&mut self, cx: &Cx) {
        for connection in &mut self.connections {
            for request in connection.requests.values_mut() {
                request.cancel(cx, self.config.request_drain_timeout);
            }
        }
    }

    fn reap_request(&mut self, success: bool) {
        if success {
            self.report.completed_requests = self.report.completed_requests.saturating_add(1);
        } else {
            self.report.cancelled_requests = self.report.cancelled_requests.saturating_add(1);
        }
    }

    fn poll_cleanup(&mut self, cx: &Cx, task_cx: &mut TaskContext<'_>) -> Poll<()> {
        let mut completed = Vec::new();
        for connection in &mut self.connections {
            connection.requests.retain(|stream_id, request| {
                match request.poll_owner(cx, &self.config, task_cx) {
                    Poll::Ready(result) => {
                        let success = request.terminal == Some(true) && result.is_ok();
                        if request.body.is_some() {
                            connection
                                .bridge
                                .release_streaming_dispatch_after_close(*stream_id);
                        }
                        if let Err(error) = result {
                            self.failure.get_or_insert(error);
                        }
                        completed.push(success);
                        false
                    }
                    Poll::Pending => true,
                }
            });
        }
        for success in completed {
            self.reap_request(success);
        }
        if self
            .connections
            .iter()
            .all(|connection| connection.requests.is_empty())
        {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    fn poll(
        &mut self,
        cx: &Cx,
        endpoint: &mut ManagedQuicEndpoint,
        task_cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), ManagedEndpointError>> {
        if self
            .deadline
            .as_mut()
            .is_some_and(|deadline| Pin::new(deadline).poll(task_cx).is_ready())
        {
            self.report.drain_timed_out = true;
            self.cancel_all(cx);
            return Poll::Ready(Ok(()));
        }
        let mut progress = false;
        // Receipt capacity is itself bounded by managed admission. Taking a
        // failed receipt releases only that peer's admission slot.
        while let Some((id, admitted)) = endpoint.take_authenticated_accept_result_with_id() {
            progress = true;
            if admitted.is_err() {
                if !self.draining {
                    self.report.failed_connections =
                        self.report.failed_connections.saturating_add(1);
                }
                continue;
            }
            if self.draining || self.connections.len() >= self.config.endpoint.max_connections {
                let _ = endpoint.remove_connection(cx, id);
                continue;
            }
            let mut session = NativeH3Session::server();
            let initialized = endpoint.with_connection_mut(cx, id, |connection| {
                if let Some(queue_bytes) = self.config.streaming_request_body_buffer_bytes {
                    session.enable_streaming_receive(
                        NonZeroUsize::new(streaming_chunk_bytes(queue_bytes))
                            .expect("streaming request chunk is nonzero"),
                    )?;
                }
                session
                    .initialize(cx, connection, crate::http::h3::H3Settings::default())
                    .map(|control| {
                        (
                            control,
                            connection.inner().streams().connection_recv_limit(),
                        )
                    })
            });
            match initialized {
                Ok(Ok((control, initial_receive_window))) => {
                    self.report.accepted_connections =
                        self.report.accepted_connections.saturating_add(1);
                    self.connections.push(ListenerConnection {
                        id,
                        session,
                        bridge: NativeH3Router::with_shared_config(
                            Arc::clone(&self.router),
                            self.config.router,
                        ),
                        control,
                        requests: BTreeMap::new(),
                        seen_requests: BTreeSet::new(),
                        assembly: BTreeMap::new(),
                        initial_receive_window,
                        retiring: false,
                        retirement_forced: false,
                        retirement_deadline: None,
                        next_request: 0,
                        live: true,
                        goaway_sent: false,
                        drained: false,
                    });
                }
                _ => {
                    self.report.failed_connections =
                        self.report.failed_connections.saturating_add(1);
                    let _ = endpoint.remove_connection(cx, id);
                }
            }
        }
        let mut active = self
            .connections
            .iter()
            .map(|connection| connection.requests.len())
            .sum::<usize>();
        // Rotate admission priority as well as giving every peer I/O turns.
        // Otherwise the first connected peer can repeatedly consume a scarce
        // global request slot before later peers are visited.
        if self.connections.len() > 1 {
            self.connections.rotate_left(1);
        }
        let mut completed = Vec::new();
        let mut retired_connection = false;
        for connection in &mut self.connections {
            for request in connection.requests.values_mut() {
                progress |= request.poll_deadline(cx, self.config.request_drain_timeout, task_cx);
            }
            if connection.live {
                let result = endpoint.with_connection_mut(cx, connection.id, |transport| {
                    connection.poll(
                        cx,
                        transport,
                        &self.config,
                        self.max_peer_uni_streams,
                        self.draining,
                        &mut active,
                        &mut self.report,
                        task_cx,
                    )
                });
                let frame_error_close = self.config.streaming_request_body_buffer_bytes.is_some()
                    && matches!(
                        &result,
                        Ok(Err(NativeH3SessionError::TruncatedStream { .. }))
                    );
                match result {
                    Ok(Ok(made_progress)) => progress |= made_progress,
                    _ => {
                        connection.live = false;
                        connection.assembly.clear();
                        connection.retirement_deadline = None;
                        self.report.failed_connections =
                            self.report.failed_connections.saturating_add(1);
                        let protected_close = frame_error_close
                            && endpoint
                                .request_authenticated_close(
                                    cx,
                                    connection.id,
                                    H3_FRAME_ERROR,
                                    true,
                                )
                                .unwrap_or(false);
                        if protected_close {
                            // A clean FIN inside an H3 frame is a connection
                            // H3_FRAME_ERROR. The endpoint retains the
                            // authenticated route and sends its protected
                            // close while owned request regions drain here.
                            retired_connection = true;
                        } else {
                            let _ = endpoint.remove_connection(cx, connection.id);
                        }
                        for request in connection.requests.values_mut() {
                            if let Some(body) = &mut request.body {
                                body.fail(IncomingBodyError::ClientAborted);
                            }
                            request.cancel(cx, self.config.request_drain_timeout);
                        }
                        progress = true;
                    }
                }
            }
            connection.requests.retain(|stream_id, request| {
                match request.poll_owner(cx, &self.config, task_cx) {
                    Poll::Pending => true,
                    Poll::Ready(result) => {
                        let success = request.terminal == Some(true) && result.is_ok();
                        if !success && !request.reset_applied && connection.live {
                            let _ = endpoint.with_connection_mut(cx, connection.id, |transport| {
                                if let Some(error_code) = request.input_error_code {
                                    connection.bridge.cancel_streaming_dispatch_with_error(
                                        cx,
                                        transport,
                                        &request.token,
                                        error_code,
                                    )
                                } else {
                                    connection
                                        .bridge
                                        .cancel_dispatch_with_cx(
                                            cx,
                                            &mut connection.session,
                                            transport,
                                            &request.token,
                                        )
                                        .map(|_| ())
                                }
                            });
                            request.reset_applied = true;
                        }
                        if request.body.is_some() {
                            connection
                                .bridge
                                .release_streaming_dispatch_after_close(*stream_id);
                        }
                        if let Err(error) = result {
                            self.failure.get_or_insert(error);
                        }
                        completed.push(success);
                        progress = true;
                        false
                    }
                }
            });
            if connection.live
                && connection.retiring
                && connection.requests.is_empty()
                && connection.assembly.is_empty()
                && (connection.drained || connection.retirement_forced)
            {
                match endpoint.request_authenticated_close(
                    cx,
                    connection.id,
                    0x100,
                    connection.retirement_forced,
                ) {
                    Ok(true) => {
                        // The endpoint retains the authenticated route and
                        // protected H3_NO_ERROR close through its drain period.
                        connection.live = false;
                        connection.retirement_deadline = None;
                        retired_connection = true;
                        progress = true;
                    }
                    Ok(false) => {}
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
        }
        for success in completed {
            self.reap_request(success);
        }
        self.connections
            .retain(|connection| connection.live || !connection.requests.is_empty());
        if self.failure.is_some() {
            return Poll::Ready(Ok(()));
        }
        if self.draining
            && !retired_connection
            && self.connections.iter().all(|connection| {
                connection.requests.is_empty() && (!connection.live || connection.drained)
            })
            && endpoint.pending_datagram_count() == 0
        {
            return Poll::Ready(Ok(()));
        }
        if progress {
            task_cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

impl ListenerConnection {
    fn poll_request_inputs(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        config: &NativeH3ListenerConfig,
        task_cx: &mut TaskContext<'_>,
    ) -> Result<bool, NativeH3SessionError> {
        let mut progress = false;
        for (stream_id, request) in &mut self.requests {
            if request.terminal.is_some() {
                continue;
            }
            let Some(body) = &mut request.body else {
                continue;
            };
            match body.poll(task_cx) {
                Ok(made_progress) => {
                    progress |= made_progress;
                    if body.paused && body.ready_to_receive() {
                        self.session.resume_request_stream(*stream_id)?;
                        body.paused = false;
                        progress = true;
                    }
                }
                Err(error) => {
                    retire_request_input(
                        cx,
                        &mut self.bridge,
                        connection,
                        *stream_id,
                        request,
                        config,
                        error,
                    )?;
                    // Local receive-stop notifications bypass the session
                    // pause. Also rearm its consumer so buffered readiness is
                    // retired without waiting for another network packet.
                    self.session.resume_request_stream(*stream_id)?;
                    progress = true;
                }
            }
        }
        Ok(progress)
    }

    fn observe_streams(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        config: &NativeH3ListenerConfig,
        max_peer_uni_streams: u64,
        draining: bool,
        report: &mut NativeH3ListenerReport,
    ) -> Result<bool, NativeH3SessionError> {
        let mut progress = false;
        let mut lifetime_exhausted = false;
        // Both loops are bounded by the authenticated local transport
        // parameters. Observe raw streams before decoding HEADERS, so a
        // partial frame cannot avoid the request assembly deadline.
        for index in 0..config.max_requests_per_connection {
            let id = StreamId(index * 4);
            let Ok(stream) = connection.inner().streams().stream(id) else {
                continue;
            };
            if self.seen_requests.contains(&id) {
                continue;
            }
            let terminal =
                stream.recv_reset.is_some() || stream.receive_stopped_error_code.is_some();
            self.seen_requests.insert(id);
            self.next_request = self.next_request.max(id.0 + 4);
            lifetime_exhausted |= index + 1 == config.max_requests_per_connection;
            if terminal {
                continue;
            }
            if draining
                || self.retiring
                || self.assembly.len() >= config.router.max_pending_requests
            {
                let reason = if draining || self.retiring {
                    NativeH3RouterRefusal::DispatchCancelled
                } else {
                    NativeH3RouterRefusal::TooManyPendingRequests {
                        limit: config.router.max_pending_requests,
                    }
                };
                self.bridge
                    .refuse_request(cx, &mut self.session, connection, id, reason, true)?;
                report.refused_requests = report.refused_requests.saturating_add(1);
            } else {
                connection.configure_stream_receive_window(cx, id, config.receive_window_bytes)?;
                let budget = cx
                    .budget()
                    .tightened_by_timeout(cx.now(), config.request_timeout);
                if let Some((timer, deadline)) = cx.timer_driver().zip(budget.deadline) {
                    self.assembly
                        .insert(id, (deadline, ServerRequestDeadline::new(timer, deadline)));
                }
            }
            progress = true;
        }
        for index in 0..max_peer_uni_streams {
            let id = StreamId(index * 4 + 2);
            if connection
                .inner()
                .stream_recv_window_bytes(id)
                .is_ok_and(|window| window.is_none())
            {
                connection.configure_stream_receive_window(cx, id, config.receive_window_bytes)?;
                progress = true;
            }
        }
        if lifetime_exhausted && !self.retiring {
            self.retiring = true;
            self.retirement_deadline = cx.timer_driver().map(|timer| {
                ServerRequestDeadline::new(
                    timer,
                    cx.now()
                        + config
                            .request_timeout
                            .saturating_add(config.request_drain_timeout),
                )
            });
            progress = true;
        }
        Ok(progress)
    }

    fn refresh_receive_credit(
        &self,
        cx: &Cx,
        connection: &mut QuicConnection,
    ) -> Result<bool, NativeH3SessionError> {
        let streams = connection.inner().streams();
        let consumed = streams.consumed_connection_receive_bytes();
        let limit = self
            .initial_receive_window
            .saturating_add(consumed)
            .min((1_u64 << 62) - 1);
        if limit > streams.connection_recv_limit() {
            connection.advertise_connection_receive_limit(cx, limit)?;
            return Ok(true);
        }
        Ok(false)
    }

    #[allow(clippy::too_many_arguments)]
    fn poll(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        config: &NativeH3ListenerConfig,
        max_peer_uni_streams: u64,
        draining: bool,
        active: &mut usize,
        report: &mut NativeH3ListenerReport,
        task_cx: &mut TaskContext<'_>,
    ) -> Result<bool, NativeH3SessionError> {
        if connection.state() != QuicConnectionState::Established {
            return Err(NativeH3SessionError::InvalidState(
                "HTTP/3 peer connection closed",
            ));
        }
        let mut progress = self.observe_streams(
            cx,
            connection,
            config,
            max_peer_uni_streams,
            draining,
            report,
        )?;
        let mut expired = Vec::new();
        for (id, (_, timer)) in &mut self.assembly {
            if Pin::new(timer).poll(task_cx).is_ready() {
                expired.push(*id);
            }
        }
        for id in expired {
            self.assembly.remove(&id);
            self.bridge.refuse_request(
                cx,
                &mut self.session,
                connection,
                id,
                NativeH3RouterRefusal::DispatchCancelled,
                true,
            )?;
            report.refused_requests = report.refused_requests.saturating_add(1);
            progress = true;
        }
        if self
            .retirement_deadline
            .as_mut()
            .is_some_and(|deadline| Pin::new(deadline).poll(task_cx).is_ready())
        {
            self.retirement_deadline = None;
            self.retirement_forced = true;
            report.drain_timed_out = true;
            for request in self.requests.values_mut() {
                request.cancel(cx, config.request_drain_timeout);
            }
            let pending = self.assembly.keys().copied().collect::<Vec<_>>();
            for id in pending {
                self.assembly.remove(&id);
                self.bridge.refuse_request(
                    cx,
                    &mut self.session,
                    connection,
                    id,
                    NativeH3RouterRefusal::DispatchCancelled,
                    true,
                )?;
                report.refused_requests = report.refused_requests.saturating_add(1);
            }
            progress = true;
        }
        if (draining || self.retiring) && !self.goaway_sent {
            let width = match self.next_request {
                0..=63 => 1,
                64..=16_383 => 2,
                16_384..=1_073_741_823 => 4,
                _ => 8,
            };
            if let Poll::Ready(result) =
                connection.poll_stream_write_ready(cx, self.control, width + 2, task_cx)
            {
                result?;
                self.session
                    .graceful_close(cx, connection, self.next_request)?;
                self.goaway_sent = true;
                progress = true;
                if draining {
                    let pending = self.assembly.keys().copied().collect::<Vec<_>>();
                    for id in pending {
                        self.assembly.remove(&id);
                        self.bridge.refuse_request(
                            cx,
                            &mut self.session,
                            connection,
                            id,
                            NativeH3RouterRefusal::DispatchCancelled,
                            true,
                        )?;
                        report.refused_requests = report.refused_requests.saturating_add(1);
                    }
                }
            }
        }
        progress |= self.poll_request_inputs(cx, connection, config, task_cx)?;
        for _ in 0..config.application_batch_size {
            let event = match self.session.poll_event(cx, connection, task_cx) {
                Poll::Pending => break,
                Poll::Ready(event) => event?,
            };
            progress = true;
            if let NativeH3Event::RequestHeaders { stream_id, .. } = &event {
                self.next_request = self
                    .next_request
                    .max(stream_id.0.saturating_add(4).min((1_u64 << 62) - 4));
                if draining || (self.retiring && !self.assembly.contains_key(stream_id)) {
                    self.assembly.remove(stream_id);
                    // Raw-stream admission may already have refused this
                    // stream before its buffered HEADERS were decoded.
                    if !self.bridge.discarding.contains(stream_id) {
                        self.bridge.refuse_request(
                            cx,
                            &mut self.session,
                            connection,
                            *stream_id,
                            NativeH3RouterRefusal::DispatchCancelled,
                            true,
                        )?;
                        report.refused_requests = report.refused_requests.saturating_add(1);
                    }
                    continue;
                }
            }
            if let NativeH3Event::StreamReset { stream_id, .. } = &event
                && let Some(body) = self
                    .requests
                    .get_mut(stream_id)
                    .and_then(|request| request.body.as_mut())
            {
                if body.clean_receive_stop {
                    // RESET_STREAM is the peer's required answer to our
                    // STOP_SENDING. Its application error code need not echo
                    // H3_NO_ERROR. This only completes abandoned input; the
                    // peer can still cancel the response with STOP_SENDING,
                    // which is checked independently below.
                    continue;
                }
                body.fail(IncomingBodyError::ClientAborted);
            }
            let ingress = match event {
                NativeH3Event::RequestHeaders { stream_id, head }
                    if config.streaming_request_body_buffer_bytes.is_some() =>
                {
                    let queue_bytes = config
                        .streaming_request_body_buffer_bytes
                        .expect("streaming mode checked");
                    let retained_bytes = queue_bytes
                        .get()
                        .checked_add(streaming_chunk_bytes(queue_bytes))
                        .ok_or(NativeH3SessionError::InvalidState(
                            "HTTP/3 request queue reservation overflow",
                        ))?;
                    self.bridge.begin_streaming_request_with_cx(
                        cx,
                        &mut self.session,
                        connection,
                        stream_id,
                        head,
                        retained_bytes,
                    )?
                }
                NativeH3Event::Data { stream_id, bytes }
                    if self
                        .requests
                        .get(&stream_id)
                        .is_some_and(|request| request.body.is_some()) =>
                {
                    let request = self
                        .requests
                        .get_mut(&stream_id)
                        .expect("streaming request was checked");
                    if request.terminal.is_none() {
                        let body = request.body.as_mut().expect("streaming body exists");
                        if !body.stopped {
                            match body.send_data(bytes, task_cx) {
                                Poll::Pending => {
                                    self.session.pause_request_stream(stream_id)?;
                                    body.paused = true;
                                }
                                Poll::Ready(Ok(())) => {}
                                Poll::Ready(Err(error)) => {
                                    retire_request_input(
                                        cx,
                                        &mut self.bridge,
                                        connection,
                                        stream_id,
                                        request,
                                        config,
                                        error,
                                    )?;
                                }
                            }
                        }
                    }
                    continue;
                }
                NativeH3Event::Finished { stream_id }
                    if self
                        .requests
                        .get(&stream_id)
                        .is_some_and(|request| request.body.is_some()) =>
                {
                    let request = self
                        .requests
                        .get_mut(&stream_id)
                        .expect("streaming request was checked");
                    if request.terminal.is_none() {
                        let body = request.body.as_mut().expect("streaming body exists");
                        if !body.stopped
                            && let Err(error) = body.finish()
                        {
                            retire_request_input(
                                cx,
                                &mut self.bridge,
                                connection,
                                stream_id,
                                request,
                                config,
                                error,
                            )?;
                        }
                    }
                    continue;
                }
                NativeH3Event::Trailers { stream_id, fields }
                    if self
                        .requests
                        .get(&stream_id)
                        .is_some_and(|request| request.body.is_some()) =>
                {
                    let request = self
                        .requests
                        .get_mut(&stream_id)
                        .expect("streaming request was checked");
                    if request.terminal.is_none() {
                        let body = request.body.as_mut().expect("streaming body exists");
                        if !body.stopped {
                            let max_bytes = streaming_chunk_bytes(
                                config
                                    .streaming_request_body_buffer_bytes
                                    .expect("streaming request has a queue budget"),
                            );
                            match body.send_trailers(fields, max_bytes, task_cx) {
                                Poll::Pending => {
                                    self.session.pause_request_stream(stream_id)?;
                                    body.paused = true;
                                }
                                Poll::Ready(Ok(())) => {}
                                Poll::Ready(Err(error)) => {
                                    retire_request_input(
                                        cx,
                                        &mut self.bridge,
                                        connection,
                                        stream_id,
                                        request,
                                        config,
                                        error,
                                    )?;
                                }
                            }
                        }
                    }
                    continue;
                }
                event => {
                    self.bridge
                        .ingest_event_with_cx(cx, &mut self.session, connection, event)?
                }
            };
            match ingress {
                NativeH3RouterIngress::Dispatch(dispatch) => {
                    let assembly_deadline = self
                        .assembly
                        .remove(&dispatch.stream_id())
                        .map(|(deadline, _)| deadline);
                    if draining || *active >= config.max_concurrent_requests {
                        self.bridge.cancel_dispatch_with_cx(
                            cx,
                            &mut self.session,
                            connection,
                            &dispatch.cancellation_token(),
                        )?;
                        if config.streaming_request_body_buffer_bytes.is_some() {
                            // HEADERS reserved credit, but the global owner
                            // cap refused this request before region opening.
                            self.bridge
                                .release_streaming_dispatch_after_close(dispatch.stream_id());
                        }
                        report.refused_requests = report.refused_requests.saturating_add(1);
                    } else {
                        if config.streaming_request_body_buffer_bytes.is_some() {
                            // No DATA is consumed until the request region
                            // has admitted its task and published a body
                            // source carrying that exact task's Cx.
                            self.session.pause_request_stream(dispatch.stream_id())?;
                        }
                        self.requests.insert(
                            dispatch.stream_id(),
                            RequestWork::new(cx, dispatch, config, assembly_deadline),
                        );
                        *active += 1;
                    }
                }
                NativeH3RouterIngress::Event(NativeH3RouterEvent::StreamReset {
                    stream_id,
                    ..
                }) => {
                    self.assembly.remove(&stream_id);
                    if let Some(request) = self.requests.get_mut(&stream_id) {
                        // RESET_STREAM terminates only the peer's send half.
                        // The Router preserves this dispatch's ownership until
                        // we acknowledge cancellation, but that acknowledgement
                        // deliberately emits no response. Terminate our send
                        // half here so a client waiting for the cancelled
                        // response cannot remain parked indefinitely. Produced
                        // responses may already have queued this reset while
                        // ingesting the event; never replace their first code.
                        if connection
                            .inner()
                            .streams()
                            .stream(stream_id)
                            .is_ok_and(|stream| stream.send_reset.is_none())
                        {
                            connection.reset_stream(cx, stream_id, H3_REQUEST_CANCELLED)?;
                        }
                        // A queued response FIN is not a completed ownership
                        // receipt. A reset received while its region is still
                        // closing must retain the cancelled outcome.
                        request.terminal = None;
                        request.cancel(cx, config.request_drain_timeout);
                    }
                }
                NativeH3RouterIngress::Event(NativeH3RouterEvent::RequestRefused {
                    stream_id,
                    ..
                }) => {
                    self.assembly.remove(&stream_id);
                    if let Some(request) = self.requests.get_mut(&stream_id) {
                        request.cancel(cx, config.request_drain_timeout);
                    } else {
                        report.refused_requests = report.refused_requests.saturating_add(1);
                    }
                }
                NativeH3RouterIngress::Event(_) => {}
            }
        }
        for (stream_id, request) in &mut self.requests {
            // STOP_SENDING may precede a response and has no H3 receive event.
            // The endpoint repolls application work after every peer packet.
            if request.terminal.is_none()
                && connection
                    .inner()
                    .streams()
                    .stream(*stream_id)
                    .is_ok_and(|stream| stream.stop_sending_error_code.is_some())
            {
                request.cancel(cx, config.request_drain_timeout);
                progress = true;
            }
            if request.terminal == Some(false) && !request.reset_applied {
                if let Some(error_code) = request.input_error_code {
                    let _ = self.bridge.cancel_streaming_dispatch_with_error(
                        cx,
                        connection,
                        &request.token,
                        error_code,
                    );
                } else {
                    let _ = self.bridge.cancel_dispatch_with_cx(
                        cx,
                        &mut self.session,
                        connection,
                        &request.token,
                    );
                }
                request.reset_applied = true;
                progress = true;
            }
            if request.terminal.is_some() {
                continue;
            }
            if let Some(reply) = &mut request.reply {
                match reply.poll_recv_uninterruptible(task_cx) {
                    Poll::Pending => {}
                    Poll::Ready(Err(_)) => {
                        request.reply = None;
                        request.cancel(cx, config.request_drain_timeout);
                        progress = true;
                    }
                    Poll::Ready(Ok((request_cx, prepared))) => {
                        request.reply = None;
                        request.response_started = true;
                        progress = true;
                        match prepared {
                            NativeH3RouterProducedDispatch::Buffered(prepared) => {
                                match prepared.response {
                                    Ok((_, head, body))
                                        if body.len() <= config.max_buffered_response_bytes =>
                                    {
                                        match self.session.start_response_writer(
                                            connection,
                                            *stream_id,
                                            &head,
                                            body.is_empty(),
                                        ) {
                                            Ok(writer) => {
                                                request.buffered = Some(BufferedResponse {
                                                    writer,
                                                    body,
                                                    offset: 0,
                                                })
                                            }
                                            Err(_) => {
                                                request.cancel(cx, config.request_drain_timeout)
                                            }
                                        }
                                    }
                                    _ => request.cancel(cx, config.request_drain_timeout),
                                }
                            }
                            NativeH3RouterProducedDispatch::Produced(prepared) => {
                                match self.bridge.start_produced_dispatch_with_cx(
                                    cx,
                                    &mut self.session,
                                    connection,
                                    prepared,
                                ) {
                                    Ok(NativeH3RouterEvent::ResponseStarted { .. }) => {
                                        self.bridge
                                            .produced
                                            .get_mut(stream_id)
                                            .expect("produced response installed")
                                            .owned_request_cx = Some(request_cx);
                                    }
                                    _ => request.cancel(cx, config.request_drain_timeout),
                                }
                            }
                        }
                    }
                }
            }
            if let Some(buffered) = &mut request.buffered {
                match buffered.poll(cx, connection, task_cx) {
                    Poll::Pending => {}
                    Poll::Ready(Ok(done)) => {
                        progress = true;
                        if done {
                            self.bridge.release_in_flight(*stream_id);
                            request.buffered = None;
                            request.complete(cx, connection, *stream_id)?;
                        }
                    }
                    Poll::Ready(Err(_)) => {
                        request.cancel(cx, config.request_drain_timeout);
                        progress = true;
                    }
                }
            }
        }
        for _ in 0..config.application_batch_size {
            let event = match self.bridge.poll_produced_response_with_cx(
                cx,
                &mut self.session,
                connection,
                task_cx,
            ) {
                Poll::Pending => break,
                Poll::Ready(Err(error)) => {
                    // The producer bridge terminalizes its affected stream
                    // before reporting a write/body failure. Reap that stream
                    // without dropping healthy requests on the same peer.
                    let mut attributed = false;
                    for (stream_id, produced) in &self.bridge.produced {
                        if produced.reset_queued {
                            if let Some(request) = self.requests.get_mut(stream_id) {
                                request.cancel(cx, config.request_drain_timeout);
                            }
                            attributed = true;
                        }
                    }
                    if !attributed {
                        return Err(error);
                    }
                    progress = true;
                    break;
                }
                Poll::Ready(Ok(event)) => event,
            };
            progress = true;
            match event {
                NativeH3ProducedEvent::ProducerReady {
                    stream_id,
                    producer,
                } => {
                    if let Some(request) = self.requests.get_mut(&stream_id)
                        && let Some(command) = request.command.take()
                        && command.send(cx, Some(producer)).is_err()
                    {
                        request.cancel(cx, config.request_drain_timeout);
                    }
                }
                NativeH3ProducedEvent::ResponseSent { stream_id, .. } => {
                    if let Some(request) = self.requests.get_mut(&stream_id) {
                        request.complete(cx, connection, stream_id)?;
                    }
                }
                NativeH3ProducedEvent::RequestReset { stream_id } => {
                    if let Some(request) = self.requests.get_mut(&stream_id) {
                        request.cancel(cx, config.request_drain_timeout);
                    }
                }
                _ => {}
            }
        }
        progress |= self.refresh_receive_credit(cx, connection)?;
        if self.retirement_forced && self.requests.is_empty() && self.assembly.is_empty() {
            self.drained = true;
            return Ok(progress);
        }
        if (draining || self.retiring)
            && self.goaway_sent
            && self.requests.is_empty()
            && self.assembly.is_empty()
            && self.bridge.produced.is_empty()
        {
            self.drained = match connection.poll_stream_queue_drained(cx, self.control, task_cx) {
                Poll::Ready(result) => {
                    result?;
                    // Preserve normal loss recovery for the final response
                    // and GOAWAY until acknowledged. The explicit graceful
                    // deadline remains the bound if the peer disappears.
                    connection.path_stats().bytes_in_flight == 0
                }
                Poll::Pending => false,
            };
        }
        Ok(progress)
    }
}
