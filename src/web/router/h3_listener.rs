//! Owned, authenticated HTTP/3 service over the native managed UDP endpoint.

use std::net::SocketAddr;

use super::*;
use crate::channel::oneshot;
use crate::cx::{ChildRegion, ChildRegionError, ChildRegionOpening, ChildRegionSpec};
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
/// Request bodies are assembled within explicit limits. CONNECT and request
/// trailers retain the bridge's explicit refusal behavior; response producers
/// may send DATA and response trailers. Buffered response limits are applied
/// before listener retention/encoding, after application code creates them.
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

struct RequestWork {
    token: NativeH3RouterDispatchToken,
    opening: Option<ChildRegionOpening>,
    region: Option<ChildRegion>,
    dispatch: Option<NativeH3RouterDispatch>,
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
        Self {
            token: dispatch.cancellation_token(),
            opening: Some(cx.open_child_region(ChildRegionSpec::inherit().with_budget(budget))),
            region: None,
            dispatch: Some(dispatch),
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

    fn complete(&mut self) {
        if self.terminal.is_none() {
            self.terminal = Some(true);
            if let Some(command) = self.command.take() {
                let _ = command.send_blocking(None);
            }
            if let Some(completion) = self.completion.take() {
                let _ = completion.send_blocking(());
            }
        }
    }

    /// Drive only runtime ownership. Application code executes in the spawned
    /// body task; the UDP callback never polls a handler or producer directly.
    fn poll_owner(
        &mut self,
        cx: &Cx,
        config: &NativeH3ListenerConfig,
        task_cx: &mut TaskContext<'_>,
    ) -> Poll<Result<bool, NativeH3ListenerError>> {
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
                                    let prepared = dispatch.run_produced(&request_cx).await;
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
                Poll::Ready(Ok(true)) => return Poll::Ready(Ok(true)),
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
            connection.requests.retain(|_, request| {
                match request.poll_owner(cx, &self.config, task_cx) {
                    Poll::Ready(result) => {
                        let success = request.terminal == Some(true) && result.is_ok();
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
                match result {
                    Ok(Ok(made_progress)) => progress |= made_progress,
                    _ => {
                        connection.live = false;
                        connection.assembly.clear();
                        connection.retirement_deadline = None;
                        self.report.failed_connections =
                            self.report.failed_connections.saturating_add(1);
                        let _ = endpoint.remove_connection(cx, connection.id);
                        for request in connection.requests.values_mut() {
                            request.cancel(cx, self.config.request_drain_timeout);
                        }
                        progress = true;
                    }
                }
            }
            connection.requests.retain(|_, request| {
                match request.poll_owner(cx, &self.config, task_cx) {
                    Poll::Pending => true,
                    Poll::Ready(result) => {
                        let success = request.terminal == Some(true) && result.is_ok();
                        if !success && !request.reset_applied && connection.live {
                            let _ = endpoint.with_connection_mut(cx, connection.id, |transport| {
                                connection.bridge.cancel_dispatch_with_cx(
                                    cx,
                                    &mut connection.session,
                                    transport,
                                    &request.token,
                                )
                            });
                            request.reset_applied = true;
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
            match self
                .bridge
                .ingest_event_with_cx(cx, &mut self.session, connection, event)?
            {
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
                        report.refused_requests = report.refused_requests.saturating_add(1);
                    } else {
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
                        request.cancel(cx, config.request_drain_timeout);
                    }
                }
                NativeH3RouterIngress::Event(NativeH3RouterEvent::RequestRefused {
                    stream_id,
                    ..
                }) => {
                    self.assembly.remove(&stream_id);
                    report.refused_requests = report.refused_requests.saturating_add(1);
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
                let _ = self.bridge.cancel_dispatch_with_cx(
                    cx,
                    &mut self.session,
                    connection,
                    &request.token,
                );
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
                            request.complete();
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
                        request.complete();
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
