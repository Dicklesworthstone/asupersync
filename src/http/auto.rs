//! HTTP/1.1 and HTTP/2 on one port.
//!
//! [`Http1Listener`] and [`Http2Listener`] each own a socket and speak one
//! protocol, so a service that must answer both (a TLS endpoint where
//! browsers negotiate `h2` and other clients `http/1.1`, gRPC next to a
//! REST API, a proxy sending cleartext HTTP/2 with prior knowledge) needed two
//! ports. [`HttpAutoListener`] accepts each connection once, decides its
//! protocol, and hands it to an HTTP/1.1 or an HTTP/2 listener that serve the
//! same handler with their own configuration, limits, drain and statistics:
//!
//! - over TLS, by the ALPN protocol the client negotiated (`h2`, else
//!   HTTP/1.1, including clients that send no ALPN);
//! - in cleartext, by the first bytes: the HTTP/2 connection preface means
//!   HTTP/2 with prior knowledge, anything else HTTP/1.1. The bytes read to
//!   decide are replayed to the chosen protocol.
//!
//! ```ignore
//! let app = Router::new().route("/", get(FnHandler::new(index))).into_http_handler();
//! let listener = HttpAutoListener::bind("0.0.0.0:8443", app, config).await?
//!     .with_tls(acceptor); // advertising ALPN ["h2", "http/1.1"]
//! let stats = listener.run(&runtime_handle).await?;
//! ```

#[cfg(feature = "http2-streaming")]
mod streaming;
#[cfg(feature = "http2-streaming")]
pub use streaming::HttpAutoStreamingListener;

use super::handoff::{HandoffQueue, Prefixed};
use crate::cx::{CancelWakerToken, Cx};
use crate::http::h1::listener::{Http1Listener, Http1ListenerConfig};
use crate::http::h1::server::IntoHttp1Response;
use crate::http::h1::types::Request;
use crate::http::h2::connection::CLIENT_PREFACE;
use crate::http::h2::listener::{Http2Listener, Http2ListenerConfig, IntoHttp2Response};
use crate::io::AsyncReadExt;
use crate::net::tcp::listener::TcpListener;
use crate::net::tcp::stream::TcpStream;
use crate::runtime::{JoinError, JoinHandle, RuntimeHandle, SpawnError, TaskHandle};
use crate::server::connection::ConnectionManager;
use crate::server::shutdown::{ShutdownPhase, ShutdownSignal, ShutdownStats};
use crate::sync::Notify;
#[cfg(feature = "tls")]
use crate::tls::TlsAcceptor;
use crate::types::Time;
use std::future::Future;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::num::NonZeroUsize;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

/// Configuration of an [`HttpAutoListener`]: one configuration per protocol,
/// and the bounds on deciding a connection's protocol.
#[derive(Debug, Clone)]
pub struct HttpAutoListenerConfig {
    /// The HTTP/1.1 listener's configuration (host policy, limits, drain).
    pub http1: Http1ListenerConfig,
    /// The HTTP/2 listener's configuration (host policy, limits, drain).
    pub http2: Http2ListenerConfig,
    /// How long a connection may take to complete its TLS handshake, or to
    /// send enough bytes to tell HTTP/2's preface from an HTTP/1.1 request,
    /// before it is dropped. Default 10 seconds.
    pub detect_timeout: Duration,
    /// Connections whose protocol is being decided at once; more are dropped
    /// as they arrive. Default 1024.
    pub max_detecting: usize,
}

impl Default for HttpAutoListenerConfig {
    fn default() -> Self {
        Self {
            http1: Http1ListenerConfig::default(),
            http2: Http2ListenerConfig::default(),
            detect_timeout: Duration::from_secs(10),
            max_detecting: 1024,
        }
    }
}

impl HttpAutoListenerConfig {
    /// Sets the HTTP/1.1 listener's configuration.
    #[must_use]
    pub fn http1(mut self, config: Http1ListenerConfig) -> Self {
        self.http1 = config;
        self
    }

    /// Sets the HTTP/2 listener's configuration.
    #[must_use]
    pub fn http2(mut self, config: Http2ListenerConfig) -> Self {
        self.http2 = config;
        self
    }

    /// Sets the protocol-detection deadline.
    #[must_use]
    pub const fn detect_timeout(mut self, timeout: Duration) -> Self {
        self.detect_timeout = timeout;
        self
    }

    /// Sets how many connections may be in protocol detection at once.
    #[must_use]
    pub const fn max_detecting(mut self, max: usize) -> Self {
        self.max_detecting = max;
        self
    }
}

/// What each protocol's listener reported after the drain.
#[derive(Debug, Clone)]
pub struct HttpAutoShutdownStats {
    /// The HTTP/1.1 listener's shutdown statistics.
    pub http1: ShutdownStats,
    /// The HTTP/2 listener's shutdown statistics.
    pub http2: ShutdownStats,
}

/// Optional overrides keep the inner listener's defaults authoritative.
/// These cannot be fields of the exhaustively constructible public config.
#[derive(Clone, Copy, Debug, Default)]
struct Http2Options {
    preface_timeout: Option<Duration>,
    write_progress_timeout: Option<Duration>,
    flow_control_progress_timeout: Option<Duration>,
    keepalive: Option<(Duration, Duration)>,
    max_in_flight_requests: Option<NonZeroUsize>,
    max_connection_in_flight_requests: Option<NonZeroUsize>,
}

impl Http2Options {
    fn apply<F>(self, mut listener: Http2Listener<F>) -> Http2Listener<F> {
        if let Some(timeout) = self.preface_timeout {
            listener = listener.preface_timeout(timeout);
        }
        if let Some(timeout) = self.write_progress_timeout {
            listener = listener.write_progress_timeout(timeout);
        }
        if let Some(timeout) = self.flow_control_progress_timeout {
            listener = listener.flow_control_progress_timeout(timeout);
        }
        if let Some((interval, timeout)) = self.keepalive {
            listener = listener.keepalive(interval, timeout);
        }
        if let Some(max) = self.max_in_flight_requests {
            listener = listener.max_in_flight_requests(max);
        }
        if let Some(max) = self.max_connection_in_flight_requests {
            listener = listener.max_connection_in_flight_requests(max);
        }
        listener
    }
}

/// One TCP listener serving HTTP/1.1 and HTTP/2; see the
/// [module documentation](self).
///
/// Each protocol's listener applies its own configuration: its host policy,
/// `max_connections` (so the port admits up to the sum), body limits and
/// drain timeouts. HTTP/1.1 upgrade actions made with `Http1Upgrade::new_any`
/// (`WebSocketUpgrade::on_upgrade_any`) run on these connections, so a Router
/// built with `into_http1_handler()` serves WebSockets next to HTTP/2;
/// TCP-typed actions are refused before the `101`.
/// HTTP/2 keepalive, transport progress deadlines and request admission limits
/// can be set with this listener's `http2_*` builders, for both cleartext and
/// TLS connections. Other per-protocol settings live in
/// [`HttpAutoListenerConfig`].
pub struct HttpAutoListener<F> {
    listener: TcpListener,
    handler: Arc<F>,
    config: HttpAutoListenerConfig,
    http2_options: Http2Options,
    shutdown_signal: ShutdownSignal,
    #[cfg(feature = "tls")]
    tls_acceptor: Option<TlsAcceptor>,
}

impl<F, Fut, R> HttpAutoListener<F>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = R> + Send + 'static,
    R: IntoHttp1Response + IntoHttp2Response + Send + 'static,
{
    /// Binds `addr` and serves `handler` over both protocols.
    ///
    /// # Errors
    /// The bind error.
    pub async fn bind<A: ToSocketAddrs + Send + 'static>(
        addr: A,
        handler: F,
        config: HttpAutoListenerConfig,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self::from_listener(listener, handler, config))
    }

    /// Serves `handler` over both protocols on an existing listener.
    #[must_use]
    pub fn from_listener(
        listener: TcpListener,
        handler: F,
        config: HttpAutoListenerConfig,
    ) -> Self {
        Self {
            listener,
            handler: Arc::new(handler),
            config,
            http2_options: Http2Options::default(),
            shutdown_signal: ShutdownSignal::new(),
            #[cfg(feature = "tls")]
            tls_acceptor: None,
        }
    }

    /// Serves every connection over TLS and picks its protocol by ALPN. The
    /// acceptor should advertise `h2` and `http/1.1`; a client that
    /// negotiates anything but `h2`, or no ALPN, is served HTTP/1.1. Its
    /// handshake is bounded by the acceptor's handshake timeout, else by
    /// [`HttpAutoListenerConfig::detect_timeout`].
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn with_tls(mut self, acceptor: TlsAcceptor) -> Self {
        self.tls_acceptor = Some(acceptor);
        self
    }

    /// Bounds receipt of the HTTP/2 preface after protocol selection. The
    /// inner listener's default is ten seconds. Cleartext detection already
    /// reads the complete preface under [`HttpAutoListenerConfig::detect_timeout`];
    /// this separate deadline also bounds a TLS client that negotiates `h2`
    /// and then never sends its preface.
    #[must_use]
    pub fn http2_preface_timeout(mut self, timeout: Duration) -> Self {
        self.http2_options.preface_timeout = Some(timeout);
        self
    }

    /// Bounds an HTTP/2 transport write, flush or shutdown that makes no
    /// progress. The inner listener's default is ten seconds; successful
    /// writes to the handed-off transport renew the deadline. Applies after
    /// TLS handoff as well as to cleartext connections.
    #[must_use]
    pub fn http2_write_progress_timeout(mut self, timeout: Duration) -> Self {
        self.http2_options.write_progress_timeout = Some(timeout);
        self
    }

    /// Bounds an HTTP/2 response stalled by exhausted stream or connection
    /// DATA credit. The inner listener's default is ten seconds. Only flushed
    /// DATA for that stream renews the deadline; expiry cancels the stalled
    /// stream and retains its owned cleanup while other streams keep running.
    #[must_use]
    pub fn http2_flow_control_progress_timeout(mut self, timeout: Duration) -> Self {
        self.http2_options.flow_control_progress_timeout = Some(timeout);
        self
    }

    /// Enables HTTP/2 server keepalive, including gRPC calls served on this
    /// port. Sends a PING after `interval` without a frame from the client,
    /// then closes the connection when no frame arrives within `timeout`.
    /// Any frame renews liveness, as with [`Http2Listener::keepalive`]. Off by
    /// default; zero durations are raised to one millisecond.
    #[must_use]
    pub fn http2_keepalive(mut self, interval: Duration, timeout: Duration) -> Self {
        self.http2_options.keepalive = Some((interval, timeout));
        self
    }

    /// Limits in-flight HTTP/2 requests across all this port's HTTP/2
    /// connections, including cancellation cleanup and responses waiting to
    /// flush. Excess requests receive REFUSED_STREAM. The inner listener's
    /// default is 4,096. HTTP/1.1 admission uses its own configuration.
    #[must_use]
    pub fn http2_max_in_flight_requests(mut self, max: NonZeroUsize) -> Self {
        self.http2_options.max_in_flight_requests = Some(max);
        self
    }

    /// Limits live HTTP/2 request coordinators on each connection. Resetting
    /// a stream frees its slot only after its coordinator joins. The inner
    /// listener's default is 256; this composes with the listener-wide limit
    /// from [`Self::http2_max_in_flight_requests`].
    #[must_use]
    pub fn http2_max_connection_in_flight_requests(mut self, max: NonZeroUsize) -> Self {
        self.http2_options.max_connection_in_flight_requests = Some(max);
        self
    }

    /// The bound address.
    ///
    /// # Errors
    /// The socket's error.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// The signal that stops accepting: `begin_drain` on it drains both
    /// protocols' listeners, each within its own drain timeouts. An immediate
    /// stop or escalation to force-close interrupts both protocols. `Stopped`
    /// is published after the listeners and detection resources finish.
    #[must_use]
    pub fn shutdown_signal(&self) -> ShutdownSignal {
        self.shutdown_signal.clone()
    }

    /// Accepts until the shutdown signal begins draining, then drains both
    /// protocols' listeners and returns their statistics. Cancelling the task
    /// that runs this future (its region closing, a runtime drain) ends
    /// accepting the same way, as an owner's cancellation does for
    /// `Http1Listener::run_in`. The listening socket closes when accepting
    /// ends, so new connection attempts are refused during the drain, unless
    /// either protocol's config sets `lb_compat_keep_socket`.
    /// Incomplete protocol detection and TLS handshakes are cancelled, and
    /// their connections are released before this method returns. Dropping
    /// this future requests immediate cleanup from the runtime-owned children;
    /// it does not claim that their cleanup has already completed.
    ///
    /// # Errors
    /// A non-transient accept error (after draining the connections already
    /// handed over), or either listener's error.
    pub async fn run(self, runtime: &RuntimeHandle) -> io::Result<HttpAutoShutdownStats> {
        let result = self.run_with(TaskSpawner::Root(runtime.clone())).await;
        acknowledge_coordinator_cancellation();
        result
    }

    /// Serve both protocols with all listener and detection tasks in `cx`'s region.
    ///
    /// Each protocol listener uses its own `run_in`, so established connections
    /// and request tasks also belong to that region or its descendants. Closing
    /// the owning region stops acceptance and drains this entire service, with
    /// no runtime-root tasks left behind. Run this future inside the region that
    /// owns the service, for example a [`ChildRegion`](crate::cx::ChildRegion).
    ///
    /// Graceful and forced shutdown use the same signal and statistics as
    /// [`Self::run`]. Either protocol task ending early also stops acceptance and
    /// drains its sibling. This method observes every retained task's retirement
    /// before reporting completion. Dropping the future requests immediate
    /// cleanup; the region remains responsible for awaiting that cleanup.
    ///
    /// # Errors
    /// The accept/listener errors of [`Self::run`], or a task-admission, task
    /// cancellation or panic error. A context without runtime spawn wiring is
    /// refused before accepting connections.
    pub async fn run_in(self, cx: &Cx) -> io::Result<HttpAutoShutdownStats> {
        let result = self.run_with(TaskSpawner::Owned(cx.clone())).await;
        acknowledge_coordinator_cancellation();
        result
    }

    async fn run_with(self, spawner: TaskSpawner) -> io::Result<HttpAutoShutdownStats> {
        let http1_queue = Arc::new(HandoffQueue::default());
        let http2_queue = Arc::new(HandoffQueue::default());
        let handler = Arc::clone(&self.handler);
        let http1 = Http1Listener::from_handoff(
            Arc::clone(&http1_queue),
            move |request: Request| (*handler)(request),
            self.config.http1.clone(),
        );
        let handler = Arc::clone(&self.handler);
        let http2 = self.http2_options.apply(Http2Listener::from_handoff(
            Arc::clone(&http2_queue),
            move |request: Request| (*handler)(request),
            self.config.http2.clone(),
        ));
        let http1 = ProtocolService {
            queue: http1_queue,
            manager: http1.connection_manager().clone(),
            run: move |child: TaskSpawner| async move {
                match child {
                    TaskSpawner::Root(runtime) => http1.run(&runtime).await,
                    TaskSpawner::Owned(cx) => http1.run_in(&cx).await,
                }
            },
        };
        let http2 = ProtocolService {
            queue: http2_queue,
            manager: http2.connection_manager().clone(),
            run: move |child: TaskSpawner| async move {
                match child {
                    TaskSpawner::Root(runtime) => http2.run(&runtime).await,
                    TaskSpawner::Owned(cx) => http2.run_in(&cx).await,
                }
            },
        };
        AutoCoordinator {
            listener: self.listener,
            config: self.config,
            shutdown_signal: self.shutdown_signal,
            #[cfg(feature = "tls")]
            tls_acceptor: self.tls_acceptor,
        }
        .run(spawner, http1, http2)
        .await
    }
}

// Both buffered and streaming handlers use this one accept/detect/drain path.
// Protocol factories choose only the established per-protocol serving mode;
// they cannot replace connection detection, admission, or terminal ownership.
struct ProtocolService<F> {
    queue: Arc<HandoffQueue>,
    manager: ConnectionManager,
    run: F,
}

struct AutoCoordinator {
    listener: TcpListener,
    config: HttpAutoListenerConfig,
    shutdown_signal: ShutdownSignal,
    #[cfg(feature = "tls")]
    tls_acceptor: Option<TlsAcceptor>,
}

impl AutoCoordinator {
    async fn run<F1, F2, Fut1, Fut2>(
        self,
        spawner: TaskSpawner,
        http1: ProtocolService<F1>,
        http2: ProtocolService<F2>,
    ) -> io::Result<HttpAutoShutdownStats>
    where
        F1: FnOnce(TaskSpawner) -> Fut1 + Send + 'static,
        F2: FnOnce(TaskSpawner) -> Fut2 + Send + 'static,
        Fut1: Future<Output = io::Result<ShutdownStats>> + Send + 'static,
        Fut2: Future<Output = io::Result<ShutdownStats>> + Send + 'static,
    {
        #[cfg(feature = "tls")]
        if let Some(acceptor) = &self.tls_acceptor
            && !acceptor
                .config()
                .alpn_protocols
                .iter()
                .any(|protocol| protocol.as_slice() == b"h2")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HttpAutoListener::with_tls needs an acceptor that advertises the h2 ALPN protocol",
            ));
        }

        let http1_drain = self.config.http1.drain_timeout;
        let http2_drain = self.config.http2.drain_timeout;
        let ProtocolService { queue: http1_queue, manager: http1_manager, run: run_http1 } = http1;
        let ProtocolService { queue: http2_queue, manager: http2_manager, run: run_http2 } = http2;
        let mut shutdown = ProtocolShutdown {
            signal: self.shutdown_signal.clone(),
            http1: http1_manager,
            http2: http2_manager,
            completed: false,
        };
        let mut http1_run = match spawner.spawn(run_http1) {
            Ok(run) => ProtocolRun::new(run),
            Err(error) => {
                drop(self.listener);
                shutdown.finish();
                return Err(io::Error::other(format!("spawn HTTP/1.1 listener: {error}")));
            }
        };
        let http2_run = match spawner.spawn(run_http2) {
            Ok(run) => ProtocolRun::new(run),
            Err(error) => {
                // The first spawn already owns a live accept loop. Stop and
                // join it before reporting that the second spawn was refused.
                shutdown.signal.trigger_immediate();
                shutdown.force_protocols();
                let _ = http1_run.join().await;
                http1_queue.close();
                http2_queue.close();
                drop(self.listener);
                shutdown.finish();
                return Err(io::Error::other(format!("spawn HTTP/2 listener: {error}")));
            }
        };

        let mut protocols = ProtocolListeners {
            http1: http1_run,
            http2: http2_run,
            http1_queue,
            http2_queue,
        };
        let mut detecting = DetectionRuns::default();
        let accept_result = self
            .accept_loop(&spawner, &mut protocols, &mut detecting)
            .await;
        // Close the listening socket when accepting ends unless either
        // protocol explicitly retains it for load-balancer compatibility.
        let keep_socket =
            self.config.http1.lb_compat_keep_socket || self.config.http2.lb_compat_keep_socket;
        let parked_socket = keep_socket.then_some(self.listener);

        let _ = self
            .shutdown_signal
            .begin_drain(http1_drain.max(http2_drain));
        let _ = shutdown.http1.begin_drain(http1_drain);
        let _ = shutdown.http2.begin_drain(http2_drain);
        let (http1_stats, http2_stats) =
            drain_protocols(&shutdown, protocols.http1.join(), protocols.http2.join()).await;
        // Wait until neither accept loop can observe a closed queue as an
        // accept error. Close then fences pushes that raced the stop check.
        protocols.http1_queue.close();
        protocols.http2_queue.close();
        detecting.slots.wait_idle().await;
        detecting.join_all().await;
        // A failed listener can return before its root-owned connections do.
        // drain_protocols has requested force-close on that error path.
        shutdown.http1.wait_all_closed().await;
        shutdown.http2.wait_all_closed().await;
        drop(parked_socket);
        shutdown.finish();
        accept_result?;
        Ok(HttpAutoShutdownStats {
            http1: http1_stats?,
            http2: http2_stats?,
        })
    }

    async fn accept_loop(
        &self,
        spawner: &TaskSpawner,
        protocols: &mut ProtocolListeners,
        detecting: &mut DetectionRuns,
    ) -> io::Result<()> {
        let mut shutdown = self.shutdown_signal.subscribe();
        let mut transient_streak: u32 = 0;
        // Once this task's cancellation is requested, accept fails with
        // Interrupted on every poll. End acceptance instead of spinning.
        let mut owner = OwnerCancellation {
            cx: spawner.owner(),
            token: None,
        };
        let mut coordinator = OwnerCancellation {
            cx: Cx::current(),
            token: None,
        };
        loop {
            let owner_cancelled = owner.is_requested();
            let coordinator_cancelled = coordinator.is_requested();
            if self.shutdown_signal.is_shutting_down() || owner_cancelled || coordinator_cancelled {
                return Ok(());
            }
            let accepted = {
                let mut accept = pin!(self.listener.accept());
                let mut stop = pin!(shutdown.wait());
                std::future::poll_fn(|cx| {
                    let owner_cancelled = owner.poll_cancelled(cx);
                    let coordinator_cancelled = coordinator.poll_cancelled(cx);
                    if self.shutdown_signal.is_shutting_down()
                        || owner_cancelled
                        || coordinator_cancelled
                        || stop.as_mut().poll(cx).is_ready()
                    {
                        return Poll::Ready(None);
                    }
                    // Retain both passive terminal observers while parked.
                    // Cached results remain available to the common drain.
                    let http1_done = protocols.http1.poll_completion(cx);
                    let http2_done = protocols.http2.poll_completion(cx);
                    if http1_done || http2_done {
                        return Poll::Ready(None);
                    }
                    accept.as_mut().poll(cx).map(Some)
                })
                .await
            };
            let Some(accepted) = accepted else {
                return Ok(());
            };
            let (stream, peer) = match accepted {
                Ok(connection) => {
                    transient_streak = 0;
                    connection
                }
                Err(error) if is_transient_accept_error(&error) => {
                    transient_streak = transient_streak.saturating_add(1);
                    let delay = Duration::from_millis(2_u64 << transient_streak.min(5));
                    let _ = until_shutdown(
                        &self.shutdown_signal,
                        crate::time::sleep(now(), delay),
                    )
                    .await;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let Some(slot) = detecting.slots.acquire(self.config.max_detecting) else {
                drop(stream);
                continue;
            };
            let detection = Detection {
                http1: Arc::clone(&protocols.http1_queue),
                http2: Arc::clone(&protocols.http2_queue),
                #[cfg(feature = "tls")]
                tls: self.tls_acceptor.clone(),
                timeout: self.config.detect_timeout,
                shutdown: self.shutdown_signal.clone(),
            };
            // The detection future owns its socket and slot even when
            // admission fails or it is dropped before the first poll.
            let connection = DetectingConnection { stream, peer, slot };
            if let Ok(task) = spawner.spawn(move |_| detection.hand_off(connection)) {
                detecting.push(task);
            }
        }
    }
}

/// Every spawn in an owned listener stays in the supplied context's region.
#[derive(Clone)]
enum TaskSpawner {
    Root(RuntimeHandle),
    Owned(Cx),
}

impl TaskSpawner {
    fn owner(&self) -> Option<Cx> {
        match self {
            Self::Root(_) => None,
            Self::Owned(cx) => Some(cx.clone()),
        }
    }

    fn spawn<F, Fut, T>(&self, factory: F) -> Result<ListenerTask<T>, SpawnError>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        match self {
            Self::Root(runtime) => runtime
                .try_spawn(factory(Self::Root(runtime.clone())))
                .map(ListenerTask::Root),
            Self::Owned(owner) => owner
                .spawn(move |cx| async move {
                    let result = factory(Self::Owned(cx.clone())).await;
                    // These tasks deliberately finish protocol cleanup after
                    // cancellation. Preserve the resulting drain statistics.
                    if cx.is_cancel_requested() {
                        let _ = cx.checkpoint();
                    }
                    result
                })
                .map(ListenerTask::Owned),
        }
    }
}

enum ListenerTask<T> {
    Root(JoinHandle<T>),
    Owned(TaskHandle<T>),
}

impl<T> ListenerTask<T> {
    fn is_finished(&self) -> bool {
        match self {
            Self::Root(task) => task.is_finished(),
            Self::Owned(task) => task.is_finished(),
        }
    }

    /// Passive terminal observation: Pending retains the handle's wake source
    /// and never requests cancellation just because a competing branch wins.
    fn poll_result(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        match self {
            Self::Root(task) => {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    Pin::new(task).poll(cx)
                })) {
                    Ok(result) => result.map(Ok),
                    Err(payload) => Poll::Ready(Err(io::Error::other(format!(
                        "HTTP task failed: {}",
                        crate::cx::scope::payload_to_string(&payload)
                    )))),
                }
            }
            Self::Owned(task) => task.poll_join(cx).map(|result| {
                result.map_err(|error| {
                    let kind = if matches!(error, JoinError::Cancelled(_)) {
                        io::ErrorKind::Interrupted
                    } else {
                        io::ErrorKind::Other
                    };
                    io::Error::new(kind, error.to_string())
                })
            }),
        }
    }
}

struct ProtocolRun {
    task: ListenerTask<io::Result<ShutdownStats>>,
    result: Option<io::Result<ShutdownStats>>,
}

impl ProtocolRun {
    fn new(task: ListenerTask<io::Result<ShutdownStats>>) -> Self {
        Self { task, result: None }
    }

    fn poll_completion(&mut self, cx: &mut Context<'_>) -> bool {
        if self.result.is_none()
            && let Poll::Ready(result) = self.task.poll_result(cx)
        {
            self.result = Some(result.and_then(std::convert::identity));
        }
        self.result.is_some()
    }

    async fn join(&mut self) -> io::Result<ShutdownStats> {
        std::future::poll_fn(|cx| {
            if self.poll_completion(cx) {
                Poll::Ready(self.result.take().expect("protocol terminal observed"))
            } else {
                Poll::Pending
            }
        })
        .await
    }
}

struct ProtocolListeners {
    http1: ProtocolRun,
    http2: ProtocolRun,
    http1_queue: Arc<HandoffQueue>,
    http2_queue: Arc<HandoffQueue>,
}

#[derive(Default)]
struct DetectionRuns {
    slots: Arc<DetectionTasks>,
    tasks: Vec<ListenerTask<()>>,
    spawned: u64,
}

impl DetectionRuns {
    fn push(&mut self, task: ListenerTask<()>) {
        self.tasks.push(task);
        self.spawned = self.spawned.wrapping_add(1);
        if self.spawned.is_multiple_of(64) {
            self.tasks.retain(|task| !task.is_finished());
        }
    }

    async fn join_all(&mut self) {
        for mut task in self.tasks.drain(..) {
            let _ = std::future::poll_fn(|cx| task.poll_result(cx)).await;
        }
    }
}

struct OwnerCancellation {
    cx: Option<Cx>,
    token: Option<CancelWakerToken>,
}

impl OwnerCancellation {
    fn is_requested(&self) -> bool {
        self.cx.as_ref().is_some_and(|cx| {
            if cx.is_cancel_requested() {
                let _ = cx.checkpoint();
                true
            } else {
                false
            }
        })
    }

    fn poll_cancelled(&mut self, task: &Context<'_>) -> bool {
        if let Some(cx) = &self.cx {
            self.token = Some(cx.refresh_cancel_waker(self.token.take(), task.waker()));
        }
        self.is_requested()
    }
}

impl Drop for OwnerCancellation {
    fn drop(&mut self) {
        if let Some(cx) = &self.cx
            && let Some(token) = self.token.take()
        {
            cx.clear_cancel_waker(token);
        }
    }
}

fn acknowledge_coordinator_cancellation() {
    // Cancellation can arrive after accepting ended, while the retained
    // children drain. Preserve their actual result after that cleanup too.
    if let Some(cx) = Cx::current()
        && cx.is_cancel_requested()
    {
        let _ = cx.checkpoint();
    }
}

/// A dropped/panicking run must not leave root-owned protocol and detection
/// tasks accepting forever. Drop requests cleanup, never publishes quiescence.
struct ProtocolShutdown {
    signal: ShutdownSignal,
    http1: ConnectionManager,
    http2: ConnectionManager,
    completed: bool,
}

impl ProtocolShutdown {
    fn force_protocols(&self) {
        // Use the managers, not just their signals: they close admission and
        // capture the exact force-close counts before waking connection tasks.
        self.http1.force_close();
        self.http2.force_close();
    }

    fn finish(&mut self) {
        self.completed = true;
        self.signal.mark_stopped();
    }
}

impl Drop for ProtocolShutdown {
    fn drop(&mut self) {
        if !self.completed {
            self.signal.trigger_immediate();
            self.force_protocols();
        }
    }
}

/// Keep forwarding a later force-close while BOTH protocol joins are driven.
/// Neither an early result nor an error from one listener drops the other.
async fn drain_protocols(
    shutdown: &ProtocolShutdown,
    http1: impl Future<Output = io::Result<ShutdownStats>>,
    http2: impl Future<Output = io::Result<ShutdownStats>>,
) -> (io::Result<ShutdownStats>, io::Result<ShutdownStats>) {
    let mut http1 = pin!(http1);
    let mut http2 = pin!(http2);
    let mut force = pin!(shutdown.signal.wait_for_phase(ShutdownPhase::ForceClosing));
    let mut forwarded = false;
    let mut first = None;
    let mut second = None;
    std::future::poll_fn(|cx| {
        if !forwarded && force.as_mut().poll(cx).is_ready() {
            shutdown.force_protocols();
            forwarded = true;
        }
        if first.is_none()
            && let Poll::Ready(result) = http1.as_mut().poll(cx)
        {
            first = Some(result);
        }
        if second.is_none()
            && let Poll::Ready(result) = http2.as_mut().poll(cx)
        {
            second = Some(result);
        }
        if !forwarded
            && (first.as_ref().is_some_and(Result::is_err)
                || second.as_ref().is_some_and(Result::is_err))
        {
            shutdown.signal.trigger_immediate();
            shutdown.force_protocols();
            forwarded = true;
        }
        if first.is_some() && second.is_some() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    (
        first.expect("HTTP/1.1 join completed"),
        second.expect("HTTP/2 join completed"),
    )
}

/// Detection only reads an unadmitted connection or performs its handshake:
/// dropping that work on shutdown closes the transport instead of abandoning
/// an established request. Poll shutdown first, including on the first poll.
async fn until_shutdown<T>(
    shutdown: &ShutdownSignal,
    operation: impl Future<Output = T>,
) -> Option<T> {
    let mut receiver = shutdown.subscribe();
    let mut stop = pin!(receiver.wait());
    let mut operation = pin!(operation);
    std::future::poll_fn(|cx| {
        if shutdown.is_shutting_down() || stop.as_mut().poll(cx).is_ready() {
            Poll::Ready(None)
        } else {
            operation.as_mut().poll(cx).map(Some)
        }
    })
    .await
}

fn now() -> Time {
    Cx::current()
        .and_then(|cx| cx.timer_driver())
        .map_or_else(crate::time::wall_now, |timer| timer.now())
}

fn is_transient_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionRefused
    ) || crate::net::tcp::listener::is_accept_resource_exhaustion(error)
}

/// One accepted connection on its way to a protocol's listener.
struct Detection {
    http1: Arc<HandoffQueue>,
    http2: Arc<HandoffQueue>,
    #[cfg(feature = "tls")]
    tls: Option<TlsAcceptor>,
    timeout: Duration,
    shutdown: ShutdownSignal,
}

// Declaration order also releases the socket before the completion slot if
// the spawned future is dropped before its very first poll.
struct DetectingConnection {
    stream: TcpStream,
    peer: SocketAddr,
    slot: DetectionSlot,
}

impl Detection {
    async fn hand_off(self, connection: DetectingConnection) {
        let DetectingConnection { stream, peer, slot } = connection;
        let _slot = slot;
        // The operation (and its socket) is dropped before the slot signals
        // completion, so an idle observation is a resource-release barrier.
        let _ = until_shutdown(&self.shutdown, self.detect(stream, peer)).await;
    }

    async fn detect(&self, stream: TcpStream, peer: SocketAddr) {
        #[cfg(feature = "tls")]
        if let Some(acceptor) = &self.tls {
            let counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let stream = super::handoff::SocketByteCounter::new(stream, std::sync::Arc::clone(&counter));
            let bound = acceptor.handshake_timeout().unwrap_or(self.timeout);
            let Ok(Ok(tls)) = crate::time::timeout(now(), bound, acceptor.accept(stream)).await
            else {
                return;
            };
            let http2 = tls.alpn_protocol() == Some(b"h2".as_slice());
            self.push(
                http2,
                super::handoff::HandoffStream::with_socket_counter(Box::new(tls), counter),
                peer,
            );
            return;
        }
        let mut stream = stream;
        let mut seen = Vec::with_capacity(CLIENT_PREFACE.len());
        let decided = crate::time::timeout(
            now(),
            self.timeout,
            read_until_decided(&mut stream, &mut seen),
        )
        .await;
        let Ok(Ok(Some(http2))) = decided else {
            return;
        };
        self.push(
            http2,
            super::handoff::HandoffStream::new(Box::new(Prefixed::new(seen, stream))),
            peer,
        );
    }

    fn push(&self, http2: bool, stream: super::handoff::HandoffStream, peer: SocketAddr) {
        // A connection decided after the drain began is closed, not queued
        // for a listener that no longer accepts.
        if self.shutdown.is_shutting_down() {
            return;
        }
        let queue = if http2 { &self.http2 } else { &self.http1 };
        queue.push(stream, Some(peer));
    }
}

/// Reads until the bytes stop matching HTTP/2's connection preface
/// (`Some(false)`: HTTP/1.1) or match all of it (`Some(true)`). `None` when
/// the peer closes first.
async fn read_until_decided(
    stream: &mut TcpStream,
    seen: &mut Vec<u8>,
) -> io::Result<Option<bool>> {
    let mut buf = [0_u8; 24];
    loop {
        let wanted = CLIENT_PREFACE.len() - seen.len();
        let read = AsyncReadExt::read(stream, &mut buf[..wanted]).await?;
        if read == 0 {
            return Ok(None);
        }
        seen.extend_from_slice(&buf[..read]);
        if !CLIENT_PREFACE.starts_with(seen) {
            return Ok(Some(false));
        }
        if seen.len() == CLIENT_PREFACE.len() {
            return Ok(Some(true));
        }
    }
}

/// Bounded detection admission and a barrier for releasing accepted sockets.
#[derive(Default)]
struct DetectionTasks {
    active: AtomicUsize,
    idle: Notify,
}

impl DetectionTasks {
    // See the note on `advance_transaction_generation` in `database::sqlite`:
    // `fetch_update` is deprecated on the pinned nightly and absent from the
    // stable subset, so the stable-compatible spelling stays with an allow.
    #[allow(deprecated)]
    fn acquire(self: &Arc<Self>, max: usize) -> Option<DetectionSlot> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < max).then(|| active + 1)
            })
            .ok()
            .map(|_| DetectionSlot(Arc::clone(self)))
    }

    async fn wait_idle(&self) {
        while self.active.load(Ordering::Acquire) != 0 {
            // notify_one retains a permit if the last slot finishes between
            // the count check and registration of this sole drain waiter.
            self.idle.notified().await;
        }
    }
}

/// Releases a detection slot when the detection ends, however it ends.
struct DetectionSlot(Arc<DetectionTasks>);

impl Drop for DetectionSlot {
    fn drop(&mut self) {
        if self.0.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.idle.notify_one();
        }
    }
}

#[cfg(test)]
#[path = "auto_inline_tests.rs"]
mod tests;
