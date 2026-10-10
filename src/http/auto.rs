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

use super::handoff::{HandoffQueue, Prefixed};
use crate::cx::Cx;
use crate::http::h1::listener::{Http1Listener, Http1ListenerConfig};
use crate::http::h1::server::IntoHttp1Response;
use crate::http::h1::types::Request;
use crate::http::h2::connection::CLIENT_PREFACE;
use crate::http::h2::listener::{Http2Listener, Http2ListenerConfig, IntoHttp2Response};
use crate::io::AsyncReadExt;
use crate::net::tcp::listener::TcpListener;
use crate::net::tcp::stream::TcpStream;
use crate::runtime::RuntimeHandle;
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
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
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
        let http1_queue = Arc::new(HandoffQueue::default());
        let http2_queue = Arc::new(HandoffQueue::default());
        let handler = Arc::clone(&self.handler);
        let http1_drain = self.config.http1.drain_timeout;
        let http1 = Http1Listener::from_handoff(
            Arc::clone(&http1_queue),
            move |request: Request| (*handler)(request),
            self.config.http1.clone(),
        );
        let handler = Arc::clone(&self.handler);
        let http2_drain = self.config.http2.drain_timeout;
        let http2 = self.http2_options.apply(Http2Listener::from_handoff(
            Arc::clone(&http2_queue),
            move |request: Request| (*handler)(request),
            self.config.http2.clone(),
        ));
        let mut shutdown = ProtocolShutdown {
            signal: self.shutdown_signal.clone(),
            http1: http1.connection_manager().clone(),
            http2: http2.connection_manager().clone(),
            completed: false,
        };
        let http1_runtime = runtime.clone();
        let http1_run = match runtime.try_spawn(async move { http1.run(&http1_runtime).await }) {
            Ok(run) => run,
            Err(error) => {
                drop(self.listener);
                shutdown.finish();
                return Err(io::Error::other(format!("spawn HTTP/1.1 listener: {error}")));
            }
        };
        let http2_runtime = runtime.clone();
        let http2_run = match runtime.try_spawn(async move { http2.run(&http2_runtime).await }) {
            Ok(run) => run,
            Err(error) => {
                // The first spawn already owns a live accept loop. Stop and
                // join it before reporting that the second spawn was refused.
                shutdown.signal.trigger_immediate();
                shutdown.force_protocols();
                let _ = http1_run.await;
                http1_queue.close();
                http2_queue.close();
                drop(self.listener);
                shutdown.finish();
                return Err(io::Error::other(format!("spawn HTTP/2 listener: {error}")));
            }
        };

        let detecting = Arc::new(DetectionTasks::default());
        let accept_result = self
            .accept_loop(runtime, &http1_queue, &http2_queue, &detecting)
            .await;
        // Accepting is over: close the listening socket now, as the HTTP/1.1
        // and HTTP/2 listeners do when their drain starts, so a new client is
        // refused at once instead of queuing in the backlog through the drain
        // and then being reset. As with them, `lb_compat_keep_socket` (in
        // either protocol's config) keeps it bound until the drain is over.
        let keep_socket =
            self.config.http1.lb_compat_keep_socket || self.config.http2.lb_compat_keep_socket;
        let parked_socket = keep_socket.then_some(self.listener);

        let _ = self
            .shutdown_signal
            .begin_drain(http1_drain.max(http2_drain));
        let _ = shutdown.http1.begin_drain(http1_drain);
        let _ = shutdown.http2.begin_drain(http2_drain);
        let (http1_stats, http2_stats) = drain_protocols(&shutdown, http1_run, http2_run).await;
        // Wait until neither accept loop can observe a closed queue as an
        // accept error. Close then fences pushes that raced the stop check.
        http1_queue.close();
        http2_queue.close();
        detecting.wait_idle().await;
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
        runtime: &RuntimeHandle,
        http1_queue: &Arc<HandoffQueue>,
        http2_queue: &Arc<HandoffQueue>,
        detecting: &Arc<DetectionTasks>,
    ) -> io::Result<()> {
        let mut shutdown = self.shutdown_signal.subscribe();
        let mut transient_streak: u32 = 0;
        // Once this task's cancellation is requested, accept fails with
        // `Interrupted` on every poll and the backoff sleep completes at once:
        // treated as transient, the loop would spin and never drain. The
        // cancellation ends accepting instead, like the shutdown signal.
        let owner = Cx::current();
        let cancelled = || owner.as_ref().is_some_and(Cx::is_cancel_requested);
        loop {
            if self.shutdown_signal.is_shutting_down() || cancelled() {
                return Ok(());
            }
            let accepted = {
                let mut accept = pin!(self.listener.accept());
                let mut stop = pin!(shutdown.wait());
                std::future::poll_fn(|cx| {
                    if self.shutdown_signal.is_shutting_down()
                        || cancelled()
                        || stop.as_mut().poll(cx).is_ready()
                    {
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
                    // Back off so a persistent condition (EMFILE) does not spin.
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
            let Some(slot) = detecting.acquire(self.config.max_detecting) else {
                drop(stream);
                continue;
            };
            // Owned by the detection future, so the slot is released even if
            // the future is dropped without running.
            let detection = Detection {
                http1: Arc::clone(http1_queue),
                http2: Arc::clone(http2_queue),
                #[cfg(feature = "tls")]
                tls: self.tls_acceptor.clone(),
                timeout: self.config.detect_timeout,
                shutdown: self.shutdown_signal.clone(),
            };
            // A spawn failure drops the future, and with it the connection and
            // its detection slot.
            let connection = DetectingConnection { stream, peer, slot };
            let _ = runtime.try_spawn(detection.hand_off(connection));
        }
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
            | io::ErrorKind::OutOfMemory
    ) || matches!(error.raw_os_error(), Some(23 | 24 | 105))
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
            let bound = acceptor.handshake_timeout().unwrap_or(self.timeout);
            let Ok(Ok(tls)) = crate::time::timeout(now(), bound, acceptor.accept(stream)).await
            else {
                return;
            };
            let http2 = tls.alpn_protocol() == Some(b"h2".as_slice());
            self.push(http2, Box::new(tls), peer);
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
        self.push(http2, Box::new(Prefixed::new(seen, stream)), peer);
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
mod tests {
    use super::*;
    use crate::http::h1::server::{HostPolicy, Http1Config};
    use crate::http::h1::types::Response;
    use crate::http::h2::client::Http2Client;
    use crate::io::AsyncWriteExt;
    use crate::runtime::RuntimeBuilder;
    use std::sync::atomic::AtomicBool;
    use std::task::{Context, Wake, Waker};

    struct WakeFlag(AtomicBool);

    impl Wake for WakeFlag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[test]
    fn detection_admission_and_idle_wait_cover_every_slot() {
        let tasks = Arc::new(DetectionTasks::default());
        assert!(tasks.acquire(0).is_none());
        let first = tasks.acquire(2).expect("first slot");
        let second = tasks.acquire(2).expect("second slot");
        assert!(tasks.acquire(2).is_none());
        assert_eq!(tasks.active.load(Ordering::Acquire), 2);

        let flag = Arc::new(WakeFlag(AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&flag));
        let mut cx = Context::from_waker(&waker);
        let mut idle = pin!(tasks.wait_idle());
        assert!(idle.as_mut().poll(&mut cx).is_pending());
        drop(first);
        assert!(idle.as_mut().poll(&mut cx).is_pending());
        assert!(!flag.0.load(Ordering::Acquire));
        drop(second);
        assert!(flag.0.load(Ordering::Acquire));
        assert!(idle.as_mut().poll(&mut cx).is_ready());

        // A completed burst may leave a notification permit. It must not
        // make a later drain finish while a new connection is still owned.
        let slot = tasks.acquire(1).expect("reused capacity");
        let mut idle = pin!(tasks.wait_idle());
        assert!(idle.as_mut().poll(&mut cx).is_pending());
        drop(slot);
        assert!(idle.as_mut().poll(&mut cx).is_ready());
        assert_eq!(tasks.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn shutdown_preempts_detection_and_drops_it_before_completion() {
        struct PendingOperation<'a> {
            polls: &'a AtomicUsize,
            dropped: &'a AtomicBool,
        }
        impl Future for PendingOperation<'_> {
            type Output = ();

            fn poll(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
                self.polls.fetch_add(1, Ordering::Relaxed);
                Poll::Pending
            }
        }
        impl Drop for PendingOperation<'_> {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::Release);
            }
        }

        for already_stopped in [false, true] {
            let shutdown = ShutdownSignal::new();
            let polls = AtomicUsize::new(0);
            let dropped = AtomicBool::new(false);
            let flag = Arc::new(WakeFlag(AtomicBool::new(false)));
            let waker = Waker::from(Arc::clone(&flag));
            let mut cx = Context::from_waker(&waker);
            if already_stopped {
                shutdown.trigger_immediate();
            }
            let mut operation = pin!(until_shutdown(
                &shutdown,
                PendingOperation {
                    polls: &polls,
                    dropped: &dropped,
                },
            ));
            if !already_stopped {
                assert!(operation.as_mut().poll(&mut cx).is_pending());
                assert_eq!(polls.load(Ordering::Relaxed), 1);
                assert!(!dropped.load(Ordering::Acquire));
                assert!(shutdown.begin_drain(Duration::from_secs(30)));
                assert!(flag.0.load(Ordering::Acquire));
            }
            assert_eq!(operation.as_mut().poll(&mut cx), Poll::Ready(None));
            assert!(dropped.load(Ordering::Acquire));
            assert_eq!(polls.load(Ordering::Relaxed), usize::from(!already_stopped));
        }
    }

    #[test]
    fn detection_result_is_preserved_while_running() {
        let shutdown = ShutdownSignal::new();
        let mut operation = pin!(until_shutdown(&shutdown, std::future::ready(42)));
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(operation.as_mut().poll(&mut cx), Poll::Ready(Some(42)));
    }

    fn stalled_connection_closes_on_shutdown(mut detection: Detection) {
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("runtime");
        let handle = runtime.handle();
        runtime.block_on(handle.spawn(async move {
            // Capture the runtime's clock, as the public listener does.
            detection.shutdown = ShutdownSignal::new();
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let mut client = TcpStream::connect(listener.local_addr().expect("address"))
                .await
                .expect("connect");
            let (stream, peer) = listener.accept().await.expect("accept");
            let tasks = Arc::new(DetectionTasks::default());
            let slot = tasks.acquire(1).expect("detection slot");
            let shutdown = detection.shutdown.clone();
            let mut handoff = pin!(detection.hand_off(DetectingConnection {
                stream,
                peer,
                slot,
            }));

            // This is the actual native TCP read / TLS handshake, polled to
            // Pending before the stop. No sleep guesses that it was reached.
            std::future::poll_fn(|cx| {
                assert!(handoff.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(tasks.active.load(Ordering::Acquire), 1);
            assert!(shutdown.begin_drain(Duration::from_secs(30)));
            crate::time::timeout(now(), Duration::from_secs(2), handoff.as_mut())
                .await
                .expect("shutdown must not wait for the detection deadline");
            assert_eq!(tasks.active.load(Ordering::Acquire), 0);
            let mut buf = [0_u8; 1];
            let read = crate::time::timeout(
                now(),
                Duration::from_secs(2),
                AsyncReadExt::read(&mut client, &mut buf),
            )
            .await
            .expect("detection completion must release the socket")
            .expect("peer read");
            assert_eq!(read, 0, "no protocol response is sent to an undecided peer");
        }));
    }

    fn detection() -> Detection {
        Detection {
            http1: Arc::new(HandoffQueue::default()),
            http2: Arc::new(HandoffQueue::default()),
            #[cfg(feature = "tls")]
            tls: None,
            timeout: Duration::from_secs(60),
            shutdown: ShutdownSignal::new(),
        }
    }

    #[test]
    fn shutdown_interrupts_a_native_preface_read() {
        stalled_connection_closes_on_shutdown(detection());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn shutdown_interrupts_a_native_tls_handshake() {
        use crate::tls::{CertificateChain, PrivateKey, TlsAcceptorBuilder};

        let chain = CertificateChain::from_pem(include_bytes!(
            "../../tests/fixtures/tls/server.crt"
        ))
        .expect("certificate chain");
        let key = PrivateKey::from_pem(include_bytes!("../../tests/fixtures/tls/server.key"))
            .expect("private key");
        let mut detection = detection();
        detection.tls = Some(TlsAcceptorBuilder::new(chain, key).build().expect("acceptor"));
        stalled_connection_closes_on_shutdown(detection);
    }

    fn protocol_shutdown() -> ProtocolShutdown {
        ProtocolShutdown {
            signal: ShutdownSignal::new(),
            http1: ConnectionManager::new(None, ShutdownSignal::new()),
            http2: ConnectionManager::new(None, ShutdownSignal::new()),
            completed: false,
        }
    }

    fn empty_stats() -> ShutdownStats {
        ShutdownStats {
            drained: 0,
            force_closed: 0,
            duration: Duration::ZERO,
            drain_report: None,
        }
    }

    #[test]
    fn force_close_is_forwarded_before_and_during_protocol_drain() {
        for immediate in [false, true] {
            let mut shutdown = protocol_shutdown();
            let second_done = AtomicBool::new(false);
            let flag = Arc::new(WakeFlag(AtomicBool::new(false)));
            let waker = Waker::from(Arc::clone(&flag));
            let mut cx = Context::from_waker(&waker);
            assert!(shutdown.signal.begin_drain(Duration::from_secs(60)));
            if immediate {
                shutdown.signal.trigger_immediate();
            }
            let first = std::future::ready(Ok(empty_stats()));
            let second = std::future::poll_fn(|_| {
                if second_done.load(Ordering::Acquire) {
                    Poll::Ready(Ok(empty_stats()))
                } else {
                    Poll::Pending
                }
            });
            let mut drain = Box::pin(drain_protocols(&shutdown, first, second));
            assert!(drain.as_mut().poll(&mut cx).is_pending());
            if !immediate {
                assert_eq!(shutdown.http1.shutdown_phase(), ShutdownPhase::Running);
                assert_eq!(shutdown.http2.shutdown_phase(), ShutdownPhase::Running);
                assert!(shutdown.signal.begin_force_close());
                assert!(flag.0.load(Ordering::Acquire));
                assert!(drain.as_mut().poll(&mut cx).is_pending());
            }
            assert_eq!(shutdown.http1.shutdown_phase(), ShutdownPhase::ForceClosing);
            assert_eq!(shutdown.http2.shutdown_phase(), ShutdownPhase::ForceClosing);
            second_done.store(true, Ordering::Release);
            assert!(matches!(
                drain.as_mut().poll(&mut cx),
                Poll::Ready((Ok(_), Ok(_)))
            ));
            drop(drain);
            shutdown.finish();
            let signal = shutdown.signal.clone();
            drop(shutdown);
            assert_eq!(signal.phase(), ShutdownPhase::Stopped);
        }
    }

    #[test]
    fn protocol_error_forces_the_sibling_but_still_awaits_it() {
        let shutdown = protocol_shutdown();
        let second_done = AtomicBool::new(false);
        let second = std::future::poll_fn(|_| {
            if second_done.load(Ordering::Acquire) {
                Poll::Ready(Ok(empty_stats()))
            } else {
                Poll::Pending
            }
        });
        let first = std::future::ready(Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "listener failed",
        )));
        let mut drain = pin!(drain_protocols(&shutdown, first, second));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(drain.as_mut().poll(&mut cx).is_pending());
        assert_eq!(shutdown.signal.phase(), ShutdownPhase::ForceClosing);
        assert_eq!(shutdown.http1.shutdown_phase(), ShutdownPhase::ForceClosing);
        assert_eq!(shutdown.http2.shutdown_phase(), ShutdownPhase::ForceClosing);
        second_done.store(true, Ordering::Release);
        match drain.as_mut().poll(&mut cx) {
            Poll::Ready((Err(error), Ok(_))) => {
                assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
            }
            _ => panic!("preserve the first error and join the sibling"),
        }
    }

    #[test]
    fn dropping_the_protocol_owner_requests_cleanup_not_quiescence() {
        let shutdown = protocol_shutdown();
        let signal = shutdown.signal.clone();
        let managers = [shutdown.http1.clone(), shutdown.http2.clone()];
        let peer = SocketAddr::from(([127, 0, 0, 1], 1234));
        let connections = managers
            .each_ref()
            .map(|manager| manager.register(peer).expect("admit"));
        drop(shutdown);
        assert_eq!(signal.phase(), ShutdownPhase::ForceClosing);
        for manager in &managers {
            assert_eq!(manager.shutdown_phase(), ShutdownPhase::ForceClosing);
            assert!(manager.register(peer).is_none());
            assert_eq!(
                manager.active_count(),
                1,
                "cleanup has only been requested"
            );
        }
        drop(connections);
        for manager in &managers {
            assert!(manager.is_empty());
        }
        assert!(
            !signal.is_stopped(),
            "only an awaited run may publish completion"
        );
    }

    struct ActiveRequest(Arc<AtomicUsize>);

    impl Drop for ActiveRequest {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::AcqRel);
        }
    }

    #[allow(clippy::too_many_lines)] // Keep the native failure/rescue lifecycle together.
    fn native_force_close(http2: bool, immediate: bool) {
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("runtime");
        let handle = runtime.handle();
        runtime.block_on(handle.clone().spawn(async move {
            let entered = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let active = Arc::new(AtomicUsize::new(0));
            let handler_entered = Arc::clone(&entered);
            let handler_release = Arc::clone(&release);
            let handler_active = Arc::clone(&active);
            let handler = move |_: Request| {
                let entered = Arc::clone(&handler_entered);
                let release = Arc::clone(&handler_release);
                let active = Arc::clone(&handler_active);
                async move {
                    active.fetch_add(1, Ordering::AcqRel);
                    let _active = ActiveRequest(active);
                    let mut finish = pin!(release.notified());
                    let mut announced = false;
                    std::future::poll_fn(|cx| {
                        let result = finish.as_mut().poll(cx);
                        if !announced {
                            announced = true;
                            entered.notify_one();
                        }
                        result
                    })
                    .await;
                    Response::new(200, "OK", Vec::new())
                }
            };
            let config = HttpAutoListenerConfig::default()
                .http1(
                    Http1ListenerConfig::default()
                        .http_config(Http1Config {
                            allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
                            ..Http1Config::default()
                        })
                        .drain_timeout(Duration::from_secs(60))
                        .hard_drain_timeout(Duration::from_secs(60)),
                )
                .http2(
                    Http2ListenerConfig::default()
                        .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
                        .drain_timeout(Duration::from_secs(60))
                        .hard_drain_timeout(Duration::from_secs(60)),
                );
            let listener = HttpAutoListener::bind("127.0.0.1:0", handler, config)
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("address");
            let shutdown = listener.shutdown_signal();
            let run_runtime = handle.clone();
            let mut run = Box::pin(handle.spawn(async move { listener.run(&run_runtime).await }));
            let client = handle.spawn(async move {
                let mut stream = TcpStream::connect(addr).await.expect("connect");
                if http2 {
                    let cx = Cx::current().expect("client context");
                    Http2Client::new()
                        .get(format!("http://localhost:{}/held", addr.port()))
                        .send_on(&cx, stream)
                        .await
                        .is_ok_and(|response| response.status == 200)
                } else {
                    AsyncWriteExt::write_all(
                        &mut stream,
                        b"GET /held HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .expect("request");
                    let mut response = Vec::new();
                    let _ = AsyncReadExt::read_to_end(&mut stream, &mut response).await;
                    response.starts_with(b"HTTP/1.1 200")
                }
            });
            crate::time::timeout(now(), Duration::from_secs(5), entered.notified())
                .await
                .expect("handler must be parked before shutdown");
            assert_eq!(active.load(Ordering::Acquire), 1);
            if immediate {
                shutdown.trigger_immediate();
            } else {
                assert!(shutdown.begin_drain(Duration::from_secs(60)));
                assert!(shutdown.begin_force_close());
            }
            let result = crate::time::timeout(now(), Duration::from_secs(5), run.as_mut()).await;
            let (without_rescue, stats) = match result {
                Ok(stats) => (true, stats),
                Err(_) => {
                    // Release the parked handler on the old/broken path so
                    // the regression fails without leaving a live task behind.
                    release.notify_waiters();
                    let stats = crate::time::timeout(now(), Duration::from_secs(5), run.as_mut())
                        .await
                        .expect("rescue must finish the listener");
                    (false, stats)
                }
            };
            let stats = stats.expect("listener result");
            let succeeded = crate::time::timeout(now(), Duration::from_secs(5), client)
                .await
                .expect("client completion");
            assert_eq!(
                active.load(Ordering::Acquire),
                0,
                "handler resources released"
            );
            assert!(without_rescue, "force-close was not forwarded to the protocol");
            assert!(
                !succeeded,
                "the held handler must not produce its success response"
            );
            assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
            let (served, idle) = if http2 {
                (stats.http2, stats.http1)
            } else {
                (stats.http1, stats.http2)
            };
            assert_eq!(served.force_closed, 1);
            assert_eq!(served.drained, 0);
            assert_eq!(idle.force_closed, 0);
        }));
    }

    #[test]
    fn http1_force_close_releases_a_running_request() {
        for immediate in [false, true] {
            native_force_close(false, immediate);
        }
    }

    #[test]
    fn http2_force_close_releases_a_running_request() {
        for immediate in [false, true] {
            native_force_close(true, immediate);
        }
    }

    #[test]
    fn graceful_run_publishes_stopped() {
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("runtime");
        let handle = runtime.handle();
        runtime.block_on(handle.clone().spawn(async move {
            let listener = HttpAutoListener::bind(
                "127.0.0.1:0",
                |_: Request| async { Response::new(200, "OK", Vec::new()) },
                HttpAutoListenerConfig::default(),
            )
            .await
            .expect("bind");
            let shutdown = listener.shutdown_signal();
            assert!(shutdown.begin_drain(Duration::from_secs(60)));
            let stats = listener.run(&handle).await.expect("drain");
            assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
            assert_eq!(stats.http1.force_closed + stats.http2.force_closed, 0);
        }));
    }

    fn localhost_config() -> HttpAutoListenerConfig {
        HttpAutoListenerConfig::default()
            .http1(
                Http1ListenerConfig::default()
                    .http_config(Http1Config {
                        allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
                        ..Http1Config::default()
                    })
                    .drain_timeout(Duration::from_secs(60))
                    .hard_drain_timeout(Duration::from_secs(60)),
            )
            .http2(
                Http2ListenerConfig::default()
                    .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
                    .drain_timeout(Duration::from_secs(60))
                    .hard_drain_timeout(Duration::from_secs(60)),
            )
    }

    async fn get(addr: SocketAddr) -> Vec<u8> {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        AsyncWriteExt::write_all(
            &mut stream,
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("request");
        let mut response = Vec::new();
        let _ = AsyncReadExt::read_to_end(&mut stream, &mut response).await;
        response
    }

    /// r14 F2 M2 (r11 F4.4): once the task running `run` was cancelled (its
    /// region closing, a runtime drain), accept failed with `Interrupted` on
    /// every poll, that counted as transient, and the backoff sleep completed
    /// at once. The loop spun, nothing drained and `Stopped` never came. The
    /// cancellation now ends accepting like the shutdown signal.
    #[test]
    fn a_cancelled_run_task_stops_accepting_and_publishes_stopped() {
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("runtime");
        let handle = runtime.handle();
        runtime.block_on(handle.clone().spawn(async move {
            let cx = Cx::current().expect("runtime Cx");
            let listener = HttpAutoListener::bind(
                "127.0.0.1:0",
                |_: Request| async { Response::new(200, "OK", Vec::new()) },
                localhost_config(),
            )
            .await
            .expect("bind");
            let addr = listener.local_addr().expect("address");
            let shutdown = listener.shutdown_signal();
            let run_runtime = handle.clone();
            let mut run = cx
                .spawn(move |_| async move { listener.run(&run_runtime).await })
                .expect("spawn the run task");
            // A served request shows the accept loop is running.
            let response = get(addr).await;
            assert!(
                response.starts_with(b"HTTP/1.1 200"),
                "{}",
                String::from_utf8_lossy(&response)
            );

            run.abort();
            let joined = crate::time::timeout(now(), Duration::from_secs(10), run.join(&cx)).await;
            if joined.is_err() {
                // Stop a spinning loop through the signal, so this failure
                // leaves no live task behind.
                shutdown.trigger_immediate();
            }
            assert!(joined.is_ok(), "the cancelled run task never finished");
            assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
        }));
    }

    /// r14 F2 M1 (r11 F2): the listening socket stayed bound until the whole
    /// drain was over (60 s by default), so a client connecting meanwhile
    /// queued in the backlog and was reset at the end. The socket now closes
    /// when accepting ends, as the HTTP/1.1 and HTTP/2 listeners' do, while
    /// the request in flight still completes. As with them,
    /// `lb_compat_keep_socket` keeps it bound through the drain.
    #[test]
    fn new_connections_are_refused_once_the_drain_starts() {
        assert!(
            drain_refuses_new_connections(false),
            "a connection made during the drain was not refused"
        );
        assert!(
            !drain_refuses_new_connections(true),
            "lb_compat_keep_socket must keep the socket connectable through the drain"
        );
    }

    /// Whether a connection attempted while a parked request holds the drain
    /// open is refused, with `lb_compat_keep_socket` set as `keep_socket` in
    /// the HTTP/1.1 config only.
    fn drain_refuses_new_connections(keep_socket: bool) -> bool {
        let mut config = localhost_config();
        config.http1 = config.http1.lb_compat_keep_socket(keep_socket);
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("runtime");
        let handle = runtime.handle();
        runtime.block_on(handle.clone().spawn(async move {
            let entered = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let handler_entered = Arc::clone(&entered);
            let handler_release = Arc::clone(&release);
            let handler = move |_: Request| {
                let entered = Arc::clone(&handler_entered);
                let release = Arc::clone(&handler_release);
                async move {
                    entered.notify_one();
                    release.notified().await;
                    Response::new(200, "OK", Vec::new())
                }
            };
            let listener = HttpAutoListener::bind("127.0.0.1:0", handler, config)
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("address");
            let shutdown = listener.shutdown_signal();
            let run_runtime = handle.clone();
            let run = handle.spawn(async move { listener.run(&run_runtime).await });
            let in_flight = handle.spawn(get(addr));
            crate::time::timeout(now(), Duration::from_secs(5), entered.notified())
                .await
                .expect("the first request reaches its handler");

            // The parked handler holds the drain open.
            assert!(shutdown.begin_drain(Duration::from_secs(60)));
            let mut refused = false;
            for _ in 0..100 {
                match TcpStream::connect(addr).await {
                    Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                        refused = true;
                        break;
                    }
                    _ => crate::time::sleep(now(), Duration::from_millis(20)).await,
                }
            }
            release.notify_one();
            let response = crate::time::timeout(now(), Duration::from_secs(10), in_flight)
                .await
                .expect("the request in flight completes");
            let stats = crate::time::timeout(now(), Duration::from_secs(10), run)
                .await
                .expect("the drain completes")
                .expect("listener result");
            assert!(
                response.starts_with(b"HTTP/1.1 200"),
                "{}",
                String::from_utf8_lossy(&response)
            );
            assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
            assert_eq!(stats.http1.force_closed + stats.http2.force_closed, 0);
            refused
        }))
    }
}
