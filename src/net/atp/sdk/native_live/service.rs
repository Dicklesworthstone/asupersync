//! Reusable live receiver with bounded, scope-owned connection workers.
//!
//! The service reserves its entire connection budget before binding. Each
//! accepted socket becomes a child of the scope passed to `next`; TLS, sink
//! creation and the existing epoch protocol execute in that child. Failed
//! clients are completions, not listener failures. A completed but uncollected
//! worker still occupies one service slot, bounding retained reports as well
//! as active handshakes. The kernel listen backlog is separate.
//!
//! Drive `next` to accept and collect results. `control().stop()` requests
//! graceful shutdown; `cancel(reason)` escalates it to cooperative cancellation.
//! Requests take effect when the service is next polled. Already accepted
//! connections can finish after a stop request. `drain_next` stops admission
//! and joins without consulting a cancelled Cx; call it until it returns None.
//! Dropping any pending wait retains the listener, jobs and terminal evidence.
//! Dropping the service closes admission and requests cancellation, but its
//! owning regions still must drain the children. User polls/destructors that
//! never return cannot be preempted. No wire-format or sink-durability change.

use super::{
    Cancellation, LiveStreamError, LiveStreamReceiver, LiveStreamReport, Permit,
    Progress, authorize, bounded, check_alpn, checkpoint,
};
use super::super::NativeClientCertificateId;
use super::commit::{FlushOnly, LiveStreamCommitSink};
use crate::cx::{Cx, Scope};
use crate::io::AsyncWrite;
use crate::net::{TcpListener, TcpStream};
use crate::runtime::{JoinError, TaskHandle};
use crate::types::{CancelReason, Policy};
use parking_lot::Mutex;
use rustls::pki_types::CertificateDer;
use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

/// Identity from the completed mandatory-mTLS connection, not an ATP label.
/// The address is diagnostic routing data, never an authorization selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveStreamPeer {
    /// Complete verified client leaf-certificate fingerprint.
    pub certificate: NativeClientCertificateId,
    /// Address of the actual accepted TCP connection.
    pub address: SocketAddr,
}

/// Domain result from one worker. A failed handshake has no authenticated peer.
#[derive(Debug)]
pub struct LiveStreamSessionReport {
    /// Present only after TLS authentication and live-profile ALPN verification.
    pub peer: Option<LiveStreamPeer>,
    /// Original transfer, factory, or TLS result, with independent partial progress.
    pub transfer: LiveStreamReport,
}

/// One actual child join, emitted once. Connection IDs never repeat per service.
#[derive(Debug)]
#[must_use = "inspect the child join and transfer result separately"]
pub struct LiveStreamCompletion {
    /// Monotonically assigned local connection number, starting at zero.
    pub connection: u64,
    /// Accepted address, including for a worker rejected before authentication.
    pub address: SocketAddr,
    /// Canonical runtime failure or exact domain report; neither is flattened.
    pub result: Result<LiveStreamSessionReport, JoinError>,
}

#[derive(Debug, Clone, Default)]
enum StopRequest {
    #[default]
    Running,
    Drain,
    Abort(CancelReason),
}

#[derive(Debug, Default)]
struct ControlState {
    request: StopRequest,
    waiter: Option<Waker>,
}

/// Cloneable shutdown request handle. It cannot create a connection or sink.
/// Requests wake an idle service; they do not themselves run the drain loop.
#[derive(Debug, Clone, Default)]
pub struct LiveStreamServiceControl {
    state: Arc<Mutex<ControlState>>,
}

impl LiveStreamServiceControl {
    /// Stop accepting when observed, preserving already accepted work.
    pub fn stop(&self) {
        self.request(StopRequest::Drain);
    }

    /// Stop admission and cancel workers when observed. The first abort reason
    /// wins; a later graceful stop cannot downgrade cancellation to draining.
    pub fn cancel(&self, reason: CancelReason) {
        self.request(StopRequest::Abort(reason));
    }

    /// Whether stop or cancellation has been requested, not proof of quiescence.
    #[must_use]
    pub fn is_stopping(&self) -> bool {
        !matches!(self.state.lock().request, StopRequest::Running)
    }

    fn request(&self, request: StopRequest) {
        let (retired, wake) = {
            let mut state = self.state.lock();
            let upgrade = matches!(state.request, StopRequest::Running)
                || matches!((&state.request, &request), (StopRequest::Drain, StopRequest::Abort(_)));
            let retired = if upgrade {
                Some(std::mem::replace(&mut state.request, request))
            } else {
                Some(request)
            };
            (retired, state.waiter.take())
        };
        drop(retired);
        if let Some(wake) = wake { wake.wake(); }
    }

    fn register(&self, waker: &Waker) {
        // RawWaker clone and destruction are user code: neither runs under lock.
        let candidate = waker.clone();
        let retired = {
            let mut state = self.state.lock();
            if state.waiter.as_ref().is_some_and(|old| old.will_wake(waker)) {
                Some(candidate)
            } else {
                state.waiter.replace(candidate)
            }
        };
        drop(retired);
    }

    fn snapshot(&self) -> StopRequest {
        self.state.lock().request.clone()
    }

    fn clear_waiter(&self) {
        let retired = self.state.lock().waiter.take();
        drop(retired);
    }
}

// All reserved admission units remain owned while the service or any worker
// exists. An abandoned manager cannot release credit underneath a live child.
#[derive(Debug)]
struct Capacity {
    _permits: Vec<Permit>,
}

#[derive(Debug)]
struct Job {
    connection: u64,
    address: SocketAddr,
    task: TaskHandle<LiveStreamSessionReport>,
}

/// One retained listening socket and a bounded set of canonical task handles.
///
/// There is no detached accept loop or unbounded completion channel. The caller
/// must keep driving it; slow completion consumption backpressures acceptance.
#[derive(Debug)]
#[must_use = "drive next, then drain_next until None when stopping"]
pub struct LiveStreamService {
    listener: Option<TcpListener>,
    address: SocketAddr,
    receiver: LiveStreamReceiver,
    capacity: Option<Arc<Capacity>>,
    max_connections: usize,
    jobs: Vec<Job>,
    next_connection: Option<u64>,
    control: LiveStreamServiceControl,
    abort_dispatched: bool,
}

impl LiveStreamReceiver {
    /// Bind a reusable receiver and reserve `max_connections` SDK admission
    /// units before creating the socket. The count must be nonzero and fit the
    /// receiver's configured capacity. A partial reservation rolls back on error.
    ///
    /// The entire reservation remains visible in `active_streams`, even while
    /// idle, until the service closes and all its workers have been joined or
    /// dropped by their owning regions. This deliberate partition avoids one
    /// service holding accepted sockets while waiting for another's credits.
    /// One listen socket plus at most `max_connections` accepted sockets is owned.
    /// OS backlog, TLS buffers and caller-provided sinks have separate limits.
    pub async fn bind_service(
        &self,
        cx: &Cx,
        address: SocketAddr,
        max_connections: usize,
    ) -> Result<LiveStreamService, LiveStreamError> {
        authorize(cx)?;
        if max_connections == 0 || max_connections > self.admission.capacity {
            return Err(LiveStreamError::Configuration("invalid service connection budget"));
        }
        let mut permits = Vec::new();
        let mut jobs = Vec::new();
        permits.try_reserve_exact(max_connections).map_err(|_| allocation_error())?;
        jobs.try_reserve_exact(max_connections).map_err(|_| allocation_error())?;
        for _ in 0..max_connections { permits.push(self.admission.reserve()?); }
        let listener = bounded(
            cx, self.config.operation_timeout, "service bind", TcpListener::bind(address),
        ).await?;
        let address = listener.local_addr()?;
        Ok(LiveStreamService {
            listener: Some(listener), address, receiver: self.clone(),
            capacity: Some(Arc::new(Capacity { _permits: permits })),
            max_connections, jobs, next_connection: Some(0),
            control: LiveStreamServiceControl::default(), abort_dispatched: false,
        })
    }
}

fn allocation_error() -> LiveStreamError {
    io::Error::from(io::ErrorKind::OutOfMemory).into()
}

impl LiveStreamService {
    /// Address assigned to the retained socket; remains available after closure.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr { self.address }

    /// Configured bound on workers, including finished but uncollected workers.
    #[must_use]
    pub const fn max_connections(&self) -> usize { self.max_connections }

    /// Accepted workers still owned by this manager, including ready joins.
    #[must_use]
    pub fn in_flight(&self) -> usize { self.jobs.len() }

    /// A request handle suitable for another task or thread.
    #[must_use]
    pub fn control(&self) -> LiveStreamServiceControl { self.control.clone() }

    /// True only after admission closed and every retained join was collected.
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.listener.is_none() && self.jobs.is_empty() && self.capacity.is_none()
    }

    /// Close the listening socket now, allowing accepted workers to finish.
    pub fn stop_accepting(&mut self) {
        self.control.stop();
        self.apply_stop();
    }

    /// Close admission now and request attributed cancellation for each worker.
    /// Call `drain_next` to observe joins and cleanup; this call does not join.
    pub fn cancel(&mut self, reason: CancelReason) {
        self.control.cancel(reason);
        self.apply_stop();
    }

    /// Accept into `scope` while collecting one real child completion at a time.
    /// No data sink is constructed before mandatory TLS and ALPN verification.
    /// The asynchronous factory gets the actual child Cx and verified client
    /// fingerprint; it may apply narrower per-client policy by returning an I/O
    /// error. Factory creation/cleanup must be drop-cancel-safe, like sink polls.
    /// Its await is bounded by the configured operation timeout.
    ///
    /// Idle listening has no timeout; context cancellation and control requests
    /// wake it. Each poll admits at most one socket, then yields. Client TLS,
    /// factory and transfer failures are ordinary completions and do not close
    /// the listener. Fatal accept/spawn errors stop admission and return Err;
    /// previously accepted workers remain available through `drain_next`.
    ///
    /// Cancelling this Cx requests worker cancellation and returns its domain
    /// error; call `drain_next` even with that Cx cancelled. Dropping a Pending
    /// wait retains all accepted workers and unconsumed reports in the service.
    pub async fn next<P, F, Fut, W>(
        &mut self,
        cx: &Cx,
        scope: &Scope<'_, P>,
        make_sink: F,
    ) -> Result<Option<LiveStreamCompletion>, LiveStreamError>
    where
        P: Policy,
        F: Fn(Cx, LiveStreamPeer) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = io::Result<W>> + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        self.next_inner(cx, scope, move |child, peer| {
            let future = make_sink(child, peer);
            async move { future.await.map(FlushOnly) }
        }, false).await
    }

    /// Accept sinks whose application commit must succeed before final Proof.
    ///
    /// Authentication, quotas and completion collection are identical to next.
    /// The sink factory is still invoked only after mTLS. Once commit begins,
    /// cancellation/timeout drains it before releasing the worker's credit.
    /// Inspect LiveStreamError::Commit to distinguish an unconfirmed transaction
    /// from an acknowledged local commit whose peer Proof could not complete.
    /// Earlier workers keep their own policy if next and next_committing are mixed.
    pub async fn next_committing<P, F, Fut, W>(
        &mut self, cx: &Cx, scope: &Scope<'_, P>, make_sink: F,
    ) -> Result<Option<LiveStreamCompletion>, LiveStreamError>
    where
        P: Policy,
        F: Fn(Cx, LiveStreamPeer) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = io::Result<W>> + Send + 'static,
        W: LiveStreamCommitSink + Unpin + Send + 'static,
    {
        self.next_inner(cx, scope, make_sink, true).await
    }

    async fn next_inner<P, F, Fut, W>(
        &mut self, cx: &Cx, scope: &Scope<'_, P>, make_sink: F, require_commit: bool,
    ) -> Result<Option<LiveStreamCompletion>, LiveStreamError>
    where
        P: Policy,
        F: Fn(Cx, LiveStreamPeer) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = io::Result<W>> + Send + 'static,
        W: LiveStreamCommitSink + Unpin + Send + 'static,
    {
        let mut cancellation = Cancellation { cx, token: None };
        let result = poll_fn(|ctx| {
            self.control.register(ctx.waker());
            cancellation.token = Some(cx.refresh_cancel_waker(cancellation.token.take(), ctx.waker()));
            if let Err(error) = authorize(cx) {
                self.cancel(cx.cancel_reason().unwrap_or_else(|| CancelReason::user("live service authority ended")));
                return Poll::Ready(Err(error));
            }
            self.apply_stop();
            if let Poll::Ready(completion) = self.poll_completion(ctx) {
                return Poll::Ready(Ok(Some(completion)));
            }
            if self.listener.is_none() {
                self.release_if_drained();
                return if self.jobs.is_empty() { Poll::Ready(Ok(None)) } else { Poll::Pending };
            }
            if self.jobs.len() >= self.max_connections { return Poll::Pending; }
            let Some(connection) = self.next_connection else {
                self.stop_accepting();
                return Poll::Ready(Err(LiveStreamError::Configuration("service connection IDs exhausted")));
            };
            let accepted = self.listener.as_ref().expect("open listener").poll_accept(ctx);
            let (tcp, address) = match accepted {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    self.stop_accepting();
                    return Poll::Ready(Err(error.into()));
                }
                Poll::Ready(Ok(pair)) => pair,
            };
            self.apply_stop();
            if self.listener.is_none() {
                drop(tcp);
                ctx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.next_connection = connection.checked_add(1);
            let receiver = self.receiver.clone();
            let capacity = Arc::clone(self.capacity.as_ref().expect("open service reservation"));
            let factory = make_sink.clone();
            let task = cx.spawn_in(scope, move |child| {
                let future: Pin<Box<dyn Future<Output = LiveStreamSessionReport> + Send>> = Box::pin(async move {
                    let _capacity = capacity;
                    serve_connection(&receiver, &child, tcp, address, factory, require_commit).await
                });
                future
            });
            match task {
                Ok(task) => self.jobs.push(Job { connection, address, task }),
                Err(error) => {
                    self.stop_accepting();
                    return Poll::Ready(Err(LiveStreamError::Spawn(error)));
                }
            }
            // Register for the new join on the next turn, even if that child
            // completed before the manager had a chance to poll its handle.
            ctx.waker().wake_by_ref();
            Poll::Pending
        }).await;
        self.control.clear_waiter();
        result
    }

    /// Stop accepting and collect one retained child join, or None after full
    /// drain and admission release. Repeat until None. No cancelled Cx is used
    /// for terminal publication. A Pending wait can be dropped and resumed
    /// without discarding any completion; there is no private accumulator.
    pub async fn drain_next(&mut self) -> Option<LiveStreamCompletion> {
        self.stop_accepting();
        let result = poll_fn(|ctx| {
            self.control.register(ctx.waker());
            self.apply_stop();
            if let Poll::Ready(completion) = self.poll_completion(ctx) {
                return Poll::Ready(Some(completion));
            }
            self.release_if_drained();
            if self.jobs.is_empty() { Poll::Ready(None) } else { Poll::Pending }
        }).await;
        self.control.clear_waiter();
        result
    }

    fn poll_completion(&mut self, ctx: &mut Context<'_>) -> Poll<LiveStreamCompletion> {
        for index in 0..self.jobs.len() {
            if let Poll::Ready(result) = self.jobs[index].task.poll_join(ctx) {
                let job = self.jobs.swap_remove(index);
                self.release_if_drained();
                return Poll::Ready(LiveStreamCompletion { connection: job.connection, address: job.address, result });
            }
        }
        Poll::Pending
    }

    fn apply_stop(&mut self) {
        match self.control.snapshot() {
            StopRequest::Running => {}
            StopRequest::Drain => { drop(self.listener.take()); }
            StopRequest::Abort(reason) => {
                drop(self.listener.take());
                if !self.abort_dispatched {
                    self.abort_dispatched = true;
                    for job in &self.jobs { job.task.abort_with_reason(reason.clone()); }
                }
            }
        }
        self.release_if_drained();
    }

    fn release_if_drained(&mut self) {
        if self.listener.is_none() && self.jobs.is_empty() {
            drop(self.capacity.take());
        }
    }
}

impl Drop for LiveStreamService {
    fn drop(&mut self) {
        self.cancel(CancelReason::user("live stream service dropped"));
        self.control.clear_waiter();
    }
}

async fn serve_connection<F, Fut, W>(
    receiver: &LiveStreamReceiver,
    cx: &Cx,
    tcp: TcpStream,
    address: SocketAddr,
    make_sink: F,
    require_commit: bool,
) -> LiveStreamSessionReport
where
    F: FnOnce(Cx, LiveStreamPeer) -> Fut,
    Fut: Future<Output = io::Result<W>>,
    W: LiveStreamCommitSink + Unpin,
{
    let mut progress = Progress::default();
    let mut peer = None;
    let outcome = async {
        authorize(cx)?;
        let timeout = receiver.config.operation_timeout;
        let tls = bounded(cx, timeout, "TLS handshake", receiver.acceptor.accept(tcp)).await?;
        check_alpn(&tls)?;
        let certificate = tls.peer_leaf_certificate_der()
            .ok_or(LiveStreamError::Protocol("authenticated client certificate missing"))?;
        let authenticated = LiveStreamPeer {
            certificate: NativeClientCertificateId::from_certificate(&CertificateDer::from(certificate)),
            address,
        };
        peer = Some(authenticated);
        checkpoint(cx)?;
        let mut sink = bounded(cx, timeout, "sink creation", make_sink(cx.clone(), authenticated)).await?;
        receiver.receive_authenticated_with_commit(cx, tls, &mut sink, &mut progress, require_commit).await
    }.await;
    LiveStreamSessionReport { peer, transfer: progress.report(outcome) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    #[test]
    fn stop_can_escalate_but_never_downgrade_or_replace_the_first_reason() {
        let control = LiveStreamServiceControl::default();
        assert!(!control.is_stopping());
        control.stop();
        let first = CancelReason::user("first");
        control.cancel(first.clone());
        control.stop();
        control.cancel(CancelReason::user("second"));
        assert!(matches!(control.snapshot(), StopRequest::Abort(reason) if reason == first));
    }

    #[test]
    fn idle_stop_wakes_outside_the_control_lock() {
        struct Probe(LiveStreamServiceControl, AtomicUsize);
        impl Wake for Probe {
            fn wake(self: Arc<Self>) {
                assert!(self.0.is_stopping());
                self.1.fetch_add(1, Ordering::SeqCst);
            }
        }
        let control = LiveStreamServiceControl::default();
        let probe = Arc::new(Probe(control.clone(), AtomicUsize::new(0)));
        control.register(&Waker::from(Arc::clone(&probe)));
        control.stop();
        assert_eq!(probe.1.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn capacity_remains_held_by_a_worker_after_the_manager_owner_drops() {
        let admission = Arc::new(super::super::Admission { active: AtomicUsize::new(0), capacity: 2 });
        let capacity = Arc::new(Capacity { _permits: vec![admission.reserve().unwrap(), admission.reserve().unwrap()] });
        let worker = Arc::clone(&capacity);
        drop(capacity);
        assert!(matches!(admission.reserve(), Err(LiveStreamError::Capacity)));
        drop(worker);
        assert_eq!(admission.active.load(Ordering::Relaxed), 0);
    }
}