//! Bounded multi-client control of a region-owned dynamic supervisor.
//!
//! A real controller task owns the existing [`super::DynamicSupervisor`]. Clients can
//! admit workers and await different children concurrently. A pending child
//! drain never holds a client mutex or prevents another child from being polled.
//! Region admission itself is serialized through the existing mint protocol.
//!
//! Request credit covers queued requests, pending waits and unclaimed start
//! receipts, not merely the mailbox. Exact-ID stop requests bypass that credit
//! so a mailbox filled by joins cannot prevent the stops those joins need.
//! Finished children occupy capacity until their result is taken; a dropped
//! waiter never consumes it. An abandoned start is stopped and drained before
//! its capacity is reused. Cleanup failures stay quarantined in the owner.
//!
//! The service handle, not its cloneable clients, owns shutdown. Drop requests
//! cancellation; only `join`/`shutdown` and the enclosing region establish the
//! eventual terminal result. A start receipt does not assert worker readiness.

use super::{
    CancelWakerToken, Cx, DynamicChildCompletion, DynamicChildId, DynamicChildState,
    DynamicSupervisorConfig, DynamicSupervisorError,
    DynamicSupervisorReport, DynamicWorkerConfig,
};
use crate::runtime::{JoinError, SpawnError, TaskHandle};
use crate::supervision::{ChildName, ManagedChildFactory, ManagedSupervisor};
use crate::types::{CancelReason, RegionId, TaskId};
use parking_lot::Mutex;
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

/// Explicit child, request and region limits for a control service.
#[derive(Debug, Clone)]
pub struct DynamicServiceConfig {
    /// Existing owner admission envelope; completed results also reserve names.
    pub supervisor: DynamicSupervisorConfig,
    /// All outstanding requests across every client; must be nonzero.
    /// This is a fail-fast bound, not an unbounded queue of permit waiters.
    pub max_requests: usize,
}

impl DynamicServiceConfig {
    /// Inherit region authority and require explicit child/request ceilings.
    #[must_use]
    pub const fn new(max_children: usize, max_requests: usize) -> Self {
        Self { supervisor: DynamicSupervisorConfig::new(max_children), max_requests }
    }
}

/// Latest observed control state, never application readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicServiceChildState {
    /// State of a still-owned managed controller/boundary.
    Live(DynamicChildState),
    /// Quiescent result retained until a successful wait takes it.
    Completed,
    /// Cleanup failed; capacity is not reusable before owner shutdown.
    Quarantined,
}

/// Non-consuming service snapshot for one admitted identity.
#[derive(Debug, Clone)]
pub struct DynamicServiceChildInfo {
    /// Exact owner, boundary and admission generation.
    pub id: DynamicChildId,
    /// Latest observation by the controller; snapshots can become stale.
    pub state: DynamicServiceChildState,
}

/// Control-plane refusal, distinct from a child's typed application outcome.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DynamicControlError {
    /// A zero request ceiling is rejected before task submission.
    #[error("dynamic service requires nonzero request capacity")]
    Configuration,
    /// No command was enqueued; retrying is a new admission attempt.
    #[error("dynamic service request capacity exhausted")]
    Busy,
    /// The control plane is sealed; this is not a quiescence receipt.
    #[error("dynamic service control plane is closed")]
    Closed,
    /// The caller stopped waiting. Accepted stop requests are not undone.
    #[error("dynamic service caller cancelled: {0:?}")]
    Cancelled(CancelReason),
    /// The identity was unknown, stale, or its completion was already taken.
    #[error("unknown, stale or already reaped dynamic child")]
    StaleChild,
    /// The authoritative dynamic owner refused admission, joining or cleanup.
    #[error("dynamic supervisor operation failed: {0}")]
    Child(#[source] Arc<DynamicSupervisorError>),
    /// Real controller-task submission failed.
    #[error("dynamic service task submission failed: {0:?}")]
    Spawn(SpawnError),
}

/// Actual controller terminal and its separately retained owner report.
#[derive(Debug)]
#[must_use = "inspect both task_outcome and report before claiming shutdown"]
pub struct DynamicServiceExit<E> {
    /// Native/lab task terminal, including cancellation and panics.
    pub task_outcome: Result<(), JoinError>,
    /// None if the controller never ran or panicked before report publication.
    /// An error here is the actual root-admission refusal.
    pub report: Option<Result<DynamicSupervisorReport<E>, Arc<DynamicSupervisorError>>>,
}

// Wakers are callbacks. Never invoke or retire them under a state lock, and
// contain a broken callback so it cannot suppress other shutdown notifications.
// A waker that panics is outside the returning-callback progress assumption.
fn callback(action: impl FnOnce()) {
    if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
        // Even the panic payload's destructor may panic.
        std::mem::forget(payload);
    }
}

#[derive(Default)]
struct Signal {
    waker: Mutex<Option<Waker>>,
    stopping: AtomicBool,
    closed: AtomicBool,
}

impl Signal {
    fn register(&self, waker: &Waker) {
        let replacement = waker.clone();
        let old = self.waker.lock().replace(replacement);
        callback(|| drop(old));
    }
    fn notify(&self) {
        let wake = self.waker.lock().take();
        callback(|| { if let Some(waker) = wake { waker.wake(); } });
    }
    fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        self.notify();
    }
}

struct Credits {
    active: AtomicUsize,
    limit: usize,
}

struct Credit(Arc<Credits>);
impl Credit {
    fn acquire(credits: &Arc<Credits>) -> Result<Self, DynamicControlError> {
        let mut active = credits.active.load(Ordering::Relaxed);
        loop {
            if active >= credits.limit { return Err(DynamicControlError::Busy); }
            match credits.active.compare_exchange_weak(
                active, active + 1, Ordering::AcqRel, Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(Self(Arc::clone(credits))),
                Err(current) => active = current,
            }
        }
    }
}
impl Drop for Credit {
    fn drop(&mut self) {
        let previous = self.0.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
    }
}

struct Completion<E> {
    value: Mutex<Option<DynamicChildCompletion<E>>>,
    signal: Arc<Signal>,
}
impl<E> Completion<E> {
    fn take(&self) -> Option<DynamicChildCompletion<E>> {
        let value = self.value.lock().take();
        if value.is_some() { self.signal.notify(); }
        value
    }
    fn consumed(&self) -> bool { self.value.lock().is_none() }
}

enum Response<E> {
    Ready(RegionId),
    Started(DynamicChildId),
    Completed(Arc<Completion<E>>),
}

struct Reply<E> {
    value: Option<Result<Response<E>, DynamicControlError>>,
    waker: Option<Waker>,
    abandoned: bool,
    received: bool,
}

struct Request<E> {
    reply: Mutex<Reply<E>>,
    signal: Arc<Signal>,
    _credit: Credit,
}
impl<E> Request<E> {
    fn disposition(&self) -> (bool, bool) {
        let reply = self.reply.lock();
        (reply.abandoned, reply.received)
    }
    fn finish(&self, value: Result<Response<E>, DynamicControlError>) {
        let mut value = Some(value);
        let wake = {
            let mut reply = self.reply.lock();
            if reply.abandoned || reply.received || reply.value.is_some() {
                None
            } else {
                reply.value = value.take();
                reply.waker.take()
            }
        };
        drop(value);
        callback(|| { if let Some(waker) = wake { waker.wake(); } });
    }
}

struct RequestWait<'a, E> {
    request: Arc<Request<E>>,
    cx: &'a Cx,
    cancel_waker: Option<CancelWakerToken>,
    finished: bool,
}
impl<E> Future for RequestWait<'_, E> {
    type Output = Result<Response<E>, DynamicControlError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.cancel_waker = Some(this.cx.refresh_cancel_waker(this.cancel_waker, cx.waker()));
        if this.cx.checkpoint().is_err() {
            return Poll::Ready(Err(cancelled(this.cx)));
        }
        let replacement = cx.waker().clone();
        let (value, old) = {
            let mut reply = this.request.reply.lock();
            let value = reply.value.take();
            if value.is_some() { reply.received = true; }
            let old = if value.is_none() {
                reply.waker.replace(replacement)
            } else {
                // Retire the unused clone after releasing the reply lock.
                Some(replacement)
            };
            (value, old)
        };
        callback(|| drop(old));
        if let Some(value) = value {
            this.finished = true;
            // Retiring the service's delivery credit need not await another command.
            this.request.signal.notify();
            return Poll::Ready(value);
        }
        if this.request.signal.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(DynamicControlError::Closed));
        }
        Poll::Pending
    }
}
impl<E> Drop for RequestWait<'_, E> {
    fn drop(&mut self) {
        if let Some(token) = self.cancel_waker.take() { self.cx.clear_cancel_waker(token); }
        let old = {
            let mut reply = self.request.reply.lock();
            if !self.finished { reply.abandoned = true; }
            reply.waker.take()
        };
        callback(|| drop(old));
        self.request.signal.notify();
    }
}

fn cancelled(cx: &Cx) -> DynamicControlError {
    DynamicControlError::Cancelled(
        cx.cancel_reason().unwrap_or_else(|| CancelReason::user("dynamic service caller cancelled")),
    )
}

enum Work<E> {
    Tree(ManagedSupervisor<E>),
    Worker(DynamicWorkerConfig, Box<dyn ManagedChildFactory<E>>),
}
enum Operation<E> {
    Ready,
    Start(ChildName, Work<E>),
    Wait(DynamicChildId),
}
struct Route {
    info: DynamicServiceChildInfo,
    stop: Arc<AtomicBool>,
}
struct Mailbox<E> {
    queue: VecDeque<(Operation<E>, Arc<Request<E>>)>,
    routes: BTreeMap<ChildName, Route>,
    // Weak references avoid Shared -> request -> Shared ownership cycles.
    // Pruned at each enqueue, so this registry is bounded by request credit.
    requests: Vec<Weak<Request<E>>>,
}
struct Shared<E> {
    mailbox: Mutex<Mailbox<E>>,
    credits: Arc<Credits>,
    signal: Arc<Signal>,
}
impl<E> Shared<E> {
    fn close(&self) {
        self.signal.closed.store(true, Ordering::Release);
        let (queued, requests) = {
            let mut mailbox = self.mailbox.lock();
            let requests: Vec<_> = mailbox.requests.iter().filter_map(Weak::upgrade).collect();
            (std::mem::take(&mut mailbox.queue), requests)
        };
        // Also wake requests already removed from the queue (including a panic
        // during a wait or admission), not only those still in the mailbox.
        for request in requests { request.finish(Err(DynamicControlError::Closed)); }
        drop(queued);
        self.signal.notify();
    }
}

/// Cloneable bounded control capability. It neither owns nor detaches the service.
/// Possession delegates the service owner's worker-admission authority. A method's
/// caller Cx controls that request's cancellation, not the service's capabilities.
pub struct DynamicSupervisorClient<E> {
    shared: Arc<Shared<E>>,
}
impl<E> Clone for DynamicSupervisorClient<E> {
    fn clone(&self) -> Self { Self { shared: Arc::clone(&self.shared) } }
}
impl<E> fmt::Debug for DynamicSupervisorClient<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicSupervisorClient")
            .field("outstanding_requests", &self.outstanding_requests())
            .field("max_requests", &self.shared.credits.limit)
            .field("closed", &self.is_closed()).finish_non_exhaustive()
    }
}
impl<E> DynamicSupervisorClient<E> {
    /// Includes queued, waiting and unclaimed-receipt requests across all clones.
    #[must_use]
    pub fn outstanding_requests(&self) -> usize {
        self.shared.credits.active.load(Ordering::Acquire)
    }
    /// Control-plane closure, not proof of worker or region quiescence.
    #[must_use]
    pub fn is_closed(&self) -> bool { self.shared.signal.closed.load(Ordering::Acquire) }
    /// Latest admitted-child snapshots in lexical name order; does not reap results.
    /// An admission currently awaiting its region mint is not yet listed.
    #[must_use]
    pub fn children(&self) -> Vec<DynamicServiceChildInfo> {
        self.shared.mailbox.lock().routes.values().map(|route| route.info.clone()).collect()
    }
    /// Non-queued, idempotent stop for this exact identity. No request credit needed.
    /// The service must still run to observe the flag and complete the drain.
    pub fn request_stop(&self, id: &DynamicChildId) -> Result<(), DynamicControlError> {
        if self.is_closed() { return Err(DynamicControlError::Closed); }
        let stop = {
            let mailbox = self.shared.mailbox.lock();
            let route = mailbox.routes.get(id.name()).filter(|route| &route.info.id == id)
                .ok_or(DynamicControlError::StaleChild)?;
            Arc::clone(&route.stop)
        };
        stop.store(true, Ordering::Release);
        self.shared.signal.notify();
        Ok(())
    }

    fn submit<'a>(&self, cx: &'a Cx, operation: Operation<E>) -> Result<RequestWait<'a, E>, DynamicControlError> {
        if cx.checkpoint().is_err() { return Err(cancelled(cx)); }
        if self.is_closed() { return Err(DynamicControlError::Closed); }
        let credit = Credit::acquire(&self.shared.credits)?;
        let request = Arc::new(Request {
            reply: Mutex::new(Reply { value: None, waker: None, abandoned: false, received: false }),
            signal: Arc::clone(&self.shared.signal), _credit: credit,
        });
        // Build the abandonment guard before publication, including unwind paths.
        let wait = RequestWait { request: Arc::clone(&request), cx, cancel_waker: None, finished: false };
        {
            let mut mailbox = self.shared.mailbox.lock();
            if self.is_closed() { return Err(DynamicControlError::Closed); }
            mailbox.requests.retain(|request| request.strong_count() != 0);
            mailbox.requests.push(Arc::downgrade(&request));
            mailbox.queue.push_back((operation, request));
        }
        self.shared.signal.notify();
        Ok(wait)
    }
}
impl<E: Send + 'static> DynamicSupervisorClient<E> {
    /// Await actual dynamic-root admission, not merely controller submission.
    pub async fn ready(&self, cx: &Cx) -> Result<RegionId, DynamicControlError> {
        match self.submit(cx, Operation::Ready)?.await? {
            Response::Ready(region) => Ok(region),
            _ => unreachable!("request and response kinds are paired internally"),
        }
    }
    /// Submit a managed tree. Abandonment before receipt acceptance cancels/drains it.
    pub async fn start_child(
        &self, cx: &Cx, name: impl Into<ChildName>, supervisor: ManagedSupervisor<E>,
    ) -> Result<DynamicChildId, DynamicControlError> {
        self.start(cx, name.into(), Work::Tree(supervisor)).await
    }
    /// Submit a retained worker factory using the existing managed restart engine.
    pub async fn start_worker(
        &self, cx: &Cx, name: impl Into<ChildName>, config: DynamicWorkerConfig,
        factory: impl ManagedChildFactory<E>,
    ) -> Result<DynamicChildId, DynamicControlError> {
        self.start(cx, name.into(), Work::Worker(config, Box::new(factory))).await
    }
    async fn start(&self, cx: &Cx, name: ChildName, work: Work<E>) -> Result<DynamicChildId, DynamicControlError> {
        match self.submit(cx, Operation::Start(name, work))?.await? {
            Response::Started(id) => Ok(id),
            _ => unreachable!("request and response kinds are paired internally"),
        }
    }
    /// Take one quiescent completion. A dropped wait leaves the result in the service.
    /// Concurrent waits compete for one result; later takers receive StaleChild.
    pub async fn wait_child(&self, cx: &Cx, id: &DynamicChildId) -> Result<DynamicChildCompletion<E>, DynamicControlError> {
        match self.submit(cx, Operation::Wait(id.clone()))?.await? {
            Response::Completed(completion) => completion.take().ok_or(DynamicControlError::StaleChild),
            _ => unreachable!("request and response kinds are paired internally"),
        }
    }
    /// Stop first, then await quiescence. Busy/Cancelled while waiting never undoes stop.
    /// `wait_child` can be retried with the same identity to take the retained result.
    pub async fn terminate_child(&self, cx: &Cx, id: &DynamicChildId) -> Result<DynamicChildCompletion<E>, DynamicControlError> {
        self.request_stop(id)?;
        self.wait_child(cx, id).await
    }
}

type ReportSlot<E> = Arc<Mutex<Option<Result<DynamicSupervisorReport<E>, Arc<DynamicSupervisorError>>>>>;

/// Sole owner of the actual controller task; clients alone cannot keep it detached.
pub struct DynamicServiceHandle<E> {
    task: TaskHandle<()>,
    client: DynamicSupervisorClient<E>,
    report: ReportSlot<E>,
}
impl<E> fmt::Debug for DynamicServiceHandle<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicServiceHandle").field("task", &self.task.task_id())
            .field("client", &self.client).finish_non_exhaustive()
    }
}
impl<E> DynamicServiceHandle<E> {
    /// Clone a control capability without transferring service lifetime ownership.
    #[must_use]
    pub fn client(&self) -> DynamicSupervisorClient<E> { self.client.clone() }
    /// Actual submitted controller identity.
    #[must_use]
    pub fn task_id(&self) -> TaskId { self.task.task_id() }
    /// Out-of-band graceful shutdown; cannot be refused by a full request mailbox.
    pub fn request_shutdown(&self) {
        self.client.shared.signal.stop();
        self.client.shared.close();
        // Task abort is the runtime's cooperative cancellation protocol. It
        // also fences a region admission currently awaiting its mint result.
        self.task.abort();
    }
    /// Await the actual task terminal and preserve any report published before it.
    pub async fn join(mut self) -> DynamicServiceExit<E> {
        let task_outcome = poll_fn(|cx| self.task.poll_join(cx)).await;
        let report = self.report.lock().take();
        DynamicServiceExit { task_outcome, report }
    }
    /// Request every worker stop, then await real owner shutdown.
    pub async fn shutdown(self) -> DynamicServiceExit<E> {
        self.request_shutdown();
        self.join().await
    }
}
impl<E> Drop for DynamicServiceHandle<E> {
    fn drop(&mut self) {
        self.request_shutdown();
    }
}

// Created before task submission, so cancellation before the FIRST poll also
// closes every client and releases queued factories outside the mailbox lock.
struct Lifetime<E>(Arc<Shared<E>>);
impl<E> Drop for Lifetime<E> {
    fn drop(&mut self) { self.0.close(); }
}
struct CancelRegistration<'a> { cx: &'a Cx, token: Option<CancelWakerToken> }
impl Drop for CancelRegistration<'_> {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() { self.cx.clear_cancel_waker(token); }
    }
}

impl Cx {
    /// Submit a region-owned dynamic control task. `client.ready` observes root admission.
    /// No global executor, detached task, ambient authority or new runtime is used.
    pub fn spawn_dynamic_supervisor_service<E: Send + 'static>(
        &self, config: DynamicServiceConfig,
    ) -> Result<DynamicServiceHandle<E>, DynamicControlError> {
        if config.max_requests == 0 { return Err(DynamicControlError::Configuration); }
        if self.checkpoint().is_err() { return Err(cancelled(self)); }
        let shared = Arc::new(Shared {
            mailbox: Mutex::new(Mailbox { queue: VecDeque::new(), routes: BTreeMap::new(), requests: Vec::new() }),
            credits: Arc::new(Credits { active: AtomicUsize::new(0), limit: config.max_requests }),
            signal: Arc::new(Signal::default()),
        });
        let lifetime = Lifetime(Arc::clone(&shared));
        let report = Arc::new(Mutex::new(None));
        let publication = Arc::clone(&report);
        let task = self.spawn(move |cx| async move {
            let _lifetime = lifetime;
            let result = serve(&cx, config, &_lifetime.0).await;
            _lifetime.0.close();
            *publication.lock() = Some(result);
        }).map_err(DynamicControlError::Spawn)?;
        Ok(DynamicServiceHandle { task, client: DynamicSupervisorClient { shared }, report })
    }
}

struct Record<E> {
    id: DynamicChildId,
    stop: Arc<AtomicBool>,
    completion: Option<Arc<Completion<E>>>,
    failure: Option<Arc<DynamicSupervisorError>>,
    forgotten_start: bool,
    stop_sent: bool,
}
struct Delivery<E> { id: DynamicChildId, request: Arc<Request<E>> }

async fn serve<E: Send + 'static>(
    cx: &Cx, config: DynamicServiceConfig, shared: &Arc<Shared<E>>,
) -> Result<DynamicSupervisorReport<E>, Arc<DynamicSupervisorError>> {
    if shared.signal.stopping.load(Ordering::Acquire) {
        return Err(Arc::new(DynamicSupervisorError::Closing));
    }
    let mut owner = cx.open_dynamic_supervisor::<E>(config.supervisor).await.map_err(Arc::new)?;
    let mut cancel = CancelRegistration { cx, token: None };
    let mut records: BTreeMap<ChildName, Record<E>> = BTreeMap::new();
    let mut deliveries: Vec<Delivery<E>> = Vec::new();
    let mut waits: Vec<(DynamicChildId, Arc<Request<E>>)> = Vec::new();
    let mut commands = 0;
    loop {
        let next = poll_fn(|poll_cx| {
            // Register BEFORE observing queues/flags to close the wake-versus-park race.
            shared.signal.register(poll_cx.waker());
            cancel.token = Some(cx.refresh_cancel_waker(cancel.token, poll_cx.waker()));
            if shared.signal.stopping.load(Ordering::Acquire) || cx.checkpoint().is_err() {
                return Poll::Ready(None);
            }
            deliveries.retain(|delivery| {
                let (abandoned, received) = delivery.request.disposition();
                if received { return false; }
                let Some(record) = records.get_mut(delivery.id.name()) else { return false; };
                if abandoned {
                    record.forgotten_start = true;
                    record.stop.store(true, Ordering::Release);
                    return record.completion.is_none() && record.failure.is_none();
                }
                true
            });
            for record in records.values_mut() {
                if record.completion.is_some() || record.failure.is_some() { continue; }
                if !record.stop_sent && record.stop.load(Ordering::Acquire) {
                    // Exact IDs were published by this owner and never reassigned.
                    if let Err(error) = owner.request_stop(&record.id) {
                        record.failure = Some(Arc::new(error));
                        continue;
                    }
                    record.stop_sent = true;
                }
                let result = {
                    let mut wait = std::pin::pin!(owner.wait_child(&record.id));
                    wait.as_mut().poll(poll_cx)
                };
                match result {
                    Poll::Pending => {}
                    Poll::Ready(Ok(value)) => record.completion = Some(Arc::new(Completion {
                        value: Mutex::new(Some(value)), signal: Arc::clone(&shared.signal),
                    })),
                    Poll::Ready(Err(error)) => record.failure = Some(Arc::new(error)),
                }
            }
            records.retain(|name, record| {
                let reaped = record.completion.as_ref().is_some_and(|value| {
                    record.forgotten_start || value.consumed()
                });
                if reaped { shared.mailbox.lock().routes.remove(name); }
                !reaped
            });
            // Completion above can retire an abandoned admission in this very
            // poll. Release its request credit now, without requiring a future
            // unrelated command or wake to make capacity available again.
            deliveries.retain(|delivery| {
                records.get(delivery.id.name()).is_some_and(|record| {
                    !delivery.request.disposition().0 || record.failure.is_none()
                })
            });
            waits.retain(|(id, request)| {
                if request.disposition().0 { return false; }
                let result = match records.get(id.name()).filter(|record| &record.id == id) {
                    None => Some(Err(DynamicControlError::StaleChild)),
                    Some(record) => {
                        if let Some(error) = &record.failure {
                            Some(Err(DynamicControlError::Child(Arc::clone(error))))
                        } else {
                            record.completion.as_ref().map(|value| Ok(Response::Completed(Arc::clone(value))))
                        }
                    }
                };
                if let Some(result) = result { request.finish(result); false } else { true }
            });
            let observed: BTreeMap<_, _> = owner.children().into_iter().map(|info| (info.id.name().to_owned(), info.state)).collect();
            {
                let mut mailbox = shared.mailbox.lock();
                for (name, record) in &records {
                    if let Some(route) = mailbox.routes.get_mut(name) {
                        route.info.state = if record.failure.is_some() {
                            DynamicServiceChildState::Quarantined
                        } else if record.completion.is_some() {
                            DynamicServiceChildState::Completed
                        } else {
                            DynamicServiceChildState::Live(*observed.get(name.as_str()).unwrap_or(&DynamicChildState::Submitted))
                        };
                    }
                }
                if let Some(command) = mailbox.queue.pop_front() { return Poll::Ready(Some(command)); }
            }
            Poll::Pending
        }).await;
        let Some((operation, request)) = next else { break; };
        if !request.disposition().0 {
            match operation {
                Operation::Ready => request.finish(Ok(Response::Ready(owner.region_id()))),
                Operation::Wait(id) => {
                    waits.push((id, request));
                    // The next iteration inspects the retained result before parking.
                }
                Operation::Start(name, work) => {
                    let result = if records.contains_key(name.as_str()) {
                        Err(DynamicSupervisorError::DuplicateName)
                    } else if records.len() >= owner.capacity() {
                        Err(DynamicSupervisorError::Capacity)
                    } else {
                        match work {
                            Work::Tree(supervisor) => owner.start_child(name.clone(), supervisor).await,
                            Work::Worker(config, factory) => owner.start_worker(name.clone(), config,
                                move |cx, generation| factory.start(cx, generation)).await,
                        }
                    };
                    match result {
                        Err(error) => request.finish(Err(DynamicControlError::Child(Arc::new(error)))),
                        Ok(id) => {
                            let stop = Arc::new(AtomicBool::new(false));
                            shared.mailbox.lock().routes.insert(name.clone(), Route {
                                info: DynamicServiceChildInfo { id: id.clone(), state: DynamicServiceChildState::Live(DynamicChildState::Submitted) },
                                stop: Arc::clone(&stop),
                            });
                            records.insert(name, Record { id: id.clone(), stop, completion: None, failure: None, forgotten_start: false, stop_sent: false });
                            request.finish(Ok(Response::Started(id.clone())));
                            deliveries.push(Delivery { id, request });
                        }
                    }
                }
            }
        }
        commands += 1;
        if commands == 32 {
            commands = 0;
            crate::runtime::yield_now().await;
        }
    }
    shared.close();
    for (_, request) in waits { request.finish(Err(DynamicControlError::Closed)); }
    // Existing owner shutdown starts every stop before polling all boundary closes.
    let mut report = owner.shutdown().await;
    for record in records.into_values() {
        if let Some(completion) = record.completion {
            if let Some(value) = completion.take() { report.children.push(value); }
        }
    }
    report.children.sort_by(|a, b| a.id.name().cmp(b.id.name()));
    shared.mailbox.lock().routes.clear();
    Ok(report)
}

#[cfg(test)]
mod tests;
