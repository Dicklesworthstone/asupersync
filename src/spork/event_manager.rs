//! Region-owned event handlers with bounded, two-phase fan-out.
//!
//! [`EventManager`] owns dynamic supervision; [`EventEmitter`] is a cloneable
//! emission capability. Every handler executes in its own managed task. A
//! notification reserves all selected mailboxes before publishing any event.
//! Dropping or cancelling that reservation phase publishes nothing. A handler
//! retiring during commit is reported explicitly, never as successful delivery.
//!
//! Remove and swap serialize with emission. They queue a FIFO stop marker,
//! drain preceding events, run `terminate`, and join the actual region barrier
//! before replacing a handler. Emitters waiting at that barrier are bounded by
//! the in-flight limit. If an admitted control future is abandoned, emission is
//! sealed; call [`EventManager::shutdown`] to drain the still-owned tasks.
//! Handler callbacks must not await a control operation or synchronous emission
//! whose completion depends on that same handler; such dependency cycles cannot
//! make progress. No callback runs on the routing-lock holder's stack.
//!
//! A processing deadline preserves partial results and a resumable receipt:
//! ```no_run
//! use asupersync::Cx;
//! use asupersync::spork::event_manager::{
//!     EventBackpressure, EventEmitter, EventManagerError, EventReport,
//! };
//! async fn publish(cx: &Cx, events: &EventEmitter<String>)
//!     -> Result<EventReport, EventManagerError>
//! {
//!     events.sync_notify(cx, "created".to_owned(), EventBackpressure::Wait).await
//! }
//! ```
//! `Interrupted` distinguishes unfinished recipients from completed results.
//! Its receipt can be observed again under a live budget. The initial policies
//! are whole-notification wait or refusal; dropping selected recipients and
//! automatic state migration between replacement factories are not provided.

use crate::channel::mpsc;
use crate::cx::{Cx, DynamicChildCompletion, DynamicChildId, DynamicSupervisor,
    DynamicSupervisorConfig, DynamicSupervisorError, DynamicSupervisorReport};
use crate::record::task::TaskOutcome;
use crate::runtime::{RuntimeState, SpawnError};
use crate::runtime::obligation_mailbox::{ObligationAdmissionError, ObligationMailbox};
use crate::supervision::{ChildSpec, ManagedChildBinding, ManagedChildFactory,
    ManagedChildFuture, ManagedGeneration, ManagedRestartMode, ManagedSupervisorBindError,
    SupervisionConfig, SupervisorBuilder};
use crate::sync::{Notify, RwLock, RwLockReadGuard};
use crate::types::{Budget, CancelReason, Outcome, PanicPayload, RegionId};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::marker::PhantomData;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::task::Poll;

/// A borrowed handler callback; no `Sync` bound is imposed on handler state.
pub type EventHandlerFuture<'a, X> = Pin<Box<dyn Future<Output = Outcome<(), X>> + Send + 'a>>;

/// One generation of a stateful event consumer.
pub trait EventHandler<E>: Send + 'static {
    /// Original domain error retained by the managed supervision report.
    type Error: Send + 'static;
    /// Initialize this generation before consuming its mailbox.
    fn init<'a>(&'a mut self, _cx: &'a Cx) -> EventHandlerFuture<'a, Self::Error> {
        Box::pin(async { Outcome::Ok(()) })
    }
    /// Process one event. Failure affects this handler's generation only.
    fn handle_event<'a>(&'a mut self, cx: &'a Cx, event: &'a E)
        -> EventHandlerFuture<'a, Self::Error>;
    /// Drain application cleanup. The manager polls this under a cancellation
    /// mask; it does not force-drop an unfinished callback. A failed terminate
    /// is a cleanup failure and forbids another generation.
    fn terminate<'a>(&'a mut self, _cx: &'a Cx, _reason: EventStopReason)
        -> EventHandlerFuture<'a, Self::Error> {
        Box::pin(async { Outcome::Ok(()) })
    }
}

/// Why a handler generation is terminating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventStopReason {
    /// Its FIFO remove marker was reached.
    Removed,
    /// Its FIFO replacement marker was reached.
    Replaced,
    /// Initialization or event processing failed or panicked.
    Failed,
    /// Owner shutdown or external cancellation interrupted the generation.
    Cancelled,
}

/// Explicit finite bounds on framework-owned work.
#[derive(Debug, Clone)]
pub struct EventManagerConfig {
    /// Maximum live, unreaped or quarantined dynamic handler children.
    pub max_handlers: usize,
    /// Pending messages per handler, including a graceful stop marker.
    pub mailbox_capacity: usize,
    /// Accepted emission waits plus events not yet settled by all recipients.
    /// Caller-owned unsent payloads are outside this bound. Payload byte size
    /// is application-defined; accepted payloads are shared through `Arc`.
    pub max_in_flight: usize,
}
impl EventManagerConfig {
    /// Set each bound explicitly; zero is rejected before any task starts.
    #[must_use]
    pub const fn new(max_handlers: usize, mailbox_capacity: usize, max_in_flight: usize) -> Self {
        Self { max_handlers, mailbox_capacity, max_in_flight }
    }
}

/// Per-handler managed restart policy.
#[derive(Debug, Clone)]
pub struct EventHandlerConfig {
    /// Application errors and panics restart only when this is true. Success
    /// and voluntary cancellation always stop, so graceful markers cannot restart.
    pub restart_on_failure: bool,
    /// Existing restart intensity, backoff, escalation and storm policy.
    pub supervision: SupervisionConfig,
    /// Existing managed generation shutdown budget.
    pub shutdown_budget: Budget,
}
impl EventHandlerConfig {
    /// Restart failures according to the supplied existing supervisor policy.
    #[must_use]
    pub fn new(supervision: SupervisionConfig) -> Self {
        Self { restart_on_failure: true, supervision, shutdown_budget: Budget::INFINITE }
    }
    /// Permanently remove a handler after its first terminal generation.
    #[must_use]
    pub fn without_restart(mut self) -> Self { self.restart_on_failure = false; self }
}

/// Backpressure is decided before any event publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventBackpressure {
    /// Wait within the caller's cancellation/deadline budget.
    Wait,
    /// Refuse the whole notification if any live recipient has no capacity.
    Reject,
}

/// Admission or lifecycle refusal. No error asserts that owned work drained.
#[derive(Debug)]
#[non_exhaustive]
pub enum EventManagerError {
    /// Invalid zero bounds or empty/overlong name.
    InvalidConfig,
    /// The finite emission/receipt limit is occupied.
    Busy,
    /// A selected mailbox is full; nothing was published.
    Backpressured(u64),
    /// A live runtime task from this manager's runtime is required.
    RuntimeRequired,
    /// Admission has been sealed or the runtime has stopped.
    Closed,
    /// The caller acknowledged cancellation before this operation completed.
    Cancelled(CancelReason),
    /// Publication succeeded, but its processing wait was interrupted. Pending
    /// recipients remain owned; completed siblings' results are preserved.
    Interrupted {
        /// Cancellation or deadline that ended this wait.
        reason: CancelReason,
        /// Per-recipient progress when the wait ended.
        report: EventReport,
        /// Resume observation using a context with a live budget.
        receipt: EventReceipt,
    },
    /// A handler reference belongs to another manager or an older admission.
    StaleHandler,
    /// Handler identity space cannot wrap.
    IdentityExhausted,
    /// Checked send-obligation admission was refused before event publication.
    Admission(ObligationAdmissionError),
    /// The supplied managed policy/topology is invalid.
    Configuration(ManagedSupervisorBindError),
    /// Original dynamic lifecycle failure; quarantined state remains owned.
    Supervisor(DynamicSupervisorError),
}
impl fmt::Display for EventManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "event manager: {self:?}") }
}
impl std::error::Error for EventManagerError {}

/// Typed user failure, retained in the actual child supervision receipt.
#[derive(Debug)]
#[non_exhaustive]
pub enum EventHandlerFailure<X> {
    /// Initialization failed.
    Init(X),
    /// Processing failed; that event is consumed and is not replayed on restart.
    Event(X),
    /// Termination failed and replacement was refused.
    Terminate(X),
    /// An internal mailbox generation was unavailable.
    MailboxUnavailable,
}

struct HandlerState {
    initialized: Mutex<Option<ManagedGeneration>>,
    cleanup: Mutex<Option<(ManagedGeneration, TaskOutcome)>>,
    closed: AtomicBool,
    changed: Notify,
}

/// Non-reusable identity of one attached handler, across its policy restarts.
#[derive(Clone)]
pub struct EventHandlerRef {
    id: u64,
    owner: RegionId,
    name: String,
    state: Arc<HandlerState>,
}
impl fmt::Debug for EventHandlerRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventHandlerRef").field("id", &self.id).field("owner", &self.owner)
            .field("name", &self.name).field("closed", &self.is_closed()).finish()
    }
}
impl EventHandlerRef {
    /// Owner-local monotone attachment identity.
    #[must_use]
    pub const fn id(&self) -> u64 { self.id }
    /// Declared handler name.
    #[must_use]
    pub fn name(&self) -> &str { &self.name }
    /// Whether this attachment can never start another generation.
    #[must_use]
    pub fn is_closed(&self) -> bool { self.state.closed.load(Ordering::Acquire) }
    /// Wait until initialization of a generation completed. This is an
    /// observation, not a promise that the generation remains alive afterwards.
    pub async fn ready(&self, cx: &Cx) -> Result<ManagedGeneration, EventManagerError> {
        loop {
            let wait = self.state.changed.wait_until(|| self.is_closed() || self.state.initialized.lock().is_some());
            wait_cancel(cx, wait).await?;
            if self.is_closed() { return Err(EventManagerError::Closed); }
            if let Some(generation) = *self.state.initialized.lock() { return Ok(generation); }
        }
    }
}

/// Processing observation; delivery acceptance alone is not success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventStatus {
    /// No terminal result was observed yet; interruption does not stop the work.
    Pending,
    /// Processing completed successfully.
    Handled,
    /// The callback returned an application error.
    Failed,
    /// The callback acknowledged cancellation.
    Cancelled,
    /// The callback panicked.
    Panicked,
    /// The recipient retired before its publication could commit.
    Departed,
    /// The accepted delivery was dropped without a processing result.
    Abandoned,
}
/// One exact snapshot recipient's processing observation.
#[derive(Debug, Clone)]
pub struct EventRecipient {
    /// Stable attachment identity.
    pub handler: EventHandlerRef,
    /// Actual generation that reported processing, when a result is available.
    pub generation: Option<ManagedGeneration>,
    /// Explicit processing or pending classification.
    pub status: EventStatus,
}
/// All recipients captured by one notification, in attachment order.
#[derive(Debug, Clone)]
pub struct EventReport {
    /// Empty is valid when no handlers were attached.
    pub recipients: Vec<EventRecipient>,
}
impl EventReport {
    /// Whether every selected recipient actually finished processing.
    #[must_use]
    pub fn all_handled(&self) -> bool {
        self.recipients.iter().all(|r| r.status == EventStatus::Handled)
    }
}

struct Credit { used: Arc<AtomicUsize> }
impl Drop for Credit { fn drop(&mut self) { self.used.fetch_sub(1, Ordering::AcqRel); } }
struct BatchState { results: Vec<Option<EventRecipient>>, credit: Option<Credit> }
struct Batch { targets: Vec<EventHandlerRef>, state: Mutex<BatchState>, changed: Notify }
impl Batch {
    fn finish(&self, index: usize, result: EventRecipient) {
        let released = {
            let mut state = self.state.lock();
            if state.results[index].is_some() { return; }
            state.results[index] = Some(result);
            if state.results.iter().all(Option::is_some) { state.credit.take() } else { None }
        };
        drop(released);
        self.changed.notify_waiters();
    }
    fn complete(&self) -> bool { self.state.lock().results.iter().all(Option::is_some) }
}
/// A repeatable wait for processing after notification publication.
/// Dropping a receipt does not cancel work already accepted by handlers.
#[derive(Clone)]
pub struct EventReceipt { batch: Arc<Batch> }
impl fmt::Debug for EventReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventReceipt").field("complete", &self.is_complete()).finish()
    }
}
impl EventReceipt {
    /// Whether every selected handler has settled its copy.
    #[must_use]
    pub fn is_complete(&self) -> bool { self.batch.complete() }
    /// Snapshot every captured recipient, preserving unfinished entries as
    /// `Pending`. This never cancels or consumes the accepted work.
    #[must_use]
    pub fn snapshot(&self) -> EventReport {
        let state = self.batch.state.lock();
        EventReport { recipients: state.results.iter().enumerate().map(|(index, result)|
            result.clone().unwrap_or_else(|| EventRecipient {
                handler: self.batch.targets[index].clone(), generation: None, status: EventStatus::Pending,
            })).collect() }
    }
    /// Wait cancellation leaves this receipt and all accepted work intact.
    pub async fn wait(&self, cx: &Cx) -> Result<EventReport, EventManagerError> {
        wait_cancel(cx, self.batch.changed.wait_until(|| self.batch.complete())).await
            .map_err(|error| match error {
                EventManagerError::Cancelled(reason) => EventManagerError::Interrupted {
                    reason, report: self.snapshot(), receipt: self.clone(),
                }, other => other,
            })?;
        Ok(self.snapshot())
    }
}

struct Delivery<E> {
    event: Arc<E>, batch: Arc<Batch>, index: usize, handler: EventHandlerRef,
    generation: Option<ManagedGeneration>, settled: bool,
}
impl<E> Delivery<E> {
    fn finish(&mut self, status: EventStatus) {
        if self.settled { return; }
        self.settled = true;
        self.batch.finish(self.index, EventRecipient {
            handler: self.handler.clone(), generation: self.generation, status,
        });
    }
}
impl<E> Drop for Delivery<E> { fn drop(&mut self) { self.finish(EventStatus::Abandoned); } }
enum Message<E> { Event(Delivery<E>), Stop(EventStopReason) }
struct Route<E> { handler: EventHandlerRef, sender: mpsc::Sender<Message<E>> }
impl<E> Clone for Route<E> {
    fn clone(&self) -> Self { Self { handler: self.handler.clone(), sender: self.sender.clone() } }
}
// Dropping a checked reservation or permit can invoke a detached producer or
// obligation waker. Keep both in one owner so abandonment releases the routing
// gate before rolling back any reserved capacity or queued admission wait.
struct Reservations<'a, E> {
    gate: Option<RwLockReadGuard<'a, ()>>,
    permits: Vec<Option<mpsc::SendPermit<'a, Message<E>>>>,
    waiting: Option<mpsc::CheckedReserve<'a, Message<E>>>,
}
impl<E> Drop for Reservations<'_, E> {
    fn drop(&mut self) { drop(self.gate.take()); }
}
struct Shared<E> {
    routes: Mutex<BTreeMap<u64, Route<E>>>,
    gate: RwLock<()>, closed: AtomicBool, changed: Notify,
    used: Arc<AtomicUsize>, limit: usize, runtime: Weak<ObligationMailbox>,
}
impl<E> Shared<E> {
    fn close(&self) { self.closed.store(true, Ordering::Release); self.changed.notify_waiters(); }
    fn validate(&self, cx: &Cx) -> Result<(), EventManagerError> {
        cx.checkpoint().map_err(|_| cancelled(cx))?;
        let runtime = runtime_identity(cx)?;
        if !Weak::ptr_eq(&runtime, &self.runtime) { return Err(EventManagerError::RuntimeRequired); }
        if self.closed.load(Ordering::Acquire) { return Err(EventManagerError::Closed); }
        Ok(())
    }
    fn credit(&self) -> Result<Credit, EventManagerError> {
        self.used.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |used| if used < self.limit { used.checked_add(1) } else { None })
            .map_err(|_| EventManagerError::Busy)?;
        Ok(Credit { used: Arc::clone(&self.used) })
    }
    async fn while_open<F: Future>(&self, future: F) -> Result<F::Output, EventManagerError> {
        let mut future = std::pin::pin!(future);
        let mut closed = std::pin::pin!(self.changed.wait_until(|| self.closed.load(Ordering::Acquire)));
        poll_fn(|task| {
            if closed.as_mut().poll(task).is_ready() { return Poll::Ready(Err(EventManagerError::Closed)); }
            future.as_mut().poll(task).map(Ok)
        }).await
    }
}

/// Cloneable notification capability; it does not own the manager's lifetime.
pub struct EventEmitter<E> { shared: Arc<Shared<E>> }
impl<E> Clone for EventEmitter<E> {
    fn clone(&self) -> Self { Self { shared: Arc::clone(&self.shared) } }
}
impl<E> fmt::Debug for EventEmitter<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventEmitter").field("in_flight", &self.in_flight()).finish_non_exhaustive()
    }
}
impl<E> EventEmitter<E> {
    /// Accepted reservation waits and not-yet-settled events.
    #[must_use]
    pub fn in_flight(&self) -> usize { self.shared.used.load(Ordering::Acquire) }
}
impl<E: Send + Sync + 'static> EventEmitter<E> {
    /// Reserve every selected active mailbox, then publish without awaiting.
    /// Cancellation/full refusal before publication sends nothing. A concurrent
    /// recipient retirement during commit becomes `Departed` in the receipt.
    /// Concurrent notifications may interleave processing across handlers.
    pub async fn notify(&self, cx: &Cx, event: E, policy: EventBackpressure)
        -> Result<EventReceipt, EventManagerError> {
        self.shared.validate(cx)?;
        let credit = self.shared.credit()?;
        // Retain one owner outside the routing gate: even failed commits cannot
        // run the last user payload destructor while the gate is held.
        let event = Arc::new(event);
        let gate = self.shared.while_open(self.shared.gate.read(cx)).await?
            .map_err(|_| cancelled_or_closed(cx))?;
        self.shared.validate(cx)?;
        let routes: Vec<_> = self.shared.routes.lock().values().cloned().collect();
        let mut reservations = Reservations {
            gate: Some(gate), permits: Vec::with_capacity(routes.len()), waiting: None,
        };
        for route in &routes {
            let reserved = if policy == EventBackpressure::Wait {
                reservations.waiting = Some(route.sender.reserve_checked(cx));
                self.shared.while_open(reservations.waiting.as_mut().expect("pending reservation")).await?
            } else { route.sender.try_reserve_checked(cx) };
            drop(reservations.waiting.take());
            match reserved {
                Ok(permit) => reservations.permits.push(Some(permit)),
                Err(mpsc::CheckedSendError::Channel(mpsc::SendError::Disconnected(()))) => reservations.permits.push(None),
                Err(mpsc::CheckedSendError::Channel(mpsc::SendError::Full(()))) => {
                    return Err(EventManagerError::Backpressured(route.handler.id));
                }
                Err(mpsc::CheckedSendError::Channel(mpsc::SendError::Cancelled(()))) => return Err(cancelled(cx)),
                Err(mpsc::CheckedSendError::Admission { error, .. }) => return Err(EventManagerError::Admission(error)),
            }
        }
        self.shared.validate(cx)?;
        let batch = Arc::new(Batch {
            targets: routes.iter().map(|route| route.handler.clone()).collect(),
            state: Mutex::new(BatchState { results: vec![None; routes.len()], credit: Some(credit) }),
            changed: Notify::new(),
        });
        if routes.is_empty() { drop(batch.state.lock().credit.take()); }
        // Checked permits own rollback. Commit has no cancellation point; an
        // asynchronously retiring receiver is accounted for individually.
        let mut wakes = Vec::with_capacity(routes.len());
        for (index, route) in routes.iter().enumerate() {
            let permit = reservations.permits[index].take();
            if let Some(permit) = permit {
                let delivery = Delivery { event: Arc::clone(&event), batch: Arc::clone(&batch), index,
                    handler: route.handler.clone(), generation: None, settled: false };
                let (sent, wake) = permit.try_send_deferred_wake(Message::Event(delivery));
                wakes.push(wake);
                if let Err(error) = sent {
                    let (mpsc::SendError::Disconnected(Message::Event(mut delivery))
                        | mpsc::SendError::Cancelled(Message::Event(mut delivery))
                        | mpsc::SendError::Full(Message::Event(mut delivery))) = error else { unreachable!() };
                    delivery.finish(EventStatus::Departed);
                }
            } else {
                batch.finish(index, EventRecipient { handler: route.handler.clone(), generation: None,
                    status: EventStatus::Departed });
            }
        }
        drop(reservations);
        // Every queue is committed and the routing gate is released before any
        // arbitrary receiver wake runs. A bad wake cannot starve later recipients.
        let mut first_panic = None;
        for wake in wakes {
            if let Err(payload) = catch_unwind(AssertUnwindSafe(|| wake.wake())) {
                if first_panic.is_none() { first_panic = Some(payload); }
                else { std::mem::forget(payload); }
            }
        }
        drop(event);
        if let Some(payload) = first_panic { std::panic::resume_unwind(payload); }
        Ok(EventReceipt { batch })
    }
    /// Publish, then wait for every captured recipient's processing result.
    /// An interrupted second phase returns its partial report and resumable
    /// receipt, without undoing accepted work or losing completed results.
    pub async fn sync_notify(&self, cx: &Cx, event: E, policy: EventBackpressure)
        -> Result<EventReport, EventManagerError> {
        self.notify(cx, event, policy).await?.wait(cx).await
    }
}

trait Factory<E, X>: Send + Sync + 'static {
    fn create(&self, cx: &Cx, generation: ManagedGeneration) -> Box<dyn EventHandler<E, Error = X>>;
}
struct FactoryFn<F, H> { factory: F, marker: PhantomData<fn() -> H> }
impl<E, X, F, H> Factory<E, X> for FactoryFn<F, H>
where E: 'static, X: Send + 'static, F: Fn(&Cx, ManagedGeneration) -> H + Send + Sync + 'static,
    H: EventHandler<E, Error = X>,
{
    fn create(&self, cx: &Cx, generation: ManagedGeneration) -> Box<dyn EventHandler<E, Error = X>> {
        Box::new((self.factory)(cx, generation))
    }
}
struct HandlerFactory<E, X> {
    factory: Arc<dyn Factory<E, X>>, handler: EventHandlerRef,
    receiver: Arc<Mutex<Option<mpsc::Receiver<Message<E>>>>>, shared: Arc<Shared<E>>,
}
impl<E: Send + Sync + 'static, X: Send + 'static> ManagedChildFactory<EventHandlerFailure<X>> for HandlerFactory<E, X> {
    fn start(&self, cx: Cx, generation: ManagedGeneration) -> ManagedChildFuture<EventHandlerFailure<X>> {
        let factory = Arc::clone(&self.factory);
        let receiver = Arc::clone(&self.receiver);
        let handler = self.handler.clone();
        Box::pin(async move { run_handler(cx, generation, handler, receiver, factory).await })
    }
    fn retired(&self) {
        self.handler.state.closed.store(true, Ordering::Release);
        let route = self.shared.routes.lock().remove(&self.handler.id);
        let receiver = self.receiver.lock().take();
        self.handler.state.changed.notify_waiters();
        drop(route);
        drop(receiver);
    }
}
struct ReceiverLease<E> {
    receiver: Option<mpsc::Receiver<Message<E>>>, slot: Arc<Mutex<Option<mpsc::Receiver<Message<E>>>>>,
}
impl<E> Drop for ReceiverLease<E> {
    fn drop(&mut self) {
        let retired = self.slot.lock().replace(self.receiver.take().expect("owned handler receiver"));
        drop(retired);
    }
}

async fn run_handler<E: Send + Sync + 'static, X: Send + 'static>(
    cx: Cx, generation: ManagedGeneration, reference: EventHandlerRef,
    slot: Arc<Mutex<Option<mpsc::Receiver<Message<E>>>>>, factory: Arc<dyn Factory<E, X>>,
) -> Outcome<(), EventHandlerFailure<X>> {
    let receiver = slot.lock().take();
    let Some(receiver) = receiver else { return Outcome::Err(EventHandlerFailure::MailboxUnavailable); };
    let mut receiver = ReceiverLease { receiver: Some(receiver), slot };
    let mut handler = match catch_unwind(AssertUnwindSafe(|| factory.create(&cx, generation))) {
        Ok(handler) => handler,
        Err(payload) => return Outcome::Panicked(panic_payload(payload)),
    };
    *reference.state.initialized.lock() = None;
    let mut outcome = invoke(|| handler.init(&cx), None).await.map_err(EventHandlerFailure::Init);
    let mut reason = EventStopReason::Failed;
    if outcome.is_ok() {
        *reference.state.initialized.lock() = Some(generation);
        reference.state.changed.notify_waiters();
        loop {
            match receiver.receiver.as_mut().expect("owned receiver").recv(&cx).await {
                Ok(Message::Event(mut delivery)) => {
                    delivery.generation = Some(generation);
                    let result = invoke(|| handler.handle_event(&cx, &delivery.event), None).await;
                    delivery.finish(match &result {
                        Outcome::Ok(()) => EventStatus::Handled, Outcome::Err(_) => EventStatus::Failed,
                        Outcome::Cancelled(_) => EventStatus::Cancelled, Outcome::Panicked(_) => EventStatus::Panicked,
                    });
                    outcome = result.map_err(EventHandlerFailure::Event);
                    if !outcome.is_ok() { break; }
                }
                Ok(Message::Stop(stopping)) => { reason = stopping; break; }
                Err(mpsc::RecvError::Cancelled) => {
                    reason = EventStopReason::Cancelled;
                    outcome = Outcome::Cancelled(cancel_reason(&cx));
                    break;
                }
                Err(_) => { reason = EventStopReason::Cancelled; break; }
            }
        }
    }
    if matches!(outcome, Outcome::Cancelled(_)) { reason = EventStopReason::Cancelled; }
    *reference.state.initialized.lock() = None;
    reference.state.changed.notify_waiters();
    let mut cleanup = invoke(|| handler.terminate(&cx, reason), Some(&cx)).await;
    if let Err(payload) = cx.masked(|| catch_unwind(AssertUnwindSafe(|| drop(handler)))) {
        let previous = std::mem::replace(&mut cleanup, Outcome::Panicked(panic_payload(payload)));
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(previous))) {
            std::mem::forget(payload);
        }
    }
    if !cleanup.is_ok() {
        let receipt = match &cleanup {
            Outcome::Ok(()) => Outcome::Ok(()), Outcome::Err(_) => Outcome::Err(()),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason.clone()),
            Outcome::Panicked(payload) => Outcome::Panicked(payload.clone()),
        };
        let retired = reference.state.cleanup.lock().replace((generation, receipt));
        drop(retired);
        if cleanup.severity() >= outcome.severity() { outcome = cleanup.map_err(EventHandlerFailure::Terminate); }
    }
    outcome
}

async fn invoke<'a, X: 'a>(action: impl FnOnce() -> EventHandlerFuture<'a, X>, mask: Option<&Cx>)
    -> Outcome<(), X> {
    let constructed = if let Some(cx) = mask {
        cx.masked(|| catch_unwind(AssertUnwindSafe(action)))
    } else {
        catch_unwind(AssertUnwindSafe(action))
    };
    let mut future = match constructed {
        Ok(future) => future,
        Err(payload) => return Outcome::Panicked(panic_payload(payload)),
    };
    let result = poll_fn(|task| {
        let polled = if let Some(cx) = mask {
            cx.masked(|| catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(task))))
        } else {
            catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(task)))
        };
        match polled {
            Ok(result) => result,
            Err(payload) => Poll::Ready(Outcome::Panicked(panic_payload(payload))),
        }
    }).await;
    let dropped = if let Some(cx) = mask {
        cx.masked(|| catch_unwind(AssertUnwindSafe(|| drop(future))))
    } else {
        catch_unwind(AssertUnwindSafe(|| drop(future)))
    };
    match dropped {
        Ok(()) => result,
        Err(payload) => Outcome::Panicked(panic_payload(payload)),
    }
}

struct Attached<E> { reference: EventHandlerRef, child: DynamicChildId, sender: mpsc::Sender<Message<E>> }
struct Transition<E> { shared: Arc<Shared<E>>, completed: bool }
impl<E> Drop for Transition<E> {
    fn drop(&mut self) { if !self.completed { self.shared.close(); } }
}

/// Owns all handler tasks and their actual finalization barriers.
/// Dropping requests structured cancellation; only shutdown is a drain receipt.
pub struct EventManager<E, X> {
    supervisor: Option<DynamicSupervisor<EventHandlerFailure<X>>>,
    shared: Arc<Shared<E>>, config: EventManagerConfig,
    attached: BTreeMap<u64, Attached<E>>, next_id: u64, region: RegionId,
}
impl<E, X> fmt::Debug for EventManager<E, X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventManager").field("region", &self.region)
            .field("handlers", &self.attached.len()).finish_non_exhaustive()
    }
}
impl<E, X> EventManager<E, X> {
    /// Clone emission capability without extending owner lifetime.
    #[must_use]
    pub fn emitter(&self) -> EventEmitter<E> { EventEmitter { shared: Arc::clone(&self.shared) } }
    /// Region owning all dynamic handler boundaries.
    #[must_use]
    pub const fn region_id(&self) -> RegionId { self.region }
    /// Attached identities, including terminal children awaiting reaping.
    #[must_use]
    pub fn handlers(&self) -> Vec<EventHandlerRef> {
        self.attached.values().map(|a| a.reference.clone()).collect()
    }
    fn check_ref(&self, reference: &EventHandlerRef) -> Result<(), EventManagerError> {
        let matches = self.attached.get(&reference.id)
            .is_some_and(|attached| Arc::ptr_eq(&attached.reference.state, &reference.state));
        if reference.owner != self.region || !matches {
            return Err(EventManagerError::StaleHandler);
        }
        Ok(())
    }
}
impl<E: Send + Sync + 'static, X: Send + 'static> EventManager<E, X> {
    /// Open the existing dynamic supervisor after validating finite bounds.
    pub async fn open(cx: &Cx, config: EventManagerConfig) -> Result<Self, EventManagerError> {
        if config.max_handlers == 0 || config.mailbox_capacity == 0 || config.max_in_flight == 0 {
            return Err(EventManagerError::InvalidConfig);
        }
        let runtime = runtime_identity(cx)?;
        let supervisor = cx.open_dynamic_supervisor(DynamicSupervisorConfig::new(config.max_handlers))
            .await.map_err(EventManagerError::Supervisor)?;
        let region = supervisor.region_id();
        Ok(Self { supervisor: Some(supervisor), region, config: config.clone(), next_id: 0,
            attached: BTreeMap::new(), shared: Arc::new(Shared { routes: Mutex::new(BTreeMap::new()),
                gate: RwLock::new(()), closed: AtomicBool::new(false), changed: Notify::new(),
                used: Arc::new(AtomicUsize::new(0)), limit: config.max_in_flight, runtime }) })
    }

    /// Admit a retained handler factory. Use the returned reference's `ready`
    /// method when initialization must finish before continuing. Each restart
    /// creates fresh handler state while retaining queued, unconsumed events.
    pub async fn add_handler<F, H>(&mut self, cx: &Cx, name: impl Into<String>,
        config: EventHandlerConfig, factory: F) -> Result<EventHandlerRef, EventManagerError>
    where F: Fn(&Cx, ManagedGeneration) -> H + Send + Sync + 'static,
        H: EventHandler<E, Error = X>,
    {
        self.shared.validate(cx)?;
        let name = name.into();
        self.preflight_name(&name)?;
        let factory: Arc<dyn Factory<E, X>> = Arc::new(FactoryFn { factory, marker: PhantomData::<fn() -> H> });
        let shared = Arc::clone(&self.shared);
        let gate = shared.while_open(shared.gate.write(cx)).await?.map_err(|_| cancelled_or_closed(cx))?;
        let mut transition = Transition { shared: Arc::clone(&shared), completed: false };
        let result = self.attach(name, config, factory).await;
        transition.completed = result.is_ok();
        drop(gate);
        result
    }

    async fn attach(&mut self, name: String, config: EventHandlerConfig,
        factory: Arc<dyn Factory<E, X>>) -> Result<EventHandlerRef, EventManagerError> {
        if name.is_empty() || name.len() > 255 { return Err(EventManagerError::InvalidConfig); }
        let id = self.next_id.checked_add(1).ok_or(EventManagerError::IdentityExhausted)?;
        self.next_id = id;
        let reference = EventHandlerRef { id, owner: self.region, name: name.clone(), state: Arc::new(HandlerState {
            initialized: Mutex::new(None), cleanup: Mutex::new(None), closed: AtomicBool::new(false), changed: Notify::new(),
        }) };
        let (sender, receiver) = mpsc::channel(self.config.mailbox_capacity);
        let state = Arc::clone(&reference.state);
        let binding = ManagedChildBinding::new(name.clone(),
            if config.restart_on_failure { ManagedRestartMode::Transient } else { ManagedRestartMode::Temporary },
            HandlerFactory { factory, handler: reference.clone(), receiver: Arc::new(Mutex::new(Some(receiver))),
                shared: Arc::clone(&self.shared) })
            .with_cleanup_observer(Arc::new(move |generation| {
                state.cleanup.lock().as_ref().filter(|(seen, _)| *seen == generation).map(|(_, outcome)| outcome.clone())
            }));
        let compiled = SupervisorBuilder::new(name.clone()).with_restart_policy(config.supervision.restart_policy)
            .child(ChildSpec::new(name.clone(), |_scope: &crate::cx::Scope<'static>,
                _state: &mut RuntimeState, _cx: &Cx| Err(SpawnError::RuntimeUnavailable))
                .with_shutdown_budget(config.shutdown_budget))
            .compile().map_err(|error| EventManagerError::Configuration(ManagedSupervisorBindError::Topology(error)))?;
        let supervisor = compiled.bind_managed(vec![binding], config.supervision)
            .map_err(EventManagerError::Configuration)?;
        let child = self.supervisor.as_mut().expect("owned supervisor").start_child(name, supervisor)
            .await.map_err(EventManagerError::Supervisor)?;
        // A quick terminal generation can retire before start_child returns.
        // Do not republish its route after the retirement callback removed it.
        {
            let mut routes = self.shared.routes.lock();
            if !reference.is_closed() {
                routes.insert(id, Route { handler: reference.clone(), sender: sender.clone() });
            }
        }
        self.attached.insert(id, Attached { reference: reference.clone(), child, sender });
        Ok(reference)
    }

    fn preflight_name(&self, name: &str) -> Result<(), EventManagerError> {
        if name.is_empty() || name.len() > 255 { return Err(EventManagerError::InvalidConfig); }
        if self.attached.len() >= self.config.max_handlers {
            return Err(EventManagerError::Supervisor(DynamicSupervisorError::Capacity));
        }
        if self.attached.values().any(|entry| entry.reference.name == name) {
            return Err(EventManagerError::Supervisor(DynamicSupervisorError::DuplicateName));
        }
        if self.next_id == u64::MAX { return Err(EventManagerError::IdentityExhausted); }
        Ok(())
    }

    /// Withdraw through a FIFO marker, then join the exact child and region.
    /// Failure/abandonment after the transition starts seals emission admission.
    pub async fn remove_handler(&mut self, cx: &Cx, reference: &EventHandlerRef)
        -> Result<DynamicChildCompletion<EventHandlerFailure<X>>, EventManagerError> {
        self.check_ref(reference)?;
        self.shared.validate(cx)?;
        let shared = Arc::clone(&self.shared);
        let gate = shared.while_open(shared.gate.write(cx)).await?.map_err(|_| cancelled_or_closed(cx))?;
        let mut transition = Transition { shared: Arc::clone(&shared), completed: false };
        let result = self.stop_handler(cx, reference, EventStopReason::Removed).await;
        transition.completed = result.is_ok();
        drop(gate);
        result
    }

    async fn stop_handler(&mut self, cx: &Cx, reference: &EventHandlerRef, reason: EventStopReason)
        -> Result<DynamicChildCompletion<EventHandlerFailure<X>>, EventManagerError> {
        let attached = self.attached.get(&reference.id).ok_or(EventManagerError::StaleHandler)?;
        let child = attached.child.clone();
        if !reference.is_closed() {
            match attached.sender.send_checked(cx, Message::Stop(reason)).await {
                Ok(()) | Err(mpsc::CheckedSendError::Channel(mpsc::SendError::Disconnected(_))) => {}
                Err(mpsc::CheckedSendError::Admission { error, .. }) => return Err(EventManagerError::Admission(error)),
                Err(_) => return Err(cancelled_or_closed(cx)),
            }
        }
        let report = self.supervisor.as_mut().expect("owned supervisor").wait_child(&child)
            .await.map_err(EventManagerError::Supervisor)?;
        let retired = self.attached.remove(&reference.id);
        drop(retired);
        Ok(report)
    }

    /// Drain and replace under one emission barrier. Accepted prior events run
    /// on the old handler; emitters waiting at the barrier target the replacement.
    /// No old/new callbacks overlap. An unsuccessful replacement seals emission.
    pub async fn swap_handler<F, H>(&mut self, cx: &Cx, reference: &EventHandlerRef,
        config: EventHandlerConfig, factory: F)
        -> Result<(EventHandlerRef, DynamicChildCompletion<EventHandlerFailure<X>>), EventManagerError>
    where F: Fn(&Cx, ManagedGeneration) -> H + Send + Sync + 'static, H: EventHandler<E, Error = X>,
    {
        self.check_ref(reference)?;
        self.shared.validate(cx)?;
        let factory: Arc<dyn Factory<E, X>> = Arc::new(FactoryFn { factory, marker: PhantomData::<fn() -> H> });
        let shared = Arc::clone(&self.shared);
        let gate = shared.while_open(shared.gate.write(cx)).await?.map_err(|_| cancelled_or_closed(cx))?;
        let mut transition = Transition { shared: Arc::clone(&shared), completed: false };
        let retired = self.stop_handler(cx, reference, EventStopReason::Replaced).await?;
        let replacement = self.attach(reference.name.clone(), config, factory).await?;
        transition.completed = true;
        drop(gate);
        Ok((replacement, retired))
    }

    /// Seal notifications, cancel every handler, then drive every real region
    /// close. Remains available after an abandoned or failed control transition.
    pub async fn shutdown(mut self) -> DynamicSupervisorReport<EventHandlerFailure<X>> {
        self.shared.close();
        self.supervisor.take().expect("owned supervisor").shutdown().await
    }
}
impl<E, X> Drop for EventManager<E, X> {
    fn drop(&mut self) { self.shared.close(); }
}

fn runtime_identity(cx: &Cx) -> Result<Weak<ObligationMailbox>, EventManagerError> {
    cx.checkpoint().map_err(|_| cancelled(cx))?;
    let (gateway, holder) = cx.obligation_transfer_destination().map_err(|_| EventManagerError::RuntimeRequired)?;
    if !gateway.is_runtime_available() || !holder.is_live() || holder.holder() != cx.task_id()
        || holder.region() != cx.region_id() { return Err(EventManagerError::RuntimeRequired); }
    Ok(Arc::downgrade(gateway.mailbox()))
}
fn cancel_reason(cx: &Cx) -> CancelReason {
    cx.cancel_reason().unwrap_or_else(|| CancelReason::user("event manager caller cancelled"))
}
fn cancelled(cx: &Cx) -> EventManagerError { EventManagerError::Cancelled(cancel_reason(cx)) }
fn cancelled_or_closed(cx: &Cx) -> EventManagerError {
    if cx.checkpoint().is_err() { cancelled(cx) } else { EventManagerError::Closed }
}
async fn wait_cancel<F: Future<Output = ()>>(cx: &Cx, wait: F) -> Result<(), EventManagerError> {
    let mut wait = std::pin::pin!(wait);
    let mut cancelled_wait = std::pin::pin!(cx.cancelled());
    poll_fn(|task| {
        let _ = cancelled_wait.as_mut().poll(task);
        if cx.checkpoint().is_err() { return Poll::Ready(Err(cancelled(cx))); }
        wait.as_mut().poll(task).map(Ok)
    }).await
}
fn panic_payload(payload: Box<dyn std::any::Any + Send>) -> PanicPayload {
    let message = payload.downcast_ref::<&str>().map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "event handler panicked".to_string());
    // A panic payload can itself have an arbitrary panicking destructor.
    if let Err(secondary) = catch_unwind(AssertUnwindSafe(|| drop(payload))) { std::mem::forget(secondary); }
    PanicPayload::new(message)
}

#[cfg(test)]
mod tests;
