//! All-settled factory joins with one fully drained private subtree per input.
//!
//! Reuses the owned branch admission and region-close barriers used by scoped
//! race, quorum and retry (core plan sections 6 and 12, asupersync-bi2462).

use super::child_region::RegionQuiescence;
use super::{ChildRegionError, Cx, ScopedTimeoutClose, cap};
use crate::runtime::spawn_mailbox::{BranchRegionSlot, SpawnGateway};
use crate::runtime::state::SpawnError;
use crate::runtime::{JoinError, TaskHandle};
use crate::types::{CancelReason, PanicPayload, RegionId};
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::future::{Future, poll_fn};
use std::num::NonZeroUsize;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};

/// Maximum number of factories accepted by the eager [`Cx::join_all_scoped`] API.
pub const MAX_SCOPED_JOIN_BRANCHES: usize = 64;

/// Why an all-settled join stopped waiting for ordinary body completion.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ScopedJoinStop {
    /// Every submitted factory ran and its task joined, including task errors
    /// and panics. This does not assert that bodies or subtree cleanup succeeded.
    /// Empty input also completes, without requiring an owning runtime.
    Completed,
    /// The explicit owner requested cancellation before all bodies joined.
    Cancelled(CancelReason),
    /// Submission, private-region admission, or first factory invocation was
    /// refused for this input. All already-submitted inputs are still drained.
    NotAdmitted {
        /// Zero-based input position of the refused branch.
        index: usize,
    },
}

/// Actual task evidence, independently of owner cancellation and region close.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScopedJoinTask<T> {
    /// No task was submitted, or its wrapper refused the user factory.
    /// A task cancelled before its first poll can instead retain its ordinary
    /// cancellation error in [`Self::Joined`].
    NotStarted,
    /// Submission refused before a task handle was returned.
    SubmissionFailed(SpawnError),
    /// The unchanged task join result. `T` can itself be a typed `Result` or
    /// `Outcome`; application failures are values and do not cancel siblings.
    Joined(Result<T, JoinError>),
}

/// Actual whole-subtree cleanup evidence, shared with scoped timeout operations.
pub type ScopedJoinClose = ScopedTimeoutClose;

/// Independent task and private-region cleanup facts for one input.
#[derive(Debug)]
#[non_exhaustive]
pub struct ScopedJoinAttempt<T> {
    /// Zero-based input position; reports preserve input order.
    pub index: usize,
    /// Actual task result, including values returned after cancellation acknowledgement.
    pub task: ScopedJoinTask<T>,
    /// Private region identity, when strict admission minted one.
    pub region_id: Option<RegionId>,
    /// The actual close receipt. `None` means no private region was published;
    /// an error does not certify quiescence, even if the body returned a value.
    pub close: Option<Result<ScopedJoinClose, ChildRegionError>>,
}

/// Input-order task results and every operation's independent close receipt.
#[derive(Debug)]
#[non_exhaustive]
#[must_use = "inspect every task result and subtree cleanup receipt"]
pub struct ScopedJoinReport<T> {
    /// Why ordinary body collection ended; cleanup cannot rewrite this fact.
    pub stop: ScopedJoinStop,
    /// Every original input, including unstarted or refused factories.
    pub attempts: Vec<ScopedJoinAttempt<T>>,
    /// Cancellation observed before return, including during unconditional
    /// cleanup. Later strengthening never erases a previously collected result.
    pub owner_cancellation: Option<CancelReason>,
}

/// Why a lazy, bounded all-settled join stopped admitting useful work.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ScopedJoinBoundedStop {
    /// The source returned `None` and every submitted factory ran and joined.
    /// Task and subtree cleanup failures remain independent receipt facts.
    Completed,
    /// The explicit owner requested cancellation before ordinary work ended.
    Cancelled(CancelReason),
    /// Submission or private-region admission refused this pulled input.
    NotAdmitted {
        /// Zero-based position in the lazy input.
        index: usize,
    },
    /// Source conversion, polling, or retirement panicked before another stop.
    /// The first panic diagnostic is retained in the report's `input_panic`.
    InputPanicked {
        /// Number of inputs already pulled when the panic was observed.
        next_index: usize,
    },
    /// A branch could not confirm its subtree closed. Its slot is not reused.
    CloseUnavailable {
        /// Input whose close receipt contains the failure.
        index: usize,
    },
}

/// Pulled-input receipts for a lazy join with a bounded active subtree window.
///
/// Unlike [`ScopedJoinReport`], this never invents entries for an unconsumed
/// input tail. The output retains O(N) receipts for N pulled inputs; the limit
/// bounds active admission, tasks and closing subtrees, not result memory.
#[derive(Debug)]
#[non_exhaustive]
#[must_use = "inspect the stop, input panic, and every task and subtree receipt"]
pub struct ScopedJoinBoundedReport<T> {
    /// Immutable reason ordinary work ended; final cleanup cannot replace it.
    pub stop: ScopedJoinBoundedStop,
    /// Exactly the pulled inputs, in input order, including submission refusal.
    pub attempts: Vec<ScopedJoinAttempt<T>>,
    /// Whether the iterator actually returned `None`; a discarded tail is not EOF.
    pub input_exhausted: bool,
    /// First source or unused-input retirement panic, even after another stop.
    pub input_panic: Option<PanicPayload>,
    /// Largest active window, from pulling an input through its actual close.
    pub max_active: usize,
    /// Owner cancellation observed before return, including during final close.
    pub owner_cancellation: Option<CancelReason>,
}

/// A heterogeneous pair with the same ownership contract as the dynamic join.
#[derive(Debug)]
#[non_exhaustive]
#[must_use = "inspect both task results and subtree cleanup receipts"]
pub struct ScopedJoinPairReport<L, R> {
    /// Why ordinary body collection ended.
    pub stop: ScopedJoinStop,
    /// First input's typed result and private-region close receipt; index zero.
    pub left: ScopedJoinAttempt<L>,
    /// Second input's typed result and private-region close receipt; index one.
    pub right: ScopedJoinAttempt<R>,
    /// Cancellation observed before return, independently of collected values.
    pub owner_cancellation: Option<CancelReason>,
}

/// Refusal before any factory can be submitted.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScopedJoinError {
    /// The caller supplied more than [`MAX_SCOPED_JOIN_BRANCHES`] factories.
    TooManyBranches {
        /// Number of supplied factories.
        total: usize,
    },
    /// The explicit context has no runtime gateway. Per-input submission
    /// refusals instead remain in the report after any admission was attempted.
    Spawn(SpawnError),
}

impl std::fmt::Display for ScopedJoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyBranches { total } => write!(
                f, "scoped join has {total} inputs; at most {MAX_SCOPED_JOIN_BRANCHES} are supported",
            ),
            Self::Spawn(error) => write!(f, "scoped join requires an owning runtime: {error}"),
        }
    }
}

impl std::error::Error for ScopedJoinError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(error) => Some(error),
            Self::TooManyBranches { .. } => None,
        }
    }
}

enum BodyResult<T> {
    Value(T),
    NotStarted,
}

struct Branch<T> {
    region: Arc<BranchRegionSlot>,
    started: Arc<AtomicBool>,
    handle: Option<TaskHandle<BodyResult<T>>>,
    receipt: ScopedJoinAttempt<T>,
}

impl<T> Branch<T> {
    fn new(index: usize, gateway: &Arc<SpawnGateway>) -> Self {
        Self {
            region: Arc::new(BranchRegionSlot::owned(gateway)),
            started: Arc::new(AtomicBool::new(false)),
            handle: None,
            receipt: empty_attempt(index),
        }
    }

    /// Consume each persistent join registration exactly once. Close the
    /// completed body's subtree promptly, without cancelling other branches.
    fn poll_result(&mut self, task: &mut Context<'_>) -> bool {
        let Some(handle) = &mut self.handle else {
            return true;
        };
        let Poll::Ready(result) = handle.poll_join(task) else {
            return false;
        };
        self.handle = None;
        self.receipt.task = match result {
            Ok(BodyResult::Value(value)) => ScopedJoinTask::Joined(Ok(value)),
            Ok(BodyResult::NotStarted) => ScopedJoinTask::NotStarted,
            Err(error) => ScopedJoinTask::Joined(Err(error)),
        };
        let _ = self.region.request_close(CancelReason::user("scoped join body completed"));
        true
    }
}

/// Every slot is guarded before any enqueue. This guard's Drop requests all
/// closes before retained values or unused factories can run their destructors.
struct OwnedJoin<T> {
    branches: Vec<Branch<T>>,
    armed: bool,
}

impl<T> OwnedJoin<T> {
    fn new(total: usize, gateway: &Arc<SpawnGateway>) -> Self {
        Self {
            branches: (0..total).map(|index| Branch::new(index, gateway)).collect(),
            armed: true,
        }
    }

    fn request_stop(&self, reason: CancelReason) {
        let mut first_panic = None;
        // Publish every subtree cancellation BEFORE any direct-task abort.
        // A body can be parked in an ordinary join on its own descendant.
        for branch in &self.branches {
            contain_callback(&mut first_panic, || {
                let _ = branch.region.request_close(reason.clone());
            });
        }
        for branch in &self.branches {
            if let Some(handle) = &branch.handle
                && !handle.terminal_published()
            {
                contain_callback(&mut first_panic, || {
                    handle.abort_with_reason(reason.clone());
                });
            }
        }
        if let Some(payload) = first_panic {
            resume_unwind(payload);
        }
    }
}

// A broken notifier/waker must not prevent cancellation reaching later slots.
// During an existing unwind, forget secondary panic payloads rather than
// risking a second panic from either the callback or its payload destructor.
fn contain_callback(first: &mut Option<Box<dyn Any + Send>>, f: impl FnOnce()) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(f)) {
        if first.is_none() && !std::thread::panicking() {
            *first = Some(payload);
        } else {
            std::mem::forget(payload);
        }
    }
}

impl<T> Drop for OwnedJoin<T> {
    fn drop(&mut self) {
        if self.armed {
            self.request_stop(CancelReason::user("scoped join dropped"));
        }
    }
}

fn empty_attempt<T>(index: usize) -> ScopedJoinAttempt<T> {
    ScopedJoinAttempt {
        index,
        task: ScopedJoinTask::NotStarted,
        region_id: None,
        close: None,
    }
}

const BOUNDED_JOIN_QUANTUM: usize = 64;

type BoundedJoinClose = Pin<
    Box<
        dyn Future<
                Output = (
                    Option<RegionId>,
                    Option<Result<ScopedJoinClose, ChildRegionError>>,
                ),
            > + Send,
    >,
>;

struct BoundedBranch<T> {
    branch: Branch<T>,
    closing: Option<BoundedJoinClose>,
    waker: Waker,
}

#[derive(Default)]
struct BoundedJoinCandidates {
    live: BTreeSet<usize>,
    ready: BTreeSet<usize>,
}

#[derive(Default)]
struct BoundedJoinReady {
    candidates: parking_lot::Mutex<BoundedJoinCandidates>,
    // Only Arc refcounts, never arbitrary RawWaker callbacks, run under locks.
    waiter: parking_lot::Mutex<Option<Arc<Waker>>>,
}

impl BoundedJoinReady {
    fn take_from(&self, from: usize) -> Option<usize> {
        let mut candidates = self.candidates.lock();
        let index = candidates.ready.range(from..).next().copied()?;
        candidates.ready.remove(&index);
        Some(index)
    }

    fn has_ready(&self) -> bool {
        !self.candidates.lock().ready.is_empty()
    }
}

/// One persistent candidate registration covers BOTH task retirement and
/// region close. A wake behind the forward scan cursor survives the next
/// collector poll, including a coalesced wake during a multi-poll sweep.
struct BoundedJoinWake {
    index: usize,
    ready: Arc<BoundedJoinReady>,
}

impl Wake for BoundedJoinWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        {
            let mut candidates = self.ready.candidates.lock();
            if !candidates.live.contains(&self.index) {
                return;
            }
            candidates.ready.insert(self.index);
        }
        let waiter = self.ready.waiter.lock().clone();
        if let Some(waiter) = waiter {
            waiter.wake_by_ref();
        }
    }
}

struct BoundedJoinWait {
    ready: Arc<BoundedJoinReady>,
    registered: Option<Arc<Waker>>,
}

impl BoundedJoinWait {
    fn refresh(&mut self, waker: &Waker) {
        if self
            .registered
            .as_ref()
            .is_some_and(|old| old.will_wake(waker))
        {
            return;
        }
        let incoming = Arc::new(waker.clone());
        let retired_slot = self.ready.waiter.lock().replace(Arc::clone(&incoming));
        let retired_owner = self.registered.replace(incoming);
        drop(retired_slot);
        drop(retired_owner);
    }
}

impl Drop for BoundedJoinWait {
    fn drop(&mut self) {
        let Some(registered) = self.registered.take() else {
            return;
        };
        let retired = {
            let mut waiter = self.ready.waiter.lock();
            if waiter
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &registered))
            {
                waiter.take()
            } else {
                None
            }
        };
        drop(retired);
        drop(registered);
    }
}

struct BoundedJoinCancel {
    reason: CancelReason,
    next: Option<usize>,
}

impl BoundedJoinCancel {
    fn new(reason: CancelReason) -> Self {
        Self {
            reason,
            next: Some(0),
        }
    }
}

/// Owns all active slots before publication and all collected values until
/// report transfer. Drop cancels every subtree before either is destroyed.
struct OwnedBoundedJoin<T> {
    branches: BTreeMap<usize, BoundedBranch<T>>,
    attempts: Vec<ScopedJoinAttempt<T>>,
    ready: Arc<BoundedJoinReady>,
    running: usize,
    max_active: usize,
    armed: bool,
}

impl<T> OwnedBoundedJoin<T> {
    fn new() -> Self {
        Self {
            branches: BTreeMap::new(),
            attempts: Vec::new(),
            ready: Arc::new(BoundedJoinReady::default()),
            running: 0,
            max_active: 0,
            armed: true,
        }
    }

    fn insert(&mut self, gateway: &Arc<SpawnGateway>) -> usize {
        let index = self.attempts.len();
        let waker = Waker::from(Arc::new(BoundedJoinWake {
            index,
            ready: Arc::clone(&self.ready),
        }));
        self.attempts.push(empty_attempt(index));
        self.branches.insert(
            index,
            BoundedBranch {
                branch: Branch::new(index, gateway),
                closing: None,
                waker,
            },
        );
        self.max_active = self.max_active.max(self.branches.len());
        let mut candidates = self.ready.candidates.lock();
        candidates.live.insert(index);
        candidates.ready.insert(index);
        index
    }

    /// Return admission-refusal and close-unavailable observations separately.
    fn poll_slot(&mut self, index: usize, gateway: &Arc<SpawnGateway>) -> (bool, bool) {
        let slot = self
            .branches
            .get_mut(&index)
            .expect("live readiness candidate");
        let mut task = Context::from_waker(&slot.waker);
        let was_running = slot.branch.handle.is_some();
        if !slot.branch.poll_result(&mut task) {
            return (false, false);
        }
        if was_running {
            self.running -= 1;
        }
        let not_started = !slot.branch.started.load(Ordering::Acquire);
        let closing = slot.closing.get_or_insert_with(|| {
            Box::pin(close_receipt(
                Arc::clone(&slot.branch.region),
                Arc::clone(gateway),
            ))
        });
        let Poll::Ready((region_id, close)) = closing.as_mut().poll(&mut task) else {
            return (not_started, false);
        };
        let unavailable = matches!(&close, Some(Err(_)));
        slot.branch.receipt.region_id = region_id;
        slot.branch.receipt.close = close;
        {
            let mut candidates = self.ready.candidates.lock();
            candidates.live.remove(&index);
            candidates.ready.remove(&index);
        }
        let retired = self
            .branches
            .remove(&index)
            .expect("settled slot remains owned");
        // The placeholder contains no user value. No result is dropped under
        // the readiness lock, and a result needs neither Clone nor Sync.
        self.attempts[index] = retired.branch.receipt;
        (not_started, unavailable)
    }

    /// Finish a complete cancellation fanout before polling any more joins.
    fn cancel_some(&self, cancel: &mut BoundedJoinCancel, remaining: &mut usize) -> bool {
        while *remaining > 0 {
            let Some(from) = cancel.next else { return true };
            let Some((&index, slot)) = self.branches.range(from..).next() else {
                return true;
            };
            *remaining -= 1;
            cancel.next = index.checked_add(1);
            let _ = slot.branch.region.request_close(cancel.reason.clone());
            if let Some(handle) = &slot.branch.handle
                && !handle.terminal_published()
            {
                handle.abort_with_reason(cancel.reason.clone());
            }
        }
        cancel
            .next
            .is_none_or(|from| self.branches.range(from..).next().is_none())
    }

    fn request_stop(&self, reason: CancelReason) {
        let mut first_panic = None;
        for slot in self.branches.values() {
            contain_callback(&mut first_panic, || {
                let _ = slot.branch.region.request_close(reason.clone());
            });
        }
        for slot in self.branches.values() {
            if let Some(handle) = &slot.branch.handle
                && !handle.terminal_published()
            {
                contain_callback(&mut first_panic, || {
                    handle.abort_with_reason(reason.clone())
                });
            }
        }
        if let Some(payload) = first_panic {
            resume_unwind(payload);
        }
    }
}

impl<T> Drop for OwnedBoundedJoin<T> {
    fn drop(&mut self) {
        if self.armed {
            self.request_stop(CancelReason::user("bounded scoped join dropped"));
        }
    }
}

fn bounded_input_panic(payload: Box<dyn Any + Send>) -> PanicPayload {
    let message = super::scope::payload_to_string(&payload);
    // An arbitrary panic payload destructor must not interrupt subtree drain.
    std::mem::forget(payload);
    PanicPayload::new(message)
}

fn retire_bounded_input<I, F>(
    inputs: &mut Option<I>,
    unused: &mut Option<F>,
) -> Option<PanicPayload> {
    let mut first = None;
    for result in [
        catch_unwind(AssertUnwindSafe(|| drop(unused.take()))),
        catch_unwind(AssertUnwindSafe(|| drop(inputs.take()))),
    ] {
        if let Err(payload) = result {
            let panic = bounded_input_panic(payload);
            if first.is_none() {
                first = Some(panic);
            }
        }
    }
    first
}

fn owner_reason<Caps>(owner: &Cx<Caps>) -> CancelReason {
    owner.cancel_reason().unwrap_or_else(|| CancelReason::user("scoped join owner cancelled"))
}

/// Observe without acknowledging cancellation or charging the owner's budget.
fn observe_owner<Caps>(owner: &Cx<Caps>, observed: &mut Option<CancelReason>) -> bool {
    if !owner.is_cancel_requested() {
        return false;
    }
    let reason = owner_reason(owner);
    if let Some(previous) = observed {
        previous.strengthen(&reason)
    } else {
        *observed = Some(reason);
        true
    }
}

fn observe_bounded_owner<Caps>(
    owner: &Cx<Caps>,
    observed: &mut Option<CancelReason>,
    stop: &mut Option<ScopedJoinBoundedStop>,
    cancel: &mut Option<BoundedJoinCancel>,
) {
    if observe_owner(owner, observed) {
        let reason = owner_reason(owner);
        stop.get_or_insert_with(|| ScopedJoinBoundedStop::Cancelled(reason.clone()));
        *cancel = Some(BoundedJoinCancel::new(reason));
    }
}

fn record_bounded_input_panic(
    panic: PanicPayload,
    next_index: usize,
    input_panic: &mut Option<PanicPayload>,
    stop: &mut Option<ScopedJoinBoundedStop>,
    cancel: &mut Option<BoundedJoinCancel>,
) {
    input_panic.get_or_insert(panic);
    if stop.is_none() {
        *stop = Some(ScopedJoinBoundedStop::InputPanicked { next_index });
        *cancel = Some(BoundedJoinCancel::new(
            CancelReason::fail_fast().with_message("bounded scoped join input failed"),
        ));
    }
}

async fn close_receipt(
    region: Arc<BranchRegionSlot>,
    gateway: Arc<SpawnGateway>,
) -> (Option<RegionId>, Option<Result<ScopedJoinClose, ChildRegionError>>) {
    let Some(minted) = region.get() else {
        return (None, None);
    };
    let closed = RegionQuiescence::watch(minted.close_notify(), Some(gateway)).await;
    let receipt = closed.and_then(|()| {
        minted.close_outcome().map(|receipt| ScopedJoinClose {
            outcome: receipt.outcome,
            cleanup_outcome: receipt.cleanup_outcome,
            descendant_panic: receipt.descendant_panic,
        }).ok_or(ChildRegionError::RuntimeUnavailable)
    });
    (Some(minted.region_id), Some(receipt))
}

impl<Caps> Cx<Caps>
where
    Caps: cap::HasSpawn + Send + Sync + 'static,
{
    /// Lazily join any number of factories with at most `limit` active subtrees.
    ///
    /// Each input occupies its slot from being pulled through actual private
    /// region close, including pending admission, body execution, descendants,
    /// obligations and finalizers. A completed body alone never releases credit.
    /// Its subtree begins closing promptly while other bodies continue. A slot
    /// is reused only after a successful close receipt; inability to confirm
    /// close stops further pulls and remains in that input's receipt.
    ///
    /// This is all-settled: typed application errors, independent cancellation,
    /// task panics and finalizer/descendant failures remain per-input facts and
    /// do not stop other factories. Admission refusal, owner cancellation or a
    /// source panic stops pulls and requests close for EVERY active subtree
    /// before joining remaining bodies. Actual late values are retained. The
    /// selected stop is immutable; later source retirement panic and owner
    /// cancellation are separate report fields. Uncooperative cleanup can keep
    /// the call pending indefinitely, and a close error never certifies quiescence.
    ///
    /// The source is converted only after runtime preflight, then pulled only
    /// when a slot is available. Pulling precedes that input's runtime admission;
    /// admission refusal can therefore consume one factory without invoking it.
    /// The source and its iterator may borrow and need not be `Send`. Conversion,
    /// `next`, and unused-input destruction run under the explicit owner, also
    /// when the returned future is dropped before its first poll. Factories run
    /// under their actual child context. Returned values belong to the caller
    /// and must not retain obligations needed to close their own region.
    ///
    /// The input tail is never traversed after stopping. `attempts` contains only
    /// pulled inputs, and `input_exhausted` means an actual `None` was observed.
    /// The limit bounds active work, not the final report: N inputs retain O(N)
    /// receipts and values, in source order. Source storage and arbitrary nested
    /// fan-out are not memory-bounded by this limit. There is no 64-input ceiling;
    /// admission, candidate polling and ordinary cancellation fanout yield in
    /// 64-step quanta. Idle members do not cause self-wakes. Panicking executor
    /// callbacks and abort-on-panic builds retain the runtime's usual boundaries.
    ///
    /// Dropping requests all subtree closes before retiring retained values and
    /// the source, including regions published after abandonment. Drop cannot
    /// await cleanup and its cancellation fanout is synchronous. No coordinator
    /// or detached cleanup task is spawned. The result needs neither `Clone`,
    /// `Sync`, nor `Unpin`.
    ///
    /// # Errors
    /// A missing or unavailable runtime, missing spawn wiring, or denied spawn
    /// authority returns [`ScopedJoinError::Spawn`] before source conversion,
    /// including for an empty source. A pre-cancelled owner instead returns an
    /// empty cancelled report without entering the source. Empty input with an
    /// authorized live owner completes normally. After runtime preflight, source
    /// unwinds are retained in the report after draining, rather than propagated
    /// past live branches. The pre-cancelled report also retains source-drop
    /// panic. Argument destructors on a runtime-preflight error may still unwind.
    ///
    /// ```no_run
    /// # async fn example(cx: &asupersync::Cx) {
    /// use asupersync::cx::{ScopedJoinBoundedStop, ScopedJoinTask};
    /// use std::num::NonZeroUsize;
    /// let factories = (0..1_000).map(|n| move |_child| async move { n * 2 });
    /// let report = cx.join_all_scoped_bounded(
    ///     NonZeroUsize::new(8).unwrap(), factories,
    /// ).await.expect("runtime available");
    /// assert!(matches!(report.stop, ScopedJoinBoundedStop::Completed));
    /// assert!(report.input_exhausted);
    /// assert_eq!(report.attempts.len(), 1_000);
    /// assert!(matches!(report.attempts[999].task, ScopedJoinTask::Joined(Ok(1_998))));
    /// assert!(report.attempts.iter().all(|attempt| matches!(attempt.close, Some(Ok(_)))));
    /// # }
    /// ```
    pub fn join_all_scoped_bounded<T, I, F, Fut>(
        &self,
        limit: NonZeroUsize,
        factories: I,
    ) -> impl Future<Output = Result<ScopedJoinBoundedReport<T>, ScopedJoinError>>
    + use<Caps, T, I, F, Fut>
    where
        Caps: cap::CapSetRuntimeMask,
        I: IntoIterator<Item = F>,
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let owner = self.clone();
        self.with_ambient(async move {
            if owner.is_cancel_requested() {
                let reason = owner_reason(&owner);
                let input_panic = catch_unwind(AssertUnwindSafe(|| drop(factories)))
                    .err()
                    .map(bounded_input_panic);
                return Ok(ScopedJoinBoundedReport {
                    stop: ScopedJoinBoundedStop::Cancelled(reason.clone()),
                    attempts: Vec::new(),
                    input_exhausted: false,
                    input_panic,
                    max_active: 0,
                    owner_cancellation: Some(owner_reason(&owner)),
                });
            }
            let gateway = owner
                .spawn_gateway_handle()
                .filter(|gateway| gateway.is_runtime_available())
                .ok_or(ScopedJoinError::Spawn(SpawnError::RuntimeUnavailable))?;
            if !owner.runtime_mask.has(cap::CapMask::SPAWN)
                || owner.pending_spawn_counter_handle().is_none()
            {
                return Err(ScopedJoinError::Spawn(SpawnError::RuntimeUnavailable));
            }
            let mut inputs = match catch_unwind(AssertUnwindSafe(|| factories.into_iter())) {
                Ok(inputs) => Some(inputs),
                Err(payload) => {
                    return Ok(ScopedJoinBoundedReport {
                        stop: ScopedJoinBoundedStop::InputPanicked { next_index: 0 },
                        attempts: Vec::new(),
                        input_exhausted: false,
                        input_panic: Some(bounded_input_panic(payload)),
                        max_active: 0,
                        owner_cancellation: owner.cancel_reason(),
                    });
                }
            };
            // Both source containers precede the guard: abandonment cancels
            // all subtrees before either may execute arbitrary destructors.
            let mut unused = None::<F>;
            let mut owned = OwnedBoundedJoin::new();
            let mut waiter = BoundedJoinWait {
                ready: Arc::clone(&owned.ready),
                registered: None,
            };
            let mut cancelled = std::pin::pin!(owner.cancelled());
            let mut owner_cancellation = None;
            let mut stop = None;
            let mut cancel = None;
            let mut input_exhausted = false;
            let mut input_panic = None;
            let mut scan_from = 0;

            poll_fn(|task| {
                waiter.refresh(task.waker());
                let _ = cancelled.as_mut().poll(task);
                observe_bounded_owner(&owner, &mut owner_cancellation, &mut stop, &mut cancel);
                let mut remaining = BOUNDED_JOIN_QUANTUM;
                if let Some(pass) = &mut cancel {
                    if !owned.cancel_some(pass, &mut remaining) {
                        task.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    cancel = None;
                    if let Some(panic) = retire_bounded_input(&mut inputs, &mut unused) {
                        record_bounded_input_panic(
                            panic,
                            owned.attempts.len(),
                            &mut input_panic,
                            &mut stop,
                            &mut cancel,
                        );
                    }
                    observe_bounded_owner(&owner, &mut owner_cancellation, &mut stop, &mut cancel);
                }

                while cancel.is_none() && remaining > 0 {
                    let Some(index) = owned.ready.take_from(scan_from) else {
                        scan_from = 0;
                        break;
                    };
                    remaining -= 1;
                    scan_from = index.checked_add(1).unwrap_or(usize::MAX);
                    let (not_started, unavailable) = owned.poll_slot(index, &gateway);
                    observe_bounded_owner(&owner, &mut owner_cancellation, &mut stop, &mut cancel);
                    if stop.is_none() && (not_started || unavailable) {
                        stop = Some(if not_started {
                            ScopedJoinBoundedStop::NotAdmitted { index }
                        } else {
                            ScopedJoinBoundedStop::CloseUnavailable { index }
                        });
                        cancel = Some(BoundedJoinCancel::new(CancelReason::fail_fast()));
                    }
                }

                while stop.is_none()
                    && cancel.is_none()
                    && !input_exhausted
                    && owned.branches.len() < limit.get()
                    && remaining > 0
                {
                    observe_bounded_owner(&owner, &mut owner_cancellation, &mut stop, &mut cancel);
                    if stop.is_some() {
                        break;
                    }
                    remaining -= 1;
                    let next = catch_unwind(AssertUnwindSafe(|| {
                        inputs.as_mut().expect("unretired lazy source").next()
                    }));
                    match next {
                        Err(payload) => {
                            record_bounded_input_panic(
                                bounded_input_panic(payload),
                                owned.attempts.len(),
                                &mut input_panic,
                                &mut stop,
                                &mut cancel,
                            );
                            break;
                        }
                        Ok(None) => {
                            input_exhausted = true;
                            observe_bounded_owner(
                                &owner,
                                &mut owner_cancellation,
                                &mut stop,
                                &mut cancel,
                            );
                            if cancel.is_none() {
                                if let Some(panic) = retire_bounded_input(&mut inputs, &mut unused)
                                {
                                    record_bounded_input_panic(
                                        panic,
                                        owned.attempts.len(),
                                        &mut input_panic,
                                        &mut stop,
                                        &mut cancel,
                                    );
                                }
                            }
                        }
                        Ok(Some(factory)) => {
                            unused = Some(factory);
                            let index = owned.insert(&gateway);
                            observe_bounded_owner(
                                &owner,
                                &mut owner_cancellation,
                                &mut stop,
                                &mut cancel,
                            );
                            if stop.is_some() {
                                break;
                            }
                            let slot = &mut owned
                                .branches
                                .get_mut(&index)
                                .expect("guard before enqueue")
                                .branch;
                            let region = Arc::clone(&slot.region);
                            let factory_region = Arc::clone(&region);
                            let started = Arc::clone(&slot.started);
                            let factory_owner = owner.clone();
                            let factory = unused.take().expect("one pulled factory");
                            match owner.spawn_owned_branch(region, move |body| async move {
                                if factory_region.get().is_none()
                                    || factory_region.close_requested()
                                    || factory_owner.is_cancel_requested()
                                    || body.is_cancel_requested()
                                {
                                    return BodyResult::NotStarted;
                                }
                                started.store(true, Ordering::Release);
                                BodyResult::Value(factory(body).await)
                            }) {
                                Ok(handle) => {
                                    slot.handle = Some(handle);
                                    owned.running += 1;
                                }
                                Err(error) => {
                                    slot.receipt.task = ScopedJoinTask::SubmissionFailed(error);
                                    stop = Some(ScopedJoinBoundedStop::NotAdmitted { index });
                                    cancel =
                                        Some(BoundedJoinCancel::new(CancelReason::fail_fast()));
                                }
                            }
                        }
                    }
                }
                observe_bounded_owner(&owner, &mut owner_cancellation, &mut stop, &mut cancel);
                if input_exhausted && owned.running == 0 && stop.is_none() {
                    stop = Some(ScopedJoinBoundedStop::Completed);
                }
                if cancel.is_none() && stop.is_some() && owned.branches.is_empty() {
                    return Poll::Ready(());
                }
                if cancel.is_some()
                    || owned.ready.has_ready()
                    || (stop.is_none() && !input_exhausted && owned.branches.len() < limit.get())
                {
                    task.waker().wake_by_ref();
                }
                Poll::Pending
            })
            .await;
            owned.armed = false;
            Ok(ScopedJoinBoundedReport {
                stop: stop.expect("settled lazy join has a stop"),
                attempts: std::mem::take(&mut owned.attempts),
                input_exhausted,
                input_panic,
                max_active: owned.max_active,
                owner_cancellation,
            })
        })
    }

    /// Run at most 64 factories in private regions, retaining every result in
    /// input order and closing every complete subtree before returning.
    ///
    /// This is an all-settled join: an application error, independent task
    /// cancellation, or panic does not cancel other admitted factories. A
    /// returned `T` may itself be a typed `Result` or `Outcome`; it is preserved
    /// unchanged. Unlike [`Self::quorum_scoped`], there is no success threshold
    /// and no fail-fast selection. Inspect task AND close receipts: `Completed`
    /// does not mean that either the operations or their cleanup succeeded.
    ///
    /// Factories run only after strict private-region admission, with their
    /// actual typed child context. Use that context for owned descendants;
    /// captured unrelated authority stays unrelated. A completed body closes
    /// its own subtree promptly, including remaining descendants. Other bodies
    /// continue normally. Results remain retained until every task, descendant,
    /// pending admission, obligation and finalizer has crossed its barrier.
    /// Values must not retain obligations needed to close their own regions.
    ///
    /// Owner cancellation and admission refusal close ALL subtrees before
    /// joining remaining bodies, including a body joining its own child. The
    /// actual late results remain in the report. Owner cancellation is observed
    /// without acknowledgement or unmasking; cancellation observed during final
    /// cleanup is recorded separately and cannot rewrite an earlier `Completed`.
    /// No timer or forced deadline is involved. Uncooperative work may delay
    /// completion indefinitely; a close error never certifies quiescence.
    ///
    /// Dropping an unpolled call starts no work. Dropping an admitted call
    /// requests close for every private subtree, including regions published
    /// after drop. Drop cannot synchronously drain; the runtime retains that
    /// asynchronous responsibility. No detached cleanup task is spawned.
    /// Polling is bounded by the 64-input ceiling and a parked group does not
    /// self-wake. Results need not be `Clone`, `Sync`, or `Unpin`.
    ///
    /// # Errors
    /// Too many inputs or a missing runtime are refused before submission.
    /// Empty input completes without runtime authority. After submission begins,
    /// individual refusals remain in the fully drained report.
    ///
    /// ```no_run
    /// # async fn example(cx: &asupersync::Cx) {
    /// use asupersync::cx::{RaceFactory, ScopedJoinStop, ScopedJoinTask};
    /// let factories: Vec<RaceFactory<Result<u32, &'static str>>> = vec![
    ///     Box::new(|_| Box::pin(async { Ok(7) })),
    ///     Box::new(|_| Box::pin(async { Err("unavailable") })),
    /// ];
    /// let report = cx.join_all_scoped(factories).await.expect("runtime admission");
    /// assert!(matches!(report.stop, ScopedJoinStop::Completed));
    /// assert!(matches!(report.attempts[0].task, ScopedJoinTask::Joined(Ok(Ok(7)))));
    /// assert!(matches!(report.attempts[1].task, ScopedJoinTask::Joined(Ok(Err("unavailable")))));
    /// assert!(report.attempts.iter().all(|attempt| matches!(attempt.close, Some(Ok(_)))));
    /// # }
    /// ```
    pub async fn join_all_scoped<T, F, Fut>(
        &self,
        factories: Vec<F>,
    ) -> Result<ScopedJoinReport<T>, ScopedJoinError>
    where
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let total = factories.len();
        if total > MAX_SCOPED_JOIN_BRANCHES {
            return Err(ScopedJoinError::TooManyBranches { total });
        }
        if total == 0 {
            return Ok(ScopedJoinReport {
                stop: ScopedJoinStop::Completed,
                attempts: Vec::new(),
                owner_cancellation: None,
            });
        }
        let gateway = self.spawn_gateway_handle()
            .ok_or(ScopedJoinError::Spawn(SpawnError::RuntimeUnavailable))?;
        // Guard declared after the iterator: cancellation must precede unused
        // factory destructors if this future is abandoned or unwinds.
        let mut factories = factories.into_iter();
        let mut owned = OwnedJoin::new(total, &gateway);
        let mut owner_cancellation = None;
        let mut admission_stop = None;
        for index in 0..total {
            if observe_owner(self, &mut owner_cancellation) {
                admission_stop = Some(ScopedJoinStop::Cancelled(owner_reason(self)));
                break;
            }
            let factory = factories.next().expect("one factory for each input");
            let region = Arc::clone(&owned.branches[index].region);
            let factory_region = Arc::clone(&region);
            let started = Arc::clone(&owned.branches[index].started);
            let factory_owner = self.clone();
            match self.spawn_owned_branch(region, move |body| async move {
                if factory_region.get().is_none()
                    || factory_region.close_requested()
                    || factory_owner.is_cancel_requested()
                    || body.is_cancel_requested()
                {
                    return BodyResult::NotStarted;
                }
                started.store(true, Ordering::Release);
                BodyResult::Value(factory(body).await)
            }) {
                Ok(handle) => owned.branches[index].handle = Some(handle),
                Err(error) => {
                    owned.branches[index].receipt.task = ScopedJoinTask::SubmissionFailed(error);
                    admission_stop = Some(ScopedJoinStop::NotAdmitted { index });
                    break;
                }
            }
        }

        let mut cancelled = std::pin::pin!(self.cancelled());
        let stop = if observe_owner(self, &mut owner_cancellation) {
            ScopedJoinStop::Cancelled(owner_reason(self))
        } else if let Some(stop) = admission_stop {
            stop
        } else {
            poll_fn(|task| {
                if cancelled.as_mut().poll(task).is_ready() {
                    observe_owner(self, &mut owner_cancellation);
                    return Poll::Ready(ScopedJoinStop::Cancelled(owner_reason(self)));
                }
                let mut all_done = true;
                for branch in &mut owned.branches {
                    if branch.poll_result(task) {
                        if observe_owner(self, &mut owner_cancellation) {
                            return Poll::Ready(ScopedJoinStop::Cancelled(owner_reason(self)));
                        }
                        if !branch.started.load(Ordering::Acquire) {
                            return Poll::Ready(ScopedJoinStop::NotAdmitted {
                                index: branch.receipt.index,
                            });
                        }
                    } else {
                        all_done = false;
                    }
                }
                if all_done {
                    Poll::Ready(ScopedJoinStop::Completed)
                } else {
                    Poll::Pending
                }
            }).await
        };
        let reason = match &stop {
            ScopedJoinStop::Cancelled(reason) => reason.clone(),
            ScopedJoinStop::NotAdmitted { .. } => CancelReason::fail_fast(),
            ScopedJoinStop::Completed => CancelReason::user("scoped join completed"),
        };
        owned.request_stop(reason);
        // These captures can own the last sender needed by admitted cleanup.
        drop(factories);

        poll_fn(|task| {
            if cancelled.as_mut().poll(task).is_ready()
                && observe_owner(self, &mut owner_cancellation)
            {
                owned.request_stop(owner_reason(self));
            }
            let mut all_done = true;
            for branch in &mut owned.branches {
                all_done &= branch.poll_result(task);
            }
            if all_done { Poll::Ready(()) } else { Poll::Pending }
        }).await;

        // Each watch captures only the region slot, not &Branch<T>. This keeps
        // the collecting future Send even when a retained T is not Sync.
        let mut closing: Vec<_> = owned.branches.iter().map(|branch| {
            Some(Box::pin(close_receipt(Arc::clone(&branch.region), Arc::clone(&gateway))))
        }).collect();
        poll_fn(|task| {
            if cancelled.as_mut().poll(task).is_ready()
                && observe_owner(self, &mut owner_cancellation)
            {
                owned.request_stop(owner_reason(self));
            }
            let mut all_done = true;
            for (branch, pending) in owned.branches.iter_mut().zip(&mut closing) {
                if let Some(close) = pending {
                    if let Poll::Ready((region, receipt)) = close.as_mut().poll(task) {
                        branch.receipt.region_id = region;
                        branch.receipt.close = receipt;
                        *pending = None;
                    } else {
                        all_done = false;
                    }
                }
            }
            if all_done { Poll::Ready(()) } else { Poll::Pending }
        }).await;
        observe_owner(self, &mut owner_cancellation);
        owned.armed = false;
        let attempts = std::mem::take(&mut owned.branches).into_iter()
            .map(|branch| branch.receipt).collect();
        Ok(ScopedJoinReport { stop, attempts, owner_cancellation })
    }

    /// Join two differently typed factories with [`Self::join_all_scoped`]'s
    /// all-settled, per-operation subtree cleanup contract.
    ///
    /// A failed or panicked left body does not cancel the right body, or vice
    /// versa. Owner cancellation and strict admission refusal still close both
    /// subtrees before drain. This uses the same collector as the dynamic join;
    /// the typed adapter does not create a coordinator task or another region.
    pub async fn join_scoped<L, R, FL, FR, FutL, FutR>(
        &self,
        left: FL,
        right: FR,
    ) -> Result<ScopedJoinPairReport<L, R>, ScopedJoinError>
    where
        FL: FnOnce(Cx<Caps>) -> FutL + Send + 'static,
        FR: FnOnce(Cx<Caps>) -> FutR + Send + 'static,
        FutL: Future<Output = L> + Send + 'static,
        FutR: Future<Output = R> + Send + 'static,
        L: Send + 'static,
        R: Send + 'static,
    {
        let factories: Vec<PairFactory<Caps, L, R>> = vec![
            Box::new(move |cx| Box::pin(async move { PairValue::Left(left(cx).await) })),
            Box::new(move |cx| Box::pin(async move { PairValue::Right(right(cx).await) })),
        ];
        let report = self.join_all_scoped(factories).await?;
        let mut attempts = report.attempts.into_iter();
        let left = map_attempt(attempts.next().expect("left input retained"), |value| match value {
            PairValue::Left(value) => value,
            PairValue::Right(_) => unreachable!("left factory returns only a left value"),
        });
        let right = map_attempt(attempts.next().expect("right input retained"), |value| match value {
            PairValue::Right(value) => value,
            PairValue::Left(_) => unreachable!("right factory returns only a right value"),
        });
        Ok(ScopedJoinPairReport {
            stop: report.stop,
            left,
            right,
            owner_cancellation: report.owner_cancellation,
        })
    }
}

enum PairValue<L, R> { Left(L), Right(R) }

type PairFactory<Caps, L, R> = Box<
    dyn FnOnce(Cx<Caps>) -> Pin<Box<dyn Future<Output = PairValue<L, R>> + Send>> + Send,
>;

fn map_attempt<T, U>(attempt: ScopedJoinAttempt<T>, f: impl FnOnce(T) -> U) -> ScopedJoinAttempt<U> {
    let task = match attempt.task {
        ScopedJoinTask::NotStarted => ScopedJoinTask::NotStarted,
        ScopedJoinTask::SubmissionFailed(error) => ScopedJoinTask::SubmissionFailed(error),
        ScopedJoinTask::Joined(result) => ScopedJoinTask::Joined(result.map(f)),
    };
    ScopedJoinAttempt {
        index: attempt.index, task, region_id: attempt.region_id, close: attempt.close,
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "scoped_join_inline_tests.rs"]
mod tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "scoped_join_native_tests.rs"]
mod native_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "scoped_join_bounded_native_tests.rs"]
mod bounded_native_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "scoped_join_bounded_tests.rs"]
mod bounded_tests;
