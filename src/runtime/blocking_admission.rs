//! Opt-in bounded admission for the blocking pool.
//!
//! Capacity counts queued jobs across all routing queues. Running jobs do not
//! consume queue capacity. A waiting submission owns its closure until it can
//! publish it; dropping that future removes its waiter and returns no work to
//! the pool. That closure exists before admission, so it is outside the byte
//! bound below. `try_spawn_charged_with` is the admission whose payload does
//! not: it reserves first, builds the payload second, and never parks.
//!
//! [`BlockingAdmissionPolicy::BoundedBytes`] adds a second bound, on two
//! separately kept components of an admitted job's memory:
//!
//! * **closure storage**, measured by the pool: the size of the closure value
//!   that is boxed and queued, which already holds every inline capture (a
//!   large array captured by value is counted here, with no help from the
//!   submitter);
//! * **declared heap**, stated by the submitter (`try_spawn_charged`,
//!   `submit_charged`): the heap that the captures own behind pointers. The
//!   pool cannot measure it and does not estimate it, and a submission that
//!   declares nothing is refused.
//!
//! Both are reserved when the job is admitted. The reservation is owned by the
//! queued task, outside the allocation that holds the closure, and is returned
//! only after the closure, its captures and that allocation have been dropped,
//! wherever that happens: after the job ran or panicked, when a worker skips a
//! cancelled job, or when a stranded queue is detached. Cancelling a handle
//! releases nothing by itself. This is a bound on the sum of those two
//! components over live jobs; it is not a cap on the process heap (allocator
//! headers and size-class rounding, the task record and the queue node, and
//! heap shared through `Arc`s are not counted).

use super::{
    BlockingPool, BlockingPoolHandle, BlockingPoolInner, BlockingTask, BlockingTaskCompletion,
    BlockingTaskHandle, enqueue_task_locked, maybe_spawn_thread_on_inner,
};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

/// Parked submissions, keyed by the address of their waiter key.
type Waiters = Mutex<BTreeMap<usize, Waker>>;

/// Admission limit, independent of FIFO/priority selection and cohort routing.
///
/// Existing constructors and runtime builders use `Unbounded`. A bound limits
/// pending jobs across every pool queue, excluding jobs already claimed by a
/// worker. Waiting submission futures retain ownership of their work outside
/// the pool until admission succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum BlockingAdmissionPolicy {
    /// Accept queued work without a capacity limit.
    #[default]
    Unbounded,
    /// Admit at most this many queued jobs across all cohorts and the global queue.
    Bounded {
        /// Maximum queued jobs; running jobs do not count toward this limit.
        max_queued: NonZeroUsize,
    },
    /// [`Self::Bounded`], and in addition at most `max_live_bytes` over admitted jobs whose closures have not yet
    /// been dropped (queued, running, and cancelled-but-not-yet-retired jobs all count) of the SUM of two components
    /// that are kept and reported separately:
    ///
    /// * **closure storage**, measured by the pool at admission: `size_of` the closure value that is boxed and
    ///   queued, rounded up to its alignment. Every inline capture is in it, so a large array captured by value is
    ///   charged without the submitter saying anything. The sum uses checked arithmetic; an overflow is a charge
    ///   that can never fit.
    /// * **declared heap**, stated by the submitter through `try_spawn_charged` or `submit_charged`: the heap that
    ///   the captures own behind pointers (a `Vec`'s buffer, a `Box`'s contents). The pool cannot measure it, does
    ///   not estimate it and trusts the number; a job whose captures own no heap states 0.
    ///
    /// Both are reserved when the job is admitted. The reservation belongs to the queued task, outside the
    /// allocation that holds the closure, and is returned only after the closure, its captures and that
    /// allocation have been dropped, on whichever thread does that. A submission that states no declared heap
    /// (`try_spawn`, `submit`, `spawn`, and the entry points built on them) is refused with
    /// [`BlockingSpawnErrorKind::ChargeRequired`], never run inline and never admitted unaccounted; the
    /// value-returning compatibility entry points that cannot return an error panic, as they do on a
    /// [`Self::Forbidden`] pool. A total larger than `max_live_bytes` can never fit and is refused with
    /// [`BlockingSpawnErrorKind::ChargeTooLarge`]; one that merely does not fit beside the live jobs waits
    /// (`submit_charged`) or is refused with [`BlockingSpawnErrorKind::ByteBudgetSaturated`]
    /// (`try_spawn_charged`).
    ///
    /// This bounds those two components, not the process heap: allocator headers and size-class rounding, the
    /// task record and queue node (bounded by `max_queued`), and heap reached through an `Arc` shared with the
    /// submitter are not counted.
    ///
    /// A panic payload is in the pool's custody. A job that panics, or a capture whose destructor panics, hands the
    /// pool a payload that may own what the job captured, and the pool frees it before it returns the reservation.
    /// If destroying a payload itself panics, the pool cannot tell what the secondary payload kept alive, so it
    /// **pins the job's whole reservation** (storage and declared heap) for the life of the pool. Those bytes stay
    /// in [`BlockingPool::charged_bytes`] after the task is done, are reported by
    /// [`BlockingPool::quarantined_bytes`], and shrink the room every later submission sees. A submission that fits
    /// an empty pool but no longer fits beside the pinned bytes is refused with
    /// [`BlockingSpawnErrorKind::ByteBudgetQuarantined`], which waiting cannot change. A pin is conservative (it
    /// also happens when the destructor merely panicked and kept nothing), and it covers what the job captured, not
    /// memory that the failing destructor newly allocates.
    ///
    /// What this bounds is what the pool holds. A closure the caller built before calling the pool is outside it: the
    /// closure owned by a waiting [`BlockingPool::submit_charged`] future, an unpolled submission, and one handed
    /// back in a refusal all belong to their holders. [`BlockingPool::try_spawn_charged_with`] is the admission whose
    /// payload does not exist yet: it reserves the storage, the declared heap and a queue slot first, then lets the
    /// caller's factory build the payload, and never parks. It bounds what the pool admits from a caller whose factory
    /// is bounded work on bounded input; it does not bound heap the caller holds.
    ///
    /// Opt-in: nothing selects it by default.
    BoundedBytes {
        /// Maximum queued jobs, as for [`Self::Bounded`].
        max_queued: NonZeroUsize,
        /// Maximum, over admitted jobs whose closures are still alive, of closure storage plus declared heap.
        max_live_bytes: NonZeroUsize,
    },
    /// Admit nothing and start no thread: every submission is refused with
    /// [`BlockingSpawnErrorKind::Forbidden`] before its closure is accepted.
    ///
    /// For a runtime that must not run blocking work at all. A runtime built
    /// with no pool is not the same thing: its contexts see no pool, and the
    /// entry points that would otherwise run the closure inline on the calling
    /// thread, or on a dedicated fallback thread, do exactly that. A forbidden
    /// pool is inherited like any other, so those entry points can tell "no
    /// pool" from "blocking is not allowed here" and refuse. Nothing is ever
    /// queued, so no thread is ever started.
    ///
    /// It is opt-in, like `Bounded`: nothing selects it by default.
    Forbidden,
}

/// Why a blocking submission was refused before its closure was accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockingSpawnErrorKind {
    /// Every configured queue slot is occupied.
    Saturated,
    /// Pool shutdown closed admission.
    Shutdown,
    /// The pool's policy is [`BlockingAdmissionPolicy::Forbidden`]: no work is ever admitted.
    Forbidden,
    /// The pool bounds live job bytes ([`BlockingAdmissionPolicy::BoundedBytes`]) and the submission declared no
    /// heap charge.
    ChargeRequired,
    /// The job's closure storage plus its declared heap exceeds the pool's whole `max_live_bytes` (or overflows),
    /// so it can never be admitted.
    ChargeTooLarge,
    /// The job fits the pool's byte limit but not beside the bytes of jobs whose closures are still alive.
    ByteBudgetSaturated,
    /// The job fits an empty pool but not the room left once the reservations pinned for good (see
    /// [`BlockingPool::quarantined_bytes`]) are set aside, so no amount of waiting can admit it. Unlike
    /// [`Self::ChargeTooLarge`] it is about this pool's present state, not the size of the job.
    ByteBudgetQuarantined,
}

impl BlockingSpawnErrorKind {
    /// Whether waiting can turn this refusal into an admission. It cannot for a closed or a forbidden pool, nor for
    /// a submission whose charge is missing, can never fit, or no longer fits beside pinned bytes.
    const fn is_final(self) -> bool {
        matches!(
            self,
            Self::Shutdown
                | Self::Forbidden
                | Self::ChargeRequired
                | Self::ChargeTooLarge
                | Self::ByteBudgetQuarantined
        )
    }
}

/// Refused work, retaining the exact closure for retry or caller-owned disposal.
///
/// No part of the closure has run. Recovery and destruction occur outside pool
/// locks, so captured values may safely reenter the pool from `Drop`.
pub struct BlockingSpawnError<F> {
    kind: BlockingSpawnErrorKind,
    work: F,
}

impl<F> BlockingSpawnError<F> {
    /// Returns the admission failure.
    #[must_use]
    pub fn kind(&self) -> BlockingSpawnErrorKind {
        self.kind
    }

    /// Recovers the original, uninvoked closure.
    #[must_use]
    pub fn into_inner(self) -> F {
        self.work
    }
}

impl<F> fmt::Debug for BlockingSpawnError<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockingSpawnError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl<F> fmt::Display for BlockingSpawnError<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            BlockingSpawnErrorKind::Saturated => f.write_str("blocking queue is saturated"),
            BlockingSpawnErrorKind::Shutdown => f.write_str("blocking pool is shut down"),
            BlockingSpawnErrorKind::Forbidden => {
                f.write_str("blocking work is forbidden by this pool's admission policy")
            }
            BlockingSpawnErrorKind::ChargeRequired => f.write_str(
                "this pool bounds live job bytes and the submission declared no heap charge",
            ),
            BlockingSpawnErrorKind::ChargeTooLarge => {
                f.write_str("the job's bytes exceed this pool's whole live-byte limit")
            }
            BlockingSpawnErrorKind::ByteBudgetSaturated => {
                f.write_str("the pool's live-byte limit is exhausted")
            }
            BlockingSpawnErrorKind::ByteBudgetQuarantined => f.write_str(
                "the job no longer fits the pool's live-byte limit beside pinned reservations",
            ),
        }
    }
}

impl<F> std::error::Error for BlockingSpawnError<F> {}

/// Why [`BlockingPool::try_spawn_charged_with`] did not submit a job.
///
/// The factory is never handed back once it has run, so nothing here can carry it: only a refusal made before the
/// factory ran does.
#[non_exhaustive]
pub enum BlockingFactoryError<M> {
    /// Refused before the factory ran, for the reasons any charged submission is refused. The factory comes back
    /// unrun inside the error.
    Refused(BlockingSpawnError<M>),
    /// The factory panicked. The pool took the panic payload into its custody and destroyed it before it returned
    /// any reservation. The error carries no text from the payload: the panic hook has already reported it, and a
    /// copy sized by the payload would be allocated after the reservation was retired.
    FactoryPanicked {
        /// Whether destroying the payload itself panicked, so that the pool pinned the job's whole reservation for
        /// good instead of returning it (see [`BlockingAdmissionPolicy::BoundedBytes`] and
        /// [`BlockingPool::quarantined_bytes`]). Always `false` on a pool that does not bound bytes.
        quarantined: bool,
    },
    /// The pool closed between the reservation and the enqueue. The job the factory built was destroyed by the
    /// pool, under the same rules, and never ran.
    Shutdown {
        /// Whether a panic payload from destroying the built job could not itself be destroyed, so that the pool
        /// pinned the job's whole reservation for good.
        /// Always `false` on a pool that does not bound bytes.
        quarantined: bool,
    },
}

impl<M> fmt::Debug for BlockingFactoryError<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(error) => f.debug_tuple("Refused").field(&error.kind()).finish(),
            Self::FactoryPanicked { quarantined } => f
                .debug_struct("FactoryPanicked")
                .field("quarantined", quarantined)
                .finish(),
            Self::Shutdown { quarantined } => f
                .debug_struct("Shutdown")
                .field("quarantined", quarantined)
                .finish(),
        }
    }
}

impl<M> fmt::Display for BlockingFactoryError<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(error) => fmt::Display::fmt(error, f),
            Self::FactoryPanicked { quarantined: false } => {
                f.write_str("the blocking job factory panicked")
            }
            Self::FactoryPanicked { quarantined: true } => f.write_str(
                "the blocking job factory panicked and its payload could not be destroyed; \
                 the reservation is pinned",
            ),
            Self::Shutdown { quarantined: false } => {
                f.write_str("blocking pool closed while its job was being built")
            }
            Self::Shutdown { quarantined: true } => f.write_str(
                "blocking pool closed while its job was being built and the job could not be \
                 destroyed; the reservation is pinned",
            ),
        }
    }
}

impl<M> std::error::Error for BlockingFactoryError<M> {}

pub(super) struct BlockingAdmission {
    pub(super) policy: BlockingAdmissionPolicy,
    // Shared with every outstanding byte charge, so a charge released after
    // the pool handle is gone still wakes parked submitters and cannot dangle.
    waiters: Arc<Waiters>,
    // The two byte components of every admitted job whose closure is alive.
    // Raised only under the pool coordination mutex after the limit check;
    // lowered by a charge's drop, so the check can only err toward refusing.
    ledger: Arc<ByteLedger>,
    // Queue slots held for jobs whose payload is still being built
    // (`try_spawn_charged_with`). They count against `max_queued` exactly like
    // queued jobs, so the bound holds before the payload exists. Raised under
    // the pool coordination mutex after the limit check; lowered by the slot's
    // conversion into a queued job (also under it) or by its drop.
    reserved_slots: AtomicUsize,
}

/// Live bytes of a [`BlockingAdmissionPolicy::BoundedBytes`] pool, by component. Kept apart so that what the pool
/// measured is never conflated with what a submitter declared.
struct ByteLedger {
    /// Measured by the pool: closure storage.
    storage: AtomicUsize,
    /// Stated by submitters: heap owned behind the closures' pointers.
    declared: AtomicUsize,
    /// Part of `storage` plus `declared` that is pinned for good: reservations whose job left a panic payload the
    /// pool could not destroy. Those bytes stay in the two counters above, since they may still be alive; this is
    /// only how many of them can never come back. Raised before the parked submitters are woken.
    pinned: AtomicUsize,
}

impl ByteLedger {
    fn total(&self) -> usize {
        self.storage
            .load(Ordering::Acquire)
            .saturating_add(self.declared.load(Ordering::Acquire))
    }
}

/// What a submission asks the byte limit for: the two components, never added until they are compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ByteRequest {
    /// Closure storage, measured by the pool from the closure's type.
    storage: usize,
    /// Heap the submitter declared for the closure's captures.
    declared: usize,
}

impl ByteRequest {
    /// The request for a closure of type `F` that owns `declared` bytes of heap.
    pub(super) fn of<F>(declared: usize) -> Self {
        Self {
            storage: std::alloc::Layout::new::<F>().pad_to_align().size(),
            declared,
        }
    }

    /// Both components together, or `None` on overflow (which can never fit).
    fn total(self) -> Option<usize> {
        self.storage.checked_add(self.declared)
    }
}

impl BlockingAdmission {
    pub(super) fn new(policy: BlockingAdmissionPolicy) -> Self {
        Self {
            policy,
            waiters: Arc::new(Mutex::new(BTreeMap::new())),
            ledger: Arc::new(ByteLedger {
                storage: AtomicUsize::new(0),
                declared: AtomicUsize::new(0),
                pinned: AtomicUsize::new(0),
            }),
            reserved_slots: AtomicUsize::new(0),
        }
    }

    /// Queued jobs plus the slots reserved for jobs still being built: what the queue bound counts.
    fn queued_or_reserved(&self, inner: &BlockingPoolInner) -> usize {
        inner
            .pending_count
            .load(Ordering::Acquire)
            .saturating_add(self.reserved_slots.load(Ordering::Acquire))
    }

    /// Called under the pool coordination mutex for definitive admission.
    ///
    /// `request` is what the submission asks of the byte limit; `None` is a submission that declared no heap.
    pub(super) fn refusal(
        &self,
        inner: &BlockingPoolInner,
        request: Option<ByteRequest>,
    ) -> Option<BlockingSpawnErrorKind> {
        // First, so a forbidden pool never reports `Shutdown`: that refusal hands the closure back, and the
        // async entry points then run a handed-back closure inline.
        if self.policy == BlockingAdmissionPolicy::Forbidden {
            return Some(BlockingSpawnErrorKind::Forbidden);
        }
        // Second, for the same reason: a missing or impossible charge is a decision about the submission, so it
        // must not be reported as `Shutdown` either.
        if let BlockingAdmissionPolicy::BoundedBytes { max_live_bytes, .. } = self.policy {
            match request {
                None => return Some(BlockingSpawnErrorKind::ChargeRequired),
                Some(request) => {
                    // An overflowing sum can never fit, exactly like one over the limit.
                    if request
                        .total()
                        .is_none_or(|total| total > max_live_bytes.get())
                    {
                        return Some(BlockingSpawnErrorKind::ChargeTooLarge);
                    }
                    // Pinned bytes never come back, so room that is gone for good is not a reason to wait. A job
                    // that fits an empty pool but not what is left of it is refused for good, with its own reason:
                    // `ChargeTooLarge` stays about the job's own size.
                    let room = max_live_bytes
                        .get()
                        .saturating_sub(self.ledger.pinned.load(Ordering::Acquire));
                    if request.total().is_none_or(|total| total > room) {
                        return Some(BlockingSpawnErrorKind::ByteBudgetQuarantined);
                    }
                }
            }
        }
        if inner.shutdown.load(Ordering::Acquire) {
            return Some(BlockingSpawnErrorKind::Shutdown);
        }
        match self.policy {
            BlockingAdmissionPolicy::Bounded { max_queued } => {
                if self.queued_or_reserved(inner) >= max_queued.get() {
                    return Some(BlockingSpawnErrorKind::Saturated);
                }
            }
            BlockingAdmissionPolicy::BoundedBytes {
                max_queued,
                max_live_bytes,
            } => {
                if self.queued_or_reserved(inner) >= max_queued.get() {
                    return Some(BlockingSpawnErrorKind::Saturated);
                }
                // The request was checked above to fit the whole limit, so only the live jobs can refuse it.
                let fits = request
                    .and_then(ByteRequest::total)
                    .and_then(|total| self.ledger.total().checked_add(total))
                    .is_some_and(|total| total <= max_live_bytes.get());
                if !fits {
                    return Some(BlockingSpawnErrorKind::ByteBudgetSaturated);
                }
            }
            BlockingAdmissionPolicy::Unbounded | BlockingAdmissionPolicy::Forbidden => {}
        }
        None
    }

    /// Reserves `request` for an admitted job. Call only under the pool coordination mutex, right after
    /// [`Self::refusal`] returned `None` for the same request. The caller owns the returned reservation until the
    /// job's closure and its allocation have been dropped.
    fn reserve(&self, request: ByteRequest) -> ByteCharge {
        self.ledger
            .storage
            .fetch_add(request.storage, Ordering::AcqRel);
        self.ledger
            .declared
            .fetch_add(request.declared, Ordering::AcqRel);
        ByteCharge {
            waiters: Arc::clone(&self.waiters),
            ledger: Arc::clone(&self.ledger),
            request,
        }
    }

    /// Whether this pool tracks bytes at all.
    fn counts_bytes(&self) -> bool {
        matches!(self.policy, BlockingAdmissionPolicy::BoundedBytes { .. })
    }

    /// Closure storage plus declared heap of admitted jobs whose closures are still alive, and of the reservations
    /// pinned for good (see [`Self::quarantined_bytes`]).
    pub(super) fn charged_bytes(&self) -> usize {
        self.ledger.total()
    }

    /// The part of [`Self::charged_bytes`] pinned for good: reservations of jobs whose panic payload the pool could
    /// not destroy.
    pub(super) fn quarantined_bytes(&self) -> usize {
        self.ledger.pinned.load(Ordering::Acquire)
    }

    /// The pool-measured component of [`Self::charged_bytes`]: closure storage.
    pub(super) fn charged_storage_bytes(&self) -> usize {
        self.ledger.storage.load(Ordering::Acquire)
    }

    /// The submitter-stated component of [`Self::charged_bytes`]: declared heap.
    pub(super) fn charged_declared_bytes(&self) -> usize {
        self.ledger.declared.load(Ordering::Acquire)
    }

    /// Dispatch outside every pool lock. A bad waker must not kill the worker
    /// that has just claimed a job, leak its busy count, or strand other waiters.
    pub(super) fn notify(&self) {
        if self.policy == BlockingAdmissionPolicy::Unbounded {
            return;
        }
        wake_all(&self.waiters);
    }

    fn remove(&self, id: usize) {
        let retired = self.waiters.lock().remove(&id);
        drop(retired);
    }
}

/// Wakes every parked submission, outside the waiter mutex.
fn wake_all(waiters: &Waiters) {
    let parked = std::mem::take(&mut *waiters.lock());
    for (_, waker) in parked {
        if let Err(payload) =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || waker.wake()))
        {
            // An opaque panic payload can itself panic on destruction.
            // Work and the remaining wakeups must still make progress.
            std::mem::forget(payload);
        }
    }
}

/// Bytes reserved against a [`BlockingAdmissionPolicy::BoundedBytes`] pool for one admitted job. Dropping it
/// returns the bytes and wakes parked submitters, without touching the pool coordination mutex.
///
/// It is owned by the queued task, never by the closure it accounts for: the closure sits in a heap allocation
/// that is freed only after the closure has been dropped, and a reservation held inside that allocation would be
/// returned while the allocation still exists. See [`BlockingTask`].
pub(super) struct ByteCharge {
    waiters: Arc<Waiters>,
    ledger: Arc<ByteLedger>,
    request: ByteRequest,
}

impl ByteCharge {
    /// Pins this reservation for good, then releases the charge.
    ///
    /// For a job whose panic payload the pool could not destroy: the payload may still own what the job captured, so
    /// the bytes may still be alive and must stay in the live counters. This records them as pinned and zeroes the
    /// request, so the drop at the end of this method subtracts nothing and only wakes the parked submitters, who now
    /// see the pin. The pinned count is raised first and saturates; it cannot exceed the live counters, which the
    /// limit bounds. The charge's `Arc`s are dropped normally.
    pub(super) fn quarantine(mut self) {
        let total = self.request.total().unwrap_or(usize::MAX);
        let _ = self
            .ledger
            .pinned
            .try_update(Ordering::AcqRel, Ordering::Acquire, |pinned| {
                Some(pinned.saturating_add(total))
            });
        self.request = ByteRequest {
            storage: 0,
            declared: 0,
        };
    }
}

impl Drop for ByteCharge {
    fn drop(&mut self) {
        self.ledger
            .storage
            .fetch_sub(self.request.storage, Ordering::AcqRel);
        self.ledger
            .declared
            .fetch_sub(self.request.declared, Ordering::AcqRel);
        wake_all(&self.waiters);
    }
}

fn try_spawn<F>(
    inner: &Arc<BlockingPoolInner>,
    work: F,
    priority: u8,
    preferred_cohort: Option<usize>,
    declared: Option<usize>,
) -> Result<BlockingTaskHandle, BlockingSpawnError<F>>
where
    F: FnOnce() + Send + 'static,
{
    let request = declared.map(ByteRequest::of::<F>);
    let guard = inner.mutex.lock();
    if let Some(kind) = inner.admission.refusal(inner, request) {
        drop(guard);
        return Err(BlockingSpawnError { kind, work });
    }
    // Reserve under the same mutex that checked the limit, so concurrent
    // submitters cannot jointly pass a check that none of them passes alone.
    // The reservation precedes the allocation it accounts for and is returned
    // only after that allocation is freed (it travels in the task, not in the
    // closure). A pool that does not bound bytes ignores a declared charge.
    let charge = request
        .filter(|_| inner.admission.counts_bytes())
        .map(|request| inner.admission.reserve(request));
    let work: Box<dyn FnOnce() + Send + 'static> = Box::new(work);
    let cancelled = Arc::new(AtomicBool::new(false));
    let completion = Arc::new(BlockingTaskCompletion::new(inner.time_getter));
    let handle = BlockingTaskHandle {
        task_id: inner.next_task_id.fetch_add(1, Ordering::Relaxed),
        cancelled: Arc::clone(&cancelled),
        completion: Arc::clone(&completion),
    };
    enqueue_task_locked(
        inner,
        BlockingTask {
            work,
            priority,
            preferred_cohort,
            cancelled,
            completion,
            charge,
        },
    );
    drop(guard);
    maybe_spawn_thread_on_inner(inner);
    {
        let _guard = inner.mutex.lock();
        inner.condvar.notify_one();
    }
    Ok(handle)
}

/// A queue slot held for a job whose payload is still being built.
///
/// Raised under the pool coordination mutex, together with the byte reservation, and lowered either by
/// [`Self::convert_locked`] when the built job is enqueued (under the same mutex, so the queue bound never sees a
/// gap) or by its drop on every other exit, which also wakes the parked submitters the slot was keeping out.
struct ReservedSlot<'a> {
    inner: &'a BlockingPoolInner,
    held: bool,
}

impl<'a> ReservedSlot<'a> {
    /// The caller holds the pool coordination mutex and has just passed [`BlockingAdmission::refusal`].
    fn take_locked(inner: &'a BlockingPoolInner) -> Self {
        inner
            .admission
            .reserved_slots
            .fetch_add(1, Ordering::AcqRel);
        Self { inner, held: true }
    }

    /// The caller holds the pool coordination mutex and is about to enqueue the job this slot was held for.
    fn convert_locked(mut self) {
        self.inner
            .admission
            .reserved_slots
            .fetch_sub(1, Ordering::AcqRel);
        self.held = false;
    }
}

impl Drop for ReservedSlot<'_> {
    fn drop(&mut self) {
        if self.held {
            self.inner
                .admission
                .reserved_slots
                .fetch_sub(1, Ordering::AcqRel);
            self.inner.admission.notify();
        }
    }
}

/// Admits a job whose payload does not exist yet, builds it, and enqueues it.
///
/// Both halves of the job's reservation, the byte charge (closure storage measured from `F`, plus the declared heap)
/// and one queue slot, are taken under the pool coordination mutex BEFORE `make` runs, so a payload can only exist
/// while it is reserved. `make` then runs outside every lock, under `catch_unwind`, on the calling thread. It does not
/// need to be `Send` or `'static`: it can borrow the caller's bounded input, which is the point.
///
/// A payload is never handed back once built. If `make` panics, its payload is destroyed in the pool's custody and the
/// reservation returns only if that succeeded (else it is pinned, as for a job's own panic payload). If the pool
/// closed meanwhile, the built job is destroyed the same way. Either way the slot and the charge are released on
/// every path, by guards declared before the payload so they outlive it.
fn try_spawn_with<M, F>(
    inner: &Arc<BlockingPoolInner>,
    declared: usize,
    make: M,
    priority: u8,
    preferred_cohort: Option<usize>,
) -> Result<BlockingTaskHandle, BlockingFactoryError<M>>
where
    M: FnOnce() -> F,
    F: FnOnce() + Send + 'static,
{
    let request = ByteRequest::of::<F>(declared);
    let (charge, slot) = {
        let guard = inner.mutex.lock();
        if let Some(kind) = inner.admission.refusal(inner, Some(request)) {
            drop(guard);
            return Err(BlockingFactoryError::Refused(BlockingSpawnError {
                kind,
                work: make,
            }));
        }
        // Reserved under the mutex that checked the limits, like `try_spawn`; the payload does not exist yet.
        let charge = inner
            .admission
            .counts_bytes()
            .then(|| inner.admission.reserve(request));
        (charge, ReservedSlot::take_locked(inner))
    };

    let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(make));
    let work = match built {
        Ok(work) => work,
        Err(payload) => {
            let resolved = super::discard_panic_payload(payload);
            // Pinned only if there is a reservation to pin: a pool that does not bound bytes holds none.
            let quarantined = !resolved && charge.is_some();
            super::retire_charge(charge, resolved);
            drop(slot);
            return Err(BlockingFactoryError::FactoryPanicked { quarantined });
        }
    };

    let work: Box<dyn FnOnce() + Send + 'static> = Box::new(work);
    let cancelled = Arc::new(AtomicBool::new(false));
    let completion = Arc::new(BlockingTaskCompletion::new(inner.time_getter));
    let handle = BlockingTaskHandle {
        task_id: inner.next_task_id.fetch_add(1, Ordering::Relaxed),
        cancelled: Arc::clone(&cancelled),
        completion: Arc::clone(&completion),
    };
    let task = BlockingTask {
        work,
        priority,
        preferred_cohort,
        cancelled,
        completion,
        charge,
    };

    let guard = inner.mutex.lock();
    if inner.shutdown.load(Ordering::Acquire) {
        drop(guard);
        // The pool closed after the reservation. The job exists and is reserved: destroy it in custody and only then
        // let the reservation go, as a worker does for a job it skips.
        let BlockingTask { work, charge, .. } = task;
        let resolved = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            drop(work);
        })) {
            Ok(()) => true,
            Err(payload) => super::discard_panic_payload(payload),
        };
        let quarantined = !resolved && charge.is_some();
        super::retire_charge(charge, resolved);
        drop(slot);
        return Err(BlockingFactoryError::Shutdown { quarantined });
    }
    slot.convert_locked();
    enqueue_task_locked(inner, task);
    drop(guard);
    maybe_spawn_thread_on_inner(inner);
    {
        let _guard = inner.mutex.lock();
        inner.condvar.notify_one();
    }
    Ok(handle)
}

/// An owned submission that waits asynchronously for queue capacity.
///
/// The closure is never invoked on the polling thread. Saturation parks the
/// future; shutdown, and a [`BlockingAdmissionPolicy::Forbidden`] pool, return
/// the original work in `BlockingSpawnError` at once.
/// Dropping a pending future unregisters its waker and drops its unsubmitted
/// closure on the dropping thread. No slot and no declared byte is reserved
/// while it is waiting.
///
/// Cancellation is by dropping this future. Region-owned drained blocking work
/// additionally keeps a cancelled envelope alive until a worker can retire its
/// captures. Queue selection priority applies after admission; waiting
/// submitters compete for released capacity without a fairness guarantee.
#[must_use = "blocking work is not submitted unless the future is polled"]
pub struct BlockingSubmission<F> {
    pool: BlockingPoolHandle,
    work: Option<F>,
    priority: u8,
    preferred_cohort: Option<usize>,
    // Heap the submitter declared for the captures; reserved (with the closure's
    // storage) only at admission.
    declared: Option<usize>,
    // Allocated only if this submission must wait. Its stable, live allocation
    // is a unique key even after arbitrarily many waiter registrations.
    waiter_key: Option<Box<u8>>,
}

// The closure is stored but never structurally pinned or polled.
impl<F> Unpin for BlockingSubmission<F> {}

impl<F> fmt::Debug for BlockingSubmission<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockingSubmission")
            .field("pending", &self.work.is_some())
            .field("priority", &self.priority)
            .field("preferred_cohort", &self.preferred_cohort)
            .field("declared", &self.declared)
            .finish_non_exhaustive()
    }
}

impl<F> BlockingSubmission<F> {
    fn remove_waiter(&self) {
        if let Some(key) = self.waiter_key.as_ref() {
            self.pool
                .inner
                .admission
                .remove(std::ptr::from_ref(key.as_ref()).addr());
        }
    }

    fn new(
        pool: BlockingPoolHandle,
        work: F,
        priority: u8,
        preferred_cohort: Option<usize>,
        declared: Option<usize>,
    ) -> Self {
        Self {
            pool,
            work: Some(work),
            priority,
            preferred_cohort,
            declared,
            waiter_key: None,
        }
    }
}

impl<F> Future for BlockingSubmission<F>
where
    F: FnOnce() + Send + 'static,
{
    type Output = Result<BlockingTaskHandle, BlockingSpawnError<F>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let work = this
            .work
            .take()
            .expect("blocking submission polled after completion");
        match try_spawn(
            &this.pool.inner,
            work,
            this.priority,
            this.preferred_cohort,
            this.declared,
        ) {
            Ok(handle) => {
                this.remove_waiter();
                return Poll::Ready(Ok(handle));
            }
            Err(error) if error.kind.is_final() => {
                this.remove_waiter();
                return Poll::Ready(Err(error));
            }
            Err(error) => this.work = Some(error.into_inner()),
        }

        // Prepare and retire RawWakers outside the waiter mutex: either
        // callback may reenter pool admission.
        let key = this.waiter_key.get_or_insert_with(|| Box::new(0));
        let waiter_id = std::ptr::from_ref(key.as_ref()).addr();
        let incoming = cx.waker().clone();
        let retired = this
            .pool
            .inner
            .admission
            .waiters
            .lock()
            .insert(waiter_id, incoming);
        drop(retired);

        // A worker can free the last slot before registration. Retry after
        // publishing our waker so that either we claim capacity now or a
        // later dequeue/shutdown wakes us. There is no wake-under-lock path.
        let work = this
            .work
            .take()
            .expect("waiting submission retains its closure");
        match try_spawn(
            &this.pool.inner,
            work,
            this.priority,
            this.preferred_cohort,
            this.declared,
        ) {
            Ok(handle) => {
                this.remove_waiter();
                Poll::Ready(Ok(handle))
            }
            Err(error) if error.kind.is_final() => {
                this.remove_waiter();
                Poll::Ready(Err(error))
            }
            Err(error) => {
                this.work = Some(error.into_inner());
                Poll::Pending
            }
        }
    }
}

impl<F> Drop for BlockingSubmission<F> {
    fn drop(&mut self) {
        self.remove_waiter();
    }
}

impl BlockingPool {
    /// Returns the admission policy selected when the pool was constructed.
    #[must_use]
    pub fn admission_policy(&self) -> BlockingAdmissionPolicy {
        self.inner.admission.policy
    }

    /// Attempts submission, returning ownership on saturation or shutdown.
    pub fn try_spawn<F>(&self, work: F) -> Result<BlockingTaskHandle, BlockingSpawnError<F>>
    where
        F: FnOnce() + Send + 'static,
    {
        try_spawn(&self.inner, work, 128, None, None)
    }

    /// Attempts submission with an explicit selection priority.
    pub fn try_spawn_with_priority<F>(
        &self,
        work: F,
        priority: u8,
    ) -> Result<BlockingTaskHandle, BlockingSpawnError<F>>
    where
        F: FnOnce() + Send + 'static,
    {
        try_spawn(&self.inner, work, priority, None, None)
    }

    /// Attempts submission with a cohort hint and explicit selection priority.
    pub fn try_spawn_on_cohort_with_priority<F>(
        &self,
        cohort: usize,
        work: F,
        priority: u8,
    ) -> Result<BlockingTaskHandle, BlockingSpawnError<F>>
    where
        F: FnOnce() + Send + 'static,
    {
        try_spawn(&self.inner, work, priority, Some(cohort), None)
    }

    /// Waits asynchronously for capacity without running work on the caller.
    pub fn submit<F>(&self, work: F) -> BlockingSubmission<F>
    where
        F: FnOnce() + Send + 'static,
    {
        BlockingSubmission::new(self.handle(), work, 128, None, None)
    }

    /// Attempts submission of a closure whose captures own `declared_heap_bytes` of heap behind their pointers
    /// (0 if none), returning ownership on refusal.
    ///
    /// On a [`BlockingAdmissionPolicy::BoundedBytes`] pool the closure's own storage (measured) and the declared
    /// heap (trusted) are reserved when the job is admitted and returned after the closure and its allocation
    /// have been dropped. On any other pool the declaration is not tracked and this behaves as
    /// [`Self::try_spawn`].
    pub fn try_spawn_charged<F>(
        &self,
        work: F,
        declared_heap_bytes: usize,
    ) -> Result<BlockingTaskHandle, BlockingSpawnError<F>>
    where
        F: FnOnce() + Send + 'static,
    {
        try_spawn(&self.inner, work, 128, None, Some(declared_heap_bytes))
    }

    /// Reserves room for a job, THEN builds it with `make`, then enqueues it, without ever parking.
    ///
    /// [`Self::try_spawn_charged`] takes a job that already exists, so a caller that must copy its input to build the
    /// job has already materialized the payload when the pool refuses it. Here the closure storage (measured from the
    /// type `F`), the `declared_heap_bytes` that `make` will allocate, and one queue slot are all reserved first, under
    /// the pool's mutex, by the same checks as `try_spawn_charged`. A payload therefore exists only while it is
    /// reserved, and a refusal costs the caller nothing: `make` is not called and comes back inside
    /// [`BlockingFactoryError::Refused`].
    ///
    /// `make` runs on the calling thread, outside every lock, with the reservation held, and does not need to be
    /// `Send` or `'static`: it can borrow the caller's input. Its panic is contained. The panic payload is destroyed
    /// by the pool before any reservation returns, and if destroying it panics too, the whole reservation is pinned
    /// (see [`BlockingAdmissionPolicy::BoundedBytes`]); the caller gets [`BlockingFactoryError::FactoryPanicked`],
    /// which says whether that happened and carries no text from the payload. If the pool closes before the job is
    /// enqueued, the built job is destroyed the same way, outside every pool lock, and the caller gets
    /// [`BlockingFactoryError::Shutdown`]. The built job is never handed back.
    ///
    /// # Shutdown
    ///
    /// [`BlockingPool::shutdown_and_wait`] waits for queued and running jobs and for the workers, not for callers
    /// still inside `make`: a caller that is mid-factory when the pool closes keeps its reservation and its slot until
    /// `make` returns, then finds the pool closed and destroys the job it built unrun. Once the pool is closed, no
    /// new submission is admitted, whether or not such a caller is still running.
    ///
    /// # Contract
    ///
    /// `make` must be bounded work on bounded input (typically one copy of a slice the caller already holds): it runs
    /// on the calling thread while the reservation is held, and the pool cannot check that what it allocates is what
    /// `declared_heap_bytes` states, as for any declared heap. This bounds what the pool admits. It does not bound
    /// heap the caller holds, and it does not change [`Self::submit_charged`], whose waiting future still owns its
    /// closure.
    ///
    /// On a pool that does not bound bytes the declaration is ignored, the queue slot still counts against a
    /// [`BlockingAdmissionPolicy::Bounded`] limit, and a [`BlockingAdmissionPolicy::Forbidden`] pool refuses before
    /// `make` runs.
    ///
    /// # Errors
    ///
    /// See [`BlockingFactoryError`].
    pub fn try_spawn_charged_with<M, F>(
        &self,
        declared_heap_bytes: usize,
        make: M,
    ) -> Result<BlockingTaskHandle, BlockingFactoryError<M>>
    where
        M: FnOnce() -> F,
        F: FnOnce() + Send + 'static,
    {
        try_spawn_with(&self.inner, declared_heap_bytes, make, 128, None)
    }

    /// Waits asynchronously for queue capacity and, on a [`BlockingAdmissionPolicy::BoundedBytes`] pool, for room
    /// in the live-byte limit, without running work on the caller. Nothing is reserved while it waits.
    pub fn submit_charged<F>(&self, work: F, declared_heap_bytes: usize) -> BlockingSubmission<F>
    where
        F: FnOnce() + Send + 'static,
    {
        BlockingSubmission::new(self.handle(), work, 128, None, Some(declared_heap_bytes))
    }

    /// Closure storage plus declared heap of admitted jobs whose closures are still alive: queued, running, and
    /// cancelled jobs not yet retired. Always 0 unless the policy is [`BlockingAdmissionPolicy::BoundedBytes`].
    ///
    /// It also counts the reservations pinned for good ([`Self::quarantined_bytes`]), so it can stay above 0 after
    /// every task is done.
    #[must_use]
    pub fn charged_bytes(&self) -> usize {
        self.inner.admission.charged_bytes()
    }

    /// The part of [`Self::charged_bytes`] that can never come back: the whole reservations of jobs whose panic
    /// payload could not be destroyed, kept because the payload may still own what the job captured. Always 0
    /// unless the policy is [`BlockingAdmissionPolicy::BoundedBytes`] and such a payload occurred.
    #[must_use]
    pub fn quarantined_bytes(&self) -> usize {
        self.inner.admission.quarantined_bytes()
    }

    /// The pool-measured component of [`Self::charged_bytes`]: the storage of the live jobs' closures.
    #[must_use]
    pub fn charged_storage_bytes(&self) -> usize {
        self.inner.admission.charged_storage_bytes()
    }

    /// The submitter-stated component of [`Self::charged_bytes`]: heap declared for the live jobs' captures.
    #[must_use]
    pub fn charged_declared_bytes(&self) -> usize {
        self.inner.admission.charged_declared_bytes()
    }

    /// Waits for capacity, then enqueues with the supplied selection priority.
    pub fn submit_with_priority<F>(&self, work: F, priority: u8) -> BlockingSubmission<F>
    where
        F: FnOnce() + Send + 'static,
    {
        BlockingSubmission::new(self.handle(), work, priority, None, None)
    }

    /// Waits for capacity, then routes with a cohort hint and selection priority.
    pub fn submit_on_cohort_with_priority<F>(
        &self,
        cohort: usize,
        work: F,
        priority: u8,
    ) -> BlockingSubmission<F>
    where
        F: FnOnce() + Send + 'static,
    {
        BlockingSubmission::new(self.handle(), work, priority, Some(cohort), None)
    }
}

impl BlockingPoolHandle {
    /// Returns the admission policy selected when the pool was constructed.
    #[must_use]
    pub fn admission_policy(&self) -> BlockingAdmissionPolicy {
        self.inner.admission.policy
    }

    /// Whether this pool admits no work at all ([`BlockingAdmissionPolicy::Forbidden`]).
    ///
    /// The entry points that fall back to running a closure inline, or on a dedicated thread, when there is no
    /// pool check this first: a forbidden pool is a decision, not an absence.
    #[must_use]
    pub(crate) fn forbids_blocking(&self) -> bool {
        self.inner.admission.policy == BlockingAdmissionPolicy::Forbidden
    }

    /// Attempts submission, returning ownership on saturation or shutdown.
    pub fn try_spawn<F>(&self, work: F) -> Result<BlockingTaskHandle, BlockingSpawnError<F>>
    where
        F: FnOnce() + Send + 'static,
    {
        try_spawn(&self.inner, work, 128, None, None)
    }

    /// Attempts submission with an explicit selection priority.
    pub fn try_spawn_with_priority<F>(
        &self,
        work: F,
        priority: u8,
    ) -> Result<BlockingTaskHandle, BlockingSpawnError<F>>
    where
        F: FnOnce() + Send + 'static,
    {
        try_spawn(&self.inner, work, priority, None, None)
    }

    /// Attempts submission with a cohort hint and explicit selection priority.
    pub fn try_spawn_on_cohort_with_priority<F>(
        &self,
        cohort: usize,
        work: F,
        priority: u8,
    ) -> Result<BlockingTaskHandle, BlockingSpawnError<F>>
    where
        F: FnOnce() + Send + 'static,
    {
        try_spawn(&self.inner, work, priority, Some(cohort), None)
    }

    /// Waits asynchronously for capacity without running work on the caller.
    pub fn submit<F>(&self, work: F) -> BlockingSubmission<F>
    where
        F: FnOnce() + Send + 'static,
    {
        BlockingSubmission::new(self.clone(), work, 128, None, None)
    }

    /// Attempts submission of a closure whose captures own `declared_heap_bytes` of heap behind their pointers
    /// (0 if none), returning ownership on refusal.
    ///
    /// See [`BlockingPool::try_spawn_charged`].
    pub fn try_spawn_charged<F>(
        &self,
        work: F,
        declared_heap_bytes: usize,
    ) -> Result<BlockingTaskHandle, BlockingSpawnError<F>>
    where
        F: FnOnce() + Send + 'static,
    {
        try_spawn(&self.inner, work, 128, None, Some(declared_heap_bytes))
    }

    /// Reserves room for a job, then builds it with `make`, then enqueues it, without parking.
    ///
    /// See [`BlockingPool::try_spawn_charged_with`].
    pub fn try_spawn_charged_with<M, F>(
        &self,
        declared_heap_bytes: usize,
        make: M,
    ) -> Result<BlockingTaskHandle, BlockingFactoryError<M>>
    where
        M: FnOnce() -> F,
        F: FnOnce() + Send + 'static,
    {
        try_spawn_with(&self.inner, declared_heap_bytes, make, 128, None)
    }

    /// Waits for queue capacity and live-byte room without running work on the caller.
    ///
    /// See [`BlockingPool::submit_charged`].
    pub fn submit_charged<F>(&self, work: F, declared_heap_bytes: usize) -> BlockingSubmission<F>
    where
        F: FnOnce() + Send + 'static,
    {
        BlockingSubmission::new(self.clone(), work, 128, None, Some(declared_heap_bytes))
    }

    /// Closure storage plus declared heap of live jobs and of pinned reservations; see
    /// [`BlockingPool::charged_bytes`].
    #[must_use]
    pub fn charged_bytes(&self) -> usize {
        self.inner.admission.charged_bytes()
    }

    /// The pinned part of [`Self::charged_bytes`]; see [`BlockingPool::quarantined_bytes`].
    #[must_use]
    pub fn quarantined_bytes(&self) -> usize {
        self.inner.admission.quarantined_bytes()
    }

    /// The pool-measured component of [`Self::charged_bytes`]: closure storage.
    #[must_use]
    pub fn charged_storage_bytes(&self) -> usize {
        self.inner.admission.charged_storage_bytes()
    }

    /// The submitter-stated component of [`Self::charged_bytes`]: declared heap.
    #[must_use]
    pub fn charged_declared_bytes(&self) -> usize {
        self.inner.admission.charged_declared_bytes()
    }

    /// Waits for capacity, then enqueues with the supplied selection priority.
    pub fn submit_with_priority<F>(&self, work: F, priority: u8) -> BlockingSubmission<F>
    where
        F: FnOnce() + Send + 'static,
    {
        BlockingSubmission::new(self.clone(), work, priority, None, None)
    }

    /// Waits for capacity, then routes with a cohort hint and selection priority.
    pub fn submit_on_cohort_with_priority<F>(
        &self,
        cohort: usize,
        work: F,
        priority: u8,
    ) -> BlockingSubmission<F>
    where
        F: FnOnce() + Send + 'static,
    {
        BlockingSubmission::new(self.clone(), work, priority, Some(cohort), None)
    }
}

#[cfg(test)]
#[path = "blocking_admission_inline_tests.rs"]
mod tests;
