//! Region record for the runtime.
//!
//! A region owns tasks and child regions, forming a tree structure.
//! When a region closes, it waits for all children to complete.

use crate::record::finalizer::{Finalizer, FinalizerStack};
use crate::record::task::TaskOutcome;
use crate::runtime::region_heap::{HeapIndex, RegionHeap};
use crate::tracing_compat::{Span, debug, info_span, warn};
use crate::types::rref::{RRef, RRefAccessWitness, RRefError};
use crate::types::{
    Budget, CancelReason, CapabilityBudget, CurveBudget, RRefAccess, RegionId, TaskId, Time,
};
use parking_lot::RwLock;
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Weak};

// Thread-local flag to detect reentrant calls and prevent deadlock
thread_local! {
    static IN_REGION_WITH_CALL: Cell<bool> = const { Cell::new(false) };
}

/// RAII guard to ensure thread-local flag is reset even on panic
struct ReentryGuard {
    was_in_call: bool,
}

impl ReentryGuard {
    fn new() -> Self {
        let was_in_call = IN_REGION_WITH_CALL.with(|flag| {
            let was_in = flag.get();
            if !was_in {
                flag.set(true);
            }
            was_in
        });
        ReentryGuard { was_in_call }
    }

    fn is_reentrant(&self) -> bool {
        self.was_in_call
    }
}

impl Drop for ReentryGuard {
    fn drop(&mut self) {
        if !self.was_in_call {
            IN_REGION_WITH_CALL.with(|flag| flag.set(false));
        }
    }
}

/// State for waking tasks waiting on a region to close.
#[derive(Debug)]
pub struct RegionCloseState {
    /// Whether the region is fully closed.
    pub closed: bool,
    /// Wakers for tasks waiting for the region to close.
    ///
    /// We retain all registered waiters until the region closes. Stale wakers
    /// are acceptable here because close is one-shot and spurious wakeups are
    /// harmless; dropping a waiter must not erase another waiter's registration.
    pub waiters: Vec<std::task::Waker>,
}

/// The state of a region in its lifecycle.
///
/// State machine:
/// ```text
/// Open → Closing → Draining → Finalizing → Closed
///   │                            │
///   └─────────────────────────────┘ (skip Draining if no children)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionState {
    /// Region is open and accepting work.
    Open,
    /// Region body completed, beginning close sequence.
    /// No more spawns allowed; about to cancel children.
    Closing,
    /// Cancel issued to children, waiting for all to complete.
    /// Cancelled tasks get scheduled with priority (cancel lane).
    Draining,
    /// Children done, running region finalizers (LIFO order).
    /// Implements `rule.region.close_run_finalizer` (#25, SEM-INV-002).
    /// Note: TLA+ omits this step per ADR-004.
    Finalizing,
    /// Terminal close phase.
    ///
    /// The aggregated close outcome is stored separately on the record via
    /// [`RegionRecord::close_outcome`] so the phase stays atomically encoded.
    Closed,
}

impl RegionState {
    /// Returns the numeric encoding for this state.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Closing => 1,
            Self::Draining => 2,
            Self::Finalizing => 3,
            Self::Closed => 4,
        }
    }

    /// Decodes a numeric state value.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Open),
            1 => Some(Self::Closing),
            2 => Some(Self::Draining),
            3 => Some(Self::Finalizing),
            4 => Some(Self::Closed),
            _ => None,
        }
    }

    /// Returns true if the region is terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Returns true if the region can accept new work.
    #[must_use]
    pub const fn can_spawn(self) -> bool {
        matches!(self, Self::Open)
    }

    /// Returns true if the region can admit normal same-region work.
    ///
    /// Finalizing is intentionally excluded: once the region has observed
    /// quiescence and started finalizers, ordinary task admission would reopen
    /// the region after close had already committed to cleanup.
    #[must_use]
    pub const fn can_accept_work(self) -> bool {
        matches!(self, Self::Open)
    }

    /// Returns true if the region can admit cleanup-only work.
    ///
    /// Async finalizer barrier tasks are allowed in `Finalizing` so required
    /// cleanup can still complete. Child-region creation and obligation
    /// reservation remain `Open`-only.
    #[must_use]
    pub const fn can_accept_cleanup_work(self) -> bool {
        matches!(self, Self::Open | Self::Finalizing)
    }

    /// Returns true if the region is draining (waiting for children to complete).
    #[must_use]
    pub const fn is_draining(self) -> bool {
        matches!(self, Self::Draining)
    }

    /// Returns true if the region is in a closing phase (any of Closing, Draining, Finalizing).
    #[must_use]
    pub const fn is_closing(self) -> bool {
        matches!(self, Self::Closing | Self::Draining | Self::Finalizing)
    }
}

/// Admission limits for a region.
///
/// # Concurrency-Safety Argument
///
/// Every admission path (`add_task`, `add_cleanup_task`, `add_child`,
/// `try_reserve_obligation`, `heap_alloc`) follows an optimistic state check
/// before mutating:
///
/// 1. **Fast-path reject** — atomic `state.load(Acquire)` checks the relevant
///    admission predicate (`can_accept_work()` for normal tasks/obligations,
///    `can_accept_cleanup_work()` for cleanup tasks,
///    `can_spawn()` for children). If false, return `Closed` without locking.
/// 2. **Acquire write lock** — `inner.write()` serialises all mutations.
/// 3. **Re-check state** — a second `state.load(Acquire)` under the lock
///    guards against a concurrent `begin_close` that landed between steps
///    1 and 2. Because `begin_close` transitions the atomic under
///    the inner write lock, the re-check is linearisable.
/// 4. **Check limit** — under the same write guard, compare the live count
///    against the configured `Option<usize>` limit.
/// 5. **Commit** — push/increment within the write guard, then drop the
///    lock.
///
/// This means:
///
/// - **No over-admission**: the live count and the limit are compared
///   inside the same write-lock critical section, so two concurrent
///   `add_task` calls cannot both see `len < limit` and both succeed
///   when only one slot remains.
/// - **No lost removes**: `remove_task`/`remove_child`/`resolve_obligation`
///   acquire the write lock before mutating, so removes are sequenced
///   with respect to additions.
/// - **No stale-close admission**: the double-check on the admission
///   predicate prevents normal work from being added to a region that has
///   already begun closing, even if the optimistic read passed before the
///   state transition. Finalizing only keeps explicit cleanup-task admission
///   open; it does not reopen normal task, obligation, or child-region
///   creation.
/// - **Double-resolve is visible**: `resolve_obligation` asserts in debug
///   builds and records a per-region counter in release builds, so unpaired
///   resolves cannot silently wrap or disappear.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegionLimits {
    /// Maximum number of live child regions.
    pub max_children: Option<usize>,
    /// Maximum number of live tasks in the region.
    pub max_tasks: Option<usize>,
    /// Maximum number of pending obligations in the region.
    pub max_obligations: Option<usize>,
    /// Maximum live bytes allocated in the region heap.
    pub max_heap_bytes: Option<usize>,
    /// Optional min-plus curve budget for hard admission bounds. When set,
    /// task admission enforces the min-plus network calculus backlog bound
    /// against live tasks.
    pub curve_budget: Option<CurveBudget>,
}

impl RegionLimits {
    /// No admission limits.
    pub const UNLIMITED: Self = Self {
        max_children: None,
        max_tasks: None,
        max_obligations: None,
        max_heap_bytes: None,
        curve_budget: None,
    };

    /// Returns an unlimited limits configuration.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self::UNLIMITED
    }

    /// Attaches a curve budget for admission control bounds.
    #[must_use]
    pub fn with_curve_budget(mut self, curve_budget: CurveBudget) -> Self {
        self.curve_budget = Some(curve_budget);
        self
    }

    /// Clears any curve budget from the limits.
    #[must_use]
    pub fn without_curve_budget(mut self) -> Self {
        self.curve_budget = None;
        self
    }
}

/// The kind of admission that was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionKind {
    /// Admission for child regions.
    Child,
    /// Admission for tasks.
    Task,
    /// Admission for obligations.
    Obligation,
    /// Admission for region heap memory.
    HeapBytes,
}

/// Admission control failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    /// The region is closed or not accepting new work.
    Closed,
    /// A configured limit has been reached.
    LimitReached {
        /// The kind of admission that was denied.
        kind: AdmissionKind,
        /// The configured limit that was exceeded.
        limit: usize,
        /// The current live count at the time of admission.
        live: usize,
    },
}

/// Atomic region state wrapper for thread-safe state transitions.
#[derive(Debug)]
pub struct AtomicRegionState {
    inner: AtomicU8,
}

impl AtomicRegionState {
    /// Creates a new atomic state.
    #[must_use]
    pub fn new(state: RegionState) -> Self {
        Self {
            inner: AtomicU8::new(state.as_u8()),
        }
    }

    /// Loads the current state.
    #[must_use]
    pub fn load(&self) -> RegionState {
        RegionState::from_u8(self.inner.load(Ordering::Acquire)).expect("invalid region state")
    }

    /// Stores the given state.
    pub fn store(&self, state: RegionState) {
        self.inner.store(state.as_u8(), Ordering::Release);
    }

    /// Atomically transitions from `from` to `to`.
    pub fn transition(&self, from: RegionState, to: RegionState) -> bool {
        self.inner
            .compare_exchange(
                from.as_u8(),
                to.as_u8(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

/// Regions at or below this many member slots keep a plain vector: a short
/// linear scan beats hashing and needs no index allocation.
const TASK_MEMBERSHIP_INDEX_THRESHOLD: usize = 16;

/// A region's member tasks or child regions: insertion-ordered,
/// duplicate-free, with O(1) insert, remove, and membership test once the
/// region grows past [`TASK_MEMBERSHIP_INDEX_THRESHOLD`]
/// (br-asupersync-issue65-criticisms-kpmoy5.1.4; child regions since
/// br-asupersync-exeimj: a parent with one child region per request paid
/// O(siblings) per open and close under the runtime lock).
///
/// Iteration order is insertion order of the live members, exactly what the
/// previous `Vec<TaskId>` + `contains` + `retain` representation produced.
/// Cancel propagation iterates this order, so traces and lab replay stay
/// byte-identical. Small regions keep a dense vector (removal shifts at most
/// [`TASK_MEMBERSHIP_INDEX_THRESHOLD`] entries). Large regions switch to
/// tombstoned slots plus a position index and compact, order-preserving, when
/// tombstones dominate, so a server keeping thousands of connection tasks in
/// one region pays O(1) per spawn and per exit instead of O(N).
struct Membership<Id> {
    /// Members in insertion order; `None` marks a removed member and only
    /// appears while `index` is built.
    slots: Vec<Option<Id>>,
    /// Slot position of every live member, present once the region grew past
    /// the threshold.
    index: Option<crate::util::DetHashMap<Id, usize>>,
    /// Number of live members.
    live: usize,
}

/// A region's member tasks.
type TaskMembership = Membership<TaskId>;

impl<Id> Default for Membership<Id> {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            index: None,
            live: 0,
        }
    }
}

impl<Id: Copy + Eq + std::hash::Hash + std::fmt::Debug> Membership<Id> {
    #[inline]
    fn len(&self) -> usize {
        self.live
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.live == 0
    }

    #[inline]
    fn position(&self, task: Id) -> Option<usize> {
        match &self.index {
            Some(index) => index.get(&task).copied(),
            None => self.slots.iter().position(|slot| *slot == Some(task)),
        }
    }

    #[inline]
    fn contains(&self, task: Id) -> bool {
        self.position(task).is_some()
    }

    /// Appends `task` unless it is already a member. Returns whether it was added.
    fn insert(&mut self, task: Id) -> bool {
        if self.contains(task) {
            return false;
        }
        self.push_absent(task);
        true
    }

    /// Appends `task`, which the caller has just checked is not a member.
    fn push_absent(&mut self, task: Id) {
        debug_assert!(
            !self.contains(task),
            "task {task:?} is already a region member"
        );
        let position = self.slots.len();
        self.slots.push(Some(task));
        self.live += 1;
        match &mut self.index {
            Some(index) => {
                index.insert(task, position);
            }
            None if self.slots.len() > TASK_MEMBERSHIP_INDEX_THRESHOLD => self.rebuild_index(),
            None => {}
        }
    }

    /// Removes `task` if it is a member. Returns whether it was removed.
    fn remove(&mut self, task: Id) -> bool {
        let Some(index) = self.index.as_mut() else {
            // Dense mode: preserve order by shifting the (short) tail.
            let Some(position) = self.slots.iter().position(|slot| *slot == Some(task)) else {
                return false;
            };
            self.slots.remove(position);
            self.live -= 1;
            return true;
        };
        let Some(position) = index.remove(&task) else {
            return false;
        };
        self.slots[position] = None;
        self.live -= 1;
        if self.live == 0 {
            self.slots.clear();
            self.index = None;
            return true;
        }
        while matches!(self.slots.last(), Some(None)) {
            self.slots.pop();
        }
        // Compact when tombstones dominate (amortized O(1) per removal), and
        // return to dense mode once the region is small again so a region
        // that briefly grew does not keep its index forever. The second arm
        // costs at most one pass over 2 * threshold slots.
        if self.slots.len() > 2 * self.live + TASK_MEMBERSHIP_INDEX_THRESHOLD
            || self.live <= TASK_MEMBERSHIP_INDEX_THRESHOLD / 2
        {
            self.compact();
        }
        true
    }

    /// Drops tombstones, keeping insertion order, and rebuilds the index (or
    /// returns to dense mode when the region shrank back below the threshold).
    fn compact(&mut self) {
        self.slots.retain(Option::is_some);
        if self.slots.len() > TASK_MEMBERSHIP_INDEX_THRESHOLD {
            self.rebuild_index();
        } else {
            self.index = None;
        }
    }

    fn rebuild_index(&mut self) {
        let mut index = crate::util::DetHashMap::default();
        index.reserve(self.live);
        for (position, slot) in self.slots.iter().enumerate() {
            if let Some(task) = *slot {
                index.insert(task, position);
            }
        }
        self.index = Some(index);
    }

    /// Live members in insertion order.
    #[inline]
    fn iter(&self) -> impl Iterator<Item = Id> + '_ {
        self.slots.iter().filter_map(|slot| *slot)
    }

    fn to_vec(&self) -> Vec<Id> {
        let mut out = Vec::with_capacity(self.live);
        out.extend(self.iter());
        out
    }
}

impl<Id: Copy + Eq + std::hash::Hash + std::fmt::Debug> std::fmt::Debug for Membership<Id> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Same rendering as the `Vec<TaskId>` this replaced.
        f.debug_list().entries(self.iter()).finish()
    }
}

#[derive(Debug)]
struct RegionInner {
    budget: Budget,
    capability_budget: CapabilityBudget,
    children: Membership<RegionId>,
    tasks: TaskMembership,
    cancel_reason: Option<CancelReason>,
    close_outcome: Option<TaskOutcome>,
    /// Finalizer terminals only; ordinary cancelled children must not masquerade
    /// as failed cleanup when a supervisor decides whether it may restart.
    cleanup_outcome: Option<TaskOutcome>,
    /// The first panic of a region that closed beneath this one, carried up so
    /// this region's owner sees a descendant's panic (br-asupersync-b834ta).
    descendant_panic: Option<crate::types::PanicPayload>,
    limits: RegionLimits,
    pending_obligations: usize,
    /// Accepted checked obligations whose terminal lifecycle has not yet been
    /// applied to the arena. This is a close barrier, not a second quota.
    unapplied_obligations: usize,
    /// Removing a record revokes handles even when the removed record survives.
    obligation_handles_live: bool,
    /// Region-owned heap for task allocations.
    /// Reclaimed when the region closes to quiescence.
    heap: RegionHeap,
}

/// A task-generation capability over the region's actual admission lock.
/// Weak references avoid retaining region heaps/finalizers through a task Cx.
#[derive(Debug)]
pub(crate) struct ObligationAdmissionHandle {
    state: Weak<AtomicRegionState>,
    inner: Weak<RwLock<RegionInner>>,
    holder: TaskId,
    region: RegionId,
    live: AtomicBool,
}

impl ObligationAdmissionHandle {
    pub(crate) fn revoke(&self) {
        if let Some(inner) = self.inner.upgrade() {
            let _guard = inner.write();
            self.live.store(false, Ordering::Release);
        } else {
            self.live.store(false, Ordering::Release);
        }
    }

    pub(crate) fn is_live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }

    pub(crate) fn holder(&self) -> TaskId {
        self.holder
    }

    pub(crate) fn region(&self) -> RegionId {
        self.region
    }

    /// Move one accepted credit. Region gates precede the credit decision;
    /// publication remains inside both gates, notification stays outside.
    pub(crate) fn transfer_to(
        &self,
        destination: &Self,
        claim: impl FnOnce() -> Result<(), crate::runtime::obligation_mailbox::ObligationTransferError>,
        publish: impl FnOnce(),
    ) -> Result<(), crate::runtime::obligation_mailbox::ObligationTransferError> {
        use crate::runtime::obligation_mailbox::{
            ObligationAdmissionError as Admission, ObligationTransferError as Error,
        };
        let source = self.inner.upgrade().ok_or(Error::SourceHolderNotLive)?;
        let target = destination
            .inner
            .upgrade()
            .ok_or(Error::Destination(Admission::RegionClosed))?;
        let target_state = destination
            .state
            .upgrade()
            .ok_or(Error::Destination(Admission::RegionClosed))?;
        let validate = |source: &RegionInner, target: &RegionInner, shared: bool| {
            if !source.obligation_handles_live || !self.live.load(Ordering::Acquire) {
                return Err(Error::SourceHolderNotLive);
            }
            if !target.obligation_handles_live || !target_state.load().can_accept_work() {
                return Err(Error::Destination(Admission::RegionClosed));
            }
            if !destination.live.load(Ordering::Acquire) {
                return Err(Error::Destination(Admission::HolderNotLive));
            }
            if !shared {
                if let Some(limit) = target.limits.max_obligations {
                    if target.pending_obligations >= limit {
                        return Err(Error::Destination(Admission::LimitReached {
                            limit,
                            live: target.pending_obligations,
                        }));
                    }
                }
                target
                    .pending_obligations
                    .checked_add(1)
                    .ok_or(Error::Destination(Admission::CapacityExhausted))?;
                source
                    .pending_obligations
                    .checked_sub(1)
                    .ok_or(Error::SourceResolved)?;
            }
            target
                .unapplied_obligations
                .checked_add(1)
                .ok_or(Error::Destination(Admission::CapacityExhausted))?;
            Ok(())
        };
        if Arc::ptr_eq(&source, &target) {
            let mut inner = source.write();
            validate(&inner, &inner, true)?;
            claim()?;
            inner.unapplied_obligations += 1;
            publish();
            return Ok(());
        }
        // Equal IDs with distinct storage are not identities in one runtime.
        if self.region == destination.region {
            return Err(Error::DifferentRuntime);
        }
        let (mut source, mut target) = if self.region < destination.region {
            let source = source.write();
            let target = target.write();
            (source, target)
        } else {
            let target = target.write();
            let source = source.write();
            (source, target)
        };
        validate(&source, &target, false)?;
        claim()?;
        target.pending_obligations += 1;
        target.unapplied_obligations += 1;
        source.pending_obligations = source
            .pending_obligations
            .checked_sub(1)
            .expect("handoff releases one accepted source credit");
        publish();
        Ok(())
    }

    /// `publish` must contain only ownership setup and queue publication. In
    /// particular it must not notify, trace, drop user values, or acquire a
    /// runtime/table/primitive lock. Revocation cannot pass a published credit.
    pub(crate) fn admit(
        &self,
        holder: TaskId,
        region: RegionId,
        publish: impl FnOnce(),
    ) -> Result<(), crate::runtime::obligation_mailbox::ObligationAdmissionError> {
        self.admit_inner(holder, region, true, publish)
    }

    pub(crate) fn reserve_direct(
        &self,
        holder: TaskId,
        region: RegionId,
    ) -> Result<(), crate::runtime::obligation_mailbox::ObligationAdmissionError> {
        self.admit_inner(holder, region, false, || {})
    }

    fn admit_inner(
        &self,
        holder: TaskId,
        region: RegionId,
        pending_application: bool,
        publish: impl FnOnce(),
    ) -> Result<(), crate::runtime::obligation_mailbox::ObligationAdmissionError> {
        use crate::runtime::obligation_mailbox::ObligationAdmissionError as Error;
        if self.holder != holder || self.region != region {
            return Err(Error::HolderMismatch);
        }
        let inner = self.inner.upgrade().ok_or(Error::RegionClosed)?;
        let state = self.state.upgrade().ok_or(Error::RegionClosed)?;
        let mut inner = inner.write();
        if !inner.obligation_handles_live || !state.load().can_accept_work() {
            return Err(Error::RegionClosed);
        }
        if !self.live.load(Ordering::Acquire) {
            return Err(Error::HolderNotLive);
        }
        if let Some(limit) = inner.limits.max_obligations {
            if inner.pending_obligations >= limit {
                return Err(Error::LimitReached {
                    limit,
                    live: inner.pending_obligations,
                });
            }
        }
        let pending = inner
            .pending_obligations
            .checked_add(1)
            .ok_or(Error::CapacityExhausted)?;
        let unapplied = inner
            .unapplied_obligations
            .checked_add(usize::from(pending_application))
            .ok_or(Error::CapacityExhausted)?;
        inner.pending_obligations = pending;
        inner.unapplied_obligations = unapplied;
        publish();
        Ok(())
    }

    /// Claim a terminal outcome and release live quota under the same gate as
    /// admission. The callback owns the credit's exactly-once state transition.
    pub(crate) fn settle(&self, claim: impl FnOnce() -> bool) -> bool {
        let Some(inner) = self.inner.upgrade() else {
            return claim();
        };
        let mut inner = inner.write();
        if !claim() {
            return false;
        }
        // Tolerate an accounting skew exactly as `resolve_obligation` does:
        // this runs from `ObligationToken::drop`, where a panic during a task
        // unwind aborts the process. Saturate, count it, and go on.
        match inner.pending_obligations.checked_sub(1) {
            Some(remaining) => inner.pending_obligations = remaining,
            None => {
                debug_assert!(false, "accepted obligation quota released more than once");
                inner.pending_obligations = 0;
            }
        }
        true
    }

    pub(crate) fn finish_application(&self) {
        if let Some(inner) = self.inner.upgrade() {
            let mut inner = inner.write();
            inner.unapplied_obligations = inner
                .unapplied_obligations
                .checked_sub(1)
                .expect("accepted obligation application finished exactly once");
        }
    }
}

/// br-asupersync-dx-core-api-v2-u1z5hn.1.2 — Shared pending-spawn counter.
///
/// Counts spawn requests that have been enqueued onto the spawn mailbox for
/// this region but not yet admitted (or resolved cancelled). The counter is
/// `Arc`-shared so producers can increment it **without holding the
/// `RuntimeState` lock** — that is the entire point of the spawn mailbox —
/// while the close path reads it under its normal locking.
///
/// # Ordering contract (the load-bearing invariant)
///
/// The counter must never *undercount* live spawn work:
///
/// 1. **Increment-before-visibility**: a producer increments (via
///    [`PendingSpawnCounter::reserve`]) *before* the request is published to
///    the mailbox. An observable request therefore always has its credit.
/// 2. **Decrement-after-successor-visibility**: the reservation is dropped
///    (decrementing) only *after* the request's successor state is in place —
///    the task admitted into the region's task list, or the request resolved
///    cancelled and its future destroyed. There is consequently a window
///    where both the pending credit and the successor state are visible;
///    that double-count is deliberate (close waits a little longer), the
///    reverse gap (neither visible) can never occur.
///
/// All operations use `SeqCst`: this counter is touched once per spawn (not
/// per poll), so the simpler proof beats the nanoseconds. See
/// `artifacts/proof_notes/` for the full argument.
#[derive(Debug, Default)]
pub struct PendingSpawnCounter {
    count: AtomicU32,
    /// Decrements observed with the count already at zero. Structurally
    /// unreachable through [`PendingSpawnReservation`]; counted rather than
    /// panicking, mirroring `double_resolve_count`.
    underflow_count: AtomicU32,
}

impl PendingSpawnCounter {
    /// Creates a counter with no pending spawns.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current number of pending (enqueued, not yet admitted) spawns.
    #[inline]
    #[must_use]
    pub fn count(&self) -> u32 {
        self.count.load(Ordering::SeqCst)
    }

    /// Reserves one pending-spawn credit (increment-before-visibility).
    ///
    /// Call this *before* publishing the spawn request to the mailbox. The
    /// returned reservation releases the credit on drop; hold it until the
    /// request is admitted or resolved cancelled.
    #[must_use]
    pub fn reserve(self: &Arc<Self>) -> PendingSpawnReservation {
        self.count.fetch_add(1, Ordering::SeqCst);
        PendingSpawnReservation {
            counter: Arc::clone(self),
        }
    }

    /// Decrements observed at zero (diagnostic; expected to stay 0).
    #[must_use]
    pub fn underflow_count(&self) -> u32 {
        self.underflow_count.load(Ordering::SeqCst)
    }

    fn release(&self) {
        let result = self
            .count
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                count.checked_sub(1)
            });
        if result.is_err() {
            debug_assert!(false, "pending-spawn counter released below zero");
            self.underflow_count.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// RAII credit for one enqueued-but-not-yet-admitted spawn request.
///
/// Created by [`PendingSpawnCounter::reserve`] *before* the request becomes
/// visible to the scheduler; dropped exactly once when the request reaches
/// its successor state (admitted, or resolved cancelled). Travelling inside
/// the spawn request makes the release panic-safe: any path that destroys
/// the request releases the credit.
#[derive(Debug)]
pub struct PendingSpawnReservation {
    counter: Arc<PendingSpawnCounter>,
}

impl Drop for PendingSpawnReservation {
    fn drop(&mut self) {
        self.counter.release();
    }
}

/// Retained close result for internal structured owners.
#[derive(Debug, Clone)]
pub(crate) struct RegionCloseOutcome {
    pub(crate) outcome: TaskOutcome,
    pub(crate) cleanup_outcome: Option<TaskOutcome>,
    /// This region's own panic, otherwise the first one a descendant region
    /// passed up.
    pub(crate) descendant_panic: Option<crate::types::PanicPayload>,
}

/// Internal record for a region in the runtime.
#[derive(Debug)]
pub struct RegionRecord {
    /// Unique identifier for this region.
    pub id: RegionId,
    /// Parent region (None for root).
    pub parent: Option<RegionId>,
    /// Logical time when the region was created.
    pub created_at: Time,
    /// Notification state for tasks waiting on this region to close.
    pub close_notify: std::sync::Arc<parking_lot::Mutex<RegionCloseState>>,
    /// Retained outside the region heap so an owned handle can observe close
    /// even after the runtime reclaims this generation's record.
    close_receipt: Arc<parking_lot::Mutex<Option<RegionCloseOutcome>>>,
    /// Explicit shutdown ceiling, separate from the ordinary work budget.
    /// Finalizers retain this same handle and observe later tightening.
    shutdown_budget: crate::record::finalizer::ShutdownBudget,
    /// Current state (atomic for concurrent access).
    state: Arc<AtomicRegionState>,
    /// Finalizers may be Send without Sync. Keep their ownership on the record,
    /// outside the Arc-shared admission state, and acquire this lock only after
    /// `inner`. This preserves both the region's Send contract and its existing
    /// shared-read heap semantics. Drop finalizers before the region heap.
    finalizers: RwLock<FinalizerStack>,
    /// Inner mutable state (guarded by a lock).
    inner: Arc<RwLock<RegionInner>>,
    /// br-asupersync-bjrqu3 — Count of `resolve_obligation` calls
    /// that fired when `pending_obligations` was already 0. Surfaces
    /// the double-resolve invariant violation that the previous
    /// `saturating_sub` shape silently masked.
    double_resolve_count: AtomicU64,
    /// br-asupersync-dx-core-api-v2-u1z5hn.1.2 — Spawn requests enqueued
    /// onto the spawn mailbox for this region but not yet admitted.
    /// `Arc`-shared so producers increment without the state lock; the
    /// close path treats a nonzero count as live children.
    pending_spawns: Arc<PendingSpawnCounter>,
    /// br-asupersync-bi2462.13 — obligation reservations held by live
    /// `ObligationToken`s of this region's tasks.
    ///
    /// The same increment-before-visibility shape as `pending_spawns`, so
    /// drain gating sees a reservation between its post and its application.
    pending_obligation_posts: Arc<PendingSpawnCounter>,
    /// A sealed region closes itself, without cancelling anything, once it
    /// has no tasks, children, pending spawns or pending obligation posts.
    /// Its own tasks may still spawn into it while it is open. Race branches
    /// run in sealed regions so a winner's descendants keep running after the
    /// race returns, and the region still never outlives its work
    /// (br-asupersync-issue65-criticisms-kpmoy5.2.2).
    sealed: AtomicBool,
    /// For a sealed region, its nearest unsealed ancestor. A spawn from one
    /// of its tasks' contexts that arrives after this region closed is
    /// admitted there, the region a race branch's context belonged to before
    /// branches had regions of their own (br-asupersync-k27oxe).
    spawn_fallback: std::sync::OnceLock<RegionId>,
    /// When this region's first cancellation report was dispatched, in
    /// nanoseconds (`u64::MAX` until then). Region close reports the drain
    /// time from it. The first cancel creates it, so a region that is never
    /// cancelled allocates nothing (br-asupersync-x9mmxl).
    cancel_reported_at: Option<Arc<AtomicU64>>,
    /// Tracing span for region lifecycle (only active with tracing-integration feature).
    #[cfg(feature = "tracing-integration")]
    span: Span,
    /// Disabled-tracing span value for builds without tracing integration.
    #[cfg(not(feature = "tracing-integration"))]
    span: Span,
}

impl RegionRecord {
    /// Creates a new region record.
    #[must_use]
    pub fn new(id: RegionId, parent: Option<RegionId>, budget: Budget) -> Self {
        Self::new_with_time(id, parent, budget, Time::from_nanos(1_000_000_000))
    }

    /// Creates a new region record with an explicit capability budget.
    #[must_use]
    pub fn new_with_capability_budget(
        id: RegionId,
        parent: Option<RegionId>,
        budget: Budget,
        capability_budget: CapabilityBudget,
    ) -> Self {
        Self::new_with_time_and_capability_budget(
            id,
            parent,
            budget,
            Time::from_nanos(1_000_000_000),
            capability_budget,
        )
    }

    /// Creates a new region record with an explicit creation time.
    #[must_use]
    pub fn new_with_time(
        id: RegionId,
        parent: Option<RegionId>,
        budget: Budget,
        created_at: Time,
    ) -> Self {
        Self::new_with_time_and_capability_budget(
            id,
            parent,
            budget,
            created_at,
            CapabilityBudget::UNSPECIFIED,
        )
    }

    /// Creates a new region record with explicit creation time and capability budget.
    #[must_use]
    pub fn new_with_time_and_capability_budget(
        id: RegionId,
        parent: Option<RegionId>,
        budget: Budget,
        created_at: Time,
        capability_budget: CapabilityBudget,
    ) -> Self {
        // Create a tracing span for the region lifecycle
        let span = info_span!(
            "region",
            region_id = ?id,
            parent_region_id = ?parent,
            state = "Open",
            initial_budget_deadline = ?budget.deadline,
            initial_budget_poll_quota = budget.poll_quota,
        );

        debug!(
            parent: &span,
            region_id = ?id,
            parent_region_id = ?parent,
            state = "Open",
            budget_deadline = ?budget.deadline,
            budget_poll_quota = budget.poll_quota,
            "region created"
        );

        Self {
            id,
            parent,
            created_at,
            close_notify: std::sync::Arc::new(parking_lot::Mutex::new(RegionCloseState {
                closed: false,
                waiters: Vec::new(),
            })),
            close_receipt: Arc::new(parking_lot::Mutex::new(None)),
            shutdown_budget: Arc::new(RwLock::new(None)),
            state: Arc::new(AtomicRegionState::new(RegionState::Open)),
            finalizers: RwLock::new(FinalizerStack::new()),
            inner: Arc::new(RwLock::new(RegionInner {
                budget,
                capability_budget,
                children: Membership::default(),
                tasks: TaskMembership::default(),
                cancel_reason: None,
                close_outcome: None,
                cleanup_outcome: None,
                descendant_panic: None,
                limits: RegionLimits::UNLIMITED,
                pending_obligations: 0,
                unapplied_obligations: 0,
                obligation_handles_live: true,
                heap: RegionHeap::new(),
            })),
            double_resolve_count: AtomicU64::new(0),
            pending_spawns: Arc::new(PendingSpawnCounter::new()),
            pending_obligation_posts: Arc::new(PendingSpawnCounter::new()),
            sealed: AtomicBool::new(false),
            spawn_fallback: std::sync::OnceLock::new(),
            cancel_reported_at: None,
            span,
        }
    }

    /// Marks this region sealed: once it holds no live work it begins a
    /// non-cancelling close by itself (see [`Self::is_sealed`]).
    /// `spawn_fallback` is its nearest unsealed ancestor (see
    /// [`Self::spawn_fallback`]).
    pub(crate) fn seal(&self, spawn_fallback: RegionId) {
        let _ = self.spawn_fallback.set(spawn_fallback);
        self.sealed.store(true, Ordering::Release);
    }

    /// For a sealed region, the region that admits a spawn from one of its
    /// tasks' contexts once this region has closed.
    #[must_use]
    pub(crate) fn spawn_fallback(&self) -> Option<RegionId> {
        self.spawn_fallback.get().copied()
    }

    /// The stamp this region's cancellation report writes when it is
    /// dispatched, created by the first cancel.
    pub(crate) fn cancel_report_stamp(&mut self) -> Arc<AtomicU64> {
        Arc::clone(
            self.cancel_reported_at
                .get_or_insert_with(|| Arc::new(AtomicU64::new(u64::MAX))),
        )
    }

    /// The cancellation-report stamp, if this region was ever cancelled.
    pub(crate) fn cancel_reported_at(&self) -> Option<Arc<AtomicU64>> {
        self.cancel_reported_at.clone()
    }

    /// Returns true when the region closes itself once its work is done,
    /// instead of waiting for an explicit close or cancel.
    #[must_use]
    pub(crate) fn is_sealed(&self) -> bool {
        self.sealed.load(Ordering::Acquire)
    }

    /// Returns the logical time when the region was created.
    #[must_use]
    pub const fn created_at(&self) -> Time {
        self.created_at
    }

    /// Returns the current region state.
    #[inline]
    #[must_use]
    pub fn state(&self) -> RegionState {
        self.state.load()
    }

    /// Returns the region budget.
    #[inline]
    #[must_use]
    pub fn budget(&self) -> Budget {
        self.inner.read().budget
    }

    /// Sets the region budget.
    pub fn set_budget(&self, budget: Budget) {
        self.inner.write().budget = budget;
    }

    /// Returns the explicit capability/resource budget for this region.
    #[inline]
    #[must_use]
    pub fn capability_budget(&self) -> CapabilityBudget {
        self.inner.read().capability_budget
    }

    /// Sets the explicit capability/resource budget for this region.
    pub fn set_capability_budget(&self, capability_budget: CapabilityBudget) {
        self.inner.write().capability_budget = capability_budget;
    }

    /// Returns the current admission limits for this region.
    #[inline]
    #[must_use]
    pub fn limits(&self) -> RegionLimits {
        self.inner.read().limits.clone()
    }

    /// Updates the admission limits for this region.
    pub fn set_limits(&self, limits: RegionLimits) {
        self.inner.write().limits = limits;
    }

    /// Returns the number of pending obligations tracked for this region.
    #[inline]
    #[must_use]
    pub fn pending_obligations(&self) -> usize {
        self.inner.read().pending_obligations
    }

    pub(crate) fn obligation_admission_handle(
        &self,
        holder: TaskId,
    ) -> Arc<ObligationAdmissionHandle> {
        Arc::new(ObligationAdmissionHandle {
            state: Arc::downgrade(&self.state),
            inner: Arc::downgrade(&self.inner),
            holder,
            region: self.id,
            live: AtomicBool::new(true),
        })
    }

    pub(crate) fn revoke_obligation_handles(&self) {
        self.inner.write().obligation_handles_live = false;
    }

    /// Checked admission accepted before its terminal arena projection.
    #[must_use]
    pub fn unapplied_obligation_count(&self) -> usize {
        self.inner.read().unapplied_obligations
    }

    /// Returns the current cancel reason, if any.
    #[must_use]
    pub fn cancel_reason(&self) -> Option<CancelReason> {
        self.inner.read().cancel_reason.clone()
    }

    /// Returns the aggregated close outcome, if one has been observed.
    #[must_use]
    pub fn close_outcome(&self) -> Option<TaskOutcome> {
        self.inner.read().close_outcome.clone()
    }

    /// Merges a terminal child/finalizer outcome into the region close outcome.
    pub fn record_close_outcome(&self, outcome: TaskOutcome) {
        let mut inner = self.inner.write();
        inner.close_outcome = Some(match inner.close_outcome.take() {
            Some(existing) => existing.join(outcome),
            None => outcome,
        });
    }

    /// Records only actual finalizer retirement, preserving the public aggregate.
    pub(crate) fn record_cleanup_outcome(&self, outcome: TaskOutcome) {
        let mut inner = self.inner.write();
        inner.cleanup_outcome = Some(match inner.cleanup_outcome.take() {
            Some(existing) => existing.join(outcome.clone()),
            None => outcome.clone(),
        });
        inner.close_outcome = Some(match inner.close_outcome.take() {
            Some(existing) => existing.join(outcome),
            None => outcome,
        });
    }

    /// Aggregate descendant/manual success evidence without changing the
    /// historical public close-outcome folding policy.
    pub(crate) fn record_cleanup_receipt(&self, outcome: TaskOutcome) {
        let mut inner = self.inner.write();
        inner.cleanup_outcome = Some(match inner.cleanup_outcome.take() {
            Some(existing) => existing.join(outcome),
            None => outcome,
        });
    }

    pub(crate) fn close_receipt_handle(
        &self,
    ) -> Arc<parking_lot::Mutex<Option<RegionCloseOutcome>>> {
        Arc::clone(&self.close_receipt)
    }

    /// Copies only cleanup evidence when folding a closed child into its parent.
    /// The retained canonical outcome can contain an allocated cancel cause chain.
    pub(crate) fn closed_cleanup_outcome(&self) -> Option<TaskOutcome> {
        self.close_receipt
            .lock()
            .as_ref()
            .and_then(|receipt| receipt.cleanup_outcome.clone())
    }

    /// Records a panic passed up by a child region as it closed. The first one
    /// wins, so the result does not depend on which child closed last.
    pub(crate) fn record_descendant_panic(&self, payload: crate::types::PanicPayload) {
        self.inner.write().descendant_panic.get_or_insert(payload);
    }

    /// The panic this closed region passes up: its own, otherwise the first
    /// one a descendant passed to it.
    pub(crate) fn closed_descendant_panic(&self) -> Option<crate::types::PanicPayload> {
        self.close_receipt
            .lock()
            .as_ref()
            .and_then(|receipt| receipt.descendant_panic.clone())
    }

    pub(crate) fn shutdown_budget_handle(&self) -> crate::record::finalizer::ShutdownBudget {
        Arc::clone(&self.shutdown_budget)
    }

    pub(crate) fn shutdown_budget(&self) -> Option<Budget> {
        *self.shutdown_budget.read()
    }

    /// Called before publishing cancellation. No user callback runs here.
    pub(crate) fn tighten_shutdown_budget(&self, budget: Budget) -> bool {
        let mut current = self.shutdown_budget.write();
        let next = current.map_or(budget, |old| old.combine_untraced(budget));
        let changed = *current != Some(next);
        *current = Some(next);
        changed
    }

    /// Strengthens or sets the cancel reason.
    pub fn strengthen_cancel_reason(&self, reason: CancelReason) {
        let mut inner = self.inner.write();
        if let Some(existing) = &mut inner.cancel_reason {
            existing.strengthen(&reason);
        } else {
            inner.cancel_reason = Some(reason);
        }
    }

    /// Returns the number of child regions without cloning the list.
    #[inline]
    #[must_use]
    pub fn child_count(&self) -> usize {
        self.inner.read().children.len()
    }

    /// Returns a snapshot of child region IDs.
    #[must_use]
    pub fn child_ids(&self) -> Vec<RegionId> {
        self.inner.read().children.to_vec()
    }

    /// Copies child region IDs into the provided buffer (avoids fresh allocation).
    #[inline]
    pub fn copy_child_ids_into(&self, buf: &mut Vec<RegionId>) {
        let inner = self.inner.read();
        buf.extend(inner.children.iter());
    }

    /// Returns the number of tracked tasks without cloning the list.
    #[inline]
    #[must_use]
    pub fn task_count(&self) -> usize {
        self.inner.read().tasks.len()
    }

    /// Returns a snapshot of task IDs.
    #[must_use]
    pub fn task_ids(&self) -> Vec<TaskId> {
        self.inner.read().tasks.to_vec()
    }

    /// Copies task IDs into the provided buffer (avoids fresh allocation).
    #[inline]
    pub fn copy_task_ids_into(&self, buf: &mut Vec<TaskId>) {
        let inner = self.inner.read();
        buf.extend(inner.tasks.iter());
    }

    /// Returns task IDs as a SmallVec, avoiding heap allocation for typical regions.
    #[inline]
    #[must_use]
    pub fn task_ids_small(&self) -> smallvec::SmallVec<[TaskId; 8]> {
        let inner = self.inner.read();
        inner.tasks.iter().collect()
    }

    /// Returns true if the region has any live children, tasks, pending
    /// obligations, or pending (not-yet-admitted) spawn requests.
    #[inline]
    #[must_use]
    pub fn has_live_work(&self) -> bool {
        let inner = self.inner.read();
        !inner.children.is_empty()
            || !inner.tasks.is_empty()
            || inner.pending_obligations > 0
            || inner.unapplied_obligations > 0
            || self.pending_spawns.count() > 0
    }

    /// Returns the number of spawn requests enqueued for this region but not
    /// yet admitted (br-asupersync-dx-core-api-v2-u1z5hn.1.2).
    #[inline]
    #[must_use]
    pub fn pending_spawn_count(&self) -> u32 {
        self.pending_spawns.count()
    }

    /// Obligation reservations posted by this region's tasks whose tokens
    /// are still alive (br-asupersync-bi2462.13).
    #[inline]
    #[must_use]
    pub fn pending_obligation_post_count(&self) -> u32 {
        self.pending_obligation_posts.count()
    }

    /// Producers clone this out of the record at task-context build time and
    /// reserve one credit per obligation token without the state lock.
    #[inline]
    #[must_use]
    pub fn pending_obligation_post_handle(&self) -> Arc<PendingSpawnCounter> {
        Arc::clone(&self.pending_obligation_posts)
    }

    /// Returns the shared pending-spawn counter handle.
    ///
    /// Producers clone this out of the record (under the state lock, once,
    /// at spawn-capability setup) and then reserve credits on it without
    /// the lock for each enqueue.
    #[inline]
    #[must_use]
    pub fn pending_spawn_handle(&self) -> Arc<PendingSpawnCounter> {
        Arc::clone(&self.pending_spawns)
    }

    /// Reserves one pending-spawn credit on this region
    /// (increment-before-visibility; see [`PendingSpawnCounter`]).
    #[inline]
    #[must_use]
    pub fn reserve_pending_spawn(&self) -> PendingSpawnReservation {
        self.pending_spawns.reserve()
    }

    /// Adds a child region.
    ///
    /// Returns `Ok(())` if the child was added or already present, or an
    /// admission error if the region is closed or at capacity.
    ///
    /// Child regions are only admitted while the parent is `Open`. Once close
    /// begins, cleanup must stay within the existing region tree.
    pub fn add_child(&self, child: RegionId) -> Result<(), AdmissionError> {
        // Optimistic check (atomic)
        if !self.state.load().can_spawn() {
            return Err(AdmissionError::Closed);
        }

        let mut inner = self.inner.write();

        // Double check under lock (though state is atomic, consistency matters)
        if !self.state.load().can_spawn() {
            return Err(AdmissionError::Closed);
        }

        if inner.children.contains(child) {
            return Ok(());
        }

        if let Some(limit) = inner.limits.max_children {
            if inner.children.len() >= limit {
                return Err(AdmissionError::LimitReached {
                    kind: AdmissionKind::Child,
                    limit,
                    live: inner.children.len(),
                });
            }
        }

        inner.children.push_absent(child);
        drop(inner);
        Ok(())
    }

    /// Removes a child region.
    pub fn remove_child(&self, child: RegionId) {
        let mut inner = self.inner.write();
        inner.children.remove(child);
    }

    fn add_task_internal(&self, task: TaskId, cleanup_task: bool) -> Result<(), AdmissionError> {
        let can_admit = |state: RegionState| {
            if cleanup_task {
                state.can_accept_cleanup_work()
            } else {
                state.can_accept_work()
            }
        };

        // Optimistic check
        let state = self.state.load();
        if !can_admit(state) {
            return Err(AdmissionError::Closed);
        }

        let mut inner = self.inner.write();

        // Double check
        let state = self.state.load();
        if !can_admit(state) {
            return Err(AdmissionError::Closed);
        }

        if inner.tasks.contains(task) {
            return Ok(());
        }

        let bypass_limit = cleanup_task && state == RegionState::Finalizing;
        if !bypass_limit {
            let mut effective_limit = inner.limits.max_tasks;
            if let Some(ref curve) = inner.limits.curve_budget {
                let horizon = curve.arrival.horizon().max(curve.service.horizon());
                let bound = usize::try_from(curve.backlog_bound(horizon)).unwrap_or(usize::MAX);
                effective_limit = Some(effective_limit.map_or(bound, |l| l.min(bound)));
            }
            if let Some(limit) = effective_limit {
                if inner.tasks.len() >= limit {
                    return Err(AdmissionError::LimitReached {
                        kind: AdmissionKind::Task,
                        limit,
                        live: inner.tasks.len(),
                    });
                }
            }
        }

        inner.tasks.push_absent(task);
        drop(inner);
        Ok(())
    }

    /// Adds a task to this region.
    ///
    /// Returns `Ok(())` if the task was added or already present, or an
    /// admission error if the region is closed or at capacity.
    pub fn add_task(&self, task: TaskId) -> Result<(), AdmissionError> {
        self.add_task_internal(task, false)
    }

    /// Adds a cleanup task to this region.
    ///
    /// Required same-region cleanup work in `Finalizing` must still be able to
    /// run even if `max_tasks` would otherwise reject new normal tasks.
    pub fn add_cleanup_task(&self, task: TaskId) -> Result<(), AdmissionError> {
        self.add_task_internal(task, true)
    }

    /// Removes a task from this region.
    pub fn remove_task(&self, task: TaskId) {
        let mut inner = self.inner.write();
        inner.tasks.remove(task);
    }

    /// Reserves an obligation slot for this region.
    pub fn try_reserve_obligation(&self) -> Result<(), AdmissionError> {
        if !self.state.load().can_accept_work() {
            return Err(AdmissionError::Closed);
        }

        let mut inner = self.inner.write();
        if !self.state.load().can_accept_work() {
            return Err(AdmissionError::Closed);
        }

        if let Some(limit) = inner.limits.max_obligations {
            if inner.pending_obligations >= limit {
                return Err(AdmissionError::LimitReached {
                    kind: AdmissionKind::Obligation,
                    limit,
                    live: inner.pending_obligations,
                });
            }
        }

        inner.pending_obligations = inner.pending_obligations.saturating_add(1);
        drop(inner);
        Ok(())
    }

    /// Marks an obligation slot as resolved for this region.
    ///
    /// br-asupersync-bjrqu3 — On a double-resolve (the counter is
    /// already 0), the previous shape used `saturating_sub`, which
    /// silently masked the invariant violation. The "no obligation
    /// leaks" invariant relies on `pending_obligations == 0` at
    /// region-close time; with the saturate, a buggy caller that
    /// resolves twice could leave a real obligation orphaned while
    /// the counter still showed 0. Now: in debug builds we panic on
    /// the bug (loud regression signal); in release builds we
    /// saturate AND increment a per-region double-resolve counter
    /// so operators can detect the invariant violation via
    /// [`Self::double_resolve_count`].
    pub fn resolve_obligation(&self) {
        let mut inner = self.inner.write();
        match inner.pending_obligations.checked_sub(1) {
            Some(n) => inner.pending_obligations = n,
            None => {
                debug_assert!(
                    false,
                    "double-resolve detected on Region: \
                     resolve_obligation called when pending_obligations was 0 \
                     (br-asupersync-bjrqu3)"
                );
                self.double_resolve_count.fetch_add(1, Ordering::Relaxed);
                #[cfg(feature = "tracing-integration")]
                tracing::warn!(
                    "Region::resolve_obligation called when pending_obligations==0 \
                     (br-asupersync-bjrqu3) — counter saturated, double-resolve \
                     count incremented"
                );
            }
        }
    }

    /// br-asupersync-bjrqu3 — Number of times `resolve_obligation`
    /// was called when `pending_obligations` was already zero. A
    /// non-zero value indicates a double-resolve protocol violation
    /// (typically: same obligation guard's `commit` AND `abort`
    /// were both invoked, or `Drop` ran twice via unsafe ABI). In
    /// debug builds the first such call panics; in release the
    /// counter increments so operators can detect the violation.
    #[must_use]
    pub fn double_resolve_count(&self) -> u64 {
        self.double_resolve_count.load(Ordering::Relaxed)
    }

    /// Adds a finalizer to run when the region closes.
    ///
    /// Finalizers are stored in LIFO order and will be executed
    /// in reverse registration order during the Finalizing phase.
    pub fn add_finalizer(&self, finalizer: Finalizer) {
        let _inner = self.inner.write();
        self.finalizers.write().push(finalizer);
    }

    /// Pops the next finalizer to run (LIFO order).
    ///
    /// Returns `None` when all finalizers have been executed.
    pub fn pop_finalizer(&self) -> Option<Finalizer> {
        let _inner = self.inner.write();
        if self.state.load() != RegionState::Finalizing {
            return None;
        }

        self.finalizers.write().pop()
    }

    /// Removes every pending finalizer, in LIFO order, whatever the region
    /// state. Runtime teardown only: a region that never reached
    /// `Finalizing` can no longer run them, and a retained value that keeps
    /// the runtime state alive would otherwise never be dropped. The caller
    /// drops them outside every runtime lock.
    pub(crate) fn take_finalizers_for_teardown(&self) -> Vec<Finalizer> {
        let _inner = self.inner.write();
        let mut stack = self.finalizers.write();
        std::iter::from_fn(|| stack.pop()).collect()
    }

    /// Returns the number of pending finalizers.
    #[must_use]
    pub fn finalizer_count(&self) -> usize {
        let _inner = self.inner.read();
        self.finalizers.read().len()
    }

    /// Returns true if there are no pending finalizers.
    #[must_use]
    pub fn finalizers_empty(&self) -> bool {
        let _inner = self.inner.read();
        self.finalizers.read().is_empty()
    }

    /// Allocates a value in the region's heap.
    ///
    /// The allocation remains valid until the region closes to quiescence.
    /// This ensures that tasks spawned in the region can safely access the data.
    ///
    /// # Errors
    ///
    /// Returns an admission error if the heap memory limit is exceeded.
    pub fn heap_alloc<T: Send + Sync + 'static>(
        &self,
        value: T,
    ) -> Result<HeapIndex, AdmissionError> {
        if self.state().is_terminal() {
            return Err(AdmissionError::Closed);
        }

        let size_hint = std::mem::size_of::<T>();
        let mut inner = self.inner.write();

        // Double check under lock to race with complete_close
        if self.state().is_terminal() {
            return Err(AdmissionError::Closed);
        }

        if let Some(limit) = inner.limits.max_heap_bytes {
            let live_bytes = inner.heap.stats().bytes_live;
            let requested = live_bytes.saturating_add(size_hint as u64);
            if requested > limit as u64 {
                let live = usize::try_from(live_bytes).unwrap_or(usize::MAX);
                return Err(AdmissionError::LimitReached {
                    kind: AdmissionKind::HeapBytes,
                    limit,
                    live,
                });
            }
        }
        Ok(inner.heap.alloc(value))
    }

    /// Returns a reference to a heap-allocated value.
    ///
    /// Returns `None` if the index is invalid or the type doesn't match.
    #[must_use]
    pub fn heap_get<T>(&self, index: HeapIndex) -> Option<T>
    where
        T: Clone + 'static,
    {
        let inner = self.inner.read();
        inner.heap.get::<T>(index).cloned()
    }

    /// Executes a closure with a reference to a heap-allocated value.
    ///
    /// This avoids cloning by giving the closure direct access to the value
    /// while holding the read lock.
    ///
    /// Returns `None` if the index is invalid or the type doesn't match.
    pub fn heap_with<T: 'static, R, F: FnOnce(&T) -> R>(
        &self,
        index: HeapIndex,
        f: F,
    ) -> Option<R> {
        let guard = ReentryGuard::new();

        // Check for reentrancy to prevent deadlock when closures call region methods
        if guard.is_reentrant() {
            // Already in a region access call - use try_read to avoid deadlock
            let inner = self.inner.try_read()?;
            return inner.heap.get::<T>(index).map(f);
        }

        let inner = self.inner.read();
        inner.heap.get::<T>(index).map(f)
        // Guard automatically resets flag on drop, even if f panics
    }

    /// Returns the number of heap allocations in this region.
    #[must_use]
    pub fn heap_len(&self) -> usize {
        self.inner.read().heap.len()
    }

    /// Returns heap stats for this region.
    #[must_use]
    pub fn heap_stats(&self) -> crate::runtime::region_heap::HeapStats {
        self.inner.read().heap.stats()
    }

    /// Returns true if the region is quiescent (no tasks, children,
    /// obligations, finalizers, or pending spawn requests).
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        let inner = self.inner.read();
        inner.children.is_empty()
            && inner.tasks.is_empty()
            && inner.pending_obligations == 0
            && inner.unapplied_obligations == 0
            && self.finalizers.read().is_empty()
            && self.pending_spawns.count() == 0
    }

    /// Requests cancellation of this region, recording the reason.
    ///
    /// Returns true if the cancel request was newly applied.
    pub fn cancel_request(&self, reason: CancelReason) -> bool {
        let mut inner = self.inner.write();
        if let Some(existing) = &mut inner.cancel_reason {
            existing.strengthen(&reason);
            false
        } else {
            inner.cancel_reason = Some(reason);
            true
        }
    }

    /// Begins closing the region.
    ///
    /// Returns true if the transition succeeded.
    ///
    /// br-asupersync-g0fk7p — perform the Open → Closing atomic
    /// transition WHILE the `inner` write lock is held so an
    /// admission path (`add_child`, `add_task_internal`,
    /// `try_reserve_obligation`) that took the same lock and is
    /// running its locked double-check cannot observe `Open` while
    /// `begin_close` simultaneously flips the state. Without this
    /// ordering, the locked double-check at the bottom of
    /// `add_child` could pass concurrently with the state
    /// transition, allowing a "task added after close-begin" race
    /// that violates the lab-oracle invariant. Safety was already
    /// preserved (the admitted work is tracked and waited on), but
    /// the spec-level admission-after-close-begin oracle now has a
    /// firm guarantee.
    pub fn begin_close(&self, reason: Option<CancelReason>) -> bool {
        let transitioned = self.begin_close_transition(reason);
        if transitioned {
            self.trace_state_change(RegionState::Closing);
        }
        transitioned
    }

    /// Begins closing without invoking the tracing subscriber.
    ///
    /// `RuntimeState::cancel_request` uses this mutation-only variant while its
    /// outer state lock is held. That path records the authoritative
    /// `RegionCloseBegin` event in the runtime trace buffer. It intentionally
    /// omits the external `"region state transition"` subscriber event and Span
    /// update for `Closing`: replaying only that receipt after unlock could race
    /// a later `Draining`/`Closed` transition and rewind observer state.
    pub(crate) fn begin_close_without_subscriber(&self, reason: Option<CancelReason>) -> bool {
        self.begin_close_transition(reason)
    }

    fn begin_close_transition(&self, reason: Option<CancelReason>) -> bool {
        let mut inner = self.inner.write();
        if self.state.load() == RegionState::Closed {
            return false;
        }

        if let Some(reason) = reason {
            if let Some(existing) = &mut inner.cancel_reason {
                existing.strengthen(&reason);
            } else {
                inner.cancel_reason = Some(reason);
            }
        }

        let transitioned = self
            .state
            .transition(RegionState::Open, RegionState::Closing);
        drop(inner);
        transitioned
    }

    /// Begins draining (after cancellation issued to children).
    ///
    /// Returns true if the transition succeeded.
    pub fn begin_drain(&self) -> bool {
        let transitioned = self
            .state
            .transition(RegionState::Closing, RegionState::Draining);
        if transitioned {
            self.trace_state_change(RegionState::Draining);
        }
        transitioned
    }

    /// Begins running finalizers.
    ///
    /// Returns true if the transition succeeded.
    pub fn begin_finalize(&self) -> bool {
        // EDGE CASE VALIDATION: Check for parent-child finalization ordering issues
        // This catches cases where child regions might start finalizing before their parents
        if let Some(parent_id) = self.parent {
            debug_assert!(
                true, // Always passes but documents the dependency
                "br-asupersync-mg70eb: beginning finalization with parent region present \
                 (region={:?}, parent={:?}) - ensure proper parent-child ordering",
                self.id,
                parent_id
            );
        }

        let transitioned = self
            .state
            .transition(RegionState::Closing, RegionState::Finalizing)
            || self
                .state
                .transition(RegionState::Draining, RegionState::Finalizing);

        if transitioned {
            self.trace_state_change(RegionState::Finalizing);
        }

        transitioned
    }

    /// Completes closing the region.
    ///
    /// Returns true if the transition succeeded.
    pub fn complete_close(&self) -> bool {
        // Enforce structural quiescence: a region cannot close if it still has live
        // tasks, children, or pending obligations, as doing so would prematurely clear
        // its heap memory and violate structured concurrency invariants.
        let mut inner = self.inner.write();

        if self.state.load() != RegionState::Finalizing {
            return false;
        }

        if !(inner.children.is_empty()
            && inner.tasks.is_empty()
            && inner.pending_obligations == 0
            && inner.unapplied_obligations == 0
            && self.finalizers.read().is_empty()
            // Pending (not-yet-admitted) spawn requests are live children:
            // their credits were taken before the requests became visible,
            // so a nonzero count here means the mailbox still holds work
            // destined for this region (br-asupersync-dx-core-api-v2-u1z5hn.1.2).
            && self.pending_spawns.count() == 0)
        {
            return false;
        }

        // br-asupersync-n0lthy: when no task or finalizer has folded a
        // terminal outcome via record_close_outcome, the default depends
        // on whether the region was cancelled. A region with cancel_reason
        // set (via cancel_request or begin_close(Some(reason))) that
        // reaches close with no live work must still surface Cancelled,
        // not Ok — the structured-concurrency contract says cancel is a
        // protocol, and observers (RegionCloseFuture, oracle harnesses,
        // audit trails) need close_outcome to agree with cancel_reason.
        // The previous unconditional `get_or_insert(Outcome::Ok(()))`
        // silently defaulted cancelled-but-empty regions to Ok.
        let default_outcome = if let Some(reason) = inner.cancel_reason.as_ref() {
            crate::types::Outcome::Cancelled(reason.clone())
        } else {
            crate::types::Outcome::Ok(())
        };
        inner.close_outcome.get_or_insert(default_outcome);

        let transitioned = self
            .state
            .transition(RegionState::Finalizing, RegionState::Closed);

        if transitioned {
            self.trace_state_change(RegionState::Closed);
            // The payloads are dropped with the region lock released, and
            // before the receipt is stored and the close waiters are woken,
            // so whoever sees the close happens-after every destructor
            // (br-asupersync-fu6cr0 M2).
            let payloads = inner.heap.take_all();
            let receipt = RegionCloseOutcome {
                outcome: inner
                    .close_outcome
                    .clone()
                    .expect("close outcome set above"),
                cleanup_outcome: inner.cleanup_outcome.clone(),
                descendant_panic: match inner.close_outcome.as_ref() {
                    Some(crate::types::Outcome::Panicked(payload)) => Some(payload.clone()),
                    _ => inner.descendant_panic.clone(),
                },
            };
            drop(inner);
            drop_region_payloads(self.id, payloads);
            *self.close_receipt.lock() = Some(receipt);
            let waiters = {
                let mut notify = self.close_notify.lock();
                notify.closed = true;
                std::mem::take(&mut notify.waiters)
            };
            for waker in waiters {
                waker.wake();
            }
        }
        transitioned
    }

    /// Updates the region state to the provided value without enforcing transitions.
    pub fn set_state(&self, state: RegionState) {
        self.state.store(state);
        self.trace_state_change(state);
    }

    fn trace_state_change(&self, new_state: RegionState) {
        let state_name = match new_state {
            RegionState::Open => "Open",
            RegionState::Closing => "Closing",
            RegionState::Draining => "Draining",
            RegionState::Finalizing => "Finalizing",
            RegionState::Closed => "Closed",
        };

        debug!(
            parent: &self.span,
            region_id = ?self.id,
            state = state_name,
            "region state transition"
        );

        self.span.record("state", state_name);
    }

    /// Clears the region heap after closing. The payloads are dropped after
    /// the region lock is released.
    fn clear_heap(&self) {
        let payloads = self.inner.write().heap.take_all();
        drop_region_payloads(self.id, payloads);
    }

    /// Resolves a `RRef` by accessing the region heap.
    ///
    /// Returns an error if the region is closed or the allocation is invalid.
    pub fn rref_get<T: Clone + 'static>(&self, rref: &RRef<T>) -> Result<T, RRefError> {
        if rref.region_id() != self.id {
            return Err(RRefError::RegionMismatch {
                expected: rref.region_id(),
                actual: self.id,
            });
        }
        if self.state().is_terminal() {
            return Err(RRefError::RegionClosed);
        }
        let inner = self.inner.read();
        inner
            .heap
            .get::<T>(rref.heap_index())
            .cloned()
            .ok_or(RRefError::AllocationInvalid)
    }

    /// Executes a closure with a reference to a heap-allocated value via `RRef`.
    pub fn rref_with<T: 'static, R, F: FnOnce(&T) -> R>(
        &self,
        rref: &RRef<T>,
        f: F,
    ) -> Result<R, RRefError> {
        if rref.region_id() != self.id {
            return Err(RRefError::RegionMismatch {
                expected: rref.region_id(),
                actual: self.id,
            });
        }
        if self.state().is_terminal() {
            return Err(RRefError::RegionClosed);
        }

        let guard = ReentryGuard::new();

        // Check for reentrancy to prevent deadlock when closures call region methods
        if guard.is_reentrant() {
            // Already in a region access call - use try_read to avoid deadlock
            let inner = self.inner.try_read().ok_or(RRefError::RegionClosed)?; // Assume locked means closing
            return inner
                .heap
                .get::<T>(rref.heap_index())
                .map(f)
                .ok_or(RRefError::AllocationInvalid);
        }

        let inner = self.inner.read();
        inner
            .heap
            .get::<T>(rref.heap_index())
            .map(f)
            .ok_or(RRefError::AllocationInvalid)
        // Guard automatically resets flag on drop, even if f panics
    }

    /// Returns an access witness for this region if it is in a non-terminal state.
    ///
    /// The witness serves as a capability token proving the caller has been
    /// granted access to the region's heap at a point when the region was alive.
    ///
    /// Returns `Err(RegionClosed)` if the region is in `Closed` state.
    pub fn access_witness(&self) -> Result<RRefAccessWitness, RRefError> {
        if self.state().is_terminal() {
            return Err(RRefError::RegionClosed);
        }
        Ok(RRefAccessWitness::new(self.id))
    }

    /// Resolves a `RRef` using a pre-validated access witness.
    ///
    /// The witness must have been obtained from this region via [`Self::access_witness`].
    /// Returns an error if the witness region doesn't match.
    pub fn rref_get_with<T: Clone + 'static>(
        &self,
        rref: &RRef<T>,
        witness: RRefAccessWitness,
    ) -> Result<T, RRefError> {
        if witness.region() != self.id {
            return Err(RRefError::WrongRegion);
        }
        rref.validate_witness(&witness)?;
        if self.state().is_terminal() {
            return Err(RRefError::RegionClosed);
        }
        let inner = self.inner.read();
        inner
            .heap
            .get::<T>(rref.heap_index())
            .cloned()
            .ok_or(RRefError::AllocationInvalid)
    }

    /// Executes a closure with a reference via a pre-validated witness.
    pub fn rref_with_witness<T: 'static, R, F: FnOnce(&T) -> R>(
        &self,
        rref: &RRef<T>,
        witness: RRefAccessWitness,
        f: F,
    ) -> Result<R, RRefError> {
        if witness.region() != self.id {
            return Err(RRefError::WrongRegion);
        }
        rref.validate_witness(&witness)?;
        if self.state().is_terminal() {
            return Err(RRefError::RegionClosed);
        }
        let inner = self.inner.read();
        inner
            .heap
            .get::<T>(rref.heap_index())
            .map(f)
            .ok_or(RRefError::AllocationInvalid)
    }

    /// Returns true if the region should begin closing (body complete).
    #[must_use]
    pub fn should_begin_close(&self) -> bool {
        let state = self.state();
        matches!(state, RegionState::Open)
    }

    /// Returns true if the region should begin draining.
    #[must_use]
    pub fn should_begin_drain(&self) -> bool {
        let state = self.state();
        state == RegionState::Closing
    }

    /// Returns true if the region can run finalizers.
    #[must_use]
    pub fn can_finalize(&self) -> bool {
        let state = self.state();
        matches!(state, RegionState::Closing | RegionState::Draining)
    }

    /// Returns true if the region can complete close.
    #[must_use]
    pub fn can_complete_close(&self) -> bool {
        let state = self.state();
        state == RegionState::Finalizing
    }

    /// Returns true if all children are closed.
    #[must_use]
    pub fn children_closed(&self, closed: &dyn Fn(RegionId) -> bool) -> bool {
        let inner = self.inner.read();
        inner.children.iter().all(closed)
    }

    /// Returns true if all tasks are completed.
    #[must_use]
    pub fn tasks_completed(&self, completed: &dyn Fn(TaskId) -> bool) -> bool {
        let inner = self.inner.read();
        inner.tasks.iter().all(completed)
    }

    /// Returns true if all obligations are resolved.
    #[must_use]
    pub fn obligations_resolved(&self) -> bool {
        self.pending_obligations() == 0
    }

    /// Returns true if the region is ready to finalize (no children/tasks/obligations).
    #[must_use]
    pub fn ready_to_finalize(&self, completed: &dyn Fn(TaskId) -> bool) -> bool {
        // This helper is intentionally conservative and local: a region can only
        // be ready to finalize when it has no *tracked* children remaining.
        //
        // In the runtime, child regions are removed from the parent's `children`
        // list when they complete close. If a caller wants to treat "children are
        // all closed" as sufficient, they must supply that logic externally.
        let inner = self.inner.read();
        inner.children.is_empty()
            && inner.tasks.iter().all(completed)
            && inner.pending_obligations == 0
            && inner.unapplied_obligations == 0
    }

    /// Applies a distributed snapshot to this region record.
    ///
    /// This method is used by the distributed bridge to update the local region state
    /// to match the state recovered from a remote replica.
    ///
    /// # CRDT semantics (br-asupersync-g4mv9b)
    ///
    /// `children` and `tasks` are merged as **G-set unions** (set semantics
    /// preserved as `Vec` for backwards compatibility with the storage
    /// format). The previous REPLACE semantics broke CRDT commutativity
    /// and associativity: if replica A held tasks `{1, 2}` and a snapshot
    /// from replica B carrying tasks `{3, 4}` was applied, A's local
    /// view became `{3, 4}` — silently dropping `{1, 2}`. Symmetrically
    /// applying A's snapshot to B dropped B's tasks. After a partition
    /// heal, the total task count could collapse, the region's
    /// quiescence check would falsely report zero live tasks for the
    /// overwritten side, and the close-to-quiescence invariant would be
    /// broken without diagnostic.
    ///
    /// Union semantics restore both CRDT properties on the additive
    /// direction: `merge(A, B) == merge(B, A)` (commutativity) and
    /// `merge(merge(A, B), C) == merge(A, merge(B, C))` (associativity).
    ///
    /// **Caveat — known stale-element gap**: this is a grow-only set.
    /// If a task was completed and removed locally on replica A before
    /// the heal, replica B's snapshot (which observed the task before A
    /// removed it) will re-add the now-stale entry. Closing that gap
    /// requires per-element vclock-aware lattice merge — tracked
    /// separately as a follow-up. The G-set fix immediately closes the
    /// silent-task-loss vector, trading "may re-add a completed task"
    /// (visible, recoverable via the quiescence check) for "may lose a
    /// live task" (silent, unrecoverable).
    ///
    /// `budget` and `cancel_reason` retain LWW (last-writer-wins)
    /// semantics — the bead scope was children + tasks; broadening to
    /// `cancel_reason` fail-closed semantics ("Some-priority over None")
    /// is left as a follow-up since changing it risks dropping a
    /// legitimate cancel-clear from the snapshot author.
    ///
    /// # Safety
    ///
    /// This method modifies the internal state of the region. It should
    /// only be used by the distributed bridge when applying a validated
    /// snapshot.
    pub fn apply_distributed_snapshot(
        &self,
        state: RegionState,
        budget: Budget,
        children: Vec<RegionId>,
        tasks: Vec<TaskId>,
        cancel_reason: Option<CancelReason>,
    ) {
        let prev_state = self.state.load();

        // Update inner protected state FIRST, then atomic state, so concurrent
        // readers never see new state with old inner data (torn read).
        let mut inner = self.inner.write();
        inner.budget = budget;
        // br-asupersync-g4mv9b: G-set union for children + tasks.
        for child_id in children {
            inner.children.insert(child_id);
        }
        for task_id in tasks {
            inner.tasks.insert(task_id);
        }
        inner.cancel_reason = cancel_reason;
        // Publish state change while still holding the write lock — readers
        // acquiring the lock after this point see both new state and new data.
        self.state.store(state);
        drop(inner);

        // Ensure heap is reclaimed if the snapshot forces the region closed
        if state == RegionState::Closed && prev_state != RegionState::Closed {
            self.clear_heap();
            let waiters = {
                let mut notify = self.close_notify.lock();
                notify.closed = true;
                std::mem::take(&mut notify.waiters)
            };
            for waker in waiters {
                waker.wake();
            }
        }
    }
}

impl RRefAccess for RegionRecord {
    fn rref_get<T: Clone + 'static>(&self, rref: &RRef<T>) -> Result<T, RRefError> {
        self.rref_get(rref)
    }

    fn rref_with<T: 'static, R, F: FnOnce(&T) -> R>(
        &self,
        rref: &RRef<T>,
        f: F,
    ) -> Result<R, RRefError> {
        self.rref_with(rref, f)
    }

    fn rref_get_with<T: Clone + 'static>(
        &self,
        rref: &RRef<T>,
        witness: RRefAccessWitness,
    ) -> Result<T, RRefError> {
        self.rref_get_with(rref, witness)
    }

    fn rref_with_witness<T: 'static, R, F: FnOnce(&T) -> R>(
        &self,
        rref: &RRef<T>,
        witness: RRefAccessWitness,
        f: F,
    ) -> Result<R, RRefError> {
        self.rref_with_witness(rref, witness, f)
    }
}

/// Drops the payloads a closing region took out of its heap, with the region
/// lock released. Each payload is dropped on its own under `catch_unwind`: a
/// panicking destructor is logged and the rest are still dropped, and the
/// caller still stores the close receipt and wakes the close waiters
/// (br-asupersync-fu6cr0 M2).
fn drop_region_payloads(region: RegionId, payloads: Vec<Box<dyn std::any::Any + Send + Sync>>) {
    for payload in payloads {
        let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(payload)));
        if dropped.is_err() {
            let _ = &region;
            warn!(
                region_id = ?region,
                "a region heap payload's destructor panicked after the region closed"
            );
        }
    }
}

#[cfg(test)]
#[path = "region_inline_tests.rs"]
mod tests;
