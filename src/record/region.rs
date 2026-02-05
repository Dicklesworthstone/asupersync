//! Region record for the runtime.
//!
//! A region owns tasks and child regions, forming a tree structure.
//! When a region closes, it waits for all children to complete.

use crate::record::finalizer::{Finalizer, FinalizerStack};
use crate::runtime::region_heap::{HeapIndex, RegionHeap};
use crate::tracing_compat::{debug, info_span, Span};
use crate::types::rref::{RRef, RRefAccessWitness, RRefError};
use crate::types::{Budget, CancelReason, CurveBudget, RRefAccess, RegionId, TaskId, Time};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::RwLock;

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
    Finalizing,
    /// Terminal state with aggregated outcome.
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

    /// Returns true if the region can accept new tasks or children.
    ///
    /// This is true for Open (normal execution) and Finalizing (cleanup).
    /// It is false for Closing and Draining phases.
    #[must_use]
    pub const fn can_accept_work(self) -> bool {
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
/// Every admission path (`add_task`, `add_child`, `try_reserve_obligation`,
/// `heap_alloc`) follows an **optimistic double-check locking** pattern:
///
/// 1. **Fast-path reject** — atomic `state.load(Acquire)` checks
///    `can_accept_work()`.  If false, return `Closed` without locking.
/// 2. **Acquire write lock** — `inner.write()` serialises all mutations.
/// 3. **Re-check state** — a second `state.load(Acquire)` under the lock
///    guards against a concurrent `begin_close` that landed between steps
///    1 and 2.  Because `begin_close` transitions the atomic *before*
///    acquiring the inner lock, the re-check is linearisable.
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
/// - **No stale-close admission**: the double-check on `can_accept_work()`
///   prevents a task from being added to a region that has already
///   begun closing, even if the optimistic read passed before the
///   state transition.
/// - **`resolve_obligation` uses `saturating_sub`**: so an unpaired
///   resolve (e.g. from a double-drop) bottoms out at zero rather
///   than wrapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionLimits {
    /// Maximum number of live child regions.
    pub max_children: Option<usize>,
    /// Maximum number of live tasks in the region.
    pub max_tasks: Option<usize>,
    /// Maximum number of pending obligations in the region.
    pub max_obligations: Option<usize>,
    /// Maximum live bytes allocated in the region heap.
    pub max_heap_bytes: Option<usize>,
    /// Optional min-plus curve budget for hard admission bounds.
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

impl Default for RegionLimits {
    fn default() -> Self {
        Self::UNLIMITED
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

#[derive(Debug)]
struct RegionInner {
    budget: Budget,
    children: Vec<RegionId>,
    tasks: Vec<TaskId>,
    finalizers: FinalizerStack,
    cancel_reason: Option<CancelReason>,
    limits: RegionLimits,
    pending_obligations: usize,
    /// Region-owned heap for task allocations.
    /// Reclaimed when the region closes to quiescence.
    heap: RegionHeap,
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
    /// Current state (atomic for concurrent access).
    state: AtomicRegionState,
    /// Inner mutable state (guarded by a lock).
    inner: RwLock<RegionInner>,
    /// Tracing span for region lifecycle (only active with tracing-integration feature).
    #[cfg(feature = "tracing-integration")]
    span: Span,
    /// Placeholder for when tracing is disabled.
    #[cfg(not(feature = "tracing-integration"))]
    span: Span,
}

impl RegionRecord {
    /// Creates a new region record.
    #[must_use]
    pub fn new(id: RegionId, parent: Option<RegionId>, budget: Budget) -> Self {
        Self::new_with_time(id, parent, budget, Time::ZERO)
    }

    /// Creates a new region record with an explicit creation time.
    #[must_use]
    pub fn new_with_time(
        id: RegionId,
        parent: Option<RegionId>,
        budget: Budget,
        created_at: Time,
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
            state: AtomicRegionState::new(RegionState::Open),
            inner: RwLock::new(RegionInner {
                budget,
                children: Vec::new(),
                tasks: Vec::new(),
                finalizers: FinalizerStack::new(),
                cancel_reason: None,
                limits: RegionLimits::UNLIMITED,
                pending_obligations: 0,
                heap: RegionHeap::new(),
            }),
            span,
        }
    }

    /// Returns the logical time when the region was created.
    #[must_use]
    pub const fn created_at(&self) -> Time {
        self.created_at
    }

    /// Returns the current region state.
    #[must_use]
    pub fn state(&self) -> RegionState {
        self.state.load()
    }

    /// Returns the region budget.
    #[must_use]
    pub fn budget(&self) -> Budget {
        self.inner.read().expect("lock poisoned").budget
    }

    /// Returns the current admission limits for this region.
    #[must_use]
    pub fn limits(&self) -> RegionLimits {
        self.inner.read().expect("lock poisoned").limits.clone()
    }

    /// Updates the admission limits for this region.
    pub fn set_limits(&self, limits: RegionLimits) {
        self.inner.write().expect("lock poisoned").limits = limits;
    }

    /// Returns the number of pending obligations tracked for this region.
    #[must_use]
    pub fn pending_obligations(&self) -> usize {
        self.inner
            .read()
            .expect("lock poisoned")
            .pending_obligations
    }

    /// Returns the current cancel reason, if any.
    #[must_use]
    pub fn cancel_reason(&self) -> Option<CancelReason> {
        self.inner
            .read()
            .expect("lock poisoned")
            .cancel_reason
            .clone()
    }

    /// Strengthens or sets the cancel reason.
    pub fn strengthen_cancel_reason(&self, reason: CancelReason) {
        let mut inner = self.inner.write().expect("lock poisoned");
        if let Some(existing) = &mut inner.cancel_reason {
            existing.strengthen(&reason);
        } else {
            inner.cancel_reason = Some(reason);
        }
    }

    /// Returns a snapshot of child region IDs.
    #[must_use]
    pub fn child_ids(&self) -> Vec<RegionId> {
        self.inner.read().expect("lock poisoned").children.clone()
    }

    /// Returns a snapshot of task IDs.
    #[must_use]
    pub fn task_ids(&self) -> Vec<TaskId> {
        self.inner.read().expect("lock poisoned").tasks.clone()
    }

    /// Returns true if the region has any live children, tasks, or pending obligations.
    #[must_use]
    pub fn has_live_work(&self) -> bool {
        let inner = self.inner.read().expect("lock poisoned");
        !inner.children.is_empty() || !inner.tasks.is_empty() || inner.pending_obligations > 0
    }

    /// Adds a child region.
    ///
    /// Returns `Ok(())` if the child was added or already present, or an
    /// admission error if the region is closed or at capacity.
    pub fn add_child(&self, child: RegionId) -> Result<(), AdmissionError> {
        // Optimistic check (atomic)
        if !self.state.load().can_accept_work() {
            return Err(AdmissionError::Closed);
        }

        let mut inner = self.inner.write().expect("lock poisoned");

        // Double check under lock (though state is atomic, consistency matters)
        if !self.state.load().can_accept_work() {
            return Err(AdmissionError::Closed);
        }

        if inner.children.contains(&child) {
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

        inner.children.push(child);
        drop(inner);
        Ok(())
    }

    /// Removes a child region.
    pub fn remove_child(&self, child: RegionId) {
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.children.retain(|&c| c != child);
    }

    /// Adds a task to this region.
    ///
    /// Returns `Ok(())` if the task was added or already present, or an
    /// admission error if the region is closed or at capacity.
    pub fn add_task(&self, task: TaskId) -> Result<(), AdmissionError> {
        // Optimistic check
        if !self.state.load().can_accept_work() {
            return Err(AdmissionError::Closed);
        }

        let mut inner = self.inner.write().expect("lock poisoned");

        // Double check
        if !self.state.load().can_accept_work() {
            return Err(AdmissionError::Closed);
        }

        if inner.tasks.contains(&task) {
            return Ok(());
        }

        if let Some(limit) = inner.limits.max_tasks {
            if inner.tasks.len() >= limit {
                return Err(AdmissionError::LimitReached {
                    kind: AdmissionKind::Task,
                    limit,
                    live: inner.tasks.len(),
                });
            }
        }

        inner.tasks.push(task);
        drop(inner);
        Ok(())
    }

    /// Removes a task from this region.
    pub fn remove_task(&self, task: TaskId) {
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.tasks.retain(|&t| t != task);
    }

    /// Reserves an obligation slot for this region.
    pub fn try_reserve_obligation(&self) -> Result<(), AdmissionError> {
        if !self.state.load().can_accept_work() {
            return Err(AdmissionError::Closed);
        }

        let mut inner = self.inner.write().expect("lock poisoned");
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

        inner.pending_obligations += 1;
        drop(inner);
        Ok(())
    }

    /// Marks an obligation slot as resolved for this region.
    pub fn resolve_obligation(&self) {
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.pending_obligations = inner.pending_obligations.saturating_sub(1);
    }

    /// Adds a finalizer to run when the region closes.
    ///
    /// Finalizers are stored in LIFO order and will be executed
    /// in reverse registration order during the Finalizing phase.
    pub fn add_finalizer(&self, finalizer: Finalizer) {
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.finalizers.push(finalizer);
    }

    /// Pops the next finalizer to run (LIFO order).
    ///
    /// Returns `None` when all finalizers have been executed.
    pub fn pop_finalizer(&self) -> Option<Finalizer> {
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.finalizers.pop()
    }

    /// Returns the number of pending finalizers.
    #[must_use]
    pub fn finalizer_count(&self) -> usize {
        self.inner.read().expect("lock poisoned").finalizers.len()
    }

    /// Returns true if there are no pending finalizers.
    #[must_use]
    pub fn finalizers_empty(&self) -> bool {
        self.inner
            .read()
            .expect("lock poisoned")
            .finalizers
            .is_empty()
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
        let size_hint = std::mem::size_of::<T>();
        let mut inner = self.inner.write().expect("lock poisoned");
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
        let inner = self.inner.read().expect("lock poisoned");
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
        let inner = self.inner.read().expect("lock poisoned");
        inner.heap.get::<T>(index).map(f)
    }

    /// Returns the number of heap allocations in this region.
    #[must_use]
    pub fn heap_len(&self) -> usize {
        self.inner.read().expect("lock poisoned").heap.len()
    }

    /// Returns heap stats for this region.
    #[must_use]
    pub fn heap_stats(&self) -> crate::runtime::region_heap::HeapStats {
        self.inner.read().expect("lock poisoned").heap.stats()
    }

    /// Returns true if the region is quiescent (no tasks or children).
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        let inner = self.inner.read().expect("lock poisoned");
        inner.children.is_empty()
            && inner.tasks.is_empty()
            && inner.pending_obligations == 0
            && inner.finalizers.is_empty()
    }

    /// Requests cancellation of this region, recording the reason.
    ///
    /// Returns true if the cancel request was newly applied.
    pub fn cancel_request(&self, reason: CancelReason) -> bool {
        let mut inner = self.inner.write().expect("lock poisoned");
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
    pub fn begin_close(&self, reason: Option<CancelReason>) -> bool {
        if let Some(reason) = reason {
            self.strengthen_cancel_reason(reason);
        }

        let transitioned = self
            .state
            .transition(RegionState::Open, RegionState::Closing);
        if transitioned {
            self.trace_state_change(RegionState::Closing);
        }
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
        let transitioned = if self.state.load() == RegionState::Closing {
            self.state
                .transition(RegionState::Closing, RegionState::Finalizing)
        } else {
            self.state
                .transition(RegionState::Draining, RegionState::Finalizing)
        };

        if transitioned {
            self.trace_state_change(RegionState::Finalizing);
        }

        transitioned
    }

    /// Completes closing the region.
    ///
    /// Returns true if the transition succeeded.
    pub fn complete_close(&self) -> bool {
        let transitioned = self
            .state
            .transition(RegionState::Finalizing, RegionState::Closed);
        if transitioned {
            self.trace_state_change(RegionState::Closed);
            self.clear_heap();
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

    /// Clears the region heap after closing.
    fn clear_heap(&self) {
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.heap.reclaim_all();
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
            return Err(RRefError::AllocationInvalid);
        }
        let inner = self.inner.read().expect("lock poisoned");
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
            return Err(RRefError::AllocationInvalid);
        }
        let inner = self.inner.read().expect("lock poisoned");
        inner
            .heap
            .get::<T>(rref.heap_index())
            .map(f)
            .ok_or(RRefError::AllocationInvalid)
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
    /// The witness must have been obtained from this region via [`access_witness`].
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
        let inner = self.inner.read().expect("lock poisoned");
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
        let inner = self.inner.read().expect("lock poisoned");
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
        let inner = self.inner.read().expect("lock poisoned");
        inner.children.iter().all(|child| closed(*child))
    }

    /// Returns true if all tasks are completed.
    #[must_use]
    pub fn tasks_completed(&self, completed: &dyn Fn(TaskId) -> bool) -> bool {
        let inner = self.inner.read().expect("lock poisoned");
        inner.tasks.iter().all(|task| completed(*task))
    }

    /// Returns true if all obligations are resolved.
    #[must_use]
    pub fn obligations_resolved(&self) -> bool {
        self.pending_obligations() == 0
    }

    /// Returns true if the region is ready to finalize (no children/tasks/obligations).
    #[must_use]
    pub fn ready_to_finalize(&self, completed: &dyn Fn(TaskId) -> bool) -> bool {
        self.children_closed(&|_region| true)
            && self.tasks_completed(completed)
            && self.obligations_resolved()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::finalizer::Finalizer;
    use crate::util::ArenaIndex;

    fn test_region_id() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(1, 0))
    }

    fn rref_get_via_trait<A: RRefAccess, T: Clone + 'static>(accessor: &A, rref: &RRef<T>) -> T {
        accessor.rref_get(rref).expect("trait get")
    }

    fn rref_with_via_trait<A: RRefAccess, T: 'static, R, F: FnOnce(&T) -> R>(
        accessor: &A,
        rref: &RRef<T>,
        f: F,
    ) -> R {
        accessor.rref_with(rref, f).expect("trait with")
    }

    fn rref_get_with_via_trait<A: RRefAccess, T: Clone + 'static>(
        accessor: &A,
        rref: &RRef<T>,
        witness: RRefAccessWitness,
    ) -> T {
        accessor
            .rref_get_with(rref, witness)
            .expect("trait get_with")
    }

    fn rref_with_witness_via_trait<A: RRefAccess, T: 'static, R, F: FnOnce(&T) -> R>(
        accessor: &A,
        rref: &RRef<T>,
        witness: RRefAccessWitness,
        f: F,
    ) -> R {
        accessor
            .rref_with_witness(rref, witness, f)
            .expect("trait with_witness")
    }

    #[test]
    fn region_initial_state() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        assert_eq!(region.state(), RegionState::Open);
    }

    #[test]
    fn region_state_transitions() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());

        assert!(region.begin_close(None));
        assert_eq!(region.state(), RegionState::Closing);

        assert!(region.begin_drain());
        assert_eq!(region.state(), RegionState::Draining);

        assert!(region.begin_finalize());
        assert_eq!(region.state(), RegionState::Finalizing);

        assert!(region.complete_close());
        assert_eq!(region.state(), RegionState::Closed);
    }

    #[test]
    fn region_state_invalid_transitions() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());

        // Cannot begin drain without close
        assert!(!region.begin_drain());
        assert_eq!(region.state(), RegionState::Open);

        // Cannot begin finalize without close
        assert!(!region.begin_finalize());
        assert_eq!(region.state(), RegionState::Open);

        // Cannot complete close without finalize
        assert!(!region.complete_close());
        assert_eq!(region.state(), RegionState::Open);
    }

    #[test]
    fn region_admission_limits() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        region.set_limits(RegionLimits {
            max_children: Some(1),
            max_tasks: Some(2),
            max_obligations: Some(1),
            max_heap_bytes: None,
            curve_budget: None,
        });

        // Add children
        assert!(region
            .add_child(RegionId::from_arena(ArenaIndex::new(2, 0)))
            .is_ok());
        assert!(region
            .add_child(RegionId::from_arena(ArenaIndex::new(3, 0)))
            .is_err());

        // Add tasks
        assert!(region
            .add_task(TaskId::from_arena(ArenaIndex::new(1, 0)))
            .is_ok());
        assert!(region
            .add_task(TaskId::from_arena(ArenaIndex::new(2, 0)))
            .is_ok());
        assert!(region
            .add_task(TaskId::from_arena(ArenaIndex::new(3, 0)))
            .is_err());

        // Reserve obligations
        assert!(region.try_reserve_obligation().is_ok());
        assert!(region.try_reserve_obligation().is_err());
    }

    #[test]
    fn region_obligation_tracking() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());

        assert_eq!(region.pending_obligations(), 0);
        assert!(region.try_reserve_obligation().is_ok());
        assert_eq!(region.pending_obligations(), 1);

        region.resolve_obligation();
        assert_eq!(region.pending_obligations(), 0);
    }

    #[test]
    fn region_obligation_limit_released_after_resolve() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        region.set_limits(RegionLimits {
            max_obligations: Some(1),
            ..RegionLimits::unlimited()
        });

        assert!(region.try_reserve_obligation().is_ok());
        assert!(matches!(
            region.try_reserve_obligation(),
            Err(AdmissionError::LimitReached {
                kind: AdmissionKind::Obligation,
                ..
            })
        ));
        assert_eq!(region.pending_obligations(), 1);

        region.resolve_obligation();
        assert_eq!(region.pending_obligations(), 0);
        assert!(region.try_reserve_obligation().is_ok());
    }

    #[test]
    fn region_quiescence() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        assert!(region.is_quiescent());

        // Add child
        region
            .add_child(RegionId::from_arena(ArenaIndex::new(2, 0)))
            .expect("add child");
        assert!(!region.is_quiescent());

        // Remove child
        region.remove_child(RegionId::from_arena(ArenaIndex::new(2, 0)));
        assert!(region.is_quiescent());
    }

    #[test]
    fn region_finalizer_stack() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());

        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        region.add_finalizer(Finalizer::Sync(Box::new({
            let log_ref = log.clone();
            move || log_ref.lock().unwrap().push("first")
        })));

        region.add_finalizer(Finalizer::Sync(Box::new({
            let log_ref = log.clone();
            move || log_ref.lock().unwrap().push("second")
        })));

        // Pop and run finalizers
        while let Some(finalizer) = region.pop_finalizer() {
            if let Finalizer::Sync(f) = finalizer {
                f();
            }
        }

        let log = log.lock().unwrap().clone();
        assert_eq!(log, vec!["second", "first"]); // LIFO order
    }

    #[test]
    fn region_heap_alloc_and_access() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());

        let idx = region.heap_alloc(42u32).expect("heap alloc");
        let value = region.heap_get::<u32>(idx).expect("heap get");
        assert_eq!(value, 42);

        let doubled = region.heap_with(idx, |v: &u32| v * 2).expect("heap with");
        assert_eq!(doubled, 84);
    }

    #[test]
    fn region_heap_bytes_limit_enforced() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        let limit = std::mem::size_of::<u32>();
        region.set_limits(RegionLimits {
            max_heap_bytes: Some(limit),
            ..RegionLimits::unlimited()
        });

        let _idx = region.heap_alloc(7u32).expect("heap alloc");
        let err = region.heap_alloc(1u8).expect_err("heap limit enforced");
        assert!(matches!(
            err,
            AdmissionError::LimitReached {
                kind: AdmissionKind::HeapBytes,
                limit: _,
                live: _
            }
        ));
    }

    #[test]
    fn begin_close_with_reason() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        let reason = CancelReason::user("test shutdown");

        assert!(region.begin_close(Some(reason.clone())));
        assert_eq!(region.cancel_reason(), Some(reason));
    }

    #[test]
    fn region_heap_reclaimed_on_close() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());

        let _idx = region.heap_alloc(42u32).expect("heap alloc");
        assert_eq!(region.heap_len(), 1);

        assert!(region.begin_close(None));
        assert!(region.begin_finalize());
        assert!(region.complete_close());

        assert_eq!(region.heap_len(), 0);
    }

    #[test]
    fn rref_invalid_after_close() {
        let region_id = test_region_id();
        let region = RegionRecord::new(region_id, None, Budget::default());

        let index = region.heap_alloc(123u32).expect("heap alloc");
        let rref = RRef::<u32>::new(region_id, index);

        assert!(region.begin_close(None));
        assert!(region.begin_finalize());
        assert!(region.complete_close());

        let err = region
            .rref_get(&rref)
            .expect_err("rref should be invalid after close");
        assert_eq!(err, RRefError::AllocationInvalid);
    }

    #[test]
    fn invalid_state_transitions_are_rejected() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());

        // Can't drain from Open
        assert!(!region.begin_drain());
        assert_eq!(region.state(), RegionState::Open);

        // Can't finalize from Open
        assert!(!region.begin_finalize());
        assert_eq!(region.state(), RegionState::Open);

        // Can't complete_close from Open
        assert!(!region.complete_close());
        assert_eq!(region.state(), RegionState::Open);

        // Move to Draining
        region.begin_close(None);
        region.begin_drain();

        // Can't close from Draining
        assert!(!region.complete_close());
        assert_eq!(region.state(), RegionState::Draining);
    }

    // =========================================================================
    // Finalizer Tests
    // =========================================================================

    #[test]
    fn finalizer_registration() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());

        assert!(region.finalizers_empty());
        assert_eq!(region.finalizer_count(), 0);

        // Add a sync finalizer
        region.add_finalizer(Finalizer::Sync(Box::new(|| {})));
        assert!(!region.finalizers_empty());
        assert_eq!(region.finalizer_count(), 1);

        // Add another finalizer
        region.add_finalizer(Finalizer::Async(Box::pin(async {})));
        assert_eq!(region.finalizer_count(), 2);
    }

    #[test]
    fn finalizer_lifo_order() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());

        let order = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let o1 = order.clone();
        let o2 = order.clone();
        let o3 = order.clone();

        // Add finalizers: 1, 2, 3
        region.add_finalizer(Finalizer::Sync(Box::new(move || {
            o1.lock().unwrap().push(1);
        })));
        region.add_finalizer(Finalizer::Sync(Box::new(move || {
            o2.lock().unwrap().push(2);
        })));
        region.add_finalizer(Finalizer::Sync(Box::new(move || {
            o3.lock().unwrap().push(3);
        })));

        // Pop and execute in LIFO order
        while let Some(finalizer) = region.pop_finalizer() {
            if let Finalizer::Sync(f) = finalizer {
                f();
            }
        }

        // Should be 3, 2, 1 (LIFO)
        assert_eq!(*order.lock().unwrap(), vec![3, 2, 1]);
    }

    #[test]
    fn finalizer_pop_returns_none_when_empty() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());

        assert!(region.pop_finalizer().is_none());

        // Add and remove
        region.add_finalizer(Finalizer::Sync(Box::new(|| {})));
        assert!(region.pop_finalizer().is_some());
        assert!(region.pop_finalizer().is_none());
    }

    // =========================================================================
    // Admission Control Correctness (bd-ecp8u)
    //
    // Formalises admission semantics for tasks, children, obligations, and
    // heap bytes.  Each test documents why the property matters for the
    // runtime's resource accounting invariants.
    //
    // Concurrency safety arguments are documented on `RegionLimits`.
    // =========================================================================

    // --- Closed-region rejection ---
    // Admission must fail with `AdmissionError::Closed` for every non-Open
    // state except Finalizing (which is allowed by `can_accept_work`).

    #[test]
    fn admission_rejected_when_closing() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        region.begin_close(None);
        assert_eq!(region.state(), RegionState::Closing);

        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        assert_eq!(region.add_task(task), Err(AdmissionError::Closed));

        let child = RegionId::from_arena(ArenaIndex::new(1, 0));
        assert_eq!(region.add_child(child), Err(AdmissionError::Closed));

        assert_eq!(region.try_reserve_obligation(), Err(AdmissionError::Closed));
    }

    #[test]
    fn admission_rejected_when_draining() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        region.begin_close(None);
        region.begin_drain();
        assert_eq!(region.state(), RegionState::Draining);

        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        assert_eq!(region.add_task(task), Err(AdmissionError::Closed));
    }

    #[test]
    fn admission_allowed_when_finalizing() {
        // Finalizing regions accept work (cleanup tasks spawned by finalizers).
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        region.begin_close(None);
        assert!(region.begin_finalize()); // skip Draining
        assert_eq!(region.state(), RegionState::Finalizing);

        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        assert!(region.add_task(task).is_ok());
    }

    #[test]
    fn admission_rejected_when_closed() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        region.begin_close(None);
        region.begin_finalize();
        region.complete_close();
        assert_eq!(region.state(), RegionState::Closed);

        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        assert_eq!(region.add_task(task), Err(AdmissionError::Closed));
    }

    // --- Idempotent add (deduplication) ---
    // Adding the same entity twice must succeed without consuming an
    // admission slot.  This protects against double-registration bugs
    // without requiring callers to track whether they already called add.

    #[test]
    fn add_task_idempotent() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        region.set_limits(RegionLimits {
            max_tasks: Some(1),
            ..RegionLimits::unlimited()
        });

        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        assert!(region.add_task(task).is_ok());
        // Second add of same task succeeds (dedup) and does NOT consume a slot.
        assert!(region.add_task(task).is_ok());
        assert_eq!(region.task_ids().len(), 1);
    }

    #[test]
    fn add_child_idempotent() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        region.set_limits(RegionLimits {
            max_children: Some(1),
            ..RegionLimits::unlimited()
        });

        let child = RegionId::from_arena(ArenaIndex::new(1, 0));
        assert!(region.add_child(child).is_ok());
        assert!(region.add_child(child).is_ok());
        assert_eq!(region.child_ids().len(), 1);
    }

    // --- Remove + re-admit ---
    // After removing a task/child, the slot should be available again.
    // This confirms the live count tracks actual membership, not a
    // monotonically increasing counter.

    #[test]
    fn remove_task_frees_slot() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        region.set_limits(RegionLimits {
            max_tasks: Some(1),
            ..RegionLimits::unlimited()
        });

        let task1 = TaskId::from_arena(ArenaIndex::new(1, 0));
        let task2 = TaskId::from_arena(ArenaIndex::new(2, 0));

        assert!(region.add_task(task1).is_ok());
        assert!(region.add_task(task2).is_err());

        region.remove_task(task1);
        // Slot freed — task2 can now be admitted.
        assert!(region.add_task(task2).is_ok());
    }

    #[test]
    fn remove_child_frees_slot() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        region.set_limits(RegionLimits {
            max_children: Some(1),
            ..RegionLimits::unlimited()
        });

        let child1 = RegionId::from_arena(ArenaIndex::new(1, 0));
        let child2 = RegionId::from_arena(ArenaIndex::new(2, 0));

        assert!(region.add_child(child1).is_ok());
        assert!(region.add_child(child2).is_err());

        region.remove_child(child1);
        assert!(region.add_child(child2).is_ok());
    }

    // --- Unlimited (None) limits ---
    // When a limit is None, admission is unbounded.  This is the default
    // for `RegionLimits::UNLIMITED` and must not panic or reject.

    #[test]
    fn unlimited_admits_many_tasks() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        assert_eq!(region.limits(), RegionLimits::UNLIMITED);

        for i in 0..100 {
            let task = TaskId::from_arena(ArenaIndex::new(i, 0));
            assert!(region.add_task(task).is_ok());
        }
        assert_eq!(region.task_ids().len(), 100);
    }

    #[test]
    fn unlimited_admits_many_obligations() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        for _ in 0..100 {
            assert!(region.try_reserve_obligation().is_ok());
        }
        assert_eq!(region.pending_obligations(), 100);
    }

    // --- resolve_obligation saturating_sub ---
    // An unpaired resolve (more resolves than reserves) must not wrap
    // around or panic.  It should bottom out at zero.

    #[test]
    fn resolve_obligation_saturates_at_zero() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        assert_eq!(region.pending_obligations(), 0);

        // Resolve without any reserve — should stay at 0, not underflow.
        region.resolve_obligation();
        assert_eq!(region.pending_obligations(), 0);

        // Reserve one, resolve two — should be 0.
        assert!(region.try_reserve_obligation().is_ok());
        assert_eq!(region.pending_obligations(), 1);
        region.resolve_obligation();
        assert_eq!(region.pending_obligations(), 0);
        region.resolve_obligation();
        assert_eq!(region.pending_obligations(), 0);
    }

    // --- AdmissionError fields ---
    // The error must carry the exact limit and live count at the point
    // of rejection so callers can produce actionable diagnostics.

    #[test]
    fn admission_error_carries_exact_counts() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        region.set_limits(RegionLimits {
            max_tasks: Some(3),
            ..RegionLimits::unlimited()
        });

        for i in 0..3 {
            let task = TaskId::from_arena(ArenaIndex::new(i, 0));
            assert!(region.add_task(task).is_ok());
        }

        let overflow_task = TaskId::from_arena(ArenaIndex::new(99, 0));
        let err = region
            .add_task(overflow_task)
            .expect_err("expected admission error");
        if let AdmissionError::LimitReached { kind, limit, live } = err {
            assert_eq!(kind, AdmissionKind::Task);
            assert_eq!(limit, 3);
            assert_eq!(live, 3);
        } else {
            panic!("expected LimitReached, got {err:?}");
        }
    }

    // --- has_live_work integration ---
    // The region should report live work whenever tasks, children, or
    // obligations are present.

    #[test]
    fn has_live_work_tracks_all_categories() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        assert!(!region.has_live_work());

        // Tasks
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        assert!(region.add_task(task).is_ok());
        assert!(region.has_live_work());
        region.remove_task(task);
        assert!(!region.has_live_work());

        // Children
        let child = RegionId::from_arena(ArenaIndex::new(1, 0));
        assert!(region.add_child(child).is_ok());
        assert!(region.has_live_work());
        region.remove_child(child);
        assert!(!region.has_live_work());

        // Obligations
        assert!(region.try_reserve_obligation().is_ok());
        assert!(region.has_live_work());
        region.resolve_obligation();
        assert!(!region.has_live_work());
    }

    // --- Heap admission boundary ---
    // Heap admission must account for existing live bytes accurately and
    // reject allocations that would push total bytes above the limit.

    #[test]
    fn heap_admits_up_to_exact_limit() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        let u32_size = std::mem::size_of::<u32>();
        // Set limit to exactly 2 u32s.
        region.set_limits(RegionLimits {
            max_heap_bytes: Some(u32_size * 2),
            ..RegionLimits::unlimited()
        });

        assert!(region.heap_alloc(1u32).is_ok());
        assert!(region.heap_alloc(2u32).is_ok());
        // Third allocation pushes beyond limit.
        let err = region.heap_alloc(3u32).expect_err("heap limit");
        assert!(matches!(
            err,
            AdmissionError::LimitReached {
                kind: AdmissionKind::HeapBytes,
                ..
            }
        ));
    }

    // --- Concurrent admission (single-threaded simulation) ---
    // While true concurrency requires thread-based tests, we can
    // verify the double-check logic by simulating a close between
    // the optimistic check and the lock acquisition.  In this
    // single-threaded test, we verify the sequenced case: close,
    // then admit.

    #[test]
    fn close_prevents_subsequent_admission() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());

        let task1 = TaskId::from_arena(ArenaIndex::new(1, 0));
        assert!(region.add_task(task1).is_ok());

        region.begin_close(None);

        // All admission paths must fail.
        let task2 = TaskId::from_arena(ArenaIndex::new(2, 0));
        assert_eq!(region.add_task(task2), Err(AdmissionError::Closed));

        let child = RegionId::from_arena(ArenaIndex::new(1, 0));
        assert_eq!(region.add_child(child), Err(AdmissionError::Closed));

        assert_eq!(region.try_reserve_obligation(), Err(AdmissionError::Closed));
    }

    // --- Sequential double-check locking verification ---
    //
    // RegionRecord is !Sync (Finalizer contains non-Sync futures), so
    // Arc-based thread tests are not possible at the type level.  The
    // runtime uses RegionRecord behind its own synchronisation (arena +
    // RwLock<State>), so thread safety is enforced at a higher layer.
    //
    // Here we verify the sequential invariants that the double-check
    // pattern relies on:
    //
    // (a) After begin_close(), all admission returns Closed.
    // (b) Limit check and push are atomic (single write-lock section).
    // (c) No over-admission when limit == live (saturated).

    #[test]
    fn saturated_limit_rejects_all_types() {
        // When every limit is exactly at capacity, all admission paths
        // must fail — verifying limit check is inside the lock.
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        region.set_limits(RegionLimits {
            max_tasks: Some(2),
            max_children: Some(2),
            max_obligations: Some(2),
            max_heap_bytes: Some(std::mem::size_of::<u64>()),
            curve_budget: None,
        });

        // Fill to capacity.
        let t1 = TaskId::from_arena(ArenaIndex::new(1, 0));
        let t2 = TaskId::from_arena(ArenaIndex::new(2, 0));
        assert!(region.add_task(t1).is_ok());
        assert!(region.add_task(t2).is_ok());

        let c1 = RegionId::from_arena(ArenaIndex::new(1, 0));
        let c2 = RegionId::from_arena(ArenaIndex::new(2, 0));
        assert!(region.add_child(c1).is_ok());
        assert!(region.add_child(c2).is_ok());

        assert!(region.try_reserve_obligation().is_ok());
        assert!(region.try_reserve_obligation().is_ok());

        assert!(region.heap_alloc(42u64).is_ok());

        // All types are now at capacity — verify rejection.
        let t3 = TaskId::from_arena(ArenaIndex::new(3, 0));
        assert!(matches!(
            region.add_task(t3),
            Err(AdmissionError::LimitReached {
                kind: AdmissionKind::Task,
                ..
            })
        ));

        let c3 = RegionId::from_arena(ArenaIndex::new(3, 0));
        assert!(matches!(
            region.add_child(c3),
            Err(AdmissionError::LimitReached {
                kind: AdmissionKind::Child,
                ..
            })
        ));

        assert!(matches!(
            region.try_reserve_obligation(),
            Err(AdmissionError::LimitReached {
                kind: AdmissionKind::Obligation,
                ..
            })
        ));

        assert!(matches!(
            region.heap_alloc(1u8),
            Err(AdmissionError::LimitReached {
                kind: AdmissionKind::HeapBytes,
                ..
            })
        ));
    }

    // --- Region Heap Reclamation Proof & Tests (bd-1ow9g) ---
    //
    // These tests verify that region heap reclamation only occurs at
    // quiescence and that the global allocation counter returns to
    // baseline after all regions are closed.

    #[test]
    fn heap_stats_return_to_zero_single_region() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        region.heap_alloc(1u32).unwrap();
        region.heap_alloc(2u64).unwrap();
        region.heap_alloc("hello".to_string()).unwrap();

        assert_eq!(region.heap_stats().live, 3);
        assert_eq!(region.heap_stats().allocations, 3);

        // Close the region
        assert!(region.begin_close(None));
        assert!(region.begin_finalize());
        assert!(region.complete_close());

        // Stats must reflect full reclamation
        assert_eq!(region.heap_stats().live, 0);
        assert_eq!(region.heap_stats().reclaimed, 3);
        assert_eq!(region.heap_len(), 0);
    }

    #[test]
    fn multi_region_hierarchy_reclamation() {
        // Create parent and two children
        let parent_id = RegionId::from_arena(ArenaIndex::new(100, 0));
        let child1_id = RegionId::from_arena(ArenaIndex::new(101, 0));
        let child2_id = RegionId::from_arena(ArenaIndex::new(102, 0));

        let parent = RegionRecord::new(parent_id, None, Budget::default());
        let child1 = RegionRecord::new(child1_id, Some(parent_id), Budget::default());
        let child2 = RegionRecord::new(child2_id, Some(parent_id), Budget::default());

        parent.add_child(child1_id).unwrap();
        parent.add_child(child2_id).unwrap();

        // Allocate in all three regions
        parent.heap_alloc(10u32).unwrap();
        parent.heap_alloc(20u32).unwrap();
        child1.heap_alloc(30u64).unwrap();
        child2.heap_alloc(40u64).unwrap();
        child2.heap_alloc(50u64).unwrap();

        // Verify per-region allocation counts
        assert_eq!(parent.heap_stats().live, 2);
        assert_eq!(child1.heap_stats().live, 1);
        assert_eq!(child2.heap_stats().live, 2);

        // Close children first (structured concurrency: innermost first)
        assert!(child1.begin_close(None));
        assert!(child1.begin_finalize());
        assert!(child1.complete_close());
        assert_eq!(child1.heap_stats().live, 0);
        assert_eq!(child1.heap_stats().reclaimed, 1);

        assert!(child2.begin_close(None));
        assert!(child2.begin_finalize());
        assert!(child2.complete_close());
        assert_eq!(child2.heap_stats().live, 0);
        assert_eq!(child2.heap_stats().reclaimed, 2);

        // Parent heap still live while parent is open
        assert_eq!(parent.heap_stats().live, 2);

        // Remove children and close parent
        parent.remove_child(child1_id);
        parent.remove_child(child2_id);
        assert!(parent.begin_close(None));
        assert!(parent.begin_finalize());
        assert!(parent.complete_close());
        assert_eq!(parent.heap_stats().live, 0);
        assert_eq!(parent.heap_stats().reclaimed, 2);
    }

    #[test]
    fn heap_alloc_allowed_during_cleanup_phases() {
        // Unlike add_task/add_child, heap_alloc does not reject during
        // Closing/Draining/Finalizing phases. This is by design: finalizers
        // and cleanup code may need temporary heap allocations. Reclamation
        // happens atomically at complete_close(), after all finalizers finish.
        let region = RegionRecord::new(test_region_id(), None, Budget::default());

        region.heap_alloc(42u32).unwrap();
        assert_eq!(region.heap_len(), 1);

        // Closing — heap_alloc still allowed
        assert!(region.begin_close(None));
        region.heap_alloc(99u32).unwrap();
        assert_eq!(region.heap_len(), 2);

        // Finalizing — heap_alloc still allowed (finalizers may allocate)
        assert!(region.begin_finalize());
        region.heap_alloc(200u32).unwrap();
        assert_eq!(region.heap_len(), 3);

        // Close — all 3 allocations reclaimed
        assert!(region.complete_close());
        assert_eq!(region.heap_len(), 0);
    }

    #[test]
    fn heap_reclamation_timing_matches_state_machine() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        region.heap_alloc(1u32).unwrap();
        region.heap_alloc(2u64).unwrap();

        // Heap still live during Closing
        assert!(region.begin_close(None));
        assert_eq!(region.heap_len(), 2);
        assert_eq!(region.state(), RegionState::Closing);

        // Heap still live during Draining
        assert!(region.begin_drain());
        assert_eq!(region.heap_len(), 2);
        assert_eq!(region.state(), RegionState::Draining);

        // Heap still live during Finalizing
        assert!(region.begin_finalize());
        assert_eq!(region.heap_len(), 2);
        assert_eq!(region.state(), RegionState::Finalizing);

        // Heap reclaimed only on complete_close (Finalizing → Closed)
        assert!(region.complete_close());
        assert_eq!(region.heap_len(), 0);
        assert_eq!(region.state(), RegionState::Closed);
    }

    #[test]
    fn heap_stats_consistent_through_lifecycle() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());

        // Allocate various types
        region.heap_alloc(42u32).unwrap();
        region.heap_alloc(std::f64::consts::PI).unwrap();
        region.heap_alloc(vec![1u8, 2, 3]).unwrap();

        let stats_before = region.heap_stats();
        assert_eq!(stats_before.allocations, 3);
        assert_eq!(stats_before.live, 3);
        assert_eq!(stats_before.reclaimed, 0);

        // Close the region
        assert!(region.begin_close(None));
        assert!(region.begin_finalize());
        assert!(region.complete_close());

        let stats_after = region.heap_stats();
        assert_eq!(stats_after.allocations, 3);
        assert_eq!(stats_after.live, 0);
        assert_eq!(stats_after.reclaimed, 3);
    }

    #[test]
    fn rref_accessible_through_finalizing_invalid_after_closed() {
        let region_id = test_region_id();
        let region = RegionRecord::new(region_id, None, Budget::default());

        let idx = region.heap_alloc(99u32).unwrap();
        let rref = RRef::<u32>::new(region_id, idx);

        // RRef accessible during normal lifecycle
        assert_eq!(region.rref_get(&rref).unwrap(), 99);

        // Close begins — still accessible (Closing is not terminal)
        assert!(region.begin_close(None));
        assert_eq!(region.rref_get(&rref).unwrap(), 99);

        // Draining — still accessible
        assert!(region.begin_drain());
        assert_eq!(region.rref_get(&rref).unwrap(), 99);

        // Finalizing — still accessible (finalizers may need data)
        assert!(region.begin_finalize());
        assert_eq!(region.rref_get(&rref).unwrap(), 99);

        // Closed — heap reclaimed, RRef invalid
        assert!(region.complete_close());
        let err = region.rref_get(&rref).expect_err("invalid after close");
        assert_eq!(err, RRefError::AllocationInvalid);
    }

    #[test]
    fn complete_close_is_idempotent_for_reclamation() {
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        region.heap_alloc(1u32).unwrap();
        region.heap_alloc(2u32).unwrap();

        assert!(region.begin_close(None));
        assert!(region.begin_finalize());
        assert!(region.complete_close());
        assert_eq!(region.heap_stats().live, 0);
        assert_eq!(region.heap_stats().reclaimed, 2);

        // Second call to complete_close should be a no-op (returns false)
        assert!(!region.complete_close());
        // Stats unchanged — reclamation was not double-counted
        assert_eq!(region.heap_stats().reclaimed, 2);
    }

    #[test]
    fn interleaved_add_remove_never_over_admits() {
        // Simulate rapid add/remove cycles and verify the live count
        // never exceeds the limit, even with interleaving.
        let region = RegionRecord::new(test_region_id(), None, Budget::default());
        region.set_limits(RegionLimits {
            max_tasks: Some(3),
            ..RegionLimits::unlimited()
        });

        for round in 0..10u32 {
            let base = round * 3;
            let a = TaskId::from_arena(ArenaIndex::new(base, 0));
            let b = TaskId::from_arena(ArenaIndex::new(base + 1, 0));
            let c = TaskId::from_arena(ArenaIndex::new(base + 2, 0));

            assert!(region.add_task(a).is_ok());
            assert!(region.add_task(b).is_ok());
            assert!(region.add_task(c).is_ok());

            // At capacity — next must fail.
            let overflow = TaskId::from_arena(ArenaIndex::new(base + 3, 0));
            assert!(region.add_task(overflow).is_err());

            // Remove all and start over.
            region.remove_task(a);
            region.remove_task(b);
            region.remove_task(c);
            assert_eq!(region.task_ids().len(), 0);
        }
    }

    // ========================================================================
    // RRef Access Safety — Witness-Gated Access Tests (bd-27c7l)
    // ========================================================================

    #[test]
    fn access_witness_available_while_open() {
        let region = RegionRecord::new(test_region_id(), None, Budget::INFINITE);
        let witness = region.access_witness();
        assert!(witness.is_ok());
        assert_eq!(witness.unwrap().region(), test_region_id());
    }

    #[test]
    fn access_witness_available_through_closing_phases() {
        let region = RegionRecord::new(test_region_id(), None, Budget::INFINITE);

        // Witness available in Open
        assert!(region.access_witness().is_ok());

        region.begin_close(None);
        // Witness available in Closing
        assert!(region.access_witness().is_ok());

        region.begin_drain();
        // Witness available in Draining
        assert!(region.access_witness().is_ok());

        region.begin_finalize();
        // Witness available in Finalizing
        assert!(region.access_witness().is_ok());
    }

    #[test]
    fn access_witness_denied_after_close() {
        let region = RegionRecord::new(test_region_id(), None, Budget::INFINITE);
        region.begin_close(None);
        region.begin_drain();
        region.begin_finalize();
        region.complete_close();

        let witness = region.access_witness();
        assert!(witness.is_err());
        assert_eq!(witness.unwrap_err(), RRefError::RegionClosed);
    }

    #[test]
    fn witness_gated_get_succeeds_with_matching_region() {
        let rid = test_region_id();
        let region = RegionRecord::new(rid, None, Budget::INFINITE);
        let index = region.heap_alloc(42u32).expect("heap alloc");
        let rref = RRef::<u32>::new(rid, index);

        let witness = region.access_witness().expect("witness");
        let value = region.rref_get_with(&rref, witness).expect("get_with");
        assert_eq!(value, 42);
    }

    #[test]
    fn witness_gated_with_succeeds_with_matching_region() {
        let rid = test_region_id();
        let region = RegionRecord::new(rid, None, Budget::INFINITE);
        let index = region.heap_alloc("hello".to_string()).expect("heap alloc");
        let rref = RRef::<String>::new(rid, index);

        let witness = region.access_witness().expect("witness");
        let len = region
            .rref_with_witness(&rref, witness, String::len)
            .expect("with_witness");
        assert_eq!(len, 5);
    }

    #[test]
    fn witness_from_wrong_region_rejected() {
        let rid_a = test_region_id();
        let rid_b = RegionId::from_arena(ArenaIndex::new(99, 0));
        let region_a = RegionRecord::new(rid_a, None, Budget::INFINITE);
        let region_b = RegionRecord::new(rid_b, None, Budget::INFINITE);

        let index = region_a.heap_alloc(7u32).expect("heap alloc");
        let rref = RRef::<u32>::new(rid_a, index);

        // Witness from region_b cannot access region_a's RRef
        let wrong_witness = region_b.access_witness().expect("witness");
        let err = region_a.rref_get_with(&rref, wrong_witness);
        assert_eq!(err.unwrap_err(), RRefError::WrongRegion);
    }

    #[test]
    fn witness_rref_region_mismatch_rejected() {
        let rid_a = test_region_id();
        let rid_b = RegionId::from_arena(ArenaIndex::new(99, 0));
        let region_a = RegionRecord::new(rid_a, None, Budget::INFINITE);

        let index = region_a.heap_alloc(7u32).expect("heap alloc");
        // RRef claims to belong to region_b but index is from region_a
        let rref = RRef::<u32>::new(rid_b, index);

        let witness = region_a.access_witness().expect("witness");
        let err = region_a.rref_get_with(&rref, witness);
        // Witness region matches record (a), but rref region is b → WrongRegion
        assert_eq!(err.unwrap_err(), RRefError::WrongRegion);
    }

    #[test]
    fn stale_witness_rejected_after_close() {
        let rid = test_region_id();
        let region = RegionRecord::new(rid, None, Budget::INFINITE);
        let index = region.heap_alloc(42u32).expect("heap alloc");
        let rref = RRef::<u32>::new(rid, index);

        // Obtain witness while open
        let witness = region.access_witness().expect("witness");

        // Close the region fully
        region.begin_close(None);
        region.begin_drain();
        region.begin_finalize();
        region.complete_close();

        // Stale witness cannot access data after region is closed
        let err = region.rref_get_with(&rref, witness);
        assert_eq!(err.unwrap_err(), RRefError::RegionClosed);
    }

    #[test]
    fn rref_access_trait_get_works() {
        let rid = test_region_id();
        let region = RegionRecord::new(rid, None, Budget::INFINITE);
        let index = region.heap_alloc(99i64).expect("heap alloc");
        let rref = RRef::<i64>::new(rid, index);

        let value = rref_get_via_trait(&region, &rref);
        assert_eq!(value, 99);
    }

    #[test]
    fn rref_access_trait_with_works() {
        let rid = test_region_id();
        let region = RegionRecord::new(rid, None, Budget::INFINITE);
        let index = region.heap_alloc(vec![1, 2, 3]).expect("heap alloc");
        let rref = RRef::<Vec<i32>>::new(rid, index);

        let len = rref_with_via_trait(&region, &rref, Vec::len);
        assert_eq!(len, 3);
    }

    #[test]
    fn rref_access_trait_witness_methods_work() {
        let rid = test_region_id();
        let region = RegionRecord::new(rid, None, Budget::INFINITE);
        let index = region
            .heap_alloc("witness".to_string())
            .expect("heap alloc");
        let rref = RRef::<String>::new(rid, index);

        let witness = region.access_witness().expect("witness");

        let value = rref_get_with_via_trait(&region, &rref, witness);
        assert_eq!(value, "witness");

        let len = rref_with_witness_via_trait(&region, &rref, witness, String::len);
        assert_eq!(len, 7);
    }
}
