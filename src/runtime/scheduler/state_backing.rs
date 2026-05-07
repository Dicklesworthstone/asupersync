//! Trait abstraction over runtime backing-state shapes for the scheduler hot
//! path. br-asupersync-30atgp.1 — first decomposition step of br-asupersync-30atgp.
//!
//! # Why this exists
//!
//! `ThreeLaneScheduler` and `ThreeLaneWorker` currently lock
//! `Arc<ContendedMutex<RuntimeState>>` and call a small handful of methods
//! on the locked guard. `ShardedState`
//! (`src/runtime/sharded_state.rs`) reduces lock contention by splitting
//! the unified table into independently-locked Tasks/Regions/Obligations
//! shards. Routing the scheduler through `ShardedState` requires a way to
//! ask "give me a task record, given an id" without committing the
//! caller to a particular backing-store implementation.
//!
//! This module defines [`RuntimeStateBacking`], the minimal surface the
//! scheduler hot path actually needs. Callers interact with the trait;
//! concrete implementations route to `RuntimeState` or, in a follow-up
//! bead, `ShardedState` via [`ShardGuard`].
//!
//! # Surface (audited 2026-05-07)
//!
//! Method calls on a locked state guard in the scheduler hot path
//! (worker.rs lines 200-700, three_lane.rs lines <5000, excluding test
//! code):
//!
//! - `task(task_id) -> Option<&TaskRecord>`
//! - `task_mut(task_id) -> Option<&mut TaskRecord>`
//! - `task_completed(task_id) -> SmallVec<[TaskId; 4]>` (returns waiter ids)
//! - `store_spawned_task(task_id, stored)`
//! - `remove_stored_future(task_id) -> Option<StoredTask>`
//! - `drain_ready_async_finalizers() -> SmallVec<[(TaskId, u8); 2]>`
//! - `tasks_iter()` — iterator over `(ArenaIndex, &TaskRecord)`
//!
//! Plus one field access: `state.now: Time` at
//! `three_lane.rs::ThreeLaneScheduler::current_scheduler_time`. That is
//! exposed as [`RuntimeStateBacking::current_time`].
//!
//! `tasks_iter` is intentionally NOT in the trait — it returns
//! `impl Iterator<Item = (ArenaIndex, &TaskRecord)>` which cannot be
//! abstracted without GATs or boxing. Callers that need iteration today
//! (a small set, mostly observability + cancel propagation) pull the
//! concrete type and iterate directly. The trait can be widened later.
//!
//! # Status
//!
//! This commit lands ONLY the trait + the `RuntimeState` impl. No
//! scheduler call site is changed yet — `ThreeLaneScheduler` still takes
//! `Arc<ContendedMutex<RuntimeState>>` directly.
//!
//! - **30atgp.2** (next): implement `RuntimeStateBacking` for
//!   `Arc<ShardedState>` by routing each method through
//!   `ShardGuard::for_*` builders so cross-table atomicity at
//!   `task_completed` and `drain_ready_async_finalizers` is preserved.
//! - **30atgp.3** (after): parameterize `ThreeLaneScheduler` over the
//!   trait, flip the `RuntimeBuilder::with_sharded_state(true)` gate
//!   in `src/runtime/builder.rs` to construct a real `ShardedState`,
//!   run the swarm-coordination workload corpus on both shapes per the
//!   br-asupersync-9kuias acceptance bar.

use crate::record::task::TaskRecord;
use crate::runtime::{RuntimeState, StoredTask};
use crate::types::{TaskId, Time};
use smallvec::SmallVec;

/// The minimal RuntimeState method surface the scheduler hot path uses.
///
/// Every method takes `&self` or `&mut self` — the caller is expected to
/// hold the appropriate lock (a unified `ContendedMutex<RuntimeState>` for
/// the existing impl, a `ShardGuard` for the future `ShardedState` impl).
///
/// This trait does NOT cover read-only iteration over the task arena
/// (`tasks_iter`). See module docs for the rationale.
pub trait RuntimeStateBacking {
    /// Looks up a task record by id (read-only).
    fn task(&self, task_id: TaskId) -> Option<&TaskRecord>;

    /// Looks up a task record by id (mutable).
    fn task_mut(&mut self, task_id: TaskId) -> Option<&mut TaskRecord>;

    /// Marks a task complete and returns its waiter ids.
    ///
    /// Implementations must preserve cross-table atomicity: completion
    /// may transition the owning region's task count and trigger region
    /// close progression. The unified impl holds the single state lock
    /// for the duration. The future ShardedState impl must use
    /// `ShardGuard::for_task_completed` (or equivalent) to lock both
    /// the Tasks and Regions shards in the canonical B→A→C order.
    fn task_completed(&mut self, task_id: TaskId) -> SmallVec<[TaskId; 4]>;

    /// Stores a spawned task's future for later polling.
    fn store_spawned_task(&mut self, task_id: TaskId, stored: StoredTask);

    /// Removes and returns a stored future for polling.
    ///
    /// This is the hot-path operation called at the start of each poll
    /// cycle. ShardedState implementations should keep this on the
    /// Tasks shard exclusively — no Regions or Obligations lock needed.
    fn remove_stored_future(&mut self, task_id: TaskId) -> Option<StoredTask>;

    /// Drains the ready async-finalizer queue.
    ///
    /// Like `task_completed`, this can mutate across tables — finalizer
    /// completion may close a region. ShardedState implementations need
    /// the same B→A→C guard treatment.
    fn drain_ready_async_finalizers(&mut self) -> SmallVec<[(TaskId, u8); 2]>;

    /// Returns the runtime's current notion of time.
    ///
    /// Exposed because `ThreeLaneScheduler::current_scheduler_time` reads
    /// `state.now` directly when no `TimerDriverHandle` is installed.
    fn current_time(&self) -> Time;
}

impl RuntimeStateBacking for RuntimeState {
    #[inline]
    fn task(&self, task_id: TaskId) -> Option<&TaskRecord> {
        RuntimeState::task(self, task_id)
    }

    #[inline]
    fn task_mut(&mut self, task_id: TaskId) -> Option<&mut TaskRecord> {
        RuntimeState::task_mut(self, task_id)
    }

    #[inline]
    fn task_completed(&mut self, task_id: TaskId) -> SmallVec<[TaskId; 4]> {
        RuntimeState::task_completed(self, task_id)
    }

    #[inline]
    fn store_spawned_task(&mut self, task_id: TaskId, stored: StoredTask) {
        RuntimeState::store_spawned_task(self, task_id, stored);
    }

    #[inline]
    fn remove_stored_future(&mut self, task_id: TaskId) -> Option<StoredTask> {
        RuntimeState::remove_stored_future(self, task_id)
    }

    #[inline]
    fn drain_ready_async_finalizers(&mut self) -> SmallVec<[(TaskId, u8); 2]> {
        RuntimeState::drain_ready_async_finalizers(self)
    }

    #[inline]
    fn current_time(&self) -> Time {
        // br-asupersync-30atgp.1: `now` is a public field on RuntimeState
        // (`pub now: Time` near the top of the struct). The unified impl
        // returns it directly. The future ShardedState impl returns
        // `ShardedState::current_time()` which is the equivalent
        // accessor at `src/runtime/sharded_state.rs:231`.
        self.now
    }
}

#[cfg(test)]
#[allow(clippy::pedantic, clippy::nursery)]
mod tests {
    use super::*;
    use crate::types::Budget;

    /// Verifies the trait's existence + dispatch shape via the
    /// unified RuntimeState impl. This is intentionally minimal — the
    /// real coverage is the existing scheduler test suite, which keeps
    /// exercising RuntimeState directly until 30atgp.3 routes through
    /// the trait.
    #[test]
    fn unified_runtime_state_implements_backing_trait() {
        let mut state = RuntimeState::new();
        let _root = state.create_root_region(Budget::INFINITE);

        // Dispatch via the trait. If this compiles + runs, the trait is
        // properly implemented for RuntimeState.
        fn assert_impl<B: RuntimeStateBacking>(_b: &B) {}
        assert_impl(&state);

        // current_time pass-through.
        let now_via_trait = RuntimeStateBacking::current_time(&state);
        assert_eq!(now_via_trait, state.now);
    }

    /// Sanity: drain_ready_async_finalizers via the trait yields the
    /// same SmallVec the direct method does (both empty on a fresh
    /// RuntimeState).
    #[test]
    fn drain_ready_async_finalizers_via_trait_matches_direct() {
        let mut state = RuntimeState::new();
        let trait_drained: SmallVec<[(TaskId, u8); 2]> =
            RuntimeStateBacking::drain_ready_async_finalizers(&mut state);
        assert!(trait_drained.is_empty());
        let direct_drained = state.drain_ready_async_finalizers();
        assert!(direct_drained.is_empty());
    }
}
