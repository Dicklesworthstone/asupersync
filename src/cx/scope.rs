//! Scope API for spawning work within a region.
//!
//! A `Scope` provides the API for spawning tasks, creating child regions,
//! and registering finalizers.
//!
//! # Execution Tiers and Soundness Rules
//!
//! Asupersync defines two execution tiers with different constraints:
//!
//! ## Fiber Tier (Phase 0)
//!
//! - Single-thread, borrow-friendly execution
//! - Can capture borrowed references (`&T`) since no migration
//! - Implemented via `spawn_local` (currently requires Send bounds; relaxed in Phase 1+)
//!
//! ## Task Tier (Phase 1+)
//!
//! - Multi-threaded, `Send` tasks that may migrate across workers
//! - **Must capture only `Send + 'static` data** by construction
//! - Can reference region-owned data via [`RRef<T>`](crate::types::rref::RRef)
//!
//! # Soundness Rules for Send Tasks
//!
//! The [`spawn`](Scope::spawn) method enforces the following bounds:
//!
//! | Component | Bound | Rationale |
//! |-----------|-------|-----------|
//! | Factory | `F: Send + 'static` | Factory may be called on any worker |
//! | Future | `Fut: Send + 'static` | Task may migrate between polls |
//! | Output | `Fut::Output: Send + 'static` | Result sent to potentially different thread |
//!
//! ## What Can Be Captured
//!
//! **Allowed captures in Send tasks:**
//! - Owned `'static` data that is `Send` (e.g., `String`, `Vec<T>`, `Arc<T>`)
//! - [`RRef<T>`](crate::types::rref::RRef) handles to region-heap-allocated data
//! - Atomic types (`AtomicU64`, etc.)
//! - Clone'd `Cx` (the capability context)
//!
//! **Disallowed captures:**
//! - Borrowed references (`&T`, `&mut T`) - not `'static`
//! - `Rc<T>`, `RefCell<T>` - not `Send`
//! - Raw pointers (unless wrapped in a `Send` type)
//! - References to stack-local data
//!
//! ## RRef for Region-Owned Data
//!
//! When tasks need to share data within a region without cloning, use the region
//! heap and [`RRef<T>`](crate::types::rref::RRef):
//!
//! ```ignore
//! // Allocate in region heap
//! let index = region.heap_alloc(expensive_data);
//! let rref = RRef::<ExpensiveData>::new(region_id, index);
//!
//! // Pass RRef to task - it's Copy + Send
//! scope.spawn(state, &cx, move |cx| async move {
//!     // Access via region record (requires runtime lookup)
//!     let data = rref.get_via_region(&region_record)?;
//!     process(data).await
//! });
//! ```
//!
//! # Compile-Time Enforcement
//!
//! The bounds are enforced at compile time. Attempting to capture non-Send
//! or non-static data will result in a compilation error:
//!
//! ```compile_fail
//! use std::rc::Rc;
//! use asupersync::cx::Scope;
//!
//! fn try_capture_rc(scope: &Scope, state: &mut RuntimeState, cx: &Cx) {
//!     let rc = Rc::new(42); // Rc is !Send
//!     scope.spawn(state, cx, move |_| async move {
//!         println!("{}", rc); // ERROR: Rc is not Send
//!     });
//! }
//! ```
//!
//! ```compile_fail
//! use asupersync::cx::Scope;
//!
//! fn try_capture_borrow(scope: &Scope, state: &mut RuntimeState, cx: &Cx) {
//!     let local = 42;
//!     let reference = &local; // Borrowed, not 'static
//!     scope.spawn(state, cx, move |_| async move {
//!         println!("{}", reference); // ERROR: borrowed data not 'static
//!     });
//! }
//! ```
//!
//! # Lab Runtime Compatibility
//!
//! The Send bounds do not affect lab runtime determinism. The lab runtime
//! simulates multi-worker scheduling deterministically (same seed = same
//! execution), regardless of whether tasks are actually migrated.

use crate::channel::oneshot;
use crate::combinator::{Either, Select};
use crate::cx::{Cx, cap};
use crate::record::task::TaskState;
use crate::record::{AdmissionError, TaskRecord};
use crate::runtime::task_handle::{JoinError, TaskHandle};
use crate::runtime::{RegionCreateError, RuntimeState, SpawnError, StoredTask};
use crate::tracing_compat::{debug, debug_span};
use crate::types::{Budget, CancelReason, Outcome, PanicPayload, Policy, RegionId, TaskId};
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// A scope for spawning work within a region.
///
/// The scope provides methods for:
/// - Spawning tasks
/// - Creating child regions
/// - Registering finalizers
/// - Cancelling all children
pub struct Scope<'r, P: Policy = crate::types::policy::FailFast> {
    /// The region this scope belongs to.
    pub(crate) region: RegionId,
    /// The budget for this scope.
    pub(crate) budget: Budget,
    /// Phantom data for the policy type.
    pub(crate) _policy: PhantomData<&'r P>,
}

#[pin_project::pin_project]
pub(crate) struct CatchUnwind<F> {
    #[pin]
    pub(crate) inner: F,
}

impl<F: Future> Future for CatchUnwind<F> {
    type Output = std::thread::Result<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            this.inner.as_mut().poll(cx)
        }));
        match result {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(v)) => Poll::Ready(Ok(v)),
            Err(payload) => Poll::Ready(Err(payload)),
        }
    }
}

pub(crate) fn payload_to_string(payload: &Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(ToString::to_string)
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".to_string())
}

struct RegionRunner<'a, Fut> {
    fut: Pin<&'a mut CatchUnwind<Fut>>,
    state: Option<&'a mut RuntimeState>,
    child_region: RegionId,
}

impl<'a, Fut: Future> Future for RegionRunner<'a, Fut> {
    type Output = (std::thread::Result<Fut::Output>, &'a mut RuntimeState);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.fut.as_mut().poll(cx) {
            Poll::Ready(res) => {
                let state = this.state.take().expect("polled after ready");
                Poll::Ready((res, state))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<Fut> Drop for RegionRunner<'_, Fut> {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            let reason = CancelReason::fail_fast().with_region(self.child_region);
            let _ = state.cancel_request(self.child_region, &reason, None);
            if let Some(region) = state.region(self.child_region) {
                region.begin_close(None);
            }
            state.advance_region_state(self.child_region);
        }
    }
}

struct RegionCloseFuture {
    state: Arc<parking_lot::Mutex<crate::record::region::RegionCloseState>>,
}

impl Future for RegionCloseFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut state = self.state.lock();
        if state.closed {
            Poll::Ready(())
        } else {
            if !state.waiters.iter().any(|w| w.will_wake(cx.waker())) {
                state.waiters.push(cx.waker().clone());
            }
            Poll::Pending
        }
    }
}

impl<P: Policy> Scope<'_, P> {
    /// Creates a new scope (internal use).
    #[must_use]
    #[allow(dead_code)]
    #[cfg_attr(feature = "test-internals", visibility::make(pub))]
    pub(crate) fn new(region: RegionId, budget: Budget) -> Self {
        Self {
            region,
            budget,
            _policy: PhantomData,
        }
    }

    /// Returns the region ID for this scope.
    #[must_use]
    pub fn region_id(&self) -> RegionId {
        self.region
    }

    /// Returns the budget for this scope.
    #[must_use]
    pub fn budget(&self) -> Budget {
        self.budget
    }

    // =========================================================================
    // Task Spawning
    // =========================================================================

    /// Spawns a new task within this scope's region.
    ///
    /// This is the **Task Tier** spawn method for parallel execution. The task
    /// may migrate between worker threads, so all captured data must be thread-safe.
    ///
    /// The task will be owned by the region and will be cancelled if the
    /// region is cancelled. The returned `TaskHandle` can be used to await
    /// the task's result.
    ///
    /// # Arguments
    ///
    /// * `state` - The runtime state
    /// * `cx` - The capability context (used for tracing/authorization)
    /// * `f` - A closure that produces the future, receiving the new task's `Cx`
    ///
    /// # Returns
    ///
    /// A `TaskHandle<T>` that can be used to await the task's result.
    ///
    /// # Soundness Rules (Type Bounds)
    ///
    /// The following bounds encode the soundness rules for Send tasks:
    ///
    /// * `F: FnOnce(Cx) -> Fut + Send + 'static` - Factory called on any worker
    /// * `Fut: Future + Send + 'static` - Task may migrate between polls
    /// * `Fut::Output: Send + 'static` - Result crosses thread boundary
    ///
    /// These bounds ensure captured data can safely cross thread boundaries.
    /// Use [`RRef<T>`](crate::types::rref::RRef) for region-heap-allocated data.
    ///
    /// # Allowed Captures
    ///
    /// | Type | Allowed | Reason |
    /// |------|---------|--------|
    /// | `String`, `Vec<T>`, owned data | ✅ | Send + 'static by ownership |
    /// | `Arc<T>` where T: Send + Sync | ✅ | Thread-safe shared ownership |
    /// | `RRef<T>` | ✅ | Region-heap reference, Copy + Send |
    /// | `Cx` (cloned) | ✅ | Capability context is Send + Sync |
    /// | `Rc<T>`, `RefCell<T>` | ❌ | Not Send |
    /// | `&T`, `&mut T` | ❌ | Not 'static |
    ///
    /// # Example
    ///
    /// ```ignore
    /// let handle = scope.spawn(&mut state, &cx, |cx| async move {
    ///     cx.trace("Child task running");
    ///     compute_value().await
    /// });
    ///
    /// let result = handle.join(&cx).await?;
    /// ```
    ///
    /// # Example with RRef
    ///
    /// ```ignore
    /// // Allocate expensive data in region heap
    /// let index = region_record.heap_alloc(vec![1, 2, 3, 4, 5]);
    /// let rref = RRef::<Vec<i32>>::new(region_id, index);
    ///
    /// // RRef is Copy + Send, can be captured by multiple tasks
    /// scope.spawn(&mut state, &cx, move |cx| async move {
    ///     // Would access via runtime state in real code
    ///     process_data(rref).await
    /// });
    /// ```
    ///
    /// # Compile-Time Errors
    ///
    /// Attempting to capture `!Send` types fails at compile time:
    ///
    /// ```compile_fail,E0277
    /// # // This test demonstrates that Rc cannot be captured
    /// use std::rc::Rc;
    /// fn require_send<T: Send>(_: &T) {}
    /// fn test_rc_rejected<'r, P: asupersync::types::Policy>(
    ///     scope: &asupersync::cx::Scope<'r, P>,
    ///     state: &mut asupersync::runtime::RuntimeState,
    ///     cx: &asupersync::cx::Cx,
    /// ) {
    ///     let rc = Rc::new(42);
    ///     require_send(&rc);
    ///     let _ = scope.spawn(state, cx, move |_| async move {
    ///         let _ = rc;  // Rc<i32> is not Send
    ///     });
    /// }
    /// ```
    ///
    /// Attempting to capture non-`'static` references fails:
    ///
    /// ```compile_fail,E0597
    /// # // This test demonstrates that borrowed data cannot be captured
    /// fn require_static<T: 'static>(_: T) {}
    /// fn test_borrow_rejected<'r, P: asupersync::types::Policy>(
    ///     scope: &asupersync::cx::Scope<'r, P>,
    ///     state: &mut asupersync::runtime::RuntimeState,
    ///     cx: &asupersync::cx::Cx,
    /// ) {
    ///     let local = 42;
    ///     let borrow = &local;
    ///     require_static(borrow);
    ///     let _ = scope.spawn(state, cx, move |_| async move {
    ///         let _ = borrow;  // &i32 is not 'static
    ///     });
    /// }
    /// ```
    pub fn spawn<F, Fut, Caps>(
        &self,
        state: &mut RuntimeState,
        cx: &Cx<Caps>,
        f: F,
    ) -> Result<(TaskHandle<Fut::Output>, StoredTask), SpawnError>
    where
        Caps: cap::HasSpawn + Send + Sync + 'static,
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        // Create oneshot channel for result delivery
        let (tx, rx) = oneshot::channel::<Result<Fut::Output, JoinError>>();

        // Create task record
        let task_id = self.create_task_record(state)?;

        // Trace task spawn event
        let _span = debug_span!(
            "task_spawn",
            task_id = ?task_id,
            region_id = ?self.region,
            initial_state = "Created",
            budget_deadline = ?self.budget.deadline,
            budget_poll_quota = self.budget.poll_quota,
            budget_cost_quota = ?self.budget.cost_quota,
            budget_priority = self.budget.priority,
            budget_source = "scope"
        )
        .entered();
        debug!(
            task_id = ?task_id,
            region_id = ?self.region,
            initial_state = "Created",
            budget_deadline = ?self.budget.deadline,
            budget_poll_quota = self.budget.poll_quota,
            budget_cost_quota = ?self.budget.cost_quota,
            budget_priority = self.budget.priority,
            budget_source = "scope",
            "task spawned"
        );

        let (child_cx, child_cx_full) = self.build_child_task_cx(state, cx, task_id);

        // Create the TaskHandle
        let handle = TaskHandle::new(task_id, rx, Arc::downgrade(&child_cx.inner));

        // Set the shared inner state in the TaskRecord
        // This links the user-facing Cx to the runtime's TaskRecord
        if let Some(record) = state.task_mut(task_id) {
            record.set_cx_inner(child_cx.inner.clone());
            record.set_cx(child_cx_full.clone());
        }

        // Capture child_cx for result sending
        let cx_for_send = child_cx_full;

        // Instantiate the future with the child context.
        // We use a guard to rollback task creation if the factory panics.
        // This prevents zombie tasks (recorded but never started) which would
        // cause the region to never close (deadlock).
        let future = {
            struct TaskCreationGuard<'a> {
                state: &'a mut RuntimeState,
                task_id: TaskId,
                region_id: RegionId,
                committed: bool,
            }

            impl Drop for TaskCreationGuard<'_> {
                fn drop(&mut self) {
                    if !self.committed {
                        // Rollback task creation
                        if let Some(region) = self.state.region_mut(self.region_id) {
                            region.remove_task(self.task_id);
                        }
                        self.state.remove_task(self.task_id);
                    }
                }
            }

            let mut guard = TaskCreationGuard {
                state,
                task_id,
                region_id: self.region,
                committed: false,
            };

            let fut = f(child_cx);
            guard.committed = true;
            fut
        };

        // Wrap the future to send its result through the channel
        // We use CatchUnwind to ensure panics are propagated as JoinError::Panicked
        // rather than silent channel closure (which looks like cancellation).
        let wrapped = async move {
            let result_result = CatchUnwind { inner: future }.await;
            match result_result {
                Ok(result) => {
                    let _ = tx.send(&cx_for_send, Ok(result));
                    crate::types::Outcome::Ok(())
                }
                Err(payload) => {
                    let msg = payload_to_string(&payload);
                    let panic_payload = PanicPayload::new(msg);
                    let _ = tx.send(
                        &cx_for_send,
                        Err(JoinError::Panicked(panic_payload.clone())),
                    );
                    crate::types::Outcome::Panicked(panic_payload)
                }
            }
        };

        // Create stored task with task_id for poll tracing
        let stored = StoredTask::new_with_id(wrapped, task_id);

        Ok((handle, stored))
    }

    /// Spawns a Send task (explicit Task Tier API).
    ///
    /// This is an explicit alias for [`spawn`](Self::spawn) that makes the
    /// execution tier clear in the API. Use this when you want to emphasize
    /// that the task may migrate between workers.
    ///
    /// # Type Bounds (Soundness Rules)
    ///
    /// Same as [`spawn`](Self::spawn):
    /// - `F: FnOnce(Cx) -> Fut + Send + 'static`
    /// - `Fut: Future + Send + 'static`
    /// - `Fut::Output: Send + 'static`
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Explicit task tier spawn
    /// let (handle, stored) = scope.spawn_task(&mut state, &cx, |cx| async move {
    ///     // This task may run on any worker
    ///     compute_parallel().await
    /// })?;
    /// ```
    #[inline]
    pub fn spawn_task<F, Fut, Caps>(
        &self,
        state: &mut RuntimeState,
        cx: &Cx<Caps>,
        f: F,
    ) -> Result<(TaskHandle<Fut::Output>, StoredTask), SpawnError>
    where
        Caps: cap::HasSpawn + Send + Sync + 'static,
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        self.spawn(state, cx, f)
    }

    /// Spawns a task and registers it with the runtime state.
    ///
    /// This is a convenience method that combines `spawn()` with
    /// `RuntimeState::store_spawned_task()`. It's the primary method
    /// used by the `spawn!` macro.
    ///
    /// # Arguments
    ///
    /// * `state` - The runtime state (for storing the task)
    /// * `cx` - The capability context (for creating child context)
    /// * `f` - A closure that produces the future, receiving the new task's `Cx`
    ///
    /// # Returns
    ///
    /// A `TaskHandle<T>` for awaiting the task's result.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let handle = scope.spawn_registered(&mut state, &cx, |cx| async move {
    ///     cx.trace("Child task running");
    ///     compute_value().await
    /// })?;
    ///
    /// let result = handle.join(&cx).await?;
    /// ```
    pub fn spawn_registered<F, Fut, Caps>(
        &self,
        state: &mut RuntimeState,
        cx: &Cx<Caps>,
        f: F,
    ) -> Result<TaskHandle<Fut::Output>, SpawnError>
    where
        Caps: cap::HasSpawn + Send + Sync + 'static,
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        let (handle, stored) = self.spawn(state, cx, f)?;
        state.store_spawned_task(handle.task_id(), stored);
        Ok(handle)
    }

    /// Spawns a local (non-Send) task within this scope's region (**Fiber Tier**).
    ///
    /// This is the **Fiber Tier** spawn method. Local tasks are pinned to the
    /// current worker thread and cannot be stolen by other workers. This enables
    /// borrow-friendly execution with `!Send` types like `Rc` or `RefCell`.
    ///
    /// # Execution Tier: Fiber
    ///
    /// | Property | Value |
    /// |----------|-------|
    /// | Migration | Never (thread-pinned) |
    /// | Send bound | Not required |
    /// | Borrowing | Requires `'static` (no local `&T`) |
    /// | Use case | `!Send` types, borrowed data |
    ///
    /// # Arguments
    ///
    /// * `state` - The runtime state
    /// * `cx` - The capability context
    /// * `f` - A closure that produces the future, receiving the new task's `Cx`
    ///
    /// # Panics
    ///
    /// Panics if called from a blocking thread (spawn_blocking context).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::rc::Rc;
    /// use std::cell::RefCell;
    ///
    /// let counter = Rc::new(RefCell::new(0));
    /// let counter_clone = counter.clone();
    ///
    /// let handle = scope.spawn_local(&mut state, &cx, |cx| async move {
    ///     // Rc<RefCell<_>> is !Send but allowed in local tasks
    ///     *counter_clone.borrow_mut() += 1;
    /// });
    /// ```
    #[allow(clippy::too_many_lines)]
    pub fn spawn_local<F, Fut, Caps>(
        &self,
        state: &mut RuntimeState,
        cx: &Cx<Caps>,
        f: F,
    ) -> Result<TaskHandle<Fut::Output>, SpawnError>
    where
        Caps: cap::HasSpawn + Send + Sync + 'static,
        F: FnOnce(Cx<Caps>) -> Fut + 'static,
        Fut: Future + 'static,
        Fut::Output: Send + 'static,
    {
        use crate::runtime::stored_task::LocalStoredTask;
        use crate::runtime::task_handle::JoinError;

        // Create oneshot channel for result delivery
        let (result_tx, rx) = oneshot::channel::<Result<Fut::Output, JoinError>>();

        // Create task record
        let task_id = self.create_task_record(state)?;

        // Trace task spawn event
        let _span = debug_span!(
            "task_spawn",
            task_id = ?task_id,
            region_id = ?self.region,
            initial_state = "Created",
            budget_deadline = ?self.budget.deadline,
            budget_poll_quota = self.budget.poll_quota,
            budget_cost_quota = ?self.budget.cost_quota,
            budget_priority = self.budget.priority,
            budget_source = "scope_local"
        )
        .entered();
        debug!(
            task_id = ?task_id,
            region_id = ?self.region,
            initial_state = "Created",
            budget_deadline = ?self.budget.deadline,
            budget_poll_quota = self.budget.poll_quota,
            budget_cost_quota = ?self.budget.cost_quota,
            budget_priority = self.budget.priority,
            budget_source = "scope_local",
            "local task spawned"
        );

        let (child_cx, child_cx_full) = self.build_child_task_cx(state, cx, task_id);

        // Create the TaskHandle
        let handle = TaskHandle::new(task_id, rx, Arc::downgrade(&child_cx.inner));

        // Set the shared inner state in the TaskRecord
        if let Some(record) = state.task_mut(task_id) {
            record.set_cx_inner(child_cx.inner.clone());
            record.set_cx(child_cx_full.clone());
        }

        // Capture child_cx for result sending
        let cx_for_send = child_cx_full;

        // Instantiate the future with the child context.
        // We use a guard to rollback task creation if the factory panics.
        let future = {
            struct TaskCreationGuard<'a> {
                state: &'a mut RuntimeState,
                task_id: TaskId,
                region_id: RegionId,
                committed: bool,
            }

            impl Drop for TaskCreationGuard<'_> {
                fn drop(&mut self) {
                    if !self.committed {
                        // Rollback task creation
                        if let Some(region) = self.state.region_mut(self.region_id) {
                            region.remove_task(self.task_id);
                        }
                        self.state.remove_task(self.task_id);
                    }
                }
            }

            let mut guard = TaskCreationGuard {
                state,
                task_id,
                region_id: self.region,
                committed: false,
            };

            let fut = f(child_cx);
            guard.committed = true;
            fut
        };

        // Wrap the future to send its result through the channel
        let wrapped = async move {
            let result_result = CatchUnwind { inner: future }.await;
            match result_result {
                Ok(result) => {
                    let _ = result_tx.send(&cx_for_send, Ok(result));
                    crate::types::Outcome::Ok(())
                }
                Err(payload) => {
                    let msg = payload_to_string(&payload);
                    let panic_payload = PanicPayload::new(msg);
                    let _ = result_tx.send(
                        &cx_for_send,
                        Err(JoinError::Panicked(panic_payload.clone())),
                    );
                    crate::types::Outcome::Panicked(panic_payload)
                }
            }
        };

        // Create local stored task
        let stored = LocalStoredTask::new_with_id(wrapped, task_id);

        // Store in thread-local storage
        crate::runtime::local::store_local_task(task_id, stored);

        // Mark the task record as local so that safety guards in the scheduler
        // (inject_ready panic, try_steal debug_assert) can detect accidental
        // cross-thread migration of !Send futures.
        if let Some(record) = state.task_mut(task_id) {
            if let Some(worker_id) = crate::runtime::scheduler::three_lane::current_worker_id() {
                record.pin_to_worker(worker_id);
            } else {
                record.mark_local();
            }
            record.wake_state.notify();
        }

        // Schedule the task on the current worker's NON-STEALABLE local scheduler.
        // spawn_local tasks MUST NOT be stealable.
        let scheduled = crate::runtime::scheduler::three_lane::schedule_local_task(task_id);

        if scheduled {
            if let Some(record) = state.task(task_id) {
                let _ = record.wake_state.notify();
            }
            return Ok(handle);
        }

        // No local scheduler available: rollback to avoid a permanently parked task.
        let _ = crate::runtime::local::remove_local_task(task_id);
        if let Some(region) = state.region(self.region) {
            region.remove_task(task_id);
        }
        state.remove_task(task_id);
        Err(SpawnError::LocalSchedulerUnavailable)
    }

    /// Spawns a blocking operation on a dedicated thread pool.
    ///
    /// This is used for CPU-bound or legacy synchronous operations that
    /// should not block async workers. The closure runs on a separate
    /// thread pool designed for blocking work.
    ///
    /// # Arguments
    ///
    /// * `state` - The runtime state
    /// * `cx` - The capability context
    /// * `f` - The blocking closure to run, receiving a context
    ///
    /// # Type Bounds
    ///
    /// * `F: FnOnce(Cx) -> R + Send + 'static` - The closure must be Send
    /// * `R: Send + 'static` - The result must be Send
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (handle, stored) = scope.spawn_blocking(&mut state, &cx, |cx| {
    ///     cx.trace("Starting blocking work");
    ///     // CPU-intensive work
    ///     expensive_computation()
    /// });
    ///
    /// let result = handle.join(&cx).await?;
    /// ```
    ///
    /// # Note
    ///
    /// In Phase 0 (single-threaded), blocking operations run inline.
    /// A proper blocking pool is implemented in Phase 1+.
    pub fn spawn_blocking<F, R, Caps>(
        &self,
        state: &mut RuntimeState,
        cx: &Cx<Caps>, // Parent Cx
        f: F,
    ) -> Result<(TaskHandle<R>, StoredTask), SpawnError>
    where
        Caps: cap::HasSpawn + Send + Sync + 'static,
        F: FnOnce(Cx<Caps>) -> R + Send + 'static,
        R: Send + 'static,
    {
        // Create oneshot channel for result delivery
        let (tx, rx) = oneshot::channel::<Result<R, JoinError>>();

        // Create task record
        let task_id = self.create_task_record(state)?;

        // Trace task spawn event
        debug!(
            task_id = ?task_id,
            region_id = ?self.region,
            initial_state = "Created",
            poll_quota = self.budget.poll_quota,
            spawn_kind = "blocking",
            "blocking task spawned"
        );

        let (child_cx, child_cx_full) = self.build_child_task_cx(state, cx, task_id);

        // Create the TaskHandle
        let handle = TaskHandle::new(task_id, rx, Arc::downgrade(&child_cx.inner));

        // Set the shared inner state in the TaskRecord
        if let Some(record) = state.task_mut(task_id) {
            record.set_cx_inner(child_cx.inner.clone());
            record.set_cx(child_cx_full.clone());
        }

        // Capture child_cx for result sending
        let cx_for_send = child_cx_full;

        // For Phase 0, we run blocking code as an async task
        // In Phase 1+, this would spawn on a blocking thread pool
        let wrapped = async move {
            // Execute the blocking closure with child context
            // Catch panics to report them correctly
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(child_cx)));
            match result {
                Ok(res) => {
                    let _ = tx.send(&cx_for_send, Ok(res));
                    crate::types::Outcome::Ok(())
                }
                Err(payload) => {
                    let msg = payload_to_string(&payload);
                    let panic_payload = PanicPayload::new(msg);
                    let _ = tx.send(
                        &cx_for_send,
                        Err(JoinError::Panicked(panic_payload.clone())),
                    );
                    crate::types::Outcome::Panicked(panic_payload)
                }
            }
        };

        let stored = StoredTask::new_with_id(wrapped, task_id);

        Ok((handle, stored))
    }

    // =========================================================================
    // Child Regions
    // =========================================================================

    /// Creates a child region and runs the provided future within a child scope.
    ///
    /// The child region inherits the parent's budget by default. Use
    /// [`Scope::region_with_budget`] to tighten constraints for the child.
    ///
    /// The returned outcome is the result of the body future. After the body
    /// completes, the child region begins its close sequence and advances until
    /// it can close (assuming all child tasks have completed and obligations are resolved).
    ///
    /// # Errors
    ///
    /// Returns [`RegionCreateError`] if the parent is closed, missing, or at capacity.
    pub async fn region<P2, F, Fut, T, Caps>(
        &self,
        state: &mut RuntimeState,
        cx: &Cx<Caps>,
        policy: P2,
        f: F,
    ) -> Result<Outcome<T, P2::Error>, RegionCreateError>
    where
        P2: Policy,
        F: FnOnce(Scope<'_, P2>, &mut RuntimeState) -> Fut,
        Fut: Future<Output = Outcome<T, P2::Error>>,
    {
        self.region_with_budget(state, cx, self.budget, policy, f)
            .await
    }

    /// Creates a child region with an explicit budget (met with the parent budget).
    ///
    /// The effective budget is `parent.meet(child)` to ensure nested scopes can
    /// never relax constraints.
    pub async fn region_with_budget<P2, F, Fut, T, Caps>(
        &self,
        state: &mut RuntimeState,
        _cx: &Cx<Caps>,
        budget: Budget,
        _policy: P2,
        f: F,
    ) -> Result<Outcome<T, P2::Error>, RegionCreateError>
    where
        P2: Policy,
        F: FnOnce(Scope<'_, P2>, &mut RuntimeState) -> Fut,
        Fut: Future<Output = Outcome<T, P2::Error>>,
    {
        let child_region = state.create_child_region(self.region, budget)?;
        let child_budget = state
            .region(child_region)
            .map_or(self.budget, crate::record::RegionRecord::budget);
        let child_scope = Scope::<P2>::new(child_region, child_budget);

        let fut_result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(child_scope, &mut *state)));

        let fut = match fut_result {
            Ok(fut) => fut,
            Err(payload) => {
                let reason = CancelReason::fail_fast().with_region(child_region);
                let _ = state.cancel_request(child_region, &reason, None);

                // Factory panicked after `scope.spawn(...)` returned the
                // `(TaskHandle, StoredTask)` pair but before the StoredTask
                // was scheduled. The matching TaskRecord is orphaned in
                // `TaskState::Created` — no executor will ever poll it, so
                // `region.task_count()` stays > 0 and `advance_region_state`
                // loops forever in Closing. Rip out any such Created-state
                // records bound to this child region so the region can reach
                // Finalizing and the surrounding close future can complete.
                let orphan_task_ids: Vec<TaskId> = state
                    .tasks_iter()
                    .filter_map(|(_, t)| {
                        if t.owner == child_region && matches!(t.state, TaskState::Created) {
                            Some(t.id)
                        } else {
                            None
                        }
                    })
                    .collect();
                for task_id in orphan_task_ids {
                    if let Some(region) = state.region(child_region) {
                        region.remove_task(task_id);
                    }
                    let _ = state.remove_task(task_id);
                }

                if let Some(region) = state.region(child_region) {
                    region.begin_close(None);
                }
                state.advance_region_state(child_region);
                std::panic::resume_unwind(payload);
            }
        };

        let pinned_fut = std::pin::pin!(CatchUnwind { inner: fut });

        let runner = RegionRunner {
            fut: pinned_fut,
            state: Some(state),
            child_region,
        };

        let (result, state) = runner.await;
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(payload) => {
                let msg = payload_to_string(&payload);
                Outcome::Panicked(PanicPayload::new(msg))
            }
        };

        match &outcome {
            Outcome::Ok(_) => {
                if let Some(region) = state.region(child_region) {
                    region.begin_close(None);
                }
            }
            Outcome::Cancelled(reason) => {
                let _ = state.cancel_request(child_region, reason, None);
                if let Some(region) = state.region(child_region) {
                    region.begin_close(None);
                }
            }
            Outcome::Err(_) | Outcome::Panicked(_) => {
                let reason = CancelReason::fail_fast().with_region(child_region);
                let _ = state.cancel_request(child_region, &reason, None);
                if let Some(region) = state.region(child_region) {
                    region.begin_close(None);
                }
            }
        }

        let close_notify = state.region(child_region).map(|r| r.close_notify.clone());
        state.advance_region_state(child_region);

        if let Some(notify) = close_notify {
            RegionCloseFuture { state: notify }.await;
        }

        Ok(outcome)
    }

    // =========================================================================
    // Combinators
    // =========================================================================

    /// Joins two tasks, waiting for both to complete.
    ///
    /// This method waits for both tasks to complete, regardless of their outcome.
    /// It returns a tuple of results.
    ///
    /// # Example
    /// ```ignore
    /// let (h1, _) = scope.spawn(...);
    /// let (h2, _) = scope.spawn(...);
    /// let (r1, r2) = scope.join(cx, h1, h2).await;
    /// ```
    pub async fn join<T1, T2>(
        &self,
        cx: &Cx,
        mut h1: TaskHandle<T1>,
        mut h2: TaskHandle<T2>,
    ) -> (Result<T1, JoinError>, Result<T2, JoinError>) {
        let mut f1 = h1.join(cx);
        let mut f2 = h2.join(cx);
        let r1 = std::pin::Pin::new(&mut f1).await;
        let r2 = std::pin::Pin::new(&mut f2).await;
        (r1, r2)
    }

    /// Races two tasks, waiting for the first to complete.
    ///
    /// The loser is cancelled and drained (awaited until it completes cancellation).
    ///
    /// # Example
    /// ```ignore
    /// let (h1, _) = scope.spawn(...);
    /// let (h2, _) = scope.spawn(...);
    /// match scope.race(cx, h1, h2).await {
    ///     Ok(val) => println!("Winner result: {val}"),
    ///     Err(e) => println!("Race failed: {e}"),
    /// }
    /// ```
    fn best_effort_poll_loser_join<T>(cx: &Cx, handle: &mut TaskHandle<T>) {
        let mut drain = std::pin::pin!(handle.join(cx));
        let waker = std::task::Waker::noop();
        let mut poll_cx = std::task::Context::from_waker(waker);
        let _ = drain.as_mut().poll(&mut poll_cx);
    }

    /// Races two task handles and returns the winner while draining the loser.
    pub async fn race<T>(
        &self,
        cx: &Cx,
        mut h1: TaskHandle<T>,
        mut h2: TaskHandle<T>,
    ) -> Result<T, JoinError> {
        let winner = {
            let f1 = h1.join_with_drop_reason(cx, CancelReason::race_loser());
            let mut f1 = std::pin::pin!(f1);
            let f2 = h2.join_with_drop_reason(cx, CancelReason::race_loser());
            let mut f2 = std::pin::pin!(f2);
            Select::new(f1.as_mut(), f2.as_mut())
                .await
                .map_err(|_| JoinError::PolledAfterCompletion)?
        };

        match winner {
            Either::Left(res) => {
                if matches!(&res, Err(JoinError::Panicked(_)))
                    && crate::runtime::scheduler::three_lane::current_worker_id().is_none()
                {
                    // In direct block_on tests there is no scheduler driving the
                    // loser task after the winner panic surfaces. Best-effort poll
                    // once so a cooperative loser can observe cancellation, then
                    // preserve the winner panic without deadlocking the test.
                    Self::best_effort_poll_loser_join(cx, &mut h2);
                    return res;
                }
                let loser_res = h2.join(cx).await;
                if let Err(JoinError::Panicked(p)) = res {
                    Err(JoinError::Panicked(p))
                } else if let Err(JoinError::Panicked(p)) = loser_res {
                    Err(JoinError::Panicked(p))
                } else {
                    res
                }
            }
            Either::Right(res) => {
                if matches!(&res, Err(JoinError::Panicked(_)))
                    && crate::runtime::scheduler::three_lane::current_worker_id().is_none()
                {
                    // See the left-branch comment above.
                    Self::best_effort_poll_loser_join(cx, &mut h1);
                    return res;
                }
                let loser_res = h1.join(cx).await;
                if let Err(JoinError::Panicked(p)) = res {
                    Err(JoinError::Panicked(p))
                } else if let Err(JoinError::Panicked(p)) = loser_res {
                    Err(JoinError::Panicked(p))
                } else {
                    res
                }
            }
        }
    }

    /// Hedges a primary operation with a backup operation.
    ///
    /// 1. Spawns the primary task immediately.
    /// 2. Waits for the delay.
    /// 3. If primary finishes before delay: returns primary result.
    /// 4. If delay fires: spawns backup task and races them.
    ///
    /// The loser is cancelled and drained.
    ///
    /// # Arguments
    /// * `state` - The runtime state
    /// * `cx` - The capability context
    /// * `delay` - The hedge delay
    /// * `primary` - The primary future factory
    /// * `backup` - The backup future factory
    ///
    /// # Returns
    /// `Ok(T)` if successful, `Err(JoinError)` if failed/cancelled.
    pub async fn hedge<F1, Fut1, F2, Fut2, T>(
        &self,
        state: &mut RuntimeState,
        cx: &Cx,
        delay: std::time::Duration,
        primary: F1,
        backup: F2,
    ) -> Result<T, JoinError>
    where
        F1: FnOnce(Cx) -> Fut1 + Send + 'static,
        Fut1: Future<Output = T> + Send + 'static,
        F2: FnOnce(Cx) -> Fut2 + Send + 'static,
        Fut2: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        use crate::combinator::Either;
        use crate::combinator::select::Select;
        // 1. Spawn primary
        let mut h1 = self
            .spawn_registered(state, cx, primary)
            .map_err(|_| JoinError::Cancelled(CancelReason::resource_unavailable()))?;

        // 2. Race primary vs delay.
        // Scope the pinned join future so we can safely reuse h1 afterwards.
        let primary_or_delay = {
            let f1_primary = h1.join(cx);
            let mut f1_primary = std::pin::pin!(f1_primary);

            let now = cx
                .timer_driver()
                .map_or_else(crate::time::wall_now, |d| d.now());
            let sleep_fut = crate::time::sleep(now, delay);
            let mut sleep_pinned = std::pin::pin!(sleep_fut);

            let res = Select::new(f1_primary.as_mut(), sleep_pinned.as_mut())
                .await
                .map_err(|_| JoinError::PolledAfterCompletion)?;
            if matches!(res, Either::Right(())) {
                f1_primary.defuse_drop_abort();
            }
            res
        };

        match primary_or_delay {
            Either::Left(res) => {
                // Primary finished first
                res
            }
            Either::Right(()) => {
                // Timeout fired. Spawn backup.
                let Ok(mut h2) = self.spawn_registered(state, cx, backup) else {
                    // Backup admission failed after primary already started.
                    // Request cancellation on primary to avoid orphaned work.
                    h1.abort_with_reason(CancelReason::resource_unavailable());

                    if crate::runtime::scheduler::three_lane::current_worker_id().is_some() {
                        // In scheduler-backed runtime execution, fully drain the
                        // cancelled primary before returning.
                        match h1.join(cx).await {
                            Ok(res) => return Ok(res),
                            Err(JoinError::Panicked(p)) => return Err(JoinError::Panicked(p)),
                            Err(JoinError::Cancelled(_) | JoinError::PolledAfterCompletion) => {}
                        }
                    } else {
                        // In no-scheduler contexts (e.g. direct unit-test block_on),
                        // full join can deadlock because nothing drives stored tasks.
                        // Keep this as best-effort and return promptly.
                        let mut drain = std::pin::pin!(h1.join(cx));
                        let waker = std::task::Waker::noop();
                        let mut poll_cx = Context::from_waker(waker);
                        match drain.as_mut().poll(&mut poll_cx) {
                            std::task::Poll::Ready(Ok(res)) => return Ok(res),
                            std::task::Poll::Ready(Err(JoinError::Panicked(p))) => {
                                return Err(JoinError::Panicked(p));
                            }
                            _ => {}
                        }
                    }

                    return Err(JoinError::Cancelled(CancelReason::resource_unavailable()));
                };

                // Now race h1 and h2 with bounded future borrows.
                let race_outcome = {
                    let f1_race = h1.join_with_drop_reason(cx, CancelReason::race_loser());
                    let mut f1_race = std::pin::pin!(f1_race);
                    let f2_race = h2.join_with_drop_reason(cx, CancelReason::race_loser());
                    let mut f2_race = std::pin::pin!(f2_race);
                    Select::new(f1_race.as_mut(), f2_race.as_mut())
                        .await
                        .map_err(|_| JoinError::PolledAfterCompletion)?
                };

                match race_outcome {
                    Either::Left(res) => {
                        if matches!(&res, Err(JoinError::Panicked(_)))
                            && crate::runtime::scheduler::three_lane::current_worker_id().is_none()
                        {
                            Self::best_effort_poll_loser_join(cx, &mut h2);
                            return res;
                        }
                        let loser_res = h2.join(cx).await;
                        if let Err(JoinError::Panicked(p)) = res {
                            Err(JoinError::Panicked(p))
                        } else if let Err(JoinError::Panicked(p)) = loser_res {
                            Err(JoinError::Panicked(p))
                        } else {
                            res
                        }
                    }
                    Either::Right(res) => {
                        if matches!(&res, Err(JoinError::Panicked(_)))
                            && crate::runtime::scheduler::three_lane::current_worker_id().is_none()
                        {
                            Self::best_effort_poll_loser_join(cx, &mut h1);
                            return res;
                        }
                        let loser_res = h1.join(cx).await;
                        if let Err(JoinError::Panicked(p)) = res {
                            Err(JoinError::Panicked(p))
                        } else if let Err(JoinError::Panicked(p)) = loser_res {
                            Err(JoinError::Panicked(p))
                        } else {
                            res
                        }
                    }
                }
            }
        }
    }

    /// Races multiple tasks, waiting for the first to complete.
    ///
    /// The winner's result is returned. Losers are cancelled and drained.
    ///
    /// # Arguments
    /// * `cx` - The capability context
    /// * `handles` - Vector of task handles to race
    ///
    /// # Returns
    /// `Ok((value, index))` if the winner succeeded.
    /// `Err(e)` if the winner failed (error/cancel/panic).
    pub async fn race_all<T>(
        &self,
        cx: &Cx,
        handles: Vec<TaskHandle<T>>,
    ) -> Result<(T, usize), JoinError> {
        let mut handles = handles;
        if handles.is_empty() {
            return std::future::poll_fn(|_poll_cx| {
                if cx.checkpoint().is_err() {
                    let reason = cx
                        .cancel_reason()
                        .unwrap_or_else(|| CancelReason::user("race_all cancelled"));
                    std::task::Poll::Ready(Err(JoinError::Cancelled(reason)))
                } else {
                    std::task::Poll::Pending
                }
            })
            .await;
        }

        let mut futures: Vec<_> = handles
            .iter_mut()
            .map(|h| h.join_with_drop_reason(cx, CancelReason::race_loser()))
            .collect();
        let mut ready_results: Vec<Option<Result<T, JoinError>>> = std::iter::repeat_with(|| None)
            .take(futures.len())
            .collect();

        // Poll every candidate in each round and keep all same-round ready
        // outcomes. This prevents losing loser panic outcomes when multiple
        // tasks become ready in the same poll.
        let winner_idx = std::future::poll_fn(|poll_cx| {
            let mut newly_ready = Vec::new();

            for (i, future) in futures.iter_mut().enumerate() {
                if ready_results[i].is_some() {
                    continue;
                }
                if let std::task::Poll::Ready(res) = std::pin::Pin::new(future).poll(poll_cx) {
                    ready_results[i] = Some(res);
                    newly_ready.push(i);
                }
            }

            if newly_ready.is_empty() {
                std::task::Poll::Pending
            } else {
                // Fairly select a winner among all that became ready in this round
                let chosen = newly_ready[cx.random_usize(newly_ready.len())];
                std::task::Poll::Ready(chosen)
            }
        })
        .await;

        let winner_result = ready_results[winner_idx]
            .take()
            .expect("winner index must have a ready result");

        // Release mutable borrows of handles held by JoinFuture values before
        // explicit loser cancellation/join.
        drop(futures);

        // Drain completed losers first so terminal panic outcomes are not
        // obscured by strengthening cancellation reasons on already-finished tasks.
        let mut loser_panic = None;
        let mut pending_loser_indices = Vec::new();
        for (i, handle) in handles.iter_mut().enumerate() {
            if i == winner_idx {
                continue;
            }
            if let Some(res) = ready_results[i].take() {
                if let Err(JoinError::Panicked(p)) = res {
                    if loser_panic.is_none() {
                        loser_panic = Some(p);
                    }
                }
            } else if handle.is_finished() {
                let res = handle.join(cx).await;
                if let Err(JoinError::Panicked(p)) = res {
                    if loser_panic.is_none() {
                        loser_panic = Some(p);
                    }
                }
            } else {
                pending_loser_indices.push(i);
            }
        }

        // Cancel and drain unfinished losers.
        // Note: Losers may also already have a race-loser reason from dropped
        // join futures; strengthening keeps attribution deterministic.
        for &idx in &pending_loser_indices {
            handles[idx].abort_with_reason(CancelReason::race_loser());
        }
        if matches!(&winner_result, Err(JoinError::Panicked(_)))
            && crate::runtime::scheduler::three_lane::current_worker_id().is_none()
        {
            // In direct block_on tests there is no scheduler driving pending
            // losers after the winner panic surfaces. Best-effort poll each
            // loser once so cooperative tasks can observe cancellation, then
            // preserve the winner panic without deadlocking the test.
            for idx in pending_loser_indices {
                Self::best_effort_poll_loser_join(cx, &mut handles[idx]);
            }
            return winner_result.map(|val| (val, winner_idx));
        }
        for idx in pending_loser_indices {
            let res = handles[idx].join(cx).await;
            if let Err(JoinError::Panicked(p)) = res {
                if loser_panic.is_none() {
                    loser_panic = Some(p);
                }
            }
        }

        let winner_result = winner_result.map(|val| (val, winner_idx));
        if matches!(&winner_result, Err(JoinError::Panicked(_))) {
            return winner_result;
        }

        loser_panic.map_or(winner_result, |panic_payload| {
            Err(JoinError::Panicked(panic_payload))
        })
    }

    /// Joins multiple tasks, waiting for all to complete.
    ///
    /// Returns a vector of results in the same order as the input handles.
    pub async fn join_all<T>(
        &self,
        cx: &Cx,
        mut handles: Vec<TaskHandle<T>>,
    ) -> Vec<Result<T, JoinError>> {
        let mut futures: Vec<_> = handles.iter_mut().map(|h| h.join(cx)).collect();
        let mut results = Vec::with_capacity(futures.len());
        for fut in &mut futures {
            results.push(std::pin::Pin::new(fut).await);
        }
        results
    }

    pub(crate) fn build_child_task_cx<Caps>(
        &self,
        state: &RuntimeState,
        parent_cx: &Cx<Caps>,
        task_id: TaskId,
    ) -> (Cx<Caps>, Cx<cap::All>) {
        let child_observability = parent_cx.child_observability(self.region, task_id);
        let child_entropy = parent_cx.child_entropy(task_id);
        let io_driver = state.io_driver_handle();
        let timer_driver = state.timer_driver_handle();
        let logical_clock = state
            .logical_clock_mode()
            .build_handle(timer_driver.clone());

        let child_cx = Cx::<Caps>::new_with_drivers(
            self.region,
            task_id,
            self.budget,
            Some(child_observability),
            io_driver,
            parent_cx.io_cap_handle(),
            timer_driver,
            Some(child_entropy),
        )
        .with_logical_clock(logical_clock)
        .with_registry_handle(parent_cx.registry_handle())
        .with_remote_cap_handle(parent_cx.remote_cap_handle())
        .with_blocking_pool_handle(parent_cx.blocking_pool_handle())
        .with_evidence_sink(parent_cx.evidence_sink_handle())
        .with_macaroon_handle(parent_cx.macaroon_handle());
        let child_cx = if let Some(pressure) = parent_cx.pressure_handle() {
            child_cx.with_pressure(pressure)
        } else {
            child_cx
        };
        child_cx.set_trace_buffer(state.trace_handle());
        let child_cx_full = child_cx.retype::<cap::All>();

        (child_cx, child_cx_full)
    }

    /// Creates a task record in the runtime state.
    ///
    /// This is a helper method used by all spawn variants.
    pub(crate) fn create_task_record(
        &self,
        state: &mut RuntimeState,
    ) -> Result<TaskId, SpawnError> {
        use crate::util::ArenaIndex;

        let now = state
            .timer_driver()
            .map_or(state.now, crate::time::TimerDriverHandle::now);

        // Create placeholder task record
        let idx = state.insert_task(TaskRecord::new_with_time(
            TaskId::from_arena(ArenaIndex::new(0, 0)), // placeholder ID
            self.region,
            self.budget,
            now,
        ));

        // Get the real task ID from the arena index
        let task_id = TaskId::from_arena(idx);

        // Update the task record with the correct ID
        if let Some(record) = state.task_mut(task_id) {
            record.id = task_id;
        }

        // Add task to the owning region
        if let Some(region) = state.region(self.region) {
            if let Err(err) = region.add_task(task_id) {
                // Rollback task creation
                state.remove_task(task_id);
                return Err(match err {
                    AdmissionError::Closed => SpawnError::RegionClosed(self.region),
                    AdmissionError::LimitReached { limit, live, .. } => {
                        SpawnError::RegionAtCapacity {
                            region: self.region,
                            limit,
                            live,
                        }
                    }
                });
            }
        } else {
            // Rollback task creation
            state.remove_task(task_id);
            return Err(SpawnError::RegionNotFound(self.region));
        }

        state.record_task_spawn(task_id, self.region);

        Ok(task_id)
    }

    // =========================================================================
    // Finalizer Registration
    // =========================================================================

    /// Registers a synchronous finalizer to run when the region closes.
    ///
    /// Finalizers are stored in LIFO order and executed during the Finalizing
    /// phase, after all children have completed. Use this for lightweight
    /// cleanup that doesn't need to await.
    ///
    /// # Arguments
    /// * `state` - The runtime state
    /// * `f` - The synchronous cleanup function
    ///
    /// # Returns
    /// `true` if the finalizer was registered successfully.
    ///
    /// # Example
    /// ```ignore
    /// scope.defer_sync(&mut state, || {
    ///     println!("Cleaning up!");
    /// });
    /// ```
    pub fn defer_sync<F>(&self, state: &mut RuntimeState, f: F) -> bool
    where
        F: FnOnce() + Send + 'static,
    {
        state.register_sync_finalizer(self.region, f)
    }

    /// Registers an asynchronous finalizer to run when the region closes.
    ///
    /// Async finalizers run under a cancel mask to prevent interruption.
    /// They are driven to completion with a bounded budget. Use this for
    /// cleanup that needs to perform async operations (e.g., closing
    /// connections, flushing buffers).
    ///
    /// # Arguments
    /// * `state` - The runtime state
    /// * `future` - The async cleanup future
    ///
    /// # Returns
    /// `true` if the finalizer was registered successfully.
    ///
    /// # Example
    /// ```ignore
    /// scope.defer_async(&mut state, async {
    ///     close_connection().await;
    /// });
    /// ```
    pub fn defer_async<F>(&self, state: &mut RuntimeState, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        state.register_async_finalizer(self.region, future)
    }
}

impl<P: Policy> std::fmt::Debug for Scope<'_, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scope")
            .field("region", &self.region)
            .field("budget", &self.budget)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;
    use crate::record::RegionLimits;
    use crate::runtime::RuntimeState;
    use crate::types::{CancelKind, Outcome, Time};
    use crate::util::ArenaIndex;
    use futures_lite::future::block_on;
    use std::sync::Arc;

    fn test_cx() -> Cx {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    fn test_scope(region: RegionId, budget: Budget) -> Scope<'static> {
        Scope::new(region, budget)
    }

    #[test]
    fn spawn_creates_task_record() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (handle, _stored) = scope.spawn(&mut state, &cx, |_| async { 42_i32 }).unwrap();

        // Task should exist in state
        let task = state.task(handle.task_id());
        assert!(task.is_some());

        // Task should be owned by the region
        let task = task.unwrap();
        assert_eq!(task.owner, region);
    }

    #[test]
    fn spawn_inherits_registry_and_remote_capabilities() {
        use crate::cx::registry::RegistryHandle;
        use crate::remote::{NodeId, RemoteCap};
        use std::task::Context;

        let mut state = RuntimeState::new();

        let registry = crate::cx::NameRegistry::new();
        let registry_handle = RegistryHandle::new(Arc::new(registry));
        let parent_registry_arc = registry_handle.as_arc();

        let cx = test_cx()
            .with_registry_handle(Some(registry_handle))
            .with_remote_cap(RemoteCap::new().with_local_node(NodeId::new("origin-test")));

        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let mut handle = scope
            .spawn_registered(&mut state, &cx, move |cx| async move {
                let child_registry = cx.registry_handle().expect("child must inherit registry");
                let child_registry_arc = child_registry.as_arc();
                let same_registry = Arc::ptr_eq(&child_registry_arc, &parent_registry_arc);

                let child_remote = cx.remote().expect("child must inherit remote cap");
                let origin = child_remote.local_node().as_str().to_owned();

                (same_registry, origin)
            })
            .unwrap();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);

        let stored = state
            .get_stored_future(handle.task_id())
            .expect("spawn_registered must store the task");
        assert!(stored.poll(&mut poll_cx).is_ready());

        let mut join_fut = std::pin::pin!(handle.join(&cx));
        match join_fut.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Ok((same_registry, origin))) => {
                assert!(
                    same_registry,
                    "child should observe the same RegistryCap instance"
                );
                assert_eq!(origin, "origin-test");
            }
            other => unreachable!("Expected Ready(Ok(_)), got {other:?}"),
        }
    }

    #[test]
    fn spawn_inherits_runtime_timer_driver() {
        use std::task::Context;

        let mut state = RuntimeState::new();
        let clock = Arc::new(crate::time::VirtualClock::new());
        state.set_timer_driver(crate::time::TimerDriverHandle::with_virtual_clock(clock));

        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (mut handle, mut stored) = scope
            .spawn(&mut state, &cx, |cx| async move { cx.has_timer() })
            .expect("spawn should succeed");

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);
        assert!(stored.poll(&mut poll_cx).is_ready());

        let mut join_fut = std::pin::pin!(handle.join(&cx));
        match join_fut.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Ok(has_timer)) => assert!(has_timer),
            other => unreachable!("Expected Ready(Ok(_)), got {other:?}"),
        }
    }

    #[test]
    fn create_task_record_uses_runtime_timer_driver_time() {
        let mut state = RuntimeState::new();
        let clock = Arc::new(crate::time::VirtualClock::starting_at(Time::from_millis(
            11,
        )));
        state.set_timer_driver(crate::time::TimerDriverHandle::with_virtual_clock(
            clock.clone(),
        ));

        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        clock.advance(Time::from_millis(7).as_nanos());
        let task_id = scope
            .create_task_record(&mut state)
            .expect("task record should be created");

        let task = state.task(task_id).expect("task record");
        assert_eq!(task.created_at, Time::from_millis(18));
    }

    #[test]
    fn spawn_blocking_inherits_runtime_timer_driver() {
        use std::task::Context;

        let mut state = RuntimeState::new();
        let clock = Arc::new(crate::time::VirtualClock::new());
        state.set_timer_driver(crate::time::TimerDriverHandle::with_virtual_clock(clock));

        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (mut handle, mut stored) = scope
            .spawn_blocking(&mut state, &cx, |cx| cx.has_timer())
            .expect("spawn_blocking should succeed");

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);
        assert!(stored.poll(&mut poll_cx).is_ready());

        let mut join_fut = std::pin::pin!(handle.join(&cx));
        match join_fut.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Ok(has_timer)) => assert!(has_timer),
            other => unreachable!("Expected Ready(Ok(_)), got {other:?}"),
        }
    }

    #[test]
    fn spawn_registered_stores_task() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // spawn_registered should both create and store the task
        let handle = scope
            .spawn_registered(&mut state, &cx, |_| async { 42_i32 })
            .unwrap();

        // Task record should exist
        let task = state.task(handle.task_id());
        assert!(task.is_some());
        assert_eq!(task.unwrap().owner, region);

        // StoredTask should be registered (can be retrieved for polling)
        let stored = state.get_stored_future(handle.task_id());
        assert!(stored.is_some(), "spawn_registered should store the task");
    }

    #[test]
    fn spawn_registered_task_can_be_polled() {
        use std::task::Context;

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let mut handle = scope
            .spawn_registered(&mut state, &cx, |_| async { 42_i32 })
            .unwrap();

        // Get the stored future and poll it
        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);

        let stored = state.get_stored_future(handle.task_id()).unwrap();
        let poll_result = stored.poll(&mut poll_cx);
        assert!(
            poll_result.is_ready(),
            "Simple async should complete in one poll"
        );

        // Join should now have the result
        let mut join_fut = std::pin::pin!(handle.join(&cx));
        match join_fut.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Ok(val)) => assert_eq!(val, 42),
            other => unreachable!("Expected Ready(Ok(42)), got {other:?}"),
        }
    }

    #[test]
    fn spawn_blocking_creates_task_record() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (handle, _stored) = scope.spawn_blocking(&mut state, &cx, |_| 42_i32).unwrap();

        // Task should exist
        let task = state.task(handle.task_id());
        assert!(task.is_some());
        assert_eq!(task.unwrap().owner, region);
    }

    #[test]
    fn spawn_local_creates_task_record() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let local_ready = Arc::new(parking_lot::Mutex::new(std::collections::VecDeque::new()));
        let _local_ready_guard =
            crate::runtime::scheduler::three_lane::ScopedLocalReady::new(Arc::clone(&local_ready));
        let _worker_guard = crate::runtime::scheduler::three_lane::ScopedWorkerId::new(1);

        // In Phase 0, spawn_local requires Send bounds
        // In Phase 1+, this will work with !Send futures
        let handle = scope
            .spawn_local(&mut state, &cx, |_| async move { 42_i32 })
            .unwrap();

        // Task should exist
        let task = state.task(handle.task_id());
        assert!(task.is_some());
        assert_eq!(task.unwrap().owner, region);
    }

    #[test]
    fn spawn_local_without_scheduler_fails_and_rolls_back() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let result = scope.spawn_local(&mut state, &cx, |_| async move { 5_i32 });
        assert!(matches!(result, Err(SpawnError::LocalSchedulerUnavailable)));

        // Task should not exist
        assert!(state.tasks_is_empty());
        let region_record = state.region(region).unwrap();
        assert!(region_record.task_ids().is_empty());
    }

    #[test]
    fn spawn_local_makes_progress_via_local_ready() {
        use std::sync::Arc;
        use std::task::Context;

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let local_ready = Arc::new(parking_lot::Mutex::new(std::collections::VecDeque::new()));
        let _local_ready_guard =
            crate::runtime::scheduler::three_lane::ScopedLocalReady::new(Arc::clone(&local_ready));
        let _worker_guard = crate::runtime::scheduler::three_lane::ScopedWorkerId::new(1);

        let mut handle = scope
            .spawn_local(&mut state, &cx, |_| async move { 7_i32 })
            .unwrap();

        let queued = {
            let queue = local_ready.lock();
            queue.contains(&handle.task_id())
        };
        assert!(queued, "spawn_local should enqueue into local_ready");

        let task_id = {
            let mut queue = local_ready.lock();
            queue
                .pop_front()
                .expect("local_ready should contain spawned task")
        };

        let mut join_fut = std::pin::pin!(handle.join(&cx));
        let waker = std::task::Waker::noop().clone();
        let mut ctx = Context::from_waker(&waker);

        assert!(join_fut.as_mut().poll(&mut ctx).is_pending());

        let mut local_task =
            crate::runtime::local::remove_local_task(task_id).expect("local task missing");
        assert!(local_task.poll(&mut ctx).is_ready());

        match join_fut.as_mut().poll(&mut ctx) {
            Poll::Ready(Ok(val)) => assert_eq!(val, 7),
            res => unreachable!("Expected Ready(Ok(7)), got {res:?}"),
        }
    }

    #[test]
    fn task_added_to_region() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (handle, _stored) = scope.spawn(&mut state, &cx, |_| async { 42_i32 }).unwrap();

        // Check region has the task
        let region_record = state.region(region).unwrap();
        assert!(region_record.task_ids().contains(&handle.task_id()));
    }

    #[test]
    fn multiple_spawns_create_distinct_tasks() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (handle1, _) = scope.spawn(&mut state, &cx, |_| async { 1_i32 }).unwrap();
        let (handle2, _) = scope.spawn(&mut state, &cx, |_| async { 2_i32 }).unwrap();
        let (handle3, _) = scope.spawn(&mut state, &cx, |_| async { 3_i32 }).unwrap();

        // All task IDs should be different
        assert_ne!(handle1.task_id(), handle2.task_id());
        assert_ne!(handle2.task_id(), handle3.task_id());
        assert_ne!(handle1.task_id(), handle3.task_id());

        // All tasks should be in the region
        let region_record = state.region(region).unwrap();
        assert!(region_record.task_ids().contains(&handle1.task_id()));
        assert!(region_record.task_ids().contains(&handle2.task_id()));
        assert!(region_record.task_ids().contains(&handle3.task_id()));
    }

    #[test]
    fn spawn_into_closing_region_should_fail() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Transition region to Closing
        let region_record = state.region_mut(region).expect("region");
        region_record.begin_close(None);

        // Attempt to spawn should fail
        let result = scope.spawn(&mut state, &cx, |_| async { 42 });
        assert!(matches!(result, Err(SpawnError::RegionClosed(_))));
    }

    #[test]
    fn test_join_manual_poll() {
        use std::task::Context;

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Spawn a task
        let (mut handle, mut stored_task) =
            scope.spawn(&mut state, &cx, |_| async { 42_i32 }).unwrap();
        // The stored task is returned directly, not put in state by scope.spawn

        // Create join future
        let mut join_fut = std::pin::pin!(handle.join(&cx));

        // Create waker context
        let waker = std::task::Waker::noop().clone();
        let mut ctx = Context::from_waker(&waker);

        // Poll join - should be pending
        assert!(join_fut.as_mut().poll(&mut ctx).is_pending());

        // Poll stored task - should complete and send result
        assert!(stored_task.poll(&mut ctx).is_ready());

        // Poll join - should be ready now
        match join_fut.as_mut().poll(&mut ctx) {
            Poll::Ready(Ok(val)) => assert_eq!(val, 42),
            other => unreachable!("Expected Ready(Ok(42)), got {other:?}"),
        }
    }

    #[test]
    fn spawn_abort_cancels_task() {
        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Spawn a task that checks for cancellation
        let (mut handle, mut stored_task) = scope
            .spawn(&mut state, &cx, |cx| async move {
                // We expect to be cancelled immediately because abort() is called before we run
                if cx.checkpoint().is_err() {
                    return "cancelled";
                }
                "finished"
            })
            .unwrap();

        // Abort the task via handle
        handle.abort();

        // Drive the task
        let waker = std::task::Waker::noop().clone();
        let mut ctx = Context::from_waker(&waker);

        // Task should run, see cancellation, and return "cancelled"
        match stored_task.poll(&mut ctx) {
            Poll::Ready(crate::types::Outcome::Ok(())) => {}
            res => unreachable!("Task should have completed with Ok(()), got {res:?}"),
        }

        // Check result via handle
        let mut join_fut = std::pin::pin!(handle.join(&cx));
        match join_fut.as_mut().poll(&mut ctx) {
            Poll::Ready(Ok(val)) => assert_eq!(val, "cancelled"),
            Poll::Ready(Err(e)) => unreachable!("Task failed unexpectedly: {e}"),
            Poll::Pending => unreachable!("Join should be ready"),
        }
    }

    #[test]
    fn hedge_backup_spawn_failure_aborts_primary() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let limits = RegionLimits {
            max_tasks: Some(1),
            ..RegionLimits::unlimited()
        };
        assert!(state.set_region_limits(region, limits));

        let result = block_on(scope.hedge(
            &mut state,
            &cx,
            std::time::Duration::ZERO,
            |_| async { 1_u8 },
            |_| async { 2_u8 },
        ));

        assert!(matches!(
            result,
            Err(JoinError::Cancelled(reason))
                if reason.kind == CancelKind::ResourceUnavailable
        ));

        let task_id = *state
            .region(region)
            .expect("region missing")
            .task_ids()
            .first()
            .expect("primary task should remain tracked");

        let task = state.task(task_id).expect("primary task record missing");
        let (cancel_requested, cancel_reason_kind) = {
            let inner = task
                .cx_inner
                .as_ref()
                .expect("primary task must have shared Cx inner")
                .read();
            (
                inner.cancel_requested,
                inner.cancel_reason.as_ref().map(|r| r.kind),
            )
        };

        assert!(
            cancel_requested,
            "primary task must be cancellation-requested when backup spawn fails"
        );
        assert_eq!(cancel_reason_kind, Some(CancelKind::ResourceUnavailable));
    }

    #[test]
    fn region_closes_empty_child() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let parent = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(parent, Budget::INFINITE);

        let outcome = block_on(scope.region(
            &mut state,
            &cx,
            crate::types::policy::FailFast,
            |child, _state| {
                let child_id = child.region_id();
                async move { Outcome::Ok(child_id) }
            },
        ))
        .expect("child region created");

        let child_id = match outcome {
            Outcome::Ok(id) => id,
            other => unreachable!("expected Outcome::Ok(child_id), got {other:?}"),
        };

        assert!(
            state.region(child_id).is_none(),
            "closed child region should be reclaimed from arena"
        );

        let parent_record = state.region(parent).expect("parent record missing");
        assert!(
            !parent_record.child_ids().contains(&child_id),
            "closed child should be removed from parent"
        );
    }

    #[test]
    fn region_budget_is_met_with_parent() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let parent = state.create_root_region(Budget::with_deadline_secs(10));
        let scope = test_scope(parent, Budget::with_deadline_secs(10));

        let outcome = block_on(scope.region_with_budget(
            &mut state,
            &cx,
            Budget::with_deadline_secs(30),
            crate::types::policy::FailFast,
            |child, _state| {
                let child_id = child.region_id();
                let child_budget = child.budget();
                async move { Outcome::Ok((child_id, child_budget)) }
            },
        ))
        .expect("child region created");

        let (child_id, child_budget) = match outcome {
            Outcome::Ok(tuple) => tuple,
            other => unreachable!("expected Outcome::Ok(child_id), got {other:?}"),
        };

        assert_eq!(
            child_budget.deadline,
            Some(crate::types::Time::from_secs(10))
        );
        assert!(
            state.region(child_id).is_none(),
            "closed child region should be reclaimed from arena"
        );
    }

    #[test]
    fn region_spawns_tasks_in_child() {
        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let parent = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(parent, Budget::INFINITE);

        let outcome = block_on(scope.region(
            &mut state,
            &cx,
            crate::types::policy::FailFast,
            |child, state| {
                let child_id = child.region_id();
                let (handle, mut stored) = child
                    .spawn(state, &cx, |_| async { 7_i32 })
                    .expect("spawn in child");

                let parent_has = state
                    .region(parent)
                    .expect("parent record missing")
                    .task_ids()
                    .contains(&handle.task_id());
                let child_has = state
                    .region(child_id)
                    .expect("child record missing")
                    .task_ids()
                    .contains(&handle.task_id());

                let waker = std::task::Waker::noop().clone();
                let mut poll_cx = Context::from_waker(&waker);
                let poll_result = stored.poll(&mut poll_cx);
                if let Poll::Ready(outcome) = poll_result {
                    let task_outcome = match outcome {
                        Outcome::Ok(()) => Outcome::Ok(()),
                        Outcome::Panicked(payload) => Outcome::Panicked(payload),
                        other => unreachable!("unexpected task outcome: {other:?}"),
                    };
                    if let Some(task_record) = state.task_mut(handle.task_id()) {
                        task_record.complete(task_outcome);
                    }
                    let _ = state.task_completed(handle.task_id());
                }

                std::future::ready(Outcome::Ok((child_id, parent_has, child_has)))
            },
        ))
        .expect("child region created");

        let (child_id, parent_has, child_has) = match outcome {
            Outcome::Ok(tuple) => tuple,
            other => unreachable!("expected Outcome::Ok(tuple), got {other:?}"),
        };

        assert!(!parent_has, "task should not be owned by parent region");
        assert!(child_has, "task should be owned by child region");

        let parent_record = state.region(parent).expect("parent record missing");
        assert!(
            !parent_record.child_ids().contains(&child_id),
            "closed child should be removed from parent"
        );
    }

    #[test]
    fn spawn_panic_propagates_as_panicked_error() {
        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (mut handle, mut stored_task) = scope
            .spawn(&mut state, &cx, |_| async {
                std::panic::panic_any("oops");
            })
            .unwrap();

        // Drive the task
        let waker = std::task::Waker::noop().clone();
        let mut ctx = Context::from_waker(&waker);

        // Polling stored task should return Ready(Panicked) even if it panics (caught inside)
        match stored_task.poll(&mut ctx) {
            Poll::Ready(crate::types::Outcome::Panicked(_)) => {}
            res => unreachable!("Task should have completed with Panicked, got {res:?}"),
        }

        // Check result via handle
        let mut join_fut = std::pin::pin!(handle.join(&cx));
        match join_fut.as_mut().poll(&mut ctx) {
            Poll::Ready(Err(JoinError::Panicked(p))) => {
                assert_eq!(p.message(), "oops");
            }
            res => unreachable!("Expected Panicked, got {res:?}"),
        }
    }

    #[test]
    fn join_all_success() {
        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (h1, mut t1) = scope.spawn(&mut state, &cx, |_| async { 1 }).unwrap();
        let (h2, mut t2) = scope.spawn(&mut state, &cx, |_| async { 2 }).unwrap();

        // Drive tasks to completion
        let waker = std::task::Waker::noop().clone();
        let mut ctx = Context::from_waker(&waker);
        assert!(t1.poll(&mut ctx).is_ready());
        assert!(t2.poll(&mut ctx).is_ready());

        let handles = vec![h1, h2];
        let mut fut = Box::pin(scope.join_all(&cx, handles));

        match fut.as_mut().poll(&mut ctx) {
            Poll::Ready(results) => {
                assert_eq!(results.len(), 2);
                assert_eq!(results[0].as_ref().unwrap(), &1);
                assert_eq!(results[1].as_ref().unwrap(), &2);
            }
            Poll::Pending => unreachable!("join_all should be ready"),
        }
    }

    #[test]
    fn race_all_aborted_task_is_drained() {
        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Task 1: completes immediately
        let (h1, mut t1) = scope.spawn(&mut state, &cx, |_| async { 1 }).unwrap();

        // Task 2: yields once, checking for cancellation
        let (h2, mut t2) = scope
            .spawn(&mut state, &cx, |cx| async move {
                // Yield once to simulate running
                struct YieldOnce(bool);
                impl std::future::Future for YieldOnce {
                    type Output = ();
                    fn poll(
                        mut self: std::pin::Pin<&mut Self>,
                        cx: &mut std::task::Context<'_>,
                    ) -> std::task::Poll<()> {
                        if self.0 {
                            std::task::Poll::Ready(())
                        } else {
                            self.0 = true;
                            cx.waker().wake_by_ref();
                            std::task::Poll::Pending
                        }
                    }
                }
                YieldOnce(false).await;

                // Check cancellation
                if cx.checkpoint().is_err() {
                    return 0; // Cancelled
                }
                2
            })
            .unwrap();

        let waker = std::task::Waker::noop().clone();
        let mut ctx = Context::from_waker(&waker);

        // Drive t1 to completion (winner)
        assert!(t1.poll(&mut ctx).is_ready());

        // Initialize race_all
        let handles = vec![h1, h2];
        let mut race_fut = Box::pin(scope.race_all(&cx, handles));

        // Poll race_all.
        // It sees h1 ready. Winner=0.
        // It aborts h2.
        // It awaits h2 drain.
        // h2 is still pending (hasn't run), so h2.join() returns Pending.
        // race_fut returns Pending.
        assert!(race_fut.as_mut().poll(&mut ctx).is_pending());

        // Now drive t2. It was aborted, so it should see cancellation if checked?
        // Wait, handle.abort() sets inner.cancel_requested.
        // But my t2 closure yields first.
        // So first poll of t2 -> YieldOnce returns Pending.
        assert!(t2.poll(&mut ctx).is_pending());

        // Poll race_fut again. Still waiting for h2 drain.
        assert!(race_fut.as_mut().poll(&mut ctx).is_pending());

        // Poll t2 again. YieldOnce finishes.
        // Then it hits checkpoint(). cancel_requested is true.
        // It returns 0 (simulated cancellation return).
        // Actually, normally tasks return Result or are wrapped.
        // Here spawn returns Result<i32>.
        // My closure returns i32.
        // So h2.join() will return Ok(0).
        // This counts as "drained".
        assert!(t2.poll(&mut ctx).is_ready());

        // Now poll race_fut. h2 drain complete.
        // Should return (1, 0).
        match race_fut.as_mut().poll(&mut ctx) {
            Poll::Ready(Ok((val, idx))) => {
                assert_eq!(val, 1);
                assert_eq!(idx, 0);
            }
            res => unreachable!("Expected Ready(Ok((1, 0))), got {res:?}"),
        }
    }

    #[test]
    fn race_surfaces_loser_panic_even_if_winner_succeeds() {
        use std::task::Context;

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (h1, mut t1) = scope.spawn(&mut state, &cx, |_| async { 1_i32 }).unwrap();
        let (h2, mut t2) = scope
            .spawn(&mut state, &cx, |_| async {
                std::panic::panic_any("loser panic");
            })
            .unwrap();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);
        assert!(t1.poll(&mut poll_cx).is_ready());
        assert!(t2.poll(&mut poll_cx).is_ready());

        let result = block_on(scope.race(&cx, h1, h2));
        assert!(
            matches!(result, Err(JoinError::Panicked(_))),
            "loser panic must dominate race result, got {result:?}"
        );
    }

    #[test]
    fn race_preserves_winner_panic_over_loser_panic() {
        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (h1, mut t1) = scope
            .spawn(&mut state, &cx, |_| async {
                std::panic::panic_any("winner panic");
            })
            .unwrap();
        let (h2, mut t2) = scope
            .spawn(&mut state, &cx, |_| {
                let mut first_poll = true;
                std::future::poll_fn(move |poll_cx| {
                    if first_poll {
                        first_poll = false;
                        poll_cx.waker().wake_by_ref();
                        Poll::Pending
                    } else {
                        std::panic::panic_any("loser panic");
                    }
                })
            })
            .unwrap();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);
        assert!(t1.poll(&mut poll_cx).is_ready());
        assert!(t2.poll(&mut poll_cx).is_pending());

        let result = block_on(scope.race(&cx, h1, h2));
        match result {
            Err(JoinError::Panicked(payload)) => {
                assert_eq!(payload.message(), "winner panic");
            }
            other => unreachable!("winner panic must dominate race result, got {other:?}"),
        }
    }

    #[test]
    fn race_all_surfaces_simultaneous_loser_panic() {
        use std::task::Context;

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (h1, mut t1) = scope.spawn(&mut state, &cx, |_| async { 1_i32 }).unwrap();
        let (h2, mut t2) = scope
            .spawn(&mut state, &cx, |_| async {
                std::panic::panic_any("simultaneous loser panic");
            })
            .unwrap();
        let (h3, mut t3) = scope.spawn(&mut state, &cx, |_| async { 3_i32 }).unwrap();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);
        assert!(t1.poll(&mut poll_cx).is_ready());
        assert!(t2.poll(&mut poll_cx).is_ready());
        assert!(t3.poll(&mut poll_cx).is_ready());

        let result = block_on(scope.race_all(&cx, vec![h1, h2, h3]));
        assert!(
            matches!(result, Err(JoinError::Panicked(_))),
            "simultaneous loser panic must dominate race_all result, got {result:?}"
        );
    }

    #[test]
    fn race_all_preserves_winner_panic_over_loser_panic() {
        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (h1, mut t1) = scope
            .spawn(&mut state, &cx, |_| async {
                std::panic::panic_any("winner panic");
            })
            .unwrap();
        let (h2, mut t2) = scope
            .spawn(&mut state, &cx, |_| {
                let mut first_poll = true;
                std::future::poll_fn(move |poll_cx| {
                    if first_poll {
                        first_poll = false;
                        poll_cx.waker().wake_by_ref();
                        Poll::Pending
                    } else {
                        std::panic::panic_any("loser panic");
                    }
                })
            })
            .unwrap();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);
        assert!(t1.poll(&mut poll_cx).is_ready());
        assert!(t2.poll(&mut poll_cx).is_pending());

        let result = block_on(scope.race_all(&cx, vec![h1, h2]));
        match result {
            Err(JoinError::Panicked(payload)) => {
                assert_eq!(payload.message(), "winner panic");
            }
            other => unreachable!("winner panic must dominate race_all result, got {other:?}"),
        }
    }

    #[test]
    fn race_all_empty_is_pending() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let fut = scope.race_all::<i32>(&cx, vec![]);
        let waker = std::task::Waker::noop();
        let mut poll_cx = std::task::Context::from_waker(waker);
        let pinned = std::pin::pin!(fut);
        let status = std::future::Future::poll(pinned, &mut poll_cx);
        assert!(status.is_pending());
    }

    // =============================================================================
    // CONFORMANCE TESTS: Structured Concurrency Invariants
    // =============================================================================
    //
    // These tests verify the core structured concurrency guarantees that must hold
    // for the spawn/join contract to be sound.

    #[test]
    fn conformance_spawn_creates_trackable_task() {
        // INVARIANT: Every spawned task creates a trackable record that belongs to the spawning region
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (handle, _stored) = scope.spawn(&mut state, &cx, |_| async { 42_i32 }).unwrap();

        // Task must exist and be trackable
        let task_record = state
            .task(handle.task_id())
            .expect("spawned task must have a record");

        // Task must belong to the spawning region
        assert_eq!(
            task_record.owner, region,
            "spawned task must be owned by the spawning region"
        );

        // Region must track the task
        let region_record = state.region(region).expect("spawning region must exist");
        assert!(
            region_record.task_ids().contains(&handle.task_id()),
            "spawning region must track the spawned task"
        );
    }

    #[test]
    fn conformance_spawn_enforces_send_bounds() {
        // INVARIANT: spawn() enforces Send + 'static bounds for cross-worker task migration
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // This should compile - Send + 'static data
        let send_data = String::from("test");
        let (handle, _stored) = scope
            .spawn(&mut state, &cx, move |_| async move {
                send_data.len() // Uses Send + 'static String
            })
            .unwrap();

        // Task record should reflect Send bounds
        let task_record = state
            .task(handle.task_id())
            .expect("Send task must have a record");
        assert_eq!(task_record.owner, region);

        // NOTE: Non-Send compile-time test examples are in module docstring
        // (compile_fail tests with Rc<T> and borrowed references)
    }

    #[test]
    fn conformance_join_awaits_task_completion() {
        // INVARIANT: TaskHandle.join() waits for task completion and returns the result

        use std::task::Context;

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (mut handle, mut stored) = scope.spawn(&mut state, &cx, |_| async { 123_i32 }).unwrap();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);

        // Before task completion, join should be pending
        let mut join_fut = std::pin::pin!(handle.join(&cx));
        assert!(
            join_fut.as_mut().poll(&mut poll_cx).is_pending(),
            "join must be pending before task completion"
        );

        // Complete the task
        assert!(
            stored.poll(&mut poll_cx).is_ready(),
            "test task must complete in one poll"
        );

        // After task completion, join should return the result
        match join_fut.as_mut().poll(&mut poll_cx) {
            std::task::Poll::Ready(Ok(result)) => {
                assert_eq!(result, 123, "join must return the task's result");
            }
            other => panic!("join must be Ready(Ok(123)) after task completion, got {other:?}"),
        }
    }

    #[test]
    fn conformance_child_region_task_isolation() {
        // INVARIANT: Tasks spawned in child regions belong to the child, not the parent

        use std::task::Context;

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let parent_region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(parent_region, Budget::INFINITE);

        let outcome = block_on(scope.region(
            &mut state,
            &cx,
            crate::types::policy::FailFast,
            |child_scope, state| {
                let child_region = child_scope.region_id();

                // Spawn task in child region
                let (handle, mut stored) = child_scope
                    .spawn(state, &cx, |_| async { 456_i32 })
                    .expect("spawn in child region must succeed");

                // Verify task ownership invariants
                let task_record = state
                    .task(handle.task_id())
                    .expect("child task must have a record");
                let child_owns = task_record.owner == child_region;
                let parent_owns = task_record.owner == parent_region;

                // Verify region tracking invariants
                let parent_tracks = state
                    .region(parent_region)
                    .is_some_and(|r| r.task_ids().contains(&handle.task_id()));
                let child_tracks = state
                    .region(child_region)
                    .is_some_and(|r| r.task_ids().contains(&handle.task_id()));

                // Complete the task for clean shutdown
                let waker = std::task::Waker::noop().clone();
                let mut poll_cx = Context::from_waker(&waker);
                if let std::task::Poll::Ready(outcome) = stored.poll(&mut poll_cx) {
                    if let Some(task) = state.task_mut(handle.task_id()) {
                        task.complete(outcome.map_err(|_| {
                            crate::error::Error::new(crate::error::ErrorKind::Internal)
                        }));
                    }
                    let _ = state.task_completed(handle.task_id());
                }

                std::future::ready(Outcome::Ok((
                    child_owns,
                    parent_owns,
                    child_tracks,
                    parent_tracks,
                )))
            },
        ))
        .expect("child region must complete");

        let (child_owns, parent_owns, child_tracks, parent_tracks) = match outcome {
            Outcome::Ok(tuple) => tuple,
            other => panic!("expected Ok(ownership_data), got {other:?}"),
        };

        assert!(
            child_owns,
            "task spawned in child region must be owned by child"
        );
        assert!(
            !parent_owns,
            "task spawned in child region must NOT be owned by parent"
        );
        assert!(child_tracks, "child region must track its spawned tasks");
        assert!(!parent_tracks, "parent region must NOT track child's tasks");
    }

    #[test]
    fn conformance_capability_inheritance() {
        // INVARIANT: Spawned tasks inherit capabilities from the parent Cx
        use crate::cx::macaroon::MacaroonToken;
        use crate::cx::registry::RegistryHandle;
        use crate::remote::{NodeId, RemoteCap};
        use crate::security::key::AuthKey;
        use crate::types::SystemPressure;
        use std::sync::Arc;
        use std::task::Context;

        let mut state = RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Setup parent Cx with capabilities
        let registry = crate::cx::NameRegistry::new();
        let registry_handle = RegistryHandle::new(Arc::new(registry));
        let parent_registry_arc = registry_handle.as_arc();
        let parent_io_cap: Arc<dyn crate::io::IoCap> = Arc::new(crate::io::LabIoCap::new());
        let parent_pressure = Arc::new(SystemPressure::new());
        parent_pressure.set_headroom(0.25);
        let auth_key = AuthKey::from_seed(7);
        let token = MacaroonToken::mint(&auth_key, "scope:spawn", "cx/scope");

        let parent_cx = Cx::new_with_io(
            crate::types::RegionId::new_for_test(0, 0),
            crate::types::TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            Some(Arc::clone(&parent_io_cap)),
            None,
        )
        .with_registry_handle(Some(registry_handle))
        .with_remote_cap(RemoteCap::new().with_local_node(NodeId::new("test-node")))
        .with_pressure(Arc::clone(&parent_pressure))
        .with_macaroon(token);
        let parent_macaroon = parent_cx
            .macaroon_handle()
            .expect("parent must retain macaroon capability");

        let mut handle = scope
            .spawn_registered(&mut state, &parent_cx, move |child_cx| async move {
                // Verify registry inheritance
                let child_registry = child_cx
                    .registry_handle()
                    .expect("child must inherit registry capability");
                let same_registry = Arc::ptr_eq(&child_registry.as_arc(), &parent_registry_arc);

                // Verify remote capability inheritance
                let child_remote = child_cx
                    .remote()
                    .expect("child must inherit remote capability");
                let node_name = child_remote.local_node().as_str().to_owned();

                // Verify I/O capability inheritance
                let child_io_cap = child_cx
                    .io_cap_handle()
                    .expect("child must inherit I/O capability");
                let same_io_cap = Arc::ptr_eq(&child_io_cap, &parent_io_cap);

                // Verify system pressure inheritance
                let child_pressure = child_cx
                    .pressure_handle()
                    .expect("child must inherit system pressure");
                let same_pressure = Arc::ptr_eq(&child_pressure, &parent_pressure);

                // Verify macaroon inheritance
                let child_macaroon = child_cx
                    .macaroon_handle()
                    .expect("child must inherit macaroon capability");
                let same_macaroon = Arc::ptr_eq(&child_macaroon, &parent_macaroon);

                // Verify timer capability inheritance (if parent has it)
                let has_timer = child_cx.has_timer();

                (
                    same_registry,
                    node_name,
                    same_io_cap,
                    same_pressure,
                    same_macaroon,
                    has_timer,
                )
            })
            .unwrap();

        // Complete the task and verify results
        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);

        let stored = state
            .get_stored_future(handle.task_id())
            .expect("spawn_registered must store the task");
        assert!(stored.poll(&mut poll_cx).is_ready());

        let mut join_fut = std::pin::pin!(handle.join(&parent_cx));
        match join_fut.as_mut().poll(&mut poll_cx) {
            std::task::Poll::Ready(Ok((
                same_registry,
                node_name,
                same_io_cap,
                same_pressure,
                same_macaroon,
                has_timer,
            ))) => {
                assert!(
                    same_registry,
                    "child must inherit exact same registry instance"
                );
                assert_eq!(
                    node_name, "test-node",
                    "child must inherit remote capability"
                );
                assert!(same_io_cap, "child must inherit exact same I/O capability");
                assert!(
                    same_pressure,
                    "child must inherit exact same system pressure handle"
                );
                assert!(
                    same_macaroon,
                    "child must inherit exact same macaroon capability"
                );
                assert_eq!(
                    has_timer,
                    parent_cx.has_timer(),
                    "child timer capability should stay consistent with the runtime-backed parent"
                );
            }
            other => panic!("capability inheritance test failed: {other:?}"),
        }
    }

    #[test]
    fn conformance_task_cancellation_propagation() {
        // INVARIANT: Cancelling a task via abort() propagates cancellation signal

        use std::task::Context;

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (mut handle, mut stored) = scope
            .spawn(&mut state, &cx, |cx| async move {
                // Check cancellation status and respond accordingly
                if cx.checkpoint().is_err() {
                    "cancelled"
                } else {
                    "completed"
                }
            })
            .unwrap();

        // Abort the task before it runs
        handle.abort();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);

        // Task should complete and see the cancellation
        assert!(
            stored.poll(&mut poll_cx).is_ready(),
            "cancelled task must still complete"
        );

        // Join should return the cancellation-aware result
        let mut join_fut = std::pin::pin!(handle.join(&cx));
        match join_fut.as_mut().poll(&mut poll_cx) {
            std::task::Poll::Ready(Ok(result)) => {
                assert_eq!(
                    result, "cancelled",
                    "cancelled task must observe cancellation via checkpoint()"
                );
            }
            other => panic!("cancelled task join failed: {other:?}"),
        }
    }

    #[test]
    fn metamorphic_nested_scope_cancellation_closes_descendants_without_spawn_leaks() {
        use std::task::{Context, Poll};

        struct YieldOnce(bool);

        impl std::future::Future for YieldOnce {
            type Output = ();

            fn poll(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> Poll<()> {
                if self.0 {
                    Poll::Ready(())
                } else {
                    self.0 = true;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let root = state.create_root_region(Budget::INFINITE);
        let child = state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let grandchild = state
            .create_child_region(child, Budget::INFINITE)
            .expect("grandchild region");
        let child_scope = test_scope(child, Budget::INFINITE);
        let grandchild_scope = test_scope(grandchild, Budget::INFINITE);
        let finalizer_log = Arc::new(std::sync::Mutex::new(Vec::new()));

        let child_log = Arc::clone(&finalizer_log);
        assert!(
            child_scope.defer_sync(&mut state, move || {
                child_log
                    .lock()
                    .expect("child finalizer log poisoned")
                    .push("child");
            }),
            "child finalizer should register before cancellation"
        );

        let grandchild_log = Arc::clone(&finalizer_log);
        assert!(
            grandchild_scope.defer_sync(&mut state, move || {
                grandchild_log
                    .lock()
                    .expect("grandchild finalizer log poisoned")
                    .push("grandchild");
            }),
            "grandchild finalizer should register before cancellation"
        );

        let mut child_handle = child_scope
            .spawn_registered(&mut state, &cx, |task_cx| async move {
                YieldOnce(false).await;
                if task_cx.checkpoint().is_err() {
                    "child_cancelled"
                } else {
                    "child_completed"
                }
            })
            .expect("spawn child task");
        let child_task_id = child_handle.task_id();

        let mut grandchild_handle = grandchild_scope
            .spawn_registered(&mut state, &cx, |task_cx| async move {
                YieldOnce(false).await;
                if task_cx.checkpoint().is_err() {
                    "grandchild_cancelled"
                } else {
                    "grandchild_completed"
                }
            })
            .expect("spawn grandchild task");
        let grandchild_task_id = grandchild_handle.task_id();

        let cancel_reason = CancelReason::shutdown().with_region(root);
        let cancelled = state.cancel_request(root, &cancel_reason, None);
        assert!(
            cancelled
                .iter()
                .any(|(task_id, _)| *task_id == child_task_id),
            "parent cancellation must reach child task"
        );
        assert!(
            cancelled
                .iter()
                .any(|(task_id, _)| *task_id == grandchild_task_id),
            "parent cancellation must reach grandchild task"
        );

        let grandchild_tasks_before_failed_spawn = state
            .region(grandchild)
            .expect("grandchild region missing")
            .task_count();
        let live_tasks_before_failed_spawn = state.live_task_count();
        let failed_spawn = grandchild_scope.spawn(&mut state, &cx, |_| async { 99_u8 });
        let grandchild_tasks_after_failed_spawn = state
            .region(grandchild)
            .expect("grandchild region missing after failed spawn")
            .task_count();
        let live_tasks_after_failed_spawn = state.live_task_count();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);
        {
            let stored = state
                .get_stored_future(grandchild_task_id)
                .expect("grandchild stored task");
            let poll_result = stored.poll(&mut poll_cx);
            assert!(
                poll_result.is_pending(),
                "grandchild task should yield once before observing cancellation"
            );
        }
        {
            let stored = state
                .get_stored_future(grandchild_task_id)
                .expect("grandchild stored task");
            let poll_result = stored.poll(&mut poll_cx);
            let task_outcome = match poll_result {
                Poll::Ready(Outcome::Ok(())) => Outcome::Ok(()),
                Poll::Ready(Outcome::Panicked(payload)) => Outcome::Panicked(payload),
                other => panic!(
                    "grandchild task should complete once cancellation is observed: {other:?}"
                ),
            };
            if let Some(task_record) = state.task_mut(grandchild_task_id) {
                task_record.complete(task_outcome);
            }
        }
        let _ = state.task_completed(grandchild_task_id);
        state.advance_region_state(grandchild);

        let mut grandchild_join_fut = std::pin::pin!(grandchild_handle.join(&cx));
        let grandchild_result = match grandchild_join_fut.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Ok(result)) => result,
            other => panic!("grandchild cancellation join should succeed: {other:?}"),
        };

        {
            let stored = state
                .get_stored_future(child_task_id)
                .expect("child stored task");
            let poll_result = stored.poll(&mut poll_cx);
            assert!(
                poll_result.is_pending(),
                "child task should yield once before observing cancellation"
            );
        }
        {
            let stored = state
                .get_stored_future(child_task_id)
                .expect("child stored task");
            let poll_result = stored.poll(&mut poll_cx);
            let task_outcome = match poll_result {
                Poll::Ready(Outcome::Ok(())) => Outcome::Ok(()),
                Poll::Ready(Outcome::Panicked(payload)) => Outcome::Panicked(payload),
                other => {
                    panic!("child task should complete once cancellation is observed: {other:?}")
                }
            };
            if let Some(task_record) = state.task_mut(child_task_id) {
                task_record.complete(task_outcome);
            }
        }
        let _ = state.task_completed(child_task_id);
        state.advance_region_state(child);

        let mut child_join_fut = std::pin::pin!(child_handle.join(&cx));
        let child_result = match child_join_fut.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Ok(result)) => result,
            other => panic!("child cancellation join should succeed: {other:?}"),
        };

        assert_eq!(child_result, "child_cancelled");
        assert_eq!(grandchild_result, "grandchild_cancelled");
        assert!(
            matches!(failed_spawn, Err(SpawnError::RegionClosed(id)) if id == grandchild),
            "nested spawn after parent cancellation must fail against the closing grandchild region"
        );
        assert_eq!(
            grandchild_tasks_before_failed_spawn, grandchild_tasks_after_failed_spawn,
            "failed spawn after cancellation must not leak task membership into the grandchild region"
        );
        assert_eq!(
            live_tasks_before_failed_spawn, live_tasks_after_failed_spawn,
            "failed spawn after cancellation must not inflate runtime task count"
        );
        assert_eq!(
            *finalizer_log.lock().expect("finalizer log poisoned"),
            vec!["grandchild", "child"],
            "nested scope finalizers must run in reverse scope creation order"
        );
        assert!(
            state.region(grandchild).is_none(),
            "grandchild region should be reclaimed after close"
        );
        assert!(
            state.region(child).is_none(),
            "child region should be reclaimed after close"
        );
    }

    #[test]
    fn conformance_race_loser_drain_invariant() {
        // INVARIANT: In race operations, losers are cancelled and fully drained

        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Winner: completes immediately
        let (winner_handle, mut winner_stored) = scope
            .spawn(&mut state, &cx, |_| async { "winner" })
            .unwrap();

        // Loser: would run longer, must be cancelled and drained
        let (loser_handle, mut loser_stored) = scope
            .spawn(&mut state, &cx, |cx| async move {
                // Simulate work that can be cancelled
                struct YieldOnce(bool);
                impl std::future::Future for YieldOnce {
                    type Output = ();
                    fn poll(
                        mut self: std::pin::Pin<&mut Self>,
                        cx: &mut std::task::Context<'_>,
                    ) -> std::task::Poll<()> {
                        if self.0 {
                            std::task::Poll::Ready(())
                        } else {
                            self.0 = true;
                            cx.waker().wake_by_ref();
                            std::task::Poll::Pending
                        }
                    }
                }
                YieldOnce(false).await;

                // Check if we were cancelled
                if cx.checkpoint().is_err() {
                    "loser_cancelled"
                } else {
                    "loser_completed"
                }
            })
            .unwrap();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);

        // Complete winner immediately
        assert!(winner_stored.poll(&mut poll_cx).is_ready());

        // Start the race
        let handles = vec![winner_handle, loser_handle];
        let mut race_fut = std::pin::pin!(scope.race_all(&cx, handles));

        // Race should be pending initially (waiting for loser drain)
        assert!(
            race_fut.as_mut().poll(&mut poll_cx).is_pending(),
            "race must wait for loser to be drained"
        );

        // Drive loser to first yield (it's now pending, but abort signal propagates)
        assert!(loser_stored.poll(&mut poll_cx).is_pending());

        // Still pending on race (loser not fully drained)
        assert!(race_fut.as_mut().poll(&mut poll_cx).is_pending());

        // Drive loser to completion (should see cancellation)
        assert!(loser_stored.poll(&mut poll_cx).is_ready());

        // Now race should complete with winner result
        match race_fut.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Ok((result, winner_index))) => {
                assert_eq!(result, "winner", "race must return winner result");
                assert_eq!(winner_index, 0, "winner index must be correct");
            }
            other => panic!("race must complete after loser drain: {other:?}"),
        }
    }

    #[test]
    fn conformance_region_quiescence_on_empty() {
        // INVARIANT: Empty regions reach quiescence and can be closed immediately
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let parent_region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(parent_region, Budget::INFINITE);

        // Create and immediately close a child region with no spawned tasks
        let outcome = block_on(scope.region(
            &mut state,
            &cx,
            crate::types::policy::FailFast,
            |_child_scope, _state| {
                // Don't spawn any tasks - region should be empty
                std::future::ready(Outcome::Ok("empty_region_completed"))
            },
        ))
        .expect("empty child region must complete");

        match outcome {
            Outcome::Ok(result) => {
                assert_eq!(
                    result, "empty_region_completed",
                    "empty region must reach quiescence immediately"
                );
            }
            other => panic!("empty region must complete successfully: {other:?}"),
        }

        // Child region should be cleaned up (no longer in parent's child list)
        let parent_record = state
            .region(parent_region)
            .expect("parent region must exist");
        assert!(
            parent_record.child_ids().is_empty(),
            "completed child region must be removed from parent"
        );
    }

    #[test]
    fn region_close_future_wakes_all_registered_waiters() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Context, Waker};

        struct CountWaker(Arc<AtomicUsize>);

        impl std::task::Wake for CountWaker {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let notify = Arc::new(parking_lot::Mutex::new(
            crate::record::region::RegionCloseState {
                closed: false,
                waiters: Vec::new(),
            },
        ));
        let wake_count_a = Arc::new(AtomicUsize::new(0));
        let wake_count_b = Arc::new(AtomicUsize::new(0));
        let waker_a = Waker::from(Arc::new(CountWaker(Arc::clone(&wake_count_a))));
        let waker_b = Waker::from(Arc::new(CountWaker(Arc::clone(&wake_count_b))));
        let mut cx_a = Context::from_waker(&waker_a);
        let mut cx_b = Context::from_waker(&waker_b);
        let mut future_a = RegionCloseFuture {
            state: Arc::clone(&notify),
        };
        let mut future_b = RegionCloseFuture { state: notify };

        assert!(Pin::new(&mut future_a).poll(&mut cx_a).is_pending());
        assert!(Pin::new(&mut future_b).poll(&mut cx_b).is_pending());

        let waiters = {
            let mut state = future_a.state.lock();
            state.closed = true;
            std::mem::take(&mut state.waiters)
        };
        for waker in waiters {
            waker.wake();
        }

        assert_eq!(wake_count_a.load(Ordering::SeqCst), 1);
        assert_eq!(wake_count_b.load(Ordering::SeqCst), 1);
        assert!(Pin::new(&mut future_a).poll(&mut cx_a).is_ready());
        assert!(Pin::new(&mut future_b).poll(&mut cx_b).is_ready());
    }

    #[test]
    fn conformance_spawn_into_closed_region_fails() {
        // INVARIANT: Cannot spawn tasks into regions that have begun closing
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Close the region
        let region_record = state.region_mut(region).expect("region must exist");
        region_record.begin_close(None);

        // Attempt to spawn should fail
        let spawn_result = scope.spawn(&mut state, &cx, |_| async { 42 });

        assert!(
            matches!(spawn_result, Err(SpawnError::RegionClosed(_))),
            "spawning into closed region must fail with RegionClosed error"
        );

        // State should remain consistent (no orphaned tasks)
        assert!(
            state.tasks_is_empty() || state.region(region).is_none_or(|r| r.task_ids().is_empty()),
            "failed spawn must not create orphaned tasks"
        );
    }

    #[test]
    fn conformance_join_multiple_tasks_preserves_results() {
        // INVARIANT: join_all preserves all task results in order

        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Spawn multiple tasks with different results
        let (h1, mut t1) = scope.spawn(&mut state, &cx, |_| async { 100_i32 }).unwrap();
        let (h2, mut t2) = scope.spawn(&mut state, &cx, |_| async { 200_i32 }).unwrap();
        let (h3, mut t3) = scope.spawn(&mut state, &cx, |_| async { 300_i32 }).unwrap();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);

        // Complete all tasks
        assert!(t1.poll(&mut poll_cx).is_ready());
        assert!(t2.poll(&mut poll_cx).is_ready());
        assert!(t3.poll(&mut poll_cx).is_ready());

        // Join all tasks
        let handles = vec![h1, h2, h3];
        let mut join_all_fut = std::pin::pin!(scope.join_all(&cx, handles));

        match join_all_fut.as_mut().poll(&mut poll_cx) {
            Poll::Ready(results) => {
                assert_eq!(results.len(), 3, "join_all must return all results");

                // Results must be in the same order as handles
                assert_eq!(
                    results[0].as_ref().unwrap(),
                    &100,
                    "first task result must be preserved"
                );
                assert_eq!(
                    results[1].as_ref().unwrap(),
                    &200,
                    "second task result must be preserved"
                );
                assert_eq!(
                    results[2].as_ref().unwrap(),
                    &300,
                    "third task result must be preserved"
                );
            }
            other @ Poll::Pending => panic!("join_all must complete with all results: {other:?}"),
        }
    }

    #[test]
    fn conformance_panic_propagation_through_join() {
        // INVARIANT: Task panics are captured and propagated through join as JoinError::Panicked

        use std::task::{Context, Poll};

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Spawn a task that panics with a specific message
        let (mut handle, mut stored) = scope
            .spawn(&mut state, &cx, |_| async {
                std::panic::panic_any("test_panic_message");
            })
            .unwrap();

        let waker = std::task::Waker::noop().clone();
        let mut poll_cx = Context::from_waker(&waker);

        // Task execution should complete with Panicked outcome
        match stored.poll(&mut poll_cx) {
            Poll::Ready(crate::types::Outcome::Panicked(_)) => {
                // Expected: panic was caught and wrapped as Outcome::Panicked
            }
            other => panic!("panicking task must complete with Panicked outcome: {other:?}"),
        }

        // Join should propagate the panic as JoinError::Panicked
        let mut join_fut = std::pin::pin!(handle.join(&cx));
        match join_fut.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Err(JoinError::Panicked(payload))) => {
                assert_eq!(
                    payload.message(),
                    "test_panic_message",
                    "join must preserve panic payload message"
                );
            }
            other => panic!("join of panicked task must return JoinError::Panicked: {other:?}"),
        }
    }

    /// Regression: region_with_budget factory panicking AFTER scope.spawn(...)
    /// returned — but BEFORE the StoredTask was scheduled — must not leave an
    /// orphan TaskRecord bound to the child region. Without the panic-catch
    /// rollback in `region_with_budget`, `region.task_count()` stays non-zero
    /// and `advance_region_state` can never transition Closing → Finalizing.
    ///
    /// Bead asupersync-c7s5de.
    #[test]
    fn region_factory_panic_after_spawn_cleans_up_orphan_task_records() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let parent = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(parent, Budget::INFINITE);

        let tasks_before = state.tasks_iter().count();

        // Wrap the call in catch_unwind because the factory intentionally
        // panics after spawn — resume_unwind re-raises in region_with_budget.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(scope.region_with_budget(
                &mut state,
                &cx,
                Budget::INFINITE,
                crate::types::policy::FailFast,
                |child, state| {
                    // Spawn a task so a TaskRecord exists in Created state,
                    // bound to the child region.
                    let (_handle, _stored) = child
                        .spawn(state, &cx, |_| async { 42_i32 })
                        .expect("spawn must succeed before the panic");
                    // Immediately panic — StoredTask is dropped unscheduled.
                    std::panic::panic_any("factory panic after spawn");
                    #[allow(unreachable_code)]
                    std::future::ready(Outcome::Ok(0_i32))
                },
            ))
        }));

        assert!(
            result.is_err(),
            "region_with_budget must re-raise the factory panic",
        );

        // Orphan TaskRecord(s) created inside the factory must have been
        // removed by the panic-catch rollback. The task count should be
        // back to its pre-call value.
        let tasks_after = state.tasks_iter().count();
        assert_eq!(
            tasks_after, tasks_before,
            "post-panic tasks_iter count must match pre-call count \
             (orphan TaskRecord not cleaned up: before={tasks_before} after={tasks_after})",
        );
    }
}
