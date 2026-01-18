//! Scope API for spawning work within a region.
//!
//! A `Scope` provides the API for spawning tasks, creating child regions,
//! and registering finalizers.

use crate::channel::oneshot;
use crate::combinator::{Either, Select};
use crate::cx::Cx;
use crate::record::TaskRecord;
use crate::runtime::task_handle::{JoinError, TaskHandle};
use crate::runtime::{RuntimeState, StoredTask};
use crate::types::{Budget, Policy, RegionId, TaskId};
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;

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

impl<P: Policy> Scope<'_, P> {
    /// Creates a new scope (internal use).
    #[must_use]
    #[allow(dead_code)]
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
    /// # Type Bounds
    ///
    /// * `F: FnOnce(Cx) -> Fut + Send + 'static` - The factory must be Send
    /// * `Fut: Future + Send + 'static` - The future must be Send
    /// * `Fut::Output: Send + 'static` - The output must be Send
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
    pub fn spawn<F, Fut>(
        &self,
        state: &mut RuntimeState,
        cx: &Cx,
        f: F,
    ) -> (TaskHandle<Fut::Output>, StoredTask)
    where
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        // Create oneshot channel for result delivery
        let (tx, rx) = oneshot::channel::<Result<Fut::Output, JoinError>>();

        // Create task record
        let task_id = self.create_task_record(state);

        // Create the child task's capability context
        let child_observability = cx.child_observability(self.region, task_id);
        let child_cx = Cx::new_with_observability(
            self.region,
            task_id,
            self.budget,
            Some(child_observability),
        );

        // Create the TaskHandle
        let handle = TaskHandle::new(task_id, rx, Arc::downgrade(&child_cx.inner));

        // Set the shared inner state in the TaskRecord
        // This links the user-facing Cx to the runtime's TaskRecord
        if let Some(record) = state.tasks.get_mut(task_id.arena_index()) {
            record.set_cx_inner(child_cx.inner.clone());
        }

        // Capture child_cx for result sending
        let cx_for_send = child_cx.clone();

        // Instantiate the future with the child context
        let future = f(child_cx);

        // Wrap the future to send its result through the channel
        let wrapped = async move {
            let result = future.await;
            // Send the result using the child's context
            let _ = tx.send(&cx_for_send, Ok(result));
        };

        // Create stored task
        let stored = StoredTask::new(wrapped);

        (handle, stored)
    }

    /// Spawns a local (non-Send) task within this scope's region.
    ///
    /// Local tasks are pinned to the current worker thread and cannot be
    /// stolen by other workers. This is useful for futures that contain
    /// `!Send` types like `Rc` or `RefCell`.
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
    /// // In Phase 1+, this will work with !Send futures:
    /// let counter = Rc::new(RefCell::new(0));
    /// let counter_clone = counter.clone();
    ///
    /// let (handle, stored) = scope.spawn_local(&mut state, &cx, |cx| async move {
    ///     *counter_clone.borrow_mut() += 1;
    /// });
    /// ```
    ///
    /// # Note
    ///
    /// In Phase 0 (single-threaded), this requires `Send` bounds since we use
    /// a shared task storage. In Phase 1+, `spawn_local` will use thread-local
    /// task storage and accept `!Send` futures.
    pub fn spawn_local<F, Fut>(
        &self,
        state: &mut RuntimeState,
        cx: &Cx,
        f: F,
    ) -> (TaskHandle<Fut::Output>, StoredTask)
    where
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        // In Phase 0, spawn_local behaves identically to spawn since
        // everything runs on a single thread. The distinction matters
        // in Phase 1+ with work-stealing where local tasks cannot migrate.
        //
        // TODO(Phase 1): Implement true thread-local task storage that
        // accepts !Send futures.
        self.spawn(state, cx, f)
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
    pub fn spawn_blocking<F, R>(
        &self,
        state: &mut RuntimeState,
        cx: &Cx, // Parent Cx
        f: F,
    ) -> (TaskHandle<R>, StoredTask)
    where
        F: FnOnce(Cx) -> R + Send + 'static,
        R: Send + 'static,
    {
        // Create oneshot channel for result delivery
        let (tx, rx) = oneshot::channel::<Result<R, JoinError>>();

        // Create task record
        let task_id = self.create_task_record(state);

        // Create the child task's capability context
        let child_observability = cx.child_observability(self.region, task_id);
        let child_cx = Cx::new_with_observability(
            self.region,
            task_id,
            self.budget,
            Some(child_observability),
        );

        // Create the TaskHandle
        let handle = TaskHandle::new(task_id, rx, Arc::downgrade(&child_cx.inner));

        // Set the shared inner state in the TaskRecord
        if let Some(record) = state.tasks.get_mut(task_id.arena_index()) {
            record.set_cx_inner(child_cx.inner.clone());
        }

        // Capture child_cx for result sending
        let cx_for_send = child_cx.clone();

        // For Phase 0, we run blocking code as an async task
        // In Phase 1+, this would spawn on a blocking thread pool
        let wrapped = async move {
            // Execute the blocking closure with child context
            let result = f(child_cx);
            // Send the result
            let _ = tx.send(&cx_for_send, Ok(result));
        };

        let stored = StoredTask::new(wrapped);

        (handle, stored)
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
        h1: TaskHandle<T1>,
        h2: TaskHandle<T2>,
    ) -> (Result<T1, JoinError>, Result<T2, JoinError>) {
        let r1 = h1.join(cx).await;
        let r2 = h2.join(cx).await;
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
    pub async fn race<T>(
        &self,
        cx: &Cx,
        h1: TaskHandle<T>,
        h2: TaskHandle<T>,
    ) -> Result<T, JoinError> {
        let f1 = Box::pin(h1.join(cx));
        let f2 = Box::pin(h2.join(cx));

        match Select::new(f1, f2).await {
            Either::Left(res) => {
                // h1 finished first
                h2.abort();
                let _ = h2.join(cx).await; // Drain h2
                res
            }
            Either::Right(res) => {
                // h2 finished first
                h1.abort();
                let _ = h1.join(cx).await; // Drain h1
                res
            }
        }
    }

    /// Creates a task record in the runtime state.
    ///
    /// This is a helper method used by all spawn variants.
    fn create_task_record(&self, state: &mut RuntimeState) -> TaskId {
        use crate::util::ArenaIndex;

        // Create placeholder task record
        let idx = state.tasks.insert(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)), // placeholder ID
            self.region,
            self.budget,
        ));

        // Get the real task ID from the arena index
        let task_id = TaskId::from_arena(idx);

        // Update the task record with the correct ID
        if let Some(record) = state.tasks.get_mut(idx) {
            record.id = task_id;
        }

        // Add task to the owning region
        if let Some(region) = state.regions.get(self.region.arena_index()) {
            if !region.add_task(task_id) {
                // Rollback task creation
                state.tasks.remove(idx);
                panic!(
                    "Attempted to spawn task into closing/draining region {:?}",
                    self.region
                );
            }
        } else {
            // Rollback task creation
            state.tasks.remove(idx);
            panic!(
                "Attempted to spawn task into non-existent region {:?}",
                self.region
            );
        }

        task_id
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
    use super::*;
    use crate::runtime::RuntimeState;
    use crate::util::ArenaIndex;

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

        let (handle, _stored) = scope.spawn(&mut state, &cx, |_| async { 42_i32 });

        // Task should exist in state
        let task = state.tasks.get(handle.task_id().arena_index());
        assert!(task.is_some());

        // Task should be owned by the region
        let task = task.unwrap();
        assert_eq!(task.owner, region);
    }

    #[test]
    fn spawn_blocking_creates_task_record() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (handle, _stored) = scope.spawn_blocking(&mut state, &cx, |_| 42_i32);

        // Task should exist
        let task = state.tasks.get(handle.task_id().arena_index());
        assert!(task.is_some());
        assert_eq!(task.unwrap().owner, region);
    }

    #[test]
    fn spawn_local_creates_task_record() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // In Phase 0, spawn_local requires Send bounds
        // In Phase 1+, this will work with !Send futures
        let (handle, _stored) = scope.spawn_local(&mut state, &cx, |_| async move { 42_i32 });

        // Task should exist
        let task = state.tasks.get(handle.task_id().arena_index());
        assert!(task.is_some());
        assert_eq!(task.unwrap().owner, region);
    }

    #[test]
    fn task_added_to_region() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (handle, _stored) = scope.spawn(&mut state, &cx, |_| async { 42_i32 });

        // Check region has the task
        let region_record = state.regions.get(region.arena_index()).unwrap();
        assert!(region_record.task_ids().contains(&handle.task_id()));
    }

    #[test]
    fn multiple_spawns_create_distinct_tasks() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        let (handle1, _) = scope.spawn(&mut state, &cx, |_| async { 1_i32 });
        let (handle2, _) = scope.spawn(&mut state, &cx, |_| async { 2_i32 });
        let (handle3, _) = scope.spawn(&mut state, &cx, |_| async { 3_i32 });

        // All task IDs should be different
        assert_ne!(handle1.task_id(), handle2.task_id());
        assert_ne!(handle2.task_id(), handle3.task_id());
        assert_ne!(handle1.task_id(), handle3.task_id());

        // All tasks should be in the region
        let region_record = state.regions.get(region.arena_index()).unwrap();
        assert!(region_record.task_ids().contains(&handle1.task_id()));
        assert!(region_record.task_ids().contains(&handle2.task_id()));
        assert!(region_record.task_ids().contains(&handle3.task_id()));
    }

    #[test]
    #[should_panic(expected = "Attempted to spawn task into closing/draining region")]
    fn spawn_into_closing_region_should_fail() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Transition region to Closing
        let region_record = state.regions.get_mut(region.arena_index()).expect("region");
        region_record.begin_close(None);

        // Attempt to spawn
        // This should now panic
        let _ = scope.spawn(&mut state, &cx, |_| async { 42 });
    }

    #[test]
    fn test_join_manual_poll() {
        use std::sync::Arc;
        use std::task::{Context, Poll, Waker};

        struct NoopWaker;
        impl std::task::Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
        }

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Spawn a task
        let (handle, mut stored_task) = scope.spawn(&mut state, &cx, |_| async { 42_i32 });
        // The stored task is returned directly, not put in state by scope.spawn

        // Create join future
        let mut join_fut = Box::pin(handle.join(&cx));

        // Create waker context
        let waker = Waker::from(Arc::new(NoopWaker));
        let mut ctx = Context::from_waker(&waker);

        // Poll join - should be pending
        assert!(join_fut.as_mut().poll(&mut ctx).is_pending());

        // Poll stored task - should complete and send result
        assert!(stored_task.poll(&mut ctx).is_ready());

        // Poll join - should be ready now
        match join_fut.as_mut().poll(&mut ctx) {
            Poll::Ready(Ok(val)) => assert_eq!(val, 42),
            _ => panic!("Expected Ready(Ok(42))"),
        }
    }

    #[test]
    fn spawn_abort_cancels_task() {
        use std::sync::Arc;
        use std::task::{Context, Poll, Waker};

        struct NoopWaker;
        impl std::task::Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
        }

        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Spawn a task that checks for cancellation
        let (handle, mut stored_task) = scope.spawn(&mut state, &cx, |cx| async move {
            // We expect to be cancelled immediately because abort() is called before we run
            if cx.checkpoint().is_err() {
                return "cancelled";
            }
            "finished"
        });

        // Abort the task via handle
        handle.abort();

        // Drive the task
        let waker = Waker::from(Arc::new(NoopWaker));
        let mut ctx = Context::from_waker(&waker);

        // Task should run, see cancellation, and return "cancelled"
        match stored_task.poll(&mut ctx) {
            Poll::Ready(()) => {}
            Poll::Pending => panic!("Task should have completed"),
        }

        // Check result via handle
        let mut join_fut = Box::pin(handle.join(&cx));
        match join_fut.as_mut().poll(&mut ctx) {
            Poll::Ready(Ok(val)) => assert_eq!(val, "cancelled"),
            Poll::Ready(Err(e)) => panic!("Task failed unexpectedly: {e}"),
            Poll::Pending => panic!("Join should be ready"),
        }
    }
}
