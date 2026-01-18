//! Scope API for spawning work within a region.
//!
//! A `Scope` provides the API for spawning tasks, creating child regions,
//! and registering finalizers.

use crate::channel::oneshot;
use crate::combinator::{Either, Select};
use crate::cx::Cx;
use crate::record::TaskRecord;
use crate::runtime::task_handle::{JoinError, TaskHandle};
use crate::runtime::{RuntimeState, SpawnError, StoredTask};
use crate::types::{Budget, PanicPayload, Policy, RegionId, TaskId};
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

struct CatchUnwind<F>(Pin<Box<F>>);

impl<F: Future> Future for CatchUnwind<F> {
    type Output = std::thread::Result<F::Output>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = self.0.as_mut();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inner.poll(cx)));
        match result {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(v)) => Poll::Ready(Ok(v)),
            Err(payload) => Poll::Ready(Err(payload)),
        }
    }
}

fn payload_to_string(payload: &Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(ToString::to_string)
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".to_string())
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
    ) -> Result<(TaskHandle<Fut::Output>, StoredTask), SpawnError>
    where
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        // Create oneshot channel for result delivery
        let (tx, rx) = oneshot::channel::<Result<Fut::Output, JoinError>>();

        // Create task record
        let task_id = self.create_task_record(state)?;

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
        // We use CatchUnwind to ensure panics are propagated as JoinError::Panicked
        // rather than silent channel closure (which looks like cancellation).
        let wrapped = async move {
            let result_result = CatchUnwind(Box::pin(future)).await;
            match result_result {
                Ok(result) => {
                    let _ = tx.send(&cx_for_send, Ok(result));
                }
                Err(payload) => {
                    let msg = payload_to_string(&payload);
                    let _ = tx.send(
                        &cx_for_send,
                        Err(JoinError::Panicked(PanicPayload::new(msg))),
                    );
                }
            }
        };

        // Create stored task
        let stored = StoredTask::new(wrapped);

        Ok((handle, stored))
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
    ) -> Result<(TaskHandle<Fut::Output>, StoredTask), SpawnError>
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
    ) -> Result<(TaskHandle<R>, StoredTask), SpawnError>
    where
        F: FnOnce(Cx) -> R + Send + 'static,
        R: Send + 'static,
    {
        // Create oneshot channel for result delivery
        let (tx, rx) = oneshot::channel::<Result<R, JoinError>>();

        // Create task record
        let task_id = self.create_task_record(state)?;

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
            // Catch panics to report them correctly
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(child_cx)));
            match result {
                Ok(res) => {
                    let _ = tx.send(&cx_for_send, Ok(res));
                }
                Err(payload) => {
                    let msg = payload_to_string(&payload);
                    let _ = tx.send(
                        &cx_for_send,
                        Err(JoinError::Panicked(PanicPayload::new(msg))),
                    );
                }
            }
        };

        let stored = StoredTask::new(wrapped);

        Ok((handle, stored))
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
        use crate::combinator::select::SelectAll;

        assert!(!handles.is_empty(), "race_all called with empty handles");

        let futures: Vec<_> = handles.iter().map(|h| Box::pin(h.join(cx))).collect();

        let (result, winner_idx) = SelectAll::new(futures).await;

        // Cancel and drain losers
        for (i, handle) in handles.iter().enumerate() {
            if i != winner_idx {
                handle.abort();
            }
        }

        for (i, handle) in handles.iter().enumerate() {
            if i != winner_idx {
                let _ = handle.join(cx).await;
            }
        }

        result.map(|val| (val, winner_idx))
    }

    /// Joins multiple tasks, waiting for all to complete.
    ///
    /// Returns a vector of results in the same order as the input handles.
    pub async fn join_all<T>(
        &self,
        cx: &Cx,
        handles: Vec<TaskHandle<T>>,
    ) -> Vec<Result<T, JoinError>> {
        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            results.push(handle.join(cx).await);
        }
        results
    }

    /// Creates a task record in the runtime state.
    ///
    /// This is a helper method used by all spawn variants.
    fn create_task_record(&self, state: &mut RuntimeState) -> Result<TaskId, SpawnError> {
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
                return Err(SpawnError::RegionClosed(self.region));
            }
        } else {
            // Rollback task creation
            state.tasks.remove(idx);
            return Err(SpawnError::RegionNotFound(self.region));
        }

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

        let (handle, _stored) = scope.spawn(&mut state, &cx, |_| async { 42_i32 }).unwrap();

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

        let (handle, _stored) = scope.spawn_blocking(&mut state, &cx, |_| 42_i32).unwrap();

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
        let (handle, _stored) = scope.spawn_local(&mut state, &cx, |_| async move { 42_i32 }).unwrap();

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

        let (handle, _stored) = scope.spawn(&mut state, &cx, |_| async { 42_i32 }).unwrap();

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

        let (handle1, _) = scope.spawn(&mut state, &cx, |_| async { 1_i32 }).unwrap();
        let (handle2, _) = scope.spawn(&mut state, &cx, |_| async { 2_i32 }).unwrap();
        let (handle3, _) = scope.spawn(&mut state, &cx, |_| async { 3_i32 }).unwrap();

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
    fn spawn_into_closing_region_should_fail() {
        let mut state = RuntimeState::new();
        let cx = test_cx();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = test_scope(region, Budget::INFINITE);

        // Transition region to Closing
        let region_record = state.regions.get_mut(region.arena_index()).expect("region");
        region_record.begin_close(None);

        // Attempt to spawn should fail
        let result = scope.spawn(&mut state, &cx, |_| async { 42 });
        assert!(matches!(result, Err(SpawnError::RegionClosed(_))));
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
        let (handle, mut stored_task) = scope.spawn(&mut state, &cx, |_| async { 42_i32 }).unwrap();
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
        }).unwrap();

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

    #[test]
    fn spawn_panic_propagates_as_panicked_error() {
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

        let (handle, mut stored_task) = scope.spawn(&mut state, &cx, |_| async {
            panic!("oops");
        }).unwrap();

        // Drive the task
        let waker = Waker::from(Arc::new(NoopWaker));
        let mut ctx = Context::from_waker(&waker);

        // Polling stored task should return Ready(()) even if it panics (caught inside)
        match stored_task.poll(&mut ctx) {
            Poll::Ready(()) => {}
            Poll::Pending => panic!("Task should have completed"),
        }

        // Check result via handle
        let mut join_fut = Box::pin(handle.join(&cx));
        match join_fut.as_mut().poll(&mut ctx) {
            Poll::Ready(Err(JoinError::Panicked(p))) => {
                assert_eq!(p.message(), "oops");
            }
            res => panic!("Expected Panicked, got {:?}", res),
        }
    }

    #[test]
    fn join_all_success() {
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

        let (h1, mut t1) = scope.spawn(&mut state, &cx, |_| async { 1 }).unwrap();
        let (h2, mut t2) = scope.spawn(&mut state, &cx, |_| async { 2 }).unwrap();

        // Drive tasks to completion
        let waker = Waker::from(Arc::new(NoopWaker));
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
            Poll::Pending => panic!("join_all should be ready"),
        }
    }

    #[test]
    fn race_all_interleaving() {
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

        // Task 1: completes immediately
        let (h1, mut t1) = scope.spawn(&mut state, &cx, |_| async { 1 }).unwrap();
        
        // Task 2: yields once, checking for cancellation
        let (h2, mut t2) = scope.spawn(&mut state, &cx, |cx| async move {
            // Yield once to simulate running
            struct YieldOnce(bool);
            impl std::future::Future for YieldOnce {
                type Output = ();
                fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
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
        }).unwrap();

        let waker = Waker::from(Arc::new(NoopWaker));
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
            res => panic!("Expected Ready(Ok((1, 0))), got {:?}", res),
        }
    }
}
