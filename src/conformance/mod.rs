//! Conformance testing infrastructure for runtime implementations.
//!
//! This module provides traits and utilities for running conformance tests across
//! different runtime implementations (Lab, production, etc.).
//!
//! # Overview
//!
//! The conformance framework allows the same test suite to be run against multiple
//! runtime implementations, ensuring they all provide consistent behavior.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::conformance::{ConformanceTarget, TestConfig, conformance_test};
//!
//! // Define a conformance test
//! conformance_test!(test_basic_spawn, |target, config| {
//!     let runtime = target.create_runtime(config);
//!     target.block_on(&runtime, async {
//!         // Test that basic spawning works
//!         let cx = Cx::current().unwrap();
//!         let handle = target.spawn(&cx, async { 42 });
//!         assert_eq!(handle.await, 42);
//!     });
//! });
//! ```

use crate::channel::oneshot;
use crate::cx::Cx;
use crate::types::{Budget, CancelReason, Outcome, RegionId, TaskId};
use parking_lot::Mutex;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

/// Configuration for conformance tests.
///
/// Controls test execution parameters like timeouts, randomness, and tracing.
#[derive(Debug, Clone)]
pub struct TestConfig {
    /// Maximum duration for a test to complete.
    pub timeout: Duration,
    /// Optional RNG seed for deterministic execution.
    ///
    /// When `Some(seed)`, the runtime should use this seed for any random decisions,
    /// making test execution reproducible.
    pub rng_seed: Option<u64>,
    /// Whether to enable detailed tracing during test execution.
    pub tracing_enabled: bool,
    /// Maximum number of steps to execute (for Lab runtime).
    ///
    /// Prevents infinite loops in deterministic tests.
    pub max_steps: Option<u64>,
    /// Budget allocated to the root region.
    pub root_budget: Budget,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            rng_seed: Some(0xDEAD_BEEF),
            tracing_enabled: false,
            max_steps: Some(100_000),
            root_budget: Budget::INFINITE,
        }
    }
}

impl TestConfig {
    /// Create a new test configuration with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the timeout duration.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the RNG seed for deterministic execution.
    #[must_use]
    pub const fn with_seed(mut self, seed: u64) -> Self {
        self.rng_seed = Some(seed);
        self
    }

    /// Disable the RNG seed (use system randomness).
    #[must_use]
    pub const fn without_seed(mut self) -> Self {
        self.rng_seed = None;
        self
    }

    /// Enable or disable tracing.
    #[must_use]
    pub const fn with_tracing(mut self, enabled: bool) -> Self {
        self.tracing_enabled = enabled;
        self
    }

    /// Set the maximum number of steps.
    #[must_use]
    pub const fn with_max_steps(mut self, steps: u64) -> Self {
        self.max_steps = Some(steps);
        self
    }

    /// Set the root region budget.
    #[must_use]
    pub const fn with_budget(mut self, budget: Budget) -> Self {
        self.root_budget = budget;
        self
    }
}

/// Handle to a spawned task.
///
/// Allows waiting for task completion and retrieving the result.
pub struct TaskHandle<T> {
    /// The task ID once the runtime has registered the task.
    task_id: Arc<Mutex<Option<TaskId>>>,
    /// Boxed future that resolves to the task outcome.
    result: Pin<Box<dyn Future<Output = Outcome<T, ()>> + Send>>,
}

impl<T> TaskHandle<T> {
    /// Create a new task handle.
    pub fn new(
        task_id: TaskId,
        result: impl Future<Output = Outcome<T, ()>> + Send + 'static,
    ) -> Self {
        Self {
            task_id: Arc::new(Mutex::new(Some(task_id))),
            result: Box::pin(result),
        }
    }

    fn pending(
        task_id: Arc<Mutex<Option<TaskId>>>,
        result: impl Future<Output = Outcome<T, ()>> + Send + 'static,
    ) -> Self {
        Self {
            task_id,
            result: Box::pin(result),
        }
    }

    /// Get the task ID.
    #[must_use]
    pub fn id(&self) -> Option<TaskId> {
        *self.task_id.lock()
    }
}

impl<T> Future for TaskHandle<T> {
    type Output = Outcome<T, ()>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.result.as_mut().poll(cx)
    }
}

/// Handle to a created region.
///
/// Allows waiting for region quiescence and managing the region lifecycle.
pub struct RegionHandle {
    /// The region ID once the runtime has created the region.
    region_id: Arc<Mutex<Option<RegionId>>>,
    /// Boxed future that resolves when the region closes.
    completion: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl RegionHandle {
    /// Create a new region handle.
    pub fn new(region_id: RegionId, completion: impl Future<Output = ()> + Send + 'static) -> Self {
        Self {
            region_id: Arc::new(Mutex::new(Some(region_id))),
            completion: Box::pin(completion),
        }
    }

    fn pending(
        region_id: Arc<Mutex<Option<RegionId>>>,
        completion: impl Future<Output = ()> + Send + 'static,
    ) -> Self {
        Self {
            region_id,
            completion: Box::pin(completion),
        }
    }

    /// Get the region ID.
    #[must_use]
    pub fn id(&self) -> Option<RegionId> {
        *self.region_id.lock()
    }
}

impl Future for RegionHandle {
    type Output = ();

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.completion.as_mut().poll(cx)
    }
}

/// Trait for runtime implementations to support conformance testing.
///
/// This trait defines the operations that a runtime must implement to run
/// conformance tests. Both the Lab runtime and production runtime should
/// implement this trait.
///
/// # Type Parameters
///
/// The trait uses associated types to allow different runtime implementations
/// to use their own concrete types while maintaining a common interface.
///
/// # Example Implementation
///
/// ```ignore
/// impl ConformanceTarget for LabRuntimeTarget {
///     type Runtime = LabRuntime;
///
///     fn create_runtime(config: TestConfig) -> Self::Runtime {
///         let mut lab_config = LabConfig::new(config.rng_seed.unwrap_or(42));
///         if let Some(max_steps) = config.max_steps {
///             lab_config = lab_config.max_steps(max_steps);
///         }
///         LabRuntime::new(lab_config)
///     }
///
///     fn block_on<F>(runtime: &Self::Runtime, f: F) -> F::Output
///     where
///         F: Future + Send + 'static,
///         F::Output: Send + 'static,
///     {
///         // Lab runtime implementation
///     }
///     // ...
/// }
/// ```
pub trait ConformanceTarget: Sized + Send + Sync {
    /// The concrete runtime type.
    type Runtime: Send;

    /// Create a new runtime instance for testing.
    ///
    /// The runtime should be configured according to the provided `TestConfig`,
    /// including setting up deterministic RNG if a seed is provided.
    fn create_runtime(config: TestConfig) -> Self::Runtime;

    /// Run a future to completion on the runtime.
    ///
    /// This is the primary entry point for executing async code in tests.
    /// For Lab runtime, this typically runs until quiescence.
    /// For production runtime, this blocks until the future completes.
    fn block_on<F>(runtime: &mut Self::Runtime, f: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static;

    /// Spawn a task within the current region.
    ///
    /// The task should be spawned with the given budget and tracked by the runtime.
    /// Returns a handle that can be awaited to get the task result.
    fn spawn<T, F>(cx: &Cx, budget: Budget, f: F) -> TaskHandle<T>
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static;

    /// Create a child region.
    ///
    /// The child region should be a sub-region of the current context's region.
    /// Returns a handle that can be awaited to wait for region closure.
    fn create_region(cx: &Cx, budget: Budget) -> RegionHandle;

    /// Request cancellation of a region.
    ///
    /// This initiates the cancellation protocol:
    /// 1. Set cancel flag
    /// 2. Wait for tasks to reach checkpoints and drain
    /// 3. Run finalizers
    /// 4. Region closes
    fn cancel(cx: &Cx, region: &RegionHandle, reason: CancelReason);

    /// Advance virtual time (Lab runtime only).
    ///
    /// For production runtime, this may be a no-op or sleep for the given duration.
    /// For Lab runtime, this advances the virtual clock without real time passing.
    fn advance_time(runtime: &mut Self::Runtime, duration: Duration);

    /// Check if the runtime is quiescent.
    ///
    /// A runtime is quiescent when:
    /// - No tasks are ready to run
    /// - No pending wakeups
    /// - All regions have completed or are waiting
    fn is_quiescent(runtime: &Self::Runtime) -> bool;

    /// Get the current virtual time.
    ///
    /// For Lab runtime, returns the virtual clock time.
    /// For production runtime, may return wall-clock time.
    fn now(runtime: &Self::Runtime) -> Duration;
}

/// A registered conformance test.
#[derive(Clone)]
pub struct ConformanceTestFn {
    /// Test name.
    pub name: &'static str,
    /// Test function.
    pub test_fn: fn(&TestConfig),
}

/// Conformance test execution events.
#[derive(Clone, Debug)]
pub enum ConformanceEvent {
    /// A test started.
    TestStart {
        /// Test name.
        name: &'static str,
    },
    /// A test completed successfully.
    TestPassed {
        /// Test name.
        name: &'static str,
    },
    /// A test failed (panic or error).
    TestFailed {
        /// Test name.
        name: &'static str,
        /// Optional failure message extracted from the panic payload.
        message: Option<String>,
    },
}

/// Run a slice of conformance tests with the given configuration,
/// reporting progress via a callback.
///
/// Returns the number of tests that passed and failed.
#[must_use]
pub fn run_conformance_tests_with_reporter<F>(
    tests: &[ConformanceTestFn],
    config: &TestConfig,
    mut report: F,
) -> (usize, usize)
where
    F: FnMut(ConformanceEvent),
{
    let mut passed = 0;
    let mut failed = 0;

    for test in tests {
        report(ConformanceEvent::TestStart { name: test.name });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            (test.test_fn)(config);
        }));

        match result {
            Ok(()) => {
                report(ConformanceEvent::TestPassed { name: test.name });
                passed += 1;
            }
            Err(e) => {
                let message = e.downcast_ref::<&str>().map_or_else(
                    || e.downcast_ref::<String>().cloned(),
                    |msg| Some((*msg).to_string()),
                );
                report(ConformanceEvent::TestFailed {
                    name: test.name,
                    message,
                });
                failed += 1;
            }
        }
    }

    (passed, failed)
}

/// Run a slice of conformance tests with the given configuration.
///
/// Returns the number of tests that passed and failed.
#[must_use]
pub fn run_conformance_tests(tests: &[ConformanceTestFn], config: &TestConfig) -> (usize, usize) {
    run_conformance_tests_with_reporter(tests, config, |_| {})
}

/// Macro for defining conformance tests.
///
/// This macro defines a test that will be run against conformance targets.
/// The test receives a `TestConfig` and should use a `ConformanceTarget` implementation
/// to execute the test.
///
/// # Example
///
/// ```ignore
/// use asupersync::conformance::{conformance_test, TestConfig};
///
/// conformance_test!(test_spawn_completes, |config: &TestConfig| {
///     use asupersync::conformance::ConformanceTarget;
///     use asupersync::lab::LabRuntime;
///
///     // Create runtime and run test
///     let mut runtime = LabRuntimeTarget::create_runtime(config.clone());
///     LabRuntimeTarget::block_on(&mut runtime, async {
///         // Test implementation
///     });
/// });
/// ```
#[macro_export]
macro_rules! conformance_test {
    ($name:ident, $body:expr) => {
        #[test]
        fn $name() {
            let config = $crate::conformance::TestConfig::default();
            let body: fn(&$crate::conformance::TestConfig) = $body;
            body(&config);
        }
    };
}

/// Implementation of `ConformanceTarget` for the Lab runtime.
///
/// This allows conformance tests to run against the deterministic Lab runtime,
/// which provides virtual time and reproducible scheduling.
pub struct LabRuntimeTarget;

type PendingLabOperation = Box<dyn FnOnce(&mut crate::lab::LabRuntime)>;

#[derive(Clone)]
struct LabConformanceSession {
    pending_ops: Rc<RefCell<VecDeque<PendingLabOperation>>>,
}

thread_local! {
    static CURRENT_LAB_CONFORMANCE_SESSION: RefCell<Option<LabConformanceSession>> =
        const { RefCell::new(None) };
}

struct LabConformanceSessionGuard {
    prev: Option<LabConformanceSession>,
}

impl Drop for LabConformanceSessionGuard {
    fn drop(&mut self) {
        let prev = self.prev.take();
        let _ = CURRENT_LAB_CONFORMANCE_SESSION.try_with(|slot| {
            *slot.borrow_mut() = prev;
        });
    }
}

impl LabConformanceSession {
    fn new() -> Self {
        Self {
            pending_ops: Rc::new(RefCell::new(VecDeque::new())),
        }
    }

    fn current() -> Self {
        CURRENT_LAB_CONFORMANCE_SESSION.with(|slot| {
            slot.borrow()
                .clone()
                .expect("LabRuntimeTarget operations must run inside LabRuntimeTarget::block_on")
        })
    }

    fn enter(&self) -> LabConformanceSessionGuard {
        let prev = CURRENT_LAB_CONFORMANCE_SESSION.with(|slot| {
            let mut guard = slot.borrow_mut();
            let prev = guard.take();
            *guard = Some(self.clone());
            prev
        });
        LabConformanceSessionGuard { prev }
    }

    fn enqueue(&self, op: PendingLabOperation) {
        self.pending_ops.borrow_mut().push_back(op);
    }

    fn has_pending(&self) -> bool {
        !self.pending_ops.borrow().is_empty()
    }

    fn drain(&self, runtime: &mut crate::lab::LabRuntime) {
        loop {
            let next = self.pending_ops.borrow_mut().pop_front();
            let Some(op) = next else {
                break;
            };
            op(runtime);
        }
    }
}

fn schedule_lab_task(runtime: &crate::lab::LabRuntime, task_id: TaskId, priority: u8) {
    runtime.scheduler.lock().schedule(task_id, priority);
}

fn request_lab_region_cancel(
    runtime: &mut crate::lab::LabRuntime,
    region_id: RegionId,
    reason: &CancelReason,
) {
    let tasks_to_schedule = runtime.state.cancel_request(region_id, reason, None);
    let mut scheduler = runtime.scheduler.lock();
    for (task_id, priority) in tasks_to_schedule {
        scheduler.schedule_cancel(task_id, priority);
    }
}

impl ConformanceTarget for LabRuntimeTarget {
    type Runtime = crate::lab::LabRuntime;

    fn create_runtime(config: TestConfig) -> Self::Runtime {
        use crate::lab::LabConfig;

        let seed = config.rng_seed.unwrap_or(0xDEAD_BEEF);
        let mut lab_config = LabConfig::new(seed);

        if let Some(max_steps) = config.max_steps {
            lab_config = lab_config.max_steps(max_steps);
        }

        if config.tracing_enabled {
            lab_config = lab_config.trace_capacity(64 * 1024);
        }

        crate::lab::LabRuntime::new(lab_config)
    }

    fn block_on<F>(runtime: &mut Self::Runtime, f: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        // Create root region
        let root_region = runtime.state.create_root_region(Budget::INFINITE);

        // Store the result
        let result: Arc<Mutex<Option<F::Output>>> = Arc::new(Mutex::new(None));
        let result_clone = result.clone();

        // Box the future with result capture
        let wrapped = async move {
            let output = f.await;
            *result_clone.lock() = Some(output);
        };

        // Create and schedule the task
        let (task_id, _handle) = runtime
            .state
            .create_task(root_region, Budget::INFINITE, wrapped)
            .expect("failed to create task");

        runtime.scheduler.lock().schedule(task_id, 0);

        let session = LabConformanceSession::new();
        let _session_guard = session.enter();

        loop {
            session.drain(runtime);

            if runtime.is_quiescent() && !session.has_pending() {
                break;
            }

            if let Some(max_steps) = runtime.config().max_steps {
                if runtime.steps() >= max_steps {
                    break;
                }
            }

            runtime.step_for_test();
        }

        session.drain(runtime);

        // Extract result
        let mut guard = result.lock();
        guard.take().expect("task did not complete")
    }

    fn spawn<T, F>(cx: &Cx, budget: Budget, f: F) -> TaskHandle<T>
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        let session = LabConformanceSession::current();
        let task_id = Arc::new(Mutex::new(None));
        let join_cx = cx.clone();
        let op_cx = cx.clone();
        let task_id_for_op = Arc::clone(&task_id);
        let (registration_tx, mut registration_rx) = oneshot::channel();

        session.enqueue(Box::new(move |runtime| {
            let scope = op_cx.scope_with_budget(budget);
            let handle = scope
                .spawn_registered(&mut runtime.state, &op_cx, move |_child_cx| f)
                .expect("failed to create runtime-backed conformance task");
            let task_id_value = handle.task_id();
            *task_id_for_op.lock() = Some(task_id_value);

            let priority = runtime
                .state
                .task(task_id_value)
                .and_then(|record| record.cx_inner.as_ref())
                .map_or(budget.priority, |inner| inner.read().budget.priority);
            schedule_lab_task(runtime, task_id_value, priority);

            let _ = registration_tx.send(&op_cx, handle);
        }));

        TaskHandle::pending(task_id, async move {
            let mut handle = registration_rx
                .recv_uninterruptible()
                .await
                .expect("conformance task registration dropped before delivery");
            match handle.join(&join_cx).await {
                Ok(value) => Outcome::Ok(value),
                Err(crate::runtime::task_handle::JoinError::Cancelled(reason)) => {
                    Outcome::Cancelled(reason)
                }
                Err(crate::runtime::task_handle::JoinError::Panicked(payload)) => {
                    Outcome::Panicked(payload)
                }
                Err(crate::runtime::task_handle::JoinError::PolledAfterCompletion) => {
                    Outcome::Err(())
                }
            }
        })
    }

    fn create_region(cx: &Cx, budget: Budget) -> RegionHandle {
        let session = LabConformanceSession::current();
        let region_id = Arc::new(Mutex::new(None));
        let region_id_for_op = Arc::clone(&region_id);
        let op_cx = cx.clone();
        let (registration_tx, mut registration_rx) = oneshot::channel();

        session.enqueue(Box::new(move |runtime| {
            let region_id_value = runtime
                .state
                .create_child_region(op_cx.region_id(), budget)
                .expect("failed to create runtime-backed conformance region");
            let close_notify = runtime
                .state
                .region(region_id_value)
                .expect("created region must exist")
                .close_notify
                .clone();
            *region_id_for_op.lock() = Some(region_id_value);
            let _ = registration_tx.send(&op_cx, close_notify);
        }));

        RegionHandle::pending(region_id, async move {
            let close_notify = registration_rx
                .recv_uninterruptible()
                .await
                .expect("conformance region registration dropped before delivery");

            poll_fn(move |cx| {
                let mut state = close_notify.lock();
                if state.closed {
                    std::task::Poll::Ready(())
                } else {
                    if !state
                        .waker
                        .as_ref()
                        .is_some_and(|waker| waker.will_wake(cx.waker()))
                    {
                        state.waker = Some(cx.waker().clone());
                    }
                    std::task::Poll::Pending
                }
            })
            .await;
        })
    }

    fn cancel(_cx: &Cx, region: &RegionHandle, reason: CancelReason) {
        let session = LabConformanceSession::current();
        let region_id = Arc::clone(&region.region_id);

        session.enqueue(Box::new(move |runtime| {
            let region_id_value = (*region_id.lock())
                .expect("conformance region cancel issued before region registration completed");
            request_lab_region_cancel(runtime, region_id_value, &reason);
        }));
    }

    fn advance_time(runtime: &mut Self::Runtime, duration: Duration) {
        let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        runtime.advance_time(nanos);
    }

    fn is_quiescent(runtime: &Self::Runtime) -> bool {
        runtime.is_quiescent()
    }

    fn now(runtime: &Self::Runtime) -> Duration {
        let time = runtime.now();
        Duration::from_nanos(time.as_nanos())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = TestConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.rng_seed, Some(0xDEAD_BEEF));
        assert!(!config.tracing_enabled);
        assert_eq!(config.max_steps, Some(100_000));
    }

    #[test]
    fn test_config_builder() {
        let config = TestConfig::new()
            .with_timeout(Duration::from_secs(60))
            .with_seed(42)
            .with_tracing(true)
            .with_max_steps(1000);

        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.rng_seed, Some(42));
        assert!(config.tracing_enabled);
        assert_eq!(config.max_steps, Some(1000));
    }

    #[test]
    fn test_lab_runtime_target_create() {
        let config = TestConfig::new().with_seed(12345);
        let runtime = LabRuntimeTarget::create_runtime(config);

        // Verify runtime was created with correct seed
        assert_eq!(runtime.config().seed, 12345);
    }

    #[test]
    fn test_lab_runtime_target_block_on() {
        let config = TestConfig::default();
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let result = LabRuntimeTarget::block_on(&mut runtime, async { 42 });

        assert_eq!(result, 42);
    }

    #[test]
    fn test_lab_runtime_target_advance_time() {
        let config = TestConfig::default();
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let before = LabRuntimeTarget::now(&runtime);
        LabRuntimeTarget::advance_time(&mut runtime, Duration::from_secs(1));
        let after = LabRuntimeTarget::now(&runtime);

        assert!(after > before);
        assert_eq!(after.checked_sub(before).unwrap(), Duration::from_secs(1));
    }

    #[test]
    fn test_lab_runtime_target_quiescence() {
        let config = TestConfig::default();
        let runtime = LabRuntimeTarget::create_runtime(config);

        // Fresh runtime should be quiescent
        assert!(LabRuntimeTarget::is_quiescent(&runtime));
    }

    #[test]
    fn test_config_debug() {
        let cfg = TestConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("TestConfig"));
    }

    #[test]
    fn test_config_clone() {
        let cfg = TestConfig::new().with_seed(99).with_tracing(true);
        let cfg2 = cfg;
        assert_eq!(cfg2.rng_seed, Some(99));
        assert!(cfg2.tracing_enabled);
    }

    #[test]
    fn test_config_without_seed() {
        let cfg = TestConfig::new().without_seed();
        assert!(cfg.rng_seed.is_none());
    }

    #[test]
    fn test_config_with_budget() {
        let budget = Budget::with_deadline_secs(100);
        let cfg = TestConfig::new().with_budget(budget);
        assert_eq!(cfg.root_budget, budget);
    }

    #[test]
    fn test_config_with_timeout() {
        let cfg = TestConfig::new().with_timeout(Duration::from_secs(60));
        assert_eq!(cfg.timeout, Duration::from_secs(60));
    }

    #[test]
    fn task_handle_id() {
        let tid = TaskId::new_for_test(5, 0);
        let handle = TaskHandle::new(tid, async { Outcome::Ok(42) });
        assert_eq!(handle.id(), Some(tid));
    }

    #[test]
    fn region_handle_id() {
        let rid = RegionId::new_for_test(3, 0);
        let handle = RegionHandle::new(rid, async {});
        assert_eq!(handle.id(), Some(rid));
    }

    #[test]
    fn lab_runtime_target_with_tracing() {
        let config = TestConfig::new().with_seed(42).with_tracing(true);
        let runtime = LabRuntimeTarget::create_runtime(config);
        assert_eq!(runtime.config().seed, 42);
        assert_eq!(runtime.config().trace_capacity, 64 * 1024);
    }

    #[test]
    fn lab_runtime_target_without_seed() {
        let config = TestConfig::new().without_seed();
        let runtime = LabRuntimeTarget::create_runtime(config);
        // Should use default seed 0xDEAD_BEEF when None
        assert_eq!(runtime.config().seed, 0xDEAD_BEEF);
    }

    #[test]
    fn lab_runtime_target_spawn_registers_real_task_handle() {
        let config = TestConfig::default();
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let (task_id, outcome) = LabRuntimeTarget::block_on(&mut runtime, async {
            let cx = Cx::current().expect("root task should have a current Cx");
            let handle = LabRuntimeTarget::spawn(&cx, Budget::INFINITE, async { 42_u8 });

            assert_eq!(handle.id(), None);
            crate::runtime::yield_now().await;

            let task_id = handle
                .id()
                .expect("task id should be resolved after the first scheduler turn");
            let outcome = handle.await;
            (task_id, outcome)
        });

        assert_ne!(task_id, TaskId::new_for_test(0, 0));
        assert_eq!(outcome, Outcome::Ok(42));
    }

    #[test]
    fn lab_runtime_target_create_region_and_cancel_before_registration_closes_region() {
        let config = TestConfig::default();
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let region_id = LabRuntimeTarget::block_on(&mut runtime, async {
            let cx = Cx::current().expect("root task should have a current Cx");
            let region = LabRuntimeTarget::create_region(&cx, Budget::INFINITE);
            let region_id = Arc::clone(&region.region_id);
            assert_eq!(region.id(), None);

            LabRuntimeTarget::cancel(&cx, &region, CancelReason::user("conformance-test"));
            region.await;
            (*region_id.lock()).expect("region id should resolve once the region has been created")
        });

        assert_ne!(region_id, RegionId::new_for_test(0, 0));
    }
}
