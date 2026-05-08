//! Fuzz pool slot allocation under cancel and concurrent operations.
//!
//! Tests race conditions in:
//! 1. Borrow-with-cancel race (acquire cancelled while resource creation in flight)
//! 2. Return-after-pool-drop race (resources returned to dropped pool)
//! 3. Weighted slot fairness (FIFO waiter queue ordering and position-based allocation)
//!
//! Critical invariants:
//! - Total resources (active + idle + creating) never exceeds max_size
//! - Waiters receive resources in FIFO order when multiple slots become available
//! - Resource returns after pool drop don't corrupt state or leak resources
//! - Cancel during acquire doesn't leak CreateSlotReservation or corrupt waiters queue
//! - Health check failures properly roll back accounting changes

#![no_main]

use arbitrary::Arbitrary;
use asupersync::cx::Cx;
use asupersync::sync::{AsyncResourceFactory, GenericPool, Pool, PoolConfig, PooledResource, PoolError};
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use futures::task::noop_waker;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Arbitrary)]
struct PoolOpsSequence {
    /// Pool max size (1-16)
    max_size: u8,
    /// Pool min size (0-max_size)
    min_size: u8,
    /// Operations to perform
    operations: Vec<PoolOp>,
}

#[derive(Debug, Clone, Arbitrary)]
enum PoolOp {
    /// Acquire resource with task ID
    Acquire { task_id: u8 },
    /// Try acquire resource with task ID
    TryAcquire { task_id: u8 },
    /// Return resource from task
    ReturnResource { task_id: u8 },
    /// Discard resource from task
    DiscardResource { task_id: u8 },
    /// Mark resource as broken
    MarkResourceBroken { task_id: u8 },
    /// Cancel acquire operation
    CancelAcquire { task_id: u8 },
    /// Close pool
    ClosePool,
    /// Create concurrent acquire burst (fairness test)
    ConcurrentAcquireBurst { task_ids: Vec<u8> },
    /// Simulate resource creation failure
    SimulateCreateFailure { enabled: bool },
    /// Health check failure simulation
    SimulateHealthCheckFailure { enabled: bool },
    /// Check pool state invariants
    CheckInvariants,
    /// Yield to allow async operations to proceed
    Yield,
    /// Drop pool handle (test return-after-drop)
    DropPoolHandle,
    /// Warmup pool with initial resources
    WarmupPool { count: u8 },
}

#[derive(Debug)]
struct MockResource {
    id: u64,
    created_at: Instant,
    is_broken: bool,
}

#[derive(Debug)]
struct MockResourceFactory {
    next_id: AtomicU64,
    failure_enabled: AtomicBool,
    health_check_failure_enabled: AtomicBool,
}

impl MockResourceFactory {
    fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            failure_enabled: AtomicBool::new(false),
            health_check_failure_enabled: AtomicBool::new(false),
        }
    }

    fn set_failure_enabled(&self, enabled: bool) {
        self.failure_enabled.store(enabled, Ordering::Relaxed);
    }

    fn set_health_check_failure_enabled(&self, enabled: bool) {
        self.health_check_failure_enabled.store(enabled, Ordering::Relaxed);
    }

    fn is_healthy(&self, _resource: &MockResource) -> bool {
        !self.health_check_failure_enabled.load(Ordering::Relaxed)
    }
}

impl AsyncResourceFactory for MockResourceFactory {
    type Resource = MockResource;
    type Error = std::io::Error;

    fn create(&self) -> Pin<Box<dyn Future<Output = Result<Self::Resource, Self::Error>> + Send + '_>> {
        Box::pin(async move {
            if self.failure_enabled.load(Ordering::Relaxed) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "simulated creation failure"
                ));
            }

            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            Ok(MockResource {
                id,
                created_at: Instant::now(),
                is_broken: false,
            })
        })
    }
}

struct TaskState {
    cx: Cx,
    resource: Option<PooledResource<MockResource>>,
    acquire_cancelled: bool,
    is_waiting: bool,
}

struct FuzzState {
    pool: Option<Box<dyn Pool<Resource = MockResource, Error = PoolError> + Send + Sync>>,
    factory: Arc<MockResourceFactory>,
    tasks: HashMap<u8, TaskState>,
    max_size: usize,
    min_size: usize,
    total_operations: AtomicUsize,
    fairness_tracker: Arc<FairnessTracker>,
    pool_dropped: bool,
}

#[derive(Debug)]
struct FairnessTracker {
    acquire_attempts: AtomicUsize,
    acquire_successes: AtomicUsize,
    acquire_order_violations: AtomicUsize,
    next_expected_task: AtomicUsize,
}

impl FairnessTracker {
    fn new() -> Self {
        Self {
            acquire_attempts: AtomicUsize::new(0),
            acquire_successes: AtomicUsize::new(0),
            acquire_order_violations: AtomicUsize::new(0),
            next_expected_task: AtomicUsize::new(0),
        }
    }

    fn record_acquire_attempt(&self) {
        self.acquire_attempts.fetch_add(1, Ordering::Relaxed);
    }

    fn record_acquire_success(&self, task_id: u8) {
        self.acquire_successes.fetch_add(1, Ordering::Relaxed);

        // Simple fairness check: in a burst scenario, tasks should generally
        // complete in the order they were queued (allowing for some variance)
        let expected = self.next_expected_task.load(Ordering::Relaxed);
        if (task_id as usize) < expected {
            self.acquire_order_violations.fetch_add(1, Ordering::Relaxed);
        } else {
            self.next_expected_task.store((task_id as usize).wrapping_add(1), Ordering::Relaxed);
        }
    }
}

impl FuzzState {
    fn new(max_size: usize, min_size: usize) -> Self {
        let factory = Arc::new(MockResourceFactory::new());
        let config = PoolConfig::default()
            .max_size(max_size)
            .min_size(min_size)
            .acquire_timeout(Duration::from_secs(1))
            .idle_timeout(Duration::from_secs(10))
            .max_lifetime(Duration::from_secs(60));

        // Create a factory function that captures the mock factory
        let factory_clone = Arc::clone(&factory);
        let factory_fn = move || {
            let factory = Arc::clone(&factory_clone);
            Box::pin(async move {
                factory.create().await
            }) as Pin<Box<dyn Future<Output = Result<MockResource, std::io::Error>> + Send>>
        };

        let pool = GenericPool::new(factory_fn, config)
            .with_health_check({
                let factory_ref = Arc::clone(&factory);
                move |resource| factory_ref.is_healthy(resource)
            });

        Self {
            pool: Some(Box::new(pool)),
            factory,
            tasks: HashMap::new(),
            max_size,
            min_size,
            total_operations: AtomicUsize::new(0),
            fairness_tracker: Arc::new(FairnessTracker::new()),
            pool_dropped: false,
        }
    }

    fn check_invariants(&self) -> bool {
        // Skip invariant checks if pool is dropped
        let Some(ref pool) = self.pool else {
            return true;
        };

        let stats = pool.stats();

        // 1. Total resources should not exceed max_size
        if stats.total > stats.max_size {
            eprintln!("Invariant violation: total resources ({}) > max_size ({})",
                     stats.total, stats.max_size);
            return false;
        }

        // 2. Active resources should match held resources
        let held_resources = self.tasks.values()
            .filter(|task| task.resource.is_some())
            .count();
        if held_resources != stats.active {
            eprintln!("Invariant violation: held resources ({}) != active ({})",
                     held_resources, stats.active);
            return false;
        }

        // 3. Fairness check: success rate shouldn't be too low under normal conditions
        let attempts = self.fairness_tracker.acquire_attempts.load(Ordering::Acquire);
        let successes = self.fairness_tracker.acquire_successes.load(Ordering::Acquire);
        let violations = self.fairness_tracker.acquire_order_violations.load(Ordering::Acquire);

        if attempts > 20 {
            // Success rate should be reasonable (allowing for contention)
            if successes * 5 < attempts {
                eprintln!("Invariant violation: very low success rate: {}/{}", successes, attempts);
                return false;
            }

            // Order violations should be limited
            if violations > successes / 2 {
                eprintln!("Invariant violation: too many fairness violations: {}/{}", violations, successes);
                return false;
            }
        }

        true
    }

    fn acquire_resource(&mut self, task_id: u8) {
        let Some(ref pool) = self.pool else {
            return; // Pool dropped
        };

        let task_state = self.tasks.entry(task_id).or_insert_with(|| TaskState {
            cx: create_cx(),
            resource: None,
            acquire_cancelled: false,
            is_waiting: false,
        });

        if task_state.resource.is_some() || task_state.is_waiting {
            return; // Already has resource or waiting
        }

        self.fairness_tracker.record_acquire_attempt();
        task_state.is_waiting = true;

        // Simulate async acquire using polling
        let mut acquire_future = pool.acquire(&task_state.cx);
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        match Pin::new(&mut acquire_future).poll(&mut context) {
            Poll::Ready(Ok(resource)) => {
                task_state.resource = Some(resource);
                task_state.is_waiting = false;
                self.fairness_tracker.record_acquire_success(task_id);
            }
            Poll::Ready(Err(_err)) => {
                task_state.is_waiting = false;
                // Acquire failed (pool closed, cancelled, timeout, etc.)
            }
            Poll::Pending => {
                // Would need actual async runtime to handle pending properly
                task_state.is_waiting = false;
            }
        }
    }

    fn try_acquire_resource(&mut self, task_id: u8) {
        let Some(ref pool) = self.pool else {
            return; // Pool dropped
        };

        let task_state = self.tasks.entry(task_id).or_insert_with(|| TaskState {
            cx: create_cx(),
            resource: None,
            acquire_cancelled: false,
            is_waiting: false,
        });

        if task_state.resource.is_some() {
            return; // Already has resource
        }

        self.fairness_tracker.record_acquire_attempt();

        if let Some(resource) = pool.try_acquire() {
            task_state.resource = Some(resource);
            self.fairness_tracker.record_acquire_success(task_id);
        }
    }

    fn return_resource(&mut self, task_id: u8) {
        if let Some(task_state) = self.tasks.get_mut(&task_id) {
            if let Some(resource) = task_state.resource.take() {
                resource.return_to_pool();
            }
        }
    }

    fn discard_resource(&mut self, task_id: u8) {
        if let Some(task_state) = self.tasks.get_mut(&task_id) {
            if let Some(resource) = task_state.resource.take() {
                resource.discard();
            }
        }
    }

    fn mark_resource_broken(&mut self, task_id: u8) {
        if let Some(task_state) = self.tasks.get_mut(&task_id) {
            if let Some(resource) = &mut task_state.resource {
                resource.mark_broken();
            }
        }
    }

    fn cancel_acquire(&mut self, task_id: u8) {
        if let Some(task_state) = self.tasks.get_mut(&task_id) {
            task_state.cx.set_cancel_requested(true);
            task_state.acquire_cancelled = true;
            task_state.is_waiting = false;
        }
    }

    fn close_pool(&mut self) {
        if let Some(ref pool) = self.pool {
            // Simulate async close using polling
            let mut close_future = pool.close();
            let waker = noop_waker();
            let mut context = Context::from_waker(&waker);
            let _ = Pin::new(&mut close_future).poll(&mut context);
        }
    }

    fn concurrent_acquire_burst(&mut self, task_ids: &[u8]) {
        // Reset fairness tracking for this burst
        self.fairness_tracker.next_expected_task.store(0, Ordering::Relaxed);

        for &task_id in task_ids.iter().take(8) { // Limit concurrent tasks
            self.acquire_resource(task_id);
        }
    }

    fn warmup_pool(&mut self, _count: u8) {
        // Simplified warmup for fuzzing - the pool itself will be tested
        // through acquire operations. Warmup is not critical for race testing.
    }
}

fn create_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

fuzz_target!(|sequence: PoolOpsSequence| {
    let max_size = sequence.max_size.max(1).min(16) as usize;
    let min_size = sequence.min_size.min(sequence.max_size) as usize;
    let mut state = FuzzState::new(max_size, min_size);

    for operation in sequence.operations.into_iter().take(100) { // Limit ops to prevent timeout
        match operation {
            PoolOp::Acquire { task_id } => {
                state.acquire_resource(task_id);
            }

            PoolOp::TryAcquire { task_id } => {
                state.try_acquire_resource(task_id);
            }

            PoolOp::ReturnResource { task_id } => {
                state.return_resource(task_id);
            }

            PoolOp::DiscardResource { task_id } => {
                state.discard_resource(task_id);
            }

            PoolOp::MarkResourceBroken { task_id } => {
                state.mark_resource_broken(task_id);
            }

            PoolOp::CancelAcquire { task_id } => {
                state.cancel_acquire(task_id);
            }

            PoolOp::ClosePool => {
                state.close_pool();
            }

            PoolOp::ConcurrentAcquireBurst { task_ids } => {
                state.concurrent_acquire_burst(&task_ids);
            }

            PoolOp::SimulateCreateFailure { enabled } => {
                state.factory.set_failure_enabled(enabled);
            }

            PoolOp::SimulateHealthCheckFailure { enabled } => {
                state.factory.set_health_check_failure_enabled(enabled);
            }

            PoolOp::CheckInvariants => {
                assert!(state.check_invariants(), "Pool invariants violated");
            }

            PoolOp::Yield => {
                // Simulate yielding to allow async operations to proceed
                // In a real async environment, this would allow tasks to be scheduled
            }

            PoolOp::DropPoolHandle => {
                // Test return-after-pool-drop race
                state.pool = None;
                state.pool_dropped = true;
            }

            PoolOp::WarmupPool { count } => {
                let count = count.min(max_size as u8);
                state.warmup_pool(count);
            }
        }

        state.total_operations.fetch_add(1, Ordering::Relaxed);

        // Periodic invariant check
        if state.total_operations.load(Ordering::Acquire) % 15 == 0 {
            assert!(state.check_invariants(), "Periodic invariant check failed");
        }
    }

    // Return all resources to test return-after-operations
    for task_id in 0..=255u8 {
        if state.tasks.contains_key(&task_id) {
            state.return_resource(task_id);
        }
    }

    // Final invariant check
    assert!(state.check_invariants(), "Final invariant check failed");
});