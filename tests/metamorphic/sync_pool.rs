//! Metamorphic tests for sync::pool acquire/release/reset invariants.
//!
//! These tests validate the core invariants of the resource pool acquisition,
//! capacity bounds, lifecycle management, and cancel-aware operations using
//! metamorphic relations and property-based testing under deterministic LabRuntime.
//!
//! ## Key Properties Tested
//!
//! 1. **Resource tracking**: acquired items tracked and released correctly
//! 2. **Capacity bounds**: pool capacity bound enforced (max_size respected)
//! 3. **Reset semantics**: close clears all pooled items
//! 4. **Cancel safety**: cancel during acquire does not leak permits
//! 5. **Idle timeout**: idle timeout recycles stale items
//! 6. **Non-blocking try**: try_acquire never blocks
//!
//! ## Metamorphic Relations
//!
//! - **Acquisition tracking**: acquired count + idle count + creating count = total managed
//! - **Capacity invariant**: total resources ≤ max_size at all times
//! - **Reset completeness**: close() → idle.is_empty() ∧ active = 0
//! - **Cancel non-leakage**: cancelled acquire ≡ never-attempted acquire
//! - **Timeout recycling**: idle > timeout ⟹ resource destroyed
//! - **Try-acquire timing**: try_acquire execution time < constant bound

use proptest::prelude::*;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use std::pin::Pin;
use std::future::Future;
use std::collections::VecDeque;

use asupersync::cx::{Cx, Scope};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::sync::{
    AsyncResourceFactory, GenericPool, Pool, PoolConfig, PoolError, PoolStats, PooledResource,
};
use asupersync::types::{
    cancel::CancelReason, ArenaIndex, Budget, RegionId, TaskId,
};

// =============================================================================
// Test Utilities
// =============================================================================

/// Create a test context for pool testing.
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Create a test context with specific slot.
fn test_cx_with_slot(slot: u32) -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, slot)),
        TaskId::from_arena(ArenaIndex::new(0, slot)),
        Budget::INFINITE,
    )
}

/// Create a test LabRuntime for deterministic testing.
fn test_lab_runtime() -> LabRuntime {
    LabRuntime::with_config(LabConfig::deterministic())
}

/// Create a test LabRuntime with specific seed.
fn test_lab_runtime_with_seed(seed: u64) -> LabRuntime {
    LabRuntime::with_config(LabConfig::deterministic().with_seed(seed))
}

/// Simple string resource for testing.
#[derive(Debug, Clone)]
struct TestResource {
    id: usize,
    value: String,
}

impl TestResource {
    fn new(id: usize) -> Self {
        Self {
            id,
            value: format!("resource_{}", id),
        }
    }
}

/// Factory that creates TestResource instances.
#[derive(Debug, Clone)]
struct TestResourceFactory {
    next_id: Arc<StdMutex<usize>>,
    failure_rate: f64, // 0.0 = never fail, 1.0 = always fail
}

impl TestResourceFactory {
    fn new() -> Self {
        Self {
            next_id: Arc::new(StdMutex::new(0)),
            failure_rate: 0.0,
        }
    }

    fn with_failure_rate(failure_rate: f64) -> Self {
        Self {
            next_id: Arc::new(StdMutex::new(0)),
            failure_rate,
        }
    }
}

impl AsyncResourceFactory for TestResourceFactory {
    type Resource = TestResource;
    type Error = std::io::Error;

    fn create(&self) -> Pin<Box<dyn Future<Output = Result<Self::Resource, Self::Error>> + Send + '_>> {
        Box::pin(async move {
            // Simulate creation time
            asupersync::time::sleep(Duration::from_millis(1)).await;

            // Check for simulated failure
            if self.failure_rate > 0.0 {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                std::thread::current().id().hash(&mut hasher);
                Instant::now().elapsed().as_nanos().hash(&mut hasher);
                let random_val = (hasher.finish() as f64) / (u64::MAX as f64);

                if random_val < self.failure_rate {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Simulated factory failure"
                    ));
                }
            }

            let mut next_id = self.next_id.lock().unwrap();
            let id = *next_id;
            *next_id += 1;
            Ok(TestResource::new(id))
        })
    }
}

/// Tracks pool operations for invariant checking.
#[derive(Debug, Clone)]
struct PoolTracker {
    acquisitions: Vec<usize>,
    releases: Vec<usize>,
    cancellations: Vec<usize>,
    try_acquire_calls: Vec<bool>, // true = success, false = failure
    active_resources: std::collections::HashSet<usize>,
    total_created: usize,
}

impl PoolTracker {
    fn new() -> Self {
        Self {
            acquisitions: Vec::new(),
            releases: Vec::new(),
            cancellations: Vec::new(),
            try_acquire_calls: Vec::new(),
            active_resources: std::collections::HashSet::new(),
            total_created: 0,
        }
    }

    /// Record a successful acquisition.
    fn record_acquire(&mut self, resource_id: usize) {
        self.acquisitions.push(resource_id);
        assert!(self.active_resources.insert(resource_id),
            "Resource {} already active", resource_id);
    }

    /// Record a resource release.
    fn record_release(&mut self, resource_id: usize) {
        self.releases.push(resource_id);
        assert!(self.active_resources.remove(&resource_id),
            "Resource {} not active when released", resource_id);
    }

    /// Record a cancellation.
    fn record_cancel(&mut self, task_id: usize) {
        self.cancellations.push(task_id);
    }

    /// Record a try_acquire call.
    fn record_try_acquire(&mut self, success: bool) {
        self.try_acquire_calls.push(success);
    }

    /// Record resource creation.
    fn record_create(&mut self) {
        self.total_created += 1;
    }

    /// Check that acquisitions balance with releases.
    fn check_acquisition_balance(&self) -> bool {
        // All acquired resources should be either released or still active
        let acquired_set: std::collections::HashSet<usize> = self.acquisitions.iter().cloned().collect();
        let released_set: std::collections::HashSet<usize> = self.releases.iter().cloned().collect();

        // active_resources + released_set should equal acquired_set
        let accounted_resources: std::collections::HashSet<usize> =
            self.active_resources.iter().chain(released_set.iter()).cloned().collect();

        acquired_set == accounted_resources
    }

    /// Check no resource is double-released.
    fn check_no_double_release(&self) -> bool {
        let mut seen = std::collections::HashSet::new();
        for &resource_id in &self.releases {
            if !seen.insert(resource_id) {
                return false; // Double release detected
            }
        }
        true
    }
}

// =============================================================================
// Proptest Strategies
// =============================================================================

/// Generate arbitrary pool configurations.
fn arb_pool_config() -> impl Strategy<Value = PoolConfig> {
    (1usize..=5, 2usize..=10, 1u64..100, 1u64..300).prop_map(|(min_size, max_size, idle_ms, acquire_ms)| {
        PoolConfig::default()
            .min_size(min_size)
            .max_size(max_size.max(min_size + 1)) // Ensure max > min
            .idle_timeout(Duration::from_millis(idle_ms))
            .acquire_timeout(Duration::from_millis(acquire_ms))
    })
}

/// Generate arbitrary acquisition sequences.
fn arb_acquisition_sequence() -> impl Strategy<Value = Vec<PoolOperation>> {
    prop::collection::vec(arb_pool_operation(), 0..15)
}

#[derive(Debug, Clone)]
enum PoolOperation {
    Acquire(usize), // task_id
    TryAcquire(usize), // task_id
    Release(usize), // task_id
    Cancel(usize), // task_id
    Sleep(u64), // milliseconds
}

fn arb_pool_operation() -> impl Strategy<Value = PoolOperation> {
    prop_oneof![
        (0usize..10).prop_map(PoolOperation::Acquire),
        (0usize..10).prop_map(PoolOperation::TryAcquire),
        (0usize..10).prop_map(PoolOperation::Release),
        (0usize..10).prop_map(PoolOperation::Cancel),
        (1u64..50).prop_map(PoolOperation::Sleep),
    ]
}

// =============================================================================
// Core Metamorphic Relations
// =============================================================================

/// MR1: Resource tracking - acquired items tracked and released correctly.
#[test]
fn mr_resource_tracking() {
    proptest!(|(config in arb_pool_config(),
               operations in arb_acquisition_sequence(),
               seed in 0u64..1000)| {
        let lab = test_lab_runtime_with_seed(seed);
        let _guard = lab.enter();

        let factory = TestResourceFactory::new();
        let pool = Arc::new(GenericPool::new(factory, config.clone()));
        let mut tracker = PoolTracker::new();

        lab.block_on(async {
            let mut active_acquisitions: std::collections::HashMap<usize, PooledResource<TestResource>> = std::collections::HashMap::new();

            for op in operations.iter().take(20) {
                match op {
                    PoolOperation::Acquire(task_id) => {
                        if !active_acquisitions.contains_key(task_id) {
                            let cx = test_cx_with_slot(*task_id as u32);
                            if let Ok(resource) = pool.acquire(&cx).await {
                                tracker.record_acquire(resource.id);
                                active_acquisitions.insert(*task_id, resource);
                            }
                        }
                    }
                    PoolOperation::Release(task_id) => {
                        if let Some(resource) = active_acquisitions.remove(task_id) {
                            tracker.record_release(resource.id);
                            // Resource is automatically returned to pool on drop
                        }
                    }
                    PoolOperation::Sleep(ms) => {
                        asupersync::time::sleep(Duration::from_millis(*ms)).await;
                    }
                    _ => {} // Skip other operations for this test
                }
            }

            // Release any remaining active resources
            for (task_id, resource) in active_acquisitions.drain() {
                tracker.record_release(resource.id);
            }

            // Verify tracking invariants
            prop_assert!(tracker.check_acquisition_balance(),
                "Acquisition/release balance violated");

            prop_assert!(tracker.check_no_double_release(),
                "Double release detected");

            // Verify pool stats consistency
            let stats = pool.stats();
            prop_assert!(stats.active <= config.max_size,
                "Active count {} exceeds max_size {}",
                stats.active, config.max_size);
        });
    });
}

/// MR2: Capacity bounds - pool capacity bound enforced.
#[test]
fn mr_capacity_bounds() {
    proptest!(|(config in arb_pool_config(),
               num_concurrent in 2usize..=8,
               seed in 0u64..1000)| {
        let lab = test_lab_runtime_with_seed(seed);
        let _guard = lab.enter();

        let factory = TestResourceFactory::new();
        let pool = Arc::new(GenericPool::new(factory, config.clone()));

        lab.block_on(async {
            let scope = Scope::new();
            let acquisitions = Arc::new(StdMutex::new(Vec::new()));

            // Spawn multiple tasks trying to acquire resources
            for i in 0..num_concurrent {
                let pool_clone = Arc::clone(&pool);
                let acq_clone = Arc::clone(&acquisitions);

                scope.spawn(async move {
                    let cx = test_cx_with_slot(i as u32);
                    if let Ok(resource) = pool_clone.acquire(&cx).await {
                        acq_clone.lock().unwrap().push(resource);

                        // Hold the resource briefly
                        asupersync::time::sleep(Duration::from_millis(10)).await;
                    }
                });
            }

            // Let tasks run and check capacity bounds periodically
            for _ in 0..5 {
                asupersync::time::sleep(Duration::from_millis(5)).await;

                let stats = pool.stats();
                prop_assert!(stats.active + stats.idle <= config.max_size,
                    "Total resources {} exceeds max_size {}",
                    stats.active + stats.idle, config.max_size);

                prop_assert!(stats.active <= config.max_size,
                    "Active resources {} exceeds max_size {}",
                    stats.active, config.max_size);
            }
        }); // scope drops, releasing all resources

        // After all resources released, verify final state
        let final_stats = pool.stats();
        prop_assert!(final_stats.active == 0,
            "Active count should be 0 after all releases, got {}",
            final_stats.active);
    });
}

/// MR3: Reset semantics - close clears all pooled items.
#[test]
fn mr_reset_semantics() {
    proptest!(|(config in arb_pool_config(),
               num_resources in 1usize..=5,
               seed in 0u64..1000)| {
        let lab = test_lab_runtime_with_seed(seed);
        let _guard = lab.enter();

        let factory = TestResourceFactory::new();
        let pool = Arc::new(GenericPool::new(factory, config.clone()));

        lab.block_on(async {
            // Acquire and release some resources to populate the idle pool
            let cx = test_cx();
            let mut resources = Vec::new();

            for _ in 0..num_resources.min(config.max_size) {
                if let Ok(resource) = pool.acquire(&cx).await {
                    resources.push(resource);
                }
            }

            // Release resources to populate idle queue
            resources.clear();

            // Give pool time to process returns
            asupersync::time::sleep(Duration::from_millis(10)).await;

            let stats_before_close = pool.stats();

            // Close the pool (equivalent to reset)
            pool.close().await;

            let stats_after_close = pool.stats();

            // After close, idle resources should be cleared
            prop_assert!(stats_after_close.idle == 0,
                "Idle count should be 0 after close, got {}",
                stats_after_close.idle);

            // New acquisitions should fail on closed pool
            match pool.acquire(&cx).await {
                Err(PoolError::Closed) => {}, // Expected
                Ok(_) => prop_assert!(false, "Acquire should fail on closed pool"),
                Err(e) => prop_assert!(false, "Expected Closed error, got {:?}", e),
            }

            // try_acquire should also fail
            prop_assert!(pool.try_acquire().is_none(),
                "try_acquire should return None on closed pool");
        });
    });
}

/// MR4: Cancel safety - cancel during acquire does not leak permits.
#[test]
fn mr_cancel_safety() {
    proptest!(|(config in arb_pool_config(),
               seed in 0u64..1000)| {
        let lab = test_lab_runtime_with_seed(seed);
        let _guard = lab.enter();

        // Use a small max_size to force contention
        let small_config = PoolConfig::default()
            .max_size(2)
            .min_size(1)
            .acquire_timeout(Duration::from_secs(10));

        let factory = TestResourceFactory::new();
        let pool = Arc::new(GenericPool::new(factory, small_config.clone()));

        lab.block_on(async {
            let cx1 = test_cx_with_slot(1);
            let cx2 = test_cx_with_slot(2);
            let cx3 = test_cx_with_slot(3);

            // First two tasks acquire resources (filling the pool)
            let _resource1 = pool.acquire(&cx1).await.expect("Should acquire first resource");
            let _resource2 = pool.acquire(&cx2).await.expect("Should acquire second resource");

            // Third task starts waiting (pool at capacity)
            let acquire_future = pool.acquire(&cx3);

            // Cancel the third task's context
            cx3.cancel(CancelReason::Timeout);

            // The cancelled acquire should fail
            match acquire_future.await {
                Err(PoolError::Cancelled) => {
                    // After cancellation, pool stats should be consistent
                    let stats = pool.stats();
                    prop_assert_eq!(stats.active, 2,
                        "Active count should remain 2 after cancellation");

                    prop_assert!(stats.pending == 0,
                        "No pending waiters should remain after cancellation");
                }
                other => prop_assert!(false, "Expected Cancelled, got {:?}", other),
            }

            // Verify no permit leak by releasing one resource and acquiring again
            drop(_resource1);

            // Give pool time to process the return
            asupersync::time::sleep(Duration::from_millis(5)).await;

            let cx4 = test_cx_with_slot(4);
            let _resource4 = pool.acquire(&cx4).await.expect("Should acquire after release");

            let final_stats = pool.stats();
            prop_assert_eq!(final_stats.active, 2,
                "Active count should be 2 after reacquisition");
        });
    });
}

/// MR5: Idle timeout - idle timeout recycles stale items.
#[test]
fn mr_idle_timeout() {
    proptest!(|(seed in 0u64..1000)| {
        let lab = test_lab_runtime_with_seed(seed);
        let _guard = lab.enter();

        // Use short idle timeout for testing
        let config = PoolConfig::default()
            .max_size(3)
            .min_size(1)
            .idle_timeout(Duration::from_millis(50));

        let factory = TestResourceFactory::new();
        let pool = Arc::new(GenericPool::new(factory, config));

        lab.block_on(async {
            let cx = test_cx();

            // Acquire and release a resource to put it in idle pool
            let resource = pool.acquire(&cx).await.expect("Should acquire resource");
            let resource_id = resource.id;
            drop(resource);

            // Give pool time to process the return
            asupersync::time::sleep(Duration::from_millis(10)).await;

            let stats_before_timeout = pool.stats();
            prop_assert!(stats_before_timeout.idle > 0,
                "Should have idle resources before timeout");

            // Wait for idle timeout to trigger
            asupersync::time::sleep(Duration::from_millis(100)).await;

            // Resource should be recycled by timeout
            let resource_after_timeout = pool.acquire(&cx).await.expect("Should acquire new resource");

            // Should get a fresh resource (different ID) due to timeout recycling
            prop_assert!(resource_after_timeout.id != resource_id || stats_before_timeout.idle == 0,
                "Should get fresh resource after idle timeout or no idle resources were present");
        });
    });
}

/// MR6: Non-blocking try - try_acquire never blocks.
#[test]
fn mr_try_acquire_non_blocking() {
    proptest!(|(config in arb_pool_config(),
               operations in arb_acquisition_sequence())| {
        let lab = test_lab_runtime();
        let _guard = lab.enter();

        let factory = TestResourceFactory::new();
        let pool = GenericPool::new(factory, config);

        // try_acquire should always return immediately
        for _ in 0..20 {
            let start_time = Instant::now();
            let _result = pool.try_acquire();
            let elapsed = start_time.elapsed();

            // try_acquire should complete very quickly (non-blocking)
            prop_assert!(elapsed < Duration::from_millis(5),
                "try_acquire took too long: {:?}", elapsed);
        }

        lab.block_on(async {
            let cx = test_cx();
            let mut acquired_resources = Vec::new();

            // Fill the pool to capacity
            for _ in 0..config.max_size {
                if let Ok(resource) = pool.acquire(&cx).await {
                    acquired_resources.push(resource);
                }
            }

            // try_acquire should fail immediately when pool is at capacity, not block
            let start_time = Instant::now();
            let result = pool.try_acquire();
            let elapsed = start_time.elapsed();

            prop_assert!(result.is_none(),
                "try_acquire should return None when pool at capacity");

            prop_assert!(elapsed < Duration::from_millis(5),
                "try_acquire blocked despite being designed not to: {:?}", elapsed);
        });
    });
}

// =============================================================================
// Additional Metamorphic Relations
// =============================================================================

/// MR7: Factory error handling - factory failures don't corrupt pool state.
#[test]
fn mr_factory_error_handling() {
    proptest!(|(failure_rate in 0.1f64..0.8,
               num_attempts in 3usize..10,
               seed in 0u64..1000)| {
        let lab = test_lab_runtime_with_seed(seed);
        let _guard = lab.enter();

        let config = PoolConfig::default().max_size(5);
        let factory = TestResourceFactory::with_failure_rate(failure_rate);
        let pool = GenericPool::new(factory, config.clone());

        lab.block_on(async {
            let cx = test_cx();
            let mut successes = 0;
            let mut failures = 0;

            for _ in 0..num_attempts {
                match pool.acquire(&cx).await {
                    Ok(_resource) => successes += 1,
                    Err(PoolError::Factory(_)) => failures += 1,
                    Err(other) => prop_assert!(false, "Unexpected error: {:?}", other),
                }
            }

            // Should have some failures given the failure rate
            prop_assert!(failures > 0, "Expected some factory failures");

            // Pool stats should remain consistent despite factory failures
            let stats = pool.stats();
            prop_assert!(stats.active <= config.max_size,
                "Active count exceeds max after factory failures");

            // try_acquire should also handle factory failures gracefully
            for _ in 0..5 {
                let _result = pool.try_acquire(); // May succeed or fail, both are OK
            }
        });
    });
}

/// MR8: Concurrent access consistency - multiple tasks don't corrupt pool state.
#[test]
fn mr_concurrent_access_consistency() {
    proptest!(|(config in arb_pool_config(),
               num_tasks in 3usize..8,
               seed in 0u64..1000)| {
        let lab = test_lab_runtime_with_seed(seed);
        let _guard = lab.enter();

        let factory = TestResourceFactory::new();
        let pool = Arc::new(GenericPool::new(factory, config.clone()));
        let operations_log = Arc::new(StdMutex::new(Vec::new()));

        lab.block_on(async {
            let scope = Scope::new();

            for task_id in 0..num_tasks {
                let pool_clone = Arc::clone(&pool);
                let log_clone = Arc::clone(&operations_log);

                scope.spawn(async move {
                    let cx = test_cx_with_slot(task_id as u32);

                    // Each task performs a sequence of operations
                    for i in 0..3 {
                        // Try acquire
                        if let Some(resource) = pool_clone.try_acquire() {
                            log_clone.lock().unwrap().push(format!("task_{}_try_acquire_{}_{}", task_id, i, resource.id));
                            asupersync::time::sleep(Duration::from_millis(2)).await;
                            drop(resource);
                            log_clone.lock().unwrap().push(format!("task_{}_release_{}", task_id, i));
                        }

                        // Regular acquire
                        if let Ok(resource) = pool_clone.acquire(&cx).await {
                            log_clone.lock().unwrap().push(format!("task_{}_acquire_{}_{}", task_id, i, resource.id));
                            asupersync::time::sleep(Duration::from_millis(1)).await;
                            drop(resource);
                            log_clone.lock().unwrap().push(format!("task_{}_release_{}", task_id, i));
                        }
                    }
                });
            }
        }); // scope drops, all tasks complete

        // Verify final pool state is consistent
        let final_stats = pool.stats();
        prop_assert_eq!(final_stats.active, 0,
            "All resources should be released after tasks complete");

        let log = operations_log.lock().unwrap();
        prop_assert!(!log.is_empty(), "Should have recorded some operations");

        // Pool should still be functional after concurrent access
        lab.block_on(async {
            let cx = test_cx();
            let _resource = pool.acquire(&cx).await.expect("Pool should still work after concurrent access");
        });
    });
}

// =============================================================================
// Regression Tests
// =============================================================================

/// Test basic pool functionality.
#[test]
fn test_basic_pool() {
    let lab = test_lab_runtime();
    let _guard = lab.enter();

    let factory = TestResourceFactory::new();
    let pool = GenericPool::new(factory, PoolConfig::default());

    lab.block_on(async {
        let cx = test_cx();

        // Basic acquire/release
        {
            let resource = pool.acquire(&cx).await.expect("Should acquire resource");
            assert!(resource.value.contains("resource_"));
        }

        // Resource should be returned to pool on drop
        let stats_after_release = pool.stats();
        assert_eq!(stats_after_release.active, 0);
    });
}

/// Test try_acquire basic functionality.
#[test]
fn test_try_acquire_basic() {
    let lab = test_lab_runtime();
    let _guard = lab.enter();

    let config = PoolConfig::default().max_size(1);
    let factory = TestResourceFactory::new();
    let pool = GenericPool::new(factory, config);

    lab.block_on(async {
        let cx = test_cx();

        // try_acquire on empty pool should succeed
        {
            let resource = pool.try_acquire().expect("Should try_acquire successfully");
            assert!(resource.value.contains("resource_"));

            // try_acquire while at capacity should fail
            assert!(pool.try_acquire().is_none(), "try_acquire should fail when pool at capacity");
        }

        // After resource drops, try_acquire should work again
        asupersync::time::sleep(Duration::from_millis(5)).await;
        assert!(pool.try_acquire().is_some(), "try_acquire should work after resource release");
    });
}

/// Test pool configuration limits.
#[test]
fn test_pool_limits() {
    let lab = test_lab_runtime();
    let _guard = lab.enter();

    let config = PoolConfig::default()
        .max_size(2)
        .acquire_timeout(Duration::from_millis(50));

    let factory = TestResourceFactory::new();
    let pool = Arc::new(GenericPool::new(factory, config));

    lab.block_on(async {
        let cx1 = test_cx_with_slot(1);
        let cx2 = test_cx_with_slot(2);
        let cx3 = test_cx_with_slot(3);

        // Acquire max resources
        let _res1 = pool.acquire(&cx1).await.expect("Should acquire first");
        let _res2 = pool.acquire(&cx2).await.expect("Should acquire second");

        // Third acquire should timeout
        let start = Instant::now();
        match pool.acquire(&cx3).await {
            Err(PoolError::Timeout) => {
                let elapsed = start.elapsed();
                assert!(elapsed >= Duration::from_millis(40), "Should respect acquire timeout");
            }
            other => panic!("Expected timeout, got {:?}", other),
        }
    });
}