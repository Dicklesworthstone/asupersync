//! Metamorphic tests for pool acquire/release pairing under cancellation.
//!
//! These tests verify invariant relationships that must hold for correct pool
//! behavior, focusing on scenarios where computing exact expected outputs
//! is intractable due to concurrency and cancellation.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::cx::Cx;
use crate::sync::{GenericPool, Pool, PoolConfig, PooledResource, PoolStats};

/// Mock resource for testing pool behavior.
#[derive(Debug, Clone)]
struct MockResource {
    id: usize,
    created_at: std::time::Instant,
}

/// Resource factory that tracks creation count.
#[derive(Debug)]
struct MockFactory {
    counter: Arc<AtomicUsize>,
    creation_delay: Duration,
}

impl MockFactory {
    fn new(creation_delay: Duration) -> Self {
        Self {
            counter: Arc::new(AtomicUsize::new(0)),
            creation_delay,
        }
    }

    fn creation_count(&self) -> usize {
        self.counter.load(Ordering::Acquire)
    }
}

impl crate::sync::AsyncResourceFactory for MockFactory {
    type Resource = MockResource;
    type Error = std::io::Error;

    fn create(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Resource, Self::Error>> + Send + '_>> {
        let id = self.counter.fetch_add(1, Ordering::AcqRel);
        let delay = self.creation_delay;

        Box::pin(async move {
            crate::time::sleep(Time::ZERO, delay).await;
            Ok(MockResource {
                id,
                created_at: std::time::Instant::now(),
            })
        })
    }
}

/// Generate sequences of pool operations.
#[derive(Debug, Clone)]
enum PoolOperation {
    Acquire { hold_ms: u64 },
    TryAcquire { hold_ms: u64 },
    AcquireWithCancel { hold_ms: u64, cancel_after_ms: u64 },
}

/// Execute a sequence of operations and collect accounting data.
async fn execute_operations(
    pool: &GenericPool<MockFactory>,
    operations: &[PoolOperation],
) -> OperationResults {
    let mut acquired_count = 0;
    let mut returned_count = 0;
    let mut discarded_count = 0;
    let mut cancel_count = 0;

    for op in operations {
        match op {
            PoolOperation::Acquire { hold_ms } => {
                let cx = Cx::root();
                if let Ok(resource) = pool.acquire(&cx).await {
                    acquired_count += 1;

                    // Simulate work by holding for the specified time
                    let delay = Duration::from_millis(*hold_ms);
                    crate::time::sleep(Time::ZERO, delay).await;

                    // Return the resource
                    resource.return_to_pool();
                    returned_count += 1;
                }
            }
            PoolOperation::TryAcquire { hold_ms } => {
                if let Some(resource) = pool.try_acquire() {
                    acquired_count += 1;

                    // Simulate work
                    let delay = Duration::from_millis(*hold_ms);
                    crate::time::sleep(Time::ZERO, delay).await;

                    // Sometimes discard instead of return to test both paths
                    if acquired_count % 3 == 0 {
                        resource.discard();
                        discarded_count += 1;
                    } else {
                        resource.return_to_pool();
                        returned_count += 1;
                    }
                }
            }
            PoolOperation::AcquireWithCancel { hold_ms, cancel_after_ms } => {
                let cx = Cx::root();
                let cancel_cx = cx.child();

                // Start the acquire operation
                let acquire_future = pool.acquire(&cancel_cx);

                // Cancel after the specified time
                let cancel_future = async {
                    crate::time::sleep(Time::ZERO,Time::ZERO,Duration::from_millis(*cancel_after_ms)).await;
                    cancel_cx.cancel();
                };

                // Race the acquire against cancellation
                tokio::select! {
                    result = acquire_future => {
                        if let Ok(resource) = result {
                            acquired_count += 1;

                            // Hold the resource briefly
                            crate::time::sleep(Time::ZERO,Time::ZERO,Duration::from_millis(*hold_ms)).await;

                            resource.return_to_pool();
                            returned_count += 1;
                        }
                    }
                    _ = cancel_future => {
                        cancel_count += 1;
                    }
                }
            }
        }

        // Small delay between operations to allow async processing
        crate::time::sleep(Time::ZERO,Time::ZERO,Duration::from_millis(10)).await;
    }

    OperationResults {
        acquired_count,
        returned_count,
        discarded_count,
        cancel_count,
    }
}

#[derive(Debug, Clone, PartialEq)]
struct OperationResults {
    acquired_count: usize,
    returned_count: usize,
    discarded_count: usize,
    cancel_count: usize,
}

#[cfg(test)]
mod metamorphic_tests {
    use super::*;

    /// MR1: Pool Accounting Invariant (Equivalence)
    /// Property: active + idle should always equal total
    #[tokio::test]
    async fn mr_pool_accounting_invariant() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("mr_pool_accounting_invariant");

        let config = PoolConfig::default().max_size(5).min_size(1);
        let factory = MockFactory::new(Duration::from_millis(1));
        let pool = GenericPool::new(factory, config);

        // Test the invariant across various operations
        for _ in 0..10 {
            let cx = Cx::root();
            let initial_stats = pool.stats();

            // Invariant must hold initially
            assert_eq!(initial_stats.active + initial_stats.idle, initial_stats.total,
                "Invariant violated initially: active={}, idle={}, total={}",
                initial_stats.active, initial_stats.idle, initial_stats.total);

            // Acquire a resource
            if let Ok(resource) = pool.acquire(&cx).await {
                let during_stats = pool.stats();
                assert_eq!(during_stats.active + during_stats.idle, during_stats.total,
                    "Invariant violated during hold: active={}, idle={}, total={}",
                    during_stats.active, during_stats.idle, during_stats.total);

                // Return the resource
                resource.return_to_pool();
                crate::time::sleep(Time::ZERO,Time::ZERO,Duration::from_millis(10)).await;

                let final_stats = pool.stats();
                assert_eq!(final_stats.active + final_stats.idle, final_stats.total,
                    "Invariant violated after return: active={}, idle={}, total={}",
                    final_stats.active, final_stats.idle, final_stats.total);
            }
        }

        crate::test_complete!("mr_pool_accounting_invariant");
    }

    /// MR2: Cancel-Safety Invariance (Equivalence)
    /// Property: Pool stats should remain consistent despite cancellations
    #[tokio::test]
    async fn mr_cancel_safety_invariance() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("mr_cancel_safety_invariance");

        let config = PoolConfig::default().max_size(3);
        let factory = MockFactory::new(Duration::from_millis(10));
        let pool = GenericPool::new(factory, config);

        let cx = Cx::root();
        let cancel_cx = cx.child();

        // Start acquiring but cancel quickly
        let acquire_future = pool.acquire(&cancel_cx);
        let cancel_future = async {
            crate::time::sleep(Time::ZERO,Time::ZERO,Duration::from_millis(5)).await;
            cancel_cx.cancel();
        };

        let initial_stats = pool.stats();

        tokio::select! {
            result = acquire_future => {
                // If acquire succeeded before cancel, return the resource
                if let Ok(resource) = result {
                    resource.return_to_pool();
                }
            }
            _ = cancel_future => {
                // Cancellation occurred
            }
        }

        crate::time::sleep(Time::ZERO,Time::ZERO,Duration::from_millis(50)).await;
        let final_stats = pool.stats();

        // Pool accounting should remain valid despite cancellation
        assert_eq!(final_stats.active + final_stats.idle, final_stats.total,
            "Pool accounting broken by cancellation");

        crate::test_complete!("mr_cancel_safety_invariance");
    }

    /// MR3: Return vs Drop Equivalence (Equivalence)
    /// Property: Explicitly returning vs dropping should yield same pool state
    #[tokio::test]
    async fn mr_return_vs_drop_equivalence() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("mr_return_vs_drop_equivalence");

        let config = PoolConfig::default().max_size(2);

        // Scenario 1: Explicit return
        let factory1 = MockFactory::new(Duration::from_millis(1));
        let pool1 = GenericPool::new(factory1, config.clone());

        let cx = Cx::root();
        let resource1 = pool1.acquire(&cx).await.unwrap();
        resource1.return_to_pool(); // Explicit return
        crate::time::sleep(Time::ZERO,Time::ZERO,Duration::from_millis(10)).await;
        let stats1 = pool1.stats();

        // Scenario 2: Drop return
        let factory2 = MockFactory::new(Duration::from_millis(1));
        let pool2 = GenericPool::new(factory2, config);

        let resource2 = pool2.acquire(&cx).await.unwrap();
        drop(resource2); // Implicit return via Drop
        crate::time::sleep(Time::ZERO,Time::ZERO,Duration::from_millis(10)).await;
        let stats2 = pool2.stats();

        // Both should result in equivalent pool states
        assert_eq!(stats1.active, stats2.active, "Active count differs between return methods");
        assert_eq!(stats1.active + stats1.idle, stats1.total);
        assert_eq!(stats2.active + stats2.idle, stats2.total);
        assert_eq!(stats1.active, 0, "Resource not returned properly (explicit)");
        assert_eq!(stats2.active, 0, "Resource not returned properly (drop)");

        crate::test_complete!("mr_return_vs_drop_equivalence");
    }

    /// MR4: Discard vs Return Counting (Multiplicative)
    /// Property: Discarding should reduce total count compared to returning
    #[tokio::test]
    async fn mr_discard_vs_return_counting() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("mr_discard_vs_return_counting");

        let config = PoolConfig::default().max_size(3);

        // Scenario 1: Return resources
        let factory1 = MockFactory::new(Duration::from_millis(1));
        let pool1 = GenericPool::new(factory1, config.clone());

        let cx = Cx::root();
        let resource1 = pool1.acquire(&cx).await.unwrap();
        resource1.return_to_pool();
        crate::time::sleep(Time::ZERO,Time::ZERO,Duration::from_millis(10)).await;
        let stats_return = pool1.stats();

        // Scenario 2: Discard resources
        let factory2 = MockFactory::new(Duration::from_millis(1));
        let pool2 = GenericPool::new(factory2, config);

        let resource2 = pool2.acquire(&cx).await.unwrap();
        resource2.discard(); // Discard instead of return
        crate::time::sleep(Time::ZERO,Time::ZERO,Duration::from_millis(10)).await;
        let stats_discard = pool2.stats();

        // Discarding should result in lower or equal total compared to returning
        assert!(stats_discard.total <= stats_return.total,
            "Discard should not increase total: discard_total={}, return_total={}",
            stats_discard.total, stats_return.total);

        // Accounting should be valid in both cases
        assert_eq!(stats_return.active + stats_return.idle, stats_return.total);
        assert_eq!(stats_discard.active + stats_discard.idle, stats_discard.total);

        crate::test_complete!("mr_discard_vs_return_counting");
    }

    /// MR5: Hold Duration Invariance (Equivalence)
    /// Property: Pool correctness independent of hold duration
    #[tokio::test]
    async fn mr_hold_duration_invariance() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("mr_hold_duration_invariance");

        let config = PoolConfig::default().max_size(2);

        // Scenario 1: Short hold
        let factory1 = MockFactory::new(Duration::from_millis(1));
        let pool1 = GenericPool::new(factory1, config.clone());

        let cx = Cx::root();
        let resource1 = pool1.acquire(&cx).await.unwrap();
        crate::time::sleep(Time::ZERO,Time::ZERO,Duration::from_millis(5)).await; // Short hold
        resource1.return_to_pool();
        crate::time::sleep(Time::ZERO,Time::ZERO,Duration::from_millis(10)).await;
        let stats_short = pool1.stats();

        // Scenario 2: Long hold
        let factory2 = MockFactory::new(Duration::from_millis(1));
        let pool2 = GenericPool::new(factory2, config);

        let resource2 = pool2.acquire(&cx).await.unwrap();
        crate::time::sleep(Time::ZERO,Time::ZERO,Duration::from_millis(50)).await; // Long hold
        resource2.return_to_pool();
        crate::time::sleep(Time::ZERO,Time::ZERO,Duration::from_millis(10)).await;
        let stats_long = pool2.stats();

        // Pool correctness should be independent of hold duration
        assert_eq!(stats_short.active + stats_short.idle, stats_short.total);
        assert_eq!(stats_long.active + stats_long.idle, stats_long.total);
        assert_eq!(stats_short.active, 0, "Resource not returned after short hold");
        assert_eq!(stats_long.active, 0, "Resource not returned after long hold");

        crate::test_complete!("mr_hold_duration_invariance");
    }

    /// MR6: Composite Operation Sequence (Multiplicative Power)
    /// Property: Complex sequences should maintain all invariants
    #[tokio::test]
    async fn mr_composite_operation_sequence() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("mr_composite_operation_sequence");

        let config = PoolConfig::default().max_size(3).min_size(1);
        let factory = MockFactory::new(Duration::from_millis(2));
        let pool = GenericPool::new(factory, config);

        // Execute a complex sequence: acquire, hold, return, try_acquire, discard
        let operations = vec![
            PoolOperation::Acquire { hold_ms: 10 },
            PoolOperation::TryAcquire { hold_ms: 5 },
            PoolOperation::AcquireWithCancel { hold_ms: 20, cancel_after_ms: 5 },
            PoolOperation::Acquire { hold_ms: 15 },
        ];

        let initial_stats = pool.stats();
        assert_eq!(initial_stats.active + initial_stats.idle, initial_stats.total);

        let _results = execute_operations(&pool, &operations).await;

        // Allow all async processing to complete
        crate::time::sleep(Time::ZERO,Time::ZERO,Duration::from_millis(100)).await;

        let final_stats = pool.stats();

        // All invariants must hold after complex operations
        assert_eq!(final_stats.active + final_stats.idle, final_stats.total,
            "Pool accounting violated after composite operations");

        assert!(final_stats.active >= 0 && final_stats.idle >= 0 && final_stats.total >= 0,
            "Negative counts detected: active={}, idle={}, total={}",
            final_stats.active, final_stats.idle, final_stats.total);

        assert!(final_stats.total <= config.max_size,
            "Pool exceeded max_size: total={}, max={}",
            final_stats.total, config.max_size);

        crate::test_complete!("mr_composite_operation_sequence");
    }
}