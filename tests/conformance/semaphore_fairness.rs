//! Conformance test for semaphore fairness ordering vs tokio::sync::Semaphore.
//!
//! Tests that asupersync::sync::Semaphore and tokio::sync::Semaphore produce
//! identical fairness ordering when given:
//! - Same N permits
//! - Same K acquirers in same order
//! - Same permit request sizes
//!
//! Verifies FIFO fairness property holds across both implementations.

use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use tokio::sync::Barrier;
use tokio::time::timeout;

use asupersync::sync::Semaphore as AsupersyncSemaphore;
use asupersync::cx::Cx;
use asupersync::runtime::{Runtime, RuntimeConfig};
use asupersync::types::Budget;

/// Maximum wait time for semaphore operations to prevent test hangs.
const MAX_WAIT: Duration = Duration::from_secs(10);

/// Result of a semaphore acquire operation with timing info.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AcquireResult {
    acquirer_id: usize,
    permit_count: usize,
    grant_order: usize,
    start_time: Duration,
    grant_time: Duration,
}

/// Configuration for a single fairness test case.
#[derive(Debug, Clone)]
struct FairnessTestCase {
    name: &'static str,
    permit_count: usize,
    acquirer_requests: Vec<(usize, usize)>, // (acquirer_id, permit_count)
    description: &'static str,
}

/// Test harness for differential fairness testing.
struct FairnessHarness {
    test_start: Instant,
}

impl FairnessHarness {
    fn new() -> Self {
        Self {
            test_start: Instant::now(),
        }
    }

    /// Run asupersync semaphore test scenario.
    async fn run_asupersync_test(&self, case: &FairnessTestCase) -> Result<Vec<AcquireResult>, String> {
        let runtime = Runtime::builder()
            .with_config(RuntimeConfig::default())
            .build()
            .map_err(|e| format!("Failed to build runtime: {}", e))?;

        runtime.run(|cx| async move {
            let sem = Arc::new(AsupersyncSemaphore::new(case.permit_count));
            let barrier = Arc::new(Barrier::new(case.acquirer_requests.len() + 1));
            let results = Arc::new(tokio::sync::Mutex::new(Vec::new()));
            let grant_counter = Arc::new(tokio::sync::Mutex::new(0usize));

            let mut handles = Vec::new();

            // Spawn acquirer tasks
            for (acquirer_id, permit_count) in &case.acquirer_requests {
                let sem = sem.clone();
                let barrier = barrier.clone();
                let results = results.clone();
                let grant_counter = grant_counter.clone();
                let acquirer_id = *acquirer_id;
                let permit_count = *permit_count;
                let test_start = self.test_start;

                let handle = tokio::spawn(async move {
                    // Wait for all acquirers to be ready
                    let _ = barrier.wait().await;

                    let start_time = test_start.elapsed();

                    // Create minimal Cx for asupersync semaphore
                    let budget = Budget::new(Duration::from_secs(5));
                    let cx = Cx::new_test(budget);

                    // Acquire permits
                    let _permit = timeout(MAX_WAIT, sem.acquire(&cx, permit_count))
                        .await
                        .map_err(|_| "Timeout waiting for permit")?
                        .map_err(|e| format!("Acquire failed: {:?}", e))?;

                    let grant_time = test_start.elapsed();

                    // Record result
                    let mut counter = grant_counter.lock().await;
                    let grant_order = *counter;
                    *counter += 1;

                    let result = AcquireResult {
                        acquirer_id,
                        permit_count,
                        grant_order,
                        start_time,
                        grant_time,
                    };

                    results.lock().await.push(result);

                    Ok::<(), String>(())
                });

                handles.push(handle);
            }

            // Release all acquirers simultaneously
            let _ = barrier.wait().await;

            // Wait for all acquirers to complete
            for handle in handles {
                if let Err(e) = handle.await {
                    return Err(format!("Acquirer task failed: {:?}", e));
                }
            }

            let mut results = results.lock().await;
            results.sort_by_key(|r| r.grant_order);
            Ok(results.clone())
        }).await
    }

    /// Run tokio semaphore test scenario.
    async fn run_tokio_test(&self, case: &FairnessTestCase) -> Result<Vec<AcquireResult>, String> {
        let sem = Arc::new(tokio::sync::Semaphore::new(case.permit_count));
        let barrier = Arc::new(Barrier::new(case.acquirer_requests.len() + 1));
        let results = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let grant_counter = Arc::new(tokio::sync::Mutex::new(0usize));

        let mut handles = Vec::new();

        // Spawn acquirer tasks
        for (acquirer_id, permit_count) in &case.acquirer_requests {
            let sem = sem.clone();
            let barrier = barrier.clone();
            let results = results.clone();
            let grant_counter = grant_counter.clone();
            let acquirer_id = *acquirer_id;
            let permit_count = *permit_count;
            let test_start = self.test_start;

            let handle = tokio::spawn(async move {
                // Wait for all acquirers to be ready
                let _ = barrier.wait().await;

                let start_time = test_start.elapsed();

                // Acquire permits
                let _permit = timeout(MAX_WAIT, sem.acquire_many(permit_count as u32))
                    .await
                    .map_err(|_| "Timeout waiting for permit")?
                    .map_err(|e| format!("Acquire failed: {:?}", e))?;

                let grant_time = test_start.elapsed();

                // Record result
                let mut counter = grant_counter.lock().await;
                let grant_order = *counter;
                *counter += 1;

                let result = AcquireResult {
                    acquirer_id,
                    permit_count,
                    grant_order,
                    start_time,
                    grant_time,
                };

                results.lock().await.push(result);

                Ok::<(), String>(())
            });

            handles.push(handle);
        }

        // Release all acquirers simultaneously
        let _ = barrier.wait().await;

        // Wait for all acquirers to complete
        for handle in handles {
            if let Err(e) = handle.await {
                return Err(format!("Acquirer task failed: {:?}", e));
            }
        }

        let mut results = results.lock().await;
        results.sort_by_key(|r| r.grant_order);
        Ok(results.clone())
    }

    /// Compare fairness ordering between implementations.
    fn compare_fairness(&self, case: &FairnessTestCase,
                       asupersync_results: &[AcquireResult],
                       tokio_results: &[AcquireResult]) -> Result<(), String> {

        if asupersync_results.len() != tokio_results.len() {
            return Err(format!(
                "Result count mismatch: asupersync={}, tokio={}",
                asupersync_results.len(), tokio_results.len()
            ));
        }

        if asupersync_results.len() != case.acquirer_requests.len() {
            return Err(format!(
                "Expected {} results, got {}",
                case.acquirer_requests.len(), asupersync_results.len()
            ));
        }

        // Compare grant ordering
        for (i, (asup, tokio)) in asupersync_results.iter().zip(tokio_results.iter()).enumerate() {
            if asup.acquirer_id != tokio.acquirer_id {
                return Err(format!(
                    "Fairness ordering divergence at position {}: \
                     asupersync granted acquirer {} first, \
                     tokio granted acquirer {} first",
                    i, asup.acquirer_id, tokio.acquirer_id
                ));
            }

            if asup.permit_count != tokio.permit_count {
                return Err(format!(
                    "Permit count mismatch for acquirer {} at position {}: \
                     asupersync={}, tokio={}",
                    asup.acquirer_id, i, asup.permit_count, tokio.permit_count
                ));
            }
        }

        Ok(())
    }

    /// Run complete fairness conformance test.
    async fn run_fairness_test(&self, case: &FairnessTestCase) -> Result<(), String> {
        println!("Running fairness test: {}", case.name);
        println!("  Permits: {}", case.permit_count);
        println!("  Acquirers: {:?}", case.acquirer_requests);

        // Run both implementations
        let asupersync_results = self.run_asupersync_test(case).await
            .map_err(|e| format!("Asupersync test failed: {}", e))?;

        let tokio_results = self.run_tokio_test(case).await
            .map_err(|e| format!("Tokio test failed: {}", e))?;

        // Compare results
        self.compare_fairness(case, &asupersync_results, &tokio_results)?;

        println!("  ✓ PASS - Fairness ordering matches");
        Ok(())
    }
}

/// Test cases covering various fairness scenarios.
fn fairness_test_cases() -> Vec<FairnessTestCase> {
    vec![
        FairnessTestCase {
            name: "basic_fifo_1_permit",
            permit_count: 1,
            acquirer_requests: vec![(0, 1), (1, 1), (2, 1)],
            description: "3 acquirers competing for 1 permit - FIFO order",
        },
        FairnessTestCase {
            name: "multiple_permits",
            permit_count: 5,
            acquirer_requests: vec![(0, 2), (1, 1), (2, 3), (3, 1)],
            description: "Mixed permit sizes with sufficient capacity",
        },
        FairnessTestCase {
            name: "oversubscribed",
            permit_count: 3,
            acquirer_requests: vec![(0, 2), (1, 2), (2, 2), (3, 1)],
            description: "More permit requests than capacity - FIFO blocking",
        },
        FairnessTestCase {
            name: "single_large_request",
            permit_count: 5,
            acquirer_requests: vec![(0, 5), (1, 1), (2, 1)],
            description: "Large request blocks smaller ones until released",
        },
        FairnessTestCase {
            name: "many_acquirers",
            permit_count: 2,
            acquirer_requests: (0..10).map(|i| (i, 1)).collect(),
            description: "High contention scenario with 10 acquirers",
        },
        FairnessTestCase {
            name: "exact_capacity",
            permit_count: 6,
            acquirer_requests: vec![(0, 2), (1, 2), (2, 2)],
            description: "Requests exactly match total capacity",
        },
    ]
}

#[tokio::test]
async fn test_semaphore_fairness_conformance() {
    let harness = FairnessHarness::new();

    for case in fairness_test_cases() {
        if let Err(e) = harness.run_fairness_test(&case).await {
            panic!("Fairness test '{}' failed: {}", case.name, e);
        }
    }

    println!("All semaphore fairness tests passed! ✓");
}

#[tokio::test]
async fn test_acquisition_order_deterministic() {
    let harness = FairnessHarness::new();
    let case = FairnessTestCase {
        name: "deterministic_order",
        permit_count: 2,
        acquirer_requests: vec![(100, 1), (200, 1), (300, 1), (400, 1)],
        description: "Specific acquirer IDs to verify ordering",
    };

    // Run the test multiple times to verify consistency
    for run in 0..3 {
        println!("Deterministic test run {}", run + 1);
        if let Err(e) = harness.run_fairness_test(&case).await {
            panic!("Deterministic test run {} failed: {}", run + 1, e);
        }
    }
}

/// Stress test with rapid acquire/release cycles.
#[tokio::test]
async fn test_fairness_under_load() {
    let harness = FairnessHarness::new();
    let case = FairnessTestCase {
        name: "load_test",
        permit_count: 3,
        acquirer_requests: (0..20).map(|i| (i, 1)).collect(),
        description: "20 acquirers competing for 3 permits",
    };

    if let Err(e) = harness.run_fairness_test(&case).await {
        panic!("Load test failed: {}", e);
    }
}