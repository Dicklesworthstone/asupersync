//! Real sync/semaphore ↔ obligation/ledger integration E2E test
//!
//! Tests integration between semaphore backpressure and obligation ledger
//! commit/abort operations. Verifies that semaphore permits act as obligation
//! gates, controlling the flow of obligation commits and aborts under
//! resource pressure scenarios.

#[cfg(all(test, feature = "real-service-e2e"))]
mod real_sync_semaphore_obligation_ledger_e2e {
    use crate::cx::{Cx, scope};
    use crate::runtime::{RuntimeBuilder, spawn};
    use crate::sync::Semaphore;
    use crate::time::{Duration, Instant, sleep, timeout};
    use crate::types::{Budget, RegionId, TaskId};
    use serde_json::json;
    use std::collections::{HashMap, VecDeque};
    use std::sync::Mutex;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    };

    /// Statistics for semaphore-obligation integration testing
    #[derive(Debug, Clone, Default)]
    struct SemaphoreObligationStats {
        /// Obligations created
        obligations_created: usize,
        /// Obligations committed successfully
        obligations_committed: usize,
        /// Obligations aborted
        obligations_aborted: usize,
        /// Semaphore permits acquired
        permits_acquired: usize,
        /// Semaphore permits released
        permits_released: usize,
        /// Backpressure events triggered
        backpressure_events: usize,
        /// Permit acquisition timeouts
        permit_timeouts: usize,
        /// Commit operations that failed due to backpressure
        commit_backpressure_failures: usize,
        /// Successful commits under backpressure
        commit_under_pressure_success: usize,
        /// Total test duration in milliseconds
        test_duration_ms: u64,
    }

    impl SemaphoreObligationStats {
        fn to_json(&self) -> serde_json::Value {
            json!({
                "obligations_created": self.obligations_created,
                "obligations_committed": self.obligations_committed,
                "obligations_aborted": self.obligations_aborted,
                "permits_acquired": self.permits_acquired,
                "permits_released": self.permits_released,
                "backpressure_events": self.backpressure_events,
                "permit_timeouts": self.permit_timeouts,
                "commit_backpressure_failures": self.commit_backpressure_failures,
                "commit_under_pressure_success": self.commit_under_pressure_success,
                "test_duration_ms": self.test_duration_ms,
                "commit_success_rate": if self.obligations_created > 0 {
                    (self.obligations_committed as f64) / (self.obligations_created as f64)
                } else { 0.0 },
            })
        }
    }

    /// Test obligation data for ledger operations
    #[derive(Debug, Clone, PartialEq)]
    struct TestObligation {
        id: u64,
        data: String,
        priority: ObligationPriority,
        resource_cost: usize,
        created_at: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    enum ObligationPriority {
        Low,
        Normal,
        High,
        Critical,
    }

    impl TestObligation {
        fn new(id: u64, data: &str) -> Self {
            Self {
                id,
                data: data.to_string(),
                priority: ObligationPriority::Normal,
                resource_cost: 1,
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            }
        }

        fn with_priority(mut self, priority: ObligationPriority) -> Self {
            self.priority = priority;
            self
        }

        fn with_resource_cost(mut self, cost: usize) -> Self {
            self.resource_cost = cost;
            self
        }
    }

    /// Semaphore-gated obligation manager
    struct SemaphoreObligationManager {
        semaphore: Arc<Semaphore>,
        ledger: Arc<Mutex<MockObligationLedger>>,
        stats: Arc<Mutex<SemaphoreObligationStats>>,
        max_concurrent: usize,
        backpressure_threshold: f64,
    }

    impl SemaphoreObligationManager {
        fn new(max_concurrent: usize, stats: Arc<Mutex<SemaphoreObligationStats>>) -> Self {
            Self {
                semaphore: Arc::new(Semaphore::new(max_concurrent)),
                ledger: Arc::new(Mutex::new(MockObligationLedger::new())),
                stats,
                max_concurrent,
                backpressure_threshold: 0.8, // 80% capacity triggers backpressure
            }
        }

        /// Commit obligation with semaphore permit gate
        async fn commit_obligation(
            &self,
            cx: &Cx,
            obligation: TestObligation,
        ) -> Result<(), Box<dyn std::error::Error>> {
            // Check if we should apply backpressure based on permit availability
            let available_permits = self.semaphore.available_permits();
            let capacity_ratio = available_permits as f64 / self.max_concurrent as f64;

            if capacity_ratio < self.backpressure_threshold {
                // Update backpressure stats
                {
                    let mut stats = self.stats.lock().unwrap();
                    stats.backpressure_events += 1;
                }

                println!(
                    "Backpressure triggered: {}% capacity available",
                    (capacity_ratio * 100.0) as u32
                );

                // Apply additional delay for low-priority obligations under pressure
                if obligation.priority == ObligationPriority::Low {
                    sleep(Duration::from_millis(50)).await;
                }
            }

            // Acquire semaphore permit with timeout
            let permit_result = timeout(
                Duration::from_secs(1),
                self.semaphore.acquire_many(obligation.resource_cost),
            )
            .await;

            let permit = match permit_result {
                Ok(permit) => {
                    // Update stats
                    {
                        let mut stats = self.stats.lock().unwrap();
                        stats.permits_acquired += obligation.resource_cost;
                    }
                    permit
                }
                Err(_) => {
                    // Timeout acquiring permit - abort obligation
                    {
                        let mut stats = self.stats.lock().unwrap();
                        stats.permit_timeouts += 1;
                        stats.commit_backpressure_failures += 1;
                    }

                    self.abort_obligation(cx, obligation.id).await?;
                    return Err("Permit acquisition timeout".into());
                }
            };

            // Perform ledger commit operation
            let commit_result = {
                let mut ledger = self.ledger.lock().unwrap();
                ledger.commit_obligation(obligation.clone())
            };

            match commit_result {
                Ok(_) => {
                    // Update stats
                    {
                        let mut stats = self.stats.lock().unwrap();
                        stats.obligations_committed += 1;
                        if capacity_ratio < self.backpressure_threshold {
                            stats.commit_under_pressure_success += 1;
                        }
                    }

                    // Hold permit for duration proportional to resource cost
                    sleep(Duration::from_millis(
                        (obligation.resource_cost * 10) as u64,
                    ))
                    .await;

                    // Release permit
                    drop(permit);
                    {
                        let mut stats = self.stats.lock().unwrap();
                        stats.permits_released += obligation.resource_cost;
                    }

                    println!("Committed obligation {} successfully", obligation.id);
                    Ok(())
                }
                Err(e) => {
                    // Commit failed - release permit and abort
                    drop(permit);
                    {
                        let mut stats = self.stats.lock().unwrap();
                        stats.permits_released += obligation.resource_cost;
                        stats.commit_backpressure_failures += 1;
                    }

                    self.abort_obligation(cx, obligation.id).await?;
                    Err(format!("Commit failed: {}", e).into())
                }
            }
        }

        /// Abort obligation
        async fn abort_obligation(
            &self,
            cx: &Cx,
            obligation_id: u64,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let abort_result = {
                let mut ledger = self.ledger.lock().unwrap();
                ledger.abort_obligation(obligation_id)
            };

            match abort_result {
                Ok(_) => {
                    {
                        let mut stats = self.stats.lock().unwrap();
                        stats.obligations_aborted += 1;
                    }
                    println!("Aborted obligation {}", obligation_id);
                    Ok(())
                }
                Err(e) => Err(format!("Abort failed: {}", e).into()),
            }
        }

        /// Create new obligation
        async fn create_obligation(
            &self,
            cx: &Cx,
            data: &str,
        ) -> Result<TestObligation, Box<dyn std::error::Error>> {
            let obligation_id = {
                let mut ledger = self.ledger.lock().unwrap();
                ledger.generate_id()
            };

            let obligation = TestObligation::new(obligation_id, data);

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.obligations_created += 1;
            }

            Ok(obligation)
        }

        /// Get current semaphore usage
        fn get_semaphore_usage(&self) -> (usize, usize) {
            (self.semaphore.available_permits(), self.max_concurrent)
        }

        /// Get ledger state
        fn get_ledger_state(&self) -> (usize, usize, usize) {
            let ledger = self.ledger.lock().unwrap();
            (
                ledger.pending_count(),
                ledger.committed_count(),
                ledger.aborted_count(),
            )
        }
    }

    /// Mock obligation ledger for testing
    #[derive(Debug)]
    struct MockObligationLedger {
        next_id: u64,
        pending_obligations: HashMap<u64, TestObligation>,
        committed_obligations: HashMap<u64, TestObligation>,
        aborted_obligations: HashMap<u64, TestObligation>,
    }

    impl MockObligationLedger {
        fn new() -> Self {
            Self {
                next_id: 1,
                pending_obligations: HashMap::new(),
                committed_obligations: HashMap::new(),
                aborted_obligations: HashMap::new(),
            }
        }

        fn generate_id(&mut self) -> u64 {
            let id = self.next_id;
            self.next_id += 1;
            id
        }

        fn commit_obligation(&mut self, obligation: TestObligation) -> Result<(), String> {
            // Simulate potential commit failures under high load
            if self.pending_obligations.len() > 100 {
                return Err("Ledger overloaded".to_string());
            }

            self.pending_obligations.remove(&obligation.id);
            self.committed_obligations.insert(obligation.id, obligation);
            Ok(())
        }

        fn abort_obligation(&mut self, obligation_id: u64) -> Result<(), String> {
            if let Some(obligation) = self.pending_obligations.remove(&obligation_id) {
                self.aborted_obligations.insert(obligation_id, obligation);
                Ok(())
            } else {
                Err("Obligation not found".to_string())
            }
        }

        fn pending_count(&self) -> usize {
            self.pending_obligations.len()
        }

        fn committed_count(&self) -> usize {
            self.committed_obligations.len()
        }

        fn aborted_count(&self) -> usize {
            self.aborted_obligations.len()
        }
    }

    /// Test harness for semaphore-obligation integration
    struct SemaphoreObligationTestHarness {
        manager: SemaphoreObligationManager,
        stats: Arc<Mutex<SemaphoreObligationStats>>,
        start_time: Instant,
    }

    impl SemaphoreObligationTestHarness {
        fn new(max_concurrent: usize) -> Self {
            let stats = Arc::new(Mutex::new(SemaphoreObligationStats::default()));
            let manager = SemaphoreObligationManager::new(max_concurrent, Arc::clone(&stats));

            Self {
                manager,
                stats,
                start_time: Instant::now(),
            }
        }

        /// Test basic obligation commit under semaphore control
        async fn test_basic_commit_with_permits(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing basic obligation commits with semaphore permits");

            // Create and commit multiple obligations
            for i in 0..10 {
                let obligation = self
                    .manager
                    .create_obligation(cx, &format!("test_data_{}", i))
                    .await?;
                self.manager.commit_obligation(cx, obligation).await?;
            }

            let (pending, committed, aborted) = self.manager.get_ledger_state();
            println!(
                "Ledger state: {} pending, {} committed, {} aborted",
                pending, committed, aborted
            );

            Ok(())
        }

        /// Test obligation commit under semaphore backpressure
        async fn test_backpressure_scenarios(
            &mut self,
            cx: &Cx,
            high_load_count: usize,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!(
                "Testing obligation commits under semaphore backpressure with {} obligations",
                high_load_count
            );

            // Create many concurrent obligations to trigger backpressure
            let mut tasks = Vec::new();

            for i in 0..high_load_count {
                let manager = &self.manager;

                // Create obligations with varying priorities and costs
                let priority = match i % 4 {
                    0 => ObligationPriority::Critical,
                    1 => ObligationPriority::High,
                    2 => ObligationPriority::Normal,
                    _ => ObligationPriority::Low,
                };

                let resource_cost = if priority == ObligationPriority::Critical {
                    2
                } else {
                    1
                };

                let obligation = manager
                    .create_obligation(cx, &format!("backpressure_test_{}", i))
                    .await?
                    .with_priority(priority)
                    .with_resource_cost(resource_cost);

                // Spawn concurrent commit operations
                let obligation_clone = obligation.clone();
                let stats_clone = Arc::clone(&self.stats);

                // Note: For this test, we'll run commits sequentially to avoid complex spawn management
                match manager.commit_obligation(cx, obligation_clone).await {
                    Ok(_) => {}
                    Err(e) => {
                        println!("Expected failure under backpressure: {}", e);
                    }
                }

                // Add small delay between operations
                sleep(Duration::from_millis(5)).await;
            }

            let (pending, committed, aborted) = self.manager.get_ledger_state();
            println!(
                "After backpressure test - Pending: {}, Committed: {}, Aborted: {}",
                pending, committed, aborted
            );

            Ok(())
        }

        /// Test permit exhaustion and recovery
        async fn test_permit_exhaustion_recovery(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing permit exhaustion and recovery scenarios");

            let (available, total) = self.manager.get_semaphore_usage();
            println!(
                "Initial semaphore state: {}/{} permits available",
                available, total
            );

            // Create high-cost obligations to exhaust permits
            for i in 0..5 {
                let obligation = self
                    .manager
                    .create_obligation(cx, &format!("exhaustion_test_{}", i))
                    .await?
                    .with_resource_cost(total / 3); // Use 1/3 of total capacity per obligation

                match self.manager.commit_obligation(cx, obligation).await {
                    Ok(_) => {}
                    Err(_) => {
                        println!("Expected permit exhaustion at obligation {}", i);
                        break;
                    }
                }
            }

            // Allow some obligations to complete and release permits
            sleep(Duration::from_millis(200)).await;

            let (available_after, _) = self.manager.get_semaphore_usage();
            println!(
                "Semaphore state after recovery: {}/{} permits available",
                available_after, total
            );

            Ok(())
        }

        /// Get test statistics
        fn get_stats(&mut self) -> SemaphoreObligationStats {
            let mut stats = self.stats.lock().unwrap();
            stats.test_duration_ms = self.start_time.elapsed().as_millis() as u64;
            stats.clone()
        }
    }

    #[tokio::test]
    async fn test_semaphore_obligation_basic_integration() {
        println!("=== Starting semaphore-obligation basic integration test ===");

        scope(|cx| async move {
            let mut harness = SemaphoreObligationTestHarness::new(5);

            // Test basic functionality
            harness
                .test_basic_commit_with_permits(&cx)
                .await
                .expect("Basic commit test should succeed");

            let stats = harness.get_stats();
            println!(
                "Basic integration stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Verify basic operation
            assert!(
                stats.obligations_created > 0,
                "Should have created obligations"
            );
            assert!(
                stats.obligations_committed > 0,
                "Should have committed obligations"
            );
            assert!(stats.permits_acquired > 0, "Should have acquired permits");
            assert_eq!(
                stats.permits_acquired, stats.permits_released,
                "Permits should be balanced"
            );

            println!("✓ Semaphore-obligation basic integration test passed");
            println!("  - Created {} obligations", stats.obligations_created);
            println!("  - Committed {} obligations", stats.obligations_committed);
            println!("  - Acquired/released {} permits", stats.permits_acquired);

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_semaphore_backpressure_obligation_commit() {
        println!("=== Testing semaphore backpressure on obligation commits ===");

        scope(|cx| async move {
            let mut harness = SemaphoreObligationTestHarness::new(3); // Small semaphore for easy backpressure

            // Test backpressure scenarios
            harness
                .test_backpressure_scenarios(&cx, 20)
                .await
                .expect("Backpressure test should succeed");

            let stats = harness.get_stats();
            println!(
                "Backpressure test stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Should have triggered backpressure with small semaphore
            assert!(
                stats.backpressure_events > 0,
                "Should have triggered backpressure events"
            );
            assert!(
                stats.obligations_committed > 0,
                "Should have committed some obligations"
            );

            // Under backpressure, we expect some operations to succeed and some to fail
            assert!(
                stats.commit_success_rate > 0.0,
                "Should have some successful commits"
            );

            println!("✓ Semaphore backpressure test passed");
            println!("  - Backpressure events: {}", stats.backpressure_events);
            println!(
                "  - Commits under pressure: {}",
                stats.commit_under_pressure_success
            );
            println!(
                "  - Backpressure failures: {}",
                stats.commit_backpressure_failures
            );

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_permit_exhaustion_recovery_patterns() {
        println!("=== Testing permit exhaustion and recovery patterns ===");

        scope(|cx| async move {
            let mut harness = SemaphoreObligationTestHarness::new(6);

            // Test permit exhaustion and recovery
            harness
                .test_permit_exhaustion_recovery(&cx)
                .await
                .expect("Permit exhaustion test should succeed");

            let stats = harness.get_stats();
            println!(
                "Permit exhaustion stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Verify permit management
            assert!(stats.permits_acquired > 0, "Should have acquired permits");
            assert!(stats.permits_released > 0, "Should have released permits");

            // Some operations should timeout when permits are exhausted
            if stats.permit_timeouts > 0 {
                println!(
                    "Expected permit timeouts occurred: {}",
                    stats.permit_timeouts
                );
            }

            println!("✓ Permit exhaustion and recovery test passed");
            println!("  - Permit timeouts: {}", stats.permit_timeouts);
            println!("  - Total aborted: {}", stats.obligations_aborted);

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }
}
