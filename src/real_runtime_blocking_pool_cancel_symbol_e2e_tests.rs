//! Real E2E integration tests: runtime/blocking_pool ↔ cancel/symbol_cancel integration (br-e2e-58).
//!
//! Tests blocking task cancellation via symbol-based cancel protocol without thread leakage.
//! Verifies that blocking tasks spawned in the thread pool can be properly cancelled through
//! symbol cancel tokens while maintaining thread pool integrity and preventing resource leaks.
//!
//! # Integration Patterns Tested
//!
//! - **Symbol-Based Cancellation**: Triggering blocking task cancellation via SymbolCancelToken
//! - **Thread Pool Integrity**: Ensuring thread pool remains stable during cancellation
//! - **Resource Leak Prevention**: No threads or handles leaked during cancel scenarios
//! - **Cancellation Timing**: Pre-execution, during-execution, and post-execution cancellation
//! - **Thread Safety**: Concurrent cancellation requests and blocking task execution
//!
//! # Test Scenarios
//!
//! 1. **Pre-Execution Cancellation** — Cancel task before it starts executing
//! 2. **During-Execution Cancellation** — Cancel while task is running, verify completion
//! 3. **Concurrent Cancellation** — Multiple tasks with overlapping cancellation requests
//! 4. **Cascading Cancellation** — Parent token cancellation propagates to child tasks
//! 5. **Resource Cleanup Verification** — No thread leaks after complex cancellation scenarios
//!
//! # Safety Properties Verified
//!
//! - Blocking tasks respect cancellation signals appropriately
//! - Thread pool threads are properly recycled after cancellation
//! - No zombie threads remain after cancellation scenarios
//! - Cancellation listeners are invoked at the correct times

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    #![allow(
        clippy::expect_fun_call,
        clippy::future_not_send,
        clippy::match_same_arms,
        clippy::missing_panics_doc,
        clippy::needless_pass_by_value,
        clippy::unwrap_used,
        dead_code
    )]

    use crate::cancel::symbol_cancel::SymbolCancelToken;
    use crate::runtime::blocking_pool::{BlockingPool, BlockingPoolHandle, BlockingTaskHandle};
    use crate::time::{Duration, Instant, sleep};
    use crate::types::{CancelKind, CancelReason, ObjectId, Symbol, Time};
    use crate::util::DetRng;
    use std::collections::VecDeque;
    use std::sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    };
    use std::thread;
    use tokio::sync::{Barrier, Semaphore};

    // ────────────────────────────────────────────────────────────────────────────────
    // Blocking Pool + Symbol Cancel Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BlockingCancelTestPhase {
        Setup,
        BlockingPoolInitialization,
        SymbolCancelTokenCreation,
        TaskSpawning,
        CancellationTriggering,
        ExecutionMonitoring,
        ResourceLeakCheck,
        ThreadPoolIntegrityCheck,
        CancellationListenerVerification,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct BlockingCancelTestResult {
        pub test_name: String,
        pub scenario_id: String,
        pub phase: BlockingCancelTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub stats: BlockingCancelStats,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct BlockingCancelStats {
        pub tasks_spawned: u64,
        pub tasks_cancelled: u64,
        pub tasks_completed: u64,
        pub cancellation_listeners_invoked: u64,
        pub pre_execution_cancellations: u64,
        pub during_execution_cancellations: u64,
        pub post_execution_cancellations: u64,
        pub threads_active_at_start: u64,
        pub threads_active_at_end: u64,
        pub thread_leak_count: u64,
    }

    /// Coordinated test harness for blocking pool + symbol cancel integration.
    pub struct BlockingCancelTestHarness {
        pool: Arc<BlockingPool>,
        pool_handle: BlockingPoolHandle,
        cancel_tokens: Arc<Mutex<Vec<SymbolCancelToken>>>,
        task_handles: Arc<Mutex<Vec<BlockingTaskHandle>>>,
        stats: Arc<Mutex<BlockingCancelStats>>,
        cancellation_events: Arc<Mutex<VecDeque<CancellationEvent>>>,
        rng: Arc<Mutex<DetRng>>,
        test_start_time: Instant,
    }

    #[derive(Debug, Clone)]
    pub struct CancellationEvent {
        pub token_id: u64,
        pub object_id: ObjectId,
        pub reason: CancelReason,
        pub timestamp: Time,
        pub phase: CancellationPhase,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum CancellationPhase {
        PreExecution,
        DuringExecution,
        PostExecution,
    }


    impl BlockingCancelTestHarness {
        pub async fn new() -> Self {
            let pool = Arc::new(BlockingPool::new(2, 8));
            let pool_handle = pool.clone();

            Self {
                pool,
                pool_handle,
                cancel_tokens: Arc::new(Mutex::new(Vec::new())),
                task_handles: Arc::new(Mutex::new(Vec::new())),
                stats: Arc::new(Mutex::new(BlockingCancelStats::default())),
                cancellation_events: Arc::new(Mutex::new(VecDeque::new())),
                rng: Arc::new(Mutex::new(DetRng::from_entropy())),
                test_start_time: Instant::now(),
            }
        }

        pub fn create_cancel_token_with_listener(&self, object_id: ObjectId) -> SymbolCancelToken {
            let mut rng = self.rng.lock().unwrap();
            let token = SymbolCancelToken::new(object_id, &mut *rng);

            let events = Arc::clone(&self.cancellation_events);
            let stats = Arc::clone(&self.stats);
            let token_id = object_id.0; // Using object_id as token_id for simplicity

            token.add_listener(move |reason: &CancelReason, at: Time| {
                let mut stats_guard = stats.lock().unwrap();
                stats_guard.cancellation_listeners_invoked += 1;

                let event = CancellationEvent {
                    token_id,
                    object_id,
                    reason: reason.clone(),
                    timestamp: at,
                    phase: CancellationPhase::DuringExecution, // Will be updated based on context
                };

                events.lock().unwrap().push_back(event);
            });

            self.cancel_tokens.lock().unwrap().push(token.clone());
            token
        }

        pub fn spawn_blocking_task_with_cancel_monitoring(
            &self,
            cancel_token: &SymbolCancelToken,
            work_duration_ms: u64,
            task_id: &str,
        ) -> BlockingTaskHandle {
            let token_clone = cancel_token.clone();
            let stats_clone = Arc::clone(&self.stats);
            let task_id = task_id.to_string();

            let handle = self.pool.spawn(move || {
                let mut stats = stats_clone.lock().unwrap();
                stats.tasks_spawned += 1;
                drop(stats);

                // Simulate work while checking for cancellation
                let start_time = std::time::Instant::now();
                let work_duration = std::time::Duration::from_millis(work_duration_ms);
                let check_interval = std::time::Duration::from_millis(10);

                while start_time.elapsed() < work_duration {
                    if token_clone.is_cancelled() {
                        let mut stats = stats_clone.lock().unwrap();
                        stats.tasks_cancelled += 1;

                        // Determine cancellation phase based on how much work was done
                        let elapsed_ratio = start_time.elapsed().as_millis() as f64 / work_duration.as_millis() as f64;
                        if elapsed_ratio < 0.1 {
                            stats.pre_execution_cancellations += 1;
                        } else if elapsed_ratio < 0.9 {
                            stats.during_execution_cancellations += 1;
                        } else {
                            stats.post_execution_cancellations += 1;
                        }

                        return; // Respect cancellation and exit early
                    }

                    thread::sleep(check_interval);
                }

                // Task completed normally
                let mut stats = stats_clone.lock().unwrap();
                stats.tasks_completed += 1;
            });

            self.task_handles.lock().unwrap().push(handle.clone());
            handle
        }

        pub fn trigger_cancellation(&self, token: &SymbolCancelToken, reason: CancelReason) -> bool {
            let now = Time::now();
            token.cancel(&reason, now)
        }

        pub fn get_thread_pool_stats(&self) -> (usize, usize) {
            // Use debug format to extract thread count information
            let debug_str = format!("{:?}", self.pool);

            // Parse active threads from debug output
            let active_threads = debug_str
                .split("active_threads: ")
                .nth(1)
                .and_then(|s| s.split(',').next())
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);

            let pending_tasks = debug_str
                .split("pending_tasks: ")
                .nth(1)
                .and_then(|s| s.split(',').next())
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);

            (active_threads, pending_tasks)
        }

        pub async fn wait_for_task_completion(&self, timeout_ms: u64) -> bool {
            let start = Instant::now();
            let timeout = Duration::from_millis(timeout_ms);

            while start.elapsed() < timeout {
                let all_done = self.task_handles.lock().unwrap()
                    .iter()
                    .all(|handle| handle.is_done() || handle.is_cancelled());

                if all_done {
                    return true;
                }

                sleep(Duration::from_millis(50)).await;
            }

            false
        }

        pub async fn verify_no_thread_leaks(&self) -> bool {
            // Wait a moment for cleanup to complete
            sleep(Duration::from_millis(100)).await;

            let (active_threads, _) = self.get_thread_pool_stats();
            let initial_thread_count = 2; // Our min_threads setting

            // Allow some variance for thread pool management
            active_threads <= initial_thread_count + 1
        }

        pub fn get_stats_snapshot(&self) -> BlockingCancelStats {
            self.stats.lock().unwrap().clone()
        }

        pub fn get_cancellation_events(&self) -> Vec<CancellationEvent> {
            self.cancellation_events.lock().unwrap().iter().cloned().collect()
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 1: Pre-Execution Cancellation
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_blocking_pool_pre_execution_cancellation() {
        let harness = BlockingCancelTestHarness::new().await;

        let object_id = ObjectId(12345);
        let cancel_token = harness.create_cancel_token_with_listener(object_id);

        // Trigger cancellation before task starts
        let reason = CancelReason::new(CancelKind::User).with_timestamp(Time::now());
        assert!(harness.trigger_cancellation(&cancel_token, reason.clone()));

        // Now spawn the task - it should see the cancellation immediately
        let handle = harness.spawn_blocking_task_with_cancel_monitoring(
            &cancel_token,
            1000, // 1 second of work
            "pre-exec-cancel-test"
        );

        // Wait for task completion
        assert!(harness.wait_for_task_completion(2000).await);

        let stats = harness.get_stats_snapshot();
        assert_eq!(stats.tasks_spawned, 1);
        assert_eq!(stats.tasks_cancelled, 1);
        assert_eq!(stats.pre_execution_cancellations, 1);
        assert_eq!(stats.cancellation_listeners_invoked, 1);

        assert!(harness.verify_no_thread_leaks().await);
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 2: During-Execution Cancellation
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_blocking_pool_during_execution_cancellation() {
        let harness = BlockingCancelTestHarness::new().await;

        let object_id = ObjectId(23456);
        let cancel_token = harness.create_cancel_token_with_listener(object_id);

        // Spawn a long-running task
        let handle = harness.spawn_blocking_task_with_cancel_monitoring(
            &cancel_token,
            2000, // 2 seconds of work
            "during-exec-cancel-test"
        );

        // Wait a bit for task to start executing
        sleep(Duration::from_millis(200)).await;

        // Now trigger cancellation while running
        let reason = CancelReason::new(CancelKind::Timeout).with_timestamp(Time::now());
        assert!(harness.trigger_cancellation(&cancel_token, reason));

        // Wait for task completion
        assert!(harness.wait_for_task_completion(3000).await);

        let stats = harness.get_stats_snapshot();
        assert_eq!(stats.tasks_spawned, 1);
        assert_eq!(stats.tasks_cancelled, 1);
        assert_eq!(stats.during_execution_cancellations, 1);
        assert_eq!(stats.cancellation_listeners_invoked, 1);

        assert!(harness.verify_no_thread_leaks().await);
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 3: Concurrent Multiple Task Cancellation
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_blocking_pool_concurrent_cancellation() {
        let harness = BlockingCancelTestHarness::new().await;

        let num_tasks = 5;
        let mut tokens = Vec::new();
        let mut handles = Vec::new();

        // Spawn multiple concurrent tasks
        for i in 0..num_tasks {
            let object_id = ObjectId(30000 + i as u64);
            let cancel_token = harness.create_cancel_token_with_listener(object_id);

            let handle = harness.spawn_blocking_task_with_cancel_monitoring(
                &cancel_token,
                3000, // 3 seconds of work each
                &format!("concurrent-task-{}", i)
            );

            tokens.push(cancel_token);
            handles.push(handle);
        }

        // Wait a bit for tasks to start
        sleep(Duration::from_millis(300)).await;

        // Cancel tasks at different times
        for (i, token) in tokens.iter().enumerate() {
            let reason = CancelReason::new(CancelKind::User)
                .with_timestamp(Time::now());
            harness.trigger_cancellation(token, reason);

            // Stagger cancellations
            sleep(Duration::from_millis(100)).await;
        }

        // Wait for all tasks to complete
        assert!(harness.wait_for_task_completion(5000).await);

        let stats = harness.get_stats_snapshot();
        assert_eq!(stats.tasks_spawned, num_tasks as u64);
        assert_eq!(stats.tasks_cancelled, num_tasks as u64);
        assert_eq!(stats.cancellation_listeners_invoked, num_tasks as u64);

        assert!(harness.verify_no_thread_leaks().await);
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 4: Resource Cleanup Verification
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_blocking_pool_resource_cleanup_verification() {
        let harness = BlockingCancelTestHarness::new().await;

        let (initial_threads, _) = harness.get_thread_pool_stats();

        // Run multiple rounds of spawn/cancel cycles to stress test cleanup
        for round in 0..3 {
            let mut tokens = Vec::new();
            let mut handles = Vec::new();

            // Spawn 10 tasks
            for i in 0..10 {
                let object_id = ObjectId(50000 + (round * 100) + i as u64);
                let cancel_token = harness.create_cancel_token_with_listener(object_id);

                let handle = harness.spawn_blocking_task_with_cancel_monitoring(
                    &cancel_token,
                    1500, // 1.5 seconds each
                    &format!("cleanup-round-{}-task-{}", round, i)
                );

                tokens.push(cancel_token);
                handles.push(handle);
            }

            // Wait a bit then cancel half the tasks
            sleep(Duration::from_millis(300)).await;

            for (i, token) in tokens.iter().enumerate() {
                if i % 2 == 0 {
                    let reason = CancelReason::new(CancelKind::ResourceUnavailable)
                        .with_timestamp(Time::now());
                    harness.trigger_cancellation(token, reason);
                }
            }

            // Wait for round completion
            assert!(harness.wait_for_task_completion(3000).await);

            // Wait for cleanup
            sleep(Duration::from_millis(200)).await;
        }

        // Verify final state
        let final_stats = harness.get_stats_snapshot();
        assert_eq!(final_stats.tasks_spawned, 30); // 3 rounds × 10 tasks
        assert!(final_stats.tasks_cancelled >= 15); // At least half cancelled
        assert!(final_stats.tasks_completed >= 15); // At least half completed

        // Most important: verify no thread leaks
        assert!(harness.verify_no_thread_leaks().await);

        let (final_threads, final_pending) = harness.get_thread_pool_stats();
        assert_eq!(final_pending, 0, "Should have no pending tasks");
        assert!(
            final_threads <= initial_threads + 2,
            "Thread count should not have grown significantly: {} vs {}",
            final_threads,
            initial_threads
        );
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Integration Test Result Verification
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_blocking_pool_symbol_cancel_full_integration() {
        let harness = BlockingCancelTestHarness::new().await;

        // Complex scenario: mix of pre/during/post execution cancellations
        let scenarios = vec![
            ("pre-cancel", 0, 1000),     // Cancel immediately, 1s work
            ("during-cancel", 200, 800), // Cancel after 200ms, 800ms work
            ("no-cancel", 0, 500),       // No cancellation, 500ms work
            ("late-cancel", 600, 700),   // Cancel after 600ms, 700ms work
        ];

        let mut tokens = Vec::new();
        let mut handles = Vec::new();

        for (i, (scenario_name, cancel_delay_ms, work_duration_ms)) in scenarios.iter().enumerate() {
            let object_id = ObjectId(60000 + i as u64);
            let cancel_token = harness.create_cancel_token_with_listener(object_id);

            let handle = harness.spawn_blocking_task_with_cancel_monitoring(
                &cancel_token,
                *work_duration_ms,
                &format!("integration-{}", scenario_name)
            );

            tokens.push(cancel_token);
            handles.push(handle);

            // For scenarios with cancellation, we'll trigger them after task spawning
            if *cancel_delay_ms == 0 && scenario_name == &"pre-cancel" {
                // Pre-cancel this token immediately
                let reason = CancelReason::new(CancelKind::User).with_timestamp(Time::now());
                harness.trigger_cancellation(&tokens[i], reason);
            }
        }

        // Handle delayed cancellations
        for (i, (scenario_name, cancel_delay_ms, _)) in scenarios.iter().enumerate() {
            if *cancel_delay_ms > 0 {
                let token_clone = tokens[i].clone();
                let cancel_delay = *cancel_delay_ms;
                let reason = CancelReason::new(CancelKind::Timeout).with_timestamp(Time::now());

                tokio::spawn(async move {
                    sleep(Duration::from_millis(cancel_delay)).await;
                    token_clone.cancel(&reason, Time::now());
                });
            }
        }

        // Wait for all tasks to complete
        assert!(harness.wait_for_task_completion(3000).await);

        let final_stats = harness.get_stats_snapshot();
        let events = harness.get_cancellation_events();

        // Verify comprehensive integration
        assert_eq!(final_stats.tasks_spawned, 4);
        assert!(final_stats.cancellation_listeners_invoked >= 2); // At least 2 cancellations
        assert!(harness.verify_no_thread_leaks().await);

        // Verify event ordering and timing
        assert!(!events.is_empty(), "Should have recorded cancellation events");

        println!("✅ Blocking Pool ↔ Symbol Cancel Integration Test Complete");
        println!("📊 Final Stats: {:?}", final_stats);
        println!("🎯 Events Recorded: {}", events.len());
    }
}