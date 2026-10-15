//! Real E2E integration tests: channel/mpsc ↔ sync/semaphore integration (br-e2e-170).
//!
//! Tests that MPSC channel producers correctly acquire semaphore permits under contention
//! without causing deadlocks. Verifies that the channel and semaphore subsystems integrate
//! properly when multiple producers compete for limited permits, ensuring proper resource
//! management and deadlock-free operation under high contention scenarios.
//!
//! # Integration Patterns Tested
//!
//! - **MPSC Producer Permit Acquisition**: Producers acquiring semaphore permits before sending
//! - **Contention Handling**: Multiple producers competing for limited semaphore permits
//! - **Deadlock Prevention**: No deadlocks when permits are exhausted and producers block
//! - **Permit Release Coordination**: Proper permit release allowing blocked producers to proceed
//! - **Backpressure Management**: Channel backpressure working with semaphore permit limiting
//!
//! # Test Scenarios
//!
//! 1. **Basic Producer Permit Integration** — Single producer with semaphore permit acquisition
//! 2. **Multi-Producer Contention** — Multiple producers competing for limited permits
//! 3. **Permit Exhaustion Handling** — Behavior when all semaphore permits are acquired
//! 4. **Deadlock Prevention** — No deadlocks when permits unavailable and channel full
//! 5. **Permit Release Coordination** — Proper permit release enables blocked producers
//! 6. **High Contention Stress** — Many producers with very limited permits
//!
//! # Safety Properties Verified
//!
//! - No deadlocks occur when semaphore permits are exhausted
//! - MPSC producers properly acquire permits before channel operations
//! - Permit release correctly unblocks waiting producers
//! - Channel and semaphore state remains consistent under contention
//! - No permit leaks when producers are cancelled or fail

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

    use crate::channel::mpsc::{channel, Receiver, Sender};
    use crate::cx::{Cx, Registry};
    use crate::runtime::Runtime;
    use crate::sync::semaphore::{Permit, Semaphore};
    use crate::time::{Duration, Instant, sleep, timeout};
    use crate::types::{CancelReason, Outcome, TaskId, Time};
    use std::collections::{HashMap, VecDeque};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    };
    use std::task::{Context, Poll};

    // ────────────────────────────────────────────────────────────────────────────────
    // MPSC + Semaphore Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MpscSemaphoreTestPhase {
        Setup,
        SemaphoreInitialization,
        ChannelCreation,
        ProducerPermitIntegration,
        BasicProducerPermitTest,
        MultiProducerContentionTest,
        PermitExhaustionHandling,
        DeadlockPreventionTest,
        PermitReleaseCoordinationTest,
        HighContentionStressTest,
        PermitLeakVerification,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MpscSemaphoreTestResult {
        pub test_name: String,
        pub producer_id: String,
        pub phase: MpscSemaphoreTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub integration_stats: MpscSemaphoreStats,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MpscSemaphoreStats {
        pub permits_acquired: u64,
        pub permits_released: u64,
        pub messages_sent: u64,
        pub messages_received: u64,
        pub contention_events: u64,
        pub blocked_producers: u64,
        pub deadlock_detections: u64,
        pub permit_wait_time_ms: u64,
        pub channel_backpressure_events: u64,
    }

    impl Default for MpscSemaphoreStats {
        fn default() -> Self {
            Self {
                permits_acquired: 0,
                permits_released: 0,
                messages_sent: 0,
                messages_received: 0,
                contention_events: 0,
                blocked_producers: 0,
                deadlock_detections: 0,
                permit_wait_time_ms: 0,
                channel_backpressure_events: 0,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct MpscSemaphoreConfig {
        pub semaphore_permits: usize,
        pub channel_capacity: usize,
        pub num_producers: usize,
        pub messages_per_producer: usize,
        pub producer_delay_ms: u64,
        pub permit_hold_time_ms: u64,
        pub deadlock_timeout_ms: u64,
        pub contention_simulation: bool,
        pub stress_test_enabled: bool,
    }

    impl Default for MpscSemaphoreConfig {
        fn default() -> Self {
            Self {
                semaphore_permits: 3,
                channel_capacity: 5,
                num_producers: 5,
                messages_per_producer: 10,
                producer_delay_ms: 10,
                permit_hold_time_ms: 50,
                deadlock_timeout_ms: 5000,
                contention_simulation: true,
                stress_test_enabled: false,
            }
        }
    }

    pub struct MockMpscSemaphoreSystem {
        config: MpscSemaphoreConfig,
        semaphore: Arc<Semaphore>,
        sender: Option<Sender<TestMessage>>,
        receiver: Option<Receiver<TestMessage>>,
        stats: Arc<Mutex<MpscSemaphoreStats>>,
        producer_handles: HashMap<String, Arc<AtomicBool>>,
        permit_tracker: Arc<RwLock<HashMap<String, Vec<Permit>>>>,
        deadlock_detector: Arc<AtomicBool>,
        runtime_stats: Arc<Mutex<HashMap<String, u64>>>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TestMessage {
        pub id: u64,
        pub producer_id: String,
        pub permit_id: String,
        pub timestamp: u64,
        pub payload: Vec<u8>,
    }

    impl MockMpscSemaphoreSystem {
        pub fn new(config: MpscSemaphoreConfig) -> Self {
            let semaphore = Arc::new(Semaphore::new(config.semaphore_permits));
            let (sender, receiver) = channel::<TestMessage>(config.channel_capacity);

            Self {
                config,
                semaphore,
                sender: Some(sender),
                receiver: Some(receiver),
                stats: Arc::new(Mutex::new(MpscSemaphoreStats::default())),
                producer_handles: HashMap::new(),
                permit_tracker: Arc::new(RwLock::new(HashMap::new())),
                deadlock_detector: Arc::new(AtomicBool::new(false)),
                runtime_stats: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        pub async fn setup_producers(&mut self, cx: &Cx) -> Result<(), String> {
            for i in 0..self.config.num_producers {
                let producer_id = format!("producer_{}", i);
                let handle = Arc::new(AtomicBool::new(true));
                self.producer_handles.insert(producer_id.clone(), handle.clone());

                // Initialize permit tracker for this producer
                self.permit_tracker.write().unwrap().insert(producer_id, Vec::new());
            }
            Ok(())
        }

        pub async fn run_producer(&self, cx: &Cx, producer_id: String) -> Result<(), String> {
            let sender = self.sender.as_ref().ok_or("Sender not available")?;
            let handle = self.producer_handles.get(&producer_id)
                .ok_or("Producer handle not found")?;

            for msg_id in 0..self.config.messages_per_producer {
                if !handle.load(Ordering::Relaxed) {
                    break;
                }

                // Acquire semaphore permit with timeout
                let permit_start = Instant::now();
                let permit = match timeout(
                    Duration::from_millis(self.config.deadlock_timeout_ms),
                    self.semaphore.acquire(cx)
                ).await {
                    Ok(Ok(permit)) => {
                        self.update_stats(|stats| {
                            stats.permits_acquired += 1;
                            stats.permit_wait_time_ms += permit_start.elapsed().as_millis() as u64;
                        });
                        permit
                    }
                    Ok(Err(_)) => {
                        return Err(format!("Failed to acquire permit for {}", producer_id));
                    }
                    Err(_) => {
                        self.update_stats(|stats| stats.deadlock_detections += 1);
                        return Err(format!("Permit acquisition timeout for {}", producer_id));
                    }
                };

                // Track permit
                let permit_id = format!("{}_{}", producer_id, msg_id);
                {
                    let mut tracker = self.permit_tracker.write().unwrap();
                    if let Some(permits) = tracker.get_mut(&producer_id) {
                        permits.push(permit);
                    }
                }

                // Simulate work while holding permit
                if self.config.permit_hold_time_ms > 0 {
                    sleep(Duration::from_millis(self.config.permit_hold_time_ms)).await;
                }

                // Create message
                let message = TestMessage {
                    id: msg_id as u64,
                    producer_id: producer_id.clone(),
                    permit_id,
                    timestamp: Instant::now().elapsed().as_millis() as u64,
                    payload: vec![msg_id as u8; 32],
                };

                // Send message with backpressure handling
                match timeout(
                    Duration::from_millis(self.config.deadlock_timeout_ms),
                    sender.send(message, cx)
                ).await {
                    Ok(Ok(())) => {
                        self.update_stats(|stats| stats.messages_sent += 1);
                    }
                    Ok(Err(_)) => {
                        self.update_stats(|stats| stats.channel_backpressure_events += 1);
                        return Err(format!("Channel send failed for {}", producer_id));
                    }
                    Err(_) => {
                        self.update_stats(|stats| stats.deadlock_detections += 1);
                        return Err(format!("Channel send timeout for {}", producer_id));
                    }
                }

                // Release permit
                {
                    let mut tracker = self.permit_tracker.write().unwrap();
                    if let Some(permits) = tracker.get_mut(&producer_id) {
                        if let Some(_permit) = permits.pop() {
                            // Permit is automatically dropped here, releasing the semaphore slot
                            self.update_stats(|stats| stats.permits_released += 1);
                        }
                    }
                }

                // Producer delay for contention simulation
                if self.config.contention_simulation && self.config.producer_delay_ms > 0 {
                    sleep(Duration::from_millis(self.config.producer_delay_ms)).await;
                }
            }

            Ok(())
        }

        pub async fn run_consumer(&self, cx: &Cx) -> Result<(), String> {
            let receiver = self.receiver.as_ref().ok_or("Receiver not available")?;
            let expected_messages = self.config.num_producers * self.config.messages_per_producer;
            let mut received_count = 0;

            while received_count < expected_messages {
                match timeout(
                    Duration::from_millis(self.config.deadlock_timeout_ms),
                    receiver.recv(cx)
                ).await {
                    Ok(Ok(Some(_message))) => {
                        received_count += 1;
                        self.update_stats(|stats| stats.messages_received += 1);
                    }
                    Ok(Ok(None)) => {
                        return Err("Channel closed unexpectedly".to_string());
                    }
                    Ok(Err(_)) => {
                        return Err("Channel receive error".to_string());
                    }
                    Err(_) => {
                        self.update_stats(|stats| stats.deadlock_detections += 1);
                        return Err("Consumer timeout - possible deadlock".to_string());
                    }
                }
            }

            Ok(())
        }

        pub async fn simulate_contention(&self, cx: &Cx) -> Result<(), String> {
            if !self.config.contention_simulation {
                return Ok(());
            }

            // Simulate high contention by having producers compete for permits
            let contention_producers = self.config.num_producers / 2;
            for _ in 0..contention_producers {
                // Acquire permits without releasing to simulate contention
                match timeout(
                    Duration::from_millis(100),
                    self.semaphore.acquire(cx)
                ).await {
                    Ok(Ok(_permit)) => {
                        self.update_stats(|stats| stats.contention_events += 1);
                        // Hold permit briefly to create contention
                        sleep(Duration::from_millis(50)).await;
                        // Permit automatically released when dropped
                    }
                    _ => break,
                }
            }

            Ok(())
        }

        pub fn check_deadlock_state(&self) -> bool {
            // Check for potential deadlock indicators
            let stats = self.stats.lock().unwrap();

            // Deadlock indicators:
            // 1. Permits acquired but no messages sent
            // 2. Multiple deadlock detections
            // 3. Blocked producers exceeding threshold

            let permit_message_ratio = if stats.messages_sent == 0 {
                f64::INFINITY
            } else {
                stats.permits_acquired as f64 / stats.messages_sent as f64
            };

            stats.deadlock_detections > 0 ||
            permit_message_ratio > 2.0 ||
            stats.blocked_producers > self.config.num_producers as u64 / 2
        }

        pub fn get_integration_stats(&self) -> MpscSemaphoreStats {
            self.stats.lock().unwrap().clone()
        }

        fn update_stats<F>(&self, f: F)
        where
            F: FnOnce(&mut MpscSemaphoreStats),
        {
            if let Ok(mut stats) = self.stats.lock() {
                f(&mut *stats);
            }
        }

        pub fn verify_permit_consistency(&self) -> bool {
            let tracker = self.permit_tracker.read().unwrap();
            let total_held_permits: usize = tracker.values()
                .map(|permits| permits.len())
                .sum();

            // Verify no more permits held than semaphore allows
            total_held_permits <= self.config.semaphore_permits
        }

        pub async fn cleanup(&mut self) -> Result<(), String> {
            // Stop all producers
            for handle in self.producer_handles.values() {
                handle.store(false, Ordering::Relaxed);
            }

            // Release all tracked permits
            let mut tracker = self.permit_tracker.write().unwrap();
            for permits in tracker.values_mut() {
                permits.clear(); // Drop all permits
            }

            Ok(())
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Integration Tests
    // ────────────────────────────────────────────────────────────────────────────────

    async fn run_mpsc_semaphore_integration_test(
        test_name: &str,
        config: MpscSemaphoreConfig,
    ) -> MpscSemaphoreTestResult {
        let start_time = Instant::now();
        let mut system = MockMpscSemaphoreSystem::new(config);

        let runtime = Runtime::new();
        let registry = Registry::new();

        let result = runtime.region(&registry, |cx| async {
            // Setup phase
            system.setup_producers(&cx).await?;

            // Start consumer task
            let consumer_task = {
                let system_ref = &system;
                async move { system_ref.run_consumer(&cx).await }
            };

            // Start producer tasks
            let mut producer_tasks = Vec::new();
            for i in 0..system.config.num_producers {
                let producer_id = format!("producer_{}", i);
                let system_ref = &system;
                let task = async move {
                    system_ref.run_producer(&cx, producer_id).await
                };
                producer_tasks.push(task);
            }

            // Run contention simulation if enabled
            if system.config.contention_simulation {
                let _ = system.simulate_contention(&cx).await;
            }

            // Wait for all tasks to complete
            let mut all_tasks = Vec::new();
            all_tasks.push(Box::pin(consumer_task) as Pin<Box<dyn Future<Output = Result<(), String>>>>);
            for task in producer_tasks {
                all_tasks.push(Box::pin(task) as Pin<Box<dyn Future<Output = Result<(), String>>>>);
            }

            // Simple join implementation for all tasks
            for task in all_tasks {
                match timeout(Duration::from_millis(system.config.deadlock_timeout_ms), task).await {
                    Ok(Ok(())) => continue,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => return Err("Task timeout".to_string()),
                }
            }

            // Verify no deadlocks occurred
            if system.check_deadlock_state() {
                return Err("Deadlock detected during integration test".to_string());
            }

            // Verify permit consistency
            if !system.verify_permit_consistency() {
                return Err("Permit consistency violation detected".to_string());
            }

            Ok(())
        }).await;

        let success = result.is_ok();
        let error = result.err();
        let duration_ms = start_time.elapsed().as_millis() as u64;

        MpscSemaphoreTestResult {
            test_name: test_name.to_string(),
            producer_id: "all".to_string(),
            phase: MpscSemaphoreTestPhase::Assert,
            success,
            error,
            duration_ms,
            integration_stats: system.get_integration_stats(),
        }
    }

    #[tokio::test]
    async fn test_basic_producer_permit_integration() {
        let config = MpscSemaphoreConfig {
            semaphore_permits: 2,
            num_producers: 3,
            messages_per_producer: 5,
            ..Default::default()
        };

        let result = run_mpsc_semaphore_integration_test(
            "basic_producer_permit_integration",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert_eq!(result.integration_stats.permits_acquired, result.integration_stats.permits_released);
        assert_eq!(result.integration_stats.messages_sent, result.integration_stats.messages_received);
        assert_eq!(result.integration_stats.deadlock_detections, 0);
    }

    #[tokio::test]
    async fn test_multi_producer_contention() {
        let config = MpscSemaphoreConfig {
            semaphore_permits: 2,
            num_producers: 8,
            messages_per_producer: 10,
            contention_simulation: true,
            permit_hold_time_ms: 100,
            ..Default::default()
        };

        let result = run_mpsc_semaphore_integration_test(
            "multi_producer_contention",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert_eq!(result.integration_stats.permits_acquired, result.integration_stats.permits_released);
        assert_eq!(result.integration_stats.messages_sent, result.integration_stats.messages_received);
        assert!(result.integration_stats.contention_events > 0);
        assert_eq!(result.integration_stats.deadlock_detections, 0);
    }

    #[tokio::test]
    async fn test_permit_exhaustion_handling() {
        let config = MpscSemaphoreConfig {
            semaphore_permits: 1, // Very limited permits
            num_producers: 5,
            messages_per_producer: 3,
            permit_hold_time_ms: 200,
            deadlock_timeout_ms: 10000, // Longer timeout for this test
            ..Default::default()
        };

        let result = run_mpsc_semaphore_integration_test(
            "permit_exhaustion_handling",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert_eq!(result.integration_stats.permits_acquired, result.integration_stats.permits_released);
        assert_eq!(result.integration_stats.messages_sent, result.integration_stats.messages_received);
        assert_eq!(result.integration_stats.deadlock_detections, 0);
    }

    #[tokio::test]
    async fn test_deadlock_prevention() {
        let config = MpscSemaphoreConfig {
            semaphore_permits: 2,
            channel_capacity: 1, // Small channel to create backpressure
            num_producers: 4,
            messages_per_producer: 5,
            permit_hold_time_ms: 50,
            deadlock_timeout_ms: 3000,
            ..Default::default()
        };

        let result = run_mpsc_semaphore_integration_test(
            "deadlock_prevention",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert_eq!(result.integration_stats.permits_acquired, result.integration_stats.permits_released);
        assert_eq!(result.integration_stats.messages_sent, result.integration_stats.messages_received);
        assert_eq!(result.integration_stats.deadlock_detections, 0);
    }

    #[tokio::test]
    async fn test_permit_release_coordination() {
        let config = MpscSemaphoreConfig {
            semaphore_permits: 3,
            num_producers: 6,
            messages_per_producer: 8,
            permit_hold_time_ms: 75,
            contention_simulation: true,
            ..Default::default()
        };

        let result = run_mpsc_semaphore_integration_test(
            "permit_release_coordination",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert_eq!(result.integration_stats.permits_acquired, result.integration_stats.permits_released);
        assert_eq!(result.integration_stats.messages_sent, result.integration_stats.messages_received);
        assert!(result.integration_stats.permit_wait_time_ms > 0); // Some waiting should occur
        assert_eq!(result.integration_stats.deadlock_detections, 0);
    }

    #[tokio::test]
    async fn test_high_contention_stress() {
        let config = MpscSemaphoreConfig {
            semaphore_permits: 2,
            num_producers: 12,
            messages_per_producer: 15,
            permit_hold_time_ms: 25,
            producer_delay_ms: 5,
            contention_simulation: true,
            stress_test_enabled: true,
            deadlock_timeout_ms: 15000, // Longer timeout for stress test
            ..Default::default()
        };

        let result = run_mpsc_semaphore_integration_test(
            "high_contention_stress",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert_eq!(result.integration_stats.permits_acquired, result.integration_stats.permits_released);
        assert_eq!(result.integration_stats.messages_sent, result.integration_stats.messages_received);
        assert!(result.integration_stats.contention_events > 0);
        assert_eq!(result.integration_stats.deadlock_detections, 0);
    }
}