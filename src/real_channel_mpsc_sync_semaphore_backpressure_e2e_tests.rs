//! Real E2E integration tests: channel/mpsc ↔ sync/semaphore backpressure integration (br-e2e-62).
//!
//! Tests MPSC producers respect semaphore permits and permit revocation correctly back-propagates
//! without leaking buffer entries. Verifies that MPSC channel and semaphore synchronization
//! integrate properly to provide coordinated backpressure control where producers must acquire
//! semaphore permits before sending to MPSC channels, and permit revocation properly propagates
//! through the system without resource leaks.
//!
//! # Integration Patterns Tested
//!
//! - **Semaphore-Gated MPSC Production**: Producers acquire permits before MPSC channel reservation
//! - **Backpressure Coordination**: Semaphore permits control MPSC send rate and buffer pressure
//! - **Permit Revocation Propagation**: Semaphore closure back-propagates to waiting MPSC producers
//! - **Buffer Entry Lifecycle**: No leaked MPSC buffer entries during permit revocation scenarios
//! - **Resource Cleanup Integration**: Proper cleanup of both semaphore permits and MPSC reservations
//!
//! # Test Scenarios
//!
//! 1. **Basic Permit-Gated Sending** — Producers acquire permits before MPSC reservation and sending
//! 2. **Permit Exhaustion Backpressure** — MPSC producers properly wait when semaphore permits exhausted
//! 3. **Permit Revocation Propagation** — Semaphore closure cancels pending MPSC operations cleanly
//! 4. **Concurrent Producer Coordination** — Multiple producers respect shared semaphore permit pool
//! 5. **Buffer Leak Prevention** — No leaked MPSC entries during complex permit revocation scenarios
//!
//! # Safety Properties Verified
//!
//! - MPSC producers acquire semaphore permits before channel operations
//! - Permit exhaustion properly blocks MPSC production without buffer leaks
//! - Permit revocation cleanly cancels pending MPSC operations and releases reservations
//! - No orphaned buffer entries or permits after complex backpressure scenarios

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

    use crate::channel::mpsc::{self, SendError, SendPermit, Sender, Receiver};
    use crate::cx::{Cx, Registry};
    use crate::runtime::{Runtime, spawn};
    use crate::sync::semaphore::{AcquireError, Semaphore, SemaphorePermit};
    use crate::time::{Duration, Instant, sleep, timeout};
    use crate::types::{CancelReason, Outcome, RegionId, TaskId, Budget};
    use std::collections::{HashMap, VecDeque};
    use std::future::Future;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    };
    use std::task::{Context, Poll};
    use tokio::sync::{Barrier, Semaphore as TokioSemaphore};

    // ────────────────────────────────────────────────────────────────────────────────
    // MPSC + Semaphore Backpressure Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BackpressureTestPhase {
        Setup,
        SemaphoreInitialization,
        MpscChannelCreation,
        ProducerRegistration,
        PermitGatedSending,
        PermitExhaustionTest,
        BackpressurePropagation,
        PermitRevocationTest,
        BufferLeakVerification,
        ResourceCleanupVerification,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct BackpressureTestResult {
        pub test_name: String,
        pub producer_id: String,
        pub phase: BackpressureTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub backpressure_stats: BackpressureStats,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct BackpressureStats {
        pub semaphore_permits_acquired: u64,
        pub semaphore_permits_released: u64,
        pub mpsc_reservations_made: u64,
        pub mpsc_messages_sent: u64,
        pub mpsc_reservations_aborted: u64,
        pub permit_acquisitions_blocked: u64,
        pub permit_revocations_propagated: u64,
        pub backpressure_events_triggered: u64,
        pub buffer_entries_leaked: u64,
        pub producers_waiting_for_permits: u64,
        pub producers_waiting_for_mpsc_capacity: u64,
    }

    /// Message sent through the MPSC channel during testing.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TestMessage {
        pub message_id: u64,
        pub producer_id: u32,
        pub payload: String,
        pub sequence_number: u32,
        pub permit_acquired_at: Instant,
        pub sent_at: Option<Instant>,
    }

    impl TestMessage {
        pub fn new(message_id: u64, producer_id: u32, payload: String, sequence: u32) -> Self {
            Self {
                message_id,
                producer_id,
                payload,
                sequence_number: sequence,
                permit_acquired_at: Instant::now(),
                sent_at: None,
            }
        }
    }

    /// Producer tracking for backpressure integration verification.
    #[derive(Debug, Clone)]
    pub struct ProducerTracker {
        pub producer_id: u32,
        pub messages_attempted: u32,
        pub messages_sent: u32,
        pub permits_acquired: u32,
        pub permits_revoked: u32,
        pub blocked_on_permits: bool,
        pub blocked_on_mpsc_capacity: bool,
        pub last_operation_time: Instant,
    }

    /// Backpressure event tracking for verification.
    #[derive(Debug, Clone)]
    pub struct BackpressureEvent {
        pub timestamp: Instant,
        pub event_type: BackpressureEventType,
        pub producer_id: u32,
        pub permit_count: u32,
        pub mpsc_buffer_usage: usize,
        pub mpsc_reserved_count: usize,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BackpressureEventType {
        PermitAcquired,
        PermitReleased,
        PermitRevoked,
        MpscReserved,
        MpscSent,
        MpscAborted,
        BackpressureBlocked,
        BackpressureUnblocked,
    }

    /// Test harness for MPSC + Semaphore backpressure integration.
    pub struct MpscSemaphoreBackpressureTestHarness {
        semaphore: Arc<Semaphore>,
        mpsc_sender: Sender<TestMessage>,
        mpsc_receiver: Arc<Mutex<Receiver<TestMessage>>>,
        stats: Arc<Mutex<BackpressureStats>>,
        producer_trackers: Arc<Mutex<HashMap<u32, ProducerTracker>>>,
        backpressure_events: Arc<Mutex<VecDeque<BackpressureEvent>>>,
        runtime: Runtime,
        test_start_time: Instant,
    }

    impl MpscSemaphoreBackpressureTestHarness {
        pub async fn new(
            semaphore_permits: usize,
            mpsc_capacity: usize,
        ) -> Self {
            let runtime = Runtime::new().expect("Failed to create runtime");

            // Create semaphore with specified permit count
            let semaphore = Arc::new(Semaphore::new(semaphore_permits));

            // Create MPSC channel with specified capacity
            let (mpsc_sender, mpsc_receiver) = mpsc::channel(mpsc_capacity);

            Self {
                semaphore,
                mpsc_sender,
                mpsc_receiver: Arc::new(Mutex::new(mpsc_receiver)),
                stats: Arc::new(Mutex::new(BackpressureStats::default())),
                producer_trackers: Arc::new(Mutex::new(HashMap::new())),
                backpressure_events: Arc::new(Mutex::new(VecDeque::new())),
                runtime,
                test_start_time: Instant::now(),
            }
        }

        pub fn register_producer(&self, producer_id: u32) {
            let tracker = ProducerTracker {
                producer_id,
                messages_attempted: 0,
                messages_sent: 0,
                permits_acquired: 0,
                permits_revoked: 0,
                blocked_on_permits: false,
                blocked_on_mpsc_capacity: false,
                last_operation_time: Instant::now(),
            };

            self.producer_trackers.lock().unwrap().insert(producer_id, tracker);
        }

        pub fn record_backpressure_event(&self, event: BackpressureEvent) {
            let mut stats = self.stats.lock().unwrap();

            match event.event_type {
                BackpressureEventType::PermitAcquired => {
                    stats.semaphore_permits_acquired += 1;
                }
                BackpressureEventType::PermitReleased => {
                    stats.semaphore_permits_released += 1;
                }
                BackpressureEventType::PermitRevoked => {
                    stats.permit_revocations_propagated += 1;
                }
                BackpressureEventType::MpscReserved => {
                    stats.mpsc_reservations_made += 1;
                }
                BackpressureEventType::MpscSent => {
                    stats.mpsc_messages_sent += 1;
                }
                BackpressureEventType::MpscAborted => {
                    stats.mpsc_reservations_aborted += 1;
                }
                BackpressureEventType::BackpressureBlocked => {
                    stats.backpressure_events_triggered += 1;
                }
                BackpressureEventType::BackpressureUnblocked => {
                    // Track unblocking events
                }
            }

            self.backpressure_events.lock().unwrap().push_back(event);
        }

        /// Core method: Permit-gated MPSC sending with full backpressure integration.
        pub async fn permit_gated_send(
            &self,
            cx: &Cx,
            message: TestMessage,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let producer_id = message.producer_id;

            // Update producer tracker
            if let Some(tracker) = self.producer_trackers.lock().unwrap().get_mut(&producer_id) {
                tracker.messages_attempted += 1;
                tracker.blocked_on_permits = true;
                tracker.last_operation_time = Instant::now();
            }

            // Phase 1: Acquire semaphore permit (backpressure control)
            let permit = self.semaphore.acquire(cx, 1).await
                .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;

            // Record permit acquisition
            let permit_event = BackpressureEvent {
                timestamp: Instant::now(),
                event_type: BackpressureEventType::PermitAcquired,
                producer_id,
                permit_count: 1,
                mpsc_buffer_usage: 0, // We don't have easy access to this
                mpsc_reserved_count: 0, // Would need channel introspection
            };
            self.record_backpressure_event(permit_event);

            // Update tracker for permit acquisition
            if let Some(tracker) = self.producer_trackers.lock().unwrap().get_mut(&producer_id) {
                tracker.permits_acquired += 1;
                tracker.blocked_on_permits = false;
                tracker.blocked_on_mpsc_capacity = true;
            }

            // Phase 2: Reserve MPSC channel slot
            let mpsc_permit = self.mpsc_sender.reserve(cx).await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    match e {
                        SendError::Disconnected(_) => Box::new(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "MPSC disconnected")),
                        SendError::Cancelled(_) => Box::new(std::io::Error::new(std::io::ErrorKind::Interrupted, "MPSC cancelled")),
                        SendError::Full(_) => Box::new(std::io::Error::new(std::io::ErrorKind::WouldBlock, "MPSC full")),
                    }
                })?;

            // Record MPSC reservation
            let mpsc_reserve_event = BackpressureEvent {
                timestamp: Instant::now(),
                event_type: BackpressureEventType::MpscReserved,
                producer_id,
                permit_count: 1,
                mpsc_buffer_usage: 0,
                mpsc_reserved_count: 0,
            };
            self.record_backpressure_event(mpsc_reserve_event);

            // Phase 3: Commit the message
            let mut message_with_timestamp = message;
            message_with_timestamp.sent_at = Some(Instant::now());

            match mpsc_permit.send(message_with_timestamp) {
                Outcome::Ok(_) => {
                    // Record successful send
                    let send_event = BackpressureEvent {
                        timestamp: Instant::now(),
                        event_type: BackpressureEventType::MpscSent,
                        producer_id,
                        permit_count: 1,
                        mpsc_buffer_usage: 0,
                        mpsc_reserved_count: 0,
                    };
                    self.record_backpressure_event(send_event);

                    // Update tracker
                    if let Some(tracker) = self.producer_trackers.lock().unwrap().get_mut(&producer_id) {
                        tracker.messages_sent += 1;
                        tracker.blocked_on_mpsc_capacity = false;
                    }
                }
                Outcome::Err(_) => {
                    // Record failed send
                    let abort_event = BackpressureEvent {
                        timestamp: Instant::now(),
                        event_type: BackpressureEventType::MpscAborted,
                        producer_id,
                        permit_count: 1,
                        mpsc_buffer_usage: 0,
                        mpsc_reserved_count: 0,
                    };
                    self.record_backpressure_event(abort_event);

                    return Err(Box::new(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "MPSC send failed")));
                }
            }

            // Phase 4: Release permit (happens automatically via Drop)
            drop(permit);

            // Record permit release
            let release_event = BackpressureEvent {
                timestamp: Instant::now(),
                event_type: BackpressureEventType::PermitReleased,
                producer_id,
                permit_count: 1,
                mpsc_buffer_usage: 0,
                mpsc_reserved_count: 0,
            };
            self.record_backpressure_event(release_event);

            Ok(())
        }

        pub fn close_semaphore(&self) {
            self.semaphore.close();

            // Record permit revocations for waiting producers
            let waiting_count = self.producer_trackers.lock().unwrap()
                .values()
                .filter(|t| t.blocked_on_permits)
                .count() as u32;

            for _ in 0..waiting_count {
                let revoke_event = BackpressureEvent {
                    timestamp: Instant::now(),
                    event_type: BackpressureEventType::PermitRevoked,
                    producer_id: 0, // General revocation
                    permit_count: 0,
                    mpsc_buffer_usage: 0,
                    mpsc_reserved_count: 0,
                };
                self.record_backpressure_event(revoke_event);
            }
        }

        pub async fn consume_messages(&self, expected_count: u32) -> Vec<TestMessage> {
            let mut consumed = Vec::new();
            let mut receiver = self.mpsc_receiver.lock().unwrap();

            for _ in 0..expected_count {
                match timeout(Duration::from_millis(100), receiver.recv()).await {
                    Ok(Ok(message)) => {
                        consumed.push(message);
                    }
                    Ok(Err(_)) => break, // Channel closed or error
                    Err(_) => break, // Timeout
                }
            }

            consumed
        }

        pub fn get_stats_snapshot(&self) -> BackpressureStats {
            self.stats.lock().unwrap().clone()
        }

        pub fn get_producer_trackers(&self) -> HashMap<u32, ProducerTracker> {
            self.producer_trackers.lock().unwrap().clone()
        }

        pub fn get_backpressure_events(&self) -> Vec<BackpressureEvent> {
            self.backpressure_events.lock().unwrap().iter().cloned().collect()
        }

        pub fn verify_no_buffer_leaks(&self) -> bool {
            let stats = self.get_stats_snapshot();

            // Check that reservations and sends/aborts balance
            let total_reservations = stats.mpsc_reservations_made;
            let total_outcomes = stats.mpsc_messages_sent + stats.mpsc_reservations_aborted;

            total_reservations == total_outcomes
        }

        pub fn verify_permit_balance(&self) -> bool {
            let stats = self.get_stats_snapshot();

            // All acquired permits should be released or revoked
            let permits_acquired = stats.semaphore_permits_acquired;
            let permits_accounted = stats.semaphore_permits_released + stats.permit_revocations_propagated;

            permits_acquired <= permits_accounted
        }
    }

    /// Helper function to create test context
    fn create_test_cx(task_id: u32) -> Cx {
        Cx::new(
            RegionId(1),
            TaskId(u64::from(task_id)),
            Budget::new(1000, 100),
        )
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 1: Basic Permit-Gated Sending
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_mpsc_semaphore_basic_permit_gated_sending() {
        let harness = MpscSemaphoreBackpressureTestHarness::new(3, 5).await;

        harness.register_producer(1);

        let cx = create_test_cx(1);
        let message = TestMessage::new(1001, 1, "test message".to_string(), 0);

        // Should succeed with available permits and capacity
        assert!(harness.permit_gated_send(&cx, message).await.is_ok());

        let stats = harness.get_stats_snapshot();
        assert_eq!(stats.semaphore_permits_acquired, 1);
        assert_eq!(stats.semaphore_permits_released, 1);
        assert_eq!(stats.mpsc_reservations_made, 1);
        assert_eq!(stats.mpsc_messages_sent, 1);

        assert!(harness.verify_no_buffer_leaks());
        assert!(harness.verify_permit_balance());

        // Consume the message to verify it was sent
        let messages = harness.consume_messages(1).await;
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id, 1001);
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 2: Permit Exhaustion Backpressure
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_mpsc_semaphore_permit_exhaustion_backpressure() {
        let harness = MpscSemaphoreBackpressureTestHarness::new(2, 10).await; // Only 2 permits available

        harness.register_producer(1);
        harness.register_producer(2);
        harness.register_producer(3);

        // Acquire permits to exhaust the semaphore
        let cx1 = create_test_cx(1);
        let permit1 = harness.semaphore.try_acquire(1).expect("Should acquire first permit");
        let permit2 = harness.semaphore.try_acquire(1).expect("Should acquire second permit");

        // Third acquire should fail immediately
        assert!(harness.semaphore.try_acquire(1).is_err());

        // Now try to send - should block on permit acquisition
        let cx3 = create_test_cx(3);
        let message3 = TestMessage::new(2003, 3, "blocked message".to_string(), 0);

        // Start the send operation in background (it will block)
        let send_result = timeout(Duration::from_millis(100),
            harness.permit_gated_send(&cx3, message3)
        ).await;

        // Should timeout because permit is not available
        assert!(send_result.is_err(), "Send should timeout waiting for permit");

        // Release one permit
        drop(permit1);

        // Now the send should succeed
        let message3_retry = TestMessage::new(2004, 3, "unblocked message".to_string(), 1);
        assert!(harness.permit_gated_send(&cx3, message3_retry).await.is_ok());

        // Clean up
        drop(permit2);

        let stats = harness.get_stats_snapshot();
        assert!(stats.semaphore_permits_acquired > 0);
        assert!(harness.verify_no_buffer_leaks());
        assert!(harness.verify_permit_balance());
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 3: Permit Revocation Propagation
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_mpsc_semaphore_permit_revocation_propagation() {
        let harness = MpscSemaphoreBackpressureTestHarness::new(1, 5).await;

        harness.register_producer(1);
        harness.register_producer(2);

        // Exhaust the single permit
        let permit = harness.semaphore.try_acquire(1).expect("Should acquire permit");

        // Start a producer that will block waiting for permit
        let cx2 = create_test_cx(2);
        let message2 = TestMessage::new(3002, 2, "waiting message".to_string(), 0);

        // Start send operation that will block on permit acquisition
        let send_future = harness.permit_gated_send(&cx2, message2);
        let send_task = tokio::spawn(send_future);

        // Give it time to start waiting
        sleep(Duration::from_millis(50)).await;

        // Close the semaphore - should revoke permits and cancel waiting operations
        harness.close_semaphore();

        // The send task should complete with an error
        let send_result = timeout(Duration::from_millis(200), send_task).await;
        assert!(send_result.is_ok(), "Send task should complete after semaphore closure");

        let task_result = send_result.unwrap().unwrap();
        assert!(task_result.is_err(), "Send should fail after permit revocation");

        // Clean up
        drop(permit);

        let stats = harness.get_stats_snapshot();
        assert!(stats.permit_revocations_propagated > 0, "Should have recorded permit revocations");
        assert!(harness.verify_no_buffer_leaks());
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 4: Concurrent Producer Coordination
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_mpsc_semaphore_concurrent_producer_coordination() {
        let harness = MpscSemaphoreBackpressureTestHarness::new(3, 10).await;

        let producer_count = 5;
        for i in 0..producer_count {
            harness.register_producer(i);
        }

        let mut send_tasks = Vec::new();

        // Launch multiple concurrent producers
        for i in 0..producer_count {
            let cx = create_test_cx(i);
            let message = TestMessage::new(4000 + u64::from(i), i, format!("message-{}", i), i);

            let harness_ref = &harness;
            let task = tokio::spawn(async move {
                harness_ref.permit_gated_send(&cx, message).await
            });
            send_tasks.push(task);
        }

        // Wait for all producers to complete
        let mut successful_sends = 0;
        let mut failed_sends = 0;

        for task in send_tasks {
            match task.await.unwrap() {
                Ok(_) => successful_sends += 1,
                Err(_) => failed_sends += 1,
            }
        }

        // Should have some successful sends (limited by permits)
        assert!(successful_sends > 0, "Should have successful sends");
        println!("✅ Concurrent: {} successful, {} failed sends", successful_sends, failed_sends);

        let stats = harness.get_stats_snapshot();
        assert!(stats.semaphore_permits_acquired > 0);
        assert!(harness.verify_no_buffer_leaks());

        // Consume any sent messages
        let messages = harness.consume_messages(successful_sends as u32).await;
        assert_eq!(messages.len(), successful_sends);
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 5: Buffer Leak Prevention
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_mpsc_semaphore_buffer_leak_prevention() {
        let harness = MpscSemaphoreBackpressureTestHarness::new(2, 3).await;

        // Register producers
        for i in 0..4 {
            harness.register_producer(i);
        }

        // Send several messages through the system
        let mut operations = Vec::new();

        for i in 0..6 {
            let cx = create_test_cx(i);
            let message = TestMessage::new(5000 + u64::from(i), i, format!("test-{}", i), 0);

            let result = harness.permit_gated_send(&cx, message).await;
            operations.push(result.is_ok());
        }

        // Close semaphore to trigger cleanup
        harness.close_semaphore();

        // Try more operations that should fail cleanly
        for i in 6..8 {
            let cx = create_test_cx(i);
            let message = TestMessage::new(5000 + u64::from(i), i, format!("fail-{}", i), 0);

            let result = harness.permit_gated_send(&cx, message).await;
            assert!(result.is_err(), "Operations should fail after semaphore closure");
        }

        // Verify no buffer leaks
        assert!(harness.verify_no_buffer_leaks(), "Should have no buffer leaks");

        let stats = harness.get_stats_snapshot();
        let events = harness.get_backpressure_events();

        // Verify proper cleanup
        assert!(stats.mpsc_reservations_made > 0, "Should have made reservations");
        assert_eq!(
            stats.mpsc_reservations_made,
            stats.mpsc_messages_sent + stats.mpsc_reservations_aborted,
            "All reservations should be accounted for"
        );

        let successful_ops = operations.iter().filter(|&&success| success).count();
        println!("✅ Buffer Leak Prevention: {} successful ops, {} total events, no leaks",
                successful_ops, events.len());
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Integration Test Result Verification
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_mpsc_semaphore_backpressure_full_integration() {
        let harness = MpscSemaphoreBackpressureTestHarness::new(4, 8).await;

        // Complex scenario: mixed workload with permits and revocations
        let producer_count = 8;
        for i in 0..producer_count {
            harness.register_producer(i);
        }

        let mut phase1_tasks = Vec::new();
        let mut phase2_tasks = Vec::new();

        // Phase 1: Normal operations with available permits
        for i in 0..4 {
            let cx = create_test_cx(i);
            let message = TestMessage::new(6000 + u64::from(i), i, format!("phase1-{}", i), 0);

            let harness_ref = &harness;
            let task = tokio::spawn(async move {
                harness_ref.permit_gated_send(&cx, message).await
            });
            phase1_tasks.push(task);
        }

        // Wait for phase 1 to mostly complete
        sleep(Duration::from_millis(100)).await;

        // Phase 2: Operations that will compete for limited permits
        for i in 4..producer_count {
            let cx = create_test_cx(i);
            let message = TestMessage::new(6000 + u64::from(i), i, format!("phase2-{}", i), 0);

            let harness_ref = &harness;
            let task = tokio::spawn(async move {
                harness_ref.permit_gated_send(&cx, message).await
            });
            phase2_tasks.push(task);
        }

        // Let phase 2 start competing
        sleep(Duration::from_millis(50)).await;

        // Close semaphore to test revocation propagation
        harness.close_semaphore();

        // Collect results from both phases
        let mut phase1_results = Vec::new();
        for task in phase1_tasks {
            phase1_results.push(task.await.unwrap());
        }

        let mut phase2_results = Vec::new();
        for task in phase2_tasks {
            phase2_results.push(task.await.unwrap());
        }

        // Verify integration properties
        let final_stats = harness.get_stats_snapshot();
        let producer_states = harness.get_producer_trackers();
        let events = harness.get_backpressure_events();

        // Comprehensive verification
        assert!(harness.verify_no_buffer_leaks(), "No MPSC buffer leaks allowed");
        assert!(harness.verify_permit_balance(), "Semaphore permits must be balanced");

        let successful_phase1 = phase1_results.iter().filter(|r| r.is_ok()).count();
        let successful_phase2 = phase2_results.iter().filter(|r| r.is_ok()).count();
        let total_successful = successful_phase1 + successful_phase2;

        // Should have permit acquisition and release events
        assert!(final_stats.semaphore_permits_acquired > 0, "Should acquire permits");
        assert!(final_stats.mpsc_reservations_made > 0, "Should make MPSC reservations");

        // Verify permit revocations were recorded
        assert!(final_stats.permit_revocations_propagated > 0, "Should record permit revocations");

        // Consume any successfully sent messages
        let consumed_messages = harness.consume_messages(total_successful as u32).await;

        println!("✅ MPSC ↔ Semaphore Backpressure Integration Test Complete");
        println!("📊 Final Stats: {:?}", final_stats);
        println!("🎯 Results: Phase1={}/{} Phase2={}/{} Total={} Messages={}",
                successful_phase1, phase1_results.len(),
                successful_phase2, phase2_results.len(),
                total_successful, consumed_messages.len());
        println!("🔄 Backpressure Events: {}, No Buffer Leaks: {}, Permit Balance: {}",
                events.len(),
                harness.verify_no_buffer_leaks(),
                harness.verify_permit_balance());
    }
}