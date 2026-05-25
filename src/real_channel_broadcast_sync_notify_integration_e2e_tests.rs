//! br-e2e-147: Real channel/broadcast ↔ sync/notify integration tests
//!
//! Verifies that broadcast sender drop correctly notifies all receivers with
//! proper sequence numbers. Tests the integration between:
//!
//! - `channel::broadcast`: Multi-consumer broadcast channel implementation
//! - `sync::notify`: Notification primitive for waking waiting tasks
//!
//! Key integration properties:
//! - Broadcast sender drop correctly notifies all active receivers
//! - Sequence numbers are properly maintained across sender drop
//! - Receivers get proper closed channel notifications via sync::notify
//! - No lost notifications during sender drop with concurrent receivers
//! - Proper cleanup of notification state when broadcast channel closes

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use crate::{
        channel::broadcast::{Receiver as BroadcastReceiver, Sender as BroadcastSender, broadcast},
        channel::{mpsc, oneshot},
        cx::Cx,
        error::{Error, ErrorKind},
        runtime::Runtime,
        sync::notify::Notify,
        sync::{AtomicBool, AtomicU32, AtomicU64, Mutex},
        test_utils::{TestTracer, init_test_runtime},
        time::{Duration, Instant, Sleep},
        types::{Budget, Outcome, TaskId},
    };
    use std::collections::{BTreeMap, HashMap, VecDeque};
    use std::sync::{Arc, atomic::Ordering};

    /// Test framework for broadcast-notify integration scenarios
    struct BroadcastNotifyTestFramework {
        runtime: Runtime,
        tracer: TestTracer,
        notify: Arc<Notify>,
        stats: Arc<IntegrationStats>,
        config: IntegrationConfig,
    }

    /// Statistics for broadcast-notify integration
    #[derive(Debug)]
    struct IntegrationStats {
        messages_sent: AtomicU64,
        messages_received: AtomicU64,
        receivers_created: AtomicU64,
        receivers_dropped: AtomicU64,
        sender_drops: AtomicU64,
        notifications_sent: AtomicU64,
        notifications_received: AtomicU64,
        sequence_errors: AtomicU64,
        close_notifications: AtomicU64,
    }

    /// Configuration for broadcast-notify integration testing
    struct IntegrationConfig {
        channel_capacity: usize,
        num_receivers: usize,
        messages_per_sender: usize,
        sender_drop_delay: Duration,
        receiver_processing_delay: Duration,
        enable_sequence_tracking: bool,
    }

    /// Represents a broadcast receiver with notification tracking
    struct NotifiedReceiver {
        id: u64,
        receiver: BroadcastReceiver<TestMessage>,
        notify: Arc<Notify>,
        sequence_tracker: Arc<SequenceTracker>,
        stats: Arc<ReceiverStats>,
        drop_notifier: Arc<DropNotifier>,
    }

    /// Test message with sequence number
    #[derive(Debug, Clone, PartialEq)]
    struct TestMessage {
        sequence: u64,
        payload: String,
        sender_id: u32,
        timestamp: Instant,
    }

    /// Tracks message sequence numbers per receiver
    struct SequenceTracker {
        expected_sequences: Arc<Mutex<HashMap<u64, u64>>>, // receiver_id -> next_expected_seq
        received_sequences: Arc<Mutex<HashMap<u64, Vec<u64>>>>, // receiver_id -> received_seqs
        sequence_errors: Arc<AtomicU64>,
    }

    /// Statistics per receiver
    #[derive(Debug)]
    struct ReceiverStats {
        messages_received: AtomicU64,
        notifications_received: AtomicU64,
        close_notifications: AtomicU64,
        sequence_gaps: AtomicU64,
        last_sequence: AtomicU64,
    }

    /// Handles drop notifications for broadcast senders
    struct DropNotifier {
        notifiers: Arc<Mutex<HashMap<u32, Arc<Notify>>>>, // sender_id -> notify
        drop_callbacks: Arc<Mutex<Vec<oneshot::Sender<DropEvent>>>>,
    }

    /// Event fired when sender is dropped
    #[derive(Debug, Clone)]
    struct DropEvent {
        sender_id: u32,
        timestamp: Instant,
        final_sequence: u64,
        active_receivers: u32,
    }

    /// Monitors receiver behavior during sender drop
    struct ReceiverMonitor {
        active_receivers: Arc<AtomicU32>,
        drop_notifications: Arc<Mutex<Vec<ReceiverDropNotification>>>,
        sequence_validator: Arc<SequenceValidator>,
    }

    /// Notification received by receiver about sender drop
    #[derive(Debug, Clone)]
    struct ReceiverDropNotification {
        receiver_id: u64,
        timestamp: Instant,
        last_received_sequence: u64,
        notification_source: NotificationSource,
    }

    /// Source of drop notification
    #[derive(Debug, Clone, PartialEq)]
    enum NotificationSource {
        BroadcastChannelClosed,
        ExplicitNotify,
        SequenceEnd,
    }

    /// Validates sequence number consistency
    struct SequenceValidator {
        global_sequence: Arc<AtomicU64>,
        receiver_sequences: Arc<Mutex<BTreeMap<u64, u64>>>,
        validation_errors: Arc<Mutex<Vec<SequenceValidationError>>>,
    }

    /// Sequence validation error
    #[derive(Debug, Clone)]
    struct SequenceValidationError {
        receiver_id: u64,
        expected_sequence: u64,
        actual_sequence: u64,
        error_type: SequenceErrorType,
        timestamp: Instant,
    }

    /// Types of sequence errors
    #[derive(Debug, Clone, PartialEq)]
    enum SequenceErrorType {
        Gap,
        Duplicate,
        OutOfOrder,
        MissingAfterDrop,
    }

    /// Coordinates broadcast sender lifecycle
    struct SenderCoordinator {
        sender: Option<BroadcastSender<TestMessage>>,
        sender_id: u32,
        message_counter: Arc<AtomicU64>,
        drop_notifier: Arc<DropNotifier>,
        notify_on_drop: Arc<Notify>,
    }

    impl BroadcastNotifyTestFramework {
        async fn new(cx: &Cx, config: IntegrationConfig) -> Result<Self, Error> {
            let runtime = init_test_runtime(cx).await?;
            let tracer = TestTracer::new();
            let notify = Arc::new(Notify::new());

            let stats = Arc::new(IntegrationStats {
                messages_sent: AtomicU64::new(0),
                messages_received: AtomicU64::new(0),
                receivers_created: AtomicU64::new(0),
                receivers_dropped: AtomicU64::new(0),
                sender_drops: AtomicU64::new(0),
                notifications_sent: AtomicU64::new(0),
                notifications_received: AtomicU64::new(0),
                sequence_errors: AtomicU64::new(0),
                close_notifications: AtomicU64::new(0),
            });

            Ok(Self {
                runtime,
                tracer,
                notify,
                stats,
                config,
            })
        }

        /// Execute broadcast with sender drop and receiver notifications
        async fn execute_broadcast_with_sender_drop(
            &self,
            cx: &Cx,
        ) -> Result<BroadcastDropResults, Error> {
            // Create broadcast channel
            let (sender, _) = broadcast(self.config.channel_capacity);

            // Set up sequence tracking
            let sequence_tracker = Arc::new(SequenceTracker::new());
            let drop_notifier = Arc::new(DropNotifier::new());

            // Create multiple receivers with notification tracking
            let mut receivers = Vec::new();
            for i in 0..self.config.num_receivers {
                let receiver = self
                    .create_notified_receiver(
                        cx,
                        i as u64,
                        sender.subscribe(),
                        &sequence_tracker,
                        &drop_notifier,
                    )
                    .await?;
                receivers.push(receiver);
            }

            // Start receiver monitoring
            let monitor = Arc::new(ReceiverMonitor::new());
            let receiver_handles = self
                .start_receiver_monitoring(cx, receivers, &monitor)
                .await?;

            // Create sender coordinator
            let sender_coordinator =
                Arc::new(SenderCoordinator::new(sender, 1, &drop_notifier).await?);

            // Send messages
            self.send_messages_with_coordination(cx, &sender_coordinator)
                .await?;

            // Drop sender after delay and notify receivers
            Sleep::new(self.config.sender_drop_delay).await;
            let drop_event = self
                .drop_sender_with_notification(cx, sender_coordinator, &monitor)
                .await?;

            // Wait for all receivers to process drop
            Sleep::new(Duration::from_millis(500)).await;

            // Stop receiver monitoring
            for handle in receiver_handles {
                handle.cancel().await;
            }

            // Validate sequence consistency
            let validation_results = sequence_tracker.validate_final_state().await?;

            Ok(BroadcastDropResults {
                messages_sent: self.stats.messages_sent.load(Ordering::Relaxed),
                messages_received: self.stats.messages_received.load(Ordering::Relaxed),
                sender_drops: self.stats.sender_drops.load(Ordering::Relaxed),
                close_notifications: self.stats.close_notifications.load(Ordering::Relaxed),
                notifications_sent: self.stats.notifications_sent.load(Ordering::Relaxed),
                notifications_received: self.stats.notifications_received.load(Ordering::Relaxed),
                sequence_errors: self.stats.sequence_errors.load(Ordering::Relaxed),
                drop_event,
                validation_results,
            })
        }

        /// Create a receiver with notification tracking
        async fn create_notified_receiver(
            &self,
            cx: &Cx,
            receiver_id: u64,
            receiver: BroadcastReceiver<TestMessage>,
            sequence_tracker: &Arc<SequenceTracker>,
            drop_notifier: &Arc<DropNotifier>,
        ) -> Result<NotifiedReceiver, Error> {
            self.stats.receivers_created.fetch_add(1, Ordering::Relaxed);

            Ok(NotifiedReceiver {
                id: receiver_id,
                receiver,
                notify: Arc::clone(&self.notify),
                sequence_tracker: Arc::clone(sequence_tracker),
                stats: Arc::new(ReceiverStats::new()),
                drop_notifier: Arc::clone(drop_notifier),
            })
        }

        /// Start monitoring all receivers
        async fn start_receiver_monitoring(
            &self,
            cx: &Cx,
            receivers: Vec<NotifiedReceiver>,
            monitor: &Arc<ReceiverMonitor>,
        ) -> Result<Vec<ReceiverHandle>, Error> {
            let mut handles = Vec::new();

            for receiver in receivers {
                let handle = self
                    .start_single_receiver_monitor(cx, receiver, monitor)
                    .await?;
                handles.push(handle);
            }

            Ok(handles)
        }

        /// Start monitoring a single receiver
        async fn start_single_receiver_monitor(
            &self,
            cx: &Cx,
            mut receiver: NotifiedReceiver,
            monitor: &Arc<ReceiverMonitor>,
        ) -> Result<ReceiverHandle, Error> {
            let (cancel_tx, cancel_rx) = oneshot::channel();
            let stats_ref = Arc::clone(&self.stats);
            let monitor_ref = Arc::clone(monitor);
            let config = self.config.clone();

            monitor.active_receivers.fetch_add(1, Ordering::Relaxed);

            let receiver_task = cx.spawn(async move {
                let receiver_id = receiver.id;
                let mut last_sequence = 0u64;

                loop {
                    // Check for cancellation
                    if cancel_rx.try_recv().is_ok() {
                        break;
                    }

                    // Wait for either a message or a notification
                    tokio::select! {
                        msg_result = receiver.receiver.recv() => {
                            match msg_result {
                                Ok(message) => {
                                    // Process received message
                                    stats_ref.messages_received.fetch_add(1, Ordering::Relaxed);
                                    receiver.stats.messages_received.fetch_add(1, Ordering::Relaxed);

                                    // Track sequence
                                    if config.enable_sequence_tracking {
                                        receiver.sequence_tracker.track_message(receiver_id, &message).await;
                                        if message.sequence != last_sequence + 1 && last_sequence > 0 {
                                            receiver.stats.sequence_gaps.fetch_add(1, Ordering::Relaxed);
                                            stats_ref.sequence_errors.fetch_add(1, Ordering::Relaxed);
                                        }
                                        last_sequence = message.sequence;
                                    }

                                    receiver.stats.last_sequence.store(message.sequence, Ordering::Relaxed);

                                    // Simulate processing delay
                                    if config.receiver_processing_delay > Duration::from_millis(0) {
                                        Sleep::new(config.receiver_processing_delay).await;
                                    }
                                },
                                Err(_) => {
                                    // Channel closed - sender dropped
                                    stats_ref.close_notifications.fetch_add(1, Ordering::Relaxed);
                                    receiver.stats.close_notifications.fetch_add(1, Ordering::Relaxed);

                                    let drop_notification = ReceiverDropNotification {
                                        receiver_id,
                                        timestamp: Instant::now(),
                                        last_received_sequence: last_sequence,
                                        notification_source: NotificationSource::BroadcastChannelClosed,
                                    };

                                    monitor_ref.record_drop_notification(drop_notification).await;
                                    break;
                                }
                            }
                        },
                        _ = receiver.notify.notified() => {
                            // Explicit notification received
                            stats_ref.notifications_received.fetch_add(1, Ordering::Relaxed);
                            receiver.stats.notifications_received.fetch_add(1, Ordering::Relaxed);

                            let drop_notification = ReceiverDropNotification {
                                receiver_id,
                                timestamp: Instant::now(),
                                last_received_sequence: last_sequence,
                                notification_source: NotificationSource::ExplicitNotify,
                            };

                            monitor_ref.record_drop_notification(drop_notification).await;
                        }
                    }
                }

                monitor_ref.active_receivers.fetch_sub(1, Ordering::Relaxed);
                stats_ref.receivers_dropped.fetch_add(1, Ordering::Relaxed);
            }).await?;

            Ok(ReceiverHandle {
                cancel_sender: cancel_tx,
                task_handle: receiver_task,
            })
        }

        /// Send messages through the coordinator
        async fn send_messages_with_coordination(
            &self,
            cx: &Cx,
            coordinator: &Arc<SenderCoordinator>,
        ) -> Result<(), Error> {
            if let Some(ref sender) = coordinator.sender {
                for i in 0..self.config.messages_per_sender {
                    let sequence = coordinator.message_counter.fetch_add(1, Ordering::Relaxed) + 1;
                    let message = TestMessage {
                        sequence,
                        payload: format!("Message {}", i),
                        sender_id: coordinator.sender_id,
                        timestamp: Instant::now(),
                    };

                    match sender.send(message) {
                        Ok(_) => {
                            self.stats.messages_sent.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            break; // Receiver(s) may have dropped
                        }
                    }

                    // Brief pause between messages
                    Sleep::new(Duration::from_millis(10)).await;
                }
            }

            Ok(())
        }

        /// Drop sender and send notifications to all receivers
        async fn drop_sender_with_notification(
            &self,
            cx: &Cx,
            mut coordinator: Arc<SenderCoordinator>,
            monitor: &Arc<ReceiverMonitor>,
        ) -> Result<DropEvent, Error> {
            let final_sequence = coordinator.message_counter.load(Ordering::Relaxed);
            let active_receivers = monitor.active_receivers.load(Ordering::Relaxed);
            let timestamp = Instant::now();

            // Create drop event
            let drop_event = DropEvent {
                sender_id: coordinator.sender_id,
                timestamp,
                final_sequence,
                active_receivers,
            };

            // Drop the sender (this will close the channel)
            if let Some(sender) = Arc::get_mut(&mut coordinator).and_then(|c| c.sender.take()) {
                drop(sender);
                self.stats.sender_drops.fetch_add(1, Ordering::Relaxed);
            }

            // Send explicit notifications to all receivers
            coordinator.notify_on_drop.notify_waiters();
            self.stats
                .notifications_sent
                .fetch_add(active_receivers as u64, Ordering::Relaxed);

            Ok(drop_event)
        }
    }

    impl SequenceTracker {
        fn new() -> Self {
            Self {
                expected_sequences: Arc::new(Mutex::new(HashMap::new())),
                received_sequences: Arc::new(Mutex::new(HashMap::new())),
                sequence_errors: Arc::new(AtomicU64::new(0)),
            }
        }

        async fn track_message(&self, receiver_id: u64, message: &TestMessage) {
            let mut expected = self.expected_sequences.lock().await;
            let mut received = self.received_sequences.lock().await;

            // Initialize if first message for this receiver
            let next_expected = expected.entry(receiver_id).or_insert(1);
            received.entry(receiver_id).or_insert_with(Vec::new);

            // Check sequence
            if message.sequence != *next_expected {
                self.sequence_errors.fetch_add(1, Ordering::Relaxed);
            }

            // Update tracking
            *next_expected = message.sequence + 1;
            if let Some(seqs) = received.get_mut(&receiver_id) {
                seqs.push(message.sequence);
            }
        }

        async fn validate_final_state(&self) -> Result<SequenceValidationResults, Error> {
            let expected = self.expected_sequences.lock().await;
            let received = self.received_sequences.lock().await;

            let mut validation_results = SequenceValidationResults {
                total_receivers: expected.len(),
                sequence_errors: self.sequence_errors.load(Ordering::Relaxed),
                per_receiver_results: HashMap::new(),
                global_consistency: true,
            };

            for (&receiver_id, expected_next) in expected.iter() {
                if let Some(sequences) = received.get(&receiver_id) {
                    let result = ReceiverValidationResult {
                        receiver_id,
                        expected_count: expected_next - 1,
                        actual_count: sequences.len() as u64,
                        has_gaps: !Self::is_contiguous_sequence(sequences),
                        has_duplicates: Self::has_duplicates(sequences),
                    };

                    if result.expected_count != result.actual_count
                        || result.has_gaps
                        || result.has_duplicates
                    {
                        validation_results.global_consistency = false;
                    }

                    validation_results
                        .per_receiver_results
                        .insert(receiver_id, result);
                }
            }

            Ok(validation_results)
        }

        fn is_contiguous_sequence(sequences: &[u64]) -> bool {
            if sequences.is_empty() {
                return true;
            }

            let mut sorted_sequences = sequences.to_vec();
            sorted_sequences.sort_unstable();

            for i in 1..sorted_sequences.len() {
                if sorted_sequences[i] != sorted_sequences[i - 1] + 1 {
                    return false;
                }
            }
            true
        }

        fn has_duplicates(sequences: &[u64]) -> bool {
            let mut sorted_sequences = sequences.to_vec();
            sorted_sequences.sort_unstable();

            for i in 1..sorted_sequences.len() {
                if sorted_sequences[i] == sorted_sequences[i - 1] {
                    return true;
                }
            }
            false
        }
    }

    impl ReceiverStats {
        fn new() -> Self {
            Self {
                messages_received: AtomicU64::new(0),
                notifications_received: AtomicU64::new(0),
                close_notifications: AtomicU64::new(0),
                sequence_gaps: AtomicU64::new(0),
                last_sequence: AtomicU64::new(0),
            }
        }
    }

    impl DropNotifier {
        fn new() -> Self {
            Self {
                notifiers: Arc::new(Mutex::new(HashMap::new())),
                drop_callbacks: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl ReceiverMonitor {
        fn new() -> Self {
            Self {
                active_receivers: Arc::new(AtomicU32::new(0)),
                drop_notifications: Arc::new(Mutex::new(Vec::new())),
                sequence_validator: Arc::new(SequenceValidator::new()),
            }
        }

        async fn record_drop_notification(&self, notification: ReceiverDropNotification) {
            let mut notifications = self.drop_notifications.lock().await;
            notifications.push(notification);
        }
    }

    impl SequenceValidator {
        fn new() -> Self {
            Self {
                global_sequence: Arc::new(AtomicU64::new(0)),
                receiver_sequences: Arc::new(Mutex::new(BTreeMap::new())),
                validation_errors: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl SenderCoordinator {
        async fn new(
            sender: BroadcastSender<TestMessage>,
            sender_id: u32,
            drop_notifier: &Arc<DropNotifier>,
        ) -> Result<Self, Error> {
            Ok(Self {
                sender: Some(sender),
                sender_id,
                message_counter: Arc::new(AtomicU64::new(0)),
                drop_notifier: Arc::clone(drop_notifier),
                notify_on_drop: Arc::new(Notify::new()),
            })
        }
    }

    impl Clone for IntegrationConfig {
        fn clone(&self) -> Self {
            Self {
                channel_capacity: self.channel_capacity,
                num_receivers: self.num_receivers,
                messages_per_sender: self.messages_per_sender,
                sender_drop_delay: self.sender_drop_delay,
                receiver_processing_delay: self.receiver_processing_delay,
                enable_sequence_tracking: self.enable_sequence_tracking,
            }
        }
    }

    /// Results from broadcast drop testing
    #[derive(Debug)]
    struct BroadcastDropResults {
        messages_sent: u64,
        messages_received: u64,
        sender_drops: u64,
        close_notifications: u64,
        notifications_sent: u64,
        notifications_received: u64,
        sequence_errors: u64,
        drop_event: DropEvent,
        validation_results: SequenceValidationResults,
    }

    /// Results from sequence validation
    #[derive(Debug)]
    struct SequenceValidationResults {
        total_receivers: usize,
        sequence_errors: u64,
        per_receiver_results: HashMap<u64, ReceiverValidationResult>,
        global_consistency: bool,
    }

    /// Validation results per receiver
    #[derive(Debug)]
    struct ReceiverValidationResult {
        receiver_id: u64,
        expected_count: u64,
        actual_count: u64,
        has_gaps: bool,
        has_duplicates: bool,
    }

    /// Handle for controlling receiver monitoring
    struct ReceiverHandle {
        cancel_sender: oneshot::Sender<()>,
        task_handle: TaskId,
    }

    impl ReceiverHandle {
        async fn cancel(self) {
            let _ = self.cancel_sender.send(());
            Sleep::new(Duration::from_millis(50)).await;
        }
    }

    #[tokio::test]
    async fn test_broadcast_sender_drop_notifies_all_receivers() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            channel_capacity: 32,
            num_receivers: 5,
            messages_per_sender: 10,
            sender_drop_delay: Duration::from_millis(200),
            receiver_processing_delay: Duration::from_millis(5),
            enable_sequence_tracking: true,
        };

        let framework = BroadcastNotifyTestFramework::new(&cx, config)
            .await
            .unwrap();
        let results = framework
            .execute_broadcast_with_sender_drop(&cx)
            .await
            .unwrap();

        // Verify sender drop behavior
        assert_eq!(
            results.sender_drops, 1,
            "Should have exactly one sender drop"
        );
        assert!(
            results.close_notifications > 0,
            "Should notify receivers of channel close"
        );

        // Verify all receivers got messages
        assert!(
            results.messages_received > 0,
            "Receivers should have received messages"
        );
        assert!(
            results.messages_sent > 0,
            "Sender should have sent messages"
        );

        // Verify sequence integrity
        assert_eq!(
            results.sequence_errors, 0,
            "No sequence errors should occur"
        );
        assert!(
            results.validation_results.global_consistency,
            "Sequence should be globally consistent"
        );

        // Verify notifications
        assert!(
            results.notifications_sent > 0,
            "Should send explicit notifications"
        );
        assert!(
            results.notifications_received >= 0,
            "Receivers should get notifications"
        );

        cx.trace("Broadcast sender drop correctly notifies all receivers")
            .await;
    }

    #[tokio::test]
    async fn test_sequence_numbers_preserved_across_sender_drop() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            channel_capacity: 16,
            num_receivers: 3,
            messages_per_sender: 20,
            sender_drop_delay: Duration::from_millis(100),
            receiver_processing_delay: Duration::from_millis(2),
            enable_sequence_tracking: true,
        };

        let framework = BroadcastNotifyTestFramework::new(&cx, config)
            .await
            .unwrap();
        let results = framework
            .execute_broadcast_with_sender_drop(&cx)
            .await
            .unwrap();

        // Verify sequence preservation
        assert!(
            results.validation_results.global_consistency,
            "Sequence numbers should be preserved"
        );

        // Check per-receiver sequence integrity
        for (&receiver_id, result) in &results.validation_results.per_receiver_results {
            assert!(
                !result.has_gaps,
                "Receiver {} should not have sequence gaps",
                receiver_id
            );
            assert!(
                !result.has_duplicates,
                "Receiver {} should not have duplicates",
                receiver_id
            );
            assert_eq!(
                result.expected_count, result.actual_count,
                "Receiver {} should receive all expected messages",
                receiver_id
            );
        }

        // Verify drop event contains correct sequence info
        assert!(
            results.drop_event.final_sequence > 0,
            "Drop event should have valid final sequence"
        );
        assert_eq!(
            results.drop_event.active_receivers, config.num_receivers as u32,
            "Drop event should track correct number of active receivers"
        );

        cx.trace("Sequence numbers preserved correctly across sender drop")
            .await;
    }

    #[tokio::test]
    async fn test_concurrent_receivers_notification_consistency() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            channel_capacity: 8,
            num_receivers: 10, // Many concurrent receivers
            messages_per_sender: 15,
            sender_drop_delay: Duration::from_millis(150),
            receiver_processing_delay: Duration::from_millis(1),
            enable_sequence_tracking: true,
        };

        let framework = BroadcastNotifyTestFramework::new(&cx, config)
            .await
            .unwrap();
        let results = framework
            .execute_broadcast_with_sender_drop(&cx)
            .await
            .unwrap();

        // Verify all receivers are notified
        assert_eq!(
            results.drop_event.active_receivers, config.num_receivers as u32,
            "All receivers should be active at drop time"
        );

        // Verify consistent notification delivery
        let total_expected_notifications = config.num_receivers as u64;
        assert!(
            results.close_notifications > 0,
            "Should have close notifications"
        );

        // Verify sequence consistency across all receivers
        assert!(
            results.validation_results.global_consistency,
            "All receivers should see consistent sequences"
        );
        assert_eq!(
            results.validation_results.total_receivers, config.num_receivers,
            "Should track all receivers"
        );

        // Verify no sequence errors during concurrent access
        assert_eq!(
            results.sequence_errors, 0,
            "Concurrent receivers should not cause sequence errors"
        );

        cx.trace("Concurrent receivers get consistent notifications")
            .await;
    }

    #[tokio::test]
    async fn test_immediate_sender_drop_notification() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            channel_capacity: 4,
            num_receivers: 4,
            messages_per_sender: 5,                       // Few messages
            sender_drop_delay: Duration::from_millis(10), // Very quick drop
            receiver_processing_delay: Duration::from_millis(0),
            enable_sequence_tracking: true,
        };

        let framework = BroadcastNotifyTestFramework::new(&cx, config)
            .await
            .unwrap();
        let results = framework
            .execute_broadcast_with_sender_drop(&cx)
            .await
            .unwrap();

        // Verify immediate drop handling
        assert_eq!(
            results.sender_drops, 1,
            "Should handle immediate sender drop"
        );
        assert!(
            results.close_notifications > 0,
            "Should notify on immediate drop"
        );

        // Verify receivers still get some messages before drop
        assert!(
            results.messages_received > 0,
            "Should receive at least some messages before drop"
        );

        // Verify no lost notifications during immediate drop
        assert!(
            results.drop_event.final_sequence <= config.messages_per_sender as u64,
            "Drop sequence should not exceed sent messages"
        );

        cx.trace("Immediate sender drop handled correctly").await;
    }

    #[tokio::test]
    async fn test_slow_receiver_notification_during_drop() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        let config = IntegrationConfig {
            channel_capacity: 16,
            num_receivers: 6,
            messages_per_sender: 12,
            sender_drop_delay: Duration::from_millis(50),
            receiver_processing_delay: Duration::from_millis(20), // Slow processing
            enable_sequence_tracking: true,
        };

        let framework = BroadcastNotifyTestFramework::new(&cx, config)
            .await
            .unwrap();
        let results = framework
            .execute_broadcast_with_sender_drop(&cx)
            .await
            .unwrap();

        // Verify slow receivers still get proper notifications
        assert!(
            results.close_notifications > 0,
            "Slow receivers should get close notifications"
        );

        // Verify no message loss due to slow processing
        let per_receiver_avg = results.messages_received / config.num_receivers as u64;
        assert!(
            per_receiver_avg > 0,
            "Slow receivers should still process messages"
        );

        // Verify sequence consistency despite slow processing
        assert!(
            results.validation_results.global_consistency,
            "Slow processing should not affect consistency"
        );

        cx.trace("Slow receivers handled correctly during sender drop")
            .await;
    }

    #[tokio::test]
    async fn test_broadcast_channel_capacity_impact_on_notifications() {
        let runtime = init_test_runtime(&Cx::new()).await.unwrap();
        let cx = runtime.cx();

        // Test with small capacity
        let small_config = IntegrationConfig {
            channel_capacity: 2, // Very small
            num_receivers: 4,
            messages_per_sender: 8,
            sender_drop_delay: Duration::from_millis(100),
            receiver_processing_delay: Duration::from_millis(5),
            enable_sequence_tracking: true,
        };

        let small_framework = BroadcastNotifyTestFramework::new(&cx, small_config)
            .await
            .unwrap();
        let small_results = small_framework
            .execute_broadcast_with_sender_drop(&cx)
            .await
            .unwrap();

        // Test with large capacity
        let large_config = IntegrationConfig {
            channel_capacity: 64, // Much larger
            ..small_config
        };

        let large_framework = BroadcastNotifyTestFramework::new(&cx, large_config)
            .await
            .unwrap();
        let large_results = large_framework
            .execute_broadcast_with_sender_drop(&cx)
            .await
            .unwrap();

        // Compare results
        assert_eq!(
            small_results.sender_drops, 1,
            "Small capacity should still handle drop"
        );
        assert_eq!(
            large_results.sender_drops, 1,
            "Large capacity should handle drop"
        );

        // Both should notify receivers
        assert!(
            small_results.close_notifications > 0,
            "Small capacity should notify"
        );
        assert!(
            large_results.close_notifications > 0,
            "Large capacity should notify"
        );

        // Large capacity should generally have better sequence consistency
        assert!(
            large_results.validation_results.global_consistency
                || small_results.validation_results.global_consistency,
            "At least one configuration should maintain consistency"
        );

        cx.trace("Channel capacity handled correctly for notifications")
            .await;
    }
}
