//! br-e2e-222: stream/debounce ↔ sync/notify integration E2E tests
//!
//! Tests integration between stream debouncing and synchronization notification
//! for coordinated stream processing with backpressure and synchronized delivery.

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use crate::channel::broadcast::{Receiver, Sender, channel as broadcast_channel};
    use crate::cx::{Cx, Scope};
    use crate::error::AsupersyncError;
    use crate::runtime::{Runtime, RuntimeBuilder};
    use crate::stream::debounce::{DebounceConfig, DebounceState, DebounceStream};
    use crate::stream::{Stream, StreamExt};
    use crate::sync::notify::{Notify, NotifyState, NotifyWaitGuard};
    use crate::time::{Duration, Instant, sleep};
    use crate::types::{Budget, Outcome, RegionId, TaskId};

    use std::collections::{HashMap, VecDeque};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::task::{Context, Poll};

    /// Configuration for debounced notification coordination
    #[derive(Debug, Clone)]
    struct DebouncedNotifyConfig {
        /// Debounce duration for stream events
        pub debounce_duration: Duration,
        /// Maximum batch size for debounced events
        pub max_batch_size: usize,
        /// Notification coordination timeout
        pub notify_timeout: Duration,
        /// Stream buffer capacity
        pub stream_buffer_capacity: usize,
        /// Notification queue depth
        pub notify_queue_depth: usize,
        /// Coordination check interval
        pub coordination_interval: Duration,
    }

    impl Default for DebouncedNotifyConfig {
        fn default() -> Self {
            Self {
                debounce_duration: Duration::from_millis(100),
                max_batch_size: 50,
                notify_timeout: Duration::from_secs(2),
                stream_buffer_capacity: 1000,
                notify_queue_depth: 100,
                coordination_interval: Duration::from_millis(50),
            }
        }
    }

    /// Event with debounce and notification metadata
    #[derive(Debug, Clone, PartialEq)]
    struct CoordinatedEvent {
        /// Event payload
        pub data: String,
        /// Event timestamp for debouncing
        pub timestamp: Instant,
        /// Event priority for ordering
        pub priority: u32,
        /// Batch identifier for grouping
        pub batch_id: Option<u64>,
        /// Notification group for coordination
        pub notify_group: String,
    }

    /// Statistics for debounced notification coordination
    #[derive(Debug, Default)]
    struct DebouncedNotifyStats {
        /// Events received in stream
        pub events_received: AtomicU64,
        /// Events debounced (filtered out)
        pub events_debounced: AtomicU64,
        /// Events delivered after debouncing
        pub events_delivered: AtomicU64,
        /// Notifications sent
        pub notifications_sent: AtomicU64,
        /// Notification waits completed
        pub notification_waits_completed: AtomicU64,
        /// Coordination cycles completed
        pub coordination_cycles: AtomicU64,
        /// Coordination errors encountered
        pub coordination_errors: AtomicU64,
    }

    /// Coordination strategy for debounced notifications
    #[derive(Debug, Clone)]
    enum CoordinationStrategy {
        /// Immediate notification after debounce
        ImmediateNotify,
        /// Batch notification with size threshold
        BatchNotify { batch_threshold: usize },
        /// Time-based notification with fixed intervals
        TimeBasedNotify { interval: Duration },
        /// Adaptive notification based on load
        AdaptiveNotify { load_threshold: f64 },
    }

    /// Comprehensive debounced notification coordination system
    struct DebouncedNotifySystem {
        config: DebouncedNotifyConfig,
        debounce_stream: DebounceStream<CoordinatedEvent>,
        notify_map: HashMap<String, Arc<Notify>>,
        event_buffer: VecDeque<CoordinatedEvent>,
        pending_notifications: HashMap<String, Vec<CoordinatedEvent>>,
        broadcast_sender: Sender<CoordinatedEvent>,
        broadcast_receiver: Receiver<CoordinatedEvent>,
        stats: Arc<DebouncedNotifyStats>,
        strategy: CoordinationStrategy,
        is_running: AtomicBool,
    }

    impl DebouncedNotifySystem {
        /// Create new debounced notification system
        fn new(
            config: DebouncedNotifyConfig,
            strategy: CoordinationStrategy,
        ) -> Result<Self, AsupersyncError> {
            let debounce_config = DebounceConfig {
                duration: config.debounce_duration,
                max_size: config.max_batch_size,
            };
            let debounce_stream = DebounceStream::new(debounce_config)?;

            let (broadcast_sender, broadcast_receiver) =
                broadcast_channel(config.stream_buffer_capacity);

            Ok(Self {
                config,
                debounce_stream,
                notify_map: HashMap::new(),
                event_buffer: VecDeque::new(),
                pending_notifications: HashMap::new(),
                broadcast_sender,
                broadcast_receiver,
                stats: Arc::new(DebouncedNotifyStats::default()),
                strategy,
                is_running: AtomicBool::new(false),
            })
        }

        /// Start the coordination system
        async fn start(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            self.is_running.store(true, Ordering::SeqCst);

            // Start debounce processing loop
            let debounce_handle = cx
                .spawn(|cx| async move { self.run_debounce_processor(cx).await })
                .await?;

            // Start notification coordinator
            let notify_handle = cx
                .spawn(|cx| async move { self.run_notification_coordinator(cx).await })
                .await?;

            // Start event delivery loop
            let delivery_handle = cx
                .spawn(|cx| async move { self.run_event_delivery(cx).await })
                .await?;

            // Start coordination loop
            let coordination_handle = cx
                .spawn(|cx| async move { self.run_coordination_loop(cx).await })
                .await?;

            Ok(())
        }

        /// Submit event for debounced processing
        async fn submit_event(
            &mut self,
            event: CoordinatedEvent,
            cx: &Cx,
        ) -> Result<(), AsupersyncError> {
            // Add to debounce stream
            self.debounce_stream.submit(event.clone()).await?;
            self.stats.events_received.fetch_add(1, Ordering::SeqCst);

            // Ensure notification group exists
            let notify_group = event.notify_group.clone();
            if !self.notify_map.contains_key(&notify_group) {
                self.notify_map
                    .insert(notify_group, Arc::new(Notify::new()));
            }

            Ok(())
        }

        /// Run debounce processor loop
        async fn run_debounce_processor(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            while self.is_running.load(Ordering::SeqCst) {
                // Process debounced events
                match self.debounce_stream.next().await {
                    Some(debounced_batch) => {
                        for event in debounced_batch {
                            self.process_debounced_event(event, cx).await?;
                        }
                    }
                    None => {
                        // No events available, short sleep
                        sleep(Duration::from_millis(10), cx).await?;
                    }
                }
            }

            Ok(())
        }

        /// Process single debounced event
        async fn process_debounced_event(
            &mut self,
            event: CoordinatedEvent,
            cx: &Cx,
        ) -> Result<(), AsupersyncError> {
            // Apply coordination strategy
            match &self.strategy {
                CoordinationStrategy::ImmediateNotify => {
                    self.handle_immediate_notify(event, cx).await?;
                }
                CoordinationStrategy::BatchNotify { batch_threshold } => {
                    self.handle_batch_notify(event, *batch_threshold, cx)
                        .await?;
                }
                CoordinationStrategy::TimeBasedNotify { interval } => {
                    self.handle_time_based_notify(event, *interval, cx).await?;
                }
                CoordinationStrategy::AdaptiveNotify { load_threshold } => {
                    self.handle_adaptive_notify(event, *load_threshold, cx)
                        .await?;
                }
            }

            self.stats.events_delivered.fetch_add(1, Ordering::SeqCst);

            Ok(())
        }

        /// Handle immediate notification strategy
        async fn handle_immediate_notify(
            &mut self,
            event: CoordinatedEvent,
            cx: &Cx,
        ) -> Result<(), AsupersyncError> {
            // Immediately deliver and notify
            self.deliver_event(event.clone(), cx).await?;

            if let Some(notify) = self.notify_map.get(&event.notify_group) {
                notify.notify_one();
                self.stats.notifications_sent.fetch_add(1, Ordering::SeqCst);
            }

            Ok(())
        }

        /// Handle batch notification strategy
        async fn handle_batch_notify(
            &mut self,
            event: CoordinatedEvent,
            batch_threshold: usize,
            cx: &Cx,
        ) -> Result<(), AsupersyncError> {
            // Add to pending notifications for this group
            let notify_group = event.notify_group.clone();
            let pending = self
                .pending_notifications
                .entry(notify_group.clone())
                .or_insert_with(Vec::new);
            pending.push(event);

            // Check if batch threshold reached
            if pending.len() >= batch_threshold {
                // Deliver entire batch
                for pending_event in pending.drain(..) {
                    self.deliver_event(pending_event, cx).await?;
                }

                // Send batch notification
                if let Some(notify) = self.notify_map.get(&notify_group) {
                    notify.notify_waiters();
                    self.stats.notifications_sent.fetch_add(1, Ordering::SeqCst);
                }
            }

            Ok(())
        }

        /// Handle time-based notification strategy
        async fn handle_time_based_notify(
            &mut self,
            event: CoordinatedEvent,
            interval: Duration,
            cx: &Cx,
        ) -> Result<(), AsupersyncError> {
            // Buffer event for time-based delivery
            self.event_buffer.push_back(event);

            // Check if interval elapsed (simplified check)
            if self.event_buffer.len() > 0 {
                let now = Instant::now();
                if let Some(first_event) = self.event_buffer.front() {
                    if now.duration_since(first_event.timestamp) >= interval {
                        self.flush_time_based_events(cx).await?;
                    }
                }
            }

            Ok(())
        }

        /// Flush time-based buffered events
        async fn flush_time_based_events(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            let mut notify_groups = HashSet::new();

            while let Some(event) = self.event_buffer.pop_front() {
                notify_groups.insert(event.notify_group.clone());
                self.deliver_event(event, cx).await?;
            }

            // Send notifications to all affected groups
            for group in notify_groups {
                if let Some(notify) = self.notify_map.get(&group) {
                    notify.notify_waiters();
                    self.stats.notifications_sent.fetch_add(1, Ordering::SeqCst);
                }
            }

            Ok(())
        }

        /// Handle adaptive notification strategy
        async fn handle_adaptive_notify(
            &mut self,
            event: CoordinatedEvent,
            load_threshold: f64,
            cx: &Cx,
        ) -> Result<(), AsupersyncError> {
            let current_load = self.calculate_system_load();

            if current_load > load_threshold {
                // High load: use batch strategy
                self.handle_batch_notify(event, 20, cx).await?;
            } else {
                // Low load: use immediate strategy
                self.handle_immediate_notify(event, cx).await?;
            }

            Ok(())
        }

        /// Calculate current system load
        fn calculate_system_load(&self) -> f64 {
            let buffer_load =
                self.event_buffer.len() as f64 / self.config.stream_buffer_capacity as f64;
            let pending_load = self
                .pending_notifications
                .values()
                .map(|v| v.len())
                .sum::<usize>() as f64
                / (self.config.notify_queue_depth * self.notify_map.len().max(1)) as f64;

            (buffer_load + pending_load) / 2.0
        }

        /// Deliver event via broadcast channel
        async fn deliver_event(
            &mut self,
            event: CoordinatedEvent,
            cx: &Cx,
        ) -> Result<(), AsupersyncError> {
            match self.broadcast_sender.send(event, cx).await {
                Ok(()) => {
                    self.stats.events_delivered.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => {
                    self.stats
                        .coordination_errors
                        .fetch_add(1, Ordering::SeqCst);
                    return Err(AsupersyncError::ChannelError(format!(
                        "Event delivery failed: {:?}",
                        e
                    )));
                }
            }

            Ok(())
        }

        /// Run notification coordinator loop
        async fn run_notification_coordinator(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            while self.is_running.load(Ordering::SeqCst) {
                // Process any pending time-based notifications
                if !self.event_buffer.is_empty() {
                    let now = Instant::now();
                    let needs_flush = self
                        .event_buffer
                        .front()
                        .map(|event| {
                            now.duration_since(event.timestamp) >= self.config.debounce_duration
                        })
                        .unwrap_or(false);

                    if needs_flush {
                        self.flush_time_based_events(cx).await?;
                    }
                }

                // Periodic notification group cleanup
                self.cleanup_notification_groups().await?;

                sleep(self.config.coordination_interval, cx).await?;
            }

            Ok(())
        }

        /// Clean up unused notification groups
        async fn cleanup_notification_groups(&mut self) -> Result<(), AsupersyncError> {
            // Remove notification groups with no pending events
            let empty_groups: Vec<_> = self
                .pending_notifications
                .iter()
                .filter(|(_, events)| events.is_empty())
                .map(|(group, _)| group.clone())
                .collect();

            for group in empty_groups {
                self.pending_notifications.remove(&group);
            }

            Ok(())
        }

        /// Run event delivery processing loop
        async fn run_event_delivery(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            while self.is_running.load(Ordering::SeqCst) {
                match self.broadcast_receiver.recv(cx).await {
                    Ok(event) => {
                        self.process_delivered_event(event, cx).await?;
                    }
                    Err(_) => {
                        // Channel closed or no events
                        sleep(Duration::from_millis(5), cx).await?;
                    }
                }
            }

            Ok(())
        }

        /// Process delivered event (for monitoring/stats)
        async fn process_delivered_event(
            &mut self,
            event: CoordinatedEvent,
            cx: &Cx,
        ) -> Result<(), AsupersyncError> {
            // Track delivery metrics
            self.stats.events_delivered.fetch_add(1, Ordering::SeqCst);

            // Verify coordination is working
            if let Some(notify) = self.notify_map.get(&event.notify_group) {
                // Check if anyone is waiting for this notification group
                // (In a real implementation, this would be more sophisticated)
            }

            Ok(())
        }

        /// Run coordination loop for system management
        async fn run_coordination_loop(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            let mut cycle_count = 0u64;

            while self.is_running.load(Ordering::SeqCst) {
                // Periodic coordination tasks
                if cycle_count % 50 == 0 {
                    self.check_coordination_health().await?;
                    self.optimize_debounce_parameters().await?;
                    self.log_coordination_metrics().await?;
                }

                cycle_count += 1;
                self.stats
                    .coordination_cycles
                    .fetch_add(1, Ordering::SeqCst);

                sleep(self.config.coordination_interval, cx).await?;
            }

            Ok(())
        }

        /// Check coordination health
        async fn check_coordination_health(&mut self) -> Result<(), AsupersyncError> {
            let received = self.stats.events_received.load(Ordering::SeqCst);
            let delivered = self.stats.events_delivered.load(Ordering::SeqCst);

            // Check for delivery lag
            if received > 0 && delivered as f64 / (received as f64) < 0.8 {
                self.stats
                    .coordination_errors
                    .fetch_add(1, Ordering::SeqCst);
            }

            Ok(())
        }

        /// Optimize debounce parameters based on current load
        async fn optimize_debounce_parameters(&mut self) -> Result<(), AsupersyncError> {
            let load = self.calculate_system_load();

            // Adjust strategy based on load
            if load > 0.7 {
                self.strategy = CoordinationStrategy::BatchNotify {
                    batch_threshold: 30,
                };
            } else if load < 0.3 {
                self.strategy = CoordinationStrategy::ImmediateNotify;
            }

            Ok(())
        }

        /// Log coordination metrics
        async fn log_coordination_metrics(&self) -> Result<(), AsupersyncError> {
            let received = self.stats.events_received.load(Ordering::SeqCst);
            let debounced = self.stats.events_debounced.load(Ordering::SeqCst);
            let delivered = self.stats.events_delivered.load(Ordering::SeqCst);
            let notifications = self.stats.notifications_sent.load(Ordering::SeqCst);
            let errors = self.stats.coordination_errors.load(Ordering::SeqCst);

            eprintln!(
                "DebouncedNotify Metrics: received={}, debounced={}, delivered={}, notifications={}, errors={}",
                received, debounced, delivered, notifications, errors
            );

            Ok(())
        }

        /// Wait for notification in specific group
        async fn wait_for_notification(&self, group: &str, cx: &Cx) -> Result<(), AsupersyncError> {
            if let Some(notify) = self.notify_map.get(group) {
                let timeout =
                    crate::time::timeout(self.config.notify_timeout, notify.notified(), cx).await;
                match timeout {
                    Ok(()) => {
                        self.stats
                            .notification_waits_completed
                            .fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }
                    Err(_) => Err(AsupersyncError::Timeout(
                        "Notification wait timed out".to_string(),
                    )),
                }
            } else {
                Err(AsupersyncError::InvalidState(
                    "Notification group not found".to_string(),
                ))
            }
        }

        /// Stop the coordination system
        async fn stop(&mut self) -> Result<(), AsupersyncError> {
            self.is_running.store(false, Ordering::SeqCst);
            Ok(())
        }

        /// Get coordination statistics
        fn get_stats(&self) -> DebouncedNotifyStats {
            DebouncedNotifyStats {
                events_received: AtomicU64::new(self.stats.events_received.load(Ordering::SeqCst)),
                events_debounced: AtomicU64::new(
                    self.stats.events_debounced.load(Ordering::SeqCst),
                ),
                events_delivered: AtomicU64::new(
                    self.stats.events_delivered.load(Ordering::SeqCst),
                ),
                notifications_sent: AtomicU64::new(
                    self.stats.notifications_sent.load(Ordering::SeqCst),
                ),
                notification_waits_completed: AtomicU64::new(
                    self.stats
                        .notification_waits_completed
                        .load(Ordering::SeqCst),
                ),
                coordination_cycles: AtomicU64::new(
                    self.stats.coordination_cycles.load(Ordering::SeqCst),
                ),
                coordination_errors: AtomicU64::new(
                    self.stats.coordination_errors.load(Ordering::SeqCst),
                ),
            }
        }
    }

    /// Test basic debounced notification integration
    #[tokio::test]
    async fn test_basic_debounced_notify_integration() -> Result<(), AsupersyncError> {
        let runtime = RuntimeBuilder::new().build().await?;
        let cx = runtime.cx();

        cx.scope(|cx| async move {
            let config = DebouncedNotifyConfig::default();
            let strategy = CoordinationStrategy::ImmediateNotify;
            let mut system = DebouncedNotifySystem::new(config, strategy)?;

            // Start coordination system
            system.start(cx).await?;

            // Submit test events
            let now = Instant::now();
            let events = vec![
                CoordinatedEvent {
                    data: "Event 1".to_string(),
                    timestamp: now,
                    priority: 1,
                    batch_id: Some(1),
                    notify_group: "group_a".to_string(),
                },
                CoordinatedEvent {
                    data: "Event 2".to_string(),
                    timestamp: now + Duration::from_millis(50),
                    priority: 2,
                    batch_id: Some(1),
                    notify_group: "group_a".to_string(),
                },
                CoordinatedEvent {
                    data: "Event 3".to_string(),
                    timestamp: now + Duration::from_millis(150),
                    priority: 1,
                    batch_id: Some(2),
                    notify_group: "group_b".to_string(),
                },
            ];

            // Submit events with small delays
            for event in events {
                system.submit_event(event, cx).await?;
                sleep(Duration::from_millis(20), cx).await?;
            }

            // Allow processing time
            sleep(Duration::from_millis(300), cx).await?;

            // Test notification waiting
            let wait_result = system.wait_for_notification("group_a", cx).await;

            system.stop().await?;

            // Verify coordination worked
            let stats = system.get_stats();
            assert_eq!(stats.events_received.load(Ordering::SeqCst), 3);
            assert!(stats.events_delivered.load(Ordering::SeqCst) > 0);
            assert!(stats.notifications_sent.load(Ordering::SeqCst) > 0);
            assert!(stats.coordination_cycles.load(Ordering::SeqCst) > 0);
            assert_eq!(stats.coordination_errors.load(Ordering::SeqCst), 0);

            Ok(())
        })
        .await
    }

    /// Test batch notification coordination
    #[tokio::test]
    async fn test_batch_notification_coordination() -> Result<(), AsupersyncError> {
        let runtime = RuntimeBuilder::new().build().await?;
        let cx = runtime.cx();

        cx.scope(|cx| async move {
            let config = DebouncedNotifyConfig::default();
            let strategy = CoordinationStrategy::BatchNotify { batch_threshold: 3 };
            let mut system = DebouncedNotifySystem::new(config, strategy)?;

            system.start(cx).await?;

            // Submit batch of events to same group
            let now = Instant::now();
            let batch_events = (0..5)
                .map(|i| CoordinatedEvent {
                    data: format!("Batch Event {}", i),
                    timestamp: now + Duration::from_millis(i * 10),
                    priority: 1,
                    batch_id: Some(100),
                    notify_group: "batch_group".to_string(),
                })
                .collect::<Vec<_>>();

            // Submit all events quickly
            for event in batch_events {
                system.submit_event(event, cx).await?;
            }

            // Allow batch processing
            sleep(Duration::from_millis(200), cx).await?;

            system.stop().await?;

            // Verify batch processing
            let stats = system.get_stats();
            assert_eq!(stats.events_received.load(Ordering::SeqCst), 5);
            assert!(stats.notifications_sent.load(Ordering::SeqCst) >= 1); // At least one batch notification
            assert!(stats.coordination_errors.load(Ordering::SeqCst) == 0);

            Ok(())
        })
        .await
    }

    /// Test adaptive coordination strategy
    #[tokio::test]
    async fn test_adaptive_coordination() -> Result<(), AsupersyncError> {
        let runtime = RuntimeBuilder::new().build().await?;
        let cx = runtime.cx();

        cx.scope(|cx| async move {
            let config = DebouncedNotifyConfig {
                stream_buffer_capacity: 50, // Smaller capacity to test adaptation
                ..DebouncedNotifyConfig::default()
            };
            let strategy = CoordinationStrategy::AdaptiveNotify {
                load_threshold: 0.5,
            };
            let mut system = DebouncedNotifySystem::new(config, strategy)?;

            system.start(cx).await?;

            // Submit high load to trigger adaptation
            let now = Instant::now();
            let high_load_events = (0..40)
                .map(|i| CoordinatedEvent {
                    data: format!("Load Event {}", i),
                    timestamp: now + Duration::from_millis(i * 5),
                    priority: i % 3,
                    batch_id: Some(200 + (i / 10) as u64),
                    notify_group: format!("group_{}", i % 5),
                })
                .collect::<Vec<_>>();

            // Submit events quickly to create load
            for event in high_load_events {
                system.submit_event(event, cx).await?;
                // Very small delay to simulate realistic load
                sleep(Duration::from_millis(1), cx).await?;
            }

            // Allow adaptive processing
            sleep(Duration::from_millis(500), cx).await?;

            system.stop().await?;

            // Verify adaptive behavior handled load
            let stats = system.get_stats();
            assert_eq!(stats.events_received.load(Ordering::SeqCst), 40);
            assert!(stats.notifications_sent.load(Ordering::SeqCst) > 5); // Multiple notifications
            assert!(stats.coordination_cycles.load(Ordering::SeqCst) > 5); // Active coordination

            // Should have low error rate even under high load
            let error_rate = stats.coordination_errors.load(Ordering::SeqCst) as f64 / 40.0;
            assert!(error_rate < 0.1, "Error rate too high: {}", error_rate);

            Ok(())
        })
        .await
    }
}
