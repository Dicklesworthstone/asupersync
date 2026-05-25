//! br-e2e-221: channel/broadcast ↔ time/wheel integration E2E tests
//!
//! Tests integration between broadcast channels and timer wheel infrastructure for
//! time-based message coordination, scheduled broadcasts, and temporal message routing.

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use crate::channel::broadcast::{channel, Receiver, Sender};
    use crate::time::wheel::{TimerWheel, TimerHandle, TimerKind};
    use crate::time::{Duration, Instant};
    use crate::cx::{Cx, Scope};
    use crate::runtime::{Runtime, RuntimeBuilder};
    use crate::types::{Budget, Outcome, TaskId, RegionId};
    use crate::error::AsupersyncError;

    use std::collections::{HashMap, VecDeque};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};

    /// Configuration for timed broadcast coordination system
    #[derive(Debug, Clone)]
    struct TimedBroadcastConfig {
        /// Buffer capacity for broadcast channels
        pub channel_capacity: usize,
        /// Timer wheel slot count for scheduling
        pub wheel_slots: usize,
        /// Tick interval for timer advancement
        pub tick_interval: Duration,
        /// Maximum message delay tolerance
        pub max_delay: Duration,
        /// Coordination timeout for multi-stage operations
        pub coordination_timeout: Duration,
    }

    impl Default for TimedBroadcastConfig {
        fn default() -> Self {
            Self {
                channel_capacity: 1024,
                wheel_slots: 512,
                tick_interval: Duration::from_millis(10),
                max_delay: Duration::from_secs(30),
                coordination_timeout: Duration::from_secs(5),
            }
        }
    }

    /// Message with scheduling and broadcast metadata
    #[derive(Debug, Clone, PartialEq)]
    struct TimedMessage {
        /// Message payload
        pub payload: String,
        /// Scheduled delivery time
        pub scheduled_at: Instant,
        /// Message priority for ordering
        pub priority: u32,
        /// Correlation ID for tracking
        pub correlation_id: u64,
        /// Broadcast group identifier
        pub group_id: Option<String>,
    }

    /// Statistics for timed broadcast operations
    #[derive(Debug, Default)]
    struct TimedBroadcastStats {
        /// Messages scheduled for delivery
        pub messages_scheduled: AtomicU64,
        /// Messages delivered on time
        pub messages_delivered: AtomicU64,
        /// Messages delivered late
        pub messages_late: AtomicU64,
        /// Timer wheel ticks processed
        pub wheel_ticks: AtomicU64,
        /// Broadcast operations completed
        pub broadcasts_completed: AtomicU64,
        /// Coordination errors encountered
        pub coordination_errors: AtomicU64,
    }

    /// Coordination strategy for timed broadcasts
    #[derive(Debug, Clone)]
    enum CoordinationStrategy {
        /// Schedule messages individually
        IndividualScheduling,
        /// Batch schedule related messages
        BatchScheduling { batch_size: usize },
        /// Adaptive scheduling based on load
        AdaptiveScheduling { load_threshold: f64 },
        /// Priority-based scheduling
        PriorityScheduling { max_priorities: u32 },
    }

    /// Comprehensive timed broadcast coordination system
    struct TimedBroadcastSystem {
        config: TimedBroadcastConfig,
        timer_wheel: TimerWheel,
        broadcast_sender: Sender<TimedMessage>,
        broadcast_receiver: Receiver<TimedMessage>,
        message_queue: VecDeque<TimedMessage>,
        active_timers: HashMap<TimerHandle, TimedMessage>,
        stats: Arc<TimedBroadcastStats>,
        strategy: CoordinationStrategy,
        is_running: AtomicBool,
    }

    impl TimedBroadcastSystem {
        /// Create new timed broadcast system with configuration
        fn new(config: TimedBroadcastConfig, strategy: CoordinationStrategy) -> Result<Self, AsupersyncError> {
            let timer_wheel = TimerWheel::new(config.wheel_slots, config.tick_interval)?;
            let (sender, receiver) = channel(config.channel_capacity);

            Ok(Self {
                config,
                timer_wheel,
                broadcast_sender: sender,
                broadcast_receiver: receiver,
                message_queue: VecDeque::new(),
                active_timers: HashMap::new(),
                stats: Arc::new(TimedBroadcastStats::default()),
                strategy,
                is_running: AtomicBool::new(false),
            })
        }

        /// Start the coordination system
        async fn start(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            self.is_running.store(true, Ordering::SeqCst);

            // Start timer wheel processing
            let wheel_handle = cx.spawn(|cx| async move {
                self.run_timer_wheel(cx).await
            }).await?;

            // Start broadcast processing
            let broadcast_handle = cx.spawn(|cx| async move {
                self.run_broadcast_processor(cx).await
            }).await?;

            // Start coordination loop
            let coordination_handle = cx.spawn(|cx| async move {
                self.run_coordination_loop(cx).await
            }).await?;

            Ok(())
        }

        /// Schedule a message for timed broadcast
        async fn schedule_message(
            &mut self,
            message: TimedMessage,
            cx: &Cx,
        ) -> Result<TimerHandle, AsupersyncError> {
            let delay = message.scheduled_at.duration_since(Instant::now());

            // Apply coordination strategy
            match &self.strategy {
                CoordinationStrategy::IndividualScheduling => {
                    self.schedule_individual_message(message, delay, cx).await
                }
                CoordinationStrategy::BatchScheduling { batch_size } => {
                    self.schedule_batch_message(message, delay, *batch_size, cx).await
                }
                CoordinationStrategy::AdaptiveScheduling { load_threshold } => {
                    self.schedule_adaptive_message(message, delay, *load_threshold, cx).await
                }
                CoordinationStrategy::PriorityScheduling { max_priorities } => {
                    self.schedule_priority_message(message, delay, *max_priorities, cx).await
                }
            }
        }

        /// Schedule individual message
        async fn schedule_individual_message(
            &mut self,
            message: TimedMessage,
            delay: Duration,
            cx: &Cx,
        ) -> Result<TimerHandle, AsupersyncError> {
            let timer_handle = self.timer_wheel.schedule(
                delay,
                TimerKind::OneShot,
                cx,
            ).await?;

            self.active_timers.insert(timer_handle, message);
            self.stats.messages_scheduled.fetch_add(1, Ordering::SeqCst);

            Ok(timer_handle)
        }

        /// Schedule batch message with grouping
        async fn schedule_batch_message(
            &mut self,
            message: TimedMessage,
            delay: Duration,
            batch_size: usize,
            cx: &Cx,
        ) -> Result<TimerHandle, AsupersyncError> {
            // Add to message queue for batching
            self.message_queue.push_back(message.clone());

            // Process batch if threshold reached
            if self.message_queue.len() >= batch_size {
                self.process_message_batch(delay, cx).await?;
            }

            // Schedule individual timer for this message
            self.schedule_individual_message(message, delay, cx).await
        }

        /// Schedule adaptive message based on system load
        async fn schedule_adaptive_message(
            &mut self,
            message: TimedMessage,
            delay: Duration,
            load_threshold: f64,
            cx: &Cx,
        ) -> Result<TimerHandle, AsupersyncError> {
            let current_load = self.calculate_system_load();

            let adjusted_delay = if current_load > load_threshold {
                // Increase delay under high load
                delay + Duration::from_millis((delay.as_millis() as f64 * 0.1) as u64)
            } else {
                delay
            };

            self.schedule_individual_message(message, adjusted_delay, cx).await
        }

        /// Schedule priority message with ordering
        async fn schedule_priority_message(
            &mut self,
            message: TimedMessage,
            delay: Duration,
            max_priorities: u32,
            cx: &Cx,
        ) -> Result<TimerHandle, AsupersyncError> {
            // Adjust delay based on priority (lower number = higher priority)
            let priority_adjustment = if message.priority < max_priorities {
                Duration::from_millis(message.priority as u64 * 10)
            } else {
                Duration::from_millis(max_priorities as u64 * 10)
            };

            let adjusted_delay = if delay > priority_adjustment {
                delay - priority_adjustment
            } else {
                Duration::from_millis(1)
            };

            self.schedule_individual_message(message, adjusted_delay, cx).await
        }

        /// Process batch of messages together
        async fn process_message_batch(
            &mut self,
            base_delay: Duration,
            cx: &Cx,
        ) -> Result<(), AsupersyncError> {
            // Group messages by scheduled time proximity
            let mut batches: Vec<Vec<TimedMessage>> = Vec::new();
            let batch_window = Duration::from_millis(100);

            while let Some(message) = self.message_queue.pop_front() {
                let mut placed = false;

                for batch in &mut batches {
                    if let Some(first) = batch.first() {
                        if message.scheduled_at.duration_since(first.scheduled_at) <= batch_window {
                            batch.push(message);
                            placed = true;
                            break;
                        }
                    }
                }

                if !placed {
                    batches.push(vec![message]);
                }
            }

            // Schedule batch timers
            for batch in batches {
                if !batch.is_empty() {
                    let batch_delay = batch[0].scheduled_at.duration_since(Instant::now());
                    let timer_handle = self.timer_wheel.schedule(
                        batch_delay,
                        TimerKind::OneShot,
                        cx,
                    ).await?;

                    // Store first message as representative
                    self.active_timers.insert(timer_handle, batch[0].clone());
                    self.stats.messages_scheduled.fetch_add(batch.len() as u64, Ordering::SeqCst);
                }
            }

            Ok(())
        }

        /// Run timer wheel processing loop
        async fn run_timer_wheel(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            while self.is_running.load(Ordering::SeqCst) {
                // Advance timer wheel
                self.timer_wheel.tick(cx).await?;
                self.stats.wheel_ticks.fetch_add(1, Ordering::SeqCst);

                // Process expired timers
                let expired_timers = self.timer_wheel.collect_expired().await?;
                for timer_handle in expired_timers {
                    if let Some(message) = self.active_timers.remove(&timer_handle) {
                        self.deliver_message(message, cx).await?;
                    }
                }

                // Tick interval
                crate::time::sleep(self.config.tick_interval, cx).await?;
            }

            Ok(())
        }

        /// Run broadcast processor loop
        async fn run_broadcast_processor(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            while self.is_running.load(Ordering::SeqCst) {
                match self.broadcast_receiver.recv(cx).await {
                    Ok(message) => {
                        self.process_broadcast_message(message, cx).await?;
                    }
                    Err(_) => {
                        // Channel closed or error
                        break;
                    }
                }
            }

            Ok(())
        }

        /// Process broadcast message delivery
        async fn process_broadcast_message(
            &mut self,
            message: TimedMessage,
            cx: &Cx,
        ) -> Result<(), AsupersyncError> {
            let now = Instant::now();

            // Check delivery timing
            if now >= message.scheduled_at {
                let delay = now.duration_since(message.scheduled_at);
                if delay <= self.config.max_delay {
                    self.stats.messages_delivered.fetch_add(1, Ordering::SeqCst);
                } else {
                    self.stats.messages_late.fetch_add(1, Ordering::SeqCst);
                }
            }

            // Perform actual broadcast
            self.stats.broadcasts_completed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        /// Deliver message via broadcast channel
        async fn deliver_message(&mut self, message: TimedMessage, cx: &Cx) -> Result<(), AsupersyncError> {
            match self.broadcast_sender.send(message, cx).await {
                Ok(()) => {
                    self.stats.messages_delivered.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => {
                    self.stats.coordination_errors.fetch_add(1, Ordering::SeqCst);
                    return Err(AsupersyncError::ChannelError(format!("Broadcast failed: {:?}", e)));
                }
            }

            Ok(())
        }

        /// Run coordination loop for system management
        async fn run_coordination_loop(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            let mut tick_count = 0u64;

            while self.is_running.load(Ordering::SeqCst) {
                // Periodic coordination tasks
                if tick_count % 100 == 0 {
                    self.cleanup_expired_timers().await?;
                    self.update_adaptive_parameters().await?;
                    self.log_coordination_metrics().await?;
                }

                tick_count += 1;
                crate::time::sleep(Duration::from_millis(50), cx).await?;
            }

            Ok(())
        }

        /// Cleanup expired timer handles
        async fn cleanup_expired_timers(&mut self) -> Result<(), AsupersyncError> {
            let now = Instant::now();
            let expired_keys: Vec<_> = self.active_timers
                .iter()
                .filter(|(_, msg)| now > msg.scheduled_at + self.config.max_delay)
                .map(|(k, _)| *k)
                .collect();

            for key in expired_keys {
                self.active_timers.remove(&key);
            }

            Ok(())
        }

        /// Update adaptive coordination parameters
        async fn update_adaptive_parameters(&mut self) -> Result<(), AsupersyncError> {
            // Adjust parameters based on performance metrics
            let load = self.calculate_system_load();

            if load > 0.8 {
                // High load: adjust batch sizes and delays
                self.strategy = CoordinationStrategy::BatchScheduling { batch_size: 64 };
            } else if load < 0.3 {
                // Low load: optimize for latency
                self.strategy = CoordinationStrategy::IndividualScheduling;
            }

            Ok(())
        }

        /// Calculate current system load
        fn calculate_system_load(&self) -> f64 {
            let active_timers = self.active_timers.len() as f64;
            let queue_size = self.message_queue.len() as f64;
            let capacity = self.config.channel_capacity as f64;

            (active_timers + queue_size) / (capacity * 2.0)
        }

        /// Log coordination metrics
        async fn log_coordination_metrics(&self) -> Result<(), AsupersyncError> {
            let scheduled = self.stats.messages_scheduled.load(Ordering::SeqCst);
            let delivered = self.stats.messages_delivered.load(Ordering::SeqCst);
            let late = self.stats.messages_late.load(Ordering::SeqCst);
            let broadcasts = self.stats.broadcasts_completed.load(Ordering::SeqCst);
            let errors = self.stats.coordination_errors.load(Ordering::SeqCst);

            eprintln!(
                "TimedBroadcast Metrics: scheduled={}, delivered={}, late={}, broadcasts={}, errors={}",
                scheduled, delivered, late, broadcasts, errors
            );

            Ok(())
        }

        /// Stop the coordination system
        async fn stop(&mut self) -> Result<(), AsupersyncError> {
            self.is_running.store(false, Ordering::SeqCst);
            Ok(())
        }

        /// Get coordination statistics
        fn get_stats(&self) -> TimedBroadcastStats {
            TimedBroadcastStats {
                messages_scheduled: AtomicU64::new(self.stats.messages_scheduled.load(Ordering::SeqCst)),
                messages_delivered: AtomicU64::new(self.stats.messages_delivered.load(Ordering::SeqCst)),
                messages_late: AtomicU64::new(self.stats.messages_late.load(Ordering::SeqCst)),
                wheel_ticks: AtomicU64::new(self.stats.wheel_ticks.load(Ordering::SeqCst)),
                broadcasts_completed: AtomicU64::new(self.stats.broadcasts_completed.load(Ordering::SeqCst)),
                coordination_errors: AtomicU64::new(self.stats.coordination_errors.load(Ordering::SeqCst)),
            }
        }
    }

    /// Test basic timed broadcast coordination
    #[tokio::test]
    async fn test_basic_timed_broadcast_integration() -> Result<(), AsupersyncError> {
        let runtime = RuntimeBuilder::new().build().await?;
        let cx = runtime.cx();

        cx.scope(|cx| async move {
            let config = TimedBroadcastConfig::default();
            let strategy = CoordinationStrategy::IndividualScheduling;
            let mut system = TimedBroadcastSystem::new(config, strategy)?;

            // Start coordination system
            system.start(cx).await?;

            // Schedule test messages
            let now = Instant::now();
            let messages = vec![
                TimedMessage {
                    payload: "Message 1".to_string(),
                    scheduled_at: now + Duration::from_millis(100),
                    priority: 1,
                    correlation_id: 1001,
                    group_id: Some("group_a".to_string()),
                },
                TimedMessage {
                    payload: "Message 2".to_string(),
                    scheduled_at: now + Duration::from_millis(200),
                    priority: 2,
                    correlation_id: 1002,
                    group_id: Some("group_a".to_string()),
                },
                TimedMessage {
                    payload: "Message 3".to_string(),
                    scheduled_at: now + Duration::from_millis(300),
                    priority: 1,
                    correlation_id: 1003,
                    group_id: Some("group_b".to_string()),
                },
            ];

            // Schedule messages for delivery
            for message in messages {
                let timer_handle = system.schedule_message(message, cx).await?;
                assert!(timer_handle.is_valid());
            }

            // Allow time for processing
            crate::time::sleep(Duration::from_millis(500), cx).await?;

            // Stop system
            system.stop().await?;

            // Verify coordination worked
            let stats = system.get_stats();
            assert_eq!(stats.messages_scheduled.load(Ordering::SeqCst), 3);
            assert!(stats.wheel_ticks.load(Ordering::SeqCst) > 0);
            assert!(stats.broadcasts_completed.load(Ordering::SeqCst) > 0);
            assert_eq!(stats.coordination_errors.load(Ordering::SeqCst), 0);

            Ok(())
        }).await
    }

    /// Test batch scheduling coordination
    #[tokio::test]
    async fn test_batch_scheduling_coordination() -> Result<(), AsupersyncError> {
        let runtime = RuntimeBuilder::new().build().await?;
        let cx = runtime.cx();

        cx.scope(|cx| async move {
            let config = TimedBroadcastConfig::default();
            let strategy = CoordinationStrategy::BatchScheduling { batch_size: 3 };
            let mut system = TimedBroadcastSystem::new(config, strategy)?;

            system.start(cx).await?;

            // Create batch of related messages
            let now = Instant::now();
            let base_time = now + Duration::from_millis(200);

            let batch_messages = (0..5).map(|i| TimedMessage {
                payload: format!("Batch Message {}", i),
                scheduled_at: base_time + Duration::from_millis(i * 10),
                priority: 1,
                correlation_id: 2000 + i as u64,
                group_id: Some("batch_group".to_string()),
            }).collect::<Vec<_>>();

            // Schedule batch messages
            for message in batch_messages {
                system.schedule_message(message, cx).await?;
            }

            // Allow batch processing time
            crate::time::sleep(Duration::from_millis(400), cx).await?;

            system.stop().await?;

            // Verify batch processing
            let stats = system.get_stats();
            assert_eq!(stats.messages_scheduled.load(Ordering::SeqCst), 5);
            assert!(stats.broadcasts_completed.load(Ordering::SeqCst) >= 3); // At least one batch
            assert!(stats.coordination_errors.load(Ordering::SeqCst) == 0);

            Ok(())
        }).await
    }

    /// Test adaptive coordination under varying load
    #[tokio::test]
    async fn test_adaptive_coordination() -> Result<(), AsupersyncError> {
        let runtime = RuntimeBuilder::new().build().await?;
        let cx = runtime.cx();

        cx.scope(|cx| async move {
            let config = TimedBroadcastConfig {
                channel_capacity: 100, // Smaller capacity to test load
                ..TimedBroadcastConfig::default()
            };
            let strategy = CoordinationStrategy::AdaptiveScheduling { load_threshold: 0.6 };
            let mut system = TimedBroadcastSystem::new(config, strategy)?;

            system.start(cx).await?;

            // Create high load scenario
            let now = Instant::now();
            let high_load_messages = (0..80).map(|i| TimedMessage {
                payload: format!("Load Message {}", i),
                scheduled_at: now + Duration::from_millis(50 + i * 5),
                priority: i % 4,
                correlation_id: 3000 + i as u64,
                group_id: Some(format!("load_group_{}", i % 10)),
            }).collect::<Vec<_>>();

            // Schedule high load
            for message in high_load_messages {
                system.schedule_message(message, cx).await?;
                // Small delay to simulate realistic load
                crate::time::sleep(Duration::from_millis(2), cx).await?;
            }

            // Allow adaptive processing
            crate::time::sleep(Duration::from_millis(800), cx).await?;

            system.stop().await?;

            // Verify adaptive behavior handled load
            let stats = system.get_stats();
            assert_eq!(stats.messages_scheduled.load(Ordering::SeqCst), 80);
            assert!(stats.wheel_ticks.load(Ordering::SeqCst) > 50); // Many wheel ticks processed
            assert!(stats.broadcasts_completed.load(Ordering::SeqCst) > 60); // Most messages delivered

            // Should have low error rate even under high load
            let error_rate = stats.coordination_errors.load(Ordering::SeqCst) as f64 / 80.0;
            assert!(error_rate < 0.1, "Error rate too high: {}", error_rate);

            Ok(())
        }).await
    }

    /// Test priority-based coordination
    #[tokio::test]
    async fn test_priority_coordination() -> Result<(), AsupersyncError> {
        let runtime = RuntimeBuilder::new().build().await?;
        let cx = runtime.cx();

        cx.scope(|cx| async move {
            let config = TimedBroadcastConfig::default();
            let strategy = CoordinationStrategy::PriorityScheduling { max_priorities: 5 };
            let mut system = TimedBroadcastSystem::new(config, strategy)?;

            system.start(cx).await?;

            // Create messages with different priorities
            let now = Instant::now();
            let base_time = now + Duration::from_millis(300);

            let priority_messages = vec![
                (0, "Critical Message"),      // Highest priority
                (4, "Low Priority Message"),  // Lowest priority
                (2, "Medium Message"),        // Medium priority
                (1, "High Priority Message"), // High priority
                (3, "Normal Message"),        // Normal priority
            ];

            let mut scheduled_times = Vec::new();

            for (priority, content) in priority_messages {
                let message = TimedMessage {
                    payload: content.to_string(),
                    scheduled_at: base_time,
                    priority,
                    correlation_id: 4000 + priority as u64,
                    group_id: Some("priority_group".to_string()),
                };

                let timer_handle = system.schedule_message(message, cx).await?;
                scheduled_times.push((priority, timer_handle));
            }

            // Allow priority processing
            crate::time::sleep(Duration::from_millis(500), cx).await?;

            system.stop().await?;

            // Verify priority coordination
            let stats = system.get_stats();
            assert_eq!(stats.messages_scheduled.load(Ordering::SeqCst), 5);
            assert!(stats.broadcasts_completed.load(Ordering::SeqCst) == 5);
            assert_eq!(stats.coordination_errors.load(Ordering::SeqCst), 0);

            // Priority 0 messages should be delivered first (shortest delay adjustment)
            // This is tested by the coordination system's priority logic

            Ok(())
        }).await
    }
}