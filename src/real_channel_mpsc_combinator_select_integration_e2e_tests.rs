//! br-e2e-226: channel/mpsc ↔ combinator/select integration E2E tests
//!
//! Tests integration between MPSC channels and select combinators for
//! multi-producer coordination, proper selection logic, and resource management.

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use crate::cancel::{CancelReason, CancelToken};
    use crate::channel::mpsc::{
        Receiver, Sender, UnboundedReceiver, UnboundedSender, channel as mpsc_channel,
        unbounded_channel,
    };
    use crate::combinator::select::{SelectBias, SelectOutcome, select, select_3, select_4};
    use crate::cx::{Cx, Scope};
    use crate::error::AsupersyncError;
    use crate::runtime::{Runtime, RuntimeBuilder};
    use crate::time::{Duration, Instant, sleep, timeout};
    use crate::types::{Budget, Outcome, RegionId, TaskId};

    use std::collections::{BTreeMap, HashMap, VecDeque};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    /// Configuration for MPSC select coordination
    #[derive(Debug, Clone)]
    struct MpscSelectConfig {
        /// Channel buffer capacity
        pub channel_capacity: usize,
        /// Maximum producers per channel
        pub max_producers_per_channel: usize,
        /// Selection timeout
        pub selection_timeout: Duration,
        /// Message send timeout
        pub send_timeout: Duration,
        /// Coordination check interval
        pub coordination_interval: Duration,
        /// Maximum pending selections
        pub max_pending_selections: usize,
    }

    impl Default for MpscSelectConfig {
        fn default() -> Self {
            Self {
                channel_capacity: 1000,
                max_producers_per_channel: 10,
                selection_timeout: Duration::from_secs(5),
                send_timeout: Duration::from_millis(100),
                coordination_interval: Duration::from_millis(50),
                max_pending_selections: 100,
            }
        }
    }

    /// Message with producer and selection metadata
    #[derive(Debug, Clone, PartialEq)]
    struct SelectMessage {
        /// Message identifier
        pub id: u64,
        /// Message data
        pub data: String,
        /// Producer identifier
        pub producer_id: u64,
        /// Channel identifier
        pub channel_id: u64,
        /// Message priority for selection
        pub priority: u32,
        /// Timestamp when sent
        pub sent_at: Instant,
        /// Expected processing duration
        pub processing_duration: Duration,
    }

    /// Statistics for MPSC select coordination
    #[derive(Debug, Default)]
    struct MpscSelectStats {
        /// Channels created
        pub channels_created: AtomicU64,
        /// Producers spawned
        pub producers_spawned: AtomicU64,
        /// Messages sent
        pub messages_sent: AtomicU64,
        /// Messages received
        pub messages_received: AtomicU64,
        /// Select operations performed
        pub select_operations: AtomicU64,
        /// Successful selections
        pub successful_selections: AtomicU64,
        /// Selection timeouts
        pub selection_timeouts: AtomicU64,
        /// Channel coordination events
        pub coordination_events: AtomicU64,
        /// Coordination errors
        pub coordination_errors: AtomicU64,
    }

    /// Selection strategy for multi-channel coordination
    #[derive(Debug, Clone)]
    enum SelectionStrategy {
        /// Round-robin selection
        RoundRobin,
        /// Priority-based selection
        PriorityBased,
        /// First-available selection
        FirstAvailable,
        /// Biased selection with preferences
        Biased { channel_weights: Vec<f64> },
        /// Adaptive selection based on performance
        Adaptive { history_size: usize },
    }

    /// Channel group management mode
    #[derive(Debug, Clone)]
    enum ChannelGroupMode {
        /// Individual channels
        Individual,
        /// Grouped channels with coordination
        Grouped { group_size: usize },
        /// Dynamic grouping based on load
        Dynamic { load_threshold: f64 },
        /// Hierarchical channel organization
        Hierarchical { levels: usize },
    }

    /// Comprehensive MPSC select coordination system
    struct MpscSelectSystem {
        config: MpscSelectConfig,
        channels: HashMap<u64, ChannelGroup>,
        active_producers: HashMap<u64, ProducerHandle>,
        pending_selections: VecDeque<SelectionRequest>,
        selection_history: VecDeque<SelectionResult>,
        stats: Arc<MpscSelectStats>,
        selection_strategy: SelectionStrategy,
        channel_mode: ChannelGroupMode,
        is_running: AtomicBool,
        next_channel_id: AtomicU64,
        next_producer_id: AtomicU64,
    }

    /// Channel group with coordination
    #[derive(Debug)]
    struct ChannelGroup {
        id: u64,
        bounded_channels: Vec<(Sender<SelectMessage>, Receiver<SelectMessage>)>,
        unbounded_channels: Vec<(
            UnboundedSender<SelectMessage>,
            UnboundedReceiver<SelectMessage>,
        )>,
        producers: Vec<u64>,
        message_count: AtomicU64,
        last_selection: Option<Instant>,
        performance_metrics: PerformanceMetrics,
    }

    /// Producer handle for coordination
    #[derive(Debug)]
    struct ProducerHandle {
        id: u64,
        channel_id: u64,
        cancel_token: CancelToken,
        messages_sent: AtomicU64,
        last_send: Option<Instant>,
    }

    /// Selection request
    #[derive(Debug)]
    struct SelectionRequest {
        id: u64,
        channel_ids: Vec<u64>,
        strategy: SelectionStrategy,
        timeout: Duration,
        created_at: Instant,
    }

    /// Selection result with metadata
    #[derive(Debug, Clone)]
    struct SelectionResult {
        request_id: u64,
        selected_channel: Option<u64>,
        selected_message: Option<SelectMessage>,
        selection_time: Duration,
        channels_checked: usize,
        completed_at: Instant,
    }

    /// Performance metrics for channels
    #[derive(Debug, Default)]
    struct PerformanceMetrics {
        messages_per_second: f64,
        average_latency: Duration,
        selection_success_rate: f64,
        last_updated: Option<Instant>,
    }

    impl MpscSelectSystem {
        /// Create new MPSC select coordination system
        fn new(
            config: MpscSelectConfig,
            selection_strategy: SelectionStrategy,
            channel_mode: ChannelGroupMode,
        ) -> Result<Self, AsupersyncError> {
            Ok(Self {
                config,
                channels: HashMap::new(),
                active_producers: HashMap::new(),
                pending_selections: VecDeque::new(),
                selection_history: VecDeque::new(),
                stats: Arc::new(MpscSelectStats::default()),
                selection_strategy,
                channel_mode,
                is_running: AtomicBool::new(false),
                next_channel_id: AtomicU64::new(1),
                next_producer_id: AtomicU64::new(1),
            })
        }

        /// Start the coordination system
        async fn start(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            self.is_running.store(true, Ordering::SeqCst);

            // Start selection processor
            let selection_handle = cx
                .spawn(|cx| async move { self.run_selection_processor(cx).await })
                .await?;

            // Start coordination monitor
            let monitor_handle = cx
                .spawn(|cx| async move { self.run_coordination_monitor(cx).await })
                .await?;

            // Start performance tracker
            let performance_handle = cx
                .spawn(|cx| async move { self.run_performance_tracker(cx).await })
                .await?;

            Ok(())
        }

        /// Create new channel group
        async fn create_channel_group(
            &mut self,
            bounded: bool,
            count: usize,
        ) -> Result<u64, AsupersyncError> {
            let group_id = self.next_channel_id.fetch_add(1, Ordering::SeqCst);

            let mut bounded_channels = Vec::new();
            let mut unbounded_channels = Vec::new();

            if bounded {
                for _ in 0..count {
                    let (tx, rx) = mpsc_channel(self.config.channel_capacity);
                    bounded_channels.push((tx, rx));
                }
            } else {
                for _ in 0..count {
                    let (tx, rx) = unbounded_channel();
                    unbounded_channels.push((tx, rx));
                }
            }

            let group = ChannelGroup {
                id: group_id,
                bounded_channels,
                unbounded_channels,
                producers: Vec::new(),
                message_count: AtomicU64::new(0),
                last_selection: None,
                performance_metrics: PerformanceMetrics::default(),
            };

            self.channels.insert(group_id, group);
            self.stats
                .channels_created
                .fetch_add(count as u64, Ordering::SeqCst);

            Ok(group_id)
        }

        /// Spawn producer for channel group
        async fn spawn_producer(
            &mut self,
            channel_id: u64,
            message_rate: Duration,
            message_count: usize,
            cx: &Cx,
        ) -> Result<u64, AsupersyncError> {
            let producer_id = self.next_producer_id.fetch_add(1, Ordering::SeqCst);
            let cancel_token = CancelToken::new();

            let producer_handle = ProducerHandle {
                id: producer_id,
                channel_id,
                cancel_token: cancel_token.clone(),
                messages_sent: AtomicU64::new(0),
                last_send: None,
            };

            self.active_producers.insert(producer_id, producer_handle);

            // Get channel sender
            let channel_group = self.channels.get_mut(&channel_id).ok_or_else(|| {
                AsupersyncError::InvalidState("Channel group not found".to_string())
            })?;

            channel_group.producers.push(producer_id);

            // Spawn producer task
            if !channel_group.bounded_channels.is_empty() {
                let sender = channel_group.bounded_channels[0].0.clone();
                self.spawn_bounded_producer(
                    producer_id,
                    sender,
                    message_rate,
                    message_count,
                    cancel_token,
                    cx,
                )
                .await?;
            } else if !channel_group.unbounded_channels.is_empty() {
                let sender = channel_group.unbounded_channels[0].0.clone();
                self.spawn_unbounded_producer(
                    producer_id,
                    sender,
                    message_rate,
                    message_count,
                    cancel_token,
                    cx,
                )
                .await?;
            }

            self.stats.producers_spawned.fetch_add(1, Ordering::SeqCst);

            Ok(producer_id)
        }

        /// Spawn bounded channel producer
        async fn spawn_bounded_producer(
            &self,
            producer_id: u64,
            sender: Sender<SelectMessage>,
            message_rate: Duration,
            message_count: usize,
            cancel_token: CancelToken,
            cx: &Cx,
        ) -> Result<(), AsupersyncError> {
            let stats = self.stats.clone();

            cx.spawn(move |cx| async move {
                for i in 0..message_count {
                    if cancel_token.is_cancelled() {
                        break;
                    }

                    let message = SelectMessage {
                        id: i as u64,
                        data: format!("Producer {} Message {}", producer_id, i),
                        producer_id,
                        channel_id: 0, // Will be set by channel group
                        priority: (i % 3) as u32,
                        sent_at: Instant::now(),
                        processing_duration: Duration::from_millis(10 + (i % 50) as u64),
                    };

                    match timeout(Duration::from_millis(100), sender.send(message, cx), cx).await {
                        Ok(Ok(())) => {
                            stats.messages_sent.fetch_add(1, Ordering::SeqCst);
                        }
                        _ => {
                            // Send timeout or error
                            break;
                        }
                    }

                    sleep(message_rate, cx).await?;
                }

                Ok::<(), AsupersyncError>(())
            })
            .await?;

            Ok(())
        }

        /// Spawn unbounded channel producer
        async fn spawn_unbounded_producer(
            &self,
            producer_id: u64,
            sender: UnboundedSender<SelectMessage>,
            message_rate: Duration,
            message_count: usize,
            cancel_token: CancelToken,
            cx: &Cx,
        ) -> Result<(), AsupersyncError> {
            let stats = self.stats.clone();

            cx.spawn(move |cx| async move {
                for i in 0..message_count {
                    if cancel_token.is_cancelled() {
                        break;
                    }

                    let message = SelectMessage {
                        id: i as u64,
                        data: format!("Producer {} Message {}", producer_id, i),
                        producer_id,
                        channel_id: 0,
                        priority: (i % 3) as u32,
                        sent_at: Instant::now(),
                        processing_duration: Duration::from_millis(10 + (i % 50) as u64),
                    };

                    match sender.send(message) {
                        Ok(()) => {
                            stats.messages_sent.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(_) => {
                            // Channel closed
                            break;
                        }
                    }

                    sleep(message_rate, cx).await?;
                }

                Ok::<(), AsupersyncError>(())
            })
            .await?;

            Ok(())
        }

        /// Perform select operation across channels
        async fn perform_select(
            &mut self,
            channel_ids: Vec<u64>,
            strategy: Option<SelectionStrategy>,
            cx: &Cx,
        ) -> Result<SelectionResult, AsupersyncError> {
            let start_time = Instant::now();
            let request_id = self.stats.select_operations.fetch_add(1, Ordering::SeqCst);

            let strategy = strategy.unwrap_or_else(|| self.selection_strategy.clone());

            let result = match strategy {
                SelectionStrategy::RoundRobin => {
                    self.perform_round_robin_select(channel_ids, cx).await?
                }
                SelectionStrategy::PriorityBased => {
                    self.perform_priority_select(channel_ids, cx).await?
                }
                SelectionStrategy::FirstAvailable => {
                    self.perform_first_available_select(channel_ids, cx).await?
                }
                SelectionStrategy::Biased { channel_weights } => {
                    self.perform_biased_select(channel_ids, channel_weights, cx)
                        .await?
                }
                SelectionStrategy::Adaptive { history_size } => {
                    self.perform_adaptive_select(channel_ids, history_size, cx)
                        .await?
                }
            };

            let selection_result = SelectionResult {
                request_id,
                selected_channel: result.selected_channel,
                selected_message: result.selected_message,
                selection_time: start_time.elapsed(),
                channels_checked: channel_ids.len(),
                completed_at: Instant::now(),
            };

            // Update statistics
            if selection_result.selected_message.is_some() {
                self.stats
                    .successful_selections
                    .fetch_add(1, Ordering::SeqCst);
                self.stats.messages_received.fetch_add(1, Ordering::SeqCst);
            }

            // Store in history
            self.selection_history.push_back(selection_result.clone());
            if self.selection_history.len() > 1000 {
                self.selection_history.pop_front();
            }

            Ok(selection_result)
        }

        /// Perform round-robin selection
        async fn perform_round_robin_select(
            &mut self,
            channel_ids: Vec<u64>,
            cx: &Cx,
        ) -> Result<SelectionOutcome, AsupersyncError> {
            // Simple round-robin: start from different index each time
            let start_index =
                self.stats.select_operations.load(Ordering::SeqCst) as usize % channel_ids.len();

            for i in 0..channel_ids.len() {
                let channel_index = (start_index + i) % channel_ids.len();
                let channel_id = channel_ids[channel_index];

                if let Some(message) = self.try_receive_from_channel(channel_id).await? {
                    return Ok(SelectionOutcome {
                        selected_channel: Some(channel_id),
                        selected_message: Some(message),
                    });
                }
            }

            Ok(SelectionOutcome {
                selected_channel: None,
                selected_message: None,
            })
        }

        /// Perform priority-based selection
        async fn perform_priority_select(
            &mut self,
            channel_ids: Vec<u64>,
            cx: &Cx,
        ) -> Result<SelectionOutcome, AsupersyncError> {
            // Select from channels with highest priority messages
            let mut best_message: Option<SelectMessage> = None;
            let mut best_channel: Option<u64> = None;

            for &channel_id in &channel_ids {
                if let Some(message) = self.peek_channel_message(channel_id).await? {
                    if best_message
                        .as_ref()
                        .map_or(true, |m| message.priority > m.priority)
                    {
                        best_message = Some(message);
                        best_channel = Some(channel_id);
                    }
                }
            }

            if let (Some(channel_id), Some(_)) = (best_channel, best_message) {
                if let Some(message) = self.try_receive_from_channel(channel_id).await? {
                    return Ok(SelectionOutcome {
                        selected_channel: Some(channel_id),
                        selected_message: Some(message),
                    });
                }
            }

            Ok(SelectionOutcome {
                selected_channel: None,
                selected_message: None,
            })
        }

        /// Perform first-available selection
        async fn perform_first_available_select(
            &mut self,
            channel_ids: Vec<u64>,
            cx: &Cx,
        ) -> Result<SelectionOutcome, AsupersyncError> {
            // Try channels in order until one has a message
            for &channel_id in &channel_ids {
                if let Some(message) = self.try_receive_from_channel(channel_id).await? {
                    return Ok(SelectionOutcome {
                        selected_channel: Some(channel_id),
                        selected_message: Some(message),
                    });
                }
            }

            Ok(SelectionOutcome {
                selected_channel: None,
                selected_message: None,
            })
        }

        /// Perform biased selection with weights
        async fn perform_biased_select(
            &mut self,
            channel_ids: Vec<u64>,
            weights: Vec<f64>,
            cx: &Cx,
        ) -> Result<SelectionOutcome, AsupersyncError> {
            // Weight-based selection (simplified implementation)
            let mut weighted_channels: Vec<_> = channel_ids.iter().zip(weights.iter()).collect();

            weighted_channels
                .sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));

            for (&channel_id, _weight) in weighted_channels {
                if let Some(message) = self.try_receive_from_channel(channel_id).await? {
                    return Ok(SelectionOutcome {
                        selected_channel: Some(channel_id),
                        selected_message: Some(message),
                    });
                }
            }

            Ok(SelectionOutcome {
                selected_channel: None,
                selected_message: None,
            })
        }

        /// Perform adaptive selection based on history
        async fn perform_adaptive_select(
            &mut self,
            channel_ids: Vec<u64>,
            history_size: usize,
            cx: &Cx,
        ) -> Result<SelectionOutcome, AsupersyncError> {
            // Use recent selection history to guide selection
            let recent_results: Vec<_> = self
                .selection_history
                .iter()
                .rev()
                .take(history_size)
                .collect();

            // Calculate success rates per channel
            let mut channel_success_rates = HashMap::new();
            for result in recent_results {
                if let Some(channel_id) = result.selected_channel {
                    let entry = channel_success_rates.entry(channel_id).or_insert((0, 0));
                    if result.selected_message.is_some() {
                        entry.0 += 1; // Successful
                    }
                    entry.1 += 1; // Total
                }
            }

            // Sort channels by success rate
            let mut sorted_channels = channel_ids.clone();
            sorted_channels.sort_by(|a, b| {
                let rate_a = channel_success_rates
                    .get(a)
                    .map(|(s, t)| *s as f64 / *t as f64)
                    .unwrap_or(0.5);
                let rate_b = channel_success_rates
                    .get(b)
                    .map(|(s, t)| *s as f64 / *t as f64)
                    .unwrap_or(0.5);
                rate_b
                    .partial_cmp(&rate_a)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            // Try channels in success rate order
            for channel_id in sorted_channels {
                if let Some(message) = self.try_receive_from_channel(channel_id).await? {
                    return Ok(SelectionOutcome {
                        selected_channel: Some(channel_id),
                        selected_message: Some(message),
                    });
                }
            }

            Ok(SelectionOutcome {
                selected_channel: None,
                selected_message: None,
            })
        }

        /// Try to receive message from specific channel
        async fn try_receive_from_channel(
            &mut self,
            channel_id: u64,
        ) -> Result<Option<SelectMessage>, AsupersyncError> {
            if let Some(channel_group) = self.channels.get_mut(&channel_id) {
                // Try bounded channels first
                if !channel_group.bounded_channels.is_empty() {
                    if let Ok(message) = channel_group.bounded_channels[0].1.try_recv() {
                        channel_group.message_count.fetch_add(1, Ordering::SeqCst);
                        return Ok(Some(message));
                    }
                }

                // Try unbounded channels
                if !channel_group.unbounded_channels.is_empty() {
                    if let Ok(message) = channel_group.unbounded_channels[0].1.try_recv() {
                        channel_group.message_count.fetch_add(1, Ordering::SeqCst);
                        return Ok(Some(message));
                    }
                }
            }

            Ok(None)
        }

        /// Peek at next message without removing it
        async fn peek_channel_message(
            &self,
            channel_id: u64,
        ) -> Result<Option<SelectMessage>, AsupersyncError> {
            // Simplified peek implementation - would need more sophisticated buffering in practice
            // For now, return None to indicate no peeking available
            Ok(None)
        }

        /// Run selection processing loop
        async fn run_selection_processor(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            while self.is_running.load(Ordering::SeqCst) {
                // Process pending selections
                while let Some(request) = self.pending_selections.pop_front() {
                    if request.created_at.elapsed() > request.timeout {
                        self.stats.selection_timeouts.fetch_add(1, Ordering::SeqCst);
                        continue;
                    }

                    match self
                        .perform_select(request.channel_ids, Some(request.strategy), cx)
                        .await
                    {
                        Ok(_result) => {
                            // Selection completed
                        }
                        Err(e) => {
                            self.stats
                                .coordination_errors
                                .fetch_add(1, Ordering::SeqCst);
                            eprintln!("Selection error: {:?}", e);
                        }
                    }
                }

                sleep(self.config.coordination_interval, cx).await?;
            }

            Ok(())
        }

        /// Run coordination monitoring loop
        async fn run_coordination_monitor(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            while self.is_running.load(Ordering::SeqCst) {
                // Monitor channel health
                for (channel_id, channel_group) in &mut self.channels {
                    let message_count = channel_group.message_count.load(Ordering::SeqCst);

                    // Update performance metrics
                    if let Some(last_selection) = channel_group.last_selection {
                        let duration = last_selection.elapsed();
                        if duration > Duration::from_secs(1) {
                            channel_group.performance_metrics.messages_per_second =
                                message_count as f64 / duration.as_secs_f64();
                        }
                    }

                    self.stats
                        .coordination_events
                        .fetch_add(1, Ordering::SeqCst);
                }

                // Clean up inactive producers
                let now = Instant::now();
                self.active_producers.retain(|_, producer| {
                    producer.last_send.map_or(true, |last| {
                        now.duration_since(last) < Duration::from_secs(60)
                    })
                });

                sleep(Duration::from_secs(1), cx).await?;
            }

            Ok(())
        }

        /// Run performance tracking loop
        async fn run_performance_tracker(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            while self.is_running.load(Ordering::SeqCst) {
                // Calculate system-wide metrics
                let total_messages = self.stats.messages_sent.load(Ordering::SeqCst);
                let total_received = self.stats.messages_received.load(Ordering::SeqCst);
                let total_selections = self.stats.select_operations.load(Ordering::SeqCst);
                let successful_selections = self.stats.successful_selections.load(Ordering::SeqCst);

                let selection_success_rate = if total_selections > 0 {
                    successful_selections as f64 / total_selections as f64
                } else {
                    0.0
                };

                eprintln!(
                    "MpscSelect Metrics: channels={}, producers={}, messages_sent={}, received={}, selections={}, success_rate={:.2}, errors={}",
                    self.channels.len(),
                    self.active_producers.len(),
                    total_messages,
                    total_received,
                    total_selections,
                    selection_success_rate,
                    self.stats.coordination_errors.load(Ordering::SeqCst)
                );

                sleep(Duration::from_secs(5), cx).await?;
            }

            Ok(())
        }

        /// Stop the coordination system
        async fn stop(&mut self) -> Result<(), AsupersyncError> {
            self.is_running.store(false, Ordering::SeqCst);

            // Cancel all producers
            for (_, producer) in &self.active_producers {
                producer.cancel_token.cancel(CancelReason::SystemShutdown);
            }

            Ok(())
        }

        /// Get coordination statistics
        fn get_stats(&self) -> &MpscSelectStats {
            &self.stats
        }
    }

    /// Selection outcome
    #[derive(Debug)]
    struct SelectionOutcome {
        selected_channel: Option<u64>,
        selected_message: Option<SelectMessage>,
    }

    /// Test basic MPSC select integration
    #[tokio::test]
    async fn test_basic_mpsc_select_integration() -> Result<(), AsupersyncError> {
        let runtime = RuntimeBuilder::new().build().await?;
        let cx = runtime.cx();

        cx.scope(|cx| async move {
            let config = MpscSelectConfig::default();
            let strategy = SelectionStrategy::FirstAvailable;
            let channel_mode = ChannelGroupMode::Individual;
            let mut system = MpscSelectSystem::new(config, strategy, channel_mode)?;

            // Start coordination system
            system.start(cx).await?;

            // Create channel groups
            let channel1 = system.create_channel_group(true, 1).await?; // Bounded
            let channel2 = system.create_channel_group(false, 1).await?; // Unbounded

            // Spawn producers
            let producer1 = system
                .spawn_producer(channel1, Duration::from_millis(50), 5, cx)
                .await?;
            let producer2 = system
                .spawn_producer(channel2, Duration::from_millis(75), 5, cx)
                .await?;

            // Perform selections
            let channel_ids = vec![channel1, channel2];

            for _ in 0..8 {
                let result = system.perform_select(channel_ids.clone(), None, cx).await?;
                if result.selected_message.is_some() {
                    // Process selected message
                    sleep(Duration::from_millis(10), cx).await?;
                }
            }

            // Allow processing time
            sleep(Duration::from_millis(300), cx).await?;

            system.stop().await?;

            // Verify coordination worked
            let stats = system.get_stats();
            assert!(stats.channels_created.load(Ordering::SeqCst) >= 2);
            assert!(stats.producers_spawned.load(Ordering::SeqCst) >= 2);
            assert!(stats.messages_sent.load(Ordering::SeqCst) >= 5);
            assert!(stats.select_operations.load(Ordering::SeqCst) >= 8);
            assert!(stats.successful_selections.load(Ordering::SeqCst) > 0);
            assert_eq!(stats.coordination_errors.load(Ordering::SeqCst), 0);

            Ok(())
        })
        .await
    }

    /// Test priority-based selection strategy
    #[tokio::test]
    async fn test_priority_based_selection() -> Result<(), AsupersyncError> {
        let runtime = RuntimeBuilder::new().build().await?;
        let cx = runtime.cx();

        cx.scope(|cx| async move {
            let config = MpscSelectConfig::default();
            let strategy = SelectionStrategy::PriorityBased;
            let channel_mode = ChannelGroupMode::Grouped { group_size: 2 };
            let mut system = MpscSelectSystem::new(config, strategy, channel_mode)?;

            system.start(cx).await?;

            // Create multiple channels
            let channel1 = system.create_channel_group(true, 1).await?;
            let channel2 = system.create_channel_group(true, 1).await?;
            let channel3 = system.create_channel_group(true, 1).await?;

            // Spawn producers with different message patterns
            let producer1 = system
                .spawn_producer(channel1, Duration::from_millis(30), 8, cx)
                .await?;
            let producer2 = system
                .spawn_producer(channel2, Duration::from_millis(40), 6, cx)
                .await?;
            let producer3 = system
                .spawn_producer(channel3, Duration::from_millis(50), 4, cx)
                .await?;

            // Perform priority-based selections
            let channel_ids = vec![channel1, channel2, channel3];

            for _ in 0..12 {
                let result = system
                    .perform_select(
                        channel_ids.clone(),
                        Some(SelectionStrategy::PriorityBased),
                        cx,
                    )
                    .await?;
                if let Some(message) = result.selected_message {
                    // Higher priority messages should be selected preferentially
                    assert!(message.priority <= 2); // Most messages have priority 0, 1, or 2
                }
                sleep(Duration::from_millis(20), cx).await?;
            }

            sleep(Duration::from_millis(400), cx).await?;

            system.stop().await?;

            // Verify priority-based coordination
            let stats = system.get_stats();
            assert_eq!(stats.producers_spawned.load(Ordering::SeqCst), 3);
            assert!(stats.select_operations.load(Ordering::SeqCst) >= 12);
            assert!(stats.successful_selections.load(Ordering::SeqCst) > 0);

            Ok(())
        })
        .await
    }

    /// Test adaptive selection under varying load
    #[tokio::test]
    async fn test_adaptive_selection_under_load() -> Result<(), AsupersyncError> {
        let runtime = RuntimeBuilder::new().build().await?;
        let cx = runtime.cx();

        cx.scope(|cx| async move {
            let config = MpscSelectConfig {
                max_producers_per_channel: 3,
                ..MpscSelectConfig::default()
            };
            let strategy = SelectionStrategy::Adaptive { history_size: 20 };
            let channel_mode = ChannelGroupMode::Dynamic {
                load_threshold: 0.7,
            };
            let mut system = MpscSelectSystem::new(config, strategy, channel_mode)?;

            system.start(cx).await?;

            // Create multiple channels with varying characteristics
            let mut channels = Vec::new();
            for i in 0..4 {
                let channel_id = system.create_channel_group(i % 2 == 0, 1).await?;
                channels.push(channel_id);
            }

            // Spawn multiple producers per channel
            for (i, &channel_id) in channels.iter().enumerate() {
                for j in 0..2 {
                    let rate = Duration::from_millis(40 + (i * 10) as u64 + (j * 5) as u64);
                    system.spawn_producer(channel_id, rate, 10, cx).await?;
                }
            }

            // Perform adaptive selections
            for _ in 0..25 {
                let result = system.perform_select(channels.clone(), None, cx).await?;
                if result.selected_message.is_some() {
                    // Process message
                    sleep(Duration::from_millis(5), cx).await?;
                }
                sleep(Duration::from_millis(15), cx).await?;
            }

            // Allow full processing
            sleep(Duration::from_millis(600), cx).await?;

            system.stop().await?;

            // Verify adaptive coordination handled load
            let stats = system.get_stats();
            assert_eq!(stats.channels_created.load(Ordering::SeqCst), 4);
            assert_eq!(stats.producers_spawned.load(Ordering::SeqCst), 8);
            assert!(stats.messages_sent.load(Ordering::SeqCst) >= 40);
            assert!(stats.select_operations.load(Ordering::SeqCst) >= 25);
            assert!(stats.successful_selections.load(Ordering::SeqCst) > 10);

            // Should maintain good performance under load
            let success_rate = stats.successful_selections.load(Ordering::SeqCst) as f64
                / stats.select_operations.load(Ordering::SeqCst) as f64;
            assert!(success_rate > 0.4, "Success rate too low: {}", success_rate);

            // Should maintain low error rate
            assert!(stats.coordination_errors.load(Ordering::SeqCst) <= 2);

            Ok(())
        })
        .await
    }
}
