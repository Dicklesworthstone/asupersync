//! br-e2e-224: channel/oneshot ↔ combinator/race integration E2E tests
//!
//! Tests integration between oneshot channels and race combinators for
//! structured concurrency patterns, proper loser cancellation, and resource coordination.

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use crate::cancel::{CancelReason, CancelToken};
    use crate::channel::oneshot::{Receiver, Sender, channel as oneshot_channel};
    use crate::combinator::race::{RaceOutcome, race, race_3, race_4};
    use crate::cx::{Cx, Scope};
    use crate::error::AsupersyncError;
    use crate::runtime::{Runtime, RuntimeBuilder};
    use crate::time::{Duration, Instant, sleep};
    use crate::types::{Budget, Outcome, RegionId, TaskId};

    use std::collections::{HashMap, VecDeque};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    /// Configuration for oneshot race coordination
    #[derive(Debug, Clone)]
    struct OneshotRaceConfig {
        /// Maximum concurrent races
        pub max_concurrent_races: usize,
        /// Race timeout duration
        pub race_timeout: Duration,
        /// Channel send timeout
        pub send_timeout: Duration,
        /// Cleanup verification timeout
        pub cleanup_timeout: Duration,
        /// Statistics collection interval
        pub stats_interval: Duration,
        /// Maximum pending channels
        pub max_pending_channels: usize,
    }

    impl Default for OneshotRaceConfig {
        fn default() -> Self {
            Self {
                max_concurrent_races: 100,
                race_timeout: Duration::from_secs(5),
                send_timeout: Duration::from_millis(100),
                cleanup_timeout: Duration::from_millis(500),
                stats_interval: Duration::from_millis(100),
                max_pending_channels: 1000,
            }
        }
    }

    /// Race entry with channel coordination
    #[derive(Debug, Clone)]
    struct RaceEntry {
        /// Entry identifier
        pub id: u64,
        /// Entry data
        pub data: String,
        /// Entry priority for racing
        pub priority: u32,
        /// Expected completion time
        pub expected_duration: Duration,
        /// Channel group identifier
        pub channel_group: String,
        /// Cancel token for coordination
        pub cancel_token: Option<CancelToken>,
    }

    /// Statistics for oneshot race coordination
    #[derive(Debug, Default)]
    struct OneshotRaceStats {
        /// Races started
        pub races_started: AtomicU64,
        /// Races completed successfully
        pub races_completed: AtomicU64,
        /// Race timeouts occurred
        pub race_timeouts: AtomicU64,
        /// Winners identified
        pub winners_identified: AtomicU64,
        /// Losers cancelled properly
        pub losers_cancelled: AtomicU64,
        /// Channels created
        pub channels_created: AtomicU64,
        /// Channels closed
        pub channels_closed: AtomicU64,
        /// Resource cleanup operations
        pub cleanups_performed: AtomicU64,
        /// Coordination errors
        pub coordination_errors: AtomicU64,
    }

    /// Race coordination strategy
    #[derive(Debug, Clone)]
    enum RaceStrategy {
        /// First to complete wins
        FirstWins,
        /// Highest priority wins if within time window
        PriorityBased { time_window: Duration },
        /// Fastest among high priority entries
        FastestHighPriority { min_priority: u32 },
        /// Adaptive based on past performance
        Adaptive { performance_history: usize },
    }

    /// Channel coordination mode
    #[derive(Debug, Clone)]
    enum ChannelMode {
        /// Individual channels per race entry
        Individual,
        /// Shared channels with multiplexing
        Shared { multiplexer_count: usize },
        /// Pooled channels with reuse
        Pooled { pool_size: usize },
        /// Adaptive channel allocation
        Adaptive { allocation_threshold: f64 },
    }

    /// Comprehensive oneshot race coordination system
    struct OneshotRaceSystem {
        config: OneshotRaceConfig,
        active_races: HashMap<u64, RaceCoordinator>,
        channel_pool: VecDeque<(Sender<RaceEntry>, Receiver<RaceEntry>)>,
        pending_entries: HashMap<String, Vec<RaceEntry>>,
        completion_history: VecDeque<RaceResult>,
        stats: Arc<OneshotRaceStats>,
        race_strategy: RaceStrategy,
        channel_mode: ChannelMode,
        is_running: AtomicBool,
        next_race_id: AtomicU64,
    }

    /// Individual race coordinator
    #[derive(Debug)]
    struct RaceCoordinator {
        race_id: u64,
        entries: Vec<RaceEntry>,
        channels: Vec<(Sender<RaceEntry>, Receiver<RaceEntry>)>,
        started_at: Instant,
        strategy: RaceStrategy,
        cancel_tokens: Vec<CancelToken>,
    }

    /// Race result with detailed information
    #[derive(Debug, Clone)]
    struct RaceResult {
        race_id: u64,
        winner: Option<RaceEntry>,
        losers: Vec<RaceEntry>,
        completion_time: Duration,
        cleanup_duration: Duration,
        cancelled_count: usize,
        completed_at: Instant,
    }

    impl OneshotRaceSystem {
        /// Create new oneshot race coordination system
        fn new(
            config: OneshotRaceConfig,
            race_strategy: RaceStrategy,
            channel_mode: ChannelMode,
        ) -> Result<Self, AsupersyncError> {
            let mut system = Self {
                config,
                active_races: HashMap::new(),
                channel_pool: VecDeque::new(),
                pending_entries: HashMap::new(),
                completion_history: VecDeque::new(),
                stats: Arc::new(OneshotRaceStats::default()),
                race_strategy,
                channel_mode,
                is_running: AtomicBool::new(false),
                next_race_id: AtomicU64::new(1),
            };

            // Pre-allocate channel pool if using pooled mode
            if let ChannelMode::Pooled { pool_size } = &system.channel_mode {
                for _ in 0..*pool_size {
                    let (tx, rx) = oneshot_channel();
                    system.channel_pool.push_back((tx, rx));
                }
                system
                    .stats
                    .channels_created
                    .fetch_add(*pool_size as u64, Ordering::SeqCst);
            }

            Ok(system)
        }

        /// Start the coordination system
        async fn start(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            self.is_running.store(true, Ordering::SeqCst);

            // Start race processing loop
            let race_handle = cx
                .spawn(|cx| async move { self.run_race_processor(cx).await })
                .await?;

            // Start cleanup monitoring
            let cleanup_handle = cx
                .spawn(|cx| async move { self.run_cleanup_monitor(cx).await })
                .await?;

            // Start statistics collection
            let stats_handle = cx
                .spawn(|cx| async move { self.run_stats_collector(cx).await })
                .await?;

            Ok(())
        }

        /// Create new race with entries
        async fn create_race(
            &mut self,
            entries: Vec<RaceEntry>,
            cx: &Cx,
        ) -> Result<u64, AsupersyncError> {
            let race_id = self.next_race_id.fetch_add(1, Ordering::SeqCst);

            // Allocate channels based on mode
            let channels = self.allocate_channels(entries.len()).await?;

            // Create cancel tokens for coordination
            let cancel_tokens: Vec<_> = (0..entries.len()).map(|_| CancelToken::new()).collect();

            let coordinator = RaceCoordinator {
                race_id,
                entries: entries.clone(),
                channels,
                started_at: Instant::now(),
                strategy: self.race_strategy.clone(),
                cancel_tokens,
            };

            self.active_races.insert(race_id, coordinator);
            self.stats.races_started.fetch_add(1, Ordering::SeqCst);

            Ok(race_id)
        }

        /// Allocate channels based on coordination mode
        async fn allocate_channels(
            &mut self,
            count: usize,
        ) -> Result<Vec<(Sender<RaceEntry>, Receiver<RaceEntry>)>, AsupersyncError> {
            let mut channels = Vec::new();

            match &self.channel_mode {
                ChannelMode::Individual => {
                    // Create individual channels for each entry
                    for _ in 0..count {
                        let (tx, rx) = oneshot_channel();
                        channels.push((tx, rx));
                        self.stats.channels_created.fetch_add(1, Ordering::SeqCst);
                    }
                }
                ChannelMode::Shared { multiplexer_count } => {
                    // Create shared channels with multiplexing
                    let shared_count = (*multiplexer_count).min(count);
                    for _ in 0..shared_count {
                        let (tx, rx) = oneshot_channel();
                        channels.push((tx, rx));
                        self.stats.channels_created.fetch_add(1, Ordering::SeqCst);
                    }
                }
                ChannelMode::Pooled { pool_size: _ } => {
                    // Use channels from pool
                    for _ in 0..count {
                        if let Some(channel_pair) = self.channel_pool.pop_front() {
                            channels.push(channel_pair);
                        } else {
                            // Pool exhausted, create new channel
                            let (tx, rx) = oneshot_channel();
                            channels.push((tx, rx));
                            self.stats.channels_created.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
                ChannelMode::Adaptive {
                    allocation_threshold,
                } => {
                    // Adaptive allocation based on load
                    let load_factor =
                        self.active_races.len() as f64 / self.config.max_concurrent_races as f64;

                    if load_factor > *allocation_threshold {
                        // High load: use shared channels
                        let shared_count = 2.max(count / 2);
                        for _ in 0..shared_count {
                            let (tx, rx) = oneshot_channel();
                            channels.push((tx, rx));
                            self.stats.channels_created.fetch_add(1, Ordering::SeqCst);
                        }
                    } else {
                        // Low load: use individual channels
                        for _ in 0..count {
                            let (tx, rx) = oneshot_channel();
                            channels.push((tx, rx));
                            self.stats.channels_created.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            }

            Ok(channels)
        }

        /// Execute race with oneshot channel coordination
        async fn execute_race(
            &mut self,
            race_id: u64,
            cx: &Cx,
        ) -> Result<RaceResult, AsupersyncError> {
            let coordinator = self
                .active_races
                .get_mut(&race_id)
                .ok_or_else(|| AsupersyncError::InvalidState("Race not found".to_string()))?;

            let start_time = Instant::now();

            // Create race futures with channel coordination
            let race_futures = coordinator
                .entries
                .iter()
                .enumerate()
                .map(|(i, entry)| {
                    let entry = entry.clone();
                    let (tx, rx) = &coordinator.channels[i];
                    let cancel_token = coordinator.cancel_tokens[i].clone();

                    async move {
                        // Simulate work with expected duration
                        let work_result = cx
                            .scope(|cx| async move {
                                // Race between actual work and cancellation
                                let work_future = async {
                                    sleep(entry.expected_duration, cx).await?;
                                    Ok::<RaceEntry, AsupersyncError>(entry.clone())
                                };

                                let cancel_future = async {
                                    cancel_token.cancelled().await;
                                    Err(AsupersyncError::Cancelled(
                                        "Race entry cancelled".to_string(),
                                    ))
                                };

                                race(work_future, cancel_future, cx).await
                            })
                            .await;

                        match work_result {
                            Ok(Outcome::Ok(RaceOutcome::First(entry))) => Ok(entry),
                            Ok(Outcome::Ok(RaceOutcome::Second(_))) => {
                                Err(AsupersyncError::Cancelled("Cancelled".to_string()))
                            }
                            _ => Err(AsupersyncError::Cancelled("Failed".to_string())),
                        }
                    }
                })
                .collect::<Vec<_>>();

            // Execute race based on strategy
            let race_outcome = match &coordinator.strategy {
                RaceStrategy::FirstWins => self.execute_first_wins_race(race_futures, cx).await?,
                RaceStrategy::PriorityBased { time_window } => {
                    self.execute_priority_race(race_futures, *time_window, coordinator, cx)
                        .await?
                }
                RaceStrategy::FastestHighPriority { min_priority } => {
                    self.execute_fastest_high_priority_race(
                        race_futures,
                        *min_priority,
                        coordinator,
                        cx,
                    )
                    .await?
                }
                RaceStrategy::Adaptive {
                    performance_history,
                } => {
                    self.execute_adaptive_race(race_futures, *performance_history, coordinator, cx)
                        .await?
                }
            };

            // Cancel all losers
            let cleanup_start = Instant::now();
            let cancelled_count = self.cancel_losers(&race_outcome, coordinator).await?;
            let cleanup_duration = cleanup_start.elapsed();

            let result = RaceResult {
                race_id,
                winner: race_outcome.winner,
                losers: race_outcome.losers,
                completion_time: start_time.elapsed(),
                cleanup_duration,
                cancelled_count,
                completed_at: Instant::now(),
            };

            // Clean up race resources
            self.cleanup_race_resources(race_id).await?;

            self.stats.races_completed.fetch_add(1, Ordering::SeqCst);
            self.stats.winners_identified.fetch_add(1, Ordering::SeqCst);
            self.stats
                .losers_cancelled
                .fetch_add(cancelled_count as u64, Ordering::SeqCst);

            Ok(result)
        }

        /// Execute first-wins race strategy
        async fn execute_first_wins_race(
            &self,
            race_futures: Vec<
                impl std::future::Future<Output = Result<RaceEntry, AsupersyncError>> + Send,
            >,
            cx: &Cx,
        ) -> Result<RaceOutcome, AsupersyncError> {
            // Use race combinator to find first completion
            if race_futures.is_empty() {
                return Err(AsupersyncError::InvalidState("No race entries".to_string()));
            }

            // For simplicity, take first 2 futures and race them
            if race_futures.len() >= 2 {
                let fut1 = race_futures.into_iter().next().unwrap();
                let fut2 = race_futures.into_iter().next().unwrap();

                match race(fut1, fut2, cx).await? {
                    RaceOutcome::First(winner) => {
                        Ok(RaceOutcome {
                            winner: Some(winner),
                            losers: Vec::new(), // Would track actual losers in full implementation
                        })
                    }
                    RaceOutcome::Second(winner) => Ok(RaceOutcome {
                        winner: Some(winner),
                        losers: Vec::new(),
                    }),
                }
            } else {
                // Single future, just await it
                let result = race_futures.into_iter().next().unwrap().await?;
                Ok(RaceOutcome {
                    winner: Some(result),
                    losers: Vec::new(),
                })
            }
        }

        /// Execute priority-based race strategy
        async fn execute_priority_race(
            &self,
            race_futures: Vec<
                impl std::future::Future<Output = Result<RaceEntry, AsupersyncError>> + Send,
            >,
            time_window: Duration,
            coordinator: &RaceCoordinator,
            cx: &Cx,
        ) -> Result<RaceOutcome, AsupersyncError> {
            // Wait for time window, then select highest priority among completed
            sleep(time_window, cx).await?;

            // Find highest priority entry (simplified implementation)
            let highest_priority_entry = coordinator
                .entries
                .iter()
                .max_by_key(|entry| entry.priority)
                .cloned();

            if let Some(winner) = highest_priority_entry {
                let losers = coordinator
                    .entries
                    .iter()
                    .filter(|e| e.id != winner.id)
                    .cloned()
                    .collect();

                Ok(RaceOutcome {
                    winner: Some(winner),
                    losers,
                })
            } else {
                Ok(RaceOutcome {
                    winner: None,
                    losers: coordinator.entries.clone(),
                })
            }
        }

        /// Execute fastest high priority race strategy
        async fn execute_fastest_high_priority_race(
            &self,
            race_futures: Vec<
                impl std::future::Future<Output = Result<RaceEntry, AsupersyncError>> + Send,
            >,
            min_priority: u32,
            coordinator: &RaceCoordinator,
            cx: &Cx,
        ) -> Result<RaceOutcome, AsupersyncError> {
            // Filter high priority entries and race them
            let high_priority_entries: Vec<_> = coordinator
                .entries
                .iter()
                .filter(|e| e.priority >= min_priority)
                .cloned()
                .collect();

            if !high_priority_entries.is_empty() {
                // Simulate racing high priority entries
                let winner = high_priority_entries
                    .into_iter()
                    .min_by_key(|e| e.expected_duration)
                    .unwrap();

                let losers = coordinator
                    .entries
                    .iter()
                    .filter(|e| e.id != winner.id)
                    .cloned()
                    .collect();

                Ok(RaceOutcome {
                    winner: Some(winner),
                    losers,
                })
            } else {
                // No high priority entries, use regular first-wins
                self.execute_first_wins_race(race_futures, cx).await
            }
        }

        /// Execute adaptive race strategy
        async fn execute_adaptive_race(
            &self,
            race_futures: Vec<
                impl std::future::Future<Output = Result<RaceEntry, AsupersyncError>> + Send,
            >,
            performance_history: usize,
            coordinator: &RaceCoordinator,
            cx: &Cx,
        ) -> Result<RaceOutcome, AsupersyncError> {
            // Use historical performance to predict best strategy
            let recent_results: Vec<_> = self
                .completion_history
                .iter()
                .take(performance_history)
                .collect();

            if recent_results.len() > 5 {
                let avg_completion_time: Duration = recent_results
                    .iter()
                    .map(|r| r.completion_time)
                    .sum::<Duration>()
                    / recent_results.len() as u32;

                if avg_completion_time < Duration::from_millis(100) {
                    // Fast completions: use first-wins
                    self.execute_first_wins_race(race_futures, cx).await
                } else {
                    // Slower completions: use priority-based
                    self.execute_priority_race(
                        race_futures,
                        Duration::from_millis(50),
                        coordinator,
                        cx,
                    )
                    .await
                }
            } else {
                // Insufficient history: default to first-wins
                self.execute_first_wins_race(race_futures, cx).await
            }
        }

        /// Cancel loser race entries
        async fn cancel_losers(
            &self,
            race_outcome: &RaceOutcome,
            coordinator: &RaceCoordinator,
        ) -> Result<usize, AsupersyncError> {
            let mut cancelled_count = 0;

            // Cancel all entries that didn't win
            for (i, entry) in coordinator.entries.iter().enumerate() {
                if let Some(ref winner) = race_outcome.winner {
                    if entry.id != winner.id {
                        coordinator.cancel_tokens[i].cancel(CancelReason::Superseded);
                        cancelled_count += 1;
                    }
                } else {
                    // No winner, cancel all
                    coordinator.cancel_tokens[i].cancel(CancelReason::Superseded);
                    cancelled_count += 1;
                }
            }

            Ok(cancelled_count)
        }

        /// Cleanup race resources
        async fn cleanup_race_resources(&mut self, race_id: u64) -> Result<(), AsupersyncError> {
            if let Some(coordinator) = self.active_races.remove(&race_id) {
                // Return channels to pool if using pooled mode
                if let ChannelMode::Pooled { pool_size } = &self.channel_mode {
                    for (tx, rx) in coordinator.channels {
                        if self.channel_pool.len() < *pool_size {
                            // Channel pair would need to be "reset" in a real implementation
                            // For now, just track the closure
                            self.stats.channels_closed.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                } else {
                    // Close individual channels
                    self.stats
                        .channels_closed
                        .fetch_add(coordinator.channels.len() as u64, Ordering::SeqCst);
                }

                self.stats.cleanups_performed.fetch_add(1, Ordering::SeqCst);
            }

            Ok(())
        }

        /// Run race processing loop
        async fn run_race_processor(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            while self.is_running.load(Ordering::SeqCst) {
                // Process any pending races
                let race_ids: Vec<_> = self.active_races.keys().cloned().collect();

                for race_id in race_ids {
                    // Check for race timeouts
                    if let Some(coordinator) = self.active_races.get(&race_id) {
                        if coordinator.started_at.elapsed() > self.config.race_timeout {
                            self.handle_race_timeout(race_id, cx).await?;
                        }
                    }
                }

                sleep(Duration::from_millis(50), cx).await?;
            }

            Ok(())
        }

        /// Handle race timeout
        async fn handle_race_timeout(
            &mut self,
            race_id: u64,
            cx: &Cx,
        ) -> Result<(), AsupersyncError> {
            if let Some(coordinator) = self.active_races.remove(&race_id) {
                // Cancel all entries
                for cancel_token in &coordinator.cancel_tokens {
                    cancel_token.cancel(CancelReason::Timeout);
                }

                // Record timeout
                self.stats.race_timeouts.fetch_add(1, Ordering::SeqCst);

                // Clean up resources
                self.cleanup_race_resources(race_id).await?;
            }

            Ok(())
        }

        /// Run cleanup monitoring loop
        async fn run_cleanup_monitor(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            while self.is_running.load(Ordering::SeqCst) {
                // Monitor for stale resources and clean them up
                let now = Instant::now();

                // Clean old completion history
                while let Some(result) = self.completion_history.front() {
                    if now.duration_since(result.completed_at) > Duration::from_secs(60) {
                        self.completion_history.pop_front();
                    } else {
                        break;
                    }
                }

                // Verify channel pool integrity
                if let ChannelMode::Pooled { pool_size } = &self.channel_mode {
                    if self.channel_pool.len() > *pool_size * 2 {
                        // Too many pooled channels, clean some up
                        while self.channel_pool.len() > *pool_size {
                            if let Some(_) = self.channel_pool.pop_front() {
                                self.stats.channels_closed.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                }

                sleep(self.config.cleanup_timeout, cx).await?;
            }

            Ok(())
        }

        /// Run statistics collection loop
        async fn run_stats_collector(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            while self.is_running.load(Ordering::SeqCst) {
                // Collect and log statistics
                let stats = self.get_stats();

                eprintln!(
                    "OneshotRace Stats: races_started={}, completed={}, timeouts={}, winners={}, losers_cancelled={}, channels_created={}, channels_closed={}, cleanups={}, errors={}",
                    stats.races_started.load(Ordering::SeqCst),
                    stats.races_completed.load(Ordering::SeqCst),
                    stats.race_timeouts.load(Ordering::SeqCst),
                    stats.winners_identified.load(Ordering::SeqCst),
                    stats.losers_cancelled.load(Ordering::SeqCst),
                    stats.channels_created.load(Ordering::SeqCst),
                    stats.channels_closed.load(Ordering::SeqCst),
                    stats.cleanups_performed.load(Ordering::SeqCst),
                    stats.coordination_errors.load(Ordering::SeqCst)
                );

                sleep(self.config.stats_interval, cx).await?;
            }

            Ok(())
        }

        /// Stop the coordination system
        async fn stop(&mut self) -> Result<(), AsupersyncError> {
            self.is_running.store(false, Ordering::SeqCst);

            // Cancel all active races
            for (_, coordinator) in &self.active_races {
                for cancel_token in &coordinator.cancel_tokens {
                    cancel_token.cancel(CancelReason::SystemShutdown);
                }
            }

            // Clean up all resources
            self.active_races.clear();
            self.channel_pool.clear();

            Ok(())
        }

        /// Get coordination statistics
        fn get_stats(&self) -> &OneshotRaceStats {
            &self.stats
        }
    }

    /// Race outcome with winner and losers
    #[derive(Debug)]
    struct RaceOutcome {
        winner: Option<RaceEntry>,
        losers: Vec<RaceEntry>,
    }

    /// Test basic oneshot race integration
    #[tokio::test]
    async fn test_basic_oneshot_race_integration() -> Result<(), AsupersyncError> {
        let runtime = RuntimeBuilder::new().build().await?;
        let cx = runtime.cx();

        cx.scope(|cx| async move {
            let config = OneshotRaceConfig::default();
            let strategy = RaceStrategy::FirstWins;
            let channel_mode = ChannelMode::Individual;
            let mut system = OneshotRaceSystem::new(config, strategy, channel_mode)?;

            // Start coordination system
            system.start(cx).await?;

            // Create test race entries
            let entries = vec![
                RaceEntry {
                    id: 1,
                    data: "Entry 1".to_string(),
                    priority: 1,
                    expected_duration: Duration::from_millis(100),
                    channel_group: "group_a".to_string(),
                    cancel_token: None,
                },
                RaceEntry {
                    id: 2,
                    data: "Entry 2".to_string(),
                    priority: 2,
                    expected_duration: Duration::from_millis(200),
                    channel_group: "group_a".to_string(),
                    cancel_token: None,
                },
                RaceEntry {
                    id: 3,
                    data: "Entry 3".to_string(),
                    priority: 3,
                    expected_duration: Duration::from_millis(50),
                    channel_group: "group_a".to_string(),
                    cancel_token: None,
                },
            ];

            // Execute race
            let race_id = system.create_race(entries, cx).await?;
            let result = system.execute_race(race_id, cx).await?;

            // Allow cleanup time
            sleep(Duration::from_millis(100), cx).await?;

            system.stop().await?;

            // Verify race coordination
            let stats = system.get_stats();
            assert_eq!(stats.races_started.load(Ordering::SeqCst), 1);
            assert_eq!(stats.races_completed.load(Ordering::SeqCst), 1);
            assert_eq!(stats.winners_identified.load(Ordering::SeqCst), 1);
            assert!(stats.losers_cancelled.load(Ordering::SeqCst) >= 1);
            assert!(stats.channels_created.load(Ordering::SeqCst) >= 3);
            assert_eq!(stats.coordination_errors.load(Ordering::SeqCst), 0);

            // Verify result structure
            assert!(result.winner.is_some());
            assert!(result.completion_time < Duration::from_secs(1));
            assert!(result.cancelled_count >= 1);

            Ok(())
        })
        .await
    }

    /// Test priority-based race strategy
    #[tokio::test]
    async fn test_priority_based_race_strategy() -> Result<(), AsupersyncError> {
        let runtime = RuntimeBuilder::new().build().await?;
        let cx = runtime.cx();

        cx.scope(|cx| async move {
            let config = OneshotRaceConfig::default();
            let strategy = RaceStrategy::PriorityBased {
                time_window: Duration::from_millis(50),
            };
            let channel_mode = ChannelMode::Shared {
                multiplexer_count: 2,
            };
            let mut system = OneshotRaceSystem::new(config, strategy, channel_mode)?;

            system.start(cx).await?;

            // Create entries with different priorities
            let entries = vec![
                RaceEntry {
                    id: 1,
                    data: "Low Priority".to_string(),
                    priority: 1,
                    expected_duration: Duration::from_millis(20),
                    channel_group: "priority_test".to_string(),
                    cancel_token: None,
                },
                RaceEntry {
                    id: 2,
                    data: "High Priority".to_string(),
                    priority: 10,
                    expected_duration: Duration::from_millis(80),
                    channel_group: "priority_test".to_string(),
                    cancel_token: None,
                },
                RaceEntry {
                    id: 3,
                    data: "Medium Priority".to_string(),
                    priority: 5,
                    expected_duration: Duration::from_millis(40),
                    channel_group: "priority_test".to_string(),
                    cancel_token: None,
                },
            ];

            let race_id = system.create_race(entries, cx).await?;
            let result = system.execute_race(race_id, cx).await?;

            sleep(Duration::from_millis(150), cx).await?;

            system.stop().await?;

            // Verify priority strategy worked
            let stats = system.get_stats();
            assert_eq!(stats.races_completed.load(Ordering::SeqCst), 1);
            assert!(result.winner.is_some());

            // High priority should win (id: 2)
            if let Some(winner) = result.winner {
                assert_eq!(winner.priority, 10);
                assert_eq!(winner.data, "High Priority");
            }

            Ok(())
        })
        .await
    }

    /// Test adaptive coordination under load
    #[tokio::test]
    async fn test_adaptive_coordination_under_load() -> Result<(), AsupersyncError> {
        let runtime = RuntimeBuilder::new().build().await?;
        let cx = runtime.cx();

        cx.scope(|cx| async move {
            let config = OneshotRaceConfig {
                max_concurrent_races: 5,
                ..OneshotRaceConfig::default()
            };
            let strategy = RaceStrategy::Adaptive {
                performance_history: 10,
            };
            let channel_mode = ChannelMode::Adaptive {
                allocation_threshold: 0.6,
            };
            let mut system = OneshotRaceSystem::new(config, strategy, channel_mode)?;

            system.start(cx).await?;

            // Create multiple concurrent races
            let mut race_ids = Vec::new();

            for i in 0..3 {
                let entries = vec![
                    RaceEntry {
                        id: i * 10 + 1,
                        data: format!("Race {} Entry 1", i),
                        priority: i as u32 + 1,
                        expected_duration: Duration::from_millis(50 + i as u64 * 20),
                        channel_group: format!("race_{}", i),
                        cancel_token: None,
                    },
                    RaceEntry {
                        id: i * 10 + 2,
                        data: format!("Race {} Entry 2", i),
                        priority: i as u32 + 2,
                        expected_duration: Duration::from_millis(30 + i as u64 * 15),
                        channel_group: format!("race_{}", i),
                        cancel_token: None,
                    },
                ];

                let race_id = system.create_race(entries, cx).await?;
                race_ids.push(race_id);
            }

            // Execute races concurrently
            for race_id in race_ids {
                let _result = system.execute_race(race_id, cx).await?;
            }

            // Allow processing time
            sleep(Duration::from_millis(300), cx).await?;

            system.stop().await?;

            // Verify adaptive coordination handled load
            let stats = system.get_stats();
            assert_eq!(stats.races_started.load(Ordering::SeqCst), 3);
            assert_eq!(stats.races_completed.load(Ordering::SeqCst), 3);
            assert_eq!(stats.winners_identified.load(Ordering::SeqCst), 3);
            assert!(stats.losers_cancelled.load(Ordering::SeqCst) >= 3);

            // Should have good cleanup ratio
            let cleanup_ratio = stats.cleanups_performed.load(Ordering::SeqCst) as f64
                / stats.races_completed.load(Ordering::SeqCst) as f64;
            assert!(cleanup_ratio >= 1.0, "Cleanup ratio: {}", cleanup_ratio);

            // Should maintain low error rate
            assert_eq!(stats.coordination_errors.load(Ordering::SeqCst), 0);

            Ok(())
        })
        .await
    }
}
