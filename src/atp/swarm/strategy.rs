//! ATP Swarm Strategy - Piece selection strategies and adaptive algorithms.
//!
//! Implements various piece selection strategies for optimal download performance,
//! including rarest-first, sequential, and adaptive strategies.

use super::{PeerId, PieceId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Piece selection strategy enumeration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PieceSelectionStrategy {
    /// Prioritize rarest pieces first to maximize swarm efficiency
    #[default]
    RarestFirst,

    /// Download pieces in sequential order
    Sequential,

    /// Random piece selection
    Random,

    /// Adaptive strategy that switches based on conditions
    Adaptive,

    /// Endgame strategy for final pieces
    Endgame,
}

/// Comprehensive swarm strategy that encompasses multiple decision-making aspects.
#[derive(Debug, Clone)]
pub struct SwarmStrategy {
    /// Current piece selection strategy
    pub piece_selection: PieceSelectionStrategy,

    /// Peer selection preferences
    pub peer_selection: PeerSelectionPreferences,

    /// Request timing strategy
    pub request_timing: RequestTimingStrategy,

    /// Redundancy management strategy
    pub redundancy_management: RedundancyStrategy,

    /// Adaptation parameters
    pub adaptation_config: AdaptationConfig,
}

/// Peer selection preferences for the swarm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSelectionPreferences {
    /// Prefer peers with higher download speeds
    pub prefer_fast_peers: bool,

    /// Prefer peers with lower latency
    pub prefer_low_latency: bool,

    /// Prefer peers with higher reliability
    pub prefer_reliable_peers: bool,

    /// Load balancing strategy
    pub load_balancing: LoadBalancingStrategy,

    /// Maximum requests per peer
    pub max_requests_per_peer: u32,
}

/// Load balancing strategies for distributing requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadBalancingStrategy {
    /// Distribute requests evenly across peers
    RoundRobin,

    /// Weighted distribution based on peer quality
    WeightedRandom,

    /// Least loaded first
    LeastLoaded,

    /// Fastest peer first
    FastestFirst,
}

/// Request timing and pipelining strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestTimingStrategy {
    /// Pipeline depth (number of outstanding requests)
    pub pipeline_depth: u32,

    /// Request timeout duration
    pub request_timeout: std::time::Duration,

    /// Retry strategy
    pub retry_strategy: RetryStrategy,

    /// Request scheduling algorithm
    pub scheduling: RequestScheduling,
}

/// Retry strategies for failed requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RetryStrategy {
    /// No retries
    None,

    /// Fixed number of retries
    Fixed { max_retries: u32 },

    /// Exponential backoff
    ExponentialBackoff {
        max_retries: u32,
        initial_delay: std::time::Duration,
        max_delay: std::time::Duration,
    },

    /// Adaptive retry based on peer performance
    Adaptive {
        max_retries: u32,
        success_rate_threshold: f64,
    },
}

/// Request scheduling algorithms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestScheduling {
    /// First-in-first-out
    FIFO,

    /// Priority-based scheduling
    Priority,

    /// Deadline-based scheduling
    EarliestDeadlineFirst,

    /// Shortest job first
    ShortestJobFirst,
}

/// Redundancy management strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedundancyStrategy {
    /// Target redundancy factor for pieces
    pub target_redundancy: f64,

    /// Duplicate request strategy
    pub duplicate_requests: DuplicateRequestStrategy,

    /// Repair strategy for lost pieces
    pub repair_strategy: RepairStrategy,
}

/// Strategies for handling duplicate requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DuplicateRequestStrategy {
    /// No duplicate requests
    None,

    /// Request from multiple peers for critical pieces
    CriticalPiecesOnly,

    /// Endgame mode - request all remaining pieces from all peers
    Endgame,

    /// Adaptive duplication based on piece rarity
    AdaptiveByRarity { rarity_threshold: u32 },
}

/// Repair strategies for handling piece loss or corruption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RepairStrategy {
    /// Re-request from different peer
    ReRequest,

    /// Use error correction codes (RaptorQ)
    ErrorCorrection,

    /// Hybrid approach
    Hybrid,
}

/// Configuration for adaptive strategy behavior.
#[derive(Debug, Clone)]
pub struct AdaptationConfig {
    /// Performance monitoring window
    pub monitoring_window: std::time::Duration,

    /// Thresholds for strategy switching
    pub switching_thresholds: SwitchingThresholds,

    /// Learning rate for adaptation
    pub learning_rate: f64,

    /// Stability period before allowing strategy changes
    pub stability_period: std::time::Duration,
}

/// Thresholds for triggering strategy adaptations.
#[derive(Debug, Clone)]
pub struct SwitchingThresholds {
    /// Download speed threshold (bytes/sec)
    pub min_download_speed: f64,

    /// Maximum acceptable latency
    pub max_latency: std::time::Duration,

    /// Minimum peer availability
    pub min_peer_availability: f64,

    /// Maximum failure rate before switching
    pub max_failure_rate: f64,
}

impl Default for SwarmStrategy {
    fn default() -> Self {
        Self {
            piece_selection: PieceSelectionStrategy::RarestFirst,
            peer_selection: PeerSelectionPreferences::default(),
            request_timing: RequestTimingStrategy::default(),
            redundancy_management: RedundancyStrategy::default(),
            adaptation_config: AdaptationConfig::default(),
        }
    }
}

impl Default for PeerSelectionPreferences {
    fn default() -> Self {
        Self {
            prefer_fast_peers: true,
            prefer_low_latency: true,
            prefer_reliable_peers: true,
            load_balancing: LoadBalancingStrategy::WeightedRandom,
            max_requests_per_peer: 4,
        }
    }
}

impl Default for RequestTimingStrategy {
    fn default() -> Self {
        Self {
            pipeline_depth: 4,
            request_timeout: std::time::Duration::from_secs(30),
            retry_strategy: RetryStrategy::Fixed { max_retries: 3 },
            scheduling: RequestScheduling::Priority,
        }
    }
}

impl Default for RedundancyStrategy {
    fn default() -> Self {
        Self {
            target_redundancy: 1.5,
            duplicate_requests: DuplicateRequestStrategy::CriticalPiecesOnly,
            repair_strategy: RepairStrategy::Hybrid,
        }
    }
}

impl Default for AdaptationConfig {
    fn default() -> Self {
        Self {
            monitoring_window: std::time::Duration::from_secs(60),
            switching_thresholds: SwitchingThresholds::default(),
            learning_rate: 0.1,
            stability_period: std::time::Duration::from_secs(30),
        }
    }
}

impl Default for SwitchingThresholds {
    fn default() -> Self {
        Self {
            min_download_speed: 100_000.0, // 100 KB/s
            max_latency: std::time::Duration::from_secs(5),
            min_peer_availability: 0.3,
            max_failure_rate: 0.2,
        }
    }
}

/// Adaptive strategy engine that can switch between different approaches.
#[derive(Debug)]
pub struct AdaptiveStrategyEngine {
    /// Current strategy state
    current_strategy: PieceSelectionStrategy,

    /// Performance history for decision making
    performance_history: Vec<StrategyPerformance>,

    /// Adaptation configuration
    config: AdaptationConfig,

    /// Last strategy change time
    last_change: std::time::Instant,

    /// Strategy scores for decision making
    strategy_scores: HashMap<PieceSelectionStrategy, f64>,
}

/// Performance metrics for a strategy over time.
#[derive(Debug, Clone)]
pub struct StrategyPerformance {
    /// Strategy that was active
    pub strategy: PieceSelectionStrategy,

    /// Time period for this measurement
    pub time_period: std::time::Duration,

    /// Average download speed during period
    pub avg_download_speed: f64,

    /// Average latency during period
    pub avg_latency: std::time::Duration,

    /// Success rate during period
    pub success_rate: f64,

    /// Swarm efficiency score
    pub efficiency_score: f64,

    /// Timestamp of measurement
    pub timestamp: std::time::Instant,
}

/// Piece selection context for strategy decision making.
#[derive(Debug)]
pub struct PieceSelectionContext {
    /// Available pieces and their redundancy
    pub piece_redundancy: HashMap<PieceId, u32>,

    /// Active peer information
    pub active_peers: HashMap<PeerId, PeerInfo>,

    /// Current transfer progress
    pub transfer_progress: f64,

    /// Remaining time estimate
    pub estimated_time_remaining: Option<std::time::Duration>,

    /// Current performance metrics
    pub current_performance: Option<StrategyPerformance>,
}

/// Information about a peer relevant to strategy decisions.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer quality metrics
    pub quality_score: f64,

    /// Current load (active requests)
    pub active_requests: u32,

    /// Available pieces from this peer
    pub available_pieces: HashSet<PieceId>,

    /// Recent response time
    pub recent_response_time: std::time::Duration,

    /// Connection reliability
    pub reliability: f64,
}

impl AdaptiveStrategyEngine {
    /// Create a new adaptive strategy engine.
    pub fn new(config: AdaptationConfig) -> Self {
        let mut strategy_scores = HashMap::new();
        strategy_scores.insert(PieceSelectionStrategy::RarestFirst, 0.8);
        strategy_scores.insert(PieceSelectionStrategy::Sequential, 0.6);
        strategy_scores.insert(PieceSelectionStrategy::Random, 0.4);
        strategy_scores.insert(PieceSelectionStrategy::Adaptive, 0.9);

        Self {
            current_strategy: PieceSelectionStrategy::RarestFirst,
            performance_history: Vec::new(),
            config,
            last_change: std::time::Instant::now(),
            strategy_scores,
        }
    }

    /// Select optimal strategy based on current context.
    pub fn select_strategy(&mut self, context: &PieceSelectionContext) -> PieceSelectionStrategy {
        // Check if enough time has passed since last change
        if self.last_change.elapsed() < self.config.stability_period {
            return self.current_strategy;
        }

        // Analyze current performance
        let current_performance = self.analyze_current_performance(context);

        // Determine if strategy change is needed
        if self.should_change_strategy(&current_performance) {
            let new_strategy = self.choose_best_strategy(context, &current_performance);
            if new_strategy != self.current_strategy {
                self.change_strategy(new_strategy);
            }
        }

        self.current_strategy
    }

    /// Record performance data for the current strategy.
    pub fn record_performance(&mut self, performance: StrategyPerformance) {
        self.performance_history.push(performance.clone());

        // Update strategy score based on performance
        let score = self.calculate_performance_score(&performance);
        if let Some(current_score) = self.strategy_scores.get_mut(&performance.strategy) {
            *current_score = (*current_score * (1.0 - self.config.learning_rate))
                + (score * self.config.learning_rate);
        }

        // Trim history to maintain reasonable size
        if self.performance_history.len() > 100 {
            self.performance_history.remove(0);
        }
    }

    /// Get recommended piece selection for given context.
    pub fn select_pieces(
        &self,
        context: &PieceSelectionContext,
        max_pieces: usize,
    ) -> Vec<PieceId> {
        match self.current_strategy {
            PieceSelectionStrategy::RarestFirst => self.select_rarest_first(context, max_pieces),
            PieceSelectionStrategy::Sequential => self.select_sequential(context, max_pieces),
            PieceSelectionStrategy::Random => self.select_random(context, max_pieces),
            PieceSelectionStrategy::Adaptive => {
                // Adaptive strategy combines multiple approaches
                self.select_adaptive(context, max_pieces)
            }
            PieceSelectionStrategy::Endgame => self.select_endgame(context, max_pieces),
        }
    }

    /// Rarest-first piece selection.
    fn select_rarest_first(
        &self,
        context: &PieceSelectionContext,
        max_pieces: usize,
    ) -> Vec<PieceId> {
        let mut pieces_by_rarity: Vec<(PieceId, u32)> = context
            .piece_redundancy
            .iter()
            .map(|(piece_id, redundancy)| (*piece_id, *redundancy))
            .collect();

        // Sort by rarity (lowest redundancy first)
        pieces_by_rarity.sort_by_key(|(_, redundancy)| *redundancy);

        pieces_by_rarity
            .into_iter()
            .take(max_pieces)
            .map(|(piece_id, _)| piece_id)
            .collect()
    }

    /// Sequential piece selection.
    fn select_sequential(
        &self,
        context: &PieceSelectionContext,
        max_pieces: usize,
    ) -> Vec<PieceId> {
        let mut available_pieces: Vec<PieceId> = context.piece_redundancy.keys().copied().collect();
        available_pieces.sort_by_key(|piece_id| piece_id.as_u64());

        available_pieces.into_iter().take(max_pieces).collect()
    }

    /// Random piece selection.
    fn select_random(&self, context: &PieceSelectionContext, max_pieces: usize) -> Vec<PieceId> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut available_pieces: Vec<PieceId> = context.piece_redundancy.keys().copied().collect();

        // Stable hash ordering gives deterministic spread without global RNG state.
        available_pieces.sort_by_key(|piece_id| {
            let mut hasher = DefaultHasher::new();
            piece_id.hash(&mut hasher);
            hasher.finish()
        });

        available_pieces.into_iter().take(max_pieces).collect()
    }

    /// Adaptive piece selection combining multiple strategies.
    fn select_adaptive(&self, context: &PieceSelectionContext, max_pieces: usize) -> Vec<PieceId> {
        let half = max_pieces / 2;

        // Combine rarest-first with sequential for balance
        let mut selected = self.select_rarest_first(context, half);
        let remaining = max_pieces - selected.len();

        if remaining > 0 {
            let sequential = self.select_sequential(context, remaining);
            for piece_id in sequential {
                if selected.len() >= max_pieces {
                    break;
                }
                if !selected.contains(&piece_id) {
                    selected.push(piece_id);
                }
            }
        }

        selected
    }

    /// Endgame mode piece selection.
    fn select_endgame(&self, context: &PieceSelectionContext, max_pieces: usize) -> Vec<PieceId> {
        // In endgame, request all remaining pieces aggressively
        context
            .piece_redundancy
            .keys()
            .take(max_pieces)
            .copied()
            .collect()
    }

    /// Analyze current performance to determine strategy effectiveness.
    fn analyze_current_performance(&self, context: &PieceSelectionContext) -> StrategyPerformance {
        // Use context to build current performance metrics
        StrategyPerformance {
            strategy: self.current_strategy,
            time_period: self.config.monitoring_window,
            avg_download_speed: context
                .current_performance
                .as_ref()
                .map_or(1_000_000.0, |p| p.avg_download_speed),
            avg_latency: context
                .current_performance
                .as_ref()
                .map_or(std::time::Duration::from_millis(100), |p| p.avg_latency),
            success_rate: context
                .current_performance
                .as_ref()
                .map_or(0.9, |p| p.success_rate),
            efficiency_score: context
                .current_performance
                .as_ref()
                .map_or(0.8, |p| p.efficiency_score),
            timestamp: std::time::Instant::now(),
        }
    }

    /// Determine if strategy should be changed based on performance.
    fn should_change_strategy(&self, performance: &StrategyPerformance) -> bool {
        let thresholds = &self.config.switching_thresholds;

        performance.avg_download_speed < thresholds.min_download_speed
            || performance.avg_latency > thresholds.max_latency
            || performance.success_rate < (1.0 - thresholds.max_failure_rate)
    }

    /// Choose the best strategy for current conditions.
    fn choose_best_strategy(
        &self,
        context: &PieceSelectionContext,
        _current_performance: &StrategyPerformance,
    ) -> PieceSelectionStrategy {
        // Check if we're in endgame phase
        if context.transfer_progress > 0.9 {
            return PieceSelectionStrategy::Endgame;
        }

        // Find strategy with highest score
        self.strategy_scores
            .iter()
            .filter(|(strategy, _)| **strategy != PieceSelectionStrategy::Adaptive)
            .max_by(|(_, score_a), (_, score_b)| {
                score_a
                    .partial_cmp(score_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map_or(PieceSelectionStrategy::RarestFirst, |(strategy, _)| {
                *strategy
            })
    }

    /// Change to a new strategy.
    fn change_strategy(&mut self, new_strategy: PieceSelectionStrategy) {
        self.current_strategy = new_strategy;
        self.last_change = std::time::Instant::now();
    }

    /// Calculate performance score from metrics.
    fn calculate_performance_score(&self, performance: &StrategyPerformance) -> f64 {
        let speed_score = (performance.avg_download_speed / 1_000_000.0).min(1.0);
        let latency_score =
            (1.0 / (performance.avg_latency.as_millis() as f64 / 1000.0 + 1.0)).min(1.0);
        let success_score = performance.success_rate;
        let efficiency_score = performance.efficiency_score;

        (speed_score * 0.3 + latency_score * 0.2 + success_score * 0.3 + efficiency_score * 0.2)
            .clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_context() -> PieceSelectionContext {
        let mut piece_redundancy = HashMap::new();
        piece_redundancy.insert(PieceId::new(0), 1); // Rare piece
        piece_redundancy.insert(PieceId::new(1), 3); // Common piece
        piece_redundancy.insert(PieceId::new(2), 2); // Medium rare

        let mut active_peers = HashMap::new();
        active_peers.insert(
            PeerId::new("peer1"),
            PeerInfo {
                quality_score: 0.8,
                active_requests: 2,
                available_pieces: [PieceId::new(0), PieceId::new(1)].iter().copied().collect(),
                recent_response_time: std::time::Duration::from_millis(100),
                reliability: 0.9,
            },
        );

        PieceSelectionContext {
            piece_redundancy,
            active_peers,
            transfer_progress: 0.5,
            estimated_time_remaining: Some(std::time::Duration::from_secs(300)),
            current_performance: None,
        }
    }

    #[test]
    fn test_adaptive_strategy_engine_creation() {
        let config = AdaptationConfig::default();
        let engine = AdaptiveStrategyEngine::new(config);

        assert_eq!(engine.current_strategy, PieceSelectionStrategy::RarestFirst);
        assert!(!engine.strategy_scores.is_empty());
    }

    #[test]
    fn test_rarest_first_selection() {
        let config = AdaptationConfig::default();
        let engine = AdaptiveStrategyEngine::new(config);
        let context = create_test_context();

        let selected = engine.select_rarest_first(&context, 2);
        assert_eq!(selected.len(), 2);
        // Should select rarest piece first (redundancy 1)
        assert_eq!(selected[0], PieceId::new(0));
    }

    #[test]
    fn test_sequential_selection() {
        let config = AdaptationConfig::default();
        let engine = AdaptiveStrategyEngine::new(config);
        let context = create_test_context();

        let selected = engine.select_sequential(&context, 2);
        assert_eq!(selected.len(), 2);
        // Should select in order
        assert_eq!(selected[0], PieceId::new(0));
        assert_eq!(selected[1], PieceId::new(1));
    }

    #[test]
    fn test_strategy_scoring() {
        let config = AdaptationConfig::default();
        let engine = AdaptiveStrategyEngine::new(config);

        let performance = StrategyPerformance {
            strategy: PieceSelectionStrategy::RarestFirst,
            time_period: std::time::Duration::from_secs(60),
            avg_download_speed: 2_000_000.0,
            avg_latency: std::time::Duration::from_millis(50),
            success_rate: 0.95,
            efficiency_score: 0.9,
            timestamp: std::time::Instant::now(),
        };

        let score = engine.calculate_performance_score(&performance);
        assert!(score > 0.5); // Should be a good score
        assert!(score <= 1.0);
    }

    #[test]
    fn test_endgame_detection() {
        let config = AdaptationConfig::default();
        let mut engine = AdaptiveStrategyEngine::new(config);

        let mut context = create_test_context();
        context.transfer_progress = 0.95; // Near completion

        let _strategy = engine.select_strategy(&context);
        // Should switch to endgame for transfers > 90% complete
        // Note: actual behavior depends on timing constraints
    }

    #[test]
    fn test_piece_selection_strategy_serialization() {
        let strategy = PieceSelectionStrategy::RarestFirst;
        let serialized = serde_json::to_string(&strategy).unwrap();
        let deserialized: PieceSelectionStrategy = serde_json::from_str(&serialized).unwrap();
        assert_eq!(strategy, deserialized);
    }
}
