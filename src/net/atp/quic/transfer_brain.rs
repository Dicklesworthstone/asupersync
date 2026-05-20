//! ATP Transfer Brain
//!
//! Intelligent path selection and congestion adaptation based on transport metrics.

use super::metrics::{AtpTransportMetrics, PathPerformanceClass, PathRecommendation};
use crate::net::atp::protocol::outcome::{AtpOutcome, TransportError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

/// ATP Transfer Brain for intelligent path and congestion management.
///
/// The Transfer Brain consumes transport metrics from multiple paths and makes
/// intelligent decisions about:
/// - Which paths to use for new transfers
/// - When to switch paths mid-transfer
/// - How to adapt congestion control parameters
/// - Whether to enable repair/FEC
/// - When to use relays vs direct paths
pub struct AtpTransferBrain {
    /// Active path metrics by path ID.
    paths: HashMap<String, PathState>,
    /// Transfer policies and preferences.
    policy: TransferPolicy,
    /// Decision history for learning.
    decision_history: DecisionHistory,
    /// Last brain update.
    last_update: Instant,
}

/// State tracking for a single path.
#[derive(Debug, Clone)]
struct PathState {
    /// Current metrics snapshot.
    metrics: AtpTransportMetrics,
    /// Historical performance data.
    history: PathHistory,
    /// Current transfer assignments.
    active_transfers: Vec<String>,
    /// Path ranking score (0.0 - 1.0, higher = better).
    ranking_score: f64,
    /// Whether this path is currently preferred.
    is_preferred: bool,
    /// Last time this path was used.
    last_used: Instant,
}

/// Historical performance tracking for a path.
#[derive(Debug, Clone)]
struct PathHistory {
    /// Recent throughput samples (bytes/second).
    throughput_samples: Vec<u64>,
    /// Recent latency samples (microseconds).
    latency_samples: Vec<u64>,
    /// Success rate over recent transfers.
    success_rate: f64,
    /// Time-weighted average performance.
    avg_performance: f64,
}

/// Transfer policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferPolicy {
    /// Maximum number of concurrent paths per transfer.
    pub max_paths_per_transfer: usize,
    /// Minimum path quality threshold (0.0 - 1.0).
    pub min_path_quality: f64,
    /// Whether to enable automatic path switching.
    pub enable_path_switching: bool,
    /// Path switching decision threshold.
    pub path_switch_threshold: f64,
    /// Whether to enable repair/FEC automatically.
    pub enable_auto_repair: bool,
    /// Loss rate threshold for enabling repair.
    pub repair_loss_threshold: f64,
    /// Maximum congestion window growth rate.
    pub max_cwnd_growth_rate: f64,
    /// Prefer paths with better stability.
    pub prefer_stable_paths: bool,
    /// Use relays when direct paths are poor.
    pub use_relays_on_poor_paths: bool,
}

impl Default for TransferPolicy {
    fn default() -> Self {
        Self {
            max_paths_per_transfer: 3,
            min_path_quality: 0.3,
            enable_path_switching: true,
            path_switch_threshold: 0.2, // Switch if new path is 20% better
            enable_auto_repair: true,
            repair_loss_threshold: 0.05,
            max_cwnd_growth_rate: 2.0,
            prefer_stable_paths: true,
            use_relays_on_poor_paths: true,
        }
    }
}

/// Transfer Brain decisions for a transfer operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferDecision {
    /// Selected paths for this transfer, ordered by preference.
    pub selected_paths: Vec<String>,
    /// Recommended congestion control parameters.
    pub congestion_params: CongestionParams,
    /// Whether to enable repair/FEC.
    pub enable_repair: bool,
    /// Recommended FEC rate if repair is enabled.
    pub fec_rate: Option<f64>,
    /// Whether to use relay.
    pub use_relay: bool,
    /// Recommended relay if applicable.
    pub suggested_relay: Option<String>,
    /// Transfer priority based on path quality.
    pub transfer_priority: TransferPriority,
    /// Estimated completion time based on current conditions.
    pub estimated_completion_time: Duration,
    /// Decision confidence (0.0 - 1.0).
    pub confidence: f64,
}

/// Recommended congestion control parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CongestionParams {
    /// Recommended initial congestion window.
    pub initial_cwnd: u32,
    /// Recommended maximum congestion window.
    pub max_cwnd: u32,
    /// Recommended congestion control algorithm.
    pub algorithm: CongestionAlgorithm,
    /// Recommended pacing rate.
    pub pacing_rate: Option<u64>,
}

/// Congestion control algorithms.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CongestionAlgorithm {
    /// NewReno (conservative, standard).
    NewReno,
    /// Cubic (aggressive growth, good for high BDP).
    Cubic,
    /// BBR (bandwidth-based, good for variable paths).
    Bbr,
    /// Custom ATP algorithm.
    AtpAdaptive,
}

/// Transfer priority levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferPriority {
    /// High priority, use best available paths.
    High,
    /// Normal priority, use good paths.
    Normal,
    /// Low priority, use any available paths.
    Low,
    /// Background priority, use only excess capacity.
    Background,
}

/// Decision tracking for learning and optimization.
#[derive(Debug, Clone)]
struct DecisionHistory {
    /// Recent decisions made.
    decisions: Vec<HistoricalDecision>,
    /// Decision outcomes for learning.
    outcomes: HashMap<String, DecisionOutcome>,
}

#[derive(Debug, Clone)]
struct HistoricalDecision {
    /// Decision identifier.
    decision_id: String,
    /// Transfer identifier.
    transfer_id: String,
    /// Decision timestamp.
    timestamp: Instant,
    /// Paths selected.
    paths_selected: Vec<String>,
    /// Decision rationale.
    rationale: String,
}

#[derive(Debug, Clone)]
struct DecisionOutcome {
    /// Transfer completion time.
    completion_time: Duration,
    /// Transfer success/failure.
    success: bool,
    /// Actual vs predicted performance.
    performance_ratio: f64,
}

impl AtpTransferBrain {
    /// Create a new Transfer Brain with default policy.
    #[must_use]
    pub fn new() -> Self {
        Self::with_policy(TransferPolicy::default())
    }

    /// Create a Transfer Brain with custom policy.
    #[must_use]
    pub fn with_policy(policy: TransferPolicy) -> Self {
        Self {
            paths: HashMap::new(),
            policy,
            decision_history: DecisionHistory {
                decisions: Vec::new(),
                outcomes: HashMap::new(),
            },
            last_update: Instant::now(),
        }
    }

    /// Update metrics for a path.
    pub fn update_path_metrics(&mut self, metrics: AtpTransportMetrics) {
        let path_id = metrics.path_id.clone();
        let ranking_score = self.calculate_path_ranking(&metrics);

        if let Some(path_state) = self.paths.get_mut(&path_id) {
            // Update existing path
            path_state.history.update_from_metrics(&metrics);
            path_state.metrics = metrics;
            path_state.ranking_score = ranking_score;
        } else {
            // New path
            let path_state = PathState {
                metrics,
                history: PathHistory::new(),
                active_transfers: Vec::new(),
                ranking_score,
                is_preferred: false,
                last_used: Instant::now(),
            };
            self.paths.insert(path_id, path_state);
        }

        self.update_path_preferences();
        self.last_update = Instant::now();
    }

    /// Make a transfer decision based on current path state.
    #[must_use]
    pub fn make_transfer_decision(
        &mut self,
        transfer_id: String,
        transfer_size: u64,
        priority: TransferPriority,
    ) -> AtpOutcome<TransferDecision> {
        // Filter paths by quality threshold
        let candidate_paths: Vec<_> = self
            .paths
            .iter()
            .filter(|(_, state)| {
                state.ranking_score >= self.policy.min_path_quality
                    && matches!(
                        state
                            .metrics
                            .path_doctor_assessment
                            .as_ref()
                            .map(|a| a.performance_class),
                        Some(
                            PathPerformanceClass::Excellent
                                | PathPerformanceClass::Good
                                | PathPerformanceClass::Fair
                        )
                    )
            })
            .collect();

        if candidate_paths.is_empty() {
            return AtpOutcome::transport_error(TransportError::NetworkUnreachable);
        }

        // Select paths based on ranking and policy
        let mut selected_paths = candidate_paths
            .into_iter()
            .map(|(path_id, state)| (path_id.clone(), state.ranking_score))
            .collect::<Vec<_>>();

        selected_paths.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        selected_paths.truncate(self.policy.max_paths_per_transfer);

        let selected_path_ids: Vec<String> =
            selected_paths.iter().map(|(id, _)| id.clone()).collect();

        // Determine if repair should be enabled
        let enable_repair = self.should_enable_repair(&selected_path_ids);
        let fec_rate = if enable_repair {
            Some(self.calculate_optimal_fec_rate(&selected_path_ids))
        } else {
            None
        };

        // Determine if relay should be used
        let use_relay = self.should_use_relay(&selected_path_ids);

        // Calculate congestion parameters
        let congestion_params = self.calculate_congestion_params(&selected_path_ids, transfer_size);

        // Estimate completion time
        let estimated_completion_time =
            self.estimate_completion_time(&selected_path_ids, transfer_size);

        // Calculate confidence
        let confidence = self.calculate_decision_confidence(&selected_path_ids);

        let decision = TransferDecision {
            selected_paths: selected_path_ids.clone(),
            congestion_params,
            enable_repair,
            fec_rate,
            use_relay,
            suggested_relay: None, // TODO: Implement relay selection
            transfer_priority: priority,
            estimated_completion_time,
            confidence,
        };

        // Record decision for learning
        self.record_decision(transfer_id, &decision);

        AtpOutcome::ok(decision)
    }

    /// Report transfer completion for learning.
    pub fn report_transfer_completion(
        &mut self,
        transfer_id: &str,
        completion_time: Duration,
        success: bool,
    ) {
        // Find the decision for this transfer
        if let Some(decision) = self
            .decision_history
            .decisions
            .iter()
            .find(|d| d.transfer_id == transfer_id)
        {
            let outcome = DecisionOutcome {
                completion_time,
                success,
                performance_ratio: 1.0, // TODO: Calculate actual vs predicted
            };
            self.decision_history
                .outcomes
                .insert(decision.decision_id.clone(), outcome);
        }
    }

    /// Get current path rankings.
    #[must_use]
    pub fn path_rankings(&self) -> BTreeMap<String, f64> {
        self.paths
            .iter()
            .map(|(path_id, state)| (path_id.clone(), state.ranking_score))
            .collect()
    }

    /// Get recommendations for path optimization.
    #[must_use]
    pub fn get_path_recommendations(&self) -> Vec<PathOptimizationRecommendation> {
        let mut recommendations = Vec::new();

        for (path_id, state) in &self.paths {
            if let Some(assessment) = &state.metrics.path_doctor_assessment {
                for rec in &assessment.recommendations {
                    recommendations.push(PathOptimizationRecommendation {
                        path_id: path_id.clone(),
                        recommendation: rec.clone(),
                        urgency: self.calculate_recommendation_urgency(rec, &state.metrics),
                    });
                }
            }
        }

        recommendations.sort_by(|a, b| {
            b.urgency
                .partial_cmp(&a.urgency)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        recommendations
    }

    // Private helper methods

    fn calculate_path_ranking(&self, metrics: &AtpTransportMetrics) -> f64 {
        let performance_score = match metrics
            .path_doctor_assessment
            .as_ref()
            .map(|a| a.performance_class)
        {
            Some(PathPerformanceClass::Excellent) => 1.0,
            Some(PathPerformanceClass::Good) => 0.8,
            Some(PathPerformanceClass::Fair) => 0.6,
            Some(PathPerformanceClass::Poor) => 0.4,
            Some(PathPerformanceClass::Unusable) => 0.0,
            None => 0.5,
        };

        let stability_weight = if self.policy.prefer_stable_paths {
            0.3
        } else {
            0.1
        };
        let performance_weight = 1.0 - stability_weight;

        performance_score * performance_weight + metrics.path_stability * stability_weight
    }

    fn update_path_preferences(&mut self) {
        // Mark top paths as preferred
        let mut paths_by_score: Vec<_> = self.paths.iter_mut().collect();
        paths_by_score.sort_by(|a, b| {
            b.1.ranking_score
                .partial_cmp(&a.1.ranking_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for (i, (_, state)) in paths_by_score.iter_mut().enumerate() {
            state.is_preferred = i < 2; // Top 2 paths are preferred
        }
    }

    fn should_enable_repair(&self, path_ids: &[String]) -> bool {
        if !self.policy.enable_auto_repair {
            return false;
        }

        path_ids.iter().any(|path_id| {
            if let Some(state) = self.paths.get(path_id) {
                state.metrics.loss_rate > self.policy.repair_loss_threshold
            } else {
                false
            }
        })
    }

    fn calculate_optimal_fec_rate(&self, path_ids: &[String]) -> f64 {
        let max_loss_rate = path_ids
            .iter()
            .filter_map(|path_id| self.paths.get(path_id))
            .map(|state| state.metrics.loss_rate)
            .fold(0.0, f64::max);

        // FEC rate should be slightly higher than loss rate
        (max_loss_rate * 1.5).min(0.3).max(0.05)
    }

    fn should_use_relay(&self, path_ids: &[String]) -> bool {
        if !self.policy.use_relays_on_poor_paths {
            return false;
        }

        path_ids.iter().all(|path_id| {
            if let Some(state) = self.paths.get(path_id) {
                state.ranking_score < 0.5
            } else {
                true
            }
        })
    }

    fn calculate_congestion_params(
        &self,
        path_ids: &[String],
        _transfer_size: u64,
    ) -> CongestionParams {
        // Use most conservative settings from selected paths
        let min_cwnd = path_ids
            .iter()
            .filter_map(|path_id| self.paths.get(path_id))
            .map(|state| state.metrics.congestion_window_bytes as u32)
            .min()
            .unwrap_or(12_000);

        CongestionParams {
            initial_cwnd: (min_cwnd / 2).max(1200),
            max_cwnd: min_cwnd * 4,
            algorithm: CongestionAlgorithm::AtpAdaptive,
            pacing_rate: None,
        }
    }

    fn estimate_completion_time(&self, path_ids: &[String], transfer_size: u64) -> Duration {
        let total_bandwidth: u64 = path_ids
            .iter()
            .filter_map(|path_id| self.paths.get(path_id))
            .map(|state| {
                // Estimate bandwidth from congestion window and RTT
                if let Some(rtt_micros) = state.metrics.smoothed_rtt_micros {
                    let rtt_seconds = rtt_micros as f64 / 1_000_000.0;
                    (state.metrics.congestion_window_bytes as f64 / rtt_seconds) as u64
                } else {
                    1_000_000 // 1 MB/s fallback
                }
            })
            .sum();

        if total_bandwidth > 0 {
            Duration::from_secs(transfer_size / total_bandwidth)
        } else {
            Duration::from_secs(60) // Fallback estimate
        }
    }

    fn calculate_decision_confidence(&self, path_ids: &[String]) -> f64 {
        let avg_stability: f64 = path_ids
            .iter()
            .filter_map(|path_id| self.paths.get(path_id))
            .map(|state| state.metrics.path_stability)
            .sum::<f64>()
            / path_ids.len() as f64;

        avg_stability.min(1.0).max(0.0)
    }

    fn record_decision(&mut self, transfer_id: String, decision: &TransferDecision) {
        let decision_id = format!("{}_{}", transfer_id, self.decision_history.decisions.len());
        let historical_decision = HistoricalDecision {
            decision_id: decision_id.clone(),
            transfer_id,
            timestamp: Instant::now(),
            paths_selected: decision.selected_paths.clone(),
            rationale: format!(
                "Paths: {:?}, Repair: {}, Relay: {}",
                decision.selected_paths, decision.enable_repair, decision.use_relay
            ),
        };
        self.decision_history.decisions.push(historical_decision);

        // Limit history size
        if self.decision_history.decisions.len() > 1000 {
            self.decision_history.decisions.remove(0);
        }
    }

    fn calculate_recommendation_urgency(
        &self,
        recommendation: &PathRecommendation,
        metrics: &AtpTransportMetrics,
    ) -> f64 {
        match recommendation {
            PathRecommendation::SwitchPath { .. } => {
                if metrics.loss_rate > 0.2 {
                    1.0 // Critical
                } else if metrics.loss_rate > 0.1 {
                    0.8 // High
                } else {
                    0.5 // Medium
                }
            }
            PathRecommendation::ReduceSendingRate { .. } => {
                if metrics.congestion_limited {
                    0.7 // High
                } else {
                    0.3 // Low
                }
            }
            PathRecommendation::EnableRepair { .. } => {
                metrics.loss_rate.min(1.0) // Urgency scales with loss rate
            }
            PathRecommendation::EnablePathValidation => 0.6,
            PathRecommendation::PerformMtuDiscovery => 0.4,
            PathRecommendation::ConsiderRelay => 0.5,
        }
    }
}

impl Default for AtpTransferBrain {
    fn default() -> Self {
        Self::new()
    }
}

impl PathHistory {
    fn new() -> Self {
        Self {
            throughput_samples: Vec::with_capacity(100),
            latency_samples: Vec::with_capacity(100),
            success_rate: 1.0,
            avg_performance: 0.5,
        }
    }

    fn update_from_metrics(&mut self, metrics: &AtpTransportMetrics) {
        // Estimate throughput from cwnd and RTT
        if let Some(rtt_micros) = metrics.smoothed_rtt_micros {
            let rtt_seconds = rtt_micros as f64 / 1_000_000.0;
            let throughput = (metrics.congestion_window_bytes as f64 / rtt_seconds) as u64;
            self.throughput_samples.push(throughput);
            if self.throughput_samples.len() > 100 {
                self.throughput_samples.remove(0);
            }
        }

        if let Some(rtt) = metrics.latest_rtt_micros {
            self.latency_samples.push(rtt);
            if self.latency_samples.len() > 100 {
                self.latency_samples.remove(0);
            }
        }

        // Update average performance (simplified)
        let current_performance = metrics.path_stability * (1.0 - metrics.loss_rate);
        self.avg_performance = self.avg_performance * 0.9 + current_performance * 0.1;
    }
}

/// Path optimization recommendation with urgency.
#[derive(Debug, Clone)]
pub struct PathOptimizationRecommendation {
    /// Path this recommendation applies to.
    pub path_id: String,
    /// The specific recommendation.
    pub recommendation: PathRecommendation,
    /// Urgency score (0.0 - 1.0, higher = more urgent).
    pub urgency: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::atp::quic::metrics::{AtpTransportMetrics, PathDoctorAssessment};

    fn create_test_metrics(
        path_id: &str,
        loss_rate: f64,
        rtt_micros: u64,
        stability: f64,
    ) -> AtpTransportMetrics {
        AtpTransportMetrics {
            connection_id: "test_conn".to_string(),
            path_id: path_id.to_string(),
            smoothed_rtt_micros: Some(rtt_micros),
            latest_rtt_micros: Some(rtt_micros),
            rttvar_micros: Some(rtt_micros / 10),
            bytes_in_flight: 1200,
            congestion_window_bytes: 12_000,
            ssthresh_bytes: 24_000,
            pto_count: 0,
            congestion_limited: false,
            anti_amplification_limited: false,
            packets_sent: 100,
            packets_lost: (loss_rate * 100.0) as u64,
            packets_acked: ((1.0 - loss_rate) * 100.0) as u64,
            loss_rate,
            path_stability: stability,
            last_updated: Instant::now(),
            path_doctor_assessment: Some(PathDoctorAssessment {
                health_score: 1.0 - loss_rate,
                detected_issues: Vec::new(),
                recommendations: Vec::new(),
                performance_class: PathPerformanceClass::from_metrics(&AtpTransportMetrics {
                    connection_id: "dummy".to_string(),
                    path_id: "dummy".to_string(),
                    smoothed_rtt_micros: Some(rtt_micros),
                    latest_rtt_micros: Some(rtt_micros),
                    rttvar_micros: Some(rtt_micros / 10),
                    bytes_in_flight: 1200,
                    congestion_window_bytes: 12_000,
                    ssthresh_bytes: 24_000,
                    pto_count: 0,
                    congestion_limited: false,
                    anti_amplification_limited: false,
                    packets_sent: 100,
                    packets_lost: (loss_rate * 100.0) as u64,
                    packets_acked: ((1.0 - loss_rate) * 100.0) as u64,
                    loss_rate,
                    path_stability: stability,
                    last_updated: Instant::now(),
                    path_doctor_assessment: None,
                }),
            }),
        }
    }

    #[test]
    fn transfer_brain_path_selection() {
        let mut brain = AtpTransferBrain::new();

        // Add some paths with different qualities
        brain.update_path_metrics(create_test_metrics("good_path", 0.01, 50_000, 0.9));
        brain.update_path_metrics(create_test_metrics("poor_path", 0.15, 200_000, 0.3));
        brain.update_path_metrics(create_test_metrics("excellent_path", 0.005, 30_000, 0.95));

        let decision = brain
            .make_transfer_decision(
                "test_transfer".to_string(),
                1_000_000,
                TransferPriority::Normal,
            )
            .expect("Should make decision");

        // Should prefer excellent path, then good path, and exclude poor path
        assert_eq!(decision.selected_paths[0], "excellent_path");
        assert_eq!(decision.selected_paths[1], "good_path");
        assert_eq!(decision.selected_paths.len(), 2);
    }

    #[test]
    fn repair_decision_logic() {
        let mut brain = AtpTransferBrain::new();

        // Add path with high loss rate
        brain.update_path_metrics(create_test_metrics("lossy_path", 0.08, 100_000, 0.7));

        let decision = brain
            .make_transfer_decision(
                "test_transfer".to_string(),
                1_000_000,
                TransferPriority::Normal,
            )
            .expect("Should make decision");

        // Should enable repair due to high loss rate (0.08 > 0.05 threshold)
        assert!(decision.enable_repair);
        assert!(decision.fec_rate.is_some());
    }

    #[test]
    fn path_ranking_calculation() {
        let brain = AtpTransferBrain::new();

        let good_metrics = create_test_metrics("good", 0.02, 50_000, 0.9);
        let poor_metrics = create_test_metrics("poor", 0.1, 300_000, 0.4);

        let good_score = brain.calculate_path_ranking(&good_metrics);
        let poor_score = brain.calculate_path_ranking(&poor_metrics);

        assert!(
            good_score > poor_score,
            "Good path should rank higher than poor path"
        );
        assert!(good_score > 0.7, "Good path should have high score");
        assert!(poor_score < 0.5, "Poor path should have low score");
    }

    #[test]
    fn completion_time_estimation() {
        let mut brain = AtpTransferBrain::new();

        // Path with known characteristics
        brain.update_path_metrics(create_test_metrics("test_path", 0.01, 100_000, 0.8));

        let transfer_size = 1_000_000; // 1MB
        let completion_time =
            brain.estimate_completion_time(&["test_path".to_string()], transfer_size);

        // Should estimate reasonable completion time (not zero or extremely long)
        assert!(completion_time.as_secs() > 0);
        assert!(completion_time.as_secs() < 3600); // Less than 1 hour
    }
}
