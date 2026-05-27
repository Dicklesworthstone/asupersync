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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
    /// Candidate relays available to the transfer brain.
    pub relay_candidates: Vec<RelayCandidate>,
}

/// Configured relay candidate for poor direct paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayCandidate {
    /// Stable relay identifier returned in transfer decisions.
    pub relay_id: String,
    /// Optional direct path this relay is best suited to assist.
    pub assisted_path_id: Option<String>,
    /// Administrative priority; higher values win after cost and latency.
    pub priority: u8,
    /// Added latency estimate in microseconds.
    pub added_latency_micros: u64,
    /// Cost estimate in microseconds per MiB.
    pub cost_micros_per_mib: u64,
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
            relay_candidates: Vec::new(),
        }
    }
}

/// Transfer Brain decisions for a transfer operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferDecision {
    /// Stable decision identifier for trace/proof correlation.
    pub decision_id: String,
    /// Selected paths for this transfer, ordered by preference.
    pub selected_paths: Vec<String>,
    /// Structured explanation of the decision.
    pub reason_vector: Vec<DecisionReason>,
    /// Candidate paths rejected by the scheduler, ordered deterministically.
    pub rejected_paths: Vec<RejectedPathEvidence>,
    /// Pressure snapshot used while making this decision.
    pub pressure_snapshot: DecisionPressureSnapshot,
    /// Fairness state used while making this decision.
    pub fairness_state: DecisionFairnessState,
    /// Replay pointer for deterministic diagnostics.
    pub replay_pointer: String,
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

/// One machine-readable reason for a transfer decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionReason {
    /// Stable reason code.
    pub code: DecisionReasonCode,
    /// Human-oriented detail suitable for logs.
    pub detail: String,
}

/// Stable reason codes emitted by the transfer brain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionReasonCode {
    /// Path was selected for the transfer.
    PathSelected,
    /// Path was rejected before scheduling.
    PathRejected,
    /// Selection order used deterministic tie-breaking.
    DeterministicTieBreak,
    /// Repair was enabled.
    RepairEnabled,
    /// Repair was disabled.
    RepairDisabled,
    /// Relay use was enabled.
    RelayEnabled,
    /// Relay use was disabled.
    RelayDisabled,
}

/// Evidence for a path that was not selected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RejectedPathEvidence {
    /// Path identifier.
    pub path_id: String,
    /// Ranking score observed for the path.
    pub ranking_score: f64,
    /// Path doctor class, if one was available.
    pub performance_class: Option<PathPerformanceClass>,
    /// Why this path was rejected.
    pub reason: PathRejectionReason,
}

/// Reason a path was not eligible for a transfer decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathRejectionReason {
    /// Ranking score did not meet the configured threshold.
    BelowQualityThreshold {
        /// Observed score.
        score: f64,
        /// Required score.
        threshold: f64,
    },
    /// Path doctor class is not usable for this transfer.
    UnschedulablePerformanceClass {
        /// Observed class, or `None` when no assessment exists.
        performance_class: Option<PathPerformanceClass>,
    },
    /// Path was eligible but not selected because the path limit was reached.
    PathLimitReached {
        /// Configured maximum selected paths.
        max_paths: usize,
    },
}

/// Network pressure inputs considered by one transfer decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionPressureSnapshot {
    /// Number of paths selected.
    pub selected_path_count: usize,
    /// Maximum observed loss rate among selected paths.
    pub max_loss_rate: f64,
    /// Smallest selected congestion window in bytes.
    pub min_cwnd_bytes: u64,
    /// Count of selected paths currently congestion-limited.
    pub congestion_limited_path_count: usize,
    /// Count of selected paths limited by anti-amplification.
    pub anti_amplification_limited_path_count: usize,
}

/// Fairness inputs considered by one transfer decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionFairnessState {
    /// Active transfer counts for selected paths.
    pub active_transfers_by_path: BTreeMap<String, usize>,
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
    /// Monotonic decision sequence for stable replay identifiers.
    next_sequence: u64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct HistoricalDecision {
    /// Decision identifier.
    decision_id: String,
    /// Transfer identifier.
    transfer_id: String,
    /// Decision timestamp.
    timestamp: Instant,
    /// Paths selected.
    paths_selected: Vec<String>,
    /// Estimated completion time captured at scheduling time.
    estimated_completion_time: Duration,
    /// Decision rationale.
    rationale: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
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
                next_sequence: 0,
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
        let mut reason_vector = Vec::new();
        let mut rejected_paths = Vec::new();
        let mut eligible_paths = Vec::new();

        for (path_id, state) in &self.paths {
            let performance_class = state
                .metrics
                .path_doctor_assessment
                .as_ref()
                .map(|a| a.performance_class);
            if let Some(reason) = self.path_rejection_reason(state, performance_class) {
                reason_vector.push(DecisionReason {
                    code: DecisionReasonCode::PathRejected,
                    detail: format!(
                        "rejected {path_id} with ranking_score={:.6}: {}",
                        state.ranking_score,
                        describe_rejection_reason(&reason)
                    ),
                });
                rejected_paths.push(RejectedPathEvidence {
                    path_id: path_id.clone(),
                    ranking_score: state.ranking_score,
                    performance_class,
                    reason,
                });
            } else {
                eligible_paths.push((path_id.clone(), state.ranking_score));
            }
        }

        sort_ranked_paths(&mut eligible_paths);
        sort_rejected_paths(&mut rejected_paths);

        if eligible_paths.is_empty() {
            return AtpOutcome::transport_error(TransportError::NetworkUnreachable);
        }

        let had_score_ties = has_score_ties(&eligible_paths);
        let mut selected_paths = eligible_paths;
        let over_limit_paths = selected_paths
            .iter()
            .skip(self.policy.max_paths_per_transfer)
            .cloned()
            .collect::<Vec<_>>();
        selected_paths.truncate(self.policy.max_paths_per_transfer);
        let selected_path_ids: Vec<String> =
            selected_paths.iter().map(|(id, _)| id.clone()).collect();

        if selected_path_ids.is_empty() {
            return AtpOutcome::transport_error(TransportError::NetworkUnreachable);
        }

        let decision_id = self.allocate_decision_id(&transfer_id);

        for (path_id, score) in &selected_paths {
            reason_vector.push(DecisionReason {
                code: DecisionReasonCode::PathSelected,
                detail: format!("selected {path_id} with ranking_score={score:.6}"),
            });
        }

        for (path_id, score) in over_limit_paths {
            let reason = PathRejectionReason::PathLimitReached {
                max_paths: self.policy.max_paths_per_transfer,
            };
            reason_vector.push(DecisionReason {
                code: DecisionReasonCode::PathRejected,
                detail: format!(
                    "rejected {path_id} with ranking_score={score:.6}: {}",
                    describe_rejection_reason(&reason)
                ),
            });
            rejected_paths.push(RejectedPathEvidence {
                path_id: path_id.clone(),
                ranking_score: score,
                performance_class: self.path_performance_class(&path_id),
                reason,
            });
        }
        sort_rejected_paths(&mut rejected_paths);

        if had_score_ties {
            reason_vector.push(DecisionReason {
                code: DecisionReasonCode::DeterministicTieBreak,
                detail: "equal ranking scores ordered by path id".to_string(),
            });
        }

        // Determine if repair should be enabled
        let enable_repair = self.should_enable_repair(&selected_path_ids);
        let fec_rate = if enable_repair {
            Some(self.calculate_optimal_fec_rate(&selected_path_ids))
        } else {
            None
        };
        reason_vector.push(DecisionReason {
            code: if enable_repair {
                DecisionReasonCode::RepairEnabled
            } else {
                DecisionReasonCode::RepairDisabled
            },
            detail: format!(
                "repair={} threshold={:.6} fec_rate={:?}",
                enable_repair, self.policy.repair_loss_threshold, fec_rate
            ),
        });

        // Determine if relay should be used
        let use_relay = self.should_use_relay(&selected_path_ids);
        let suggested_relay = if use_relay {
            self.select_suggested_relay(&selected_path_ids)
        } else {
            None
        };
        reason_vector.push(DecisionReason {
            code: if use_relay {
                DecisionReasonCode::RelayEnabled
            } else {
                DecisionReasonCode::RelayDisabled
            },
            detail: self.relay_decision_detail(use_relay, suggested_relay.as_deref()),
        });

        // Calculate congestion parameters
        let congestion_params = self.calculate_congestion_params(&selected_path_ids, transfer_size);

        // Estimate completion time
        let estimated_completion_time =
            self.estimate_completion_time(&selected_path_ids, transfer_size);

        // Calculate confidence
        let confidence = self.calculate_decision_confidence(&selected_path_ids);
        let pressure_snapshot = self.decision_pressure_snapshot(&selected_path_ids);
        let fairness_state = self.decision_fairness_state(&selected_path_ids);
        let replay_pointer = format!("atp-transfer-brain:{decision_id}");

        let decision = TransferDecision {
            decision_id,
            selected_paths: selected_path_ids.clone(),
            reason_vector,
            rejected_paths,
            pressure_snapshot,
            fairness_state,
            replay_pointer,
            congestion_params,
            enable_repair,
            fec_rate,
            use_relay,
            suggested_relay,
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
            let performance_ratio =
                calculate_performance_ratio(decision.estimated_completion_time, completion_time);
            let outcome = DecisionOutcome {
                completion_time,
                success,
                performance_ratio,
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
            compare_score_desc(a.urgency, b.urgency).then_with(|| a.path_id.cmp(&b.path_id))
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

        finite_unit(
            performance_score * performance_weight + metrics.path_stability * stability_weight,
        )
    }

    fn update_path_preferences(&mut self) {
        // Mark top paths as preferred
        let mut paths_by_score: Vec<_> = self.paths.iter_mut().collect();
        paths_by_score.sort_by(|a, b| {
            compare_score_desc(a.1.ranking_score, b.1.ranking_score).then_with(|| a.0.cmp(b.0))
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
        (max_loss_rate * 1.5).clamp(0.05, 0.3)
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

    fn select_suggested_relay(&self, path_ids: &[String]) -> Option<String> {
        self.policy
            .relay_candidates
            .iter()
            .filter(|candidate| {
                candidate
                    .assisted_path_id
                    .as_ref()
                    .is_none_or(|assisted_path_id| path_ids.contains(assisted_path_id))
            })
            .min_by(|left, right| {
                left.cost_micros_per_mib
                    .cmp(&right.cost_micros_per_mib)
                    .then_with(|| left.added_latency_micros.cmp(&right.added_latency_micros))
                    .then_with(|| right.priority.cmp(&left.priority))
                    .then_with(|| left.relay_id.cmp(&right.relay_id))
            })
            .map(|candidate| candidate.relay_id.clone())
    }

    fn relay_decision_detail(&self, use_relay: bool, suggested_relay: Option<&str>) -> String {
        if !use_relay {
            return format!(
                "relay=false policy_use_relays_on_poor_paths={}",
                self.policy.use_relays_on_poor_paths
            );
        }

        match suggested_relay {
            Some(relay_id) => format!(
                "relay=true selected_relay={relay_id} candidate_count={}",
                self.policy.relay_candidates.len()
            ),
            None => format!(
                "relay=true selected_relay=none candidate_count={} no_applicable_configured_relay",
                self.policy.relay_candidates.len()
            ),
        }
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

        finite_unit(avg_stability)
    }

    fn record_decision(&mut self, transfer_id: String, decision: &TransferDecision) {
        let historical_decision = HistoricalDecision {
            decision_id: decision.decision_id.clone(),
            transfer_id,
            timestamp: Instant::now(),
            paths_selected: decision.selected_paths.clone(),
            estimated_completion_time: decision.estimated_completion_time,
            rationale: decision
                .reason_vector
                .iter()
                .map(|reason| reason.detail.as_str())
                .collect::<Vec<_>>()
                .join("; "),
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

    fn allocate_decision_id(&mut self, transfer_id: &str) -> String {
        let sequence = self.decision_history.next_sequence;
        self.decision_history.next_sequence += 1;
        format!("{transfer_id}_{sequence}")
    }

    fn path_rejection_reason(
        &self,
        state: &PathState,
        performance_class: Option<PathPerformanceClass>,
    ) -> Option<PathRejectionReason> {
        if state.ranking_score < self.policy.min_path_quality {
            return Some(PathRejectionReason::BelowQualityThreshold {
                score: state.ranking_score,
                threshold: self.policy.min_path_quality,
            });
        }

        if !matches!(
            performance_class,
            Some(
                PathPerformanceClass::Excellent
                    | PathPerformanceClass::Good
                    | PathPerformanceClass::Fair
            )
        ) {
            return Some(PathRejectionReason::UnschedulablePerformanceClass { performance_class });
        }

        None
    }

    fn path_performance_class(&self, path_id: &str) -> Option<PathPerformanceClass> {
        self.paths.get(path_id).and_then(|state| {
            state
                .metrics
                .path_doctor_assessment
                .as_ref()
                .map(|assessment| assessment.performance_class)
        })
    }

    fn decision_pressure_snapshot(&self, path_ids: &[String]) -> DecisionPressureSnapshot {
        let mut max_loss_rate = 0.0_f64;
        let mut min_cwnd_bytes = u64::MAX;
        let mut congestion_limited_path_count = 0;
        let mut anti_amplification_limited_path_count = 0;

        for state in path_ids
            .iter()
            .filter_map(|path_id| self.paths.get(path_id))
        {
            max_loss_rate = max_loss_rate.max(state.metrics.loss_rate);
            min_cwnd_bytes = min_cwnd_bytes.min(state.metrics.congestion_window_bytes);
            if state.metrics.congestion_limited {
                congestion_limited_path_count += 1;
            }
            if state.metrics.anti_amplification_limited {
                anti_amplification_limited_path_count += 1;
            }
        }

        DecisionPressureSnapshot {
            selected_path_count: path_ids.len(),
            max_loss_rate: finite_unit(max_loss_rate),
            min_cwnd_bytes: if min_cwnd_bytes == u64::MAX {
                0
            } else {
                min_cwnd_bytes
            },
            congestion_limited_path_count,
            anti_amplification_limited_path_count,
        }
    }

    fn decision_fairness_state(&self, path_ids: &[String]) -> DecisionFairnessState {
        DecisionFairnessState {
            active_transfers_by_path: path_ids
                .iter()
                .filter_map(|path_id| {
                    self.paths
                        .get(path_id)
                        .map(|state| (path_id.clone(), state.active_transfers.len()))
                })
                .collect(),
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

        if metrics.packets_acked + metrics.packets_lost > 0 {
            let observed_success_rate = metrics.packets_acked as f64
                / (metrics.packets_acked + metrics.packets_lost) as f64;
            self.success_rate =
                finite_unit((self.success_rate * 0.8) + (observed_success_rate * 0.2));
        }

        let latest_throughput = self.throughput_samples.last().copied().unwrap_or(0);
        let peak_throughput = self.throughput_samples.iter().copied().max().unwrap_or(1);
        let throughput_score = if peak_throughput > 0 {
            latest_throughput as f64 / peak_throughput as f64
        } else {
            0.0
        };
        let latest_latency = self.latency_samples.last().copied().unwrap_or(u64::MAX);
        let best_latency = self
            .latency_samples
            .iter()
            .copied()
            .min()
            .unwrap_or(latest_latency);
        let latency_score = if latest_latency > 0 && latest_latency != u64::MAX {
            best_latency as f64 / latest_latency as f64
        } else {
            0.0
        };
        let congestion_penalty = if metrics.congestion_limited {
            0.15
        } else {
            0.0
        } + if metrics.anti_amplification_limited {
            0.10
        } else {
            0.0
        };
        let current_performance = finite_unit(
            throughput_score.clamp(0.0, 1.0) * 0.25
                + latency_score.clamp(0.0, 1.0) * 0.20
                + self.success_rate.clamp(0.0, 1.0) * 0.25
                + metrics.path_stability.clamp(0.0, 1.0) * 0.30
                - congestion_penalty,
        );
        self.avg_performance =
            finite_unit((self.avg_performance * 0.85) + (current_performance * 0.15));
    }
}

fn sort_ranked_paths(paths: &mut [(String, f64)]) {
    paths.sort_by(|a, b| compare_score_desc(a.1, b.1).then_with(|| a.0.cmp(&b.0)));
}

fn sort_rejected_paths(paths: &mut [RejectedPathEvidence]) {
    paths.sort_by(|a, b| {
        compare_score_desc(a.ranking_score, b.ranking_score).then_with(|| a.path_id.cmp(&b.path_id))
    });
}

fn compare_score_desc(left: f64, right: f64) -> std::cmp::Ordering {
    right
        .partial_cmp(&left)
        .unwrap_or(std::cmp::Ordering::Equal)
}

fn has_score_ties(paths: &[(String, f64)]) -> bool {
    paths
        .windows(2)
        .any(|window| window[0].1.total_cmp(&window[1].1) == std::cmp::Ordering::Equal)
}

fn finite_unit(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

fn calculate_performance_ratio(predicted: Duration, actual: Duration) -> f64 {
    let predicted_nanos = predicted.as_nanos();
    let actual_nanos = actual.as_nanos();

    match (predicted_nanos, actual_nanos) {
        (0, 0) => 1.0,
        (_, 0) => f64::INFINITY,
        (0, _) => 0.0,
        (predicted, actual) => (predicted as f64 / actual as f64).clamp(0.0, f64::MAX),
    }
}

fn describe_rejection_reason(reason: &PathRejectionReason) -> String {
    match reason {
        PathRejectionReason::BelowQualityThreshold { score, threshold } => {
            format!("quality below threshold score={score:.6} threshold={threshold:.6}")
        }
        PathRejectionReason::UnschedulablePerformanceClass { performance_class } => {
            format!("unschedulable performance_class={performance_class:?}")
        }
        PathRejectionReason::PathLimitReached { max_paths } => {
            format!("path limit reached max_paths={max_paths}")
        }
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
                    connection_id: format!("test_conn_{path_id}"),
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
        brain.update_path_metrics(create_test_metrics("poor_path", 0.9, 800_000, 0.1));
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
    fn relay_selection_uses_configured_candidate() {
        let policy = TransferPolicy {
            relay_candidates: vec![
                RelayCandidate {
                    relay_id: "relay_slow".to_string(),
                    assisted_path_id: Some("poor_direct".to_string()),
                    priority: 10,
                    added_latency_micros: 80_000,
                    cost_micros_per_mib: 400_000,
                },
                RelayCandidate {
                    relay_id: "relay_fast".to_string(),
                    assisted_path_id: Some("poor_direct".to_string()),
                    priority: 5,
                    added_latency_micros: 20_000,
                    cost_micros_per_mib: 100_000,
                },
            ],
            ..TransferPolicy::default()
        };
        let mut brain = AtpTransferBrain::with_policy(policy);
        let mut metrics = create_test_metrics("poor_direct", 0.04, 250_000, 0.1);
        metrics
            .path_doctor_assessment
            .as_mut()
            .unwrap()
            .performance_class = PathPerformanceClass::Fair;
        brain.update_path_metrics(metrics);

        let decision = brain
            .make_transfer_decision(
                "relay_transfer".to_string(),
                1_000_000,
                TransferPriority::Normal,
            )
            .expect("decision");

        assert!(decision.use_relay);
        assert_eq!(decision.suggested_relay.as_deref(), Some("relay_fast"));
    }

    #[test]
    fn completion_report_records_prediction_error_ratio() {
        let mut brain = AtpTransferBrain::new();
        brain.update_path_metrics(create_test_metrics("test_path", 0.01, 100_000, 0.8));

        let decision = brain
            .make_transfer_decision(
                "ratio_transfer".to_string(),
                1_000_000,
                TransferPriority::Normal,
            )
            .expect("decision");
        let actual = decision.estimated_completion_time.saturating_mul(2);
        brain.report_transfer_completion("ratio_transfer", actual, true);

        let outcome = brain
            .decision_history
            .outcomes
            .get(&decision.decision_id)
            .expect("outcome");
        assert!(outcome.success);
        assert!(outcome.performance_ratio > 0.0);
        assert!(outcome.performance_ratio < 1.0);
    }

    #[test]
    fn path_ranking_calculation() {
        let brain = AtpTransferBrain::new();

        let good_metrics = create_test_metrics("good", 0.02, 50_000, 0.9);
        let poor_metrics = create_test_metrics("poor", 0.9, 800_000, 0.1);

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

    #[test]
    fn equal_scores_use_deterministic_tie_break_and_record_evidence() {
        let policy = TransferPolicy {
            max_paths_per_transfer: 1,
            min_path_quality: 0.0,
            ..TransferPolicy::default()
        };
        let mut brain = AtpTransferBrain::with_policy(policy);

        brain.update_path_metrics(create_test_metrics("z_path", 0.01, 50_000, 0.9));
        brain.update_path_metrics(create_test_metrics("a_path", 0.01, 50_000, 0.9));

        let decision = brain
            .make_transfer_decision(
                "tie_transfer".to_string(),
                1_000_000,
                TransferPriority::Normal,
            )
            .expect("decision");

        assert_eq!(decision.decision_id, "tie_transfer_0");
        assert_eq!(decision.selected_paths, vec!["a_path"]);
        assert_eq!(decision.replay_pointer, "atp-transfer-brain:tie_transfer_0");
        assert_eq!(
            brain.decision_history.decisions[0].decision_id,
            decision.decision_id
        );
        assert_eq!(decision.rejected_paths.len(), 1);
        assert_eq!(decision.rejected_paths[0].path_id, "z_path");
        assert!(matches!(
            decision.rejected_paths[0].reason,
            PathRejectionReason::PathLimitReached { max_paths: 1 }
        ));
        assert!(
            decision
                .reason_vector
                .iter()
                .any(|reason| reason.code == DecisionReasonCode::DeterministicTieBreak)
        );
        assert_eq!(
            decision
                .fairness_state
                .active_transfers_by_path
                .get("a_path"),
            Some(&0)
        );
    }

    #[test]
    fn zero_path_limit_fails_closed_without_empty_confidence() {
        let policy = TransferPolicy {
            max_paths_per_transfer: 0,
            min_path_quality: 0.0,
            ..TransferPolicy::default()
        };
        let mut brain = AtpTransferBrain::with_policy(policy);

        brain.update_path_metrics(create_test_metrics("good_path", 0.01, 50_000, 0.95));

        let decision = brain.make_transfer_decision(
            "zero_limit_transfer".to_string(),
            1_000_000,
            TransferPriority::Normal,
        );

        assert!(decision.is_err());
        assert!(brain.decision_history.decisions.is_empty());
    }

    #[test]
    fn rejected_paths_explain_quality_and_class_failures() {
        let policy = TransferPolicy {
            min_path_quality: 0.2,
            ..TransferPolicy::default()
        };
        let mut brain = AtpTransferBrain::with_policy(policy);

        brain.update_path_metrics(create_test_metrics("good_path", 0.01, 50_000, 0.95));
        brain.update_path_metrics(create_test_metrics("low_score_path", 0.15, 200_000, 0.3));
        brain
            .paths
            .get_mut("low_score_path")
            .expect("low score path should exist")
            .ranking_score = 0.1;

        let mut unusable = create_test_metrics("unusable_path", 0.01, 50_000, 0.95);
        unusable
            .path_doctor_assessment
            .as_mut()
            .unwrap()
            .performance_class = PathPerformanceClass::Unusable;
        brain.update_path_metrics(unusable);

        let decision = brain
            .make_transfer_decision(
                "reject_transfer".to_string(),
                1_000_000,
                TransferPriority::Normal,
            )
            .expect("decision");

        assert_eq!(decision.selected_paths, vec!["good_path"]);
        assert_eq!(decision.rejected_paths.len(), 2);
        assert!(decision.rejected_paths.iter().any(|path| {
            path.path_id == "low_score_path"
                && matches!(
                    path.reason,
                    PathRejectionReason::BelowQualityThreshold { threshold, .. }
                    if (threshold - 0.2).abs() < f64::EPSILON
                )
        }));
        assert!(decision.rejected_paths.iter().any(|path| {
            path.path_id == "unusable_path"
                && matches!(
                    path.reason,
                    PathRejectionReason::UnschedulablePerformanceClass {
                        performance_class: Some(PathPerformanceClass::Unusable)
                    }
                )
        }));
        assert!(
            decision
                .reason_vector
                .iter()
                .any(|reason| reason.code == DecisionReasonCode::PathSelected)
        );
        assert!(
            decision
                .reason_vector
                .iter()
                .any(|reason| reason.code == DecisionReasonCode::PathRejected)
        );
    }

    #[test]
    fn pressure_snapshot_records_selected_path_pressure() {
        let mut brain = AtpTransferBrain::new();
        let mut metrics = create_test_metrics("limited_path", 0.08, 100_000, 0.8);
        metrics.congestion_limited = true;
        metrics.anti_amplification_limited = true;
        metrics.congestion_window_bytes = 24_000;
        brain.update_path_metrics(metrics);

        let decision = brain
            .make_transfer_decision(
                "pressure_transfer".to_string(),
                1_000_000,
                TransferPriority::High,
            )
            .expect("decision");

        assert_eq!(decision.pressure_snapshot.selected_path_count, 1);
        assert_eq!(decision.pressure_snapshot.max_loss_rate, 0.08);
        assert_eq!(decision.pressure_snapshot.min_cwnd_bytes, 24_000);
        assert_eq!(decision.pressure_snapshot.congestion_limited_path_count, 1);
        assert_eq!(
            decision
                .pressure_snapshot
                .anti_amplification_limited_path_count,
            1
        );
        assert!(decision.enable_repair);
        assert!(
            decision
                .reason_vector
                .iter()
                .any(|reason| reason.code == DecisionReasonCode::RepairEnabled)
        );
    }

    #[test]
    fn non_finite_path_scores_fail_closed() {
        let mut brain = AtpTransferBrain::new();
        let mut non_finite = create_test_metrics("nan_path", 0.01, 50_000, f64::NAN);
        non_finite.path_stability = f64::NAN;
        brain.update_path_metrics(non_finite);
        brain.update_path_metrics(create_test_metrics("good_path", 0.01, 50_000, 0.95));

        let rankings = brain.path_rankings();
        assert_eq!(rankings.get("nan_path"), Some(&0.0));

        let decision = brain
            .make_transfer_decision(
                "finite_transfer".to_string(),
                1_000_000,
                TransferPriority::Normal,
            )
            .expect("decision");

        assert_eq!(decision.selected_paths, vec!["good_path"]);
        assert!(decision.rejected_paths.iter().any(|path| {
            path.path_id == "nan_path"
                && matches!(
                    path.reason,
                    PathRejectionReason::BelowQualityThreshold { score, .. }
                    if score == 0.0
                )
        }));
    }
}
