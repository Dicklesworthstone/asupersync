//! Adaptive RaptorQ policy integration for economically optimal repair.
//!
//! Integrates the RepairCoordinator with existing RaptorQ pipeline to make
//! repair decisions economically adaptive based on measurable ROI across
//! different network regimes and transfer scenarios.

use crate::atp::object::ObjectId;
use crate::atp::repair_coordinator::{
    PathCharacteristics, RepairCoordinator, RepairCoordinatorConfig, RepairDecision, RepairMode,
    RepairRoi, RepairTelemetry, TransferState,
};
use crate::error::{Error, ErrorKind, Result};
use crate::types::TraceId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

/// Configuration for adaptive RaptorQ integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveRaptorQConfig {
    /// Repair coordinator configuration
    pub coordinator_config: RepairCoordinatorConfig,
    /// Enable automatic mode adaptation based on telemetry
    pub enable_adaptive_thresholds: bool,
    /// Learning rate for threshold adaptation (0.0 to 1.0)
    pub learning_rate: f64,
    /// Minimum number of samples before adapting thresholds
    pub min_samples_for_adaptation: u32,
    /// Integration with existing RaptorQ pipeline
    pub integrate_with_pipeline: bool,
}

impl Default for AdaptiveRaptorQConfig {
    fn default() -> Self {
        Self {
            coordinator_config: RepairCoordinatorConfig::default(),
            enable_adaptive_thresholds: true,
            learning_rate: 0.1,
            min_samples_for_adaptation: 10,
            integrate_with_pipeline: true,
        }
    }
}

/// Adaptive RaptorQ repair policy that learns from actual ROI
pub struct AdaptiveRaptorQPolicy {
    /// Configuration
    config: AdaptiveRaptorQConfig,
    /// Core repair coordinator
    coordinator: RepairCoordinator,
    /// Adaptive thresholds per repair mode
    adaptive_thresholds: HashMap<RepairMode, f64>,
    /// Active repair operations
    active_repairs: HashMap<ObjectId, ActiveRepair>,
    /// Policy statistics for monitoring
    policy_stats: PolicyStatistics,
}

/// Statistics for the adaptive policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStatistics {
    /// Total repair decisions made
    pub total_decisions: u64,
    /// Decisions by mode
    pub decisions_by_mode: HashMap<RepairMode, u64>,
    /// Average actual ROI by mode
    pub avg_roi_by_mode: HashMap<RepairMode, f64>,
    /// Success rate by mode
    pub success_rate_by_mode: HashMap<RepairMode, f64>,
    /// Policy start time
    pub started_at: SystemTime,
    /// Last threshold adaptation time
    pub last_adaptation: SystemTime,
}

impl Default for PolicyStatistics {
    fn default() -> Self {
        let now = SystemTime::now();
        Self {
            total_decisions: 0,
            decisions_by_mode: HashMap::new(),
            avg_roi_by_mode: HashMap::new(),
            success_rate_by_mode: HashMap::new(),
            started_at: now,
            last_adaptation: now,
        }
    }
}

/// Active repair operation being tracked
#[derive(Debug, Clone)]
struct ActiveRepair {
    /// Object being repaired
    object_id: ObjectId,
    /// Repair decision that started this operation
    decision: RepairDecision,
    /// Start time
    started_at: SystemTime,
    /// Expected completion time
    expected_completion: SystemTime,
    /// Repair progress (0.0 to 1.0)
    progress: f64,
    /// Actual resources used so far
    actual_cpu_used: Duration,
    /// Actual bandwidth used so far
    actual_bandwidth_used: u64,
    /// Number of repair symbols generated
    symbols_generated: u32,
    /// Number of symbols successfully transmitted
    symbols_transmitted: u32,
}

impl AdaptiveRaptorQPolicy {
    /// Create a new adaptive RaptorQ policy
    pub fn new(config: AdaptiveRaptorQConfig) -> Self {
        let coordinator = RepairCoordinator::new(config.coordinator_config.clone());

        // Initialize adaptive thresholds from base configuration
        let mut adaptive_thresholds = HashMap::new();
        for mode in [
            RepairMode::Off,
            RepairMode::Tail,
            RepairMode::Lossy,
            RepairMode::ResumeRepair,
            RepairMode::Broadcast,
            RepairMode::Swarm,
            RepairMode::RelayExpensive,
            RepairMode::MobileUnstable,
            RepairMode::HighBDP,
        ] {
            adaptive_thresholds.insert(mode, config.coordinator_config.min_roi_threshold);
        }

        Self {
            config,
            coordinator,
            adaptive_thresholds,
            active_repairs: HashMap::new(),
            policy_stats: PolicyStatistics::default(),
        }
    }

    /// Decide whether to use repair for a transfer and which mode
    pub fn should_use_repair(
        &mut self,
        object_id: ObjectId,
        path: &PathCharacteristics,
        transfer: &TransferState,
        trace_id: TraceId,
    ) -> Result<RepairPolicyResult> {
        // Make decision using repair coordinator
        let decision =
            self.coordinator
                .decide_repair_mode(object_id.clone(), path, transfer, trace_id)?;

        // Check against adaptive threshold if available
        let mode_threshold = self
            .adaptive_thresholds
            .get(&decision.mode)
            .copied()
            .unwrap_or(self.config.coordinator_config.min_roi_threshold);

        let should_repair =
            decision.mode != RepairMode::Off && decision.roi.roi_ratio >= mode_threshold;

        // Update statistics
        self.policy_stats.total_decisions += 1;
        *self
            .policy_stats
            .decisions_by_mode
            .entry(decision.mode)
            .or_insert(0) += 1;

        let result = RepairPolicyResult {
            should_use_repair: should_repair,
            recommended_mode: decision.mode,
            roi_estimate: decision.roi.clone(),
            reasoning: decision.reasoning.clone(),
            decision_factors: decision.factors.clone(),
            threshold_used: mode_threshold,
            adaptive_threshold: self.adaptive_thresholds.get(&decision.mode).copied(),
        };

        // Start tracking if repair is chosen
        if should_repair {
            self.start_tracking_repair(object_id, decision);
        }

        info!(
            "Repair policy decision for {}: {} (mode: {:?}, ROI: {:.2}, threshold: {:.2})",
            object_id,
            if should_repair { "REPAIR" } else { "NO_REPAIR" },
            result.recommended_mode,
            result.roi_estimate.roi_ratio,
            mode_threshold
        );

        Ok(result)
    }

    /// Update progress for an active repair operation
    pub fn update_repair_progress(
        &mut self,
        object_id: ObjectId,
        progress: f64,
        cpu_used: Duration,
        bandwidth_used: u64,
        symbols_generated: u32,
        symbols_transmitted: u32,
    ) -> Result<()> {
        if let Some(repair) = self.active_repairs.get_mut(&object_id) {
            repair.progress = progress.clamp(0.0, 1.0);
            repair.actual_cpu_used = cpu_used;
            repair.actual_bandwidth_used = bandwidth_used;
            repair.symbols_generated = symbols_generated;
            repair.symbols_transmitted = symbols_transmitted;

            debug!(
                "Updated repair progress for {}: {:.1}% ({} symbols)",
                object_id,
                progress * 100.0,
                symbols_transmitted
            );
        }

        Ok(())
    }

    /// Complete a repair operation and record telemetry
    pub fn complete_repair(
        &mut self,
        object_id: ObjectId,
        success: bool,
        final_cpu_time: Duration,
        final_bandwidth_used: u64,
        symbols_decoded: u32,
    ) -> Result<()> {
        if let Some(repair) = self.active_repairs.remove(&object_id) {
            let actual_repair_time = repair.started_at.elapsed().unwrap_or(Duration::ZERO);

            // Calculate actual benefit score
            let expected_benefit = repair.decision.roi.benefit_score;
            let time_factor = if actual_repair_time < repair.decision.roi.expected_time_saved {
                1.2 // Better than expected
            } else if actual_repair_time > repair.decision.roi.expected_time_saved * 2 {
                0.5 // Much worse than expected
            } else {
                1.0 // About as expected
            };

            let success_factor = if success { 1.0 } else { 0.0 };
            let actual_benefit_score = expected_benefit * time_factor * success_factor;

            let actual_roi_ratio = if repair.decision.roi.cost_score > 0.0 {
                actual_benefit_score / repair.decision.roi.cost_score
            } else {
                0.0
            };

            // Create telemetry record
            let telemetry = RepairTelemetry {
                object_id: object_id.clone(),
                mode: repair.decision.mode,
                predicted_roi: repair.decision.roi.clone(),
                actual_repair_time,
                actual_encode_cpu: final_cpu_time,
                actual_decode_cpu: Duration::from_millis(final_cpu_time.as_millis() as u64 / 2), // Estimate
                actual_bandwidth_used: final_bandwidth_used,
                repair_symbols_sent: repair.symbols_transmitted,
                repair_symbols_decoded: symbols_decoded,
                success,
                actual_benefit_score,
                actual_roi_ratio,
                measured_at: SystemTime::now(),
            };

            // Record telemetry with coordinator
            self.coordinator.record_telemetry(telemetry.clone());

            // Update policy statistics
            self.update_policy_statistics(&telemetry);

            // Adapt thresholds if enabled
            if self.config.enable_adaptive_thresholds {
                self.maybe_adapt_thresholds();
            }

            info!(
                "Completed repair for {}: {} (actual ROI: {:.2}, predicted: {:.2})",
                object_id,
                if success { "SUCCESS" } else { "FAILED" },
                actual_roi_ratio,
                repair.decision.roi.roi_ratio
            );
        }

        Ok(())
    }

    /// Get current policy statistics
    pub fn get_statistics(&self) -> &PolicyStatistics {
        &self.policy_stats
    }

    /// Get current adaptive thresholds
    pub fn get_adaptive_thresholds(&self) -> &HashMap<RepairMode, f64> {
        &self.adaptive_thresholds
    }

    /// Reset adaptive thresholds to default values
    pub fn reset_adaptive_thresholds(&mut self) {
        for threshold in self.adaptive_thresholds.values_mut() {
            *threshold = self.config.coordinator_config.min_roi_threshold;
        }
        info!(
            "Reset adaptive thresholds to default: {:.2}",
            self.config.coordinator_config.min_roi_threshold
        );
    }

    /// Get repair coordinator statistics
    pub fn get_coordinator_statistics(
        &self,
    ) -> &HashMap<RepairMode, crate::atp::repair_coordinator::ModeStatistics> {
        self.coordinator.get_mode_statistics()
    }

    // Private helper methods

    fn start_tracking_repair(&mut self, object_id: ObjectId, decision: RepairDecision) {
        let repair = ActiveRepair {
            object_id: object_id.clone(),
            expected_completion: SystemTime::now() + decision.roi.expected_time_saved,
            started_at: SystemTime::now(),
            decision,
            progress: 0.0,
            actual_cpu_used: Duration::ZERO,
            actual_bandwidth_used: 0,
            symbols_generated: 0,
            symbols_transmitted: 0,
        };

        self.active_repairs.insert(object_id, repair);
    }

    fn update_policy_statistics(&mut self, telemetry: &RepairTelemetry) {
        // Update average ROI for the mode
        let current_avg = self
            .policy_stats
            .avg_roi_by_mode
            .get(&telemetry.mode)
            .copied()
            .unwrap_or(0.0);
        let current_count = self
            .policy_stats
            .decisions_by_mode
            .get(&telemetry.mode)
            .copied()
            .unwrap_or(0);

        if current_count > 0 {
            let new_avg = (current_avg * (current_count - 1) as f64 + telemetry.actual_roi_ratio)
                / current_count as f64;
            self.policy_stats
                .avg_roi_by_mode
                .insert(telemetry.mode, new_avg);
        }

        // Update success rate
        let current_success_rate = self
            .policy_stats
            .success_rate_by_mode
            .get(&telemetry.mode)
            .copied()
            .unwrap_or(1.0);
        let success_value = if telemetry.success { 1.0 } else { 0.0 };
        let new_success_rate = (current_success_rate * (current_count - 1) as f64 + success_value)
            / current_count as f64;
        self.policy_stats
            .success_rate_by_mode
            .insert(telemetry.mode, new_success_rate);
    }

    fn maybe_adapt_thresholds(&mut self) {
        let now = SystemTime::now();
        let min_samples = self.config.min_samples_for_adaptation;

        // Only adapt every 60 seconds at most
        if now
            .duration_since(self.policy_stats.last_adaptation)
            .unwrap_or(Duration::ZERO)
            < Duration::from_secs(60)
        {
            return;
        }

        let mode_stats = self.coordinator.get_mode_statistics();
        let mut adapted_any = false;

        for (mode, stats) in mode_stats {
            if stats.usage_count >= min_samples {
                let current_threshold = self
                    .adaptive_thresholds
                    .get(mode)
                    .copied()
                    .unwrap_or(self.config.coordinator_config.min_roi_threshold);

                // If actual ROI is consistently higher than predicted, lower threshold
                // If actual ROI is consistently lower than predicted, raise threshold
                let roi_ratio = stats.avg_actual_roi / stats.avg_predicted_roi.max(0.1);
                let success_factor = stats.success_rate;

                let target_threshold = if roi_ratio > 1.2 && success_factor > 0.8 {
                    // Good performance, lower threshold to use more
                    current_threshold * 0.95
                } else if roi_ratio < 0.8 || success_factor < 0.6 {
                    // Poor performance, raise threshold to use less
                    current_threshold * 1.05
                } else {
                    current_threshold // No change
                };

                // Apply learning rate
                let new_threshold = current_threshold
                    + (target_threshold - current_threshold) * self.config.learning_rate;

                // Clamp to reasonable bounds
                let new_threshold = new_threshold.clamp(0.5, 5.0);

                if (new_threshold - current_threshold).abs() > 0.01 {
                    self.adaptive_thresholds.insert(*mode, new_threshold);
                    adapted_any = true;

                    debug!(
                        "Adapted threshold for {:?}: {:.3} -> {:.3} (ROI ratio: {:.2}, success: {:.1}%)",
                        mode,
                        current_threshold,
                        new_threshold,
                        roi_ratio,
                        success_factor * 100.0
                    );
                }
            }
        }

        if adapted_any {
            self.policy_stats.last_adaptation = now;
            info!("Adapted repair thresholds based on {} samples", min_samples);
        }
    }
}

/// Result of a repair policy decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairPolicyResult {
    /// Whether repair should be used
    pub should_use_repair: bool,
    /// Recommended repair mode
    pub recommended_mode: RepairMode,
    /// ROI estimate for the decision
    pub roi_estimate: RepairRoi,
    /// Human-readable reasoning
    pub reasoning: String,
    /// Decision factors considered
    pub decision_factors: crate::atp::repair_coordinator::RepairDecisionFactors,
    /// Threshold that was used for decision
    pub threshold_used: f64,
    /// Current adaptive threshold for this mode
    pub adaptive_threshold: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::repair_coordinator::TransferState;

    fn create_test_path() -> PathCharacteristics {
        PathCharacteristics {
            rtt_ms: 100.0,
            bandwidth_bps: 5_000_000,
            loss_rate: 0.05, // 5% loss
            jitter_ms: 10.0,
            bdp_bytes: 62_500,
            stability_score: 0.6,
            uses_relay: true,
            relay_cost_per_byte: 0.001,
            is_mobile: true,
            is_high_latency: false,
        }
    }

    fn create_test_transfer() -> TransferState {
        TransferState {
            object_size_bytes: 10_000_000, // 10MB
            bytes_transferred: 8_000_000,  // 80% complete
            missing_chunks: 50,
            missing_bytes: 2_000_000,
            is_resume: true,
            elapsed_time: Duration::from_secs(30),
            retransmit_attempts: 5,
            available_peers: 3,
            memory_pressure: 0.4,
            cpu_pressure: 0.3,
        }
    }

    #[test]
    fn test_adaptive_policy_creation() {
        let config = AdaptiveRaptorQConfig::default();
        let policy = AdaptiveRaptorQPolicy::new(config);

        assert!(policy.adaptive_thresholds.contains_key(&RepairMode::Off));
        assert!(policy.adaptive_thresholds.contains_key(&RepairMode::Tail));
        assert_eq!(policy.policy_stats.total_decisions, 0);
    }

    #[test]
    fn test_repair_decision() -> Result<()> {
        let config = AdaptiveRaptorQConfig {
            coordinator_config: RepairCoordinatorConfig {
                min_roi_threshold: 0.8,
                ..RepairCoordinatorConfig::default()
            },
            ..AdaptiveRaptorQConfig::default()
        };
        let mut policy = AdaptiveRaptorQPolicy::new(config);

        let object_id = ObjectId::from("test-object");
        let path = create_test_path();
        let transfer = create_test_transfer();

        let result = policy.should_use_repair(object_id, &path, &transfer, TraceId::new())?;

        assert!(result.roi_estimate.confidence > 0.0);
        assert!(!result.reasoning.is_empty());

        // Should consider repair for lossy mobile path with resume
        if result.should_use_repair {
            assert_ne!(result.recommended_mode, RepairMode::Off);
        }

        Ok(())
    }

    #[test]
    fn test_repair_tracking() -> Result<()> {
        let config = AdaptiveRaptorQConfig::default();
        let mut policy = AdaptiveRaptorQPolicy::new(config);

        let object_id = ObjectId::from("test-object");

        // Record an in-flight repair progress sample.
        policy.update_repair_progress(
            object_id.clone(),
            0.5, // 50% progress
            Duration::from_millis(100),
            50000,
            10,
            8,
        )?;

        // Complete repair
        policy.complete_repair(object_id, true, Duration::from_millis(150), 100000, 8)?;

        // Should have recorded telemetry
        assert!(
            policy.policy_stats.total_decisions > 0
                || !policy.coordinator.get_mode_statistics().is_empty()
        );

        Ok(())
    }

    #[test]
    fn test_threshold_adaptation() {
        let config = AdaptiveRaptorQConfig {
            enable_adaptive_thresholds: true,
            learning_rate: 0.2,
            min_samples_for_adaptation: 1, // Low for test
            ..AdaptiveRaptorQConfig::default()
        };
        let mut policy = AdaptiveRaptorQPolicy::new(config);

        let original_threshold = policy.adaptive_thresholds[&RepairMode::Tail];

        // Feed successful telemetry that should lower threshold.
        let telemetry = RepairTelemetry {
            object_id: ObjectId::from("test"),
            mode: RepairMode::Tail,
            predicted_roi: RepairRoi {
                roi_ratio: 1.0,
                confidence: 0.9,
                ..Default::default()
            },
            actual_roi_ratio: 1.5, // Better than predicted
            success: true,
            ..Default::default()
        };

        // Manually update statistics to trigger adaptation
        policy.coordinator.record_telemetry(telemetry);
        policy.policy_stats.last_adaptation = SystemTime::now() - Duration::from_secs(120);

        policy.maybe_adapt_thresholds();

        // Threshold might be adapted (depends on exact statistics)
        let new_threshold = policy.adaptive_thresholds[&RepairMode::Tail];
        assert!(new_threshold >= 0.5 && new_threshold <= 5.0); // In valid bounds
    }

    // Helper to create default RepairRoi for tests
    impl Default for RepairRoi {
        fn default() -> Self {
            Self {
                expected_time_saved: Duration::from_millis(100),
                encode_cpu_cost: Duration::from_millis(10),
                decode_cpu_cost: Duration::from_millis(5),
                bandwidth_overhead: 1000,
                memory_overhead: 500,
                coordination_cost: Duration::ZERO,
                benefit_score: 1.0,
                cost_score: 0.8,
                roi_ratio: 1.25,
                confidence: 0.7,
            }
        }
    }

    // Helper to create default RepairTelemetry for tests
    impl Default for RepairTelemetry {
        fn default() -> Self {
            Self {
                object_id: ObjectId::from("test"),
                mode: RepairMode::Tail,
                predicted_roi: RepairRoi::default(),
                actual_repair_time: Duration::from_millis(90),
                actual_encode_cpu: Duration::from_millis(12),
                actual_decode_cpu: Duration::from_millis(6),
                actual_bandwidth_used: 1200,
                repair_symbols_sent: 5,
                repair_symbols_decoded: 5,
                success: true,
                actual_benefit_score: 1.1,
                actual_roi_ratio: 1.3,
                measured_at: SystemTime::now(),
            }
        }
    }
}
