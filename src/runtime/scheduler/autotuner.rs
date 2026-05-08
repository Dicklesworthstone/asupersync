//! Scheduler hot-path autotuner for performance optimization.
//!
//! Provides observe-first autotuning for scheduler hot paths including:
//! - Lane selection priority tuning
//! - Local/global queue handoff optimization
//! - Batch sizing for ready/steal/handoff operations
//! - Cancellation promotion threshold adjustment
//!
//! The autotuner operates in configuration-driven mode with deterministic
//! behavior under LabRuntime testing.

use std::time::{Duration, Instant};

use crate::runtime::scheduler::three_lane::{AdaptiveBatchSizingProfile, PreemptionMetrics};

/// Configuration-driven scheduler autotuning parameters.
#[derive(Debug, Clone)]
pub struct AutotunerConfig {
    /// Enable adaptive batch size tuning.
    pub enable_batch_tuning: bool,
    /// Enable steal batch size adjustment.
    pub enable_steal_tuning: bool,
    /// Enable browser handoff limit tuning.
    pub enable_handoff_tuning: bool,
    /// Minimum observation window before making adjustments.
    pub observation_window_ms: u64,
    /// Maximum allowed batch size adjustment per iteration.
    pub max_batch_delta: usize,
    /// Target p95 latency threshold in microseconds.
    pub target_p95_latency_us: u64,
}

impl Default for AutotunerConfig {
    fn default() -> Self {
        Self {
            enable_batch_tuning: true,
            enable_steal_tuning: true,
            enable_handoff_tuning: false, // More conservative default
            observation_window_ms: 1000,  // 1 second observation window
            max_batch_delta: 4,           // Conservative adjustment steps
            target_p95_latency_us: 1000,  // 1ms target latency
        }
    }
}

/// Observed performance metrics from scheduler hot paths.
#[derive(Debug, Clone, Default)]
pub struct HotPathObservation {
    /// Timestamp when observation was recorded.
    pub timestamp: Option<Instant>,
    /// Cancel lane dispatch ratio (basis points).
    pub cancel_dispatch_ratio_bps: u16,
    /// Timed lane dispatch ratio (basis points).
    pub timed_dispatch_ratio_bps: u16,
    /// Ready lane dispatch ratio (basis points).
    pub ready_dispatch_ratio_bps: u16,
    /// Average batch size for global ready drains.
    pub mean_ready_batch_size: f64,
    /// Current steal batch size configuration.
    pub current_steal_batch_size: usize,
    /// Current browser handoff limit.
    pub current_handoff_limit: usize,
    /// Adaptive batch scale-up events count.
    pub adaptive_scale_up_events: u64,
    /// Cancel debt floor hits count.
    pub cancel_debt_floor_hits: u64,
    /// Estimated p95 task dispatch latency in microseconds.
    pub estimated_p95_latency_us: u64,
}

/// Autotuner recommendation for scheduler parameter adjustments.
#[derive(Debug, Clone)]
pub struct AutotunerRecommendation {
    /// Recommended steal batch size adjustment.
    pub steal_batch_size: Option<usize>,
    /// Recommended browser handoff limit adjustment.
    pub handoff_limit: Option<usize>,
    /// Recommended adaptive ready profile adjustments.
    pub adaptive_profile: Option<AdaptiveBatchSizingProfile>,
    /// Confidence level in recommendation (0-100).
    pub confidence_percentage: u8,
    /// Human-readable reasoning for the recommendation.
    pub reasoning: String,
}

/// Observe-first autotuner for scheduler hot-path optimization.
pub struct SchedulerAutotuner {
    config: AutotunerConfig,
    last_observation: Option<HotPathObservation>,
    observation_history: Vec<HotPathObservation>,
    last_adjustment_time: Option<Instant>,
}

impl SchedulerAutotuner {
    /// Create a new scheduler autotuner with the given configuration.
    #[must_use]
    pub fn new(config: AutotunerConfig) -> Self {
        Self {
            config,
            last_observation: None,
            observation_history: Vec::new(),
            last_adjustment_time: None,
        }
    }

    /// Record a hot-path observation for analysis.
    pub fn observe(&mut self, observation: HotPathObservation) {
        self.observation_history.push(observation.clone());
        // Keep only recent observations to bound memory
        if self.observation_history.len() > 100 {
            self.observation_history.drain(0..50);
        }
        self.last_observation = Some(observation);
    }

    /// Generate autotuning recommendations based on observed metrics.
    #[must_use]
    pub fn recommend(&self) -> Option<AutotunerRecommendation> {
        let last_obs = self.last_observation.as_ref()?;

        // Require minimum observation window
        if let Some(last_adj) = self.last_adjustment_time {
            let elapsed = last_obs.timestamp?.duration_since(last_adj);
            if elapsed < Duration::from_millis(self.config.observation_window_ms) {
                return None;
            }
        }

        let mut recommendation = AutotunerRecommendation {
            steal_batch_size: None,
            handoff_limit: None,
            adaptive_profile: None,
            confidence_percentage: 0,
            reasoning: String::new(),
        };

        let mut reasons = Vec::new();
        let mut confidence_factors = Vec::new();

        // Analyze steal batch sizing
        if self.config.enable_steal_tuning {
            if let Some((new_size, reason, conf)) = self.analyze_steal_batch_size(last_obs) {
                recommendation.steal_batch_size = Some(new_size);
                reasons.push(format!("Steal batch: {}", reason));
                confidence_factors.push(conf);
            }
        }

        // Analyze browser handoff tuning
        if self.config.enable_handoff_tuning {
            if let Some((new_limit, reason, conf)) = self.analyze_handoff_limit(last_obs) {
                recommendation.handoff_limit = Some(new_limit);
                reasons.push(format!("Handoff: {}", reason));
                confidence_factors.push(conf);
            }
        }

        // Analyze adaptive batch profile tuning
        if self.config.enable_batch_tuning {
            if let Some((profile, reason, conf)) = self.analyze_adaptive_profile(last_obs) {
                recommendation.adaptive_profile = Some(profile);
                reasons.push(format!("Adaptive: {}", reason));
                confidence_factors.push(conf);
            }
        }

        if reasons.is_empty() {
            return None;
        }

        recommendation.confidence_percentage = if confidence_factors.is_empty() {
            50 // Default moderate confidence
        } else {
            average_confidence(&confidence_factors)
        };

        recommendation.reasoning = reasons.join("; ");

        Some(recommendation)
    }

    /// Mark that autotuner recommendations were applied.
    pub fn mark_adjustment_applied(&mut self) {
        self.last_adjustment_time = Some(Instant::now());
    }

    /// Analyze steal batch size performance and recommend adjustments.
    fn analyze_steal_batch_size(&self, obs: &HotPathObservation) -> Option<(usize, String, u8)> {
        let current = obs.current_steal_batch_size;

        // High latency suggests oversized batches
        if obs.estimated_p95_latency_us > self.config.target_p95_latency_us.saturating_mul(2) {
            let new_size = (current / 2).max(1);
            return Some((
                new_size,
                format!(
                    "Reduce for latency: {}us > {}us",
                    obs.estimated_p95_latency_us, self.config.target_p95_latency_us
                ),
                80,
            ));
        }

        // High cancel dispatch ratio suggests smaller batches for responsiveness
        if obs.cancel_dispatch_ratio_bps > 3000 {
            let new_size = current.saturating_sub(self.config.max_batch_delta).max(1);
            return Some((
                new_size,
                format!(
                    "Reduce for cancel responsiveness: {}bps",
                    obs.cancel_dispatch_ratio_bps
                ),
                70,
            ));
        }

        // Low ready utilization with good latency suggests we can increase batch size
        // Keep a conservative upper bound while the tuner is observe-first.
        if obs.ready_dispatch_ratio_bps < 4000 // <40% ready work
            && obs.estimated_p95_latency_us < self.config.target_p95_latency_us / 2
            && current < 32
        {
            let new_size = current.saturating_add(self.config.max_batch_delta);
            return Some((
                new_size,
                format!(
                    "Increase for throughput: low ready util {}bps, good latency",
                    obs.ready_dispatch_ratio_bps
                ),
                60,
            ));
        }

        None
    }

    /// Analyze browser handoff limit and recommend adjustments.
    fn analyze_handoff_limit(&self, obs: &HotPathObservation) -> Option<(usize, String, u8)> {
        let current = obs.current_handoff_limit;

        // High ready dispatch suggests reducing handoff frequency for better batching
        if obs.ready_dispatch_ratio_bps > 7000 {
            let new_limit = current.saturating_mul(2).min(64);
            return Some((
                new_limit,
                format!(
                    "Increase limit for ready batching: {}bps",
                    obs.ready_dispatch_ratio_bps
                ),
                65,
            ));
        }

        // High cancel ratio suggests more frequent handoffs for responsiveness
        if obs.cancel_dispatch_ratio_bps > 2000 && current > 2 {
            let new_limit = (current / 2).max(1);
            return Some((
                new_limit,
                format!(
                    "Decrease limit for cancel responsiveness: {}bps",
                    obs.cancel_dispatch_ratio_bps
                ),
                75,
            ));
        }

        None
    }

    /// Analyze adaptive batch profile and recommend adjustments.
    fn analyze_adaptive_profile(
        &self,
        obs: &HotPathObservation,
    ) -> Option<(AdaptiveBatchSizingProfile, String, u8)> {
        // This would contain logic to tune AdaptiveBatchSizingProfile parameters
        // based on scale-up events, cancel debt hits, and observed batch sizes

        // High cancel debt floor hits suggests lowering the threshold
        if obs.cancel_debt_floor_hits > 10 {
            let profile = AdaptiveBatchSizingProfile {
                enabled: true,
                min_batch_size: 1,
                max_batch_size: 16,
                scale_up_ready_depth: 8,
                scale_up_in_flight: 4,
                scale_up_claim_failures: 2,
                cancel_debt_floor: 2, // Lower threshold
                cooldown_steps: 5,
            };
            return Some((
                profile,
                format!(
                    "Lower cancel debt floor: {} hits",
                    obs.cancel_debt_floor_hits
                ),
                70,
            ));
        }

        // Few scale-up events with high ready load suggests more aggressive scaling
        if obs.adaptive_scale_up_events < 2 && obs.ready_dispatch_ratio_bps > 6000 {
            let profile = AdaptiveBatchSizingProfile {
                enabled: true,
                min_batch_size: 2,
                max_batch_size: 32,
                scale_up_ready_depth: 4, // Lower threshold for scaling
                scale_up_in_flight: 2,
                scale_up_claim_failures: 1,
                cancel_debt_floor: 5,
                cooldown_steps: 3,
            };
            return Some((
                profile,
                format!(
                    "Increase scaling aggressiveness: {} scale events, {}bps ready",
                    obs.adaptive_scale_up_events, obs.ready_dispatch_ratio_bps
                ),
                65,
            ));
        }

        None
    }
}

fn average_confidence(confidence_factors: &[u8]) -> u8 {
    let sum: u16 = confidence_factors
        .iter()
        .map(|confidence| u16::from(*confidence))
        .sum();
    let count = u16::try_from(confidence_factors.len()).unwrap_or(1).max(1);
    u8::try_from((sum / count).min(100)).unwrap_or(100)
}

/// Extract hot-path observation from scheduler metrics.
#[must_use]
pub fn extract_observation(metrics: &PreemptionMetrics) -> HotPathObservation {
    let total_dispatches = metrics
        .cancel_dispatches
        .saturating_add(metrics.timed_dispatches)
        .saturating_add(metrics.ready_dispatches);

    let cancel_ratio = if total_dispatches > 0 {
        ratio_bps(metrics.cancel_dispatches, total_dispatches)
    } else {
        0
    };

    let timed_ratio = if total_dispatches > 0 {
        ratio_bps(metrics.timed_dispatches, total_dispatches)
    } else {
        0
    };

    let ready_ratio = if total_dispatches > 0 {
        ratio_bps(metrics.ready_dispatches, total_dispatches)
    } else {
        0
    };

    let mean_batch_size = if metrics.global_ready_batch_drains > 0 {
        metrics.global_ready_batch_tasks as f64 / metrics.global_ready_batch_drains as f64
    } else {
        0.0
    };

    let estimated_latency = metrics.avg_timeout_park_nanos() / 1000;

    HotPathObservation {
        timestamp: Some(Instant::now()),
        cancel_dispatch_ratio_bps: cancel_ratio,
        timed_dispatch_ratio_bps: timed_ratio,
        ready_dispatch_ratio_bps: ready_ratio,
        mean_ready_batch_size: mean_batch_size,
        current_steal_batch_size: 8, // Would be extracted from scheduler state
        current_handoff_limit: 0,    // Would be extracted from scheduler state
        adaptive_scale_up_events: metrics.adaptive_batch_scale_up_events,
        cancel_debt_floor_hits: metrics.adaptive_batch_cancel_floor_hits,
        estimated_p95_latency_us: estimated_latency,
    }
}

fn ratio_bps(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        return 0;
    }
    let raw = numerator
        .saturating_mul(10_000)
        .saturating_div(denominator)
        .min(10_000);
    raw as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autotuner_reduces_batch_size_for_high_latency() {
        let mut autotuner = SchedulerAutotuner::new(AutotunerConfig::default());

        let obs = HotPathObservation {
            timestamp: Some(Instant::now()),
            estimated_p95_latency_us: 5000, // 5ms - much higher than 1ms target
            current_steal_batch_size: 16,
            ..Default::default()
        };

        autotuner.observe(obs);
        let recommendation = autotuner.recommend().unwrap();

        assert!(recommendation.steal_batch_size.unwrap() < 16);
        assert!(recommendation.reasoning.contains("latency"));
    }

    #[test]
    fn autotuner_reduces_batch_size_for_high_cancel_load() {
        let mut autotuner = SchedulerAutotuner::new(AutotunerConfig::default());

        let obs = HotPathObservation {
            timestamp: Some(Instant::now()),
            cancel_dispatch_ratio_bps: 4000, // 40% cancel work
            current_steal_batch_size: 12,
            ..Default::default()
        };

        autotuner.observe(obs);
        let recommendation = autotuner.recommend().unwrap();

        assert!(recommendation.steal_batch_size.unwrap() < 12);
        assert!(recommendation.reasoning.contains("cancel responsiveness"));
    }

    #[test]
    fn autotuner_increases_batch_size_for_low_utilization() {
        let mut autotuner = SchedulerAutotuner::new(AutotunerConfig::default());

        let obs = HotPathObservation {
            timestamp: Some(Instant::now()),
            ready_dispatch_ratio_bps: 2000, // 20% ready work - low utilization
            estimated_p95_latency_us: 200,  // Good latency
            current_steal_batch_size: 4,
            ..Default::default()
        };

        autotuner.observe(obs);
        let recommendation = autotuner.recommend().unwrap();

        assert!(recommendation.steal_batch_size.unwrap() > 4);
        assert!(recommendation.reasoning.contains("throughput"));
    }

    #[test]
    fn autotuner_respects_observation_window() {
        let config = AutotunerConfig {
            observation_window_ms: 5000, // 5 second window
            ..Default::default()
        };
        let mut autotuner = SchedulerAutotuner::new(config);

        autotuner.last_adjustment_time = Some(Instant::now());

        let obs = HotPathObservation {
            timestamp: Some(Instant::now()),
            estimated_p95_latency_us: 5000, // Should trigger recommendation
            current_steal_batch_size: 16,
            ..Default::default()
        };

        autotuner.observe(obs);

        // Should not recommend due to recent adjustment
        assert!(autotuner.recommend().is_none());
    }

    #[test]
    fn extract_observation_from_metrics() {
        let mut metrics = PreemptionMetrics::default();
        metrics.cancel_dispatches = 20;
        metrics.ready_dispatches = 80;
        metrics.global_ready_batch_drains = 10;
        metrics.global_ready_batch_tasks = 50;

        let obs = extract_observation(&metrics);

        assert_eq!(obs.cancel_dispatch_ratio_bps, 2000); // 20%
        assert_eq!(obs.ready_dispatch_ratio_bps, 8000); // 80%
        assert_eq!(obs.mean_ready_batch_size, 5.0); // 50/10
    }
}
