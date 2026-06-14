//! Conformal exploration-budget estimates for schedule search.
//!
//! This module converts DPOR or seed-sweep novelty observations into a
//! deterministic stopping signal. The conformal bound is intentionally scoped:
//! it is a finite-sample upper prediction threshold for the next binary
//! novelty observation under exchangeability, not a proof that every reachable
//! schedule class has been enumerated.

use crate::lab::explorer::RunResult;
use serde::Serialize;

/// Configuration for conformal exploration-budget estimates.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ExplorationBudgetConfig {
    /// Target miscoverage rate for the conformal novelty bound.
    pub alpha: f64,
    /// Desired coverage confidence, expressed as `1 - residual novelty`.
    pub target_coverage: f64,
    /// Minimum observations before a stop recommendation may be issued.
    pub min_samples: usize,
    /// Maximum additional existing-class runs considered for the recommendation.
    pub max_additional_runs: usize,
}

impl Default for ExplorationBudgetConfig {
    fn default() -> Self {
        Self {
            alpha: 0.05,
            target_coverage: 0.95,
            min_samples: 20,
            max_additional_runs: 1_000,
        }
    }
}

impl ExplorationBudgetConfig {
    /// Create a budget config with a target miscoverage and coverage level.
    #[must_use]
    pub fn new(alpha: f64, target_coverage: f64) -> Self {
        assert_valid_probability("alpha", alpha);
        assert_valid_probability("target_coverage", target_coverage);
        Self {
            alpha,
            target_coverage,
            ..Self::default()
        }
    }

    /// Set the minimum sample count required before stop recommendations.
    #[must_use]
    pub fn min_samples(mut self, samples: usize) -> Self {
        assert!(samples > 0, "min_samples must be greater than zero");
        self.min_samples = samples;
        self
    }

    /// Set the maximum additional run count considered by recommendations.
    #[must_use]
    pub fn max_additional_runs(mut self, runs: usize) -> Self {
        self.max_additional_runs = runs;
        self
    }
}

/// Explicit assumptions behind an exploration-budget estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ExplorationBudgetAssumptions {
    /// Observed runs are treated as exchangeable for conformal calibration.
    pub exchangeable_runs: bool,
    /// The novelty score is binary: `1.0` for a new class and `0.0` otherwise.
    pub binary_novelty_score: bool,
    /// Additional-run recommendations assume future added runs hit known classes.
    pub additional_runs_assume_existing_classes: bool,
}

impl Default for ExplorationBudgetAssumptions {
    fn default() -> Self {
        Self {
            exchangeable_runs: true,
            binary_novelty_score: true,
            additional_runs_assume_existing_classes: true,
        }
    }
}

/// Deterministic exploration-budget estimate.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExplorationBudgetEstimate {
    /// Total novelty observations consumed.
    pub total_runs: usize,
    /// Number of observations that discovered a new equivalence class.
    pub discoveries: usize,
    /// Empirical residual discovery rate, `discoveries / total_runs`, or `1.0`
    /// before the first calibration sample.
    pub residual_discovery_rate: f64,
    /// Finite-sample conformal upper threshold for the next novelty score.
    pub conformal_upper_bound: f64,
    /// Target residual discovery rate, `1 - target_coverage`.
    pub target_residual_rate: f64,
    /// Requested coverage confidence.
    pub target_coverage: f64,
    /// Number of samples used by the conformal bound.
    pub calibration_samples: usize,
    /// Additional runs recommended before the target should be re-evaluated.
    pub recommended_additional_runs: usize,
    /// True when the conformal bound is at or below the target residual rate.
    pub target_met: bool,
    /// True when the recommendation hit `max_additional_runs` before the target.
    pub exhausted_recommendation: bool,
    /// Assumptions that scope this estimate.
    pub assumptions: ExplorationBudgetAssumptions,
}

/// Pure estimator for exploration-budget reports.
#[derive(Debug, Clone, Copy)]
pub struct ExplorationBudget;

impl ExplorationBudget {
    /// Estimate residual novelty from an ordered novelty-observation series.
    ///
    /// Each `true` value represents a run that discovered a new equivalence
    /// class; each `false` value represents an existing-class hit.
    #[must_use]
    pub fn estimate_from_novelty<I>(
        novelty: I,
        config: ExplorationBudgetConfig,
    ) -> ExplorationBudgetEstimate
    where
        I: IntoIterator<Item = bool>,
    {
        Self::estimate_from_flags(novelty.into_iter().collect(), config)
    }

    /// Estimate residual novelty directly from explorer run results.
    #[must_use]
    pub fn estimate_from_runs(
        runs: &[RunResult],
        config: ExplorationBudgetConfig,
    ) -> ExplorationBudgetEstimate {
        Self::estimate_from_novelty(runs.iter().map(|run| run.is_new_class), config)
    }

    /// Estimate residual novelty from aggregate counts.
    ///
    /// This is useful for serialized coverage reports that preserve discovery
    /// counts but not individual run order. The conformal binary quantile is
    /// order-insensitive, so the aggregate path produces the same bound as a
    /// per-run series with the same counts.
    #[must_use]
    pub fn estimate_from_counts(
        total_runs: usize,
        discoveries: usize,
        config: ExplorationBudgetConfig,
    ) -> ExplorationBudgetEstimate {
        assert!(
            discoveries <= total_runs,
            "discoveries must not exceed total_runs"
        );
        let existing_hits = total_runs - discoveries;
        let mut novelty = Vec::with_capacity(total_runs);
        novelty.extend(std::iter::repeat_n(true, discoveries));
        novelty.extend(std::iter::repeat_n(false, existing_hits));
        Self::estimate_from_flags(novelty, config)
    }

    fn estimate_from_flags(
        novelty: Vec<bool>,
        config: ExplorationBudgetConfig,
    ) -> ExplorationBudgetEstimate {
        assert_valid_config(config);

        let total_runs = novelty.len();
        let discoveries = novelty.iter().filter(|&&is_new| is_new).count();
        let residual_discovery_rate = ratio(discoveries, total_runs);
        let target_residual_rate = 1.0 - config.target_coverage;
        let conformal_upper_bound =
            conformal_binary_upper_bound(&novelty, config.alpha, config.min_samples);
        let target_met = conformal_upper_bound <= target_residual_rate;
        let recommended_additional_runs = if target_met {
            0
        } else {
            recommended_existing_class_runs(&novelty, config)
        };
        let exhausted_recommendation = !target_met
            && recommended_additional_runs == config.max_additional_runs
            && !target_reached_after_existing_hits(&novelty, config, recommended_additional_runs);

        ExplorationBudgetEstimate {
            total_runs,
            discoveries,
            residual_discovery_rate,
            conformal_upper_bound,
            target_residual_rate,
            target_coverage: config.target_coverage,
            calibration_samples: total_runs,
            recommended_additional_runs,
            target_met,
            exhausted_recommendation,
            assumptions: ExplorationBudgetAssumptions::default(),
        }
    }
}

fn assert_valid_config(config: ExplorationBudgetConfig) {
    assert_valid_probability("alpha", config.alpha);
    assert_valid_probability("target_coverage", config.target_coverage);
    assert!(
        config.min_samples > 0,
        "min_samples must be greater than zero"
    );
}

fn assert_valid_probability(name: &str, value: f64) {
    assert!(
        value.is_finite() && value > 0.0 && value < 1.0,
        "{name} must be finite and in (0, 1)"
    );
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        return 1.0;
    }
    numerator as f64 / denominator as f64
}

fn conformal_binary_upper_bound(novelty: &[bool], alpha: f64, min_samples: usize) -> f64 {
    if novelty.len() < min_samples {
        return 1.0;
    }
    let scores: Vec<f64> = novelty
        .iter()
        .map(|&is_new| if is_new { 1.0 } else { 0.0 })
        .collect();
    conformal_quantile(&scores, alpha)
}

fn conformal_quantile(scores: &[f64], alpha: f64) -> f64 {
    if scores.is_empty() {
        return f64::INFINITY;
    }

    let mut sorted = scores.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let level = (1.0 - alpha) * (scores.len() as f64 + 1.0);
    let idx = (level.ceil() as usize).min(scores.len()).saturating_sub(1);
    sorted[idx]
}

fn recommended_existing_class_runs(novelty: &[bool], config: ExplorationBudgetConfig) -> usize {
    for additional in 0..=config.max_additional_runs {
        if target_reached_after_existing_hits(novelty, config, additional) {
            return additional;
        }
    }
    config.max_additional_runs
}

fn target_reached_after_existing_hits(
    novelty: &[bool],
    config: ExplorationBudgetConfig,
    additional: usize,
) -> bool {
    let mut projected = Vec::with_capacity(novelty.len() + additional);
    projected.extend_from_slice(novelty);
    projected.extend(std::iter::repeat_n(false, additional));
    conformal_binary_upper_bound(&projected, config.alpha, config.min_samples)
        <= 1.0 - config.target_coverage
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::float_cmp)]

    use super::*;
    use crate::lab::runtime::InvariantViolation;

    #[test]
    fn empty_series_reports_uncalibrated_upper_bound() {
        let estimate = ExplorationBudget::estimate_from_novelty(
            [],
            ExplorationBudgetConfig::new(0.05, 0.95)
                .min_samples(5)
                .max_additional_runs(3),
        );

        assert_eq!(estimate.total_runs, 0);
        assert_eq!(estimate.discoveries, 0);
        assert_eq!(estimate.residual_discovery_rate, 1.0);
        assert_eq!(estimate.conformal_upper_bound, 1.0);
        assert_eq!(estimate.recommended_additional_runs, 3);
        assert!(estimate.exhausted_recommendation);
        assert!(!estimate.target_met);
    }

    #[test]
    fn existing_class_hits_can_satisfy_target_after_min_samples() {
        let estimate = ExplorationBudget::estimate_from_novelty(
            [false, false, false, false, false],
            ExplorationBudgetConfig::new(0.20, 0.80).min_samples(5),
        );

        assert_eq!(estimate.total_runs, 5);
        assert_eq!(estimate.conformal_upper_bound, 0.0);
        assert_eq!(estimate.recommended_additional_runs, 0);
        assert!(estimate.target_met);
        assert!(!estimate.exhausted_recommendation);
    }

    #[test]
    fn discoveries_keep_conformal_bound_conservative() {
        let no_discoveries = ExplorationBudget::estimate_from_novelty(
            [false; 20],
            ExplorationBudgetConfig::new(0.20, 0.80).min_samples(5),
        );
        let with_discoveries = ExplorationBudget::estimate_from_novelty(
            [
                true, true, true, true, true, false, false, false, false, false, false, false,
                false, false, false, false, false, false, false, false,
            ],
            ExplorationBudgetConfig::new(0.20, 0.80).min_samples(5),
        );

        assert!(with_discoveries.conformal_upper_bound >= no_discoveries.conformal_upper_bound);
        assert!(with_discoveries.recommended_additional_runs > 0);
    }

    #[test]
    fn counts_match_same_size_novelty_series() {
        let config = ExplorationBudgetConfig::new(0.20, 0.80).min_samples(5);
        let from_counts = ExplorationBudget::estimate_from_counts(10, 2, config);
        let from_series = ExplorationBudget::estimate_from_novelty(
            [
                true, false, false, true, false, false, false, false, false, false,
            ],
            config,
        );

        assert_eq!(
            from_counts.conformal_upper_bound,
            from_series.conformal_upper_bound
        );
        assert_eq!(
            from_counts.residual_discovery_rate,
            from_series.residual_discovery_rate
        );
    }

    #[test]
    fn run_results_feed_budget_estimator() {
        let runs = [
            RunResult {
                seed: 1,
                steps: 10,
                fingerprint: 101,
                is_new_class: true,
                violations: Vec::<InvariantViolation>::new(),
                certificate_hash: 1_001,
            },
            RunResult {
                seed: 2,
                steps: 8,
                fingerprint: 101,
                is_new_class: false,
                violations: Vec::<InvariantViolation>::new(),
                certificate_hash: 1_001,
            },
        ];

        let estimate = ExplorationBudget::estimate_from_runs(
            &runs,
            ExplorationBudgetConfig::new(0.20, 0.80).min_samples(2),
        );

        assert_eq!(estimate.total_runs, 2);
        assert_eq!(estimate.discoveries, 1);
        assert_eq!(estimate.residual_discovery_rate, 0.5);
    }
}
