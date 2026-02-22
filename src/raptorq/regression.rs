//! G8: Anytime-valid regression detection with conformal/e-value guardrails.
//!
//! Provides statistically principled regression detection for RaptorQ decode
//! performance metrics using conformal calibration envelopes and e-process
//! sequential testing. Replaces fixed-threshold regression gates with
//! adaptive, distribution-free guardrails that maintain valid coverage
//! guarantees while reducing false-positive rates.
//!
//! # Architecture
//!
//! ```text
//! DecodeStats ──► RegressionMonitor
//!                    ├─ HealthThresholdCalibrator (conformal envelope)
//!                    ├─ EProcess per metric (anytime-valid evidence)
//!                    └─ RegressionVerdict (accept / regressed / calibrating)
//! ```
//!
//! # Determinism
//!
//! All operations are deterministic for fixed input sequences. No randomness
//! or floating-point non-determinism is introduced. The conformal calibrator
//! uses exact order-statistic computation and the e-process uses a fixed-lambda
//! product martingale.

use crate::lab::conformal::{HealthThresholdCalibrator, HealthThresholdConfig, ThresholdMode};
use crate::lab::oracle::eprocess::{EProcess, EProcessConfig};
use crate::raptorq::decoder::DecodeStats;
use serde::Serialize;
use std::collections::BTreeMap;

/// Schema version for G8 regression artifacts.
pub const G8_SCHEMA_VERSION: &str = "raptorq-g8-anytime-regression-v1";

/// Replay pointer for G8 regression detection events.
pub const G8_REPLAY_REF: &str = "replay:rq-track-g-regression-v1";

/// Minimum calibration samples before regression detection activates.
const MIN_CALIBRATION_SAMPLES: usize = 10;

/// Significance level for conformal coverage guarantee (95% coverage).
const CONFORMAL_ALPHA: f64 = 0.05;

/// Null hypothesis violation probability for e-process (0.1% baseline rate).
const EPROCESS_P0: f64 = 0.10;

/// Bet size for e-process martingale (conservative).
const EPROCESS_LAMBDA: f64 = 0.5;

/// Significance level for e-process rejection.
const EPROCESS_ALPHA: f64 = 0.05;

/// Metric names extracted from `DecodeStats` for regression tracking.
const TRACKED_METRICS: &[&str] = &[
    "gauss_ops",
    "dense_core_rows",
    "dense_core_cols",
    "inactivated",
    "pivots_selected",
    "peel_frontier_peak",
];

/// Verdict from a single regression check.
///
/// Ordered by severity: Accept < Calibrating < Warning < Regressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RegressionVerdict {
    /// Observation is within conformal envelope — no regression.
    Accept,
    /// Not enough calibration data yet.
    Calibrating,
    /// Observation exceeds conformal threshold but e-value hasn't rejected.
    Warning,
    /// E-process has rejected H₀ — statistically significant regression.
    Regressed,
}

impl RegressionVerdict {
    /// Label for structured logging.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Calibrating => "calibrating",
            Self::Accept => "accept",
            Self::Warning => "warning",
            Self::Regressed => "regressed",
        }
    }
}

/// Per-metric regression check result.
#[derive(Debug, Clone, Serialize)]
pub struct MetricRegressionResult {
    /// Metric name.
    pub metric: String,
    /// Observed value.
    pub value: f64,
    /// Conformal threshold (if calibrated).
    pub threshold: Option<f64>,
    /// Current e-value (evidence against H₀).
    pub e_value: f64,
    /// Number of calibration samples.
    pub calibration_n: usize,
    /// Whether the observation exceeds the conformal threshold.
    pub exceeds_threshold: bool,
    /// Verdict.
    pub verdict: RegressionVerdict,
}

/// Aggregate regression report for a single observation.
#[derive(Debug, Clone, Serialize)]
pub struct RegressionReport {
    /// Schema version.
    pub schema_version: &'static str,
    /// Replay pointer.
    pub replay_ref: &'static str,
    /// Per-metric results.
    pub metrics: Vec<MetricRegressionResult>,
    /// Overall verdict (worst-case across all metrics).
    pub overall_verdict: RegressionVerdict,
    /// Total observations processed.
    pub total_observations: usize,
    /// Number of metrics currently in regression.
    pub regressed_count: usize,
    /// Number of metrics in warning state.
    pub warning_count: usize,
    /// Regime state covariate (from F6 detector, if available).
    pub regime_state: Option<String>,
}

/// Anytime-valid regression monitor for RaptorQ decode metrics.
///
/// Combines conformal calibration envelopes with e-process sequential testing
/// to provide:
/// - Distribution-free adaptive thresholds (via conformal prediction)
/// - Anytime-valid evidence accumulation (via e-process martingale)
/// - Reduced false-positive rate vs. static thresholds
/// - Deterministic, replayable regression decisions
///
/// # Usage
///
/// 1. Create a monitor with `RegressionMonitor::new()`
/// 2. Feed baseline `DecodeStats` observations via `calibrate()`
/// 3. Check new observations via `check()` which returns a `RegressionReport`
/// 4. The monitor automatically transitions from calibrating → active
///
/// # Safety
///
/// - The conformal guarantee (P(conforming) ≥ 1 - α) holds for exchangeable
///   observations without distributional assumptions.
/// - The e-process guarantee (P(false rejection) ≤ α) holds anytime, not
///   just at a fixed sample size.
pub struct RegressionMonitor {
    /// Conformal calibrator for adaptive thresholds.
    calibrator: HealthThresholdCalibrator,
    /// Per-metric e-process for sequential testing.
    e_processes: BTreeMap<String, EProcess>,
    /// Total observations processed.
    total_observations: usize,
    /// Whether the calibration phase is complete.
    calibration_complete: bool,
}

impl RegressionMonitor {
    /// Create a new regression monitor with default configuration.
    #[must_use]
    pub fn new() -> Self {
        let config = HealthThresholdConfig::new(CONFORMAL_ALPHA, ThresholdMode::Upper)
            .min_samples(MIN_CALIBRATION_SAMPLES);
        let calibrator = HealthThresholdCalibrator::new(config);

        let eprocess_config = EProcessConfig {
            p0: EPROCESS_P0,
            lambda: EPROCESS_LAMBDA,
            alpha: EPROCESS_ALPHA,
            ..Default::default()
        };

        let mut e_processes = BTreeMap::new();
        for &metric in TRACKED_METRICS {
            e_processes.insert(
                metric.to_string(),
                EProcess::new_without_history(metric, eprocess_config.clone()),
            );
        }

        Self {
            calibrator,
            e_processes,
            total_observations: 0,
            calibration_complete: false,
        }
    }

    /// Feed a baseline observation for calibration.
    ///
    /// Call this with `DecodeStats` from known-good baseline runs.
    pub fn calibrate(&mut self, stats: &DecodeStats) {
        let values = Self::extract_metrics(stats);
        for (metric, value) in &values {
            self.calibrator.calibrate(metric, *value);
        }
        self.total_observations += 1;

        // Check if all metrics are calibrated.
        if !self.calibration_complete {
            self.calibration_complete = TRACKED_METRICS
                .iter()
                .all(|m| self.calibrator.is_metric_calibrated(m));
        }
    }

    /// Check a new observation against calibrated thresholds and e-process.
    ///
    /// Returns a regression report with per-metric verdicts and an overall
    /// verdict (worst-case across all metrics).
    #[must_use]
    pub fn check(&mut self, stats: &DecodeStats) -> RegressionReport {
        let values = Self::extract_metrics(stats);
        let mut results = Vec::with_capacity(TRACKED_METRICS.len());
        let mut overall_verdict = RegressionVerdict::Accept;
        let mut regressed_count = 0usize;
        let mut warning_count = 0usize;

        self.total_observations += 1;

        for (metric, value) in &values {
            let check_result = self.calibrator.check_and_track(metric, *value);

            let (threshold, exceeds_threshold, calibration_n) =
                check_result.as_ref().map_or((None, false, 0), |cr| {
                    (Some(cr.threshold), !cr.conforming, cr.calibration_n)
                });

            // Feed violation signal to e-process.
            if let Some(ep) = self.e_processes.get_mut(metric.as_str()) {
                ep.observe(exceeds_threshold);
            }

            let e_value = self
                .e_processes
                .get(metric.as_str())
                .map_or(1.0, EProcess::e_value);

            let e_rejected = self
                .e_processes
                .get(metric.as_str())
                .is_some_and(|ep| ep.rejected);

            let verdict = if threshold.is_none() {
                RegressionVerdict::Calibrating
            } else if e_rejected {
                RegressionVerdict::Regressed
            } else if exceeds_threshold {
                RegressionVerdict::Warning
            } else {
                RegressionVerdict::Accept
            };

            match verdict {
                RegressionVerdict::Regressed => regressed_count += 1,
                RegressionVerdict::Warning => warning_count += 1,
                _ => {}
            }

            // Promote overall verdict.
            if (verdict as u8) > (overall_verdict as u8) {
                overall_verdict = verdict;
            }

            results.push(MetricRegressionResult {
                metric: metric.clone(),
                value: *value,
                threshold,
                e_value,
                calibration_n,
                exceeds_threshold,
                verdict,
            });
        }

        let regime_state = stats
            .policy_mode
            .map(ToString::to_string)
            .or_else(|| stats.hard_regime_branch.map(ToString::to_string))
            .or_else(|| {
                stats
                    .hard_regime_activated
                    .then(|| "hard-regime".to_string())
            });

        RegressionReport {
            schema_version: G8_SCHEMA_VERSION,
            replay_ref: G8_REPLAY_REF,
            metrics: results,
            overall_verdict,
            total_observations: self.total_observations,
            regressed_count,
            warning_count,
            regime_state,
        }
    }

    /// Whether the calibration phase is complete.
    #[must_use]
    pub fn is_calibrated(&self) -> bool {
        self.calibration_complete
    }

    /// Total observations processed (calibration + checks).
    #[must_use]
    pub fn total_observations(&self) -> usize {
        self.total_observations
    }

    /// Get the current e-value for a specific metric.
    #[must_use]
    pub fn e_value(&self, metric: &str) -> Option<f64> {
        self.e_processes.get(metric).map(EProcess::e_value)
    }

    /// Get the current conformal threshold for a specific metric.
    #[must_use]
    pub fn threshold(&self, metric: &str) -> Option<f64> {
        self.calibrator.threshold(metric)
    }

    /// Check if any metric has a statistically significant regression.
    #[must_use]
    pub fn any_regressed(&self) -> bool {
        self.e_processes.values().any(|ep| ep.rejected)
    }

    /// Get names of all regressed metrics.
    #[must_use]
    pub fn regressed_metrics(&self) -> Vec<String> {
        self.e_processes
            .iter()
            .filter(|(_, ep)| ep.rejected)
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Reset all e-processes (clear accumulated evidence) while keeping
    /// calibration state. Useful after addressing a regression.
    pub fn reset_evidence(&mut self) {
        for ep in self.e_processes.values_mut() {
            ep.reset();
        }
    }

    /// Extract tracked metric values from `DecodeStats`.
    #[allow(clippy::cast_precision_loss)]
    fn extract_metrics(stats: &DecodeStats) -> Vec<(String, f64)> {
        vec![
            ("gauss_ops".to_string(), stats.gauss_ops as f64),
            ("dense_core_rows".to_string(), stats.dense_core_rows as f64),
            ("dense_core_cols".to_string(), stats.dense_core_cols as f64),
            ("inactivated".to_string(), stats.inactivated as f64),
            ("pivots_selected".to_string(), stats.pivots_selected as f64),
            (
                "peel_frontier_peak".to_string(),
                stats.peel_frontier_peak as f64,
            ),
        ]
    }
}

impl Default for RegressionMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Emit a structured NDJSON log line for a regression check.
///
/// Outputs to stderr for CI capture, matching the benchmark logging convention.
pub fn emit_regression_log(report: &RegressionReport) {
    for result in &report.metrics {
        eprintln!(
            "{{\"schema_version\":\"{}\",\"replay_ref\":\"{}\",\
             \"metric\":\"{}\",\"value\":{:.3},\"threshold\":{},\
             \"e_value\":{:.6},\"exceeds_threshold\":{},\
             \"verdict\":\"{}\",\"calibration_n\":{},\
             \"total_observations\":{},\"regime_state\":\"{}\"}}",
            report.schema_version,
            report.replay_ref,
            result.metric,
            result.value,
            result
                .threshold
                .map_or_else(|| "null".to_string(), |t| format!("{t:.3}")),
            result.e_value,
            result.exceeds_threshold,
            result.verdict.label(),
            result.calibration_n,
            report.total_observations,
            report.regime_state.as_deref().unwrap_or("unknown"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_baseline_stats(gauss_ops: usize, inactivated: usize) -> DecodeStats {
        DecodeStats {
            gauss_ops,
            inactivated,
            dense_core_rows: gauss_ops / 2,
            dense_core_cols: gauss_ops / 3,
            pivots_selected: inactivated,
            peel_frontier_peak: 4,
            policy_mode: Some("stable"),
            ..Default::default()
        }
    }

    #[test]
    fn monitor_starts_in_calibrating_state() {
        let mut monitor = RegressionMonitor::new();
        let stats = make_baseline_stats(10, 3);
        let report = monitor.check(&stats);
        assert_eq!(
            report.overall_verdict,
            RegressionVerdict::Calibrating,
            "should be calibrating before min samples"
        );
    }

    #[test]
    fn monitor_transitions_to_accept_after_calibration() {
        let mut monitor = RegressionMonitor::new();

        // Calibrate with baseline observations.
        for i in 0..MIN_CALIBRATION_SAMPLES + 5 {
            let stats = make_baseline_stats(10 + i % 3, 3);
            monitor.calibrate(&stats);
        }
        assert!(
            monitor.is_calibrated(),
            "should be calibrated after {} samples",
            MIN_CALIBRATION_SAMPLES + 5
        );

        // Check a normal observation.
        let stats = make_baseline_stats(11, 3);
        let report = monitor.check(&stats);
        assert_eq!(
            report.overall_verdict,
            RegressionVerdict::Accept,
            "normal observation should be accepted"
        );
    }

    #[test]
    fn monitor_detects_warning_on_threshold_exceedance() {
        let mut monitor = RegressionMonitor::new();

        // Calibrate with small values.
        for i in 0..(MIN_CALIBRATION_SAMPLES + 5) {
            let stats = make_baseline_stats(10 + i % 2, 3);
            monitor.calibrate(&stats);
        }

        // Check with a much larger value.
        let stats = make_baseline_stats(1000, 3);
        let report = monitor.check(&stats);
        assert!(
            matches!(
                report.overall_verdict,
                RegressionVerdict::Warning | RegressionVerdict::Regressed
            ),
            "large deviation should trigger warning or regression, got {:?}",
            report.overall_verdict
        );
    }

    #[test]
    fn monitor_accumulates_evidence_for_regression() {
        let mut monitor = RegressionMonitor::new();

        // Calibrate with small values.
        for i in 0..(MIN_CALIBRATION_SAMPLES + 5) {
            let stats = make_baseline_stats(10 + i % 2, 3);
            monitor.calibrate(&stats);
        }

        // Feed many anomalous observations to accumulate e-value evidence.
        let mut any_regressed = false;
        for _ in 0..200 {
            let stats = make_baseline_stats(1000, 100);
            let report = monitor.check(&stats);
            if report.overall_verdict == RegressionVerdict::Regressed {
                any_regressed = true;
                break;
            }
        }

        assert!(
            any_regressed,
            "sustained large deviation should trigger regression detection"
        );
        assert!(monitor.any_regressed());
        assert!(!monitor.regressed_metrics().is_empty());
    }

    #[test]
    fn monitor_stable_workload_no_false_alarm() {
        let mut monitor = RegressionMonitor::new();

        // Calibrate.
        for i in 0..(MIN_CALIBRATION_SAMPLES + 5) {
            let stats = make_baseline_stats(10 + i % 3, 3 + i % 2);
            monitor.calibrate(&stats);
        }

        // Check 100 normal observations — no false alarm.
        for i in 0..100 {
            let stats = make_baseline_stats(10 + i % 3, 3 + i % 2);
            let report = monitor.check(&stats);
            assert_ne!(
                report.overall_verdict,
                RegressionVerdict::Regressed,
                "stable workload should not trigger false alarm at check {i}"
            );
        }

        assert!(
            !monitor.any_regressed(),
            "stable workload should have no regressions"
        );
    }

    #[test]
    fn monitor_reset_evidence_clears_e_processes() {
        let mut monitor = RegressionMonitor::new();

        // Calibrate and force regression.
        for i in 0..(MIN_CALIBRATION_SAMPLES + 5) {
            let stats = make_baseline_stats(10, 3 + i % 2);
            monitor.calibrate(&stats);
        }
        for _ in 0..200 {
            let stats = make_baseline_stats(1000, 100);
            let _ = monitor.check(&stats);
        }

        // Reset evidence.
        monitor.reset_evidence();
        assert!(
            !monitor.any_regressed(),
            "reset should clear regression state"
        );

        // Normal observations should be accepted.
        let stats = make_baseline_stats(11, 3);
        let report = monitor.check(&stats);
        assert_ne!(
            report.overall_verdict,
            RegressionVerdict::Regressed,
            "post-reset should not show regression"
        );
    }

    #[test]
    fn regression_report_schema_and_replay_ref() {
        let mut monitor = RegressionMonitor::new();

        for i in 0..(MIN_CALIBRATION_SAMPLES + 5) {
            let stats = make_baseline_stats(10 + i, 3);
            monitor.calibrate(&stats);
        }

        let stats = make_baseline_stats(10, 3);
        let report = monitor.check(&stats);
        assert_eq!(report.schema_version, G8_SCHEMA_VERSION);
        assert_eq!(report.replay_ref, G8_REPLAY_REF);
        assert_eq!(report.metrics.len(), TRACKED_METRICS.len());
    }

    #[test]
    fn verdict_ordering_is_correct() {
        assert!((RegressionVerdict::Accept as u8) < (RegressionVerdict::Calibrating as u8));
        assert!((RegressionVerdict::Calibrating as u8) < (RegressionVerdict::Warning as u8));
        assert!((RegressionVerdict::Warning as u8) < (RegressionVerdict::Regressed as u8));
    }

    #[test]
    fn e_value_and_threshold_accessors() {
        let mut monitor = RegressionMonitor::new();

        // Before calibration.
        assert!(monitor.threshold("gauss_ops").is_none());

        for i in 0..(MIN_CALIBRATION_SAMPLES + 5) {
            let stats = make_baseline_stats(10 + i, 3);
            monitor.calibrate(&stats);
        }

        // After calibration.
        assert!(monitor.threshold("gauss_ops").is_some());
        assert!(monitor.e_value("gauss_ops").is_some());
    }

    #[test]
    fn regime_state_covariate_captured() {
        let mut monitor = RegressionMonitor::new();

        for i in 0..(MIN_CALIBRATION_SAMPLES + 5) {
            let stats = make_baseline_stats(10 + i, 3);
            monitor.calibrate(&stats);
        }

        let mut stats = make_baseline_stats(10, 3);
        stats.policy_mode = Some("retuned");
        let report = monitor.check(&stats);
        assert_eq!(
            report.regime_state,
            Some("retuned".to_string()),
            "regime state should be captured from DecodeStats"
        );
    }

    #[test]
    fn deterministic_replay_produces_identical_reports() {
        let observations: Vec<DecodeStats> = (0..50)
            .map(|i| make_baseline_stats(10 + i % 5, 3 + i % 3))
            .collect();

        let mut mon_a = RegressionMonitor::new();
        let mut mon_b = RegressionMonitor::new();

        // Calibrate both.
        for obs in observations.iter().take(MIN_CALIBRATION_SAMPLES + 5) {
            mon_a.calibrate(obs);
            mon_b.calibrate(obs);
        }

        // Check remaining.
        for obs in observations.iter().skip(MIN_CALIBRATION_SAMPLES + 5) {
            let report_a = mon_a.check(obs);
            let report_b = mon_b.check(obs);

            assert_eq!(
                report_a.overall_verdict, report_b.overall_verdict,
                "deterministic replay violated"
            );
            for (ra, rb) in report_a.metrics.iter().zip(report_b.metrics.iter()) {
                assert_eq!(ra.metric, rb.metric);
                assert!(
                    (ra.e_value - rb.e_value).abs() < f64::EPSILON,
                    "expected {}, got {}",
                    rb.e_value,
                    ra.e_value
                );
                assert_eq!(ra.verdict, rb.verdict);
            }
        }
    }
}
