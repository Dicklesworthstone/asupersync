//! Distribution-free conformal calibration for lab metrics.
//!
//! Conformal prediction provides finite-sample, distribution-free coverage
//! guarantees for prediction sets. Given a target miscoverage rate `alpha`,
//! the conformal prediction set `C(X)` satisfies:
//!
//!   `P(Y ∈ C(X)) ≥ 1 - alpha`
//!
//! for **any** joint distribution of (X, Y), with no parametric assumptions.
//!
//! # Algorithm: Split Conformal Prediction
//!
//! 1. **Calibration phase**: Accumulate conformity scores `s_1, ..., s_n` from
//!    past oracle reports. A conformity score measures how "normal" an observation
//!    is — lower scores indicate more conforming behavior.
//!
//! 2. **Prediction phase**: For a new observation, compute the `(1 - alpha)(1 + 1/n)`
//!    quantile of the calibration scores. The prediction set is all values with
//!    conformity score ≤ this threshold.
//!
//! 3. **Coverage guarantee**: By the exchangeability assumption (all runs are drawn
//!    from the same program under varying seeds), Vovk et al. (2005) show that
//!    `P(s_{n+1} ≤ q_hat) ≥ 1 - alpha`.
//!
//! # Conformity Scores for Oracle Metrics
//!
//! We define conformity scores from `OracleReport` statistics:
//!
//! - **Violation score**: 0 if passed, 1 if violated (binary nonconformity).
//! - **Entity score**: Normalized entity count relative to running median.
//! - **Event density score**: Events per entity relative to calibration set.
//!
//! # References
//!
//! - Vovk, Gammerman, Shafer, "Algorithmic Learning in a Random World" (2005)
//! - Lei et al., "Distribution-Free Predictive Inference for Regression" (JASA 2018)
//! - Angelopoulos & Bates, "A Gentle Introduction to Conformal Prediction" (2022)

use crate::lab::oracle::{OracleEntryReport, OracleReport};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn count_to_f64(count: usize) -> f64 {
    f64::from(count.min(u32::MAX as usize) as u32)
}

/// Configuration for the conformal calibrator.
#[derive(Debug, Clone)]
pub struct ConformalConfig {
    /// Target miscoverage rate (e.g., 0.05 for 95% coverage).
    pub alpha: f64,
    /// Minimum calibration samples before producing prediction sets.
    pub min_calibration_samples: usize,
}

impl Default for ConformalConfig {
    fn default() -> Self {
        Self {
            alpha: 0.05,
            min_calibration_samples: 5,
        }
    }
}

impl ConformalConfig {
    /// Create a config with the given miscoverage rate.
    #[must_use]
    pub fn new(alpha: f64) -> Self {
        Self {
            alpha,
            ..Default::default()
        }
    }

    /// Set the minimum calibration samples.
    #[must_use]
    pub fn min_samples(mut self, n: usize) -> Self {
        self.min_calibration_samples = n;
        self
    }
}

/// A conformity score for a single oracle observation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ConformityScore {
    /// The nonconformity value (higher = more unusual).
    pub value: f64,
    /// Whether the oracle violated its invariant.
    pub violated: bool,
}

/// Per-invariant calibration state.
#[derive(Debug, Clone)]
struct InvariantCalibration {
    /// Accumulated conformity scores (sorted for quantile computation).
    scores: Vec<f64>,
    /// Running sum of entity counts for normalization.
    entity_sum: f64,
    /// Running sum of event counts for normalization.
    event_sum: f64,
    /// Number of violations observed.
    violation_count: usize,
}

impl InvariantCalibration {
    fn new() -> Self {
        Self {
            scores: Vec::new(),
            entity_sum: 0.0,
            event_sum: 0.0,
            violation_count: 0,
        }
    }

    fn n(&self) -> usize {
        self.scores.len()
    }

    fn mean_entities(&self) -> f64 {
        let n = self.n();
        if n == 0 {
            1.0
        } else {
            (self.entity_sum / count_to_f64(n)).max(1.0)
        }
    }

    fn mean_events(&self) -> f64 {
        let n = self.n();
        if n == 0 {
            1.0
        } else {
            (self.event_sum / count_to_f64(n)).max(1.0)
        }
    }

    fn empirical_violation_rate(&self) -> f64 {
        let n = self.n();
        if n == 0 {
            0.0
        } else {
            count_to_f64(self.violation_count) / count_to_f64(n)
        }
    }
}

/// A prediction set for a single invariant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictionSet {
    /// The invariant name.
    pub invariant: String,
    /// The conformity threshold (quantile).
    pub threshold: f64,
    /// Whether a new observation is within the prediction set (conforming).
    pub conforming: bool,
    /// The new observation's conformity score.
    pub score: f64,
    /// Number of calibration samples used.
    pub calibration_n: usize,
    /// Target coverage level (1 - alpha).
    pub coverage_target: f64,
}

/// Empirical coverage tracking for calibration diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageTracker {
    /// Total predictions made.
    pub total: usize,
    /// Predictions where the observation was within the prediction set.
    pub covered: usize,
}

impl CoverageTracker {
    fn new() -> Self {
        Self {
            total: 0,
            covered: 0,
        }
    }

    /// Empirical coverage rate.
    #[must_use]
    pub fn rate(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            count_to_f64(self.covered) / count_to_f64(self.total)
        }
    }
}

/// Calibration report with coverage diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationReport {
    /// Per-invariant prediction sets from the latest observation.
    pub prediction_sets: Vec<PredictionSet>,
    /// Per-invariant empirical coverage tracking.
    pub coverage: BTreeMap<String, CoverageTracker>,
    /// Overall empirical coverage across all invariants.
    pub overall_coverage: CoverageTracker,
    /// Target miscoverage rate.
    pub alpha: f64,
    /// Total calibration observations.
    pub calibration_samples: usize,
}

impl CalibrationReport {
    /// Returns true if all observed coverage rates are above the target.
    #[must_use]
    pub fn is_well_calibrated(&self) -> bool {
        if self.overall_coverage.total == 0 {
            return true;
        }
        // Allow small slack for finite samples.
        let target = 1.0 - self.alpha;
        self.overall_coverage.rate() >= target - 0.05
    }

    /// Invariants whose empirical coverage falls below the target.
    #[must_use]
    pub fn miscalibrated_invariants(&self) -> Vec<String> {
        let target = 1.0 - self.alpha;
        self.coverage
            .iter()
            .filter(|(_, tracker)| tracker.total > 0 && tracker.rate() < target - 0.05)
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Render as structured text.
    #[must_use]
    pub fn to_text(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        out.push_str("CONFORMAL CALIBRATION REPORT\n");
        let _ = writeln!(
            out,
            "target coverage: {:.1}% (alpha={:.3})",
            (1.0 - self.alpha) * 100.0,
            self.alpha
        );
        let _ = writeln!(out, "calibration samples: {}", self.calibration_samples);
        let _ = writeln!(
            out,
            "overall empirical coverage: {:.1}% ({}/{})\n",
            self.overall_coverage.rate() * 100.0,
            self.overall_coverage.covered,
            self.overall_coverage.total,
        );

        for ps in &self.prediction_sets {
            let status = if ps.conforming { "OK" } else { "ANOMALOUS" };
            let _ = writeln!(
                out,
                "  {}: score={:.4} threshold={:.4} [{}] (n={})",
                ps.invariant, ps.score, ps.threshold, status, ps.calibration_n
            );
        }

        let miscal = self.miscalibrated_invariants();
        if miscal.is_empty() {
            out.push_str("\ncalibration: WELL-CALIBRATED\n");
        } else {
            let _ = writeln!(
                out,
                "\ncalibration: MISCALIBRATED on: {}",
                miscal.join(", ")
            );
        }

        out
    }

    /// Serialize to JSON.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "alpha": self.alpha,
            "coverage_target": 1.0 - self.alpha,
            "calibration_samples": self.calibration_samples,
            "overall_coverage": {
                "total": self.overall_coverage.total,
                "covered": self.overall_coverage.covered,
                "rate": self.overall_coverage.rate(),
            },
            "well_calibrated": self.is_well_calibrated(),
            "prediction_sets": self.prediction_sets,
            "per_invariant_coverage": self.coverage.iter().map(|(name, t)| {
                serde_json::json!({
                    "invariant": name,
                    "total": t.total,
                    "covered": t.covered,
                    "rate": t.rate(),
                })
            }).collect::<Vec<_>>(),
        })
    }
}

/// Distribution-free conformal calibrator for oracle metrics.
///
/// Accumulates conformity scores from oracle reports during a calibration
/// phase, then produces prediction sets with guaranteed marginal coverage
/// for new observations.
///
/// # Coverage Guarantee
///
/// For exchangeable observations (same program, varying seeds), the
/// prediction set `C(X_{n+1})` satisfies:
///
///   `P(Y_{n+1} ∈ C(X_{n+1})) ≥ 1 - alpha`
///
/// This is a finite-sample, distribution-free guarantee.
#[derive(Debug, Clone)]
pub struct ConformalCalibrator {
    config: ConformalConfig,
    /// Per-invariant calibration state.
    calibrations: BTreeMap<String, InvariantCalibration>,
    /// Per-invariant coverage tracking.
    coverage_trackers: BTreeMap<String, CoverageTracker>,
    /// Overall coverage tracker.
    overall_coverage: CoverageTracker,
    /// Total calibration observations.
    n_calibration: usize,
}

impl ConformalCalibrator {
    /// Create a new calibrator with the given config.
    #[must_use]
    pub fn new(config: ConformalConfig) -> Self {
        Self {
            config,
            calibrations: BTreeMap::new(),
            coverage_trackers: BTreeMap::new(),
            overall_coverage: CoverageTracker::new(),
            n_calibration: 0,
        }
    }

    /// Create a calibrator with the default config (alpha=0.05).
    #[must_use]
    pub fn default_calibrator() -> Self {
        Self::new(ConformalConfig::default())
    }

    /// Number of calibration observations accumulated.
    #[must_use]
    pub fn calibration_samples(&self) -> usize {
        self.n_calibration
    }

    /// Whether enough calibration samples have been collected.
    #[must_use]
    pub fn is_calibrated(&self) -> bool {
        self.n_calibration >= self.config.min_calibration_samples
    }

    /// Add a calibration observation from an oracle report.
    ///
    /// During the calibration phase, conformity scores are accumulated
    /// but no predictions are made.
    pub fn calibrate(&mut self, report: &OracleReport) {
        for entry in &report.entries {
            let cal = self
                .calibrations
                .entry(entry.invariant.clone())
                .or_insert_with(InvariantCalibration::new);
            let score = conformity_score(entry, cal);
            cal.scores.push(score);
            cal.entity_sum += count_to_f64(entry.stats.entities_tracked);
            cal.event_sum += count_to_f64(entry.stats.events_recorded);
            if !entry.passed {
                cal.violation_count += 1;
            }
        }
        self.n_calibration += 1;
    }

    /// Observe a new report and produce prediction sets.
    ///
    /// If not yet calibrated, returns `None`. Otherwise, returns a
    /// `CalibrationReport` with prediction sets and coverage diagnostics.
    #[must_use]
    pub fn predict(&mut self, report: &OracleReport) -> Option<CalibrationReport> {
        if !self.is_calibrated() {
            // Add to calibration set first.
            self.calibrate(report);
            if !self.is_calibrated() {
                // Still not enough data — no prediction yet.
                return None;
            }
            // Just became calibrated — fall through to produce a prediction
            // using the calibration set that now includes this observation.
        }

        let mut prediction_sets = Vec::new();

        for entry in &report.entries {
            let Some(cal) = self.calibrations.get(&entry.invariant) else {
                continue;
            };

            // Compute conformity score for the new observation.
            let score = conformity_score(entry, cal);

            // Compute the conformal quantile threshold.
            let threshold = conformal_quantile(&cal.scores, self.config.alpha);

            let conforming = score <= threshold;

            // Update coverage tracking.
            let tracker = self
                .coverage_trackers
                .entry(entry.invariant.clone())
                .or_insert_with(CoverageTracker::new);
            tracker.total += 1;
            if conforming {
                tracker.covered += 1;
            }
            self.overall_coverage.total += 1;
            if conforming {
                self.overall_coverage.covered += 1;
            }

            prediction_sets.push(PredictionSet {
                invariant: entry.invariant.clone(),
                threshold,
                conforming,
                score,
                calibration_n: cal.n(),
                coverage_target: 1.0 - self.config.alpha,
            });
        }

        // Add this observation to the calibration set for future predictions
        // (only if not already added above during the transition from uncalibrated).
        if self.n_calibration > self.config.min_calibration_samples {
            self.calibrate(report);
        }

        Some(CalibrationReport {
            prediction_sets,
            coverage: self.coverage_trackers.clone(),
            overall_coverage: self.overall_coverage.clone(),
            alpha: self.config.alpha,
            calibration_samples: self.n_calibration,
        })
    }

    /// Per-invariant empirical violation rates from calibration data.
    #[must_use]
    pub fn violation_rates(&self) -> BTreeMap<String, f64> {
        self.calibrations
            .iter()
            .map(|(name, cal)| (name.clone(), cal.empirical_violation_rate()))
            .collect()
    }

    /// Per-invariant coverage rates from prediction tracking.
    #[must_use]
    pub fn coverage_rates(&self) -> BTreeMap<String, f64> {
        self.coverage_trackers
            .iter()
            .map(|(name, tracker)| (name.clone(), tracker.rate()))
            .collect()
    }
}

/// Compute a conformity score for an oracle entry.
///
/// The score combines:
/// 1. Violation indicator (0/1) — dominates for invariant violations
/// 2. Entity count deviation from mean (normalized)
/// 3. Event density anomaly (events/entity vs mean)
///
/// Lower scores indicate more conforming behavior.
fn conformity_score(entry: &OracleEntryReport, cal: &InvariantCalibration) -> f64 {
    let violation_component = if entry.passed { 0.0 } else { 1.0 };

    // When calibration has no data, deviations are undefined — treat as zero.
    if cal.n() == 0 {
        return violation_component;
    }

    let mean_entities = cal.mean_entities();
    let entity_deviation = if mean_entities > 0.0 {
        ((count_to_f64(entry.stats.entities_tracked) - mean_entities) / mean_entities).abs()
    } else {
        0.0
    };

    let mean_events = cal.mean_events();
    let event_deviation = if mean_events > 0.0 {
        ((count_to_f64(entry.stats.events_recorded) - mean_events) / mean_events).abs()
    } else {
        0.0
    };

    // Weighted combination: violations dominate, deviations are secondary.
    0.1_f64.mul_add(
        event_deviation,
        0.1_f64.mul_add(entity_deviation, violation_component),
    )
}

/// Compute the conformal quantile from calibration scores.
///
/// Returns the `ceil((1-alpha)(1+1/n))`-th smallest value from the
/// sorted scores, which gives the finite-sample coverage guarantee.
fn conformal_quantile(scores: &[f64], alpha: f64) -> f64 {
    if scores.is_empty() {
        return f64::INFINITY;
    }

    let n = scores.len();
    let mut sorted = scores.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    // The conformal quantile level: ceil((1-alpha)(n+1)/n) mapped to index.
    // Equivalently: the ceil((1-alpha)(n+1))-th order statistic.
    let level = (1.0 - alpha) * (count_to_f64(n) + 1.0);
    #[allow(clippy::cast_sign_loss)]
    let idx = (level.ceil() as usize).min(n).saturating_sub(1);

    sorted[idx]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::OracleStats;

    fn make_clean_report(entities: usize, events: usize) -> OracleReport {
        OracleReport {
            entries: vec![OracleEntryReport {
                invariant: "test_oracle".to_string(),
                passed: true,
                violation: None,
                stats: OracleStats {
                    entities_tracked: entities,
                    events_recorded: events,
                },
            }],
            total: 1,
            passed: 1,
            failed: 0,
            check_time_nanos: 0,
        }
    }

    fn make_violated_report(entities: usize, events: usize) -> OracleReport {
        OracleReport {
            entries: vec![OracleEntryReport {
                invariant: "test_oracle".to_string(),
                passed: false,
                violation: Some("test violation".to_string()),
                stats: OracleStats {
                    entities_tracked: entities,
                    events_recorded: events,
                },
            }],
            total: 1,
            passed: 0,
            failed: 1,
            check_time_nanos: 0,
        }
    }

    #[test]
    fn conformal_quantile_empty() {
        assert!(conformal_quantile(&[], 0.05).is_infinite());
    }

    #[test]
    fn conformal_quantile_single() {
        let scores = [0.5];
        let q = conformal_quantile(&scores, 0.05);
        assert!((q - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn conformal_quantile_sorted() {
        let scores = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0];
        let q95 = conformal_quantile(&scores, 0.05);
        // (1-0.05)(10+1) = 10.45, ceil = 11, min(10)-1 = 9 => scores[9] = 1.0
        assert!((q95 - 1.0).abs() < f64::EPSILON);

        let q80 = conformal_quantile(&scores, 0.20);
        // (1-0.20)(10+1) = 8.8, ceil = 9, -1 = 8 => scores[8] = 0.9
        assert!((q80 - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn calibrator_starts_uncalibrated() {
        let cal = ConformalCalibrator::default_calibrator();
        assert!(!cal.is_calibrated());
        assert_eq!(cal.calibration_samples(), 0);
    }

    #[test]
    fn calibrator_becomes_calibrated() {
        let config = ConformalConfig::new(0.10).min_samples(3);
        let mut cal = ConformalCalibrator::new(config);

        for _ in 0..3 {
            cal.calibrate(&make_clean_report(10, 50));
        }
        assert!(cal.is_calibrated());
        assert_eq!(cal.calibration_samples(), 3);
    }

    #[test]
    fn predict_returns_none_before_calibrated() {
        let config = ConformalConfig::new(0.10).min_samples(5);
        let mut cal = ConformalCalibrator::new(config);

        // First 4 reports: not yet calibrated.
        for _ in 0..4 {
            assert!(cal.predict(&make_clean_report(10, 50)).is_none());
        }
        // 5th: now calibrated.
        let report = cal.predict(&make_clean_report(10, 50));
        assert!(report.is_some());
    }

    #[test]
    fn clean_observations_are_conforming() {
        let config = ConformalConfig::new(0.10).min_samples(3);
        let mut cal = ConformalCalibrator::new(config);

        // Calibrate with clean reports.
        for _ in 0..5 {
            cal.calibrate(&make_clean_report(10, 50));
        }

        // New clean observation should be conforming.
        let report = cal.predict(&make_clean_report(10, 50)).unwrap();
        assert_eq!(report.prediction_sets.len(), 1);
        assert!(
            report.prediction_sets[0].conforming,
            "clean observation should be conforming"
        );
    }

    #[test]
    fn violation_is_anomalous() {
        let config = ConformalConfig::new(0.10).min_samples(3);
        let mut cal = ConformalCalibrator::new(config);

        // Calibrate with clean reports.
        for _ in 0..10 {
            cal.calibrate(&make_clean_report(10, 50));
        }

        // Violated observation should be anomalous.
        let report = cal.predict(&make_violated_report(10, 50)).unwrap();
        assert!(!report.prediction_sets[0].conforming);
    }

    #[test]
    fn coverage_tracking() {
        let config = ConformalConfig::new(0.10).min_samples(3);
        let mut cal = ConformalCalibrator::new(config);

        // Calibrate.
        for _ in 0..5 {
            cal.calibrate(&make_clean_report(10, 50));
        }

        // Predict multiple clean observations.
        for _ in 0..10 {
            let _ = cal.predict(&make_clean_report(10, 50));
        }

        let rates = cal.coverage_rates();
        let rate = rates.get("test_oracle").copied().unwrap_or(0.0);
        assert!(
            rate >= 0.8,
            "coverage rate should be high for clean data, got {rate:.2}"
        );
    }

    #[test]
    fn calibration_report_text_output() {
        let config = ConformalConfig::new(0.05).min_samples(3);
        let mut cal = ConformalCalibrator::new(config);

        for _ in 0..5 {
            cal.calibrate(&make_clean_report(10, 50));
        }
        let report = cal.predict(&make_clean_report(10, 50)).unwrap();
        let text = report.to_text();

        assert!(text.contains("CONFORMAL CALIBRATION REPORT"));
        assert!(text.contains("95.0%"));
        assert!(text.contains("alpha=0.050"));
        assert!(text.contains("test_oracle"));
    }

    #[test]
    fn calibration_report_json_roundtrip() {
        let config = ConformalConfig::new(0.05).min_samples(3);
        let mut cal = ConformalCalibrator::new(config);

        for _ in 0..5 {
            cal.calibrate(&make_clean_report(10, 50));
        }
        let report = cal.predict(&make_clean_report(10, 50)).unwrap();
        let json = report.to_json();

        assert!(json.is_object());
        assert_eq!(json["alpha"], 0.05);
        assert!(json["well_calibrated"].as_bool().unwrap());
        assert!(json["prediction_sets"].is_array());
    }

    #[test]
    fn well_calibrated_with_clean_data() {
        let config = ConformalConfig::new(0.10).min_samples(3);
        let mut cal = ConformalCalibrator::new(config);

        for _ in 0..5 {
            cal.calibrate(&make_clean_report(10, 50));
        }

        let mut last_report = None;
        for _ in 0..20 {
            last_report = cal.predict(&make_clean_report(10, 50));
        }
        let report = last_report.unwrap();
        assert!(report.is_well_calibrated());
        assert!(report.miscalibrated_invariants().is_empty());
    }

    #[test]
    fn violation_rates_tracked() {
        let config = ConformalConfig::new(0.10).min_samples(2);
        let mut cal = ConformalCalibrator::new(config);

        cal.calibrate(&make_clean_report(10, 50));
        cal.calibrate(&make_violated_report(10, 50));
        cal.calibrate(&make_clean_report(10, 50));

        let rates = cal.violation_rates();
        let rate = rates.get("test_oracle").copied().unwrap_or(0.0);
        assert!(
            (rate - 1.0 / 3.0).abs() < 0.01,
            "expected ~0.33 violation rate, got {rate:.3}"
        );
    }

    #[test]
    fn conformity_score_clean_is_low() {
        let cal = InvariantCalibration::new();
        let entry = OracleEntryReport {
            invariant: "test".to_string(),
            passed: true,
            violation: None,
            stats: OracleStats {
                entities_tracked: 10,
                events_recorded: 50,
            },
        };
        let score = conformity_score(&entry, &cal);
        assert!(score < 1.0, "clean score should be < 1.0, got {score}");
    }

    #[test]
    fn conformity_score_violation_is_high() {
        let cal = InvariantCalibration::new();
        let entry = OracleEntryReport {
            invariant: "test".to_string(),
            passed: false,
            violation: Some("leak".to_string()),
            stats: OracleStats {
                entities_tracked: 10,
                events_recorded: 50,
            },
        };
        let score = conformity_score(&entry, &cal);
        assert!(
            score >= 1.0,
            "violation score should be >= 1.0, got {score}"
        );
    }

    #[test]
    fn deterministic_calibration() {
        let run = || {
            let config = ConformalConfig::new(0.05).min_samples(3);
            let mut cal = ConformalCalibrator::new(config);
            for i in 0..5 {
                cal.calibrate(&make_clean_report(10 + i, 50 + i * 5));
            }
            cal.predict(&make_clean_report(10, 50))
        };

        let r1 = run().unwrap();
        let r2 = run().unwrap();
        assert_eq!(r1.prediction_sets.len(), r2.prediction_sets.len());
        for (a, b) in r1.prediction_sets.iter().zip(r2.prediction_sets.iter()) {
            assert!((a.score - b.score).abs() < f64::EPSILON);
            assert!((a.threshold - b.threshold).abs() < f64::EPSILON);
            assert_eq!(a.conforming, b.conforming);
        }
    }
}
