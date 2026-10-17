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
//! The calibrator is opt-in. `ScheduleExplorer::with_conformal_calibration`
//! feeds it every explored run's oracle report and lists the seeds whose
//! metrics fall outside the prediction set; callers can also feed it reports
//! themselves. No lab oracle consults it on its own.
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

fn assert_valid_alpha(alpha: f64) {
    assert!(
        alpha.is_finite() && alpha > 0.0 && alpha < 1.0,
        "alpha must be finite and in (0, 1), got {alpha}"
    );
}

fn assert_valid_min_samples(min_samples: usize) {
    assert!(min_samples > 0, "min_calibration_samples must be > 0");
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
        assert_valid_alpha(alpha);
        Self {
            alpha,
            ..Default::default()
        }
    }

    /// Set the minimum calibration samples.
    #[must_use]
    pub fn min_samples(mut self, n: usize) -> Self {
        assert_valid_min_samples(n);
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
#[derive(Debug, Clone, Default)]
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageTracker {
    /// Total predictions made.
    pub total: usize,
    /// Predictions where the observation was within the prediction set.
    pub covered: usize,
}

impl CoverageTracker {
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
    ///
    /// br-asupersync-9u4ext: tolerance is now alpha-derived (1/5 of
    /// the configured alpha) rather than a fixed 5-percentage-point
    /// absolute slack. With the default alpha=0.05 (95% target),
    /// well-calibrated now means observed rate is at least
    /// `0.95 - 0.01 = 0.94` rather than the previous `0.95 - 0.05
    /// = 0.90`. The fixed 0.05 cushion was roughly 5x the alpha
    /// itself — wide enough that a system whose anomaly rate had
    /// climbed to 9% was still reported as 'well-calibrated',
    /// defeating the conformal-prediction guarantee operators
    /// believe they are getting.
    ///
    /// Tolerance derivation: scaling at `alpha / 5` means the slack
    /// stays proportional to the prediction guarantee — strict
    /// (alpha=0.01 → 0.2pp slack) and looser (alpha=0.20 → 4pp
    /// slack) configurations both get a band that's a fixed
    /// fraction of their stated risk budget. The floor of
    /// `f64::EPSILON` keeps the comparison strictly correct even
    /// when alpha is configured to extreme values.
    #[must_use]
    pub fn is_well_calibrated(&self) -> bool {
        if self.overall_coverage.total == 0 {
            return true;
        }
        let target = 1.0 - self.alpha;
        self.overall_coverage.rate() >= target - self.calibration_tolerance()
    }

    /// br-asupersync-9u4ext: tolerance band used by
    /// `is_well_calibrated` and `miscalibrated_invariants`. Exposed so
    /// operators / harness reports can show the same number that
    /// drives the pass/fail decision.
    #[must_use]
    pub fn calibration_tolerance(&self) -> f64 {
        (self.alpha / 5.0).max(f64::EPSILON)
    }

    /// Invariants whose empirical coverage falls below the target.
    #[must_use]
    pub fn miscalibrated_invariants(&self) -> Vec<String> {
        let target = 1.0 - self.alpha;
        let tolerance = self.calibration_tolerance();
        self.coverage
            .iter()
            .filter(|(_, tracker)| tracker.total > 0 && tracker.rate() < target - tolerance)
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
        assert_valid_alpha(config.alpha);
        assert_valid_min_samples(config.min_calibration_samples);
        Self {
            config,
            calibrations: BTreeMap::new(),
            coverage_trackers: BTreeMap::new(),
            overall_coverage: CoverageTracker::default(),
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
                .or_default();
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
        let was_already_calibrated = self.is_calibrated();

        if !was_already_calibrated {
            // Add to calibration set first.
            self.calibrate(report);
            // Whether we just became calibrated or still need more data,
            // skip the prediction for this observation: it is part of the
            // calibration set and testing it against the same set violates
            // the exchangeability assumption of split conformal prediction.
            return None;
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
                .or_default();
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

        // Grow the calibration set with this observation for future predictions,
        // unless it was already added above during the uncalibrated→calibrated transition.
        if was_already_calibrated {
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
/// Returns the `ceil((1-alpha)(n+1))`-th smallest calibration score (1-indexed),
/// which yields the split-conformal finite-sample guarantee
/// `P(score_{n+1} <= threshold) >= 1 - alpha` under exchangeability. When that
/// rank exceeds `n` (i.e. `alpha < 1/(n+1)`), no finite score attains the
/// target coverage, so the threshold is `+inf` (cover everything) — the same
/// convention as the empty-calibration case.
fn conformal_quantile(scores: &[f64], alpha: f64) -> f64 {
    if scores.is_empty() {
        return f64::INFINITY;
    }

    let n = scores.len();
    let mut sorted = scores.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    // The conformal threshold is the ceil((1-alpha)(n+1))-th order statistic
    // (1-indexed). br-asupersync-mdym3s: when that rank exceeds n the correct
    // threshold is +inf — clamping to the largest score (min(n)) instead only
    // attains n/(n+1) < 1-alpha worst-case coverage (the test point can be the
    // new maximum) and silently violates the finite-sample guarantee.
    let level = (1.0 - alpha) * (count_to_f64(n) + 1.0);
    #[allow(clippy::cast_sign_loss)]
    let rank = level.ceil() as usize;
    if rank > n {
        return f64::INFINITY;
    }

    sorted[rank.saturating_sub(1)]
}

// ============================================================================
// Health threshold conformal calibration
// ============================================================================

/// How the threshold bounds anomalous values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdMode {
    /// Only values above the threshold are anomalous (e.g., queue depth,
    /// restart intensity). Uses the (1-α)(n+1)-th order statistic directly.
    Upper,
    /// Both unusually high and unusually low values are anomalous.
    /// Uses |value - median| as the nonconformity score.
    TwoSided,
}

/// Configuration for health threshold calibration.
#[derive(Debug, Clone)]
pub struct HealthThresholdConfig {
    /// Target miscoverage rate (e.g., 0.05 for 95% coverage).
    pub alpha: f64,
    /// Minimum calibration samples before producing thresholds.
    pub min_calibration_samples: usize,
    /// Threshold direction.
    pub mode: ThresholdMode,
}

impl Default for HealthThresholdConfig {
    fn default() -> Self {
        Self {
            alpha: 0.05,
            min_calibration_samples: 5,
            mode: ThresholdMode::Upper,
        }
    }
}

impl HealthThresholdConfig {
    /// Create a config with the given miscoverage rate and mode.
    #[must_use]
    pub fn new(alpha: f64, mode: ThresholdMode) -> Self {
        assert_valid_alpha(alpha);
        Self {
            alpha,
            mode,
            ..Default::default()
        }
    }

    /// Set the minimum calibration samples.
    #[must_use]
    pub fn min_samples(mut self, n: usize) -> Self {
        assert_valid_min_samples(n);
        self.min_calibration_samples = n;
        self
    }
}

/// Result of checking a health metric against a conformal threshold.
#[derive(Debug, Clone)]
pub struct ThresholdCheck {
    /// The metric name.
    pub metric: String,
    /// The observed value.
    pub value: f64,
    /// The conformal threshold.
    pub threshold: f64,
    /// Whether the observation is within the prediction set (conforming).
    pub conforming: bool,
    /// The nonconformity score.
    pub nonconformity_score: f64,
    /// Number of calibration samples used.
    pub calibration_n: usize,
    /// Target coverage level (1 - alpha).
    pub coverage_target: f64,
}

/// Per-metric calibration state.
#[derive(Debug, Clone, Default)]
struct MetricCalibration {
    /// Raw observations for direct upper-bound thresholding.
    values: Vec<f64>,
}

impl MetricCalibration {
    fn n(&self) -> usize {
        self.values.len()
    }

    fn median(&self) -> f64 {
        if self.values.is_empty() {
            return 0.0;
        }
        let mut sorted = self.values.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mid = sorted.len() / 2;
        if sorted.len().is_multiple_of(2) && sorted.len() >= 2 {
            (sorted[mid - 1]).midpoint(sorted[mid])
        } else {
            sorted[mid]
        }
    }
}

/// Conformal calibrator for health metrics (queue depth, restart latency, etc.).
///
/// Accumulates observations during a calibration phase, then produces
/// adaptive thresholds with finite-sample, distribution-free coverage
/// guarantees.
///
/// # Coverage Guarantee
///
/// For exchangeable observations, P(new observation conforming) ≥ 1 - alpha.
/// This holds without distributional assumptions (Vovk et al. 2005).
///
/// # Modes
///
/// - [`ThresholdMode::Upper`]: Flags values above the conformal quantile.
///   Good for metrics where only high values are problematic (queue depth,
///   restart intensity).
///
/// - [`ThresholdMode::TwoSided`]: Uses |value - median| as the nonconformity
///   score. Flags observations that deviate from the calibration distribution
///   in either direction.
///
/// # Example
///
/// ```
/// use asupersync::lab::conformal::{
///     HealthThresholdCalibrator, HealthThresholdConfig, ThresholdMode,
/// };
///
/// let config = HealthThresholdConfig::new(0.05, ThresholdMode::Upper).min_samples(5);
/// let mut cal = HealthThresholdCalibrator::new(config);
///
/// // Calibrate with normal observations
/// for depth in (1..=20).map(f64::from) {
///     cal.calibrate("queue_depth", depth);
/// }
///
/// // Check a new observation
/// let result = cal.check("queue_depth", 100.0).unwrap();
/// assert!(!result.conforming); // queue depth 100 is anomalous
/// ```
#[derive(Debug, Clone)]
pub struct HealthThresholdCalibrator {
    config: HealthThresholdConfig,
    metrics: BTreeMap<String, MetricCalibration>,
    coverage_trackers: BTreeMap<String, CoverageTracker>,
    n_calibration: usize,
}

impl HealthThresholdCalibrator {
    /// Create a new calibrator with the given config.
    #[must_use]
    pub fn new(config: HealthThresholdConfig) -> Self {
        assert_valid_alpha(config.alpha);
        assert_valid_min_samples(config.min_calibration_samples);
        Self {
            config,
            metrics: BTreeMap::new(),
            coverage_trackers: BTreeMap::new(),
            n_calibration: 0,
        }
    }

    /// Number of calibration observations accumulated (total across all metrics).
    #[must_use]
    pub fn calibration_samples(&self) -> usize {
        self.n_calibration
    }

    /// Whether a named metric has enough samples for prediction.
    #[must_use]
    pub fn is_metric_calibrated(&self, metric: &str) -> bool {
        self.metrics
            .get(metric)
            .is_some_and(|m| m.n() >= self.config.min_calibration_samples)
    }

    /// Add a calibration observation for a named metric.
    pub fn calibrate(&mut self, metric: &str, value: f64) {
        // Non-finite calibration values can poison quantile computation.
        // Ignore them so thresholds remain stable and deterministic.
        if !value.is_finite() {
            return;
        }

        let cal = self.metrics.entry(metric.to_string()).or_default();

        cal.values.push(value);

        self.n_calibration += 1;
    }

    /// Check if a new observation exceeds the conformal threshold.
    ///
    /// Returns `None` if the metric is not yet calibrated.
    #[must_use]
    pub fn check(&self, metric: &str, value: f64) -> Option<ThresholdCheck> {
        let cal = self.metrics.get(metric)?;
        if cal.n() < self.config.min_calibration_samples {
            return None;
        }

        // Non-finite observations are always anomalous; report explicitly
        // without mutating calibration state.
        if !value.is_finite() {
            return Some(ThresholdCheck {
                metric: metric.to_string(),
                value,
                threshold: self.threshold(metric)?,
                conforming: false,
                nonconformity_score: f64::INFINITY,
                calibration_n: cal.n(),
                coverage_target: 1.0 - self.config.alpha,
            });
        }

        let (nonconformity_score, threshold) = match self.config.mode {
            ThresholdMode::Upper => {
                let score = value;
                let threshold = conformal_quantile(&cal.values, self.config.alpha);
                (score, threshold)
            }
            ThresholdMode::TwoSided => {
                // Recompute nonconformity scores from the current full median so
                // that both calibration and test scores use the same reference
                // point, preserving exchangeability for the conformal guarantee.
                let median = cal.median();
                let scores: Vec<f64> = cal.values.iter().map(|v| (v - median).abs()).collect();
                let score = (value - median).abs();
                let threshold = conformal_quantile(&scores, self.config.alpha);
                (score, threshold)
            }
        };

        let conforming = nonconformity_score <= threshold;

        Some(ThresholdCheck {
            metric: metric.to_string(),
            value,
            threshold,
            conforming,
            nonconformity_score,
            calibration_n: cal.n(),
            coverage_target: 1.0 - self.config.alpha,
        })
    }

    /// Check a metric and update coverage tracking.
    pub fn check_and_track(&mut self, metric: &str, value: f64) -> Option<ThresholdCheck> {
        let result = self.check(metric, value)?;

        let tracker = self
            .coverage_trackers
            .entry(metric.to_string())
            .or_default();
        tracker.total += 1;
        if result.conforming {
            tracker.covered += 1;
        }

        Some(result)
    }

    /// Get the current adaptive threshold for a metric.
    ///
    /// Returns `None` if not yet calibrated.
    #[must_use]
    pub fn threshold(&self, metric: &str) -> Option<f64> {
        let cal = self.metrics.get(metric)?;
        if cal.n() < self.config.min_calibration_samples {
            return None;
        }

        match self.config.mode {
            ThresholdMode::Upper => Some(conformal_quantile(&cal.values, self.config.alpha)),
            ThresholdMode::TwoSided => {
                let median = cal.median();
                let scores: Vec<f64> = cal.values.iter().map(|v| (v - median).abs()).collect();
                Some(conformal_quantile(&scores, self.config.alpha))
            }
        }
    }

    /// Per-metric coverage rates from prediction tracking.
    #[must_use]
    pub fn coverage_rates(&self) -> BTreeMap<String, f64> {
        self.coverage_trackers
            .iter()
            .map(|(name, tracker)| (name.clone(), tracker.rate()))
            .collect()
    }

    /// Per-metric calibration sample counts.
    #[must_use]
    pub fn metric_counts(&self) -> BTreeMap<String, usize> {
        self.metrics
            .iter()
            .map(|(name, cal)| (name.clone(), cal.n()))
            .collect()
    }

    /// Check multiple metrics at once and return all results.
    #[must_use]
    pub fn check_all(&self, observations: &[(&str, f64)]) -> Vec<ThresholdCheck> {
        observations
            .iter()
            .filter_map(|(metric, value)| self.check(metric, *value))
            .collect()
    }

    /// Returns true if any checked metric is non-conforming.
    #[must_use]
    pub fn any_anomalous(&self, observations: &[(&str, f64)]) -> bool {
        observations
            .iter()
            .filter_map(|(metric, value)| self.check(metric, *value))
            .any(|r| !r.conforming)
    }
}

impl std::fmt::Display for ThresholdCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status = if self.conforming { "OK" } else { "ANOMALOUS" };
        write!(
            f,
            "{}: value={:.4} threshold={:.4} [{}] (n={})",
            self.metric, self.value, self.threshold, status, self.calibration_n
        )
    }
}

#[cfg(test)]
#[path = "conformal_inline_tests.rs"]
mod tests;
