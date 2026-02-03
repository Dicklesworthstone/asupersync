//! Evidence ledger for "galaxy-brain" oracle diagnostics.
//!
//! The evidence ledger explains invariant violations (or their absence) using
//! Bayes factors and log-likelihood contributions. Each invariant gets a
//! structured evidence entry with:
//!
//! - **Bayes factor** (BF): quantifies how much the observed data favours the
//!   "invariant violated" hypothesis vs "invariant holds".
//! - **Log-likelihood contributions**: breaks the evidence into structural,
//!   temporal, and aggregate components.
//! - **Evidence lines**: human-readable `equation + substitution + intuition`
//!   triples that form the "galaxy-brain" explanation.
//!
//! # Bayes Factor Interpretation (Kass & Raftery 1995)
//!
//! | log₁₀(BF) | BF        | Strength      |
//! |-----------|-----------|---------------|
//! | < 0       | < 1       | Against       |
//! | 0 – 0.5  | 1 – 3.2   | Negligible    |
//! | 0.5 – 1.3| 3.2 – 20  | Positive      |
//! | 1.3 – 2.2| 20 – 150  | Strong        |
//! | > 2.2    | > 150     | Very strong   |

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use super::{OracleReport, OracleStats};

// ---------------------------------------------------------------------------
// Evidence strength classification
// ---------------------------------------------------------------------------

/// Strength of evidence for a hypothesis, following Kass & Raftery (1995).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceStrength {
    /// BF < 1 — evidence *against* the hypothesis.
    Against,
    /// 1 ≤ BF < 3.2 (log₁₀ BF < 0.5) — barely worth mentioning.
    Negligible,
    /// 3.2 ≤ BF < 20 (0.5 ≤ log₁₀ BF < 1.3) — positive evidence.
    Positive,
    /// 20 ≤ BF < 150 (1.3 ≤ log₁₀ BF < 2.2) — strong evidence.
    Strong,
    /// BF ≥ 150 (log₁₀ BF ≥ 2.2) — very strong evidence.
    VeryStrong,
}

impl EvidenceStrength {
    /// Classifies a log₁₀ Bayes factor into a strength category.
    #[must_use]
    pub fn from_log10_bf(log10_bf: f64) -> Self {
        if log10_bf.is_nan() {
            Self::Negligible
        } else if log10_bf < 0.0 {
            Self::Against
        } else if log10_bf < 0.5 {
            Self::Negligible
        } else if log10_bf < 1.3 {
            Self::Positive
        } else if log10_bf < 2.2 {
            Self::Strong
        } else {
            Self::VeryStrong
        }
    }

    /// Returns a short label for the strength.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Against => "against",
            Self::Negligible => "negligible",
            Self::Positive => "positive",
            Self::Strong => "strong",
            Self::VeryStrong => "very strong",
        }
    }
}

impl std::fmt::Display for EvidenceStrength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Bayes factor
// ---------------------------------------------------------------------------

/// Bayes factor for an invariant hypothesis.
///
/// `BF = P(data | H_violation) / P(data | H_holds)`.
///
/// Stored as `log₁₀(BF)` for numerical stability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BayesFactor {
    /// `log₁₀(BF)`. Positive ⇒ evidence for violation, negative ⇒ evidence for clean.
    pub log10_bf: f64,
    /// The hypothesis being tested.
    pub hypothesis: String,
    /// Classified evidence strength.
    pub strength: EvidenceStrength,
}

impl BayesFactor {
    /// Computes a Bayes factor from explicit log-likelihoods.
    ///
    /// `log10_bf = log₁₀ P(data | H1) − log₁₀ P(data | H0)`
    #[must_use]
    pub fn from_log_likelihoods(
        log10_likelihood_h1: f64,
        log10_likelihood_h0: f64,
        hypothesis: String,
    ) -> Self {
        let log10_bf = log10_likelihood_h1 - log10_likelihood_h0;
        Self {
            log10_bf,
            hypothesis,
            strength: EvidenceStrength::from_log10_bf(log10_bf),
        }
    }

    /// Returns the raw Bayes factor (10^log10_bf), clamped to avoid infinity.
    #[must_use]
    pub fn value(&self) -> f64 {
        10.0_f64.powf(self.log10_bf.clamp(-300.0, 300.0))
    }
}

// ---------------------------------------------------------------------------
// Log-likelihood contributions
// ---------------------------------------------------------------------------

/// Decomposed log-likelihood contributions from different evidence sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLikelihoodContributions {
    /// Contribution from structural observations (entity counts, topology).
    pub structural: f64,
    /// Contribution from the detection signal (violation present/absent).
    pub detection: f64,
    /// Aggregate (sum of components).
    pub total: f64,
}

// ---------------------------------------------------------------------------
// Evidence line — the "galaxy-brain" unit
// ---------------------------------------------------------------------------

/// A single evidence line: equation + substituted values + one-line intuition.
///
/// # Example
///
/// ```text
/// equation:     BF = P(violation_observed | leak) / P(violation_observed | clean)
/// substitution: BF = 0.998 / 0.001 = 998.0
/// intuition:    Very strong evidence of task leak in region R1 (3 tasks tracked)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceLine {
    /// The general equation form.
    pub equation: String,
    /// The equation with concrete values substituted.
    pub substitution: String,
    /// One-line human-readable intuition.
    pub intuition: String,
}

// ---------------------------------------------------------------------------
// Per-invariant evidence entry
// ---------------------------------------------------------------------------

/// Evidence entry for a single invariant within the ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEntry {
    /// Invariant name (e.g., "task_leak").
    pub invariant: String,
    /// Whether the invariant passed.
    pub passed: bool,
    /// Bayes factor for the violation hypothesis.
    pub bayes_factor: BayesFactor,
    /// Decomposed log-likelihood contributions.
    pub log_likelihoods: LogLikelihoodContributions,
    /// Evidence lines (equations + substitutions + intuitions).
    pub evidence_lines: Vec<EvidenceLine>,
}

// ---------------------------------------------------------------------------
// Evidence summary
// ---------------------------------------------------------------------------

/// Aggregate summary across all invariants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSummary {
    /// Total invariants examined.
    pub total_invariants: usize,
    /// Number where a violation was detected.
    pub violations_detected: usize,
    /// Invariant with the strongest evidence of violation (if any).
    pub strongest_violation: Option<String>,
    /// Invariant with the strongest evidence of being clean (if any violations exist).
    pub strongest_clean: Option<String>,
    /// Sum of log₁₀ BF across all invariants with violations.
    pub aggregate_log10_bf: f64,
}

// ---------------------------------------------------------------------------
// Evidence ledger
// ---------------------------------------------------------------------------

/// The evidence ledger: structured Bayesian explanation of oracle results.
///
/// Constructed from an [`OracleReport`] via [`EvidenceLedger::from_report`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceLedger {
    /// Per-invariant evidence entries.
    pub entries: Vec<EvidenceEntry>,
    /// Aggregate summary.
    pub summary: EvidenceSummary,
    /// Check time in nanoseconds (inherited from the oracle report).
    pub check_time_nanos: u64,
}

// ---------------------------------------------------------------------------
// Bayes factor computation model
// ---------------------------------------------------------------------------

/// Detection model parameters for computing Bayes factors.
///
/// These encode assumptions about oracle sensitivity.
#[derive(Debug, Clone)]
pub struct DetectionModel {
    /// Per-entity detection probability when the invariant is violated.
    /// Default: 0.9 (oracle detects 90% of single-entity violations).
    pub per_entity_detection_rate: f64,
    /// False-positive rate: probability of observing a violation when the
    /// invariant actually holds.  Default: 0.001.
    pub false_positive_rate: f64,
}

impl Default for DetectionModel {
    fn default() -> Self {
        Self {
            per_entity_detection_rate: 0.9,
            false_positive_rate: 0.001,
        }
    }
}

impl DetectionModel {
    /// Probability of observing a violation given that one exists,
    /// as a function of the number of tracked entities.
    ///
    /// `P(violation_observed | H_violated) = 1 − (1 − p)^n`
    ///
    /// More entities → higher detection probability.
    #[must_use]
    pub fn p_detection_given_violation(&self, entities_tracked: usize) -> f64 {
        let n = f64::from(entities_tracked.max(1).min(u32::MAX as usize) as u32);
        1.0 - (1.0 - self.per_entity_detection_rate).powf(n)
    }

    /// Probability of observing a pass given that the invariant holds.
    ///
    /// `P(pass | H_holds) = 1 − ε`
    #[must_use]
    pub fn p_pass_given_clean(&self) -> f64 {
        1.0 - self.false_positive_rate
    }

    /// Probability of observing a pass given that a violation exists.
    ///
    /// `P(pass | H_violated) = (1 − p)^n`
    #[must_use]
    pub fn p_pass_given_violation(&self, entities_tracked: usize) -> f64 {
        let n = f64::from(entities_tracked.max(1).min(u32::MAX as usize) as u32);
        (1.0 - self.per_entity_detection_rate).powf(n)
    }

    /// Computes a [`BayesFactor`] and evidence lines for an invariant.
    #[must_use]
    pub fn compute_evidence(
        &self,
        invariant: &str,
        passed: bool,
        stats: &OracleStats,
    ) -> (BayesFactor, LogLikelihoodContributions, Vec<EvidenceLine>) {
        let n = stats.entities_tracked;

        if passed {
            // Observed: pass.  BF for "holds" = P(pass|holds) / P(pass|violated)
            let p_h0 = self.p_pass_given_clean();
            let p_h1 = self.p_pass_given_violation(n);
            let log10_h0 = p_h0.log10();
            let log10_h1 = p_h1.log10();

            // The BF for "violation" hypothesis is inverted: we want BF < 1 for clean.
            let log10_bf_violation = log10_h1 - log10_h0;

            // Structural bonus: more events recorded → slightly more confident.
            let structural = structural_contribution(stats);

            let detection = log10_bf_violation;
            let total = structural + detection;

            let bf_val = 10.0_f64.powf(total.clamp(-300.0, 300.0));

            let bf = BayesFactor {
                log10_bf: total,
                hypothesis: format!("{invariant} violated"),
                strength: EvidenceStrength::from_log10_bf(total),
            };

            let lines = vec![
                EvidenceLine {
                    equation: "BF_violation = P(pass | violated) / P(pass | holds)".into(),
                    substitution: format!("BF = {p_h1:.6} / {p_h0:.6} = {bf_val:.4}"),
                    intuition: format!(
                        "{} evidence that '{invariant}' is violated ({n} entities tracked, oracle saw pass)",
                        bf.strength.label().to_uppercase(),
                    ),
                },
                EvidenceLine {
                    equation: "P(pass | violated) = (1 − p)^n".into(),
                    substitution: format!(
                        "P(pass | violated) = (1 − {:.2})^{n} = {:.6}",
                        self.per_entity_detection_rate, p_h1,
                    ),
                    intuition: format!(
                        "With {n} entities, a real violation would be missed with probability {p_h1:.6}",
                    ),
                },
            ];

            let ll = LogLikelihoodContributions {
                structural,
                detection,
                total,
            };

            (bf, ll, lines)
        } else {
            // Observed: violation.  BF for "violated" = P(violation|violated) / P(violation|holds)
            let p_h1 = self.p_detection_given_violation(n);
            let p_h0 = self.false_positive_rate;
            let log10_h1 = p_h1.log10();
            let log10_h0 = p_h0.log10();

            let structural = structural_contribution(stats);
            let detection = log10_h1 - log10_h0;
            let total = structural + detection;

            let bf_val = 10.0_f64.powf(total.clamp(-300.0, 300.0));

            let bf = BayesFactor {
                log10_bf: total,
                hypothesis: format!("{invariant} violated"),
                strength: EvidenceStrength::from_log10_bf(total),
            };

            let lines = vec![
                EvidenceLine {
                    equation:
                        "BF_violation = P(violation_observed | violated) / P(violation_observed | holds)"
                            .into(),
                    substitution: format!("BF = {p_h1:.6} / {p_h0:.6} = {bf_val:.1}"),
                    intuition: format!(
                        "{} evidence that '{invariant}' is violated ({n} entities tracked, violation observed)",
                        bf.strength.label().to_uppercase(),
                    ),
                },
                EvidenceLine {
                    equation: "P(violation_observed | violated) = 1 − (1 − p)^n".into(),
                    substitution: format!(
                        "P(detected | violated) = 1 − (1 − {:.2})^{n} = {:.6}",
                        self.per_entity_detection_rate, p_h1,
                    ),
                    intuition: format!(
                        "With {n} entities, a real violation would be detected with probability {p_h1:.6}",
                    ),
                },
            ];

            let ll = LogLikelihoodContributions {
                structural,
                detection,
                total,
            };

            (bf, ll, lines)
        }
    }
}

/// Small structural evidence contribution from event counts.
///
/// More events ⇒ marginally more confident in whatever conclusion was reached.
/// Uses `log₁₀(1 + events / 100)` as a mild bonus (< 0.1 for typical runs).
fn structural_contribution(stats: &OracleStats) -> f64 {
    let events = stats.events_recorded.min(u32::MAX as usize) as u32;
    (1.0 + f64::from(events) / 100.0).log10()
}

// ---------------------------------------------------------------------------
// EvidenceLedger construction
// ---------------------------------------------------------------------------

impl EvidenceLedger {
    /// Constructs an evidence ledger from an oracle report using the default
    /// detection model.
    #[must_use]
    pub fn from_report(report: &OracleReport) -> Self {
        Self::from_report_with_model(report, &DetectionModel::default())
    }

    /// Constructs an evidence ledger from an oracle report using a custom
    /// detection model.
    #[must_use]
    pub fn from_report_with_model(report: &OracleReport, model: &DetectionModel) -> Self {
        let entries: Vec<EvidenceEntry> = report
            .entries
            .iter()
            .map(|entry| {
                let (bf, ll, lines) =
                    model.compute_evidence(&entry.invariant, entry.passed, &entry.stats);
                EvidenceEntry {
                    invariant: entry.invariant.clone(),
                    passed: entry.passed,
                    bayes_factor: bf,
                    log_likelihoods: ll,
                    evidence_lines: lines,
                }
            })
            .collect();

        let summary = Self::compute_summary(&entries);
        Self {
            entries,
            summary,
            check_time_nanos: report.check_time_nanos,
        }
    }

    fn compute_summary(entries: &[EvidenceEntry]) -> EvidenceSummary {
        let total_invariants = entries.len();
        let violations_detected = entries.iter().filter(|e| !e.passed).count();

        let strongest_violation = entries
            .iter()
            .filter(|e| !e.passed)
            .max_by(|a, b| {
                a.bayes_factor
                    .log10_bf
                    .partial_cmp(&b.bayes_factor.log10_bf)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|e| e.invariant.clone());

        let strongest_clean = entries
            .iter()
            .filter(|e| e.passed)
            .min_by(|a, b| {
                a.bayes_factor
                    .log10_bf
                    .partial_cmp(&b.bayes_factor.log10_bf)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|e| e.invariant.clone());

        let aggregate_log10_bf: f64 = entries
            .iter()
            .filter(|e| !e.passed)
            .map(|e| e.bayes_factor.log10_bf)
            .sum();

        EvidenceSummary {
            total_invariants,
            violations_detected,
            strongest_violation,
            strongest_clean,
            aggregate_log10_bf,
        }
    }

    /// Returns entries with violations, sorted by descending evidence strength.
    #[must_use]
    pub fn violations_by_strength(&self) -> Vec<&EvidenceEntry> {
        let mut v: Vec<_> = self.entries.iter().filter(|e| !e.passed).collect();
        v.sort_by(|a, b| {
            b.bayes_factor
                .log10_bf
                .partial_cmp(&a.bayes_factor.log10_bf)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        v
    }

    /// Returns entries for clean invariants, sorted by ascending log₁₀ BF
    /// (most confident first, i.e. most negative).
    #[must_use]
    pub fn clean_by_confidence(&self) -> Vec<&EvidenceEntry> {
        let mut v: Vec<_> = self.entries.iter().filter(|e| e.passed).collect();
        v.sort_by(|a, b| {
            a.bayes_factor
                .log10_bf
                .partial_cmp(&b.bayes_factor.log10_bf)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        v
    }

    /// Renders the ledger as structured text (the "galaxy-brain" output).
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();

        let _ = writeln!(
            &mut out,
            "╔══════════════════════════════════════════════════╗"
        );
        let _ = writeln!(
            &mut out,
            "║          EVIDENCE LEDGER — ORACLE DIAGNOSTICS    ║"
        );
        let _ = writeln!(
            &mut out,
            "╚══════════════════════════════════════════════════╝"
        );
        let _ = writeln!(&mut out);
        let _ = writeln!(
            &mut out,
            "  Invariants examined: {}",
            self.summary.total_invariants
        );
        let _ = writeln!(
            &mut out,
            "  Violations detected: {}",
            self.summary.violations_detected
        );
        if let Some(ref s) = self.summary.strongest_violation {
            let _ = writeln!(&mut out, "  Strongest violation: {s}");
        }
        let _ = writeln!(
            &mut out,
            "  Aggregate log₁₀(BF): {:.3}",
            self.summary.aggregate_log10_bf
        );
        let _ = writeln!(&mut out, "  Check time: {}ns", self.check_time_nanos);
        let _ = writeln!(&mut out);

        // Violations first.
        let violations = self.violations_by_strength();
        if !violations.is_empty() {
            let _ = writeln!(
                &mut out,
                "── VIOLATIONS ──────────────────────────────────────"
            );
            for entry in violations {
                write_entry(&mut out, entry);
            }
        }

        // Clean invariants.
        let clean = self.clean_by_confidence();
        if !clean.is_empty() {
            let _ = writeln!(
                &mut out,
                "── CLEAN INVARIANTS ────────────────────────────────"
            );
            for entry in clean {
                write_entry(&mut out, entry);
            }
        }

        out
    }

    /// Serializes the ledger to a JSON value.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

fn write_entry(out: &mut String, entry: &EvidenceEntry) {
    let status = if entry.passed { "PASS" } else { "FAIL" };
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "  [{status}] {inv}  (BF = {bf:.2}, strength = {strength})",
        inv = entry.invariant,
        bf = entry.bayes_factor.value(),
        strength = entry.bayes_factor.strength,
    );
    let _ = writeln!(
        out,
        "        log₁₀(BF) = {:.4}  [structural={:.4}, detection={:.4}]",
        entry.log_likelihoods.total,
        entry.log_likelihoods.structural,
        entry.log_likelihoods.detection,
    );

    for (i, line) in entry.evidence_lines.iter().enumerate() {
        let _ = writeln!(out, "        ({}) {}", i + 1, line.equation);
        let _ = writeln!(out, "            → {}", line.substitution);
        let _ = writeln!(out, "            ⇒ {}", line.intuition);
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::oracle::{OracleEntryReport, OracleReport};

    fn make_clean_report() -> OracleReport {
        OracleReport {
            entries: vec![
                OracleEntryReport {
                    invariant: "task_leak".into(),
                    passed: true,
                    violation: None,
                    stats: OracleStats {
                        entities_tracked: 5,
                        events_recorded: 10,
                    },
                },
                OracleEntryReport {
                    invariant: "obligation_leak".into(),
                    passed: true,
                    violation: None,
                    stats: OracleStats {
                        entities_tracked: 3,
                        events_recorded: 6,
                    },
                },
            ],
            total: 2,
            passed: 2,
            failed: 0,
            check_time_nanos: 42,
        }
    }

    fn make_violation_report() -> OracleReport {
        OracleReport {
            entries: vec![
                OracleEntryReport {
                    invariant: "task_leak".into(),
                    passed: false,
                    violation: Some("leaked 2 tasks".into()),
                    stats: OracleStats {
                        entities_tracked: 5,
                        events_recorded: 10,
                    },
                },
                OracleEntryReport {
                    invariant: "quiescence".into(),
                    passed: true,
                    violation: None,
                    stats: OracleStats {
                        entities_tracked: 2,
                        events_recorded: 4,
                    },
                },
                OracleEntryReport {
                    invariant: "obligation_leak".into(),
                    passed: false,
                    violation: Some("leaked 1 obligation".into()),
                    stats: OracleStats {
                        entities_tracked: 1,
                        events_recorded: 2,
                    },
                },
            ],
            total: 3,
            passed: 1,
            failed: 2,
            check_time_nanos: 100,
        }
    }

    // -- EvidenceStrength classification --

    #[test]
    fn strength_from_log10_bf() {
        assert_eq!(
            EvidenceStrength::from_log10_bf(-1.0),
            EvidenceStrength::Against
        );
        assert_eq!(
            EvidenceStrength::from_log10_bf(0.0),
            EvidenceStrength::Negligible
        );
        assert_eq!(
            EvidenceStrength::from_log10_bf(0.49),
            EvidenceStrength::Negligible
        );
        assert_eq!(
            EvidenceStrength::from_log10_bf(0.5),
            EvidenceStrength::Positive
        );
        assert_eq!(
            EvidenceStrength::from_log10_bf(1.29),
            EvidenceStrength::Positive
        );
        assert_eq!(
            EvidenceStrength::from_log10_bf(1.3),
            EvidenceStrength::Strong
        );
        assert_eq!(
            EvidenceStrength::from_log10_bf(2.19),
            EvidenceStrength::Strong
        );
        assert_eq!(
            EvidenceStrength::from_log10_bf(2.2),
            EvidenceStrength::VeryStrong
        );
        assert_eq!(
            EvidenceStrength::from_log10_bf(5.0),
            EvidenceStrength::VeryStrong
        );
    }

    #[test]
    fn strength_labels() {
        assert_eq!(EvidenceStrength::Against.label(), "against");
        assert_eq!(EvidenceStrength::Negligible.label(), "negligible");
        assert_eq!(EvidenceStrength::Positive.label(), "positive");
        assert_eq!(EvidenceStrength::Strong.label(), "strong");
        assert_eq!(EvidenceStrength::VeryStrong.label(), "very strong");
    }

    #[test]
    fn strength_display() {
        assert_eq!(format!("{}", EvidenceStrength::Strong), "strong");
    }

    // -- BayesFactor --

    #[test]
    fn bayes_factor_from_log_likelihoods() {
        let bf = BayesFactor::from_log_likelihoods(-0.5, -3.0, "test".into());
        assert!((bf.log10_bf - 2.5).abs() < 1e-10);
        assert_eq!(bf.strength, EvidenceStrength::VeryStrong);
    }

    #[test]
    fn bayes_factor_value() {
        let bf = BayesFactor::from_log_likelihoods(0.0, -2.0, "test".into());
        // log10_bf = 2.0, so value = 100.0
        assert!((bf.value() - 100.0).abs() < 1e-6);
    }

    #[test]
    fn bayes_factor_value_clamped() {
        // Extreme value should not produce infinity.
        let bf = BayesFactor {
            log10_bf: 1000.0,
            hypothesis: "extreme".into(),
            strength: EvidenceStrength::VeryStrong,
        };
        assert!(bf.value().is_finite());
    }

    // -- DetectionModel --

    #[test]
    fn detection_model_default() {
        let m = DetectionModel::default();
        assert!((m.per_entity_detection_rate - 0.9).abs() < 1e-10);
        assert!((m.false_positive_rate - 0.001).abs() < 1e-10);
    }

    #[test]
    fn detection_model_p_detection_single_entity() {
        let m = DetectionModel::default();
        let p = m.p_detection_given_violation(1);
        assert!((p - 0.9).abs() < 1e-10);
    }

    #[test]
    fn detection_model_p_detection_multiple_entities() {
        let m = DetectionModel::default();
        // With 2 entities: 1 - (1 - 0.9)^2 = 1 - 0.01 = 0.99
        let p = m.p_detection_given_violation(2);
        assert!((p - 0.99).abs() < 1e-10);
    }

    #[test]
    fn detection_model_p_detection_zero_entities_uses_one() {
        let m = DetectionModel::default();
        let p = m.p_detection_given_violation(0);
        assert!(
            (p - 0.9).abs() < 1e-10,
            "zero entities should be treated as 1"
        );
    }

    #[test]
    fn detection_model_p_pass_given_clean() {
        let m = DetectionModel::default();
        assert!((m.p_pass_given_clean() - 0.999).abs() < 1e-10);
    }

    #[test]
    fn detection_model_p_pass_given_violation() {
        let m = DetectionModel::default();
        // (1 - 0.9)^1 = 0.1
        assert!((m.p_pass_given_violation(1) - 0.1).abs() < 1e-10);
        // (1 - 0.9)^2 = 0.01
        assert!((m.p_pass_given_violation(2) - 0.01).abs() < 1e-10);
    }

    // -- structural_contribution --

    #[test]
    fn structural_contribution_zero_events() {
        let s = structural_contribution(&OracleStats {
            entities_tracked: 0,
            events_recorded: 0,
        });
        assert!((s - 0.0_f64.log10()).abs() < 1e-10 || (s - (1.0_f64).log10()).abs() < 1e-10);
        // log10(1 + 0/100) = log10(1) = 0
        assert!(s.abs() < 1e-10);
    }

    #[test]
    fn structural_contribution_increases_with_events() {
        let s1 = structural_contribution(&OracleStats {
            entities_tracked: 0,
            events_recorded: 10,
        });
        let s2 = structural_contribution(&OracleStats {
            entities_tracked: 0,
            events_recorded: 100,
        });
        assert!(s2 > s1);
    }

    // -- EvidenceLedger from clean report --

    #[test]
    fn ledger_from_clean_report() {
        let report = make_clean_report();
        let ledger = EvidenceLedger::from_report(&report);

        assert_eq!(ledger.entries.len(), 2);
        assert_eq!(ledger.summary.total_invariants, 2);
        assert_eq!(ledger.summary.violations_detected, 0);
        assert!(ledger.summary.strongest_violation.is_none());
        assert!((ledger.summary.aggregate_log10_bf).abs() < 1e-10);
        assert_eq!(ledger.check_time_nanos, 42);
    }

    #[test]
    fn ledger_clean_entries_have_negative_bf() {
        let report = make_clean_report();
        let ledger = EvidenceLedger::from_report(&report);

        for entry in &ledger.entries {
            assert!(entry.passed);
            // BF for "violation" should be < 1 (log10 < 0) since oracle passed.
            assert!(
                entry.bayes_factor.log10_bf < 0.0,
                "clean entry '{inv}' should have BF < 1, got log10_bf={bf}",
                inv = entry.invariant,
                bf = entry.bayes_factor.log10_bf,
            );
            assert_eq!(entry.bayes_factor.strength, EvidenceStrength::Against);
        }
    }

    #[test]
    fn ledger_clean_evidence_lines() {
        let report = make_clean_report();
        let ledger = EvidenceLedger::from_report(&report);

        for entry in &ledger.entries {
            assert!(
                !entry.evidence_lines.is_empty(),
                "entry should have evidence lines"
            );
            // Check first line references the equation.
            assert!(entry.evidence_lines[0]
                .equation
                .contains("P(pass | violated)"));
        }
    }

    // -- EvidenceLedger from violation report --

    #[test]
    fn ledger_from_violation_report() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);

        assert_eq!(ledger.entries.len(), 3);
        assert_eq!(ledger.summary.total_invariants, 3);
        assert_eq!(ledger.summary.violations_detected, 2);
        assert!(ledger.summary.strongest_violation.is_some());
        assert!(ledger.summary.aggregate_log10_bf > 0.0);
    }

    #[test]
    fn ledger_violation_entries_have_positive_bf() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);

        for entry in ledger.entries.iter().filter(|e| !e.passed) {
            assert!(
                entry.bayes_factor.log10_bf > 0.0,
                "violation entry '{inv}' should have BF > 1, got log10_bf={bf}",
                inv = entry.invariant,
                bf = entry.bayes_factor.log10_bf,
            );
        }
    }

    #[test]
    fn ledger_violation_evidence_lines() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);

        let task_entry = ledger
            .entries
            .iter()
            .find(|e| e.invariant == "task_leak")
            .unwrap();
        assert!(!task_entry.passed);
        assert!(task_entry.evidence_lines[0]
            .equation
            .contains("P(violation_observed | violated)"));
    }

    // -- violations_by_strength --

    #[test]
    fn violations_by_strength_ordering() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);
        let violations = ledger.violations_by_strength();

        assert_eq!(violations.len(), 2);
        // Stronger evidence (more entities) should come first.
        assert!(violations[0].bayes_factor.log10_bf >= violations[1].bayes_factor.log10_bf);
    }

    // -- clean_by_confidence --

    #[test]
    fn clean_by_confidence_ordering() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);
        let clean = ledger.clean_by_confidence();

        assert_eq!(clean.len(), 1);
        assert_eq!(clean[0].invariant, "quiescence");
    }

    // -- text output --

    #[test]
    fn ledger_to_text_contains_header() {
        let report = make_clean_report();
        let ledger = EvidenceLedger::from_report(&report);
        let text = ledger.to_text();

        assert!(text.contains("EVIDENCE LEDGER"));
        assert!(text.contains("Invariants examined: 2"));
        assert!(text.contains("Violations detected: 0"));
        assert!(text.contains("CLEAN INVARIANTS"));
    }

    #[test]
    fn ledger_to_text_violations_section() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);
        let text = ledger.to_text();

        assert!(text.contains("VIOLATIONS"));
        assert!(text.contains("[FAIL] task_leak"));
        assert!(text.contains("[FAIL] obligation_leak"));
        assert!(text.contains("[PASS] quiescence"));
    }

    #[test]
    fn ledger_to_text_evidence_lines() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);
        let text = ledger.to_text();

        assert!(text.contains("BF ="));
        assert!(text.contains("log₁₀(BF)"));
    }

    // -- JSON serialization --

    #[test]
    fn ledger_json_roundtrip() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);
        let json = serde_json::to_string(&ledger).unwrap();
        let deserialized: EvidenceLedger = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.entries.len(), ledger.entries.len());
        assert_eq!(
            deserialized.summary.violations_detected,
            ledger.summary.violations_detected
        );
        assert_eq!(deserialized.check_time_nanos, ledger.check_time_nanos);
    }

    #[test]
    fn ledger_to_json_structure() {
        let report = make_clean_report();
        let ledger = EvidenceLedger::from_report(&report);
        let json = ledger.to_json();

        assert!(json["entries"].is_array());
        assert!(json["summary"].is_object());
        assert_eq!(json["summary"]["total_invariants"], 2);
        assert_eq!(json["check_time_nanos"], 42);
    }

    // -- custom detection model --

    #[test]
    fn custom_detection_model() {
        let model = DetectionModel {
            per_entity_detection_rate: 0.5,
            false_positive_rate: 0.01,
        };
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report_with_model(&report, &model);

        // With lower detection rate, BF for violations should be smaller.
        let default_ledger = EvidenceLedger::from_report(&report);
        for (custom, default) in ledger
            .entries
            .iter()
            .zip(default_ledger.entries.iter())
            .filter(|(_, d)| !d.passed)
        {
            assert!(
                custom.bayes_factor.log10_bf < default.bayes_factor.log10_bf,
                "lower detection rate should produce weaker evidence"
            );
        }
    }

    // -- log-likelihood contributions --

    #[test]
    fn log_likelihood_components_sum_to_total() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);

        for entry in &ledger.entries {
            let expected_total = entry.log_likelihoods.structural + entry.log_likelihoods.detection;
            assert!(
                (entry.log_likelihoods.total - expected_total).abs() < 1e-10,
                "total should equal structural + detection"
            );
        }
    }

    // -- integration with OracleSuite --

    #[test]
    fn ledger_from_oracle_suite() {
        let suite = super::super::OracleSuite::new();
        let report = suite.report(crate::types::Time::ZERO);
        let ledger = EvidenceLedger::from_report(&report);

        assert_eq!(ledger.entries.len(), 12);
        assert_eq!(ledger.summary.violations_detected, 0);
        // All should show evidence against violation.
        for entry in &ledger.entries {
            assert!(entry.passed);
            assert_eq!(entry.bayes_factor.strength, EvidenceStrength::Against);
        }
    }

    // -- EvidenceEntry struct --

    #[test]
    fn evidence_entry_fields() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);

        let task_entry = &ledger.entries[0];
        assert_eq!(task_entry.invariant, "task_leak");
        assert!(!task_entry.passed);
        assert!(!task_entry.evidence_lines.is_empty());
        assert!(task_entry.bayes_factor.log10_bf.is_finite());
        assert!(task_entry.log_likelihoods.total.is_finite());
    }

    // -- EvidenceSummary --

    #[test]
    fn evidence_summary_strongest_violation() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);

        // task_leak has 5 entities, obligation_leak has 1 — task_leak should be strongest.
        assert_eq!(
            ledger.summary.strongest_violation.as_deref(),
            Some("task_leak")
        );
    }

    #[test]
    fn evidence_summary_strongest_clean() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);

        assert_eq!(
            ledger.summary.strongest_clean.as_deref(),
            Some("quiescence")
        );
    }
}
