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
            // The BF for the violation hypothesis should stay below 1 for a clean
            // observation, so structural support must reinforce the clean outcome
            // instead of always pushing toward violation.
            let detection = p_h1.log10() - p_h0.log10();
            let structural = -structural_contribution(stats);
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
                        "{} evidence against '{invariant}' violation ({n} entities tracked, oracle saw pass)",
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
#[path = "evidence_inline_tests.rs"]
mod tests;
