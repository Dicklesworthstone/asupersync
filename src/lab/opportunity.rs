//! Opportunity scoring and performance PR gate logic.
//!
//! Implements the opportunity matrix scoring formula from
//! `docs/benchmarking.md` as a Rust type so the gate logic can be
//! unit-tested and reused by CLI tooling.
//!
//! # Scoring Formula
//!
//! ```text
//! Score = (Impact × Confidence) / Effort
//! ```
//!
//! | Factor | Range | Description |
//! |--------|-------|-------------|
//! | Impact | 1–5 | Expected improvement (1 = <5%, 5 = >50%) |
//! | Confidence | 0.2–1.0 | Evidence level (0.2 = speculative, 1.0 = certain) |
//! | Effort | 1–5 | Implementation cost (1 = trivial, 5 = major) |
//!
//! # Gate Decision
//!
//! Performance PRs must satisfy:
//!
//! 1. Score ≥ 2.0 (the "implement" threshold)
//! 2. Isomorphism proof section present
//! 3. Baseline metrics present (p50, p99)
//! 4. One Lever Rule documented
//!
//! See `.github/workflows/perf-pr-check.yml` for the CI enforcement.

/// Opportunity score factors for a performance optimization proposal.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OpportunityScore {
    /// Expected performance improvement magnitude (1–5).
    pub impact: f64,
    /// Confidence in the estimate based on evidence (0.2–1.0).
    pub confidence: f64,
    /// Implementation effort (1–5).
    pub effort: f64,
}

/// Score threshold for "implement" decision.
pub const SCORE_THRESHOLD: f64 = 2.0;

/// Decision from the perf gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDecision {
    /// Score meets threshold — implement the optimization.
    Implement,
    /// Score is promising but below threshold — gather more evidence.
    NeedsEvidence,
    /// Score is too low — not worthwhile.
    Reject,
}

/// Structured gate result with decision path for CI logging.
#[derive(Debug, Clone, PartialEq)]
pub struct GateResult {
    /// The computed opportunity score.
    pub score: f64,
    /// The gate decision.
    pub decision: GateDecision,
    /// Structured reasons for the decision.
    pub reasons: Vec<&'static str>,
}

/// Validation errors for opportunity score inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreError {
    /// Impact must be in [1, 5].
    ImpactOutOfRange,
    /// Confidence must be in [0.2, 1.0].
    ConfidenceOutOfRange,
    /// Effort must be in [1, 5].
    EffortOutOfRange,
    /// Effort must not be zero (division by zero).
    ZeroEffort,
}

impl OpportunityScore {
    /// Creates a new score, validating inputs.
    pub fn new(impact: f64, confidence: f64, effort: f64) -> Result<Self, ScoreError> {
        if effort.abs() < f64::EPSILON {
            return Err(ScoreError::ZeroEffort);
        }
        if !(1.0..=5.0).contains(&impact) {
            return Err(ScoreError::ImpactOutOfRange);
        }
        if !(0.2..=1.0).contains(&confidence) {
            return Err(ScoreError::ConfidenceOutOfRange);
        }
        if !(1.0..=5.0).contains(&effort) {
            return Err(ScoreError::EffortOutOfRange);
        }
        Ok(Self {
            impact,
            confidence,
            effort,
        })
    }

    /// Computes the opportunity score: `(Impact × Confidence) / Effort`.
    #[must_use]
    pub fn score(&self) -> f64 {
        (self.impact * self.confidence) / self.effort
    }

    /// Evaluates the perf gate and returns a structured decision.
    #[must_use]
    pub fn evaluate(&self) -> GateResult {
        let score = self.score();
        let mut reasons = Vec::new();

        let decision = if score >= SCORE_THRESHOLD {
            reasons.push("score meets threshold (>= 2.0)");
            if self.confidence >= 0.8 {
                reasons.push("high confidence from profiling evidence");
            }
            if self.effort <= 2.0 {
                reasons.push("low implementation effort");
            }
            GateDecision::Implement
        } else if score >= 1.0 {
            reasons.push("score below threshold but promising (1.0–2.0)");
            if self.confidence < 0.6 {
                reasons.push("needs profiling data to increase confidence");
            }
            if self.impact >= 3.0 {
                reasons.push("high potential impact justifies further investigation");
            }
            GateDecision::NeedsEvidence
        } else {
            reasons.push("score below 1.0 — not worthwhile");
            if self.impact <= 2.0 {
                reasons.push("low expected impact");
            }
            if self.effort >= 4.0 {
                reasons.push("high implementation effort relative to gain");
            }
            GateDecision::Reject
        };

        GateResult {
            score,
            decision,
            reasons,
        }
    }
}

impl core::fmt::Display for OpportunityScore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Impact={:.1} × Confidence={:.1} / Effort={:.1} = {:.2}",
            self.impact,
            self.confidence,
            self.effort,
            self.score()
        )
    }
}

impl core::fmt::Display for GateDecision {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Implement => write!(f, "IMPLEMENT"),
            Self::NeedsEvidence => write!(f, "NEEDS_EVIDENCE"),
            Self::Reject => write!(f, "REJECT"),
        }
    }
}

impl core::fmt::Display for GateResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "score={:.2} decision={}", self.score, self.decision)?;
        for reason in &self.reasons {
            write!(f, " reason=\"{reason}\"")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Scoring Formula Tests
    // =========================================================================

    #[test]
    fn score_basic_formula() {
        // Impact=3, Confidence=0.8, Effort=1 → 3×0.8/1 = 2.4
        let s = OpportunityScore::new(3.0, 0.8, 1.0).unwrap();
        let score = s.score();
        assert!((score - 2.4).abs() < 1e-9, "expected 2.4, got {score}");
    }

    #[test]
    fn score_examples_from_docs() {
        // Pre-size BinaryHeap lanes: 3 × 0.8 / 1 = 2.4
        let s = OpportunityScore::new(3.0, 0.8, 1.0).unwrap();
        assert!((s.score() - 2.4).abs() < 1e-9);

        // Arena-backed task nodes: 4 × 0.6 / 3 = 0.8
        let s = OpportunityScore::new(4.0, 0.6, 3.0).unwrap();
        assert!((s.score() - 0.8).abs() < 1e-9);

        // Intrusive queues: 4 × 0.6 / 4 = 0.6
        let s = OpportunityScore::new(4.0, 0.6, 4.0).unwrap();
        assert!((s.score() - 0.6).abs() < 1e-9);

        // Reuse steal_batch Vec: 2 × 1.0 / 1 = 2.0
        let s = OpportunityScore::new(2.0, 1.0, 1.0).unwrap();
        assert!((s.score() - 2.0).abs() < 1e-9);

        // SIMD for RaptorQ GF ops: 5 × 0.4 / 3 ≈ 0.667
        let s = OpportunityScore::new(5.0, 0.4, 3.0).unwrap();
        assert!((s.score() - 2.0 / 3.0).abs() < 1e-9);
    }

    // =========================================================================
    // Gate Decision Tests
    // =========================================================================

    #[test]
    fn gate_implement_when_above_threshold() {
        let s = OpportunityScore::new(3.0, 0.8, 1.0).unwrap();
        let result = s.evaluate();
        assert_eq!(result.decision, GateDecision::Implement);
        assert!(result.score >= SCORE_THRESHOLD);
    }

    #[test]
    fn gate_implement_at_exact_threshold() {
        // 2 × 1.0 / 1 = 2.0 — exactly at threshold
        let s = OpportunityScore::new(2.0, 1.0, 1.0).unwrap();
        let result = s.evaluate();
        assert_eq!(result.decision, GateDecision::Implement);
    }

    #[test]
    fn gate_needs_evidence_below_threshold() {
        // 4 × 0.6 / 3 = 0.8 — below threshold but promising
        let s = OpportunityScore::new(4.0, 0.6, 3.0).unwrap();
        let result = s.evaluate();
        // 0.8 < 1.0, so it's actually Reject
        assert_eq!(result.decision, GateDecision::Reject);
    }

    #[test]
    fn gate_needs_evidence_mid_range() {
        // 3 × 0.5 / 1 = 1.5 — between 1.0 and 2.0
        let s = OpportunityScore::new(3.0, 0.5, 1.0).unwrap();
        let result = s.evaluate();
        assert_eq!(result.decision, GateDecision::NeedsEvidence);
    }

    #[test]
    fn gate_reject_low_score() {
        // 1 × 0.2 / 5 = 0.04
        let s = OpportunityScore::new(1.0, 0.2, 5.0).unwrap();
        let result = s.evaluate();
        assert_eq!(result.decision, GateDecision::Reject);
        assert!(result.score < 1.0);
    }

    // =========================================================================
    // Decision Path (Structured Logging) Tests
    // =========================================================================

    #[test]
    fn gate_result_includes_reasons() {
        let s = OpportunityScore::new(3.0, 0.9, 1.0).unwrap();
        let result = s.evaluate();
        assert!(!result.reasons.is_empty());
        assert!(result.reasons.contains(&"score meets threshold (>= 2.0)"));
        assert!(
            result
                .reasons
                .contains(&"high confidence from profiling evidence")
        );
        assert!(result.reasons.contains(&"low implementation effort"));
    }

    #[test]
    fn gate_result_needs_evidence_reasons() {
        let s = OpportunityScore::new(4.0, 0.4, 1.0).unwrap();
        // 4 × 0.4 / 1 = 1.6 → NeedsEvidence
        let result = s.evaluate();
        assert_eq!(result.decision, GateDecision::NeedsEvidence);
        assert!(
            result
                .reasons
                .contains(&"needs profiling data to increase confidence")
        );
        assert!(
            result
                .reasons
                .contains(&"high potential impact justifies further investigation")
        );
    }

    #[test]
    fn gate_result_reject_reasons() {
        let s = OpportunityScore::new(2.0, 0.3, 4.0).unwrap();
        // 2 × 0.3 / 4 = 0.15 → Reject
        let result = s.evaluate();
        assert_eq!(result.decision, GateDecision::Reject);
        assert!(result.reasons.contains(&"low expected impact"));
        assert!(
            result
                .reasons
                .contains(&"high implementation effort relative to gain")
        );
    }

    #[test]
    fn gate_result_display_is_structured() {
        let s = OpportunityScore::new(3.0, 0.8, 1.0).unwrap();
        let result = s.evaluate();
        let display = format!("{result}");
        assert!(display.contains("score=2.40"));
        assert!(display.contains("decision=IMPLEMENT"));
        assert!(display.contains("reason="));
    }

    // =========================================================================
    // Input Validation Tests
    // =========================================================================

    #[test]
    fn rejects_impact_out_of_range() {
        assert_eq!(
            OpportunityScore::new(0.5, 0.5, 1.0),
            Err(ScoreError::ImpactOutOfRange)
        );
        assert_eq!(
            OpportunityScore::new(6.0, 0.5, 1.0),
            Err(ScoreError::ImpactOutOfRange)
        );
    }

    #[test]
    fn rejects_confidence_out_of_range() {
        assert_eq!(
            OpportunityScore::new(3.0, 0.1, 1.0),
            Err(ScoreError::ConfidenceOutOfRange)
        );
        assert_eq!(
            OpportunityScore::new(3.0, 1.1, 1.0),
            Err(ScoreError::ConfidenceOutOfRange)
        );
    }

    #[test]
    fn rejects_effort_out_of_range() {
        assert_eq!(
            OpportunityScore::new(3.0, 0.5, 0.5),
            Err(ScoreError::EffortOutOfRange)
        );
        assert_eq!(
            OpportunityScore::new(3.0, 0.5, 6.0),
            Err(ScoreError::EffortOutOfRange)
        );
    }

    #[test]
    fn rejects_zero_effort() {
        assert_eq!(
            OpportunityScore::new(3.0, 0.5, 0.0),
            Err(ScoreError::ZeroEffort)
        );
    }

    // =========================================================================
    // Monotonicity Properties
    // =========================================================================

    #[test]
    fn score_increases_with_impact() {
        let lo = OpportunityScore::new(1.0, 0.8, 2.0).unwrap();
        let hi = OpportunityScore::new(5.0, 0.8, 2.0).unwrap();
        assert!(hi.score() > lo.score());
    }

    #[test]
    fn score_increases_with_confidence() {
        let lo = OpportunityScore::new(3.0, 0.2, 2.0).unwrap();
        let hi = OpportunityScore::new(3.0, 1.0, 2.0).unwrap();
        assert!(hi.score() > lo.score());
    }

    #[test]
    fn score_decreases_with_effort() {
        let lo = OpportunityScore::new(3.0, 0.8, 1.0).unwrap();
        let hi = OpportunityScore::new(3.0, 0.8, 5.0).unwrap();
        assert!(lo.score() > hi.score());
    }

    // =========================================================================
    // Boundary Cases
    // =========================================================================

    #[test]
    fn max_score() {
        // 5 × 1.0 / 1 = 5.0
        let s = OpportunityScore::new(5.0, 1.0, 1.0).unwrap();
        assert!((s.score() - 5.0).abs() < 1e-9);
        assert_eq!(s.evaluate().decision, GateDecision::Implement);
    }

    #[test]
    fn min_score() {
        // 1 × 0.2 / 5 = 0.04
        let s = OpportunityScore::new(1.0, 0.2, 5.0).unwrap();
        assert!(s.score() < 0.05);
        assert_eq!(s.evaluate().decision, GateDecision::Reject);
    }

    #[test]
    fn opportunity_score_debug_clone_copy_eq() {
        let s = OpportunityScore::new(3.0, 0.8, 2.0).unwrap();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("OpportunityScore"), "{dbg}");
        let copied: OpportunityScore = s;
        let cloned = s;
        assert_eq!(copied, cloned);
    }

    #[test]
    fn gate_decision_debug_clone_copy_eq() {
        let d = GateDecision::Implement;
        let dbg = format!("{d:?}");
        assert!(dbg.contains("Implement"), "{dbg}");
        let copied: GateDecision = d;
        let cloned = d;
        assert_eq!(copied, cloned);
        assert_ne!(d, GateDecision::Reject);
    }

    #[test]
    fn gate_result_debug_clone_eq() {
        let s = OpportunityScore::new(4.0, 0.9, 1.0).unwrap();
        let r = s.evaluate();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("GateResult"), "{dbg}");
        let cloned = r.clone();
        assert_eq!(r, cloned);
    }

    #[test]
    fn score_error_debug_clone_copy_eq() {
        let e = ScoreError::ImpactOutOfRange;
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ImpactOutOfRange"), "{dbg}");
        let copied: ScoreError = e;
        let cloned = e;
        assert_eq!(copied, cloned);
        assert_ne!(e, ScoreError::ZeroEffort);
    }
}
