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
        if effort == 0.0 {
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
#[path = "opportunity_inline_tests.rs"]
mod tests;
