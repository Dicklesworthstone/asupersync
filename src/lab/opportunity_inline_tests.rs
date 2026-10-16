    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
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
    fn gate_reject_below_needs_evidence_threshold() {
        // 4 × 0.6 / 3 = 0.8 — below 1.0 - not worthwhile
        let s = OpportunityScore::new(4.0, 0.6, 3.0).unwrap();
        let result = s.evaluate();
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

    #[test]
    fn rejects_tiny_nonzero_effort_as_out_of_range() {
        assert_eq!(
            OpportunityScore::new(3.0, 0.5, f64::EPSILON / 2.0),
            Err(ScoreError::EffortOutOfRange)
        );
        assert_eq!(
            OpportunityScore::new(3.0, 0.5, -f64::EPSILON / 2.0),
            Err(ScoreError::EffortOutOfRange)
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
