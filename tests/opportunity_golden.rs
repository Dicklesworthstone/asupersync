use asupersync::lab::opportunity::{GateDecision, OpportunityScore, SCORE_THRESHOLD};

#[test]
fn opportunity_score_display_golden() {
    // Brackets of the valid input domain.
    let min = OpportunityScore::new(1.0, 0.2, 5.0).unwrap(); // 0.04
    let threshold = OpportunityScore::new(2.0, 1.0, 1.0).unwrap(); // 2.00
    let max = OpportunityScore::new(5.0, 1.0, 1.0).unwrap(); // 5.00
    let rendered = format!("min:       {min}\nthreshold: {threshold}\nmax:       {max}");
    insta::assert_snapshot!(rendered);
}

#[test]
fn gate_result_implement_full_reasons_golden() {
    let result = OpportunityScore::new(3.0, 0.9, 1.0).unwrap().evaluate();
    insta::assert_snapshot!(format!("{result}"));
}

#[test]
fn gate_result_implement_high_confidence_only_golden() {
    let result = OpportunityScore::new(5.0, 1.0, 2.5).unwrap().evaluate();
    insta::assert_snapshot!(format!("{result}"));
}

#[test]
fn gate_result_implement_low_effort_only_golden() {
    let result = OpportunityScore::new(4.0, 0.7, 1.0).unwrap().evaluate();
    insta::assert_snapshot!(format!("{result}"));
}

#[test]
fn gate_result_needs_evidence_both_reasons_golden() {
    let result = OpportunityScore::new(4.0, 0.4, 1.0).unwrap().evaluate();
    insta::assert_snapshot!(format!("{result}"));
}

#[test]
fn gate_result_needs_evidence_high_impact_only_golden() {
    let result = OpportunityScore::new(3.0, 0.6, 1.0).unwrap().evaluate();
    insta::assert_snapshot!(format!("{result}"));
}

#[test]
fn gate_result_needs_evidence_low_confidence_only_golden() {
    let result = OpportunityScore::new(2.0, 0.5, 1.0).unwrap().evaluate();
    insta::assert_snapshot!(format!("{result}"));
}

#[test]
fn gate_result_needs_evidence_minimal_golden() {
    let result = OpportunityScore::new(2.0, 0.8, 1.0).unwrap().evaluate();
    insta::assert_snapshot!(format!("{result}"));
}

#[test]
fn gate_result_reject_both_reasons_golden() {
    let result = OpportunityScore::new(2.0, 0.3, 4.0).unwrap().evaluate();
    insta::assert_snapshot!(format!("{result}"));
}

#[test]
fn gate_result_reject_low_impact_only_golden() {
    let result = OpportunityScore::new(2.0, 0.3, 3.0).unwrap().evaluate();
    insta::assert_snapshot!(format!("{result}"));
}

#[test]
fn gate_result_reject_high_effort_only_golden() {
    let result = OpportunityScore::new(3.0, 0.3, 4.0).unwrap().evaluate();
    insta::assert_snapshot!(format!("{result}"));
}

#[test]
fn gate_result_reject_minimal_golden() {
    let result = OpportunityScore::new(3.0, 0.3, 3.0).unwrap().evaluate();
    insta::assert_snapshot!(format!("{result}"));
}

#[test]
fn perf_gate_docs_example_matrix_golden() {
    let examples = [
        ("Pre-size BinaryHeap lanes  ", (3.0_f64, 0.8_f64, 1.0_f64)),
        ("Arena-backed task nodes    ", (4.0, 0.6, 3.0)),
        ("Intrusive queues           ", (4.0, 0.6, 4.0)),
        ("Reuse steal_batch Vec      ", (2.0, 1.0, 1.0)),
        ("SIMD for RaptorQ GF ops    ", (5.0, 0.4, 3.0)),
    ];
    let mut out = String::new();
    for (label, (i, c, e)) in examples {
        let s = OpportunityScore::new(i, c, e).unwrap();
        let r = s.evaluate();
        out.push_str(&format!("{label} | {s} | decision={}\n", r.decision));
    }
    insta::assert_snapshot!(out);
}
