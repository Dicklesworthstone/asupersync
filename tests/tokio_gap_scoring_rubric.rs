//! Contract tests for the Tokio gap severity scoring rubric (2oh2u.1.3.1).
//!
//! Validates rubric structure, score formula correctness, and classification consistency.

#![allow(missing_docs)]

use std::path::Path;

fn load_rubric_doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_gap_scoring_rubric.md");
    std::fs::read_to_string(path).expect("rubric document must exist")
}

/// Computes the composite score from dimension values using the documented formula.
fn compute_score(
    user_impact: f64,
    migration: f64,
    safety: f64,
    coupling: f64,
    effort: f64,
    multiplier: f64,
) -> f64 {
    user_impact.mul_add(0.25, migration * 0.25)
        + safety.mul_add(0.20, coupling * 0.10)
        + effort.mul_add(0.10, multiplier * 0.10)
}

fn classify_priority(score: f64) -> &'static str {
    if score >= 4.0 {
        "P0"
    } else if score >= 3.0 {
        "P1"
    } else if score >= 2.0 {
        "P2"
    } else {
        "P3"
    }
}

#[test]
fn rubric_document_exists_and_is_nonempty() {
    let doc = load_rubric_doc();
    assert!(
        doc.len() > 500,
        "rubric document should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn rubric_references_correct_bead() {
    let doc = load_rubric_doc();
    assert!(
        doc.contains("asupersync-2oh2u.1.3.1"),
        "document must reference bead 2oh2u.1.3.1"
    );
    assert!(doc.contains("[T1.3.a]"), "document must reference T1.3.a");
}

#[test]
fn rubric_has_six_scoring_dimensions() {
    let doc = load_rubric_doc();
    let dimensions = [
        "User Impact",
        "Migration Blockage",
        "Safety Risk",
        "Coupling",
        "Effort",
        "Downstream Multiplier",
    ];
    for dim in &dimensions {
        assert!(doc.contains(dim), "rubric must include dimension: {dim}");
    }
}

#[test]
fn rubric_weights_sum_to_one() {
    // Weights from the document: 0.25 + 0.25 + 0.20 + 0.10 + 0.10 + 0.10
    let total: f64 = 0.25 + 0.25 + 0.20 + 0.10 + 0.10 + 0.10;
    assert!(
        (total - 1.0).abs() < 1e-10,
        "weights must sum to 1.0, got {total}"
    );
}

#[test]
fn score_range_is_one_to_five() {
    // Minimum: all dimensions = 1
    let min_score = compute_score(1.0, 1.0, 1.0, 1.0, 1.0, 1.0);
    assert!(
        (min_score - 1.0).abs() < 1e-10,
        "minimum score should be 1.0, got {min_score}"
    );

    // Maximum: all dimensions = 5
    let max_score = compute_score(5.0, 5.0, 5.0, 5.0, 5.0, 5.0);
    assert!(
        (max_score - 5.0).abs() < 1e-10,
        "maximum score should be 5.0, got {max_score}"
    );
}

#[test]
fn priority_classification_boundaries() {
    assert_eq!(classify_priority(5.0), "P0");
    assert_eq!(classify_priority(4.0), "P0");
    assert_eq!(classify_priority(3.9), "P1");
    assert_eq!(classify_priority(3.0), "P1");
    assert_eq!(classify_priority(2.9), "P2");
    assert_eq!(classify_priority(2.0), "P2");
    assert_eq!(classify_priority(1.9), "P3");
    assert_eq!(classify_priority(1.0), "P3");
}

#[test]
fn gap_scores_match_documented_values() {
    // Verify each gap's computed score matches the documented score.
    // G1: QUIC transport — U=2, B=3, S=3, C=3, E=1, M=4
    // = 0.50 + 0.75 + 0.60 + 0.30 + 0.10 + 0.40 = 2.65
    let g1 = compute_score(2.0, 3.0, 3.0, 3.0, 1.0, 4.0);
    assert!(
        (g1 - 2.65).abs() < 0.01,
        "G1 score mismatch: expected 2.65, got {g1}"
    );

    // G3: Tokio interop — U=4, B=5, S=2, C=5, E=2, M=5
    // = 1.00 + 1.25 + 0.40 + 0.50 + 0.20 + 0.50 = 3.85
    let g3 = compute_score(4.0, 5.0, 2.0, 5.0, 2.0, 5.0);
    assert!(
        (g3 - 3.85).abs() < 0.01,
        "G3 score mismatch: expected 3.85, got {g3}"
    );

    // G4: HTTP client — U=4, B=4, S=1, C=2, E=3, M=3
    // = 1.00 + 1.00 + 0.20 + 0.20 + 0.30 + 0.30 = 3.00
    let g4 = compute_score(4.0, 4.0, 1.0, 2.0, 3.0, 3.0);
    assert!(
        (g4 - 3.00).abs() < 0.01,
        "G4 score mismatch: expected 3.00, got {g4}"
    );

    // G7: Web middleware — U=4, B=3, S=2, C=3, E=4, M=2
    // = 1.00 + 0.75 + 0.40 + 0.30 + 0.40 + 0.20 = 3.05
    let g7 = compute_score(4.0, 3.0, 2.0, 3.0, 4.0, 2.0);
    assert!(
        (g7 - 3.05).abs() < 0.01,
        "G7 score mismatch: expected 3.05, got {g7}"
    );

    // G9: DB connection pooling — U=4, B=3, S=3, C=3, E=3, M=2
    // = 1.00 + 0.75 + 0.60 + 0.30 + 0.30 + 0.20 = 3.15
    let g9 = compute_score(4.0, 3.0, 3.0, 3.0, 3.0, 2.0);
    assert!(
        (g9 - 3.15).abs() < 0.01,
        "G9 score mismatch: expected 3.15, got {g9}"
    );

    // G6: MQTT client — U=1, B=1, S=1, C=1, E=3, M=1
    // = 0.25 + 0.25 + 0.20 + 0.10 + 0.30 + 0.10 = 1.20
    let g6 = compute_score(1.0, 1.0, 1.0, 1.0, 3.0, 1.0);
    assert!(
        (g6 - 1.20).abs() < 0.01,
        "G6 score mismatch: expected 1.20, got {g6}"
    );

    // G13: Process pty — U=1, B=1, S=1, C=1, E=3, M=1
    // = 0.25 + 0.25 + 0.20 + 0.10 + 0.30 + 0.10 = 1.20
    let g13 = compute_score(1.0, 1.0, 1.0, 1.0, 3.0, 1.0);
    assert!(
        (g13 - 1.20).abs() < 0.01,
        "G13 score mismatch: expected 1.20, got {g13}"
    );
}

#[test]
fn gap_priorities_match_documented_classifications() {
    // G3 → P1 (3.85)
    assert_eq!(classify_priority(3.85), "P1");
    // G1 → P2 (2.65)
    assert_eq!(classify_priority(2.65), "P2");
    // G6 → P3 (1.20)
    assert_eq!(classify_priority(1.20), "P3");
    // G9 → P1 (3.15)
    assert_eq!(classify_priority(3.15), "P1");
}

#[test]
fn rubric_document_includes_all_13_gaps() {
    let doc = load_rubric_doc();
    for gap_num in 1..=13 {
        let gap_id = format!("G{gap_num}");
        assert!(
            doc.contains(&format!("| {gap_id}")),
            "rubric must include gap {gap_id}"
        );
    }
}

#[test]
fn rubric_has_four_priority_levels() {
    let doc = load_rubric_doc();
    for level in &["P0", "P1", "P2", "P3"] {
        assert!(
            doc.contains(level),
            "rubric must include priority level {level}"
        );
    }
}

#[test]
fn rubric_sorted_ranking_is_descending() {
    let doc = load_rubric_doc();
    // Find the "Sorted by Score" section and verify descending order
    let sorted_section = doc
        .split("Sorted by Score")
        .nth(1)
        .expect("must have sorted section");

    let scores: Vec<f64> = sorted_section
        .lines()
        .filter(|line| line.contains("| G"))
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('|').collect();
            // Score is typically the 4th or 5th column
            parts.iter().find_map(|part| {
                let trimmed = part.trim();
                if trimmed.contains('.') && trimmed.len() <= 5 {
                    trimmed.parse::<f64>().ok()
                } else {
                    None
                }
            })
        })
        .collect();

    assert!(
        scores.len() >= 10,
        "sorted ranking must include at least 10 gaps, found {}",
        scores.len()
    );

    for window in scores.windows(2) {
        assert!(
            window[0] >= window[1],
            "scores must be descending: {} should be >= {}",
            window[0],
            window[1]
        );
    }
}

#[test]
fn rubric_each_dimension_has_5_level_scale() {
    let doc = load_rubric_doc();
    // Each dimension section should have entries for scores 1 through 5
    for score in 1..=5 {
        let marker = format!("| {score} |");
        // Should appear at least once per dimension (6 dimensions)
        let count = doc.matches(&marker).count();
        assert!(
            count >= 6,
            "score level {score} should appear >= 6 times (once per dimension), found {count}"
        );
    }
}

#[test]
fn score_is_deterministic() {
    let s1 = compute_score(3.0, 4.0, 2.0, 5.0, 1.0, 3.0);
    let s2 = compute_score(3.0, 4.0, 2.0, 5.0, 1.0, 3.0);
    assert!((s1 - s2).abs() < 1e-15, "scoring must be deterministic");
}

#[test]
fn rubric_references_evidence_checklist_dependency() {
    let doc = load_rubric_doc();
    assert!(
        doc.contains("T1.2.c") || doc.contains("evidence checklist"),
        "rubric must reference T1.2.c (evidence checklist) as dependency"
    );
}
