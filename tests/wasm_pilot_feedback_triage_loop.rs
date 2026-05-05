//! WASM Pilot Feedback Triage Loop Contract Checks (WASM-16).
//!
//! Bead: asupersync-umelq.17.3

#![allow(missing_docs)]

use std::fs;
use std::path::Path;

const DOC_PATH: &str = "docs/wasm_pilot_feedback_triage_loop.md";

fn load_doc() -> String {
    fs::read_to_string(DOC_PATH).expect("failed to load wasm pilot feedback triage loop doc")
}

#[test]
fn pilot_feedback_doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "Pilot feedback triage doc must exist at {DOC_PATH}"
    );
}

#[test]
fn pilot_feedback_doc_references_contract_and_dependencies() {
    let doc = load_doc();
    for token in [
        "wasm-pilot-feedback-triage-loop-v1",
        "asupersync-umelq.17.3",
        "asupersync-umelq.17.1",
        "asupersync-umelq.16.5",
    ] {
        assert!(
            doc.contains(token),
            "Pilot feedback triage doc missing required token: {token}"
        );
    }
}

#[test]
fn pilot_feedback_doc_contains_taxonomy_and_scoring_contract() {
    let doc = load_doc();
    for token in [
        "## Triage Taxonomy",
        "| Class ID | Meaning | Severity Weight | Examples |",
        "runtime_correctness",
        "determinism_replay",
        "## Deterministic Prioritization Formula",
        "priority_score =",
        "Tie-breaker order (strict):",
    ] {
        assert!(
            doc.contains(token),
            "Pilot feedback triage doc missing taxonomy/scoring token: {token}"
        );
    }
}

#[test]
fn pilot_feedback_doc_contains_assimilation_and_log_schema() {
    let doc = load_doc();
    for token in [
        "## Roadmap Assimilation Rules",
        "| Score Band | Action | SLA | Expected Owner |",
        "## Decision Log Schema (Required)",
        "linked_bead_id",
        "evidence_artifacts",
        "replay_command",
        "trace_pointer",
    ] {
        assert!(
            doc.contains(token),
            "Pilot feedback triage doc missing assimilation/log token: {token}"
        );
    }
}

#[test]
fn pilot_feedback_doc_contains_deterministic_command_bundle_and_refs() {
    let doc = load_doc();
    let required_commands = [
        "python3 scripts/evaluate_wasm_pilot_cohort.py --self-test",
        "bash scripts/test_wasm_pilot_observability_e2e.sh",
        "bash ./scripts/run_all_e2e.sh --verify-matrix",
        "rch exec -- cargo test --test wasm_pilot_feedback_triage_loop -- --nocapture",
        "sha256sum artifacts/pilot/pilot_observability_summary.json",
    ];

    let mut missing = Vec::new();
    for command in required_commands {
        if !doc.contains(command) {
            missing.push(command);
        }
    }
    assert!(
        missing.is_empty(),
        "Pilot feedback triage doc missing command(s):\n{}",
        missing
            .iter()
            .map(|cmd| format!("  - {cmd}"))
            .collect::<Vec<_>>()
            .join("\n")
    );

    for doc_ref in [
        "docs/wasm_pilot_cohort_rubric.md",
        "docs/wasm_pilot_observability_contract.md",
        "docs/wasm_rationale_index.md",
        "docs/wasm_troubleshooting_compendium.md",
        "docs/integration.md",
    ] {
        assert!(
            doc.contains(doc_ref),
            "Pilot feedback triage doc missing cross-reference: {doc_ref}"
        );
    }
}
