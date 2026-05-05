//! WASM Browser Rationale Index Contract Checks (WASM-15).
//!
//! Bead: asupersync-umelq.16.5

#![allow(missing_docs)]

use std::fs;
use std::path::Path;

const DOC_PATH: &str = "docs/wasm_rationale_index.md";

fn load_doc() -> String {
    fs::read_to_string(DOC_PATH).expect("failed to load wasm rationale index")
}

#[test]
fn rationale_doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "Rationale index must exist at {DOC_PATH}"
    );
}

#[test]
fn rationale_doc_references_contract_bead_and_dependencies() {
    let doc = load_doc();
    for token in [
        "wasm-browser-rationale-index-v1",
        "asupersync-umelq.16.5",
        "asupersync-umelq.16.3",
        "asupersync-umelq.16.4",
        "asupersync-umelq.18.3",
    ] {
        assert!(
            doc.contains(token),
            "Rationale index missing required token: {token}"
        );
    }
}

#[test]
fn rationale_doc_contains_decision_register_and_rejected_alternatives() {
    let doc = load_doc();
    for token in [
        "## Decision Register",
        "| Decision ID | Decision | Why | Tradeoff | Rejected Alternatives | Primary Evidence |",
        "## Rejected Alternatives (Global)",
        "BR-DEC-01",
        "BR-DEC-10",
    ] {
        assert!(
            doc.contains(token),
            "Rationale index missing decision/rationale token: {token}"
        );
    }
}

#[test]
fn rationale_doc_contains_validation_bundle_commands() {
    let doc = load_doc();
    let required_commands = [
        "rch exec -- cargo test --test wasm_rationale_index -- --nocapture",
        "python3 scripts/run_browser_onboarding_checks.py --scenario all",
        "bash ./scripts/run_all_e2e.sh --verify-matrix",
        "rch exec -- cargo test --test e2e_log_quality_schema -- --nocapture",
    ];

    let mut missing = Vec::new();
    for command in required_commands {
        if !doc.contains(command) {
            missing.push(command);
        }
    }

    assert!(
        missing.is_empty(),
        "Rationale index missing validation command(s):\n{}",
        missing
            .iter()
            .map(|cmd| format!("  - {cmd}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn rationale_doc_contains_expected_cross_references() {
    let doc = load_doc();
    for doc_ref in [
        "docs/integration.md",
        "docs/wasm_quickstart_migration.md",
        "docs/wasm_canonical_examples.md",
        "docs/wasm_troubleshooting_compendium.md",
        "docs/wasm_flake_governance_and_forensics.md",
        "docs/doctor_logging_contract.md",
        "docs/semantic_adr_decisions.md",
    ] {
        assert!(
            doc.contains(doc_ref),
            "Rationale index missing cross-reference: {doc_ref}"
        );
    }
}
