//! WASM Browser Troubleshooting Compendium Contract Checks (WASM-15).
//!
//! Bead: asupersync-umelq.16.4

#![allow(missing_docs)]

use std::fs;
use std::path::Path;

const DOC_PATH: &str = "docs/wasm_troubleshooting_compendium.md";

fn load_doc() -> String {
    fs::read_to_string(DOC_PATH).expect("failed to load wasm troubleshooting compendium")
}

#[test]
fn troubleshooting_doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "Troubleshooting compendium must exist at {DOC_PATH}"
    );
}

#[test]
fn troubleshooting_doc_references_bead_and_contract() {
    let doc = load_doc();
    for token in [
        "asupersync-umelq.16.4",
        "asupersync-3qv04.8.6.3",
        "wasm-browser-troubleshooting-cookbook-v1",
    ] {
        assert!(
            doc.contains(token),
            "Troubleshooting compendium missing required token: {token}"
        );
    }
}

#[test]
fn troubleshooting_doc_contains_symptom_to_action_matrix() {
    let doc = load_doc();
    for token in [
        "## Recipe Matrix",
        "| Symptom | Likely Cause | Run | Expected Evidence |",
    ] {
        assert!(
            doc.contains(token),
            "Troubleshooting compendium missing matrix token: {token}"
        );
    }
}

#[test]
fn troubleshooting_doc_includes_deterministic_command_paths() {
    let doc = load_doc();
    let required_tokens = [
        "python3 scripts/run_browser_onboarding_checks.py --scenario all",
        "python3 scripts/run_browser_onboarding_checks.py --scenario all --dry-run --out-dir artifacts/onboarding",
        "bash ./scripts/run_wasm_qa_evidence_smoke.sh --all --execute",
        "bash ./scripts/run_all_e2e.sh --suite wasm-qa-evidence-smoke",
        "bash ./scripts/run_all_e2e.sh --verify-matrix",
        "python3 scripts/check_wasm_dependency_policy.py",
        "--policy .github/wasm_dependency_policy.json",
        "rch exec -- cargo test --test e2e_log_quality_schema -- --nocapture",
        "rch exec -- cargo test --test wasm_bundler_compatibility -- --nocapture",
        "python3 scripts/check_wasm_flake_governance.py --policy .github/wasm_flake_governance_policy.json",
        "rch exec -- cargo test --test obligation_wasm_parity wasm_full_browser_lifecycle_simulation -- --nocapture",
    ];

    let mut missing = Vec::new();
    for token in required_tokens {
        if !doc.contains(token) {
            missing.push(token);
        }
    }

    assert!(
        missing.is_empty(),
        "Troubleshooting compendium missing deterministic command(s):\n{}",
        missing
            .iter()
            .map(|cmd| format!("  - {cmd}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn troubleshooting_doc_includes_expected_artifacts_and_cross_refs() {
    let doc = load_doc();

    let required_artifacts = [
        "artifacts/onboarding/vanilla.summary.json",
        "artifacts/wasm_bundler_compatibility_summary.json",
        "artifacts/wasm_flake_governance_report.json",
        "artifacts/wasm_flake_governance_events.ndjson",
        "target/wasm-qa-evidence-smoke/<run>/<scenario>/bundle_manifest.json",
        "target/e2e-results/wasm_qa_evidence_smoke/run_<timestamp>/summary.json",
    ];
    for artifact in required_artifacts {
        assert!(
            doc.contains(artifact),
            "Troubleshooting compendium missing expected artifact pointer: {artifact}"
        );
    }

    let required_refs = [
        "docs/integration.md",
        "docs/wasm_quickstart_migration.md",
        "docs/wasm_qa_evidence_matrix_contract.md",
        "docs/wasm_bundler_compatibility_matrix.md",
        "docs/wasm_flake_governance_and_forensics.md",
        "docs/doctor_logging_contract.md",
    ];
    for doc_ref in required_refs {
        assert!(
            doc.contains(doc_ref),
            "Troubleshooting compendium missing cross-reference: {doc_ref}"
        );
    }
}

#[test]
fn troubleshooting_doc_mentions_browser_qa_smoke_ci_lane_contract() {
    let doc = load_doc();
    for token in [
        "wasm-browser-qa-smoke",
        "Browser Edition onboarding command bundle smoke",
        "WASM QA smoke runner (dry-run bundle contract)",
        ".github/workflows/ci.yml",
        ".github/ci_matrix_policy.json",
    ] {
        assert!(
            doc.contains(token),
            "Troubleshooting compendium missing Browser Edition QA smoke token: {token}"
        );
    }
}
