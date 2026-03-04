//! WASM GA go/no-go evidence packet enforcement (WASM-17.4 support lane).
//!
//! Ensures the GA decision packet contract is explicit, deterministic, and
//! fail-closed when release-blocking evidence is missing.

use std::path::Path;

fn load_packet_doc() -> String {
    std::fs::read_to_string("docs/wasm_ga_go_no_go_evidence_packet.md")
        .expect("failed to load wasm ga go/no-go evidence packet doc")
}

#[test]
fn packet_doc_exists() {
    assert!(
        Path::new("docs/wasm_ga_go_no_go_evidence_packet.md").exists(),
        "ga go/no-go evidence packet doc must exist"
    );
}

#[test]
fn packet_doc_references_bead_and_contract() {
    let doc = load_packet_doc();
    assert!(
        doc.contains("asupersync-umelq.17.4"),
        "doc must reference bead asupersync-umelq.17.4"
    );
    assert!(
        doc.contains("wasm-ga-go-no-go-evidence-packet-v1"),
        "doc must define contract id"
    );
}

#[test]
fn packet_doc_defines_required_evidence_fields() {
    let doc = load_packet_doc();
    for field in [
        "packet_schema_version",
        "generated_at_utc",
        "decision_state",
        "gate_results",
        "threshold_evaluation",
        "waivers",
        "signoff_roles",
        "unresolved_risks",
        "deterministic_replay_commands",
        "structured_decision_log_pointer",
    ] {
        assert!(
            doc.contains(field),
            "doc missing required evidence field token: {field}"
        );
    }
}

#[test]
fn packet_doc_defines_threshold_and_release_blocking_policy() {
    let doc = load_packet_doc();
    for token in [
        "Mandatory threshold policy",
        "release-blocking",
        "GA-SEC-01",
        "GA-PERF-01",
        "GA-REPLAY-01",
        "GA-OPS-01",
        "GA-LOG-01",
    ] {
        assert!(
            doc.contains(token),
            "doc missing threshold/release-blocking token: {token}"
        );
    }
}

#[test]
fn packet_doc_defines_waiver_and_signoff_rules() {
    let doc = load_packet_doc();
    for token in [
        "Waiver Policy",
        "Runtime Owner",
        "Security Owner",
        "Release Captain",
        "QA/Conformance Owner",
        "Support/Operations Owner",
        "Missing sign-off from any required role forces `NO_GO`",
    ] {
        assert!(
            doc.contains(token),
            "doc missing waiver/signoff token: {token}"
        );
    }
}

#[test]
fn packet_doc_declares_automatic_fail_closed_rules() {
    let doc = load_packet_doc();
    for token in [
        "Automatic Failure Rules",
        "any release-blocking gate status is not `pass`",
        "lacks verifiable `unit_evidence`, `e2e_evidence`, or `logging_evidence`",
        "deterministic replay command bundle is missing",
        "decision must be `NO_GO`",
    ] {
        assert!(
            doc.contains(token),
            "doc missing fail-closed token: {token}"
        );
    }
}

#[test]
fn packet_doc_contains_deterministic_repro_commands_and_rch_usage() {
    let doc = load_packet_doc();
    for command in [
        "rch exec -- cargo test -p asupersync --test wasm_ga_go_no_go_evidence_packet -- --nocapture",
        "rch exec -- cargo test -p asupersync --test wasm_release_rollback_incident_playbook -- --nocapture",
        "rch exec -- cargo test -p asupersync --test wasm_supply_chain_controls -- --nocapture",
        "python3 scripts/check_security_release_gate.py --policy .github/security_release_policy.json --check-deps --dep-policy .github/wasm_dependency_policy.json",
        "python3 scripts/run_browser_onboarding_checks.py --scenario all",
    ] {
        assert!(
            doc.contains(command),
            "doc missing deterministic reproduction command: {command}"
        );
    }
}

#[test]
fn packet_doc_points_to_required_artifact_bundle_and_cross_refs() {
    let doc = load_packet_doc();
    for token in [
        "artifacts/security_release_gate_report.json",
        "artifacts/wasm/release/release_traceability.json",
        "artifacts/wasm/release/rollback_safety_report.json",
        "artifacts/wasm/release/incident_response_packet.json",
        "artifacts/wasm_release_rollback_playbook_summary.json",
        "docs/wasm_release_rollback_incident_playbook.md",
        "docs/wasm_release_channel_strategy.md",
        ".github/workflows/publish.yml",
        ".github/workflows/ci.yml",
    ] {
        assert!(
            doc.contains(token),
            "doc missing artifact/cross-reference token: {token}"
        );
    }
}
