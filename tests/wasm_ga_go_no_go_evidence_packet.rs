//! WASM GA go/no-go evidence packet enforcement (WASM-17.4 support lane).
//!
//! Ensures the GA decision packet contract is explicit, deterministic, and
//! fail-closed when release-blocking evidence is missing.

use std::path::Path;

fn load_packet_doc() -> String {
    std::fs::read_to_string("docs/wasm_ga_go_no_go_evidence_packet.md")
        .expect("failed to load wasm ga go/no-go evidence packet doc")
}

fn load_release_strategy_doc() -> String {
    std::fs::read_to_string("docs/wasm_release_channel_strategy.md")
        .expect("failed to load wasm release channel strategy doc")
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
        "artifacts/wasm_abi_contract_summary.json",
        "artifacts/wasm_abi_contract_events.ndjson",
        "artifacts/wasm_bundle_size_budget_v1.json",
        "artifacts/wasm_budget_summary.json",
        "artifacts/wasm_packaged_bootstrap_harness_v1.json",
        "artifacts/wasm_packaged_bootstrap_perf_summary.json",
        "artifacts/wasm_packaged_cancellation_harness_v1.json",
        "artifacts/wasm_packaged_cancellation_perf_summary.json",
        "artifacts/wasm_perf_regression_report.json",
        "artifacts/wasm_typescript_package_summary.json",
        "artifacts/wasm_typescript_package_log.ndjson",
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

#[test]
fn packet_doc_binds_browser_release_packet_to_current_artifact_set() {
    let doc = load_packet_doc();
    for token in [
        "asupersync-3qv04.7.3",
        "asupersync-3qv04.6.5",
        "asupersync-3qv04.6.6",
        "asupersync-3qv04.6.7",
        "asupersync-3qv04.6.7.1",
        "asupersync-3qv04.6.7.2",
        "asupersync-3qv04.6.7.3",
        "asupersync-3qv04.6.8",
        "asupersync-3qv04.7.1",
        "asupersync-3qv04.7.2",
        "asupersync-3qv04.8.6",
        "asupersync-3qv04.9.1",
        "asupersync-3qv04.9.2",
        "asupersync-3qv04.9.3",
        "asupersync-3qv04.9.4",
        "asupersync-3qv04.9.5",
        "artifacts/npm/package_release_validation.json",
        "artifacts/npm/package_pack_dry_run_summary.json",
        "artifacts/npm/publish_outcome.json",
        "docs/wasm_browser_sbom_v1.json",
        "docs/wasm_browser_provenance_attestation_v1.json",
        "docs/wasm_browser_artifact_integrity_manifest_v1.json",
        "docs/wasm_abi_compatibility_policy.md",
        "artifacts/wasm_abi_contract_summary.json",
        "artifacts/wasm_abi_contract_events.ndjson",
        "docs/wasm_packaged_bootstrap_harness_contract.md",
        "docs/wasm_packaged_cancellation_harness_contract.md",
        "artifacts/wasm_packaged_bootstrap_harness_v1.json",
        "artifacts/wasm_packaged_cancellation_harness_v1.json",
        ".github/wasm_perf_budgets.json",
        "artifacts/wasm_budget_summary.json",
        "artifacts/wasm_perf_regression_report.json",
        "docs/wasm_bundle_size_budget.md",
        "artifacts/wasm_bundle_size_budget_v1.json",
        "artifacts/wasm_packaged_bootstrap_perf_summary.json",
        "artifacts/wasm_packaged_cancellation_perf_summary.json",
        "docs/wasm_typescript_package_topology.md",
        "artifacts/wasm_typescript_package_summary.json",
        "artifacts/wasm_typescript_package_log.ndjson",
        "artifacts/onboarding/vanilla.summary.json",
        "artifacts/onboarding/react.summary.json",
        "artifacts/onboarding/next.summary.json",
        "target/e2e-results/wasm_qa_evidence_smoke/run_<timestamp>/summary.json",
        "docs/wasm_quickstart_migration.md",
        "docs/wasm_bundler_compatibility_matrix.md",
        "docs/wasm_canonical_examples.md",
        "docs/wasm_troubleshooting_compendium.md",
        "docs/wasm_api_surface_census.md",
    ] {
        assert!(
            doc.contains(token),
            "doc missing Browser Edition release packet token: {token}"
        );
    }
}

#[test]
fn release_strategy_doc_requires_package_and_consumer_artifacts_for_ga_promotion() {
    let doc = load_release_strategy_doc();
    for token in [
        "Gate 6: Packaged release artifact and consumer-build evidence",
        "real packages",
        "consumer builds",
        "real behavioral evidence",
        "corepack pnpm run validate",
        "bash scripts/validate_package_build.sh",
        "bash scripts/validate_npm_pack_smoke.sh",
        "artifacts/npm/package_release_validation.json",
        "artifacts/npm/package_pack_dry_run_summary.json",
        "artifacts/npm/publish_outcome.json",
        "artifacts/onboarding/vanilla.summary.json",
        "artifacts/onboarding/react.summary.json",
        "artifacts/onboarding/next.summary.json",
        "target/wasm-qa-evidence-smoke/<run>/<scenario>/bundle_manifest.json",
        "target/e2e-results/wasm_qa_evidence_smoke/run_<timestamp>/summary.json",
        "Missing any Gate 6 artifact is a release-blocking failure",
    ] {
        assert!(
            doc.contains(token),
            "release strategy doc missing artifact-backed promotion token: {token}"
        );
    }
}
