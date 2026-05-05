//! WASM GA readiness review board checklist enforcement (WASM-17.4).
//!
//! Verifies that the GA go/no-go checklist contract exists, references all
//! blocker beads, encodes fail-closed policy, and is wired into CI
//! certification artifacts.

use std::path::Path;

fn load_checklist_doc() -> String {
    std::fs::read_to_string("docs/wasm_ga_readiness_review_board_checklist.md")
        .expect("failed to load wasm GA readiness checklist doc")
}

fn load_ci_workflow() -> String {
    std::fs::read_to_string(".github/workflows/ci.yml").expect("failed to load CI workflow")
}

#[test]
fn checklist_doc_exists() {
    assert!(
        Path::new("docs/wasm_ga_readiness_review_board_checklist.md").exists(),
        "WASM GA readiness checklist doc must exist"
    );
}

#[test]
fn checklist_doc_references_bead_and_contract() {
    let doc = load_checklist_doc();
    assert!(
        doc.contains("asupersync-umelq.17.4"),
        "checklist doc must reference bead asupersync-umelq.17.4"
    );
    assert!(
        doc.contains("wasm-ga-readiness-review-board-checklist-v1"),
        "checklist doc must define contract id"
    );
}

#[test]
fn checklist_doc_references_all_required_blocker_beads() {
    let doc = load_checklist_doc();
    let blockers = [
        "asupersync-umelq.17.2",
        "asupersync-umelq.15.5",
        "asupersync-umelq.14.5",
        "asupersync-umelq.13.5",
        "asupersync-umelq.16.5",
        "asupersync-umelq.12.5",
        "asupersync-umelq.18.10",
    ];
    for blocker in blockers {
        assert!(
            doc.contains(blocker),
            "checklist doc missing blocker bead reference: {blocker}"
        );
    }
}

#[test]
fn checklist_doc_maps_current_browser_release_evidence_lineage() {
    let doc = load_checklist_doc();
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
        "corepack pnpm run validate",
        "bash scripts/validate_package_build.sh",
        "bash scripts/validate_npm_pack_smoke.sh",
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
        "artifacts/onboarding/worker.summary.json",
        "target/e2e-results/wasm_qa_evidence_smoke/run_<timestamp>/summary.json",
        "target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json",
        "target/e2e-results/dedicated_worker_consumer/<timestamp>/browser-run.json",
        "docs/wasm_quickstart_migration.md",
        "docs/wasm_bundler_compatibility_matrix.md",
        "docs/wasm_canonical_examples.md",
        "docs/wasm_troubleshooting_compendium.md",
        "docs/wasm_api_surface_census.md",
        "target/e2e-results/rust_browser_consumer/<timestamp>/summary.json",
        "target/e2e-results/rust_browser_consumer/<timestamp>/browser-run.json",
    ] {
        assert!(
            doc.contains(token),
            "checklist doc missing Browser Edition release token: {token}"
        );
    }
}

#[test]
fn checklist_doc_requires_vnext_surface_review_rows() {
    let doc = load_checklist_doc();
    for token in [
        "## VNext Surface Review Rows",
        "VT-DW-01",
        "VT-STORAGE-01",
        "VT-RUST-01",
        "VT-WT-01",
        "VT-SW-BROKER-01",
        "VT-SHARED-01",
        "VT-MSG-01",
        "VT-SAB-01",
        "Dedicated Web Worker",
        "IndexedDB",
        "BrowserArtifactStore",
        "Rust-authored browser path",
        "WebTransport",
        "Service-worker bounded broker registration + durable handoff",
        "Shared-worker bounded coordinator attach + downgrade",
        "MessageChannel",
        "SharedArrayBuffer",
        "preview_only",
        "guarded canary-only",
        "nightly-only",
        "target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json",
        "target/e2e-results/dedicated_worker_consumer/<timestamp>/browser-run.json",
        "target/e2e-results/vite_vanilla_consumer/<timestamp>/summary.json",
        "target/e2e-results/rust_browser_consumer/<timestamp>/summary.json",
        "target/e2e-results/rust_browser_consumer/<timestamp>/browser-run.json",
        "tests/fixtures/service-worker-broker-consumer/",
        "PATH=/usr/bin:$PATH bash scripts/validate_service_worker_broker_consumer.sh",
        "target/e2e-results/service_worker_broker_consumer/<timestamp>/summary.json",
        "target/e2e-results/service_worker_broker_consumer/<timestamp>/browser-run.json",
        "tests/fixtures/shared-worker-consumer/",
        "PATH=/usr/bin:$PATH bash scripts/validate_shared_worker_consumer.sh",
        "target/e2e-results/shared_worker_consumer/<timestamp>/summary.json",
        "target/e2e-results/shared_worker_consumer/<timestamp>/browser-run.json",
        "scenario_inventory",
        "artifact pointers under `artifacts`",
        "service_worker_not_yet_shipped",
        "service_worker_direct_runtime_not_shipped",
        "shared_worker_direct_runtime_not_shipped",
    ] {
        assert!(
            doc.contains(token),
            "checklist doc missing vNext surface review token: {token}"
        );
    }
}

#[test]
fn checklist_doc_defines_mandatory_evidence_fields() {
    let doc = load_checklist_doc();
    let required_fields = [
        "gate_id",
        "source_bead",
        "artifact_path",
        "generated_at_utc",
        "repro_command",
        "threshold_rule",
        "observed_value",
        "gate_status",
        "owner_role",
        "log_pointer",
        "trace_pointer",
        "waiver_reason",
        "waiver_approver",
        "unresolved_risk_ids",
    ];
    for field in required_fields {
        assert!(
            doc.contains(field),
            "checklist doc missing mandatory evidence field token: {field}"
        );
    }
}

#[test]
fn checklist_doc_defines_required_signoff_roles_and_quorum() {
    let doc = load_checklist_doc();
    let required_roles = [
        "Review Board Chair",
        "Runtime Semantics Lead",
        "Security Lead",
        "Performance Lead",
        "Observability Lead",
        "Release Operations Lead",
        "Support Readiness Lead",
    ];
    for role in required_roles {
        assert!(
            doc.contains(role),
            "checklist doc missing required sign-off role: {role}"
        );
    }

    assert!(
        doc.contains("Minimum quorum"),
        "checklist doc must define quorum policy"
    );
    assert!(
        doc.contains("mandatory participants"),
        "checklist doc must define mandatory participant set"
    );
}

#[test]
fn checklist_doc_encodes_fail_closed_go_no_go_logic() {
    let doc = load_checklist_doc();
    let required = [
        "fail-closed",
        "NO_GO",
        "GO",
        "hard-blocking",
        "aggregate score is",
        ">= 0.90",
    ];
    for token in required {
        assert!(
            doc.contains(token),
            "checklist doc missing fail-closed decision token: {token}"
        );
    }
}

#[test]
fn checklist_doc_defines_waiver_policy_restrictions() {
    let doc = load_checklist_doc();
    let required = [
        "Waiver Policy",
        "Waivers are forbidden",
        "security blockers",
        "missing rollback controls",
        "missing deterministic replay pointers",
        "unresolved critical risks",
    ];
    for token in required {
        assert!(
            doc.contains(token),
            "checklist doc missing waiver policy token: {token}"
        );
    }
}

#[test]
fn checklist_doc_includes_deterministic_rehearsal_commands() {
    let doc = load_checklist_doc();
    let required_commands = [
        "rch exec -- cargo test -p asupersync --test wasm_ga_readiness_review_board_checklist -- --nocapture",
        "rch exec -- cargo test -p asupersync --test wasm_release_rollback_incident_playbook -- --nocapture",
        "python3 scripts/check_security_release_gate.py --policy .github/security_release_policy.json",
        "python3 scripts/check_perf_regression.py --budgets .github/wasm_perf_budgets.json --profile core-min",
    ];
    for command in required_commands {
        assert!(
            doc.contains(command),
            "checklist doc missing deterministic rehearsal command: {command}"
        );
    }
}

#[test]
fn checklist_doc_defines_decision_packet_artifacts_and_schema() {
    let doc = load_checklist_doc();
    let required = [
        "artifacts/wasm_ga_readiness_decision_packet.json",
        "artifacts/wasm_ga_readiness_review_board_test.log",
        "wasm-ga-readiness-decision-packet-v1",
        "decision_status",
        "quorum_satisfied",
        "gate_rows",
        "signoffs",
        "waivers",
        "residual_risks",
        "replay_bundle",
    ];
    for token in required {
        assert!(
            doc.contains(token),
            "checklist doc missing decision packet token: {token}"
        );
    }
}

#[test]
fn ci_workflow_has_ga_review_board_certification_step_and_artifacts() {
    let ci = load_ci_workflow();
    let required = [
        "WASM GA readiness review board certification",
        "cargo test -p asupersync --test wasm_ga_readiness_review_board_checklist -- --nocapture",
        "artifacts/wasm_ga_readiness_review_board_summary.json",
        "artifacts/wasm_ga_readiness_review_board_test.log",
        "wasm-ga-readiness-review-board-certification",
        "wasm-ga-readiness-review-board-certification-v1",
    ];
    for token in required {
        assert!(
            ci.contains(token),
            "ci workflow missing GA readiness certification token: {token}"
        );
    }
}
