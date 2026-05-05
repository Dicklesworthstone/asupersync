//! WASM launch rollout/support stabilization enforcement (WASM-17.5).
//!
//! Verifies staged rollout policy, support escalation rules, communication
//! obligations, stabilization exit gates, and CI certification wiring.

use std::path::Path;

fn load_doc() -> String {
    std::fs::read_to_string("docs/wasm_launch_rollout_support_stabilization.md")
        .expect("failed to load launch rollout/support stabilization doc")
}

fn load_ci_workflow() -> String {
    std::fs::read_to_string(".github/workflows/ci.yml").expect("failed to load CI workflow")
}

#[test]
fn rollout_doc_exists() {
    assert!(
        Path::new("docs/wasm_launch_rollout_support_stabilization.md").exists(),
        "rollout/support stabilization doc must exist"
    );
}

#[test]
fn rollout_doc_references_bead_and_contract() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-umelq.17.5"),
        "doc must reference bead asupersync-umelq.17.5"
    );
    assert!(
        doc.contains("wasm-launch-rollout-support-stabilization-v1"),
        "doc must define contract id"
    );
}

#[test]
fn rollout_doc_references_required_upstream_dependencies() {
    let doc = load_doc();
    for token in [
        "asupersync-umelq.17.4",
        "asupersync-umelq.15.5",
        "asupersync-umelq.17.3",
        "asupersync-umelq.16.5",
    ] {
        assert!(
            doc.contains(token),
            "doc missing required dependency token: {token}"
        );
    }
}

#[test]
fn rollout_doc_maps_browser_release_bundle_into_launch_requirements() {
    let doc = load_doc();
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
        "wasm-browser-onboarding-smoke",
        "wasm-qa-smoke-bundles",
        "wasm-qa-smoke-suite-summaries",
        "artifacts/onboarding/vanilla.summary.json",
        "artifacts/onboarding/react.summary.json",
        "artifacts/onboarding/next.summary.json",
        "artifacts/onboarding/worker.summary.json",
        "target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json",
        "target/e2e-results/dedicated_worker_consumer/<timestamp>/browser-run.json",
        "target/e2e-results/wasm_qa_evidence_smoke/run_<timestamp>/summary.json",
        "docs/wasm_quickstart_migration.md",
        "docs/wasm_bundler_compatibility_matrix.md",
        "docs/wasm_canonical_examples.md",
        "docs/wasm_troubleshooting_compendium.md",
        "docs/wasm_api_surface_census.md",
        "target/e2e-results/rust_browser_consumer/<timestamp>/summary.json",
        "target/e2e-results/rust_browser_consumer/<timestamp>/browser-run.json",
        "wasm-ga-readiness-review-board-certification",
        "wasm-launch-rollout-support-stabilization-certification",
    ] {
        assert!(
            doc.contains(token),
            "doc missing Browser Edition rollout token: {token}"
        );
    }
}

#[test]
fn rollout_doc_defines_vnext_surface_stage_ceilings() {
    let doc = load_doc();
    for token in [
        "## Surface-Specific Rollout Floors and Ceilings",
        "Dedicated Web Worker",
        "`IndexedDB` durable storage + `BrowserArtifactStore`",
        "Rust-authored browser path",
        "`WebTransport` datagrams",
        "Service-worker bounded broker registration + durable handoff",
        "Shared-worker bounded coordinator attach + downgrade",
        "MessageChannel",
        "SharedArrayBuffer",
        "L0_INTERNAL",
        "L1_PILOT",
        "L2_CANARY",
        "L3_GA",
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
        "LR-06",
        "LR-07",
    ] {
        assert!(
            doc.contains(token),
            "rollout doc missing vNext surface stage token: {token}"
        );
    }
}

#[test]
fn rollout_doc_defines_stages_guardrails_and_comm_obligations() {
    let doc = load_doc();
    for token in [
        "L0_INTERNAL",
        "L1_PILOT",
        "L2_CANARY",
        "L3_GA",
        "L4_STABILIZATION",
        "Entry Criteria",
        "Exit Criteria",
        "Communication Obligation",
    ] {
        assert!(
            doc.contains(token),
            "doc missing rollout stage/guardrail token: {token}"
        );
    }
}

#[test]
fn rollout_doc_defines_rollback_triggers_and_policy_linkage() {
    let doc = load_doc();
    for token in [
        "LR-01",
        "LR-02",
        "LR-03",
        "LR-04",
        "LR-05",
        "docs/wasm_release_rollback_incident_playbook.md",
    ] {
        assert!(doc.contains(token), "doc missing rollback token: {token}");
    }
}

#[test]
fn rollout_doc_defines_support_roles_and_escalation_slas() {
    let doc = load_doc();
    for token in [
        "Launch Commander",
        "Support Lead",
        "Incident Commander",
        "Runtime On-Call Engineer",
        "Security On-Call",
        "Communications Lead",
        "Tier-1 support triages incoming incidents in <= 30 minutes",
        "Tier-2 engineering response in <= 60 minutes",
    ] {
        assert!(
            doc.contains(token),
            "doc missing support/escalation token: {token}"
        );
    }
}

#[test]
fn rollout_doc_defines_incident_communication_cadence() {
    let doc = load_doc();
    for token in [
        "incident updates at fixed cadence",
        "30m",
        "60m",
        "release-notes",
        "incident-updates",
        "status page",
    ] {
        assert!(
            doc.contains(token),
            "doc missing communication cadence token: {token}"
        );
    }
}

#[test]
fn rollout_doc_includes_deterministic_rehearsal_commands() {
    let doc = load_doc();
    for command in [
        "rch exec -- cargo test -p asupersync --test wasm_launch_rollout_support_stabilization -- --nocapture",
        "rch exec -- cargo test -p asupersync --test wasm_ga_readiness_review_board_checklist -- --nocapture",
        "rch exec -- cargo test -p asupersync --test wasm_release_rollback_incident_playbook -- --nocapture",
        "rch exec -- cargo test -p asupersync --test wasm_pilot_feedback_triage_loop -- --nocapture",
    ] {
        assert!(
            doc.contains(command),
            "doc missing rehearsal command: {command}"
        );
    }
}

#[test]
fn rollout_doc_defines_structured_logging_and_stabilization_exit_criteria() {
    let doc = load_doc();
    for token in [
        "artifacts/wasm_launch_rollout_support_stabilization_summary.json",
        "artifacts/wasm_launch_rollout_support_stabilization_test.log",
        "launch_stage",
        "incident_id",
        "user_impact_scope",
        "stabilization_gate",
        "30 consecutive days",
        "replay-backed postmortem closure",
        "Support SLA adherence >= 99%",
    ] {
        assert!(
            doc.contains(token),
            "doc missing structured logging/stabilization token: {token}"
        );
    }
}

#[test]
fn ci_workflow_has_rollout_support_certification_step_and_artifacts() {
    let ci = load_ci_workflow();
    let required = [
        "WASM launch rollout and support stabilization certification",
        "cargo test -p asupersync --test wasm_launch_rollout_support_stabilization -- --nocapture",
        "artifacts/wasm_launch_rollout_support_stabilization_summary.json",
        "artifacts/wasm_launch_rollout_support_stabilization_test.log",
        "wasm-launch-rollout-support-stabilization-certification",
        "wasm-launch-rollout-support-stabilization-certification-v1",
    ];
    for token in required {
        assert!(
            ci.contains(token),
            "ci workflow missing rollout/support certification token: {token}"
        );
    }
}
