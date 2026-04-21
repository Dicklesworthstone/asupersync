#![allow(clippy::all)]
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
        "artifacts/security_release_gate_events.ndjson",
        "artifacts/wasm_dependency_audit_summary.json",
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
        "artifacts/wasm_optimization_pipeline_summary.json",
        "artifacts/wasm/release/release_traceability.json",
        "artifacts/wasm/release/rollback_safety_report.json",
        "artifacts/wasm/release/incident_response_packet.json",
        "artifacts/wasm_release_rollback_playbook_summary.json",
        "artifacts/npm/package_release_validation.json",
        "artifacts/npm/package_pack_dry_run_summary.json",
        "artifacts/npm/publish_outcome.json",
        "artifacts/onboarding/worker.summary.json",
        "target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json",
        "target/e2e-results/dedicated_worker_consumer/<timestamp>/browser-run.json",
        "target/e2e-results/vite_vanilla_consumer/<timestamp>/summary.json",
        "target/e2e-results/rust_browser_consumer/<timestamp>/summary.json",
        "target/e2e-results/rust_browser_consumer/<timestamp>/browser-run.json",
        "docs/WASM.md",
        "docs/wasm_release_rollback_incident_playbook.md",
        "docs/wasm_release_channel_strategy.md",
        "docs/wasm_troubleshooting_compendium.md",
        "docs/wasm_service_worker_broker_contract.md",
        "docs/wasm_shared_worker_tenancy_lifecycle_contract.md",
        "docs/wasm_flake_governance_and_forensics.md",
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
        "artifacts/onboarding/worker.summary.json",
        "target/e2e-results/wasm_qa_evidence_smoke/run_<timestamp>/summary.json",
        "target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json",
        "target/e2e-results/dedicated_worker_consumer/<timestamp>/browser-run.json",
        "target/e2e-results/rust_browser_consumer/<timestamp>/summary.json",
        "target/e2e-results/rust_browser_consumer/<timestamp>/browser-run.json",
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

#[test]
fn release_docs_define_vnext_surface_promotion_and_packet_rows() {
    let packet = load_packet_doc();
    let strategy = load_release_strategy_doc();

    for token in [
        "GA-VNEXT-01",
        "surface_decisions",
        "support_bucket_snapshot",
        "promotion_ceiling_snapshot",
        "surface_evidence_rows",
        "Dedicated Web Worker",
        "IndexedDB durable storage",
        "BrowserArtifactStore",
        "Rust-authored browser path",
        "WebTransport",
        "Service-worker bounded broker registration + durable handoff",
        "Shared-worker bounded coordinator attach + downgrade",
        "MessageChannel",
        "MessagePort",
        "BroadcastChannel",
        "SharedArrayBuffer",
        "worker offload",
        "preview_only",
        "guarded canary-only",
    ] {
        assert!(
            packet.contains(token),
            "packet doc missing vNext surface governance token: {token}"
        );
    }

    for token in [
        "## VNext Surface Promotion Ceilings",
        "Dedicated Web Worker",
        "`IndexedDB` durable storage + `BrowserArtifactStore`",
        "Rust-authored browser path",
        "`WebTransport` datagrams",
        "Service-worker bounded broker registration + durable handoff",
        "Shared-worker bounded coordinator attach + downgrade",
        "MessageChannel",
        "SharedArrayBuffer",
        "target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json",
        "target/e2e-results/dedicated_worker_consumer/<timestamp>/browser-run.json",
        "target/e2e-results/vite_vanilla_consumer/<timestamp>/summary.json",
        "target/e2e-results/rust_browser_consumer/<timestamp>/summary.json",
        "target/e2e-results/rust_browser_consumer/<timestamp>/browser-run.json",
        "scenario_inventory",
        "service_worker_not_yet_shipped",
        "service_worker_direct_runtime_not_shipped",
        "shared_worker_direct_runtime_not_shipped",
        "preview_only",
        "guarded canary-only",
        "nightly-only",
    ] {
        assert!(
            strategy.contains(token),
            "release strategy doc missing vNext surface promotion token: {token}"
        );
    }
}

#[test]
fn release_strategy_doc_defines_optional_lane_operator_decision_law() {
    let strategy = load_release_strategy_doc();

    for token in [
        "## Optional-Lane Operator Decision Law",
        "support_class",
        "reason_code",
        "fallback_lane_id",
        "lane_health_status",
        "lane_health_failure_count",
        "lane_health_retry_budget_remaining",
        "lane_health_cooldown_until_ms",
        "lane_health_last_trigger",
        "demoted_lane_id",
        "repro_command",
        "policy_schema_version",
        "python3 scripts/check_wasm_worker_offload_policy.py --policy .github/wasm_worker_offload_policy.json",
        "artifacts/wasm_worker_offload_summary.json",
        "python3 scripts/check_wasm_benchmark_corpus.py --policy .github/wasm_benchmark_corpus.json",
        "artifacts/wasm_benchmark_corpus_summary.json",
        "python3 scripts/check_perf_regression.py --budgets .github/wasm_perf_budgets.json --profile core-min",
        "artifacts/wasm_perf_regression_report.json",
        "artifacts/wasm_perf_gate_events.ndjson",
        "rch exec -- ./scripts/run_perf_e2e.sh --bench phase0_baseline --bench scheduler_benchmark --seed 42 --metric p95_ns",
        "rch exec -- bash ./scripts/run_nightly_stress_soak.sh --ci --suites cancellation_stress,scheduler_fairness --timeout 3600",
        "target/nightly-stress/<run_id>/trend_report.json",
        "preview_only",
        "guarded canary-only",
        "nightly-only",
        "shared_array_buffer_requires_cross_origin_isolation",
    ] {
        assert!(
            strategy.contains(token),
            "release strategy doc missing optional-lane operator token: {token}"
        );
    }
}
