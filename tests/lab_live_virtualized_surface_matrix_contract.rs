//! Contract tests for the Phase 2 virtualized-surface coverage matrix
//! (`asupersync-2a6k9.7.4`).
//!
//! Verifies the upstream anchors, shared verification/time vocabulary,
//! surface rows, invalid-experiment rules, downstream bindings, and
//! `rch`-offloaded validation commands.

#![allow(missing_docs)]

use std::path::Path;

fn load_doc() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/lab_live_virtualized_surface_matrix.md");
    std::fs::read_to_string(path).expect("virtualized surface matrix doc must exist")
}

fn load_readme() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md");
    std::fs::read_to_string(path).expect("README must exist")
}

fn load_testing_guide() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("TESTING.md");
    std::fs::read_to_string(path).expect("TESTING guide must exist")
}

#[test]
fn doc_exists_and_is_substantial() {
    let doc = load_doc();
    assert!(
        doc.len() > 10_000,
        "document should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn doc_references_bead_parent_and_upstream_contracts() {
    let doc = load_doc();
    for token in [
        "asupersync-2a6k9.7.4",
        "asupersync-2a6k9.7",
        "asupersync-2a6k9",
        "docs/lab_live_differential_scope_matrix.md",
        "docs/lab_live_verification_taxonomy.md",
        "docs/lab_live_time_normalization_policy.md",
        "docs/lab_live_scenario_adapter_contract.md",
        "docs/lab_live_normalized_observable_schema.md",
        "docs/lab_live_divergence_taxonomy.md",
        "src/lab/dual_run.rs",
        "tests/common/mod.rs",
        "README.md",
        "docs/WASM.md",
    ] {
        assert!(
            doc.contains(token),
            "document missing upstream token: {token}"
        );
    }
}

#[test]
fn doc_reuses_existing_taxonomy_instead_of_inventing_a_new_one() {
    let doc = load_doc();
    for token in [
        "asupersync-2a6k9.6.6",
        "do not invent a second testing language",
        "T0",
        "T1",
        "T2",
        "T3",
        "T4",
        "T5",
        "lab-live-scenario-spec-v1",
        "lab-live-normalized-observable-v1",
        "lab-live-verification-taxonomy-v1",
        "lab-live-time-normalization-v1",
        "semantic_time",
        "qualified_time",
        "scheduler_noise_signal",
        "provenance_only_time",
        "unsupported_time_surface",
    ] {
        assert!(
            doc.contains(token),
            "document missing taxonomy token: {token}"
        );
    }
}

#[test]
fn doc_defines_required_matrix_columns_and_phase2_surface_rows() {
    let doc = load_doc();
    for token in [
        "surface_family",
        "phase",
        "runtime_profile",
        "virtualization_boundary",
        "unit_checks",
        "golden_fixtures",
        "dual_run_scripts",
        "required_log_fields",
        "invalid_experiment_signals",
        "promotion_floor",
        "Phase 2",
        "timer_surface",
        "virtual_transport_surface",
        "http_surface",
        "browser_surface",
    ] {
        assert!(
            doc.contains(token),
            "document missing matrix token: {token}"
        );
    }
}

#[test]
fn doc_requires_machine_readable_log_and_capture_fields() {
    let doc = load_doc();
    for token in [
        "scenario_clock_id",
        "clock_source",
        "logical_deadline_id",
        "timeout_budget_class",
        "timeout_outcome_class",
        "logical_elapsed_ticks",
        "normalization_window",
        "time_policy_class",
        "scheduler_noise_class",
        "suppression_reason",
        "rerun_decision",
        "observability_status",
        "eligibility_verdict",
        "capture_manifest_path",
        "normalized_record_path",
        "artifact_bundle",
        "repro_command",
        "unsupported_reason",
        "host_role",
        "support_class",
        "reason_code",
        "lane_id",
        "CaptureManifest",
        "FieldObservability",
        "LiveRunMetadata",
        "ReplayMetadata",
        "observed",
        "inferred",
        "unsupported",
        "unsupported_fields",
    ] {
        assert!(
            doc.contains(token),
            "document missing log/capture token: {token}"
        );
    }
}

#[test]
fn doc_names_invalid_experiment_and_scope_violation_classes() {
    let doc = load_doc();
    for token in [
        "insufficient_observability",
        "blocked_missing_virtualization",
        "blocked_missing_observability",
        "blocked_missing_verification",
        "blocked_scope_red_line",
        "unsupported_time_surface",
        "policy violation",
        "bridge_only",
        "downgrade_to_server_bridge",
        "unsupported_runtime_context",
    ] {
        assert!(
            doc.contains(token),
            "document missing invalid-experiment token: {token}"
        );
    }
}

#[test]
fn doc_binds_expected_downstream_beads() {
    let doc = load_doc();
    for token in [
        "asupersync-2a6k9.7.1",
        "asupersync-2a6k9.7.2",
        "asupersync-2a6k9.7.3",
        "asupersync-2a6k9.8.1",
        "README.md",
        "docs/WASM.md",
    ] {
        assert!(
            doc.contains(token),
            "document missing downstream binding token: {token}"
        );
    }
}

#[test]
fn readme_indexes_phase2_virtualized_surface_docs() {
    let readme = load_readme();
    for token in [
        "docs/lab_live_differential_scope_matrix.md",
        "docs/lab_live_time_normalization_policy.md",
        "docs/lab_live_virtualized_surface_matrix.md",
        "Lab-vs-Live Differential Scope Matrix",
        "Time + Scheduler-Noise Policy",
        "Phase 2 Virtualized Surface Matrix",
    ] {
        assert!(
            readme.contains(token),
            "README missing Phase 2 differential doc token: {token}"
        );
    }
}

#[test]
fn testing_guide_pins_phase2_virtualized_surface_validation_commands() {
    let testing = load_testing_guide();
    for token in [
        "Phase 2 Differential Policy Docs",
        "docs/lab_live_differential_scope_matrix.md",
        "docs/lab_live_time_normalization_policy.md",
        "docs/lab_live_virtualized_surface_matrix.md",
        "rch exec -- cargo test --test lab_live_time_normalization_policy_contract -- --nocapture",
        "rch exec -- cargo test --test lab_live_virtualized_surface_matrix_contract -- --nocapture",
    ] {
        assert!(
            testing.contains(token),
            "TESTING guide missing Phase 2 virtualized-surface token: {token}"
        );
    }
}

#[test]
fn doc_requires_rch_validation_commands() {
    let doc = load_doc();
    for token in [
        "rch exec -- cargo fmt --check",
        "rch exec -- cargo check --all-targets",
        "rch exec -- cargo clippy --all-targets -- -D warnings",
        "rch exec -- cargo test --test lab_live_virtualized_surface_matrix_contract -- --nocapture",
        "rch exec -- cargo test --test time_e2e -- --nocapture",
        "rch exec -- cargo test --test e2e_transport -- --nocapture",
    ] {
        assert!(
            doc.contains(token),
            "document missing validation command: {token}"
        );
    }
}
