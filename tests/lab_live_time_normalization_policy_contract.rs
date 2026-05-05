//! Contract tests for the lab-vs-live time normalization policy (2a6k9.4.4).
//!
//! Verifies the timing/noise classes, phase policy, report vocabulary,
//! downstream bindings, and `rch`-offloaded validation commands.

#![allow(missing_docs)]

use std::path::Path;

fn load_doc() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/lab_live_time_normalization_policy.md");
    std::fs::read_to_string(path).expect("lab-live time normalization policy must exist")
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
        doc.len() > 8_000,
        "document should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn doc_references_bead_parent_and_upstream_contracts() {
    let doc = load_doc();
    for token in [
        "asupersync-2a6k9.4.4",
        "asupersync-2a6k9.4",
        "asupersync-2a6k9",
        "docs/lab_live_differential_scope_matrix.md",
        "docs/lab_live_normalized_observable_schema.md",
        "docs/lab_live_divergence_taxonomy.md",
        "docs/lab_live_verification_taxonomy.md",
        "docs/lab_live_scenario_adapter_contract.md",
        "src/lab/dual_run.rs",
        "tests/common/mod.rs",
        "LiveRunMetadata",
        "CaptureManifest",
        "ReplayMetadata",
    ] {
        assert!(
            doc.contains(token),
            "document missing upstream dependency token: {token}"
        );
    }
}

#[test]
fn doc_defines_canonical_time_and_noise_classes() {
    let doc = load_doc();
    for token in [
        "semantic_time",
        "qualified_time",
        "provenance_only_time",
        "scheduler_noise_signal",
        "unsupported_time_surface",
    ] {
        assert!(
            doc.contains(token),
            "document missing time/noise class token: {token}"
        );
    }
}

#[test]
fn doc_locks_phase_policy() {
    let doc = load_doc();
    for token in [
        "Phase 1",
        "supported-now",
        "Phase 2",
        "supported-later",
        "scenario-clocked",
        "wall-clock timestamps",
        "schedule_hash",
        "event_hash",
        "nondeterminism_notes",
    ] {
        assert!(
            doc.contains(token),
            "document missing phase-policy token: {token}"
        );
    }
}

#[test]
fn doc_gates_external_surface_timing_claims() {
    let doc = load_doc();
    for token in [
        "Eligibility-Gate Timing Rules for Raw-Socket, HTTP, and Browser Surfaces",
        "raw_socket",
        "http_surface",
        "browser_surface",
        "service-worker lifetime timing",
        "kernel wake ordering",
        "host_role",
        "lane_id",
        "support_class",
        "reason_code",
        "unsupported_time_surface",
    ] {
        assert!(
            doc.contains(token),
            "document missing external-surface timing token: {token}"
        );
    }
}

#[test]
fn doc_defines_field_level_normalization_contract() {
    let doc = load_doc();
    for token in [
        "scenario_clock_id",
        "clock_source",
        "logical_deadline_id",
        "timeout_budget_class",
        "timeout_outcome_class",
        "logical_elapsed_ticks",
        "normalization_window",
        "rerun_interval_class",
        "wall_elapsed_ns",
        "monotonic_start_ns",
        "monotonic_end_ns",
        "now_nanos",
        "steps_delta",
        "suppression_reason",
        "rerun_decision",
    ] {
        assert!(
            doc.contains(token),
            "document missing normalization-field token: {token}"
        );
    }
}

#[test]
fn doc_requires_report_semantics() {
    let doc = load_doc();
    for token in [
        "time_policy_class",
        "scheduler_noise_class",
        "scenario_clock_id",
        "clock_source",
        "normalization_window",
        "suppression_reason",
        "rerun_decision",
        "nondeterminism_notes",
    ] {
        assert!(
            doc.contains(token),
            "document missing report-semantics token: {token}"
        );
    }
}

#[test]
fn doc_defines_rerun_and_qualification_rules() {
    let doc = load_doc();
    for token in [
        "scheduler_noise_suspected",
        "insufficient_observability",
        "runtime_semantic_bug",
        "lab_model_or_mapping_bug",
        "irreproducible_divergence",
        "reruns may help classify time/noise observations",
    ] {
        assert!(
            doc.contains(token),
            "document missing rerun-policy token: {token}"
        );
    }
}

#[test]
fn doc_binds_downstream_beads() {
    let doc = load_doc();
    for token in [
        "asupersync-2a6k9.4.5",
        "asupersync-2a6k9.5.1",
        "asupersync-2a6k9.5.3",
        "asupersync-2a6k9.5.4",
        "asupersync-2a6k9.6.6",
        "asupersync-2a6k9.7.1",
        "asupersync-2a6k9.7.3",
        "asupersync-2a6k9.7.4",
    ] {
        assert!(
            doc.contains(token),
            "document missing downstream binding token: {token}"
        );
    }
}

#[test]
fn readme_and_testing_surface_time_policy_for_phase2_work() {
    let readme = load_readme();
    let testing = load_testing_guide();

    for token in [
        "docs/lab_live_time_normalization_policy.md",
        "Time + Scheduler-Noise Policy",
    ] {
        assert!(
            readme.contains(token),
            "README missing time-normalization policy token: {token}"
        );
    }

    for token in [
        "Phase 2 Differential Policy Docs",
        "docs/lab_live_time_normalization_policy.md",
        "scenario-clock rules",
        "rch exec -- cargo test --test lab_live_time_normalization_policy_contract -- --nocapture",
    ] {
        assert!(
            testing.contains(token),
            "TESTING guide missing time-normalization policy token: {token}"
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
        "rch exec -- cargo test --test lab_live_time_normalization_policy_contract -- --nocapture",
    ] {
        assert!(
            doc.contains(token),
            "document missing validation command: {token}"
        );
    }
}
