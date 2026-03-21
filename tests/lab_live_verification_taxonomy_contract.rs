//! Contract tests for the lab-vs-live verification taxonomy (2a6k9.1.4).
//!
//! Verifies the tier vocabulary, minimum coverage matrix, structured logging
//! field set, downstream bindings, and `rch`-offloaded validation policy.

#![allow(missing_docs)]

use std::path::Path;

fn load_doc() -> std::io::Result<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/lab_live_verification_taxonomy.md");
    std::fs::read_to_string(path)
}

fn load_divergence_doc() -> std::io::Result<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/lab_live_divergence_taxonomy.md");
    std::fs::read_to_string(path)
}

#[test]
fn doc_exists_and_is_substantial() -> std::io::Result<()> {
    let doc = load_doc()?;
    assert!(
        doc.len() > 8_000,
        "document should be substantial, got {} bytes",
        doc.len()
    );
    Ok(())
}

#[test]
fn doc_references_bead_parent_and_upstream_contracts() -> std::io::Result<()> {
    let doc = load_doc()?;
    for token in [
        "asupersync-2a6k9.1.4",
        "asupersync-2a6k9.1",
        "asupersync-2a6k9",
        "docs/lab_live_differential_scope_matrix.md",
        "docs/lab_live_normalized_observable_schema.md",
        "docs/lab_live_divergence_taxonomy.md",
        "docs/lab_live_scenario_adapter_contract.md",
        "docs/tokio_differential_behavior_suites.md",
        "TESTING.md",
        "tests/common/mod.rs",
    ] {
        assert!(
            doc.contains(token),
            "document missing upstream contract token: {token}"
        );
    }
    Ok(())
}

#[test]
fn doc_defines_taxonomy_tiers() -> std::io::Result<()> {
    let doc = load_doc()?;
    for token in [
        "T0",
        "unit_contract",
        "T1",
        "golden_fixture",
        "T2",
        "dual_run_smoke",
        "T3",
        "pilot_surface",
        "T4",
        "negative_control",
        "T5",
        "stress_nightly",
    ] {
        assert!(
            doc.contains(token),
            "document missing taxonomy tier token: {token}"
        );
    }
    Ok(())
}

#[test]
fn doc_defines_minimum_bead_class_requirements() -> std::io::Result<()> {
    let doc = load_doc()?;
    for token in [
        "Policy or Contract Beads",
        "Shared Harness or Helper Beads",
        "Live Evidence, Normalizer, and Comparator Beads",
        "Pilot Surface Beads",
        "Expansion, Eligibility, and Operations Beads",
    ] {
        assert!(
            doc.contains(token),
            "document missing bead-class section: {token}"
        );
    }
    Ok(())
}

#[test]
fn doc_locks_phase1_surface_coverage_matrix() -> std::io::Result<()> {
    let doc = load_doc()?;
    for token in [
        "cancellation -> combinators -> channels -> obligations -> region close/quiescence",
        "cancellation",
        "combinators",
        "channels",
        "obligations",
        "region_close",
        "quiescence",
    ] {
        assert!(
            doc.contains(token),
            "document missing phase-1 coverage token: {token}"
        );
    }
    Ok(())
}

#[test]
fn doc_refines_phase1_matrix_for_core_pilot_bead() -> std::io::Result<()> {
    let doc = load_doc()?;
    for token in [
        "Core Pilot Refinement Matrix (`asupersync-2a6k9.6.6`)",
        "cancel_before_first_poll",
        "cancel_during_cleanup_budget",
        "missing_cleanup_ack_hard_failure",
        "join_loser_drain",
        "race_winner_commit_boundary",
        "loser_not_drained_hard_failure",
        "reserve_abort_invisible_to_receiver",
        "committed_message_missing_hard_failure",
        "balanced_after_commit_and_abort",
        "leaked_obligation_forces_failure",
        "close_with_nested_children",
        "late_spawn_after_close_rejected",
        "stuck_finalizer_retained",
        "every Phase 1 pilot surface must name at least one concrete scenario family",
    ] {
        assert!(
            doc.contains(token),
            "document missing refined phase-1 matrix token: {token}"
        );
    }
    Ok(())
}

#[test]
fn doc_defines_external_surface_gate_requirements() -> std::io::Result<()> {
    let doc = load_doc()?;
    for token in [
        "Eligibility-Gate Matrix for External Surfaces",
        "raw_socket",
        "http_surface",
        "browser_surface",
        "eligibility_verdict",
        "virtualization_boundary",
        "observability_status",
        "capture_manifest_path",
        "unsupported_reason",
        "host_role",
        "support_class",
        "reason_code",
        "lane_id",
    ] {
        assert!(
            doc.contains(token),
            "document missing external-surface gate token: {token}"
        );
    }
    Ok(())
}

#[test]
fn doc_requires_structured_logging_vocabulary() -> std::io::Result<()> {
    let doc = load_doc()?;
    for token in [
        "schema_version",
        "suite_id",
        "scenario_id",
        "surface_id",
        "surface_contract_version",
        "seed_lineage_id",
        "runtime_kind",
        "runner_profile",
        "adapter",
        "attempt_index",
        "rerun_count",
        "divergence_class",
        "policy_class",
        "normalized_record_path",
        "artifact_bundle",
        "repro_command",
        "terminal_outcome",
        "loser_drain",
        "obligation_balance",
    ] {
        assert!(
            doc.contains(token),
            "document missing structured logging token: {token}"
        );
    }
    Ok(())
}

#[test]
fn doc_requires_bundle_file_names() -> std::io::Result<()> {
    let doc = load_doc()?;
    for token in [
        "differential_summary.json",
        "differential_event_log.jsonl",
        "differential_failures.json",
        "differential_deviations.json",
        "differential_repro_manifest.json",
        "lab_normalized.json",
        "live_normalized.json",
    ] {
        assert!(
            doc.contains(token),
            "document missing artifact bundle token: {token}"
        );
    }
    Ok(())
}

#[test]
fn doc_binds_downstream_beads() -> std::io::Result<()> {
    let doc = load_doc()?;
    for token in [
        "asupersync-2a6k9.2.2",
        "asupersync-2a6k9.2.5",
        "asupersync-2a6k9.4.5",
        "asupersync-2a6k9.5.4",
        "asupersync-2a6k9.5.5",
        "asupersync-2a6k9.6.6",
        "asupersync-2a6k9.7.3",
        "asupersync-2a6k9.8.*",
    ] {
        assert!(
            doc.contains(token),
            "document missing downstream binding token: {token}"
        );
    }
    Ok(())
}

#[test]
fn doc_requires_rch_validation_commands() -> std::io::Result<()> {
    let doc = load_doc()?;
    for token in [
        "rch exec -- cargo fmt --check",
        "rch exec -- cargo check --all-targets",
        "rch exec -- cargo clippy --all-targets -- -D warnings",
        "rch exec -- cargo test --test lab_live_verification_taxonomy_contract -- --nocapture",
    ] {
        assert!(
            doc.contains(token),
            "document missing validation command: {token}"
        );
    }
    Ok(())
}

#[test]
fn divergence_doc_defines_registry_schema_and_lifecycle() -> std::io::Result<()> {
    let doc = load_divergence_doc()?;
    for token in [
        "lab-live-divergence-corpus-v1",
        "entry_id",
        "first_seen.runner_profile",
        "minimization_lineage",
        "artifact_bundle",
        "failure_artifacts",
        "normalized_record_path",
        "crashpack_link",
        "repro_commands",
        "promoted_scenario_id",
        "regression_promotion_state",
        "investigating",
        "minimized",
        "promoted_regression",
        "known_open",
        "rejected",
        "retention.bundle_level",
        "retention.local_retention_days",
        "retention.ci_retention_days",
        "retention.redaction_mode",
    ] {
        assert!(
            doc.contains(token),
            "divergence taxonomy missing registry token: {token}"
        );
    }
    Ok(())
}

#[test]
fn differential_runner_script_exists_and_uses_rch_cli_surface() -> std::io::Result<()> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/run_lab_live_differential.sh");
    let script = std::fs::read_to_string(path)?;
    for token in [
        "target/debug/asupersync",
        "lab differential \"$@\"",
        "rch exec -- cargo run --features cli --bin asupersync -- lab differential",
    ] {
        assert!(
            script.contains(token),
            "differential runner script missing token: {token}"
        );
    }
    Ok(())
}

#[test]
fn cli_source_defines_differential_runner_surface() -> std::io::Result<()> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/asupersync.rs");
    let src = std::fs::read_to_string(path)?;
    for token in [
        "LabCommand::Differential",
        "struct LabDifferentialArgs",
        "run_lab_differential(args)",
        "differential_event_log.jsonl",
        "runner_summary.json",
        "calibration.cancellation.cleanup_missing",
        "calibration.obligation.leak_detected",
    ] {
        assert!(
            src.contains(token),
            "CLI differential runner source missing token: {token}"
        );
    }
    Ok(())
}
