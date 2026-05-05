//! Contract tests for the lab-vs-live verification taxonomy (2a6k9.1.4).
//!
//! Verifies the tier vocabulary, minimum coverage matrix, structured logging
//! field set, downstream bindings, and `rch`-offloaded validation policy.

#![allow(missing_docs)]

use serde_json::{Value, json};
use std::path::Path;

fn load_doc() -> std::io::Result<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/lab_live_verification_taxonomy.md");
    std::fs::read_to_string(path)
}

fn load_divergence_doc() -> std::io::Result<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/lab_live_divergence_taxonomy.md");
    std::fs::read_to_string(path)
}

fn load_ci_workflow() -> std::io::Result<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/ci.yml");
    std::fs::read_to_string(path)
}

fn load_nightly_differential_workflow() -> std::io::Result<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".github/workflows/nightly-differential-stress.yml");
    std::fs::read_to_string(path)
}

fn load_runner_script() -> std::io::Result<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/run_lab_live_differential.sh");
    std::fs::read_to_string(path)
}

fn load_ci_matrix_policy() -> std::io::Result<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/ci_matrix_policy.json");
    std::fs::read_to_string(path)
}

fn load_ci_matrix_policy_json() -> std::io::Result<Value> {
    let raw = load_ci_matrix_policy()?;
    serde_json::from_str(&raw)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
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
fn doc_pins_current_executable_anchor_inventory() -> std::io::Result<()> {
    let doc = load_doc()?;
    for token in [
        "Current Executable Anchor Inventory",
        "Current differential runner profiles",
        "asupersync lab differential-profile-manifest --json",
        "lab-live-differential-profile-manifest-v1",
        "Smoke",
        "Phase1Core",
        "Calibration",
        "repro-targeted",
        "nightly-stress",
        "phase1.cancel.protocol.drain_finalize",
        "phase1.cancel.protocol.before_first_poll",
        "phase1.cancel.protocol.child_await",
        "phase1.cancel.protocol.cleanup_budget",
        "phase1.combinator.race.one_loser",
        "phase1.channel.reserve_send.commit",
        "phase1.channel.reserve_send.abort_visible",
        "phase1.region.close.quiescent",
        "calibration.combinator.loser_not_drained",
        "calibration.cancellation.cleanup_missing",
        "calibration.cancellation.cleanup_budget_exhausted",
        "calibration.comparator.resource_counter_mismatch",
        "calibration.channel.commit_visibility_mismatch",
        "calibration.obligation.leak_detected",
        "calibration.region.close.non_quiescent",
        "tests/lab_live_scenario_adapter_contract.rs",
        "tests/e2e/combinator/cancel_correctness/async_loser_drain.rs",
        "tests/e2e_channel_patterns.rs",
        "tests/obligation_lifecycle_e2e.rs",
        "tests/close_quiescence_regression.rs",
        "phase1.cancel.protocol.before_first_poll` is the canonical pre-checkpoint",
        "phase1.cancel.protocol.child_await` is the canonical awaited-child",
        "calibration.combinator.loser_not_drained` is the dedicated adversarial",
        "calibration.cancellation.cleanup_budget_exhausted",
        "calibration.combinator.loser_not_drained` proves incomplete loser drain is escalated through the shared runner and retained artifact bundle",
        "calibration.region.close.non_quiescent` proves non-quiescent root close is escalated through the shared runner and retained artifact bundle",
        "currently piggybacks on `phase1.cancel.protocol.drain_finalize`, `phase1.channel.reserve_send.commit`, and `phase1.region.close.quiescent`",
    ] {
        assert!(
            doc.contains(token),
            "document missing executable inventory token: {token}"
        );
    }
    Ok(())
}

#[test]
fn doc_defines_contributor_playbook_workflows() -> std::io::Result<()> {
    let doc = load_doc()?;
    for token in [
        "Contributor Playbook (`asupersync-2a6k9.8.3`)",
        "Preflight checklist before touching a new surface",
        "local_smoke",
        "targeted_core_validation",
        "self_calibration",
        "targeted_repro",
        "scheduled_stress",
        "smoke_local_validation",
        "phase1_core_validation",
        "playbook-smoke",
        "playbook-phase1-core",
        "playbook-repro",
        "playbook-calibration",
        "nightly-stress/<date>/<seed>/",
        "--seed-count 4",
        "--seed-stride 9973",
        "nightly_stress_manifest.json",
        "nightly_stress_summary.txt",
        "retained_divergence_artifacts/",
        "profile_contract.evidence_grade",
        "profile_contract.confidence_label",
        "profile_contract.runtime_cost",
        "profile_contract.operator_intent",
        "profile_contract.exit_semantics",
        "unexpected_divergence",
        "missing_expected_divergence",
        "artifact_schema_violation",
        "unsupported_surface",
        "scheduler_noise_suspected",
        "irreproducible_divergence",
    ] {
        assert!(
            doc.contains(token),
            "document missing contributor playbook token: {token}"
        );
    }
    Ok(())
}

#[test]
fn doc_defines_supported_claims_and_limitations_matrix() -> std::io::Result<()> {
    let doc = load_doc()?;
    for token in [
        "Supported Claims and Limitations Matrix (`asupersync-2a6k9.8.4`)",
        "t2_dual_run_smoke",
        "baseline_signal",
        "t3_pilot_surface",
        "surface_backed",
        "t4_negative_control",
        "guardrail_validation",
        "selected_scenario_tier",
        "Rotating-seed nightly adversarial search is shipped for the admitted Phase 1 pack",
        "aggregate manifests",
        "retained divergence pointers",
        "direct replay/minimization guidance",
        "not magically broaden the program's surface-admission boundary",
        "Partial and out-of-bound claims",
        "raw_socket",
        "http_surface",
        "browser_surface",
        "outside the current trust boundary",
        "yes, the project can compare lab and live behavior on supported surfaces",
        "no, the project does not yet simulate or prove every external-system behavior",
    ] {
        assert!(
            doc.contains(token),
            "document missing claims/limitations token: {token}"
        );
    }
    Ok(())
}

#[test]
fn doc_defines_nightly_stress_retention_and_promotion_rules() -> std::io::Result<()> {
    let doc = load_doc()?;
    for token in [
        "Nightly stress retention and promotion rules",
        "local retention stays at `14` days",
        "CI retention stays at `30` days",
        "open_or_update_bead_with_retained_bundle",
        "missing_expected_divergence",
        "guardrail regression first",
        "The purpose of `nightly-stress` is to make new witnesses actionable",
    ] {
        assert!(
            doc.contains(token),
            "document missing nightly-stress governance token: {token}"
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
        "checkpoint_observed",
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
    let script = load_runner_script()?;
    for token in [
        "target/debug/asupersync",
        "RCH_BIN=\"${RCH_BIN:-$HOME/.local/bin/rch}\"",
        "run_differential()",
        "\"${RCH_BIN}\" exec -- cargo run --features cli --bin asupersync -- lab differential",
        "exec cargo run --features cli --bin asupersync -- lab differential \"${pass_through[@]}\"",
        "Nightly differential stress wrapper (`asupersync-2a6k9.8.2`)",
        "--profile nightly-stress",
        "--seed-count N",
        "--seed-stride N",
        "--rotation-date DATE",
        "nightly_stress_manifest.json",
        "nightly_stress_summary.txt",
        "retained_divergence_artifacts/",
        "lab-live-differential-nightly-stress-v1",
        "open_or_update_bead_with_retained_bundle",
        "phase1-core",
    ] {
        assert!(
            script.contains(token),
            "differential runner script missing token: {token}"
        );
    }
    Ok(())
}

#[test]
fn doc_records_fast_ci_differential_lane() -> std::io::Result<()> {
    let doc = load_doc()?;
    for token in [
        "Current fast CI differential lane",
        "scripts/run_lab_live_differential.sh --profile smoke --seed 91",
        "scripts/run_lab_live_differential.sh --profile calibration --scenario calibration.channel.commit_visibility_mismatch --seed 20260323",
        "artifacts/lab-differential-fast/",
        "smoke/operator_summary.txt",
        "smoke/artifact_index.json",
        "calibration/operator_summary.txt",
        "calibration/artifact_index.json",
    ] {
        assert!(
            doc.contains(token),
            "taxonomy doc missing fast-CI differential token: {token}"
        );
    }
    Ok(())
}

#[test]
fn ci_workflow_defines_fast_differential_gate() -> std::io::Result<()> {
    let workflow = load_ci_workflow()?;
    for token in [
        "differential-fast:",
        "name: Differential Fast Gate",
        "Differential fast CI gate",
        "scripts/run_lab_live_differential.sh \\",
        "--profile smoke",
        "--profile calibration",
        "calibration.channel.commit_visibility_mismatch",
        "Summarize differential fast gate",
        "lab-live-differential-fast-artifacts",
        "artifact_index.json",
        "operator_summary.txt",
        "[(.scenarios // [])[] | .scenario_id] | join(\", \")",
        "<unavailable>",
        "GITHUB_STEP_SUMMARY",
    ] {
        assert!(
            workflow.contains(token),
            "CI workflow missing fast differential token: {token}"
        );
    }
    Ok(())
}

#[test]
fn nightly_workflow_defines_rotating_seed_lane() -> std::io::Result<()> {
    let workflow = load_nightly_differential_workflow()?;
    for token in [
        "name: Nightly Differential Stress",
        "schedule:",
        "workflow_dispatch:",
        "nightly-differential-stress:",
        "Run nightly differential stress lane",
        "bash scripts/run_lab_live_differential.sh \\",
        "--profile nightly-stress",
        "--seed-count",
        "--seed-stride",
        "--rotation-date",
        "nightly_stress_manifest.json",
        "nightly_stress_summary.txt",
        "lab-live-differential-nightly-stress-artifacts",
        "retention-days: 30",
        "GITHUB_STEP_SUMMARY",
    ] {
        assert!(
            workflow.contains(token),
            "nightly workflow missing token: {token}"
        );
    }
    Ok(())
}

#[test]
fn ci_matrix_policy_tracks_fast_differential_lane() -> std::io::Result<()> {
    let policy = load_ci_matrix_policy_json()?;
    let manifest = policy["differential_profile_manifest"]
        .as_object()
        .expect("differential_profile_manifest must be object");
    assert_eq!(
        manifest["schema_version"],
        json!("lab-live-differential-profile-manifest-v1")
    );
    assert_eq!(
        manifest["command"],
        json!(
            "rch exec -- cargo run --features cli --bin asupersync -- lab differential-profile-manifest --json"
        )
    );
    assert_eq!(
        manifest["profile_ids"],
        json!([
            "smoke",
            "phase1-core",
            "calibration",
            "repro-targeted",
            "nightly-stress"
        ])
    );

    let lanes = policy["lanes"]
        .as_array()
        .expect("policy lanes must be array");
    let lane = lanes
        .iter()
        .find(|lane| lane["lane_id"] == "lab-live-differential-fast")
        .expect("fast differential lane missing from policy");

    assert_eq!(lane["required_job_ids"], json!(["differential-fast"]));
    assert_eq!(
        lane["required_step_names"],
        json!(["Differential fast CI gate"])
    );
    assert_eq!(
        lane["required_artifact_names"],
        json!(["lab-live-differential-fast-artifacts"])
    );
    assert_eq!(lane["require_rch"], false);
    assert_eq!(lane["thresholds"]["max_failures"], 0);
    assert_eq!(lane["thresholds"]["required_artifacts_min"], 1);

    let replay_command = lane["replay_command"]
        .as_str()
        .expect("replay_command must be string");
    assert!(
        replay_command.contains(
            "bash scripts/run_lab_live_differential.sh --profile smoke --seed 91 --out-dir artifacts/lab-differential-fast"
        ),
        "replay command must include smoke fast-lane invocation"
    );
    assert!(
        replay_command.contains(
            "bash scripts/run_lab_live_differential.sh --profile calibration --scenario calibration.channel.commit_visibility_mismatch --seed 20260323 --out-dir artifacts/lab-differential-fast"
        ),
        "replay command must include calibration fast-lane invocation"
    );

    assert_eq!(
        lane["failure_taxonomy"],
        json!([
            "profile_contract_regression",
            "artifact_bundle_contract_regression",
            "calibration_path_regression"
        ])
    );
    Ok(())
}

#[test]
fn cli_source_defines_differential_runner_surface() -> std::io::Result<()> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/asupersync.rs");
    let src = std::fs::read_to_string(path)?;
    for token in [
        "LabCommand::Differential",
        "LabCommand::DifferentialProfileManifest",
        "struct LabDifferentialArgs",
        "lab_differential_profile_manifest_command(&manifest_args, output)",
        "lab-live-differential-profile-manifest-v1",
        "\"repro-targeted\"",
        "\"nightly-stress\"",
        "\"rotating_seed_phase1_core_pack\"",
        "\"nightly_stress_manifest.json\"",
        "\"nightly_stress_summary.txt\"",
        "run_lab_differential(args)",
        "differential_event_log.jsonl",
        "runner_summary.json",
        "phase1.cancel.protocol.before_first_poll",
        "phase1.cancel.protocol.child_await",
        "phase1.cancel.protocol.cleanup_budget",
        "calibration.cancellation.cleanup_missing",
        "calibration.cancellation.cleanup_budget_exhausted",
        "calibration.comparator.resource_counter_mismatch",
        "calibration.obligation.leak_detected",
        "calibration.region.close.non_quiescent",
        "semantic_mismatch_admitted_surface",
        "Runs the admitted Phase 1 core pack across rotated seeds",
    ] {
        assert!(
            src.contains(token),
            "CLI differential runner source missing token: {token}"
        );
    }
    Ok(())
}
