#![allow(missing_docs)]

use asupersync::lab::explorer::SaturationMetrics;
use asupersync::lab::replay::{
    DifferentialBundleArtifacts, DifferentialPolicyClass, DivergenceCorpusEntry,
    DivergenceMinimizationLineage, DivergenceShrinkStatus, RegressionPromotionState,
};
use asupersync::lab::runtime::InvariantViolation;
use asupersync::lab::{
    CoverageMetrics, DualRunHarness, ExplorationReport, ObligationBalanceRecord, RunResult,
    ViolationReport, promote_exploration_report,
};
use std::collections::BTreeMap;

fn sample_report() -> ExplorationReport {
    ExplorationReport {
        total_runs: 3,
        unique_classes: 2,
        violations: vec![ViolationReport {
            seed: 0x22,
            steps: 88,
            violations: vec![InvariantViolation::TaskLeak { count: 1 }],
            fingerprint: 0xA11CE,
        }],
        coverage: CoverageMetrics {
            equivalence_classes: 2,
            total_runs: 3,
            new_class_discoveries: 2,
            class_run_counts: BTreeMap::from([(0xA11CE, 2), (0xB0B, 1)]),
            novelty_histogram: BTreeMap::from([(0, 1), (1, 2)]),
            saturation: SaturationMetrics {
                window: 10,
                saturated: false,
                existing_class_hits: 1,
                runs_since_last_new_class: Some(1),
            },
        },
        top_unexplored: Vec::new(),
        runs: vec![
            RunResult {
                seed: 0x11,
                steps: 21,
                fingerprint: 0xA11CE,
                is_new_class: true,
                violations: Vec::new(),
                certificate_hash: 0x111,
            },
            RunResult {
                seed: 0x22,
                steps: 88,
                fingerprint: 0xA11CE,
                is_new_class: false,
                violations: vec![InvariantViolation::TaskLeak { count: 1 }],
                certificate_hash: 0x222,
            },
            RunResult {
                seed: 0x33,
                steps: 13,
                fingerprint: 0xB0B,
                is_new_class: true,
                violations: Vec::new(),
                certificate_hash: 0x333,
            },
        ],
    }
}

fn make_happy_semantics() -> asupersync::lab::NormalizedSemantics {
    asupersync::lab::NormalizedSemantics {
        terminal_outcome: asupersync::lab::TerminalOutcome::ok(),
        cancellation: asupersync::lab::CancellationRecord::none(),
        loser_drain: asupersync::lab::LoserDrainRecord::not_applicable(),
        region_close: asupersync::lab::RegionCloseRecord::quiescent(),
        obligation_balance: asupersync::lab::ObligationBalanceRecord::zero(),
        resource_surface: asupersync::lab::ResourceSurfaceRecord::empty("test"),
    }
}

fn make_obligation_leak_semantics() -> asupersync::lab::NormalizedSemantics {
    let mut semantics = make_happy_semantics();
    semantics.obligation_balance = ObligationBalanceRecord {
        reserved: 1,
        committed: 0,
        aborted: 0,
        leaked: 1,
        unresolved: 0,
        balanced: false,
    };
    semantics
}

fn make_cancellation_finalizing_semantics() -> asupersync::lab::NormalizedSemantics {
    let mut semantics = make_happy_semantics();
    semantics.cancellation = asupersync::lab::CancellationRecord {
        requested: true,
        acknowledged: true,
        cleanup_completed: true,
        finalization_completed: false,
        terminal_phase: asupersync::lab::dual_run::CancelTerminalPhase::Finalizing,
        checkpoint_observed: Some(true),
    };
    semantics
}

fn make_region_draining_semantics() -> asupersync::lab::NormalizedSemantics {
    let mut semantics = make_happy_semantics();
    semantics.region_close = asupersync::lab::RegionCloseRecord {
        root_state: asupersync::lab::dual_run::RegionState::Draining,
        quiescent: false,
        live_children: 2,
        finalizers_pending: 1,
        close_completed: false,
    };
    semantics
}

#[test]
fn promoted_schedule_scenarios_preserve_lineage_and_class_shape() {
    let promoted = promote_exploration_report(&sample_report(), "scheduler.surface", "v1");
    assert_eq!(promoted.len(), 2);

    let violating = promoted
        .iter()
        .find(|scenario| scenario.trace_fingerprint == 0xA11CE)
        .expect("violating class should be promoted");
    assert_eq!(violating.replay_seed, 0x22);
    assert_eq!(violating.original_seeds, vec![0x11, 0x22]);
    assert_eq!(violating.violation_seeds, vec![0x22]);
    assert_eq!(violating.class_run_count, 2);
    assert!(
        violating
            .violation_summaries
            .iter()
            .any(|summary| summary.contains("tasks leaked"))
    );
}

#[test]
fn promoted_schedule_scenario_runs_through_dual_run_harness_and_metadata() {
    let promoted = promote_exploration_report(&sample_report(), "scheduler.surface", "v1");
    let promoted = promoted[0]
        .clone()
        .with_source_artifact_path("/tmp/exploration/report.json");

    let metadata = promoted.lab_replay_metadata();
    assert_eq!(
        metadata.artifact_path.as_deref(),
        Some("/tmp/exploration/report.json")
    );
    assert_eq!(metadata.trace_fingerprint, Some(promoted.trace_fingerprint));
    assert_eq!(
        metadata.schedule_hash,
        Some(promoted.representative_schedule_hash)
    );
    assert_eq!(
        metadata.repro_command.as_deref(),
        Some(promoted.repro_command().as_str())
    );

    let result = DualRunHarness::from_identity(promoted.identity)
        .lab(|_config| make_happy_semantics())
        .live(|_seed, _entropy| make_happy_semantics())
        .run();

    assert!(result.passed(), "promoted scenario should replay cleanly");
}

#[test]
fn promoted_schedule_divergence_builds_retained_bundle_with_lineage() {
    let promoted = promote_exploration_report(&sample_report(), "scheduler.surface", "v1");
    let promoted = promoted[0]
        .clone()
        .with_source_artifact_path("/tmp/exploration/report.json");

    let result = DualRunHarness::from_identity(promoted.identity.clone())
        .lab(|_config| make_happy_semantics())
        .live(|_seed, _entropy| make_obligation_leak_semantics())
        .run();

    assert!(
        !result.passed(),
        "leaky live side should create a divergence"
    );

    let entry =
        DivergenceCorpusEntry::from_dual_run_result(
            &result,
            "smoke",
            "obligation_balance_mismatch",
            DifferentialPolicyClass::RuntimeSemanticBug,
            "artifacts/differential/scheduler/promoted-case",
        )
        .with_first_seen_attempt(1, 0)
        .with_minimization_lineage(
            DivergenceMinimizationLineage::from_seed_lineage(&result.seed_lineage)
                .with_minimized_seed(0x2A, "schedule_prefix", true, true),
        )
        .promote_to_regression("regression.scheduler.surface.obligation_leak.seed_2a");

    let default_bundle_root = entry.default_bundle_root();
    assert!(
        default_bundle_root.starts_with("artifacts/differential/scheduler_surface/"),
        "default bundle root should normalize the surface id: {default_bundle_root}"
    );

    let bundle = DifferentialBundleArtifacts::from_dual_run_result(&entry, &result);

    assert_eq!(bundle.summary.scenario_id, promoted.identity.scenario_id);
    assert_eq!(bundle.summary.surface_id, promoted.identity.surface_id);
    assert_eq!(
        bundle.summary.policy_class,
        DifferentialPolicyClass::RuntimeSemanticBug
    );
    assert_eq!(
        bundle.summary.regression_promotion_state,
        RegressionPromotionState::PromotedRegression
    );
    assert_eq!(
        bundle.repro_manifest.seed_lineage.seed_lineage_id,
        promoted.identity.seed_plan.seed_lineage_id
    );
    assert_eq!(
        bundle.repro_manifest.promoted_scenario_id.as_deref(),
        Some("regression.scheduler.surface.obligation_leak.seed_2a")
    );
    assert_eq!(
        bundle.repro_manifest.minimization_lineage.shrink_status,
        DivergenceShrinkStatus::PreservedSemanticClass
    );
    assert_eq!(bundle.failures.failure_artifacts.len(), 2);
    assert_eq!(
        bundle.failures.failure_artifacts[0].normalized_record_path,
        entry.artifact_bundle.lab_normalized_path
    );
    assert_eq!(
        bundle.failures.failure_artifacts[1].normalized_record_path,
        entry.artifact_bundle.live_normalized_path
    );
    assert!(
        !bundle.repro_manifest.repro_commands.is_empty(),
        "bundle must retain deterministic repro commands"
    );
    assert!(
        bundle
            .deviations
            .mismatches
            .iter()
            .any(|mismatch| mismatch.field == "semantics.obligation_balance.balanced"),
        "obligation balance divergence should be retained in the bundle"
    );
}

#[test]
fn promoted_schedule_divergence_bundle_retains_cancellation_mismatch() {
    let promoted = promote_exploration_report(&sample_report(), "scheduler.surface", "v1");
    let promoted = promoted[0]
        .clone()
        .with_source_artifact_path("/tmp/exploration/report.json");

    let result = DualRunHarness::from_identity(promoted.identity.clone())
        .lab(|_config| make_happy_semantics())
        .live(|_seed, _entropy| make_cancellation_finalizing_semantics())
        .run();

    assert!(
        !result.passed(),
        "incomplete cancellation finalization should create a divergence"
    );

    let entry = DivergenceCorpusEntry::from_dual_run_result(
        &result,
        "smoke",
        "cancellation_terminal_phase_mismatch",
        DifferentialPolicyClass::RuntimeSemanticBug,
        "artifacts/differential/scheduler/promoted-cancellation",
    );

    let bundle = DifferentialBundleArtifacts::from_dual_run_result(&entry, &result);

    assert!(
        bundle
            .deviations
            .mismatches
            .iter()
            .any(|mismatch| mismatch.field == "semantics.cancellation.terminal_phase"),
        "cancellation terminal phase divergence should be retained in the bundle"
    );
    assert!(
        bundle
            .deviations
            .mismatches
            .iter()
            .any(|mismatch| mismatch.field == "semantics.cancellation.requested"),
        "cancellation request divergence should be retained in the bundle"
    );
}

#[test]
fn promoted_schedule_divergence_bundle_retains_region_close_mismatch() {
    let promoted = promote_exploration_report(&sample_report(), "scheduler.surface", "v1");
    let promoted = promoted[0]
        .clone()
        .with_source_artifact_path("/tmp/exploration/report.json");

    let result = DualRunHarness::from_identity(promoted.identity.clone())
        .lab(|_config| make_happy_semantics())
        .live(|_seed, _entropy| make_region_draining_semantics())
        .run();

    assert!(
        !result.passed(),
        "non-quiescent region close state should create a divergence"
    );

    let entry = DivergenceCorpusEntry::from_dual_run_result(
        &result,
        "smoke",
        "region_close_quiescence_mismatch",
        DifferentialPolicyClass::RuntimeSemanticBug,
        "artifacts/differential/scheduler/promoted-region-close",
    );

    let bundle = DifferentialBundleArtifacts::from_dual_run_result(&entry, &result);

    assert!(
        bundle
            .deviations
            .mismatches
            .iter()
            .any(|mismatch| mismatch.field == "semantics.region_close.quiescent"),
        "region quiescence divergence should be retained in the bundle"
    );
    assert!(
        bundle
            .deviations
            .mismatches
            .iter()
            .any(|mismatch| mismatch.field == "semantics.region_close.live_children"),
        "region live child count divergence should be retained in the bundle"
    );
    assert!(
        bundle
            .deviations
            .mismatches
            .iter()
            .any(|mismatch| mismatch.field == "semantics.region_close.close_completed"),
        "region close completion divergence should be retained in the bundle"
    );
}
