#![allow(missing_docs)]

use asupersync::lab::explorer::SaturationMetrics;
use asupersync::lab::runtime::InvariantViolation;
use asupersync::lab::{
    CoverageMetrics, DualRunHarness, ExplorationReport, RunResult, ViolationReport,
    promote_exploration_report,
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
