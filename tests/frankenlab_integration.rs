//! FrankenLab integration tests (bd-1hu19.5).
//!
//! Covers:
//! - Loading and executing all example YAML scenarios
//! - Proptest YAML/JSON roundtrip
//! - Deterministic replay across 100 runs
//! - Fault injection determinism
//! - Scenario validation (positive and negative)
//! - Virtual time auto-advance semantics
//! - Seed exploration consistency
#![allow(missing_docs)]

#[macro_use]
mod common;

use asupersync::lab::config::LabConfig;
use asupersync::lab::runtime::LabRuntime;
use asupersync::lab::scenario::{
    CancellationSection, CancellationStrategy, ChaosSection, FaultAction, FaultEvent, LabSection,
    NetworkPreset, NetworkSection, Participant, Scenario, SCENARIO_SCHEMA_VERSION,
};
use asupersync::lab::scenario_runner::ScenarioRunner;
use common::*;
use proptest::prelude::*;
use std::collections::BTreeMap;
use std::path::Path;

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

// ============================================================================
// Helpers
// ============================================================================

fn load_scenario(path: &Path) -> Scenario {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()));
    serde_yaml::from_str(&raw).unwrap_or_else(|e| panic!("Failed to parse {}: {e}", path.display()))
}

fn minimal_scenario() -> Scenario {
    Scenario {
        schema_version: SCENARIO_SCHEMA_VERSION,
        id: "integration-minimal".to_string(),
        description: "Minimal integration test scenario".to_string(),
        lab: LabSection::default(),
        chaos: ChaosSection::Off,
        network: NetworkSection::default(),
        faults: Vec::new(),
        participants: Vec::new(),
        oracles: vec!["all".to_string()],
        cancellation: None,
        include: Vec::new(),
        metadata: BTreeMap::new(),
    }
}

fn scenario_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/scenarios")
}

// ============================================================================
// (1) Deterministic scheduler reproducibility
// ============================================================================

#[test]
fn deterministic_replay_100_runs() {
    init_test("deterministic_replay_100_runs");
    let scenario = minimal_scenario();

    let first = ScenarioRunner::run(&scenario).expect("first run");
    let reference_cert = first.certificate;

    for i in 1..100 {
        let result = ScenarioRunner::run(&scenario).unwrap_or_else(|e| panic!("run {i}: {e}"));
        assert_eq!(
            result.certificate, reference_cert,
            "Run {i} diverged from run 0: {:?} != {:?}",
            result.certificate, reference_cert
        );
    }

    test_complete!("deterministic_replay_100_runs");
}

// ============================================================================
// (2) Virtual time correctness
// ============================================================================

#[test]
fn virtual_time_auto_advance_completes() {
    init_test("virtual_time_auto_advance_completes");
    let config = LabConfig::new(42).with_auto_advance();
    let mut runtime = LabRuntime::new(config);

    // With no tasks or timers, auto-advance should complete immediately
    let report = runtime.run_with_auto_advance();
    assert_eq!(report.auto_advances, 0, "No timers means no auto-advances");
    assert_eq!(report.virtual_elapsed_nanos, 0, "No elapsed time expected");

    test_complete!("virtual_time_auto_advance_completes");
}

#[test]
fn virtual_time_advance_without_timers_is_noop() {
    init_test("virtual_time_advance_without_timers_is_noop");
    let config = LabConfig::new(42);
    let mut runtime = LabRuntime::new(config);

    let wakeups = runtime.advance_to_next_timer();
    assert_eq!(wakeups, 0, "No timers means no wakeups");
    assert!(
        runtime.next_timer_deadline().is_none(),
        "No timers should mean no deadline"
    );

    test_complete!("virtual_time_advance_without_timers_is_noop");
}

// ============================================================================
// (3) YAML scenario parser roundtrip (proptest)
// ============================================================================

fn arb_scenario() -> impl Strategy<Value = Scenario> {
    (
        // seed
        any::<u64>(),
        // worker_count (1..=8)
        1usize..=8,
        // chaos preset
        prop_oneof![Just(ChaosSection::Off), Just(ChaosSection::Light),],
        // network preset
        prop_oneof![
            Just(NetworkPreset::Ideal),
            Just(NetworkPreset::Lan),
            Just(NetworkPreset::Wan),
        ],
        // fault count (0..=3)
        0usize..=3,
        // participant count (0..=3)
        0usize..=3,
    )
        .prop_map(
            |(seed, workers, chaos, net_preset, fault_count, part_count)| {
                let mut faults = Vec::new();
                for i in 0..fault_count {
                    faults.push(FaultEvent {
                        at_ms: (i as u64 + 1) * 100,
                        action: if i % 2 == 0 {
                            FaultAction::Partition
                        } else {
                            FaultAction::Heal
                        },
                        args: BTreeMap::new(),
                    });
                }

                let participants: Vec<Participant> = (0..part_count)
                    .map(|i| Participant {
                        name: format!("node-{i}"),
                        role: "test".to_string(),
                        properties: BTreeMap::new(),
                    })
                    .collect();

                Scenario {
                    schema_version: SCENARIO_SCHEMA_VERSION,
                    id: format!("proptest-{seed}"),
                    description: "Property test scenario".to_string(),
                    lab: LabSection {
                        seed,
                        worker_count: workers,
                        ..LabSection::default()
                    },
                    chaos,
                    network: NetworkSection {
                        preset: net_preset,
                        links: BTreeMap::new(),
                    },
                    faults,
                    participants,
                    oracles: vec!["all".to_string()],
                    cancellation: None,
                    include: Vec::new(),
                    metadata: BTreeMap::new(),
                }
            },
        )
}

proptest! {
    #![proptest_config(test_proptest_config(50))]

    #[test]
    fn scenario_json_roundtrip(scenario in arb_scenario()) {
        let json = scenario.to_json().expect("serialize to JSON");
        let parsed = Scenario::from_json(&json).expect("parse from JSON");

        prop_assert_eq!(&scenario.id, &parsed.id);
        prop_assert_eq!(scenario.schema_version, parsed.schema_version);
        prop_assert_eq!(scenario.lab.seed, parsed.lab.seed);
        prop_assert_eq!(scenario.lab.worker_count, parsed.lab.worker_count);
        prop_assert_eq!(scenario.faults.len(), parsed.faults.len());
        prop_assert_eq!(scenario.participants.len(), parsed.participants.len());
    }

    #[test]
    fn scenario_yaml_roundtrip(scenario in arb_scenario()) {
        let yaml = serde_yaml::to_string(&scenario).expect("serialize to YAML");
        let parsed: Scenario = serde_yaml::from_str(&yaml).expect("parse from YAML");

        prop_assert_eq!(&scenario.id, &parsed.id);
        prop_assert_eq!(scenario.schema_version, parsed.schema_version);
        prop_assert_eq!(scenario.lab.seed, parsed.lab.seed);
        prop_assert_eq!(scenario.lab.worker_count, parsed.lab.worker_count);
        prop_assert_eq!(scenario.faults.len(), parsed.faults.len());
        prop_assert_eq!(scenario.participants.len(), parsed.participants.len());
    }

    #[test]
    fn generated_scenarios_validate(scenario in arb_scenario()) {
        let errors = scenario.validate();
        prop_assert!(errors.is_empty(), "Validation failed: {:?}", errors);
    }
}

// ============================================================================
// (4) Schema validation: all example scenarios pass validation
// ============================================================================

#[test]
fn all_example_scenarios_validate() {
    init_test("all_example_scenarios_validate");
    let dir = scenario_dir();

    let mut count = 0;
    for entry in std::fs::read_dir(&dir).expect("read scenario dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "yaml") {
            let scenario = load_scenario(&path);
            let errors = scenario.validate();
            assert!(
                errors.is_empty(),
                "Scenario {} failed validation: {:?}",
                path.display(),
                errors
            );
            count += 1;
        }
    }

    assert!(
        count >= 10,
        "Expected at least 10 scenario files, found {count}"
    );
    test_complete!("all_example_scenarios_validate", count = count);
}

// ============================================================================
// (5) Full scenario execution: run all example scenarios
// ============================================================================

#[test]
fn run_all_example_scenarios() {
    init_test("run_all_example_scenarios");
    let dir = scenario_dir();

    let mut passed = 0;
    let mut total = 0;

    for entry in std::fs::read_dir(&dir).expect("read scenario dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "yaml") {
            let scenario = load_scenario(&path);
            total += 1;

            let result = ScenarioRunner::run(&scenario);
            match result {
                Ok(r) => {
                    assert!(
                        r.passed(),
                        "Scenario {} (seed={}) did not pass: {} oracle failures, {} invariant violations",
                        path.file_name().unwrap().to_string_lossy(),
                        r.seed,
                        r.oracle_report.failed_count,
                        r.lab_report.invariant_violations.len()
                    );
                    passed += 1;
                }
                Err(e) => {
                    panic!(
                        "Scenario {} failed to run: {e}",
                        path.file_name().unwrap().to_string_lossy()
                    );
                }
            }
        }
    }

    assert!(
        total >= 10,
        "Expected at least 10 scenario files, found {total}"
    );
    assert_eq!(passed, total, "Not all scenarios passed");
    test_complete!("run_all_example_scenarios", passed = passed, total = total);
}

// ============================================================================
// (6) Invalid scenarios are rejected with clear errors
// ============================================================================

#[test]
fn invalid_scenario_empty_id() {
    init_test("invalid_scenario_empty_id");
    let mut scenario = minimal_scenario();
    scenario.id = String::new();
    let errors = scenario.validate();
    assert!(!errors.is_empty(), "Empty ID should be rejected");
    assert!(
        errors.iter().any(|e| e.field == "id"),
        "Should report error on 'id' field"
    );
    test_complete!("invalid_scenario_empty_id");
}

#[test]
fn invalid_scenario_bad_schema_version() {
    init_test("invalid_scenario_bad_schema_version");
    let mut scenario = minimal_scenario();
    scenario.schema_version = 99;
    let errors = scenario.validate();
    assert!(
        errors.iter().any(|e| e.field == "schema_version"),
        "Bad schema version should be rejected"
    );
    test_complete!("invalid_scenario_bad_schema_version");
}

#[test]
fn invalid_scenario_unordered_faults() {
    init_test("invalid_scenario_unordered_faults");
    let mut scenario = minimal_scenario();
    scenario.faults = vec![
        FaultEvent {
            at_ms: 500,
            action: FaultAction::Partition,
            args: BTreeMap::new(),
        },
        FaultEvent {
            at_ms: 100,
            action: FaultAction::Heal,
            args: BTreeMap::new(),
        },
    ];
    let errors = scenario.validate();
    assert!(
        errors.iter().any(|e| e.field == "faults"),
        "Unordered faults should be rejected"
    );
    test_complete!("invalid_scenario_unordered_faults");
}

#[test]
fn invalid_scenario_duplicate_participants() {
    init_test("invalid_scenario_duplicate_participants");
    let mut scenario = minimal_scenario();
    scenario.participants = vec![
        Participant {
            name: "alice".to_string(),
            role: "sender".to_string(),
            properties: BTreeMap::new(),
        },
        Participant {
            name: "alice".to_string(),
            role: "receiver".to_string(),
            properties: BTreeMap::new(),
        },
    ];
    let errors = scenario.validate();
    assert!(
        errors.iter().any(|e| e.message.contains("duplicate")),
        "Duplicate participants should be rejected"
    );
    test_complete!("invalid_scenario_duplicate_participants");
}

#[test]
fn invalid_scenario_missing_cancellation_count() {
    init_test("invalid_scenario_missing_cancellation_count");
    let mut scenario = minimal_scenario();
    scenario.cancellation = Some(CancellationSection {
        strategy: CancellationStrategy::RandomSample,
        count: None,
        probability: None,
    });
    let errors = scenario.validate();
    assert!(
        errors.iter().any(|e| e.field == "cancellation.count"),
        "Missing count should be rejected for RandomSample strategy"
    );
    test_complete!("invalid_scenario_missing_cancellation_count");
}

#[test]
fn invalid_scenario_runner_rejects_unknown_oracle() {
    init_test("invalid_scenario_runner_rejects_unknown_oracle");
    let mut scenario = minimal_scenario();
    scenario.oracles = vec!["totally_fake_oracle".to_string()];
    let result = ScenarioRunner::run(&scenario);
    assert!(
        result.is_err(),
        "Unknown oracle should be rejected by runner"
    );
    test_complete!("invalid_scenario_runner_rejects_unknown_oracle");
}

#[test]
fn invalid_yaml_parse_error() {
    init_test("invalid_yaml_parse_error");
    let bad_yaml = "this: is: not: valid: yaml: [[[";
    let result: Result<Scenario, _> = serde_yaml::from_str(bad_yaml);
    assert!(result.is_err(), "Malformed YAML should fail to parse");
    test_complete!("invalid_yaml_parse_error");
}

// ============================================================================
// (7) Fault injection determinism
// ============================================================================

#[test]
fn fault_injection_determinism() {
    init_test("fault_injection_determinism");
    let mut scenario = minimal_scenario();
    scenario.lab.seed = 7;
    scenario.faults = vec![
        FaultEvent {
            at_ms: 10,
            action: FaultAction::Partition,
            args: BTreeMap::new(),
        },
        FaultEvent {
            at_ms: 50,
            action: FaultAction::Heal,
            args: BTreeMap::new(),
        },
        FaultEvent {
            at_ms: 100,
            action: FaultAction::HostCrash,
            args: BTreeMap::new(),
        },
        FaultEvent {
            at_ms: 150,
            action: FaultAction::HostRestart,
            args: BTreeMap::new(),
        },
        FaultEvent {
            at_ms: 200,
            action: FaultAction::ClockSkew,
            args: BTreeMap::new(),
        },
        FaultEvent {
            at_ms: 250,
            action: FaultAction::ClockReset,
            args: BTreeMap::new(),
        },
    ];

    let r1 = ScenarioRunner::run(&scenario).expect("run 1");
    let r2 = ScenarioRunner::run(&scenario).expect("run 2");

    assert_eq!(
        r1.certificate, r2.certificate,
        "Fault injection should be deterministic"
    );
    assert_eq!(r1.faults_injected, 6);
    assert_eq!(r2.faults_injected, 6);

    test_complete!("fault_injection_determinism");
}

// ============================================================================
// (8) Record/replay round-trip
// ============================================================================

#[test]
fn replay_validation_passes_for_all_examples() {
    init_test("replay_validation_passes_for_all_examples");
    let dir = scenario_dir();

    let mut validated = 0;
    for entry in std::fs::read_dir(&dir).expect("read scenario dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "yaml") {
            let scenario = load_scenario(&path);
            let result = ScenarioRunner::validate_replay(&scenario);
            match result {
                Ok(r) => {
                    assert!(
                        r.passed(),
                        "Replay validation failed for {}",
                        path.file_name().unwrap().to_string_lossy()
                    );
                    validated += 1;
                }
                Err(e) => {
                    panic!(
                        "Replay validation error for {}: {e}",
                        path.file_name().unwrap().to_string_lossy()
                    );
                }
            }
        }
    }

    assert!(
        validated >= 10,
        "Expected at least 10 validated scenarios, got {validated}"
    );
    test_complete!(
        "replay_validation_passes_for_all_examples",
        validated = validated
    );
}

// ============================================================================
// (9) Seed exploration consistency
// ============================================================================

#[test]
fn seed_exploration_10_seeds() {
    init_test("seed_exploration_10_seeds");
    let scenario = minimal_scenario();
    let result = ScenarioRunner::explore_seeds(&scenario, 0, 10).expect("explore");

    assert_eq!(result.seeds_explored, 10);
    assert_eq!(result.failed, 0, "No seeds should fail on minimal scenario");
    assert!(result.all_passed());
    assert!(
        result.unique_fingerprints >= 1,
        "Should have at least one fingerprint"
    );

    // Verify each run has the correct seed
    for (i, run) in result.runs.iter().enumerate() {
        assert_eq!(run.seed, i as u64, "Run {i} should have seed {i}");
        assert!(run.passed, "Run {i} (seed={}) should pass", run.seed);
    }

    test_complete!("seed_exploration_10_seeds");
}

#[test]
fn seed_exploration_deterministic() {
    init_test("seed_exploration_deterministic");
    let scenario = minimal_scenario();

    let r1 = ScenarioRunner::explore_seeds(&scenario, 42, 5).expect("explore 1");
    let r2 = ScenarioRunner::explore_seeds(&scenario, 42, 5).expect("explore 2");

    assert_eq!(r1.seeds_explored, r2.seeds_explored);
    assert_eq!(r1.unique_fingerprints, r2.unique_fingerprints);
    for (a, b) in r1.runs.iter().zip(r2.runs.iter()) {
        assert_eq!(a.seed, b.seed);
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_eq!(a.steps, b.steps);
    }

    test_complete!("seed_exploration_deterministic");
}

// ============================================================================
// (10) Scenario to LabConfig conversion
// ============================================================================

#[test]
fn scenario_to_lab_config_preserves_settings() {
    init_test("scenario_to_lab_config_preserves_settings");
    let mut scenario = minimal_scenario();
    scenario.lab.seed = 12345;
    scenario.lab.worker_count = 4;
    scenario.lab.trace_capacity = 8192;
    scenario.lab.max_steps = Some(50_000);
    scenario.lab.panic_on_obligation_leak = false;
    scenario.lab.panic_on_futurelock = false;
    scenario.lab.futurelock_max_idle_steps = 5000;
    scenario.lab.entropy_seed = Some(99);

    let config = scenario.to_lab_config();
    assert_eq!(config.seed, 12345);
    assert_eq!(config.worker_count, 4);
    assert_eq!(config.trace_capacity, 8192);
    assert_eq!(config.max_steps, Some(50_000));
    assert!(!config.panic_on_obligation_leak);
    assert!(!config.panic_on_futurelock);
    assert_eq!(config.futurelock_max_idle_steps, 5000);
    assert_eq!(config.entropy_seed, 99);

    test_complete!("scenario_to_lab_config_preserves_settings");
}

#[test]
fn scenario_chaos_presets_convert_correctly() {
    init_test("scenario_chaos_presets_convert_correctly");

    let off = {
        let mut s = minimal_scenario();
        s.chaos = ChaosSection::Off;
        s.to_lab_config()
    };
    assert!(!off.has_chaos());

    let light = {
        let mut s = minimal_scenario();
        s.chaos = ChaosSection::Light;
        s.to_lab_config()
    };
    assert!(light.has_chaos());

    let heavy = {
        let mut s = minimal_scenario();
        s.chaos = ChaosSection::Heavy;
        s.to_lab_config()
    };
    assert!(heavy.has_chaos());

    test_complete!("scenario_chaos_presets_convert_correctly");
}

// ============================================================================
// (11) JSON output format
// ============================================================================

#[test]
fn result_json_contains_required_fields() {
    init_test("result_json_contains_required_fields");
    let scenario = minimal_scenario();
    let result = ScenarioRunner::run(&scenario).expect("run");
    let json = result.to_json();

    assert!(json["scenario_id"].is_string());
    assert!(json["seed"].is_u64());
    assert!(json["passed"].is_boolean());
    assert!(json["steps"].is_u64());
    assert!(json["faults_injected"].is_u64());
    assert!(json["certificate"]["event_hash"].is_u64());
    assert!(json["certificate"]["schedule_hash"].is_u64());
    assert!(json["certificate"]["trace_fingerprint"].is_u64());
    assert!(json["oracle_report"]["all_passed"].is_boolean());

    test_complete!("result_json_contains_required_fields");
}

#[test]
fn exploration_json_contains_per_seed_results() {
    init_test("exploration_json_contains_per_seed_results");
    let scenario = minimal_scenario();
    let result = ScenarioRunner::explore_seeds(&scenario, 0, 3).expect("explore");
    let json = result.to_json();

    assert_eq!(json["seeds_explored"], 3);
    let runs = json["runs"].as_array().expect("runs should be array");
    assert_eq!(runs.len(), 3);
    for (i, run) in runs.iter().enumerate() {
        assert_eq!(run["seed"], i as u64);
        assert!(run["passed"].is_boolean());
        assert!(run["steps"].is_u64());
        assert!(run["fingerprint"].is_u64());
    }

    test_complete!("exploration_json_contains_per_seed_results");
}

// ============================================================================
// (12) Determinism across different worker counts
// ============================================================================

#[test]
fn same_seed_same_worker_count_same_certificate() {
    init_test("same_seed_same_worker_count_same_certificate");

    for workers in [1, 2, 4] {
        let mut scenario = minimal_scenario();
        scenario.lab.seed = 42;
        scenario.lab.worker_count = workers;

        let r1 = ScenarioRunner::run(&scenario).expect("run 1");
        let r2 = ScenarioRunner::run(&scenario).expect("run 2");
        assert_eq!(
            r1.certificate, r2.certificate,
            "Worker count {workers}: same seed should produce same certificate"
        );
    }

    test_complete!("same_seed_same_worker_count_same_certificate");
}
