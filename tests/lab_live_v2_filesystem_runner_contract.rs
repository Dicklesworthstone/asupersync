#![allow(missing_docs)]

use asupersync::lab::{
    CancellationRecord, DualRunHarness, DualRunResult, DualRunScenarioIdentity, LoserDrainRecord,
    NormalizedSemantics, ObligationBalanceRecord, ResourceSurfaceRecord, SeedPlan, TerminalOutcome,
    capture_region_close, run_live_adapter,
};
use serde_json::{Value, json};

const ARTIFACT: &str = include_str!("../artifacts/lab_live_v2_filesystem_runner_v1.json");
const ARTIFACT_PATH: &str = "artifacts/lab_live_v2_filesystem_runner_v1.json";
const ATOMIC_WRITE_PASS: &str =
    include_str!("fixtures/lab_live_v2_filesystem_runner/atomic_write_pass.json");
const RENAME_VISIBILITY_FAIL: &str =
    include_str!("fixtures/lab_live_v2_filesystem_runner/rename_visibility_fail.json");
const RAW_HOST_SKIP: &str =
    include_str!("fixtures/lab_live_v2_filesystem_runner/raw_host_skip.json");
const REPORT_SCHEMA: &str = "lab-live-v2-filesystem-runner-report-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunnerVerdict {
    Pass,
    Fail,
    Skip,
}

impl RunnerVerdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Skip => "skip",
        }
    }
}

#[derive(Debug, Clone)]
struct FilesystemScenario {
    scenario_id: String,
    description: String,
    surface_id: String,
    surface_contract_version: String,
    canonical_seed: u64,
    expected_verdict: RunnerVerdict,
    raw_host_surface: bool,
    lab_counters: Vec<(String, i64)>,
    live_counters: Vec<(String, i64)>,
}

fn artifact() -> Value {
    serde_json::from_str(ARTIFACT).expect("filesystem runner artifact must be valid JSON")
}

fn fixture_values() -> Vec<(&'static str, Value)> {
    vec![
        (
            "tests/fixtures/lab_live_v2_filesystem_runner/atomic_write_pass.json",
            serde_json::from_str(ATOMIC_WRITE_PASS).expect("atomic write fixture must be JSON"),
        ),
        (
            "tests/fixtures/lab_live_v2_filesystem_runner/rename_visibility_fail.json",
            serde_json::from_str(RENAME_VISIBILITY_FAIL)
                .expect("rename visibility fixture must be JSON"),
        ),
        (
            "tests/fixtures/lab_live_v2_filesystem_runner/raw_host_skip.json",
            serde_json::from_str(RAW_HOST_SKIP).expect("raw host skip fixture must be JSON"),
        ),
    ]
}

fn parse_verdict(value: &Value) -> RunnerVerdict {
    match value.as_str().expect("expected_verdict must be a string") {
        "pass" => RunnerVerdict::Pass,
        "fail" => RunnerVerdict::Fail,
        "skip" => RunnerVerdict::Skip,
        other => panic!("unknown runner verdict {other}"),
    }
}

fn parse_counters(fixture: &Value, side: &str) -> Vec<(String, i64)> {
    let mut counters = fixture["counters"][side]
        .as_object()
        .unwrap_or_else(|| panic!("{side} counters must be an object"))
        .iter()
        .map(|(name, value)| {
            (
                name.clone(),
                value
                    .as_i64()
                    .unwrap_or_else(|| panic!("{side}.{name} counter must be an i64")),
            )
        })
        .collect::<Vec<_>>();
    counters.sort_by(|left, right| left.0.cmp(&right.0));
    counters
}

fn parse_scenario(fixture: &Value) -> FilesystemScenario {
    assert_eq!(
        fixture["schema_version"],
        "lab-live-v2-filesystem-runner-fixture-v1"
    );
    assert_eq!(fixture["surface_family"], "filesystem");
    assert_eq!(fixture["adapter_family"], "captured_filesystem");
    assert_eq!(fixture["platform_policy"]["skip_is_pass"], false);

    FilesystemScenario {
        scenario_id: fixture["scenario_id"]
            .as_str()
            .expect("scenario_id")
            .to_string(),
        description: fixture["description"]
            .as_str()
            .expect("description")
            .to_string(),
        surface_id: fixture["surface_id"]
            .as_str()
            .expect("surface_id")
            .to_string(),
        surface_contract_version: fixture["surface_contract_version"]
            .as_str()
            .expect("surface_contract_version")
            .to_string(),
        canonical_seed: fixture["canonical_seed"].as_u64().expect("canonical_seed"),
        expected_verdict: parse_verdict(&fixture["expected_verdict"]),
        raw_host_surface: fixture["platform_policy"]["raw_host_surface"]
            .as_bool()
            .expect("raw_host_surface"),
        lab_counters: parse_counters(fixture, "lab"),
        live_counters: parse_counters(fixture, "live"),
    }
}

fn semantics(surface_id: &str, counters: &[(String, i64)]) -> NormalizedSemantics {
    let mut resource_surface = ResourceSurfaceRecord::empty(surface_id);
    for (name, value) in counters {
        resource_surface = resource_surface.with_counter(name.clone(), *value);
    }

    NormalizedSemantics {
        terminal_outcome: TerminalOutcome::ok(),
        cancellation: CancellationRecord::none(),
        loser_drain: LoserDrainRecord::not_applicable(),
        region_close: capture_region_close(true, true),
        obligation_balance: ObligationBalanceRecord::zero(),
        resource_surface,
    }
}

fn scenario_identity(scenario: &FilesystemScenario) -> DualRunScenarioIdentity {
    let seed_plan = SeedPlan::inherit(
        scenario.canonical_seed,
        format!("seed.{}.v2.filesystem", scenario.scenario_id),
    );

    DualRunScenarioIdentity::phase1(
        &scenario.scenario_id,
        &scenario.surface_id,
        &scenario.surface_contract_version,
        &scenario.description,
        scenario.canonical_seed,
    )
    .with_seed_plan(seed_plan)
    .with_metadata("bead_id", "asupersync-idea-wizard-fifth-wave-3gaiun.5.2")
    .with_metadata("adapter_family", "captured_filesystem")
    .with_metadata("artifact_path", ARTIFACT_PATH)
}

fn run_filesystem_scenario(scenario: &FilesystemScenario) -> DualRunResult {
    let identity = scenario_identity(scenario);
    let surface_id = scenario.surface_id.clone();
    let live_counters = scenario.live_counters.clone();
    let live_result = run_live_adapter(&identity, |_config, witness| {
        witness.set_outcome(TerminalOutcome::ok());
        witness.set_region_close(capture_region_close(true, true));
        witness.set_obligation_balance(ObligationBalanceRecord::zero());
        for (name, value) in &live_counters {
            witness.record_counter(name, *value);
        }
        witness.note_nondeterminism(
            "captured filesystem fixture; raw host paths, metadata, and timing excluded",
        );
    });
    let lab_counters = scenario.lab_counters.clone();

    DualRunHarness::from_identity(identity)
        .lab(move |_config| semantics(&surface_id, &lab_counters))
        .live_result(move |_seed, _entropy| live_result)
        .run()
}

fn runner_report(scenario: &FilesystemScenario, result: &DualRunResult) -> Value {
    let actual_verdict = if scenario.raw_host_surface {
        RunnerVerdict::Skip
    } else if result.passed() {
        RunnerVerdict::Pass
    } else {
        RunnerVerdict::Fail
    };
    let policy_class = if actual_verdict == RunnerVerdict::Skip {
        "unsupported_surface".to_string()
    } else {
        result.policy.provisional_class.to_string()
    };

    json!({
        "schema_version": REPORT_SCHEMA,
        "scenario_id": scenario.scenario_id,
        "surface_family": "filesystem",
        "adapter_family": "captured_filesystem",
        "expected_verdict": scenario.expected_verdict.as_str(),
        "actual_verdict": actual_verdict.as_str(),
        "policy_class": policy_class,
        "lab_deterministic": true,
        "live_adapter_executed": true,
        "skip_is_pass": false,
        "artifact_bundle": {
            "runner_artifact": ARTIFACT_PATH,
            "docs": "docs/lab_live_v2_filesystem_runner.md"
        },
        "structured_logs": [
            {
                "event": "LAB_FIXTURE_LOADED",
                "scenario_id": scenario.scenario_id,
                "counter_count": scenario.lab_counters.len()
            },
            {
                "event": "LIVE_ADAPTER_CAPTURED",
                "scenario_id": scenario.scenario_id,
                "counter_count": scenario.live_counters.len()
            },
            {
                "event": "FILESYSTEM_RUNNER_VERDICT",
                "scenario_id": scenario.scenario_id,
                "verdict": actual_verdict.as_str()
            }
        ],
        "mismatches": result.verdict.mismatches.iter().map(|mismatch| {
            json!({
                "field": mismatch.field,
                "description": mismatch.description,
                "lab_value": mismatch.lab_value,
                "live_value": mismatch.live_value,
            })
        }).collect::<Vec<_>>(),
        "repro_command": result.lab.provenance.default_repro_command(),
        "no_claims": [
            "does not prove raw host filesystem parity",
            "does not prove process or signal support",
            "does not prove broad workspace health"
        ]
    })
}

fn assert_report_matches_fixture(path: &str, fixture: &Value) -> Value {
    let scenario = parse_scenario(fixture);
    let result = run_filesystem_scenario(&scenario);
    let report = runner_report(&scenario, &result);

    assert_eq!(
        report["expected_verdict"],
        scenario.expected_verdict.as_str(),
        "{path} must preserve expected verdict"
    );
    assert_eq!(
        report["actual_verdict"],
        scenario.expected_verdict.as_str(),
        "{path} must produce expected verdict"
    );
    assert_eq!(report["schema_version"], REPORT_SCHEMA);
    assert_eq!(report["live_adapter_executed"], true);
    assert_eq!(report["artifact_bundle"]["runner_artifact"], ARTIFACT_PATH);
    assert!(
        report["repro_command"]
            .as_str()
            .expect("repro command")
            .starts_with("rch exec -- env ASUPERSYNC_SEED=")
    );

    report
}

#[test]
fn contract_links_sources_and_existing_policy_docs() {
    let artifact = artifact();
    assert_eq!(
        artifact["schema_version"],
        "lab-live-v2-filesystem-runner-artifact-v1"
    );
    assert_eq!(
        artifact["bead_id"],
        "asupersync-idea-wizard-fifth-wave-3gaiun.5.2"
    );
    assert_eq!(artifact["artifact_path"], ARTIFACT_PATH);
    assert_eq!(artifact["adapter_family"], "captured_filesystem");
    assert_eq!(
        artifact["runner_contract"]["live_adapter"],
        "asupersync::lab::run_live_adapter"
    );

    let source_docs = artifact["source_docs"]
        .as_array()
        .expect("source docs must be an array");
    for doc in [
        "docs/lab_live_differential_scope_matrix.md",
        "docs/lab_live_timing_platform_policy.md",
        "docs/lab_live_v2_filesystem_runner.md",
    ] {
        assert!(
            source_docs.iter().any(|entry| entry == doc),
            "missing {doc}"
        );
    }

    let proof_lane = artifact["proof_lane"].as_str().expect("proof lane");
    assert!(proof_lane.starts_with("RCH_REQUIRE_REMOTE=1 "));
    assert!(proof_lane.contains("cargo test -p asupersync"));
    assert!(proof_lane.contains("--test lab_live_v2_filesystem_runner_contract"));
}

#[test]
fn fixtures_define_three_filesystem_scenarios() {
    let artifact = artifact();
    let fixtures = artifact["fixtures"].as_array().expect("fixtures");
    assert_eq!(fixtures.len(), 3);

    let mut saw_pass = false;
    let mut saw_fail = false;
    let mut saw_skip = false;
    for (path, fixture) in fixture_values() {
        let scenario = parse_scenario(&fixture);
        assert!(
            fixtures.iter().any(|entry| {
                entry["scenario_id"] == scenario.scenario_id && entry["fixture_path"] == path
            }),
            "artifact must link fixture {path}"
        );
        assert!(!scenario.lab_counters.is_empty(), "{path} lab counters");
        assert!(!scenario.live_counters.is_empty(), "{path} live counters");
        match scenario.expected_verdict {
            RunnerVerdict::Pass => saw_pass = true,
            RunnerVerdict::Fail => saw_fail = true,
            RunnerVerdict::Skip => {
                saw_skip = true;
                assert!(
                    scenario.raw_host_surface,
                    "skip fixture must be raw-host gated"
                );
            }
        }
    }

    assert!(saw_pass && saw_fail && saw_skip);
}

#[test]
fn captured_filesystem_runner_executes_pass_fail_and_skip() {
    let mut reports = Vec::new();
    for (path, fixture) in fixture_values() {
        reports.push(assert_report_matches_fixture(path, &fixture));
    }

    assert!(
        reports
            .iter()
            .any(|report| report["actual_verdict"] == "pass"),
        "pass report missing"
    );
    assert!(
        reports
            .iter()
            .any(|report| report["actual_verdict"] == "fail"),
        "fail report missing"
    );
    assert!(
        reports
            .iter()
            .any(|report| report["actual_verdict"] == "skip"),
        "skip report missing"
    );
}

#[test]
fn rename_visibility_failure_preserves_counter_mismatch() {
    let fixture: Value = serde_json::from_str(RENAME_VISIBILITY_FAIL).unwrap();
    let scenario = parse_scenario(&fixture);
    let result = run_filesystem_scenario(&scenario);
    assert!(!result.passed(), "rename visibility fixture must fail");

    let fields = result
        .verdict
        .mismatches
        .iter()
        .map(|mismatch| mismatch.field.as_str())
        .collect::<Vec<_>>();
    assert!(
        fields
            .iter()
            .any(|field| field.contains("temp_visible_before_commit")),
        "missing temp visibility mismatch: {fields:?}"
    );
}

#[test]
fn raw_host_skip_is_not_a_pass() {
    let fixture: Value = serde_json::from_str(RAW_HOST_SKIP).unwrap();
    let scenario = parse_scenario(&fixture);
    assert!(scenario.raw_host_surface);

    let result = run_filesystem_scenario(&scenario);
    let report = runner_report(&scenario, &result);
    assert_eq!(report["actual_verdict"], "skip");
    assert_eq!(report["policy_class"], "unsupported_surface");
    assert_eq!(report["skip_is_pass"], false);
    assert_eq!(report["live_adapter_executed"], true);
    assert!(
        report["no_claims"]
            .as_array()
            .unwrap()
            .iter()
            .any(|claim| claim == "does not prove raw host filesystem parity")
    );
}

#[test]
fn docs_explain_capture_boundary_and_no_claims() {
    let docs = include_str!("../docs/lab_live_v2_filesystem_runner.md");
    for marker in [
        "captured filesystem",
        "raw host filesystem probes as `skip`, not `pass`",
        "does not prove process or signal support",
        "raw OS filesystem equivalence",
        "artifacts/lab_live_v2_filesystem_runner_v1.json",
    ] {
        assert!(docs.contains(marker), "missing docs marker {marker}");
    }
}
