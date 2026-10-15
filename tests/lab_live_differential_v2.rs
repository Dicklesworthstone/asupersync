#![allow(missing_docs)]

use asupersync::lab::{
    CancellationRecord, DualRunHarness, DualRunResult, DualRunScenarioIdentity, LoserDrainRecord,
    NormalizedSemantics, ObligationBalanceRecord, ResourceSurfaceRecord, SeedPlan, TerminalOutcome,
    capture_region_close, run_live_adapter,
};
use serde_json::{Value, json};

const ARTIFACT: &str = include_str!("../artifacts/lab_live_differential_v2_scenarios_v1.json");
const ARTIFACT_PATH: &str = "artifacts/lab_live_differential_v2_scenarios_v1.json";
const TRANSCRIPT_SCHEMA: &str = "lab-live-differential-v2-transcript-v1";
const EQUIVALENCE_SCENARIO: &str = "xeh8m0.lab_live_v2.semantic_equivalence";
const REGION_DIVERGENCE_SCENARIO: &str = "xeh8m0.lab_live_v2.region_close_divergence";

fn artifact() -> Value {
    serde_json::from_str(ARTIFACT).expect("lab-live v2 artifact must be valid JSON")
}

fn pilot<'a>(artifact: &'a Value, scenario_id: &str) -> &'a Value {
    artifact["pilot_scenarios"]
        .as_array()
        .expect("pilot_scenarios must be an array")
        .iter()
        .find(|scenario| scenario["scenario_id"] == scenario_id)
        .expect("requested pilot scenario must exist")
}

fn scenario_seed(pilot: &Value) -> u64 {
    pilot["canonical_seed"]
        .as_u64()
        .expect("pilot canonical_seed must be a u64")
}

fn scenario_identity(pilot: &Value) -> DualRunScenarioIdentity {
    let scenario_id = pilot["scenario_id"]
        .as_str()
        .expect("pilot scenario_id must be a string");
    let seed_plan = SeedPlan::inherit(scenario_seed(pilot), format!("seed.{scenario_id}.v2"));

    DualRunScenarioIdentity::phase1(
        scenario_id,
        pilot["surface_id"]
            .as_str()
            .expect("pilot surface_id must be a string"),
        pilot["surface_contract_version"]
            .as_str()
            .expect("pilot surface_contract_version must be a string"),
        pilot["description"]
            .as_str()
            .expect("pilot description must be a string"),
        seed_plan.canonical_seed,
    )
    .with_seed_plan(seed_plan)
    .with_metadata("bead_id", "asupersync-xeh8m0.4")
    .with_metadata(
        "transcript_artifact_path",
        pilot["transcript_artifact_path"].as_str().unwrap(),
    )
}

fn semantics(
    surface_id: &str,
    live_children_joined: bool,
    finalizers_done: bool,
    counters: &[(&str, i64)],
) -> NormalizedSemantics {
    let mut resource_surface = ResourceSurfaceRecord::empty(surface_id);
    for (name, value) in counters {
        resource_surface = resource_surface.with_counter(*name, *value);
    }

    NormalizedSemantics {
        terminal_outcome: TerminalOutcome::ok(),
        cancellation: CancellationRecord::none(),
        loser_drain: LoserDrainRecord::not_applicable(),
        region_close: capture_region_close(live_children_joined, finalizers_done),
        obligation_balance: ObligationBalanceRecord::zero(),
        resource_surface,
    }
}

fn run_equivalence_pilot(pilot: &Value) -> DualRunResult {
    let identity = scenario_identity(pilot);
    let surface_id = identity.surface_id.clone();
    let live_result = run_live_adapter(&identity, |config, witness| {
        witness.set_outcome(TerminalOutcome::ok());
        witness.set_region_close(capture_region_close(true, true));
        witness.set_obligation_balance(ObligationBalanceRecord::zero());
        witness.record_counter("schedule_decisions", 2);
        witness.record_counter("seed_low_bits", i64::from((config.seed & 0xFF) as u8));
    });

    DualRunHarness::from_identity(identity)
        .lab(move |config| {
            semantics(
                &surface_id,
                true,
                true,
                &[
                    ("schedule_decisions", 2),
                    ("seed_low_bits", i64::from((config.seed & 0xFF) as u8)),
                ],
            )
        })
        .live_result(move |_seed, _entropy| live_result)
        .run()
}

fn run_region_divergence_pilot(pilot: &Value) -> DualRunResult {
    let identity = scenario_identity(pilot);
    let surface_id = identity.surface_id.clone();
    let live_result = run_live_adapter(&identity, |config, witness| {
        witness.set_outcome(TerminalOutcome::ok());
        witness.set_region_close(capture_region_close(false, true));
        witness.set_obligation_balance(ObligationBalanceRecord::zero());
        witness.record_counter("schedule_decisions", 2);
        witness.record_counter("seed_low_bits", i64::from((config.seed & 0xFF) as u8));
    });

    DualRunHarness::from_identity(identity)
        .lab(move |config| {
            semantics(
                &surface_id,
                true,
                true,
                &[
                    ("schedule_decisions", 2),
                    ("seed_low_bits", i64::from((config.seed & 0xFF) as u8)),
                ],
            )
        })
        .live_result(move |_seed, _entropy| live_result)
        .run()
}

fn transcript(result: &DualRunResult) -> Value {
    let live_divergence_point = result
        .verdict
        .mismatches
        .first()
        .map_or(Value::Null, |mismatch| {
            json!({
                "field": mismatch.field,
                "description": mismatch.description,
                "lab_value": mismatch.lab_value,
                "live_value": mismatch.live_value,
            })
        });

    json!({
        "schema_version": TRANSCRIPT_SCHEMA,
        "scenario_id": result.verdict.scenario_id,
        "surface_id": result.verdict.surface_id,
        "seed": result.seed_lineage.canonical_seed,
        "schedule_decisions": [
            {
                "runtime": "lab",
                "decision_seq": 0,
                "seed": result.seed_lineage.lab_effective_seed,
                "source": "SeedPlan::effective_lab_seed"
            },
            {
                "runtime": "live",
                "decision_seq": 0,
                "seed": result.seed_lineage.live_effective_seed,
                "source": "SeedPlan::effective_live_seed"
            }
        ],
        "live_divergence_point": live_divergence_point,
        "minimized_replay_handle": {
            "kind": "seed_lineage",
            "seed_lineage_id": result.seed_lineage.seed_lineage_id,
            "lab_seed": result.seed_lineage.lab_effective_seed,
            "live_seed": result.seed_lineage.live_effective_seed,
            "repro_command": result.lab.provenance.default_repro_command()
        },
        "verdict": result.policy.provisional_class.to_string(),
        "mismatches": result.verdict.mismatches.iter().map(|mismatch| {
            json!({
                "field": mismatch.field,
                "description": mismatch.description,
                "lab_value": mismatch.lab_value,
                "live_value": mismatch.live_value,
            })
        }).collect::<Vec<_>>(),
    })
}

#[test]
fn artifact_declares_v2_schema_and_proof_lane() {
    let artifact = artifact();
    assert_eq!(
        artifact["schema_version"],
        "lab-live-differential-v2-scenarios-v1"
    );
    assert_eq!(artifact["bead_id"], "asupersync-xeh8m0.4");
    assert_eq!(artifact["artifact_path"], ARTIFACT_PATH);

    let proof_lane = artifact["proof_lane"].as_str().expect("proof lane");
    assert!(proof_lane.starts_with("rch exec -- "));
    assert!(proof_lane.contains("cargo test -p asupersync --test lab_live_differential_v2"));

    assert_eq!(
        artifact["runtime_seam"]["lab"],
        "asupersync::lab::DualRunHarness"
    );
    assert_eq!(
        artifact["runtime_seam"]["live"],
        "asupersync::lab::run_live_adapter"
    );
}

#[test]
fn artifact_defines_required_transcript_fields_and_two_pilots() {
    let artifact = artifact();
    let fields = artifact["transcript_schema"]["required_fields"]
        .as_array()
        .expect("required transcript fields");
    for field in [
        "schema_version",
        "scenario_id",
        "surface_id",
        "seed",
        "schedule_decisions",
        "live_divergence_point",
        "minimized_replay_handle",
        "verdict",
    ] {
        assert!(fields.iter().any(|entry| entry == field), "missing {field}");
    }

    let pilots = artifact["pilot_scenarios"]
        .as_array()
        .expect("pilot scenarios");
    assert_eq!(pilots.len(), 2);
    assert_eq!(pilot(&artifact, EQUIVALENCE_SCENARIO)["phase"], "Phase 1");
    assert_eq!(
        pilot(&artifact, REGION_DIVERGENCE_SCENARIO)["phase"],
        "Phase 1"
    );
}

#[test]
fn semantic_equivalence_pilot_emits_pass_transcript() {
    let artifact = artifact();
    let result = run_equivalence_pilot(pilot(&artifact, EQUIVALENCE_SCENARIO));
    assert!(result.passed(), "equivalence pilot should pass: {result}");

    let transcript = transcript(&result);
    assert_eq!(transcript["schema_version"], TRANSCRIPT_SCHEMA);
    assert_eq!(transcript["scenario_id"], EQUIVALENCE_SCENARIO);
    assert_eq!(transcript["verdict"], "pass");
    assert!(transcript["live_divergence_point"].is_null());
    assert_eq!(
        transcript["schedule_decisions"].as_array().unwrap().len(),
        2
    );
    assert!(
        transcript["minimized_replay_handle"]["repro_command"]
            .as_str()
            .unwrap()
            .starts_with("rch exec -- env ASUPERSYNC_SEED=")
    );
}

#[test]
fn region_close_divergence_pilot_pins_first_live_mismatch() {
    let artifact = artifact();
    let result = run_region_divergence_pilot(pilot(&artifact, REGION_DIVERGENCE_SCENARIO));
    assert!(!result.passed(), "region divergence pilot must fail");

    let transcript = transcript(&result);
    assert_eq!(transcript["scenario_id"], REGION_DIVERGENCE_SCENARIO);
    assert_eq!(transcript["verdict"], "hard_contract_break");
    assert_eq!(
        transcript["live_divergence_point"]["field"],
        "semantics.region_close.quiescent"
    );
    assert_eq!(transcript["live_divergence_point"]["lab_value"], "true");
    assert_eq!(transcript["live_divergence_point"]["live_value"], "false");
    assert_eq!(
        transcript["minimized_replay_handle"]["kind"],
        "seed_lineage"
    );
}
