#![allow(missing_docs)]
//! Golden Fixture Validation Tests (SEM-12.8)
//!
//! Loads golden fixture data from `tests/fixtures/semantic_golden/` and validates
//! that runtime behavior matches the golden expected values. These tests serve as
//! regression guards: any semantic drift requires explicit review and justification
//! per the update policy in `manifest.json`.
//!
//! Bead: asupersync-3cddg.12.8
//! Rule IDs exercised: #7, #8, #29, #30, #31, #39, #42, #46

#[cfg(feature = "test-internals")]
use asupersync::lab::{
    ChaosSection, DualRunScenarioIdentity, LabSection, NetworkSection, Scenario, ScenarioRunner,
    SeedPlan, SporkScenarioConfig, SporkScenarioRunner, SporkScenarioSpec,
};
#[cfg(feature = "test-internals")]
use asupersync::spork::prelude::AppSpec;
#[cfg(feature = "test-internals")]
use asupersync::test_logging::{ReproManifest, TestContext};
use serde_json::Value;
#[cfg(feature = "test-internals")]
use serde_json::json;
#[cfg(feature = "test-internals")]
use std::collections::BTreeMap;
use std::collections::HashMap;

use asupersync::combinator::timeout::effective_deadline;
use asupersync::lab::fuzz::{FuzzConfig, FuzzHarness};
use asupersync::types::Time;
use asupersync::types::budget::Budget;
use asupersync::types::cancel::{CancelKind, CancelReason};
use asupersync::types::outcome::{Outcome, PanicPayload, Severity, join_outcomes};

// ─────────────────────────────────────────────────────────────────────────────
// Fixture loading helpers
// ─────────────────────────────────────────────────────────────────────────────

const FIXTURE_DIR: &str = "tests/fixtures/semantic_golden";

fn load_fixture(filename: &str) -> Value {
    let path = format!("{FIXTURE_DIR}/{filename}");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to load fixture {path}: {e}"));
    serde_json::from_str(&content).unwrap_or_else(|e| panic!("failed to parse fixture {path}: {e}"))
}

fn load_manifest() -> Value {
    load_fixture("manifest.json")
}

#[cfg(feature = "test-internals")]
fn assert_pretty_json_eq(label: &str, actual: &Value, expected: &Value) {
    if actual != expected {
        let actual_pretty =
            serde_json::to_string_pretty(actual).expect("serialize actual golden JSON");
        let expected_pretty =
            serde_json::to_string_pretty(expected).expect("serialize expected golden JSON");
        panic!("{label} mismatch\nexpected:\n{expected_pretty}\nactual:\n{actual_pretty}");
    }
}

#[cfg(feature = "test-internals")]
fn build_contract_identity() -> DualRunScenarioIdentity {
    let seed_plan = SeedPlan::inherit(42, "seed.phase1.cancel.race.one_loser.v1")
        .with_live_override(99)
        .with_entropy_seed(777);
    DualRunScenarioIdentity::phase1(
        "phase1.cancel.race.one_loser",
        "cancel.race",
        "cancel.race.v1",
        "Single loser is cancelled and drained",
        seed_plan.canonical_seed,
    )
    .with_seed_plan(seed_plan)
}

#[cfg(feature = "test-internals")]
fn build_contract_scenario(identity: &DualRunScenarioIdentity) -> Scenario {
    let mut metadata = BTreeMap::new();
    metadata.insert("surface_id".into(), identity.surface_id.clone());
    metadata.insert(
        "surface_contract_version".into(),
        identity.surface_contract_version.clone(),
    );
    metadata.insert(
        "seed_lineage_id".into(),
        identity.seed_plan.seed_lineage_id.clone(),
    );

    Scenario {
        schema_version: 1,
        id: identity.scenario_id.clone(),
        description: identity.description.clone(),
        lab: LabSection {
            seed: identity.seed_plan.canonical_seed,
            ..LabSection::default()
        },
        chaos: ChaosSection::Off,
        network: NetworkSection::default(),
        faults: Vec::new(),
        participants: Vec::new(),
        oracles: vec!["all".to_string()],
        cancellation: None,
        include: Vec::new(),
        metadata,
    }
}

#[cfg(feature = "test-internals")]
fn run_minimal_spork(identity: &DualRunScenarioIdentity) -> asupersync::lab::SporkScenarioResult {
    let mut runner = SporkScenarioRunner::new();
    runner
        .register(
            SporkScenarioSpec::new(&identity.scenario_id, |_config| {
                AppSpec::new("dual_run_contract_app")
            })
            .with_description(identity.description.clone())
            .with_expected_invariants(["no_task_leaks", "quiescence_on_close"])
            .with_default_config(SporkScenarioConfig {
                seed: identity.seed_plan.canonical_seed,
                ..SporkScenarioConfig::default()
            })
            .with_surface_id(identity.surface_id.clone())
            .with_surface_contract_version(identity.surface_contract_version.clone())
            .with_seed_lineage_id(identity.seed_plan.seed_lineage_id.clone()),
        )
        .expect("register spork scenario");

    runner
        .run(&identity.scenario_id)
        .expect("run spork scenario")
}

#[allow(clippy::too_many_lines)]
#[cfg(feature = "test-internals")]
fn build_dual_run_harness_contract_fixture() -> Value {
    let identity = build_contract_identity();
    let scenario = build_contract_scenario(&identity);
    let lab_config = identity.to_lab_config();
    let lab_replay = identity.lab_replay_metadata();
    let lab_result = ScenarioRunner::run_with_identity(&scenario, &identity)
        .expect("lab scenario runner smoke contract must execute");
    let spork_result = run_minimal_spork(&identity);
    let live_ctx = TestContext::from_live_dual_run(&identity);
    let live_replay = live_ctx
        .replay_metadata
        .as_ref()
        .expect("dual-run live context should include replay metadata");
    let seed_lineage = live_ctx
        .seed_lineage
        .as_ref()
        .expect("dual-run live context should include seed lineage");
    let failure_manifest = ReproManifest::from_context(&live_ctx, false)
        .with_failure_reason("contract smoke mismatch")
        .with_phases(vec!["setup".into(), "execute".into(), "compare".into()]);
    let failure_value =
        serde_json::to_value(&failure_manifest).expect("serialize failure manifest");

    json!({
        "schema_version": "semantic-golden-fixture-v1",
        "fixture_id": "golden-dual-run-harness-contract",
        "rule_ids": [
            "differential.shared_harness.contract",
            "differential.seed_lineage.roundtrip"
        ],
        "description": "Expected shared dual-run identity and provenance records for the canonical harness contract case",
        "identity": {
            "schema_version": identity.schema_version,
            "scenario_id": identity.scenario_id,
            "surface_id": identity.surface_id,
            "surface_contract_version": identity.surface_contract_version,
            "description": identity.description,
            "phase": identity.phase,
            "seed_plan": {
                "canonical_seed": identity.seed_plan.canonical_seed,
                "seed_lineage_id": identity.seed_plan.seed_lineage_id,
                "lab_seed_mode": identity.seed_plan.lab_seed_mode,
                "live_seed_mode": identity.seed_plan.live_seed_mode,
                "replay_policy": identity.seed_plan.replay_policy,
                "lab_seed_override": identity.seed_plan.lab_seed_override,
                "live_seed_override": identity.seed_plan.live_seed_override,
                "entropy_seed_override": identity.seed_plan.entropy_seed_override
            }
        },
        "lab_runtime": {
            "seed": lab_config.seed,
            "entropy_seed": lab_config.entropy_seed
        },
        "lab_replay": {
            "execution_instance_id": lab_replay.instance.key(),
            "effective_seed": lab_replay.effective_seed,
            "effective_entropy_seed": lab_replay.effective_entropy_seed,
            "surface_id": lab_replay.family.surface_id,
            "surface_contract_version": lab_replay.family.surface_contract_version
        },
        "live_context": {
            "adapter": live_ctx.adapter.as_deref().expect("live adapter"),
            "seed": live_ctx.seed,
            "execution_instance_id": live_replay.instance.key(),
            "surface_id": live_replay.family.surface_id,
            "surface_contract_version": live_replay.family.surface_contract_version,
            "seed_lineage_id": seed_lineage.seed_lineage_id
        },
        "seed_lineage": {
            "seed_lineage_id": seed_lineage.seed_lineage_id.clone(),
            "canonical_seed": seed_lineage.canonical_seed,
            "lab_effective_seed": seed_lineage.lab_effective_seed,
            "live_effective_seed": seed_lineage.live_effective_seed,
            "lab_seed_mode": seed_lineage.lab_seed_mode,
            "live_seed_mode": seed_lineage.live_seed_mode,
            "lab_entropy_seed": seed_lineage.lab_entropy_seed,
            "live_entropy_seed": seed_lineage.live_entropy_seed,
            "replay_policy": seed_lineage.replay_policy,
            "seeds_match": seed_lineage.seeds_match
        },
        "invariants": [
            "Scenario family identity is shared across lab and live adapters",
            "Seed lineage records explicit live overrides instead of hiding them",
            "Live current-thread provenance keeps the same surface contract as lab",
            "Explicit entropy overrides are retained in both replay metadata and seed lineage"
        ],
        "smoke_snapshot": {
            "scenario_id": identity.scenario_id,
            "surface_id": identity.surface_id,
            "surface_contract_version": identity.surface_contract_version,
            "seed_lineage_id": identity.seed_plan.seed_lineage_id,
            "adapters": {
                "lab": lab_result.adapter,
                "spork": spork_result.adapter,
                "live": live_ctx.adapter.as_deref().expect("live adapter"),
            },
            "execution_instances": {
                "lab": lab_result.replay_metadata.instance.key(),
                "spork": spork_result.replay_metadata.instance.key(),
                "live": live_replay.instance.key(),
            },
            "passed": {
                "lab": lab_result.passed(),
                "spork": spork_result.passed(),
            }
        },
        "failure_manifest_excerpt": {
            "scenario_id": failure_value["scenario_id"],
            "adapter": failure_value["adapter"],
            "surface_id": failure_value["replay_metadata"]["family"]["surface_id"],
            "surface_contract_version": failure_value["replay_metadata"]["family"]["surface_contract_version"],
            "seed_lineage_id": failure_value["seed_lineage"]["seed_lineage_id"],
            "failure_reason": failure_value["failure_reason"],
            "phases_executed": failure_value["phases_executed"],
        }
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Manifest validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn golden_manifest_schema_valid() {
    let manifest = load_manifest();

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("semantic-golden-manifest-v1"),
        "manifest schema version must be v1"
    );

    let fixtures = manifest["fixtures"]
        .as_array()
        .expect("fixtures must be array");
    assert!(
        !fixtures.is_empty(),
        "manifest must have at least one fixture"
    );

    for fixture in fixtures {
        let id = fixture["id"].as_str().expect("fixture must have id");
        assert!(
            id.starts_with("golden-"),
            "fixture id must start with 'golden-': {id}"
        );
        let file = fixture["file"].as_str().expect("fixture must have file");
        let path = format!("{FIXTURE_DIR}/{file}");
        assert!(
            std::path::Path::new(&path).exists(),
            "fixture file must exist: {path}"
        );
        let rule_ids = fixture["rule_ids"]
            .as_array()
            .expect("fixture must have rule_ids");
        assert!(
            !rule_ids.is_empty(),
            "fixture {id} must reference at least one rule_id"
        );
    }

    let change_log = manifest["change_log"]
        .as_array()
        .expect("manifest must have change_log");
    assert!(
        !change_log.is_empty(),
        "manifest change_log must have at least one entry"
    );
}

#[test]
fn golden_manifest_fixtures_all_loadable() {
    let manifest = load_manifest();
    let fixtures = manifest["fixtures"].as_array().unwrap();

    for fixture in fixtures {
        let id = fixture["id"].as_str().unwrap();
        let file = fixture["file"].as_str().unwrap();
        let data = load_fixture(file);
        assert_eq!(
            data["fixture_id"].as_str(),
            Some(id),
            "fixture_id in {file} must match manifest id"
        );
        assert_eq!(
            data["schema_version"].as_str(),
            Some("semantic-golden-fixture-v1"),
            "fixture {id} must have schema_version"
        );
    }
}

#[cfg(feature = "test-internals")]
#[test]
fn golden_dual_run_harness_contract_matches_runtime_helpers() {
    let expected = load_fixture("dual_run_harness_contract.json");
    let actual = build_dual_run_harness_contract_fixture();
    assert_pretty_json_eq("golden dual-run harness contract", &actual, &expected);
}

// ─────────────────────────────────────────────────────────────────────────────
// Severity lattice (rules #29, #30)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn golden_severity_lattice_values() {
    let data = load_fixture("severity_lattice.json");
    let entries = data["entries"].as_array().expect("entries must be array");
    assert_eq!(entries.len(), 4, "exactly 4 outcome variants");

    let expected: HashMap<&str, (u8, &str)> = HashMap::from([
        ("Ok", (0, "ok")),
        ("Err", (1, "err")),
        ("Cancelled", (2, "cancelled")),
        ("Panicked", (3, "panicked")),
    ]);

    for entry in entries {
        let variant = entry["variant"].as_str().unwrap();
        let sev_val = entry["severity_value"].as_u64().unwrap() as u8;
        let sev_name = entry["severity_name"].as_str().unwrap();

        let (exp_val, exp_name) = expected
            .get(variant)
            .unwrap_or_else(|| panic!("unexpected variant: {variant}"));
        assert_eq!(sev_val, *exp_val, "severity value for {variant}");
        assert_eq!(sev_name, *exp_name, "severity name for {variant}");
    }

    // Validate against actual runtime types
    let ok: Outcome<(), ()> = Outcome::ok(());
    let err: Outcome<(), ()> = Outcome::err(());
    let cancelled: Outcome<(), ()> = Outcome::Cancelled(CancelReason::user("golden-test"));
    let panicked: Outcome<(), ()> = Outcome::Panicked(PanicPayload::new("golden-test"));

    assert_eq!(ok.severity(), Severity::Ok);
    assert_eq!(err.severity(), Severity::Err);
    assert_eq!(cancelled.severity(), Severity::Cancelled);
    assert_eq!(panicked.severity(), Severity::Panicked);

    assert_eq!(Severity::Ok.as_u8(), 0);
    assert_eq!(Severity::Err.as_u8(), 1);
    assert_eq!(Severity::Cancelled.as_u8(), 2);
    assert_eq!(Severity::Panicked.as_u8(), 3);

    // Round-trip: from_u8(as_u8(s)) == Some(s)
    for val in 0..=3u8 {
        let s = Severity::from_u8(val).expect("valid severity");
        assert_eq!(s.as_u8(), val, "round-trip for severity {val}");
    }
    assert!(Severity::from_u8(4).is_none(), "4 is out of range");
}

#[test]
fn golden_severity_total_order() {
    assert!(Severity::Ok < Severity::Err);
    assert!(Severity::Err < Severity::Cancelled);
    assert!(Severity::Cancelled < Severity::Panicked);
}

// ─────────────────────────────────────────────────────────────────────────────
// Cancel severity map (rules #7, #8)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn golden_cancel_severity_map() {
    let data = load_fixture("cancel_severity_map.json");
    let entries = data["entries"].as_array().expect("entries must be array");
    assert_eq!(entries.len(), 11, "exactly 11 CancelKind variants");

    let all_kinds: [CancelKind; 11] = [
        CancelKind::User,
        CancelKind::Timeout,
        CancelKind::Deadline,
        CancelKind::PollQuota,
        CancelKind::CostBudget,
        CancelKind::FailFast,
        CancelKind::RaceLost,
        CancelKind::LinkedExit,
        CancelKind::ParentCancelled,
        CancelKind::ResourceUnavailable,
        CancelKind::Shutdown,
    ];

    let kind_name_to_enum: HashMap<&str, CancelKind> = HashMap::from([
        ("User", CancelKind::User),
        ("Timeout", CancelKind::Timeout),
        ("Deadline", CancelKind::Deadline),
        ("PollQuota", CancelKind::PollQuota),
        ("CostBudget", CancelKind::CostBudget),
        ("FailFast", CancelKind::FailFast),
        ("RaceLost", CancelKind::RaceLost),
        ("LinkedExit", CancelKind::LinkedExit),
        ("ParentCancelled", CancelKind::ParentCancelled),
        ("ResourceUnavailable", CancelKind::ResourceUnavailable),
        ("Shutdown", CancelKind::Shutdown),
    ]);

    // Verify golden data matches runtime
    for entry in entries {
        let kind_name = entry["kind"].as_str().unwrap();
        let golden_severity = entry["severity"].as_u64().unwrap() as u8;
        let kind = kind_name_to_enum
            .get(kind_name)
            .unwrap_or_else(|| panic!("unknown CancelKind in golden data: {kind_name}"));
        assert_eq!(
            kind.severity(),
            golden_severity,
            "severity mismatch for CancelKind::{kind_name}: golden={golden_severity}, runtime={}",
            kind.severity()
        );
    }

    // Verify exhaustiveness: all runtime kinds are in the golden data
    let golden_kinds: Vec<&str> = entries
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    for kind in &all_kinds {
        let name = format!("{kind:?}");
        assert!(
            golden_kinds.contains(&name.as_str()),
            "CancelKind::{name} missing from golden data"
        );
    }
}

#[test]
fn golden_cancel_severity_ordering() {
    // Verify the ordering invariant: User < Timeout = Deadline < ... < Shutdown
    assert!(CancelKind::User.severity() < CancelKind::Timeout.severity());
    assert_eq!(
        CancelKind::Timeout.severity(),
        CancelKind::Deadline.severity()
    );
    assert!(CancelKind::Deadline.severity() < CancelKind::PollQuota.severity());
    assert_eq!(
        CancelKind::PollQuota.severity(),
        CancelKind::CostBudget.severity()
    );
    assert!(CancelKind::CostBudget.severity() < CancelKind::FailFast.severity());
    assert_eq!(
        CancelKind::FailFast.severity(),
        CancelKind::RaceLost.severity()
    );
    assert_eq!(
        CancelKind::RaceLost.severity(),
        CancelKind::LinkedExit.severity()
    );
    assert!(CancelKind::LinkedExit.severity() < CancelKind::ParentCancelled.severity());
    assert_eq!(
        CancelKind::ParentCancelled.severity(),
        CancelKind::ResourceUnavailable.severity()
    );
    assert!(CancelKind::ResourceUnavailable.severity() < CancelKind::Shutdown.severity());
}

// ─────────────────────────────────────────────────────────────────────────────
// Join associativity (rules #31, #42)
// ─────────────────────────────────────────────────────────────────────────────

fn make_outcome(severity: u8) -> Outcome<u8, u8> {
    match severity {
        0 => Outcome::ok(0),
        1 => Outcome::err(0),
        2 => Outcome::Cancelled(CancelReason::user("golden-join")),
        3 => Outcome::Panicked(PanicPayload::new("golden-join")),
        _ => panic!("invalid severity: {severity}"),
    }
}

#[test]
fn golden_join_associativity_64_triples() {
    let data = load_fixture("join_associativity.json");
    let triples = data["triples"].as_array().expect("triples must be array");
    assert_eq!(triples.len(), 64, "4^3 = 64 triples");

    for triple in triples {
        let a = triple["a"].as_u64().unwrap() as u8;
        let b = triple["b"].as_u64().unwrap() as u8;
        let c = triple["c"].as_u64().unwrap() as u8;
        let golden_ab_c = triple["join_ab_c"].as_u64().unwrap() as u8;
        let golden_a_bc = triple["join_a_bc"].as_u64().unwrap() as u8;

        // Compute runtime values
        let ab = join_outcomes(make_outcome(a), make_outcome(b));
        let ab_c = join_outcomes(ab, make_outcome(c));
        let bc = join_outcomes(make_outcome(b), make_outcome(c));
        let a_bc = join_outcomes(make_outcome(a), bc);

        assert_eq!(
            ab_c.severity_u8(),
            golden_ab_c,
            "join(join({a},{b}),{c}) severity: golden={golden_ab_c}, runtime={}",
            ab_c.severity_u8()
        );
        assert_eq!(
            a_bc.severity_u8(),
            golden_a_bc,
            "join({a},join({b},{c})) severity: golden={golden_a_bc}, runtime={}",
            a_bc.severity_u8()
        );

        // Associativity: both groupings yield same severity
        assert_eq!(
            ab_c.severity_u8(),
            a_bc.severity_u8(),
            "associativity violated for ({a},{b},{c})"
        );

        // Join rule: result severity == max(inputs)
        let expected_max = a.max(b).max(c);
        assert_eq!(
            ab_c.severity_u8(),
            expected_max,
            "join severity must be max for ({a},{b},{c})"
        );
    }
}

#[test]
fn golden_join_max_rule() {
    // Verify join_rule from the golden data
    let data = load_fixture("join_associativity.json");
    assert_eq!(
        data["join_rule"].as_str(),
        Some("join(a, b).severity == max(a.severity, b.severity)")
    );

    // Exhaustive pairwise check
    for a in 0..=3u8 {
        for b in 0..=3u8 {
            let result = join_outcomes(make_outcome(a), make_outcome(b));
            assert_eq!(
                result.severity_u8(),
                a.max(b),
                "join({a},{b}).severity must be max({a},{b})"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Timeout min law (rule #39)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn golden_timeout_min_law() {
    let data = load_fixture("timeout_min_law.json");
    let cases = data["cases"].as_array().expect("cases must be array");
    assert_eq!(cases.len(), 5, "5 canonical timeout cases");

    for case in cases {
        let case_id = case["id"].as_str().unwrap();
        let outer_ns = case["outer_ns"].as_u64().unwrap();
        let inner_ns = case["inner_ns"].as_u64().unwrap();
        let expected_ns = case["expected_ns"].as_u64().unwrap();

        let outer = Time::from_nanos(outer_ns);
        let inner = Time::from_nanos(inner_ns);
        let result = effective_deadline(outer, Some(inner));

        assert_eq!(
            result.as_nanos(),
            expected_ns,
            "timeout min law case '{case_id}': effective_deadline({outer_ns}, {inner_ns}) = {}, expected {expected_ns}",
            result.as_nanos()
        );
    }
}

#[test]
fn golden_timeout_identity() {
    // effective_deadline(x, None) == x
    for ns in [0, 1_000_000_000, u64::MAX] {
        let t = Time::from_nanos(ns);
        let result = effective_deadline(t, None);
        assert_eq!(
            result.as_nanos(),
            ns,
            "effective_deadline({ns}, None) must be identity"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fuzz baseline (rule #46)
// ─────────────────────────────────────────────────────────────────────────────

const FUZZ_BASELINE_SEED: u64 = 0xADC0_0003;
const FUZZ_BASELINE_ITERATIONS: usize = 50;

#[test]
fn golden_fuzz_baseline_determinism() {
    let data = load_fixture("fuzz_baseline.json");
    assert_eq!(data["seed"].as_u64(), Some(FUZZ_BASELINE_SEED));
    assert_eq!(
        data["iterations"].as_u64(),
        Some(FUZZ_BASELINE_ITERATIONS as u64)
    );

    // Run fuzz campaign twice with the same seed
    let config = FuzzConfig::new(FUZZ_BASELINE_SEED, FUZZ_BASELINE_ITERATIONS);
    let harness = FuzzHarness::new(config);
    let report1 = harness.run(|runtime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (t, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async { 42u64 })
            .expect("task creation");
        runtime.scheduler.lock().schedule(t, 0);
        runtime.run_until_quiescent();
    });

    let config2 = FuzzConfig::new(FUZZ_BASELINE_SEED, FUZZ_BASELINE_ITERATIONS);
    let harness2 = FuzzHarness::new(config2);
    let report2 = harness2.run(|runtime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (t, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async { 42u64 })
            .expect("task creation");
        runtime.scheduler.lock().schedule(t, 0);
        runtime.run_until_quiescent();
    });

    // Determinism: both runs must have identical results
    assert_eq!(
        report1.iterations, report2.iterations,
        "iteration count must be deterministic"
    );
    assert_eq!(
        report1.unique_certificates, report2.unique_certificates,
        "unique certificate count must be deterministic"
    );
    assert_eq!(
        report1.findings.len(),
        report2.findings.len(),
        "findings count must be deterministic"
    );
}

#[test]
fn golden_fuzz_baseline_corpus_serde_roundtrip() {
    let config = FuzzConfig::new(FUZZ_BASELINE_SEED, FUZZ_BASELINE_ITERATIONS);
    let harness = FuzzHarness::new(config);
    let report = harness.run(|runtime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (t, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async { 42u64 })
            .expect("task creation");
        runtime.scheduler.lock().schedule(t, 0);
        runtime.run_until_quiescent();
    });

    let corpus = report.to_regression_corpus(FUZZ_BASELINE_SEED);

    // Verify corpus metadata
    assert_eq!(corpus.schema_version, 1);
    assert_eq!(corpus.base_seed, FUZZ_BASELINE_SEED);
    assert_eq!(corpus.iterations, FUZZ_BASELINE_ITERATIONS);

    // Serde round-trip
    let json = serde_json::to_string_pretty(&corpus).expect("serialize corpus");
    let deserialized: asupersync::lab::fuzz::FuzzRegressionCorpus =
        serde_json::from_str(&json).expect("deserialize corpus");

    assert_eq!(deserialized.schema_version, corpus.schema_version);
    assert_eq!(deserialized.base_seed, corpus.base_seed);
    assert_eq!(deserialized.iterations, corpus.iterations);
    assert_eq!(deserialized.cases.len(), corpus.cases.len());

    for (orig, deser) in corpus.cases.iter().zip(deserialized.cases.iter()) {
        assert_eq!(orig.seed, deser.seed);
        assert_eq!(orig.replay_seed, deser.replay_seed);
        assert_eq!(orig.certificate_hash, deser.certificate_hash);
        assert_eq!(orig.trace_fingerprint, deser.trace_fingerprint);
        assert_eq!(orig.violation_categories, deser.violation_categories);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Update policy validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn golden_manifest_update_policy() {
    let manifest = load_manifest();
    let policy = &manifest["update_policy"];

    assert_eq!(
        policy["review_required"].as_bool(),
        Some(true),
        "review must be required for golden fixture updates"
    );
    assert_eq!(
        policy["drift_justification_required"].as_bool(),
        Some(true),
        "drift justification must be required"
    );

    let reviewers = policy["reviewers"]
        .as_array()
        .expect("reviewers must be array");
    assert!(
        !reviewers.is_empty(),
        "at least one reviewer group must be specified"
    );

    let checklist = policy["checklist"]
        .as_array()
        .expect("checklist must be array");
    assert!(
        checklist.len() >= 3,
        "update checklist must have at least 3 items"
    );
}

#[test]
fn golden_manifest_change_log_integrity() {
    let manifest = load_manifest();
    let change_log = manifest["change_log"].as_array().unwrap();

    for entry in change_log {
        assert!(
            entry["date"].as_str().is_some(),
            "change_log entry must have date"
        );
        assert!(
            entry["author"].as_str().is_some(),
            "change_log entry must have author"
        );
        assert!(
            entry["action"].as_str().is_some(),
            "change_log entry must have action"
        );
        assert!(
            entry["justification"].as_str().is_some(),
            "change_log entry must have justification"
        );
        let affected = entry["fixtures_affected"]
            .as_array()
            .expect("change_log entry must have fixtures_affected");
        assert!(!affected.is_empty(), "fixtures_affected must not be empty");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-fixture consistency
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn golden_cross_fixture_schema_consistency() {
    let manifest = load_manifest();
    let fixtures = manifest["fixtures"].as_array().unwrap();

    for fixture in fixtures {
        let file = fixture["file"].as_str().unwrap();
        let data = load_fixture(file);

        // Every fixture must have schema_version, fixture_id, description, invariants
        assert!(
            data["schema_version"].as_str().is_some(),
            "{file} must have schema_version"
        );
        assert!(
            data["fixture_id"].as_str().is_some(),
            "{file} must have fixture_id"
        );
        assert!(
            data["description"].as_str().is_some(),
            "{file} must have description"
        );

        // rule_ids in fixture data must match manifest
        let manifest_rule_ids: Vec<&str> = fixture["rule_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let data_rule_ids: Vec<&str> = data["rule_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            manifest_rule_ids, data_rule_ids,
            "rule_ids mismatch between manifest and {file}"
        );
    }
}
