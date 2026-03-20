//! Contract tests for the lab-vs-live scenario adapter contract (2a6k9.2.1).
//!
//! Verifies the shared ScenarioSpec shape, adapter boundary, valid/invalid
//! examples, downstream bindings, and `rch`-offloaded validation policy.

#![allow(missing_docs)]

mod common;

use asupersync::lab::{
    ChaosSection, DualRunScenarioIdentity, LabSection, NetworkSection, Scenario, ScenarioRunner,
    SeedPlan, SporkScenarioConfig, SporkScenarioRunner, SporkScenarioSpec,
};
use asupersync::runtime::yield_now;
use asupersync::spork::prelude::AppSpec;
use asupersync::test_logging::{LIVE_CURRENT_THREAD_ADAPTER, ReproManifest, TestContext};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

fn load_doc() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/lab_live_scenario_adapter_contract.md");
    std::fs::read_to_string(path).expect("lab-live scenario adapter contract must exist")
}

fn load_golden_harness_fixture() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/semantic_golden/dual_run_harness_contract.json");
    let content =
        std::fs::read_to_string(path).expect("dual-run harness golden fixture must exist");
    serde_json::from_str(&content).expect("dual-run harness golden fixture must parse")
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
fn doc_references_bead_and_dependencies() {
    let doc = load_doc();
    for token in [
        "asupersync-2a6k9.2.1",
        "asupersync-2a6k9.2",
        "asupersync-2a6k9",
        "docs/lab_live_differential_scope_matrix.md",
        "docs/lab_live_normalized_observable_schema.md",
        "docs/tokio_differential_behavior_suites.md",
        "src/lab/scenario.rs",
        "src/lab/scenario_runner.rs",
        "src/lab/spork_harness.rs",
        "tests/common/mod.rs",
        "docs/integration.md",
    ] {
        assert!(
            doc.contains(token),
            "document missing dependency token: {token}"
        );
    }
}

#[test]
fn doc_defines_shared_scenario_contract_and_version() {
    let doc = load_doc();
    for token in [
        "DualRunScenarioSpec",
        "schema_version = \"lab-live-scenario-spec-v1\"",
        "lab-live-scenario-spec-v1",
        "ScenarioSpec intent -> lab adapter / live adapter -> normalized observable -> comparator",
    ] {
        assert!(
            doc.contains(token),
            "document missing scenario-contract token: {token}"
        );
    }
}

#[test]
fn doc_names_required_top_level_fields() {
    let doc = load_doc();
    for token in [
        "scenario_id",
        "surface_id",
        "surface_contract_version",
        "seed_plan",
        "participants",
        "setup",
        "operations",
        "perturbations",
        "expectations",
        "lab_binding",
        "live_binding",
        "artifacts",
    ] {
        assert!(
            doc.contains(token),
            "document missing top-level field token: {token}"
        );
    }
}

#[test]
fn doc_bridges_real_existing_code_surfaces() {
    let doc = load_doc();
    for token in [
        "src/lab/scenario.rs::Scenario",
        "src/lab/scenario_runner.rs::ScenarioRunner",
        "src/lab/spork_harness.rs::SporkScenarioSpec",
        "SporkScenarioRunner",
        "RuntimeBuilder::current_thread()",
        "run_test_with_cx(...)",
        "live.current_thread",
        "lab.scenario_runner",
        "lab.spork_harness",
    ] {
        assert!(
            doc.contains(token),
            "document missing adapter-boundary token: {token}"
        );
    }
}

#[test]
fn doc_requires_normalized_schema_bridge() {
    let doc = load_doc();
    for token in [
        "lab-live-normalized-observable-v1",
        "terminal_outcome",
        "cancellation",
        "loser_drain",
        "region_close",
        "obligation_balance",
        "resource_surface",
        "allowed_provenance_variance",
    ] {
        assert!(
            doc.contains(token),
            "document missing normalized-schema token: {token}"
        );
    }
}

#[test]
fn doc_includes_valid_example_and_expected_normalized_record() {
    let doc = load_doc();
    for token in [
        "phase1.cancel.race.one_loser",
        "cancel.race.v1",
        "seed.phase1.cancel.race.one_loser.v1",
        "winner=fast_branch",
        "\"schema_version\": \"lab-live-normalized-observable-v1\"",
        "\"surface_id\": \"cancel.race\"",
        "\"status\": \"complete\"",
        "\"balanced\": true",
    ] {
        assert!(
            doc.contains(token),
            "document missing valid-example token: {token}"
        );
    }
}

#[test]
fn doc_includes_invalid_examples_and_rejection_reasons() {
    let doc = load_doc();
    for token in [
        "invalid.missing_live_binding",
        "invalid.real_network_claim",
        "missing_adapter_binding",
        "unsupported_surface",
        "not_comparison_ready",
        "artifact_schema_violation",
    ] {
        assert!(
            doc.contains(token),
            "document missing invalid-example token: {token}"
        );
    }
}

#[test]
fn doc_names_validation_rules_and_non_goals() {
    let doc = load_doc();
    for token in [
        "seed_lineage_violation",
        "semantic_expectation_gap",
        "new universal scheduler DSL",
        "raw OS or real-network parity claims",
        "browser ambient behavior parity",
        "ad hoc per-surface one-off harness contracts",
    ] {
        assert!(
            doc.contains(token),
            "document missing validation or non-goal token: {token}"
        );
    }
}

#[test]
fn doc_binds_downstream_beads_and_validation_commands() {
    let doc = load_doc();
    for token in [
        "asupersync-2a6k9.2.2",
        "asupersync-2a6k9.2.3",
        "asupersync-2a6k9.2.4",
        "asupersync-2a6k9.4.*",
        "asupersync-2a6k9.6.*",
        "rch exec -- cargo fmt --check",
        "rch exec -- cargo check --all-targets",
        "rch exec -- cargo clippy --all-targets -- -D warnings",
        "rch exec -- cargo test --test lab_live_scenario_adapter_contract -- --nocapture",
    ] {
        assert!(
            doc.contains(token),
            "document missing downstream or validation token: {token}"
        );
    }
}

fn minimal_contract_identity() -> DualRunScenarioIdentity {
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

fn minimal_contract_scenario(identity: &DualRunScenarioIdentity) -> Scenario {
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

fn assert_pretty_json_eq(label: &str, actual: &Value, expected: &Value) {
    if actual != expected {
        let actual_pretty =
            serde_json::to_string_pretty(actual).expect("serialize actual contract JSON");
        let expected_pretty =
            serde_json::to_string_pretty(expected).expect("serialize expected contract JSON");
        panic!("{label} mismatch\nexpected:\n{expected_pretty}\nactual:\n{actual_pretty}");
    }
}

#[test]
fn shared_harness_smoke_executes_same_contract_across_lab_and_live_entrypoints() {
    let identity = minimal_contract_identity();
    let scenario = minimal_contract_scenario(&identity);
    let lab_result = ScenarioRunner::run_with_identity(&scenario, &identity).unwrap();
    let spork_result = run_minimal_spork(&identity);

    let mut harness = common::e2e_harness::E2eLabHarness::from_dual_run_identity(&identity);
    let root = harness.create_root();
    harness.spawn(root, async {});
    assert!(
        harness.run_until_quiescent() > 0,
        "lab harness should make scheduler progress for the shared smoke case"
    );
    assert!(
        harness.is_quiescent(),
        "lab harness should reach quiescence"
    );
    assert_eq!(
        harness.check_invariants(),
        0,
        "lab harness should end without invariant violations"
    );
    harness.finish();

    let live_identity = identity.clone();
    common::run_test(move || async move {
        yield_now().await;
        let live_ctx = TestContext::from_live_dual_run(&live_identity);
        let manifest = ReproManifest::from_context(&live_ctx, true).with_phases(vec![
            "setup".into(),
            "execute".into(),
            "compare".into(),
        ]);
        assert_eq!(
            manifest.adapter.as_deref(),
            Some(LIVE_CURRENT_THREAD_ADAPTER),
            "live smoke path should tag the current-thread adapter"
        );
        assert_eq!(
            manifest.scenario_id, "phase1.cancel.race.one_loser",
            "live smoke path should preserve the shared scenario id"
        );
    });

    assert!(
        lab_result.passed(),
        "lab scenario runner smoke case must pass"
    );
    assert!(spork_result.passed(), "spork harness smoke case must pass");

    let live_ctx = TestContext::from_live_dual_run(&identity);
    let live_replay = live_ctx
        .replay_metadata
        .as_ref()
        .expect("live context should retain replay metadata");
    let fixture = load_golden_harness_fixture();

    let actual = json!({
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
    });

    let expected = fixture["smoke_snapshot"].clone();

    assert_pretty_json_eq("shared dual-run smoke snapshot", &actual, &expected);
}

#[test]
fn dual_run_failure_manifest_keeps_readable_provenance() {
    let identity = minimal_contract_identity();
    let manifest = ReproManifest::from_context(&TestContext::from_live_dual_run(&identity), false)
        .with_failure_reason("contract smoke mismatch")
        .with_phases(vec!["setup".into(), "execute".into(), "compare".into()]);

    let actual = serde_json::to_value(&manifest).expect("serialize repro manifest");
    let expected = load_golden_harness_fixture()["failure_manifest_excerpt"].clone();
    let normalized = json!({
        "scenario_id": actual["scenario_id"],
        "adapter": actual["adapter"],
        "surface_id": actual["replay_metadata"]["family"]["surface_id"],
        "surface_contract_version": actual["replay_metadata"]["family"]["surface_contract_version"],
        "seed_lineage_id": actual["seed_lineage"]["seed_lineage_id"],
        "failure_reason": actual["failure_reason"],
        "phases_executed": actual["phases_executed"],
    });

    assert_pretty_json_eq("dual-run failure manifest", &normalized, &expected);
    assert!(
        actual["replay_command"]
            .as_str()
            .is_some_and(|cmd| cmd.contains("cargo test")),
        "failure manifest should retain a replay command instead of opaque diagnostics"
    );
}
