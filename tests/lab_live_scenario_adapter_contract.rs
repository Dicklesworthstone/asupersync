#![allow(missing_docs)]
//! Contract tests for the lab-vs-live scenario adapter contract (2a6k9.2.1).
//!
//! Verifies the shared ScenarioSpec shape, adapter boundary, valid/invalid
//! examples, downstream bindings, and `rch`-offloaded validation policy.

mod common;

#[cfg(feature = "test-internals")]
use asupersync::lab::{
    ChaosSection, LabSection, NetworkSection, Scenario, ScenarioRunner, SporkScenarioConfig,
    SporkScenarioRunner, SporkScenarioSpec,
};
use asupersync::lab::DrainStatus;
use asupersync::lab::replay::{
    DifferentialBundleArtifacts, DifferentialPolicyClass, DivergenceCorpusEntry,
};
use asupersync::lab::{
    DualRunHarness, DualRunScenarioIdentity, LiveRunResult, NormalizedSemantics, SeedPlan,
    TerminalOutcome, assert_dual_run_passes, capture_cancellation, capture_loser_drain,
    capture_obligation_balance, capture_region_close, run_live_adapter,
};
#[cfg(feature = "test-internals")]
use asupersync::runtime::yield_now;
#[cfg(feature = "test-internals")]
use asupersync::spork::prelude::AppSpec;
#[cfg(feature = "test-internals")]
use asupersync::test_logging::{LIVE_CURRENT_THREAD_ADAPTER, ReproManifest, TestContext};
#[cfg(feature = "test-internals")]
use serde_json::json;
#[cfg(feature = "test-internals")]
use serde_json::Value;
#[cfg(feature = "test-internals")]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::Path;

fn load_doc() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/lab_live_scenario_adapter_contract.md");
    std::fs::read_to_string(path).expect("lab-live scenario adapter contract must exist")
}

#[cfg(feature = "test-internals")]
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

#[cfg(feature = "test-internals")]
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

#[cfg(feature = "test-internals")]
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

fn cancellation_pilot_identity() -> DualRunScenarioIdentity {
    cancellation_pilot_identity_with(
        "phase1.cancel.protocol.drain_finalize",
        "Cancellation pilot preserves request, drain, finalize, and loser-drain semantics",
        0xCA11_CE11,
    )
}

const CANCELLATION_PROTOCOL_CONTRACT_VERSION: &str = "cancel.protocol.v1";

fn cancellation_pilot_identity_with(
    scenario_id: &str,
    description: &str,
    seed: u64,
) -> DualRunScenarioIdentity {
    let seed_plan = SeedPlan::inherit(seed, format!("seed.{scenario_id}.v1"))
        .with_live_override(seed + 1)
        .with_entropy_seed(seed + 2);
    DualRunScenarioIdentity::phase1(
        scenario_id,
        "cancellation.protocol",
        CANCELLATION_PROTOCOL_CONTRACT_VERSION,
        description,
        seed_plan.canonical_seed,
    )
    .with_seed_plan(seed_plan)
}

fn cancellation_pilot_semantics(
    loser_joined: &[bool],
    cleanup_completed: bool,
    finalization_completed: bool,
    checkpoint_observed: Option<bool>,
) -> NormalizedSemantics {
    NormalizedSemantics {
        terminal_outcome: TerminalOutcome::cancelled("timeout"),
        cancellation: capture_cancellation(
            true,
            true,
            cleanup_completed,
            finalization_completed,
            checkpoint_observed,
        ),
        loser_drain: capture_loser_drain(loser_joined),
        region_close: capture_region_close(cleanup_completed, finalization_completed),
        obligation_balance: capture_obligation_balance(1, 0, 1),
        resource_surface: asupersync::lab::ResourceSurfaceRecord::empty("cancellation.protocol")
            .with_counter("cancel_requests", 1)
            .with_counter("cancel_acks", 1)
            .with_counter("cleanup_callbacks", i64::from(cleanup_completed))
            .with_counter("finalizers_completed", i64::from(finalization_completed)),
    }
}

fn make_cancellation_live_result(
    identity: &DualRunScenarioIdentity,
    loser_joined: &[bool],
    cleanup_completed: bool,
    finalization_completed: bool,
    checkpoint_observed: Option<bool>,
) -> LiveRunResult {
    run_live_adapter(identity, |config, witness| {
        assert_eq!(config.scenario_id, identity.scenario_id);
        assert_eq!(config.surface_id, identity.surface_id);
        witness.set_outcome(TerminalOutcome::cancelled("timeout"));
        witness.set_cancellation(capture_cancellation(
            true,
            true,
            cleanup_completed,
            finalization_completed,
            checkpoint_observed,
        ));
        witness.set_loser_drain(capture_loser_drain(loser_joined));
        witness.set_region_close(capture_region_close(
            cleanup_completed,
            finalization_completed,
        ));
        witness.set_obligation_balance(capture_obligation_balance(1, 0, 1));
        witness.record_counter("cancel_requests", 1);
        witness.record_counter("cancel_acks", 1);
        witness.record_counter("cleanup_callbacks", i64::from(cleanup_completed));
        witness.record_counter("finalizers_completed", i64::from(finalization_completed));
    })
}

#[cfg(feature = "test-internals")]
fn assert_pretty_json_eq(label: &str, actual: &Value, expected: &Value) {
    if actual != expected {
        let actual_pretty =
            serde_json::to_string_pretty(actual).expect("serialize actual contract JSON");
        let expected_pretty =
            serde_json::to_string_pretty(expected).expect("serialize expected contract JSON");
        panic!("{label} mismatch\nexpected:\n{expected_pretty}\nactual:\n{actual_pretty}");
    }
}

#[cfg(feature = "test-internals")]
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

#[cfg(feature = "test-internals")]
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

#[test]
fn cancellation_dual_run_pilot_preserves_request_drain_finalize_semantics() {
    let identity = cancellation_pilot_identity();
    let lab_semantics = cancellation_pilot_semantics(&[true], true, true, Some(true));
    let live_result = make_cancellation_live_result(&identity, &[true], true, true, Some(true));

    assert_eq!(
        live_result
            .metadata
            .capture_manifest
            .describe_field_capture("semantics.cancellation.finalization_completed")
            .as_deref(),
        Some("observed via witness.set_cancellation"),
        "live adapter should retain explicit cancellation capture provenance"
    );

    let result = DualRunHarness::from_identity(identity.clone())
        .lab(move |_config| lab_semantics)
        .live_result(move |_seed, _entropy| live_result)
        .run();

    assert_dual_run_passes(&result);
    assert_eq!(
        result.verdict.seed_lineage.seed_lineage_id,
        identity.seed_plan.seed_lineage_id
    );
    assert_eq!(result.lab.surface_id, "cancellation.protocol");
    assert_eq!(
        result.live.surface_contract_version,
        CANCELLATION_PROTOCOL_CONTRACT_VERSION
    );
}

#[test]
fn cancellation_dual_run_pilot_failure_bundle_calls_out_drain_and_finalize_gaps() {
    let identity = cancellation_pilot_identity();
    let lab_semantics = cancellation_pilot_semantics(&[true], true, true, Some(true));
    let live_result = make_cancellation_live_result(&identity, &[false], false, false, Some(false));
    let live_result_for_harness = live_result.clone();

    let result = DualRunHarness::from_identity(identity.clone())
        .lab(move |_config| lab_semantics)
        .live_result(move |_seed, _entropy| live_result_for_harness)
        .run();

    assert!(
        !result.passed(),
        "incomplete loser-drain/finalize evidence should fail the cancellation pilot"
    );

    let mismatch_fields = result
        .verdict
        .mismatches
        .iter()
        .map(|mismatch| mismatch.field.as_str())
        .collect::<BTreeSet<_>>();
    for field in [
        "semantics.cancellation.cleanup_completed",
        "semantics.cancellation.finalization_completed",
        "semantics.cancellation.terminal_phase",
        "semantics.cancellation.checkpoint_observed",
        "semantics.loser_drain.drained_losers",
        "semantics.loser_drain.status",
        "semantics.region_close.quiescent",
    ] {
        assert!(
            mismatch_fields.contains(field),
            "expected retained mismatch field: {field}"
        );
    }

    let entry = DivergenceCorpusEntry::from_dual_run_result(
        &result,
        "smoke",
        "cancellation_protocol_mismatch",
        DifferentialPolicyClass::RuntimeSemanticBug,
        "artifacts/lab_live/phase1.cancel.protocol.drain_finalize",
    );
    let bundle = DifferentialBundleArtifacts::from_dual_run_result(&entry, &result);

    assert_eq!(bundle.summary.scenario_id, identity.scenario_id);
    assert_eq!(bundle.summary.surface_id, identity.surface_id);
    assert_eq!(
        bundle.repro_manifest.seed_lineage.seed_lineage_id,
        identity.seed_plan.seed_lineage_id
    );
    assert!(
        bundle
            .deviations
            .mismatches
            .iter()
            .any(|mismatch| mismatch.field == "semantics.cancellation.finalization_completed"),
        "retained bundle should name the finalize mismatch explicitly"
    );
    assert!(
        bundle
            .deviations
            .mismatches
            .iter()
            .any(|mismatch| mismatch.field == "semantics.loser_drain.status"),
        "retained bundle should name the loser-drain mismatch explicitly"
    );
    assert_eq!(
        live_result
            .metadata
            .capture_manifest
            .describe_field_capture("semantics.loser_drain.status")
            .as_deref(),
        Some("observed via witness.set_loser_drain"),
        "live failure path should preserve loser-drain capture provenance"
    );
}

#[test]
fn cancellation_dual_run_pilot_before_first_poll_keeps_checkpoint_false() {
    let identity = cancellation_pilot_identity_with(
        "phase1.cancel.protocol.before_first_poll",
        "Cancellation before the first checkpoint still finalizes cleanly",
        0xCA11_CE21,
    );
    let lab_semantics = cancellation_pilot_semantics(&[], true, true, Some(false));
    let live_result = make_cancellation_live_result(&identity, &[], true, true, Some(false));

    let result = DualRunHarness::from_identity(identity)
        .lab(move |_config| lab_semantics)
        .live_result(move |_seed, _entropy| live_result)
        .run();

    assert_dual_run_passes(&result);
    assert_eq!(
        result.live.semantics.cancellation.checkpoint_observed,
        Some(false)
    );
    assert_eq!(
        result.live.semantics.loser_drain.status,
        DrainStatus::NotApplicable
    );
}

#[test]
fn cancellation_dual_run_pilot_child_await_records_loser_drain() {
    let identity = cancellation_pilot_identity_with(
        "phase1.cancel.protocol.child_await",
        "Cancellation during child await drains the awaited child before finalize",
        0xCA11_CE31,
    );
    let lab_semantics = cancellation_pilot_semantics(&[true], true, true, Some(true));
    let live_result = make_cancellation_live_result(&identity, &[true], true, true, Some(true));

    let result = DualRunHarness::from_identity(identity)
        .lab(move |_config| lab_semantics)
        .live_result(move |_seed, _entropy| live_result)
        .run();

    assert_dual_run_passes(&result);
    assert_eq!(result.live.semantics.loser_drain.drained_losers, 1);
    assert_eq!(
        result.live.semantics.loser_drain.status,
        DrainStatus::Complete
    );
}
