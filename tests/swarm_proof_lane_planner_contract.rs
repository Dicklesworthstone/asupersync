#![allow(missing_docs)]

use asupersync::lab::{
    SWARM_PROOF_LANE_PLAN_SCHEMA_VERSION, SwarmProofLaneAdmissionDecision,
    SwarmProofLaneAtlasAdmissionContext, SwarmProofLaneDecision, SwarmProofLaneFallbackPolicy,
    SwarmProofLanePeerReservationOverlapStatus, SwarmProofLanePlan, SwarmProofLaneRequest,
    SwarmProofLaneTargetDirIsolationStatus, SwarmProofLaneTrappedCycleWitnessStatus,
    plan_swarm_proof_lane, render_swarm_proof_lane_agent_mail_summary,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/swarm_proof_lane_planner_contract_v1.json";
const RUNBOOK_PATH: &str = "docs/proof_runner_usage.md";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn contract() -> Value {
    let raw = std::fs::read_to_string(repo_path(ARTIFACT_PATH))
        .unwrap_or_else(|error| panic!("read {ARTIFACT_PATH}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {ARTIFACT_PATH}: {error}"))
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn rows_by_id<'a>(value: &'a Value, key: &str, id_key: &str) -> BTreeMap<String, &'a Value> {
    array(value, key)
        .iter()
        .map(|row| (string(row, id_key).to_string(), row))
        .collect()
}

fn lane_rows(contract: &Value) -> BTreeMap<String, &Value> {
    array(contract, "lanes")
        .iter()
        .map(|row| (string(row, "lane_id").to_string(), row))
        .collect()
}

fn parse_request(row: &Value) -> SwarmProofLaneRequest {
    serde_json::from_value(
        row.get("planner_request")
            .unwrap_or_else(|| panic!("{} missing planner_request", string(row, "lane_id")))
            .clone(),
    )
    .unwrap_or_else(|error| panic!("parse planner_request {}: {error}", string(row, "lane_id")))
}

fn finding_codes(plan: &SwarmProofLanePlan) -> BTreeSet<String> {
    plan.findings
        .iter()
        .map(|finding| finding.code.clone())
        .collect()
}

fn base_focused_request(contract: &Value) -> SwarmProofLaneRequest {
    let rows = lane_rows(contract);
    parse_request(
        rows.get("swarm-workload-corpus-focused")
            .expect("focused lane fixture"),
    )
}

fn atlas_context(
    mut configure: impl FnMut(&mut SwarmProofLaneAtlasAdmissionContext),
) -> SwarmProofLaneAtlasAdmissionContext {
    let mut context = SwarmProofLaneAtlasAdmissionContext {
        source_rows: vec![
            "rch_proof_lane_admission:swarm-workload-corpus-focused".to_string(),
            "large_host_worker_warmth:rch-worker-fixture-01".to_string(),
        ],
        reason_codes: vec!["atlas_fixture".to_string()],
        ..SwarmProofLaneAtlasAdmissionContext::default()
    };
    configure(&mut context);
    context
}

fn admission_decision(value: &Value, key: &str) -> SwarmProofLaneAdmissionDecision {
    match string(value, key) {
        "admit" => SwarmProofLaneAdmissionDecision::Admit,
        "defer" => SwarmProofLaneAdmissionDecision::Defer,
        "reject" => SwarmProofLaneAdmissionDecision::Reject,
        "batch" => SwarmProofLaneAdmissionDecision::Batch,
        "blocked" => SwarmProofLaneAdmissionDecision::Blocked,
        "stale_evidence" => SwarmProofLaneAdmissionDecision::StaleEvidence,
        "malformed" => SwarmProofLaneAdmissionDecision::Malformed,
        "advisory_spectral_warning" => SwarmProofLaneAdmissionDecision::AdvisorySpectralWarning,
        "trapped_cycle_proven" => SwarmProofLaneAdmissionDecision::TrappedCycleProven,
        other => panic!("unknown admission decision {other}"),
    }
}

fn apply_request_overrides(request: &mut SwarmProofLaneRequest, row: &Value) {
    let Some(overrides) = row.get("request_overrides").and_then(Value::as_object) else {
        return;
    };
    if let Some(lane_id) = overrides.get("lane_id").and_then(Value::as_str) {
        request.lane_id = lane_id.to_string();
    }
    if let Some(markers) = overrides
        .get("append_transcript_markers")
        .and_then(Value::as_array)
    {
        request
            .transcript_markers
            .extend(markers.iter().map(|marker| {
                marker
                    .as_str()
                    .unwrap_or_else(|| panic!("{} transcript marker", string(row, "case_id")))
                    .to_string()
            }));
    }
}

fn scenario_request(base: &SwarmProofLaneRequest, row: &Value) -> SwarmProofLaneRequest {
    let case_id = string(row, "case_id");
    let mut request = base.clone();
    request.lane_id = case_id.to_string();
    request.scenario_id = format!("atlas-decision-{case_id}");
    request.atlas_context = Some(
        serde_json::from_value(
            row.get("atlas_context")
                .unwrap_or_else(|| panic!("{case_id} missing atlas_context"))
                .clone(),
        )
        .unwrap_or_else(|error| panic!("{case_id} atlas_context parse failed: {error}")),
    );
    apply_request_overrides(&mut request, row);
    request
}

fn assert_stable_log_is_scrubbed(corpus: &Value, row: &Value) {
    let policy = Value::Object(object(corpus, "scrubbing_policy").clone());
    let forbidden = string_set(&policy, "forbidden_log_fragments");
    let stable_tokens = string_set(&policy, "stable_tokens");
    let lines = array(row, "stable_log");
    assert!(
        lines.len() >= 4,
        "{} stable_log must include replay and closeout detail",
        string(row, "case_id")
    );
    let joined = lines
        .iter()
        .map(|line| {
            line.as_str()
                .unwrap_or_else(|| panic!("{} stable_log entries", string(row, "case_id")))
        })
        .collect::<Vec<_>>()
        .join("\n");
    for fragment in forbidden {
        assert!(
            !joined.contains(&fragment),
            "{} stable log leaks host-specific fragment {fragment}",
            string(row, "case_id")
        );
    }
    for token in stable_tokens {
        assert!(
            joined.contains(&token),
            "{} stable log missing {token}",
            string(row, "case_id")
        );
    }
}

#[test]
fn artifact_declares_source_schema_and_planner_boundary() {
    let contract = contract();
    assert_eq!(
        contract["contract_version"].as_str(),
        Some("swarm-proof-lane-planner-v1")
    );
    assert_eq!(contract["bead_id"].as_str(), Some("asupersync-bt63nr.8"));
    assert_eq!(
        contract["schema_version"].as_str(),
        Some(SWARM_PROOF_LANE_PLAN_SCHEMA_VERSION)
    );

    let source = contract
        .get("source_of_truth")
        .expect("source_of_truth object");
    for key in ["contract", "contract_test", "runtime_planner_source"] {
        let path = string(source, key);
        assert!(
            repo_path(path).exists(),
            "source_of_truth.{key} must point to a live repo file: {path}"
        );
    }
    assert_eq!(
        string(source, "runtime_request_type"),
        "asupersync::lab::SwarmProofLaneRequest"
    );
    assert_eq!(
        string(source, "runtime_plan_type"),
        "asupersync::lab::SwarmProofLanePlan"
    );
    assert_eq!(
        string(source, "runtime_planner"),
        "asupersync::lab::plan_swarm_proof_lane"
    );
}

#[test]
fn decision_scenario_corpus_is_stable_scrubbed_and_replayable() {
    let contract = contract();
    let corpus = contract
        .get("decision_scenario_corpus")
        .expect("decision_scenario_corpus");
    assert_eq!(
        corpus["corpus_id"].as_str(),
        Some("admission-aware-atlas-decision-scenarios-v1")
    );
    assert_eq!(corpus["bead_id"].as_str(), Some("asupersync-bt63nr.8"));

    let proof_command = string(corpus, "proof_command");
    for token in [
        "RCH_REQUIRE_REMOTE=1",
        "rch exec -- env",
        "CARGO_TARGET_DIR=",
        "cargo test -p asupersync --test swarm_proof_lane_planner_contract",
    ] {
        assert!(
            proof_command.contains(token),
            "proof command missing {token}"
        );
    }

    let required = string_set(corpus, "required_cases");
    let cases = rows_by_id(corpus, "cases", "case_id");
    assert_eq!(
        cases.keys().cloned().collect::<BTreeSet<_>>(),
        required,
        "scenario corpus cases must match required_cases exactly"
    );

    let base = base_focused_request(&contract);
    for row in cases.values() {
        assert_stable_log_is_scrubbed(corpus, row);
        let request = scenario_request(&base, row);
        let plan = plan_swarm_proof_lane(&request);
        assert_eq!(
            plan.admission_decision,
            admission_decision(row, "expected_admission_decision"),
            "{} admission decision",
            string(row, "case_id")
        );
        assert!(!plan.source_rows.is_empty(), "{} source rows", plan.lane_id);
        assert!(
            !plan.reason_codes.is_empty(),
            "{} reason codes",
            plan.lane_id
        );
        assert!(!plan.covers.is_empty(), "{} cover claims", plan.lane_id);
        assert!(
            !plan.does_not_cover.is_empty(),
            "{} does_not_cover claims",
            plan.lane_id
        );
        assert!(
            !plan.agent_mail_summary.trim().is_empty(),
            "{} summary",
            plan.lane_id
        );
        assert!(!plan.mutates_external_state);
        assert!(!plan.destructive_cleanup_required);
        assert!(!plan.branch_or_worktree_required);
        for token in array(row, "expected_summary_tokens") {
            let token = token
                .as_str()
                .unwrap_or_else(|| panic!("{} expected token", string(row, "case_id")));
            assert!(
                plan.agent_mail_summary.contains(token)
                    || plan.reason_codes.iter().any(|code| code == token),
                "{} receipt missing {token}",
                string(row, "case_id")
            );
        }
    }
}

#[test]
fn operator_runbook_preserves_closeout_receipt_taxonomy() {
    let text = read_repo_file(RUNBOOK_PATH);
    for required in [
        ARTIFACT_PATH,
        "tests/swarm_proof_lane_planner_contract.rs",
        "asupersync::lab::plan_swarm_proof_lane",
        "asupersync::lab::render_swarm_proof_lane_agent_mail_summary",
        "admission-aware-atlas-decision-scenarios-v1",
        "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_bt63nr8_swarm_planner cargo test -p asupersync --test swarm_proof_lane_planner_contract -- --nocapture",
        "replay-backed",
        "advisory",
        "trapped-cycle-proven",
        "validation-blocked",
        "stale",
        "admission_decision",
        "source_rows",
        "reason_codes",
        "covers",
        "does_not_cover",
        "agent_mail_summary",
        "target_dir_isolation_status",
        "peer_reservation_overlap_status",
        "trapped_cycle_witness_status",
        "mutates_external_state=false",
        "destructive_cleanup_required=false",
        "branch_or_worktree_required=false",
        "Validated-only or advisory rows are not enough",
        "Do not paste an old green transcript as current proof",
        "Never broaden the claim in prose",
    ] {
        assert!(
            text.contains(required),
            "{RUNBOOK_PATH} must contain closeout taxonomy marker {required:?}"
        );
    }

    for outcome in [
        "Admit",
        "Defer",
        "Batch",
        "AdvisorySpectralWarning",
        "TrappedCycleProven",
        "Reject",
        "Blocked",
        "Malformed",
        "StaleEvidence",
    ] {
        assert!(
            text.contains(outcome),
            "{RUNBOOK_PATH} must describe admission outcome {outcome}"
        );
    }
}

#[test]
fn focused_scenario_fixture_maps_to_remote_only_proof_lane() {
    let contract = contract();
    let rows = lane_rows(&contract);
    let request = parse_request(
        rows.get("swarm-workload-corpus-focused")
            .expect("focused lane fixture"),
    );
    let plan = plan_swarm_proof_lane(&request);

    assert_eq!(plan.schema_version, SWARM_PROOF_LANE_PLAN_SCHEMA_VERSION);
    assert_eq!(plan.lane_id, "swarm-workload-corpus-focused");
    assert_eq!(plan.scenario_id, "swarm-minimal-healthy-run");
    assert_eq!(plan.decision, SwarmProofLaneDecision::Ready);
    assert_eq!(
        plan.admission_decision,
        SwarmProofLaneAdmissionDecision::Admit
    );
    assert_eq!(
        plan.fallback_policy,
        SwarmProofLaneFallbackPolicy::RemoteOnly
    );
    assert!(plan.findings.is_empty(), "findings: {:?}", plan.findings);
    assert!(plan.remote_required);
    assert!(plan.remote_provenance_observed);
    assert!(!plan.local_fallback_marker_detected);
    assert!(!plan.stale_head);
    assert!(!plan.missing_target_dir);
    assert_eq!(
        plan.target_dir_isolation_status,
        SwarmProofLaneTargetDirIsolationStatus::Isolated
    );
    assert_eq!(
        plan.peer_reservation_overlap_status,
        SwarmProofLanePeerReservationOverlapStatus::Clear
    );
    assert_eq!(
        plan.trapped_cycle_witness_status,
        SwarmProofLaneTrappedCycleWitnessStatus::NotRequired
    );
    assert!(
        plan.reason_codes
            .contains(&"remote_required_policy".to_string())
    );
    assert!(
        plan.source_rows
            .contains(&"src/lab/swarm_replay.rs".to_string())
    );
    assert_eq!(plan.features, vec!["test-internals"]);
    assert!(
        plan.command.contains("RCH_REQUIRE_REMOTE=1 rch exec --"),
        "published proof command must require remote RCH execution"
    );
    assert!(
        plan.command
            .contains("swarm_workload_scenario_corpus_contract"),
        "focused lane must prove the scenario DSL corpus contract"
    );
    assert!(
        plan.covers
            .contains(&"scenario_schema_validation".to_string()),
        "lane must declare its positive proof claim"
    );
    assert!(
        plan.does_not_cover
            .contains(&"workspace_release_health".to_string()),
        "lane must avoid broad release-health claims"
    );
    assert!(!plan.mutates_external_state);
    assert!(!plan.destructive_cleanup_required);
    assert!(!plan.branch_or_worktree_required);

    let rendered = render_swarm_proof_lane_agent_mail_summary(&plan);
    assert_eq!(rendered, plan.agent_mail_summary);
    for expected in [
        "proof_lane: swarm-workload-corpus-focused",
        "remote_required=true remote_observed=true",
        "admission_decision: Admit",
        "target_dir_isolation: Isolated",
        "peer_reservation_overlap: Clear",
        "trapped_cycle_witness: NotRequired",
        "does_not_cover: broad_conformance,workspace_release_health",
        "command: RCH_REQUIRE_REMOTE=1 rch exec --",
    ] {
        assert!(rendered.contains(expected), "summary missing {expected:?}");
    }
    assert!(
        rendered.contains("covers:") && rendered.contains("scenario_schema_validation"),
        "summary must include the scenario_schema_validation cover claim"
    );

    let roundtrip: SwarmProofLanePlan =
        serde_json::from_str(&serde_json::to_string(&plan).expect("render plan"))
            .expect("parse rendered plan");
    assert_eq!(roundtrip, plan);
}

#[test]
fn atlas_aware_admission_outcomes_have_complete_receipts() {
    let contract = contract();
    let base = base_focused_request(&contract);
    let mut fixtures = Vec::new();

    fixtures.push((SwarmProofLaneAdmissionDecision::Admit, base.clone()));

    let mut defer = base.clone();
    defer.atlas_context = Some(atlas_context(|context| {
        context.worker_saturation = Some("worker_saturated".to_string());
        context.batching_decision = Some("defer_worker_saturated".to_string());
    }));
    fixtures.push((SwarmProofLaneAdmissionDecision::Defer, defer));

    let mut reject = base.clone();
    reject
        .transcript_markers
        .push("[RCH] local fallback executed".to_string());
    fixtures.push((SwarmProofLaneAdmissionDecision::Reject, reject));

    let mut batch = base.clone();
    batch.atlas_context = Some(atlas_context(|context| {
        context.batching_decision = Some("admit_batch".to_string());
    }));
    fixtures.push((SwarmProofLaneAdmissionDecision::Batch, batch));

    let mut blocked = base.clone();
    blocked.atlas_context = Some(atlas_context(|context| {
        context.peer_reservation_overlap_status =
            SwarmProofLanePeerReservationOverlapStatus::ActiveExclusiveConflict;
    }));
    fixtures.push((SwarmProofLaneAdmissionDecision::Blocked, blocked));

    let mut stale = base.clone();
    stale.atlas_context = Some(atlas_context(|context| {
        context.stale_evidence = true;
    }));
    fixtures.push((SwarmProofLaneAdmissionDecision::StaleEvidence, stale));

    let mut malformed = base.clone();
    malformed.lane_id.clear();
    fixtures.push((SwarmProofLaneAdmissionDecision::Malformed, malformed));

    let mut advisory = base.clone();
    advisory.atlas_context = Some(atlas_context(|context| {
        context.spectral_warning_advisory = true;
        context.trapped_cycle_witness_status =
            SwarmProofLaneTrappedCycleWitnessStatus::RequiredMissing;
    }));
    fixtures.push((
        SwarmProofLaneAdmissionDecision::AdvisorySpectralWarning,
        advisory,
    ));

    let mut proven = base.clone();
    proven.atlas_context = Some(atlas_context(|context| {
        context.trapped_cycle_witness_status = SwarmProofLaneTrappedCycleWitnessStatus::Proven;
    }));
    fixtures.push((SwarmProofLaneAdmissionDecision::TrappedCycleProven, proven));

    let mut observed = BTreeSet::new();
    for (expected, request) in fixtures {
        let plan = plan_swarm_proof_lane(&request);
        assert_eq!(
            plan.admission_decision, expected,
            "fixture {} mapped to {:?}",
            plan.lane_id, plan.admission_decision
        );
        observed.insert(plan.admission_decision);
        assert!(
            !plan.reason_codes.is_empty(),
            "{} must include reason codes",
            plan.lane_id
        );
        assert!(!plan.covers.is_empty(), "{} covers", plan.lane_id);
        assert!(
            !plan.does_not_cover.is_empty(),
            "{} does_not_cover",
            plan.lane_id
        );
        assert!(!plan.source_rows.is_empty(), "{} source rows", plan.lane_id);
        assert!(
            !plan.agent_mail_summary.trim().is_empty(),
            "{} summary",
            plan.lane_id
        );
        for expected_text in [
            "admission_decision:",
            "target_dir_isolation:",
            "peer_reservation_overlap:",
            "trapped_cycle_witness:",
            "reason_codes:",
            "covers:",
            "does_not_cover:",
        ] {
            assert!(
                plan.agent_mail_summary.contains(expected_text),
                "{} summary missing {expected_text}",
                plan.lane_id
            );
        }
    }

    assert_eq!(
        observed,
        BTreeSet::from([
            SwarmProofLaneAdmissionDecision::Admit,
            SwarmProofLaneAdmissionDecision::Defer,
            SwarmProofLaneAdmissionDecision::Reject,
            SwarmProofLaneAdmissionDecision::Batch,
            SwarmProofLaneAdmissionDecision::Blocked,
            SwarmProofLaneAdmissionDecision::StaleEvidence,
            SwarmProofLaneAdmissionDecision::Malformed,
            SwarmProofLaneAdmissionDecision::AdvisorySpectralWarning,
            SwarmProofLaneAdmissionDecision::TrappedCycleProven,
        ])
    );

    let mut overclaim = base;
    overclaim.atlas_context = Some(atlas_context(|context| {
        context.reason_codes.push("deadlock_proven".to_string());
        context.trapped_cycle_witness_status = SwarmProofLaneTrappedCycleWitnessStatus::Validated;
    }));
    assert_ne!(
        plan_swarm_proof_lane(&overclaim).admission_decision,
        SwarmProofLaneAdmissionDecision::TrappedCycleProven,
        "validated-only witness rows must not produce a proven label"
    );
}

#[test]
fn malformed_lanes_fail_closed_with_specific_findings() {
    let contract = contract();
    for row in array(&contract, "malformed_examples") {
        let request = parse_request(row);
        let plan = plan_swarm_proof_lane(&request);
        let expected = string(row, "expected_finding_code");
        assert_ne!(
            plan.decision,
            SwarmProofLaneDecision::Ready,
            "{} must not be accepted",
            string(row, "lane_id")
        );
        assert!(
            finding_codes(&plan).contains(expected),
            "{} expected finding {expected:?}, got {:?}",
            string(row, "lane_id"),
            plan.findings
        );
    }
}

#[test]
fn batching_is_stable_for_compatible_lanes_and_sensitive_to_features() {
    let contract = contract();
    let rows = lane_rows(&contract);
    let request = parse_request(
        rows.get("swarm-workload-corpus-focused")
            .expect("focused lane fixture"),
    );
    let first = plan_swarm_proof_lane(&request);

    let mut compatible = request.clone();
    compatible.lane_id = "swarm-workload-corpus-focused-replay".to_string();
    compatible
        .expected_artifacts
        .push("target/lab-replay/swarm-workload/extra-proof-copy.json".to_string());
    let second = plan_swarm_proof_lane(&compatible);
    assert_eq!(
        first.batch_key, second.batch_key,
        "lanes with the same target, features, and surfaces should batch together"
    );

    let mut incompatible = request;
    incompatible.lane_id = "swarm-workload-corpus-kafka-feature".to_string();
    incompatible.features = vec!["kafka".to_string()];
    incompatible.command = incompatible
        .command
        .replace("--features test-internals", "--features kafka");
    let third = plan_swarm_proof_lane(&incompatible);
    assert_ne!(
        first.batch_key, third.batch_key,
        "feature changes must split proof-lane batches"
    );
}

#[test]
fn schema_fields_are_source_backed_and_plan_serializes_stably() {
    let contract = contract();
    let source_path = string(&contract["source_of_truth"], "runtime_planner_source");
    let source = std::fs::read_to_string(repo_path(source_path))
        .unwrap_or_else(|error| panic!("read {source_path}: {error}"));
    for token in [
        "SWARM_PROOF_LANE_PLAN_SCHEMA_VERSION",
        "pub struct SwarmProofLaneRequest",
        "pub struct SwarmProofLanePlan",
        "pub fn plan_swarm_proof_lane",
        "pub fn render_swarm_proof_lane_agent_mail_summary",
    ] {
        assert!(source.contains(token), "planner source missing {token}");
    }

    let plan_fields = string_set(&contract["schema"], "required_plan_fields");
    let rows = lane_rows(&contract);
    let request = parse_request(
        rows.get("swarm-workload-corpus-focused")
            .expect("focused lane fixture"),
    );
    let value = serde_json::to_value(plan_swarm_proof_lane(&request)).expect("plan to JSON");
    let object = value.as_object().expect("plan JSON object");
    for field in plan_fields {
        assert!(object.contains_key(&field), "plan JSON missing {field}");
    }

    let reject_codes = string_set(&contract["schema"], "reject_finding_codes");
    for expected in [
        "missing_rch_provenance",
        "local_fallback_marker",
        "stale_head",
        "missing_target_dir",
        "missing_feature_scope",
    ] {
        assert!(
            reject_codes.contains(expected),
            "schema reject codes missing {expected}"
        );
    }

    let outcomes = string_set(&contract["schema"], "admission_decision_outcomes");
    assert_eq!(
        outcomes,
        BTreeSet::from([
            "admit".to_string(),
            "defer".to_string(),
            "reject".to_string(),
            "batch".to_string(),
            "blocked".to_string(),
            "stale_evidence".to_string(),
            "malformed".to_string(),
            "advisory_spectral_warning".to_string(),
            "trapped_cycle_proven".to_string(),
        ])
    );
}
