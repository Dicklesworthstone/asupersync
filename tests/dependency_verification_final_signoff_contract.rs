#![allow(clippy::nursery, clippy::pedantic, missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

const ARTIFACT_PATH: &str = "artifacts/dependency_verification_final_signoff_v1.json";
const REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const BASELINE_PATH: &str = "artifacts/dependency_capability_baseline_v1.json";
const CUTOVER_PATH: &str = "artifacts/dependency_cutover_policy_v1.json";
const MATRIX_PATH: &str = "artifacts/dependency_verification_matrix_v1.json";
const FAILURE_PATH: &str = "artifacts/dependency_failure_injection_matrix_v1.json";
const SERVICE_PATH: &str = "artifacts/dependency_real_service_fixture_matrix_v1.json";
const FEATURE_PATH: &str = "artifacts/dependency_feature_platform_consumer_matrix_v1.json";
const RUNNER_PATH: &str = "scripts/run_dependency_sovereignty_e2e.sh";
const DOC_PATH: &str = "docs/dependency_verification_final_signoff.md";
const MATRIX_DOC_PATH: &str = "docs/dependency_verification_matrix.md";
const TESTING_PATH: &str = "TESTING.md";
const LOG_SCHEMA_PATH: &str = "tests/e2e_log_quality_schema.rs";
const BEAD_ID: &str = "asupersync-dep-p1-foundations-upksjk.6.6";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(|| panic!("{key} must be an array"), Vec::as_slice)
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .unwrap_or_else(|| panic!("{key} must be a non-empty string"))
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .filter(|text| !text.trim().is_empty())
                .unwrap_or_else(|| panic!("{key} entries must be non-empty strings"))
                .to_owned()
        })
        .collect()
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    strings(value, key).into_iter().collect()
}

fn rows_by_id<'a>(
    rows: &'a [Value],
    id_key: &str,
    collection_name: &str,
) -> BTreeMap<&'a str, &'a Value> {
    let mut indexed = BTreeMap::new();
    for row in rows {
        let id = row
            .get(id_key)
            .and_then(Value::as_str)
            .filter(|text| !text.trim().is_empty())
            .unwrap_or_else(|| {
                panic!("{collection_name} {id_key} must be a non-empty string: {row}")
            });
        assert!(
            indexed.insert(id, row).is_none(),
            "duplicate {collection_name} row {id}"
        );
    }
    indexed
}

fn evidence_classes(row: &Value) -> BTreeSet<&str> {
    array(row, "evidence_plans")
        .iter()
        .map(|plan| string(plan, "class"))
        .collect()
}

fn has_e2e_or_downstream(row: &Value) -> bool {
    evidence_classes(row)
        .iter()
        .any(|class| matches!(*class, "e2e" | "downstream"))
}

#[test]
fn aggregate_join_emits_a_zero_gap_capability_matrix() {
    let artifact = json(ARTIFACT_PATH);
    let registry = json(REGISTRY_PATH);
    let baseline = json(BASELINE_PATH);
    let cutover = json(CUTOVER_PATH);
    let matrix = json(MATRIX_PATH);
    let failure = json(FAILURE_PATH);
    let service = json(SERVICE_PATH);
    let feature = json(FEATURE_PATH);

    assert_eq!(artifact["schema_version"], 1);
    assert_eq!(
        artifact["artifact_id"],
        "dependency-verification-final-signoff-v1"
    );
    assert_eq!(artifact["bead_id"], BEAD_ID);
    assert_eq!(artifact["verdict"]["outcome"], "PASS_SCOPED_KEEP_DEFER");
    assert_eq!(artifact["verdict"]["dependency_exit_allowed"], false);
    assert_eq!(artifact["verdict"]["cutover_authority"], false);

    let prerequisites = array(&artifact, "prerequisite_deliverables");
    assert_eq!(prerequisites.len(), 9);
    for prerequisite in prerequisites {
        string(prerequisite, "bead_id");
        assert_eq!(string(prerequisite, "required_status"), "closed");
        string(prerequisite, "role");
        string(prerequisite, "primary_evidence");
    }
    assert_eq!(
        artifact["tracker_snapshot"]["plan_semantic_sha256"],
        matrix["inputs"]["tracker_plan_sha256"],
        "VER A6 and VER A1 must resolve the same plan-semantic tracker graph"
    );
    assert_eq!(
        artifact["tracker_snapshot"]["graph_signoff_bead_id"],
        registry["graph_signoff_report"]["signoff_bead_id"]
    );
    assert_eq!(
        artifact["tracker_snapshot"]["graph_signoff_status"],
        registry["graph_signoff_report"]["status"]
    );
    assert_eq!(registry["graph_signoff_report"]["status"], "PASS_SCOPED");
    assert!(
        string(&artifact["canonical_commands"], "live_prerequisite_audit").contains("br show"),
        "operators need an exact live prerequisite audit before closeout"
    );

    let registry_rows = rows_by_id(
        array(&registry, "capabilities"),
        "capability_id",
        "registry",
    );
    let baseline_rows = rows_by_id(
        array(&baseline, "capability_baselines"),
        "capability_id",
        "baseline",
    );
    let cutover_rows = rows_by_id(
        array(&cutover, "capability_bindings"),
        "capability_id",
        "cutover",
    );
    let signoff_rows = string_set(&artifact["resolved_matrix_contract"], "row_ids");
    let registry_ids: BTreeSet<_> = registry_rows.keys().copied().collect();
    let baseline_ids: BTreeSet<_> = baseline_rows.keys().copied().collect();
    let cutover_ids: BTreeSet<_> = cutover_rows.keys().copied().collect();
    let signoff_ids: BTreeSet<_> = signoff_rows.iter().map(String::as_str).collect();

    assert_eq!(registry_rows.len(), 50);
    assert_eq!(registry_ids, baseline_ids);
    assert_eq!(registry_ids, cutover_ids);
    assert_eq!(registry_ids, signoff_ids);
    assert_eq!(
        artifact["resolved_matrix_contract"]["expected_row_count"],
        50
    );
    assert_eq!(
        string(
            &artifact["resolved_matrix_contract"],
            "missing_coordinate_outcome"
        ),
        "FAIL_CLOSED"
    );

    let required_columns = string_set(&artifact["resolved_matrix_contract"], "required_columns");
    let expected_columns = BTreeSet::from([
        "capability_id".to_owned(),
        "unit_evidence".to_owned(),
        "integration_evidence".to_owned(),
        "e2e_evidence".to_owned(),
        "scan_evidence".to_owned(),
        "audit_evidence".to_owned(),
        "scenario_owner".to_owned(),
        "fixture_or_seed".to_owned(),
        "feature_cells".to_owned(),
        "platform_cells".to_owned(),
        "artifact_schema".to_owned(),
        "failure_injection".to_owned(),
        "real_service_owner_or_na".to_owned(),
        "redaction_policy".to_owned(),
        "final_cutover_beads".to_owned(),
        "cutover_state".to_owned(),
    ]);
    assert_eq!(required_columns, expected_columns);
    for column in &required_columns {
        string(
            &artifact["resolved_matrix_contract"]["column_joins"],
            column,
        );
    }

    let verification_rows = array(&matrix, "matrix");
    let mut aggregate_e2e = BTreeMap::<&str, usize>::new();
    for row in verification_rows {
        if has_e2e_or_downstream(row) {
            for capability_id in strings(row, "capability_ids") {
                *aggregate_e2e
                    .entry(
                        registry_rows
                            .get_key_value(capability_id.as_str())
                            .map_or_else(
                                || panic!("matrix references unknown capability {capability_id}"),
                                |(id, _)| *id,
                            ),
                    )
                    .or_default() += 1;
            }
        }
    }

    let implementation_rows: Vec<_> = verification_rows
        .iter()
        .filter(|row| string(row, "role") == "implementation")
        .collect();
    assert_eq!(implementation_rows.len(), 106);
    for row in &implementation_rows {
        let classes = evidence_classes(row);
        assert!(
            classes.contains("unit"),
            "{} lacks focused unit evidence",
            string(row, "bead_id")
        );
        if !has_e2e_or_downstream(row) {
            for capability_id in strings(row, "capability_ids") {
                assert!(
                    aggregate_e2e
                        .get(capability_id.as_str())
                        .is_some_and(|count| *count > 0),
                    "{} lacks direct and capability-aggregate E2E/downstream coverage",
                    string(row, "bead_id")
                );
            }
        }
    }

    let universal_failure_rule = array(&failure, "applicability_rules")
        .iter()
        .find(|rule| string(rule, "family_id") == "universal-boundary")
        .expect("universal failure-injection rule");
    assert_eq!(universal_failure_rule["selector"]["all"], true);
    assert!(
        !array(universal_failure_rule, "scenario_ids").is_empty(),
        "every capability must receive deterministic failure-injection scenarios"
    );
    for scenario in array(&failure, "scenarios") {
        string(scenario, "scenario_id");
        string(scenario, "seed_or_fixture_id");
        string(scenario, "replay_command");
        assert!(
            scenario["max_steps"]
                .as_u64()
                .is_some_and(|value| value > 0),
            "failure scenario must have a bounded step budget"
        );
        assert!(
            scenario["max_virtual_time_ms"]
                .as_u64()
                .is_some_and(|value| value > 0),
            "failure scenario must have a bounded virtual-time budget"
        );
    }

    assert_eq!(feature["counts"]["capabilities"], 50);
    assert_eq!(
        feature["capability_projection"]["missing_coordinate_outcome"],
        "contract failure"
    );

    let service_families = rows_by_id(array(&service, "service_families"), "family_id", "service");
    let service_bindings = rows_by_id(
        array(&artifact, "real_service_capability_bindings"),
        "capability_id",
        "service binding",
    );
    for (capability_id, binding) in &service_bindings {
        assert!(
            registry_rows.contains_key(capability_id),
            "service binding references unknown capability {capability_id}"
        );
        for family_id in strings(binding, "family_ids") {
            assert!(
                service_families.contains_key(family_id.as_str()),
                "{capability_id} references unknown service family {family_id}"
            );
        }
    }

    let mut cutover_counts = BTreeMap::<&str, usize>::new();
    for capability_id in registry_ids {
        let capability = registry_rows[capability_id];
        let baseline_row = baseline_rows[capability_id];
        let cutover_row = cutover_rows[capability_id];

        string(capability, "unit_test_owner");
        string(capability, "e2e_owner");
        assert!(!array(capability, "scenario_ids").is_empty());
        assert!(!array(capability, "features").is_empty());
        assert!(!array(capability, "platforms").is_empty());
        assert!(!array(capability, "replacement_bead_ids").is_empty());
        assert!(!array(baseline_row, "evidence_ids").is_empty());
        assert!(!array(baseline_row, "scenario_ids").is_empty());

        let state = string(cutover_row, "registry_cutover_state");
        *cutover_counts.entry(state).or_default() += 1;
        assert_eq!(
            cutover_row["dependency_exit_allowed"], false,
            "{capability_id} must remain fail-closed for dependency exit"
        );

        if !service_bindings.contains_key(capability_id) {
            assert!(
                artifact["resolved_matrix_contract"]["not_applicable_policy"]
                    .as_str()
                    .is_some_and(|policy| {
                        policy.contains("NOT_APPLICABLE_NON_SERVICE_CAPABILITY")
                    }),
                "non-service N/A policy must be explicit"
            );
        }
    }
    assert_eq!(
        cutover_counts,
        BTreeMap::from([
            ("BLOCKED_PENDING_EVIDENCE", 18),
            ("KEEP_INCUMBENT", 23),
            ("NOT_A_CUTOVER", 9),
        ])
    );
}

#[derive(Clone)]
struct GateFixture {
    unit_test: Option<&'static str>,
    e2e_path: Option<&'static str>,
    artifact_fields: BTreeSet<&'static str>,
    structured_assertion: bool,
    retained_secret: bool,
    replay_pointer: Option<&'static str>,
    rch_required: bool,
    local_fallback_allowed: bool,
    external_service_kind: &'static str,
    sparse_feature_present: bool,
    platform_supported: bool,
    platform_outcome: &'static str,
    service_version: Option<&'static str>,
    service_identity: Option<&'static str>,
    timeout_seconds: Option<u64>,
    orphan_processes: usize,
    evidence_complete: bool,
    cutover_authorized: bool,
}

impl GateFixture {
    fn positive() -> Self {
        Self {
            unit_test: Some("unit-owner"),
            e2e_path: Some("aggregate-e2e-owner"),
            artifact_fields: BTreeSet::from([
                "summary.json",
                "validation_stages.ndjson",
                "stdout.log",
                "stderr.log",
                "repro_manifest.json",
            ]),
            structured_assertion: true,
            retained_secret: false,
            replay_pointer: Some(
                "RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh",
            ),
            rch_required: true,
            local_fallback_allowed: false,
            external_service_kind: "real",
            sparse_feature_present: true,
            platform_supported: false,
            platform_outcome: "UNSUPPORTED",
            service_version: Some("1.2.3"),
            service_identity: Some("sha256:fixture"),
            timeout_seconds: Some(900),
            orphan_processes: 0,
            evidence_complete: true,
            cutover_authorized: false,
        }
    }
}

fn validate_gate(fixture: &GateFixture) -> BTreeSet<&'static str> {
    let mut errors = BTreeSet::new();
    if fixture.unit_test.is_none() {
        errors.insert("missing_unit_test");
    }
    if fixture.e2e_path.is_none() {
        errors.insert("missing_e2e_path");
    }
    let required_artifacts = BTreeSet::from([
        "summary.json",
        "validation_stages.ndjson",
        "stdout.log",
        "stderr.log",
        "repro_manifest.json",
    ]);
    if fixture.artifact_fields != required_artifacts {
        errors.insert("incomplete_artifact_contract");
    }
    if !fixture.structured_assertion {
        errors.insert("log_only_assertion");
    }
    if fixture.retained_secret {
        errors.insert("secret_leakage");
    }
    if fixture.replay_pointer.is_none() {
        errors.insert("missing_replay_pointer");
    }
    if !fixture.rch_required || fixture.local_fallback_allowed {
        errors.insert("silent_local_fallback");
    }
    if fixture.external_service_kind == "mock" {
        errors.insert("mocked_external_service");
    }
    if !fixture.sparse_feature_present {
        errors.insert("missing_sparse_feature");
    }
    if !fixture.platform_supported && fixture.platform_outcome == "PASSED" {
        errors.insert("unsupported_platform_reported_pass");
    }
    if fixture.service_version.is_none() || fixture.service_identity.is_none() {
        errors.insert("unpinned_service");
    }
    if fixture.timeout_seconds.is_none() {
        errors.insert("unbounded_wait");
    }
    if fixture.orphan_processes != 0 {
        errors.insert("orphan_process");
    }
    if fixture.cutover_authorized && !fixture.evidence_complete {
        errors.insert("cutover_preceding_evidence");
    }
    errors
}

#[test]
fn every_named_negative_fixture_fails_closed() {
    let artifact = json(ARTIFACT_PATH);
    let catalog: BTreeMap<_, _> = array(&artifact, "negative_fixture_catalog")
        .iter()
        .map(|fixture| {
            (
                string(fixture, "fixture_id"),
                string(fixture, "expected_error"),
            )
        })
        .collect();
    let expected_catalog = BTreeMap::from([
        (
            "NEG-A6-CUTOVER-BEFORE-EVIDENCE",
            "cutover_preceding_evidence",
        ),
        ("NEG-A6-LOCAL-FALLBACK", "silent_local_fallback"),
        ("NEG-A6-LOG-ONLY", "log_only_assertion"),
        ("NEG-A6-MISSING-SPARSE-FEATURE", "missing_sparse_feature"),
        ("NEG-A6-MOCKED-SERVICE", "mocked_external_service"),
        (
            "NEG-A6-NO-ARTIFACT-CONTRACT",
            "incomplete_artifact_contract",
        ),
        ("NEG-A6-NO-E2E", "missing_e2e_path"),
        ("NEG-A6-NO-REPLAY", "missing_replay_pointer"),
        ("NEG-A6-NO-UNIT", "missing_unit_test"),
        ("NEG-A6-ORPHAN-PROCESS", "orphan_process"),
        ("NEG-A6-SECRET-LEAK", "secret_leakage"),
        ("NEG-A6-UNBOUNDED-WAIT", "unbounded_wait"),
        ("NEG-A6-UNPINNED-SERVICE", "unpinned_service"),
        (
            "NEG-A6-UNSUPPORTED-AS-PASS",
            "unsupported_platform_reported_pass",
        ),
    ]);
    assert_eq!(catalog, expected_catalog);

    let positive = GateFixture::positive();
    assert!(
        validate_gate(&positive).is_empty(),
        "positive fixture must have no gaps"
    );

    let mut cases = Vec::new();

    let mut fixture = positive.clone();
    fixture.unit_test = None;
    cases.push(("missing_unit_test", fixture));

    let mut fixture = positive.clone();
    fixture.e2e_path = None;
    cases.push(("missing_e2e_path", fixture));

    let mut fixture = positive.clone();
    fixture.artifact_fields.remove("stderr.log");
    cases.push(("incomplete_artifact_contract", fixture));

    let mut fixture = positive.clone();
    fixture.structured_assertion = false;
    cases.push(("log_only_assertion", fixture));

    let mut fixture = positive.clone();
    fixture.retained_secret = true;
    cases.push(("secret_leakage", fixture));

    let mut fixture = positive.clone();
    fixture.replay_pointer = None;
    cases.push(("missing_replay_pointer", fixture));

    let mut fixture = positive.clone();
    fixture.local_fallback_allowed = true;
    cases.push(("silent_local_fallback", fixture));

    let mut fixture = positive.clone();
    fixture.external_service_kind = "mock";
    cases.push(("mocked_external_service", fixture));

    let mut fixture = positive.clone();
    fixture.sparse_feature_present = false;
    cases.push(("missing_sparse_feature", fixture));

    let mut fixture = positive.clone();
    fixture.platform_outcome = "PASSED";
    cases.push(("unsupported_platform_reported_pass", fixture));

    let mut fixture = positive.clone();
    fixture.service_identity = None;
    cases.push(("unpinned_service", fixture));

    let mut fixture = positive.clone();
    fixture.timeout_seconds = None;
    cases.push(("unbounded_wait", fixture));

    let mut fixture = positive.clone();
    fixture.orphan_processes = 1;
    cases.push(("orphan_process", fixture));

    let mut fixture = positive;
    fixture.evidence_complete = false;
    fixture.cutover_authorized = true;
    cases.push(("cutover_preceding_evidence", fixture));

    assert_eq!(cases.len(), 14);
    for (expected_error, fixture) in cases {
        assert_eq!(
            validate_gate(&fixture),
            BTreeSet::from([expected_error]),
            "negative fixture for {expected_error} must fail for exactly that reason"
        );
    }
}

#[test]
fn forensic_runner_and_operator_docs_expose_the_signoff() {
    let artifact = json(ARTIFACT_PATH);
    let runner = read_repo_file(RUNNER_PATH);
    let docs = read_repo_file(DOC_PATH);
    let matrix_docs = read_repo_file(MATRIX_DOC_PATH);
    let testing = read_repo_file(TESTING_PATH);
    let log_schema = read_repo_file(LOG_SCHEMA_PATH);

    let focused_command = string(&artifact["canonical_commands"], "focused_contract");
    let dry_run_command = string(&artifact["canonical_commands"], "suite_dry_run");
    let replay_command = string(&artifact["canonical_commands"], "replay");
    for token in [
        "RCH_REQUIRE_REMOTE=1",
        "--base HEAD",
        "--clean-overlay",
        "--no-overlay",
        "dependency_verification_final_signoff_contract",
    ] {
        assert!(
            focused_command.contains(token),
            "focused command missing {token}"
        );
    }
    assert!(dry_run_command.contains("--dry-run"));
    assert!(replay_command.contains("aggregate-signoff-contract"));

    for token in [
        "artifacts/dependency_verification_final_signoff_v1.json",
        "aggregate-signoff-contract",
        "dependency_verification_final_signoff_contract",
        "ver-a6-aggregate-signoff-contract",
    ] {
        assert!(runner.contains(token), "runner missing {token}");
        assert!(log_schema.contains(token), "log schema missing {token}");
    }

    for token in [
        "PASS_SCOPED_KEEP_DEFER",
        "N/A_ROW_LOCAL_AGGREGATE_CAPABILITY_COVERAGE",
        "aggregate-signoff-contract",
        "No-claim boundary",
    ] {
        assert!(docs.contains(token), "signoff docs missing {token}");
    }
    assert!(
        matrix_docs.contains("VER A6 aggregate verification signoff"),
        "verification matrix docs must link the aggregate signoff"
    );
    assert!(
        testing.contains("aggregate-signoff-contract"),
        "TESTING.md must record the canonical scenario"
    );

    let retained_files = string_set(
        &artifact["forensic_artifact_contract"],
        "required_retained_files",
    );
    assert_eq!(retained_files.len(), 9);
    assert_eq!(
        artifact["forensic_artifact_contract"]["minimum_log_quality_score"],
        80
    );
    assert_eq!(
        artifact["forensic_artifact_contract"]["remote_execution"]["local_cargo_fallback_allowed"],
        false
    );
    assert_eq!(
        artifact["forensic_artifact_contract"]["orphan_processes_allowed"],
        false
    );
}

#[test]
fn no_claim_boundary_remains_explicit_and_fail_closed() {
    let artifact = json(ARTIFACT_PATH);
    let no_claims = strings(&artifact, "no_claim_boundaries").join(" ");
    for phrase in [
        "plans, not proof",
        "does not authorize",
        "broad runtime correctness",
        "performance",
        "release readiness",
        "live RCH fleet availability",
        "unavailable service or platform execution",
    ] {
        assert!(
            no_claims.contains(phrase),
            "no-claim boundary missing {phrase}"
        );
    }
}
