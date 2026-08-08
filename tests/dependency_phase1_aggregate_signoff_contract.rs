#![allow(clippy::nursery, clippy::pedantic, missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

const ARTIFACT_PATH: &str = "artifacts/dependency_phase1_aggregate_signoff_v1.json";
const TAXONOMY_PATH: &str = "artifacts/dependency_safety_taxonomy_v1.json";
const LEDGER_PATH: &str = "artifacts/dependency_marginal_ledger_v1.json";
const ORACLE_PATH: &str = "artifacts/dependency_oracle_policy_v1.json";
const REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const BASELINE_PATH: &str = "artifacts/dependency_capability_baseline_v1.json";
const MATRIX_PATH: &str = "artifacts/dependency_verification_matrix_v1.json";
const VERIFICATION_SIGNOFF_PATH: &str = "artifacts/dependency_verification_final_signoff_v1.json";
const TRACKER_PATH: &str = ".beads/issues.jsonl";
const DOC_PATH: &str = "docs/dependency_phase1_aggregate_signoff.md";
const GATE_BEAD_ID: &str = "asupersync-dep-p1-foundations-upksjk.4";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
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

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn tracker_issues() -> BTreeMap<String, Value> {
    let mut issues = BTreeMap::new();
    for (line_number, line) in read_repo_file(TRACKER_PATH).lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let issue: Value = serde_json::from_str(line).unwrap_or_else(|error| {
            panic!("parse {TRACKER_PATH} line {}: {error}", line_number + 1)
        });
        let id = string(&issue, "id").to_owned();
        assert!(
            issues.insert(id.clone(), issue).is_none(),
            "duplicate tracker issue {id}"
        );
    }
    issues
}

fn blocking_dependency_ids(issue: &Value) -> impl Iterator<Item = &str> {
    issue
        .get("dependencies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|dependency| {
            (dependency.get("type").and_then(Value::as_str) == Some("blocks"))
                .then(|| dependency.get("depends_on_id").and_then(Value::as_str))
                .flatten()
        })
}

fn gate_dependency_ids(issue: &Value) -> impl Iterator<Item = &str> {
    issue
        .get("dependencies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|dependency| {
            matches!(
                dependency.get("type").and_then(Value::as_str),
                Some("blocks" | "parent-child")
            )
            .then(|| dependency.get("depends_on_id").and_then(Value::as_str))
            .flatten()
        })
}

fn transitively_depends_on(
    issues: &BTreeMap<String, Value>,
    start: &str,
    required_ancestor: &str,
) -> bool {
    let mut pending = vec![start];
    let mut seen = BTreeSet::new();
    while let Some(issue_id) = pending.pop() {
        if !seen.insert(issue_id) {
            continue;
        }
        let issue = issues
            .get(issue_id)
            .unwrap_or_else(|| panic!("tracker is missing dependency node {issue_id}"));
        for dependency_id in gate_dependency_ids(issue) {
            if dependency_id == required_ancestor {
                return true;
            }
            pending.push(dependency_id);
        }
    }
    false
}

fn visit_blocking_graph(
    issue_id: &str,
    issues: &BTreeMap<String, Value>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
) -> bool {
    if visited.contains(issue_id) {
        return false;
    }
    if !visiting.insert(issue_id.to_owned()) {
        return true;
    }
    if let Some(issue) = issues.get(issue_id) {
        for dependency_id in blocking_dependency_ids(issue) {
            if issues.contains_key(dependency_id)
                && visit_blocking_graph(dependency_id, issues, visiting, visited)
            {
                return true;
            }
        }
    }
    visiting.remove(issue_id);
    visited.insert(issue_id.to_owned());
    false
}

fn blocking_graph_has_cycle(issues: &BTreeMap<String, Value>) -> bool {
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    issues
        .keys()
        .any(|issue_id| visit_blocking_graph(issue_id, issues, &mut visiting, &mut visited))
}

#[test]
fn source_contracts_are_content_pinned_and_closed() {
    let artifact = json(ARTIFACT_PATH);
    let issues = tracker_issues();

    assert_eq!(artifact["schema_version"], 1);
    assert_eq!(
        artifact["artifact_id"],
        "dependency-phase1-aggregate-signoff-v1"
    );
    assert_eq!(artifact["bead_id"], GATE_BEAD_ID);
    assert_eq!(artifact["program_id"], "asupersync-ir2uf0");
    assert_eq!(
        artifact["verdict"]["outcome"],
        "PASS_SCOPED_FOUNDATIONS_ONLY"
    );
    assert_eq!(artifact["verdict"]["dependency_exit_allowed"], false);
    assert_eq!(artifact["verdict"]["cutover_authority"], false);

    let sources = array(&artifact, "source_contracts");
    assert_eq!(sources.len(), 8);
    for source in sources {
        let path = string(source, "path");
        let expected_digest = string(source, "sha256");
        assert_eq!(expected_digest.len(), 64, "{path} digest must be SHA-256");
        assert_eq!(
            sha256_hex(read_repo_file(path).as_bytes()),
            expected_digest,
            "{path} drifted after aggregate signoff"
        );
        let issue = issues
            .get(string(source, "bead_id"))
            .unwrap_or_else(|| panic!("missing source bead {}", string(source, "bead_id")));
        assert_eq!(
            issue["status"],
            "closed",
            "{} must be closed",
            string(source, "bead_id")
        );
        string(source, "role");
    }
}

#[test]
fn candidate_capability_ledger_and_oracle_ids_reconcile() {
    let artifact = json(ARTIFACT_PATH);
    let taxonomy = json(TAXONOMY_PATH);
    let ledger = json(LEDGER_PATH);
    let oracle = json(ORACLE_PATH);
    let registry = json(REGISTRY_PATH);
    let reconciliation = &artifact["inventory_reconciliation"];

    let taxonomy_ids = array(&taxonomy, "classifications")
        .iter()
        .map(|row| string(row, "candidate_id").to_owned())
        .collect::<BTreeSet<_>>();
    let mapping_ids = array(&registry, "taxonomy_mapping")
        .iter()
        .map(|row| string(row, "candidate_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(taxonomy_ids.len(), 33);
    assert_eq!(taxonomy_ids, mapping_ids);

    let capability_ids = array(&registry, "capabilities")
        .iter()
        .map(|row| string(row, "capability_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(capability_ids.len(), 50);
    for mapping in array(&registry, "taxonomy_mapping") {
        for capability_id in strings(mapping, "capability_ids") {
            assert!(
                capability_ids.contains(&capability_id),
                "{} maps unknown capability {capability_id}",
                string(mapping, "candidate_id")
            );
        }
    }

    let ledger_ids = array(&ledger, "marginal_measurements")
        .iter()
        .flat_map(|row| {
            array(row, "taxonomy_refs")
                .iter()
                .map(|reference| string(reference, "candidate_id").to_owned())
        })
        .collect::<BTreeSet<_>>();
    let implementation_only = string_set(reconciliation, "implementation_only_candidate_ids");
    assert!(ledger_ids.is_subset(&taxonomy_ids));
    assert_eq!(
        ledger_ids
            .union(&implementation_only)
            .cloned()
            .collect::<BTreeSet<_>>(),
        taxonomy_ids,
        "every taxonomy candidate needs a measured Cargo projection or an explicit implementation-only disposition"
    );
    assert_eq!(
        implementation_only,
        BTreeSet::from(["simd-dispatch-boundary".to_owned()])
    );

    let oracle_ids = array(&oracle, "oracle_registry")
        .iter()
        .flat_map(|row| strings(row, "replacement_candidate_ids"))
        .collect::<BTreeSet<_>>();
    let no_oracle_required = string_set(reconciliation, "no_oracle_required_candidate_ids");
    let quarantine_only = string_set(reconciliation, "quarantine_only_oracle_candidate_ids");
    assert_eq!(
        taxonomy_ids
            .difference(&oracle_ids)
            .cloned()
            .collect::<BTreeSet<_>>(),
        no_oracle_required
    );
    assert_eq!(
        oracle_ids
            .difference(&taxonomy_ids)
            .cloned()
            .collect::<BTreeSet<_>>(),
        quarantine_only
    );
    assert_eq!(
        quarantine_only,
        BTreeSet::from([
            "kafka-native-client".to_owned(),
            "sqlite-cycle-safe-integration".to_owned(),
        ])
    );
    for disposition in array(reconciliation, "no_oracle_required_dispositions") {
        assert!(no_oracle_required.contains(string(disposition, "candidate_id")));
        string(disposition, "reason");
    }
    assert_eq!(
        array(reconciliation, "no_oracle_required_dispositions").len(),
        no_oracle_required.len()
    );
    for binding in array(reconciliation, "quarantine_candidate_capability_bindings") {
        assert!(quarantine_only.contains(string(binding, "candidate_id")));
        for capability_id in strings(binding, "capability_ids") {
            assert!(capability_ids.contains(&capability_id));
        }
    }
}

#[test]
fn baseline_matrix_and_provenance_are_frozen() {
    let artifact = json(ARTIFACT_PATH);
    let ledger = json(LEDGER_PATH);
    let baseline = json(BASELINE_PATH);
    let matrix = &artifact["baseline_provenance"];

    assert_eq!(
        string(matrix, "ledger_source_commit"),
        string(&ledger, "source_commit")
    );
    assert_eq!(
        string(matrix, "capability_baseline_revision"),
        string(&baseline, "baseline_source_revision")
    );
    assert_eq!(
        string(matrix, "cargo_version"),
        string(&ledger, "cargo_version")
    );
    assert_eq!(
        string(matrix, "rustc_version"),
        string(&ledger, "rustc_version")
    );
    assert_eq!(
        string(matrix, "host_triple"),
        string(&ledger, "host_triple")
    );

    let required_profiles = string_set(matrix, "feature_profiles");
    let actual_profiles = array(&ledger, "canonical_profiles")
        .iter()
        .map(|profile| string(profile, "profile_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(required_profiles.len(), 13);
    assert_eq!(required_profiles, actual_profiles);

    let required_targets = string_set(matrix, "target_triples");
    let actual_targets = string_set(&ledger, "canonical_target_triples");
    assert_eq!(required_targets.len(), 4);
    assert_eq!(required_targets, actual_targets);

    let graph_keys = array(&ledger, "graph_records")
        .iter()
        .map(|row| {
            (
                string(row, "feature_profile").to_owned(),
                string(row, "target_triple").to_owned(),
                string(row, "host_triple").to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    let expected_keys = required_profiles
        .iter()
        .flat_map(|profile| {
            required_targets.iter().map(|target| {
                (
                    profile.clone(),
                    target.clone(),
                    string(matrix, "host_triple").to_owned(),
                )
            })
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(graph_keys, expected_keys);
    assert_eq!(graph_keys.len(), 52);

    for row in array(&ledger, "marginal_measurements") {
        assert!(required_profiles.contains(string(row, "feature_profile")));
        assert!(required_targets.contains(string(row, "target_triple")));
        assert_eq!(string(row, "host_triple"), string(matrix, "host_triple"));
        assert_ne!(
            string(row, "baseline_manifest_hash"),
            string(row, "counterfactual_manifest_hash")
        );
        assert_ne!(
            string(row, "exact_baseline_command"),
            string(row, "exact_counterfactual_command")
        );
    }

    let identity_policy = strings(&ledger, "upstream_identity_policy").join(" ");
    assert!(identity_policy.contains("immutable revision"));
    assert!(identity_policy.contains("unknown:<package-id>"));
    assert!(identity_policy.contains("never merged"));
    let native_policy = strings(&ledger, "native_evidence_policy").join(" ");
    assert!(native_policy.contains("unknown is fail-closed"));
    assert_eq!(
        artifact["operator_summary"]["unknown_native_evidence"]["disposition"],
        "EXPLICITLY_BLOCKED_NOT_GREEN"
    );
}

#[test]
fn oracle_locations_lifecycles_and_release_quarantine_fail_closed() {
    let artifact = json(ARTIFACT_PATH);
    let oracle = json(ORACLE_PATH);

    assert_eq!(array(&oracle, "oracle_registry").len(), 24);
    assert_eq!(oracle["summary"]["active_expired_without_extension"], 0);
    assert_eq!(
        oracle["summary"]["native_or_reverse_allowed_in_ordinary_workspace_profiles"],
        0
    );
    for row in array(&oracle, "oracle_registry") {
        let allowed = string_set(row, "allowed_profiles");
        let forbidden = string_set(row, "forbidden_profiles");
        assert!(
            allowed.is_disjoint(&forbidden),
            "{} has overlapping allowed and forbidden profiles",
            string(row, "oracle_id")
        );
        assert!(
            forbidden.contains("workspace-release"),
            "{} is not forbidden from release",
            string(row, "oracle_id")
        );
        string(row, "harness_location");
        string(row, "retirement_bead");
        string(row, "expiry_release");
        if matches!(
            string(row, "oracle_class"),
            "NATIVE_OR_C_ORACLE" | "REVERSE_DEPENDENCY_ORACLE"
        ) {
            assert!(
                allowed.iter().all(|profile| {
                    matches!(
                        profile.as_str(),
                        "external-cargo-harness"
                            | "frozen-fixture-only"
                            | "downstream-project"
                            | "neutral-synthesized-consumer"
                    )
                }),
                "{} escaped its cycle-safe quarantine",
                string(row, "oracle_id")
            );
            assert!(
                forbidden.contains("workspace-normal")
                    && forbidden.contains("workspace-dev")
                    && forbidden.contains("workspace-build")
                    && forbidden.contains("workspace-release")
                    && forbidden.contains("workspace-fuzz-quarantine")
            );
        }
    }

    assert_eq!(
        artifact["oracle_gate"]["native_or_reverse_release_policy"],
        "FORBIDDEN"
    );
    assert_eq!(
        artifact["oracle_gate"]["expired_active_oracle_policy"],
        "FAIL_CLOSED"
    );
    assert_eq!(
        artifact["oracle_gate"]["reverse_dependency_cycle_policy"],
        "FAIL_CLOSED"
    );
}

#[test]
fn every_later_plan_row_is_transitively_blocked_by_the_gate() {
    let artifact = json(ARTIFACT_PATH);
    let verification = json(MATRIX_PATH);
    let issues = tracker_issues();
    let graph = &artifact["graph_gate"];

    assert!(!blocking_graph_has_cycle(&issues));
    let direct_dependents = issues
        .values()
        .filter(|issue| {
            blocking_dependency_ids(issue).any(|dependency_id| dependency_id == GATE_BEAD_ID)
        })
        .count();
    assert_eq!(
        direct_dependents as u64,
        graph["direct_blocked_issue_count"]
            .as_u64()
            .expect("direct_blocked_issue_count")
    );

    let later_rows = array(&verification, "matrix")
        .iter()
        .filter(|row| !string(row, "bead_id").starts_with("asupersync-dep-p1-foundations-upksjk"))
        .collect::<Vec<_>>();
    assert_eq!(
        later_rows.len() as u64,
        graph["later_matrix_row_count"]
            .as_u64()
            .expect("later_matrix_row_count")
    );
    let mut roles = BTreeMap::<&str, usize>::new();
    for row in &later_rows {
        let bead_id = string(row, "bead_id");
        assert!(
            transitively_depends_on(&issues, bead_id, GATE_BEAD_ID),
            "{bead_id} bypasses the Phase-1 aggregate gate"
        );
        *roles.entry(string(row, "role")).or_default() += 1;
    }
    assert_eq!(
        roles,
        BTreeMap::from([
            ("architecture", 11),
            ("decision", 15),
            ("implementation", 104),
            ("verification", 187),
        ])
    );
    assert_eq!(graph["later_implementation_row_count"], 104);
    assert_eq!(graph["blocking_graph_cycle_count"], 0);
}

#[test]
fn operator_summary_is_non_authorizing_and_preserves_typed_blockers() {
    let artifact = json(ARTIFACT_PATH);
    let registry = json(REGISTRY_PATH);
    let baseline = json(BASELINE_PATH);
    let verification_signoff = json(VERIFICATION_SIGNOFF_PATH);
    let summary = &artifact["operator_summary"];

    let mut cutover_states = BTreeMap::<&str, usize>::new();
    for capability in array(&registry, "capabilities") {
        *cutover_states
            .entry(string(capability, "cutover_state"))
            .or_default() += 1;
    }
    assert_eq!(
        cutover_states,
        BTreeMap::from([
            ("BLOCKED_PENDING_EVIDENCE", 18),
            ("KEEP_INCUMBENT", 23),
            ("NOT_A_CUTOVER", 9),
        ])
    );
    assert_eq!(summary["evidence_gated_capabilities"]["count"], 18);
    assert_eq!(summary["keep_incumbent_capabilities"]["count"], 23);
    assert_eq!(summary["guard_only_capabilities"]["count"], 9);
    assert_eq!(
        summary["authorized_work"]["scope"],
        "DOWNSTREAM_EVIDENCE_WORK_ONLY"
    );
    assert_eq!(summary["authorized_work"]["dependency_exit_allowed"], false);
    assert_eq!(summary["authorized_work"]["cutover_allowed"], false);

    let mut blocked_owner_cases = 0_u64;
    let mut blocked_owner_ids = BTreeSet::new();
    for capability in array(&baseline, "capability_baselines") {
        for case in capability
            .get("cases")
            .and_then(Value::as_object)
            .unwrap_or_else(|| {
                panic!(
                    "{} cases must be an object",
                    string(capability, "capability_id")
                )
            })
            .values()
        {
            if case.get("disposition").and_then(Value::as_str) == Some("BLOCKED_OWNER") {
                blocked_owner_cases += 1;
                blocked_owner_ids.insert(string(case, "owner_bead").to_owned());
            }
        }
    }
    assert_eq!(blocked_owner_cases, 35);
    assert_eq!(blocked_owner_ids.len(), 21);
    assert_eq!(summary["blocked_owner_cases"]["count"], 35);
    assert_eq!(summary["blocked_owner_cases"]["owner_count"], 21);

    assert_eq!(
        verification_signoff["verdict"]["outcome"],
        "PASS_SCOPED_KEEP_DEFER"
    );
    assert_eq!(
        verification_signoff["verdict"]["dependency_exit_allowed"],
        false
    );
    assert_eq!(verification_signoff["verdict"]["cutover_authority"], false);
}

#[derive(Clone)]
struct FoundationFixture {
    planned_candidates: BTreeSet<&'static str>,
    taxonomy_candidates: BTreeSet<&'static str>,
    required_profiles: BTreeSet<&'static str>,
    ledger_profiles: BTreeSet<&'static str>,
    unknown_native_rows: usize,
    unknown_native_explicitly_blocked: bool,
    native_oracle_allowed_in_release: bool,
    reverse_dependency_cycle: bool,
    active_oracle_expired: bool,
}

impl FoundationFixture {
    fn positive() -> Self {
        Self {
            planned_candidates: BTreeSet::from(["codec", "platform"]),
            taxonomy_candidates: BTreeSet::from(["codec", "platform"]),
            required_profiles: BTreeSet::from(["minimal", "default", "workspace-audit"]),
            ledger_profiles: BTreeSet::from(["minimal", "default", "workspace-audit"]),
            unknown_native_rows: 1,
            unknown_native_explicitly_blocked: true,
            native_oracle_allowed_in_release: false,
            reverse_dependency_cycle: false,
            active_oracle_expired: false,
        }
    }
}

fn validate_foundation(fixture: &FoundationFixture) -> BTreeSet<&'static str> {
    let mut errors = BTreeSet::new();
    if fixture.planned_candidates != fixture.taxonomy_candidates {
        errors.insert("missing_taxonomy_row");
    }
    if fixture.required_profiles != fixture.ledger_profiles {
        errors.insert("stale_ledger_profile");
    }
    if fixture.native_oracle_allowed_in_release {
        errors.insert("native_oracle_in_release_lane");
    }
    if fixture.reverse_dependency_cycle {
        errors.insert("reverse_dependency_cycle");
    }
    if fixture.unknown_native_rows > 0 && !fixture.unknown_native_explicitly_blocked {
        errors.insert("unknown_native_evidence");
    }
    if fixture.active_oracle_expired {
        errors.insert("expired_oracle");
    }
    errors
}

#[test]
fn all_six_aggregate_negative_fixtures_fail_for_exactly_one_reason() {
    let artifact = json(ARTIFACT_PATH);
    let catalog = array(&artifact, "negative_fixture_catalog")
        .iter()
        .map(|fixture| {
            (
                string(fixture, "fixture_id"),
                string(fixture, "expected_error"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        catalog,
        BTreeMap::from([
            ("NEG-P1-EXPIRED-ORACLE", "expired_oracle"),
            ("NEG-P1-MISSING-TAXONOMY", "missing_taxonomy_row"),
            (
                "NEG-P1-NATIVE-ORACLE-RELEASE",
                "native_oracle_in_release_lane",
            ),
            ("NEG-P1-REVERSE-CYCLE", "reverse_dependency_cycle"),
            ("NEG-P1-STALE-LEDGER-PROFILE", "stale_ledger_profile"),
            ("NEG-P1-UNKNOWN-NATIVE", "unknown_native_evidence"),
        ])
    );

    let positive = FoundationFixture::positive();
    assert!(validate_foundation(&positive).is_empty());
    let mut cases = Vec::new();

    let mut fixture = positive.clone();
    fixture.taxonomy_candidates.remove("codec");
    cases.push(("missing_taxonomy_row", fixture));

    let mut fixture = positive.clone();
    fixture.ledger_profiles.remove("default");
    cases.push(("stale_ledger_profile", fixture));

    let mut fixture = positive.clone();
    fixture.native_oracle_allowed_in_release = true;
    cases.push(("native_oracle_in_release_lane", fixture));

    let mut fixture = positive.clone();
    fixture.reverse_dependency_cycle = true;
    cases.push(("reverse_dependency_cycle", fixture));

    let mut fixture = positive.clone();
    fixture.unknown_native_explicitly_blocked = false;
    cases.push(("unknown_native_evidence", fixture));

    let mut fixture = positive;
    fixture.active_oracle_expired = true;
    cases.push(("expired_oracle", fixture));

    assert_eq!(cases.len(), 6);
    for (expected_error, fixture) in cases {
        assert_eq!(
            validate_foundation(&fixture),
            BTreeSet::from([expected_error]),
            "{expected_error} fixture must fail for exactly its named reason"
        );
    }
}

#[test]
fn commands_docs_and_no_claim_boundaries_are_exact() {
    let artifact = json(ARTIFACT_PATH);
    let docs = read_repo_file(DOC_PATH);
    let commands = &artifact["canonical_commands"];
    let focused = string(commands, "focused_foundation_and_aggregate_contracts");
    for token in [
        "RCH_REQUIRE_REMOTE=1",
        "--base HEAD",
        "--clean-overlay",
        "--no-overlay",
        "dependency_safety_taxonomy_contract",
        "dependency_marginal_ledger_contract",
        "dependency_oracle_policy_contract",
        "dependency_phase1_aggregate_signoff_contract",
    ] {
        assert!(focused.contains(token), "focused command missing {token}");
    }
    assert!(string(commands, "live_graph_audit").contains("br dep cycles"));
    assert!(string(commands, "live_prerequisite_audit").contains("br show"));
    assert!(string(commands, "ledger_regeneration").contains("cargo run"));

    for token in [
        "PASS_SCOPED_FOUNDATIONS_ONLY",
        "f606e28983199a1b51af11e6f65bb9b00686ceb3",
        "33 taxonomy candidates",
        "13 feature profiles",
        "4 target triples",
        "104 later implementation rows",
        "35 baseline cases",
        "No-claim boundary",
    ] {
        assert!(docs.contains(token), "operator docs missing {token}");
    }

    let no_claims = strings(&artifact, "no_claim_boundaries").join(" ");
    for phrase in [
        "does not authorize dependency exit",
        "performance",
        "runtime correctness",
        "release readiness",
        "broad workspace health",
        "live RCH fleet availability",
        "permission to delete files",
    ] {
        assert!(
            no_claims.contains(phrase),
            "no-claim boundary missing {phrase}"
        );
    }
}
