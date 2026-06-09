#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const AGENTS_PATH: &str = "AGENTS.md";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const README_PATH: &str = "README.md";
const RUNBOOK_PATH: &str = "docs/fourth_wave_swarm_governor_runbook.md";
const SIGNOFF_PATH: &str = "artifacts/fourth_wave_governor_final_signoff_v1.json";
const SNAPSHOT_PATH: &str = "artifacts/proof_status_snapshot_v1.json";
const TEST_PATH: &str = "tests/fourth_wave_governor_final_signoff_contract.rs";

const CHILD_LANES: &[&str] = &[
    "fourth-wave-governor-schema-contract",
    "fourth-wave-governor-policy-engine",
    "fourth-wave-swarm-replay-corpus",
    "fourth-wave-runtime-bridge-contract",
    "fourth-wave-governor-signoff-runbook",
    "fourth-wave-benchmark-contract",
];

#[derive(Debug, Clone, Eq, PartialEq)]
struct ReportRow {
    row_id: String,
    child_bead_id: String,
    proof_command_id: String,
    evidence_status: String,
    artifact_hashes: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct OperatorReport {
    final_verdict: String,
    parent_close_allowed: bool,
    first_failing_row: Option<String>,
    rows: Vec<ReportRow>,
    markdown: String,
}

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

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
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

fn manifest_lanes(manifest: &Value) -> BTreeMap<String, Value> {
    array(manifest, "lanes")
        .iter()
        .map(|lane| (string(lane, "lane_id").to_string(), lane.clone()))
        .collect()
}

fn snapshot_claims(snapshot: &Value) -> BTreeMap<String, Value> {
    array(snapshot, "claim_categories")
        .iter()
        .map(|row| (string(row, "claim_id").to_string(), row.clone()))
        .collect()
}

fn signoff() -> Value {
    json(SIGNOFF_PATH)
}

fn assert_contains_all(label: &str, text: &str, markers: &[&str]) {
    for marker in markers {
        assert!(text.contains(marker), "{label} missing {marker}");
    }
}

fn assert_remote_required_cargo(command: &str) {
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
        "command must be remote-required RCH: {command}"
    );
    assert!(
        command.contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_fourth_wave_"),
        "command must isolate a fourth-wave target dir: {command}"
    );
    assert!(
        command.contains(" cargo "),
        "command must route Cargo through RCH: {command}"
    );
    for forbidden in [
        "RCH_ALLOW_LOCAL=1",
        "RCH_REQUIRE_REMOTE=0",
        "rch exec -- cargo",
    ] {
        assert!(
            !command.contains(forbidden),
            "command contains forbidden local/fallback marker {forbidden}: {command}"
        );
    }
}

fn sha256_file(relative: &str) -> String {
    let bytes = std::fs::read(repo_path(relative))
        .unwrap_or_else(|error| panic!("hash input {relative}: {error}"));
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn render_report(signoff: &Value) -> OperatorReport {
    let policy = &signoff["freshness_policy"];
    let required_status = string(policy, "required_evidence_status");
    let rows = array(signoff, "required_child_rows")
        .iter()
        .map(|row| {
            let mut artifact_paths = string_set(row, "artifact_paths")
                .into_iter()
                .collect::<Vec<_>>();
            artifact_paths.sort();
            let artifact_hashes = artifact_paths
                .iter()
                .map(|path| format!("{path}:sha256={}", sha256_file(path)))
                .collect::<Vec<_>>();
            ReportRow {
                row_id: string(row, "row_id").to_string(),
                child_bead_id: string(row, "owner_bead").to_string(),
                proof_command_id: string(row, "proof_command_id").to_string(),
                evidence_status: string(row, "current_evidence_status").to_string(),
                artifact_hashes,
            }
        })
        .collect::<Vec<_>>();

    let first_failing_row = rows
        .iter()
        .find(|row| row.evidence_status != required_status)
        .map(|row| row.row_id.clone());
    let final_verdict = if first_failing_row.is_some() {
        "no_win_rerun_required"
    } else {
        "pass"
    }
    .to_string();
    let parent_close_allowed = final_verdict == "pass";
    let mut markdown = format!(
        "# Fourth-wave final signoff\n\nfinal_verdict={final_verdict}\nparent_close_allowed={parent_close_allowed}\nfirst_failing_row={}\nfreshness_window_seconds={}\n",
        first_failing_row.as_deref().unwrap_or("none"),
        policy["freshness_window_seconds"]
            .as_u64()
            .expect("freshness_window_seconds")
    );
    for row in &rows {
        markdown.push_str(&format!(
            "\n- child_bead_id={} proof_command_id={} evidence_status={}",
            row.child_bead_id, row.proof_command_id, row.evidence_status
        ));
        for hash in &row.artifact_hashes {
            markdown.push_str(&format!(" artifact_sha256={hash}"));
        }
    }

    OperatorReport {
        final_verdict,
        parent_close_allowed,
        first_failing_row,
        rows,
        markdown,
    }
}

#[test]
fn signoff_artifact_declares_sources_child_rows_and_current_no_win_report() {
    let artifact = signoff();
    assert_eq!(
        string(&artifact, "schema_version"),
        "fourth-wave-governor-final-signoff-v1"
    );
    assert_eq!(string(&artifact, "bead_id"), "asupersync-86fe9v.6");
    assert_eq!(string(&artifact, "parent_bead"), "asupersync-86fe9v");

    let source = &artifact["source_of_truth"];
    for (key, expected) in [
        ("signoff_artifact", SIGNOFF_PATH),
        ("contract_test", TEST_PATH),
        ("operator_runbook", RUNBOOK_PATH),
        ("proof_lane_manifest", MANIFEST_PATH),
        ("proof_status_snapshot", SNAPSHOT_PATH),
        ("readme", README_PATH),
        ("agent_instructions", AGENTS_PATH),
    ] {
        assert_eq!(string(source, key), expected);
        assert!(
            repo_path(expected).exists(),
            "source_of_truth.{key} path {expected} must exist"
        );
    }

    let rows = array(&artifact, "required_child_rows");
    assert_eq!(
        rows.len(),
        6,
        "final signoff must audit every child bead lane"
    );
    let owner_beads = rows
        .iter()
        .map(|row| string(row, "owner_bead").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        owner_beads,
        BTreeSet::from([
            "asupersync-86fe9v.1".to_string(),
            "asupersync-86fe9v.2".to_string(),
            "asupersync-86fe9v.3".to_string(),
            "asupersync-86fe9v.4".to_string(),
            "asupersync-86fe9v.5".to_string(),
            "asupersync-86fe9v.7".to_string(),
        ])
    );
    assert_eq!(
        string(&artifact["current_operator_report"], "final_verdict"),
        "no_win_rerun_required"
    );
    assert_eq!(
        artifact["current_operator_report"]["parent_close_allowed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        string(&artifact["current_operator_report"], "first_failing_row"),
        "schema-contract"
    );
    for row in rows {
        assert_eq!(
            string(row, "current_evidence_status"),
            "blocked",
            "{} must name the current blocked proof state",
            string(row, "row_id")
        );
        assert_contains_all(
            "blocked_followup",
            string(row, "blocked_followup"),
            &[
                "dirty shared-main peer changes",
                "same-project RCH contention",
                "clean committed main",
            ],
        );
    }
}

#[test]
fn manifest_and_status_snapshot_wire_the_final_signoff_lane() {
    let artifact = signoff();
    let manifest = json(MANIFEST_PATH);
    let snapshot = json(SNAPSHOT_PATH);
    let lanes = manifest_lanes(&manifest);
    let claims = snapshot_claims(&snapshot);
    let signoff_lane = &artifact["signoff_lane"];
    let lane_id = string(signoff_lane, "lane_id");
    let guarantee_id = string(signoff_lane, "guarantee_id");
    let claim_id = string(signoff_lane, "proof_status_claim_id");

    let lane = lanes
        .get(lane_id)
        .unwrap_or_else(|| panic!("manifest missing lane {lane_id}"));
    assert_eq!(string(lane, "kind"), "artifact_contract");
    assert_eq!(
        string(lane, "resource_envelope_class"),
        "artifact-contract-medium"
    );
    assert_eq!(
        string(lane, "command"),
        string(signoff_lane, "proof_command")
    );
    assert_remote_required_cargo(string(lane, "command"));
    assert!(string_set(lane, "guarantee_ids").contains(guarantee_id));
    for required_path in [
        SIGNOFF_PATH,
        TEST_PATH,
        RUNBOOK_PATH,
        MANIFEST_PATH,
        SNAPSHOT_PATH,
        README_PATH,
        AGENTS_PATH,
    ] {
        assert!(
            string_set(lane, "source_paths").contains(required_path),
            "final signoff lane missing source path {required_path}"
        );
    }
    assert!(
        string(lane, "explicit_not_covered").contains("production-on-by-default")
            && string(lane, "explicit_not_covered").contains("fresh benchmark improvement"),
        "final signoff lane must preserve broad non-claims"
    );

    let aggregate = claims
        .get(claim_id)
        .unwrap_or_else(|| panic!("snapshot missing claim {claim_id}"));
    assert!(string_set(aggregate, "manifest_lane_ids").contains(lane_id));
    assert!(string_set(aggregate, "manifest_guarantee_ids").contains(guarantee_id));
    assert!(
        string_set(aggregate, "proof_commands").contains(string(signoff_lane, "proof_command"))
    );
    assert_eq!(string(aggregate, "status"), "yellow_scoped");
    assert_eq!(string(aggregate, "proof_evidence_status"), "blocked");
    assert_contains_all(
        "aggregate blocked frontier",
        string(&aggregate["blocked_frontier"], "required_followup"),
        &["Rerun all fourth-wave child lanes", "clean committed main"],
    );
}

#[test]
fn child_rows_match_manifest_snapshot_commands_and_artifacts() {
    let artifact = signoff();
    let manifest = json(MANIFEST_PATH);
    let snapshot = json(SNAPSHOT_PATH);
    let lanes = manifest_lanes(&manifest);
    let claims = snapshot_claims(&snapshot);
    let seen_child_lanes = array(&artifact, "required_child_rows")
        .iter()
        .map(|row| string(row, "manifest_lane_id").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        seen_child_lanes,
        CHILD_LANES
            .iter()
            .map(|lane| (*lane).to_string())
            .collect::<BTreeSet<_>>()
    );

    for row in array(&artifact, "required_child_rows") {
        let row_id = string(row, "row_id");
        let lane_id = string(row, "manifest_lane_id");
        let claim_id = string(row, "proof_status_claim_id");
        let lane = lanes
            .get(lane_id)
            .unwrap_or_else(|| panic!("{row_id}: missing lane {lane_id}"));
        let claim = claims
            .get(claim_id)
            .unwrap_or_else(|| panic!("{row_id}: missing claim {claim_id}"));

        assert_eq!(string(row, "proof_command_id"), lane_id);
        assert_eq!(string(row, "required_evidence_status"), "fresh-rch-pass");
        assert_eq!(
            string(row, "current_evidence_status"),
            string(claim, "proof_evidence_status"),
            "{row_id}: current evidence status must mirror proof status snapshot"
        );
        assert_eq!(
            string(row, "current_claim_status"),
            string(claim, "status"),
            "{row_id}: current claim status must mirror proof status snapshot"
        );
        assert!(
            string_set(claim, "proof_commands").contains(string(lane, "command")),
            "{row_id}: snapshot proof commands must include manifest command"
        );
        assert_remote_required_cargo(string(lane, "command"));
        assert!(
            row["test_evidence_min_count"].as_u64().unwrap_or(0) > 0,
            "{row_id}: zero-test exact filters are not acceptable"
        );
        assert!(
            string(row, "claim_boundary").contains("only")
                || string(row, "claim_boundary").contains("no-claim"),
            "{row_id}: claim boundary must stay scoped"
        );
        for artifact_path in string_set(row, "artifact_paths") {
            assert!(
                repo_path(&artifact_path).exists(),
                "{row_id}: artifact path missing: {artifact_path}"
            );
        }
    }
}

#[test]
fn failure_fixtures_reject_missing_bridge_local_fallback_zero_tests_and_benchmark_overclaim() {
    let artifact = signoff();
    let fixtures = array(&artifact, "failure_fixtures")
        .iter()
        .map(|fixture| (string(fixture, "fixture_id").to_string(), fixture.clone()))
        .collect::<BTreeMap<_, _>>();

    for (fixture_id, row_id, reason) in [
        (
            "missing-runtime-bridge-proof",
            "runtime-bridge",
            "missing required child evidence",
        ),
        (
            "local-fallback-evidence",
            "schema-contract",
            "local fallback evidence rejected",
        ),
        (
            "zero-test-filter",
            "policy-engine",
            "zero-test exact filter rejected",
        ),
        (
            "stale-benchmark-claim",
            "benchmark-no-claim",
            "fresh benchmark artifact required before performance claim",
        ),
    ] {
        let fixture = fixtures
            .get(fixture_id)
            .unwrap_or_else(|| panic!("missing fixture {fixture_id}"));
        assert_eq!(string(fixture, "expected_verdict"), "fail_closed");
        assert_eq!(string(fixture, "expected_first_failing_row"), row_id);
        assert_eq!(string(fixture, "expected_reason"), reason);
    }
}

#[test]
fn deterministic_operator_report_logs_required_fields_and_non_claims() {
    let artifact = signoff();
    let left = render_report(&artifact);
    let right = render_report(&artifact);
    assert_eq!(left, right, "operator report rendering must be stable");
    assert_eq!(left.final_verdict, "no_win_rerun_required");
    assert!(!left.parent_close_allowed);
    assert_eq!(left.first_failing_row.as_deref(), Some("schema-contract"));

    assert_contains_all(
        "operator report",
        &left.markdown,
        &[
            "child_bead_id=",
            "proof_command_id=",
            "artifact_sha256=",
            "freshness_window_seconds=86400",
            "first_failing_row=schema-contract",
            "final_verdict=no_win_rerun_required",
            "evidence_status=blocked",
        ],
    );
    for row in &left.rows {
        assert!(!row.artifact_hashes.is_empty(), "{} hashes", row.row_id);
        for hash in &row.artifact_hashes {
            let digest = hash
                .rsplit_once("sha256=")
                .map(|(_, digest)| digest)
                .expect("sha256 marker");
            assert_eq!(digest.len(), 64, "sha256 digest length for {hash}");
            assert!(
                digest.chars().all(|ch| ch.is_ascii_hexdigit()),
                "sha256 digest must be hex for {hash}"
            );
        }
    }

    let non_claims = string_set(&artifact, "non_claims")
        .into_iter()
        .collect::<Vec<_>>()
        .join("\n");
    assert_contains_all(
        "non_claims",
        &non_claims,
        &[
            "does not prove p95 improvement",
            "does not prove throughput improvement",
            "does not prove no regression",
            "does not prove production-on-by-default control",
            "does not prove broad workspace health",
            "does not prove RCH fleet availability",
        ],
    );
    for forbidden in [
        "proves p95 improvement",
        "proves throughput improvement",
        "production-on-by-default control is enabled",
    ] {
        assert!(
            !left.markdown.contains(forbidden),
            "operator report overclaims: {forbidden}"
        );
    }
}
