#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const DOC_PATH: &str = "docs/agent_swarm_coordination_collector.md";
const ARTIFACT_PATH: &str = "artifacts/agent_swarm_coordination_collector_contract_v1.json";
const SCRIPT_PATH: &str = "scripts/run_agent_swarm_coordination_collector.sh";
const WORKLOAD_ARTIFACT_PATH: &str = "artifacts/agent_swarm_coordination_workload_contract_v1.json";
const REDACTION_ARTIFACT_PATH: &str =
    "artifacts/agent_swarm_coordination_redaction_contract_v1.json";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn temp_root(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "asupersync-agent-swarm-collector-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("create temp root");
    path
}

fn load_doc() -> String {
    fs::read_to_string(repo_path(DOC_PATH)).expect("read collector doc")
}

fn load_json(relative: &str) -> Value {
    let raw = fs::read_to_string(repo_path(relative)).expect("read json artifact");
    serde_json::from_str(&raw).expect("parse json artifact")
}

fn run_script(args: &[&str]) -> std::process::Output {
    Command::new("bash")
        .arg(repo_path(SCRIPT_PATH))
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run collector script")
}

fn run_script_owned(args: &[String]) -> std::process::Output {
    Command::new("bash")
        .arg(repo_path(SCRIPT_PATH))
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run collector script")
}

fn string_array<'a>(value: &'a Value, key: &str) -> Vec<&'a str> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
        })
        .collect()
}

fn fixture_bundle(root: &Path) -> Value {
    let bundle_path = root
        .join("coordination-collector-fixture")
        .join("coordination-workload-bundle.json");
    let raw = fs::read_to_string(bundle_path).expect("read fixture bundle");
    serde_json::from_str(&raw).expect("parse fixture bundle")
}

fn fixture_report(root: &Path) -> Value {
    let report_path = root
        .join("coordination-collector-fixture")
        .join("coordination-collector-report.json");
    let raw = fs::read_to_string(report_path).expect("read fixture report");
    serde_json::from_str(&raw).expect("parse fixture report")
}

#[test]
fn doc_and_artifact_reference_collector_surfaces() {
    let doc = load_doc();
    for expected in [
        "asupersync-qn8i0p.2",
        SCRIPT_PATH,
        ARTIFACT_PATH,
        "tests/agent_swarm_coordination_collector_contract.rs",
        WORKLOAD_ARTIFACT_PATH,
        REDACTION_ARTIFACT_PATH,
        "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_agent_swarm_coordination_collector cargo test -p asupersync --test agent_swarm_coordination_collector_contract -- --nocapture",
    ] {
        assert!(doc.contains(expected), "doc must mention {expected}");
    }

    let artifact = load_json(ARTIFACT_PATH);
    assert_eq!(
        artifact.get("contract_version").and_then(Value::as_str),
        Some("agent-swarm-coordination-collector-contract-v1")
    );
    assert_eq!(
        artifact.get("bead_id").and_then(Value::as_str),
        Some("asupersync-qn8i0p.2")
    );
    assert_eq!(
        artifact
            .pointer("/source_contracts/workload")
            .and_then(Value::as_str),
        Some(WORKLOAD_ARTIFACT_PATH)
    );
    assert_eq!(
        artifact
            .pointer("/source_contracts/redaction")
            .and_then(Value::as_str),
        Some(REDACTION_ARTIFACT_PATH)
    );
}

#[test]
fn artifact_lists_required_modes_adapters_outputs_and_fail_closed_cases() {
    let artifact = load_json(ARTIFACT_PATH);

    let modes: BTreeSet<_> = artifact["modes"]
        .as_array()
        .expect("modes array")
        .iter()
        .map(|mode| mode["mode"].as_str().expect("mode string"))
        .collect();
    assert_eq!(
        modes,
        BTreeSet::from(["dry-run", "execute", "fixture", "list"])
    );

    let adapters: BTreeSet<_> = artifact["source_adapters"]
        .as_array()
        .expect("source adapters array")
        .iter()
        .map(|adapter| adapter["kind"].as_str().expect("adapter kind"))
        .collect();
    assert_eq!(
        adapters,
        BTreeSet::from([
            "agent_mail",
            "artifact_store",
            "beads",
            "bv",
            "git_dirty_frontier",
            "rch",
        ])
    );

    let outputs: BTreeSet<_> = string_array(&artifact, "artifact_outputs")
        .into_iter()
        .collect();
    assert_eq!(
        outputs,
        BTreeSet::from([
            "coordination-collector-report.json",
            "coordination-collector.summary.txt",
            "coordination-workload-bundle.json",
            "coordination-workload-events.jsonl",
        ])
    );

    let e2e_fields: BTreeSet<_> = string_array(&artifact, "e2e_log_fields")
        .into_iter()
        .collect();
    assert_eq!(
        e2e_fields,
        BTreeSet::from([
            "correlation_id",
            "output_bundle_path",
            "pseudonymized_agent",
            "refusal_reason",
            "replay_command",
            "source_hash",
            "source_kind",
            "workload_family",
        ])
    );

    let fail_closed: BTreeSet<_> = artifact["fail_closed_cases"]
        .as_array()
        .expect("fail cases")
        .iter()
        .map(|case| case["case"].as_str().expect("case string"))
        .collect();
    assert_eq!(
        fail_closed,
        BTreeSet::from([
            "malformed_json",
            "missing_required_identifier",
            "stale_source",
            "unknown_source_kind",
            "unredacted_secret",
        ])
    );
}

#[test]
fn list_and_dry_run_do_not_read_missing_sources() {
    let listed = run_script(&["--list"]);
    assert!(
        listed.status.success(),
        "list stderr: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let stdout = String::from_utf8_lossy(&listed.stdout);
    for token in [
        "adapter agent_mail",
        "adapter beads",
        "adapter bv",
        "adapter rch",
        "adapter git_dirty_frontier",
        "adapter artifact_store",
        "modes list dry-run fixture execute",
    ] {
        assert!(stdout.contains(token), "list missing {token}: {stdout}");
    }

    let dry = run_script(&["--dry-run", "--source", "beads:/definitely/missing.json"]);
    assert!(
        dry.status.success(),
        "dry-run stderr: {}",
        String::from_utf8_lossy(&dry.stderr)
    );
    let stdout = String::from_utf8_lossy(&dry.stdout);
    assert!(stdout.contains("read_sources=false"));
    assert!(stdout.contains("planned_source beads:/definitely/missing.json"));
}

#[test]
fn fixture_execute_emits_schema_valid_sorted_bundle_and_artifacts() {
    let root = temp_root("fixture-schema");
    let out = run_script_owned(&[
        "--fixture".into(),
        "--output-root".into(),
        root.to_string_lossy().into_owned(),
    ]);
    assert!(
        out.status.success(),
        "fixture stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    for file in [
        "coordination-workload-bundle.json",
        "coordination-workload-events.jsonl",
        "coordination-collector-report.json",
        "coordination-collector.summary.txt",
    ] {
        assert!(
            root.join("coordination-collector-fixture")
                .join(file)
                .exists(),
            "missing artifact {file}"
        );
    }

    let bundle = fixture_bundle(&root);
    let workload = load_json(WORKLOAD_ARTIFACT_PATH);
    let required = string_array(&workload["record_layout"], "event_required_fields");
    assert_eq!(
        bundle.get("schema_version").and_then(Value::as_str),
        Some("agent-swarm-coordination-workload-bundle-v1")
    );

    let events = bundle["events"].as_array().expect("events array");
    assert!(!events.is_empty(), "fixture should emit events");
    for event in events {
        for field in &required {
            assert!(
                event.get(*field).is_some(),
                "event missing {field}: {event}"
            );
        }
    }

    let mut previous: Option<Vec<String>> = None;
    for event in events {
        let current = [
            "event_ts",
            "stable_sequence",
            "source_kind",
            "source_thread_or_bead",
            "event_kind",
            "correlation_id",
        ]
        .iter()
        .map(|key| event[*key].as_str().expect("sort field").to_string())
        .collect::<Vec<_>>();
        if let Some(prev) = previous {
            assert!(prev <= current, "events must be sorted");
        }
        previous = Some(current);
    }
}

#[test]
fn fixture_deduplicates_messages_and_covers_required_workload_families() {
    let root = temp_root("fixture-dedupe");
    let out = run_script_owned(&[
        "--fixture".into(),
        "--output-root".into(),
        root.to_string_lossy().into_owned(),
    ]);
    assert!(
        out.status.success(),
        "fixture stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bundle = fixture_bundle(&root);
    let report = fixture_report(&root);

    assert_eq!(
        report.get("duplicate_event_count").and_then(Value::as_u64),
        Some(1),
        "fixture should suppress one duplicate mail event"
    );
    let events = bundle["events"].as_array().expect("events array");
    let families: BTreeSet<_> = events
        .iter()
        .map(|event| event["workload_family"].as_str().expect("family"))
        .collect();
    for expected in [
        "tracker_lock_contention",
        "concurrent_rch_proofs",
        "fail_closed_dirty_frontier",
        "artifact_retrieval_tail",
        "proof_runner_fanout",
        "stale_in_progress_reclaim",
    ] {
        assert!(
            families.contains(expected),
            "missing workload family {expected}"
        );
    }

    assert_eq!(
        report.get("privacy_verdict").and_then(Value::as_str),
        Some("pass")
    );
}

#[test]
fn report_e2e_rows_cover_required_smoke_log_fields() {
    let root = temp_root("fixture-e2e-log");
    let out = run_script_owned(&[
        "--fixture".into(),
        "--output-root".into(),
        root.to_string_lossy().into_owned(),
    ]);
    assert!(
        out.status.success(),
        "fixture stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bundle = fixture_bundle(&root);
    let report = fixture_report(&root);
    let bundle_path = report["artifact_paths"]["bundle"]
        .as_str()
        .expect("bundle path");
    let replay_command = report["replay_command"].as_str().expect("replay command");
    assert!(
        replay_command.contains("scripts/run_runtime_workload_corpus.sh"),
        "replay command should point at workload corpus runner: {replay_command}"
    );
    assert!(
        replay_command.contains("--synthesize-coordination-pack"),
        "replay command should synthesize coordination pack: {replay_command}"
    );
    assert!(
        replay_command.contains("--coordination-bundle"),
        "replay command should pass collector bundle: {replay_command}"
    );
    assert!(
        replay_command.contains(bundle_path),
        "replay command should include output bundle path"
    );

    let rows = report["e2e_log_rows"].as_array().expect("e2e rows");
    let events = bundle["events"].as_array().expect("bundle events");
    assert_eq!(
        rows.len(),
        events.len(),
        "every emitted event needs one E2E log row"
    );

    for (row, event) in rows.iter().zip(events) {
        for field in [
            "source_kind",
            "pseudonymized_agent",
            "correlation_id",
            "workload_family",
            "refusal_reason",
            "source_hash",
            "output_bundle_path",
            "replay_command",
        ] {
            assert!(row.get(field).is_some(), "row missing {field}: {row}");
        }
        assert_eq!(row["source_kind"], event["source_kind"]);
        assert_eq!(row["pseudonymized_agent"], event["source_agent"]);
        assert_eq!(row["correlation_id"], event["correlation_id"]);
        assert_eq!(row["workload_family"], event["workload_family"]);
        assert_eq!(row["refusal_reason"], event["refusal_reason"]);
        assert_eq!(row["source_hash"], event["source_hash"]);
        assert_eq!(row["output_bundle_path"], bundle_path);
        assert_eq!(row["replay_command"], replay_command);
    }
}

#[test]
fn fixture_output_is_deterministic_across_repeated_runs() {
    let root_a = temp_root("fixture-a");
    let root_b = temp_root("fixture-b");
    for root in [&root_a, &root_b] {
        let out = run_script_owned(&[
            "--fixture".into(),
            "--output-root".into(),
            root.to_string_lossy().into_owned(),
        ]);
        assert!(
            out.status.success(),
            "fixture stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let a = fixture_bundle(&root_a);
    let b = fixture_bundle(&root_b);
    assert_eq!(a["source_bundle_hash"], b["source_bundle_hash"]);
    assert_eq!(a["events"], b["events"]);
}

#[test]
fn malformed_json_source_fails_closed_with_refused_event() {
    let root = temp_root("malformed");
    let bad = root.join("bad.json");
    fs::write(&bad, "{not json").expect("write malformed source");
    let out = run_script_owned(&[
        "--execute".into(),
        "--source".into(),
        format!("beads:{}", bad.to_string_lossy()),
        "--output-root".into(),
        root.to_string_lossy().into_owned(),
        "--run-id".into(),
        "malformed-json".into(),
    ]);
    assert!(!out.status.success(), "malformed input must fail closed");
    let report_path = root
        .join("malformed-json")
        .join("coordination-collector-report.json");
    let report: Value = serde_json::from_str(&fs::read_to_string(report_path).expect("report"))
        .expect("parse report");
    assert_eq!(report["privacy_verdict"], "fail_closed");
    assert_eq!(report["refused_event_count"], 1);
    assert!(
        report["first_failure_line"]
            .as_str()
            .unwrap_or_default()
            .contains("unknown_schema_version")
    );
}

#[test]
fn adapter_refused_event_fails_closed_for_missing_required_field() {
    let root = temp_root("missing-field");
    let source = root.join("br.json");
    fs::write(&source, r#"{"issues":[{"status":"open"}]}"#).expect("write missing id source");
    let out = run_script_owned(&[
        "--execute".into(),
        "--source".into(),
        format!("beads:{}", source.to_string_lossy()),
        "--output-root".into(),
        root.to_string_lossy().into_owned(),
        "--run-id".into(),
        "missing-field".into(),
    ]);
    assert!(
        !out.status.success(),
        "adapter refusal must fail closed instead of passing"
    );

    let report: Value = serde_json::from_str(
        &fs::read_to_string(
            root.join("missing-field")
                .join("coordination-collector-report.json"),
        )
        .expect("read missing-field report"),
    )
    .expect("parse missing-field report");
    assert_eq!(report["privacy_verdict"], "fail_closed");
    assert_eq!(report["refused_event_count"].as_u64(), Some(1));
    assert!(
        report["first_failure_line"]
            .as_str()
            .unwrap_or_default()
            .contains("missing_required_field")
    );

    let bundle: Value = serde_json::from_str(
        &fs::read_to_string(
            root.join("missing-field")
                .join("coordination-workload-bundle.json"),
        )
        .expect("read missing-field bundle"),
    )
    .expect("parse missing-field bundle");
    let event = &bundle["events"][0];
    assert_eq!(event["redaction_verdict"], "refused");
    assert_eq!(event["refusal_reason"], "missing_required_field");
}

#[test]
fn unredacted_secret_source_fails_closed_and_does_not_leak_token() {
    let root = temp_root("secret");
    let source = root.join("mail.json");
    fs::write(
        &source,
        r#"[{"id":1,"from":"BlueMountain","thread_id":"asupersync-qn8i0p.2","created_ts":"2026-05-05T05:00:00Z","subject":"secret","body_md":"Authorization: Bearer REDACTION_FIXTURE_TOKEN_12345"}]"#,
    )
    .expect("write secret source");
    let out = run_script_owned(&[
        "--execute".into(),
        "--source".into(),
        format!("agent_mail:{}", source.to_string_lossy()),
        "--output-root".into(),
        root.to_string_lossy().into_owned(),
        "--run-id".into(),
        "secret-source".into(),
    ]);
    assert!(!out.status.success(), "secret input must fail closed");
    let output_text = fs::read_to_string(
        root.join("secret-source")
            .join("coordination-workload-bundle.json"),
    )
    .expect("read bundle");
    assert!(!output_text.contains("REDACTION_FIXTURE_TOKEN_12345"));
    assert!(output_text.contains("unredacted_secret"));
}

#[test]
fn stale_source_input_fails_closed_with_refused_event() {
    let root = temp_root("stale");
    let source = root.join("mail.json");
    fs::write(
        &source,
        r#"[{"id":7,"from":"BlueMountain","thread_id":"asupersync-d87ytw.1","created_ts":"2026-05-03T05:00:00Z","subject":"old source","body_md":"metadata-only body"}]"#,
    )
    .expect("write stale source");
    let out = run_script_owned(&[
        "--execute".into(),
        "--source".into(),
        format!("agent_mail:{}", source.to_string_lossy()),
        "--output-root".into(),
        root.to_string_lossy().into_owned(),
        "--run-id".into(),
        "stale-source".into(),
        "--generated-at".into(),
        "2026-05-05T05:00:00Z".into(),
    ]);
    assert!(!out.status.success(), "stale source must fail closed");

    let report: Value = serde_json::from_str(
        &fs::read_to_string(
            root.join("stale-source")
                .join("coordination-collector-report.json"),
        )
        .expect("read stale report"),
    )
    .expect("parse stale report");
    assert_eq!(report["privacy_verdict"], "fail_closed");
    assert_eq!(report["stale_source_event_count"].as_u64(), Some(1));
    assert!(
        report["first_failure_line"]
            .as_str()
            .unwrap_or_default()
            .contains("stale_source")
    );

    let bundle: Value = serde_json::from_str(
        &fs::read_to_string(
            root.join("stale-source")
                .join("coordination-workload-bundle.json"),
        )
        .expect("read stale bundle"),
    )
    .expect("parse stale bundle");
    let event = &bundle["events"][0];
    assert_eq!(event["redaction_verdict"], "refused");
    assert_eq!(event["refusal_reason"], "stale_source");
    let bundle_text = serde_json::to_string(&bundle).expect("serialize stale bundle");
    assert!(!bundle_text.contains("metadata-only body"));
}

#[test]
fn git_dirty_frontier_hashes_paths_and_retains_counts_only() {
    let root = temp_root("dirty");
    let source = root.join("dirty.json");
    fs::write(
        &source,
        r#"{"observed_at":"2026-05-05T05:00:00Z","paths":["/data/projects/asupersync/.beads/issues.jsonl","src/http/h2/connection.rs"]}"#,
    )
    .expect("write dirty source");
    let out = run_script_owned(&[
        "--execute".into(),
        "--source".into(),
        format!("git_dirty_frontier:{}", source.to_string_lossy()),
        "--output-root".into(),
        root.to_string_lossy().into_owned(),
        "--run-id".into(),
        "dirty-frontier".into(),
    ]);
    assert!(
        out.status.success(),
        "dirty source stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bundle_raw = fs::read_to_string(
        root.join("dirty-frontier")
            .join("coordination-workload-bundle.json"),
    )
    .expect("read bundle");
    assert!(!bundle_raw.contains("/data/projects/asupersync"));
    assert!(!bundle_raw.contains("src/http/h2/connection.rs"));
    let bundle: Value = serde_json::from_str(&bundle_raw).expect("parse bundle");
    let frontier = &bundle["events"][0]["file_frontier"];
    assert_eq!(frontier["changed_paths_count"], 2);
    assert_eq!(frontier["unsupported_dirty_paths_count"], 1);
    assert_eq!(frontier["path_hashes"].as_array().expect("hashes").len(), 2);
}

#[test]
fn explicit_source_adapters_encode_expected_event_kinds() {
    let root = temp_root("adapters");
    let beads = root.join("br.json");
    let bv = root.join("bv.json");
    let rch = root.join("rch.json");
    let artifacts = root.join("artifacts.json");
    fs::write(
        &beads,
        r#"{"issues":[{"id":"asupersync-qn8i0p.2","status":"in_progress","assignee":"CreamCarp","updated_at":"2026-05-05T05:00:00Z","dependencies":[{"id":"asupersync-qn8i0p.1"}]}]}"#,
    )
    .expect("write beads");
    fs::write(
        &bv,
        r#"{"generated_at":"2026-05-05T05:00:01Z","label_scope":"swarm-ops","plan":{"total_actionable":1,"summary":{"highest_impact":"asupersync-qn8i0p.2"}}}"#,
    )
    .expect("write bv");
    fs::write(
        &rch,
        r#"{"jobs":[{"id":"job-1","status":"started","bead_id":"asupersync-qn8i0p.2","queue_depth":2,"started_ts":"2026-05-05T05:00:02Z"}]}"#,
    )
    .expect("write rch");
    fs::write(
        &artifacts,
        r#"{"artifacts":[{"bead_id":"asupersync-qn8i0p.2","path":"target/proof/report.json","created_at":"2026-05-05T05:00:03Z"}]}"#,
    )
    .expect("write artifact refs");

    let out = run_script_owned(&[
        "--execute".into(),
        "--source".into(),
        format!("beads:{}", beads.to_string_lossy()),
        "--source".into(),
        format!("bv:{}", bv.to_string_lossy()),
        "--source".into(),
        format!("rch:{}", rch.to_string_lossy()),
        "--source".into(),
        format!("artifact_store:{}", artifacts.to_string_lossy()),
        "--output-root".into(),
        root.to_string_lossy().into_owned(),
        "--run-id".into(),
        "adapter-matrix".into(),
    ]);
    assert!(
        out.status.success(),
        "adapter stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bundle: Value = serde_json::from_str(
        &fs::read_to_string(
            root.join("adapter-matrix")
                .join("coordination-workload-bundle.json"),
        )
        .expect("bundle"),
    )
    .expect("parse bundle");
    let kinds: BTreeSet<_> = bundle["events"]
        .as_array()
        .expect("events")
        .iter()
        .map(|event| event["event_kind"].as_str().expect("event kind"))
        .collect();
    for expected in [
        "bead_status_changed",
        "dependency_added",
        "robot_plan_snapshot",
        "rch_job_started",
        "artifact_published",
    ] {
        assert!(kinds.contains(expected), "missing event kind {expected}");
    }

    let by_kind: BTreeMap<_, _> = bundle["events"]
        .as_array()
        .expect("events")
        .iter()
        .map(|event| {
            (
                event["event_kind"].as_str().expect("event kind"),
                event["redaction_verdict"]
                    .as_str()
                    .expect("redaction verdict"),
            )
        })
        .collect();
    assert_eq!(by_kind["rch_job_started"], "redacted");
}
