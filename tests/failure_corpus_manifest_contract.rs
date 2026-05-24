//! Contract tests for the deterministic failure corpus and replay promotion path.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::io::Write;
use std::process::{Command, Output};

const ARTIFACT_PATH: &str = "artifacts/failure_corpus_manifest_v1.json";
const DOC_PATH: &str = "docs/proof_runner_usage.md";
const SCRIPT_PATH: &str = "scripts/proof_runner.py";
const FIXTURE_CASE_ID: &str = "FC-RCH-ADMISSION-001";

fn load_json(path: &str) -> Value {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {path}: {error}"))
}

fn run_proof_runner(args: &[&str]) -> Output {
    Command::new("python3")
        .arg(SCRIPT_PATH)
        .args(args)
        .output()
        .expect("proof runner should execute")
}

fn proof_runner_json(args: &[&str]) -> Value {
    let output = run_proof_runner(args);
    assert!(
        output.status.success(),
        "proof runner failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("proof runner output not JSON: {error}\noutput: {stdout}"))
}

fn string_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn cases(artifact: &Value) -> &[Value] {
    artifact["cases"]
        .as_array()
        .expect("cases must be an array")
}

#[test]
fn failure_corpus_manifest_has_required_shape_and_docs() {
    let artifact = load_json(ARTIFACT_PATH);
    assert_eq!(
        artifact["contract_version"].as_str(),
        Some("failure-corpus-manifest-v1")
    );
    assert_eq!(artifact["bead_id"].as_str(), Some("asupersync-9u057b.3"));
    assert_eq!(
        artifact["source_of_truth"]["contract_test"].as_str(),
        Some("tests/failure_corpus_manifest_contract.rs")
    );
    assert_eq!(
        artifact["source_of_truth"]["replay_helper"].as_str(),
        Some(SCRIPT_PATH)
    );

    let scrub_rules = artifact["scrub_rules"]
        .as_array()
        .expect("scrub rules must be an array");
    let scrub_rule_ids = scrub_rules
        .iter()
        .map(|rule| string_field(rule, "rule_id").to_string())
        .collect::<BTreeSet<_>>();
    for required in [
        "iso-timestamp",
        "repo-root",
        "tmp-path",
        "sha256-value",
        "rch-command-field",
        "worker-field",
        "active-project-exclusion-count",
        "duration-value",
    ] {
        assert!(
            scrub_rule_ids.contains(required),
            "scrub rule {required} must be declared"
        );
    }

    assert!(
        !cases(&artifact).is_empty(),
        "at least one replay case is required"
    );
    for case in cases(&artifact) {
        for required in [
            "case_id",
            "title",
            "failure_kind",
            "seed",
            "raw_event_log",
            "expected_scrubbed_log",
        ] {
            assert!(
                !string_field(case, required).is_empty(),
                "case field {required} must be nonempty"
            );
        }
        assert_eq!(
            case["external_services_required"].as_bool(),
            Some(false),
            "corpus replay cases must be local deterministic fixtures"
        );
        assert!(
            string_field(&case["replay"], "command")
                .starts_with("python3 scripts/proof_runner.py --failure-corpus-replay"),
            "case replay must route through the proof-runner helper"
        );
        let scrubbed = string_field(case, "expected_scrubbed_log");
        for forbidden in [
            "/data/projects/asupersync",
            "/tmp/",
            "worker=ts",
            "2026-05-24T",
            "sha256:aaaaaaaa",
        ] {
            assert!(
                !scrubbed.contains(forbidden),
                "expected scrubbed log must not contain unsanitized marker {forbidden}"
            );
        }
    }

    let docs = std::fs::read_to_string(DOC_PATH).expect("proof runner docs must exist");
    for required in [
        ARTIFACT_PATH,
        "python3 scripts/proof_runner.py --failure-corpus-replay",
        "python3 scripts/proof_runner.py --failure-corpus-scrub-input",
        "Promote a red proof",
    ] {
        assert!(
            docs.contains(required),
            "docs must mention failure corpus workflow marker {required}"
        );
    }
}

#[test]
fn failure_corpus_replay_fixture_matches_scrubbed_golden() {
    let artifact = load_json(ARTIFACT_PATH);
    let case = cases(&artifact)
        .iter()
        .find(|case| case["case_id"].as_str() == Some(FIXTURE_CASE_ID))
        .expect("fixture case must exist");

    let replay = proof_runner_json(&[
        "--failure-corpus-replay",
        FIXTURE_CASE_ID,
        "--output",
        "json",
    ]);

    assert_eq!(
        replay["schema_version"].as_str(),
        Some("failure-corpus-replay-result-v1")
    );
    assert_eq!(replay["case_id"].as_str(), Some(FIXTURE_CASE_ID));
    assert_eq!(replay["verdict"].as_str(), Some("pass"));
    assert_eq!(
        replay["scrubbed_log"].as_str(),
        case["expected_scrubbed_log"].as_str()
    );
    assert_eq!(replay["external_services_required"].as_bool(), Some(false));
    assert_eq!(replay["stage_log_count"].as_u64(), Some(1));

    let minimized = replay["minimized_replay_lines"]
        .as_array()
        .expect("minimized replay lines");
    assert!(
        minimized
            .iter()
            .any(|line| line.as_str().unwrap_or("").contains("remote required")),
        "minimized replay must keep the remote-required blocker"
    );
    assert!(
        minimized.iter().any(|line| {
            line.as_str()
                .unwrap_or("")
                .contains("active_project_exclusion=[COUNT]")
        }),
        "minimized replay must keep the admission-refusal class"
    );
}

#[test]
fn failure_corpus_scrubber_masks_nondeterminism() {
    let mut input = tempfile::NamedTempFile::new().expect("create raw failure fixture");
    writeln!(
        input,
        "2026-05-24T02:55:00.123456Z worker=ts2 command=RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_x cargo test --test failure_corpus"
    )
    .expect("write fixture line");
    writeln!(
        input,
        "[RCH] local (no admissible workers: active_project_exclusion=17)"
    )
    .expect("write fixture line");
    writeln!(
        input,
        "[RCH] remote required; refusing local fallback (no worker assigned)"
    )
    .expect("write fixture line");
    writeln!(
        input,
        "first_failure file=/data/projects/asupersync/src/lib.rs digest=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb elapsed=42ms"
    )
    .expect("write fixture line");

    let input_path = input.path().to_str().expect("temp path utf8");
    let scrub = proof_runner_json(&[
        "--failure-corpus-scrub-input",
        input_path,
        "--output",
        "json",
    ]);
    assert_eq!(scrub["verdict"].as_str(), Some("pass"));

    let scrubbed = scrub["scrubbed_text"].as_str().expect("scrubbed text");
    for required in [
        "[TIMESTAMP]",
        "worker=[WORKER]",
        "command=[RCH_COMMAND]",
        "active_project_exclusion=[COUNT]",
        "[REPO]/src/lib.rs",
        "sha256:[HASH]",
        "[DURATION]",
    ] {
        assert!(
            scrubbed.contains(required),
            "scrubbed text should contain {required}: {scrubbed}"
        );
    }
    for forbidden in [
        "2026-05-24T02:55",
        "worker=ts2",
        "/tmp/rch_target_x",
        "/data/projects/asupersync",
        "sha256:bbbbbbbb",
        "42ms",
    ] {
        assert!(
            !scrubbed.contains(forbidden),
            "scrubbed text should remove {forbidden}: {scrubbed}"
        );
    }

    let minimized = scrub["minimized_replay_lines"]
        .as_array()
        .expect("minimized replay lines");
    assert!(
        minimized.len() >= 2,
        "minimizer should retain multiple blocker-bearing lines"
    );
}
