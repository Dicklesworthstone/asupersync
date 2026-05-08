#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use std::path::{Path, PathBuf};

const README_PATH: &str = "README.md";
const WORKFLOW_PATH: &str = ".github/workflows/methodology-gates.yml";
const CONTRACT_PATH: &str = "artifacts/phase6_methodology_gate_enforcement_contract_v1.json";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn contract() -> JsonValue {
    serde_json::from_str(&read_repo_file(CONTRACT_PATH))
        .expect("parse phase6 methodology gate contract")
}

fn nonempty_string<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    let item = value
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!item.trim().is_empty(), "{key} must be nonempty");
    item
}

#[test]
fn phase6_contract_records_main_only_enforcement_split() {
    let contract = contract();
    assert_eq!(
        contract.get("contract_version").and_then(JsonValue::as_str),
        Some("phase6-methodology-gate-enforcement-contract-v1")
    );
    assert_eq!(
        contract.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-rckg8s")
    );

    let workflow = contract
        .get("repository_workflow")
        .expect("repository_workflow object");
    assert_eq!(
        workflow.get("branch_model").and_then(JsonValue::as_str),
        Some("main_only")
    );
    assert_eq!(
        workflow
            .get("normal_agent_landing")
            .and_then(JsonValue::as_str),
        Some("direct_main_commit")
    );
    assert_eq!(
        workflow
            .get("pull_requests_required_for_agents")
            .and_then(JsonValue::as_bool),
        Some(false)
    );

    let signoff = contract.get("final_signoff").expect("final_signoff object");
    assert_eq!(
        signoff.get("pr_only").and_then(JsonValue::as_bool),
        Some(true)
    );
    assert_eq!(
        signoff.get("push_enforced").and_then(JsonValue::as_bool),
        Some(false)
    );
    assert_eq!(
        signoff.get("local_enforced").and_then(JsonValue::as_bool),
        Some(true)
    );
    assert_eq!(
        signoff.get("release_only").and_then(JsonValue::as_bool),
        Some(false)
    );
}

#[test]
fn local_gate_commands_are_rch_backed_and_scoped() {
    let contract = contract();
    let gates = contract
        .get("direct_main_local_gates")
        .and_then(JsonValue::as_array)
        .expect("direct_main_local_gates array");
    assert_eq!(gates.len(), 5, "expected five direct-main local gates");

    for gate in gates {
        let gate_id = nonempty_string(gate, "gate_id");
        let command = nonempty_string(gate, "rch_command");
        assert!(
            command.starts_with("rch exec -- "),
            "{gate_id}: command must be rch-backed: {command}"
        );
        assert!(
            !command.starts_with("rch exec -- cargo "),
            "{gate_id}: cargo command must declare env before cargo: {command}"
        );

        if command.contains(" cargo ") {
            assert!(
                command.contains("CARGO_TARGET_DIR="),
                "{gate_id}: cargo command must use an explicit target dir: {command}"
            );
        }

        if command.contains(" cargo bench ")
            || command.contains(" cargo test ")
            || command.contains(" cargo flamegraph ")
        {
            assert!(
                command.contains("-p asupersync") || command.contains("--package asupersync"),
                "{gate_id}: cargo command must stay scoped to the asupersync crate: {command}"
            );
        }

        let artifacts = gate
            .get("artifact_locations")
            .and_then(JsonValue::as_array)
            .unwrap_or_else(|| panic!("{gate_id}: artifact_locations must be an array"));
        assert!(
            !artifacts.is_empty(),
            "{gate_id}: must name at least one artifact location"
        );
        assert!(
            artifacts.iter().all(|item| item
                .as_str()
                .is_some_and(|path| path.starts_with("artifacts/")
                    || path.starts_with("target/")
                    || path.starts_with("tests/"))),
            "{gate_id}: artifact locations must stay in repo artifact/test surfaces"
        );
    }
}

#[test]
fn workflow_parses_and_is_explicitly_pr_only() {
    let workflow_text = read_repo_file(WORKFLOW_PATH);
    let workflow: YamlValue =
        serde_yaml::from_str(&workflow_text).expect("methodology workflow must parse as YAML");
    let mapping = workflow
        .as_mapping()
        .expect("methodology workflow must be a YAML mapping");

    let on_key = YamlValue::String("on".to_string());
    let on = mapping
        .get(&on_key)
        .expect("workflow must declare triggers");
    let on_mapping = on.as_mapping().expect("workflow on: must be a mapping");
    assert!(
        on_mapping.contains_key(YamlValue::String("pull_request".to_string())),
        "methodology workflow must keep its PR trigger explicit"
    );
    assert!(
        !on_mapping.contains_key(YamlValue::String("push".to_string())),
        "contract currently records no push-on-main enforcement"
    );

    assert!(
        workflow_text.contains("${{ github.event.pull_request.number }}"),
        "PR artifact names must remain visibly PR-number based"
    );

    let jobs = mapping
        .get(YamlValue::String("jobs".to_string()))
        .and_then(YamlValue::as_mapping)
        .expect("workflow must contain jobs mapping");
    for required_job in [
        "baseline-gate",
        "flamegraph-gate",
        "golden-checksum-gate",
        "proof-note-gate",
        "summary",
    ] {
        assert!(
            jobs.contains_key(YamlValue::String(required_job.to_string())),
            "workflow must contain job {required_job}"
        );
    }
}

#[test]
fn readme_describes_direct_main_lane_and_no_longer_claims_pr_only_enforcement() {
    let readme = read_repo_file(README_PATH);
    for required in [
        "direct commits on `main`",
        "Direct-main agent lane",
        "PR/release-review lane",
        "artifacts/phase6_methodology_gate_enforcement_contract_v1.json",
        "tests/phase6_methodology_gate_contract.rs",
        "rch exec -- env CARGO_INCREMENTAL=0",
        "Push-on-main GitHub enforcement is not currently enabled",
    ] {
        assert!(
            readme.contains(required),
            "README Phase 6 policy gates section must contain `{required}`"
        );
    }

    for stale in [
        "The methodology bar is enforced at PR review time",
        "runs on every pull request targeting `main`. There are no advisory-only gates",
        "All four gates are **live today** on `pull_request` events targeting `main`",
        "before opening the PR",
    ] {
        assert!(
            !readme.contains(stale),
            "README must not preserve stale PR-only claim `{stale}`"
        );
    }
}
