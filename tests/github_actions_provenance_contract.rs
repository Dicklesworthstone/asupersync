#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const POLICY_PATH: &str = "artifacts/github_actions_provenance_v1.json";
const DOC_PATH: &str = "docs/github_actions_provenance.md";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn json(relative: &str) -> Value {
    serde_json::from_str(&read(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn workflow_paths() -> Vec<String> {
    let mut paths = std::fs::read_dir(repo_path(".github/workflows"))
        .expect("read workflow directory")
        .map(|entry| entry.expect("read workflow entry").path())
        .filter(|path| {
            matches!(
                path.extension().and_then(|extension| extension.to_str()),
                Some("yml" | "yaml")
            )
        })
        .map(|path| {
            format!(
                ".github/workflows/{}",
                path.file_name()
                    .and_then(|name| name.to_str())
                    .expect("workflow name must be UTF-8")
            )
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn uses_reference(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    trimmed
        .strip_prefix("- uses:")
        .or_else(|| trimmed.strip_prefix("uses:"))
        .map(str::trim)
}

fn validate_reference(reference_and_comment: &str) -> Result<(String, String, String), String> {
    let (reference, comment) = reference_and_comment
        .split_once('#')
        .ok_or_else(|| "uses reference must have a readable trailing comment".to_owned())?;
    let comment = comment.trim();
    if comment.is_empty() {
        return Err("uses reference comment must not be empty".to_owned());
    }

    let (action, revision) = reference
        .trim()
        .rsplit_once('@')
        .ok_or_else(|| "uses reference must contain @revision".to_owned())?;
    if !action.contains('/') || action.starts_with("./") || action.starts_with("docker://") {
        return Err("uses reference must name an inventoried remote action".to_owned());
    }
    let full_lower_hex = revision.len() == 40
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !full_lower_hex {
        return Err("uses revision must be a lowercase 40-hex commit SHA".to_owned());
    }

    Ok((action.to_owned(), revision.to_owned(), comment.to_owned()))
}

#[test]
fn every_workflow_reference_matches_the_reviewed_inventory() {
    let policy = json(POLICY_PATH);
    let discovered_paths = workflow_paths();
    let declared_paths = array(&policy["inventory"], "workflow_paths")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("workflow path must be text")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(discovered_paths, declared_paths);

    let mut observed = BTreeMap::<(String, String, String), u64>::new();
    for path in &discovered_paths {
        for (index, line) in read(path).lines().enumerate() {
            let Some(reference) = uses_reference(line) else {
                continue;
            };
            let key = validate_reference(reference).unwrap_or_else(|error| {
                panic!("{path}:{} invalid uses reference: {error}", index + 1)
            });
            *observed.entry(key).or_default() += 1;
        }
    }

    let mut declared = BTreeMap::<(String, String, String), u64>::new();
    for row in array(&policy, "pins") {
        let action = text(row, "action");
        let sha = text(row, "sha");
        let comment = text(row, "version_comment");
        assert!(!text(row, "source_ref").is_empty());
        let occurrences = row["occurrences"]
            .as_u64()
            .expect("occurrences must be unsigned");
        assert_eq!(
            text(row, "provenance_url"),
            format!("https://github.com/{action}/commit/{sha}")
        );
        assert!(
            text(row, "source_ref_url").starts_with(&format!("https://github.com/{action}/")),
            "source_ref_url must identify the action repository"
        );
        assert!(
            declared
                .insert(
                    (action.to_owned(), sha.to_owned(), comment.to_owned()),
                    occurrences,
                )
                .is_none(),
            "pin rows must be unique"
        );
    }

    assert_eq!(observed, declared);
    assert_eq!(
        observed.values().sum::<u64>(),
        policy["inventory"]["action_reference_count"]
            .as_u64()
            .expect("action_reference_count must be unsigned")
    );
    assert_eq!(
        discovered_paths.len() as u64,
        policy["inventory"]["workflow_file_count"]
            .as_u64()
            .expect("workflow_file_count must be unsigned")
    );
    let repositories = observed
        .keys()
        .map(|(action, _, _)| action)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        repositories.len() as u64,
        policy["inventory"]["distinct_action_repository_count"]
            .as_u64()
            .expect("distinct_action_repository_count must be unsigned")
    );
    assert_eq!(
        policy["inventory"]["reference_classes"],
        serde_json::json!({
            "remote_actions": 182,
            "local_actions": 0,
            "reusable_workflows": 0,
            "container_actions": 0,
            "job_containers": 0
        })
    );
}

#[test]
fn update_and_no_claim_policies_are_explicit() {
    let policy = json(POLICY_PATH);
    let docs = read(DOC_PATH);
    assert_eq!(text(&policy, "bead_id"), "asupersync-mnotoo.3.1");
    assert_eq!(
        text(&policy, "artifact_kind"),
        "policy_and_inventory_not_execution_receipt"
    );
    assert_eq!(
        text(&policy["update_contract"], "automated_tag_drift"),
        "forbidden"
    );
    assert!(array(&policy, "exceptions").is_empty());
    assert_eq!(policy["inventory"]["exception_count"].as_u64(), Some(0));
    assert!(
        text(&policy["review_receipt"], "scope")
            .contains("does not assert upstream trustworthiness")
    );
    assert_eq!(text(&policy["review_receipt"], "reviewer"), "FoggyPrairie");
    assert!(
        array(&policy["update_contract"], "required_review_steps").len() >= 7,
        "update contract must retain the complete review sequence"
    );
    assert!(array(&policy, "no_claim_boundaries").len() >= 4);
    for marker in [
        "Annotated tags",
        "No automated tag drift",
        "Branch-selected actions",
        "## Deterministic contract",
        "## No-claim boundaries",
        "does not make an action trustworthy",
    ] {
        assert!(docs.contains(marker), "runbook missing {marker}");
    }
}

#[test]
fn mutable_short_and_uncommented_references_fail_closed() {
    assert!(validate_reference("actions/checkout@v4 # v4").is_err());
    assert!(validate_reference("actions/checkout@11bd719 # v4.2.2").is_err());
    assert!(
        validate_reference("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683").is_err()
    );
    assert!(
        validate_reference("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2")
            .is_ok()
    );
}
