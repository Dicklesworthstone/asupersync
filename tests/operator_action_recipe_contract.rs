//! Contract tests for shared-main operator action recipes.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/proof_runner.py";
const CONTRACT_PATH: &str = "artifacts/operator_action_recipe_contract_v1.json";

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
    if !output.status.success() {
        panic!(
            "proof runner failed: {}\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("proof runner output not JSON: {error}\noutput: {stdout}"))
}

fn recipe_ids(recipes: &[Value]) -> BTreeSet<String> {
    recipes
        .iter()
        .map(|recipe| recipe["recipe_id"].as_str().expect("recipe_id").to_string())
        .collect()
}

#[test]
fn operator_recipe_catalog_matches_contract() {
    let contract = load_json(CONTRACT_PATH);
    assert_eq!(
        contract["generated_artifact_schema"].as_str(),
        Some("operator-action-recipe-v1")
    );
    assert_eq!(contract["bead_id"].as_str(), Some("asupersync-xeh8m0.7"));

    let result = proof_runner_json(&["--list-operator-recipes", "--output", "json"]);
    assert_eq!(
        result["schema_version"].as_str(),
        Some("operator-action-recipe-v1")
    );
    let recipes = result["recipes"].as_array().expect("recipes array");
    let listed_ids = recipe_ids(recipes);
    for required in contract["required_recipe_ids"]
        .as_array()
        .expect("required recipe ids")
    {
        let required = required.as_str().expect("required id");
        assert!(
            listed_ids.contains(required),
            "missing operator recipe {required}"
        );
    }
}

#[test]
fn operator_recipes_are_safe_and_complete() {
    let contract = load_json(CONTRACT_PATH);
    let required_fields: BTreeSet<&str> = contract["required_recipe_fields"]
        .as_array()
        .expect("required recipe fields")
        .iter()
        .map(|field| field.as_str().expect("field"))
        .collect();
    let required_log_fields: BTreeSet<&str> = contract["required_log_fields"]
        .as_array()
        .expect("required log fields")
        .iter()
        .map(|field| field.as_str().expect("field"))
        .collect();
    let allowed_verdicts: BTreeSet<&str> = contract["allowed_operator_verdicts"]
        .as_array()
        .expect("allowed verdicts")
        .iter()
        .map(|field| field.as_str().expect("verdict"))
        .collect();

    let result = proof_runner_json(&["--list-operator-recipes", "--output", "json"]);
    let recipes = result["recipes"].as_array().expect("recipes array");
    assert!(!recipes.is_empty(), "recipe catalog must not be empty");

    for recipe in recipes {
        for required in &required_fields {
            assert!(recipe.get(*required).is_some(), "missing field {required}");
        }

        let command = recipe["proof_command_shape"]
            .as_str()
            .expect("proof command shape");
        assert!(
            command.starts_with("rch exec -- "),
            "proof command must be rch-routed: {command}"
        );
        assert!(
            !command.starts_with("cargo ") && !command.contains(" cargo +"),
            "proof command must not use local cargo fallback: {command}"
        );

        let br_commands = recipe["allowed_br_commands"]
            .as_array()
            .expect("allowed br commands");
        assert!(
            br_commands
                .iter()
                .all(|command| command.as_str().expect("br command").starts_with("br ")),
            "allowed br commands must be explicit br commands"
        );

        let bv_commands = recipe["allowed_bv_commands"]
            .as_array()
            .expect("allowed bv commands");
        assert!(
            bv_commands.iter().all(|command| {
                command
                    .as_str()
                    .expect("bv command")
                    .starts_with("bv --robot-")
            }),
            "allowed bv commands must use robot modes"
        );

        let log_fields: BTreeSet<&str> = recipe["expected_log_fields"]
            .as_array()
            .expect("expected log fields")
            .iter()
            .map(|field| field.as_str().expect("field"))
            .collect();
        for required in &required_log_fields {
            assert!(
                log_fields.contains(required),
                "recipe missing log field {required}"
            );
        }
        assert_eq!(recipe["first_blocker_line_required"].as_bool(), Some(true));
        assert!(
            recipe["reservation_policy"]
                .as_str()
                .expect("reservation policy")
                .contains("Agent Mail"),
            "reservation policy must be explicit"
        );
        assert!(
            allowed_verdicts.contains(recipe["operator_verdict"].as_str().expect("verdict")),
            "operator verdict must be allowed"
        );
        assert_eq!(
            recipe["tracker_payload_recommendation"]["mutates_tracker"].as_bool(),
            Some(false),
            "recipes may recommend tracker payloads but must not mutate tracker state"
        );
    }
}

#[test]
fn operator_recipes_reject_raw_coordination_and_destructive_text() {
    let result = proof_runner_json(&["--list-operator-recipes", "--output", "json"]);
    let rendered = serde_json::to_string(&result).expect("render recipes");

    for forbidden in [
        "/home/ubuntu/",
        "body_md",
        "ack_required",
        "git reset --hard",
        "git clean -fd",
        "rm -rf",
        "git worktree add",
        "git branch ",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "operator recipe output must not contain forbidden marker {forbidden}"
        );
    }
}

#[test]
fn operator_recipe_dry_run_recommends_without_mutating() {
    let result = proof_runner_json(&[
        "--operator-recipe",
        "rerun-proof-lane",
        "--operator-mode",
        "dry-run",
        "--output",
        "json",
    ]);
    assert_eq!(result["mode"].as_str(), Some("dry-run"));
    assert_eq!(result["would_execute"].as_bool(), Some(true));
    assert_eq!(result["executed"].as_bool(), Some(false));
    assert_eq!(result["mutates_tracker"].as_bool(), Some(false));
    assert_eq!(
        result["recommended_tracker_payload"]["mutates_tracker"].as_bool(),
        Some(false)
    );
}

#[test]
fn operator_recipe_execute_mode_is_limited_to_safe_scenarios() {
    let result = proof_runner_json(&[
        "--operator-recipe",
        "dirty-frontier-refusal",
        "--operator-mode",
        "execute",
        "--output",
        "json",
    ]);
    assert_eq!(result["mode"].as_str(), Some("execute"));
    assert_eq!(result["executed"].as_bool(), Some(true));
    assert_eq!(
        result["side_effects"]
            .as_array()
            .expect("side effects")
            .len(),
        0
    );
    assert_eq!(result["operator_verdict"].as_str(), Some("refuse"));

    let blocked = run_proof_runner(&[
        "--operator-recipe",
        "stale-in-progress-reclaim",
        "--operator-mode",
        "execute",
        "--output",
        "json",
    ]);
    assert!(
        !blocked.status.success(),
        "unsafe execute-mode recipe should fail closed"
    );
    let stdout = String::from_utf8_lossy(&blocked.stdout);
    assert!(
        stdout.contains("execute mode is disabled"),
        "blocked execute output should explain fail-closed behavior: {stdout}"
    );
}
