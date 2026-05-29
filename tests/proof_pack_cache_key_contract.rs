//! Contract tests for the proof-pack cache-key helper and schema artifact.

#![allow(missing_docs)]

use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/proof_pack_cache_key.py";
const ARTIFACT_PATH: &str = "artifacts/proof_pack_cache_key_contract_v1.json";
const GENERATED_AT: &str = "2026-05-29T01:15:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn base_input() -> Value {
    json!({
        "schema_version": "proof-pack-cache-key-input-v1",
        "cargo_lock_sha256": "aaf0f521d13f2db8cfc04d5a8c10d7c9a4c3f9426bcdd54841c9f4f58f08c2ac",
        "rust_toolchain": {
            "channel": "nightly-2026-05-28",
            "profile": "minimal",
            "components": ["rustfmt", "clippy"],
            "targets": ["x86_64-unknown-linux-gnu"]
        },
        "target_triple": "x86_64-unknown-linux-gnu",
        "workspace_package": "asupersync",
        "features": ["test-internals", "metrics"],
        "proof_lane_family": "module-microharness",
        "env": {
            "RUSTFLAGS": "-C debuginfo=0",
            "CARGO_BUILD_JOBS": "2",
            "IGNORED_SECRET_LIKE_VALUE": "not-keyed"
        },
        "repo": {
            "branch": "main",
            "head_sha": "2edfde3452d95df357c6c059fe6a0476ca9048f9",
            "ref_kind": "branch"
        }
    })
}

fn run_key(input: &Value) -> Output {
    let mut file = tempfile::NamedTempFile::new().expect("create key input");
    file.write_all(
        serde_json::to_string_pretty(input)
            .expect("serialize input")
            .as_bytes(),
    )
    .expect("write input");

    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--input")
        .arg(file.path())
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run proof-pack cache-key helper")
}

fn key_json(input: &Value) -> Value {
    let output = run_key(input);
    assert!(
        output.status.success(),
        "cache-key helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cache-key receipt must be JSON")
}

fn refusal_codes(receipt: &Value) -> Vec<String> {
    receipt["refusal_reasons"]
        .as_array()
        .expect("refusal reasons")
        .iter()
        .map(|item| item.as_str().expect("reason").to_string())
        .collect()
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "helper must exist at {SCRIPT_PATH}"
    );
    let output = Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--help")
        .current_dir(repo_root())
        .output()
        .expect("run helper --help");
    assert!(output.status.success(), "--help should succeed");
}

#[test]
fn contract_artifact_defines_required_key_material_and_safety_rules() {
    let artifact_text = fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("read proof-pack cache-key contract artifact");
    let artifact: Value = serde_json::from_str(&artifact_text).expect("artifact is JSON");

    assert_eq!(
        artifact["schema_version"].as_str(),
        Some("proof-pack-cache-key-contract-v1")
    );
    let component_ids: Vec<&str> = artifact["canonical_components"]
        .as_array()
        .expect("components")
        .iter()
        .map(|component| component["id"].as_str().expect("component id"))
        .collect();
    for required in [
        "cargo_lock_sha256",
        "rust_toolchain",
        "target_triple",
        "workspace_package",
        "features",
        "proof_lane_family",
        "env_flags",
        "git_branch",
        "git_head_sha",
    ] {
        assert!(
            component_ids.contains(&required),
            "contract artifact missing required component {required}"
        );
    }
    assert_eq!(
        artifact["safety_contract"]["warmed_caches_are_advisory_only"].as_bool(),
        Some(true)
    );
    assert_eq!(
        artifact["safety_contract"]["proof_must_still_execute"].as_bool(),
        Some(true)
    );
    assert_eq!(
        artifact["safety_contract"]["branch_required"].as_str(),
        Some("main")
    );
    assert_eq!(
        artifact["safety_contract"]["cross_ref_reuse_forbidden"].as_bool(),
        Some(true)
    );
}

#[test]
fn equivalent_material_emits_stable_key_despite_ordering() {
    let first = key_json(&base_input());
    let mut reordered = base_input();
    reordered["features"] = json!(["metrics", "test-internals", "metrics"]);
    reordered["rust_toolchain"]["components"] = json!(["clippy", "rustfmt", "clippy"]);
    reordered["env"] = json!({
        "IGNORED_SECRET_LIKE_VALUE": "changed-but-not-keyed",
        "CARGO_BUILD_JOBS": "2",
        "RUSTFLAGS": "-C debuginfo=0"
    });
    let second = key_json(&reordered);

    assert_eq!(first["decision"].as_str(), Some("emit-advisory-cache-key"));
    assert_eq!(first["cache_key_valid"].as_bool(), Some(true));
    assert_eq!(first["cache_key"], second["cache_key"]);
    assert_eq!(
        first["normalized_key_material"]["features"],
        json!(["metrics", "test-internals"])
    );
    assert_eq!(
        first["ignored_env_keys"],
        json!(["IGNORED_SECRET_LIKE_VALUE"])
    );
}

#[test]
fn lockfile_feature_and_toolchain_changes_invalidate_key() {
    let baseline = key_json(&base_input());

    let mut lock_changed = base_input();
    lock_changed["cargo_lock_sha256"] =
        json!("bbf0f521d13f2db8cfc04d5a8c10d7c9a4c3f9426bcdd54841c9f4f58f08c2ac");
    let mut feature_changed = base_input();
    feature_changed["features"] = json!(["metrics", "test-internals", "sqlite"]);
    let mut toolchain_changed = base_input();
    toolchain_changed["rust_toolchain"]["channel"] = json!("nightly-2026-05-29");

    for changed in [&lock_changed, &feature_changed, &toolchain_changed] {
        let receipt = key_json(changed);
        assert_eq!(receipt["cache_key_valid"].as_bool(), Some(true));
        assert_ne!(
            baseline["cache_key"], receipt["cache_key"],
            "changed invalidation material must change the advisory cache key"
        );
    }
}

#[test]
fn non_main_ref_is_refused_instead_of_reused() {
    let mut input = base_input();
    input["repo"]["branch"] = json!("feature/cache-warmth");

    let receipt = key_json(&input);

    assert_eq!(receipt["decision"].as_str(), Some("refuse-cache-key"));
    assert_eq!(receipt["cache_key_valid"].as_bool(), Some(false));
    assert_eq!(receipt["cache_key"].as_str(), Some(""));
    assert!(refusal_codes(&receipt).contains(&"non-main-ref".to_string()));
}

#[test]
fn unknown_head_sha_is_refused_instead_of_reused() {
    let mut input = base_input();
    input["repo"]["head_sha"] = json!("unknown");

    let receipt = key_json(&input);

    assert_eq!(receipt["decision"].as_str(), Some("refuse-cache-key"));
    assert_eq!(receipt["cache_key_valid"].as_bool(), Some(false));
    assert!(refusal_codes(&receipt).contains(&"unknown-head-sha".to_string()));
}

#[test]
fn receipt_declares_advisory_non_mutating_cache_semantics() {
    let receipt = key_json(&base_input());

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("proof-pack-cache-key-receipt-v1")
    );
    assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(receipt["current_date"].as_str(), Some("2026-05-29"));
    assert_eq!(
        receipt["safety_contract"]["warmed_caches_are_advisory_only"].as_bool(),
        Some(true)
    );
    assert_eq!(
        receipt["safety_contract"]["proof_must_still_execute"].as_bool(),
        Some(true)
    );
    assert_eq!(
        receipt["safety_contract"]["branch_required"].as_str(),
        Some("main")
    );
    assert_eq!(receipt["non_mutating"].as_bool(), Some(true));
    assert_eq!(
        receipt["forbidden_actions"]["writes_remote_cache"].as_bool(),
        Some(false)
    );
    assert_eq!(
        receipt["forbidden_actions"]["runs_cargo"].as_bool(),
        Some(false)
    );
    assert_eq!(
        receipt["forbidden_actions"]["runs_git_mutation"].as_bool(),
        Some(false)
    );
}
