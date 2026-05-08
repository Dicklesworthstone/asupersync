//! Contract ratchets for memory-tier aware slab/pool certification.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const CONTRACT_PATH: &str = "artifacts/memory_tier_slab_pool_contract_v1.json";
const TEST_PATH: &str = "tests/memory_tier_slab_pool_contract.rs";

fn load_contract() -> Value {
    serde_json::from_str(&fs::read_to_string(CONTRACT_PATH).expect("read memory tier contract"))
        .expect("parse memory tier contract")
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} array"))
        .as_slice()
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value[key]
        .as_object()
        .unwrap_or_else(|| panic!("{key} object"))
}

fn string_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} string"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| entry.as_str().expect("string array entry").to_string())
        .collect()
}

fn tier_rows(contract: &Value) -> Vec<&Value> {
    array(contract, "tier_rows").iter().collect()
}

fn rows_by_id(contract: &Value) -> BTreeMap<String, &Value> {
    tier_rows(contract)
        .into_iter()
        .map(|row| (string_field(row, "row_id").to_string(), row))
        .collect()
}

fn validation_commands(contract: &Value) -> BTreeSet<String> {
    string_set(contract, "validation_commands")
}

fn render_markdown(contract: &Value) -> Vec<String> {
    let mut rows = vec![
        "| Row | Domain | Tier | Verdict | Proofs |".to_string(),
        "| --- | --- | --- | --- | --- |".to_string(),
    ];

    for row in tier_rows(contract) {
        rows.push(format!(
            "| {} | {} | {} | {} | {} |",
            string_field(row, "row_id"),
            string_field(row, "runtime_domain"),
            string_field(row, "memory_tier"),
            string_field(row, "operator_verdict"),
            array(row, "proof_commands").len()
        ));
    }

    rows
}

#[test]
fn contract_declares_the_memory_tier_coverage_surface() {
    let contract = load_contract();
    assert_eq!(
        string_field(&contract, "contract_version"),
        "memory-tier-slab-pool-contract-v1"
    );
    assert_eq!(string_field(&contract, "bead_id"), "asupersync-h6pjqb");
    assert_eq!(string_field(&contract, "status"), "contract_guarded");

    let requirements = object(&contract, "coverage_requirements");
    let required_domains = string_set(
        &Value::Object(requirements.clone()),
        "required_runtime_domains",
    );
    for domain in [
        "task_records",
        "region_records",
        "obligation_records",
        "trace_evidence",
        "proof_artifacts",
    ] {
        assert!(
            required_domains.contains(domain),
            "missing required runtime domain {domain}"
        );
    }

    let required_tiers = string_set(
        &Value::Object(requirements.clone()),
        "required_memory_tiers",
    );
    for tier in [
        "hot_runtime_records",
        "warm_capacity_and_locality_plans",
        "cold_evidence_artifacts",
        "safe_heap_fallback",
    ] {
        assert!(required_tiers.contains(tier), "missing memory tier {tier}");
    }
}

#[test]
fn every_tier_row_is_source_owned_and_has_a_proof_lane() {
    let contract = load_contract();
    let rows = rows_by_id(&contract);
    for row_id in [
        "hot_task_record_pool",
        "warm_runtime_capacity_hints",
        "warm_numa_arena_locality",
        "cold_trace_evidence_tiers",
        "cold_proof_artifact_retention",
        "safe_heap_fallback",
    ] {
        assert!(rows.contains_key(row_id), "missing row {row_id}");
    }

    for row in rows.values() {
        let row_id = string_field(row, "row_id");
        let source_files = array(row, "source_files");
        assert!(!source_files.is_empty(), "{row_id} has no source files");
        for source in source_files {
            let path = source.as_str().expect("source file string");
            assert!(Path::new(path).exists(), "{row_id} source {path} missing");
        }

        let proof_commands = array(row, "proof_commands");
        assert!(!proof_commands.is_empty(), "{row_id} has no proof commands");
        for command in proof_commands {
            let command = command.as_str().expect("proof command string");
            if command.contains("cargo ") || command.contains("rustfmt") {
                assert!(
                    command.starts_with("rch exec -- "),
                    "{row_id} CPU-heavy proof must be rch-routed: {command}"
                );
            }
            if command.contains("cargo test") {
                assert!(
                    command.contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_"),
                    "{row_id} cargo proof must use an isolated target dir: {command}"
                );
            }
        }
    }
}

#[test]
fn fail_closed_rows_cannot_render_as_green_or_unbounded() {
    let contract = load_contract();
    let allowed_states = string_set(
        &Value::Object(object(&contract, "coverage_requirements").clone()),
        "required_fail_closed_states",
    );
    let forbidden = string_set(
        &Value::Object(object(&contract, "coverage_requirements").clone()),
        "forbidden_green_without_live_proof",
    );
    let rendered = render_markdown(&contract).join("\n");

    for row in tier_rows(&contract) {
        let row_id = string_field(row, "row_id");
        let verdict = string_field(row, "operator_verdict");
        assert!(
            allowed_states.contains(verdict),
            "{row_id} uses non fail-closed verdict {verdict}"
        );
        assert_ne!(
            verdict, "ready_for_rch",
            "{row_id} renders a stale green verdict"
        );
        assert_ne!(verdict, "pass", "{row_id} renders a stale green verdict");
    }

    for forbidden_claim in forbidden {
        assert!(
            !rendered.contains(&forbidden_claim),
            "rendered matrix contains stale unsupported claim {forbidden_claim:?}"
        );
    }
}

#[test]
fn validation_commands_cover_this_contract_test() {
    let contract = load_contract();
    let policy = object(&contract, "validation_policy");
    assert_eq!(
        policy["contract_test_target"].as_str(),
        Some("memory_tier_slab_pool_contract")
    );
    assert_eq!(
        policy["cargo_proofs_must_be_rch_routed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        policy["cargo_proofs_must_use_isolated_target_dir"].as_bool(),
        Some(true)
    );

    let required_flags = string_set(&Value::Object(policy.clone()), "required_feature_flags");
    assert!(required_flags.contains("test-internals"));

    let commands_must_cover = string_set(&Value::Object(policy.clone()), "commands_must_cover");
    for required in ["json_syntax", "contract_rustfmt", "contract_cargo_test"] {
        assert!(
            commands_must_cover.contains(required),
            "validation policy omits {required}"
        );
    }

    let commands = validation_commands(&contract);
    assert!(commands.iter().any(|command| {
        command
            == "python3 -m json.tool artifacts/memory_tier_slab_pool_contract_v1.json >/dev/null"
    }));
    assert!(commands.iter().any(|command| {
        command.starts_with("rch exec -- rustfmt")
            && command.contains("--edition 2024")
            && command.contains(TEST_PATH)
    }));
    assert!(commands.iter().any(|command| {
        command.starts_with("rch exec -- ")
            && command.contains(
                "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_memory_tier_slab_pool_contract",
            )
            && command.contains("cargo test -p asupersync --test memory_tier_slab_pool_contract")
            && command.contains("--features test-internals")
    }));
}

#[test]
fn markdown_projection_is_stable() {
    let contract = load_contract();
    let rendered = render_markdown(&contract);
    let golden: Vec<String> = array(&contract, "markdown_golden")
        .iter()
        .map(|line| line.as_str().expect("markdown line string").to_string())
        .collect();

    assert_eq!(
        rendered, golden,
        "memory-tier certification matrix projection must stay reviewed"
    );
}
