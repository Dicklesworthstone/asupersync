//! Contract tests for the memory-residency source inventory.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const CONTRACT_PATH: &str = "artifacts/memory_residency_inventory_v1.json";
const REQUIRED_CLAIMS: &[&str] = &[
    "runtime_capacity_hints",
    "memory_tier_slab_pool_substrate",
    "hot_cold_arena_tiers",
    "numa_arena_locality",
    "proof_pack_warmth_planner",
    "runtime_pressure_control_evidence",
    "swarm_memory_residency_policy",
];
const REQUIRED_GAPS: &[&str] = &["artifact_cache_pressure_snapshot"];
const REQUIRED_BOUNDARIES: &[&str] = &[
    "broad_workspace_health",
    "release_readiness",
    "allocator_universality",
    "performance_improvement",
    "permission_to_delete_files",
    "local_cargo_fallback",
    "default_runtime_behavior_change",
];
const REQUIRED_FAIL_CLOSED_CHECKS: &[&str] = &[
    "missing_owner_row",
    "duplicate_claim_owner",
    "duplicate_claim_id",
    "stale_proof_command",
    "broad_performance_claim",
    "broad_allocator_claim",
    "release_readiness_claim",
    "local_cargo_fallback",
    "missing_no_claim_boundary",
    "missing_overlap_decision",
    "missing_next_child_for_gap",
];
const REQUIRED_OVERLAPS: &[&str] = &[
    "asupersync-h6pjqb",
    "scheduler-hot-path-perf",
    "fourth-wave-pressure-governance",
    "validation-frontier",
    "appspec",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_contract() -> Value {
    let path = repo_root().join(CONTRACT_PATH);
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn read_repo_file(path: &str) -> String {
    let path = repo_root().join(path);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} array"))
        .as_slice()
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

fn field_path_exists(path: &str) {
    assert!(
        repo_root().join(path).exists(),
        "inventory path must exist: {path}"
    );
}

fn path_set(row: &Value, key: &str) -> BTreeSet<String> {
    let paths = string_set(row, key);
    assert!(
        !paths.is_empty(),
        "{key} must not be empty for {}",
        row["claim_id"]
            .as_str()
            .or_else(|| row["gap_id"].as_str())
            .unwrap_or("row")
    );
    for path in &paths {
        field_path_exists(path);
    }
    paths
}

fn test_stem(path: &str) -> String {
    Path::new(path)
        .file_stem()
        .expect("test file stem")
        .to_string_lossy()
        .into_owned()
}

fn assert_rch_cargo_proof_command(command: &str, test_paths: &BTreeSet<String>) {
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
        "proof command must require remote RCH: {command}"
    );
    assert!(
        command.contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_")
            || command.contains("CARGO_TARGET_DIR=\"${TMPDIR:-/tmp}/rch_target_"),
        "proof command must isolate CARGO_TARGET_DIR: {command}"
    );
    assert!(
        command.contains("cargo test -p asupersync"),
        "proof command must be a focused asupersync cargo test: {command}"
    );
    assert!(
        !command.starts_with("cargo ") && !command.contains(" cargo check "),
        "proof command must not use local Cargo fallback or a non-test lane: {command}"
    );
    assert!(
        test_paths.iter().any(|path| {
            let stem = test_stem(path);
            command.contains(&format!("--test {stem}"))
        }),
        "proof command must name one mapped contract test: {command}"
    );
}

#[test]
fn inventory_declares_scope_and_fail_closed_policy() {
    let contract = load_contract();
    assert_eq!(
        string_field(&contract, "schema_version"),
        "memory-residency-inventory-v1"
    );
    assert_eq!(
        string_field(&contract, "bead_id"),
        "asupersync-memory-residency-control-ho2itz.1"
    );
    assert_eq!(string_field(&contract, "status"), "inventory_only");
    assert_eq!(
        string_field(&contract, "next_child_bead"),
        "asupersync-memory-residency-control-ho2itz.2"
    );

    field_path_exists(string_field(&contract, "docs_path"));
    field_path_exists(string_field(&contract, "focused_contract_test"));

    let source_of_truth = &contract["source_of_truth"];
    for key in [
        "inventory_artifact",
        "inventory_docs",
        "inventory_contract_test",
        "proof_lane_manifest",
        "proof_status_snapshot",
    ] {
        field_path_exists(string_field(source_of_truth, key));
    }

    let validation_policy = &contract["validation_policy"];
    let checks = string_set(validation_policy, "fail_closed_checks");
    for required in REQUIRED_FAIL_CLOSED_CHECKS {
        assert!(
            checks.contains(*required),
            "missing fail-closed check {required}"
        );
    }

    let boundaries: BTreeSet<_> = array(&contract, "global_no_claim_boundaries")
        .iter()
        .map(|row| string_field(row, "boundary_id").to_string())
        .collect();
    for required in REQUIRED_BOUNDARIES {
        assert!(
            boundaries.contains(*required),
            "missing global no-claim boundary {required}"
        );
    }
}

#[test]
fn claim_rows_are_owned_unique_and_backed_by_existing_contracts() {
    let contract = load_contract();
    let mut claim_ids = BTreeSet::new();
    let mut owner_ids = BTreeSet::new();

    for row in array(&contract, "claim_rows") {
        let claim_id = string_field(row, "claim_id");
        let owner_id = string_field(row, "owner_id");
        assert!(
            claim_ids.insert(claim_id.to_string()),
            "duplicate {claim_id}"
        );
        assert!(
            owner_ids.insert(owner_id.to_string()),
            "duplicate {owner_id}"
        );
        assert_eq!(string_field(row, "claim_status"), "contract_guarded");

        let supported_claim = string_field(row, "supported_claim").to_ascii_lowercase();
        for forbidden in [
            "release ready",
            "release readiness",
            "performance improvement",
            "p999 improvement",
            "allocator replacement",
            "universal allocator",
            "production-on-by-default",
        ] {
            assert!(
                !supported_claim.contains(forbidden),
                "{claim_id} overclaims with forbidden phrase {forbidden}"
            );
        }

        let test_paths = path_set(row, "contract_tests");
        path_set(row, "source_files");
        path_set(row, "artifacts");

        let boundaries = string_set(row, "no_claim_boundaries");
        assert!(
            !boundaries.is_empty(),
            "{claim_id} must carry explicit no-claim boundaries"
        );

        let commands = string_set(row, "proof_commands");
        assert!(
            !commands.is_empty(),
            "{claim_id} must carry at least one proof command"
        );
        for command in &commands {
            assert_rch_cargo_proof_command(command, &test_paths);
        }
    }

    for required in REQUIRED_CLAIMS {
        assert!(
            claim_ids.contains(*required),
            "missing required claim row {required}"
        );
    }
}

#[test]
fn source_gap_rows_are_explicitly_not_claim_rows() {
    let contract = load_contract();
    let mut gap_ids = BTreeSet::new();
    let mut owner_ids = BTreeSet::new();

    for row in array(&contract, "source_gap_rows") {
        let gap_id = string_field(row, "gap_id");
        let owner_id = string_field(row, "owner_id");
        assert!(gap_ids.insert(gap_id.to_string()), "duplicate gap {gap_id}");
        assert!(
            owner_ids.insert(owner_id.to_string()),
            "duplicate gap owner {owner_id}"
        );
        assert_eq!(string_field(row, "gap_status"), "source_mapped_no_claim");
        path_set(row, "source_files");
        assert!(
            string_field(row, "why_not_claimed").contains("does not create"),
            "{gap_id} must explain why it is not a claim"
        );
        assert!(
            string_field(row, "next_child_bead")
                .starts_with("asupersync-memory-residency-control-ho2itz."),
            "{gap_id} must name a memory-residency child bead"
        );
        assert!(
            !array(row, "required_before_claim").is_empty(),
            "{gap_id} must list required work before claim"
        );
        assert!(
            !array(row, "no_claim_boundaries").is_empty(),
            "{gap_id} must carry no-claim boundaries"
        );
    }

    for required in REQUIRED_GAPS {
        assert!(
            gap_ids.contains(*required),
            "missing required source gap row {required}"
        );
    }
}

#[test]
fn overlap_decisions_cover_known_program_boundaries() {
    let contract = load_contract();
    let overlaps: BTreeSet<_> = array(&contract, "overlap_decisions")
        .iter()
        .map(|row| {
            let overlap_id = string_field(row, "overlap_id").to_string();
            assert!(!string_field(row, "decision").is_empty());
            assert!(!string_field(row, "rationale").is_empty());
            path_set(row, "referenced_surfaces");
            overlap_id
        })
        .collect();

    for required in REQUIRED_OVERLAPS {
        assert!(
            overlaps.contains(*required),
            "missing overlap decision {required}"
        );
    }
}

#[test]
fn docs_inventory_and_focused_proof_stay_aligned() {
    let contract = load_contract();
    let docs = read_repo_file(string_field(&contract, "docs_path"));
    assert!(docs.contains(CONTRACT_PATH));
    assert!(docs.contains("M1 is inventory-only"));
    assert!(docs.contains("local Cargo fallback"));
    assert!(docs.contains("release readiness"));
    assert!(docs.contains(string_field(&contract, "next_child_bead")));

    for row in array(&contract, "claim_rows") {
        assert!(docs.contains(string_field(row, "claim_id")));
    }
    for row in array(&contract, "source_gap_rows") {
        assert!(docs.contains(string_field(row, "gap_id")));
    }

    let focused = &contract["focused_proof"];
    assert_eq!(
        string_field(focused, "lane_id"),
        "memory-residency-inventory-contract"
    );
    let mut test_paths = BTreeSet::new();
    test_paths.insert(string_field(&contract, "focused_contract_test").to_string());
    assert_rch_cargo_proof_command(string_field(focused, "command"), &test_paths);
    assert!(string_field(focused, "explicit_not_covered").contains("release readiness"));
}
