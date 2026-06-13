//! Contract tests for the parser fuzz protocol-family inventory receipt.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const INVENTORY_PATH: &str = "artifacts/parser_fuzz_protocol_inventory_v1.json";
const FUZZ_MANIFEST_PATH: &str = "fuzz/Cargo.toml";
const DOC_PATH: &str = "docs/parser_fuzz_protocol_inventory.md";

const REQUIRED_FAMILIES: &[&str] = &[
    "http1",
    "http2_hpack",
    "http3_qpack",
    "websocket",
    "tls_helpers",
    "dns",
    "database_protocols",
    "kafka",
    "quic",
    "codecs",
    "raptorq_metadata",
];

const REQUIRED_FIXTURES: &[&str] = &[
    "covered_registry",
    "missing_high_risk",
    "partial_and_stale_target",
    "duplicate_targets",
    "schema_and_stale_target",
    "exempt_and_expired",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_text(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn inventory() -> Value {
    serde_json::from_str(&read_text(INVENTORY_PATH)).expect("inventory JSON parses")
}

fn as_array<'a>(value: &'a Value, context: &str) -> &'a [Value] {
    value
        .as_array()
        .map_or_else(|| panic!("{context} must be an array"), Vec::as_slice)
}

fn as_str<'a>(value: &'a Value, context: &str) -> &'a str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("{context} must be a string"))
}

fn manifest_path_for_inventory_target(path: &str) -> &str {
    path.strip_prefix("fuzz/").unwrap_or(path)
}

fn manifest_has_bin(manifest: &str, name: &str, path: &str) -> bool {
    let name_line = format!("name = \"{name}\"");
    let manifest_path = manifest_path_for_inventory_target(path);
    let path_line = format!("path = \"{manifest_path}\"");
    manifest
        .split("[[bin]]")
        .any(|block| block.contains(&name_line) && block.contains(&path_line))
}

#[test]
fn inventory_declares_required_protocol_families() {
    let receipt = inventory();

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("parser-fuzz-protocol-inventory-v1")
    );
    assert_eq!(
        receipt["source_bead"].as_str(),
        Some("asupersync-idea-wizard-fifth-wave-3gaiun.10")
    );

    let families = as_array(&receipt["families"], "families");
    let family_ids: BTreeSet<&str> = families
        .iter()
        .map(|family| as_str(&family["id"], "family id"))
        .collect();

    for required in REQUIRED_FAMILIES {
        assert!(
            family_ids.contains(required),
            "required family {required} missing from parser fuzz inventory"
        );
    }

    assert_eq!(
        receipt["summary"]["family_count"].as_u64(),
        Some(families.len() as u64)
    );
    assert_eq!(
        receipt["summary"]["required_family_count"].as_u64(),
        Some(REQUIRED_FAMILIES.len() as u64)
    );
}

#[test]
fn every_family_has_target_coverage_or_an_owner_bead() {
    let receipt = inventory();
    let manifest = read_text(FUZZ_MANIFEST_PATH);
    let mut status_counts: BTreeMap<&str, usize> = BTreeMap::new();

    for family in as_array(&receipt["families"], "families") {
        let family_id = as_str(&family["id"], "family id");
        let status = as_str(&family["status"], "family status");
        let risk = as_str(&family["risk"], "family risk");
        assert!(
            ["covered", "partial", "owner_bead", "missing"].contains(&status),
            "family {family_id} has unsupported status {status}"
        );
        assert!(
            ["medium", "high", "critical"].contains(&risk),
            "family {family_id} has unsupported risk {risk}"
        );
        *status_counts.entry(status).or_insert(0) += 1;

        let targets = as_array(&family["target_refs"], "target refs");
        let owners = as_array(&family["owner_beads"], "owner beads");
        if status == "covered" || status == "partial" {
            assert!(
                !targets.is_empty(),
                "family {family_id} must cite registered fuzz target evidence"
            );
        }
        if status == "partial" || status == "owner_bead" || status == "missing" {
            assert!(
                !owners.is_empty(),
                "family {family_id} needs an owner bead for non-covered status"
            );
        }

        for target in targets {
            let name = as_str(&target["name"], "target name");
            let path = as_str(&target["path"], "target path");
            assert!(
                path.starts_with("fuzz/fuzz_targets/"),
                "target path {path} for {family_id} must stay under fuzz/fuzz_targets"
            );
            assert!(
                repo_root().join(path).exists(),
                "target path {path} for {family_id} does not exist"
            );
            assert!(
                manifest_has_bin(&manifest, name, path),
                "target {name} at {path} for {family_id} is not registered in {FUZZ_MANIFEST_PATH}"
            );
        }
    }

    for status in ["covered", "partial", "owner_bead", "missing"] {
        let expected = receipt["summary"]["status_counts"][status]
            .as_u64()
            .unwrap_or_else(|| panic!("missing status count for {status}"));
        let actual = status_counts.get(status).copied().unwrap_or(0);
        assert_eq!(expected, actual as u64, "status count drift for {status}");
    }

    assert_eq!(
        receipt["requirements"]["each_required_family_has_registered_targets_or_owner_bead"]
            .as_bool(),
        Some(true)
    );
}

#[test]
fn parser_registry_fixtures_cover_stale_missing_duplicate_and_exemptions() {
    let receipt = inventory();
    let fixture_contract = &receipt["fixture_contract"];

    assert_eq!(
        fixture_contract["helper"].as_str(),
        Some("scripts/parser_fuzz_coverage_registry.py")
    );
    assert_eq!(
        fixture_contract["contract"].as_str(),
        Some("tests/parser_fuzz_coverage_registry_contract.rs")
    );
    assert!(
        repo_root()
            .join(as_str(&fixture_contract["helper"], "fixture helper path"))
            .exists()
    );
    assert!(
        repo_root()
            .join(as_str(
                &fixture_contract["contract"],
                "fixture contract path"
            ))
            .exists()
    );

    let fixtures = as_array(&fixture_contract["fixtures"], "fixtures");
    let fixture_ids: BTreeSet<&str> = fixtures
        .iter()
        .map(|fixture| as_str(&fixture["id"], "fixture id"))
        .collect();
    for required in REQUIRED_FIXTURES {
        assert!(
            fixture_ids.contains(required),
            "required parser registry fixture {required} missing"
        );
    }

    for fixture in fixtures {
        let input = as_str(&fixture["input"], "fixture input");
        let expected = as_str(&fixture["expected"], "fixture expected");
        assert!(
            repo_root().join(input).exists(),
            "fixture input {input} does not exist"
        );
        assert!(
            repo_root().join(expected).exists(),
            "fixture expected {expected} does not exist"
        );
        assert!(
            !as_str(&fixture["purpose"], "fixture purpose").is_empty(),
            "fixture purpose must be documented"
        );
    }

    assert_eq!(
        receipt["requirements"]["stale_missing_duplicate_fixtures_present"].as_bool(),
        Some(true)
    );
}

#[test]
fn receipt_preserves_no_claim_and_non_mutating_boundaries() {
    let receipt = inventory();
    let non_claims: BTreeSet<&str> = as_array(&receipt["non_claims"], "non claims")
        .iter()
        .map(|claim| as_str(claim, "non claim"))
        .collect();
    assert!(non_claims.contains("not a fuzz coverage completeness claim"));
    assert!(non_claims.contains("not a replacement for cargo-fuzz execution or coverage reports"));
    assert!(non_claims.contains("not a broad workspace health proof"));

    for key in [
        "edits_fuzz_manifest",
        "creates_fuzz_targets",
        "runs_cargo_fuzz",
        "runs_local_cargo",
        "runs_git_mutation",
        "runs_destructive_command",
    ] {
        assert_eq!(
            receipt["forbidden_actions"][key].as_bool(),
            Some(false),
            "{key} must stay false"
        );
    }

    let doc = read_text(DOC_PATH);
    assert!(doc.contains("It does not claim complete semantic-oracle coverage"));
    assert!(doc.contains("does not run cargo-fuzz"));
}

#[test]
fn validation_lane_is_remote_only_and_points_at_this_contract() {
    let receipt = inventory();
    let command = as_str(&receipt["validation"]["rch_command"], "RCH command");

    assert!(
        command.contains("RCH_REQUIRE_REMOTE=1 rch exec --"),
        "proof command must require remote RCH execution"
    );
    assert!(
        command.contains("cargo test -p asupersync --test parser_fuzz_protocol_inventory_contract"),
        "proof command must target this focused contract"
    );
    assert!(
        command.contains("--no-default-features"),
        "proof command must avoid the default feature graph"
    );
    assert!(
        command.contains(
            "CARGO_TARGET_DIR=\"${TMPDIR:-/tmp}/rch_target_parser_fuzz_protocol_inventory\""
        ),
        "proof command must isolate its remote target directory"
    );
}
