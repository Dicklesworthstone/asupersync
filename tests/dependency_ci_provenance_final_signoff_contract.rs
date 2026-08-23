#![allow(clippy::nursery, clippy::pedantic, missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const AGENTS_PATH: &str = "AGENTS.md";
const ARTIFACT_PATH: &str = "artifacts/dependency_ci_provenance_final_signoff_v1.json";
const ACTIONS_PATH: &str = "artifacts/github_actions_provenance_v1.json";
const BUDGET_PATH: &str = "artifacts/dependency_budget_contract_v1.json";
const DOWNSTREAM_PATH: &str = "artifacts/downstream_consumer_proof_v1.json";
const DOC_PATH: &str = "docs/dependency_ci_provenance_final_signoff.md";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const README_PATH: &str = "README.md";
const STATUS_PATH: &str = "artifacts/proof_status_snapshot_v1.json";
const SUPPLY_PATH: &str = "artifacts/dependency_supply_chain_policy_v1.json";
const BEAD_ID: &str = "asupersync-mnotoo.3.7";
const LANE_ID: &str = "dependency-ci-provenance-final-signoff";
const PROOF_COMMAND: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_dependency_ci_provenance_final_signoff CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -j 2 -p asupersync --test dependency_ci_provenance_final_signoff_contract -- --nocapture";

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
    let result = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!result.trim().is_empty(), "{key} must be nonempty");
    result
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn number(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn boolean(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a boolean"))
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    strings(value, key).into_iter().collect()
}

fn sha256_file(relative: &str) -> String {
    let bytes = std::fs::read(repo_path(relative))
        .unwrap_or_else(|error| panic!("read bytes {relative}: {error}"));
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_full_lower_hex(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn discover_package_manifests_in(root: &Path, relative: &Path, output: &mut Vec<String>) {
    let directory = root.join(relative);
    for entry in std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
    {
        let entry = entry.expect("read package inventory entry");
        let file_type = entry.file_type().expect("read package inventory file type");
        let child_relative = relative.join(entry.file_name());
        if file_type.is_dir() {
            if matches!(
                entry.file_name().to_str(),
                Some("node_modules" | "target" | ".next" | "dist")
            ) {
                continue;
            }
            discover_package_manifests_in(root, &child_relative, output);
        } else if entry.file_name() == "package.json" {
            output.push(child_relative.to_string_lossy().replace('\\', "/"));
        }
    }
}

fn discovered_package_manifests() -> Vec<String> {
    let root = repo_path("");
    let mut result = vec!["package.json".to_owned()];
    discover_package_manifests_in(&root, Path::new("packages"), &mut result);
    discover_package_manifests_in(&root, Path::new("tests/fixtures"), &mut result);
    result.sort();
    result
}

fn validation_errors(receipt: &Value) -> BTreeSet<String> {
    let mut errors = BTreeSet::new();
    let verdict = &receipt["verdict"];
    let children = array(receipt, "child_outcomes");
    if children.len() != 6
        || children
            .iter()
            .any(|row| row["required_status"] != "closed")
    {
        errors.insert("child-not-closed".to_owned());
    }
    if boolean(verdict, "package_manager_execution_authorized")
        || boolean(
            &receipt["javascript_package_tree_decision"],
            "package_manager_execution_authorized",
        )
        || boolean(
            &receipt["javascript_package_tree_decision"],
            "package_manager_invoked_by_signoff",
        )
    {
        errors.insert("unauthorized-package-manager".to_owned());
    }

    let database = &receipt["fresh_cargo_scanner_receipt"]["advisory_database"];
    if !boolean(database, "fresh")
        || !boolean(database, "fetched")
        || number(database, "age_seconds") > number(database, "maximum_age_seconds")
    {
        errors.insert("stale-advisory-database".to_owned());
    }
    if receipt["fresh_cargo_scanner_receipt"]["excluded_fuzz_workspace"]["tokio_quarantine"]
        != "expected_excluded_fuzz_only"
    {
        errors.insert("fuzz-quarantine-drift".to_owned());
    }
    if receipt["downstream_minimum_version_receipt"]["full_transitive_minimal_status"]
        != "blocked_upstream_transitive_range"
        || receipt["downstream_minimum_version_receipt"]["blocker_package"]
            != "curve25519-dalek 4.0.0"
    {
        errors.insert("transitive-minimal-overclaim".to_owned());
    }
    let generated = &receipt["generated_dependency_documentation_receipt"];
    if generated["status"] != "pass"
        || number(generated, "generated_row_count") != 14
        || number(generated, "displayed_dependency_name_count") != 15
        || generated["check_mode"] != "read-only"
        || boolean(generated, "automatic_local_rewrite")
    {
        errors.insert("generated-document-drift".to_owned());
    }
    if boolean(verdict, "dependency_exit_allowed")
        || boolean(verdict, "cutover_authority")
        || boolean(verdict, "file_deletion_authorized")
    {
        errors.insert("authority-overclaim".to_owned());
    }
    if array(receipt, "source_contracts")
        .iter()
        .any(|row| sha256_file(text(row, "path")) != text(row, "sha256"))
    {
        errors.insert("source-contract-drift".to_owned());
    }
    errors
}

#[test]
fn header_verdict_and_child_tracker_outcomes_are_scoped() {
    let receipt = json(ARTIFACT_PATH);
    assert_eq!(receipt["schema_version"], 1);
    assert_eq!(
        receipt["artifact_id"],
        "dependency-ci-provenance-final-signoff-v1"
    );
    assert_eq!(receipt["bead_id"], BEAD_ID);
    assert!(is_full_lower_hex(text(&receipt, "input_head")));
    assert_eq!(receipt["verdict"]["outcome"], "PASS_SCOPED_KEEP_DEFER");
    assert!(boolean(&receipt["verdict"], "all_required_children_closed"));
    assert!(!boolean(&receipt["verdict"], "dependency_exit_allowed"));
    assert!(!boolean(&receipt["verdict"], "cutover_authority"));
    assert!(!boolean(
        &receipt["verdict"],
        "package_manager_execution_authorized"
    ));

    let expected_children = (1..=6)
        .map(|index| format!("asupersync-mnotoo.3.{index}"))
        .collect::<BTreeSet<_>>();
    let actual_children = array(&receipt, "child_outcomes")
        .iter()
        .map(|row| text(row, "bead_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_children, expected_children);

    for child in array(&receipt, "child_outcomes") {
        assert_eq!(child["required_status"], "closed");
        assert!(!text(child, "tracker_close_reason").is_empty());
    }
    let child_map = array(&receipt, "child_outcomes")
        .iter()
        .map(|child| (text(child, "bead_id"), child))
        .collect::<BTreeMap<_, _>>();
    assert!(
        text(
            child_map
                .get("asupersync-mnotoo.3.2")
                .expect("owner decision tracker row"),
            "tracker_close_reason"
        )
        .contains("static inventory only")
    );
    assert!(
        text(
            child_map
                .get("asupersync-mnotoo.3.3")
                .expect("static receipt tracker row"),
            "tracker_close_reason"
        )
        .contains("STATIC_ONLY")
    );
}

#[test]
fn actions_and_static_javascript_receipts_match_live_sources() {
    let receipt = json(ARTIFACT_PATH);
    let actions = json(ACTIONS_PATH);
    let aggregate_actions = &receipt["github_actions_provenance"];
    for field in [
        "workflow_file_count",
        "action_reference_count",
        "distinct_action_repository_count",
        "exception_count",
    ] {
        assert_eq!(aggregate_actions[field], actions["inventory"][field]);
    }
    assert_eq!(
        aggregate_actions["execution_status"],
        "NOT_EXECUTION_EVIDENCE"
    );
    for pin in array(&actions, "pins") {
        assert!(is_full_lower_hex(text(pin, "sha")));
        assert!(!text(pin, "version_comment").is_empty());
    }

    let package = &receipt["javascript_package_tree_decision"];
    assert_eq!(package["decision"], "STATIC_ONLY");
    assert!(!boolean(package, "package_manager_execution_authorized"));
    assert!(!boolean(package, "package_manager_invoked_by_signoff"));
    assert_eq!(number(package, "tracked_package_manifest_count"), 15);
    assert_eq!(
        strings(package, "tracked_package_manifests"),
        discovered_package_manifests()
    );
    assert!(array(package, "tracked_lockfiles").is_empty());
    assert_eq!(package["configured_package_manager"], "pnpm@10.34.3");
    assert_eq!(
        package["workspace_admission"],
        serde_json::json!(["packages/*"])
    );
    assert_eq!(package["lifecycle_policy"]["enable_pre_post_scripts"], true);
    assert_eq!(
        package["lifecycle_policy"]["strict_peer_dependencies"],
        false
    );
    assert_eq!(
        package["lifecycle_policy"]["only_built_dependencies"],
        serde_json::json!(["sharp"])
    );
    assert!(array(package, "unknowns").len() >= 8);
}

#[test]
fn cargo_scanner_graph_consumer_and_generated_doc_receipts_join_children() {
    let receipt = json(ARTIFACT_PATH);
    let supply = json(SUPPLY_PATH);
    let downstream = json(DOWNSTREAM_PATH);
    let budget = json(BUDGET_PATH);
    let scanner = &receipt["fresh_cargo_scanner_receipt"];

    assert_eq!(scanner["outcome"], "PASS");
    assert_eq!(
        scanner["cargo_deny_version"],
        supply["tools"]["cargo_deny"]["version"]
    );
    assert_eq!(
        scanner["cargo_audit_version"],
        supply["tools"]["cargo_audit"]["version"]
    );
    assert!(boolean(&scanner["advisory_database"], "fresh"));
    assert!(
        number(&scanner["advisory_database"], "age_seconds")
            <= number(&scanner["advisory_database"], "maximum_age_seconds")
    );
    for scope in ["root_workspace", "excluded_fuzz_workspace"] {
        assert_eq!(scanner[scope]["status"], "pass");
        assert_eq!(scanner[scope]["cargo_deny_exit"], 0);
        assert_eq!(scanner[scope]["cargo_audit_exit"], 0);
        assert_eq!(scanner[scope]["duplicate_expansion_count"], 0);
    }
    assert_eq!(
        scanner["excluded_fuzz_workspace"]["tokio_quarantine"],
        supply["excluded_fuzz_workspace"]["tokio_quarantine"]["state"]
    );

    let graph = &receipt["cargo_graph_matrix"];
    let expected_profiles = array(&budget, "graph_ceilings")
        .iter()
        .map(|row| text(row, "feature_profile").to_owned())
        .collect::<BTreeSet<_>>();
    let expected_targets = array(&budget, "graph_ceilings")
        .iter()
        .map(|row| text(row, "target_triple").to_owned())
        .collect::<BTreeSet<_>>();
    let expected_hosts = array(&budget, "graph_ceilings")
        .iter()
        .map(|row| text(row, "host_triple").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(string_set(graph, "feature_profiles"), expected_profiles);
    assert_eq!(string_set(graph, "target_triples"), expected_targets);
    assert_eq!(string_set(graph, "host_triples"), expected_hosts);
    assert_eq!(
        graph["root_manifest_sha256"],
        supply["root_workspace"]["manifest_sha256"]
    );
    assert_eq!(
        graph["root_lock_sha256"],
        supply["root_workspace"]["lockfile_sha256"]
    );

    let minimum = &downstream["minimum_version_policy"];
    let aggregate_minimum = &receipt["downstream_minimum_version_receipt"];
    assert_eq!(aggregate_minimum["toolchain"], minimum["toolchain_channel"]);
    assert_eq!(
        aggregate_minimum["resolution_policy"],
        minimum["resolution_policy"]
    );
    assert_eq!(
        aggregate_minimum["tracked_package_count"],
        minimum["tracked_package_count"]
    );
    assert_eq!(
        aggregate_minimum["full_transitive_minimal_status"],
        minimum["transitive_minimal_probe"]["status"]
    );
    assert_eq!(
        aggregate_minimum["blocker_package"],
        minimum["transitive_minimal_probe"]["selected_package"]
    );

    let generated = &receipt["generated_dependency_documentation_receipt"];
    assert_eq!(
        number(generated, "budget_allowed_direct_edge_count") as usize,
        array(&budget, "allowed_direct_dependencies").len()
    );
    assert_eq!(
        number(generated, "generated_row_count") as usize,
        array(&budget["agents_key_dependencies"], "rows").len()
    );
}

#[test]
fn source_contracts_are_content_pinned() {
    let receipt = json(ARTIFACT_PATH);
    let sources = array(&receipt, "source_contracts");
    assert_eq!(sources.len(), 8);
    let mut paths = BTreeSet::new();
    for source in sources {
        let path = text(source, "path");
        assert!(paths.insert(path));
        assert_eq!(
            sha256_file(path),
            text(source, "sha256"),
            "hash drift: {path}"
        );
        assert!(text(source, "owner_bead_id").starts_with("asupersync-mnotoo.3."));
    }
}

#[test]
fn negative_mutations_fail_closed_with_catalogued_errors() {
    let canonical = json(ARTIFACT_PATH);
    assert!(validation_errors(&canonical).is_empty());
    let catalog = array(&canonical, "negative_fixture_catalog")
        .iter()
        .map(|row| (text(row, "fixture_id"), text(row, "expected_error")))
        .collect::<BTreeMap<_, _>>();

    let mut cases = Vec::new();
    let mut child = canonical.clone();
    child["child_outcomes"][0]["required_status"] = Value::String("open".to_owned());
    cases.push(("child-not-closed", child));

    let mut javascript = canonical.clone();
    javascript["javascript_package_tree_decision"]["package_manager_execution_authorized"] =
        Value::Bool(true);
    cases.push(("javascript-execution-authorized", javascript));

    let mut stale = canonical.clone();
    stale["fresh_cargo_scanner_receipt"]["advisory_database"]["age_seconds"] =
        Value::from(604_801_u64);
    cases.push(("stale-advisory-database", stale));

    let mut quarantine = canonical.clone();
    quarantine["fresh_cargo_scanner_receipt"]["excluded_fuzz_workspace"]["tokio_quarantine"] =
        Value::String("removed".to_owned());
    cases.push(("excluded-fuzz-tokio-quarantine-removed", quarantine));

    let mut transitive = canonical.clone();
    transitive["downstream_minimum_version_receipt"]["full_transitive_minimal_status"] =
        Value::String("pass".to_owned());
    cases.push(("transitive-minimal-blocker-erased", transitive));

    let mut generated = canonical.clone();
    generated["generated_dependency_documentation_receipt"]["generated_row_count"] =
        Value::from(13_u64);
    cases.push(("generated-document-row-drift", generated));

    let mut authority = canonical.clone();
    authority["verdict"]["dependency_exit_allowed"] = Value::Bool(true);
    cases.push(("dependency-exit-authorized", authority));

    let mut source = canonical.clone();
    source["source_contracts"][0]["sha256"] = Value::String("0".repeat(64));
    cases.push(("source-contract-hash-drift", source));

    assert_eq!(cases.len(), catalog.len());
    for (fixture_id, mutated) in cases {
        let expected = catalog
            .get(fixture_id)
            .unwrap_or_else(|| panic!("missing catalog row {fixture_id}"));
        assert!(
            validation_errors(&mutated).contains(*expected),
            "{fixture_id} did not fail with {expected}"
        );
    }
}

#[test]
fn proof_mapping_commands_docs_and_no_claims_are_exact() {
    let receipt = json(ARTIFACT_PATH);
    let manifest = json(MANIFEST_PATH);
    let status = json(STATUS_PATH);
    let docs = read(DOC_PATH);
    let readme = read(README_PATH);
    let agents = read(AGENTS_PATH);

    let lane = array(&manifest, "lanes")
        .iter()
        .find(|lane| text(lane, "lane_id") == LANE_ID)
        .expect("aggregate signoff manifest lane");
    assert_eq!(text(lane, "command"), PROOF_COMMAND);
    assert_eq!(
        string_set(lane, "guarantee_ids"),
        BTreeSet::from([LANE_ID.to_owned()])
    );
    let claim = array(&status, "claim_categories")
        .iter()
        .find(|claim| text(claim, "claim_id") == LANE_ID)
        .expect("aggregate signoff status row");
    assert_eq!(claim["status"], "green");
    assert_eq!(claim["proof_evidence_status"], "fresh-rch-pass");
    assert_eq!(
        string_set(claim, "proof_commands"),
        BTreeSet::from([PROOF_COMMAND.to_owned()])
    );
    assert_eq!(
        receipt["canonical_commands"]["focused_signoff"],
        PROOF_COMMAND
    );
    for marker in [
        "PASS_SCOPED_KEEP_DEFER",
        "STATIC_ONLY_EXECUTABLE_AUDIT_DEFERRED",
        "bf5c0d245a92671908518d7e765914d437954ed6",
        "curve25519-dalek 4.0.0",
        "dependency-ci-provenance-final-signoff",
        "No-claim boundaries",
    ] {
        assert!(docs.contains(marker), "runbook missing {marker}");
    }
    for marker in [
        "Dependency CI/provenance final signoff",
        "dependency-ci-provenance-final-signoff",
    ] {
        assert!(readme.contains(marker), "README missing {marker}");
    }
    for marker in [
        "dependency CI/provenance final signoff",
        "dependency-ci-provenance-final-signoff",
    ] {
        assert!(agents.contains(marker), "AGENTS missing {marker}");
    }
    let no_claims = strings(&receipt, "no_claim_boundaries").join(" ");
    for marker in [
        "not a release-readiness",
        "STATIC_ONLY",
        "undisclosed vulnerabilities",
        "full transitive-minimal",
        "automatic local rewrite",
        "does not authorize dependency removal",
        "package-manager execution",
        "file deletion",
        "local Cargo fallback",
    ] {
        assert!(
            no_claims.contains(marker),
            "no-claim boundary missing {marker}"
        );
    }
}
