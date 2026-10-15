#![allow(clippy::nursery, clippy::pedantic, missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

const ARTIFACT_PATH: &str = "artifacts/lz4_final_signoff_v1.json";
const A1_ARTIFACT_PATH: &str = "artifacts/lz4_surface_artifact_inventory_v1.json";
const A3_ARTIFACT_PATH: &str = "artifacts/lz4_owned_codec_corpus_v1.json";
const A4_ARTIFACT_PATH: &str = "artifacts/lz4_trace_integration_go_no_go_v1.json";
const REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const BASELINE_PATH: &str = "artifacts/dependency_capability_baseline_v1.json";
const CUTOVER_PATH: &str = "artifacts/dependency_cutover_policy_v1.json";
const TRACKER_PATH: &str = ".beads/issues.jsonl";
const MANIFEST_PATH: &str = "Cargo.toml";
const LOCK_PATH: &str = "Cargo.lock";
const TRACE_SOURCE_PATH: &str = "src/trace/file.rs";
const RUNNER_PATH: &str = "scripts/run_dependency_sovereignty_e2e.sh";
const DOC_PATH: &str = "docs/lz4_final_signoff.md";
const A1_DOC_PATH: &str = "docs/lz4_surface_artifact_inventory.md";
const BEAD_ID: &str = "asupersync-0h6myr.4.5";
const EPIC_ID: &str = "asupersync-0h6myr.4";
const CAPABILITY_ID: &str = "CAP-TRACE-LZ4";
const SCENARIO_ID: &str = "dep-sovereignty-asupersync_0h6myr_4_5_04aaef97c5dd";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_bytes(relative: &str) -> Vec<u8> {
    std::fs::read(repo_path(relative)).unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn read_repo_file(relative: &str) -> String {
    String::from_utf8(read_repo_bytes(relative))
        .unwrap_or_else(|error| panic!("{relative} must be UTF-8: {error}"))
}

fn json(relative: &str) -> Value {
    serde_json::from_slice(&read_repo_bytes(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(|| panic!("{key} must be an array"), Vec::as_slice)
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|entry| !entry.trim().is_empty())
        .unwrap_or_else(|| panic!("{key} must be a non-empty string"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .filter(|item| !item.trim().is_empty())
                .unwrap_or_else(|| panic!("{key} entries must be non-empty strings"))
                .to_owned()
        })
        .collect()
}

fn find_by<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn count(source: &str, needle: &str) -> usize {
    source.match_indices(needle).count()
}

fn tracker_issues() -> BTreeMap<String, Value> {
    let mut issues = BTreeMap::new();
    for (line_number, line) in read_repo_file(TRACKER_PATH).lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let issue: Value = serde_json::from_str(line).unwrap_or_else(|error| {
            panic!("parse {TRACKER_PATH} line {}: {error}", line_number + 1)
        });
        let id = text(&issue, "id").to_owned();
        assert!(
            issues.insert(id.clone(), issue).is_none(),
            "duplicate tracker issue {id}"
        );
    }
    issues
}

fn blocking_dependency_ids(issue: &Value) -> BTreeSet<String> {
    array(issue, "dependencies")
        .iter()
        .filter(|dependency| dependency["type"] == "blocks")
        .map(|dependency| text(dependency, "depends_on_id").to_owned())
        .collect()
}

fn package(lock: &str, name: &str) -> BTreeMap<String, String> {
    lock.split("[[package]]")
        .find_map(|section| {
            let fields = section
                .lines()
                .filter_map(|line| line.split_once(" = "))
                .map(|(key, value)| {
                    (
                        key.trim().to_owned(),
                        value.trim().trim_matches('"').to_owned(),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            (fields.get("name").map(String::as_str) == Some(name)).then_some(fields)
        })
        .unwrap_or_else(|| panic!("missing Cargo.lock package {name}"))
}

fn validate_terminal_packet(packet: &Value) -> Result<(), String> {
    if packet["artifact_id"] != "lz4-final-signoff-v1"
        || packet["bead_id"] != BEAD_ID
        || packet["epic_id"] != EPIC_ID
        || packet["capability_id"] != CAPABILITY_ID
    {
        return Err("terminal packet identity drift".to_owned());
    }

    let verdict = &packet["terminal_verdict"];
    if verdict["outcome"] != "KEEP_INCUMBENT_NO_CUTOVER"
        || verdict["terminal_receipt"] != true
        || verdict["dependency_exit_allowed"] != false
        || verdict["production_cutover_authorized"] != false
        || verdict["production_default_changed"] != false
        || verdict["production_manifest_changed"] != false
        || verdict["public_surface_narrowing_allowed"] != false
        || verdict["persisted_format_changed"] != false
        || verdict["oracle_retirement_allowed"] != false
        || verdict["partial_switch_allowed"] != false
    {
        return Err("terminal verdict is not fail-closed KEEP".to_owned());
    }

    let expected_children = BTreeSet::from([
        "asupersync-0h6myr.4.1".to_owned(),
        "asupersync-0h6myr.4.2".to_owned(),
        "asupersync-0h6myr.4.3".to_owned(),
        "asupersync-0h6myr.4.4".to_owned(),
        "asupersync-5z2scg.3.7".to_owned(),
    ]);
    let children = array(packet, "child_receipts")
        .iter()
        .map(|receipt| text(receipt, "bead_id").to_owned())
        .collect::<BTreeSet<_>>();
    if children != expected_children {
        return Err("terminal child receipt set drift".to_owned());
    }

    let expected_gaps = BTreeMap::from([
        ("LZ4-GAP-01", "KEEP_BLOCKER"),
        ("LZ4-GAP-02", "KEEP_BLOCKER"),
        ("LZ4-GAP-03", "KEEP_BLOCKER"),
        ("LZ4-GAP-04", "RESOLVED_FORMAT_FREEZE"),
        ("LZ4-GAP-05", "RESOLVED_A3_SUCCESSOR_EVIDENCE"),
        ("LZ4-GAP-06", "RESOLVED_CURRENT_VERSION_PIN"),
        ("LZ4-GAP-07", "RESOLVED_RETAINED_CORPUS"),
        ("LZ4-GAP-08", "RESOLVED_CANONICAL_SCENARIOS"),
        ("LZ4-GAP-09", "KEEP_BLOCKER"),
        ("LZ4-GAP-10", "KEEP_BLOCKER_OUTSIDE_CAPABILITY"),
        ("LZ4-GAP-11", "KEEP_BLOCKER_OUTSIDE_CAPABILITY"),
    ]);
    let gaps = array(packet, "gap_disposition")
        .iter()
        .map(|row| (text(row, "gap_id"), text(row, "disposition")))
        .collect::<BTreeMap<_, _>>();
    if gaps != expected_gaps {
        return Err("terminal gap disposition drift".to_owned());
    }

    let performance = &packet["performance_gate"];
    if performance["accepted_for_cutover"] != false
        || performance["disposition"] != "FAIL_CUTOVER_KEEP_INCUMBENT"
        || performance["owned_encode_time_delta_percent"] != 50.292
        || performance["owned_decode_time_delta_percent"] != 105.505
    {
        return Err("performance gate was not preserved as a KEEP blocker".to_owned());
    }

    let graph = &packet["dependency_graph_disposition"];
    if graph["normal_edge"] != "KEEP"
        || graph["dev_edge"] != "KEEP"
        || graph["fuzz_edge"] != "KEEP"
        || graph["dependency_exit_allowed"] != false
        || graph["atp_production_call_sites"] != 5
    {
        return Err("dependency graph disposition is not complete KEEP".to_owned());
    }

    let oracle = &packet["oracle_disposition"];
    if oracle["disposition"] != "KEEP_INCUMBENT_ORACLE"
        || oracle["retirement_allowed"] != false
        || oracle["replacement_grade_independent_oracle_available"] != false
    {
        return Err("oracle retirement was silently authorized".to_owned());
    }

    if packet["canonical_scenario"]["scenario_id"] != SCENARIO_ID
        || packet["canonical_scenario"]["expected_outcome"] != "PASSED"
    {
        return Err("canonical terminal scenario drift".to_owned());
    }

    if array(packet, "no_claim_boundaries").len() < 8 {
        return Err("terminal no-claim boundary is incomplete".to_owned());
    }
    Ok(())
}

#[test]
fn terminal_identity_child_closure_and_dependency_edges_are_exact() {
    let packet = json(ARTIFACT_PATH);
    validate_terminal_packet(&packet).expect("valid terminal packet");
    assert_eq!(packet["schema_version"], 1);
    assert_eq!(packet["program_id"], "asupersync-ir2uf0");

    let issues = tracker_issues();
    for receipt in array(&packet, "child_receipts") {
        let bead_id = text(receipt, "bead_id");
        assert_eq!(text(receipt, "required_status"), "closed");
        assert_eq!(
            issues
                .get(bead_id)
                .unwrap_or_else(|| panic!("missing child {bead_id}"))["status"],
            "closed",
            "{bead_id} must remain closed"
        );
        assert!(!array(receipt, "content_commits").is_empty());
        text(receipt, "role");
    }

    assert_eq!(
        blocking_dependency_ids(issues.get(BEAD_ID).expect("A5 tracker row")),
        BTreeSet::from([
            "asupersync-0h6myr.4.4".to_owned(),
            "asupersync-5z2scg.3.7".to_owned(),
        ])
    );
    for dependent in [
        "asupersync-0h6myr.7",
        "asupersync-dep-p7-kafka-removal-sarszu.2.4.4",
    ] {
        assert!(
            blocking_dependency_ids(
                issues
                    .get(dependent)
                    .unwrap_or_else(|| panic!("missing dependent {dependent}"))
            )
            .contains(BEAD_ID),
            "{dependent} must remain downstream of terminal LZ4 A5"
        );
    }
}

#[test]
fn every_terminal_source_contract_is_content_pinned() {
    let packet = json(ARTIFACT_PATH);
    let contracts = array(&packet, "source_contracts");
    assert_eq!(contracts.len(), 19);

    let mut paths = BTreeSet::new();
    for contract in contracts {
        let path = text(contract, "path");
        assert!(paths.insert(path), "duplicate source contract {path}");
        let expected = text(contract, "sha256");
        assert_eq!(expected.len(), 64, "{path} must use SHA-256");
        assert_eq!(
            sha256_hex(&read_repo_bytes(path)),
            expected,
            "{path} drifted after A5 aggregation"
        );
        text(contract, "role");
    }
}

#[test]
fn a1_through_a4_evidence_reconciles_without_promotion() {
    let packet = json(ARTIFACT_PATH);
    let a1 = json(A1_ARTIFACT_PATH);
    let a3 = json(A3_ARTIFACT_PATH);
    let a4 = json(A4_ARTIFACT_PATH);

    assert_eq!(a1["artifact_id"], "lz4-surface-artifact-inventory-v1");
    assert_eq!(a1["policy"]["unknown_rows"], 0);
    assert_eq!(a1["authority"]["registry_disposition"], "KEEP_UNTIL_PARITY");
    assert_eq!(a1["authority"]["registry_cutover_state"], "KEEP_INCUMBENT");
    assert_eq!(array(&a1, "observed_semantic_gaps").len(), 11);

    assert_eq!(a3["artifact_id"], "lz4-owned-codec-corpus-v1");
    assert_eq!(array(&a3, "valid_vectors").len(), 6);
    assert_eq!(array(&a3, "malformed_vectors").len(), 17);
    assert_eq!(array(&a3, "budget_vectors").len(), 4);
    assert_eq!(a3["property_contract"]["cases"], 256);
    assert_eq!(a3["fuzz_contract"]["incumbent_resolved"], "0.14.0");
    assert_eq!(a3["fuzz_contract"]["execution_receipt"]["exit_code"], 0);
    assert_eq!(
        a3["baseline_evidence_disposition"]["historical_state"],
        "SEMANTIC_FILTERING_ONLY"
    );

    assert_eq!(a4["artifact_id"], "lz4-trace-integration-go-no-go-v1");
    assert_eq!(a4["decision"]["verdict"], "KEEP_INCUMBENT");
    assert_eq!(a4["decision"]["production_default_changed"], false);
    assert_eq!(a4["decision"]["dependency_removal_authorized"], false);
    assert_eq!(array(&a4, "canonical_scenarios").len(), 3);
    assert!(
        array(&a4["decision"], "blockers").len() >= 6,
        "A4 KEEP blockers must not be dropped"
    );

    let join = array(&packet, "evidence_join");
    assert_eq!(join.len(), 5);
    for row in join {
        assert_eq!(text(row, "admission"), "ADMITTED_FOR_TERMINAL_KEEP");
        text(row, "scope");
        text(row, "no_claim_boundary");
    }
}

#[test]
fn live_registry_policy_manifest_lock_and_defaults_remain_keep() {
    let packet = json(ARTIFACT_PATH);
    let registry = json(REGISTRY_PATH);
    let baseline = json(BASELINE_PATH);
    let cutover = json(CUTOVER_PATH);

    let capability = find_by(
        array(&registry, "capabilities"),
        "capability_id",
        CAPABILITY_ID,
    );
    assert_eq!(capability["disposition"], "KEEP_UNTIL_PARITY");
    assert_eq!(capability["cutover_state"], "KEEP_INCUMBENT");
    assert_eq!(capability["evidence_state"], "BASELINE_PLANNED");
    assert_eq!(
        string_set(capability, "scenario_ids"),
        BTreeSet::from([
            "lz4_cross_version_artifact".to_owned(),
            "lz4_malformed_limits".to_owned(),
            "lz4_trace_replay".to_owned(),
        ])
    );

    let baseline_row = find_by(
        array(&baseline, "capability_baselines"),
        "capability_id",
        CAPABILITY_ID,
    );
    assert_eq!(baseline_row["cutover_eligible"], false);
    assert_eq!(baseline_row["baseline_state"], "EXECUTABLE_COMPLETE");

    let binding = find_by(
        array(&cutover, "capability_bindings"),
        "capability_id",
        CAPABILITY_ID,
    );
    assert_eq!(binding["registry_cutover_state"], "KEEP_INCUMBENT");
    assert_eq!(binding["dependency_exit_allowed"], false);
    assert_eq!(binding["migration_class"], "VERSIONED_DATA");

    let manifest = read_repo_file(MANIFEST_PATH);
    for marker in [
        "trace-compression = [\"dep:lz4_flex\"]",
        "lz4_flex = { version = \"0.14\", optional = true }",
        "lz4_flex = \"0.14\"",
    ] {
        assert!(manifest.contains(marker), "manifest lost {marker}");
    }
    let lock = package(&read_repo_file(LOCK_PATH), "lz4_flex");
    assert_eq!(lock.get("version").map(String::as_str), Some("0.14.0"));
    assert_eq!(
        lock.get("checksum").map(String::as_str),
        Some("ecbdfe44b1bd960b68170b417450a628c43f7cf56bb3c5317e61cb230ee7f226")
    );

    let source = read_repo_file(TRACE_SOURCE_PATH);
    for marker in [
        "Self::from_file_with_lz4_codec(file, config, Lz4Codec::Incumbent)",
        "Self::open_with_lz4_codec(path, Lz4Codec::Incumbent)",
        "migrate_trace_file_with_lz4_codec(input, output, Lz4Codec::Incumbent)",
        "#[cfg(all(feature = \"trace-compression\", feature = \"test-internals\"))]",
    ] {
        assert!(
            source.contains(marker),
            "production/default guard missing: {marker}"
        );
    }
    assert_eq!(
        packet["terminal_verdict"]["production_manifest_changed"],
        false
    );
    assert_eq!(
        packet["terminal_verdict"]["production_default_changed"],
        false
    );
}

#[test]
fn graph_oracle_format_gap_and_rollback_boundaries_are_explicit() {
    let packet = json(ARTIFACT_PATH);
    let graph = &packet["dependency_graph_disposition"];
    assert_eq!(graph["normal_edge"], "KEEP");
    assert_eq!(graph["dev_edge"], "KEEP");
    assert_eq!(graph["fuzz_edge"], "KEEP");
    assert_eq!(graph["root_locked_version"], "0.14.0");
    assert_eq!(graph["fuzz_requirement"], "=0.14.0");
    assert_eq!(graph["dependency_exit_allowed"], false);
    assert_eq!(graph["atp_production_call_sites"], 5);

    let trace = read_repo_file(TRACE_SOURCE_PATH);
    assert_eq!(count(&trace, "lz4_flex::compress_prepend_size"), 3);
    assert_eq!(count(&trace, "lz4_flex::decompress_size_prepended"), 1);
    assert_eq!(
        count(
            &read_repo_file("src/net/atp/compress/mod.rs"),
            "lz4_flex::compress_prepend_size"
        ),
        2
    );
    assert_eq!(
        count(
            &read_repo_file("src/net/atp/compress/mod.rs"),
            "lz4_flex::decompress_size_prepended"
        ),
        1
    );
    assert_eq!(
        count(
            &read_repo_file("src/net/atp/compress/algorithms.rs"),
            "lz4_flex::compress_prepend_size"
        ),
        1
    );
    assert_eq!(
        count(
            &read_repo_file("src/net/atp/compress/algorithms.rs"),
            "lz4_flex::decompress_size_prepended"
        ),
        1
    );
    assert_eq!(
        count(
            &read_repo_file("src/atp/manifest.rs"),
            "lz4_flex::compress_prepend_size"
        ),
        1
    );

    let format = &packet["format_and_public_surface"];
    assert_eq!(format["container"], "LZ4_SIZE_PREPENDED_BLOCK");
    assert_eq!(format["persisted_format_changed"], false);
    assert_eq!(format["frame_format_supported"], false);
    assert_eq!(format["dictionary_supported"], false);
    assert_eq!(format["block_checksum_supported"], false);
    assert_eq!(format["content_checksum_supported"], false);
    assert_eq!(format["public_compression_modes_preserved"], true);

    let rollback = &packet["rollback_contract"];
    assert_eq!(rollback["manifest_rollback_required"], false);
    assert_eq!(rollback["artifact_migration_required"], false);
    assert_eq!(rollback["incumbent_artifacts_remain_readable"], true);
    assert_eq!(rollback["owned_shadow_removal_is_independent"], true);
    text(rollback, "future_go_requirement");

    validate_terminal_packet(&packet).expect("positive terminal packet");
}

#[test]
fn canonical_runner_and_documentation_are_discoverable() {
    let packet = json(ARTIFACT_PATH);
    let runner = read_repo_file(RUNNER_PATH);
    let doc = read_repo_file(DOC_PATH);
    let a1_doc = read_repo_file(A1_DOC_PATH);

    assert_eq!(packet["canonical_scenario"]["scenario_id"], SCENARIO_ID);
    for marker in [
        SCENARIO_ID,
        "--no-default-features --features trace-compression",
        "--test lz4_surface_artifact_inventory_contract",
        "--test lz4_owned_codec_corpus_contract",
        "--test lz4_trace_integration_e2e",
        "--test lz4_final_signoff_contract",
    ] {
        assert!(runner.contains(marker), "runner lacks A5 marker {marker}");
    }
    for marker in [
        "KEEP_INCUMBENT_NO_CUTOVER",
        "50.292%",
        "105.505%",
        "KEEP_INCUMBENT_ORACLE",
        SCENARIO_ID,
        "No-claim boundary",
    ] {
        assert!(doc.contains(marker), "terminal doc lacks marker {marker}");
    }
    for marker in [
        "## A5 terminal decision",
        "lz4_final_signoff.md",
        "KEEP_INCUMBENT_NO_CUTOVER",
    ] {
        assert!(a1_doc.contains(marker), "A1 doc lacks A5 marker {marker}");
    }
}

#[test]
fn malformed_terminal_packets_fail_closed() {
    let packet = json(ARTIFACT_PATH);
    validate_terminal_packet(&packet).expect("positive terminal packet");

    let mutations: Vec<(&str, Box<dyn Fn(&mut Value)>)> = vec![
        (
            "dependency exit",
            Box::new(|value| value["terminal_verdict"]["dependency_exit_allowed"] = true.into()),
        ),
        (
            "production cutover",
            Box::new(|value| {
                value["terminal_verdict"]["production_cutover_authorized"] = true.into();
            }),
        ),
        (
            "drop child",
            Box::new(|value| {
                value["child_receipts"]
                    .as_array_mut()
                    .expect("child receipts")
                    .pop();
            }),
        ),
        (
            "accept performance",
            Box::new(|value| value["performance_gate"]["accepted_for_cutover"] = true.into()),
        ),
        (
            "resolve public level",
            Box::new(|value| {
                value["gap_disposition"][0]["disposition"] = "RESOLVED".into();
            }),
        ),
        (
            "remove ATP graph edge",
            Box::new(|value| {
                value["dependency_graph_disposition"]["atp_production_call_sites"] = 0.into()
            }),
        ),
        (
            "retire oracle",
            Box::new(|value| value["oracle_disposition"]["retirement_allowed"] = true.into()),
        ),
        (
            "remove no-claim boundaries",
            Box::new(|value| value["no_claim_boundaries"] = Value::Array(Vec::new())),
        ),
    ];

    for (name, mutation) in mutations {
        let mut invalid = packet.clone();
        mutation(&mut invalid);
        assert!(
            validate_terminal_packet(&invalid).is_err(),
            "{name} mutation must fail closed"
        );
    }
}
