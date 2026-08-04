//! Fail-closed contract for the XATTR boundary inventory and terminal gate.
//!
//! Bead: asupersync-3u3tej.3.1
//! Artifact: artifacts/xattr_boundary_inventory_v1.json
//!
//! This contract proves the claim-time call/API/platform inventory, canonical
//! marginal-graph interpretation, source pins, routed evidence gaps, and a
//! terminal `DEFER` decision. It does not prove replacement parity, broad
//! workspace health, runtime behavior on every target, or permission to
//! modify the incumbent dependency.

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const ARTIFACT_PATH: &str = "artifacts/xattr_boundary_inventory_v1.json";
const DOC_PATH: &str = "docs/xattr_boundary_inventory.md";
const REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const BASELINE_PATH: &str = "artifacts/dependency_capability_baseline_v1.json";
const MARGINAL_LEDGER_PATH: &str = "artifacts/dependency_marginal_ledger_v1.json";
const API_SURFACE_PATH: &str = "artifacts/api_surface_map_v1.json";
const RUNNER_PATH: &str = "scripts/run_dependency_sovereignty_e2e.sh";
const METADATA_SOURCE_PATH: &str = "src/net/atp/transport_common/metadata.rs";
const POLICY_SOURCE_PATH: &str = "src/atp/object.rs";
const CLI_SOURCE_PATH: &str = "src/bin/atp.rs";
const E2E_SOURCE_PATH: &str = "tests/atp_tcp_metadata_fidelity.rs";
const BEAD_ID: &str = "asupersync-3u3tej.3.1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const CAPABILITY_ID: &str = "CAP-XATTR";
const BASELINE_REVISION: &str = "e958dadee7b692faaf51bee42352d4bc6e7738ef";
const DIRECT_EDGE: &str = "target-normal:cfg(unix):xattr";
const DOC_BEGIN: &str = "<!-- BEGIN XATTR BOUNDARY INVENTORY -->";
const DOC_END: &str = "<!-- END XATTR BOUNDARY INVENTORY -->";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn read_repo_bytes(path: &str) -> Vec<u8> {
    std::fs::read(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn parse_repo_json(path: &str) -> Value {
    serde_json::from_str(&read_repo_file(path))
        .unwrap_or_else(|error| panic!("{path} must be valid JSON: {error}"))
}

fn artifact() -> Value {
    parse_repo_json(ARTIFACT_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn find_row<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
}

fn row_ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
}

fn string_set(values: &[Value]) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("array entry must be a string"))
                .to_owned()
        })
        .collect()
}

fn validate_no_unknown(value: &Value, path: &str) -> Result<(), String> {
    match value {
        Value::String(state) if state == "UNKNOWN" => {
            return Err(format!("{path} must not be UNKNOWN"));
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_no_unknown(child, &format!("{path}[{index}]"))?;
            }
        }
        Value::Object(values) => {
            for (key, child) in values {
                validate_no_unknown(child, &format!("{path}.{key}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_inventory(inventory: &Value) -> Result<(), String> {
    if inventory.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("schema_version must be 1".to_owned());
    }
    for (key, expected) in [
        ("artifact_id", "xattr-boundary-inventory-v1"),
        ("program_id", PROGRAM_ID),
        ("bead_id", BEAD_ID),
        ("capability_id", CAPABILITY_ID),
        ("baseline_revision", BASELINE_REVISION),
    ] {
        if inventory.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("{key} must be {expected}"));
        }
    }

    let authority = object(inventory, "authority");
    for (key, expected) in [
        ("registry_disposition", "KEEP_UNTIL_PARITY"),
        ("registry_evidence_state", "BASELINE_PLANNED"),
        ("registry_cutover_state", "KEEP_INCUMBENT"),
        ("gate_decision", "DEFER"),
        ("gate_state", "TERMINAL"),
    ] {
        if authority.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("authority.{key} must be {expected}"));
        }
    }
    for key in [
        "dependency_exit_allowed",
        "implementation_children_authorized",
    ] {
        if authority.get(key).and_then(Value::as_bool) != Some(false) {
            return Err(format!("authority.{key} must remain false"));
        }
    }
    if authority
        .get("owner_review_required_to_change")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("the terminal gate must require owner review to change".to_owned());
    }

    let policy = object(inventory, "policy");
    if policy.get("zero_unknown_required").and_then(Value::as_bool) != Some(true)
        || policy.get("unknown_rows").and_then(Value::as_u64) != Some(0)
        || policy.get("inventory_state").and_then(Value::as_str)
            != Some("BASELINED_WITH_ROUTED_GAPS")
        || policy.get("evidence_state").and_then(Value::as_str) != Some("MEASURED_TERMINAL_DEFER")
        || policy
            .get("missing_evidence_is_parity")
            .and_then(Value::as_bool)
            != Some(false)
        || policy
            .get("source_changes_authorized")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("policy must remain fail-closed and terminal DEFER".to_owned());
    }
    validate_no_unknown(inventory, "$")?;

    for (key, count, id_key) in [
        ("occurrence_census", 7, "occurrence_id"),
        ("call_inventory", 7, "call_id"),
        ("public_and_operator_surfaces", 6, "surface_id"),
        ("semantic_matrix", 14, "semantic_id"),
        ("error_matrix", 7, "error_id"),
        ("platform_matrix", 6, "platform_id"),
        ("journey_inventory", 8, "journey_id"),
        ("gaps", 13, "gap_id"),
        ("reconsideration_triggers", 5, "trigger_id"),
    ] {
        let rows = array(inventory, key);
        if rows.len() != count || row_ids(rows, id_key).len() != count {
            return Err(format!("{key} must contain {count} unique rows"));
        }
    }

    let calls = array(inventory, "call_inventory");
    if calls
        .iter()
        .filter(|call| text(call, "scope") == "production")
        .count()
        != 5
        || calls
            .iter()
            .filter(|call| text(call, "scope") == "test")
            .count()
            != 2
    {
        return Err("call inventory must retain five production and two test calls".to_owned());
    }
    for call_id in ["XATTR-CALL-PROD-LIST-DEREF", "XATTR-CALL-PROD-GET-DEREF"] {
        if find_row(calls, "call_id", call_id)
            .get("currently_reachable")
            .and_then(Value::as_bool)
            != Some(false)
        {
            return Err(format!("{call_id} must remain recorded as unreachable"));
        }
    }

    let expected_gaps: BTreeSet<String> = (1..=13)
        .map(|suffix| format!("XATTR-A1-GAP-{suffix:02}"))
        .collect();
    let gaps = array(inventory, "gaps");
    if row_ids(gaps, "gap_id") != expected_gaps {
        return Err("gap inventory must retain XATTR-A1-GAP-01..13".to_owned());
    }
    for gap in gaps {
        if text(gap, "state") != "ROUTED"
            || text(gap, "owner").is_empty()
            || gap.get("replacement_required").and_then(Value::as_bool) != Some(false)
        {
            return Err(format!(
                "{} must remain routed without requiring replacement",
                text(gap, "gap_id")
            ));
        }
    }

    let graph = object(inventory, "marginal_graph");
    if graph.get("measurement_cells").and_then(Value::as_u64) != Some(26)
        || graph
            .get("rustix_present_in_active_baselines")
            .and_then(Value::as_u64)
            != Some(26)
        || graph
            .get("rustix_removed_by_xattr_counterfactual")
            .and_then(Value::as_u64)
            != Some(0)
        || graph
            .get("rustix_retained_after_xattr_counterfactual")
            .and_then(Value::as_u64)
            != Some(26)
        || graph.get("last_rustix_parent").and_then(Value::as_bool) != Some(false)
        || graph.get("measured_graph_benefit").and_then(Value::as_str) != Some("MINIMAL")
    {
        return Err("marginal graph decision receipt drifted".to_owned());
    }

    let decision = object(inventory, "decision");
    if decision.get("outcome").and_then(Value::as_str) != Some("DEFER")
        || decision.get("terminal_for_bead").and_then(Value::as_bool) != Some(true)
        || decision.get("dependency_retained").and_then(Value::as_str) != Some("xattr")
        || decision
            .get("implementation_authority")
            .and_then(Value::as_str)
            != Some("NONE")
        || decision
            .get("implementation_children_authorized")
            .and_then(Value::as_bool)
            != Some(false)
        || decision
            .get("children_unblocked")
            .and_then(Value::as_array)
            .is_none_or(|children| !children.is_empty())
    {
        return Err("decision must be terminal DEFER with no implementation authority".to_owned());
    }
    if array(inventory, "no_claim_boundaries").len() != 10 {
        return Err("ten no-claim boundaries are required".to_owned());
    }

    Ok(())
}

#[test]
fn inventory_is_source_pinned_complete_and_zero_unknown() {
    let inventory = artifact();
    validate_inventory(&inventory).unwrap_or_else(|error| panic!("{error}"));

    for pin in array(&inventory, "source_pins") {
        let path = text(pin, "path");
        let bytes = read_repo_bytes(path);
        let digest = hex::encode(Sha256::digest(&bytes));
        assert_eq!(digest, text(pin, "sha256"), "{path} source pin drifted");
        let line_count =
            u64::try_from(read_repo_file(path).lines().count()).expect("line count fits u64");
        assert_eq!(
            pin.get("line_count").and_then(Value::as_u64),
            Some(line_count),
            "{path} line count drifted"
        );
    }
}

#[test]
fn registry_baseline_and_runner_preserve_missing_evidence() {
    let registry = parse_repo_json(REGISTRY_PATH);
    let capability = find_row(
        array(&registry, "capabilities"),
        "capability_id",
        CAPABILITY_ID,
    );
    assert_eq!(text(capability, "disposition"), "KEEP_UNTIL_PARITY");
    assert_eq!(text(capability, "evidence_state"), "BASELINE_PLANNED");
    assert_eq!(text(capability, "cutover_state"), "KEEP_INCUMBENT");
    assert_eq!(capability["baseline"]["state"], "planned");

    let baseline = parse_repo_json(BASELINE_PATH);
    let baseline_row = find_row(
        array(&baseline, "capability_baselines"),
        "capability_id",
        CAPABILITY_ID,
    );
    assert_eq!(text(baseline_row, "baseline_state"), "BLOCKED_PLATFORM");
    assert_eq!(baseline_row["cutover_eligible"], false);
    assert_eq!(
        string_set(array(baseline_row, "scenario_ids")),
        [
            "xattr_atp_transfer",
            "xattr_follow_nofollow",
            "xattr_permission_size_race",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    let evidence = find_row(
        array(&baseline, "evidence_catalog"),
        "evidence_id",
        "EVD-XATTR-ATP",
    );
    assert_eq!(array(evidence, "fixture_paths").len(), 1);
    assert_eq!(array(evidence, "case_classes").len(), 6);

    let runner = read_repo_file(RUNNER_PATH);
    for absent_scenario in [
        "xattr_follow_nofollow",
        "xattr_atp_transfer",
        "xattr_permission_size_race",
    ] {
        assert!(
            !runner.contains(absent_scenario),
            "{absent_scenario} is recorded as absent; update the inventory when implemented"
        );
    }
    assert!(
        !read_repo_file(API_SURFACE_PATH).contains(CAPABILITY_ID),
        "the inventory records CAP-XATTR as absent from the API surface map"
    );
}

#[test]
fn marginal_graph_proves_xattr_is_not_the_last_rustix_parent() {
    let ledger = parse_repo_json(MARGINAL_LEDGER_PATH);
    let rows: Vec<&Value> = array(&ledger, "marginal_measurements")
        .iter()
        .filter(|row| row.get("direct_root_edge").and_then(Value::as_str) == Some(DIRECT_EDGE))
        .collect();
    assert_eq!(rows.len(), 26);

    let expected_profiles: BTreeSet<String> = [
        "cli",
        "compression",
        "default",
        "fuzz-quarantine",
        "io-uring",
        "kafka",
        "loom-tests",
        "metrics",
        "minimal",
        "sqlite",
        "tls",
        "trace-compression",
        "workspace-dev-build-audit",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(
        rows.iter()
            .map(|row| text(row, "feature_profile").to_owned())
            .collect::<BTreeSet<_>>(),
        expected_profiles
    );
    assert_eq!(
        rows.iter()
            .map(|row| text(row, "target_triple").to_owned())
            .collect::<BTreeSet<_>>(),
        ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    assert_eq!(
        rows.iter()
            .map(|row| text(row, "host_triple").to_owned())
            .collect::<BTreeSet<_>>(),
        std::iter::once("x86_64-unknown-linux-gnu")
            .map(str::to_owned)
            .collect()
    );

    for row in rows {
        assert_eq!(row["marginal_package_version_count"], 1);
        assert_eq!(
            string_set(array(row, "marginal_unique_package_names")),
            std::iter::once("xattr").map(str::to_owned).collect()
        );
        let marginal_versions = array(row, "marginal_package_versions");
        assert_eq!(marginal_versions.len(), 1);
        assert!(
            marginal_versions[0]
                .as_str()
                .is_some_and(|package| package.ends_with("#xattr@1.6.1"))
        );
        assert!(array(row, "build_scripts").is_empty());
        assert!(array(row, "proc_macros").is_empty());
        assert_eq!(row["marginal_native_code"]["status"], "none");
        assert_eq!(row["root_native_code"]["status"], "unknown");
        assert!(
            array(&row["root_native_code"], "packages")
                .iter()
                .any(|package| text(package, "package_id").contains("#rustix@1.1.4")),
            "rustix must be present in every active baseline"
        );
        let taxonomy = array(row, "taxonomy_refs");
        assert_eq!(taxonomy.len(), 1);
        assert_eq!(text(&taxonomy[0], "candidate_id"), "extended-attributes");
        assert_eq!(text(&taxonomy[0], "class_id"), "BOUNDARY-UNSAFE");
        assert_eq!(text(&taxonomy[0], "program_verdict"), "OWN_DEFERRED");
    }

    let mut active_by_target = BTreeMap::<String, usize>::new();
    let mut inactive_by_target = BTreeMap::<String, usize>::new();
    for record in array(&ledger, "graph_records") {
        let target = text(record, "target_triple").to_owned();
        let active = array(record, "active_direct_root_edges")
            .iter()
            .any(|edge| edge.as_str() == Some(DIRECT_EDGE));
        let absent = array(record, "absent_direct_root_edges")
            .iter()
            .any(|edge| edge.as_str() == Some(DIRECT_EDGE));
        assert_ne!(active, absent, "xattr edge must be active or absent");
        let counts = if active {
            &mut active_by_target
        } else {
            &mut inactive_by_target
        };
        *counts.entry(target).or_default() += 1;
    }
    assert_eq!(
        active_by_target,
        BTreeMap::from([
            ("aarch64-apple-darwin".to_owned(), 13),
            ("x86_64-unknown-linux-gnu".to_owned(), 13),
        ])
    );
    assert_eq!(
        inactive_by_target,
        BTreeMap::from([
            ("wasm32-unknown-unknown".to_owned(), 13),
            ("x86_64-pc-windows-msvc".to_owned(), 13),
        ])
    );

    let lock = read_repo_file("Cargo.lock");
    for marker in [
        "name = \"xattr\"\nversion = \"1.6.1\"",
        "name = \"rustix\"\nversion = \"1.1.4\"",
        "name = \"polling\"\nversion = \"3.11.0\"",
        "name = \"tempfile\"\nversion = \"3.27.0\"",
    ] {
        assert!(lock.contains(marker), "lockfile must retain {marker}");
    }
}

#[test]
fn source_topology_matches_the_exact_call_and_policy_inventory() {
    let metadata = read_repo_file(METADATA_SOURCE_PATH);
    for (marker, count) in [
        ("xattr::list_deref(", 1),
        ("xattr::list(", 1),
        ("xattr::get_deref(", 1),
        ("xattr::get(", 1),
        ("xattr::set(", 1),
    ] {
        assert_eq!(
            metadata.matches(marker).count(),
            count,
            "production call count drifted for {marker}"
        );
    }
    for marker in [
        "meta.xattrs = read_xattrs_best_effort_sync(abs_path, false);",
        "let Some(name_str) = name.to_str().map(str::to_owned) else",
        "if let Ok(Some(value)) = value",
        "return BTreeMap::new();",
        "report.mark_skipped(\"xattr\", format!(\"{name}: {e}\"))",
        "xattr apply skipped for special file",
    ] {
        assert!(
            metadata.contains(marker),
            "metadata source must retain {marker}"
        );
    }

    let policy = read_repo_file(POLICY_SOURCE_PATH);
    for marker in [
        "pub preserve_extended_attributes: bool",
        "preserve_extended_attributes: false",
        "preserve_extended_attributes: true",
        "pub const fn full_preservation() -> Self",
    ] {
        assert!(
            policy.contains(marker),
            "policy source must retain {marker}"
        );
    }

    let cli = read_repo_file(CLI_SOURCE_PATH);
    assert!(cli.contains("fn selected_cli_metadata_policy() -> MetadataPolicy"));
    assert!(cli.contains("preserve_timestamps: true"));
    assert!(cli.contains("..MetadataPolicy::default()"));

    let e2e = read_repo_file(E2E_SOURCE_PATH);
    assert_eq!(e2e.matches("xattr::set(").count(), 1);
    assert_eq!(e2e.matches("xattr::get(").count(), 1);
    for marker in [
        "fn xattr_roundtrip_preserves_value_when_supported()",
        "if !set_xattr_or_skip(&data, attr_name, attr_value)",
        "return;",
        "b\"\\0binary-value\\nwith-newline\"",
    ] {
        assert!(e2e.contains(marker), "xattr fixture must retain {marker}");
    }
}

#[test]
fn semantic_platform_and_journey_states_preserve_known_gaps() {
    let inventory = artifact();
    let semantics = array(&inventory, "semantic_matrix");
    for (id, state) in [
        ("XATTR-SEM-FOLLOW-MAPPING", "PRESENT"),
        ("XATTR-SEM-DEREF-REACHABILITY", "PARTIAL"),
        ("XATTR-SEM-NAME-BYTES", "PARTIAL"),
        ("XATTR-SEM-VALUE-BYTES", "PRESENT"),
        ("XATTR-SEM-LIST-ERROR", "PARTIAL"),
        ("XATTR-SEM-SIZE-RACE", "PARTIAL"),
        ("XATTR-SEM-LIMITS", "BLOCKED_MISSING_EVIDENCE"),
        ("XATTR-SEM-CANCELLATION", "PARTIAL"),
    ] {
        assert_eq!(text(find_row(semantics, "semantic_id", id), "state"), state);
    }

    let platforms = array(&inventory, "platform_matrix");
    for (id, state) in [
        ("XATTR-PLAT-LINUX-ANDROID-HURD", "SOURCE_BASELINED"),
        ("XATTR-PLAT-MACOS", "SOURCE_ONLY"),
        ("XATTR-PLAT-FREEBSD-NETBSD", "SOURCE_ONLY"),
        ("XATTR-PLAT-OTHER-UNIX", "EXPLICIT_UNSUPPORTED"),
        ("XATTR-PLAT-WINDOWS", "OUTSIDE_DEPENDENCY_EDGE"),
        ("XATTR-PLAT-WASM", "OUTSIDE_DEPENDENCY_EDGE"),
    ] {
        assert_eq!(text(find_row(platforms, "platform_id", id), "state"), state);
    }

    let journeys = array(&inventory, "journey_inventory");
    assert_eq!(
        text(
            find_row(journeys, "journey_id", "XATTR-JOURNEY-REGULAR-FILE-TCP"),
            "state"
        ),
        "PARTIAL"
    );
    assert_eq!(
        text(
            find_row(journeys, "journey_id", "XATTR-JOURNEY-SYMLINK"),
            "state"
        ),
        "KNOWN_OMISSION"
    );
    assert_eq!(
        text(
            find_row(journeys, "journey_id", "XATTR-JOURNEY-CANONICAL-RUNNER"),
            "state"
        ),
        "PLANNED"
    );
}

#[test]
fn upstream_pins_and_replacement_cost_remain_explicit() {
    let inventory = artifact();
    let upstream = object(&inventory, "reviewed_upstream_sources");
    let xattr = upstream
        .get("xattr")
        .and_then(Value::as_object)
        .expect("xattr upstream pin");
    assert_eq!(xattr.get("version").and_then(Value::as_str), Some("1.6.1"));
    assert_eq!(
        xattr.get("cargo_lock_checksum").and_then(Value::as_str),
        Some("32e45ad4206f6d2479085147f02bc2ef834ac85886624a23575ae137c8aa8156")
    );
    assert_eq!(
        xattr.get("files").and_then(Value::as_array).map(Vec::len),
        Some(8)
    );
    let rustix = upstream
        .get("rustix")
        .and_then(Value::as_object)
        .expect("rustix upstream pin");
    assert_eq!(rustix.get("version").and_then(Value::as_str), Some("1.1.4"));
    assert_eq!(
        rustix
            .get("reviewed_files")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(2)
    );

    assert_eq!(inventory["unsafe_cost"]["replacement_delta"], "HIGH");
    assert!(
        inventory["unsafe_cost"]["conclusion"]
            .as_str()
            .is_some_and(|conclusion| conclusion.contains("leaving rustix"))
    );
}

#[test]
fn operator_doc_preserves_terminal_gate_and_no_claims() {
    let doc = read_repo_file(DOC_PATH);
    for marker in [
        DOC_BEGIN,
        DOC_END,
        "terminal `DEFER`",
        "26 active `xattr` cells",
        "not the last `rustix` parent",
        "five direct production calls",
        "xattr_follow_nofollow",
        "implementation_children_authorized",
        "No local Cargo fallback is approved",
        "does not authorize",
    ] {
        assert!(
            doc.contains(marker),
            "missing documentation marker {marker}"
        );
    }
}

#[test]
fn negative_mutations_fail_closed() {
    let inventory = artifact();

    let mut replace = inventory.clone();
    replace["authority"]["gate_decision"] = Value::String("REPLACE".to_owned());
    assert!(validate_inventory(&replace).is_err());

    let mut authorize = inventory.clone();
    authorize["authority"]["implementation_children_authorized"] = Value::Bool(true);
    assert!(validate_inventory(&authorize).is_err());

    let mut last_parent = inventory.clone();
    last_parent["marginal_graph"]["last_rustix_parent"] = Value::Bool(true);
    assert!(validate_inventory(&last_parent).is_err());

    let mut unblock = inventory.clone();
    unblock["decision"]["children_unblocked"] =
        Value::Array(vec![Value::String("asupersync-3u3tej.3.2".to_owned())]);
    assert!(validate_inventory(&unblock).is_err());

    let mut unknown = inventory;
    unknown["platform_matrix"][0]["state"] = Value::String("UNKNOWN".to_owned());
    assert!(validate_inventory(&unknown).is_err());
}
