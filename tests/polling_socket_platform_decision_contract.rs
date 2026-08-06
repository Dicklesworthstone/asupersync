//! Fail-closed static contract for the polling and socket platform decision.
//!
//! Bead: asupersync-3u3tej.4
//! Artifact: artifacts/polling_socket_platform_decision_v1.json
//!
//! This contract checks the terminal KEEP authority, direct-use path census,
//! source pins, canonical marginal-ledger interpretation, cross-platform
//! semantic anchors, reconsideration gate, and explicit no-claim boundary. It
//! does not prove live platform behavior, runtime correctness, performance, or
//! permission to replace either incumbent.

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/polling_socket_platform_decision_v1.json";
const DOC_PATH: &str = "docs/polling_socket_platform_decision.md";
const CONTRACT_PATH: &str = "tests/polling_socket_platform_decision_contract.rs";
const REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const BASELINE_PATH: &str = "artifacts/dependency_capability_baseline_v1.json";
const CUTOVER_PATH: &str = "artifacts/dependency_cutover_policy_v1.json";
const LEDGER_PATH: &str = "artifacts/dependency_marginal_ledger_v1.json";
const TAXONOMY_PATH: &str = "artifacts/dependency_safety_taxonomy_v1.json";
const PLAN_PATH: &str = "COMPREHENSIVE_DEPENDENCY_REPLACEMENT_PLAN.md";
const BEAD_ID: &str = "asupersync-3u3tej.4";
const PROGRAM_ID: &str = "asupersync-3u3tej";
const CAPABILITY_ID: &str = "CAP-POLLING-SOCKET";
const BASELINE_REVISION: &str = "e263782a6d5a793b78e53065f70ce7f76605e863";
const DOC_BEGIN: &str = "<!-- BEGIN POLLING SOCKET PLATFORM DECISION -->";
const DOC_END: &str = "<!-- END POLLING SOCKET PLATFORM DECISION -->";

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

fn map_array<'a>(value: &'a serde_json::Map<String, Value>, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn map_object<'a>(
    value: &'a serde_json::Map<String, Value>,
    key: &str,
) -> &'a serde_json::Map<String, Value> {
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

fn map_text<'a>(value: &'a serde_json::Map<String, Value>, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn usize_value(value: Option<&Value>, key: &str) -> usize {
    let raw = value
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an integer"));
    usize::try_from(raw).unwrap_or_else(|_| panic!("{key} must fit usize"))
}

fn usize_field(value: &Value, key: &str) -> usize {
    usize_value(value.get(key), key)
}

fn map_usize(value: &serde_json::Map<String, Value>, key: &str) -> usize {
    usize_value(value.get(key), key)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn row_ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
}

fn find_row<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
}

fn map_string_set(value: &serde_json::Map<String, Value>, key: &str) -> BTreeSet<String> {
    map_array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
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

#[allow(clippy::too_many_lines)]
fn validate_inventory(inventory: &Value) -> Result<(), String> {
    if inventory.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("schema_version must be 1".to_owned());
    }
    for (key, expected) in [
        ("artifact_id", "polling-socket-platform-decision-v1"),
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
        ("plan_decision", "KEEP"),
        ("registry_disposition", "KEEP_UNTIL_PARITY"),
        ("registry_evidence_state", "BASELINE_PLANNED"),
        ("registry_cutover_state", "KEEP_INCUMBENT"),
        ("baseline_state", "BLOCKED_PLATFORM"),
        ("gate_decision", "KEEP"),
        ("gate_state", "TERMINAL"),
    ] {
        if authority.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("authority.{key} must be {expected}"));
        }
    }
    for key in [
        "dependency_exit_allowed",
        "replacement_implementation_authorized",
        "source_changes_authorized",
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
        return Err("owner review must be required to change KEEP".to_owned());
    }

    let dependencies = array(inventory, "dependency_resolution");
    if dependencies.len() != 2
        || row_ids(dependencies, "dependency")
            != ["polling", "socket2"]
                .into_iter()
                .map(str::to_owned)
                .collect()
    {
        return Err("dependency resolution must cover polling and socket2".to_owned());
    }
    for dependency in dependencies {
        if text(dependency, "unsafe_exposure_class") != "BOUNDARY-UNSAFE"
            || text(dependency, "taxonomy_verdict") != "KEEP_UNLESS_GATED"
        {
            return Err(format!(
                "{} taxonomy must remain fail-closed",
                text(dependency, "dependency")
            ));
        }
    }

    for (key, count, id_key) in [
        ("source_pins", 27, "path"),
        ("platform_matrix", 5, "platform_id"),
        ("polling_semantic_matrix", 12, "semantic_id"),
        ("socket_semantic_matrix", 9, "semantic_id"),
        ("gaps", 14, "gap_id"),
        ("reconsideration_triggers", 5, "trigger_id"),
    ] {
        let rows = array(inventory, key);
        if rows.len() != count || row_ids(rows, id_key).len() != count {
            return Err(format!("{key} must contain {count} unique rows"));
        }
    }

    for gap in array(inventory, "gaps") {
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
    if map_text(graph, "freshness_state")
        != "HISTORICAL_CANONICAL_MEASUREMENT_STATICALLY_CORROBORATED"
        || map_usize(graph, "cells_per_dependency") != 52
        || map_usize(graph, "active_native_cells_per_dependency") != 39
        || map_usize(graph, "inactive_wasm_cells_per_dependency") != 13
        || map_usize(graph, "recorded_active_rows") != 78
        || map_usize(graph, "combined_marginal_package_version_observations") != 87
        || graph
            .get("rustix_eviction_supported")
            .and_then(Value::as_bool)
            != Some(false)
        || map_text(graph, "measured_graph_benefit") != "MINIMAL"
    {
        return Err("marginal graph summary drifted".to_owned());
    }
    let polling = map_object(graph, "polling");
    if map_usize(polling, "active_rows") != 39
        || map_usize(polling, "cells_removing_one_package_version") != 27
        || map_usize(polling, "cells_removing_two_package_versions") != 12
        || map_usize(polling, "marginal_package_version_observations") != 51
    {
        return Err("polling marginal summary drifted".to_owned());
    }
    let socket2 = map_object(graph, "socket2");
    if map_usize(socket2, "active_rows") != 39
        || map_usize(socket2, "cells_removing_zero_package_versions") != 3
        || map_usize(socket2, "cells_removing_one_package_version") != 36
        || map_usize(socket2, "marginal_package_version_observations") != 36
    {
        return Err("socket2 marginal summary drifted".to_owned());
    }

    let decision = object(inventory, "decision");
    if map_text(decision, "outcome") != "KEEP"
        || decision.get("terminal_for_bead").and_then(Value::as_bool) != Some(true)
        || map_text(decision, "cutover_state") != "KEEP_INCUMBENT"
        || map_text(decision, "implementation_authority") != "NONE"
        || decision
            .get("replacement_implementation_authorized")
            .and_then(Value::as_bool)
            != Some(false)
        || decision
            .get("dependency_exit_allowed")
            .and_then(Value::as_bool)
            != Some(false)
        || !map_array(decision, "children_unblocked").is_empty()
        || map_string_set(decision, "dependencies_retained")
            != ["polling", "socket2"]
                .into_iter()
                .map(str::to_owned)
                .collect()
    {
        return Err("decision must remain terminal KEEP with no authority".to_owned());
    }

    let boundaries = array(inventory, "no_claim_boundaries");
    if boundaries.len() != 10
        || !boundaries.iter().any(|row| {
            row.as_str()
                .is_some_and(|value| value.contains("executes no build"))
        })
        || !boundaries.iter().any(|row| {
            row.as_str()
                .is_some_and(|value| value.contains("No thin-wrapper claim"))
        })
        || !boundaries.iter().any(|row| {
            row.as_str()
                .is_some_and(|value| value.contains("No replacement implementation"))
        })
    {
        return Err("no-claim boundaries must remain explicit".to_owned());
    }

    validate_no_unknown(inventory, "$")
}

fn visit_rust_files(root: &Path, files: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(root)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", root.display()))
        .map(|entry| entry.expect("directory entry must be readable"))
        .collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .unwrap_or_else(|error| panic!("failed to stat {}: {error}", path.display()));
        if file_type.is_dir() {
            visit_rust_files(&path, files);
        } else if file_type.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
}

fn direct_use_paths(token: &str) -> BTreeSet<String> {
    let root = repo_root();
    let mut rust_files = Vec::new();
    for relative in ["src", "tests"] {
        visit_rust_files(&root.join(relative), &mut rust_files);
    }

    rust_files
        .into_iter()
        .filter_map(|path| {
            let relative = path
                .strip_prefix(&root)
                .expect("census path must remain below repository root")
                .to_string_lossy()
                .replace('\\', "/");
            if relative == CONTRACT_PATH {
                return None;
            }
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read {relative}: {error}"));
            source.contains(token).then_some(relative)
        })
        .collect()
}

#[test]
fn decision_is_terminal_keep_without_replacement_authority() {
    validate_inventory(&artifact()).expect("canonical polling/socket decision must validate");
}

#[test]
fn direct_dependency_use_path_sets_are_exact() {
    let inventory = artifact();
    let census = object(&inventory, "occurrence_census");

    let polling = map_object(census, "polling");
    let expected_polling = map_string_set(polling, "production_paths");
    assert_eq!(
        expected_polling.len(),
        map_usize(polling, "direct_file_count")
    );
    assert_eq!(direct_use_paths("polling::"), expected_polling);

    let socket2 = map_object(census, "socket2");
    let production = map_string_set(socket2, "production_paths");
    let test_only = map_string_set(socket2, "test_only_paths");
    assert!(production.is_disjoint(&test_only));
    assert_eq!(
        production.len(),
        map_usize(socket2, "production_file_count")
    );
    assert_eq!(test_only.len(), map_usize(socket2, "test_only_file_count"));
    let expected_socket2: BTreeSet<_> = production.union(&test_only).cloned().collect();
    assert_eq!(
        expected_socket2.len(),
        map_usize(socket2, "direct_file_count")
    );
    assert_eq!(direct_use_paths("socket2::"), expected_socket2);

    let registry_paths = map_string_set(census, "registry_source_owner_paths");
    let omitted = map_string_set(census, "registry_omitted_production_direct_paths");
    assert!(omitted.is_subset(&production));
    assert!(omitted.is_disjoint(&registry_paths));
}

#[test]
fn source_pins_match_claim_revision() {
    for pin in array(&artifact(), "source_pins") {
        let path = text(pin, "path");
        let bytes = read_repo_bytes(path);
        let digest = sha256_hex(&bytes);
        let line_count = std::str::from_utf8(&bytes)
            .unwrap_or_else(|error| panic!("{path} must be UTF-8: {error}"))
            .lines()
            .count();
        assert_eq!(digest, text(pin, "sha256"), "{path} hash drifted");
        assert_eq!(
            line_count,
            usize_field(pin, "line_count"),
            "{path} line count drifted"
        );
    }
}

#[test]
fn plan_registry_baseline_cutover_and_taxonomy_retain_incumbents() {
    let plan = read_repo_file(PLAN_PATH);
    for token in [
        "| `socket2` | **KEEP** |",
        "| `polling` | **KEEP** |",
        "polling/socket2 revisit (only with measured defect or a suite-wide platform-boundary project)",
    ] {
        assert!(plan.contains(token), "plan token missing: {token}");
    }

    let registry = parse_repo_json(REGISTRY_PATH);
    let capability = find_row(
        array(&registry, "capabilities"),
        "capability_id",
        CAPABILITY_ID,
    );
    assert_eq!(text(capability, "disposition"), "KEEP_UNTIL_PARITY");
    assert_eq!(text(capability, "evidence_state"), "BASELINE_PLANNED");
    assert_eq!(text(capability, "cutover_state"), "KEEP_INCUMBENT");
    assert!(text(capability, "no_claim_boundary").contains("terminal KEEP/defer"));

    let baseline = parse_repo_json(BASELINE_PATH);
    let baseline_row = find_row(
        array(&baseline, "capability_baselines"),
        "capability_id",
        CAPABILITY_ID,
    );
    assert_eq!(text(baseline_row, "baseline_state"), "BLOCKED_PLATFORM");
    assert_eq!(
        baseline_row
            .get("cutover_eligible")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(array(baseline_row, "parity_modes").len(), 7);

    let cutover = parse_repo_json(CUTOVER_PATH);
    let binding = find_row(
        array(&cutover, "capability_bindings"),
        "capability_id",
        CAPABILITY_ID,
    );
    assert_eq!(text(binding, "registry_cutover_state"), "KEEP_INCUMBENT");
    assert_eq!(
        binding
            .get("dependency_exit_allowed")
            .and_then(Value::as_bool),
        Some(false)
    );

    let taxonomy = parse_repo_json(TAXONOMY_PATH);
    for candidate in ["polling-reactor", "socket-platform"] {
        let row = find_row(
            array(&taxonomy, "classifications"),
            "candidate_id",
            candidate,
        );
        assert_eq!(text(row, "class_id"), "BOUNDARY-UNSAFE");
        assert_eq!(text(row, "program_verdict"), "KEEP_UNLESS_GATED");
        let gates = array(row, "program_gates");
        assert!(gates.iter().any(|gate| {
            gate.as_str()
                .is_some_and(|value| value.contains("Measured defect"))
        }));
        assert!(gates.iter().any(|gate| {
            gate.as_str()
                .is_some_and(|value| value.contains("owner sign-off"))
        }));
    }
}

#[test]
fn manifest_and_lock_resolution_remain_exact() {
    let manifest = read_repo_file("Cargo.toml");
    for token in [
        "[target.'cfg(not(target_arch = \"wasm32\"))'.dependencies]",
        "polling = \"3.11\"",
        "socket2 = { version = \"0.6\", features = [\"all\"] }",
    ] {
        assert!(manifest.contains(token), "manifest token missing: {token}");
    }

    let lock = read_repo_file("Cargo.lock");
    for token in [
        "name = \"polling\"\nversion = \"3.11.0\"",
        "checksum = \"5d0e4f59085d47d8241c88ead0f274e8a0cb551f3625263c05eb8dd897c34218\"",
        "name = \"socket2\"\nversion = \"0.6.5\"",
        "checksum = \"c3d1e2c7f27f8d4cb10542a02c49005dbd6e93095799d6f3be745fae9f8fedd4\"",
    ] {
        assert!(lock.contains(token), "lock token missing: {token}");
    }
}

fn marginal_rows<'a>(ledger: &'a Value, dependency: &str) -> Vec<&'a Value> {
    array(ledger, "marginal_measurements")
        .iter()
        .filter(|row| row.get("dependency_name").and_then(Value::as_str) == Some(dependency))
        .collect()
}

fn row_nested_text<'a>(row: &'a Value, object_key: &str, text_key: &str) -> &'a str {
    map_text(object(row, object_key), text_key)
}

#[test]
fn canonical_marginal_rows_match_terminal_graph_summary() {
    let ledger = parse_repo_json(LEDGER_PATH);
    assert_eq!(
        ledger.get("source_commit").and_then(Value::as_str),
        Some("ddea6250aee80357756fa1f39456823df88f7af1")
    );

    let polling = marginal_rows(&ledger, "polling");
    let socket2 = marginal_rows(&ledger, "socket2");
    assert_eq!(polling.len(), 39);
    assert_eq!(socket2.len(), 39);

    for rows in [&polling, &socket2] {
        let profiles: BTreeSet<_> = rows
            .iter()
            .map(|row| text(row, "feature_profile").to_owned())
            .collect();
        let targets: BTreeSet<_> = rows
            .iter()
            .map(|row| text(row, "target_triple").to_owned())
            .collect();
        let hosts: BTreeSet<_> = rows
            .iter()
            .map(|row| text(row, "host_triple").to_owned())
            .collect();
        assert_eq!(profiles.len(), 13);
        assert_eq!(
            targets,
            [
                "aarch64-apple-darwin",
                "x86_64-pc-windows-msvc",
                "x86_64-unknown-linux-gnu",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
        assert_eq!(
            hosts,
            ["x86_64-unknown-linux-gnu"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
        for row in rows.iter().copied() {
            assert_eq!(
                row_nested_text(row, "marginal_native_code", "status"),
                "none"
            );
            assert!(array(row, "build_scripts").is_empty());
            assert!(array(row, "proc_macros").is_empty());
            assert_eq!(text(row, "unsafe_exposure_class"), "BOUNDARY-UNSAFE");
        }
    }

    assert_eq!(
        polling
            .iter()
            .filter(|row| usize_field(row, "marginal_package_version_count") == 1)
            .count(),
        27
    );
    assert_eq!(
        polling
            .iter()
            .filter(|row| usize_field(row, "marginal_package_version_count") == 2)
            .count(),
        12
    );
    assert_eq!(
        polling
            .iter()
            .map(|row| usize_field(row, "marginal_package_version_count"))
            .sum::<usize>(),
        51
    );
    assert_eq!(
        socket2
            .iter()
            .filter(|row| usize_field(row, "marginal_package_version_count") == 0)
            .count(),
        3
    );
    assert_eq!(
        socket2
            .iter()
            .filter(|row| usize_field(row, "marginal_package_version_count") == 1)
            .count(),
        36
    );

    let all_rows: Vec<_> = polling.iter().chain(socket2.iter()).copied().collect();
    assert_eq!(
        all_rows
            .iter()
            .filter(|row| row_nested_text(row, "root_native_code", "status") == "unknown")
            .count(),
        65
    );
    assert_eq!(
        all_rows
            .iter()
            .filter(|row| row_nested_text(row, "root_native_code", "status") == "none")
            .count(),
        13
    );
}

#[test]
fn source_anchors_preserve_nontrivial_platform_scope() {
    for (path, tokens) in [
        (
            "src/runtime/reactor/epoll.rs",
            &[
                "struct FdIdentity",
                "add_with_mode",
                "modify_with_mode",
                "PollMode::EdgeOneshot",
                "self.poller.notify()",
            ][..],
        ),
        (
            "src/runtime/reactor/kqueue.rs",
            &[
                "libc::fcntl(raw_fd, libc::F_GETFD)",
                "Interest::PRIORITY is not supported",
                "PollMode::EdgeOneshot",
                "self.poller.notify()",
            ][..],
        ),
        (
            "src/runtime/reactor/windows.rs",
            &[
                "IOCP reactor only supports READABLE and WRITABLE interests",
                "self.poller.add(&borrowed_socket, event)",
                "self.poller.notify()",
            ][..],
        ),
        (
            "src/runtime/reactor/token.rs",
            &[
                "generation",
                "current_generation == SlabToken::MAX_GENERATION",
                "let recycle_slot = current_generation != SlabToken::MAX_GENERATION",
            ][..],
        ),
        (
            "src/runtime/reactor/registration.rs",
            &[
                "impl Drop for Registration",
                "retry once",
                "panic::catch_unwind",
            ][..],
        ),
        (
            "src/net/tcp/stream.rs",
            &[
                "socket2::TcpKeepalive",
                "socket.set_tcp_keepalive(&params)",
                "TCP keepalive interval is unsupported on this platform",
                "TCP keepalive retry count is unsupported on this platform",
            ][..],
        ),
        (
            "src/net/tcp/traits.rs",
            &[
                "socket.set_reuse_address(true)",
                "socket.set_reuse_port(true)",
                "socket.set_only_v6(true)",
                "socket.set_nonblocking(true)",
            ][..],
        ),
        (
            "src/net/udp.rs",
            &[
                "socket2::SockRef::from(&*self.inner)",
                "sock.set_recv_buffer_size(size)",
                "sock.set_send_buffer_size(size)",
            ][..],
        ),
        (
            "src/net/unix/stream.rs",
            &[
                "pub async fn connect_abstract(name: &[u8])",
                "path_bytes.push(0)",
                "SockAddr::unix(abstract_path)",
            ][..],
        ),
        (
            "src/net/atp/transport_rq/mod.rs",
            &[
                "socket2::SockRef::from(std_stream)",
                "set_send_buffer_size(RQ_CONTROL_STREAM_SOCKET_BUFFER_BYTES)",
                "set_recv_buffer_size(RQ_CONTROL_STREAM_SOCKET_BUFFER_BYTES)",
            ][..],
        ),
    ] {
        let source = read_repo_file(path);
        for token in tokens {
            assert!(source.contains(token), "{path} lost semantic token {token}");
        }
    }
}

#[test]
fn docs_expose_terminal_keep_reopen_gate_and_no_claims() {
    let document = read_repo_file(DOC_PATH);
    let begin = document
        .find(DOC_BEGIN)
        .expect("missing document begin marker");
    let end = document.find(DOC_END).expect("missing document end marker");
    assert!(begin < end);

    for token in [
        "The terminal decision is **KEEP**",
        "KEEP is the decision, not an unfinished replacement campaign",
        "No public route selects",
        "Fork safety after",
        "There is no `rustix`-eviction result",
        "Every trigger requires owner approval",
        "did not compile or execute the focused contract",
        "replacement implementation, dependency removal",
    ] {
        assert!(
            document.contains(token),
            "documentation token missing: {token}"
        );
    }
}
