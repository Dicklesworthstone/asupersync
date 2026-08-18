//! Fail-closed contract for the OS-lock inventory and terminal gate.
//!
//! Bead: asupersync-0h6myr.1.1
//! Artifact: artifacts/oslock_inventory_gate_v1.json
//!
//! This contract proves an exact dependency-token census, primitive and
//! visible-signature inventory, canonical marginal-graph interpretation,
//! source pins, routed evidence gaps, and a terminal `DEFER` decision. It does
//! not prove replacement parity, broad workspace health, performance, or
//! permission to modify the incumbent dependency.

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/oslock_inventory_gate_v1.json";
const DOC_PATH: &str = "docs/oslock_inventory_gate.md";
const REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const MARGINAL_LEDGER_PATH: &str = "artifacts/dependency_marginal_ledger_v1.json";
const CONTRACT_PATH: &str = "tests/oslock_inventory_gate_contract.rs";
const BEAD_ID: &str = "asupersync-0h6myr.1.1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const CAPABILITY_ID: &str = "CAP-SYNC-LOCKS";
const BASELINE_REVISION: &str = "d6bfec75aba10957b6a3e29654a29e650b45d510";
const DEPENDENCY_TOKEN: &str = "parking_lot";
const DOC_BEGIN: &str = "<!-- BEGIN OSLOCK INVENTORY GATE -->";
const DOC_END: &str = "<!-- END OSLOCK INVENTORY GATE -->";

#[derive(Debug, Default, PartialEq, Eq)]
struct Counts {
    files: BTreeSet<String>,
    occurrences: usize,
}

#[derive(Debug)]
struct Census {
    records: Vec<String>,
    files: BTreeSet<String>,
    scopes: BTreeMap<String, Counts>,
    workloads: BTreeMap<String, Counts>,
    imports: BTreeMap<String, usize>,
}

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

fn map_text<'a>(value: &'a serde_json::Map<String, Value>, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
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
        ("artifact_id", "oslock-inventory-gate-v1"),
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

    let census = object(inventory, "source_census");
    if census.get("matching_file_count").and_then(Value::as_u64) != Some(246)
        || census.get("matching_line_count").and_then(Value::as_u64) != Some(558)
        || census.get("sha256").and_then(Value::as_str)
            != Some("a87e2904096723b994ccebddb429757b76507b9e04941a8b2ee883dc4b04bbb0")
    {
        return Err("source census receipt drifted".to_owned());
    }

    let imports = object(inventory, "import_inventory");
    if imports
        .get("direct_use_statement_count")
        .and_then(Value::as_u64)
        != Some(180)
    {
        return Err("direct use-statement count drifted".to_owned());
    }

    for (key, count, id_key) in [
        ("primitive_surface", 8, "surface_id"),
        ("visible_and_crate_signatures", 9, "surface_id"),
        ("semantic_matrix", 14, "semantic_id"),
        ("baseline_matrix", 9, "baseline_id"),
        ("gaps", 9, "gap_id"),
        ("reconsideration_triggers", 5, "trigger_id"),
    ] {
        let rows = array(inventory, key);
        if rows.len() != count || row_ids(rows, id_key).len() != count {
            return Err(format!("{key} must contain {count} unique rows"));
        }
    }

    let expected_surfaces: BTreeSet<String> = [
        "OSLOCK-MUTEX",
        "OSLOCK-RWLOCK",
        "OSLOCK-CONDVAR",
        "OSLOCK-MUTEX-GUARD",
        "OSLOCK-RWLOCK-READ-GUARD",
        "OSLOCK-RWLOCK-WRITE-GUARD",
        "OSLOCK-MAPPED-GUARDS",
        "OSLOCK-TYPE-ALIASES",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(array(inventory, "primitive_surface"), "surface_id") != expected_surfaces {
        return Err("primitive surface inventory drifted".to_owned());
    }

    let baselines = array(inventory, "baseline_matrix");
    let correctness = find_row(baselines, "baseline_id", "OSLOCK-BASE-CORRECTNESS-SYNC");
    if correctness.get("state").and_then(Value::as_str) != Some("MEASURED_FAIL")
        || !text(correctness, "receipt").contains("test result: FAILED. 614 passed; 1 failed")
        || !text(correctness, "receipt")
            .contains("mutex_queued_waiter_sees_poison_after_holder_panics")
    {
        return Err(
            "focused correctness baseline must retain its terminal failure receipt".to_owned(),
        );
    }
    let reproduction = object(correctness, "isolated_reproduction");
    if reproduction.get("state").and_then(Value::as_str) != Some("MEASURED_PASS")
        || !map_text(reproduction, "receipt").contains("test result: ok. 1 passed")
        || !map_text(reproduction, "interpretation").contains("does not erase")
    {
        return Err("isolated reproduction receipt or no-claim interpretation drifted".to_owned());
    }
    for row in baselines {
        if text(row, "baseline_id") != "OSLOCK-BASE-CORRECTNESS-SYNC"
            && text(row, "state") != "BLOCKED_MISSING_EVIDENCE"
        {
            return Err(format!(
                "{} must remain blocked until a retained measurement exists",
                text(row, "baseline_id")
            ));
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
    if graph.get("measurement_cells").and_then(Value::as_u64) != Some(52)
        || graph
            .get("cells_removing_four_package_versions")
            .and_then(Value::as_u64)
            != Some(48)
        || graph
            .get("cells_removing_zero_package_versions")
            .and_then(Value::as_u64)
            != Some(4)
        || graph.get("unsafe_exposure_class").and_then(Value::as_str) != Some("ALGORITHMIC-UNSAFE")
    {
        return Err("marginal graph summary drifted".to_owned());
    }

    let decision = object(inventory, "decision");
    if decision.get("outcome").and_then(Value::as_str) != Some("DEFER")
        || decision.get("terminal_for_bead").and_then(Value::as_bool) != Some(true)
        || decision.get("dependency_retained").and_then(Value::as_str) != Some(DEPENDENCY_TOKEN)
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
        return Err("decision must remain a terminal no-authority DEFER".to_owned());
    }

    let boundaries = array(inventory, "no_claim_boundaries");
    if boundaries.len() < 6
        || !boundaries.iter().any(|row| {
            row.as_str()
                .is_some_and(|text| text.contains("does not prove release readiness"))
        })
        || !boundaries.iter().any(|row| {
            row.as_str()
                .is_some_and(|text| text.contains("does not authorize"))
        })
    {
        return Err("no-claim boundaries must remain explicit".to_owned());
    }

    Ok(())
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

fn workload_for(path: &str) -> &'static str {
    if path.starts_with("benches/") {
        "benchmarks"
    } else if path.starts_with("examples/") {
        "examples"
    } else if path.starts_with("fuzz/") {
        "fuzz"
    } else if path.starts_with("tests/") {
        "integration_tests"
    } else if path.starts_with("src/runtime/") {
        "runtime_scheduler_reactors"
    } else if path.starts_with("src/sync/") {
        "sync_primitives"
    } else if path.starts_with("src/channel/") {
        "channels"
    } else if path.starts_with("src/lab/") {
        "deterministic_lab"
    } else if path.starts_with("src/net/") {
        "networking"
    } else if path.starts_with("src/service/") {
        "services"
    } else if path.starts_with("src/database") {
        "database"
    } else if path.starts_with("src/messaging") {
        "messaging"
    } else if path.starts_with("src/observability/") {
        "observability"
    } else if path.starts_with("src/transport/") {
        "transport"
    } else if path.starts_with("src/raptorq/") {
        "raptorq"
    } else if ["src/grpc/", "src/http/", "src/server/", "src/web/"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        "protocol_and_server"
    } else if [
        "src/actor.rs",
        "src/app.rs",
        "src/gen_server.rs",
        "src/supervision.rs",
    ]
    .contains(&path)
    {
        "structured_app"
    } else if [
        "src/cx/",
        "src/cancel/",
        "src/combinator/",
        "src/record/",
        "src/types/",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
    {
        "structured_concurrency_core"
    } else {
        "other_runtime_surfaces"
    }
}

fn collect_census() -> Census {
    let root = repo_root();
    let mut rust_files = Vec::new();
    for relative in ["benches", "examples", "fuzz", "src", "tests"] {
        visit_rust_files(&root.join(relative), &mut rust_files);
    }

    let mut census = Census {
        records: Vec::new(),
        files: BTreeSet::new(),
        scopes: BTreeMap::new(),
        workloads: BTreeMap::new(),
        imports: BTreeMap::new(),
    };

    for absolute_path in rust_files {
        let relative_path = absolute_path
            .strip_prefix(&root)
            .expect("census path must be below repository root")
            .to_string_lossy()
            .replace('\\', "/");
        if relative_path == CONTRACT_PATH {
            continue;
        }

        let source = std::fs::read_to_string(&absolute_path)
            .unwrap_or_else(|error| panic!("failed to read {relative_path}: {error}"));
        for line in source.lines() {
            let trimmed = line.trim_start();
            if let Some(import) = trimmed.strip_prefix("use parking_lot::")
                && let Some(form) = import.strip_suffix(';')
            {
                *census.imports.entry(form.to_owned()).or_default() += 1;
            }
            if !line.contains(DEPENDENCY_TOKEN) {
                continue;
            }

            census.records.push(format!("{relative_path}:{line}"));
            census.files.insert(relative_path.clone());

            let scope = relative_path
                .split_once('/')
                .map_or(relative_path.as_str(), |(scope, _)| scope)
                .to_owned();
            let scope_counts = census.scopes.entry(scope).or_default();
            scope_counts.files.insert(relative_path.clone());
            scope_counts.occurrences += 1;

            let workload = workload_for(&relative_path).to_owned();
            let workload_counts = census.workloads.entry(workload).or_default();
            workload_counts.files.insert(relative_path.clone());
            workload_counts.occurrences += 1;
        }
    }
    census.records.sort();
    census
}

fn count_rows(rows: &[Value], key: &str) -> BTreeMap<String, (usize, usize)> {
    rows.iter()
        .map(|row| {
            (
                text(row, key).to_owned(),
                (
                    usize_field(row, "file_count"),
                    usize_field(row, "occurrence_count"),
                ),
            )
        })
        .collect()
}

fn measured_counts(counts: &BTreeMap<String, Counts>) -> BTreeMap<String, (usize, usize)> {
    counts
        .iter()
        .map(|(key, value)| (key.clone(), (value.files.len(), value.occurrences)))
        .collect()
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

#[test]
fn inventory_is_terminal_fail_closed_defer() {
    validate_inventory(&artifact()).expect("canonical OS-lock inventory must validate");
}

#[test]
fn source_census_and_import_forms_match_clean_baseline() {
    let inventory = artifact();
    let expected = object(&inventory, "source_census");
    let census = collect_census();

    assert_eq!(
        census.files.len(),
        usize_value(expected.get("matching_file_count"), "matching_file_count")
    );
    assert_eq!(
        census.records.len(),
        usize_value(expected.get("matching_line_count"), "matching_line_count")
    );

    let mut stream = census.records.join("\n");
    stream.push('\n');
    let digest = sha256_hex(stream.as_bytes());
    assert_eq!(digest, map_text(expected, "sha256"));

    assert_eq!(
        measured_counts(&census.scopes),
        count_rows(map_array(expected, "scope_counts"), "scope")
    );
    assert_eq!(
        measured_counts(&census.workloads),
        count_rows(map_array(expected, "workload_counts"), "workload")
    );

    let import_inventory = object(&inventory, "import_inventory");
    let expected_imports: BTreeMap<String, usize> = map_array(import_inventory, "forms")
        .iter()
        .map(|row| (text(row, "form").to_owned(), usize_field(row, "count")))
        .collect();
    assert_eq!(census.imports, expected_imports);
    assert_eq!(
        census.imports.values().sum::<usize>(),
        usize_value(
            import_inventory.get("direct_use_statement_count"),
            "direct_use_statement_count",
        )
    );
}

#[test]
fn source_pins_match_clean_overlay() {
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
fn capability_registry_and_marginal_ledger_match_summary() {
    let registry = parse_repo_json(REGISTRY_PATH);
    let capability = find_row(
        array(&registry, "capabilities"),
        "capability_id",
        CAPABILITY_ID,
    );
    assert_eq!(
        capability.get("disposition").and_then(Value::as_str),
        Some("KEEP_UNTIL_PARITY")
    );
    assert_eq!(
        capability.get("evidence_state").and_then(Value::as_str),
        Some("BASELINE_PLANNED")
    );
    assert_eq!(
        capability.get("cutover_state").and_then(Value::as_str),
        Some("KEEP_INCUMBENT")
    );
    assert!(
        text(capability, "no_claim_boundary").contains("not enough"),
        "registry must reject compile-only parity"
    );

    let ledger = parse_repo_json(MARGINAL_LEDGER_PATH);
    let rows: Vec<&Value> = array(&ledger, "marginal_measurements")
        .iter()
        .filter(|row| row.get("dependency_name").and_then(Value::as_str) == Some(DEPENDENCY_TOKEN))
        .collect();
    assert_eq!(rows.len(), 52);
    assert_eq!(
        rows.iter()
            .filter(|row| {
                row.get("marginal_package_version_count")
                    .and_then(Value::as_u64)
                    == Some(4)
            })
            .count(),
        48
    );
    assert_eq!(
        rows.iter()
            .filter(|row| {
                row.get("marginal_package_version_count")
                    .and_then(Value::as_u64)
                    == Some(0)
            })
            .count(),
        4
    );

    let expected_packages: BTreeSet<String> =
        ["lock_api", "parking_lot", "parking_lot_core", "scopeguard"]
            .into_iter()
            .map(str::to_owned)
            .collect();
    for row in rows.iter().filter(|row| {
        row.get("marginal_package_version_count")
            .and_then(Value::as_u64)
            == Some(4)
    }) {
        assert_eq!(
            string_set(row, "marginal_unique_package_names"),
            expected_packages
        );
        assert_eq!(
            row.get("unsafe_exposure_class").and_then(Value::as_str),
            Some("ALGORITHMIC-UNSAFE")
        );
    }
}

#[test]
fn visible_signatures_and_condvar_sites_remain_present() {
    for (path, tokens) in [
        (
            "src/cx/cx.rs",
            &["pub(crate) fn from_inner(inner: Arc<parking_lot::RwLock<CxInner>>)"][..],
        ),
        (
            "src/runtime/io_driver.rs",
            &[
                "pub fn lock(&self) -> parking_lot::MutexGuard<'_, IoDriver>",
                "pub fn try_lock(&self) -> Option<parking_lot::MutexGuard<'_, IoDriver>>",
            ][..],
        ),
        (
            "src/runtime/state.rs",
            &[
                "pub fn io_driver_mut(&self) -> Option<parking_lot::MutexGuard<'_, IoDriver>>",
                "pub fn cancel_protocol_validator(&self) -> &Arc<parking_lot::Mutex<CancelProtocolValidator>>",
            ][..],
        ),
        (
            "src/service/steer.rs",
            &["pub fn services_mut(&self) -> Vec<MutexGuard<'_, S>>"][..],
        ),
        (
            "src/test_utils.rs",
            &["pub(crate) fn env_lock() -> parking_lot::MutexGuard<'static, ()>"][..],
        ),
        (
            "src/messaging/kafka.rs",
            &["pub struct DeterministicBrokerTestGuard(parking_lot::MutexGuard<'static, ()>)"][..],
        ),
        (
            "src/sync/notify.rs",
            &["fn pass_baton(&self, mut waiters: parking_lot::MutexGuard<'_, WaiterSlab>)"][..],
        ),
    ] {
        let source = read_repo_file(path);
        for token in tokens {
            assert!(
                source.contains(token),
                "{path} lost signature token {token}"
            );
        }
    }

    let blocking_pool = read_repo_file("src/runtime/blocking_pool.rs");
    for token in [
        "use parking_lot::{Condvar, Mutex};",
        ".condvar.wait(&mut guard)",
        ".condvar.wait_for(&mut guard, remaining)",
        ".condvar.notify_one()",
        ".condvar.notify_all()",
    ] {
        assert!(
            blocking_pool.contains(token),
            "blocking-pool Condvar token missing: {token}"
        );
    }

    let discover = read_repo_file("src/service/discover.rs");
    for token in [
        "use parking_lot::{Condvar, Mutex};",
        "resolve_done: Condvar",
        "self.resolve_done.wait(&mut state)",
        "self.resolve_done.notify_all()",
    ] {
        assert!(
            discover.contains(token),
            "discovery Condvar token missing: {token}"
        );
    }

    let resolve = read_repo_file("src/net/resolve.rs");
    assert!(resolve.contains("#[cfg(test)]\nmod tests"));
    assert!(resolve.contains("use parking_lot::{Condvar, Mutex};"));
}

#[test]
fn documentation_markers_and_no_claims_are_discoverable() {
    let document = read_repo_file(DOC_PATH);
    let begin = document
        .find(DOC_BEGIN)
        .expect("missing document begin marker");
    let end = document.find(DOC_END).expect("missing document end marker");
    assert!(begin < end);
    for token in [
        "terminal `DEFER`",
        "`implementation_authority` is `NONE`",
        "`implementation_children_authorized` is false",
        "No local Cargo fallback is approved.",
        "does not prove release readiness",
        "does not authorize",
    ] {
        assert!(
            document.contains(token),
            "operator document must retain {token}"
        );
    }
}

#[test]
fn replacement_authority_mutation_fails_closed() {
    let mut mutated = artifact();
    mutated["authority"]["gate_decision"] = Value::String("REPLACE".to_owned());
    mutated["authority"]["implementation_children_authorized"] = Value::Bool(true);
    mutated["decision"]["outcome"] = Value::String("REPLACE".to_owned());
    mutated["decision"]["implementation_authority"] = Value::String("GRANTED".to_owned());
    mutated["decision"]["implementation_children_authorized"] = Value::Bool(true);
    assert!(
        validate_inventory(&mutated).is_err(),
        "granting replacement authority must fail closed"
    );
}

#[test]
fn missing_performance_evidence_cannot_be_promoted_to_parity() {
    let mut mutated = artifact();
    let baselines = mutated["baseline_matrix"]
        .as_array_mut()
        .expect("baseline_matrix must be mutable array");
    let tails = baselines
        .iter_mut()
        .find(|row| row.get("baseline_id").and_then(Value::as_str) == Some("OSLOCK-BASE-TAILS"))
        .expect("tail baseline must exist");
    tails["state"] = Value::String("MEASURED_PASS".to_owned());
    assert!(
        validate_inventory(&mutated).is_err(),
        "missing performance evidence must not become parity"
    );
}
