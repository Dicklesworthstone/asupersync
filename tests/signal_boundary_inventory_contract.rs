//! Fail-closed contract for the all-platform signal boundary inventory.
//!
//! Bead: asupersync-3u3tej.1.1
//! Artifact: artifacts/signal_boundary_inventory_v1.json
//!
//! This contract proves a source-pinned inventory, measured dependency cost,
//! explicit semantic/platform/journey states, routed gaps, and a terminal
//! `DEFER` gate. It does not prove OS delivery, platform parity, process
//! identity safety, release readiness, or permission to replace signal-hook.

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;

const ARTIFACT_PATH: &str = "artifacts/signal_boundary_inventory_v1.json";
const DOC_PATH: &str = "docs/signal_boundary_inventory.md";
const REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const MARGINAL_LEDGER_PATH: &str = "artifacts/dependency_marginal_ledger_v1.json";
const UNSAFE_LEDGER_PATH: &str = "artifacts/unsafe_boundary_ledger_v1.json";
const SIGNAL_SOURCE_PATH: &str = "src/signal/signal.rs";
const KIND_SOURCE_PATH: &str = "src/signal/kind.rs";
const SHUTDOWN_SOURCE_PATH: &str = "src/signal/shutdown.rs";
const CLI_SIGNAL_SOURCE_PATH: &str = "src/cli/signal.rs";
const ATPD_SOURCE_PATH: &str = "src/bin/atpd.rs";
const PROCESS_SOURCE_PATH: &str = "src/process.rs";
const DAEMON_CONTROL_SOURCE_PATH: &str = "src/atp/daemon_control.rs";
const RUNNER_PATH: &str = "scripts/run_dependency_sovereignty_e2e.sh";
const BEAD_ID: &str = "asupersync-3u3tej.1.1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const CAPABILITY_ID: &str = "CAP-SIGNALS";
const BASELINE_REVISION: &str = "1d8c77755daac957c52438d09d1dfca9b9c6cfc4";
const DOC_BEGIN: &str = "<!-- BEGIN SIGNAL BOUNDARY INVENTORY -->";
const DOC_END: &str = "<!-- END SIGNAL BOUNDARY INVENTORY -->";

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

fn row_ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
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
        ("artifact_id", "signal-boundary-inventory-v1"),
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

    let expected_occurrences: BTreeSet<String> = [
        "SIG-OCC-FACADE",
        "SIG-OCC-SHUTDOWN",
        "SIG-OCC-CLI-MODEL",
        "SIG-OCC-ATPD",
        "SIG-OCC-DAEMON-CONTROL",
        "SIG-OCC-PROCESS",
        "SIG-OCC-TESTS-DOCS",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(array(inventory, "occurrence_census"), "occurrence_id") != expected_occurrences {
        return Err("occurrence census drifted".to_owned());
    }

    let expected_surfaces: BTreeSet<String> = [
        "SIG-PUB-KIND",
        "SIG-PUB-STREAM",
        "SIG-PUB-CONSTRUCTORS",
        "SIG-PUB-MASK",
        "SIG-PUB-SHUTDOWN",
        "SIG-PUB-CLI",
        "SIG-PUB-PROCESS",
        "SIG-OP-ATPD",
        "SIG-OP-ATP-DAEMON",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(
        array(inventory, "public_and_operator_surfaces"),
        "surface_id",
    ) != expected_surfaces
    {
        return Err("public/operator surface inventory drifted".to_owned());
    }

    for (key, count, id_key) in [
        ("semantic_matrix", 15, "semantic_id"),
        ("platform_matrix", 6, "platform_id"),
        ("journey_inventory", 9, "journey_id"),
        ("gaps", 13, "gap_id"),
        ("reconsideration_triggers", 5, "trigger_id"),
    ] {
        let rows = array(inventory, key);
        if rows.len() != count || row_ids(rows, id_key).len() != count {
            return Err(format!("{key} must contain {count} unique rows"));
        }
    }

    let expected_gaps: BTreeSet<String> = (1..=13)
        .map(|suffix| format!("SIG-A1-GAP-{suffix:02}"))
        .collect();
    let gaps = array(inventory, "gaps");
    if row_ids(gaps, "gap_id") != expected_gaps {
        return Err("gap inventory must retain SIG-A1-GAP-01..13".to_owned());
    }
    for gap in gaps {
        if text(gap, "state") != "ROUTED"
            || text(gap, "owner").is_empty()
            || gap.get("replacement_required").and_then(Value::as_bool) != Some(false)
        {
            return Err(format!(
                "{} must be routed without requiring replacement",
                text(gap, "gap_id")
            ));
        }
    }

    let decision = object(inventory, "decision");
    if decision.get("outcome").and_then(Value::as_str) != Some("DEFER")
        || decision.get("terminal_for_bead").and_then(Value::as_bool) != Some(true)
        || decision.get("dependency_retained").and_then(Value::as_str) != Some("signal-hook")
        || decision
            .get("implementation_authority")
            .and_then(Value::as_str)
            != Some("NONE")
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
fn registry_and_marginal_graph_match_the_terminal_gate() {
    let registry = parse_repo_json(REGISTRY_PATH);
    let capability = find_row(
        array(&registry, "capabilities"),
        "capability_id",
        CAPABILITY_ID,
    );
    assert_eq!(text(capability, "disposition"), "KEEP_UNTIL_PARITY");
    assert_eq!(text(capability, "evidence_state"), "BASELINE_PLANNED");
    assert_eq!(text(capability, "cutover_state"), "KEEP_INCUMBENT");
    assert_eq!(
        string_set(capability, "scenario_ids"),
        [
            "signal_graceful_shutdown",
            "signal_permission_pid_reuse",
            "signal_repeated_escalation",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    assert!(
        text(capability, "no_claim_boundary").contains("Windows control events"),
        "registry must preserve the cross-platform no-claim boundary"
    );

    let ledger = parse_repo_json(MARGINAL_LEDGER_PATH);
    let rows: Vec<&Value> = array(&ledger, "marginal_measurements")
        .iter()
        .filter(|row| row.get("dependency_name").and_then(Value::as_str) == Some("signal-hook"))
        .collect();
    assert_eq!(rows.len(), 39);
    assert_eq!(
        rows.iter()
            .map(|row| text(row, "feature_profile").to_owned())
            .collect::<BTreeSet<_>>()
            .len(),
        13
    );
    assert_eq!(
        rows.iter()
            .map(|row| text(row, "target_triple").to_owned())
            .collect::<BTreeSet<_>>(),
        [
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
            "x86_64-unknown-linux-gnu",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    for row in rows {
        assert_eq!(row["marginal_native_code"]["status"], "declared-inactive");
        assert_eq!(
            array(row, "build_scripts").len(),
            1,
            "the no-op upstream build script remains graph-visible"
        );
        assert!(array(row, "proc_macros").is_empty());
        let package_count = row
            .get("marginal_package_version_count")
            .and_then(Value::as_u64)
            .expect("marginal package count");
        assert!((1..=3).contains(&package_count));
    }

    let inventory = artifact();
    assert_eq!(inventory["marginal_graph"]["measurement_cells"], 39);
    assert_eq!(
        inventory["marginal_graph"]["marginal_native_status"],
        "declared-inactive"
    );
    assert_eq!(
        inventory["marginal_graph"]["measured_graph_benefit"],
        "SMALL"
    );
}

#[test]
fn source_topology_covers_receive_shutdown_daemon_and_process_paths() {
    let signal = read_repo_file(SIGNAL_SOURCE_PATH);
    for marker in [
        "signal_hook::iterator::Signals::new(raw_signals)?",
        "for kind in all_signal_kinds()",
        ".name(\"asupersync-signal-dispatch\"",
        "static SIGNAL_DISPATCHER: OnceLock",
        "signal_hook::low_level::register",
        "CreateEventW",
        "WaitForMultipleObjects",
        "no signal notification",
    ] {
        assert!(
            signal.contains(marker),
            "signal facade must retain {marker}"
        );
    }

    let kind = read_repo_file(KIND_SOURCE_PATH);
    for marker in [
        "pub enum SignalKind",
        "signal_hook::consts::SIGBREAK",
        "SignalKind::WindowChange",
    ] {
        assert!(kind.contains(marker), "signal kinds must retain {marker}");
    }

    let shutdown = read_repo_file(SHUTDOWN_SOURCE_PATH);
    for marker in [
        "pub fn listen_for_signals",
        "thread::spawn",
        "ReloadController",
        "Weak<ReloadState>",
    ] {
        assert!(
            shutdown.contains(marker),
            "shutdown surface must retain {marker}"
        );
    }

    let cli_signal = read_repo_file(CLI_SIGNAL_SOURCE_PATH);
    for marker in ["pub enum Signal", "force_quit_threshold", "signal_count"] {
        assert!(
            cli_signal.contains(marker),
            "CLI signal model must retain {marker}"
        );
    }

    let atpd = read_repo_file(ATPD_SOURCE_PATH);
    for marker in [
        "Signals::new([SIGINT, SIGTERM, SIGHUP])?",
        "flag::register(SIGBREAK",
        "libc::kill(native_pid, libc::SIGTERM)",
        "libc::kill(native_pid, libc::SIGKILL)",
        "Command::new(\"taskkill.exe\")",
        "fn process_is_running",
    ] {
        assert!(atpd.contains(marker), "atpd must retain {marker}");
    }

    let process = read_repo_file(PROCESS_SOURCE_PATH);
    for marker in [
        "pub fn signal(&mut self, sig: i32)",
        "self.send_configured_signal(libc::SIGKILL)",
        "ProcessSignalTarget",
        "libc::kill",
    ] {
        assert!(
            process.contains(marker),
            "process surface must retain {marker}"
        );
    }

    let daemon_control = read_repo_file(DAEMON_CONTROL_SOURCE_PATH);
    for marker in [
        "fn is_our_daemon_process",
        "process.kill_with(signal)",
        "Command::new(\"taskkill.exe\")",
        "is unsupported or pid",
        "no longer exists",
    ] {
        assert!(
            daemon_control.contains(marker),
            "daemon control must retain {marker}"
        );
    }
}

#[test]
fn semantic_platform_and_journey_states_preserve_known_gaps() {
    let inventory = artifact();
    let semantics = array(&inventory, "semantic_matrix");
    for (id, state) in [
        ("SIG-SEM-DELIVERY", "PARTIAL"),
        ("SIG-SEM-COALESCING", "PRESENT"),
        ("SIG-SEM-ORDER", "PRESENT"),
        ("SIG-SEM-REPEATED", "PARTIAL"),
        ("SIG-SEM-LIFETIME", "PARTIAL"),
        ("SIG-SEM-FORK", "BLOCKED"),
        ("SIG-SEM-PERMISSION", "PARTIAL"),
        ("SIG-SEM-STALE-PID", "PARTIAL"),
        ("SIG-SEM-CANCEL-TEARDOWN", "PARTIAL"),
    ] {
        assert_eq!(text(find_row(semantics, "semantic_id", id), "state"), state);
    }

    let platforms = array(&inventory, "platform_matrix");
    for (id, state) in [
        ("SIG-PLAT-LINUX", "PARTIAL"),
        ("SIG-PLAT-MACOS", "BLOCKED"),
        ("SIG-PLAT-BSD", "BLOCKED"),
        ("SIG-PLAT-WINDOWS", "PARTIAL"),
        ("SIG-PLAT-OTHER-NATIVE", "UNSUPPORTED"),
        ("SIG-PLAT-WASM", "OUT_OF_SCOPE"),
    ] {
        assert_eq!(text(find_row(platforms, "platform_id", id), "state"), state);
    }

    let journeys = array(&inventory, "journey_inventory");
    assert_eq!(
        text(
            find_row(journeys, "journey_id", "SIG-JOURNEY-CHILD-SEND"),
            "state"
        ),
        "PRESENT"
    );
    assert_eq!(
        text(
            find_row(journeys, "journey_id", "SIG-JOURNEY-WINDOWS-CONSOLE"),
            "state"
        ),
        "BLOCKED"
    );
    assert_eq!(
        text(
            find_row(journeys, "journey_id", "SIG-JOURNEY-CANONICAL-E2E"),
            "state"
        ),
        "PLANNED"
    );

    let runner = read_repo_file(RUNNER_PATH);
    for absent_scenario in [
        "signal_graceful_shutdown",
        "signal_repeated_escalation",
        "signal_permission_pid_reuse",
    ] {
        assert!(
            !runner.contains(absent_scenario),
            "{absent_scenario} is recorded as absent; update the inventory when implemented"
        );
    }
}

#[test]
fn unsafe_cost_is_ledgered_without_hiding_drift() {
    let ledger = parse_repo_json(UNSAFE_LEDGER_PATH);
    let sites = array(&ledger, "sites");
    for (site_id, path) in [
        ("unsafe-src-signal-signal-rs", SIGNAL_SOURCE_PATH),
        ("unsafe-src-bin-atpd-rs", ATPD_SOURCE_PATH),
        ("unsafe-src-process-rs", PROCESS_SOURCE_PATH),
    ] {
        let site = find_row(sites, "site_id", site_id);
        assert_eq!(text(site, "path"), path);
        assert_eq!(text(site, "category"), "process-signal-ffi");
    }

    let inventory = artifact();
    assert_eq!(inventory["unsafe_cost"]["replacement_delta"], "HIGH");
    assert!(
        inventory["unsafe_cost"]["ledger_quality_gap"]
            .as_str()
            .is_some_and(|gap| gap.contains("locators") && gap.contains("broad file-level"))
    );
    assert!(
        inventory["unsafe_cost"]["conclusion"]
            .as_str()
            .is_some_and(|conclusion| conclusion.contains("at most three"))
    );
}

#[test]
fn operator_doc_preserves_terminal_gate_and_no_claims() {
    let doc = read_repo_file(DOC_PATH);
    for marker in [
        DOC_BEGIN,
        DOC_END,
        "terminal `DEFER`",
        "39 `signal-hook` cells",
        "`declared-inactive`",
        "raw OS arrival",
        "PID reuse",
        "signal_graceful_shutdown",
        "implementation_children_authorized",
        "No local Cargo fallback is approved",
        "does not authorize deletion",
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

    let mut unblock = inventory.clone();
    unblock["decision"]["children_unblocked"] =
        Value::Array(vec![Value::String("asupersync-3u3tej.1.2".to_owned())]);
    assert!(validate_inventory(&unblock).is_err());

    let mut unknown = inventory;
    unknown["platform_matrix"][0]["state"] = Value::String("UNKNOWN".to_owned());
    assert!(validate_inventory(&unknown).is_err());
}
