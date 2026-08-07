//! Fail-closed inventory contract for the incumbent futures-lite capability.
//!
//! Beads: A1 asupersync-d24mms.6.1 through A5 asupersync-d24mms.6.5
//! Capability: CAP-FUTURES-STREAMS
//! Fixture: the inventory artifact declared by `ARTIFACT_PATH` below.
//!
//! This contract proves the source-pinned occurrence census, Cargo profile
//! classification, production/public sites, consumed helper semantics,
//! reservation groups, marginal ledger interpretation, and explicit gaps. It
//! does not authorize dependency removal or claim replacement parity.

#![allow(missing_docs)]

use asupersync::net::atp::sdk::{AtpReader, AtpWriter, TransferProgress};
use asupersync::stream::Stream as OwnedStream;
use futures_lite as incumbent;
use incumbent::{FutureExt, Stream};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

const ARTIFACT_PATH: &str = concat!("artifacts/futures", "_lite_capability_inventory_v1.json");
const DOC_PATH: &str = concat!("docs/futures", "_lite_capability_inventory.md");
const SELF_PATH: &str = concat!("tests/futures", "_lite_capability_inventory_contract.rs");
const ADR_PATH: &str = "docs/adr/dep_plan_adr_008_futures_streams.md";
const CAPABILITY_REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const MARGINAL_LEDGER_PATH: &str = "artifacts/dependency_marginal_ledger_v1.json";
const BEAD_ID: &str = "asupersync-d24mms.6.1";
const A3_BEAD_ID: &str = "asupersync-d24mms.6.3";
const A4_BEAD_ID: &str = "asupersync-d24mms.6.4";
const A5_BEAD_ID: &str = "asupersync-d24mms.6.5";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const CAPABILITY_ID: &str = "CAP-FUTURES-STREAMS";
const BASELINE_REVISION: &str = "ed1c0c3ae4ba68947cd2c0212f1aab2242f60724";
const AUTHORITY_REVISION: &str = "295136459f9e3e38e7373394e713866ec0693a8d";
const TOKEN: &str = concat!("futures", "_lite");
const DOC_BEGIN: &str = "<!-- BEGIN FUTURES LITE CAPABILITY INVENTORY -->";
const DOC_END: &str = "<!-- END FUTURES LITE CAPABILITY INVENTORY -->";

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

fn object_text<'a>(value: &'a serde_json::Map<String, Value>, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn row_ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
}

fn find_row<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
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

fn validate_a3_receipt(inventory: &Value) -> Result<(), String> {
    let receipt = inventory
        .get("a3_block_on_receipt")
        .expect("A3 blocking-kernel receipt");
    if text(receipt, "owner_bead") != A3_BEAD_ID
        || text(receipt, "base_revision") != "02b380ee063e7e643105b1a7997360a7021bf32e"
        || text(receipt, "implementation_revision") != "050fd0f08e4cf127e348bbf545c1e46cc392f6b5"
        || text(receipt, "source_status") != "STATIC_SOURCE_PROGRESS"
        || text(receipt, "execution_status") != "NOT_RUN_STATIC_ONLY"
        || text(receipt, "module") != "crate::util::future"
        || text(receipt, "visibility") != "crate-private alongside-incumbent"
        || receipt.get("cutover_authorized") != Some(&Value::Bool(false))
        || receipt.get("closure_allowed") != Some(&Value::Bool(false))
    {
        return Err("A3 receipt must remain static-only and fail closed".to_owned());
    }

    let expected_source_pins = BTreeMap::from([
        (
            "src/future.rs",
            (
                "c0a02784a010e9709dfab3b40259bccf8d312e9101834d8c110f2b1f19bd8598",
                972_u64,
            ),
        ),
        (
            "src/util/mod.rs",
            (
                "2f833ed4e8c6b11701490669d96bcea63239af4e6868ff379daf3606b569ef4a",
                35_u64,
            ),
        ),
    ]);
    let source_pins = array(receipt, "current_source_pins");
    if source_pins.len() != expected_source_pins.len() {
        return Err("A3 receipt must pin the exact two source paths".to_owned());
    }
    for pin in source_pins {
        let path = text(pin, "path");
        let (expected_sha, expected_lines) = expected_source_pins
            .get(path)
            .unwrap_or_else(|| panic!("unexpected A3 source pin: {path}"));
        if text(pin, "sha256") != *expected_sha
            || pin.get("line_count").and_then(Value::as_u64) != Some(*expected_lines)
        {
            return Err(format!("A3 source pin drift: {path}"));
        }
        let bytes = read_repo_bytes(path);
        if hex_bytes(&Sha256::digest(&bytes)) != *expected_sha
            || read_repo_file(path).lines().count() as u64 != *expected_lines
        {
            return Err(format!(
                "A3 current source no longer matches receipt: {path}"
            ));
        }
    }

    let projection = object(receipt, "kernel_projection");
    let source = read_repo_file(object_text(projection, "path"));
    let start_marker = object_text(projection, "start_marker");
    let end_marker = object_text(projection, "end_marker");
    let start = source
        .find(start_marker)
        .ok_or_else(|| "A3 kernel start marker is missing".to_owned())?;
    let relative_end = source[start..]
        .find(end_marker)
        .ok_or_else(|| "A3 kernel end marker is missing".to_owned())?;
    let kernel = &source.as_bytes()[start..start + relative_end];
    if hex_bytes(&Sha256::digest(kernel)) != object_text(projection, "sha256") {
        return Err("A3 kernel projection hash drift".to_owned());
    }

    let expected_tests: BTreeSet<String> = [
        "ready_future_completes_without_parking",
        "borrowed_non_send_future_and_recursive_call_are_admitted",
        "wakes_during_poll_are_coalesced_without_parking",
        "spurious_park_return_does_not_trigger_an_unnotified_poll",
        "repeated_polls_receive_the_same_waker_identity",
        "wake_after_pending_makes_progress",
        "explicit_cancellation_wake_makes_progress",
        "future_panic_propagates_without_poisoning_kernel_state",
        "installed_runtime_context_is_refused_before_poll",
        "blocking_pool_thread_is_admitted",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if string_set(receipt, "authored_inline_tests") != expected_tests {
        return Err("A3 receipt must list the exact ten authored source cases".to_owned());
    }
    let future_source = read_repo_file("src/future.rs");
    for test_name in expected_tests {
        if !future_source.contains(&format!("fn {test_name}()")) {
            return Err(format!("A3 authored source case is missing: {test_name}"));
        }
    }

    let contexts = array(receipt, "context_policy");
    if contexts.len() != 7
        || !contexts.iter().any(|row| {
            text(row, "context") == "Asupersync runtime driver versus scheduler worker"
                && text(row, "decision") == "UNRESOLVED_CONFLATED_BY_CURRENT_HANDLE_CHECK"
                && text(row, "evidence") == "BLOCKED_GAP"
        })
        || !contexts.iter().any(|row| {
            text(row, "context") == "foreign executor thread"
                && text(row, "decision") == "UNRESOLVED_NOT_IDENTIFIABLE"
                && text(row, "evidence") == "BLOCKED_GAP"
        })
    {
        return Err("A3 context policy must preserve both unresolved boundaries".to_owned());
    }
    if array(receipt, "semantic_guarantees").len() != 9
        || array(receipt, "incumbent_production_sites").len() != 3
        || array(receipt, "missing_terminal_evidence").len() != 7
    {
        return Err("A3 semantics, incumbent sites, or evidence gaps are incomplete".to_owned());
    }

    Ok(())
}

fn validate_a4_receipt(inventory: &Value) -> Result<(), String> {
    let receipt = inventory
        .get("a4_helper_receipt")
        .expect("A4 helper receipt");
    if text(receipt, "owner_bead") != A4_BEAD_ID
        || text(receipt, "first_base_revision") != "050fd0f08e4cf127e348bbf545c1e46cc392f6b5"
        || string_set(receipt, "implementation_revisions")
            != [
                "da8d632b5ef51ea4074589aed0664cb8f5e33d41",
                "9f3684b48af00f93a6717af8575bbb4c984d5873",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        || text(receipt, "source_status") != "PARTIAL_STATIC_SOURCE_PROGRESS"
        || text(receipt, "execution_status") != "NOT_RUN_STATIC_ONLY"
        || text(receipt, "module") != "crate::util::future"
        || receipt
            .get("incumbent_call_sites_migrated")
            .and_then(Value::as_u64)
            != Some(0)
        || receipt.get("cutover_authorized") != Some(&Value::Bool(false))
        || receipt.get("closure_allowed") != Some(&Value::Bool(false))
    {
        return Err("A4 receipt must remain partial, static-only, and fail closed".to_owned());
    }

    let source_pin = object(receipt, "current_source_pin");
    if source_pin.get("path").and_then(Value::as_str) != Some("src/future.rs")
        || source_pin.get("sha256").and_then(Value::as_str)
            != Some("da6ef76c90a77c430149cabc5556343bb6408e179f62b1615c0a57b7643067b0")
        || source_pin.get("line_count").and_then(Value::as_u64) != Some(1088)
    {
        return Err("A4 current source pin drift".to_owned());
    }
    let source_bytes = read_repo_bytes("src/future.rs");
    if hex_bytes(&Sha256::digest(&source_bytes))
        != "da6ef76c90a77c430149cabc5556343bb6408e179f62b1615c0a57b7643067b0"
        || read_repo_file("src/future.rs").lines().count() != 1088
    {
        return Err("A4 current source no longer matches its receipt".to_owned());
    }

    let projection = object(receipt, "helper_projection");
    let source = read_repo_file(object_text(projection, "path"));
    let start_marker = object_text(projection, "start_marker");
    let end_marker = object_text(projection, "end_marker");
    let start = source
        .find(start_marker)
        .ok_or_else(|| "A4 helper start marker is missing".to_owned())?;
    let relative_end = source[start..]
        .find(end_marker)
        .ok_or_else(|| "A4 helper end marker is missing".to_owned())?;
    let helper_source = &source.as_bytes()[start..start + relative_end];
    if hex_bytes(&Sha256::digest(helper_source)) != object_text(projection, "sha256") {
        return Err("A4 helper projection hash drift".to_owned());
    }

    let helpers = array(receipt, "live_helper_matrix");
    let expected_helpers: BTreeMap<&str, &str> = BTreeMap::from([
        ("FUT-API-POLL-FN", "SOURCE_AUTHORED_NOT_EXECUTED"),
        ("FUT-API-POLL-ONCE", "SOURCE_AUTHORED_NOT_EXECUTED"),
        ("FUT-API-YIELD-NOW", "SOURCE_AUTHORED_NOT_EXECUTED"),
        ("FUT-API-PENDING", "SOURCE_AUTHORED_NOT_EXECUTED"),
        ("FUT-API-ZIP", "SOURCE_AUTHORED_NOT_EXECUTED"),
        ("FUT-API-OR", "SOURCE_AUTHORED_NOT_EXECUTED"),
        ("FUT-API-RACE", "MISSING_BLOCKED_POLICY"),
        ("FUT-API-JOIN-ALL-MENTION", "COMMENT_ONLY_NOT_A_LIVE_HELPER"),
    ]);
    if helpers.len() != expected_helpers.len() {
        return Err("A4 helper matrix must contain the exact corrected live set".to_owned());
    }
    for (api_id, expected_status) in expected_helpers {
        let row = find_row(helpers, "api_id", api_id);
        if text(row, "source_status") != expected_status
            || text(row, "poll_policy").is_empty()
            || text(row, "allocation_policy").is_empty()
        {
            return Err(format!("A4 helper matrix drift: {api_id}"));
        }
    }

    let expected_tests: BTreeSet<String> = [
        "poll_fn_forwards_context_and_calls_once_per_wrapper_poll",
        "poll_once_observes_ready_and_pending_without_waiting",
        "yield_now_wakes_once_then_remains_ready",
        "pending_never_completes_or_schedules_a_wake",
        "zip_polls_left_then_right_and_stops_polling_completed_children",
        "dropping_pending_zip_drops_retained_output_and_unfinished_child",
        "or_is_left_biased_and_drops_the_loser_with_the_wrapper",
        "zip_and_or_readiness_matrix_is_deterministic",
        "helper_futures_quiesce_under_lab_dpor_exploration",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if string_set(receipt, "authored_inline_tests") != expected_tests {
        return Err("A4 receipt must list the exact nine authored source cases".to_owned());
    }
    for test_name in expected_tests {
        if !source.contains(&format!("fn {test_name}()")) {
            return Err(format!("A4 authored source case is missing: {test_name}"));
        }
    }
    if source.contains("pub(crate) fn race") || source.contains("join_all") {
        return Err("A4 source must not invent the blocked race or comment-only helper".to_owned());
    }

    let race = object(receipt, "race_policy_boundary");
    if race.get("decision").and_then(Value::as_str)
        != Some("KEEP_INCUMBENT_UNTIL_STRUCTURED_RACE_POLICY")
        || race
            .get("drop_only_owned_race_allowed")
            .and_then(Value::as_bool)
            != Some(false)
        || !text(receipt, "completion_boundary").contains("post-Ready repoll")
        || array(receipt, "missing_terminal_evidence").len() != 7
    {
        return Err("A4 race, completion, or terminal-evidence boundary drift".to_owned());
    }

    Ok(())
}

fn validate_a5_receipt(inventory: &Value) -> Result<(), String> {
    let receipt = inventory
        .get("a5_panic_boundary_receipt")
        .expect("A5 panic-boundary receipt");
    if text(receipt, "owner_bead") != A5_BEAD_ID
        || text(receipt, "claimed_base_revision") != "e37de5b6c44c3c0d86c6f05a981249491d3c2343"
        || text(receipt, "source_status") != "PARTIAL_STATIC_SOURCE_PROGRESS"
        || text(receipt, "execution_status") != "NOT_RUN_STATIC_ONLY"
        || receipt.get("cutover_authorized") != Some(&Value::Bool(false))
        || receipt.get("closure_allowed") != Some(&Value::Bool(false))
    {
        return Err("A5 receipt must remain partial, static-only, and fail closed".to_owned());
    }

    let expected_source_pins = BTreeMap::from([
        (
            "src/future.rs",
            (
                "c0a02784a010e9709dfab3b40259bccf8d312e9101834d8c110f2b1f19bd8598",
                972_u64,
            ),
        ),
        (
            "src/web/middleware.rs",
            (
                "d4f6e9bbe0cb18849ce58aa293301c796ac079ad016f261d0db8affd8a0bb10a",
                6030_u64,
            ),
        ),
        (
            "src/web/negotiate.rs",
            (
                "4a98a71fe252c26e059e2bb4f0b2350a4a6e9b4bd13519f35590627788794c61",
                903_u64,
            ),
        ),
    ]);
    let source_pins = array(receipt, "current_source_pins");
    if source_pins.len() != expected_source_pins.len() {
        return Err("A5 receipt must pin the exact three source paths".to_owned());
    }
    for pin in source_pins {
        let path = text(pin, "path");
        let (expected_sha, expected_lines) = expected_source_pins
            .get(path)
            .unwrap_or_else(|| panic!("unexpected A5 source pin: {path}"));
        if text(pin, "sha256") != *expected_sha
            || pin.get("line_count").and_then(Value::as_u64) != Some(*expected_lines)
            || hex_bytes(&Sha256::digest(read_repo_bytes(path))) != *expected_sha
            || read_repo_file(path).lines().count() as u64 != *expected_lines
        {
            return Err(format!("A5 source pin drift: {path}"));
        }
    }

    let projection = object(receipt, "poll_helper_projection");
    let future_source = read_repo_file(object_text(projection, "path"));
    let start_marker = object_text(projection, "start_marker");
    let end_marker = object_text(projection, "end_marker");
    let start = future_source
        .find(start_marker)
        .ok_or_else(|| "A5 helper start marker is missing".to_owned())?;
    let relative_end = future_source[start..]
        .find(end_marker)
        .ok_or_else(|| "A5 helper end marker is missing".to_owned())?;
    let helper_source = &future_source.as_bytes()[start..start + relative_end];
    if hex_bytes(&Sha256::digest(helper_source)) != object_text(projection, "sha256") {
        return Err("A5 poll-helper projection hash drift".to_owned());
    }

    let helper = object(receipt, "poll_helper_contract");
    if helper.get("api").and_then(Value::as_str) != Some("crate::util::future::catch_unwind")
        || helper.get("drop_panic_contained").and_then(Value::as_bool) != Some(false)
        || !helper
            .get("post_terminal_behavior")
            .and_then(Value::as_str)
            .is_some_and(|value| value.contains("prevents every later inner poll"))
    {
        return Err("A5 owned poll-helper contract drift".to_owned());
    }

    let boundaries = array(receipt, "production_boundary_matrix");
    if row_ids(boundaries, "surface_id")
        != ["FUT-PROD-MIDDLEWARE-CATCH", "FUT-PROD-NEGOTIATE-CATCH"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    {
        return Err("A5 receipt must cover the exact two production boundaries".to_owned());
    }
    let middleware_boundary = find_row(boundaries, "surface_id", "FUT-PROD-MIDDLEWARE-CATCH");
    let negotiate_boundary = find_row(boundaries, "surface_id", "FUT-PROD-NEGOTIATE-CATCH");
    if !text(middleware_boundary, "operator_diagnostic").contains("ASUP-E502")
        || text(negotiate_boundary, "operator_diagnostic")
            != "missing stable code and structured log"
        || text(middleware_boundary, "source_status") != "SOURCE_AUTHORED_NOT_EXECUTED"
        || text(negotiate_boundary, "source_status") != "SOURCE_AUTHORED_NOT_EXECUTED"
    {
        return Err("A5 production diagnostic boundary drift".to_owned());
    }

    let expected_tests: BTreeSet<String> = [
        "catch_unwind_forwards_pending_wake_and_ready",
        "catch_unwind_preserves_payload_and_refuses_repoll",
        "dropping_unpolled_catch_unwind_drops_inner",
        "error_handler_catches_construction_panic",
        "error_handler_disabled_propagates_construction_panic",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if string_set(receipt, "authored_source_cases") != expected_tests {
        return Err("A5 receipt must list the exact five authored source cases".to_owned());
    }
    let negotiate_source = read_repo_file("src/web/negotiate.rs");
    for test_name in expected_tests {
        if !future_source.contains(&format!("fn {test_name}()"))
            && !negotiate_source.contains(&format!("fn {test_name}()"))
        {
            return Err(format!("A5 authored source case is missing: {test_name}"));
        }
    }

    let middleware_source = read_repo_file("src/web/middleware.rs");
    for (path, source) in [
        ("src/web/middleware.rs", &middleware_source),
        ("src/web/negotiate.rs", &negotiate_source),
    ] {
        if source.contains(&format!("use {TOKEN}::FutureExt;"))
            || source.matches("crate::util::future::catch_unwind").count() != 1
        {
            return Err(format!(
                "A5 production poll-adapter migration drift: {path}"
            ));
        }
    }
    if !middleware_source.contains("std::panic::catch_unwind")
        || !negotiate_source.contains("std::panic::catch_unwind")
    {
        return Err("both A5 production sites must contain construction panic".to_owned());
    }

    let delta = object(receipt, "dependency_token_delta");
    if delta
        .get("production_poll_adapter_sites_before")
        .and_then(Value::as_u64)
        != Some(2)
        || delta
            .get("production_poll_adapter_sites_after")
            .and_then(Value::as_u64)
            != Some(0)
        || delta
            .get("current_census_token_delta")
            .and_then(Value::as_i64)
            != Some(-2)
        || delta.get("manifest_changed").and_then(Value::as_bool) != Some(false)
        || delta
            .get("dependency_removal_authorized")
            .and_then(Value::as_bool)
            != Some(false)
        || array(receipt, "missing_terminal_evidence").len() != 8
    {
        return Err("A5 dependency delta or terminal-evidence boundary drift".to_owned());
    }

    Ok(())
}

fn validate_current_snapshot(inventory: &Value) -> Result<(), String> {
    let snapshot = inventory
        .get("post_baseline_current_snapshot")
        .expect("post-baseline current snapshot");
    if text(snapshot, "captured_date_utc") != "2026-08-06"
        || snapshot.get("historical_baseline_preserved") != Some(&Value::Bool(true))
        || text(snapshot, "source_status") != "STATIC_SOURCE_PROGRESS"
        || text(snapshot, "evidence_state") != "SOURCE_BASELINED"
        || text(snapshot, "execution_status") != "NOT_RUN_STATIC_ONLY"
        || !text(snapshot, "no_claim").contains("not executable proof")
    {
        return Err("current snapshot must remain static-only and preserve A1".to_owned());
    }

    let census = inventory
        .get("occurrence_census")
        .expect("historical occurrence census");
    if census.get("baseline_file_count").and_then(Value::as_u64) != Some(310)
        || census.get("baseline_token_count").and_then(Value::as_u64) != Some(1362)
        || text(census, "baseline_digest_sha256")
            != "899a9f62fd77ce8843c00a37902efa5ccc447ead46018a8fe14cdf2d0a241d9c"
    {
        return Err("historical A1 occurrence baseline must not be rewritten".to_owned());
    }

    let current = snapshot
        .get("current_occurrence")
        .expect("current occurrence snapshot");
    if current.get("file_count").and_then(Value::as_u64) != Some(315)
        || current.get("token_count").and_then(Value::as_u64) != Some(1382)
        || text(current, "digest_sha256")
            != "86755aabb204be53aca205404e7449a9218bb7353a3adb45fc019cddc581b30a"
        || array(current, "scope_rows").len() != 6
        || array(snapshot, "current_migration_reservation_groups").len() != 4
    {
        return Err("current occurrence snapshot is incomplete".to_owned());
    }

    let reconciliations = array(snapshot, "source_pin_reconciliations");
    let expected_paths: BTreeSet<String> = [
        "Cargo.toml",
        "Cargo.lock",
        "src/sync/notify.rs",
        "artifacts/dependency_capability_registry_v1.json",
        "artifacts/dependency_marginal_ledger_v1.json",
        "artifacts/api_surface_map_v1.json",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(reconciliations, "path") != expected_paths {
        return Err("current snapshot must reconcile the exact six drifted pins".to_owned());
    }
    let expected_reconciliations = [
        (
            "Cargo.toml",
            "5eb3d7f25fb2584dcc7dd4dc3addb59573d08a7404b4ffca1356e53a93cfb2e0",
            "CAPABILITY_PROJECTION_UNCHANGED",
            Some("81edacba422d047cd609290f9b0a95a8cda255ef326afe8d34afd7dfa7b80def"),
        ),
        (
            "Cargo.lock",
            "9fa12e8af1e6b15a3070d88d62b2b81b8ba49c0e9d8592c1d1682f1cd72a4461",
            "CAPABILITY_PROJECTION_UNCHANGED",
            Some("9260990a318c00b457e53860e1d10774e380ff818c7d7579f2d922473ade1b4b"),
        ),
        (
            "src/sync/notify.rs",
            "11d85d8cc9bcd7ec6c21245dba5b58f381b3aa4c54dc3d8d17d01f68b213a3ef",
            "CAPABILITY_PROJECTION_UNCHANGED",
            Some("ff73e9793bd9748d2e82dba7b4d16e27830b5d35491c2759021dcbb81b33b2c7"),
        ),
        (
            "artifacts/dependency_capability_registry_v1.json",
            "4d91239e2f2e83069414ca36eafc4aaba283cd3f89576fbb5e75f3374bd41b11",
            "CAPABILITY_PROJECTION_UNCHANGED",
            Some("e4440233403e24db85a0b8719e0670b5af45ff6c0728f956a9f02c8a9dba5c12"),
        ),
        (
            "artifacts/dependency_marginal_ledger_v1.json",
            "832e8d68eefe9400a246ea619a250ea91bcf16a57d5fe728a6ce45e25bbdb4a6",
            "CAPABILITY_MEASUREMENTS_UNCHANGED_METADATA_REFRESHED",
            None,
        ),
        (
            "artifacts/api_surface_map_v1.json",
            "a00b61fe82326d766cde69e2392bc493a67d3c62f9d5cd83e3e02f8b5bf5535a",
            "CAPABILITY_PROJECTION_UNCHANGED",
            None,
        ),
    ];
    let source_pins = array(inventory, "source_pins");
    for (path, baseline_sha, classification, projection_sha) in expected_reconciliations {
        let reconciliation = find_row(reconciliations, "path", path);
        let pin = find_row(source_pins, "path", path);
        if text(reconciliation, "baseline_sha256") != baseline_sha
            || text(reconciliation, "current_sha256") != text(pin, "sha256")
            || reconciliation
                .get("current_line_count")
                .and_then(Value::as_u64)
                != pin.get("line_count").and_then(Value::as_u64)
            || text(reconciliation, "classification") != classification
            || projection_sha.is_some_and(|expected| {
                reconciliation
                    .get("projection_sha256")
                    .and_then(Value::as_str)
                    != Some(expected)
            })
        {
            return Err(format!("source-pin reconciliation drift: {path}"));
        }
    }

    Ok(())
}

fn validate_state_fields(value: &Value, path: &str) -> Result<(), String> {
    match value {
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_state_fields(child, &format!("{path}[{index}]"))?;
            }
        }
        Value::Object(values) => {
            for (key, child) in values {
                let child_path = format!("{path}.{key}");
                if matches!(key.as_str(), "inventory_state" | "evidence_state" | "state")
                    && child.as_str() == Some("UNKNOWN")
                {
                    return Err(format!("{child_path} must not be UNKNOWN"));
                }
                validate_state_fields(child, &child_path)?;
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
        ("artifact_id", "futures-lite-capability-inventory-v1"),
        ("program_id", PROGRAM_ID),
        ("bead_id", BEAD_ID),
        ("capability_id", CAPABILITY_ID),
        ("baseline_revision", BASELINE_REVISION),
        ("authority_revision", AUTHORITY_REVISION),
    ] {
        if inventory.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("{key} must be {expected}"));
        }
    }

    let authority = object(inventory, "authority");
    for (key, expected) in [
        ("adr_id", "DEP-ADR-008"),
        ("decision", "KEEP_UNTIL_PARITY"),
        ("disposition", "PRESERVE_AND_REPLACE_IF_PARITY"),
        ("cutover_state", "BLOCKED_PENDING_EVIDENCE"),
    ] {
        if authority.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("authority.{key} must be {expected}"));
        }
    }
    if authority
        .get("dependency_exit_allowed")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err("authority must forbid dependency exit".to_owned());
    }

    let policy = object(inventory, "policy");
    if policy.get("zero_unknown_required").and_then(Value::as_bool) != Some(true)
        || policy.get("unknown_rows").and_then(Value::as_u64) != Some(0)
    {
        return Err("policy must require and report zero unknown rows".to_owned());
    }
    for key in ["allowed_inventory_states", "allowed_evidence_states"] {
        if string_set(inventory.get("policy").expect("policy"), key).contains("UNKNOWN") {
            return Err(format!("{key} must not permit UNKNOWN"));
        }
    }
    validate_state_fields(inventory, "$")?;
    validate_a3_receipt(inventory)?;
    validate_a4_receipt(inventory)?;
    validate_a5_receipt(inventory)?;
    validate_current_snapshot(inventory)?;

    let owned_contract_value = inventory
        .get("owned_stream_semantics_contract")
        .expect("owned Stream semantics contract");
    let expected_owned_sources: BTreeSet<String> = [
        "src/stream/stream.rs",
        "src/stream/mod.rs",
        "src/stream/next.rs",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let expected_owned_dimensions: BTreeSet<String> = [
        "pinning_and_unpin",
        "pending_and_latest_waker",
        "termination_and_fuse",
        "size_hint_trust_boundary",
        "cancellation_and_drop",
        "send_sync_and_lifetimes",
        "result_item_errors",
        "forwarding_adapters",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let expected_next_cancellation = concat!(
        "dropping Next releases its mutable borrow but does not roll back state changes ",
        "made by the underlying poll_next call"
    );
    if text(owned_contract_value, "owner_bead") != "asupersync-d24mms.6.2"
        || text(owned_contract_value, "trait") != "asupersync::stream::Stream"
        || text(owned_contract_value, "extension_trait") != "asupersync::stream::StreamExt"
        || string_set(owned_contract_value, "source_paths") != expected_owned_sources
        || string_set(owned_contract_value, "dimensions") != expected_owned_dimensions
        || text(owned_contract_value, "next_future_cancellation") != expected_next_cancellation
        || text(owned_contract_value, "documentation_state") != "SOURCE_AUTHORED_NOT_EXECUTED"
        || owned_contract_value.get("behavior_change") != Some(&Value::Bool(false))
        || owned_contract_value.get("cutover_authorized") != Some(&Value::Bool(false))
    {
        return Err("owned Stream semantics contract must remain complete and fail closed".into());
    }
    let direct_next = object(owned_contract_value, "next_direct_compile_fail");
    if direct_next.get("source").and_then(Value::as_str) != Some("src/stream/mod.rs")
        || direct_next.get("rejected_shape").and_then(Value::as_str)
            != Some("AddressSensitive: !Unpin; direct StreamExt::next call")
        || direct_next.get("required_bound").and_then(Value::as_str) != Some("Self: Unpin")
        || direct_next
            .get("implementation_state")
            .and_then(Value::as_str)
            != Some("SOURCE_AUTHORED_NOT_EXECUTED")
    {
        return Err("direct next compile-fail contract must remain source-only".into());
    }

    let a2_status = inventory
        .get("a2_acceptance_status")
        .expect("A2 acceptance status");
    if text(a2_status, "owner_bead") != "asupersync-d24mms.6.2"
        || text(a2_status, "overall_status") != "PARTIAL_SOURCE_ONLY"
        || a2_status.get("closure_allowed") != Some(&Value::Bool(false))
    {
        return Err("A2 acceptance status must remain partial and fail closed".to_owned());
    }
    let a2_requirements = array(a2_status, "requirements");
    let expected_a2_requirements: BTreeSet<String> = [
        "FUT-A2-OWNED-API",
        "FUT-A2-DOWNSTREAM-ERGONOMICS",
        "FUT-A2-COMPILE-FAIL-RUSTDOC",
        "FUT-A2-PIN-DROP-BOUNDS",
        "FUT-A2-ERROR-ADAPTER",
        "FUT-A2-ATP-RUNTIME-E2E",
        "FUT-A2-USER-TRIAL",
        "FUT-A2-CUTOVER",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(a2_requirements, "requirement_id") != expected_a2_requirements {
        return Err("A2 acceptance matrix must contain the exact requirement set".to_owned());
    }
    for (requirement_id, source_status, terminal_status) in [
        (
            "FUT-A2-OWNED-API",
            "AUTHORED_NOT_EXECUTED",
            "MISSING_FOCUSED_COMPILE",
        ),
        (
            "FUT-A2-DOWNSTREAM-ERGONOMICS",
            "AUTHORED_NOT_EXECUTED",
            "MISSING_FIXTURE_EXECUTION",
        ),
        (
            "FUT-A2-COMPILE-FAIL-RUSTDOC",
            "AUTHORED_NOT_EXECUTED",
            "MISSING_RUSTDOC_EXECUTION",
        ),
        (
            "FUT-A2-PIN-DROP-BOUNDS",
            "AUTHORED_NOT_EXECUTED",
            "MISSING_BEHAVIOR_EXECUTION",
        ),
        (
            "FUT-A2-ERROR-ADAPTER",
            "AUTHORED_NOT_EXECUTED",
            "MISSING_BEHAVIOR_EXECUTION",
        ),
        (
            "FUT-A2-ATP-RUNTIME-E2E",
            "MISSING_RUNTIME_SCENARIO",
            "MISSING",
        ),
        (
            "FUT-A2-USER-TRIAL",
            "MISSING",
            "MISSING_SAME_OR_BETTER_RECEIPT",
        ),
        ("FUT-A2-CUTOVER", "BLOCKED", "BLOCKED_PENDING_ALL_RECEIPTS"),
    ] {
        let requirement = find_row(a2_requirements, "requirement_id", requirement_id);
        if text(requirement, "source_status") != source_status
            || text(requirement, "terminal_status") != terminal_status
        {
            return Err(format!("A2 requirement status drift: {requirement_id}"));
        }
    }
    let expected_a2_receipts: BTreeSet<String> = [
        "focused compile",
        "compile-fail rustdoc",
        "downstream fixture",
        "ATP runtime E2E",
        "SAME-or-BETTER user trial",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if string_set(a2_status, "required_terminal_receipts") != expected_a2_receipts {
        return Err("A2 terminal receipt set must remain complete".to_owned());
    }

    let expected_profiles: BTreeSet<String> = [
        "FUT-PROFILE-ROOT-NORMAL",
        "FUT-PROFILE-ROOT-UNIT",
        "FUT-PROFILE-ROOT-INTEGRATION",
        "FUT-PROFILE-ROOT-BENCH",
        "FUT-PROFILE-ROOT-EXAMPLE",
        "FUT-PROFILE-TOKIO-COMPAT-NORMAL",
        "FUT-PROFILE-TOKIO-COMPAT-TEST",
        "FUT-PROFILE-FUZZ",
        "FUT-PROFILE-WASM",
        "FUT-PROFILE-CONFORMANCE",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(array(inventory, "cargo_built_profiles"), "profile_id") != expected_profiles {
        return Err("Cargo-built profiles must cover the exact ten classified profiles".to_owned());
    }

    let surfaces = array(inventory, "production_surfaces");
    let expected_surfaces: BTreeSet<String> = [
        "FUT-PROD-ATP-STREAM",
        "FUT-PROD-MIDDLEWARE-CATCH",
        "FUT-PROD-NEGOTIATE-CATCH",
        "FUT-PROD-ROUTER-BLOCK",
        "FUT-PROD-RELOAD-BLOCK",
        "FUT-PROD-SHUTDOWN-BLOCK",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(surfaces, "surface_id") != expected_surfaces {
        return Err("production surface inventory must contain the exact six sites".to_owned());
    }
    let atp_surface = find_row(surfaces, "surface_id", "FUT-PROD-ATP-STREAM");
    let owned_surface = object(atp_surface, "owned_parallel_surface");
    if owned_surface.get("api").and_then(Value::as_str) != Some("asupersync::stream::Stream")
        || owned_surface
            .get("behavioral_impl_count")
            .and_then(Value::as_u64)
            != Some(2)
        || owned_surface
            .get("shared_poll_kernel")
            .and_then(Value::as_str)
            != Some("poll_progress")
        || owned_surface
            .get("implementation_state")
            .and_then(Value::as_str)
            != Some("SOURCE_AUTHORED_NOT_EXECUTED")
        || owned_surface
            .get("cutover_authorized")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("owned ATP Stream progress must remain source-only and fail closed".to_owned());
    }
    let token_total: u64 = surfaces
        .iter()
        .map(|row| {
            row.get("token_occurrences")
                .and_then(Value::as_u64)
                .expect("token_occurrences")
        })
        .sum();
    let behavior_total: u64 = surfaces
        .iter()
        .map(|row| {
            row.get("behavioral_impl_count")
                .and_then(Value::as_u64)
                .expect("behavioral_impl_count")
        })
        .sum();
    if token_total != 6 || behavior_total != 7 {
        return Err("six production tokens must preserve seven behaviors".to_owned());
    }

    let expected_apis: BTreeSet<String> = [
        "FUT-API-BLOCK-ON",
        "FUT-API-POLL-FN",
        "FUT-API-POLL-ONCE",
        "FUT-API-YIELD-NOW",
        "FUT-API-ZIP",
        "FUT-API-RACE",
        "FUT-API-OR",
        "FUT-API-PENDING",
        "FUT-API-CATCH-UNWIND",
        "FUT-API-STREAM",
        "FUT-API-JOIN-ALL-MENTION",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let api_rows = array(inventory, "consumed_api_semantics");
    if row_ids(api_rows, "api_id") != expected_apis {
        return Err(
            "consumed API inventory must contain the exact live set and join-all correction".into(),
        );
    }
    for row in api_rows {
        for field in [
            "poll_order",
            "wake_behavior",
            "completion",
            "cancellation",
            "panic",
            "send_lifetime",
            "replacement_owner",
        ] {
            if text(row, field).is_empty() {
                return Err(format!(
                    "{}.{} must be non-empty",
                    text(row, "api_id"),
                    field
                ));
            }
        }
    }
    if text(
        find_row(api_rows, "api_id", "FUT-API-JOIN-ALL-MENTION"),
        "classification",
    ) != "COMMENT_ONLY"
        || text(find_row(api_rows, "api_id", "FUT-API-OR"), "classification") != "CONSUMED"
    {
        return Err("join_all must be comment-only and or must be consumed".to_owned());
    }

    let expected_groups: BTreeSet<String> = [
        "FUT-A6-CORE",
        "FUT-A7-IO",
        "FUT-A8-SERVICES",
        "FUT-A9-ATP-DEV",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(array(inventory, "migration_reservation_groups"), "group_id") != expected_groups {
        return Err("migration reservation groups must partition A6 through A9".to_owned());
    }

    let gaps = array(inventory, "gaps");
    let expected_gaps: BTreeSet<String> = [
        "FUT-GAP-01",
        "FUT-GAP-02",
        "FUT-GAP-03",
        "FUT-GAP-04",
        "FUT-GAP-05",
        "FUT-GAP-06",
        "FUT-GAP-07",
        "FUT-A1-GAP-08",
        "FUT-A1-GAP-09",
        "FUT-A1-GAP-10",
        "FUT-A1-GAP-11",
        "FUT-A1-GAP-12",
        "FUT-A3-GAP-13",
        "FUT-A3-GAP-14",
        "FUT-A3-GAP-15",
        "FUT-A4-GAP-16",
        "FUT-A4-GAP-17",
        "FUT-A4-GAP-18",
        "FUT-A5-GAP-19",
        "FUT-A5-GAP-20",
        "FUT-A5-GAP-21",
        "FUT-A5-GAP-22",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(gaps, "gap_id") != expected_gaps {
        return Err("all ADR and A1 through A5 gaps must remain routed".to_owned());
    }

    let journeys = array(inventory, "downstream_and_e2e");
    let owned_journey = find_row(journeys, "journey_id", "FUT-JOURNEY-OWNED-STREAM");
    let owned_atp = owned_journey
        .get("owned_atp_progress_compile_contract")
        .expect("owned ATP downstream compile contract");
    let expected_owned_types: BTreeSet<String> = ["AtpWriter", "AtpReader"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    if string_set(owned_atp, "types") != expected_owned_types
        || owned_atp.get("trait").and_then(Value::as_str)
            != Some("asupersync::stream::Stream<Item = TransferProgress>")
        || owned_atp.get("extension_method").and_then(Value::as_str) != Some("StreamExt::next")
        || owned_atp
            .get("implementation_state")
            .and_then(Value::as_str)
            != Some("SOURCE_AUTHORED_NOT_EXECUTED")
    {
        return Err("owned ATP downstream progress must remain source-only".to_owned());
    }
    let pinned_local = owned_journey
        .get("pinned_local_downstream_contract")
        .expect("pinned local downstream contract");
    let expected_pinned_properties: BTreeSet<String> = [
        "borrowed_non_static",
        "rc_local_not_send_or_sync",
        "phantom_pinned_not_unpin",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let expected_pinned_observations: BTreeSet<String> = [
        "forwarded size_hint",
        "dropped unpolled Next preserves the item",
        "one item then EOF",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if text(pinned_local, "type") != "DownstreamPinnedLocalStream<'_>"
        || string_set(pinned_local, "properties") != expected_pinned_properties
        || text(pinned_local, "forwarding_adapter") != "Pin<Box<S>> through impl Stream for Pin<P>"
        || text(pinned_local, "extension_method") != "StreamExt::next on Pin<Box<S>>"
        || string_set(pinned_local, "observations") != expected_pinned_observations
        || text(pinned_local, "implementation_state") != "SOURCE_AUTHORED_NOT_EXECUTED"
    {
        return Err("pinned local downstream contract must remain source-only".to_owned());
    }
    let fallible = object(owned_journey, "fallible_terminal_compile_contract");
    if fallible.get("item").and_then(Value::as_str) != Some("Result<u32, &'static str>")
        || fallible.get("adapter").and_then(Value::as_str)
            != Some("StreamExt::try_collect::<u32, &'static str, Vec<u32>>")
        || fallible.get("implementation_state").and_then(Value::as_str)
            != Some("SOURCE_AUTHORED_NOT_EXECUTED")
    {
        return Err("fallible downstream contract must remain source-only".to_owned());
    }

    if journeys.len() != 4
        || array(inventory, "rollback_triggers").len() < 8
        || array(inventory, "no_claim_boundaries").len() < 7
    {
        return Err("downstream, rollback, and no-claim ledgers are incomplete".to_owned());
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OccurrenceRow {
    path: String,
    count: usize,
}

fn collect_rs_files(dir: &Path, files: &mut Vec<PathBuf>) {
    if !dir.exists() {
        return;
    }
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let relative = path
            .strip_prefix(repo_root())
            .expect("repository-relative path")
            .to_string_lossy()
            .replace('\\', "/");
        if relative == "tests/tests"
            || relative.starts_with("tests/tests/")
            || relative == "target"
            || relative.starts_with("target/")
        {
            continue;
        }
        if path.is_dir() {
            collect_rs_files(&path, files);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs")
            && relative != SELF_PATH
        {
            files.push(path);
        }
    }
}

fn occurrence_rows_for_scope(scope: &str) -> Vec<OccurrenceRow> {
    let mut files = Vec::new();
    collect_rs_files(&repo_root().join(scope), &mut files);
    let mut rows = Vec::new();
    for path in files {
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let source = String::from_utf8(bytes)
            .unwrap_or_else(|error| panic!("{} must be UTF-8: {error}", path.display()));
        let count = source.match_indices(TOKEN).count();
        if count != 0 {
            rows.push(OccurrenceRow {
                path: path
                    .strip_prefix(repo_root())
                    .expect("repository-relative path")
                    .to_string_lossy()
                    .replace('\\', "/"),
                count,
            });
        }
    }
    rows.sort_by(|left, right| left.path.cmp(&right.path));
    rows
}

fn all_occurrence_rows() -> Vec<OccurrenceRow> {
    let mut rows = Vec::new();
    for scope in [
        "src",
        "tests",
        "benches",
        "examples",
        "asupersync-tokio-compat",
        "fuzz",
    ] {
        rows.extend(occurrence_rows_for_scope(scope));
    }
    rows.sort_by(|left, right| left.path.cmp(&right.path));
    rows
}

fn rows_digest(rows: &[OccurrenceRow]) -> String {
    let mut hasher = Sha256::new();
    for row in rows {
        hasher.update(row.path.as_bytes());
        hasher.update(b"\t");
        hasher.update(row.count.to_string().as_bytes());
        hasher.update(b"\n");
    }
    hex_bytes(&hasher.finalize())
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn route_group(path: &str) -> &'static str {
    if path.starts_with("tests/")
        || path.starts_with("benches/")
        || path.starts_with("examples/")
        || path.starts_with("asupersync-tokio-compat/")
        || path.starts_with("fuzz/")
        || path.starts_with("src/atp/")
        || path.starts_with("src/net/atp/")
        || path.starts_with("src/transport/")
        || path.starts_with("src/real_")
        || path.ends_with("_conformance_tests.rs")
        || path == "src/io_bytes_time_conformance_tests.rs"
        || path == "src/sync_primitives_conformance_tests.rs"
    {
        "FUT-A9-ATP-DEV"
    } else if [
        "src/web/",
        "src/http/",
        "src/grpc/",
        "src/database/",
        "src/messaging/",
        "src/distributed/",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
    {
        "FUT-A8-SERVICES"
    } else if [
        "src/fs/",
        "src/io/",
        "src/net/",
        "src/tls/",
        "src/time/",
        "src/signal/",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
        || path == "src/process.rs"
    {
        "FUT-A7-IO"
    } else if path.starts_with("src/") {
        "FUT-A6-CORE"
    } else {
        panic!("unrouted occurrence path: {path}");
    }
}

#[test]
fn identity_authority_zero_unknown_and_docs_are_fail_closed() {
    let inventory = artifact();
    validate_inventory(&inventory).expect("canonical inventory must validate");

    let doc = read_repo_file(DOC_PATH);
    let begin = doc.find(DOC_BEGIN).expect("doc begin marker");
    let end = doc.find(DOC_END).expect("doc end marker");
    assert!(begin < end);
    for required in [
        "KEEP_UNTIL_PARITY",
        "817",
        "150",
        "1362",
        "310",
        "no `join_all`",
        "`future::or`",
        "Dropping a race loser is not",
        "documentation-contract base revision",
        "former blanket claim that every stream poll is losslessly",
        "pinned-downstream base revision",
        "DownstreamPinnedLocalStream<'_>",
        "Neither case has been compiled or run",
        "StreamExt::try_collect::<u32, &'static str, Vec<u32>>",
        "A2 acceptance status",
        "does not authorize closing A2",
        "source-authored and unexecuted",
        "Post-baseline current snapshot",
        "315",
        "1,382",
        "FUT A3 static kernel progress",
        "STATIC_SOURCE_PROGRESS",
        "NOT_RUN_STATIC_ONLY",
        "FUT-A3-GAP-13",
        "FUT-A3-GAP-14",
        "FUT-A3-GAP-15",
        "FUT A4 static helper progress",
        "PARTIAL_STATIC_SOURCE_PROGRESS",
        "KEEP_INCUMBENT_UNTIL_STRUCTURED_RACE_POLICY",
        "FUT-A4-GAP-16",
        "FUT-A4-GAP-17",
        "FUT-A4-GAP-18",
        "FUT A5 static panic-boundary progress",
        "crate::util::future::catch_unwind",
        "FUT-A5-GAP-19",
        "FUT-A5-GAP-20",
        "FUT-A5-GAP-21",
        "FUT-A5-GAP-22",
        "No-claim boundary",
    ] {
        assert!(doc.contains(required), "missing docs marker: {required}");
    }

    let adr = read_repo_file(ADR_PATH);
    assert!(adr.contains("Decision: `KEEP_UNTIL_PARITY`"));
    assert!(adr.contains("BLOCKED_PENDING_EVIDENCE"));

    let registry = parse_repo_json(CAPABILITY_REGISTRY_PATH);
    let capability = array(&registry, "capabilities")
        .iter()
        .find(|row| row.get("capability_id").and_then(Value::as_str) == Some(CAPABILITY_ID))
        .expect("CAP-FUTURES-STREAMS registry row");
    assert_eq!(
        capability.get("disposition").and_then(Value::as_str),
        Some("PRESERVE_AND_REPLACE_IF_PARITY")
    );
    assert_eq!(
        capability.get("cutover_state").and_then(Value::as_str),
        Some("BLOCKED_PENDING_EVIDENCE")
    );
}

#[test]
fn source_pins_and_manifest_resolution_are_exact() {
    let inventory = artifact();
    for pin in array(&inventory, "source_pins") {
        let path = text(pin, "path");
        let bytes = read_repo_bytes(path);
        let digest = hex_bytes(&Sha256::digest(&bytes));
        assert_eq!(digest, text(pin, "sha256"), "source pin drift: {path}");
        let line_count = read_repo_file(path).lines().count() as u64;
        assert_eq!(
            Some(line_count),
            pin.get("line_count").and_then(Value::as_u64),
            "line count drift: {path}"
        );
    }

    let root_manifest = read_repo_file("Cargo.toml");
    assert!(root_manifest.contains("futures-lite = \"2.6\""));
    assert!(!root_manifest.contains("futures-lite = {"));
    let compat_manifest = read_repo_file("asupersync-tokio-compat/Cargo.toml");
    let dev_dependencies = compat_manifest
        .split("[dev-dependencies]")
        .nth(1)
        .expect("compat dev-dependencies");
    assert!(dev_dependencies.contains("futures-lite = \"2\""));
    assert_eq!(
        read_repo_file("Cargo.lock")
            .matches("name = \"futures-lite\"")
            .count(),
        1
    );
    assert!(read_repo_file("Cargo.lock").contains("version = \"2.6.1\""));

    let resolution = object(&inventory, "dependency_resolution");
    let root_resolution = resolution.get("root_manifest").expect("root_manifest");
    assert_eq!(
        string_set(root_resolution, "default_features"),
        ["race", "std"].into_iter().map(str::to_owned).collect()
    );
}

#[test]
fn occurrence_census_and_reservation_partition_are_exact() {
    let inventory = artifact();
    let census = inventory
        .get("occurrence_census")
        .expect("occurrence_census");
    assert_eq!(
        census.get("baseline_file_count").and_then(Value::as_u64),
        Some(310)
    );
    assert_eq!(
        census.get("baseline_token_count").and_then(Value::as_u64),
        Some(1362)
    );

    let snapshot = inventory
        .get("post_baseline_current_snapshot")
        .expect("post-baseline current snapshot");
    let current = snapshot
        .get("current_occurrence")
        .expect("current occurrence snapshot");
    let all_rows = all_occurrence_rows();
    let all_count: usize = all_rows.iter().map(|row| row.count).sum();
    assert_eq!(
        all_rows.len() as u64,
        current
            .get("file_count")
            .and_then(Value::as_u64)
            .expect("current file_count")
    );
    assert_eq!(
        all_count as u64,
        current
            .get("token_count")
            .and_then(Value::as_u64)
            .expect("current token_count")
    );
    assert_eq!(rows_digest(&all_rows), text(current, "digest_sha256"));

    for scope_row in array(current, "scope_rows") {
        let scope = text(scope_row, "scope");
        let rows = occurrence_rows_for_scope(scope);
        let count: usize = rows.iter().map(|row| row.count).sum();
        assert_eq!(
            rows.len() as u64,
            scope_row
                .get("file_count")
                .and_then(Value::as_u64)
                .expect("file_count"),
            "scope file count drift: {scope}"
        );
        assert_eq!(
            count as u64,
            scope_row
                .get("token_count")
                .and_then(Value::as_u64)
                .expect("token_count"),
            "scope token count drift: {scope}"
        );
        assert_eq!(
            rows_digest(&rows),
            text(scope_row, "digest_sha256"),
            "scope digest drift: {scope}"
        );
    }

    assert_eq!(read_repo_file(SELF_PATH).match_indices(TOKEN).count(), 1);

    let historical_groups = array(&inventory, "migration_reservation_groups");
    let expected_historical_groups = BTreeMap::from([
        ("FUT-A6-CORE", (42_u64, 258_u64)),
        ("FUT-A7-IO", (31_u64, 145_u64)),
        ("FUT-A8-SERVICES", (33_u64, 196_u64)),
        ("FUT-A9-ATP-DEV", (204_u64, 763_u64)),
    ]);
    for group in historical_groups {
        let (expected_files, expected_tokens) = expected_historical_groups
            .get(text(group, "group_id"))
            .expect("known historical migration group");
        assert_eq!(
            group.get("file_count").and_then(Value::as_u64),
            Some(*expected_files)
        );
        assert_eq!(
            group.get("token_count").and_then(Value::as_u64),
            Some(*expected_tokens)
        );
    }

    let groups = array(snapshot, "current_migration_reservation_groups");
    for group in groups {
        let group_id = text(group, "group_id");
        let rows: Vec<_> = all_rows
            .iter()
            .filter(|row| route_group(&row.path) == group_id)
            .cloned()
            .collect();
        let count: usize = rows.iter().map(|row| row.count).sum();
        assert_eq!(
            rows.len() as u64,
            group.get("file_count").and_then(Value::as_u64).unwrap(),
            "group file count drift: {group_id}"
        );
        assert_eq!(
            count as u64,
            group.get("token_count").and_then(Value::as_u64).unwrap(),
            "group token count drift: {group_id}"
        );
        assert_eq!(
            rows_digest(&rows),
            text(group, "digest_sha256"),
            "group digest drift: {group_id}"
        );
    }
}

#[test]
fn production_public_and_comment_only_sites_match_source() {
    let stream = read_repo_file("src/net/atp/sdk/stream.rs");
    assert!(stream.contains(&format!("use {TOKEN}::Stream;")));
    assert_eq!(stream.matches("impl Stream for AtpWriter").count(), 1);
    assert_eq!(stream.matches("impl Stream for AtpReader").count(), 1);
    assert_eq!(
        stream
            .matches("impl crate::stream::Stream for AtpWriter")
            .count(),
        1
    );
    assert_eq!(
        stream
            .matches("impl crate::stream::Stream for AtpReader")
            .count(),
        1
    );
    assert_eq!(stream.matches("fn poll_progress(").count(), 1);
    let progress_kernel = stream
        .split_once("fn poll_progress(")
        .expect("owned progress kernel")
        .1
        .split_once("// Keep the incumbent public trait implementations")
        .expect("owned progress kernel terminator")
        .0;
    assert_eq!(
        progress_kernel.matches("cx.waker().wake_by_ref();").count(),
        1
    );
    assert!(stream.contains("obligation.resolve(Resolution::Abort)"));

    let middleware = read_repo_file("src/web/middleware.rs");
    assert!(!middleware.contains(&format!("use {TOKEN}::FutureExt;")));
    assert!(middleware.contains("std::panic::catch_unwind"));
    assert!(
        middleware.contains("crate::util::future::catch_unwind(AssertUnwindSafe(future)).await")
    );
    assert!(middleware.contains("[ASUP-E502] web handler panic recovered"));

    let negotiate = read_repo_file("src/web/negotiate.rs");
    assert!(!negotiate.contains(&format!("use {TOKEN}::FutureExt;")));
    assert!(negotiate.contains("std::panic::catch_unwind"));
    assert!(
        negotiate.contains("crate::util::future::catch_unwind(AssertUnwindSafe(future)).await")
    );

    let router = read_repo_file("src/web/router.rs");
    assert!(router.contains("pub fn handle(&self, req: Request) -> Response"));
    assert!(router.contains(&format!(
        "{TOKEN}::future::block_on(self.handle_with_cx(&cx, req))"
    )));

    let signal = read_repo_file("src/signal/shutdown.rs");
    assert_eq!(
        signal
            .matches(&format!("{TOKEN}::future::block_on(stream.recv())"))
            .count(),
        2
    );
    assert!(signal.contains("asupersync-reload-sighup"));
    assert!(signal.contains("asupersync-shutdown-"));

    let notify = read_repo_file("src/sync/notify.rs");
    assert_eq!(
        notify
            .matches(&format!("{TOKEN}::future::block_on(async"))
            .count(),
        2
    );

    let baseline_rows = all_occurrence_rows();
    let join_all_pattern = format!("{TOKEN}::future::join_all");
    let join_all_rows: Vec<_> = baseline_rows
        .iter()
        .filter(|row| read_repo_file(&row.path).contains(&join_all_pattern))
        .collect();
    assert_eq!(join_all_rows.len(), 1);
    assert_eq!(join_all_rows[0].path, "src/sync/notify_metamorphic.rs");
    let join_source = read_repo_file(&join_all_rows[0].path);
    let join_line = join_source
        .lines()
        .find(|line| line.contains(&join_all_pattern))
        .expect("join_all mention");
    assert!(join_line.trim_start().starts_with("//"));

    let channel = read_repo_file("tests/channel_conformance.rs");
    assert!(channel.contains(&format!("use {TOKEN}::future;")));
    assert_eq!(channel.matches("future::or(").count(), 2);

    let downstream =
        read_repo_file("tests/fixtures/dependency-capability-baseline-consumer/src/lib.rs");
    assert!(downstream.contains("use asupersync::stream::{Stream, StreamExt};"));
    assert!(!downstream.contains(TOKEN));
    assert!(downstream.contains("use asupersync::net::atp::sdk::{"));
    assert!(downstream.contains("AtpReader, AtpWriter, TransferProgress"));
    assert!(downstream.contains("assert_owned_progress_stream::<AtpWriter>();"));
    assert!(downstream.contains("assert_owned_progress_stream::<AtpReader>();"));
    assert!(downstream.contains("next_owned_progress::<AtpWriter>"));
    assert!(downstream.contains("next_owned_progress::<AtpReader>"));
    assert!(downstream.contains("struct DownstreamPinnedLocalStream<'a>"));
    assert!(downstream.contains("_local_only: Rc<()>"));
    assert!(downstream.contains("_pin: PhantomPinned"));
    assert!(downstream.contains("item: &'a Cell<Option<u32>>"));
    assert!(downstream.contains("Stream::size_hint(&stream)"));
    assert!(downstream.contains("let _pending_next = stream.next();"));
    assert!(downstream.contains("poll_stream_once(Pin::new(&mut stream))"));
    assert!(downstream.contains("downstream_fallible_stream_terminal_adapter_compile_contract"));
    assert!(downstream.contains("Err(\"downstream error\")"));
    assert!(downstream.contains("try_collect::<u32, &'static str, Vec<u32>>()"));
}

#[test]
fn owned_stream_semantics_are_explicit_and_fail_closed() {
    let stream = read_repo_file("src/stream/stream.rs");
    for required in [
        "defines a polling protocol, not a blanket losslessness promise",
        "P::Target: Unpin",
        "later poll arriving with a different",
        "require subsequent polls to keep returning `None`",
        "must not be used for correctness",
        "adds no `Send`, `Sync`, `Unpin`, or `'static` requirement",
        "Item = Result<T, E>",
        "impl<P> Stream for Pin<P>",
        "impl<S: Stream + Unpin + ?Sized> Stream for Box<S>",
        "impl<S: Stream + Unpin + ?Sized> Stream for &mut S",
    ] {
        assert!(
            stream.contains(required),
            "missing Stream marker: {required}"
        );
    }
    assert!(!stream.contains("The Stream trait is inherently cancel-safe"));
    assert!(!stream.contains("This method is cancel-safe"));

    let extension = read_repo_file("src/stream/mod.rs");
    for required in [
        "Neither trait adds a global `Send`, `Sync`, `Unpin`, or `'static` bound",
        "Cancellation and drop behavior is adapter-specific",
        "Dropping the returned future before it resolves releases the mutable",
        "Address-sensitive (`!Unpin`) streams",
        "```compile_fail",
        "struct AddressSensitive",
        "let _next = stream.next(); // `AddressSensitive` does not implement `Unpin`.",
    ] {
        assert!(
            extension.contains(required),
            "missing StreamExt marker: {required}"
        );
    }

    let next = read_repo_file("src/stream/next.rs");
    for required in [
        "Dropping it before completion releases its mutable borrow",
        "does not undo state changes",
        "completed `Next` is fused",
    ] {
        assert!(next.contains(required), "missing Next marker: {required}");
    }
}

#[test]
fn marginal_ledger_distinguishes_production_exit_from_dev_retention() {
    let inventory = artifact();
    let expected = inventory
        .get("marginal_counterfactual")
        .expect("marginal_counterfactual");
    let ledger = parse_repo_json(MARGINAL_LEDGER_PATH);
    let rows: Vec<_> = array(&ledger, "marginal_measurements")
        .iter()
        .filter(|row| {
            row.get("direct_root_edge").and_then(Value::as_str) == Some("normal:futures-lite")
        })
        .collect();
    assert_eq!(
        rows.len() as u64,
        expected.get("cell_count").and_then(Value::as_u64).unwrap()
    );

    let profiles: BTreeSet<_> = rows
        .iter()
        .map(|row| text(row, "feature_profile").to_owned())
        .collect();
    let targets: BTreeSet<_> = rows
        .iter()
        .map(|row| text(row, "target_triple").to_owned())
        .collect();
    assert_eq!(profiles.len(), 13);
    assert_eq!(targets.len(), 4);

    let mut histogram = BTreeMap::<u64, u64>::new();
    let mut zero_cells = BTreeSet::new();
    for row in rows {
        let count = row
            .get("marginal_package_version_count")
            .and_then(Value::as_u64)
            .expect("marginal_package_version_count");
        *histogram.entry(count).or_default() += 1;
        if count == 0 {
            zero_cells.insert(format!(
                "{}@{}",
                text(row, "feature_profile"),
                text(row, "target_triple")
            ));
        }
        assert_eq!(
            row.get("unsafe_exposure_class").and_then(Value::as_str),
            Some("SAFE-OWN")
        );
        assert!(array(row, "proc_macros").is_empty());
        assert!(array(row, "build_scripts").is_empty());
        assert_eq!(
            row.get("marginal_native_code")
                .and_then(Value::as_object)
                .and_then(|value| value.get("status"))
                .and_then(Value::as_str),
            Some("none")
        );
    }
    assert_eq!(
        histogram,
        BTreeMap::from([(0, 4), (3, 21), (4, 13), (5, 14)])
    );
    assert_eq!(zero_cells, string_set(expected, "zero_marginal_cells"));
}

struct WakeCounter(AtomicUsize);

impl Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct LogReady {
    name: &'static str,
    log: Rc<RefCell<Vec<&'static str>>>,
    output: usize,
}

impl Future for LogReady {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.log.borrow_mut().push(self.name);
        Poll::Ready(self.output)
    }
}

struct ReadyTracked {
    dropped: Arc<AtomicBool>,
}

impl Future for ReadyTracked {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(7)
    }
}

impl Drop for ReadyTracked {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

struct PendingTracked {
    dropped: Arc<AtomicBool>,
}

impl Future for PendingTracked {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

impl Drop for PendingTracked {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

struct PanicOnPoll;

impl Future for PanicOnPoll {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        panic!("inventory panic probe")
    }
}

#[test]
fn incumbent_helper_probes_freeze_poll_wake_drop_and_lifetime_semantics() {
    let local = Rc::new(Cell::new(40));
    let borrowed = Rc::clone(&local);
    let nested = incumbent::future::block_on(async {
        borrowed.set(borrowed.get() + 1);
        incumbent::future::block_on(async { borrowed.get() + 1 })
    });
    assert_eq!(
        nested, 42,
        "block_on accepts borrowed non-Send state and recursion"
    );

    let polls = Rc::new(Cell::new(0));
    let polls_for_future = Rc::clone(&polls);
    let result = incumbent::future::block_on(incumbent::future::poll_fn(move |cx| {
        let next = polls_for_future.get() + 1;
        polls_for_future.set(next);
        if next == 1 {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(11)
        }
    }));
    assert_eq!(result, 11);
    assert_eq!(polls.get(), 2);

    assert_eq!(
        incumbent::future::block_on(incumbent::future::poll_once(incumbent::future::ready(5))),
        Some(5)
    );
    assert_eq!(
        incumbent::future::block_on(incumbent::future::poll_once(incumbent::future::pending::<
            usize,
        >())),
        None
    );

    let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);
    let mut yielded = std::pin::pin!(incumbent::future::yield_now());
    assert!(yielded.as_mut().poll(&mut cx).is_pending());
    assert_eq!(wake_counter.0.load(Ordering::SeqCst), 1);
    assert!(yielded.as_mut().poll(&mut cx).is_ready());

    let log = Rc::new(RefCell::new(Vec::new()));
    let zipped = incumbent::future::block_on(incumbent::future::zip(
        LogReady {
            name: "left",
            log: Rc::clone(&log),
            output: 1,
        },
        LogReady {
            name: "right",
            log: Rc::clone(&log),
            output: 2,
        },
    ));
    assert_eq!(zipped, (1, 2));
    assert_eq!(&*log.borrow(), &["left", "right"]);

    assert_eq!(
        incumbent::future::block_on(incumbent::future::or(
            incumbent::future::ready(1),
            incumbent::future::ready(2)
        )),
        1,
        "or is left-biased when both futures are ready"
    );

    let winner_dropped = Arc::new(AtomicBool::new(false));
    let loser_dropped = Arc::new(AtomicBool::new(false));
    let winner = incumbent::future::block_on(incumbent::future::race(
        ReadyTracked {
            dropped: Arc::clone(&winner_dropped),
        },
        PendingTracked {
            dropped: Arc::clone(&loser_dropped),
        },
    ));
    assert_eq!(winner, 7);
    assert!(winner_dropped.load(Ordering::SeqCst));
    assert!(
        loser_dropped.load(Ordering::SeqCst),
        "incumbent race drops rather than drains its loser"
    );

    let caught =
        incumbent::future::block_on(std::panic::AssertUnwindSafe(PanicOnPoll).catch_unwind());
    assert!(caught.is_err());
}

#[test]
fn public_stream_impls_compile_but_downstream_evidence_remains_planned() {
    fn assert_progress_stream<S>()
    where
        S: Stream<Item = TransferProgress>,
    {
    }
    fn assert_owned_progress_stream<S>()
    where
        S: OwnedStream<Item = TransferProgress>,
    {
    }

    assert_progress_stream::<AtpWriter>();
    assert_progress_stream::<AtpReader>();
    assert_owned_progress_stream::<AtpWriter>();
    assert_owned_progress_stream::<AtpReader>();

    let inventory = artifact();
    let journeys = array(&inventory, "downstream_and_e2e");
    let owned_journey = find_row(journeys, "journey_id", "FUT-JOURNEY-OWNED-STREAM");
    assert_eq!(text(owned_journey, "state"), "EXISTING_TEST");
    assert_eq!(
        owned_journey
            .get("owned_atp_progress_compile_contract")
            .and_then(|value| value.get("implementation_state"))
            .and_then(Value::as_str),
        Some("SOURCE_AUTHORED_NOT_EXECUTED")
    );
    for journey_id in [
        "FUT-JOURNEY-ECOSYSTEM-STREAM",
        "FUT-JOURNEY-STREAM-CANCEL",
        "FUT-JOURNEY-TEST-BLOCK",
    ] {
        assert_eq!(
            text(find_row(journeys, "journey_id", journey_id), "state"),
            "PLANNED",
            "{journey_id} must not be promoted by inventory-only evidence"
        );
    }
}

#[test]
fn malformed_inventory_mutations_fail_closed() {
    let canonical = artifact();

    let mut unknown = canonical.clone();
    unknown["gaps"][0]["state"] = Value::String("UNKNOWN".to_owned());
    assert!(validate_inventory(&unknown).is_err());

    let mut exit_allowed = canonical.clone();
    exit_allowed["authority"]["dependency_exit_allowed"] = Value::Bool(true);
    assert!(validate_inventory(&exit_allowed).is_err());

    let mut missing_api = canonical.clone();
    missing_api["consumed_api_semantics"]
        .as_array_mut()
        .expect("api array")
        .retain(|row| row.get("api_id").and_then(Value::as_str) != Some("FUT-API-OR"));
    assert!(validate_inventory(&missing_api).is_err());

    let mut join_promoted = canonical.clone();
    let row = join_promoted["consumed_api_semantics"]
        .as_array_mut()
        .expect("api array")
        .iter_mut()
        .find(|row| row.get("api_id").and_then(Value::as_str) == Some("FUT-API-JOIN-ALL-MENTION"))
        .expect("join-all row");
    row["classification"] = Value::String("CONSUMED".to_owned());
    assert!(validate_inventory(&join_promoted).is_err());

    let mut a3_promoted = canonical.clone();
    a3_promoted["a3_block_on_receipt"]["execution_status"] =
        Value::String("EXECUTED_CONTRACT".to_owned());
    assert!(validate_inventory(&a3_promoted).is_err());

    let mut a3_cutover = canonical.clone();
    a3_cutover["a3_block_on_receipt"]["cutover_authorized"] = Value::Bool(true);
    assert!(validate_inventory(&a3_cutover).is_err());

    let mut a4_promoted = canonical.clone();
    a4_promoted["a4_helper_receipt"]["execution_status"] =
        Value::String("EXECUTED_CONTRACT".to_owned());
    assert!(validate_inventory(&a4_promoted).is_err());

    let mut drop_only_race = canonical.clone();
    drop_only_race["a4_helper_receipt"]["race_policy_boundary"]["drop_only_owned_race_allowed"] =
        Value::Bool(true);
    assert!(validate_inventory(&drop_only_race).is_err());

    let mut a5_promoted = canonical.clone();
    a5_promoted["a5_panic_boundary_receipt"]["execution_status"] =
        Value::String("EXECUTED_CONTRACT".to_owned());
    assert!(validate_inventory(&a5_promoted).is_err());

    let mut drop_panic_contained = canonical.clone();
    drop_panic_contained["a5_panic_boundary_receipt"]["poll_helper_contract"]["drop_panic_contained"] =
        Value::Bool(true);
    assert!(validate_inventory(&drop_panic_contained).is_err());

    let mut baseline_rewritten = canonical;
    baseline_rewritten["post_baseline_current_snapshot"]["historical_baseline_preserved"] =
        Value::Bool(false);
    assert!(validate_inventory(&baseline_rewritten).is_err());
}
