//! Fail-closed inventory contract for the incumbent futures-lite capability.
//!
//! Bead: asupersync-d24mms.6.1
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
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(gaps, "gap_id") != expected_gaps {
        return Err("all ADR and A1-discovered gaps must remain routed".to_owned());
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
        || owned_atp.get("extension_method").and_then(Value::as_str)
            != Some("StreamExt::next")
        || owned_atp
            .get("implementation_state")
            .and_then(Value::as_str)
            != Some("SOURCE_AUTHORED_NOT_EXECUTED")
    {
        return Err("owned ATP downstream progress must remain source-only".to_owned());
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
    let all_rows = all_occurrence_rows();
    let all_count: usize = all_rows.iter().map(|row| row.count).sum();
    assert_eq!(
        all_rows.len() as u64,
        census
            .get("baseline_file_count")
            .and_then(Value::as_u64)
            .expect("baseline_file_count")
    );
    assert_eq!(
        all_count as u64,
        census
            .get("baseline_token_count")
            .and_then(Value::as_u64)
            .expect("baseline_token_count")
    );
    assert_eq!(
        rows_digest(&all_rows),
        text(census, "baseline_digest_sha256")
    );

    for scope_row in array(census, "scope_rows") {
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

    let groups = array(&inventory, "migration_reservation_groups");
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
    assert_eq!(progress_kernel.matches("cx.waker().wake_by_ref();").count(), 1);
    assert!(stream.contains("obligation.resolve(Resolution::Abort)"));

    let middleware = read_repo_file("src/web/middleware.rs");
    assert!(middleware.contains(&format!("use {TOKEN}::FutureExt;")));
    assert!(middleware.contains("std::panic::catch_unwind"));
    assert!(middleware.contains("AssertUnwindSafe(future).catch_unwind().await"));
    assert!(middleware.contains("[ASUP-E502] web handler panic recovered"));

    let negotiate = read_repo_file("src/web/negotiate.rs");
    assert!(negotiate.contains(&format!("use {TOKEN}::FutureExt;")));
    assert!(negotiate.contains(".catch_unwind()"));

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
    assert_eq!(
        text(owned_journey, "state"),
        "EXISTING_TEST"
    );
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

    let mut join_promoted = canonical;
    let row = join_promoted["consumed_api_semantics"]
        .as_array_mut()
        .expect("api array")
        .iter_mut()
        .find(|row| row.get("api_id").and_then(Value::as_str) == Some("FUT-API-JOIN-ALL-MENTION"))
        .expect("join-all row");
    row["classification"] = Value::String("CONSUMED".to_owned());
    assert!(validate_inventory(&join_promoted).is_err());
}
