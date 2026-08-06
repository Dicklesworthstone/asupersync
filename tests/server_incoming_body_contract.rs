//! Static contract for the server incoming-body foundation packet.
//!
//! Bead: asupersync-server-stack-hardening-eeexl1.6.1
//! Artifact: artifacts/server_incoming_body_contract_v1.json
//!
//! This contract checks source fingerprints, current buffered boundaries,
//! single-consumer ownership, checked budgets, terminal states, protocol-specific
//! unread-body cleanup, unchanged extractor defaults, the bounded BODY-2 static
//! H1 scaffold receipt, and explicit no-claim boundaries. It does not prove live
//! handler integration or runtime behavior.

#![allow(missing_docs)]

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::PathBuf;

const ARTIFACT_PATH: &str = "artifacts/server_incoming_body_contract_v1.json";
const DOC_PATH: &str = "docs/server_incoming_body_contract.md";
const BEAD_ID: &str = "asupersync-server-stack-hardening-eeexl1.6.1";
const BODY_2_BEAD_ID: &str = "asupersync-server-stack-hardening-eeexl1.6.2";
const BODY_2_BASE_REVISION: &str = "1620c55e5a3d139e7fb39b1c5e545055e3841541";
const PROGRAM_ID: &str = "asupersync-server-stack-hardening-eeexl1";
const BASELINE_REVISION: &str = "e9fa01f67318b3aa7764511e51d35291438a3e40";
const DOC_BEGIN: &str = "<!-- BEGIN SERVER INCOMING BODY CONTRACT -->";
const DOC_END: &str = "<!-- END SERVER INCOMING BODY CONTRACT -->";

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

fn artifact() -> Value {
    serde_json::from_str(&read_repo_file(ARTIFACT_PATH))
        .unwrap_or_else(|error| panic!("{ARTIFACT_PATH} must be valid JSON: {error}"))
}

fn object<'a>(value: &'a Value, key: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{key} must be an object"))
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{key} must be an array"))
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be text"))
}

fn map_text<'a>(value: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be text"))
}

fn map_u64(value: &Map<String, Value>, key: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{key} must be an unsigned integer"))
}

fn map_bool(value: &Map<String, Value>, key: &str) -> Result<bool, String> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{key} must be boolean"))
}

fn string_set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn value_string_set(value: &Value, key: &str) -> Result<BTreeSet<String>, String> {
    let values = array(value, key)?;
    let entries: BTreeSet<String> = values
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{key} entries must be text"))
        })
        .collect::<Result<_, _>>()?;
    if entries.len() != values.len() {
        return Err(format!("{key} entries must be unique"));
    }
    Ok(entries)
}

fn map_string_set(value: &Map<String, Value>, key: &str) -> Result<BTreeSet<String>, String> {
    let values = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{key} must be an array"))?;
    let entries: BTreeSet<String> = values
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{key} entries must be text"))
        })
        .collect::<Result<_, _>>()?;
    if entries.len() != values.len() {
        return Err(format!("{key} entries must be unique"));
    }
    Ok(entries)
}

fn row_ids(rows: &[Value], key: &str) -> Result<BTreeSet<String>, String> {
    let entries: BTreeSet<String> = rows
        .iter()
        .map(|row| text(row, key).map(str::to_owned))
        .collect::<Result<_, _>>()?;
    if entries.len() != rows.len() {
        return Err(format!("{key} entries must be unique"));
    }
    Ok(entries)
}

fn find_row<'a>(rows: &'a [Value], key: &str, expected: &str) -> Result<&'a Value, String> {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .ok_or_else(|| format!("missing {key}={expected}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn validate_no_unknown(value: &Value, location: &str) -> Result<(), String> {
    match value {
        Value::String(state) if state == "UNKNOWN" => {
            return Err(format!("{location} must not be UNKNOWN"));
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_no_unknown(child, &format!("{location}[{index}]"))?;
            }
        }
        Value::Object(values) => {
            for (key, child) in values {
                validate_no_unknown(child, &format!("{location}.{key}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_raw_json_key_census() -> Result<(), String> {
    let raw = read_repo_file(ARTIFACT_PATH);
    for (needle, expected) in [
        ("\"authority\":", 1),
        ("\"current_defaults\":", 1),
        ("\"request_budget_scope\":", 1),
        ("\"surface_id\":", 15),
        ("\"current_semantics\":", 15),
        ("\"mapping_id\":", 20),
        ("\"lifecycle_applicability\":", 9),
        ("\"current_variants\":", 9),
        ("\"telemetry_status\":", 9),
        ("\"protocol_action\":", 9),
        ("\"operator_code\":", 9),
        ("\"current_ambiguity\":", 2),
        ("\"allowed_entries\":", 12),
        ("\"sha256\":", 30),
        ("\"line_count\":", 30),
    ] {
        let actual = raw.matches(needle).count();
        if actual != expected {
            return Err(format!(
                "raw JSON key census for {needle} must be {expected}, found {actual}"
            ));
        }
    }
    Ok(())
}

fn validate_identity_and_authority(inventory: &Value) -> Result<(), String> {
    let expected_keys = string_set(&[
        "schema_version",
        "artifact_id",
        "program_id",
        "bead_id",
        "captured_date_utc",
        "baseline_revision",
        "purpose",
        "authority",
        "current_defaults",
        "current_surface_matrix",
        "incoming_body_contract",
        "state_machine",
        "frame_and_budget_contract",
        "size_hint_contract",
        "cancellation_and_abort_contract",
        "drain_and_reuse_contract",
        "error_mapping",
        "operator_code_policy",
        "telemetry_contract",
        "compatibility_migration",
        "body_2_h1_scaffold_progress",
        "source_pins",
        "evidence_status",
        "direct_follow_on_children",
        "no_claim_boundaries",
    ]);
    let actual_keys = inventory
        .as_object()
        .ok_or_else(|| "artifact root must be an object".to_owned())?
        .keys()
        .cloned()
        .collect();
    if actual_keys != expected_keys {
        return Err("artifact top-level keys drifted".to_owned());
    }
    if inventory.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("schema_version must be 1".to_owned());
    }
    for (key, expected) in [
        ("artifact_id", "server-incoming-body-contract-v1"),
        ("program_id", PROGRAM_ID),
        ("bead_id", BEAD_ID),
        ("baseline_revision", BASELINE_REVISION),
        ("captured_date_utc", "2026-08-04"),
    ] {
        if text(inventory, key)? != expected {
            return Err(format!("{key} must be {expected}"));
        }
    }

    let authority = object(inventory, "authority")?;
    if !map_bool(authority, "foundation_only")? {
        return Err("authority must remain foundation-only".to_owned());
    }
    for key in [
        "production_source_changes_authorized",
        "protocol_behavior_changes_authorized",
        "handler_streaming_present",
        "tracker_closure_authorized",
    ] {
        if map_bool(authority, key)? {
            return Err(format!("authority.{key} must remain false"));
        }
    }
    if map_text(authority, "executable_validation_status")? != "UNRUN_STATIC_ONLY"
        || map_text(authority, "required_disposition")? != "KEEP_OPEN_PENDING_EXECUTABLE_VALIDATION"
    {
        return Err("static validation disposition drifted".to_owned());
    }
    validate_no_unknown(inventory, "artifact")
}

#[allow(clippy::too_many_lines)]
fn validate_defaults_and_inventory(inventory: &Value) -> Result<(), String> {
    let defaults = object(inventory, "current_defaults")?;
    for (key, expected) in [
        ("h1_protocol_body_limit_bytes", 16_777_216),
        ("h2_protocol_body_limit_bytes", 16_777_216),
        ("h1_stream_frame_limit_bytes", 65_536),
        ("h1_stream_decoder_buffer_limit_bytes", 262_144),
        ("h1_stream_trailer_limit_bytes", 16_384),
        ("h1_stream_channel_capacity_frames", 8),
        ("h1_stream_derived_channel_capacity_bytes", 524_288),
        ("json_extractor_limit_bytes", 10_485_760),
        ("form_extractor_limit_bytes", 2_097_152),
        ("raw_extractor_limit_bytes", 10_485_760),
        ("multipart_total_limit_bytes", 16_777_216),
        ("multipart_part_limit_bytes", 8_388_608),
        ("multipart_header_limit_bytes", 8_192),
        ("multipart_part_count_limit", 1_024),
        ("multipart_request_timeout_seconds", 30),
        ("multipart_idle_timeout_seconds", 5),
        ("handler_request_drain_grace_milliseconds", 500),
    ] {
        if map_u64(defaults, key)? != expected {
            return Err(format!("current_defaults.{key} must be {expected}"));
        }
    }
    if map_bool(defaults, "h1_stream_channel_byte_cap_enforced")? {
        return Err("current H1 scaffold must not claim a byte-enforced queue".to_owned());
    }
    if map_text(defaults, "json_and_raw_default_policy")?
        != "RETAIN_10_MIB_UNLESS_OWNER_APPROVES_A_LOWER_DEFAULT"
    {
        return Err("JSON/raw default policy drifted".to_owned());
    }

    let surfaces = array(inventory, "current_surface_matrix")?;
    let expected_states = [
        ("BODY-TRAIT", "PRESENT"),
        ("STREAM-BODY-ADAPTER", "PRESENT"),
        ("LIMITED-ADAPTER", "PRESENT"),
        ("H1-STREAM-SCAFFOLD", "PRESENT_WITH_GAPS"),
        ("H1-LIVE-DISPATCH", "BUFFERED"),
        ("H2-LIVE-DISPATCH", "BUFFERED"),
        ("WEB-REQUEST", "BUFFERED"),
        ("WEB-HANDLER-ROUTER", "BUFFERED"),
        ("WEB-RETRY-BODY-REPLAY", "CLONES_BUFFERED_REQUEST"),
        ("WEB-EXTRACTOR-LIMITS", "PRESENT_AFTER_BUFFERING"),
        ("WEB-MIDDLEWARE-LIMIT", "PRESENT_AFTER_BUFFERING"),
        ("WEB-MULTIPART", "CONTIGUOUS_BUFFERED_PARSE"),
        ("WEB-RESPONSE", "BUFFERED_OUT_OF_SCOPE"),
        ("REQUEST-REGION", "PRESENT_FOR_HANDLER"),
        ("ERROR-REGISTRY", "NO_INCOMING_BODY_CODE"),
    ];
    let expected_ids: BTreeSet<String> = expected_states
        .iter()
        .map(|(surface_id, _)| (*surface_id).to_owned())
        .collect();
    if row_ids(surfaces, "surface_id")? != expected_ids {
        return Err("current surface matrix is incomplete".to_owned());
    }
    let pin_paths = row_ids(array(inventory, "source_pins")?, "path")?;
    for (surface_id, expected_state) in expected_states {
        let row = find_row(surfaces, "surface_id", surface_id)?;
        if text(row, "state")?.is_empty()
            || text(row, "current_semantics")?.is_empty()
            || text(row, "gap")?.is_empty()
            || array(row, "anchors")?.is_empty()
        {
            return Err(format!(
                "surface {} is incomplete",
                text(row, "surface_id")?
            ));
        }
        if text(row, "state")? != expected_state {
            return Err(format!("{surface_id} state drifted"));
        }
        for anchor in array(row, "anchors")? {
            let anchor = anchor
                .as_str()
                .ok_or_else(|| format!("{surface_id} anchors must be text"))?;
            let (path, _) = anchor
                .split_once("::")
                .ok_or_else(|| format!("{surface_id} anchor must name a pinned path"))?;
            if !pin_paths.contains(path) {
                return Err(format!(
                    "{surface_id} anchor path is not source-pinned: {path}"
                ));
            }
        }
    }
    let h1_scaffold = find_row(surfaces, "surface_id", "H1-STREAM-SCAFFOLD")?;
    let h1_semantics = text(h1_scaffold, "current_semantics")?;
    let h1_gap = text(h1_scaffold, "gap")?;
    if !h1_semantics.contains("producer terminal reason")
        || !h1_semantics.contains("before mutation")
        || !h1_semantics.contains("premature disconnect")
        || !h1_semantics.contains("decrementing a fixed-length SizeHint")
        || !h1_gap.contains("HttpError")
        || !h1_gap.contains("queue-byte permits")
        || !h1_gap.contains("consumer-drop signal")
        || !h1_gap.contains("live handler dispatch")
        || !text(find_row(surfaces, "surface_id", "H1-LIVE-DISPATCH")?, "gap")?
            .contains("saturating addition")
        || !text(
            find_row(surfaces, "surface_id", "H2-LIVE-DISPATCH")?,
            "current_semantics",
        )?
        .contains("RST_STREAM(ENHANCE_YOUR_CALM)")
        || !text(
            find_row(surfaces, "surface_id", "H2-LIVE-DISPATCH")?,
            "current_semantics",
        )?
        .contains("saturating prospective addition")
        || !text(
            find_row(surfaces, "surface_id", "H2-LIVE-DISPATCH")?,
            "current_semantics",
        )?
        .contains("separate validated trailer block")
        || !text(find_row(surfaces, "surface_id", "H2-LIVE-DISPATCH")?, "gap")?
            .contains("aggregate incoming-body budget")
    {
        return Err("current H1/H2 accounting inventory drifted".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_state_and_budgets(inventory: &Value) -> Result<(), String> {
    let contract = object(inventory, "incoming_body_contract")?;
    if map_text(contract, "proposed_type")? != "IncomingRequestBody"
        || map_text(contract, "proposed_error_type")? != "IncomingBodyError"
        || map_text(contract, "public_trait")?
            != "crate::http::body::Body<Data = BytesCursor, Error = IncomingBodyError>"
        || map_bool(contract, "reuse_stream_body")?
        || !map_bool(contract, "reuse_limited_adapter")?
        || map_text(contract, "stream_body_role")?
            != "LANDED_REFERENCE_ADAPTER_NOT_AUTHORITATIVE_INCOMING_TYPE"
        || !map_bool(contract, "replace_or_generalize_h1_incoming_body")?
        || map_bool(contract, "coexisting_second_public_incoming_type_allowed")?
        || !map_bool(contract, "single_consumer")?
        || map_bool(contract, "clone_allowed")?
        || map_bool(contract, "ambient_authority_allowed")?
    {
        return Err("incoming-body ownership contract drifted".to_owned());
    }
    if map_string_set(contract, "required_auto_traits")?
        != string_set(&["Send", "Unpin", "'static"])
        || !map_text(contract, "sync_policy")?.contains("NOT_REQUIRED_FOR_SINGLE_CONSUMER_BODY")
        || !map_text(contract, "sync_policy")?.contains("remove any Sync bound")
        || !map_text(contract, "limited_compatibility")?.contains("Limited<B>")
    {
        return Err("incoming-body auto-trait or Limited compatibility policy drifted".to_owned());
    }
    if !map_text(contract, "handoff")?.contains("sole consumer obligation") {
        return Err("incoming-body handoff must transfer the sole consumer obligation".to_owned());
    }
    let incoming_error = contract
        .get("incoming_error_contract")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            "incoming_body_contract.incoming_error_contract must be an object".to_owned()
        })?;
    let error_variants = incoming_error
        .get("required_variants")
        .and_then(Value::as_array)
        .ok_or_else(|| "required error variants must be an array".to_owned())?;
    if row_ids(error_variants, "variant_id")?
        != string_set(&[
            "FRAMING",
            "LIMIT_EXCEEDED",
            "CANCELLED",
            "SOURCE_DISCONNECTED",
            "CLIENT_ABORTED",
            "ACCOUNTING_OVERFLOW",
            "ALREADY_TERMINAL",
        ])
        || !map_bool(incoming_error, "cancel_kind_preserved")?
        || map_bool(incoming_error, "consumer_drop_is_poll_error")?
        || !map_text(incoming_error, "consumer_drop_rule")?.contains("Drop-side ownership")
    {
        return Err("incoming-body typed error contract drifted".to_owned());
    }
    for (variant_id, fields) in [
        ("FRAMING", &["mapping_id", "detail", "offset"][..]),
        ("LIMIT_EXCEEDED", &["observed", "limit", "limit_source"][..]),
        ("CANCELLED", &["cancel_kind"][..]),
        ("SOURCE_DISCONNECTED", &["source_kind"][..]),
        ("CLIENT_ABORTED", &["transport_kind"][..]),
        ("ACCOUNTING_OVERFLOW", &["counter", "lhs", "rhs"][..]),
        ("ALREADY_TERMINAL", &["prior_terminal_state"][..]),
    ] {
        if value_string_set(
            find_row(error_variants, "variant_id", variant_id)?,
            "payload_fields",
        )? != string_set(fields)
        {
            return Err(format!("{variant_id} payload contract drifted"));
        }
    }
    let ownership = contract
        .get("ownership")
        .and_then(Value::as_object)
        .ok_or_else(|| "incoming_body_contract.ownership must be an object".to_owned())?;
    for key in [
        "producer",
        "consumer",
        "budget_owner",
        "drain_and_reuse_owner",
        "telemetry_owner",
    ] {
        if map_text(ownership, key)?.is_empty() {
            return Err(format!(
                "incoming_body_contract.ownership.{key} must be nonempty"
            ));
        }
    }
    if !map_text(ownership, "consumer")?.contains("exactly one")
        || !map_text(ownership, "telemetry_owner")?.contains("protocol driver")
    {
        return Err("incoming-body consumer or telemetry ownership drifted".to_owned());
    }

    let state_machine = object(inventory, "state_machine")?;
    if !map_text(state_machine, "lifecycle_boundary")?
        .contains("created only after request-head framing is valid")
        || !map_text(state_machine, "lifecycle_boundary")?.contains("create no body obligation")
        || !map_text(state_machine, "lifecycle_boundary")?
            .contains("no http.incoming_body.terminal receipt")
    {
        return Err("incoming-body lifecycle boundary drifted".to_owned());
    }
    if map_string_set(state_machine, "states")?
        != string_set(&[
            "CREATED",
            "OPEN",
            "EOF",
            "ERROR",
            "LIMIT_EXCEEDED",
            "CANCELLED",
            "CLIENT_ABORTED",
            "CONSUMER_DROPPED",
        ])
    {
        return Err("incoming-body state set drifted".to_owned());
    }
    let transitions = state_machine
        .get("transitions")
        .and_then(Value::as_array)
        .ok_or_else(|| "state_machine.transitions must be an array".to_owned())?;
    if transitions.len() != 7 {
        return Err("state_machine.transitions must contain exactly seven rows".to_owned());
    }
    let actual_transitions: Result<BTreeSet<String>, String> = transitions
        .iter()
        .map(|row| Ok(format!("{}->{}", text(row, "from")?, text(row, "to")?)))
        .collect();
    if actual_transitions?
        != string_set(&[
            "CREATED->OPEN",
            "OPEN->EOF",
            "OPEN->ERROR",
            "OPEN->LIMIT_EXCEEDED",
            "OPEN->CANCELLED",
            "OPEN->CLIENT_ABORTED",
            "OPEN->CONSUMER_DROPPED",
        ])
        || map_bool(state_machine, "disconnect_is_eof")?
    {
        return Err("terminal transition contract drifted".to_owned());
    }

    let budgets = object(inventory, "frame_and_budget_contract")?;
    for (key, expected) in [
        ("max_frame_bytes", 65_536),
        ("queue_capacity_frames", 8),
        ("queue_capacity_bytes", 524_288),
        ("decoder_buffer_capacity_bytes", 262_144),
        ("trailer_capacity_bytes", 16_384),
        ("default_protocol_total_bytes", 16_777_216),
    ] {
        if map_u64(budgets, key)? != expected {
            return Err(format!(
                "frame_and_budget_contract.{key} must be {expected}"
            ));
        }
    }
    let derived_queue = map_u64(budgets, "max_frame_bytes")?
        .checked_mul(map_u64(budgets, "queue_capacity_frames")?)
        .ok_or_else(|| "derived queue byte capacity overflowed".to_owned())?;
    if derived_queue != map_u64(budgets, "queue_capacity_bytes")?
        || !map_bool(budgets, "checked_accounting_required")?
        || map_bool(budgets, "saturating_accounting_allowed")?
    {
        return Err("checked queue accounting contract drifted".to_owned());
    }
    if !map_text(budgets, "effective_total_limit")?.contains("RequestBodyLimitMiddleware")
        || !map_text(budgets, "effective_total_limit")?.contains("request quota")
        || !map_text(budgets, "limit_binding_rule")?.contains("before body handoff")
        || !map_text(budgets, "limit_binding_rule")?.contains("monotonically tighten")
        || !map_text(budgets, "limit_binding_rule")?.contains("never relaxes")
        || !map_text(budgets, "limit_binding_rule")?
            .contains("bytes already received, delivered, or queued")
        || !map_text(budgets, "trailer_accounting_rule")?.contains("queue byte cap")
        || !map_text(budgets, "trailer_accounting_rule")?.contains("trailer cap")
        || !map_text(budgets, "queue_release_rule")?.contains("transfers exactly once on dequeue")
        || !map_text(budgets, "queue_release_rule")?
            .contains("releases all residual permits exactly once")
        || !map_text(budgets, "h2_connection_aggregate_rule")?
            .contains("connection-level in-flight byte and frame caps")
        || !map_text(budgets, "h2_connection_aggregate_rule")?
            .contains("reserve aggregate and stream capacity atomically")
    {
        return Err("effective limit or trailer accounting contract drifted".to_owned());
    }
    let trailer_metric = budgets
        .get("trailer_size_metric")
        .and_then(Value::as_object)
        .ok_or_else(|| "trailer_size_metric must be an object".to_owned())?;
    if !map_text(trailer_metric, "h1")?.contains("excluding the terminating empty line")
        || !map_text(trailer_metric, "h2")?.contains("plus 32 octets")
        || !map_text(trailer_metric, "h2")?.contains("compressed wire size is not used")
        || !map_bool(trailer_metric, "same_metric_for_queue_and_trailer_cap")?
    {
        return Err("protocol trailer-size metric drifted".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_semantics_and_telemetry(inventory: &Value) -> Result<(), String> {
    let state_machine = object(inventory, "state_machine")?;
    if map_string_set(state_machine, "terminal_states")?
        != string_set(&[
            "EOF",
            "ERROR",
            "LIMIT_EXCEEDED",
            "CANCELLED",
            "CLIENT_ABORTED",
        ])
    {
        return Err("terminal state set drifted".to_owned());
    }
    if map_string_set(state_machine, "cleanup_handoff_states")? != string_set(&["CONSUMER_DROPPED"])
    {
        return Err("cleanup handoff state set drifted".to_owned());
    }
    for transition in state_machine
        .get("transitions")
        .and_then(Value::as_array)
        .ok_or_else(|| "state transitions must be an array".to_owned())?
    {
        if text(transition, "cause")?.is_empty() {
            return Err("every state transition must have a cause".to_owned());
        }
    }
    if !map_text(state_machine, "terminal_poll_rule")?
        .contains("without polling the producer again")
        || !map_text(state_machine, "terminal_poll_rule")?.contains("Limited")
        || !map_text(state_machine, "trailers_rule")?.contains("At most one")
    {
        return Err("terminal polling or trailer obligations drifted".to_owned());
    }

    let size_hint = object(inventory, "size_hint_contract")?;
    if !map_text(size_hint, "content_length")?.contains("Exact remaining bytes")
        || !map_text(size_hint, "chunked")?.contains("remaining effective total limit")
        || map_text(size_hint, "eof")? != "Exact zero."
        || !map_text(size_hint, "terminal_error")?.contains("fail-closed repoll")
        || !map_string_set(size_hint, "forbidden")?.contains("using a hint as admission authority")
    {
        return Err("size-hint contract drifted".to_owned());
    }

    let cancellation = object(inventory, "cancellation_and_abort_contract")?;
    if !map_text(cancellation, "request_budget_scope")?.contains("handler consumption")
        || map_text(cancellation, "request_budget_scope")?.contains("cleanup")
        || !map_text(cancellation, "post_cancel_cleanup_scope")?
            .contains("separate strictly bounded cleanup grace")
        || !map_text(cancellation, "post_cancel_cleanup_scope")?
            .contains("does not reuse the cancelled request Cx")
        || !map_text(cancellation, "client_abort_rule")?.contains("never EOF")
        || !map_text(cancellation, "source_disconnect_rule")?.contains("is ERROR")
        || !map_text(cancellation, "consumer_drop_rule")?.contains("drain-or-close")
    {
        return Err("cancellation and abort contract drifted".to_owned());
    }
    let cancel_rows = cancellation
        .get("cancel_kind_mapping")
        .and_then(Value::as_array)
        .ok_or_else(|| "cancel_kind_mapping must be an array".to_owned())?;
    if cancel_rows.len() != 11
        || row_ids(cancel_rows, "cancel_kind")?
            != string_set(&[
                "User",
                "Timeout",
                "Deadline",
                "PollQuota",
                "CostBudget",
                "FailFast",
                "RaceLost",
                "ParentCancelled",
                "ResourceUnavailable",
                "Shutdown",
                "LinkedExit",
            ])
    {
        return Err("CancelKind inventory drifted".to_owned());
    }
    for (cancel_kind, mapping_id) in [
        ("User", "BODY-CANCELLED"),
        ("Timeout", "BODY-REQUEST-DEADLINE"),
        ("Deadline", "BODY-REQUEST-DEADLINE"),
        ("PollQuota", "BODY-RESOURCE-EXHAUSTED"),
        ("CostBudget", "BODY-RESOURCE-EXHAUSTED"),
        ("FailFast", "BODY-CANCELLED"),
        ("RaceLost", "BODY-CANCELLED"),
        ("ParentCancelled", "BODY-CANCELLED"),
        ("ResourceUnavailable", "BODY-RESOURCE-EXHAUSTED"),
        ("Shutdown", "BODY-CANCELLED"),
        ("LinkedExit", "BODY-CANCELLED"),
    ] {
        if text(
            find_row(cancel_rows, "cancel_kind", cancel_kind)?,
            "mapping_id",
        )? != mapping_id
        {
            return Err(format!("{cancel_kind} mapping drifted"));
        }
    }
    if !map_text(cancellation, "cancel_kind_preservation_rule")?.contains("exact CancelKind")
        || !map_text(cancellation, "status_499_scope")?.contains("not an HTTP response status")
        || !map_text(cancellation, "status_499_scope")?.contains("not universal")
        || !map_text(cancellation, "transport_loss_mapping")?.contains("BODY-CLIENT-ABORTED")
    {
        return Err("cancellation classification policy drifted".to_owned());
    }

    let telemetry = object(inventory, "telemetry_contract")?;
    if map_text(telemetry, "terminal_event")? != "http.incoming_body.terminal"
        || !map_text(telemetry, "emitter_owner")?.contains("protocol driver")
        || !map_text(telemetry, "emitter_owner")?.contains("final cleanup/reuse decision")
        || map_text(telemetry, "current_status")? != "NO_INCOMING_BODY_TERMINAL_RECEIPT"
        || !map_text(telemetry, "time_authority")?.contains("no body-local wall clock")
        || !map_text(telemetry, "obligation_rule")?.contains("exactly once")
    {
        return Err("incoming-body telemetry authority drifted".to_owned());
    }
    if map_string_set(telemetry, "required_fields")?
        != string_set(&[
            "request_id",
            "connection_id",
            "stream_id",
            "region_id",
            "protocol",
            "terminal_state",
            "declared_length",
            "bytes_received",
            "bytes_delivered",
            "bytes_refused",
            "bytes_queued_peak",
            "queued_frames_peak",
            "unread_bytes",
            "discarded_bytes",
            "trailer_bytes_received",
            "trailer_bytes_delivered",
            "trailer_bytes_discarded",
            "frames_delivered",
            "frames_received",
            "frames_refused",
            "frames_discarded",
            "frames_drained",
            "effective_total_limit",
            "limit_sources",
            "queue_byte_limit",
            "drain_bytes",
            "drain_elapsed_milliseconds",
            "drain_frame_limit",
            "drain_byte_limit",
            "drain_time_limit_milliseconds",
            "drain_result",
            "connection_reuse_decision",
            "connection_reuse_reason",
            "obligation_outcome",
            "mapping_id",
            "cancel_kind",
        ])
        || map_string_set(telemetry, "forbidden_fields")?
            != string_set(&[
                "body content",
                "raw authorization headers",
                "raw cookie headers",
            ])
    {
        return Err("incoming-body telemetry field set drifted".to_owned());
    }
    let applicability = telemetry
        .get("field_applicability")
        .and_then(Value::as_object)
        .ok_or_else(|| "telemetry field_applicability must be an object".to_owned())?;
    if !map_bool(applicability, "keys_always_present")?
        || !map_bool(applicability, "null_is_distinct_from_zero")?
        || map_string_set(applicability, "nullable_fields")?
            != string_set(&[
                "stream_id",
                "declared_length",
                "unread_bytes",
                "frames_drained",
                "drain_bytes",
                "drain_elapsed_milliseconds",
                "drain_frame_limit",
                "drain_byte_limit",
                "drain_time_limit_milliseconds",
                "drain_result",
                "mapping_id",
                "cancel_kind",
            ])
        || !map_text(applicability, "stream_id_rule")?.contains("null for H1")
        || !map_text(applicability, "declared_length_rule")?.contains("null for chunked")
        || !map_text(applicability, "mapping_id_rule")?.contains("null only for normal EOF")
        || !map_text(applicability, "mapping_id_rule")?.contains("exactly one")
        || !map_text(applicability, "cancel_kind_rule")?.contains("required only")
        || !map_text(applicability, "drain_fields_rule")?.contains("null for normal EOF")
    {
        return Err("telemetry field applicability drifted".to_owned());
    }
    let counters = telemetry
        .get("counter_semantics")
        .and_then(Value::as_object)
        .ok_or_else(|| "telemetry counter_semantics must be an object".to_owned())?;
    if !map_text(counters, "data_rule")?.contains("equals bytes_delivered plus discarded_bytes")
        || !map_text(counters, "trailer_rule")?
            .contains("equals trailer_bytes_delivered plus trailer_bytes_discarded")
        || !map_text(counters, "frame_rule")?
            .contains("equals frames_delivered plus frames_discarded")
        || !map_text(counters, "cleanup_subset_rule")?.contains("subsets")
        || !map_text(counters, "unknown_unread_rule")?.contains("unread_bytes is null")
    {
        return Err("telemetry counter conservation drifted".to_owned());
    }
    if value_string_set(inventory, "direct_follow_on_children")?
        != string_set(&[
            "asupersync-server-stack-hardening-eeexl1.6.2",
            "asupersync-server-stack-hardening-eeexl1.6.3",
            "asupersync-server-stack-hardening-eeexl1.6.5",
        ])
    {
        return Err("follow-on child set drifted".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_cleanup_errors_and_evidence(inventory: &Value) -> Result<(), String> {
    let cleanup = object(inventory, "drain_and_reuse_contract")?;
    let cleanup_states = map_string_set(cleanup, "cleanup_states")?;
    if cleanup_states
        != string_set(&[
            "IDLE",
            "DRAINING",
            "RESETTING",
            "REUSABLE",
            "CLOSE_REQUIRED",
            "RESET_COMPLETE",
        ])
        || map_string_set(cleanup, "cleanup_terminal_states")?
            != string_set(&["REUSABLE", "CLOSE_REQUIRED", "RESET_COMPLETE"])
    {
        return Err("protocol cleanup state set drifted".to_owned());
    }
    let cleanup_transitions = cleanup
        .get("cleanup_transitions")
        .and_then(Value::as_array)
        .ok_or_else(|| "cleanup_transitions must be an array".to_owned())?;
    if cleanup_transitions.len() != 7 {
        return Err("cleanup_transitions must contain exactly seven rows".to_owned());
    }
    let mut cleanup_edges = BTreeSet::new();
    for transition in cleanup_transitions {
        let from = text(transition, "from")?;
        let to = text(transition, "to")?;
        if !cleanup_states.contains(from)
            || !cleanup_states.contains(to)
            || text(transition, "cause")?.is_empty()
            || !cleanup_edges.insert(format!("{from}->{to}"))
        {
            return Err("cleanup transition graph is not closed and unique".to_owned());
        }
    }
    if cleanup_edges
        != string_set(&[
            "IDLE->DRAINING",
            "DRAINING->REUSABLE",
            "DRAINING->CLOSE_REQUIRED",
            "IDLE->RESETTING",
            "RESETTING->RESET_COMPLETE",
            "RESETTING->CLOSE_REQUIRED",
            "IDLE->CLOSE_REQUIRED",
        ])
        || !map_text(cleanup, "budget_authority")?.contains("cancelled request Cx")
        || !map_text(cleanup, "budget_authority")?.contains("never a detached task")
        || !map_text(cleanup, "obligation_completion")?.contains("exactly once")
        || !map_text(cleanup, "obligation_completion")?.contains("RESET_COMPLETE")
    {
        return Err("protocol cleanup authority or completion contract drifted".to_owned());
    }
    let entry_rows = cleanup
        .get("cleanup_entry_policy")
        .and_then(Value::as_array)
        .ok_or_else(|| "cleanup_entry_policy must be an array".to_owned())?;
    if entry_rows.len() != 12 {
        return Err("cleanup_entry_policy must contain twelve rows".to_owned());
    }
    let mut entry_keys = BTreeSet::new();
    for row in entry_rows {
        let protocol = text(row, "protocol")?;
        let state = text(row, "body_state")?;
        if !entry_keys.insert(format!("{protocol}:{state}"))
            || value_string_set(row, "allowed_entries")?.is_empty()
            || text(row, "decision_rule")?.is_empty()
        {
            return Err("cleanup entry rows must be complete and unique".to_owned());
        }
    }
    for (protocol, state, entries) in [
        ("h1", "EOF", &["NONE"][..]),
        ("h1", "ERROR", &["CLOSE_REQUIRED"][..]),
        ("h1", "LIMIT_EXCEEDED", &["DRAINING", "CLOSE_REQUIRED"][..]),
        ("h1", "CANCELLED", &["DRAINING", "CLOSE_REQUIRED"][..]),
        ("h1", "CLIENT_ABORTED", &["CLOSE_REQUIRED"][..]),
        ("h1", "CONSUMER_DROPPED", &["DRAINING"][..]),
        ("h2", "EOF", &["NONE"][..]),
        ("h2", "ERROR", &["RESETTING", "CLOSE_REQUIRED"][..]),
        ("h2", "LIMIT_EXCEEDED", &["RESETTING", "CLOSE_REQUIRED"][..]),
        ("h2", "CANCELLED", &["RESETTING", "CLOSE_REQUIRED"][..]),
        ("h2", "CLIENT_ABORTED", &["CLOSE_REQUIRED"][..]),
        ("h2", "CONSUMER_DROPPED", &["RESETTING"][..]),
    ] {
        let row = entry_rows
            .iter()
            .find(|row| {
                row.get("protocol").and_then(Value::as_str) == Some(protocol)
                    && row.get("body_state").and_then(Value::as_str) == Some(state)
            })
            .ok_or_else(|| format!("missing cleanup entry for {protocol}:{state}"))?;
        if value_string_set(row, "allowed_entries")? != string_set(entries) {
            return Err(format!("cleanup entry drifted for {protocol}:{state}"));
        }
    }
    for protocol in ["h1", "h2"] {
        let row = cleanup
            .get(protocol)
            .and_then(Value::as_object)
            .ok_or_else(|| format!("drain_and_reuse_contract.{protocol} must be an object"))?;
        if map_u64(row, "time_budget_milliseconds")? != 500
            || map_u64(row, "byte_budget")? != 524_288
            || map_u64(row, "frame_budget")? != 8
            || map_text(row, "time_budget_provenance")?
                != "PROPOSED_INITIAL_VALUE_FROM_HANDLER_REQUEST_DRAIN_GRACE_NOT_LIVE_BODY_CLEANUP"
        {
            return Err(format!("{protocol} cleanup budgets drifted"));
        }
        if !map_text(row, "reuse_when")?.contains("EOF") || map_text(row, "close_when")?.is_empty()
        {
            return Err(format!("{protocol} reuse decision is incomplete"));
        }
    }
    if !map_text(
        cleanup
            .get("h2")
            .and_then(Value::as_object)
            .ok_or_else(|| "h2 cleanup row is missing".to_owned())?,
        "reuse_when",
    )?
    .contains("reset")
    {
        return Err("H2 cleanup must be stream-scoped when possible".to_owned());
    }
    let h2_cleanup = cleanup
        .get("h2")
        .and_then(Value::as_object)
        .ok_or_else(|| "h2 cleanup row is missing".to_owned())?;
    if !map_text(h2_cleanup, "post_drop_data_accounting")?.contains("frame_budget")
        || !map_text(h2_cleanup, "post_drop_data_accounting")?.contains("byte_budget")
        || !map_text(h2_cleanup, "post_drop_data_accounting")?
            .contains("RESETTING to CLOSE_REQUIRED")
    {
        return Err("H2 reset-in-flight accounting drifted".to_owned());
    }

    let errors = array(inventory, "error_mapping")?;
    if row_ids(errors, "mapping_id")?
        != string_set(&[
            "BODY-LIMIT-EXCEEDED",
            "BODY-FRAMING-INVALID",
            "BODY-CANCELLED",
            "BODY-REQUEST-DEADLINE",
            "BODY-RESOURCE-EXHAUSTED",
            "BODY-SOURCE-DISCONNECTED",
            "BODY-CLIENT-ABORTED",
            "BODY-ACCOUNTING-OVERFLOW",
            "BODY-CONSUMER-DROPPED",
        ])
    {
        return Err("stable body error mapping IDs drifted".to_owned());
    }
    for row in errors {
        let mapping_id = text(row, "mapping_id")?;
        let operator_code = row
            .get("operator_code")
            .ok_or_else(|| format!("{mapping_id}.operator_code is missing"))?;
        if mapping_id == "BODY-REQUEST-DEADLINE" {
            if operator_code.as_str() != Some("ASUP-E501") {
                return Err("request deadline must retain ASUP-E501".to_owned());
            }
        } else if !operator_code.is_null() {
            return Err(format!(
                "{mapping_id} must not allocate a new operator code"
            ));
        }
        if text(row, "protocol_action")?.is_empty() {
            return Err(format!("{mapping_id}.protocol_action must be nonempty"));
        }
    }
    for (mapping_id, scopes) in [
        ("BODY-LIMIT-EXCEEDED", &["PRE_BODY", "BODY_OPEN"][..]),
        ("BODY-FRAMING-INVALID", &["PRE_BODY", "BODY_OPEN"][..]),
        ("BODY-CANCELLED", &["PRE_BODY", "BODY_OPEN"][..]),
        ("BODY-REQUEST-DEADLINE", &["PRE_BODY", "BODY_OPEN"][..]),
        ("BODY-RESOURCE-EXHAUSTED", &["PRE_BODY", "BODY_OPEN"][..]),
        ("BODY-SOURCE-DISCONNECTED", &["BODY_OPEN"][..]),
        ("BODY-CLIENT-ABORTED", &["PRE_BODY", "BODY_OPEN"][..]),
        ("BODY-ACCOUNTING-OVERFLOW", &["BODY_OPEN"][..]),
        ("BODY-CONSUMER-DROPPED", &["BODY_OPEN"][..]),
    ] {
        if value_string_set(
            find_row(errors, "mapping_id", mapping_id)?,
            "lifecycle_applicability",
        )? != string_set(scopes)
        {
            return Err(format!("{mapping_id} lifecycle applicability drifted"));
        }
    }
    let status = |mapping_id: &str| -> Result<Option<u64>, String> {
        let value = find_row(errors, "mapping_id", mapping_id)?
            .get("http_status_when_response_possible")
            .ok_or_else(|| format!("{mapping_id} response status is missing"))?;
        if value.is_null() {
            Ok(None)
        } else {
            value
                .as_u64()
                .map(Some)
                .ok_or_else(|| format!("{mapping_id} response status must be integer or null"))
        }
    };
    if status("BODY-LIMIT-EXCEEDED")? != Some(413)
        || status("BODY-FRAMING-INVALID")? != Some(400)
        || status("BODY-REQUEST-DEADLINE")? != Some(503)
        || status("BODY-RESOURCE-EXHAUSTED")? != Some(503)
        || status("BODY-SOURCE-DISCONNECTED")? != Some(500)
        || status("BODY-ACCOUNTING-OVERFLOW")? != Some(500)
        || status("BODY-CANCELLED")?.is_some()
        || status("BODY-CLIENT-ABORTED")?.is_some()
        || status("BODY-CONSUMER-DROPPED")?.is_some()
    {
        return Err("body error-to-status mapping drifted".to_owned());
    }
    let telemetry_status = |mapping_id: &str| -> Result<Option<u64>, String> {
        let value = find_row(errors, "mapping_id", mapping_id)?
            .get("telemetry_status")
            .ok_or_else(|| format!("{mapping_id}.telemetry_status is missing"))?;
        if value.is_null() {
            Ok(None)
        } else {
            value
                .as_u64()
                .map(Some)
                .ok_or_else(|| format!("{mapping_id}.telemetry_status must be integer or null"))
        }
    };
    for mapping_id in [
        "BODY-LIMIT-EXCEEDED",
        "BODY-FRAMING-INVALID",
        "BODY-REQUEST-DEADLINE",
        "BODY-RESOURCE-EXHAUSTED",
        "BODY-SOURCE-DISCONNECTED",
        "BODY-CLIENT-ABORTED",
        "BODY-ACCOUNTING-OVERFLOW",
        "BODY-CONSUMER-DROPPED",
    ] {
        if telemetry_status(mapping_id)?.is_some() {
            return Err(format!(
                "{mapping_id} must not claim cancellation telemetry status"
            ));
        }
    }
    if telemetry_status("BODY-CANCELLED")? != Some(499) {
        return Err("body cancellation must retain the 499 telemetry representation".to_owned());
    }

    let variants = |mapping_id: &str| {
        find_row(errors, "mapping_id", mapping_id)
            .and_then(|row| value_string_set(row, "current_variants"))
    };
    if variants("BODY-LIMIT-EXCEEDED")?
        != string_set(&[
            "HttpError::BodyTooLarge",
            "HttpError::BodyTooLargeDetailed",
            "LimitedError::LengthLimit",
        ])
        || variants("BODY-FRAMING-INVALID")?
            != string_set(&[
                "HttpError::BadContentLength",
                "HttpError::DuplicateContentLength",
                "HttpError::DuplicateTransferEncoding",
                "HttpError::BadTransferEncoding",
                "HttpError::BadChunkedEncoding",
                "HttpError::AmbiguousBodyLength",
                "HttpError::TrailersNotAllowed",
                "HttpError::HeadersTooLarge",
                "HttpError::BadHeader",
                "HttpError::InvalidHeaderName",
                "HttpError::InvalidHeaderValue",
            ])
        || variants("BODY-CANCELLED")?
            != string_set(&["HttpError::BodyCancelled", "ServerHopOutcome::Cancelled"])
        || variants("BODY-REQUEST-DEADLINE")? != string_set(&["ServerHopOutcome::DeadlineExceeded"])
        || !variants("BODY-RESOURCE-EXHAUSTED")?.is_empty()
        || !variants("BODY-SOURCE-DISCONNECTED")?.is_empty()
        || variants("BODY-CLIENT-ABORTED")? != string_set(&["ServerHopOutcome::ConnectionLost"])
        || !variants("BODY-ACCOUNTING-OVERFLOW")?.is_empty()
        || !variants("BODY-CONSUMER-DROPPED")?.is_empty()
    {
        return Err("current body error variant mapping drifted".to_owned());
    }
    for mapping_id in ["BODY-SOURCE-DISCONNECTED", "BODY-CONSUMER-DROPPED"] {
        if !text(
            find_row(errors, "mapping_id", mapping_id)?,
            "current_ambiguity",
        )?
        .contains("HttpError::BodyChannelClosed")
        {
            return Err(format!(
                "{mapping_id} must retain channel-closure ambiguity"
            ));
        }
    }
    let action = |mapping_id: &str| {
        find_row(errors, "mapping_id", mapping_id).and_then(|row| text(row, "protocol_action"))
    };
    for (mapping_id, required) in [
        ("BODY-LIMIT-EXCEEDED", "drains within every bound"),
        ("BODY-FRAMING-INVALID", "do not reuse"),
        ("BODY-CANCELLED", "existing web cancellation representation"),
        ("BODY-REQUEST-DEADLINE", "existing request-deadline"),
        ("BODY-RESOURCE-EXHAUSTED", "exact CancelKind"),
        ("BODY-SOURCE-DISCONNECTED", "never convert to EOF"),
        ("BODY-CLIENT-ABORTED", "without synthesizing a response"),
        ("BODY-ACCOUNTING-OVERFLOW", "Fail before enqueue"),
        ("BODY-CONSUMER-DROPPED", "H1 drain-or-close"),
    ] {
        if !action(mapping_id)?.contains(required) {
            return Err(format!("{mapping_id} action must retain {required}"));
        }
    }
    let operator_policy = text(inventory, "operator_code_policy")?;
    if !operator_policy.contains("ASUP-E501")
        || !operator_policy.contains("ASUP-E5xx")
        || !operator_policy.contains("allocates no new code")
    {
        return Err("operator-code no-allocation policy drifted".to_owned());
    }

    let compatibility = object(inventory, "compatibility_migration")?;
    let migration_order: Result<Vec<&str>, String> = compatibility
        .get("migration_order")
        .and_then(Value::as_array)
        .ok_or_else(|| "migration_order must be an array".to_owned())?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| "migration_order entries must be text".to_owned())
        })
        .collect();
    let migration_order = migration_order?;
    if map_text(compatibility, "policy")? != "DIRECT_CUTOVER_NO_COMPATIBILITY_SHIM"
        || !map_text(compatibility, "request_change")?.contains("single IncomingRequestBody")
        || !map_text(compatibility, "buffered_extractors")?.contains("Limited")
        || !map_text(compatibility, "buffered_extractors")?.contains("checked accounting")
        || migration_order.iter().copied().ne([
            "H1 producer integration",
            "assign and complete H2 producer integration",
            "web request and handler ownership",
            "buffered extractor adapters",
            "telemetry and stable diagnostics",
        ])
    {
        return Err("direct-cutover compatibility contract drifted".to_owned());
    }
    for (key, expected) in [
        ("json_default_disposition", "KEEP_10_MIB"),
        ("raw_default_disposition", "KEEP_10_MIB"),
        ("form_default_disposition", "KEEP_2_MIB"),
        ("response_surface_change", "NONE_IN_THIS_FOUNDATION"),
    ] {
        if map_text(compatibility, key)? != expected {
            return Err(format!("compatibility_migration.{key} must be {expected}"));
        }
    }
    if !map_text(compatibility, "retry_policy")?.contains("bounded replayable body") {
        return Err("retry policy must address non-replayable bodies".to_owned());
    }
    if !map_text(compatibility, "multipart_policy")?.contains("bounded whole-body collection")
        || !map_text(compatibility, "multipart_policy")?.contains("16 MiB")
        || !map_text(compatibility, "multipart_policy")?.contains("not claimed")
    {
        return Err("multipart compatibility policy drifted".to_owned());
    }
    if map_text(compatibility, "h2_incoming_follow_up")?
        != "REQUIRES_EXPLICIT_OWNER_BEFORE_LIVE_INTEGRATION"
    {
        return Err("H2 incoming integration must retain explicit ownership gap".to_owned());
    }

    let evidence = object(inventory, "evidence_status")?;
    for key in [
        "rust_contract_compiled",
        "rust_contract_executed",
        "protocol_integration_executed",
        "bead_complete",
    ] {
        if map_bool(evidence, key)? {
            return Err(format!("evidence_status.{key} must remain false"));
        }
    }
    if !map_bool(evidence, "static_source_fingerprints_recorded")?
        || !map_bool(evidence, "architecture_contract_authored")?
        || !map_bool(evidence, "rust_contract_authored")?
    {
        return Err("static evidence status is incomplete".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_body_2_static_progress(inventory: &Value) -> Result<(), String> {
    let progress_value = inventory
        .get("body_2_h1_scaffold_progress")
        .ok_or_else(|| "body_2_h1_scaffold_progress must be present".to_owned())?;
    let progress = progress_value
        .as_object()
        .ok_or_else(|| "body_2_h1_scaffold_progress must be an object".to_owned())?;
    let expected_keys = string_set(&[
        "bead_id",
        "captured_date_utc",
        "base_revision",
        "progress_state",
        "execution_state",
        "modified_paths",
        "implemented_semantics",
        "authored_inline_tests",
        "remaining_gaps",
        "no_claim_boundary",
    ]);
    let actual_keys: BTreeSet<String> = progress.keys().cloned().collect();
    if actual_keys != expected_keys {
        return Err("BODY-2 static progress keys drifted".to_owned());
    }
    for (key, expected) in [
        ("bead_id", BODY_2_BEAD_ID),
        ("captured_date_utc", "2026-08-05"),
        ("base_revision", BODY_2_BASE_REVISION),
        ("progress_state", "STATIC_SOURCE_PROGRESS"),
        ("execution_state", "NOT_RUN_STATIC_ONLY"),
    ] {
        if map_text(progress, key)? != expected {
            return Err(format!(
                "body_2_h1_scaffold_progress.{key} must be {expected}"
            ));
        }
    }

    if value_string_set(progress_value, "modified_paths")?
        != string_set(&[
            "src/http/h1/stream.rs",
            "artifacts/server_incoming_body_contract_v1.json",
            "docs/server_incoming_body_contract.md",
            "tests/server_incoming_body_contract.rs",
        ])
    {
        return Err("BODY-2 modified path inventory drifted".to_owned());
    }

    let semantics = object(progress_value, "implemented_semantics")?;
    let expected_semantic_keys = string_set(&[
        "premature_disconnect_is_error",
        "explicit_completion_is_eof",
        "incoming_total_accounting_checked_before_mutation",
        "incoming_trailer_accounting_checked_before_mutation",
        "incoming_buffer_accounting_checked_before_extension",
        "fixed_length_size_hint_decreases_on_delivery",
        "producer_error_reason_mirroring",
        "live_h1_dispatch_streaming",
        "queue_byte_budget_enforced",
        "consumer_drop_signal_present",
        "drain_or_close_policy_present",
        "incoming_body_error_type_present",
        "already_terminal_repoll_error_present",
    ]);
    let actual_semantic_keys: BTreeSet<String> = semantics.keys().cloned().collect();
    if actual_semantic_keys != expected_semantic_keys {
        return Err("BODY-2 implemented semantics keys drifted".to_owned());
    }
    for key in [
        "premature_disconnect_is_error",
        "explicit_completion_is_eof",
        "incoming_total_accounting_checked_before_mutation",
        "incoming_trailer_accounting_checked_before_mutation",
        "incoming_buffer_accounting_checked_before_extension",
        "fixed_length_size_hint_decreases_on_delivery",
    ] {
        if !map_bool(semantics, key)? {
            return Err(format!("body_2 implemented_semantics.{key} must be true"));
        }
    }
    for key in [
        "live_h1_dispatch_streaming",
        "queue_byte_budget_enforced",
        "consumer_drop_signal_present",
        "drain_or_close_policy_present",
        "incoming_body_error_type_present",
        "already_terminal_repoll_error_present",
    ] {
        if map_bool(semantics, key)? {
            return Err(format!(
                "body_2 implemented_semantics.{key} must remain false"
            ));
        }
    }
    if map_text(semantics, "producer_error_reason_mirroring")?
        != "WRITER_GENERATED_HTTP_ERROR_SUBSET_AFTER_QUEUED_FRAMES"
    {
        return Err("BODY-2 producer error-reason scope drifted".to_owned());
    }

    if value_string_set(progress_value, "authored_inline_tests")?
        != string_set(&[
            "incoming_body_content_length_hint_tracks_delivered_bytes",
            "incoming_body_unfinished_producer_drop_is_not_eof",
            "incoming_body_completed_chunked_without_trailers_ends_cleanly",
            "incoming_body_chunked_finish_incomplete_errors",
            "incoming_body_limit_refuses_whole_crossing_frame_and_surfaces_error",
        ])
    {
        return Err("BODY-2 authored inline-test inventory drifted".to_owned());
    }

    let gaps = array(progress_value, "remaining_gaps")?;
    if gaps.len() != 4 {
        return Err("BODY-2 remaining-gap inventory must contain four entries".to_owned());
    }
    let joined_gaps = gaps
        .iter()
        .map(|gap| {
            gap.as_str()
                .ok_or_else(|| "BODY-2 remaining gaps must be text".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    for required in [
        "buffer the complete request",
        "queued-byte permit budget",
        "consumer-drop notification",
        "IncomingBodyError",
        "already-terminal error",
        "drain-or-close",
        "terminal telemetry",
    ] {
        if !joined_gaps.contains(required) {
            return Err(format!("BODY-2 remaining gaps must mention {required}"));
        }
    }

    let no_claim = map_text(progress, "no_claim_boundary")?;
    for required in [
        "static source receipt",
        "does not prove compilation",
        "live streaming dispatch",
        "connection reuse",
        "completion of BODY-2",
    ] {
        if !no_claim.contains(required) {
            return Err(format!("BODY-2 no-claim boundary must mention {required}"));
        }
    }
    Ok(())
}

fn validate_source_pins(inventory: &Value) -> Result<(), String> {
    let pins = array(inventory, "source_pins")?;
    let expected_paths = string_set(&[
        "src/http/mod.rs",
        "src/http/body.rs",
        "src/channel/mpsc.rs",
        "src/stream/stream.rs",
        "src/codec/framed.rs",
        "src/codec/framed_read.rs",
        "src/http/h1/mod.rs",
        "src/http/h1/stream.rs",
        "src/http/h1/codec.rs",
        "src/http/h1/types.rs",
        "src/http/h1/server.rs",
        "src/http/h2/connection.rs",
        "src/http/h2/stream.rs",
        "src/http/h2/listener.rs",
        "src/web/mod.rs",
        "src/web/extract.rs",
        "src/web/handler.rs",
        "src/web/router.rs",
        "src/web/middleware.rs",
        "src/web/multipart.rs",
        "src/web/response.rs",
        "src/web/request_region.rs",
        "src/types/cancel.rs",
        "docs/error_codes/registry.json",
        "docs/error_codes/ASUP-E501.md",
        "tests/error_code_registry_contract.rs",
        "tests/conformance/h1_body_framing.rs",
        "tests/conformance/h1_trailer_restrictions.rs",
        "tests/web_extract_content_length_audit.rs",
        "tests/web_framework_integration.rs",
    ]);
    if row_ids(pins, "path")? != expected_paths || pins.len() != expected_paths.len() {
        return Err("source pin path set drifted".to_owned());
    }
    for pin in pins {
        let path = text(pin, "path")?;
        let bytes = read_repo_bytes(path);
        let source = std::str::from_utf8(&bytes)
            .map_err(|error| format!("{path} must be UTF-8: {error}"))?;
        let expected_lines = usize::try_from(
            pin.get("line_count")
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("{path}.line_count must be an integer"))?,
        )
        .map_err(|_| format!("{path}.line_count must fit usize"))?;
        if sha256_hex(&bytes) != text(pin, "sha256")? || source.lines().count() != expected_lines {
            return Err(format!("source fingerprint drifted for {path}"));
        }
        for anchor in array(pin, "anchors")? {
            let anchor = anchor
                .as_str()
                .ok_or_else(|| format!("{path} anchors must be text"))?;
            if !source.contains(anchor) {
                return Err(format!("source anchor missing from {path}: {anchor}"));
            }
        }
    }
    Ok(())
}

fn validate_docs_and_boundaries(inventory: &Value) -> Result<(), String> {
    let doc = read_repo_file(DOC_PATH);
    if doc.matches(DOC_BEGIN).count() != 1 || doc.matches(DOC_END).count() != 1 {
        return Err("documentation markers must each appear exactly once".to_owned());
    }
    let begin = doc
        .find(DOC_BEGIN)
        .ok_or_else(|| "documentation begin marker is missing".to_owned())?;
    let end = doc
        .find(DOC_END)
        .ok_or_else(|| "documentation end marker is missing".to_owned())?;
    if begin >= end {
        return Err("documentation markers are out of order".to_owned());
    }
    for required in [
        "## Current architecture",
        "## BODY-2 static H1 scaffold progress",
        "## Public ownership contract",
        "## Terminal-state contract",
        "## Frame, queue, and total budgets",
        "## Cancellation, abort, drain, and reuse",
        "## Stable error mapping",
        "## Evidence status and no-claim boundary",
        "IncomingRequestBody",
        "IncomingBodyError",
        "is not cloneable",
        "Send + Unpin + 'static",
        "CONSUMER_DROPPED",
        "65,536 bytes",
        "524,288 bytes",
        "16,777,216 bytes",
        "JSON: 10 MiB",
        "raw bytes: 10 MiB",
        "form: 2 MiB",
        "nine mapping identifiers",
        "Null is distinct from zero",
        BODY_2_BASE_REVISION,
        "Those cases have not been compiled or run",
        "The bead must remain open",
    ] {
        if !doc.contains(required) {
            return Err(format!("documentation must contain {required}"));
        }
    }
    let boundaries = array(inventory, "no_claim_boundaries")?;
    if boundaries.len() < 8 {
        return Err("no-claim boundary is incomplete".to_owned());
    }
    let joined = boundaries
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    for required in [
        "handlers receive a streaming request body",
        "reduced memory use or improved performance",
        "protocol, cancellation, or runtime correctness",
        "broad server-stack or workspace health",
        "response streaming or incremental multipart parsing",
        "allocate an ASUP error code",
        "tracker closure",
    ] {
        if !joined.contains(required) {
            return Err(format!("no-claim boundary must mention {required}"));
        }
    }
    Ok(())
}

fn validate_inventory(inventory: &Value) -> Result<(), String> {
    validate_raw_json_key_census()?;
    validate_identity_and_authority(inventory)?;
    validate_defaults_and_inventory(inventory)?;
    validate_state_and_budgets(inventory)?;
    validate_semantics_and_telemetry(inventory)?;
    validate_cleanup_errors_and_evidence(inventory)?;
    validate_body_2_static_progress(inventory)?;
    validate_source_pins(inventory)?;
    validate_docs_and_boundaries(inventory)
}

#[test]
fn server_incoming_body_foundation_is_complete_and_source_pinned() {
    validate_inventory(&artifact()).unwrap_or_else(|error| panic!("{error}"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn server_incoming_body_contract_fails_closed_on_material_drift() {
    let base = artifact();
    let mut mutations: Vec<(&str, Value)> = Vec::new();

    let mut cloneable = base.clone();
    cloneable["incoming_body_contract"]["clone_allowed"] = Value::Bool(true);
    mutations.push(("cloneable body", cloneable));

    let mut zero_queue = base.clone();
    zero_queue["frame_and_budget_contract"]["queue_capacity_frames"] = Value::from(0_u64);
    mutations.push(("zero queue", zero_queue));

    let mut overflowing_queue = base.clone();
    overflowing_queue["frame_and_budget_contract"]["queue_capacity_frames"] = Value::from(u64::MAX);
    mutations.push(("overflowing queue", overflowing_queue));

    let mut lowered_json = base.clone();
    lowered_json["current_defaults"]["json_extractor_limit_bytes"] = Value::from(1_u64);
    mutations.push(("lowered JSON default", lowered_json));

    let mut false_integration = base.clone();
    false_integration["authority"]["handler_streaming_present"] = Value::Bool(true);
    mutations.push(("false integration claim", false_integration));

    let mut false_body_2_integration = base.clone();
    false_body_2_integration["body_2_h1_scaffold_progress"]["implemented_semantics"]["live_h1_dispatch_streaming"] =
        Value::Bool(true);
    mutations.push(("false BODY-2 integration claim", false_body_2_integration));

    let mut false_body_2_execution = base.clone();
    false_body_2_execution["body_2_h1_scaffold_progress"]["execution_state"] =
        Value::String("EXECUTED".to_owned());
    mutations.push(("false BODY-2 execution claim", false_body_2_execution));

    let mut disconnect_eof = base.clone();
    disconnect_eof["state_machine"]["disconnect_is_eof"] = Value::Bool(true);
    mutations.push(("disconnect as EOF", disconnect_eof));

    let mut reuse_before_eof = base.clone();
    reuse_before_eof["drain_and_reuse_contract"]["h1"]["reuse_when"] =
        Value::String("always reusable".to_owned());
    mutations.push(("reuse before EOF", reuse_before_eof));

    let mut unknown_state = base.clone();
    unknown_state["state_machine"]["states"][0] = Value::String("UNKNOWN".to_owned());
    mutations.push(("unknown state", unknown_state));

    let mut duplicate_surface = base.clone();
    let surfaces = duplicate_surface["current_surface_matrix"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("current_surface_matrix must be an array"));
    let duplicate_id = surfaces[0]["surface_id"].clone();
    surfaces[1]["surface_id"] = duplicate_id;
    mutations.push(("duplicate surface ID", duplicate_surface));

    let mut drifted_surface_state = base.clone();
    drifted_surface_state["current_surface_matrix"][0]["state"] =
        Value::String("BUFFERED".to_owned());
    mutations.push(("drifted non-live surface state", drifted_surface_state));

    let mut fabricated_anchor_path = base.clone();
    fabricated_anchor_path["current_surface_matrix"][0]["anchors"][0] =
        Value::String("src/http/not_real.rs::Body".to_owned());
    mutations.push(("fabricated surface anchor path", fabricated_anchor_path));

    let mut open_cleanup_graph = base.clone();
    open_cleanup_graph["drain_and_reuse_contract"]["cleanup_transitions"][0]["from"] =
        Value::String("CONSUMER_DROPPED".to_owned());
    mutations.push(("open cleanup graph", open_cleanup_graph));

    let mut lost_deadline_code = base.clone();
    lost_deadline_code["error_mapping"][3]["operator_code"] = Value::Null;
    mutations.push(("lost deadline code", lost_deadline_code));

    let mut wrong_source_status = base.clone();
    wrong_source_status["error_mapping"][5]["http_status_when_response_possible"] =
        Value::from(200_u64);
    mutations.push(("wrong source-disconnect status", wrong_source_status));

    let mut wrong_consumer_status = base.clone();
    wrong_consumer_status["error_mapping"][8]["http_status_when_response_possible"] =
        Value::from(500_u64);
    mutations.push(("wrong consumer-drop status", wrong_consumer_status));

    let mut compatibility_shim = base.clone();
    compatibility_shim["compatibility_migration"]["policy"] =
        Value::String("ADD_COMPATIBILITY_SHIM".to_owned());
    mutations.push(("compatibility shim policy", compatibility_shim));

    let mut missing_pin = base.clone();
    let _ = missing_pin["source_pins"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("source_pins must be an array"))
        .pop();
    mutations.push(("missing source pin", missing_pin));

    for (name, mutation) in mutations {
        assert!(
            validate_inventory(&mutation).is_err(),
            "mutation must fail closed: {name}"
        );
    }
}
