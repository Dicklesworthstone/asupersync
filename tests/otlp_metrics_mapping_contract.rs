//! Static contract for the OTLP A3 metrics mapping packet.
//!
//! Bead: asupersync-5z2scg.2.3
//! Artifact: artifacts/otlp_metrics_mapping_contract_v1.json
//!
//! This contract pins the retained instrument census, future owned-message
//! mapping, current embedder-owned production boundary, timestamp/reset policy,
//! cardinality and queue semantics, private schema limits, evidence gaps, source
//! fingerprints, and explicit no-claim boundary. It is not production adapter,
//! runtime, collector, or broad-workspace evidence.

#![allow(missing_docs)]

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;

const ARTIFACT_PATH: &str = "artifacts/otlp_metrics_mapping_contract_v1.json";
const DOC_PATH: &str = "docs/otlp_metrics_mapping_contract.md";
const BEAD_ID: &str = "asupersync-5z2scg.2.3";
const PROGRAM_ID: &str = "asupersync-5z2scg";
const CLAIM_REVISION: &str = "f3ccd58d8d9b740ad07b4f2197d56d70ad049125";
const DOC_BEGIN: &str = "<!-- BEGIN OTLP METRICS MAPPING CONTRACT -->";
const DOC_END: &str = "<!-- END OTLP METRICS MAPPING CONTRACT -->";

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

fn object<'a>(value: &'a Value, key: &str) -> &'a Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be text"))
}

fn map_text<'a>(value: &'a Map<String, Value>, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be text"))
}

fn map_u64(value: &Map<String, Value>, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn map_bool(value: &Map<String, Value>, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be boolean"))
}

fn assert_map_keys(value: &Map<String, Value>, expected: &[&str], context: &str) {
    let actual: BTreeSet<String> = value.keys().cloned().collect();
    assert_eq!(actual, string_set(expected), "unexpected keys in {context}");
}

fn string_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn value_string_set(value: &Value, key: &str) -> BTreeSet<String> {
    let rows = array(value, key);
    let result: BTreeSet<String> = rows
        .iter()
        .map(|row| {
            row.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be text"))
                .to_owned()
        })
        .collect();
    assert_eq!(result.len(), rows.len(), "{key} entries must be unique");
    result
}

fn value_string_vec(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|row| {
            row.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be text"))
                .to_owned()
        })
        .collect()
}

fn map_string_set(value: &Map<String, Value>, key: &str) -> BTreeSet<String> {
    let rows = value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"));
    let result: BTreeSet<String> = rows
        .iter()
        .map(|row| {
            row.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be text"))
                .to_owned()
        })
        .collect();
    assert_eq!(result.len(), rows.len(), "{key} entries must be unique");
    result
}

fn row_ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    let result: BTreeSet<String> = rows.iter().map(|row| text(row, key).to_owned()).collect();
    assert_eq!(result.len(), rows.len(), "{key} entries must be unique");
    result
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn validate_authority(value: &Value) -> Result<(), String> {
    let authority = value
        .get("authority")
        .and_then(Value::as_object)
        .ok_or_else(|| "authority must be an object".to_owned())?;
    let expected_keys = string_set(&[
        "static_contract_only",
        "production_adapter_present",
        "production_source_changes_authorized",
        "external_meter_bridge_retained",
        "dependency_cutover_authorized",
        "executable_validation_status",
        "lab_runtime_status",
        "real_collector_status",
        "tracker_closure_authorized",
        "required_disposition",
    ]);
    let actual_keys: BTreeSet<String> = authority.keys().cloned().collect();
    if actual_keys != expected_keys {
        return Err("authority keys must match the closed schema".to_owned());
    }
    for key in ["static_contract_only", "external_meter_bridge_retained"] {
        if authority.get(key).and_then(Value::as_bool) != Some(true) {
            return Err(format!("authority.{key} must be true"));
        }
    }
    for key in [
        "production_adapter_present",
        "production_source_changes_authorized",
        "dependency_cutover_authorized",
        "tracker_closure_authorized",
    ] {
        if authority.get(key).and_then(Value::as_bool) != Some(false) {
            return Err(format!("authority.{key} must be false"));
        }
    }
    if authority
        .get("executable_validation_status")
        .and_then(Value::as_str)
        != Some("UNRUN_STATIC_ONLY")
    {
        return Err("executable validation must remain UNRUN_STATIC_ONLY".to_owned());
    }
    if authority.get("lab_runtime_status").and_then(Value::as_str) != Some("UNRUN_REQUIRED") {
        return Err("LabRuntime status must remain UNRUN_REQUIRED".to_owned());
    }
    if authority
        .get("real_collector_status")
        .and_then(Value::as_str)
        != Some("UNRUN_REQUIRED")
    {
        return Err("real collector status must remain UNRUN_REQUIRED".to_owned());
    }
    if authority
        .get("required_disposition")
        .and_then(Value::as_str)
        != Some("KEEP_OPEN_PENDING_IMPLEMENTATION_AND_EXECUTABLE_EVIDENCE")
    {
        return Err("required disposition must keep the bead open".to_owned());
    }
    Ok(())
}

#[test]
fn identity_authority_and_current_boundary_are_fail_closed() {
    let inventory = artifact();
    let expected_root_keys = string_set(&[
        "schema_version",
        "artifact_id",
        "program_id",
        "bead_id",
        "captured_date_utc",
        "claim_revision",
        "purpose",
        "authority",
        "current_architecture",
        "retained_instrument_row_semantics",
        "retained_instruments",
        "unmapped_provider_callbacks",
        "discarded_provider_inputs",
        "additional_retained_surfaces",
        "dynamic_registry_mapping",
        "descriptor_and_unit_policy",
        "dynamic_stream_identity_contract",
        "temporality_timestamp_and_reset_contract",
        "attribute_ordering_and_cardinality_contract",
        "sampling_contract",
        "owned_producer_limit_decisions",
        "snapshot_queue_and_batch_contract",
        "owned_message_mapping",
        "owned_schema_limits",
        "required_golden_matrix",
        "known_gaps",
        "source_pins",
        "evidence_status",
        "follow_on_order",
        "no_claim_boundaries",
    ]);
    let actual_root_keys: BTreeSet<String> = inventory
        .as_object()
        .expect("artifact root must be an object")
        .keys()
        .cloned()
        .collect();
    assert_eq!(actual_root_keys, expected_root_keys);
    assert_eq!(inventory["schema_version"], 1);
    assert_eq!(inventory["artifact_id"], "otlp-metrics-mapping-contract-v1");
    assert_eq!(inventory["program_id"], PROGRAM_ID);
    assert_eq!(inventory["bead_id"], BEAD_ID);
    assert_eq!(inventory["captured_date_utc"], "2026-08-06");
    assert_eq!(inventory["claim_revision"], CLAIM_REVISION);
    assert_eq!(
        inventory["purpose"],
        "Freeze the reviewed OTLP-relevant Asupersync metrics surfaces, record the currently decidable owned-message mapping requirements, and fail closed on unresolved producer limits, histogram boundaries, numeric domains, reset state, and executable evidence."
    );
    validate_authority(&inventory).expect("canonical authority must validate");

    let current = object(&inventory, "current_architecture");
    assert_eq!(
        map_text(current, "capability_inventory_state"),
        "SHIPPED_VIA_DEPENDENCY"
    );
    assert_eq!(
        map_text(current, "owned_production_mapping_state"),
        "ABSENT"
    );
    assert_eq!(
        map_text(current, "surface_inventory_scope"),
        "PARTIAL_OTLP_RELEVANT_BASELINE_NOT_ALL_METRIC_TYPES_OR_PRODUCERS"
    );
    assert_eq!(
        map_text(current, "mapping_design_completion"),
        "PARTIAL_STATIC_WITH_BLOCKING_DECISIONS"
    );
    for key in [
        "capability_inventory_temporality_drift",
        "capability_inventory_queue_drift",
        "capability_inventory_a3_evidence_drift",
    ] {
        assert!(!map_text(current, key).is_empty(), "{key} must be explicit");
    }
    assert!(
        text(&inventory, "retained_instrument_row_semantics")
            .contains("required future owned-adapter mapping")
    );

    let mut false_production_claim = inventory.clone();
    false_production_claim["authority"]["production_adapter_present"] = Value::Bool(true);
    assert!(
        validate_authority(&false_production_claim).is_err(),
        "a false production-adapter claim must fail closed"
    );
}

#[test]
fn retained_instrument_census_and_mapping_are_exact() {
    let inventory = artifact();
    let rows = array(&inventory, "retained_instruments");
    let expected = [
        (
            "asupersync.tasks.active",
            "OBSERVABLE_GAUGE_U64",
            "Currently running tasks",
            "1",
        ),
        (
            "asupersync.regions.active",
            "OBSERVABLE_GAUGE_U64",
            "Currently active regions",
            "1",
        ),
        (
            "asupersync.obligations.active",
            "OBSERVABLE_GAUGE_U64",
            "Currently active obligations",
            "1",
        ),
        (
            "asupersync.tasks.spawned",
            "COUNTER_U64",
            "Total tasks spawned",
            "1",
        ),
        (
            "asupersync.tasks.completed",
            "COUNTER_U64",
            "Total tasks completed",
            "1",
        ),
        (
            "asupersync.regions.created",
            "COUNTER_U64",
            "Total regions created",
            "1",
        ),
        (
            "asupersync.regions.closed",
            "COUNTER_U64",
            "Total regions closed",
            "1",
        ),
        (
            "asupersync.cancellations",
            "COUNTER_U64",
            "Cancellation requests",
            "1",
        ),
        (
            "asupersync.deadlines.set",
            "COUNTER_U64",
            "Deadlines configured",
            "1",
        ),
        (
            "asupersync.deadlines.exceeded",
            "COUNTER_U64",
            "Deadline exceeded events",
            "1",
        ),
        (
            "asupersync.deadline.warnings_total",
            "COUNTER_U64",
            "Deadline warning events",
            "1",
        ),
        (
            "asupersync.deadline.violations_total",
            "COUNTER_U64",
            "Deadline violation events",
            "1",
        ),
        (
            "asupersync.task.stuck_detected_total",
            "COUNTER_U64",
            "Tasks detected as stuck (no progress)",
            "1",
        ),
        (
            "asupersync.obligations.created",
            "COUNTER_U64",
            "Obligations created",
            "1",
        ),
        (
            "asupersync.obligations.discharged",
            "COUNTER_U64",
            "Obligations discharged",
            "1",
        ),
        (
            "asupersync.obligations.leaked",
            "COUNTER_U64",
            "Obligations leaked",
            "1",
        ),
        (
            "asupersync.tasks.duration",
            "HISTOGRAM_F64",
            "Task execution duration in seconds",
            "s",
        ),
        (
            "asupersync.regions.lifetime",
            "HISTOGRAM_F64",
            "Region lifetime in seconds",
            "s",
        ),
        (
            "asupersync.cancellation.drain_duration",
            "HISTOGRAM_F64",
            "Cancellation drain duration in seconds",
            "s",
        ),
        (
            "asupersync.deadline.remaining_seconds",
            "HISTOGRAM_F64",
            "Time remaining at completion in seconds",
            "s",
        ),
        (
            "asupersync.checkpoint.interval_seconds",
            "HISTOGRAM_F64",
            "Time between checkpoints in seconds",
            "s",
        ),
        (
            "asupersync.scheduler.poll_time",
            "HISTOGRAM_F64",
            "Scheduler poll duration in seconds",
            "s",
        ),
        (
            "asupersync.scheduler.tasks_polled",
            "HISTOGRAM_F64",
            "Tasks polled per scheduler tick",
            "1",
        ),
    ];
    assert_eq!(rows.len(), expected.len());

    let by_name: BTreeMap<&str, &Value> = rows.iter().map(|row| (text(row, "name"), row)).collect();
    assert_eq!(by_name.len(), rows.len(), "instrument names must be unique");
    let expected_callbacks: BTreeMap<&str, &str> = [
        (
            "asupersync.tasks.active",
            "task_spawned plus task_completed",
        ),
        (
            "asupersync.regions.active",
            "region_created plus region_closed",
        ),
        (
            "asupersync.obligations.active",
            "obligation_created plus obligation_discharged or obligation_leaked",
        ),
        ("asupersync.tasks.spawned", "task_spawned"),
        ("asupersync.tasks.completed", "task_completed"),
        ("asupersync.regions.created", "region_created"),
        ("asupersync.regions.closed", "region_closed"),
        ("asupersync.cancellations", "cancellation_requested"),
        ("asupersync.deadlines.set", "deadline_set"),
        ("asupersync.deadlines.exceeded", "deadline_exceeded"),
        ("asupersync.deadline.warnings_total", "deadline_warning"),
        ("asupersync.deadline.violations_total", "deadline_violation"),
        (
            "asupersync.task.stuck_detected_total",
            "task_stuck_detected",
        ),
        ("asupersync.obligations.created", "obligation_created"),
        ("asupersync.obligations.discharged", "obligation_discharged"),
        ("asupersync.obligations.leaked", "obligation_leaked"),
        ("asupersync.tasks.duration", "task_completed"),
        ("asupersync.regions.lifetime", "region_closed"),
        ("asupersync.cancellation.drain_duration", "drain_completed"),
        (
            "asupersync.deadline.remaining_seconds",
            "deadline_remaining",
        ),
        (
            "asupersync.checkpoint.interval_seconds",
            "checkpoint_interval",
        ),
        ("asupersync.scheduler.poll_time", "scheduler_tick"),
        ("asupersync.scheduler.tasks_polled", "scheduler_tick"),
    ]
    .into_iter()
    .collect();
    for (name, kind, description, semantic_unit) in expected {
        let row = by_name
            .get(name)
            .unwrap_or_else(|| panic!("missing retained instrument {name}"));
        assert_map_keys(
            row.as_object()
                .unwrap_or_else(|| panic!("instrument {name} must be an object")),
            &[
                "name",
                "kind",
                "description",
                "semantic_unit",
                "incumbent_descriptor_unit",
                "attributes",
                "sampling_group",
                "provider_callback",
                "owned_metric_data",
                "owned_aggregation",
                "owned_temporality",
                "exemplars",
            ],
            name,
        );
        assert_eq!(text(row, "kind"), kind, "kind mismatch for {name}");
        assert_eq!(
            text(row, "description"),
            description,
            "description mismatch for {name}"
        );
        assert_eq!(
            text(row, "semantic_unit"),
            semantic_unit,
            "semantic unit mismatch for {name}"
        );
        assert_eq!(text(row, "incumbent_descriptor_unit"), "");
        assert_eq!(text(row, "exemplars"), "EMPTY");
        assert_eq!(
            text(row, "provider_callback"),
            expected_callbacks[name],
            "provider callback mismatch for {name}"
        );
    }

    let expected_labels: BTreeMap<&str, BTreeSet<String>> = [
        ("asupersync.tasks.completed", string_set(&["outcome"])),
        ("asupersync.tasks.duration", string_set(&["outcome"])),
        ("asupersync.cancellations", string_set(&["kind"])),
        (
            "asupersync.deadline.warnings_total",
            string_set(&["reason", "task_type"]),
        ),
        (
            "asupersync.deadline.violations_total",
            string_set(&["task_type"]),
        ),
        (
            "asupersync.deadline.remaining_seconds",
            string_set(&["task_type"]),
        ),
        (
            "asupersync.checkpoint.interval_seconds",
            string_set(&["task_type"]),
        ),
        (
            "asupersync.task.stuck_detected_total",
            string_set(&["task_type"]),
        ),
    ]
    .into_iter()
    .collect();
    for (name, row) in &by_name {
        let kind = text(row, "kind");
        let actual = value_string_set(row, "attributes");
        let expected = expected_labels.get(name).cloned().unwrap_or_default();
        assert_eq!(actual, expected, "attribute mismatch for {name}");
        let ordered = value_string_vec(row, "attributes");
        let mut sorted = ordered.clone();
        sorted.sort_unstable();
        assert_eq!(ordered, sorted, "attributes must be ordered for {name}");

        let expected_sampling = if kind == "HISTOGRAM_F64" {
            if name.starts_with("asupersync.scheduler.") {
                "asupersync.scheduler"
            } else {
                "SELF"
            }
        } else {
            "UNSAMPLED"
        };
        assert_eq!(
            text(row, "sampling_group"),
            expected_sampling,
            "sampling group mismatch for {name}"
        );

        let (expected_data, expected_aggregation, expected_temporality) = match kind {
            "OBSERVABLE_GAUGE_U64" => (
                "Gauge(NumberDataPoint::Int)",
                "LAST_VALUE_AT_COLLECTION",
                "NOT_APPLICABLE",
            ),
            "COUNTER_U64" if actual.is_empty() => {
                ("Sum(NumberDataPoint::Int)", "MONOTONIC_SUM", "CUMULATIVE")
            }
            "COUNTER_U64" => (
                "Sum(NumberDataPoint::Int)",
                "MONOTONIC_SUM_PER_ATTRIBUTE_SET",
                "CUMULATIVE",
            ),
            "HISTOGRAM_F64" if actual.is_empty() => (
                "Histogram(HistogramDataPoint)",
                "EXPLICIT_BUCKET_HISTOGRAM",
                "CUMULATIVE",
            ),
            "HISTOGRAM_F64" => (
                "Histogram(HistogramDataPoint)",
                "EXPLICIT_BUCKET_HISTOGRAM_PER_ATTRIBUTE_SET",
                "CUMULATIVE",
            ),
            other => panic!("unexpected retained instrument kind {other}"),
        };
        assert_eq!(text(row, "owned_metric_data"), expected_data);
        assert_eq!(text(row, "owned_aggregation"), expected_aggregation);
        assert_eq!(text(row, "owned_temporality"), expected_temporality);
    }

    let cardinality = object(&inventory, "attribute_ordering_and_cardinality_contract");
    let tracked = map_string_set(cardinality, "tracker_visible_fixed_metric_names");
    let expected_tracked: BTreeSet<String> = expected_labels
        .keys()
        .map(|name| (*name).to_owned())
        .collect();
    assert_eq!(tracked, expected_tracked);

    let hooks = array(&inventory, "unmapped_provider_callbacks");
    assert_eq!(hooks.len(), 1);
    assert_map_keys(
        hooks[0]
            .as_object()
            .expect("unmapped provider callback must be an object"),
        &[
            "callback",
            "current_otel_metrics_behavior",
            "required_disposition",
            "closure_blocker",
        ],
        "unmapped_provider_callbacks row",
    );
    assert_eq!(text(&hooks[0], "callback"), "MetricsProvider::record_panic");
    assert_eq!(
        text(&hooks[0], "current_otel_metrics_behavior"),
        "INHERITED_NO_OP"
    );
    assert_eq!(
        text(&hooks[0], "required_disposition"),
        "ADD_A_VERSIONED_COUNTER_MAPPING_OR_EXPLICITLY_KEEP_UNSUPPORTED_BEFORE_CUTOVER"
    );
    assert_eq!(hooks[0]["closure_blocker"].as_bool(), Some(true));

    let dynamic_rows = array(&inventory, "dynamic_registry_mapping");
    let expected_dynamic: BTreeMap<&str, (&str, &str, &str, &str)> = [
        (
            "Counter",
            (
                "Sum(NumberDataPoint::Int)",
                "CUMULATIVE",
                "MONOTONIC_SUM",
                "BLOCKED_ON_U64_TO_I64_RANGE_POLICY_AND_EPOCH_STATE",
            ),
        ),
        (
            "Gauge",
            (
                "Gauge(NumberDataPoint::Int)",
                "NOT_APPLICABLE",
                "LAST_VALUE_AT_COLLECTION",
                "DESIGN_COMPLETE_IMPLEMENTATION_ABSENT",
            ),
        ),
        (
            "Histogram",
            (
                "Histogram(HistogramDataPoint)",
                "CUMULATIVE",
                "EXPLICIT_BUCKET_HISTOGRAM",
                "USE_HISTOGRAM_SNAPSHOT_DIRECTLY_OR_EXTEND_SNAPSHOT_WITHOUT_LOSS",
            ),
        ),
        (
            "Summary",
            (
                "Summary(SummaryDataPoint)",
                "NOT_APPLICABLE",
                "EXACT_COUNT_AND_SUM_PLUS_BOUNDED_ROLLING_QUANTILE_SAMPLE",
                "BLOCKED_ON_SNAPSHOT_AND_QUANTILE_POLICY",
            ),
        ),
    ]
    .into_iter()
    .collect();
    assert_eq!(dynamic_rows.len(), expected_dynamic.len());
    let expected_dynamic_kinds: BTreeSet<String> = expected_dynamic
        .keys()
        .map(|kind| (*kind).to_owned())
        .collect();
    assert_eq!(
        row_ids(dynamic_rows, "registry_kind"),
        expected_dynamic_kinds
    );
    for row in dynamic_rows {
        let map = row
            .as_object()
            .expect("dynamic mapping row must be an object");
        assert_map_keys(
            map,
            &[
                "registry_kind",
                "owned_metric_data",
                "temporality",
                "aggregation",
                "available_snapshot_fidelity",
                "mapping_state",
            ],
            "dynamic_registry_mapping row",
        );
        let kind = text(row, "registry_kind");
        let expected = expected_dynamic
            .get(kind)
            .unwrap_or_else(|| panic!("unexpected registry kind {kind}"));
        assert_eq!(text(row, "owned_metric_data"), expected.0);
        assert_eq!(text(row, "temporality"), expected.1);
        assert_eq!(text(row, "aggregation"), expected.2);
        assert_eq!(text(row, "mapping_state"), expected.3);
        assert!(!text(row, "available_snapshot_fidelity").is_empty());
    }

    let discarded_rows = array(&inventory, "discarded_provider_inputs");
    let expected_discarded: BTreeMap<&str, BTreeSet<String>> = [
        ("task_spawned", string_set(&["region_id", "task_id"])),
        ("task_completed", string_set(&["task_id"])),
        (
            "region_created",
            string_set(&["parent_region_id", "region_id"]),
        ),
        ("region_closed", string_set(&["region_id"])),
        ("cancellation_requested", string_set(&["region_id"])),
        ("drain_completed", string_set(&["region_id"])),
        ("deadline_set", string_set(&["deadline", "region_id"])),
        ("deadline_exceeded", string_set(&["region_id"])),
        ("deadline_warning", string_set(&["remaining"])),
        ("deadline_violation", string_set(&["over_by"])),
        (
            "obligation_created or obligation_discharged or obligation_leaked",
            string_set(&["region_id"]),
        ),
    ]
    .into_iter()
    .collect();
    assert_eq!(discarded_rows.len(), expected_discarded.len());
    let expected_discarded_callbacks: BTreeSet<String> = expected_discarded
        .keys()
        .map(|callback| (*callback).to_owned())
        .collect();
    assert_eq!(
        row_ids(discarded_rows, "callback"),
        expected_discarded_callbacks
    );
    for row in discarded_rows {
        let map = row
            .as_object()
            .expect("discarded input row must be an object");
        assert_map_keys(map, &["callback", "discarded"], "discarded input row");
        let callback = text(row, "callback");
        assert_eq!(
            value_string_set(row, "discarded"),
            expected_discarded[callback],
            "discarded inputs mismatch for {callback}"
        );
    }

    let additional = array(&inventory, "additional_retained_surfaces");
    let additional_by_id: BTreeMap<&str, &Value> = additional
        .iter()
        .map(|row| (text(row, "surface_id"), row))
        .collect();
    assert_eq!(additional.len(), additional_by_id.len());
    assert_eq!(additional_by_id.len(), 3);
    assert_eq!(
        row_ids(additional, "surface_id"),
        string_set(&[
            "RUNTIME-METRICS-FEATURE",
            "DYNAMIC-METRICS-REGISTRY-PRODUCERS",
            "DIRECT-METRIC-INSTRUMENT-PRODUCERS",
        ])
    );

    let runtime = additional_by_id["RUNTIME-METRICS-FEATURE"];
    assert_map_keys(
        runtime
            .as_object()
            .expect("runtime surface must be an object"),
        &[
            "surface_id",
            "path",
            "state",
            "counters",
            "gauges",
            "reset_behavior",
            "owned_mapping_state",
        ],
        "runtime metrics retained surface",
    );
    assert_eq!(text(runtime, "path"), "src/runtime/metrics.rs");
    assert_eq!(
        value_string_set(runtime, "counters"),
        string_set(&[
            "sched_yield_calls",
            "timer_threads_spawned",
            "timers_cancelled",
            "timers_fired",
            "timers_registered",
            "worker_parks",
            "worker_spins",
            "worker_unparks",
        ])
    );
    assert_eq!(
        value_string_set(runtime, "gauges"),
        string_set(&["active_timers"])
    );
    assert_eq!(text(runtime, "owned_mapping_state"), "UNMAPPED_GAP");

    let dynamic = additional_by_id["DYNAMIC-METRICS-REGISTRY-PRODUCERS"];
    assert_map_keys(
        dynamic
            .as_object()
            .expect("dynamic surface must be an object"),
        &[
            "surface_id",
            "paths",
            "state",
            "examples",
            "owned_mapping_state",
        ],
        "dynamic registry retained surface",
    );
    assert_eq!(
        value_string_set(dynamic, "paths"),
        string_set(&[
            "src/observability/pressure_governor.rs",
            "src/raptorq/pipeline.rs",
        ])
    );
    assert_eq!(
        text(dynamic, "owned_mapping_state"),
        "TYPE_LEVEL_MAPPING_ONLY_NAME_CENSUS_INCOMPLETE"
    );

    let direct = additional_by_id["DIRECT-METRIC-INSTRUMENT-PRODUCERS"];
    assert_map_keys(
        direct
            .as_object()
            .expect("direct surface must be an object"),
        &[
            "surface_id",
            "paths",
            "state",
            "examples",
            "owned_mapping_state",
        ],
        "direct instrument retained surface",
    );
    assert_eq!(
        value_string_set(direct, "paths"),
        string_set(&[
            "src/agent_swarm/release_proof_aggregator.rs",
            "src/net/atp/quic/metrics.rs",
            "src/observability/network_truth.rs",
        ])
    );
    assert_eq!(text(direct, "owned_mapping_state"), "UNMAPPED_GAP");
}

#[test]
fn policy_limits_golden_matrix_and_gaps_are_explicit() {
    let inventory = artifact();

    let descriptor = object(&inventory, "descriptor_and_unit_policy");
    assert_map_keys(
        descriptor,
        &[
            "name_policy",
            "description_policy",
            "incumbent_unit_fact",
            "owned_cutover_policy",
            "semantic_unit_field",
            "metadata_policy",
        ],
        "descriptor_and_unit_policy",
    );
    assert!(map_text(descriptor, "incumbent_unit_fact").contains("never with_unit"));
    assert!(map_text(descriptor, "owned_cutover_policy").contains("empty Metric.unit"));

    let identity = object(&inventory, "dynamic_stream_identity_contract");
    assert_map_keys(
        identity,
        &[
            "descriptor_identity_fields",
            "stream_identity_fields",
            "attribute_form",
            "metric_grouping",
            "duplicate_exact_identity",
            "same_name_conflicting_kind_or_descriptor",
            "duplicate_point_identity",
            "coalescing",
            "current_snapshot_gap",
        ],
        "dynamic_stream_identity_contract",
    );
    assert_eq!(
        map_string_set(identity, "descriptor_identity_fields"),
        string_set(&["description", "kind", "name", "unit"])
    );
    assert_eq!(
        map_string_set(identity, "stream_identity_fields"),
        string_set(&["attributes", "description", "kind", "name", "unit"])
    );
    for key in [
        "duplicate_exact_identity",
        "same_name_conflicting_kind_or_descriptor",
        "duplicate_point_identity",
    ] {
        assert_eq!(
            map_text(identity, key),
            "HARD_REJECT_BEFORE_MODEL_CONSTRUCTION"
        );
    }

    let timing = object(&inventory, "temporality_timestamp_and_reset_contract");
    assert_eq!(
        map_text(timing, "production_meter_bridge_ownership"),
        "EMBEDDER_OWNED_NOT_ENFORCED_BY_ASUPERSYNC"
    );
    assert_eq!(
        map_text(timing, "required_owned_sum_temporality"),
        "CUMULATIVE_ONLY"
    );
    assert_eq!(
        map_text(timing, "required_owned_histogram_temporality"),
        "CUMULATIVE_ONLY"
    );
    for key in [
        "current_fixture_gap",
        "counter_range_policy",
        "observable_gauge_range_policy",
        "counter_wrap_policy",
        "scheduler_tasks_polled_precision",
        "clock_authority",
    ] {
        assert!(!map_text(timing, key).is_empty(), "{key} must be explicit");
    }

    let cardinality = object(&inventory, "attribute_ordering_and_cardinality_contract");
    let defaults = cardinality
        .get("otel_metrics_defaults")
        .and_then(Value::as_object)
        .expect("otel_metrics_defaults must be an object");
    assert_eq!(map_u64(defaults, "max_cardinality_per_metric"), 1000);
    assert_eq!(map_u64(defaults, "max_metric_names"), 4096);
    assert_eq!(map_text(defaults, "overflow_strategy"), "Drop");
    assert!(defaults["sampling"].is_null());
    let zero = cardinality
        .get("otel_metrics_zero_semantics")
        .and_then(Value::as_object)
        .expect("otel_metrics_zero_semantics must be an object");
    assert_eq!(
        map_text(zero, "max_cardinality_zero"),
        "PRIMARY_ADMISSION_OVERFLOWS_EVERY_FRESH_LABEL_SET"
    );
    assert_eq!(
        map_text(zero, "max_cardinality_zero_drop"),
        "OMIT_AND_COUNT_OVERFLOW"
    );
    assert_eq!(
        map_text(zero, "max_cardinality_zero_aggregate"),
        "AGGREGATE_RETRY_ALSO_OVERFLOWS_UNLESS_ALREADY_ADMITTED_THEN_OMIT"
    );
    assert_eq!(
        map_text(zero, "max_cardinality_zero_warn"),
        "WARN_THEN_RECORD_BEYOND_ZERO_CAP"
    );
    assert_eq!(map_text(zero, "max_metrics_zero"), "UNLIMITED_METRIC_NAMES");
    let registry = cardinality
        .get("dynamic_registry_defaults")
        .and_then(Value::as_object)
        .expect("dynamic_registry_defaults must be an object");
    assert_eq!(map_u64(registry, "per_kind_metric_name_cap"), 10_000);
    assert_eq!(map_text(registry, "zero_means"), "UNLIMITED");

    let sampling = object(&inventory, "sampling_contract");
    assert_map_keys(
        sampling,
        &[
            "rate_input",
            "threshold",
            "granularity",
            "selector",
            "sequence",
            "admission_order",
            "paired_callback_divergence",
            "reweighting",
            "concurrency",
            "required_owned_nan_policy",
        ],
        "sampling_contract",
    );
    assert_eq!(
        map_text(sampling, "granularity"),
        "ONE_PERCENT_WITH_DOWNWARD_QUANTIZATION"
    );
    assert_eq!(map_text(sampling, "reweighting"), "NONE");
    assert_eq!(
        map_text(sampling, "required_owned_nan_policy"),
        "HARD_REJECT_CONFIGURATION_BEFORE_PROVIDER_CONSTRUCTION"
    );
    assert!(map_text(sampling, "threshold").contains("NaN casts to zero"));
    assert!(map_text(sampling, "admission_order").contains("before task_type"));

    let producer_limits = object(&inventory, "owned_producer_limit_decisions");
    assert_map_keys(
        producer_limits,
        &[
            "decision_state",
            "points_per_metric",
            "metrics_per_scope_batch",
            "batch_bytes",
            "queue_depth",
            "queue_overload",
            "histogram_bound_vectors",
            "summary_quantiles",
            "resolution_rule",
        ],
        "owned_producer_limit_decisions",
    );
    assert_eq!(
        map_text(producer_limits, "decision_state"),
        "UNRESOLVED_CLOSURE_BLOCKER"
    );
    for key in [
        "points_per_metric",
        "metrics_per_scope_batch",
        "batch_bytes",
        "queue_depth",
        "queue_overload",
        "histogram_bound_vectors",
        "summary_quantiles",
    ] {
        assert!(
            map_text(producer_limits, key).contains("UNSELECTED"),
            "{key} must remain unresolved"
        );
    }
    assert!(map_text(producer_limits, "resolution_rule").contains("covered by goldens"));

    let queue = object(&inventory, "snapshot_queue_and_batch_contract");
    assert_eq!(
        map_text(queue, "queue_overload"),
        "DROP_OLDEST_THEN_RETAIN_FIFO"
    );
    assert_eq!(
        map_text(queue, "snapshot_entry_limit"),
        "EXPLICIT_UNBOUNDED"
    );
    assert_eq!(
        map_text(queue, "snapshot_label_limit"),
        "EXPLICIT_UNBOUNDED"
    );
    assert_eq!(
        map_text(queue, "snapshot_batch_byte_limit"),
        "EXPLICIT_UNBOUNDED"
    );
    assert!(map_text(queue, "queue_capacity_zero").contains("EFFECTIVE_DEPTH_ONE"));

    let message = object(&inventory, "owned_message_mapping");
    assert_map_keys(
        message,
        &[
            "request",
            "nesting",
            "counter",
            "gauge",
            "histogram",
            "summary",
            "exponential_histogram",
            "exemplars",
            "metric_order",
            "partial_output",
        ],
        "owned_message_mapping",
    );
    assert_eq!(
        map_text(message, "request"),
        "collector::metrics::ExportMetricsServiceRequest"
    );
    assert!(map_text(message, "counter").contains("Cumulative"));
    assert!(map_text(message, "histogram").contains("bounds_len_plus_one"));
    assert!(map_text(message, "partial_output").contains("No model or wire bytes"));

    let limits = object(&inventory, "owned_schema_limits");
    assert_map_keys(
        limits,
        &[
            "default_max_message_bytes",
            "default_max_wire_fields",
            "default_max_wire_depth",
            "default_max_wire_work_bytes",
            "hard_protobuf_message_ceiling_bytes",
            "wire_envelope_configurability",
            "max_total_repeated_items",
            "max_total_any_value_nodes",
            "max_total_owned_bytes",
            "resource_groups_per_request",
            "scopes_per_resource_group",
            "metrics_per_scope",
            "data_points_per_metric",
            "attributes_per_owner",
            "metric_metadata_entries",
            "exemplars_per_data_point",
            "histogram_bucket_counts",
            "histogram_explicit_bounds",
            "exponential_histogram_buckets_per_sign",
            "summary_quantiles",
            "attribute_key_bytes",
            "attribute_value_bytes",
            "schema_url_bytes",
            "scope_name_bytes",
            "scope_version_bytes",
            "metric_name_bytes",
            "metric_description_bytes",
            "metric_unit_bytes",
            "limit_failure",
            "producer_note",
        ],
        "owned_schema_limits",
    );
    for (key, expected) in [
        ("default_max_message_bytes", 4_194_304),
        ("default_max_wire_fields", 65_536),
        ("default_max_wire_depth", 100),
        ("default_max_wire_work_bytes", 16_777_216),
        ("hard_protobuf_message_ceiling_bytes", 2_147_483_647),
        ("max_total_repeated_items", 65_536),
        ("max_total_any_value_nodes", 4_096),
        ("max_total_owned_bytes", 4_194_304),
        ("resource_groups_per_request", 64),
        ("scopes_per_resource_group", 128),
        ("metrics_per_scope", 4_096),
        ("data_points_per_metric", 1_000),
        ("attributes_per_owner", 128),
        ("metric_metadata_entries", 128),
        ("exemplars_per_data_point", 128),
        ("histogram_bucket_counts", 4_096),
        ("histogram_explicit_bounds", 4_095),
        ("exponential_histogram_buckets_per_sign", 4_096),
        ("summary_quantiles", 1_024),
        ("attribute_key_bytes", 1_024),
        ("attribute_value_bytes", 4_096),
        ("schema_url_bytes", 2_048),
        ("scope_name_bytes", 1_024),
        ("scope_version_bytes", 1_024),
        ("metric_name_bytes", 1_024),
        ("metric_description_bytes", 4_096),
        ("metric_unit_bytes", 256),
    ] {
        assert_eq!(
            map_u64(limits, key),
            expected,
            "owned limit mismatch for {key}"
        );
    }
    assert_eq!(
        map_text(limits, "limit_failure"),
        "TYPED_HARD_REJECT_WITHOUT_PARTIAL_FRESH_MODEL"
    );
    assert!(
        map_text(limits, "wire_envelope_configurability")
            .contains("defaults, not immutable schema caps")
    );
    assert!(
        map_text(limits, "producer_note").contains("do not make an unbounded producer bounded")
    );

    let expected_goldens = string_set(&[
        "A3-GOLDEN-INSTRUMENT-CENSUS",
        "A3-GOLDEN-CUMULATIVE-EPOCH",
        "A3-GOLDEN-COUNTER-RESET",
        "A3-GOLDEN-COUNTER-RANGE",
        "A3-GOLDEN-HISTOGRAM-SHAPE",
        "A3-GOLDEN-TIMESTAMPS",
        "A3-GOLDEN-ATTRIBUTES",
        "A3-GOLDEN-CARDINALITY",
        "A3-GOLDEN-ZERO-CARDINALITY-STRATEGIES",
        "A3-GOLDEN-WARN-BOUNDARY",
        "A3-GOLDEN-SUMMARY-NEGATIVE",
        "A3-GOLDEN-NUMERIC-DOMAINS",
        "A3-GOLDEN-DYNAMIC-IDENTITY",
        "A3-GOLDEN-SAMPLING",
        "A3-GOLDEN-RETAINED-SURFACE-CENSUS",
        "A3-GOLDEN-PRODUCER-ENVELOPE",
        "A3-GOLDEN-PANIC-DISPOSITION",
        "A3-GOLDEN-LAB-REPLAY",
        "A3-GOLDEN-REAL-COLLECTOR",
    ]);
    let golden_rows = array(&inventory, "required_golden_matrix");
    assert_eq!(row_ids(golden_rows, "case_id"), expected_goldens);
    for row in golden_rows {
        assert_map_keys(
            row.as_object().expect("golden row must be an object"),
            &[
                "case_id",
                "requirement",
                "current_evidence",
                "acceptance_state",
            ],
            "required_golden_matrix row",
        );
        assert!(!text(row, "requirement").is_empty());
        assert!(!text(row, "current_evidence").is_empty());
        assert_ne!(text(row, "acceptance_state"), "COMPLETE");
    }

    let expected_gaps = string_set(&[
        "A3-GAP-OWNED-ADAPTER",
        "A3-GAP-EPOCH",
        "A3-GAP-HISTOGRAM-BOUNDS",
        "A3-GAP-U64-RANGE",
        "A3-GAP-SUMMARY",
        "A3-GAP-SUMMARY-NEGATIVE",
        "A3-GAP-NUMERIC-DOMAINS",
        "A3-GAP-PANIC",
        "A3-GAP-DETERMINISTIC-SAMPLING",
        "A3-GAP-SAMPLING-NAN-ORDER",
        "A3-GAP-SCHEDULER-PRECISION",
        "A3-GAP-EMPTY-LABEL-VALUE",
        "A3-GAP-WARN-UNBOUNDED",
        "A3-GAP-AGGREGATE",
        "A3-GAP-BATCH-ENVELOPE",
        "A3-GAP-PRODUCER-LIMIT-DECISIONS",
        "A3-GAP-DYNAMIC-IDENTITY",
        "A3-GAP-RETAINED-SURFACE-CENSUS",
        "A3-GAP-INVENTORY-DRIFT",
        "A3-GAP-INTEGRATION-CENSUS",
        "A3-GAP-EXECUTION",
    ]);
    let gap_rows = array(&inventory, "known_gaps");
    assert_eq!(row_ids(gap_rows, "gap_id"), expected_gaps);
    for row in gap_rows {
        assert_map_keys(
            row.as_object().expect("gap row must be an object"),
            &["gap_id", "summary", "closure_blocker"],
            "known_gaps row",
        );
        assert!(!text(row, "summary").is_empty());
        assert_eq!(row["closure_blocker"].as_bool(), Some(true));
    }
}

#[test]
fn source_pins_and_documentation_match_the_claim_revision() {
    let inventory = artifact();
    let pins = array(&inventory, "source_pins");
    let expected_paths = string_set(&[
        "src/observability/metrics.rs",
        "src/observability/otel.rs",
        "src/observability/otlp_proto.rs",
        "src/observability/mod.rs",
        "src/grpc/protobuf_wire.rs",
        "src/grpc/protobuf.rs",
        "src/runtime/deadline_monitor.rs",
        "src/runtime/metrics.rs",
        "src/observability/pressure_governor.rs",
        "src/raptorq/pipeline.rs",
        "src/net/atp/quic/metrics.rs",
        "src/agent_swarm/release_proof_aggregator.rs",
        "src/observability/network_truth.rs",
        "tests/otlp_metrics_request_golden.rs",
        "tests/observability_metrics_conformance_harness.rs",
        "tests/otel_metric_counter_monotonicity_audit.rs",
        "tests/otel_metrics.rs",
        "tests/protobuf_owned_otlp_schema_contract.rs",
        "tests/golden/otel/otlp_metrics_request_README.md",
        "artifacts/otlp_capability_inventory_v1.json",
        "artifacts/protobuf_owned_otlp_schema_v1.json",
        "docs/otlp_capability_inventory.md",
        "docs/adr/dep_plan_adr_003_otlp_ecosystem.md",
    ]);
    assert_eq!(pins.len(), expected_paths.len());
    let mut paths = BTreeSet::new();
    for pin in pins {
        assert_map_keys(
            pin.as_object().expect("source pin must be an object"),
            &["path", "sha256", "line_count", "anchors"],
            "source_pins row",
        );
        let path = text(pin, "path");
        assert!(
            paths.insert(path.to_owned()),
            "duplicate source pin for {path}"
        );
        let bytes = read_repo_bytes(path);
        assert_eq!(
            sha256_hex(&bytes),
            text(pin, "sha256"),
            "source fingerprint drift for {path}"
        );
        let source = String::from_utf8(bytes)
            .unwrap_or_else(|error| panic!("{path} must be UTF-8: {error}"));
        assert_eq!(
            source.lines().count() as u64,
            pin["line_count"]
                .as_u64()
                .unwrap_or_else(|| panic!("line_count must be unsigned for {path}")),
            "line-count drift for {path}"
        );
        let anchors = array(pin, "anchors");
        assert!(!anchors.is_empty(), "{path} must have source anchors");
        for anchor in anchors {
            let anchor = anchor
                .as_str()
                .unwrap_or_else(|| panic!("source anchor must be text for {path}"));
            assert!(
                source.contains(anchor),
                "missing source anchor {anchor:?} in {path}"
            );
        }
    }
    assert_eq!(paths, expected_paths);

    let docs = read_repo_file(DOC_PATH);
    assert_eq!(docs.matches(DOC_BEGIN).count(), 1);
    assert_eq!(docs.matches(DOC_END).count(), 1);
    assert!(
        docs.find(DOC_BEGIN) < docs.find(DOC_END),
        "documentation markers must be ordered"
    );
    assert!(docs.contains(CLAIM_REVISION));
    for required in [
        BEAD_ID,
        ARTIFACT_PATH,
        "23 instruments",
        "EMBEDDER_OWNED_NOT_ENFORCED_BY_ASUPERSYNC",
        "drops the oldest batch",
        "i64::MAX + 1",
        "UNRUN_STATIC_ONLY",
        "exhaustive retained surface",
        "exact producer limits",
        "panic-callback",
        "The bead stays open",
        "This packet does not implement an owned production adapter",
    ] {
        assert!(
            docs.contains(required),
            "documentation missing {required:?}"
        );
    }
}

#[test]
fn evidence_and_no_claims_cannot_be_promoted_by_the_static_packet() {
    let inventory = artifact();
    let evidence = object(&inventory, "evidence_status");
    assert_map_keys(
        evidence,
        &[
            "claim_time_source_inventory",
            "retained_fixed_instrument_census",
            "all_retained_surface_census",
            "dynamic_registry_mapping",
            "owned_producer_limit_design",
            "owned_schema_limit_inventory",
            "prior_a3_integration_receipt",
            "dedicated_contract_source",
            "feature_compile",
            "contract_execution",
            "lab_runtime",
            "real_collector",
            "tracker_status",
        ],
        "evidence_status",
    );
    assert_eq!(
        map_text(evidence, "claim_time_source_inventory"),
        "COMPLETE_STATIC"
    );
    assert_eq!(
        map_text(evidence, "retained_fixed_instrument_census"),
        "COMPLETE_STATIC_23"
    );
    assert_eq!(
        map_text(evidence, "all_retained_surface_census"),
        "PARTIAL_STATIC_CLOSURE_BLOCKER"
    );
    assert_eq!(
        map_text(evidence, "dynamic_registry_mapping"),
        "COMPLETE_STATIC_WITH_BLOCKERS"
    );
    assert_eq!(
        map_text(evidence, "owned_producer_limit_design"),
        "UNRESOLVED_CLOSURE_BLOCKER"
    );
    assert_eq!(
        map_text(evidence, "owned_schema_limit_inventory"),
        "COMPLETE_STATIC"
    );
    assert_eq!(
        map_text(evidence, "prior_a3_integration_receipt"),
        "PARTIAL_EXECUTED_NOT_ACCEPTANCE_COMPLETE"
    );
    assert_eq!(
        map_text(evidence, "dedicated_contract_source"),
        "AUTHORED_UNRUN"
    );
    assert_eq!(map_text(evidence, "feature_compile"), "UNRUN");
    assert_eq!(map_text(evidence, "contract_execution"), "UNRUN");
    assert_eq!(map_text(evidence, "lab_runtime"), "UNRUN");
    assert_eq!(map_text(evidence, "real_collector"), "UNRUN");
    assert_eq!(map_text(evidence, "tracker_status"), "OPEN");

    let authority = object(&inventory, "authority");
    assert!(map_bool(authority, "static_contract_only"));
    assert!(!map_bool(authority, "production_adapter_present"));
    assert!(!map_bool(authority, "dependency_cutover_authorized"));
    assert!(!map_bool(authority, "tracker_closure_authorized"));

    let no_claims = array(&inventory, "no_claim_boundaries");
    assert_eq!(
        value_string_set(&inventory, "no_claim_boundaries"),
        string_set(&[
            "This static packet does not implement or prove an owned production metrics adapter.",
            "It does not prove compilation, formatting, tests, LabRuntime determinism, collector interoperability, feature-matrix health, or broad workspace health.",
            "It does not prove that the current external SDK chooses these temporality, aggregation, timestamp, histogram-boundary, or exemplar policies.",
            "It does not treat the generated-message fixture or JSON-only golden as owned protobuf production evidence.",
            "It does not authorize removal of opentelemetry, opentelemetry_sdk, the caller-supplied Meter bridge, or any retained public API.",
            "It does not authorize tracker closure, release readiness, performance claims, or local execution fallback.",
        ])
    );
    assert_eq!(no_claims.len(), 6);

    let follow_on = array(&inventory, "follow_on_order");
    assert_eq!(follow_on.len(), 7);
    assert!(
        follow_on[0]
            .as_str()
            .expect("first follow-on step must be text")
            .contains("exhaustive retained metric surface")
    );
    assert!(
        follow_on[1]
            .as_str()
            .expect("second follow-on step must be text")
            .contains("Select exact producer")
    );
    assert!(
        follow_on[6]
            .as_str()
            .expect("last follow-on step must be text")
            .contains("Only then evaluate dependency cutover")
    );
}
