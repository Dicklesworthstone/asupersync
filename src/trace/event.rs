//! Trace events and data types.
//!
//! Each event in the trace represents an observable action in the runtime.
//! Events carry sufficient information for replay and analysis.

use crate::monitor::DownReason;
use crate::record::{ObligationAbortReason, ObligationKind, ObligationState};
use crate::trace::distributed::LogicalTime;
use crate::types::{CancelReason, ObligationId, RegionId, TaskId, Time};
use core::fmt;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Current schema version for trace events.
pub const TRACE_EVENT_SCHEMA_VERSION: u32 = 1;
/// Browser trace contract schema version.
pub const BROWSER_TRACE_SCHEMA_VERSION: &str = "browser-trace-schema-v1";
const MAX_BROWSER_TRACE_ATTRIBUTE_BYTES: usize = 128;

/// Browser trace event category for deterministic diagnostics.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BrowserTraceCategory {
    /// Scheduler decisions and task lifecycle.
    Scheduler,
    /// Timer and virtual-time transitions.
    Timer,
    /// Host callback and host-signal integration events.
    HostCallback,
    /// Capability/authority mediated runtime effects.
    CapabilityInvocation,
    /// Cancellation protocol transitions.
    CancellationTransition,
}

/// One browser-trace event taxonomy entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserTraceEventSpec {
    /// Stable event-kind identifier.
    pub event_kind: String,
    /// High-level event category.
    pub category: BrowserTraceCategory,
    /// Required event data fields in lexical order.
    pub required_fields: Vec<String>,
    /// Fields that must be redacted in browser-friendly logs.
    pub redacted_fields: Vec<String>,
}

/// Browser trace schema compatibility policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserTraceCompatibility {
    /// Oldest reader version that must be supported.
    pub minimum_reader_version: String,
    /// Supported reader versions in lexical order.
    pub supported_reader_versions: Vec<String>,
    /// Legacy aliases that decode into v1 semantics.
    pub backward_decode_aliases: Vec<String>,
}

/// Browser trace schema v1 contract for deterministic diagnostics and replay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserTraceSchema {
    /// Contract version identifier.
    pub schema_version: String,
    /// Required envelope metadata fields in lexical order.
    pub required_envelope_fields: Vec<String>,
    /// Required ordering semantics in lexical order.
    pub ordering_semantics: Vec<String>,
    /// Required structured-log fields for trace diagnostics.
    pub structured_log_required_fields: Vec<String>,
    /// Validation-failure categories in lexical order.
    pub validation_failure_categories: Vec<String>,
    /// Canonical event taxonomy in lexical `event_kind` order.
    pub event_specs: Vec<BrowserTraceEventSpec>,
    /// Compatibility policy for readers/writers.
    pub compatibility: BrowserTraceCompatibility,
}

/// Browser capture source for deterministic replay reconstruction.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BrowserCaptureSource {
    /// Runtime-originated event without explicit host sample metadata.
    Runtime,
    /// Host-time sample capture.
    Time,
    /// Host callback/event-loop sample capture.
    Event,
    /// External host input capture (user/input/network-originated trigger).
    HostInput,
}

/// Deterministic capture metadata for browser trace events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserCaptureMetadata {
    /// Monotonic host turn sequence provided by the browser adapter.
    pub host_turn_seq: u64,
    /// Capture source class.
    pub source: BrowserCaptureSource,
    /// Monotonic source-local sequence number.
    pub source_seq: u64,
    /// Host time sample in nanoseconds (`performance.now()`-derived).
    pub host_time_ns: u64,
}

/// The kind of trace event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TraceEventKind {
    /// A task was spawned.
    Spawn,
    /// A task was scheduled for execution.
    Schedule,
    /// A task voluntarily yielded.
    Yield,
    /// A task was woken by a waker.
    Wake,
    /// A task was polled.
    Poll,
    /// A task completed.
    Complete,
    /// Cancellation was requested.
    CancelRequest,
    /// Cancellation was acknowledged.
    CancelAck,
    /// Worker-offload cancellation was requested across the browser boundary.
    WorkerCancelRequested,
    /// Worker-offload cancellation was acknowledged by the worker coordinator.
    WorkerCancelAcknowledged,
    /// Worker-offload drain phase started after cancellation acknowledgement.
    WorkerDrainStarted,
    /// Worker-offload drain phase completed.
    WorkerDrainCompleted,
    /// Worker-offload finalize phase completed.
    WorkerFinalizeCompleted,
    /// A region began closing.
    RegionCloseBegin,
    /// A region completed closing.
    RegionCloseComplete,
    /// A region was created.
    RegionCreated,
    /// A region received a cancellation request.
    RegionCancelled,
    /// An obligation was reserved.
    ObligationReserve,
    /// An obligation was committed.
    ObligationCommit,
    /// An obligation was aborted.
    ObligationAbort,
    /// An obligation was leaked (error).
    ObligationLeak,
    /// Time advanced.
    TimeAdvance,
    /// A timer was scheduled.
    TimerScheduled,
    /// A timer fired.
    TimerFired,
    /// A timer was cancelled.
    TimerCancelled,
    /// I/O interest was requested.
    IoRequested,
    /// I/O became ready.
    IoReady,
    /// I/O result (bytes transferred).
    IoResult,
    /// I/O error injected/observed.
    IoError,
    /// RNG was seeded.
    RngSeed,
    /// RNG value generated.
    RngValue,
    /// Replay checkpoint event.
    Checkpoint,
    /// A task held obligations but stopped being polled (futurelock).
    FuturelockDetected,
    /// Chaos injection occurred.
    ChaosInjection,
    /// User-defined trace point.
    UserTrace,
    /// A monitor was established.
    MonitorCreated,
    /// A monitor was removed.
    MonitorDropped,
    /// A Down notification was delivered.
    DownDelivered,
    /// A link was established.
    LinkCreated,
    /// A link was removed.
    LinkDropped,
    /// An exit signal was delivered to a linked task.
    ExitDelivered,
}

impl TraceEventKind {
    /// Canonical list of all trace event kinds.
    ///
    /// Keep this list in sync with the enum definition and
    /// `docs/spork_deterministic_ordering.md` taxonomy section.
    pub const ALL: [Self; 41] = [
        Self::Spawn,
        Self::Schedule,
        Self::Yield,
        Self::Wake,
        Self::Poll,
        Self::Complete,
        Self::CancelRequest,
        Self::CancelAck,
        Self::WorkerCancelRequested,
        Self::WorkerCancelAcknowledged,
        Self::WorkerDrainStarted,
        Self::WorkerDrainCompleted,
        Self::WorkerFinalizeCompleted,
        Self::RegionCloseBegin,
        Self::RegionCloseComplete,
        Self::RegionCreated,
        Self::RegionCancelled,
        Self::ObligationReserve,
        Self::ObligationCommit,
        Self::ObligationAbort,
        Self::ObligationLeak,
        Self::TimeAdvance,
        Self::TimerScheduled,
        Self::TimerFired,
        Self::TimerCancelled,
        Self::IoRequested,
        Self::IoReady,
        Self::IoResult,
        Self::IoError,
        Self::RngSeed,
        Self::RngValue,
        Self::Checkpoint,
        Self::FuturelockDetected,
        Self::ChaosInjection,
        Self::UserTrace,
        Self::MonitorCreated,
        Self::MonitorDropped,
        Self::DownDelivered,
        Self::LinkCreated,
        Self::LinkDropped,
        Self::ExitDelivered,
    ];

    /// Stable, grep-friendly taxonomy name.
    #[must_use]
    pub const fn stable_name(self) -> &'static str {
        match self {
            Self::Spawn => "spawn",
            Self::Schedule => "schedule",
            Self::Yield => "yield",
            Self::Wake => "wake",
            Self::Poll => "poll",
            Self::Complete => "complete",
            Self::CancelRequest => "cancel_request",
            Self::CancelAck => "cancel_ack",
            Self::WorkerCancelRequested => "worker_cancel_requested",
            Self::WorkerCancelAcknowledged => "worker_cancel_acknowledged",
            Self::WorkerDrainStarted => "worker_drain_started",
            Self::WorkerDrainCompleted => "worker_drain_completed",
            Self::WorkerFinalizeCompleted => "worker_finalize_completed",
            Self::RegionCloseBegin => "region_close_begin",
            Self::RegionCloseComplete => "region_close_complete",
            Self::RegionCreated => "region_created",
            Self::RegionCancelled => "region_cancelled",
            Self::ObligationReserve => "obligation_reserve",
            Self::ObligationCommit => "obligation_commit",
            Self::ObligationAbort => "obligation_abort",
            Self::ObligationLeak => "obligation_leak",
            Self::TimeAdvance => "time_advance",
            Self::TimerScheduled => "timer_scheduled",
            Self::TimerFired => "timer_fired",
            Self::TimerCancelled => "timer_cancelled",
            Self::IoRequested => "io_requested",
            Self::IoReady => "io_ready",
            Self::IoResult => "io_result",
            Self::IoError => "io_error",
            Self::RngSeed => "rng_seed",
            Self::RngValue => "rng_value",
            Self::Checkpoint => "checkpoint",
            Self::FuturelockDetected => "futurelock_detected",
            Self::ChaosInjection => "chaos_injection",
            Self::UserTrace => "user_trace",
            Self::MonitorCreated => "monitor_created",
            Self::MonitorDropped => "monitor_dropped",
            Self::DownDelivered => "down_delivered",
            Self::LinkCreated => "link_created",
            Self::LinkDropped => "link_dropped",
            Self::ExitDelivered => "exit_delivered",
        }
    }

    /// Stable required field set for taxonomy documentation.
    #[must_use]
    pub const fn required_fields(self) -> &'static str {
        match self {
            Self::Spawn
            | Self::Schedule
            | Self::Yield
            | Self::Wake
            | Self::Poll
            | Self::Complete => "task, region",
            Self::CancelRequest | Self::CancelAck => "task, region, reason",
            Self::WorkerCancelRequested
            | Self::WorkerCancelAcknowledged
            | Self::WorkerDrainStarted
            | Self::WorkerDrainCompleted
            | Self::WorkerFinalizeCompleted => {
                "decision_seq, job_id, obligation, region, replay_hash, task, worker_id"
            }
            Self::RegionCloseBegin | Self::RegionCloseComplete | Self::RegionCreated => {
                "region, parent"
            }
            Self::RegionCancelled => "region, reason",
            Self::ObligationReserve => "obligation, task, region, kind, state",
            Self::ObligationCommit | Self::ObligationLeak => {
                "obligation, task, region, kind, state, duration_ns"
            }
            Self::ObligationAbort => {
                "obligation, task, region, kind, state, duration_ns, abort_reason"
            }
            Self::TimeAdvance => "old, new",
            Self::TimerScheduled => "timer_id, deadline",
            Self::TimerFired | Self::TimerCancelled => "timer_id",
            Self::IoRequested => "token, interest",
            Self::IoReady => "token, readiness",
            Self::IoResult => "token, bytes",
            Self::IoError => "token, kind",
            Self::RngSeed => "seed",
            Self::RngValue => "value",
            Self::Checkpoint => "sequence, active_tasks, active_regions",
            Self::FuturelockDetected => "task, region, idle_steps, held",
            Self::ChaosInjection => "kind, task, detail",
            Self::UserTrace => "message",
            Self::MonitorCreated | Self::MonitorDropped => {
                "monitor_ref, watcher, watcher_region, monitored"
            }
            Self::DownDelivered => "monitor_ref, watcher, monitored, completion_vt, reason",
            Self::LinkCreated | Self::LinkDropped => "link_ref, task_a, region_a, task_b, region_b",
            Self::ExitDelivered => "link_ref, from, to, failure_vt, reason",
        }
    }
}

/// Returns the browser trace category for one trace event kind.
#[must_use]
pub const fn browser_trace_category_for_kind(kind: TraceEventKind) -> BrowserTraceCategory {
    match kind {
        TraceEventKind::Spawn
        | TraceEventKind::Schedule
        | TraceEventKind::Yield
        | TraceEventKind::Wake
        | TraceEventKind::Poll
        | TraceEventKind::Complete
        | TraceEventKind::Checkpoint
        | TraceEventKind::FuturelockDetected => BrowserTraceCategory::Scheduler,
        TraceEventKind::TimeAdvance
        | TraceEventKind::TimerScheduled
        | TraceEventKind::TimerFired
        | TraceEventKind::TimerCancelled => BrowserTraceCategory::Timer,
        TraceEventKind::IoRequested
        | TraceEventKind::IoReady
        | TraceEventKind::IoResult
        | TraceEventKind::IoError
        | TraceEventKind::RngSeed
        | TraceEventKind::RngValue
        | TraceEventKind::UserTrace
        | TraceEventKind::ChaosInjection => BrowserTraceCategory::HostCallback,
        TraceEventKind::ObligationReserve
        | TraceEventKind::ObligationCommit
        | TraceEventKind::ObligationAbort
        | TraceEventKind::ObligationLeak
        | TraceEventKind::RegionCreated
        | TraceEventKind::MonitorCreated
        | TraceEventKind::MonitorDropped
        | TraceEventKind::DownDelivered
        | TraceEventKind::LinkCreated
        | TraceEventKind::LinkDropped
        | TraceEventKind::ExitDelivered => BrowserTraceCategory::CapabilityInvocation,
        TraceEventKind::CancelRequest
        | TraceEventKind::CancelAck
        | TraceEventKind::WorkerCancelRequested
        | TraceEventKind::WorkerCancelAcknowledged
        | TraceEventKind::WorkerDrainStarted
        | TraceEventKind::WorkerDrainCompleted
        | TraceEventKind::WorkerFinalizeCompleted
        | TraceEventKind::RegionCloseBegin
        | TraceEventKind::RegionCloseComplete
        | TraceEventKind::RegionCancelled => BrowserTraceCategory::CancellationTransition,
    }
}

/// Returns stable snake_case category name for structured logs.
#[must_use]
pub const fn browser_trace_category_name(category: BrowserTraceCategory) -> &'static str {
    match category {
        BrowserTraceCategory::Scheduler => "scheduler",
        BrowserTraceCategory::Timer => "timer",
        BrowserTraceCategory::HostCallback => "host_callback",
        BrowserTraceCategory::CapabilityInvocation => "capability_invocation",
        BrowserTraceCategory::CancellationTransition => "cancellation_transition",
    }
}

fn redacted_fields_for_kind(kind: TraceEventKind) -> Vec<String> {
    match kind {
        TraceEventKind::UserTrace => vec!["message".to_string()],
        TraceEventKind::ChaosInjection => vec!["detail".to_string()],
        _ => Vec::new(),
    }
}

fn split_required_fields_csv(csv: &str) -> Vec<String> {
    let mut fields = csv
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    fields.sort();
    fields.dedup();
    fields
}

fn trace_event_kind_from_stable_name(name: &str) -> Option<TraceEventKind> {
    TraceEventKind::ALL
        .iter()
        .copied()
        .find(|kind| kind.stable_name() == name)
}

fn validate_lexical_string_set(values: &[String], field: &str) -> Result<(), String> {
    if values.is_empty() {
        return Err(format!("{field} must be non-empty"));
    }
    for value in values {
        if value.trim().is_empty() {
            return Err(format!("{field} must not contain empty values"));
        }
    }
    for window in values.windows(2) {
        if window[0] >= window[1] {
            return Err(format!("{field} must be lexically sorted and unique"));
        }
    }
    Ok(())
}

/// Returns canonical browser-trace schema v1 contract.
#[must_use]
pub fn browser_trace_schema_v1() -> BrowserTraceSchema {
    let mut event_specs = TraceEventKind::ALL
        .iter()
        .map(|kind| {
            let mut redacted_fields = redacted_fields_for_kind(*kind);
            redacted_fields.sort();
            redacted_fields.dedup();
            BrowserTraceEventSpec {
                event_kind: kind.stable_name().to_string(),
                category: browser_trace_category_for_kind(*kind),
                required_fields: split_required_fields_csv(kind.required_fields()),
                redacted_fields,
            }
        })
        .collect::<Vec<_>>();
    event_specs.sort_by(|left, right| left.event_kind.cmp(&right.event_kind));

    BrowserTraceSchema {
        schema_version: BROWSER_TRACE_SCHEMA_VERSION.to_string(),
        required_envelope_fields: vec![
            "event_kind".to_string(),
            "schema_version".to_string(),
            "seq".to_string(),
            "time_ns".to_string(),
            "trace_id".to_string(),
        ],
        ordering_semantics: vec![
            "events must be strictly ordered by seq ascending".to_string(),
            "logical_time must be monotonic for comparable causal domains".to_string(),
            "trace streams must be deterministic for identical seed/config/replay inputs"
                .to_string(),
        ],
        structured_log_required_fields: vec![
            "capture_host_time_ns".to_string(),
            "capture_host_turn_seq".to_string(),
            "capture_replay_key".to_string(),
            "capture_source".to_string(),
            "capture_source_seq".to_string(),
            "event_kind".to_string(),
            "schema_version".to_string(),
            "seq".to_string(),
            "sequence_group".to_string(),
            "time_ns".to_string(),
            "trace_id".to_string(),
            "validation_failure_category".to_string(),
            "validation_status".to_string(),
        ],
        validation_failure_categories: vec![
            "invalid_event_payload".to_string(),
            "missing_required_field".to_string(),
            "schema_version_mismatch".to_string(),
            "sequence_regression".to_string(),
        ],
        event_specs,
        compatibility: BrowserTraceCompatibility {
            minimum_reader_version: "browser-trace-schema-v0".to_string(),
            supported_reader_versions: vec![
                "browser-trace-schema-v0".to_string(),
                BROWSER_TRACE_SCHEMA_VERSION.to_string(),
            ],
            backward_decode_aliases: vec!["browser-trace-schema-v0".to_string()],
        },
    }
}

/// Validates browser trace schema invariants.
///
/// # Errors
///
/// Returns `Err` when deterministic ordering, schema, or compatibility
/// invariants are violated.
#[allow(clippy::too_many_lines)]
pub fn validate_browser_trace_schema(schema: &BrowserTraceSchema) -> Result<(), String> {
    if schema.schema_version != BROWSER_TRACE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported browser trace schema version {}",
            schema.schema_version
        ));
    }

    validate_lexical_string_set(&schema.required_envelope_fields, "required_envelope_fields")?;
    validate_lexical_string_set(&schema.ordering_semantics, "ordering_semantics")?;
    validate_lexical_string_set(
        &schema.structured_log_required_fields,
        "structured_log_required_fields",
    )?;
    validate_lexical_string_set(
        &schema.validation_failure_categories,
        "validation_failure_categories",
    )?;

    for required in [
        "capture_host_time_ns",
        "capture_host_turn_seq",
        "capture_replay_key",
        "capture_source",
        "capture_source_seq",
        "trace_id",
        "time_ns",
        "seq",
        "sequence_group",
        "event_kind",
        "schema_version",
        "validation_failure_category",
        "validation_status",
    ] {
        if !schema
            .structured_log_required_fields
            .iter()
            .any(|field| field == required)
        {
            return Err(format!("structured_log_required_fields missing {required}"));
        }
    }

    if schema.event_specs.is_empty() {
        return Err("event_specs must be non-empty".to_string());
    }
    let event_kinds = schema
        .event_specs
        .iter()
        .map(|entry| entry.event_kind.clone())
        .collect::<Vec<_>>();
    validate_lexical_string_set(&event_kinds, "event_specs.event_kind")?;

    let expected = TraceEventKind::ALL
        .iter()
        .map(|kind| kind.stable_name().to_string())
        .collect::<BTreeSet<_>>();
    let observed = event_kinds.into_iter().collect::<BTreeSet<_>>();
    if expected != observed {
        return Err("event_specs must include exactly all TraceEventKind stable names".to_string());
    }

    for entry in &schema.event_specs {
        validate_lexical_string_set(
            &entry.required_fields,
            &format!("event_specs[{}].required_fields", entry.event_kind),
        )?;
        if !entry.redacted_fields.is_empty() {
            validate_lexical_string_set(
                &entry.redacted_fields,
                &format!("event_specs[{}].redacted_fields", entry.event_kind),
            )?;
            for field in &entry.redacted_fields {
                if !entry
                    .required_fields
                    .iter()
                    .any(|required| required == field)
                {
                    return Err(format!(
                        "event_specs[{}].redacted_fields contains unknown field {}",
                        entry.event_kind, field
                    ));
                }
            }
        }
    }

    if schema
        .compatibility
        .minimum_reader_version
        .trim()
        .is_empty()
    {
        return Err("compatibility.minimum_reader_version must be non-empty".to_string());
    }
    validate_lexical_string_set(
        &schema.compatibility.supported_reader_versions,
        "compatibility.supported_reader_versions",
    )?;
    if !schema
        .compatibility
        .supported_reader_versions
        .iter()
        .any(|version| version == &schema.compatibility.minimum_reader_version)
    {
        return Err("minimum_reader_version missing from supported_reader_versions".to_string());
    }
    if !schema
        .compatibility
        .supported_reader_versions
        .iter()
        .any(|version| version == BROWSER_TRACE_SCHEMA_VERSION)
    {
        return Err("supported_reader_versions must include browser-trace-schema-v1".to_string());
    }
    validate_lexical_string_set(
        &schema.compatibility.backward_decode_aliases,
        "compatibility.backward_decode_aliases",
    )?;

    Ok(())
}

#[derive(Debug, Deserialize)]
struct BrowserTraceSchemaLegacyV0 {
    schema_version: String,
    required_envelope_fields: Vec<String>,
    ordering_semantics: Vec<String>,
    event_specs: Vec<BrowserTraceEventSpecLegacyV0>,
}

#[derive(Debug, Deserialize)]
struct BrowserTraceEventSpecLegacyV0 {
    event_kind: String,
    category: Option<BrowserTraceCategory>,
    required_fields: Option<Vec<String>>,
    redacted_fields: Option<Vec<String>>,
}

fn upgrade_legacy_event_specs(
    legacy_specs: Vec<BrowserTraceEventSpecLegacyV0>,
) -> Result<Vec<BrowserTraceEventSpec>, String> {
    let mut event_specs = Vec::with_capacity(legacy_specs.len());
    for legacy in legacy_specs {
        let kind = trace_event_kind_from_stable_name(legacy.event_kind.as_str())
            .ok_or_else(|| format!("unknown legacy event kind {}", legacy.event_kind))?;

        let mut required_fields = legacy
            .required_fields
            .unwrap_or_else(|| split_required_fields_csv(kind.required_fields()));
        required_fields.sort();
        required_fields.dedup();

        let mut redacted_fields = legacy
            .redacted_fields
            .unwrap_or_else(|| redacted_fields_for_kind(kind));
        redacted_fields.sort();
        redacted_fields.dedup();

        event_specs.push(BrowserTraceEventSpec {
            event_kind: kind.stable_name().to_string(),
            category: legacy
                .category
                .unwrap_or_else(|| browser_trace_category_for_kind(kind)),
            required_fields,
            redacted_fields,
        });
    }
    event_specs.sort_by(|left, right| left.event_kind.cmp(&right.event_kind));
    Ok(event_specs)
}

/// Decodes browser trace schema payload with backwards-compatible v0 support.
///
/// # Errors
///
/// Returns `Err` when JSON decoding fails or schema version is unsupported.
pub fn decode_browser_trace_schema(payload: &str) -> Result<BrowserTraceSchema, String> {
    let value: serde_json::Value =
        serde_json::from_str(payload).map_err(|err| format!("invalid schema JSON: {err}"))?;
    let version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "schema_version must be a string".to_string())?;

    let schema = match version {
        BROWSER_TRACE_SCHEMA_VERSION => serde_json::from_value::<BrowserTraceSchema>(value)
            .map_err(|err| format!("invalid browser-trace-schema-v1 payload: {err}"))?,
        "browser-trace-schema-v0" => {
            let legacy = serde_json::from_value::<BrowserTraceSchemaLegacyV0>(value)
                .map_err(|err| format!("invalid browser-trace-schema-v0 payload: {err}"))?;
            if legacy.schema_version != "browser-trace-schema-v0" {
                return Err(format!(
                    "invalid legacy schema version {}",
                    legacy.schema_version
                ));
            }
            let mut schema = browser_trace_schema_v1();
            schema.required_envelope_fields = legacy.required_envelope_fields;
            schema.ordering_semantics = legacy.ordering_semantics;
            schema.event_specs = upgrade_legacy_event_specs(legacy.event_specs)?;
            schema.compatibility.backward_decode_aliases =
                vec!["browser-trace-schema-v0".to_string()];
            schema.compatibility.minimum_reader_version = "browser-trace-schema-v0".to_string();
            schema
        }
        other => {
            return Err(format!("unsupported browser trace schema version {other}"));
        }
    };

    validate_browser_trace_schema(&schema)?;
    Ok(schema)
}

/// Returns redacted trace event suitable for browser diagnostics.
#[must_use]
pub fn redact_browser_trace_event(event: &TraceEvent) -> TraceEvent {
    let mut redacted = event.clone();
    match (&event.kind, &event.data) {
        (TraceEventKind::UserTrace, TraceData::Message(_)) => {
            redacted.data = TraceData::Message("<redacted>".to_string());
        }
        (
            TraceEventKind::ChaosInjection,
            TraceData::Chaos {
                kind,
                task,
                detail: _,
            },
        ) => {
            redacted.data = TraceData::Chaos {
                kind: kind.clone(),
                task: *task,
                detail: "<redacted>".to_string(),
            };
        }
        _ => {}
    }
    redacted
}

fn default_browser_capture_metadata(event: &TraceEvent) -> BrowserCaptureMetadata {
    BrowserCaptureMetadata {
        host_turn_seq: event.seq,
        source: BrowserCaptureSource::Runtime,
        source_seq: event.seq,
        host_time_ns: event.time.as_nanos(),
    }
}

fn stable_browser_trace_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

fn cap_browser_trace_attribute(value: &str) -> String {
    if value.len() <= MAX_BROWSER_TRACE_ATTRIBUTE_BYTES {
        return value.to_string();
    }

    let suffix = format!("#{:016x}", stable_browser_trace_hash(value.as_bytes()));
    let mut cut = MAX_BROWSER_TRACE_ATTRIBUTE_BYTES.saturating_sub(suffix.len());
    while cut > 0 && !value.is_char_boundary(cut) {
        cut -= 1;
    }

    let mut capped = value[..cut].to_string();
    capped.push_str(&suffix);
    capped
}

fn obligation_state_name(state: ObligationState) -> &'static str {
    match state {
        ObligationState::Reserved => "reserved",
        ObligationState::Committed => "committed",
        ObligationState::Aborted => "aborted",
        ObligationState::Leaked => "leaked",
    }
}

fn optional_time_field(value: Option<Time>) -> String {
    value.map_or_else(|| "none".to_string(), |time| time.as_nanos().to_string())
}

fn optional_display_field<T: fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "none".to_string(), |value| value.to_string())
}

fn futurelock_held_field(held: &[(ObligationId, ObligationKind)]) -> String {
    let held = held
        .iter()
        .map(|(obligation, kind)| format!("{obligation}:{kind}"))
        .collect::<Vec<_>>();
    serde_json::to_string(&held).expect("futurelock held obligations serialize")
}

fn insert_browser_trace_payload_fields(fields: &mut BTreeMap<String, String>, event: &TraceEvent) {
    match &event.data {
        TraceData::None => {}
        TraceData::Task { task, region } => {
            fields.insert("task".to_string(), task.to_string());
            fields.insert("region".to_string(), region.to_string());
        }
        TraceData::Region { region, parent } => {
            fields.insert("region".to_string(), region.to_string());
            fields.insert("parent".to_string(), optional_display_field(*parent));
        }
        TraceData::Obligation {
            obligation,
            task,
            region,
            kind,
            state,
            duration_ns,
            abort_reason,
        } => {
            fields.insert("obligation".to_string(), obligation.to_string());
            fields.insert("task".to_string(), task.to_string());
            fields.insert("region".to_string(), region.to_string());
            fields.insert("kind".to_string(), kind.to_string());
            fields.insert(
                "state".to_string(),
                obligation_state_name(*state).to_string(),
            );

            if matches!(
                event.kind,
                TraceEventKind::ObligationCommit
                    | TraceEventKind::ObligationAbort
                    | TraceEventKind::ObligationLeak
            ) {
                fields.insert(
                    "duration_ns".to_string(),
                    duration_ns.map_or_else(|| "none".to_string(), |value| value.to_string()),
                );
            }

            if matches!(event.kind, TraceEventKind::ObligationAbort) {
                fields.insert(
                    "abort_reason".to_string(),
                    abort_reason.map_or_else(|| "none".to_string(), |reason| reason.to_string()),
                );
            }
        }
        TraceData::Cancel {
            task,
            region,
            reason,
        } => {
            fields.insert("task".to_string(), task.to_string());
            fields.insert("region".to_string(), region.to_string());
            fields.insert("reason".to_string(), reason.to_string());
        }
        TraceData::Worker {
            worker_id,
            job_id,
            decision_seq,
            replay_hash,
            task,
            region,
            obligation,
        } => {
            fields.insert("decision_seq".to_string(), decision_seq.to_string());
            fields.insert("job_id".to_string(), job_id.to_string());
            fields.insert("obligation".to_string(), obligation.to_string());
            fields.insert("region".to_string(), region.to_string());
            fields.insert("replay_hash".to_string(), replay_hash.to_string());
            fields.insert("task".to_string(), task.to_string());
            fields.insert(
                "worker_id".to_string(),
                cap_browser_trace_attribute(worker_id),
            );
        }
        TraceData::RegionCancel { region, reason } => {
            fields.insert("region".to_string(), region.to_string());
            fields.insert("reason".to_string(), reason.to_string());
        }
        TraceData::Time { old, new } => {
            fields.insert("old".to_string(), old.as_nanos().to_string());
            fields.insert("new".to_string(), new.as_nanos().to_string());
        }
        TraceData::Timer { timer_id, deadline } => {
            fields.insert("timer_id".to_string(), timer_id.to_string());
            if matches!(event.kind, TraceEventKind::TimerScheduled) || deadline.is_some() {
                fields.insert("deadline".to_string(), optional_time_field(*deadline));
            }
        }
        TraceData::IoRequested { token, interest } => {
            fields.insert("token".to_string(), token.to_string());
            fields.insert("interest".to_string(), interest.to_string());
        }
        TraceData::IoReady { token, readiness } => {
            fields.insert("token".to_string(), token.to_string());
            fields.insert("readiness".to_string(), readiness.to_string());
        }
        TraceData::IoResult { token, bytes } => {
            fields.insert("token".to_string(), token.to_string());
            fields.insert("bytes".to_string(), bytes.to_string());
        }
        TraceData::IoError { token, kind } => {
            fields.insert("token".to_string(), token.to_string());
            fields.insert("kind".to_string(), kind.to_string());
        }
        TraceData::RngSeed { seed } => {
            fields.insert("seed".to_string(), seed.to_string());
        }
        TraceData::RngValue { value } => {
            fields.insert("value".to_string(), value.to_string());
        }
        TraceData::Checkpoint {
            sequence,
            active_tasks,
            active_regions,
        } => {
            fields.insert("sequence".to_string(), sequence.to_string());
            fields.insert("active_tasks".to_string(), active_tasks.to_string());
            fields.insert("active_regions".to_string(), active_regions.to_string());
        }
        TraceData::Futurelock {
            task,
            region,
            idle_steps,
            held,
        } => {
            fields.insert("task".to_string(), task.to_string());
            fields.insert("region".to_string(), region.to_string());
            fields.insert("idle_steps".to_string(), idle_steps.to_string());
            fields.insert("held".to_string(), futurelock_held_field(held));
        }
        TraceData::Monitor {
            monitor_ref,
            watcher,
            watcher_region,
            monitored,
        } => {
            fields.insert("monitor_ref".to_string(), monitor_ref.to_string());
            fields.insert("watcher".to_string(), watcher.to_string());
            fields.insert("watcher_region".to_string(), watcher_region.to_string());
            fields.insert("monitored".to_string(), monitored.to_string());
        }
        TraceData::Down {
            monitor_ref,
            watcher,
            monitored,
            completion_vt,
            reason,
        } => {
            fields.insert("monitor_ref".to_string(), monitor_ref.to_string());
            fields.insert("watcher".to_string(), watcher.to_string());
            fields.insert("monitored".to_string(), monitored.to_string());
            fields.insert(
                "completion_vt".to_string(),
                completion_vt.as_nanos().to_string(),
            );
            fields.insert("reason".to_string(), reason.to_string());
        }
        TraceData::Link {
            link_ref,
            task_a,
            region_a,
            task_b,
            region_b,
        } => {
            fields.insert("link_ref".to_string(), link_ref.to_string());
            fields.insert("task_a".to_string(), task_a.to_string());
            fields.insert("region_a".to_string(), region_a.to_string());
            fields.insert("task_b".to_string(), task_b.to_string());
            fields.insert("region_b".to_string(), region_b.to_string());
        }
        TraceData::Exit {
            link_ref,
            from,
            to,
            failure_vt,
            reason,
        } => {
            fields.insert("link_ref".to_string(), link_ref.to_string());
            fields.insert("from".to_string(), from.to_string());
            fields.insert("to".to_string(), to.to_string());
            fields.insert("failure_vt".to_string(), failure_vt.as_nanos().to_string());
            fields.insert("reason".to_string(), reason.to_string());
        }
        TraceData::Message(message) => {
            fields.insert("message".to_string(), message.clone());
        }
        TraceData::Chaos { kind, task, detail } => {
            fields.insert("kind".to_string(), kind.clone());
            fields.insert("task".to_string(), optional_display_field(*task));
            fields.insert("detail".to_string(), detail.clone());
        }
    }
}

fn browser_trace_sequence_group(event: &TraceEvent) -> String {
    // Sequence groups must identify the causal or relationship domain for
    // ordering checks; category labels are too coarse and collapse independent
    // streams into the same group.
    let raw = match &event.data {
        TraceData::Task { task, .. }
        | TraceData::Cancel { task, .. }
        | TraceData::Futurelock { task, .. } => format!("task:{task}"),
        TraceData::Region { region, .. } | TraceData::RegionCancel { region, .. } => {
            format!("region:{region}")
        }
        TraceData::Obligation { obligation, .. } => format!("obligation:{obligation}"),
        TraceData::Worker {
            worker_id, job_id, ..
        } => format!("worker_job:{job_id}:{worker_id}"),
        TraceData::Time { .. } => "time".to_string(),
        TraceData::Timer { timer_id, .. } => format!("timer:{timer_id}"),
        TraceData::IoRequested { token, .. }
        | TraceData::IoReady { token, .. }
        | TraceData::IoResult { token, .. }
        | TraceData::IoError { token, .. } => format!("io:{token}"),
        TraceData::RngSeed { .. } | TraceData::RngValue { .. } => "rng".to_string(),
        TraceData::Checkpoint { sequence, .. } => format!("checkpoint:{sequence}"),
        TraceData::Monitor { monitor_ref, .. } | TraceData::Down { monitor_ref, .. } => {
            format!("monitor:{monitor_ref}")
        }
        TraceData::Link { link_ref, .. } | TraceData::Exit { link_ref, .. } => {
            format!("link:{link_ref}")
        }
        TraceData::Message(_) => "user_trace".to_string(),
        TraceData::Chaos {
            task: Some(task), ..
        } => format!("task:{task}"),
        TraceData::Chaos { task: None, .. } => "chaos".to_string(),
        TraceData::None => format!("kind:{}", event.kind.stable_name()),
    };
    cap_browser_trace_attribute(&raw)
}

fn browser_capture_replay_key(metadata: &BrowserCaptureMetadata) -> String {
    format!(
        "{}:{}:{}:{}",
        match metadata.source {
            BrowserCaptureSource::Runtime => "runtime",
            BrowserCaptureSource::Time => "time",
            BrowserCaptureSource::Event => "event",
            BrowserCaptureSource::HostInput => "host_input",
        },
        metadata.host_turn_seq,
        metadata.source_seq,
        metadata.host_time_ns
    )
}

/// Returns deterministic structured-log fields for one browser trace event.
///
/// When `capture_metadata` is not provided, deterministic fallback values are
/// reconstructed from event sequence and event time.
#[must_use]
pub fn browser_trace_log_fields_with_capture(
    event: &TraceEvent,
    trace_id: &str,
    validation_failure_category: Option<&str>,
    capture_metadata: Option<&BrowserCaptureMetadata>,
) -> BTreeMap<String, String> {
    let capture = capture_metadata
        .cloned()
        .unwrap_or_else(|| default_browser_capture_metadata(event));
    let mut fields = BTreeMap::new();
    fields.insert(
        "capture_host_time_ns".to_string(),
        capture.host_time_ns.to_string(),
    );
    fields.insert(
        "capture_host_turn_seq".to_string(),
        capture.host_turn_seq.to_string(),
    );
    fields.insert(
        "capture_replay_key".to_string(),
        browser_capture_replay_key(&capture),
    );
    fields.insert(
        "capture_source".to_string(),
        match capture.source {
            BrowserCaptureSource::Runtime => "runtime".to_string(),
            BrowserCaptureSource::Time => "time".to_string(),
            BrowserCaptureSource::Event => "event".to_string(),
            BrowserCaptureSource::HostInput => "host_input".to_string(),
        },
    );
    fields.insert(
        "capture_source_seq".to_string(),
        capture.source_seq.to_string(),
    );
    fields.insert(
        "event_kind".to_string(),
        event.kind.stable_name().to_string(),
    );
    fields.insert(
        "schema_version".to_string(),
        BROWSER_TRACE_SCHEMA_VERSION.to_string(),
    );
    fields.insert("seq".to_string(), event.seq.to_string());
    fields.insert("time_ns".to_string(), event.time.as_nanos().to_string());
    fields.insert("trace_id".to_string(), trace_id.to_string());
    fields.insert(
        "sequence_group".to_string(),
        browser_trace_sequence_group(event),
    );
    let failure_category = validation_failure_category
        .filter(|category| !category.trim().is_empty())
        .unwrap_or("none");
    fields.insert(
        "validation_failure_category".to_string(),
        failure_category.to_string(),
    );
    fields.insert(
        "validation_status".to_string(),
        if failure_category == "none" {
            "valid".to_string()
        } else {
            "invalid".to_string()
        },
    );
    insert_browser_trace_payload_fields(&mut fields, event);
    fields
}

/// Returns deterministic structured-log fields for one browser trace event.
#[must_use]
pub fn browser_trace_log_fields(
    event: &TraceEvent,
    trace_id: &str,
    validation_failure_category: Option<&str>,
) -> BTreeMap<String, String> {
    browser_trace_log_fields_with_capture(event, trace_id, validation_failure_category, None)
}

impl fmt::Display for TraceEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.stable_name())
    }
}

/// Additional data carried by a trace event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceData {
    /// No additional data.
    None,
    /// Task-related data.
    Task {
        /// The task involved.
        task: TaskId,
        /// The region the task belongs to.
        region: RegionId,
    },
    /// Region-related data.
    Region {
        /// The region involved.
        region: RegionId,
        /// The parent region, if any.
        parent: Option<RegionId>,
    },
    /// Obligation-related data.
    Obligation {
        /// The obligation involved.
        obligation: ObligationId,
        /// The task holding the obligation.
        task: TaskId,
        /// The region that owns the obligation.
        region: RegionId,
        /// The kind of obligation.
        kind: ObligationKind,
        /// The obligation state at this event.
        state: ObligationState,
        /// Duration held in nanoseconds, if resolved.
        duration_ns: Option<u64>,
        /// Abort reason, if aborted.
        abort_reason: Option<ObligationAbortReason>,
    },
    /// Cancellation data.
    Cancel {
        /// The task involved.
        task: TaskId,
        /// The region involved.
        region: RegionId,
        /// The reason for cancellation.
        reason: CancelReason,
    },
    /// Worker-offload lifecycle data across the browser boundary.
    Worker {
        /// Worker runtime instance identifier.
        worker_id: String,
        /// Offloaded job identifier within the worker coordinator.
        job_id: u64,
        /// Deterministic decision sequence carried by the worker envelope.
        decision_seq: u64,
        /// Stable replay digest carried by the worker envelope.
        replay_hash: u64,
        /// The originating task that owns the offloaded work.
        task: TaskId,
        /// The originating region that owns the task.
        region: RegionId,
        /// The originating obligation that must be drained/finalized.
        obligation: ObligationId,
    },
    /// Region cancellation data.
    RegionCancel {
        /// The region involved.
        region: RegionId,
        /// The reason for cancellation.
        reason: CancelReason,
    },
    /// Time data.
    Time {
        /// The previous time.
        old: Time,
        /// The new time.
        new: Time,
    },
    /// Timer data.
    Timer {
        /// Timer identifier.
        timer_id: u64,
        /// Deadline, if applicable.
        deadline: Option<Time>,
    },
    /// I/O interest request data.
    IoRequested {
        /// I/O token.
        token: u64,
        /// Interest bitflags (readable=1, writable=2, error=4, hangup=8).
        interest: u8,
    },
    /// I/O readiness data.
    IoReady {
        /// I/O token.
        token: u64,
        /// Readiness bitflags (readable=1, writable=2, error=4, hangup=8).
        readiness: u8,
    },
    /// I/O result data.
    IoResult {
        /// I/O token.
        token: u64,
        /// Bytes transferred (negative for errors).
        bytes: i64,
    },
    /// I/O error data.
    IoError {
        /// I/O token.
        token: u64,
        /// Error kind as u8 (maps to io::ErrorKind).
        kind: u8,
    },
    /// RNG seed data.
    RngSeed {
        /// Seed value.
        seed: u64,
    },
    /// RNG value data.
    RngValue {
        /// Generated value.
        value: u64,
    },
    /// Checkpoint data.
    Checkpoint {
        /// Monotonic sequence number.
        sequence: u64,
        /// Active task count.
        active_tasks: u32,
        /// Active region count.
        active_regions: u32,
    },
    /// Futurelock detection data.
    Futurelock {
        /// The task that futurelocked.
        task: TaskId,
        /// The owning region of the task.
        region: RegionId,
        /// How many lab steps since the task was last polled.
        idle_steps: u64,
        /// Obligations held by the task at detection time.
        held: Vec<(ObligationId, ObligationKind)>,
    },
    /// Monitor lifecycle event.
    Monitor {
        /// Monitor reference id.
        monitor_ref: u64,
        /// The task watching for termination.
        watcher: TaskId,
        /// The region owning the watcher (for region-close cleanup).
        watcher_region: RegionId,
        /// The task being monitored.
        monitored: TaskId,
    },
    /// Down notification delivery.
    ///
    /// Includes the deterministic ordering key (`completion_vt`, `monitored`).
    Down {
        /// Monitor reference id from establishment.
        monitor_ref: u64,
        /// The task receiving the notification.
        watcher: TaskId,
        /// The task that terminated.
        monitored: TaskId,
        /// Virtual time of monitored task completion.
        completion_vt: Time,
        /// Why it terminated.
        reason: DownReason,
    },
    /// Link lifecycle event.
    Link {
        /// Link reference id.
        link_ref: u64,
        /// One side of the link.
        task_a: TaskId,
        /// Region owning task_a (for region-close cleanup).
        region_a: RegionId,
        /// The other side of the link.
        task_b: TaskId,
        /// Region owning task_b (for region-close cleanup).
        region_b: RegionId,
    },
    /// Exit signal delivery to a linked task.
    ///
    /// Includes the deterministic ordering key (`failure_vt`, `from`).
    Exit {
        /// Link reference id.
        link_ref: u64,
        /// The task that terminated (source of the exit).
        from: TaskId,
        /// The linked task receiving the exit signal.
        to: TaskId,
        /// Virtual time of failure used for deterministic ordering.
        failure_vt: Time,
        /// Why it terminated.
        reason: DownReason,
    },
    /// User message.
    Message(String),
    /// Chaos injection data.
    Chaos {
        /// Kind of chaos injected (e.g., "cancel", "delay", "budget_exhaust", "wakeup_storm").
        kind: String,
        /// The task affected, if any.
        task: Option<TaskId>,
        /// Additional detail.
        detail: String,
    },
}

/// A trace event in the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEvent {
    /// Event schema version.
    pub version: u32,
    /// Sequence number (monotonically increasing).
    pub seq: u64,
    /// Timestamp when the event occurred.
    pub time: Time,
    /// Logical clock timestamp for causal ordering.
    ///
    /// When set, enables causal consistency verification across distributed
    /// traces. The logical time is ticked when the event is recorded and
    /// can be used to establish happens-before relationships.
    pub logical_time: Option<LogicalTime>,
    /// The kind of event.
    pub kind: TraceEventKind,
    /// Additional data.
    pub data: TraceData,
}

impl TraceEvent {
    /// Creates a new trace event.
    #[must_use]
    #[inline]
    pub fn new(seq: u64, time: Time, kind: TraceEventKind, data: TraceData) -> Self {
        Self {
            version: TRACE_EVENT_SCHEMA_VERSION,
            seq,
            time,
            logical_time: None,
            kind,
            data,
        }
    }

    /// Attaches a logical clock timestamp to this event for causal ordering.
    #[inline]
    #[must_use]
    pub fn with_logical_time(mut self, logical_time: LogicalTime) -> Self {
        self.logical_time = Some(logical_time);
        self
    }

    /// Creates a spawn event.
    #[must_use]
    pub fn spawn(seq: u64, time: Time, task: TaskId, region: RegionId) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::Spawn,
            TraceData::Task { task, region },
        )
    }

    /// Creates a schedule event.
    #[must_use]
    pub fn schedule(seq: u64, time: Time, task: TaskId, region: RegionId) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::Schedule,
            TraceData::Task { task, region },
        )
    }

    /// Creates a yield event.
    #[must_use]
    pub fn yield_task(seq: u64, time: Time, task: TaskId, region: RegionId) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::Yield,
            TraceData::Task { task, region },
        )
    }

    /// Creates a wake event.
    #[must_use]
    pub fn wake(seq: u64, time: Time, task: TaskId, region: RegionId) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::Wake,
            TraceData::Task { task, region },
        )
    }

    /// Creates a poll event.
    #[must_use]
    pub fn poll(seq: u64, time: Time, task: TaskId, region: RegionId) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::Poll,
            TraceData::Task { task, region },
        )
    }

    /// Creates a complete event.
    #[must_use]
    pub fn complete(seq: u64, time: Time, task: TaskId, region: RegionId) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::Complete,
            TraceData::Task { task, region },
        )
    }

    /// Creates a cancel request event.
    #[must_use]
    pub fn cancel_request(
        seq: u64,
        time: Time,
        task: TaskId,
        region: RegionId,
        reason: CancelReason,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::CancelRequest,
            TraceData::Cancel {
                task,
                region,
                reason,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn worker_lifecycle(
        seq: u64,
        time: Time,
        kind: TraceEventKind,
        worker_id: impl Into<String>,
        job_id: u64,
        decision_seq: u64,
        replay_hash: u64,
        task: TaskId,
        region: RegionId,
        obligation: ObligationId,
    ) -> Self {
        Self::new(
            seq,
            time,
            kind,
            TraceData::Worker {
                worker_id: worker_id.into(),
                job_id,
                decision_seq,
                replay_hash,
                task,
                region,
                obligation,
            },
        )
    }

    /// Creates a worker-offload cancel-requested event.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn worker_cancel_requested(
        seq: u64,
        time: Time,
        worker_id: impl Into<String>,
        job_id: u64,
        decision_seq: u64,
        replay_hash: u64,
        task: TaskId,
        region: RegionId,
        obligation: ObligationId,
    ) -> Self {
        Self::worker_lifecycle(
            seq,
            time,
            TraceEventKind::WorkerCancelRequested,
            worker_id,
            job_id,
            decision_seq,
            replay_hash,
            task,
            region,
            obligation,
        )
    }

    /// Creates a worker-offload cancel-acknowledged event.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn worker_cancel_acknowledged(
        seq: u64,
        time: Time,
        worker_id: impl Into<String>,
        job_id: u64,
        decision_seq: u64,
        replay_hash: u64,
        task: TaskId,
        region: RegionId,
        obligation: ObligationId,
    ) -> Self {
        Self::worker_lifecycle(
            seq,
            time,
            TraceEventKind::WorkerCancelAcknowledged,
            worker_id,
            job_id,
            decision_seq,
            replay_hash,
            task,
            region,
            obligation,
        )
    }

    /// Creates a worker-offload drain-started event.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn worker_drain_started(
        seq: u64,
        time: Time,
        worker_id: impl Into<String>,
        job_id: u64,
        decision_seq: u64,
        replay_hash: u64,
        task: TaskId,
        region: RegionId,
        obligation: ObligationId,
    ) -> Self {
        Self::worker_lifecycle(
            seq,
            time,
            TraceEventKind::WorkerDrainStarted,
            worker_id,
            job_id,
            decision_seq,
            replay_hash,
            task,
            region,
            obligation,
        )
    }

    /// Creates a worker-offload drain-completed event.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn worker_drain_completed(
        seq: u64,
        time: Time,
        worker_id: impl Into<String>,
        job_id: u64,
        decision_seq: u64,
        replay_hash: u64,
        task: TaskId,
        region: RegionId,
        obligation: ObligationId,
    ) -> Self {
        Self::worker_lifecycle(
            seq,
            time,
            TraceEventKind::WorkerDrainCompleted,
            worker_id,
            job_id,
            decision_seq,
            replay_hash,
            task,
            region,
            obligation,
        )
    }

    /// Creates a worker-offload finalize-completed event.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn worker_finalize_completed(
        seq: u64,
        time: Time,
        worker_id: impl Into<String>,
        job_id: u64,
        decision_seq: u64,
        replay_hash: u64,
        task: TaskId,
        region: RegionId,
        obligation: ObligationId,
    ) -> Self {
        Self::worker_lifecycle(
            seq,
            time,
            TraceEventKind::WorkerFinalizeCompleted,
            worker_id,
            job_id,
            decision_seq,
            replay_hash,
            task,
            region,
            obligation,
        )
    }

    /// Creates a region created event.
    #[must_use]
    pub fn region_created(
        seq: u64,
        time: Time,
        region: RegionId,
        parent: Option<RegionId>,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::RegionCreated,
            TraceData::Region { region, parent },
        )
    }

    /// Creates a region cancelled event.
    #[must_use]
    pub fn region_cancelled(seq: u64, time: Time, region: RegionId, reason: CancelReason) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::RegionCancelled,
            TraceData::RegionCancel { region, reason },
        )
    }

    /// Creates a time advance event.
    #[must_use]
    pub fn time_advance(seq: u64, time: Time, old: Time, new: Time) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::TimeAdvance,
            TraceData::Time { old, new },
        )
    }

    /// Creates a timer scheduled event.
    #[must_use]
    pub fn timer_scheduled(seq: u64, time: Time, timer_id: u64, deadline: Time) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::TimerScheduled,
            TraceData::Timer {
                timer_id,
                deadline: Some(deadline),
            },
        )
    }

    /// Creates a timer fired event.
    #[must_use]
    pub fn timer_fired(seq: u64, time: Time, timer_id: u64) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::TimerFired,
            TraceData::Timer {
                timer_id,
                deadline: None,
            },
        )
    }

    /// Creates a timer cancelled event.
    #[must_use]
    pub fn timer_cancelled(seq: u64, time: Time, timer_id: u64) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::TimerCancelled,
            TraceData::Timer {
                timer_id,
                deadline: None,
            },
        )
    }

    /// Creates an I/O requested event.
    #[must_use]
    pub fn io_requested(seq: u64, time: Time, token: u64, interest: u8) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::IoRequested,
            TraceData::IoRequested { token, interest },
        )
    }

    /// Creates an I/O ready event.
    #[must_use]
    pub fn io_ready(seq: u64, time: Time, token: u64, readiness: u8) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::IoReady,
            TraceData::IoReady { token, readiness },
        )
    }

    /// Creates an I/O result event.
    #[must_use]
    pub fn io_result(seq: u64, time: Time, token: u64, bytes: i64) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::IoResult,
            TraceData::IoResult { token, bytes },
        )
    }

    /// Creates an I/O error event.
    #[must_use]
    pub fn io_error(seq: u64, time: Time, token: u64, kind: u8) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::IoError,
            TraceData::IoError { token, kind },
        )
    }

    /// Creates an RNG seed event.
    #[must_use]
    pub fn rng_seed(seq: u64, time: Time, seed: u64) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::RngSeed,
            TraceData::RngSeed { seed },
        )
    }

    /// Creates an RNG value event.
    #[must_use]
    pub fn rng_value(seq: u64, time: Time, value: u64) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::RngValue,
            TraceData::RngValue { value },
        )
    }

    /// Creates a checkpoint event.
    #[must_use]
    pub fn checkpoint(
        seq: u64,
        time: Time,
        sequence: u64,
        active_tasks: u32,
        active_regions: u32,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::Checkpoint,
            TraceData::Checkpoint {
                sequence,
                active_tasks,
                active_regions,
            },
        )
    }

    /// Creates an obligation reserve event.
    #[must_use]
    pub fn obligation_reserve(
        seq: u64,
        time: Time,
        obligation: ObligationId,
        task: TaskId,
        region: RegionId,
        kind: ObligationKind,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::ObligationReserve,
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state: ObligationState::Reserved,
                duration_ns: None,
                abort_reason: None,
            },
        )
    }

    /// Creates an obligation commit event.
    #[must_use]
    pub fn obligation_commit(
        seq: u64,
        time: Time,
        obligation: ObligationId,
        task: TaskId,
        region: RegionId,
        kind: ObligationKind,
        duration_ns: u64,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::ObligationCommit,
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state: ObligationState::Committed,
                duration_ns: Some(duration_ns),
                abort_reason: None,
            },
        )
    }

    /// Creates an obligation abort event.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn obligation_abort(
        seq: u64,
        time: Time,
        obligation: ObligationId,
        task: TaskId,
        region: RegionId,
        kind: ObligationKind,
        duration_ns: u64,
        reason: ObligationAbortReason,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::ObligationAbort,
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state: ObligationState::Aborted,
                duration_ns: Some(duration_ns),
                abort_reason: Some(reason),
            },
        )
    }

    /// Creates an obligation leak event.
    #[must_use]
    pub fn obligation_leak(
        seq: u64,
        time: Time,
        obligation: ObligationId,
        task: TaskId,
        region: RegionId,
        kind: ObligationKind,
        duration_ns: u64,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::ObligationLeak,
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state: ObligationState::Leaked,
                duration_ns: Some(duration_ns),
                abort_reason: None,
            },
        )
    }

    /// Creates a monitor created event.
    #[must_use]
    pub fn monitor_created(
        seq: u64,
        time: Time,
        monitor_ref: u64,
        watcher: TaskId,
        watcher_region: RegionId,
        monitored: TaskId,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::MonitorCreated,
            TraceData::Monitor {
                monitor_ref,
                watcher,
                watcher_region,
                monitored,
            },
        )
    }

    /// Creates a monitor dropped event.
    #[must_use]
    pub fn monitor_dropped(
        seq: u64,
        time: Time,
        monitor_ref: u64,
        watcher: TaskId,
        watcher_region: RegionId,
        monitored: TaskId,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::MonitorDropped,
            TraceData::Monitor {
                monitor_ref,
                watcher,
                watcher_region,
                monitored,
            },
        )
    }

    /// Creates a down delivered event.
    #[must_use]
    pub fn down_delivered(
        seq: u64,
        time: Time,
        monitor_ref: u64,
        watcher: TaskId,
        monitored: TaskId,
        completion_vt: Time,
        reason: DownReason,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::DownDelivered,
            TraceData::Down {
                monitor_ref,
                watcher,
                monitored,
                completion_vt,
                reason,
            },
        )
    }

    /// Creates a link created event.
    #[must_use]
    pub fn link_created(
        seq: u64,
        time: Time,
        link_ref: u64,
        task_a: TaskId,
        region_a: RegionId,
        task_b: TaskId,
        region_b: RegionId,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::LinkCreated,
            TraceData::Link {
                link_ref,
                task_a,
                region_a,
                task_b,
                region_b,
            },
        )
    }

    /// Creates a link dropped event.
    #[must_use]
    pub fn link_dropped(
        seq: u64,
        time: Time,
        link_ref: u64,
        task_a: TaskId,
        region_a: RegionId,
        task_b: TaskId,
        region_b: RegionId,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::LinkDropped,
            TraceData::Link {
                link_ref,
                task_a,
                region_a,
                task_b,
                region_b,
            },
        )
    }

    /// Creates an exit delivered event.
    #[must_use]
    pub fn exit_delivered(
        seq: u64,
        time: Time,
        link_ref: u64,
        from: TaskId,
        to: TaskId,
        failure_vt: Time,
        reason: DownReason,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::ExitDelivered,
            TraceData::Exit {
                link_ref,
                from,
                to,
                failure_vt,
                reason,
            },
        )
    }

    /// Creates a user trace event.
    #[must_use]
    pub fn user_trace(seq: u64, time: Time, message: impl Into<String>) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::UserTrace,
            TraceData::Message(message.into()),
        )
    }
}

impl fmt::Display for TraceEvent {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:06}] {} {}", self.seq, self.time, self.kind)?;
        if let Some(ref lt) = self.logical_time {
            write!(f, " @{lt:?}")?;
        }
        match &self.data {
            TraceData::None => {}
            TraceData::Task { task, region } => write!(f, " {task} in {region}")?,
            TraceData::Region { region, parent } => {
                write!(f, " {region}")?;
                if let Some(p) = parent {
                    write!(f, " (parent: {p})")?;
                }
            }
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state,
                duration_ns,
                abort_reason,
            } => {
                write!(
                    f,
                    " {obligation} {kind:?} {state:?} holder={task} region={region}"
                )?;
                if let Some(duration) = duration_ns {
                    write!(f, " duration={duration}ns")?;
                }
                if let Some(reason) = abort_reason {
                    write!(f, " abort_reason={reason}")?;
                }
            }
            TraceData::Cancel {
                task,
                region,
                reason,
            } => write!(f, " {task} in {region} reason={reason}")?,
            TraceData::Worker {
                worker_id,
                job_id,
                decision_seq,
                replay_hash,
                task,
                region,
                obligation,
            } => write!(
                f,
                " worker={worker_id} job_id={job_id} {task} in {region} obligation={obligation} decision_seq={decision_seq} replay_hash={replay_hash}"
            )?,
            TraceData::RegionCancel { region, reason } => {
                write!(f, " {region} reason={reason}")?;
            }
            TraceData::Time { old, new } => write!(f, " {old} -> {new}")?,
            TraceData::Timer { timer_id, deadline } => {
                write!(f, " timer={timer_id}")?;
                if let Some(dl) = deadline {
                    write!(f, " deadline={dl}")?;
                }
            }
            TraceData::IoRequested { token, interest } => {
                write!(f, " io_requested token={token} interest={interest}")?;
            }
            TraceData::IoReady { token, readiness } => {
                write!(f, " io_ready token={token} readiness={readiness}")?;
            }
            TraceData::IoResult { token, bytes } => {
                write!(f, " io_result token={token} bytes={bytes}")?;
            }
            TraceData::IoError { token, kind } => {
                write!(f, " io_error token={token} kind={kind}")?;
            }
            TraceData::RngSeed { seed } => write!(f, " rng_seed={seed}")?,
            TraceData::RngValue { value } => write!(f, " rng_value={value}")?,
            TraceData::Checkpoint {
                sequence,
                active_tasks,
                active_regions,
            } => write!(
                f,
                " checkpoint seq={sequence} tasks={active_tasks} regions={active_regions}"
            )?,
            TraceData::Futurelock {
                task,
                region,
                idle_steps,
                held,
            } => {
                write!(f, " futurelock: {task} in {region} idle={idle_steps}")?;
                write!(f, " held=[")?;
                for (i, (oid, kind)) in held.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{oid}:{kind:?}")?;
                }
                write!(f, "]")?;
            }
            TraceData::Monitor {
                monitor_ref,
                watcher,
                watcher_region,
                monitored,
            } => write!(
                f,
                " monitor_ref={monitor_ref} watcher={watcher} watcher_region={watcher_region} monitored={monitored}"
            )?,
            TraceData::Down {
                monitor_ref,
                watcher,
                monitored,
                completion_vt,
                reason,
            } => write!(
                f,
                " down monitor_ref={monitor_ref} watcher={watcher} monitored={monitored} completion_vt={completion_vt} reason={reason}"
            )?,
            TraceData::Link {
                link_ref,
                task_a,
                region_a,
                task_b,
                region_b,
            } => write!(
                f,
                " link_ref={link_ref} a={task_a} region_a={region_a} b={task_b} region_b={region_b}"
            )?,
            TraceData::Exit {
                link_ref,
                from,
                to,
                failure_vt,
                reason,
            } => write!(
                f,
                " exit link_ref={link_ref} from={from} to={to} failure_vt={failure_vt} reason={reason}"
            )?,
            TraceData::Message(msg) => write!(f, " \"{msg}\"")?,
            TraceData::Chaos { kind, task, detail } => {
                write!(f, " chaos:{kind}")?;
                if let Some(t) = task {
                    write!(f, " task={t}")?;
                }
                write!(f, " {detail}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;
    use crate::monitor::DownReason;
    use crate::record::{ObligationAbortReason, ObligationKind, ObligationState};
    use crate::trace::distributed::LamportTime;
    use crate::types::CancelReason;
    use serde_json::Value;
    use std::collections::BTreeSet;

    fn task(n: u32) -> TaskId {
        TaskId::new_for_test(n, 1)
    }
    fn region(n: u32) -> RegionId {
        RegionId::new_for_test(n, 1)
    }
    fn obligation(n: u32) -> ObligationId {
        ObligationId::new_for_test(n, 1)
    }

    fn scrub_browser_trace_fields(fields: &std::collections::BTreeMap<String, String>) -> Value {
        let mut value = serde_json::to_value(fields).expect("serialize browser trace fields");
        let obj = value
            .as_object_mut()
            .expect("browser trace fields serialize to an object");

        for key in [
            "capture_host_time_ns",
            "capture_replay_key",
            "completion_vt",
            "deadline",
            "failure_vt",
            "from",
            "monitored",
            "new",
            "old",
            "parent",
            "region_a",
            "region_b",
            "seq",
            "task_a",
            "task_b",
            "to",
            "time_ns",
            "trace_id",
            "task",
            "region",
            "obligation",
            "sequence_group",
            "watcher",
            "watcher_region",
        ] {
            if obj.contains_key(key) {
                obj.insert(key.to_string(), Value::String(format!("[{key}]")));
            }
        }

        value
    }

    // ── TraceEventKind basics ──────────────────────────────────────

    #[test]
    fn trace_event_version_is_set() {
        let event = TraceEvent::new(1, Time::ZERO, TraceEventKind::UserTrace, TraceData::None);
        assert_eq!(event.version, TRACE_EVENT_SCHEMA_VERSION);
    }

    #[test]
    fn trace_event_kind_stable_names_are_unique() {
        let mut names = BTreeSet::new();
        for kind in TraceEventKind::ALL {
            assert!(names.insert(kind.stable_name()));
        }
    }

    #[test]
    fn trace_event_taxonomy_is_documented() {
        const DOC: &str = include_str!("../../docs/spork_deterministic_ordering.md");
        for kind in TraceEventKind::ALL {
            let marker = format!("- `{}` => `{}`", kind.stable_name(), kind.required_fields());
            assert!(
                DOC.contains(&marker),
                "missing taxonomy entry in docs/spork_deterministic_ordering.md for {}",
                kind.stable_name()
            );
        }
    }

    #[test]
    fn all_array_has_41_kinds() {
        assert_eq!(TraceEventKind::ALL.len(), 41);
    }

    #[test]
    fn all_kinds_are_distinct() {
        let set: BTreeSet<TraceEventKind> = TraceEventKind::ALL.iter().copied().collect();
        assert_eq!(set.len(), TraceEventKind::ALL.len());
    }

    #[test]
    fn display_delegates_to_stable_name() {
        for kind in TraceEventKind::ALL {
            assert_eq!(format!("{kind}"), kind.stable_name());
        }
    }

    #[test]
    fn kind_ord_is_consistent_with_eq() {
        for a in TraceEventKind::ALL {
            for b in TraceEventKind::ALL {
                if a == b {
                    assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
                } else {
                    assert_ne!(a.cmp(&b), std::cmp::Ordering::Equal);
                }
            }
        }
    }

    #[test]
    fn required_fields_non_empty_for_all() {
        for kind in TraceEventKind::ALL {
            assert!(
                !kind.required_fields().is_empty(),
                "required_fields empty for {kind:?}"
            );
        }
    }

    // ── Constructor tests ──────────────────────────────────────────

    #[test]
    fn spawn_constructor() {
        let e = TraceEvent::spawn(1, Time::ZERO, task(10), region(20));
        assert_eq!(e.kind, TraceEventKind::Spawn);
        assert_eq!(e.seq, 1);
        assert_eq!(
            e.data,
            TraceData::Task {
                task: task(10),
                region: region(20)
            }
        );
    }

    #[test]
    fn schedule_constructor() {
        let e = TraceEvent::schedule(2, Time::from_nanos(100), task(1), region(2));
        assert_eq!(e.kind, TraceEventKind::Schedule);
        assert_eq!(
            e.data,
            TraceData::Task {
                task: task(1),
                region: region(2)
            }
        );
    }

    #[test]
    fn yield_task_constructor() {
        let e = TraceEvent::yield_task(3, Time::ZERO, task(5), region(6));
        assert_eq!(e.kind, TraceEventKind::Yield);
        assert_eq!(
            e.data,
            TraceData::Task {
                task: task(5),
                region: region(6)
            }
        );
    }

    #[test]
    fn wake_constructor() {
        let e = TraceEvent::wake(4, Time::ZERO, task(7), region(8));
        assert_eq!(e.kind, TraceEventKind::Wake);
        assert_eq!(
            e.data,
            TraceData::Task {
                task: task(7),
                region: region(8)
            }
        );
    }

    #[test]
    fn poll_constructor() {
        let e = TraceEvent::poll(5, Time::ZERO, task(9), region(10));
        assert_eq!(e.kind, TraceEventKind::Poll);
        assert_eq!(
            e.data,
            TraceData::Task {
                task: task(9),
                region: region(10)
            }
        );
    }

    #[test]
    fn complete_constructor() {
        let e = TraceEvent::complete(6, Time::ZERO, task(11), region(12));
        assert_eq!(e.kind, TraceEventKind::Complete);
        assert_eq!(
            e.data,
            TraceData::Task {
                task: task(11),
                region: region(12)
            }
        );
    }

    #[test]
    fn cancel_request_constructor() {
        let e =
            TraceEvent::cancel_request(7, Time::ZERO, task(1), region(2), CancelReason::timeout());
        assert_eq!(e.kind, TraceEventKind::CancelRequest);
        match &e.data {
            TraceData::Cancel {
                task: t,
                region: r,
                reason,
            } => {
                assert_eq!(*t, task(1));
                assert_eq!(*r, region(2));
                assert_eq!(reason.kind(), crate::types::CancelKind::Timeout);
            }
            other => panic!("expected Cancel, got {other:?}"),
        }
    }

    #[test]
    fn region_created_constructor_with_parent() {
        let e = TraceEvent::region_created(8, Time::ZERO, region(3), Some(region(1)));
        assert_eq!(e.kind, TraceEventKind::RegionCreated);
        assert_eq!(
            e.data,
            TraceData::Region {
                region: region(3),
                parent: Some(region(1))
            }
        );
    }

    #[test]
    fn region_created_constructor_without_parent() {
        let e = TraceEvent::region_created(9, Time::ZERO, region(3), None);
        assert_eq!(e.kind, TraceEventKind::RegionCreated);
        assert_eq!(
            e.data,
            TraceData::Region {
                region: region(3),
                parent: None
            }
        );
    }

    #[test]
    fn region_cancelled_constructor() {
        let e = TraceEvent::region_cancelled(10, Time::ZERO, region(5), CancelReason::shutdown());
        assert_eq!(e.kind, TraceEventKind::RegionCancelled);
        match &e.data {
            TraceData::RegionCancel { region: r, .. } => assert_eq!(*r, region(5)),
            other => panic!("expected RegionCancel, got {other:?}"),
        }
    }

    #[test]
    fn time_advance_constructor() {
        let e =
            TraceEvent::time_advance(11, Time::ZERO, Time::from_nanos(0), Time::from_nanos(100));
        assert_eq!(e.kind, TraceEventKind::TimeAdvance);
        assert_eq!(
            e.data,
            TraceData::Time {
                old: Time::from_nanos(0),
                new: Time::from_nanos(100)
            }
        );
    }

    #[test]
    fn timer_scheduled_constructor() {
        let e = TraceEvent::timer_scheduled(12, Time::ZERO, 42, Time::from_millis(500));
        assert_eq!(e.kind, TraceEventKind::TimerScheduled);
        assert_eq!(
            e.data,
            TraceData::Timer {
                timer_id: 42,
                deadline: Some(Time::from_millis(500))
            }
        );
    }

    #[test]
    fn timer_fired_constructor() {
        let e = TraceEvent::timer_fired(13, Time::ZERO, 42);
        assert_eq!(e.kind, TraceEventKind::TimerFired);
        assert_eq!(
            e.data,
            TraceData::Timer {
                timer_id: 42,
                deadline: None
            }
        );
    }

    #[test]
    fn timer_cancelled_constructor() {
        let e = TraceEvent::timer_cancelled(14, Time::ZERO, 42);
        assert_eq!(e.kind, TraceEventKind::TimerCancelled);
        assert_eq!(
            e.data,
            TraceData::Timer {
                timer_id: 42,
                deadline: None
            }
        );
    }

    #[test]
    fn io_requested_constructor() {
        let e = TraceEvent::io_requested(15, Time::ZERO, 99, 0x03);
        assert_eq!(e.kind, TraceEventKind::IoRequested);
        assert_eq!(
            e.data,
            TraceData::IoRequested {
                token: 99,
                interest: 0x03
            }
        );
    }

    #[test]
    fn io_ready_constructor() {
        let e = TraceEvent::io_ready(16, Time::ZERO, 99, 0x01);
        assert_eq!(e.kind, TraceEventKind::IoReady);
        assert_eq!(
            e.data,
            TraceData::IoReady {
                token: 99,
                readiness: 0x01
            }
        );
    }

    #[test]
    fn io_result_constructor() {
        let e = TraceEvent::io_result(17, Time::ZERO, 99, 1024);
        assert_eq!(e.kind, TraceEventKind::IoResult);
        assert_eq!(
            e.data,
            TraceData::IoResult {
                token: 99,
                bytes: 1024
            }
        );
    }

    #[test]
    fn io_result_negative_bytes() {
        let e = TraceEvent::io_result(18, Time::ZERO, 99, -1);
        assert_eq!(
            e.data,
            TraceData::IoResult {
                token: 99,
                bytes: -1
            }
        );
    }

    #[test]
    fn io_error_constructor() {
        let e = TraceEvent::io_error(19, Time::ZERO, 99, 13);
        assert_eq!(e.kind, TraceEventKind::IoError);
        assert_eq!(
            e.data,
            TraceData::IoError {
                token: 99,
                kind: 13
            }
        );
    }

    #[test]
    fn rng_seed_constructor() {
        let e = TraceEvent::rng_seed(20, Time::ZERO, 0xDEAD_BEEF);
        assert_eq!(e.kind, TraceEventKind::RngSeed);
        assert_eq!(e.data, TraceData::RngSeed { seed: 0xDEAD_BEEF });
    }

    #[test]
    fn rng_value_constructor() {
        let e = TraceEvent::rng_value(21, Time::ZERO, 42);
        assert_eq!(e.kind, TraceEventKind::RngValue);
        assert_eq!(e.data, TraceData::RngValue { value: 42 });
    }

    #[test]
    fn checkpoint_constructor() {
        let e = TraceEvent::checkpoint(22, Time::ZERO, 7, 3, 2);
        assert_eq!(e.kind, TraceEventKind::Checkpoint);
        assert_eq!(
            e.data,
            TraceData::Checkpoint {
                sequence: 7,
                active_tasks: 3,
                active_regions: 2
            }
        );
    }

    #[test]
    fn obligation_reserve_constructor() {
        let e = TraceEvent::obligation_reserve(
            23,
            Time::ZERO,
            obligation(1),
            task(2),
            region(3),
            ObligationKind::SendPermit,
        );
        assert_eq!(e.kind, TraceEventKind::ObligationReserve);
        match &e.data {
            TraceData::Obligation {
                state,
                duration_ns,
                abort_reason,
                ..
            } => {
                assert_eq!(*state, ObligationState::Reserved);
                assert_eq!(*duration_ns, None);
                assert_eq!(*abort_reason, None);
            }
            other => panic!("expected Obligation, got {other:?}"),
        }
    }

    #[test]
    fn obligation_commit_constructor() {
        let e = TraceEvent::obligation_commit(
            24,
            Time::ZERO,
            obligation(1),
            task(2),
            region(3),
            ObligationKind::Ack,
            5000,
        );
        assert_eq!(e.kind, TraceEventKind::ObligationCommit);
        match &e.data {
            TraceData::Obligation {
                state,
                duration_ns,
                abort_reason,
                ..
            } => {
                assert_eq!(*state, ObligationState::Committed);
                assert_eq!(*duration_ns, Some(5000));
                assert_eq!(*abort_reason, None);
            }
            other => panic!("expected Obligation, got {other:?}"),
        }
    }

    #[test]
    fn obligation_abort_constructor() {
        let e = TraceEvent::obligation_abort(
            25,
            Time::ZERO,
            obligation(1),
            task(2),
            region(3),
            ObligationKind::Lease,
            3000,
            ObligationAbortReason::Cancel,
        );
        assert_eq!(e.kind, TraceEventKind::ObligationAbort);
        match &e.data {
            TraceData::Obligation {
                state,
                duration_ns,
                abort_reason,
                ..
            } => {
                assert_eq!(*state, ObligationState::Aborted);
                assert_eq!(*duration_ns, Some(3000));
                assert_eq!(*abort_reason, Some(ObligationAbortReason::Cancel));
            }
            other => panic!("expected Obligation, got {other:?}"),
        }
    }

    #[test]
    fn obligation_leak_constructor() {
        let e = TraceEvent::obligation_leak(
            26,
            Time::ZERO,
            obligation(1),
            task(2),
            region(3),
            ObligationKind::IoOp,
            9000,
        );
        assert_eq!(e.kind, TraceEventKind::ObligationLeak);
        match &e.data {
            TraceData::Obligation {
                state,
                duration_ns,
                abort_reason,
                ..
            } => {
                assert_eq!(*state, ObligationState::Leaked);
                assert_eq!(*duration_ns, Some(9000));
                assert_eq!(*abort_reason, None);
            }
            other => panic!("expected Obligation, got {other:?}"),
        }
    }

    #[test]
    fn monitor_created_constructor() {
        let e = TraceEvent::monitor_created(27, Time::ZERO, 100, task(1), region(2), task(3));
        assert_eq!(e.kind, TraceEventKind::MonitorCreated);
        assert_eq!(
            e.data,
            TraceData::Monitor {
                monitor_ref: 100,
                watcher: task(1),
                watcher_region: region(2),
                monitored: task(3),
            }
        );
    }

    #[test]
    fn monitor_dropped_constructor() {
        let e = TraceEvent::monitor_dropped(28, Time::ZERO, 100, task(1), region(2), task(3));
        assert_eq!(e.kind, TraceEventKind::MonitorDropped);
        assert_eq!(
            e.data,
            TraceData::Monitor {
                monitor_ref: 100,
                watcher: task(1),
                watcher_region: region(2),
                monitored: task(3),
            }
        );
    }

    #[test]
    fn down_delivered_constructor() {
        let e = TraceEvent::down_delivered(
            29,
            Time::ZERO,
            100,
            task(1),
            task(3),
            Time::from_nanos(500),
            DownReason::Normal,
        );
        assert_eq!(e.kind, TraceEventKind::DownDelivered);
        assert_eq!(
            e.data,
            TraceData::Down {
                monitor_ref: 100,
                watcher: task(1),
                monitored: task(3),
                completion_vt: Time::from_nanos(500),
                reason: DownReason::Normal,
            }
        );
    }

    #[test]
    fn link_created_constructor() {
        let e =
            TraceEvent::link_created(30, Time::ZERO, 200, task(1), region(2), task(3), region(4));
        assert_eq!(e.kind, TraceEventKind::LinkCreated);
        assert_eq!(
            e.data,
            TraceData::Link {
                link_ref: 200,
                task_a: task(1),
                region_a: region(2),
                task_b: task(3),
                region_b: region(4),
            }
        );
    }

    #[test]
    fn link_dropped_constructor() {
        let e =
            TraceEvent::link_dropped(31, Time::ZERO, 200, task(1), region(2), task(3), region(4));
        assert_eq!(e.kind, TraceEventKind::LinkDropped);
        assert_eq!(
            e.data,
            TraceData::Link {
                link_ref: 200,
                task_a: task(1),
                region_a: region(2),
                task_b: task(3),
                region_b: region(4),
            }
        );
    }

    #[test]
    fn exit_delivered_constructor() {
        let e = TraceEvent::exit_delivered(
            32,
            Time::ZERO,
            200,
            task(1),
            task(3),
            Time::from_nanos(999),
            DownReason::Normal,
        );
        assert_eq!(e.kind, TraceEventKind::ExitDelivered);
        assert_eq!(
            e.data,
            TraceData::Exit {
                link_ref: 200,
                from: task(1),
                to: task(3),
                failure_vt: Time::from_nanos(999),
                reason: DownReason::Normal,
            }
        );
    }

    #[test]
    fn user_trace_constructor() {
        let e = TraceEvent::user_trace(33, Time::ZERO, "hello");
        assert_eq!(e.kind, TraceEventKind::UserTrace);
        assert_eq!(e.data, TraceData::Message("hello".into()));
    }

    #[test]
    fn user_trace_accepts_string() {
        let e = TraceEvent::user_trace(34, Time::ZERO, String::from("world"));
        assert_eq!(e.data, TraceData::Message("world".into()));
    }

    #[test]
    fn worker_lifecycle_constructors_preserve_payload_shape() {
        let e = TraceEvent::worker_cancel_requested(
            35,
            Time::ZERO,
            "worker-a",
            77,
            91,
            0x00C0_FFEE,
            task(9),
            region(10),
            obligation(11),
        );
        assert_eq!(e.kind, TraceEventKind::WorkerCancelRequested);
        assert_eq!(
            e.data,
            TraceData::Worker {
                worker_id: "worker-a".into(),
                job_id: 77,
                decision_seq: 91,
                replay_hash: 0x00C0_FFEE,
                task: task(9),
                region: region(10),
                obligation: obligation(11),
            }
        );
    }

    // ── with_logical_time ──────────────────────────────────────────

    #[test]
    fn with_logical_time_sets_field() {
        let lt = LogicalTime::Lamport(LamportTime::from_raw(42));
        let e = TraceEvent::new(1, Time::ZERO, TraceEventKind::UserTrace, TraceData::None)
            .with_logical_time(lt);
        assert_eq!(
            e.logical_time,
            Some(LogicalTime::Lamport(LamportTime::from_raw(42)))
        );
    }

    #[test]
    fn default_logical_time_is_none() {
        let e = TraceEvent::new(1, Time::ZERO, TraceEventKind::UserTrace, TraceData::None);
        assert_eq!(e.logical_time, None);
    }

    // ── Display formatting ─────────────────────────────────────────

    #[test]
    fn display_task_event() {
        let e = TraceEvent::spawn(1, Time::ZERO, task(10), region(20));
        let s = format!("{e}");
        assert!(s.contains("spawn"), "expected 'spawn' in {s}");
        assert!(s.contains("[000001]"), "expected seq in {s}");
    }

    #[test]
    fn display_region_with_parent() {
        let e = TraceEvent::region_created(2, Time::ZERO, region(3), Some(region(1)));
        let s = format!("{e}");
        assert!(s.contains("region_created"), "expected kind in {s}");
        assert!(s.contains("parent"), "expected parent in {s}");
    }

    #[test]
    fn display_region_without_parent() {
        let e = TraceEvent::region_created(3, Time::ZERO, region(3), None);
        let s = format!("{e}");
        assert!(s.contains("region_created"), "expected kind in {s}");
        assert!(!s.contains("parent"), "should not contain parent: {s}");
    }

    #[test]
    fn display_obligation_with_duration_and_abort() {
        let e = TraceEvent::obligation_abort(
            4,
            Time::ZERO,
            obligation(1),
            task(2),
            region(3),
            ObligationKind::Lease,
            5000,
            ObligationAbortReason::Error,
        );
        let s = format!("{e}");
        assert!(s.contains("obligation_abort"), "expected kind in {s}");
        assert!(s.contains("duration=5000ns"), "expected duration in {s}");
        assert!(s.contains("abort_reason="), "expected abort_reason in {s}");
    }

    #[test]
    fn display_obligation_reserve_no_duration() {
        let e = TraceEvent::obligation_reserve(
            5,
            Time::ZERO,
            obligation(1),
            task(2),
            region(3),
            ObligationKind::SendPermit,
        );
        let s = format!("{e}");
        assert!(
            !s.contains("duration="),
            "reserve should not show duration: {s}"
        );
        assert!(
            !s.contains("abort_reason="),
            "reserve should not show abort_reason: {s}"
        );
    }

    #[test]
    fn display_cancel_event() {
        let e =
            TraceEvent::cancel_request(6, Time::ZERO, task(1), region(2), CancelReason::timeout());
        let s = format!("{e}");
        assert!(s.contains("cancel_request"), "expected kind in {s}");
        assert!(s.contains("reason="), "expected reason in {s}");
    }

    #[test]
    fn display_region_cancel() {
        let e = TraceEvent::region_cancelled(7, Time::ZERO, region(5), CancelReason::shutdown());
        let s = format!("{e}");
        assert!(s.contains("region_cancelled"), "expected kind in {s}");
        assert!(s.contains("reason="), "expected reason in {s}");
    }

    #[test]
    fn display_time_advance() {
        let e = TraceEvent::time_advance(8, Time::ZERO, Time::from_nanos(0), Time::from_nanos(100));
        let s = format!("{e}");
        assert!(s.contains("time_advance"), "expected kind in {s}");
        assert!(s.contains("->"), "expected arrow in {s}");
    }

    #[test]
    fn display_timer_with_deadline() {
        let e = TraceEvent::timer_scheduled(9, Time::ZERO, 42, Time::from_millis(500));
        let s = format!("{e}");
        assert!(s.contains("timer=42"), "expected timer id in {s}");
        assert!(s.contains("deadline="), "expected deadline in {s}");
    }

    #[test]
    fn display_timer_without_deadline() {
        let e = TraceEvent::timer_fired(10, Time::ZERO, 42);
        let s = format!("{e}");
        assert!(s.contains("timer=42"), "expected timer id in {s}");
        assert!(!s.contains("deadline="), "should not show deadline: {s}");
    }

    #[test]
    fn display_io_requested() {
        let e = TraceEvent::io_requested(11, Time::ZERO, 99, 0x03);
        let s = format!("{e}");
        assert!(s.contains("io_requested"), "expected kind in {s}");
        assert!(s.contains("token=99"), "expected token in {s}");
        assert!(s.contains("interest=3"), "expected interest in {s}");
    }

    #[test]
    fn display_io_ready() {
        let e = TraceEvent::io_ready(12, Time::ZERO, 99, 0x01);
        let s = format!("{e}");
        assert!(s.contains("io_ready"), "expected kind in {s}");
        assert!(s.contains("readiness=1"), "expected readiness in {s}");
    }

    #[test]
    fn display_io_result() {
        let e = TraceEvent::io_result(13, Time::ZERO, 99, 1024);
        let s = format!("{e}");
        assert!(s.contains("io_result"), "expected kind in {s}");
        assert!(s.contains("bytes=1024"), "expected bytes in {s}");
    }

    #[test]
    fn display_io_error() {
        let e = TraceEvent::io_error(14, Time::ZERO, 99, 13);
        let s = format!("{e}");
        assert!(s.contains("io_error"), "expected kind in {s}");
        assert!(s.contains("kind=13"), "expected kind in {s}");
    }

    #[test]
    fn display_rng_seed() {
        let e = TraceEvent::rng_seed(15, Time::ZERO, 0xCAFE);
        let s = format!("{e}");
        assert!(s.contains("rng_seed=51966"), "expected seed in {s}");
    }

    #[test]
    fn display_rng_value() {
        let e = TraceEvent::rng_value(16, Time::ZERO, 42);
        let s = format!("{e}");
        assert!(s.contains("rng_value=42"), "expected value in {s}");
    }

    #[test]
    fn display_checkpoint() {
        let e = TraceEvent::checkpoint(17, Time::ZERO, 7, 3, 2);
        let s = format!("{e}");
        assert!(s.contains("checkpoint"), "expected kind in {s}");
        assert!(s.contains("seq=7"), "expected seq in {s}");
        assert!(s.contains("tasks=3"), "expected tasks in {s}");
        assert!(s.contains("regions=2"), "expected regions in {s}");
    }

    #[test]
    fn display_futurelock_empty_held() {
        let e = TraceEvent::new(
            18,
            Time::ZERO,
            TraceEventKind::FuturelockDetected,
            TraceData::Futurelock {
                task: task(1),
                region: region(2),
                idle_steps: 10,
                held: vec![],
            },
        );
        let s = format!("{e}");
        assert!(s.contains("futurelock"), "expected kind in {s}");
        assert!(s.contains("idle=10"), "expected idle in {s}");
        assert!(s.contains("held=[]"), "expected empty held in {s}");
    }

    #[test]
    fn display_futurelock_with_held() {
        let e = TraceEvent::new(
            19,
            Time::ZERO,
            TraceEventKind::FuturelockDetected,
            TraceData::Futurelock {
                task: task(1),
                region: region(2),
                idle_steps: 5,
                held: vec![(obligation(10), ObligationKind::SendPermit)],
            },
        );
        let s = format!("{e}");
        assert!(s.contains("held=["), "expected held in {s}");
        assert!(s.contains("SendPermit"), "expected kind in {s}");
    }

    #[test]
    fn display_monitor() {
        let e = TraceEvent::monitor_created(20, Time::ZERO, 100, task(1), region(2), task(3));
        let s = format!("{e}");
        assert!(s.contains("monitor_ref=100"), "expected ref in {s}");
    }

    #[test]
    fn display_down() {
        let e = TraceEvent::down_delivered(
            21,
            Time::ZERO,
            100,
            task(1),
            task(3),
            Time::from_nanos(500),
            DownReason::Normal,
        );
        let s = format!("{e}");
        assert!(s.contains("down"), "expected down in {s}");
        assert!(s.contains("monitor_ref=100"), "expected ref in {s}");
    }

    #[test]
    fn display_link() {
        let e =
            TraceEvent::link_created(22, Time::ZERO, 200, task(1), region(2), task(3), region(4));
        let s = format!("{e}");
        assert!(s.contains("link_ref=200"), "expected ref in {s}");
    }

    #[test]
    fn display_exit() {
        let e = TraceEvent::exit_delivered(
            23,
            Time::ZERO,
            200,
            task(1),
            task(3),
            Time::from_nanos(999),
            DownReason::Normal,
        );
        let s = format!("{e}");
        assert!(s.contains("exit"), "expected exit in {s}");
        assert!(s.contains("link_ref=200"), "expected ref in {s}");
    }

    #[test]
    fn display_message() {
        let e = TraceEvent::user_trace(24, Time::ZERO, "hello world");
        let s = format!("{e}");
        assert!(s.contains("\"hello world\""), "expected msg in {s}");
    }

    #[test]
    fn display_chaos_with_task() {
        let e = TraceEvent::new(
            25,
            Time::ZERO,
            TraceEventKind::ChaosInjection,
            TraceData::Chaos {
                kind: "delay".into(),
                task: Some(task(1)),
                detail: "200ns".into(),
            },
        );
        let s = format!("{e}");
        assert!(s.contains("chaos:delay"), "expected kind in {s}");
        assert!(s.contains("task="), "expected task in {s}");
        assert!(s.contains("200ns"), "expected detail in {s}");
    }

    #[test]
    fn display_chaos_without_task() {
        let e = TraceEvent::new(
            26,
            Time::ZERO,
            TraceEventKind::ChaosInjection,
            TraceData::Chaos {
                kind: "budget_exhaust".into(),
                task: None,
                detail: "all".into(),
            },
        );
        let s = format!("{e}");
        assert!(s.contains("chaos:budget_exhaust"), "expected kind in {s}");
        assert!(!s.contains("task="), "should not show task: {s}");
    }

    #[test]
    fn display_none_data() {
        let e = TraceEvent::new(27, Time::ZERO, TraceEventKind::UserTrace, TraceData::None);
        let s = format!("{e}");
        // Should have seq, time, kind but nothing else
        assert!(s.contains("user_trace"), "expected kind in {s}");
    }

    #[test]
    fn display_with_logical_time() {
        let lt = LogicalTime::Lamport(LamportTime::from_raw(42));
        let e = TraceEvent::new(28, Time::ZERO, TraceEventKind::UserTrace, TraceData::None)
            .with_logical_time(lt);
        let s = format!("{e}");
        assert!(s.contains('@'), "expected @lt in {s}");
    }

    // ── Equality and Clone ─────────────────────────────────────────

    #[test]
    fn events_equal_same_fields() {
        let a = TraceEvent::spawn(1, Time::ZERO, task(1), region(2));
        let b = TraceEvent::spawn(1, Time::ZERO, task(1), region(2));
        assert_eq!(a, b);
    }

    #[test]
    fn events_differ_on_seq() {
        let a = TraceEvent::spawn(1, Time::ZERO, task(1), region(2));
        let b = TraceEvent::spawn(2, Time::ZERO, task(1), region(2));
        assert_ne!(a, b);
    }

    #[test]
    fn events_differ_on_kind() {
        let a = TraceEvent::spawn(1, Time::ZERO, task(1), region(2));
        let b = TraceEvent::schedule(1, Time::ZERO, task(1), region(2));
        assert_ne!(a, b);
    }

    #[test]
    fn events_differ_on_data() {
        let a = TraceEvent::spawn(1, Time::ZERO, task(1), region(2));
        let b = TraceEvent::spawn(1, Time::ZERO, task(1), region(3));
        assert_ne!(a, b);
    }

    #[test]
    fn trace_data_clone() {
        let data = TraceData::Task {
            task: task(1),
            region: region(2),
        };
        let cloned = data.clone();
        assert_eq!(data, cloned);
    }

    #[test]
    fn trace_data_message_eq() {
        let a = TraceData::Message("hello".into());
        let b = TraceData::Message("hello".into());
        assert_eq!(a, b);
    }

    #[test]
    fn trace_data_message_ne() {
        let a = TraceData::Message("hello".into());
        let b = TraceData::Message("world".into());
        assert_ne!(a, b);
    }

    #[test]
    fn trace_data_none_variant() {
        assert_eq!(TraceData::None, TraceData::None);
    }

    #[test]
    fn trace_event_clone() {
        let e = TraceEvent::spawn(1, Time::ZERO, task(1), region(2));
        let c = e.clone();
        assert_eq!(e, c);
    }

    // ── Obligation all-kinds coverage ──────────────────────────────

    #[test]
    fn obligation_reserve_all_kinds() {
        for kind in [
            ObligationKind::SendPermit,
            ObligationKind::Ack,
            ObligationKind::Lease,
            ObligationKind::IoOp,
        ] {
            let e = TraceEvent::obligation_reserve(
                1,
                Time::ZERO,
                obligation(1),
                task(2),
                region(3),
                kind,
            );
            match &e.data {
                TraceData::Obligation { kind: k, .. } => assert_eq!(*k, kind),
                _ => panic!("wrong variant"),
            }
        }
    }

    #[test]
    fn obligation_abort_all_reasons() {
        for reason in [
            ObligationAbortReason::Cancel,
            ObligationAbortReason::Error,
            ObligationAbortReason::Explicit,
        ] {
            let e = TraceEvent::obligation_abort(
                1,
                Time::ZERO,
                obligation(1),
                task(2),
                region(3),
                ObligationKind::SendPermit,
                1000,
                reason,
            );
            match &e.data {
                TraceData::Obligation { abort_reason, .. } => {
                    assert_eq!(*abort_reason, Some(reason));
                }
                _ => panic!("wrong variant"),
            }
        }
    }

    // ── Down with error variant ────────────────────────────────────

    #[test]
    fn down_delivered_with_error_reason() {
        let e = TraceEvent::down_delivered(
            1,
            Time::ZERO,
            50,
            task(1),
            task(2),
            Time::from_nanos(100),
            DownReason::Error("boom".into()),
        );
        match &e.data {
            TraceData::Down { reason, .. } => {
                assert_eq!(*reason, DownReason::Error("boom".into()));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn exit_delivered_with_cancelled_reason() {
        let e = TraceEvent::exit_delivered(
            1,
            Time::ZERO,
            50,
            task(1),
            task(2),
            Time::from_nanos(100),
            DownReason::Cancelled(CancelReason::timeout()),
        );
        match &e.data {
            TraceData::Exit { reason, .. } => {
                assert!(matches!(reason, DownReason::Cancelled(_)));
            }
            _ => panic!("wrong variant"),
        }
    }

    // ── Edge cases ─────────────────────────────────────────────────

    #[test]
    fn seq_zero() {
        let e = TraceEvent::new(0, Time::ZERO, TraceEventKind::UserTrace, TraceData::None);
        assert_eq!(e.seq, 0);
    }

    #[test]
    fn seq_max() {
        let e = TraceEvent::new(
            u64::MAX,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::None,
        );
        assert_eq!(e.seq, u64::MAX);
    }

    #[test]
    fn time_max() {
        let e = TraceEvent::new(1, Time::MAX, TraceEventKind::UserTrace, TraceData::None);
        assert_eq!(e.time, Time::MAX);
    }

    #[test]
    fn io_result_zero_bytes() {
        let e = TraceEvent::io_result(1, Time::ZERO, 0, 0);
        assert_eq!(e.data, TraceData::IoResult { token: 0, bytes: 0 });
    }

    #[test]
    fn checkpoint_zero_counts() {
        let e = TraceEvent::checkpoint(1, Time::ZERO, 0, 0, 0);
        assert_eq!(
            e.data,
            TraceData::Checkpoint {
                sequence: 0,
                active_tasks: 0,
                active_regions: 0
            }
        );
    }

    #[test]
    fn futurelock_many_held() {
        let held: Vec<_> = (0..100)
            .map(|i| (obligation(i), ObligationKind::SendPermit))
            .collect();
        let e = TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::FuturelockDetected,
            TraceData::Futurelock {
                task: task(1),
                region: region(2),
                idle_steps: 1000,
                held,
            },
        );
        let s = format!("{e}");
        // Should contain all 100 entries
        assert!(s.matches("SendPermit").count() == 100);
    }

    // --- wave 78 trait coverage ---

    #[test]
    fn trace_event_kind_debug_clone_copy_eq_ord_hash() {
        use std::collections::HashSet;
        let k = TraceEventKind::Spawn;
        let k2 = k; // Copy
        let k3 = k;
        assert_eq!(k, k2);
        assert_eq!(k, k3);
        assert_ne!(k, TraceEventKind::Complete);
        assert!(k < TraceEventKind::Complete);
        let dbg = format!("{k:?}");
        assert!(dbg.contains("Spawn"));
        let mut set = HashSet::new();
        set.insert(k);
        assert!(set.contains(&k2));
    }

    #[test]
    fn trace_data_debug_clone_eq() {
        let d = TraceData::None;
        let d2 = d.clone();
        assert_eq!(d, d2);
        assert_ne!(d, TraceData::Message("hi".into()));
        let dbg = format!("{d:?}");
        assert!(dbg.contains("None"));
    }

    #[test]
    fn trace_event_debug_clone_eq() {
        let e = TraceEvent::new(
            0,
            Time::from_nanos(100),
            TraceEventKind::UserTrace,
            TraceData::Message("hello".into()),
        );
        let e2 = e.clone();
        assert_eq!(e, e2);
        let dbg = format!("{e:?}");
        assert!(dbg.contains("TraceEvent"));
    }

    #[test]
    fn browser_trace_schema_v1_validates() {
        let schema = browser_trace_schema_v1();
        validate_browser_trace_schema(&schema).expect("browser schema should validate");
    }

    #[test]
    fn browser_trace_schema_round_trip_json() {
        let schema = browser_trace_schema_v1();
        let payload = serde_json::to_string(&schema).expect("serialize schema");
        let decoded = decode_browser_trace_schema(&payload).expect("decode schema");
        assert_eq!(schema, decoded);
    }

    #[test]
    fn browser_trace_schema_timer_required_fields_match_payload_shape() {
        let schema = browser_trace_schema_v1();
        let scheduled = schema
            .event_specs
            .iter()
            .find(|entry| entry.event_kind == "timer_scheduled")
            .expect("timer_scheduled entry should exist");
        let fired = schema
            .event_specs
            .iter()
            .find(|entry| entry.event_kind == "timer_fired")
            .expect("timer_fired entry should exist");
        let cancelled = schema
            .event_specs
            .iter()
            .find(|entry| entry.event_kind == "timer_cancelled")
            .expect("timer_cancelled entry should exist");

        assert_eq!(
            scheduled.required_fields,
            vec!["deadline".to_string(), "timer_id".to_string()]
        );
        assert_eq!(fired.required_fields, vec!["timer_id".to_string()]);
        assert_eq!(cancelled.required_fields, vec!["timer_id".to_string()]);
    }

    #[test]
    fn browser_trace_schema_obligation_required_fields_match_payload_shape() {
        let schema = browser_trace_schema_v1();
        let reserve = schema
            .event_specs
            .iter()
            .find(|entry| entry.event_kind == "obligation_reserve")
            .expect("obligation_reserve entry should exist");
        let commit = schema
            .event_specs
            .iter()
            .find(|entry| entry.event_kind == "obligation_commit")
            .expect("obligation_commit entry should exist");
        let abort = schema
            .event_specs
            .iter()
            .find(|entry| entry.event_kind == "obligation_abort")
            .expect("obligation_abort entry should exist");
        let leak = schema
            .event_specs
            .iter()
            .find(|entry| entry.event_kind == "obligation_leak")
            .expect("obligation_leak entry should exist");

        assert_eq!(
            reserve.required_fields,
            vec![
                "kind".to_string(),
                "obligation".to_string(),
                "region".to_string(),
                "state".to_string(),
                "task".to_string(),
            ]
        );
        assert_eq!(
            commit.required_fields,
            vec![
                "duration_ns".to_string(),
                "kind".to_string(),
                "obligation".to_string(),
                "region".to_string(),
                "state".to_string(),
                "task".to_string(),
            ]
        );
        assert_eq!(
            abort.required_fields,
            vec![
                "abort_reason".to_string(),
                "duration_ns".to_string(),
                "kind".to_string(),
                "obligation".to_string(),
                "region".to_string(),
                "state".to_string(),
                "task".to_string(),
            ]
        );
        assert_eq!(
            leak.required_fields,
            vec![
                "duration_ns".to_string(),
                "kind".to_string(),
                "obligation".to_string(),
                "region".to_string(),
                "state".to_string(),
                "task".to_string(),
            ]
        );
    }

    #[test]
    fn browser_trace_schema_worker_required_fields_match_payload_shape() {
        let schema = browser_trace_schema_v1();
        for event_kind in [
            "worker_cancel_requested",
            "worker_cancel_acknowledged",
            "worker_drain_started",
            "worker_drain_completed",
            "worker_finalize_completed",
        ] {
            let entry = schema
                .event_specs
                .iter()
                .find(|entry| entry.event_kind == event_kind)
                .unwrap_or_else(|| panic!("{event_kind} entry should exist"));
            assert_eq!(entry.category, BrowserTraceCategory::CancellationTransition);
            assert_eq!(
                entry.required_fields,
                vec![
                    "decision_seq".to_string(),
                    "job_id".to_string(),
                    "obligation".to_string(),
                    "region".to_string(),
                    "replay_hash".to_string(),
                    "task".to_string(),
                    "worker_id".to_string(),
                ]
            );
        }
    }

    #[test]
    fn browser_trace_schema_decode_v0_migrates() {
        let legacy = serde_json::json!({
            "schema_version": "browser-trace-schema-v0",
            "required_envelope_fields": [
                "event_kind",
                "schema_version",
                "seq",
                "time_ns",
                "trace_id"
            ],
            "ordering_semantics": [
                "events must be strictly ordered by seq ascending",
                "logical_time must be monotonic for comparable causal domains",
                "trace streams must be deterministic for identical seed/config/replay inputs"
            ],
            "event_specs": browser_trace_schema_v1().event_specs
        });
        let payload = serde_json::to_string(&legacy).expect("serialize legacy schema");
        let decoded = decode_browser_trace_schema(&payload).expect("decode legacy schema");
        assert_eq!(
            decoded.schema_version,
            BROWSER_TRACE_SCHEMA_VERSION.to_string()
        );
        assert!(
            decoded
                .compatibility
                .backward_decode_aliases
                .iter()
                .any(|alias| alias == "browser-trace-schema-v0")
        );
    }

    #[test]
    fn browser_trace_schema_decode_v0_sparse_event_specs_use_defaults() {
        let event_specs = TraceEventKind::ALL
            .iter()
            .map(|kind| serde_json::json!({ "event_kind": kind.stable_name() }))
            .collect::<Vec<_>>();
        let legacy = serde_json::json!({
            "schema_version": "browser-trace-schema-v0",
            "required_envelope_fields": [
                "event_kind",
                "schema_version",
                "seq",
                "time_ns",
                "trace_id"
            ],
            "ordering_semantics": [
                "events must be strictly ordered by seq ascending",
                "logical_time must be monotonic for comparable causal domains",
                "trace streams must be deterministic for identical seed/config/replay inputs"
            ],
            "event_specs": event_specs
        });
        let payload = serde_json::to_string(&legacy).expect("serialize sparse legacy schema");
        let decoded = decode_browser_trace_schema(&payload).expect("decode sparse legacy schema");

        let user_trace = decoded
            .event_specs
            .iter()
            .find(|entry| entry.event_kind == "user_trace")
            .expect("user_trace entry should exist");
        assert_eq!(user_trace.category, BrowserTraceCategory::HostCallback);
        assert_eq!(user_trace.required_fields, vec!["message".to_string()]);
        assert_eq!(user_trace.redacted_fields, vec!["message".to_string()]);
    }

    #[test]
    fn browser_trace_schema_decode_v0_unknown_event_kind_fails_closed() {
        let legacy = serde_json::json!({
            "schema_version": "browser-trace-schema-v0",
            "required_envelope_fields": [
                "event_kind",
                "schema_version",
                "seq",
                "time_ns",
                "trace_id"
            ],
            "ordering_semantics": [
                "events must be strictly ordered by seq ascending",
                "logical_time must be monotonic for comparable causal domains",
                "trace streams must be deterministic for identical seed/config/replay inputs"
            ],
            "event_specs": [{ "event_kind": "not_a_real_event_kind" }]
        });
        let payload = serde_json::to_string(&legacy).expect("serialize invalid legacy schema");
        let error = decode_browser_trace_schema(&payload)
            .expect_err("unknown legacy event kinds must fail decode");
        assert!(error.contains("unknown legacy event kind"));
    }

    #[test]
    fn browser_trace_redaction_masks_message_payloads() {
        let event = TraceEvent::user_trace(4, Time::ZERO, "secret-token");
        let redacted = redact_browser_trace_event(&event);
        assert_eq!(
            redacted,
            TraceEvent::new(
                4,
                Time::ZERO,
                TraceEventKind::UserTrace,
                TraceData::Message("<redacted>".to_string())
            )
        );
    }

    #[test]
    fn browser_trace_log_fields_include_required_metadata() {
        let event = TraceEvent::timer_fired(9, Time::from_nanos(42), 10);
        let fields = browser_trace_log_fields(&event, "trace-browser-1", None);

        assert_eq!(
            fields.get("schema_version"),
            Some(&BROWSER_TRACE_SCHEMA_VERSION.to_string())
        );
        assert_eq!(fields.get("trace_id"), Some(&"trace-browser-1".to_string()));
        assert_eq!(fields.get("event_kind"), Some(&"timer_fired".to_string()));
        assert_eq!(fields.get("seq"), Some(&"9".to_string()));
        assert_eq!(fields.get("capture_source"), Some(&"runtime".to_string()));
        assert_eq!(fields.get("capture_host_turn_seq"), Some(&"9".to_string()));
        assert_eq!(fields.get("capture_source_seq"), Some(&"9".to_string()));
        assert_eq!(fields.get("capture_host_time_ns"), Some(&"42".to_string()));
        assert_eq!(
            fields.get("capture_replay_key"),
            Some(&"runtime:9:9:42".to_string())
        );
        assert_eq!(fields.get("validation_status"), Some(&"valid".to_string()));
        assert_eq!(
            fields.get("validation_failure_category"),
            Some(&"none".to_string())
        );
        assert_eq!(fields.get("sequence_group"), Some(&"timer:10".to_string()));
        assert_eq!(fields.get("timer_id"), Some(&"10".to_string()));
    }

    #[test]
    fn browser_trace_log_fields_with_capture_include_host_metadata() {
        let event = TraceEvent::timer_fired(17, Time::from_nanos(200), 11);
        let capture = BrowserCaptureMetadata {
            host_turn_seq: 71,
            source: BrowserCaptureSource::HostInput,
            source_seq: 4,
            host_time_ns: 9_001,
        };
        let fields =
            browser_trace_log_fields_with_capture(&event, "trace-browser-2", None, Some(&capture));
        assert_eq!(
            fields.get("capture_source"),
            Some(&"host_input".to_string())
        );
        assert_eq!(fields.get("capture_host_turn_seq"), Some(&"71".to_string()));
        assert_eq!(fields.get("capture_source_seq"), Some(&"4".to_string()));
        assert_eq!(
            fields.get("capture_host_time_ns"),
            Some(&"9001".to_string())
        );
        assert_eq!(
            fields.get("capture_replay_key"),
            Some(&"host_input:71:4:9001".to_string())
        );
    }

    #[test]
    fn browser_trace_log_fields_sequence_group_tracks_causal_domain() {
        let first = TraceEvent::timer_fired(7, Time::from_nanos(10), 41);
        let second = TraceEvent::timer_cancelled(8, Time::from_nanos(11), 41);
        let unrelated = TraceEvent::timer_fired(9, Time::from_nanos(12), 99);

        let first_fields = browser_trace_log_fields(&first, "trace-browser-group-1", None);
        let second_fields = browser_trace_log_fields(&second, "trace-browser-group-2", None);
        let unrelated_fields = browser_trace_log_fields(&unrelated, "trace-browser-group-3", None);

        assert_eq!(
            first_fields.get("sequence_group"),
            Some(&"timer:41".to_string())
        );
        assert_eq!(
            first_fields.get("sequence_group"),
            second_fields.get("sequence_group")
        );
        assert_ne!(
            first_fields.get("sequence_group"),
            unrelated_fields.get("sequence_group")
        );
    }

    #[test]
    fn browser_trace_log_fields_sequence_group_preserves_link_relationships() {
        let created = TraceEvent::link_created(
            20,
            Time::from_nanos(100),
            77,
            task(1),
            region(2),
            task(3),
            region(4),
        );
        let exited = TraceEvent::exit_delivered(
            21,
            Time::from_nanos(101),
            77,
            task(1),
            task(3),
            Time::from_nanos(55),
            DownReason::Normal,
        );
        let other = TraceEvent::link_dropped(
            22,
            Time::from_nanos(102),
            88,
            task(1),
            region(2),
            task(3),
            region(4),
        );

        let created_fields = browser_trace_log_fields(&created, "trace-browser-link-1", None);
        let exited_fields = browser_trace_log_fields(&exited, "trace-browser-link-2", None);
        let other_fields = browser_trace_log_fields(&other, "trace-browser-link-3", None);

        assert_eq!(
            created_fields.get("sequence_group"),
            Some(&"link:77".to_string())
        );
        assert_eq!(
            created_fields.get("sequence_group"),
            exited_fields.get("sequence_group")
        );
        assert_ne!(
            created_fields.get("sequence_group"),
            other_fields.get("sequence_group")
        );
    }

    #[test]
    fn browser_trace_log_fields_mark_invalid_when_failure_category_is_set() {
        let event = TraceEvent::timer_fired(9, Time::from_nanos(42), 10);
        let fields =
            browser_trace_log_fields(&event, "trace-browser-1", Some("schema_version_mismatch"));
        assert_eq!(
            fields.get("validation_status"),
            Some(&"invalid".to_string())
        );
        assert_eq!(
            fields.get("validation_failure_category"),
            Some(&"schema_version_mismatch".to_string())
        );
    }

    #[test]
    fn browser_trace_log_fields_include_worker_replay_linkage() {
        let event = TraceEvent::worker_cancel_requested(
            21,
            Time::from_nanos(55),
            "worker-a",
            77,
            91,
            0x00C0_FFEE,
            task(9),
            region(10),
            obligation(11),
        );
        let fields = browser_trace_log_fields(&event, "trace-browser-worker-1", None);
        assert_eq!(fields.get("decision_seq"), Some(&"91".to_string()));
        assert_eq!(fields.get("job_id"), Some(&"77".to_string()));
        assert_eq!(fields.get("obligation"), Some(&obligation(11).to_string()));
        assert_eq!(fields.get("region"), Some(&region(10).to_string()));
        assert_eq!(fields.get("replay_hash"), Some(&"12648430".to_string()));
        assert_eq!(fields.get("task"), Some(&task(9).to_string()));
        assert_eq!(fields.get("worker_id"), Some(&"worker-a".to_string()));
        assert_eq!(
            fields.get("sequence_group"),
            Some(&"worker_job:77:worker-a".to_string())
        );
    }

    #[test]
    fn browser_trace_log_fields_snapshot_scrubs_ids_and_timestamps() {
        let event = TraceEvent::worker_cancel_requested(
            41,
            Time::from_nanos(123_456_789),
            "worker-browser-snapshot",
            88,
            17,
            0x00C0_FFEE,
            task(9),
            region(10),
            obligation(11),
        );
        let capture = BrowserCaptureMetadata {
            host_turn_seq: 7,
            source: BrowserCaptureSource::HostInput,
            source_seq: 19,
            host_time_ns: 1_726_133_456_789_000_000,
        };

        let fields = browser_trace_log_fields_with_capture(
            &event,
            "trace-browser-snapshot-1",
            None,
            Some(&capture),
        );

        insta::assert_json_snapshot!(
            "browser_trace_log_fields_worker_scrubbed",
            scrub_browser_trace_fields(&fields)
        );
    }

    #[test]
    fn browser_trace_log_fields_timer_snapshot_scrubs_ids_and_timestamps() {
        let event =
            TraceEvent::timer_scheduled(14, Time::from_nanos(333), 42, Time::from_nanos(999));
        let fields = browser_trace_log_fields(&event, "trace-browser-timer-1", None);

        insta::assert_json_snapshot!(
            "browser_trace_log_fields_timer_scrubbed",
            scrub_browser_trace_fields(&fields)
        );
    }

    #[test]
    fn browser_trace_log_fields_obligation_abort_snapshot_scrubs_ids_and_timestamps() {
        let event = TraceEvent::obligation_abort(
            52,
            Time::from_nanos(7_777),
            obligation(4),
            task(8),
            region(9),
            ObligationKind::Lease,
            5_000,
            ObligationAbortReason::Error,
        );
        let fields = browser_trace_log_fields(&event, "trace-browser-obligation-1", None);

        insta::assert_json_snapshot!(
            "browser_trace_log_fields_obligation_abort_scrubbed",
            scrub_browser_trace_fields(&fields)
        );
    }

    #[test]
    fn browser_trace_log_fields_exit_snapshot_scrubs_ids_and_timestamps() {
        let event = TraceEvent::exit_delivered(
            61,
            Time::from_nanos(8_001),
            77,
            task(2),
            task(3),
            Time::from_nanos(4_444),
            DownReason::Normal,
        );
        let fields = browser_trace_log_fields(&event, "trace-browser-exit-1", None);

        insta::assert_json_snapshot!(
            "browser_trace_log_fields_exit_scrubbed",
            scrub_browser_trace_fields(&fields)
        );
    }

    #[test]
    fn browser_trace_log_fields_cap_large_worker_attributes_without_utf8_breakage() {
        let worker_id = format!("worker-{}", "e\u{0301}".repeat(200));
        let event = TraceEvent::worker_cancel_requested(
            30,
            Time::from_nanos(60),
            worker_id,
            123,
            456,
            0xDEAD_BEEF,
            task(5),
            region(6),
            obligation(7),
        );
        let fields = browser_trace_log_fields(&event, "trace-browser-worker-2", None);

        let worker_id = fields
            .get("worker_id")
            .expect("worker_id field should be present");
        let sequence_group = fields
            .get("sequence_group")
            .expect("sequence_group field should be present");

        assert!(worker_id.len() <= MAX_BROWSER_TRACE_ATTRIBUTE_BYTES);
        assert!(sequence_group.len() <= MAX_BROWSER_TRACE_ATTRIBUTE_BYTES);
        assert!(worker_id.starts_with("worker-"));
        assert!(sequence_group.starts_with("worker_job:123:worker-"));
        assert!(worker_id.contains('#'));
        assert!(sequence_group.contains('#'));
    }
}
