//! Trace events and data types.
//!
//! Each event in the trace represents an observable action in the runtime.
//! Events carry sufficient information for replay and analysis.

use crate::monitor::DownReason;
use crate::record::{ObligationAbortReason, ObligationKind, ObligationState};
use crate::trace::distributed::LogicalTime;
use crate::types::{CancelReason, ObligationId, PanicPayload, RegionId, TaskId, Time};
use core::fmt;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Current schema version for trace events.
pub const TRACE_EVENT_SCHEMA_VERSION: u32 = 1;
/// Browser trace contract schema version.
pub const BROWSER_TRACE_SCHEMA_VERSION: &str = "browser-trace-schema-v1";
const MAX_BROWSER_TRACE_ATTRIBUTE_BYTES: usize = 128;

/// Private versioned ownership record carried inside the existing UserTrace
/// envelope. IDs use their maintained serde representation, never Debug text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ObligationHandoff {
    pub(crate) id: ObligationId,
    pub(crate) source_ticket: u64,
    pub(crate) destination_ticket: u64,
    pub(crate) source_holder: TaskId,
    pub(crate) destination_holder: TaskId,
    pub(crate) source_region: RegionId,
    pub(crate) destination_region: RegionId,
}

const OBLIGATION_HANDOFF_PREFIX: &str = "obligation_handoff_v1 ";
const MAX_OBLIGATION_HANDOFF_MESSAGE_BYTES: usize = 2048;

impl ObligationHandoff {
    pub(crate) fn to_message(&self) -> String {
        format!(
            "{OBLIGATION_HANDOFF_PREFIX}{}",
            serde_json::to_string(self).expect("fixed scalar handoff fields serialize")
        )
    }
}

/// Decode the reserved ownership-message namespace; unrelated annotations are
/// unchanged. Parsing establishes syntax only. Consumers must validate the
/// pending source, destination generation/region, and prior ticket linkage.
pub(crate) fn decode_obligation_handoff(
    event: &TraceEvent,
) -> Result<Option<ObligationHandoff>, String> {
    let TraceData::Message(message) = &event.data else {
        return Ok(None);
    };
    if !message.starts_with("obligation_handoff_v") {
        return Ok(None);
    }
    if event.kind != TraceEventKind::UserTrace || event.version != TRACE_EVENT_SCHEMA_VERSION {
        return Err("handoff requires the supported UserTrace envelope".to_owned());
    }
    if message.len() > MAX_OBLIGATION_HANDOFF_MESSAGE_BYTES {
        return Err("handoff message exceeds 2048 bytes".to_owned());
    }
    let payload = message
        .strip_prefix(OBLIGATION_HANDOFF_PREFIX)
        .ok_or_else(|| "unsupported handoff message version".to_owned())?;
    let handoff: ObligationHandoff = serde_json::from_str(payload)
        .map_err(|error| format!("invalid handoff fields: {error}"))?;
    if handoff.source_holder == handoff.destination_holder {
        return Err("handoff requires distinct holder generations".to_owned());
    }
    if handoff.destination_ticket <= handoff.source_ticket {
        return Err("handoff destination ticket must follow its source ticket".to_owned());
    }
    Ok(Some(handoff))
}

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
    /// A spawn request was enqueued onto the spawn mailbox (pre-admission).
    TaskSpawnEnqueued,
    /// A mailbox spawn request was admitted into its region (task created).
    TaskAdmitted,
    /// A server request region installed its request budget (per-request
    /// deadline / poll / cost quota minted at the runtime boundary).
    BudgetInstalled,
    /// A server request region's budget was consumed/resolved (the request
    /// finished on some path, including the force-closed backstop).
    BudgetConsumed,
}

impl TraceEventKind {
    /// Canonical list of all trace event kinds.
    ///
    /// Keep this list in sync with the enum definition and
    /// `docs/spork_deterministic_ordering.md` taxonomy section.
    pub const ALL: [Self; 45] = [
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
        Self::TaskSpawnEnqueued,
        Self::TaskAdmitted,
        Self::BudgetInstalled,
        Self::BudgetConsumed,
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
            Self::TaskSpawnEnqueued => "task_spawn_enqueued",
            Self::TaskAdmitted => "task_admitted",
            Self::BudgetInstalled => "budget_installed",
            Self::BudgetConsumed => "budget_consumed",
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
            | Self::Complete
            | Self::TaskSpawnEnqueued
            | Self::TaskAdmitted => "task, region",
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
            Self::BudgetInstalled => {
                "task, region, protocol, deadline_ns, poll_quota, cost_quota, priority, source"
            }
            Self::BudgetConsumed => "task, region, protocol, deadline_ns, elapsed_ns, outcome",
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
        | TraceEventKind::FuturelockDetected
        | TraceEventKind::TaskSpawnEnqueued
        | TraceEventKind::TaskAdmitted
        | TraceEventKind::BudgetInstalled
        | TraceEventKind::BudgetConsumed => BrowserTraceCategory::Scheduler,
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
    sort_and_dedup_strings(&mut fields);
    fields
}

fn sort_and_dedup_strings(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
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
            sort_and_dedup_strings(&mut redacted_fields);
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
        sort_and_dedup_strings(&mut required_fields);

        let mut redacted_fields = legacy
            .redacted_fields
            .unwrap_or_else(|| redacted_fields_for_kind(kind));
        sort_and_dedup_strings(&mut redacted_fields);

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
///
/// br-asupersync-92qzak: pre-fix this function only redacted
/// `UserTrace::Message` and `ChaosInjection::Chaos.detail`, leaving
/// every other TraceData variant's free-form String fields
/// (Cancel.reason.message, RegionCancel.reason.message,
/// Worker.worker_id, Down.reason / Exit.reason payload strings)
/// unredacted. Production browser-trace exporters that bypass this
/// function entirely (the only caller in the repo was a single test)
/// shipped raw events to less-trusted destinations — sensitive
/// strings (CancelReasons containing stack-frame paths or user
/// tags, IoError payloads, panic payloads) leaked to whatever
/// collector the browser surface forwarded to.
///
/// The post-fix function is EXHAUSTIVE — `match` over every
/// TraceData variant with NO `_ =>` fallthrough — so any future
/// variant addition is a compile error until the redactor declares
/// its policy. Variants carrying potentially sensitive String
/// fields (Cancel, RegionCancel, Worker, Down, Exit) have their
/// strings rewritten to `"<redacted>"` while structural fields
/// (TaskId, RegionId, sequence numbers) are preserved so causality
/// can still be reconstructed by browser-side debug tooling.
/// The reserved handoff message schema contains only structural IDs and
/// tickets, which are preserved after strict decoding; malformed reserved
/// messages become a fixed invalid marker without their original payload.
#[must_use]
pub fn redact_browser_trace_event(event: &TraceEvent) -> TraceEvent {
    let mut redacted = event.clone();
    redacted.data = match decode_obligation_handoff(event) {
        // This strict schema contains structural IDs/tickets only, just like
        // the structural fields retained in an Obligation event below.
        Ok(Some(handoff)) => TraceData::Message(handoff.to_message()),
        // Never turn malformed ownership into a harmless annotation. Retain
        // a fixed invalid marker without exposing its untrusted payload.
        Err(_) => TraceData::Message("obligation_handoff_v1 <redacted-invalid>".to_owned()),
        Ok(None) => redact_browser_trace_data(&event.data),
    };
    redacted
}

/// br-asupersync-92qzak: variant-exhaustive redactor for TraceData.
/// Returns a copy with every free-form String field replaced by
/// `"<redacted>"` (or the equivalent in nested types). Structural
/// identifiers (TaskId, RegionId, ObligationId, u64 sequence
/// numbers, ObligationKind, ObligationState, ObligationAbortReason,
/// CancelKind enum variant, ErrorKind discriminants) are preserved
/// so causality and lifecycle reconstruction stay possible
/// browser-side without leaking the message payloads.
///
/// The match has NO `_ => {}` fallthrough: every variant must
/// declare its redaction policy explicitly so the next addition
/// to TraceData is a compile-time prompt to think about
/// confidentiality.
fn redact_browser_trace_data(data: &TraceData) -> TraceData {
    match data {
        TraceData::None => TraceData::None,
        TraceData::Task { task, region } => TraceData::Task {
            task: *task,
            region: *region,
        },
        TraceData::Region { region, parent } => TraceData::Region {
            region: *region,
            parent: *parent,
        },
        TraceData::Obligation {
            obligation,
            task,
            region,
            kind,
            state,
            duration_ns,
            abort_reason,
        } => TraceData::Obligation {
            obligation: *obligation,
            task: *task,
            region: *region,
            kind: *kind,
            state: *state,
            duration_ns: *duration_ns,
            abort_reason: *abort_reason,
        },
        TraceData::Cancel {
            task,
            region,
            reason,
        } => TraceData::Cancel {
            task: *task,
            region: *region,
            reason: redact_cancel_reason(reason),
        },
        TraceData::Worker {
            worker_id: _,
            job_id,
            decision_seq,
            replay_hash,
            task,
            region,
            obligation,
        } => TraceData::Worker {
            worker_id: "<redacted>".to_string(),
            job_id: *job_id,
            decision_seq: *decision_seq,
            replay_hash: *replay_hash,
            task: *task,
            region: *region,
            obligation: *obligation,
        },
        TraceData::RegionCancel { region, reason } => TraceData::RegionCancel {
            region: *region,
            reason: redact_cancel_reason(reason),
        },
        TraceData::Time { old, new } => TraceData::Time {
            old: *old,
            new: *new,
        },
        TraceData::Timer { timer_id, deadline } => TraceData::Timer {
            timer_id: *timer_id,
            deadline: *deadline,
        },
        TraceData::IoRequested { token, interest } => TraceData::IoRequested {
            token: *token,
            interest: *interest,
        },
        TraceData::IoReady { token, readiness } => TraceData::IoReady {
            token: *token,
            readiness: *readiness,
        },
        TraceData::IoResult { token, bytes } => TraceData::IoResult {
            token: *token,
            bytes: *bytes,
        },
        TraceData::IoError { token, kind } => TraceData::IoError {
            token: *token,
            kind: *kind,
        },
        TraceData::RngSeed { seed } => TraceData::RngSeed { seed: *seed },
        TraceData::RngValue { value } => TraceData::RngValue { value: *value },
        TraceData::Checkpoint {
            sequence,
            active_tasks,
            active_regions,
        } => TraceData::Checkpoint {
            sequence: *sequence,
            active_tasks: *active_tasks,
            active_regions: *active_regions,
        },
        TraceData::Futurelock {
            task,
            region,
            idle_steps,
            held,
        } => TraceData::Futurelock {
            task: *task,
            region: *region,
            idle_steps: *idle_steps,
            held: held.clone(),
        },
        TraceData::Monitor {
            monitor_ref,
            watcher,
            watcher_region,
            monitored,
        } => TraceData::Monitor {
            monitor_ref: *monitor_ref,
            watcher: *watcher,
            watcher_region: *watcher_region,
            monitored: *monitored,
        },
        TraceData::Down {
            monitor_ref,
            watcher,
            monitored,
            completion_vt,
            reason,
        } => TraceData::Down {
            monitor_ref: *monitor_ref,
            watcher: *watcher,
            monitored: *monitored,
            completion_vt: *completion_vt,
            reason: redact_down_reason(reason),
        },
        TraceData::Link {
            link_ref,
            task_a,
            region_a,
            task_b,
            region_b,
        } => TraceData::Link {
            link_ref: *link_ref,
            task_a: *task_a,
            region_a: *region_a,
            task_b: *task_b,
            region_b: *region_b,
        },
        TraceData::Exit {
            link_ref,
            from,
            to,
            failure_vt,
            reason,
        } => TraceData::Exit {
            link_ref: *link_ref,
            from: *from,
            to: *to,
            failure_vt: *failure_vt,
            reason: redact_down_reason(reason),
        },
        TraceData::Message(_) => TraceData::Message("<redacted>".to_string()),
        TraceData::Chaos {
            kind,
            task,
            detail: _,
        } => TraceData::Chaos {
            kind: kind.clone(),
            task: *task,
            detail: "<redacted>".to_string(),
        },
        // Budget payloads are task/region ids, budget quotas, and stable
        // source/outcome tokens — no free-form/user data to redact.
        TraceData::Budget {
            task,
            region,
            protocol,
            deadline_ns,
            poll_quota,
            cost_quota,
            priority,
            source,
            elapsed_ns,
            outcome,
        } => TraceData::Budget {
            task: *task,
            region: *region,
            protocol: protocol.clone(),
            deadline_ns: *deadline_ns,
            poll_quota: *poll_quota,
            cost_quota: *cost_quota,
            priority: *priority,
            source: source.clone(),
            elapsed_ns: *elapsed_ns,
            outcome: outcome.clone(),
        },
    }
}

/// Replace any free-form payload inside a CancelReason with a fixed
/// sentinel; preserve the kind enum (which is finite and non-secret).
fn redact_cancel_reason(reason: &CancelReason) -> CancelReason {
    let mut redacted = reason.clone();
    if redacted.message.is_some() {
        redacted.message = Some("<redacted>".to_string());
    }
    redacted
}

/// Replace free-form String fields inside a DownReason with sentinels.
/// `Normal` carries no payload; `Error(String)`, `Cancelled(CancelReason)`,
/// and `Panicked(PanicPayload)` all do.
fn redact_down_reason(reason: &DownReason) -> DownReason {
    match reason {
        DownReason::Normal => DownReason::Normal,
        DownReason::Error(_) => DownReason::Error("<redacted>".to_string()),
        DownReason::Cancelled(cr) => DownReason::Cancelled(redact_cancel_reason(cr)),
        DownReason::Panicked(payload) => DownReason::Panicked(redact_panic_payload(payload)),
    }
}

/// Replace any String inside a PanicPayload with the redaction
/// sentinel. PanicPayload's message field is private, so we
/// construct a fresh payload via the public constructor.
fn redact_panic_payload(_payload: &PanicPayload) -> PanicPayload {
    PanicPayload::new("<redacted>")
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
        TraceData::Budget {
            task,
            region,
            protocol,
            deadline_ns,
            poll_quota,
            cost_quota,
            priority,
            source,
            elapsed_ns,
            outcome,
        } => {
            fields.insert("task".to_string(), task.to_string());
            fields.insert("region".to_string(), region.to_string());
            fields.insert("protocol".to_string(), protocol.clone());
            fields.insert(
                "deadline_ns".to_string(),
                optional_display_field(*deadline_ns),
            );
            fields.insert("poll_quota".to_string(), poll_quota.to_string());
            fields.insert(
                "cost_quota".to_string(),
                optional_display_field(*cost_quota),
            );
            fields.insert("priority".to_string(), priority.to_string());
            if let Some(source) = source {
                fields.insert("source".to_string(), source.clone());
            }
            if let Some(elapsed_ns) = elapsed_ns {
                fields.insert("elapsed_ns".to_string(), elapsed_ns.to_string());
            }
            if let Some(outcome) = outcome {
                fields.insert("outcome".to_string(), outcome.clone());
            }
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
        | TraceData::Futurelock { task, .. }
        | TraceData::Budget { task, .. } => format!("task:{task}"),
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
    // br-asupersync-92qzak: every public browser-trace export now
    // routes through the redactor before any payload-field
    // serialization. Pre-fix this function read event.data verbatim,
    // bypassing redact_browser_trace_event entirely (the redactor
    // had only a single test caller). Post-fix the redacted variant
    // is the *only* event passed to insert_browser_trace_payload_fields,
    // so any free-form String inside event.data (cancel reasons,
    // worker IDs, panic payloads, error strings) lands as
    // `<redacted>` in the exported log fields.
    let event = &redact_browser_trace_event(event);
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Server request-region budget data for [`TraceEventKind::BudgetInstalled`]
    /// and [`TraceEventKind::BudgetConsumed`].
    Budget {
        /// The request task.
        task: TaskId,
        /// The request region.
        region: RegionId,
        /// Transport protocol token (e.g. `h1`, `h2`, `grpc`).
        protocol: String,
        /// Budget deadline in nanoseconds, if any.
        deadline_ns: Option<u64>,
        /// Poll quota.
        poll_quota: u64,
        /// Cost quota, if any.
        cost_quota: Option<u64>,
        /// Scheduling priority.
        priority: u8,
        /// Budget source token (install events; `None` for consume).
        source: Option<String>,
        /// Elapsed nanoseconds at consumption (`None` for install).
        elapsed_ns: Option<u64>,
        /// Outcome token at consumption (`None` for install): one of
        /// `ok`/`err`/`cancelled`/`panicked`/`deadline_exceeded`/
        /// `connection_lost`/`force_closed`.
        outcome: Option<String>,
    },
}

/// A trace event in the runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

macro_rules! trace_event_constructors {
    ($(
        $(#[$meta:meta])*
        $name:ident($($arg:ident: $ty:ty),* $(,)?) => $kind:ident, $data:expr;
    )*) => {
        $(
            $(#[$meta])*
            #[must_use]
            pub fn $name(seq: u64, time: Time, $($arg: $ty),*) -> Self {
                Self::new(seq, time, TraceEventKind::$kind, $data)
            }
        )*
    };
}

macro_rules! worker_lifecycle_constructors {
    ($(
        $(#[$meta:meta])*
        $name:ident => $kind:ident;
    )*) => {
        $(
            $(#[$meta])*
            #[allow(clippy::too_many_arguments)]
            #[must_use]
            pub fn $name(
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
                    TraceEventKind::$kind,
                    worker_id,
                    job_id,
                    decision_seq,
                    replay_hash,
                    task,
                    region,
                    obligation,
                )
            }
        )*
    };
}

impl TraceEvent {
    /// Record an actual ownership projection without extending the public
    /// exhaustive event enums or changing the outer wire schema.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn obligation_handoff(seq: u64, time: Time, handoff: &ObligationHandoff) -> Self {
        Self::user_trace(seq, time, handoff.to_message())
    }

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

    trace_event_constructors! {
        /// Creates a spawn event.
        spawn(task: TaskId, region: RegionId) => Spawn, TraceData::Task { task, region };
        /// Creates a schedule event.
        schedule(task: TaskId, region: RegionId) => Schedule, TraceData::Task { task, region };
        /// Creates a yield event.
        yield_task(task: TaskId, region: RegionId) => Yield, TraceData::Task { task, region };
        /// Creates a wake event.
        wake(task: TaskId, region: RegionId) => Wake, TraceData::Task { task, region };
        /// Creates a poll event.
        poll(task: TaskId, region: RegionId) => Poll, TraceData::Task { task, region };
        /// Creates a complete event.
        complete(task: TaskId, region: RegionId) => Complete, TraceData::Task { task, region };
        /// Creates a task-spawn-enqueued event (spawn-mailbox intake, pre-admission).
        task_spawn_enqueued(task: TaskId, region: RegionId) => TaskSpawnEnqueued,
            TraceData::Task { task, region };
        /// Creates a task-admitted event (spawn-mailbox admission; task carries the
        /// canonical arena id, pairing with the enqueue event by per-region FIFO order).
        task_admitted(task: TaskId, region: RegionId) => TaskAdmitted,
            TraceData::Task { task, region };
        /// Creates a cancel request event.
        cancel_request(task: TaskId, region: RegionId, reason: CancelReason) => CancelRequest,
            TraceData::Cancel { task, region, reason };
    }

    /// Creates a server-budget-installed event (per-request budget minted at the
    /// runtime boundary).
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn budget_installed(
        seq: u64,
        time: Time,
        task: TaskId,
        region: RegionId,
        protocol: impl Into<String>,
        deadline_ns: Option<u64>,
        poll_quota: u64,
        cost_quota: Option<u64>,
        priority: u8,
        source: impl Into<String>,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::BudgetInstalled,
            TraceData::Budget {
                task,
                region,
                protocol: protocol.into(),
                deadline_ns,
                poll_quota,
                cost_quota,
                priority,
                source: Some(source.into()),
                elapsed_ns: None,
                outcome: None,
            },
        )
    }

    /// Creates a server-budget-consumed event (request resolved on some path,
    /// including the force-closed Drop backstop).
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn budget_consumed(
        seq: u64,
        time: Time,
        task: TaskId,
        region: RegionId,
        protocol: impl Into<String>,
        deadline_ns: Option<u64>,
        poll_quota: u64,
        cost_quota: Option<u64>,
        priority: u8,
        elapsed_ns: Option<u64>,
        outcome: impl Into<String>,
    ) -> Self {
        Self::new(
            seq,
            time,
            TraceEventKind::BudgetConsumed,
            TraceData::Budget {
                task,
                region,
                protocol: protocol.into(),
                deadline_ns,
                poll_quota,
                cost_quota,
                priority,
                source: None,
                elapsed_ns,
                outcome: Some(outcome.into()),
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

    worker_lifecycle_constructors! {
        /// Creates a worker-offload cancel-requested event.
        worker_cancel_requested => WorkerCancelRequested;
        /// Creates a worker-offload cancel-acknowledged event.
        worker_cancel_acknowledged => WorkerCancelAcknowledged;
        /// Creates a worker-offload drain-started event.
        worker_drain_started => WorkerDrainStarted;
        /// Creates a worker-offload drain-completed event.
        worker_drain_completed => WorkerDrainCompleted;
        /// Creates a worker-offload finalize-completed event.
        worker_finalize_completed => WorkerFinalizeCompleted;
    }

    trace_event_constructors! {
        /// Creates a region created event.
        region_created(region: RegionId, parent: Option<RegionId>) => RegionCreated,
            TraceData::Region { region, parent };
        /// Creates a region cancelled event.
        region_cancelled(region: RegionId, reason: CancelReason) => RegionCancelled,
            TraceData::RegionCancel { region, reason };
        /// Creates a time advance event.
        time_advance(old: Time, new: Time) => TimeAdvance, TraceData::Time { old, new };
        /// Creates a timer scheduled event.
        timer_scheduled(timer_id: u64, deadline: Time) => TimerScheduled,
            TraceData::Timer { timer_id, deadline: Some(deadline) };
        /// Creates a timer fired event.
        timer_fired(timer_id: u64) => TimerFired, TraceData::Timer { timer_id, deadline: None };
        /// Creates a timer cancelled event.
        timer_cancelled(timer_id: u64) => TimerCancelled,
            TraceData::Timer { timer_id, deadline: None };
        /// Creates an I/O requested event.
        io_requested(token: u64, interest: u8) => IoRequested,
            TraceData::IoRequested { token, interest };
        /// Creates an I/O ready event.
        io_ready(token: u64, readiness: u8) => IoReady, TraceData::IoReady { token, readiness };
        /// Creates an I/O result event.
        io_result(token: u64, bytes: i64) => IoResult, TraceData::IoResult { token, bytes };
        /// Creates an I/O error event.
        io_error(token: u64, kind: u8) => IoError, TraceData::IoError { token, kind };
        /// Creates an RNG seed event.
        rng_seed(seed: u64) => RngSeed, TraceData::RngSeed { seed };
        /// Creates an RNG value event.
        rng_value(value: u64) => RngValue, TraceData::RngValue { value };
        /// Creates a checkpoint event.
        checkpoint(sequence: u64, active_tasks: u32, active_regions: u32) => Checkpoint,
            TraceData::Checkpoint { sequence, active_tasks, active_regions };
        /// Creates an obligation reserve event.
        obligation_reserve(
            obligation: ObligationId,
            task: TaskId,
            region: RegionId,
            kind: ObligationKind,
        ) => ObligationReserve,
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state: ObligationState::Reserved,
                duration_ns: None,
                abort_reason: None,
            };
        /// Creates an obligation commit event.
        obligation_commit(
            obligation: ObligationId,
            task: TaskId,
            region: RegionId,
            kind: ObligationKind,
            duration_ns: u64,
        ) => ObligationCommit,
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state: ObligationState::Committed,
                duration_ns: Some(duration_ns),
                abort_reason: None,
            };
        /// Creates an obligation abort event.
        #[allow(clippy::too_many_arguments)]
        obligation_abort(
            obligation: ObligationId,
            task: TaskId,
            region: RegionId,
            kind: ObligationKind,
            duration_ns: u64,
            reason: ObligationAbortReason,
        ) => ObligationAbort,
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state: ObligationState::Aborted,
                duration_ns: Some(duration_ns),
                abort_reason: Some(reason),
            };
        /// Creates an obligation leak event.
        obligation_leak(
            obligation: ObligationId,
            task: TaskId,
            region: RegionId,
            kind: ObligationKind,
            duration_ns: u64,
        ) => ObligationLeak,
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state: ObligationState::Leaked,
                duration_ns: Some(duration_ns),
                abort_reason: None,
            };
        /// Creates a monitor created event.
        monitor_created(
            monitor_ref: u64,
            watcher: TaskId,
            watcher_region: RegionId,
            monitored: TaskId,
        ) => MonitorCreated,
            TraceData::Monitor { monitor_ref, watcher, watcher_region, monitored };
        /// Creates a monitor dropped event.
        monitor_dropped(
            monitor_ref: u64,
            watcher: TaskId,
            watcher_region: RegionId,
            monitored: TaskId,
        ) => MonitorDropped,
            TraceData::Monitor { monitor_ref, watcher, watcher_region, monitored };
        /// Creates a down delivered event.
        down_delivered(
            monitor_ref: u64,
            watcher: TaskId,
            monitored: TaskId,
            completion_vt: Time,
            reason: DownReason,
        ) => DownDelivered,
            TraceData::Down { monitor_ref, watcher, monitored, completion_vt, reason };
        /// Creates a link created event.
        link_created(
            link_ref: u64,
            task_a: TaskId,
            region_a: RegionId,
            task_b: TaskId,
            region_b: RegionId,
        ) => LinkCreated,
            TraceData::Link { link_ref, task_a, region_a, task_b, region_b };
        /// Creates a link dropped event.
        link_dropped(
            link_ref: u64,
            task_a: TaskId,
            region_a: RegionId,
            task_b: TaskId,
            region_b: RegionId,
        ) => LinkDropped,
            TraceData::Link { link_ref, task_a, region_a, task_b, region_b };
        /// Creates an exit delivered event.
        exit_delivered(link_ref: u64, from: TaskId, to: TaskId, failure_vt: Time, reason: DownReason)
            => ExitDelivered, TraceData::Exit { link_ref, from, to, failure_vt, reason };
        /// Creates a user trace event.
        user_trace(message: impl Into<String>) => UserTrace, TraceData::Message(message.into());
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
            TraceData::Budget {
                task,
                region,
                protocol,
                outcome,
                ..
            } => {
                write!(f, " {task} in {region} [{protocol}]")?;
                if let Some(outcome) = outcome {
                    write!(f, " outcome={outcome}")?;
                }
            }
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
#[path = "event_inline_tests.rs"]
mod tests;
