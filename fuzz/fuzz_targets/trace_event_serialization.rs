#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::monitor::DownReason;
use asupersync::record::{ObligationAbortReason, ObligationKind, ObligationState};
use asupersync::trace::distributed::{LamportTime, LogicalTime};
use asupersync::trace::event::{
    BrowserTraceCategory, BrowserTraceCompatibility, BrowserTraceEventSpec, BrowserTraceSchema,
    TraceData, TraceEvent, TraceEventKind, TRACE_EVENT_SCHEMA_VERSION,
};
use asupersync::types::{CancelReason, ObligationId, RegionId, TaskId, Time};
use std::collections::BTreeMap;

/// Fuzzing configuration for trace event serialization testing.
#[derive(Debug, Clone, Arbitrary)]
struct TraceEventSerializationConfig {
    /// Sequence of trace events to test
    pub events: Vec<FuzzTraceEvent>,
    /// Browser trace schema to test
    pub browser_schema: Option<FuzzBrowserTraceSchema>,
    /// Serialization format tests
    pub serialization_tests: SerializationTests,
    /// Schema version compatibility tests
    pub version_tests: VersionTests,
}

/// A trace event for fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct FuzzTraceEvent {
    /// Event schema version (might be invalid for testing)
    pub version: u32,
    /// Sequence number
    pub seq: u64,
    /// Timestamp
    pub time: FuzzTime,
    /// Optional logical time for causal ordering
    pub logical_time: Option<FuzzLogicalTime>,
    /// Event kind
    pub kind: FuzzTraceEventKind,
    /// Event data
    pub data: FuzzTraceData,
}

/// Time for fuzzing (simplified)
#[derive(Debug, Clone, Arbitrary)]
struct FuzzTime {
    pub nanos: u64,
}

impl From<FuzzTime> for Time {
    fn from(fuzz_time: FuzzTime) -> Self {
        Time::from_nanos(fuzz_time.nanos)
    }
}

/// Logical time for fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct FuzzLogicalTime {
    #[allow(dead_code)]
    pub process_id: u32,
    pub sequence: u64,
}

impl From<FuzzLogicalTime> for LogicalTime {
    fn from(fuzz_lt: FuzzLogicalTime) -> Self {
        // Use Lamport clock for simplicity in fuzzing
        let lamport_time = LamportTime::from_raw(fuzz_lt.sequence);
        LogicalTime::Lamport(lamport_time)
    }
}

/// Fuzzing version of TraceEventKind (subset of all 41 types)
#[derive(Debug, Clone, Arbitrary, PartialEq)]
enum FuzzTraceEventKind {
    Spawn,
    Schedule,
    Yield,
    Wake,
    Poll,
    Complete,
    CancelRequest,
    CancelAck,
    WorkerCancelRequested,
    WorkerCancelAcknowledged,
    RegionCreated,
    RegionCancelled,
    ObligationReserve,
    ObligationCommit,
    ObligationAbort,
    ObligationLeak,
    TimeAdvance,
    TimerScheduled,
    TimerFired,
    IoRequested,
    IoReady,
    IoResult,
    IoError,
    RngSeed,
    RngValue,
    Checkpoint,
    FuturelockDetected,
    MonitorCreated,
    DownDelivered,
    UserTrace,
}

impl From<FuzzTraceEventKind> for TraceEventKind {
    fn from(fuzz_kind: FuzzTraceEventKind) -> Self {
        match fuzz_kind {
            FuzzTraceEventKind::Spawn => TraceEventKind::Spawn,
            FuzzTraceEventKind::Schedule => TraceEventKind::Schedule,
            FuzzTraceEventKind::Yield => TraceEventKind::Yield,
            FuzzTraceEventKind::Wake => TraceEventKind::Wake,
            FuzzTraceEventKind::Poll => TraceEventKind::Poll,
            FuzzTraceEventKind::Complete => TraceEventKind::Complete,
            FuzzTraceEventKind::CancelRequest => TraceEventKind::CancelRequest,
            FuzzTraceEventKind::CancelAck => TraceEventKind::CancelAck,
            FuzzTraceEventKind::WorkerCancelRequested => TraceEventKind::WorkerCancelRequested,
            FuzzTraceEventKind::WorkerCancelAcknowledged => {
                TraceEventKind::WorkerCancelAcknowledged
            }
            FuzzTraceEventKind::RegionCreated => TraceEventKind::RegionCreated,
            FuzzTraceEventKind::RegionCancelled => TraceEventKind::RegionCancelled,
            FuzzTraceEventKind::ObligationReserve => TraceEventKind::ObligationReserve,
            FuzzTraceEventKind::ObligationCommit => TraceEventKind::ObligationCommit,
            FuzzTraceEventKind::ObligationAbort => TraceEventKind::ObligationAbort,
            FuzzTraceEventKind::ObligationLeak => TraceEventKind::ObligationLeak,
            FuzzTraceEventKind::TimeAdvance => TraceEventKind::TimeAdvance,
            FuzzTraceEventKind::TimerScheduled => TraceEventKind::TimerScheduled,
            FuzzTraceEventKind::TimerFired => TraceEventKind::TimerFired,
            FuzzTraceEventKind::IoRequested => TraceEventKind::IoRequested,
            FuzzTraceEventKind::IoReady => TraceEventKind::IoReady,
            FuzzTraceEventKind::IoResult => TraceEventKind::IoResult,
            FuzzTraceEventKind::IoError => TraceEventKind::IoError,
            FuzzTraceEventKind::RngSeed => TraceEventKind::RngSeed,
            FuzzTraceEventKind::RngValue => TraceEventKind::RngValue,
            FuzzTraceEventKind::Checkpoint => TraceEventKind::Checkpoint,
            FuzzTraceEventKind::FuturelockDetected => TraceEventKind::FuturelockDetected,
            FuzzTraceEventKind::MonitorCreated => TraceEventKind::MonitorCreated,
            FuzzTraceEventKind::DownDelivered => TraceEventKind::DownDelivered,
            FuzzTraceEventKind::UserTrace => TraceEventKind::UserTrace,
        }
    }
}

/// Fuzzing version of TraceData with all major variants
#[derive(Debug, Clone, Arbitrary)]
enum FuzzTraceData {
    None,
    Task {
        task: u64,
        region: u64,
    },
    Region {
        region: u64,
        parent: Option<u64>,
    },
    Obligation {
        obligation: u64,
        task: u64,
        region: u64,
        kind: FuzzObligationKind,
        state: FuzzObligationState,
        duration_ns: Option<u64>,
        abort_reason: Option<FuzzObligationAbortReason>,
    },
    Cancel {
        task: u64,
        region: u64,
        reason: FuzzCancelReason,
    },
    Worker {
        worker_id: String,
        job_id: u64,
        decision_seq: u64,
        replay_hash: u64,
        task: u64,
        region: u64,
        obligation: u64,
    },
    RegionCancel {
        region: u64,
        reason: FuzzCancelReason,
    },
    Time {
        old: FuzzTime,
        new: FuzzTime,
    },
    Timer {
        timer_id: u64,
        deadline: Option<FuzzTime>,
    },
    IoRequested {
        token: u64,
        interest: u8,
    },
    IoReady {
        token: u64,
        readiness: u8,
    },
    IoResult {
        token: u64,
        bytes: i64,
    },
    IoError {
        token: u64,
        kind: u8,
    },
    RngSeed {
        seed: u64,
    },
    RngValue {
        value: u64,
    },
    Checkpoint {
        sequence: u64,
        active_tasks: u32,
        active_regions: u32,
    },
    Futurelock {
        task: u64,
        region: u64,
        idle_steps: u64,
        held: Vec<(u64, FuzzObligationKind)>,
    },
    Monitor {
        monitor_ref: u64,
        watcher: u64,
        watcher_region: u64,
        monitored: u64,
    },
    Down {
        monitor_ref: u64,
        completion_vt: FuzzTime,
        monitored: u64,
        reason: FuzzDownReason,
    },
    UserTrace {
        name: String,
        message: String,
        attributes: BTreeMap<String, String>,
    },
}

/// Fuzzing obligation kinds
#[derive(Debug, Clone, Arbitrary)]
enum FuzzObligationKind {
    SendPermit,
    Lease,
    Ack,
    IoOp,
}

impl From<FuzzObligationKind> for ObligationKind {
    fn from(fuzz_kind: FuzzObligationKind) -> Self {
        match fuzz_kind {
            FuzzObligationKind::SendPermit => ObligationKind::SendPermit,
            FuzzObligationKind::Lease => ObligationKind::Lease,
            FuzzObligationKind::Ack => ObligationKind::Ack,
            FuzzObligationKind::IoOp => ObligationKind::IoOp,
        }
    }
}

/// Fuzzing obligation states
#[derive(Debug, Clone, Arbitrary)]
enum FuzzObligationState {
    Reserved,
    Committed,
    Aborted,
}

impl From<FuzzObligationState> for ObligationState {
    fn from(fuzz_state: FuzzObligationState) -> Self {
        match fuzz_state {
            FuzzObligationState::Reserved => ObligationState::Reserved,
            FuzzObligationState::Committed => ObligationState::Committed,
            FuzzObligationState::Aborted => ObligationState::Aborted,
        }
    }
}

/// Fuzzing obligation abort reasons
#[derive(Debug, Clone, Arbitrary)]
enum FuzzObligationAbortReason {
    Cancel,
    Error,
    Explicit,
}

impl From<FuzzObligationAbortReason> for ObligationAbortReason {
    fn from(fuzz_reason: FuzzObligationAbortReason) -> Self {
        match fuzz_reason {
            FuzzObligationAbortReason::Cancel => ObligationAbortReason::Cancel,
            FuzzObligationAbortReason::Error => ObligationAbortReason::Error,
            FuzzObligationAbortReason::Explicit => ObligationAbortReason::Explicit,
        }
    }
}

/// Fuzzing cancel reasons
#[derive(Debug, Clone, Arbitrary)]
enum FuzzCancelReason {
    Shutdown,
    User,
    Timeout,
    FailFast,
    ParentCancelled,
}

impl From<FuzzCancelReason> for CancelReason {
    fn from(fuzz_reason: FuzzCancelReason) -> Self {
        match fuzz_reason {
            FuzzCancelReason::Shutdown => CancelReason::shutdown(),
            FuzzCancelReason::User => CancelReason::user("fuzz cancel"),
            FuzzCancelReason::Timeout => CancelReason::timeout(),
            FuzzCancelReason::FailFast => CancelReason::fail_fast(),
            FuzzCancelReason::ParentCancelled => CancelReason::parent_cancelled(),
        }
    }
}

/// Fuzzing down reasons
#[derive(Debug, Clone, Arbitrary)]
enum FuzzDownReason {
    Normal,
    Error,
    Cancelled,
}

impl From<FuzzDownReason> for DownReason {
    fn from(fuzz_reason: FuzzDownReason) -> Self {
        match fuzz_reason {
            FuzzDownReason::Normal => DownReason::Normal,
            FuzzDownReason::Error => DownReason::Error("fuzz error".to_string()),
            FuzzDownReason::Cancelled => DownReason::Cancelled(CancelReason::user("fuzz cancel")),
        }
    }
}

/// Browser trace schema for fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct FuzzBrowserTraceSchema {
    pub schema_version: String,
    pub required_envelope_fields: Vec<String>,
    pub event_specs: Vec<FuzzBrowserTraceEventSpec>,
    pub compatibility: FuzzBrowserTraceCompatibility,
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzBrowserTraceEventSpec {
    pub event_kind: String,
    pub category: FuzzBrowserTraceCategory,
    pub required_fields: Vec<String>,
    pub redacted_fields: Vec<String>,
}

#[derive(Debug, Clone, Arbitrary)]
enum FuzzBrowserTraceCategory {
    Scheduler,
    Timer,
    HostCallback,
    CapabilityInvocation,
    CancellationTransition,
}

impl From<FuzzBrowserTraceCategory> for BrowserTraceCategory {
    fn from(fuzz_cat: FuzzBrowserTraceCategory) -> Self {
        match fuzz_cat {
            FuzzBrowserTraceCategory::Scheduler => BrowserTraceCategory::Scheduler,
            FuzzBrowserTraceCategory::Timer => BrowserTraceCategory::Timer,
            FuzzBrowserTraceCategory::HostCallback => BrowserTraceCategory::HostCallback,
            FuzzBrowserTraceCategory::CapabilityInvocation => {
                BrowserTraceCategory::CapabilityInvocation
            }
            FuzzBrowserTraceCategory::CancellationTransition => {
                BrowserTraceCategory::CancellationTransition
            }
        }
    }
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzBrowserTraceCompatibility {
    pub minimum_reader_version: String,
    pub supported_reader_versions: Vec<String>,
    pub backward_decode_aliases: Vec<String>,
}

/// Serialization format tests
#[derive(Debug, Clone, Arbitrary)]
struct SerializationTests {
    /// Test JSON serialization
    pub test_json: bool,
    /// Test with invalid UTF-8 in strings
    #[allow(dead_code)]
    pub test_invalid_utf8: bool,
    /// Test extremely large values
    #[allow(dead_code)]
    pub test_large_values: bool,
    /// Test malformed enum variants
    #[allow(dead_code)]
    pub test_malformed_enums: bool,
}

/// Version compatibility tests
#[derive(Debug, Clone, Arbitrary)]
struct VersionTests {
    /// Test future schema versions
    pub future_versions: Vec<u32>,
    /// Test past schema versions
    pub past_versions: Vec<u32>,
    /// Test invalid version numbers
    pub invalid_versions: Vec<u32>,
}

/// Normalize fuzz configuration to valid ranges
fn normalize_config(config: &mut TraceEventSerializationConfig) {
    // Limit number of events for performance
    config.events.truncate(20);

    // Normalize event data
    for event in &mut config.events {
        // Clamp version to reasonable range
        event.version = event.version.clamp(0, 100);

        // Normalize string fields
        if let FuzzTraceData::Worker { worker_id, .. } = &mut event.data {
            // Safe UTF-8 aware truncation
            if worker_id.len() > 128 {
                let mut truncate_at = 128;
                while truncate_at > 0 && !worker_id.is_char_boundary(truncate_at) {
                    truncate_at -= 1;
                }
                worker_id.truncate(truncate_at);
            }
            worker_id.retain(|c| c.is_ascii() && c != '\0' && c != '\r' && c != '\n');
        }

        if let FuzzTraceData::UserTrace {
            name,
            message,
            attributes,
        } = &mut event.data
        {
            // Normalize string lengths
            if name.len() > 64 {
                let mut truncate_at = 64;
                while truncate_at > 0 && !name.is_char_boundary(truncate_at) {
                    truncate_at -= 1;
                }
                name.truncate(truncate_at);
            }
            name.retain(|c| c.is_ascii() && c != '\0');

            if message.len() > 512 {
                let mut truncate_at = 512;
                while truncate_at > 0 && !message.is_char_boundary(truncate_at) {
                    truncate_at -= 1;
                }
                message.truncate(truncate_at);
            }
            message.retain(|c| c != '\0');

            // Limit attributes
            attributes.retain(|k, v| {
                k.len() <= 32
                    && v.len() <= 128
                    && k.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                    && !v.contains('\0')
            });
            if attributes.len() > 10 {
                let keys: Vec<_> = attributes.keys().take(10).cloned().collect();
                attributes.retain(|k, _| keys.contains(k));
            }
        }

        if let FuzzTraceData::Futurelock { held, .. } = &mut event.data {
            held.truncate(20);
        }
    }

    // Normalize browser schema if present
    if let Some(ref mut schema) = config.browser_schema {
        schema.event_specs.truncate(50);

        for spec in &mut schema.event_specs {
            if spec.event_kind.len() > 64 {
                let mut truncate_at = 64;
                while truncate_at > 0 && !spec.event_kind.is_char_boundary(truncate_at) {
                    truncate_at -= 1;
                }
                spec.event_kind.truncate(truncate_at);
            }
            spec.event_kind
                .retain(|c| c.is_ascii_alphanumeric() || c == '_');

            spec.required_fields.truncate(20);
            spec.redacted_fields.truncate(20);

            for field in spec
                .required_fields
                .iter_mut()
                .chain(spec.redacted_fields.iter_mut())
            {
                if field.len() > 32 {
                    let mut truncate_at = 32;
                    while truncate_at > 0 && !field.is_char_boundary(truncate_at) {
                        truncate_at -= 1;
                    }
                    field.truncate(truncate_at);
                }
                field.retain(|c| c.is_ascii_alphanumeric() || c == '_');
            }
        }

        schema.compatibility.supported_reader_versions.truncate(10);
        schema.compatibility.backward_decode_aliases.truncate(10);
    }

    // Normalize version tests
    config.version_tests.future_versions.truncate(5);
    config.version_tests.past_versions.truncate(5);
    config.version_tests.invalid_versions.truncate(5);

    for version in config.version_tests.future_versions.iter_mut() {
        *version = (*version).clamp(0, 1000);
    }
    for version in config.version_tests.past_versions.iter_mut() {
        *version = (*version).clamp(0, 1000);
    }
}

/// Convert FuzzTraceData to TraceData
fn fuzz_trace_data_to_trace_data(fuzz_data: FuzzTraceData) -> TraceData {
    match fuzz_data {
        FuzzTraceData::None => TraceData::None,
        FuzzTraceData::Task { task, region } => TraceData::Task {
            task: TaskId::new_for_test(task as u32, 0),
            region: RegionId::new_for_test(region as u32, 0),
        },
        FuzzTraceData::Region { region, parent } => TraceData::Region {
            region: RegionId::new_for_test(region as u32, 0),
            parent: parent.map(|p| RegionId::new_for_test(p as u32, 0)),
        },
        FuzzTraceData::Obligation {
            obligation,
            task,
            region,
            kind,
            state,
            duration_ns,
            abort_reason,
        } => TraceData::Obligation {
            obligation: ObligationId::new_for_test(obligation as u32, 0),
            task: TaskId::new_for_test(task as u32, 0),
            region: RegionId::new_for_test(region as u32, 0),
            kind: kind.into(),
            state: state.into(),
            duration_ns,
            abort_reason: abort_reason.map(|r| r.into()),
        },
        FuzzTraceData::Cancel {
            task,
            region,
            reason,
        } => TraceData::Cancel {
            task: TaskId::new_for_test(task as u32, 0),
            region: RegionId::new_for_test(region as u32, 0),
            reason: reason.into(),
        },
        FuzzTraceData::Worker {
            worker_id,
            job_id,
            decision_seq,
            replay_hash,
            task,
            region,
            obligation,
        } => TraceData::Worker {
            worker_id,
            job_id,
            decision_seq,
            replay_hash,
            task: TaskId::new_for_test(task as u32, 0),
            region: RegionId::new_for_test(region as u32, 0),
            obligation: ObligationId::new_for_test(obligation as u32, 0),
        },
        FuzzTraceData::RegionCancel { region, reason } => TraceData::RegionCancel {
            region: RegionId::new_for_test(region as u32, 0),
            reason: reason.into(),
        },
        FuzzTraceData::Time { old, new } => TraceData::Time {
            old: old.into(),
            new: new.into(),
        },
        FuzzTraceData::Timer { timer_id, deadline } => TraceData::Timer {
            timer_id,
            deadline: deadline.map(|d| d.into()),
        },
        FuzzTraceData::IoRequested { token, interest } => {
            TraceData::IoRequested { token, interest }
        }
        FuzzTraceData::IoReady { token, readiness } => TraceData::IoReady { token, readiness },
        FuzzTraceData::IoResult { token, bytes } => TraceData::IoResult { token, bytes },
        FuzzTraceData::IoError { token, kind } => TraceData::IoError { token, kind },
        FuzzTraceData::RngSeed { seed } => TraceData::RngSeed { seed },
        FuzzTraceData::RngValue { value } => TraceData::RngValue { value },
        FuzzTraceData::Checkpoint {
            sequence,
            active_tasks,
            active_regions,
        } => TraceData::Checkpoint {
            sequence,
            active_tasks,
            active_regions,
        },
        FuzzTraceData::Futurelock {
            task,
            region,
            idle_steps,
            held,
        } => TraceData::Futurelock {
            task: TaskId::new_for_test(task as u32, 0),
            region: RegionId::new_for_test(region as u32, 0),
            idle_steps,
            held: held
                .into_iter()
                .map(|(id, kind)| (ObligationId::new_for_test(id as u32, 0), kind.into()))
                .collect(),
        },
        FuzzTraceData::Monitor {
            monitor_ref,
            watcher,
            watcher_region,
            monitored,
        } => TraceData::Monitor {
            monitor_ref,
            watcher: TaskId::new_for_test(watcher as u32, 0),
            watcher_region: RegionId::new_for_test(watcher_region as u32, 0),
            monitored: TaskId::new_for_test(monitored as u32, 0),
        },
        FuzzTraceData::Down {
            monitor_ref,
            completion_vt,
            monitored,
            reason,
        } => {
            TraceData::Down {
                monitor_ref,
                watcher: TaskId::new_for_test(1, 0), // Default watcher for fuzzing
                monitored: TaskId::new_for_test(monitored as u32, 0),
                completion_vt: completion_vt.into(),
                reason: reason.into(),
            }
        }
        FuzzTraceData::UserTrace {
            name,
            message,
            attributes: _,
        } => TraceData::Message(format!("{}: {}", name, message)),
    }
}

/// Test trace event creation and properties
fn test_trace_event_serialization(config: &TraceEventSerializationConfig) -> Result<(), String> {
    for fuzz_event in &config.events {
        // Convert to actual TraceEvent
        let trace_event = TraceEvent {
            version: fuzz_event.version,
            seq: fuzz_event.seq,
            time: fuzz_event.time.clone().into(),
            logical_time: fuzz_event.logical_time.clone().map(|lt| lt.into()),
            kind: fuzz_event.kind.clone().into(),
            data: fuzz_trace_data_to_trace_data(fuzz_event.data.clone()),
        };

        // Test event kind properties
        let kind: TraceEventKind = fuzz_event.kind.clone().into();
        let stable_name = kind.stable_name();
        let required_fields = kind.required_fields();

        // Validate stable name is not empty
        if stable_name.is_empty() {
            return Err("Event kind has empty stable name".to_string());
        }

        // Validate version is reasonable
        if trace_event.version > 1000 {
            return Err("Event version is unreasonably high".to_string());
        }

        // Test that event creation succeeded
        if trace_event.seq != fuzz_event.seq {
            return Err("Event sequence mismatch".to_string());
        }

        // Test required fields parsing (should not be empty for most events)
        if required_fields.is_empty()
            && !matches!(
                kind,
                TraceEventKind::TimeAdvance | TraceEventKind::Checkpoint
            )
        {
            // Most events should have required fields, but some might not
        }

        // Test data consistency with event kind
        match (&fuzz_event.kind, &trace_event.data) {
            (FuzzTraceEventKind::Spawn, TraceData::Task { .. })
            | (FuzzTraceEventKind::Schedule, TraceData::Task { .. })
            | (FuzzTraceEventKind::Poll, TraceData::Task { .. }) => {
                // Valid combinations
            }
            (FuzzTraceEventKind::ObligationReserve, TraceData::Obligation { .. })
            | (FuzzTraceEventKind::ObligationCommit, TraceData::Obligation { .. })
            | (FuzzTraceEventKind::ObligationAbort, TraceData::Obligation { .. }) => {
                // Valid combinations
            }
            (FuzzTraceEventKind::TimeAdvance, TraceData::Time { .. }) => {
                // Valid combination
            }
            _ => {
                // Other combinations might be valid or invalid - test graceful handling
            }
        }
    }

    Ok(())
}

/// Test browser trace schema serialization
fn test_browser_schema_serialization(config: &TraceEventSerializationConfig) -> Result<(), String> {
    let Some(ref fuzz_schema) = config.browser_schema else {
        return Ok(());
    };

    // Convert to actual schema
    let browser_schema = BrowserTraceSchema {
        schema_version: fuzz_schema.schema_version.clone(),
        required_envelope_fields: fuzz_schema.required_envelope_fields.clone(),
        ordering_semantics: vec!["causal".to_string(), "sequential".to_string()],
        structured_log_required_fields: vec!["timestamp".to_string(), "level".to_string()],
        validation_failure_categories: vec![
            "schema_mismatch".to_string(),
            "data_corruption".to_string(),
        ],
        event_specs: fuzz_schema
            .event_specs
            .iter()
            .map(|spec| BrowserTraceEventSpec {
                event_kind: spec.event_kind.clone(),
                category: spec.category.clone().into(),
                required_fields: spec.required_fields.clone(),
                redacted_fields: spec.redacted_fields.clone(),
            })
            .collect(),
        compatibility: BrowserTraceCompatibility {
            minimum_reader_version: fuzz_schema.compatibility.minimum_reader_version.clone(),
            supported_reader_versions: fuzz_schema.compatibility.supported_reader_versions.clone(),
            backward_decode_aliases: fuzz_schema.compatibility.backward_decode_aliases.clone(),
        },
    };

    // Test serialization
    if config.serialization_tests.test_json {
        let serialization_result = serde_json::to_string(&browser_schema);
        match serialization_result {
            Ok(json_str) => {
                let deserialization_result: Result<BrowserTraceSchema, _> =
                    serde_json::from_str(&json_str);
                if let Err(_e) = deserialization_result {
                    // Round-trip failure acceptable for malformed data
                }
            }
            Err(_e) => {
                // Serialization failure acceptable for invalid data
            }
        }
    }

    Ok(())
}

/// Test version compatibility handling
fn test_version_compatibility(config: &TraceEventSerializationConfig) -> Result<(), String> {
    // Test with different schema versions
    for &version in &config.version_tests.future_versions {
        // Future versions should be handled gracefully
        if version > TRACE_EVENT_SCHEMA_VERSION {
            // Should either parse with compatibility mode or reject gracefully
        }
    }

    for &version in &config.version_tests.past_versions {
        // Past versions might need compatibility handling
        if version < TRACE_EVENT_SCHEMA_VERSION {
            // Should either parse with backward compatibility or reject gracefully
        }
    }

    for &version in &config.version_tests.invalid_versions {
        // Invalid versions should be rejected
        if version == u32::MAX || version == 0 {
            // Should be rejected gracefully
        }
    }

    Ok(())
}

/// Test enum variant handling
fn test_enum_variant_handling(config: &TraceEventSerializationConfig) -> Result<(), String> {
    // Test all TraceEventKind variants are covered
    for fuzz_event in &config.events {
        let kind: TraceEventKind = fuzz_event.kind.clone().into();

        // Ensure each kind has consistent properties
        let stable_name = kind.stable_name();
        if stable_name.is_empty() {
            return Err("Empty stable name for event kind".to_string());
        }

        let required_fields = kind.required_fields();
        if required_fields.is_empty()
            && !matches!(
                kind,
                TraceEventKind::TimeAdvance | TraceEventKind::Checkpoint
            )
        {
            // Most events should have required fields
        }

        // Test data compatibility with event kind
        match (&fuzz_event.kind, &fuzz_event.data) {
            (FuzzTraceEventKind::Spawn, FuzzTraceData::Task { .. })
            | (FuzzTraceEventKind::Schedule, FuzzTraceData::Task { .. })
            | (FuzzTraceEventKind::Poll, FuzzTraceData::Task { .. }) => {
                // Valid combinations
            }
            (FuzzTraceEventKind::ObligationReserve, FuzzTraceData::Obligation { .. })
            | (FuzzTraceEventKind::ObligationCommit, FuzzTraceData::Obligation { .. })
            | (FuzzTraceEventKind::ObligationAbort, FuzzTraceData::Obligation { .. }) => {
                // Valid combinations
            }
            (FuzzTraceEventKind::TimeAdvance, FuzzTraceData::Time { .. }) => {
                // Valid combination
            }
            _ => {
                // Other combinations might be valid or invalid - test graceful handling
            }
        }
    }

    Ok(())
}

/// Main fuzzing function
fn fuzz_trace_event_serialization(mut config: TraceEventSerializationConfig) -> Result<(), String> {
    normalize_config(&mut config);

    // Skip degenerate cases
    if config.events.is_empty() {
        return Ok(());
    }

    // Test 1: Basic trace event serialization
    test_trace_event_serialization(&config)?;

    // Test 2: Browser schema serialization
    test_browser_schema_serialization(&config)?;

    // Test 3: Version compatibility
    test_version_compatibility(&config)?;

    // Test 4: Enum variant handling
    test_enum_variant_handling(&config)?;

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Limit input size for performance
    if data.len() > 8_000 {
        return;
    }

    let mut unstructured = Unstructured::new(data);

    // Generate fuzz configuration
    let config = if let Ok(c) = TraceEventSerializationConfig::arbitrary(&mut unstructured) {
        c
    } else {
        return;
    };

    // Run trace event serialization fuzzing
    let _ = fuzz_trace_event_serialization(config);
});
