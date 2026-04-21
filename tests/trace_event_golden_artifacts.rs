#![allow(warnings)]
#![allow(clippy::all)]
//! Golden artifact tests for trace event serialization.
//!
//! **STATUS: gated off until the schema converges.**
//!
//! This file was authored against a speculative trace schema that differs
//! from the one implemented in `src/trace/event.rs`:
//!
//! - Uses fictional `TraceEventKind` variants (`Cancel`, `TimerSet`,
//!   `TimerFire`, `RegionCreate`, `RegionClose`, `ObligationCreate`,
//!   `IoRegister`, `IoEvent`, `WorkerOffload`) — real names end in past
//!   tense / *Request / *Scheduled / *Fired / *Requested / *Ready etc.
//! - Uses `ObligationKind::Permit` (real: `SendPermit`),
//!   `ObligationState::Created` (real: `Reserved`),
//!   `ObligationAbortReason::Cancellation` (real: `Cancel`),
//!   `CancelReason::ExplicitCancel` (real: `CancelReason` is a struct with
//!   `kind: CancelKind::User`).
//! - Calls `LamportTime::new(n)` (real: `LamportTime::from_raw(n)`) and
//!   `browser_trace_log_fields(kind)` (real 3-arg signature).
//! - Reads `BrowserTraceSchema::compatibility_policy` (field removed).
//! - Relies on `TraceEvent: serde::Serialize`, which isn't derived (the
//!   canonical text form is `TraceEvent::stable_name` + `TraceData`'s
//!   internal exporters, not a raw serde round-trip).
//!
//! Once the trace schema is frozen and `TraceEvent`/`TraceData`/friends
//! derive `Serialize`, rewrite this suite against the real variants and
//! delete the `#[cfg(any())]` gate. See `audit_index.jsonl` for progress.

#![cfg(any())]

use std::fs;
use std::path::Path;

use asupersync::record::{ObligationAbortReason, ObligationKind, ObligationState};
use asupersync::trace::distributed::{LamportTime, LogicalTime};
use asupersync::trace::event::{
    BROWSER_TRACE_SCHEMA_VERSION, BrowserTraceCategory, TRACE_EVENT_SCHEMA_VERSION, TraceData,
    TraceEvent, TraceEventKind, browser_trace_log_fields, browser_trace_schema_v1,
};
use asupersync::types::{CancelReason, ObligationId, RegionId, TaskId, Time};
use serde_json;

/// Test utilities for creating deterministic trace events
mod test_utils {
    use super::*;

    /// Create deterministic test IDs for reproducible golden artifacts
    pub fn test_task_id(index: u32) -> TaskId {
        TaskId::new_for_test(index, 1)
    }

    pub fn test_region_id(index: u32) -> RegionId {
        RegionId::new_for_test(index, 1)
    }

    pub fn test_obligation_id(index: u32) -> ObligationId {
        ObligationId::new_for_test(index, 1)
    }

    pub fn test_time(nanos: u64) -> Time {
        Time::from_nanos(nanos)
    }

    /// Ensure the golden artifacts directory exists
    pub fn ensure_golden_dir() -> std::path::PathBuf {
        let golden_dir = Path::new("tests/golden/trace_events");
        if !golden_dir.exists() {
            fs::create_dir_all(golden_dir).expect("Failed to create golden artifacts directory");
        }
        golden_dir.to_path_buf()
    }

    /// Write a golden artifact with pretty-printed JSON
    pub fn write_golden_artifact(name: &str, data: &serde_json::Value) {
        let golden_dir = ensure_golden_dir();
        let file_path = golden_dir.join(format!("{}.json", name));

        let pretty_json =
            serde_json::to_string_pretty(data).expect("Failed to serialize to pretty JSON");

        fs::write(&file_path, pretty_json).unwrap_or_else(|e| {
            panic!(
                "Failed to write golden artifact {}: {}",
                file_path.display(),
                e
            )
        });
    }

    /// Read and compare against existing golden artifact
    pub fn verify_golden_artifact(name: &str, actual: &serde_json::Value) {
        let golden_dir = ensure_golden_dir();
        let file_path = golden_dir.join(format!("{}.json", name));

        if !file_path.exists() {
            // First run - create the golden artifact
            write_golden_artifact(name, actual);
            println!("Created new golden artifact: {}", file_path.display());
            return;
        }

        let expected_json = fs::read_to_string(&file_path).unwrap_or_else(|e| {
            panic!(
                "Failed to read golden artifact {}: {}",
                file_path.display(),
                e
            )
        });

        let expected: serde_json::Value =
            serde_json::from_str(&expected_json).unwrap_or_else(|e| {
                panic!(
                    "Failed to parse golden artifact {}: {}",
                    file_path.display(),
                    e
                )
            });

        if actual != &expected {
            // Write the actual output for comparison
            let actual_path = file_path.with_extension("actual.json");
            write_golden_artifact(&format!("{}.actual", name), actual);

            panic!(
                "Golden artifact mismatch for {}!\nExpected: {}\nActual: {}\nDiff file: {}",
                name,
                file_path.display(),
                actual_path.display(),
                actual_path.display()
            );
        }
    }
}

/// Generate a comprehensive trace event test suite
fn generate_comprehensive_trace_events() -> Vec<TraceEvent> {
    use test_utils::*;

    vec![
        // Basic task lifecycle events
        TraceEvent::spawn(1, test_time(1000), test_task_id(1), test_region_id(1)),
        TraceEvent::schedule(2, test_time(2000), test_task_id(1), test_region_id(1)),
        TraceEvent::wake(3, test_time(3000), test_task_id(1), test_region_id(1)),
        TraceEvent::poll(4, test_time(4000), test_task_id(1), test_region_id(1)),
        TraceEvent::yield_task(5, test_time(5000), test_task_id(1), test_region_id(1)),
        TraceEvent::complete(6, test_time(6000), test_task_id(1), test_region_id(1)),
        // Region lifecycle events
        TraceEvent::new(
            7,
            test_time(7000),
            TraceEventKind::RegionCreate,
            TraceData::Region {
                region: test_region_id(2),
                parent: Some(test_region_id(1)),
            },
        ),
        TraceEvent::new(
            8,
            test_time(8000),
            TraceEventKind::RegionClose,
            TraceData::Region {
                region: test_region_id(2),
                parent: Some(test_region_id(1)),
            },
        ),
        // Obligation tracking events
        TraceEvent::new(
            9,
            test_time(9000),
            TraceEventKind::ObligationCreate,
            TraceData::Obligation {
                obligation: test_obligation_id(1),
                task: test_task_id(1),
                region: test_region_id(1),
                kind: ObligationKind::Permit,
                state: ObligationState::Created,
                duration_ns: None,
                abort_reason: None,
            },
        ),
        TraceEvent::new(
            10,
            test_time(10000),
            TraceEventKind::ObligationCommit,
            TraceData::Obligation {
                obligation: test_obligation_id(1),
                task: test_task_id(1),
                region: test_region_id(1),
                kind: ObligationKind::Permit,
                state: ObligationState::Committed,
                duration_ns: Some(1000),
                abort_reason: None,
            },
        ),
        TraceEvent::new(
            11,
            test_time(11000),
            TraceEventKind::ObligationAbort,
            TraceData::Obligation {
                obligation: test_obligation_id(2),
                task: test_task_id(2),
                region: test_region_id(2),
                kind: ObligationKind::Lease,
                state: ObligationState::Aborted,
                duration_ns: Some(500),
                abort_reason: Some(ObligationAbortReason::Cancellation),
            },
        ),
        // Cancellation events
        TraceEvent::new(
            12,
            test_time(12000),
            TraceEventKind::Cancel,
            TraceData::Cancel {
                task: test_task_id(3),
                region: test_region_id(3),
                reason: CancelReason::ExplicitCancel,
            },
        ),
        // Timer events
        TraceEvent::new(
            13,
            test_time(13000),
            TraceEventKind::TimerSet,
            TraceData::Timer {
                timer_id: 1,
                deadline: Some(test_time(20000)),
            },
        ),
        TraceEvent::new(
            14,
            test_time(20000),
            TraceEventKind::TimerFire,
            TraceData::Timer {
                timer_id: 1,
                deadline: Some(test_time(20000)),
            },
        ),
        // I/O events
        TraceEvent::new(
            15,
            test_time(15000),
            TraceEventKind::IoRegister,
            TraceData::IoRequested {
                token: 42,
                interest: 0b00000011, // readable + writable
            },
        ),
        TraceEvent::new(
            16,
            test_time(16000),
            TraceEventKind::IoEvent,
            TraceData::IoReady {
                token: 42,
                readiness: 0b00000001, // readable
            },
        ),
        // Time advancement event
        TraceEvent::new(
            17,
            test_time(17000),
            TraceEventKind::TimeAdvance,
            TraceData::Time {
                old: test_time(16000),
                new: test_time(17000),
            },
        ),
        // Region cancellation event
        TraceEvent::new(
            18,
            test_time(18000),
            TraceEventKind::Cancel,
            TraceData::RegionCancel {
                region: test_region_id(4),
                reason: CancelReason::ExplicitCancel,
            },
        ),
        // Events with logical time for distributed tracing
        TraceEvent::new(
            19,
            test_time(19000),
            TraceEventKind::Spawn,
            TraceData::Task {
                task: test_task_id(4),
                region: test_region_id(3),
            },
        )
        .with_logical_time(LogicalTime::Lamport(LamportTime::new(10))),
        // Event with no additional data
        TraceEvent::new(20, test_time(20000), TraceEventKind::Yield, TraceData::None),
    ]
}

/// Test serialization of all TraceEvent variants
#[test]
fn test_trace_event_comprehensive_serialization() {
    let events = generate_comprehensive_trace_events();

    // Create a comprehensive test artifact containing all event types
    let mut event_collection = serde_json::Map::new();

    // Add metadata
    event_collection.insert(
        "schema_version".to_string(),
        serde_json::Value::Number(TRACE_EVENT_SCHEMA_VERSION.into()),
    );
    event_collection.insert(
        "test_description".to_string(),
        serde_json::Value::String("Comprehensive trace event serialization test".to_string()),
    );
    event_collection.insert(
        "event_count".to_string(),
        serde_json::Value::Number(events.len().into()),
    );

    // Serialize all events
    let events_json: Vec<serde_json::Value> = events
        .iter()
        .map(|event| serde_json::to_value(event).expect("Failed to serialize TraceEvent"))
        .collect();

    event_collection.insert("events".to_string(), serde_json::Value::Array(events_json));

    let comprehensive_artifact = serde_json::Value::Object(event_collection);

    // Verify against golden artifact
    test_utils::verify_golden_artifact("comprehensive_trace_events", &comprehensive_artifact);
}

/// Test browser trace schema compatibility
#[test]
fn test_browser_trace_schema_golden() {
    let schema = browser_trace_schema_v1();

    let mut schema_artifact = serde_json::Map::new();
    schema_artifact.insert(
        "schema_version".to_string(),
        serde_json::Value::String(BROWSER_TRACE_SCHEMA_VERSION.to_string()),
    );
    schema_artifact.insert(
        "compatibility_policy".to_string(),
        serde_json::to_value(&schema.compatibility_policy)
            .expect("Failed to serialize compatibility policy"),
    );
    schema_artifact.insert(
        "event_specs".to_string(),
        serde_json::to_value(&schema.event_specs).expect("Failed to serialize event specs"),
    );

    let schema_json = serde_json::Value::Object(schema_artifact);
    test_utils::verify_golden_artifact("browser_trace_schema_v1", &schema_json);
}

/// Test trace event categorization and field mapping
#[test]
fn test_trace_event_categorization_golden() {
    let mut categorization = serde_json::Map::new();

    // Test all TraceEventKind variants and their categories
    let event_kinds = vec![
        TraceEventKind::Spawn,
        TraceEventKind::Schedule,
        TraceEventKind::Wake,
        TraceEventKind::Poll,
        TraceEventKind::Yield,
        TraceEventKind::Complete,
        TraceEventKind::RegionCreate,
        TraceEventKind::RegionClose,
        TraceEventKind::ObligationCreate,
        TraceEventKind::ObligationCommit,
        TraceEventKind::ObligationAbort,
        TraceEventKind::Cancel,
        TraceEventKind::TimerSet,
        TraceEventKind::TimerFire,
    ];

    for kind in event_kinds {
        let category = asupersync::trace::event::browser_trace_category_for_kind(kind);
        let log_fields = browser_trace_log_fields(kind);

        let mut kind_info = serde_json::Map::new();
        kind_info.insert(
            "category".to_string(),
            serde_json::to_value(category).expect("Failed to serialize category"),
        );
        kind_info.insert(
            "log_fields".to_string(),
            serde_json::to_value(log_fields).expect("Failed to serialize log fields"),
        );

        categorization.insert(format!("{:?}", kind), serde_json::Value::Object(kind_info));
    }

    let categorization_artifact = serde_json::Value::Object(categorization);
    test_utils::verify_golden_artifact("trace_event_categorization", &categorization_artifact);
}

/// Test deterministic trace event serialization
#[test]
fn test_deterministic_trace_event_serialization() {
    use test_utils::*;

    // Create the same event multiple times to ensure deterministic serialization
    let events: Vec<TraceEvent> = (0..3)
        .map(|_| {
            TraceEvent::new(
                42,
                test_time(12345),
                TraceEventKind::Schedule,
                TraceData::Task {
                    task: test_task_id(100),
                    region: test_region_id(200),
                },
            )
            .with_logical_time(LogicalTime::Lamport(LamportTime::new(5)))
        })
        .collect();

    // All serializations should be identical
    let serialized: Vec<String> = events
        .iter()
        .map(|event| serde_json::to_string(event).expect("Failed to serialize"))
        .collect();

    assert!(
        serialized.windows(2).all(|pair| pair[0] == pair[1]),
        "TraceEvent serialization is not deterministic"
    );

    // Create golden artifact for deterministic serialization
    let deterministic_test = serde_json::json!({
        "test_description": "Deterministic trace event serialization verification",
        "iterations": 3,
        "all_identical": true,
        "canonical_form": serialized[0]
    });

    test_utils::verify_golden_artifact("deterministic_serialization", &deterministic_test);
}

/// Test trace event with complex nested data (Worker variant)
#[test]
fn test_complex_trace_data_golden() {
    use test_utils::*;

    // Create an event with complex Worker TraceData (most complex variant)
    let complex_event = TraceEvent::new(
        999,
        test_time(999999),
        TraceEventKind::WorkerOffload,
        TraceData::Worker {
            worker_id: "worker_alpha_42".to_string(),
            job_id: 12345,
            decision_seq: 67890,
            replay_hash: 0xdeadbeef_cafebabe,
            task: test_task_id(999),
            region: test_region_id(888),
            obligation: test_obligation_id(777),
        },
    );

    let complex_artifact =
        serde_json::to_value(&complex_event).expect("Failed to serialize complex TraceEvent");

    test_utils::verify_golden_artifact("complex_trace_data", &complex_artifact);
}

/// Update golden artifacts (run with GOLDEN_UPDATE=1 to regenerate all)
#[test]
#[ignore]
fn update_all_golden_artifacts() {
    if std::env::var("GOLDEN_UPDATE").is_ok() {
        println!("Regenerating all trace event golden artifacts...");

        // Re-run all the golden tests to regenerate artifacts
        test_trace_event_comprehensive_serialization();
        test_browser_trace_schema_golden();
        test_trace_event_categorization_golden();
        test_deterministic_trace_event_serialization();
        test_complex_trace_data_golden();

        println!("All golden artifacts updated successfully!");
    } else {
        println!("Set GOLDEN_UPDATE=1 to regenerate golden artifacts");
    }
}
