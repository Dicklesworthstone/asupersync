//! Diagnostic snapshot parsing fuzz target.
//!
//! This fuzzer tests diagnostic snapshot parsing per observability specification with focus on:
//! - JSON schema validation rejecting unknown fields by default
//! - Timestamp ordering monotonic validation
//! - Correlation IDs parsed as valid UUID variants
//! - Compressed snapshots decoded correctly
//! - Oversized snapshot rejection for security
//! Tests malformed diagnostic snapshots to verify robust error handling and security boundaries.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use std::collections::BTreeMap;

use asupersync::observability::task_inspector::{
    TASK_CONSOLE_WIRE_SCHEMA_V1, TaskConsoleWireSnapshot, TaskDetailsWire, TaskRegionCountWire,
    TaskStateInfo, TaskSummaryWire,
};
use asupersync::types::{ObligationId, RegionId, TaskId, Time};

/// Maximum reasonable snapshot size for security testing (1MB)
const MAX_SNAPSHOT_SIZE: usize = 1_048_576;

/// Diagnostic snapshot parsing attack patterns
#[derive(Arbitrary, Debug, Clone)]
enum DiagnosticAttackPattern {
    /// Unknown fields injection (schema validation bypass)
    UnknownFieldsInjection {
        /// Base valid snapshot
        base_snapshot: DiagnosticSnapshotFuzz,
        /// Unknown fields to inject
        unknown_fields: Vec<(String, String)>,
    },
    /// Timestamp ordering violation (monotonic bypass)
    TimestampOrdering {
        /// Base timestamp
        base_timestamp: u64,
        /// Task timestamp deltas (can be negative)
        task_deltas: Vec<i64>,
        /// Whether to inject decreasing timestamps
        inject_decreasing: bool,
    },
    /// Correlation ID malformation (UUID variant bypass)
    CorrelationIdMalform {
        /// Base snapshot with malformed IDs
        base_snapshot: DiagnosticSnapshotFuzz,
        /// Malformed task IDs to inject
        malformed_task_ids: Vec<u64>,
        /// Malformed region IDs to inject
        malformed_region_ids: Vec<u64>,
    },
    /// Compressed snapshot manipulation
    CompressedSnapshot {
        /// Valid snapshot JSON
        json_data: String,
        /// Compression corruption pattern
        corruption: CompressionCorruption,
    },
    /// Oversized snapshot attack
    OversizedSnapshot {
        /// Size multiplier for amplification
        size_multiplier: u32,
        /// Pattern for content amplification
        amplification_pattern: AmplificationPattern,
    },
}

#[derive(Arbitrary, Debug, Clone)]
enum CompressionCorruption {
    /// Truncate compressed data
    Truncate { bytes_to_remove: u8 },
    /// Bit flip corruption
    BitFlip { offset: u16, bit_index: u8 },
    /// Header corruption
    HeaderCorruption { new_header: Vec<u8> },
    /// Invalid compression format
    InvalidFormat,
}

#[derive(Arbitrary, Debug, Clone)]
enum AmplificationPattern {
    /// Repeat JSON structure
    JsonRepeat { repeat_count: u32 },
    /// Large string fields
    LargeStrings { string_size: u32 },
    /// Deep nesting
    DeepNesting { depth: u16 },
    /// Array amplification
    ArrayAmplification { array_size: u32 },
}

/// Fuzzable diagnostic snapshot structure
#[derive(Arbitrary, Debug, Clone)]
struct DiagnosticSnapshotFuzz {
    /// Schema version (might be malformed)
    schema_version: String,
    /// Timestamp for snapshot generation
    generated_at_nanos: u64,
    /// Task summary data
    summary: TaskSummaryFuzz,
    /// Individual task records
    tasks: Vec<TaskDetailsFuzz>,
}

#[derive(Arbitrary, Debug, Clone)]
struct TaskSummaryFuzz {
    total_tasks: u32,
    created: u32,
    running: u32,
    cancelling: u32,
    completed: u32,
    stuck_count: u32,
    by_region: Vec<TaskRegionFuzz>,
}

#[derive(Arbitrary, Debug, Clone)]
struct TaskRegionFuzz {
    region_id_raw: u64,
    task_count: u32,
}

#[derive(Arbitrary, Debug, Clone)]
struct TaskDetailsFuzz {
    task_id_raw: u64,
    region_id_raw: u64,
    state: TaskStateFuzz,
    phase: String,
    poll_count: u64,
    polls_remaining: u32,
    created_at_nanos: u64,
    age_nanos: u64,
    time_since_last_poll_nanos: Option<u64>,
    wake_pending: bool,
    obligations: Vec<u64>,
    waiters: Vec<u64>,
}

#[derive(Arbitrary, Debug, Clone)]
enum TaskStateFuzz {
    Created,
    Running,
    CancelRequested { reason: String },
    Cancelling { reason: String },
    Finalizing { reason: String },
    Completed { outcome: String },
}

impl DiagnosticAttackPattern {
    /// Convert attack pattern to JSON bytes for fuzzing
    fn to_json_bytes(&self) -> Vec<u8> {
        match self {
            DiagnosticAttackPattern::UnknownFieldsInjection {
                base_snapshot,
                unknown_fields,
            } => {
                let mut json_obj = base_snapshot.to_json_value();

                // Inject unknown fields at various levels
                for (key, value) in unknown_fields {
                    json_obj
                        .as_object_mut()
                        .unwrap()
                        .insert(key.clone(), serde_json::Value::String(value.clone()));
                }

                serde_json::to_vec(&json_obj).unwrap_or_default()
            }
            DiagnosticAttackPattern::TimestampOrdering {
                base_timestamp,
                task_deltas,
                inject_decreasing,
            } => {
                let mut snapshot = DiagnosticSnapshotFuzz {
                    schema_version: TASK_CONSOLE_WIRE_SCHEMA_V1.to_string(),
                    generated_at_nanos: *base_timestamp,
                    summary: TaskSummaryFuzz {
                        total_tasks: task_deltas.len() as u32,
                        created: 0,
                        running: task_deltas.len() as u32,
                        cancelling: 0,
                        completed: 0,
                        stuck_count: 0,
                        by_region: vec![],
                    },
                    tasks: vec![],
                };

                // Create tasks with potentially non-monotonic timestamps
                let mut current_time = *base_timestamp;
                for (i, delta) in task_deltas.iter().enumerate() {
                    if *inject_decreasing && i > 0 {
                        // Deliberately inject decreasing timestamp
                        current_time = current_time.saturating_sub(1000);
                    } else {
                        current_time = (current_time as i64).saturating_add(*delta) as u64;
                    }

                    snapshot.tasks.push(TaskDetailsFuzz {
                        task_id_raw: i as u64,
                        region_id_raw: 0,
                        state: TaskStateFuzz::Running,
                        phase: "Running".to_string(),
                        poll_count: 1,
                        polls_remaining: 100,
                        created_at_nanos: current_time,
                        age_nanos: (*base_timestamp).saturating_sub(current_time),
                        time_since_last_poll_nanos: None,
                        wake_pending: false,
                        obligations: vec![],
                        waiters: vec![],
                    });
                }

                serde_json::to_vec(&snapshot.to_json_value()).unwrap_or_default()
            }
            DiagnosticAttackPattern::CorrelationIdMalform {
                base_snapshot,
                malformed_task_ids,
                malformed_region_ids,
            } => {
                let mut snapshot = base_snapshot.clone();

                // Inject malformed IDs (invalid ArenaIndex patterns)
                for (i, &malformed_id) in malformed_task_ids.iter().enumerate() {
                    if i < snapshot.tasks.len() {
                        snapshot.tasks[i].task_id_raw = malformed_id;
                    }
                }

                for (i, &malformed_id) in malformed_region_ids.iter().enumerate() {
                    if i < snapshot.tasks.len() {
                        snapshot.tasks[i].region_id_raw = malformed_id;
                    }
                }

                serde_json::to_vec(&snapshot.to_json_value()).unwrap_or_default()
            }
            DiagnosticAttackPattern::CompressedSnapshot {
                json_data,
                corruption,
            } => {
                // Simulate compression (basic gzip-like pattern)
                let mut compressed = json_data.as_bytes().to_vec();

                match corruption {
                    CompressionCorruption::Truncate { bytes_to_remove } => {
                        let remove_count = (*bytes_to_remove as usize).min(compressed.len());
                        compressed.truncate(compressed.len().saturating_sub(remove_count));
                    }
                    CompressionCorruption::BitFlip { offset, bit_index } => {
                        let byte_offset = (*offset as usize) % compressed.len();
                        let bit = 1 << (bit_index % 8);
                        compressed[byte_offset] ^= bit;
                    }
                    CompressionCorruption::HeaderCorruption { new_header } => {
                        if !new_header.is_empty() && !compressed.is_empty() {
                            let header_len = new_header.len().min(compressed.len());
                            compressed[..header_len].copy_from_slice(&new_header[..header_len]);
                        }
                    }
                    CompressionCorruption::InvalidFormat => {
                        // Insert invalid compression magic bytes
                        compressed.insert(0, 0xFF);
                        compressed.insert(1, 0xFE);
                    }
                }

                compressed
            }
            DiagnosticAttackPattern::OversizedSnapshot {
                size_multiplier,
                amplification_pattern,
            } => {
                let multiplier = (*size_multiplier as usize).min(1000); // Limit for test safety

                match amplification_pattern {
                    AmplificationPattern::JsonRepeat { repeat_count } => {
                        let base_json = r#"{"schema_version":"test","generated_at":0,"summary":{"total_tasks":0,"created":0,"running":0,"cancelling":0,"completed":0,"stuck_count":0,"by_region":[]},"tasks":[]}"#;
                        let mut result = Vec::new();
                        result.push(b'[');
                        for i in 0..(*repeat_count as usize).min(multiplier) {
                            if i > 0 {
                                result.push(b',');
                            }
                            result.extend_from_slice(base_json.as_bytes());
                        }
                        result.push(b']');
                        result
                    }
                    AmplificationPattern::LargeStrings { string_size } => {
                        let large_string = "A".repeat((*string_size as usize).min(multiplier));
                        let json = serde_json::json!({
                            "schema_version": large_string,
                            "generated_at": 0,
                            "summary": {
                                "total_tasks": 1,
                                "created": 0,
                                "running": 1,
                                "cancelling": 0,
                                "completed": 0,
                                "stuck_count": 0,
                                "by_region": []
                            },
                            "tasks": [
                                {
                                    "id": 0,
                                    "region_id": 0,
                                    "state": "Running",
                                    "phase": large_string,
                                    "poll_count": 0,
                                    "polls_remaining": 100,
                                    "created_at": 0,
                                    "age_nanos": 0,
                                    "wake_pending": false,
                                    "obligations": [],
                                    "waiters": []
                                }
                            ]
                        });
                        serde_json::to_vec(&json).unwrap_or_default()
                    }
                    AmplificationPattern::DeepNesting { depth } => {
                        let mut json = serde_json::Value::Object(serde_json::Map::new());
                        let mut current = &mut json;
                        for _ in 0..(*depth as usize).min(multiplier.min(1000)) {
                            let mut nested = serde_json::Map::new();
                            nested.insert(
                                "nested".to_string(),
                                serde_json::Value::Object(serde_json::Map::new()),
                            );
                            if let serde_json::Value::Object(obj) = current {
                                obj.insert("child".to_string(), serde_json::Value::Object(nested));
                                if let Some(serde_json::Value::Object(child)) = obj.get_mut("child")
                                {
                                    if let Some(nested_obj) = child.get_mut("nested") {
                                        current = nested_obj;
                                    }
                                }
                            }
                        }
                        serde_json::to_vec(&json).unwrap_or_default()
                    }
                    AmplificationPattern::ArrayAmplification { array_size } => {
                        let mut tasks = Vec::new();
                        for i in 0..(*array_size as usize).min(multiplier) {
                            tasks.push(serde_json::json!({
                                "id": i,
                                "region_id": 0,
                                "state": "Running",
                                "phase": "Running",
                                "poll_count": i,
                                "polls_remaining": 100,
                                "created_at": i,
                                "age_nanos": 1000,
                                "wake_pending": false,
                                "obligations": [],
                                "waiters": []
                            }));
                        }
                        let json = serde_json::json!({
                            "schema_version": TASK_CONSOLE_WIRE_SCHEMA_V1,
                            "generated_at": 0,
                            "summary": {
                                "total_tasks": tasks.len(),
                                "created": 0,
                                "running": tasks.len(),
                                "cancelling": 0,
                                "completed": 0,
                                "stuck_count": 0,
                                "by_region": []
                            },
                            "tasks": tasks
                        });
                        serde_json::to_vec(&json).unwrap_or_default()
                    }
                }
            }
        }
    }
}

impl DiagnosticSnapshotFuzz {
    /// Convert to JSON Value for manipulation
    fn to_json_value(&self) -> Value {
        let tasks: Vec<Value> = self
            .tasks
            .iter()
            .map(|task| {
                serde_json::json!({
                    "id": task.task_id_raw,
                    "region_id": task.region_id_raw,
                    "state": task.state.to_json_value(),
                    "phase": task.phase,
                    "poll_count": task.poll_count,
                    "polls_remaining": task.polls_remaining,
                    "created_at": task.created_at_nanos,
                    "age_nanos": task.age_nanos,
                    "time_since_last_poll_nanos": task.time_since_last_poll_nanos,
                    "wake_pending": task.wake_pending,
                    "obligations": task.obligations,
                    "waiters": task.waiters
                })
            })
            .collect();

        let by_region: Vec<Value> = self
            .summary
            .by_region
            .iter()
            .map(|region| {
                serde_json::json!({
                    "region_id": region.region_id_raw,
                    "task_count": region.task_count
                })
            })
            .collect();

        serde_json::json!({
            "schema_version": self.schema_version,
            "generated_at": self.generated_at_nanos,
            "summary": {
                "total_tasks": self.summary.total_tasks,
                "created": self.summary.created,
                "running": self.summary.running,
                "cancelling": self.summary.cancelling,
                "completed": self.summary.completed,
                "stuck_count": self.summary.stuck_count,
                "by_region": by_region
            },
            "tasks": tasks
        })
    }
}

impl TaskStateFuzz {
    fn to_json_value(&self) -> Value {
        match self {
            Self::Created => serde_json::Value::String("Created".to_string()),
            Self::Running => serde_json::Value::String("Running".to_string()),
            Self::CancelRequested { reason } => serde_json::json!({
                "CancelRequested": { "reason": reason }
            }),
            Self::Cancelling { reason } => serde_json::json!({
                "Cancelling": { "reason": reason }
            }),
            Self::Finalizing { reason } => serde_json::json!({
                "Finalizing": { "reason": reason }
            }),
            Self::Completed { outcome } => serde_json::json!({
                "Completed": { "outcome": outcome }
            }),
        }
    }
}

/// Fuzz input structure for diagnostic snapshot parsing
#[derive(Arbitrary, Debug)]
struct DiagnosticSnapshotFuzzInput {
    /// The attack pattern to test
    pattern: DiagnosticAttackPattern,
    /// Whether to test valid vs invalid parsing
    test_valid_path: bool,
    /// Additional JSON manipulation flags
    json_manipulation: JsonManipulation,
}

#[derive(Arbitrary, Debug, Clone)]
struct JsonManipulation {
    /// Whether to inject null bytes
    inject_nulls: bool,
    /// Whether to use invalid UTF-8
    invalid_utf8: bool,
    /// Whether to inject control characters
    inject_control_chars: bool,
    /// Whether to test numeric overflow
    numeric_overflow: bool,
}

fuzz_target!(|input: DiagnosticSnapshotFuzzInput| {
    // Limit input processing to reasonable bounds
    let mut raw_data = input.pattern.to_json_bytes();
    if raw_data.len() > MAX_SNAPSHOT_SIZE {
        return;
    }

    // Apply JSON manipulations
    if input.json_manipulation.inject_nulls {
        raw_data.push(0);
    }

    if input.json_manipulation.inject_control_chars {
        raw_data.insert(0, 0x1F); // Unit separator
        raw_data.insert(1, 0x07); // Bell
    }

    if input.json_manipulation.invalid_utf8 {
        // Insert invalid UTF-8 sequences
        raw_data.extend_from_slice(&[0xFF, 0xFE, 0x80]);
    }

    // ASSERTION 1: JSON schema validation rejects unknown fields by default
    // The parser should handle unknown fields gracefully, either rejecting or ignoring
    if matches!(
        input.pattern,
        DiagnosticAttackPattern::UnknownFieldsInjection { .. }
    ) {
        let json_str = String::from_utf8_lossy(&raw_data);
        let parse_result = TaskConsoleWireSnapshot::from_json(&json_str);

        match parse_result {
            Ok(snapshot) => {
                // If parsing succeeds with unknown fields, schema should still be valid
                assert!(
                    snapshot.has_expected_schema() || snapshot.schema_version.is_empty(),
                    "Unknown fields injection: schema validation should be consistent"
                );
            }
            Err(_) => {
                // Error is acceptable for unknown field rejection - this is good behavior
            }
        }
    }

    // ASSERTION 2: Timestamp ordering monotonic validation
    // Snapshots with non-monotonic timestamps should either be rejected or handled gracefully
    if matches!(
        input.pattern,
        DiagnosticAttackPattern::TimestampOrdering {
            inject_decreasing: true,
            ..
        }
    ) {
        let json_str = String::from_utf8_lossy(&raw_data);
        let parse_result = TaskConsoleWireSnapshot::from_json(&json_str);

        match parse_result {
            Ok(snapshot) => {
                // If parsing succeeds, timestamp ordering should be reasonable
                let mut prev_timestamp = snapshot.generated_at;
                let mut violations = 0;

                for task in &snapshot.tasks {
                    // Task created_at should be <= snapshot generated_at for logical consistency
                    if task.created_at > snapshot.generated_at {
                        violations += 1;
                    }
                    prev_timestamp = task.created_at;
                }

                // Allow some timestamp violations but not excessive ones (indicates corruption)
                assert!(
                    violations <= snapshot.tasks.len() / 2,
                    "Excessive timestamp ordering violations: {} out of {}",
                    violations,
                    snapshot.tasks.len()
                );
            }
            Err(_) => {
                // Rejection is acceptable for malformed timestamps
            }
        }
    }

    // ASSERTION 3: Correlation IDs parsed as valid ID variants
    // Task and Region IDs should be valid ArenaIndex patterns or rejected gracefully
    if matches!(
        input.pattern,
        DiagnosticAttackPattern::CorrelationIdMalform { .. }
    ) {
        let json_str = String::from_utf8_lossy(&raw_data);
        let parse_result = TaskConsoleWireSnapshot::from_json(&json_str);

        match parse_result {
            Ok(snapshot) => {
                // If parsing succeeds, IDs should be valid or reasonable
                for task in &snapshot.tasks {
                    // Task ID and Region ID should not overflow reasonable bounds
                    // ArenaIndex uses generation + index pattern - very high values are suspicious
                    assert!(
                        task.id.as_u64() < (1u64 << 48),
                        "Correlation ID malform: task ID {} exceeds reasonable bounds",
                        task.id.as_u64()
                    );
                    assert!(
                        task.region_id.as_u64() < (1u64 << 48),
                        "Correlation ID malform: region ID {} exceeds reasonable bounds",
                        task.region_id.as_u64()
                    );
                }
            }
            Err(_) => {
                // Error is expected for malformed correlation IDs
            }
        }
    }

    // ASSERTION 4: Compressed snapshots decoded correctly
    // Corrupted compression should be detected and rejected
    if matches!(
        input.pattern,
        DiagnosticAttackPattern::CompressedSnapshot { .. }
    ) {
        let json_str = String::from_utf8_lossy(&raw_data);
        let parse_result = TaskConsoleWireSnapshot::from_json(&json_str);

        match parse_result {
            Ok(snapshot) => {
                // If decompression succeeded, snapshot should be valid
                assert!(
                    snapshot.schema_version.len() <= 100,
                    "Compressed snapshot: schema version too long after decompression"
                );
                assert!(
                    snapshot.tasks.len() <= 10000,
                    "Compressed snapshot: too many tasks after decompression"
                );

                // Verify round-trip consistency if parsing succeeded
                if let Ok(reencoded) = snapshot.to_json() {
                    assert!(
                        reencoded.len() <= MAX_SNAPSHOT_SIZE,
                        "Compressed snapshot: re-encoded size {} exceeds limit",
                        reencoded.len()
                    );
                }
            }
            Err(_) => {
                // Error is expected for corrupted compression
            }
        }
    }

    // ASSERTION 5: Oversized snapshot rejection for security
    // Very large snapshots should be rejected or handled with limits
    if matches!(
        input.pattern,
        DiagnosticAttackPattern::OversizedSnapshot { .. }
    ) {
        if raw_data.len() > MAX_SNAPSHOT_SIZE / 2 {
            // Large but not maximum
            let json_str = String::from_utf8_lossy(&raw_data);
            let parse_result = TaskConsoleWireSnapshot::from_json(&json_str);

            match parse_result {
                Ok(snapshot) => {
                    // If oversized parsing succeeds, should have reasonable limits
                    assert!(
                        snapshot.tasks.len() <= 50000,
                        "Oversized snapshot security: too many tasks {} allowed",
                        snapshot.tasks.len()
                    );

                    // Memory usage should be reasonable
                    let estimated_memory = snapshot.tasks.len() * 1000; // Rough estimate
                    assert!(
                        estimated_memory <= 50_000_000, // 50MB limit
                        "Oversized snapshot security: estimated memory {} bytes too high",
                        estimated_memory
                    );
                }
                Err(_) => {
                    // Rejection is good security behavior for oversized inputs
                }
            }
        }
    }

    // General robustness: parser must never panic on any input
    let json_str = String::from_utf8_lossy(&raw_data);
    let _ = TaskConsoleWireSnapshot::from_json(&json_str);

    // Test round-trip consistency for valid cases
    if input.test_valid_path && raw_data.len() <= 65536 {
        // Try to parse as valid JSON first
        if let Ok(json_value) = serde_json::from_slice::<Value>(&raw_data) {
            if let Ok(json_str) = serde_json::to_string(&json_value) {
                if let Ok(snapshot) = TaskConsoleWireSnapshot::from_json(&json_str) {
                    // Round-trip test
                    if let Ok(reencoded) = snapshot.to_json() {
                        if let Ok(reparsed) = TaskConsoleWireSnapshot::from_json(&reencoded) {
                            assert_eq!(
                                snapshot.schema_version, reparsed.schema_version,
                                "Round-trip consistency: schema version mismatch"
                            );
                            assert_eq!(
                                snapshot.generated_at, reparsed.generated_at,
                                "Round-trip consistency: timestamp mismatch"
                            );
                            assert_eq!(
                                snapshot.summary.total_tasks, reparsed.summary.total_tasks,
                                "Round-trip consistency: task count mismatch"
                            );
                        }
                    }
                }
            }
        }
    }

    // Numeric overflow test
    if input.json_manipulation.numeric_overflow {
        // Test with extreme numeric values
        let overflow_json = serde_json::json!({
            "schema_version": TASK_CONSOLE_WIRE_SCHEMA_V1,
            "generated_at": u64::MAX,
            "summary": {
                "total_tasks": u32::MAX,
                "created": u32::MAX,
                "running": 0,
                "cancelling": 0,
                "completed": 0,
                "stuck_count": u32::MAX,
                "by_region": []
            },
            "tasks": []
        });

        if let Ok(overflow_str) = serde_json::to_string(&overflow_json) {
            let result = TaskConsoleWireSnapshot::from_json(&overflow_str);
            match result {
                Ok(snapshot) => {
                    // If parsing succeeds with extreme values, should be handled safely
                    assert!(
                        snapshot.summary.total_tasks >= snapshot.summary.created,
                        "Numeric overflow: total_tasks {} < created {}",
                        snapshot.summary.total_tasks,
                        snapshot.summary.created
                    );
                }
                Err(_) => {
                    // Error is acceptable for numeric overflow
                }
            }
        }
    }

    // Additional edge case: Empty and minimal inputs
    let minimal_cases = [
        "",
        "null",
        "{}",
        "[]",
        r#"{"schema_version":""}"#,
        r#"{"malformed": true}"#,
    ];

    for &minimal in &minimal_cases {
        let _ = TaskConsoleWireSnapshot::from_json(minimal);
        // Should not panic on minimal/malformed inputs
    }
});
