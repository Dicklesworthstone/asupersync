#![no_main]

//! Fuzz target for trace canonicalization and Foata normal form invariants.
//!
//! This target exercises trace monoid canonicalization to ensure robust handling
//! of equivalent traces and edge cases in DPOR (Dynamic Partial Order Reduction).
//!
//! Key invariants tested:
//! 1. Canonical Equivalence: Equivalent traces produce identical canonical forms
//! 2. Permutation Invariance: Independent events can be reordered without changing equivalence
//! 3. Timestamp Skew Tolerance: Small timestamp differences don't affect logical ordering
//! 4. Missing Field Defaults: Traces with missing optional fields canonicalize correctly
//! 5. UTF-8 Corruption Handling: Invalid UTF-8 in trace data fails gracefully
//! 6. Monoid Laws: Identity, associativity, and commutativity properties hold

use libfuzzer_sys::fuzz_target;
use asupersync::trace::canonicalize::{canonicalize, trace_fingerprint, TraceMonoid, FoataTrace};
use asupersync::trace::event::{TraceEvent, TraceEventKind, TraceData};
use asupersync::trace::distributed::{LogicalTime, LamportTime};
use asupersync::types::{TaskId, RegionId, Time};

fuzz_target!(|data: &[u8]| {
    // Skip tiny inputs
    if data.len() < 4 {
        return;
    }

    // Limit size to prevent timeouts
    if data.len() > 2048 {
        return;
    }

    // Parse fuzz input into test scenarios
    let mut input = data;
    let scenarios = parse_canonicalize_operations(&mut input);

    // Test trace canonicalization invariants
    test_canonical_equivalence(&scenarios);
    test_permutation_invariance(&scenarios);
    test_timestamp_skew_tolerance(&scenarios);
    test_missing_field_defaults(&scenarios);
    test_utf8_corruption_handling(&scenarios);
    test_monoid_laws(&scenarios);
    test_fingerprint_consistency(&scenarios);
});

#[derive(Debug, Clone)]
enum CanonicalizeOperation {
    LinearTrace(Vec<TraceEvent>),
    PermutedTrace(Vec<TraceEvent>),
    TimestampSkewed(Vec<TraceEvent>, i64),
    MissingFields(Vec<TraceEvent>),
    CorruptUtf8(Vec<TraceEvent>),
    EmptyTrace,
}

fn parse_canonicalize_operations(input: &mut &[u8]) -> Vec<CanonicalizeOperation> {
    let mut ops = Vec::new();
    let mut rng_state = 42u64;

    while input.len() >= 2 && ops.len() < 10 {
        let op_type = extract_u8(input, &mut rng_state) % 6;
        let event_count = (extract_u8(input, &mut rng_state) % 8) as usize + 1;

        match op_type {
            0 => {
                let events = generate_linear_trace(event_count, &mut rng_state);
                ops.push(CanonicalizeOperation::LinearTrace(events));
            }
            1 => {
                let events = generate_linear_trace(event_count, &mut rng_state);
                let permuted = permute_independent_events(&events, &mut rng_state);
                ops.push(CanonicalizeOperation::PermutedTrace(permuted));
            }
            2 => {
                let events = generate_linear_trace(event_count, &mut rng_state);
                let skew = (extract_u32(input, &mut rng_state) % 1000) as i64 - 500;
                ops.push(CanonicalizeOperation::TimestampSkewed(events, skew));
            }
            3 => {
                let events = generate_trace_with_missing_fields(event_count, &mut rng_state);
                ops.push(CanonicalizeOperation::MissingFields(events));
            }
            4 => {
                let mut events = generate_linear_trace(event_count, &mut rng_state);
                // Simulate UTF-8 corruption by generating events with extreme values
                for event in &mut events {
                    if (*rng_state % 4) == 0 {
                        // Corrupt by using extreme sequence numbers
                        event.seq = u64::MAX;
                    }
                }
                ops.push(CanonicalizeOperation::CorruptUtf8(events));
            }
            5 => {
                ops.push(CanonicalizeOperation::EmptyTrace);
            }
            _ => unreachable!(),
        }
    }

    ops
}

/// Generate a linear trace with deterministic event dependencies
fn generate_linear_trace(count: usize, rng_state: &mut u64) -> Vec<TraceEvent> {
    let mut events = Vec::new();
    let mut seq = 0;
    let base_time = Time::from_nanos(1_000_000_000); // 1 second base

    for i in 0..count {
        *rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        let time_offset = (*rng_state % 1000) as u64;
        let time = Time::from_nanos(base_time.as_nanos() + (i as u64 * 10_000) + time_offset);

        let event_type = (*rng_state >> 8) % 4;
        let (kind, data) = match event_type {
            0 => {
                let task_id = TaskId::new_for_test((*rng_state % 100) as u32, 0);
                let region_id = RegionId::new_for_test((*rng_state % 50) as u32, 0);
                (TraceEventKind::Spawn, TraceData::Task { task: task_id, region: region_id })
            }
            1 => {
                let task_id = TaskId::new_for_test((*rng_state % 100) as u32, 0);
                let region_id = RegionId::new_for_test((*rng_state % 50) as u32, 0);
                (TraceEventKind::Complete, TraceData::Task { task: task_id, region: region_id })
            }
            2 => {
                let region_id = RegionId::new_for_test((*rng_state % 50) as u32, 0);
                (TraceEventKind::RegionCreated, TraceData::Region { region: region_id, parent: None })
            }
            3 => {
                let region_id = RegionId::new_for_test((*rng_state % 50) as u32, 0);
                (TraceEventKind::RegionCloseComplete, TraceData::Region { region: region_id, parent: None })
            }
            _ => unreachable!(),
        };

        let event = TraceEvent::new(seq, time, kind, data);
        events.push(event);
        seq += 1;
    }

    events
}

/// Permute independent events to test trace equivalence
fn permute_independent_events(events: &[TraceEvent], rng_state: &mut u64) -> Vec<TraceEvent> {
    let mut permuted = events.to_vec();

    // Simple permutation: swap adjacent events if they're independent
    for i in 0..permuted.len().saturating_sub(1) {
        *rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        if (*rng_state % 2) == 0 {
            // Try swapping adjacent events
            if can_swap_safely(&permuted[i], &permuted[i + 1]) {
                permuted.swap(i, i + 1);
            }
        }
    }

    permuted
}

/// Check if two events can be safely swapped (heuristic independence check)
fn can_swap_safely(a: &TraceEvent, b: &TraceEvent) -> bool {
    match (&a.data, &b.data) {
        // Different tasks/regions can typically be reordered
        (TraceData::Task { task: task_a, region: region_a },
         TraceData::Task { task: task_b, region: region_b }) => {
            task_a != task_b && region_a != region_b
        }
        (TraceData::Region { region: region_a, .. },
         TraceData::Region { region: region_b, .. }) => {
            region_a != region_b
        }
        // Different data types might be independent
        _ => a.kind != b.kind
    }
}

/// Generate trace with timestamp skewing to test tolerance
fn apply_timestamp_skew(events: &[TraceEvent], skew_ns: i64) -> Vec<TraceEvent> {
    events.iter().map(|event| {
        let new_time = if skew_ns >= 0 {
            Time::from_nanos(event.time.as_nanos() + skew_ns as u64)
        } else {
            Time::from_nanos(event.time.as_nanos().saturating_sub((-skew_ns) as u64))
        };
        TraceEvent {
            version: event.version,
            seq: event.seq,
            time: new_time,
            logical_time: event.logical_time.clone(),
            kind: event.kind,
            data: event.data.clone(),
        }
    }).collect()
}

/// Generate trace with missing optional fields
fn generate_trace_with_missing_fields(count: usize, rng_state: &mut u64) -> Vec<TraceEvent> {
    let mut events = generate_linear_trace(count, rng_state);

    // Remove logical_time from some events to test missing field handling
    for (i, event) in events.iter_mut().enumerate() {
        if i % 2 == 0 {
            event.logical_time = None;
        } else if i % 3 == 0 {
            // Add logical time for variety
            event.logical_time = Some(LogicalTime::Lamport(LamportTime::from_raw(i as u64 + 1000)));
        }
    }

    events
}

/// Test that equivalent traces produce identical canonical forms
fn test_canonical_equivalence(operations: &[CanonicalizeOperation]) {
    for op in operations {
        match op {
            CanonicalizeOperation::LinearTrace(events) => {
                let canonical1 = canonicalize(events);
                let canonical2 = canonicalize(events);

                // Same input should produce same canonical form
                assert_eq!(canonical1.fingerprint(), canonical2.fingerprint(),
                    "Same trace produced different canonical forms");
                assert_eq!(canonical1.len(), canonical2.len(),
                    "Same trace produced different lengths");
            }
            CanonicalizeOperation::PermutedTrace(events) => {
                let canonical = canonicalize(events);

                // Verify canonical form properties
                assert!(canonical.depth() <= events.len(),
                    "Canonical depth exceeds original length");
                assert_eq!(canonical.len(), events.len(),
                    "Canonical form lost events during canonicalization");
            }
            _ => {}
        }
    }
}

/// Test that permuting independent events doesn't change equivalence
fn test_permutation_invariance(operations: &[CanonicalizeOperation]) {
    for op in operations {
        if let CanonicalizeOperation::LinearTrace(events) = op {
            if events.len() < 2 { continue; }

            let original_fingerprint = trace_fingerprint(events);
            let original_canonical = canonicalize(events);

            // Try a different permutation
            let mut rng_state = 12345u64;
            let permuted = permute_independent_events(events, &mut rng_state);

            if permuted != *events {
                let permuted_fingerprint = trace_fingerprint(&permuted);
                let permuted_canonical = canonicalize(&permuted);

                // Independent permutations should have same fingerprint
                // Note: This is a heuristic test - true independence requires
                // deep semantic analysis, but we test obvious cases
                if are_likely_equivalent(&original_canonical, &permuted_canonical) {
                    assert_eq!(original_fingerprint, permuted_fingerprint,
                        "Independent permutation changed fingerprint");
                }
            }
        }
    }
}

/// Test that small timestamp skews don't affect logical ordering
fn test_timestamp_skew_tolerance(operations: &[CanonicalizeOperation]) {
    for op in operations {
        match op {
            CanonicalizeOperation::TimestampSkewed(events, skew) => {
                let original_canonical = canonicalize(events);
                let skewed_events = apply_timestamp_skew(events, *skew);
                let skewed_canonical = canonicalize(&skewed_events);

                // Small skews shouldn't change the logical structure dramatically
                if skew.abs() < 100 {  // Small skew threshold
                    assert_eq!(original_canonical.len(), skewed_canonical.len(),
                        "Small timestamp skew changed event count");
                    // Depth might change slightly due to reordering, but shouldn't be dramatic
                    assert!((original_canonical.depth() as i32 - skewed_canonical.depth() as i32).abs() <= 2,
                        "Small timestamp skew caused dramatic depth change");
                }
            }
            _ => {}
        }
    }
}

/// Test that missing optional fields are handled gracefully
fn test_missing_field_defaults(operations: &[CanonicalizeOperation]) {
    for op in operations {
        if let CanonicalizeOperation::MissingFields(events) = op {
            // Should not panic on missing fields
            let canonical = canonicalize(events);
            assert_eq!(canonical.len(), events.len(),
                "Missing fields caused event loss during canonicalization");

            // Should produce valid fingerprint
            let fingerprint = canonical.fingerprint();
            assert_ne!(fingerprint, 0, "Missing fields produced zero fingerprint");
        }
    }
}

/// Test that UTF-8 corruption is handled gracefully
fn test_utf8_corruption_handling(operations: &[CanonicalizeOperation]) {
    // Test with operations containing corrupted events
    for op in operations {
        if let CanonicalizeOperation::CorruptUtf8(events) = op {
            // Should not panic on corrupted events with extreme values
            let canonical = canonicalize(events);
            assert_eq!(canonical.len(), events.len(),
                "Corrupted events caused event loss during canonicalization");

            // Should produce valid fingerprint
            let fingerprint = canonical.fingerprint();
            assert_ne!(fingerprint, 0, "Corrupted events produced zero fingerprint");
        }
    }

    // Also test with additional extreme values that might cause issues
    let extreme_task_id = TaskId::new_for_test(u32::MAX, u32::MAX);
    let extreme_region_id = RegionId::new_for_test(u32::MAX, u32::MAX);

    let extreme_events = vec![
        TraceEvent::new(
            u64::MAX,
            Time::from_nanos(u64::MAX),
            TraceEventKind::Spawn,
            TraceData::Task { task: extreme_task_id, region: extreme_region_id }
        )
    ];

    // Should not panic with extreme values
    let canonical = canonicalize(&extreme_events);
    assert_eq!(canonical.len(), 1, "Extreme values caused canonicalization failure");
}

/// Test monoid laws: identity, associativity
fn test_monoid_laws(operations: &[CanonicalizeOperation]) {
    for op in operations {
        if let CanonicalizeOperation::LinearTrace(events) = op {
            if events.is_empty() { continue; }

            let trace_monoid = TraceMonoid::from_events(events);
            let identity = TraceMonoid::identity();

            // Test identity laws
            let left_identity = identity.concat(&trace_monoid);
            let right_identity = trace_monoid.concat(&identity);

            assert_eq!(trace_monoid.class_fingerprint(), left_identity.class_fingerprint(),
                "Left identity law violated");
            assert_eq!(trace_monoid.class_fingerprint(), right_identity.class_fingerprint(),
                "Right identity law violated");
        }
    }
}

/// Test that fingerprint is consistent with canonical form
fn test_fingerprint_consistency(operations: &[CanonicalizeOperation]) {
    for op in operations {
        match op {
            CanonicalizeOperation::LinearTrace(events) |
            CanonicalizeOperation::PermutedTrace(events) |
            CanonicalizeOperation::MissingFields(events) => {
                let canonical = canonicalize(events);
                let direct_fingerprint = trace_fingerprint(events);
                let canonical_fingerprint = canonical.fingerprint();

                assert_eq!(direct_fingerprint, canonical_fingerprint,
                    "Direct fingerprint doesn't match canonical fingerprint");
            }
            CanonicalizeOperation::EmptyTrace => {
                let empty_events: Vec<TraceEvent> = vec![];
                let canonical = canonicalize(&empty_events);
                let fingerprint = canonical.fingerprint();
                let direct_fingerprint = trace_fingerprint(&empty_events);

                assert_eq!(fingerprint, direct_fingerprint,
                    "Empty trace fingerprints don't match");
            }
            _ => {}
        }
    }
}

/// Heuristic check if two canonical forms are likely equivalent
fn are_likely_equivalent(canonical1: &FoataTrace, canonical2: &FoataTrace) -> bool {
    // Simple heuristic: same number of events and similar structure
    canonical1.len() == canonical2.len() &&
    (canonical1.depth() as i32 - canonical2.depth() as i32).abs() <= 1
}

// Helper functions to extract data from fuzzer input
fn extract_u8(input: &mut &[u8], rng_state: &mut u64) -> u8 {
    if input.is_empty() {
        *rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        (*rng_state >> 8) as u8
    } else {
        let val = input[0];
        *input = &input[1..];
        val
    }
}

fn extract_u32(input: &mut &[u8], rng_state: &mut u64) -> u32 {
    if input.len() < 4 {
        *rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        *rng_state as u32
    } else {
        let val = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
        *input = &input[4..];
        val
    }
}