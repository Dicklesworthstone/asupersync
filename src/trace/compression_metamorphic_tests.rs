//! Metamorphic tests for trace compression.
//!
//! This module applies metamorphic testing to the trace compression system,
//! verifying properties and relationships that must hold for any correct
//! compression implementation.
//!
//! ## Oracle Problem
//!
//! We cannot compute the "correct" compressed output for arbitrary trace inputs.
//! Compression behavior depends on complex event filtering rules, and the expected
//! result varies by compression level and input characteristics.
//!
//! ## Metamorphic Relations Tested
//!
//! 1. **Compression Level Monotonicity**: Skeleton ⊆ Structural ⊆ Lossless (event counts)
//! 2. **Idempotence**: Compressing compressed trace = same result
//! 3. **Certificate Consistency**: Certificate should always validate compressed trace
//! 4. **Event Order Preservation**: Retained events maintain temporal ordering
//! 5. **Noise Event Elimination**: Noise events removed in structural/skeleton compression
//! 6. **Single Event Preservation**: Skeleton events survive skeleton compression
//! 7. **Event Count Consistency**: len + events_removed = original_count
//! 8. **Level-Specific Event Filtering**: Each level filters appropriate event types

use super::*;
use crate::trace::event::{TraceData, TraceEvent, TraceEventKind};
use crate::types::Time;

/// Create test trace events with different types for comprehensive testing.
fn create_test_traces() -> Vec<Vec<TraceEvent>> {
    vec![
        // Empty trace (edge case)
        vec![],
        // Single skeleton event
        vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::Spawn,
            TraceData::None,
        )],
        // Single noise event
        vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::None,
        )],
        // Mixed skeleton and noise events
        vec![
            TraceEvent::new(1, Time::ZERO, TraceEventKind::Spawn, TraceData::None),
            TraceEvent::new(
                2,
                Time::from_nanos(100),
                TraceEventKind::UserTrace,
                TraceData::None,
            ),
            TraceEvent::new(
                3,
                Time::from_nanos(200),
                TraceEventKind::Wake,
                TraceData::None,
            ),
            TraceEvent::new(
                4,
                Time::from_nanos(300),
                TraceEventKind::Complete,
                TraceData::None,
            ),
        ],
        // Complex trace with all event types
        vec![
            TraceEvent::new(1, Time::ZERO, TraceEventKind::Spawn, TraceData::None),
            TraceEvent::new(
                2,
                Time::from_nanos(50),
                TraceEventKind::RegionCreated,
                TraceData::None,
            ),
            TraceEvent::new(
                3,
                Time::from_nanos(100),
                TraceEventKind::UserTrace,
                TraceData::None,
            ),
            TraceEvent::new(
                4,
                Time::from_nanos(150),
                TraceEventKind::Wake,
                TraceData::None,
            ),
            TraceEvent::new(
                5,
                Time::from_nanos(200),
                TraceEventKind::ObligationReserve,
                TraceData::None,
            ),
            TraceEvent::new(
                6,
                Time::from_nanos(250),
                TraceEventKind::TimerScheduled,
                TraceData::None,
            ),
            TraceEvent::new(
                7,
                Time::from_nanos(300),
                TraceEventKind::CancelRequest,
                TraceData::None,
            ),
            TraceEvent::new(
                8,
                Time::from_nanos(350),
                TraceEventKind::TimerFired,
                TraceData::None,
            ),
            TraceEvent::new(
                9,
                Time::from_nanos(400),
                TraceEventKind::CancelAck,
                TraceData::None,
            ),
            TraceEvent::new(
                10,
                Time::from_nanos(450),
                TraceEventKind::ObligationCommit,
                TraceData::None,
            ),
            TraceEvent::new(
                11,
                Time::from_nanos(500),
                TraceEventKind::RegionCloseComplete,
                TraceData::None,
            ),
            TraceEvent::new(
                12,
                Time::from_nanos(550),
                TraceEventKind::Complete,
                TraceData::None,
            ),
        ],
        // All noise events
        vec![
            TraceEvent::new(1, Time::ZERO, TraceEventKind::UserTrace, TraceData::None),
            TraceEvent::new(
                2,
                Time::from_nanos(100),
                TraceEventKind::Wake,
                TraceData::None,
            ),
            TraceEvent::new(
                3,
                Time::from_nanos(200),
                TraceEventKind::TimerScheduled,
                TraceData::None,
            ),
            TraceEvent::new(
                4,
                Time::from_nanos(300),
                TraceEventKind::TimerFired,
                TraceData::None,
            ),
        ],
        // All skeleton events
        vec![
            TraceEvent::new(1, Time::ZERO, TraceEventKind::Spawn, TraceData::None),
            TraceEvent::new(
                2,
                Time::from_nanos(100),
                TraceEventKind::RegionCreated,
                TraceData::None,
            ),
            TraceEvent::new(
                3,
                Time::from_nanos(200),
                TraceEventKind::ObligationReserve,
                TraceData::None,
            ),
            TraceEvent::new(
                4,
                Time::from_nanos(300),
                TraceEventKind::CancelRequest,
                TraceData::None,
            ),
            TraceEvent::new(
                5,
                Time::from_nanos(400),
                TraceEventKind::CancelAck,
                TraceData::None,
            ),
            TraceEvent::new(
                6,
                Time::from_nanos(500),
                TraceEventKind::ObligationCommit,
                TraceData::None,
            ),
            TraceEvent::new(
                7,
                Time::from_nanos(600),
                TraceEventKind::RegionCloseComplete,
                TraceData::None,
            ),
            TraceEvent::new(
                8,
                Time::from_nanos(700),
                TraceEventKind::Complete,
                TraceData::None,
            ),
        ],
    ]
}

/// MR1: Compression Level Monotonicity
/// Property: Skeleton ⊆ Structural ⊆ Lossless (event count ordering)
/// Category: Inclusive/Exclusive (subset relations)
#[test]
fn mr_compression_level_monotonicity() {
    for trace in create_test_traces() {
        let lossless = compress(&trace, Level::Lossless);
        let structural = compress(&trace, Level::Structural);
        let skeleton = compress(&trace, Level::Skeleton);

        // Event count ordering: skeleton ≤ structural ≤ lossless
        assert!(
            skeleton.events.len() <= structural.events.len(),
            "Skeleton compression ({} events) should have ≤ events than Structural ({} events)",
            skeleton.events.len(),
            structural.events.len()
        );

        assert!(
            structural.events.len() <= lossless.events.len(),
            "Structural compression ({} events) should have ≤ events than Lossless ({} events)",
            structural.events.len(),
            lossless.events.len()
        );

        // Subset relationship: every skeleton event should be in structural
        for event in &skeleton.events {
            assert!(
                structural.events.contains(event),
                "Skeleton event {:?} not found in structural compression",
                event.kind
            );
        }

        // Every structural event should be in lossless
        for event in &structural.events {
            assert!(
                lossless.events.contains(event),
                "Structural event {:?} not found in lossless compression",
                event.kind
            );
        }
    }
}

/// MR2: Idempotence
/// Property: compress(compress(trace)) = compress(trace)
/// Category: Invertive (applying transformation twice)
#[test]
fn mr_compression_idempotence() {
    for trace in create_test_traces() {
        for level in [Level::Lossless, Level::Structural, Level::Skeleton] {
            let compressed_once = compress(&trace, level);
            let compressed_twice = compress(&compressed_once.events, level);

            assert_eq!(
                compressed_once.events.len(),
                compressed_twice.events.len(),
                "Double compression changed event count for level {:?}",
                level
            );

            assert_eq!(
                compressed_once.events, compressed_twice.events,
                "Double compression changed events for level {:?}",
                level
            );

            assert_eq!(
                compressed_once.certificate.event_hash(),
                compressed_twice.certificate.event_hash(),
                "Double compression changed certificate for level {:?}",
                level
            );
        }
    }
}

/// MR3: Certificate Consistency
/// Property: validate_compressed(compressed_trace) = true (always)
/// Category: Equivalence (certificate should always be valid)
#[test]
fn mr_certificate_consistency() {
    for trace in create_test_traces() {
        for level in [Level::Lossless, Level::Structural, Level::Skeleton] {
            let compressed = compress(&trace, level);

            assert!(
                validate_compressed(&compressed),
                "Certificate validation failed for level {:?} with {} events",
                level,
                trace.len()
            );

            // Certificate should match event count
            assert_eq!(
                compressed.certificate.event_count() as usize,
                compressed.events.len(),
                "Certificate event count mismatch for level {:?}",
                level
            );
        }
    }
}

/// MR4: Event Order Preservation
/// Property: Retained events maintain original temporal ordering
/// Category: Permutative (ordering relationships preserved)
#[test]
fn mr_event_order_preservation() {
    for trace in create_test_traces() {
        if trace.len() < 2 {
            continue;
        } // Skip traces too short for ordering tests

        for level in [Level::Lossless, Level::Structural, Level::Skeleton] {
            let compressed = compress(&trace, level);

            // Check that retained events maintain relative order
            for i in 1..compressed.events.len() {
                let prev_event = &compressed.events[i - 1];
                let curr_event = &compressed.events[i];

                assert!(
                    prev_event.seq < curr_event.seq,
                    "Event ordering violated: event {} (seq {}) appears before event {} (seq {}) for level {:?}",
                    i - 1,
                    prev_event.seq,
                    i,
                    curr_event.seq,
                    level
                );

                assert!(
                    prev_event.time <= curr_event.time,
                    "Timestamp ordering violated: event {} (time {:?}) appears before event {} (time {:?}) for level {:?}",
                    i - 1,
                    prev_event.time,
                    i,
                    curr_event.time,
                    level
                );
            }
        }
    }
}

/// MR5: Noise Event Elimination
/// Property: Noise events removed in structural/skeleton compression
/// Category: Exclusive (specific events should be filtered out)
#[test]
fn mr_noise_event_elimination() {
    let noise_events = [
        TraceEventKind::UserTrace,
        TraceEventKind::Wake,
        TraceEventKind::TimerScheduled,
        TraceEventKind::TimerFired,
    ];

    for trace in create_test_traces() {
        let structural = compress(&trace, Level::Structural);
        let skeleton = compress(&trace, Level::Skeleton);

        // Structural compression should remove noise events
        for event in &structural.events {
            assert!(
                !noise_events.contains(&event.kind),
                "Noise event {:?} found in structural compression",
                event.kind
            );
        }

        // Skeleton compression should also remove noise events
        for event in &skeleton.events {
            assert!(
                !noise_events.contains(&event.kind),
                "Noise event {:?} found in skeleton compression",
                event.kind
            );
        }

        // Lossless should retain noise events (if any in input)
        let lossless = compress(&trace, Level::Lossless);
        let original_noise_count = trace
            .iter()
            .filter(|e| noise_events.contains(&e.kind))
            .count();
        let lossless_noise_count = lossless
            .events
            .iter()
            .filter(|e| noise_events.contains(&e.kind))
            .count();

        assert_eq!(
            original_noise_count, lossless_noise_count,
            "Lossless compression changed noise event count"
        );
    }
}

/// MR6: Single Event Preservation
/// Property: Skeleton events survive skeleton compression
/// Category: Equivalence (skeleton events should be preserved)
#[test]
fn mr_single_event_preservation() {
    let skeleton_events = [
        TraceEventKind::Spawn,
        TraceEventKind::Complete,
        TraceEventKind::CancelRequest,
        TraceEventKind::CancelAck,
        TraceEventKind::ObligationReserve,
        TraceEventKind::ObligationCommit,
        TraceEventKind::ObligationAbort,
        TraceEventKind::RegionCreated,
        TraceEventKind::RegionCloseComplete,
    ];

    for trace in create_test_traces() {
        let skeleton_compressed = compress(&trace, Level::Skeleton);

        // Count skeleton events in original trace
        let original_skeleton_count = trace
            .iter()
            .filter(|e| skeleton_events.contains(&e.kind))
            .count();

        // All events in skeleton compression should be skeleton events
        for event in &skeleton_compressed.events {
            assert!(
                skeleton_events.contains(&event.kind),
                "Non-skeleton event {:?} found in skeleton compression",
                event.kind
            );
        }

        // Skeleton compression should preserve all skeleton events
        assert_eq!(
            original_skeleton_count,
            skeleton_compressed.events.len(),
            "Skeleton compression changed skeleton event count from {} to {}",
            original_skeleton_count,
            skeleton_compressed.events.len()
        );
    }
}

/// MR7: Event Count Consistency
/// Property: compressed.events.len() + compressed.events_removed() = original_count
/// Category: Additive (parts sum to whole)
#[test]
fn mr_event_count_consistency() {
    for trace in create_test_traces() {
        for level in [Level::Lossless, Level::Structural, Level::Skeleton] {
            let compressed = compress(&trace, level);

            assert_eq!(
                compressed.events.len() + compressed.events_removed(),
                compressed.original_count,
                "Event count consistency violated for level {:?}: {} + {} != {}",
                level,
                compressed.events.len(),
                compressed.events_removed(),
                compressed.original_count
            );

            assert_eq!(
                compressed.original_count,
                trace.len(),
                "Original count mismatch for level {:?}: {} != {}",
                level,
                compressed.original_count,
                trace.len()
            );

            // Compression ratio should be consistent
            let expected_ratio = if trace.is_empty() {
                1.0
            } else {
                compressed.events.len() as f64 / trace.len() as f64
            };

            assert!(
                (compressed.ratio() - expected_ratio).abs() < f64::EPSILON,
                "Compression ratio inconsistent for level {:?}: {} != {}",
                level,
                compressed.ratio(),
                expected_ratio
            );
        }
    }
}

/// MR8: Level-Specific Event Filtering
/// Property: Each compression level filters appropriate event types
/// Category: Exclusive (level-specific filtering behavior)
#[test]
fn mr_level_specific_event_filtering() {
    for trace in create_test_traces() {
        let lossless = compress(&trace, Level::Lossless);
        let structural = compress(&trace, Level::Structural);
        let skeleton = compress(&trace, Level::Skeleton);

        // Lossless should retain all events
        assert_eq!(
            lossless.events.len(),
            trace.len(),
            "Lossless compression should retain all events"
        );

        // If trace contains noise events, structural should remove them
        let noise_count = trace.iter().filter(|e| is_noise_event(e)).count();

        if noise_count > 0 {
            assert!(
                structural.events.len() < lossless.events.len(),
                "Structural compression should remove noise events when present"
            );
        }

        // If trace contains non-skeleton events, skeleton should remove them
        let non_skeleton_count = trace.iter().filter(|e| !is_skeleton_event(e)).count();

        if non_skeleton_count > 0 {
            assert!(
                skeleton.events.len() <= structural.events.len(),
                "Skeleton compression should remove non-skeleton events when present"
            );
        }
    }
}

/// Composite MR: Monotonicity + Idempotence + Certificate Consistency
/// Tests compound property: compression level ordering with idempotence and certificate validation
#[test]
fn mr_composite_monotonicity_idempotence_certificate() {
    for trace in create_test_traces() {
        // Apply all compression levels
        let lossless = compress(&trace, Level::Lossless);
        let structural = compress(&trace, Level::Structural);
        let skeleton = compress(&trace, Level::Skeleton);

        // MR1: Monotonicity
        assert!(skeleton.events.len() <= structural.events.len());
        assert!(structural.events.len() <= lossless.events.len());

        // MR2: Idempotence on each level
        for (level, compressed) in [
            (Level::Lossless, &lossless),
            (Level::Structural, &structural),
            (Level::Skeleton, &skeleton),
        ] {
            let double_compressed = compress(&compressed.events, level);
            assert_eq!(
                compressed.events, double_compressed.events,
                "Idempotence failed for level {:?}",
                level
            );
        }

        // MR3: Certificate consistency for all levels
        assert!(validate_compressed(&lossless));
        assert!(validate_compressed(&structural));
        assert!(validate_compressed(&skeleton));

        // Compound property: certificate hashes should be independent of compression path
        // (i.e., direct compression vs. stepwise compression should yield same certificate)
        let direct_skeleton = compress(&trace, Level::Skeleton);
        let stepwise_skeleton = compress(&structural.events, Level::Skeleton);

        if !trace.is_empty() {
            assert_eq!(
                direct_skeleton.events, stepwise_skeleton.events,
                "Direct vs stepwise skeleton compression should yield same events"
            );
        }
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    /// Mutation testing: verify MR suite catches planted bugs
    #[test]
    fn test_mr_suite_catches_mutations() {
        // We can't easily mutate the compress function without changing the source,
        // but we can test that our MRs would catch common compression bugs by
        // constructing invalid CompressedTrace objects and verifying our validation fails

        let trace = vec![
            TraceEvent::new(1, Time::ZERO, TraceEventKind::Spawn, TraceData::None),
            TraceEvent::new(
                2,
                Time::from_nanos(100),
                TraceEventKind::UserTrace,
                TraceData::None,
            ),
            TraceEvent::new(
                3,
                Time::from_nanos(200),
                TraceEventKind::Complete,
                TraceData::None,
            ),
        ];

        // Test certificate consistency catches certificate corruption
        let mut compressed = compress(&trace, Level::Structural);
        let mut bad_cert = compressed.certificate.clone();
        bad_cert.record_event(&TraceEvent::new(
            999,
            Time::ZERO,
            TraceEventKind::Wake,
            TraceData::None,
        ));
        compressed.certificate = bad_cert;

        assert!(
            !validate_compressed(&compressed),
            "Certificate consistency should catch corrupted certificate"
        );

        // Additional validation tests could be added here for specific bug classes
    }
}
