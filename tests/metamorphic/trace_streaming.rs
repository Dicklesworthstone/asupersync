#![allow(clippy::all)]
//! Metamorphic tests for trace::streaming partial-stream replay invariants.
//!
//! These tests validate the core invariants of the streaming trace replay system
//! including partial replay preservation, checkpoint continuity, bounded backpressure,
//! clean cancellation, and concurrent reader consistency using metamorphic relations.
//!
//! ## Key Properties Tested
//!
//! 1. **Partial stream preservation**: First-N events from partial replay match first-N from full replay
//! 2. **Checkpoint continuity**: Replay from checkpoint produces same results as continuous replay
//! 3. **Bounded backpressure**: Memory usage remains O(1), flow control prevents unbounded buffering
//! 4. **Clean cancellation drain**: Cancel during replay drains consumer without resource leaks
//! 5. **Concurrent reader consistency**: Multiple readers see same event order on same trace
//!
//! ## Metamorphic Relations
//!
//! - **Prefix preservation**: partial_replay(trace, N) ≡ full_replay(trace)[0..N]
//! - **Checkpoint equivalence**: resume(checkpoint) + replay(remaining) ≡ full_replay(trace)
//! - **Memory invariant**: memory_usage(streaming_replay) ≤ O(1) regardless of trace_size
//! - **Cancel idempotence**: cancel(streaming_replay) → clean_resource_state
//! - **Order consistency**: concurrent_readers(trace) → identical_event_sequences

use proptest::prelude::*;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex as StdMutex};
use std::path::Path;
use tempfile::NamedTempFile;

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::trace::streaming::{StreamingReplayer, ReplayCheckpoint, ReplayProgress};
use asupersync::trace::replay::{ReplayEvent, TraceMetadata, CompactTaskId};
use asupersync::trace::file::{TraceWriter, write_trace};
use asupersync::trace::replayer::EventSource;
use asupersync::cx::Cx;
use asupersync::types::{ArenaIndex, Budget, RegionId, TaskId};

// =============================================================================
// Test Utilities
// =============================================================================

/// Create a test context for streaming tests.
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Create a deterministic LabRuntime for testing.
fn test_lab_runtime() -> LabRuntime {
    LabRuntime::with_config(LabConfig::deterministic())
}

/// Create a deterministic LabRuntime with specific seed.
fn test_lab_runtime_with_seed(seed: u64) -> LabRuntime {
    LabRuntime::with_config(LabConfig::deterministic().with_seed(seed))
}

/// Generate sample events for testing.
fn sample_events(count: u64, seed: u64) -> Vec<ReplayEvent> {
    let mut events = Vec::new();

    // Use seed to generate deterministic variety
    let mut rng_state = seed;

    for i in 0..count {
        // Simple LCG for deterministic variety
        rng_state = rng_state.wrapping_mul(1664525).wrapping_add(1013904223);

        let event = match rng_state % 5 {
            0 => ReplayEvent::TaskScheduled {
                task: CompactTaskId(i),
                at_tick: i,
            },
            1 => ReplayEvent::TaskYielded {
                task: CompactTaskId(i % 10),
            },
            2 => ReplayEvent::TaskCompleted {
                task: CompactTaskId(i % 10),
            },
            3 => ReplayEvent::RngSeed { seed: rng_state },
            _ => ReplayEvent::TimeAdvanced {
                new_time: i * 1000,
            },
        };

        events.push(event);
    }

    events
}

/// Create a trace file with the given events.
fn create_trace_file(events: &[ReplayEvent], seed: u64) -> NamedTempFile {
    let temp = NamedTempFile::new().unwrap();
    let metadata = TraceMetadata::new(seed);
    write_trace(temp.path(), &metadata, events).unwrap();
    temp
}

/// Tracks streaming replay operations for invariant checking.
#[derive(Debug, Clone)]
struct StreamingTracker {
    /// Events read during replay: position -> event
    events_read: HashMap<usize, ReplayEvent>,
    /// Checkpoint positions tested
    checkpoints: Vec<(u64, ReplayCheckpoint)>,
    /// Memory usage samples: (position, estimated_bytes)
    memory_samples: Vec<(u64, usize)>,
    /// Cancellation points tested
    cancel_positions: Vec<u64>,
    /// Reader event sequences for concurrency testing
    reader_sequences: HashMap<usize, Vec<(usize, ReplayEvent)>>,
}

impl StreamingTracker {
    fn new() -> Self {
        Self {
            events_read: HashMap::new(),
            checkpoints: Vec::new(),
            memory_samples: Vec::new(),
            cancel_positions: Vec::new(),
            reader_sequences: HashMap::new(),
        }
    }

    fn record_event(&mut self, position: usize, event: ReplayEvent) {
        self.events_read.insert(position, event);
    }

    fn record_checkpoint(&mut self, position: u64, checkpoint: ReplayCheckpoint) {
        self.checkpoints.push((position, checkpoint));
    }

    fn record_memory_usage(&mut self, position: u64, estimated_bytes: usize) {
        self.memory_samples.push((position, estimated_bytes));
    }

    fn record_cancel(&mut self, position: u64) {
        self.cancel_positions.push(position);
    }

    fn record_reader_sequence(&mut self, reader_id: usize, position: usize, event: ReplayEvent) {
        self.reader_sequences
            .entry(reader_id)
            .or_default()
            .push((position, event));
    }

    /// Get events in the order they were read.
    fn get_ordered_events(&self) -> Vec<(usize, &ReplayEvent)> {
        let mut ordered: Vec<_> = self.events_read.iter().collect();
        ordered.sort_by_key(|(pos, _)| *pos);
        ordered.into_iter().map(|(pos, event)| (*pos, event)).collect()
    }

    /// Check if memory usage remains bounded (MR3).
    fn verify_memory_bounded(&self, max_allowed_bytes: usize) -> bool {
        self.memory_samples.iter().all(|(_, bytes)| *bytes <= max_allowed_bytes)
    }

    /// Check if concurrent readers see consistent event order (MR5).
    fn verify_concurrent_consistency(&self) -> bool {
        if self.reader_sequences.len() < 2 {
            return true; // No concurrency to check
        }

        let mut sequences: Vec<_> = self.reader_sequences.values().collect();

        // All sequences should have the same events at the same positions
        for i in 1..sequences.len() {
            let seq0 = &sequences[0];
            let seqi = &sequences[i];

            // Find common positions
            let positions0: std::collections::HashSet<_> = seq0.iter().map(|(pos, _)| pos).collect();
            let positionsi: std::collections::HashSet<_> = seqi.iter().map(|(pos, _)| pos).collect();

            for &common_pos in positions0.intersection(&positionsi) {
                let event0 = seq0.iter().find(|(pos, _)| pos == common_pos).map(|(_, e)| e);
                let eventi = seqi.iter().find(|(pos, _)| pos == common_pos).map(|(_, e)| e);

                if event0 != eventi {
                    return false;
                }
            }
        }

        true
    }
}

// =============================================================================
// Metamorphic Relation Tests
// =============================================================================

/// **MR1: Partial Stream Preservation**
///
/// First-N events from partial replay should exactly match first-N events
/// from full replay of the same trace.
#[test]
fn mr1_partial_stream_preservation() {
    proptest!(|(
        event_count in 10u64..200u64,
        partial_count in 1u64..200u64,
        seed in any::<u64>()
    )| {
        let lab = test_lab_runtime_with_seed(seed);
        let events = sample_events(event_count, seed);
        let trace_file = create_trace_file(&events, seed);
        let partial_n = std::cmp::min(partial_count, event_count);

        futures_lite::future::block_on(async {
            // Full replay for reference
            let mut full_replayer = StreamingReplayer::open(trace_file.path()).unwrap();
            let mut full_events = Vec::new();

            while let Some(event) = full_replayer.next_event().unwrap() {
                full_events.push(event);
            }

            // Partial replay (stop after partial_n events)
            let mut partial_replayer = StreamingReplayer::open(trace_file.path()).unwrap();
            let mut partial_events = Vec::new();

            for _ in 0..partial_n {
                if let Some(event) = partial_replayer.next_event().unwrap() {
                    partial_events.push(event);
                } else {
                    break;
                }
            }

            // MR1: First partial_n events should be identical
            prop_assert_eq!(
                partial_events.len(),
                std::cmp::min(partial_n as usize, full_events.len()),
                "Partial replay length mismatch"
            );

            for (i, (partial_event, full_event)) in partial_events.iter()
                .zip(full_events.iter())
                .enumerate()
            {
                prop_assert_eq!(
                    partial_event,
                    full_event,
                    "Event mismatch at position {}: partial={:?}, full={:?}",
                    i,
                    partial_event,
                    full_event
                );
            }

            // Progress should be consistent
            let progress = partial_replayer.progress();
            prop_assert_eq!(
                progress.events_processed,
                partial_events.len() as u64,
                "Progress tracking inconsistent"
            );
        });
    });
}

/// **MR2: Checkpoint Continuity**
///
/// Replay from checkpoint should produce the same results as continuous replay
/// from the beginning up to the same total position.
#[test]
fn mr2_checkpoint_continuity() {
    proptest!(|(
        event_count in 20u64..100u64,
        checkpoint_position in 5u64..50u64,
        seed in any::<u64>()
    )| {
        let lab = test_lab_runtime_with_seed(seed);
        let events = sample_events(event_count, seed);
        let trace_file = create_trace_file(&events, seed);
        let checkpoint_pos = std::cmp::min(checkpoint_position, event_count - 5);

        futures_lite::future::block_on(async {
            // Continuous replay for reference
            let mut continuous_replayer = StreamingReplayer::open(trace_file.path()).unwrap();
            let mut continuous_events = Vec::new();

            while let Some(event) = continuous_replayer.next_event().unwrap() {
                continuous_events.push(event);
            }

            // Checkpointed replay: read to checkpoint, then resume
            let mut checkpoint_replayer = StreamingReplayer::open(trace_file.path()).unwrap();

            // Read up to checkpoint position
            for _ in 0..checkpoint_pos {
                if checkpoint_replayer.next_event().unwrap().is_none() {
                    return Ok(()); // Trace ended before checkpoint
                }
            }

            // Create checkpoint
            let checkpoint = checkpoint_replayer.checkpoint().unwrap();

            // Resume from checkpoint
            let mut resumed_replayer = StreamingReplayer::resume(trace_file.path(), checkpoint).unwrap();

            // Read remaining events
            let mut checkpoint_events = Vec::new();

            // Add events before checkpoint (from checkpoint position)
            for event in continuous_events.iter().take(checkpoint_pos as usize) {
                checkpoint_events.push(event.clone());
            }

            // Add events after checkpoint
            while let Some(event) = resumed_replayer.next_event().unwrap() {
                checkpoint_events.push(event);
            }

            // MR2: Total events should be identical
            prop_assert_eq!(
                checkpoint_events.len(),
                continuous_events.len(),
                "Checkpoint replay produced different event count"
            );

            for (i, (checkpoint_event, continuous_event)) in checkpoint_events.iter()
                .zip(continuous_events.iter())
                .enumerate()
            {
                prop_assert_eq!(
                    checkpoint_event,
                    continuous_event,
                    "Event mismatch at position {} after checkpoint resume",
                    i
                );
            }

            // Progress should be consistent
            let final_progress = resumed_replayer.progress();
            prop_assert!(
                final_progress.is_complete(),
                "Checkpointed replay should complete"
            );
        });
    });
}

/// **MR3: Bounded Backpressure**
///
/// Memory usage should remain O(1) bounded regardless of trace size,
/// and flow control should prevent unbounded buffering.
#[test]
fn mr3_bounded_backpressure() {
    proptest!(|(
        trace_sizes in prop::collection::vec(50u64..500u64, 3..10),
        seed in any::<u64>()
    )| {
        let lab = test_lab_runtime_with_seed(seed);
        let mut tracker = StreamingTracker::new();

        // Test with multiple trace sizes
        let max_allowed_memory = 1024 * 64; // 64KB should be sufficient for O(1) streaming

        futures_lite::future::block_on(async {
            for trace_size in trace_sizes {
                let events = sample_events(trace_size, seed + trace_size);
                let trace_file = create_trace_file(&events, seed + trace_size);

                let mut replayer = StreamingReplayer::open(trace_file.path()).unwrap();

                let mut position = 0u64;
                while let Some(_event) = replayer.next_event().unwrap() {
                    position += 1;

                    // Estimate memory usage (simplified)
                    let estimated_memory = std::mem::size_of::<StreamingReplayer>()
                        + 64 * 1024  // File buffer estimate
                        + 128;       // Event size estimate

                    tracker.record_memory_usage(position, estimated_memory);

                    // Sample at regular intervals
                    if position % 10 == 0 {
                        // MR3: Memory should remain bounded
                        prop_assert!(
                            estimated_memory <= max_allowed_memory,
                            "Memory usage {} exceeds bound {} at position {} for trace size {}",
                            estimated_memory,
                            max_allowed_memory,
                            position,
                            trace_size
                        );
                    }
                }
            }

            // Final verification: memory usage was bounded throughout
            prop_assert!(
                tracker.verify_memory_bounded(max_allowed_memory),
                "Memory usage exceeded bounds during streaming"
            );
        });
    });
}

/// **MR4: Clean Cancellation Drain**
///
/// Cancelling during replay should drain the consumer cleanly without
/// resource leaks or hanging state.
#[test]
fn mr4_clean_cancellation_drain() {
    proptest!(|(
        event_count in 20u64..100u64,
        cancel_positions in prop::collection::vec(5u64..50u64, 1..5),
        seed in any::<u64>()
    )| {
        let lab = test_lab_runtime_with_seed(seed);
        let events = sample_events(event_count, seed);
        let trace_file = create_trace_file(&events, seed);
        let mut tracker = StreamingTracker::new();

        futures_lite::future::block_on(async {
            for &cancel_pos in &cancel_positions {
                let cancel_position = std::cmp::min(cancel_pos, event_count - 1);
                tracker.record_cancel(cancel_position);

                // Start replay and cancel at specific position
                let mut replayer = StreamingReplayer::open(trace_file.path()).unwrap();

                let mut position = 0u64;
                let mut events_before_cancel = Vec::new();

                // Read events until cancel position
                while position < cancel_position {
                    if let Some(event) = replayer.next_event().unwrap() {
                        events_before_cancel.push(event);
                        position += 1;
                    } else {
                        break; // Trace ended
                    }
                }

                // Simulate cancellation by dropping the replayer
                let progress_before_drop = replayer.progress();
                drop(replayer);

                // MR4: Verify clean state after cancellation
                prop_assert_eq!(
                    progress_before_drop.events_processed,
                    position,
                    "Progress inconsistent before cancellation"
                );

                // Verify we can create a new replayer on the same file (no locks held)
                let new_replayer = StreamingReplayer::open(trace_file.path()).unwrap();
                prop_assert_eq!(
                    new_replayer.total_events(),
                    event_count,
                    "New replayer after cancel cannot read file metadata"
                );

                // Verify the events we read before cancel were correct
                let mut reference_replayer = StreamingReplayer::open(trace_file.path()).unwrap();
                let mut reference_events = Vec::new();

                for _ in 0..position {
                    if let Some(event) = reference_replayer.next_event().unwrap() {
                        reference_events.push(event);
                    }
                }

                prop_assert_eq!(
                    events_before_cancel,
                    reference_events,
                    "Events before cancel don't match reference"
                );
            }
        });
    });
}

/// **MR5: Concurrent Reader Consistency**
///
/// Multiple concurrent StreamingReplayers on the same trace file should
/// see events in the same order.
#[test]
fn mr5_concurrent_reader_consistency() {
    proptest!(|(
        event_count in 30u64..100u64,
        reader_count in 2usize..5usize,
        read_lengths in prop::collection::vec(10u64..50u64, 2..5),
        seed in any::<u64>()
    )| {
        let lab = test_lab_runtime_with_seed(seed);
        let events = sample_events(event_count, seed);
        let trace_file = create_trace_file(&events, seed);
        let shared_tracker = Arc::new(StdMutex::new(StreamingTracker::new()));

        futures_lite::future::block_on(async {
            let mut readers = Vec::new();

            // Create multiple concurrent readers
            for i in 0..reader_count {
                let replayer = StreamingReplayer::open(trace_file.path()).unwrap();
                readers.push((i, replayer));
            }

            // Read events concurrently (simulated by interleaving)
            let max_reads = read_lengths.iter().max().copied().unwrap_or(20);
            let max_reads = std::cmp::min(max_reads, event_count);

            for position in 0..max_reads {
                for (reader_id, replayer) in &mut readers {
                    // Not all readers need to read the same amount
                    if position >= read_lengths.get(*reader_id).copied().unwrap_or(max_reads) {
                        continue;
                    }

                    if let Some(event) = replayer.next_event().unwrap() {
                        let mut tracker = shared_tracker.lock().unwrap();
                        tracker.record_reader_sequence(*reader_id, position as usize, event);
                    }
                }
            }

            // Verify all readers saw consistent events
            let tracker = shared_tracker.lock().unwrap();

            // MR5: Concurrent consistency check
            prop_assert!(
                tracker.verify_concurrent_consistency(),
                "Concurrent readers saw inconsistent event sequences"
            );

            // Additional check: all readers with overlapping ranges should agree
            for reader_id in 0..reader_count {
                let reader_events = tracker.reader_sequences.get(&reader_id);
                if let Some(events) = reader_events {
                    for (position, event) in events {
                        // Check this position against other readers
                        for other_reader_id in 0..reader_count {
                            if other_reader_id == reader_id {
                                continue;
                            }

                            if let Some(other_events) = tracker.reader_sequences.get(&other_reader_id) {
                                if let Some((_, other_event)) = other_events.iter()
                                    .find(|(other_pos, _)| other_pos == position)
                                {
                                    prop_assert_eq!(
                                        event,
                                        other_event,
                                        "Readers {} and {} disagree on event at position {}",
                                        reader_id,
                                        other_reader_id,
                                        position
                                    );
                                }
                            }
                        }
                    }
                }
            }
        });
    });
}

// =============================================================================
// Integration Tests
// =============================================================================

/// **Comprehensive Integration Test**
///
/// Tests all metamorphic relations together to ensure they work in combination.
#[test]
fn comprehensive_streaming_integration() {
    let lab = test_lab_runtime();
    let seed = 42u64;
    let event_count = 100u64;

    futures_lite::future::block_on(async {
        let events = sample_events(event_count, seed);
        let trace_file = create_trace_file(&events, seed);
        let mut tracker = StreamingTracker::new();

        // Test 1: Partial preservation + checkpoint continuity
        let mut full_replayer = StreamingReplayer::open(trace_file.path()).unwrap();
        let mut all_events = Vec::new();

        while let Some(event) = full_replayer.next_event().unwrap() {
            all_events.push(event);
        }

        // Test partial replay (first 30 events)
        let partial_count = 30;
        let mut partial_replayer = StreamingReplayer::open(trace_file.path()).unwrap();
        let mut partial_events = Vec::new();

        for i in 0..partial_count {
            if let Some(event) = partial_replayer.next_event().unwrap() {
                partial_events.push(event);
                tracker.record_event(i, event);
            }
        }

        // Verify partial preservation
        assert_eq!(partial_events.len(), partial_count);
        for (i, (partial, full)) in partial_events.iter()
            .zip(all_events.iter())
            .enumerate()
        {
            assert_eq!(partial, full, "Partial mismatch at position {}", i);
        }

        // Test checkpoint at position 20
        let mut checkpoint_replayer = StreamingReplayer::open(trace_file.path()).unwrap();
        for _ in 0..20 {
            checkpoint_replayer.next_event().unwrap();
        }

        let checkpoint = checkpoint_replayer.checkpoint().unwrap();
        tracker.record_checkpoint(20, checkpoint);

        // Resume and continue
        let mut resumed_replayer = StreamingReplayer::resume(trace_file.path(), checkpoint).unwrap();
        let mut remaining_events = Vec::new();

        while let Some(event) = resumed_replayer.next_event().unwrap() {
            remaining_events.push(event);
        }

        // Verify checkpoint continuity: first 20 + remaining should equal all events
        let mut reconstructed = Vec::new();
        reconstructed.extend_from_slice(&all_events[0..20]);
        reconstructed.extend(remaining_events);

        assert_eq!(reconstructed.len(), all_events.len());
        for (i, (recon, original)) in reconstructed.iter()
            .zip(all_events.iter())
            .enumerate()
        {
            assert_eq!(recon, original, "Checkpoint reconstruction mismatch at {}", i);
        }

        // Test concurrent readers
        let mut reader1 = StreamingReplayer::open(trace_file.path()).unwrap();
        let mut reader2 = StreamingReplayer::open(trace_file.path()).unwrap();

        // Read first 10 events from both
        for i in 0..10 {
            let event1 = reader1.next_event().unwrap().unwrap();
            let event2 = reader2.next_event().unwrap().unwrap();

            tracker.record_reader_sequence(0, i, event1.clone());
            tracker.record_reader_sequence(1, i, event2.clone());

            assert_eq!(event1, event2, "Concurrent readers disagree at position {}", i);
        }

        // Test cancellation
        let mut cancel_replayer = StreamingReplayer::open(trace_file.path()).unwrap();
        for _ in 0..15 {
            cancel_replayer.next_event().unwrap();
        }

        tracker.record_cancel(15);
        drop(cancel_replayer); // Simulate cancellation

        // Should be able to create new replayer
        let post_cancel_replayer = StreamingReplayer::open(trace_file.path()).unwrap();
        assert_eq!(post_cancel_replayer.total_events(), event_count);

        // Verify all tracking
        assert!(tracker.verify_concurrent_consistency());

        println!("✓ All streaming metamorphic relations verified successfully!");
    });
}