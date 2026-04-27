#![allow(warnings)]
#![allow(clippy::all)]
//! Golden tests for trace canonicalizer Foata normal form vectors.
//!
//! Tests deterministic canonicalization of trace event sequences into Foata normal forms.
//! These golden vectors capture the exact canonical output for specific input patterns
//! to detect regressions in the canonicalization algorithm.

use asupersync::monitor::DownReason;
use asupersync::record::{ObligationAbortReason, ObligationKind};
use asupersync::trace::canonicalize::{TraceEventKey, canonicalize, trace_event_key};
use asupersync::trace::event::{TraceData, TraceEvent, TraceEventKind};
use asupersync::types::{CancelReason, ObligationId, RegionId, TaskId, Time};
use insta::assert_json_snapshot;
use serde::Serialize;

/// Golden snapshot format for trace canonicalization results.
#[derive(Debug, Serialize)]
struct TraceCanonicalizeGolden {
    /// Test scenario name.
    scenario: &'static str,
    /// Input event sequence metadata.
    input_metadata: TraceInputMetadata,
    /// Canonical Foata normal form result.
    canonical_output: FoataGoldenSnapshot,
}

/// Metadata about the input trace sequence.
#[derive(Debug, Serialize)]
struct TraceInputMetadata {
    /// Number of input events.
    event_count: usize,
    /// Event kinds present in input order.
    event_kinds: Vec<&'static str>,
    /// Number of unique tasks referenced.
    unique_tasks: usize,
    /// Number of unique regions referenced.
    unique_regions: usize,
    /// Input sequence description.
    description: &'static str,
}

/// Golden snapshot of Foata normal form output.
#[derive(Debug, Serialize)]
struct FoataGoldenSnapshot {
    /// Number of layers (critical path depth).
    depth: usize,
    /// Total number of events.
    len: usize,
    /// Layer-by-layer canonical form.
    layers: Vec<Vec<EventGoldenSnapshot>>,
    /// Independence statistics.
    independence_stats: IndependenceStats,
}

/// Golden snapshot of a canonical trace event.
#[derive(Debug, Serialize)]
struct EventGoldenSnapshot {
    /// Original sequence number.
    seq: u64,
    /// Timestamp in nanoseconds.
    time_ns: u64,
    /// Event kind stable name.
    kind: &'static str,
    /// Canonical sort key.
    sort_key: TraceEventKey,
    /// Structured event data.
    data_summary: String,
}

/// Independence relationship statistics.
#[derive(Debug, Serialize)]
struct IndependenceStats {
    /// Number of layers (= depth).
    layer_count: usize,
    /// Events per layer.
    events_per_layer: Vec<usize>,
    /// Maximum layer width (parallelism).
    max_parallelism: usize,
    /// Total independent pairs.
    independent_pairs: usize,
}

// Helper functions for creating test IDs
fn tid(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}

fn rid(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

fn oid(n: u32) -> ObligationId {
    ObligationId::new_for_test(n, 0)
}

/// Create golden snapshot from trace events.
fn create_golden_snapshot(
    scenario: &'static str,
    description: &'static str,
    events: &[TraceEvent],
) -> TraceCanonicalizeGolden {
    let foata = canonicalize(events);

    // Extract unique tasks and regions
    let mut unique_tasks = std::collections::BTreeSet::new();
    let mut unique_regions = std::collections::BTreeSet::new();

    for event in events {
        match &event.data {
            TraceData::Task { task, region } => {
                unique_tasks.insert(*task);
                unique_regions.insert(*region);
            }
            TraceData::Region { region, parent } => {
                unique_regions.insert(*region);
                if let Some(parent) = parent {
                    unique_regions.insert(*parent);
                }
            }
            TraceData::Obligation { task, region, .. } => {
                unique_tasks.insert(*task);
                unique_regions.insert(*region);
            }
            TraceData::Cancel { task, region, .. } => {
                unique_tasks.insert(*task);
                unique_regions.insert(*region);
            }
            TraceData::Worker { task, region, .. } => {
                unique_tasks.insert(*task);
                unique_regions.insert(*region);
            }
            TraceData::Futurelock { task, region, .. } => {
                unique_tasks.insert(*task);
                unique_regions.insert(*region);
            }
            _ => {}
        }
    }

    let input_metadata = TraceInputMetadata {
        event_count: events.len(),
        event_kinds: events.iter().map(|e| e.kind.stable_name()).collect(),
        unique_tasks: unique_tasks.len(),
        unique_regions: unique_regions.len(),
        description,
    };

    // Calculate independence stats
    let events_per_layer: Vec<usize> = foata.layers().iter().map(|layer| layer.len()).collect();
    let max_parallelism = events_per_layer.iter().copied().max().unwrap_or(0);

    // Count independent pairs (events in the same layer)
    let independent_pairs = events_per_layer
        .iter()
        .map(|&n| n * (n.saturating_sub(1)) / 2)
        .sum();

    let independence_stats = IndependenceStats {
        layer_count: foata.depth(),
        events_per_layer,
        max_parallelism,
        independent_pairs,
    };

    let canonical_output = FoataGoldenSnapshot {
        depth: foata.depth(),
        len: foata.len(),
        layers: foata
            .layers()
            .iter()
            .map(|layer| {
                layer
                    .iter()
                    .map(|event| EventGoldenSnapshot {
                        seq: event.seq,
                        time_ns: event.time.as_nanos(),
                        kind: event.kind.stable_name(),
                        sort_key: trace_event_key(event),
                        data_summary: summarize_event_data(&event.data),
                    })
                    .collect()
            })
            .collect(),
        independence_stats,
    };

    TraceCanonicalizeGolden {
        scenario,
        input_metadata,
        canonical_output,
    }
}

/// Create a concise summary of event data for golden snapshots.
fn summarize_event_data(data: &TraceData) -> String {
    match data {
        TraceData::None => "none".to_string(),
        TraceData::Task { task, region } => {
            format!("T{}/R{}", task.as_u64(), region.as_u64())
        }
        TraceData::Region { region, parent } => {
            format!(
                "R{}/P{}",
                region.as_u64(),
                parent.map_or_else(|| "none".to_string(), |r| r.as_u64().to_string())
            )
        }
        TraceData::Obligation {
            obligation,
            task,
            region,
            kind,
            ..
        } => {
            format!(
                "O{}/T{}/R{}/{}",
                obligation.arena_index().index(),
                task.as_u64(),
                region.as_u64(),
                kind.as_str()
            )
        }
        TraceData::Cancel { task, region, .. } => {
            format!("T{}/R{}/cancel", task.as_u64(), region.as_u64())
        }
        TraceData::Worker { task, region, .. } => {
            format!("T{}/R{}/worker", task.as_u64(), region.as_u64())
        }
        TraceData::RegionCancel { region, .. } => {
            format!("R{}/cancel", region.as_u64())
        }
        TraceData::Timer { timer_id, .. } => {
            format!("timer/{}", timer_id)
        }
        TraceData::Monitor {
            watcher, monitored, ..
        } => {
            format!("monitor/W{}/M{}", watcher.as_u64(), monitored.as_u64())
        }
        TraceData::Down {
            watcher, monitored, ..
        } => {
            format!("down/W{}/M{}", watcher.as_u64(), monitored.as_u64())
        }
        TraceData::Link { task_a, task_b, .. } => {
            format!("link/T{}/T{}", task_a.as_u64(), task_b.as_u64())
        }
        TraceData::Exit { from, to, .. } => {
            format!("exit/F{}/T{}", from.as_u64(), to.as_u64())
        }
        TraceData::RngValue { value } => {
            format!("rng/{}", value)
        }
        TraceData::RngSeed { seed } => {
            format!("rng_seed/{}", seed)
        }
        TraceData::Time { .. } => "time".to_string(),
        TraceData::IoRequested { token, .. } => {
            format!("io_req/{}", token)
        }
        TraceData::IoReady { token, .. } => {
            format!("io_ready/{}", token)
        }
        TraceData::IoResult { token, bytes } => {
            format!("io_result/{}/{}", token, bytes)
        }
        TraceData::IoError { token, .. } => {
            format!("io_error/{}", token)
        }
        TraceData::Chaos { kind, .. } => {
            format!("chaos/{}", kind)
        }
        TraceData::Checkpoint { sequence, .. } => {
            format!("checkpoint/{}", sequence)
        }
        TraceData::Futurelock { task, region, .. } => {
            format!("T{}/R{}/futurelock", task.as_u64(), region.as_u64())
        }
        TraceData::Message(msg) => {
            format!("msg/{}", msg)
        }
    }
}

// ============================================================================
// Golden Test Cases
// ============================================================================

#[test]
fn golden_empty_trace() {
    let events = [];
    let golden = create_golden_snapshot(
        "empty_trace",
        "Empty trace sequence - boundary case",
        &events,
    );
    assert_json_snapshot!("trace_canonicalize_empty", golden);
}

#[test]
fn golden_single_event() {
    let events = [TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1))];
    let golden = create_golden_snapshot(
        "single_event",
        "Single event - minimal valid trace",
        &events,
    );
    assert_json_snapshot!("trace_canonicalize_single", golden);
}

#[test]
fn golden_fully_independent_events() {
    // Multiple spawns in different regions - all independent
    let events = [
        TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
        TraceEvent::spawn(2, Time::from_nanos(1), tid(2), rid(2)),
        TraceEvent::spawn(3, Time::from_nanos(2), tid(3), rid(3)),
        TraceEvent::spawn(4, Time::from_nanos(3), tid(4), rid(4)),
    ];
    let golden = create_golden_snapshot(
        "fully_independent",
        "Four independent task spawns in different regions - maximum parallelism",
        &events,
    );
    assert_json_snapshot!("trace_canonicalize_independent", golden);
}

#[test]
fn golden_sequential_dependency_chain() {
    // Same task: spawn -> poll -> complete
    let events = [
        TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
        TraceEvent::poll(2, Time::from_nanos(1), tid(1), rid(1)),
        TraceEvent::complete(3, Time::from_nanos(2), tid(1), rid(1)),
    ];
    let golden = create_golden_snapshot(
        "sequential_chain",
        "Task lifecycle dependency chain - no parallelism",
        &events,
    );
    assert_json_snapshot!("trace_canonicalize_sequential", golden);
}

#[test]
fn golden_diamond_dependency_pattern() {
    // Diamond: Region create -> (T1 spawn || T2 spawn) -> (T1 complete || T2 complete) -> Region close
    let events = [
        TraceEvent::region_created(1, Time::ZERO, rid(1), None),
        TraceEvent::spawn(2, Time::from_nanos(1), tid(1), rid(1)),
        TraceEvent::spawn(3, Time::from_nanos(2), tid(2), rid(1)),
        TraceEvent::complete(4, Time::from_nanos(3), tid(1), rid(1)),
        TraceEvent::complete(5, Time::from_nanos(4), tid(2), rid(1)),
        TraceEvent::new(
            6,
            Time::from_nanos(5),
            TraceEventKind::RegionCloseComplete,
            TraceData::Region {
                region: rid(1),
                parent: None,
            },
        ),
    ];
    let golden = create_golden_snapshot(
        "diamond_dependency",
        "Diamond pattern: shared setup/teardown with parallel middle",
        &events,
    );
    assert_json_snapshot!("trace_canonicalize_diamond", golden);
}

#[test]
fn golden_cancellation_propagation() {
    // Cancel request -> ack -> obligation abort -> region cancel
    let cancel = CancelReason::timeout();
    let events = [
        TraceEvent::region_created(1, Time::ZERO, rid(1), None),
        TraceEvent::spawn(2, Time::from_nanos(1), tid(1), rid(1)),
        TraceEvent::obligation_reserve(
            3,
            Time::from_nanos(2),
            oid(1),
            tid(1),
            rid(1),
            ObligationKind::SendPermit,
        ),
        TraceEvent::cancel_request(4, Time::from_nanos(3), tid(1), rid(1), cancel.clone()),
        TraceEvent::new(
            5,
            Time::from_nanos(4),
            TraceEventKind::CancelAck,
            TraceData::Cancel {
                task: tid(1),
                region: rid(1),
                reason: cancel.clone(),
            },
        ),
        TraceEvent::obligation_abort(
            6,
            Time::from_nanos(5),
            oid(1),
            tid(1),
            rid(1),
            ObligationKind::SendPermit,
            100,
            ObligationAbortReason::Cancel,
        ),
        TraceEvent::region_cancelled(7, Time::from_nanos(6), rid(1), cancel),
    ];
    let golden = create_golden_snapshot(
        "cancellation_chain",
        "Cancellation protocol propagation chain",
        &events,
    );
    assert_json_snapshot!("trace_canonicalize_cancellation", golden);
}

#[test]
fn golden_mixed_parallelism_pattern() {
    // Complex pattern with multiple regions and mixed dependencies
    let events = [
        // Layer 0: Independent region creation
        TraceEvent::region_created(1, Time::ZERO, rid(1), None),
        TraceEvent::region_created(2, Time::ZERO, rid(2), None),
        // Layer 1: Independent spawns within regions
        TraceEvent::spawn(3, Time::from_nanos(1), tid(1), rid(1)),
        TraceEvent::spawn(4, Time::from_nanos(1), tid(2), rid(1)),
        TraceEvent::spawn(5, Time::from_nanos(1), tid(3), rid(2)),
        // Layer 2: T1 and T3 poll (independent), T2 depends on T1
        TraceEvent::poll(6, Time::from_nanos(2), tid(1), rid(1)),
        TraceEvent::poll(7, Time::from_nanos(2), tid(3), rid(2)),
        // Layer 3: T1 completes, enables T2 to poll
        TraceEvent::complete(8, Time::from_nanos(3), tid(1), rid(1)),
        // Layer 4: T2 can now poll, T3 still independent
        TraceEvent::poll(9, Time::from_nanos(4), tid(2), rid(1)),
        TraceEvent::complete(10, Time::from_nanos(4), tid(3), rid(2)),
        // Layer 5: T2 completes
        TraceEvent::complete(11, Time::from_nanos(5), tid(2), rid(1)),
        // Layer 6: Regions close
        TraceEvent::new(
            12,
            Time::from_nanos(6),
            TraceEventKind::RegionCloseComplete,
            TraceData::Region {
                region: rid(1),
                parent: None,
            },
        ),
        TraceEvent::new(
            13,
            Time::from_nanos(6),
            TraceEventKind::RegionCloseComplete,
            TraceData::Region {
                region: rid(2),
                parent: None,
            },
        ),
    ];
    let golden = create_golden_snapshot(
        "mixed_parallelism",
        "Complex mixed parallel and sequential dependencies across multiple regions",
        &events,
    );
    assert_json_snapshot!("trace_canonicalize_mixed", golden);
}

#[test]
fn golden_large_parallel_burst() {
    // Boundary case: many independent events in one layer
    let mut events = vec![TraceEvent::region_created(1, Time::ZERO, rid(1), None)];

    // Add 16 independent spawns in different regions
    for i in 2..18u64 {
        events.push(TraceEvent::spawn(
            i,
            Time::from_nanos(1),
            tid(i as u32),
            rid(i as u32),
        ));
    }

    let golden = create_golden_snapshot(
        "large_parallel_burst",
        "Boundary case: large burst of independent events - stress test parallelism detection",
        &events,
    );
    assert_json_snapshot!("trace_canonicalize_large_parallel", golden);
}
