//! Integration tests for distributed, trace, and remote module invariants.
//!
//! Covers gaps identified in bd-3q6f: causality verification edge cases,
//! certificate determinism, replay serialization roundtrips, snapshot
//! binary format stability, bridge state machine transitions, and remote
//! API surface contracts.

mod common;

use asupersync::distributed::bridge::{
    BridgeConfig, ConflictResolution, EffectiveState, RegionMode, SyncMode,
};
use asupersync::distributed::snapshot::{
    BudgetSnapshot, RegionSnapshot, SnapshotError, TaskSnapshot, TaskState,
};
use asupersync::record::region::RegionState;
use asupersync::remote::{
    ComputationName, DedupDecision, IdempotencyKey, IdempotencyStore, NodeId, RemoteCap,
    RemoteError, RemoteInput, RemoteOutcome, RemoteTaskId, RemoteTaskState, Saga, SagaState,
};
use asupersync::trace::causality::{CausalOrderVerifier, CausalityViolationKind};
use asupersync::trace::certificate::{CertificateVerifier, TraceCertificate};
use asupersync::trace::compat::{
    check_schema_compatibility, CompatStats, CompatibilityResult, TraceMigrator,
};
use asupersync::trace::distributed::{LamportClock, LogicalTime, VectorClock};
use asupersync::trace::event::{TraceData, TraceEvent, TraceEventKind};
use asupersync::trace::geodesic::{
    count_switches, is_valid_linear_extension, normalize, GeodesicConfig,
};
use asupersync::trace::replay::{
    CompactRegionId, CompactTaskId, ReplayEvent, ReplayTrace, TraceMetadata, REPLAY_SCHEMA_VERSION,
};
use asupersync::trace::replayer::{Breakpoint, ReplayMode, TraceReplayer};
use asupersync::types::{CancelReason, RegionId, TaskId, Time};
use std::collections::HashSet;
use std::time::Duration;

// ===========================================================================
// Helpers
// ===========================================================================

fn tid(n: u32) -> TaskId {
    TaskId::new_for_test(n, 0)
}

fn rid(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

fn lamport_tick(clock: &LamportClock) -> LogicalTime {
    LogicalTime::Lamport(clock.tick())
}

fn spawn_ev(seq: u64, task: TaskId, lt: LogicalTime) -> TraceEvent {
    TraceEvent::spawn(seq, Time::ZERO, task, rid(0)).with_logical_time(lt)
}

fn schedule_ev(seq: u64, task: TaskId, lt: LogicalTime) -> TraceEvent {
    TraceEvent::schedule(seq, Time::ZERO, task, rid(0)).with_logical_time(lt)
}

fn wake_ev(seq: u64, task: TaskId, lt: LogicalTime) -> TraceEvent {
    TraceEvent::wake(seq, Time::ZERO, task, rid(0)).with_logical_time(lt)
}

fn complete_ev(seq: u64, task: TaskId, lt: LogicalTime) -> TraceEvent {
    TraceEvent::complete(seq, Time::ZERO, task, rid(0)).with_logical_time(lt)
}

fn make_snapshot(region_id: RegionId) -> RegionSnapshot {
    RegionSnapshot {
        region_id,
        state: RegionState::Open,
        timestamp: Time::from_nanos(1_000_000),
        sequence: 42,
        tasks: vec![
            TaskSnapshot {
                task_id: tid(1),
                state: TaskState::Running,
                priority: 10,
            },
            TaskSnapshot {
                task_id: tid(2),
                state: TaskState::Pending,
                priority: 5,
            },
        ],
        children: vec![rid(10), rid(11)],
        finalizer_count: 3,
        budget: BudgetSnapshot {
            deadline_nanos: Some(5_000_000_000),
            polls_remaining: Some(100),
            cost_remaining: Some(9999),
        },
        cancel_reason: Some("timeout".to_string()),
        parent: Some(rid(0)),
        metadata: vec![0xDE, 0xAD, 0xBE, 0xEF],
    }
}

// ===========================================================================
// CAUSALITY VERIFICATION
// ===========================================================================

#[test]
fn causality_multi_task_interleaved_vector_clocks() {
    // Two tasks with causally-ordered vector clocks across nodes
    let mut vc = VectorClock::new();
    let node_a = NodeId::new("a");
    let node_b = NodeId::new("b");

    vc.increment(&node_a);
    let t1 = LogicalTime::Vector(vc.clone());
    vc.increment(&node_a);
    let t2 = LogicalTime::Vector(vc.clone());
    vc.increment(&node_b);
    let t3 = LogicalTime::Vector(vc.clone());
    vc.increment(&node_a);
    let t4 = LogicalTime::Vector(vc.clone());

    // All monotonically increasing across the same vector clock chain
    let trace = vec![
        spawn_ev(0, tid(1), t1),
        schedule_ev(1, tid(1), t2),
        wake_ev(2, tid(1), t3),
        complete_ev(3, tid(1), t4),
    ];
    assert!(CausalOrderVerifier::verify(&trace).is_ok());
}

#[test]
fn causality_equal_lamport_same_task_is_violation() {
    // Two events on the same task with identical lamport times = violation
    let clock = LamportClock::new();
    let t1 = LogicalTime::Lamport(clock.tick());
    // Create a second with the same value
    let t1_dup = t1.clone();

    let trace = vec![spawn_ev(0, tid(1), t1), schedule_ev(1, tid(1), t1_dup)];
    let err = CausalOrderVerifier::verify(&trace).unwrap_err();
    assert!(err
        .iter()
        .any(|v| v.kind == CausalityViolationKind::SameTaskConcurrent));
}

#[test]
fn causality_different_tasks_concurrent_vector_clocks_ok() {
    // Two independent tasks with truly concurrent vector clocks
    let mut vc_a = VectorClock::new();
    let mut vc_b = VectorClock::new();
    let node_a = NodeId::new("a");
    let node_b = NodeId::new("b");

    vc_a.increment(&node_a);
    vc_b.increment(&node_b);

    // These are concurrent (neither dominates) but on different tasks
    let trace = vec![
        spawn_ev(0, tid(1), LogicalTime::Vector(vc_a)),
        spawn_ev(1, tid(2), LogicalTime::Vector(vc_b)),
    ];
    assert!(CausalOrderVerifier::verify(&trace).is_ok());
}

#[test]
fn causality_large_trace_no_violations() {
    let clock = LamportClock::new();
    let mut trace = Vec::new();
    for i in 0..50u64 {
        let task = tid((i % 5) as u32 + 1);
        let lt = lamport_tick(&clock);
        match i % 4 {
            0 => trace.push(spawn_ev(i, task, lt)),
            1 => trace.push(schedule_ev(i, task, lt)),
            2 => trace.push(wake_ev(i, task, lt)),
            _ => trace.push(complete_ev(i, task, lt)),
        }
    }
    assert!(CausalOrderVerifier::verify(&trace).is_ok());
}

#[test]
fn causality_violation_display_format() {
    let clock = LamportClock::new();
    let t2 = LogicalTime::Lamport(clock.tick());
    let _skip = clock.tick();
    let t1 = LogicalTime::Lamport(clock.tick());

    let trace = vec![spawn_ev(0, tid(1), t1), schedule_ev(1, tid(1), t2)];
    let errs = CausalOrderVerifier::verify(&trace).unwrap_err();
    for v in &errs {
        let display = format!("{v}");
        assert!(display.contains("event["));
        assert!(display.contains("seq="));
    }
}

// ===========================================================================
// CERTIFICATE INVARIANTS
// ===========================================================================

#[test]
fn certificate_deterministic_hash_across_instances() {
    let events = vec![
        TraceEvent::new(1, Time::ZERO, TraceEventKind::Spawn, TraceData::None),
        TraceEvent::new(2, Time::ZERO, TraceEventKind::Schedule, TraceData::None),
        TraceEvent::new(3, Time::ZERO, TraceEventKind::Complete, TraceData::None),
    ];

    let mut cert_a = TraceCertificate::new();
    let mut cert_b = TraceCertificate::new();
    for e in &events {
        cert_a.record_event(e);
        cert_b.record_event(e);
    }

    assert_eq!(cert_a.event_hash(), cert_b.event_hash());
    assert_eq!(cert_a.event_count(), cert_b.event_count());
}

#[test]
fn certificate_cancel_balance_tracks_correctly() {
    let mut cert = TraceCertificate::new();
    cert.record_event(&TraceEvent::new(
        1,
        Time::ZERO,
        TraceEventKind::CancelRequest,
        TraceData::None,
    ));
    assert_eq!(cert.cancel_balance(), 1);

    cert.record_event(&TraceEvent::new(
        2,
        Time::ZERO,
        TraceEventKind::CancelAck,
        TraceData::None,
    ));
    assert_eq!(cert.cancel_balance(), 0);
}

#[test]
fn certificate_obligation_balance_multiple_cycles() {
    let mut cert = TraceCertificate::new();
    // Two reserves, one commit, one abort -> balance = 0
    cert.record_event(&TraceEvent::new(
        1,
        Time::ZERO,
        TraceEventKind::ObligationReserve,
        TraceData::None,
    ));
    cert.record_event(&TraceEvent::new(
        2,
        Time::ZERO,
        TraceEventKind::ObligationReserve,
        TraceData::None,
    ));
    assert_eq!(cert.obligation_balance(), 2);

    cert.record_event(&TraceEvent::new(
        3,
        Time::ZERO,
        TraceEventKind::ObligationCommit,
        TraceData::None,
    ));
    cert.record_event(&TraceEvent::new(
        4,
        Time::ZERO,
        TraceEventKind::ObligationAbort,
        TraceData::None,
    ));
    assert_eq!(cert.obligation_balance(), 0);
}

#[test]
fn certificate_verifier_full_roundtrip() {
    let events: Vec<TraceEvent> = (1..=10)
        .map(|i| TraceEvent::new(i, Time::ZERO, TraceEventKind::Spawn, TraceData::None))
        .collect();

    let mut cert = TraceCertificate::new();
    for e in &events {
        cert.record_event(e);
    }

    let result = CertificateVerifier::verify(&cert, &events);
    assert!(result.valid, "Verification failed: {result}");
    assert_eq!(cert.task_balance(), 10); // 10 spawns, 0 completes
}

#[test]
fn certificate_hash_sensitive_to_event_kind() {
    let mut cert_spawn = TraceCertificate::new();
    cert_spawn.record_event(&TraceEvent::new(
        1,
        Time::ZERO,
        TraceEventKind::Spawn,
        TraceData::None,
    ));

    let mut cert_complete = TraceCertificate::new();
    cert_complete.record_event(&TraceEvent::new(
        1,
        Time::ZERO,
        TraceEventKind::Complete,
        TraceData::None,
    ));

    assert_ne!(cert_spawn.event_hash(), cert_complete.event_hash());
}

#[test]
fn certificate_schedule_hash_independent() {
    let mut cert = TraceCertificate::new();
    cert.set_schedule_hash(0xDEAD_BEEF);
    assert_eq!(cert.schedule_hash(), 0xDEAD_BEEF);
    assert!(cert.is_clean());
    assert_eq!(cert.event_count(), 0);
}

// ===========================================================================
// REPLAY SERIALIZATION
// ===========================================================================

#[test]
fn replay_trace_empty_roundtrip() {
    let trace = ReplayTrace::new(TraceMetadata::new(0));
    let bytes = trace.to_bytes().unwrap();
    let loaded = ReplayTrace::from_bytes(&bytes).unwrap();
    assert_eq!(loaded.metadata.seed, 0);
    assert!(loaded.events.is_empty());
}

#[test]
fn replay_trace_all_event_variants_roundtrip() {
    let mut trace = ReplayTrace::new(TraceMetadata::new(999));
    trace.push(ReplayEvent::RngSeed { seed: 42 });
    trace.push(ReplayEvent::RngValue { value: 123 });
    trace.push(ReplayEvent::TaskScheduled {
        task: CompactTaskId(1),
        at_tick: 0,
    });
    trace.push(ReplayEvent::TaskYielded {
        task: CompactTaskId(1),
    });
    trace.push(ReplayEvent::TaskCompleted {
        task: CompactTaskId(1),
        outcome: 0,
    });
    trace.push(ReplayEvent::TaskSpawned {
        task: CompactTaskId(2),
        region: CompactRegionId(0),
        at_tick: 1,
    });
    trace.push(ReplayEvent::TimeAdvanced {
        from_nanos: 0,
        to_nanos: 1_000_000,
    });
    trace.push(ReplayEvent::TimerCreated {
        timer_id: 1,
        deadline_nanos: 5_000_000,
    });
    trace.push(ReplayEvent::TimerFired { timer_id: 1 });
    trace.push(ReplayEvent::TimerCancelled { timer_id: 2 });
    trace.push(ReplayEvent::IoReady {
        token: 10,
        readiness: 0b1111,
    });
    trace.push(ReplayEvent::IoResult {
        token: 10,
        bytes: 1024,
    });
    trace.push(ReplayEvent::IoError { token: 10, kind: 4 });
    trace.push(ReplayEvent::ChaosInjection {
        kind: 0,
        task: Some(CompactTaskId(1)),
        data: 0,
    });
    trace.push(ReplayEvent::ChaosInjection {
        kind: 1,
        task: None,
        data: 1_000_000,
    });
    trace.push(ReplayEvent::RegionCreated {
        region: CompactRegionId(0),
        parent: None,
        at_tick: 0,
    });
    trace.push(ReplayEvent::RegionCreated {
        region: CompactRegionId(1),
        parent: Some(CompactRegionId(0)),
        at_tick: 5,
    });
    trace.push(ReplayEvent::RegionClosed {
        region: CompactRegionId(1),
        outcome: 2,
    });
    trace.push(ReplayEvent::RegionCancelled {
        region: CompactRegionId(0),
        cancel_kind: 1,
    });
    trace.push(ReplayEvent::WakerWake {
        task: CompactTaskId(3),
    });
    trace.push(ReplayEvent::WakerBatchWake { count: 8 });
    trace.push(ReplayEvent::Checkpoint {
        sequence: 1,
        time_nanos: 1_000_000,
        active_tasks: 5,
        active_regions: 2,
    });

    let bytes = trace.to_bytes().unwrap();
    let loaded = ReplayTrace::from_bytes(&bytes).unwrap();
    assert_eq!(loaded.metadata.seed, 999);
    assert_eq!(loaded.events.len(), trace.events.len());
    for (a, b) in loaded.events.iter().zip(trace.events.iter()) {
        assert_eq!(a, b);
    }
}

#[test]
fn replay_metadata_config_hash_preserved() {
    let meta = TraceMetadata::new(42)
        .with_config_hash(0xCAFE_BABE)
        .with_description("test description");
    let mut trace = ReplayTrace::new(meta);
    trace.push(ReplayEvent::RngSeed { seed: 42 });

    let bytes = trace.to_bytes().unwrap();
    let loaded = ReplayTrace::from_bytes(&bytes).unwrap();
    assert_eq!(loaded.metadata.config_hash, 0xCAFE_BABE);
    assert_eq!(
        loaded.metadata.description.as_deref(),
        Some("test description")
    );
}

#[test]
fn replay_compact_task_id_roundtrip_extremes() {
    // Test edge values for compact task ID packing
    for (index, gen) in [(0, 0), (u32::MAX, u32::MAX), (1, 0), (0, 1)] {
        let task = TaskId::new_for_test(index, gen);
        let compact = CompactTaskId::from(task);
        let (idx, g) = compact.unpack();
        assert_eq!(idx, index, "index mismatch for ({index}, {gen})");
        assert_eq!(g, gen, "gen mismatch for ({index}, {gen})");
        assert_eq!(compact.to_task_id(), task);
    }
}

#[test]
fn replay_compact_region_id_roundtrip_extremes() {
    for (index, gen) in [(0, 0), (u32::MAX, u32::MAX), (100, 200)] {
        let region = RegionId::new_for_test(index, gen);
        let compact = CompactRegionId::from(region);
        let (idx, g) = compact.unpack();
        assert_eq!(idx, index);
        assert_eq!(g, gen);
        assert_eq!(compact.to_region_id(), region);
    }
}

#[test]
fn replay_estimated_size_under_64_all_variants() {
    let variants: Vec<ReplayEvent> = vec![
        ReplayEvent::TaskScheduled {
            task: CompactTaskId(u64::MAX),
            at_tick: u64::MAX,
        },
        ReplayEvent::TaskYielded {
            task: CompactTaskId(u64::MAX),
        },
        ReplayEvent::TaskCompleted {
            task: CompactTaskId(u64::MAX),
            outcome: 255,
        },
        ReplayEvent::TaskSpawned {
            task: CompactTaskId(u64::MAX),
            region: CompactRegionId(u64::MAX),
            at_tick: u64::MAX,
        },
        ReplayEvent::TimeAdvanced {
            from_nanos: u64::MAX,
            to_nanos: u64::MAX,
        },
        ReplayEvent::TimerCreated {
            timer_id: u64::MAX,
            deadline_nanos: u64::MAX,
        },
        ReplayEvent::TimerFired { timer_id: u64::MAX },
        ReplayEvent::TimerCancelled { timer_id: u64::MAX },
        ReplayEvent::IoReady {
            token: u64::MAX,
            readiness: 255,
        },
        ReplayEvent::IoResult {
            token: u64::MAX,
            bytes: i64::MAX,
        },
        ReplayEvent::IoError {
            token: u64::MAX,
            kind: 255,
        },
        ReplayEvent::RngSeed { seed: u64::MAX },
        ReplayEvent::RngValue { value: u64::MAX },
        ReplayEvent::ChaosInjection {
            kind: 255,
            task: Some(CompactTaskId(u64::MAX)),
            data: u64::MAX,
        },
        ReplayEvent::ChaosInjection {
            kind: 255,
            task: None,
            data: u64::MAX,
        },
        ReplayEvent::RegionCreated {
            region: CompactRegionId(u64::MAX),
            parent: Some(CompactRegionId(u64::MAX)),
            at_tick: u64::MAX,
        },
        ReplayEvent::RegionClosed {
            region: CompactRegionId(u64::MAX),
            outcome: 255,
        },
        ReplayEvent::RegionCancelled {
            region: CompactRegionId(u64::MAX),
            cancel_kind: 255,
        },
        ReplayEvent::WakerWake {
            task: CompactTaskId(u64::MAX),
        },
        ReplayEvent::WakerBatchWake { count: u32::MAX },
        ReplayEvent::Checkpoint {
            sequence: u64::MAX,
            time_nanos: u64::MAX,
            active_tasks: u32::MAX,
            active_regions: u32::MAX,
        },
    ];

    for event in &variants {
        assert!(
            event.estimated_size() < 64,
            "Event {:?} estimated_size={} >= 64",
            std::mem::discriminant(event),
            event.estimated_size()
        );
    }
}

// ===========================================================================
// REPLAYER LIFECYCLE
// ===========================================================================

#[test]
fn replayer_run_mode_completes_all() {
    let events = vec![
        ReplayEvent::RngSeed { seed: 1 },
        ReplayEvent::TaskScheduled {
            task: CompactTaskId(1),
            at_tick: 0,
        },
        ReplayEvent::TaskCompleted {
            task: CompactTaskId(1),
            outcome: 0,
        },
    ];

    let mut replayer = TraceReplayer::new(ReplayTrace {
        metadata: TraceMetadata::new(1),
        events,
        cursor: 0,
    });
    replayer.set_mode(ReplayMode::Run);
    let count = replayer.run().unwrap();
    assert_eq!(count, 3);
    assert!(replayer.is_completed());
}

#[test]
fn replayer_step_mode_stops_each_event() {
    let events = vec![
        ReplayEvent::RngSeed { seed: 1 },
        ReplayEvent::RngSeed { seed: 2 },
        ReplayEvent::RngSeed { seed: 3 },
    ];

    let mut replayer = TraceReplayer::new(ReplayTrace {
        metadata: TraceMetadata::new(1),
        events,
        cursor: 0,
    });
    replayer.set_mode(ReplayMode::Step);

    for i in 0..3 {
        let event = replayer.step().unwrap();
        assert!(event.is_some(), "step {i} should return event");
        assert!(replayer.at_breakpoint());
    }
    assert!(replayer.is_completed());
}

#[test]
fn replayer_breakpoint_task() {
    let target_task = CompactTaskId(42);
    let events = vec![
        ReplayEvent::TaskScheduled {
            task: CompactTaskId(1),
            at_tick: 0,
        },
        ReplayEvent::TaskScheduled {
            task: CompactTaskId(2),
            at_tick: 1,
        },
        ReplayEvent::TaskScheduled {
            task: target_task,
            at_tick: 2,
        },
        ReplayEvent::TaskScheduled {
            task: CompactTaskId(3),
            at_tick: 3,
        },
    ];

    let mut replayer = TraceReplayer::new(ReplayTrace {
        metadata: TraceMetadata::new(1),
        events,
        cursor: 0,
    });
    replayer.set_mode(ReplayMode::RunTo(Breakpoint::Task(target_task)));
    let count = replayer.run().unwrap();
    assert_eq!(count, 3); // stops after processing event at index 2
    assert!(replayer.at_breakpoint());
    assert!(!replayer.is_completed());
}

#[test]
fn replayer_verify_divergence_detection() {
    let events = vec![ReplayEvent::RngSeed { seed: 42 }];
    let replayer = TraceReplayer::new(ReplayTrace {
        metadata: TraceMetadata::new(42),
        events,
        cursor: 0,
    });

    // Correct event passes
    assert!(replayer.verify(&ReplayEvent::RngSeed { seed: 42 }).is_ok());

    // Wrong event fails
    let err = replayer
        .verify(&ReplayEvent::RngSeed { seed: 99 })
        .unwrap_err();
    assert_eq!(err.index, 0);
}

#[test]
fn replayer_seek_and_reset() {
    let events = vec![
        ReplayEvent::RngSeed { seed: 1 },
        ReplayEvent::RngSeed { seed: 2 },
        ReplayEvent::RngSeed { seed: 3 },
    ];

    let mut replayer = TraceReplayer::new(ReplayTrace {
        metadata: TraceMetadata::new(1),
        events,
        cursor: 0,
    });

    // Advance to end
    replayer.set_mode(ReplayMode::Run);
    replayer.run().unwrap();
    assert!(replayer.is_completed());

    // Seek back to start
    replayer.seek(0).unwrap();
    assert!(!replayer.is_completed());
    assert_eq!(replayer.current_index(), 0);

    // Reset also works
    replayer.next();
    replayer.reset();
    assert_eq!(replayer.current_index(), 0);
    assert!(!replayer.is_completed());
}

#[test]
fn replayer_remaining_events_decreases() {
    let events = vec![
        ReplayEvent::RngSeed { seed: 1 },
        ReplayEvent::RngSeed { seed: 2 },
        ReplayEvent::RngSeed { seed: 3 },
    ];

    let mut replayer = TraceReplayer::new(ReplayTrace {
        metadata: TraceMetadata::new(1),
        events,
        cursor: 0,
    });

    assert_eq!(replayer.remaining_events().len(), 3);
    replayer.next();
    assert_eq!(replayer.remaining_events().len(), 2);
    replayer.next();
    assert_eq!(replayer.remaining_events().len(), 1);
    replayer.next();
    assert_eq!(replayer.remaining_events().len(), 0);
}

// ===========================================================================
// COMPAT LAYER
// ===========================================================================

#[test]
fn compat_current_version_is_compatible() {
    assert_eq!(
        check_schema_compatibility(REPLAY_SCHEMA_VERSION),
        CompatibilityResult::Compatible
    );
}

#[test]
fn compat_future_version_is_too_new() {
    let result = check_schema_compatibility(REPLAY_SCHEMA_VERSION + 100);
    assert!(matches!(result, CompatibilityResult::TooNew { .. }));
}

#[test]
fn compat_version_zero_is_too_old() {
    let result = check_schema_compatibility(0);
    assert!(matches!(result, CompatibilityResult::TooOld { .. }));
}

#[test]
fn compat_stats_default_has_no_issues() {
    let stats = CompatStats::default();
    assert!(!stats.has_issues());
    assert_eq!(stats.events_read, 0);
    assert_eq!(stats.events_skipped, 0);
}

#[test]
fn compat_stats_records_skipped_dedup() {
    let mut stats = CompatStats::default();
    stats.record_skipped(Some("UnknownA"));
    stats.record_skipped(Some("UnknownA")); // duplicate
    stats.record_skipped(Some("UnknownB"));
    assert_eq!(stats.events_skipped, 3);
    assert_eq!(stats.unknown_event_types.len(), 2);
    assert!(stats.has_issues());
}

#[test]
fn compat_migrator_same_version_noop() {
    let migrator = TraceMigrator::new();
    let meta = TraceMetadata::new(42);
    let events = vec![ReplayEvent::RngSeed { seed: 42 }];
    let result = migrator.migrate(meta, events, REPLAY_SCHEMA_VERSION);
    assert!(result.is_some());
    let (new_meta, new_events) = result.unwrap();
    assert_eq!(new_meta.seed, 42);
    assert_eq!(new_events.len(), 1);
}

#[test]
fn compat_migrator_unregistered_path_fails() {
    let migrator = TraceMigrator::new();
    assert!(!migrator.can_migrate(1, 999));
}

// ===========================================================================
// SNAPSHOT SERIALIZATION
// ===========================================================================

#[test]
fn snapshot_empty_roundtrip() {
    let snap = RegionSnapshot::empty(rid(42));
    let bytes = snap.to_bytes();
    let loaded = RegionSnapshot::from_bytes(&bytes).unwrap();
    assert_eq!(loaded.region_id, rid(42));
    assert_eq!(loaded.sequence, 0);
    assert!(loaded.tasks.is_empty());
    assert!(loaded.children.is_empty());
    assert!(loaded.cancel_reason.is_none());
    assert!(loaded.parent.is_none());
    assert!(loaded.metadata.is_empty());
}

#[test]
fn snapshot_full_roundtrip() {
    let snap = make_snapshot(rid(7));
    let bytes = snap.to_bytes();
    let loaded = RegionSnapshot::from_bytes(&bytes).unwrap();

    assert_eq!(loaded.region_id, rid(7));
    assert_eq!(loaded.state, RegionState::Open);
    assert_eq!(loaded.timestamp, Time::from_nanos(1_000_000));
    assert_eq!(loaded.sequence, 42);
    assert_eq!(loaded.tasks.len(), 2);
    assert_eq!(loaded.tasks[0].task_id, tid(1));
    assert_eq!(loaded.tasks[0].state, TaskState::Running);
    assert_eq!(loaded.tasks[0].priority, 10);
    assert_eq!(loaded.tasks[1].state, TaskState::Pending);
    assert_eq!(loaded.children.len(), 2);
    assert_eq!(loaded.children[0], rid(10));
    assert_eq!(loaded.children[1], rid(11));
    assert_eq!(loaded.finalizer_count, 3);
    assert_eq!(loaded.budget.deadline_nanos, Some(5_000_000_000));
    assert_eq!(loaded.budget.polls_remaining, Some(100));
    assert_eq!(loaded.budget.cost_remaining, Some(9999));
    assert_eq!(loaded.cancel_reason.as_deref(), Some("timeout"));
    assert_eq!(loaded.parent, Some(rid(0)));
    assert_eq!(loaded.metadata, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn snapshot_content_hash_deterministic() {
    let snap = make_snapshot(rid(1));
    let h1 = snap.content_hash();
    let h2 = snap.content_hash();
    assert_eq!(h1, h2, "content_hash must be deterministic");
}

#[test]
fn snapshot_content_hash_differs_on_change() {
    let snap_a = make_snapshot(rid(1));
    let mut snap_b = make_snapshot(rid(1));
    snap_b.sequence = 43; // single field change

    assert_ne!(snap_a.content_hash(), snap_b.content_hash());
}

#[test]
fn snapshot_all_task_states_roundtrip() {
    let states = [
        TaskState::Pending,
        TaskState::Running,
        TaskState::Completed,
        TaskState::Cancelled,
        TaskState::Panicked,
    ];

    for (i, &state) in states.iter().enumerate() {
        let mut snap = RegionSnapshot::empty(rid(0));
        snap.tasks.push(TaskSnapshot {
            task_id: tid(i as u32),
            state,
            priority: 0,
        });
        let bytes = snap.to_bytes();
        let loaded = RegionSnapshot::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.tasks[0].state, state, "TaskState mismatch at {i}");
    }
}

#[test]
fn snapshot_invalid_magic_rejected() {
    let err = RegionSnapshot::from_bytes(b"NOPE\x01").unwrap_err();
    assert_eq!(err, SnapshotError::InvalidMagic);
}

#[test]
fn snapshot_truncated_data_rejected() {
    let snap = make_snapshot(rid(1));
    let bytes = snap.to_bytes();
    // Truncate to just the header
    let err = RegionSnapshot::from_bytes(&bytes[..6]).unwrap_err();
    assert_eq!(err, SnapshotError::UnexpectedEof);
}

#[test]
fn snapshot_wrong_version_rejected() {
    let snap = RegionSnapshot::empty(rid(0));
    let mut bytes = snap.to_bytes();
    bytes[4] = 99; // corrupt version byte
    let err = RegionSnapshot::from_bytes(&bytes).unwrap_err();
    assert_eq!(err, SnapshotError::UnsupportedVersion(99));
}

#[test]
fn snapshot_budget_none_roundtrip() {
    let mut snap = RegionSnapshot::empty(rid(0));
    snap.budget = BudgetSnapshot {
        deadline_nanos: None,
        polls_remaining: None,
        cost_remaining: None,
    };
    let bytes = snap.to_bytes();
    let loaded = RegionSnapshot::from_bytes(&bytes).unwrap();
    assert!(loaded.budget.deadline_nanos.is_none());
    assert!(loaded.budget.polls_remaining.is_none());
    assert!(loaded.budget.cost_remaining.is_none());
}

#[test]
fn snapshot_size_estimate_covers_actual() {
    let snap = make_snapshot(rid(1));
    let actual_size = snap.to_bytes().len();
    let estimated = snap.size_estimate();
    assert!(
        estimated >= actual_size,
        "size_estimate ({estimated}) < actual ({actual_size})"
    );
}

#[test]
fn snapshot_large_metadata_roundtrip() {
    let mut snap = RegionSnapshot::empty(rid(0));
    snap.metadata = vec![0xAB; 4096]; // 4K metadata blob
    let bytes = snap.to_bytes();
    let loaded = RegionSnapshot::from_bytes(&bytes).unwrap();
    assert_eq!(loaded.metadata.len(), 4096);
    assert!(loaded.metadata.iter().all(|&b| b == 0xAB));
}

// ===========================================================================
// BRIDGE STATE MACHINE
// ===========================================================================

#[test]
fn bridge_region_mode_properties() {
    let local = RegionMode::local();
    assert!(!local.is_replicated());
    assert!(!local.is_distributed());
    assert_eq!(local.replication_factor(), 1);

    let dist = RegionMode::distributed(3);
    assert!(dist.is_replicated());
    assert!(dist.is_distributed());
    assert_eq!(dist.replication_factor(), 3);

    let hybrid = RegionMode::hybrid(2);
    assert!(hybrid.is_replicated());
    assert!(!hybrid.is_distributed());
    assert_eq!(hybrid.replication_factor(), 2);
}

#[test]
fn bridge_config_defaults() {
    let config = BridgeConfig::default();
    assert!(config.allow_upgrade);
    assert_eq!(config.sync_mode, SyncMode::Synchronous);
    assert_eq!(
        config.conflict_resolution,
        ConflictResolution::DistributedWins
    );
}

#[test]
fn bridge_effective_state_open_when_local_open() {
    let state = EffectiveState::compute(RegionState::Open, None);
    assert!(state.can_spawn());
    assert!(!state.is_inconsistent());
    assert!(!state.needs_recovery());
}

#[test]
fn bridge_effective_state_closed_when_local_closed() {
    let state = EffectiveState::compute(RegionState::Closed, None);
    assert!(!state.can_spawn());
}

// ===========================================================================
// REMOTE MODULE
// ===========================================================================

#[test]
fn remote_node_id_equality_and_display() {
    let a = NodeId::new("node-1");
    let b = NodeId::new("node-1");
    let c = NodeId::new("node-2");

    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_eq!(a.as_str(), "node-1");

    let display = format!("{a}");
    assert!(display.contains("node-1"));
}

#[test]
fn remote_task_id_uniqueness() {
    let mut ids = HashSet::new();
    for _ in 0..100 {
        let id = RemoteTaskId::next();
        assert!(ids.insert(id.raw()), "duplicate RemoteTaskId");
    }
}

#[test]
fn remote_task_id_from_raw_roundtrip() {
    let id = RemoteTaskId::from_raw(42);
    assert_eq!(id.raw(), 42);
    let display = format!("{id}");
    assert!(display.contains("42"));
}

#[test]
fn remote_computation_name_api() {
    let name = ComputationName::new("encode_block");
    assert_eq!(name.as_str(), "encode_block");
    let display = format!("{name}");
    assert_eq!(display, "encode_block");
}

#[test]
fn remote_input_api() {
    let empty = RemoteInput::empty();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);

    let data = vec![1, 2, 3, 4];
    let input = RemoteInput::new(data.clone());
    assert!(!input.is_empty());
    assert_eq!(input.len(), 4);
    assert_eq!(input.data(), &[1, 2, 3, 4]);
    assert_eq!(input.into_data(), data);
}

#[test]
fn remote_cap_defaults() {
    let cap = RemoteCap::new();
    assert_eq!(cap.default_lease(), Duration::from_secs(30));
    assert!(cap.remote_budget().is_none());
}

#[test]
fn remote_cap_builder() {
    let cap = RemoteCap::new().with_default_lease(Duration::from_secs(60));
    assert_eq!(cap.default_lease(), Duration::from_secs(60));
}

#[test]
fn remote_task_state_display() {
    let states = [
        (RemoteTaskState::Pending, "Pending"),
        (RemoteTaskState::Running, "Running"),
        (RemoteTaskState::Completed, "Completed"),
        (RemoteTaskState::Failed, "Failed"),
        (RemoteTaskState::Cancelled, "Cancelled"),
        (RemoteTaskState::LeaseExpired, "LeaseExpired"),
    ];
    for (state, expected) in states {
        assert_eq!(format!("{state}"), expected);
    }
}

#[test]
fn remote_error_display_variants() {
    let errors: Vec<RemoteError> = vec![
        RemoteError::NoCapability,
        RemoteError::NodeUnreachable("node-x".into()),
        RemoteError::UnknownComputation("foo".into()),
        RemoteError::LeaseExpired,
        RemoteError::Cancelled(CancelReason::user("test")),
        RemoteError::RemotePanic("oh no".into()),
        RemoteError::SerializationError("bad bytes".into()),
        RemoteError::TransportError("timeout".into()),
    ];
    for err in &errors {
        let msg = format!("{err}");
        assert!(!msg.is_empty(), "empty display for {err:?}");
    }
}

#[test]
fn remote_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(RemoteError::LeaseExpired);
    assert!(format!("{err}").contains("lease"));
}

#[test]
fn idempotency_store_duplicate_returns_cached_outcome() {
    let mut store = IdempotencyStore::new(Duration::from_secs(60));
    let key = IdempotencyKey::from_raw(0x42);
    let computation = ComputationName::new("encode_block");
    let now = Time::from_secs(1);

    assert!(matches!(
        store.check(&key, &computation),
        DedupDecision::New
    ));
    assert!(store.record(key, RemoteTaskId::from_raw(7), computation.clone(), now));

    let outcome = RemoteOutcome::Success(vec![1, 2, 3]);
    assert!(store.complete(&key, outcome));

    match store.check(&key, &computation) {
        DedupDecision::Duplicate(record) => {
            assert_eq!(record.remote_task_id, RemoteTaskId::from_raw(7));
            match record.outcome {
                Some(RemoteOutcome::Success(payload)) => {
                    assert_eq!(payload, vec![1, 2, 3]);
                }
                other => panic!("unexpected outcome: {other:?}"),
            }
        }
        other => panic!("expected duplicate, got {other:?}"),
    }

    let conflict = store.check(&key, &ComputationName::new("other"));
    assert!(matches!(conflict, DedupDecision::Conflict));
}

#[test]
fn saga_compensates_in_reverse_order_on_failure() {
    let mut saga = Saga::new();

    saga.step("step-1", || Ok(()), || "undo-1".into())
        .expect("step-1 should succeed");
    saga.step("step-2", || Ok(()), || "undo-2".into())
        .expect("step-2 should succeed");

    let err = saga
        .step("step-3", || Err::<(), _>("boom".into()), || "undo-3".into())
        .unwrap_err();
    assert!(err.message.contains("boom"));
    assert_eq!(saga.state(), SagaState::Aborted);

    let results = saga.compensation_results();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].result, "undo-2");
    assert_eq!(results[1].result, "undo-1");
}

// ===========================================================================
// GEODESIC NORMALIZATION DETERMINISM
// ===========================================================================

#[test]
fn geodesic_normalize_deterministic_across_10_runs() {
    let events = vec![
        TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
        TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
        TraceEvent::spawn(3, Time::ZERO, tid(3), rid(3)),
        TraceEvent::complete(4, Time::ZERO, tid(1), rid(1)),
        TraceEvent::complete(5, Time::ZERO, tid(2), rid(2)),
        TraceEvent::complete(6, Time::ZERO, tid(3), rid(3)),
    ];

    let poset = asupersync::trace::event_structure::TracePoset::from_trace(&events);
    let config = GeodesicConfig::default();

    let first = normalize(&poset, &config);
    for i in 1..10 {
        let run = normalize(&poset, &config);
        assert_eq!(first.schedule, run.schedule, "Run {i} schedule differs");
        assert_eq!(
            first.switch_count, run.switch_count,
            "Run {i} switch_count differs"
        );
    }
}

#[test]
fn geodesic_valid_linear_extension_always() {
    let configs = [
        GeodesicConfig::default(),
        GeodesicConfig::greedy_only(),
        GeodesicConfig::high_quality(),
    ];

    let events = vec![
        TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
        TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
        TraceEvent::complete(3, Time::ZERO, tid(1), rid(1)),
        TraceEvent::complete(4, Time::ZERO, tid(2), rid(2)),
    ];
    let poset = asupersync::trace::event_structure::TracePoset::from_trace(&events);

    for config in &configs {
        let result = normalize(&poset, config);
        assert!(
            is_valid_linear_extension(&poset, &result.schedule),
            "Invalid extension for config {config:?}"
        );
    }
}

#[test]
fn geodesic_switch_count_matches_schedule() {
    let events = vec![
        TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
        TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
        TraceEvent::spawn(3, Time::ZERO, tid(3), rid(3)),
    ];
    let poset = asupersync::trace::event_structure::TracePoset::from_trace(&events);
    let result = normalize(&poset, &GeodesicConfig::default());

    let computed = count_switches(&poset, &result.schedule);
    assert_eq!(
        result.switch_count, computed,
        "Reported switches {} != computed {}",
        result.switch_count, computed
    );
}
