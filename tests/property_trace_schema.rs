#![allow(clippy::cast_possible_wrap)]
//! Property tests for trace schema invariants and compatibility proofs.
//!
//! Formalizes versioned trace event schema with explicit invariants:
//! - ReplayEvent serde round-trip for all variants
//! - CompactTaskId / CompactRegionId packing algebra
//! - Schema version compatibility classification
//! - VectorClock merge lattice laws (commutativity, associativity, idempotency, LUB)
//! - LamportClock monotonicity
//! - TraceCertificate hash determinism and balance tracking
//! - TraceMigrator chain composability
//! - CausalOrder trichotomy and symmetry

mod common;

use asupersync::remote::NodeId;
use asupersync::trace::certificate::{CertificateVerifier, TraceCertificate};
use asupersync::trace::compat::{
    CompatStats, CompatibilityResult, TraceMigration, TraceMigrator, check_schema_compatibility,
};
use asupersync::trace::distributed::{
    CausalOrder, CausalTracker, LamportClock, LamportTime, LogicalTime, VectorClock,
};
use asupersync::trace::event::{TRACE_EVENT_SCHEMA_VERSION, TraceData, TraceEvent, TraceEventKind};
use asupersync::trace::replay::{
    CompactRegionId, CompactTaskId, REPLAY_SCHEMA_VERSION, ReplayEvent, ReplayTrace, TraceMetadata,
};
use asupersync::types::{RegionId, TaskId, Time};
use common::{init_test_logging, test_proptest_config};
use proptest::prelude::*;

// ============================================================================
// Arbitrary Generators
// ============================================================================

fn arb_compact_task_id() -> impl Strategy<Value = CompactTaskId> {
    any::<u64>().prop_map(CompactTaskId)
}

fn arb_compact_region_id() -> impl Strategy<Value = CompactRegionId> {
    any::<u64>().prop_map(CompactRegionId)
}

fn arb_node_id() -> impl Strategy<Value = NodeId> {
    prop_oneof![
        Just(NodeId::new("a")),
        Just(NodeId::new("b")),
        Just(NodeId::new("c")),
        Just(NodeId::new("d")),
    ]
}

fn arb_schema_version() -> impl Strategy<Value = u32> {
    0u32..=100
}

fn arb_replay_event() -> impl Strategy<Value = ReplayEvent> {
    prop_oneof![
        (arb_compact_task_id(), any::<u64>())
            .prop_map(|(task, at_tick)| { ReplayEvent::TaskScheduled { task, at_tick } }),
        arb_compact_task_id().prop_map(|task| ReplayEvent::TaskYielded { task }),
        (arb_compact_task_id(), 0u8..=3)
            .prop_map(|(task, outcome)| { ReplayEvent::TaskCompleted { task, outcome } }),
        (arb_compact_task_id(), arb_compact_region_id(), any::<u64>()).prop_map(
            |(task, region, at_tick)| {
                ReplayEvent::TaskSpawned {
                    task,
                    region,
                    at_tick,
                }
            }
        ),
        (any::<u64>(), any::<u64>()).prop_map(|(from_nanos, to_nanos)| {
            ReplayEvent::TimeAdvanced {
                from_nanos,
                to_nanos,
            }
        }),
        (any::<u64>(), any::<u64>()).prop_map(|(timer_id, deadline_nanos)| {
            ReplayEvent::TimerCreated {
                timer_id,
                deadline_nanos,
            }
        }),
        any::<u64>().prop_map(|timer_id| ReplayEvent::TimerFired { timer_id }),
        any::<u64>().prop_map(|timer_id| ReplayEvent::TimerCancelled { timer_id }),
        (any::<u64>(), any::<u8>())
            .prop_map(|(token, readiness)| ReplayEvent::IoReady { token, readiness }),
        (any::<u64>(), any::<i64>())
            .prop_map(|(token, bytes)| ReplayEvent::IoResult { token, bytes }),
        (any::<u64>(), any::<u8>()).prop_map(|(token, kind)| ReplayEvent::IoError { token, kind }),
        any::<u64>().prop_map(|seed| ReplayEvent::RngSeed { seed }),
        any::<u64>().prop_map(|value| ReplayEvent::RngValue { value }),
        (
            any::<u8>(),
            proptest::option::of(arb_compact_task_id()),
            any::<u64>()
        )
            .prop_map(|(kind, task, data)| { ReplayEvent::ChaosInjection { kind, task, data } }),
        (
            arb_compact_region_id(),
            proptest::option::of(arb_compact_region_id()),
            any::<u64>()
        )
            .prop_map(|(region, parent, at_tick)| {
                ReplayEvent::RegionCreated {
                    region,
                    parent,
                    at_tick,
                }
            }),
        (arb_compact_region_id(), 0u8..=3)
            .prop_map(|(region, outcome)| ReplayEvent::RegionClosed { region, outcome }),
        (arb_compact_region_id(), any::<u8>()).prop_map(|(region, cancel_kind)| {
            ReplayEvent::RegionCancelled {
                region,
                cancel_kind,
            }
        }),
        arb_compact_task_id().prop_map(|task| ReplayEvent::WakerWake { task }),
        any::<u32>().prop_map(|count| ReplayEvent::WakerBatchWake { count }),
        (any::<u64>(), any::<u64>(), any::<u32>(), any::<u32>()).prop_map(
            |(sequence, time_nanos, active_tasks, active_regions)| {
                ReplayEvent::Checkpoint {
                    sequence,
                    time_nanos,
                    active_tasks,
                    active_regions,
                }
            }
        ),
    ]
}

fn arb_trace_event_kind() -> impl Strategy<Value = TraceEventKind> {
    prop_oneof![
        Just(TraceEventKind::Spawn),
        Just(TraceEventKind::Schedule),
        Just(TraceEventKind::Yield),
        Just(TraceEventKind::Wake),
        Just(TraceEventKind::Poll),
        Just(TraceEventKind::Complete),
        Just(TraceEventKind::CancelRequest),
        Just(TraceEventKind::CancelAck),
        Just(TraceEventKind::RegionCloseBegin),
        Just(TraceEventKind::RegionCloseComplete),
        Just(TraceEventKind::RegionCreated),
        Just(TraceEventKind::RegionCancelled),
        Just(TraceEventKind::ObligationReserve),
        Just(TraceEventKind::ObligationCommit),
        Just(TraceEventKind::ObligationAbort),
        Just(TraceEventKind::ObligationLeak),
        Just(TraceEventKind::TimeAdvance),
        Just(TraceEventKind::TimerScheduled),
        Just(TraceEventKind::TimerFired),
        Just(TraceEventKind::TimerCancelled),
        Just(TraceEventKind::Checkpoint),
    ]
}

/// Generate a small VectorClock with 1-4 nodes.
fn arb_vector_clock() -> impl Strategy<Value = VectorClock> {
    prop::collection::vec((arb_node_id(), 1u64..=100), 1..=4).prop_map(|pairs| {
        let mut vc = VectorClock::new();
        for (node, count) in pairs {
            for _ in 0..count {
                vc.increment(&node);
            }
        }
        vc
    })
}

// ============================================================================
// CompactTaskId / CompactRegionId Packing Round-Trip
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(500))]

    /// CompactTaskId pack/unpack round-trip for all u32 pairs.
    #[test]
    fn compact_task_id_roundtrip(index in any::<u32>(), gen in any::<u32>()) {
        init_test_logging();
        let task = TaskId::new_for_test(index, gen);
        let compact = CompactTaskId::from(task);
        let (idx, g) = compact.unpack();
        prop_assert_eq!(idx, index);
        prop_assert_eq!(g, gen);
        prop_assert_eq!(compact.to_task_id(), task);
    }

    /// CompactRegionId pack/unpack round-trip for all u32 pairs.
    #[test]
    fn compact_region_id_roundtrip(index in any::<u32>(), gen in any::<u32>()) {
        init_test_logging();
        let region = RegionId::new_for_test(index, gen);
        let compact = CompactRegionId::from(region);
        let (idx, g) = compact.unpack();
        prop_assert_eq!(idx, index);
        prop_assert_eq!(g, gen);
        prop_assert_eq!(compact.to_region_id(), region);
    }

    /// CompactTaskId packing is a bijection: distinct (index, gen) → distinct u64.
    #[test]
    fn compact_task_id_injective(
        i1 in any::<u32>(), g1 in any::<u32>(),
        i2 in any::<u32>(), g2 in any::<u32>(),
    ) {
        init_test_logging();
        let a = CompactTaskId::from(TaskId::new_for_test(i1, g1));
        let b = CompactTaskId::from(TaskId::new_for_test(i2, g2));
        if i1 != i2 || g1 != g2 {
            prop_assert_ne!(a.0, b.0, "distinct (index,gen) must produce distinct packed u64");
        } else {
            prop_assert_eq!(a.0, b.0);
        }
    }
}

// ============================================================================
// ReplayEvent Serde Round-Trip
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(300))]

    /// Every ReplayEvent variant survives MessagePack round-trip.
    #[test]
    fn replay_event_msgpack_roundtrip(event in arb_replay_event()) {
        init_test_logging();
        let bytes = rmp_serde::to_vec(&event).unwrap();
        let decoded: ReplayEvent = rmp_serde::from_slice(&bytes).unwrap();
        prop_assert_eq!(decoded, event);
    }

    /// ReplayTrace with arbitrary events survives round-trip.
    #[test]
    fn replay_trace_roundtrip(
        seed in any::<u64>(),
        events in prop::collection::vec(arb_replay_event(), 0..=20),
    ) {
        init_test_logging();
        let mut trace = ReplayTrace::new(TraceMetadata::new(seed));
        for e in &events {
            trace.push(e.clone());
        }
        let bytes = trace.to_bytes().unwrap();
        let loaded = ReplayTrace::from_bytes(&bytes).unwrap();
        prop_assert_eq!(loaded.metadata.seed, seed);
        prop_assert_eq!(loaded.events.len(), events.len());
        for (a, b) in loaded.events.iter().zip(events.iter()) {
            prop_assert_eq!(a, b);
        }
    }
}

// ============================================================================
// ReplayEvent Size Invariant
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(500))]

    /// All ReplayEvent variants have estimated_size < 64 bytes.
    #[test]
    fn replay_event_size_under_64(event in arb_replay_event()) {
        init_test_logging();
        prop_assert!(
            event.estimated_size() < 64,
            "estimated_size={} >= 64",
            event.estimated_size()
        );
    }
}

// ============================================================================
// Schema Version Compatibility Classification
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// check_schema_compatibility partitions all versions into exactly one class.
    #[test]
    fn compat_classification_exhaustive(version in arb_schema_version()) {
        init_test_logging();
        let result = check_schema_compatibility(version);
        match result {
            CompatibilityResult::Compatible => {
                prop_assert_eq!(version, REPLAY_SCHEMA_VERSION);
            }
            CompatibilityResult::NeedsMigration { from, to } => {
                prop_assert_eq!(from, version);
                prop_assert_eq!(to, REPLAY_SCHEMA_VERSION);
                prop_assert!(version >= 1, "NeedsMigration version must be >= MIN_SUPPORTED");
                prop_assert!(version < REPLAY_SCHEMA_VERSION);
            }
            CompatibilityResult::TooOld { found, min_supported } => {
                prop_assert_eq!(found, version);
                prop_assert!(version < min_supported);
            }
            CompatibilityResult::TooNew { found, max_supported } => {
                prop_assert_eq!(found, version);
                prop_assert_eq!(max_supported, REPLAY_SCHEMA_VERSION);
                prop_assert!(version > REPLAY_SCHEMA_VERSION);
            }
        }
    }

    /// Current version is always Compatible.
    #[test]
    fn compat_current_version_always_compatible(_dummy in 0u8..1) {
        init_test_logging();
        prop_assert_eq!(
            check_schema_compatibility(REPLAY_SCHEMA_VERSION),
            CompatibilityResult::Compatible,
        );
    }

    /// Version 0 is always TooOld.
    #[test]
    fn compat_version_zero_always_too_old(_dummy in 0u8..1) {
        init_test_logging();
        let result = check_schema_compatibility(0);
        prop_assert!(
            matches!(result, CompatibilityResult::TooOld { .. }),
            "version 0 should be TooOld"
        );
    }

    /// Versions above current are always TooNew.
    #[test]
    fn compat_future_versions_too_new(offset in 1u32..=50) {
        init_test_logging();
        let version = REPLAY_SCHEMA_VERSION + offset;
        let result = check_schema_compatibility(version);
        prop_assert!(
            matches!(result, CompatibilityResult::TooNew { .. }),
            "version {} should be TooNew",
            version
        );
    }
}

// ============================================================================
// CompatStats Invariants
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(100))]

    /// has_issues iff events_skipped > 0 or unknown_event_types non-empty.
    #[test]
    fn compat_stats_has_issues_iff_skipped(
        reads in 0u64..=100,
        skips in 0u64..=10,
    ) {
        init_test_logging();
        let mut stats = CompatStats::default();
        for _ in 0..reads {
            stats.record_read();
        }
        for i in 0..skips {
            stats.record_skipped(Some(&format!("Unknown{i}")));
        }
        prop_assert_eq!(
            stats.has_issues(),
            skips > 0,
            "has_issues should be {} with {} skips",
            skips > 0,
            skips
        );
        prop_assert_eq!(stats.events_read, reads);
        prop_assert_eq!(stats.events_skipped, skips);
    }
}

// ============================================================================
// VectorClock Merge Lattice Laws
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// VectorClock merge is commutative: a.merge(b) == b.merge(a).
    #[test]
    fn vector_clock_merge_commutative(a in arb_vector_clock(), b in arb_vector_clock()) {
        init_test_logging();
        prop_assert_eq!(a.merge(&b), b.merge(&a));
    }

    /// VectorClock merge is associative: (a.merge(b)).merge(c) == a.merge(b.merge(c)).
    #[test]
    fn vector_clock_merge_associative(
        a in arb_vector_clock(),
        b in arb_vector_clock(),
        c in arb_vector_clock(),
    ) {
        init_test_logging();
        let ab_c = a.merge(&b).merge(&c);
        let a_bc = a.merge(&b.merge(&c));
        prop_assert_eq!(ab_c, a_bc);
    }

    /// VectorClock merge is idempotent: a.merge(a) == a.
    #[test]
    fn vector_clock_merge_idempotent(a in arb_vector_clock()) {
        init_test_logging();
        prop_assert_eq!(a.merge(&a), a);
    }

    /// VectorClock merge is an upper bound: a ≤ merge(a, b) and b ≤ merge(a, b).
    #[test]
    fn vector_clock_merge_is_upper_bound(a in arb_vector_clock(), b in arb_vector_clock()) {
        init_test_logging();
        let merged = a.merge(&b);
        let a_order = a.causal_order(&merged);
        let b_order = b.causal_order(&merged);
        prop_assert!(
            a_order == CausalOrder::Before || a_order == CausalOrder::Equal,
            "a should be <= merge(a,b), got {:?}",
            a_order
        );
        prop_assert!(
            b_order == CausalOrder::Before || b_order == CausalOrder::Equal,
            "b should be <= merge(a,b), got {:?}",
            b_order
        );
    }

    /// Empty clock is the identity for merge.
    #[test]
    fn vector_clock_merge_identity(a in arb_vector_clock()) {
        init_test_logging();
        let empty = VectorClock::new();
        let merged = a.merge(&empty);
        prop_assert_eq!(&merged, &a);
        let merged_back = empty.merge(&a);
        prop_assert_eq!(&merged_back, &a);
    }

    /// increment always produces a strictly greater clock.
    #[test]
    fn vector_clock_increment_monotone(a in arb_vector_clock(), node in arb_node_id()) {
        init_test_logging();
        let mut b = a.clone();
        b.increment(&node);
        prop_assert!(
            a.happens_before(&b),
            "after increment, old clock should happen-before new"
        );
    }
}

// ============================================================================
// CausalOrder Properties
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// CausalOrder is symmetric-antisymmetric: if a < b then b > a.
    #[test]
    fn causal_order_antisymmetric(a in arb_vector_clock(), b in arb_vector_clock()) {
        init_test_logging();
        let ab = a.causal_order(&b);
        let ba = b.causal_order(&a);
        match ab {
            CausalOrder::Before => prop_assert_eq!(ba, CausalOrder::After),
            CausalOrder::After => prop_assert_eq!(ba, CausalOrder::Before),
            CausalOrder::Equal => prop_assert_eq!(ba, CausalOrder::Equal),
            CausalOrder::Concurrent => prop_assert_eq!(ba, CausalOrder::Concurrent),
        }
    }

    /// CausalOrder::Equal iff clocks are identical.
    #[test]
    fn causal_order_equal_iff_same(a in arb_vector_clock(), b in arb_vector_clock()) {
        init_test_logging();
        let order = a.causal_order(&b);
        if a == b {
            prop_assert_eq!(order, CausalOrder::Equal);
        } else {
            prop_assert_ne!(order, CausalOrder::Equal);
        }
    }

    /// Reflexivity: a.causal_order(a) == Equal.
    #[test]
    fn causal_order_reflexive(a in arb_vector_clock()) {
        init_test_logging();
        prop_assert_eq!(a.causal_order(&a), CausalOrder::Equal);
    }
}

// ============================================================================
// LamportClock Monotonicity
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// LamportClock tick produces strictly increasing values.
    #[test]
    fn lamport_tick_monotone(ticks in 2u32..=100) {
        init_test_logging();
        let clock = LamportClock::new();
        let mut prev = clock.tick();
        for _ in 1..ticks {
            let next = clock.tick();
            prop_assert!(next > prev, "tick must produce strictly increasing values");
            prev = next;
        }
    }

    /// LamportClock receive produces a value > max(local, remote).
    #[test]
    fn lamport_receive_dominates(
        local_ticks in 1u32..=50,
        remote_value in 0u64..=1000,
    ) {
        init_test_logging();
        let clock = LamportClock::new();
        for _ in 0..local_ticks {
            let _ = clock.tick();
        }
        let before = clock.now();
        let remote = LamportTime::from_raw(remote_value);
        let after = clock.receive(remote);
        prop_assert!(
            after.raw() > before.raw(),
            "receive must advance past local: {} > {}",
            after.raw(), before.raw()
        );
        prop_assert!(
            after.raw() > remote.raw(),
            "receive must advance past remote: {} > {}",
            after.raw(), remote.raw()
        );
    }

    /// LamportClock with_start initializes to the given value.
    #[test]
    fn lamport_with_start(start in 0u64..=10000) {
        init_test_logging();
        let clock = LamportClock::with_start(start);
        prop_assert_eq!(clock.now().raw(), start);
        let ticked = clock.tick();
        prop_assert_eq!(ticked.raw(), start + 1);
    }
}

// ============================================================================
// TraceCertificate Hash Determinism
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// Same event sequence always produces same certificate hash.
    #[test]
    fn certificate_hash_deterministic(
        kinds in prop::collection::vec(arb_trace_event_kind(), 1..=20),
    ) {
        init_test_logging();
        let events: Vec<TraceEvent> = kinds.iter().enumerate().map(|(i, &kind)| {
            TraceEvent::new(i as u64, Time::ZERO, kind, TraceData::None)
        }).collect();

        let mut cert_a = TraceCertificate::new();
        let mut cert_b = TraceCertificate::new();
        for e in &events {
            cert_a.record_event(e);
            cert_b.record_event(e);
        }

        prop_assert_eq!(cert_a.event_hash(), cert_b.event_hash());
        prop_assert_eq!(cert_a.event_count(), cert_b.event_count());
    }

    /// Different event kinds produce different hashes (with high probability).
    #[test]
    fn certificate_hash_sensitive_to_kind(kind1 in arb_trace_event_kind(), kind2 in arb_trace_event_kind()) {
        init_test_logging();
        prop_assume!(kind1 != kind2);
        let mut cert_a = TraceCertificate::new();
        cert_a.record_event(&TraceEvent::new(1, Time::ZERO, kind1, TraceData::None));
        let mut cert_b = TraceCertificate::new();
        cert_b.record_event(&TraceEvent::new(1, Time::ZERO, kind2, TraceData::None));
        prop_assert_ne!(cert_a.event_hash(), cert_b.event_hash());
    }

    /// Certificate event count always equals number of recorded events.
    #[test]
    fn certificate_event_count_accurate(
        kinds in prop::collection::vec(arb_trace_event_kind(), 0..=30),
    ) {
        init_test_logging();
        let mut cert = TraceCertificate::new();
        for (i, &kind) in kinds.iter().enumerate() {
            cert.record_event(&TraceEvent::new(i as u64, Time::ZERO, kind, TraceData::None));
        }
        prop_assert_eq!(cert.event_count(), kinds.len() as u64);
    }
}

// ============================================================================
// TraceCertificate Balance Tracking
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// task_balance = spawns - completes.
    #[test]
    fn certificate_task_balance(spawns in 0u64..=50, completes in 0u64..=50) {
        init_test_logging();
        let mut cert = TraceCertificate::new();
        for i in 0..spawns {
            cert.record_event(&TraceEvent::new(i, Time::ZERO, TraceEventKind::Spawn, TraceData::None));
        }
        for i in 0..completes {
            cert.record_event(&TraceEvent::new(spawns + i, Time::ZERO, TraceEventKind::Complete, TraceData::None));
        }
        prop_assert_eq!(cert.task_balance(), spawns as i64 - completes as i64);
    }

    /// cancel_balance = cancel_requests - cancel_acks.
    #[test]
    fn certificate_cancel_balance(requests in 0u64..=50, acks in 0u64..=50) {
        init_test_logging();
        let mut cert = TraceCertificate::new();
        for i in 0..requests {
            cert.record_event(&TraceEvent::new(i, Time::ZERO, TraceEventKind::CancelRequest, TraceData::None));
        }
        for i in 0..acks {
            cert.record_event(&TraceEvent::new(requests + i, Time::ZERO, TraceEventKind::CancelAck, TraceData::None));
        }
        prop_assert_eq!(cert.cancel_balance(), requests as i64 - acks as i64);
    }

    /// obligation_balance = reserves - (commits + aborts).
    #[test]
    fn certificate_obligation_balance(reserves in 0u64..=30, commits in 0u64..=15, aborts in 0u64..=15) {
        init_test_logging();
        let mut cert = TraceCertificate::new();
        let mut seq = 0u64;
        for _ in 0..reserves {
            cert.record_event(&TraceEvent::new(seq, Time::ZERO, TraceEventKind::ObligationReserve, TraceData::None));
            seq += 1;
        }
        for _ in 0..commits {
            cert.record_event(&TraceEvent::new(seq, Time::ZERO, TraceEventKind::ObligationCommit, TraceData::None));
            seq += 1;
        }
        for _ in 0..aborts {
            cert.record_event(&TraceEvent::new(seq, Time::ZERO, TraceEventKind::ObligationAbort, TraceData::None));
            seq += 1;
        }
        prop_assert_eq!(cert.obligation_balance(), reserves as i64 - (commits + aborts) as i64);
    }
}

// ============================================================================
// CertificateVerifier Self-Consistency
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(100))]

    /// A certificate built from events always verifies against those same events.
    #[test]
    fn certificate_verifier_self_consistent(
        kinds in prop::collection::vec(arb_trace_event_kind(), 1..=20),
    ) {
        init_test_logging();
        let events: Vec<TraceEvent> = kinds.iter().enumerate().map(|(i, &kind)| {
            TraceEvent::new(i as u64, Time::ZERO, kind, TraceData::None)
        }).collect();

        let mut cert = TraceCertificate::new();
        for e in &events {
            cert.record_event(e);
        }

        let result = CertificateVerifier::verify(&cert, &events);
        // event_count and event_hash checks must always pass for self-built certificates
        for check in &result.checks {
            if check.name == "event_count" || check.name == "event_hash" {
                prop_assert!(
                    check.passed,
                    "self-built certificate should pass {}: {:?}",
                    check.name,
                    check.detail
                );
            }
        }
    }
}

// ============================================================================
// TraceMigrator Chain Composability
// ============================================================================

/// Identity migration: passes all events through unchanged.
struct IdentityMigration {
    from: u32,
    to: u32,
}

impl TraceMigration for IdentityMigration {
    fn from_version(&self) -> u32 {
        self.from
    }
    fn to_version(&self) -> u32 {
        self.to
    }
    fn migrate_event(&self, event: ReplayEvent) -> Option<ReplayEvent> {
        Some(event)
    }
}

/// Dropping migration: drops all events (for testing filter behavior).
struct DroppingMigration {
    from: u32,
    to: u32,
}

impl TraceMigration for DroppingMigration {
    fn from_version(&self) -> u32 {
        self.from
    }
    fn to_version(&self) -> u32 {
        self.to
    }
    fn migrate_event(&self, _event: ReplayEvent) -> Option<ReplayEvent> {
        None
    }
}

proptest! {
    #![proptest_config(test_proptest_config(100))]

    /// Migrator same-version is a no-op: events pass through unchanged.
    #[test]
    fn migrator_same_version_noop(
        seed in any::<u64>(),
        events in prop::collection::vec(arb_replay_event(), 0..=10),
    ) {
        init_test_logging();
        let migrator = TraceMigrator::new();
        let meta = TraceMetadata::new(seed);
        let result = migrator.migrate(meta.clone(), events.clone(), REPLAY_SCHEMA_VERSION);
        let (new_meta, new_events) = result.unwrap();
        prop_assert_eq!(new_meta.seed, meta.seed);
        prop_assert_eq!(new_events.len(), events.len());
        for (a, b) in new_events.iter().zip(events.iter()) {
            prop_assert_eq!(a, b);
        }
    }

    /// Identity migrations compose: v1→v2→v3 with identity preserves all events.
    #[test]
    fn migrator_identity_chain_preserves_events(
        events in prop::collection::vec(arb_replay_event(), 1..=10),
    ) {
        init_test_logging();
        let migrator = TraceMigrator::new()
            .with_migration(IdentityMigration { from: 1, to: 2 })
            .with_migration(IdentityMigration { from: 2, to: 3 });

        let mut meta = TraceMetadata::new(42);
        meta.version = 1;
        let result = migrator.migrate(meta, events.clone(), 3);
        let (new_meta, new_events) = result.unwrap();
        prop_assert_eq!(new_meta.version, 3);
        prop_assert_eq!(new_events.len(), events.len());
    }

    /// Dropping migration produces empty events.
    #[test]
    fn migrator_dropping_removes_all(
        events in prop::collection::vec(arb_replay_event(), 1..=10),
    ) {
        init_test_logging();
        let migrator = TraceMigrator::new()
            .with_migration(DroppingMigration { from: 1, to: 2 });

        let mut meta = TraceMetadata::new(42);
        meta.version = 1;
        let result = migrator.migrate(meta, events, 2);
        let (_, new_events) = result.unwrap();
        prop_assert!(new_events.is_empty(), "dropping migration should remove all events");
    }

    /// can_migrate is consistent with migrate: if can_migrate is true, migrate succeeds.
    #[test]
    fn migrator_can_migrate_consistent(from in 1u32..=5, to in 1u32..=5) {
        init_test_logging();
        let migrator = TraceMigrator::new()
            .with_migration(IdentityMigration { from: 1, to: 2 })
            .with_migration(IdentityMigration { from: 2, to: 3 })
            .with_migration(IdentityMigration { from: 3, to: 4 });

        let can = migrator.can_migrate(from, to);
        let mut meta = TraceMetadata::new(0);
        meta.version = from;
        let result = migrator.migrate(meta, vec![], to);

        if can {
            prop_assert!(result.is_some(), "can_migrate=true but migrate failed");
        } else {
            prop_assert!(result.is_none(), "can_migrate=false but migrate succeeded");
        }
    }
}

// ============================================================================
// TraceMetadata Compatibility
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// TraceMetadata.is_compatible iff version == REPLAY_SCHEMA_VERSION.
    #[test]
    fn metadata_is_compatible_iff_current(version in arb_schema_version()) {
        init_test_logging();
        let meta = TraceMetadata {
            version,
            seed: 0,
            recorded_at: 0,
            config_hash: 0,
            description: None,
        };
        prop_assert_eq!(meta.is_compatible(), version == REPLAY_SCHEMA_VERSION);
    }

    /// TraceMetadata serde round-trip preserves all fields.
    #[test]
    fn metadata_serde_roundtrip(
        seed in any::<u64>(),
        config_hash in any::<u64>(),
        desc in proptest::option::of("[a-z ]{0,30}"),
    ) {
        init_test_logging();
        let meta = TraceMetadata::new(seed)
            .with_config_hash(config_hash);
        let meta = if let Some(d) = desc.as_ref() {
            meta.with_description(d.as_str())
        } else {
            meta
        };

        let bytes = rmp_serde::to_vec(&meta).unwrap();
        let loaded: TraceMetadata = rmp_serde::from_slice(&bytes).unwrap();

        prop_assert_eq!(loaded.seed, seed);
        prop_assert_eq!(loaded.config_hash, config_hash);
        prop_assert_eq!(loaded.description, desc);
        prop_assert_eq!(loaded.version, REPLAY_SCHEMA_VERSION);
    }
}

// ============================================================================
// CausalTracker Protocol Invariants
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(100))]

    /// CausalTracker: send always produces a clock that happens-after previous state.
    #[test]
    fn causal_tracker_send_monotone(local_ops in 1u32..=20) {
        init_test_logging();
        let node = NodeId::new("test");
        let mut tracker = CausalTracker::new(node);
        let mut prev_clock = tracker.current_clock().clone();

        for _ in 0..local_ops {
            let send_clock = tracker.on_send();
            prop_assert!(
                prev_clock.happens_before(&send_clock) || prev_clock == send_clock,
                "send clock must not regress"
            );
            prev_clock = send_clock;
        }
    }

    /// CausalTracker: receive merges and advances past sender.
    #[test]
    fn causal_tracker_receive_dominates_sender(
        local_ops in 1u32..=10,
        remote_ops in 1u32..=10,
    ) {
        init_test_logging();
        let node_a = NodeId::new("a");
        let node_b = NodeId::new("b");
        let mut tracker_a = CausalTracker::new(node_a);
        let mut tracker_b = CausalTracker::new(node_b);

        for _ in 0..local_ops {
            tracker_a.record_local_event();
        }
        let sender_clock = tracker_a.on_send();

        for _ in 0..remote_ops {
            tracker_b.record_local_event();
        }
        tracker_b.on_receive(&sender_clock);

        // After receive, B's clock dominates sender's clock
        prop_assert!(
            sender_clock.happens_before(tracker_b.current_clock()),
            "receiver clock must dominate sender after receive"
        );
    }
}

// ============================================================================
// TraceEvent Schema Version Invariant
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(100))]

    /// All TraceEvents created via constructors have the current schema version.
    #[test]
    fn trace_event_version_is_current(kind in arb_trace_event_kind()) {
        init_test_logging();
        let event = TraceEvent::new(0, Time::ZERO, kind, TraceData::None);
        prop_assert_eq!(event.version, TRACE_EVENT_SCHEMA_VERSION);
    }

    /// TraceEventKind Ord is total (all pairs comparable).
    #[test]
    fn trace_event_kind_total_order(k1 in arb_trace_event_kind(), k2 in arb_trace_event_kind()) {
        init_test_logging();
        // Ord requires exactly one of: k1 < k2, k1 == k2, k1 > k2
        let cmp = k1.cmp(&k2);
        let rev = k2.cmp(&k1);
        prop_assert_eq!(cmp, rev.reverse());
    }
}

// ============================================================================
// LogicalTime Cross-Kind Safety
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(100))]

    /// LogicalTime partial_cmp returns None for mismatched clock kinds.
    #[test]
    fn logical_time_cross_kind_incomparable(
        lamport_val in any::<u64>(),
        vc in arb_vector_clock(),
    ) {
        init_test_logging();
        let lt_lamport = LogicalTime::Lamport(LamportTime::from_raw(lamport_val));
        let lt_vector = LogicalTime::Vector(vc);
        prop_assert_eq!(lt_lamport.partial_cmp(&lt_vector), None);
        prop_assert_eq!(lt_vector.partial_cmp(&lt_lamport), None);
    }

    /// LogicalTime causal_order returns Concurrent for mismatched clock kinds.
    #[test]
    fn logical_time_cross_kind_concurrent(
        lamport_val in any::<u64>(),
        vc in arb_vector_clock(),
    ) {
        init_test_logging();
        let lt_lamport = LogicalTime::Lamport(LamportTime::from_raw(lamport_val));
        let lt_vector = LogicalTime::Vector(vc);
        prop_assert_eq!(lt_lamport.causal_order(&lt_vector), CausalOrder::Concurrent);
    }
}
