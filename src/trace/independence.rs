//! Independence relation over trace events for DPOR.
//!
//! Two trace events are *independent* if swapping their order does not change
//! observable behavior. The relation is symmetric and irreflexive.
//!
//! Independence is defined via resource footprints: each event accesses a set
//! of resources with read or write mode. Events conflict when they access the
//! same resource and at least one access is a write. Independent events have
//! no conflicts.
//!
//! # Resource model
//!
//! The runtime state is modeled as a set of typed resources:
//!
//! | Resource | Semantics |
//! |----------|-----------|
//! | `Task(id)` | Execution state of a single task |
//! | `Region(id)` | Lifecycle state of a single region |
//! | `Obligation(id)` | Resolution state of a single obligation |
//! | `Timer(id)` | A scheduled timer |
//! | `IoToken(id)` | An I/O registration |
//! | `GlobalClock` | The simulated clock (advanced by `TimeAdvance`) |
//! | `GlobalRng` | The deterministic RNG state |
//! | `GlobalState` | Global runtime state (checkpoints, chaos) |
//!
//! # References
//!
//! - Mazurkiewicz, "Trace theory" (1987)
//! - Flanagan & Godefroid, "Dynamic partial-order reduction" (2005)

use crate::trace::event::{TraceData, TraceEvent, TraceEventKind};
use crate::types::{ObligationId, RegionId, TaskId};

/// A runtime resource accessed by a trace event.
///
/// Each variant identifies a distinct piece of runtime state. Two events that
/// both access the same `Resource` with at least one [`AccessMode::Write`]
/// are considered *dependent* (they cannot be freely reordered).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Resource {
    /// Execution state of a specific task.
    Task(TaskId),
    /// Lifecycle state of a specific region.
    Region(RegionId),
    /// Resolution state of a specific obligation.
    Obligation(ObligationId),
    /// A specific timer.
    Timer(u64),
    /// A specific I/O registration.
    IoToken(u64),
    /// The global simulated clock.
    GlobalClock,
    /// The global RNG state.
    GlobalRng,
    /// Global runtime state (checkpoints, chaos injection).
    GlobalState,
}

/// Access mode for a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessMode {
    /// Read-only: compatible with other reads on the same resource.
    Read,
    /// Write: conflicts with both reads and writes on the same resource.
    Write,
}

/// A resource access: resource identity plus access mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceAccess {
    /// The resource being accessed.
    pub resource: Resource,
    /// How the resource is accessed.
    pub mode: AccessMode,
}

impl ResourceAccess {
    /// Create a read access to the given resource.
    #[must_use]
    pub fn read(resource: Resource) -> Self {
        Self {
            resource,
            mode: AccessMode::Read,
        }
    }

    /// Create a write access to the given resource.
    #[must_use]
    pub fn write(resource: Resource) -> Self {
        Self {
            resource,
            mode: AccessMode::Write,
        }
    }
}

/// Check whether two resource accesses conflict.
///
/// A conflict occurs when both accesses target the same resource and at least
/// one is a write. Two concurrent reads never conflict.
#[must_use]
pub fn accesses_conflict(a: &ResourceAccess, b: &ResourceAccess) -> bool {
    a.resource == b.resource && (a.mode == AccessMode::Write || b.mode == AccessMode::Write)
}

/// Compute the resource footprint of a trace event.
///
/// Returns the set of (resource, access-mode) pairs that this event touches.
/// Events with an empty footprint (like `UserTrace`) are independent of all
/// other events (except themselves, by irreflexivity).
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn resource_footprint(event: &TraceEvent) -> Vec<ResourceAccess> {
    use TraceEventKind::{
        CancelAck, CancelRequest, ChaosInjection, Checkpoint, Complete, DownDelivered,
        ExitDelivered, FuturelockDetected, IoError, IoReady, IoRequested, IoResult, LinkCreated,
        LinkDropped, MonitorCreated, MonitorDropped, ObligationAbort, ObligationCommit,
        ObligationLeak, ObligationReserve, Poll, RegionCancelled, RegionCloseBegin,
        RegionCloseComplete, RegionCreated, RngSeed, RngValue, Schedule, Spawn, TimeAdvance,
        TimerCancelled, TimerFired, TimerScheduled, UserTrace, Wake, Yield,
    };

    match (&event.kind, &event.data) {
        // === Task lifecycle: write task state, read region membership ===
        (Spawn | Schedule | Yield | Wake | Poll | Complete, TraceData::Task { task, region })
        | (CancelAck, TraceData::Cancel { task, region, .. }) => {
            vec![
                ResourceAccess::write(Resource::Task(*task)),
                ResourceAccess::read(Resource::Region(*region)),
            ]
        }

        // === Cancel request: writes both task and region (propagation) ===
        (CancelRequest, TraceData::Cancel { task, region, .. }) => {
            vec![
                ResourceAccess::write(Resource::Task(*task)),
                ResourceAccess::write(Resource::Region(*region)),
            ]
        }

        // === Region created: writes new region, reads parent ===
        (RegionCreated, TraceData::Region { region, parent }) => {
            let mut fp = vec![ResourceAccess::write(Resource::Region(*region))];
            if let Some(p) = parent {
                fp.push(ResourceAccess::read(Resource::Region(*p)));
            }
            fp
        }

        // === Region close / complete / cancelled: writes region ===
        (RegionCloseBegin | RegionCloseComplete, TraceData::Region { region, .. })
        | (RegionCancelled, TraceData::RegionCancel { region, .. }) => {
            vec![ResourceAccess::write(Resource::Region(*region))]
        }

        // === Obligation events: write obligation, read task and region ===
        (
            ObligationReserve | ObligationCommit | ObligationAbort | ObligationLeak,
            TraceData::Obligation {
                obligation,
                task,
                region,
                ..
            },
        ) => {
            vec![
                ResourceAccess::write(Resource::Obligation(*obligation)),
                ResourceAccess::read(Resource::Task(*task)),
                ResourceAccess::read(Resource::Region(*region)),
            ]
        }

        // === Time advance: writes global clock ===
        (TimeAdvance, _) => {
            vec![ResourceAccess::write(Resource::GlobalClock)]
        }

        // === Timer events: write timer, read global clock ===
        (TimerScheduled | TimerFired | TimerCancelled, TraceData::Timer { timer_id, .. }) => {
            vec![
                ResourceAccess::write(Resource::Timer(*timer_id)),
                ResourceAccess::read(Resource::GlobalClock),
            ]
        }

        // === I/O events: write I/O resource === // ubs:ignore — "token" refers to IoToken type, not a secret
        (IoRequested, TraceData::IoRequested { token, .. })
        | (IoReady, TraceData::IoReady { token, .. })
        | (IoResult, TraceData::IoResult { token, .. })
        | (IoError, TraceData::IoError { token, .. }) => {
            vec![ResourceAccess::write(Resource::IoToken(*token))]
        }

        // === RNG events: write global RNG ===
        (RngSeed | RngValue, _) => {
            vec![ResourceAccess::write(Resource::GlobalRng)]
        }

        // === Checkpoint: read global state (pure observation) ===
        (Checkpoint, _) => {
            vec![ResourceAccess::read(Resource::GlobalState)]
        }

        // === Futurelock detection: read task and region (observation) ===
        (FuturelockDetected, TraceData::Futurelock { task, region, .. }) => {
            vec![
                ResourceAccess::read(Resource::Task(*task)),
                ResourceAccess::read(Resource::Region(*region)),
            ]
        }

        // === Chaos injection: write global state, optionally write task ===
        (ChaosInjection, TraceData::Chaos { task, .. }) => {
            let mut fp = vec![ResourceAccess::write(Resource::GlobalState)];
            if let Some(t) = task {
                fp.push(ResourceAccess::write(Resource::Task(*t)));
            }
            fp
        }

        // === User trace: no resource footprint (pure annotation) ===
        (UserTrace, _) => {
            vec![]
        }

        // === Monitor / Down (Spork) ===
        //
        // Conservative footprint: treat these as touching the involved tasks
        // (and watcher region) so Foata layers can commute truly independent
        // notifications while preserving per-task ordering.
        (
            MonitorCreated | MonitorDropped,
            TraceData::Monitor {
                watcher,
                watcher_region,
                monitored,
                ..
            },
        ) => vec![
            ResourceAccess::write(Resource::Task(*watcher)),
            ResourceAccess::read(Resource::Region(*watcher_region)),
            ResourceAccess::read(Resource::Task(*monitored)),
        ],
        (
            DownDelivered,
            TraceData::Down {
                watcher, monitored, ..
            },
        ) => vec![
            ResourceAccess::write(Resource::Task(*watcher)),
            ResourceAccess::read(Resource::Task(*monitored)),
            ResourceAccess::read(Resource::GlobalClock),
        ],

        // === Link / Exit (Spork) ===
        (
            LinkCreated | LinkDropped,
            TraceData::Link {
                task_a,
                region_a,
                task_b,
                region_b,
                ..
            },
        ) => vec![
            ResourceAccess::write(Resource::Task(*task_a)),
            ResourceAccess::read(Resource::Region(*region_a)),
            ResourceAccess::write(Resource::Task(*task_b)),
            ResourceAccess::read(Resource::Region(*region_b)),
        ],
        (ExitDelivered, TraceData::Exit { from, to, .. }) => vec![
            ResourceAccess::read(Resource::Task(*from)),
            ResourceAccess::write(Resource::Task(*to)),
            ResourceAccess::read(Resource::GlobalClock),
        ],

        // === Fallback: conservative global state write ===
        // Handles unexpected kind/data combinations safely.
        _ => {
            vec![ResourceAccess::write(Resource::GlobalState)]
        }
    }
}

/// Check whether two trace events are independent.
///
/// Independent events can be reordered without changing observable behavior.
/// The relation is:
/// - **Symmetric**: `independent(a, b) == independent(b, a)`
/// - **Irreflexive**: `!independent(e, e)` for any event `e`
///
/// Returns `false` if the events access the same resource with at least one
/// write, or if they are the same event instance (same sequence number).
#[must_use]
pub fn independent(a: &TraceEvent, b: &TraceEvent) -> bool {
    // Irreflexivity: same event instance.
    if a.seq == b.seq {
        return false;
    }

    let fa = resource_footprint(a);
    let fb = resource_footprint(b);

    // Events with empty footprints are independent of everything.
    if fa.is_empty() || fb.is_empty() {
        return true;
    }

    // Check all pairs for conflicts.
    for ra in &fa {
        for rb in &fb {
            if accesses_conflict(ra, rb) {
                return false;
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::ObligationKind;
    use crate::types::{CancelReason, Time};

    // === Helper constructors ===

    fn tid(n: u32) -> TaskId {
        TaskId::new_for_test(n, 0)
    }

    fn rid(n: u32) -> RegionId {
        RegionId::new_for_test(n, 0)
    }

    fn oid(n: u32) -> ObligationId {
        ObligationId::new_for_test(n, 0)
    }

    // === Irreflexivity ===

    #[test]
    fn irreflexive_spawn() {
        let e = TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1));
        assert!(!independent(&e, &e));
    }

    #[test]
    fn irreflexive_user_trace() {
        let e = TraceEvent::user_trace(1, Time::ZERO, "hello");
        assert!(!independent(&e, &e));
    }

    // === Symmetry ===

    #[test]
    fn symmetry_dependent() {
        let a = TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1));
        let b = TraceEvent::complete(2, Time::ZERO, tid(1), rid(1));
        assert_eq!(independent(&a, &b), independent(&b, &a));
        assert!(!independent(&a, &b));
    }

    #[test]
    fn symmetry_independent() {
        let a = TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1));
        let b = TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2));
        assert_eq!(independent(&a, &b), independent(&b, &a));
        assert!(independent(&a, &b));
    }

    // === Task events ===

    #[test]
    fn same_task_events_are_dependent() {
        let a = TraceEvent::schedule(1, Time::ZERO, tid(1), rid(1));
        let b = TraceEvent::complete(2, Time::ZERO, tid(1), rid(1));
        assert!(!independent(&a, &b));
    }

    #[test]
    fn different_tasks_different_regions_are_independent() {
        let a = TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1));
        let b = TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2));
        assert!(independent(&a, &b));
    }

    #[test]
    fn different_tasks_same_region_are_independent() {
        // Both only read the region, so no conflict.
        let a = TraceEvent::schedule(1, Time::ZERO, tid(1), rid(1));
        let b = TraceEvent::schedule(2, Time::ZERO, tid(2), rid(1));
        assert!(independent(&a, &b));
    }

    // === Cancel events ===

    #[test]
    fn cancel_request_conflicts_with_task_in_same_region() {
        // CancelRequest writes region, Spawn reads region -> conflict.
        let a =
            TraceEvent::cancel_request(1, Time::ZERO, tid(1), rid(1), CancelReason::user("test"));
        let b = TraceEvent::spawn(2, Time::ZERO, tid(2), rid(1));
        assert!(!independent(&a, &b));
    }

    #[test]
    fn cancel_request_independent_of_different_region() {
        let a =
            TraceEvent::cancel_request(1, Time::ZERO, tid(1), rid(1), CancelReason::user("test"));
        let b = TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2));
        assert!(independent(&a, &b));
    }

    // === Region events ===

    #[test]
    fn region_create_conflicts_with_spawn_in_same_region() {
        // RegionCreated writes R1, Spawn reads R1 -> conflict.
        let a = TraceEvent::region_created(1, Time::ZERO, rid(1), None);
        let b = TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1));
        assert!(!independent(&a, &b));
    }

    #[test]
    fn region_create_independent_of_different_region_task() {
        let a = TraceEvent::region_created(1, Time::ZERO, rid(1), None);
        let b = TraceEvent::spawn(2, Time::ZERO, tid(1), rid(2));
        assert!(independent(&a, &b));
    }

    #[test]
    fn child_region_create_depends_on_parent_region_events() {
        // Child region reads parent; region cancel writes parent -> conflict.
        let a = TraceEvent::region_created(1, Time::ZERO, rid(2), Some(rid(1)));
        let b = TraceEvent::region_cancelled(2, Time::ZERO, rid(1), CancelReason::user("test"));
        assert!(!independent(&a, &b));
    }

    // === Obligation events ===

    #[test]
    fn same_obligation_events_are_dependent() {
        let a = TraceEvent::obligation_reserve(
            1,
            Time::ZERO,
            oid(1),
            tid(1),
            rid(1),
            ObligationKind::SendPermit,
        );
        let b = TraceEvent::obligation_commit(
            2,
            Time::ZERO,
            oid(1),
            tid(1),
            rid(1),
            ObligationKind::SendPermit,
            1000,
        );
        assert!(!independent(&a, &b));
    }

    #[test]
    fn different_obligation_events_are_independent() {
        let a = TraceEvent::obligation_reserve(
            1,
            Time::ZERO,
            oid(1),
            tid(1),
            rid(1),
            ObligationKind::SendPermit,
        );
        let b = TraceEvent::obligation_reserve(
            2,
            Time::ZERO,
            oid(2),
            tid(2),
            rid(2),
            ObligationKind::Ack,
        );
        assert!(independent(&a, &b));
    }

    #[test]
    fn obligation_conflicts_with_task_write_on_same_task() {
        // Obligation reads task; task event writes task -> conflict.
        let a = TraceEvent::obligation_reserve(
            1,
            Time::ZERO,
            oid(1),
            tid(1),
            rid(1),
            ObligationKind::SendPermit,
        );
        let b = TraceEvent::complete(2, Time::ZERO, tid(1), rid(1));
        assert!(!independent(&a, &b));
    }

    // === Timer events ===

    #[test]
    fn time_advance_conflicts_with_timer() {
        let a = TraceEvent::time_advance(1, Time::ZERO, Time::ZERO, Time::from_nanos(1000));
        let b = TraceEvent::timer_fired(2, Time::ZERO, 42);
        assert!(!independent(&a, &b));
    }

    #[test]
    fn different_timers_are_independent() {
        let a = TraceEvent::timer_scheduled(1, Time::ZERO, 1, Time::from_nanos(1000));
        let b = TraceEvent::timer_scheduled(2, Time::ZERO, 2, Time::from_nanos(2000));
        assert!(independent(&a, &b));
    }

    #[test]
    fn same_timer_events_are_dependent() {
        let a = TraceEvent::timer_scheduled(1, Time::ZERO, 42, Time::from_nanos(1000));
        let b = TraceEvent::timer_fired(2, Time::ZERO, 42);
        assert!(!independent(&a, &b));
    }

    // === I/O events ===

    #[test]
    fn different_io_tokens_are_independent() {
        let a = TraceEvent::io_ready(1, Time::ZERO, 10, 0x01);
        let b = TraceEvent::io_ready(2, Time::ZERO, 20, 0x02);
        assert!(independent(&a, &b));
    }

    #[test]
    fn same_io_token_events_are_dependent() {
        let a = TraceEvent::io_requested(1, Time::ZERO, 10, 0x01);
        let b = TraceEvent::io_result(2, Time::ZERO, 10, 512);
        assert!(!independent(&a, &b));
    }

    // === RNG events ===

    #[test]
    fn rng_events_are_dependent() {
        let a = TraceEvent::rng_seed(1, Time::ZERO, 0xDEAD);
        let b = TraceEvent::rng_value(2, Time::ZERO, 42);
        assert!(!independent(&a, &b));
    }

    #[test]
    fn rng_independent_of_task_events() {
        let a = TraceEvent::rng_value(1, Time::ZERO, 42);
        let b = TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1));
        assert!(independent(&a, &b));
    }

    // === UserTrace ===

    #[test]
    fn user_trace_independent_of_everything() {
        let u = TraceEvent::user_trace(1, Time::ZERO, "annotation");
        let events = [
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::time_advance(3, Time::ZERO, Time::ZERO, Time::from_nanos(1)),
            TraceEvent::rng_value(4, Time::ZERO, 42),
            TraceEvent::io_ready(5, Time::ZERO, 1, 0x01),
            TraceEvent::timer_fired(6, Time::ZERO, 1),
            TraceEvent::checkpoint(7, Time::ZERO, 1, 10, 5),
        ];
        for e in &events {
            assert!(
                independent(&u, e),
                "UserTrace should be independent of {:?}",
                e.kind
            );
            assert!(
                independent(e, &u),
                "Symmetry: {:?} should be independent of UserTrace",
                e.kind
            );
        }
    }

    // === Checkpoint ===

    #[test]
    fn checkpoints_are_independent_of_each_other() {
        // Both read GlobalState — no conflict.
        let a = TraceEvent::checkpoint(1, Time::ZERO, 1, 10, 5);
        let b = TraceEvent::checkpoint(2, Time::ZERO, 2, 12, 6);
        assert!(independent(&a, &b));
    }

    #[test]
    fn checkpoint_conflicts_with_chaos_injection() {
        // Checkpoint reads GlobalState, ChaosInjection writes GlobalState.
        let a = TraceEvent::checkpoint(1, Time::ZERO, 1, 10, 5);
        let b = TraceEvent::new(
            2,
            Time::ZERO,
            TraceEventKind::ChaosInjection,
            TraceData::Chaos {
                kind: "delay".into(),
                task: None,
                detail: "test".into(),
            },
        );
        assert!(!independent(&a, &b));
    }

    // === Cross-category independence ===

    #[test]
    fn task_event_independent_of_unrelated_io() {
        let a = TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1));
        let b = TraceEvent::io_ready(2, Time::ZERO, 99, 0x01);
        assert!(independent(&a, &b));
    }

    #[test]
    fn timer_independent_of_obligation() {
        let a = TraceEvent::timer_fired(1, Time::ZERO, 1);
        let b = TraceEvent::obligation_reserve(
            2,
            Time::ZERO,
            oid(1),
            tid(1),
            rid(1),
            ObligationKind::Lease,
        );
        assert!(independent(&a, &b));
    }

    // === Resource footprint ===

    #[test]
    fn spawn_footprint() {
        let e = TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1));
        let fp = resource_footprint(&e);
        assert_eq!(fp.len(), 2);
        assert_eq!(fp[0], ResourceAccess::write(Resource::Task(tid(1))));
        assert_eq!(fp[1], ResourceAccess::read(Resource::Region(rid(1))));
    }

    #[test]
    fn user_trace_empty_footprint() {
        let e = TraceEvent::user_trace(1, Time::ZERO, "no resources");
        let fp = resource_footprint(&e);
        assert!(fp.is_empty());
    }

    #[test]
    fn obligation_footprint_has_three_accesses() {
        let e = TraceEvent::obligation_reserve(
            1,
            Time::ZERO,
            oid(5),
            tid(3),
            rid(2),
            ObligationKind::Lease,
        );
        let fp = resource_footprint(&e);
        assert_eq!(fp.len(), 3);
        assert_eq!(fp[0], ResourceAccess::write(Resource::Obligation(oid(5))));
        assert_eq!(fp[1], ResourceAccess::read(Resource::Task(tid(3))));
        assert_eq!(fp[2], ResourceAccess::read(Resource::Region(rid(2))));
    }

    // === Conflict function ===

    #[test]
    fn two_reads_do_not_conflict() {
        let a = ResourceAccess::read(Resource::Task(tid(1)));
        let b = ResourceAccess::read(Resource::Task(tid(1)));
        assert!(!accesses_conflict(&a, &b));
    }

    #[test]
    fn read_write_conflict() {
        let a = ResourceAccess::read(Resource::Task(tid(1)));
        let b = ResourceAccess::write(Resource::Task(tid(1)));
        assert!(accesses_conflict(&a, &b));
    }

    #[test]
    fn write_write_conflict() {
        let a = ResourceAccess::write(Resource::Task(tid(1)));
        let b = ResourceAccess::write(Resource::Task(tid(1)));
        assert!(accesses_conflict(&a, &b));
    }

    #[test]
    fn different_resources_no_conflict() {
        let a = ResourceAccess::write(Resource::Task(tid(1)));
        let b = ResourceAccess::write(Resource::Task(tid(2)));
        assert!(!accesses_conflict(&a, &b));
    }

    #[test]
    fn access_mode_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let a = AccessMode::Read;
        let b = a; // Copy
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, AccessMode::Write);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Read"));
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }
}
