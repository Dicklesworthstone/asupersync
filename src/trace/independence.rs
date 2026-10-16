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
/// Events with an empty footprint (ordinary `UserTrace` annotations) are independent of all
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

        // === User trace: ownership messages carry real resources ===
        (UserTrace, _) => match super::event::decode_obligation_handoff(event) {
            Ok(Some(handoff)) => vec![
                ResourceAccess::write(Resource::Obligation(handoff.id)),
                ResourceAccess::write(Resource::Task(handoff.source_holder)),
                ResourceAccess::write(Resource::Task(handoff.destination_holder)),
                ResourceAccess::write(Resource::Region(handoff.source_region)),
                ResourceAccess::write(Resource::Region(handoff.destination_region)),
            ],
            Ok(None) => vec![],
            Err(_) => vec![ResourceAccess::write(Resource::GlobalState)],
        },

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

    // Unknown ownership cannot commute with any event, including an empty
    // annotation. GlobalState alone does not intersect every typed footprint.
    if super::event::decode_obligation_handoff(a).is_err()
        || super::event::decode_obligation_handoff(b).is_err()
    {
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
#[path = "independence_inline_tests.rs"]
mod tests;
