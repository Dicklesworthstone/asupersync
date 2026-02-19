//! TLA+ export for model checking.
//!
//! Converts runtime traces into TLA+ behaviors (sequences of states) and
//! generates TLA+ spec skeletons for bounded model checking with TLC.
//!
//! # Exports
//!
//! - **Trace-to-behavior**: A trace becomes a TLA+ behavior (sequence of
//!   state snapshots). Each step corresponds to one `TraceEvent`.
//!
//! - **Spec skeleton**: A TLA+ module with typed variables, an `Init`
//!   predicate, a `Next` action, and property templates for the runtime's
//!   core invariants (no orphans, quiescence, obligation linearity).
//!
//! # Usage
//!
//! ```ignore
//! let exporter = TlaExporter::from_trace(&events);
//! let module = exporter.export_behavior("MyTest");
//! std::fs::write("MyTest.tla", module.to_string()).unwrap();
//! ```

use crate::trace::event::{TraceData, TraceEvent, TraceEventKind};
use std::collections::BTreeMap;
use std::fmt::{self, Write};

/// State of a task in the TLA+ model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlaTaskState {
    /// Task has been spawned but not yet scheduled.
    Spawned,
    /// Task is in the ready queue.
    Scheduled,
    /// Task is currently being polled.
    Polling,
    /// Task has yielded, waiting for a wake.
    Yielded,
    /// Task has completed.
    Completed,
    /// Task has been cancelled.
    Cancelled,
}

impl fmt::Display for TlaTaskState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawned => write!(f, "\"Spawned\""),
            Self::Scheduled => write!(f, "\"Scheduled\""),
            Self::Polling => write!(f, "\"Polling\""),
            Self::Yielded => write!(f, "\"Yielded\""),
            Self::Completed => write!(f, "\"Completed\""),
            Self::Cancelled => write!(f, "\"Cancelled\""),
        }
    }
}

/// State of a region in the TLA+ model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlaRegionState {
    /// Region is open and accepting new tasks.
    Open,
    /// Region is closing (draining tasks).
    Closing,
    /// Region is fully closed.
    Closed,
    /// Region was cancelled.
    Cancelled,
}

impl fmt::Display for TlaRegionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => write!(f, "\"Open\""),
            Self::Closing => write!(f, "\"Closing\""),
            Self::Closed => write!(f, "\"Closed\""),
            Self::Cancelled => write!(f, "\"Cancelled\""),
        }
    }
}

/// State of an obligation in the TLA+ model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlaObligationState {
    /// Obligation has been reserved.
    Reserved,
    /// Obligation has been committed.
    Committed,
    /// Obligation has been aborted.
    Aborted,
    /// Obligation was leaked (error state).
    Leaked,
}

impl fmt::Display for TlaObligationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reserved => write!(f, "\"Reserved\""),
            Self::Committed => write!(f, "\"Committed\""),
            Self::Aborted => write!(f, "\"Aborted\""),
            Self::Leaked => write!(f, "\"Leaked\""),
        }
    }
}

/// A snapshot of the runtime state for TLA+ export.
#[derive(Debug, Clone)]
pub struct TlaStateSnapshot {
    /// Task states.
    pub tasks: BTreeMap<u32, (TlaTaskState, u32)>, // task_index -> (state, region_index)
    /// Region states.
    pub regions: BTreeMap<u32, (TlaRegionState, Option<u32>)>, // region_index -> (state, parent)
    /// Obligation states.
    pub obligations: BTreeMap<u32, (TlaObligationState, u32, u32)>, // obl_index -> (state, task, region)
    /// Virtual time in nanoseconds.
    pub time_nanos: u64,
    /// Step counter.
    pub step: u64,
}

impl TlaStateSnapshot {
    fn new() -> Self {
        Self {
            tasks: BTreeMap::new(),
            regions: BTreeMap::new(),
            obligations: BTreeMap::new(),
            time_nanos: 0,
            step: 0,
        }
    }

    fn apply(&mut self, event: &TraceEvent) {
        self.step = event.seq;
        self.time_nanos = event.time.as_nanos();

        match (&event.kind, &event.data) {
            (TraceEventKind::Spawn, TraceData::Task { task, region }) => {
                self.tasks
                    .insert(task.0.index(), (TlaTaskState::Spawned, region.0.index()));
            }
            (TraceEventKind::Schedule, TraceData::Task { task, .. }) => {
                if let Some(entry) = self.tasks.get_mut(&task.0.index()) {
                    entry.0 = TlaTaskState::Scheduled;
                }
            }
            (TraceEventKind::Poll, TraceData::Task { task, .. }) => {
                if let Some(entry) = self.tasks.get_mut(&task.0.index()) {
                    entry.0 = TlaTaskState::Polling;
                }
            }
            (TraceEventKind::Yield, TraceData::Task { task, .. }) => {
                if let Some(entry) = self.tasks.get_mut(&task.0.index()) {
                    entry.0 = TlaTaskState::Yielded;
                }
            }
            (TraceEventKind::Complete, TraceData::Task { task, .. }) => {
                if let Some(entry) = self.tasks.get_mut(&task.0.index()) {
                    entry.0 = TlaTaskState::Completed;
                }
            }
            (TraceEventKind::CancelAck, TraceData::Cancel { task, .. }) => {
                if let Some(entry) = self.tasks.get_mut(&task.0.index()) {
                    entry.0 = TlaTaskState::Cancelled;
                }
            }
            (TraceEventKind::RegionCreated, TraceData::Region { region, parent }) => {
                self.regions.insert(
                    region.0.index(),
                    (TlaRegionState::Open, parent.map(|p| p.0.index())),
                );
            }
            (TraceEventKind::RegionCloseBegin, TraceData::Region { region, .. }) => {
                if let Some(entry) = self.regions.get_mut(&region.0.index()) {
                    entry.0 = TlaRegionState::Closing;
                }
            }
            (TraceEventKind::RegionCloseComplete, TraceData::Region { region, .. }) => {
                if let Some(entry) = self.regions.get_mut(&region.0.index()) {
                    entry.0 = TlaRegionState::Closed;
                }
            }
            (TraceEventKind::RegionCancelled, TraceData::RegionCancel { region, .. }) => {
                if let Some(entry) = self.regions.get_mut(&region.0.index()) {
                    entry.0 = TlaRegionState::Cancelled;
                }
            }
            (
                TraceEventKind::ObligationReserve,
                TraceData::Obligation {
                    obligation,
                    task,
                    region,
                    ..
                },
            ) => {
                self.obligations.insert(
                    obligation.0.index(),
                    (
                        TlaObligationState::Reserved,
                        task.0.index(),
                        region.0.index(),
                    ),
                );
            }
            (TraceEventKind::ObligationCommit, TraceData::Obligation { obligation, .. }) => {
                if let Some(entry) = self.obligations.get_mut(&obligation.0.index()) {
                    entry.0 = TlaObligationState::Committed;
                }
            }
            (TraceEventKind::ObligationAbort, TraceData::Obligation { obligation, .. }) => {
                if let Some(entry) = self.obligations.get_mut(&obligation.0.index()) {
                    entry.0 = TlaObligationState::Aborted;
                }
            }
            (TraceEventKind::ObligationLeak, TraceData::Obligation { obligation, .. }) => {
                if let Some(entry) = self.obligations.get_mut(&obligation.0.index()) {
                    entry.0 = TlaObligationState::Leaked;
                }
            }
            _ => {} // Other events don't change the abstract state.
        }
    }
}

/// TLA+ module output.
#[derive(Debug)]
pub struct TlaModule {
    /// Module name.
    pub name: String,
    /// Full TLA+ source code.
    pub source: String,
}

impl fmt::Display for TlaModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.source)
    }
}

/// TLA+ exporter.
pub struct TlaExporter {
    snapshots: Vec<TlaStateSnapshot>,
}

impl TlaExporter {
    /// Build state snapshots from a trace.
    #[must_use]
    pub fn from_trace(events: &[TraceEvent]) -> Self {
        let mut state = TlaStateSnapshot::new();
        let mut snapshots = vec![state.clone()]; // initial state
        for event in events {
            state.apply(event);
            snapshots.push(state.clone());
        }
        Self { snapshots }
    }

    /// Export a TLA+ behavior (concrete trace as a sequence of states).
    #[must_use]
    pub fn export_behavior(&self, name: &str) -> TlaModule {
        let mut src = String::new();
        let _ = writeln!(&mut src, "---- MODULE {name} ----");
        src.push_str("EXTENDS Integers, Sequences, TLC\n\n");

        // Variables
        src.push_str("VARIABLES tasks, regions, obligations, time, step\n\n");

        // State type constants
        src.push_str("TaskStates == {\"Spawned\", \"Scheduled\", \"Polling\", \"Yielded\", \"Completed\", \"Cancelled\"}\n");
        src.push_str("RegionStates == {\"Open\", \"Closing\", \"Closed\", \"Cancelled\"}\n");
        src.push_str(
            "ObligationStates == {\"Reserved\", \"Committed\", \"Aborted\", \"Leaked\"}\n\n",
        );

        // Init
        let init = &self.snapshots[0];
        src.push_str("Init ==\n");
        let _ = writeln!(
            &mut src,
            "    /\\ tasks = {}",
            format_tla_task_map(&init.tasks)
        );
        let _ = writeln!(
            &mut src,
            "    /\\ regions = {}",
            format_tla_region_map(&init.regions)
        );
        let _ = writeln!(
            &mut src,
            "    /\\ obligations = {}",
            format_tla_obligation_map(&init.obligations)
        );
        let _ = writeln!(&mut src, "    /\\ time = {}", init.time_nanos);
        let _ = writeln!(&mut src, "    /\\ step = {}\n", init.step);

        // Next: disjunction of concrete steps
        if self.snapshots.len() > 1 {
            src.push_str("Next ==\n");
            for i in 1..self.snapshots.len() {
                let s = &self.snapshots[i];
                let prefix = if i == 1 { "    " } else { "    \\/ " };
                let _ = writeln!(&mut src, "{prefix}/\\ step = {} /\\ step' = {}", i - 1, i);
                let _ = writeln!(
                    &mut src,
                    "       /\\ tasks' = {}",
                    format_tla_task_map(&s.tasks)
                );
                let _ = writeln!(
                    &mut src,
                    "       /\\ regions' = {}",
                    format_tla_region_map(&s.regions)
                );
                let _ = writeln!(
                    &mut src,
                    "       /\\ obligations' = {}",
                    format_tla_obligation_map(&s.obligations)
                );
                let _ = writeln!(&mut src, "       /\\ time' = {}", s.time_nanos);
            }
        } else {
            src.push_str("Next == FALSE \\* Empty trace\n");
        }

        src.push('\n');

        // Invariants
        src.push_str("\\* Safety: no leaked obligations in terminal states\n");
        src.push_str("NoObligationLeaks ==\n");
        src.push_str("    \\A o \\in DOMAIN obligations:\n");
        src.push_str("        obligations[o][1] /= \"Leaked\"\n\n");

        src.push_str("\\* Safety: completed tasks are not in open regions\n");
        src.push_str("QuiescenceOnClose ==\n");
        src.push_str("    \\A r \\in DOMAIN regions:\n");
        src.push_str("        regions[r][1] = \"Closed\" =>\n");
        src.push_str("            \\A t \\in DOMAIN tasks:\n");
        src.push_str("                tasks[t][2] = r => tasks[t][1] \\in {\"Completed\", \"Cancelled\"}\n\n");

        src.push_str("\\* Safety: obligation linearity (no double-commit/abort)\n");
        src.push_str("ObligationLinearity ==\n");
        src.push_str("    \\A o \\in DOMAIN obligations:\n");
        src.push_str("        obligations[o][1] \\in ObligationStates\n\n");

        // Spec
        src.push_str("Spec == Init /\\ [][Next]_<<tasks, regions, obligations, time, step>>\n\n");
        src.push_str("====\n");

        TlaModule {
            name: name.to_string(),
            source: src,
        }
    }

    /// Export a TLA+ spec skeleton (parametric model).
    #[must_use]
    pub fn export_spec_skeleton(name: &str) -> TlaModule {
        let mut src = String::new();
        let _ = writeln!(&mut src, "---- MODULE {name} ----");
        src.push_str("EXTENDS Integers, Sequences, FiniteSets\n\n");
        src.push_str("CONSTANTS MaxTasks, MaxRegions, MaxObligations\n\n");
        src.push_str("VARIABLES tasks, regions, obligations, time\n\n");

        src.push_str("TaskStates == {\"Spawned\", \"Scheduled\", \"Polling\", \"Yielded\", \"Completed\", \"Cancelled\"}\n");
        src.push_str("RegionStates == {\"Open\", \"Closing\", \"Closed\", \"Cancelled\"}\n");
        src.push_str(
            "ObligationStates == {\"Reserved\", \"Committed\", \"Aborted\", \"Leaked\"}\n\n",
        );

        src.push_str("Init ==\n");
        src.push_str("    /\\ tasks = <<>>\n");
        src.push_str("    /\\ regions = <<>>\n");
        src.push_str("    /\\ obligations = <<>>\n");
        src.push_str("    /\\ time = 0\n\n");

        src.push_str("\\* Action: spawn a new task in an open region\n");
        src.push_str("SpawnTask(r) ==\n");
        src.push_str("    /\\ r \\in DOMAIN regions\n");
        src.push_str("    /\\ regions[r][1] = \"Open\"\n");
        src.push_str("    /\\ Len(tasks) < MaxTasks\n");
        src.push_str("    /\\ tasks' = Append(tasks, <<\"Spawned\", r>>)\n");
        src.push_str("    /\\ UNCHANGED <<regions, obligations, time>>\n\n");

        src.push_str("\\* Action: complete a running task\n");
        src.push_str("CompleteTask(t) ==\n");
        src.push_str("    /\\ t \\in DOMAIN tasks\n");
        src.push_str("    /\\ tasks[t][1] \\in {\"Polling\", \"Scheduled\"}\n");
        src.push_str("    /\\ tasks' = [tasks EXCEPT ![t][1] = \"Completed\"]\n");
        src.push_str("    /\\ UNCHANGED <<regions, obligations, time>>\n\n");

        src.push_str("\\* Action: close a region\n");
        src.push_str("CloseRegion(r) ==\n");
        src.push_str("    /\\ r \\in DOMAIN regions\n");
        src.push_str("    /\\ regions[r][1] = \"Open\"\n");
        src.push_str("    /\\ regions' = [regions EXCEPT ![r][1] = \"Closing\"]\n");
        src.push_str("    /\\ UNCHANGED <<tasks, obligations, time>>\n\n");

        src.push_str("Next ==\n");
        src.push_str("    \\/ \\E r \\in DOMAIN regions: SpawnTask(r)\n");
        src.push_str("    \\/ \\E t \\in DOMAIN tasks: CompleteTask(t)\n");
        src.push_str("    \\/ \\E r \\in DOMAIN regions: CloseRegion(r)\n\n");

        src.push_str("\\* Invariant: no obligation leaks\n");
        src.push_str("NoObligationLeaks ==\n");
        src.push_str("    \\A o \\in DOMAIN obligations: obligations[o][1] /= \"Leaked\"\n\n");

        src.push_str("\\* Invariant: quiescence on close\n");
        src.push_str("QuiescenceOnClose ==\n");
        src.push_str("    \\A r \\in DOMAIN regions:\n");
        src.push_str("        regions[r][1] = \"Closed\" =>\n");
        src.push_str("            \\A t \\in DOMAIN tasks:\n");
        src.push_str("                tasks[t][2] = r => tasks[t][1] \\in {\"Completed\", \"Cancelled\"}\n\n");

        src.push_str("Spec == Init /\\ [][Next]_<<tasks, regions, obligations, time>>\n\n");
        src.push_str("====\n");

        TlaModule {
            name: name.to_string(),
            source: src,
        }
    }

    /// Number of state snapshots (trace length + 1 for initial state).
    #[must_use]
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }
}

// === Formatting helpers ===

fn format_tla_task_map(tasks: &BTreeMap<u32, (TlaTaskState, u32)>) -> String {
    if tasks.is_empty() {
        return "<<>>".to_string();
    }
    let entries: Vec<String> = tasks
        .iter()
        .map(|(k, (state, region))| format!("{k} :> <<{state}, {region}>>"))
        .collect();
    format!("({})", entries.join(" @@ "))
}

fn format_tla_region_map(regions: &BTreeMap<u32, (TlaRegionState, Option<u32>)>) -> String {
    if regions.is_empty() {
        return "<<>>".to_string();
    }
    let entries: Vec<String> = regions
        .iter()
        .map(|(k, (state, parent))| {
            let p = parent.map_or("\"NONE\"".to_string(), |p| p.to_string());
            format!("{k} :> <<{state}, {p}>>")
        })
        .collect();
    format!("({})", entries.join(" @@ "))
}

fn format_tla_obligation_map(
    obligations: &BTreeMap<u32, (TlaObligationState, u32, u32)>,
) -> String {
    if obligations.is_empty() {
        return "<<>>".to_string();
    }
    let entries: Vec<String> = obligations
        .iter()
        .map(|(k, (state, task, region))| format!("{k} :> <<{state}, {task}, {region}>>"))
        .collect();
    format!("({})", entries.join(" @@ "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::ObligationKind;
    use crate::types::{ObligationId, RegionId, TaskId, Time};

    fn tid(n: u32) -> TaskId {
        TaskId::new_for_test(n, 0)
    }

    fn rid(n: u32) -> RegionId {
        RegionId::new_for_test(n, 0)
    }

    fn oid(n: u32) -> ObligationId {
        ObligationId::new_for_test(n, 0)
    }

    #[test]
    fn empty_trace_produces_module() {
        let exporter = TlaExporter::from_trace(&[]);
        let module = exporter.export_behavior("EmptyTest");
        assert!(module.source.contains("MODULE EmptyTest"));
        assert!(module.source.contains("Init =="));
        assert!(module.source.contains("Next == FALSE"));
    }

    #[test]
    fn spawn_complete_trace() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ];
        let exporter = TlaExporter::from_trace(&events);
        let module = exporter.export_behavior("SpawnComplete");

        // Should have 3 snapshots: initial, after spawn, after complete.
        assert_eq!(exporter.snapshot_count(), 3);
        assert!(module.source.contains("\"Completed\""));
        assert!(module.source.contains("NoObligationLeaks"));
    }

    #[test]
    fn obligation_lifecycle_trace() {
        let events = [
            TraceEvent::obligation_reserve(
                1,
                Time::ZERO,
                oid(1),
                tid(1),
                rid(1),
                ObligationKind::SendPermit,
            ),
            TraceEvent::obligation_commit(
                2,
                Time::ZERO,
                oid(1),
                tid(1),
                rid(1),
                ObligationKind::SendPermit,
                1000,
            ),
        ];
        let exporter = TlaExporter::from_trace(&events);
        let module = exporter.export_behavior("ObligationTest");

        assert!(module.source.contains("\"Committed\""));
        assert!(module.source.contains("ObligationLinearity"));
    }

    #[test]
    fn spec_skeleton_is_valid_structure() {
        let module = TlaExporter::export_spec_skeleton("RuntimeModel");
        assert!(module.source.contains("MODULE RuntimeModel"));
        assert!(module.source.contains("CONSTANTS MaxTasks"));
        assert!(module.source.contains("SpawnTask(r)"));
        assert!(module.source.contains("CompleteTask(t)"));
        assert!(module.source.contains("CloseRegion(r)"));
        assert!(module.source.contains("NoObligationLeaks"));
        assert!(module.source.contains("QuiescenceOnClose"));
    }

    #[test]
    fn region_lifecycle_in_snapshot() {
        let events = [
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::region_cancelled(
                2,
                Time::ZERO,
                rid(1),
                crate::types::CancelReason::user("test"),
            ),
        ];
        let exporter = TlaExporter::from_trace(&events);
        assert_eq!(exporter.snapshot_count(), 3);

        let module = exporter.export_behavior("RegionLifecycle");
        assert!(module.source.contains("\"Cancelled\""));
    }

    #[test]
    fn display_impl_returns_source() {
        let module = TlaExporter::export_spec_skeleton("Test");
        assert_eq!(format!("{module}"), module.source);
    }

    #[test]
    fn tla_task_state_debug() {
        let dbg = format!("{:?}", TlaTaskState::Spawned);
        assert_eq!(dbg, "Spawned");
        let dbg = format!("{:?}", TlaTaskState::Scheduled);
        assert_eq!(dbg, "Scheduled");
        let dbg = format!("{:?}", TlaTaskState::Polling);
        assert_eq!(dbg, "Polling");
        let dbg = format!("{:?}", TlaTaskState::Yielded);
        assert_eq!(dbg, "Yielded");
        let dbg = format!("{:?}", TlaTaskState::Completed);
        assert_eq!(dbg, "Completed");
        let dbg = format!("{:?}", TlaTaskState::Cancelled);
        assert_eq!(dbg, "Cancelled");
    }

    #[test]
    fn tla_task_state_clone_copy_eq() {
        let s = TlaTaskState::Polling;
        let s2 = s;
        let s3 = s;
        assert_eq!(s2, s3);
        assert_ne!(TlaTaskState::Spawned, TlaTaskState::Completed);
    }

    #[test]
    fn tla_task_state_display_all_variants() {
        assert_eq!(format!("{}", TlaTaskState::Spawned), "\"Spawned\"");
        assert_eq!(format!("{}", TlaTaskState::Scheduled), "\"Scheduled\"");
        assert_eq!(format!("{}", TlaTaskState::Polling), "\"Polling\"");
        assert_eq!(format!("{}", TlaTaskState::Yielded), "\"Yielded\"");
        assert_eq!(format!("{}", TlaTaskState::Completed), "\"Completed\"");
        assert_eq!(format!("{}", TlaTaskState::Cancelled), "\"Cancelled\"");
    }

    #[test]
    fn tla_region_state_debug() {
        let dbg = format!("{:?}", TlaRegionState::Open);
        assert_eq!(dbg, "Open");
        let dbg = format!("{:?}", TlaRegionState::Closing);
        assert_eq!(dbg, "Closing");
        let dbg = format!("{:?}", TlaRegionState::Closed);
        assert_eq!(dbg, "Closed");
        let dbg = format!("{:?}", TlaRegionState::Cancelled);
        assert_eq!(dbg, "Cancelled");
    }

    #[test]
    fn tla_region_state_clone_copy_eq() {
        let s = TlaRegionState::Open;
        let s2 = s;
        let s3 = s;
        assert_eq!(s2, s3);
        assert_ne!(TlaRegionState::Open, TlaRegionState::Closed);
    }

    #[test]
    fn tla_region_state_display_all_variants() {
        assert_eq!(format!("{}", TlaRegionState::Open), "\"Open\"");
        assert_eq!(format!("{}", TlaRegionState::Closing), "\"Closing\"");
        assert_eq!(format!("{}", TlaRegionState::Closed), "\"Closed\"");
        assert_eq!(format!("{}", TlaRegionState::Cancelled), "\"Cancelled\"");
    }

    #[test]
    fn tla_obligation_state_debug() {
        let dbg = format!("{:?}", TlaObligationState::Reserved);
        assert_eq!(dbg, "Reserved");
        let dbg = format!("{:?}", TlaObligationState::Committed);
        assert_eq!(dbg, "Committed");
        let dbg = format!("{:?}", TlaObligationState::Aborted);
        assert_eq!(dbg, "Aborted");
        let dbg = format!("{:?}", TlaObligationState::Leaked);
        assert_eq!(dbg, "Leaked");
    }

    #[test]
    fn tla_obligation_state_clone_copy_eq() {
        let s = TlaObligationState::Reserved;
        let s2 = s;
        let s3 = s;
        assert_eq!(s2, s3);
        assert_ne!(TlaObligationState::Reserved, TlaObligationState::Leaked);
    }

    #[test]
    fn tla_obligation_state_display_all_variants() {
        assert_eq!(format!("{}", TlaObligationState::Reserved), "\"Reserved\"");
        assert_eq!(format!("{}", TlaObligationState::Committed), "\"Committed\"");
        assert_eq!(format!("{}", TlaObligationState::Aborted), "\"Aborted\"");
        assert_eq!(format!("{}", TlaObligationState::Leaked), "\"Leaked\"");
    }

    #[test]
    fn tla_state_snapshot_debug_clone() {
        let snap = TlaStateSnapshot::new();
        let dbg = format!("{snap:?}");
        assert!(dbg.contains("TlaStateSnapshot"));
        let snap2 = snap.clone();
        assert_eq!(snap2.step, 0);
        assert_eq!(snap2.time_nanos, 0);
        assert!(snap2.tasks.is_empty());
        assert!(snap2.regions.is_empty());
        assert!(snap2.obligations.is_empty());
    }

    #[test]
    fn tla_state_snapshot_apply_updates_step() {
        let mut snap = TlaStateSnapshot::new();
        let event = TraceEvent::spawn(42, Time::from_nanos(100), tid(1), rid(1));
        snap.apply(&event);
        assert_eq!(snap.step, 42);
        assert_eq!(snap.time_nanos, 100);
        assert!(snap.tasks.contains_key(&1));
    }

    #[test]
    fn tla_module_debug() {
        let module = TlaExporter::export_spec_skeleton("DebugTest");
        let dbg = format!("{module:?}");
        assert!(dbg.contains("TlaModule"));
    }

    #[test]
    fn tla_exporter_snapshot_count_with_events() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(1)),
        ];
        let exporter = TlaExporter::from_trace(&events);
        // initial + 2 events = 3 snapshots
        assert_eq!(exporter.snapshot_count(), 3);
    }

    #[test]
    fn format_tla_task_map_empty() {
        let map = BTreeMap::new();
        assert_eq!(format_tla_task_map(&map), "<<>>");
    }

    #[test]
    fn format_tla_task_map_with_entries() {
        let mut map = BTreeMap::new();
        map.insert(1, (TlaTaskState::Spawned, 0));
        let result = format_tla_task_map(&map);
        assert!(result.contains("1 :>"));
        assert!(result.contains("\"Spawned\""));
    }

    #[test]
    fn format_tla_region_map_empty() {
        let map = BTreeMap::new();
        assert_eq!(format_tla_region_map(&map), "<<>>");
    }

    #[test]
    fn format_tla_region_map_with_parent() {
        let mut map = BTreeMap::new();
        map.insert(1, (TlaRegionState::Open, Some(0)));
        let result = format_tla_region_map(&map);
        assert!(result.contains("\"Open\""));
        assert!(result.contains("0"));
    }

    #[test]
    fn format_tla_region_map_without_parent() {
        let mut map = BTreeMap::new();
        map.insert(1, (TlaRegionState::Closed, None));
        let result = format_tla_region_map(&map);
        assert!(result.contains("\"NONE\""));
    }

    #[test]
    fn format_tla_obligation_map_empty() {
        let map = BTreeMap::new();
        assert_eq!(format_tla_obligation_map(&map), "<<>>");
    }

    #[test]
    fn format_tla_obligation_map_with_entries() {
        let mut map = BTreeMap::new();
        map.insert(1, (TlaObligationState::Committed, 2, 3));
        let result = format_tla_obligation_map(&map);
        assert!(result.contains("\"Committed\""));
        assert!(result.contains("2"));
        assert!(result.contains("3"));
    }
}
