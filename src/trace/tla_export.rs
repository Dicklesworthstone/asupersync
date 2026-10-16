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
use std::collections::{BTreeMap, BTreeSet};
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

/// A `(arena index, generation)` key that uniquely identifies a snapshot
/// entity across arena slot reuse.
///
/// Keying the TLA+ domains on this pair — rather than the bare
/// `ArenaIndex::index()` — keeps distinct generations distinct domain elements.
/// Otherwise a reused slot (task `5` gen `0` completes, then task `5` gen `1`
/// spawns) would alias two distinct entities onto one key, and invariants like
/// `QuiescenceOnClose` could pass *vacuously* because one entity silently
/// overwrote the other in the map.
pub type EntityKey = (u32, u32);

/// A snapshot of the runtime state for TLA+ export.
#[derive(Debug, Clone)]
pub struct TlaStateSnapshot {
    /// Task states: `(task index, gen) -> (state, (region index, gen))`.
    pub tasks: BTreeMap<EntityKey, (TlaTaskState, EntityKey)>,
    /// Region states: `(region index, gen) -> (state, parent (index, gen))`.
    pub regions: BTreeMap<EntityKey, (TlaRegionState, Option<EntityKey>)>,
    /// Obligation states: `(obl index, gen) -> (state, task key, region key)`.
    pub obligations: BTreeMap<EntityKey, (TlaObligationState, EntityKey, EntityKey)>,
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
                self.tasks.insert(
                    arena_key(task.0),
                    (TlaTaskState::Spawned, arena_key(region.0)),
                );
            }
            (TraceEventKind::Schedule, TraceData::Task { task, .. }) => {
                if let Some(entry) = self.tasks.get_mut(&arena_key(task.0)) {
                    entry.0 = TlaTaskState::Scheduled;
                }
            }
            (TraceEventKind::Poll, TraceData::Task { task, .. }) => {
                if let Some(entry) = self.tasks.get_mut(&arena_key(task.0)) {
                    entry.0 = TlaTaskState::Polling;
                }
            }
            (TraceEventKind::Yield, TraceData::Task { task, .. }) => {
                if let Some(entry) = self.tasks.get_mut(&arena_key(task.0)) {
                    entry.0 = TlaTaskState::Yielded;
                }
            }
            (TraceEventKind::Complete, TraceData::Task { task, .. }) => {
                if let Some(entry) = self.tasks.get_mut(&arena_key(task.0)) {
                    entry.0 = TlaTaskState::Completed;
                }
            }
            (TraceEventKind::CancelAck, TraceData::Cancel { task, .. }) => {
                if let Some(entry) = self.tasks.get_mut(&arena_key(task.0)) {
                    entry.0 = TlaTaskState::Cancelled;
                }
            }
            (TraceEventKind::RegionCreated, TraceData::Region { region, parent }) => {
                self.regions.insert(
                    arena_key(region.0),
                    (TlaRegionState::Open, parent.map(|p| arena_key(p.0))),
                );
            }
            (TraceEventKind::RegionCloseBegin, TraceData::Region { region, .. }) => {
                if let Some(entry) = self.regions.get_mut(&arena_key(region.0)) {
                    entry.0 = TlaRegionState::Closing;
                }
            }
            (TraceEventKind::RegionCloseComplete, TraceData::Region { region, .. }) => {
                if let Some(entry) = self.regions.get_mut(&arena_key(region.0)) {
                    entry.0 = TlaRegionState::Closed;
                }
            }
            (TraceEventKind::RegionCancelled, TraceData::RegionCancel { region, .. }) => {
                if let Some(entry) = self.regions.get_mut(&arena_key(region.0)) {
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
                    arena_key(obligation.0),
                    (
                        TlaObligationState::Reserved,
                        arena_key(task.0),
                        arena_key(region.0),
                    ),
                );
            }
            (TraceEventKind::ObligationCommit, TraceData::Obligation { obligation, .. }) => {
                if let Some(entry) = self.obligations.get_mut(&arena_key(obligation.0)) {
                    entry.0 = TlaObligationState::Committed;
                }
            }
            (TraceEventKind::ObligationAbort, TraceData::Obligation { obligation, .. }) => {
                if let Some(entry) = self.obligations.get_mut(&arena_key(obligation.0)) {
                    entry.0 = TlaObligationState::Aborted;
                }
            }
            (TraceEventKind::ObligationLeak, TraceData::Obligation { obligation, .. }) => {
                if let Some(entry) = self.obligations.get_mut(&arena_key(obligation.0)) {
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
    handoff_error: Option<TlaTraceError>,
}

/// A reserved ownership message cannot be interpreted as a valid handoff.
/// This checks trace interpretation, not TLA model validity or a TLC result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlaTraceError {
    /// Zero-based index of the first invalid ownership event.
    pub event_index: usize,
    /// The original event sequence number.
    pub event_seq: u64,
    /// The malformed or inconsistent ownership assertion.
    pub detail: String,
}

impl fmt::Display for TlaTraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unverifiable handoff at event[{}] seq={}: {}",
            self.event_index, self.event_seq, self.detail
        )
    }
}

impl std::error::Error for TlaTraceError {}

impl TlaExporter {
    /// Build state snapshots from a trace.
    ///
    /// Ordinary annotations and historical partial/negative traces retain
    /// their previous interpretation. The reserved `obligation_handoff_v*`
    /// message namespace must describe valid ownership transitions. Malformed
    /// handoffs are retained as a diagnostic accessible through
    /// [`Self::validation_error`]; [`Self::export_behavior`] then emits an
    /// explicitly unverifiable diagnostic with no runnable module or `Spec`.
    /// Use [`Self::try_from_trace`] to receive the refusal directly.
    #[must_use]
    pub fn from_trace(events: &[TraceEvent]) -> Self {
        let mut state = TlaStateSnapshot::new();
        let mut snapshots = vec![state.clone()]; // initial state
        let mut tickets = BTreeMap::new();
        let mut completed_tasks = BTreeSet::new();
        let mut closed_regions = BTreeSet::new();
        let mut reserved_ids = BTreeSet::new();
        let mut duplicate_reservations = BTreeSet::new();
        let mut first_task_regions = BTreeMap::new();
        let mut handoff_error = None;
        for (index, event) in events.iter().enumerate() {
            if handoff_error.is_none() {
                let result = super::event::decode_obligation_handoff(event).and_then(|handoff| {
                    if let Some(handoff) = handoff {
                        Self::apply_handoff(
                            &mut state,
                            &mut tickets,
                            &completed_tasks,
                            &closed_regions,
                            &duplicate_reservations,
                            &first_task_regions,
                            &handoff,
                        )
                    } else {
                        Self::validate_handoff_terminal(&state, &tickets, event)
                    }
                });
                if let Err(detail) = result {
                    handoff_error = Some(TlaTraceError {
                        event_index: index,
                        event_seq: event.seq,
                        detail,
                    });
                }
            }
            // Historical negative prefixes remain representable, but a later
            // reserved handoff cannot resurrect these exact generations.
            match (&event.kind, &event.data) {
                (TraceEventKind::Spawn, TraceData::Task { task, region }) => {
                    first_task_regions
                        .entry(arena_key(task.0))
                        .or_insert(arena_key(region.0));
                }
                (TraceEventKind::ObligationReserve, TraceData::Obligation { obligation, .. }) => {
                    let id = arena_key(obligation.0);
                    if !reserved_ids.insert(id) {
                        duplicate_reservations.insert(id);
                    }
                }
                (TraceEventKind::Complete, TraceData::Task { task, .. }) => {
                    completed_tasks.insert(arena_key(task.0));
                }
                (TraceEventKind::RegionCloseComplete, TraceData::Region { region, .. }) => {
                    closed_regions.insert(arena_key(region.0));
                }
                _ => {}
            }
            state.apply(event);
            snapshots.push(state.clone());
        }
        Self {
            snapshots,
            handoff_error,
        }
    }

    /// Build snapshots while explicitly refusing malformed/inconsistent
    /// reserved handoff records. Other negative traces remain exportable for
    /// model exploration; success is not a model-checking verdict.
    ///
    /// # Errors
    /// Returns the first invalid reserved handoff or inconsistent terminal
    /// ownership event after an interpreted handoff.
    pub fn try_from_trace(events: &[TraceEvent]) -> Result<Self, TlaTraceError> {
        let exporter = Self::from_trace(events);
        if let Some(error) = &exporter.handoff_error {
            return Err(error.clone());
        }
        Ok(exporter)
    }

    /// The first reserved handoff error, if any.
    #[must_use]
    pub fn validation_error(&self) -> Option<&TlaTraceError> {
        self.handoff_error.as_ref()
    }

    fn apply_handoff(
        state: &mut TlaStateSnapshot,
        tickets: &mut BTreeMap<EntityKey, u64>,
        completed_tasks: &BTreeSet<EntityKey>,
        closed_regions: &BTreeSet<EntityKey>,
        duplicate_reservations: &BTreeSet<EntityKey>,
        first_task_regions: &BTreeMap<EntityKey, EntityKey>,
        handoff: &super::event::ObligationHandoff,
    ) -> Result<(), String> {
        let id = arena_key(handoff.id.0);
        let source = arena_key(handoff.source_holder.0);
        let destination = arena_key(handoff.destination_holder.0);
        let source_region = arena_key(handoff.source_region.0);
        let destination_region = arena_key(handoff.destination_region.0);
        if duplicate_reservations.contains(&id)
            || state.obligations.get(&id)
                != Some(&(TlaObligationState::Reserved, source, source_region))
            || tickets
                .get(&id)
                .is_some_and(|ticket| *ticket != handoff.source_ticket)
        {
            return Err("handoff does not match its pending source and ticket lineage".to_owned());
        }
        if first_task_regions.get(&source) != Some(&source_region)
            || first_task_regions.get(&destination) != Some(&destination_region)
            || completed_tasks.contains(&source)
            || completed_tasks.contains(&destination)
            || closed_regions.contains(&source_region)
            || closed_regions.contains(&destination_region)
            || state.tasks.get(&source).is_none_or(|(status, region)| {
                *status == TlaTaskState::Completed || *region != source_region
            })
            || state
                .tasks
                .get(&destination)
                .is_none_or(|(status, region)| {
                    *status == TlaTaskState::Completed || *region != destination_region
                })
            || state
                .regions
                .get(&destination_region)
                .is_some_and(|(status, _)| *status == TlaRegionState::Closed)
        {
            return Err(
                "handoff source/destination generation or owning region is not live".to_owned(),
            );
        }
        // Close-begin or cancellation may precede projection of an admission
        // which already succeeded; completed destination ownership may not.
        state.obligations.insert(
            id,
            (
                TlaObligationState::Reserved,
                destination,
                destination_region,
            ),
        );
        tickets.insert(id, handoff.destination_ticket);
        Ok(())
    }

    fn validate_handoff_terminal(
        state: &TlaStateSnapshot,
        tickets: &BTreeMap<EntityKey, u64>,
        event: &TraceEvent,
    ) -> Result<(), String> {
        if matches!(
            event.kind,
            TraceEventKind::ObligationReserve
                | TraceEventKind::ObligationCommit
                | TraceEventKind::ObligationAbort
                | TraceEventKind::ObligationLeak
        ) {
            if let TraceData::Obligation {
                obligation,
                task,
                region,
                ..
            } = &event.data
            {
                let id = arena_key(obligation.0);
                if tickets.contains_key(&id) && event.kind == TraceEventKind::ObligationReserve {
                    return Err("transferred obligation cannot be reserved again".to_owned());
                }
                if tickets.contains_key(&id)
                    && state.obligations.get(&id)
                        != Some(&(
                            TlaObligationState::Reserved,
                            arena_key(task.0),
                            arena_key(region.0),
                        ))
                {
                    return Err("transferred obligation terminal does not match its pending destination owner".to_owned());
                }
            }
        }
        Ok(())
    }

    /// Export a TLA+ behavior (concrete trace as a sequence of states).
    #[must_use]
    pub fn export_behavior(&self, name: &str) -> TlaModule {
        // Sanitize so a name with whitespace/newlines/`-` cannot produce an
        // invalid or injected `---- MODULE ... ----` header.
        let name = sanitize_module_name(name);
        if let Some(error) = &self.handoff_error {
            // A diagnostic only: deliberately no MODULE/Init/Next/Spec and
            // no ASSUME FALSE that could turn refusal into a vacuous proof.
            // Debug quoting keeps untrusted field errors on one comment line.
            return TlaModule {
                name,
                source: format!("\\* UNVERIFIABLE_TRANSFER_TRACE {:?}\n", error.to_string()),
            };
        }
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
                let prefix = "    \\/ ";
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

        TlaModule { name, source: src }
    }

    /// Export a TLA+ spec skeleton (parametric model).
    #[must_use]
    pub fn export_spec_skeleton(name: &str) -> TlaModule {
        // Sanitize so a name with whitespace/newlines/`-` cannot produce an
        // invalid or injected `---- MODULE ... ----` header.
        let name = sanitize_module_name(name);
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

        TlaModule { name, source: src }
    }

    /// Number of state snapshots (trace length + 1 for initial state).
    #[must_use]
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }
}

// === Formatting helpers ===

/// Build an [`EntityKey`] (index + generation) from an id's arena index.
fn arena_key(arena: crate::util::ArenaIndex) -> EntityKey {
    (arena.index(), arena.generation())
}

/// Render an [`EntityKey`] as a TLA+ string literal, e.g. `"5.0"`.
///
/// Emitting the composite key as a quoted string keeps distinct generations
/// distinct domain elements and matches the `"NONE"` sentinel already used for
/// absent parents, so region references and region domains compare on the same
/// (string) type.
fn tla_entity_key(key: EntityKey) -> String {
    format!("\"{}.{}\"", key.0, key.1)
}

/// Sanitize a caller-supplied name into a valid TLA+ module identifier.
///
/// TLA+ module names are identifiers (letters, digits, underscores). An
/// unsanitized name containing whitespace, a newline, or `-`/`=` would produce
/// an invalid `---- MODULE ... ----` header or let a crafted name inject spec
/// syntax. Every character outside `[A-Za-z0-9_]` is replaced with `_`; a
/// leading digit is prefixed with `_`; an empty/all-invalid name becomes
/// `Module`.
fn sanitize_module_name(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() {
        return "Module".to_string();
    }
    if out.as_bytes()[0].is_ascii_digit() {
        out.insert(0, '_');
    }
    out
}

fn format_tla_task_map(tasks: &BTreeMap<EntityKey, (TlaTaskState, EntityKey)>) -> String {
    if tasks.is_empty() {
        return "<<>>".to_string();
    }
    let entries: Vec<String> = tasks
        .iter()
        .map(|(k, (state, region))| {
            format!(
                "{} :> <<{state}, {}>>",
                tla_entity_key(*k),
                tla_entity_key(*region)
            )
        })
        .collect();
    format!("({})", entries.join(" @@ "))
}

fn format_tla_region_map(
    regions: &BTreeMap<EntityKey, (TlaRegionState, Option<EntityKey>)>,
) -> String {
    if regions.is_empty() {
        return "<<>>".to_string();
    }
    let entries: Vec<String> = regions
        .iter()
        .map(|(k, (state, parent))| {
            let p = parent.map_or_else(|| "\"NONE\"".to_string(), tla_entity_key);
            format!("{} :> <<{state}, {p}>>", tla_entity_key(*k))
        })
        .collect();
    format!("({})", entries.join(" @@ "))
}

fn format_tla_obligation_map(
    obligations: &BTreeMap<EntityKey, (TlaObligationState, EntityKey, EntityKey)>,
) -> String {
    if obligations.is_empty() {
        return "<<>>".to_string();
    }
    let entries: Vec<String> = obligations
        .iter()
        .map(|(k, (state, task, region))| {
            format!(
                "{} :> <<{state}, {}, {}>>",
                tla_entity_key(*k),
                tla_entity_key(*task),
                tla_entity_key(*region)
            )
        })
        .collect();
    format!("({})", entries.join(" @@ "))
}

#[cfg(test)]
#[path = "tla_export_inline_tests.rs"]
mod tests;
