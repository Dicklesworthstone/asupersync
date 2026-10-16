//! VASS/WSTS obligation marking analysis.
//!
//! Projects obligation registry behavior into a vector-addition system (VAS)
//! where each dimension tracks token counts per obligation kind within a region.
//! This enables fast trace checks and bounded coverability-style analyses.
//!
//! # Vector Addition System Model
//!
//! The obligation marking is a vector `M ∈ ℕ^(K × R)` where:
//! - `K` = set of obligation kinds (`SendPermit`, `Ack`, `Lease`, `IoOp`)
//! - `R` = set of region identifiers
//!
//! Each dimension `M[k, r]` counts the number of **pending** (Reserved, not yet
//! resolved) obligations of kind `k` in region `r`.
//!
//! # Transitions
//!
//! ```text
//! Reserve(k, r):  M[k, r] += 1
//! Commit(k, r):   M[k, r] -= 1   (requires M[k, r] > 0)
//! Abort(k, r):    M[k, r] -= 1   (requires M[k, r] > 0)
//! Leak(k, r):     M[k, r] -= 1   (error: obligation dropped without resolve)
//! ```
//!
//! # Safety Property
//!
//! A marking is **safe** iff for every closed region `r`:
//! ```text
//! ∀ k ∈ K: M[k, r] = 0
//! ```
//!
//! Any closed region with `M[k, r] > 0` represents a **leak**.
//!
//! # Usage
//!
//! ```
//! use asupersync::obligation::marking::{MarkingAnalyzer, MarkingEvent, MarkingEventKind};
//! use asupersync::record::ObligationKind;
//! use asupersync::types::{ObligationId, RegionId, TaskId, Time};
//!
//! let r0 = RegionId::new_for_test(0, 0);
//! let t0 = TaskId::new_for_test(0, 0);
//! let o0 = ObligationId::new_for_test(0, 0);
//!
//! let events = vec![
//!     MarkingEvent::new(Time::ZERO, MarkingEventKind::Reserve {
//!         obligation: o0, kind: ObligationKind::SendPermit, task: t0, region: r0,
//!     }),
//!     MarkingEvent::new(Time::from_nanos(10), MarkingEventKind::Commit {
//!         obligation: o0, region: r0, kind: ObligationKind::SendPermit,
//!     }),
//!     MarkingEvent::new(Time::from_nanos(20), MarkingEventKind::RegionClose { region: r0 }),
//! ];
//!
//! let mut analyzer = MarkingAnalyzer::new();
//! let result = analyzer.analyze(&events);
//! assert!(result.is_safe());
//! ```

use crate::record::ObligationKind;
use crate::trace::{TraceData, TraceEvent, TraceEventKind};
use crate::types::{ObligationId, RegionId, TaskId, Time};
use std::collections::{HashMap, HashSet};
use std::fmt;

// ============================================================================
// MarkingEvent
// ============================================================================

/// The kind of marking event.
#[derive(Debug, Clone)]
pub enum MarkingEventKind {
    /// An obligation was reserved.
    Reserve {
        /// Obligation identifier.
        obligation: ObligationId,
        /// Obligation kind.
        kind: ObligationKind,
        /// Holding task.
        task: TaskId,
        /// Owning region.
        region: RegionId,
    },
    /// An obligation was committed.
    Commit {
        /// Obligation identifier.
        obligation: ObligationId,
        /// Region.
        region: RegionId,
        /// Obligation kind (for marking update).
        kind: ObligationKind,
    },
    /// An obligation was aborted.
    Abort {
        /// Obligation identifier.
        obligation: ObligationId,
        /// Region.
        region: RegionId,
        /// Obligation kind (for marking update).
        kind: ObligationKind,
    },
    /// An obligation was leaked (error state).
    Leak {
        /// Obligation identifier.
        obligation: ObligationId,
        /// Region.
        region: RegionId,
        /// Obligation kind.
        kind: ObligationKind,
    },
    /// A region was closed.
    RegionClose {
        /// Region that closed.
        region: RegionId,
    },
    /// A task completed.
    TaskComplete {
        /// Task that completed.
        task: TaskId,
    },
}

/// A marking event with a timestamp.
#[derive(Debug, Clone)]
pub struct MarkingEvent {
    /// When the event occurred.
    pub time: Time,
    /// What happened.
    pub kind: MarkingEventKind,
}

impl MarkingEvent {
    /// Creates a new marking event.
    #[must_use]
    pub fn new(time: Time, kind: MarkingEventKind) -> Self {
        Self { time, kind }
    }
}

// ============================================================================
// Projection from TraceEvent
// ============================================================================

/// Extract obligation marking events from a trace event stream.
///
/// Filters and projects the full trace into only the events relevant
/// for VASS marking analysis.
///
/// This legacy event representation cannot express ownership handoffs.
/// Use [`MarkingAnalyzer::analyze_trace`] for complete runtime traces, or
/// [`try_project_trace`] to refuse rather than lose a reserved handoff.
#[must_use]
pub fn project_trace(events: &[TraceEvent]) -> Vec<MarkingEvent> {
    let mut projected = Vec::new();

    for event in events {
        match (&event.kind, &event.data) {
            (
                TraceEventKind::ObligationReserve,
                TraceData::Obligation {
                    obligation,
                    task,
                    region,
                    kind,
                    ..
                },
            ) => {
                projected.push(MarkingEvent::new(
                    event.time,
                    MarkingEventKind::Reserve {
                        obligation: *obligation,
                        kind: *kind,
                        task: *task,
                        region: *region,
                    },
                ));
            }

            (
                TraceEventKind::ObligationCommit,
                TraceData::Obligation {
                    obligation,
                    region,
                    kind,
                    ..
                },
            ) => {
                projected.push(MarkingEvent::new(
                    event.time,
                    MarkingEventKind::Commit {
                        obligation: *obligation,
                        region: *region,
                        kind: *kind,
                    },
                ));
            }

            (
                TraceEventKind::ObligationAbort,
                TraceData::Obligation {
                    obligation,
                    region,
                    kind,
                    ..
                },
            ) => {
                projected.push(MarkingEvent::new(
                    event.time,
                    MarkingEventKind::Abort {
                        obligation: *obligation,
                        region: *region,
                        kind: *kind,
                    },
                ));
            }

            (
                TraceEventKind::ObligationLeak,
                TraceData::Obligation {
                    obligation,
                    region,
                    kind,
                    ..
                },
            ) => {
                projected.push(MarkingEvent::new(
                    event.time,
                    MarkingEventKind::Leak {
                        obligation: *obligation,
                        region: *region,
                        kind: *kind,
                    },
                ));
            }

            (TraceEventKind::RegionCloseBegin, TraceData::Region { region, .. }) => {
                projected.push(MarkingEvent::new(
                    event.time,
                    MarkingEventKind::RegionClose { region: *region },
                ));
            }

            (TraceEventKind::Complete, TraceData::Task { task, .. }) => {
                projected.push(MarkingEvent::new(
                    event.time,
                    MarkingEventKind::TaskComplete { task: *task },
                ));
            }

            _ => {}
        }
    }

    projected
}

/// Project only traces representable by the legacy marking event enum.
///
/// # Errors
/// Refuses any reserved handoff message, including malformed messages. A
/// valid handoff must be interpreted directly by [`MarkingAnalyzer::analyze_trace`].
pub fn try_project_trace(events: &[TraceEvent]) -> Result<Vec<MarkingEvent>, InvalidTransition> {
    for event in events {
        match crate::trace::event::decode_obligation_handoff(event) {
            Ok(None) => {}
            Ok(Some(_)) => {
                return Err(InvalidTransition {
                    time: event.time,
                    description: "ownership handoff requires transfer-aware trace analysis"
                        .to_owned(),
                });
            }
            Err(description) => {
                return Err(InvalidTransition {
                    time: event.time,
                    description,
                });
            }
        }
    }
    Ok(project_trace(events))
}

#[derive(Debug)]
struct TraceObligationBinding {
    kind: ObligationKind,
    holder: TaskId,
    region: RegionId,
    ticket: Option<u64>,
    pending: bool,
}

#[derive(Default)]
struct TraceOwnership {
    bindings: HashMap<ObligationId, TraceObligationBinding>,
    tasks: HashMap<TaskId, RegionId>,
    completed: HashSet<TaskId>,
    closed: HashSet<RegionId>,
}

impl TraceOwnership {
    fn observe(&mut self, event: &TraceEvent) -> Result<(), String> {
        match (&event.kind, &event.data) {
            (TraceEventKind::Spawn, TraceData::Task { task, region }) => {
                self.tasks.entry(*task).or_insert(*region);
            }
            (TraceEventKind::Complete, TraceData::Task { task, .. }) => {
                self.completed.insert(*task);
            }
            (TraceEventKind::RegionCloseComplete, TraceData::Region { region, .. }) => {
                self.closed.insert(*region);
            }
            (
                TraceEventKind::ObligationReserve,
                TraceData::Obligation {
                    obligation,
                    task,
                    region,
                    kind,
                    ..
                },
            ) => {
                if let Some(binding) = self.bindings.get(obligation) {
                    return Err(format!(
                        "obligation cannot be reserved again (pending={})",
                        binding.pending
                    ));
                }
                self.bindings.insert(
                    *obligation,
                    TraceObligationBinding {
                        kind: *kind,
                        holder: *task,
                        region: *region,
                        ticket: None,
                        pending: true,
                    },
                );
            }
            (
                TraceEventKind::ObligationCommit
                | TraceEventKind::ObligationAbort
                | TraceEventKind::ObligationLeak,
                TraceData::Obligation {
                    obligation,
                    task,
                    region,
                    kind,
                    ..
                },
            ) => {
                let binding = self
                    .bindings
                    .get_mut(obligation)
                    .ok_or_else(|| "terminal precedes its actual reservation".to_owned())?;
                if !binding.pending
                    || binding.holder != *task
                    || binding.region != *region
                    || binding.kind != *kind
                {
                    return Err(
                        "transferred obligation terminal does not match its pending owner/kind"
                            .to_owned(),
                    );
                }
                binding.pending = false;
            }
            _ => {}
        }
        Ok(())
    }

    fn handoff(
        &mut self,
        handoff: &crate::trace::event::ObligationHandoff,
        apply: impl FnOnce(ObligationKind) -> Result<(), String>,
    ) -> Result<(), String> {
        let binding = self
            .bindings
            .get_mut(&handoff.id)
            .ok_or_else(|| "handoff precedes its reservation".to_owned())?;
        if !binding.pending
            || binding.holder != handoff.source_holder
            || binding.region != handoff.source_region
            || binding
                .ticket
                .is_some_and(|ticket| ticket != handoff.source_ticket)
        {
            return Err(
                "handoff does not match a unique pending source and ticket lineage".to_owned(),
            );
        }
        if self.tasks.get(&handoff.source_holder) != Some(&handoff.source_region)
            || self.tasks.get(&handoff.destination_holder) != Some(&handoff.destination_region)
            || self.completed.contains(&handoff.source_holder)
            || self.completed.contains(&handoff.destination_holder)
            || self.closed.contains(&handoff.source_region)
            || self.closed.contains(&handoff.destination_region)
        {
            return Err(
                "handoff requires live source/destination generations and owning regions"
                    .to_owned(),
            );
        }
        apply(binding.kind)?;
        binding.holder = handoff.destination_holder;
        binding.region = handoff.destination_region;
        binding.ticket = Some(handoff.destination_ticket);
        Ok(())
    }
}

// ============================================================================
// Obligation kind index (avoids requiring Hash/Ord on ObligationKind)
// ============================================================================

/// Map `ObligationKind` to a compact index for use as a key component.
const fn kind_index(kind: ObligationKind) -> u8 {
    match kind {
        ObligationKind::SendPermit => 0,
        ObligationKind::Ack => 1,
        ObligationKind::Lease => 2,
        ObligationKind::IoOp => 3,
        ObligationKind::SemaphorePermit => 4,
        ObligationKind::Transaction => 5,
    }
}

/// All obligation kinds in index order. MUST be exhaustive — every variant
/// returned by `kind_index()` is used to index into this array via
/// `ALL_KINDS[ki as usize]` in `non_zero()` (and any future readers of the
/// counts map). Adding a new variant to ObligationKind requires extending
/// both `kind_index` and this array. Bug history: br-asupersync-m06vgf
/// missed SemaphorePermit (kind_index=4) here, causing
/// index-out-of-bounds panic the moment any Semaphore-using region was
/// observed by the marking machinery.
const ALL_KINDS: [ObligationKind; 6] = [
    ObligationKind::SendPermit,
    ObligationKind::Ack,
    ObligationKind::Lease,
    ObligationKind::IoOp,
    ObligationKind::SemaphorePermit,
    ObligationKind::Transaction,
];

const OBLIGATION_KIND_COUNT: usize = ALL_KINDS.len();

// ============================================================================
// MarkingDimension
// ============================================================================

/// Composite key for a marking dimension: (kind, region).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkingDimension {
    /// The obligation kind.
    pub kind: ObligationKind,
    /// The region.
    pub region: RegionId,
}

impl fmt::Display for MarkingDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {:?})", self.kind, self.region)
    }
}

/// Internal key for HashMap: (kind_index, RegionId).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DimKey(u8, RegionId);

// ============================================================================
// ObligationMarking (the vector state)
// ============================================================================

/// The obligation marking vector M ∈ ℕ^(K × R).
///
/// Each entry counts the number of pending (unresolved) obligations
/// of a given kind in a given region.
#[derive(Debug, Clone, Default)]
pub struct ObligationMarking {
    /// The marking vector: (kind_index, region) → count.
    counts: HashMap<DimKey, u32>,
}

impl ObligationMarking {
    /// Creates an empty marking (all zeros).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Increment the count for a dimension (Reserve transition).
    pub fn increment(&mut self, kind: ObligationKind, region: RegionId) {
        let key = DimKey(kind_index(kind), region);
        let count = self.counts.entry(key).or_insert(0);
        *count = count.saturating_add(1);
    }

    /// Decrement the count for a dimension (Commit/Abort/Leak transition).
    ///
    /// Returns `false` if the count was already zero (invalid transition).
    pub fn decrement(&mut self, kind: ObligationKind, region: RegionId) -> bool {
        let key = DimKey(kind_index(kind), region);
        match self.counts.get_mut(&key) {
            Some(count) if *count > 0 => {
                *count -= 1;
                true
            }
            _ => false,
        }
    }

    /// Returns the count for a specific dimension.
    #[must_use]
    pub fn get(&self, kind: ObligationKind, region: RegionId) -> u32 {
        let key = DimKey(kind_index(kind), region);
        self.counts.get(&key).copied().unwrap_or(0)
    }

    /// Returns the total pending obligations across all dimensions.
    #[must_use]
    pub fn total_pending(&self) -> u32 {
        self.counts
            .values()
            .fold(0u32, |acc, &v| acc.saturating_add(v))
    }

    /// Returns the total pending obligations for a specific region.
    #[must_use]
    pub fn region_pending(&self, region: RegionId) -> u32 {
        self.counts
            .iter()
            .filter(|(DimKey(_, r), _)| *r == region)
            .map(|(_, count)| *count)
            .fold(0u32, u32::saturating_add)
    }

    /// Returns true if the marking is zero (no pending obligations).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.counts.values().all(|&c| c == 0)
    }

    /// Returns all non-zero dimensions (sorted for deterministic output).
    #[must_use]
    pub fn non_zero(&self) -> Vec<(MarkingDimension, u32)> {
        let mut result: Vec<_> = self
            .counts
            .iter()
            .filter(|(_, c)| **c > 0)
            .map(|(DimKey(ki, region), count)| {
                (
                    MarkingDimension {
                        kind: ALL_KINDS[*ki as usize],
                        region: *region,
                    },
                    *count,
                )
            })
            .collect();
        result.sort_by_key(|(dim, _)| (kind_index(dim.kind), dim.region));
        result
    }

    /// Take a snapshot of the current marking.
    #[must_use]
    pub fn snapshot(&self) -> Self {
        self.clone()
    }
}

impl fmt::Display for ObligationMarking {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let non_zero = self.non_zero();
        if non_zero.is_empty() {
            return f.write_str("M = [0]");
        }
        write!(f, "M = [")?;
        for (i, (dim, count)) in non_zero.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{dim}={count}")?;
        }
        write!(f, "]")
    }
}

// ============================================================================
// MarkingTimeline
// ============================================================================

/// A snapshot of the marking at a point in time.
#[derive(Debug, Clone)]
pub struct MarkingSnapshot {
    /// Timestamp.
    pub time: Time,
    /// The marking at this time.
    pub marking: ObligationMarking,
    /// Description of what caused this snapshot.
    pub cause: String,
}

/// Timeline of marking evolution.
#[derive(Debug, Clone, Default)]
pub struct MarkingTimeline {
    /// Snapshots in chronological order.
    pub snapshots: Vec<MarkingSnapshot>,
}

impl MarkingTimeline {
    /// Returns the final marking.
    #[must_use]
    pub fn final_marking(&self) -> Option<&ObligationMarking> {
        self.snapshots.last().map(|s| &s.marking)
    }

    /// Returns the maximum pending count observed.
    #[must_use]
    pub fn max_pending(&self) -> u32 {
        self.snapshots
            .iter()
            .map(|s| s.marking.total_pending())
            .max()
            .unwrap_or(0)
    }
}

impl fmt::Display for MarkingTimeline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Marking Timeline ({} snapshots):", self.snapshots.len())?;
        for snap in &self.snapshots {
            writeln!(f, "  t={}: {} ({})", snap.time, snap.marking, snap.cause)?;
        }
        Ok(())
    }
}

// ============================================================================
// AnalysisResult
// ============================================================================

/// A detected leak violation.
#[derive(Debug, Clone)]
pub struct LeakViolation {
    /// The region that was closed with pending obligations.
    pub region: RegionId,
    /// The obligation kind that leaked.
    pub kind: ObligationKind,
    /// The count of leaked obligations.
    pub count: u32,
    /// When the region was closed.
    pub close_time: Time,
}

impl LeakViolation {
    /// Stable ASUP error code for the specific leak class, if one exists.
    #[must_use]
    pub const fn asup_code(&self) -> Option<&'static str> {
        match self.kind {
            ObligationKind::SendPermit => Some("ASUP-E202"),
            _ => None,
        }
    }
}

impl fmt::Display for LeakViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.asup_code() {
            write!(f, "[{code}] ")?;
        }
        write!(
            f,
            "leak: {} {} obligation(s) in {:?} at {}",
            self.count, self.kind, self.region, self.close_time,
        )
    }
}

/// An invalid transition (e.g., decrement below zero).
#[derive(Debug, Clone)]
pub struct InvalidTransition {
    /// The time of the invalid transition.
    pub time: Time,
    /// Description.
    pub description: String,
}

impl fmt::Display for InvalidTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid at {}: {}", self.time, self.description)
    }
}

/// Result of the marking analysis.
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    /// The marking timeline.
    pub timeline: MarkingTimeline,
    /// Detected leak violations.
    pub leaks: Vec<LeakViolation>,
    /// Invalid transitions encountered.
    pub invalid_transitions: Vec<InvalidTransition>,
    /// Regions that were closed during the trace.
    pub closed_regions: HashSet<RegionId>,
    /// Total events processed.
    pub events_processed: usize,
    /// Summary statistics.
    pub stats: AnalysisStats,
}

/// Summary statistics for the analysis.
#[derive(Debug, Clone, Default)]
pub struct AnalysisStats {
    /// Total obligations reserved.
    pub total_reserved: u32,
    /// Total obligations committed.
    pub total_committed: u32,
    /// Total obligations aborted.
    pub total_aborted: u32,
    /// Total obligations leaked.
    pub total_leaked: u32,
    /// Maximum concurrent pending obligations.
    pub max_pending: u32,
    /// Number of distinct regions.
    pub distinct_regions: usize,
    /// Number of distinct obligation kinds used.
    pub distinct_kinds: usize,
}

impl AnalysisResult {
    /// Returns true if no leaks or invalid transitions were found.
    #[must_use]
    pub fn is_safe(&self) -> bool {
        self.leaks.is_empty() && self.invalid_transitions.is_empty()
    }

    /// Returns only the leak violations.
    #[must_use]
    pub fn leak_count(&self) -> usize {
        self.leaks.len()
    }
}

impl fmt::Display for AnalysisResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "VASS Marking Analysis Result")?;
        writeln!(f, "============================")?;
        writeln!(f, "Events processed: {}", self.events_processed)?;
        writeln!(f, "Safe: {}", self.is_safe())?;
        writeln!(f)?;
        writeln!(f, "Statistics:")?;
        writeln!(f, "  Reserved:  {}", self.stats.total_reserved)?;
        writeln!(f, "  Committed: {}", self.stats.total_committed)?;
        writeln!(f, "  Aborted:   {}", self.stats.total_aborted)?;
        writeln!(f, "  Leaked:    {}", self.stats.total_leaked)?;
        writeln!(f, "  Max pending: {}", self.stats.max_pending)?;
        writeln!(f, "  Regions:   {}", self.stats.distinct_regions)?;
        writeln!(f, "  Kinds:     {}", self.stats.distinct_kinds)?;

        if !self.leaks.is_empty() {
            writeln!(f)?;
            writeln!(f, "Leak violations ({}):", self.leaks.len())?;
            for leak in &self.leaks {
                writeln!(f, "  {leak}")?;
            }
        }

        if !self.invalid_transitions.is_empty() {
            writeln!(f)?;
            writeln!(
                f,
                "Invalid transitions ({}):",
                self.invalid_transitions.len()
            )?;
            for inv in &self.invalid_transitions {
                writeln!(f, "  {inv}")?;
            }
        }

        Ok(())
    }
}

// ============================================================================
// MarkingAnalyzer
// ============================================================================

/// VASS obligation marking analyzer.
///
/// Consumes a sequence of [`MarkingEvent`]s and produces an [`AnalysisResult`]
/// with the marking timeline, detected leaks, and statistics.
#[derive(Debug, Default)]
pub struct MarkingAnalyzer {
    /// Current marking state.
    marking: ObligationMarking,
    /// Marking timeline.
    timeline: MarkingTimeline,
    /// Detected leaks.
    leaks: Vec<LeakViolation>,
    /// Invalid transitions.
    invalid_transitions: Vec<InvalidTransition>,
    /// Closed regions.
    closed_regions: HashSet<RegionId>,
    /// Statistics.
    stats: AnalysisStats,
    /// All regions seen.
    all_regions: HashSet<RegionId>,
    /// Kinds seen (indexed by kind_index).
    kinds_seen: [bool; OBLIGATION_KIND_COUNT],
}

impl MarkingAnalyzer {
    /// Creates a new analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Analyze a sequence of marking events.
    ///
    /// The analyzer is reset before each invocation.
    #[must_use]
    pub fn analyze(&mut self, events: &[MarkingEvent]) -> AnalysisResult {
        self.reset();

        // Record initial state (before any events, time is zero).
        self.snapshot("initial", Time::ZERO);

        for event in events {
            self.process_event(event);
        }

        // Record final state using the last event's timestamp (or zero if empty).
        let final_time = events.last().map_or(Time::ZERO, |e| e.time);
        self.finish_analysis(events.len(), final_time)
    }

    fn finish_analysis(&mut self, events_processed: usize, final_time: Time) -> AnalysisResult {
        self.snapshot("final", final_time);

        AnalysisResult {
            timeline: self.timeline.clone(),
            leaks: self.leaks.clone(),
            invalid_transitions: self.invalid_transitions.clone(),
            closed_regions: self.closed_regions.clone(),
            events_processed,
            stats: AnalysisStats {
                total_reserved: self.stats.total_reserved,
                total_committed: self.stats.total_committed,
                total_aborted: self.stats.total_aborted,
                total_leaked: self.stats.total_leaked,
                max_pending: self.timeline.max_pending(),
                distinct_regions: self.all_regions.len(),
                distinct_kinds: self.kinds_seen.iter().filter(|&&b| b).count(),
            },
        }
    }

    /// Analyze a trace event stream directly (convenience method).
    ///
    /// Ordinary traces retain the legacy projection. Reserved handoffs move
    /// one existing obligation between region dimensions without fabricating
    /// a reservation or resolution. Malformed handoffs and inconsistent
    /// transferred ownership produce [`InvalidTransition`] entries.
    ///
    /// For transfer-bearing runtime traces, closure is observed at
    /// `RegionCloseComplete`: close-begin can precede projection of an already
    /// admitted handoff, whose application barrier still prevents completion.
    #[must_use]
    pub fn analyze_trace(&mut self, trace: &[TraceEvent]) -> AnalysisResult {
        if let Ok(events) = try_project_trace(trace) {
            return self.analyze(&events);
        }
        self.reset();
        self.snapshot("initial", Time::ZERO);
        let mut ownership = TraceOwnership::default();
        let mut processed = 0;
        let mut final_time = Time::ZERO;
        for event in trace {
            let handoff = crate::trace::event::decode_obligation_handoff(event);
            match handoff {
                Ok(Some(handoff)) => {
                    processed += 1;
                    final_time = event.time;
                    let result = ownership.handoff(&handoff, |kind| {
                        if self.marking.get(kind, handoff.source_region) == 0 {
                            return Err("handoff source marking is already zero".to_owned());
                        }
                        if handoff.source_region != handoff.destination_region {
                            if self.marking.get(kind, handoff.destination_region) == u32::MAX {
                                return Err("handoff destination marking would overflow".to_owned());
                            }
                            self.marking.decrement(kind, handoff.source_region);
                            self.marking.increment(kind, handoff.destination_region);
                        }
                        self.all_regions.insert(handoff.destination_region);
                        self.snapshot(
                            &format!(
                                "handoff({:?}, {:?}->{:?})",
                                handoff.id, handoff.source_region, handoff.destination_region
                            ),
                            event.time,
                        );
                        Ok(())
                    });
                    if let Err(description) = result {
                        self.invalid_transitions.push(InvalidTransition {
                            time: event.time,
                            description,
                        });
                    }
                    continue;
                }
                Err(description) => {
                    processed += 1;
                    final_time = event.time;
                    self.invalid_transitions.push(InvalidTransition {
                        time: event.time,
                        description,
                    });
                    continue;
                }
                Ok(None) => {}
            }
            if let Err(description) = ownership.observe(event) {
                processed += 1;
                final_time = event.time;
                self.invalid_transitions.push(InvalidTransition {
                    time: event.time,
                    description,
                });
                continue;
            }
            if event.kind == TraceEventKind::RegionCloseBegin {
                continue;
            }
            let projected =
                if let (TraceEventKind::RegionCloseComplete, TraceData::Region { region, .. }) =
                    (&event.kind, &event.data)
                {
                    vec![MarkingEvent::new(
                        event.time,
                        MarkingEventKind::RegionClose { region: *region },
                    )]
                } else {
                    project_trace(std::slice::from_ref(event))
                };
            for marking_event in projected {
                processed += 1;
                final_time = marking_event.time;
                self.process_event(&marking_event);
            }
        }
        self.finish_analysis(processed, final_time)
    }

    fn reset(&mut self) {
        self.marking = ObligationMarking::empty();
        self.timeline = MarkingTimeline::default();
        self.leaks.clear();
        self.invalid_transitions.clear();
        self.closed_regions.clear();
        self.stats = AnalysisStats::default();
        self.all_regions.clear();
        self.kinds_seen = [false; OBLIGATION_KIND_COUNT];
    }

    fn snapshot(&mut self, cause: &str, time: Time) {
        self.timeline.snapshots.push(MarkingSnapshot {
            time,
            marking: self.marking.snapshot(),
            cause: cause.to_string(),
        });
    }

    fn process_event(&mut self, event: &MarkingEvent) {
        match &event.kind {
            MarkingEventKind::Reserve { kind, region, .. } => {
                self.marking.increment(*kind, *region);
                self.stats.total_reserved = self.stats.total_reserved.saturating_add(1);
                self.all_regions.insert(*region);
                self.kinds_seen[kind_index(*kind) as usize] = true;
                self.timeline.snapshots.push(MarkingSnapshot {
                    time: event.time,
                    marking: self.marking.snapshot(),
                    cause: format!("reserve({kind}, {region:?})"),
                });
            }

            MarkingEventKind::Commit { kind, region, .. } => {
                if !self.marking.decrement(*kind, *region) {
                    self.invalid_transitions.push(InvalidTransition {
                        time: event.time,
                        description: format!(
                            "commit({kind}, {region:?}) but marking is already zero"
                        ),
                    });
                }
                self.stats.total_committed = self.stats.total_committed.saturating_add(1);
                self.timeline.snapshots.push(MarkingSnapshot {
                    time: event.time,
                    marking: self.marking.snapshot(),
                    cause: format!("commit({kind}, {region:?})"),
                });
            }

            MarkingEventKind::Abort { kind, region, .. } => {
                if !self.marking.decrement(*kind, *region) {
                    self.invalid_transitions.push(InvalidTransition {
                        time: event.time,
                        description: format!(
                            "abort({kind}, {region:?}) but marking is already zero"
                        ),
                    });
                }
                self.stats.total_aborted = self.stats.total_aborted.saturating_add(1);
                self.timeline.snapshots.push(MarkingSnapshot {
                    time: event.time,
                    marking: self.marking.snapshot(),
                    cause: format!("abort({kind}, {region:?})"),
                });
            }

            MarkingEventKind::Leak { kind, region, .. } => {
                // Leak still decrements (obligation is gone, just erroneously).
                if !self.marking.decrement(*kind, *region) {
                    self.invalid_transitions.push(InvalidTransition {
                        time: event.time,
                        description: format!(
                            "leak({kind}, {region:?}) but marking is already zero"
                        ),
                    });
                }
                self.stats.total_leaked = self.stats.total_leaked.saturating_add(1);
                self.timeline.snapshots.push(MarkingSnapshot {
                    time: event.time,
                    marking: self.marking.snapshot(),
                    cause: format!("LEAK({kind}, {region:?})"),
                });
            }

            MarkingEventKind::TaskComplete { .. } => {
                // Task completion does not change region/kind VASS counters.
            }

            MarkingEventKind::RegionClose { region } => {
                self.closed_regions.insert(*region);
                let pending = self.marking.region_pending(*region);
                if pending > 0 {
                    // Check each kind for this region.
                    for kind in ALL_KINDS {
                        let count = self.marking.get(kind, *region);
                        if count > 0 {
                            self.leaks.push(LeakViolation {
                                region: *region,
                                kind,
                                count,
                                close_time: event.time,
                            });
                        }
                    }
                }
                self.timeline.snapshots.push(MarkingSnapshot {
                    time: event.time,
                    marking: self.marking.snapshot(),
                    cause: format!("region_close({region:?})"),
                });
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "marking_inline_tests.rs"]
mod tests;
