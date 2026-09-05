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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::util::ArenaIndex;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn r(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    fn t(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn o(n: u32) -> ObligationId {
        ObligationId::from_arena(ArenaIndex::new(n, 0))
    }

    fn reserve(
        time_ns: u64,
        obligation: ObligationId,
        kind: ObligationKind,
        task: TaskId,
        region: RegionId,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Reserve {
                obligation,
                kind,
                task,
                region,
            },
        )
    }

    fn commit(
        time_ns: u64,
        obligation: ObligationId,
        region: RegionId,
        kind: ObligationKind,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Commit {
                obligation,
                region,
                kind,
            },
        )
    }

    fn abort(
        time_ns: u64,
        obligation: ObligationId,
        region: RegionId,
        kind: ObligationKind,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Abort {
                obligation,
                region,
                kind,
            },
        )
    }

    fn leak(
        time_ns: u64,
        obligation: ObligationId,
        region: RegionId,
        kind: ObligationKind,
    ) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::Leak {
                obligation,
                region,
                kind,
            },
        )
    }

    fn close(time_ns: u64, region: RegionId) -> MarkingEvent {
        MarkingEvent::new(
            Time::from_nanos(time_ns),
            MarkingEventKind::RegionClose { region },
        )
    }

    fn transfer_trace(
        cross_region: bool,
        kind: ObligationKind,
    ) -> (Vec<TraceEvent>, crate::trace::event::ObligationHandoff) {
        let destination_region = if cross_region { r(1) } else { r(0) };
        let handoff = crate::trace::event::ObligationHandoff {
            id: o(0),
            source_ticket: 4,
            destination_ticket: 7,
            source_holder: t(0),
            destination_holder: TaskId::new_for_test(0, 1),
            source_region: r(0),
            destination_region,
        };
        (
            vec![
                TraceEvent::region_created(0, Time::ZERO, r(0), None),
                TraceEvent::spawn(1, Time::ZERO, handoff.source_holder, r(0)),
                TraceEvent::spawn(
                    2,
                    Time::ZERO,
                    handoff.destination_holder,
                    destination_region,
                ),
                TraceEvent::obligation_reserve(
                    3,
                    Time::ZERO,
                    o(0),
                    handoff.source_holder,
                    r(0),
                    kind,
                ),
            ],
            handoff,
        )
    }

    fn trace_close(seq: u64, region: RegionId, kind: TraceEventKind) -> TraceEvent {
        TraceEvent::new(
            seq,
            Time::from_nanos(seq),
            kind,
            TraceData::Region {
                region,
                parent: None,
            },
        )
    }

    #[test]
    fn transfer_trace_moves_one_marking_without_minting_or_settling() {
        for cross_region in [false, true] {
            for kind in [ObligationKind::Lease, ObligationKind::SemaphorePermit] {
                for abort in [false, true] {
                    let (mut trace, handoff) = transfer_trace(cross_region, kind);
                    trace.push(TraceEvent::obligation_handoff(
                        4,
                        Time::from_nanos(4),
                        &handoff,
                    ));
                    if cross_region {
                        trace.push(TraceEvent::complete(
                            5,
                            Time::from_nanos(5),
                            handoff.source_holder,
                            handoff.source_region,
                        ));
                        trace.push(trace_close(
                            6,
                            handoff.source_region,
                            TraceEventKind::RegionCloseComplete,
                        ));
                    }
                    let mut analyzer = MarkingAnalyzer::new();
                    let pending = analyzer.analyze_trace(&trace);
                    assert!(pending.is_safe(), "pending handoff: {pending}");
                    let marking = pending.timeline.final_marking().unwrap();
                    assert_eq!(marking.total_pending(), 1);
                    assert_eq!(marking.region_pending(handoff.destination_region), 1);
                    if cross_region {
                        assert_eq!(marking.region_pending(handoff.source_region), 0);
                    }
                    assert_eq!(pending.stats.total_reserved, 1);
                    assert_eq!(pending.stats.total_committed, 0);
                    assert_eq!(pending.stats.total_aborted, 0);
                    assert_eq!(pending.stats.max_pending, 1);
                    let terminal = if abort {
                        TraceEvent::obligation_abort(
                            7,
                            Time::from_nanos(7),
                            handoff.id,
                            handoff.destination_holder,
                            handoff.destination_region,
                            kind,
                            7,
                            crate::record::ObligationAbortReason::Explicit,
                        )
                    } else {
                        TraceEvent::obligation_commit(
                            7,
                            Time::from_nanos(7),
                            handoff.id,
                            handoff.destination_holder,
                            handoff.destination_region,
                            kind,
                            7,
                        )
                    };
                    trace.push(terminal);
                    trace.push(trace_close(
                        8,
                        handoff.destination_region,
                        TraceEventKind::RegionCloseComplete,
                    ));
                    let result = analyzer.analyze_trace(&trace);
                    assert!(
                        result.is_safe(),
                        "cross_region={cross_region} abort={abort}: {result}"
                    );
                    assert!(result.timeline.final_marking().unwrap().is_zero());
                    assert_eq!(result.stats.total_reserved, 1);
                    assert_eq!(result.stats.total_committed, u32::from(!abort));
                    assert_eq!(result.stats.total_aborted, u32::from(abort));
                    assert_eq!(result.stats.total_leaked, 0);
                    assert_eq!(result.stats.max_pending, 1);
                    assert!(
                        try_project_trace(&trace).is_err(),
                        "legacy projection must refuse loss of ownership"
                    );
                    eprintln!(
                        "marking transfer cross_region={cross_region} kind={kind:?} abort={abort}: {result}"
                    );
                }
            }
        }
    }

    #[test]
    fn transfer_trace_refuses_stale_or_reset_ownership_and_keeps_destination_leaks() {
        for scenario in [
            "malformed",
            "missing",
            "generation",
            "ticket",
            "source",
            "old_terminal",
            "reset",
            "double_terminal",
            "completed",
            "closed",
            "source_closed",
        ] {
            let (mut trace, mut handoff) = transfer_trace(true, ObligationKind::Lease);
            match scenario {
                "missing" => handoff.id = o(2),
                "generation" => handoff.destination_holder = TaskId::new_for_test(0, 2),
                "ticket" => handoff.destination_ticket = handoff.source_ticket,
                "source" => handoff.source_region = r(2),
                "source_closed" => trace.insert(
                    1,
                    trace_close(
                        0,
                        handoff.source_region,
                        TraceEventKind::RegionCloseComplete,
                    ),
                ),
                "completed" => trace.push(TraceEvent::complete(
                    4,
                    Time::ZERO,
                    handoff.destination_holder,
                    handoff.destination_region,
                )),
                "closed" => trace.push(trace_close(
                    4,
                    handoff.destination_region,
                    TraceEventKind::RegionCloseComplete,
                )),
                _ => {}
            }
            trace.push(if scenario == "malformed" {
                TraceEvent::user_trace(5, Time::ZERO, "obligation_handoff_v1 {}")
            } else {
                TraceEvent::obligation_handoff(5, Time::ZERO, &handoff)
            });
            if scenario == "old_terminal" {
                trace.push(TraceEvent::obligation_commit(
                    6,
                    Time::ZERO,
                    handoff.id,
                    handoff.source_holder,
                    handoff.source_region,
                    ObligationKind::Lease,
                    1,
                ));
            }
            if scenario == "reset" {
                trace.push(TraceEvent::obligation_reserve(
                    6,
                    Time::ZERO,
                    handoff.id,
                    handoff.source_holder,
                    handoff.source_region,
                    ObligationKind::Lease,
                ));
            }
            if scenario == "double_terminal" {
                for seq in [6, 7] {
                    trace.push(TraceEvent::obligation_commit(
                        seq,
                        Time::ZERO,
                        handoff.id,
                        handoff.destination_holder,
                        handoff.destination_region,
                        ObligationKind::Lease,
                        1,
                    ));
                }
            }
            let result = MarkingAnalyzer::new().analyze_trace(&trace);
            assert!(!result.is_safe(), "accepted {scenario}");
            assert_eq!(result.invalid_transitions.len(), 1, "{scenario}: {result}");
            assert_eq!(result.stats.total_reserved, 1, "{scenario}");
        }
        let (mut trace, handoff) = transfer_trace(true, ObligationKind::Lease);
        trace.push(TraceEvent::obligation_handoff(4, Time::ZERO, &handoff));
        trace.push(trace_close(
            5,
            handoff.destination_region,
            TraceEventKind::RegionCloseComplete,
        ));
        let result = MarkingAnalyzer::new().analyze_trace(&trace);
        assert!(!result.is_safe());
        assert_eq!(result.leaks.len(), 1);
        assert_eq!(result.leaks[0].region, handoff.destination_region);
        assert_eq!(result.leaks[0].count, 1);
    }

    #[test]
    fn transfer_trace_queued_close_and_return_chain_preserve_legacy_analysis() {
        let (mut trace, handoff) = transfer_trace(true, ObligationKind::Lease);
        let mut analyzer = MarkingAnalyzer::new();
        let old = analyzer.analyze(&project_trace(&trace));
        let direct = analyzer.analyze_trace(&trace);
        assert_eq!(old.to_string(), direct.to_string());
        assert_eq!(old.timeline.to_string(), direct.timeline.to_string());
        assert!(try_project_trace(&trace).is_ok());
        trace.push(trace_close(
            4,
            handoff.destination_region,
            TraceEventKind::RegionCloseBegin,
        ));
        trace.push(TraceEvent::obligation_handoff(5, Time::ZERO, &handoff));
        let returned = crate::trace::event::ObligationHandoff {
            id: handoff.id,
            source_ticket: 7,
            destination_ticket: 11,
            source_holder: handoff.destination_holder,
            destination_holder: handoff.source_holder,
            source_region: handoff.destination_region,
            destination_region: handoff.source_region,
        };
        trace.push(TraceEvent::obligation_handoff(6, Time::ZERO, &returned));
        trace.push(trace_close(
            7,
            handoff.destination_region,
            TraceEventKind::RegionCloseComplete,
        ));
        trace.push(TraceEvent::obligation_commit(
            8,
            Time::ZERO,
            returned.id,
            returned.destination_holder,
            returned.destination_region,
            ObligationKind::Lease,
            1,
        ));
        let result = analyzer.analyze_trace(&trace);
        assert!(result.is_safe(), "{result}");
        assert_eq!(result.stats.total_reserved, 1);
        assert_eq!(result.stats.total_committed, 1);
        assert_eq!(result.stats.max_pending, 1);
        assert!(result.timeline.final_marking().unwrap().is_zero());
        let legacy_negative = [TraceEvent::obligation_commit(
            1,
            Time::ZERO,
            o(3),
            t(0),
            r(0),
            ObligationKind::Lease,
            1,
        )];
        let old = analyzer.analyze(&project_trace(&legacy_negative));
        let direct = analyzer.analyze_trace(&legacy_negative);
        assert!(!direct.is_safe());
        assert_eq!(old.to_string(), direct.to_string());
        assert_eq!(old.timeline.to_string(), direct.timeline.to_string());
    }

    #[test]
    fn transfer_trace_unrelated_terminal_cannot_consume_destination_marking() {
        for scenario in ["unknown", "other_region", "other_kind", "other_duplicate"] {
            let (mut trace, handoff) = transfer_trace(true, ObligationKind::Lease);
            let other_holder = if scenario == "other_region" {
                handoff.source_holder
            } else {
                handoff.destination_holder
            };
            let other_region = if scenario == "other_region" {
                handoff.source_region
            } else {
                handoff.destination_region
            };
            if scenario != "unknown" {
                trace.push(TraceEvent::obligation_reserve(
                    4,
                    Time::ZERO,
                    o(1),
                    other_holder,
                    other_region,
                    if scenario == "other_kind" {
                        ObligationKind::Ack
                    } else {
                        ObligationKind::Lease
                    },
                ));
            }
            if scenario == "other_duplicate" {
                trace.push(TraceEvent::obligation_commit(
                    5,
                    Time::ZERO,
                    o(1),
                    other_holder,
                    other_region,
                    ObligationKind::Lease,
                    1,
                ));
            }
            trace.push(TraceEvent::obligation_handoff(6, Time::ZERO, &handoff));
            trace.push(TraceEvent::obligation_commit(
                7,
                Time::ZERO,
                o(1),
                other_holder,
                handoff.destination_region,
                ObligationKind::Lease,
                1,
            ));
            if scenario == "other_kind" {
                trace.push(TraceEvent::obligation_commit(
                    8,
                    Time::ZERO,
                    o(1),
                    other_holder,
                    other_region,
                    ObligationKind::Ack,
                    1,
                ));
            }
            trace.push(trace_close(
                8,
                handoff.destination_region,
                TraceEventKind::RegionCloseComplete,
            ));
            let result = MarkingAnalyzer::new().analyze_trace(&trace);
            assert!(!result.is_safe(), "aggregate theft accepted: {scenario}");
            assert_eq!(result.invalid_transitions.len(), 1, "{scenario}: {result}");
            assert_eq!(
                result
                    .timeline
                    .final_marking()
                    .unwrap()
                    .region_pending(handoff.destination_region),
                1
            );
            assert_eq!(result.leaks.len(), 1);
            assert_eq!(result.leaks[0].region, handoff.destination_region);
            assert_eq!(result.leaks[0].count, 1);
            assert_eq!(
                result.stats.total_committed,
                u32::from(matches!(scenario, "other_duplicate" | "other_kind"))
            );
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ConformanceRequirementLevel {
        Must,
        Should,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ConformanceStatus {
        Pass,
        Fail,
    }

    #[derive(Debug, Clone)]
    struct MarkingConformanceResult {
        requirement_id: &'static str,
        description: &'static str,
        level: ConformanceRequirementLevel,
        status: ConformanceStatus,
        evidence: String,
    }

    struct MarkingConformanceHarness;

    impl MarkingConformanceHarness {
        fn run_all() -> Vec<MarkingConformanceResult> {
            vec![
                Self::reserve_commit_close_returns_to_zero(),
                Self::region_close_surfaces_pending_obligations(),
                Self::below_zero_transitions_are_invalid(),
                Self::projection_keeps_only_marking_events(),
            ]
        }

        fn render_matrix(results: &[MarkingConformanceResult]) -> String {
            use std::fmt::Write;

            let mut out = String::new();
            out.push_str("# Obligation Marking VASS Conformance Matrix\n\n");
            out.push_str("| Req ID | Level | Status | Description | Evidence |\n");
            out.push_str("|--------|-------|--------|-------------|----------|\n");

            let mut must_total = 0;
            let mut must_pass = 0;
            let mut should_total = 0;
            let mut should_pass = 0;

            for result in results {
                let level = match result.level {
                    ConformanceRequirementLevel::Must => {
                        must_total += 1;
                        if result.status == ConformanceStatus::Pass {
                            must_pass += 1;
                        }
                        "MUST"
                    }
                    ConformanceRequirementLevel::Should => {
                        should_total += 1;
                        if result.status == ConformanceStatus::Pass {
                            should_pass += 1;
                        }
                        "SHOULD"
                    }
                };
                let status = match result.status {
                    ConformanceStatus::Pass => "PASS",
                    ConformanceStatus::Fail => "FAIL",
                };
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} | {} |",
                    result.requirement_id, level, status, result.description, result.evidence
                );
            }

            let _ = writeln!(out, "\nSummary:");
            let _ = writeln!(out, "- MUST: {must_pass}/{must_total}");
            let _ = writeln!(out, "- SHOULD: {should_pass}/{should_total}");
            let overall = if must_pass == must_total {
                "CONFORMANT"
            } else {
                "NON-CONFORMANT"
            };
            let _ = writeln!(out, "- Overall: {overall}");

            out
        }

        fn reserve_commit_close_returns_to_zero() -> MarkingConformanceResult {
            let events = vec![
                reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
                commit(10, o(0), r(0), ObligationKind::SendPermit),
                close(20, r(0)),
            ];
            let mut analyzer = MarkingAnalyzer::new();
            let result = analyzer.analyze(&events);
            let passes = result.is_safe()
                && result.leak_count() == 0
                && result
                    .timeline
                    .final_marking()
                    .is_some_and(ObligationMarking::is_zero);

            MarkingConformanceResult {
                requirement_id: "VASS-001",
                description: "reserve/commit/close returns to zero marking",
                level: ConformanceRequirementLevel::Must,
                status: if passes {
                    ConformanceStatus::Pass
                } else {
                    ConformanceStatus::Fail
                },
                evidence: format!(
                    "safe={} leaks={} final_zero={}",
                    result.is_safe(),
                    result.leak_count(),
                    result
                        .timeline
                        .final_marking()
                        .is_some_and(ObligationMarking::is_zero)
                ),
            }
        }

        fn region_close_surfaces_pending_obligations() -> MarkingConformanceResult {
            let events = vec![
                reserve(0, o(1), ObligationKind::SendPermit, t(0), r(0)),
                close(10, r(0)),
            ];
            let mut analyzer = MarkingAnalyzer::new();
            let result = analyzer.analyze(&events);
            let passes = !result.is_safe()
                && result.leak_count() == 1
                && result.leaks[0].kind == ObligationKind::SendPermit;

            MarkingConformanceResult {
                requirement_id: "VASS-002",
                description: "region close surfaces pending obligations as leaks",
                level: ConformanceRequirementLevel::Must,
                status: if passes {
                    ConformanceStatus::Pass
                } else {
                    ConformanceStatus::Fail
                },
                evidence: format!(
                    "safe={} leaks={} first_kind={:?}",
                    result.is_safe(),
                    result.leak_count(),
                    result.leaks.first().map(|leak| leak.kind)
                ),
            }
        }

        fn below_zero_transitions_are_invalid() -> MarkingConformanceResult {
            let events = vec![commit(10, o(2), r(0), ObligationKind::Ack)];
            let mut analyzer = MarkingAnalyzer::new();
            let result = analyzer.analyze(&events);
            let passes = result.invalid_transitions.len() == 1 && !result.is_safe();

            MarkingConformanceResult {
                requirement_id: "VASS-003",
                description: "commit below zero is recorded as invalid transition",
                level: ConformanceRequirementLevel::Must,
                status: if passes {
                    ConformanceStatus::Pass
                } else {
                    ConformanceStatus::Fail
                },
                evidence: format!(
                    "invalid={} safe={}",
                    result.invalid_transitions.len(),
                    result.is_safe()
                ),
            }
        }

        fn projection_keeps_only_marking_events() -> MarkingConformanceResult {
            let trace_events = vec![
                TraceEvent::new(
                    0,
                    Time::ZERO,
                    TraceEventKind::Spawn,
                    TraceData::Task {
                        task: t(0),
                        region: r(0),
                    },
                ),
                TraceEvent::new(
                    1,
                    Time::ZERO,
                    TraceEventKind::ObligationReserve,
                    TraceData::Obligation {
                        obligation: o(3),
                        task: t(0),
                        region: r(0),
                        kind: ObligationKind::Lease,
                        state: crate::record::ObligationState::Reserved,
                        duration_ns: None,
                        abort_reason: None,
                    },
                ),
                TraceEvent::new(
                    2,
                    Time::from_nanos(5),
                    TraceEventKind::Poll,
                    TraceData::Task {
                        task: t(0),
                        region: r(0),
                    },
                ),
                TraceEvent::new(
                    3,
                    Time::from_nanos(10),
                    TraceEventKind::ObligationAbort,
                    TraceData::Obligation {
                        obligation: o(3),
                        task: t(0),
                        region: r(0),
                        kind: ObligationKind::Lease,
                        state: crate::record::ObligationState::Aborted,
                        duration_ns: Some(10),
                        abort_reason: None,
                    },
                ),
                TraceEvent::new(
                    4,
                    Time::from_nanos(20),
                    TraceEventKind::RegionCloseBegin,
                    TraceData::Region {
                        region: r(0),
                        parent: None,
                    },
                ),
            ];
            let projected = project_trace(&trace_events);
            let mut analyzer = MarkingAnalyzer::new();
            let result = analyzer.analyze(&projected);
            let passes = projected.len() == 3 && result.is_safe();

            MarkingConformanceResult {
                requirement_id: "VASS-004",
                description: "trace projection keeps only obligation and close events",
                level: ConformanceRequirementLevel::Should,
                status: if passes {
                    ConformanceStatus::Pass
                } else {
                    ConformanceStatus::Fail
                },
                evidence: format!("projected={} safe={}", projected.len(), result.is_safe()),
            }
        }
    }

    // ---- Safe traces -------------------------------------------------------

    #[test]
    fn empty_trace_is_safe() {
        init_test("empty_trace_is_safe");
        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&[]);
        let is_safe = result.is_safe();
        crate::assert_with_log!(is_safe, "safe", true, is_safe);
        let total = result.stats.total_reserved;
        crate::assert_with_log!(total == 0, "reserved", 0, total);
        crate::test_complete!("empty_trace_is_safe");
    }

    #[test]
    fn single_reserve_commit_is_safe() {
        init_test("single_reserve_commit_is_safe");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            close(20, r(0)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let is_safe = result.is_safe();
        crate::assert_with_log!(is_safe, "safe", true, is_safe);
        let reserved = result.stats.total_reserved;
        crate::assert_with_log!(reserved == 1, "reserved", 1, reserved);
        let committed = result.stats.total_committed;
        crate::assert_with_log!(committed == 1, "committed", 1, committed);
        crate::test_complete!("single_reserve_commit_is_safe");
    }

    #[test]
    fn single_reserve_abort_is_safe() {
        init_test("single_reserve_abort_is_safe");
        let events = vec![
            reserve(0, o(0), ObligationKind::Ack, t(0), r(0)),
            abort(5, o(0), r(0), ObligationKind::Ack),
            close(10, r(0)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let is_safe = result.is_safe();
        crate::assert_with_log!(is_safe, "safe", true, is_safe);
        let aborted = result.stats.total_aborted;
        crate::assert_with_log!(aborted == 1, "aborted", 1, aborted);
        crate::test_complete!("single_reserve_abort_is_safe");
    }

    #[test]
    fn multiple_obligations_safe() {
        init_test("multiple_obligations_safe");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::Ack, t(0), r(0)),
            reserve(2, o(2), ObligationKind::Lease, t(1), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            abort(11, o(1), r(0), ObligationKind::Ack),
            commit(12, o(2), r(0), ObligationKind::Lease),
            close(20, r(0)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let is_safe = result.is_safe();
        crate::assert_with_log!(is_safe, "safe", true, is_safe);
        let max_pending = result.stats.max_pending;
        crate::assert_with_log!(max_pending == 3, "max pending", 3, max_pending);
        crate::test_complete!("multiple_obligations_safe");
    }

    #[test]
    fn multiple_regions_safe() {
        init_test("multiple_regions_safe");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::Lease, t(1), r(1)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            commit(11, o(1), r(1), ObligationKind::Lease),
            close(20, r(0)),
            close(21, r(1)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let is_safe = result.is_safe();
        crate::assert_with_log!(is_safe, "safe", true, is_safe);
        let regions = result.stats.distinct_regions;
        crate::assert_with_log!(regions == 2, "regions", 2, regions);
        crate::test_complete!("multiple_regions_safe");
    }

    // ---- Leak detection ----------------------------------------------------

    #[test]
    fn leak_detected_on_region_close() {
        init_test("leak_detected_on_region_close");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close(10, r(0)), // Close without resolving.
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let is_safe = result.is_safe();
        crate::assert_with_log!(!is_safe, "not safe", false, is_safe);
        let leak_count = result.leak_count();
        crate::assert_with_log!(leak_count == 1, "leak count", 1, leak_count);
        let leak = &result.leaks[0];
        let kind = leak.kind;
        crate::assert_with_log!(
            kind == ObligationKind::SendPermit,
            "kind",
            ObligationKind::SendPermit,
            kind
        );
        let count = leak.count;
        crate::assert_with_log!(count == 1, "count", 1, count);
        crate::test_complete!("leak_detected_on_region_close");
    }

    #[test]
    fn send_permit_leak_display_has_asup_e202() {
        init_test("send_permit_leak_display_has_asup_e202");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close(10, r(0)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let rendered = result.leaks[0].to_string();

        assert!(rendered.starts_with("[ASUP-E202]"));
        assert!(rendered.contains("send_permit obligation(s)"));
        crate::test_complete!("send_permit_leak_display_has_asup_e202");
    }

    #[test]
    fn multiple_leaks_same_region() {
        init_test("multiple_leaks_same_region");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::Lease, t(0), r(0)),
            close(10, r(0)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let leak_count = result.leak_count();
        crate::assert_with_log!(leak_count == 2, "leak count", 2, leak_count);
        crate::test_complete!("multiple_leaks_same_region");
    }

    #[test]
    fn partial_leak_one_region() {
        init_test("partial_leak_one_region");
        // One obligation resolved, one leaked.
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::Ack, t(0), r(0)),
            commit(5, o(0), r(0), ObligationKind::SendPermit),
            close(10, r(0)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let leak_count = result.leak_count();
        crate::assert_with_log!(leak_count == 1, "leak count", 1, leak_count);
        let kind = result.leaks[0].kind;
        crate::assert_with_log!(
            kind == ObligationKind::Ack,
            "kind",
            ObligationKind::Ack,
            kind
        );
        crate::test_complete!("partial_leak_one_region");
    }

    // ---- Leak event --------------------------------------------------------

    #[test]
    fn explicit_leak_event() {
        init_test("explicit_leak_event");
        let events = vec![
            reserve(0, o(0), ObligationKind::IoOp, t(0), r(0)),
            leak(5, o(0), r(0), ObligationKind::IoOp),
            close(10, r(0)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        // The leak event decrements the marking, so region close sees 0 pending.
        // But we still record it in stats.
        let total_leaked = result.stats.total_leaked;
        crate::assert_with_log!(total_leaked == 1, "leaked", 1, total_leaked);
        let is_safe = result.is_safe();
        crate::assert_with_log!(is_safe, "safe (marking cleared)", true, is_safe);
        crate::test_complete!("explicit_leak_event");
    }

    // ---- Invalid transitions -----------------------------------------------

    #[test]
    fn commit_below_zero_is_invalid() {
        init_test("commit_below_zero_is_invalid");
        let events = vec![commit(10, o(0), r(0), ObligationKind::SendPermit)];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let invalid = result.invalid_transitions.len();
        crate::assert_with_log!(invalid == 1, "invalid count", 1, invalid);
        crate::test_complete!("commit_below_zero_is_invalid");
    }

    // ---- Marking vector ----------------------------------------------------

    #[test]
    fn marking_vector_operations() {
        init_test("marking_vector_operations");
        let mut marking = ObligationMarking::empty();
        let is_zero = marking.is_zero();
        crate::assert_with_log!(is_zero, "initially zero", true, is_zero);

        marking.increment(ObligationKind::SendPermit, r(0));
        marking.increment(ObligationKind::SendPermit, r(0));
        marking.increment(ObligationKind::Lease, r(1));

        let total = marking.total_pending();
        crate::assert_with_log!(total == 3, "total", 3, total);
        let r0_pending = marking.region_pending(r(0));
        crate::assert_with_log!(r0_pending == 2, "r0 pending", 2, r0_pending);
        let r1_pending = marking.region_pending(r(1));
        crate::assert_with_log!(r1_pending == 1, "r1 pending", 1, r1_pending);

        let ok = marking.decrement(ObligationKind::SendPermit, r(0));
        crate::assert_with_log!(ok, "decrement ok", true, ok);
        let total = marking.total_pending();
        crate::assert_with_log!(total == 2, "total after decrement", 2, total);

        // Decrement to zero and try again.
        let ok = marking.decrement(ObligationKind::SendPermit, r(0));
        crate::assert_with_log!(ok, "second decrement ok", true, ok);
        let fail = marking.decrement(ObligationKind::SendPermit, r(0));
        crate::assert_with_log!(!fail, "third decrement fails", false, fail);

        crate::test_complete!("marking_vector_operations");
    }

    #[test]
    fn marking_display() {
        init_test("marking_display");
        let mut marking = ObligationMarking::empty();
        let empty_str = format!("{marking}");

        marking.increment(ObligationKind::SendPermit, r(0));
        let nonempty_str = format!("{marking}");
        let rendered = format!("empty: {empty_str}\nnonempty: {nonempty_str}");
        let expected = "empty: M = [0]\nnonempty: M = [(send_permit, RegionId(0:0))=1]";
        assert_eq!(rendered, expected);
        crate::test_complete!("marking_display");
    }

    // ---- Timeline ----------------------------------------------------------

    #[test]
    fn timeline_tracks_evolution() {
        init_test("timeline_tracks_evolution");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(5, o(1), ObligationKind::Ack, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            commit(15, o(1), r(0), ObligationKind::Ack),
            close(20, r(0)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);

        // initial + 5 events + final = 7 snapshots.
        let snap_count = result.timeline.snapshots.len();
        crate::assert_with_log!(snap_count == 7, "snapshot count", 7, snap_count);

        let max = result.timeline.max_pending();
        crate::assert_with_log!(max == 2, "max pending", 2, max);
        let rendered = format!("{}", result.timeline);
        let expected = r#"Marking Timeline (7 snapshots):
  t=0ns: M = [0] (initial)
  t=0ns: M = [(send_permit, RegionId(0:0))=1] (reserve(send_permit, RegionId(0:0)))
  t=5ns: M = [(send_permit, RegionId(0:0))=1, (ack, RegionId(0:0))=1] (reserve(ack, RegionId(0:0)))
  t=10ns: M = [(ack, RegionId(0:0))=1] (commit(send_permit, RegionId(0:0)))
  t=15ns: M = [0] (commit(ack, RegionId(0:0)))
  t=20ns: M = [0] (region_close(RegionId(0:0)))
  t=20ns: M = [0] (final)
"#;
        assert_eq!(rendered, expected);
        crate::test_complete!("timeline_tracks_evolution");
    }

    // ---- Statistics --------------------------------------------------------

    #[test]
    fn stats_are_accurate() {
        init_test("stats_are_accurate");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::Ack, t(0), r(0)),
            reserve(2, o(2), ObligationKind::Lease, t(1), r(1)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            abort(11, o(1), r(0), ObligationKind::Ack),
            commit(12, o(2), r(1), ObligationKind::Lease),
            close(20, r(0)),
            close(21, r(1)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let reserved = result.stats.total_reserved;
        crate::assert_with_log!(reserved == 3, "reserved", 3, reserved);
        let committed = result.stats.total_committed;
        crate::assert_with_log!(committed == 2, "committed", 2, committed);
        let aborted = result.stats.total_aborted;
        crate::assert_with_log!(aborted == 1, "aborted", 1, aborted);
        let regions = result.stats.distinct_regions;
        crate::assert_with_log!(regions == 2, "regions", 2, regions);
        let kinds = result.stats.distinct_kinds;
        crate::assert_with_log!(kinds == 3, "kinds", 3, kinds);
        crate::test_complete!("stats_are_accurate");
    }

    #[test]
    fn stats_track_semaphore_permit_kind() {
        init_test("stats_track_semaphore_permit_kind");
        let events = vec![
            reserve(0, o(0), ObligationKind::SemaphorePermit, t(0), r(0)),
            commit(1, o(0), r(0), ObligationKind::SemaphorePermit),
            close(2, r(0)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);

        let is_safe = result.is_safe();
        crate::assert_with_log!(is_safe, "semaphore permit trace is safe", true, is_safe);
        let reserved = result.stats.total_reserved;
        crate::assert_with_log!(reserved == 1, "reserved", 1, reserved);
        let kinds = result.stats.distinct_kinds;
        crate::assert_with_log!(kinds == 1, "kinds", 1, kinds);
        crate::test_complete!("stats_track_semaphore_permit_kind");
    }

    // ---- Analyzer reuse ----------------------------------------------------

    #[test]
    fn analyzer_reuse() {
        init_test("analyzer_reuse");
        let mut analyzer = MarkingAnalyzer::new();

        let events1 = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            close(10, r(0)),
        ];
        let r1 = analyzer.analyze(&events1);
        let r1_safe = r1.is_safe();
        crate::assert_with_log!(!r1_safe, "first not safe", false, r1_safe);

        let events2 = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            commit(5, o(0), r(0), ObligationKind::SendPermit),
            close(10, r(0)),
        ];
        let r2 = analyzer.analyze(&events2);
        let r2_safe = r2.is_safe();
        crate::assert_with_log!(r2_safe, "second safe", true, r2_safe);

        // First result unaffected.
        let r1_leaks = r1.leak_count();
        crate::assert_with_log!(r1_leaks == 1, "first still has leak", 1, r1_leaks);
        crate::test_complete!("analyzer_reuse");
    }

    // ---- Display impls -----------------------------------------------------

    #[test]
    fn display_impls() {
        init_test("marking_display_impls");
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(5, o(1), ObligationKind::Ack, t(0), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            close(15, r(0)),
            abort(20, o(2), r(1), ObligationKind::Lease),
        ];
        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let rendered = format!(
            "leak: {}\ninvalid: {}\n\n{}",
            result.leaks[0], result.invalid_transitions[0], result
        );
        let expected = r#"leak: leak: 1 ack obligation(s) in RegionId(0:0) at 15ns
invalid: invalid at 20ns: abort(lease, RegionId(1:0)) but marking is already zero

VASS Marking Analysis Result
============================
Events processed: 5
Safe: false

Statistics:
  Reserved:  2
  Committed: 1
  Aborted:   1
  Leaked:    0
  Max pending: 2
  Regions:   1
  Kinds:     2

Leak violations (1):
  leak: 1 ack obligation(s) in RegionId(0:0) at 15ns

Invalid transitions (1):
  invalid at 20ns: abort(lease, RegionId(1:0)) but marking is already zero
"#;
        assert_eq!(rendered, expected);
        crate::test_complete!("marking_display_impls");
    }

    // ---- Realistic: channel send with cancel race --------------------------

    #[test]
    fn realistic_send_cancel_race() {
        init_test("realistic_send_cancel_race");
        // Model: Two tasks in a region, one sends, one gets cancelled.
        // The cancelled task should abort its obligation.
        let events = vec![
            reserve(0, o(0), ObligationKind::SendPermit, t(0), r(0)),
            reserve(1, o(1), ObligationKind::SendPermit, t(1), r(0)),
            commit(10, o(0), r(0), ObligationKind::SendPermit),
            abort(11, o(1), r(0), ObligationKind::SendPermit), // Cancelled task aborts.
            close(20, r(0)),
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let is_safe = result.is_safe();
        crate::assert_with_log!(is_safe, "safe", true, is_safe);
        let max = result.stats.max_pending;
        crate::assert_with_log!(max == 2, "max pending", 2, max);
        crate::test_complete!("realistic_send_cancel_race");
    }

    // ---- Realistic: nested regions -----------------------------------------

    #[test]
    fn realistic_nested_regions() {
        init_test("realistic_nested_regions");
        // Model: Parent region r0 with child region r1.
        // Child closes first, then parent.
        let events = vec![
            reserve(0, o(0), ObligationKind::Lease, t(0), r(0)),
            reserve(1, o(1), ObligationKind::SendPermit, t(1), r(1)),
            commit(10, o(1), r(1), ObligationKind::SendPermit),
            close(15, r(1)), // Child closes.
            commit(20, o(0), r(0), ObligationKind::Lease),
            close(25, r(0)), // Parent closes.
        ];

        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&events);
        let is_safe = result.is_safe();
        crate::assert_with_log!(is_safe, "safe", true, is_safe);
        let closed = result.closed_regions.len();
        crate::assert_with_log!(closed == 2, "closed regions", 2, closed);
        crate::test_complete!("realistic_nested_regions");
    }

    // ---- project_trace integration -----------------------------------------

    #[test]
    fn project_trace_extracts_obligation_events() {
        init_test("project_trace_extracts_obligation_events");
        // Build synthetic trace events.
        let trace_events = vec![
            TraceEvent::new(
                0,
                Time::ZERO,
                TraceEventKind::Spawn,
                TraceData::Task {
                    task: t(0),
                    region: r(0),
                },
            ),
            TraceEvent::new(
                1,
                Time::ZERO,
                TraceEventKind::ObligationReserve,
                TraceData::Obligation {
                    obligation: o(0),
                    task: t(0),
                    region: r(0),
                    kind: ObligationKind::SendPermit,
                    state: crate::record::ObligationState::Reserved,
                    duration_ns: None,
                    abort_reason: None,
                },
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(10),
                TraceEventKind::ObligationCommit,
                TraceData::Obligation {
                    obligation: o(0),
                    task: t(0),
                    region: r(0),
                    kind: ObligationKind::SendPermit,
                    state: crate::record::ObligationState::Committed,
                    duration_ns: Some(10),
                    abort_reason: None,
                },
            ),
            TraceEvent::new(
                3,
                Time::from_nanos(20),
                TraceEventKind::RegionCloseBegin,
                TraceData::Region {
                    region: r(0),
                    parent: None,
                },
            ),
        ];

        let projected = project_trace(&trace_events);
        let len = projected.len();
        crate::assert_with_log!(len == 3, "projected count", 3, len);

        // Feed to analyzer.
        let mut analyzer = MarkingAnalyzer::new();
        let result = analyzer.analyze(&projected);
        let is_safe = result.is_safe();
        crate::assert_with_log!(is_safe, "safe", true, is_safe);
        crate::test_complete!("project_trace_extracts_obligation_events");
    }

    #[test]
    fn project_trace_ignores_non_obligation() {
        init_test("project_trace_ignores_non_obligation");
        let trace_events = vec![
            TraceEvent::new(
                0,
                Time::ZERO,
                TraceEventKind::Spawn,
                TraceData::Task {
                    task: t(0),
                    region: r(0),
                },
            ),
            TraceEvent::new(
                1,
                Time::ZERO,
                TraceEventKind::Poll,
                TraceData::Task {
                    task: t(0),
                    region: r(0),
                },
            ),
        ];

        let projected = project_trace(&trace_events);
        let len = projected.len();
        crate::assert_with_log!(len == 0, "no obligation events", 0, len);
        crate::test_complete!("project_trace_ignores_non_obligation");
    }

    #[test]
    fn marking_vass_conformance_matrix() {
        init_test("marking_vass_conformance_matrix");
        let results = MarkingConformanceHarness::run_all();
        let must_total = results
            .iter()
            .filter(|result| result.level == ConformanceRequirementLevel::Must)
            .count();
        let must_pass = results
            .iter()
            .filter(|result| {
                result.level == ConformanceRequirementLevel::Must
                    && result.status == ConformanceStatus::Pass
            })
            .count();
        crate::assert_with_log!(
            must_total == must_pass,
            "all MUST requirements pass",
            must_total,
            must_pass
        );

        let rendered = MarkingConformanceHarness::render_matrix(&results);
        let expected = r#"# Obligation Marking VASS Conformance Matrix

| Req ID | Level | Status | Description | Evidence |
|--------|-------|--------|-------------|----------|
| VASS-001 | MUST | PASS | reserve/commit/close returns to zero marking | safe=true leaks=0 final_zero=true |
| VASS-002 | MUST | PASS | region close surfaces pending obligations as leaks | safe=false leaks=1 first_kind=Some(SendPermit) |
| VASS-003 | MUST | PASS | commit below zero is recorded as invalid transition | invalid=1 safe=false |
| VASS-004 | SHOULD | PASS | trace projection keeps only obligation and close events | projected=3 safe=true |

Summary:
- MUST: 3/3
- SHOULD: 1/1
- Overall: CONFORMANT
"#;
        assert_eq!(rendered, expected);
        crate::test_complete!("marking_vass_conformance_matrix");
    }

    #[test]
    fn marking_dimension_debug_clone_copy_eq() {
        let d = MarkingDimension {
            kind: ObligationKind::SendPermit,
            region: r(1),
        };
        let dbg = format!("{d:?}");
        assert!(dbg.contains("MarkingDimension"));

        let d2 = d;
        assert_eq!(d, d2);

        let d3 = d;
        assert_eq!(d, d3);
    }

    #[test]
    fn obligation_marking_debug_clone_default() {
        let m = ObligationMarking::default();
        let dbg = format!("{m:?}");
        assert!(dbg.contains("ObligationMarking"));

        let m2 = m;
        assert!(m2.is_zero());

        let m3 = ObligationMarking::empty();
        assert!(m3.is_zero());
    }

    #[test]
    fn marking_timeline_debug_clone_default() {
        let t = MarkingTimeline::default();
        let dbg = format!("{t:?}");
        assert!(dbg.contains("MarkingTimeline"));

        let t2 = t;
        assert!(t2.snapshots.is_empty());
    }

    #[test]
    fn analysis_stats_debug_clone_default() {
        let s = AnalysisStats::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("AnalysisStats"));

        let s2 = s;
        assert_eq!(s2.total_reserved, 0);
        assert_eq!(s2.total_committed, 0);
    }
}
