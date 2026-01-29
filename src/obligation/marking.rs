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
//! use asupersync::types::{RegionId, ObligationId, TaskId, Time};
//! use asupersync::util::ArenaIndex;
//!
//! let r0 = RegionId::from_arena(ArenaIndex::new(0, 0));
//! let t0 = TaskId::from_arena(ArenaIndex::new(0, 0));
//! let o0 = ObligationId::from_arena(ArenaIndex::new(0, 0));
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
use std::collections::{BTreeMap, HashMap, HashSet};
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
pub fn project_trace(events: &[TraceEvent]) -> Vec<MarkingEvent> {
    // Track obligation metadata so we can reconstruct kind/region for commits/aborts.
    let mut obligation_meta: HashMap<ObligationId, (ObligationKind, RegionId)> = HashMap::new();
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
                obligation_meta.insert(*obligation, (*kind, *region));
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

            _ => {}
        }
    }

    projected
}

// ============================================================================
// ObligationMarking (the vector state)
// ============================================================================

/// Composite key for a marking dimension: (kind, region).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

/// The obligation marking vector M ∈ ℕ^(K × R).
///
/// Each entry counts the number of pending (unresolved) obligations
/// of a given kind in a given region.
#[derive(Debug, Clone, Default)]
pub struct ObligationMarking {
    /// The marking vector: dimension → count.
    counts: BTreeMap<MarkingDimension, u32>,
}

impl ObligationMarking {
    /// Creates an empty marking (all zeros).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Increment the count for a dimension (Reserve transition).
    pub fn increment(&mut self, kind: ObligationKind, region: RegionId) {
        let dim = MarkingDimension { kind, region };
        *self.counts.entry(dim).or_insert(0) += 1;
    }

    /// Decrement the count for a dimension (Commit/Abort/Leak transition).
    ///
    /// Returns `false` if the count was already zero (invalid transition).
    pub fn decrement(&mut self, kind: ObligationKind, region: RegionId) -> bool {
        let dim = MarkingDimension { kind, region };
        match self.counts.get_mut(&dim) {
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
        let dim = MarkingDimension { kind, region };
        self.counts.get(&dim).copied().unwrap_or(0)
    }

    /// Returns the total pending obligations across all dimensions.
    #[must_use]
    pub fn total_pending(&self) -> u32 {
        self.counts.values().sum()
    }

    /// Returns the total pending obligations for a specific region.
    #[must_use]
    pub fn region_pending(&self, region: RegionId) -> u32 {
        self.counts
            .iter()
            .filter(|(dim, _)| dim.region == region)
            .map(|(_, count)| *count)
            .sum()
    }

    /// Returns true if the marking is zero (no pending obligations).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.counts.values().all(|&c| c == 0)
    }

    /// Returns all non-zero dimensions.
    #[must_use]
    pub fn non_zero(&self) -> Vec<(MarkingDimension, u32)> {
        self.counts
            .iter()
            .filter(|(_, &c)| c > 0)
            .map(|(dim, count)| (*dim, *count))
            .collect()
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

impl fmt::Display for LeakViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    /// All kinds seen.
    all_kinds: HashSet<ObligationKind>,
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

        // Record initial state.
        self.snapshot("initial");

        for event in events {
            self.process_event(event);
        }

        // Record final state.
        self.snapshot("final");

        AnalysisResult {
            timeline: self.timeline.clone(),
            leaks: self.leaks.clone(),
            invalid_transitions: self.invalid_transitions.clone(),
            closed_regions: self.closed_regions.clone(),
            events_processed: events.len(),
            stats: AnalysisStats {
                total_reserved: self.stats.total_reserved,
                total_committed: self.stats.total_committed,
                total_aborted: self.stats.total_aborted,
                total_leaked: self.stats.total_leaked,
                max_pending: self.timeline.max_pending(),
                distinct_regions: self.all_regions.len(),
                distinct_kinds: self.all_kinds.len(),
            },
        }
    }

    /// Analyze a trace event stream directly (convenience method).
    ///
    /// Projects the trace into marking events and analyzes them.
    #[must_use]
    pub fn analyze_trace(&mut self, trace: &[TraceEvent]) -> AnalysisResult {
        let events = project_trace(trace);
        self.analyze(&events)
    }

    fn reset(&mut self) {
        self.marking = ObligationMarking::empty();
        self.timeline = MarkingTimeline::default();
        self.leaks.clear();
        self.invalid_transitions.clear();
        self.closed_regions.clear();
        self.stats = AnalysisStats::default();
        self.all_regions.clear();
        self.all_kinds.clear();
    }

    fn snapshot(&mut self, cause: &str) {
        let time = self
            .timeline
            .snapshots
            .last()
            .map_or(Time::ZERO, |s| s.time);
        self.timeline.snapshots.push(MarkingSnapshot {
            time,
            marking: self.marking.snapshot(),
            cause: cause.to_string(),
        });
    }

    fn process_event(&mut self, event: &MarkingEvent) {
        match &event.kind {
            MarkingEventKind::Reserve {
                kind, region, ..
            } => {
                self.marking.increment(*kind, *region);
                self.stats.total_reserved += 1;
                self.all_regions.insert(*region);
                self.all_kinds.insert(*kind);
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
                self.stats.total_committed += 1;
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
                self.stats.total_aborted += 1;
                self.timeline.snapshots.push(MarkingSnapshot {
                    time: event.time,
                    marking: self.marking.snapshot(),
                    cause: format!("abort({kind}, {region:?})"),
                });
            }

            MarkingEventKind::Leak { kind, region, .. } => {
                // Leak still decrements (obligation is gone, just erroneously).
                let _ = self.marking.decrement(*kind, *region);
                self.stats.total_leaked += 1;
                self.timeline.snapshots.push(MarkingSnapshot {
                    time: event.time,
                    marking: self.marking.snapshot(),
                    cause: format!("LEAK({kind}, {region:?})"),
                });
            }

            MarkingEventKind::RegionClose { region } => {
                self.closed_regions.insert(*region);
                let pending = self.marking.region_pending(*region);
                if pending > 0 {
                    // Check each kind for this region.
                    for kind in [
                        ObligationKind::SendPermit,
                        ObligationKind::Ack,
                        ObligationKind::Lease,
                        ObligationKind::IoOp,
                    ] {
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
        crate::assert_with_log!(kind == ObligationKind::Ack, "kind", ObligationKind::Ack, kind);
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
        let has_zero = empty_str.contains("[0]");
        crate::assert_with_log!(has_zero, "empty display", true, has_zero);

        marking.increment(ObligationKind::SendPermit, r(0));
        let nonempty_str = format!("{marking}");
        let has_m = nonempty_str.contains("M = [");
        crate::assert_with_log!(has_m, "nonempty display", true, has_m);
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
        let violation = LeakViolation {
            region: r(0),
            kind: ObligationKind::SendPermit,
            count: 2,
            close_time: Time::from_nanos(100),
        };
        let s = format!("{violation}");
        let has_leak = s.contains("leak");
        crate::assert_with_log!(has_leak, "violation display", true, has_leak);

        let invalid = InvalidTransition {
            time: Time::from_nanos(50),
            description: "test".to_string(),
        };
        let s = format!("{invalid}");
        let has_invalid = s.contains("invalid");
        crate::assert_with_log!(has_invalid, "invalid display", true, has_invalid);

        let result = AnalysisResult {
            timeline: MarkingTimeline::default(),
            leaks: vec![],
            invalid_transitions: vec![],
            closed_regions: HashSet::new(),
            events_processed: 0,
            stats: AnalysisStats::default(),
        };
        let s = format!("{result}");
        let has_safe = s.contains("Safe: true");
        crate::assert_with_log!(has_safe, "result display", true, has_safe);
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
}
