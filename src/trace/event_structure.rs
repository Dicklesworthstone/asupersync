//! Event-structure representation for true-concurrency analysis.
//!
//! This module provides a minimal event-structure model derived from a single
//! execution trace. It captures:
//! - Events (with labels)
//! - Causality (partial order edges)
//! - Conflict (empty for single-trace derivation)
//!
//! # Notes
//!
//! A single interleaving trace is enough to derive causality edges between
//! *dependent* events (using the independence relation), but it is **not**
//! sufficient to derive conflicts. Conflicts require branching observations
//! (alternative traces) or additional semantic metadata.

use crate::trace::independence::independent;
use crate::trace::TraceData;
use crate::trace::TraceEvent;
use crate::trace::TraceEventKind;
use crate::types::{RegionId, TaskId};
use core::cmp::Reverse;
use std::collections::BinaryHeap;

/// Identifier for an event in an event structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventId(usize);

impl EventId {
    /// Creates a new event id from an index.
    #[must_use]
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    /// Returns the underlying index.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}

/// A labeled event in an event structure.
#[derive(Debug, Clone)]
pub struct Event {
    /// Event id.
    pub id: EventId,
    /// The source trace event.
    pub trace: TraceEvent,
}

impl Event {
    /// Returns the event label.
    #[must_use]
    pub const fn label(&self) -> TraceEventKind {
        self.trace.kind
    }
}

fn causality_pairs(trace: &[TraceEvent]) -> Vec<(usize, usize)> {
    let mut pairs = Vec::new();
    for i in 0..trace.len() {
        for j in (i + 1)..trace.len() {
            if !independent(&trace[i], &trace[j]) {
                pairs.push((i, j));
            }
        }
    }
    pairs
}

/// A stable notion of "owner" for a trace event, used by schedule-cost models.
///
/// This is intentionally low-cardinality and deterministic: it should group
/// events that "belong together" (task-lane events, region events, timer events)
/// so switch-count objectives behave predictably.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OwnerKey {
    /// Task-local owner key (task lane).
    Task(TaskId),
    /// Region-local owner key (region lifecycle lane).
    Region(RegionId),
    /// Timer-local owner key (timer lane).
    Timer(u64),
    /// I/O token-local owner key (I/O lane).
    IoToken(u64),
    /// Fallback for events that do not carry a stable owner key in their data.
    Kind(TraceEventKind),
}

impl OwnerKey {
    /// Compute an [`OwnerKey`] for a trace event.
    ///
    /// This is used by cost models (e.g., switch-count objectives) and must be
    /// deterministic given the event value.
    #[must_use]
    pub fn for_event(event: &TraceEvent) -> Self {
        match &event.data {
            TraceData::Task { task, .. }
            | TraceData::Cancel { task, .. }
            | TraceData::Obligation { task, .. }
            | TraceData::Futurelock { task, .. }
            | TraceData::Chaos {
                task: Some(task), ..
            } => Self::Task(*task),
            TraceData::Region { region, .. } | TraceData::RegionCancel { region, .. } => {
                Self::Region(*region)
            }
            TraceData::Timer { timer_id, .. } => Self::Timer(*timer_id),
            TraceData::IoRequested { token, .. }
            | TraceData::IoReady { token, .. }
            | TraceData::IoResult { token, .. }
            | TraceData::IoError { token, .. } => Self::IoToken(*token),
            _ => Self::Kind(event.kind),
        }
    }
}

/// A deterministic partial-order view of a single execution trace.
///
/// This is the dependency DAG induced by the independence relation:
/// for every `i < j`, we add an edge `i -> j` iff `NOT independent(e_i, e_j)`.
///
/// Note: this is intentionally a dense representation (transitive closure for
/// each "dependent" pair). Later optimizations may compute a transitive
/// reduction, but the semantics are defined by the full relation.
#[derive(Debug, Clone)]
pub struct TracePoset {
    n: usize,
    preds: Vec<Vec<usize>>,
    succs: Vec<Vec<usize>>,
    owner: Vec<OwnerKey>,
}

impl TracePoset {
    /// Build the dependency DAG induced by the trace's independence relation.
    ///
    /// For every `i < j`, we add an edge `i -> j` iff `NOT independent(e_i, e_j)`.
    #[must_use]
    pub fn from_trace(trace: &[TraceEvent]) -> Self {
        let n = trace.len();
        let mut preds = vec![Vec::new(); n];
        let mut succs = vec![Vec::new(); n];

        for (i, j) in causality_pairs(trace) {
            succs[i].push(j);
            preds[j].push(i);
        }

        let owner = trace.iter().map(OwnerKey::for_event).collect();

        Self {
            n,
            preds,
            succs,
            owner,
        }
    }

    #[must_use]
    /// Number of nodes (events) in the poset.
    pub const fn len(&self) -> usize {
        self.n
    }

    /// Returns `true` if this poset has no nodes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// Predecessor list for `idx`.
    #[must_use]
    pub fn preds(&self, idx: usize) -> &[usize] {
        &self.preds[idx]
    }

    /// Successor list for `idx`.
    #[must_use]
    pub fn succs(&self, idx: usize) -> &[usize] {
        &self.succs[idx]
    }

    /// Owner key for `idx`.
    #[must_use]
    pub fn owner(&self, idx: usize) -> OwnerKey {
        self.owner[idx]
    }

    /// Returns `true` if the poset contains edge `from -> to`.
    #[must_use]
    pub fn has_edge(&self, from: usize, to: usize) -> bool {
        // `succs[from]` is strictly increasing by construction.
        self.succs[from].binary_search(&to).is_ok()
    }

    /// Deterministic topological sort (lowest index first among available nodes).
    ///
    /// Returns `None` if a cycle is detected (should never happen for posets
    /// derived from a single trace with edges `i -> j` for `i < j`).
    #[must_use]
    pub fn topo_sort(&self) -> Option<Vec<usize>> {
        let mut indeg: Vec<usize> = self.preds.iter().map(Vec::len).collect();
        let mut heap: BinaryHeap<Reverse<usize>> = BinaryHeap::new();

        for (i, &deg) in indeg.iter().enumerate().take(self.n) {
            if deg == 0 {
                heap.push(Reverse(i));
            }
        }

        let mut out = Vec::with_capacity(self.n);
        while let Some(Reverse(v)) = heap.pop() {
            out.push(v);
            for &w in &self.succs[v] {
                debug_assert!(indeg[w] > 0, "in-degree underflow for node {w}");
                indeg[w] -= 1;
                if indeg[w] == 0 {
                    heap.push(Reverse(w));
                }
            }
        }

        if out.len() == self.n {
            Some(out)
        } else {
            None
        }
    }
}

/// Minimal event-structure representation.
#[derive(Debug, Clone)]
pub struct EventStructure {
    events: Vec<Event>,
    causality: Vec<(EventId, EventId)>,
    conflicts: Vec<(EventId, EventId)>,
}

impl EventStructure {
    /// Builds an event structure from a single interleaving trace.
    ///
    /// Causality edges are derived for any pair of **dependent** events with
    /// increasing trace order. Conflicts are left empty because they require
    /// multiple traces or semantic branching information.
    #[must_use]
    pub fn from_trace(trace: &[TraceEvent]) -> Self {
        let events: Vec<Event> = trace
            .iter()
            .enumerate()
            .map(|(idx, event)| Event {
                id: EventId::new(idx),
                trace: event.clone(),
            })
            .collect();

        let causality: Vec<(EventId, EventId)> = causality_pairs(trace)
            .into_iter()
            .map(|(i, j)| (EventId::new(i), EventId::new(j)))
            .collect();

        Self {
            events,
            causality,
            conflicts: Vec::new(),
        }
    }

    /// Returns the events in this structure.
    #[must_use]
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// Returns the causality edges.
    #[must_use]
    pub fn causality(&self) -> &[(EventId, EventId)] {
        &self.causality
    }

    /// Returns the conflict edges.
    #[must_use]
    pub fn conflicts(&self) -> &[(EventId, EventId)] {
        &self.conflicts
    }

    /// Returns a trivial HDA representation where each event is a 0-cell.
    #[must_use]
    pub fn to_hda(&self) -> HdaComplex {
        let cells = self
            .events
            .iter()
            .map(|event| HdaCell {
                dimension: 0,
                events: vec![event.id],
            })
            .collect();
        HdaComplex { cells }
    }
}

/// A simple HDA cell (conceptual placeholder).
#[derive(Debug, Clone)]
pub struct HdaCell {
    /// Dimension of the cell.
    pub dimension: usize,
    /// Events that span the cell.
    pub events: Vec<EventId>,
}

/// A minimal HDA complex representation.
#[derive(Debug, Clone)]
pub struct HdaComplex {
    /// Cells in the complex.
    pub cells: Vec<HdaCell>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::TraceEvent;
    use crate::types::{RegionId, TaskId, Time};

    #[test]
    fn independent_events_have_no_causal_edge() {
        let region_a = RegionId::new_for_test(1, 0);
        let region_b = RegionId::new_for_test(2, 0);
        let task_a = TaskId::new_for_test(1, 0);
        let task_b = TaskId::new_for_test(2, 0);

        let t1 = TraceEvent::spawn(1, Time::from_nanos(10), task_a, region_a);
        let t2 = TraceEvent::spawn(2, Time::from_nanos(20), task_b, region_b);

        let es = EventStructure::from_trace(&[t1, t2]);
        assert!(es.causality().is_empty());
    }

    #[test]
    fn dependent_events_form_causal_edge() {
        let region = RegionId::new_for_test(1, 0);
        let task = TaskId::new_for_test(7, 0);

        let t1 = TraceEvent::spawn(1, Time::from_nanos(10), task, region);
        let t2 = TraceEvent::schedule(2, Time::from_nanos(20), task, region);

        let es = EventStructure::from_trace(&[t1, t2]);
        assert_eq!(es.causality().len(), 1);
        assert_eq!(es.causality()[0].0.index(), 0);
        assert_eq!(es.causality()[0].1.index(), 1);
    }

    #[test]
    fn trace_poset_edges_match_dependence_relation() {
        let region_a = RegionId::new_for_test(1, 0);
        let region_b = RegionId::new_for_test(2, 0);
        let task_a = TaskId::new_for_test(1, 0);
        let task_b = TaskId::new_for_test(2, 0);

        let trace = vec![
            TraceEvent::spawn(1, Time::from_nanos(10), task_a, region_a),
            TraceEvent::spawn(2, Time::from_nanos(20), task_b, region_b),
            TraceEvent::schedule(3, Time::from_nanos(30), task_a, region_a),
            TraceEvent::schedule(4, Time::from_nanos(40), task_b, region_b),
        ];

        let poset = TracePoset::from_trace(&trace);

        for i in 0..trace.len() {
            for j in (i + 1)..trace.len() {
                let expected = !independent(&trace[i], &trace[j]);
                assert_eq!(poset.has_edge(i, j), expected, "edge {i}->{j}");
            }
        }

        assert_eq!(
            poset.topo_sort(),
            Some((0..trace.len()).collect::<Vec<_>>())
        );
    }

    #[test]
    fn trace_poset_owner_key_is_stable_for_task_events() {
        let region = RegionId::new_for_test(1, 0);
        let task = TaskId::new_for_test(7, 0);

        let trace = vec![
            TraceEvent::spawn(1, Time::from_nanos(10), task, region),
            TraceEvent::schedule(2, Time::from_nanos(20), task, region),
        ];

        let poset = TracePoset::from_trace(&trace);
        assert_eq!(poset.owner(0), OwnerKey::Task(task));
        assert_eq!(poset.owner(1), OwnerKey::Task(task));
    }

    #[test]
    fn trace_poset_owner_key_handles_region_timer_and_user_trace() {
        let region = RegionId::new_for_test(42, 0);
        let time = Time::from_nanos(10);

        let trace = vec![
            TraceEvent::region_created(1, time, region, None),
            TraceEvent::timer_scheduled(2, time, 7, time),
            TraceEvent::user_trace(3, time, "hello"),
        ];

        let poset = TracePoset::from_trace(&trace);
        assert_eq!(poset.owner(0), OwnerKey::Region(region));
        assert_eq!(poset.owner(1), OwnerKey::Timer(7));
        assert_eq!(poset.owner(2), OwnerKey::Kind(TraceEventKind::UserTrace));
    }
}
