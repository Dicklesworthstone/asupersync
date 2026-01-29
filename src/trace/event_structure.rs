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
use crate::trace::TraceEvent;
use crate::trace::TraceEventKind;

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

        let mut causality = Vec::new();
        for i in 0..trace.len() {
            for j in (i + 1)..trace.len() {
                if !independent(&trace[i], &trace[j]) {
                    causality.push((EventId::new(i), EventId::new(j)));
                }
            }
        }

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
}
