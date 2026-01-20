//! Replay and diff utilities for trace analysis.
//!
//! This module provides utilities for:
//! - Replaying a trace to reproduce an execution
//! - Comparing two traces to find divergences

use crate::trace::{TraceBuffer, TraceEvent};

/// Compares two traces and returns the first divergence point.
///
/// Returns `None` if the traces are equivalent.
#[must_use]
pub fn find_divergence(a: &TraceBuffer, b: &TraceBuffer) -> Option<TraceDivergence> {
    let a_events: Vec<_> = a.iter().collect();
    let b_events: Vec<_> = b.iter().collect();

    for (i, (a_event, b_event)) in a_events.iter().zip(b_events.iter()).enumerate() {
        if a_event.seq != b_event.seq || !events_match(a_event, b_event) {
            return Some(TraceDivergence {
                position: i,
                event_a: (*a_event).clone(),
                event_b: (*b_event).clone(),
            });
        }
    }

    // Check for length mismatch
    if a_events.len() != b_events.len() {
        let position = a_events.len().min(b_events.len());
        #[allow(clippy::map_unwrap_or)]
        return Some(TraceDivergence {
            position,
            event_a: a_events
                .get(position)
                .map(|e| (*e).clone())
                .unwrap_or_else(|| {
                    TraceEvent::user_trace(0, crate::types::Time::ZERO, "<end of trace A>")
                }),
            event_b: b_events
                .get(position)
                .map(|e| (*e).clone())
                .unwrap_or_else(|| {
                    TraceEvent::user_trace(0, crate::types::Time::ZERO, "<end of trace B>")
                }),
        });
    }

    None
}

/// Checks if two events match (ignoring sequence numbers).
fn events_match(a: &TraceEvent, b: &TraceEvent) -> bool {
    a.kind == b.kind && a.time == b.time
    // In a full implementation, we'd also compare data
}

/// A divergence between two traces.
#[derive(Debug, Clone)]
pub struct TraceDivergence {
    /// Position in the trace where divergence occurred.
    pub position: usize,
    /// Event from trace A at the divergence point.
    pub event_a: TraceEvent,
    /// Event from trace B at the divergence point.
    pub event_b: TraceEvent,
}

impl std::fmt::Display for TraceDivergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Divergence at position {}:\n  A: {}\n  B: {}",
            self.position, self.event_a, self.event_b
        )
    }
}

/// Summary of a trace for quick comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceSummary {
    /// Number of events.
    pub event_count: usize,
    /// Number of spawn events.
    pub spawn_count: usize,
    /// Number of complete events.
    pub complete_count: usize,
    /// Number of cancel events.
    pub cancel_count: usize,
}

impl TraceSummary {
    /// Creates a summary from a trace buffer.
    #[must_use]
    pub fn from_buffer(buffer: &TraceBuffer) -> Self {
        use crate::trace::event::TraceEventKind;

        let mut summary = Self {
            event_count: 0,
            spawn_count: 0,
            complete_count: 0,
            cancel_count: 0,
        };

        for event in buffer.iter() {
            summary.event_count += 1;
            match event.kind {
                TraceEventKind::Spawn => summary.spawn_count += 1,
                TraceEventKind::Complete => summary.complete_count += 1,
                TraceEventKind::CancelRequest | TraceEventKind::CancelAck => {
                    summary.cancel_count += 1;
                }
                _ => {}
            }
        }

        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::event::{TraceData, TraceEventKind};
    use crate::types::Time;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn identical_traces_no_divergence() {
        init_test("identical_traces_no_divergence");
        let mut a = TraceBuffer::new(10);
        let mut b = TraceBuffer::new(10);

        a.push(TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::None,
        ));
        b.push(TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::None,
        ));

        let div = find_divergence(&a, &b);
        let ok = div.is_none();
        crate::assert_with_log!(ok, "no divergence", true, ok);
        crate::test_complete!("identical_traces_no_divergence");
    }

    #[test]
    fn different_traces_find_divergence() {
        init_test("different_traces_find_divergence");
        let mut a = TraceBuffer::new(10);
        let mut b = TraceBuffer::new(10);

        a.push(TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::Spawn,
            TraceData::None,
        ));
        b.push(TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::Complete,
            TraceData::None,
        ));

        let div = find_divergence(&a, &b);
        let some = div.is_some();
        crate::assert_with_log!(some, "divergence", true, some);
        let pos = div.expect("divergence").position;
        crate::assert_with_log!(pos == 0, "position", 0, pos);
        crate::test_complete!("different_traces_find_divergence");
    }
}
