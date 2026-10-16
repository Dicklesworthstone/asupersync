//! Causal order verification for trace events.
//!
//! Uses logical timestamps attached to [`TraceEvent`]s to verify that
//! the recorded execution respects the happens-before partial order.
//!
//! # Verification Rules
//!
//! 1. **Monotonic sequence**: Within the same logical clock domain,
//!    later sequence numbers must have greater-or-equal logical times.
//! 2. **Causal consistency**: If event A causally precedes event B
//!    (same task, A.seq < B.seq), then A's logical time must be
//!    strictly less than B's logical time.
//! 3. **No backward causation**: A receive event's logical time must
//!    be strictly greater than the sender's logical time at send.

use crate::trace::distributed::{CausalOrder, LogicalTime};
use crate::trace::event::{TraceData, TraceEvent, TraceEventKind};
use crate::types::TaskId;
use core::fmt;
use std::collections::BTreeMap;

fn causal_order(a: &LogicalTime, b: &LogicalTime) -> CausalOrder {
    match a.partial_cmp(b) {
        Some(std::cmp::Ordering::Less) => CausalOrder::Before,
        Some(std::cmp::Ordering::Greater) => CausalOrder::After,
        Some(std::cmp::Ordering::Equal) => CausalOrder::Equal,
        None => CausalOrder::Concurrent,
    }
}

/// A violation of causal ordering in a trace.
#[derive(Debug, Clone)]
pub struct CausalityViolation {
    /// The kind of violation.
    pub kind: CausalityViolationKind,
    /// Index of the earlier event in the trace.
    pub earlier_idx: usize,
    /// Index of the later event in the trace.
    pub later_idx: usize,
    /// Sequence number of the earlier event.
    pub earlier_seq: u64,
    /// Sequence number of the later event.
    pub later_seq: u64,
}

/// The kind of causal ordering violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CausalityViolationKind {
    /// Logical time went backward for sequentially ordered events.
    NonMonotonic,
    /// Two events on the same task have incomparable (concurrent) logical
    /// times, but they must be ordered since they share a single thread
    /// of execution.
    SameTaskConcurrent,
    /// A dependent event (e.g. wake after spawn) has a logical time that
    /// does not reflect the causal dependency.
    MissingDependency,
}

impl fmt::Display for CausalityViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?}: event[{}] (seq={}) -> event[{}] (seq={})",
            self.kind, self.earlier_idx, self.earlier_seq, self.later_idx, self.later_seq,
        )
    }
}

/// Verifies causal consistency of a trace using attached logical timestamps.
///
/// Events without logical timestamps are skipped during verification.
pub struct CausalOrderVerifier {
    violations: Vec<CausalityViolation>,
}

impl CausalOrderVerifier {
    /// Verify causal ordering of a trace.
    ///
    /// Returns `Ok(())` if the trace is causally consistent, or `Err` with
    /// all detected violations.
    pub fn verify(trace: &[TraceEvent]) -> Result<(), Vec<CausalityViolation>> {
        let mut verifier = Self {
            violations: Vec::new(),
        };

        verifier.check_monotonic(trace);
        verifier.check_same_task_ordering(trace);
        verifier.check_causal_dependencies(trace);

        if verifier.violations.is_empty() {
            Ok(())
        } else {
            Err(verifier.violations)
        }
    }

    /// Check that logical times are monotonically non-decreasing by sequence.
    fn check_monotonic(&mut self, trace: &[TraceEvent]) {
        let mut last_time: Option<(usize, u64, &LogicalTime)> = None;

        for (idx, event) in trace.iter().enumerate() {
            let Some(ref lt) = event.logical_time else {
                continue;
            };

            if let Some((prev_idx, prev_seq, prev_lt)) = last_time {
                // Same-type comparison only (Lamport vs Lamport, etc.)
                if let Some(ordering) = prev_lt.partial_cmp(lt) {
                    if ordering == std::cmp::Ordering::Greater {
                        self.violations.push(CausalityViolation {
                            kind: CausalityViolationKind::NonMonotonic,
                            earlier_idx: prev_idx,
                            later_idx: idx,
                            earlier_seq: prev_seq,
                            later_seq: event.seq,
                        });
                    }
                }
                // Different clock types are incomparable — skip check
            }

            last_time = Some((idx, event.seq, lt));
        }
    }

    /// Check that events on the same task have properly ordered logical times.
    fn check_same_task_ordering(&mut self, trace: &[TraceEvent]) {
        // Group events by task
        let mut task_events: BTreeMap<TaskId, Vec<(usize, &TraceEvent)>> = BTreeMap::new();

        for (idx, event) in trace.iter().enumerate() {
            if event.logical_time.is_none() {
                continue;
            }
            if let Some(task_id) = extract_task_id(event) {
                task_events.entry(task_id).or_default().push((idx, event));
            }
        }

        for events in task_events.values() {
            for window in events.windows(2) {
                let (idx_a, ev_a) = window[0];
                let (idx_b, ev_b) = window[1];

                let lt_a = ev_a.logical_time.as_ref().expect("logical_time must exist");
                let lt_b = ev_b.logical_time.as_ref().expect("logical_time must exist");

                match causal_order(lt_a, lt_b) {
                    CausalOrder::After | CausalOrder::Concurrent | CausalOrder::Equal => {
                        self.violations.push(CausalityViolation {
                            kind: CausalityViolationKind::SameTaskConcurrent,
                            earlier_idx: idx_a,
                            later_idx: idx_b,
                            earlier_seq: ev_a.seq,
                            later_seq: ev_b.seq,
                        });
                    }
                    CausalOrder::Before => {}
                }
            }
        }
    }

    /// Check that explicit causal dependencies have proper logical time ordering.
    ///
    /// For example, a Wake event for task T should have a logical time
    /// strictly after the Spawn event for task T.
    fn check_causal_dependencies(&mut self, trace: &[TraceEvent]) {
        // Map task_id -> spawn event index
        let mut spawn_events: BTreeMap<TaskId, (usize, &TraceEvent)> = BTreeMap::new();

        for (idx, event) in trace.iter().enumerate() {
            if event.logical_time.is_none() {
                continue;
            }

            if let Some(task_id) = extract_task_id(event) {
                if event.kind == TraceEventKind::Spawn {
                    spawn_events.insert(task_id, (idx, event));
                } else if event.kind == TraceEventKind::Wake
                    || event.kind == TraceEventKind::Schedule
                {
                    // Wake/Schedule must happen after spawn
                    if let Some(&(spawn_idx, spawn_ev)) = spawn_events.get(&task_id) {
                        let spawn_lt = spawn_ev
                            .logical_time
                            .as_ref()
                            .expect("logical_time must exist");
                        let current_lt = event
                            .logical_time
                            .as_ref()
                            .expect("logical_time must exist");

                        match causal_order(spawn_lt, current_lt) {
                            CausalOrder::After | CausalOrder::Equal | CausalOrder::Concurrent => {
                                self.violations.push(CausalityViolation {
                                    kind: CausalityViolationKind::MissingDependency,
                                    earlier_idx: spawn_idx,
                                    later_idx: idx,
                                    earlier_seq: spawn_ev.seq,
                                    later_seq: event.seq,
                                });
                            }
                            CausalOrder::Before => {}
                        }
                    }
                }
            }
        }
    }
}

/// Extract the task ID from a trace event, if present.
fn extract_task_id(event: &TraceEvent) -> Option<TaskId> {
    match &event.data {
        TraceData::Task { task, .. }
        | TraceData::Cancel { task, .. }
        | TraceData::Futurelock { task, .. }
        | TraceData::Obligation { task, .. }
        | TraceData::Worker { task, .. } => Some(*task),
        _ => None,
    }
}

#[cfg(test)]
#[path = "causality_inline_tests.rs"]
mod tests;
