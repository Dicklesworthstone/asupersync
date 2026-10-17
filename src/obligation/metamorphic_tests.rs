//! Metamorphic tests for obligation system invariants.
//!
//! These tests verify properties that must hold regardless of execution order,
//! catching bugs that conventional unit tests miss by exploiting transformations
//! of the input space while checking relationships between outputs.

#[cfg(test)]
use crate::obligation::ledger::{LedgerStats, ObligationLedger, ObligationToken};
#[cfg(test)]
use crate::record::{ObligationAbortReason, ObligationKind};
#[cfg(test)]
use crate::types::{RegionId, TaskId, Time};

#[cfg(test)]
#[inline]
fn tid(n: u32) -> TaskId {
    // Helper: TaskId/RegionId expose `new_for_test(index, generation)`
    // (src/types/id.rs:297, 109) — there is no `new(u64)` constructor.
    // The metamorphic relations only need distinct IDs, so generation 0
    // suffices.
    TaskId::new_for_test(n, 0)
}

#[cfg(test)]
#[inline]
fn rid(n: u32) -> RegionId {
    RegionId::new_for_test(n, 0)
}

#[cfg(test)]
/// Represents a scheduled operation with its timing
#[derive(Debug, Clone)]
pub enum ScheduledOp {
    /// Acquire an obligation, returning a token
    Acquire {
        /// Obligation resource kind to acquire.
        kind: ObligationKind,
        /// Task that owns the acquired obligation.
        task: TaskId,
        /// Region that bounds the obligation lifecycle.
        region: RegionId,
        /// Logical acquisition time recorded in the ledger.
        time: Time,
    },
    /// Commit a previously acquired token (by acquire index)
    CommitByIndex {
        /// Index of the earlier acquire operation whose token should commit.
        acquire_index: usize,
        /// Logical commit time recorded in the ledger.
        time: Time,
    },
    /// Abort a previously acquired token (by acquire index)
    AbortByIndex {
        /// Index of the earlier acquire operation whose token should abort.
        acquire_index: usize,
        /// Abort reason recorded for the obligation.
        reason: ObligationAbortReason,
        /// Logical abort time recorded in the ledger.
        time: Time,
    },
    /// Mark a region as finalized (closed)
    FinalizeRegion {
        /// Region whose pending obligations should be finalized.
        region: RegionId,
    },
}

#[cfg(test)]
/// Execution context that executes a sequence of operations
#[derive(Debug)]
struct ExecutionContext {
    ledger: ObligationLedger,
    /// Tokens acquired by index in the operation sequence
    acquired_tokens: Vec<Option<ObligationToken>>,
}

#[cfg(test)]
impl ExecutionContext {
    fn new() -> Self {
        Self {
            ledger: ObligationLedger::new(),
            acquired_tokens: Vec::new(),
        }
    }

    fn execute(&mut self, ops: &[ScheduledOp]) -> LedgerStats {
        self.acquired_tokens.clear();
        // Work around ObligationToken not implementing Clone by storing indices instead
        self.acquired_tokens = (0..ops.len()).map(|_| None).collect();

        for (idx, op) in ops.iter().enumerate() {
            match op {
                ScheduledOp::Acquire {
                    kind,
                    task,
                    region,
                    time,
                } => {
                    let token = self.ledger.acquire(*kind, *task, *region, *time);
                    self.acquired_tokens[idx] = Some(token);
                }
                ScheduledOp::CommitByIndex {
                    acquire_index,
                    time,
                } => {
                    // ObligationToken is intentionally !Copy/!Clone (linear
                    // by design — see src/obligation/ledger.rs:108), so we
                    // must move the token out of the Option via `take()`
                    // rather than dereference it. After commit, the slot
                    // is left as None so a duplicate CommitByIndex /
                    // AbortByIndex on the same index becomes a no-op.
                    if let Some(slot) = self.acquired_tokens.get_mut(*acquire_index) {
                        if let Some(token) = slot.take() {
                            let _ = self.ledger.commit(token, *time);
                        }
                    }
                }
                ScheduledOp::AbortByIndex {
                    acquire_index,
                    reason,
                    time,
                } => {
                    if let Some(slot) = self.acquired_tokens.get_mut(*acquire_index) {
                        if let Some(token) = slot.take() {
                            let _ = self.ledger.abort(token, *time, *reason);
                        }
                    }
                }
                ScheduledOp::FinalizeRegion { region } => {
                    self.ledger.mark_region_finalized(*region);
                }
            }
        }

        self.ledger.stats()
    }
}

//
// METAMORPHIC RELATIONS
//

#[cfg(test)]
#[path = "metamorphic_tests_metamorphic_tests_inline_tests.rs"]
mod metamorphic_tests;
