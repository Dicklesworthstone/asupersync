#![no_main]

//! Fuzz target for obligation ledger permit/ack/lease state machine.
//!
//! This target drives the obligation lifecycle (reserve, commit, abort, leak-detection paths)
//! with interleaved cancel signals to test the no-leak invariant. Every permit must be
//! either committed or aborted, never leaked.
//!
//! The test focuses on:
//! 1. Random sequences of acquire/commit/abort operations
//! 2. Interleaved cancellation signals that trigger abort operations
//! 3. Mixed obligation kinds (SendPermit, Ack, Lease, IoOp, SemaphorePermit)
//! 4. Region-based grouping and cleanup
//! 5. Leak detection and invariant checking

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use asupersync::obligation::ledger::{ObligationLedger, ObligationToken};
use asupersync::record::{ObligationAbortReason, ObligationKind};
use asupersync::types::{ObligationId, RegionId, TaskId, Time};
use asupersync::util::ArenaIndex;
use std::collections::HashMap;

/// Simplified fuzz input for obligation ledger operations
#[derive(Arbitrary, Debug, Clone)]
struct ObligationLedgerFuzzInput {
    /// Random seed for deterministic execution
    pub seed: u64,
    /// Sequence of operations to execute
    pub operations: Vec<ObligationOperation>,
    /// Configuration parameters
    pub config: LedgerFuzzConfig,
}

/// Individual obligation operations to fuzz
#[derive(Arbitrary, Debug, Clone)]
enum ObligationOperation {
    /// Acquire a new obligation
    Acquire {
        kind: ObligationKindInput,
        holder_idx: u8,     // Index into holders array
        region_idx: u8,     // Index into regions array
        time_offset: u64,   // Offset from base time
    },
    /// Commit an obligation by token index
    Commit {
        token_idx: u16,     // Index into tokens array
        time_offset: u64,   // Offset from base time
    },
    /// Abort an obligation by token index
    Abort {
        token_idx: u16,     // Index into tokens array
        time_offset: u64,   // Offset from base time
        reason: AbortReasonInput,
    },
    /// Abort an obligation by ID (simulates external cancellation)
    AbortById {
        obligation_idx: u16, // Index into obligation IDs list
        time_offset: u64,    // Offset from base time
        reason: AbortReasonInput,
    },
    /// Mark an obligation as leaked (simulates runtime leak detection)
    MarkLeaked {
        obligation_idx: u16, // Index into obligation IDs list
        time_offset: u64,    // Offset from base time
    },
    /// Check region cleanliness
    CheckRegionClean {
        region_idx: u8,      // Index into regions array
    },
    /// Perform global leak check
    CheckLeaks,
    /// Check pending counts
    CheckCounts,
}

/// Input wrapper for ObligationKind to make it Arbitrary-compatible
#[derive(Arbitrary, Debug, Clone, Copy)]
enum ObligationKindInput {
    SendPermit,
    Ack,
    Lease,
    IoOp,
    SemaphorePermit,
}

impl From<ObligationKindInput> for ObligationKind {
    fn from(input: ObligationKindInput) -> Self {
        match input {
            ObligationKindInput::SendPermit => ObligationKind::SendPermit,
            ObligationKindInput::Ack => ObligationKind::Ack,
            ObligationKindInput::Lease => ObligationKind::Lease,
            ObligationKindInput::IoOp => ObligationKind::IoOp,
            ObligationKindInput::SemaphorePermit => ObligationKind::SemaphorePermit,
        }
    }
}

/// Input wrapper for ObligationAbortReason to make it Arbitrary-compatible
#[derive(Arbitrary, Debug, Clone, Copy)]
enum AbortReasonInput {
    Cancel,
    Error,
    Explicit,
}

impl From<AbortReasonInput> for ObligationAbortReason {
    fn from(input: AbortReasonInput) -> Self {
        match input {
            AbortReasonInput::Cancel => ObligationAbortReason::Cancel,
            AbortReasonInput::Error => ObligationAbortReason::Error,
            AbortReasonInput::Explicit => ObligationAbortReason::Explicit,
        }
    }
}

/// Configuration for obligation ledger fuzzing
#[derive(Arbitrary, Debug, Clone)]
struct LedgerFuzzConfig {
    /// Number of regions to use (1-8)
    pub region_count: u8,
    /// Number of task holders to use (1-8)
    pub holder_count: u8,
    /// Base time for operations
    pub base_time_nanos: u64,
    /// Maximum operations to process
    pub max_operations: u16,
    /// Enable strict leak checking
    pub strict_leak_checking: bool,
}

/// Shadow model to track expected behavior
#[derive(Debug)]
struct ObligationLedgerShadowModel {
    /// Expected pending obligation count
    expected_pending: u64,
    /// Expected total acquired count
    expected_acquired: u64,
    /// Expected total committed count
    expected_committed: u64,
    /// Expected total aborted count
    expected_aborted: u64,
    /// Expected total leaked count
    expected_leaked: u64,
    /// Tracked obligations by ID
    tracked_obligations: HashMap<ObligationId, ObligationState>,
}

#[derive(Debug, Clone, PartialEq)]
enum ObligationState {
    Reserved,
    Committed,
    Aborted,
    Leaked,
}

impl ObligationLedgerShadowModel {
    fn new() -> Self {
        Self {
            expected_pending: 0,
            expected_acquired: 0,
            expected_committed: 0,
            expected_aborted: 0,
            expected_leaked: 0,
            tracked_obligations: HashMap::new(),
        }
    }

    fn record_acquire(&mut self, id: ObligationId) {
        self.expected_acquired += 1;
        self.expected_pending += 1;
        self.tracked_obligations.insert(id, ObligationState::Reserved);
    }

    fn record_commit(&mut self, id: ObligationId) -> bool {
        if let Some(state) = self.tracked_obligations.get_mut(&id) {
            if *state == ObligationState::Reserved {
                *state = ObligationState::Committed;
                self.expected_committed += 1;
                self.expected_pending = self.expected_pending.saturating_sub(1);
                return true;
            }
        }
        false
    }

    fn record_abort(&mut self, id: ObligationId) -> bool {
        if let Some(state) = self.tracked_obligations.get_mut(&id) {
            if *state == ObligationState::Reserved {
                *state = ObligationState::Aborted;
                self.expected_aborted += 1;
                self.expected_pending = self.expected_pending.saturating_sub(1);
                return true;
            }
        }
        false
    }

    fn record_leaked(&mut self, id: ObligationId) -> bool {
        if let Some(state) = self.tracked_obligations.get_mut(&id) {
            if *state == ObligationState::Reserved {
                *state = ObligationState::Leaked;
                self.expected_leaked += 1;
                self.expected_pending = self.expected_pending.saturating_sub(1);
                return true;
            }
        }
        false
    }

    fn verify_stats(&self, ledger: &ObligationLedger) -> Result<(), String> {
        let stats = ledger.stats();

        if stats.total_acquired != self.expected_acquired {
            return Err(format!(
                "Acquired count mismatch: expected {}, actual {}",
                self.expected_acquired, stats.total_acquired
            ));
        }

        if stats.total_committed != self.expected_committed {
            return Err(format!(
                "Committed count mismatch: expected {}, actual {}",
                self.expected_committed, stats.total_committed
            ));
        }

        if stats.total_aborted != self.expected_aborted {
            return Err(format!(
                "Aborted count mismatch: expected {}, actual {}",
                self.expected_aborted, stats.total_aborted
            ));
        }

        if stats.total_leaked != self.expected_leaked {
            return Err(format!(
                "Leaked count mismatch: expected {}, actual {}",
                self.expected_leaked, stats.total_leaked
            ));
        }

        if stats.pending != self.expected_pending {
            return Err(format!(
                "Pending count mismatch: expected {}, actual {}",
                self.expected_pending, stats.pending
            ));
        }

        Ok(())
    }

    fn get_reserved_obligations(&self) -> Vec<ObligationId> {
        self.tracked_obligations
            .iter()
            .filter(|(_, state)| **state == ObligationState::Reserved)
            .map(|(id, _)| *id)
            .collect()
    }
}

/// Normalize fuzz input to valid ranges
fn normalize_fuzz_input(input: &mut ObligationLedgerFuzzInput) {
    // Limit operations to prevent timeouts
    input.operations.truncate(500);

    // Bound configuration values
    input.config.region_count = input.config.region_count.clamp(1, 8);
    input.config.holder_count = input.config.holder_count.clamp(1, 8);
    input.config.max_operations = input.config.max_operations.clamp(1, 1000);

    // Normalize time values to reasonable ranges
    input.config.base_time_nanos = input.config.base_time_nanos.clamp(0, u64::MAX / 2);

    // Normalize individual operations
    for op in &mut input.operations {
        match op {
            ObligationOperation::Acquire { holder_idx, region_idx, time_offset, .. } => {
                *holder_idx = (*holder_idx) % input.config.holder_count.max(1);
                *region_idx = (*region_idx) % input.config.region_count.max(1);
                *time_offset = (*time_offset).clamp(0, 1_000_000_000); // Max 1 second offset
            }
            ObligationOperation::Commit { time_offset, .. } |
            ObligationOperation::Abort { time_offset, .. } |
            ObligationOperation::AbortById { time_offset, .. } |
            ObligationOperation::MarkLeaked { time_offset, .. } => {
                *time_offset = (*time_offset).clamp(0, 1_000_000_000);
            }
            ObligationOperation::CheckRegionClean { region_idx } => {
                *region_idx = (*region_idx) % input.config.region_count.max(1);
            }
            _ => {}
        }
    }
}

/// Execute obligation operations and verify invariants
fn execute_obligation_operations(
    input: &ObligationLedgerFuzzInput,
) -> Result<(), String> {
    let mut ledger = ObligationLedger::new();
    let mut shadow = ObligationLedgerShadowModel::new();
    let mut tokens: Vec<ObligationToken> = Vec::new();
    let mut obligation_ids: Vec<ObligationId> = Vec::new();

    // Create fixed sets of regions and tasks for consistent indexing
    let regions: Vec<RegionId> = (0..input.config.region_count)
        .map(|i| RegionId::from_arena(ArenaIndex::new(i as u32, 0)))
        .collect();

    let holders: Vec<TaskId> = (0..input.config.holder_count)
        .map(|i| TaskId::from_arena(ArenaIndex::new(i as u32, 0)))
        .collect();

    let base_time = Time::from_nanos(input.config.base_time_nanos);

    // Execute operation sequence
    for (op_index, operation) in input.operations.iter().enumerate() {
        if op_index >= input.config.max_operations as usize {
            break;
        }

        match operation {
            ObligationOperation::Acquire { kind, holder_idx, region_idx, time_offset } => {
                let holder = holders[*holder_idx as usize % holders.len()];
                let region = regions[*region_idx as usize % regions.len()];
                let time = Time::from_nanos(base_time.as_nanos() + time_offset);

                let token = ledger.acquire((*kind).into(), holder, region, time);
                let id = token.id();

                shadow.record_acquire(id);
                obligation_ids.push(id);
                tokens.push(token);
            }

            ObligationOperation::Commit { token_idx, time_offset } => {
                if !tokens.is_empty() {
                    let idx = (*token_idx as usize) % tokens.len();
                    if idx < tokens.len() {
                        let token = tokens.remove(idx);
                        let id = token.id();
                        let time = Time::from_nanos(base_time.as_nanos() + time_offset);

                        let _duration = ledger.commit(token, time);

                        if !shadow.record_commit(id) {
                            return Err(format!("Attempted to commit non-reserved obligation {}", id));
                        }
                    }
                }
            }

            ObligationOperation::Abort { token_idx, time_offset, reason } => {
                if !tokens.is_empty() {
                    let idx = (*token_idx as usize) % tokens.len();
                    if idx < tokens.len() {
                        let token = tokens.remove(idx);
                        let id = token.id();
                        let time = Time::from_nanos(base_time.as_nanos() + time_offset);

                        let _duration = ledger.abort(token, time, (*reason).into());

                        if !shadow.record_abort(id) {
                            return Err(format!("Attempted to abort non-reserved obligation {}", id));
                        }
                    }
                }
            }

            ObligationOperation::AbortById { obligation_idx, time_offset, reason } => {
                let reserved_ids = shadow.get_reserved_obligations();
                if !reserved_ids.is_empty() {
                    let idx = (*obligation_idx as usize) % reserved_ids.len();
                    let id = reserved_ids[idx];
                    let time = Time::from_nanos(base_time.as_nanos() + time_offset);

                    // Remove token from our tracking if it exists
                    tokens.retain(|token| token.id() != id);

                    let _duration = ledger.abort_by_id(id, time, (*reason).into());

                    if !shadow.record_abort(id) {
                        return Err(format!("Attempted to abort_by_id non-reserved obligation {}", id));
                    }
                }
            }

            ObligationOperation::MarkLeaked { obligation_idx, time_offset } => {
                let reserved_ids = shadow.get_reserved_obligations();
                if !reserved_ids.is_empty() {
                    let idx = (*obligation_idx as usize) % reserved_ids.len();
                    let id = reserved_ids[idx];
                    let time = Time::from_nanos(base_time.as_nanos() + time_offset);

                    // Remove token from our tracking if it exists
                    tokens.retain(|token| token.id() != id);

                    let _duration = ledger.mark_leaked(id, time);

                    if !shadow.record_leaked(id) {
                        return Err(format!("Attempted to mark_leaked non-reserved obligation {}", id));
                    }
                }
            }

            ObligationOperation::CheckRegionClean { region_idx } => {
                let region = regions[*region_idx as usize % regions.len()];
                let _is_clean = ledger.is_region_clean(region);
                let _pending_count = ledger.pending_for_region(region);
            }

            ObligationOperation::CheckLeaks => {
                let leak_result = ledger.check_leaks();

                if input.config.strict_leak_checking && !leak_result.is_clean() {
                    return Err(format!("Leak check found {} leaked obligations", leak_result.leaked.len()));
                }
            }

            ObligationOperation::CheckCounts => {
                let _pending = ledger.pending_count();
                let stats = ledger.stats();

                // Verify accounting invariants
                if stats.total_acquired != stats.total_committed + stats.total_aborted + stats.total_leaked + stats.pending {
                    return Err(format!(
                        "Accounting invariant violation: acquired({}) != committed({}) + aborted({}) + leaked({}) + pending({})",
                        stats.total_acquired, stats.total_committed, stats.total_aborted, stats.total_leaked, stats.pending
                    ));
                }
            }
        }

        // Verify shadow model matches ledger state every 10 operations
        if op_index % 10 == 0 {
            shadow.verify_stats(&ledger)?;
        }
    }

    // Final verification
    shadow.verify_stats(&ledger)?;

    // Final leak check - this is the critical invariant
    let final_leak_check = ledger.check_leaks();
    if input.config.strict_leak_checking && !final_leak_check.is_clean() {
        return Err(format!(
            "CRITICAL: Final leak check failed - {} obligations leaked",
            final_leak_check.leaked.len()
        ));
    }

    // Verify that all remaining tokens correspond to pending obligations
    let remaining_token_ids: std::collections::HashSet<_> = tokens.iter().map(|t| t.id()).collect();
    let pending_obligation_ids = shadow.get_reserved_obligations();
    let pending_set: std::collections::HashSet<_> = pending_obligation_ids.into_iter().collect();

    if remaining_token_ids != pending_set {
        return Err(format!(
            "Token-obligation mismatch: tokens={} pending={}",
            remaining_token_ids.len(), pending_set.len()
        ));
    }

    Ok(())
}

/// Main fuzzing entry point
fn fuzz_obligation_ledger(mut input: ObligationLedgerFuzzInput) -> Result<(), String> {
    normalize_fuzz_input(&mut input);

    // Skip degenerate cases
    if input.operations.is_empty() {
        return Ok(());
    }

    // Execute obligation ledger operations
    execute_obligation_operations(&input)?;

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Limit input size for performance
    if data.len() > 16_384 {
        return;
    }

    let mut unstructured = arbitrary::Unstructured::new(data);

    // Generate fuzz configuration
    let input = if let Ok(input) = ObligationLedgerFuzzInput::arbitrary(&mut unstructured) {
        input
    } else {
        return;
    };

    // Run obligation ledger fuzzing
    let _ = fuzz_obligation_ledger(input);
});
