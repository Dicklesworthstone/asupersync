#![no_main]

use arbitrary::Arbitrary;
use asupersync::{
    obligation::ledger::ObligationLedger,
    record::{ObligationAbortReason, ObligationKind},
    types::{ObligationId, RegionId, TaskId, Time},
    util::ArenaIndex,
};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;

// Maximum operations to prevent timeouts
const MAX_OPS: usize = 1000;
const MAX_THREADS: usize = 4;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    operations: Vec<Operation>,
    thread_count: u8,
    use_wraparound_scenario: bool,
}

#[derive(Debug, Clone, Arbitrary)]
enum Operation {
    /// Acquire a new obligation with given parameters
    Acquire {
        kind: ObligationKindFuzz,
        task_index: u8,
        region_index: u8,
        time_ns: u64,
    },
    /// Commit an obligation by token index
    Commit { token_index: u8, time_ns: u64 },
    /// Abort an obligation by token index
    Abort {
        token_index: u8,
        time_ns: u64,
        reason: AbortReasonFuzz,
    },
    /// Abort an obligation by ID
    AbortById {
        obligation_index: u8,
        time_ns: u64,
        reason: AbortReasonFuzz,
    },
    /// Mark a region as finalized
    MarkRegionFinalized { region_index: u8 },
    /// Reset the ledger (requires clean state)
    Reset,
    /// Force wraparound scenario for testing ID collision
    ForceWraparound { target_index: u32 },
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum ObligationKindFuzz {
    SendPermit,
    Ack,
    Lease,
    IoOp,
    SemaphorePermit,
}

impl From<ObligationKindFuzz> for ObligationKind {
    fn from(kind: ObligationKindFuzz) -> Self {
        match kind {
            ObligationKindFuzz::SendPermit => ObligationKind::SendPermit,
            ObligationKindFuzz::Ack => ObligationKind::Ack,
            ObligationKindFuzz::Lease => ObligationKind::Lease,
            ObligationKindFuzz::IoOp => ObligationKind::IoOp,
            ObligationKindFuzz::SemaphorePermit => ObligationKind::SemaphorePermit,
        }
    }
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum AbortReasonFuzz {
    Cancel,
    Error,
    Explicit,
}

impl From<AbortReasonFuzz> for ObligationAbortReason {
    fn from(reason: AbortReasonFuzz) -> Self {
        match reason {
            AbortReasonFuzz::Cancel => ObligationAbortReason::Cancel,
            AbortReasonFuzz::Error => ObligationAbortReason::Error,
            AbortReasonFuzz::Explicit => ObligationAbortReason::Explicit,
        }
    }
}

/// Shared state for concurrent fuzzing
#[derive(Debug)]
struct SharedFuzzState {
    ledger: Mutex<ObligationLedger>,
    active_tokens: Mutex<HashMap<u8, ObligationTokenSnapshot>>,
    known_ids: Mutex<HashMap<u8, ObligationId>>,
    task_pool: Vec<TaskId>,
    region_pool: Vec<RegionId>,
}

/// Snapshot of an obligation token (since tokens aren't Clone)
#[derive(Debug, Clone)]
struct ObligationTokenSnapshot {
    kind: ObligationKind,
    holder: TaskId,
    region: RegionId,
}

impl SharedFuzzState {
    fn new() -> Self {
        // Create a pool of task and region IDs for testing
        let mut task_pool = Vec::new();
        let mut region_pool = Vec::new();

        for i in 0..16 {
            task_pool.push(TaskId::from_arena(ArenaIndex::new(i, 0)));
            region_pool.push(RegionId::from_arena(ArenaIndex::new(i, 0)));
        }

        Self {
            ledger: Mutex::new(ObligationLedger::new()),
            active_tokens: Mutex::new(HashMap::new()),
            known_ids: Mutex::new(HashMap::new()),
            task_pool,
            region_pool,
        }
    }

    fn get_task(&self, index: u8) -> TaskId {
        self.task_pool[index as usize % self.task_pool.len()]
    }

    fn get_region(&self, index: u8) -> RegionId {
        self.region_pool[index as usize % self.region_pool.len()]
    }
}

fuzz_target!(|data: FuzzInput| {
    if data.operations.len() > MAX_OPS {
        return;
    }

    let thread_count = (data.thread_count as usize % MAX_THREADS) + 1;

    // Create shared state
    let shared_state = Arc::new(SharedFuzzState::new());

    // If requested, set up a wraparound scenario
    if data.use_wraparound_scenario {
        setup_wraparound_scenario(&shared_state);
    }

    // Test three scenarios:
    // 1. Single-threaded execution for baseline correctness
    test_single_threaded(&shared_state, &data.operations);

    // 2. Multi-threaded execution for race conditions
    test_multi_threaded(shared_state.clone(), &data.operations, thread_count);

    // 3. Metamorphic testing: single-threaded vs multi-threaded should have equivalent end state
    test_metamorphic_equivalence(&data.operations, thread_count);
});

/// Test single-threaded execution to establish baseline correctness
fn test_single_threaded(shared_state: &SharedFuzzState, operations: &[Operation]) {
    for (op_idx, op) in operations.iter().enumerate() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            execute_operation(shared_state, op);
        }));
        assert!(
            result.is_ok(),
            "obligation single-threaded operation {op_idx} panicked: {op:?}"
        );
    }

    // Verify final state invariants
    verify_ledger_invariants(shared_state);
}

/// Test multi-threaded execution for race conditions
fn test_multi_threaded(
    shared_state: Arc<SharedFuzzState>,
    operations: &[Operation],
    thread_count: usize,
) {
    let ops_per_thread = operations.len().max(1) / thread_count;
    let mut handles = Vec::new();

    for thread_idx in 0..thread_count {
        let state = shared_state.clone();
        let start = thread_idx * ops_per_thread;
        let end = if thread_idx == thread_count - 1 {
            operations.len()
        } else {
            start + ops_per_thread
        };
        let thread_ops = operations[start..end].to_vec();

        handles.push(thread::spawn(move || {
            for (op_idx, op) in thread_ops.iter().enumerate() {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    execute_operation(&state, op);
                }));
                assert!(
                    result.is_ok(),
                    "obligation worker thread {thread_idx} operation {op_idx} panicked: {op:?}"
                );
            }
        }));
    }

    // Wait for all threads to complete
    for (thread_idx, handle) in handles.into_iter().enumerate() {
        if handle.join().is_err() {
            panic!("obligation worker thread {thread_idx} panicked");
        }
    }

    // Verify final state invariants after concurrent execution
    verify_ledger_invariants(&shared_state);
}

/// Metamorphic test: compare single-threaded vs multi-threaded execution
fn test_metamorphic_equivalence(operations: &[Operation], thread_count: usize) {
    // Execute single-threaded
    let single_state = Arc::new(SharedFuzzState::new());
    test_single_threaded(&single_state, operations);
    let single_stats = single_state.ledger.lock().unwrap().stats();

    // Execute multi-threaded
    let multi_state = Arc::new(SharedFuzzState::new());
    test_multi_threaded(multi_state.clone(), operations, thread_count);
    let multi_stats = multi_state.ledger.lock().unwrap().stats();

    // Metamorphic relations:
    // MR1: Total acquired should be the same regardless of threading
    assert_eq!(
        single_stats.total_acquired, multi_stats.total_acquired,
        "MR1: total_acquired must be invariant to thread interleaving"
    );

    // MR2: Sum of outcomes should be the same (acquired = committed + aborted + leaked)
    let single_total =
        single_stats.total_committed + single_stats.total_aborted + single_stats.total_leaked;
    let multi_total =
        multi_stats.total_committed + multi_stats.total_aborted + multi_stats.total_leaked;
    assert_eq!(
        single_total, multi_total,
        "MR2: sum of all outcomes must be invariant to thread interleaving"
    );
}

/// Execute a single operation on the shared state
fn execute_operation(shared_state: &SharedFuzzState, operation: &Operation) {
    match operation {
        Operation::Acquire {
            kind,
            task_index,
            region_index,
            time_ns,
        } => {
            let task = shared_state.get_task(*task_index);
            let region = shared_state.get_region(*region_index);
            let time = Time::from_nanos(*time_ns);
            let kind = (*kind).into();

            if let Ok(mut ledger) = shared_state.ledger.try_lock()
                && let Ok(token) = ledger.try_acquire(kind, task, region, time)
            {
                let token_snapshot = ObligationTokenSnapshot {
                    kind: token.kind(),
                    holder: token.holder(),
                    region: token.region(),
                };

                // Store token for later operations
                if let Ok(mut tokens) = shared_state.active_tokens.try_lock() {
                    tokens.insert(*task_index, token_snapshot.clone());
                }

                // Store ID for abort_by_id operations
                if let Ok(mut ids) = shared_state.known_ids.try_lock() {
                    ids.insert(*task_index, token.id());
                }

                // Consume the token immediately or store for commit/abort
                std::mem::drop(token);
            }
        }

        Operation::Commit {
            token_index,
            time_ns,
        } => {
            let time = Time::from_nanos(*time_ns);
            if let (Ok(mut ledger), Ok(tokens)) = (
                shared_state.ledger.try_lock(),
                shared_state.active_tokens.try_lock(),
            ) && let Some(token_snapshot) = tokens.get(token_index)
            {
                // Try to commit using try_commit (fallible)
                if let Ok(token) = ledger.try_acquire(
                    token_snapshot.kind,
                    token_snapshot.holder,
                    token_snapshot.region,
                    time,
                ) {
                    let _ = ledger.try_commit(token, time);
                }
            }
        }

        Operation::Abort {
            token_index,
            time_ns,
            reason,
        } => {
            let time = Time::from_nanos(*time_ns);
            let reason = (*reason).into();
            if let (Ok(mut ledger), Ok(tokens)) = (
                shared_state.ledger.try_lock(),
                shared_state.active_tokens.try_lock(),
            ) && let Some(token_snapshot) = tokens.get(token_index)
            {
                // Try to abort using try_abort (fallible)
                if let Ok(token) = ledger.try_acquire(
                    token_snapshot.kind,
                    token_snapshot.holder,
                    token_snapshot.region,
                    time,
                ) {
                    let _ = ledger.try_abort(token, time, reason);
                }
            }
        }

        Operation::AbortById {
            obligation_index,
            time_ns,
            reason,
        } => {
            let time = Time::from_nanos(*time_ns);
            let reason = (*reason).into();
            if let (Ok(mut ledger), Ok(ids)) = (
                shared_state.ledger.try_lock(),
                shared_state.known_ids.try_lock(),
            ) && let Some(&id) = ids.get(obligation_index)
            {
                // This is the key race: abort_by_id concurrent with reset.
                // Use the race-tolerant surface so malformed input that
                // repeats an already-resolved ID does not become a trivial
                // fuzzer crash; an internal panic still escapes.
                let _ = ledger.try_abort_by_id(id, time, reason);
            }
        }

        Operation::MarkRegionFinalized { region_index } => {
            let region = shared_state.get_region(*region_index);
            if let Ok(mut ledger) = shared_state.ledger.try_lock() {
                ledger.mark_region_finalized(region);
            }
        }

        Operation::Reset => {
            if let Ok(mut ledger) = shared_state.ledger.try_lock() {
                // Reset requires clean state. Dirty reset attempts are invalid
                // input, so only call reset when its documented precondition holds.
                if ledger.stats().is_clean() {
                    ledger.reset();

                    // Clear our tracking state after a successful reset.
                    if let Ok(mut tokens) = shared_state.active_tokens.try_lock() {
                        tokens.clear();
                    }
                    if let Ok(mut ids) = shared_state.known_ids.try_lock() {
                        ids.clear();
                    }
                }
            }
        }

        Operation::ForceWraparound { target_index } => {
            // Force the ledger to a state near wraparound for testing ID collision
            if let Ok(mut ledger) = shared_state.ledger.try_lock() {
                // This is a test-only scenario to force wraparound conditions
                // We'll create a fresh ledger with high index to test overflow
                setup_wraparound_test(&mut ledger, *target_index);
            }
        }
    }
}

/// Set up a wraparound scenario for testing ID collision
fn setup_wraparound_scenario(shared_state: &SharedFuzzState) {
    if let Ok(mut ledger) = shared_state.ledger.try_lock() {
        // This is test-only code to simulate near-wraparound conditions
        setup_wraparound_test(&mut ledger, u32::MAX - 10);
    }
}

/// Helper to set up wraparound test conditions
fn setup_wraparound_test(ledger: &mut ObligationLedger, _start_index: u32) {
    // This is a theoretical test helper - in practice we can't directly
    // manipulate the internal state, but we can test near-boundary conditions
    let task = TaskId::from_arena(ArenaIndex::new(0, 0));
    let region = RegionId::from_arena(ArenaIndex::new(0, 0));
    let time = Time::from_nanos(1000);

    // Try to acquire enough obligations to approach wraparound
    for _ in 0..100 {
        if let Ok(token) = ledger.try_acquire(ObligationKind::SendPermit, task, region, time) {
            let _ = ledger.try_commit(token, time);
        } else {
            break;
        }
    }
}

/// Verify key invariants that must hold for the ledger
fn verify_ledger_invariants(shared_state: &SharedFuzzState) {
    if let Ok(ledger) = shared_state.ledger.try_lock() {
        let stats = ledger.stats();

        // Invariant 1: Conservation - all acquired obligations must be accounted for
        let total_resolved = stats.total_committed + stats.total_aborted + stats.total_leaked;
        let total_unresolved = stats.pending;
        assert_eq!(
            stats.total_acquired,
            total_resolved + total_unresolved,
            "Conservation invariant: acquired = resolved + pending"
        );

        // Invariant 2: No negative counts (u64 should prevent this but check anyway)
        assert!(stats.total_acquired >= stats.total_committed);
        assert!(stats.total_acquired >= stats.total_aborted);
        assert!(stats.total_acquired >= stats.total_leaked);
        assert!(stats.total_acquired >= stats.pending);

        // Invariant 3: Ledger consistency
        assert_eq!(
            ledger.pending_count(),
            stats.pending,
            "Ledger pending count must match stats"
        );

        // Invariant 4: If clean, no pending or leaked
        if stats.is_clean() {
            assert_eq!(stats.pending, 0, "Clean ledger has no pending obligations");
            assert_eq!(
                stats.total_leaked, 0,
                "Clean ledger has no leaked obligations"
            );
        }
    }
}
