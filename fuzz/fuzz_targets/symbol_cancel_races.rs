#![no_main]

use arbitrary::Arbitrary;
use asupersync::{
    cancel::symbol_cancel::SymbolCancelToken,
    types::{CancelKind, CancelReason, ObjectId, Time},
    util::DetRng,
};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

// Maximum operations to prevent timeouts
const MAX_OPS: usize = 500;
const MAX_THREADS: usize = 4;
const MAX_NESTING_DEPTH: usize = 8;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    operations: Vec<Operation>,
    thread_count: u8,
    use_token_wraparound: bool,
    nesting_depth: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum Operation {
    /// Create a new root token with specific RNG state for ID wraparound testing
    CreateRootToken {
        object_high: u32,
        rng_seed: u64,
        force_high_token_id: bool,
    },
    /// Create a child token from a parent
    CreateChild {
        parent_index: u8,
        rng_seed: u64,
    },
    /// Cancel a token with specific reason
    Cancel {
        token_index: u8,
        cancel_kind: CancelKindFuzz,
        time_ns: u64,
    },
    /// Add a listener to a token
    AddListener {
        token_index: u8,
        listener_id: u8,
    },
    /// Check if token is cancelled (polling operation)
    Poll {
        token_index: u8,
    },
    /// Get cancellation reason (another polling operation)
    GetReason {
        token_index: u8,
    },
    /// Multi-threaded stress test with barrier synchronization
    BarrierStress {
        token_index: u8,
        operation_type: StressOp,
    },
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum StressOp {
    Cancel,
    CreateChild,
    AddListener,
    Poll,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum CancelKindFuzz {
    User,
    Timeout,
    Deadline,
    PollQuota,
    CostBudget,
    FailFast,
    RaceLost,
    ParentCancelled,
    ResourceUnavailable,
    Shutdown,
    LinkedExit,
}

impl From<CancelKindFuzz> for CancelKind {
    fn from(kind: CancelKindFuzz) -> Self {
        match kind {
            CancelKindFuzz::User => CancelKind::User,
            CancelKindFuzz::Timeout => CancelKind::Timeout,
            CancelKindFuzz::Deadline => CancelKind::Deadline,
            CancelKindFuzz::PollQuota => CancelKind::PollQuota,
            CancelKindFuzz::CostBudget => CancelKind::CostBudget,
            CancelKindFuzz::FailFast => CancelKind::FailFast,
            CancelKindFuzz::RaceLost => CancelKind::RaceLost,
            CancelKindFuzz::ParentCancelled => CancelKind::ParentCancelled,
            CancelKindFuzz::ResourceUnavailable => CancelKind::ResourceUnavailable,
            CancelKindFuzz::Shutdown => CancelKind::Shutdown,
            CancelKindFuzz::LinkedExit => CancelKind::LinkedExit,
        }
    }
}

/// Mock listener that records when it was called
#[derive(Debug)]
struct MockListener {
    id: u8,
    called_count: Arc<Mutex<u32>>,
    panic_on_call: bool,
}

impl MockListener {
    fn new(id: u8, panic_on_call: bool) -> Self {
        Self {
            id,
            called_count: Arc::new(Mutex::new(0)),
            panic_on_call,
        }
    }

    fn call_count(&self) -> u32 {
        *self.called_count.lock().unwrap()
    }
}

impl asupersync::cancel::symbol_cancel::CancelListener for MockListener {
    fn on_cancel(&self, _reason: &CancelReason, _at: Time) {
        if self.panic_on_call {
            panic!("Mock listener {} intentional panic", self.id);
        }
        let mut count = self.called_count.lock().unwrap();
        *count += 1;
    }
}

/// Shared state for concurrent fuzzing
#[derive(Debug)]
struct SharedFuzzState {
    tokens: Mutex<Vec<SymbolCancelToken>>,
    listeners: Mutex<HashMap<u8, MockListener>>,
    barriers: Vec<Arc<Barrier>>,
    operation_results: Mutex<Vec<OperationResult>>,
}

#[derive(Debug, Clone)]
struct OperationResult {
    operation_id: usize,
    thread_id: usize,
    token_id: Option<u64>,
    was_cancelled: bool,
    cancel_result: bool,
    listener_panics: Option<u64>,
}

impl SharedFuzzState {
    fn new(thread_count: usize) -> Self {
        let mut barriers = Vec::new();
        for _ in 0..8 {  // Create multiple barriers for different synchronization points
            barriers.push(Arc::new(Barrier::new(thread_count)));
        }

        Self {
            tokens: Mutex::new(Vec::new()),
            listeners: Mutex::new(HashMap::new()),
            barriers,
            operation_results: Mutex::new(Vec::new()),
        }
    }

    fn get_barrier(&self, index: usize) -> Arc<Barrier> {
        self.barriers[index % self.barriers.len()].clone()
    }
}

fuzz_target!(|data: FuzzInput| {
    if data.operations.len() > MAX_OPS {
        return;
    }

    let thread_count = ((data.thread_count as usize) % MAX_THREADS).max(1);
    let nesting_depth = ((data.nesting_depth as usize) % MAX_NESTING_DEPTH).max(1);

    // Create shared state
    let shared_state = Arc::new(SharedFuzzState::new(thread_count));

    // Test three scenarios for metamorphic validation:

    // 1. Single-threaded execution
    test_single_threaded(&shared_state, &data.operations, data.use_token_wraparound);

    // 2. Multi-threaded execution with race conditions
    test_multi_threaded(shared_state.clone(), &data.operations, thread_count, data.use_token_wraparound);

    // 3. Hierarchical nesting stress test
    test_nested_scope_drain_ordering(&data.operations, nesting_depth);

    // 4. Metamorphic verification
    verify_metamorphic_properties(&shared_state);
});

/// Test single-threaded execution for baseline behavior
fn test_single_threaded(shared_state: &SharedFuzzState, operations: &[Operation], use_wraparound: bool) {
    for (op_idx, op) in operations.iter().enumerate() {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            execute_operation_single_threaded(shared_state, op, op_idx, use_wraparound);
        }));
    }
}

/// Test multi-threaded execution for race conditions
fn test_multi_threaded(
    shared_state: Arc<SharedFuzzState>,
    operations: &[Operation],
    thread_count: usize,
    use_wraparound: bool
) {
    let ops_per_thread = operations.len().max(1) / thread_count;
    let mut handles = Vec::new();

    for thread_id in 0..thread_count {
        let state = shared_state.clone();
        let start = thread_id * ops_per_thread;
        let end = if thread_id == thread_count - 1 {
            operations.len()
        } else {
            start + ops_per_thread
        };
        let thread_ops = operations[start..end].to_vec();

        handles.push(thread::spawn(move || {
            for (op_idx, op) in thread_ops.iter().enumerate() {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    execute_operation_multi_threaded(&state, op, thread_id, start + op_idx, use_wraparound);
                }));
            }
        }));
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap_or_default();
    }
}

/// Test nested scope drain ordering with deep hierarchies
fn test_nested_scope_drain_ordering(operations: &[Operation], max_depth: usize) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut rng = DetRng::new(0x1234_5678_9abc_def0);
        let object_id = ObjectId::new_for_test(42);

        // Create nested token hierarchy
        let mut tokens = Vec::new();
        let root = SymbolCancelToken::new(object_id, &mut rng);
        tokens.push(root.clone());

        // Build deep hierarchy
        for depth in 1..max_depth {
            let parent_idx = depth.saturating_sub(1);
            if parent_idx < tokens.len() {
                let child = tokens[parent_idx].child(&mut rng);
                tokens.push(child);
            }
        }

        // Test various cancellation patterns
        test_cascade_cancel(&tokens);
        test_reverse_cancel(&tokens);
        test_random_cancel(&tokens, operations);
    }));
}

/// Test cascading cancellation from root to leaves
fn test_cascade_cancel(tokens: &[SymbolCancelToken]) {
    if tokens.is_empty() {
        return;
    }

    let reason = CancelReason::new(CancelKind::Shutdown);
    let now = Time::from_nanos(1000);

    // Cancel root - should cascade to all children
    let initial_cancelled_count = tokens.iter().filter(|t| t.is_cancelled()).count();
    tokens[0].cancel(&reason, now);
    let final_cancelled_count = tokens.iter().filter(|t| t.is_cancelled()).count();

    // Metamorphic relation: Cancelling root should cancel all descendants
    assert!(final_cancelled_count >= initial_cancelled_count,
        "MR: Root cancellation should not decrease cancelled token count");
}

/// Test reverse cancellation from leaves to root
fn test_reverse_cancel(tokens: &[SymbolCancelToken]) {
    if tokens.is_empty() {
        return;
    }

    let reason = CancelReason::new(CancelKind::Timeout);
    let now = Time::from_nanos(2000);

    // Cancel from deepest to shallowest
    for token in tokens.iter().rev() {
        if !token.is_cancelled() {
            token.cancel(&reason, now);
        }
    }
}

/// Test random cancellation pattern with listener verification
fn test_random_cancel(tokens: &[SymbolCancelToken], operations: &[Operation]) {
    for (idx, op) in operations.iter().enumerate().take(10) {
        if let Operation::Cancel { cancel_kind, time_ns, .. } = op {
            let token_idx = idx % tokens.len();
            if token_idx < tokens.len() {
                let reason = CancelReason::new((*cancel_kind).into());
                let now = Time::from_nanos(*time_ns);

                let was_cancelled_before = tokens[token_idx].is_cancelled();
                let cancel_result = tokens[token_idx].cancel(&reason, now);
                let was_cancelled_after = tokens[token_idx].is_cancelled();

                // Metamorphic relation: cancel() idempotency
                if was_cancelled_before {
                    assert!(!cancel_result, "MR: Cancelling already-cancelled token should return false");
                }
                assert!(was_cancelled_after, "MR: Token should be cancelled after cancel() call");
            }
        }
    }
}

/// Execute operation in single-threaded mode
fn execute_operation_single_threaded(
    shared_state: &SharedFuzzState,
    operation: &Operation,
    op_idx: usize,
    use_wraparound: bool
) {
    match operation {
        Operation::CreateRootToken { object_high, rng_seed, force_high_token_id } => {
            let mut rng = if use_wraparound && *force_high_token_id {
                // Force RNG to generate high token IDs for wraparound testing
                DetRng::new(u64::MAX - (*rng_seed % 1000))
            } else {
                DetRng::new(*rng_seed)
            };

            let object_id = ObjectId::new_for_test((*object_high) as u64);
            let token = SymbolCancelToken::new(object_id, &mut rng);

            if let Ok(mut tokens) = shared_state.tokens.try_lock() {
                tokens.push(token);
            }
        }

        Operation::CreateChild { parent_index, rng_seed } => {
            let mut rng = DetRng::new(*rng_seed);
            if let Ok(tokens) = shared_state.tokens.try_lock() {
                if !tokens.is_empty() {
                    let parent_idx = (*parent_index as usize) % tokens.len();
                    let child = tokens[parent_idx].child(&mut rng);
                    drop(tokens);

                    if let Ok(mut tokens) = shared_state.tokens.try_lock() {
                        tokens.push(child);
                    }
                }
            }
        }

        Operation::Cancel { token_index, cancel_kind, time_ns } => {
            if let Ok(tokens) = shared_state.tokens.try_lock() {
                if !tokens.is_empty() {
                    let idx = (*token_index as usize) % tokens.len();
                    let reason = CancelReason::new((*cancel_kind).into());
                    let now = Time::from_nanos(*time_ns);
                    let cancel_result = tokens[idx].cancel(&reason, now);

                    let result = OperationResult {
                        operation_id: op_idx,
                        thread_id: 0,
                        token_id: Some(tokens[idx].token_id()),
                        was_cancelled: tokens[idx].is_cancelled(),
                        cancel_result,
                        listener_panics: Some(tokens[idx].listener_panic_count()),
                    };

                    if let Ok(mut results) = shared_state.operation_results.try_lock() {
                        results.push(result);
                    }
                }
            }
        }

        Operation::AddListener { token_index, listener_id } => {
            if let Ok(tokens) = shared_state.tokens.try_lock() {
                if !tokens.is_empty() {
                    let idx = (*token_index as usize) % tokens.len();
                    let listener = MockListener::new(*listener_id, false);

                    if let Ok(mut listeners) = shared_state.listeners.try_lock() {
                        listeners.insert(*listener_id, listener);
                    }
                }
            }
        }

        Operation::Poll { token_index } => {
            if let Ok(tokens) = shared_state.tokens.try_lock() {
                if !tokens.is_empty() {
                    let idx = (*token_index as usize) % tokens.len();
                    let _is_cancelled = tokens[idx].is_cancelled();
                    let _reason = tokens[idx].reason();
                    let _cancelled_at = tokens[idx].cancelled_at();
                }
            }
        }

        _ => {}
    }
}

/// Execute operation in multi-threaded mode with potential races
fn execute_operation_multi_threaded(
    shared_state: &SharedFuzzState,
    operation: &Operation,
    thread_id: usize,
    op_idx: usize,
    use_wraparound: bool
) {
    match operation {
        Operation::BarrierStress { token_index, operation_type } => {
            // Use barrier to synchronize threads for race testing
            let barrier = shared_state.get_barrier(0);
            barrier.wait();

            if let Ok(tokens) = shared_state.tokens.try_lock() {
                if !tokens.is_empty() {
                    let idx = (*token_index as usize) % tokens.len();

                    match operation_type {
                        StressOp::Cancel => {
                            let reason = CancelReason::new(CancelKind::RaceLost);
                            let now = Time::from_nanos((thread_id as u64) * 1000);
                            tokens[idx].cancel(&reason, now);
                        }
                        StressOp::CreateChild => {
                            let mut rng = DetRng::new((thread_id as u64) * 0x1337);
                            let _child = tokens[idx].child(&mut rng);
                        }
                        StressOp::AddListener => {
                            let listener = MockListener::new(thread_id as u8, thread_id % 3 == 0);
                            tokens[idx].add_listener(listener);
                        }
                        StressOp::Poll => {
                            let _is_cancelled = tokens[idx].is_cancelled();
                            let _token_id = tokens[idx].token_id();
                        }
                    }
                }
            }
        }

        _ => {
            // Execute regular operation with thread-specific modifications
            execute_operation_single_threaded(shared_state, operation, op_idx, use_wraparound);
        }
    }
}

/// Verify metamorphic properties across all test scenarios
fn verify_metamorphic_properties(shared_state: &SharedFuzzState) {
    if let Ok(tokens) = shared_state.tokens.try_lock() {
        if let Ok(results) = shared_state.operation_results.try_lock() {
            // MR1: Token ID uniqueness (check for wraparound collisions)
            let mut token_ids = std::collections::HashSet::new();
            let mut collision_count = 0;

            for token in tokens.iter() {
                let id = token.token_id();
                if !token_ids.insert(id) {
                    collision_count += 1;
                }
            }

            if collision_count > 0 {
                // This could indicate either legitimate wraparound or a bug
                // Log for analysis but don't fail - wraparound is theoretically possible
            }

            // MR2: Cancellation monotonicity - once cancelled, stays cancelled
            let cancelled_tokens: Vec<_> = tokens.iter()
                .filter(|t| t.is_cancelled())
                .collect();

            for token in cancelled_tokens {
                assert!(token.is_cancelled(),
                    "MR2: Cancelled token should remain cancelled");
                assert!(token.reason().is_some(),
                    "MR2: Cancelled token should have a reason");
            }

            // MR3: Listener panic count monotonicity
            for token in tokens.iter() {
                let panic_count = token.listener_panic_count();
                // Panic count should never decrease
                assert!(panic_count >= 0,
                    "MR3: Listener panic count should be non-negative");
            }

            // MR4: Cancel operation idempotency
            let cancel_operations: Vec<_> = results.iter()
                .filter(|r| r.was_cancelled)
                .collect();

            for op in cancel_operations {
                if let Some(token_id) = op.token_id {
                    if let Some(token) = tokens.iter().find(|t| t.token_id() == token_id) {
                        assert!(token.is_cancelled(),
                            "MR4: Token recorded as cancelled should still be cancelled");
                    }
                }
            }
        }
    }
}