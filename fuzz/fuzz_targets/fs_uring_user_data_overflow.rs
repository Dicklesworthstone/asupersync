//! Fuzz target for src/fs/uring.rs user_data integer overflow and state corruption.
//!
//! **CRITICAL FOLLOW-UP**: Previous work fixed user_data collision between test constants
//! and production values. This fuzzer targets remaining vulnerabilities in the user_data
//! allocation and completion tracking system.
//!
//! **VULNERABILITY SURFACES**:
//! 1. next_user_data counter overflow: fetch_add(1) wraps after 2^64 operations
//! 2. sequence.max(1) collision: wrapped 0 becomes 1, conflicts with early operations
//! 3. OpKind decode failures: invalid values > 5 cause completion loss
//! 4. State machine corruption: completions for non-pending operations
//! 5. Double completion attacks: same user_data completed multiple times
//!
//! **ATTACK VECTORS**:
//! - Force counter overflow through massive operation submission
//! - Submit operations with crafted user_data values
//! - Test completion ordering and state transitions
//! - Verify OpKind encode/decode boundary conditions
//!
//! **ORACLE**: State consistency - operation states must be valid, no lost completions

#![no_main]
#![allow(clippy::too_many_lines)]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_OPERATIONS: usize = 1000; // Reasonable for exec/s
const USER_DATA_KIND_SHIFT: u32 = 56;
const USER_DATA_SEQUENCE_MASK: u64 = (1u64 << USER_DATA_KIND_SHIFT) - 1;

#[derive(Debug, Clone, Copy, Arbitrary, PartialEq, Eq)]
#[repr(u8)]
enum OpKind {
    Read = 1,
    Write = 2,
    Fsync = 3,
    Fdatasync = 4,
    Close = 5,
}

impl OpKind {
    fn encode(self, sequence: u64) -> u64 {
        (u64::from(self as u8) << USER_DATA_KIND_SHIFT) | (sequence & USER_DATA_SEQUENCE_MASK)
    }

    fn decode(user_data: u64) -> Option<Self> {
        match (user_data >> USER_DATA_KIND_SHIFT) as u8 {
            1 => Some(Self::Read),
            2 => Some(Self::Write),
            3 => Some(Self::Fsync),
            4 => Some(Self::Fdatasync),
            5 => Some(Self::Close),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum UserDataScenario {
    Normal,                    // Regular operation allocation
    NearOverflow,             // Counter near u64::MAX
    PostOverflow,             // Counter has wrapped around
    InvalidOpKind,            // OpKind values > 5
    ZeroSequence,             // Test sequence = 0 handling
    MaxSequence,              // Test sequence = u64::MAX
    CollidingValues,          // Deliberately colliding user_data
    MixedAllocation,          // Mix of normal + boundary scenarios
}

#[derive(Debug, Clone, Arbitrary)]
struct UserDataOperation {
    scenario: UserDataScenario,
    op_kind: OpKind,
    custom_sequence: Option<u64>,  // Override sequence for testing
    custom_user_data: Option<u64>, // Direct user_data for completion testing
    expect_decode_success: bool,
}

#[derive(Debug)]
struct MockUserDataAllocator {
    next_user_data: AtomicU64,
}

impl MockUserDataAllocator {
    fn new() -> Self {
        Self {
            next_user_data: AtomicU64::new(0),
        }
    }

    fn new_with_value(initial: u64) -> Self {
        Self {
            next_user_data: AtomicU64::new(initial),
        }
    }

    fn allocate_user_data(&self, kind: OpKind) -> u64 {
        let sequence = self.next_user_data.fetch_add(1, Ordering::Relaxed);
        kind.encode(sequence.max(1))
    }

    fn set_counter(&self, value: u64) {
        self.next_user_data.store(value, Ordering::Relaxed);
    }

    fn get_counter(&self) -> u64 {
        self.next_user_data.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
struct CompletionTracker {
    completed_operations: Vec<(u64, OpKind, i32)>, // user_data, kind, result
    failed_decodes: Vec<u64>,                      // user_data that failed decode
    duplicate_completions: Vec<u64>,               // user_data completed multiple times
}

impl CompletionTracker {
    fn new() -> Self {
        Self {
            completed_operations: Vec::new(),
            failed_decodes: Vec::new(),
            duplicate_completions: Vec::new(),
        }
    }

    fn process_completion(&mut self, user_data: u64, result: i32) -> bool {
        // Check if already completed (duplicate)
        if self.completed_operations.iter().any(|(ud, _, _)| *ud == user_data) {
            self.duplicate_completions.push(user_data);
            return false; // Duplicate completion
        }

        // Try to decode OpKind
        match OpKind::decode(user_data) {
            Some(kind) => {
                self.completed_operations.push((user_data, kind, result));
                true
            }
            None => {
                self.failed_decodes.push(user_data);
                false // Failed decode
            }
        }
    }

    fn get_stats(&self) -> CompletionStats {
        CompletionStats {
            successful_completions: self.completed_operations.len(),
            failed_decodes: self.failed_decodes.len(),
            duplicate_completions: self.duplicate_completions.len(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CompletionStats {
    successful_completions: usize,
    failed_decodes: usize,
    duplicate_completions: usize,
}

fn execute_scenario(allocator: &MockUserDataAllocator, scenario: UserDataScenario, op: &UserDataOperation) -> u64 {
    match scenario {
        UserDataScenario::Normal => {
            allocator.allocate_user_data(op.op_kind)
        }
        UserDataScenario::NearOverflow => {
            allocator.set_counter(u64::MAX - 100);
            allocator.allocate_user_data(op.op_kind)
        }
        UserDataScenario::PostOverflow => {
            allocator.set_counter(u64::MAX - 5);
            // Allocate a few to cause overflow
            for _ in 0..10 {
                let _ = allocator.allocate_user_data(op.op_kind);
            }
            // This allocation will have wrapped counter
            allocator.allocate_user_data(op.op_kind)
        }
        UserDataScenario::InvalidOpKind => {
            // Craft user_data with invalid OpKind (> 5)
            let sequence = op.custom_sequence.unwrap_or(42);
            let invalid_kind = 99u8; // Invalid OpKind
            (u64::from(invalid_kind) << USER_DATA_KIND_SHIFT) | (sequence & USER_DATA_SEQUENCE_MASK)
        }
        UserDataScenario::ZeroSequence => {
            // Test what happens when sequence is 0 (should become 1 via .max(1))
            let explicit_sequence = 0u64;
            op.op_kind.encode(explicit_sequence.max(1))
        }
        UserDataScenario::MaxSequence => {
            // Test maximum possible sequence value
            let max_sequence = USER_DATA_SEQUENCE_MASK;
            op.op_kind.encode(max_sequence)
        }
        UserDataScenario::CollidingValues => {
            // Create deliberately colliding user_data
            if let Some(custom) = op.custom_user_data {
                custom
            } else {
                // Use a common collision-prone value
                op.op_kind.encode(1) // This will collide with second-ever operation
            }
        }
        UserDataScenario::MixedAllocation => {
            // Start with near overflow, then do normal allocation
            allocator.set_counter(u64::MAX - 2);
            let _overflow = allocator.allocate_user_data(op.op_kind);
            allocator.allocate_user_data(op.op_kind) // This is post-overflow
        }
    }
}

fuzz_target!(|operations: Vec<UserDataOperation>| {
    if operations.len() > MAX_OPERATIONS {
        return;
    }

    let allocator = MockUserDataAllocator::new();
    let mut tracker = CompletionTracker::new();
    let mut allocated_user_data = Vec::new();

    // Phase 1: Allocate user_data values using various scenarios
    for operation in &operations {
        let user_data = execute_scenario(&allocator, operation.scenario, operation);
        allocated_user_data.push((user_data, operation.op_kind, operation.expect_decode_success));

        // Validate encoding/decoding consistency
        let decoded_kind = OpKind::decode(user_data);
        match (decoded_kind, operation.expect_decode_success) {
            (Some(decoded), true) => {
                // Should decode successfully
                assert_eq!(
                    decoded, operation.op_kind,
                    "OpKind encode/decode mismatch: expected {:?}, got {:?} for user_data 0x{:016x}",
                    operation.op_kind, decoded, user_data
                );
            }
            (None, false) => {
                // Expected decode failure - this is fine for invalid scenarios
            }
            (Some(_), false) => {
                // Unexpected successful decode
                panic!(
                    "DECODE INCONSISTENCY: Expected decode failure but got success for user_data 0x{:016x}",
                    user_data
                );
            }
            (None, true) => {
                // Unexpected decode failure
                panic!(
                    "DECODE FAILURE: Expected successful decode but failed for user_data 0x{:016x}, scenario: {:?}",
                    user_data, operation.scenario
                );
            }
        }
    }

    // Phase 2: Simulate completions and track state
    for (user_data, original_kind, should_decode) in &allocated_user_data {
        let completion_result = 42i32; // Mock completion result
        let processed = tracker.process_completion(*user_data, completion_result);

        if *should_decode && !processed {
            panic!(
                "COMPLETION PROCESSING FAILURE: user_data 0x{:016x} should have been processable",
                user_data
            );
        }
    }

    // Phase 3: Analyze results for vulnerabilities
    let stats = tracker.get_stats();

    // Check for completion loss (failed decodes when they should succeed)
    let expected_successful = allocated_user_data.iter()
        .filter(|(_, _, should_decode)| *should_decode)
        .count();

    if stats.successful_completions != expected_successful {
        panic!(
            "COMPLETION LOSS: Expected {} successful completions, got {}. Failed decodes: {}, Duplicates: {}",
            expected_successful, stats.successful_completions, stats.failed_decodes, stats.duplicate_completions
        );
    }

    // Check for duplicate completions (same user_data completed twice)
    if stats.duplicate_completions > 0 {
        panic!(
            "DUPLICATE COMPLETIONS: {} user_data values were completed multiple times",
            stats.duplicate_completions
        );
    }

    // Phase 4: Test overflow behavior specifically
    let initial_counter = allocator.get_counter();

    // Force counter to near overflow
    allocator.set_counter(u64::MAX - 5);
    let mut overflow_user_data = Vec::new();

    // Allocate operations that will cause overflow
    for i in 0..10 {
        let user_data = allocator.allocate_user_data(OpKind::Read);
        overflow_user_data.push(user_data);

        // Verify that wrapped values don't decode to None unexpectedly
        let decoded = OpKind::decode(user_data);
        if decoded.is_none() {
            panic!(
                "OVERFLOW DECODE FAILURE: user_data 0x{:016x} (iteration {}) failed to decode after counter overflow",
                user_data, i
            );
        }
    }

    // Check for collisions in post-overflow user_data
    overflow_user_data.sort_unstable();
    overflow_user_data.dedup();
    if overflow_user_data.len() != 10 {
        panic!(
            "OVERFLOW COLLISION: {} unique user_data values from 10 allocations (expected 10)",
            overflow_user_data.len()
        );
    }

    // Phase 5: Test sequence.max(1) behavior at overflow boundary
    allocator.set_counter(0); // Simulate post-overflow wrap to 0
    let zero_wrapped = allocator.allocate_user_data(OpKind::Write);

    allocator.set_counter(1); // Second operation ever
    let second_ever = allocator.allocate_user_data(OpKind::Write);

    if zero_wrapped == second_ever {
        panic!(
            "SEQUENCE COLLISION: Post-overflow allocation (0 -> 1) collides with second operation: 0x{:016x}",
            zero_wrapped
        );
    }

    // Restore counter for cleanup
    allocator.set_counter(initial_counter);
});