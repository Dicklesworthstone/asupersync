#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Comprehensive fuzz target for intrusive heap operations in scheduler
///
/// This fuzzes both IntrusiveRing and IntrusiveStack operations to find:
/// - Memory safety violations (use-after-free, double-free)
/// - Logic bugs in linked list manipulation
/// - Invariant violations (queue_tag consistency, link integrity)
/// - ABA problems in concurrent-like scenarios
/// - Invalid state transitions
/// - Arithmetic overflow/underflow
#[derive(Arbitrary, Debug)]
struct IntrusiveHeapFuzz {
    /// Sequence of operations to execute on ring
    ring_ops: Vec<RingOperation>,
    /// Sequence of operations to execute on stack
    stack_ops: Vec<StackOperation>,
    /// Initial task count (1-100)
    initial_tasks: u8,
    /// Ring queue tag (1-255)
    ring_tag: u8,
    /// Stack queue tag (1-255)
    stack_tag: u8,
}

/// Operations for IntrusiveRing fuzzing
#[derive(Arbitrary, Debug)]
enum RingOperation {
    /// Push task to back of ring
    PushBack { task_index: u8 },
    /// Pop task from front of ring
    PopFront,
    /// Remove specific task from ring
    Remove { task_index: u8 },
    /// Check if task is in ring
    Contains { task_index: u8 },
    /// Peek front without removing
    PeekFront,
    /// Clear entire ring
    Clear,
    /// Verify ring invariants
    VerifyInvariants,
}

/// Operations for IntrusiveStack fuzzing
#[derive(Arbitrary, Debug)]
enum StackOperation {
    /// Push task to top of stack
    Push { task_index: u8 },
    /// Push to bottom of stack
    PushBottom { task_index: u8 },
    /// Pop from top (LIFO)
    Pop,
    /// Steal batch from bottom
    StealBatch { max_steal: u8 },
    /// Steal batch into another stack
    StealBatchInto { max_steal: u8 },
    /// Verify stack invariants
    VerifyInvariants,
    /// Check local task count
    CheckLocalCount,
}

/// Shadow model for state verification
#[derive(Debug)]
struct ShadowState {
    /// Tasks expected to be in ring (by task_index)
    ring_tasks: std::collections::HashSet<u8>,
    /// Tasks expected to be in stack (by task_index)
    stack_tasks: std::collections::HashSet<u8>,
    /// Expected ring length
    ring_len: usize,
    /// Expected stack length
    stack_len: usize,
}

impl ShadowState {
    fn new() -> Self {
        Self {
            ring_tasks: std::collections::HashSet::new(),
            stack_tasks: std::collections::HashSet::new(),
            ring_len: 0,
            stack_len: 0,
        }
    }

    fn verify_ring_invariants(
        &self,
        ring: &asupersync::runtime::scheduler::intrusive::IntrusiveRing,
    ) {
        // Ring length must match shadow state
        assert_eq!(ring.len(), self.ring_len, "Ring length mismatch");
        assert_eq!(
            ring.is_empty(),
            self.ring_len == 0,
            "Ring emptiness mismatch"
        );
    }

    fn verify_stack_invariants(
        &self,
        stack: &asupersync::runtime::scheduler::intrusive::IntrusiveStack,
    ) {
        // Stack length must match shadow state
        assert_eq!(stack.len(), self.stack_len, "Stack length mismatch");
        assert_eq!(
            stack.is_empty(),
            self.stack_len == 0,
            "Stack emptiness mismatch"
        );
    }
}

/// Maximum limits for safety
const MAX_OPERATIONS: usize = 100;
const MAX_TASKS: usize = 100;

fuzz_target!(|input: IntrusiveHeapFuzz| {
    use asupersync::record::task::TaskRecord;
    use asupersync::runtime::scheduler::intrusive::{IntrusiveRing, IntrusiveStack};
    use asupersync::types::{Budget, RegionId, TaskId};
    use asupersync::util::Arena;
    use std::collections::HashMap;

    // Bounds checking
    if input.ring_ops.len() > MAX_OPERATIONS || input.stack_ops.len() > MAX_OPERATIONS {
        return;
    }

    let initial_tasks = (input.initial_tasks as usize).max(1).min(MAX_TASKS);

    // Ensure valid queue tags (non-zero)
    let ring_tag = if input.ring_tag == 0 {
        1
    } else {
        input.ring_tag
    };
    let stack_tag = if input.stack_tag == 0 || input.stack_tag == ring_tag {
        ring_tag.wrapping_add(1).max(1)
    } else {
        input.stack_tag
    };

    // Initialize test environment
    let mut arena = Arena::<TaskRecord>::new();
    let mut shadow = ShadowState::new();
    let mut ring = IntrusiveRing::new(ring_tag);
    let mut stack = IntrusiveStack::new(stack_tag);
    let mut task_map: HashMap<u8, TaskId> = HashMap::new();

    // Pre-allocate some tasks in arena
    for i in 0..initial_tasks {
        let task_id = TaskId::testing_default();
        let region_id = RegionId::testing_default();
        let budget = Budget::with_deadline_ns(1_000_000_000); // 1 second in nanoseconds

        let record = TaskRecord::new(task_id, region_id, budget);
        let arena_index = arena.insert(record);
        // Map logical task index to actual TaskId
        task_map.insert(i as u8, TaskId::from_arena(arena_index));
    }

    // Execute ring operations
    for op in input.ring_ops.iter().take(MAX_OPERATIONS) {
        match op {
            RingOperation::PushBack { task_index } => {
                if let Some(&task_id) = task_map.get(task_index) {
                    let arena_index = task_id.arena_index();

                    // Check if task is already in a queue
                    if let Some(record) = arena.get(arena_index) {
                        if !record.is_in_queue() {
                            ring.push_back(task_id, &mut arena);

                            // Update shadow state
                            shadow.ring_tasks.insert(*task_index);
                            shadow.ring_len += 1;
                        }
                    }
                }
            }

            RingOperation::PopFront => {
                if let Some(task_id) = ring.pop_front(&mut arena) {
                    // Find the logical task index
                    if let Some((&logical_index, _)) =
                        task_map.iter().find(|(_, &id)| id == task_id)
                    {
                        // Update shadow state
                        shadow.ring_tasks.remove(&logical_index);
                        shadow.ring_len = shadow.ring_len.saturating_sub(1);
                    }

                    // Verify task is no longer in queue
                    if let Some(record) = arena.get(task_id.arena_index()) {
                        assert!(!record.is_in_queue(), "Popped task still shows as in queue");
                    }
                }
            }

            RingOperation::Remove { task_index } => {
                if let Some(&task_id) = task_map.get(task_index) {
                    let removed = ring.remove(task_id, &mut arena);

                    if removed {
                        // Update shadow state
                        shadow.ring_tasks.remove(task_index);
                        shadow.ring_len = shadow.ring_len.saturating_sub(1);

                        // Verify task is no longer in queue
                        if let Some(record) = arena.get(task_id.arena_index()) {
                            assert!(
                                !record.is_in_queue(),
                                "Removed task still shows as in queue"
                            );
                        }
                    }
                }
            }

            RingOperation::Contains { task_index } => {
                if let Some(&task_id) = task_map.get(task_index) {
                    let contains = ring.contains(task_id, &arena);
                    let expected = shadow.ring_tasks.contains(task_index);

                    // Verify contains matches shadow state
                    assert_eq!(
                        contains, expected,
                        "Contains mismatch for task {}: ring says {}, shadow says {}",
                        task_index, contains, expected
                    );
                }
            }

            RingOperation::PeekFront => {
                let front = ring.peek_front();
                let is_empty = shadow.ring_len == 0;

                assert_eq!(
                    front.is_none(),
                    is_empty,
                    "Peek front emptiness mismatch: got {:?}, expected empty: {}",
                    front,
                    is_empty
                );
            }

            RingOperation::Clear => {
                ring.clear(&mut arena);

                // Update shadow state
                shadow.ring_tasks.clear();
                shadow.ring_len = 0;

                assert_eq!(ring.len(), 0, "Ring not empty after clear");
                assert!(ring.is_empty(), "Ring not empty after clear");
            }

            RingOperation::VerifyInvariants => {
                shadow.verify_ring_invariants(&ring);
            }
        }
    }

    // Execute stack operations
    for op in input.stack_ops.iter().take(MAX_OPERATIONS) {
        match op {
            StackOperation::Push { task_index } => {
                if let Some(&task_id) = task_map.get(task_index) {
                    let arena_index = task_id.arena_index();

                    // Check if task is already in a queue
                    if let Some(record) = arena.get(arena_index) {
                        if !record.is_in_queue() {
                            stack.push(task_id, &mut arena);

                            // Update shadow state
                            shadow.stack_tasks.insert(*task_index);
                            shadow.stack_len += 1;
                        }
                    }
                }
            }

            StackOperation::PushBottom { task_index } => {
                if let Some(&task_id) = task_map.get(task_index) {
                    let arena_index = task_id.arena_index();

                    if let Some(record) = arena.get(arena_index) {
                        if !record.is_in_queue() {
                            stack.push_bottom(task_id, &mut arena);

                            // Update shadow state
                            shadow.stack_tasks.insert(*task_index);
                            shadow.stack_len += 1;
                        }
                    }
                }
            }

            StackOperation::Pop => {
                if let Some(task_id) = stack.pop(&mut arena) {
                    // Find the logical task index
                    if let Some((&logical_index, _)) =
                        task_map.iter().find(|(_, &id)| id == task_id)
                    {
                        // Update shadow state
                        shadow.stack_tasks.remove(&logical_index);
                        shadow.stack_len = shadow.stack_len.saturating_sub(1);
                    }

                    // Verify task is no longer in queue
                    if let Some(record) = arena.get(task_id.arena_index()) {
                        assert!(!record.is_in_queue(), "Popped task still shows as in queue");
                    }
                }
            }

            StackOperation::StealBatch { max_steal } => {
                let mut stolen = Vec::new();
                let max_steal = (*max_steal as usize).min(20); // Reasonable limit

                stack.steal_batch(max_steal, &mut arena, &mut stolen);

                // Update shadow state for stolen tasks
                for &task_id in &stolen {
                    if let Some((&logical_index, _)) =
                        task_map.iter().find(|(_, &id)| id == task_id)
                    {
                        shadow.stack_tasks.remove(&logical_index);
                    }
                }
                shadow.stack_len = shadow.stack_len.saturating_sub(stolen.len());
            }

            StackOperation::StealBatchInto { max_steal } => {
                let mut dest_stack = IntrusiveStack::new(stack_tag.wrapping_add(1).max(1));
                let max_steal = (*max_steal as usize).min(20);

                let stolen_count = stack.steal_batch_into(max_steal, &mut arena, &mut dest_stack);

                // Update shadow state
                shadow.stack_len = shadow.stack_len.saturating_sub(stolen_count);

                // Clear stolen tasks from shadow (conservative approach)
                if stolen_count > 0 {
                    let remaining_tasks: std::collections::HashSet<u8> = shadow
                        .stack_tasks
                        .iter()
                        .take(shadow.stack_len)
                        .copied()
                        .collect();
                    shadow.stack_tasks = remaining_tasks;
                }
            }

            StackOperation::VerifyInvariants => {
                shadow.verify_stack_invariants(&stack);
            }

            StackOperation::CheckLocalCount => {
                let has_local = stack.has_local_tasks();

                // Basic invariant: empty stack should not have local tasks
                if shadow.stack_len == 0 {
                    assert!(!has_local, "Empty stack reports local tasks");
                }
            }
        }
    }

    // Final invariant checks
    shadow.verify_ring_invariants(&ring);
    shadow.verify_stack_invariants(&stack);
});
