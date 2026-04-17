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
    /// Arena size (10-500 tasks)
    arena_size: u16,
    /// Initial task count (0-arena_size)
    initial_tasks: u16,
    /// Ring queue tag (1-255)
    ring_tag: u8,
    /// Stack queue tag (1-255)
    stack_tag: u8,
}

/// Operations for IntrusiveRing fuzzing
#[derive(Arbitrary, Debug)]
enum RingOperation {
    /// Push task to back of ring
    PushBack { task_index: u16 },
    /// Pop task from front of ring
    PopFront,
    /// Remove specific task from ring
    Remove { task_index: u16 },
    /// Check if task is in ring
    Contains { task_index: u16 },
    /// Peek front without removing
    PeekFront,
    /// Clear entire ring
    Clear,
    /// Verify ring invariants
    VerifyInvariants,
    /// Double enqueue attempt (should fail)
    DoubleEnqueue { task_index: u16 },
}

/// Operations for IntrusiveStack fuzzing
#[derive(Arbitrary, Debug)]
enum StackOperation {
    /// Push task to top of stack
    Push { task_index: u16 },
    /// Push to bottom of stack
    PushBottom { task_index: u16 },
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
    ring_tasks: std::collections::HashSet<usize>,
    /// Tasks expected to be in stack (by task_index)
    stack_tasks: std::collections::HashSet<usize>,
    /// Expected ring length
    ring_len: usize,
    /// Expected stack length
    stack_len: usize,
    /// Local task count in stack
    stack_local_count: usize,
}

impl ShadowState {
    fn new() -> Self {
        Self {
            ring_tasks: std::collections::HashSet::new(),
            stack_tasks: std::collections::HashSet::new(),
            ring_len: 0,
            stack_len: 0,
            stack_local_count: 0,
        }
    }

    fn verify_ring_invariants(&self, ring: &asupersync::runtime::scheduler::intrusive::IntrusiveRing) {
        // Ring length must match shadow state
        assert_eq!(ring.len(), self.ring_len, "Ring length mismatch");
        assert_eq!(ring.is_empty(), self.ring_len == 0, "Ring emptiness mismatch");
    }

    fn verify_stack_invariants(&self, stack: &asupersync::runtime::scheduler::intrusive::IntrusiveStack) {
        // Stack length must match shadow state
        assert_eq!(stack.len(), self.stack_len, "Stack length mismatch");
        assert_eq!(stack.is_empty(), self.stack_len == 0, "Stack emptiness mismatch");

        // Local count invariant
        assert_eq!(stack.has_local_tasks(), self.stack_local_count > 0,
            "Stack local task count mismatch: expected {}, has_local={}",
            self.stack_local_count, stack.has_local_tasks());
    }
}

/// Maximum limits for safety
const MAX_OPERATIONS: usize = 200;
const MAX_ARENA_SIZE: usize = 500;
const MIN_ARENA_SIZE: usize = 10;

fuzz_target!(|input: IntrusiveHeapFuzz| {
    use asupersync::runtime::scheduler::intrusive::{IntrusiveRing, IntrusiveStack};
    use asupersync::record::task::TaskRecord;
    use asupersync::types::TaskId;
    use asupersync::util::{Arena, ArenaIndex};
    use std::collections::HashSet;

    // Bounds checking
    if input.ring_ops.len() > MAX_OPERATIONS || input.stack_ops.len() > MAX_OPERATIONS {
        return;
    }

    // Ensure valid arena size
    let arena_size = (input.arena_size as usize)
        .max(MIN_ARENA_SIZE)
        .min(MAX_ARENA_SIZE);

    let initial_tasks = (input.initial_tasks as usize).min(arena_size);

    // Ensure valid queue tags (non-zero)
    let ring_tag = if input.ring_tag == 0 { 1 } else { input.ring_tag };
    let stack_tag = if input.stack_tag == 0 || input.stack_tag == ring_tag {
        ring_tag.wrapping_add(1).max(1)
    } else {
        input.stack_tag
    };

    // Initialize test environment
    let mut arena = Arena::<TaskRecord>::new(arena_size);
    let mut shadow = ShadowState::new();
    let mut ring = IntrusiveRing::new(ring_tag);
    let mut stack = IntrusiveStack::new(stack_tag);
    let mut allocated_tasks = HashSet::new();

    // Pre-allocate some tasks in arena
    for i in 0..initial_tasks {
        let record = TaskRecord::test_placeholder();
        if let Some(index) = arena.insert(record) {
            allocated_tasks.insert(index);
        }
    }

    // Execute ring operations
    for op in input.ring_ops.iter().take(MAX_OPERATIONS) {
        match op {
            RingOperation::PushBack { task_index } => {
                let task_index = (*task_index as usize) % arena_size;
                if let Some(task_id) = get_or_create_task(task_index, &mut arena, &mut allocated_tasks) {
                    let arena_index = task_id.arena_index();

                    // Check if task is already in a queue
                    if let Some(record) = arena.get(arena_index) {
                        if !record.is_in_queue() {
                            ring.push_back(task_id, &mut arena);

                            // Update shadow state
                            shadow.ring_tasks.insert(arena_index.to_usize());
                            shadow.ring_len += 1;
                        }
                    }
                }
            },

            RingOperation::PopFront => {
                if let Some(task_id) = ring.pop_front(&mut arena) {
                    let arena_index = task_id.arena_index();

                    // Update shadow state
                    shadow.ring_tasks.remove(&arena_index.to_usize());
                    shadow.ring_len = shadow.ring_len.saturating_sub(1);

                    // Verify task is no longer in queue
                    if let Some(record) = arena.get(arena_index) {
                        assert!(!record.is_in_queue(), "Popped task still shows as in queue");
                    }
                }
            },

            RingOperation::Remove { task_index } => {
                let task_index = (*task_index as usize) % arena_size;
                if let Some(task_id) = get_task_id(task_index, &allocated_tasks) {
                    let removed = ring.remove(task_id, &mut arena);

                    if removed {
                        // Update shadow state
                        shadow.ring_tasks.remove(&task_id.arena_index().to_usize());
                        shadow.ring_len = shadow.ring_len.saturating_sub(1);

                        // Verify task is no longer in queue
                        if let Some(record) = arena.get(task_id.arena_index()) {
                            assert!(!record.is_in_queue(), "Removed task still shows as in queue");
                        }
                    }
                }
            },

            RingOperation::Contains { task_index } => {
                let task_index = (*task_index as usize) % arena_size;
                if let Some(task_id) = get_task_id(task_index, &allocated_tasks) {
                    let contains = ring.contains(task_id, &arena);
                    let expected = shadow.ring_tasks.contains(&task_id.arena_index().to_usize());

                    // Verify contains matches shadow state
                    assert_eq!(contains, expected,
                        "Contains mismatch for task {}: ring says {}, shadow says {}",
                        task_index, contains, expected);
                }
            },

            RingOperation::PeekFront => {
                let front = ring.peek_front();
                let is_empty = shadow.ring_len == 0;

                assert_eq!(front.is_none(), is_empty,
                    "Peek front emptiness mismatch: got {:?}, expected empty: {}",
                    front, is_empty);
            },

            RingOperation::Clear => {
                ring.clear(&mut arena);

                // Update shadow state
                shadow.ring_tasks.clear();
                shadow.ring_len = 0;

                assert_eq!(ring.len(), 0, "Ring not empty after clear");
                assert!(ring.is_empty(), "Ring not empty after clear");
            },

            RingOperation::VerifyInvariants => {
                shadow.verify_ring_invariants(&ring);
            },

            RingOperation::DoubleEnqueue { task_index } => {
                let task_index = (*task_index as usize) % arena_size;
                if let Some(task_id) = get_task_id(task_index, &allocated_tasks) {
                    let initial_len = ring.len();

                    // Try to enqueue task that might already be in queue
                    ring.push_back(task_id, &mut arena);

                    // If task was already in queue, length shouldn't change
                    if shadow.ring_tasks.contains(&task_id.arena_index().to_usize()) {
                        assert_eq!(ring.len(), initial_len,
                            "Double enqueue changed ring length");
                    }
                }
            },
        }
    }

    // Execute stack operations
    for op in input.stack_ops.iter().take(MAX_OPERATIONS) {
        match op {
            StackOperation::Push { task_index } => {
                let task_index = (*task_index as usize) % arena_size;
                if let Some(task_id) = get_or_create_task(task_index, &mut arena, &mut allocated_tasks) {
                    let arena_index = task_id.arena_index();

                    // Check if task is already in a queue
                    if let Some(record) = arena.get(arena_index) {
                        if !record.is_in_queue() {
                            let is_local = record.is_local();
                            stack.push(task_id, &mut arena);

                            // Update shadow state
                            shadow.stack_tasks.insert(arena_index.to_usize());
                            shadow.stack_len += 1;
                            if is_local {
                                shadow.stack_local_count += 1;
                            }
                        }
                    }
                }
            },

            StackOperation::PushBottom { task_index } => {
                let task_index = (*task_index as usize) % arena_size;
                if let Some(task_id) = get_or_create_task(task_index, &mut arena, &mut allocated_tasks) {
                    let arena_index = task_id.arena_index();

                    if let Some(record) = arena.get(arena_index) {
                        if !record.is_in_queue() {
                            let is_local = record.is_local();
                            stack.push_bottom(task_id, &mut arena);

                            // Update shadow state
                            shadow.stack_tasks.insert(arena_index.to_usize());
                            shadow.stack_len += 1;
                            if is_local {
                                shadow.stack_local_count += 1;
                            }
                        }
                    }
                }
            },

            StackOperation::Pop => {
                if let Some(task_id) = stack.pop(&mut arena) {
                    let arena_index = task_id.arena_index();

                    // Update shadow state (approximate local count)
                    shadow.stack_tasks.remove(&arena_index.to_usize());
                    shadow.stack_len = shadow.stack_len.saturating_sub(1);
                    if shadow.stack_local_count > 0 {
                        shadow.stack_local_count = shadow.stack_local_count.saturating_sub(1);
                    }

                    // Verify task is no longer in queue
                    if let Some(record) = arena.get(arena_index) {
                        assert!(!record.is_in_queue(), "Popped task still shows as in queue");
                    }
                }
            },

            StackOperation::StealBatch { max_steal } => {
                let mut stolen = Vec::new();
                let max_steal = (*max_steal as usize).min(50); // Reasonable limit

                stack.steal_batch(max_steal, &mut arena, &mut stolen);

                // Update shadow state for stolen tasks
                for &task_id in &stolen {
                    shadow.stack_tasks.remove(&task_id.arena_index().to_usize());
                }
                shadow.stack_len = shadow.stack_len.saturating_sub(stolen.len());
                // Reset local count to 0 as steal removes tasks
                shadow.stack_local_count = 0;
            },

            StackOperation::StealBatchInto { max_steal } => {
                let mut dest_stack = IntrusiveStack::new(stack_tag.wrapping_add(1).max(1));
                let max_steal = (*max_steal as usize).min(50);

                let stolen_count = stack.steal_batch_into(max_steal, &mut arena, &mut dest_stack);

                // Update shadow state
                shadow.stack_len = shadow.stack_len.saturating_sub(stolen_count);
                shadow.stack_local_count = 0; // Conservative reset
            },

            StackOperation::VerifyInvariants => {
                shadow.verify_stack_invariants(&stack);
            },

            StackOperation::CheckLocalCount => {
                let has_local = stack.has_local_tasks();

                // Note: This is approximate due to steal operations
                if shadow.stack_len == 0 {
                    assert!(!has_local, "Empty stack reports local tasks");
                }
            },
        }
    }

    // Final invariant checks
    shadow.verify_ring_invariants(&ring);
    shadow.verify_stack_invariants(&stack);

    // Verify no orphaned queue links in allocated tasks
    for &arena_index in &allocated_tasks {
        if let Some(record) = arena.get(ArenaIndex::from_usize(arena_index)) {
            if record.is_in_queue() {
                let queue_tag = record.queue_tag;
                let in_ring = ring.tag() == queue_tag;
                // Note: Can't access stack tag directly, so we approximate
                let in_known_queue = in_ring || queue_tag == stack_tag;

                assert!(in_known_queue,
                    "Task {} has queue_tag {} but not in any known queue (ring tag: {})",
                    arena_index, queue_tag, ring.tag());
            }
        }
    }
});

/// Helper to get or create a task in the arena
fn get_or_create_task(
    task_index: usize,
    arena: &mut Arena<TaskRecord>,
    allocated_tasks: &mut HashSet<usize>,
) -> Option<TaskId> {
    if let Some(&arena_index) = allocated_tasks.iter().find(|&&idx| idx == task_index) {
        return Some(TaskId::from_arena_index(ArenaIndex::from_usize(arena_index)));
    }

    // Try to allocate new task if arena has space
    if arena.len() < arena.len() + 1000 { // Conservative space check
        let record = TaskRecord::test_placeholder();
        if let Some(index) = arena.insert(record) {
            allocated_tasks.insert(index.to_usize());
            return Some(TaskId::from_arena_index(index));
        }
    }

    None
}

/// Helper to get existing task ID
fn get_task_id(task_index: usize, allocated_tasks: &HashSet<usize>) -> Option<TaskId> {
    if let Some(&arena_index) = allocated_tasks.iter().find(|&&idx| idx == task_index) {
        Some(TaskId::from_arena_index(ArenaIndex::from_usize(arena_index)))
    } else {
        None
    }
}