#![no_main]

use arbitrary::Arbitrary;
use asupersync::record::task::TaskRecord;
use asupersync::runtime::scheduler::IntrusivePriorityHeap;
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::{Arena, ArenaIndex};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Structure-aware intrusive-heap harness for insert/decrease-key sequences.
///
/// Asserts:
/// 1. heap invariants remain valid after every operation
/// 2. peek/pop always match a shadow max-heap model
/// 3. decrease-key is a no-op when not strictly lowering priority
/// 4. repeating the same decrease-key is idempotent
#[derive(Arbitrary, Debug)]
struct IntrusiveHeapFuzz {
    /// Number of preallocated task records addressable by the operation stream.
    task_slots: u8,
    /// Sequence of heap operations.
    operations: Vec<HeapOperation>,
}

#[derive(Arbitrary, Debug, Clone)]
enum HeapOperation {
    Insert { task_index: u8, priority: u8 },
    DecreaseKey { task_index: u8, new_priority: u8 },
    Pop,
    Peek,
    Clear,
    VerifyInvariants,
}

#[derive(Debug, Clone, Copy)]
struct ShadowEntry {
    priority: u8,
    generation: u64,
}

#[derive(Debug, Default)]
struct ShadowHeap {
    live: HashMap<u8, ShadowEntry>,
    next_generation: u64,
}

impl ShadowHeap {
    fn insert(&mut self, task_index: u8, priority: u8) {
        if self.live.contains_key(&task_index) {
            return;
        }

        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        self.live.insert(
            task_index,
            ShadowEntry {
                priority,
                generation,
            },
        );
    }

    fn decrease_key(&mut self, task_index: u8, new_priority: u8) -> bool {
        let Some(entry) = self.live.get_mut(&task_index) else {
            return false;
        };
        if new_priority >= entry.priority {
            return false;
        }
        entry.priority = new_priority;
        true
    }

    fn expected_top(&self) -> Option<u8> {
        let mut best: Option<(u8, ShadowEntry)> = None;
        for (&task_index, &entry) in &self.live {
            match best {
                None => best = Some((task_index, entry)),
                Some((_, current)) if shadow_beats(entry, current) => {
                    best = Some((task_index, entry));
                }
                _ => {}
            }
        }
        best.map(|(task_index, _)| task_index)
    }

    fn pop_expected_top(&mut self) -> Option<u8> {
        let top = self.expected_top()?;
        self.live.remove(&top);
        self.reset_generation_if_empty();
        Some(top)
    }

    fn clear(&mut self) {
        self.live.clear();
        self.reset_generation_if_empty();
    }

    fn reset_generation_if_empty(&mut self) {
        if self.live.is_empty() {
            self.next_generation = 0;
        }
    }
}

fn shadow_beats(candidate: ShadowEntry, incumbent: ShadowEntry) -> bool {
    candidate.priority > incumbent.priority
        || (candidate.priority == incumbent.priority
            && incumbent
                .generation
                .wrapping_sub(candidate.generation)
                .cast_signed()
                > 0)
}

const MAX_TASK_SLOTS: usize = 64;
const MAX_OPERATIONS: usize = 256;

fuzz_target!(|input: IntrusiveHeapFuzz| {
    let task_slots = usize::from(input.task_slots).clamp(1, MAX_TASK_SLOTS);
    let operations: Vec<_> = input.operations.into_iter().take(MAX_OPERATIONS).collect();

    let mut arena = setup_arena(task_slots as u32);
    let task_ids: Vec<_> = (0..task_slots).map(|idx| task(idx as u32)).collect();
    let mut heap = IntrusivePriorityHeap::with_capacity(task_slots);
    let mut shadow = ShadowHeap::default();

    for op in operations {
        match op {
            HeapOperation::Insert {
                task_index,
                priority,
            } => {
                if let Some(&task_id) = task_ids.get(usize::from(task_index)) {
                    let was_present = shadow.live.contains_key(&task_index);
                    heap.push(task_id, priority, &mut arena);
                    if !was_present {
                        shadow.insert(task_index, priority);
                    }
                }
            }
            HeapOperation::DecreaseKey {
                task_index,
                new_priority,
            } => {
                if let Some(&task_id) = task_ids.get(usize::from(task_index)) {
                    let expected = shadow.decrease_key(task_index, new_priority);
                    let changed = heap.decrease_key_for_test(task_id, new_priority, &mut arena);
                    assert_eq!(
                        changed, expected,
                        "decrease-key result must match shadow model"
                    );

                    let repeated = heap.decrease_key_for_test(task_id, new_priority, &mut arena);
                    assert!(
                        !repeated,
                        "repeating the same decrease-key must be idempotent"
                    );
                }
            }
            HeapOperation::Pop => {
                let expected = shadow
                    .pop_expected_top()
                    .and_then(|task_index| task_ids.get(usize::from(task_index)).copied());
                let popped = heap.pop(&mut arena);
                assert_eq!(popped, expected, "pop must match the shadow heap");
            }
            HeapOperation::Peek => {
                let expected = shadow
                    .expected_top()
                    .and_then(|task_index| task_ids.get(usize::from(task_index)).copied());
                assert_eq!(heap.peek(), expected, "peek must match the shadow heap");
            }
            HeapOperation::Clear => {
                heap.clear(&mut arena);
                shadow.clear();
            }
            HeapOperation::VerifyInvariants => {}
        }

        assert_heap_matches_shadow(&heap, &shadow, &arena, &task_ids);
    }

    while !heap.is_empty() {
        let expected = shadow
            .pop_expected_top()
            .and_then(|task_index| task_ids.get(usize::from(task_index)).copied());
        assert_eq!(
            heap.pop(&mut arena),
            expected,
            "final drain must preserve shadow heap ordering"
        );
        assert_heap_matches_shadow(&heap, &shadow, &arena, &task_ids);
    }

    assert!(shadow.live.is_empty(), "shadow heap should drain to empty");
});

fn assert_heap_matches_shadow(
    heap: &IntrusivePriorityHeap,
    shadow: &ShadowHeap,
    arena: &Arena<TaskRecord>,
    task_ids: &[TaskId],
) {
    assert_eq!(heap.len(), shadow.live.len(), "heap length mismatch");
    assert_eq!(
        heap.is_empty(),
        shadow.live.is_empty(),
        "heap emptiness mismatch"
    );
    assert!(
        heap.verify_invariants_for_test(arena),
        "intrusive heap invariants must hold after every operation"
    );

    let expected_top = shadow
        .expected_top()
        .and_then(|task_index| task_ids.get(usize::from(task_index)).copied());
    assert_eq!(heap.peek(), expected_top, "peek must match the shadow heap");
}

fn region() -> RegionId {
    RegionId::from_arena(ArenaIndex::new(0, 0))
}

fn task(n: u32) -> TaskId {
    TaskId::from_arena(ArenaIndex::new(n, 0))
}

fn setup_arena(count: u32) -> Arena<TaskRecord> {
    let mut arena = Arena::new();
    for i in 0..count {
        let id = task(i);
        let record = TaskRecord::new(id, region(), Budget::INFINITE);
        let idx = arena.insert(record);
        assert_eq!(idx.index(), i);
    }
    arena
}
