#![no_main]

use std::collections::VecDeque;

use arbitrary::Arbitrary;
use asupersync::record::task::TaskRecord;
use asupersync::runtime::scheduler::intrusive::{IntrusiveRing, QUEUE_TAG_CANCEL, QUEUE_TAG_READY};
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::{Arena, ArenaIndex};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Arbitrary)]
enum QueueKind {
    Ready,
    Cancel,
}

#[derive(Debug, Clone, Arbitrary)]
enum Operation {
    Schedule {
        queue: QueueKind,
        task_index: u8,
        repeats: u8,
    },
    Remove {
        queue: QueueKind,
        task_index: u8,
        repeats: u8,
    },
    Dispatch {
        queue: QueueKind,
        repeats: u8,
    },
    Clear {
        queue: QueueKind,
    },
    Contains {
        queue: QueueKind,
        task_index: u8,
    },
}

#[derive(Debug, Arbitrary)]
struct IntrusiveScheduledSetDedupInput {
    num_tasks: u8,
    operations: Vec<Operation>,
}

const MAX_TASKS: usize = 64;
const MAX_OPERATIONS: usize = 256;

#[derive(Debug)]
struct ShadowModel {
    queue_by_task: Vec<Option<QueueKind>>,
    scheduled_generation: Vec<u32>,
    last_fired_generation: Vec<u32>,
    ready: VecDeque<TaskId>,
    cancel: VecDeque<TaskId>,
}

impl ShadowModel {
    fn new(num_tasks: usize) -> Self {
        Self {
            queue_by_task: vec![None; num_tasks],
            scheduled_generation: vec![0; num_tasks],
            last_fired_generation: vec![0; num_tasks],
            ready: VecDeque::new(),
            cancel: VecDeque::new(),
        }
    }

    fn queue_mut(&mut self, queue: QueueKind) -> &mut VecDeque<TaskId> {
        match queue {
            QueueKind::Ready => &mut self.ready,
            QueueKind::Cancel => &mut self.cancel,
        }
    }
}

fuzz_target!(|input: IntrusiveScheduledSetDedupInput| {
    let num_tasks = usize::from(input.num_tasks.clamp(1, MAX_TASKS as u8));
    let operations: Vec<_> = input.operations.into_iter().take(MAX_OPERATIONS).collect();

    if operations.is_empty() {
        return;
    }

    let mut arena = setup_arena(num_tasks);
    let mut ready = IntrusiveRing::new(QUEUE_TAG_READY);
    let mut cancel = IntrusiveRing::new(QUEUE_TAG_CANCEL);
    let mut shadow = ShadowModel::new(num_tasks);

    for (op_index, operation) in operations.iter().enumerate() {
        match operation {
            Operation::Schedule {
                queue,
                task_index,
                repeats,
            } => {
                let task_index = usize::from(*task_index) % num_tasks;
                let task_id = task_id_from_index(task_index);
                let repeat_count = usize::from((*repeats).max(1));
                let was_unscheduled = shadow.queue_by_task[task_index].is_none();
                let len_before = ring_ref(*queue, &ready, &cancel).len();

                for _ in 0..repeat_count {
                    ring_mut(*queue, &mut ready, &mut cancel).push_back(task_id, &mut arena);
                }

                if was_unscheduled {
                    shadow.queue_by_task[task_index] = Some(*queue);
                    shadow.queue_mut(*queue).push_back(task_id);
                    shadow.scheduled_generation[task_index] =
                        shadow.scheduled_generation[task_index].saturating_add(1);
                }

                let expected_len = len_before + if was_unscheduled { 1 } else { 0 };
                assert_eq!(
                    ring_ref(*queue, &ready, &cancel).len(),
                    expected_len,
                    "op {op_index}: duplicate schedule should be idempotent"
                );
            }
            Operation::Remove {
                queue,
                task_index,
                repeats,
            } => {
                let task_index = usize::from(*task_index) % num_tasks;
                let task_id = task_id_from_index(task_index);
                let repeat_count = usize::from((*repeats).max(1));

                for attempt in 0..repeat_count {
                    let expected = shadow.queue_by_task[task_index] == Some(*queue);
                    let removed =
                        ring_mut(*queue, &mut ready, &mut cancel).remove(task_id, &mut arena);
                    assert_eq!(
                        removed, expected,
                        "op {op_index} attempt {attempt}: remove result must match membership"
                    );

                    if expected {
                        shadow.queue_by_task[task_index] = None;
                        let queue_shadow = shadow.queue_mut(*queue);
                        let removed_shadow = queue_shadow
                            .iter()
                            .position(|&queued| queued == task_id)
                            .map(|pos| queue_shadow.remove(pos));
                        assert_eq!(removed_shadow, Some(task_id));
                    }
                }
            }
            Operation::Dispatch { queue, repeats } => {
                let repeat_count = usize::from((*repeats).max(1));

                for attempt in 0..repeat_count {
                    let actual = ring_mut(*queue, &mut ready, &mut cancel).pop_front(&mut arena);
                    let expected = shadow.queue_mut(*queue).pop_front();
                    assert_eq!(
                        actual, expected,
                        "op {op_index} attempt {attempt}: dispatch must match shadow queue"
                    );

                    if let Some(task_id) = expected {
                        let task_index = usize::try_from(task_id.arena_index().index())
                            .expect("task index fits usize");
                        assert_eq!(shadow.queue_by_task[task_index], Some(*queue));
                        shadow.queue_by_task[task_index] = None;

                        let generation = shadow.scheduled_generation[task_index];
                        assert!(
                            shadow.last_fired_generation[task_index] < generation,
                            "op {op_index}: task {task_id:?} fired twice in generation {generation}"
                        );
                        shadow.last_fired_generation[task_index] = generation;
                    }
                }
            }
            Operation::Clear { queue } => {
                ring_mut(*queue, &mut ready, &mut cancel).clear(&mut arena);
                while let Some(task_id) = shadow.queue_mut(*queue).pop_front() {
                    let task_index =
                        usize::try_from(task_id.arena_index().index()).expect("task index fits");
                    shadow.queue_by_task[task_index] = None;
                }
            }
            Operation::Contains { queue, task_index } => {
                let task_index = usize::from(*task_index) % num_tasks;
                let task_id = task_id_from_index(task_index);
                let actual = ring_ref(*queue, &ready, &cancel).contains(task_id, &arena);
                let expected = shadow.queue_by_task[task_index] == Some(*queue);
                assert_eq!(
                    actual, expected,
                    "op {op_index}: contains result must match shadow membership"
                );
            }
        }

        verify_model(&ready, &cancel, &arena, &shadow, op_index);
    }

    drain_and_verify(&mut ready, &mut cancel, &mut arena, &mut shadow);
});

fn ring_mut<'a>(
    queue: QueueKind,
    ready: &'a mut IntrusiveRing,
    cancel: &'a mut IntrusiveRing,
) -> &'a mut IntrusiveRing {
    match queue {
        QueueKind::Ready => ready,
        QueueKind::Cancel => cancel,
    }
}

fn ring_ref<'a>(
    queue: QueueKind,
    ready: &'a IntrusiveRing,
    cancel: &'a IntrusiveRing,
) -> &'a IntrusiveRing {
    match queue {
        QueueKind::Ready => ready,
        QueueKind::Cancel => cancel,
    }
}

fn verify_model(
    ready: &IntrusiveRing,
    cancel: &IntrusiveRing,
    arena: &Arena<TaskRecord>,
    shadow: &ShadowModel,
    op_index: usize,
) {
    assert_eq!(
        ready.len(),
        shadow.ready.len(),
        "op {op_index}: ready len drifted"
    );
    assert_eq!(
        cancel.len(),
        shadow.cancel.len(),
        "op {op_index}: cancel len drifted"
    );

    for task_index in 0..shadow.queue_by_task.len() {
        let task_id = task_id_from_index(task_index);
        let in_ready = ready.contains(task_id, arena);
        let in_cancel = cancel.contains(task_id, arena);
        let expected = shadow.queue_by_task[task_index];

        assert!(
            !(in_ready && in_cancel),
            "op {op_index}: task {task_id:?} present in multiple queues"
        );

        assert_eq!(
            in_ready,
            expected == Some(QueueKind::Ready),
            "op {op_index}: ready membership drift for {task_id:?}"
        );
        assert_eq!(
            in_cancel,
            expected == Some(QueueKind::Cancel),
            "op {op_index}: cancel membership drift for {task_id:?}"
        );

        assert!(
            shadow.last_fired_generation[task_index] <= shadow.scheduled_generation[task_index],
            "op {op_index}: fired generation exceeds scheduled generation for {task_id:?}"
        );
    }
}

fn drain_and_verify(
    ready: &mut IntrusiveRing,
    cancel: &mut IntrusiveRing,
    arena: &mut Arena<TaskRecord>,
    shadow: &mut ShadowModel,
) {
    while let Some(task_id) = ready.pop_front(arena) {
        let expected = shadow.ready.pop_front();
        assert_eq!(Some(task_id), expected, "final ready drain drifted");
        let task_index = usize::try_from(task_id.arena_index().index()).expect("task index fits");
        shadow.queue_by_task[task_index] = None;
        let generation = shadow.scheduled_generation[task_index];
        assert!(shadow.last_fired_generation[task_index] < generation);
        shadow.last_fired_generation[task_index] = generation;
    }

    while let Some(task_id) = cancel.pop_front(arena) {
        let expected = shadow.cancel.pop_front();
        assert_eq!(Some(task_id), expected, "final cancel drain drifted");
        let task_index = usize::try_from(task_id.arena_index().index()).expect("task index fits");
        shadow.queue_by_task[task_index] = None;
        let generation = shadow.scheduled_generation[task_index];
        assert!(shadow.last_fired_generation[task_index] < generation);
        shadow.last_fired_generation[task_index] = generation;
    }

    assert!(
        shadow.ready.is_empty(),
        "shadow ready queue should be empty"
    );
    assert!(
        shadow.cancel.is_empty(),
        "shadow cancel queue should be empty"
    );
    assert!(ready.is_empty(), "ready queue should be empty");
    assert!(cancel.is_empty(), "cancel queue should be empty");
}

fn task_id_from_index(index: usize) -> TaskId {
    TaskId::from_arena(ArenaIndex::new(index as u32, 0))
}

fn setup_arena(num_tasks: usize) -> Arena<TaskRecord> {
    let mut arena = Arena::new();
    let region_id = RegionId::from_arena(ArenaIndex::new(0, 0));

    for i in 0..num_tasks {
        let task_id = task_id_from_index(i);
        let record = TaskRecord::new(task_id, region_id, Budget::INFINITE);
        let inserted_index = arena.insert(record);
        assert_eq!(inserted_index.index(), i as u32, "arena index mismatch");
    }

    arena
}
