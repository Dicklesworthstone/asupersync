//! Scheduler benchmark suite for Asupersync.
//!
//! Benchmarks the performance of scheduling primitives:
//! - LocalQueue: Per-worker LIFO queue operations
//! - GlobalQueue: Cross-thread injection queue
//! - PriorityScheduler: Three-lane scheduler (cancel/timed/ready)
//! - Work stealing: Batch theft between workers
//!
//! Performance targets:
//! - LocalQueue push/pop: < 50ns
//! - GlobalQueue push/pop: < 100ns (lock-free)
//! - PriorityScheduler schedule/pop: < 200ns (heap operations)
//! - Batch steal: < 500ns for 8-task batch

#![allow(missing_docs)]
#![allow(clippy::semicolon_if_nothing_returned)]

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use asupersync::record::task::TaskRecord;
use asupersync::runtime::RuntimeState;
use asupersync::runtime::scheduler::{
    GlobalQueue, IntrusiveRing, IntrusiveStack, LocalQueue, Parker, QUEUE_TAG_READY, Scheduler,
};
use asupersync::sync::ContendedMutex;
use asupersync::types::{Budget, RegionId, TaskId, Time};
use asupersync::util::{Arena, ArenaIndex};
use std::collections::{BinaryHeap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

const BURST_TASKS: usize = 10_000;

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Creates a test TaskId from an index.
fn task(id: u32) -> TaskId {
    TaskId::new_for_test(id, 0)
}

/// Creates a vector of test TaskIds.
fn tasks(count: usize) -> Vec<TaskId> {
    (0..count as u32).map(task).collect()
}

/// Creates a test RegionId.
fn region() -> RegionId {
    RegionId::from_arena(ArenaIndex::new(0, 0))
}

/// Creates an arena with `count` TaskRecords.
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

fn setup_runtime_state(max_task_id: u32) -> Arc<ContendedMutex<RuntimeState>> {
    let mut state = RuntimeState::new();
    for i in 0..=max_task_id {
        let id = task(i);
        let record = TaskRecord::new(id, region(), Budget::INFINITE);
        let idx = state.tasks.insert(record);
        assert_eq!(idx.index(), i);
    }
    Arc::new(ContendedMutex::new("runtime_state", state))
}

fn local_queue(max_task_id: u32) -> LocalQueue {
    LocalQueue::new(setup_runtime_state(max_task_id))
}

// =============================================================================
// LOCAL QUEUE BENCHMARKS
// =============================================================================

fn bench_local_queue(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/local_queue");

    // Single push/pop cycle
    group.bench_function("push_pop_single", |b| {
        b.iter_batched(
            || local_queue(1),
            |queue| {
                queue.push(task(1));
                let result = queue.pop();
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });

    // Sequential push then pop
    for &count in &[10, 100, 1000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("push_then_pop", count),
            &count,
            |b, &count| {
                let task_ids = tasks(count as usize);
                let max_id = count as u32 - 1;
                b.iter_batched(
                    || (local_queue(max_id), task_ids.clone()),
                    |(queue, tasks)| {
                        for t in &tasks {
                            queue.push(*t);
                        }
                        for _ in 0..tasks.len() {
                            let _ = black_box(queue.pop());
                        }
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // Interleaved push/pop (simulates real workload)
    group.bench_function("interleaved_push_pop", |b| {
        b.iter_batched(
            || local_queue(199),
            |queue| {
                for i in 0..100u32 {
                    queue.push(task(i * 2));
                    queue.push(task(i * 2 + 1));
                    let _ = black_box(queue.pop());
                }
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

// =============================================================================
// GLOBAL QUEUE BENCHMARKS
// =============================================================================

fn bench_global_queue(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/global_queue");

    // Single push/pop
    group.bench_function("push_pop_single", |b| {
        b.iter_batched(
            GlobalQueue::new,
            |queue| {
                queue.push(task(1));
                let result = queue.pop();
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });

    // Batch operations
    for &count in &[10, 100, 1000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("push_batch", count),
            &count,
            |b, &count| {
                let task_ids = tasks(count as usize);
                b.iter_batched(
                    || (GlobalQueue::new(), task_ids.clone()),
                    |(queue, tasks)| {
                        for t in &tasks {
                            queue.push(*t);
                        }
                        black_box(queue.len())
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // FIFO ordering verification (pop all after push all)
    for &count in &[10, 100, 1000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("push_then_pop", count),
            &count,
            |b, &count| {
                let task_ids = tasks(count as usize);
                b.iter_batched(
                    || (GlobalQueue::new(), task_ids.clone()),
                    |(queue, tasks)| {
                        for t in &tasks {
                            queue.push(*t);
                        }
                        for _ in 0..tasks.len() {
                            let _ = black_box(queue.pop());
                        }
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

// =============================================================================
// PRIORITY SCHEDULER BENCHMARKS
// =============================================================================

fn bench_priority_scheduler(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/priority");

    // Ready lane schedule/pop
    group.bench_function("schedule_ready_pop", |b| {
        b.iter_batched(
            Scheduler::new,
            |mut scheduler| {
                scheduler.schedule(task(1), 0);
                let result = scheduler.pop();
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });

    // Cancel lane schedule/pop
    group.bench_function("schedule_cancel_pop", |b| {
        b.iter_batched(
            Scheduler::new,
            |mut scheduler| {
                scheduler.schedule_cancel(task(1), 0);
                let result = scheduler.pop();
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });

    // Timed lane schedule/pop
    group.bench_function("schedule_timed_pop", |b| {
        b.iter_batched(
            Scheduler::new,
            |mut scheduler| {
                scheduler.schedule_timed(task(1), Time::from_nanos(1_000_000));
                let result = scheduler.pop();
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });

    // Batch scheduling to ready lane
    for &count in &[10, 100, 1000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("batch_schedule_ready", count),
            &count,
            |b, &count| {
                let task_ids = tasks(count as usize);
                b.iter_batched(
                    || (Scheduler::new(), task_ids.clone()),
                    |(mut scheduler, tasks)| {
                        for (i, t) in tasks.iter().enumerate() {
                            scheduler.schedule(*t, (i % 256) as u8);
                        }
                        black_box(scheduler.len())
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // Batch scheduling then pop all
    for &count in &[10, 100, 1000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("batch_schedule_then_pop", count),
            &count,
            |b, &count| {
                let task_ids = tasks(count as usize);
                b.iter_batched(
                    || (Scheduler::new(), task_ids.clone()),
                    |(mut scheduler, tasks)| {
                        for t in &tasks {
                            scheduler.schedule(*t, 0);
                        }
                        while scheduler.pop().is_some() {}
                        black_box(scheduler.is_empty())
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // Deduplication behavior (scheduling same task twice)
    group.bench_function("dedup_same_task", |b| {
        b.iter_batched(
            Scheduler::new,
            |mut scheduler| {
                // Schedule same task 100 times - should only add once
                for _ in 0..100 {
                    scheduler.schedule(task(1), 0);
                }
                black_box(scheduler.len())
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

// =============================================================================
// LANE PRIORITY ORDERING BENCHMARKS
// =============================================================================

fn bench_lane_priority(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/lane_priority");

    // Mixed lanes: cancel > timed > ready ordering
    group.bench_function("mixed_lanes_pop_order", |b| {
        b.iter_batched(
            || {
                let mut scheduler = Scheduler::new();
                // Add tasks to each lane
                scheduler.schedule(task(1), 0); // ready
                scheduler.schedule_timed(task(2), Time::from_nanos(1_000_000)); // timed
                scheduler.schedule_cancel(task(3), 0); // cancel
                scheduler
            },
            |mut scheduler| {
                // Pop should return: cancel(3), timed(2), ready(1)
                let first = scheduler.pop();
                let second = scheduler.pop();
                let third = scheduler.pop();
                black_box((first, second, third))
            },
            BatchSize::SmallInput,
        )
    });

    // EDF ordering within timed lane
    group.bench_function("timed_edf_ordering", |b| {
        b.iter_batched(
            || {
                let mut scheduler = Scheduler::new();
                // Add tasks with different deadlines (out of order)
                scheduler.schedule_timed(task(1), Time::from_nanos(3_000_000));
                scheduler.schedule_timed(task(2), Time::from_nanos(1_000_000));
                scheduler.schedule_timed(task(3), Time::from_nanos(2_000_000));
                scheduler
            },
            |mut scheduler| {
                // Pop should return: task(2), task(3), task(1) (earliest deadline first)
                let first = scheduler.pop();
                let second = scheduler.pop();
                let third = scheduler.pop();
                black_box((first, second, third))
            },
            BatchSize::SmallInput,
        )
    });

    // Priority ordering within ready lane
    group.bench_function("ready_priority_ordering", |b| {
        b.iter_batched(
            || {
                let mut scheduler = Scheduler::new();
                // Add tasks with different priorities
                scheduler.schedule(task(1), 1); // low priority
                scheduler.schedule(task(2), 100); // high priority
                scheduler.schedule(task(3), 50); // medium priority
                scheduler
            },
            |mut scheduler| {
                // Pop should return highest priority first
                let first = scheduler.pop();
                let second = scheduler.pop();
                let third = scheduler.pop();
                black_box((first, second, third))
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

// =============================================================================
// WORK STEALING BENCHMARKS
// =============================================================================

fn bench_work_stealing(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/work_stealing");

    // Single steal operation
    group.bench_function("steal_single", |b| {
        b.iter_batched(
            || {
                let state = setup_runtime_state(1);
                let victim = LocalQueue::new(Arc::clone(&state));
                victim.push(task(1));
                let stealer = victim.stealer();
                (victim, stealer)
            },
            |(_victim, stealer)| {
                let result = stealer.steal();
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });

    // Batch steal
    for &victim_size in &[16u32, 64, 256] {
        group.bench_with_input(
            BenchmarkId::new("steal_batch", victim_size),
            &victim_size,
            |b, &victim_size| {
                b.iter_batched(
                    || {
                        let max_id = victim_size.saturating_sub(1);
                        let state = setup_runtime_state(max_id);
                        let victim = LocalQueue::new(Arc::clone(&state));
                        for i in 0..victim_size {
                            victim.push(task(i));
                        }
                        let stealer = victim.stealer();
                        let dest = LocalQueue::new(Arc::clone(&state));
                        (victim, stealer, dest)
                    },
                    |(_victim, stealer, dest)| {
                        let success = stealer.steal_batch(&dest);
                        black_box(success)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // Steal from empty queue
    group.bench_function("steal_empty", |b| {
        b.iter_batched(
            || {
                let victim = LocalQueue::new(setup_runtime_state(0));
                victim.stealer()
            },
            |stealer| {
                let result = stealer.steal();
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

// =============================================================================
// THROUGHPUT BENCHMARKS
// =============================================================================

fn bench_scheduler_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/throughput");
    group.sample_size(50);

    // High-throughput scheduling workload
    for &count in &[1000, 10000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("schedule_pop_cycle", count),
            &count,
            |b, &count| {
                b.iter(|| {
                    let mut scheduler = Scheduler::new();
                    for i in 0..count as u32 {
                        scheduler.schedule(task(i), (i % 256) as u8);
                    }
                    let mut popped = 0;
                    while scheduler.pop().is_some() {
                        popped += 1;
                    }
                    black_box(popped)
                })
            },
        );
    }

    // Mixed lane throughput
    for &count in &[1000, 10000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("mixed_lane_cycle", count),
            &count,
            |b, &count| {
                b.iter(|| {
                    let mut scheduler = Scheduler::new();
                    for i in 0..count as u32 {
                        match i % 3 {
                            0 => scheduler.schedule(task(i), 0),
                            1 => scheduler
                                .schedule_timed(task(i), Time::from_nanos(u64::from(i) * 1000)),
                            _ => scheduler.schedule_cancel(task(i), 0),
                        }
                    }
                    let mut popped = 0;
                    while scheduler.pop().is_some() {
                        popped += 1;
                    }
                    black_box(popped)
                })
            },
        );
    }

    group.finish();
}

fn bench_scheduler_capacity_profiles(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/capacity_profiles");
    group.sample_size(30);
    let profiles: [(&str, Option<usize>); 4] = [
        ("default", None),
        ("cap_256", Some(256)),
        ("cap_512", Some(512)),
        ("cap_1024", Some(1024)),
    ];

    for (profile, capacity) in profiles {
        group.throughput(Throughput::Elements(BURST_TASKS as u64));
        group.bench_with_input(
            BenchmarkId::new("mixed_lane_burst", profile),
            &capacity,
            |b, &capacity| {
                b.iter(|| {
                    let mut scheduler =
                        capacity.map_or_else(Scheduler::new, Scheduler::with_capacity);

                    // Realistic burst profile:
                    // - mostly ready tasks
                    // - periodic cancel promotions
                    // - periodic timed work
                    for i in 0..BURST_TASKS as u32 {
                        match i % 10 {
                            0 => scheduler.schedule_cancel(task(i), 96),
                            1 => scheduler
                                .schedule_timed(task(i), Time::from_nanos(u64::from(i) * 1_000)),
                            _ => scheduler.schedule(task(i), (i % 32) as u8),
                        }
                    }

                    let mut popped = 0;
                    while scheduler.pop().is_some() {
                        popped += 1;
                    }
                    black_box(popped)
                })
            },
        );
    }

    group.finish();
}

// =============================================================================
// PARKER BENCHMARKS
// =============================================================================

fn bench_parker(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/parker");

    // Unpark-before-park (permit model, no blocking)
    group.bench_function("unpark_then_park", |b| {
        b.iter_batched(
            Parker::new,
            |parker| {
                parker.unpark();
                parker.park();
            },
            BatchSize::SmallInput,
        )
    });

    // Park with timeout (no notification, immediate timeout)
    group.bench_function("park_timeout_zero", |b| {
        b.iter_batched(
            Parker::new,
            |parker| {
                parker.park_timeout(Duration::from_nanos(0));
            },
            BatchSize::SmallInput,
        )
    });

    // Unpark-before-park cycle repeated (reuse)
    group.bench_function("park_unpark_cycle_100", |b| {
        b.iter_batched(
            Parker::new,
            |parker| {
                for _ in 0..100 {
                    parker.unpark();
                    parker.park();
                }
            },
            BatchSize::SmallInput,
        )
    });

    // Cross-thread unpark latency
    group.bench_function("cross_thread_unpark", |b| {
        b.iter_batched(
            || {
                let parker = Parker::new();
                let unparker = parker.clone();
                (parker, unparker)
            },
            |(parker, unparker)| {
                let handle = std::thread::spawn(move || {
                    unparker.unpark();
                });
                parker.park();
                handle.join().unwrap();
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

// =============================================================================
// INTRUSIVE QUEUE BENCHMARKS
// =============================================================================

fn bench_intrusive_ring(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/intrusive_ring");

    // Single push_back/pop_front cycle
    group.bench_function("push_pop_single", |b| {
        b.iter_batched(
            || {
                let arena = setup_arena(1);
                let ring = IntrusiveRing::new(QUEUE_TAG_READY);
                (arena, ring)
            },
            |(mut arena, mut ring)| {
                ring.push_back(task(0), &mut arena);
                let result = ring.pop_front(&mut arena);
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });

    // Batch push then pop (compare with VecDeque)
    for &count in &[10, 100, 1000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("push_then_pop", count),
            &count,
            |b, &count| {
                let task_ids = tasks(count as usize);
                b.iter_batched(
                    || {
                        let arena = setup_arena(count as u32);
                        let ring = IntrusiveRing::new(QUEUE_TAG_READY);
                        (arena, ring, task_ids.clone())
                    },
                    |(mut arena, mut ring, tasks)| {
                        for t in &tasks {
                            ring.push_back(*t, &mut arena);
                        }
                        for _ in 0..tasks.len() {
                            let _ = black_box(ring.pop_front(&mut arena));
                        }
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // Interleaved push/pop
    group.bench_function("interleaved_push_pop", |b| {
        b.iter_batched(
            || {
                let arena = setup_arena(200);
                let ring = IntrusiveRing::new(QUEUE_TAG_READY);
                (arena, ring)
            },
            |(mut arena, mut ring)| {
                for i in 0..100u32 {
                    ring.push_back(task(i * 2), &mut arena);
                    ring.push_back(task(i * 2 + 1), &mut arena);
                    let _ = black_box(ring.pop_front(&mut arena));
                }
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_intrusive_stack(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/intrusive_stack");

    // Single push/pop cycle
    group.bench_function("push_pop_single", |b| {
        b.iter_batched(
            || {
                let arena = setup_arena(1);
                let stack = IntrusiveStack::new(QUEUE_TAG_READY);
                (arena, stack)
            },
            |(mut arena, mut stack)| {
                stack.push(task(0), &mut arena);
                let result = stack.pop(&mut arena);
                black_box(result)
            },
            BatchSize::SmallInput,
        )
    });

    // Batch push then pop (LIFO)
    for &count in &[10, 100, 1000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("push_then_pop", count),
            &count,
            |b, &count| {
                let task_ids = tasks(count as usize);
                b.iter_batched(
                    || {
                        let arena = setup_arena(count as u32);
                        let stack = IntrusiveStack::new(QUEUE_TAG_READY);
                        (arena, stack, task_ids.clone())
                    },
                    |(mut arena, mut stack, tasks)| {
                        for t in &tasks {
                            stack.push(*t, &mut arena);
                        }
                        for _ in 0..tasks.len() {
                            let _ = black_box(stack.pop(&mut arena));
                        }
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // Work stealing: push then steal half
    for &count in &[16usize, 64, 256] {
        group.bench_with_input(
            BenchmarkId::new("push_then_steal_batch", count),
            &count,
            |b, &count| {
                let task_ids = tasks(count);
                b.iter_batched(
                    || {
                        let count_u32 = u32::try_from(count).expect("count fits u32");
                        let arena = setup_arena(count_u32);
                        let stack = IntrusiveStack::new(QUEUE_TAG_READY);
                        (arena, stack, task_ids.clone())
                    },
                    |(mut arena, mut stack, tasks)| {
                        for t in &tasks {
                            stack.push(*t, &mut arena);
                        }
                        let stolen = stack.steal_batch(count / 2, &mut arena);
                        black_box(stolen)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

fn bench_intrusive_vs_vecdeque(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/intrusive_vs_vecdeque");
    group.sample_size(100);

    // Compare FIFO push/pop throughput
    for &count in &[100, 1000, 10000] {
        group.throughput(Throughput::Elements(count));

        // IntrusiveRing (allocation-free)
        group.bench_with_input(
            BenchmarkId::new("intrusive_ring", count),
            &count,
            |b, &count| {
                let task_ids = tasks(count as usize);
                b.iter_batched(
                    || {
                        let arena = setup_arena(count as u32);
                        let ring = IntrusiveRing::new(QUEUE_TAG_READY);
                        (arena, ring, task_ids.clone())
                    },
                    |(mut arena, mut ring, tasks)| {
                        for t in &tasks {
                            ring.push_back(*t, &mut arena);
                        }
                        let mut popped = 0;
                        while ring.pop_front(&mut arena).is_some() {
                            popped += 1;
                        }
                        black_box(popped)
                    },
                    BatchSize::SmallInput,
                )
            },
        );

        // VecDeque (allocates on growth)
        group.bench_with_input(BenchmarkId::new("vecdeque", count), &count, |b, &count| {
            let task_ids = tasks(count as usize);
            b.iter_batched(
                || {
                    let deque: VecDeque<TaskId> = VecDeque::new();
                    (deque, task_ids.clone())
                },
                |(mut deque, tasks)| {
                    for t in &tasks {
                        deque.push_back(*t);
                    }
                    let mut popped = 0;
                    while deque.pop_front().is_some() {
                        popped += 1;
                    }
                    black_box(popped)
                },
                BatchSize::SmallInput,
            )
        });

        // VecDeque with pre-allocated capacity
        group.bench_with_input(
            BenchmarkId::new("vecdeque_preallocated", count),
            &count,
            |b, &count| {
                let task_ids = tasks(count as usize);
                b.iter_batched(
                    || {
                        let deque: VecDeque<TaskId> = VecDeque::with_capacity(count as usize);
                        (deque, task_ids.clone())
                    },
                    |(mut deque, tasks)| {
                        for t in &tasks {
                            deque.push_back(*t);
                        }
                        let mut popped = 0;
                        while deque.pop_front().is_some() {
                            popped += 1;
                        }
                        black_box(popped)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

/// Compare IntrusiveRing vs BinaryHeap for the ready lane hot path.
///
/// This benchmark measures the operation targeted by bd-3nod: replacing
/// the BinaryHeap in the local priority scheduler's ready/cancel lanes with
/// an IntrusiveRing. For the common case (all tasks at priority 0), BinaryHeap
/// performs O(log n) comparisons per push/pop with no ordering benefit, while
/// IntrusiveRing performs O(1) with better cache locality.
#[allow(clippy::items_after_statements)]
fn bench_intrusive_vs_binaryheap(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/intrusive_vs_binaryheap");
    group.sample_size(100);

    #[derive(Debug, Clone, Eq, PartialEq)]
    struct HeapEntry {
        task_id: u32,
        priority: u8,
        generation: u64,
    }

    impl Ord for HeapEntry {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.priority
                .cmp(&other.priority)
                .then_with(|| other.generation.cmp(&self.generation))
        }
    }

    impl PartialOrd for HeapEntry {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    for &count in &[10, 100, 1000] {
        group.throughput(Throughput::Elements(count));

        // IntrusiveRing: O(1) push/pop, zero allocation
        group.bench_with_input(
            BenchmarkId::new("intrusive_ring", count),
            &count,
            |b, &count| {
                let task_ids = tasks(count as usize);
                b.iter_batched(
                    || {
                        let arena = setup_arena(count as u32);
                        let ring = IntrusiveRing::new(QUEUE_TAG_READY);
                        (arena, ring, task_ids.clone())
                    },
                    |(mut arena, mut ring, tasks)| {
                        for t in &tasks {
                            ring.push_back(*t, &mut arena);
                        }
                        let mut popped = 0;
                        while ring.pop_front(&mut arena).is_some() {
                            popped += 1;
                        }
                        black_box(popped)
                    },
                    BatchSize::SmallInput,
                )
            },
        );

        // BinaryHeap: O(log n) push/pop, allocating
        group.bench_with_input(
            BenchmarkId::new("binaryheap_uniform_priority", count),
            &count,
            |b, &count| {
                b.iter_batched(
                    BinaryHeap::new,
                    |mut heap: BinaryHeap<HeapEntry>| {
                        for i in 0..count {
                            heap.push(HeapEntry {
                                task_id: i as u32,
                                priority: 0,
                                generation: i,
                            });
                        }
                        let mut popped = 0;
                        while heap.pop().is_some() {
                            popped += 1;
                        }
                        black_box(popped)
                    },
                    BatchSize::SmallInput,
                )
            },
        );

        // PriorityScheduler: full schedule/pop cycle (actual hot path)
        group.bench_with_input(
            BenchmarkId::new("priority_scheduler", count),
            &count,
            |b, &count| {
                let task_ids = tasks(count as usize);
                b.iter_batched(
                    || (Scheduler::new(), task_ids.clone()),
                    |(mut scheduler, tasks)| {
                        for t in &tasks {
                            scheduler.schedule(*t, 0);
                        }
                        let mut popped = 0;
                        while scheduler.pop().is_some() {
                            popped += 1;
                        }
                        black_box(popped)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

// =============================================================================
// CANCEL-LANE PREEMPTION BENCHMARKS (bd-17uu)
// =============================================================================

#[allow(clippy::too_many_lines)]
fn bench_cancel_preemption(c: &mut Criterion) {
    use asupersync::runtime::scheduler::ThreeLaneScheduler;

    let mut group = c.benchmark_group("scheduler/cancel_preemption");

    // Cancel-only dispatch throughput: measures cancel dispatch latency
    // when no ready/timed work competes.
    for &count in &[100u64, 1000, 10000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("cancel_only_dispatch", count),
            &count,
            |b, &count| {
                b.iter_batched(
                    || {
                        let state = setup_runtime_state(count as u32);
                        let sched = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 8);
                        for i in 0..count as u32 {
                            sched.inject_cancel(task(i), 100);
                        }
                        sched
                    },
                    |mut sched| {
                        let mut workers = sched.take_workers().into_iter();
                        let mut worker = workers.next().unwrap();
                        let mut dispatched = 0u64;
                        while worker.next_task().is_some() {
                            dispatched += 1;
                        }
                        black_box(dispatched)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // Cancel + ready interleaved: measures fairness overhead when cancel
    // and ready work compete (cancel_streak_limit forces yields).
    for &limit in &[2usize, 4, 8, 16] {
        let cancel_n = 100u32;
        let ready_n = 100u32;
        let total = u64::from(cancel_n + ready_n);
        group.throughput(Throughput::Elements(total));
        group.bench_with_input(
            BenchmarkId::new("cancel_ready_mixed", limit),
            &limit,
            |b, &limit| {
                b.iter_batched(
                    || {
                        let max_id = cancel_n + ready_n;
                        let state = setup_runtime_state(max_id);
                        let sched = ThreeLaneScheduler::new_with_cancel_limit(1, &state, limit);
                        for i in 0..cancel_n {
                            sched.inject_cancel(task(i), 100);
                        }
                        for i in cancel_n..cancel_n + ready_n {
                            sched.inject_ready(task(i), 50);
                        }
                        sched
                    },
                    |mut sched| {
                        let mut workers = sched.take_workers().into_iter();
                        let mut worker = workers.next().unwrap();
                        let mut dispatched = 0u64;
                        for _ in 0..total {
                            if worker.next_task().is_some() {
                                dispatched += 1;
                            }
                        }
                        black_box(dispatched)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // Ready-lane stall under cancel flood: measures how quickly the first
    // ready task gets dispatched when cancel work dominates.
    for &limit in &[2usize, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("ready_stall_depth", limit),
            &limit,
            |b, &limit| {
                b.iter_batched(
                    || {
                        let cancel_n = 50u32;
                        let state = setup_runtime_state(cancel_n + 1);
                        let sched = ThreeLaneScheduler::new_with_cancel_limit(1, &state, limit);
                        for i in 0..cancel_n {
                            sched.inject_cancel(task(i), 100);
                        }
                        sched.inject_ready(task(cancel_n), 50);
                        sched
                    },
                    |mut sched| {
                        let mut workers = sched.take_workers().into_iter();
                        let mut worker = workers.next().unwrap();
                        let ready_id = task(50);
                        let mut steps = 0u64;
                        loop {
                            steps += 1;
                            if let Some(dispatched) = worker.next_task() {
                                if dispatched == ready_id {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                        black_box(steps)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

// =============================================================================
// MAIN
// =============================================================================

criterion_group!(
    benches,
    bench_local_queue,
    bench_global_queue,
    bench_priority_scheduler,
    bench_lane_priority,
    bench_work_stealing,
    bench_scheduler_throughput,
    bench_scheduler_capacity_profiles,
    bench_parker,
    bench_intrusive_ring,
    bench_intrusive_stack,
    bench_intrusive_vs_vecdeque,
    bench_intrusive_vs_binaryheap,
    bench_cancel_preemption,
);

criterion_main!(benches);
