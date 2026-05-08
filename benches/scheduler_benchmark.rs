#![cfg(feature = "test-internals")]
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
use std::sync::atomic::{AtomicUsize, Ordering};

use asupersync::record::task::TaskRecord;
use asupersync::runtime::RuntimeState;
use asupersync::runtime::config::BlockingPoolAffinityProfile;
use asupersync::runtime::scheduler::local_queue::Stealer;
use asupersync::runtime::scheduler::stealing::steal_task;
use asupersync::runtime::scheduler::three_lane::AdaptiveBatchSizingProfile;
use asupersync::runtime::scheduler::{
    GlobalQueue, IntrusiveRing, IntrusiveStack, LocalQueue, Parker, QUEUE_TAG_READY, Scheduler,
    ThreeLaneScheduler,
};
use asupersync::runtime::{BlockingPool, BlockingPoolOptions, Runtime, RuntimeBuilder};
use asupersync::sync::ContendedMutex;
use asupersync::types::{Budget, RegionId, TaskId, Time};
use asupersync::util::{Arena, DetRng};
use std::collections::{BinaryHeap, VecDeque};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

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
    RegionId::testing_default()
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

fn skipped_local_steal_case(victim_size: u32, local_prefix: u32) -> (LocalQueue, Stealer) {
    let max_id = victim_size.saturating_sub(1);
    let state = LocalQueue::test_state(max_id);
    {
        let mut guard = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for id in 0..local_prefix.min(victim_size) {
            guard
                .task_mut(task(id))
                .expect("task record missing")
                .mark_local();
        }
    }

    let victim = LocalQueue::new(Arc::clone(&state));
    for id in 0..victim_size {
        victim.push(task(id));
    }
    let stealer = victim.stealer();
    (victim, stealer)
}

fn run_global_ready_contention_case(
    producer_count: usize,
    tasks_per_producer: usize,
) -> (usize, u64, u64) {
    let total_tasks = producer_count * tasks_per_producer;
    let state = setup_runtime_state(total_tasks as u32 + 1);
    let scheduler = Arc::new(ThreeLaneScheduler::new(1, &state));
    let barrier = Arc::new(std::sync::Barrier::new(producer_count.max(1)));

    let inject_handles: Vec<_> = (0..producer_count)
        .map(|producer| {
            let scheduler = Arc::clone(&scheduler);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let base = producer * tasks_per_producer;
                for offset in 0..tasks_per_producer {
                    scheduler.inject_ready(task((base + offset) as u32), 50);
                }
            })
        })
        .collect();

    for handle in inject_handles {
        handle.join().expect("producer should complete");
    }

    let mut scheduler = match Arc::try_unwrap(scheduler) {
        Ok(scheduler) => scheduler,
        Err(_) => panic!("all producer handles should release the scheduler"),
    };
    let mut workers = scheduler.take_workers();
    let worker = workers.get_mut(0).expect("benchmark requires one worker");
    let mut total_dispatched = 0usize;
    while worker.next_task().is_some() {
        total_dispatched += 1;
    }

    let metrics = worker.preemption_metrics();
    (
        total_dispatched,
        metrics.global_ready_batch_drains,
        metrics.global_ready_batch_tasks,
    )
}

fn run_adaptive_batch_contention_case(
    producer_count: usize,
    tasks_per_producer: usize,
    fixed_batch_size: usize,
    adaptive_profile: Option<AdaptiveBatchSizingProfile>,
) -> (usize, u64, u64, usize) {
    let total_tasks = producer_count * tasks_per_producer;
    let state = setup_runtime_state(total_tasks as u32 + 1);
    let mut scheduler = ThreeLaneScheduler::new(1, &state);
    scheduler.set_steal_batch_size(fixed_batch_size.max(1));
    scheduler.set_adaptive_batch_profile_for_test(adaptive_profile);
    let scheduler = Arc::new(scheduler);
    let barrier = Arc::new(std::sync::Barrier::new(producer_count.max(1)));

    let inject_handles: Vec<_> = (0..producer_count)
        .map(|producer| {
            let scheduler = Arc::clone(&scheduler);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let base = producer * tasks_per_producer;
                for offset in 0..tasks_per_producer {
                    scheduler.inject_ready(task((base + offset) as u32), 50);
                }
            })
        })
        .collect();

    for handle in inject_handles {
        handle.join().expect("producer should complete");
    }

    let mut scheduler = match Arc::try_unwrap(scheduler) {
        Ok(scheduler) => scheduler,
        Err(_) => panic!("all producer handles should release the scheduler"),
    };
    let mut workers = scheduler.take_workers();
    let worker = workers.get_mut(0).expect("benchmark requires one worker");
    let mut total_dispatched = 0usize;
    while worker.next_task().is_some() {
        total_dispatched += 1;
    }

    let metrics = worker.preemption_metrics();
    let selected_batch_size = worker
        .adaptive_batch_snapshot_for_test()
        .map(|snapshot| snapshot.selected_batch_size)
        .unwrap_or(fixed_batch_size.max(1));
    (
        total_dispatched,
        metrics.global_ready_batch_drains,
        metrics.global_ready_batch_tasks,
        selected_batch_size,
    )
}

fn blocking_affinity_bench_pool(
    affinity_profile: BlockingPoolAffinityProfile,
    cohort_count: Option<usize>,
) -> BlockingPool {
    let options = BlockingPoolOptions {
        idle_timeout: Duration::from_millis(100),
        time_getter: Instant::now,
        sleep_fn: thread::sleep,
        thread_name_prefix: "bench-blocking-affinity".to_string(),
        on_thread_start: None,
        on_thread_stop: None,
        affinity_profile,
        cohort_count,
    };
    BlockingPool::with_config(2, 2, options)
}

#[derive(Clone, Copy)]
enum BlockingAffinityDispatchMode {
    CohortTargeted,
    UnhintedGlobal,
}

fn blocking_affinity_bench_runtime(
    affinity_profile: BlockingPoolAffinityProfile,
    worker_threads: usize,
    cohort_count: usize,
) -> Runtime {
    let worker_cohort_map: Vec<_> = (0..worker_threads)
        .map(|worker_slot| worker_slot % cohort_count.max(1))
        .collect();
    RuntimeBuilder::new()
        .worker_threads(worker_threads)
        .worker_cohorts(worker_cohort_map)
        .blocking_threads(2, 2)
        .blocking_affinity_profile(affinity_profile)
        .build()
        .expect("blocking affinity benchmark runtime should build")
}

fn run_blocking_affinity_saturation_case(
    affinity_profile: BlockingPoolAffinityProfile,
    cohort_count: usize,
    queued_task_count: usize,
) -> (usize, usize, usize) {
    let pool = blocking_affinity_bench_pool(affinity_profile, Some(cohort_count));
    let start_barrier = Arc::new(Barrier::new(3));
    let release_barrier = Arc::new(Barrier::new(3));

    let blocker0_start = Arc::clone(&start_barrier);
    let blocker0_release = Arc::clone(&release_barrier);
    let blocker0 = pool.spawn_on_cohort(0, move || {
        blocker0_start.wait();
        blocker0_release.wait();
    });

    let blocker1_start = Arc::clone(&start_barrier);
    let blocker1_release = Arc::clone(&release_barrier);
    let blocker1 = pool.spawn_on_cohort(1 % cohort_count.max(1), move || {
        blocker1_start.wait();
        blocker1_release.wait();
    });

    start_barrier.wait();

    let queued_handles: Vec<_> = (0..queued_task_count)
        .map(|_| pool.spawn_on_cohort(0, thread::yield_now))
        .collect();

    release_barrier.wait();

    blocker0.wait();
    blocker1.wait();
    for handle in queued_handles {
        handle.wait();
    }

    let metrics = pool.affinity_metrics();
    assert!(
        pool.shutdown_and_wait(Duration::from_secs(1)),
        "blocking affinity bench pool should shutdown cleanly"
    );
    (
        metrics.local_queue_dispatches,
        metrics.spill_dispatches,
        metrics.fallback_dispatches,
    )
}

fn run_blocking_affinity_mixed_case(
    affinity_profile: BlockingPoolAffinityProfile,
    cohort_count: usize,
    queued_task_count: usize,
    async_coordinator_task_count: usize,
    dispatch_mode: BlockingAffinityDispatchMode,
) -> (usize, usize, usize) {
    let runtime = blocking_affinity_bench_runtime(affinity_profile, 2, cohort_count);
    let blocking_handle = runtime
        .blocking_handle()
        .expect("mixed blocking affinity benchmark should expose a blocking handle");
    let start_barrier = Arc::new(Barrier::new(3));
    let release_barrier = Arc::new(Barrier::new(3));

    let blocker0_start = Arc::clone(&start_barrier);
    let blocker0_release = Arc::clone(&release_barrier);
    let blocker0 = match dispatch_mode {
        BlockingAffinityDispatchMode::CohortTargeted => runtime
            .spawn_blocking_on_cohort(0, move || {
                blocker0_start.wait();
                blocker0_release.wait();
            })
            .expect("mixed benchmark should accept cohort-0 blocker"),
        BlockingAffinityDispatchMode::UnhintedGlobal => runtime
            .spawn_blocking(move || {
                blocker0_start.wait();
                blocker0_release.wait();
            })
            .expect("mixed benchmark should accept unhinted blocker"),
    };

    let blocker1_start = Arc::clone(&start_barrier);
    let blocker1_release = Arc::clone(&release_barrier);
    let blocker1 = match dispatch_mode {
        BlockingAffinityDispatchMode::CohortTargeted => runtime
            .spawn_blocking_on_cohort(1 % cohort_count.max(1), move || {
                blocker1_start.wait();
                blocker1_release.wait();
            })
            .expect("mixed benchmark should accept cohort-1 blocker"),
        BlockingAffinityDispatchMode::UnhintedGlobal => runtime
            .spawn_blocking(move || {
                blocker1_start.wait();
                blocker1_release.wait();
            })
            .expect("mixed benchmark should accept unhinted blocker"),
    };

    start_barrier.wait();

    let base_spawn_requests = queued_task_count / async_coordinator_task_count.max(1);
    let remainder = queued_task_count % async_coordinator_task_count.max(1);
    let queued_handles = runtime.block_on(async {
        let runtime_handle =
            Runtime::current_handle().expect("mixed benchmark should run inside a runtime");
        let mut handles = Vec::with_capacity(queued_task_count);
        for coordinator_index in 0..async_coordinator_task_count {
            let spawn_requests = base_spawn_requests + usize::from(coordinator_index < remainder);
            for _ in 0..spawn_requests {
                let handle = match dispatch_mode {
                    BlockingAffinityDispatchMode::CohortTargeted => runtime_handle
                        .spawn_blocking_on_cohort(0, thread::yield_now)
                        .expect("mixed benchmark should enqueue cohort-targeted helper"),
                    BlockingAffinityDispatchMode::UnhintedGlobal => runtime_handle
                        .spawn_blocking(thread::yield_now)
                        .expect("mixed benchmark should enqueue unhinted helper"),
                };
                handles.push(handle);
            }
            asupersync::runtime::yield_now().await;
        }
        handles
    });

    release_barrier.wait();

    blocker0.wait();
    blocker1.wait();
    for handle in queued_handles {
        handle.wait();
    }

    let metrics = blocking_handle.affinity_metrics();
    (
        metrics.local_queue_dispatches,
        metrics.spill_dispatches,
        metrics.fallback_dispatches,
    )
}

// =============================================================================
// LOCAL QUEUE BENCHMARKS
// =============================================================================

fn bench_local_queue(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/local_queue");

    // Single push/pop cycle
    group.bench_function("push_pop_single", |b: &mut criterion::Bencher| {
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
    group.bench_function("interleaved_push_pop", |b: &mut criterion::Bencher| {
        b.iter_batched(
            || local_queue(199),
            |queue: LocalQueue| {
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

fn bench_local_queue_push_many(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/local_queue_push_many");
    group.warm_up_time(Duration::from_millis(200));
    group.measurement_time(Duration::from_millis(600));
    group.sample_size(30);

    for &count in &[8usize, 32, 128, 512] {
        group.throughput(Throughput::Elements(count as u64));
        let task_ids = tasks(count);
        let max_id = count as u32 - 1;

        group.bench_with_input(
            BenchmarkId::new("push_many", count),
            &count,
            |b, &_count| {
                b.iter_batched(
                    || (local_queue(max_id), task_ids.clone()),
                    |(queue, task_ids)| {
                        queue.push_many(black_box(&task_ids));
                        black_box(queue.len())
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

// =============================================================================
// GLOBAL QUEUE BENCHMARKS
// =============================================================================

fn bench_global_queue(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/global_queue");

    // Single push/pop
    group.bench_function("push_pop_single", |b: &mut criterion::Bencher| {
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

    group.throughput(Throughput::Elements((8 * 2_048) as u64));
    group.bench_function("contention_mpmc_8x8", |b: &mut criterion::Bencher| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let queue = Arc::new(GlobalQueue::new());
                let producers = 8usize;
                let consumers = 8usize;
                let items_per_producer = 2_048usize;
                let total_items = producers * items_per_producer;
                let consumed = Arc::new(AtomicUsize::new(0));
                let barrier = Arc::new(std::sync::Barrier::new(producers + consumers));
                let start = std::time::Instant::now();

                thread::scope(|scope| {
                    for producer in 0..producers {
                        let queue = Arc::clone(&queue);
                        let barrier = Arc::clone(&barrier);
                        scope.spawn(move || {
                            barrier.wait();
                            let base = producer * items_per_producer;
                            for offset in 0..items_per_producer {
                                queue.push(task((base + offset) as u32));
                            }
                        });
                    }

                    for _ in 0..consumers {
                        let queue = Arc::clone(&queue);
                        let barrier = Arc::clone(&barrier);
                        let consumed = Arc::clone(&consumed);
                        scope.spawn(move || {
                            barrier.wait();
                            loop {
                                let already = consumed.load(Ordering::Acquire);
                                if already >= total_items {
                                    break;
                                }
                                if queue.pop().is_some() {
                                    let previous = consumed.fetch_add(1, Ordering::AcqRel);
                                    if previous + 1 >= total_items {
                                        break;
                                    }
                                } else {
                                    std::hint::spin_loop();
                                }
                            }
                        });
                    }
                });

                total += start.elapsed();
                black_box(consumed.load(Ordering::Relaxed));
            }
            total
        })
    });

    group.finish();
}

// =============================================================================
// PRIORITY SCHEDULER BENCHMARKS
// =============================================================================

fn bench_priority_scheduler(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/priority");

    // Ready lane schedule/pop
    group.bench_function("schedule_ready_pop", |b: &mut criterion::Bencher| {
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
    group.bench_function("schedule_cancel_pop", |b: &mut criterion::Bencher| {
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
    group.bench_function("schedule_timed_pop", |b: &mut criterion::Bencher| {
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
    group.bench_function("dedup_same_task", |b: &mut criterion::Bencher| {
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

    for &count in &[256usize, 4096, 16_384] {
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::new("promote_ready_to_cancel", count),
            &count,
            |b, &count| {
                let task_ids = tasks(count);
                let promoted = task_ids[count / 2];
                b.iter_batched(
                    || {
                        let mut scheduler = Scheduler::with_capacity(count);
                        for (i, task_id) in task_ids.iter().enumerate() {
                            scheduler.schedule(*task_id, (i % 32) as u8);
                        }
                        (scheduler, promoted)
                    },
                    |(mut scheduler, promoted)| {
                        scheduler.schedule_cancel(promoted, 255);
                        black_box(scheduler.has_cancel_work())
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

fn bench_priority_observability(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/priority_observability");

    for &count in &[256usize, 4096, 16_384] {
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::new("has_runnable_work_ready", count),
            &count,
            |b, &count| {
                b.iter_batched(
                    || {
                        let mut scheduler = Scheduler::with_capacity(count);
                        for i in 0..count as u32 {
                            scheduler.schedule(task(i), (i % 256) as u8);
                        }
                        scheduler
                    },
                    |mut scheduler| {
                        let mut observed = false;
                        for _ in 0..128 {
                            observed ^= scheduler.has_runnable_work(Time::ZERO);
                        }
                        black_box(observed)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("next_deadline_timed", count),
            &count,
            |b, &count| {
                b.iter_batched(
                    || {
                        let mut scheduler = Scheduler::with_capacity(count);
                        for i in 0..count as u32 {
                            scheduler.schedule_timed(task(i), Time::from_nanos(u64::from(i) + 1));
                        }
                        scheduler
                    },
                    |mut scheduler| {
                        let mut observed = None;
                        for _ in 0..128 {
                            observed = scheduler.next_deadline();
                        }
                        black_box(observed)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

// =============================================================================
// LANE PRIORITY ORDERING BENCHMARKS
// =============================================================================

fn bench_lane_priority(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/lane_priority");

    // Mixed lanes: cancel > timed > ready ordering
    group.bench_function("mixed_lanes_pop_order", |b: &mut criterion::Bencher| {
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
    group.bench_function("timed_edf_ordering", |b: &mut criterion::Bencher| {
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
    group.bench_function("ready_priority_ordering", |b: &mut criterion::Bencher| {
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
    group.bench_function("steal_single", |b: &mut criterion::Bencher| {
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
    group.bench_function("steal_empty", |b: &mut criterion::Bencher| {
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

    group.bench_function(
        "steal_single_skipped_local_frontier_256",
        |b: &mut criterion::Bencher| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let (victim, stealer) = skipped_local_steal_case(256, 7);
                    let start = std::time::Instant::now();
                    let result = stealer.steal();
                    total += start.elapsed();
                    black_box(result);
                    black_box(victim);
                }
                total
            });
        },
    );

    group.finish();
}

fn bench_steal_task(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/steal_task");
    group.warm_up_time(Duration::from_millis(200));
    group.measurement_time(Duration::from_millis(600));
    group.sample_size(30);

    for &stealer_count in &[2usize, 8] {
        group.bench_with_input(
            BenchmarkId::new("empty_queues", stealer_count),
            &stealer_count,
            |b, &stealer_count| {
                b.iter_batched(
                    || {
                        let stealers = (0..stealer_count)
                            .map(|_| LocalQueue::new(setup_runtime_state(0)).stealer())
                            .collect::<Vec<_>>();
                        (stealers, DetRng::new(42))
                    },
                    |(stealers, mut rng)| black_box(steal_task(&stealers, &mut rng)),
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

fn bench_try_steal_locality(c: &mut Criterion) {
    use asupersync::runtime::scheduler::ThreeLaneScheduler;

    let mut group = c.benchmark_group("scheduler/try_steal_locality");
    group.warm_up_time(Duration::from_millis(200));
    group.measurement_time(Duration::from_millis(600));
    group.sample_size(30);

    for &(cohort_count, worker_threads) in &[(1usize, 4usize), (2usize, 4usize), (4usize, 8usize)] {
        group.bench_with_input(
            BenchmarkId::new("fast_queue_preferred_first", cohort_count),
            &cohort_count,
            |b, _| {
                b.iter_batched(
                    || {
                        let state = LocalQueue::test_state(32);
                        let mut scheduler = ThreeLaneScheduler::new(worker_threads, &state);
                        let worker_to_cohort = (0..worker_threads)
                            .map(|worker| worker % cohort_count)
                            .collect::<Vec<_>>();
                        scheduler
                            .set_worker_cohort_map(&worker_to_cohort)
                            .expect("bench cohort map should apply");

                        let thief_id = worker_threads - 1;
                        let thief_cohort = worker_to_cohort[thief_id];
                        let local_victim = (0..thief_id)
                            .find(|&worker| worker_to_cohort[worker] == thief_cohort)
                            .unwrap_or(0);
                        scheduler.seed_worker_fast_ready_for_test(local_victim, task(1));

                        if let Some(remote_victim) =
                            (0..thief_id).find(|&worker| worker_to_cohort[worker] != thief_cohort)
                        {
                            scheduler.seed_worker_fast_ready_for_test(remote_victim, task(2));
                        }

                        let mut workers = scheduler.take_workers();
                        workers.swap_remove(thief_id)
                    },
                    |mut worker| black_box(worker.bench_try_steal()),
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

fn bench_global_ready_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/global_ready_contention");
    group.warm_up_time(Duration::from_millis(200));
    group.measurement_time(Duration::from_millis(600));
    group.sample_size(20);

    for &(producer_count, tasks_per_producer) in &[
        (1usize, 32usize),
        (8usize, 64usize),
        (32usize, 32usize),
        (64usize, 32usize),
    ] {
        let total_tasks = producer_count * tasks_per_producer;
        group.throughput(Throughput::Elements(total_tasks as u64));
        group.bench_with_input(
            BenchmarkId::new("inject_ready_then_drain", producer_count),
            &producer_count,
            |b, _| {
                b.iter_batched(
                    || (),
                    |_| {
                        black_box(run_global_ready_contention_case(
                            producer_count,
                            tasks_per_producer,
                        ))
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

fn bench_adaptive_batch_sizing(c: &mut Criterion) {
    let mut group = c.benchmark_group("scheduler/adaptive_batch_sizing");
    group.warm_up_time(Duration::from_millis(200));
    group.measurement_time(Duration::from_millis(600));
    group.sample_size(20);

    let adaptive_profile = AdaptiveBatchSizingProfile {
        enabled: true,
        min_batch_size: 1,
        max_batch_size: 8,
        scale_up_ready_depth: 32,
        scale_up_in_flight: 4,
        scale_up_claim_failures: 1,
        cancel_debt_floor: 4,
        cooldown_steps: 2,
    };

    for &(producer_count, tasks_per_producer, fixed_batch_size) in &[
        (1usize, 32usize, 4usize),
        (8usize, 64usize, 1usize),
        (32usize, 32usize, 1usize),
        (64usize, 32usize, 1usize),
    ] {
        let total_tasks = producer_count * tasks_per_producer;
        group.throughput(Throughput::Elements(total_tasks as u64));
        group.bench_with_input(
            BenchmarkId::new("fixed", producer_count),
            &producer_count,
            |b, _| {
                b.iter_batched(
                    || (),
                    |_| {
                        black_box(run_adaptive_batch_contention_case(
                            producer_count,
                            tasks_per_producer,
                            fixed_batch_size,
                            None,
                        ))
                    },
                    BatchSize::SmallInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("adaptive", producer_count),
            &producer_count,
            |b, _| {
                b.iter_batched(
                    || (),
                    |_| {
                        black_box(run_adaptive_batch_contention_case(
                            producer_count,
                            tasks_per_producer,
                            fixed_batch_size,
                            Some(adaptive_profile),
                        ))
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

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
    group.bench_function("unpark_then_park", |b: &mut criterion::Bencher| {
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
    group.bench_function("park_timeout_zero", |b: &mut criterion::Bencher| {
        b.iter_batched(
            Parker::new,
            |parker| {
                parker.park_timeout(Duration::from_nanos(0));
            },
            BatchSize::SmallInput,
        )
    });

    // Unpark-before-park cycle repeated (reuse)
    group.bench_function("park_unpark_cycle_100", |b: &mut criterion::Bencher| {
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
    group.bench_function("cross_thread_unpark", |b: &mut criterion::Bencher| {
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
    group.bench_function("push_pop_single", |b: &mut criterion::Bencher| {
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
    group.bench_function("interleaved_push_pop", |b: &mut criterion::Bencher| {
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
    group.bench_function("push_pop_single", |b: &mut criterion::Bencher| {
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
                        let mut stolen = Vec::new();
                        stack.steal_batch(count / 2, &mut arena, &mut stolen);
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
// THREE-LANE DECISION MICROBENCHMARKS
// =============================================================================

fn bench_three_lane_decision(c: &mut Criterion) {
    use asupersync::runtime::scheduler::{SchedulerWorkloadClass, ThreeLaneScheduler};

    let mut group = c.benchmark_group("scheduler/three_lane_decision");
    group.sample_size(30);

    #[derive(Clone, Copy)]
    enum LockCommand {
        HoldForMicros(u64),
        Stop,
    }

    group.bench_function("fast_ready_uncontended", |b: &mut criterion::Bencher| {
        let state = setup_runtime_state(2);
        let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 16);
        let mut worker = scheduler
            .take_workers()
            .into_iter()
            .next()
            .expect("single worker");
        worker.schedule_local(task(2), 200);
        let fast_queue = worker.bench_fast_ready_queue();

        b.iter_custom(|iters| {
            let loops = iters.clamp(1, 1024);
            let mut total = Duration::ZERO;
            for _ in 0..loops {
                fast_queue.push(task(1));
                let start = std::time::Instant::now();
                let dispatched = worker.bench_try_phase3_ready_work();
                total += start.elapsed();
                black_box(dispatched);
            }
            total.mul_f64(iters as f64 / loops as f64)
        });
    });

    group.bench_function(
        "fast_ready_local_peek_contended",
        |b: &mut criterion::Bencher| {
            let state = setup_runtime_state(2);
            let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 16);
            let mut worker = scheduler
                .take_workers()
                .into_iter()
                .next()
                .expect("single worker");
            worker.schedule_local(task(2), 200);
            let fast_queue = worker.bench_fast_ready_queue();
            let local = worker.bench_local_priority_scheduler();
            let (cmd_tx, cmd_rx) = std::sync::mpsc::sync_channel::<LockCommand>(0);
            let (ack_tx, ack_rx) = std::sync::mpsc::sync_channel::<()>(0);
            let holder = thread::spawn(move || {
                while let Ok(cmd) = cmd_rx.recv() {
                    match cmd {
                        LockCommand::HoldForMicros(micros) => {
                            let _guard = local.lock();
                            ack_tx.send(()).expect("ack hold");
                            let deadline =
                                std::time::Instant::now() + Duration::from_micros(micros);
                            while std::time::Instant::now() < deadline {
                                std::hint::spin_loop();
                            }
                        }
                        LockCommand::Stop => break,
                    }
                }
            });

            b.iter_custom(|iters| {
                let loops = iters.clamp(1, 1024);
                let mut total = Duration::ZERO;
                for _ in 0..loops {
                    fast_queue.push(task(1));
                    cmd_tx
                        .send(LockCommand::HoldForMicros(50))
                        .expect("request held local lock");
                    ack_rx.recv().expect("local lock held");
                    let start = std::time::Instant::now();
                    let dispatched = worker.bench_try_phase3_ready_work();
                    total += start.elapsed();
                    black_box(dispatched);
                }
                total.mul_f64(iters as f64 / loops as f64)
            });

            cmd_tx.send(LockCommand::Stop).expect("stop holder");
            holder.join().expect("join holder");
        },
    );

    for &count in &[64usize, 512] {
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::new("global_ready_burst", count),
            &count,
            |b, &count| {
                b.iter_batched(
                    || {
                        let max_id = count as u32 - 1;
                        let state = setup_runtime_state(max_id);
                        let mut scheduler =
                            ThreeLaneScheduler::new_with_cancel_limit(1, &state, 16);
                        for i in 0..count as u32 {
                            scheduler.inject_ready(task(i), 50);
                        }
                        scheduler
                            .take_workers()
                            .into_iter()
                            .next()
                            .expect("single worker")
                    },
                    |mut worker| {
                        let mut drained = 0usize;
                        while worker.bench_try_phase3_ready_work().is_some() {
                            drained += 1;
                        }
                        black_box(drained)
                    },
                    BatchSize::PerIteration,
                )
            },
        );
    }

    for &(label, sample_window) in &[
        ("global_ready_burst_evidence_off", 0usize),
        ("global_ready_burst_evidence_on", 256usize),
    ] {
        let count = 256usize;
        group.throughput(Throughput::Elements(count as u64));
        group.bench_function(label, |b: &mut criterion::Bencher| {
            b.iter_batched(
                || {
                    let max_id = count as u32 - 1;
                    let state = setup_runtime_state(max_id);
                    let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 16);
                    if sample_window > 0 {
                        scheduler.set_scheduler_evidence_window(sample_window);
                    }
                    for i in 0..count as u32 {
                        scheduler.inject_ready(task(i), 50);
                    }
                    scheduler
                },
                |mut scheduler| {
                    let mut drained = 0usize;
                    {
                        let worker = scheduler.worker_mut_for_test(0);
                        while worker.next_task().is_some() {
                            drained += 1;
                        }
                    }
                    if sample_window > 0 {
                        black_box(scheduler.scheduler_evidence_artifact(
                            "bench-capture",
                            SchedulerWorkloadClass::MixedBurst,
                            256,
                        ));
                    }
                    black_box(drained)
                },
                BatchSize::PerIteration,
            )
        });
    }

    group.finish();
}

// =============================================================================
// ADAPTIVE CANCEL-STREAK POLICY BENCHMARKS (UCB1 vs EXP3)
// =============================================================================

fn bench_adaptive_cancel_streak_policy(c: &mut Criterion) {
    use asupersync::runtime::scheduler::three_lane::{
        AdaptiveCancelStreakPolicyBench, AdaptivePolicyBenchSnapshot,
    };

    let mut group = c.benchmark_group("scheduler/adaptive_cancel_streak");
    group.sample_size(50);

    // Helper function to create test epoch snapshots
    fn test_snapshot(
        potential: f64,
        deadline_pressure: f64,
        base_exceed: u64,
        eff_exceed: u64,
        fallback: u64,
    ) -> AdaptivePolicyBenchSnapshot {
        AdaptivePolicyBenchSnapshot::new(
            potential,
            deadline_pressure,
            base_exceed,
            eff_exceed,
            fallback,
        )
    }

    // UCB1 arm selection performance
    group.bench_function("ucb1_arm_selection", |b: &mut criterion::Bencher| {
        b.iter_batched(
            || {
                let mut policy = AdaptiveCancelStreakPolicyBench::new(10);
                // Pre-train with some data
                let start = test_snapshot(100.0, 0.25, 0, 0, 0);
                for i in 0..20 {
                    policy.force_selected_arm(i % policy.arm_count());
                    policy.begin_epoch(start);
                    let end = if i % 3 == 0 {
                        test_snapshot(120.0, 0.6, 2, 3, 1)
                    } else {
                        test_snapshot(80.0, 0.2, 0, 0, 0)
                    };
                    let _reward = policy.complete_epoch(end);
                }
                policy
            },
            |policy| {
                // Benchmark arm selection
                let selected_arm = policy.select_arm_ucb();
                black_box(selected_arm)
            },
            BatchSize::SmallInput,
        )
    });

    // UCB1 epoch completion performance
    group.bench_function("ucb1_epoch_completion", |b: &mut criterion::Bencher| {
        b.iter_batched(
            || {
                let mut policy = AdaptiveCancelStreakPolicyBench::new(10);
                let start = test_snapshot(100.0, 0.25, 0, 0, 0);
                policy.begin_epoch(start);
                policy
            },
            |mut policy| {
                let end = test_snapshot(110.0, 0.4, 1, 1, 0);
                let reward = policy.complete_epoch(end);
                black_box(reward)
            },
            BatchSize::SmallInput,
        )
    });

    // UCB1 convergence simulation (measures how quickly it converges to optimal arm)
    for &epochs in &[50, 100, 200] {
        group.throughput(Throughput::Elements(epochs));
        group.bench_with_input(
            BenchmarkId::new("ucb1_convergence_simulation", epochs),
            &epochs,
            |b, &epochs| {
                b.iter_batched(
                    || {
                        let policy = AdaptiveCancelStreakPolicyBench::new(10);
                        policy
                    },
                    |mut policy| {
                        let start = test_snapshot(100.0, 0.25, 0, 0, 0);

                        // Simulate epochs with arm 2 being optimal (gets best rewards)
                        let mut total_reward = 0.0;
                        for _epoch in 0..epochs as usize {
                            let selected_arm = policy.select_arm_ucb();
                            policy.force_selected_arm(selected_arm);
                            policy.begin_epoch(start);

                            // Arm 2 gets better rewards, others get worse
                            let end = if selected_arm == 2 {
                                test_snapshot(90.0, 0.15, 0, 0, 0) // Good performance
                            } else {
                                test_snapshot(130.0, 0.7, 3, 4, 2) // Poor performance
                            };

                            if let Some(reward) = policy.complete_epoch(end) {
                                total_reward += reward;
                            }
                        }
                        black_box(total_reward)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // Compare update overhead for different prior-history masses. The policy
    // has a fixed arm table, so varying synthetic pull mass is the honest
    // state dimension to benchmark here.
    for &history_mass in &[1u64, 10, 100] {
        group.bench_with_input(
            BenchmarkId::new("ucb1_arm_update_overhead", history_mass),
            &history_mass,
            |b, &history_mass| {
                b.iter_batched(
                    || {
                        let mut policy = AdaptiveCancelStreakPolicyBench::new(10);
                        policy.seed_history([0.5; 5], [history_mass as f64; 5]);
                        let start = test_snapshot(100.0, 0.25, 0, 0, 0);
                        policy.begin_epoch(start);
                        policy
                    },
                    |mut policy| {
                        let end = test_snapshot(120.0, 0.5, 2, 2, 1);
                        let reward = policy.complete_epoch(end);
                        black_box(reward)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // Benchmark adaptation under different pressure patterns
    group.bench_function("ucb1_pressure_adaptation", |b: &mut criterion::Bencher| {
        b.iter_batched(
            || {
                let policy = AdaptiveCancelStreakPolicyBench::new(10);
                policy
            },
            |mut policy| {
                let start = test_snapshot(100.0, 0.25, 0, 0, 0);
                let pressure_patterns = [
                    (70.0, 0.1, 0, 0, 0),  // Very relaxed
                    (110.0, 0.5, 2, 3, 1), // Moderate pressure
                    (150.0, 0.9, 5, 7, 3), // High pressure
                ];

                let mut total_rewards = 0.0;
                for &(potential, deadline_pressure, base_exceed, eff_exceed, fallback) in
                    &pressure_patterns
                {
                    for _ in 0..10 {
                        let arm = policy.select_arm_ucb();
                        policy.force_selected_arm(arm);
                        policy.begin_epoch(start);

                        let end = test_snapshot(
                            potential,
                            deadline_pressure,
                            base_exceed,
                            eff_exceed,
                            fallback,
                        );

                        if let Some(reward) = policy.complete_epoch(end) {
                            total_rewards += reward;
                        }
                    }
                }
                black_box(total_rewards)
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_blocking_pool_affinity(c: &mut Criterion) {
    let mut group = c.benchmark_group("runtime/blocking_pool_affinity");
    group.throughput(Throughput::Elements(4));

    group.bench_function("disabled_saturation", |b: &mut criterion::Bencher| {
        b.iter_batched(
            || (),
            |_| {
                black_box(run_blocking_affinity_saturation_case(
                    BlockingPoolAffinityProfile::Disabled,
                    2,
                    4,
                ))
            },
            BatchSize::PerIteration,
        )
    });

    group.bench_function("cohort_biased_saturation", |b: &mut criterion::Bencher| {
        b.iter_batched(
            || (),
            |_| {
                black_box(run_blocking_affinity_saturation_case(
                    BlockingPoolAffinityProfile::CohortBiased {
                        local_queue_soft_limit: 1,
                        spill_check_interval: 1,
                    },
                    2,
                    4,
                ))
            },
            BatchSize::PerIteration,
        )
    });

    group.bench_function(
        "mixed_async_blocking_disabled",
        |b: &mut criterion::Bencher| {
            b.iter_batched(
                || (),
                |_| {
                    black_box(run_blocking_affinity_mixed_case(
                        BlockingPoolAffinityProfile::Disabled,
                        2,
                        4,
                        2,
                        BlockingAffinityDispatchMode::CohortTargeted,
                    ))
                },
                BatchSize::PerIteration,
            )
        },
    );

    group.bench_function(
        "mixed_async_blocking_cohort_biased",
        |b: &mut criterion::Bencher| {
            b.iter_batched(
                || (),
                |_| {
                    black_box(run_blocking_affinity_mixed_case(
                        BlockingPoolAffinityProfile::CohortBiased {
                            local_queue_soft_limit: 1,
                            spill_check_interval: 1,
                        },
                        2,
                        4,
                        2,
                        BlockingAffinityDispatchMode::CohortTargeted,
                    ))
                },
                BatchSize::PerIteration,
            )
        },
    );

    group.bench_function(
        "mixed_async_unhinted_disabled",
        |b: &mut criterion::Bencher| {
            b.iter_batched(
                || (),
                |_| {
                    black_box(run_blocking_affinity_mixed_case(
                        BlockingPoolAffinityProfile::Disabled,
                        2,
                        4,
                        2,
                        BlockingAffinityDispatchMode::UnhintedGlobal,
                    ))
                },
                BatchSize::PerIteration,
            )
        },
    );

    group.bench_function(
        "mixed_async_unhinted_cohort_biased",
        |b: &mut criterion::Bencher| {
            b.iter_batched(
                || (),
                |_| {
                    black_box(run_blocking_affinity_mixed_case(
                        BlockingPoolAffinityProfile::CohortBiased {
                            local_queue_soft_limit: 1,
                            spill_check_interval: 1,
                        },
                        2,
                        4,
                        2,
                        BlockingAffinityDispatchMode::UnhintedGlobal,
                    ))
                },
                BatchSize::PerIteration,
            )
        },
    );

    group.finish();
}

// =============================================================================
// MAIN
// =============================================================================

criterion_group!(
    benches,
    bench_local_queue,
    bench_local_queue_push_many,
    bench_global_queue,
    bench_priority_scheduler,
    bench_priority_observability,
    bench_lane_priority,
    bench_work_stealing,
    bench_steal_task,
    bench_try_steal_locality,
    bench_global_ready_contention,
    bench_adaptive_batch_sizing,
    bench_scheduler_throughput,
    bench_scheduler_capacity_profiles,
    bench_parker,
    bench_intrusive_ring,
    bench_intrusive_stack,
    bench_intrusive_vs_vecdeque,
    bench_intrusive_vs_binaryheap,
    bench_cancel_preemption,
    bench_three_lane_decision,
    bench_adaptive_cancel_streak_policy,
    bench_blocking_pool_affinity,
);

criterion_main!(benches);
