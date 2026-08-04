//! Task-state hot-read benchmarks
//! (br-asupersync-sched-hot-path-perf-bt4y5f.1; decision instrument for the
//! seqlock/BRAVO hot-read lever br-asupersync-sched-hot-path-perf-bt4y5f.4).
//!
//! The scheduler's poll loop repeatedly answers "what state is this task in,
//! and is it cancelling?" Today that read costs a `ContendedMutex<RuntimeState>`
//! lock acquisition plus an arena lookup per check. This bench pins that cost:
//!
//! - `locked_read_cycle`: single-thread floor — 256 lock→lookup→read cycles
//!   over a rotating index window in a 1024-task table.
//! - `locked_read_contended/{4,8}`: N barrier-synced reader threads each
//!   perform the same 256-read cycle concurrently against the same lock; the
//!   measured thread's round time includes the contention the seqlock lever
//!   (read-mostly, writer-serialized) is meant to remove.
//!
//! Reads are `record.state_name()` + `record.state.is_cancelling()` — the
//! exact state + cancel-flag pair named by the lever. Fixed table size, fixed
//! index walk, no randomness: iterations are directly comparable.

#![cfg(feature = "test-internals")]
#![allow(missing_docs)]

use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};

use asupersync::record::task::TaskRecord;
use asupersync::runtime::RuntimeState;
use asupersync::sync::ContendedMutex;
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::ArenaIndex;

mod phase6_gate;

const TABLE_TASKS: usize = 1024;
const READS_PER_ITER: usize = 256;

fn task(id: usize) -> TaskId {
    TaskId::new_for_test(u32::try_from(id).expect("bench task ids fit u32"), 0)
}

fn setup_state() -> (Arc<ContendedMutex<RuntimeState>>, Vec<ArenaIndex>) {
    let mut state = RuntimeState::new();
    let mut handles = Vec::with_capacity(TABLE_TASKS);
    for i in 0..TABLE_TASKS {
        let record = TaskRecord::new(task(i), RegionId::testing_default(), Budget::INFINITE);
        handles.push(state.tasks.insert(record));
    }
    (Arc::new(ContendedMutex::new("bench_state", state)), handles)
}

/// One hot-read cycle: per read, acquire the state lock, look the record up,
/// and read the state + cancel flag — the current per-poll-check shape.
fn read_cycle(
    state: &ContendedMutex<RuntimeState>,
    handles: &[ArenaIndex],
    offset: usize,
) -> usize {
    let mut cancelling = 0usize;
    for i in 0..READS_PER_ITER {
        let handle = handles[(offset + i) % handles.len()];
        let guard = state.lock().expect("bench state lock");
        let record = guard.tasks.get(handle).expect("bench task exists");
        let name = record.state_name();
        if !name.is_empty() && record.state.is_cancelling() {
            cancelling += 1;
        }
    }
    cancelling
}

fn handle_window(handles: &[ArenaIndex], start: usize) -> Vec<ArenaIndex> {
    (0..handles.len())
        .map(|i| handles[(start + i) % handles.len()])
        .collect()
}

fn bench_locked_read_single(c: &mut Criterion) {
    let mut group = c.benchmark_group("sched/task_state");
    group.throughput(Throughput::Elements(READS_PER_ITER as u64));
    group.sample_size(20);

    let (state, handles) = setup_state();
    let mut offset = 0usize;
    group.bench_function("locked_read_cycle", |b| {
        b.iter(|| {
            let cancelling = read_cycle(black_box(&state), &handles, offset);
            offset = offset.wrapping_add(READS_PER_ITER);
            assert_eq!(cancelling, 0, "fresh records never report cancelling");
        });
    });

    group.finish();
}

fn bench_locked_read_contended(c: &mut Criterion) {
    let mut group = c.benchmark_group("sched/task_state");
    group.throughput(Throughput::Elements(READS_PER_ITER as u64));
    group.sample_size(20);

    for readers in [4usize, 8] {
        let (state, handles) = setup_state();
        let start = Arc::new(Barrier::new(readers + 1));
        let done = Arc::new(Barrier::new(readers + 1));
        let stop = Arc::new(AtomicBool::new(false));

        std::thread::scope(|scope| {
            for reader in 0..readers {
                let state = Arc::clone(&state);
                let start = Arc::clone(&start);
                let done = Arc::clone(&done);
                let stop = Arc::clone(&stop);
                // Each reader walks its own rotated window so threads touch
                // different records while sharing the one state lock.
                let window = handle_window(&handles, reader * (TABLE_TASKS / readers.max(1)));
                scope.spawn(move || {
                    let mut offset = 0usize;
                    loop {
                        start.wait();
                        if stop.load(Ordering::Acquire) {
                            break;
                        }
                        black_box(read_cycle(&state, &window, offset));
                        offset = offset.wrapping_add(READS_PER_ITER);
                        done.wait();
                    }
                });
            }

            let window = handle_window(&handles, TABLE_TASKS / 2);
            let mut offset = 0usize;
            group.bench_function(
                criterion::BenchmarkId::new("locked_read_contended", readers),
                |b| {
                    b.iter(|| {
                        start.wait();
                        let cancelling = read_cycle(black_box(&state), &window, offset);
                        offset = offset.wrapping_add(READS_PER_ITER);
                        done.wait();
                        assert_eq!(cancelling, 0, "fresh records never report cancelling");
                    });
                },
            );

            stop.store(true, Ordering::Release);
            start.wait();
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_locked_read_single,
    bench_locked_read_contended
);

fn main() {
    benches();
    Criterion::default().configure_from_args().final_summary();
    if let Err(error) = phase6_gate::run_phase6_p50_gate("sched/task_state/") {
        eprintln!("[PHASE6] baseline gate failed: {error}");
        std::process::exit(2);
    }
}
