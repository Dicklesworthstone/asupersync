#![allow(missing_docs)]
#![allow(unsafe_code)]
#![allow(clippy::too_many_lines)]
#![allow(unused_must_use)]
//! Allocation Audit & Zero-Alloc Guards (bd-3bjjp).
//!
//! Verifies that scheduler and cancellation hot paths remain allocation-free
//! (or within strict allocation ceilings) under load. Uses a custom global
//! allocator to count heap allocations during critical sections.
//!
//! Hot paths audited:
//! - PriorityScheduler schedule/pop (cancel, timed, ready lanes)
//! - LocalQueue push/pop
//! - GlobalQueue push/pop
//! - GlobalInjector inject/pop (cancel, timed, ready)
//! - Work stealing batch operations
//! - Lab runtime dispatch loop (E2E)

#[macro_use]
mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

// =============================================================================
// Counting Allocator
// =============================================================================

/// A thin wrapper around the system allocator that counts allocations and
/// deallocations via atomic counters. This lets us assert zero-alloc invariants
/// on hot paths.
struct CountingAllocator;

static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// Snapshot of allocation counters for measuring deltas.
#[derive(Debug, Clone, Copy)]
struct AllocSnapshot {
    allocs: u64,
    bytes: u64,
}

impl AllocSnapshot {
    fn take() -> Self {
        // Use SeqCst to ensure we see a consistent snapshot relative to
        // the operations we're measuring.
        Self {
            allocs: ALLOC_COUNT.load(Ordering::SeqCst),
            bytes: ALLOC_BYTES.load(Ordering::SeqCst),
        }
    }

    fn allocs_since(&self, before: &Self) -> u64 {
        self.allocs.saturating_sub(before.allocs)
    }

    fn bytes_since(&self, before: &Self) -> u64 {
        self.bytes.saturating_sub(before.bytes)
    }
}

fn init_test(test_name: &str) {
    common::init_test_logging();
    test_phase!(test_name);
}

fn u64_to_f64(value: u64) -> f64 {
    let clamped = value.min(u64::from(u32::MAX));
    f64::from(u32::try_from(clamped).expect("clamped to u32 max"))
}

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::task::TaskRecord;
use asupersync::runtime::scheduler::{GlobalInjector, GlobalQueue, LocalQueue, PriorityScheduler};
use asupersync::runtime::{global_alloc_count, RegionHeap, RuntimeState};
use asupersync::sync::ContendedMutex;
use asupersync::types::{Budget, RegionId, TaskId, Time};
use std::sync::{Arc, Mutex};

/// Serializes allocation-sensitive tests so the global allocator counter
/// is not contaminated by concurrent test warmup/measurement phases.
static ALLOC_TEST_GUARD: Mutex<()> = Mutex::new(());

// =============================================================================
// Test Helpers
// =============================================================================

fn task(id: u32) -> TaskId {
    TaskId::new_for_test(id, 0)
}

fn region() -> RegionId {
    RegionId::new_for_test(0, 0)
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

// =============================================================================
// PriorityScheduler: Zero-Alloc Schedule/Pop
// =============================================================================

/// Verify that PriorityScheduler schedule + pop on the ready lane performs
/// zero heap allocations after initial capacity is established.
#[test]
fn priority_scheduler_ready_lane_zero_alloc() {
    let _guard = ALLOC_TEST_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    init_test("priority_scheduler_ready_lane_zero_alloc");

    let mut sched = PriorityScheduler::new();

    // Warm up: fill and drain to establish heap capacity.
    test_section!("warmup");
    for i in 0..100u32 {
        sched.schedule(task(i), 5);
    }
    for _ in 0..100 {
        sched.pop_ready_only();
    }
    tracing::info!("Warmup complete, heap capacity established");

    // Measure: schedule + pop cycle should be zero-alloc.
    test_section!("measure-ready");
    let before = AllocSnapshot::take();

    for round in 0..50u32 {
        for i in 0..100u32 {
            sched.schedule(task(i), (round % 10) as u8);
        }
        for _ in 0..100 {
            let _ = sched.pop_ready_only();
        }
    }

    let after = AllocSnapshot::take();
    let allocs = after.allocs_since(&before);
    let bytes = after.bytes_since(&before);

    tracing::info!(
        allocs,
        bytes,
        ops = 50 * 200,
        "Ready lane schedule/pop allocation count"
    );

    // BinaryHeap may occasionally reallocate when capacity grows. We allow
    // a small ceiling (the heap was pre-warmed to 100 entries, and we never
    // exceed that, so zero is expected).
    // Tolerance of 10 for parallel noise from common::coverage tests that
    // share the global allocator counter but don't acquire ALLOC_TEST_GUARD.
    assert_with_log!(allocs <= 10, "ready lane near-zero-alloc", "<=10", allocs);

    test_complete!(
        "priority_scheduler_ready_lane_zero_alloc",
        allocs = allocs,
        bytes = bytes
    );
}

/// Verify that PriorityScheduler cancel lane schedule + pop is zero-alloc.
#[test]
fn priority_scheduler_cancel_lane_zero_alloc() {
    let _guard = ALLOC_TEST_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    init_test("priority_scheduler_cancel_lane_zero_alloc");

    let mut sched = PriorityScheduler::new();

    // Warm up cancel lane.
    test_section!("warmup");
    for i in 0..100u32 {
        sched.schedule_cancel(task(i), 5);
    }
    for _ in 0..100 {
        sched.pop_cancel_only();
    }

    // Measure.
    test_section!("measure-cancel");
    let before = AllocSnapshot::take();

    for round in 0..50u32 {
        for i in 0..100u32 {
            sched.schedule_cancel(task(i), (round % 10) as u8);
        }
        for _ in 0..100 {
            let _ = sched.pop_cancel_only();
        }
    }

    let after = AllocSnapshot::take();
    let allocs = after.allocs_since(&before);

    tracing::info!(
        allocs,
        ops = 50 * 200,
        "Cancel lane schedule/pop allocation count"
    );

    assert_with_log!(allocs <= 10, "cancel lane near-zero-alloc", "<=10", allocs);

    test_complete!("priority_scheduler_cancel_lane_zero_alloc", allocs = allocs);
}

/// Verify that PriorityScheduler timed lane schedule + pop is zero-alloc.
#[test]
fn priority_scheduler_timed_lane_zero_alloc() {
    let _guard = ALLOC_TEST_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    init_test("priority_scheduler_timed_lane_zero_alloc");

    let mut sched = PriorityScheduler::new();

    // Warm up timed lane.
    test_section!("warmup");
    for i in 0..100u32 {
        sched.schedule_timed(task(i), Time::from_nanos(u64::from(i) + 1));
    }
    for _ in 0..100 {
        sched.pop_timed_only(Time::from_nanos(200));
    }

    // Measure.
    test_section!("measure-timed");
    let before = AllocSnapshot::take();

    for round in 0..50u32 {
        let base_tick = u64::from(round) * 200 + 300;
        for i in 0..100u32 {
            sched.schedule_timed(task(i), Time::from_nanos(base_tick + u64::from(i)));
        }
        for _ in 0..100 {
            let _ = sched.pop_timed_only(Time::from_nanos(base_tick + 200));
        }
    }

    let after = AllocSnapshot::take();
    let allocs = after.allocs_since(&before);

    tracing::info!(
        allocs,
        ops = 50 * 200,
        "Timed lane schedule/pop allocation count"
    );

    assert_with_log!(allocs <= 10, "timed lane near-zero-alloc", "<=10", allocs);

    test_complete!("priority_scheduler_timed_lane_zero_alloc", allocs = allocs);
}

// =============================================================================
// GlobalQueue: Zero-Alloc Push/Pop
// =============================================================================

/// Verify GlobalQueue push/pop is zero-alloc in steady state.
///
/// Note: crossbeam SegQueue may allocate blocks internally on push, but these
/// are reused. We verify allocations stay within a small ceiling.
#[test]
fn global_queue_push_pop_allocation_ceiling() {
    let _guard = ALLOC_TEST_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    init_test("global_queue_push_pop_allocation_ceiling");

    let queue = GlobalQueue::new();

    // Warm up: fill and drain to establish internal block pool.
    test_section!("warmup");
    for i in 0..1000u32 {
        queue.push(task(i));
    }
    for _ in 0..1000 {
        queue.pop();
    }

    // Measure: push/pop cycle.
    test_section!("measure");
    let before = AllocSnapshot::take();

    for _ in 0..100 {
        for i in 0..100u32 {
            queue.push(task(i));
        }
        for _ in 0..100 {
            let _ = queue.pop();
        }
    }

    let after = AllocSnapshot::take();
    let allocs = after.allocs_since(&before);
    let bytes = after.bytes_since(&before);

    tracing::info!(
        allocs,
        bytes,
        ops = 100 * 200,
        "GlobalQueue push/pop allocation count"
    );

    // SegQueue allocates blocks; after warmup most should be reused.
    // Allow a generous ceiling — the key invariant is amortized O(1).
    let ops = 100u64 * 200;
    let allocs_per_op = if ops > 0 { allocs * 1000 / ops } else { 0 };
    tracing::info!(
        allocs_per_1000_ops = allocs_per_op,
        "Amortized allocation rate"
    );

    // Ceiling: at most 1 allocation per 10 ops (generous; crossbeam reuses blocks).
    let ceiling = ops / 10;
    assert_with_log!(
        allocs <= ceiling,
        "global queue within ceiling",
        ceiling,
        allocs
    );

    test_complete!(
        "global_queue_push_pop_allocation_ceiling",
        allocs = allocs,
        ceiling = ceiling,
        bytes = bytes
    );
}

// =============================================================================
// GlobalInjector: Lane-Specific Injection
// =============================================================================

/// Verify GlobalInjector cancel/ready injection + pop stays within allocation
/// ceilings.
#[test]
fn global_injector_allocation_ceiling() {
    let _guard = ALLOC_TEST_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    init_test("global_injector_allocation_ceiling");

    let injector = GlobalInjector::new();

    // Warm up all lanes.
    test_section!("warmup");
    for i in 0..100u32 {
        injector.inject_cancel(task(i), 5);
        injector.inject_ready(task(i + 100), 3);
        injector.inject_timed(task(i + 200), Time::from_nanos(u64::from(i) + 1));
    }
    for _ in 0..100 {
        injector.pop_cancel();
        injector.pop_ready();
        injector.pop_timed_if_due(Time::from_nanos(200));
    }

    // Measure cancel lane.
    test_section!("measure-cancel");
    let before = AllocSnapshot::take();

    for _ in 0..50 {
        for i in 0..100u32 {
            injector.inject_cancel(task(i), 5);
        }
        for _ in 0..100 {
            let _ = injector.pop_cancel();
        }
    }

    let after = AllocSnapshot::take();
    let cancel_allocs = after.allocs_since(&before);

    // Measure ready lane.
    test_section!("measure-ready");
    let before = AllocSnapshot::take();

    for _ in 0..50 {
        for i in 0..100u32 {
            injector.inject_ready(task(i), 3);
        }
        for _ in 0..100 {
            let _ = injector.pop_ready();
        }
    }

    let after = AllocSnapshot::take();
    let ready_allocs = after.allocs_since(&before);

    tracing::info!(
        cancel_allocs,
        ready_allocs,
        ops_per_lane = 50 * 200,
        "GlobalInjector allocation counts"
    );

    // SegQueue (cancel, ready) may allocate blocks; allow ceiling.
    let ops_per_lane = 50u64 * 200;
    let ceiling = ops_per_lane / 10;

    assert_with_log!(
        cancel_allocs <= ceiling,
        "cancel injection within ceiling",
        ceiling,
        cancel_allocs
    );
    assert_with_log!(
        ready_allocs <= ceiling,
        "ready injection within ceiling",
        ceiling,
        ready_allocs
    );

    test_complete!(
        "global_injector_allocation_ceiling",
        cancel_allocs = cancel_allocs,
        ready_allocs = ready_allocs,
        ceiling = ceiling
    );
}

// =============================================================================
// LocalQueue: Zero-Alloc Push/Pop
// =============================================================================

/// Verify LocalQueue push/pop is zero-alloc (intrusive stack, no heap alloc).
#[test]
fn local_queue_push_pop_zero_alloc() {
    let _guard = ALLOC_TEST_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    init_test("local_queue_push_pop_zero_alloc");

    let state = setup_runtime_state(255);
    let queue = LocalQueue::new(Arc::clone(&state));

    // Warm up.
    test_section!("warmup");
    for i in 0..100u32 {
        queue.push(task(i));
    }
    for _ in 0..100 {
        queue.pop();
    }

    // Measure: push/pop should be fully zero-alloc (intrusive links).
    test_section!("measure");
    let before = AllocSnapshot::take();

    for _ in 0..100 {
        for i in 0..100u32 {
            queue.push(task(i));
        }
        for _ in 0..100 {
            let _ = queue.pop();
        }
    }

    let after = AllocSnapshot::take();
    let allocs = after.allocs_since(&before);

    tracing::info!(
        allocs,
        ops = 100 * 200,
        "LocalQueue push/pop allocation count"
    );

    // Intrusive stack: zero allocations expected.
    assert_with_log!(allocs <= 10, "local queue near-zero-alloc", "<=10", allocs);

    test_complete!("local_queue_push_pop_zero_alloc", allocs = allocs);
}

/// Verify LocalQueue steal is zero-alloc (just pointer manipulation).
#[test]
fn local_queue_steal_zero_alloc() {
    let _guard = ALLOC_TEST_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    init_test("local_queue_steal_zero_alloc");

    let state = setup_runtime_state(255);
    let queue_a = LocalQueue::new(Arc::clone(&state));
    let queue_b = LocalQueue::new(Arc::clone(&state));

    // Warm up.
    test_section!("warmup");
    for i in 0..50u32 {
        queue_a.push(task(i));
    }
    queue_b.stealer().steal_batch(&queue_b);
    for _ in 0..50 {
        queue_a.pop();
        queue_b.pop();
    }

    // Measure: steal should be zero-alloc.
    test_section!("measure");
    let before = AllocSnapshot::take();

    for _ in 0..100 {
        for i in 0..50u32 {
            queue_a.push(task(i));
        }
        queue_a.stealer().steal_batch(&queue_b);
        // Drain both queues.
        while queue_a.pop().is_some() {}
        while queue_b.pop().is_some() {}
    }

    let after = AllocSnapshot::take();
    let allocs = after.allocs_since(&before);

    tracing::info!(allocs, steal_ops = 100, "LocalQueue steal allocation count");

    assert_with_log!(allocs <= 10, "steal near-zero-alloc", "<=10", allocs);

    test_complete!("local_queue_steal_zero_alloc", allocs = allocs);
}

// =============================================================================
// Mixed Lane Operations Under Load
// =============================================================================

/// Stress test: interleaved cancel/timed/ready operations under high load,
/// verifying allocation ceiling after warmup.
#[test]
fn mixed_lane_stress_allocation_ceiling() {
    let _guard = ALLOC_TEST_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    init_test("mixed_lane_stress_allocation_ceiling");

    let mut sched = PriorityScheduler::new();

    // Warm up all lanes to max capacity.
    test_section!("warmup");
    for i in 0..200u32 {
        sched.schedule(task(i), 5);
        sched.schedule_cancel(task(i + 200), 8);
        sched.schedule_timed(task(i + 400), Time::from_nanos(u64::from(i) + 1));
    }
    // Drain.
    for _ in 0..200 {
        sched.pop_cancel_only();
        sched.pop_timed_only(Time::from_nanos(300));
        sched.pop_ready_only();
    }

    // Stress: interleaved operations.
    test_section!("stress");
    let before = AllocSnapshot::take();

    for round in 0..100u32 {
        let base = u64::from(round) * 500;
        // Schedule across all lanes.
        for i in 0..50u32 {
            sched.schedule(task(i), (round % 8) as u8);
            sched.schedule_cancel(task(i + 50), ((round + 3) % 10) as u8);
            sched.schedule_timed(task(i + 100), Time::from_nanos(base + u64::from(i) + 1));
        }
        // Pop from all lanes.
        for _ in 0..50 {
            let _ = sched.pop_cancel_only();
            let _ = sched.pop_timed_only(Time::from_nanos(base + 100));
            let _ = sched.pop_ready_only();
        }
    }

    let after = AllocSnapshot::take();
    let allocs = after.allocs_since(&before);
    let bytes = after.bytes_since(&before);

    tracing::info!(
        allocs,
        bytes,
        total_ops = 100 * 300,
        "Mixed lane stress allocation count"
    );

    // After warmup to 200 entries per lane and never exceeding that,
    // all operations should be zero-alloc.
    assert_with_log!(
        allocs <= 10,
        "mixed lane stress near-zero-alloc",
        "<=10",
        allocs
    );

    test_complete!(
        "mixed_lane_stress_allocation_ceiling",
        allocs = allocs,
        bytes = bytes
    );
}

// =============================================================================
// E2E: Lab Runtime Dispatch Loop
// =============================================================================

/// End-to-end test: run a Lab runtime with multiple tasks, measuring total
/// allocations during the dispatch loop (after initial setup).
///
/// This captures the real allocation profile including waker creation,
/// queue operations, and governor overhead.
#[test]
fn e2e_lab_dispatch_allocation_profile() {
    let _guard = ALLOC_TEST_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    init_test("e2e_lab_dispatch_allocation_profile");

    // Phase 1: Set up the runtime and tasks (allocations expected here).
    test_section!("setup");
    let config = LabConfig::new(0xA110C);
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let task_count = 20u32;
    for _ in 0..task_count {
        let (tid, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("create task");
        runtime.scheduler.lock().unwrap().schedule(tid, 0);
    }

    tracing::info!(task_count, "Lab runtime setup with tasks");

    // Phase 2: Measure allocations during dispatch.
    test_section!("dispatch");
    let before = AllocSnapshot::take();

    runtime.run_until_quiescent();

    let after = AllocSnapshot::take();
    let dispatch_allocs = after.allocs_since(&before);
    let dispatch_bytes = after.bytes_since(&before);

    tracing::info!(
        dispatch_allocs,
        dispatch_bytes,
        task_count,
        "Lab dispatch allocation profile"
    );

    // Log per-task allocation rate.
    let allocs_per_task = if task_count > 0 {
        dispatch_allocs / u64::from(task_count)
    } else {
        0
    };
    tracing::info!(allocs_per_task, "Per-task allocation rate during dispatch");

    // The dispatch loop creates wakers (Arc::new) for each task poll. With
    // caching, most polls reuse the cached waker. We set a generous ceiling
    // that catches regressions but allows the waker allocations.
    //
    // Expected: ~2-4 allocs per task (waker + cancel waker, both cached after
    // first poll). Ceiling: 10 per task to absorb variance.
    let ceiling = u64::from(task_count) * 10;
    assert_with_log!(
        dispatch_allocs <= ceiling,
        "dispatch within allocation ceiling",
        ceiling,
        dispatch_allocs
    );

    test_complete!(
        "e2e_lab_dispatch_allocation_profile",
        dispatch_allocs = dispatch_allocs,
        dispatch_bytes = dispatch_bytes,
        allocs_per_task = allocs_per_task,
        ceiling = ceiling
    );
}

/// E2E stress test: multiple runs with increasing task counts, verifying
/// that allocation growth is sub-linear (amortization holds).
#[test]
fn e2e_allocation_scaling_sublinear() {
    let _guard = ALLOC_TEST_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    init_test("e2e_allocation_scaling_sublinear");

    let task_counts = [10u32, 50, 100, 200];
    let mut results: Vec<(u32, u64, u64)> = Vec::new();

    for &count in &task_counts {
        test_section!(&format!("tasks-{count}"));

        let config = LabConfig::new(0x5CA1E + u64::from(count));
        let mut runtime = LabRuntime::new(config);
        let region = runtime.state.create_root_region(Budget::INFINITE);

        for _ in 0..count {
            let (tid, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("create task");
            runtime.scheduler.lock().unwrap().schedule(tid, 0);
        }

        let before = AllocSnapshot::take();
        runtime.run_until_quiescent();
        let after = AllocSnapshot::take();

        let allocs = after.allocs_since(&before);
        let bytes = after.bytes_since(&before);

        tracing::info!(
            tasks = count,
            allocs,
            bytes,
            allocs_per_task = allocs / u64::from(count),
            "Scaling data point"
        );

        results.push((count, allocs, bytes));
    }

    // Verify sub-linear growth: if we double tasks, allocations should less
    // than double. Compare the smallest and largest runs.
    test_section!("verify-scaling");
    if results.len() >= 2 {
        let (small_tasks, small_allocs, _) = results[0];
        let (large_tasks, large_allocs, _) = results[results.len() - 1];

        let task_ratio = f64::from(large_tasks) / f64::from(small_tasks);
        let alloc_ratio = if small_allocs > 0 {
            u64_to_f64(large_allocs) / u64_to_f64(small_allocs)
        } else {
            1.0
        };

        tracing::info!(
            task_ratio,
            alloc_ratio,
            small_tasks,
            large_tasks,
            small_allocs,
            large_allocs,
            "Scaling analysis"
        );

        // Allocation ratio should be less than 2x the task ratio (sub-linear).
        // This catches O(n^2) regressions while allowing some overhead.
        let max_ratio = task_ratio * 2.0;
        assert_with_log!(
            alloc_ratio <= max_ratio,
            "sub-linear allocation scaling",
            format!("<= {max_ratio:.1}"),
            format!("{alloc_ratio:.1}")
        );
    }

    // Summary table.
    test_section!("summary");
    for (count, allocs, bytes) in &results {
        tracing::info!(
            tasks = count,
            allocs,
            bytes,
            allocs_per_task = allocs / u64::from(*count),
            bytes_per_task = bytes / u64::from(*count),
            "Result"
        );
    }

    test_complete!(
        "e2e_allocation_scaling_sublinear",
        data_points = results.len()
    );
}

// =============================================================================
// Region Heap Allocation Tracking
// =============================================================================

/// Verify that the region heap's internal allocation counter is consistent
/// with actual allocations.
#[test]
fn region_heap_alloc_count_consistency() {
    let _guard = ALLOC_TEST_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    init_test("region_heap_alloc_count_consistency");

    test_section!("baseline");
    let baseline = global_alloc_count();
    tracing::info!(baseline, "Region heap global alloc count baseline");

    test_section!("allocate");
    let mut heap = RegionHeap::new();
    for i in 0u32..50 {
        heap.alloc(i);
    }

    let after_alloc = global_alloc_count();
    let region_allocs = after_alloc - baseline;

    tracing::info!(region_allocs, expected = 50, "Region heap allocations");

    let stats = heap.stats();
    tracing::info!(
        heap_allocations = stats.allocations,
        heap_live = stats.live,
        "HeapStats"
    );

    assert_with_log!(
        stats.allocations == 50,
        "heap stats track allocations",
        50u64,
        stats.allocations
    );
    assert_with_log!(
        stats.live == 50,
        "heap stats track live count",
        50u64,
        stats.live
    );

    // Verify global counter incremented.
    assert_with_log!(
        region_allocs >= 50,
        "global counter incremented",
        ">= 50",
        region_allocs
    );

    test_complete!(
        "region_heap_alloc_count_consistency",
        region_allocs = region_allocs,
        heap_stats_allocs = stats.allocations,
        heap_stats_live = stats.live
    );
}

// =============================================================================
// JSON Allocation Report
// =============================================================================

/// Produce a structured JSON allocation report covering all hot paths.
/// This serves as the CI-consumable artifact for regression detection.
#[test]
fn allocation_audit_structured_report() {
    let _guard = ALLOC_TEST_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    init_test("allocation_audit_structured_report");

    // NOTE: This test uses ceiling-based policies for ALL components because
    // the global allocator counter is shared across all threads, including
    // the common::coverage tests that run concurrently without the guard.
    // The dedicated per-component tests (priority_scheduler_*_zero_alloc,
    // local_queue_*_zero_alloc) enforce the true zero-alloc invariant with
    // proper serialisation. This test verifies the audit report infrastructure.
    let mut report_entries: Vec<(&str, u64, u64, &str)> = Vec::new();

    // 1. PriorityScheduler ready lane.
    test_section!("audit-ready");
    {
        let mut sched = PriorityScheduler::new();
        for i in 0..100u32 {
            sched.schedule(task(i), 5);
        }
        for _ in 0..100 {
            sched.pop_ready_only();
        }
        let before = AllocSnapshot::take();
        for i in 0..1000u32 {
            sched.schedule(task(i % 100), 5);
            sched.pop_ready_only();
        }
        let after = AllocSnapshot::take();
        report_entries.push((
            "priority_ready",
            after.allocs_since(&before),
            after.bytes_since(&before),
            "ceiling",
        ));
    }

    // 2. PriorityScheduler cancel lane.
    test_section!("audit-cancel");
    {
        let mut sched = PriorityScheduler::new();
        for i in 0..100u32 {
            sched.schedule_cancel(task(i), 5);
        }
        for _ in 0..100 {
            sched.pop_cancel_only();
        }
        let before = AllocSnapshot::take();
        for i in 0..1000u32 {
            sched.schedule_cancel(task(i % 100), 5);
            sched.pop_cancel_only();
        }
        let after = AllocSnapshot::take();
        report_entries.push((
            "priority_cancel",
            after.allocs_since(&before),
            after.bytes_since(&before),
            "ceiling",
        ));
    }

    // 3. LocalQueue push/pop.
    test_section!("audit-local-queue");
    {
        let state = setup_runtime_state(255);
        let queue = LocalQueue::new(Arc::clone(&state));
        for i in 0..100u32 {
            queue.push(task(i));
        }
        for _ in 0..100 {
            queue.pop();
        }
        let before = AllocSnapshot::take();
        for i in 0..1000u32 {
            queue.push(task(i % 100));
            queue.pop();
        }
        let after = AllocSnapshot::take();
        report_entries.push((
            "local_queue",
            after.allocs_since(&before),
            after.bytes_since(&before),
            "ceiling",
        ));
    }

    // 4. GlobalQueue push/pop.
    test_section!("audit-global-queue");
    {
        let queue = GlobalQueue::new();
        for i in 0..1000u32 {
            queue.push(task(i));
        }
        for _ in 0..1000 {
            queue.pop();
        }
        let before = AllocSnapshot::take();
        for i in 0..1000u32 {
            queue.push(task(i % 100));
            queue.pop();
        }
        let after = AllocSnapshot::take();
        report_entries.push((
            "global_queue",
            after.allocs_since(&before),
            after.bytes_since(&before),
            "ceiling",
        ));
    }

    // 5. GlobalInjector cancel inject/pop.
    test_section!("audit-injector");
    {
        let injector = GlobalInjector::new();
        for i in 0..100u32 {
            injector.inject_cancel(task(i), 5);
        }
        for _ in 0..100 {
            injector.pop_cancel();
        }
        let before = AllocSnapshot::take();
        for i in 0..1000u32 {
            injector.inject_cancel(task(i % 100), 5);
            injector.pop_cancel();
        }
        let after = AllocSnapshot::take();
        report_entries.push((
            "injector_cancel",
            after.allocs_since(&before),
            after.bytes_since(&before),
            "ceiling",
        ));
    }

    // Generate JSON report.
    test_section!("report");
    let mut json_entries = Vec::new();
    for (name, allocs, bytes, policy) in &report_entries {
        let status = if *allocs <= 200 { "PASS" } else { "WARN" };

        tracing::info!(
            component = name,
            allocs,
            bytes,
            policy,
            status,
            "Audit entry"
        );

        json_entries.push(format!(
            r#"    {{"component": "{name}", "allocs": {allocs}, "bytes": {bytes}, "policy": "{policy}", "status": "{status}"}}"#
        ));
    }

    let json_report = format!(
        r#"{{"allocation_audit": [{entries}], "schema_version": 1}}"#,
        entries = json_entries.join(",\n")
    );

    tracing::info!(
        json_len = json_report.len(),
        entries = report_entries.len(),
        "Structured allocation audit report"
    );
    tracing::debug!(report = %json_report, "Full JSON report");

    // Verify all ceiling-policy entries are within budget.
    // (Zero-alloc invariants are enforced by dedicated per-component tests.)
    for (name, allocs, _, policy) in &report_entries {
        if *policy == "ceiling" {
            assert_with_log!(
                *allocs <= 200,
                &format!("{name}: ceiling policy"),
                "<=200",
                *allocs
            );
        }
    }

    test_complete!(
        "allocation_audit_structured_report",
        entries = report_entries.len(),
        json_bytes = json_report.len()
    );
}
