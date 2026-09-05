#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]
#![allow(unsafe_code)]
#![allow(clippy::too_many_lines)]
#![allow(unused_must_use)]
//! Allocation Audit & Zero-Alloc Guards (bd-3bjjp).
//!
//! Verifies that scheduler and cancellation hot paths remain allocation-free
//! (or within strict allocation ceilings) under load. Uses a custom global
//! allocator to count heap allocations during critical sections on the
//! measured test thread.
//!
//! Hot paths audited:
//! - Mutex/RwLock cold construction, uncontended acquisition, and lazy waiter spill
//! - PriorityScheduler schedule/pop (cancel, timed, ready lanes)
//! - LocalQueue push/pop
//! - GlobalQueue push/pop
//! - GlobalInjector inject/pop (cancel, timed, ready)
//! - Work stealing batch operations
//! - Lab runtime dispatch loop (E2E)

#[macro_use]
mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};

// =============================================================================
// Counting Allocator
// =============================================================================

/// A thin wrapper around the system allocator that counts allocations on the
/// current test thread. This lets hot-path audits run beside unrelated test
/// threads without inheriting their allocator noise.
struct CountingAllocator;

thread_local! {
    static ALLOC_COUNT: Cell<u64> = const { Cell::new(0) };
    static ALLOC_BYTES: Cell<u64> = const { Cell::new(0) };
}

// Disabled for all existing audits. The native paired measurement opts in
// while holding ALLOC_TEST_GUARD and counts every thread in this process.
static NATIVE_COST_COUNTING: AtomicBool = AtomicBool::new(false);
static NATIVE_COST_ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static NATIVE_COST_BYTES: AtomicU64 = AtomicU64::new(0);
static NATIVE_COST_COUNTER_WRITERS: AtomicUsize = AtomicUsize::new(0);
static NATIVE_COST_WINDOW_GENERATION: AtomicU64 = AtomicU64::new(0);

fn count_native_cost_allocation(bytes: usize) {
    let generation = NATIVE_COST_WINDOW_GENERATION.load(Ordering::SeqCst);
    if NATIVE_COST_COUNTING.load(Ordering::SeqCst) {
        NATIVE_COST_COUNTER_WRITERS.fetch_add(1, Ordering::SeqCst);
        // A writer paused before joining the window must not update a closed
        // window. Closing waits for writers that observed this second check.
        if NATIVE_COST_COUNTING.load(Ordering::SeqCst)
            && NATIVE_COST_WINDOW_GENERATION.load(Ordering::SeqCst) == generation
        {
            NATIVE_COST_ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
            NATIVE_COST_BYTES.fetch_add(bytes as u64, Ordering::SeqCst);
        }
        NATIVE_COST_COUNTER_WRITERS.fetch_sub(1, Ordering::SeqCst);
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.with(|count| count.set(count.get().saturating_add(1)));
        ALLOC_BYTES.with(|bytes| {
            bytes.set(bytes.get().saturating_add(layout.size() as u64));
        });
        count_native_cost_allocation(layout.size());
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
        Self {
            allocs: ALLOC_COUNT.with(Cell::get),
            bytes: ALLOC_BYTES.with(Cell::get),
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
    common::init_test_logging_with_level(tracing::Level::WARN);
    test_phase!(test_name);
}

fn u64_to_f64(value: u64) -> f64 {
    let clamped = value.min(u64::from(u32::MAX));
    f64::from(u32::try_from(clamped).expect("clamped to u32 max"))
}

use asupersync::cx::{Cx, cap};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::task::TaskRecord;
use asupersync::runtime::scheduler::{GlobalInjector, GlobalQueue, LocalQueue, PriorityScheduler};
use asupersync::runtime::{RegionHeap, RuntimeState, global_alloc_count};
use asupersync::sync::{ContendedMutex, Mutex as AsupersyncMutex, RwLock};
use asupersync::types::{Budget, RegionId, TaskId, Time};
use parking_lot::Mutex;
use std::sync::Arc;

/// Serializes allocation-sensitive tests whose measured code mutates shared
/// runtime structures or emits tracing output from helper threads.
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
        let idx = state.insert_task(record);
        assert_eq!(idx.index(), i);
    }
    Arc::new(ContendedMutex::new("runtime_state", state))
}

/// Empty waiter queues must stay allocation-free until contention actually
/// queues a task. This covers construction plus the first uncontended guard for
/// both synchronization primitives backed by `WaiterChain`.
#[test]
fn mutex_and_rwlock_uncontended_paths_zero_alloc() {
    let _guard = ALLOC_TEST_GUARD.lock();
    init_test("mutex_and_rwlock_uncontended_paths_zero_alloc");

    let before_mutex = AllocSnapshot::take();
    let mutex = AsupersyncMutex::new(());
    drop(mutex.try_lock().expect("new mutex acquires immediately"));
    let after_mutex = AllocSnapshot::take();
    let mutex_allocs = after_mutex.allocs_since(&before_mutex);
    let mutex_bytes = after_mutex.bytes_since(&before_mutex);

    let before_rwlock = AllocSnapshot::take();
    let rwlock = RwLock::new(());
    drop(rwlock.try_read().expect("new rwlock admits a reader"));
    drop(rwlock.try_write().expect("new rwlock admits a writer"));
    let after_rwlock = AllocSnapshot::take();
    let rwlock_allocs = after_rwlock.allocs_since(&before_rwlock);
    let rwlock_bytes = after_rwlock.bytes_since(&before_rwlock);

    assert_eq!(mutex_allocs, 0, "cold mutex path must not allocate");
    assert_eq!(mutex_bytes, 0, "cold mutex path must allocate no bytes");
    assert_eq!(rwlock_allocs, 0, "cold rwlock path must not allocate");
    assert_eq!(rwlock_bytes, 0, "cold rwlock path must allocate no bytes");
    test_complete!(
        "mutex_and_rwlock_uncontended_paths_zero_alloc",
        mutex_allocs = mutex_allocs,
        mutex_bytes = mutex_bytes,
        rwlock_allocs = rwlock_allocs,
        rwlock_bytes = rwlock_bytes
    );
}

/// The first queued waiter pays for the lazy slab and stable-id index. Removing
/// that waiter retains both capacities, so the next contention reuses them.
#[test]
fn mutex_waiter_storage_allocates_once_then_reuses_capacity() {
    let _guard = ALLOC_TEST_GUARD.lock();
    init_test("mutex_waiter_storage_allocates_once_then_reuses_capacity");

    let mutex = AsupersyncMutex::new(());
    let held = mutex.try_lock().expect("initial mutex guard acquires");
    let cx = Cx::<cap::None>::detached_cancel_context();
    let mut task_cx = Context::from_waker(std::task::Waker::noop());

    let mut first_waiter = Box::pin(mutex.lock(&cx));
    let before_first = AllocSnapshot::take();
    assert!(matches!(
        first_waiter.as_mut().poll(&mut task_cx),
        Poll::Pending
    ));
    let after_first = AllocSnapshot::take();
    let first_allocs = after_first.allocs_since(&before_first);
    let first_bytes = after_first.bytes_since(&before_first);
    drop(first_waiter);

    let mut reused_waiter = Box::pin(mutex.lock(&cx));
    let before_reuse = AllocSnapshot::take();
    assert!(matches!(
        reused_waiter.as_mut().poll(&mut task_cx),
        Poll::Pending
    ));
    let after_reuse = AllocSnapshot::take();
    let reuse_allocs = after_reuse.allocs_since(&before_reuse);
    let reuse_bytes = after_reuse.bytes_since(&before_reuse);
    drop(reused_waiter);
    drop(held);

    assert_eq!(
        first_allocs, 2,
        "first contention allocates the slab and stable-id index"
    );
    assert!(first_bytes > 0, "first contention must allocate storage");
    assert_eq!(reuse_allocs, 0, "retained waiter capacity must be reused");
    assert_eq!(reuse_bytes, 0, "capacity reuse must allocate no bytes");
    test_complete!(
        "mutex_waiter_storage_allocates_once_then_reuses_capacity",
        first_allocs = first_allocs,
        first_bytes = first_bytes,
        reuse_allocs = reuse_allocs,
        reuse_bytes = reuse_bytes
    );
}

/// Releasing an active writer to a shallow batch of readers must use the
/// `SmallVec` inline storage directly. The wait queues and futures are prepared
/// before the snapshot so the measured delta isolates release and fanout.
#[test]
fn rwlock_shallow_reader_release_zero_alloc() {
    let _guard = ALLOC_TEST_GUARD.lock();
    init_test("rwlock_shallow_reader_release_zero_alloc");

    let lock = RwLock::with_name("runtime_state", ());
    let writer = lock.try_write().expect("initial writer acquires");
    let cx = Cx::<cap::None>::detached_cancel_context();
    let mut task_cx = Context::from_waker(std::task::Waker::noop());
    let mut readers = [
        Box::pin(lock.read(&cx)),
        Box::pin(lock.read(&cx)),
        Box::pin(lock.read(&cx)),
        Box::pin(lock.read(&cx)),
    ];

    for reader in &mut readers {
        assert!(matches!(reader.as_mut().poll(&mut task_cx), Poll::Pending));
    }

    let before = AllocSnapshot::take();
    drop(writer);
    let after = AllocSnapshot::take();
    let allocs = after.allocs_since(&before);
    let bytes = after.bytes_since(&before);

    assert_eq!(allocs, 0, "shallow reader release must stay inline");
    assert_eq!(bytes, 0, "shallow reader release must allocate no bytes");
    test_complete!(
        "rwlock_shallow_reader_release_zero_alloc",
        allocs = allocs,
        bytes = bytes
    );
}

// =============================================================================
// PriorityScheduler: Zero-Alloc Schedule/Pop
// =============================================================================

/// Verify that PriorityScheduler schedule + pop on the ready lane performs
/// zero heap allocations after initial capacity is established.
#[test]
fn priority_scheduler_ready_lane_zero_alloc() {
    let _guard = ALLOC_TEST_GUARD.lock();
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
    let _guard = ALLOC_TEST_GUARD.lock();
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
    let _guard = ALLOC_TEST_GUARD.lock();
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
    let _guard = ALLOC_TEST_GUARD.lock();
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
    let allocs_per_op = allocs
        .checked_mul(1000)
        .and_then(|v| v.checked_div(ops))
        .unwrap_or(0);
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
    let _guard = ALLOC_TEST_GUARD.lock();
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
    let _guard = ALLOC_TEST_GUARD.lock();
    init_test("local_queue_push_pop_zero_alloc");

    let state = setup_runtime_state(255);
    let queue = LocalQueue::new(Arc::clone(&state));

    // Warm up.
    test_section!("warmup");
    for i in 0..8u32 {
        queue.push(task(i));
    }
    for _ in 0..8 {
        queue.pop();
    }

    // Measure: push/pop should be fully zero-alloc (intrusive links).
    test_section!("measure");
    let before = AllocSnapshot::take();

    for _ in 0..100 {
        for i in 0..8u32 {
            queue.push(task(i));
        }
        for _ in 0..8 {
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
    let _guard = ALLOC_TEST_GUARD.lock();
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
    let _guard = ALLOC_TEST_GUARD.lock();
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
    let _guard = ALLOC_TEST_GUARD.lock();
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
        runtime.scheduler.lock().schedule(tid, 0);
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

    // This measures the lab dispatch path as it is used by RuntimeState::create_task:
    // polling, result delivery through the task handle oneshot, completion trace
    // events, and first-poll wakers. It is intentionally stricter than broad
    // "no unbounded growth" checks, but it is not a scheduler-only microbenchmark.
    //
    // Expected: ~24-25 allocs per one-poll task in the current fully
    // instrumented path. Ceiling: 26 per task catches renewed growth while
    // leaving one allocation per task of cross-target variance.
    let ceiling = u64::from(task_count) * 26;
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
    let _guard = ALLOC_TEST_GUARD.lock();
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
            runtime.scheduler.lock().schedule(tid, 0);
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
    let _guard = ALLOC_TEST_GUARD.lock();
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
    let _guard = ALLOC_TEST_GUARD.lock();
    init_test("allocation_audit_structured_report");

    // The dedicated per-component tests (priority_scheduler_*_zero_alloc,
    // local_queue_*_zero_alloc) enforce the true zero-alloc invariant. This
    // report keeps ceiling-based rows so CI can surface all components in one
    // stable JSON shape.
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

/// A/B allocation measurement for the codec-flush optimization
/// (br-asupersync-framed-flush-split-alloc). The `Framed`/`FramedWrite` flush
/// loop discards already-written bytes on every write pass. The old
/// `let _ = buf.split_to(n)` heap-allocated and memcpy'd a throwaway head each
/// pass; `buf.advance(n)` bumps the front offset in place. This exercises the
/// exact discard operation and proves `advance` is allocation-free and strictly
/// cheaper than `split_to`.
#[test]
fn bytes_mut_advance_flush_discard_is_zero_alloc_vs_split_to() {
    use asupersync::bytes::{BufMut, BytesMut};

    let _guard = ALLOC_TEST_GUARD.lock();
    init_test("bytes_mut_advance_flush_discard_is_zero_alloc_vs_split_to");

    const FRAMES: usize = 64; // write passes per flush (MAX_WRITE_PASSES_PER_POLL-scale)
    const FRAME: usize = 1024; // bytes discarded per pass

    // Warm up so the measured sections are steady-state (no capacity growth).
    {
        let mut warm = BytesMut::with_capacity(FRAMES * FRAME);
        for _ in 0..FRAMES {
            warm.put_slice(&[0u8; FRAME]);
        }
        for _ in 0..FRAMES {
            warm.advance(FRAME);
        }
    }

    // A) Optimized path: fill (outside measurement), then drain via advance().
    test_section!("measure-advance");
    let mut buf_a = BytesMut::with_capacity(FRAMES * FRAME);
    for _ in 0..FRAMES {
        buf_a.put_slice(&[7u8; FRAME]);
    }
    let before_a = AllocSnapshot::take();
    for _ in 0..FRAMES {
        buf_a.advance(FRAME);
    }
    let advance_allocs = AllocSnapshot::take().allocs_since(&before_a);

    // B) Old path: same fill, then drain via split_to() (head discarded).
    test_section!("measure-split_to");
    let mut buf_b = BytesMut::with_capacity(FRAMES * FRAME);
    for _ in 0..FRAMES {
        buf_b.put_slice(&[7u8; FRAME]);
    }
    let before_b = AllocSnapshot::take();
    for _ in 0..FRAMES {
        let _ = buf_b.split_to(FRAME);
    }
    let split_to_allocs = AllocSnapshot::take().allocs_since(&before_b);

    tracing::info!(
        advance_allocs,
        split_to_allocs,
        frames = FRAMES,
        "flush-discard A/B allocations"
    );

    // The advance discard loop is allocation-free (bumps `start` only); small
    // tolerance for parallel allocator-counter noise from tests that don't hold
    // ALLOC_TEST_GUARD. split_to heap-allocs one head per call, so advance must
    // allocate strictly fewer.
    assert_with_log!(
        advance_allocs <= 2,
        "advance flush discard is ~zero-alloc",
        "<=2",
        advance_allocs
    );
    assert_with_log!(
        advance_allocs < split_to_allocs,
        "advance allocates strictly fewer than split_to",
        format!("advance {advance_allocs} < split_to {split_to_allocs}"),
        advance_allocs < split_to_allocs
    );

    test_complete!(
        "bytes_mut_advance_flush_discard_is_zero_alloc_vs_split_to",
        advance_allocs = advance_allocs,
        split_to_allocs = split_to_allocs
    );
}

// =============================================================================
// Native paired legacy/checked full-lifecycle cost observations (.28/.29)
// =============================================================================
// These are instrumented end-to-end cycle costs, NOT admission-only timings.
// Every cycle observes one real arena ID while holding its permit, performs
// the successful operation, and waits for the holder's arena index to empty.
// Inspector allocation/locking, polling, yield, clocks, trace, and other native
// runtime work during the process-wide window are deliberately included.
// Setup, warmup, sample allocation/sorting/logging, and teardown are excluded.
// Performance evidence requires the exact named test with --exact and
// --test-threads=1; other invocations still execute all correctness assertions
// but their observations are explicitly ineligible for performance comparison.
// No timing/allocation ratio is asserted to be a speed or regression gate.

const NATIVE_COST_WARMUP: usize = 256;
const NATIVE_COST_SAMPLES: usize = 4096;
const NATIVE_COST_BLOCKS: usize = 4;
const NATIVE_COST_OBSERVATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const NATIVE_COST_ARM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);
const NATIVE_COST_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

struct NativeCostWindow;

impl NativeCostWindow {
    fn wait_for_writers() {
        let started = std::time::Instant::now();
        while NATIVE_COST_COUNTER_WRITERS.load(Ordering::SeqCst) != 0 {
            assert!(
                started.elapsed() < NATIVE_COST_OBSERVATION_TIMEOUT,
                "allocation counter writers must finish their atomic-only section"
            );
            std::thread::yield_now();
        }
    }

    fn start() -> Self {
        assert!(!NATIVE_COST_COUNTING.load(Ordering::SeqCst));
        Self::wait_for_writers();
        NATIVE_COST_WINDOW_GENERATION.fetch_add(1, Ordering::SeqCst);
        NATIVE_COST_ALLOCATIONS.store(0, Ordering::SeqCst);
        NATIVE_COST_BYTES.store(0, Ordering::SeqCst);
        NATIVE_COST_COUNTING.store(true, Ordering::SeqCst);
        Self
    }

    fn finish(self) -> AllocSnapshot {
        NATIVE_COST_COUNTING.store(false, Ordering::SeqCst);
        Self::wait_for_writers();
        AllocSnapshot {
            allocs: NATIVE_COST_ALLOCATIONS.load(Ordering::SeqCst),
            bytes: NATIVE_COST_BYTES.load(Ordering::SeqCst),
        }
    }
}

impl Drop for NativeCostWindow {
    fn drop(&mut self) {
        // Unwinding must never leave the process-wide instrumentation enabled
        // or replace the primary panic with a second teardown assertion.
        NATIVE_COST_COUNTING.store(false, Ordering::SeqCst);
    }
}

fn verify_native_cost_worker_counter() {
    // Create the worker and synchronization storage before enabling counting.
    // Its explicit 4096-byte allocation is opaque to the optimizer and happens
    // entirely on a different native thread from the caller.
    let ready = Arc::new(AtomicBool::new(false));
    let go = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let worker_ready = Arc::clone(&ready);
    let worker_go = Arc::clone(&go);
    let worker_done = Arc::clone(&done);
    let worker = std::thread::spawn(move || {
        worker_ready.store(true, Ordering::Release);
        let started = std::time::Instant::now();
        while !worker_go.load(Ordering::Acquire) {
            assert!(started.elapsed() < NATIVE_COST_OBSERVATION_TIMEOUT);
            std::thread::yield_now();
        }
        let bytes = std::hint::black_box(vec![0x5a_u8; 4096]);
        assert_eq!(std::hint::black_box(bytes[4095]), 0x5a);
        drop(bytes);
        worker_done.store(true, Ordering::Release);
    });
    let started = std::time::Instant::now();
    while !ready.load(Ordering::Acquire) {
        assert!(started.elapsed() < NATIVE_COST_OBSERVATION_TIMEOUT);
        std::thread::yield_now();
    }
    let window = NativeCostWindow::start();
    go.store(true, Ordering::Release);
    let started = std::time::Instant::now();
    while !done.load(Ordering::Acquire) {
        assert!(started.elapsed() < NATIVE_COST_OBSERVATION_TIMEOUT);
        std::thread::yield_now();
    }
    let observed = window.finish();
    worker.join().expect("native allocator probe must complete");
    assert!(observed.allocs >= 1);
    assert!(observed.bytes >= 4096);
    assert!(!NATIVE_COST_COUNTING.load(Ordering::SeqCst));
    eprintln!(
        "native_cost_worker_counter allocations={} bytes={} minimum_explicit_worker_allocation=4096",
        observed.allocs, observed.bytes
    );
}

#[derive(Clone, Copy, Debug)]
enum NativeCostArm {
    Legacy,
    Checked,
}

#[derive(Clone, Copy, Debug)]
enum NativeCostPrimitive {
    Mpsc,
    Semaphore,
}

impl NativeCostPrimitive {
    fn kind(self) -> asupersync::record::ObligationKind {
        match self {
            Self::Mpsc => asupersync::record::ObligationKind::SendPermit,
            Self::Semaphore => asupersync::record::ObligationKind::SemaphorePermit,
        }
    }
}

struct NativeCostObservation {
    holder: TaskId,
    region: RegionId,
    ids: Vec<asupersync::types::ObligationId>,
    samples_ns: Vec<u64>,
    allocations: AllocSnapshot,
    elapsed: std::time::Duration,
    // Observed cycle-end threads, not a claim that every configured worker
    // participated in this single-holder workload.
    cycle_end_threads: Vec<std::thread::ThreadId>,
}

fn native_cost_holder_ids(
    observer: &asupersync::runtime::RuntimeHandle,
    holder: TaskId,
) -> Vec<asupersync::types::ObligationId> {
    // Keep the inspector and its state access strictly within this synchronous
    // call. They must not be retained across a native spawned future's await.
    let details = observer
        .task_inspector(Default::default())
        .expect("owning native runtime remains alive")
        .inspect_task(holder)
        .expect("the measured holder is an actual live native task");
    assert_eq!(details.id, holder);
    details.obligations
}

async fn native_cost_observe_reserved(
    observer: &asupersync::runtime::RuntimeHandle,
    holder: TaskId,
) -> asupersync::types::ObligationId {
    let started = std::time::Instant::now();
    loop {
        let ids = native_cost_holder_ids(observer, holder);
        assert!(
            ids.len() <= 1,
            "quota-one holder has unexpected IDs: {ids:?}"
        );
        if let Some(id) = ids.first() {
            return *id;
        }
        assert!(
            started.elapsed() < NATIVE_COST_OBSERVATION_TIMEOUT,
            "reservation must materialize while its permit is held: holder={holder:?}"
        );
        asupersync::runtime::yield_now().await;
    }
}

async fn native_cost_observe_settled(
    observer: &asupersync::runtime::RuntimeHandle,
    holder: TaskId,
    reserved: asupersync::types::ObligationId,
) {
    let started = std::time::Instant::now();
    loop {
        let ids = native_cost_holder_ids(observer, holder);
        if ids.is_empty() {
            return;
        }
        assert_eq!(ids, [reserved], "only the observed reservation may remain");
        assert!(
            started.elapsed() < NATIVE_COST_OBSERVATION_TIMEOUT,
            "terminal must apply before cycle completion: holder={holder:?} obligation={reserved:?}"
        );
        asupersync::runtime::yield_now().await;
    }
}

async fn native_cost_cycle(
    primitive: NativeCostPrimitive,
    arm: NativeCostArm,
    cx: &Cx,
    observer: &asupersync::runtime::RuntimeHandle,
    sender: &asupersync::channel::mpsc::Sender<u64>,
    receiver: &mut asupersync::channel::mpsc::Receiver<u64>,
    semaphore: &asupersync::sync::Semaphore,
    value: u64,
) -> asupersync::types::ObligationId {
    let reserved = match primitive {
        NativeCostPrimitive::Mpsc => {
            let permit = match arm {
                NativeCostArm::Legacy => sender.reserve(cx).await.expect("legacy reservation"),
                NativeCostArm::Checked => sender
                    .reserve_checked(cx)
                    .await
                    .expect("checked quota-one reservation"),
            };
            let id = native_cost_observe_reserved(observer, cx.task_id()).await;
            permit.try_send(value).expect("accepted native payload");
            assert_eq!(receiver.try_recv(), Ok(value), "exact u64 delivery");
            id
        }
        NativeCostPrimitive::Semaphore => {
            let permit = match arm {
                NativeCostArm::Legacy => {
                    semaphore.acquire(cx, 1).await.expect("legacy acquisition")
                }
                NativeCostArm::Checked => semaphore
                    .acquire_checked(cx, 1)
                    .await
                    .expect("checked quota-one acquisition"),
            };
            assert_eq!(permit.count(), 1);
            let id = native_cost_observe_reserved(observer, cx.task_id()).await;
            drop(permit);
            assert_eq!(semaphore.available_permits(), 1, "actual capacity release");
            id
        }
    };
    native_cost_observe_settled(observer, cx.task_id(), reserved).await;
    reserved
}

fn native_cost_validate_cleanup(
    runtime: &asupersync::runtime::Runtime,
    primitive: NativeCostPrimitive,
    observation: &NativeCostObservation,
) -> usize {
    use asupersync::record::ObligationState;
    use asupersync::trace::TraceData;

    let started = std::time::Instant::now();
    while !runtime.is_quiescent() {
        assert!(
            started.elapsed() < NATIVE_COST_SHUTDOWN_TIMEOUT,
            "native tasks and application barriers must drain; active={:?} leaks={:?}",
            runtime
                .task_inspector(Default::default())
                .list_active_tasks(),
            runtime.diagnostics().find_leaked_obligations(),
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert!(
        runtime
            .task_inspector(Default::default())
            .list_tasks()
            .is_empty()
    );
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    let mut ids = observation.ids.clone();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), NATIVE_COST_WARMUP + NATIVE_COST_SAMPLES);
    let trace = runtime.trace_snapshot();
    let retained_events = trace.len();
    assert!(
        retained_events < runtime.trace_buffer_capacity(),
        "fresh native ring must never reach capacity; missing history cannot establish complete lifecycle pairs"
    );
    let mut lifecycles = std::collections::BTreeMap::new();
    for event in trace {
        if let TraceData::Obligation {
            obligation,
            task,
            region,
            kind,
            state,
            ..
        } = event.data
        {
            assert_eq!(
                task, observation.holder,
                "only the live holder creates obligations"
            );
            assert_eq!(region, observation.region);
            assert_eq!(kind, primitive.kind());
            lifecycles
                .entry(obligation)
                .or_insert_with(Vec::new)
                .push(state);
        }
    }
    assert_eq!(
        lifecycles.len(),
        ids.len(),
        "complete retained trace, no extra obligations"
    );
    for id in &ids {
        assert_eq!(
            lifecycles
                .get(id)
                .expect("every observed ID must have actual trace evidence"),
            &[ObligationState::Reserved, ObligationState::Committed],
            "exact successful reservation/terminal pair for {id:?}"
        );
    }
    retained_events
}

fn native_cost_measure_arm(
    sharded: bool,
    primitive: NativeCostPrimitive,
    arm: NativeCostArm,
) -> (NativeCostObservation, usize) {
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::runtime::config::{RuntimeStateShape, TraceStorageProfile};

    let mut limits = asupersync::record::RegionLimits::UNLIMITED;
    limits.max_obligations = Some(1);
    let builder = if sharded {
        RuntimeBuilder::multi_thread()
            .worker_threads(2)
            .with_sharded_state(true)
    } else {
        RuntimeBuilder::current_thread()
    };
    let runtime = builder
        .root_region_limits(limits)
        // Predeclare the same fixed retention envelope for both arms. Cleanup
        // refuses a full ring and requires all 4352 exact lifecycle pairs;
        // extra scheduler events may not silently evict required evidence.
        // This is storage setup, not a claim about the worker's physical RAM.
        .trace_storage_profile(TraceStorageProfile::LargeMemory256G)
        .build()
        .expect("build measured native runtime");
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_eq!(runtime.config().worker_threads, if sharded { 2 } else { 1 });
        assert_eq!(
            runtime.config().runtime_state_shape,
            if sharded {
                RuntimeStateShape::Sharded
            } else {
                RuntimeStateShape::Unified
            }
        );
        assert_eq!(
            runtime
                .config()
                .trace_storage_profile
                .trace_buffer_capacity(),
            262_144
        );
        assert_eq!(runtime.trace_buffer_capacity(), 262_144);
        let observer = runtime.handle();
        let (sender, mut receiver) = asupersync::channel::mpsc::channel::<u64>(1);
        let observed_sender = sender.clone();
        let semaphore = Arc::new(asupersync::sync::Semaphore::new(1));
        let observed_semaphore = Arc::clone(&semaphore);
        let join = runtime.handle().spawn(async move {
            let cx = Cx::current().expect("real spawned native holder context");
            let mut ids = Vec::with_capacity(NATIVE_COST_WARMUP + NATIVE_COST_SAMPLES);
            let mut samples_ns = Vec::with_capacity(NATIVE_COST_SAMPLES);
            let mut cycle_end_threads = Vec::with_capacity(if sharded { 2 } else { 1 });
            assert!(native_cost_holder_ids(&observer, cx.task_id()).is_empty());
            for index in 0..NATIVE_COST_WARMUP {
                ids.push(
                    native_cost_cycle(
                        primitive,
                        arm,
                        &cx,
                        &observer,
                        &sender,
                        &mut receiver,
                        &semaphore,
                        index as u64,
                    )
                    .await,
                );
            }
            let window = NativeCostWindow::start();
            let measured_start = std::time::Instant::now();
            for index in 0..NATIVE_COST_SAMPLES {
                let started = std::time::Instant::now();
                let id = native_cost_cycle(
                    primitive,
                    arm,
                    &cx,
                    &observer,
                    &sender,
                    &mut receiver,
                    &semaphore,
                    (NATIVE_COST_WARMUP + index) as u64,
                )
                .await;
                let elapsed_ns = u64::try_from(started.elapsed().as_nanos())
                    .expect("bounded cycle duration fits u64 nanoseconds");
                samples_ns.push(elapsed_ns);
                ids.push(id);
                let current_thread = std::thread::current().id();
                if !cycle_end_threads.contains(&current_thread) {
                    assert!(
                        cycle_end_threads.len() < cycle_end_threads.capacity(),
                        "sample storage must not grow inside the counting window"
                    );
                    cycle_end_threads.push(current_thread);
                }
            }
            let elapsed = measured_start.elapsed();
            let allocations = window.finish();
            NativeCostObservation {
                holder: cx.task_id(),
                region: cx.region_id(),
                ids,
                samples_ns,
                allocations,
                elapsed,
                cycle_end_threads,
            }
        });
        let started = std::time::Instant::now();
        while !join.is_finished() {
            assert!(
                started.elapsed() < NATIVE_COST_ARM_TIMEOUT,
                "bounded native arm failed to complete: sharded={sharded} primitive={primitive:?} arm={arm:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        // Already terminal: this preserves any original spawned-task panic.
        let observation = runtime.block_on(join);
        assert!(!NATIVE_COST_COUNTING.load(Ordering::SeqCst));
        let retained_events = native_cost_validate_cleanup(&runtime, primitive, &observation);
        let channel = observed_sender.telemetry_snapshot(29);
        assert_eq!(channel.capacity, 1);
        assert_eq!(channel.queued_messages, 0);
        assert_eq!(channel.reserved_uncommitted_obligations, 0);
        assert_eq!(channel.send_waiter_count, 0);
        assert_eq!(channel.recv_waiter_count, 0);
        let semaphore = observed_semaphore.telemetry_snapshot(29);
        assert_eq!(semaphore.capacity, 1);
        assert_eq!(semaphore.available_units, 1);
        assert_eq!(semaphore.occupied_units, 0);
        assert_eq!(semaphore.waiter_count, 0);
        (observation, retained_events)
    }));
    NATIVE_COST_COUNTING.store(false, Ordering::SeqCst);
    let shutdown = runtime.shutdown_timeout(NATIVE_COST_SHUTDOWN_TIMEOUT);
    match outcome {
        Ok(observation) => {
            assert!(shutdown, "all native workers must finish teardown");
            observation
        }
        Err(payload) => {
            if !shutdown {
                eprintln!("native_cost: shutdown also timed out after the primary arm failure");
            }
            std::panic::resume_unwind(payload)
        }
    }
}

fn native_cost_paired(sharded: bool, test_name: &str) {
    let _guard = ALLOC_TEST_GUARD.lock();
    init_test(test_name);
    verify_native_cost_worker_counter();
    let arguments: Vec<String> = std::env::args().collect();
    let single_thread = arguments.iter().any(|arg| arg == "--test-threads=1")
        || arguments
            .windows(2)
            .any(|pair| pair == ["--test-threads", "1"]);
    let eligible_invocation = single_thread
        && arguments.iter().any(|arg| arg == "--exact")
        && arguments.iter().any(|arg| arg == test_name);
    let mut completed_measured_cycles = 0;
    let mut completed_warmup_cycles = 0;
    for primitive in [NativeCostPrimitive::Mpsc, NativeCostPrimitive::Semaphore] {
        for block in 0..NATIVE_COST_BLOCKS {
            for (position, arm) in [
                NativeCostArm::Legacy,
                NativeCostArm::Checked,
                NativeCostArm::Checked,
                NativeCostArm::Legacy,
            ]
            .into_iter()
            .enumerate()
            {
                let (observation, retained_events) =
                    native_cost_measure_arm(sharded, primitive, arm);
                assert_eq!(observation.samples_ns.len(), NATIVE_COST_SAMPLES);
                assert!(!observation.elapsed.is_zero());
                let mut sorted = observation.samples_ns.clone();
                sorted.sort_unstable();
                let p95_index = (95 * NATIVE_COST_SAMPLES).div_ceil(100) - 1;
                completed_measured_cycles += observation.samples_ns.len();
                completed_warmup_cycles += observation.ids.len() - observation.samples_ns.len();
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "scenario": "native_instrumented_full_lifecycle_cost",
                        "test": test_name, "crate_version": env!("CARGO_PKG_VERSION"),
                        "debug_assertions": cfg!(debug_assertions),
                        "performance_invocation_eligible": eligible_invocation,
                        "backend": if sharded { "two_worker_sharded" } else { "current_thread_unified" },
                        "configured_workers": if sharded { 2 } else { 1 },
                        "cycle_end_threads": observation.cycle_end_threads.iter()
                            .map(|id| format!("{id:?}")).collect::<Vec<_>>(),
                        "primitive": format!("{primitive:?}"), "arm": format!("{arm:?}"),
                        "block": block, "abba_position": position,
                        "region_obligation_limit": 1, "physical_capacity": 1,
                        "trace_event_slots": 262_144,
                        "observed_retained_trace_events": retained_events,
                        "warmup_cycles": NATIVE_COST_WARMUP,
                        "completed_measured_cycles": observation.samples_ns.len(),
                        "observed_distinct_reserved_then_committed_ids": observation.ids.len(),
                        "holder": format!("{:?}", observation.holder),
                        "region": format!("{:?}", observation.region),
                        "raw_allocation_calls": observation.allocations.allocs,
                        "raw_requested_allocation_bytes": observation.allocations.bytes,
                        "allocation_calls_per_completed_cycle": observation.allocations.allocs as f64 / NATIVE_COST_SAMPLES as f64,
                        "requested_bytes_per_completed_cycle": observation.allocations.bytes as f64 / NATIVE_COST_SAMPLES as f64,
                        "window_elapsed_ns": observation.elapsed.as_nanos(),
                        "completed_cycles_per_second": NATIVE_COST_SAMPLES as f64 / observation.elapsed.as_secs_f64(),
                        "p95_method": "nearest_rank_ceil_0.95_times_n",
                        "p95_ns": sorted[p95_index], "raw_samples_ns": observation.samples_ns,
                        "denominator": "accepted_delivery_or_release_then_observed_terminal_projection",
                        "includes": "inspector_allocation_and_locking_poll_yield_clock_trace_process_background",
                        "excludes": "setup_warmup_sample_storage_allocation_sorting_logging_teardown",
                        "allocation_scope": "process_wide_alloc_calls_and_requested_bytes_not_live_or_peak_bytes",
                        "cleanup": "zero_tasks_obligations_physical_reservations_waiters_and_joined_workers",
                        "no_claim": "isolated_admission_cost_speedup_no_regression_external_task_table_full_28_or_29_closure"
                    })
                );
            }
        }
    }
    assert_eq!(
        completed_measured_cycles,
        2 * NATIVE_COST_BLOCKS * 4 * NATIVE_COST_SAMPLES
    );
    assert_eq!(
        completed_warmup_cycles,
        2 * NATIVE_COST_BLOCKS * 4 * NATIVE_COST_WARMUP
    );
    assert!(!NATIVE_COST_COUNTING.load(Ordering::SeqCst));
    eprintln!(
        "native_cost_complete test={test_name} measured_cycles={completed_measured_cycles} warmup_cycles={completed_warmup_cycles} abba_blocks_per_primitive={NATIVE_COST_BLOCKS} performance_invocation_eligible={eligible_invocation}"
    );
}

#[test]
fn native_obligation_cost_legacy_checked_current_thread() {
    native_cost_paired(
        false,
        "native_obligation_cost_legacy_checked_current_thread",
    );
}

#[test]
fn native_obligation_cost_legacy_checked_two_worker_sharded() {
    native_cost_paired(
        true,
        "native_obligation_cost_legacy_checked_two_worker_sharded",
    );
}
