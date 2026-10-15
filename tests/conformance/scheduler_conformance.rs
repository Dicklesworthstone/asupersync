//! Scheduler conformance suite, driven against the production scheduler.
//!
//! Every row exercises code under `src/runtime/scheduler/`, a runtime built by
//! `RuntimeBuilder`, or the lab runtime. This file defines no scheduler,
//! queue or task type of its own.
//!
//! | Row prefix            | Production code exercised                                         |
//! |-----------------------|-------------------------------------------------------------------|
//! | `local_queue/`        | `LocalQueue` and its `Stealer`                                    |
//! | `stealing/`           | `stealing::steal_task` (power of two choices)                     |
//! | `global_queue/`       | `GlobalQueue`                                                     |
//! | `global_injector/`    | `GlobalInjector` cancel, timed and ready lanes                    |
//! | `intrusive_heap/`     | `IntrusivePriorityHeap` over a real `Arena<TaskRecord>`           |
//! | `priority_scheduler/` | `PriorityScheduler`, the per-worker three-lane scheduler          |
//! | `three_lane/`         | `ThreeLaneScheduler` workers driven through `next_task()`         |
//! | `runtime/`            | current-thread and multi-thread runtimes from `RuntimeBuilder`    |
//! | `lab/`                | `LabRuntime` through `asupersync::conformance::LabRuntimeTarget`  |
//!
//! Contracts checked:
//!
//! - the owner end of a local queue is LIFO and the thief end is FIFO; single
//!   steals, batch steals and `steal_task` move work without losing or
//!   duplicating it, also while the owner and thieves race;
//! - the global queue and the injector's ready and cancel lanes are FIFO and
//!   deliver each task exactly once, also under concurrent producers;
//! - timed work is ordered earliest deadline first with ties in insertion
//!   order and is not dispatched before its deadline; ready work is ordered by
//!   priority with ties in insertion order; the intrusive heap orders by
//!   priority with ties in insertion order;
//! - a worker dispatches cancel, then due timed, then ready work; the cancel
//!   streak limit hands the next dispatch to waiting non-cancel work and never
//!   blocks cancel work that is alone; thieves take ready work only; idle
//!   workers steal from a busy worker's queue;
//! - every task spawned on a runtime runs exactly once, on the thread its
//!   flavor documents; a panicking task joins as `JoinError::Panicked` while
//!   its siblings and later tasks complete; on a single worker, an aborted
//!   task's cleanup runs before ready work queued next to it.
//!
//! Each row's spec section cites the production documentation or in-crate
//! test (file:line) that promises the contract. Contracts that production does
//! not promise, or that this suite cannot reach, are reported as
//! `TestVerdict::Skip` at `RequirementLevel::May` with the reason, never as a
//! pass. One of them is the "finalize lane" an earlier version of this file
//! claimed: production has no such lane.
//!
//! Every wait is bounded. Runtime and lab runs execute on a runner thread
//! awaited with `recv_timeout`; helper threads are joined against a deadline;
//! every drain, spin and yield loop has an iteration or time cap.

use super::harness::{
    ConformanceTestResult, RequirementLevel, RuntimeConformanceHarness, TestCategory, TestVerdict,
};
use asupersync::Cx;
use asupersync::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
use asupersync::record::TaskRecord;
use asupersync::runtime::scheduler::stealing::steal_task;
use asupersync::runtime::scheduler::{
    DispatchLane, GlobalInjector, GlobalQueue, IntrusivePriorityHeap, LocalQueue,
    PriorityScheduler, ThreeLaneScheduler, ThreeLaneWorker,
};
use asupersync::runtime::{JoinError, Runtime, RuntimeBuilder, RuntimeState, yield_now};
use asupersync::sync::ContendedMutex;
use asupersync::time::{TimerDriverHandle, VirtualClock};
use asupersync::types::{Budget, RegionId, TaskId, Time};
use asupersync::util::{Arena, DetRng};
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread::{self, ThreadId};
use std::time::{Duration, Instant};

/// Tasks pushed by the ordering rows.
const SEQUENCE_LEN: u32 = 12;
/// Tasks in the batch-steal row.
const STEAL_BATCH_TASKS: u32 = 200;
/// Tasks shared by the owner and the thieves in the concurrent row.
const CONCURRENT_TASKS: u32 = 512;
/// Thief threads in the concurrent local-queue row.
const THIEVES: usize = 3;
/// Producer threads in the concurrent global-queue and injector rows.
const PRODUCERS: u32 = 4;
/// Tasks pushed by each producer.
const PER_PRODUCER: u32 = 256;
/// Index distance between two producers' task ranges.
const PRODUCER_STRIDE: u32 = 10_000;
/// Tasks in the single-threaded global-queue and injector rows.
const GLOBAL_TASKS: u32 = 64;
/// Victim queues in the `steal_task` drain row.
const VICTIMS: u32 = 5;
/// Seeds tried by the power-of-two-choices row.
const POWER_OF_TWO_SEEDS: u64 = 8;
/// Seed of the `steal_task` drain row.
const STEAL_SEED: u64 = 0x5EED;
/// Workers in the three-lane round-robin rows.
const ROUND_ROBIN_WORKERS: usize = 3;
/// Tasks seeded into worker 0's fast queue in the idle-steal row.
const ROUND_ROBIN_TASKS: u32 = 12;
/// Tasks injected globally across `ROUND_ROBIN_WORKERS` workers: six per
/// worker, inside the ratio range that MR-WS3 covers
/// (work_stealing_fairness_metamorphic.rs:245-250).
const GLOBAL_INJECTION_TASKS: u32 = 18;
/// Cancel streak limits checked through `new_with_cancel_limit`.
const CANCEL_LIMITS: [usize; 4] = [1, 2, 4, 8];
/// The default cancel streak limit (three_lane.rs:166, three_lane_tests.rs:3214).
const DEFAULT_CANCEL_STREAK_LIMIT: usize = 16;
/// Worker threads of the multi-thread runtime rows.
const MULTI_THREAD_WORKERS: usize = 4;
/// Tasks spawned by the exactly-once runtime rows.
const SPAWNED_TASKS: usize = 64;
/// Tasks in the idle-worker row; each holds its worker until a second task
/// has started somewhere.
const RENDEZVOUS_TASKS: usize = 4;
/// Longest a rendezvous task holds its worker waiting for a second task.
const RENDEZVOUS_WAIT: Duration = Duration::from_secs(3);
/// Siblings spawned next to the task that panics.
const PANIC_SIBLINGS: usize = 6;
/// Message of the task that panics on purpose.
const PANIC_MESSAGE: &str = "scheduler conformance: deliberate task panic";
/// Children spawned through `Cx::spawn` by the exactly-once scenario.
const SCENARIO_CHILDREN: usize = 16;
/// Cap on every yield loop inside a scenario.
const SPIN_TURNS: usize = 10_000;
/// Log entry written by the aborted task when it observes cancellation.
const VICTIM_CLEANUP: &str = "victim-cleanup";
/// Log entries written by the ready tasks queued next to the aborted one.
const READY_LABELS: [&str; 3] = ["ready-0", "ready-1", "ready-2"];
/// Seeds of the lab rows.
const LAB_SEEDS: [u64; 3] = [1, 0x5EED, 0xC0_FFEE];
/// Step cap handed to the lab runtime.
const LAB_MAX_STEPS: u64 = 200_000;
/// Bound on helper threads in the data-structure rows.
const THREAD_DEADLINE: Duration = Duration::from_secs(10);
/// Bound on one runtime or lab run.
const RUN_DEADLINE: Duration = Duration::from_secs(30);
/// Bound handed to `Runtime::shutdown_timeout`.
const SHUTDOWN_BOUND: Duration = Duration::from_secs(5);
/// Virtual time, in nanoseconds, at which the worker lane-order row starts.
const LANE_CLOCK_START: u64 = 1_000;

// ---------------------------------------------------------------------------
// Contract table
// ---------------------------------------------------------------------------

/// How a contract row is produced.
#[derive(Clone, Copy)]
enum Check {
    /// Runs the observation against production code.
    Run(fn() -> Observation),
    /// Production does not promise the contract, or this suite cannot reach
    /// it; the row is reported as `Skip` with this reason.
    NotChecked(&'static str),
}

/// One documented scheduler contract.
struct Contract {
    name: &'static str,
    level: RequirementLevel,
    category: TestCategory,
    /// Where the contract is documented or asserted in-crate (file:line).
    spec: &'static str,
    check: Check,
}

impl Contract {
    /// Runs the check; a panic inside it fails the row instead of the suite.
    fn observe(&self) -> Observation {
        match self.check {
            Check::Run(check) => match std::panic::catch_unwind(check) {
                Ok(observation) => observation,
                Err(payload) => Observation::failed(format!(
                    "the check panicked: {}",
                    panic_text(payload.as_ref())
                )),
            },
            Check::NotChecked(reason) => Observation::not_checked(reason),
        }
    }
}

const CONTRACTS: &[Contract] = &[
    // ----- local queue -----------------------------------------------------
    Contract {
        name: "local_queue/owner_pop_is_lifo",
        level: RequirementLevel::Must,
        category: TestCategory::WorkStealing,
        spec: "src/runtime/scheduler/local_queue.rs:3, 77-81 (owner pushes and pops one end, \
               LIFO), 320 (pop is LIFO); in-crate local_queue.rs:819",
        check: Check::Run(local_queue_owner_pop_is_lifo),
    },
    Contract {
        name: "local_queue/steal_is_fifo",
        level: RequirementLevel::Must,
        category: TestCategory::WorkStealing,
        spec: "src/runtime/scheduler/local_queue.rs:3, 77-81 (other workers steal from the other \
               end, FIFO), 567-576; in-crate local_queue.rs:832",
        check: Check::Run(local_queue_steal_is_fifo),
    },
    Contract {
        name: "local_queue/steal_batch_moves_without_loss_or_duplication",
        level: RequirementLevel::Must,
        category: TestCategory::WorkStealing,
        spec: "src/runtime/scheduler/local_queue.rs:618-622 (steal_batch), 63-70 (queue and \
               presence index move together), 77-81 (thieves take the FIFO end); in-crate \
               local_queue.rs:929",
        check: Check::Run(local_queue_steal_batch_conserves_tasks),
    },
    Contract {
        name: "local_queue/concurrent_owner_and_thieves_take_each_task_once",
        level: RequirementLevel::Must,
        category: TestCategory::WorkStealing,
        spec: "src/runtime/scheduler/local_queue.rs:77-81 (single producer, multi consumer); \
               in-crate local_queue.rs:973",
        check: Check::Run(local_queue_concurrent_take_once),
    },
    // ----- steal_task ------------------------------------------------------
    Contract {
        name: "stealing/steal_task_drains_every_victim_once",
        level: RequirementLevel::Must,
        category: TestCategory::WorkStealing,
        spec: "src/runtime/scheduler/stealing.rs:7-16, 57-69 (fallback scan visits every \
               victim); in-crate stealing.rs:168, 191",
        check: Check::Run(steal_task_drains_every_victim_once),
    },
    Contract {
        name: "stealing/power_of_two_prefers_heavier_victim",
        level: RequirementLevel::Should,
        category: TestCategory::LoadBalancing,
        spec: "src/runtime/scheduler/stealing.rs:9-14, 33-41 (steal from the more loaded of \
               two candidates); in-crate stealing.rs:341",
        check: Check::Run(steal_task_prefers_heavier_victim),
    },
    // ----- global queue ----------------------------------------------------
    Contract {
        name: "global_queue/fifo_exactly_once",
        level: RequirementLevel::Must,
        category: TestCategory::TaskPoolManagement,
        spec: "src/runtime/scheduler/global_queue.rs:1-4, 71-75 (unbounded MPMC FIFO), \
               269-310; in-crate global_queue.rs:428, 443",
        check: Check::Run(global_queue_fifo_exactly_once),
    },
    Contract {
        name: "global_queue/concurrent_producers_exactly_once_in_producer_order",
        level: RequirementLevel::Must,
        category: TestCategory::TaskPoolManagement,
        spec: "src/runtime/scheduler/global_queue.rs:71-75; in-crate global_queue.rs:473 (no \
               duplicates), 511 (each producer's order is kept)",
        check: Check::Run(global_queue_concurrent_producers_exactly_once),
    },
    // ----- global injector -------------------------------------------------
    Contract {
        name: "global_injector/ready_lane_fifo_exactly_once",
        level: RequirementLevel::Must,
        category: TestCategory::TaskPoolManagement,
        spec: "src/runtime/scheduler/global_injector.rs:274-280 (the global ready queue is FIFO; \
               priority ordering happens after a worker takes the task), 533-537; in-crate \
               global_injector.rs:880",
        check: Check::Run(injector_ready_lane_fifo),
    },
    Contract {
        name: "global_injector/concurrent_ready_injection_exactly_once",
        level: RequirementLevel::Must,
        category: TestCategory::TaskPoolManagement,
        spec: "src/runtime/scheduler/global_injector.rs:274-294; in-crate \
               global_injector.rs:675-740 (no loss and no double enqueue under producer \
               contention)",
        check: Check::Run(injector_concurrent_ready_exactly_once),
    },
    Contract {
        name: "global_injector/cancel_lane_fifo",
        level: RequirementLevel::Should,
        category: TestCategory::CancellationLane,
        spec: "src/runtime/scheduler/global_injector.rs:160-170, 242-248; in-crate \
               global_injector.rs:768",
        check: Check::Run(injector_cancel_lane_fifo),
    },
    Contract {
        name: "global_injector/timed_lane_edf_ties_in_insertion_order",
        level: RequirementLevel::Must,
        category: TestCategory::PriorityScheduling,
        spec: "src/runtime/scheduler/global_injector.rs:114-151 (earliest deadline first, then \
               insertion order), 250-255, 458-466 (pop_timed_if_due); in-crate \
               global_injector.rs:806, 823, 838",
        check: Check::Run(injector_timed_lane_edf),
    },
    Contract {
        name: "global_injector/lane_counts_track_contents",
        level: RequirementLevel::Should,
        category: TestCategory::MetricsCollection,
        spec: "src/runtime/scheduler/global_injector.rs:548-552 (is_empty), 577-618 (len, \
               cancel_count, ready_count and has_*_work); in-crate global_injector.rs:893",
        check: Check::Run(injector_lane_counts),
    },
    // ----- intrusive heap --------------------------------------------------
    Contract {
        name: "intrusive_heap/priority_order_ties_in_insertion_order",
        level: RequirementLevel::Must,
        category: TestCategory::PriorityScheduling,
        spec: "src/runtime/scheduler/intrusive_heap.rs:24-27 (higher priority first, earlier \
               generation wins ties), 141-151 (re-pushing a queued task is a no-op), 191-198 \
               (remove); in-crate intrusive_heap.rs:476, 507, 524",
        check: Check::Run(intrusive_heap_priority_order),
    },
    // ----- priority scheduler ----------------------------------------------
    Contract {
        name: "priority_scheduler/lanes_dispatch_cancel_then_timed_then_ready",
        level: RequirementLevel::Must,
        category: TestCategory::PriorityScheduling,
        spec: "src/runtime/scheduler/priority.rs:1-9, 541-547 (cancel > timed > ready), 578-587 \
               (pop_with_lane); in-crate priority.rs:1764, 2073",
        check: Check::Run(priority_lanes_cancel_timed_ready),
    },
    Contract {
        name: "priority_scheduler/cancel_promotes_a_queued_task_once",
        level: RequirementLevel::Must,
        category: TestCategory::CancellationLane,
        spec: "src/runtime/scheduler/priority.rs:507-513 (an already scheduled task moves to the \
               cancel lane), 490-493 (no duplicate scheduling); in-crate priority.rs:3230",
        check: Check::Run(priority_cancel_promotion_once),
    },
    Contract {
        name: "priority_scheduler/timed_lane_edf_ties_in_insertion_order",
        level: RequirementLevel::Must,
        category: TestCategory::PriorityScheduling,
        spec: "src/runtime/scheduler/priority.rs:50-75 (earliest deadline first, then earlier \
               generation); in-crate priority.rs:1653, 2782",
        check: Check::Run(priority_timed_lane_edf),
    },
    Contract {
        name: "priority_scheduler/ready_lane_priority_ties_in_insertion_order",
        level: RequirementLevel::Must,
        category: TestCategory::PriorityScheduling,
        spec: "src/runtime/scheduler/priority.rs:17-41 (higher priority first, then earlier \
               generation); in-crate priority.rs:1751",
        check: Check::Run(priority_ready_lane_order),
    },
    Contract {
        name: "priority_scheduler/timed_work_waits_for_its_deadline",
        level: RequirementLevel::Should,
        category: TestCategory::PriorityScheduling,
        spec: "src/runtime/scheduler/priority.rs:623-628 (pop_with_lane_if_due), 928-933 \
               (pop_timed_only); in-crate priority.rs:2113, 2130, 2552",
        check: Check::Run(priority_timed_waits_for_deadline),
    },
    // ----- three-lane workers ----------------------------------------------
    Contract {
        name: "three_lane/worker_dispatches_cancel_then_timed_then_ready",
        level: RequirementLevel::Must,
        category: TestCategory::TaskPoolManagement,
        spec: "src/runtime/scheduler/three_lane.rs:3-4 (strict cancel > timed > ready), \
               6504-6595 (next_task phases); in-crate three_lane_tests.rs:1262 (EDF from the \
               global queue), 1310 (future deadlines wait), 1340 (cancel before timed)",
        check: Check::Run(worker_lane_order),
    },
    Contract {
        name: "three_lane/preemption_metrics_count_each_lane",
        level: RequirementLevel::Should,
        category: TestCategory::MetricsCollection,
        spec: "src/runtime/scheduler/three_lane.rs:3615-3623 (cancel, timed and ready dispatch \
               counters), 6756-6791 (recorded on each dispatch)",
        check: Check::Run(worker_lane_metrics),
    },
    Contract {
        name: "three_lane/cancel_streak_limit_yields_to_ready_work",
        level: RequirementLevel::Must,
        category: TestCategory::CancellationLane,
        spec: "src/runtime/scheduler/three_lane.rs:41-47 (at most E_c consecutive cancel \
               dispatches while other work is eligible), 78-88, 166 (default limit 16), \
               1881-1888; in-crate three_lane_tests.rs:870, 3214, 5174",
        check: Check::Run(worker_cancel_streak_limit),
    },
    Contract {
        name: "three_lane/cancel_only_work_is_not_blocked_by_the_limit",
        level: RequirementLevel::Must,
        category: TestCategory::CancellationLane,
        spec: "src/runtime/scheduler/three_lane.rs:90-93 (fallback cancel dispatch when no other \
               work exists), 6597-6611; in-crate three_lane_tests.rs:5205",
        check: Check::Run(worker_cancel_only_work_proceeds),
    },
    Contract {
        name: "three_lane/thieves_steal_ready_work_only",
        level: RequirementLevel::Must,
        category: TestCategory::WorkStealing,
        spec: "src/runtime/scheduler/three_lane.rs:68-70, 124-126 (stealing operates on ready \
               work only); priority.rs:1044-1047; in-crate three_lane_tests.rs:935",
        check: Check::Run(worker_thieves_take_ready_only),
    },
    Contract {
        name: "three_lane/idle_workers_steal_from_a_busy_fast_queue",
        level: RequirementLevel::Must,
        category: TestCategory::WorkStealing,
        spec: "src/runtime/scheduler/three_lane.rs:7466-7476 (idle workers steal other workers' \
               fast queues first); local_queue.rs:77-81 (owner LIFO, thief FIFO); in-crate \
               three_lane_tests.rs:5815, 6025",
        check: Check::Run(worker_idle_workers_steal),
    },
    Contract {
        name: "three_lane/steal_counters_record_successful_steals",
        level: RequirementLevel::Should,
        category: TestCategory::MetricsCollection,
        spec: "src/runtime/scheduler/three_lane.rs:3416-3427 (successful fast-queue and heap \
               steal counters), 7486-7490",
        check: Check::Run(worker_steal_counters),
    },
    Contract {
        name: "three_lane/global_injection_reaches_each_task_once",
        level: RequirementLevel::Must,
        category: TestCategory::TaskPoolManagement,
        spec: "src/runtime/scheduler/mod.rs:8-9; in-crate \
               work_stealing_fairness_metamorphic.rs:86-125 (MR-WS1: every injected task \
               polled exactly once), 245-333 (MR-WS3: every worker polls a task)",
        check: Check::Run(worker_global_injection_once),
    },
    // ----- public runtime --------------------------------------------------
    Contract {
        name: "runtime/current_thread/spawned_tasks_run_exactly_once",
        level: RequirementLevel::Must,
        category: TestCategory::TaskExecution,
        spec: "src/runtime/builder.rs:5045-5057 (RuntimeHandle::spawn), 5262-5263 (the join \
               handle yields the task's output), 4123-4130",
        check: Check::Run(current_thread_tasks_run_once),
    },
    Contract {
        name: "runtime/current_thread/tasks_spawned_and_joined_inside_block_on_run_on_the_caller",
        level: RequirementLevel::Should,
        category: TestCategory::TaskExecution,
        spec: "src/runtime/builder.rs:3613-3626 (while block_on runs, every task spawned through \
               RuntimeHandle::spawn or Cx::spawn is polled on the calling thread; between calls \
               the background thread runs the worker), 4114-4127, 4244-4263 \
               (Runtime::current_handle inside block_on); in-crate \
               tests/runtime_current_thread_root_task.rs:189, 211",
        check: Check::Run(current_thread_block_on_tasks_on_caller),
    },
    Contract {
        name: "runtime/multi_thread/spawned_tasks_run_exactly_once",
        level: RequirementLevel::Must,
        category: TestCategory::TaskExecution,
        spec: "src/runtime/builder.rs:5045-5057 (RuntimeHandle::spawn), 5262-5263",
        check: Check::Run(multi_thread_tasks_run_once),
    },
    Contract {
        name: "runtime/multi_thread/tasks_run_on_worker_threads",
        level: RequirementLevel::Should,
        category: TestCategory::TaskExecution,
        spec: "src/runtime/builder.rs:4131-4135 (spawned tasks run on workers; block_on polls \
               only its own future on the caller)",
        check: Check::Run(multi_thread_tasks_on_workers),
    },
    Contract {
        name: "runtime/multi_thread/idle_workers_take_queued_work",
        level: RequirementLevel::Should,
        category: TestCategory::LoadBalancing,
        spec: "src/runtime/scheduler/mod.rs:8-9 (work stealing for load balancing across \
               workers); three_lane.rs:3155-3158 (an enqueued spawn wakes a parked worker); \
               in-crate work_stealing_fairness_metamorphic.rs:245-333 (MR-WS3)",
        check: Check::Run(multi_thread_idle_workers_take_work),
    },
    Contract {
        name: "runtime/current_thread/panic_is_isolated_to_its_task",
        level: RequirementLevel::Must,
        category: TestCategory::PanicIsolation,
        spec: "src/runtime/builder.rs:6238-6239 (a task panic does not take down its worker), \
               6641-6646, 6714-6726 (spawn_checked reports JoinError::Panicked); in-crate \
               builder.rs:11303",
        check: Check::Run(current_thread_panic_isolated),
    },
    Contract {
        name: "runtime/multi_thread/panic_is_isolated_to_its_task",
        level: RequirementLevel::Must,
        category: TestCategory::PanicIsolation,
        spec: "src/runtime/builder.rs:6238-6239, 6641-6646, 6714-6726; in-crate \
               builder.rs:11303",
        check: Check::Run(multi_thread_panic_isolated),
    },
    Contract {
        name: "runtime/current_thread/aborted_task_cleanup_precedes_ready_work",
        level: RequirementLevel::Should,
        category: TestCategory::CancellationLane,
        spec: "src/runtime/scheduler/mod.rs:3-6 (cancel lane first); three_lane.rs:3-4, \
               6423-6424 (abort commands are drained before any dispatch), 6506-6525; \
               task_handle.rs:968-969 (abort publishes into the cancel lane); \
               cx.rs:4471-4483",
        check: Check::Run(current_thread_abort_cleanup_first),
    },
    Contract {
        name: "runtime/multi_thread/cx_spawned_children_run_exactly_once",
        level: RequirementLevel::Must,
        category: TestCategory::TaskExecution,
        spec: "src/cx/cx.rs:4451-4458 (Cx::spawn), 4471-4483; task_handle.rs:763 \
               (TaskHandle::join)",
        check: Check::Run(multi_thread_cx_children_once),
    },
    // ----- lab runtime -----------------------------------------------------
    Contract {
        name: "lab/cx_spawned_children_run_exactly_once",
        level: RequirementLevel::Must,
        category: TestCategory::TaskExecution,
        spec: "src/cx/cx.rs:4451-4458; src/lab/runtime.rs:4412-4418 (spawn admission at each \
               step); src/conformance/mod.rs:708-796 (LabRuntimeTarget::block_on)",
        check: Check::Run(lab_cx_children_once),
    },
    Contract {
        name: "lab/aborted_task_cleanup_precedes_ready_work",
        level: RequirementLevel::Should,
        category: TestCategory::CancellationLane,
        spec: "src/lab/runtime.rs:4412-4418 (abort commands drained before dispatch), \
               6138-6157 (schedule_cancel promotes), 6243-6290 (cancel lane popped first); \
               priority.rs:541-547",
        check: Check::Run(lab_abort_cleanup_first),
    },
    // ----- not promised or not reachable -----------------------------------
    Contract {
        name: "three_lane/finalize_lane",
        level: RequirementLevel::May,
        category: TestCategory::TaskPoolManagement,
        spec: "src/runtime/scheduler/mod.rs:1-6 (the three lanes are cancel, timed and ready)",
        check: Check::NotChecked(
            "production defines no finalize lane: the lanes are cancel, timed and ready \
             (src/runtime/scheduler/mod.rs:1-6, three_lane.rs:3-4)",
        ),
    },
    Contract {
        name: "three_lane/global_priority_order_across_workers",
        level: RequirementLevel::May,
        category: TestCategory::PriorityScheduling,
        spec: "src/runtime/scheduler/three_lane.rs:68-70, 103-127",
        check: Check::NotChecked(
            "not promised: the fairness and priority contract is per worker and explicitly \
             claims no global priority order across workers (three_lane.rs:68-70, 103-127)",
        ),
    },
    Contract {
        name: "runtime/preemption_inside_a_poll",
        level: RequirementLevel::May,
        category: TestCategory::PriorityScheduling,
        spec: "src/runtime/scheduler/three_lane.rs:62-67",
        check: Check::NotChecked(
            "not promised: a dispatch runs exactly one Future::poll and the runtime cannot \
             preempt inside it (three_lane.rs:62-67); higher-priority work waits for the next \
             dispatch, which the lane-order rows check",
        ),
    },
    Contract {
        name: "intrusive_heap/zero_allocation_after_warmup",
        level: RequirementLevel::May,
        category: TestCategory::PriorityScheduling,
        spec: "src/runtime/scheduler/intrusive_heap.rs:18-19, 72-80",
        check: Check::NotChecked(
            "not reachable here: counting allocations needs a #[global_allocator], which a \
             shared conformance binary cannot install; tests/cache_aware_queues.rs:545 covers \
             it in its own binary",
        ),
    },
    Contract {
        name: "intrusive_heap/concurrent_access",
        level: RequirementLevel::May,
        category: TestCategory::PriorityScheduling,
        spec: "src/runtime/scheduler/intrusive_heap.rs:151, 181",
        check: Check::NotChecked(
            "not promised: IntrusivePriorityHeap::push and pop take &mut self and the arena by \
             &mut (intrusive_heap.rs:151, 181); callers serialize access, so there is no \
             concurrent-access contract to check",
        ),
    },
    Contract {
        name: "global_injector/injection_rate_limiting",
        level: RequirementLevel::May,
        category: TestCategory::LoadBalancing,
        spec: "src/runtime/scheduler/three_lane.rs:2936-2941",
        check: Check::NotChecked(
            "not promised: admission policy belongs before task creation, and an admitted task \
             must be published, never dropped or throttled by the injector \
             (three_lane.rs:2936-2941)",
        ),
    },
    Contract {
        name: "runtime/panic_count_metric",
        level: RequirementLevel::May,
        category: TestCategory::PanicIsolation,
        spec: "src/runtime/panic_isolation.rs:622-640",
        check: Check::NotChecked(
            "not checked: a panic count exists only as the MetricsProvider record_panic hook \
             (panic_isolation.rs:622-640), which needs a full custom MetricsProvider, and no \
             scheduler document says that a RuntimeHandle::spawn panic, caught by the spawn \
             wrapper (builder.rs:6237-6241), reaches it",
        ),
    },
];

// ---------------------------------------------------------------------------
// Observation and harness
// ---------------------------------------------------------------------------

/// What one contract check saw.
#[derive(Debug, Default)]
struct Observation {
    /// Number of requirements evaluated; a row that evaluated none fails.
    checks: usize,
    /// Contract violations; any entry fails the row.
    violations: Vec<String>,
    /// Set for contracts that are not promised or not reachable.
    not_checked: Option<String>,
}

impl Observation {
    fn failed(message: impl Into<String>) -> Self {
        let mut observation = Self::default();
        observation.violation(message);
        observation
    }

    fn not_checked(reason: &str) -> Self {
        Self {
            not_checked: Some(reason.to_owned()),
            ..Self::default()
        }
    }

    fn require(&mut self, holds: bool, message: impl FnOnce() -> String) {
        self.checks += 1;
        if !holds {
            self.violations.push(message());
        }
    }

    fn violation(&mut self, message: impl Into<String>) {
        self.checks += 1;
        self.violations.push(message.into());
    }

    /// Fails on any violation, reports `Skip` for unchecked contracts, and
    /// fails closed when nothing was evaluated.
    fn verdict(&self) -> TestVerdict {
        if !self.violations.is_empty() {
            TestVerdict::Fail(self.violations.join("; "))
        } else if let Some(reason) = &self.not_checked {
            TestVerdict::Skip(reason.clone())
        } else if self.checks == 0 {
            TestVerdict::Fail("no requirement was evaluated, so nothing was verified".to_owned())
        } else {
            TestVerdict::Pass
        }
    }
}

/// Conformance harness that runs every scheduler contract against production
/// scheduler code.
pub struct SchedulerConformanceHarness {
    harness: RuntimeConformanceHarness,
}

impl SchedulerConformanceHarness {
    /// Create a new scheduler conformance test harness.
    pub fn new() -> Self {
        Self {
            harness: RuntimeConformanceHarness::new(),
        }
    }

    /// Run the complete scheduler conformance suite, one row per contract.
    pub fn run_full_suite(&mut self) -> Vec<ConformanceTestResult> {
        CONTRACTS
            .iter()
            .map(|contract| self.run_contract(contract))
            .collect()
    }

    fn run_contract(&self, contract: &Contract) -> ConformanceTestResult {
        self.harness
            .run_test(
                || contract.observe().verdict(),
                contract.name,
                contract.level,
                contract.category,
            )
            .with_spec_section(contract.spec)
    }
}

impl Default for SchedulerConformanceHarness {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Fixtures and judges
// ---------------------------------------------------------------------------

fn task(index: u32) -> TaskId {
    TaskId::new_for_test(index, 0)
}

fn tasks(count: u32) -> Vec<TaskId> {
    (0..count).map(task).collect()
}

fn index_of(id: TaskId) -> usize {
    id.arena_index().index() as usize
}

fn max_index(list: &[TaskId]) -> u32 {
    list.iter()
        .map(|id| id.arena_index().index())
        .max()
        .unwrap_or(0)
}

fn producer_task(producer: u32, offset: u32) -> TaskId {
    task(producer * PRODUCER_STRIDE + offset)
}

fn ids(list: &[TaskId]) -> String {
    list.iter()
        .map(|id| index_of(*id).to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// A runtime state with no task records; scheduler code treats a missing
/// record as an ordinary stealable task (local_queue.rs:594-599).
fn bare_state() -> Arc<ContendedMutex<RuntimeState>> {
    Arc::new(ContendedMutex::new(
        "scheduler_conformance",
        RuntimeState::new(),
    ))
}

/// A runtime state whose scheduler time comes from a virtual clock.
fn clocked_state(start: Time) -> (Arc<ContendedMutex<RuntimeState>>, Arc<VirtualClock>) {
    let clock = Arc::new(VirtualClock::starting_at(start));
    let mut state = RuntimeState::new();
    state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::clone(&clock)));
    (
        Arc::new(ContendedMutex::new("scheduler_conformance", state)),
        clock,
    )
}

/// An arena holding a task record for each of `task(0..count)`.
fn task_arena(count: u32) -> Arena<TaskRecord> {
    let mut arena = Arena::new();
    for index in 0..count {
        let _ = arena.insert(TaskRecord::new(
            task(index),
            RegionId::new_for_test(0, 1),
            Budget::INFINITE,
        ));
    }
    arena
}

/// Collects items until `next` returns `None` or `limit` items were taken.
fn drain_with(limit: usize, mut next: impl FnMut() -> Option<TaskId>) -> Vec<TaskId> {
    let mut drained = Vec::new();
    while drained.len() < limit {
        match next() {
            Some(id) => drained.push(id),
            None => break,
        }
    }
    drained
}

fn load_counts(counters: &[AtomicUsize]) -> Vec<usize> {
    counters
        .iter()
        .map(|counter| counter.load(Ordering::SeqCst))
        .collect()
}

fn push_locked<T>(shared: &Mutex<Vec<T>>, value: T) {
    shared
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(value);
}

fn take_locked<T>(shared: &Mutex<Vec<T>>) -> Vec<T> {
    std::mem::take(&mut *shared.lock().unwrap_or_else(PoisonError::into_inner))
}

fn panic_text(payload: &(dyn Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_owned()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

/// The observed order must equal the expected order exactly.
fn expect_sequence(obs: &mut Observation, what: &str, observed: &[TaskId], expected: &[TaskId]) {
    obs.require(observed == expected, || {
        format!(
            "{what}: observed [{}], expected [{}]",
            ids(observed),
            ids(expected)
        )
    });
}

/// Every expected task must be delivered exactly once, and nothing else.
fn expect_each_once(obs: &mut Observation, what: &str, delivered: &[TaskId], expected: &[TaskId]) {
    let mut counts: HashMap<TaskId, usize> = HashMap::new();
    for id in delivered {
        *counts.entry(*id).or_insert(0) += 1;
    }
    let expected_set: HashSet<TaskId> = expected.iter().copied().collect();
    let missing: Vec<TaskId> = expected
        .iter()
        .copied()
        .filter(|id| !counts.contains_key(id))
        .collect();
    let repeated: Vec<TaskId> = expected
        .iter()
        .copied()
        .filter(|id| counts.get(id).is_some_and(|seen| *seen > 1))
        .collect();
    let foreign: Vec<TaskId> = counts
        .keys()
        .copied()
        .filter(|id| !expected_set.contains(id))
        .collect();
    obs.require(missing.is_empty(), || {
        format!(
            "{what}: {} of {} tasks never delivered: [{}]",
            missing.len(),
            expected.len(),
            ids(&missing)
        )
    });
    obs.require(repeated.is_empty(), || {
        format!("{what}: delivered more than once: [{}]", ids(&repeated))
    });
    obs.require(foreign.is_empty(), || {
        format!("{what}: delivered tasks never queued: [{}]", ids(&foreign))
    });
}

/// Each counter must read exactly one: every task ran, none ran twice.
fn expect_counts_once(obs: &mut Observation, what: &str, counts: &[usize]) {
    let missing: Vec<usize> = counts
        .iter()
        .enumerate()
        .filter(|(_, runs)| **runs == 0)
        .map(|(index, _)| index)
        .collect();
    let repeated: Vec<(usize, usize)> = counts
        .iter()
        .enumerate()
        .filter(|(_, runs)| **runs > 1)
        .map(|(index, runs)| (index, *runs))
        .collect();
    obs.require(!counts.is_empty(), || {
        format!("{what}: no task was counted")
    });
    obs.require(missing.is_empty(), || {
        format!(
            "{what}: {} of {} tasks never ran: {missing:?}",
            missing.len(),
            counts.len()
        )
    });
    obs.require(repeated.is_empty(), || {
        format!("{what}: tasks ran more than once (index, runs): {repeated:?}")
    });
}

/// A start line for helper threads that spins, yielding, until it opens or
/// its deadline passes.
#[derive(Clone)]
struct Gate {
    open: Arc<AtomicBool>,
    give_up: Instant,
}

impl Gate {
    fn new() -> Self {
        Self {
            open: Arc::new(AtomicBool::new(false)),
            give_up: Instant::now() + THREAD_DEADLINE,
        }
    }

    fn open(&self) {
        self.open.store(true, Ordering::SeqCst);
    }

    fn wait(&self) {
        while !self.open.load(Ordering::SeqCst) && Instant::now() < self.give_up {
            thread::yield_now();
        }
    }
}

fn spawn_into<T: Send + 'static>(
    obs: &mut Observation,
    handles: &mut Vec<thread::JoinHandle<T>>,
    name: &str,
    body: impl FnOnce() -> T + Send + 'static,
) {
    match thread::Builder::new()
        .name(format!("sched-conf-{name}"))
        .spawn(body)
    {
        Ok(handle) => handles.push(handle),
        Err(err) => obs.violation(format!("could not start thread {name}: {err}")),
    }
}

/// Joins helper threads, giving all of them together `THREAD_DEADLINE` to
/// finish; a thread still running then is reported and left detached.
fn join_within<T>(
    obs: &mut Observation,
    what: &str,
    handles: Vec<thread::JoinHandle<T>>,
) -> Vec<T> {
    let give_up = Instant::now() + THREAD_DEADLINE;
    let mut joined = Vec::with_capacity(handles.len());
    for handle in handles {
        while !handle.is_finished() && Instant::now() < give_up {
            thread::yield_now();
        }
        if !handle.is_finished() {
            obs.violation(format!(
                "{what} was still running after {:?}; left detached",
                THREAD_DEADLINE
            ));
            continue;
        }
        match handle.join() {
            Ok(value) => joined.push(value),
            Err(payload) => {
                obs.violation(format!("{what} panicked: {}", panic_text(payload.as_ref())))
            }
        }
    }
    joined
}

/// Runs `body` on its own thread and waits at most `deadline` for it. A body
/// that panics or overruns becomes an error message; an overrunning thread is
/// left detached so the suite itself never hangs.
fn run_bounded<T: Send + 'static>(
    what: &str,
    deadline: Duration,
    body: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    let (sender, receiver) = mpsc::channel();
    let spawned = thread::Builder::new()
        .name(format!("sched-conf-{what}"))
        .spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
            let _ = sender.send(outcome.map_err(|payload| panic_text(payload.as_ref())));
        });
    if let Err(err) = spawned {
        return Err(format!("{what}: could not start its runner thread: {err}"));
    }
    match receiver.recv_timeout(deadline) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(message)) => Err(format!("{what} panicked: {message}")),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
            "{what} did not finish within {deadline:?}; its thread is left detached"
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(format!("{what}: the runner thread ended without reporting"))
        }
    }
}

fn flatten<T>(outcome: Result<Result<T, String>, String>) -> Result<T, String> {
    outcome.and_then(|inner| inner)
}

// ---------------------------------------------------------------------------
// Local queue and steal_task
// ---------------------------------------------------------------------------

/// Pushes `pushed` in order onto a fresh queue and drains its owner end.
fn owner_pops(pushed: &[TaskId]) -> Vec<TaskId> {
    let queue = LocalQueue::new_for_test(max_index(pushed));
    for id in pushed {
        queue.push(*id);
    }
    drain_with(pushed.len() + 2, || queue.pop())
}

/// Pushes `pushed` in order onto a fresh queue and drains its thief end.
fn thief_steals(pushed: &[TaskId]) -> Vec<TaskId> {
    let queue = LocalQueue::new_for_test(max_index(pushed));
    for id in pushed {
        queue.push(*id);
    }
    let stealer = queue.stealer();
    drain_with(pushed.len() + 2, || stealer.steal())
}

fn local_queue_owner_pop_is_lifo() -> Observation {
    let mut obs = Observation::default();
    let pushed = tasks(SEQUENCE_LEN);
    let mut newest_first = pushed.clone();
    newest_first.reverse();
    expect_sequence(
        &mut obs,
        "owner pop order after pushing 0..12",
        &owner_pops(&pushed),
        &newest_first,
    );
    obs
}

fn local_queue_steal_is_fifo() -> Observation {
    let mut obs = Observation::default();
    let pushed = tasks(SEQUENCE_LEN);
    expect_sequence(
        &mut obs,
        "thief steal order after pushing 0..12",
        &thief_steals(&pushed),
        &pushed,
    );
    obs
}

fn local_queue_steal_batch_conserves_tasks() -> Observation {
    let mut obs = Observation::default();
    let pushed = tasks(STEAL_BATCH_TASKS);
    let state = LocalQueue::test_state(STEAL_BATCH_TASKS - 1);
    let source = LocalQueue::new(Arc::clone(&state));
    let destination = LocalQueue::new(Arc::clone(&state));
    for id in &pushed {
        source.push(*id);
    }
    let reported = source.stealer().steal_batch(&destination);
    let moved: Vec<TaskId> = destination.snapshot_tasks().to_vec();
    obs.require(reported && !moved.is_empty(), || {
        format!(
            "steal_batch from a queue of {} reported {reported} and moved {} tasks",
            pushed.len(),
            moved.len()
        )
    });
    obs.require(source.len() + moved.len() == pushed.len(), || {
        format!(
            "after steal_batch the source holds {} and the destination {} of {} tasks",
            source.len(),
            moved.len(),
            pushed.len()
        )
    });
    let oldest = &pushed[..moved.len().min(pushed.len())];
    expect_sequence(
        &mut obs,
        "tasks moved by steal_batch (thieves take the FIFO end)",
        &moved,
        oldest,
    );
    let mut delivered = drain_with(pushed.len() + 2, || source.pop());
    delivered.extend(drain_with(pushed.len() + 2, || destination.pop()));
    expect_each_once(
        &mut obs,
        "source pops plus destination pops after steal_batch",
        &delivered,
        &pushed,
    );
    obs
}

fn local_queue_concurrent_take_once() -> Observation {
    let mut obs = Observation::default();
    let pushed = tasks(CONCURRENT_TASKS);
    let queue = LocalQueue::new_for_test(CONCURRENT_TASKS - 1);
    for id in &pushed {
        queue.push(*id);
    }
    let limit = pushed.len() + 2;
    let gate = Gate::new();
    let mut handles = Vec::new();
    let owner = queue.clone();
    let owner_gate = gate.clone();
    spawn_into(&mut obs, &mut handles, "lq-owner", move || {
        owner_gate.wait();
        drain_with(limit, || {
            let next = owner.pop();
            thread::yield_now();
            next
        })
    });
    for _ in 0..THIEVES {
        let stealer = queue.stealer();
        let thief_gate = gate.clone();
        spawn_into(&mut obs, &mut handles, "lq-thief", move || {
            thief_gate.wait();
            drain_with(limit, || {
                let next = stealer.steal();
                thread::yield_now();
                next
            })
        });
    }
    gate.open();
    let delivered: Vec<TaskId> = join_within(&mut obs, "local queue owner or thief", handles)
        .into_iter()
        .flatten()
        .collect();
    expect_each_once(
        &mut obs,
        "owner pops plus concurrent thief steals",
        &delivered,
        &pushed,
    );
    obs
}

fn steal_task_drains_every_victim_once() -> Observation {
    let mut obs = Observation::default();
    let mut expected = Vec::new();
    // Victim v holds v + 1 tasks, so the victims' loads differ.
    let queues: Vec<LocalQueue> = (0..VICTIMS)
        .map(|victim| {
            let queue = LocalQueue::new_for_test(VICTIMS * 10);
            for slot in 0..=victim {
                let id = task(victim * 10 + slot);
                queue.push(id);
                expected.push(id);
            }
            queue
        })
        .collect();
    let stealers: Vec<_> = queues.iter().map(LocalQueue::stealer).collect();
    let mut rng = DetRng::new(STEAL_SEED);
    let delivered = drain_with(expected.len() + 2, || steal_task(&stealers, &mut rng));
    expect_each_once(
        &mut obs,
        "steal_task over five victims until it returns None",
        &delivered,
        &expected,
    );
    let left: usize = queues.iter().map(LocalQueue::len).sum();
    obs.require(left == 0, || {
        format!("{left} tasks remained in victim queues after steal_task returned None")
    });
    obs
}

fn steal_task_prefers_heavier_victim() -> Observation {
    let mut obs = Observation::default();
    for seed in 0..POWER_OF_TWO_SEEDS {
        let heavy = LocalQueue::new_for_test(20);
        let light = LocalQueue::new_for_test(20);
        for index in 10..13 {
            heavy.push(task(index));
        }
        light.push(task(19));
        // Both candidate orders must pick the heavier victim.
        let stealers = if seed % 2 == 0 {
            vec![heavy.stealer(), light.stealer()]
        } else {
            vec![light.stealer(), heavy.stealer()]
        };
        let mut rng = DetRng::new(seed);
        let stolen = steal_task(&stealers, &mut rng);
        obs.require(stolen == Some(task(10)), || {
            format!(
                "seed {seed}: steal_task took {stolen:?} from a 3-task and a 1-task victim; \
                 expected the heavier victim's oldest task {:?}",
                task(10)
            )
        });
    }
    obs
}

// ---------------------------------------------------------------------------
// Global queue and injector
// ---------------------------------------------------------------------------

fn global_queue_fifo_exactly_once() -> Observation {
    let mut obs = Observation::default();
    let queue = GlobalQueue::new();
    let pushed = tasks(GLOBAL_TASKS);
    for id in &pushed {
        queue.push(*id);
    }
    obs.require(queue.len() == pushed.len(), || {
        format!("len {} after {} pushes", queue.len(), pushed.len())
    });
    let popped = drain_with(pushed.len() + 2, || queue.pop());
    expect_sequence(&mut obs, "global queue pop order", &popped, &pushed);
    obs.require(queue.is_empty() && queue.len() == 0, || {
        format!("a drained global queue reports len {}", queue.len())
    });
    obs
}

fn global_queue_concurrent_producers_exactly_once() -> Observation {
    let mut obs = Observation::default();
    let queue = Arc::new(GlobalQueue::new());
    let gate = Gate::new();
    let mut handles = Vec::new();
    for producer in 0..PRODUCERS {
        let queue = Arc::clone(&queue);
        let producer_gate = gate.clone();
        spawn_into(&mut obs, &mut handles, "gq-producer", move || {
            producer_gate.wait();
            for offset in 0..PER_PRODUCER {
                queue.push(producer_task(producer, offset));
            }
        });
    }
    gate.open();
    let _ = join_within(&mut obs, "global queue producer", handles);
    let expected: Vec<TaskId> = (0..PRODUCERS)
        .flat_map(|producer| (0..PER_PRODUCER).map(move |offset| producer_task(producer, offset)))
        .collect();
    let drained = drain_with(expected.len() + 2, || queue.pop());
    expect_each_once(
        &mut obs,
        "global queue drained after concurrent producers",
        &drained,
        &expected,
    );
    let mut next = vec![0_usize; PRODUCERS as usize];
    let mut out_of_order = Vec::new();
    for id in &drained {
        let raw = index_of(*id);
        let producer = raw / PRODUCER_STRIDE as usize;
        let offset = raw % PRODUCER_STRIDE as usize;
        if let Some(expected_offset) = next.get_mut(producer) {
            if offset != *expected_offset {
                out_of_order.push((producer, offset, *expected_offset));
            }
            *expected_offset = offset + 1;
        }
    }
    obs.require(out_of_order.is_empty(), || {
        format!(
            "a producer's tasks left out of order (producer, offset, expected offset): \
             {out_of_order:?}"
        )
    });
    obs
}

/// A priority that differs between neighbours, so a priority-ordered lane
/// would not reproduce insertion order.
fn varied_priority(rank: usize) -> u8 {
    ((rank * 37) % 256) as u8
}

fn injector_ready_lane_fifo() -> Observation {
    let mut obs = Observation::default();
    let injector = GlobalInjector::new();
    let pushed = tasks(GLOBAL_TASKS);
    for (rank, id) in pushed.iter().enumerate() {
        injector.inject_ready(*id, varied_priority(rank));
    }
    let mut popped = Vec::new();
    while popped.len() < pushed.len() + 2 {
        match injector.pop_ready() {
            Some(entry) => popped.push((entry.task, entry.priority)),
            None => break,
        }
    }
    let order: Vec<TaskId> = popped.iter().map(|(id, _)| *id).collect();
    expect_sequence(&mut obs, "injector ready-lane pop order", &order, &pushed);
    let wrong_priority: Vec<(usize, u8)> = popped
        .iter()
        .enumerate()
        .filter(|(rank, (_, priority))| *priority != varied_priority(*rank))
        .map(|(rank, (_, priority))| (rank, *priority))
        .collect();
    obs.require(wrong_priority.is_empty(), || {
        format!(
            "ready entries came back with other priorities (rank, priority): {wrong_priority:?}"
        )
    });
    obs
}

fn injector_concurrent_ready_exactly_once() -> Observation {
    let mut obs = Observation::default();
    let injector = Arc::new(GlobalInjector::new());
    let gate = Gate::new();
    let mut handles = Vec::new();
    for producer in 0..PRODUCERS {
        let injector = Arc::clone(&injector);
        let producer_gate = gate.clone();
        spawn_into(&mut obs, &mut handles, "gi-producer", move || {
            producer_gate.wait();
            for offset in 0..PER_PRODUCER {
                injector.inject_ready(producer_task(producer, offset), 50);
            }
        });
    }
    gate.open();
    let _ = join_within(&mut obs, "injector producer", handles);
    let expected: Vec<TaskId> = (0..PRODUCERS)
        .flat_map(|producer| (0..PER_PRODUCER).map(move |offset| producer_task(producer, offset)))
        .collect();
    let drained = drain_with(expected.len() + 2, || {
        injector.pop_ready().map(|entry| entry.task)
    });
    expect_each_once(
        &mut obs,
        "injector ready lane drained after concurrent producers",
        &drained,
        &expected,
    );
    obs
}

fn injector_cancel_lane_fifo() -> Observation {
    let mut obs = Observation::default();
    let injector = GlobalInjector::new();
    let pushed = tasks(SEQUENCE_LEN);
    for (rank, id) in pushed.iter().enumerate() {
        injector.inject_cancel(*id, varied_priority(rank));
    }
    let popped = drain_with(pushed.len() + 2, || {
        injector.pop_cancel().map(|entry| entry.task)
    });
    expect_sequence(&mut obs, "injector cancel-lane pop order", &popped, &pushed);
    obs
}

fn injector_timed_lane_edf() -> Observation {
    let mut obs = Observation::default();
    let injector = GlobalInjector::new();
    let plan: [(u32, u64); 6] = [(0, 75), (1, 25), (2, 100), (3, 50), (4, 50), (5, 50)];
    for (index, seconds) in plan {
        injector.inject_timed(task(index), Time::from_secs(seconds));
    }
    let popped = drain_with(plan.len() + 2, || {
        injector.pop_timed().map(|entry| entry.task)
    });
    expect_sequence(
        &mut obs,
        "injector timed-lane pop order for deadlines 75,25,100,50,50,50 s",
        &popped,
        &[task(1), task(3), task(4), task(5), task(0), task(2)],
    );

    let gated = GlobalInjector::new();
    gated.inject_timed(task(6), Time::from_secs(100));
    gated.inject_timed(task(7), Time::from_secs(50));
    let probes = [
        (25, None),
        (50, Some(task(7))),
        (75, None),
        (100, Some(task(6))),
    ];
    for (now, expected) in probes {
        let got = gated
            .pop_timed_if_due(Time::from_secs(now))
            .map(|entry| entry.task);
        obs.require(got == expected, || {
            format!("pop_timed_if_due at {now} s returned {got:?}, expected {expected:?}")
        });
    }
    obs
}

fn injector_lane_counts() -> Observation {
    let mut obs = Observation::default();
    let injector = GlobalInjector::new();
    obs.require(injector.is_empty() && injector.len() == 0, || {
        format!("a new injector reports len {}", injector.len())
    });
    for index in 0..3 {
        injector.inject_cancel(task(index), 10);
    }
    for index in 3..5 {
        injector.inject_timed(task(index), Time::from_secs(u64::from(index)));
    }
    for index in 5..9 {
        injector.inject_ready(task(index), 10);
    }
    let loaded = (
        injector.len(),
        injector.cancel_count(),
        injector.ready_count(),
        injector.has_cancel_work(),
        injector.has_timed_work(),
        injector.has_ready_work(),
    );
    obs.require(loaded == (9, 3, 4, true, true, true), || {
        format!(
            "after 3 cancel, 2 timed and 4 ready injections (len, cancel_count, ready_count, \
             has_cancel_work, has_timed_work, has_ready_work) = {loaded:?}"
        )
    });
    for _ in 0..3 {
        let _ = injector.pop_cancel();
    }
    for _ in 0..2 {
        let _ = injector.pop_timed();
    }
    for _ in 0..4 {
        let _ = injector.pop_ready();
    }
    let drained = (
        injector.len(),
        injector.is_empty(),
        injector.has_cancel_work(),
        injector.has_timed_work(),
        injector.has_ready_work(),
    );
    obs.require(drained == (0, true, false, false, false), || {
        format!(
            "after popping everything (len, is_empty, has_cancel_work, has_timed_work, \
             has_ready_work) = {drained:?}"
        )
    });
    obs
}

// ---------------------------------------------------------------------------
// Intrusive heap and priority scheduler
// ---------------------------------------------------------------------------

fn intrusive_heap_priority_order() -> Observation {
    let mut obs = Observation::default();
    let mut arena = task_arena(8);
    let mut heap = IntrusivePriorityHeap::new();
    let plan: [(u32, u8); 7] = [(0, 1), (1, 5), (2, 3), (3, 5), (4, 2), (5, 5), (6, 1)];
    for (index, priority) in plan {
        heap.push(task(index), priority, &mut arena);
    }
    obs.require(heap.len() == plan.len(), || {
        format!(
            "{} pushes left {} tasks in the heap",
            plan.len(),
            heap.len()
        )
    });
    obs.require(heap.verify_invariants_for_test(&arena), || {
        "heap invariants (stored indices, parent priority) broken after the pushes".to_owned()
    });
    heap.push(task(1), 9, &mut arena);
    obs.require(heap.len() == plan.len(), || {
        format!(
            "pushing a queued task again changed the heap length to {}",
            heap.len()
        )
    });
    obs.require(heap.remove(task(2), &mut arena), || {
        "remove of a queued task returned false".to_owned()
    });
    obs.require(!heap.contains(task(2), &arena), || {
        "a removed task is still reported as contained".to_owned()
    });
    obs.require(heap.verify_invariants_for_test(&arena), || {
        "heap invariants broken after remove".to_owned()
    });
    let popped = drain_with(plan.len() + 2, || heap.pop(&mut arena));
    // Priority 5 in push order, then 2, then 1 in push order; task 2 was
    // removed and task 1 keeps its first priority.
    expect_sequence(
        &mut obs,
        "intrusive heap pop order",
        &popped,
        &[task(1), task(3), task(5), task(4), task(0), task(6)],
    );
    obs.require(heap.is_empty(), || {
        format!("{} tasks left after draining", heap.len())
    });
    obs
}

fn priority_lanes_cancel_timed_ready() -> Observation {
    let mut obs = Observation::default();
    let (ready, timed, cancel) = (task(1), task(2), task(3));
    let loaded = || {
        let mut scheduler = PriorityScheduler::new();
        scheduler.schedule(ready, 255);
        scheduler.schedule_timed(timed, Time::from_secs(100));
        scheduler.schedule_cancel(cancel, 1);
        scheduler
    };

    let mut scheduler = loaded();
    obs.require(scheduler.len() == 3, || {
        format!("len {} after scheduling three tasks", scheduler.len())
    });
    let popped = drain_with(5, || scheduler.pop());
    expect_sequence(
        &mut obs,
        "pop order for a priority-255 ready, a timed and a priority-1 cancel task",
        &popped,
        &[cancel, timed, ready],
    );

    let mut scheduler = loaded();
    let mut lanes = Vec::new();
    while lanes.len() < 5 {
        match scheduler.pop_with_lane(0) {
            Some(pair) => lanes.push(pair),
            None => break,
        }
    }
    let expected = vec![
        (cancel, DispatchLane::Cancel),
        (timed, DispatchLane::Timed),
        (ready, DispatchLane::Ready),
    ];
    obs.require(lanes == expected, || {
        format!("pop_with_lane returned {lanes:?}, expected {expected:?}")
    });
    obs
}

fn priority_cancel_promotion_once() -> Observation {
    let mut obs = Observation::default();
    let (victim, first, second) = (task(1), task(2), task(3));
    let mut scheduler = PriorityScheduler::new();
    scheduler.schedule(victim, 10);
    scheduler.schedule(first, 200);
    scheduler.schedule(second, 200);
    scheduler.schedule_cancel(victim, 10);
    obs.require(scheduler.is_in_cancel_lane(victim), || {
        "schedule_cancel did not move an already queued task into the cancel lane".to_owned()
    });
    obs.require(scheduler.len() == 3, || {
        format!("len {} after promoting one of three tasks", scheduler.len())
    });
    let popped = drain_with(6, || scheduler.pop());
    expect_sequence(
        &mut obs,
        "pop order after promoting a priority-10 ready task to the cancel lane",
        &popped,
        &[victim, first, second],
    );
    obs
}

fn priority_timed_lane_edf() -> Observation {
    let mut obs = Observation::default();
    let mut scheduler = PriorityScheduler::new();
    let plan: [(u32, u64); 6] = [(0, 75), (1, 25), (2, 100), (3, 50), (4, 50), (5, 50)];
    for (index, seconds) in plan {
        scheduler.schedule_timed(task(index), Time::from_secs(seconds));
    }
    let popped = drain_with(plan.len() + 2, || scheduler.pop());
    expect_sequence(
        &mut obs,
        "timed-lane pop order for deadlines 75,25,100,50,50,50 s",
        &popped,
        &[task(1), task(3), task(4), task(5), task(0), task(2)],
    );
    obs
}

fn priority_ready_lane_order() -> Observation {
    let mut obs = Observation::default();
    let mut scheduler = PriorityScheduler::new();
    let plan: [(u32, u8); 5] = [(0, 50), (1, 200), (2, 50), (3, 200), (4, 100)];
    for (index, priority) in plan {
        scheduler.schedule(task(index), priority);
    }
    let popped = drain_with(plan.len() + 2, || scheduler.pop());
    expect_sequence(
        &mut obs,
        "ready-lane pop order for priorities 50,200,50,200,100",
        &popped,
        &[task(1), task(3), task(4), task(0), task(2)],
    );
    obs
}

fn priority_timed_waits_for_deadline() -> Observation {
    let mut obs = Observation::default();
    let (ready, timed) = (task(1), task(2));
    let mut scheduler = PriorityScheduler::new();
    scheduler.schedule(ready, 50);
    scheduler.schedule_timed(timed, Time::from_secs(100));
    let probes = [
        (50, Some((ready, DispatchLane::Ready))),
        (50, None),
        (100, Some((timed, DispatchLane::Timed))),
    ];
    for (now, expected) in probes {
        let got = scheduler.pop_with_lane_if_due(0, Time::from_secs(now));
        obs.require(got == expected, || {
            format!("pop_with_lane_if_due at {now} s returned {got:?}, expected {expected:?}")
        });
    }

    let mut scheduler = PriorityScheduler::new();
    scheduler.schedule_timed(timed, Time::from_secs(100));
    let early = scheduler.pop_timed_only(Time::from_secs(99));
    let due = scheduler.pop_timed_only(Time::from_secs(100));
    obs.require(early.is_none() && due == Some(timed), || {
        format!("pop_timed_only returned {early:?} at 99 s and {due:?} at 100 s")
    });
    obs
}

// ---------------------------------------------------------------------------
// Three-lane workers
// ---------------------------------------------------------------------------

/// Copies of the `PreemptionMetrics` fields the rows judge.
#[derive(Clone, Copy, Debug, Default)]
struct LaneCounts {
    cancel: u64,
    timed: u64,
    ready: u64,
    fairness_yields: u64,
    max_cancel_streak: usize,
    fallback_cancel: u64,
    effective_limit_exceedances: u64,
}

fn lane_counts(worker: &ThreeLaneWorker) -> LaneCounts {
    let metrics = worker.preemption_metrics();
    LaneCounts {
        cancel: metrics.cancel_dispatches,
        timed: metrics.timed_dispatches,
        ready: metrics.ready_dispatches,
        fairness_yields: metrics.fairness_yields,
        max_cancel_streak: metrics.max_cancel_streak,
        fallback_cancel: metrics.fallback_cancel_dispatches,
        effective_limit_exceedances: metrics.effective_limit_exceedances,
    }
}

/// Round-robin `next_task()` over all workers until a full round dispatches
/// nothing. Records (worker, task) per dispatch.
fn round_robin(workers: &mut [ThreeLaneWorker], expected: usize) -> Vec<(usize, TaskId)> {
    let mut dispatches = Vec::new();
    for _ in 0..expected * 4 + 4 {
        let mut progressed = false;
        for (worker_index, worker) in workers.iter_mut().enumerate() {
            if let Some(id) = worker.next_task() {
                dispatches.push((worker_index, id));
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
    dispatches
}

struct LaneRun {
    order: Vec<TaskId>,
    expected: Vec<TaskId>,
    idle_probe: Option<TaskId>,
    after_deadline: Vec<TaskId>,
    future: TaskId,
    counts: LaneCounts,
}

/// One worker, virtual time 1000 ns: a high-priority ready task, three due
/// timed tasks injected out of deadline order, one timed task due at 5000 ns
/// and a priority-1 cancel task.
fn worker_lane_run() -> Result<LaneRun, String> {
    let (state, clock) = clocked_state(Time::from_nanos(LANE_CLOCK_START));
    let mut scheduler = ThreeLaneScheduler::new(1, &state);
    let (ready, late, early, middle, future, cancel) =
        (task(1), task(2), task(3), task(4), task(5), task(6));
    scheduler.inject_ready(ready, 200);
    scheduler.inject_timed(late, Time::from_nanos(750));
    scheduler.inject_timed(early, Time::from_nanos(250));
    scheduler.inject_timed(middle, Time::from_nanos(500));
    scheduler.inject_timed(future, Time::from_nanos(5_000));
    scheduler.inject_cancel(cancel, 1);
    let mut workers = scheduler.take_workers();
    let worker = workers
        .first_mut()
        .ok_or_else(|| "ThreeLaneScheduler::new(1, ..) yielded no worker".to_owned())?;
    let order = drain_with(8, || worker.next_task());
    let idle_probe = worker.next_task();
    clock.advance_to(Time::from_nanos(5_000));
    let after_deadline = drain_with(4, || worker.next_task());
    let counts = lane_counts(worker);
    Ok(LaneRun {
        order,
        expected: vec![cancel, early, middle, late, ready],
        idle_probe,
        after_deadline,
        future,
        counts,
    })
}

fn worker_lane_order() -> Observation {
    let mut obs = Observation::default();
    match worker_lane_run() {
        Ok(run) => {
            expect_sequence(
                &mut obs,
                "single-worker dispatch order (cancel, due timed by deadline, ready)",
                &run.order,
                &run.expected,
            );
            obs.require(run.idle_probe.is_none(), || {
                format!(
                    "next_task dispatched {:?} while the only queued task was due in the future",
                    run.idle_probe
                )
            });
            expect_sequence(
                &mut obs,
                "dispatch once the clock reaches the remaining deadline",
                &run.after_deadline,
                &[run.future],
            );
        }
        Err(message) => obs.violation(message),
    }
    obs
}

fn worker_lane_metrics() -> Observation {
    let mut obs = Observation::default();
    match worker_lane_run() {
        Ok(run) => {
            let seen = (run.counts.cancel, run.counts.timed, run.counts.ready);
            obs.require(seen == (1, 4, 1), || {
                format!(
                    "(cancel, timed, ready) dispatch counters read {seen:?} after 1 cancel, 4 \
                     timed and 1 ready dispatch"
                )
            });
        }
        Err(message) => obs.violation(message),
    }
    obs
}

struct StreakRun {
    order: Vec<TaskId>,
    cancels: Vec<TaskId>,
    ready: TaskId,
    counts: LaneCounts,
}

/// One worker with `cancel_count` cancel tasks and one ready task injected.
/// `limit: None` uses the default constructor.
fn streak_run(limit: Option<usize>, cancel_count: u32) -> Result<StreakRun, String> {
    let state = bare_state();
    let mut scheduler = match limit {
        Some(limit) => ThreeLaneScheduler::new_with_cancel_limit(1, &state, limit),
        None => ThreeLaneScheduler::new(1, &state),
    };
    let cancels = tasks(cancel_count);
    let ready = task(cancel_count);
    for id in &cancels {
        scheduler.inject_cancel(*id, 100);
    }
    scheduler.inject_ready(ready, 50);
    let mut workers = scheduler.take_workers();
    let worker = workers
        .first_mut()
        .ok_or_else(|| "a one-worker ThreeLaneScheduler yielded no worker".to_owned())?;
    let order = drain_with(cancels.len() + 3, || worker.next_task());
    let counts = lane_counts(worker);
    Ok(StreakRun {
        order,
        cancels,
        ready,
        counts,
    })
}

fn judge_streak(obs: &mut Observation, what: &str, limit: usize, run: &StreakRun) {
    let mut expected = run.cancels.clone();
    expected.push(run.ready);
    expect_each_once(obs, what, &run.order, &expected);
    match run.order.iter().position(|id| *id == run.ready) {
        Some(at) => {
            obs.require(at <= limit, || {
                format!(
                    "{what}: the waiting ready task was dispatched at position {at}, after more \
                     than {limit} consecutive cancel dispatches"
                )
            });
            obs.require(at >= limit, || {
                format!(
                    "{what}: the ready task was dispatched at position {at}, ahead of cancel \
                     work while the cancel streak was below {limit}"
                )
            });
        }
        None => obs.violation(format!("{what}: the ready task was never dispatched")),
    }
    obs.require(run.counts.max_cancel_streak <= limit, || {
        format!(
            "{what}: max_cancel_streak {} exceeds the limit {limit}",
            run.counts.max_cancel_streak
        )
    });
    obs.require(run.counts.effective_limit_exceedances == 0, || {
        format!(
            "{what}: {} cancel dispatches exceeded the effective limit",
            run.counts.effective_limit_exceedances
        )
    });
    obs.require(run.counts.fairness_yields > 0, || {
        format!("{what}: the streak limit was never reached (fairness_yields is 0)")
    });
}

fn worker_cancel_streak_limit() -> Observation {
    let mut obs = Observation::default();
    for limit in CANCEL_LIMITS {
        let what = format!("cancel streak limit {limit}");
        match streak_run(Some(limit), (limit * 3) as u32) {
            Ok(run) => judge_streak(&mut obs, &what, limit, &run),
            Err(message) => obs.violation(format!("{what}: {message}")),
        }
    }
    let what = "default cancel streak limit";
    match streak_run(None, 20) {
        Ok(run) => judge_streak(&mut obs, what, DEFAULT_CANCEL_STREAK_LIMIT, &run),
        Err(message) => obs.violation(format!("{what}: {message}")),
    }
    obs
}

fn worker_cancel_only_work_proceeds() -> Observation {
    let mut obs = Observation::default();
    let state = bare_state();
    let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, 2);
    let cancels = tasks(6);
    for id in &cancels {
        scheduler.inject_cancel(*id, 100);
    }
    let mut workers = scheduler.take_workers();
    let Some(worker) = workers.first_mut() else {
        return Observation::failed("a one-worker ThreeLaneScheduler yielded no worker");
    };
    let order = drain_with(cancels.len() + 2, || worker.next_task());
    let counts = lane_counts(worker);
    expect_each_once(
        &mut obs,
        "six cancel tasks and no other work, limit 2",
        &order,
        &cancels,
    );
    obs.require(counts.fallback_cancel > 0, || {
        "the fallback cancel dispatch never ran although only cancel work existed".to_owned()
    });
    obs.require(counts.effective_limit_exceedances == 0, || {
        format!(
            "{} cancel dispatches exceeded the effective limit",
            counts.effective_limit_exceedances
        )
    });
    obs
}

fn worker_thieves_take_ready_only() -> Observation {
    let mut obs = Observation::default();
    let state = bare_state();
    let mut scheduler = ThreeLaneScheduler::new(2, &state);
    let (cancel, ready_a, ready_b) = (task(1), task(2), task(3));
    let mut workers = scheduler.take_workers();
    if workers.len() != 2 {
        return Observation::failed(format!(
            "ThreeLaneScheduler::new(2, ..) yielded {} workers",
            workers.len()
        ));
    }
    {
        let mut owner_local = workers[0].local.lock();
        owner_local.schedule_cancel(cancel, 100);
        owner_local.schedule(ready_a, 50);
        owner_local.schedule(ready_b, 50);
    }
    let stolen = {
        let thief = &mut workers[1];
        drain_with(8, || thief.next_task())
    };
    expect_each_once(
        &mut obs,
        "tasks the idle worker took from a peer holding one cancel and two ready tasks",
        &stolen,
        &[ready_a, ready_b],
    );
    obs.require(!stolen.contains(&cancel), || {
        "a thief took the peer's cancel-lane task".to_owned()
    });
    let owner = {
        let owner = &mut workers[0];
        drain_with(4, || owner.next_task())
    };
    expect_sequence(
        &mut obs,
        "what the owner dispatched after the thief finished",
        &owner,
        &[cancel],
    );
    obs
}

struct RoundRobinRun {
    seeded: Vec<TaskId>,
    dispatches: Vec<(usize, TaskId)>,
    thief_fast_steals: u64,
    thief_heap_steals: u64,
}

/// Three workers; every task sits in worker 0's fast queue, workers 1 and 2
/// have nothing of their own.
fn fast_queue_round_robin() -> RoundRobinRun {
    let state = bare_state();
    let mut scheduler = ThreeLaneScheduler::new(ROUND_ROBIN_WORKERS, &state);
    let seeded = tasks(ROUND_ROBIN_TASKS);
    for id in &seeded {
        scheduler.seed_worker_fast_ready_for_test(0, *id);
    }
    let mut workers = scheduler.take_workers();
    let dispatches = round_robin(&mut workers, seeded.len());
    let (thief_fast_steals, thief_heap_steals) = workers.get(1).map_or((0, 0), |thief| {
        let counters = thief.steal_locality_counters();
        (
            counters.preferred_fast_steals + counters.remote_fast_steals,
            counters.preferred_heap_steals + counters.remote_heap_steals,
        )
    });
    RoundRobinRun {
        seeded,
        dispatches,
        thief_fast_steals,
        thief_heap_steals,
    }
}

fn first_dispatch_of(run: &RoundRobinRun, worker: usize) -> Option<TaskId> {
    run.dispatches
        .iter()
        .find(|(dispatcher, _)| *dispatcher == worker)
        .map(|(_, id)| *id)
}

fn worker_idle_workers_steal() -> Observation {
    let mut obs = Observation::default();
    let run = fast_queue_round_robin();
    let delivered: Vec<TaskId> = run.dispatches.iter().map(|(_, id)| *id).collect();
    expect_each_once(
        &mut obs,
        "round-robin dispatch of worker 0's fast queue across three workers",
        &delivered,
        &run.seeded,
    );
    let helpers: HashSet<usize> = run
        .dispatches
        .iter()
        .map(|(dispatcher, _)| *dispatcher)
        .filter(|dispatcher| *dispatcher != 0)
        .collect();
    obs.require(!helpers.is_empty(), || {
        "idle workers 1 and 2 dispatched nothing while worker 0's fast queue held work".to_owned()
    });
    let owner_first = first_dispatch_of(&run, 0);
    let thief_first = first_dispatch_of(&run, 1);
    obs.require(owner_first == run.seeded.last().copied(), || {
        format!(
            "worker 0 first dispatched {owner_first:?}; the owner end is LIFO, expected {:?}",
            run.seeded.last()
        )
    });
    obs.require(thief_first == run.seeded.first().copied(), || {
        format!(
            "worker 1 first stole {thief_first:?}; the thief end is FIFO, expected {:?}",
            run.seeded.first()
        )
    });
    obs
}

fn worker_steal_counters() -> Observation {
    let mut obs = Observation::default();
    let run = fast_queue_round_robin();
    let thief_dispatches = run
        .dispatches
        .iter()
        .filter(|(dispatcher, _)| *dispatcher == 1)
        .count() as u64;
    obs.require(thief_dispatches > 0, || {
        "worker 1 dispatched nothing, so its steal counters cannot be judged".to_owned()
    });
    obs.require(run.thief_fast_steals == thief_dispatches, || {
        format!(
            "worker 1 dispatched {thief_dispatches} tasks, all stolen from worker 0's fast \
             queue, but its fast-steal counters read {}",
            run.thief_fast_steals
        )
    });
    obs.require(run.thief_heap_steals == 0, || {
        format!(
            "worker 1's heap-steal counters read {} although no heap held work",
            run.thief_heap_steals
        )
    });
    obs
}

fn worker_global_injection_once() -> Observation {
    let mut obs = Observation::default();
    let state = bare_state();
    let mut scheduler = ThreeLaneScheduler::new(ROUND_ROBIN_WORKERS, &state);
    let injected = tasks(GLOBAL_INJECTION_TASKS);
    for id in &injected {
        scheduler.inject_ready(*id, 100);
    }
    let mut workers = scheduler.take_workers();
    let dispatches = round_robin(&mut workers, injected.len());
    let delivered: Vec<TaskId> = dispatches.iter().map(|(_, id)| *id).collect();
    expect_each_once(
        &mut obs,
        "globally injected tasks dispatched round-robin by three workers",
        &delivered,
        &injected,
    );
    let mut per_worker = vec![0_usize; workers.len()];
    for (dispatcher, _) in &dispatches {
        if let Some(count) = per_worker.get_mut(*dispatcher) {
            *count += 1;
        }
    }
    obs.require(per_worker.iter().all(|count| *count > 0), || {
        format!("dispatches per worker {per_worker:?}: a worker polled nothing")
    });
    obs
}

// ---------------------------------------------------------------------------
// Public runtime
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Flavor {
    CurrentThread,
    MultiThread,
}

impl Flavor {
    fn label(self) -> &'static str {
        match self {
            Self::CurrentThread => "current_thread",
            Self::MultiThread => "multi_thread",
        }
    }

    fn build(self) -> Result<Runtime, String> {
        let builder = match self {
            Self::CurrentThread => RuntimeBuilder::current_thread(),
            Self::MultiThread => {
                RuntimeBuilder::multi_thread().worker_threads(MULTI_THREAD_WORKERS)
            }
        };
        builder
            .build()
            .map_err(|err| format!("{} runtime failed to build: {err:?}", self.label()))
    }
}

struct SpawnRun {
    caller: ThreadId,
    counts: Vec<usize>,
    joined: Vec<usize>,
    threads: Vec<ThreadId>,
}

/// Spawns `SPAWNED_TASKS` tasks through `RuntimeHandle::spawn`; each yields
/// once, counts its run and records its thread.
fn spawn_run(flavor: Flavor) -> Result<SpawnRun, String> {
    flatten(run_bounded(
        flavor.label(),
        RUN_DEADLINE,
        move || -> Result<SpawnRun, String> {
            let caller = thread::current().id();
            let runtime = flavor.build()?;
            let counters: Arc<Vec<AtomicUsize>> =
                Arc::new((0..SPAWNED_TASKS).map(|_| AtomicUsize::new(0)).collect());
            let threads: Arc<Mutex<Vec<ThreadId>>> = Arc::new(Mutex::new(Vec::new()));
            let handle = runtime.handle();
            let joins: Vec<_> = (0..SPAWNED_TASKS)
                .map(|index| {
                    let counters = Arc::clone(&counters);
                    let threads = Arc::clone(&threads);
                    handle.spawn(async move {
                        yield_now().await;
                        counters[index].fetch_add(1, Ordering::SeqCst);
                        push_locked(&threads, thread::current().id());
                        index
                    })
                })
                .collect();
            drop(handle);
            let joined = runtime.block_on(async move {
                let mut joined = Vec::with_capacity(joins.len());
                for join in joins {
                    joined.push(join.await);
                }
                joined
            });
            let _ = runtime.shutdown_timeout(SHUTDOWN_BOUND);
            Ok(SpawnRun {
                caller,
                counts: load_counts(&counters),
                joined,
                threads: take_locked(&threads),
            })
        },
    ))
}

fn judge_spawn_run(obs: &mut Observation, flavor: Flavor, run: &SpawnRun) {
    expect_counts_once(
        obs,
        &format!("{} runtime spawned tasks", flavor.label()),
        &run.counts,
    );
    let expected: Vec<usize> = (0..SPAWNED_TASKS).collect();
    obs.require(run.joined == expected, || {
        format!(
            "{}: the join handles returned {:?}, expected each task's own index",
            flavor.label(),
            run.joined
        )
    });
}

fn tasks_run_once(flavor: Flavor) -> Observation {
    let mut obs = Observation::default();
    match spawn_run(flavor) {
        Ok(run) => judge_spawn_run(&mut obs, flavor, &run),
        Err(message) => obs.violation(message),
    }
    obs
}

fn current_thread_tasks_run_once() -> Observation {
    tasks_run_once(Flavor::CurrentThread)
}

fn multi_thread_tasks_run_once() -> Observation {
    tasks_run_once(Flavor::MultiThread)
}

/// Spawns `SPAWNED_TASKS` tasks through `Runtime::current_handle()` from
/// inside `block_on` on a current-thread runtime and joins them in the same
/// call. Each yields once and returns the thread it ran on. Returns the
/// caller's thread and the threads the tasks reported, in spawn order.
fn caller_driven_run() -> Result<(ThreadId, Vec<ThreadId>), String> {
    flatten(run_bounded(
        "current_thread inside block_on",
        RUN_DEADLINE,
        || -> Result<(ThreadId, Vec<ThreadId>), String> {
            let caller = thread::current().id();
            let runtime = Flavor::CurrentThread.build()?;
            let threads = runtime.block_on(async {
                match Runtime::current_handle() {
                    Some(handle) => {
                        let joins: Vec<_> = (0..SPAWNED_TASKS)
                            .map(|_| {
                                handle.spawn(async {
                                    yield_now().await;
                                    thread::current().id()
                                })
                            })
                            .collect();
                        let mut threads = Vec::with_capacity(joins.len());
                        for join in joins {
                            threads.push(join.await);
                        }
                        Some(threads)
                    }
                    None => None,
                }
            });
            let _ = runtime.shutdown_timeout(SHUTDOWN_BOUND);
            threads
                .map(|threads| (caller, threads))
                .ok_or_else(|| "Runtime::current_handle() returned None inside block_on".to_owned())
        },
    ))
}

fn current_thread_block_on_tasks_on_caller() -> Observation {
    let mut obs = Observation::default();
    match caller_driven_run() {
        Ok((caller, threads)) => {
            obs.require(threads.len() == SPAWNED_TASKS, || {
                format!(
                    "{} of {SPAWNED_TASKS} tasks spawned inside block_on reported a thread",
                    threads.len()
                )
            });
            let elsewhere = threads.iter().filter(|id| **id != caller).count();
            obs.require(elsewhere == 0, || {
                format!(
                    "{elsewhere} of {} tasks spawned and joined inside block_on ran on a thread \
                     other than the block_on caller",
                    threads.len()
                )
            });
        }
        Err(message) => obs.violation(message),
    }
    obs
}

fn multi_thread_tasks_on_workers() -> Observation {
    let mut obs = Observation::default();
    match spawn_run(Flavor::MultiThread) {
        Ok(run) => {
            obs.require(run.threads.len() == SPAWNED_TASKS, || {
                format!(
                    "{} of {SPAWNED_TASKS} tasks recorded a thread",
                    run.threads.len()
                )
            });
            let on_caller = run.threads.iter().filter(|id| **id == run.caller).count();
            obs.require(on_caller == 0, || {
                format!("{on_caller} spawned tasks ran on the block_on caller instead of a worker")
            });
        }
        Err(message) => obs.violation(message),
    }
    obs
}

struct RendezvousRun {
    caller: ThreadId,
    threads: Vec<ThreadId>,
}

/// Spawns `RENDEZVOUS_TASKS` tasks on a multi-thread runtime. Each records
/// its thread, then holds its worker without yielding until a second task has
/// started, for at most `RENDEZVOUS_WAIT`. A second task can start meanwhile
/// only on another worker.
fn rendezvous_run() -> Result<RendezvousRun, String> {
    flatten(run_bounded(
        "multi_thread rendezvous",
        RUN_DEADLINE,
        || -> Result<RendezvousRun, String> {
            let caller = thread::current().id();
            let runtime = Flavor::MultiThread.build()?;
            let arrived = Arc::new(AtomicUsize::new(0));
            let threads: Arc<Mutex<Vec<ThreadId>>> = Arc::new(Mutex::new(Vec::new()));
            let handle = runtime.handle();
            let joins: Vec<_> = (0..RENDEZVOUS_TASKS)
                .map(|_| {
                    let arrived = Arc::clone(&arrived);
                    let threads = Arc::clone(&threads);
                    handle.spawn(async move {
                        push_locked(&threads, thread::current().id());
                        arrived.fetch_add(1, Ordering::SeqCst);
                        let give_up = Instant::now() + RENDEZVOUS_WAIT;
                        while arrived.load(Ordering::SeqCst) < 2 && Instant::now() < give_up {
                            thread::yield_now();
                        }
                    })
                })
                .collect();
            drop(handle);
            runtime.block_on(async move {
                for join in joins {
                    join.await;
                }
            });
            let _ = runtime.shutdown_timeout(SHUTDOWN_BOUND);
            Ok(RendezvousRun {
                caller,
                threads: take_locked(&threads),
            })
        },
    ))
}

fn judge_distinct_workers(obs: &mut Observation, run: &RendezvousRun) {
    obs.require(run.threads.len() == RENDEZVOUS_TASKS, || {
        format!(
            "{} of {RENDEZVOUS_TASKS} rendezvous tasks recorded a thread",
            run.threads.len()
        )
    });
    let workers: HashSet<ThreadId> = run
        .threads
        .iter()
        .copied()
        .filter(|id| *id != run.caller)
        .collect();
    obs.require(workers.len() >= 2, || {
        format!(
            "all {} tasks ran on {} worker thread(s) of {MULTI_THREAD_WORKERS}: the first task \
             held its worker for up to {:?} while the others stayed queued and the remaining \
             workers stayed idle",
            run.threads.len(),
            workers.len(),
            RENDEZVOUS_WAIT
        )
    });
}

fn multi_thread_idle_workers_take_work() -> Observation {
    let mut obs = Observation::default();
    match rendezvous_run() {
        Ok(run) => judge_distinct_workers(&mut obs, &run),
        Err(message) => obs.violation(message),
    }
    obs
}

struct PanicRun {
    siblings: Vec<Result<usize, JoinError>>,
    panicked: Result<usize, JoinError>,
    after: Result<usize, JoinError>,
}

fn panic_on_purpose() -> usize {
    panic!("{}", PANIC_MESSAGE)
}

/// Spawns siblings and one panicking task through `spawn_checked`, joins
/// them, then spawns one more task after the panic.
fn panic_run(flavor: Flavor) -> Result<PanicRun, String> {
    flatten(run_bounded(
        flavor.label(),
        RUN_DEADLINE,
        move || -> Result<PanicRun, String> {
            let runtime = flavor.build()?;
            let handle = runtime.handle();
            let siblings: Vec<_> = (0..PANIC_SIBLINGS)
                .map(|index| {
                    handle.spawn_checked(async move {
                        yield_now().await;
                        index
                    })
                })
                .collect();
            let panicking = handle.spawn_checked(async move {
                yield_now().await;
                panic_on_purpose()
            });
            let (siblings, panicked) = runtime.block_on(async move {
                let mut results = Vec::with_capacity(siblings.len());
                for join in siblings {
                    results.push(join.await);
                }
                (results, panicking.await)
            });
            let late = handle.spawn_checked(async move {
                yield_now().await;
                PANIC_SIBLINGS
            });
            let after = runtime.block_on(late);
            drop(handle);
            let _ = runtime.shutdown_timeout(SHUTDOWN_BOUND);
            Ok(PanicRun {
                siblings,
                panicked,
                after,
            })
        },
    ))
}

fn judge_panic_run(obs: &mut Observation, what: &str, run: &PanicRun) {
    match &run.panicked {
        Err(JoinError::Panicked(payload)) => {
            obs.require(payload.message() == PANIC_MESSAGE, || {
                format!(
                    "{what}: the panic surfaced with message {:?}, expected {:?}",
                    payload.message(),
                    PANIC_MESSAGE
                )
            })
        }
        other => obs.violation(format!(
            "{what}: the panicking task joined as {other:?}, expected JoinError::Panicked"
        )),
    }
    obs.require(run.siblings.len() == PANIC_SIBLINGS, || {
        format!(
            "{what}: {} of {PANIC_SIBLINGS} sibling results",
            run.siblings.len()
        )
    });
    for (index, result) in run.siblings.iter().enumerate() {
        obs.require(result.as_ref().ok() == Some(&index), || {
            format!("{what}: sibling {index} joined as {result:?}, expected Ok({index})")
        });
    }
    obs.require(run.after.as_ref().ok() == Some(&PANIC_SIBLINGS), || {
        format!(
            "{what}: a task spawned after the panic joined as {:?}, expected Ok({PANIC_SIBLINGS})",
            run.after
        )
    });
}

fn panic_isolated(flavor: Flavor) -> Observation {
    let mut obs = Observation::default();
    match panic_run(flavor) {
        Ok(run) => judge_panic_run(&mut obs, flavor.label(), &run),
        Err(message) => obs.violation(message),
    }
    obs
}

fn current_thread_panic_isolated() -> Observation {
    panic_isolated(Flavor::CurrentThread)
}

fn multi_thread_panic_isolated() -> Observation {
    panic_isolated(Flavor::MultiThread)
}

// ---------------------------------------------------------------------------
// Cx scenarios, run on a native runtime and on the lab runtime
// ---------------------------------------------------------------------------

type ScenarioFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Runs `scenario` as a task spawned on a runtime of `flavor`, with the
/// task's own `Cx`.
fn run_scenario_native<T: Send + 'static>(
    flavor: Flavor,
    scenario: fn(Cx) -> ScenarioFuture<T>,
) -> Result<T, String> {
    flatten(run_bounded(
        flavor.label(),
        RUN_DEADLINE,
        move || -> Result<T, String> {
            let runtime = flavor.build()?;
            let root = runtime.handle().spawn(async move {
                match Cx::current() {
                    Some(cx) => Some(scenario(cx).await),
                    None => None,
                }
            });
            let outcome = runtime.block_on(root);
            let _ = runtime.shutdown_timeout(SHUTDOWN_BOUND);
            outcome.ok_or_else(|| {
                format!(
                    "{}: the spawned root task found no ambient Cx",
                    flavor.label()
                )
            })
        },
    ))
}

/// Runs `scenario` as the root task of a lab runtime with `seed`.
fn run_scenario_lab<T: Send + 'static>(
    seed: u64,
    scenario: fn(Cx) -> ScenarioFuture<T>,
) -> Result<T, String> {
    flatten(run_bounded(
        "lab",
        RUN_DEADLINE,
        move || -> Result<T, String> {
            let config = TestConfig {
                rng_seed: Some(seed),
                max_steps: Some(LAB_MAX_STEPS),
                ..TestConfig::default()
            };
            let mut runtime = LabRuntimeTarget::create_runtime(config);
            let outcome = LabRuntimeTarget::block_on(&mut runtime, async move {
                match Cx::current() {
                    Some(cx) => Some(scenario(cx).await),
                    None => None,
                }
            });
            outcome.ok_or_else(|| "the lab root task found no ambient Cx".to_owned())
        },
    ))
}

struct ChildrenRun {
    counts: Vec<usize>,
    joined: Vec<Result<usize, String>>,
}

fn children_scenario(cx: Cx) -> ScenarioFuture<Result<ChildrenRun, String>> {
    Box::pin(children_body(cx))
}

/// Spawns `SCENARIO_CHILDREN` children through `Cx::spawn`, each yielding
/// once before it counts its run, and joins them all.
async fn children_body(cx: Cx) -> Result<ChildrenRun, String> {
    let counters: Arc<Vec<AtomicUsize>> = Arc::new(
        (0..SCENARIO_CHILDREN)
            .map(|_| AtomicUsize::new(0))
            .collect(),
    );
    let mut handles = Vec::with_capacity(SCENARIO_CHILDREN);
    for index in 0..SCENARIO_CHILDREN {
        let counters = Arc::clone(&counters);
        let handle = cx
            .spawn(move |_child| async move {
                yield_now().await;
                counters[index].fetch_add(1, Ordering::SeqCst);
                index
            })
            .map_err(|err| format!("Cx::spawn of child {index} failed: {err:?}"))?;
        handles.push(handle);
    }
    let mut joined = Vec::with_capacity(handles.len());
    for mut handle in handles {
        joined.push(handle.join(&cx).await.map_err(|err| format!("{err:?}")));
    }
    Ok(ChildrenRun {
        counts: load_counts(&counters),
        joined,
    })
}

fn judge_children(obs: &mut Observation, what: &str, run: &ChildrenRun) {
    expect_counts_once(obs, &format!("{what}: Cx::spawn children"), &run.counts);
    obs.require(run.joined.len() == SCENARIO_CHILDREN, || {
        format!(
            "{what}: {} of {SCENARIO_CHILDREN} children joined",
            run.joined.len()
        )
    });
    for (index, joined) in run.joined.iter().enumerate() {
        obs.require(joined.as_ref().ok() == Some(&index), || {
            format!("{what}: child {index} joined as {joined:?}, expected Ok({index})")
        });
    }
}

struct CleanupRun {
    /// Entries in the order the tasks wrote them.
    log: Vec<String>,
    /// How the aborted task joined: `Ok(true)` once it observed cancellation
    /// at a checkpoint, `Ok(false)` if it ran out of turns without seeing it.
    victim: Result<bool, JoinError>,
}

fn cleanup_scenario(cx: Cx) -> ScenarioFuture<Result<CleanupRun, String>> {
    Box::pin(cleanup_body(cx))
}

/// Starts a victim that checks for cancellation and yields in a loop, then,
/// without yielding in between, spawns three ready tasks and aborts the
/// victim. On one worker nothing else runs until this task awaits the joins,
/// so the next dispatches show whether the cancel lane goes first.
async fn cleanup_body(cx: Cx) -> Result<CleanupRun, String> {
    let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let started = Arc::new(AtomicBool::new(false));
    let victim_log = Arc::clone(&log);
    let victim_started = Arc::clone(&started);
    let mut victim = cx
        .spawn(move |victim_cx| async move {
            for _ in 0..SPIN_TURNS {
                if victim_cx.checkpoint().is_err() {
                    push_locked(&victim_log, VICTIM_CLEANUP.to_owned());
                    return true;
                }
                victim_started.store(true, Ordering::SeqCst);
                yield_now().await;
            }
            false
        })
        .map_err(|err| format!("Cx::spawn of the victim failed: {err:?}"))?;
    let mut turns = 0;
    while !started.load(Ordering::SeqCst) {
        if turns == SPIN_TURNS {
            victim.abort();
            return Err(format!(
                "the victim was not polled within {} yields",
                SPIN_TURNS
            ));
        }
        turns += 1;
        yield_now().await;
    }
    let mut ready = Vec::with_capacity(READY_LABELS.len());
    for label in READY_LABELS {
        let ready_log = Arc::clone(&log);
        let handle = cx
            .spawn(move |_ready_cx| async move {
                push_locked(&ready_log, label.to_owned());
            })
            .map_err(|err| format!("Cx::spawn of {label} failed: {err:?}"))?;
        ready.push(handle);
    }
    victim.abort();
    let victim_outcome = victim.join(&cx).await;
    for (label, mut handle) in READY_LABELS.into_iter().zip(ready) {
        if let Err(err) = handle.join(&cx).await {
            return Err(format!("{label} failed to join: {err:?}"));
        }
    }
    Ok(CleanupRun {
        log: take_locked(&log),
        victim: victim_outcome,
    })
}

fn positions(log: &[String], entry: &str) -> Vec<usize> {
    log.iter()
        .enumerate()
        .filter(|(_, written)| written.as_str() == entry)
        .map(|(at, _)| at)
        .collect()
}

fn judge_cleanup_order(obs: &mut Observation, what: &str, run: &CleanupRun) {
    let cleanup = positions(&run.log, VICTIM_CLEANUP);
    obs.require(cleanup.len() == 1, || {
        format!(
            "{what}: the aborted task logged its cleanup {} times, expected once; log {:?}",
            cleanup.len(),
            run.log
        )
    });
    for label in READY_LABELS {
        let at = positions(&run.log, label);
        obs.require(at.len() == 1, || {
            format!(
                "{what}: {label} logged {} times, expected once; log {:?}",
                at.len(),
                run.log
            )
        });
        if let (Some(cleanup_at), Some(ready_at)) = (cleanup.first(), at.first()) {
            obs.require(cleanup_at < ready_at, || {
                format!(
                    "{what}: {label} ran at position {ready_at}, before the aborted task's \
                     cleanup at position {cleanup_at}; log {:?}",
                    run.log
                )
            });
        }
    }
    obs.require(
        matches!(run.victim, Ok(true) | Err(JoinError::Cancelled(_))),
        || {
            format!(
                "{what}: the aborted task joined as {:?}; expected it to observe the \
                 cancellation at a checkpoint (Ok(true)) or join as JoinError::Cancelled",
                run.victim
            )
        },
    );
}

fn multi_thread_cx_children_once() -> Observation {
    let mut obs = Observation::default();
    match run_scenario_native(Flavor::MultiThread, children_scenario).and_then(|run| run) {
        Ok(run) => judge_children(&mut obs, "multi_thread runtime", &run),
        Err(message) => obs.violation(message),
    }
    obs
}

fn current_thread_abort_cleanup_first() -> Observation {
    let mut obs = Observation::default();
    match run_scenario_native(Flavor::CurrentThread, cleanup_scenario).and_then(|run| run) {
        Ok(run) => judge_cleanup_order(&mut obs, "current_thread runtime", &run),
        Err(message) => obs.violation(message),
    }
    obs
}

fn lab_cx_children_once() -> Observation {
    let mut obs = Observation::default();
    for seed in LAB_SEEDS {
        let what = format!("lab seed {seed:#x}");
        match run_scenario_lab(seed, children_scenario).and_then(|run| run) {
            Ok(run) => judge_children(&mut obs, &what, &run),
            Err(message) => obs.violation(format!("{what}: {message}")),
        }
    }
    obs
}

fn lab_abort_cleanup_first() -> Observation {
    let mut obs = Observation::default();
    for seed in LAB_SEEDS {
        let what = format!("lab seed {seed:#x}");
        match run_scenario_lab(seed, cleanup_scenario).and_then(|run| run) {
            Ok(run) => judge_cleanup_order(&mut obs, &what, &run),
            Err(message) => obs.violation(format!("{what}: {message}")),
        }
    }
    obs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cites_lines(spec: &str) -> bool {
        spec.split(".rs:")
            .skip(1)
            .any(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
    }

    #[test]
    fn full_suite_reports_every_row_without_hard_failures() {
        let rows = SchedulerConformanceHarness::new().run_full_suite();
        // One line per row, so a log shows how each contract was judged, not
        // only that the suite passed.
        for row in &rows {
            eprintln!(
                "scheduler_conformance row={} verdict={:?}",
                row.test_name, row.verdict
            );
        }
        assert_eq!(rows.len(), CONTRACTS.len(), "one row per contract");
        let names: HashSet<&str> = rows.iter().map(|row| row.test_name).collect();
        assert_eq!(names.len(), rows.len(), "row names must be unique");
        let categories: HashSet<TestCategory> = rows.iter().map(|row| row.category).collect();
        for required in [
            TestCategory::TaskExecution,
            TestCategory::WorkStealing,
            TestCategory::LoadBalancing,
            TestCategory::PriorityScheduling,
            TestCategory::CancellationLane,
            TestCategory::TaskPoolManagement,
            TestCategory::PanicIsolation,
            TestCategory::MetricsCollection,
        ] {
            assert!(
                categories.contains(&required),
                "the scheduler suite has no {required:?} row"
            );
        }
        for row in &rows {
            assert!(
                row.duration_micros.is_some(),
                "{} did not run through the harness",
                row.test_name
            );
            assert!(
                row.spec_section.is_some_and(cites_lines),
                "{} cites no file:line",
                row.test_name
            );
            assert!(
                !matches!(row.verdict, TestVerdict::ExpectedGap(_)),
                "{} reports a gap this suite does not track: {:?}",
                row.test_name,
                row.verdict
            );
            if matches!(row.verdict, TestVerdict::Skip(_)) {
                assert_eq!(
                    row.requirement_level,
                    RequirementLevel::May,
                    "{} is skipped at a level that counts toward conformance",
                    row.test_name
                );
            }
        }
        let failures: Vec<(&str, &TestVerdict)> = rows
            .iter()
            .filter(|row| row.is_hard_failure())
            .map(|row| (row.test_name, &row.verdict))
            .collect();
        assert!(
            failures.is_empty(),
            "scheduler contract violations: {failures:#?}"
        );
    }

    #[test]
    fn unchecked_rows_are_may_level_skips_and_every_row_cites_source() {
        for contract in CONTRACTS {
            assert!(
                cites_lines(contract.spec),
                "{} cites no file:line",
                contract.name
            );
            if let Check::NotChecked(reason) = contract.check {
                assert_eq!(
                    contract.level,
                    RequirementLevel::May,
                    "{} is not checked, so it must not count toward MUST or SHOULD scores",
                    contract.name
                );
                assert!(!reason.is_empty(), "{} gives no reason", contract.name);
                assert!(
                    matches!(contract.observe().verdict(), TestVerdict::Skip(_)),
                    "{} must be reported as Skip, never Pass",
                    contract.name
                );
            }
        }
    }

    #[test]
    fn structure_rows_pass_without_a_runtime() {
        for contract in CONTRACTS {
            if contract.name.starts_with("runtime/") || contract.name.starts_with("lab/") {
                continue;
            }
            if let Check::Run(_) = contract.check {
                let verdict = contract.observe().verdict();
                assert_eq!(verdict, TestVerdict::Pass, "{}", contract.name);
            }
        }
    }

    /// Deliberate-failure control: every judge must reject a wrong
    /// expectation, including one fed with real production output.
    #[test]
    fn judges_reject_wrong_expectations() {
        // The real owner order judged against the thief (FIFO) order.
        let pushed = tasks(SEQUENCE_LEN);
        let popped = owner_pops(&pushed);
        let mut wrong = Observation::default();
        expect_sequence(&mut wrong, "control", &popped, &pushed);
        assert!(
            matches!(wrong.verdict(), TestVerdict::Fail(_)),
            "a LIFO drain judged as FIFO must fail"
        );
        let mut newest_first = pushed.clone();
        newest_first.reverse();
        let mut right = Observation::default();
        expect_sequence(&mut right, "control", &popped, &newest_first);
        assert_eq!(right.verdict(), TestVerdict::Pass);

        // A duplicate plus a missing task.
        let mut duplicated = Observation::default();
        expect_each_once(
            &mut duplicated,
            "control",
            &[task(1), task(1), task(3)],
            &[task(1), task(2), task(3)],
        );
        let TestVerdict::Fail(message) = duplicated.verdict() else {
            panic!("a duplicate and a missing task must fail");
        };
        assert!(message.contains("never delivered") && message.contains("more than once"));

        let mut counted = Observation::default();
        expect_counts_once(&mut counted, "control", &[1, 0, 2]);
        assert!(matches!(counted.verdict(), TestVerdict::Fail(_)));

        // A ready task logged before the aborted task's cleanup.
        let in_order: Vec<String> = std::iter::once(VICTIM_CLEANUP)
            .chain(READY_LABELS)
            .map(str::to_owned)
            .collect();
        let mut reordered = in_order.clone();
        reordered.swap(0, 1);
        let mut late = Observation::default();
        judge_cleanup_order(
            &mut late,
            "control",
            &CleanupRun {
                log: reordered,
                victim: Ok(true),
            },
        );
        assert!(matches!(late.verdict(), TestVerdict::Fail(_)));
        let mut spun = Observation::default();
        judge_cleanup_order(
            &mut spun,
            "control",
            &CleanupRun {
                log: in_order.clone(),
                victim: Ok(false),
            },
        );
        assert!(matches!(spun.verdict(), TestVerdict::Fail(_)));
        let mut ordered = Observation::default();
        judge_cleanup_order(
            &mut ordered,
            "control",
            &CleanupRun {
                log: in_order,
                victim: Ok(true),
            },
        );
        assert_eq!(ordered.verdict(), TestVerdict::Pass);

        // Every task on one worker thread.
        let worker = thread::spawn(|| thread::current().id())
            .join()
            .expect("control thread");
        let mut single = Observation::default();
        judge_distinct_workers(
            &mut single,
            &RendezvousRun {
                caller: thread::current().id(),
                threads: vec![worker; RENDEZVOUS_TASKS],
            },
        );
        assert!(matches!(single.verdict(), TestVerdict::Fail(_)));

        // A panicking task that joined as a success.
        let mut unpanicked = Observation::default();
        judge_panic_run(
            &mut unpanicked,
            "control",
            &PanicRun {
                siblings: (0..PANIC_SIBLINGS).map(Ok).collect(),
                panicked: Ok(0),
                after: Ok(PANIC_SIBLINGS),
            },
        );
        assert!(matches!(unpanicked.verdict(), TestVerdict::Fail(_)));

        // A streak run whose ready task waited past the limit.
        let cancels = tasks(4);
        let ready = task(4);
        let mut overdue_order = cancels.clone();
        overdue_order.push(ready);
        let mut overdue = Observation::default();
        judge_streak(
            &mut overdue,
            "control",
            2,
            &StreakRun {
                order: overdue_order,
                cancels,
                ready,
                counts: LaneCounts {
                    fairness_yields: 1,
                    max_cancel_streak: 2,
                    ..LaneCounts::default()
                },
            },
        );
        assert!(matches!(overdue.verdict(), TestVerdict::Fail(_)));

        // Nothing evaluated fails closed; an unchecked row is a Skip.
        assert!(matches!(
            Observation::default().verdict(),
            TestVerdict::Fail(_)
        ));
        assert!(matches!(
            Observation::not_checked("control").verdict(),
            TestVerdict::Skip(_)
        ));
    }

    #[test]
    fn bounded_runner_reports_overruns_and_panics() {
        let (release, parked) = mpsc::channel::<()>();
        let overrun = run_bounded("control-overrun", Duration::from_millis(50), move || {
            let _ = parked.recv();
            7_u32
        });
        assert!(
            matches!(&overrun, Err(message) if message.contains("did not finish")),
            "{overrun:?}"
        );
        // Lets the parked runner thread exit.
        drop(release);

        let panicked = run_bounded("control-panic", Duration::from_secs(5), || -> u32 {
            panic!("control panic")
        });
        assert!(
            matches!(&panicked, Err(message) if message.contains("control panic")),
            "{panicked:?}"
        );

        let finished = run_bounded("control-finish", Duration::from_secs(5), || 7_u32);
        assert_eq!(finished, Ok(7));
    }
}
