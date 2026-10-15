#![no_main]

use std::cmp;
use std::collections::BTreeSet;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Duration;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::obligation::lyapunov::{
    LyapunovGovernor, PotentialWeights, SchedulingSuggestion, StateSnapshot,
};
use asupersync::record::TaskRecord;
use asupersync::runtime::IoDriverHandle;
use asupersync::runtime::reactor::{Events, Interest, Reactor, Source, Token};
use asupersync::runtime::scheduler::three_lane::{
    AdaptiveCancelStreakPolicyBench, AdaptivePolicyBenchSnapshot, ThreeLaneScheduler,
};
use asupersync::runtime::state::RuntimeState;
use asupersync::sync::ContendedMutex;
use asupersync::time::{TimerDriverHandle, VirtualClock};
use asupersync::types::{Budget, CancelReason, RegionId, TaskId, Time};

/// Structure-aware input for fuzzing the three-lane scheduler decision arbiter.
///
/// This captures the key decision inputs that drive lane choice in the scheduler:
/// - Governor state (Lyapunov potential weights, runtime snapshots)
/// - Scheduler state (cancel streak, queue depths, fairness counters)
/// - Environmental factors (timing, budget pressure, suggestion caching)
#[derive(Debug, Clone, Arbitrary)]
pub struct DecisionArbiterInput {
    /// Lyapunov governor weights that influence scheduling suggestions
    weights: FuzzPotentialWeights,
    /// Runtime state snapshot for governor decision-making
    state_snapshots: Vec<FuzzStateSnapshot>,
    /// Scheduler-level decision context
    scheduler_context: FuzzSchedulerContext,
    /// Environmental decision factors
    environment: FuzzEnvironment,
    /// Concrete lane mix driven through the real scheduler arbiter.
    workload: FuzzLaneWorkload,
    /// Local timed tasks promoted after deadline miss.
    deadline_promotion: FuzzDeadlinePromotionScenario,
    /// Zero-reward adaptive policy trace for discounted arm-mass stability.
    zero_reward_trace: FuzzZeroRewardPolicyTrace,
    /// Reactor leader shutdown handshake while an I/O poll is in flight.
    reactor_shutdown: FuzzReactorShutdownScenario,
    /// Concurrent steal attempts across multiple victims/workers.
    concurrent_multi_victim_steal: FuzzConcurrentMultiVictimStealScenario,
    /// Adaptive governor workload driven by arrival bursts and Lyapunov state.
    adaptive_budget: FuzzAdaptiveBudgetScenario,
}

/// Fuzzable version of PotentialWeights with bounded ranges
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzPotentialWeights {
    /// Weight for live task count (0.0 to 10.0)
    #[arbitrary(with = bounded_weight)]
    w_tasks: f64,
    /// Weight for obligation age sum (0.0 to 10.0)
    #[arbitrary(with = bounded_weight)]
    w_obligation_age: f64,
    /// Weight for draining regions (0.0 to 10.0)
    #[arbitrary(with = bounded_weight)]
    w_draining_regions: f64,
    /// Weight for deadline pressure (0.0 to 10.0)
    #[arbitrary(with = bounded_weight)]
    w_deadline_pressure: f64,
}

/// Fuzzable version of StateSnapshot with realistic bounds
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzStateSnapshot {
    /// Virtual time offset from epoch (0 to 1 hour in nanoseconds)
    #[arbitrary(with = bounded_time_offset)]
    time_offset_ns: u64,
    /// Number of live tasks (0 to 10000)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=10000))]
    live_tasks: u32,
    /// Pending obligations count (0 to 50000)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=50000))]
    pending_obligations: u32,
    /// Sum of obligation ages in nanoseconds (0 to 24 hours)
    #[arbitrary(with = bounded_age_sum)]
    obligation_age_sum_ns: u64,
    /// Draining regions count (0 to 1000)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=1000))]
    draining_regions: u32,
    /// Deadline pressure (0.0 to 100.0)
    #[arbitrary(with = bounded_deadline_pressure)]
    deadline_pressure: f64,
    /// Tasks in CancelRequested state (0 to 12)
    #[arbitrary(with = bounded_cancel_phase_count)]
    cancel_requested_tasks: u8,
    /// Tasks in Cancelling state (0 to 12)
    #[arbitrary(with = bounded_cancel_phase_count)]
    cancelling_tasks: u8,
    /// Tasks in Finalizing state (0 to 12)
    #[arbitrary(with = bounded_cancel_phase_count)]
    finalizing_tasks: u8,
}

/// Scheduler context affecting lane decision logic
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzSchedulerContext {
    /// Queue depth signals for decision weighting
    queue_depths: FuzzQueueDepths,
}

/// Simulated queue depths for different lanes
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzQueueDepths {
    /// Global ready queue depth (0 to 5000)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=5000))]
    global_ready: u32,
    /// Local ready queue depth (0 to 2000)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=2000))]
    local_ready: u32,
}

/// Environmental factors affecting decisions
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzEnvironment {
    /// Decision consistency tracking
    consistency_context: FuzzConsistencyContext,
}

/// Structure-aware workload for exercising the real scheduler arbiter.
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzLaneWorkload {
    /// Base cancel streak limit to enforce before fairness yields.
    #[arbitrary(with = bounded_cancel_limit)]
    cancel_streak_limit: usize,
    /// Cached governor suggestion used to model budget pressure.
    cached_suggestion: FuzzSchedulingSuggestion,
    /// Cancel-lane tasks and priorities.
    #[arbitrary(with = bounded_priority_vec)]
    cancel_priorities: Vec<u8>,
    /// Ready-lane tasks and priorities.
    #[arbitrary(with = bounded_priority_vec)]
    ready_priorities: Vec<u8>,
    /// Due timed tasks bucketed by relative deadline.
    #[arbitrary(with = bounded_timed_buckets)]
    timed_deadline_buckets: Vec<u8>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzDeadlinePromotionScenario {
    /// Timed tasks subjected to repeated post-deadline promotion decisions.
    #[arbitrary(with = bounded_deadline_promotion_tasks)]
    tasks: Vec<FuzzDeadlinePromotionTask>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzDeadlinePromotionTask {
    /// Relative deadline bucket for the timed lane.
    deadline_bucket: u8,
    /// Whether this task is promoted after missing its deadline.
    promote_after_miss: bool,
    /// Number of repeated promote decisions applied after the miss.
    #[arbitrary(with = bounded_promote_attempts)]
    promote_attempts: u8,
    /// Cancel priority used for the promotion path.
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=100))]
    cancel_priority: u8,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzZeroRewardPolicyTrace {
    /// Number of dispatches per adaptive epoch.
    #[arbitrary(with = bounded_epoch_steps)]
    epoch_steps: u32,
    /// Forced arm sequence for repeated all-zero reward updates.
    #[arbitrary(with = bounded_zero_reward_arm_trace)]
    forced_arms: Vec<u8>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzReactorShutdownScenario {
    /// Number of worker threads participating in the scheduler.
    #[arbitrary(with = bounded_worker_count)]
    worker_count: u8,
    /// Number of repeated shutdown calls after the leader enters the reactor.
    #[arbitrary(with = bounded_shutdown_calls)]
    shutdown_calls: u8,
    /// Additional wake-all calls after shutdown to verify idempotent handoff.
    #[arbitrary(with = bounded_post_shutdown_wakes)]
    post_shutdown_wakes: u8,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzConcurrentMultiVictimStealScenario {
    /// Number of workers participating in the steal graph.
    #[arbitrary(with = bounded_steal_worker_count)]
    worker_count: u8,
    /// Per-worker fast-queue task counts (first `worker_count` entries used).
    #[arbitrary(with = bounded_steal_task_counts)]
    fast_task_counts: Vec<u8>,
    /// Per-worker priority-queue task counts (first `worker_count` entries used).
    #[arbitrary(with = bounded_steal_task_counts)]
    heap_task_counts: Vec<u8>,
    /// Worker IDs selected as stealers (mod `worker_count`, duplicates collapsed).
    #[arbitrary(with = bounded_thief_indices)]
    thief_indices: Vec<u8>,
    /// Steal batch size applied to each thief.
    #[arbitrary(with = bounded_steal_batch_size)]
    steal_batch_size: u8,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzAdaptiveBudgetScenario {
    /// Number of executed dispatches per adaptive epoch.
    #[arbitrary(with = bounded_epoch_steps)]
    epoch_steps: u32,
    /// Arrival bursts combined with Lyapunov snapshots.
    #[arbitrary(with = bounded_adaptive_rounds)]
    rounds: Vec<FuzzAdaptiveBudgetRound>,
}

#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzAdaptiveBudgetRound {
    /// Snapshot used to synthesize a Lyapunov governor state.
    snapshot: FuzzStateSnapshot,
    /// New cancel-lane arrivals in this round.
    #[arbitrary(with = bounded_arrival_count)]
    cancel_arrivals: u8,
    /// New ready-lane arrivals in this round.
    #[arbitrary(with = bounded_arrival_count)]
    ready_arrivals: u8,
    /// New timed-lane arrivals in this round.
    #[arbitrary(with = bounded_arrival_count)]
    timed_arrivals: u8,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
pub enum FuzzSchedulingSuggestion {
    NoPreference,
    MeetDeadlines,
    DrainObligations,
    DrainRegions,
}

/// Decision consistency tracking for metamorphic properties
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzConsistencyContext {
    /// Whether to test deterministic properties
    test_determinism: bool,
}

// Bounded arbitrary generators for realistic fuzzing

fn bounded_weight(u: &mut arbitrary::Unstructured) -> arbitrary::Result<f64> {
    Ok(f64::from(u.int_in_range::<u16>(0..=1000)?) / 100.0) // 0.0 to 10.0
}

fn bounded_time_offset(u: &mut arbitrary::Unstructured) -> arbitrary::Result<u64> {
    u.int_in_range(0..=3_600_000_000_000) // 0 to 1 hour in nanoseconds
}

fn bounded_age_sum(u: &mut arbitrary::Unstructured) -> arbitrary::Result<u64> {
    u.int_in_range(0..=86_400_000_000_000) // 0 to 24 hours in nanoseconds
}

fn bounded_deadline_pressure(u: &mut arbitrary::Unstructured) -> arbitrary::Result<f64> {
    Ok(f64::from(u.int_in_range::<u16>(0..=10_000)?) / 100.0) // 0.0 to 100.0
}

fn bounded_cancel_phase_count(u: &mut arbitrary::Unstructured) -> arbitrary::Result<u8> {
    u.int_in_range(0..=12)
}

fn bounded_cancel_limit(u: &mut arbitrary::Unstructured) -> arbitrary::Result<usize> {
    Ok(usize::from(u.int_in_range::<u8>(1..=8)?))
}

fn bounded_epoch_steps(u: &mut arbitrary::Unstructured) -> arbitrary::Result<u32> {
    Ok(u32::from(u.int_in_range::<u8>(1..=8)?))
}

fn bounded_arrival_count(u: &mut arbitrary::Unstructured) -> arbitrary::Result<u8> {
    u.int_in_range(0..=12)
}

fn bounded_adaptive_rounds(
    u: &mut arbitrary::Unstructured,
) -> arbitrary::Result<Vec<FuzzAdaptiveBudgetRound>> {
    let len = usize::from(u.int_in_range::<u8>(1..=10)?);
    let mut rounds = Vec::with_capacity(len);
    for _ in 0..len {
        rounds.push(u.arbitrary()?);
    }
    Ok(rounds)
}

fn bounded_priority_vec(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Vec<u8>> {
    let len = usize::from(u.int_in_range::<u8>(0..=24)?);
    let mut priorities = Vec::with_capacity(len);
    for _ in 0..len {
        priorities.push(u.int_in_range(0..=100)?);
    }
    Ok(priorities)
}

fn bounded_timed_buckets(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Vec<u8>> {
    let len = usize::from(u.int_in_range::<u8>(0..=24)?);
    let mut buckets = Vec::with_capacity(len);
    for _ in 0..len {
        buckets.push(u.int_in_range(0..=3)?);
    }
    Ok(buckets)
}

fn bounded_promote_attempts(u: &mut arbitrary::Unstructured) -> arbitrary::Result<u8> {
    u.int_in_range(1..=4)
}

fn bounded_deadline_promotion_tasks(
    u: &mut arbitrary::Unstructured,
) -> arbitrary::Result<Vec<FuzzDeadlinePromotionTask>> {
    let len = usize::from(u.int_in_range::<u8>(0..=12)?);
    let mut tasks = Vec::with_capacity(len);
    for _ in 0..len {
        tasks.push(u.arbitrary()?);
    }
    Ok(tasks)
}

fn bounded_zero_reward_arm_trace(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Vec<u8>> {
    let len = usize::from(u.int_in_range::<u8>(1..=24)?);
    let mut trace = Vec::with_capacity(len);
    for _ in 0..len {
        trace.push(u.int_in_range(0..=8)?);
    }
    Ok(trace)
}

fn bounded_worker_count(u: &mut arbitrary::Unstructured) -> arbitrary::Result<u8> {
    u.int_in_range(1..=4)
}

fn bounded_shutdown_calls(u: &mut arbitrary::Unstructured) -> arbitrary::Result<u8> {
    u.int_in_range(1..=4)
}

fn bounded_post_shutdown_wakes(u: &mut arbitrary::Unstructured) -> arbitrary::Result<u8> {
    u.int_in_range(0..=4)
}

fn bounded_steal_worker_count(u: &mut arbitrary::Unstructured) -> arbitrary::Result<u8> {
    u.int_in_range(2..=5)
}

fn bounded_steal_task_counts(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Vec<u8>> {
    let len = usize::from(u.int_in_range::<u8>(0..=5)?);
    let mut counts = Vec::with_capacity(len);
    for _ in 0..len {
        counts.push(u.int_in_range(0..=4)?);
    }
    Ok(counts)
}

fn bounded_thief_indices(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Vec<u8>> {
    let len = usize::from(u.int_in_range::<u8>(0..=5)?);
    let mut thieves = Vec::with_capacity(len);
    for _ in 0..len {
        thieves.push(u.int_in_range(0..=7)?);
    }
    Ok(thieves)
}

fn bounded_steal_batch_size(u: &mut arbitrary::Unstructured) -> arbitrary::Result<u8> {
    u.int_in_range(1..=4)
}

impl From<FuzzPotentialWeights> for PotentialWeights {
    fn from(fuzz_weights: FuzzPotentialWeights) -> Self {
        Self {
            w_tasks: fuzz_weights.w_tasks,
            w_obligation_age: fuzz_weights.w_obligation_age,
            w_draining_regions: fuzz_weights.w_draining_regions,
            w_deadline_pressure: fuzz_weights.w_deadline_pressure,
        }
    }
}

impl From<FuzzSchedulingSuggestion> for SchedulingSuggestion {
    fn from(suggestion: FuzzSchedulingSuggestion) -> Self {
        match suggestion {
            FuzzSchedulingSuggestion::NoPreference => Self::NoPreference,
            FuzzSchedulingSuggestion::MeetDeadlines => Self::MeetDeadlines,
            FuzzSchedulingSuggestion::DrainObligations => Self::DrainObligations,
            FuzzSchedulingSuggestion::DrainRegions => Self::DrainRegions,
        }
    }
}

impl FuzzStateSnapshot {
    fn total_cancel_mask_tasks(&self) -> u32 {
        u32::from(self.cancel_requested_tasks)
            .saturating_add(u32::from(self.cancelling_tasks))
            .saturating_add(u32::from(self.finalizing_tasks))
    }

    fn to_state_snapshot(&self, base_time: Time, ready_queue_depth: u32) -> StateSnapshot {
        StateSnapshot {
            time: Time::from_nanos(base_time.as_nanos() + self.time_offset_ns),
            live_tasks: cmp::max(self.live_tasks, self.total_cancel_mask_tasks()),
            pending_obligations: self.pending_obligations,
            obligation_age_sum_ns: if self.pending_obligations == 0 {
                0
            } else {
                self.obligation_age_sum_ns
            },
            draining_regions: self.draining_regions,
            deadline_pressure: self.deadline_pressure,
            pending_send_permits: self.pending_obligations,
            pending_acks: 0,
            pending_leases: 0,
            pending_io_ops: 0,
            cancel_requested_tasks: u32::from(self.cancel_requested_tasks),
            cancelling_tasks: u32::from(self.cancelling_tasks),
            finalizing_tasks: u32::from(self.finalizing_tasks),
            ready_queue_depth,
        }
    }
}

/// Test that lane decisions are deterministic for identical input
fn test_decision_determinism(weights: &PotentialWeights, snapshots: &[StateSnapshot]) -> bool {
    if snapshots.is_empty() {
        return true; // Vacuously true
    }

    let governor1 = LyapunovGovernor::new(*weights);
    let governor2 = LyapunovGovernor::new(*weights);

    for snapshot in snapshots {
        let suggestion1 = governor1.suggest(snapshot);
        let suggestion2 = governor2.suggest(snapshot);

        if suggestion1 != suggestion2 {
            return false; // Non-deterministic behavior detected
        }
    }
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaneKind {
    Cancel,
    Timed,
    Ready,
}

fn timed_deadline_from_bucket(bucket: u8) -> Time {
    match bucket % 4 {
        0 => Time::from_nanos(0),
        1 => Time::from_nanos(250),
        2 => Time::from_nanos(500),
        _ => Time::from_nanos(1_000),
    }
}

fn scheduler_task_id(base: u32, index: usize) -> TaskId {
    TaskId::new_for_test(base + u32::try_from(index).unwrap_or(u32::MAX), 0)
}

fn burst_task_id(round: usize, lane_offset: u32, index: usize) -> TaskId {
    let round_base = u32::try_from(round)
        .unwrap_or(u32::MAX / 100)
        .saturating_mul(100);
    scheduler_task_id(
        70_000u32
            .saturating_add(round_base)
            .saturating_add(lane_offset),
        index,
    )
}

fn request_cancel_mask_task(record: &mut TaskRecord, task_id: TaskId, phase: &str) {
    let cancel_effects =
        record.request_cancel_with_budget(CancelReason::timeout(), Budget::INFINITE);
    let (accepted, cancel_wakes) = cancel_effects.into_parts();
    cancel_wakes.suppress();
    assert!(
        accepted,
        "cancel-mask {phase} task {task_id:?} must accept its initial cancel request"
    );
}

fn acknowledge_cancel_mask_task(record: &mut TaskRecord, task_id: TaskId, phase: &str) {
    assert!(
        record.acknowledge_cancel().is_some(),
        "cancel-mask {phase} task {task_id:?} must transition from requested to cancelling"
    );
}

fn finish_cancel_mask_cleanup(record: &mut TaskRecord, task_id: TaskId, phase: &str) {
    assert!(
        record.cleanup_done(),
        "cancel-mask {phase} task {task_id:?} must transition from cancelling to finalizing"
    );
}

fn install_cancel_mask(state: &Arc<ContendedMutex<RuntimeState>>, snapshot: &FuzzStateSnapshot) {
    let total_cancel_tasks = snapshot.total_cancel_mask_tasks();
    if total_cancel_tasks == 0 {
        return;
    }

    let mut state = state.lock().expect("lock runtime state for cancel mask");
    let owner = RegionId::testing_default();

    for idx in 0..usize::from(snapshot.cancel_requested_tasks) {
        let task_id = scheduler_task_id(40_000, idx);
        let inserted = state.insert_task(TaskRecord::new_with_time(
            task_id,
            owner,
            Budget::INFINITE,
            Time::ZERO,
        ));
        let task_id = TaskId::from_arena(inserted);
        state
            .update_task(task_id, |record| {
                request_cancel_mask_task(record, task_id, "cancel-requested");
            })
            .expect("cancel-requested task must exist");
    }

    for idx in 0..usize::from(snapshot.cancelling_tasks) {
        let task_id = scheduler_task_id(50_000, idx);
        let inserted = state.insert_task(TaskRecord::new_with_time(
            task_id,
            owner,
            Budget::INFINITE,
            Time::ZERO,
        ));
        let task_id = TaskId::from_arena(inserted);
        state
            .update_task(task_id, |record| {
                request_cancel_mask_task(record, task_id, "cancelling");
                acknowledge_cancel_mask_task(record, task_id, "cancelling");
            })
            .expect("cancelling task must exist");
    }

    for idx in 0..usize::from(snapshot.finalizing_tasks) {
        let task_id = scheduler_task_id(60_000, idx);
        let inserted = state.insert_task(TaskRecord::new_with_time(
            task_id,
            owner,
            Budget::INFINITE,
            Time::ZERO,
        ));
        let task_id = TaskId::from_arena(inserted);
        state
            .update_task(task_id, |record| {
                request_cancel_mask_task(record, task_id, "finalizing");
                acknowledge_cancel_mask_task(record, task_id, "finalizing");
                finish_cancel_mask_cleanup(record, task_id, "finalizing");
            })
            .expect("finalizing task must exist");
    }
}

fn runtime_cancel_mask_snapshot(state: &Arc<ContendedMutex<RuntimeState>>) -> StateSnapshot {
    let guard = state
        .lock()
        .expect("lock runtime state for cancel-mask snapshot");
    StateSnapshot::from_runtime_state(&guard)
}

fn assert_cancel_mask_propagation(workload: &FuzzLaneWorkload, cancel_mask: &FuzzStateSnapshot) {
    if cancel_mask.total_cancel_mask_tasks() == 0 {
        return;
    }

    let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(2_000)));
    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    {
        let mut guard = state.lock().expect("lock runtime state");
        guard.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));
    }
    install_cancel_mask(&state, cancel_mask);

    let initial_snapshot = runtime_cancel_mask_snapshot(&state);
    assert_eq!(
        initial_snapshot.cancel_requested_tasks,
        u32::from(cancel_mask.cancel_requested_tasks),
        "cancel-requested count must propagate from RuntimeState into StateSnapshot"
    );
    assert_eq!(
        initial_snapshot.cancelling_tasks,
        u32::from(cancel_mask.cancelling_tasks),
        "cancelling count must propagate from RuntimeState into StateSnapshot"
    );
    assert_eq!(
        initial_snapshot.finalizing_tasks,
        u32::from(cancel_mask.finalizing_tasks),
        "finalizing count must propagate from RuntimeState into StateSnapshot"
    );
    assert_eq!(
        initial_snapshot.live_tasks,
        cancel_mask.total_cancel_mask_tasks(),
        "cancel-mask installation should account for every synthetic task in live_tasks"
    );

    let total_dispatchable = workload.cancel_priorities.len()
        + workload.ready_priorities.len()
        + workload.timed_deadline_buckets.len();

    let mut scheduler =
        ThreeLaneScheduler::new_with_options(1, &state, workload.cancel_streak_limit, true, 1);

    let mut cancel_tasks = Vec::with_capacity(workload.cancel_priorities.len());
    let mut timed_tasks = Vec::with_capacity(workload.timed_deadline_buckets.len());
    let mut ready_tasks = Vec::with_capacity(workload.ready_priorities.len());

    for (index, &priority) in workload.cancel_priorities.iter().enumerate() {
        let task = scheduler_task_id(10_000, index);
        cancel_tasks.push(task);
        scheduler.inject_cancel(task, priority);
    }

    for (index, &bucket) in workload.timed_deadline_buckets.iter().enumerate() {
        let task = scheduler_task_id(20_000, index);
        timed_tasks.push(task);
        scheduler.inject_timed(task, timed_deadline_from_bucket(bucket));
    }

    for (index, &priority) in workload.ready_priorities.iter().enumerate() {
        let task = scheduler_task_id(30_000, index);
        ready_tasks.push(task);
        scheduler.inject_ready(task, priority);
    }

    let mut workers = scheduler.take_workers();
    let worker = &mut workers[0];
    worker.set_cached_suggestion(workload.cached_suggestion.into());

    let mut dispatched = Vec::with_capacity(total_dispatchable);
    while dispatched.len() < total_dispatchable {
        let Some(task) = worker.next_task() else {
            break;
        };
        assert!(
            cancel_tasks.contains(&task)
                || timed_tasks.contains(&task)
                || ready_tasks.contains(&task),
            "cancel-mask propagation leaked non-runnable synthetic state into dispatch: {task:?}"
        );
        assert!(
            !dispatched.contains(&task),
            "dispatch loop duplicated task {task:?} while cancel-mask state was active"
        );
        dispatched.push(task);
    }

    assert_eq!(
        dispatched.len(),
        total_dispatchable,
        "cancel-mask propagation must not strand or fabricate dispatchable work"
    );
    for _ in 0..3 {
        assert_eq!(
            worker.next_task(),
            None,
            "cancel-mask-only state must not keep producing runnable tasks after injected work drains"
        );
    }

    let final_snapshot = runtime_cancel_mask_snapshot(&state);
    assert_eq!(
        final_snapshot.cancel_requested_tasks, initial_snapshot.cancel_requested_tasks,
        "scheduling injected work must not mutate cancel-requested mask counts"
    );
    assert_eq!(
        final_snapshot.cancelling_tasks, initial_snapshot.cancelling_tasks,
        "scheduling injected work must not mutate cancelling mask counts"
    );
    assert_eq!(
        final_snapshot.finalizing_tasks, initial_snapshot.finalizing_tasks,
        "scheduling injected work must not mutate finalizing mask counts"
    );
    assert_eq!(
        final_snapshot.live_tasks, initial_snapshot.live_tasks,
        "cancel-mask propagation must preserve the live-task accounting for synthetic state"
    );
}

fn assert_scheduler_fairness(workload: &FuzzLaneWorkload, cancel_mask: &FuzzStateSnapshot) {
    let total_tasks = workload.cancel_priorities.len()
        + workload.ready_priorities.len()
        + workload.timed_deadline_buckets.len();
    if total_tasks == 0 && cancel_mask.total_cancel_mask_tasks() == 0 {
        return;
    }

    let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(1_000)));
    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    {
        let mut guard = state.lock().expect("lock runtime state");
        guard.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));
    }
    install_cancel_mask(&state, cancel_mask);

    let mut scheduler =
        ThreeLaneScheduler::new_with_options(1, &state, workload.cancel_streak_limit, true, 1);

    let mut cancel_tasks = Vec::with_capacity(workload.cancel_priorities.len());
    let mut timed_tasks = Vec::with_capacity(workload.timed_deadline_buckets.len());
    let mut ready_tasks = Vec::with_capacity(workload.ready_priorities.len());

    for (index, &priority) in workload.cancel_priorities.iter().enumerate() {
        let task = scheduler_task_id(10_000, index);
        cancel_tasks.push(task);
        scheduler.inject_cancel(task, priority);
    }

    for (index, &bucket) in workload.timed_deadline_buckets.iter().enumerate() {
        let task = scheduler_task_id(20_000, index);
        timed_tasks.push(task);
        scheduler.inject_timed(task, timed_deadline_from_bucket(bucket));
    }

    for (index, &priority) in workload.ready_priorities.iter().enumerate() {
        let task = scheduler_task_id(30_000, index);
        ready_tasks.push(task);
        scheduler.inject_ready(task, priority);
    }

    let mut workers = scheduler.take_workers();
    let worker = &mut workers[0];
    worker.set_cached_suggestion(workload.cached_suggestion.into());

    let mut dispatch_trace = Vec::with_capacity(total_tasks);
    let mut dispatched_tasks = Vec::with_capacity(total_tasks);
    while dispatch_trace.len() < total_tasks {
        let Some(task) = worker.next_task() else {
            break;
        };
        assert!(
            !dispatched_tasks.contains(&task),
            "arbiter re-dispatched {task:?} under cancel-mask pressure"
        );
        dispatched_tasks.push(task);

        let lane = if cancel_tasks.contains(&task) {
            LaneKind::Cancel
        } else if timed_tasks.contains(&task) {
            LaneKind::Timed
        } else if ready_tasks.contains(&task) {
            LaneKind::Ready
        } else {
            panic!("dispatched unknown task {task:?}");
        };
        dispatch_trace.push(lane);
    }

    assert_eq!(
        dispatch_trace.len(),
        total_tasks,
        "all injected due workloads should drain under the arbiter"
    );

    let cert = worker.preemption_fairness_certificate();
    assert!(
        cert.invariant_holds(),
        "fairness certificate must hold under arbitrary pressure: {cert:?}"
    );
    assert_eq!(cert.cancel_dispatches as usize, cancel_tasks.len());
    assert_eq!(cert.timed_dispatches as usize, timed_tasks.len());
    assert_eq!(cert.ready_dispatches as usize, ready_tasks.len());

    for _ in 0..3 {
        assert_eq!(
            worker.next_task(),
            None,
            "arbiter must terminate once dispatchable work drains even with active cancel-mask state"
        );
    }

    if !cancel_tasks.is_empty() {
        assert!(dispatch_trace.contains(&LaneKind::Cancel));
    }
    if !timed_tasks.is_empty() {
        assert!(dispatch_trace.contains(&LaneKind::Timed));
        assert!(
            cert.observed_max_timed_stall_steps <= cert.ready_stall_bound_steps(),
            "timed lane exceeded fairness stall bound: {cert:?}"
        );
    }
    if !ready_tasks.is_empty() {
        assert!(dispatch_trace.contains(&LaneKind::Ready));
        assert!(
            cert.observed_max_ready_stall_steps <= cert.ready_stall_bound_steps(),
            "ready lane exceeded fairness stall bound: {cert:?}"
        );
    }

    if (!ready_tasks.is_empty() || !timed_tasks.is_empty()) && !cancel_tasks.is_empty() {
        let first_non_cancel = dispatch_trace
            .iter()
            .position(|lane| *lane != LaneKind::Cancel)
            .expect("competing non-cancel work should dispatch");
        assert!(
            first_non_cancel <= cert.ready_stall_bound_steps(),
            "non-cancel work starved beyond fairness bound: first_non_cancel={first_non_cancel}, cert={cert:?}"
        );
    }

    if cert.cancel_dispatches as usize > cert.effective_limit
        && (!ready_tasks.is_empty() || !timed_tasks.is_empty())
    {
        assert!(
            cert.fairness_yields > 0,
            "cancel pressure above effective limit should force a fairness yield: {cert:?}"
        );
    }
}

fn assert_timed_lane_edf_order(workload: &FuzzLaneWorkload) {
    if workload.timed_deadline_buckets.is_empty() {
        return;
    }

    let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(1_000)));
    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    {
        let mut guard = state.lock().expect("lock runtime state");
        guard.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));
    }

    let mut scheduler =
        ThreeLaneScheduler::new_with_options(1, &state, workload.cancel_streak_limit, true, 1);
    let mut expected = Vec::with_capacity(workload.timed_deadline_buckets.len());

    for (index, &bucket) in workload.timed_deadline_buckets.iter().enumerate() {
        let task = scheduler_task_id(80_000, index);
        let deadline = timed_deadline_from_bucket(bucket);
        expected.push((deadline.as_nanos(), index, task));
        scheduler.inject_timed(task, deadline);
    }

    expected.sort_by_key(|&(deadline_ns, arrival_index, _)| (deadline_ns, arrival_index));
    let expected_tasks: Vec<_> = expected.into_iter().map(|(_, _, task)| task).collect();

    let mut workers = scheduler.take_workers();
    let worker = &mut workers[0];
    let actual: Vec<_> = (0..expected_tasks.len())
        .map(|_| {
            worker
                .next_task()
                .expect("all due timed tasks should drain from the lane")
        })
        .collect();

    assert_eq!(
        actual, expected_tasks,
        "timed lane must preserve stable earliest-deadline-first order for arbitrary arrival order"
    );
    for _ in 0..2 {
        assert_eq!(
            worker.next_task(),
            None,
            "timed lane should be empty after draining the EDF-ordered workload"
        );
    }
}

fn assert_deadline_miss_promotion_once(scenario: &FuzzDeadlinePromotionScenario) {
    if scenario.tasks.is_empty() {
        return;
    }

    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    let clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
    {
        let mut guard = state.lock().expect("lock runtime state");
        guard.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock.clone()));
    }

    let cancel_limit = scenario.tasks.len().max(1);
    let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, cancel_limit);
    let mut workers = scheduler.take_workers();
    let worker = workers.first_mut().expect("worker");

    let mut max_deadline_ns = 0u64;
    let mut promoted_tasks = Vec::new();
    let mut expected_total = 0usize;

    for (index, task) in scenario.tasks.iter().enumerate() {
        let task_id = scheduler_task_id(95_000, index);
        let deadline = timed_deadline_from_bucket(task.deadline_bucket);
        max_deadline_ns = max_deadline_ns.max(deadline.as_nanos());
        worker.schedule_local_timed(task_id, deadline);
        expected_total += 1;
        if task.promote_after_miss {
            promoted_tasks.push((task_id, task.promote_attempts, task.cancel_priority));
        }
    }

    clock.advance_to(Time::from_nanos(max_deadline_ns.saturating_add(1)));
    for (task_id, attempts, priority) in &promoted_tasks {
        for _ in 0..usize::from(*attempts) {
            worker.schedule_local_cancel(*task_id, *priority);
        }
    }

    let mut dispatch_trace = Vec::with_capacity(expected_total);
    while dispatch_trace.len() < expected_total {
        let Some(task) = worker.next_task() else {
            break;
        };
        assert!(
            !dispatch_trace.contains(&task),
            "missed-deadline promotion duplicated task {task:?}"
        );
        dispatch_trace.push(task);
    }

    assert_eq!(
        dispatch_trace.len(),
        expected_total,
        "missed-deadline promotion must preserve total timed tasks without fabricating or dropping work"
    );

    let promoted_ids: Vec<_> = promoted_tasks
        .iter()
        .map(|(task_id, _, _)| *task_id)
        .collect();
    for task_id in &promoted_ids {
        assert!(
            dispatch_trace.contains(task_id),
            "promoted task {task_id:?} must still dispatch exactly once"
        );
    }

    let promoted_prefix_len = promoted_ids.len();
    if promoted_prefix_len > 0 {
        assert!(
            dispatch_trace[..promoted_prefix_len]
                .iter()
                .all(|task_id| promoted_ids.contains(task_id)),
            "promoted missed-deadline tasks must dispatch from cancel lane before remaining timed work"
        );
    }

    let metrics = worker.preemption_metrics();
    assert_eq!(
        metrics.cancel_dispatches as usize,
        promoted_ids.len(),
        "each missed-deadline promotion should contribute exactly one cancel dispatch"
    );
    assert_eq!(
        metrics.timed_dispatches as usize,
        scenario.tasks.len().saturating_sub(promoted_ids.len()),
        "promoted missed-deadline tasks must not remain observable through the timed lane"
    );
    assert_eq!(metrics.ready_dispatches, 0);
    assert!(
        worker.invariant_violations().is_empty(),
        "missed-deadline promotion must not introduce scheduler invariant violations"
    );

    for _ in 0..2 {
        assert_eq!(
            worker.next_task(),
            None,
            "worker should quiesce after draining the missed-deadline promotion scenario"
        );
    }
}

fn assert_monotone_deadlines_preserve_edf_under_promotion(
    scenario: &FuzzDeadlinePromotionScenario,
) {
    if scenario.tasks.is_empty() {
        return;
    }

    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    let clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
    {
        let mut guard = state.lock().expect("lock runtime state");
        guard.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock.clone()));
    }

    let cancel_limit = scenario.tasks.len().max(1);
    let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(1, &state, cancel_limit);
    let mut workers = scheduler.take_workers();
    let worker = workers.first_mut().expect("worker");

    let mut monotone_deadlines = Vec::with_capacity(scenario.tasks.len());
    let mut current_deadline_ns = 0u64;
    for task in &scenario.tasks {
        current_deadline_ns =
            current_deadline_ns.max(timed_deadline_from_bucket(task.deadline_bucket).as_nanos());
        monotone_deadlines.push(Time::from_nanos(current_deadline_ns));
    }

    let mut promoted = Vec::new();
    let mut remaining_timed = Vec::new();
    for (index, task) in scenario.tasks.iter().enumerate() {
        let task_id = scheduler_task_id(96_000, index);
        worker.schedule_local_timed(task_id, monotone_deadlines[index]);
        if task.promote_after_miss {
            promoted.push((task_id, task.promote_attempts, task.cancel_priority));
        } else {
            remaining_timed.push(task_id);
        }
    }

    let max_deadline_ns = monotone_deadlines
        .last()
        .map(|deadline| deadline.as_nanos())
        .unwrap_or(0u64)
        .saturating_add(1);
    clock.advance_to(Time::from_nanos(max_deadline_ns));
    for (task_id, attempts, priority) in &promoted {
        for _ in 0..usize::from(*attempts) {
            worker.schedule_local_cancel(*task_id, *priority);
        }
    }

    let expected_total = scenario.tasks.len();
    let mut dispatch_trace = Vec::with_capacity(expected_total);
    while dispatch_trace.len() < expected_total {
        let Some(task) = worker.next_task() else {
            break;
        };
        assert!(
            !dispatch_trace.contains(&task),
            "monotone deadline promotion duplicated task {task:?}"
        );
        dispatch_trace.push(task);
    }

    assert_eq!(
        dispatch_trace.len(),
        expected_total,
        "monotone deadline scenario must dispatch every task exactly once"
    );

    let expected_promoted: Vec<_> = promoted.iter().map(|(task_id, _, _)| *task_id).collect();
    let observed_promoted: Vec<_> = dispatch_trace
        .iter()
        .copied()
        .filter(|task_id| expected_promoted.contains(task_id))
        .collect();
    assert_eq!(
        observed_promoted, expected_promoted,
        "promoted tasks from a monotone deadline stream must preserve EDF-equivalent order"
    );

    let observed_remaining: Vec<_> = dispatch_trace
        .iter()
        .copied()
        .filter(|task_id| remaining_timed.contains(task_id))
        .collect();
    assert_eq!(
        observed_remaining, remaining_timed,
        "non-promoted timed tasks from a monotone deadline stream must preserve EDF order"
    );

    let expected_trace: Vec<_> = expected_promoted
        .iter()
        .copied()
        .chain(remaining_timed.iter().copied())
        .collect();
    assert_eq!(
        dispatch_trace, expected_trace,
        "lane promotion must preserve monotone EDF order across cancel/timed observation boundaries"
    );

    let metrics = worker.preemption_metrics();
    assert_eq!(metrics.cancel_dispatches as usize, expected_promoted.len());
    assert_eq!(metrics.timed_dispatches as usize, remaining_timed.len());
    assert_eq!(metrics.ready_dispatches, 0);
    assert!(
        worker.invariant_violations().is_empty(),
        "monotone deadline promotion must not introduce scheduler invariant violations"
    );

    for _ in 0..2 {
        assert_eq!(
            worker.next_task(),
            None,
            "worker should quiesce after draining the monotone deadline promotion scenario"
        );
    }
}

fn assert_zero_reward_policy_trace(trace: &FuzzZeroRewardPolicyTrace) {
    if trace.forced_arms.is_empty() {
        return;
    }

    let mut policy = AdaptiveCancelStreakPolicyBench::new(trace.epoch_steps);
    policy.seed_history([0.0; 5], [1e-9; 5]);
    policy.begin_epoch(AdaptivePolicyBenchSnapshot::new(0.0, 0.0, 0, 0, 0));

    let mut potential = 0.0f64;
    for &arm_seed in &trace.forced_arms {
        let arm = usize::from(arm_seed) % policy.arm_count();
        policy.force_selected_arm(arm);

        let next_potential = potential.mul_add(2.0, 1.0);
        let reward = policy
            .complete_epoch(AdaptivePolicyBenchSnapshot::new(
                next_potential,
                0.0,
                0,
                0,
                0,
            ))
            .expect("zero-reward trace must have an open epoch");
        assert!(
            reward.abs() <= f64::EPSILON,
            "synthetic all-zero reward trace should stay at zero reward, got {reward}"
        );

        let discounted_pulls = policy.discounted_pulls();
        for (idx, weight) in discounted_pulls.iter().enumerate() {
            assert!(
                weight.is_finite() && *weight > 0.0,
                "discounted arm mass must stay finite and strictly positive under zero rewards: arm={idx} weight={weight}"
            );
        }

        let mean_rewards = policy.mean_rewards();
        for (idx, mean_reward) in mean_rewards.iter().enumerate() {
            assert!(
                mean_reward.is_finite() && (0.0..=1.0).contains(mean_reward),
                "mean reward must stay finite and bounded under zero rewards: arm={idx} mean={mean_reward}"
            );
        }

        let e_value = policy.e_value();
        assert!(
            e_value.is_finite() && e_value > 0.0,
            "adaptive e-process must stay finite and strictly positive under zero rewards: {e_value}"
        );
        assert!(
            policy.select_arm_ucb() < policy.arm_count(),
            "zero-reward adaptive trace must keep selecting a valid arm"
        );

        potential = next_potential;
    }
}

#[derive(Debug)]
struct ShutdownHandshakeReactor {
    poll_started: AtomicBool,
    release_poll: AtomicBool,
    wake_calls: AtomicUsize,
    poll_calls: AtomicUsize,
}

impl ShutdownHandshakeReactor {
    fn new() -> Self {
        Self {
            poll_started: AtomicBool::new(false),
            release_poll: AtomicBool::new(false),
            wake_calls: AtomicUsize::new(0),
            poll_calls: AtomicUsize::new(0),
        }
    }

    fn wait_until_poll_started(&self) {
        for _ in 0..50_000 {
            if self.poll_started.load(Ordering::Acquire) {
                return;
            }
            thread::yield_now();
        }
        panic!("reactor leader never entered poll");
    }

    fn wake_calls(&self) -> usize {
        self.wake_calls.load(Ordering::SeqCst)
    }

    fn poll_calls(&self) -> usize {
        self.poll_calls.load(Ordering::SeqCst)
    }
}

impl Reactor for ShutdownHandshakeReactor {
    fn register(&self, _source: &dyn Source, _token: Token, _interest: Interest) -> io::Result<()> {
        Ok(())
    }

    fn modify(&self, _token: Token, _interest: Interest) -> io::Result<()> {
        Ok(())
    }

    fn deregister(&self, _token: Token) -> io::Result<()> {
        Ok(())
    }

    fn registration_count(&self) -> usize {
        0
    }

    fn poll(&self, _events: &mut Events, _timeout: Option<Duration>) -> io::Result<usize> {
        self.poll_calls.fetch_add(1, Ordering::SeqCst);
        self.poll_started.store(true, Ordering::Release);
        while !self.release_poll.load(Ordering::Acquire) {
            thread::yield_now();
        }
        Ok(0)
    }

    fn wake(&self) -> io::Result<()> {
        self.wake_calls.fetch_add(1, Ordering::SeqCst);
        self.release_poll.store(true, Ordering::Release);
        Ok(())
    }
}

fn assert_reactor_shutdown_handshake(scenario: &FuzzReactorShutdownScenario) {
    let reactor = Arc::new(ShutdownHandshakeReactor::new());
    let reactor_handle: Arc<dyn Reactor> = reactor.clone();
    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    {
        let mut guard = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.set_io_driver(IoDriverHandle::new(reactor_handle));
    }

    let mut scheduler = ThreeLaneScheduler::new(usize::from(scenario.worker_count), &state);
    let handles: Vec<_> = scheduler
        .take_workers()
        .into_iter()
        .map(|mut worker| thread::spawn(move || worker.run_loop()))
        .collect();

    reactor.wait_until_poll_started();

    for _ in 0..usize::from(scenario.shutdown_calls) {
        scheduler.shutdown();
    }
    for _ in 0..usize::from(scenario.post_shutdown_wakes) {
        scheduler.wake_all();
    }

    assert!(scheduler.is_shutdown(), "shutdown bit must stay set");

    for handle in handles {
        handle
            .join()
            .expect("worker must complete reactor-shutdown handshake");
    }

    let expected_wakes =
        usize::from(scenario.shutdown_calls) + usize::from(scenario.post_shutdown_wakes);
    assert!(
        reactor.wake_calls() >= expected_wakes,
        "shutdown handshake must wake the in-flight reactor leader at least once per explicit wake: observed {} expected at least {}",
        reactor.wake_calls(),
        expected_wakes
    );
    assert!(
        reactor.poll_calls() >= 1,
        "at least one worker must enter the reactor leader poll"
    );
}

fn assert_concurrent_multi_victim_steal_no_double_steal(
    scenario: &FuzzConcurrentMultiVictimStealScenario,
) {
    let worker_count = usize::from(scenario.worker_count.max(2));
    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    let mut scheduler = ThreeLaneScheduler::new(worker_count, &state);
    scheduler.set_steal_batch_size(usize::from(scenario.steal_batch_size.max(1)));

    let mut next_task_index = 1u32;
    let mut seeded = BTreeSet::new();

    for worker_id in 0..worker_count {
        let fast_count = usize::from(
            scenario
                .fast_task_counts
                .get(worker_id)
                .copied()
                .unwrap_or_default(),
        );
        let heap_count = usize::from(
            scenario
                .heap_task_counts
                .get(worker_id)
                .copied()
                .unwrap_or_default(),
        );

        for _ in 0..fast_count {
            let task = TaskId::new_for_test(next_task_index, worker_id as u32);
            next_task_index = next_task_index.saturating_add(1);
            scheduler.seed_worker_fast_ready_for_test(worker_id, task);
            seeded.insert(task.as_u64());
        }

        for offset in 0..heap_count {
            let task = TaskId::new_for_test(next_task_index, worker_id as u32);
            next_task_index = next_task_index.saturating_add(1);
            let priority = 200u8.saturating_sub(offset as u8);
            scheduler.seed_worker_priority_ready_for_test(worker_id, task, priority);
            seeded.insert(task.as_u64());
        }
    }

    if seeded.is_empty() {
        let task = TaskId::new_for_test(next_task_index, 0);
        scheduler.seed_worker_fast_ready_for_test(0, task);
        seeded.insert(task.as_u64());
    }

    let mut thief_ids = BTreeSet::new();
    for &idx in &scenario.thief_indices {
        thief_ids.insert(usize::from(idx) % worker_count);
    }
    if thief_ids.is_empty() {
        thief_ids.insert(worker_count - 1);
    }

    let attempts_per_thief = seeded.len().clamp(1, 32);
    let barrier = Arc::new(Barrier::new(thief_ids.len()));
    let stolen = Arc::new(Mutex::new(Vec::<u64>::new()));
    let mut workers: Vec<_> = scheduler.take_workers().into_iter().map(Some).collect();

    let handles: Vec<_> = thief_ids
        .into_iter()
        .map(|worker_id| {
            let mut worker = workers[worker_id]
                .take()
                .expect("selected thief worker must exist");
            let barrier = Arc::clone(&barrier);
            let stolen = Arc::clone(&stolen);
            thread::spawn(move || {
                barrier.wait();
                for _ in 0..attempts_per_thief {
                    if let Some(task) = worker.steal_once_for_test() {
                        stolen.lock().expect("stolen lock").push(task.as_u64());
                    }
                    thread::yield_now();
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("concurrent steal worker must join");
    }

    let stolen = stolen.lock().expect("stolen lock");
    let mut seen = BTreeSet::new();
    for &task in stolen.iter() {
        assert!(
            seeded.contains(&task),
            "stolen task {task} must come from the seeded victim set"
        );
        assert!(
            seen.insert(task),
            "same task must not be stolen twice under multi-victim contention: {task}"
        );
    }
}

fn assert_adaptive_budget_governor(
    scenario: &FuzzAdaptiveBudgetScenario,
    weights: &PotentialWeights,
) {
    if scenario.rounds.is_empty() {
        return;
    }

    let governor = LyapunovGovernor::new(*weights);
    let mut policy = AdaptiveCancelStreakPolicyBench::new(scenario.epoch_steps);

    let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(10_000)));
    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    {
        let mut guard = state.lock().expect("lock runtime state");
        guard.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));
    }

    let mut scheduler = ThreeLaneScheduler::new_with_options(
        1,
        &state,
        usize::try_from(scenario.epoch_steps).unwrap_or(1),
        true,
        1,
    );
    scheduler.set_adaptive_cancel_streak(true, scenario.epoch_steps);

    let mut workers = scheduler.take_workers();
    let worker = &mut workers[0];
    let mut dispatched = Vec::new();
    let mut total_injected = 0usize;
    let mut cumulative_effective_exceedances = 0u64;
    let mut cumulative_fallback_dispatches = 0u64;
    let base_time = Time::from_nanos(50_000);

    for (round_index, round) in scenario.rounds.iter().enumerate() {
        let ready_depth = u32::from(round.ready_arrivals) + u32::from(round.timed_arrivals);
        let mut snapshot = round.snapshot.to_state_snapshot(base_time, ready_depth);
        snapshot.time = Time::from_nanos(
            base_time.as_nanos()
                + u64::try_from(round_index)
                    .unwrap_or(0)
                    .saturating_mul(1_000),
        );

        let potential = governor.compute_record(&snapshot).total;
        assert!(
            potential.is_finite() && potential >= 0.0,
            "adaptive governor potential must stay finite and non-negative: {potential}"
        );

        let cancel_pressure =
            u32::from(round.cancel_arrivals).saturating_add(snapshot.total_cancelling_tasks());
        let non_cancel_pressure =
            u32::from(round.ready_arrivals).saturating_add(u32::from(round.timed_arrivals));
        cumulative_effective_exceedances = cumulative_effective_exceedances.saturating_add(
            u64::from(cancel_pressure.saturating_sub(non_cancel_pressure).min(4)),
        );
        if cancel_pressure > 0 && non_cancel_pressure == 0 {
            cumulative_fallback_dispatches = cumulative_fallback_dispatches.saturating_add(1);
        }

        let bench_snapshot = AdaptivePolicyBenchSnapshot::new(
            potential,
            snapshot.deadline_pressure,
            0,
            cumulative_effective_exceedances,
            cumulative_fallback_dispatches,
        );
        if round_index == 0 {
            policy.begin_epoch(bench_snapshot);
        } else {
            let reward = policy
                .complete_epoch(bench_snapshot)
                .expect("adaptive epoch must have a start snapshot");
            assert!(
                reward.is_finite() && (0.0..=1.0).contains(&reward),
                "adaptive reward must stay within [0, 1]: {reward}"
            );
        }
        assert!(
            policy.select_arm_ucb() < policy.arm_count(),
            "adaptive governor must always select a valid arm"
        );

        for idx in 0..usize::from(round.cancel_arrivals) {
            scheduler.inject_cancel(burst_task_id(round_index, 0, idx), 100);
            total_injected = total_injected.saturating_add(1);
        }
        for idx in 0..usize::from(round.ready_arrivals) {
            scheduler.inject_ready(burst_task_id(round_index, 20, idx), 50);
            total_injected = total_injected.saturating_add(1);
        }
        for idx in 0..usize::from(round.timed_arrivals) {
            scheduler.inject_timed(
                burst_task_id(round_index, 40, idx),
                timed_deadline_from_bucket(u8::try_from(idx).unwrap_or(u8::MAX)),
            );
            total_injected = total_injected.saturating_add(1);
        }

        while dispatched.len() < total_injected {
            let Some(task) = worker.next_task() else {
                break;
            };
            assert!(
                !dispatched.contains(&task),
                "adaptive governor promoted {task:?} into a duplicate-dispatch loop"
            );
            dispatched.push(task);
        }

        assert!(
            worker.preemption_metrics().adaptive_current_limit >= 1,
            "adaptive governor budget must stay positive"
        );
    }

    assert_eq!(
        dispatched.len(),
        total_injected,
        "adaptive governor should drain every injected arrival without duplication"
    );
    for _ in 0..3 {
        assert_eq!(
            worker.next_task(),
            None,
            "adaptive governor must terminate after draining arbitrary arrival bursts"
        );
    }
    assert!(
        worker.preemption_metrics().adaptive_current_limit >= 1,
        "adaptive governor budget must remain positive after drain"
    );
}

// Main fuzzing target for three-lane scheduler decision arbiter.
fuzz_target!(|input: DecisionArbiterInput| {
    // Convert fuzz inputs to real types
    let weights = PotentialWeights::from(input.weights);
    let base_time = Time::from_nanos(1_000_000_000); // 1 second epoch
    let ready_queue_depth = input
        .scheduler_context
        .queue_depths
        .global_ready
        .saturating_add(input.scheduler_context.queue_depths.local_ready);

    let snapshots: Vec<StateSnapshot> = input
        .state_snapshots
        .iter()
        .map(|s| s.to_state_snapshot(base_time, ready_queue_depth))
        .collect();

    if snapshots.is_empty() {
        return; // Nothing to test
    }

    // Test 1: Decision determinism
    if input.environment.consistency_context.test_determinism {
        assert!(
            test_decision_determinism(&weights, &snapshots),
            "Decision arbiter should be deterministic for identical inputs"
        );
    }

    // Test 2: Governor suggestion generation
    let governor = LyapunovGovernor::new(weights);
    for snapshot in &snapshots {
        match governor.suggest(snapshot) {
            SchedulingSuggestion::DrainObligations
            | SchedulingSuggestion::DrainRegions
            | SchedulingSuggestion::MeetDeadlines
            | SchedulingSuggestion::NoPreference => {}
        }
    }

    // Test 3: Real scheduler no-starvation invariant under arbitrary lane mixes.
    assert_scheduler_fairness(&input.workload, &input.state_snapshots[0]);

    // Test 4: Timed lane preserves stable EDF order under arbitrary deadlines
    // and arrival order.
    assert_timed_lane_edf_order(&input.workload);

    // Test 5: Missed-deadline promotion collapses to a single cancel observation.
    assert_deadline_miss_promotion_once(&input.deadline_promotion);

    // Test 6: Monotone deadlines preserve EDF-equivalent order across
    // cancel-lane promotion boundaries.
    assert_monotone_deadlines_preserve_edf_under_promotion(&input.deadline_promotion);

    // Test 7: All-zero adaptive reward traces must keep discounted arm masses
    // finite and strictly positive.
    assert_zero_reward_policy_trace(&input.zero_reward_trace);

    // Test 8: Shutdown must wake an in-flight reactor leader and let workers
    // exit without hanging.
    assert_reactor_shutdown_handshake(&input.reactor_shutdown);

    // Test 9: Concurrent steals across multiple victims must never surface the
    // same task twice.
    assert_concurrent_multi_victim_steal_no_double_steal(&input.concurrent_multi_victim_steal);

    // Test 10: Cancel-mask state propagates into scheduler snapshots without
    // becoming runnable phantom work.
    assert_cancel_mask_propagation(&input.workload, &input.state_snapshots[0]);

    // Test 11: Adaptive cancel-streak governor stays bounded and terminates.
    assert_adaptive_budget_governor(&input.adaptive_budget, &weights);
});
