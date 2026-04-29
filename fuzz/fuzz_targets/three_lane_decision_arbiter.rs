#![no_main]

use std::cmp;
use std::sync::Arc;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::obligation::lyapunov::{
    LyapunovGovernor, PotentialWeights, SchedulingSuggestion, StateSnapshot,
};
use asupersync::record::TaskRecord;
use asupersync::runtime::scheduler::three_lane::ThreeLaneScheduler;
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

    let governor1 = LyapunovGovernor::new(weights.clone());
    let governor2 = LyapunovGovernor::new(weights.clone());

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
                record.request_cancel_with_budget(CancelReason::timeout(), Budget::INFINITE);
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
                record.request_cancel_with_budget(CancelReason::timeout(), Budget::INFINITE);
                let _ = record.acknowledge_cancel();
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
                record.request_cancel_with_budget(CancelReason::timeout(), Budget::INFINITE);
                let _ = record.acknowledge_cancel();
                let _ = record.cleanup_done();
            })
            .expect("finalizing task must exist");
    }
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
    let governor = LyapunovGovernor::new(weights.clone());
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
});
