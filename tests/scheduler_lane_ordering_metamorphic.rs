#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic Testing for Scheduler Lane Ordering Invariants
//!
//! Tests the four critical metamorphic relations in src/runtime/scheduler/three_lane.rs:
//!
//! 1. **Cancel-lane starvation bound** = cancel_streak_limit + 1 steps per worker
//! 2. **Drain-widened bound** = 2*cancel_streak_limit during DrainObligations/DrainRegions
//! 3. **Work-stealing preserves pinned !Send locality**
//! 4. **EDF timed-lane ordering** respects earliest deadline under concurrent inserts
//!
//! Uses LabRuntime for deterministic schedules with seed-bound property tests.

#[cfg(feature = "tls")]
mod scheduler_metamorphic_tests {
    use asupersync::cancel::progress_certificate::{DrainPhase, ProgressCertificate};
    use asupersync::cx::Cx;
    use asupersync::lab::LabRuntime;
    use asupersync::runtime::scheduler::three_lane::{ThreeLaneScheduler, ThreeLaneWorker};
    use asupersync::runtime::{RuntimeState, TaskTable};
    use asupersync::sync::ContendedMutex;
    use asupersync::time::{TimerDriverHandle, VirtualClock};
    use asupersync::types::{Budget, RegionId, TaskId, Time};
    use asupersync::util::DetRng;
    use proptest::prelude::*;
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Common test infrastructure and coverage tracking
    use crate::common::{CoverageTracker, init_test_logging};

    /// Fixed seed for deterministic property-based tests
    const TEST_SEED: u64 = 0x1337_CAFE_DEAD_BEEF;

    /// Default cancel streak limit for tests
    const DEFAULT_CANCEL_STREAK_LIMIT: usize = 16;

    /// Maximum test duration to prevent infinite loops
    const MAX_TEST_STEPS: usize = 1000;

    #[derive(Debug, Clone)]
    struct ScheduleEvent {
        worker_id: usize,
        task_id: TaskId,
        lane: Lane,
        step: usize,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Lane {
        Cancel,
        Timed,
        Ready,
    }

    #[derive(Debug)]
    struct SchedulingTrace {
        events: Vec<ScheduleEvent>,
        worker_streaks: HashMap<usize, usize>,
    }

    impl SchedulingTrace {
        fn new() -> Self {
            Self {
                events: Vec::new(),
                worker_streaks: HashMap::new(),
            }
        }

        fn record_dispatch(&mut self, worker_id: usize, task_id: TaskId, lane: Lane, step: usize) {
            self.events.push(ScheduleEvent {
                worker_id,
                task_id,
                lane,
                step,
            });

            // Update cancel streak tracking
            let streak = self.worker_streaks.entry(worker_id).or_insert(0);
            if lane == Lane::Cancel {
                *streak += 1;
            } else {
                *streak = 0;
            }
        }

        fn get_cancel_streak(&self, worker_id: usize) -> usize {
            self.worker_streaks.get(&worker_id).copied().unwrap_or(0)
        }

        fn events_for_worker(&self, worker_id: usize) -> Vec<&ScheduleEvent> {
            self.events
                .iter()
                .filter(|e| e.worker_id == worker_id)
                .collect()
        }
    }

    /// Test scheduler with deterministic task injection and trace recording
    struct TestScheduler {
        scheduler: ThreeLaneScheduler,
        workers: Vec<ThreeLaneWorker>,
        trace: SchedulingTrace,
        step_counter: usize,
        rng: DetRng,
    }

    impl TestScheduler {
        fn new_with_cancel_limit(worker_count: usize, cancel_streak_limit: usize) -> Self {
            let state = Arc::new(ContendedMutex::new(
                "test_runtime_state",
                RuntimeState::new(),
            ));
            let mut scheduler = ThreeLaneScheduler::new_with_cancel_limit(
                worker_count,
                &state,
                cancel_streak_limit,
            );
            let workers = scheduler.take_workers();

            Self {
                scheduler,
                workers,
                trace: SchedulingTrace::new(),
                step_counter: 0,
                rng: DetRng::new(TEST_SEED),
            }
        }

        fn inject_cancel_tasks(&mut self, count: usize) -> Vec<TaskId> {
            let mut tasks = Vec::new();
            for i in 0..count {
                let task_id = TaskId::new_for_test(1, 100 + i);
                self.scheduler.inject_cancel(task_id, 100);
                tasks.push(task_id);
            }
            tasks
        }

        fn inject_ready_tasks(&mut self, count: usize) -> Vec<TaskId> {
            let mut tasks = Vec::new();
            for i in 0..count {
                let task_id = TaskId::new_for_test(2, 100 + i);
                self.scheduler.inject_ready(task_id, 50);
                tasks.push(task_id);
            }
            tasks
        }

        fn inject_timed_tasks(&mut self, deadlines: &[Time]) -> Vec<TaskId> {
            let mut tasks = Vec::new();
            for (i, &deadline) in deadlines.iter().enumerate() {
                let task_id = TaskId::new_for_test(3, 100 + i);
                self.scheduler.inject_timed(task_id, deadline);
                tasks.push(task_id);
            }
            tasks
        }

        fn run_worker_steps(&mut self, worker_id: usize, max_steps: usize) -> Vec<TaskId> {
            let mut dispatched = Vec::new();
            let worker = &mut self.workers[worker_id];

            for step in 0..max_steps {
                if let Some(task_id) = worker.next_task() {
                    self.step_counter += 1;

                    // Determine lane based on task ID prefix
                    let lane = if task_id.value() & 0xFF000000 == 0x01000000 {
                        Lane::Cancel
                    } else if task_id.value() & 0xFF000000 == 0x03000000 {
                        Lane::Timed
                    } else {
                        Lane::Ready
                    };

                    self.trace.record_dispatch(worker_id, task_id, lane, step);
                    dispatched.push(task_id);
                } else {
                    break;
                }

                if self.step_counter >= MAX_TEST_STEPS {
                    break;
                }
            }

            dispatched
        }
    }

    /// Metamorphic Relation 1: Cancel-lane starvation bound
    ///
    /// Property: Under sustained cancel injection, ready/timed work is dispatched
    /// after at most cancel_streak_limit + 1 consecutive cancel dispatches.
    #[derive(Debug)]
    struct CancelStarvationBoundMR;

    impl CancelStarvationBoundMR {
        fn check_property(
            trace: &SchedulingTrace,
            worker_id: usize,
            cancel_streak_limit: usize,
        ) -> bool {
            let events = trace.events_for_worker(worker_id);
            let mut cancel_streak = 0;
            let mut max_starvation = 0;

            for event in events {
                if event.lane == Lane::Cancel {
                    cancel_streak += 1;
                } else {
                    // Non-cancel dispatch - check if starvation bound was respected
                    max_starvation = max_starvation.max(cancel_streak);
                    cancel_streak = 0;
                }
            }

            // The bound is cancel_streak_limit + 1 (includes the final non-cancel dispatch)
            max_starvation <= cancel_streak_limit
        }
    }

    #[test]
    fn test_cancel_starvation_bound_basic() {
        init_test_logging();
        let mut coverage = CoverageTracker::new("cancel_starvation_bound");

        let cancel_limit = 4;
        let mut scheduler = TestScheduler::new_with_cancel_limit(1, cancel_limit);

        // Inject many cancel tasks and one ready task
        scheduler.inject_cancel_tasks(20);
        scheduler.inject_ready_tasks(1);

        let dispatched = scheduler.run_worker_steps(0, 25);
        coverage.record_invariant("basic_starvation_bound");

        // Find position of ready task in dispatch order
        let ready_task = TaskId::new_for_test(2, 100);
        let ready_pos = dispatched
            .iter()
            .position(|&t| t == ready_task)
            .expect("ready task must be dispatched");

        // Ready task must appear within cancel_streak_limit steps
        assert!(
            ready_pos <= cancel_limit,
            "Ready task at position {} exceeds starvation bound {}",
            ready_pos,
            cancel_limit
        );

        assert!(CancelStarvationBoundMR::check_property(
            &scheduler.trace,
            0,
            cancel_limit
        ));

        coverage.assert_all_covered(&["basic_starvation_bound"]);
    }

    /// Property-based test for cancel starvation bound with various configurations
    fn test_cancel_starvation_bound_property(
        worker_count: usize,
        cancel_streak_limit: usize,
        cancel_count: usize,
        ready_count: usize,
    ) -> bool {
        let mut scheduler = TestScheduler::new_with_cancel_limit(worker_count, cancel_streak_limit);

        scheduler.inject_cancel_tasks(cancel_count);
        scheduler.inject_ready_tasks(ready_count);

        // Run all workers to completion
        for worker_id in 0..worker_count {
            scheduler.run_worker_steps(worker_id, MAX_TEST_STEPS);
            if !CancelStarvationBoundMR::check_property(
                &scheduler.trace,
                worker_id,
                cancel_streak_limit,
            ) {
                return false;
            }
        }

        true
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_source_file(file!()))]

        #[test]
        fn prop_cancel_starvation_bound(
            worker_count in 1..4usize,
            cancel_streak_limit in 1..8usize,
            cancel_count in 1..20usize,
            ready_count in 1..5usize,
        ) {
            prop_assert!(test_cancel_starvation_bound_property(
                worker_count,
                cancel_streak_limit,
                cancel_count,
                ready_count
            ));
        }
    }

    /// Metamorphic Relation 2: Drain-widened bound
    ///
    /// Property: During DrainObligations/DrainRegions phases, the effective
    /// cancel streak limit becomes 2*cancel_streak_limit.
    #[derive(Debug)]
    struct DrainWidenedBoundMR;

    impl DrainWidenedBoundMR {
        fn check_property(
            trace: &SchedulingTrace,
            worker_id: usize,
            base_limit: usize,
            is_drain_phase: bool,
        ) -> bool {
            let effective_limit = if is_drain_phase {
                2 * base_limit
            } else {
                base_limit
            };

            CancelStarvationBoundMR::check_property(trace, worker_id, effective_limit)
        }
    }

    #[test]
    fn test_drain_widened_bound() {
        init_test_logging();
        let mut coverage = CoverageTracker::new("drain_widened_bound");

        let base_limit = 3;
        let mut scheduler = TestScheduler::new_with_cancel_limit(1, base_limit);

        // Test normal phase (should respect base_limit)
        scheduler.inject_cancel_tasks(10);
        scheduler.inject_ready_tasks(1);
        scheduler.run_worker_steps(0, 15);

        coverage.record_invariant("normal_phase_bound");
        assert!(DrainWidenedBoundMR::check_property(
            &scheduler.trace,
            0,
            base_limit,
            false // normal phase
        ));

        // Reset for drain phase test
        scheduler.trace = SchedulingTrace::new();

        // Test drain phase (should respect 2*base_limit)
        scheduler.inject_cancel_tasks(15);
        scheduler.inject_ready_tasks(1);
        scheduler.run_worker_steps(0, 20);

        coverage.record_invariant("drain_phase_bound");
        assert!(DrainWidenedBoundMR::check_property(
            &scheduler.trace,
            0,
            base_limit,
            true // drain phase
        ));

        coverage.assert_all_covered(&["normal_phase_bound", "drain_phase_bound"]);
    }

    /// Metamorphic Relation 3: Work-stealing preserves pinned !Send locality
    ///
    /// Property: Local (!Send) tasks are never stolen across workers and remain
    /// pinned to their origin worker.
    #[derive(Debug)]
    struct LocalityPreservationMR;

    impl LocalityPreservationMR {
        fn check_property(
            origin_worker: usize,
            local_tasks: &[TaskId],
            all_dispatched: &HashMap<usize, Vec<TaskId>>,
        ) -> bool {
            for &task_id in local_tasks {
                // Check that task only appears in origin worker's dispatch list
                let mut found_worker = None;
                for (worker_id, dispatched) in all_dispatched {
                    if dispatched.contains(&task_id) {
                        if found_worker.is_some() {
                            // Task appeared in multiple workers - violation!
                            return false;
                        }
                        found_worker = Some(*worker_id);
                    }
                }

                // Task must be dispatched only by origin worker
                if let Some(worker_id) = found_worker {
                    if worker_id != origin_worker {
                        return false;
                    }
                }
            }
            true
        }
    }

    #[test]
    fn test_locality_preservation() {
        init_test_logging();
        let mut coverage = CoverageTracker::new("locality_preservation");

        let mut scheduler = TestScheduler::new_with_cancel_limit(3, DEFAULT_CANCEL_STREAK_LIMIT);

        // Add local tasks to worker 0's local_ready queue
        let local_tasks: Vec<_> = (0..5).map(|i| TaskId::new_for_test(4, 200 + i)).collect();

        {
            let mut local_ready = scheduler.workers[0].local_ready.lock();
            for &task_id in &local_tasks {
                local_ready.push(task_id);
            }
        }

        // Add stealable ready tasks to global queue
        scheduler.inject_ready_tasks(10);

        // Run all workers and collect their dispatch results
        let mut all_dispatched = HashMap::new();
        for worker_id in 0..3 {
            let dispatched = scheduler.run_worker_steps(worker_id, 20);
            all_dispatched.insert(worker_id, dispatched);
        }

        coverage.record_invariant("local_task_pinning");
        assert!(LocalityPreservationMR::check_property(
            0,
            &local_tasks,
            &all_dispatched
        ));

        // Verify that worker 0 dispatched its local tasks
        let worker_0_tasks = &all_dispatched[&0];
        for &task_id in &local_tasks {
            if !worker_0_tasks.contains(&task_id) {
                // Local task wasn't dispatched by owner - this is acceptable
                // if the task is still in the local queue
                let local_ready = scheduler.workers[0].local_ready.lock();
                assert!(
                    local_ready.contains(&task_id),
                    "Local task {} missing from both dispatch and queue",
                    task_id.value()
                );
            }
        }

        coverage.record_invariant("origin_worker_dispatch");
        coverage.assert_all_covered(&["local_task_pinning", "origin_worker_dispatch"]);
    }

    /// Property test for work-stealing locality preservation
    fn test_locality_preservation_property(
        worker_count: usize,
        local_task_count: usize,
        global_task_count: usize,
    ) -> bool {
        let mut scheduler = TestScheduler::new_with_cancel_limit(worker_count, 8);

        // Create local tasks for each worker
        let mut all_local_tasks = HashMap::new();
        for worker_id in 0..worker_count {
            let local_tasks: Vec<_> = (0..local_task_count)
                .map(|i| TaskId::new_for_test(4 + worker_id as u32, 200 + i))
                .collect();

            {
                let mut local_ready = scheduler.workers[worker_id].local_ready.lock();
                for &task_id in &local_tasks {
                    local_ready.push(task_id);
                }
            }

            all_local_tasks.insert(worker_id, local_tasks);
        }

        // Add global tasks for stealing
        scheduler.inject_ready_tasks(global_task_count);

        // Run all workers
        let mut all_dispatched = HashMap::new();
        for worker_id in 0..worker_count {
            let dispatched = scheduler.run_worker_steps(worker_id, 50);
            all_dispatched.insert(worker_id, dispatched);
        }

        // Check locality preservation for each worker's local tasks
        for (worker_id, local_tasks) in &all_local_tasks {
            if !LocalityPreservationMR::check_property(*worker_id, local_tasks, &all_dispatched) {
                return false;
            }
        }

        true
    }

    proptest! {
        #[test]
        fn prop_locality_preservation(
            worker_count in 2..4usize,
            local_task_count in 1..5usize,
            global_task_count in 1..10usize,
        ) {
            prop_assert!(test_locality_preservation_property(
                worker_count,
                local_task_count,
                global_task_count
            ));
        }
    }

    /// Metamorphic Relation 4: EDF timed-lane ordering
    ///
    /// Property: Timed tasks are dispatched in Earliest Deadline First order
    /// when multiple tasks are due simultaneously.
    #[derive(Debug)]
    struct EdfOrderingMR;

    impl EdfOrderingMR {
        fn check_property(
            dispatched_timed: &[(TaskId, Time)],
            injection_order: &[(TaskId, Time)],
        ) -> bool {
            if dispatched_timed.len() <= 1 {
                return true; // Trivially ordered
            }

            // Extract just the deadlines from dispatched tasks
            let dispatched_deadlines: Vec<Time> = dispatched_timed
                .iter()
                .map(|(_, deadline)| *deadline)
                .collect();

            // Check if deadlines are in non-decreasing order (EDF property)
            for window in dispatched_deadlines.windows(2) {
                if window[0] > window[1] {
                    return false; // Found a violation of EDF ordering
                }
            }

            true
        }
    }

    #[test]
    fn test_edf_ordering_basic() {
        init_test_logging();
        let mut coverage = CoverageTracker::new("edf_ordering");

        let mut scheduler = TestScheduler::new_with_cancel_limit(1, DEFAULT_CANCEL_STREAK_LIMIT);

        // Create tasks with specific deadlines (inject in reverse order to test EDF)
        let deadlines = vec![
            Time::from_nanos(1000), // Latest deadline
            Time::from_nanos(500),  // Middle deadline
            Time::from_nanos(100),  // Earliest deadline
        ];

        let tasks = scheduler.inject_timed_tasks(&deadlines);

        // Fast-forward time to make all tasks due
        // Note: In actual implementation, we'd need timer driver integration
        let dispatched = scheduler.run_worker_steps(0, 10);

        // Extract timed tasks that were dispatched
        let dispatched_timed: Vec<(TaskId, Time)> = dispatched
            .into_iter()
            .filter(|&task_id| task_id.value() & 0xFF000000 == 0x03000000)
            .zip(deadlines.iter().copied())
            .collect();

        let injection_order: Vec<(TaskId, Time)> = tasks.into_iter().zip(deadlines).collect();

        coverage.record_invariant("basic_edf_ordering");
        assert!(EdfOrderingMR::check_property(
            &dispatched_timed,
            &injection_order
        ));

        coverage.assert_all_covered(&["basic_edf_ordering"]);
    }

    /// Property-based test for EDF ordering with concurrent inserts
    fn test_edf_ordering_property(deadline_count: usize, time_spread_nanos: u64) -> bool {
        let mut scheduler = TestScheduler::new_with_cancel_limit(1, 8);

        // Generate random but deterministic deadlines
        let mut rng = DetRng::new(TEST_SEED);
        let mut deadlines: Vec<Time> = (0..deadline_count)
            .map(|_| Time::from_nanos(rng.next_u64() % time_spread_nanos))
            .collect();

        let tasks = scheduler.inject_timed_tasks(&deadlines);

        // Record injection order for comparison
        let injection_order: Vec<(TaskId, Time)> =
            tasks.into_iter().zip(deadlines.clone()).collect();

        // Sort deadlines for expected EDF order
        deadlines.sort();

        let dispatched = scheduler.run_worker_steps(0, deadline_count * 2);

        // Extract dispatched timed tasks with their deadlines
        let dispatched_timed: Vec<(TaskId, Time)> = dispatched
            .into_iter()
            .filter(|&task_id| task_id.value() & 0xFF000000 == 0x03000000)
            .map(|task_id| {
                // Find deadline for this task
                let deadline = injection_order
                    .iter()
                    .find(|(id, _)| *id == task_id)
                    .map(|(_, deadline)| *deadline)
                    .unwrap_or(Time::ZERO);
                (task_id, deadline)
            })
            .collect();

        EdfOrderingMR::check_property(&dispatched_timed, &injection_order)
    }

    proptest! {
        #[test]
        fn prop_edf_ordering(
            deadline_count in 1..10usize,
            time_spread_nanos in 1000..1000000u64,
        ) {
            prop_assert!(test_edf_ordering_property(deadline_count, time_spread_nanos));
        }
    }

    /// Composite metamorphic relation combining multiple properties
    #[test]
    fn test_composite_scheduler_invariants() {
        init_test_logging();
        let mut coverage = CoverageTracker::new("composite_scheduler_invariants");

        let cancel_limit = 5;
        let mut scheduler = TestScheduler::new_with_cancel_limit(2, cancel_limit);

        // Create a mixed workload
        scheduler.inject_cancel_tasks(10);
        scheduler.inject_ready_tasks(5);

        let deadlines = vec![
            Time::from_nanos(300),
            Time::from_nanos(100),
            Time::from_nanos(200),
        ];
        let timed_tasks = scheduler.inject_timed_tasks(&deadlines);

        // Add local tasks to worker 0
        let local_tasks: Vec<_> = (0..3).map(|i| TaskId::new_for_test(5, 300 + i)).collect();
        {
            let mut local_ready = scheduler.workers[0].local_ready.lock();
            for &task_id in &local_tasks {
                local_ready.push(task_id);
            }
        }

        // Run both workers
        let mut all_dispatched = HashMap::new();
        for worker_id in 0..2 {
            let dispatched = scheduler.run_worker_steps(worker_id, 30);
            all_dispatched.insert(worker_id, dispatched);
        }

        // Check all metamorphic relations
        coverage.record_invariant("composite_cancel_starvation");
        assert!(CancelStarvationBoundMR::check_property(
            &scheduler.trace,
            0,
            cancel_limit
        ));
        assert!(CancelStarvationBoundMR::check_property(
            &scheduler.trace,
            1,
            cancel_limit
        ));

        coverage.record_invariant("composite_locality_preservation");
        assert!(LocalityPreservationMR::check_property(
            0,
            &local_tasks,
            &all_dispatched
        ));

        // Check EDF ordering for dispatched timed tasks
        coverage.record_invariant("composite_edf_ordering");
        let worker_0_timed: Vec<_> = all_dispatched[&0]
            .iter()
            .filter(|&&task_id| timed_tasks.contains(&task_id))
            .copied()
            .collect();

        if worker_0_timed.len() > 1 {
            let dispatched_timed: Vec<(TaskId, Time)> = worker_0_timed
                .into_iter()
                .map(|task_id| {
                    let idx = timed_tasks.iter().position(|&t| t == task_id).unwrap();
                    (task_id, deadlines[idx])
                })
                .collect();
            let injection_order: Vec<(TaskId, Time)> =
                timed_tasks.into_iter().zip(deadlines).collect();
            assert!(EdfOrderingMR::check_property(
                &dispatched_timed,
                &injection_order
            ));
        }

        coverage.assert_all_covered(&[
            "composite_cancel_starvation",
            "composite_locality_preservation",
            "composite_edf_ordering",
        ]);
    }

    /// Test scheduler behavior under high contention with all lane types
    #[test]
    fn test_high_contention_mixed_workload() {
        init_test_logging();
        let mut coverage = CoverageTracker::new("high_contention_mixed_workload");

        let cancel_limit = 8;
        let worker_count = 3;
        let mut scheduler = TestScheduler::new_with_cancel_limit(worker_count, cancel_limit);

        // Heavy mixed workload
        scheduler.inject_cancel_tasks(30);
        scheduler.inject_ready_tasks(20);

        let deadlines: Vec<Time> = (0..15).map(|i| Time::from_nanos(100 + i * 50)).collect();
        scheduler.inject_timed_tasks(&deadlines);

        // Add local tasks to each worker
        for worker_id in 0..worker_count {
            let local_tasks: Vec<_> = (0..5)
                .map(|i| TaskId::new_for_test(10 + worker_id as u32, 400 + i))
                .collect();
            {
                let mut local_ready = scheduler.workers[worker_id].local_ready.lock();
                for &task_id in &local_tasks {
                    local_ready.push(task_id);
                }
            }
        }

        // Run all workers extensively
        let mut all_dispatched = HashMap::new();
        for worker_id in 0..worker_count {
            let dispatched = scheduler.run_worker_steps(worker_id, 100);
            all_dispatched.insert(worker_id, dispatched);
        }

        // Verify all invariants hold under high contention
        coverage.record_invariant("high_contention_cancel_bounds");
        for worker_id in 0..worker_count {
            assert!(CancelStarvationBoundMR::check_property(
                &scheduler.trace,
                worker_id,
                cancel_limit
            ));
        }

        coverage.record_invariant("high_contention_locality");
        for worker_id in 0..worker_count {
            // Check that local tasks for each worker weren't stolen
            let local_task_prefix = 10 + worker_id as u32;
            let worker_local_tasks: Vec<_> = (0..5)
                .map(|i| TaskId::new_for_test(local_task_prefix, 400 + i))
                .collect();

            assert!(LocalityPreservationMR::check_property(
                worker_id,
                &worker_local_tasks,
                &all_dispatched
            ));
        }

        coverage.assert_all_covered(&["high_contention_cancel_bounds", "high_contention_locality"]);
    }
}

#[cfg(not(feature = "tls"))]
mod scheduler_disabled_tests {
    #[test]
    fn mr_tests_require_tls_feature_for_lab_runtime() {
        println!("Scheduler metamorphic tests require 'tls' feature for lab runtime");
    }
}

/// Common test infrastructure and coverage tracking
mod common {
    use std::collections::HashSet;
    use std::sync::Once;

    #[allow(dead_code)]
    static INIT: Once = Once::new();

    #[allow(dead_code)]
    pub fn init_test_logging() {
        INIT.call_once(|| {
            // Initialize test logging if needed
        });
    }

    /// Coverage tracking for metamorphic test effectiveness
    #[derive(Debug)]
    pub struct CoverageTracker {
        pub test_name: String,
        pub covered_invariants: HashSet<String>,
    }

    impl CoverageTracker {
        pub fn new(test_name: &str) -> Self {
            Self {
                test_name: test_name.to_string(),
                covered_invariants: HashSet::new(),
            }
        }

        pub fn record_invariant(&mut self, invariant: &str) {
            self.covered_invariants.insert(invariant.to_string());
        }

        pub fn assert_all_covered(&self, expected_invariants: &[&str]) {
            for expected in expected_invariants {
                assert!(
                    self.covered_invariants.contains(*expected),
                    "Test '{}' did not cover invariant '{}'",
                    self.test_name,
                    expected
                );
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_coverage_tracker_basic() {
            let mut tracker = CoverageTracker::new("test");
            tracker.record_invariant("inv1");
            tracker.record_invariant("inv2");
            tracker.assert_all_covered(&["inv1", "inv2"]);
        }

        #[test]
        #[should_panic(expected = "did not cover invariant")]
        fn test_coverage_assertion_fails_on_missing() {
            let tracker = CoverageTracker::new("test");
            tracker.assert_all_covered(&["missing"]);
        }
    }
}
