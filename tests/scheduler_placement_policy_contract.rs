use asupersync::runtime::scheduler::{LocalQueue, SchedulerPlacementMode, ThreeLaneScheduler};
use asupersync::types::TaskId;

fn scheduler_with_map(worker_to_cohort: &[usize]) -> ThreeLaneScheduler {
    let state = LocalQueue::test_state(16);
    let mut scheduler = ThreeLaneScheduler::new(worker_to_cohort.len(), &state);
    scheduler
        .set_worker_cohort_map(worker_to_cohort)
        .expect("valid worker cohort map should apply");
    scheduler
}

fn push_fast_task(scheduler: &mut ThreeLaneScheduler, worker_id: usize, task: TaskId) {
    scheduler
        .worker_mut_for_test(worker_id)
        .bench_fast_ready_queue()
        .push(task);
}

#[test]
fn locality_first_prefers_same_cohort_before_remote_and_counts_the_steal() {
    let mut scheduler = scheduler_with_map(&[0, 0, 1, 1]);
    let same_cohort_task = TaskId::new_for_test(1, 0);
    let cross_cohort_task = TaskId::new_for_test(2, 0);
    push_fast_task(&mut scheduler, 2, same_cohort_task);
    push_fast_task(&mut scheduler, 0, cross_cohort_task);

    let mut workers = scheduler.take_workers();
    let thief = &mut workers[3];

    assert_eq!(thief.bench_try_steal(), Some(same_cohort_task));
    let counters = thief.steal_locality_counters();
    assert_eq!(counters.preferred_fast_steals, 1);
    assert_eq!(counters.remote_fast_steals, 0);
}

#[test]
fn latency_first_keeps_cohort_preference_but_orders_same_cohort_by_ring_distance() {
    let mut scheduler = scheduler_with_map(&[0, 1, 0, 0, 1, 1]);
    scheduler.set_scheduler_placement_mode(SchedulerPlacementMode::LatencyFirst);

    let lower_worker_id_task = TaskId::new_for_test(3, 0);
    let nearer_task = TaskId::new_for_test(4, 0);
    push_fast_task(&mut scheduler, 0, lower_worker_id_task);
    push_fast_task(&mut scheduler, 3, nearer_task);

    let mut workers = scheduler.take_workers();
    let thief = &mut workers[2];

    assert_eq!(
        thief.bench_try_steal(),
        Some(nearer_task),
        "latency-first should prefer the nearest same-cohort peer over lower worker id"
    );
    let counters = thief.steal_locality_counters();
    assert_eq!(counters.preferred_fast_steals, 1);
    assert_eq!(counters.remote_fast_steals, 0);
}

#[test]
fn throughput_first_allows_remote_first_without_losing_cross_cohort_evidence() {
    let mut scheduler = scheduler_with_map(&[0, 0, 1, 1]);
    scheduler.set_scheduler_placement_mode(SchedulerPlacementMode::ThroughputFirst);

    let same_cohort_task = TaskId::new_for_test(5, 0);
    let cross_cohort_task = TaskId::new_for_test(6, 0);
    push_fast_task(&mut scheduler, 2, same_cohort_task);
    push_fast_task(&mut scheduler, 0, cross_cohort_task);

    let mut workers = scheduler.take_workers();
    let thief = &mut workers[3];

    assert_eq!(thief.bench_try_steal(), Some(cross_cohort_task));
    let counters = thief.steal_locality_counters();
    assert_eq!(counters.remote_fast_steals, 1);
    assert_eq!(counters.preferred_fast_steals, 0);
}
