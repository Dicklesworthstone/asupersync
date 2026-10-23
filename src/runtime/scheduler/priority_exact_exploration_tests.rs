#![allow(clippy::pedantic, clippy::nursery)]

use super::*;
use crate::util::ArenaIndex;

fn task(index: u32) -> TaskId {
    TaskId::from_arena(ArenaIndex::new(index, 0))
}

#[test]
fn exact_inventory_preserves_priority_deadline_and_cancel_streak_policy() {
    let mut scheduler = Scheduler::with_capacity(1);
    scheduler.schedule(task(1), 10);
    scheduler.schedule(task(2), 10);
    scheduler.schedule(task(3), 1);
    scheduler.schedule_timed(task(4), Time::from_nanos(20));
    scheduler.schedule_timed(task(5), Time::from_nanos(20));
    scheduler.schedule_timed(task(6), Time::from_nanos(30));
    scheduler.schedule_cancel(task(7), 0);

    assert_eq!(
        scheduler.exact_exploration_choices(Time::ZERO, true, 16).unwrap(),
        vec![(task(7), DispatchLane::Cancel)]
    );
    assert_eq!(
        scheduler.exact_exploration_choices(Time::ZERO, false, 16).unwrap(),
        vec![(task(1), DispatchLane::Ready), (task(2), DispatchLane::Ready)]
    );
    assert_eq!(
        scheduler
            .exact_exploration_choices(Time::from_nanos(20), false, 16)
            .unwrap(),
        vec![(task(4), DispatchLane::Timed), (task(5), DispatchLane::Timed)]
    );
    assert_eq!(scheduler.len(), 7, "inventory must not mutate scheduling state");

    let mut cancel_only = Scheduler::new();
    cancel_only.schedule_cancel(task(8), 1);
    assert_eq!(
        cancel_only.exact_exploration_choices(Time::ZERO, false, 1).unwrap(),
        vec![(task(8), DispatchLane::Cancel)],
        "exhausted streak still falls back to cancel when no other lane can run"
    );
}

#[test]
fn exact_inventory_matches_every_normal_rng_choice_in_the_admitted_frontier() {
    let build = || {
        let mut scheduler = Scheduler::with_capacity(1);
        scheduler.schedule(task(3), 10);
        scheduler.schedule(task(1), 10);
        scheduler.schedule(task(2), 1);
        scheduler
    };
    let expected: std::collections::BTreeSet<_> = build()
        .exact_exploration_choices(Time::ZERO, true, 3)
        .unwrap()
        .into_iter()
        .map(|(task, _)| task)
        .collect();
    let actual: std::collections::BTreeSet<_> = (0..8)
        .map(|hint| build().pop_with_lane_if_due(hint, Time::ZERO).unwrap().0)
        .collect();
    assert_eq!(actual, expected);
    assert_eq!(actual, std::collections::BTreeSet::from([task(1), task(3)]));
}

#[test]
fn exact_inventory_rejects_lazy_promotions_and_bounded_window_overflow() {
    let mut promoted = Scheduler::new();
    promoted.schedule(task(1), 0);
    promoted.move_to_cancel_lane(task(1), 0);
    assert!(promoted.exact_exploration_choices(Time::ZERO, true, 8).is_err());
    assert_eq!(promoted.pop(), Some(task(1)), "rejection did not alter the queue");

    let mut wide = Scheduler::with_capacity(1);
    let window = wide.scratch_entries.capacity();
    for index in 0..=window {
        wide.schedule(task(index as u32), 0);
    }
    assert!(wide.exact_exploration_choices(Time::ZERO, true, window + 1).is_err());
    assert!(wide.exact_exploration_choices(Time::ZERO, true, 1).is_err());
    assert_eq!(wide.len(), window + 1);
}

#[test]
fn exact_inventory_keeps_full_task_generations_distinct() {
    let old = TaskId::from_arena(ArenaIndex::new(7, 1));
    let new = TaskId::from_arena(ArenaIndex::new(7, 2));
    let mut scheduler = Scheduler::new();
    scheduler.schedule(old, 0);
    scheduler.schedule(new, 0);
    assert_eq!(
        scheduler.exact_exploration_choices(Time::ZERO, true, 2).unwrap(),
        vec![(old, DispatchLane::Ready), (new, DispatchLane::Ready)]
    );
    scheduler.take_exact(new, DispatchLane::Ready, Time::ZERO).unwrap();
    assert_eq!(
        scheduler.exact_exploration_choices(Time::ZERO, true, 1).unwrap(),
        vec![(old, DispatchLane::Ready)]
    );
}
