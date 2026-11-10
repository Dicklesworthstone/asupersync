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
fn exact_inventory_rejects_bounded_window_overflow() {
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
fn exact_inventory_matches_normal_cancel_promotions_and_repeated_cancels() {
    fn build() -> Scheduler {
        let mut scheduler = Scheduler::with_capacity(1);
        scheduler.schedule(task(1), 100);
        scheduler.schedule_timed(task(2), Time::ZERO);
        scheduler.schedule(task(3), 0);
        scheduler.move_to_cancel_lane(task(1), 1);
        scheduler.move_to_cancel_lane(task(1), 9);
        scheduler.move_to_cancel_lane(task(1), 9);
        scheduler.move_to_cancel_lane(task(2), 9);
        scheduler
    }

    let mut scheduler = build();
    let before = format!("{scheduler:?}");
    let choices = scheduler.exact_exploration_choices(Time::ZERO, true, 8).unwrap();
    assert_eq!(choices, vec![(task(1), DispatchLane::Cancel), (task(2), DispatchLane::Cancel)]);
    assert_eq!(format!("{scheduler:?}"), before, "inventory must not prune promotion copies");

    // Compare the admitted set with the actual ordinary selector, including
    // each duplicate's physical RNG slot and the lower-priority re-cancel.
    let ordinary: std::collections::BTreeSet<_> = (0..6)
        .map(|hint| {
            let (task, lane) = build().pop_with_lane_if_due(hint, Time::ZERO).unwrap();
            assert_eq!(lane, DispatchLane::Cancel);
            task
        })
        .collect();
    assert_eq!(ordinary, choices.iter().map(|(task, _)| *task).collect());

    for (selected, lane) in choices {
        scheduler = build();
        scheduler.take_exact(selected, lane, Time::ZERO).unwrap();
        let remaining = if selected == task(1) { task(2) } else { task(1) };
        assert_eq!(
            scheduler.exact_exploration_choices(Time::ZERO, true, 8).unwrap(),
            vec![(remaining, DispatchLane::Cancel)]
        );
        scheduler.take_exact(remaining, DispatchLane::Cancel, Time::ZERO).unwrap();
        assert_eq!(
            scheduler.exact_exploration_choices(Time::ZERO, true, 8).unwrap(),
            vec![(task(3), DispatchLane::Ready)]
        );
        assert_eq!(scheduler.len(), 1, "retired promotion copies must not become fresh work");
    }
}

#[test]
fn exact_inventory_preserves_cancel_promotion_refusal_boundaries() {
    let mut promoted = Scheduler::new();
    promoted.schedule(task(1), 0);
    promoted.move_to_cancel_lane(task(1), 0);
    let before = format!("{promoted:?}");
    assert_eq!(
        promoted.exact_exploration_choices(Time::ZERO, false, 8),
        Err("cancel promotions in a non-cancel frontier are unsupported")
    );
    assert_eq!(format!("{promoted:?}"), before, "streak refusal must not alter a queue");
    assert_eq!(
        promoted.pop_non_cancel_with_rng_if_due(0, Time::ZERO),
        Some((task(1), DispatchLane::Ready)),
        "ordinary streak-limited selection really can claim the old lane"
    );
    assert!(promoted.exact_exploration_choices(Time::ZERO, true, 8).is_err(),
        "a stale post-dispatch cancel entry is still unsupported");

    let mut duplicate = Scheduler::new();
    duplicate.schedule(task(2), 0);
    duplicate.ready_lane.push(SchedulerEntry { task: task(2), priority: 0, generation: 1 });
    duplicate.move_to_cancel_lane(task(2), 0);
    assert_eq!(
        duplicate.exact_exploration_choices(Time::ZERO, true, 8),
        Err("duplicate non-cancel scheduler entries are unsupported")
    );
}

#[test]
fn exact_inventory_counts_physical_cancel_entries_before_deduplication() {
    let mut scheduler = Scheduler::with_capacity(1);
    let window = scheduler.scratch_entries.capacity();
    scheduler.schedule(task(1), 0);
    for _ in 0..=window {
        scheduler.move_to_cancel_lane(task(1), 1);
    }
    let before = format!("{scheduler:?}");
    assert_eq!(
        scheduler.exact_exploration_choices(Time::ZERO, true, window + 2),
        Err("scheduler tie group exceeds the legacy selection window"),
        "one distinct task does not authorize widening its physical tie group"
    );
    assert!(scheduler.exact_exploration_choices(Time::ZERO, true, window + 1).is_err(),
        "inventory also charges the lower-lane promotion copy");
    assert_eq!(format!("{scheduler:?}"), before);
}

#[test]
fn exact_inventory_charges_discarded_copies_when_new_work_arrives() {
    let mut scheduler = Scheduler::with_capacity(1);
    let window = scheduler.scratch_entries.capacity().min(scheduler.scratch_timed.capacity());
    scheduler.schedule(task(0), 0);
    scheduler.move_to_cancel_lane(task(0), 1);
    scheduler.validate_exact_exploration_copy_bound(0, 2).unwrap();
    let discarded = scheduler.exact_exploration_discarded_copies(task(0));
    assert_eq!(discarded, 1);
    scheduler.take_exact(task(0), DispatchLane::Cancel, Time::ZERO).unwrap();
    for index in 1..=window {
        scheduler.schedule(task(index as u32), 0);
    }
    assert_eq!(scheduler.exact_exploration_choices(Time::ZERO, true, window).unwrap().len(), window);
    assert_eq!(
        scheduler.validate_exact_exploration_copy_bound(discarded, window + 1),
        Err("cancel-copy inventory exceeds the legacy selection window"),
        "removed copies must not widen a later physical selection window"
    );
    assert_eq!(
        scheduler.validate_exact_exploration_copy_bound(discarded, window),
        Err("discarded cancel copies exceed the inventory bound")
    );
    scheduler.remove(task(window as u32));
    scheduler.validate_exact_exploration_copy_bound(discarded, window).unwrap();
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

    scheduler.schedule(new, 0);
    scheduler.move_to_cancel_lane(old, 1);
    scheduler.move_to_cancel_lane(new, 1);
    scheduler.move_to_cancel_lane(new, 1);
    assert_eq!(
        scheduler.exact_exploration_choices(Time::ZERO, true, 5).unwrap(),
        vec![(old, DispatchLane::Cancel), (new, DispatchLane::Cancel)]
    );
    scheduler.take_exact(new, DispatchLane::Cancel, Time::ZERO).unwrap();
    assert_eq!(
        scheduler.exact_exploration_choices(Time::ZERO, true, 2).unwrap(),
        vec![(old, DispatchLane::Cancel)],
        "retiring a new generation must retain the old generation's promotion"
    );
}
