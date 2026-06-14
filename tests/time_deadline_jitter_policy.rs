use std::time::Duration;

use asupersync::time::{DeadlineJitterPolicy, DeadlineJitterScope};
use asupersync::types::{RegionId, TaskId, Time};
use asupersync::util::ArenaIndex;

fn task(index: u32) -> TaskId {
    TaskId::from_arena(ArenaIndex::new(index, 1))
}

fn region(index: u32) -> RegionId {
    RegionId::from_arena(ArenaIndex::new(index, 1))
}

#[test]
fn disabled_deadline_jitter_preserves_exact_deadline() {
    let policy = DeadlineJitterPolicy::disabled().with_policy_id(7);
    let original = Time::from_secs(30);
    let decision = policy.apply(original, task(11), region(3));

    assert_eq!(decision.policy_id, 7);
    assert_eq!(decision.original_deadline, original);
    assert_eq!(decision.jittered_deadline, original);
    assert_eq!(decision.jitter, Duration::ZERO);
}

#[test]
fn deadline_jitter_is_replay_deterministic_for_same_seed_and_scope() {
    let policy = DeadlineJitterPolicy::new(Duration::from_millis(25), 0xA5A5).with_policy_id(42);
    let original = Time::from_secs(10);
    let first = policy.apply(original, task(17), region(4));
    let second = policy.apply(original, task(17), region(4));

    assert_eq!(first, second);
    assert!(first.jittered_deadline >= original);
    assert!(first.jitter <= Duration::from_millis(25));
    assert_eq!(
        first.jittered_deadline.as_nanos() - original.as_nanos(),
        first.jitter.as_nanos() as u64
    );
}

#[test]
fn deadline_jitter_scope_controls_identity_inputs() {
    let original = Time::from_secs(5);
    let task_scoped = DeadlineJitterPolicy::new(Duration::from_millis(100), 99)
        .with_scope(DeadlineJitterScope::Task);
    let region_scoped = DeadlineJitterPolicy::new(Duration::from_millis(100), 99)
        .with_scope(DeadlineJitterScope::Region);

    let task_decision_a = task_scoped.apply(original, task(21), region(1));
    let task_decision_b = task_scoped.apply(original, task(21), region(2));
    assert_eq!(task_decision_a.jitter, task_decision_b.jitter);

    let region_decision_a = region_scoped.apply(original, task(21), region(8));
    let region_decision_b = region_scoped.apply(original, task(22), region(8));
    assert_eq!(region_decision_a.jitter, region_decision_b.jitter);
}

#[test]
fn deadline_jitter_never_schedules_before_original_deadline() {
    let policy = DeadlineJitterPolicy::new(Duration::from_secs(1), 0xDEAD_BEEF)
        .with_scope(DeadlineJitterScope::TaskAndRegion);
    let original = Time::MAX.saturating_sub_nanos(500_000_000);

    for i in 0..32 {
        let decision = policy.apply(original, task(100 + i), region(200 + i));
        assert!(decision.jittered_deadline >= original);
        assert!(decision.jittered_deadline <= Time::MAX);
        assert!(decision.jitter <= Duration::from_secs(1));
    }
}
