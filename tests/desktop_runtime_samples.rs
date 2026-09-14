//! Focused tests for the bounded owned and host runtime samples.

#![cfg(feature = "desktop-runtime-profile")]
#![forbid(unsafe_code)]

use asupersync::desktop_samples::{
    validate_priority_max_meet, HostClockSample, OwnedRuntimeSample, SampleClockError,
};
use asupersync::desktop_profile::{
    run_foreign_call, DesktopRuntimeProfile, DesktopRuntimeStartError, ForeignCallCompletion,
};
use asupersync::Budget;
use asupersync::types::id::Time;
use std::time::{Duration, Instant};

/// worker=2, queue=32, steal=4, poll=16, blocking=1..2, regions=16/64/64/4096.
fn explicit_profile() -> DesktopRuntimeProfile {
    DesktopRuntimeProfile::with_limits(2, 32, 4, 16, 1, 2, 16, 64, 64, 4096)
}

#[test]
fn owned_sample_starts_with_explicit_bounds_runs_and_drains() {
    let sample = OwnedRuntimeSample::start(explicit_profile()).expect("explicit bounds are valid");
    let limits = sample.limits();
    assert_eq!(limits.worker_threads, 2);
    assert_eq!(limits.blocking_max_threads, 2);
    assert_eq!(limits.global_queue_limit, 32);
    assert_eq!(limits.root_max_heap_bytes, 4096);

    let value = sample.block_on(run_foreign_call(ForeignCallCompletion::new(), || 21));
    assert_eq!(value, 21);

    let report = sample.close(Duration::from_secs(1));
    assert!(report.drained, "bounded sample must drain within 1s");
    assert_eq!(report.limits.worker_threads, 2);
    assert_eq!(report.limits.root_max_heap_bytes, 4096);
}

#[test]
fn owned_sample_refuses_unbounded_profile_before_any_thread_spawns() {
    let unbounded = DesktopRuntimeProfile::with_limits(2, 0, 4, 16, 1, 2, 16, 64, 64, 4096);
    let error = OwnedRuntimeSample::start(unbounded)
        .expect_err("a zero queue depth is refused, not normalized");
    assert!(matches!(
        error,
        DesktopRuntimeStartError::InvalidProfile(_)
    ));
}

#[test]
fn priority_max_meet_yields_max_priority_and_tightest_bounds() {
    // A maximal-priority child under an unbounded parent keeps priority 255
    // and the child's tight bounds.
    let parent = Budget::INFINITE;
    let child = Budget::with_deadline_at_secs(10)
        .with_priority(255)
        .with_cost_quota(64);
    let met = validate_priority_max_meet(parent, child).expect("documented algebra holds");
    assert_eq!(met.priority, 255);
    assert_eq!(met.deadline.map(Time::as_nanos), child.deadline.map(Time::as_nanos));
    assert_eq!(met.cost_quota, child.cost_quota);

    // Tighter child bounds win; looser parents are narrowed.
    let parent = Budget::with_deadline_at_secs(30).with_cost_quota(100);
    let child = Budget::with_deadline_at_secs(10).with_cost_quota(40);
    let met = validate_priority_max_meet(parent, child).expect("documented algebra holds");
    assert_eq!(met.deadline.map(Time::as_nanos), child.deadline.map(Time::as_nanos));
    assert_eq!(met.cost_quota, Some(40));
}

#[test]
fn meet_is_commutative_and_infinite_is_the_identity() {
    let a = Budget::with_deadline_at_secs(5)
        .with_priority(200)
        .with_cost_quota(10);
    let b = Budget::with_deadline_at_secs(9)
        .with_priority(100)
        .with_cost_quota(20);

    let ab = validate_priority_max_meet(a, b).expect("algebra holds");
    let ba = validate_priority_max_meet(b, a).expect("algebra holds");
    assert_budgets_equal(&ab, &ba, "meet is commutative");
    assert_eq!(ab.priority, 200, "priority-max selects the more urgent side");

    // INFINITE carries priority 0, so meeting it preserves the other budget.
    let preserved = validate_priority_max_meet(Budget::INFINITE, b).expect("algebra holds");
    assert_budgets_equal(&preserved, &b, "INFINITE is the meet identity");
}

/// `Budget` does not implement `Debug`, so equality is asserted field-wise.
fn assert_budgets_equal(actual: &Budget, expected: &Budget, context: &str) {
    assert_eq!(
        actual.deadline.map(Time::as_nanos),
        expected.deadline.map(Time::as_nanos),
        "{context}: deadline"
    );
    assert_eq!(actual.poll_quota, expected.poll_quota, "{context}: poll quota");
    assert_eq!(actual.cost_quota, expected.cost_quota, "{context}: cost quota");
    assert_eq!(actual.priority, expected.priority, "{context}: priority");
}

#[test]
fn host_sample_runs_foreign_call_before_host_deadline() {
    let sample = HostClockSample::start().expect("standard profile is valid");
    let deadline = Instant::now() + Duration::from_secs(10);

    let outcome = sample
        .run_foreign_call_before(deadline, || "host-clock")
        .expect("deadline lies in the future");
    assert_eq!(outcome.value, "host-clock");
    assert!(outcome.met, "an instant operation meets a 10s host window");
    assert!(outcome.elapsed <= outcome.allowed);

    let report = sample.close(Duration::from_secs(1));
    assert!(report.drained);
}

#[test]
fn host_sample_refuses_deadline_already_in_past() {
    let sample = HostClockSample::start().expect("standard profile is valid");
    let past = Instant::now() - Duration::from_secs(1);
    let outcome = sample.run_foreign_call_before(past, || 0);
    assert_eq!(outcome.err(), Some(SampleClockError::DeadlineInPast));
    sample.close(Duration::from_secs(1));
}

#[test]
fn two_samples_coexist_and_close_without_hidden_globals() {
    let small = OwnedRuntimeSample::start(DesktopRuntimeProfile::with_limits(
        1, 8, 2, 8, 1, 1, 8, 16, 16, 2048,
    ))
    .expect("small bounds are valid");
    let large = OwnedRuntimeSample::start(explicit_profile()).expect("explicit bounds are valid");

    assert_ne!(small.limits(), large.limits());

    assert_eq!(
        small.block_on(run_foreign_call(ForeignCallCompletion::new(), || 1)),
        1
    );
    let small_report = small.close(Duration::from_secs(1));
    assert!(small_report.drained);

    // Closing the first sample leaves the second fully operational.
    assert_eq!(
        large.block_on(run_foreign_call(ForeignCallCompletion::new(), || 2)),
        2
    );
    let large_report = large.close(Duration::from_secs(1));
    assert!(large_report.drained);
    assert_ne!(
        small_report.limits.global_queue_limit,
        large_report.limits.global_queue_limit
    );
}
