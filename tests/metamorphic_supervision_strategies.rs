#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic integration tests for supervision configuration and trackers.
//!
//! These tests validate relationships that should hold across transformed
//! supervision inputs while exercising the real `src/supervision.rs` APIs.
//! They intentionally avoid the old hand-rolled simulator that could drift
//! away from the runtime's actual semantics.

#[path = "metamorphic/supervision.rs"]
mod compiled_supervision_planning;

use asupersync::supervision::{BackoffStrategy, RestartConfig, RestartVerdict, SupervisionConfig};
use std::time::Duration;

fn verdict_kind(verdict: &RestartVerdict) -> &'static str {
    match verdict {
        RestartVerdict::Allowed { .. } => "allowed",
        RestartVerdict::Denied { .. } => "denied",
    }
}

fn allowed_delay(verdict: &RestartVerdict) -> Option<Duration> {
    match verdict {
        RestartVerdict::Allowed { delay, .. } => *delay,
        RestartVerdict::Denied { .. } => None,
    }
}

fn assert_allowed_with_delay(verdict: RestartVerdict, attempt: u32, delay: Option<Duration>) {
    assert_eq!(
        verdict,
        RestartVerdict::Allowed { attempt, delay },
        "expected allowed restart verdict with attempt {attempt} and delay {delay:?}"
    );
}

#[test]
fn mr_named_policy_constructors_match_explicit_builders() {
    let window = Duration::from_secs(45);

    assert_eq!(
        SupervisionConfig::one_for_all(4, window),
        SupervisionConfig::new(4, window)
            .with_restart_policy(asupersync::supervision::RestartPolicy::OneForAll)
    );
    assert_eq!(
        SupervisionConfig::rest_for_one(4, window),
        SupervisionConfig::new(4, window)
            .with_restart_policy(asupersync::supervision::RestartPolicy::RestForOne)
    );
}

#[test]
fn mr_supervision_config_restart_tracker_preserves_backoff() {
    let backoff = BackoffStrategy::Fixed(Duration::from_millis(75));
    let config = SupervisionConfig::new(3, Duration::from_secs(60))
        .with_backoff(backoff)
        .with_storm_threshold(2.0);
    let mut tracker = config.restart_tracker();

    assert_allowed_with_delay(tracker.evaluate(0), 1, Some(Duration::from_millis(75)));

    tracker.record(0);
    assert_allowed_with_delay(tracker.evaluate(1), 2, Some(Duration::from_millis(75)));
}

#[test]
fn mr_larger_restart_budget_never_denies_earlier_than_smaller_budget() {
    let mut smaller = asupersync::supervision::RestartTracker::from_restart_config(
        RestartConfig::new(2, Duration::from_secs(60)),
    );
    let mut larger = asupersync::supervision::RestartTracker::from_restart_config(
        RestartConfig::new(4, Duration::from_secs(60)),
    );

    for now in [0_u64, 1_000_000_000] {
        smaller.record(now);
        larger.record(now);
    }

    let smaller_verdict = smaller.evaluate(2_000_000_000);
    let larger_verdict = larger.evaluate(2_000_000_000);
    let expected_smaller_verdict = "denied";
    let expected_larger_verdict = "allowed";
    let expected_delay = Some(Duration::from_millis(400));
    let delay_actual = allowed_delay(&larger_verdict);
    let verdict = if verdict_kind(&smaller_verdict) == expected_smaller_verdict
        && larger_verdict
            == (RestartVerdict::Allowed {
                attempt: 3,
                delay: expected_delay,
            }) {
        "pass"
    } else {
        "fail"
    };
    let first_failure = if verdict == "pass" {
        "none"
    } else if verdict_kind(&smaller_verdict) != expected_smaller_verdict {
        "smaller_budget_not_denied"
    } else if verdict_kind(&larger_verdict) != expected_larger_verdict {
        "larger_budget_denied_too_early"
    } else {
        "larger_budget_delay_mismatch"
    };

    println!(
        "bead_id=asupersync-ta56mp scenario_id=larger_budget_default_backoff policy=restart smaller_budget=2 larger_budget=4 attempt=3 expected_smaller_verdict={expected_smaller_verdict} actual_smaller_verdict={} expected_larger_verdict={expected_larger_verdict} actual_larger_verdict={} delay_expected_ms={} delay_actual_ms={} verdict={verdict} first_failure={first_failure}",
        verdict_kind(&smaller_verdict),
        verdict_kind(&larger_verdict),
        expected_delay.map_or(0, |delay| delay.as_millis()),
        delay_actual.map_or(0, |delay| delay.as_millis())
    );

    assert!(
        matches!(smaller_verdict, RestartVerdict::Denied { .. }),
        "smaller restart budget should deny the third restart inside the same window"
    );
    assert_allowed_with_delay(larger_verdict, 3, expected_delay);
}

#[test]
fn mr_larger_restart_budget_preserves_no_backoff_policy() {
    let config = |max_restarts| {
        RestartConfig::new(max_restarts, Duration::from_secs(60))
            .with_backoff(BackoffStrategy::None)
    };
    let mut smaller = asupersync::supervision::RestartTracker::from_restart_config(config(2));
    let mut larger = asupersync::supervision::RestartTracker::from_restart_config(config(4));

    for now in [0_u64, 1_000_000_000] {
        smaller.record(now);
        larger.record(now);
    }

    assert!(matches!(
        smaller.evaluate(2_000_000_000),
        RestartVerdict::Denied { .. }
    ));
    assert_allowed_with_delay(larger.evaluate(2_000_000_000), 3, None);
}

#[test]
fn mr_larger_restart_budget_preserves_fixed_delay_policy() {
    let fixed_delay = Duration::from_millis(75);
    let config = |max_restarts| {
        RestartConfig::new(max_restarts, Duration::from_secs(60))
            .with_backoff(BackoffStrategy::Fixed(fixed_delay))
    };
    let mut smaller = asupersync::supervision::RestartTracker::from_restart_config(config(2));
    let mut larger = asupersync::supervision::RestartTracker::from_restart_config(config(4));

    for now in [0_u64, 1_000_000_000] {
        smaller.record(now);
        larger.record(now);
    }

    assert!(matches!(
        smaller.evaluate(2_000_000_000),
        RestartVerdict::Denied { .. }
    ));
    assert_allowed_with_delay(larger.evaluate(2_000_000_000), 3, Some(fixed_delay));
}

#[test]
fn mr_larger_restart_budget_eventually_denies_after_its_own_limit() {
    let mut tracker = asupersync::supervision::RestartTracker::from_restart_config(
        RestartConfig::new(4, Duration::from_secs(60)),
    );

    for now in [0_u64, 1_000_000_000, 2_000_000_000, 3_000_000_000] {
        assert!(
            tracker.evaluate(now).is_allowed(),
            "restart at {now} should be within the larger budget"
        );
        tracker.record(now);
    }

    assert!(
        matches!(
            tracker.evaluate(4_000_000_000),
            RestartVerdict::Denied { .. }
        ),
        "larger budget must still deny after its own configured limit"
    );
}

#[test]
fn mr_lower_storm_threshold_flags_intensity_no_later_than_higher_threshold() {
    let build_tracker = |threshold| {
        SupervisionConfig::new(10, Duration::from_secs(1))
            .with_storm_threshold(threshold)
            .restart_tracker()
    };

    let mut sensitive = build_tracker(2.0);
    let mut tolerant = build_tracker(4.0);

    for now in [0_u64, 300_000_000, 600_000_000] {
        sensitive.record(now);
        tolerant.record(now);
    }

    assert!(
        sensitive.is_intensity_storm(600_000_000),
        "lower threshold should flag the same burst as a storm"
    );
    assert!(
        !tolerant.is_intensity_storm(600_000_000),
        "higher threshold should not flag the same burst yet"
    );
}
