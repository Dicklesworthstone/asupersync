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

    assert!(
        matches!(
            smaller.evaluate(2_000_000_000),
            RestartVerdict::Denied { .. }
        ),
        "smaller restart budget should deny the third restart inside the same window"
    );
    assert_allowed_with_delay(larger.evaluate(2_000_000_000), 3, None);
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
