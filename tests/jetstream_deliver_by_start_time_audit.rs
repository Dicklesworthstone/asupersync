#![cfg(feature = "test-internals")]

//! Audit tests for JetStream `DeliverByStartTime` retention-gap assumptions.

use asupersync::messaging::jetstream::{
    ConsumerConfig, DeliverPolicy, FuzzPullSubscriberState, FuzzPullSubscriberStep,
    FuzzPullSubscriberTerminal, fuzz_apply_pull_subscriber_step,
};
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn deliver_by_start_time_configuration_preserves_historical_start_time() {
    let before_purge_time = UNIX_EPOCH + Duration::from_secs(42);
    let consumer_config = ConsumerConfig::new("before_purge_consumer")
        .deliver_policy(DeliverPolicy::ByStartTime(before_purge_time));

    match consumer_config.deliver_policy {
        DeliverPolicy::ByStartTime(time) => assert_eq!(time, before_purge_time),
        other => panic!("expected ByStartTime policy, got {other:?}"),
    }
}

#[test]
fn empty_pull_timeout_is_not_reclassified_as_stream_retention_gap() {
    let mut state = FuzzPullSubscriberState {
        batch: 1,
        received: 0,
        ignored: 0,
        terminal: FuzzPullSubscriberTerminal::Active,
    };

    fuzz_apply_pull_subscriber_step(&mut state, FuzzPullSubscriberStep::ProcessTimedOut);

    assert_eq!(state.received, 0);
    assert_eq!(state.terminal, FuzzPullSubscriberTerminal::TimedOut);
}
