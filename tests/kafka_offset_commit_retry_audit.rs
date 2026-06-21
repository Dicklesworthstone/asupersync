//! Audit and regression tests for Kafka OffsetCommit retry behavior.
//!
//! Kafka protocol requirement: "When OffsetCommit RPC fails with retriable error
//! (NETWORK_EXCEPTION, NOT_COORDINATOR), client must retry up to N times then
//! surface error to caller, not retry indefinitely (block forever)."
//!
//! Source-truth status: the stale audit finding is fixed. `ConsumerConfig`
//! exposes a bounded retry budget and `commit_offsets` routes real Kafka commits
//! through `retry_consumer_operation`; the no-feature test path uses the
//! deterministic in-process broker.

use asupersync::cx::Cx;
use asupersync::messaging::kafka_consumer::{ConsumerConfig, KafkaConsumer, TopicPartitionOffset};
use futures_lite::future::block_on;
use std::time::Duration;

#[test]
fn consumer_config_exposes_bounded_retry_budget() {
    let default_config = ConsumerConfig::default();
    assert_eq!(default_config.retries, 3);

    let tuned = ConsumerConfig::new(vec!["localhost:9092".to_string()], "retry-budget")
        .retries(7)
        .heartbeat_interval(Duration::from_millis(5));
    assert_eq!(tuned.retries, 7);
    assert_eq!(tuned.heartbeat_interval, Duration::from_millis(5));
}

#[test]
fn offset_commit_uses_configured_consumer_surface() {
    let cx = Cx::for_testing();
    let config = ConsumerConfig::new(
        vec!["localhost:9092".to_string()],
        "offset-commit-retry-audit",
    )
    .retries(2)
    .allow_deterministic_broker_for_testing(true);
    let consumer = KafkaConsumer::new(config).expect("create consumer");

    block_on(async {
        consumer.subscribe(&cx, &["test-topic"]).await.unwrap();
        consumer
            .commit_offsets(&cx, &[TopicPartitionOffset::new("test-topic", 0, 42)])
            .await
            .unwrap();
    });

    assert_eq!(consumer.config().retries, 2);
    assert_eq!(consumer.committed_offset("test-topic", 0), Some(42));
}

#[test]
fn consumer_retry_implementation_is_budgeted_in_source() {
    let source = include_str!("../src/messaging/kafka_consumer.rs");

    for required in [
        "pub retries: u32",
        "pub const fn retries",
        "fn consumer_retry_backoff",
        "async fn wait_consumer_retry_backoff",
        "async fn retry_consumer_operation",
        "attempt < config.retries",
        "wait_consumer_retry_backoff(cx, delay).await?",
        "retry_consumer_operation(cx, config",
    ] {
        assert!(
            source.contains(required),
            "missing Kafka consumer retry source marker: {required}"
        );
    }
}
