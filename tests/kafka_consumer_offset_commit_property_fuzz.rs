//! Property-based fuzz over `KafkaConsumer::commit_offsets` invariants.
//!
//! Bead: br-asupersync-61m3lc
//!
//! `src/messaging/kafka_consumer.rs:1222` enforces:
//!   1. (topic, partition) must be in `assigned_partitions`
//!   2. offset must be non-negative
//!   3. offset must NOT be < the previously committed offset for that
//!      partition (no regression)
//!   4. duplicate (topic, partition) entries in a single batch reject
//!   5. closed consumer rejects every commit
//!
//! In test mode (no `kafka` feature), `subscribe()` auto-assigns
//! partition 0 of every subscribed topic. This test exploits that to
//! drive the consumer in-process across thousands of randomly
//! generated commit batches without needing a real broker.
//!
//! Invariants asserted:
//!   * After a successful commit_offsets, every (topic, partition)
//!     reflected by `committed_offset()` is monotonically non-decreasing
//!     across the entire test sequence — no regression silently slipped
//!     through.
//!   * A commit batch that contains an offset *strictly less than*
//!     the current committed_offset for that partition MUST return Err.
//!   * A batch over an unsubscribed topic MUST return Err (the
//!     assignment gate cannot be bypassed).
//!   * A duplicate (topic, partition) within one batch MUST return Err.

#![cfg(test)]
#![allow(clippy::pedantic, clippy::nursery, clippy::print_stderr)]

use asupersync::messaging::kafka_consumer::{ConsumerConfig, KafkaConsumer, TopicPartitionOffset};
use asupersync::test_utils::run_test_with_cx;

use proptest::collection::vec as prop_vec;
use proptest::prelude::*;
use std::collections::BTreeMap;

/// Strategy: a topic name from a tiny pool, so commit batches share
/// (topic, partition) keys often enough to exercise the regression
/// check.
fn topic_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("alpha".to_string()),
        Just("beta".to_string()),
        Just("gamma".to_string()),
    ]
}

/// Strategy: a single TopicPartitionOffset against partition 0 (the
/// only partition auto-assigned by subscribe() in test mode).
/// Offsets cover negative (must reject), zero, and positive small
/// integers to make regression collisions likely.
fn tpo_strategy() -> impl Strategy<Value = TopicPartitionOffset> {
    (topic_strategy(), -2i64..50i64)
        .prop_map(|(topic, offset)| TopicPartitionOffset::new(topic, 0, offset))
}

/// Strategy: an entire commit batch (1..=8 entries).
fn batch_strategy() -> impl Strategy<Value = Vec<TopicPartitionOffset>> {
    prop_vec(tpo_strategy(), 1..=8)
}

/// Strategy: a sequence of commit batches.
fn sequence_strategy() -> impl Strategy<Value = Vec<Vec<TopicPartitionOffset>>> {
    prop_vec(batch_strategy(), 1..=10)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Drive a sequence of random commit batches against a consumer
    /// subscribed to {alpha, beta, gamma}. The shadow `committed`
    /// table tracks what we expect committed_offset() to report after
    /// each successful commit.
    #[test]
    fn kafka_consumer_commit_offsets_invariants(seq in sequence_strategy()) {
        run_test_with_cx(|cx| async move {
            let config = ConsumerConfig::new(
                vec!["127.0.0.1:9092".to_string()],
                "asupersync-61m3lc-property-group",
            )
            .client_id("asupersync-61m3lc-prop")
            .allow_deterministic_broker_for_testing(true);
            let consumer = KafkaConsumer::new(config).expect("consumer config");

            consumer
                .subscribe(&cx, &["alpha", "beta", "gamma"])
                .await
                .expect("subscribe");

            // Shadow table: highest committed offset we've observed
            // succeed for each (topic, partition).
            let mut shadow: BTreeMap<(String, i32), i64> = BTreeMap::new();

            for batch in seq {
                // Pre-classify the batch so we know whether
                // commit_offsets *should* succeed.
                let has_negative = batch.iter().any(|tpo| tpo.offset < 0);
                let has_duplicate = {
                    let mut seen = std::collections::HashSet::new();
                    batch
                        .iter()
                        .any(|tpo| !seen.insert((tpo.topic.clone(), tpo.partition)))
                };
                // Regression: the batch tries to commit an offset
                // strictly less than what's already committed for the
                // same (topic, partition).
                let has_regression = batch.iter().any(|tpo| {
                    shadow
                        .get(&(tpo.topic.clone(), tpo.partition))
                        .is_some_and(|prev| tpo.offset < *prev)
                });

                let should_reject = has_negative || has_duplicate || has_regression;

                let result = consumer.commit_offsets(&cx, &batch).await;

                match result {
                    Ok(()) => {
                        // The consumer accepted the batch. The
                        // pre-classification must have agreed.
                        assert!(
                            !should_reject,
                            "consumer accepted batch that should have been rejected: \
                             has_negative={has_negative} has_duplicate={has_duplicate} \
                             has_regression={has_regression} batch={batch:?}"
                        );
                        // Update the shadow with the highest offset per
                        // (topic, partition) in this batch (the consumer
                        // de-duplicates internally via BTreeMap::insert).
                        for tpo in &batch {
                            shadow
                                .entry((tpo.topic.clone(), tpo.partition))
                                .and_modify(|v| *v = (*v).max(tpo.offset))
                                .or_insert(tpo.offset);
                        }

                        // Cross-check: committed_offset() must reflect
                        // the shadow for every key the shadow knows
                        // about.
                        for ((topic, partition), expected) in &shadow {
                            let actual = consumer.committed_offset(topic, *partition);
                            assert_eq!(
                                actual,
                                Some(*expected),
                                "committed_offset({}, {}) must match shadow {} after \
                                 successful batch {:?}",
                                topic,
                                partition,
                                expected,
                                batch
                            );
                        }
                    }
                    Err(_e) => {
                        // The consumer rejected the batch.
                        // Pre-classification must agree the batch was
                        // bad. (We don't pin the exact error variant
                        // because some valid batches can fail for
                        // unrelated reasons in test mode — but every
                        // bad-pattern batch should land here.)
                        // If the shadow is unchanged after a reject,
                        // we don't need to re-check committed_offset
                        // because the consumer never mutated state.
                        assert!(
                            should_reject,
                            "consumer rejected batch that looked valid: batch={batch:?}, \
                             shadow={shadow:?}"
                        );
                    }
                }
            }
        });
    }

    /// A commit batch over an unsubscribed topic must always reject.
    #[test]
    fn kafka_consumer_rejects_unsubscribed_topic(
        topic in "[a-z]{4,8}",
        offset in 0i64..1_000_000,
    ) {
        // The shadow consumer is subscribed only to 'alpha'. Generating
        // any topic OTHER than 'alpha' tests the assignment gate.
        prop_assume!(topic != "alpha");

        run_test_with_cx(|cx| async move {
            let config = ConsumerConfig::new(
                vec!["127.0.0.1:9092".to_string()],
                "asupersync-61m3lc-unsubscribed-group",
            )
            .client_id("asupersync-61m3lc-unsubscribed")
            .allow_deterministic_broker_for_testing(true);
            let consumer = KafkaConsumer::new(config).expect("consumer config");
            consumer.subscribe(&cx, &["alpha"]).await.expect("subscribe");

            let batch = vec![TopicPartitionOffset::new(&topic, 0, offset)];
            let result = consumer.commit_offsets(&cx, &batch).await;
            assert!(
                result.is_err(),
                "commit on unsubscribed topic '{}' must reject; got Ok",
                topic
            );
        });
    }
}
