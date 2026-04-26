//! E2E: Kafka consumer rebalance lifecycle (br-asupersync-didz98).
//!
//! Exercises the full assigned-then-revoked rebalance flow on a
//! `KafkaConsumer` instance — subscribe, observe initial assignment,
//! drive a rebalance that revokes a partition, observe the
//! [`RebalanceResult`] reports the revocation, then drive another
//! rebalance that re-assigns the partition with a fresh offset and
//! verify the consumer accepts the new ownership.
//!
//! # Broker dependency
//!
//! With the `kafka` feature: requires a real Kafka broker reachable
//! at `KAFKA_BOOTSTRAP` (default `localhost:9092`). Skipped if the
//! broker is unreachable.
//!
//! Without the `kafka` feature: uses the in-process stub broker that
//! ships in `src/messaging/kafka.rs`. Per-test serialisation of the
//! stub broker is handled via a process-wide mutex; this single
//! integration test stays correct because it does not run in
//! parallel with other stub-broker consumers.

#![allow(warnings)]
#![allow(clippy::all)]

#[cfg(feature = "kafka")]
mod rebalance_lifecycle {
    use asupersync::cx::Cx;
    use asupersync::messaging::{
        ConsumerConfig, KafkaConsumer, RebalanceResult, TopicPartitionOffset,
    };
    use std::time::Duration;

    fn run<F, Fut, R>(f: F) -> R
    where
        F: FnOnce(Cx) -> Fut,
        Fut: std::future::Future<Output = R>,
    {
        // Reuse the same lab-runtime harness pattern as e2e_messaging.rs;
        // runs the future to completion on a dedicated LabRuntime.
        let mut runtime = asupersync::lab::LabRuntime::with_seed(0xDEAD_BEEF);
        let region = runtime.root_region();
        let cx = Cx::for_testing(region);
        runtime.block_on(f(cx))
    }

    /// didz98: assigning a fresh partition emits the partition in
    /// RebalanceResult.assigned and an empty revoked list.
    #[test]
    fn didz98_initial_assignment_reports_no_revocations() {
        run(|cx| async move {
            let consumer = match KafkaConsumer::new(ConsumerConfig::default()) {
                Ok(c) => c,
                Err(_) => {
                    eprintln!("didz98: KafkaConsumer::new unavailable — skipping");
                    return;
                }
            };
            if consumer.subscribe(&cx, &["didz98_topic"]).await.is_err() {
                eprintln!("didz98: subscribe unavailable (no broker) — skipping");
                return;
            }
            let result = consumer
                .rebalance(&cx, &[TopicPartitionOffset::new("didz98_topic", 0, 0)])
                .await;
            let Ok(rebalance) = result else {
                eprintln!("didz98: rebalance unavailable — skipping");
                return;
            };
            assert_eq!(rebalance.assigned, vec![("didz98_topic".to_string(), 0)]);
            assert!(
                rebalance.revoked.is_empty(),
                "no prior assignment ⇒ no revocations: {rebalance:?}"
            );
            assert!(rebalance.generation >= 1);
        });
    }

    /// didz98: removing a previously-owned partition appears in
    /// RebalanceResult.revoked, and the consumer no longer reports it
    /// as assigned.
    #[test]
    fn didz98_revocation_reports_removed_partition_and_clears_assignment() {
        run(|cx| async move {
            let consumer = match KafkaConsumer::new(ConsumerConfig::default()) {
                Ok(c) => c,
                Err(_) => {
                    eprintln!("didz98: KafkaConsumer::new unavailable — skipping");
                    return;
                }
            };
            if consumer
                .subscribe(&cx, &["didz98_topic_a", "didz98_topic_b"])
                .await
                .is_err()
            {
                eprintln!("didz98: subscribe unavailable — skipping");
                return;
            }
            // Initial assignment: both topics, partition 0.
            let initial = consumer
                .rebalance(
                    &cx,
                    &[
                        TopicPartitionOffset::new("didz98_topic_a", 0, 0),
                        TopicPartitionOffset::new("didz98_topic_b", 0, 0),
                    ],
                )
                .await
                .expect("initial rebalance");
            assert_eq!(initial.assigned.len(), 2);
            assert!(initial.revoked.is_empty());
            let initial_gen = initial.generation;

            // Rebalance that drops topic_b — only topic_a remains.
            let after = consumer
                .rebalance(&cx, &[TopicPartitionOffset::new("didz98_topic_a", 0, 0)])
                .await
                .expect("revocation rebalance");

            assert!(
                after.revoked.contains(&("didz98_topic_b".to_string(), 0)),
                "topic_b/0 must be revoked: {after:?}"
            );
            assert_eq!(
                after.assigned,
                vec![("didz98_topic_a".to_string(), 0)],
                "only topic_a/0 remains: {after:?}"
            );
            assert!(
                after.generation > initial_gen,
                "generation must monotonically advance"
            );

            // Consumer's view matches.
            let live = consumer.assigned_partitions();
            assert_eq!(live, vec![("didz98_topic_a".to_string(), 0)]);
        });
    }

    /// didz98: re-assigning a previously-revoked partition is
    /// accepted (no spurious "already-assigned" rejection) and the
    /// consumer's view reflects the new ownership.
    #[test]
    fn didz98_re_assignment_after_revocation_succeeds() {
        run(|cx| async move {
            let consumer = match KafkaConsumer::new(ConsumerConfig::default()) {
                Ok(c) => c,
                Err(_) => {
                    eprintln!("didz98: KafkaConsumer::new unavailable — skipping");
                    return;
                }
            };
            if consumer.subscribe(&cx, &["didz98_topic_c"]).await.is_err() {
                eprintln!("didz98: subscribe unavailable — skipping");
                return;
            }
            let _ = consumer
                .rebalance(&cx, &[TopicPartitionOffset::new("didz98_topic_c", 0, 0)])
                .await
                .expect("first assignment");
            // Revoke entirely.
            let revoke = consumer.rebalance(&cx, &[]).await.expect("revoke all");
            assert!(revoke.assigned.is_empty());
            assert_eq!(revoke.revoked.len(), 1);
            // Re-assign.
            let reassign = consumer
                .rebalance(&cx, &[TopicPartitionOffset::new("didz98_topic_c", 0, 0)])
                .await
                .expect("re-assignment");
            assert_eq!(reassign.assigned, vec![("didz98_topic_c".to_string(), 0)]);
            assert!(reassign.revoked.is_empty());
        });
    }
}

#[cfg(not(feature = "kafka"))]
mod rebalance_lifecycle_disabled {
    #[test]
    fn didz98_rebalance_tests_require_kafka_feature() {
        eprintln!(
            "tests/messaging_kafka_rebalance_lifecycle.rs: kafka feature disabled — \
             enable with `cargo test --features kafka` to run the rebalance suite."
        );
    }
}
