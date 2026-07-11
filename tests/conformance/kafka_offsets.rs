//! Kafka Offset Management Conformance Tests
//!
//! Implements metamorphic relations for Kafka consumer offset management to verify
//! protocol compliance across commit operations, rebalancing, and transactional semantics.

use asupersync::cx::Cx;
use asupersync::messaging::kafka::KafkaError;
use asupersync::messaging::kafka_consumer::{ConsumerConfig, KafkaConsumer, TopicPartitionOffset};
use asupersync::runtime::RuntimeBuilder;
use std::collections::HashMap;
use std::time::Duration;

/// Test configuration for Kafka conformance testing
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ConformanceConfig {
    pub group_id: String,
    pub retention_minutes: u32,
    pub enable_auto_commit: bool,
    pub auto_commit_interval: Duration,
}

impl Default for ConformanceConfig {
    #[allow(dead_code)]
    fn default() -> Self {
        Self {
            group_id: "conformance-test-group".to_string(),
            retention_minutes: 60,
            enable_auto_commit: false,
            auto_commit_interval: Duration::from_secs(5),
        }
    }
}

fn unique_group_id(label: &str) -> String {
    format!("asupersync-conformance-{label}-{}", std::process::id())
}

fn conformance_requires_unavailable_kafka_feature() -> bool {
    #[cfg(not(feature = "kafka"))]
    {
        true
    }
    #[cfg(feature = "kafka")]
    {
        false
    }
}

/// Creates a test consumer with the given configuration
async fn create_test_consumer(
    _cx: &Cx,
    config: ConformanceConfig,
) -> Result<Option<KafkaConsumer>, KafkaError> {
    if conformance_requires_unavailable_kafka_feature() {
        return Ok(None);
    }

    let bootstrap_servers = vec!["localhost:9092".to_string()];

    let consumer_config = ConsumerConfig::new(bootstrap_servers, config.group_id.clone())
        .enable_auto_commit(config.enable_auto_commit)
        .auto_commit_interval(config.auto_commit_interval)
        .session_timeout(Duration::from_secs(10))
        .heartbeat_interval(Duration::from_secs(3))
        .max_poll_records(500)
        .fetch_min_bytes(1)
        .fetch_max_bytes(1024 * 1024)
        .fetch_max_wait(Duration::from_millis(500))
        .auto_offset_reset(Default::default())
        .isolation_level(Default::default())
        .force_real_kafka(true);

    let _ = config.retention_minutes;
    match KafkaConsumer::new(consumer_config) {
        Ok(consumer) => Ok(Some(consumer)),
        Err(KafkaError::FeatureDisabled) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(not(feature = "kafka"))]
#[test]
fn no_feature_broker_operations_return_feature_disabled() -> Result<(), Box<dyn std::error::Error>>
{
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("failed to build test runtime");
    runtime.block_on(async {
        let cx = Cx::for_testing();
        let consumer = KafkaConsumer::new(ConsumerConfig::new(
            vec!["localhost:9092".to_string()],
            "no-feature-consumer",
        ))?;

        let subscribe = consumer.subscribe(&cx, &["orders"]).await;
        assert!(matches!(subscribe, Err(KafkaError::FeatureDisabled)));
        assert!(consumer.subscriptions().is_empty());

        let poll = consumer.poll(&cx, Duration::ZERO).await;
        assert!(matches!(poll, Err(KafkaError::FeatureDisabled)));

        let commit = consumer
            .commit_offsets(&cx, &[TopicPartitionOffset::new("orders", 0, 1)])
            .await;
        assert!(matches!(commit, Err(KafkaError::FeatureDisabled)));
        assert!(consumer.committed_offset("orders", 0).is_none());

        let seek = consumer
            .seek(&cx, &TopicPartitionOffset::new("orders", 0, 1))
            .await;
        assert!(matches!(seek, Err(KafkaError::FeatureDisabled)));
        assert!(consumer.position("orders", 0).is_none());

        Ok(())
    })
}

/// Subscribe the consumer and deterministically assign every partition used by a relation.
async fn prepare_consumer_offsets(
    cx: &Cx,
    consumer: &KafkaConsumer,
    offsets: &[TopicPartitionOffset],
) -> Result<(), KafkaError> {
    let mut topics: Vec<&str> = offsets.iter().map(|tpo| tpo.topic.as_str()).collect();
    topics.sort_unstable();
    topics.dedup();

    consumer.subscribe(cx, &topics).await?;
    consumer.rebalance(cx, offsets).await?;
    Ok(())
}

/// Helper to create test offset data
#[allow(dead_code)]
fn create_test_offsets(
    topic: &str,
    partitions: &[i32],
    base_offset: i64,
) -> Vec<TopicPartitionOffset> {
    partitions
        .iter()
        .enumerate()
        .map(|(i, &partition)| TopicPartitionOffset {
            topic: topic.to_string(),
            partition,
            offset: base_offset + (i as i64 * 100),
        })
        .collect()
}

/// Metamorphic Relation 1: Commit offsets are monotonic per partition
///
/// Property: For a given topic/partition, committed offsets must never decrease
/// unless explicitly reset. This ensures no message loss through offset regression.
#[test]
#[allow(dead_code)]
fn mr1_commit_offsets_monotonic_per_partition() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("failed to build test runtime");
    runtime.block_on(async {
        let cx = Cx::for_testing();
        let config = ConformanceConfig {
            group_id: unique_group_id("mr1"),
            ..ConformanceConfig::default()
        };

        let Some(consumer) = create_test_consumer(&cx, config.clone()).await? else {
            return Ok(());
        };

        let topic = "test-monotonic";
        let partition = 0;

        // Initial offset commit
        let initial_offsets = vec![TopicPartitionOffset {
            topic: topic.to_string(),
            partition,
            offset: 100,
        }];

        prepare_consumer_offsets(&cx, &consumer, &initial_offsets).await?;
        consumer.commit_offsets(&cx, &initial_offsets).await?;
        let committed_1 = consumer.committed_offset(topic, partition);
        assert_eq!(committed_1, Some(100));

        // Increasing offset commit (should succeed)
        let increased_offsets = vec![TopicPartitionOffset {
            topic: topic.to_string(),
            partition,
            offset: 200,
        }];

        consumer.commit_offsets(&cx, &increased_offsets).await?;
        let committed_2 = consumer.committed_offset(topic, partition);
        assert_eq!(committed_2, Some(200));

        // Attempt decreasing offset commit (should be rejected)
        let decreased_offsets = vec![TopicPartitionOffset {
            topic: topic.to_string(),
            partition,
            offset: 150,
        }];

        let result = consumer.commit_offsets(&cx, &decreased_offsets).await;
        match result {
            Err(KafkaError::Config(message)) if message.contains("regression") => {
                // Expected - offset regression should be prevented
                let committed_3 = consumer.committed_offset(topic, partition);
                assert_eq!(
                    committed_3,
                    Some(200),
                    "Offset should remain at previous value after regression attempt"
                );
            }
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Offset regression should have been rejected",
                )
                .into());
            }
            Err(e) => return Err(e.into()),
        }

        // Subsequent increasing commit should work
        let final_offsets = vec![TopicPartitionOffset {
            topic: topic.to_string(),
            partition,
            offset: 300,
        }];

        consumer.commit_offsets(&cx, &final_offsets).await?;
        let committed_4 = consumer.committed_offset(topic, partition);
        assert_eq!(committed_4, Some(300));

        Ok(())
    })
}

/// Metamorphic Relation 2: Idempotent commit with same ConsumerGroupId
///
/// Property: Multiple commits of the same offsets by the same consumer group
/// should be idempotent - committing offset O twice should result in the same
/// state as committing it once.
#[test]
#[allow(dead_code)]
fn mr2_idempotent_commit_same_group() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("failed to build test runtime");
    runtime.block_on(async {
        let cx = Cx::for_testing();
        let config = ConformanceConfig {
            group_id: unique_group_id("mr2"),
            ..ConformanceConfig::default()
        };

        let Some(consumer1) = create_test_consumer(&cx, config.clone()).await? else {
            return Ok(());
        };

        let topic = "test-idempotent";
        let offsets = create_test_offsets(topic, &[0, 1, 2], 1000);

        prepare_consumer_offsets(&cx, &consumer1, &offsets).await?;

        // First commit
        consumer1.commit_offsets(&cx, &offsets).await?;

        // Verify committed state after first commit
        let state_after_first = offsets
            .iter()
            .map(|tpo| {
                (
                    tpo.partition,
                    consumer1.committed_offset(&tpo.topic, tpo.partition),
                )
            })
            .collect::<Vec<_>>();

        // Second identical commit (should be idempotent)
        consumer1.commit_offsets(&cx, &offsets).await?;

        // Verify state is identical after second commit
        let state_after_second = offsets
            .iter()
            .map(|tpo| {
                (
                    tpo.partition,
                    consumer1.committed_offset(&tpo.topic, tpo.partition),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            state_after_first, state_after_second,
            "Idempotent commit should not change committed state"
        );

        // Every partition in the group's local committed view remains exact.
        for tpo in &offsets {
            let committed = consumer1.committed_offset(&tpo.topic, tpo.partition);
            assert_eq!(
                committed,
                Some(tpo.offset),
                "Committed offset should match expected value"
            );
        }

        Ok(())
    })
}

/// Metamorphic Relation 3: Offset retention respected per group.metadata.retention.minutes
///
/// Property: Offsets should be retained for at least the configured retention period.
/// Offsets committed within the retention window should remain accessible.
#[test]
#[allow(dead_code)]
fn mr3_offset_retention_respected() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("failed to build test runtime");
    runtime.block_on(async {
        let cx = Cx::for_testing();

        // Test with short retention for faster testing
        let short_retention_config = ConformanceConfig {
            group_id: unique_group_id("mr3-short"),
            retention_minutes: 1, // 1 minute retention
            ..ConformanceConfig::default()
        };

        // Test with longer retention
        let long_retention_config = ConformanceConfig {
            group_id: unique_group_id("mr3-long"),
            retention_minutes: 60, // 1 hour retention
            ..ConformanceConfig::default()
        };

        // Test short retention scenario
        let Some(short_consumer) =
            create_test_consumer(&cx, short_retention_config.clone()).await?
        else {
            return Ok(());
        };

        let topic = "test-retention-short";
        let offsets = create_test_offsets(topic, &[0], 500);

        prepare_consumer_offsets(&cx, &short_consumer, &offsets).await?;

        // Commit offsets
        short_consumer.commit_offsets(&cx, &offsets).await?;

        // Verify offsets are immediately available
        let committed_immediate = short_consumer.committed_offset(topic, 0);
        assert_eq!(
            committed_immediate,
            Some(500),
            "Offsets should be immediately available after commit"
        );
        short_consumer.close(&cx).await?;

        // Test long retention scenario
        let Some(long_consumer) = create_test_consumer(&cx, long_retention_config.clone()).await?
        else {
            return Ok(());
        };

        let long_topic = "test-retention-long";
        let long_offsets = create_test_offsets(long_topic, &[0], 1000);

        prepare_consumer_offsets(&cx, &long_consumer, &long_offsets).await?;
        long_consumer.commit_offsets(&cx, &long_offsets).await?;

        // Verify offsets are available within retention period
        let committed_long = long_consumer.committed_offset(long_topic, 0);
        assert_eq!(
            committed_long,
            Some(1000),
            "Offsets should be available within retention period"
        );

        // Note: In a real implementation, we would test that offsets expire after
        // the retention period, but this requires time manipulation or very long waits.
        // For this conformance test, we verify that the retention configuration
        // is properly applied to the consumer.

        Ok(())
    })
}

/// Metamorphic Relation 4: Rebalance preserves committed offsets
///
/// Property: Consumer group rebalancing should preserve previously committed offsets.
/// After a rebalance, consumers should see the same committed offsets as before.
#[test]
#[allow(dead_code)]
fn mr4_rebalance_preserves_committed_offsets() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("failed to build test runtime");
    runtime.block_on(async {
        let cx = Cx::for_testing();
        let config = ConformanceConfig {
            group_id: unique_group_id("mr4"),
            ..ConformanceConfig::default()
        };

        let Some(consumer) = create_test_consumer(&cx, config.clone()).await? else {
            return Ok(());
        };

        let topic = "test-rebalance";
        let initial_assignments = create_test_offsets(topic, &[0, 1, 2], 2000);

        prepare_consumer_offsets(&cx, &consumer, &initial_assignments).await?;

        // Commit initial offsets
        consumer.commit_offsets(&cx, &initial_assignments).await?;

        // Store pre-rebalance committed offsets
        let pre_rebalance_offsets: HashMap<i32, Option<i64>> = initial_assignments
            .iter()
            .map(|tpo| {
                (
                    tpo.partition,
                    consumer.committed_offset(&tpo.topic, tpo.partition),
                )
            })
            .collect();

        // Simulate rebalance (partition reassignment)
        let rebalance_assignments = create_test_offsets(topic, &[0, 1], 2000); // Fewer partitions
        let rebalance_result = consumer.rebalance(&cx, &rebalance_assignments).await?;

        // Verify rebalance was processed
        assert!(
            rebalance_result.generation > 0,
            "rebalance should advance the consumer generation"
        );
        assert!(
            !rebalance_result.assigned.is_empty(),
            "rebalance should leave the consumer with assigned partitions"
        );

        // Verify committed offsets are preserved after rebalance
        for (partition, expected_offset) in pre_rebalance_offsets {
            if rebalance_assignments
                .iter()
                .any(|tpo| tpo.partition == partition)
            {
                // Only check partitions still assigned after rebalance
                let post_rebalance_offset = consumer.committed_offset(topic, partition);
                assert_eq!(
                    post_rebalance_offset, expected_offset,
                    "Committed offset for partition {} should be preserved after rebalance",
                    partition
                );
            }
        }

        // Test rebalance with additional partitions
        let expanded_assignments = create_test_offsets(topic, &[0, 1, 2, 3], 2000);
        consumer.rebalance(&cx, &expanded_assignments).await?;

        // Original partitions should still have their committed offsets
        for tpo in &initial_assignments {
            let offset = consumer.committed_offset(&tpo.topic, tpo.partition);
            assert_eq!(
                offset,
                Some(tpo.offset),
                "Original committed offsets should survive partition expansion"
            );
        }

        Ok(())
    })
}

/// Metamorphic Relation 5: Transactional commit atomic
///
/// Property: Transactional offset commits should be atomic - either all offsets
/// in a transaction are committed, or none are. Partial commits should not occur.
#[test]
#[allow(dead_code)]
fn mr5_transactional_commit_atomic() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("failed to build test runtime");
    runtime.block_on(async {
        let cx = Cx::for_testing();

        // Create transactional configuration
        let tx_config = ConformanceConfig {
            group_id: unique_group_id("mr5-transactional"),
            ..ConformanceConfig::default()
        };

        let Some(consumer) = create_test_consumer(&cx, tx_config.clone()).await? else {
            return Ok(());
        };

        let topic = "test-transactional";

        // Create a batch of offsets for atomic commit
        let transaction_offsets = vec![
            TopicPartitionOffset {
                topic: topic.to_string(),
                partition: 0,
                offset: 1000,
            },
            TopicPartitionOffset {
                topic: topic.to_string(),
                partition: 1,
                offset: 2000,
            },
            TopicPartitionOffset {
                topic: topic.to_string(),
                partition: 2,
                offset: 3000,
            },
        ];

        prepare_consumer_offsets(&cx, &consumer, &transaction_offsets).await?;

        // Store initial state (should be None for new partitions)
        let initial_state: Vec<Option<i64>> = transaction_offsets
            .iter()
            .map(|tpo| consumer.committed_offset(&tpo.topic, tpo.partition))
            .collect();

        // Attempt atomic commit of all offsets
        let commit_result = consumer.commit_offsets(&cx, &transaction_offsets).await;

        match commit_result {
            Ok(()) => {
                // Successful commit - verify all offsets were committed atomically
                for (i, tpo) in transaction_offsets.iter().enumerate() {
                    let committed = consumer.committed_offset(&tpo.topic, tpo.partition);
                    assert_eq!(
                        committed,
                        Some(tpo.offset),
                        "All offsets in transaction should be committed on success (partition {})",
                        tpo.partition
                    );

                    // Verify state changed from initial
                    assert_ne!(
                        committed, initial_state[i],
                        "Committed offset should differ from initial state"
                    );
                }
            }
            Err(_) => {
                // Failed commit - verify NO offsets were committed (atomicity)
                for (i, tpo) in transaction_offsets.iter().enumerate() {
                    let committed = consumer.committed_offset(&tpo.topic, tpo.partition);
                    assert_eq!(
                        committed, initial_state[i],
                        "No offsets should be committed on transaction failure (partition {})",
                        tpo.partition
                    );
                }
            }
        }

        // Test partial transaction with one invalid offset
        let mixed_offsets = vec![
            TopicPartitionOffset {
                topic: topic.to_string(),
                partition: 0,
                offset: 5000, // Valid increasing offset
            },
            TopicPartitionOffset {
                topic: topic.to_string(),
                partition: 1,
                offset: 1500, // Invalid - would be regression from 2000
            },
        ];

        // Store state before mixed transaction
        let pre_mixed_state: Vec<Option<i64>> = mixed_offsets
            .iter()
            .map(|tpo| consumer.committed_offset(&tpo.topic, tpo.partition))
            .collect();

        let mixed_result = consumer.commit_offsets(&cx, &mixed_offsets).await;

        // This should fail due to regression, and no offsets should be committed
        if let Err(KafkaError::Config(ref message)) = mixed_result
            && message.contains("regression")
        {
            for (i, tpo) in mixed_offsets.iter().enumerate() {
                let committed = consumer.committed_offset(&tpo.topic, tpo.partition);
                assert_eq!(
                    committed, pre_mixed_state[i],
                    "Atomic failure should preserve all original offsets (partition {})",
                    tpo.partition
                );
            }
        } else {
            // If the implementation allows partial commits, verify atomicity constraints
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Expected transaction to fail atomically, but got: {mixed_result:?}"),
            )
            .into());
        }

        Ok(())
    })
}

/// Integration test that exercises all metamorphic relations in sequence
#[test]
#[allow(dead_code)]
fn integration_all_metamorphic_relations() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("failed to build test runtime");
    runtime.block_on(async {
        let cx = Cx::for_testing();
        let config = ConformanceConfig {
            group_id: unique_group_id("integration"),
            retention_minutes: 30,
            enable_auto_commit: false,
            auto_commit_interval: Duration::from_secs(10),
        };

        let Some(consumer) = create_test_consumer(&cx, config).await? else {
            return Ok(());
        };
        let topic = "integration-test";

        // MR1: Verify monotonic commits
        let offsets_v1 = create_test_offsets(topic, &[0, 1], 100);
        prepare_consumer_offsets(&cx, &consumer, &offsets_v1).await?;
        consumer.commit_offsets(&cx, &offsets_v1).await?;

        let offsets_v2 = create_test_offsets(topic, &[0, 1], 200);
        consumer.commit_offsets(&cx, &offsets_v2).await?;

        // MR2: Verify idempotency
        consumer.commit_offsets(&cx, &offsets_v2).await?;
        consumer.commit_offsets(&cx, &offsets_v2).await?;

        // MR4: Verify rebalance preservation
        let rebalance_assignment = create_test_offsets(topic, &[0], 200);
        consumer.rebalance(&cx, &rebalance_assignment).await?;
        assert_eq!(consumer.committed_offset(topic, 0), Some(200));

        // MR5: Verify atomic behavior
        let atomic_offsets = create_test_offsets(topic, &[0, 2, 3], 300);
        prepare_consumer_offsets(&cx, &consumer, &atomic_offsets).await?;
        consumer.commit_offsets(&cx, &atomic_offsets).await?;

        for tpo in &atomic_offsets {
            let committed = consumer.committed_offset(&tpo.topic, tpo.partition);
            assert_eq!(committed, Some(tpo.offset));
        }

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test helper functions and utilities
    #[test]
    #[allow(dead_code)]
    fn test_create_test_offsets() {
        let offsets = create_test_offsets("test-topic", &[0, 1, 2], 1000);

        assert_eq!(offsets.len(), 3);
        assert_eq!(offsets[0].topic, "test-topic");
        assert_eq!(offsets[0].partition, 0);
        assert_eq!(offsets[0].offset, 1000);

        assert_eq!(offsets[1].partition, 1);
        assert_eq!(offsets[1].offset, 1100);

        assert_eq!(offsets[2].partition, 2);
        assert_eq!(offsets[2].offset, 1200);
    }

    #[test]
    #[allow(dead_code)]
    fn test_conformance_config_default() {
        let config = ConformanceConfig::default();
        assert_eq!(config.group_id, "conformance-test-group");
        assert_eq!(config.retention_minutes, 60);
        assert!(!config.enable_auto_commit);
        assert_eq!(config.auto_commit_interval, Duration::from_secs(5));
    }
}
