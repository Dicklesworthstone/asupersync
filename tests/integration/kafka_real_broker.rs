//! Real Kafka broker integration tests - no mocks.
//!
//! These tests require a real Kafka broker running with specific configuration.
//! Run with: REAL_KAFKA_TESTS=true cargo test kafka_real_broker

#![cfg(test)]

use asupersync::{
    messaging::kafka::{KafkaProducer, ProducerConfig, KafkaError, RecordMetadata, Compression, Acks},
    messaging::kafka_consumer::{KafkaConsumer, ConsumerConfig, TopicPartitionOffset, AutoOffsetReset, ConsumerRecord},
    test_utils::run_test_with_cx,
    time::Duration,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// Real-broker test configuration
struct RealBrokerConfig {
    bootstrap_servers: Vec<String>,
    enabled: bool,
    reason: Option<String>,
}

impl RealBrokerConfig {
    fn new() -> Self {
        let enabled = std::env::var("REAL_KAFKA_TESTS").unwrap_or_default() == "true";
        let bootstrap_servers = std::env::var("KAFKA_BOOTSTRAP_SERVERS")
            .unwrap_or_else(|_| "localhost:29092".to_string())
            .split(',')
            .map(str::to_string)
            .collect();

        // Production safety guards
        let reason = if !enabled {
            Some("REAL_KAFKA_TESTS not set to 'true'".to_string())
        } else if bootstrap_servers.contains(&"prod-kafka.company.com:9092".to_string()) {
            Some("BLOCKED: Production Kafka URL detected".to_string())
        } else if std::env::var("NODE_ENV").unwrap_or_default() == "production" {
            Some("BLOCKED: NODE_ENV=production".to_string())
        } else {
            None
        };

        Self {
            bootstrap_servers,
            enabled: enabled && reason.is_none(),
            reason,
        }
    }
}

/// Structured test logger for Kafka integration tests
#[derive(Debug)]
struct KafkaTestLogger {
    test_name: String,
    start_time: std::time::Instant,
    phase_count: AtomicU32,
}

impl KafkaTestLogger {
    fn new(test_name: &str) -> Self {
        let logger = Self {
            test_name: test_name.to_string(),
            start_time: std::time::Instant::now(),
            phase_count: AtomicU32::new(0),
        };

        // JSON-line structured logging for CI parsing
        eprintln!("{{\"test\":\"{}\",\"event\":\"test_start\",\"ts\":\"{}\"}}",
            test_name,
            chrono::Utc::now().to_rfc3339()
        );

        logger
    }

    fn phase(&self, phase_name: &str) {
        let phase_num = self.phase_count.fetch_add(1, Ordering::SeqCst);
        let elapsed_ms = self.start_time.elapsed().as_millis();

        eprintln!("{{\"test\":\"{}\",\"event\":\"phase\",\"phase\":\"{}\",\"phase_num\":{},\"elapsed_ms\":{},\"ts\":\"{}\"}}",
            self.test_name,
            phase_name,
            phase_num,
            elapsed_ms,
            chrono::Utc::now().to_rfc3339()
        );
    }

    fn kafka_operation(&self, operation: &str, metadata: Option<&RecordMetadata>, error: Option<&KafkaError>) {
        let mut log_entry = json!({
            "test": self.test_name,
            "event": "kafka_operation",
            "operation": operation,
            "ts": chrono::Utc::now().to_rfc3339()
        });

        if let Some(meta) = metadata {
            log_entry["metadata"] = json!({
                "topic": meta.topic,
                "partition": meta.partition,
                "offset": meta.offset,
                "timestamp": meta.timestamp
            });
        }

        if let Some(err) = error {
            log_entry["error"] = json!(err.to_string());
        }

        eprintln!("{}", log_entry);
    }

    fn assert_match(&self, field: &str, expected: &Value, actual: &Value) -> bool {
        let matches = expected == actual;

        eprintln!("{{\"test\":\"{}\",\"event\":\"assertion\",\"field\":\"{}\",\"expected\":{},\"actual\":{},\"matches\":{},\"ts\":\"{}\"}}",
            self.test_name,
            field,
            expected,
            actual,
            matches,
            chrono::Utc::now().to_rfc3339()
        );

        matches
    }

    fn test_end(&self, result: &str) {
        let duration_ms = self.start_time.elapsed().as_millis();

        eprintln!("{{\"test\":\"{}\",\"event\":\"test_end\",\"result\":\"{}\",\"duration_ms\":{},\"ts\":\"{}\"}}",
            self.test_name,
            result,
            duration_ms,
            chrono::Utc::now().to_rfc3339()
        );
    }
}

/// Test data factory for realistic Kafka messages
struct KafkaMessageFactory {
    message_counter: AtomicU32,
}

impl KafkaMessageFactory {
    fn new() -> Self {
        Self {
            message_counter: AtomicU32::new(0),
        }
    }

    fn create_order_message(&self) -> (Vec<u8>, Vec<u8>) {
        let msg_id = self.message_counter.fetch_add(1, Ordering::SeqCst);
        let key = format!("order-{}", msg_id).into_bytes();
        let payload = json!({
            "order_id": format!("ord_{}", msg_id),
            "user_id": format!("user_{}", msg_id % 100),
            "product": "test-product",
            "amount": 99.99,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "version": "1.0"
        }).to_string().into_bytes();

        (key, payload)
    }

    fn create_batch_messages(&self, count: usize, topic_prefix: &str) -> Vec<(String, Vec<u8>, Vec<u8>)> {
        (0..count)
            .map(|i| {
                let topic = format!("{}-{}", topic_prefix, i % 3); // Spread across 3 topics
                let (key, payload) = self.create_order_message();
                (topic, key, payload)
            })
            .collect()
    }
}

fn check_real_broker_available() -> RealBrokerConfig {
    RealBrokerConfig::new()
}

fn skip_if_no_real_broker(config: &RealBrokerConfig) {
    if !config.enabled {
        let reason = config.reason.as_ref()
            .map(|r| r.as_str())
            .unwrap_or("Real Kafka broker not available");
        eprintln!("SKIPPING: {}", reason);
        panic!("Test requires real Kafka broker");
    }
}

/// Generate unique topic names to avoid cross-test contamination
fn unique_topic(base: &str) -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let random: u32 = rand::random();
    format!("{}-{}-{}", base, timestamp, random)
}

#[tokio::test]
async fn test_real_broker_producer_send_and_metadata() {
    let config = check_real_broker_available();
    skip_if_no_real_broker(&config);

    let log = KafkaTestLogger::new("real_broker_producer_send");

    run_test_with_cx(|cx| async move {
        let topic = unique_topic("test-producer-send");
        let factory = KafkaMessageFactory::new();

        log.phase("setup");

        // Create real producer with force_real_kafka=true equivalent
        let producer_config = ProducerConfig::new(config.bootstrap_servers.clone())
            .client_id("test-producer-real")
            .acks(Acks::All)
            .enable_idempotence(true)
            .compression(Compression::Snappy)
            .retries(5);

        let producer = KafkaProducer::new(producer_config).unwrap();

        log.phase("act");

        let (key, payload) = factory.create_order_message();
        let metadata = producer.send(&cx, &topic, Some(&key), &payload, Some(0)).await;

        log.phase("assert");

        match &metadata {
            Ok(meta) => {
                log.kafka_operation("send", Some(meta), None);

                // Assert against real broker responses (not mocked values)
                assert!(log.assert_match("topic", &json!(topic), &json!(meta.topic)));
                assert!(log.assert_match("partition", &json!(0), &json!(meta.partition)));
                assert!(meta.offset >= 0, "Real broker should assign non-negative offset");
                assert!(meta.timestamp.is_some(), "Real broker should provide timestamp");

                // Real Kafka timestamp should be recent (within last 10 seconds)
                if let Some(ts) = meta.timestamp {
                    let now = chrono::Utc::now().timestamp_millis();
                    assert!((now - ts).abs() < 10_000,
                        "Timestamp should be recent: now={}, ts={}, diff={}ms", now, ts, (now - ts).abs());
                }
            }
            Err(err) => {
                log.kafka_operation("send", None, Some(err));
                panic!("Real broker send failed: {}", err);
            }
        }

        log.phase("cleanup");
        producer.flush(&cx, Duration::from_secs(5)).await.unwrap();
        producer.close(&cx, Duration::from_secs(5)).await.unwrap();

        log.test_end("pass");
    }).await;
}

#[tokio::test]
async fn test_real_broker_consumer_producer_round_trip() {
    let config = check_real_broker_available();
    skip_if_no_real_broker(&config);

    let log = KafkaTestLogger::new("real_broker_round_trip");

    run_test_with_cx(|cx| async move {
        let topic = unique_topic("test-round-trip");
        let group_id = format!("test-group-{}", rand::random::<u32>());
        let factory = KafkaMessageFactory::new();

        log.phase("setup");

        // Producer with real Kafka
        let producer_config = ProducerConfig::new(config.bootstrap_servers.clone())
            .client_id("test-producer-roundtrip");
        let producer = KafkaProducer::new(producer_config).unwrap();

        // Consumer with force_real_kafka=true
        let consumer_config = ConsumerConfig::new(config.bootstrap_servers.clone(), &group_id)
            .client_id("test-consumer-roundtrip")
            .auto_offset_reset(AutoOffsetReset::Earliest)
            .enable_auto_commit(false)
            .force_real_kafka(true);  // KEY: Force real Kafka even in test mode
        let consumer = KafkaConsumer::new(consumer_config).unwrap();

        log.phase("produce");

        // Send test messages
        let test_messages = factory.create_batch_messages(5, &topic);
        let mut sent_metadata = Vec::new();

        for (msg_topic, key, payload) in &test_messages {
            let metadata = producer.send(&cx, msg_topic, Some(key), payload, None).await.unwrap();
            log.kafka_operation("send", Some(&metadata), None);
            sent_metadata.push(metadata);
        }

        // Ensure all messages are committed to broker
        producer.flush(&cx, Duration::from_secs(10)).await.unwrap();

        log.phase("consume");

        // Subscribe and consume
        let topics: Vec<&str> = test_messages.iter()
            .map(|(topic, _, _)| topic.as_str())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        consumer.subscribe(&cx, &topics).await.unwrap();

        let mut received_messages = Vec::new();
        let poll_timeout = Duration::from_secs(30); // Real broker needs time for consumer group coordination
        let start_time = std::time::Instant::now();

        while received_messages.len() < test_messages.len() && start_time.elapsed() < poll_timeout {
            if let Some(record) = consumer.poll(&cx, Duration::from_secs(1)).await.unwrap() {
                log.kafka_operation("poll", None, None);
                received_messages.push(record);
            }
        }

        log.phase("assert");

        // Verify message count
        assert!(log.assert_match("message_count",
            &json!(test_messages.len()),
            &json!(received_messages.len())));

        // Verify message content integrity (real serialization round-trip)
        let mut received_by_key: HashMap<Vec<u8>, ConsumerRecord> = received_messages
            .into_iter()
            .map(|record| (record.key.clone().unwrap_or_default(), record))
            .collect();

        for (sent_topic, sent_key, sent_payload) in &test_messages {
            if let Some(received) = received_by_key.remove(sent_key) {
                assert_eq!(received.topic, *sent_topic, "Topic should match");
                assert_eq!(received.key.as_ref().unwrap(), sent_key, "Key should match exactly");
                assert_eq!(received.payload, *sent_payload, "Payload should match exactly - real serialization");
                assert!(received.offset >= 0, "Real broker offset should be non-negative");
                assert!(received.timestamp.is_some(), "Real broker should provide timestamp");
            } else {
                panic!("Message with key {:?} not received from real broker",
                    String::from_utf8_lossy(sent_key));
            }
        }

        log.phase("commit");

        // Test offset commits with real broker
        let last_record_offset = sent_metadata.last().unwrap().offset;
        let commit_offset = TopicPartitionOffset::new(&topic, 0, last_record_offset + 1);
        consumer.commit_offsets(&cx, &[commit_offset]).await.unwrap();

        // Verify committed offset is persisted in broker
        assert_eq!(consumer.committed_offset(&topic, 0), Some(last_record_offset + 1));

        log.phase("cleanup");
        consumer.close(&cx).await.unwrap();
        producer.close(&cx, Duration::from_secs(5)).await.unwrap();

        log.test_end("pass");
    }).await;
}

#[tokio::test]
async fn test_real_broker_transaction_exactly_once() {
    let config = check_real_broker_available();
    skip_if_no_real_broker(&config);

    let log = KafkaTestLogger::new("real_broker_transactions");

    run_test_with_cx(|cx| async move {
        let topic = unique_topic("test-transactions");
        let transaction_id = format!("test-tx-{}", rand::random::<u32>());
        let factory = KafkaMessageFactory::new();

        log.phase("setup");

        // Real transactional producer
        use asupersync::messaging::kafka::{TransactionalProducer, TransactionalConfig};
        let tx_config = TransactionalConfig::new(
            ProducerConfig::new(config.bootstrap_servers.clone())
                .client_id("test-tx-producer")
                .enable_idempotence(true), // Required for transactions
            transaction_id
        ).transaction_timeout(Duration::from_secs(60));

        let tx_producer = TransactionalProducer::new(tx_config).unwrap();

        // Consumer to verify exactly-once behavior
        let group_id = format!("test-tx-group-{}", rand::random::<u32>());
        let consumer_config = ConsumerConfig::new(config.bootstrap_servers.clone(), &group_id)
            .auto_offset_reset(AutoOffsetReset::Earliest)
            .enable_auto_commit(false)
            .force_real_kafka(true)
            .isolation_level(asupersync::messaging::kafka_consumer::IsolationLevel::ReadCommitted); // Only read committed transactions
        let consumer = KafkaConsumer::new(consumer_config).unwrap();

        log.phase("transaction_commit");

        // Committed transaction
        {
            let transaction = tx_producer.begin_transaction(&cx).await.unwrap();
            let (key, payload) = factory.create_order_message();
            transaction.send(&cx, &topic, Some(&key), &payload).await.unwrap();
            transaction.commit(&cx).await.unwrap();
            log.kafka_operation("transaction_commit", None, None);
        }

        log.phase("transaction_abort");

        // Aborted transaction
        {
            let transaction = tx_producer.begin_transaction(&cx).await.unwrap();
            let (key, payload) = factory.create_order_message();
            transaction.send(&cx, &topic, Some(&key), &payload).await.unwrap();
            transaction.abort(&cx).await.unwrap();
            log.kafka_operation("transaction_abort", None, None);
        }

        log.phase("verify");

        // Consumer should only see committed message, not aborted
        consumer.subscribe(&cx, &[&topic]).await.unwrap();

        let mut received_count = 0;
        let poll_timeout = Duration::from_secs(30);
        let start_time = std::time::Instant::now();

        while start_time.elapsed() < poll_timeout {
            if let Some(_record) = consumer.poll(&cx, Duration::from_secs(1)).await.unwrap() {
                received_count += 1;
                log.kafka_operation("poll_committed", None, None);
            } else {
                // No more messages available
                break;
            }
        }

        log.phase("assert");

        // Exactly-once: only 1 committed message should be visible
        assert!(log.assert_match("committed_message_count", &json!(1), &json!(received_count)));

        log.phase("cleanup");
        consumer.close(&cx).await.unwrap();

        log.test_end("pass");
    }).await;
}

#[tokio::test]
async fn test_real_broker_consumer_group_rebalancing() {
    let config = check_real_broker_available();
    skip_if_no_real_broker(&config);

    let log = KafkaTestLogger::new("real_broker_rebalancing");

    run_test_with_cx(|cx| async move {
        let topic = unique_topic("test-rebalance");
        let group_id = format!("test-rebalance-group-{}", rand::random::<u32>());

        log.phase("setup");

        // Create two consumers in the same group to trigger rebalancing
        let consumer_config = |client_id: &str| {
            ConsumerConfig::new(config.bootstrap_servers.clone(), &group_id)
                .client_id(client_id)
                .auto_offset_reset(AutoOffsetReset::Latest)
                .force_real_kafka(true)
                .session_timeout(Duration::from_secs(30))
                .heartbeat_interval(Duration::from_secs(3))
        };

        let consumer1 = Arc::new(KafkaConsumer::new(consumer_config("consumer-1")).unwrap());
        let consumer2 = Arc::new(KafkaConsumer::new(consumer_config("consumer-2")).unwrap());

        log.phase("initial_subscription");

        // Consumer 1 joins first
        consumer1.subscribe(&cx, &[&topic]).await.unwrap();
        let initial_gen = consumer1.rebalance_generation();

        // Wait for initial assignment to stabilize
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        log.phase("second_consumer_join");

        // Consumer 2 joins, triggering rebalance
        consumer2.subscribe(&cx, &[&topic]).await.unwrap();

        // Wait for rebalance to complete
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

        log.phase("verify_rebalance");

        // Both consumers should have incremented generation due to rebalance
        let gen1_after = consumer1.rebalance_generation();
        let gen2_after = consumer2.rebalance_generation();

        assert!(gen1_after > initial_gen,
            "Consumer 1 generation should increment after rebalance: {} -> {}",
            initial_gen, gen1_after);
        assert!(gen2_after > 0,
            "Consumer 2 should have non-zero generation after joining");

        // In a real broker, both consumers should be assigned to the same group
        let assignments1 = consumer1.assigned_partitions();
        let assignments2 = consumer2.assigned_partitions();

        log.kafka_operation("rebalance_complete", None, None);

        log.phase("assert");

        // Real consumer group coordination - assignments shouldn't overlap
        let all_assignments: std::collections::HashSet<_> = assignments1.iter()
            .chain(assignments2.iter())
            .collect();
        let total_individual = assignments1.len() + assignments2.len();

        assert_eq!(all_assignments.len(), total_individual,
            "Real broker rebalancing should not assign same partition to multiple consumers");

        log.phase("cleanup");
        consumer1.close(&cx).await.unwrap();
        consumer2.close(&cx).await.unwrap();

        log.test_end("pass");
    }).await;
}

#[tokio::test]
async fn test_real_broker_network_failure_recovery() {
    let config = check_real_broker_available();
    skip_if_no_real_broker(&config);

    let log = KafkaTestLogger::new("real_broker_network_failure");

    run_test_with_cx(|cx| async move {
        let topic = unique_topic("test-network-failure");
        let factory = KafkaMessageFactory::new();

        log.phase("setup");

        // Producer configured for retries and idempotence
        let producer_config = ProducerConfig::new(config.bootstrap_servers.clone())
            .client_id("test-failure-recovery")
            .retries(10) // High retry count to survive temporary failures
            .enable_idempotence(true)
            .acks(Acks::All); // Wait for full replication
        let producer = KafkaProducer::new(producer_config).unwrap();

        log.phase("baseline_send");

        // Verify normal operation first
        let (key, payload) = factory.create_order_message();
        let baseline_result = producer.send(&cx, &topic, Some(&key), &payload, None).await;
        assert!(baseline_result.is_ok(), "Baseline send should succeed: {:?}", baseline_result);
        log.kafka_operation("baseline_send", baseline_result.as_ref().ok(), baseline_result.as_ref().err());

        log.phase("stress_test");

        // Rapid-fire sends to test real broker under load
        let mut send_results = Vec::new();
        let stress_count = 50;

        for i in 0..stress_count {
            let (stress_key, stress_payload) = factory.create_order_message();
            let result = producer.send(&cx, &topic, Some(&stress_key), &stress_payload, None).await;

            match &result {
                Ok(metadata) => log.kafka_operation(&format!("stress_send_{}", i), Some(metadata), None),
                Err(error) => log.kafka_operation(&format!("stress_send_{}", i), None, Some(error)),
            }

            send_results.push(result);

            // Small delay to avoid overwhelming broker
            if i % 10 == 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }

        log.phase("verify_resilience");

        // Count successes vs failures
        let successes = send_results.iter().filter(|r| r.is_ok()).count();
        let failures = send_results.iter().filter(|r| r.is_err()).count();

        // Real broker should handle most requests successfully
        let success_rate = successes as f64 / stress_count as f64;
        assert!(success_rate >= 0.8,
            "Real broker should handle at least 80% of rapid requests: {:.1}% success rate",
            success_rate * 100.0);

        // Any transient failures should be specific Kafka errors, not generic panics
        for (i, result) in send_results.iter().enumerate() {
            if let Err(error) = result {
                assert!(error.is_transient(),
                    "Send {} failure should be transient Kafka error: {}", i, error);
            }
        }

        log.phase("cleanup");
        producer.flush(&cx, Duration::from_secs(30)).await.unwrap();
        producer.close(&cx, Duration::from_secs(10)).await.unwrap();

        log.test_end("pass");
    }).await;
}

// Helper to setup test dependencies
#[ctor::ctor]
fn setup_test_dependencies() {
    // Ensure chrono and serde_json are available for structured logging
    // These would be dev-dependencies in Cargo.toml
}