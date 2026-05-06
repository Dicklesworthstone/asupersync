//! Real Kafka broker integration tests - no mocks.
//!
//! These tests require a real Kafka broker running with specific configuration.
//! Run with:
//! `REAL_KAFKA_TESTS=true cargo test --features kafka --test kafka_real_broker -- --nocapture`

#![cfg(test)]

use asupersync::{
    messaging::kafka::{
        Acks, Compression, KafkaError, KafkaProducer, ProducerConfig, RecordMetadata,
    },
    messaging::kafka_consumer::{
        AutoOffsetReset, ConsumerConfig, ConsumerRecord, KafkaConsumer, TopicPartitionOffset,
    },
    test_utils::run_test_with_cx,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const KAFKA_BROKER_PARITY_BEAD_ID: &str = "asupersync-0xbecl";

/// Real-broker test configuration
struct RealBrokerConfig {
    bootstrap_servers: Vec<String>,
    enabled: bool,
    reason: Option<String>,
}

impl RealBrokerConfig {
    fn new() -> Self {
        let enabled = std::env::var("REAL_KAFKA_TESTS").unwrap_or_default() == "true";
        let bootstrap_servers: Vec<String> = std::env::var("KAFKA_BOOTSTRAP_SERVERS")
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
        eprintln!(
            "{{\"test\":\"{}\",\"event\":\"test_start\",\"ts\":\"{}\"}}",
            test_name,
            chrono::Utc::now().to_rfc3339()
        );

        logger
    }

    fn phase(&self, phase_name: &str) {
        let phase_num = self.phase_count.fetch_add(1, Ordering::SeqCst);
        let elapsed_ms = self.start_time.elapsed().as_millis();

        eprintln!(
            "{{\"test\":\"{}\",\"event\":\"phase\",\"phase\":\"{}\",\"phase_num\":{},\"elapsed_ms\":{},\"ts\":\"{}\"}}",
            self.test_name,
            phase_name,
            phase_num,
            elapsed_ms,
            chrono::Utc::now().to_rfc3339()
        );
    }

    fn kafka_operation(
        &self,
        operation: &str,
        metadata: Option<&RecordMetadata>,
        error: Option<&KafkaError>,
    ) {
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

        eprintln!(
            "{{\"test\":\"{}\",\"event\":\"assertion\",\"field\":\"{}\",\"expected\":{},\"actual\":{},\"matches\":{},\"ts\":\"{}\"}}",
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

        eprintln!(
            "{{\"test\":\"{}\",\"event\":\"test_end\",\"result\":\"{}\",\"duration_ms\":{},\"ts\":\"{}\"}}",
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
        })
        .to_string()
        .into_bytes();

        (key, payload)
    }

    fn create_batch_messages(
        &self,
        count: usize,
        topic_prefix: &str,
    ) -> Vec<(String, Vec<u8>, Vec<u8>)> {
        (0..count)
            .map(|i| {
                let topic = format!("{}-{}", topic_prefix, i % 3); // Spread across 3 topics
                let (key, payload) = self.create_order_message();
                (topic, key, payload)
            })
            .collect()
    }

    /// Create payment settlement message (critical financial data).
    fn create_payment_settle_message(
        &self,
        user_id: &str,
        amount_cents: u64,
    ) -> (Vec<u8>, Vec<u8>) {
        let msg_id = self.message_counter.fetch_add(1, Ordering::SeqCst);
        let key = format!("payment-{}", user_id).into_bytes();
        let payload = json!({
            "type": "payment.settle",
            "user_id": user_id,
            "amount_cents": amount_cents,
            "transaction_id": format!("txn_settle_{}", msg_id),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "payment_method": "credit_card",
            "currency": "USD",
            "version": "1.0"
        })
        .to_string()
        .into_bytes();

        (key, payload)
    }

    /// Create payment charge message.
    fn create_payment_charge_message(
        &self,
        user_id: &str,
        amount_cents: u64,
    ) -> (Vec<u8>, Vec<u8>) {
        let msg_id = self.message_counter.fetch_add(1, Ordering::SeqCst);
        let key = format!("payment-{}", user_id).into_bytes();
        let payload = json!({
            "type": "payment.charge",
            "user_id": user_id,
            "amount_cents": amount_cents,
            "transaction_id": format!("txn_charge_{}", msg_id),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "payment_method": "debit_card",
            "currency": "USD",
            "version": "1.0"
        })
        .to_string()
        .into_bytes();

        (key, payload)
    }

    /// Create payment refund message.
    fn create_payment_refund_message(
        &self,
        user_id: &str,
        amount_cents: u64,
    ) -> (Vec<u8>, Vec<u8>) {
        let msg_id = self.message_counter.fetch_add(1, Ordering::SeqCst);
        let key = format!("payment-{}", user_id).into_bytes();
        let payload = json!({
            "type": "payment.refund",
            "user_id": user_id,
            "amount_cents": amount_cents,
            "transaction_id": format!("txn_refund_{}", msg_id),
            "original_transaction_id": format!("txn_charge_{}", msg_id - 1),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "reason": "customer_request",
            "currency": "USD",
            "version": "1.0"
        })
        .to_string()
        .into_bytes();

        (key, payload)
    }

    /// Create transaction message for abort/replay testing.
    #[allow(dead_code)]
    fn create_transaction_message(
        &self,
        transaction_id: &str,
        transaction_type: &str,
        amount: u64,
    ) -> (Vec<u8>, Vec<u8>) {
        let key = transaction_id.to_string().into_bytes();
        let payload = json!({
            "transaction_id": transaction_id,
            "type": transaction_type,
            "amount": amount,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "account_id": "acc_test_12345",
            "version": "1.0"
        })
        .to_string()
        .into_bytes();

        (key, payload)
    }

    /// Create payment message with sequence for ordering tests.
    #[allow(dead_code)]
    fn create_payment_message_with_sequence(
        &self,
        user_id: &str,
        payment_type: &str,
        amount_cents: u64,
        sequence: u64,
    ) -> (Vec<u8>, Vec<u8>) {
        let key = format!("payment-{}", user_id).into_bytes();
        let payload = json!({
            "type": format!("payment.{}", payment_type),
            "user_id": user_id,
            "amount_cents": amount_cents,
            "sequence": sequence,
            "transaction_id": format!("txn_{}_{}", payment_type, sequence),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "currency": "USD",
            "version": "1.0"
        })
        .to_string()
        .into_bytes();

        (key, payload)
    }
}

fn require_real_broker() -> Option<RealBrokerConfig> {
    let config = RealBrokerConfig::new();
    if !config.enabled {
        let reason = config
            .reason
            .as_deref()
            .unwrap_or("Real Kafka broker not available");
        eprintln!("SKIPPING: {}", reason);
        return None;
    }
    Some(config)
}

/// Generate unique topic names to avoid cross-test contamination
fn unique_topic(base: &str) -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let random = fastrand::u32(..);
    format!("{}-{}-{}", base, timestamp, random)
}

fn kafka_broker_proof_artifact_path() -> String {
    std::env::var("ASUPERSYNC_KAFKA_BROKER_PARITY_PROOF_DIR")
        .unwrap_or_else(|_| "target/kafka-broker-parity-proof/asupersync-0xbecl".to_string())
}

fn kafka_broker_proof_features() -> Value {
    json!({
        "kafka": cfg!(feature = "kafka"),
        "test_internals": cfg!(feature = "test-internals")
    })
}

fn kafka_auth_mode() -> &'static str {
    if std::env::var_os("KAFKA_SASL_USERNAME").is_some()
        || std::env::var_os("KAFKA_SASL_PASSWORD").is_some()
        || std::env::var_os("KAFKA_SASL_MECHANISM").is_some()
    {
        "sasl"
    } else {
        "plaintext"
    }
}

fn redact_bootstrap_server(server: &str) -> String {
    let trimmed = server.trim();
    if let Some((_, host)) = trimmed.rsplit_once('@') {
        format!("redacted@{host}")
    } else {
        trimmed.to_string()
    }
}

fn redacted_bootstrap_servers(servers: &[String]) -> Value {
    json!(
        servers
            .iter()
            .map(|server| redact_bootstrap_server(server))
            .collect::<Vec<_>>()
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_kafka_broker_proof_row(
    scenario_id: &str,
    broker_version: &str,
    connection_uri_redacted: Value,
    topic_or_stream: &str,
    message_count: usize,
    ack_count: usize,
    consumer_lag: i64,
    reconnect_count: usize,
    cancellation_point: &str,
    expected_result: &str,
    actual_result: &str,
    unsupported_reason: &str,
    verdict: &str,
    first_failure: &str,
) {
    println!(
        "{}",
        json!({
            "bead_id": KAFKA_BROKER_PARITY_BEAD_ID,
            "broker_kind": "kafka",
            "broker_version": broker_version,
            "scenario_id": scenario_id,
            "feature_flags": kafka_broker_proof_features(),
            "connection_uri_redacted": connection_uri_redacted,
            "auth_mode": kafka_auth_mode(),
            "topic_or_stream": topic_or_stream,
            "message_count": message_count,
            "ack_count": ack_count,
            "consumer_lag": consumer_lag,
            "reconnect_count": reconnect_count,
            "cancellation_point": cancellation_point,
            "expected_result": expected_result,
            "actual_result": actual_result,
            "artifact_path": kafka_broker_proof_artifact_path(),
            "unsupported_reason": unsupported_reason,
            "verdict": verdict,
            "first_failure": first_failure
        })
    );
}

#[test]
fn kafka_broker_parity_default_feature_gate_logs_required_fields() {
    let config = ProducerConfig::new(vec!["localhost:9092".to_string()]).require_kafka_feature();
    let result = config.validate();

    #[cfg(feature = "kafka")]
    let (actual_result, verdict, first_failure) = if result.is_ok() {
        (
            "kafka feature enabled; real broker lane must run separately",
            "pass",
            "",
        )
    } else {
        (
            "kafka feature enabled but feature requirement validation failed",
            "fail",
            "feature requirement rejected with kafka feature enabled",
        )
    };

    #[cfg(not(feature = "kafka"))]
    let (actual_result, verdict, first_failure) = match result {
        Err(KafkaError::FeatureDisabled) => (
            "default build rejects real Kafka requirement with FeatureDisabled",
            "pass",
            "",
        ),
        Ok(()) => (
            "default build accepted real Kafka requirement",
            "fail",
            "default build must fail closed for required Kafka feature",
        ),
        Err(_) => (
            "default build rejected real Kafka requirement with unexpected error",
            "fail",
            "unexpected error kind for missing kafka feature",
        ),
    };

    emit_kafka_broker_proof_row(
        "kafka-default-feature-gate",
        "n/a",
        redacted_bootstrap_servers(&config.bootstrap_servers),
        "",
        0,
        0,
        0,
        0,
        "feature-gate",
        "default build fails closed for real Kafka broker requirement",
        actual_result,
        "",
        verdict,
        first_failure,
    );

    assert_eq!(verdict, "pass");
}

#[derive(Debug)]
struct KafkaBrokerProofOutcome {
    message_count: usize,
    ack_count: usize,
    consumer_lag: i64,
}

async fn run_kafka_broker_parity_roundtrip(
    cx: &asupersync::cx::Cx,
    bootstrap_servers: Vec<String>,
    topic: &str,
) -> Result<KafkaBrokerProofOutcome, String> {
    let producer_config = ProducerConfig::new(bootstrap_servers.clone())
        .client_id("asupersync-kafka-parity-producer")
        .acks(Acks::All)
        .enable_idempotence(true)
        .retries(3)
        .allow_insecure_transport_for_testing(true)
        .require_kafka_feature();
    let producer = KafkaProducer::new(producer_config).map_err(|error| error.to_string())?;

    let group_id = format!("asupersync-kafka-parity-{}", fastrand::u32(..));
    let consumer_config = ConsumerConfig::new(bootstrap_servers, &group_id)
        .client_id("asupersync-kafka-parity-consumer")
        .auto_offset_reset(AutoOffsetReset::Earliest)
        .enable_auto_commit(false)
        .max_poll_records(1)
        .force_real_kafka(true)
        .allow_insecure_transport_for_testing(true);
    let consumer = KafkaConsumer::new(consumer_config).map_err(|error| error.to_string())?;

    let result: Result<KafkaBrokerProofOutcome, String> = async {
        consumer
            .subscribe(cx, &[topic])
            .await
            .map_err(|error| error.to_string())?;
        consumer
            .rebalance(cx, &[TopicPartitionOffset::new(topic, 0, 0)])
            .await
            .map_err(|error| error.to_string())?;

        let key = b"asupersync-kafka-proof-key".to_vec();
        let payload = b"asupersync-kafka-proof-payload".to_vec();
        let metadata = producer
            .send(cx, topic, Some(&key), &payload, Some(0))
            .await
            .map_err(|error| error.to_string())?;
        producer
            .flush(cx, Duration::from_secs(10))
            .await
            .map_err(|error| error.to_string())?;

        let poll_deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut received = None;
        while std::time::Instant::now() < poll_deadline {
            if let Some(record) = consumer
                .poll(cx, Duration::from_secs(1))
                .await
                .map_err(|error| error.to_string())?
                && record.topic == topic
                && record.key.as_deref() == Some(key.as_slice())
                && record.payload == payload
            {
                received = Some(record);
                break;
            }
        }

        let record = received.ok_or_else(|| {
            "timed out waiting for matching record from real Kafka broker".to_string()
        })?;
        consumer
            .commit_offsets(
                cx,
                &[TopicPartitionOffset::new(
                    record.topic.clone(),
                    record.partition,
                    record.offset + 1,
                )],
            )
            .await
            .map_err(|error| error.to_string())?;

        let committed = consumer
            .committed_offset(&record.topic, record.partition)
            .ok_or_else(|| "committed offset not visible after commit".to_string())?;
        let consumer_lag = metadata.offset.saturating_add(1).saturating_sub(committed);

        Ok(KafkaBrokerProofOutcome {
            message_count: 1,
            ack_count: usize::from(metadata.offset >= 0),
            consumer_lag,
        })
    }
    .await;

    let consumer_close = consumer.close(cx).await.map_err(|error| error.to_string());
    let producer_close = producer
        .close(cx, Duration::from_secs(10))
        .await
        .map_err(|error| error.to_string());

    let outcome = result?;
    consumer_close?;
    producer_close?;

    Ok(outcome)
}

#[test]
fn kafka_broker_parity_real_broker_proof_row() {
    let config = RealBrokerConfig::new();
    let redacted_servers = redacted_bootstrap_servers(&config.bootstrap_servers);
    let topic = unique_topic("asupersync-kafka-parity");

    if !config.enabled {
        let unsupported_reason = config
            .reason
            .as_deref()
            .unwrap_or("real Kafka broker unavailable");
        emit_kafka_broker_proof_row(
            "kafka-producer-consumer-roundtrip",
            "unavailable",
            redacted_servers,
            &topic,
            0,
            0,
            0,
            0,
            "broker-availability",
            "real broker producer send, consumer receive, explicit offset commit, and cleanup",
            "deterministic skip because broker configuration is unavailable",
            unsupported_reason,
            "skip",
            "",
        );
        return;
    }

    let outcome_slot = Arc::new(Mutex::new(None));
    let result_slot = Arc::clone(&outcome_slot);
    let bootstrap_servers = config.bootstrap_servers.clone();
    let topic_for_test = topic.clone();

    run_test_with_cx(|cx| async move {
        let outcome =
            run_kafka_broker_parity_roundtrip(&cx, bootstrap_servers, &topic_for_test).await;
        *result_slot.lock().expect("outcome slot poisoned") = Some(outcome);
    });

    let outcome = outcome_slot
        .lock()
        .expect("outcome slot poisoned")
        .take()
        .expect("Kafka broker proof did not record an outcome");

    match outcome {
        Ok(outcome) => emit_kafka_broker_proof_row(
            "kafka-producer-consumer-roundtrip",
            "unknown",
            redacted_servers,
            &topic,
            outcome.message_count,
            outcome.ack_count,
            outcome.consumer_lag,
            0,
            "producer-consumer-cleanup",
            "real broker producer send, consumer receive, explicit offset commit, and cleanup",
            "message reached broker and was consumed with explicit offset commit",
            "",
            "pass",
            "",
        ),
        Err(error) => {
            emit_kafka_broker_proof_row(
                "kafka-producer-consumer-roundtrip",
                "unknown",
                redacted_servers,
                &topic,
                0,
                0,
                0,
                0,
                "producer-consumer-cleanup",
                "real broker producer send, consumer receive, explicit offset commit, and cleanup",
                "real broker proof failed",
                "",
                "fail",
                &error,
            );
            panic!("Kafka broker parity proof failed: {error}");
        }
    }
}

#[test]
fn test_real_broker_producer_send_and_metadata() {
    let Some(config) = require_real_broker() else {
        return;
    };

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
        let metadata = producer
            .send(&cx, &topic, Some(&key), &payload, Some(0))
            .await;

        log.phase("assert");

        match &metadata {
            Ok(meta) => {
                log.kafka_operation("send", Some(meta), None);

                // Assert against real broker responses (not mocked values)
                assert!(log.assert_match("topic", &json!(topic), &json!(meta.topic)));
                assert!(log.assert_match("partition", &json!(0), &json!(meta.partition)));
                assert!(
                    meta.offset >= 0,
                    "Real broker should assign non-negative offset"
                );
                assert!(
                    meta.timestamp.is_some(),
                    "Real broker should provide timestamp"
                );

                // Real Kafka timestamp should be recent (within last 10 seconds)
                if let Some(ts) = meta.timestamp {
                    let now = chrono::Utc::now().timestamp_millis();
                    assert!(
                        (now - ts).abs() < 10_000,
                        "Timestamp should be recent: now={}, ts={}, diff={}ms",
                        now,
                        ts,
                        (now - ts).abs()
                    );
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
    });
}

#[test]
fn test_real_broker_consumer_producer_round_trip() {
    let Some(config) = require_real_broker() else {
        return;
    };

    let log = KafkaTestLogger::new("real_broker_round_trip");

    run_test_with_cx(|cx| async move {
        let topic = unique_topic("test-round-trip");
        let group_id = format!("test-group-{}", fastrand::u32(..));
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
            .force_real_kafka(true); // KEY: Force real Kafka even in test mode
        let consumer = KafkaConsumer::new(consumer_config).unwrap();

        log.phase("produce");

        // Send test messages
        let test_messages = factory.create_batch_messages(5, &topic);
        let mut sent_metadata = Vec::new();

        for (msg_topic, key, payload) in &test_messages {
            let metadata = producer
                .send(&cx, msg_topic, Some(key), payload, None)
                .await
                .unwrap();
            log.kafka_operation("send", Some(&metadata), None);
            sent_metadata.push(metadata);
        }

        // Ensure all messages are committed to broker
        producer.flush(&cx, Duration::from_secs(10)).await.unwrap();

        log.phase("consume");

        // Subscribe and consume
        let topics: Vec<&str> = test_messages
            .iter()
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
        assert!(log.assert_match(
            "message_count",
            &json!(test_messages.len()),
            &json!(received_messages.len())
        ));

        // Verify message content integrity (real serialization round-trip)
        let mut received_by_key: HashMap<Vec<u8>, ConsumerRecord> = received_messages
            .into_iter()
            .map(|record| (record.key.clone().unwrap_or_default(), record))
            .collect();

        for (sent_topic, sent_key, sent_payload) in &test_messages {
            if let Some(received) = received_by_key.remove(sent_key) {
                assert_eq!(received.topic, *sent_topic, "Topic should match");
                assert_eq!(
                    received.key.as_ref().unwrap(),
                    sent_key,
                    "Key should match exactly"
                );
                assert_eq!(
                    received.payload, *sent_payload,
                    "Payload should match exactly - real serialization"
                );
                assert!(
                    received.offset >= 0,
                    "Real broker offset should be non-negative"
                );
                assert!(
                    received.timestamp.is_some(),
                    "Real broker should provide timestamp"
                );
            } else {
                panic!(
                    "Message with key {:?} not received from real broker",
                    String::from_utf8_lossy(sent_key)
                );
            }
        }

        log.phase("commit");

        // Test offset commits with real broker
        let last_record_offset = sent_metadata.last().unwrap().offset;
        let commit_offset = TopicPartitionOffset::new(&topic, 0, last_record_offset + 1);
        consumer
            .commit_offsets(&cx, &[commit_offset])
            .await
            .unwrap();

        // Verify committed offset is persisted in broker
        assert_eq!(
            consumer.committed_offset(&topic, 0),
            Some(last_record_offset + 1)
        );

        log.phase("cleanup");
        consumer.close(&cx).await.unwrap();
        producer.close(&cx, Duration::from_secs(5)).await.unwrap();

        log.test_end("pass");
    });
}

#[test]
fn test_real_broker_transaction_exactly_once() {
    let Some(config) = require_real_broker() else {
        return;
    };

    let log = KafkaTestLogger::new("real_broker_transactions");

    run_test_with_cx(|cx| async move {
        let topic = unique_topic("test-transactions");
        let transaction_id = format!("test-tx-{}", fastrand::u32(..));
        let factory = KafkaMessageFactory::new();

        log.phase("setup");

        // Real transactional producer
        use asupersync::messaging::kafka::{TransactionalConfig, TransactionalProducer};
        let tx_config = TransactionalConfig::new(
            ProducerConfig::new(config.bootstrap_servers.clone())
                .client_id("test-tx-producer")
                .enable_idempotence(true), // Required for transactions
            transaction_id,
        )
        .transaction_timeout(Duration::from_secs(60));

        let tx_producer = TransactionalProducer::new(tx_config).unwrap();

        // Consumer to verify exactly-once behavior
        let group_id = format!("test-tx-group-{}", fastrand::u32(..));
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
            transaction
                .send(&cx, &topic, Some(&key), &payload)
                .await
                .unwrap();
            transaction.commit(&cx).await.unwrap();
            log.kafka_operation("transaction_commit", None, None);
        }

        log.phase("transaction_abort");

        // Aborted transaction
        {
            let transaction = tx_producer.begin_transaction(&cx).await.unwrap();
            let (key, payload) = factory.create_order_message();
            transaction
                .send(&cx, &topic, Some(&key), &payload)
                .await
                .unwrap();
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
    });
}

#[test]
fn test_real_broker_consumer_group_rebalancing() {
    let Some(config) = require_real_broker() else {
        return;
    };

    let log = KafkaTestLogger::new("real_broker_rebalancing");

    run_test_with_cx(|cx| async move {
        let topic = unique_topic("test-rebalance");
        let group_id = format!("test-rebalance-group-{}", fastrand::u32(..));

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
        std::thread::sleep(std::time::Duration::from_secs(5));

        log.phase("second_consumer_join");

        // Consumer 2 joins, triggering rebalance
        consumer2.subscribe(&cx, &[&topic]).await.unwrap();

        // Wait for rebalance to complete
        std::thread::sleep(std::time::Duration::from_secs(10));

        log.phase("verify_rebalance");

        // Both consumers should have incremented generation due to rebalance
        let gen1_after = consumer1.rebalance_generation();
        let gen2_after = consumer2.rebalance_generation();

        assert!(
            gen1_after > initial_gen,
            "Consumer 1 generation should increment after rebalance: {} -> {}",
            initial_gen,
            gen1_after
        );
        assert!(
            gen2_after > 0,
            "Consumer 2 should have non-zero generation after joining"
        );

        // In a real broker, both consumers should be assigned to the same group
        let assignments1 = consumer1.assigned_partitions();
        let assignments2 = consumer2.assigned_partitions();

        log.kafka_operation("rebalance_complete", None, None);

        log.phase("assert");

        // Real consumer group coordination - assignments shouldn't overlap
        let all_assignments: std::collections::HashSet<_> =
            assignments1.iter().chain(assignments2.iter()).collect();
        let total_individual = assignments1.len() + assignments2.len();

        assert_eq!(
            all_assignments.len(),
            total_individual,
            "Real broker rebalancing should not assign same partition to multiple consumers"
        );

        log.phase("cleanup");
        consumer1.close(&cx).await.unwrap();
        consumer2.close(&cx).await.unwrap();

        log.test_end("pass");
    });
}

#[test]
fn test_real_broker_network_failure_recovery() {
    let Some(config) = require_real_broker() else {
        return;
    };

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
        assert!(
            baseline_result.is_ok(),
            "Baseline send should succeed: {:?}",
            baseline_result
        );
        log.kafka_operation(
            "baseline_send",
            baseline_result.as_ref().ok(),
            baseline_result.as_ref().err(),
        );

        log.phase("stress_test");

        // Rapid-fire sends to test real broker under load
        let mut send_results = Vec::new();
        let stress_count = 50;

        for i in 0..stress_count {
            let (stress_key, stress_payload) = factory.create_order_message();
            let result = producer
                .send(&cx, &topic, Some(&stress_key), &stress_payload, None)
                .await;

            match &result {
                Ok(metadata) => {
                    log.kafka_operation(&format!("stress_send_{}", i), Some(metadata), None)
                }
                Err(error) => log.kafka_operation(&format!("stress_send_{}", i), None, Some(error)),
            }

            send_results.push(result);

            // Small delay to avoid overwhelming broker
            if i % 10 == 0 {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }

        log.phase("verify_resilience");

        // Count successes vs failures
        let successes = send_results.iter().filter(|r| r.is_ok()).count();
        let _failures = send_results.iter().filter(|r| r.is_err()).count();

        // Real broker should handle most requests successfully
        let success_rate = successes as f64 / stress_count as f64;
        assert!(
            success_rate >= 0.8,
            "Real broker should handle at least 80% of rapid requests: {:.1}% success rate",
            success_rate * 100.0
        );

        // Any transient failures should be specific Kafka errors, not generic panics
        for (i, result) in send_results.iter().enumerate() {
            if let Err(error) = result {
                assert!(
                    error.is_transient(),
                    "Send {} failure should be transient Kafka error: {}",
                    i,
                    error
                );
            }
        }

        log.phase("cleanup");
        producer.flush(&cx, Duration::from_secs(30)).await.unwrap();
        producer.close(&cx, Duration::from_secs(10)).await.unwrap();

        log.test_end("pass");
    });
}

/// Test payment message delivery with real broker (no StubBroker allowed).
/// This test ensures critical financial messages are never lost due to mock semantics.
#[test]
fn test_real_broker_payment_message_delivery() {
    let Some(config) = require_real_broker() else {
        return;
    };

    let log = KafkaTestLogger::new("real_broker_payment_delivery");

    run_test_with_cx(|cx| async move {
        let payment_topic = unique_topic("fabric.payment.settle");
        let factory = KafkaMessageFactory::new();

        log.phase("setup");

        // Producer with maximum safety settings for payment messages
        let producer_config = ProducerConfig::new(config.bootstrap_servers.clone())
            .client_id("payment-producer")
            .acks(Acks::All) // Wait for full replication
            .retries(10)
            .enable_idempotence(true)
            .batch_size(1) // Send immediately, no batching for payments
            .linger_ms(0)
            .compression(Compression::None); // No compression for payment audit trail

        let producer = KafkaProducer::new(producer_config).unwrap();

        // Consumer with strict ordering requirements
        let consumer_config =
            ConsumerConfig::new(config.bootstrap_servers.clone(), "payment-consumer-group")
                .auto_offset_reset(AutoOffsetReset::Earliest)
                .enable_auto_commit(false) // Manual commit for payment processing
                .max_poll_records(1)
                .force_real_kafka(true); // One payment at a time

        let consumer = KafkaConsumer::new(consumer_config).unwrap();
        consumer.subscribe(&cx, &[&payment_topic]).await.unwrap();

        log.phase("send_payment_messages");

        // Send critical payment messages
        let payment_messages = vec![
            factory.create_payment_settle_message("user123", 10000), // $100.00
            factory.create_payment_charge_message("user456", 5000),  // $50.00
            factory.create_payment_refund_message("user789", 2500),  // $25.00
        ];

        let mut sent_metadata = Vec::new();
        for (i, (key, payload)) in payment_messages.iter().enumerate() {
            let result = producer
                .send(&cx, &payment_topic, Some(key), payload, None)
                .await;

            match result {
                Ok(metadata) => {
                    log.kafka_operation(&format!("payment_send_{}", i), Some(&metadata), None);
                    sent_metadata.push(metadata);
                }
                Err(error) => {
                    log.kafka_operation(&format!("payment_send_{}", i), None, Some(&error));
                    panic!("Payment message send failed: {}", error);
                }
            }
        }

        log.phase("consume_payments");

        // Consume and verify all payment messages are delivered in order
        let mut received_messages = Vec::new();
        let timeout = Duration::from_secs(30);
        let poll_start = std::time::Instant::now();

        while received_messages.len() < payment_messages.len() && poll_start.elapsed() < timeout {
            if let Some(record) = consumer
                .poll(&cx, Duration::from_millis(1000))
                .await
                .unwrap()
            {
                // Payment processing simulation: verify message integrity
                let key = record.key.clone().unwrap_or_default();
                let payload = record.payload.clone();
                let payment: serde_json::Value = serde_json::from_slice(&payload).unwrap();

                // Verify payment message structure
                assert!(payment["user_id"].is_string(), "Payment must have user_id");
                assert!(
                    payment["amount_cents"].is_u64(),
                    "Payment must have amount in cents"
                );
                assert!(
                    payment["transaction_id"].is_string(),
                    "Payment must have transaction_id"
                );
                assert!(
                    payment["timestamp"].is_string(),
                    "Payment must have timestamp"
                );

                received_messages.push((key, payload));

                // Manual commit after processing (like real payment system)
                let offset = TopicPartitionOffset::new(
                    record.topic.clone(),
                    record.partition,
                    record.offset + 1,
                );
                consumer.commit_offsets(&cx, &[offset]).await.unwrap();

                log.kafka_operation("payment_processed", None, None);
            }
        }

        log.phase("verify_payment_delivery");

        // ALL payment messages must be delivered - no tolerance for loss
        assert_eq!(
            received_messages.len(),
            payment_messages.len(),
            "All payment messages must be delivered: sent={}, received={}",
            payment_messages.len(),
            received_messages.len()
        );

        // Verify no payment data corruption
        for (i, (sent_key, sent_payload)) in payment_messages.iter().enumerate() {
            let (received_key, received_payload) = &received_messages[i];
            assert_eq!(sent_key, received_key, "Payment key must match exactly");
            assert_eq!(
                sent_payload, received_payload,
                "Payment payload must match exactly"
            );
        }

        log.phase("cleanup");
        producer.flush(&cx, Duration::from_secs(10)).await.unwrap();
        producer.close(&cx, Duration::from_secs(5)).await.unwrap();
        consumer.close(&cx).await.unwrap();

        log.test_end("pass");
    });
}
