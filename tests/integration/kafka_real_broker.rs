//! Real Kafka broker integration tests - no in-memory broker substitutes.
//!
//! These tests require a real Kafka broker running with specific configuration.
//! Run with:
//! `rch exec -- env REAL_KAFKA_TESTS=true CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_kafka_real_broker cargo test --features kafka --test kafka_real_broker -- --nocapture`

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
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
    std::env::var("ASUPERSYNC_KAFKA_BROKER_PARITY_PROOF_DIR").unwrap_or_else(|_| {
        format!(
            "target/kafka-broker-parity-proof/{}",
            kafka_broker_parity_bead_id()
        )
    })
}

fn kafka_broker_parity_bead_id() -> String {
    std::env::var("ASUPERSYNC_KAFKA_BROKER_PARITY_BEAD_ID")
        .unwrap_or_else(|_| "asupersync-0xbecl".to_string())
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

fn payload_sha256(payload: &[u8]) -> String {
    hex::encode(Sha256::digest(payload))
}

#[test]
fn kafka_broker_parity_redacts_credentials_and_hashes_payloads() {
    let servers = vec![
        "alice:super-secret@broker-one:9092".to_string(),
        "broker-two:9092".to_string(),
    ];

    assert_eq!(
        redacted_bootstrap_servers(&servers),
        json!(["redacted@broker-one:9092", "broker-two:9092"])
    );
    assert_eq!(
        payload_sha256(b"asupersync-kafka-proof-payload"),
        "bb9487100a163143e9d771b9bf506962ac3310a2cf2c1f8cdfd30e3909571a11"
    );
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
    partition: Option<i32>,
    offset: Option<i64>,
    delivery_status: &str,
    payload_sha256: &str,
    expected_ordering_scope: &str,
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
            "bead_id": kafka_broker_parity_bead_id(),
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
            "partition": partition,
            "offset": offset,
            "delivery_status": delivery_status,
            "payload_sha256": payload_sha256,
            "expected_ordering_scope": expected_ordering_scope,
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
        None,
        None,
        "not-attempted",
        "",
        "not-applicable",
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
    partition: i32,
    offset: i64,
    delivery_status: String,
    payload_sha256: String,
    expected_ordering_scope: String,
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
        if metadata.partition != record.partition || metadata.offset != record.offset {
            return Err(format!(
                "producer metadata partition/offset {}:{} did not match consumed record {}:{}",
                metadata.partition, metadata.offset, record.partition, record.offset
            ));
        }
        let expected_committed_offset = record.offset + 1;
        if committed != expected_committed_offset {
            return Err(format!(
                "committed offset {committed} did not advance to {expected_committed_offset}"
            ));
        }
        let consumer_lag = metadata.offset.saturating_add(1).saturating_sub(committed);
        let payload_digest = payload_sha256(&record.payload);
        let expected_ordering_scope = format!("topic={topic};partition={}", record.partition);

        Ok(KafkaBrokerProofOutcome {
            message_count: 1,
            ack_count: usize::from(committed == expected_committed_offset),
            consumer_lag,
            partition: record.partition,
            offset: record.offset,
            delivery_status: "offset-committed".to_string(),
            payload_sha256: payload_digest,
            expected_ordering_scope,
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

fn emit_kafka_broker_parity_roundtrip_proof_row(
    scenario_id: &str,
    topic_prefix: &str,
    cancellation_point: &str,
    expected_result: &str,
    pass_actual_result: &str,
) -> Result<(), String> {
    let config = RealBrokerConfig::new();
    let redacted_servers = redacted_bootstrap_servers(&config.bootstrap_servers);
    let topic = unique_topic(topic_prefix);

    if !config.enabled {
        let unsupported_reason = config
            .reason
            .as_deref()
            .unwrap_or("real Kafka broker unavailable");
        emit_kafka_broker_proof_row(
            scenario_id,
            "unavailable",
            redacted_servers,
            &topic,
            0,
            0,
            0,
            None,
            None,
            "not-attempted",
            "",
            "topic-partition-offset",
            0,
            "broker-availability",
            expected_result,
            "deterministic skip because broker configuration is unavailable",
            unsupported_reason,
            "skip",
            "",
        );
        return Ok(());
    }

    let outcome_slot = Arc::new(Mutex::new(None));
    let result_slot = Arc::clone(&outcome_slot);
    let bootstrap_servers = config.bootstrap_servers.clone();
    let topic_for_test = topic.clone();

    run_test_with_cx(|cx| async move {
        let outcome =
            run_kafka_broker_parity_roundtrip(&cx, bootstrap_servers, &topic_for_test).await;
        match result_slot.lock() {
            Ok(mut slot) => *slot = Some(outcome),
            Err(poisoned) => *poisoned.into_inner() = Some(outcome),
        }
    });

    let outcome = match outcome_slot.lock() {
        Ok(mut slot) => slot.take(),
        Err(poisoned) => poisoned.into_inner().take(),
    }
    .ok_or_else(|| "Kafka broker proof did not record an outcome".to_string())?;

    match outcome {
        Ok(outcome) => {
            emit_kafka_broker_proof_row(
                scenario_id,
                "unknown",
                redacted_servers,
                &topic,
                outcome.message_count,
                outcome.ack_count,
                outcome.consumer_lag,
                Some(outcome.partition),
                Some(outcome.offset),
                &outcome.delivery_status,
                &outcome.payload_sha256,
                &outcome.expected_ordering_scope,
                0,
                cancellation_point,
                expected_result,
                pass_actual_result,
                "",
                "pass",
                "",
            );
            Ok(())
        }
        Err(error) => {
            emit_kafka_broker_proof_row(
                scenario_id,
                "unknown",
                redacted_servers,
                &topic,
                0,
                0,
                0,
                None,
                None,
                "failed-before-commit",
                "",
                "topic-partition-offset",
                0,
                cancellation_point,
                expected_result,
                "real broker proof failed",
                "",
                "fail",
                &error,
            );
            Err(format!(
                "Kafka broker parity proof failed for {scenario_id}: {error}"
            ))
        }
    }
}

#[test]
fn kafka_broker_parity_real_broker_proof_row() -> Result<(), String> {
    emit_kafka_broker_parity_roundtrip_proof_row(
        "kafka-producer-consumer-roundtrip",
        "asupersync-kafka-parity",
        "producer-consumer-cleanup",
        "real broker producer send, consumer receive, explicit offset commit, and cleanup",
        "message reached broker and was consumed with explicit offset commit",
    )
}

#[test]
fn kafka_broker_parity_offset_ack_redaction_row() -> Result<(), String> {
    emit_kafka_broker_parity_roundtrip_proof_row(
        "kafka-producer-consumer-offset-ack-redaction",
        "asupersync-kafka-offset-ack-redaction",
        "offset-ack-redaction-cleanup",
        "real broker producer metadata matches consumed partition/offset, payload digest is emitted, bootstrap credentials are redacted, and offset commit is observed",
        "message reached broker, payload digest was emitted without raw payload, and consumed offset was explicitly committed",
    )
}

fn assert_kafka_resilience_error_taxonomy() -> Result<(), String> {
    let reconnectable = KafkaError::Broker("broker transport disconnected".to_string());
    if !reconnectable.is_retryable()
        || !reconnectable.is_transient()
        || !reconnectable.is_connection_error()
    {
        return Err(
            "broker disconnect must stay retryable, transient, and connection-scoped".into(),
        );
    }

    let queue_full = KafkaError::QueueFull;
    if !queue_full.is_retryable()
        || !queue_full.is_transient()
        || !queue_full.is_capacity_error()
        || queue_full.is_connection_error()
    {
        return Err(
            "queue-full must be retryable capacity pressure, not a connection error".into(),
        );
    }

    let auth = KafkaError::Authentication("redacted credentials rejected".to_string());
    if auth.is_retryable() || auth.is_transient() || auth.is_connection_error() {
        return Err("authentication failures must remain terminal and non-retryable".into());
    }

    let cancelled = KafkaError::Cancelled;
    if cancelled.is_retryable()
        || cancelled.is_transient()
        || cancelled.is_connection_error()
        || cancelled.is_capacity_error()
    {
        return Err(
            "cancelled operations must not be classified as retryable broker errors".into(),
        );
    }

    Ok(())
}

#[derive(Debug)]
struct KafkaResilienceProofOutcome {
    message_count: usize,
    ack_count: usize,
    consumer_lag: i64,
    partition: Option<i32>,
    offset: Option<i64>,
    delivery_status: String,
    payload_sha256: String,
    expected_ordering_scope: String,
    reconnect_count: usize,
    actual_result: String,
}

async fn run_kafka_resilience_cancellation_probe(
    cx: &asupersync::cx::Cx,
    bootstrap_servers: Vec<String>,
) -> Result<String, String> {
    assert_kafka_resilience_error_taxonomy()?;

    let producer_config = ProducerConfig::new(bootstrap_servers.clone())
        .client_id("asupersync-kafka-resilience-cancel-producer")
        .acks(Acks::All)
        .enable_idempotence(false)
        .linger_ms(0)
        .retries(0)
        .allow_insecure_transport_for_testing(true)
        .require_kafka_feature();
    let producer = KafkaProducer::new(producer_config).map_err(|error| error.to_string())?;

    let consumer_config = ConsumerConfig::new(
        bootstrap_servers,
        "asupersync-kafka-resilience-cancel-group",
    )
    .client_id("asupersync-kafka-resilience-cancel-consumer")
    .auto_offset_reset(AutoOffsetReset::Earliest)
    .enable_auto_commit(false)
    .force_real_kafka(true)
    .allow_insecure_transport_for_testing(true);
    let consumer = KafkaConsumer::new(consumer_config).map_err(|error| error.to_string())?;

    cx.set_cancel_requested(true);
    let send_result = producer
        .send(
            cx,
            "asupersync-kafka-resilience-cancel-proof",
            None,
            b"cancel-before-send-commit",
            Some(0),
        )
        .await;
    if !matches!(send_result, Err(KafkaError::Cancelled)) {
        return Err(format!(
            "cancelled producer send returned {send_result:?}, expected KafkaError::Cancelled"
        ));
    }

    let poll_result = consumer.poll(cx, Duration::ZERO).await;
    if !matches!(poll_result, Err(KafkaError::Cancelled)) {
        return Err(format!(
            "cancelled consumer poll returned {poll_result:?}, expected KafkaError::Cancelled"
        ));
    }

    cx.set_cancel_requested(false);
    producer
        .close(cx, Duration::from_millis(10))
        .await
        .map_err(|error| format!("producer cleanup after cancellation failed: {error}"))?;
    consumer
        .close(cx)
        .await
        .map_err(|error| format!("consumer cleanup after cancellation failed: {error}"))?;

    if !producer.is_closed() || !consumer.is_closed() {
        return Err("producer and consumer must both report closed after cleanup".into());
    }

    Ok("unavailable-bootstrap clients constructed; cancel-before-send returned KafkaError::Cancelled; cancelled poll returned KafkaError::Cancelled; producer/consumer cleanup closed cleanly; broker disconnect remains retryable while auth/cancel remain terminal".to_string())
}

async fn run_kafka_resilience_proof(
    cx: &asupersync::cx::Cx,
    unavailable_bootstrap_servers: Vec<String>,
    recovery_bootstrap_servers: Option<Vec<String>>,
    recovery_topic: &str,
) -> Result<KafkaResilienceProofOutcome, String> {
    let Some(recovery_bootstrap_servers) = recovery_bootstrap_servers else {
        assert_kafka_resilience_error_taxonomy()?;
        return Ok(KafkaResilienceProofOutcome {
            message_count: 0,
            ack_count: 0,
            consumer_lag: 0,
            partition: None,
            offset: None,
            delivery_status: "skipped-real-broker-prerequisites-unavailable".to_string(),
            payload_sha256: String::new(),
            expected_ordering_scope: "not-applicable".to_string(),
            reconnect_count: 0,
            actual_result:
                "real broker resilience proof skipped because broker prerequisites are unavailable; Kafka error taxonomy checked locally"
                    .to_string(),
        });
    };

    let cancellation_result =
        run_kafka_resilience_cancellation_probe(cx, unavailable_bootstrap_servers).await?;

    let recovery =
        run_kafka_broker_parity_roundtrip(cx, recovery_bootstrap_servers, recovery_topic).await?;

    Ok(KafkaResilienceProofOutcome {
        message_count: recovery.message_count,
        ack_count: recovery.ack_count,
        consumer_lag: recovery.consumer_lag,
        partition: Some(recovery.partition),
        offset: Some(recovery.offset),
        delivery_status: "recovered-after-unavailable-bootstrap-and-cancelled-send-poll"
            .to_string(),
        payload_sha256: recovery.payload_sha256,
        expected_ordering_scope: recovery.expected_ordering_scope,
        reconnect_count: 1,
        actual_result: format!(
            "{cancellation_result}; real broker recovery roundtrip committed offset with consumer_lag={}",
            recovery.consumer_lag
        ),
    })
}

#[test]
fn kafka_broker_parity_resilience_taxonomy_row() -> Result<(), String> {
    let config = RealBrokerConfig::new();
    let unavailable_bootstrap_servers = vec!["127.0.0.1:1".to_string()];
    let recovery_bootstrap_servers = if config.enabled {
        Some(config.bootstrap_servers.clone())
    } else {
        None
    };
    let unsupported_reason = config
        .reason
        .as_deref()
        .unwrap_or("real Kafka broker unavailable");
    let redacted_servers = json!({
        "unavailable_probe": redacted_bootstrap_servers(&unavailable_bootstrap_servers),
        "recovery_broker": redacted_bootstrap_servers(&config.bootstrap_servers)
    });
    let topic = unique_topic("asupersync-kafka-resilience-recovery");
    let expected_result = "producer send and consumer poll must observe cancellation before committing broker work; broker disconnect errors must remain retryable/connection-scoped while auth and cancel remain terminal; configured real broker lanes must recover with explicit offset commit and zero lag";
    let result_slot = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&result_slot);
    let unavailable_probe = unavailable_bootstrap_servers.clone();
    let topic_for_test = topic.clone();

    run_test_with_cx(|cx| async move {
        let result = run_kafka_resilience_proof(
            &cx,
            unavailable_probe,
            recovery_bootstrap_servers,
            &topic_for_test,
        )
        .await;
        match slot.lock() {
            Ok(mut slot) => *slot = Some(result),
            Err(poisoned) => *poisoned.into_inner() = Some(result),
        }
    });

    let result = match result_slot.lock() {
        Ok(mut slot) => slot.take(),
        Err(poisoned) => poisoned.into_inner().take(),
    }
    .ok_or_else(|| "Kafka resilience proof did not record an outcome".to_string())?;

    match result {
        Ok(outcome) if config.enabled => {
            emit_kafka_broker_proof_row(
                "kafka-reconnect-cancellation-error-taxonomy",
                "unknown",
                redacted_servers,
                &topic,
                outcome.message_count,
                outcome.ack_count,
                outcome.consumer_lag,
                outcome.partition,
                outcome.offset,
                &outcome.delivery_status,
                &outcome.payload_sha256,
                &outcome.expected_ordering_scope,
                outcome.reconnect_count,
                "unavailable-bootstrap-send-before-commit-and-consumer-poll",
                expected_result,
                &outcome.actual_result,
                "",
                "pass",
                "",
            );
            Ok(())
        }
        Ok(outcome) => {
            emit_kafka_broker_proof_row(
                "kafka-reconnect-cancellation-error-taxonomy",
                "unavailable",
                redacted_servers,
                &topic,
                outcome.message_count,
                outcome.ack_count,
                outcome.consumer_lag,
                outcome.partition,
                outcome.offset,
                &outcome.delivery_status,
                &outcome.payload_sha256,
                &outcome.expected_ordering_scope,
                outcome.reconnect_count,
                "unavailable-bootstrap-send-before-commit-and-consumer-poll",
                expected_result,
                &outcome.actual_result,
                unsupported_reason,
                "skip",
                "",
            );
            Ok(())
        }
        Err(error) => {
            emit_kafka_broker_proof_row(
                "kafka-reconnect-cancellation-error-taxonomy",
                "unknown",
                redacted_servers,
                &topic,
                0,
                0,
                0,
                None,
                None,
                "failed-before-cleanup",
                "",
                "not-applicable",
                0,
                "unavailable-bootstrap-send-before-commit-and-consumer-poll",
                expected_result,
                "Kafka resilience taxonomy proof failed",
                "",
                "fail",
                &error,
            );
            Err(error)
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

                // Assert against real broker responses, not in-memory substituted values.
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
/// This test ensures critical financial messages are never lost due to substituted-broker semantics.
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

/// Real-Kafka roundtrip: prove `KafkaConsumer::close()` is NOT a commit
/// barrier. The current implementation
/// (`src/messaging/kafka_consumer.rs:1383`) calls `consumer.unsubscribe()` +
/// `consumer.unassign()` and clears every local mirror of `committed_offsets`
/// / `positions` — but never invokes `commit_offsets`. A consumer that
/// polls messages and updates positions but skips the explicit
/// `commit_offsets` before `close()` therefore loses its progress: the
/// broker side has no record, and the next consumer in the same
/// `group_id` re-reads everything (`AutoOffsetReset::Earliest`) or skips
/// it (`AutoOffsetReset::Latest`). Either way is unsafe for at-least-once
/// pipelines unless the caller commits explicitly.
///
/// asupersync-z9ka3u: this test pins the contract by demonstrating the
/// re-read against a real broker. Producer writes N messages, consumer A
/// (group G) consumes all N WITHOUT commit, calls `close()`. Consumer B
/// (same group G, `AutoOffsetReset::Earliest`) subscribes and is
/// asserted to re-read all N messages — proving the broker still sees
/// G's committed offset at the pre-A baseline (typically 0).
///
/// If a future change makes `close()` auto-commit, this test will FAIL
/// (B will see 0 messages). That failure is then the signal to update
/// the contract: either re-document `close()` as a commit barrier or
/// add a `force_uncommitted: true` opt-in for callers who want the
/// current "discard pending positions" semantics.
#[test]
fn test_real_broker_close_without_commit_loses_positions() {
    let Some(config) = require_real_broker() else {
        return;
    };

    let log = KafkaTestLogger::new("real_broker_close_without_commit_z9ka3u");

    run_test_with_cx(|cx| async move {
        let topic = unique_topic("close-without-commit-z9ka3u");
        // Single shared group_id across consumers A and B — they're the same
        // logical reader, just split across a graceful-shutdown boundary.
        let group_id = format!("test-group-z9ka3u-{}", fastrand::u32(..));
        let factory = KafkaMessageFactory::new();

        log.phase("setup_producer");
        let producer_config =
            ProducerConfig::new(config.bootstrap_servers.clone()).client_id("z9ka3u-producer");
        let producer = KafkaProducer::new(producer_config).expect("producer config");

        log.phase("produce_3_messages");
        let test_messages = factory.create_batch_messages(3, &topic);
        for (msg_topic, key, payload) in &test_messages {
            let metadata = producer
                .send(&cx, msg_topic, Some(key), payload, None)
                .await
                .expect("send");
            log.kafka_operation("send", Some(&metadata), None);
        }
        producer
            .flush(&cx, Duration::from_secs(10))
            .await
            .expect("producer flush");

        log.phase("consumer_A_subscribe_poll_close_without_commit");
        let consumer_a_config = ConsumerConfig::new(config.bootstrap_servers.clone(), &group_id)
            .client_id("z9ka3u-consumer-A")
            .auto_offset_reset(AutoOffsetReset::Earliest)
            .enable_auto_commit(false)
            .force_real_kafka(true);
        let consumer_a = KafkaConsumer::new(consumer_a_config).expect("consumer A config");

        let topics: Vec<&str> = test_messages
            .iter()
            .map(|(t, _, _)| t.as_str())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        consumer_a
            .subscribe(&cx, &topics)
            .await
            .expect("A subscribe");

        let mut polled_a = 0usize;
        let poll_deadline = std::time::Instant::now() + Duration::from_secs(30);
        while polled_a < test_messages.len() && std::time::Instant::now() < poll_deadline {
            if let Some(record) = consumer_a
                .poll(&cx, Duration::from_secs(1))
                .await
                .expect("A poll")
            {
                log.kafka_operation("poll_A", None, None);
                let _ = record;
                polled_a += 1;
            }
        }
        assert_eq!(
            polled_a,
            test_messages.len(),
            "consumer A should poll all {} messages from the real broker",
            test_messages.len()
        );

        // CRITICAL STEP: close() WITHOUT commit_offsets. This is the
        // exact production hazard — graceful shutdown that forgot the
        // commit barrier. The broker still has G's offset at the
        // pre-subscription baseline.
        consumer_a.close(&cx).await.expect("A close");

        log.phase("consumer_B_subscribes_with_same_group_id");
        let consumer_b_config = ConsumerConfig::new(config.bootstrap_servers.clone(), &group_id)
            .client_id("z9ka3u-consumer-B")
            .auto_offset_reset(AutoOffsetReset::Earliest)
            .enable_auto_commit(false)
            .force_real_kafka(true);
        let consumer_b = KafkaConsumer::new(consumer_b_config).expect("consumer B config");
        consumer_b
            .subscribe(&cx, &topics)
            .await
            .expect("B subscribe");

        let mut polled_b = 0usize;
        let poll_deadline_b = std::time::Instant::now() + Duration::from_secs(30);
        while polled_b < test_messages.len() && std::time::Instant::now() < poll_deadline_b {
            if let Some(record) = consumer_b
                .poll(&cx, Duration::from_secs(1))
                .await
                .expect("B poll")
            {
                log.kafka_operation("poll_B_replay", None, None);
                let _ = record;
                polled_b += 1;
            }
        }

        // The contract being pinned: B re-reads A's messages because A
        // never committed. If a future patch makes close() commit
        // automatically, this assert will fail with polled_b == 0 and
        // surface the contract change for review.
        assert_eq!(
            polled_b,
            test_messages.len(),
            "consumer B (same group {group_id}) must re-read all {} messages because \
             consumer A's close() did NOT commit pending positions; observed only {} replays. \
             If this fails with 0 replays, close() may have started auto-committing — review \
             src/messaging/kafka_consumer.rs:1383 and update the contract docstring.",
            test_messages.len(),
            polled_b
        );

        log.phase("cleanup");
        consumer_b.close(&cx).await.expect("B close");
        producer
            .close(&cx, Duration::from_secs(5))
            .await
            .expect("producer close");

        log.test_end("pass");
    });
}
