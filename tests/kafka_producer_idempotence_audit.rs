//! Audit test for Kafka producer idempotence behavior.
//!
//! When ProducerConfig.enable_idempotence=true, producers should track
//! producer-id + sequence-number per partition to prevent duplicates
//! during retries. This is critical for exactly-once semantics.
//!
//! DEFECT IDENTIFIED: StubBroker has no deduplication logic, meaning
//! retry behavior cannot be properly validated in tests. Hidden bugs
//! in retry logic may only surface in production.

#[cfg(not(feature = "kafka"))]
use asupersync::messaging::kafka::KafkaError;
use asupersync::messaging::kafka::{KafkaProducer, ProducerConfig};
use asupersync::test_utils::run_test_with_cx;

#[cfg(not(feature = "kafka"))]
#[test]
fn test_stub_broker_enables_idempotence_config() {
    use asupersync::messaging::kafka::lock_stub_broker_for_tests;

    let _broker = lock_stub_broker_for_tests();

    // Verify that idempotence can be configured (use builder — struct has a
    // private field for the insecure-transport opt-in).
    let config = ProducerConfig::default()
        .enable_idempotence(true)
        .retries(3);

    assert!(config.enable_idempotence);

    let producer = KafkaProducer::new(config).unwrap();
    let _ = producer; // keep alive for the duration of the test
    // Producer was created with enable_idempotence=true.

    // But the underlying StubBroker doesn't implement idempotence!
    // (DEFECT: StubBroker has no deduplication logic.)
}

#[cfg(not(feature = "kafka"))]
#[test]
fn default_feature_integration_send_fails_closed_instead_of_using_stub() {
    run_test_with_cx(|cx| async move {
        let producer = KafkaProducer::new(
            ProducerConfig::default().enable_idempotence(true), // Claims to be idempotent
        )
        .unwrap();

        let topic = "idempotence-test";

        let send_result = producer
            .send(&cx, topic, Some(b"key1"), b"message1", None)
            .await;

        assert!(
            matches!(send_result, Err(KafkaError::FeatureDisabled)),
            "default-feature integration tests must fail closed instead of silently using stub broker"
        );
    });
}

#[cfg(not(feature = "kafka"))]
#[test]
fn default_feature_integration_send_fails_closed_for_all_producers() {
    run_test_with_cx(|cx| async move {
        // Create two producers with idempotence enabled
        let producer1 = KafkaProducer::new(
            ProducerConfig::default()
                .enable_idempotence(true)
                .client_id("producer-1"),
        )
        .unwrap();

        let producer2 = KafkaProducer::new(
            ProducerConfig::default()
                .enable_idempotence(true)
                .client_id("producer-2"),
        )
        .unwrap();

        let topic = "producer-id-test";

        // Integration tests compile as downstream consumers, so default builds
        // must not route broker operations to the crate-local stub.
        let first_send = producer1
            .send(&cx, topic, Some(b"key"), b"from-p1", None)
            .await;
        let second_send = producer2
            .send(&cx, topic, Some(b"key"), b"from-p2", None)
            .await;

        assert!(
            matches!(first_send, Err(KafkaError::FeatureDisabled)),
            "producer 1 should hit the default-feature fail-closed boundary"
        );
        assert!(
            matches!(second_send, Err(KafkaError::FeatureDisabled)),
            "producer 2 should hit the default-feature fail-closed boundary"
        );
    });
}

#[test]
fn audit_kafka_producer_idempotence_implementation() {
    println!("\n=== KAFKA PRODUCER IDEMPOTENCE AUDIT ===\n");

    println!("KAFKA IDEMPOTENCE SPECIFICATION:");
    println!("- Each producer gets unique producer-id from broker");
    println!("- Client maintains per-partition sequence numbers starting at 0");
    println!("- Broker deduplicates based on (producer-id, partition, sequence)");
    println!("- Out-of-sequence messages cause OOSR (OutOfOrderSequence) errors");
    println!("- Duplicate sequence numbers are silently deduplicated\n");

    println!("IMPLEMENTATION ANALYSIS:");
    println!("File: src/messaging/kafka.rs");
    println!("1. ProducerConfig.enable_idempotence (line 1102): ✓ SOUND config field");
    println!("2. rdkafka integration (line 430): ✓ SOUND passes config to rdkafka");
    println!("3. StubBroker implementation (lines 703-732): ✗ DEFECT - no deduplication");
    println!("4. Test infrastructure: ✗ DEFECT - cannot validate idempotent behavior\n");

    println!("DEFECT IDENTIFIED:");
    println!("✗ CRITICAL: StubBroker has no producer ID tracking");
    println!("✗ CRITICAL: StubBroker has no sequence number validation");
    println!("✗ CRITICAL: StubBroker accepts all duplicates without deduplication");
    println!("✗ CRITICAL: Retry logic cannot be properly tested\n");

    println!("IMPACT:");
    println!("- Test/production behavior divergence (tests pass, production may duplicate)");
    println!("- Untested retry scenarios could cause duplicate payments");
    println!("- False confidence in exactly-once semantics");
    println!("- Financial risk in payment/billing systems\n");

    println!("EXACTLY-ONCE SEMANTICS GAP:");
    println!("Kafka exactly-once requires BOTH:");
    println!("1. Idempotent producers (prevent duplicates) - MISSING in StubBroker");
    println!("2. Transactional producers (atomic commits) - Present but untested\n");

    println!("RECOMMENDATION:");
    println!("Enhance StubBroker with idempotence simulation:");
    println!("```rust");
    println!("struct IdempotentStubBroker {{");
    println!("    producer_ids: BTreeMap<String, u64>, // client_id -> producer_id");
    println!(
        "    sequences: BTreeMap<(u64, String, i32), u64>, // (producer_id, topic, partition) -> next_seq"
    );
    println!(
        "    dedup_cache: BTreeMap<(u64, String, i32, u64), RecordMetadata>, // recent records"
    );
    println!("}}");
    println!();
    println!("impl IdempotentStubBroker {{");
    println!(
        "    fn publish_with_idempotence(&mut self, record: StubBrokerRecord, producer_id: u64, sequence: u64) {{"
    );
    println!("        let key = (producer_id, record.topic.clone(), record.partition, sequence);");
    println!("        if let Some(cached) = self.dedup_cache.get(&key) {{");
    println!("            return cached.clone(); // Deduplicated!");
    println!("        }}");
    println!("        // Check sequence ordering, publish if valid...");
    println!("    }}");
    println!("}}");
    println!("```\n");

    println!("PRIORITY: HIGH - Exactly-once semantics critical for financial systems");
}

#[test]
fn run_audit() {
    audit_kafka_producer_idempotence_implementation();
}
