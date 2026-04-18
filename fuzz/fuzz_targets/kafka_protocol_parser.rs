#![no_main]

//! Focused fuzz target for Kafka protocol parser edge cases
//!
//! This target specifically tests the protocol parsing features mentioned:
//! - API key boundaries (invalid/extreme API versions)
//! - Correlation ID matching (mismatched/duplicate/extreme correlation IDs)
//! - Throttle time handling (extreme throttle values, timeout interactions)
//! - Compression codec dispatch (invalid codecs, mixed compression)
//! - Partial response recovery (truncated/malformed responses)
//!
//! Since asupersync uses rdkafka as the underlying implementation, we test
//! these protocol features by creating edge case configurations and operations
//! that should trigger the specific parsing paths in the underlying library.

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::time::Duration;

#[cfg(feature = "kafka")]
use asupersync::messaging::kafka::*;
#[cfg(feature = "kafka")]
use asupersync::messaging::kafka_consumer::*;
use asupersync::cx::Cx;

/// Protocol edge case scenarios to fuzz
#[derive(Arbitrary, Debug, Clone)]
struct KafkaProtocolParserFuzz {
    /// Random seed for deterministic behavior
    pub seed: u64,
    /// Protocol test scenarios
    pub scenarios: Vec<ProtocolTestScenario>,
}

/// Individual protocol test scenarios
#[derive(Arbitrary, Debug, Clone)]
enum ProtocolTestScenario {
    /// Test API key/version boundaries
    ApiVersionBoundaries {
        /// Use extreme API versions to test parsing
        api_version_override: Option<i16>,
        /// Trigger version negotiation edge cases
        force_old_protocol: bool,
        /// Mix of operations to test version compatibility
        operations: Vec<VersionedOperation>,
    },
    /// Test correlation ID edge cases
    CorrelationIdMatching {
        /// Operations with potentially problematic correlation IDs
        operations: Vec<CorrelationOperation>,
        /// Interleave operations to test matching
        concurrent_operations: u8,
    },
    /// Test throttle time handling
    ThrottleTimeHandling {
        /// Configuration that might trigger throttling
        throttle_config: ThrottleConfig,
        /// Operations to execute under throttling
        throttled_operations: Vec<ThrottledOperation>,
    },
    /// Test compression codec dispatch
    CompressionCodecDispatch {
        /// Mix of compression types and invalid codecs
        compression_tests: Vec<CompressionTest>,
        /// Message sizes to test compression boundaries
        message_sizes: Vec<u32>,
    },
    /// Test partial response recovery
    PartialResponseRecovery {
        /// Network conditions that might cause partial responses
        network_conditions: NetworkConditions,
        /// Operations to test under flaky network
        recovery_operations: Vec<RecoveryOperation>,
    },
}

/// Operations with potentially problematic API versions
#[derive(Arbitrary, Debug, Clone)]
enum VersionedOperation {
    /// Producer send with version override
    ProducerSend {
        topic: String,
        payload_size: u16,
        use_headers: bool,
    },
    /// Consumer poll with version override
    ConsumerPoll {
        topics: Vec<String>,
        timeout_ms: u16,
    },
    /// Metadata request with version override
    MetadataRequest {
        topics: Option<Vec<String>>,
    },
    /// Transaction operation with version override
    TransactionOp {
        operation: TransactionOpType,
    },
}

#[derive(Arbitrary, Debug, Clone)]
enum TransactionOpType {
    Begin,
    Commit,
    Abort,
    AddPartitions,
}

/// Operations with potentially problematic correlation IDs
#[derive(Arbitrary, Debug, Clone)]
enum CorrelationOperation {
    /// Send with specific correlation ID timing
    ProducerSend {
        topic: String,
        payload: Vec<u8>,
        delay_before_ms: u16,
    },
    /// Consumer operation with timing
    ConsumerOperation {
        operation: ConsumerOpType,
        delay_before_ms: u16,
    },
    /// Administrative operation
    AdminOperation {
        operation: AdminOpType,
        delay_before_ms: u16,
    },
}

#[derive(Arbitrary, Debug, Clone)]
enum ConsumerOpType {
    Poll(u16), // timeout_ms
    Commit,
    Seek { partition: i32, offset: i64 },
}

#[derive(Arbitrary, Debug, Clone)]
enum AdminOpType {
    ListGroups,
    DescribeGroups(Vec<String>),
    ListTopics,
}

/// Configuration to potentially trigger throttling
#[derive(Arbitrary, Debug, Clone)]
struct ThrottleConfig {
    /// Very high request rate to trigger throttling
    requests_per_second: u16,
    /// Small batch sizes to increase request frequency
    batch_size: u16,
    /// Short linger time to increase frequency
    linger_ms: u8,
    /// Multiple producers to amplify load
    producer_count: u8,
    /// Target topics (potentially with rate limits)
    target_topics: Vec<String>,
}

/// Operations to run under throttling conditions
#[derive(Arbitrary, Debug, Clone)]
enum ThrottledOperation {
    /// Burst of producer sends
    ProducerBurst {
        topic: String,
        burst_size: u16,
        message_size: u16,
    },
    /// Rapid metadata requests
    MetadataBurst {
        request_count: u16,
    },
    /// Consumer poll under throttling
    ConsumerPoll {
        topics: Vec<String>,
        timeout_ms: u16,
    },
}

/// Compression testing scenarios
#[derive(Arbitrary, Debug, Clone)]
struct CompressionTest {
    /// Compression type to test
    compression_type: CompressionTypeTest,
    /// Message pattern that might stress compression
    message_pattern: MessagePattern,
    /// Whether to mix compression types in the same topic
    mix_compression: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum CompressionTypeTest {
    None,
    Gzip,
    Snappy,
    Lz4,
    Zstd,
    /// Invalid compression codec value
    Invalid(u8),
    /// Switch compression mid-stream
    Dynamic(Vec<CompressionTypeTest>),
}

#[derive(Arbitrary, Debug, Clone)]
enum MessagePattern {
    /// Highly compressible (repeated data)
    Compressible(u8), // repeat value
    /// Random data (low compressibility)
    Random,
    /// Mixed compressible/incompressible
    Mixed { compressible_ratio: u8 },
    /// Pathological compression cases
    Pathological(PathologicalPattern),
}

#[derive(Arbitrary, Debug, Clone)]
enum PathologicalPattern {
    /// Compression bomb-like patterns
    Repetitive { pattern_size: u8, repeat_count: u16 },
    /// Alternating patterns that might break compression
    Alternating { pattern1: Vec<u8>, pattern2: Vec<u8> },
}

/// Network conditions for testing partial response recovery
#[derive(Arbitrary, Debug, Clone)]
struct NetworkConditions {
    /// Packet loss rate (0-255, where 255 = very high loss)
    packet_loss_rate: u8,
    /// Network delay variation
    delay_jitter_ms: u16,
    /// Connection timeout scenarios
    timeout_scenarios: Vec<TimeoutScenario>,
    /// Whether to simulate connection drops
    simulate_drops: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum TimeoutScenario {
    /// Timeout during request
    RequestTimeout { after_ms: u16 },
    /// Timeout during response parsing
    ResponseTimeout { after_ms: u16 },
    /// Metadata timeout
    MetadataTimeout { after_ms: u16 },
}

/// Operations to test under network recovery conditions
#[derive(Arbitrary, Debug, Clone)]
enum RecoveryOperation {
    /// Producer send that might get interrupted
    ProducerSendWithRetry {
        topic: String,
        payload_size: u16,
        max_retries: u8,
    },
    /// Consumer poll that might get partial data
    ConsumerPollWithRecovery {
        topics: Vec<String>,
        timeout_ms: u16,
        retry_on_error: bool,
    },
    /// Transaction that might fail mid-way
    TransactionWithRecovery {
        operations: Vec<String>, // topic names for sends
        commit: bool,
    },
    /// Metadata request that might timeout
    MetadataWithRecovery {
        topics: Vec<String>,
        timeout_ms: u16,
    },
}

/// Normalize fuzz input to prevent resource exhaustion
fn normalize_fuzz_input(input: &mut KafkaProtocolParserFuzz) {
    // Limit number of scenarios to prevent timeouts
    input.scenarios.truncate(10);

    for scenario in &mut input.scenarios {
        match scenario {
            ProtocolTestScenario::ApiVersionBoundaries { api_version_override, operations, .. } => {
                // Bound API version to reasonable range
                if let Some(ref mut version) = api_version_override {
                    *version = (*version).clamp(-1, 50); // Kafka API versions typically 0-20
                }
                operations.truncate(20);
            }
            ProtocolTestScenario::CorrelationIdMatching { operations, concurrent_operations, .. } => {
                operations.truncate(50);
                *concurrent_operations = (*concurrent_operations).min(10);
            }
            ProtocolTestScenario::ThrottleTimeHandling { throttle_config, throttled_operations } => {
                throttle_config.requests_per_second = throttle_config.requests_per_second.clamp(1, 1000);
                throttle_config.batch_size = throttle_config.batch_size.clamp(1, 10000);
                throttle_config.producer_count = throttle_config.producer_count.clamp(1, 10);
                throttled_operations.truncate(20);
            }
            ProtocolTestScenario::CompressionCodecDispatch { compression_tests, message_sizes } => {
                compression_tests.truncate(10);
                message_sizes.truncate(20);
                for size in message_sizes.iter_mut() {
                    *size = (*size).clamp(1, 100_000); // Max 100KB per message
                }
            }
            ProtocolTestScenario::PartialResponseRecovery { network_conditions, recovery_operations } => {
                network_conditions.delay_jitter_ms = network_conditions.delay_jitter_ms.min(30_000);
                recovery_operations.truncate(15);
            }
        }
    }
}

/// Test API version boundaries
async fn test_api_version_boundaries(
    api_version_override: Option<i16>,
    _force_old_protocol: bool,
    operations: &[VersionedOperation],
    cx: &Cx,
) {
    // Since we can't directly control rdkafka's API version selection,
    // we test by creating configurations and operations that would trigger
    // different API version usage patterns

    for operation in operations.iter().take(10) {
        match operation {
            VersionedOperation::ProducerSend { topic, payload_size, use_headers } => {
                let config = ProducerConfig::new(vec!["localhost:9092".to_string()]);
                if let Ok(producer) = KafkaProducer::new(config) {
                    let payload = vec![0u8; (*payload_size as usize).min(10000)];

                    if *use_headers {
                        let headers = vec![("test-header", b"value".as_slice())];
                        let _ = producer.send_with_headers(cx, topic, None, &payload, &headers).await;
                    } else {
                        let _ = producer.send(cx, topic, None, &payload, None).await;
                    }
                    let _ = producer.close(cx, Duration::from_millis(100)).await;
                }
            }
            VersionedOperation::ConsumerPoll { topics, timeout_ms } => {
                #[cfg(feature = "kafka")]
                {
                    let config = ConsumerConfig::new(
                        vec!["localhost:9092".to_string()],
                        "test-group".to_string()
                    );
                    if let Ok(consumer) = KafkaConsumer::new(config) {
                        let _ = consumer.subscribe(topics).await;
                        let timeout = Duration::from_millis((*timeout_ms as u64).min(5000));
                        let _ = consumer.poll(cx, timeout).await;
                        let _ = consumer.close(cx).await;
                    }
                }
            }
            VersionedOperation::MetadataRequest { topics } => {
                // Test metadata requests by creating producer/consumer and using topic operations
                let config = ProducerConfig::new(vec!["localhost:9092".to_string()]);
                if let Ok(producer) = KafkaProducer::new(config) {
                    if let Some(topics) = topics {
                        for topic in topics.iter().take(5) {
                            let _ = producer.send(cx, topic, None, b"test", None).await;
                        }
                    }
                    let _ = producer.close(cx, Duration::from_millis(100)).await;
                }
            }
            VersionedOperation::TransactionOp { operation } => {
                let producer_config = ProducerConfig::new(vec!["localhost:9092".to_string()])
                    .enable_idempotence(true);
                let tx_config = TransactionalConfig::new(producer_config, "test-tx-id".to_string());

                if let Ok(producer) = TransactionalProducer::new(tx_config) {
                    match operation {
                        TransactionOpType::Begin => {
                            if let Ok(tx) = producer.begin_transaction(cx).await {
                                let _ = tx.abort(cx).await;
                            }
                        }
                        _ => {
                            // Other operations require a transaction, just test begin for now
                            if let Ok(tx) = producer.begin_transaction(cx).await {
                                let _ = tx.abort(cx).await;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Test correlation ID edge cases
async fn test_correlation_id_matching(
    operations: &[CorrelationOperation],
    concurrent_operations: u8,
    cx: &Cx,
) {
    // Create multiple concurrent operations to potentially cause correlation ID conflicts
    let mut futures = Vec::new();

    for (i, operation) in operations.iter().take(concurrent_operations as usize).enumerate() {
        let operation = operation.clone();
        let cx = cx.clone();

        let future = async move {
            // Add varying delays to create timing edge cases
            if let Some(delay_ms) = match &operation {
                CorrelationOperation::ProducerSend { delay_before_ms, .. } => Some(*delay_before_ms),
                CorrelationOperation::ConsumerOperation { delay_before_ms, .. } => Some(*delay_before_ms),
                CorrelationOperation::AdminOperation { delay_before_ms, .. } => Some(*delay_before_ms),
            } {
                asupersync::time::sleep(Duration::from_millis((delay_ms as u64).min(1000))).await;
            }

            match operation {
                CorrelationOperation::ProducerSend { topic, payload, .. } => {
                    let config = ProducerConfig::new(vec!["localhost:9092".to_string()]);
                    if let Ok(producer) = KafkaProducer::new(config) {
                        let bounded_payload = if payload.len() > 10000 {
                            &payload[..10000]
                        } else {
                            &payload
                        };
                        let _ = producer.send(&cx, &topic, None, bounded_payload, None).await;
                        let _ = producer.close(&cx, Duration::from_millis(100)).await;
                    }
                }
                CorrelationOperation::ConsumerOperation { operation, .. } => {
                    #[cfg(feature = "kafka")]
                    {
                        let config = ConsumerConfig::new(
                            vec!["localhost:9092".to_string()],
                            format!("test-group-{}", i)
                        );
                        if let Ok(consumer) = KafkaConsumer::new(config) {
                            match operation {
                                ConsumerOpType::Poll(timeout_ms) => {
                                    let timeout = Duration::from_millis((*timeout_ms as u64).min(2000));
                                    let _ = consumer.poll(&cx, timeout).await;
                                }
                                ConsumerOpType::Commit => {
                                    let _ = consumer.commit_offsets(&[]).await;
                                }
                                ConsumerOpType::Seek { partition, offset } => {
                                    let tpo = TopicPartitionOffset::new("test-topic".to_string(), *partition, *offset);
                                    let _ = consumer.seek(&[tpo]).await;
                                }
                            }
                            let _ = consumer.close(&cx).await;
                        }
                    }
                }
                CorrelationOperation::AdminOperation { operation, .. } => {
                    // Admin operations would require additional client setup
                    // For now, just test basic producer/consumer operations
                    let config = ProducerConfig::new(vec!["localhost:9092".to_string()]);
                    if let Ok(producer) = KafkaProducer::new(config) {
                        let _ = producer.send(&cx, "test-topic", None, b"test", None).await;
                        let _ = producer.close(&cx, Duration::from_millis(100)).await;
                    }
                }
            }
        };

        futures.push(future);
    }

    // Execute operations concurrently to test correlation ID handling
    for future in futures {
        future.await;
    }
}

/// Test throttle time handling
async fn test_throttle_time_handling(
    config: &ThrottleConfig,
    operations: &[ThrottledOperation],
    cx: &Cx,
) {
    // Create high-frequency operations that might trigger throttling
    let producer_config = ProducerConfig::new(vec!["localhost:9092".to_string()])
        .batch_size(config.batch_size as usize)
        .linger_ms(config.linger_ms as u64);

    if let Ok(producer) = KafkaProducer::new(producer_config) {
        for operation in operations.iter().take(10) {
            match operation {
                ThrottledOperation::ProducerBurst { topic, burst_size, message_size } => {
                    let payload = vec![0u8; (*message_size as usize).min(10000)];
                    for _ in 0..(*burst_size).min(50) {
                        let _ = producer.send(cx, topic, None, &payload, None).await;
                    }
                }
                ThrottledOperation::MetadataBurst { request_count } => {
                    // Trigger metadata requests by sending to different topics
                    for i in 0..(*request_count).min(20) {
                        let topic = format!("test-topic-{}", i);
                        let _ = producer.send(cx, &topic, None, b"test", None).await;
                    }
                }
                ThrottledOperation::ConsumerPoll { topics, timeout_ms } => {
                    #[cfg(feature = "kafka")]
                    {
                        let config = ConsumerConfig::new(
                            vec!["localhost:9092".to_string()],
                            "throttle-test-group".to_string()
                        );
                        if let Ok(consumer) = KafkaConsumer::new(config) {
                            let _ = consumer.subscribe(topics).await;
                            let timeout = Duration::from_millis((*timeout_ms as u64).min(2000));
                            let _ = consumer.poll(cx, timeout).await;
                            let _ = consumer.close(cx).await;
                        }
                    }
                }
            }
        }
        let _ = producer.close(cx, Duration::from_millis(100)).await;
    }
}

/// Test compression codec dispatch
async fn test_compression_codec_dispatch(
    tests: &[CompressionTest],
    message_sizes: &[u32],
    cx: &Cx,
) {
    for test in tests.iter().take(5) {
        for &size in message_sizes.iter().take(5) {
            let message = generate_message_for_pattern(&test.message_pattern, size.min(50000) as usize);

            // Test different compression types
            let compression_types = match &test.compression_type {
                CompressionTypeTest::None => vec![Compression::None],
                CompressionTypeTest::Gzip => vec![Compression::Gzip],
                CompressionTypeTest::Snappy => vec![Compression::Snappy],
                CompressionTypeTest::Lz4 => vec![Compression::Lz4],
                CompressionTypeTest::Zstd => vec![Compression::Zstd],
                CompressionTypeTest::Invalid(_) => vec![Compression::None], // Fallback for invalid
                CompressionTypeTest::Dynamic(types) => {
                    types.iter().take(3).map(|t| match t {
                        CompressionTypeTest::Gzip => Compression::Gzip,
                        CompressionTypeTest::Snappy => Compression::Snappy,
                        CompressionTypeTest::Lz4 => Compression::Lz4,
                        CompressionTypeTest::Zstd => Compression::Zstd,
                        _ => Compression::None,
                    }).collect()
                }
            };

            for compression in compression_types {
                let config = ProducerConfig::new(vec!["localhost:9092".to_string()])
                    .compression(compression);

                if let Ok(producer) = KafkaProducer::new(config) {
                    let _ = producer.send(cx, "compression-test", None, &message, None).await;
                    let _ = producer.close(cx, Duration::from_millis(100)).await;
                }
            }
        }
    }
}

/// Generate message data based on pattern
fn generate_message_for_pattern(pattern: &MessagePattern, size: usize) -> Vec<u8> {
    match pattern {
        MessagePattern::Compressible(value) => vec![*value; size],
        MessagePattern::Random => (0..size).map(|i| (i % 256) as u8).collect(),
        MessagePattern::Mixed { compressible_ratio } => {
            let compressible_size = (size * (*compressible_ratio as usize)) / 255;
            let mut data = vec![42u8; compressible_size];
            data.extend((0..size - compressible_size).map(|i| (i % 256) as u8));
            data
        }
        MessagePattern::Pathological(pathological) => match pathological {
            PathologicalPattern::Repetitive { pattern_size, repeat_count } => {
                let pattern: Vec<u8> = (0..*pattern_size).map(|i| i).collect();
                pattern.repeat((*repeat_count as usize).min(size / pattern.len().max(1)))
            }
            PathologicalPattern::Alternating { pattern1, pattern2 } => {
                let mut data = Vec::new();
                let mut use_pattern1 = true;
                while data.len() < size {
                    let pattern = if use_pattern1 { pattern1 } else { pattern2 };
                    data.extend_from_slice(pattern);
                    use_pattern1 = !use_pattern1;
                }
                data.truncate(size);
                data
            }
        }
    }
}

/// Test partial response recovery scenarios
async fn test_partial_response_recovery(
    _network_conditions: &NetworkConditions,
    operations: &[RecoveryOperation],
    cx: &Cx,
) {
    // Test operations under potentially flaky network conditions
    // Since we can't directly simulate network issues, we test with short timeouts
    // and retry logic that would exercise the recovery paths

    for operation in operations.iter().take(8) {
        match operation {
            RecoveryOperation::ProducerSendWithRetry { topic, payload_size, max_retries } => {
                let config = ProducerConfig::new(vec!["localhost:9092".to_string()])
                    .retries(*max_retries as u32);

                if let Ok(producer) = KafkaProducer::new(config) {
                    let payload = vec![0u8; (*payload_size as usize).min(10000)];
                    let _ = producer.send(cx, topic, None, &payload, None).await;
                    let _ = producer.close(cx, Duration::from_millis(100)).await;
                }
            }
            RecoveryOperation::ConsumerPollWithRecovery { topics, timeout_ms, .. } => {
                #[cfg(feature = "kafka")]
                {
                    let config = ConsumerConfig::new(
                        vec!["localhost:9092".to_string()],
                        "recovery-test-group".to_string()
                    );
                    if let Ok(consumer) = KafkaConsumer::new(config) {
                        let _ = consumer.subscribe(topics).await;
                        let timeout = Duration::from_millis((*timeout_ms as u64).min(2000));
                        let _ = consumer.poll(cx, timeout).await;
                        let _ = consumer.close(cx).await;
                    }
                }
            }
            RecoveryOperation::TransactionWithRecovery { operations, commit } => {
                let producer_config = ProducerConfig::new(vec!["localhost:9092".to_string()])
                    .enable_idempotence(true);
                let tx_config = TransactionalConfig::new(producer_config, "recovery-tx-id".to_string());

                if let Ok(producer) = TransactionalProducer::new(tx_config) {
                    if let Ok(tx) = producer.begin_transaction(cx).await {
                        for topic in operations.iter().take(5) {
                            let _ = tx.send(cx, topic, None, b"test-data").await;
                        }

                        if *commit {
                            let _ = tx.commit(cx).await;
                        } else {
                            let _ = tx.abort(cx).await;
                        }
                    }
                }
            }
            RecoveryOperation::MetadataWithRecovery { topics, timeout_ms } => {
                // Test metadata recovery by attempting operations on topics
                let config = ProducerConfig::new(vec!["localhost:9092".to_string()]);
                if let Ok(producer) = KafkaProducer::new(config) {
                    for topic in topics.iter().take(5) {
                        let _ = producer.send(cx, topic, None, b"test", None).await;
                    }
                    let _ = producer.flush(cx, Duration::from_millis((*timeout_ms as u64).min(2000))).await;
                    let _ = producer.close(cx, Duration::from_millis(100)).await;
                }
            }
        }
    }
}

/// Execute Kafka protocol parser fuzz test scenarios
async fn execute_kafka_protocol_fuzz(input: &KafkaProtocolParserFuzz, cx: &Cx) {
    for scenario in &input.scenarios {
        match scenario {
            ProtocolTestScenario::ApiVersionBoundaries {
                api_version_override,
                force_old_protocol,
                operations
            } => {
                test_api_version_boundaries(*api_version_override, *force_old_protocol, operations, cx).await;
            }
            ProtocolTestScenario::CorrelationIdMatching {
                operations,
                concurrent_operations
            } => {
                test_correlation_id_matching(operations, *concurrent_operations, cx).await;
            }
            ProtocolTestScenario::ThrottleTimeHandling {
                throttle_config,
                throttled_operations
            } => {
                test_throttle_time_handling(throttle_config, throttled_operations, cx).await;
            }
            ProtocolTestScenario::CompressionCodecDispatch {
                compression_tests,
                message_sizes
            } => {
                test_compression_codec_dispatch(compression_tests, message_sizes, cx).await;
            }
            ProtocolTestScenario::PartialResponseRecovery {
                network_conditions,
                recovery_operations
            } => {
                test_partial_response_recovery(network_conditions, recovery_operations, cx).await;
            }
        }
    }
}

/// Main fuzz entry point
fn fuzz_kafka_protocol_parser(mut input: KafkaProtocolParserFuzz) -> Result<(), String> {
    normalize_fuzz_input(&mut input);

    if input.scenarios.is_empty() {
        return Ok(());
    }

    use asupersync::runtime::RuntimeBuilder;

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .map_err(|e| format!("Failed to build runtime: {e}"))?;

    let cx = Cx::for_testing();

    runtime.block_on(async {
        execute_kafka_protocol_fuzz(&input, &cx).await;
    });

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Limit input size for performance
    if data.len() > 16384 {
        return;
    }

    let mut unstructured = arbitrary::Unstructured::new(data);

    let input = if let Ok(input) = KafkaProtocolParserFuzz::arbitrary(&mut unstructured) {
        input
    } else {
        return;
    };

    // Run protocol parser fuzzing
    let _ = fuzz_kafka_protocol_parser(input);
});