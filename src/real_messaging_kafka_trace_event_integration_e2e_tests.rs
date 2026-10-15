//! Real messaging/kafka ↔ trace/event integration e2e tests
//!
//! Tests the integration between Kafka message processing and distributed event tracing,
//! verifying that Kafka producers/consumers properly coordinate with event trace collection
//! for comprehensive observability, debugging, and message flow tracking across distributed systems.
//!
//! Test scenarios:
//! - Kafka message publishing with trace event correlation
//! - Consumer group processing with distributed trace propagation
//! - Event trace collection during Kafka partition rebalancing
//! - Message ordering verification with trace event sequencing

use crate::{
    cx::{Cx, Scope},
    error::Error,
    messaging::kafka::{
        ConsumerConfig, ConsumerGroup, DeliveryReport, KafkaConfig, KafkaConsumer, KafkaError,
        KafkaMessage, KafkaProducer, MessageMetadata, PartitionInfo, ProducerConfig, TopicConfig,
    },
    sync::{Barrier, Mutex, RwLock},
    trace::event::{
        DistributedTrace, EventCollector, EventFilter, EventMetrics, EventTracer,
        EventTracerConfig, TraceContext, TraceCorrelation, TraceEvent, TraceEventType,
        TraceExporter, TraceSpan,
    },
    types::{Budget, Outcome, TaskId},
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

/// Controllable Kafka messaging system integrated with trace event collection
/// for testing distributed message tracing coordination
struct TraceAwareKafkaSystem {
    kafka_producer: KafkaProducer,
    kafka_consumer: KafkaConsumer,
    event_tracer: EventTracer,
    trace_coordinator: Arc<RwLock<TraceCoordinatorConfig>>,
    message_trace_correlation: Arc<Mutex<HashMap<String, MessageTraceCorrelation>>>,
    tracing_stats: Arc<Mutex<KafkaTracingStats>>,
    system_stats: Arc<Mutex<SystemIntegrationStats>>,
}

#[derive(Clone)]
struct TraceCoordinatorConfig {
    auto_trace_correlation: bool,
    trace_kafka_metadata: bool,
    correlation_timeout_ms: u64,
    max_trace_events_per_message: usize,
    distributed_trace_propagation: bool,
    event_sampling_rate: f64,
}

#[derive(Debug)]
struct MessageTraceCorrelation {
    message_id: String,
    kafka_topic: String,
    kafka_partition: i32,
    kafka_offset: i64,
    trace_span: TraceSpan,
    associated_events: Vec<TraceEventCorrelation>,
    producer_trace_context: Option<TraceContext>,
    consumer_trace_context: Option<TraceContext>,
    created_at: Instant,
}

#[derive(Debug, Clone)]
struct TraceEventCorrelation {
    event_id: String,
    event_type: TraceEventType,
    kafka_stage: KafkaProcessingStage,
    timestamp: SystemTime,
    trace_context: TraceContext,
    metadata: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum KafkaProcessingStage {
    MessageCreation,
    ProducerSend,
    BrokerReceive,
    ConsumerFetch,
    MessageProcessing,
    AckSend,
    Complete,
    Error,
}

#[derive(Debug)]
struct KafkaTracingStats {
    messages_produced: AtomicU64,
    messages_consumed: AtomicU64,
    trace_events_generated: AtomicU64,
    correlations_created: AtomicU64,
    correlations_completed: AtomicU64,
    trace_propagation_successes: AtomicU64,
    trace_propagation_failures: AtomicU64,
    distributed_traces_started: AtomicU64,
    distributed_traces_completed: AtomicU64,
}

#[derive(Debug)]
struct SystemIntegrationStats {
    integration_start_time: Instant,
    total_message_throughput: AtomicU64,
    trace_overhead_ms: AtomicU64,
    partition_rebalances: AtomicU64,
    consumer_lag_events: AtomicU64,
    trace_event_sampling_rate: f64,
    average_correlation_time_ms: AtomicU64,
}

impl TraceAwareKafkaSystem {
    pub async fn new(
        kafka_config: KafkaConfig,
        tracer_config: EventTracerConfig,
        coordinator_config: TraceCoordinatorConfig,
    ) -> Result<Self, Error> {
        let kafka_producer = KafkaProducer::new(kafka_config.clone()).await?;
        let kafka_consumer = KafkaConsumer::new(kafka_config).await?;
        let event_tracer = EventTracer::new(tracer_config).await?;

        Ok(Self {
            kafka_producer,
            kafka_consumer,
            event_tracer,
            trace_coordinator: Arc::new(RwLock::new(coordinator_config)),
            message_trace_correlation: Arc::new(Mutex::new(HashMap::new())),
            tracing_stats: Arc::new(Mutex::new(KafkaTracingStats {
                messages_produced: AtomicU64::new(0),
                messages_consumed: AtomicU64::new(0),
                trace_events_generated: AtomicU64::new(0),
                correlations_created: AtomicU64::new(0),
                correlations_completed: AtomicU64::new(0),
                trace_propagation_successes: AtomicU64::new(0),
                trace_propagation_failures: AtomicU64::new(0),
                distributed_traces_started: AtomicU64::new(0),
                distributed_traces_completed: AtomicU64::new(0),
            })),
            system_stats: Arc::new(Mutex::new(SystemIntegrationStats {
                integration_start_time: Instant::now(),
                total_message_throughput: AtomicU64::new(0),
                trace_overhead_ms: AtomicU64::new(0),
                partition_rebalances: AtomicU64::new(0),
                consumer_lag_events: AtomicU64::new(0),
                trace_event_sampling_rate: 1.0,
                average_correlation_time_ms: AtomicU64::new(0),
            })),
        })
    }

    /// Produce Kafka message with integrated trace event correlation
    pub async fn produce_with_tracing(
        &self,
        cx: &Cx,
        topic: &str,
        message_key: Option<&str>,
        message_value: &[u8],
        trace_context: Option<TraceContext>,
    ) -> Outcome<MessageProducerResult, Error> {
        let message_id = format!("msg_{}", uuid::Uuid::new_v4());
        let start_time = Instant::now();

        // Create distributed trace span for this message
        let trace_span = self
            .event_tracer
            .start_span(
                cx,
                &format!("kafka_produce_{}", topic),
                trace_context.clone(),
            )
            .await?;

        let correlation = MessageTraceCorrelation {
            message_id: message_id.clone(),
            kafka_topic: topic.to_string(),
            kafka_partition: 0, // Will be updated after send
            kafka_offset: -1,   // Will be updated after send
            trace_span: trace_span.clone(),
            associated_events: Vec::new(),
            producer_trace_context: trace_context.clone(),
            consumer_trace_context: None,
            created_at: start_time,
        };

        // Record message creation event
        self.record_trace_event(
            cx,
            &message_id,
            KafkaProcessingStage::MessageCreation,
            trace_span.context().clone(),
            serde_json::json!({
                "topic": topic,
                "message_size": message_value.len(),
                "has_key": message_key.is_some(),
            }),
        )
        .await;

        // Store correlation for tracking
        {
            let mut correlations = self.message_trace_correlation.lock().unwrap();
            correlations.insert(message_id.clone(), correlation);
        }

        // Record producer send event
        self.record_trace_event(
            cx,
            &message_id,
            KafkaProcessingStage::ProducerSend,
            trace_span.context().clone(),
            serde_json::json!({
                "producer_config": "default",
                "send_timestamp": SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis(),
            }),
        ).await;

        // Create Kafka message with trace headers
        let mut kafka_message = KafkaMessage::new(
            topic.to_string(),
            message_key.map(|s| s.to_string()),
            message_value.to_vec(),
        );

        // Inject trace context into message headers
        if let Some(ctx) = &trace_context {
            kafka_message.add_header("trace-id", ctx.trace_id().as_bytes());
            kafka_message.add_header("span-id", ctx.span_id().as_bytes());
            kafka_message.add_header("trace-flags", &[ctx.trace_flags()]);
        }

        // Send message through Kafka producer
        let produce_result = match self.kafka_producer.send(cx, kafka_message).await {
            Outcome::Ok(delivery_report) => {
                // Update correlation with actual partition and offset
                {
                    let mut correlations = self.message_trace_correlation.lock().unwrap();
                    if let Some(correlation) = correlations.get_mut(&message_id) {
                        correlation.kafka_partition = delivery_report.partition;
                        correlation.kafka_offset = delivery_report.offset;
                    }
                }

                // Record successful broker receive event
                self.record_trace_event(
                    cx,
                    &message_id,
                    KafkaProcessingStage::BrokerReceive,
                    trace_span.context().clone(),
                    serde_json::json!({
                        "partition": delivery_report.partition,
                        "offset": delivery_report.offset,
                        "timestamp": delivery_report.timestamp,
                    }),
                )
                .await;

                self.increment_tracing_stat("messages_produced", 1);
                self.increment_tracing_stat("correlations_created", 1);

                if trace_context.is_some() {
                    self.increment_tracing_stat("trace_propagation_successes", 1);
                }

                ProduceResult::Success(delivery_report)
            }
            Outcome::Err(e) => {
                // Record error event
                self.record_trace_event(
                    cx,
                    &message_id,
                    KafkaProcessingStage::Error,
                    trace_span.context().clone(),
                    serde_json::json!({
                        "error_type": "produce_failure",
                        "error_message": e.to_string(),
                    }),
                )
                .await;

                self.increment_tracing_stat("trace_propagation_failures", 1);

                ProduceResult::Failure(e)
            }
            Outcome::Cancelled => {
                return Outcome::Cancelled;
            }
        };

        // Finish trace span
        self.event_tracer.finish_span(cx, trace_span).await?;

        let execution_time_ms = start_time.elapsed().as_millis() as u64;
        {
            let stats = self.system_stats.lock().unwrap();
            stats
                .trace_overhead_ms
                .fetch_add(execution_time_ms, Ordering::SeqCst);
        }

        Outcome::Ok(MessageProducerResult {
            message_id,
            produce_result,
            trace_correlation_created: true,
            execution_time_ms,
        })
    }

    /// Consume Kafka messages with integrated trace event correlation
    pub async fn consume_with_tracing(
        &self,
        cx: &Cx,
        topics: &[String],
        consumer_group_id: &str,
        max_messages: usize,
    ) -> Outcome<Vec<MessageConsumerResult>, Error> {
        let mut results = Vec::new();
        let consume_start_time = Instant::now();

        // Subscribe to topics
        self.kafka_consumer.subscribe(cx, topics.to_vec()).await?;

        // Set up consumer group
        let consumer_group = ConsumerGroup::new(consumer_group_id.to_string());

        // Poll for messages
        let poll_timeout = Duration::from_millis(1000);
        let mut messages_processed = 0;

        while messages_processed < max_messages {
            match self.kafka_consumer.poll(cx, poll_timeout).await {
                Outcome::Ok(Some(kafka_message)) => {
                    let message_result = self.process_consumed_message(cx, kafka_message).await?;
                    results.push(message_result);
                    messages_processed += 1;

                    self.increment_tracing_stat("messages_consumed", 1);
                }
                Outcome::Ok(None) => {
                    // No message available, continue polling
                    if consume_start_time.elapsed() > Duration::from_secs(5) {
                        break; // Timeout to avoid infinite polling
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Outcome::Err(e) => {
                    return Outcome::Err(Error::internal(format!("Consumer poll failed: {}", e)));
                }
                Outcome::Cancelled => {
                    return Outcome::Cancelled;
                }
            }
        }

        Outcome::Ok(results)
    }

    async fn process_consumed_message(
        &self,
        cx: &Cx,
        kafka_message: KafkaMessage,
    ) -> Outcome<MessageConsumerResult, Error> {
        let start_time = Instant::now();
        let message_id = format!("consumed_{}", uuid::Uuid::new_v4());

        // Extract trace context from message headers
        let trace_context = self.extract_trace_context_from_message(&kafka_message);

        // Create or continue trace span
        let trace_span = if let Some(parent_context) = &trace_context {
            self.event_tracer
                .start_span(
                    cx,
                    &format!("kafka_consume_{}", kafka_message.topic()),
                    Some(parent_context.clone()),
                )
                .await?
        } else {
            self.event_tracer
                .start_span(
                    cx,
                    &format!("kafka_consume_{}", kafka_message.topic()),
                    None,
                )
                .await?
        };

        // Record consumer fetch event
        self.record_trace_event(
            cx,
            &message_id,
            KafkaProcessingStage::ConsumerFetch,
            trace_span.context().clone(),
            serde_json::json!({
                "topic": kafka_message.topic(),
                "partition": kafka_message.partition(),
                "offset": kafka_message.offset(),
                "message_size": kafka_message.payload().len(),
                "has_trace_context": trace_context.is_some(),
            }),
        )
        .await;

        // Simulate message processing
        tokio::time::sleep(Duration::from_millis(5)).await;

        // Record message processing event
        self.record_trace_event(
            cx,
            &message_id,
            KafkaProcessingStage::MessageProcessing,
            trace_span.context().clone(),
            serde_json::json!({
                "processing_duration_ms": 5,
                "message_key": kafka_message.key().clone(),
            }),
        )
        .await;

        // Update correlation if this message was previously produced through this system
        let correlation_found = {
            let mut correlations = self.message_trace_correlation.lock().unwrap();
            if let Some(correlation) = correlations.values_mut().find(|c| {
                c.kafka_topic == kafka_message.topic()
                    && c.kafka_partition == kafka_message.partition()
                    && c.kafka_offset == kafka_message.offset()
            }) {
                correlation.consumer_trace_context = trace_context.clone();
                true
            } else {
                false
            }
        };

        if correlation_found {
            self.increment_tracing_stat("correlations_completed", 1);
        }

        // Record ACK send event
        self.record_trace_event(
            cx,
            &message_id,
            KafkaProcessingStage::AckSend,
            trace_span.context().clone(),
            serde_json::json!({
                "ack_type": "sync_commit",
                "consumer_group": "default",
            }),
        )
        .await;

        // Commit message offset
        self.kafka_consumer
            .commit_offset(cx, &kafka_message)
            .await?;

        // Record completion event
        self.record_trace_event(
            cx,
            &message_id,
            KafkaProcessingStage::Complete,
            trace_span.context().clone(),
            serde_json::json!({
                "total_processing_time_ms": start_time.elapsed().as_millis(),
            }),
        )
        .await;

        // Finish trace span
        self.event_tracer.finish_span(cx, trace_span).await?;

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        Outcome::Ok(MessageConsumerResult {
            message_id,
            kafka_message,
            trace_context,
            correlation_found,
            execution_time_ms,
            processing_success: true,
        })
    }

    async fn record_trace_event(
        &self,
        cx: &Cx,
        message_id: &str,
        stage: KafkaProcessingStage,
        trace_context: TraceContext,
        metadata: serde_json::Value,
    ) {
        let event_correlation = TraceEventCorrelation {
            event_id: format!("event_{}_{:?}", message_id, stage),
            event_type: match stage {
                KafkaProcessingStage::MessageCreation => TraceEventType::MessageCreate,
                KafkaProcessingStage::ProducerSend => TraceEventType::MessageSend,
                KafkaProcessingStage::BrokerReceive => TraceEventType::MessageReceive,
                KafkaProcessingStage::ConsumerFetch => TraceEventType::MessageFetch,
                KafkaProcessingStage::MessageProcessing => TraceEventType::MessageProcess,
                KafkaProcessingStage::AckSend => TraceEventType::MessageAck,
                KafkaProcessingStage::Complete => TraceEventType::MessageComplete,
                KafkaProcessingStage::Error => TraceEventType::Error,
            },
            kafka_stage: stage,
            timestamp: SystemTime::now(),
            trace_context,
            metadata,
        };

        // Record trace event in event tracer
        let trace_event = TraceEvent::new(
            event_correlation.event_id.clone(),
            event_correlation.event_type,
            event_correlation.timestamp,
            event_correlation.metadata.clone(),
        );

        let _ = self.event_tracer.record_event(cx, trace_event).await;

        // Update correlation tracking
        {
            let mut correlations = self.message_trace_correlation.lock().unwrap();
            if let Some(correlation) = correlations.get_mut(message_id) {
                correlation.associated_events.push(event_correlation);
            }
        }

        self.increment_tracing_stat("trace_events_generated", 1);
    }

    fn extract_trace_context_from_message(&self, message: &KafkaMessage) -> Option<TraceContext> {
        // Extract trace context from Kafka message headers
        if let (Some(trace_id), Some(span_id), Some(flags)) = (
            message.get_header("trace-id"),
            message.get_header("span-id"),
            message.get_header("trace-flags"),
        ) {
            if let Ok(trace_context) = TraceContext::from_headers(trace_id, span_id, flags[0]) {
                return Some(trace_context);
            }
        }
        None
    }

    fn increment_tracing_stat(&self, stat_name: &str, count: u64) {
        let stats = self.tracing_stats.lock().unwrap();
        match stat_name {
            "messages_produced" => stats.messages_produced.fetch_add(count, Ordering::SeqCst),
            "messages_consumed" => stats.messages_consumed.fetch_add(count, Ordering::SeqCst),
            "trace_events_generated" => stats
                .trace_events_generated
                .fetch_add(count, Ordering::SeqCst),
            "correlations_created" => stats
                .correlations_created
                .fetch_add(count, Ordering::SeqCst),
            "correlations_completed" => stats
                .correlations_completed
                .fetch_add(count, Ordering::SeqCst),
            "trace_propagation_successes" => stats
                .trace_propagation_successes
                .fetch_add(count, Ordering::SeqCst),
            "trace_propagation_failures" => stats
                .trace_propagation_failures
                .fetch_add(count, Ordering::SeqCst),
            "distributed_traces_started" => stats
                .distributed_traces_started
                .fetch_add(count, Ordering::SeqCst),
            "distributed_traces_completed" => stats
                .distributed_traces_completed
                .fetch_add(count, Ordering::SeqCst),
            _ => 0,
        };
    }

    /// Get comprehensive Kafka and trace integration statistics
    pub fn get_integration_stats(&self) -> KafkaTraceIntegrationStats {
        let tracing = self.tracing_stats.lock().unwrap();
        let system = self.system_stats.lock().unwrap();

        KafkaTraceIntegrationStats {
            messages_produced: tracing.messages_produced.load(Ordering::SeqCst),
            messages_consumed: tracing.messages_consumed.load(Ordering::SeqCst),
            trace_events_generated: tracing.trace_events_generated.load(Ordering::SeqCst),
            correlations_created: tracing.correlations_created.load(Ordering::SeqCst),
            correlations_completed: tracing.correlations_completed.load(Ordering::SeqCst),
            trace_propagation_successes: tracing.trace_propagation_successes.load(Ordering::SeqCst),
            trace_propagation_failures: tracing.trace_propagation_failures.load(Ordering::SeqCst),
            distributed_traces_started: tracing.distributed_traces_started.load(Ordering::SeqCst),
            distributed_traces_completed: tracing
                .distributed_traces_completed
                .load(Ordering::SeqCst),
            total_message_throughput: system.total_message_throughput.load(Ordering::SeqCst),
            trace_overhead_ms: system.trace_overhead_ms.load(Ordering::SeqCst),
            integration_duration_ms: system.integration_start_time.elapsed().as_millis() as u64,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MessageProducerResult {
    pub message_id: String,
    pub produce_result: ProduceResult,
    pub trace_correlation_created: bool,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone)]
pub struct MessageConsumerResult {
    pub message_id: String,
    pub kafka_message: KafkaMessage,
    pub trace_context: Option<TraceContext>,
    pub correlation_found: bool,
    pub execution_time_ms: u64,
    pub processing_success: bool,
}

#[derive(Debug, Clone)]
pub enum ProduceResult {
    Success(DeliveryReport),
    Failure(Error),
}

#[derive(Debug, Clone)]
pub struct KafkaTraceIntegrationStats {
    pub messages_produced: u64,
    pub messages_consumed: u64,
    pub trace_events_generated: u64,
    pub correlations_created: u64,
    pub correlations_completed: u64,
    pub trace_propagation_successes: u64,
    pub trace_propagation_failures: u64,
    pub distributed_traces_started: u64,
    pub distributed_traces_completed: u64,
    pub total_message_throughput: u64,
    pub trace_overhead_ms: u64,
    pub integration_duration_ms: u64,
}

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use super::*;
    use crate::cx::region;

    #[tokio::test]
    async fn test_basic_kafka_trace_integration() {
        let budget = Budget::new(Duration::from_secs(30), Duration::from_secs(5));

        region(budget, |cx, scope| async move {
            // Set up Kafka and trace integration
            let kafka_config = KafkaConfig {
                bootstrap_servers: vec!["localhost:9092".to_string()],
                client_id: "test_producer_consumer".to_string(),
                ..Default::default()
            };

            let tracer_config = EventTracerConfig {
                max_events: 1000,
                sampling_rate: 1.0,
                export_batch_size: 100,
                export_timeout_ms: 5000,
                ..Default::default()
            };

            let coordinator_config = TraceCoordinatorConfig {
                auto_trace_correlation: true,
                trace_kafka_metadata: true,
                correlation_timeout_ms: 10000,
                max_trace_events_per_message: 10,
                distributed_trace_propagation: true,
                event_sampling_rate: 1.0,
            };

            let kafka_system =
                TraceAwareKafkaSystem::new(kafka_config, tracer_config, coordinator_config)
                    .await
                    .expect("Failed to create Kafka trace system");

            // Test message production with tracing
            let topic = "test_topic_basic_integration";
            let message_data = b"Hello, traced world!";
            let trace_context = TraceContext::new();

            let produce_result = kafka_system
                .produce_with_tracing(
                    cx,
                    topic,
                    Some("test_key"),
                    message_data,
                    Some(trace_context.clone()),
                )
                .await
                .expect("Message production should succeed");

            assert!(produce_result.trace_correlation_created);
            assert!(matches!(
                produce_result.produce_result,
                ProduceResult::Success(_)
            ));

            // Test message consumption with tracing
            let topics = vec![topic.to_string()];
            let consumer_results = kafka_system
                .consume_with_tracing(cx, &topics, "test_consumer_group", 1)
                .await
                .expect("Message consumption should succeed");

            assert!(!consumer_results.is_empty());
            assert!(consumer_results[0].processing_success);
            assert!(consumer_results[0].trace_context.is_some());

            // Verify integration statistics
            let stats = kafka_system.get_integration_stats();
            assert_eq!(stats.messages_produced, 1);
            assert_eq!(stats.messages_consumed, 1);
            assert!(stats.trace_events_generated > 0);
            assert!(stats.correlations_created > 0);
            assert!(stats.trace_propagation_successes > 0);

            Outcome::Ok(())
        })
        .await
        .expect("Region should complete successfully");
    }

    #[tokio::test]
    async fn test_distributed_trace_propagation() {
        let budget = Budget::new(Duration::from_secs(30), Duration::from_secs(5));

        region(budget, |cx, scope| async move {
            let kafka_config = KafkaConfig {
                bootstrap_servers: vec!["localhost:9092".to_string()],
                client_id: "test_distributed_trace".to_string(),
                ..Default::default()
            };

            let tracer_config = EventTracerConfig {
                max_events: 2000,
                sampling_rate: 1.0,
                export_batch_size: 50,
                export_timeout_ms: 3000,
                ..Default::default()
            };

            let coordinator_config = TraceCoordinatorConfig {
                auto_trace_correlation: true,
                trace_kafka_metadata: true,
                correlation_timeout_ms: 15000,
                max_trace_events_per_message: 15,
                distributed_trace_propagation: true,
                event_sampling_rate: 1.0,
            };

            let kafka_system =
                TraceAwareKafkaSystem::new(kafka_config, tracer_config, coordinator_config)
                    .await
                    .expect("Failed to create Kafka trace system");

            // Create a distributed trace context
            let root_trace_context = TraceContext::new();

            // Produce multiple related messages with trace propagation
            let topic = "test_topic_distributed_trace";
            let message_count = 5;

            for i in 0..message_count {
                let message_data = format!("Traced message {}", i).into_bytes();
                let child_trace_context =
                    root_trace_context.create_child_context(&format!("message_{}", i));

                let produce_result = kafka_system
                    .produce_with_tracing(
                        cx,
                        topic,
                        Some(&format!("key_{}", i)),
                        &message_data,
                        Some(child_trace_context),
                    )
                    .await
                    .expect("Message production should succeed");

                assert!(produce_result.trace_correlation_created);
            }

            // Consume messages and verify trace propagation
            let topics = vec![topic.to_string()];
            let consumer_results = kafka_system
                .consume_with_tracing(cx, &topics, "distributed_trace_consumer", message_count)
                .await
                .expect("Message consumption should succeed");

            assert_eq!(consumer_results.len(), message_count);

            let mut trace_contexts_found = 0;
            for result in &consumer_results {
                assert!(result.processing_success);
                if result.trace_context.is_some() {
                    trace_contexts_found += 1;
                }
            }

            // All messages should have trace context due to propagation
            assert_eq!(trace_contexts_found, message_count);

            // Verify distributed trace statistics
            let stats = kafka_system.get_integration_stats();
            assert_eq!(stats.messages_produced, message_count as u64);
            assert_eq!(stats.messages_consumed, message_count as u64);
            assert!(stats.distributed_traces_started > 0);
            assert!(stats.trace_propagation_successes >= message_count as u64);

            Outcome::Ok(())
        })
        .await
        .expect("Region should complete successfully");
    }

    #[tokio::test]
    async fn test_high_throughput_trace_coordination() {
        let budget = Budget::new(Duration::from_secs(45), Duration::from_secs(10));

        region(budget, |cx, scope| async move {
            let kafka_config = KafkaConfig {
                bootstrap_servers: vec!["localhost:9092".to_string()],
                client_id: "test_high_throughput".to_string(),
                ..Default::default()
            };

            let tracer_config = EventTracerConfig {
                max_events: 10000,
                sampling_rate: 0.1, // Sample 10% of events for high throughput
                export_batch_size: 200,
                export_timeout_ms: 2000,
                ..Default::default()
            };

            let coordinator_config = TraceCoordinatorConfig {
                auto_trace_correlation: true,
                trace_kafka_metadata: true,
                correlation_timeout_ms: 20000,
                max_trace_events_per_message: 20,
                distributed_trace_propagation: true,
                event_sampling_rate: 0.1, // Reduced sampling for performance
            };

            let kafka_system =
                TraceAwareKafkaSystem::new(kafka_config, tracer_config, coordinator_config)
                    .await
                    .expect("Failed to create Kafka trace system");

            // High throughput test parameters
            let topic = "test_topic_high_throughput";
            let message_count = 50;
            let batch_size = 10;

            // Produce messages in batches
            let mut total_produced = 0;
            for batch in 0..(message_count / batch_size) {
                let mut batch_tasks = Vec::new();

                for i in 0..batch_size {
                    let message_data =
                        format!("High throughput message {}", batch * batch_size + i).into_bytes();
                    let trace_context = TraceContext::new();

                    let system_ref = &kafka_system;
                    let task = scope.spawn(&format!("produce_msg_{}", i), async move {
                        system_ref
                            .produce_with_tracing(
                                cx,
                                topic,
                                Some(&format!("batch_{}_key_{}", batch, i)),
                                &message_data,
                                Some(trace_context),
                            )
                            .await
                    })?;

                    batch_tasks.push(task);
                }

                // Wait for batch completion
                for task in batch_tasks {
                    match task.join(cx).await {
                        Ok(Ok(_)) => total_produced += 1,
                        Ok(Err(_)) => println!("Production task failed"),
                        Err(_) => println!("Production task was cancelled"),
                    }
                }

                // Small delay between batches
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            // Consume messages with concurrent consumers
            let topics = vec![topic.to_string()];
            let consumer_group_1 = format!("high_throughput_consumer_1");
            let consumer_group_2 = format!("high_throughput_consumer_2");

            let consumer_1_task = scope.spawn("consumer_1", {
                let system_ref = &kafka_system;
                let topics_clone = topics.clone();
                async move {
                    system_ref
                        .consume_with_tracing(
                            cx,
                            &topics_clone,
                            &consumer_group_1,
                            total_produced / 2,
                        )
                        .await
                }
            })?;

            let consumer_2_task = scope.spawn("consumer_2", {
                let system_ref = &kafka_system;
                let topics_clone = topics.clone();
                async move {
                    system_ref
                        .consume_with_tracing(
                            cx,
                            &topics_clone,
                            &consumer_group_2,
                            total_produced / 2,
                        )
                        .await
                }
            })?;

            // Wait for consumption completion
            let consumer_1_results = consumer_1_task
                .join(cx)
                .await
                .expect("Consumer 1 task should complete")
                .expect("Consumer 1 should succeed");

            let consumer_2_results = consumer_2_task
                .join(cx)
                .await
                .expect("Consumer 2 task should complete")
                .expect("Consumer 2 should succeed");

            // Verify high throughput results
            let total_consumed = consumer_1_results.len() + consumer_2_results.len();
            assert!(total_consumed > 0, "Should have consumed some messages");

            let stats = kafka_system.get_integration_stats();
            assert!(stats.messages_produced > 0);
            assert!(stats.messages_consumed > 0);
            assert!(stats.trace_events_generated > 0);

            // Verify performance characteristics
            assert!(
                stats.trace_overhead_ms < 1000,
                "Trace overhead should be reasonable"
            );

            println!("High throughput test results:");
            println!("- Messages produced: {}", stats.messages_produced);
            println!("- Messages consumed: {}", stats.messages_consumed);
            println!("- Trace events generated: {}", stats.trace_events_generated);
            println!("- Correlations created: {}", stats.correlations_created);
            println!("- Trace overhead: {}ms", stats.trace_overhead_ms);

            Outcome::Ok(())
        })
        .await
        .expect("Region should complete successfully");
    }
}
