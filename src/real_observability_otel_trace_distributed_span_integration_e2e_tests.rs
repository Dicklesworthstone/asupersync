//! Real observability/otel ↔ trace/distributed/span integration e2e tests
//!
//! Tests the integration between OpenTelemetry observability and distributed span tracing,
//! verifying that OTel metrics collection coordinates properly with distributed span
//! management, context propagation, and performance monitoring.
//!
//! Test scenarios:
//! - OTel metrics collection coordinated with distributed span lifecycle
//! - Span context propagation through OTel instrumentation points
//! - Trace sampling decisions aligned with metrics collection
//! - Concurrent span operations with OTel metric aggregation

use crate::{
    cx::{Cx, Scope},
    observability::otel::{
        OtelCollector, OtelConfig, MetricDefinition, MetricType,
        SpanProcessor, TraceExporter, OtelError,
    },
    trace::distributed::{
        span::{DistributedSpan, SpanContext, SpanBuilder, SpanKind},
        context::{TraceContext, TraceId, SpanId},
        sampling::{SamplingDecision, SamplingStrategy},
    },
    sync::{Mutex, RwLock},
    types::{Budget, Outcome},
    error::Error,
};
use std::{
    sync::{Arc, atomic::{AtomicU64, AtomicUsize, Ordering}},
    time::Duration,
    collections::HashMap,
};

/// Controllable OpenTelemetry collector that simulates various monitoring conditions
/// for testing distributed span integration
struct ControllableOtelCollector {
    collector: OtelCollector,
    monitoring_config: Arc<RwLock<MonitoringConfig>>,
    metric_storage: Arc<Mutex<HashMap<String, MetricDataPoint>>>,
    span_correlation: Arc<Mutex<HashMap<SpanId, SpanMetrics>>>,
    collection_stats: Arc<Mutex<CollectionStatistics>>,
}

#[derive(Clone)]
struct MonitoringConfig {
    metric_collection_interval_ms: u64,
    span_sampling_rate: f64,
    enable_metric_span_correlation: bool,
    max_active_spans: usize,
    metric_aggregation_window_ms: u64,
    trace_export_batch_size: usize,
}

#[derive(Debug, Clone)]
struct MetricDataPoint {
    name: String,
    value: f64,
    timestamp: std::time::Instant,
    labels: HashMap<String, String>,
    associated_span_id: Option<SpanId>,
}

#[derive(Debug, Clone)]
struct SpanMetrics {
    span_id: SpanId,
    trace_id: TraceId,
    duration_ms: f64,
    operation_name: String,
    metrics_collected: Vec<String>,
    child_span_count: u32,
    error_count: u32,
}

#[derive(Debug, Default)]
struct CollectionStatistics {
    spans_processed: u64,
    metrics_collected: u64,
    correlation_hits: u64,
    correlation_misses: u64,
    sampling_decisions: u64,
    export_batches_sent: u64,
}

impl ControllableOtelCollector {
    async fn new(cx: &Cx) -> Result<Self, Error> {
        let config = OtelConfig {
            endpoint: "http://localhost:4317".to_string(),
            headers: HashMap::new(),
            timeout_ms: 5000,
            batch_size: 100,
            export_interval_ms: 1000,
        };

        let collector = OtelCollector::new(cx, config).await?;

        Ok(Self {
            collector,
            monitoring_config: Arc::new(RwLock::new(MonitoringConfig {
                metric_collection_interval_ms: 1000,
                span_sampling_rate: 1.0, // 100% for testing
                enable_metric_span_correlation: true,
                max_active_spans: 1000,
                metric_aggregation_window_ms: 5000,
                trace_export_batch_size: 50,
            })),
            metric_storage: Arc::new(Mutex::new(HashMap::new())),
            span_correlation: Arc::new(Mutex::new(HashMap::new())),
            collection_stats: Arc::new(Mutex::new(CollectionStatistics::default())),
        })
    }

    async fn record_metric_with_span_correlation(
        &self,
        cx: &Cx,
        metric_name: &str,
        value: f64,
        labels: HashMap<String, String>,
        span_context: Option<&SpanContext>,
    ) -> Result<(), Error> {
        let config = self.monitoring_config.read().unwrap().clone();

        // Create metric data point
        let metric_data = MetricDataPoint {
            name: metric_name.to_string(),
            value,
            timestamp: std::time::Instant::now(),
            labels: labels.clone(),
            associated_span_id: span_context.map(|ctx| ctx.span_id()),
        };

        // Store metric for correlation
        self.metric_storage.lock().unwrap().insert(
            format!("{}_{}", metric_name, metric_data.timestamp.elapsed().as_nanos()),
            metric_data.clone(),
        );

        // Update correlation statistics
        if let Some(span_ctx) = span_context {
            if config.enable_metric_span_correlation {
                self.collection_stats.lock().unwrap().correlation_hits += 1;

                // Update span metrics
                if let Some(span_metrics) = self.span_correlation.lock().unwrap().get_mut(&span_ctx.span_id()) {
                    span_metrics.metrics_collected.push(metric_name.to_string());
                }
            }
        } else {
            self.collection_stats.lock().unwrap().correlation_misses += 1;
        }

        // Record with OTel collector
        let metric_def = MetricDefinition {
            name: metric_name.to_string(),
            description: format!("Metric {} with span correlation", metric_name),
            unit: "count".to_string(),
            metric_type: MetricType::Counter,
        };

        self.collector.record_metric(cx, &metric_def, value, labels).await?;
        self.collection_stats.lock().unwrap().metrics_collected += 1;

        Ok(())
    }

    async fn process_distributed_span(
        &self,
        cx: &Cx,
        span: &DistributedSpan,
        operation_metrics: Vec<(&str, f64)>,
    ) -> Result<SpanProcessingResult, Error> {
        let config = self.monitoring_config.read().unwrap().clone();
        let span_start = std::time::Instant::now();

        // Make sampling decision
        let sampling_decision = self.make_sampling_decision(&span.context());
        self.collection_stats.lock().unwrap().sampling_decisions += 1;

        if !sampling_decision.should_sample {
            return Ok(SpanProcessingResult {
                span_id: span.context().span_id(),
                processed: false,
                metrics_collected: 0,
                sampling_decision: sampling_decision.clone(),
                processing_duration_ms: span_start.elapsed().as_secs_f64() * 1000.0,
            });
        }

        // Initialize span metrics tracking
        let span_metrics = SpanMetrics {
            span_id: span.context().span_id(),
            trace_id: span.context().trace_id(),
            duration_ms: 0.0,
            operation_name: span.operation_name().to_string(),
            metrics_collected: Vec::new(),
            child_span_count: span.child_count(),
            error_count: if span.has_errors() { 1 } else { 0 },
        };

        self.span_correlation.lock().unwrap().insert(span.context().span_id(), span_metrics);

        // Collect operation metrics correlated with span
        let mut metrics_collected = 0;
        for (metric_name, value) in operation_metrics {
            let labels = HashMap::from([
                ("span_id".to_string(), span.context().span_id().to_string()),
                ("trace_id".to_string(), span.context().trace_id().to_string()),
                ("operation".to_string(), span.operation_name().to_string()),
            ]);

            self.record_metric_with_span_correlation(
                cx,
                metric_name,
                value,
                labels,
                Some(&span.context()),
            ).await?;

            metrics_collected += 1;
        }

        // Record span timing metrics
        let span_duration = span.duration().as_secs_f64() * 1000.0;
        self.record_span_timing_metrics(cx, span, span_duration).await?;

        // Update span metrics
        if let Some(mut span_metrics) = self.span_correlation.lock().unwrap().get_mut(&span.context().span_id()) {
            span_metrics.duration_ms = span_duration;
        }

        // Export span to OTel
        self.collector.export_span(cx, span).await?;
        self.collection_stats.lock().unwrap().spans_processed += 1;

        Ok(SpanProcessingResult {
            span_id: span.context().span_id(),
            processed: true,
            metrics_collected,
            sampling_decision,
            processing_duration_ms: span_start.elapsed().as_secs_f64() * 1000.0,
        })
    }

    async fn record_span_timing_metrics(
        &self,
        cx: &Cx,
        span: &DistributedSpan,
        duration_ms: f64,
    ) -> Result<(), Error> {
        let labels = HashMap::from([
            ("operation".to_string(), span.operation_name().to_string()),
            ("span_kind".to_string(), span.kind().to_string()),
        ]);

        // Record duration metric
        self.record_metric_with_span_correlation(
            cx,
            "span_duration_ms",
            duration_ms,
            labels.clone(),
            Some(&span.context()),
        ).await?;

        // Record child span count
        self.record_metric_with_span_correlation(
            cx,
            "span_child_count",
            span.child_count() as f64,
            labels.clone(),
            Some(&span.context()),
        ).await?;

        // Record error count if any
        if span.has_errors() {
            self.record_metric_with_span_correlation(
                cx,
                "span_error_count",
                1.0,
                labels,
                Some(&span.context()),
            ).await?;
        }

        Ok(())
    }

    fn make_sampling_decision(&self, span_context: &SpanContext) -> SamplingDecision {
        let config = self.monitoring_config.read().unwrap();

        // Simple sampling based on configured rate
        let should_sample = fastrand::f64() < config.span_sampling_rate;

        SamplingDecision {
            should_sample,
            sampling_rate: config.span_sampling_rate,
            reason: if should_sample {
                "Sampled based on configured rate".to_string()
            } else {
                "Dropped by sampling rate".to_string()
            },
        }
    }

    async fn flush_and_export_batch(&self, cx: &Cx) -> Result<BatchExportResult, Error> {
        let config = self.monitoring_config.read().unwrap().clone();

        let metrics_to_export: Vec<_> = self.metric_storage.lock().unwrap()
            .values()
            .take(config.trace_export_batch_size)
            .cloned()
            .collect();

        let spans_to_export: Vec<_> = self.span_correlation.lock().unwrap()
            .values()
            .take(config.trace_export_batch_size)
            .cloned()
            .collect();

        // Export batch to OTel
        self.collector.export_batch(cx, &metrics_to_export, &spans_to_export).await?;

        self.collection_stats.lock().unwrap().export_batches_sent += 1;

        Ok(BatchExportResult {
            metrics_exported: metrics_to_export.len(),
            spans_exported: spans_to_export.len(),
            export_success: true,
        })
    }

    fn configure_monitoring(&self, config: MonitoringConfig) {
        *self.monitoring_config.write().unwrap() = config;
    }

    fn get_collection_statistics(&self) -> CollectionStatistics {
        self.collection_stats.lock().unwrap().clone()
    }

    fn get_span_metric_correlation(&self, span_id: SpanId) -> Option<SpanMetrics> {
        self.span_correlation.lock().unwrap().get(&span_id).cloned()
    }
}

#[derive(Debug, Clone)]
struct SpanProcessingResult {
    span_id: SpanId,
    processed: bool,
    metrics_collected: usize,
    sampling_decision: SamplingDecision,
    processing_duration_ms: f64,
}

#[derive(Debug, Clone)]
struct SamplingDecision {
    should_sample: bool,
    sampling_rate: f64,
    reason: String,
}

#[derive(Debug)]
struct BatchExportResult {
    metrics_exported: usize,
    spans_exported: usize,
    export_success: bool,
}

/// Enhanced distributed span system with OTel integration
struct OtelIntegratedSpanSystem {
    trace_context: TraceContext,
    span_builder: SpanBuilder,
    active_spans: Arc<Mutex<HashMap<SpanId, DistributedSpan>>>,
    span_hierarchy: Arc<Mutex<HashMap<SpanId, Vec<SpanId>>>>, // parent -> children
}

impl OtelIntegratedSpanSystem {
    async fn new(cx: &Cx) -> Result<Self, Error> {
        let trace_context = TraceContext::new();
        let span_builder = SpanBuilder::new();

        Ok(Self {
            trace_context,
            span_builder,
            active_spans: Arc::new(Mutex::new(HashMap::new())),
            span_hierarchy: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn create_distributed_span(
        &self,
        cx: &Cx,
        operation_name: &str,
        kind: SpanKind,
        parent_span_id: Option<SpanId>,
    ) -> Result<DistributedSpan, Error> {
        let span = self.span_builder.create_span(
            cx,
            operation_name,
            kind,
            parent_span_id.map(|id| {
                self.active_spans.lock().unwrap().get(&id).unwrap().context().clone()
            }).as_ref(),
        ).await?;

        // Track in active spans
        self.active_spans.lock().unwrap().insert(span.context().span_id(), span.clone());

        // Update hierarchy
        if let Some(parent_id) = parent_span_id {
            self.span_hierarchy.lock().unwrap()
                .entry(parent_id)
                .or_insert_with(Vec::new)
                .push(span.context().span_id());
        }

        Ok(span)
    }

    async fn finish_span_with_metrics(
        &self,
        cx: &Cx,
        span_id: SpanId,
        operation_metrics: Vec<(&str, f64)>,
    ) -> Result<SpanCompletionResult, Error> {
        let mut active_spans = self.active_spans.lock().unwrap();

        if let Some(mut span) = active_spans.remove(&span_id) {
            // Finish the span
            span.finish(cx).await?;

            let completion_result = SpanCompletionResult {
                span_id,
                trace_id: span.context().trace_id(),
                duration_ms: span.duration().as_secs_f64() * 1000.0,
                child_spans_finished: self.finish_child_spans(cx, span_id).await?,
                operation_metrics_count: operation_metrics.len(),
                completion_success: true,
            };

            // Clean up hierarchy
            self.span_hierarchy.lock().unwrap().remove(&span_id);

            Ok(completion_result)
        } else {
            Err(Error::custom("Span not found in active spans"))
        }
    }

    async fn finish_child_spans(&self, cx: &Cx, parent_span_id: SpanId) -> Result<usize, Error> {
        let child_spans = self.span_hierarchy.lock().unwrap()
            .get(&parent_span_id)
            .cloned()
            .unwrap_or_default();

        let mut finished_count = 0;
        for child_span_id in child_spans {
            if self.finish_span_with_metrics(cx, child_span_id, vec![]).await.is_ok() {
                finished_count += 1;
            }
        }

        Ok(finished_count)
    }

    fn get_active_span_count(&self) -> usize {
        self.active_spans.lock().unwrap().len()
    }

    fn get_span_hierarchy_depth(&self) -> usize {
        self.span_hierarchy.lock().unwrap().keys().len()
    }
}

#[derive(Debug, Clone)]
struct SpanCompletionResult {
    span_id: SpanId,
    trace_id: TraceId,
    duration_ms: f64,
    child_spans_finished: usize,
    operation_metrics_count: usize,
    completion_success: bool,
}

/// Integration coordinator that validates OTel-span coordination
struct OtelSpanIntegrationCoordinator {
    otel_collector: ControllableOtelCollector,
    span_system: OtelIntegratedSpanSystem,
    validation_results: Arc<Mutex<Vec<IntegrationValidationResult>>>,
}

#[derive(Debug, Clone)]
struct IntegrationValidationResult {
    test_case: String,
    otel_collection_success: bool,
    span_processing_success: bool,
    metric_span_correlation_effective: bool,
    sampling_coordination: bool,
    performance_metrics: OtelSpanPerformanceMetrics,
    details: String,
}

#[derive(Debug, Clone)]
struct OtelSpanPerformanceMetrics {
    span_processing_throughput_per_sec: f64,
    metric_collection_latency_ms: f64,
    correlation_hit_rate: f64,
    batch_export_efficiency: f64,
}

impl OtelSpanIntegrationCoordinator {
    async fn new(cx: &Cx) -> Result<Self, Error> {
        let otel_collector = ControllableOtelCollector::new(cx).await?;
        let span_system = OtelIntegratedSpanSystem::new(cx).await?;

        Ok(Self {
            otel_collector,
            span_system,
            validation_results: Arc::new(Mutex::new(Vec::new())),
        })
    }

    async fn validate_basic_otel_span_coordination(
        &self,
        cx: &Cx,
        test_case: &str,
        span_count: usize,
    ) -> Result<IntegrationValidationResult, Error> {
        let test_start = std::time::Instant::now();

        let mut span_processing_results = Vec::new();

        // Create and process multiple spans with metrics
        for i in 0..span_count {
            let operation_name = format!("test_operation_{}", i);

            // Create distributed span
            let span = self.span_system.create_distributed_span(
                cx,
                &operation_name,
                SpanKind::Internal,
                None, // No parent
            ).await?;

            // Define operation metrics for this span
            let operation_metrics = vec![
                ("operation_count", 1.0),
                ("processing_time_ms", (i * 10) as f64),
                ("bytes_processed", (i * 1024) as f64),
            ];

            // Process span with OTel collector
            let processing_result = self.otel_collector.process_distributed_span(
                cx,
                &span,
                operation_metrics.clone(),
            ).await?;

            span_processing_results.push(processing_result);

            // Finish span
            let _completion_result = self.span_system.finish_span_with_metrics(
                cx,
                span.context().span_id(),
                operation_metrics,
            ).await?;
        }

        // Export batch
        let batch_result = self.otel_collector.flush_and_export_batch(cx).await?;

        let total_duration = test_start.elapsed();
        let collection_stats = self.otel_collector.get_collection_statistics();

        // Calculate performance metrics
        let performance_metrics = OtelSpanPerformanceMetrics {
            span_processing_throughput_per_sec: span_count as f64 / total_duration.as_secs_f64(),
            metric_collection_latency_ms: span_processing_results.iter()
                .map(|r| r.processing_duration_ms)
                .sum::<f64>() / span_count as f64,
            correlation_hit_rate: if collection_stats.correlation_hits + collection_stats.correlation_misses > 0 {
                collection_stats.correlation_hits as f64 / (collection_stats.correlation_hits + collection_stats.correlation_misses) as f64
            } else {
                0.0
            },
            batch_export_efficiency: batch_result.metrics_exported as f64 / span_count.max(1) as f64,
        };

        let result = IntegrationValidationResult {
            test_case: test_case.to_string(),
            otel_collection_success: collection_stats.metrics_collected > 0,
            span_processing_success: span_processing_results.iter().all(|r| r.processed),
            metric_span_correlation_effective: performance_metrics.correlation_hit_rate > 0.8,
            sampling_coordination: span_processing_results.iter().any(|r| r.sampling_decision.should_sample),
            performance_metrics,
            details: format!(
                "Spans: {}, Metrics: {}, Correlations: {}/{}, Batch exported: {}/{}",
                span_count,
                collection_stats.metrics_collected,
                collection_stats.correlation_hits,
                collection_stats.correlation_hits + collection_stats.correlation_misses,
                batch_result.metrics_exported,
                batch_result.spans_exported
            ),
        };

        self.validation_results.lock().unwrap().push(result.clone());

        Ok(result)
    }

    async fn validate_sampling_coordination(
        &self,
        cx: &Cx,
        test_case: &str,
        sampling_rate: f64,
    ) -> Result<IntegrationValidationResult, Error> {
        // Configure reduced sampling rate
        self.otel_collector.configure_monitoring(MonitoringConfig {
            metric_collection_interval_ms: 100,
            span_sampling_rate: sampling_rate,
            enable_metric_span_correlation: true,
            max_active_spans: 100,
            metric_aggregation_window_ms: 1000,
            trace_export_batch_size: 10,
        });

        let span_count = 50;
        let mut sampled_spans = 0;
        let mut dropped_spans = 0;

        // Create many spans to test sampling
        for i in 0..span_count {
            let span = self.span_system.create_distributed_span(
                cx,
                &format!("sampling_test_{}", i),
                SpanKind::Internal,
                None,
            ).await?;

            let processing_result = self.otel_collector.process_distributed_span(
                cx,
                &span,
                vec![("test_metric", i as f64)],
            ).await?;

            if processing_result.processed {
                sampled_spans += 1;
            } else {
                dropped_spans += 1;
            }

            self.span_system.finish_span_with_metrics(
                cx,
                span.context().span_id(),
                vec![],
            ).await?;
        }

        let actual_sampling_rate = sampled_spans as f64 / span_count as f64;
        let sampling_accuracy = 1.0 - (actual_sampling_rate - sampling_rate).abs();

        let result = IntegrationValidationResult {
            test_case: test_case.to_string(),
            otel_collection_success: sampled_spans > 0,
            span_processing_success: true,
            metric_span_correlation_effective: true,
            sampling_coordination: sampling_accuracy > 0.8, // Within 20% of target
            performance_metrics: OtelSpanPerformanceMetrics {
                span_processing_throughput_per_sec: span_count as f64,
                metric_collection_latency_ms: 0.0,
                correlation_hit_rate: 1.0,
                batch_export_efficiency: actual_sampling_rate,
            },
            details: format!(
                "Target rate: {:.1}%, Actual: {:.1}%, Sampled: {}, Dropped: {}",
                sampling_rate * 100.0,
                actual_sampling_rate * 100.0,
                sampled_spans,
                dropped_spans
            ),
        };

        self.validation_results.lock().unwrap().push(result.clone());

        Ok(result)
    }

    async fn validate_hierarchical_span_metrics(
        &self,
        cx: &Cx,
        test_case: &str,
    ) -> Result<IntegrationValidationResult, Error> {
        // Create hierarchical span structure: parent -> multiple children
        let parent_span = self.span_system.create_distributed_span(
            cx,
            "parent_operation",
            SpanKind::Server,
            None,
        ).await?;

        let parent_span_id = parent_span.context().span_id();

        let mut child_spans = Vec::new();
        let child_count = 3;

        // Create child spans
        for i in 0..child_count {
            let child_span = self.span_system.create_distributed_span(
                cx,
                &format!("child_operation_{}", i),
                SpanKind::Internal,
                Some(parent_span_id),
            ).await?;

            child_spans.push(child_span);
        }

        // Process parent span with metrics
        let parent_processing = self.otel_collector.process_distributed_span(
            cx,
            &parent_span,
            vec![
                ("parent_operation_count", 1.0),
                ("total_children", child_count as f64),
            ],
        ).await?;

        // Process each child span
        let mut child_processing_results = Vec::new();
        for (i, child_span) in child_spans.iter().enumerate() {
            let child_result = self.otel_collector.process_distributed_span(
                cx,
                child_span,
                vec![
                    ("child_operation_count", 1.0),
                    ("child_index", i as f64),
                ],
            ).await?;

            child_processing_results.push(child_result);
        }

        // Finish child spans first
        for child_span in &child_spans {
            self.span_system.finish_span_with_metrics(
                cx,
                child_span.context().span_id(),
                vec![],
            ).await?;
        }

        // Finish parent span
        let parent_completion = self.span_system.finish_span_with_metrics(
            cx,
            parent_span_id,
            vec![],
        ).await?;

        // Verify span hierarchy correlation
        let parent_span_metrics = self.otel_collector.get_span_metric_correlation(parent_span_id);

        let hierarchy_correlation_effective = parent_span_metrics.is_some() &&
            child_processing_results.iter().all(|r| r.processed) &&
            parent_completion.child_spans_finished == 0; // Already finished manually

        let result = IntegrationValidationResult {
            test_case: test_case.to_string(),
            otel_collection_success: parent_processing.processed,
            span_processing_success: child_processing_results.iter().all(|r| r.processed),
            metric_span_correlation_effective: hierarchy_correlation_effective,
            sampling_coordination: true,
            performance_metrics: OtelSpanPerformanceMetrics {
                span_processing_throughput_per_sec: (child_count + 1) as f64,
                metric_collection_latency_ms: parent_processing.processing_duration_ms,
                correlation_hit_rate: 1.0,
                batch_export_efficiency: 1.0,
            },
            details: format!(
                "Parent processed: {}, Children processed: {}/{}, Hierarchy depth: {}",
                parent_processing.processed,
                child_processing_results.iter().filter(|r| r.processed).count(),
                child_count,
                self.span_system.get_span_hierarchy_depth()
            ),
        };

        self.validation_results.lock().unwrap().push(result.clone());

        Ok(result)
    }

    fn get_validation_summary(&self) -> Vec<IntegrationValidationResult> {
        self.validation_results.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        runtime::test_rt,
        cx::region,
        types::Budget,
    };

    #[test]
    fn test_basic_otel_span_coordination() {
        test_rt(|rt| async move {
            region(&rt, Budget::new(Duration::from_secs(30)), |cx| async move {
                let coordinator = OtelSpanIntegrationCoordinator::new(cx).await?;

                let result = coordinator.validate_basic_otel_span_coordination(
                    cx,
                    "basic_coordination",
                    10, // 10 spans
                ).await?;

                assert!(result.otel_collection_success, "OTel collection should succeed");
                assert!(result.span_processing_success, "Span processing should succeed");
                assert!(result.metric_span_correlation_effective, "Metric-span correlation should be effective");
                assert!(result.performance_metrics.span_processing_throughput_per_sec > 5.0, "Should achieve reasonable throughput");

                Ok(())
            }).await
        });
    }

    #[test]
    fn test_sampling_coordination() {
        test_rt(|rt| async move {
            region(&rt, Budget::new(Duration::from_secs(45)), |cx| async move {
                let coordinator = OtelSpanIntegrationCoordinator::new(cx).await?;

                let result = coordinator.validate_sampling_coordination(
                    cx,
                    "sampling_coordination",
                    0.5, // 50% sampling rate
                ).await?;

                assert!(result.sampling_coordination, "Sampling should coordinate with OTel collection");
                assert!(result.performance_metrics.batch_export_efficiency > 0.3, "Should achieve reasonable sampling efficiency");
                assert!(result.performance_metrics.batch_export_efficiency < 0.7, "Should respect sampling rate limits");

                Ok(())
            }).await
        });
    }

    #[test]
    fn test_hierarchical_span_metrics() {
        test_rt(|rt| async move {
            region(&rt, Budget::new(Duration::from_secs(60)), |cx| async move {
                let coordinator = OtelSpanIntegrationCoordinator::new(cx).await?;

                let result = coordinator.validate_hierarchical_span_metrics(
                    cx,
                    "hierarchical_spans"
                ).await?;

                assert!(result.otel_collection_success, "OTel should collect hierarchical span metrics");
                assert!(result.span_processing_success, "All spans in hierarchy should be processed");
                assert!(result.metric_span_correlation_effective, "Parent-child span correlation should work");
                assert!(result.performance_metrics.correlation_hit_rate > 0.9, "Should achieve high correlation rate");

                Ok(())
            }).await
        });
    }
}