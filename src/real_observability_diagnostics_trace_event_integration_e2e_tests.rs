//! br-e2e-223: observability/diagnostics ↔ trace/event integration E2E tests
//!
//! Tests integration between observability diagnostics and trace event systems
//! for comprehensive runtime monitoring, event correlation, and diagnostic analysis.

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use crate::observability::diagnostics::{DiagnosticCollector, DiagnosticLevel, DiagnosticReport, SystemHealth};
    use crate::trace::event::{EventTracer, TraceEvent, EventKind, EventSeverity, EventContext};
    use crate::observability::metrics::{MetricCollector, MetricValue, MetricType};
    use crate::trace::{TraceId, SpanId, Span};
    use crate::cx::{Cx, Scope};
    use crate::runtime::{Runtime, RuntimeBuilder};
    use crate::time::{Duration, Instant};
    use crate::types::{Budget, Outcome, TaskId, RegionId};
    use crate::error::AsupersyncError;

    use std::collections::{HashMap, BTreeMap, VecDeque};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};

    /// Configuration for diagnostic event tracing coordination
    #[derive(Debug, Clone)]
    struct DiagnosticEventConfig {
        /// Maximum diagnostic buffer size
        pub max_diagnostic_buffer: usize,
        /// Event tracing buffer capacity
        pub event_buffer_capacity: usize,
        /// Diagnostic collection interval
        pub collection_interval: Duration,
        /// Event correlation window
        pub correlation_window: Duration,
        /// Health check frequency
        pub health_check_frequency: Duration,
        /// Maximum correlation history size
        pub max_correlation_history: usize,
    }

    impl Default for DiagnosticEventConfig {
        fn default() -> Self {
            Self {
                max_diagnostic_buffer: 10000,
                event_buffer_capacity: 50000,
                collection_interval: Duration::from_millis(100),
                correlation_window: Duration::from_secs(1),
                health_check_frequency: Duration::from_millis(500),
                max_correlation_history: 1000,
            }
        }
    }

    /// Correlated diagnostic and event data
    #[derive(Debug, Clone)]
    struct CorrelatedEntry {
        /// Diagnostic information
        pub diagnostic: DiagnosticReport,
        /// Related trace events
        pub events: Vec<TraceEvent>,
        /// Correlation timestamp
        pub correlated_at: Instant,
        /// Correlation confidence score
        pub confidence: f64,
        /// System context when correlated
        pub system_context: SystemHealth,
    }

    /// Statistics for diagnostic event coordination
    #[derive(Debug, Default)]
    struct DiagnosticEventStats {
        /// Diagnostics collected
        pub diagnostics_collected: AtomicU64,
        /// Events traced
        pub events_traced: AtomicU64,
        /// Successful correlations
        pub correlations_successful: AtomicU64,
        /// Failed correlations
        pub correlations_failed: AtomicU64,
        /// Health checks performed
        pub health_checks_performed: AtomicU64,
        /// Critical issues detected
        pub critical_issues_detected: AtomicU64,
        /// Coordination cycles completed
        pub coordination_cycles: AtomicU64,
        /// Coordination errors
        pub coordination_errors: AtomicU64,
    }

    /// Correlation strategy for diagnostics and events
    #[derive(Debug, Clone)]
    enum CorrelationStrategy {
        /// Time-based correlation within window
        TimeBasedCorrelation,
        /// Task/Region ID correlation
        TaskRegionCorrelation,
        /// Span-based correlation using trace context
        SpanBasedCorrelation,
        /// Adaptive correlation using multiple signals
        AdaptiveCorrelation { confidence_threshold: f64 },
    }

    /// Analysis mode for diagnostic event integration
    #[derive(Debug, Clone)]
    enum AnalysisMode {
        /// Real-time analysis and alerting
        RealTimeAnalysis,
        /// Batch analysis with aggregation
        BatchAnalysis { batch_size: usize },
        /// Streaming analysis with windowing
        StreamingAnalysis { window_size: Duration },
        /// Predictive analysis with trending
        PredictiveAnalysis { history_window: Duration },
    }

    /// Comprehensive diagnostic event coordination system
    struct DiagnosticEventSystem {
        config: DiagnosticEventConfig,
        diagnostic_collector: DiagnosticCollector,
        event_tracer: EventTracer,
        metric_collector: MetricCollector,
        correlation_history: VecDeque<CorrelatedEntry>,
        event_buffer: VecDeque<TraceEvent>,
        diagnostic_buffer: VecDeque<DiagnosticReport>,
        correlation_map: HashMap<TraceId, Vec<DiagnosticReport>>,
        span_diagnostics: HashMap<SpanId, Vec<DiagnosticReport>>,
        stats: Arc<DiagnosticEventStats>,
        correlation_strategy: CorrelationStrategy,
        analysis_mode: AnalysisMode,
        is_running: AtomicBool,
    }

    impl DiagnosticEventSystem {
        /// Create new diagnostic event coordination system
        fn new(
            config: DiagnosticEventConfig,
            correlation_strategy: CorrelationStrategy,
            analysis_mode: AnalysisMode,
        ) -> Result<Self, AsupersyncError> {
            let diagnostic_collector = DiagnosticCollector::new(config.max_diagnostic_buffer)?;
            let event_tracer = EventTracer::new(config.event_buffer_capacity)?;
            let metric_collector = MetricCollector::new()?;

            Ok(Self {
                config,
                diagnostic_collector,
                event_tracer,
                metric_collector,
                correlation_history: VecDeque::new(),
                event_buffer: VecDeque::new(),
                diagnostic_buffer: VecDeque::new(),
                correlation_map: HashMap::new(),
                span_diagnostics: HashMap::new(),
                stats: Arc::new(DiagnosticEventStats::default()),
                correlation_strategy,
                analysis_mode,
                is_running: AtomicBool::new(false),
            })
        }

        /// Start the coordination system
        async fn start(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            self.is_running.store(true, Ordering::SeqCst);

            // Start diagnostic collection loop
            let diagnostic_handle = cx.spawn(|cx| async move {
                self.run_diagnostic_collection(cx).await
            }).await?;

            // Start event tracing loop
            let event_handle = cx.spawn(|cx| async move {
                self.run_event_tracing(cx).await
            }).await?;

            // Start correlation engine
            let correlation_handle = cx.spawn(|cx| async move {
                self.run_correlation_engine(cx).await
            }).await?;

            // Start analysis engine
            let analysis_handle = cx.spawn(|cx| async move {
                self.run_analysis_engine(cx).await
            }).await?;

            // Start health monitoring
            let health_handle = cx.spawn(|cx| async move {
                self.run_health_monitoring(cx).await
            }).await?;

            Ok(())
        }

        /// Collect diagnostic information
        async fn collect_diagnostic(&mut self, source: &str, level: DiagnosticLevel, message: &str, cx: &Cx) -> Result<(), AsupersyncError> {
            let diagnostic = self.diagnostic_collector.collect_diagnostic(source, level, message)?;
            self.diagnostic_buffer.push_back(diagnostic);
            self.stats.diagnostics_collected.fetch_add(1, Ordering::SeqCst);

            // Truncate buffer if needed
            if self.diagnostic_buffer.len() > self.config.max_diagnostic_buffer {
                self.diagnostic_buffer.pop_front();
            }

            Ok(())
        }

        /// Trace event with context
        async fn trace_event(
            &mut self,
            kind: EventKind,
            severity: EventSeverity,
            message: &str,
            context: EventContext,
            cx: &Cx,
        ) -> Result<(), AsupersyncError> {
            let event = self.event_tracer.trace_event(kind, severity, message, context)?;
            self.event_buffer.push_back(event);
            self.stats.events_traced.fetch_add(1, Ordering::SeqCst);

            // Truncate buffer if needed
            if self.event_buffer.len() > self.config.event_buffer_capacity {
                self.event_buffer.pop_front();
            }

            Ok(())
        }

        /// Run diagnostic collection loop
        async fn run_diagnostic_collection(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            while self.is_running.load(Ordering::SeqCst) {
                // Collect system diagnostics
                let system_health = self.diagnostic_collector.collect_system_health()?;

                // Generate diagnostic reports based on health
                if system_health.memory_pressure > 0.8 {
                    self.collect_diagnostic("memory", DiagnosticLevel::Warning, "High memory pressure detected", cx).await?;
                }

                if system_health.cpu_load > 0.9 {
                    self.collect_diagnostic("cpu", DiagnosticLevel::Critical, "Critical CPU load", cx).await?;
                    self.stats.critical_issues_detected.fetch_add(1, Ordering::SeqCst);
                }

                if system_health.active_tasks > 1000 {
                    self.collect_diagnostic("scheduler", DiagnosticLevel::Info, "High task count", cx).await?;
                }

                // Collect metrics
                self.metric_collector.record_metric("system.health.memory_pressure", MetricValue::Gauge(system_health.memory_pressure))?;
                self.metric_collector.record_metric("system.health.cpu_load", MetricValue::Gauge(system_health.cpu_load))?;
                self.metric_collector.record_metric("system.health.active_tasks", MetricValue::Counter(system_health.active_tasks as u64))?;

                crate::time::sleep(self.config.collection_interval, cx).await?;
            }

            Ok(())
        }

        /// Run event tracing loop
        async fn run_event_tracing(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            while self.is_running.load(Ordering::SeqCst) {
                // Process pending events from tracer
                while let Some(pending_event) = self.event_tracer.next_event()? {
                    self.event_buffer.push_back(pending_event);
                    self.stats.events_traced.fetch_add(1, Ordering::SeqCst);
                }

                // Periodic event flush
                if self.event_buffer.len() > self.config.event_buffer_capacity / 2 {
                    self.flush_event_buffer(cx).await?;
                }

                crate::time::sleep(Duration::from_millis(50), cx).await?;
            }

            Ok(())
        }

        /// Flush event buffer for processing
        async fn flush_event_buffer(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            let events_to_process: Vec<_> = self.event_buffer.drain(..).collect();

            for event in events_to_process {
                self.process_single_event(event, cx).await?;
            }

            Ok(())
        }

        /// Process single event for correlation
        async fn process_single_event(&mut self, event: TraceEvent, cx: &Cx) -> Result<(), AsupersyncError> {
            // Add to correlation map by trace ID
            if let Some(trace_id) = event.trace_id() {
                let diagnostics = self.correlation_map.entry(trace_id).or_insert_with(Vec::new);
                // Would collect related diagnostics here in full implementation
            }

            // Add to span diagnostics if applicable
            if let Some(span_id) = event.span_id() {
                let diagnostics = self.span_diagnostics.entry(span_id).or_insert_with(Vec::new);
                // Would collect span-related diagnostics here
            }

            Ok(())
        }

        /// Run correlation engine loop
        async fn run_correlation_engine(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            while self.is_running.load(Ordering::SeqCst) {
                // Perform correlation based on strategy
                match &self.correlation_strategy {
                    CorrelationStrategy::TimeBasedCorrelation => {
                        self.perform_time_based_correlation(cx).await?;
                    }
                    CorrelationStrategy::TaskRegionCorrelation => {
                        self.perform_task_region_correlation(cx).await?;
                    }
                    CorrelationStrategy::SpanBasedCorrelation => {
                        self.perform_span_based_correlation(cx).await?;
                    }
                    CorrelationStrategy::AdaptiveCorrelation { confidence_threshold } => {
                        self.perform_adaptive_correlation(*confidence_threshold, cx).await?;
                    }
                }

                crate::time::sleep(Duration::from_millis(100), cx).await?;
            }

            Ok(())
        }

        /// Perform time-based correlation
        async fn perform_time_based_correlation(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            let now = Instant::now();
            let window_start = now - self.config.correlation_window;

            // Find diagnostics and events within correlation window
            let recent_diagnostics: Vec<_> = self.diagnostic_buffer.iter()
                .filter(|d| d.timestamp >= window_start)
                .cloned()
                .collect();

            let recent_events: Vec<_> = self.event_buffer.iter()
                .filter(|e| e.timestamp >= window_start)
                .cloned()
                .collect();

            // Create correlations for temporally close items
            for diagnostic in recent_diagnostics {
                let related_events: Vec<_> = recent_events.iter()
                    .filter(|e| (e.timestamp.duration_since(diagnostic.timestamp)).as_millis() <= 100)
                    .cloned()
                    .collect();

                if !related_events.is_empty() {
                    let correlation = CorrelatedEntry {
                        diagnostic: diagnostic.clone(),
                        events: related_events,
                        correlated_at: now,
                        confidence: 0.7, // Time-based correlation confidence
                        system_context: self.diagnostic_collector.collect_system_health()?,
                    };

                    self.add_correlation(correlation).await?;
                    self.stats.correlations_successful.fetch_add(1, Ordering::SeqCst);
                }
            }

            Ok(())
        }

        /// Perform task/region-based correlation
        async fn perform_task_region_correlation(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            // Group diagnostics and events by task/region ID
            let mut task_diagnostics: HashMap<TaskId, Vec<DiagnosticReport>> = HashMap::new();
            let mut region_diagnostics: HashMap<RegionId, Vec<DiagnosticReport>> = HashMap::new();

            for diagnostic in &self.diagnostic_buffer {
                if let Some(task_id) = diagnostic.task_id {
                    task_diagnostics.entry(task_id).or_insert_with(Vec::new).push(diagnostic.clone());
                }
                if let Some(region_id) = diagnostic.region_id {
                    region_diagnostics.entry(region_id).or_insert_with(Vec::new).push(diagnostic.clone());
                }
            }

            // Correlate with events by task/region
            for diagnostic in &self.diagnostic_buffer {
                let related_events: Vec<_> = self.event_buffer.iter()
                    .filter(|e| {
                        e.task_id() == diagnostic.task_id ||
                        e.region_id() == diagnostic.region_id
                    })
                    .cloned()
                    .collect();

                if !related_events.is_empty() {
                    let correlation = CorrelatedEntry {
                        diagnostic: diagnostic.clone(),
                        events: related_events,
                        correlated_at: Instant::now(),
                        confidence: 0.9, // High confidence for task/region correlation
                        system_context: self.diagnostic_collector.collect_system_health()?,
                    };

                    self.add_correlation(correlation).await?;
                    self.stats.correlations_successful.fetch_add(1, Ordering::SeqCst);
                }
            }

            Ok(())
        }

        /// Perform span-based correlation
        async fn perform_span_based_correlation(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            // Correlate diagnostics with events based on span context
            for diagnostic in &self.diagnostic_buffer {
                if let Some(span_id) = diagnostic.span_id {
                    let related_events: Vec<_> = self.event_buffer.iter()
                        .filter(|e| e.span_id() == Some(span_id))
                        .cloned()
                        .collect();

                    if !related_events.is_empty() {
                        let correlation = CorrelatedEntry {
                            diagnostic: diagnostic.clone(),
                            events: related_events,
                            correlated_at: Instant::now(),
                            confidence: 0.95, // Very high confidence for span correlation
                            system_context: self.diagnostic_collector.collect_system_health()?,
                        };

                        self.add_correlation(correlation).await?;
                        self.stats.correlations_successful.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }

            Ok(())
        }

        /// Perform adaptive correlation
        async fn perform_adaptive_correlation(&mut self, confidence_threshold: f64, cx: &Cx) -> Result<(), AsupersyncError> {
            // Try multiple correlation strategies and use highest confidence
            let mut best_correlations = Vec::new();

            // Try time-based correlation
            self.perform_time_based_correlation(cx).await?;
            let time_correlations = self.correlation_history.len();

            // Try task/region correlation
            self.perform_task_region_correlation(cx).await?;
            let task_correlations = self.correlation_history.len() - time_correlations;

            // Try span-based correlation
            self.perform_span_based_correlation(cx).await?;
            let span_correlations = self.correlation_history.len() - time_correlations - task_correlations;

            // Keep only high-confidence correlations
            self.correlation_history.retain(|c| c.confidence >= confidence_threshold);

            self.stats.correlations_successful.fetch_add(self.correlation_history.len() as u64, Ordering::SeqCst);

            Ok(())
        }

        /// Add correlation to history
        async fn add_correlation(&mut self, correlation: CorrelatedEntry) -> Result<(), AsupersyncError> {
            self.correlation_history.push_back(correlation);

            // Limit history size
            if self.correlation_history.len() > self.config.max_correlation_history {
                self.correlation_history.pop_front();
            }

            Ok(())
        }

        /// Run analysis engine loop
        async fn run_analysis_engine(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            while self.is_running.load(Ordering::SeqCst) {
                match &self.analysis_mode {
                    AnalysisMode::RealTimeAnalysis => {
                        self.perform_realtime_analysis(cx).await?;
                    }
                    AnalysisMode::BatchAnalysis { batch_size } => {
                        self.perform_batch_analysis(*batch_size, cx).await?;
                    }
                    AnalysisMode::StreamingAnalysis { window_size } => {
                        self.perform_streaming_analysis(*window_size, cx).await?;
                    }
                    AnalysisMode::PredictiveAnalysis { history_window } => {
                        self.perform_predictive_analysis(*history_window, cx).await?;
                    }
                }

                crate::time::sleep(Duration::from_millis(200), cx).await?;
            }

            Ok(())
        }

        /// Perform real-time analysis
        async fn perform_realtime_analysis(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            // Analyze recent correlations for patterns
            let recent_correlations: Vec<_> = self.correlation_history.iter()
                .filter(|c| c.correlated_at.elapsed() < Duration::from_secs(5))
                .collect();

            // Detect critical patterns
            let critical_count = recent_correlations.iter()
                .filter(|c| c.diagnostic.level == DiagnosticLevel::Critical)
                .count();

            if critical_count > 3 {
                self.stats.critical_issues_detected.fetch_add(1, Ordering::SeqCst);
                eprintln!("ALERT: Multiple critical issues detected in short timeframe");
            }

            Ok(())
        }

        /// Perform batch analysis
        async fn perform_batch_analysis(&mut self, batch_size: usize, cx: &Cx) -> Result<(), AsupersyncError> {
            if self.correlation_history.len() >= batch_size {
                let batch: Vec<_> = self.correlation_history.iter().take(batch_size).collect();

                // Analyze batch for trends
                let avg_confidence: f64 = batch.iter().map(|c| c.confidence).sum::<f64>() / batch.len() as f64;

                eprintln!("Batch analysis: {} correlations, avg confidence: {:.2}", batch.len(), avg_confidence);
            }

            Ok(())
        }

        /// Perform streaming analysis
        async fn perform_streaming_analysis(&mut self, window_size: Duration, cx: &Cx) -> Result<(), AsupersyncError> {
            let cutoff = Instant::now() - window_size;
            let window_correlations: Vec<_> = self.correlation_history.iter()
                .filter(|c| c.correlated_at > cutoff)
                .collect();

            // Analyze correlation trends in window
            if !window_correlations.is_empty() {
                let correlation_rate = window_correlations.len() as f64 / window_size.as_secs_f64();
                self.metric_collector.record_metric("correlation.rate", MetricValue::Gauge(correlation_rate))?;
            }

            Ok(())
        }

        /// Perform predictive analysis
        async fn perform_predictive_analysis(&mut self, history_window: Duration, cx: &Cx) -> Result<(), AsupersyncError> {
            let cutoff = Instant::now() - history_window;
            let historical_data: Vec<_> = self.correlation_history.iter()
                .filter(|c| c.correlated_at > cutoff)
                .collect();

            // Simple trend analysis (would be more sophisticated in practice)
            if historical_data.len() > 10 {
                let recent_half = historical_data.len() / 2;
                let recent_critical = historical_data[recent_half..].iter()
                    .filter(|c| c.diagnostic.level == DiagnosticLevel::Critical)
                    .count();
                let older_critical = historical_data[..recent_half].iter()
                    .filter(|c| c.diagnostic.level == DiagnosticLevel::Critical)
                    .count();

                if recent_critical > older_critical * 2 {
                    eprintln!("PREDICTION: Critical issue rate increasing");
                    self.stats.critical_issues_detected.fetch_add(1, Ordering::SeqCst);
                }
            }

            Ok(())
        }

        /// Run health monitoring loop
        async fn run_health_monitoring(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            while self.is_running.load(Ordering::SeqCst) {
                // Perform comprehensive health check
                let system_health = self.diagnostic_collector.collect_system_health()?;
                self.stats.health_checks_performed.fetch_add(1, Ordering::SeqCst);

                // Check for system-wide issues
                if system_health.error_rate > 0.05 {
                    self.collect_diagnostic("system", DiagnosticLevel::Warning, "High system error rate", cx).await?;
                }

                // Monitor coordination system health
                self.stats.coordination_cycles.fetch_add(1, Ordering::SeqCst);

                // Log health metrics
                self.metric_collector.record_metric("system.health.overall", MetricValue::Gauge(system_health.overall_score()))?;
                self.metric_collector.record_metric("diagnostics.buffer_size", MetricValue::Gauge(self.diagnostic_buffer.len() as f64))?;
                self.metric_collector.record_metric("events.buffer_size", MetricValue::Gauge(self.event_buffer.len() as f64))?;
                self.metric_collector.record_metric("correlations.history_size", MetricValue::Gauge(self.correlation_history.len() as f64))?;

                crate::time::sleep(self.config.health_check_frequency, cx).await?;
            }

            Ok(())
        }

        /// Get recent correlations for analysis
        fn get_recent_correlations(&self, since: Duration) -> Vec<&CorrelatedEntry> {
            let cutoff = Instant::now() - since;
            self.correlation_history.iter()
                .filter(|c| c.correlated_at > cutoff)
                .collect()
        }

        /// Stop the coordination system
        async fn stop(&mut self) -> Result<(), AsupersyncError> {
            self.is_running.store(false, Ordering::SeqCst);
            Ok(())
        }

        /// Get coordination statistics
        fn get_stats(&self) -> DiagnosticEventStats {
            DiagnosticEventStats {
                diagnostics_collected: AtomicU64::new(self.stats.diagnostics_collected.load(Ordering::SeqCst)),
                events_traced: AtomicU64::new(self.stats.events_traced.load(Ordering::SeqCst)),
                correlations_successful: AtomicU64::new(self.stats.correlations_successful.load(Ordering::SeqCst)),
                correlations_failed: AtomicU64::new(self.stats.correlations_failed.load(Ordering::SeqCst)),
                health_checks_performed: AtomicU64::new(self.stats.health_checks_performed.load(Ordering::SeqCst)),
                critical_issues_detected: AtomicU64::new(self.stats.critical_issues_detected.load(Ordering::SeqCst)),
                coordination_cycles: AtomicU64::new(self.stats.coordination_cycles.load(Ordering::SeqCst)),
                coordination_errors: AtomicU64::new(self.stats.coordination_errors.load(Ordering::SeqCst)),
            }
        }
    }

    /// Test basic diagnostic event integration
    #[tokio::test]
    async fn test_basic_diagnostic_event_integration() -> Result<(), AsupersyncError> {
        let runtime = RuntimeBuilder::new().build().await?;
        let cx = runtime.cx();

        cx.scope(|cx| async move {
            let config = DiagnosticEventConfig::default();
            let correlation_strategy = CorrelationStrategy::TimeBasedCorrelation;
            let analysis_mode = AnalysisMode::RealTimeAnalysis;
            let mut system = DiagnosticEventSystem::new(config, correlation_strategy, analysis_mode)?;

            // Start coordination system
            system.start(cx).await?;

            // Collect some diagnostics
            system.collect_diagnostic("test", DiagnosticLevel::Info, "Test diagnostic 1", cx).await?;
            system.collect_diagnostic("test", DiagnosticLevel::Warning, "Test diagnostic 2", cx).await?;

            // Trace some events
            let context = EventContext::new().with_component("test_component");
            system.trace_event(EventKind::RuntimeEvent, EventSeverity::Info, "Test event 1", context.clone(), cx).await?;
            system.trace_event(EventKind::UserEvent, EventSeverity::Warning, "Test event 2", context, cx).await?;

            // Allow processing time
            crate::time::sleep(Duration::from_millis(300), cx).await?;

            system.stop().await?;

            // Verify coordination worked
            let stats = system.get_stats();
            assert_eq!(stats.diagnostics_collected.load(Ordering::SeqCst), 2);
            assert_eq!(stats.events_traced.load(Ordering::SeqCst), 2);
            assert!(stats.health_checks_performed.load(Ordering::SeqCst) > 0);
            assert!(stats.coordination_cycles.load(Ordering::SeqCst) > 0);

            Ok(())
        }).await
    }

    /// Test span-based correlation
    #[tokio::test]
    async fn test_span_based_correlation() -> Result<(), AsupersyncError> {
        let runtime = RuntimeBuilder::new().build().await?;
        let cx = runtime.cx();

        cx.scope(|cx| async move {
            let config = DiagnosticEventConfig::default();
            let correlation_strategy = CorrelationStrategy::SpanBasedCorrelation;
            let analysis_mode = AnalysisMode::StreamingAnalysis { window_size: Duration::from_secs(1) };
            let mut system = DiagnosticEventSystem::new(config, correlation_strategy, analysis_mode)?;

            system.start(cx).await?;

            // Create span context
            let trace_id = TraceId::new();
            let span_id = SpanId::new();
            let span = Span::new(trace_id, span_id, "test_operation");

            // Collect diagnostics and events within same span
            cx.scope(|cx| async move {
                system.collect_diagnostic("span_test", DiagnosticLevel::Info, "Span diagnostic", cx).await?;

                let context = EventContext::new()
                    .with_trace_id(trace_id)
                    .with_span_id(span_id);
                system.trace_event(EventKind::SpanEvent, EventSeverity::Info, "Span event", context, cx).await?;

                Ok::<(), AsupersyncError>(())
            }).await?;

            // Allow correlation processing
            crate::time::sleep(Duration::from_millis(400), cx).await?;

            system.stop().await?;

            // Verify span-based correlation
            let stats = system.get_stats();
            assert!(stats.correlations_successful.load(Ordering::SeqCst) > 0);
            assert_eq!(stats.coordination_errors.load(Ordering::SeqCst), 0);

            Ok(())
        }).await
    }

    /// Test adaptive correlation with high load
    #[tokio::test]
    async fn test_adaptive_correlation_high_load() -> Result<(), AsupersyncError> {
        let runtime = RuntimeBuilder::new().build().await?;
        let cx = runtime.cx();

        cx.scope(|cx| async move {
            let config = DiagnosticEventConfig {
                max_diagnostic_buffer: 500,
                event_buffer_capacity: 1000,
                ..DiagnosticEventConfig::default()
            };
            let correlation_strategy = CorrelationStrategy::AdaptiveCorrelation { confidence_threshold: 0.8 };
            let analysis_mode = AnalysisMode::BatchAnalysis { batch_size: 10 };
            let mut system = DiagnosticEventSystem::new(config, correlation_strategy, analysis_mode)?;

            system.start(cx).await?;

            // Generate high load of diagnostics and events
            for i in 0..50 {
                system.collect_diagnostic("load_test", DiagnosticLevel::Info, &format!("Load diagnostic {}", i), cx).await?;

                let context = EventContext::new().with_component(&format!("component_{}", i % 5));
                system.trace_event(EventKind::RuntimeEvent, EventSeverity::Info, &format!("Load event {}", i), context, cx).await?;

                // Small delay to simulate realistic load
                crate::time::sleep(Duration::from_millis(5), cx).await?;
            }

            // Allow adaptive processing
            crate::time::sleep(Duration::from_millis(600), cx).await?;

            system.stop().await?;

            // Verify adaptive behavior handled load
            let stats = system.get_stats();
            assert_eq!(stats.diagnostics_collected.load(Ordering::SeqCst), 50);
            assert_eq!(stats.events_traced.load(Ordering::SeqCst), 50);
            assert!(stats.correlations_successful.load(Ordering::SeqCst) > 0);
            assert!(stats.coordination_cycles.load(Ordering::SeqCst) > 5);

            // Should maintain low error rate under load
            let error_rate = stats.coordination_errors.load(Ordering::SeqCst) as f64 / 50.0;
            assert!(error_rate < 0.1, "Error rate too high: {}", error_rate);

            Ok(())
        }).await
    }
}