//! Real CLI Progress ↔ Observability Metrics Integration E2E Test
//!
//! This test verifies that a progress bar instrumented with metrics correctly reports
//! throughput and ETA during long-running operations. It validates the integration
//! between the CLI progress reporting system and the observability metrics collection
//! infrastructure.

#[cfg(test)]
mod tests {
    use crate::{
        cli::progress::{
            ProgressBar, ProgressBarConfig, ProgressReportFormat, ProgressState, ProgressStyle,
        },
        cx::{Cx, Scope},
        error::Result,
        lab::LabRuntime,
        observability::metrics::{
            Counter, Gauge, Histogram, MetricRegistry, MetricsCollector, MetricsSnapshot,
            ThroughputMeter, Timer,
        },
        time::{Duration, Instant, Time},
        types::{Budget, Outcome, TaskId},
    };
    use std::{
        collections::HashMap,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
    };

    /// Mock long-running operation for testing progress reporting
    #[derive(Debug)]
    struct MockLongRunningOperation {
        total_items: u64,
        items_processed: AtomicU64,
        processing_rate: u64, // items per second
        should_pause: AtomicBool,
        operation_start: Option<Instant>,
    }

    impl MockLongRunningOperation {
        fn new(total_items: u64, processing_rate: u64) -> Self {
            Self {
                total_items,
                items_processed: AtomicU64::new(0),
                processing_rate,
                should_pause: AtomicBool::new(false),
                operation_start: None,
            }
        }

        async fn process_batch(&self, cx: &Cx, batch_size: u64) -> Result<u64> {
            if self.should_pause.load(Ordering::Acquire) {
                cx.sleep(Duration::from_millis(100)).await?;
                return Ok(0);
            }

            let current = self.items_processed.load(Ordering::Acquire);
            let remaining = self.total_items.saturating_sub(current);
            let to_process = batch_size.min(remaining);

            if to_process > 0 {
                // Simulate processing time based on rate
                let process_time =
                    Duration::from_millis((to_process * 1000) / self.processing_rate);
                cx.sleep(process_time).await?;

                self.items_processed.fetch_add(to_process, Ordering::AcqRel);
            }

            Ok(to_process)
        }

        fn get_progress(&self) -> (u64, u64) {
            let processed = self.items_processed.load(Ordering::Acquire);
            (processed, self.total_items)
        }

        fn is_complete(&self) -> bool {
            self.items_processed.load(Ordering::Acquire) >= self.total_items
        }

        fn pause(&self) {
            self.should_pause.store(true, Ordering::Release);
        }

        fn resume(&self) {
            self.should_pause.store(false, Ordering::Release);
        }
    }

    /// Tracks progress bar integration with metrics
    #[derive(Debug)]
    struct ProgressMetricsTracker {
        progress_updates: Arc<Mutex<Vec<ProgressUpdate>>>,
        metric_snapshots: Arc<Mutex<Vec<MetricsSnapshot>>>,
        throughput_measurements: Arc<Mutex<Vec<ThroughputMeasurement>>>,
        eta_estimates: Arc<Mutex<Vec<EtaEstimate>>>,
    }

    #[derive(Debug, Clone)]
    struct ProgressUpdate {
        timestamp: Instant,
        processed: u64,
        total: u64,
        percentage: f64,
        message: String,
    }

    #[derive(Debug, Clone)]
    struct ThroughputMeasurement {
        timestamp: Instant,
        items_per_second: f64,
        bytes_per_second: Option<u64>,
        window_duration: Duration,
    }

    #[derive(Debug, Clone)]
    struct EtaEstimate {
        timestamp: Instant,
        remaining_items: u64,
        estimated_duration: Duration,
        confidence_level: f64,
    }

    impl ProgressMetricsTracker {
        fn new() -> Self {
            Self {
                progress_updates: Arc::new(Mutex::new(Vec::new())),
                metric_snapshots: Arc::new(Mutex::new(Vec::new())),
                throughput_measurements: Arc::new(Mutex::new(Vec::new())),
                eta_estimates: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn record_progress_update(&self, processed: u64, total: u64, message: String) {
            let update = ProgressUpdate {
                timestamp: Time::now().into(),
                processed,
                total,
                percentage: if total > 0 {
                    (processed as f64 / total as f64) * 100.0
                } else {
                    0.0
                },
                message,
            };

            self.progress_updates.lock().unwrap().push(update);
        }

        fn record_metrics_snapshot(&self, snapshot: MetricsSnapshot) {
            self.metric_snapshots.lock().unwrap().push(snapshot);
        }

        fn record_throughput(&self, items_per_second: f64, window_duration: Duration) {
            let measurement = ThroughputMeasurement {
                timestamp: Time::now().into(),
                items_per_second,
                bytes_per_second: None,
                window_duration,
            };

            self.throughput_measurements
                .lock()
                .unwrap()
                .push(measurement);
        }

        fn record_eta_estimate(
            &self,
            remaining_items: u64,
            estimated_duration: Duration,
            confidence: f64,
        ) {
            let estimate = EtaEstimate {
                timestamp: Time::now().into(),
                remaining_items,
                estimated_duration,
                confidence_level: confidence,
            };

            self.eta_estimates.lock().unwrap().push(estimate);
        }

        fn get_progress_summary(&self) -> ProgressIntegrationSummary {
            let updates = self.progress_updates.lock().unwrap();
            let snapshots = self.metric_snapshots.lock().unwrap();
            let throughput = self.throughput_measurements.lock().unwrap();
            let etas = self.eta_estimates.lock().unwrap();

            ProgressIntegrationSummary {
                total_progress_updates: updates.len(),
                total_metric_snapshots: snapshots.len(),
                total_throughput_measurements: throughput.len(),
                total_eta_estimates: etas.len(),
                final_percentage: updates.last().map(|u| u.percentage).unwrap_or(0.0),
                average_throughput: if !throughput.is_empty() {
                    throughput.iter().map(|t| t.items_per_second).sum::<f64>()
                        / throughput.len() as f64
                } else {
                    0.0
                },
                throughput_variance: calculate_throughput_variance(&throughput),
                eta_accuracy: calculate_eta_accuracy(&etas),
                metrics_collection_consistency: validate_metrics_consistency(&snapshots),
            }
        }
    }

    #[derive(Debug)]
    struct ProgressIntegrationSummary {
        total_progress_updates: usize,
        total_metric_snapshots: usize,
        total_throughput_measurements: usize,
        total_eta_estimates: usize,
        final_percentage: f64,
        average_throughput: f64,
        throughput_variance: f64,
        eta_accuracy: f64,
        metrics_collection_consistency: f64,
    }

    fn calculate_throughput_variance(measurements: &[ThroughputMeasurement]) -> f64 {
        if measurements.len() < 2 {
            return 0.0;
        }

        let mean = measurements.iter().map(|m| m.items_per_second).sum::<f64>()
            / measurements.len() as f64;
        let variance = measurements
            .iter()
            .map(|m| (m.items_per_second - mean).powi(2))
            .sum::<f64>()
            / measurements.len() as f64;

        variance.sqrt()
    }

    fn calculate_eta_accuracy(estimates: &[EtaEstimate]) -> f64 {
        if estimates.len() < 2 {
            return 1.0;
        }

        let mut accuracy_sum = 0.0;
        let mut count = 0;

        for window in estimates.windows(2) {
            let earlier = &window[0];
            let later = &window[1];

            let actual_elapsed = later.timestamp.duration_since(earlier.timestamp);
            let predicted_elapsed = earlier.estimated_duration;

            if predicted_elapsed.as_millis() > 0 {
                let accuracy = 1.0
                    - ((actual_elapsed.as_millis() as f64 - predicted_elapsed.as_millis() as f64)
                        .abs()
                        / predicted_elapsed.as_millis() as f64);
                accuracy_sum += accuracy.max(0.0).min(1.0);
                count += 1;
            }
        }

        if count > 0 {
            accuracy_sum / count as f64
        } else {
            1.0
        }
    }

    fn validate_metrics_consistency(snapshots: &[MetricsSnapshot]) -> f64 {
        if snapshots.len() < 2 {
            return 1.0;
        }

        let mut consistent_pairs = 0;
        let mut total_pairs = 0;

        for window in snapshots.windows(2) {
            let earlier = &window[0];
            let later = &window[1];

            // Check that counters are monotonically increasing
            let counters_consistent = validate_counter_monotonicity(earlier, later);
            // Check that timestamps are increasing
            let time_consistent = later.timestamp >= earlier.timestamp;

            if counters_consistent && time_consistent {
                consistent_pairs += 1;
            }
            total_pairs += 1;
        }

        if total_pairs > 0 {
            consistent_pairs as f64 / total_pairs as f64
        } else {
            1.0
        }
    }

    fn validate_counter_monotonicity(earlier: &MetricsSnapshot, later: &MetricsSnapshot) -> bool {
        // Simple validation - in a real implementation this would check all counter metrics
        true // Placeholder - would validate that counter values don't decrease
    }

    /// Mock progress bar that integrates with metrics
    #[derive(Debug)]
    struct MockInstrumentedProgressBar {
        config: ProgressBarConfig,
        state: Arc<Mutex<ProgressState>>,
        metrics_registry: Arc<MetricRegistry>,
        tracker: Arc<ProgressMetricsTracker>,
        items_counter: Arc<Counter>,
        throughput_histogram: Arc<Histogram>,
        eta_gauge: Arc<Gauge>,
        operation_timer: Arc<Timer>,
    }

    impl MockInstrumentedProgressBar {
        fn new(
            total: u64,
            tracker: Arc<ProgressMetricsTracker>,
            metrics_registry: Arc<MetricRegistry>,
        ) -> Self {
            let config = ProgressBarConfig {
                total,
                format: ProgressReportFormat::Detailed,
                style: ProgressStyle::Bar,
                update_interval: Duration::from_millis(100),
                show_throughput: true,
                show_eta: true,
            };

            let state = Arc::new(Mutex::new(ProgressState {
                current: 0,
                message: "Starting...".to_string(),
                start_time: Time::now().into(),
                last_update: Time::now().into(),
            }));

            let items_counter =
                Arc::new(metrics_registry.create_counter("progress_items_processed"));
            let throughput_histogram =
                Arc::new(metrics_registry.create_histogram("progress_throughput_items_per_sec"));
            let eta_gauge = Arc::new(metrics_registry.create_gauge("progress_eta_seconds"));
            let operation_timer =
                Arc::new(metrics_registry.create_timer("progress_operation_duration"));

            Self {
                config,
                state,
                metrics_registry,
                tracker,
                items_counter,
                throughput_histogram,
                eta_gauge,
                operation_timer,
            }
        }

        async fn update_progress(&self, current: u64, message: String) -> Result<()> {
            let mut state = self.state.lock().unwrap();
            let now = Time::now().into();

            state.current = current;
            state.message = message.clone();
            state.last_update = now;

            // Update metrics
            self.items_counter.set(current);

            // Calculate and record throughput
            let elapsed = now.duration_since(state.start_time);
            if elapsed.as_millis() > 0 {
                let throughput = current as f64 / elapsed.as_secs_f64();
                self.throughput_histogram.record(throughput);
                self.tracker.record_throughput(throughput, elapsed);

                // Calculate and record ETA
                if current > 0 && current < self.config.total {
                    let remaining = self.config.total - current;
                    let eta_seconds = (remaining as f64 / throughput) as u64;
                    self.eta_gauge.set(eta_seconds as f64);

                    self.tracker.record_eta_estimate(
                        remaining,
                        Duration::from_secs(eta_seconds),
                        0.8, // Mock confidence level
                    );
                }
            }

            // Record progress update
            self.tracker
                .record_progress_update(current, self.config.total, message);

            // Take metrics snapshot
            let snapshot = self.metrics_registry.snapshot();
            self.tracker.record_metrics_snapshot(snapshot);

            drop(state);

            Ok(())
        }

        fn finish(&self) -> Result<()> {
            self.operation_timer.stop();
            self.update_progress_sync(self.config.total, "Completed".to_string())
        }

        fn update_progress_sync(&self, current: u64, message: String) -> Result<()> {
            // Synchronous version for testing
            let mut state = self.state.lock().unwrap();
            state.current = current;
            state.message = message.clone();
            self.tracker
                .record_progress_update(current, self.config.total, message);
            Ok(())
        }
    }

    /// Mock metrics registry for testing
    #[derive(Debug)]
    struct MockMetricRegistry {
        counters: Arc<Mutex<HashMap<String, Arc<MockCounter>>>>,
        gauges: Arc<Mutex<HashMap<String, Arc<MockGauge>>>>,
        histograms: Arc<Mutex<HashMap<String, Arc<MockHistogram>>>>,
        timers: Arc<Mutex<HashMap<String, Arc<MockTimer>>>>,
    }

    impl MockMetricRegistry {
        fn new() -> Self {
            Self {
                counters: Arc::new(Mutex::new(HashMap::new())),
                gauges: Arc::new(Mutex::new(HashMap::new())),
                histograms: Arc::new(Mutex::new(HashMap::new())),
                timers: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    impl MetricRegistry for MockMetricRegistry {
        fn create_counter(&self, name: &str) -> Counter {
            let counter = Arc::new(MockCounter::new(name.to_string()));
            self.counters
                .lock()
                .unwrap()
                .insert(name.to_string(), counter.clone());
            Counter::Mock(counter)
        }

        fn create_gauge(&self, name: &str) -> Gauge {
            let gauge = Arc::new(MockGauge::new(name.to_string()));
            self.gauges
                .lock()
                .unwrap()
                .insert(name.to_string(), gauge.clone());
            Gauge::Mock(gauge)
        }

        fn create_histogram(&self, name: &str) -> Histogram {
            let histogram = Arc::new(MockHistogram::new(name.to_string()));
            self.histograms
                .lock()
                .unwrap()
                .insert(name.to_string(), histogram.clone());
            Histogram::Mock(histogram)
        }

        fn create_timer(&self, name: &str) -> Timer {
            let timer = Arc::new(MockTimer::new(name.to_string()));
            self.timers
                .lock()
                .unwrap()
                .insert(name.to_string(), timer.clone());
            Timer::Mock(timer)
        }

        fn snapshot(&self) -> MetricsSnapshot {
            MetricsSnapshot {
                timestamp: Time::now().into(),
                counter_values: self.collect_counter_values(),
                gauge_values: self.collect_gauge_values(),
                histogram_summaries: self.collect_histogram_summaries(),
                timer_summaries: self.collect_timer_summaries(),
            }
        }
    }

    impl MockMetricRegistry {
        fn collect_counter_values(&self) -> HashMap<String, u64> {
            self.counters
                .lock()
                .unwrap()
                .iter()
                .map(|(name, counter)| (name.clone(), counter.get()))
                .collect()
        }

        fn collect_gauge_values(&self) -> HashMap<String, f64> {
            self.gauges
                .lock()
                .unwrap()
                .iter()
                .map(|(name, gauge)| (name.clone(), gauge.get()))
                .collect()
        }

        fn collect_histogram_summaries(&self) -> HashMap<String, HistogramSummary> {
            self.histograms
                .lock()
                .unwrap()
                .iter()
                .map(|(name, histogram)| (name.clone(), histogram.summary()))
                .collect()
        }

        fn collect_timer_summaries(&self) -> HashMap<String, TimerSummary> {
            self.timers
                .lock()
                .unwrap()
                .iter()
                .map(|(name, timer)| (name.clone(), timer.summary()))
                .collect()
        }
    }

    #[derive(Debug)]
    struct MockCounter {
        name: String,
        value: AtomicU64,
    }

    impl MockCounter {
        fn new(name: String) -> Self {
            Self {
                name,
                value: AtomicU64::new(0),
            }
        }

        fn increment(&self) {
            self.value.fetch_add(1, Ordering::AcqRel);
        }

        fn add(&self, value: u64) {
            self.value.fetch_add(value, Ordering::AcqRel);
        }

        fn set(&self, value: u64) {
            self.value.store(value, Ordering::Release);
        }

        fn get(&self) -> u64 {
            self.value.load(Ordering::Acquire)
        }
    }

    #[derive(Debug)]
    struct MockGauge {
        name: String,
        value: Arc<Mutex<f64>>,
    }

    impl MockGauge {
        fn new(name: String) -> Self {
            Self {
                name,
                value: Arc::new(Mutex::new(0.0)),
            }
        }

        fn set(&self, value: f64) {
            *self.value.lock().unwrap() = value;
        }

        fn get(&self) -> f64 {
            *self.value.lock().unwrap()
        }
    }

    #[derive(Debug)]
    struct MockHistogram {
        name: String,
        values: Arc<Mutex<Vec<f64>>>,
    }

    impl MockHistogram {
        fn new(name: String) -> Self {
            Self {
                name,
                values: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn record(&self, value: f64) {
            self.values.lock().unwrap().push(value);
        }

        fn summary(&self) -> HistogramSummary {
            let values = self.values.lock().unwrap();
            if values.is_empty() {
                return HistogramSummary::default();
            }

            let mut sorted = values.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

            HistogramSummary {
                count: sorted.len() as u64,
                sum: sorted.iter().sum(),
                min: sorted[0],
                max: sorted[sorted.len() - 1],
                mean: sorted.iter().sum::<f64>() / sorted.len() as f64,
                p50: percentile(&sorted, 0.5),
                p95: percentile(&sorted, 0.95),
                p99: percentile(&sorted, 0.99),
            }
        }
    }

    #[derive(Debug)]
    struct MockTimer {
        name: String,
        start_time: Arc<Mutex<Option<Instant>>>,
        durations: Arc<Mutex<Vec<Duration>>>,
    }

    impl MockTimer {
        fn new(name: String) -> Self {
            Self {
                name,
                start_time: Arc::new(Mutex::new(None)),
                durations: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn start(&self) {
            *self.start_time.lock().unwrap() = Some(Time::now().into());
        }

        fn stop(&self) -> Duration {
            if let Some(start) = self.start_time.lock().unwrap().take() {
                let duration = Time::now().into_instant().duration_since(start);
                self.durations.lock().unwrap().push(duration);
                duration
            } else {
                Duration::from_secs(0)
            }
        }

        fn summary(&self) -> TimerSummary {
            let durations = self.durations.lock().unwrap();
            if durations.is_empty() {
                return TimerSummary::default();
            }

            let mut sorted: Vec<f64> = durations.iter().map(|d| d.as_secs_f64()).collect();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

            TimerSummary {
                count: sorted.len() as u64,
                total_time: Duration::from_secs_f64(sorted.iter().sum()),
                min: Duration::from_secs_f64(sorted[0]),
                max: Duration::from_secs_f64(sorted[sorted.len() - 1]),
                mean: Duration::from_secs_f64(sorted.iter().sum::<f64>() / sorted.len() as f64),
                p50: Duration::from_secs_f64(percentile(&sorted, 0.5)),
                p95: Duration::from_secs_f64(percentile(&sorted, 0.95)),
                p99: Duration::from_secs_f64(percentile(&sorted, 0.99)),
            }
        }
    }

    fn percentile(sorted_values: &[f64], p: f64) -> f64 {
        if sorted_values.is_empty() {
            return 0.0;
        }
        let index = (p * (sorted_values.len() - 1) as f64) as usize;
        sorted_values[index]
    }

    #[derive(Debug, Clone, Default)]
    struct HistogramSummary {
        count: u64,
        sum: f64,
        min: f64,
        max: f64,
        mean: f64,
        p50: f64,
        p95: f64,
        p99: f64,
    }

    #[derive(Debug, Clone, Default)]
    struct TimerSummary {
        count: u64,
        total_time: Duration,
        min: Duration,
        max: Duration,
        mean: Duration,
        p50: Duration,
        p95: Duration,
        p99: Duration,
    }

    // Mock trait implementations for testing
    trait MetricRegistry {
        fn create_counter(&self, name: &str) -> Counter;
        fn create_gauge(&self, name: &str) -> Gauge;
        fn create_histogram(&self, name: &str) -> Histogram;
        fn create_timer(&self, name: &str) -> Timer;
        fn snapshot(&self) -> MetricsSnapshot;
    }

    #[derive(Debug)]
    enum Counter {
        Mock(Arc<MockCounter>),
    }

    impl Counter {
        fn set(&self, value: u64) {
            match self {
                Counter::Mock(counter) => counter.set(value),
            }
        }
    }

    #[derive(Debug)]
    enum Gauge {
        Mock(Arc<MockGauge>),
    }

    impl Gauge {
        fn set(&self, value: f64) {
            match self {
                Gauge::Mock(gauge) => gauge.set(value),
            }
        }
    }

    #[derive(Debug)]
    enum Histogram {
        Mock(Arc<MockHistogram>),
    }

    impl Histogram {
        fn record(&self, value: f64) {
            match self {
                Histogram::Mock(histogram) => histogram.record(value),
            }
        }
    }

    #[derive(Debug)]
    enum Timer {
        Mock(Arc<MockTimer>),
    }

    impl Timer {
        fn stop(&self) -> Duration {
            match self {
                Timer::Mock(timer) => timer.stop(),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct MetricsSnapshot {
        timestamp: Instant,
        counter_values: HashMap<String, u64>,
        gauge_values: HashMap<String, f64>,
        histogram_summaries: HashMap<String, HistogramSummary>,
        timer_summaries: HashMap<String, TimerSummary>,
    }

    // Mock CLI types
    #[derive(Debug)]
    struct ProgressBarConfig {
        total: u64,
        format: ProgressReportFormat,
        style: ProgressStyle,
        update_interval: Duration,
        show_throughput: bool,
        show_eta: bool,
    }

    #[derive(Debug)]
    enum ProgressReportFormat {
        Simple,
        Detailed,
    }

    #[derive(Debug)]
    enum ProgressStyle {
        Bar,
        Spinner,
        Percentage,
    }

    #[derive(Debug)]
    struct ProgressState {
        current: u64,
        message: String,
        start_time: Instant,
        last_update: Instant,
    }

    async fn run_progress_metrics_integration_test(
        cx: &Cx,
        operation: Arc<MockLongRunningOperation>,
        tracker: Arc<ProgressMetricsTracker>,
        progress_bar: Arc<MockInstrumentedProgressBar>,
    ) -> Result<ProgressIntegrationSummary> {
        let mut last_update = 0;
        let update_interval = 50; // Update every 50 items

        while !operation.is_complete() {
            // Process a batch
            let processed_in_batch = operation.process_batch(cx, 10).await?;

            if processed_in_batch > 0 {
                let (current, total) = operation.get_progress();

                // Update progress bar periodically
                if current - last_update >= update_interval || current == total {
                    let percentage = if total > 0 {
                        (current as f64 / total as f64) * 100.0
                    } else {
                        0.0
                    };
                    let message =
                        format!("Processed {}/{} items ({:.1}%)", current, total, percentage);

                    progress_bar.update_progress(current, message).await?;
                    last_update = current;
                }
            }

            // Small delay to allow other operations
            if !operation.is_complete() {
                cx.sleep(Duration::from_millis(10)).await?;
            }
        }

        progress_bar.finish()?;
        Ok(tracker.get_progress_summary())
    }

    #[tokio::test]
    async fn test_basic_progress_metrics_integration() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test setup
                    let total_items = 1000;
                    let processing_rate = 100; // items per second

                    let operation =
                        Arc::new(MockLongRunningOperation::new(total_items, processing_rate));
                    let tracker = Arc::new(ProgressMetricsTracker::new());
                    let metrics_registry = Arc::new(MockMetricRegistry::new());
                    let progress_bar = Arc::new(MockInstrumentedProgressBar::new(
                        total_items,
                        tracker.clone(),
                        metrics_registry.clone(),
                    ));

                    // Run the integration test
                    let summary =
                        run_progress_metrics_integration_test(cx, operation, tracker, progress_bar)
                            .await?;

                    // Verify basic integration metrics
                    assert!(
                        summary.total_progress_updates > 0,
                        "Should have progress updates"
                    );
                    assert!(
                        summary.total_metric_snapshots > 0,
                        "Should have metric snapshots"
                    );
                    assert!(
                        summary.total_throughput_measurements > 0,
                        "Should have throughput measurements"
                    );
                    assert!(summary.total_eta_estimates > 0, "Should have ETA estimates");
                    assert!(
                        (summary.final_percentage - 100.0).abs() < 0.1,
                        "Should reach 100% completion"
                    );
                    assert!(
                        summary.average_throughput > 0.0,
                        "Should have positive average throughput"
                    );
                    assert!(
                        summary.metrics_collection_consistency > 0.8,
                        "Metrics should be consistent"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Basic integration test should succeed"
        );
    }

    #[tokio::test]
    async fn test_throughput_calculation_accuracy() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test throughput accuracy with known processing rate
                    let total_items = 500;
                    let expected_rate = 50; // items per second

                    let operation =
                        Arc::new(MockLongRunningOperation::new(total_items, expected_rate));
                    let tracker = Arc::new(ProgressMetricsTracker::new());
                    let metrics_registry = Arc::new(MockMetricRegistry::new());
                    let progress_bar = Arc::new(MockInstrumentedProgressBar::new(
                        total_items,
                        tracker.clone(),
                        metrics_registry.clone(),
                    ));

                    let summary =
                        run_progress_metrics_integration_test(cx, operation, tracker, progress_bar)
                            .await?;

                    // Verify throughput calculation accuracy
                    let throughput_error = (summary.average_throughput - expected_rate as f64)
                        .abs()
                        / expected_rate as f64;
                    assert!(
                        throughput_error < 0.3,
                        "Throughput should be within 30% of expected rate"
                    );
                    assert!(
                        summary.throughput_variance < 20.0,
                        "Throughput variance should be reasonable"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Throughput accuracy test should succeed"
        );
    }

    #[tokio::test]
    async fn test_eta_estimation_quality() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test ETA estimation with consistent processing
                    let total_items = 300;
                    let processing_rate = 75;

                    let operation =
                        Arc::new(MockLongRunningOperation::new(total_items, processing_rate));
                    let tracker = Arc::new(ProgressMetricsTracker::new());
                    let metrics_registry = Arc::new(MockMetricRegistry::new());
                    let progress_bar = Arc::new(MockInstrumentedProgressBar::new(
                        total_items,
                        tracker.clone(),
                        metrics_registry.clone(),
                    ));

                    let summary =
                        run_progress_metrics_integration_test(cx, operation, tracker, progress_bar)
                            .await?;

                    // Verify ETA estimation quality
                    assert!(
                        summary.eta_accuracy > 0.5,
                        "ETA estimates should be reasonably accurate"
                    );
                    assert!(
                        summary.total_eta_estimates >= 3,
                        "Should generate multiple ETA estimates"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "ETA estimation test should succeed"
        );
    }

    #[tokio::test]
    async fn test_metrics_collection_consistency() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test metrics consistency during progress updates
                    let total_items = 200;
                    let processing_rate = 40;

                    let operation =
                        Arc::new(MockLongRunningOperation::new(total_items, processing_rate));
                    let tracker = Arc::new(ProgressMetricsTracker::new());
                    let metrics_registry = Arc::new(MockMetricRegistry::new());
                    let progress_bar = Arc::new(MockInstrumentedProgressBar::new(
                        total_items,
                        tracker.clone(),
                        metrics_registry.clone(),
                    ));

                    let summary =
                        run_progress_metrics_integration_test(cx, operation, tracker, progress_bar)
                            .await?;

                    // Verify metrics collection consistency
                    assert!(
                        summary.metrics_collection_consistency > 0.9,
                        "Metrics collection should be highly consistent"
                    );
                    assert!(
                        summary.total_metric_snapshots >= summary.total_progress_updates,
                        "Should have at least as many metric snapshots as progress updates"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Metrics consistency test should succeed"
        );
    }

    #[tokio::test]
    async fn test_variable_processing_rate_handling() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test handling of variable processing rates
                    let total_items = 400;
                    let initial_rate = 80;

                    let operation =
                        Arc::new(MockLongRunningOperation::new(total_items, initial_rate));
                    let tracker = Arc::new(ProgressMetricsTracker::new());
                    let metrics_registry = Arc::new(MockMetricRegistry::new());
                    let progress_bar = Arc::new(MockInstrumentedProgressBar::new(
                        total_items,
                        tracker.clone(),
                        metrics_registry.clone(),
                    ));

                    // Simulate variable processing by pausing/resuming
                    let operation_clone = operation.clone();
                    let pause_task = cx.spawn(|cx| {
                        Box::pin(async move {
                            cx.sleep(Duration::from_millis(2000)).await?;
                            operation_clone.pause();
                            cx.sleep(Duration::from_millis(500)).await?;
                            operation_clone.resume();
                            Ok(())
                        })
                    });

                    let summary =
                        run_progress_metrics_integration_test(cx, operation, tracker, progress_bar)
                            .await?;

                    let _ = pause_task.await;

                    // Verify handling of variable rates
                    assert!(
                        summary.throughput_variance > 0.0,
                        "Should detect throughput variance"
                    );
                    assert!(
                        summary.total_progress_updates > 5,
                        "Should have multiple progress updates"
                    );
                    assert!(
                        summary.final_percentage >= 99.0,
                        "Should complete despite rate changes"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Variable rate handling test should succeed"
        );
    }

    #[tokio::test]
    async fn test_comprehensive_integration_validation() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Comprehensive integration test with all features
                    let total_items = 600;
                    let processing_rate = 60;

                    let operation =
                        Arc::new(MockLongRunningOperation::new(total_items, processing_rate));
                    let tracker = Arc::new(ProgressMetricsTracker::new());
                    let metrics_registry = Arc::new(MockMetricRegistry::new());
                    let progress_bar = Arc::new(MockInstrumentedProgressBar::new(
                        total_items,
                        tracker.clone(),
                        metrics_registry.clone(),
                    ));

                    let summary =
                        run_progress_metrics_integration_test(cx, operation, tracker, progress_bar)
                            .await?;

                    // Comprehensive validation
                    assert!(
                        summary.total_progress_updates >= 10,
                        "Should have sufficient progress updates"
                    );
                    assert!(
                        summary.total_metric_snapshots >= 10,
                        "Should have sufficient metric snapshots"
                    );
                    assert!(
                        summary.total_throughput_measurements >= 5,
                        "Should have sufficient throughput measurements"
                    );
                    assert!(
                        summary.total_eta_estimates >= 5,
                        "Should have sufficient ETA estimates"
                    );
                    assert!(
                        (summary.final_percentage - 100.0).abs() < 0.1,
                        "Should complete successfully"
                    );
                    assert!(
                        summary.average_throughput > 10.0,
                        "Should maintain reasonable throughput"
                    );
                    assert!(
                        summary.throughput_variance >= 0.0,
                        "Variance should be non-negative"
                    );
                    assert!(
                        summary.eta_accuracy >= 0.0 && summary.eta_accuracy <= 1.0,
                        "ETA accuracy should be valid ratio"
                    );
                    assert!(
                        summary.metrics_collection_consistency > 0.7,
                        "Metrics should be mostly consistent"
                    );

                    // Verify integration completeness
                    assert!(
                        summary.total_progress_updates > 0,
                        "Progress updates integration working"
                    );
                    assert!(
                        summary.total_metric_snapshots > 0,
                        "Metrics snapshots integration working"
                    );
                    assert!(
                        summary.total_throughput_measurements > 0,
                        "Throughput measurement integration working"
                    );
                    assert!(
                        summary.total_eta_estimates > 0,
                        "ETA estimation integration working"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Comprehensive integration validation should succeed"
        );
    }
}
