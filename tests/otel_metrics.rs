#![allow(clippy::too_many_lines)]
//! Comprehensive OTel metrics test suite.
//!
//! Validates the full metrics pipeline:
//! - `MetricsProvider` trait compliance
//! - `TestMetricsProvider` spy for event capture
//! - `OtelMetrics` OpenTelemetry integration (feature-gated)
//! - Thread-safety under concurrent emission
//! - `NoOpMetrics` zero-overhead verification
//! - `InMemoryExporter` round-trip
//! - Snapshot building and custom exporters

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use asupersync::observability::{Metrics, MetricsProvider, NoOpMetrics, OutcomeKind};
use asupersync::record::ObligationKind;
use asupersync::runtime::RuntimeState;
use asupersync::runtime::config::ObligationLeakResponse;
use asupersync::trace::TraceEventKind;
use asupersync::types::cancel::CancelKind;
use asupersync::types::id::{RegionId, TaskId};
use asupersync::types::{Budget, Outcome};

/// Lightweight logging init for integration tests (no test_utils dependency).
fn init_test_logging() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();
    });
}

// ─── Test Spy MetricsProvider ────────────────────────────────────────────────

/// A test spy implementing `MetricsProvider` that records all events
/// as atomic counters, suitable for concurrent verification.
#[derive(Debug)]
struct TestMetricsProvider {
    tasks_spawned: AtomicUsize,
    tasks_completed: AtomicUsize,
    regions_created: AtomicUsize,
    regions_closed: AtomicUsize,
    cancellations_requested: AtomicUsize,
    drains_completed: AtomicUsize,
    deadlines_set: AtomicUsize,
    deadlines_exceeded: AtomicUsize,
    deadline_warnings: AtomicUsize,
    deadline_violations: AtomicUsize,
    deadline_remaining_calls: AtomicUsize,
    checkpoint_intervals: AtomicUsize,
    tasks_stuck: AtomicUsize,
    obligations_created: AtomicUsize,
    obligations_discharged: AtomicUsize,
    obligations_leaked: AtomicUsize,
    scheduler_ticks: AtomicUsize,
}

impl TestMetricsProvider {
    fn new() -> Self {
        Self {
            tasks_spawned: AtomicUsize::new(0),
            tasks_completed: AtomicUsize::new(0),
            regions_created: AtomicUsize::new(0),
            regions_closed: AtomicUsize::new(0),
            cancellations_requested: AtomicUsize::new(0),
            drains_completed: AtomicUsize::new(0),
            deadlines_set: AtomicUsize::new(0),
            deadlines_exceeded: AtomicUsize::new(0),
            deadline_warnings: AtomicUsize::new(0),
            deadline_violations: AtomicUsize::new(0),
            deadline_remaining_calls: AtomicUsize::new(0),
            checkpoint_intervals: AtomicUsize::new(0),
            tasks_stuck: AtomicUsize::new(0),
            obligations_created: AtomicUsize::new(0),
            obligations_discharged: AtomicUsize::new(0),
            obligations_leaked: AtomicUsize::new(0),
            scheduler_ticks: AtomicUsize::new(0),
        }
    }
}

impl MetricsProvider for TestMetricsProvider {
    fn task_spawned(&self, _region_id: RegionId, _task_id: TaskId) {
        self.tasks_spawned.fetch_add(1, Ordering::SeqCst);
    }

    fn task_completed(&self, _task_id: TaskId, _outcome: OutcomeKind, _duration: Duration) {
        self.tasks_completed.fetch_add(1, Ordering::SeqCst);
    }

    fn region_created(&self, _region_id: RegionId, _parent: Option<RegionId>) {
        self.regions_created.fetch_add(1, Ordering::SeqCst);
    }

    fn region_closed(&self, _region_id: RegionId, _lifetime: Duration) {
        self.regions_closed.fetch_add(1, Ordering::SeqCst);
    }

    fn cancellation_requested(&self, _region_id: RegionId, _kind: CancelKind) {
        self.cancellations_requested.fetch_add(1, Ordering::SeqCst);
    }

    fn drain_completed(&self, _region_id: RegionId, _duration: Duration) {
        self.drains_completed.fetch_add(1, Ordering::SeqCst);
    }

    fn deadline_set(&self, _region_id: RegionId, _deadline: Duration) {
        self.deadlines_set.fetch_add(1, Ordering::SeqCst);
    }

    fn deadline_exceeded(&self, _region_id: RegionId) {
        self.deadlines_exceeded.fetch_add(1, Ordering::SeqCst);
    }

    fn deadline_warning(&self, _task_type: &str, _reason: &'static str, _remaining: Duration) {
        self.deadline_warnings.fetch_add(1, Ordering::SeqCst);
    }

    fn deadline_violation(&self, _task_type: &str, _over_by: Duration) {
        self.deadline_violations.fetch_add(1, Ordering::SeqCst);
    }

    fn deadline_remaining(&self, _task_type: &str, _remaining: Duration) {
        self.deadline_remaining_calls.fetch_add(1, Ordering::SeqCst);
    }

    fn checkpoint_interval(&self, _task_type: &str, _interval: Duration) {
        self.checkpoint_intervals.fetch_add(1, Ordering::SeqCst);
    }

    fn task_stuck_detected(&self, _task_type: &str) {
        self.tasks_stuck.fetch_add(1, Ordering::SeqCst);
    }

    fn obligation_created(&self, _region_id: RegionId) {
        self.obligations_created.fetch_add(1, Ordering::SeqCst);
    }

    fn obligation_discharged(&self, _region_id: RegionId) {
        self.obligations_discharged.fetch_add(1, Ordering::SeqCst);
    }

    fn obligation_leaked(&self, _region_id: RegionId) {
        self.obligations_leaked.fetch_add(1, Ordering::SeqCst);
    }

    fn scheduler_tick(&self, _tasks_polled: usize, _duration: Duration) {
        self.scheduler_ticks.fetch_add(1, Ordering::SeqCst);
    }
}

// ─── MetricsProvider trait tests ─────────────────────────────────────────────

#[test]
fn test_provider_receives_task_events() {
    init_test_logging();
    let provider = TestMetricsProvider::new();
    let rid = RegionId::testing_default();
    let tid = TaskId::testing_default();

    provider.task_spawned(rid, tid);
    provider.task_spawned(rid, tid);
    provider.task_completed(tid, OutcomeKind::Ok, Duration::from_millis(10));

    assert_eq!(provider.tasks_spawned.load(Ordering::SeqCst), 2);
    assert_eq!(provider.tasks_completed.load(Ordering::SeqCst), 1);
}

#[test]
fn test_provider_receives_region_events() {
    init_test_logging();
    let provider = TestMetricsProvider::new();
    let rid = RegionId::testing_default();

    provider.region_created(rid, None);
    provider.region_created(rid, Some(rid));
    provider.region_closed(rid, Duration::from_secs(1));

    assert_eq!(provider.regions_created.load(Ordering::SeqCst), 2);
    assert_eq!(provider.regions_closed.load(Ordering::SeqCst), 1);
}

#[test]
fn test_provider_receives_cancellation_events() {
    init_test_logging();
    let provider = TestMetricsProvider::new();
    let rid = RegionId::testing_default();

    provider.cancellation_requested(rid, CancelKind::User);
    provider.cancellation_requested(rid, CancelKind::Timeout);
    provider.drain_completed(rid, Duration::from_millis(50));

    assert_eq!(provider.cancellations_requested.load(Ordering::SeqCst), 2);
    assert_eq!(provider.drains_completed.load(Ordering::SeqCst), 1);
}

#[test]
fn test_provider_receives_deadline_events() {
    init_test_logging();
    let provider = TestMetricsProvider::new();
    let rid = RegionId::testing_default();

    provider.deadline_set(rid, Duration::from_secs(5));
    provider.deadline_exceeded(rid);
    provider.deadline_warning("http_handler", "approaching", Duration::from_millis(500));
    provider.deadline_violation("http_handler", Duration::from_millis(100));
    provider.deadline_remaining("http_handler", Duration::from_secs(2));
    provider.checkpoint_interval("worker", Duration::from_millis(200));
    provider.task_stuck_detected("worker");

    assert_eq!(provider.deadlines_set.load(Ordering::SeqCst), 1);
    assert_eq!(provider.deadlines_exceeded.load(Ordering::SeqCst), 1);
    assert_eq!(provider.deadline_warnings.load(Ordering::SeqCst), 1);
    assert_eq!(provider.deadline_violations.load(Ordering::SeqCst), 1);
    assert_eq!(provider.deadline_remaining_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.checkpoint_intervals.load(Ordering::SeqCst), 1);
    assert_eq!(provider.tasks_stuck.load(Ordering::SeqCst), 1);
}

#[test]
fn test_provider_receives_obligation_events() {
    init_test_logging();
    let provider = TestMetricsProvider::new();
    let rid = RegionId::testing_default();

    provider.obligation_created(rid);
    provider.obligation_created(rid);
    provider.obligation_discharged(rid);
    provider.obligation_leaked(rid);

    assert_eq!(provider.obligations_created.load(Ordering::SeqCst), 2);
    assert_eq!(provider.obligations_discharged.load(Ordering::SeqCst), 1);
    assert_eq!(provider.obligations_leaked.load(Ordering::SeqCst), 1);
}

#[test]
fn test_provider_receives_scheduler_events() {
    init_test_logging();
    let provider = TestMetricsProvider::new();

    provider.scheduler_tick(5, Duration::from_micros(200));
    provider.scheduler_tick(3, Duration::from_micros(100));

    assert_eq!(provider.scheduler_ticks.load(Ordering::SeqCst), 2);
}

#[test]
fn test_provider_all_outcomes_accepted() {
    init_test_logging();
    let provider = TestMetricsProvider::new();
    let tid = TaskId::testing_default();

    provider.task_completed(tid, OutcomeKind::Ok, Duration::from_millis(1));
    provider.task_completed(tid, OutcomeKind::Err, Duration::from_millis(2));
    provider.task_completed(tid, OutcomeKind::Cancelled, Duration::from_millis(3));
    provider.task_completed(tid, OutcomeKind::Panicked, Duration::from_millis(4));

    assert_eq!(provider.tasks_completed.load(Ordering::SeqCst), 4);
}

// ─── NoOpMetrics tests ──────────────────────────────────────────────────────

#[test]
fn test_noop_metrics_object_safe() {
    init_test_logging();
    let noop = NoOpMetrics;

    // Verify it can be used as a trait object.
    let boxed: Box<dyn MetricsProvider> = Box::new(noop);
    boxed.task_spawned(RegionId::testing_default(), TaskId::testing_default());
    boxed.task_completed(
        TaskId::testing_default(),
        OutcomeKind::Ok,
        Duration::from_millis(1),
    );
    boxed.region_created(RegionId::testing_default(), None);
    boxed.region_closed(RegionId::testing_default(), Duration::from_secs(1));
    boxed.cancellation_requested(RegionId::testing_default(), CancelKind::User);
    boxed.drain_completed(RegionId::testing_default(), Duration::from_millis(5));
    boxed.deadline_set(RegionId::testing_default(), Duration::from_secs(10));
    boxed.deadline_exceeded(RegionId::testing_default());
    boxed.deadline_warning("t", "r", Duration::from_secs(1));
    boxed.deadline_violation("t", Duration::from_secs(1));
    boxed.deadline_remaining("t", Duration::from_secs(1));
    boxed.checkpoint_interval("t", Duration::from_secs(1));
    boxed.task_stuck_detected("t");
    boxed.obligation_created(RegionId::testing_default());
    boxed.obligation_discharged(RegionId::testing_default());
    boxed.obligation_leaked(RegionId::testing_default());
    boxed.scheduler_tick(1, Duration::from_millis(1));
    // If we got here, all methods dispatched correctly.
}

#[test]
fn test_noop_metrics_is_default() {
    fn assert_default<T: Default>() {}
    assert_default::<NoOpMetrics>();
}

#[test]
fn test_noop_metrics_is_clone_copy() {
    fn assert_clone<T: Clone>() {}
    fn assert_copy<T: Copy>() {}
    assert_clone::<NoOpMetrics>();
    assert_copy::<NoOpMetrics>();
}

// ─── Thread safety ──────────────────────────────────────────────────────────

#[test]
fn test_provider_concurrent_emission() {
    init_test_logging();
    let provider = Arc::new(TestMetricsProvider::new());
    let rid = RegionId::testing_default();
    let tid = TaskId::testing_default();

    let threads: Vec<_> = (0..8)
        .map(|_| {
            let p = Arc::clone(&provider);
            std::thread::spawn(move || {
                for _ in 0..100 {
                    p.task_spawned(rid, tid);
                    p.task_completed(tid, OutcomeKind::Ok, Duration::from_millis(1));
                    p.region_created(rid, None);
                    p.scheduler_tick(1, Duration::from_micros(10));
                }
            })
        })
        .collect();

    for t in threads {
        t.join().expect("thread join");
    }

    assert_eq!(provider.tasks_spawned.load(Ordering::SeqCst), 800);
    assert_eq!(provider.tasks_completed.load(Ordering::SeqCst), 800);
    assert_eq!(provider.regions_created.load(Ordering::SeqCst), 800);
    assert_eq!(provider.scheduler_ticks.load(Ordering::SeqCst), 800);
}

#[test]
fn test_arc_dyn_provider_send_sync() {
    init_test_logging();
    // Verify MetricsProvider: Send + Sync is satisfied with Arc.
    let provider: Arc<dyn MetricsProvider> = Arc::new(TestMetricsProvider::new());

    let p2 = Arc::clone(&provider);
    let handle = std::thread::spawn(move || {
        p2.task_spawned(RegionId::testing_default(), TaskId::testing_default());
    });
    handle.join().expect("thread join");
}

// ─── Obligation leak escalation policy ─────────────────────────────────────

fn setup_leaked_obligation(state: &mut RuntimeState) -> TaskId {
    let region = state.create_root_region(Budget::INFINITE);
    let (task_id, _handle) = state
        .create_task(region, Budget::INFINITE, async {})
        .expect("create task");
    state
        .create_obligation(ObligationKind::SendPermit, task_id, region, None)
        .expect("create obligation");
    if let Some(task) = state.task_mut(task_id) {
        task.complete(Outcome::Ok(()));
    }
    task_id
}

fn trace_has_obligation_leak(state: &RuntimeState) -> bool {
    state
        .trace
        .snapshot()
        .iter()
        .any(|event| event.kind == TraceEventKind::ObligationLeak)
}

#[test]
fn obligation_leak_response_log_emits_metric_and_trace() {
    init_test_logging();
    let provider = Arc::new(TestMetricsProvider::new());
    let mut state = RuntimeState::new_with_metrics(provider.clone());
    state.set_obligation_leak_response(ObligationLeakResponse::Log);

    let task_id = setup_leaked_obligation(&mut state);
    let _ = state.task_completed(task_id);

    assert_eq!(provider.obligations_leaked.load(Ordering::SeqCst), 1);
    assert!(trace_has_obligation_leak(&state));
}

#[test]
fn obligation_leak_response_silent_still_records_trace_and_metric() {
    init_test_logging();
    let provider = Arc::new(TestMetricsProvider::new());
    let mut state = RuntimeState::new_with_metrics(provider.clone());
    state.set_obligation_leak_response(ObligationLeakResponse::Silent);

    let task_id = setup_leaked_obligation(&mut state);
    let _ = state.task_completed(task_id);

    assert_eq!(provider.obligations_leaked.load(Ordering::SeqCst), 1);
    assert!(trace_has_obligation_leak(&state));
}

#[test]
fn obligation_leak_response_panics() {
    init_test_logging();
    let provider = Arc::new(TestMetricsProvider::new());
    let mut state = RuntimeState::new_with_metrics(provider.clone());
    state.set_obligation_leak_response(ObligationLeakResponse::Panic);

    let task_id = setup_leaked_obligation(&mut state);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = state.task_completed(task_id);
    }));

    assert!(result.is_err(), "expected panic on obligation leak");
    assert_eq!(provider.obligations_leaked.load(Ordering::SeqCst), 1);
    assert!(trace_has_obligation_leak(&state));
}

// ─── Built-in Counter / Gauge / Histogram (via Metrics registry) ────────────

#[test]
fn test_counter_monotonic() {
    init_test_logging();
    let mut metrics = Metrics::new();
    let c = metrics.counter("test_counter");
    assert_eq!(c.get(), 0);
    c.increment();
    assert_eq!(c.get(), 1);
    c.add(99);
    assert_eq!(c.get(), 100);
}

#[test]
fn test_gauge_bidirectional() {
    init_test_logging();
    let mut metrics = Metrics::new();
    let g = metrics.gauge("test_gauge");
    g.set(50);
    assert_eq!(g.get(), 50);
    g.increment();
    assert_eq!(g.get(), 51);
    g.decrement();
    assert_eq!(g.get(), 50);
    g.add(10);
    assert_eq!(g.get(), 60);
    g.sub(20);
    assert_eq!(g.get(), 40);
}

#[test]
#[allow(clippy::float_cmp)]
fn test_histogram_records_observations() {
    init_test_logging();
    let mut metrics = Metrics::new();
    let h = metrics.histogram("latency", vec![1.0, 5.0, 10.0, 50.0]);
    h.observe(0.5);
    h.observe(3.0);
    h.observe(8.0);
    h.observe(100.0);

    assert_eq!(h.count(), 4);
    assert_eq!(h.sum(), 111.5);
    assert_eq!(h.name(), "latency");
}

#[test]
fn test_registry_counter_reuse() {
    init_test_logging();
    let mut metrics = Metrics::new();
    let c1 = metrics.counter("requests");
    c1.increment();

    let c2 = metrics.counter("requests");
    assert_eq!(c2.get(), 1, "same counter returned on duplicate name");
}

#[test]
fn test_registry_gauge_reuse() {
    init_test_logging();
    let mut metrics = Metrics::new();
    let g1 = metrics.gauge("active_connections");
    g1.set(42);

    let g2 = metrics.gauge("active_connections");
    assert_eq!(g2.get(), 42);
}

#[test]
fn test_registry_prometheus_export() {
    init_test_logging();
    let mut metrics = Metrics::new();
    metrics.counter("http_requests").add(150);
    metrics.gauge("memory_bytes").set(8192);

    let output = metrics.export_prometheus();
    assert!(
        output.contains("http_requests 150"),
        "expected counter in export"
    );
    assert!(
        output.contains("memory_bytes 8192"),
        "expected gauge in export"
    );
}

// ─── OutcomeKind ─────────────────────────────────────────────────────────────

#[test]
fn test_outcome_kind_variants() {
    // Ensure all variants exist and are distinguishable.
    let variants = [
        OutcomeKind::Ok,
        OutcomeKind::Err,
        OutcomeKind::Cancelled,
        OutcomeKind::Panicked,
    ];
    for (i, a) in variants.iter().enumerate() {
        for (j, b) in variants.iter().enumerate() {
            if i == j {
                assert_eq!(
                    std::mem::discriminant(a),
                    std::mem::discriminant(b),
                    "same variant should match"
                );
            } else {
                assert_ne!(
                    std::mem::discriminant(a),
                    std::mem::discriminant(b),
                    "different variants should differ"
                );
            }
        }
    }
}

// ─── Feature-gated OTel tests ───────────────────────────────────────────────

#[cfg(feature = "metrics")]
mod otel_integration {
    use super::*;
    use asupersync::observability::{
        ExportError, InMemoryExporter, MetricsConfig, MetricsExporter, MetricsSnapshot,
        MultiExporter, NullExporter, OtelMetrics,
    };
    use opentelemetry::metrics::MeterProvider;
    use opentelemetry_sdk::metrics::{
        InMemoryMetricExporter as OtelInMemoryExporter, PeriodicReader, SdkMeterProvider,
        data::ResourceMetrics,
    };
    use std::collections::HashSet;

    fn otel_metric_names(finished: &[ResourceMetrics]) -> HashSet<String> {
        let mut names = HashSet::new();
        for rm in finished {
            for sm in &rm.scope_metrics {
                for m in &sm.metrics {
                    names.insert(m.name.to_string());
                }
            }
        }
        names
    }

    // ── OtelMetrics instrument creation ──

    #[test]
    fn otel_creates_all_instruments() {
        init_test_logging();
        let exporter = OtelInMemoryExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("asupersync");

        let metrics = OtelMetrics::new(meter);

        // Call every method to ensure instruments are created.
        let rid = RegionId::testing_default();
        let tid = TaskId::testing_default();

        metrics.task_spawned(rid, tid);
        metrics.task_completed(tid, OutcomeKind::Ok, Duration::from_millis(10));
        metrics.region_created(rid, None);
        metrics.region_closed(rid, Duration::from_secs(1));
        metrics.cancellation_requested(rid, CancelKind::User);
        metrics.drain_completed(rid, Duration::from_millis(5));
        metrics.deadline_set(rid, Duration::from_secs(2));
        metrics.deadline_exceeded(rid);
        metrics.deadline_warning("test", "approaching", Duration::from_secs(1));
        metrics.deadline_violation("test", Duration::from_millis(200));
        metrics.deadline_remaining("test", Duration::from_secs(4));
        metrics.checkpoint_interval("test", Duration::from_millis(100));
        metrics.task_stuck_detected("test");
        metrics.obligation_created(rid);
        metrics.obligation_discharged(rid);
        metrics.obligation_leaked(rid);
        metrics.scheduler_tick(5, Duration::from_millis(1));

        provider.force_flush().expect("flush");
        let finished = exporter.get_finished_metrics().expect("finished");
        assert!(!finished.is_empty(), "expected exported metrics");

        let names = otel_metric_names(&finished);

        let expected = [
            "asupersync.tasks.spawned",
            "asupersync.tasks.completed",
            "asupersync.tasks.duration",
            "asupersync.regions.created",
            "asupersync.regions.closed",
            "asupersync.regions.lifetime",
            "asupersync.cancellations",
            "asupersync.cancellation.drain_duration",
            "asupersync.deadlines.set",
            "asupersync.deadlines.exceeded",
            "asupersync.deadline.warnings_total",
            "asupersync.deadline.violations_total",
            "asupersync.deadline.remaining_seconds",
            "asupersync.checkpoint.interval_seconds",
            "asupersync.task.stuck_detected_total",
            "asupersync.obligations.created",
            "asupersync.obligations.discharged",
            "asupersync.obligations.leaked",
            "asupersync.scheduler.poll_time",
            "asupersync.scheduler.tasks_polled",
        ];

        for name in expected {
            assert!(names.contains(name), "missing OTel metric: {name}");
        }

        provider.shutdown().expect("shutdown");
    }

    // ── OtelMetrics with MetricsConfig ──

    #[test]
    fn otel_config_cardinality_and_sampling() {
        init_test_logging();
        let exporter = OtelInMemoryExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("asupersync");

        let config = MetricsConfig::new().with_max_cardinality(256);
        let metrics = OtelMetrics::new_with_config(meter, config);

        assert_eq!(metrics.config().max_cardinality, 256);

        // Emit metrics — should still work with custom config.
        metrics.task_spawned(RegionId::testing_default(), TaskId::testing_default());
        metrics.task_completed(
            TaskId::testing_default(),
            OutcomeKind::Ok,
            Duration::from_millis(5),
        );

        provider.force_flush().expect("flush");
        let finished = exporter.get_finished_metrics().expect("finished");
        assert!(!finished.is_empty());

        provider.shutdown().expect("shutdown");
    }

    // ── Custom exporters ──

    #[test]
    fn null_exporter_accepts_everything() {
        init_test_logging();
        let exporter = NullExporter::new();
        let snapshot = MetricsSnapshot::new();
        assert!(exporter.export(&snapshot).is_ok());
        assert!(exporter.flush().is_ok());
    }

    #[test]
    fn in_memory_exporter_round_trip() {
        init_test_logging();
        let exporter = InMemoryExporter::new();

        let mut snap = MetricsSnapshot::new();
        snap.add_counter("tasks_spawned", vec![], 42);
        snap.add_gauge(
            "active_tasks",
            vec![("region".to_string(), "root".to_string())],
            7,
        );
        snap.add_histogram("duration", vec![], 100, 55.5);

        assert!(exporter.export(&snap).is_ok());
        assert_eq!(exporter.total_metrics(), 3);

        let snapshots = exporter.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].counters.len(), 1);
        assert_eq!(snapshots[0].gauges.len(), 1);
        assert_eq!(snapshots[0].histograms.len(), 1);

        // Verify counter content.
        let (name, labels, value) = &snapshots[0].counters[0];
        assert_eq!(name, "tasks_spawned");
        assert!(labels.is_empty());
        assert_eq!(*value, 42);

        exporter.clear();
        assert_eq!(exporter.total_metrics(), 0);
    }

    #[test]
    fn multi_exporter_fans_to_all() {
        init_test_logging();
        let e1 = Arc::new(InMemoryExporter::new());
        let e2 = Arc::new(InMemoryExporter::new());

        struct ArcWrap(Arc<InMemoryExporter>);
        impl MetricsExporter for ArcWrap {
            fn export(&self, m: &MetricsSnapshot) -> Result<(), ExportError> {
                self.0.export(m)
            }
            fn flush(&self) -> Result<(), ExportError> {
                self.0.flush()
            }
        }

        let mut multi = MultiExporter::new(vec![]);
        multi.add(Box::new(ArcWrap(Arc::clone(&e1))));
        multi.add(Box::new(ArcWrap(Arc::clone(&e2))));

        let mut snap = MetricsSnapshot::new();
        snap.add_counter("test", vec![], 1);
        assert!(multi.export(&snap).is_ok());

        assert_eq!(e1.total_metrics(), 1);
        assert_eq!(e2.total_metrics(), 1);
    }

    #[test]
    fn snapshot_building() {
        init_test_logging();
        let mut snap = MetricsSnapshot::new();
        snap.add_counter("c1", vec![("k".into(), "v".into())], 10);
        snap.add_gauge("g1", vec![], 42);
        snap.add_histogram("h1", vec![], 50, 25.0);

        assert_eq!(snap.counters.len(), 1);
        assert_eq!(snap.gauges.len(), 1);
        assert_eq!(snap.histograms.len(), 1);
    }

    #[test]
    fn export_error_is_displayable() {
        let err = ExportError::new("connection refused");
        let msg = format!("{err}");
        assert!(msg.contains("connection refused"));
    }

    // ── OtelMetrics concurrent emission ──

    #[test]
    fn otel_concurrent_emission() {
        init_test_logging();
        let exporter = OtelInMemoryExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("asupersync");
        let metrics = Arc::new(OtelMetrics::new(meter));

        let threads: Vec<_> = (0..4)
            .map(|_| {
                let m = Arc::clone(&metrics);
                std::thread::spawn(move || {
                    let rid = RegionId::testing_default();
                    let tid = TaskId::testing_default();
                    for _ in 0..50 {
                        m.task_spawned(rid, tid);
                        m.task_completed(tid, OutcomeKind::Ok, Duration::from_millis(1));
                        m.scheduler_tick(1, Duration::from_micros(10));
                    }
                })
            })
            .collect();

        for t in threads {
            t.join().expect("thread join");
        }

        provider.force_flush().expect("flush");
        let finished = exporter.get_finished_metrics().expect("finished");
        assert!(
            !finished.is_empty(),
            "expected metrics after concurrent emission"
        );

        provider.shutdown().expect("shutdown");
    }

    // ── RuntimeBuilder metrics wiring ──

    #[test]
    fn runtime_builder_accepts_otel_metrics() {
        use asupersync::runtime::RuntimeBuilder;

        init_test_logging();
        let exporter = OtelInMemoryExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("asupersync");

        let otel = OtelMetrics::new(meter);

        // Verify the builder accepts OtelMetrics.
        let _runtime = RuntimeBuilder::new().metrics(otel).build().expect("build");

        provider.shutdown().expect("shutdown");
    }

    #[test]
    fn runtime_builder_accepts_noop_metrics() {
        use asupersync::runtime::RuntimeBuilder;
        init_test_logging();
        let _runtime = RuntimeBuilder::new()
            .metrics(NoOpMetrics)
            .build()
            .expect("build");
    }

    #[test]
    fn runtime_builder_accepts_test_provider() {
        use asupersync::runtime::RuntimeBuilder;
        init_test_logging();
        let _runtime = RuntimeBuilder::new()
            .metrics(TestMetricsProvider::new())
            .build()
            .expect("build");
    }
}
