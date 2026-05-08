//! Example: Prometheus-compatible metrics export with OtelMetrics.
//!
//! This example demonstrates how to integrate Asupersync's metrics with
//! OpenTelemetry for export to Prometheus or other metrics backends.
//!
//! # Running
//!
//! ```bash
//! rch exec -- cargo run --example prometheus_metrics --features metrics
//! ```
//!
//! # Production Setup with Prometheus
//!
//! For actual Prometheus export, add these dependencies to your Cargo.toml:
//!
//! ```toml
//! [dependencies]
//! opentelemetry-prometheus = "0.17"
//! prometheus = "0.13"
//! ```
//!
//! Then use the prometheus exporter instead of InMemoryMetricExporter.

// This example requires the "metrics" feature
#[cfg(not(feature = "metrics"))]
fn main() {
    println!("This example requires the 'metrics' feature.");
    println!("Run with: rch exec -- cargo run --example prometheus_metrics --features metrics");
}

#[cfg(feature = "metrics")]
fn main() {
    use asupersync::observability::{MetricsProvider, OtelMetrics};
    use asupersync::runtime::RuntimeBuilder;
    use opentelemetry::metrics::MeterProvider;
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
    use std::time::Duration;

    println!("=== Asupersync Prometheus Metrics Example ===\n");

    // Step 1: Set up OpenTelemetry metrics infrastructure
    // In production, you would use opentelemetry-prometheus exporter instead
    let exporter = InMemoryMetricExporter::default();
    let reader = PeriodicReader::builder(exporter.clone()).build();
    let provider = SdkMeterProvider::builder().with_reader(reader).build();
    let meter = provider.meter("asupersync");

    // Step 2: Create OtelMetrics from the meter
    let metrics = OtelMetrics::new(meter);

    // Step 3: Wire metrics into the runtime
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .metrics(metrics.clone())
        .build()
        .expect("Failed to build runtime");

    println!("Runtime created with OtelMetrics provider\n");

    // Step 4: Run some workload that generates metrics
    // In this example we'll demonstrate the metrics API directly
    println!("Simulating runtime activity...");

    // Simulate task lifecycle
    use asupersync::observability::OutcomeKind;
    use asupersync::types::{RegionId, TaskId};

    // Spawn some tasks
    for i in 0..10 {
        metrics.task_spawned(RegionId::testing_default(), TaskId::testing_default());
        println!("  Task {} spawned", i);
    }

    // Complete tasks with various outcomes
    for i in 0..10 {
        let outcome = match i % 4 {
            0 => OutcomeKind::Ok,
            1 => OutcomeKind::Err,
            2 => OutcomeKind::Cancelled,
            _ => OutcomeKind::Ok,
        };
        metrics.task_completed(
            TaskId::testing_default(),
            outcome,
            Duration::from_millis(i as u64 * 10 + 5),
        );
        println!("  Task {} completed with {:?}", i, outcome);
    }

    // Region lifecycle
    metrics.region_created(RegionId::testing_default(), None);
    metrics.region_closed(RegionId::testing_default(), Duration::from_secs(1));
    println!("  Region created and closed");

    // Cancellation
    use asupersync::types::CancelKind;
    metrics.cancellation_requested(RegionId::testing_default(), CancelKind::Timeout);
    metrics.drain_completed(RegionId::testing_default(), Duration::from_millis(50));
    println!("  Cancellation with drain completed");

    // Scheduler tick
    metrics.scheduler_tick(5, Duration::from_micros(250));
    println!("  Scheduler tick recorded\n");

    // Step 5: Force flush and read metrics
    provider.force_flush().expect("Failed to flush metrics");

    // Read exported metrics (in-memory for this example)
    let finished = exporter
        .get_finished_metrics()
        .expect("Failed to get metrics");

    println!("=== Exported Metrics ===\n");

    for resource_metrics in &finished {
        for scope_metrics in resource_metrics.scope_metrics() {
            for metric in scope_metrics.metrics() {
                println!("Metric: {}", metric.name());
                if !metric.description().is_empty() {
                    println!("  Description: {}", metric.description());
                }
                println!("  Data: {:?}", metric.data());
                println!();
            }
        }
    }

    // Clean up
    provider.shutdown().expect("Failed to shutdown provider");

    // Show the runtime config to verify metrics was wired
    println!("Runtime configuration:");
    println!("  Worker threads: {}", runtime.config().worker_threads);
    println!("  Poll budget: {}", runtime.config().poll_budget);

    println!("\n=== Example Complete ===");

    // Note: In production with Prometheus, you would expose an HTTP endpoint:
    //
    // ```ignore
    // use prometheus::TextEncoder;
    //
    // let registry = prometheus::Registry::new();
    // let exporter = opentelemetry_prometheus::exporter()
    //     .with_registry(registry.clone())
    //     .build()
    //     .unwrap();
    //
    // // ... set up provider with this exporter ...
    //
    // // HTTP endpoint handler:
    // let encoder = TextEncoder::new();
    // let metrics = encoder.encode_to_string(&registry.gather()).unwrap();
    // // Return `metrics` as the HTTP response body
    // ```
}
