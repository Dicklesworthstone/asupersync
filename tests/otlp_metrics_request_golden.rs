//! Golden snapshot tests for OTLP metrics export request wire format.
//!
//! Validates that OTLP metrics export requests maintain stable wire format
//! across code changes. Tests the full pipeline from metrics collection to
//! protobuf serialization.
//!
//! # Coverage
//!
//! - Counter metrics with labels
//! - Gauge metrics with resource attributes
//! - Histogram metrics with buckets
//! - Multiple metric types in single request
//! - Resource attributes and instrumentation scope
//! - Timestamp handling and temporality
//! - Error conditions and edge cases

#![cfg(test)]

use serde_json::{Value, json};
use std::collections::HashMap;

/// Test data structure representing an OTLP metrics export request.
/// This mirrors the actual OTLP protobuf structure but in a
/// JSON-serializable format for golden snapshots.
#[derive(Debug, Clone, serde::Serialize)]
struct OtlpMetricsRequest {
    /// Resource attributes (e.g., service.name, service.version)
    resource_attributes: HashMap<String, String>,
    /// Instrumentation scope metadata
    scope_metrics: Vec<ScopeMetrics>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ScopeMetrics {
    scope: InstrumentationScope,
    metrics: Vec<Metric>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct InstrumentationScope {
    name: String,
    version: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct Metric {
    name: String,
    description: String,
    unit: String,
    #[serde(flatten)]
    data: MetricData,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type")]
enum MetricData {
    #[serde(rename = "counter")]
    Counter { data_points: Vec<NumberDataPoint> },
    #[serde(rename = "gauge")]
    Gauge { data_points: Vec<NumberDataPoint> },
    #[serde(rename = "histogram")]
    Histogram {
        data_points: Vec<HistogramDataPoint>,
    },
}

#[derive(Debug, Clone, serde::Serialize)]
struct NumberDataPoint {
    attributes: HashMap<String, String>,
    time_unix_nano: u64,
    value: MetricValue,
}

#[derive(Debug, Clone, serde::Serialize)]
struct HistogramDataPoint {
    attributes: HashMap<String, String>,
    time_unix_nano: u64,
    count: u64,
    sum: f64,
    bucket_counts: Vec<u64>,
    explicit_bounds: Vec<f64>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged)]
enum MetricValue {
    Int64(i64),
    Double(f64),
}

/// Helper to create a baseline OTLP metrics request for golden snapshots.
fn create_baseline_otlp_request() -> OtlpMetricsRequest {
    let timestamp = 1640995200000000000u64; // 2022-01-01T00:00:00Z (deterministic)

    OtlpMetricsRequest {
        resource_attributes: [
            ("service.name".to_string(), "asupersync".to_string()),
            ("service.version".to_string(), "0.3.1".to_string()),
            ("deployment.environment".to_string(), "test".to_string()),
            ("host.name".to_string(), "test-host".to_string()),
            ("process.pid".to_string(), "12345".to_string()),
        ]
        .into(),
        scope_metrics: vec![ScopeMetrics {
            scope: InstrumentationScope {
                name: "asupersync".to_string(),
                version: "0.3.1".to_string(),
            },
            metrics: vec![
                // Counter: tasks spawned
                Metric {
                    name: "asupersync.tasks.spawned".to_string(),
                    description: "Total number of tasks spawned".to_string(),
                    unit: "1".to_string(),
                    data: MetricData::Counter {
                        data_points: vec![
                            NumberDataPoint {
                                attributes: [("region_type".to_string(), "root".to_string())]
                                    .into(),
                                time_unix_nano: timestamp,
                                value: MetricValue::Int64(42),
                            },
                            NumberDataPoint {
                                attributes: [("region_type".to_string(), "child".to_string())]
                                    .into(),
                                time_unix_nano: timestamp,
                                value: MetricValue::Int64(18),
                            },
                        ],
                    },
                },
                // Gauge: active connections
                Metric {
                    name: "asupersync.connections.active".to_string(),
                    description: "Current number of active connections".to_string(),
                    unit: "1".to_string(),
                    data: MetricData::Gauge {
                        data_points: vec![NumberDataPoint {
                            attributes: [
                                ("protocol".to_string(), "http1".to_string()),
                                ("status".to_string(), "healthy".to_string()),
                            ]
                            .into(),
                            time_unix_nano: timestamp,
                            value: MetricValue::Int64(8),
                        }],
                    },
                },
                // Histogram: task duration
                Metric {
                    name: "asupersync.tasks.duration".to_string(),
                    description: "Task execution duration in seconds".to_string(),
                    unit: "s".to_string(),
                    data: MetricData::Histogram {
                        data_points: vec![HistogramDataPoint {
                            attributes: [("outcome".to_string(), "ok".to_string())].into(),
                            time_unix_nano: timestamp,
                            count: 100,
                            sum: 42.5,
                            bucket_counts: vec![10, 50, 35, 5, 0],
                            explicit_bounds: vec![0.1, 0.5, 1.0, 5.0],
                        }],
                    },
                },
            ],
        }],
    }
}

/// Helper to create an edge case OTLP request with boundary conditions.
fn create_edge_case_otlp_request() -> OtlpMetricsRequest {
    let timestamp = 1640995260000000000u64; // +1 minute

    OtlpMetricsRequest {
        resource_attributes: [
            ("service.name".to_string(), "edge-test".to_string()),
            ("service.version".to_string(), "unknown".to_string()),
            // Test Unicode and special characters
            ("custom.label".to_string(), "测试 with 🚀 emoji".to_string()),
            ("empty.value".to_string(), String::new()),
        ]
        .into(),
        scope_metrics: vec![ScopeMetrics {
            scope: InstrumentationScope {
                name: "edge-test".to_string(),
                version: String::new(),
            },
            metrics: vec![
                // Counter with zero value
                Metric {
                    name: "zero.counter".to_string(),
                    description: String::new(),
                    unit: String::new(),
                    data: MetricData::Counter {
                        data_points: vec![NumberDataPoint {
                            attributes: HashMap::new(),
                            time_unix_nano: timestamp,
                            value: MetricValue::Int64(0),
                        }],
                    },
                },
                // Gauge with negative value
                Metric {
                    name: "temperature.celsius".to_string(),
                    description: "Temperature reading".to_string(),
                    unit: "°C".to_string(),
                    data: MetricData::Gauge {
                        data_points: vec![NumberDataPoint {
                            attributes: [("sensor".to_string(), "outdoor".to_string())].into(),
                            time_unix_nano: timestamp,
                            value: MetricValue::Double(-15.5),
                        }],
                    },
                },
                // Histogram with empty buckets
                Metric {
                    name: "empty.histogram".to_string(),
                    description: "Histogram with no observations".to_string(),
                    unit: "ms".to_string(),
                    data: MetricData::Histogram {
                        data_points: vec![HistogramDataPoint {
                            attributes: HashMap::new(),
                            time_unix_nano: timestamp,
                            count: 0,
                            sum: 0.0,
                            bucket_counts: vec![0, 0, 0],
                            explicit_bounds: vec![1.0, 10.0],
                        }],
                    },
                },
            ],
        }],
    }
}

/// Helper to create a high-cardinality OTLP request for stress testing.
fn create_high_cardinality_otlp_request() -> OtlpMetricsRequest {
    let timestamp = 1640995320000000000u64; // +2 minutes

    // Generate multiple data points with different label combinations
    let mut data_points = Vec::new();
    for i in 0..10 {
        data_points.push(NumberDataPoint {
            attributes: [
                ("endpoint".to_string(), format!("/api/v{}", i)),
                (
                    "method".to_string(),
                    if i % 2 == 0 {
                        "GET".to_string()
                    } else {
                        "POST".to_string()
                    },
                ),
                (
                    "status_code".to_string(),
                    format!("{}", 200 + (i % 5) * 100),
                ),
            ]
            .into(),
            time_unix_nano: timestamp + (i as u64 * 1000000), // Slightly different timestamps
            value: MetricValue::Int64((i + 1) * 10),
        });
    }

    OtlpMetricsRequest {
        resource_attributes: [
            (
                "service.name".to_string(),
                "high-cardinality-test".to_string(),
            ),
            ("service.version".to_string(), "1.0.0".to_string()),
        ]
        .into(),
        scope_metrics: vec![ScopeMetrics {
            scope: InstrumentationScope {
                name: "high-cardinality".to_string(),
                version: "1.0.0".to_string(),
            },
            metrics: vec![Metric {
                name: "http.requests.total".to_string(),
                description: "HTTP requests by endpoint and status".to_string(),
                unit: "1".to_string(),
                data: MetricData::Counter { data_points },
            }],
        }],
    }
}

/// Helper to scrub dynamic values for deterministic golden snapshots.
fn scrub_for_golden(request: &OtlpMetricsRequest) -> Value {
    // Convert to JSON and apply consistent scrubbing patterns
    let mut value = serde_json::to_value(request).expect("serialize to JSON");

    fn scrub_recursive(value: &mut Value) {
        match value {
            Value::Object(map) => {
                for (key, val) in map.iter_mut() {
                    match key.as_str() {
                        // Scrub timestamps to [TIMESTAMP]
                        "time_unix_nano" => {
                            *val = Value::String("[TIMESTAMP]".to_string());
                        }
                        // Scrub process IDs
                        "process.pid" => {
                            *val = Value::String("[PID]".to_string());
                        }
                        // Scrub host names
                        "host.name" => {
                            *val = Value::String("[HOSTNAME]".to_string());
                        }
                        _ => scrub_recursive(val),
                    }
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    scrub_recursive(item);
                }
            }
            _ => {}
        }
    }

    scrub_recursive(&mut value);

    // Add metadata for context
    json!({
        "otlp_version": "1.0.0",
        "content_type": "application/x-protobuf",
        "scrubbed_fields": ["time_unix_nano", "process.pid", "host.name"],
        "export_request": value
    })
}

// =============================================================================
// Golden Snapshot Tests
// =============================================================================

#[test]
fn test_otlp_baseline_metrics_request() {
    let request = create_baseline_otlp_request();
    let scrubbed = scrub_for_golden(&request);

    insta::assert_json_snapshot!("otlp_baseline_metrics_request", scrubbed);
}

#[test]
fn test_otlp_edge_case_metrics_request() {
    let request = create_edge_case_otlp_request();
    let scrubbed = scrub_for_golden(&request);

    insta::assert_json_snapshot!("otlp_edge_case_metrics_request", scrubbed);
}

#[test]
fn test_otlp_high_cardinality_metrics_request() {
    let request = create_high_cardinality_otlp_request();
    let scrubbed = scrub_for_golden(&request);

    insta::assert_json_snapshot!("otlp_high_cardinality_metrics_request", scrubbed);
}

#[test]
fn test_otlp_multiple_scopes_metrics_request() {
    let timestamp = 1640995380000000000u64; // +3 minutes

    let request = OtlpMetricsRequest {
        resource_attributes: [
            ("service.name".to_string(), "multi-scope-test".to_string()),
            ("service.version".to_string(), "0.1.0".to_string()),
        ]
        .into(),
        scope_metrics: vec![
            // Runtime metrics scope
            ScopeMetrics {
                scope: InstrumentationScope {
                    name: "asupersync::runtime".to_string(),
                    version: "0.3.1".to_string(),
                },
                metrics: vec![Metric {
                    name: "runtime.scheduler.ticks".to_string(),
                    description: "Scheduler tick count".to_string(),
                    unit: "1".to_string(),
                    data: MetricData::Counter {
                        data_points: vec![NumberDataPoint {
                            attributes: [("worker_id".to_string(), "0".to_string())].into(),
                            time_unix_nano: timestamp,
                            value: MetricValue::Int64(1000),
                        }],
                    },
                }],
            },
            // HTTP metrics scope
            ScopeMetrics {
                scope: InstrumentationScope {
                    name: "asupersync::http".to_string(),
                    version: "0.3.1".to_string(),
                },
                metrics: vec![Metric {
                    name: "http.server.duration".to_string(),
                    description: "HTTP request duration".to_string(),
                    unit: "s".to_string(),
                    data: MetricData::Histogram {
                        data_points: vec![HistogramDataPoint {
                            attributes: [
                                ("method".to_string(), "GET".to_string()),
                                ("route".to_string(), "/health".to_string()),
                            ]
                            .into(),
                            time_unix_nano: timestamp,
                            count: 25,
                            sum: 12.5,
                            bucket_counts: vec![20, 5, 0, 0],
                            explicit_bounds: vec![0.1, 1.0, 10.0],
                        }],
                    },
                }],
            },
        ],
    };

    let scrubbed = scrub_for_golden(&request);
    insta::assert_json_snapshot!("otlp_multiple_scopes_metrics_request", scrubbed);
}

#[test]
fn test_otlp_empty_metrics_request() {
    let request = OtlpMetricsRequest {
        resource_attributes: [("service.name".to_string(), "empty-test".to_string())].into(),
        scope_metrics: vec![ScopeMetrics {
            scope: InstrumentationScope {
                name: "empty".to_string(),
                version: String::new(),
            },
            metrics: vec![], // No metrics
        }],
    };

    let scrubbed = scrub_for_golden(&request);
    insta::assert_json_snapshot!("otlp_empty_metrics_request", scrubbed);
}

// =============================================================================
// Validation Tests
// =============================================================================

#[test]
fn test_golden_snapshot_determinism() {
    // Ensure multiple runs produce identical golden snapshots
    let request1 = create_baseline_otlp_request();
    let request2 = create_baseline_otlp_request();

    let scrubbed1 = scrub_for_golden(&request1);
    let scrubbed2 = scrub_for_golden(&request2);

    assert_eq!(
        scrubbed1, scrubbed2,
        "Golden snapshots should be deterministic"
    );
}

#[test]
fn test_scrubbing_removes_dynamic_values() {
    let request = create_baseline_otlp_request();
    let scrubbed = scrub_for_golden(&request);

    let scrubbed_str = serde_json::to_string(&scrubbed).expect("serialize scrubbed");

    // Verify dynamic values are scrubbed
    assert!(
        scrubbed_str.contains("[TIMESTAMP]"),
        "Timestamps should be scrubbed"
    );
    assert!(
        scrubbed_str.contains("[PID]"),
        "Process IDs should be scrubbed"
    );
    assert!(
        scrubbed_str.contains("[HOSTNAME]"),
        "Hostnames should be scrubbed"
    );

    // Verify static values are preserved
    assert!(
        scrubbed_str.contains("asupersync"),
        "Service name should be preserved"
    );
    assert!(
        scrubbed_str.contains("tasks.spawned"),
        "Metric names should be preserved"
    );
}

#[test]
fn test_metric_data_types_coverage() {
    let baseline = create_baseline_otlp_request();
    let edge_case = create_edge_case_otlp_request();
    let high_card = create_high_cardinality_otlp_request();

    // Collect all metric types across test requests
    let mut metric_types = std::collections::HashSet::new();

    for request in &[baseline, edge_case, high_card] {
        for scope in &request.scope_metrics {
            for metric in &scope.metrics {
                match &metric.data {
                    MetricData::Counter { .. } => {
                        metric_types.insert("counter");
                    }
                    MetricData::Gauge { .. } => {
                        metric_types.insert("gauge");
                    }
                    MetricData::Histogram { .. } => {
                        metric_types.insert("histogram");
                    }
                }
            }
        }
    }

    // Ensure we test all major OTLP metric types
    assert!(
        metric_types.contains("counter"),
        "Should test counter metrics"
    );
    assert!(metric_types.contains("gauge"), "Should test gauge metrics");
    assert!(
        metric_types.contains("histogram"),
        "Should test histogram metrics"
    );
    assert_eq!(
        metric_types.len(),
        3,
        "Should cover all supported metric types"
    );
}

#[cfg(all(feature = "metrics", feature = "test-internals"))]
fn loopback_otlp_capture(
    path: &str,
    request_count: usize,
) -> (
    String,
    std::sync::mpsc::Receiver<Vec<u8>>,
    std::thread::JoinHandle<()>,
) {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::time::Duration;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback collector");
    let endpoint = format!(
        "http://{}{}",
        listener.local_addr().expect("collector addr"),
        path
    );
    let (body_tx, body_rx) = mpsc::sync_channel(request_count);
    let collector = std::thread::spawn(move || {
        for _ in 0..request_count {
            let (mut stream, _) = listener.accept().expect("accept exporter connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("collector read timeout");
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            let (header_end, content_length) = loop {
                let read = stream.read(&mut buffer).expect("read exporter request");
                assert_ne!(read, 0, "exporter closed before HTTP headers");
                request.extend_from_slice(&buffer[..read]);
                if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    let header_end = end + 4;
                    let headers =
                        std::str::from_utf8(&request[..header_end]).expect("ASCII headers");
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().expect("content length"))
                        })
                        .expect("content-length header");
                    break (header_end, content_length);
                }
            };
            while request.len() < header_end + content_length {
                let read = stream.read(&mut buffer).expect("read exporter body");
                assert_ne!(read, 0, "exporter closed before complete body");
                request.extend_from_slice(&buffer[..read]);
            }
            body_tx
                .send(request[header_end..header_end + content_length].to_vec())
                .expect("publish collector body");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .expect("write collector response");
        }
    });
    (endpoint, body_rx, collector)
}

#[cfg(all(feature = "metrics", feature = "test-internals"))]
fn lab_owned_metrics_bytes(seed: u64) -> Vec<Vec<u8>> {
    use asupersync::lab::{LabConfig, LabRuntime};
    use asupersync::observability::{
        MetricsProvider, OutcomeKind, OwnedOtlpMetrics, OwnedOtlpMetricsConfig,
    };
    use asupersync::types::{Budget, RegionId, TaskId};
    use parking_lot::Mutex;
    use std::sync::Arc;
    use std::time::Duration;

    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(1_000));
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let metrics = Arc::new(
        OwnedOtlpMetrics::try_new(OwnedOtlpMetricsConfig::new(1_000))
            .expect("valid owned metrics config"),
    );
    let output = Arc::new(Mutex::new(None));
    let task_metrics = Arc::clone(&metrics);
    let task_output = Arc::clone(&output);
    let (task_id, _handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            let region = RegionId::new_for_test(7, 0);
            let task = TaskId::new_for_test(9, 0);
            task_metrics.task_spawned(region, task);
            task_metrics.task_completed(task, OutcomeKind::Ok, Duration::from_millis(20));
            task_metrics.scheduler_tick(4, Duration::from_micros(25));
            *task_output.lock() = Some(
                task_metrics
                    .collect(2_000, &[("service.name", "lab-replay")])
                    .expect("lab collection"),
            );
        })
        .expect("create deterministic producer task");
    runtime
        .scheduler
        .lock()
        .schedule(task_id, Budget::INFINITE.priority);
    runtime.run_until_quiescent();
    assert!(runtime.oracles.check_all(runtime.now()).is_empty());
    output.lock().take().expect("producer completed")
}

#[cfg(all(feature = "metrics", feature = "test-internals"))]
#[test]
fn owned_metrics_lab_replay_is_byte_identical() {
    assert_eq!(
        lab_owned_metrics_bytes(0x0A31),
        lab_owned_metrics_bytes(0x0A31)
    );
}

#[cfg(all(feature = "metrics", feature = "test-internals"))]
fn lab_owned_trace_bytes(seed: u64) -> Vec<Vec<u8>> {
    use asupersync::lab::{LabConfig, LabRuntime};
    use asupersync::observability::{
        OtlpTraceEventInput, OtlpTraceSpanInput, OtlpTraceStatus, OwnedOtlpStatusCode,
        OwnedOtlpTraces,
    };
    use asupersync::types::Budget;
    use parking_lot::Mutex;
    use std::sync::Arc;

    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(1_000));
    let root_region = runtime.state.create_root_region(Budget::INFINITE);
    let output = Arc::new(Mutex::new(None));
    let task_output = Arc::clone(&output);
    let (task_id, _handle) = runtime
        .state
        .create_task(root_region, Budget::INFINITE, async move {
            let trace_id = [0x31; 16];
            let root_id = [0x41; 8];
            let child_id = [0x42; 8];
            let events = [OtlpTraceEventInput::new(200, "cancel-requested")];
            let root = OtlpTraceSpanInput::new(trace_id, root_id, "region.root", 100, 500);
            let child = OtlpTraceSpanInput::new(trace_id, child_id, "task.cancelled", 150, 400)
                .with_parent_span_id(root_id)
                .with_events(&events)
                .with_status(OtlpTraceStatus::new(
                    OwnedOtlpStatusCode::Error,
                    "cancelled",
                ));
            *task_output.lock() = Some(
                OwnedOtlpTraces::try_new(Default::default())
                    .expect("valid owned trace mapper")
                    .collect(&[child, root], &[("service.name", "lab-trace-replay")])
                    .expect("lab trace collection")
                    .into_requests(),
            );
        })
        .expect("create deterministic trace producer task");
    runtime
        .scheduler
        .lock()
        .schedule(task_id, Budget::INFINITE.priority);
    runtime.run_until_quiescent();
    assert!(runtime.oracles.check_all(runtime.now()).is_empty());
    output.lock().take().expect("trace producer completed")
}

#[cfg(all(feature = "metrics", feature = "test-internals"))]
#[test]
fn owned_traces_lab_replay_is_byte_identical() {
    assert_eq!(lab_owned_trace_bytes(0x0A41), lab_owned_trace_bytes(0x0A41));
}

#[cfg(all(feature = "metrics", feature = "test-internals"))]
#[test]
fn owned_traces_loopback_http_wire_smoke_decodes_request() {
    use asupersync::cx::Cx;
    use asupersync::observability::{
        OtlpHttpExporter, OtlpTraceEventInput, OtlpTraceSpanInput, OtlpTraceStatus,
        OwnedOtlpStatusCode, OwnedOtlpTraces,
    };
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use prost::Message;

    let (endpoint, body_rx, collector) = loopback_otlp_capture("/v1/traces", 1);
    let trace_id = [0x51; 16];
    let root_id = [0x61; 8];
    let child_id = [0x62; 8];
    let events = [OtlpTraceEventInput::new(250, "cancel-requested")];
    let root = OtlpTraceSpanInput::new(trace_id, root_id, "region.root", 100, 500);
    let child = OtlpTraceSpanInput::new(trace_id, child_id, "task.cancelled", 200, 400)
        .with_parent_span_id(root_id)
        .with_events(&events)
        .with_status(OtlpTraceStatus::new(
            OwnedOtlpStatusCode::Error,
            "parent cancelled",
        ));
    let traces = OwnedOtlpTraces::try_new(Default::default()).expect("valid trace mapper");
    let exporter = OtlpHttpExporter::try_new(endpoint).expect("valid trace endpoint");
    asupersync::test_utils::run_test(|| async {
        let cx = Cx::current().expect("native test runtime installs Cx");
        exporter
            .send_owned_traces(&cx, &traces, &[child, root])
            .await
            .expect("loopback collector accepts owned traces");
    });

    collector.join().expect("collector thread");
    let body = body_rx.recv().expect("trace collector body");
    let request = ExportTraceServiceRequest::decode(body.as_slice()).expect("generated decode");
    let spans = &request.resource_spans[0].scope_spans[0].spans;
    assert_eq!(
        spans
            .iter()
            .map(|span| span.name.as_str())
            .collect::<Vec<_>>(),
        ["region.root", "task.cancelled"]
    );
    assert!(spans[0].parent_span_id.is_empty());
    assert_eq!(spans[1].parent_span_id, root_id);
    assert_eq!(spans[1].events[0].name, "cancel-requested");
    assert_eq!(spans[1].status.as_ref().expect("status").code, 2);
    assert_eq!(
        spans[1].status.as_ref().expect("status").message,
        "parent cancelled"
    );
}

#[cfg(all(feature = "metrics", feature = "test-internals"))]
#[test]
fn owned_logs_map_full_body_union_context_and_stable_batches() {
    use asupersync::observability::{
        LogLevel, OtlpLogBody, OtlpLogKeyValueInput, OtlpLogRecordInput, OwnedOtlpLogConfig,
        OwnedOtlpLogs,
    };
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::common::v1::any_value::Value;
    use prost::Message;

    let structured = [
        OtlpLogKeyValueInput::string("z-last", "tail"),
        OtlpLogKeyValueInput::new("a-first", OtlpLogBody::Int(7)),
    ];
    let body = [
        OtlpLogBody::String("message"),
        OtlpLogBody::Bool(true),
        OtlpLogBody::Int(-7),
        OtlpLogBody::Double(2.5),
        OtlpLogBody::Bytes(&[0, 0xff]),
        OtlpLogBody::KeyValueList(&structured),
    ];
    let attributes = [
        OtlpLogKeyValueInput::string("z-key", "z-value"),
        OtlpLogKeyValueInput::new("a-key", OtlpLogBody::Bool(false)),
    ];
    let resource = [
        OtlpLogKeyValueInput::string("service.name", "owned-logs"),
        OtlpLogKeyValueInput::string("deployment.environment", "test"),
    ];
    let trace_id = [0x31; 16];
    let span_id = [0x41; 8];
    let records = [
        OtlpLogRecordInput::new(LogLevel::Error, OtlpLogBody::Array(&body), 100)
            .with_observed_time_unix_nano(120)
            .with_attributes(&attributes)
            .with_dropped_attributes_count(3)
            .with_trace_context(&trace_id, &span_id, 1)
            .with_event_name("request.failed"),
        OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::Absent, 200),
        OtlpLogRecordInput::new(LogLevel::Debug, OtlpLogBody::String(""), 300),
    ];
    let mapper = OwnedOtlpLogs::try_new(
        OwnedOtlpLogConfig::new()
            .with_max_records_per_request(1)
            .with_scope("asupersync.logs.test", "1"),
    )
    .expect("valid owned logs mapper");

    let first = mapper
        .collect(&records, &resource)
        .expect("strict logs map");
    let second = mapper
        .collect(&records, &resource)
        .expect("deterministic repeat map");
    assert_eq!(first, second);
    assert_eq!(first.record_count(), 3);
    assert_eq!(first.producer_dropped_attributes(), 3);
    assert_eq!(first.requests().len(), 3);

    let request = ExportLogsServiceRequest::decode(first.requests()[0].as_slice())
        .expect("generated OTLP logs decode");
    assert_eq!(
        request.encode_to_vec(),
        first.requests()[0],
        "the crate-owned encoder must match the reference prost re-encoding"
    );
    let resource_logs = &request.resource_logs[0];
    assert_eq!(
        resource_logs
            .resource
            .as_ref()
            .expect("resource")
            .attributes
            .iter()
            .map(|attribute| attribute.key.as_str())
            .collect::<Vec<_>>(),
        ["deployment.environment", "service.name"]
    );
    let scope_logs = &resource_logs.scope_logs[0];
    let scope = scope_logs.scope.as_ref().expect("scope");
    assert_eq!(scope.name, "asupersync.logs.test");
    assert_eq!(scope.version, "1");
    let record = &scope_logs.log_records[0];
    assert_eq!(record.time_unix_nano, 100);
    assert_eq!(record.observed_time_unix_nano, 120);
    assert_eq!(record.severity_number, 17);
    assert_eq!(record.severity_text, "ERROR");
    assert_eq!(record.dropped_attributes_count, 3);
    assert_eq!(record.trace_id, trace_id);
    assert_eq!(record.span_id, span_id);
    assert_eq!(record.flags, 1);
    assert_eq!(record.event_name, "request.failed");
    assert_eq!(
        record
            .attributes
            .iter()
            .map(|attribute| attribute.key.as_str())
            .collect::<Vec<_>>(),
        ["a-key", "z-key"]
    );
    let Value::ArrayValue(array) = record
        .body
        .as_ref()
        .and_then(|body| body.value.as_ref())
        .expect("array body")
    else {
        panic!("body must retain the OTLP array variant");
    };
    assert!(
        matches!(array.values[0].value, Some(Value::StringValue(ref value)) if value == "message")
    );
    assert!(matches!(
        array.values[1].value,
        Some(Value::BoolValue(true))
    ));
    assert!(matches!(array.values[2].value, Some(Value::IntValue(-7))));
    assert!(matches!(array.values[3].value, Some(Value::DoubleValue(value)) if value == 2.5));
    assert!(
        matches!(array.values[4].value, Some(Value::BytesValue(ref value)) if value == &[0, 0xff])
    );
    let Some(Value::KvlistValue(map)) = array.values[5].value.as_ref() else {
        panic!("structured body must retain the OTLP key/value-list variant");
    };
    assert_eq!(
        map.values
            .iter()
            .map(|attribute| attribute.key.as_str())
            .collect::<Vec<_>>(),
        ["a-first", "z-last"]
    );

    let request = ExportLogsServiceRequest::decode(first.requests()[1].as_slice())
        .expect("decode absent-body batch");
    assert_eq!(request.encode_to_vec(), first.requests()[1]);
    assert!(
        request.resource_logs[0].scope_logs[0].log_records[0]
            .body
            .is_none()
    );

    let request = ExportLogsServiceRequest::decode(first.requests()[2].as_slice())
        .expect("decode empty-string-body batch");
    assert_eq!(request.encode_to_vec(), first.requests()[2]);
    assert!(matches!(
        request.resource_logs[0].scope_logs[0].log_records[0]
            .body
            .as_ref()
            .and_then(|body| body.value.as_ref()),
        Some(Value::StringValue(value)) if value.is_empty()
    ));
}

#[cfg(all(feature = "metrics", feature = "test-internals"))]
#[test]
fn owned_logs_preserve_all_five_asupersync_severity_levels() {
    use asupersync::observability::{LogLevel, OtlpLogBody, OtlpLogRecordInput, OwnedOtlpLogs};
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use prost::Message;

    let records = [
        OtlpLogRecordInput::new(LogLevel::Trace, OtlpLogBody::String("trace"), 1),
        OtlpLogRecordInput::new(LogLevel::Debug, OtlpLogBody::String("debug"), 2),
        OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::String("info"), 3),
        OtlpLogRecordInput::new(LogLevel::Warn, OtlpLogBody::String("warn"), 4),
        OtlpLogRecordInput::new(LogLevel::Error, OtlpLogBody::String("error"), 5),
    ];
    let collection = OwnedOtlpLogs::try_new(Default::default())
        .expect("valid mapper")
        .collect(&records, &[])
        .expect("severity map");
    let request = ExportLogsServiceRequest::decode(collection.requests()[0].as_slice())
        .expect("generated decode");
    let records = &request.resource_logs[0].scope_logs[0].log_records;
    assert_eq!(
        records
            .iter()
            .map(|record| (record.severity_number, record.severity_text.as_str()))
            .collect::<Vec<_>>(),
        [
            (1, "TRACE"),
            (5, "DEBUG"),
            (9, "INFO"),
            (13, "WARN"),
            (17, "ERROR"),
        ]
    );
}

#[cfg(all(feature = "metrics", feature = "test-internals"))]
#[test]
fn owned_logs_fail_closed_before_encoding_invalid_input() {
    use asupersync::observability::{
        LogLevel, OtlpLogBody, OtlpLogKeyValueInput, OtlpLogRecord, OtlpLogRecordInput,
        OwnedOtlpLogConfig, OwnedOtlpLogError, OwnedOtlpLogs,
    };

    let mapper = OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new()).expect("valid mapper");
    let duplicate_attributes = [
        OtlpLogKeyValueInput::string("duplicate", "one"),
        OtlpLogKeyValueInput::string("duplicate", "two"),
    ];
    let duplicate = OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::String("body"), 1)
        .with_attributes(&duplicate_attributes);
    assert_eq!(
        mapper.collect(&[duplicate], &[]),
        Err(OwnedOtlpLogError::InvalidAttributes)
    );

    let invalid_number = OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::Double(f64::NAN), 1);
    assert_eq!(
        mapper.collect(&[invalid_number], &[]),
        Err(OwnedOtlpLogError::InvalidNumericValue)
    );

    let nested_value = [OtlpLogKeyValueInput::string("child", "value")];
    let nested =
        OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::KeyValueList(&nested_value), 1);
    let shallow = OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new().with_max_body_depth(1))
        .expect("valid shallow mapper");
    assert_eq!(
        shallow.collect(&[nested], &[]),
        Err(OwnedOtlpLogError::InvalidBody),
        "structured bodies must not reset recursive depth validation"
    );

    let two_records = [
        OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::String("one"), 1),
        OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::String("two"), 2),
    ];
    let one_record = OwnedOtlpLogs::try_new(
        OwnedOtlpLogConfig::new()
            .with_max_records_per_collection(1)
            .with_max_records_per_request(1),
    )
    .expect("valid one-record mapper");
    assert_eq!(
        one_record.collect(&two_records, &[]),
        Err(OwnedOtlpLogError::LimitExceeded)
    );

    let two_values = [OtlpLogBody::Int(1), OtlpLogBody::Int(2)];
    let wide_body = OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::Array(&two_values), 1);
    let one_item = OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new().with_max_body_items(1))
        .expect("valid one-item mapper");
    assert_eq!(
        one_item.collect(&[wide_body], &[]),
        Err(OwnedOtlpLogError::InvalidBody)
    );

    let leaf_values = [OtlpLogBody::Int(1); 128];
    let branch = OtlpLogBody::Array(&leaf_values);
    let oversized_tree = [branch; 33];
    let oversized_tree =
        OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::Array(&oversized_tree), 1);
    assert_eq!(
        mapper.collect(&[oversized_tree], &[]),
        Err(OwnedOtlpLogError::LimitExceeded),
        "recursive validation must stop at the aggregate node envelope"
    );

    let two_attributes = [
        OtlpLogKeyValueInput::string("one", "1"),
        OtlpLogKeyValueInput::string("two", "2"),
    ];
    let attributed = OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::String("body"), 1)
        .with_attributes(&two_attributes);
    let one_attribute =
        OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new().with_max_attributes_per_entity(1))
            .expect("valid one-attribute mapper");
    assert_eq!(
        one_attribute.collect(&[attributed], &[]),
        Err(OwnedOtlpLogError::LimitExceeded)
    );

    let owned_byte_limit =
        OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new().with_max_owned_bytes(1))
            .expect("valid one-byte mapper");
    let two_bytes = OtlpLogRecordInput::new(LogLevel::Info, OtlpLogBody::String("xx"), 1);
    assert_eq!(
        owned_byte_limit.collect(&[two_bytes], &[]),
        Err(OwnedOtlpLogError::LimitExceeded)
    );

    let request_byte_limit =
        OwnedOtlpLogs::try_new(OwnedOtlpLogConfig::new().with_max_request_bytes(1))
            .expect("valid one-byte request mapper");
    assert_eq!(
        request_byte_limit.collect(&[two_bytes], &[]),
        Err(OwnedOtlpLogError::WireEnvelopeExceeded)
    );

    let mut malformed_context = OtlpLogRecord::new(LogLevel::Info, "body", 1);
    malformed_context.trace_id = vec![1; 16];
    malformed_context.flags = 0x100;
    let malformed_context = OtlpLogRecordInput::from_legacy_record(&malformed_context);
    assert_eq!(
        mapper.collect(&[malformed_context], &[]),
        Err(OwnedOtlpLogError::InvalidIdentifier)
    );

    let mut flags_without_context = OtlpLogRecord::new(LogLevel::Info, "body", 1);
    flags_without_context.flags = 1;
    let flags_without_context = OtlpLogRecordInput::from_legacy_record(&flags_without_context);
    assert_eq!(
        mapper.collect(&[flags_without_context], &[]),
        Err(OwnedOtlpLogError::InvalidIdentifier)
    );

    let zero_trace_id = [0; 16];
    let nonzero_span_id = [1; 8];
    let zero_trace_context = OtlpLogRecordInput::new(
        LogLevel::Info,
        OtlpLogBody::String("body"),
        1,
    )
    .with_trace_context(&zero_trace_id, &nonzero_span_id, 1);
    assert_eq!(
        mapper.collect(&[zero_trace_context], &[]),
        Err(OwnedOtlpLogError::InvalidIdentifier)
    );
}

#[cfg(all(feature = "metrics", feature = "test-internals"))]
fn lab_owned_logs_bytes(seed: u64) -> Vec<Vec<u8>> {
    use asupersync::lab::{LabConfig, LabRuntime};
    use asupersync::observability::{
        LogLevel, OtlpLogBody, OtlpLogKeyValueInput, OtlpLogRecordInput, OwnedOtlpLogs,
    };
    use asupersync::types::Budget;
    use parking_lot::Mutex;
    use std::sync::Arc;

    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(1_000));
    let root_region = runtime.state.create_root_region(Budget::INFINITE);
    let output = Arc::new(Mutex::new(None));
    let task_output = Arc::clone(&output);
    let (task_id, _handle) = runtime
        .state
        .create_task(root_region, Budget::INFINITE, async move {
            let attributes = [OtlpLogKeyValueInput::new("attempt", OtlpLogBody::Int(2))];
            let record = OtlpLogRecordInput::new(
                LogLevel::Warn,
                OtlpLogBody::String("retry scheduled"),
                500,
            )
            .with_observed_time_unix_nano(550)
            .with_attributes(&attributes);
            *task_output.lock() = Some(
                OwnedOtlpLogs::try_new(Default::default())
                    .expect("valid mapper")
                    .collect(&[record], &[])
                    .expect("lab logs collection")
                    .into_requests(),
            );
        })
        .expect("create deterministic logs producer task");
    runtime
        .scheduler
        .lock()
        .schedule(task_id, Budget::INFINITE.priority);
    runtime.run_until_quiescent();
    assert!(runtime.oracles.check_all(runtime.now()).is_empty());
    output.lock().take().expect("logs producer completed")
}

#[cfg(all(feature = "metrics", feature = "test-internals"))]
#[test]
fn owned_logs_lab_replay_is_byte_identical() {
    assert_eq!(lab_owned_logs_bytes(0x0A51), lab_owned_logs_bytes(0x0A51));
}

#[cfg(all(feature = "metrics", feature = "test-internals"))]
#[test]
fn owned_logs_loopback_http_wire_smoke_decodes_request() {
    use asupersync::cx::Cx;
    use asupersync::observability::{
        LogLevel, OtlpHttpConfigBuilder, OtlpHttpExporter, OtlpLogBody, OtlpLogRecordInput,
        OwnedOtlpLogs,
    };
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use prost::Message;

    let (endpoint, body_rx, collector) = loopback_otlp_capture("/v1/logs", 1);
    let exporter = OtlpHttpExporter::from_config(
        OtlpHttpConfigBuilder::new(endpoint)
            .with_resource_attribute("service.name", "logs-loopback")
            .build()
            .expect("valid logs endpoint"),
    );
    let logs = OwnedOtlpLogs::try_new(Default::default()).expect("valid logs mapper");
    let record = OtlpLogRecordInput::new(
        LogLevel::Warn,
        OtlpLogBody::String("shutdown requested"),
        900,
    );
    asupersync::test_utils::run_test(|| async {
        let cx = Cx::current().expect("native test runtime installs Cx");
        exporter
            .send_owned_logs(&cx, &logs, &[record])
            .await
            .expect("loopback collector accepts owned logs");
    });

    collector.join().expect("collector thread");
    let body = body_rx.recv().expect("logs collector body");
    let request = ExportLogsServiceRequest::decode(body.as_slice()).expect("generated decode");
    let resource_logs = &request.resource_logs[0];
    assert!(
        resource_logs
            .resource
            .as_ref()
            .expect("resource")
            .attributes
            .iter()
            .any(|attribute| attribute.key == "service.name")
    );
    let record = &resource_logs.scope_logs[0].log_records[0];
    assert_eq!(record.time_unix_nano, 900);
    assert_eq!(record.severity_text, "WARN");
}

#[cfg(all(feature = "metrics", feature = "test-internals"))]
#[test]
fn owned_metrics_loopback_http_wire_smoke_decodes_request() {
    use asupersync::cx::Cx;
    use asupersync::observability::{
        MetricsProvider, OtlpHttpExporter, OutcomeKind, OwnedOtlpMetrics, OwnedOtlpMetricsConfig,
    };
    use asupersync::types::{RegionId, TaskId};
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use prost::Message;
    use std::time::Duration;

    let (endpoint, body_rx, collector) = loopback_otlp_capture("/v1/metrics", 2);

    let metrics = OwnedOtlpMetrics::try_new(
        OwnedOtlpMetricsConfig::new(1_000).with_max_cardinality_per_metric(1),
    )
    .expect("valid owned metrics config");
    let region = RegionId::new_for_test(1, 0);
    let task = TaskId::new_for_test(2, 0);
    metrics.task_spawned(region, task);
    metrics.task_completed(task, OutcomeKind::Ok, Duration::from_millis(12));
    metrics.task_spawned(region, task);
    metrics.task_completed(task, OutcomeKind::Err, Duration::from_millis(15));
    assert_eq!(metrics.rejected_updates(), 2);
    let exporter = OtlpHttpExporter::try_new(endpoint).expect("valid loopback exporter");
    asupersync::test_utils::run_test(|| async {
        let cx = Cx::current().expect("native test runtime installs Cx");
        exporter
            .send_owned_metrics(&cx, &metrics, 2_000)
            .await
            .expect("collector accepts owned metrics");
        metrics.reset(3_000).expect("rotate accumulation epoch");
        metrics.task_spawned(region, task);
        exporter
            .send_owned_metrics(&cx, &metrics, 4_000)
            .await
            .expect("collector accepts reset epoch");
    });

    collector.join().expect("collector thread");
    let first_body = body_rx.recv().expect("first collector body");
    let second_body = body_rx.recv().expect("second collector body");
    let first =
        ExportMetricsServiceRequest::decode(first_body.as_slice()).expect("generated decode");
    let resource = &first.resource_metrics[0];
    let scope = &resource.scope_metrics[0];
    let spawned = scope
        .metrics
        .iter()
        .find(|metric| metric.name == "asupersync.tasks.spawned")
        .expect("spawned metric reached collector");
    let sum = spawned.data.as_ref().and_then(|data| match data {
        opentelemetry_proto::tonic::metrics::v1::metric::Data::Sum(sum) => Some(sum),
        _ => None,
    });
    let sum = sum.expect("spawned maps to Sum");
    assert!(sum.is_monotonic);
    assert_eq!(sum.aggregation_temporality, 2);
    assert_eq!(sum.data_points[0].start_time_unix_nano, 1_000);
    assert_eq!(sum.data_points[0].time_unix_nano, 2_000);
    assert_eq!(
        sum.data_points[0].value,
        Some(opentelemetry_proto::tonic::metrics::v1::number_data_point::Value::AsInt(2))
    );

    let active = scope
        .metrics
        .iter()
        .find(|metric| metric.name == "asupersync.tasks.active")
        .expect("active gauge reached collector");
    assert!(matches!(
        active.data,
        Some(opentelemetry_proto::tonic::metrics::v1::metric::Data::Gauge(_))
    ));
    let duration = scope
        .metrics
        .iter()
        .find(|metric| metric.name == "asupersync.tasks.duration")
        .expect("duration histogram reached collector");
    let histogram = duration.data.as_ref().and_then(|data| match data {
        opentelemetry_proto::tonic::metrics::v1::metric::Data::Histogram(histogram) => {
            Some(histogram)
        }
        _ => None,
    });
    let histogram = histogram.expect("duration maps to Histogram");
    assert_eq!(histogram.data_points.len(), 1);
    assert_eq!(histogram.data_points[0].attributes[0].key, "outcome");
    assert_eq!(
        histogram.data_points[0].attributes[0]
            .value
            .as_ref()
            .and_then(|value| value.value.as_ref()),
        Some(
            &opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue("ok".to_owned())
        ),
        "the second outcome stream must be omitted at the cardinality boundary"
    );
    assert_eq!(histogram.data_points[0].count, 1);

    let second =
        ExportMetricsServiceRequest::decode(second_body.as_slice()).expect("decode reset request");
    let reset_spawned = second.resource_metrics[0].scope_metrics[0]
        .metrics
        .iter()
        .find(|metric| metric.name == "asupersync.tasks.spawned")
        .expect("reset spawned metric reached collector");
    let reset_sum = reset_spawned.data.as_ref().and_then(|data| match data {
        opentelemetry_proto::tonic::metrics::v1::metric::Data::Sum(sum) => Some(sum),
        _ => None,
    });
    let reset_sum = reset_sum.expect("reset spawned maps to Sum");
    assert_eq!(reset_sum.data_points[0].start_time_unix_nano, 3_000);
    assert_eq!(reset_sum.data_points[0].time_unix_nano, 4_000);
    assert_eq!(
        reset_sum.data_points[0].value,
        Some(opentelemetry_proto::tonic::metrics::v1::number_data_point::Value::AsInt(1))
    );
}

#[cfg(all(
    feature = "metrics",
    feature = "test-internals",
    target_os = "linux",
    target_arch = "x86_64"
))]
#[test]
#[ignore = "real-service E2E downloads the pinned official OpenTelemetry Collector distribution"]
fn owned_metrics_external_otel_collector_accepts_and_exports_request() {
    use asupersync::cx::Cx;
    use asupersync::observability::otel::PrivacyConfig;
    use asupersync::observability::{
        LogEntry, MetricsProvider, OtlpHttpExporter, OtlpLogRecord, OtlpLogRecordInput,
        OtlpTraceEventInput, OtlpTraceSpanInput, OtlpTraceStatus, OutcomeKind, OwnedOtlpLogs,
        OwnedOtlpMetrics, OwnedOtlpMetricsConfig, OwnedOtlpStatusCode, OwnedOtlpTraces,
    };
    use asupersync::types::{RegionId, TaskId, Time};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const COLLECTOR_VERSION: &str = "0.157.0";
    const COLLECTOR_URL: &str = "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.157.0/otelcol-contrib_0.157.0_linux_amd64.tar.gz";
    const COLLECTOR_SHA256: &str =
        "d33177515a244a2393f03ffd66ab3e68a8fc11a56bc145ec4d0ca2644ee95504";

    struct CollectorGuard(Child);

    impl Drop for CollectorGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn sha256_hex(path: &Path) -> String {
        let bytes = fs::read(path).expect("read pinned collector archive");
        let digest = Sha256::digest(bytes);
        let mut hex = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            write!(&mut hex, "{byte:02x}").expect("write digest");
        }
        hex
    }

    fn wait_for_collector(address: SocketAddr, collector: &mut Child) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
                return;
            }
            if let Some(status) = collector.try_wait().expect("poll collector process") {
                panic!("OpenTelemetry Collector exited before readiness: {status}");
            }
            assert!(
                Instant::now() < deadline,
                "OpenTelemetry Collector did not become ready within 15 seconds"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    let fixture_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let work_dir = fixture_root.join(format!("external-fixtures/otelcol-{COLLECTOR_VERSION}"));
    fs::create_dir_all(&work_dir).expect("create collector work directory");
    let archive = work_dir.join("otelcol-contrib.tar.gz");
    let collector_binary = work_dir.join("otelcol-contrib");
    if !archive.is_file() || sha256_hex(&archive) != COLLECTOR_SHA256 {
        let status = Command::new("curl")
            .args(["--fail", "--location", "--silent", "--show-error"])
            .arg("--output")
            .arg(&archive)
            .arg(COLLECTOR_URL)
            .status()
            .expect("launch curl for pinned collector archive");
        assert!(status.success(), "collector download failed: {status}");
    }
    assert_eq!(
        sha256_hex(&archive),
        COLLECTOR_SHA256,
        "pinned collector archive digest drifted"
    );
    let status = Command::new("tar")
        .args(["-xzf"])
        .arg(&archive)
        .arg("-C")
        .arg(&work_dir)
        .status()
        .expect("extract pinned collector archive");
    assert!(status.success(), "collector extraction failed: {status}");

    let port_probe = TcpListener::bind("127.0.0.1:0").expect("reserve collector port");
    let collector_address = port_probe.local_addr().expect("collector port");
    drop(port_probe);
    let run_nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    let run_id = format!("{}-{run_nonce}", std::process::id());
    let output_path = work_dir.join(format!("signals-{run_id}.jsonl"));
    let config_path = work_dir.join(format!("collector-{run_id}.yaml"));
    let config = format!(
        "receivers:\n  otlp:\n    protocols:\n      http:\n        endpoint: {collector_address}\nexporters:\n  file:\n    path: {}\n    flush_interval: 100ms\nservice:\n  telemetry:\n    logs:\n      level: warn\n  pipelines:\n    metrics:\n      receivers: [otlp]\n      exporters: [file]\n    traces:\n      receivers: [otlp]\n      exporters: [file]\n    logs:\n      receivers: [otlp]\n      exporters: [file]\n",
        output_path.display()
    );
    fs::write(&config_path, config).expect("write collector config");
    let child = Command::new(&collector_binary)
        .arg("--config")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn pinned OpenTelemetry Collector");
    let mut collector = CollectorGuard(child);
    wait_for_collector(collector_address, &mut collector.0);

    let metrics = OwnedOtlpMetrics::try_new(
        OwnedOtlpMetricsConfig::new(1_000).with_max_cardinality_per_metric(1),
    )
    .expect("valid owned metrics config");
    let region = RegionId::new_for_test(1, 0);
    let task = TaskId::new_for_test(2, 0);
    metrics.task_spawned(region, task);
    metrics.task_completed(task, OutcomeKind::Ok, Duration::from_millis(12));
    metrics.task_spawned(region, task);
    metrics.task_completed(task, OutcomeKind::Err, Duration::from_millis(15));
    assert_eq!(metrics.rejected_updates(), 2);
    let metrics_exporter =
        OtlpHttpExporter::try_new(format!("http://{collector_address}/v1/metrics"))
            .expect("valid collector endpoint");
    let traces_exporter =
        OtlpHttpExporter::try_new(format!("http://{collector_address}/v1/traces"))
            .expect("valid trace collector endpoint");
    let logs_exporter = OtlpHttpExporter::try_new(format!("http://{collector_address}/v1/logs"))
        .expect("valid logs collector endpoint");
    let traces = OwnedOtlpTraces::try_new(Default::default()).expect("valid trace mapper");
    let logs = OwnedOtlpLogs::try_new(Default::default()).expect("valid logs mapper");
    let trace_id = [0x71; 16];
    let root_id = [0x72; 8];
    let child_id = [0x73; 8];
    let events = [OtlpTraceEventInput::new(250, "cancel-requested")];
    let root_span = OtlpTraceSpanInput::new(trace_id, root_id, "region.root", 100, 500);
    let child_span = OtlpTraceSpanInput::new(trace_id, child_id, "task.cancelled", 200, 400)
        .with_parent_span_id(root_id)
        .with_events(&events)
        .with_status(OtlpTraceStatus::new(
            OwnedOtlpStatusCode::Error,
            "parent cancelled",
        ));
    let log_entry = LogEntry::error("request failed")
        .with_timestamp(Time::from_nanos(600))
        .with_target("collector-e2e")
        .with_field("request.kind", "shutdown")
        .with_field("auth.token", "must-not-reach-collector");
    let privacy = PrivacyConfig::new().with_drop_attribute("auth.token");
    let legacy_log = OtlpLogRecord::from_log_entry_with_privacy(&log_entry, 650, &privacy)
        .with_trace_context(trace_id, child_id, 1)
        .with_event_name("request.failed");
    let owned_log = OtlpLogRecordInput::from_legacy_record(&legacy_log);
    asupersync::test_utils::run_test(|| async {
        let cx = Cx::current().expect("native test runtime installs Cx");
        metrics_exporter
            .send_owned_metrics(&cx, &metrics, 2_000)
            .await
            .expect("official collector accepts owned metrics");
        metrics.reset(3_000).expect("rotate accumulation epoch");
        metrics.task_spawned(region, task);
        metrics_exporter
            .send_owned_metrics(&cx, &metrics, 4_000)
            .await
            .expect("official collector accepts reset metrics");
        traces_exporter
            .send_owned_traces(&cx, &traces, &[child_span, root_span])
            .await
            .expect("official collector accepts owned traces");
        logs_exporter
            .send_owned_logs(&cx, &logs, &[owned_log])
            .await
            .expect("official collector accepts owned logs");
    });

    let deadline = Instant::now() + Duration::from_secs(15);
    let exported = loop {
        if let Ok(text) = fs::read_to_string(&output_path)
            && text.matches("asupersync.tasks.spawned").count() >= 2
            && text.contains("task.cancelled")
            && text.contains("request failed")
        {
            break text;
        }
        assert!(
            Instant::now() < deadline,
            "official collector did not export the accepted signals within 15 seconds"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let records = exported
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("collector output must be JSON"))
        .collect::<Vec<_>>();
    assert!(
        !records.is_empty(),
        "collector must emit at least one record"
    );
    let canonical_output = serde_json::to_string(&records).expect("serialize collector output");
    assert!(canonical_output.contains("asupersync.tasks.spawned"));
    assert!(canonical_output.contains("asupersync.tasks.active"));
    assert!(canonical_output.contains("asupersync.tasks.duration"));
    assert!(canonical_output.contains("ok"));
    assert!(canonical_output.contains("service.name"));
    assert!(canonical_output.contains("asupersync"));
    assert!(canonical_output.contains("region.root"));
    assert!(canonical_output.contains("task.cancelled"));
    assert!(canonical_output.contains("cancel-requested"));
    assert!(canonical_output.contains("parent cancelled"));
    assert!(canonical_output.contains("request failed"));
    assert!(canonical_output.contains("request.failed"));
    assert!(canonical_output.contains("request.kind"));
    assert!(canonical_output.contains("shutdown"));
    assert!(!canonical_output.contains("auth.token"));
    assert!(!canonical_output.contains("must-not-reach-collector"));
}
