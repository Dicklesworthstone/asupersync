use super::*;
use crate::grpc::client::Channel;
use crate::observability::metrics::MetricsProvider;
use crate::observability::otel::{OtelMetrics, OtlpGrpcExporter, PrivacyConfig};
use crate::observability::otlp_proto::common_and_resource::AnyValueValue;
use opentelemetry::metrics::MeterProvider;
use opentelemetry::{Array, InstrumentationScope as SdkScope, KeyValue as SdkAttribute};
use opentelemetry_sdk::metrics::{
    Aggregation, Instrument, PeriodicReader, SdkMeterProvider, Stream,
};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

type MappingResult = Result<OwnedOtlpPolicyOutput<Vec<Vec<u8>>>, OtlpSdkMetricsError>;

fn channel() -> Channel {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    let mut connect = std::pin::pin!(Channel::connect("http://127.0.0.1:1"));
    let Poll::Ready(Ok(channel)) = connect
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    else {
        panic!("native channel construction performs no I/O");
    };
    channel
}

#[derive(Clone)]
struct Capture {
    config: OtlpSdkMetricsConfig,
    policy: OwnedOtlpExportPolicy,
    temporality: Temporality,
    results: Arc<Mutex<Vec<MappingResult>>>,
}

impl PushMetricExporter for Capture {
    async fn export(&self, metrics: &sdk::ResourceMetrics) -> OTelSdkResult {
        self.results
            .lock()
            .unwrap()
            .push(map_metrics(metrics, &self.policy, &self.config));
        Ok(())
    }
    fn force_flush(&self) -> OTelSdkResult {
        Ok(())
    }
    fn shutdown_with_timeout(&self, _: Duration) -> OTelSdkResult {
        Ok(())
    }
    fn temporality(&self) -> Temporality {
        self.temporality
    }
}

fn capture(
    config: OtlpSdkMetricsConfig,
    policy: OwnedOtlpExportPolicy,
    temporality: Temporality,
    record: impl FnOnce(&SdkMeterProvider),
) -> MappingResult {
    let results = Arc::new(Mutex::new(Vec::new()));
    let exporter = Capture {
        config,
        policy,
        temporality,
        results: Arc::clone(&results),
    };
    let reader = PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(3600))
        .build();
    let resource = opentelemetry_sdk::Resource::builder_empty()
        .with_schema_url(
            [
                SdkAttribute::new("service.name", "sdk-service"),
                SdkAttribute::new("resource.number", 7_i64),
            ],
            "https://example.test/resource",
        )
        .build();
    let provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader)
        .with_view(|instrument: &Instrument| {
            if instrument.name().starts_with("exp") {
                Stream::builder()
                    .with_aggregation(Aggregation::Base2ExponentialHistogram {
                        max_size: 160,
                        max_scale: 20,
                        record_min_max: true,
                    })
                    .build()
                    .ok()
            } else if instrument.name() == "renamed_empty" {
                Stream::builder().with_name("").build().ok()
            } else {
                None
            }
        })
        .build();
    record(&provider);
    provider.force_flush().unwrap();
    let result = results
        .lock()
        .unwrap()
        .first()
        .expect("SDK invoked capture exporter")
        .clone();
    provider.shutdown().unwrap();
    result
}

fn decode(bytes: &[u8]) -> ExportMetricsServiceRequest {
    ExportMetricsServiceRequest::decode_from_bytes(
        bytes,
        crate::observability::otel::otlp_request_limits(MAX_BYTES),
    )
    .unwrap()
}

fn decoded(output: &OwnedOtlpPolicyOutput<Vec<Vec<u8>>>) -> Vec<ExportMetricsServiceRequest> {
    output.output().iter().map(|bytes| decode(bytes)).collect()
}

fn all_metrics(requests: &[ExportMetricsServiceRequest]) -> Vec<&Metric> {
    requests
        .iter()
        .flat_map(|request| &request.resource_metrics)
        .flat_map(|resource| &resource.scope_metrics)
        .flat_map(|scope| &scope.metrics)
        .collect()
}

fn find_metric<'a>(requests: &'a [ExportMetricsServiceRequest], name: &str) -> &'a Metric {
    all_metrics(requests)
        .into_iter()
        .find(|metric| metric.name == name)
        .unwrap()
}

fn attribute<'a>(attributes: &'a [KeyValue], key: &str) -> &'a AnyValueValue {
    attributes
        .iter()
        .find(|attribute| attribute.key == key)
        .unwrap()
        .value
        .as_ref()
        .unwrap()
        .value
        .as_ref()
        .unwrap()
}

#[test]
fn real_sdk_all_aggregation_families_preserve_typed_metadata_and_measurements() {
    let output = capture(
        OtlpSdkMetricsConfig::new(),
        OwnedOtlpExportPolicy::new(),
        Temporality::Cumulative,
        |provider| {
            let scope = SdkScope::builder("custom-sdk-scope")
                .with_version("7")
                .with_schema_url("https://example.test/scope")
                .with_attributes([SdkAttribute::new("scope.flag", true)])
                .build();
            let meter = provider.meter_with_scope(scope);
            let attrs = [
                SdkAttribute::new("flag", true),
                SdkAttribute::new("number", 12_i64),
                SdkAttribute::new("ratio", 1.25),
                SdkAttribute::new("array", Value::Array(Array::I64(vec![2, 3]))),
            ];
            meter
                .u64_counter("counter")
                .with_description("request total")
                .with_unit("{request}")
                .build()
                .add(4, &attrs);
            meter.i64_up_down_counter("balance").build().add(-2, &attrs);
            meter.f64_counter("float.counter").build().add(2.5, &attrs);
            meter.f64_gauge("gauge").build().record(1.5, &attrs);
            meter.i64_gauge("signed.gauge").build().record(-7, &attrs);
            meter.u64_gauge("unsigned.gauge").build().record(9, &attrs);
            let histogram = meter.f64_histogram("histogram").build();
            histogram.record(1.0, &attrs);
            histogram.record(9.0, &attrs);
            meter
                .u64_histogram("integer.histogram")
                .build()
                .record(6, &attrs);
            let exponential = meter.f64_histogram("exponential").build();
            exponential.record(1.0, &attrs);
            exponential.record(32.0, &attrs);
            exponential.record(0.0, &attrs);
            meter.u64_histogram("exp.integer").build().record(4, &attrs);
        },
    )
    .unwrap();
    assert_eq!(*output.report(), OwnedOtlpPolicyReport::default());
    let requests = decoded(&output);
    assert_eq!(all_metrics(&requests).len(), 10);
    for request in &requests {
        let resource = &request.resource_metrics[0];
        assert_eq!(resource.schema_url, "https://example.test/resource");
        assert_eq!(
            attribute(
                &resource.resource.as_ref().unwrap().attributes,
                "resource.number"
            ),
            &AnyValueValue::Int(7)
        );
        let group = &resource.scope_metrics[0];
        assert_eq!(group.schema_url, "https://example.test/scope");
        let scope = group.scope.as_ref().unwrap();
        assert_eq!(scope.name, "custom-sdk-scope");
        assert_eq!(scope.version, "7");
        assert_eq!(
            attribute(&scope.attributes, "scope.flag"),
            &AnyValueValue::Bool(true)
        );
    }
    let counter = find_metric(&requests, "counter");
    assert_eq!(counter.description, "request total");
    assert_eq!(counter.unit, "{request}");
    let Some(MetricData::Sum(counter)) = &counter.data else {
        panic!("sum")
    };
    assert!(counter.is_monotonic);
    assert_eq!(
        counter.aggregation_temporality,
        AggregationTemporality::Cumulative.as_raw()
    );
    assert_eq!(
        counter.data_points[0].value,
        Some(NumberDataPointValue::Int(4))
    );
    assert_eq!(
        attribute(&counter.data_points[0].attributes, "ratio"),
        &AnyValueValue::Double(1.25)
    );
    let AnyValueValue::Array(array) = attribute(&counter.data_points[0].attributes, "array") else {
        panic!("typed array")
    };
    assert_eq!(array.values[0].value, Some(AnyValueValue::Int(2)));
    let Some(MetricData::Sum(balance)) = &find_metric(&requests, "balance").data else {
        panic!("sum")
    };
    assert!(!balance.is_monotonic);
    assert_eq!(
        balance.data_points[0].value,
        Some(NumberDataPointValue::Int(-2))
    );
    let Some(MetricData::Gauge(gauge)) = &find_metric(&requests, "gauge").data else {
        panic!("gauge")
    };
    assert_eq!(
        gauge.data_points[0].value,
        Some(NumberDataPointValue::Double(1.5))
    );
    let Some(MetricData::Histogram(histogram)) = &find_metric(&requests, "histogram").data else {
        panic!("histogram")
    };
    assert_eq!(histogram.data_points[0].count, 2);
    assert_eq!(histogram.data_points[0].sum, Some(10.0));
    assert_eq!(histogram.data_points[0].min, Some(1.0));
    assert_eq!(histogram.data_points[0].max, Some(9.0));
    assert_eq!(
        histogram.data_points[0].bucket_counts.iter().sum::<u64>(),
        2
    );
    let Some(MetricData::ExponentialHistogram(exponential)) =
        &find_metric(&requests, "exponential").data
    else {
        panic!("exponential histogram")
    };
    assert_eq!(exponential.data_points[0].count, 3);
    assert_eq!(exponential.data_points[0].sum, Some(33.0));
    assert_eq!(exponential.data_points[0].zero_count, 1);
    assert!(
        exponential.data_points[0]
            .positive
            .as_ref()
            .unwrap()
            .bucket_counts
            .iter()
            .sum::<u64>()
            == 2
    );
}

#[test]
fn typed_series_identity_preserves_distinct_numbers_booleans_strings_and_arrays() {
    let output = capture(
        OtlpSdkMetricsConfig::new(),
        OwnedOtlpExportPolicy::new(),
        Temporality::Cumulative,
        |provider| {
            let counter = provider.meter("typed").u64_counter("typed.counter").build();
            let values = [
                Value::I64(1),
                Value::I64(2),
                Value::Bool(true),
                Value::String("1".into()),
                Value::Array(Array::I64(vec![1, 2])),
                Value::Array(Array::I64(vec![1, 3])),
            ];
            for value in values {
                counter.add(1, &[SdkAttribute::new("key", value)]);
            }
        },
    )
    .unwrap();
    let requests = decoded(&output);
    let Some(MetricData::Sum(sum)) = &find_metric(&requests, "typed.counter").data else {
        panic!("sum")
    };
    assert_eq!(sum.data_points.len(), 6);
}

#[test]
fn shared_policy_filters_typed_arrays_and_preserves_sdk_scope_attributes() {
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_resource_attributes([("service.name".to_owned(), "override".to_owned())])
        .unwrap()
        .try_with_scope_attributes([("policy.attr".to_owned(), "added".to_owned())])
        .unwrap()
        .try_with_privacy(
            PrivacyConfig::new()
                .with_drop_label("secret")
                .with_pii_pattern("credential-[a-z]+"),
        )
        .unwrap();
    let output = capture(
        OtlpSdkMetricsConfig::new(),
        policy,
        Temporality::Cumulative,
        |provider| {
            let scope = SdkScope::builder("preserved")
                .with_attributes([SdkAttribute::new("existing", 7_i64)])
                .build();
            let counter = provider
                .meter_with_scope(scope)
                .u64_counter("counter")
                .build();
            counter.add(
                1,
                &[
                    SdkAttribute::new("secret", "credential-hidden"),
                    SdkAttribute::new(
                        "typed",
                        Value::Array(Array::String(vec![
                            "credential-private".into(),
                            "safe".into(),
                        ])),
                    ),
                ],
            );
        },
    )
    .unwrap();
    assert_eq!(output.report().dropped_attributes, 1);
    assert_eq!(output.report().redacted_values, 1);
    let requests = decoded(&output);
    let group = &requests[0].resource_metrics[0];
    assert_eq!(
        attribute(&group.resource.as_ref().unwrap().attributes, "service.name"),
        &AnyValueValue::String("override".to_owned())
    );
    let scope = group.scope_metrics[0].scope.as_ref().unwrap();
    assert_eq!(
        attribute(&scope.attributes, "existing"),
        &AnyValueValue::Int(7)
    );
    assert_eq!(
        attribute(&scope.attributes, "policy.attr"),
        &AnyValueValue::String("added".to_owned())
    );
    let Some(MetricData::Sum(sum)) = &find_metric(&requests, "counter").data else {
        panic!("sum")
    };
    let AnyValueValue::Array(array) = attribute(&sum.data_points[0].attributes, "typed") else {
        panic!("array")
    };
    assert_eq!(
        array.values[0].value,
        Some(AnyValueValue::String("[REDACTED]".to_owned()))
    );
    assert_eq!(
        array.values[1].value,
        Some(AnyValueValue::String("safe".to_owned()))
    );
}

#[test]
fn scope_overrides_refuse_cross_scope_series_collisions() {
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_scope("merged", "1")
        .unwrap();
    let result = capture(
        OtlpSdkMetricsConfig::new(),
        policy,
        Temporality::Cumulative,
        |provider| {
            provider
                .meter("first")
                .u64_counter("counter")
                .build()
                .add(1, &[]);
            provider
                .meter("second")
                .u64_counter("counter")
                .build()
                .add(2, &[]);
        },
    );
    assert_eq!(result.unwrap_err(), OtlpSdkMetricsError::SeriesCollision);
}

#[test]
fn label_policy_refuses_collisions_within_one_sdk_metric() {
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_privacy(PrivacyConfig::new().with_drop_label("label"))
        .unwrap();
    let result = capture(
        OtlpSdkMetricsConfig::new(),
        policy,
        Temporality::Cumulative,
        |provider| {
            let counter = provider.meter("scope").u64_counter("counter").build();
            counter.add(1, &[SdkAttribute::new("label", 1_i64)]);
            counter.add(2, &[SdkAttribute::new("label", 2_i64)]);
        },
    );
    assert_eq!(
        result.unwrap_err(),
        OtlpSdkMetricsError::Policy(OwnedOtlpPolicyError::MetricSeriesCollision)
    );
}

#[test]
fn one_sdk_metric_splits_all_points_without_loss_or_duplicate_descriptors() {
    let output = capture(
        OtlpSdkMetricsConfig::new(),
        OwnedOtlpExportPolicy::new(),
        Temporality::Cumulative,
        |provider| {
            let counter = provider.meter("split").u64_counter("many.points").build();
            for index in 0..1500 {
                counter.add(1, &[SdkAttribute::new("index", i64::from(index))]);
            }
        },
    )
    .unwrap();
    assert!(output.output().len() >= 2);
    let requests = decoded(&output);
    let mut seen = BTreeSet::new();
    let mut start_time = None;
    for request in requests {
        let metrics = &request.resource_metrics[0].scope_metrics[0].metrics;
        assert_eq!(
            metrics.len(),
            1,
            "one descriptor for a split series per request"
        );
        let Some(MetricData::Sum(sum)) = &metrics[0].data else {
            panic!("sum")
        };
        assert!(sum.data_points.len() <= POINTS_PER_METRIC_REQUEST);
        for point in &sum.data_points {
            let AnyValueValue::Int(index) = attribute(&point.attributes, "index") else {
                panic!("int")
            };
            assert!(seen.insert(*index));
            assert_eq!(point.value, Some(NumberDataPointValue::Int(1)));
            assert_eq!(
                *start_time.get_or_insert(point.start_time_unix_nano),
                point.start_time_unix_nano
            );
        }
    }
    assert_eq!(seen.len(), 1500);
}

#[test]
fn small_request_limit_splits_at_point_boundaries_before_transport() {
    let output = capture(
        OtlpSdkMetricsConfig::new().with_max_request_bytes(512),
        OwnedOtlpExportPolicy::new(),
        Temporality::Cumulative,
        |provider| {
            let counter = provider.meter("small").u64_counter("counter").build();
            for index in 0..100 {
                counter.add(1, &[SdkAttribute::new("index", i64::from(index))]);
            }
        },
    )
    .unwrap();
    assert!(output.output().iter().all(|request| request.len() <= 512));
    let requests = decoded(&output);
    assert_eq!(
        all_metrics(&requests)
            .iter()
            .map(|metric| point_count(metric))
            .sum::<usize>(),
        100
    );
}

#[test]
fn unrepresentable_unsigned_values_are_not_silently_zeroed() {
    let result = capture(
        OtlpSdkMetricsConfig::new(),
        OwnedOtlpExportPolicy::new(),
        Temporality::Cumulative,
        |provider| {
            provider
                .meter("overflow")
                .u64_counter("counter")
                .build()
                .add(u64::MAX, &[]);
        },
    );
    assert_eq!(
        result.unwrap_err(),
        OtlpSdkMetricsError::InvalidNumericValue
    );
    assert_eq!(
        u64::MAX.number(),
        Err(OtlpSdkMetricsError::InvalidNumericValue)
    );
    assert_eq!(
        (i64::MAX as u64).number(),
        Ok(NumberDataPointValue::Int(i64::MAX))
    );
}

#[test]
fn delta_input_is_explicitly_refused_and_sdk_exporter_selects_cumulative() {
    let result = capture(
        OtlpSdkMetricsConfig::new(),
        OwnedOtlpExportPolicy::new(),
        Temporality::Delta,
        |provider| {
            provider
                .meter("delta")
                .u64_counter("counter")
                .build()
                .add(1, &[]);
        },
    );
    assert_eq!(
        result.unwrap_err(),
        OtlpSdkMetricsError::UnsupportedTemporality
    );
    let queue = QueuedOtlpGrpcExporter::new(OtlpGrpcExporter::new(channel()).unwrap());
    assert_eq!(
        OtlpSdkMetricExporter::new(queue).temporality(),
        Temporality::Cumulative
    );
}

#[test]
fn complete_borrowed_collection_is_admitted_before_any_mapping_output() {
    let result = capture(
        OtlpSdkMetricsConfig::new().with_max_data_points(1),
        OwnedOtlpExportPolicy::new(),
        Temporality::Cumulative,
        |provider| {
            let counter = provider.meter("bounds").u64_counter("counter").build();
            counter.add(1, &[SdkAttribute::new("key", "one")]);
            counter.add(1, &[SdkAttribute::new("key", "two")]);
        },
    );
    assert_eq!(result.unwrap_err(), OtlpSdkMetricsError::LimitExceeded);
    let result = capture(
        OtlpSdkMetricsConfig::new(),
        OwnedOtlpExportPolicy::new(),
        Temporality::Cumulative,
        |provider| {
            let meter = provider.meter("bounds");
            meter.u64_counter("first.valid").build().add(1, &[]);
            meter
                .u64_counter("last.invalid")
                .build()
                .add(1, &[SdkAttribute::new("key", "x".repeat(4097))]);
        },
    );
    assert_eq!(result.unwrap_err(), OtlpSdkMetricsError::LimitExceeded);
}

#[test]
fn concurrent_sdk_recording_and_existing_otelmetrics_meter_injection_work() {
    let output = capture(
        OtlpSdkMetricsConfig::new(),
        OwnedOtlpExportPolicy::new(),
        Temporality::Cumulative,
        |provider| {
            let meter = provider.meter("shared-provider");
            let counter = meter.u64_counter("concurrent").build();
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let counter = counter.clone();
                    std::thread::spawn(move || {
                        for _ in 0..100 {
                            counter.add(1, &[]);
                        }
                    })
                })
                .collect();
            for handle in handles {
                handle.join().unwrap();
            }
            let runtime_metrics = OtelMetrics::new(meter);
            runtime_metrics.task_stuck_detected("worker");
        },
    )
    .unwrap();
    let requests = decoded(&output);
    let Some(MetricData::Sum(sum)) = &find_metric(&requests, "concurrent").data else {
        panic!("sum")
    };
    assert_eq!(
        sum.data_points[0].value,
        Some(NumberDataPointValue::Int(400))
    );
    let Some(MetricData::Sum(sum)) =
        &find_metric(&requests, "asupersync.task.stuck_detected_total").data
    else {
        panic!("sum")
    };
    assert_eq!(sum.data_points[0].value, Some(NumberDataPointValue::Int(1)));
}

#[test]
fn sdk_view_name_is_not_revalidated_as_an_instrument_identifier() {
    let output = capture(
        OtlpSdkMetricsConfig::new(),
        OwnedOtlpExportPolicy::new(),
        Temporality::Cumulative,
        |provider| {
            provider
                .meter("views")
                .u64_counter("renamed_empty")
                .build()
                .add(1, &[]);
        },
    )
    .unwrap();
    assert!(find_metric(&decoded(&output), "").name.is_empty());
}

#[test]
fn configuration_numeric_timestamp_and_histogram_boundaries_are_static() {
    for config in [
        OtlpSdkMetricsConfig::new().with_max_scopes(0),
        OtlpSdkMetricsConfig::new().with_max_metrics(MAX_METRICS + 1),
        OtlpSdkMetricsConfig::new().with_max_data_points(0),
        OtlpSdkMetricsConfig::new().with_max_collection_bytes(MAX_BYTES + 1),
        OtlpSdkMetricsConfig::new().with_max_request_bytes(0),
    ] {
        assert_eq!(
            config.validate(),
            Err(OtlpSdkMetricsError::InvalidConfiguration)
        );
    }
    assert_eq!(
        finite(f64::NAN),
        Err(OtlpSdkMetricsError::InvalidNumericValue)
    );
    assert_eq!(
        nanos(UNIX_EPOCH, false),
        Err(OtlpSdkMetricsError::InvalidTimestamp)
    );
    assert_eq!(
        nanos(UNIX_EPOCH - Duration::from_secs(1), true),
        Err(OtlpSdkMetricsError::InvalidTimestamp)
    );
    assert_eq!(
        times(
            Some(UNIX_EPOCH + Duration::from_secs(2)),
            UNIX_EPOCH + Duration::from_secs(1)
        ),
        Err(OtlpSdkMetricsError::InvalidTimestamp)
    );
    assert_eq!(
        preflight_histogram_values(Some(5_i64), Some(4_i64), 9_i64, 2),
        Err(OtlpSdkMetricsError::InvalidHistogram)
    );
    assert_eq!(
        preflight_histogram_values(None, None, 1.0_f64, 0),
        Err(OtlpSdkMetricsError::InvalidHistogram)
    );
}

#[test]
fn missing_managed_owner_fails_on_first_poll_without_dial_or_admission() {
    let queue = QueuedOtlpGrpcExporter::new(OtlpGrpcExporter::new(channel()).unwrap());
    let exporter = OtlpSdkMetricExporter::new(queue.clone());
    let input = sdk::ResourceMetrics::default();
    let future = exporter.export(&input);
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        std::future::Future::poll(future.as_mut(), &mut context),
        std::task::Poll::Ready(Err(_))
    ));
    assert_eq!(queue.queue_stats().queue.queued_batches, 0);
}

#[test]
fn default_empty_sdk_collection_and_diagnostics_are_value_free() {
    let empty = map_metrics(
        &sdk::ResourceMetrics::default(),
        &OwnedOtlpExportPolicy::new(),
        &OtlpSdkMetricsConfig::new(),
    )
    .unwrap();
    assert!(empty.output().is_empty());
    assert_eq!(*empty.report(), OwnedOtlpPolicyReport::default());
    let queue = QueuedOtlpGrpcExporter::new(OtlpGrpcExporter::new(channel()).unwrap());
    let secret = "credential-private";
    let exporter = OtlpSdkMetricExporter::new(queue).with_policy(
        OwnedOtlpExportPolicy::new()
            .try_with_resource_attributes([("private".to_owned(), secret.to_owned())])
            .unwrap(),
    );
    assert!(!format!("{exporter:?}").contains(secret));
    assert!(!format!("{}", OtlpSdkMetricsError::InvalidAttributes).contains(secret));
}

#[test]
fn all_admitted_sdk_scopes_share_one_request_without_losing_metadata() {
    let output = capture(
        OtlpSdkMetricsConfig::new(),
        OwnedOtlpExportPolicy::new(),
        Temporality::Cumulative,
        |provider| {
            for index in 0..128_i64 {
                let scope = SdkScope::builder(format!("scope.{index:03}"))
                    .with_version("2")
                    .with_schema_url(format!("https://example.test/scope/{index}"))
                    .with_attributes([SdkAttribute::new("scope.index", index)])
                    .build();
                provider
                    .meter_with_scope(scope)
                    .u64_counter("counter")
                    .build()
                    .add(1, &[SdkAttribute::new("point.index", index)]);
            }
        },
    )
    .unwrap();
    assert_eq!(
        output.output().len(),
        1,
        "small scopes share native RPC capacity"
    );
    let requests = decoded(&output);
    let resource = &requests[0].resource_metrics[0];
    assert_eq!(resource.schema_url, "https://example.test/resource");
    assert_eq!(resource.scope_metrics.len(), 128);
    let mut seen = BTreeSet::new();
    for group in &resource.scope_metrics {
        let scope = group.scope.as_ref().unwrap();
        let AnyValueValue::Int(index) = attribute(&scope.attributes, "scope.index") else {
            panic!("typed scope index")
        };
        assert!(seen.insert(*index));
        assert_eq!(scope.name, format!("scope.{index:03}"));
        assert_eq!(scope.version, "2");
        assert_eq!(
            group.schema_url,
            format!("https://example.test/scope/{index}")
        );
        assert_eq!(group.metrics.len(), 1);
        let Some(MetricData::Sum(sum)) = &group.metrics[0].data else {
            panic!("sum")
        };
        assert_eq!(sum.data_points.len(), 1);
        assert_eq!(
            attribute(&sum.data_points[0].attributes, "point.index"),
            &AnyValueValue::Int(*index)
        );
        assert_eq!(sum.data_points[0].value, Some(NumberDataPointValue::Int(1)));
    }
    assert_eq!(seen.len(), 128);
}

#[test]
fn packed_sdk_scopes_roll_requests_at_the_shared_byte_bound() {
    let output = capture(
        OtlpSdkMetricsConfig::new().with_max_request_bytes(512),
        OwnedOtlpExportPolicy::new(),
        Temporality::Cumulative,
        |provider| {
            for index in 0..20_i64 {
                provider
                    .meter(format!("scope.{index:02}"))
                    .u64_counter("counter")
                    .build()
                    .add(1, &[SdkAttribute::new("index", index)]);
            }
        },
    )
    .unwrap();
    assert!(output.output().len() > 1);
    assert!(
        output.output().len() < 20,
        "small groups are actually packed"
    );
    assert!(output.output().iter().all(|bytes| bytes.len() <= 512));
    let requests = decoded(&output);
    let mut seen = BTreeSet::new();
    for request in &requests {
        for group in &request.resource_metrics[0].scope_metrics {
            let Some(MetricData::Sum(sum)) = &group.metrics[0].data else {
                panic!("sum")
            };
            let AnyValueValue::Int(index) = attribute(&sum.data_points[0].attributes, "index")
            else {
                panic!("typed index")
            };
            assert!(seen.insert(*index));
            assert_eq!(
                group.scope.as_ref().unwrap().name,
                format!("scope.{index:02}")
            );
        }
    }
    assert_eq!(seen.len(), 20, "every scope survives request rollover");
}

#[test]
fn policy_collapsed_scopes_do_not_duplicate_metric_descriptors_in_one_request() {
    let policy = OwnedOtlpExportPolicy::new()
        .try_with_scope("merged", "1")
        .unwrap();
    let output = capture(
        OtlpSdkMetricsConfig::new(),
        policy,
        Temporality::Cumulative,
        |provider| {
            for index in 0..4_i64 {
                provider
                    .meter(format!("source.{index}"))
                    .u64_counter("counter")
                    .build()
                    .add(1, &[SdkAttribute::new("index", index)]);
            }
        },
    )
    .unwrap();
    let requests = decoded(&output);
    let mut seen = BTreeSet::new();
    for request in &requests {
        let resource = &request.resource_metrics[0];
        assert_eq!(resource.scope_metrics.len(), 1);
        let scope = &resource.scope_metrics[0];
        assert_eq!(scope.scope.as_ref().unwrap().name, "merged");
        assert_eq!(scope.metrics.len(), 1);
        let Some(MetricData::Sum(sum)) = &scope.metrics[0].data else {
            panic!("sum")
        };
        let AnyValueValue::Int(index) = attribute(&sum.data_points[0].attributes, "index") else {
            panic!("typed index")
        };
        assert!(seen.insert(*index));
    }
    assert_eq!(seen.len(), 4, "disjoint post-policy series remain distinct");
}
