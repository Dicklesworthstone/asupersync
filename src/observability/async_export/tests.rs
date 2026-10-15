use super::*;

fn batch(snapshot: &MetricsSnapshot) -> MetricsExportBatch<'_> {
    MetricsExportBatch::new(snapshot, 1000, 2000).expect("valid explicit epoch")
}

fn decode(bytes: &[u8]) -> ExportMetricsServiceRequest {
    ExportMetricsServiceRequest::decode_from_bytes(
        bytes,
        ProtobufWireLimits::for_message_size(MAX_REQUEST_BYTES),
    )
    .expect("owned OTLP decoder accepts the encoded request")
}

#[test]
fn snapshot_preserves_counter_gauge_histogram_resource_and_time_semantics() {
    let mut snapshot = MetricsSnapshot::new();
    snapshot.add_counter("requests", vec![("route".into(), "/".into())], 42);
    snapshot.add_gauge("active", Vec::new(), -7);
    snapshot.add_histogram("duration", Vec::new(), 3, 1.25);
    let resource = vec![("service.name".into(), "test-service".into())];
    let bytes = encode_snapshot(batch(&snapshot), &resource).unwrap().unwrap();
    let decoded = decode(&bytes);
    let resource = &decoded.resource_metrics[0];
    assert_eq!(resource.resource.as_ref().unwrap().attributes[0].key, "service.name");
    let metrics = &resource.scope_metrics[0].metrics;
    assert_eq!(metrics.len(), 3);
    assert_eq!(metrics[0].name, "active");
    assert_eq!(metrics[1].name, "duration");
    assert_eq!(metrics[2].name, "requests");

    let Some(MetricData::Gauge(gauge)) = &metrics[0].data else {
        panic!("gauge wire type");
    };
    assert_eq!(gauge.data_points[0].value, Some(NumberDataPointValue::Int(-7)));
    assert_eq!(gauge.data_points[0].start_time_unix_nano, 0);
    assert_eq!(gauge.data_points[0].time_unix_nano, 2000);

    let Some(MetricData::Histogram(histogram)) = &metrics[1].data else {
        panic!("histogram wire type");
    };
    assert_eq!(histogram.aggregation_temporality, AggregationTemporality::Cumulative.as_raw());
    let point = &histogram.data_points[0];
    assert_eq!(point.count, 3);
    assert_eq!(point.sum, Some(1.25));
    assert_eq!(point.bucket_counts, vec![3]);
    assert!(point.explicit_bounds.is_empty());
    assert_eq!(point.start_time_unix_nano, 1000);
    assert_eq!(point.time_unix_nano, 2000);

    let Some(MetricData::Sum(sum)) = &metrics[2].data else {
        panic!("counter wire type");
    };
    assert!(sum.is_monotonic);
    assert_eq!(sum.aggregation_temporality, AggregationTemporality::Cumulative.as_raw());
    assert_eq!(sum.data_points[0].value, Some(NumberDataPointValue::Int(42)));
    assert_eq!(sum.data_points[0].start_time_unix_nano, 1000);
    assert_eq!(sum.data_points[0].time_unix_nano, 2000);
    assert_eq!(sum.data_points[0].attributes[0].key, "route");
}

#[test]
fn encoding_is_independent_of_series_label_and_resource_insertion_order() {
    let mut first = MetricsSnapshot::new();
    first.add_counter("requests", vec![("z".into(), "2".into()), ("a".into(), "1".into())], 5);
    first.add_counter("requests", vec![("route".into(), "/other".into())], 9);
    first.add_gauge("active", Vec::new(), 2);
    let mut second = first.clone();
    second.counters.reverse();
    for (_, labels, _) in &mut second.counters {
        labels.reverse();
    }
    let resource = vec![("z".into(), "2".into()), ("a".into(), "1".into())];
    let mut reversed = resource.clone();
    reversed.reverse();
    assert_eq!(
        encode_snapshot(batch(&first), &resource).unwrap(),
        encode_snapshot(batch(&second), &reversed).unwrap(),
    );
}

#[test]
fn empty_snapshot_produces_no_request() {
    assert!(encode_snapshot(batch(&MetricsSnapshot::new()), &[]).unwrap().is_none());
}

#[test]
fn explicit_epoch_is_required_and_may_equal_collection_time() {
    let snapshot = MetricsSnapshot::new();
    assert!(MetricsExportBatch::new(&snapshot, 0, 0).is_err());
    assert!(MetricsExportBatch::new(&snapshot, 0, 2000).is_err());
    assert!(MetricsExportBatch::new(&snapshot, 2000, 1999).is_err());
    let batch = MetricsExportBatch::new(&snapshot, 2000, 2000).unwrap();
    assert_eq!(batch.start_time_unix_nano(), 2000);
    assert_eq!(batch.time_unix_nano(), 2000);
    assert!(std::ptr::eq(batch.snapshot(), &snapshot));
}

#[test]
fn counter_integer_boundary_is_exact_and_overflow_is_rejected() {
    let mut snapshot = MetricsSnapshot::new();
    snapshot.add_counter("counter", Vec::new(), i64::MAX as u64);
    let decoded = decode(&encode_snapshot(batch(&snapshot), &[]).unwrap().unwrap());
    let Some(MetricData::Sum(sum)) = &decoded.resource_metrics[0].scope_metrics[0].metrics[0].data else {
        panic!("counter wire type");
    };
    assert_eq!(sum.data_points[0].value, Some(NumberDataPointValue::Int(i64::MAX)));
    for invalid in [i64::MAX as u64 + 1, u64::MAX] {
        snapshot.counters[0].2 = invalid;
        assert!(encode_snapshot(batch(&snapshot), &[]).is_err());
    }
}

#[test]
fn invalid_histograms_never_produce_a_request() {
    for (count, sum) in [(1, f64::NAN), (1, f64::INFINITY), (1, f64::NEG_INFINITY), (0, 1.0)] {
        let mut snapshot = MetricsSnapshot::new();
        snapshot.add_histogram("histogram", Vec::new(), count, sum);
        assert!(encode_snapshot(batch(&snapshot), &[]).is_err());
    }
    let mut empty = MetricsSnapshot::new();
    empty.add_histogram("histogram", Vec::new(), 0, 0.0);
    assert!(encode_snapshot(batch(&empty), &[]).is_ok());
}

#[test]
fn duplicate_series_and_mixed_metric_kinds_are_rejected() {
    let labels = vec![("a".into(), "1".into()), ("b".into(), "2".into())];
    let mut snapshot = MetricsSnapshot::new();
    snapshot.add_counter("counter", labels.clone(), 1);
    let mut reversed = labels;
    reversed.reverse();
    snapshot.add_counter("counter", reversed, 2);
    assert!(encode_snapshot(batch(&snapshot), &[]).is_err());
    snapshot.counters.pop();
    snapshot.add_gauge("counter", Vec::new(), 2);
    assert!(encode_snapshot(batch(&snapshot), &[]).is_err());
}

#[test]
fn malformed_names_and_labels_are_rejected_with_value_redacted_errors() {
    for labels in [
        vec![(String::new(), "private-value".into())],
        vec![("key".into(), "private-value".into()), ("key".into(), "other".into())],
        vec![("k".repeat(1025), "private-value".into())],
        vec![("key".into(), "v".repeat(4097))],
    ] {
        let mut snapshot = MetricsSnapshot::new();
        snapshot.add_counter("private-name", labels, 1);
        let error = encode_snapshot(batch(&snapshot), &[]).unwrap_err().to_string();
        assert!(!error.contains("private-value"));
        assert!(!error.contains("private-name"));
    }
    for name in [String::new(), "n".repeat(1025)] {
        let mut snapshot = MetricsSnapshot::new();
        snapshot.add_counter(name, Vec::new(), 1);
        assert!(encode_snapshot(batch(&snapshot), &[]).is_err());
    }
}

#[test]
fn resource_attributes_obey_the_same_duplicate_and_size_rules() {
    let mut snapshot = MetricsSnapshot::new();
    snapshot.add_gauge("active", Vec::new(), 1);
    let duplicate = vec![("service.name".into(), "one".into()), ("service.name".into(), "two".into())];
    assert!(encode_snapshot(batch(&snapshot), &duplicate).is_err());
    let oversized = vec![("resource".into(), "x".repeat(4097))];
    assert!(encode_snapshot(batch(&snapshot), &oversized).is_err());
}

#[test]
fn aggregate_and_per_metric_point_limits_fail_closed() {
    let mut snapshot = MetricsSnapshot::new();
    for index in 0..=MAX_POINTS_PER_METRIC {
        snapshot.add_gauge("active", vec![("id".into(), index.to_string())], 1);
    }
    assert!(encode_snapshot(batch(&snapshot), &[]).is_err());
    let mut snapshot = MetricsSnapshot::new();
    for index in 0..=MAX_POINTS {
        snapshot.add_gauge(format!("metric-{index}"), Vec::new(), 1);
    }
    assert!(encode_snapshot(batch(&snapshot), &[]).is_err());
}

#[test]
fn aggregate_attribute_and_string_limits_are_enforced_before_owned_encoding() {
    let mut snapshot = MetricsSnapshot::new();
    for index in 0..=MAX_ATTRIBUTE_VALUES / 2 {
        snapshot.add_gauge(
            format!("metric-{index}"),
            vec![("a".into(), "1".into()), ("b".into(), "2".into())],
            1,
        );
    }
    assert!(encode_snapshot(batch(&snapshot), &[]).is_err());
    let mut snapshot = MetricsSnapshot::new();
    for index in 0..800 {
        snapshot.add_gauge(format!("metric-{index}"), vec![("key".into(), "v".repeat(4096))], 1);
    }
    assert!(encode_snapshot(batch(&snapshot), &[]).is_err());
}

#[test]
fn cancelled_context_is_rejected_before_export_work() {
    let cx = Cx::for_testing();
    cx.cancel_with(crate::types::CancelKind::User, Some("test cancellation"));
    assert!(checkpoint(&cx).is_err());
}
