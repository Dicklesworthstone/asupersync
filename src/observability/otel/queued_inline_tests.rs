    use super::*;

    #[test]
    fn bounded_queue_counts_inflight_and_rejects_without_losing_admitted_batches() {
        let exporter = OtlpHttpExporter::new("http://127.0.0.1:4318/v1/metrics");
        let mut metrics = MetricsSnapshot::new();
        metrics.add_counter("requests", Vec::new(), 7);
        for _ in 0..OTLP_EXPORT_QUEUE_MAX_BATCHES {
            exporter.export(&metrics).unwrap();
        }
        let consumer = exporter.export_queue.consumer().unwrap();
        assert!(exporter.export_queue.consumer().is_err());
        let delivery = exporter.export_queue.take().unwrap();
        assert_eq!(
            exporter.queue_stats().queued_batches,
            OTLP_EXPORT_QUEUE_MAX_BATCHES - 1
        );
        assert_eq!(
            exporter.queue_stats().retained_batches,
            OTLP_EXPORT_QUEUE_MAX_BATCHES
        );
        assert!(
            exporter
                .export(&metrics)
                .unwrap_err()
                .message
                .contains("capacity_exceeded")
        );
        assert!(exporter.flush().is_err());
        drop(delivery);
        assert_eq!(exporter.queue_stats().failed_batches, 1);
        exporter.export(&metrics).unwrap();
        drop(consumer);
        assert!(!exporter.queue_stats().consumer_active);
    }

    #[test]
    fn byte_admission_and_invalid_snapshots_leave_queue_unchanged() {
        let exporter = OtlpLogsHttpExporter::new("http://127.0.0.1:4318/v1/logs");
        let mut logs = LogsSnapshot::new("queue-test");
        logs.add_record(OtlpLogRecord::new(
            LogLevel::Info,
            "x".repeat(OTLP_EXPORT_QUEUE_MAX_BYTES),
            1,
        ));
        assert!(exporter.export(&logs).is_err());
        assert_eq!(exporter.queue_stats(), OtlpExportQueueStats::default());
        let exporter = OtlpHttpExporter::new("http://127.0.0.1:4318/v1/metrics");
        let mut metrics = MetricsSnapshot::new();
        metrics.add_counter("requests", Vec::new(), u64::MAX);
        assert!(exporter.export(&metrics).is_err());
        metrics.counters[0].2 = 1;
        metrics.add_gauge("requests", Vec::new(), 2);
        assert!(exporter.export(&metrics).is_err());
        assert_eq!(exporter.queue_stats().retained_batches, 0);
    }

    /// Admission checked only the total point count and the queue byte
    /// budget, so it accepted snapshots delivery could never encode: 1001
    /// points for one metric name, or a logs body over the 4 MiB request
    /// limit. Delivery then failed without any I/O, lost the whole snapshot
    /// and stopped run_queued.
    #[test]
    fn a_snapshot_delivery_could_never_send_is_refused_at_admission() {
        let exporter = OtlpHttpExporter::new("http://127.0.0.1:4318/v1/metrics");
        let mut metrics = MetricsSnapshot::new();
        for route in 0..=OWNED_OTLP_MAX_POINTS_PER_METRIC {
            metrics.add_counter(
                "requests",
                vec![("route".to_string(), route.to_string())],
                1,
            );
        }
        assert!(exporter.export(&metrics).is_err());
        assert_eq!(exporter.queue_stats().retained_batches, 0);

        let exporter = OtlpLogsHttpExporter::new("http://127.0.0.1:4318/v1/logs");
        let mut logs = LogsSnapshot::new("queue-test");
        logs.add_record(OtlpLogRecord::new(
            LogLevel::Info,
            "x".repeat(OWNED_OTLP_DEFAULT_REQUEST_BYTES + 1),
            1,
        ));
        assert!(exporter.export(&logs).is_err());
        assert_eq!(exporter.queue_stats(), OtlpExportQueueStats::default());
    }

    #[test]
    fn metrics_queue_encodes_real_registry_values_and_captures_destination() {
        use crate::observability::otlp_proto::collector::metrics::ExportMetricsServiceRequest;
        use crate::observability::otlp_proto::metrics::{MetricData, NumberDataPointValue};
        let mut registry = crate::observability::metrics::Metrics::new();
        registry.counter("requests").add(7);
        registry.gauge("active").set(-2);
        registry.histogram("latency", vec![1.0, 10.0]).observe(3.0);
        let snapshot = registry.export_snapshot();
        let exporter = OtlpHttpExporter::new("http://127.0.0.1:4318/v1/metrics");
        exporter.export(&snapshot).unwrap();
        let changed = exporter.clone().with_bearer_token("later-credential");
        let delivery = changed.export_queue.take().unwrap();
        let batch = delivery.batch.as_ref().unwrap();
        assert!(batch.config.auth_headers.is_empty());
        let body = encode_metrics(&snapshot, 42, &batch.config).unwrap();
        // Decode under the encoder's envelope, like the sibling OTLP tests. A
        // body-sized envelope leaves too little work budget for the nested
        // metric messages.
        let decoded = ExportMetricsServiceRequest::decode_from_bytes(
            &body,
            ProtobufWireLimits::for_message_size(OWNED_OTLP_DEFAULT_REQUEST_BYTES),
        )
        .unwrap();
        let metrics = &decoded.resource_metrics[0].scope_metrics[0].metrics;
        assert_eq!(
            metrics.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
            vec!["active", "latency", "requests"]
        );
        match metrics[0].data.as_ref().unwrap() {
            MetricData::Gauge(gauge) => assert_eq!(
                gauge.data_points[0].value,
                Some(NumberDataPointValue::Int(-2))
            ),
            other => panic!("wrong gauge: {other:?}"),
        }
        match metrics[1].data.as_ref().unwrap() {
            MetricData::Histogram(hist) => {
                assert_eq!(hist.data_points[0].count, 1);
                assert_eq!(hist.data_points[0].sum, Some(3.0));
                assert_eq!(hist.data_points[0].bucket_counts, vec![1]);
            }
            other => panic!("wrong histogram: {other:?}"),
        }
        match metrics[2].data.as_ref().unwrap() {
            MetricData::Sum(sum) => {
                assert_eq!(sum.data_points[0].value, Some(NumberDataPointValue::Int(7)));
                assert_eq!(sum.data_points[0].time_unix_nano, 42);
            }
            other => panic!("wrong counter: {other:?}"),
        }
    }
