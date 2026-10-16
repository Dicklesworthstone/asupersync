    use super::*;

    #[test]
    fn null_exporter_works() {
        let exporter = NullExporter::new();
        let snapshot = MetricsSnapshot::new();
        assert!(exporter.export(&snapshot).is_ok());
        assert!(exporter.flush().is_ok());
    }

    #[test]
    fn in_memory_exporter_collects() {
        let exporter = InMemoryExporter::new();

        let mut snapshot = MetricsSnapshot::new();
        snapshot.add_counter("test.counter", vec![], 42);
        snapshot.add_gauge(
            "test.gauge",
            vec![("label".to_string(), "value".to_string())],
            100,
        );
        snapshot.add_histogram("test.histogram", vec![], 10, 5.5);

        assert!(exporter.export(&snapshot).is_ok());
        assert_eq!(exporter.total_metrics(), 3);

        let snapshots = exporter.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].counters.len(), 1);
        assert_eq!(snapshots[0].gauges.len(), 1);
        assert_eq!(snapshots[0].histograms.len(), 1);

        exporter.clear();
        assert_eq!(exporter.total_metrics(), 0);
    }

    #[test]
    fn multi_exporter_fans_out() {
        // Create a wrapper to use with MultiExporter
        struct ArcExporter(Arc<InMemoryExporter>);
        impl MetricsExporter for ArcExporter {
            fn export(&self, metrics: &MetricsSnapshot) -> Result<(), ExportError> {
                self.0.export(metrics)
            }
            fn flush(&self) -> Result<(), ExportError> {
                self.0.flush()
            }
        }

        let exp1 = InMemoryExporter::new();
        let exp2 = InMemoryExporter::new();

        // Need to use Arc to share between multi-exporter and tests
        let exp1_arc = Arc::new(exp1);
        let exp2_arc = Arc::new(exp2);

        let mut multi = MultiExporter::new(vec![]);
        multi.add(Box::new(ArcExporter(Arc::clone(&exp1_arc))));
        multi.add(Box::new(ArcExporter(Arc::clone(&exp2_arc))));
        assert_eq!(multi.len(), 2);

        let mut snapshot = MetricsSnapshot::new();
        snapshot.add_counter("test", vec![], 1);

        assert!(multi.export(&snapshot).is_ok());
        assert!(multi.flush().is_ok());

        // Both exporters should have received the snapshot
        assert_eq!(exp1_arc.total_metrics(), 1);
        assert_eq!(exp2_arc.total_metrics(), 1);
    }

    #[test]
    fn metrics_snapshot_building() {
        let mut snapshot = MetricsSnapshot::new();

        snapshot.add_counter(
            "requests",
            vec![("method".to_string(), "GET".to_string())],
            100,
        );
        snapshot.add_gauge("connections", vec![], 42);
        snapshot.add_histogram("latency", vec![], 1000, 125.5);

        assert_eq!(snapshot.counters.len(), 1);
        assert_eq!(snapshot.gauges.len(), 1);
        assert_eq!(snapshot.histograms.len(), 1);

        let (name, labels, value) = &snapshot.counters[0];
        assert_eq!(name, "requests");
        assert_eq!(labels.len(), 1);
        assert_eq!(*value, 100);
    }

    #[test]
    fn export_error_display() {
        let err = ExportError::new("test error");
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn log_level_to_otlp_severity_matches_data_model_bases() {
        assert_eq!(log_level_to_otlp_severity(LogLevel::Trace), (1, "TRACE"));
        assert_eq!(log_level_to_otlp_severity(LogLevel::Debug), (5, "DEBUG"));
        assert_eq!(log_level_to_otlp_severity(LogLevel::Info), (9, "INFO"));
        assert_eq!(log_level_to_otlp_severity(LogLevel::Warn), (13, "WARN"));
        assert_eq!(log_level_to_otlp_severity(LogLevel::Error), (17, "ERROR"));
    }

    #[test]
    fn null_logs_exporter_is_disabled_noop() {
        let exporter = NullLogsExporter::new();
        let snapshot = LogsSnapshot::new("checkout").with_record(OtlpLogRecord::new(
            LogLevel::Info,
            "ignored",
            10,
        ));

        assert!(exporter.export(&snapshot).is_ok());
        assert!(exporter.flush().is_ok());
    }

    #[test]
    fn in_memory_logs_exporter_collects_snapshots() {
        let exporter = InMemoryLogsExporter::new();
        let snapshot = LogsSnapshot::new("checkout")
            .with_record(OtlpLogRecord::new(LogLevel::Info, "first", 10))
            .with_record(OtlpLogRecord::new(LogLevel::Warn, "second", 20));

        exporter.export(&snapshot).expect("logs export");
        assert_eq!(exporter.total_records(), 2);
        assert_eq!(exporter.snapshots(), vec![snapshot]);

        exporter.clear();
        assert_eq!(exporter.total_records(), 0);
    }

    /// process_queue dequeued a batch and exported it with `?`, so a batch
    /// whose export failed was dropped uncounted: each flush during an outage
    /// lost one more.
    #[test]
    fn load_shedding_logs_exporter_keeps_a_batch_whose_export_failed() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct FlakyLogsExporter {
            fail: Arc<AtomicBool>,
            inner: Arc<InMemoryLogsExporter>,
        }
        impl LogsExporter for FlakyLogsExporter {
            fn export(&self, logs: &LogsSnapshot) -> Result<(), ExportError> {
                if self.fail.load(Ordering::SeqCst) {
                    return Err(ExportError::new("collector unavailable"));
                }
                self.inner.export(logs)
            }

            fn flush(&self) -> Result<(), ExportError> {
                Ok(())
            }
        }

        let fail = Arc::new(AtomicBool::new(true));
        let memory = Arc::new(InMemoryLogsExporter::new());
        let exporter = LoadSheddingLogsExporter::new(
            Box::new(FlakyLogsExporter {
                fail: Arc::clone(&fail),
                inner: Arc::clone(&memory),
            }),
            10,
        );
        for timestamp in 1..=3 {
            let snapshot = LogsSnapshot::new("checkout").with_record(OtlpLogRecord::new(
                LogLevel::Info,
                "event",
                timestamp,
            ));
            exporter.export(&snapshot).expect("queued");
        }
        for _ in 0..3 {
            assert!(exporter.flush().is_err(), "the collector is down");
        }
        let stats = exporter.load_shedding_stats();
        assert_eq!((stats.queue_depth, stats.dropped_batches), (3, 0));

        fail.store(false, Ordering::SeqCst);
        exporter.flush().expect("the collector is back");
        assert_eq!(memory.total_records(), 3);
        assert_eq!(exporter.load_shedding_stats().queue_depth, 0);

        // A failed batch put back into a queue that filled up meanwhile is the
        // oldest, so it is the one shed, and it is counted.
        let queue = BoundedExportQueue::new(2);
        queue.enqueue(1);
        queue.enqueue(2);
        let failed = queue.dequeue().expect("oldest batch");
        queue.enqueue(3);
        assert!(!queue.requeue_front(failed));
        assert_eq!(queue.dropped_count(), 1);
        assert_eq!(queue.dequeue(), Some(2));
    }

    #[test]
    fn multi_logs_exporter_fans_out_and_reports_errors() {
        struct ArcLogsExporter(Arc<InMemoryLogsExporter>);
        impl LogsExporter for ArcLogsExporter {
            fn export(&self, logs: &LogsSnapshot) -> Result<(), ExportError> {
                self.0.export(logs)
            }

            fn flush(&self) -> Result<(), ExportError> {
                self.0.flush()
            }
        }

        struct FailingLogsExporter;
        impl LogsExporter for FailingLogsExporter {
            fn export(&self, _logs: &LogsSnapshot) -> Result<(), ExportError> {
                Err(ExportError::new("collector rejected logs"))
            }

            fn flush(&self) -> Result<(), ExportError> {
                Ok(())
            }
        }

        let first = Arc::new(InMemoryLogsExporter::new());
        let second = Arc::new(InMemoryLogsExporter::new());
        let snapshot =
            LogsSnapshot::new("checkout").with_record(OtlpLogRecord::new(LogLevel::Info, "ok", 1));

        let multi = MultiLogsExporter::new(vec![
            Box::new(ArcLogsExporter(Arc::clone(&first))),
            Box::new(ArcLogsExporter(Arc::clone(&second))),
        ]);
        multi.export(&snapshot).expect("multi logs export");
        assert_eq!(first.total_records(), 1);
        assert_eq!(second.total_records(), 1);

        let failing = MultiLogsExporter::new(vec![Box::new(FailingLogsExporter)]);
        let error = failing
            .export(&snapshot)
            .expect_err("failure must propagate");
        assert!(error.to_string().contains("collector rejected logs"));
    }

    #[test]
    fn logs_load_shedding_drops_oldest_snapshots() {
        struct ArcLogsExporter(Arc<InMemoryLogsExporter>);
        impl LogsExporter for ArcLogsExporter {
            fn export(&self, logs: &LogsSnapshot) -> Result<(), ExportError> {
                self.0.export(logs)
            }

            fn flush(&self) -> Result<(), ExportError> {
                self.0.flush()
            }
        }

        fn snapshot(id: u64) -> LogsSnapshot {
            LogsSnapshot::new("checkout").with_record(
                OtlpLogRecord::new(LogLevel::Info, format!("batch-{id}"), id)
                    .with_attribute("batch_id", id.to_string()),
            )
        }

        let received = Arc::new(InMemoryLogsExporter::new());
        let exporter =
            LoadSheddingLogsExporter::new(Box::new(ArcLogsExporter(Arc::clone(&received))), 2);

        exporter.export(&snapshot(0)).expect("export 0");
        exporter.export(&snapshot(1)).expect("export 1");
        exporter.export(&snapshot(2)).expect("export 2");

        let stats = exporter.load_shedding_stats();
        assert_eq!(stats.queue_depth, 2);
        assert_eq!(stats.dropped_batches, 1);

        assert_eq!(exporter.process_queue().expect("process logs"), 2);
        let bodies: Vec<_> = received
            .snapshots()
            .iter()
            .flat_map(|snapshot| snapshot.records.iter().map(|record| record.body.clone()))
            .collect();
        assert_eq!(bodies, vec!["batch-1", "batch-2"]);
    }

    #[test]
    fn traces_metrics_and_logs_export_without_cross_signal_duplication() {
        use crate::observability::otlp_trace_exporter::{
            ExportError as TraceExportError, OtlpSpan, SpanBatch, TraceExporter,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Instant;

        #[derive(Debug, Default)]
        struct CountingTraceExporter {
            batches: AtomicUsize,
            spans: AtomicUsize,
        }

        impl TraceExporter for CountingTraceExporter {
            fn export(&self, batch: &SpanBatch) -> Result<(), TraceExportError> {
                self.batches.fetch_add(1, Ordering::Relaxed);
                self.spans.fetch_add(batch.spans.len(), Ordering::Relaxed);
                Ok(())
            }

            fn flush(&self) -> Result<(), TraceExportError> {
                Ok(())
            }
        }

        let trace_exporter = CountingTraceExporter::default();
        let metrics_exporter = InMemoryExporter::new();
        let logs_exporter = InMemoryLogsExporter::new();

        let trace_batch = SpanBatch {
            batch_id: 7,
            spans: vec![OtlpSpan::new(
                "span-1".to_string(),
                "checkout".to_string(),
                1,
                2,
                vec![("route".to_string(), "/pay".to_string())],
            )],
            created_at: Instant::now(),
        };
        trace_exporter
            .export(&trace_batch)
            .expect("trace export should work");

        let mut metrics = MetricsSnapshot::new();
        metrics.add_counter(
            "otel.export.requests",
            vec![("signal".into(), "metrics".into())],
            1,
        );
        metrics_exporter
            .export(&metrics)
            .expect("metrics export should work");

        let logs = LogsSnapshot::new("checkout").with_record(
            OtlpLogRecord::new(LogLevel::Info, "checkout complete", 3)
                .with_attribute("signal", "logs"),
        );
        logs_exporter
            .export(&logs)
            .expect("logs export should work");

        assert_eq!(trace_exporter.batches.load(Ordering::Relaxed), 1);
        assert_eq!(trace_exporter.spans.load(Ordering::Relaxed), 1);
        assert_eq!(metrics_exporter.total_metrics(), 1);
        assert_eq!(logs_exporter.total_records(), 1);
    }

    #[test]
    fn logs_exporter_reuses_otlp_retry_classifier() {
        let retry = classify_otlp_http_response(503, &[]);
        assert!(matches!(
            retry,
            Err(OtlpError::Retryable {
                status_code: 503,
                ..
            })
        ));

        let terminal = classify_otlp_http_response(400, &[]);
        assert!(matches!(terminal, Err(OtlpError::NonRetryable { .. })));

        let exporter = OtlpLogsHttpExporter::new("http://collector:4318/v1/logs")
            .with_retry_config(4, Duration::from_millis(50), Duration::from_secs(5))
            .with_timeout(Duration::from_secs(3));
        assert_eq!(exporter.endpoint(), "http://collector:4318/v1/logs");

        let logs = LogsSnapshot::new("checkout");
        #[cfg(not(target_arch = "wasm32"))]
        {
            exporter.export(&logs).expect("sync export admitted");
            assert_eq!(exporter.queue_stats().queued_batches, 1);
            assert!(
                exporter
                    .flush()
                    .expect_err("delivery is pending")
                    .message
                    .contains("otlp.queue.pending")
            );
        }
        #[cfg(target_arch = "wasm32")]
        {
            let sync_error = exporter.export(&logs).expect_err("sync export rejected");
            assert!(sync_error.to_string().contains("requires async context"));
        }
    }

    #[test]
    fn logs_snapshot_encodes_otlp_wire_compatible_records() {
        use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
        use opentelemetry_proto::tonic::common::v1::any_value::Value as ProtoValue;
        use opentelemetry_proto::tonic::logs::v1::SeverityNumber;
        use prost::Message;

        let long_value = "x".repeat(OTLP_LOGS_MAX_ATTRIBUTE_VALUE_BYTES + 16);
        let record = OtlpLogRecord::new(LogLevel::Warn, "", 100)
            .with_observed_time_unix_nano(101)
            .with_attribute("component", "scheduler")
            .with_attribute("long", long_value)
            .with_attribute("", "dropped")
            .with_trace_context(vec![1; 16], vec![2; 8], 0x0101)
            .with_event_name("asupersync.scheduler.warning");
        let snapshot = LogsSnapshot::new("checkout")
            .with_scope("asupersync.test.logs", "test-version")
            .with_resource_attribute("deployment.environment", "test")
            .with_record(record);

        let encoded = snapshot.to_otlp_protobuf();
        let decoded = ExportLogsServiceRequest::decode(encoded.as_slice()).expect("decode logs");
        assert_eq!(decoded.resource_logs.len(), 1);

        let resource_logs = &decoded.resource_logs[0];
        let resource = resource_logs.resource.as_ref().expect("resource");
        assert!(
            resource
                .attributes
                .iter()
                .any(|attribute| attribute.key == "service.name")
        );

        let scope_logs = &resource_logs.scope_logs[0];
        let scope = scope_logs.scope.as_ref().expect("scope");
        assert_eq!(scope.name, "asupersync.test.logs");
        assert_eq!(scope.version, "test-version");

        let decoded_record = &scope_logs.log_records[0];
        assert_eq!(decoded_record.severity_number, SeverityNumber::Warn as i32);
        assert_eq!(decoded_record.severity_text, "WARN");
        assert_eq!(decoded_record.time_unix_nano, 100);
        assert_eq!(decoded_record.observed_time_unix_nano, 101);
        assert_eq!(decoded_record.trace_id, vec![1; 16]);
        assert_eq!(decoded_record.span_id, vec![2; 8]);
        assert_eq!(decoded_record.flags, 1);
        assert_eq!(decoded_record.event_name, "asupersync.scheduler.warning");
        assert_eq!(decoded_record.dropped_attributes_count, 1);

        let body = decoded_record.body.as_ref().expect("body");
        assert!(matches!(
            body.value.as_ref(),
            Some(ProtoValue::StringValue(value)) if value.is_empty()
        ));
        let long = decoded_record
            .attributes
            .iter()
            .find(|attribute| attribute.key == "long")
            .expect("long attribute")
            .value
            .as_ref()
            .expect("long attr value");
        assert!(matches!(
            long.value.as_ref(),
            Some(ProtoValue::StringValue(value))
                if value.len() == OTLP_LOGS_MAX_ATTRIBUTE_VALUE_BYTES
        ));
    }

    #[test]
    fn otlp_export_queue_load_shedding_drops_oldest_batches() {
        // AUDIT TEST: OTLP exporter load shedding behavior
        //
        // REQUIREMENT: When export channel is full, drop OLDEST batches (correct)
        // NOT drop NEWEST batches (incorrect) per OTLP exporter best practices.
        //
        // GOAL: Preserve recent data over stale data for better observability.

        let received_batches = Arc::new(Mutex::new(Vec::<MetricsSnapshot>::new()));

        struct TrackingExporter {
            received: Arc<Mutex<Vec<MetricsSnapshot>>>,
        }

        impl MetricsExporter for TrackingExporter {
            fn export(&self, metrics: &MetricsSnapshot) -> Result<(), ExportError> {
                self.received.lock().push(metrics.clone());
                Ok(())
            }

            fn flush(&self) -> Result<(), ExportError> {
                Ok(())
            }
        }

        let tracking_exporter = TrackingExporter {
            received: Arc::clone(&received_batches),
        };

        // Create load shedding exporter with small capacity for testing
        let queue_capacity = 3;
        let exporter = LoadSheddingExporter::new(Box::new(tracking_exporter), queue_capacity);

        // Create identifiable test batches
        let mut batches = Vec::new();
        for i in 0..6 {
            let mut batch = MetricsSnapshot::new();
            batch.add_counter(
                "test_metric",
                vec![("batch_id".to_string(), i.to_string())],
                i as u64 + 1,
            );
            batches.push(batch);
        }

        // Fill queue beyond capacity to trigger load shedding
        for batch in &batches {
            let result = exporter.export(batch);
            assert!(
                result.is_ok(),
                "export should succeed even when dropping oldest"
            );
        }

        // Verify load shedding stats
        let stats = exporter.load_shedding_stats();
        assert_eq!(stats.queue_capacity, 3, "queue capacity should be 3");
        assert_eq!(stats.queue_depth, 3, "queue should be full");
        assert_eq!(
            stats.dropped_batches, 3,
            "should have dropped 3 oldest batches"
        );

        // Process queue and verify OLDEST batches were dropped
        let processed = exporter
            .process_queue()
            .expect("process queue should succeed");
        assert_eq!(processed, 3, "should have processed 3 batches");

        let received = received_batches.lock();
        assert_eq!(received.len(), 3, "should have received 3 batches");

        // Verify we kept the NEWEST 3 batches (3, 4, 5) and dropped oldest (0, 1, 2)
        let received_batch_ids: Vec<String> = received
            .iter()
            .map(|batch| {
                // Extract batch_id from the counter labels
                batch.counters[0].1[0].1.clone()
            })
            .collect();

        assert_eq!(
            received_batch_ids,
            vec!["3", "4", "5"],
            "should preserve NEWEST batches (3,4,5) and drop oldest (0,1,2)"
        );

        eprintln!("OTLP LOAD SHEDDING AUDIT RESULTS:");
        eprintln!("  ✓ CORRECT: Drops OLDEST batches when queue is full");
        eprintln!("  ✓ CORRECT: Preserves NEWEST batches for recent observability");
        eprintln!("  ✓ CORRECT: Maintains FIFO export order");
        eprintln!("  Queue capacity: {}", stats.queue_capacity);
        eprintln!("  Dropped batches: {}", stats.dropped_batches);
        eprintln!("  Preserved batches: {}", received_batch_ids.join(", "));
    }

    #[test]
    fn bounded_export_queue_fifo_order_preserved() {
        // Test that the bounded queue maintains FIFO order even with load shedding
        let queue = BoundedExportQueue::new(2);

        // Add items that fit in queue
        assert!(!queue.enqueue("first"));
        assert!(!queue.enqueue("second"));
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.dropped_count(), 0);

        // Add item that triggers load shedding (drops oldest = "first")
        assert!(queue.enqueue("third"));
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.dropped_count(), 1);

        // Verify FIFO order: should get "second" then "third"
        assert_eq!(queue.dequeue(), Some("second"));
        assert_eq!(queue.dequeue(), Some("third"));
        assert_eq!(queue.dequeue(), None);
    }

    #[test]
    fn bounded_export_queue_capacity_limits() {
        let queue = BoundedExportQueue::new(0); // Zero capacity edge case
        assert!(queue.enqueue("item"));
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.dropped_count(), 0); // No previous item to drop

        let queue = BoundedExportQueue::new(1);
        assert!(!queue.enqueue("first"));
        assert!(queue.enqueue("second")); // Drops "first"
        assert_eq!(queue.dequeue(), Some("second"));
        assert_eq!(queue.dropped_count(), 1);
    }

    // Pure data-type tests (wave 38 – CyanBarn)

    #[test]
    fn cardinality_overflow_debug_clone_copy_eq_default() {
        let overflow = CardinalityOverflow::default();
        assert_eq!(overflow, CardinalityOverflow::Drop);
        let dbg = format!("{overflow:?}");
        assert!(dbg.contains("Drop"));

        let aggregate = CardinalityOverflow::Aggregate;
        let cloned = aggregate;
        assert_eq!(cloned, CardinalityOverflow::Aggregate);
        assert_ne!(aggregate, CardinalityOverflow::Warn);

        let warn = CardinalityOverflow::Warn;
        let copied = warn;
        assert_eq!(copied, warn);
    }

    #[test]
    fn metrics_config_debug_clone_default() {
        let config = MetricsConfig::default();
        assert_eq!(config.max_cardinality, 1000);
        assert_eq!(config.overflow_strategy, CardinalityOverflow::Drop);
        assert!(config.drop_labels.is_empty());
        assert!(config.sampling.is_none());

        let dbg = format!("{config:?}");
        assert!(dbg.contains("MetricsConfig"));

        let cloned = config;
        assert_eq!(cloned.max_cardinality, 1000);
    }

    #[test]
    fn sampling_config_debug_clone_default() {
        let config = SamplingConfig::default();
        assert!((config.sample_rate - 1.0).abs() < f64::EPSILON);
        assert!(config.sampled_metrics.is_empty());

        let dbg = format!("{config:?}");
        assert!(dbg.contains("SamplingConfig"));

        let cloned = config;
        assert!((cloned.sample_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn metrics_snapshot_debug_clone_default() {
        let snapshot = MetricsSnapshot::default();
        assert!(snapshot.counters.is_empty());
        assert!(snapshot.gauges.is_empty());
        assert!(snapshot.histograms.is_empty());

        let dbg = format!("{snapshot:?}");
        assert!(dbg.contains("MetricsSnapshot"));

        let mut s = MetricsSnapshot::new();
        s.add_counter("c", vec![], 1);
        let cloned = s.clone();
        assert_eq!(cloned.counters.len(), 1);
    }

    #[test]
    fn export_error_debug_clone() {
        let err = ExportError::new("something failed");
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ExportError"));

        let cloned = err.clone();
        assert_eq!(cloned.to_string(), err.to_string());
    }

    #[test]
    fn stdout_exporter_debug_default() {
        let exporter = StdoutExporter::default();
        let dbg = format!("{exporter:?}");
        assert!(dbg.contains("StdoutExporter"));

        let with_prefix = StdoutExporter::with_prefix("[test] ");
        let dbg2 = format!("{with_prefix:?}");
        assert!(dbg2.contains("StdoutExporter"));
    }

    #[test]
    fn null_exporter_debug_default() {
        let exporter = NullExporter;
        let dbg = format!("{exporter:?}");
        assert!(dbg.contains("NullExporter"));
    }

    #[test]
    fn multi_exporter_debug_default() {
        let exporter = MultiExporter::default();
        assert!(exporter.is_empty());
        assert_eq!(exporter.len(), 0);
        let dbg = format!("{exporter:?}");
        assert!(dbg.contains("MultiExporter"));
    }

    #[test]
    fn in_memory_exporter_debug_default() {
        let exporter = InMemoryExporter::default();
        assert_eq!(exporter.total_metrics(), 0);
        let dbg = format!("{exporter:?}");
        assert!(dbg.contains("InMemoryExporter"));
    }

    /// br-asupersync-coxhdt: escape_label_value must handle the
    /// Prometheus-spec-required escape trio (\\\\, \\n, \\") plus \\r as
    /// defense-in-depth. Otherwise an attacker-controlled label value
    /// containing a literal '"' would close the value-string early
    /// and inject spurious labels.
    #[test]
    fn escape_label_value_handles_spec_required_trio_plus_cr() {
        // Plain values pass through unchanged.
        assert_eq!(escape_label_value("plain"), "plain");
        // Backslash → \\
        assert_eq!(escape_label_value(r"a\b"), r"a\\b");
        // Newline → \n
        assert_eq!(escape_label_value("a\nb"), r"a\nb");
        // Double-quote → \"
        assert_eq!(escape_label_value(r#"a"b"#), r#"a\"b"#);
        // Carriage return → \r
        assert_eq!(escape_label_value("a\rb"), r"a\rb");
        // All four together.
        assert_eq!(escape_label_value("a\\b\nc\"d\re"), r#"a\\b\nc\"d\re"#);
    }

    /// br-asupersync-coxhdt: format_labels MUST route every label
    /// value through escape_label_value. An attacker who controls
    /// a label value containing a literal '"' must NOT be able to
    /// close the value string early and inject `,attacker_label="x"`
    /// into the resulting Prometheus output.
    #[test]
    fn format_labels_escapes_quote_to_prevent_label_injection() {
        let labels = vec![(
            "path".to_string(),
            r#"/api","attacker_label"="injected"#.to_string(),
        )];
        let rendered = StdoutExporter::format_labels(&labels);
        // The literal '"' in the value MUST appear as \" in the output.
        assert!(
            rendered.contains(r#"\""#),
            "format_labels failed to escape attacker quote: {rendered}"
        );
        // The fragment that would inject if escaping failed must NOT
        // appear as a parseable second label.
        assert!(
            !rendered.contains(r#"","attacker_label"="injected"}"#),
            "format_labels permitted label injection: {rendered}"
        );
    }

    /// br-asupersync-coxhdt: a backslash in a label value is doubled,
    /// not consumed.
    #[test]
    fn format_labels_escapes_backslash_to_prevent_value_corruption() {
        let labels = vec![("k".to_string(), r"a\b".to_string())];
        let rendered = StdoutExporter::format_labels(&labels);
        assert!(rendered.contains(r"a\\b"));
    }
