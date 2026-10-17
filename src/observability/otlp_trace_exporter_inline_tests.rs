    use super::*;
    use std::time::Instant;

    fn create_test_span(span_id: &str, name: &str) -> OtlpSpan {
        OtlpSpan {
            span_id: span_id.to_string(),
            name: name.to_string(),
            start_time_unix_nano: 1000000000,
            end_time_unix_nano: 1000001000,
            attributes: vec![("service".to_string(), "test".to_string())],
            trace_flags: Some(0x01), // Default to sampled for backward compatibility
        }
    }

    fn create_test_batch(batch_id: u64, span_count: usize) -> SpanBatch {
        let spans = (0..span_count)
            .map(|i| create_test_span(&format!("span-{}-{}", batch_id, i), "test_operation"))
            .collect();

        SpanBatch {
            batch_id,
            spans,
            created_at: Instant::now(),
        }
    }

    /// **AUDIT TEST**: Verifies OTLP trace exporter load shedding under high load.
    ///
    /// **SCENARIO**: 10,000+ spans/sec arrive, batch_size=512, queue capacity=3
    /// **REQUIREMENT**: Spans are dropped when batch fills, oldest-drop behavior
    /// **METRICS**: `otel.exporter.dropped_spans` correctly reports dropped count
    #[test]
    fn audit_otlp_trace_exporter_high_load_shedding() {
        let memory_exporter = InMemoryOtlpHttpExporter::new(Duration::from_millis(1));
        let queue_capacity = 3;
        let batch_timeout = Duration::from_secs(1);

        let exporter = LoadSheddingTraceExporter::new(
            Box::new(memory_exporter.clone()),
            queue_capacity,
            batch_timeout,
        );

        // Create batches with 512 spans each (typical OTLP batch size)
        let batch_size = 512;
        let batches: Vec<SpanBatch> = (0..6).map(|i| create_test_batch(i, batch_size)).collect();

        // Submit batches beyond capacity to trigger load shedding
        for batch in &batches {
            let result = exporter.export(batch);
            assert!(
                result.is_ok(),
                "export should succeed even during load shedding"
            );
        }

        // Verify load shedding statistics
        let stats = exporter.load_shedding_stats();
        assert_eq!(stats.queue_capacity, 3, "queue capacity should be 3");
        assert_eq!(stats.queue_depth, 3, "queue should be at capacity");
        assert_eq!(
            stats.dropped_batches, 3,
            "should have dropped 3 oldest batches"
        );

        // **CRITICAL**: Verify dropped spans metric (OTLP compliance requirement)
        let expected_dropped_spans = 3 * batch_size as u64; // 3 batches × 512 spans each
        assert_eq!(
            exporter.dropped_spans_count(),
            expected_dropped_spans,
            "otel.exporter.dropped_spans must track total dropped spans"
        );

        // Process queue and verify only newest batches were preserved
        let processed = exporter
            .process_queue()
            .expect("queue processing should succeed");
        assert_eq!(processed, 3, "should process 3 remaining batches");

        let exported = memory_exporter.exported_batches();
        assert_eq!(exported.len(), 3, "should have exported 3 batches");

        // Verify NEWEST batches were preserved (batch IDs 3, 4, 5)
        let exported_batch_ids: Vec<u64> = exported.iter().map(|b| b.batch_id).collect();
        assert_eq!(
            exported_batch_ids,
            vec![3, 4, 5],
            "should preserve NEWEST batches and drop oldest (0,1,2)"
        );

        println!("✅ OTLP TRACE EXPORTER LOAD SHEDDING AUDIT PASSED");
        println!("   Queue capacity: {}", stats.queue_capacity);
        println!("   Dropped batches: {}", stats.dropped_batches);
        println!("   Dropped spans: {}", exporter.dropped_spans_count());
        println!("   Preserved batches: {:?}", exported_batch_ids);
    }

    /// **AUDIT TEST**: Normal operation without load shedding.
    #[test]
    fn audit_normal_operation_no_shedding() {
        let memory_exporter = InMemoryOtlpHttpExporter::new(Duration::from_millis(1));
        let exporter = LoadSheddingTraceExporter::new(
            Box::new(memory_exporter.clone()),
            10, // Large capacity
            Duration::from_secs(1),
        );

        // Submit batches within capacity
        for i in 0..5 {
            let batch = create_test_batch(i, 100);
            exporter.export(&batch).expect("export should succeed");
        }

        let stats = exporter.load_shedding_stats();
        assert_eq!(stats.dropped_batches, 0, "no batches should be dropped");
        assert_eq!(
            exporter.dropped_spans_count(),
            0,
            "no spans should be dropped"
        );

        exporter
            .process_queue()
            .expect("queue processing should succeed");
        let exported_spans = memory_exporter.exported_span_count();
        assert_eq!(exported_spans, 500, "all 500 spans should be exported");

        println!("✅ NORMAL OPERATION AUDIT PASSED - No load shedding");
    }

    /// **AUDIT TEST**: FIFO order preservation during load shedding.
    #[test]
    fn audit_fifo_order_preserved_during_shedding() {
        let memory_exporter = InMemoryOtlpHttpExporter::new(Duration::from_millis(1));
        let exporter = LoadSheddingTraceExporter::new(
            Box::new(memory_exporter.clone()),
            2, // Very small capacity
            Duration::from_secs(1),
        );

        // Submit 4 batches, expect FIFO processing of newest 2
        for i in 0..4 {
            let batch = create_test_batch(i, 10);
            exporter.export(&batch).expect("export should succeed");
        }

        exporter
            .process_queue()
            .expect("queue processing should succeed");
        let exported = memory_exporter.exported_batches();

        // Should export batches 2,3 in FIFO order (oldest batches 0,1 dropped)
        assert_eq!(exported.len(), 2, "should export 2 batches");
        assert_eq!(exported[0].batch_id, 2, "first exported should be batch 2");
        assert_eq!(exported[1].batch_id, 3, "second exported should be batch 3");

        println!("✅ FIFO ORDER AUDIT PASSED - Correct processing order maintained");
    }

    /// br-asupersync-eup06n: regression test for the multi-producer overflow
    /// race. Many concurrent producers + a tiny capacity used to trip the
    /// `assert!(...push.is_ok(), "overflow replacement must succeed")` panic
    /// on a saturated queue. With `force_push` the enqueue must always make
    /// progress without panicking, and the dropped count must equal
    /// (total_pushes - capacity).
    #[test]
    fn enqueue_does_not_panic_under_concurrent_overload() {
        use std::sync::Arc;
        use std::thread;

        const CAPACITY: usize = 8;
        const PRODUCERS: usize = 16;
        const PER_PRODUCER: usize = 4096;

        let queue: Arc<BoundedExportQueue<u64>> = Arc::new(BoundedExportQueue::new(CAPACITY));

        let mut handles = Vec::with_capacity(PRODUCERS);
        for producer in 0..PRODUCERS {
            let queue = Arc::clone(&queue);
            handles.push(thread::spawn(move || {
                let base = (producer as u64) * (PER_PRODUCER as u64);
                for offset in 0..PER_PRODUCER {
                    let _ = queue.enqueue(base + offset as u64);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("producer must not panic");
        }

        let dropped = queue.dropped_count();
        let len = queue.len();
        let total = (PRODUCERS * PER_PRODUCER) as u64;
        assert_eq!(
            dropped + len as u64,
            total,
            "every push must either land in the queue or be counted as dropped",
        );
        assert!(len <= CAPACITY, "queue must respect capacity");
        assert_eq!(
            dropped,
            total - len as u64,
            "dropped count must equal total minus retained",
        );
    }

    /// Fails every export while `fail` is set, then records into `inner`.
    #[derive(Debug)]
    struct FlakyExporter {
        fail: Arc<std::sync::atomic::AtomicBool>,
        inner: InMemoryOtlpHttpExporter,
    }

    impl TraceExporter for FlakyExporter {
        fn export(&self, batch: &SpanBatch) -> Result<(), ExportError> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(ExportError::Unavailable);
            }
            self.inner.export(batch)
        }

        fn flush(&self) -> Result<(), ExportError> {
            Ok(())
        }
    }

    /// A batch whose export failed had already been taken off the queue and
    /// was dropped uncounted, so each flush during an outage silently lost
    /// one more batch.
    #[test]
    fn a_failed_export_keeps_its_batch_for_the_next_flush() {
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let memory = InMemoryOtlpHttpExporter::new(Duration::ZERO);
        let exporter = LoadSheddingTraceExporter::new(
            Box::new(FlakyExporter {
                fail: Arc::clone(&fail),
                inner: memory.clone(),
            }),
            10,
            Duration::from_secs(1),
        );
        for id in 0..3 {
            exporter.export(&create_test_batch(id, 2)).unwrap();
        }
        for _ in 0..3 {
            assert!(exporter.flush().is_err(), "the collector is down");
        }
        assert_eq!(
            exporter.load_shedding_stats().queue_depth,
            3,
            "the batches that failed are still pending"
        );
        assert_eq!(exporter.dropped_spans_count(), 0);

        fail.store(false, Ordering::SeqCst);
        exporter.flush().expect("the collector is back");
        assert_eq!(memory.exported_span_count(), 6);
        assert_eq!(exporter.load_shedding_stats().queue_depth, 0);
    }

    /// process_queue stopped as soon as a batch was older than batch_timeout,
    /// so after an outage flush exported one batch of the backlog and
    /// returned Ok with the rest still queued.
    #[test]
    fn flush_exports_a_backlog_of_old_batches() {
        let memory = InMemoryOtlpHttpExporter::new(Duration::ZERO);
        let exporter =
            LoadSheddingTraceExporter::new(Box::new(memory.clone()), 10, Duration::from_secs(1));
        for id in 0..3 {
            let mut batch = create_test_batch(id, 2);
            batch.created_at = Instant::now()
                .checked_sub(Duration::from_secs(2))
                .expect("an instant 2 s ago");
            exporter.export(&batch).unwrap();
        }
        exporter.flush().expect("flush");
        assert_eq!(memory.exported_batches().len(), 3);
        assert_eq!(exporter.load_shedding_stats().queue_depth, 0);
    }
