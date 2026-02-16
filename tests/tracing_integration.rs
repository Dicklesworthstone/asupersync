#![allow(missing_docs)]

#[macro_use]
mod common;

/// Tests for Cx structured tracing, spans, and request correlation.
/// These use the internal LogCollector and do not require the tracing-integration feature.
mod cx_tracing_tests {
    use crate::common::*;
    use asupersync::Cx;
    use asupersync::observability::{LogCollector, ObservabilityConfig};

    fn make_cx_with_collector() -> (Cx, LogCollector) {
        let config = ObservabilityConfig::testing();
        let collector = config.create_collector();
        let cx: Cx = Cx::for_testing();
        cx.set_log_collector(collector.clone());
        (cx, collector)
    }

    #[test]
    fn trace_with_fields_emits_structured_entry() {
        init_test_logging();
        test_phase!("trace_with_fields_emits_structured_entry");

        let (cx, collector) = make_cx_with_collector();

        cx.trace_with_fields(
            "request handled",
            &[("method", "GET"), ("path", "/api/users"), ("status", "200")],
        );

        let entries = collector.peek();
        let entry = entries
            .iter()
            .find(|e| e.message() == "request handled")
            .expect("should find trace entry");

        let fields: Vec<_> = entry.fields().collect();
        let has_method = fields.iter().any(|&(k, v)| k == "method" && v == "GET");
        assert_with_log!(has_method, "has method field", true, has_method);
        let has_path = fields
            .iter()
            .any(|&(k, v)| k == "path" && v == "/api/users");
        assert_with_log!(has_path, "has path field", true, has_path);
        let has_status = fields.iter().any(|&(k, v)| k == "status" && v == "200");
        assert_with_log!(has_status, "has status field", true, has_status);

        test_complete!("trace_with_fields_emits_structured_entry");
    }

    #[test]
    fn enter_span_creates_child_context() {
        init_test_logging();
        test_phase!("enter_span_creates_child_context");

        let (cx, collector) = make_cx_with_collector();

        let outer_span = cx.diagnostic_context().span_id();

        {
            let _guard = cx.enter_span("parse_request");
            let inner_ctx = cx.diagnostic_context();
            let inner_span = inner_ctx.span_id();

            // Should have a new span id
            assert_with_log!(
                inner_span != outer_span,
                "new span id",
                true,
                inner_span != outer_span
            );

            // Parent should be the outer span
            let parent = inner_ctx.parent_span_id();
            assert_with_log!(
                parent == outer_span,
                "parent matches outer",
                true,
                parent == outer_span
            );

            // Custom field should be set
            let name = inner_ctx.custom("span.name");
            assert_with_log!(
                name == Some("parse_request"),
                "span name",
                "parse_request",
                name
            );
        }

        // After guard drop, context should be restored
        let restored_span = cx.diagnostic_context().span_id();
        assert_with_log!(
            restored_span == outer_span,
            "span restored",
            true,
            restored_span == outer_span
        );

        // Should have enter and exit log entries
        let entries = collector.peek();
        let has_enter = entries
            .iter()
            .any(|e| e.message().contains("span enter: parse_request"));
        assert_with_log!(has_enter, "span enter logged", true, has_enter);
        let has_exit = entries
            .iter()
            .any(|e| e.message().contains("span exit: parse_request"));
        assert_with_log!(has_exit, "span exit logged", true, has_exit);

        test_complete!("enter_span_creates_child_context");
    }

    #[test]
    fn nested_spans_form_hierarchy() {
        init_test_logging();
        test_phase!("nested_spans_form_hierarchy");

        let (cx, _collector) = make_cx_with_collector();

        let root_span = cx.diagnostic_context().span_id();

        {
            let _outer = cx.enter_span("outer");
            let outer_span = cx.diagnostic_context().span_id();
            let outer_parent = cx.diagnostic_context().parent_span_id();
            assert_with_log!(
                outer_parent == root_span,
                "outer parent is root",
                true,
                outer_parent == root_span
            );

            {
                let _inner = cx.enter_span("inner");
                let inner_parent = cx.diagnostic_context().parent_span_id();
                assert_with_log!(
                    inner_parent == outer_span,
                    "inner parent is outer",
                    true,
                    inner_parent == outer_span
                );
            }

            // After inner drop, should be back to outer
            let current = cx.diagnostic_context().span_id();
            assert_with_log!(
                current == outer_span,
                "restored to outer",
                true,
                current == outer_span
            );
        }

        // After outer drop, should be back to root
        let current = cx.diagnostic_context().span_id();
        assert_with_log!(
            current == root_span,
            "restored to root",
            true,
            current == root_span
        );

        test_complete!("nested_spans_form_hierarchy");
    }

    #[test]
    fn request_id_correlation() {
        init_test_logging();
        test_phase!("request_id_correlation");

        let (cx, collector) = make_cx_with_collector();

        // Initially no request ID
        let initial = cx.request_id();
        assert_with_log!(
            initial.is_none(),
            "no initial request_id",
            true,
            initial.is_none()
        );

        // Set request ID
        cx.set_request_id("req-abc-123");

        let id = cx.request_id();
        assert_with_log!(
            id.as_deref() == Some("req-abc-123"),
            "request_id set",
            "req-abc-123",
            id
        );

        // Log entries should include request_id
        cx.trace("after setting request_id");
        let entries = collector.peek();
        let entry = entries
            .iter()
            .find(|e| e.message() == "after setting request_id")
            .expect("should find entry");
        let fields: Vec<_> = entry.fields().collect();
        let has_req_id = fields
            .iter()
            .any(|&(k, v)| k == "request_id" && v == "req-abc-123");
        assert_with_log!(has_req_id, "log has request_id", true, has_req_id);

        test_complete!("request_id_correlation");
    }

    #[test]
    fn request_id_propagates_to_spans() {
        init_test_logging();
        test_phase!("request_id_propagates_to_spans");

        let (cx, collector) = make_cx_with_collector();

        cx.set_request_id("req-xyz-789");

        {
            let _guard = cx.enter_span("handle_request");
            cx.trace("inside span");
        }

        let entries = collector.peek();
        let entry = entries
            .iter()
            .find(|e| e.message() == "inside span")
            .expect("should find entry");
        let fields: Vec<_> = entry.fields().collect();
        let has_req_id = fields
            .iter()
            .any(|&(k, v)| k == "request_id" && v == "req-xyz-789");
        assert_with_log!(has_req_id, "request_id in span log", true, has_req_id);

        test_complete!("request_id_propagates_to_spans");
    }
}

#[cfg(feature = "tracing-integration")]
mod tests {
    use crate::common::*;
    use asupersync::runtime::RuntimeState;
    use asupersync::types::Budget;
    use std::sync::{Arc, Mutex};
    use tracing::Subscriber;
    use tracing_subscriber::layer::{Context, Layer};
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::registry::LookupSpan;

    struct SpanRecorder {
        spans: Arc<Mutex<Vec<String>>>,
    }

    impl<S> Layer<S> for SpanRecorder
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::Id,
            _ctx: Context<'_, S>,
        ) {
            if attrs.metadata().name() == "region" {
                let mut spans = self.spans.lock().unwrap();
                spans.push(format!("region_new: {:?}", attrs));
            }
        }

        fn on_record(
            &self,
            _id: &tracing::Id,
            values: &tracing::span::Record<'_>,
            _ctx: Context<'_, S>,
        ) {
            let mut spans = self.spans.lock().unwrap();
            spans.push(format!("region_record: {:?}", values));
        }

        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut spans = self.spans.lock().unwrap();
            spans.push(format!("event: {:?}", event));
        }
    }

    #[test]
    fn verify_region_spans() {
        init_test_logging();
        test_phase!("verify_region_spans");
        test_section!("setup");
        let spans = Arc::new(Mutex::new(Vec::new()));
        let recorder = SpanRecorder {
            spans: spans.clone(),
        };

        let subscriber = tracing_subscriber::registry().with(recorder);

        tracing::subscriber::with_default(subscriber, || {
            test_section!("exercise");
            let mut state = RuntimeState::new();
            let region = state.create_root_region(Budget::INFINITE);

            // Should have created a span
            {
                let spans = spans.lock().unwrap();
                let span_count = spans.len();
                assert_with_log!(
                    span_count > 0,
                    "should have recorded region span creation",
                    "> 0",
                    span_count
                );
                let creation = spans.iter().find(|s| s.contains("region_new")).unwrap();
                assert_with_log!(
                    creation.contains("region_id"),
                    "region_new should include region_id",
                    true,
                    creation.contains("region_id")
                );
                assert_with_log!(
                    creation.contains("state"),
                    "region_new should include state",
                    true,
                    creation.contains("state")
                );
            }

            // Close the region
            let region_record = state.region_mut(region).expect("region");
            region_record.begin_close(None);

            // Check for update
            {
                let spans = spans.lock().unwrap();
                let has_closing = spans
                    .iter()
                    .any(|s| s.contains("region_record") && s.contains("Closing"));
                assert_with_log!(
                    has_closing,
                    "should record Closing state",
                    true,
                    has_closing
                );
            }

            region_record.begin_finalize();
            region_record.complete_close();

            // Check for final update
            {
                let spans = spans.lock().unwrap();
                let has_closed = spans
                    .iter()
                    .any(|s| s.contains("region_record") && s.contains("Closed"));
                assert_with_log!(has_closed, "should record Closed state", true, has_closed);
            }
        });
        test_complete!("verify_region_spans");
    }

    #[test]
    fn verify_task_logs() {
        init_test_logging();
        test_phase!("verify_task_logs");
        test_section!("setup");
        let logs = Arc::new(Mutex::new(Vec::new()));
        let recorder = SpanRecorder {
            spans: logs.clone(),
        };
        let subscriber = tracing_subscriber::registry().with(recorder);

        tracing::subscriber::with_default(subscriber, || {
            test_section!("exercise");
            let mut state = RuntimeState::new();
            let region = state.create_root_region(Budget::INFINITE);

            // Create a task
            let _ = state.create_task(region, Budget::INFINITE, async { 42 });

            // Check for log
            {
                let logs = logs.lock().unwrap();
                let has_task_log = logs
                    .iter()
                    .any(|s| s.contains("event") && s.contains("task created"));
                assert_with_log!(
                    has_task_log,
                    "should record task creation log",
                    true,
                    has_task_log
                );
            }
        });
        test_complete!("verify_task_logs");
    }
}
