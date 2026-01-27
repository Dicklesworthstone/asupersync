#![allow(missing_docs)]

#[macro_use]
mod common;

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
