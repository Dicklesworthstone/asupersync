    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use insta::assert_json_snapshot;
    use parking_lot::Mutex;
    use std::io::{self, Cursor, Write};
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl SharedBuffer {
        fn snapshot(&self) -> Vec<u8> {
            self.0.lock().clone()
        }

        fn snapshot_string(&self) -> String {
            String::from_utf8(self.snapshot()).expect("shared buffer should contain UTF-8")
        }
    }

    impl Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[derive(Serialize)]
    struct ProgressRenderSnapshot {
        indeterminate: String,
        zero_percent: String,
        fifty_percent: String,
        one_hundred_percent: String,
    }

    fn capture_human_progress(event: ProgressEvent) -> String {
        let shared = SharedBuffer::default();
        let inspector = shared.clone();
        let mut reporter = ProgressReporter::with_writer(OutputFormat::Human, shared);
        reporter
            .report(event)
            .expect("human progress event should render");
        inspector.snapshot_string()
    }

    #[test]
    fn progress_event_percentage() {
        init_test("progress_event_percentage");
        let event = ProgressEvent::update(50, 100, "test");
        let percentage = event.percentage();
        crate::assert_with_log!(
            percentage == Some(50.0),
            "percentage 50",
            Some(50.0),
            percentage
        );

        let event = ProgressEvent::update(25, 100, "test");
        let percentage = event.percentage();
        crate::assert_with_log!(
            percentage == Some(25.0),
            "percentage 25",
            Some(25.0),
            percentage
        );

        let event = ProgressEvent::started("test");
        let percentage: Option<f64> = event.percentage();
        crate::assert_with_log!(
            percentage.is_none(),
            "percentage none",
            "None",
            format!("{:?}", percentage)
        );

        let event = ProgressEvent::update(0, 0, "test");
        let percentage: Option<f64> = event.percentage();
        crate::assert_with_log!(
            percentage.is_none(),
            "percentage none for 0/0",
            "None",
            format!("{:?}", percentage)
        );
        crate::test_complete!("progress_event_percentage");
    }

    #[test]
    fn progress_event_serializes() {
        init_test("progress_event_serializes");
        let event = ProgressEvent::update(5, 10, "Processing")
            .operation("sync")
            .elapsed(Duration::from_millis(1500));

        let json = serde_json::to_string(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        crate::assert_with_log!(
            parsed["kind"] == "update",
            "kind",
            "update",
            parsed["kind"].clone()
        );
        crate::assert_with_log!(
            parsed["current"] == 5,
            "current",
            5,
            parsed["current"].clone()
        );
        crate::assert_with_log!(parsed["total"] == 10, "total", 10, parsed["total"].clone());
        crate::assert_with_log!(
            parsed["message"] == "Processing",
            "message",
            "Processing",
            parsed["message"].clone()
        );
        crate::assert_with_log!(
            parsed["operation"] == "sync",
            "operation",
            "sync",
            parsed["operation"].clone()
        );
        crate::assert_with_log!(
            parsed["elapsed_ms"] == 1500,
            "elapsed_ms",
            1500,
            parsed["elapsed_ms"].clone()
        );
        crate::test_complete!("progress_event_serializes");
    }

    #[test]
    fn progress_reporter_json_output() {
        init_test("progress_reporter_json_output");

        let cursor = Cursor::new(Vec::new());
        let mut reporter =
            ProgressReporter::with_writer(OutputFormat::Json, cursor).operation("test");

        reporter.start("Starting").unwrap();
        crate::test_complete!("progress_reporter_json_output");
    }

    #[test]
    fn progress_reporter_tracks_elapsed() {
        init_test("progress_reporter_tracks_elapsed");
        let reporter = ProgressReporter::new(OutputFormat::Human);
        std::thread::sleep(Duration::from_millis(10));
        let elapsed = reporter.elapsed().as_millis();
        crate::assert_with_log!(elapsed >= 10, "elapsed >= 10ms", ">= 10ms", elapsed);
        crate::test_complete!("progress_reporter_tracks_elapsed");
    }

    #[test]
    fn progress_kind_serializes_snake_case() {
        init_test("progress_kind_serializes_snake_case");
        let json = serde_json::to_string(&ProgressKind::Started).unwrap();
        crate::assert_with_log!(json == "\"started\"", "started json", "\"started\"", json);

        let json = serde_json::to_string(&ProgressKind::Completed).unwrap();
        crate::assert_with_log!(
            json == "\"completed\"",
            "completed json",
            "\"completed\"",
            json
        );
        crate::test_complete!("progress_kind_serializes_snake_case");
    }

    #[test]
    fn progress_kind_debug() {
        init_test("progress_kind_debug");
        let dbg = format!("{:?}", ProgressKind::Started);
        assert_eq!(dbg, "Started");
        let dbg = format!("{:?}", ProgressKind::Update);
        assert_eq!(dbg, "Update");
        let dbg = format!("{:?}", ProgressKind::Completed);
        assert_eq!(dbg, "Completed");
        let dbg = format!("{:?}", ProgressKind::Failed);
        assert_eq!(dbg, "Failed");
        let dbg = format!("{:?}", ProgressKind::Cancelled);
        assert_eq!(dbg, "Cancelled");
        crate::test_complete!("progress_kind_debug");
    }

    #[test]
    fn progress_kind_clone_copy() {
        init_test("progress_kind_clone_copy");
        let k = ProgressKind::Completed;
        let k2 = k;
        let k3 = k;
        assert_eq!(k2, k3);
        crate::test_complete!("progress_kind_clone_copy");
    }

    #[test]
    fn progress_kind_eq() {
        init_test("progress_kind_eq");
        assert_eq!(ProgressKind::Started, ProgressKind::Started);
        assert_ne!(ProgressKind::Started, ProgressKind::Failed);
        crate::test_complete!("progress_kind_eq");
    }

    #[test]
    fn progress_event_debug() {
        init_test("progress_event_debug");
        let ev = ProgressEvent::started("hello");
        let dbg = format!("{ev:?}");
        assert!(dbg.contains("ProgressEvent"));
        crate::test_complete!("progress_event_debug");
    }

    #[test]
    fn progress_event_clone() {
        init_test("progress_event_clone");
        let ev = ProgressEvent::update(3, 10, "cloning");
        let ev2 = ev;
        assert_eq!(ev2.kind, ProgressKind::Update);
        assert_eq!(ev2.current, Some(3));
        assert_eq!(ev2.total, Some(10));
        assert_eq!(ev2.message, "cloning");
        crate::test_complete!("progress_event_clone");
    }

    #[test]
    fn progress_event_started() {
        init_test("progress_event_started");
        let ev = ProgressEvent::started("begin");
        assert_eq!(ev.kind, ProgressKind::Started);
        assert_eq!(ev.message, "begin");
        assert!(ev.current.is_none());
        assert!(ev.total.is_none());
        assert!(ev.elapsed_ms.is_none());
        assert!(ev.operation.is_none());
        crate::test_complete!("progress_event_started");
    }

    #[test]
    fn progress_event_completed() {
        init_test("progress_event_completed");
        let ev = ProgressEvent::completed("done");
        assert_eq!(ev.kind, ProgressKind::Completed);
        assert_eq!(ev.message, "done");
        crate::test_complete!("progress_event_completed");
    }

    #[test]
    fn progress_event_failed() {
        init_test("progress_event_failed");
        let ev = ProgressEvent::failed("error");
        assert_eq!(ev.kind, ProgressKind::Failed);
        assert_eq!(ev.message, "error");
        crate::test_complete!("progress_event_failed");
    }

    #[test]
    fn progress_event_cancelled() {
        init_test("progress_event_cancelled");
        let ev = ProgressEvent::cancelled("abort");
        assert_eq!(ev.kind, ProgressKind::Cancelled);
        assert_eq!(ev.message, "abort");
        crate::test_complete!("progress_event_cancelled");
    }

    #[test]
    fn progress_event_update_fields() {
        init_test("progress_event_update_fields");
        let ev = ProgressEvent::update(5, 20, "processing");
        assert_eq!(ev.kind, ProgressKind::Update);
        assert_eq!(ev.current, Some(5));
        assert_eq!(ev.total, Some(20));
        assert_eq!(ev.message, "processing");
        crate::test_complete!("progress_event_update_fields");
    }

    #[test]
    fn progress_event_operation_builder() {
        init_test("progress_event_operation_builder");
        let ev = ProgressEvent::started("go").operation("sync");
        assert_eq!(ev.operation, Some("sync".to_string()));
        crate::test_complete!("progress_event_operation_builder");
    }

    #[test]
    fn progress_event_elapsed_builder() {
        init_test("progress_event_elapsed_builder");
        let ev = ProgressEvent::completed("done").elapsed(Duration::from_millis(2500));
        assert_eq!(ev.elapsed_ms, Some(2500));
        crate::test_complete!("progress_event_elapsed_builder");
    }

    #[test]
    fn progress_event_percentage_100() {
        init_test("progress_event_percentage_100");
        let ev = ProgressEvent::update(100, 100, "done");
        assert_eq!(ev.percentage(), Some(100.0));
        crate::test_complete!("progress_event_percentage_100");
    }

    #[test]
    fn progress_event_percentage_clamps_above_100() {
        init_test("progress_event_percentage_clamps_above_100");
        let ev = ProgressEvent::update(15, 10, "over-complete");
        assert_eq!(ev.percentage(), Some(100.0));
        crate::test_complete!("progress_event_percentage_clamps_above_100");
    }

    #[test]
    fn progress_reporter_with_writer_and_operation() {
        init_test("progress_reporter_with_writer_and_operation");
        let cursor = Cursor::new(Vec::new());
        let mut reporter =
            ProgressReporter::with_writer(OutputFormat::Json, cursor).operation("test_op");
        reporter.start("starting").unwrap();
        reporter.update(1, 10, "step 1").unwrap();
        reporter.complete("finished").unwrap();
        // No panic means success
        crate::test_complete!("progress_reporter_with_writer_and_operation");
    }

    #[test]
    fn progress_reporter_fail_and_cancel() {
        init_test("progress_reporter_fail_and_cancel");
        let cursor = Cursor::new(Vec::new());
        let mut reporter = ProgressReporter::with_writer(OutputFormat::Json, cursor);
        reporter.fail("oops").unwrap();
        // Create a separate reporter for cancel
        let cursor2 = Cursor::new(Vec::new());
        let mut reporter2 = ProgressReporter::with_writer(OutputFormat::Json, cursor2);
        reporter2.cancel("aborted").unwrap();
        crate::test_complete!("progress_reporter_fail_and_cancel");
    }

    #[test]
    fn progress_reporter_human_format() {
        init_test("progress_reporter_human_format");
        let cursor = Cursor::new(Vec::new());
        let mut reporter = ProgressReporter::with_writer(OutputFormat::Human, cursor);
        reporter.start("begin").unwrap();
        reporter.update(5, 10, "half").unwrap();
        reporter.complete("end").unwrap();
        crate::test_complete!("progress_reporter_human_format");
    }

    #[test]
    fn progress_reporter_human_clamps_over_100_percent() {
        init_test("progress_reporter_human_clamps_over_100_percent");
        let cursor = Cursor::new(Vec::new());
        let mut reporter = ProgressReporter::with_writer(OutputFormat::Human, cursor);
        reporter.start("begin").unwrap();
        reporter.update(15, 10, "over-complete").unwrap();
        reporter.complete("done").unwrap();
        crate::test_complete!("progress_reporter_human_clamps_over_100_percent");
    }

    #[test]
    fn progress_reporter_human_terminal_event_replaces_update_line() {
        init_test("progress_reporter_human_terminal_event_replaces_update_line");
        let shared = SharedBuffer::default();
        let inspector = shared.clone();
        let mut reporter = ProgressReporter::with_writer(OutputFormat::Human, shared);
        reporter.start("begin").unwrap();
        reporter.update(5, 10, "half").unwrap();
        reporter.complete("end").unwrap();

        let output = String::from_utf8(inspector.snapshot()).unwrap();
        crate::assert_with_log!(
            output.contains("half\r"),
            "update line terminated with carriage return",
            "contains `half\\r`",
            output
        );
        crate::assert_with_log!(
            !output.contains("half✓"),
            "terminal line not concatenated to update line",
            "does not contain `half✓`",
            output
        );
        crate::test_complete!("progress_reporter_human_terminal_event_replaces_update_line");
    }

    #[test]
    fn progress_reporter_tsv_format() {
        init_test("progress_reporter_tsv_format");
        let cursor = Cursor::new(Vec::new());
        let mut reporter = ProgressReporter::with_writer(OutputFormat::Tsv, cursor);
        reporter.start("tsv test").unwrap();
        reporter.complete("done").unwrap();
        crate::test_complete!("progress_reporter_tsv_format");
    }

    #[test]
    fn progress_reporter_json_pretty_format() {
        init_test("progress_reporter_json_pretty_format");
        let cursor = Cursor::new(Vec::new());
        let mut reporter = ProgressReporter::with_writer(OutputFormat::JsonPretty, cursor);
        reporter.start("pretty test").unwrap();
        reporter.complete("done").unwrap();
        crate::test_complete!("progress_reporter_json_pretty_format");
    }

    #[test]
    fn progress_reporter_tsv_clamps_percentage_above_100() {
        init_test("progress_reporter_tsv_clamps_percentage_above_100");
        let shared = SharedBuffer::default();
        let inspector = shared.clone();
        let mut reporter = ProgressReporter::with_writer(OutputFormat::Tsv, shared);
        reporter.update(15, 10, "over-complete").unwrap();

        let output = String::from_utf8(inspector.snapshot()).unwrap();
        let line = output.trim_end();
        crate::assert_with_log!(
            line.starts_with("Update\t100.0\t"),
            "tsv percentage is clamped",
            "prefix `Update\\t100.0\\t`",
            line
        );
        crate::test_complete!("progress_reporter_tsv_clamps_percentage_above_100");
    }

    #[test]
    fn progress_reporter_with_color() {
        init_test("progress_reporter_with_color");
        let reporter = ProgressReporter::new(OutputFormat::Human).with_color(ColorChoice::Never);
        let dbg = format!("{:?}", reporter.elapsed());
        assert!(!dbg.is_empty());
        crate::test_complete!("progress_reporter_with_color");
    }

    #[test]
    fn progress_reporter_auto_color_follows_target_terminal_state() {
        init_test("progress_reporter_auto_color_follows_target_terminal_state");
        let shared = SharedBuffer::default();
        let inspector = shared.clone();
        let mut reporter = ProgressReporter::with_writer(OutputFormat::Human, shared)
            .with_color(ColorChoice::Auto);
        reporter.target_is_terminal = true;

        reporter.start("begin").unwrap();

        let output = String::from_utf8(inspector.snapshot()).unwrap();
        crate::assert_with_log!(
            output.contains("\x1b[34m"),
            "started event color follows terminal target",
            "contains blue ANSI prefix",
            output
        );
        crate::test_complete!("progress_reporter_auto_color_follows_target_terminal_state");
    }

    #[test]
    fn progress_reporter_auto_color_avoids_redirected_target() {
        init_test("progress_reporter_auto_color_avoids_redirected_target");
        let shared = SharedBuffer::default();
        let inspector = shared.clone();
        let mut reporter = ProgressReporter::with_writer(OutputFormat::Human, shared)
            .with_color(ColorChoice::Auto);
        reporter.target_is_terminal = false;

        reporter.start("begin").unwrap();

        let output = String::from_utf8(inspector.snapshot()).unwrap();
        crate::assert_with_log!(
            !output.contains("\x1b["),
            "auto color avoids redirected target",
            "no ANSI escapes",
            output
        );
        crate::test_complete!("progress_reporter_auto_color_avoids_redirected_target");
    }

    #[test]
    fn progress_bar_render_snapshot() {
        init_test("progress_bar_render_snapshot");

        let snapshot = ProgressRenderSnapshot {
            indeterminate: capture_human_progress(ProgressEvent::started("Connecting to cluster")),
            zero_percent: capture_human_progress(ProgressEvent::update(0, 100, "Queued")),
            fifty_percent: capture_human_progress(ProgressEvent::update(50, 100, "Syncing")),
            one_hundred_percent: capture_human_progress(ProgressEvent::update(
                100,
                100,
                "Finalize verification",
            )),
        };

        assert_json_snapshot!("progress_bar_render_states", snapshot);
        crate::test_complete!("progress_bar_render_snapshot");
    }
