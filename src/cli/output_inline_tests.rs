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
    use serde::Serializer;
    use serde::ser::Error as _;
    use serde_json::Value;
    use std::io::{self, Cursor, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Serialize)]
    struct TestItem {
        id: u32,
        name: String,
    }

    impl Outputtable for TestItem {
        fn human_format(&self) -> String {
            format!("Item {}: {}", self.id, self.name)
        }

        fn tsv_format(&self) -> String {
            format!("{}\t{}", self.id, self.name)
        }
    }

    #[derive(Clone, Debug, Serialize)]
    #[serde(rename_all = "snake_case")]
    enum JsonModeState {
        Normal,
        Warn,
        Error,
    }

    #[derive(Clone, Serialize)]
    struct JsonModeStatusItem {
        state: JsonModeState,
        message: String,
        generated_at: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<String>,
    }

    impl Outputtable for JsonModeStatusItem {
        fn human_format(&self) -> String {
            match &self.code {
                Some(code) => format!("{:?}: {} ({code})", self.state, self.message),
                None => format!("{:?}: {}", self.state, self.message),
            }
        }
    }

    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl SharedBuffer {
        fn snapshot(&self) -> Vec<u8> {
            self.0.lock().clone()
        }

        fn snapshot_string(&self) -> String {
            String::from_utf8(self.snapshot()).expect("snapshot should be utf-8")
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

    #[derive(Clone)]
    struct FlushFailWriter {
        buffer: SharedBuffer,
        flush_calls: Arc<AtomicUsize>,
        fail_on_flush_call: usize,
    }

    impl FlushFailWriter {
        fn new(fail_on_flush_call: usize) -> Self {
            Self {
                buffer: SharedBuffer::default(),
                flush_calls: Arc::new(AtomicUsize::new(0)),
                fail_on_flush_call,
            }
        }

        fn snapshot_string(&self) -> String {
            self.buffer.snapshot_string()
        }

        fn flush_count(&self) -> usize {
            self.flush_calls.load(Ordering::SeqCst)
        }
    }

    impl Write for FlushFailWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buffer.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            let call = self.flush_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call == self.fail_on_flush_call {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("synthetic flush failure on call {call}"),
                ))
            } else {
                Ok(())
            }
        }
    }

    struct FailingItem;

    impl Serialize for FailingItem {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Err(S::Error::custom("synthetic serialize failure"))
        }
    }

    impl Outputtable for FailingItem {
        fn human_format(&self) -> String {
            "failing-item".to_string()
        }
    }

    #[derive(Serialize)]
    struct JsonRendererSuccessSnapshot {
        json_raw: String,
        json_value: Value,
        json_pretty_raw: String,
        json_pretty_value: Value,
        stream_json_raw: String,
        stream_json_values: Vec<Value>,
    }

    #[derive(Serialize)]
    struct JsonRendererFailureSnapshot {
        error_kind: String,
        error_message: String,
        flush_calls: usize,
        written_raw: String,
        written_values: Vec<Value>,
    }

    #[derive(Serialize)]
    struct JsonRendererFullFailureSnapshot {
        error_kind: String,
        error_message: String,
        written_raw: String,
        written_bytes: usize,
    }

    #[derive(Serialize)]
    struct JsonRendererStateSnapshot {
        json_raw: String,
        json_value: Value,
        json_pretty_raw: String,
        json_pretty_value: Value,
        stream_json_raw: String,
        stream_json_values: Vec<Value>,
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn parse_json_document(raw: &str) -> Value {
        serde_json::from_str(raw.trim_end()).expect("snapshot json should parse")
    }

    fn parse_json_lines(raw: &str) -> Vec<Value> {
        raw.lines()
            .map(|line| serde_json::from_str(line).expect("streamed json line should parse"))
            .collect()
    }

    fn synthetic_timestamp(seed: u64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch");
        format!(
            "2026-04-21T09:15:{:02}.{:09}Z",
            (now.as_secs().wrapping_add(seed)) % 60,
            now.subsec_nanos()
        )
    }

    fn scrub_generated_at(value: Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(
                map.into_iter()
                    .map(|(key, value)| {
                        let value = if key == "generated_at" {
                            Value::String("<scrubbed-timestamp>".to_string())
                        } else {
                            scrub_generated_at(value)
                        };
                        (key, value)
                    })
                    .collect(),
            ),
            Value::Array(values) => {
                Value::Array(values.into_iter().map(scrub_generated_at).collect())
            }
            other => other,
        }
    }

    fn scrub_json_document_raw(raw: &str, pretty: bool) -> String {
        let value = scrub_generated_at(parse_json_document(raw));
        let mut rendered = if pretty {
            serde_json::to_string_pretty(&value).expect("scrubbed pretty json should serialize")
        } else {
            serde_json::to_string(&value).expect("scrubbed json should serialize")
        };
        rendered.push('\n');
        rendered
    }

    fn scrub_json_lines_raw(raw: &str) -> String {
        let mut rendered = String::new();
        for value in parse_json_lines(raw).into_iter().map(scrub_generated_at) {
            rendered.push_str(
                &serde_json::to_string(&value).expect("scrubbed json line should serialize"),
            );
            rendered.push('\n');
        }
        rendered
    }

    #[test]
    fn output_format_default_is_human() {
        init_test("output_format_default_is_human");
        let is_human = matches!(OutputFormat::default(), OutputFormat::Human);
        crate::assert_with_log!(is_human, "default is human", true, is_human);
        crate::test_complete!("output_format_default_is_human");
    }

    #[test]
    fn output_format_is_json() {
        init_test("output_format_is_json");
        let json = OutputFormat::Json.is_json();
        crate::assert_with_log!(json, "json", true, json);
        let stream = OutputFormat::StreamJson.is_json();
        crate::assert_with_log!(stream, "stream json", true, stream);
        let pretty = OutputFormat::JsonPretty.is_json();
        crate::assert_with_log!(pretty, "json pretty", true, pretty);
        let human = OutputFormat::Human.is_json();
        crate::assert_with_log!(!human, "human not json", false, human);
        let tsv = OutputFormat::Tsv.is_json();
        crate::assert_with_log!(!tsv, "tsv not json", false, tsv);
        crate::test_complete!("output_format_is_json");
    }

    #[test]
    fn color_choice_never_returns_false() {
        init_test("color_choice_never_returns_false");
        let should = ColorChoice::Never.should_colorize();
        crate::assert_with_log!(!should, "never colorize", false, should);
        crate::test_complete!("color_choice_never_returns_false");
    }

    #[test]
    fn color_choice_always_returns_true() {
        init_test("color_choice_always_returns_true");
        let should = ColorChoice::Always.should_colorize();
        crate::assert_with_log!(should, "always colorize", true, should);
        crate::test_complete!("color_choice_always_returns_true");
    }

    #[test]
    fn color_choice_auto_follows_target_terminal_state() {
        init_test("color_choice_auto_follows_target_terminal_state");
        let should = ColorChoice::Auto.should_colorize_for(true);
        crate::assert_with_log!(should, "auto colorizes terminal", true, should);

        let should = ColorChoice::Auto.should_colorize_for(false);
        crate::assert_with_log!(!should, "auto avoids non-terminal", false, should);
        crate::test_complete!("color_choice_auto_follows_target_terminal_state");
    }

    #[test]
    fn json_output_parses() {
        init_test("json_output_parses");
        let item = TestItem {
            id: 42,
            name: "test".into(),
        };

        let json = serde_json::to_string(&item).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        crate::assert_with_log!(parsed["id"] == 42, "id", 42, parsed["id"].clone());
        crate::assert_with_log!(
            parsed["name"] == "test",
            "name",
            "test",
            parsed["name"].clone()
        );
        crate::test_complete!("json_output_parses");
    }

    #[test]
    fn output_writer_json_format() {
        init_test("output_writer_json_format");

        let cursor = Cursor::new(Vec::new());
        let mut output = Output::with_writer(OutputFormat::Json, cursor);

        let item = TestItem {
            id: 1,
            name: "one".into(),
        };
        output.write(&item).unwrap();
        crate::test_complete!("output_writer_json_format");
    }

    #[test]
    fn output_writer_human_format() {
        init_test("output_writer_human_format");

        let cursor = Cursor::new(Vec::new());
        let mut output = Output::with_writer(OutputFormat::Human, cursor);

        let item = TestItem {
            id: 1,
            name: "one".into(),
        };
        output.write(&item).unwrap();
        crate::test_complete!("output_writer_human_format");
    }

    #[test]
    fn output_writer_tsv_format() {
        init_test("output_writer_tsv_format");

        let cursor = Cursor::new(Vec::new());
        let mut output = Output::with_writer(OutputFormat::Tsv, cursor);

        let item = TestItem {
            id: 1,
            name: "one".into(),
        };
        output.write(&item).unwrap();
        crate::test_complete!("output_writer_tsv_format");
    }

    #[test]
    fn output_writer_list_json_is_array() {
        init_test("output_writer_list_json_is_array");

        let cursor = Cursor::new(Vec::new());
        let mut output = Output::with_writer(OutputFormat::Json, cursor);

        let items = vec![
            TestItem {
                id: 1,
                name: "one".into(),
            },
            TestItem {
                id: 2,
                name: "two".into(),
            },
        ];
        output.write_list(&items).unwrap();
        crate::test_complete!("output_writer_list_json_is_array");
    }

    #[derive(Serialize)]
    struct DeclaredOrderItem {
        zeta: u32,
        alpha: f32,
        tags: Vec<&'static str>,
    }

    impl Outputtable for DeclaredOrderItem {
        fn human_format(&self) -> String {
            format!("{} {}", self.zeta, self.alpha)
        }
    }

    #[derive(Serialize)]
    struct ReshapedItem {
        inner: u32,
    }

    impl Outputtable for ReshapedItem {
        fn json(&self) -> Result<Value, serde_json::Error> {
            Ok(serde_json::json!({ "value": self.inner, "kind": "reshaped" }))
        }

        fn human_format(&self) -> String {
            self.inner.to_string()
        }
    }

    /// Serializes only through its `json()` override.
    struct OverrideOnlyItem;

    impl Serialize for OverrideOnlyItem {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Err(S::Error::custom("internal shape is not serializable"))
        }
    }

    impl Outputtable for OverrideOnlyItem {
        fn json(&self) -> Result<Value, serde_json::Error> {
            Ok(serde_json::json!({ "ok": true }))
        }

        fn human_format(&self) -> String {
            "ok".to_string()
        }
    }

    fn rendered<T: Outputtable>(format: OutputFormat, items: &[T], list: bool) -> String {
        let buffer = SharedBuffer::default();
        let mut output = Output::with_writer(format, buffer.clone());
        if list {
            output.write_list(items).unwrap();
        } else {
            output.write(&items[0]).unwrap();
        }
        buffer.snapshot_string()
    }

    #[test]
    fn json_formats_keep_declared_field_order_and_shortest_f32() {
        init_test("json_formats_keep_declared_field_order_and_shortest_f32");
        let items = [
            DeclaredOrderItem {
                zeta: 1,
                alpha: 12.34,
                tags: vec!["x"],
            },
            DeclaredOrderItem {
                zeta: 2,
                alpha: 0.1,
                tags: vec![],
            },
        ];
        let first = "{\"zeta\":1,\"alpha\":12.34,\"tags\":[\"x\"]}";
        let second = "{\"zeta\":2,\"alpha\":0.1,\"tags\":[]}";

        assert_eq!(
            rendered(OutputFormat::Json, &items, false),
            format!("{first}\n")
        );
        assert_eq!(
            rendered(OutputFormat::StreamJson, &items, false),
            format!("{first}\n")
        );
        assert_eq!(
            rendered(OutputFormat::JsonPretty, &items, false),
            "{\n  \"zeta\": 1,\n  \"alpha\": 12.34,\n  \"tags\": [\n    \"x\"\n  ]\n}\n"
        );
        assert_eq!(
            rendered(OutputFormat::Json, &items, true),
            format!("[{first},{second}]\n")
        );
        assert_eq!(
            rendered(OutputFormat::StreamJson, &items, true),
            format!("{first}\n{second}\n")
        );
        crate::test_complete!("json_formats_keep_declared_field_order_and_shortest_f32");
    }

    #[test]
    fn json_override_that_reshapes_is_rendered_from_its_value() {
        init_test("json_override_that_reshapes_is_rendered_from_its_value");
        let items = [ReshapedItem { inner: 5 }];
        let reshaped = "{\"kind\":\"reshaped\",\"value\":5}";

        assert_eq!(
            rendered(OutputFormat::Json, &items, false),
            format!("{reshaped}\n")
        );
        assert_eq!(
            rendered(OutputFormat::Json, &items, true),
            format!("[{reshaped}]\n")
        );
        assert_eq!(
            rendered(OutputFormat::StreamJson, &items, true),
            format!("{reshaped}\n")
        );

        // An override stands in for a type that cannot serialize itself.
        let override_only = [OverrideOnlyItem];
        assert_eq!(
            rendered(OutputFormat::Json, &override_only, false),
            "{\"ok\":true}\n"
        );
        assert_eq!(
            rendered(OutputFormat::JsonPretty, &override_only, true),
            "[\n  {\n    \"ok\": true\n  }\n]\n"
        );
        crate::test_complete!("json_override_that_reshapes_is_rendered_from_its_value");
    }

    #[test]
    fn json_renderer_success_snapshot() {
        init_test("json_renderer_success_snapshot");

        let items = vec![
            TestItem {
                id: 7,
                name: "alpha".into(),
            },
            TestItem {
                id: 8,
                name: "beta".into(),
            },
        ];

        let compact_buffer = SharedBuffer::default();
        let mut compact = Output::with_writer(OutputFormat::Json, compact_buffer.clone());
        compact.write_list(&items).unwrap();
        let compact_raw = compact_buffer.snapshot_string();

        let pretty_buffer = SharedBuffer::default();
        let mut pretty = Output::with_writer(OutputFormat::JsonPretty, pretty_buffer.clone());
        pretty.write_list(&items).unwrap();
        let pretty_raw = pretty_buffer.snapshot_string();

        let stream_buffer = SharedBuffer::default();
        let mut stream = Output::with_writer(OutputFormat::StreamJson, stream_buffer.clone());
        stream.write_list(&items).unwrap();
        let stream_raw = stream_buffer.snapshot_string();

        let snapshot = JsonRendererSuccessSnapshot {
            json_raw: compact_raw,
            json_value: parse_json_document(&compact_buffer.snapshot_string()),
            json_pretty_raw: pretty_raw,
            json_pretty_value: parse_json_document(&pretty_buffer.snapshot_string()),
            stream_json_raw: stream_raw,
            stream_json_values: parse_json_lines(&stream_buffer.snapshot_string()),
        };

        assert_json_snapshot!("json_renderer_success", snapshot);
        crate::test_complete!("json_renderer_success_snapshot");
    }

    #[test]
    fn json_renderer_partial_failure_snapshot() {
        init_test("json_renderer_partial_failure_snapshot");

        let items = vec![
            TestItem {
                id: 9,
                name: "partial-alpha".into(),
            },
            TestItem {
                id: 10,
                name: "partial-beta".into(),
            },
        ];
        let writer = FlushFailWriter::new(1);
        let inspector = writer.clone();
        let mut output = Output::with_writer(OutputFormat::StreamJson, writer);

        let err = output
            .write_list(&items)
            .expect_err("stream flush should fail");
        let written = inspector.snapshot_string();
        let snapshot = JsonRendererFailureSnapshot {
            error_kind: format!("{:?}", err.kind()),
            error_message: err.to_string(),
            flush_calls: inspector.flush_count(),
            written_raw: written,
            written_values: parse_json_lines(&inspector.snapshot_string()),
        };

        assert_json_snapshot!("json_renderer_partial_failure", snapshot);
        crate::test_complete!("json_renderer_partial_failure_snapshot");
    }

    #[test]
    fn json_renderer_full_failure_snapshot() {
        init_test("json_renderer_full_failure_snapshot");

        let buffer = SharedBuffer::default();
        let mut output = Output::with_writer(OutputFormat::Json, buffer.clone());
        let err = output
            .write(&FailingItem)
            .expect_err("serialization should fail");

        let snapshot = JsonRendererFullFailureSnapshot {
            error_kind: format!("{:?}", err.kind()),
            error_message: err.to_string(),
            written_raw: buffer.snapshot_string(),
            written_bytes: buffer.snapshot().len(),
        };

        assert_json_snapshot!("json_renderer_full_failure", snapshot);
        crate::test_complete!("json_renderer_full_failure_snapshot");
    }

    #[test]
    fn json_renderer_state_snapshot_scrubs_generated_timestamps() {
        init_test("json_renderer_state_snapshot_scrubs_generated_timestamps");

        let items = vec![
            JsonModeStatusItem {
                state: JsonModeState::Normal,
                message: "workspace scan complete".to_string(),
                generated_at: synthetic_timestamp(0),
                code: None,
            },
            JsonModeStatusItem {
                state: JsonModeState::Warn,
                message: "using cached dependency graph".to_string(),
                generated_at: synthetic_timestamp(1),
                code: Some("cache_stale".to_string()),
            },
            JsonModeStatusItem {
                state: JsonModeState::Error,
                message: "cargo metadata failed".to_string(),
                generated_at: synthetic_timestamp(2),
                code: Some("metadata_error".to_string()),
            },
        ];

        let compact_buffer = SharedBuffer::default();
        let mut compact = Output::with_writer(OutputFormat::Json, compact_buffer.clone());
        compact.write_list(&items).unwrap();
        let compact_raw = compact_buffer.snapshot_string();

        let pretty_buffer = SharedBuffer::default();
        let mut pretty = Output::with_writer(OutputFormat::JsonPretty, pretty_buffer.clone());
        pretty.write_list(&items).unwrap();
        let pretty_raw = pretty_buffer.snapshot_string();

        let stream_buffer = SharedBuffer::default();
        let mut stream = Output::with_writer(OutputFormat::StreamJson, stream_buffer.clone());
        stream.write_list(&items).unwrap();
        let stream_raw = stream_buffer.snapshot_string();

        let snapshot = JsonRendererStateSnapshot {
            json_raw: scrub_json_document_raw(&compact_raw, false),
            json_value: scrub_generated_at(parse_json_document(&compact_raw)),
            json_pretty_raw: scrub_json_document_raw(&pretty_raw, true),
            json_pretty_value: scrub_generated_at(parse_json_document(&pretty_raw)),
            stream_json_raw: scrub_json_lines_raw(&stream_raw),
            stream_json_values: parse_json_lines(&stream_raw)
                .into_iter()
                .map(scrub_generated_at)
                .collect(),
        };

        assert_json_snapshot!("json_renderer_state_matrix_scrubbed", snapshot);
        crate::test_complete!("json_renderer_state_snapshot_scrubs_generated_timestamps");
    }

    #[test]
    fn output_format_debug_clone_copy_default_eq() {
        let f = OutputFormat::default();
        assert_eq!(f, OutputFormat::Human);

        let dbg = format!("{f:?}");
        assert!(dbg.contains("Human"));

        let f2 = f;
        assert_eq!(f, f2);

        // Copy
        let f3 = f;
        assert_eq!(f, f3);

        assert_ne!(OutputFormat::Json, OutputFormat::Tsv);
    }

    #[test]
    fn color_choice_debug_clone_copy_default_eq() {
        let c = ColorChoice::default();
        assert_eq!(c, ColorChoice::Auto);

        let dbg = format!("{c:?}");
        assert!(dbg.contains("Auto"));

        let c2 = c;
        assert_eq!(c, c2);

        // Copy
        let c3 = c;
        assert_eq!(c, c3);

        assert_ne!(ColorChoice::Always, ColorChoice::Never);
    }
