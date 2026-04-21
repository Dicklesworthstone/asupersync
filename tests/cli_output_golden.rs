#![allow(warnings)]
#![cfg(feature = "cli")]
#![allow(missing_docs)]

use asupersync::cli::{Output, OutputFormat, Outputtable};
use insta::assert_json_snapshot;
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::Value;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[allow(dead_code)]
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum JsonModeState {
    Normal,
    Warn,
    Error,
}

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

#[derive(Clone, Serialize)]
struct CliShowItem {
    id: u32,
    name: String,
    state: JsonModeState,
    retries: u32,
    generated_at: String,
    details: Vec<String>,
}

impl Outputtable for CliShowItem {
    fn human_format(&self) -> String {
        let details = self
            .details
            .iter()
            .map(|detail| format!("  - {detail}"))
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "Record {}: {}\nState: {:?}\nRetries: {}\nDetails:\n{}",
            self.id, self.name, self.state, self.retries, details
        )
    }

    fn tsv_format(&self) -> String {
        format!(
            "{}\t{}\t{:?}\t{}\t{}",
            self.id,
            self.name,
            self.state,
            self.retries,
            self.details.join("|")
        )
    }
}

#[derive(Clone, Serialize)]
struct CliErrorItem {
    operation: String,
    code: String,
    message: String,
    retryable: bool,
    generated_at: String,
}

impl Outputtable for CliErrorItem {
    fn human_format(&self) -> String {
        format!(
            "ERROR [{}] {}: {} (retryable: {})",
            self.code, self.operation, self.message, self.retryable
        )
    }

    fn tsv_format(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}",
            self.operation, self.code, self.message, self.retryable
        )
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

#[derive(Serialize)]
struct StructuredCliFormatCase {
    human_raw: String,
    json_raw: String,
    json_value: Value,
    json_pretty_raw: String,
    json_pretty_value: Value,
    stream_json_raw: String,
    stream_json_values: Vec<Value>,
    tsv_raw: String,
}

#[derive(Serialize)]
struct StructuredCliOutputSnapshot {
    status: StructuredCliFormatCase,
    list: StructuredCliFormatCase,
    show: StructuredCliFormatCase,
    error: StructuredCliFormatCase,
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
        Value::Array(values) => Value::Array(values.into_iter().map(scrub_generated_at).collect()),
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
        rendered
            .push_str(&serde_json::to_string(&value).expect("scrubbed json line should serialize"));
        rendered.push('\n');
    }
    rendered
}

fn capture_single_format_case<T: Outputtable>(value: &T) -> StructuredCliFormatCase {
    let human_buffer = SharedBuffer::default();
    let mut human = Output::with_writer(OutputFormat::Human, human_buffer.clone());
    human.write(value).expect("human output should render");

    let compact_buffer = SharedBuffer::default();
    let mut compact = Output::with_writer(OutputFormat::Json, compact_buffer.clone());
    compact.write(value).expect("json output should render");
    let compact_raw = compact_buffer.snapshot_string();

    let pretty_buffer = SharedBuffer::default();
    let mut pretty = Output::with_writer(OutputFormat::JsonPretty, pretty_buffer.clone());
    pretty
        .write(value)
        .expect("pretty json output should render");
    let pretty_raw = pretty_buffer.snapshot_string();

    let stream_buffer = SharedBuffer::default();
    let mut stream = Output::with_writer(OutputFormat::StreamJson, stream_buffer.clone());
    stream
        .write(value)
        .expect("stream json output should render");
    let stream_raw = stream_buffer.snapshot_string();

    let tsv_buffer = SharedBuffer::default();
    let mut tsv = Output::with_writer(OutputFormat::Tsv, tsv_buffer.clone());
    tsv.write(value).expect("tsv output should render");

    StructuredCliFormatCase {
        human_raw: human_buffer.snapshot_string(),
        json_raw: scrub_json_document_raw(&compact_raw, false),
        json_value: scrub_generated_at(parse_json_document(&compact_raw)),
        json_pretty_raw: scrub_json_document_raw(&pretty_raw, true),
        json_pretty_value: scrub_generated_at(parse_json_document(&pretty_raw)),
        stream_json_raw: scrub_json_lines_raw(&stream_raw),
        stream_json_values: parse_json_lines(&stream_raw)
            .into_iter()
            .map(scrub_generated_at)
            .collect(),
        tsv_raw: tsv_buffer.snapshot_string(),
    }
}

fn capture_list_format_case<T: Outputtable>(values: &[T]) -> StructuredCliFormatCase {
    let human_buffer = SharedBuffer::default();
    let mut human = Output::with_writer(OutputFormat::Human, human_buffer.clone());
    human
        .write_list(values)
        .expect("human list output should render");

    let compact_buffer = SharedBuffer::default();
    let mut compact = Output::with_writer(OutputFormat::Json, compact_buffer.clone());
    compact
        .write_list(values)
        .expect("json list output should render");
    let compact_raw = compact_buffer.snapshot_string();

    let pretty_buffer = SharedBuffer::default();
    let mut pretty = Output::with_writer(OutputFormat::JsonPretty, pretty_buffer.clone());
    pretty
        .write_list(values)
        .expect("pretty json list output should render");
    let pretty_raw = pretty_buffer.snapshot_string();

    let stream_buffer = SharedBuffer::default();
    let mut stream = Output::with_writer(OutputFormat::StreamJson, stream_buffer.clone());
    stream
        .write_list(values)
        .expect("stream json list output should render");
    let stream_raw = stream_buffer.snapshot_string();

    let tsv_buffer = SharedBuffer::default();
    let mut tsv = Output::with_writer(OutputFormat::Tsv, tsv_buffer.clone());
    tsv.write_list(values)
        .expect("tsv list output should render");

    StructuredCliFormatCase {
        human_raw: human_buffer.snapshot_string(),
        json_raw: scrub_json_document_raw(&compact_raw, false),
        json_value: scrub_generated_at(parse_json_document(&compact_raw)),
        json_pretty_raw: scrub_json_document_raw(&pretty_raw, true),
        json_pretty_value: scrub_generated_at(parse_json_document(&pretty_raw)),
        stream_json_raw: scrub_json_lines_raw(&stream_raw),
        stream_json_values: parse_json_lines(&stream_raw)
            .into_iter()
            .map(scrub_generated_at)
            .collect(),
        tsv_raw: tsv_buffer.snapshot_string(),
    }
}

#[test]
fn structured_cli_output_format_matrix_scrubbed() {
    let status = JsonModeStatusItem {
        state: JsonModeState::Warn,
        message: "using cached plan for status".to_string(),
        generated_at: synthetic_timestamp(10),
        code: Some("cache_warm".to_string()),
    };

    let list_items = vec![
        TestItem {
            id: 41,
            name: "alpha".into(),
        },
        TestItem {
            id: 42,
            name: "beta".into(),
        },
        TestItem {
            id: 43,
            name: "gamma".into(),
        },
    ];

    let show = CliShowItem {
        id: 91,
        name: "scheduler".to_string(),
        state: JsonModeState::Normal,
        retries: 2,
        generated_at: synthetic_timestamp(11),
        details: vec![
            "queue depth stable".to_string(),
            "backpressure inactive".to_string(),
            "trace export healthy".to_string(),
        ],
    };

    let error = CliErrorItem {
        operation: "br show".to_string(),
        code: "not_found".to_string(),
        message: "bead asupersync-missing was not found".to_string(),
        retryable: false,
        generated_at: synthetic_timestamp(12),
    };

    let snapshot = StructuredCliOutputSnapshot {
        status: capture_single_format_case(&status),
        list: capture_list_format_case(&list_items),
        show: capture_single_format_case(&show),
        error: capture_single_format_case(&error),
    };

    assert_json_snapshot!("structured_cli_output_format_matrix_scrubbed", snapshot);
}
