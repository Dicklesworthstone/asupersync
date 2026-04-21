//! Golden snapshots for structured log-level filtering.

use asupersync::observability::{LogEntry, LogLevel, ObservabilityConfig};
use asupersync::types::Time;
use insta::assert_json_snapshot;
use serde_json::{Map, Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

fn dynamic_timestamp_nanos(offset: u64) -> u64 {
    let base = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos() as u64;
    base.saturating_add(offset)
}

fn fixture_entries(pid: u32) -> [LogEntry; 5] {
    [
        LogEntry::trace("trace handshake probe")
            .with_target("net::handshake")
            .with_timestamp(Time::from_nanos(dynamic_timestamp_nanos(1)))
            .with_field("pid", pid.to_string())
            .with_field("request_id", "REQ-TRACE"),
        LogEntry::debug("debug collector state")
            .with_target("collector::state")
            .with_timestamp(Time::from_nanos(dynamic_timestamp_nanos(2)))
            .with_field("pid", pid.to_string())
            .with_field("request_id", "REQ-DEBUG"),
        LogEntry::info("info runtime ready")
            .with_target("runtime::startup")
            .with_timestamp(Time::from_nanos(dynamic_timestamp_nanos(3)))
            .with_field("pid", pid.to_string())
            .with_field("request_id", "REQ-INFO"),
        LogEntry::warn("warn backlog elevated")
            .with_target("scheduler::queue")
            .with_timestamp(Time::from_nanos(dynamic_timestamp_nanos(4)))
            .with_field("pid", pid.to_string())
            .with_field("request_id", "REQ-WARN"),
        LogEntry::error("error downstream unavailable")
            .with_target("grpc::client")
            .with_timestamp(Time::from_nanos(dynamic_timestamp_nanos(5)))
            .with_field("pid", pid.to_string())
            .with_field("request_id", "REQ-ERROR"),
    ]
}

fn scrub_formatted_entry(entry: &LogEntry) -> Value {
    let mut value: Value =
        serde_json::from_str(&entry.format_json()).expect("formatted log entry must be valid JSON");
    let object = value.as_object_mut().expect("log entry should serialize as object");
    object.insert("timestamp_ns".into(), Value::String("[timestamp_ns]".into()));
    if object.contains_key("pid") {
        object.insert("pid".into(), Value::String("[pid]".into()));
    }
    if object.contains_key("field.pid") {
        object.insert("field.pid".into(), Value::String("[pid]".into()));
    }
    value
}

fn filtered_snapshot_for_threshold(threshold: LogLevel) -> Value {
    let config = ObservabilityConfig::default().with_log_level(threshold);
    let collector = config.create_collector();
    let pid = std::process::id();

    for entry in fixture_entries(pid) {
        collector.log(entry);
    }

    let accepted_entries = collector.peek();
    json!({
        "threshold": threshold.as_str_lower(),
        "accepted_levels": accepted_entries
            .iter()
            .map(|entry| entry.level().as_str_lower())
            .collect::<Vec<_>>(),
        "entries": accepted_entries
            .iter()
            .map(scrub_formatted_entry)
            .collect::<Vec<_>>(),
    })
}

#[test]
fn structured_log_level_filter_output() {
    let snapshot = [
        LogLevel::Trace,
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Warn,
        LogLevel::Error,
    ]
    .into_iter()
    .map(|threshold| (threshold.as_str_lower().to_string(), filtered_snapshot_for_threshold(threshold)))
    .collect::<Map<String, Value>>();

    assert_json_snapshot!("structured_log_level_filter_output", snapshot);
}
