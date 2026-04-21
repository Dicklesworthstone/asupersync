#![allow(warnings)]
#![cfg(feature = "cli")]
//! Golden snapshot tests for CLI output formats
//!
//! Comprehensive tests for all structured output formats in src/cli/output.rs:
//! - Human-readable format
//! - JSON (compact)
//! - StreamJSON (newline-delimited with flush)
//! - JsonPretty (formatted)
//! - TSV (tab-separated values)
//!
//! These tests capture the exact output format to detect any regressions
//! in CLI output formatting.

#![cfg(test)]
#![cfg(feature = "cli")]

use asupersync::cli::output::{OutputFormat, Output, Outputtable};
use insta::assert_snapshot;
use parking_lot::Mutex;
use serde::Serialize;
use std::io::Write;
use std::sync::Arc;

/// Shared buffer for capturing output
#[derive(Clone, Default)]
struct CaptureBuffer(Arc<Mutex<Vec<u8>>>);

impl CaptureBuffer {
    fn to_string(&self) -> String {
        String::from_utf8(self.0.lock().clone()).expect("valid UTF-8")
    }

    fn clear(&self) {
        self.0.lock().clear();
    }
}

impl Write for CaptureBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Sample task data for testing different output formats
#[derive(Serialize, Debug, Clone)]
struct TaskInfo {
    id: u32,
    name: String,
    status: TaskStatus,
    priority: u8,
    duration_ms: Option<u64>,
    tags: Vec<String>,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
enum TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

impl Outputtable for TaskInfo {
    fn human_format(&self) -> String {
        let duration = match self.duration_ms {
            Some(ms) => format!(" ({}ms)", ms),
            None => String::new(),
        };
        let tags = if self.tags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", self.tags.join(", "))
        };
        format!(
            "Task {}: {} - {:?} (P{}){}{}",
            self.id, self.name, self.status, self.priority, duration, tags
        )
    }

    fn tsv_format(&self) -> String {
        let duration = self.duration_ms.map_or("".to_string(), |ms| ms.to_string());
        let tags = self.tags.join(",");
        format!(
            "{}\t{}\t{:?}\t{}\t{}\t{}",
            self.id, self.name, self.status, self.priority, duration, tags
        )
    }
}

/// Resource usage statistics for testing numeric output
#[derive(Serialize, Debug, Clone)]
struct ResourceStats {
    memory_mb: f64,
    cpu_percent: f32,
    disk_io_kb: u64,
    network_bytes: u64,
    uptime_seconds: u32,
}

impl Outputtable for ResourceStats {
    fn human_format(&self) -> String {
        format!(
            "Memory: {:.1}MB, CPU: {:.1}%, Disk: {}KB, Network: {}B, Uptime: {}s",
            self.memory_mb,
            self.cpu_percent,
            self.disk_io_kb,
            self.network_bytes,
            self.uptime_seconds
        )
    }

    fn tsv_format(&self) -> String {
        format!(
            "{:.1}\t{:.1}\t{}\t{}\t{}",
            self.memory_mb,
            self.cpu_percent,
            self.disk_io_kb,
            self.network_bytes,
            self.uptime_seconds
        )
    }
}

/// Configuration entry for testing nested structures
#[derive(Serialize, Debug, Clone)]
struct ConfigEntry {
    key: String,
    value: ConfigValue,
    source: String,
    overridden: bool,
}

#[derive(Serialize, Debug, Clone)]
#[serde(untagged)]
enum ConfigValue {
    String(String),
    Number(i64),
    Boolean(bool),
    Array(Vec<String>),
}

impl Outputtable for ConfigEntry {
    fn human_format(&self) -> String {
        let value_str = match &self.value {
            ConfigValue::String(s) => format!("\"{}\"", s),
            ConfigValue::Number(n) => n.to_string(),
            ConfigValue::Boolean(b) => b.to_string(),
            ConfigValue::Array(arr) => format!("[{}]", arr.join(", ")),
        };
        let override_marker = if self.overridden { " (overridden)" } else { "" };
        format!(
            "{} = {} (from: {}){}",
            self.key, value_str, self.source, override_marker
        )
    }

    fn tsv_format(&self) -> String {
        let value_str = match &self.value {
            ConfigValue::String(s) => s.clone(),
            ConfigValue::Number(n) => n.to_string(),
            ConfigValue::Boolean(b) => b.to_string(),
            ConfigValue::Array(arr) => arr.join(","),
        };
        format!(
            "{}\t{}\t{}\t{}",
            self.key, value_str, self.source, self.overridden
        )
    }
}

fn sample_tasks() -> Vec<TaskInfo> {
    vec![
        TaskInfo {
            id: 1,
            name: "Initialize runtime".to_string(),
            status: TaskStatus::Completed,
            priority: 1,
            duration_ms: Some(150),
            tags: vec!["startup".to_string(), "critical".to_string()],
        },
        TaskInfo {
            id: 2,
            name: "Load configuration".to_string(),
            status: TaskStatus::Running,
            priority: 2,
            duration_ms: None,
            tags: vec!["config".to_string()],
        },
        TaskInfo {
            id: 3,
            name: "Background cleanup".to_string(),
            status: TaskStatus::Pending,
            priority: 5,
            duration_ms: None,
            tags: vec![],
        },
        TaskInfo {
            id: 4,
            name: "Network sync".to_string(),
            status: TaskStatus::Failed,
            priority: 3,
            duration_ms: Some(2450),
            tags: vec![
                "network".to_string(),
                "retry".to_string(),
                "timeout".to_string(),
            ],
        },
    ]
}

fn sample_resources() -> ResourceStats {
    ResourceStats {
        memory_mb: 256.7,
        cpu_percent: 12.34,
        disk_io_kb: 1024,
        network_bytes: 87654321,
        uptime_seconds: 3661,
    }
}

fn sample_config() -> Vec<ConfigEntry> {
    vec![
        ConfigEntry {
            key: "server.port".to_string(),
            value: ConfigValue::Number(8080),
            source: "config.toml".to_string(),
            overridden: false,
        },
        ConfigEntry {
            key: "server.host".to_string(),
            value: ConfigValue::String("localhost".to_string()),
            source: "environment".to_string(),
            overridden: true,
        },
        ConfigEntry {
            key: "debug.enabled".to_string(),
            value: ConfigValue::Boolean(true),
            source: "command_line".to_string(),
            overridden: false,
        },
        ConfigEntry {
            key: "allowed_origins".to_string(),
            value: ConfigValue::Array(vec![
                "https://api.example.com".to_string(),
                "https://web.example.com".to_string(),
            ]),
            source: "config.toml".to_string(),
            overridden: false,
        },
    ]
}

fn capture_output<T: Outputtable>(format: OutputFormat, items: &[T]) -> String {
    let buffer = CaptureBuffer::default();
    let mut writer = Output::with_writer(format, buffer.clone());

    for item in items {
        writer.write(item).expect("write should succeed");
    }

    buffer.to_string()
}

#[test]
fn golden_task_output_human() {
    let tasks = sample_tasks();
    let output = capture_output(OutputFormat::Human, &tasks);
    assert_snapshot!(output, @r###"
    Task 1: Initialize runtime - Completed (P1) (150ms) [startup, critical]
    Task 2: Load configuration - Running (P2) [config]
    Task 3: Background cleanup - Pending (P5)
    Task 4: Network sync - Failed (P3) (2450ms) [network, retry, timeout]
    "###);
}

#[test]
fn golden_task_output_json() {
    let tasks = sample_tasks();
    let output = capture_output(OutputFormat::Json, &tasks);
    assert_snapshot!(output, @r###"
    {"id":1,"name":"Initialize runtime","status":"completed","priority":1,"duration_ms":150,"tags":["startup","critical"]}
    {"id":2,"name":"Load configuration","status":"running","priority":2,"duration_ms":null,"tags":["config"]}
    {"id":3,"name":"Background cleanup","status":"pending","priority":5,"duration_ms":null,"tags":[]}
    {"id":4,"name":"Network sync","status":"failed","priority":3,"duration_ms":2450,"tags":["network","retry","timeout"]}
    "###);
}

#[test]
fn golden_task_output_stream_json() {
    let tasks = sample_tasks();
    let output = capture_output(OutputFormat::StreamJson, &tasks);
    // StreamJson should be identical to Json for this case (flush happens per item)
    assert_snapshot!(output, @r###"
    {"id":1,"name":"Initialize runtime","status":"completed","priority":1,"duration_ms":150,"tags":["startup","critical"]}
    {"id":2,"name":"Load configuration","status":"running","priority":2,"duration_ms":null,"tags":["config"]}
    {"id":3,"name":"Background cleanup","status":"pending","priority":5,"duration_ms":null,"tags":[]}
    {"id":4,"name":"Network sync","status":"failed","priority":3,"duration_ms":2450,"tags":["network","retry","timeout"]}
    "###);
}

#[test]
fn golden_task_output_json_pretty() {
    let tasks = sample_tasks();
    let output = capture_output(OutputFormat::JsonPretty, &tasks);
    assert_snapshot!(output, @r###"
    {
      "id": 1,
      "name": "Initialize runtime",
      "status": "completed",
      "priority": 1,
      "duration_ms": 150,
      "tags": [
        "startup",
        "critical"
      ]
    }
    {
      "id": 2,
      "name": "Load configuration",
      "status": "running",
      "priority": 2,
      "duration_ms": null,
      "tags": [
        "config"
      ]
    }
    {
      "id": 3,
      "name": "Background cleanup",
      "status": "pending",
      "priority": 5,
      "duration_ms": null,
      "tags": []
    }
    {
      "id": 4,
      "name": "Network sync",
      "status": "failed",
      "priority": 3,
      "duration_ms": 2450,
      "tags": [
        "network",
        "retry",
        "timeout"
      ]
    }
    "###);
}

#[test]
fn golden_task_output_tsv() {
    let tasks = sample_tasks();
    let output = capture_output(OutputFormat::Tsv, &tasks);
    assert_snapshot!(output, @r###"
    1	Initialize runtime	Completed	1	150	startup,critical
    2	Load configuration	Running	2		config
    3	Background cleanup	Pending	5
    4	Network sync	Failed	3	2450	network,retry,timeout
    "###);
}

#[test]
fn golden_resource_stats_all_formats() {
    let stats = vec![sample_resources()];

    // Human format
    let human_output = capture_output(OutputFormat::Human, &stats);
    assert_snapshot!(human_output, @"Memory: 256.7MB, CPU: 12.3%, Disk: 1024KB, Network: 87654321B, Uptime: 3661s\n");

    // JSON format
    let json_output = capture_output(OutputFormat::Json, &stats);
    assert_snapshot!(json_output, @r###"{"memory_mb":256.7,"cpu_percent":12.34,"disk_io_kb":1024,"network_bytes":87654321,"uptime_seconds":3661}
    "###);

    // TSV format
    let tsv_output = capture_output(OutputFormat::Tsv, &stats);
    assert_snapshot!(tsv_output, @"256.7	12.3	1024	87654321	3661\n");
}

#[test]
fn golden_config_entries_complex_values() {
    let config = sample_config();

    // Human format with complex nested values
    let human_output = capture_output(OutputFormat::Human, &config);
    assert_snapshot!(human_output, @r###"
    server.port = 8080 (from: config.toml)
    server.host = "localhost" (from: environment) (overridden)
    debug.enabled = true (from: command_line)
    allowed_origins = [https://api.example.com, https://web.example.com] (from: config.toml)
    "###);

    // JSON format preserving structure
    let json_output = capture_output(OutputFormat::Json, &config);
    assert_snapshot!(json_output, @r###"
    {"key":"server.port","value":8080,"source":"config.toml","overridden":false}
    {"key":"server.host","value":"localhost","source":"environment","overridden":true}
    {"key":"debug.enabled","value":true,"source":"command_line","overridden":false}
    {"key":"allowed_origins","value":["https://api.example.com","https://web.example.com"],"source":"config.toml","overridden":false}
    "###);

    // TSV format with flattened arrays
    let tsv_output = capture_output(OutputFormat::Tsv, &config);
    assert_snapshot!(tsv_output, @r###"
    server.port	8080	config.toml	false
    server.host	localhost	environment	true
    debug.enabled	true	command_line	false
    allowed_origins	https://api.example.com,https://web.example.com	config.toml	false
    "###);
}

#[test]
fn golden_empty_collections() {
    let empty_tasks: Vec<TaskInfo> = vec![];
    let output = capture_output(OutputFormat::Json, &empty_tasks);
    assert_snapshot!(output, @"");

    let output_human = capture_output(OutputFormat::Human, &empty_tasks);
    assert_snapshot!(output_human, @"");
}

#[test]
fn golden_single_item_all_formats() {
    let single_task = vec![TaskInfo {
        id: 42,
        name: "Test task".to_string(),
        status: TaskStatus::Completed,
        priority: 1,
        duration_ms: Some(999),
        tags: vec!["test".to_string()],
    }];

    let formats = [
        OutputFormat::Human,
        OutputFormat::Json,
        OutputFormat::StreamJson,
        OutputFormat::JsonPretty,
        OutputFormat::Tsv,
    ];

    for format in &formats {
        let output = capture_output(*format, &single_task);
        insta::with_settings!({
            snapshot_suffix => format!("{:?}", format).to_lowercase()
        }, {
            assert_snapshot!(output);
        });
    }
}
