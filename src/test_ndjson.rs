//! NDJSON event schema, trace file naming, and artifact bundle helpers (bd-1t58q).
//!
//! This module defines the unified NDJSON (newline-delimited JSON) event format
//! for all test suites, standardized trace file naming conventions, and artifact
//! bundle directory layout helpers.
//!
//! # NDJSON Schema (v1)
//!
//! Every test event can be serialized as one JSON line for CI parsing, log
//! aggregation, and failure triage. Enable streaming output via
//! `ASUPERSYNC_TEST_NDJSON=1`.
//!
//! ## Standard Fields
//!
//! | Field        | Type       | Description                                          |
//! |-------------|-----------|------------------------------------------------------|
//! | `v`         | `u32`     | Schema version ([`NDJSON_SCHEMA_VERSION`])            |
//! | `ts_us`     | `u64`     | Microseconds since test start                        |
//! | `level`     | `string`  | Log level: ERROR/WARN/INFO/DEBUG/TRACE               |
//! | `category`  | `string`  | Event category: reactor/io/waker/task/timer/etc.     |
//! | `event`     | `string`  | Specific event type (e.g., `TaskSpawn`)              |
//! | `test_id`   | `string?` | Test identifier from [`TestContext`]                  |
//! | `seed`      | `u64?`    | Root seed for deterministic replay                   |
//! | `subsystem` | `string?` | Subsystem tag (scheduler, obligation, etc.)          |
//! | `invariant` | `string?` | Invariant being verified                             |
//! | `thread_id` | `u64`     | OS thread ID                                         |
//! | `message`   | `string`  | Human-readable description                           |
//! | `data`      | `object`  | Event-specific key-value pairs                       |
//!
//! ## Trace File Naming
//!
//! ```text
//! {subsystem}_{scenario}_{seed:016x}.trace   — binary replay trace
//! {subsystem}_{scenario}_{seed:016x}.ndjson  — structured event log
//! ```
//!
//! ## Artifact Bundle Layout
//!
//! ```text
//! $ASUPERSYNC_TEST_ARTIFACTS_DIR/{test_id}/{seed:016x}/
//!   manifest.json        — ReproManifest with full reproducibility info
//!   events.ndjson        — Structured event log in NDJSON format
//!   summary.json         — TestSummary from the harness
//!   environment.json     — EnvironmentMetadata snapshot
//!   *.trace              — Binary trace files (if recording enabled)
//!   failed_assertions.json — Assertion details (on failure)
//! ```
//!
//! # Example
//!
//! ```ignore
//! use asupersync::test_ndjson::{NdjsonLogger, write_artifact_bundle};
//! use asupersync::test_logging::{TestLogLevel, TestEvent, TestContext, ReproManifest};
//!
//! let ctx = TestContext::new("my_test", 0xDEAD_BEEF).with_subsystem("scheduler");
//! let logger = NdjsonLogger::enabled(TestLogLevel::Info, Some(ctx.clone()));
//!
//! logger.log(TestEvent::TaskSpawn { task_id: 1, name: Some("worker".into()) });
//!
//! let manifest = ReproManifest::from_context(&ctx, true).with_env_snapshot();
//! let bundle = write_artifact_bundle(&manifest, Some(&logger), None).unwrap();
//! ```

use crate::test_logging::{
    LogRecord, ReproManifest, TestContext, TestEvent, TestLogLevel, TestLogger, TestSummary,
};

// ============================================================================
// NDJSON Schema
// ============================================================================

/// NDJSON schema version for structured test event lines.
///
/// Version history:
/// - v1: Initial schema with standard fields (ts, level, category, event, test context).
pub const NDJSON_SCHEMA_VERSION: u32 = 1;

/// A single NDJSON (newline-delimited JSON) event line.
///
/// See [module documentation](self) for full schema specification.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NdjsonEvent {
    /// Schema version.
    pub v: u32,
    /// Microseconds elapsed since the test/logger start.
    pub ts_us: u64,
    /// Log level.
    pub level: &'static str,
    /// Event category (reactor, io, waker, task, timer, region, obligation, custom).
    pub category: &'static str,
    /// Specific event type name.
    pub event: String,
    /// Test identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_id: Option<String>,
    /// Root seed for deterministic replay.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    /// Subsystem under test.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subsystem: Option<String>,
    /// Invariant being verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invariant: Option<String>,
    /// OS thread ID.
    pub thread_id: u64,
    /// Human-readable message.
    pub message: String,
    /// Event-specific data.
    #[serde(skip_serializing_if = "serde_json::Map::is_empty")]
    pub data: serde_json::Map<String, serde_json::Value>,
}

impl NdjsonEvent {
    /// Create a new NDJSON event from a [`LogRecord`] and optional [`TestContext`].
    #[must_use]
    pub fn from_record(record: &LogRecord, ctx: Option<&TestContext>) -> Self {
        let mut data = serde_json::Map::new();
        populate_event_data(&record.event, &mut data);

        Self {
            v: NDJSON_SCHEMA_VERSION,
            ts_us: record.elapsed.as_micros() as u64,
            level: record.event.level().name(),
            category: record.event.category(),
            event: event_type_name(&record.event),
            test_id: ctx.map(|c| c.test_id.clone()),
            seed: ctx.map(|c| c.seed),
            subsystem: ctx.and_then(|c| c.subsystem.clone()),
            invariant: ctx.and_then(|c| c.invariant.clone()),
            thread_id: thread_id_u64(),
            message: format!("{}", record.event),
            data,
        }
    }

    /// Serialize to a single JSON line (no trailing newline).
    #[must_use]
    pub fn to_json_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Returns a short type name for a [`TestEvent`] variant.
fn event_type_name(event: &TestEvent) -> String {
    match event {
        TestEvent::ReactorPoll { .. } => "ReactorPoll",
        TestEvent::ReactorWake { .. } => "ReactorWake",
        TestEvent::ReactorRegister { .. } => "ReactorRegister",
        TestEvent::ReactorDeregister { .. } => "ReactorDeregister",
        TestEvent::IoRead { .. } => "IoRead",
        TestEvent::IoWrite { .. } => "IoWrite",
        TestEvent::IoConnect { .. } => "IoConnect",
        TestEvent::IoAccept { .. } => "IoAccept",
        TestEvent::WakerWake { .. } => "WakerWake",
        TestEvent::WakerClone { .. } => "WakerClone",
        TestEvent::WakerDrop { .. } => "WakerDrop",
        TestEvent::TaskPoll { .. } => "TaskPoll",
        TestEvent::TaskSpawn { .. } => "TaskSpawn",
        TestEvent::TaskComplete { .. } => "TaskComplete",
        TestEvent::TimerScheduled { .. } => "TimerScheduled",
        TestEvent::TimerFired { .. } => "TimerFired",
        TestEvent::RegionCreate { .. } => "RegionCreate",
        TestEvent::RegionStateChange { .. } => "RegionStateChange",
        TestEvent::RegionClose { .. } => "RegionClose",
        TestEvent::ObligationCreate { .. } => "ObligationCreate",
        TestEvent::ObligationResolve { .. } => "ObligationResolve",
        TestEvent::Custom { .. } => "Custom",
        TestEvent::Error { .. } => "Error",
        TestEvent::Warn { .. } => "Warn",
    }
    .to_string()
}

/// Populate event-specific data fields into a JSON map.
///
/// Uses `..` patterns to be resilient to field additions in [`TestEvent`].
#[allow(clippy::too_many_lines)]
fn populate_event_data(event: &TestEvent, data: &mut serde_json::Map<String, serde_json::Value>) {
    use serde_json::Value;
    match event {
        TestEvent::ReactorPoll {
            events_returned, ..
        } => {
            data.insert("events_returned".into(), Value::from(*events_returned));
        }
        TestEvent::ReactorWake { source, .. } => {
            data.insert("source".into(), Value::from(*source));
        }
        TestEvent::ReactorRegister {
            token, interest, ..
        } => {
            data.insert("token".into(), Value::from(*token));
            data.insert("readable".into(), Value::from(interest.readable));
            data.insert("writable".into(), Value::from(interest.writable));
        }
        TestEvent::ReactorDeregister { token, .. }
        | TestEvent::WakerClone { token, .. }
        | TestEvent::WakerDrop { token, .. } => {
            data.insert("token".into(), Value::from(*token));
        }
        TestEvent::IoRead {
            token,
            bytes,
            would_block,
            ..
        }
        | TestEvent::IoWrite {
            token,
            bytes,
            would_block,
            ..
        } => {
            data.insert("token".into(), Value::from(*token));
            data.insert("bytes".into(), Value::from(*bytes));
            data.insert("would_block".into(), Value::from(*would_block));
        }
        TestEvent::IoConnect { addr, result, .. } => {
            data.insert("addr".into(), Value::from(addr.as_str()));
            data.insert("result".into(), Value::from(*result));
        }
        TestEvent::IoAccept { local, peer, .. } => {
            data.insert("local".into(), Value::from(local.as_str()));
            data.insert("peer".into(), Value::from(peer.as_str()));
        }
        TestEvent::WakerWake { task_id, .. }
        | TestEvent::TimerScheduled { task_id, .. }
        | TestEvent::TimerFired { task_id, .. } => {
            data.insert("task_id".into(), Value::from(*task_id));
        }
        TestEvent::TaskPoll {
            task_id, result, ..
        } => {
            data.insert("task_id".into(), Value::from(*task_id));
            data.insert("result".into(), Value::from(*result));
        }
        TestEvent::TaskSpawn { task_id, name, .. } => {
            data.insert("task_id".into(), Value::from(*task_id));
            if let Some(n) = name {
                data.insert("name".into(), Value::from(n.as_str()));
            }
        }
        TestEvent::TaskComplete {
            task_id, outcome, ..
        } => {
            data.insert("task_id".into(), Value::from(*task_id));
            data.insert("outcome".into(), Value::from(*outcome));
        }
        TestEvent::RegionCreate {
            region_id,
            parent_id,
            ..
        } => {
            data.insert("region_id".into(), Value::from(*region_id));
            if let Some(p) = parent_id {
                data.insert("parent_id".into(), Value::from(*p));
            }
        }
        TestEvent::RegionStateChange {
            region_id,
            from_state,
            to_state,
            ..
        } => {
            data.insert("region_id".into(), Value::from(*region_id));
            data.insert("from_state".into(), Value::from(*from_state));
            data.insert("to_state".into(), Value::from(*to_state));
        }
        TestEvent::RegionClose {
            region_id,
            task_count,
            ..
        } => {
            data.insert("region_id".into(), Value::from(*region_id));
            data.insert("task_count".into(), Value::from(*task_count));
        }
        TestEvent::ObligationCreate {
            obligation_id,
            kind,
            holder_id,
            ..
        } => {
            data.insert("obligation_id".into(), Value::from(*obligation_id));
            data.insert("kind".into(), Value::from(*kind));
            data.insert("holder_id".into(), Value::from(*holder_id));
        }
        TestEvent::ObligationResolve {
            obligation_id,
            resolution,
            ..
        } => {
            data.insert("obligation_id".into(), Value::from(*obligation_id));
            data.insert("resolution".into(), Value::from(*resolution));
        }
        TestEvent::Custom {
            category, message, ..
        }
        | TestEvent::Error {
            category, message, ..
        }
        | TestEvent::Warn {
            category, message, ..
        } => {
            data.insert("category_detail".into(), Value::from(*category));
            data.insert("detail".into(), Value::from(message.as_str()));
        }
    }
}

/// Get the current OS thread ID as u64 (parsed from Debug representation).
fn thread_id_u64() -> u64 {
    let id = std::thread::current().id();
    let s = format!("{id:?}");
    s.trim_start_matches("ThreadId(")
        .trim_end_matches(')')
        .parse::<u64>()
        .unwrap_or_default()
}

// ============================================================================
// NDJSON Logger
// ============================================================================

/// An NDJSON log writer that wraps [`TestLogger`] and optionally streams
/// structured JSON lines to stderr for CI log parsing.
///
/// Enable with `ASUPERSYNC_TEST_NDJSON=1` or by constructing with
/// [`NdjsonLogger::enabled`].
pub struct NdjsonLogger {
    inner: TestLogger,
    ctx: Option<TestContext>,
    ndjson_enabled: bool,
}

impl NdjsonLogger {
    /// Create a new NDJSON logger. Checks `ASUPERSYNC_TEST_NDJSON` env var.
    #[must_use]
    pub fn new(level: TestLogLevel, ctx: Option<TestContext>) -> Self {
        let ndjson_enabled = std::env::var("ASUPERSYNC_TEST_NDJSON")
            .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        Self {
            inner: TestLogger::new(level),
            ctx,
            ndjson_enabled,
        }
    }

    /// Create with NDJSON output explicitly enabled.
    #[must_use]
    pub fn enabled(level: TestLogLevel, ctx: Option<TestContext>) -> Self {
        Self {
            inner: TestLogger::new(level),
            ctx,
            ndjson_enabled: true,
        }
    }

    /// Log an event, optionally emitting an NDJSON line to stderr.
    pub fn log(&self, event: TestEvent) {
        self.inner.log(event.clone());
        if self.ndjson_enabled {
            let record = LogRecord {
                elapsed: self.inner.elapsed(),
                event,
            };
            let ndjson = NdjsonEvent::from_record(&record, self.ctx.as_ref());
            eprintln!("{}", ndjson.to_json_line());
        }
    }

    /// Access the underlying [`TestLogger`].
    #[must_use]
    pub fn inner(&self) -> &TestLogger {
        &self.inner
    }

    /// Export all captured events as NDJSON lines.
    #[must_use]
    pub fn to_ndjson(&self) -> String {
        let events = self.inner.events();
        let mut output = String::new();
        for record in &events {
            let ndjson = NdjsonEvent::from_record(record, self.ctx.as_ref());
            output.push_str(&ndjson.to_json_line());
            output.push('\n');
        }
        output
    }

    /// Write all captured events as NDJSON to a file.
    pub fn write_ndjson_file(&self, path: &std::path::Path) -> std::io::Result<()> {
        std::fs::write(path, self.to_ndjson())
    }
}

// ============================================================================
// Trace File Naming Conventions
// ============================================================================

/// Generate a standardized trace file name.
///
/// Format: `{subsystem}_{scenario}_{seed:016x}.trace`
///
/// # Examples
///
/// ```
/// # use asupersync::test_ndjson::trace_file_name;
/// assert_eq!(
///     trace_file_name("scheduler", "cancel_drain", 0xDEAD_BEEF),
///     "scheduler_cancel_drain_00000000deadbeef.trace"
/// );
/// ```
#[must_use]
pub fn trace_file_name(subsystem: &str, scenario: &str, seed: u64) -> String {
    format!("{subsystem}_{scenario}_{seed:016x}.trace")
}

/// Generate a standardized NDJSON log file name.
///
/// Format: `{subsystem}_{scenario}_{seed:016x}.ndjson`
#[must_use]
pub fn ndjson_file_name(subsystem: &str, scenario: &str, seed: u64) -> String {
    format!("{subsystem}_{scenario}_{seed:016x}.ndjson")
}

// ============================================================================
// Artifact Bundle Helpers
// ============================================================================

/// Generate the standard artifact bundle directory path.
///
/// Layout: `{base_dir}/{test_id}/{seed:016x}/`
///
/// See [module documentation](self) for the full bundle contents.
#[must_use]
pub fn artifact_bundle_dir(
    base_dir: &std::path::Path,
    test_id: &str,
    seed: u64,
) -> std::path::PathBuf {
    base_dir.join(test_id).join(format!("{seed:016x}"))
}

/// Resolve the artifact base directory from the environment.
///
/// Checks `ASUPERSYNC_TEST_ARTIFACTS_DIR`, falling back to `target/test-artifacts`.
#[must_use]
pub fn artifact_base_dir() -> std::path::PathBuf {
    std::env::var("ASUPERSYNC_TEST_ARTIFACTS_DIR").map_or_else(
        |_| std::path::PathBuf::from("target/test-artifacts"),
        std::path::PathBuf::from,
    )
}

/// Write a complete artifact bundle for a test execution.
///
/// Creates the bundle directory and writes all available artifacts:
/// - `manifest.json` from the [`ReproManifest`]
/// - `events.ndjson` from the [`NdjsonLogger`] (if provided)
/// - `summary.json` from the [`TestSummary`] (if provided)
///
/// Returns the path to the bundle directory.
pub fn write_artifact_bundle(
    manifest: &ReproManifest,
    ndjson_logger: Option<&NdjsonLogger>,
    summary: Option<&TestSummary>,
) -> std::io::Result<std::path::PathBuf> {
    let base = artifact_base_dir();
    let bundle_dir = artifact_bundle_dir(&base, &manifest.scenario_id, manifest.seed);
    std::fs::create_dir_all(&bundle_dir)?;

    // Write manifest
    let manifest_json = serde_json::to_string_pretty(manifest).map_err(std::io::Error::other)?;
    std::fs::write(bundle_dir.join("manifest.json"), manifest_json)?;

    // Write NDJSON event log
    if let Some(logger) = ndjson_logger {
        logger.write_ndjson_file(&bundle_dir.join("events.ndjson"))?;
    }

    // Write test summary
    if let Some(s) = summary {
        let summary_json = serde_json::to_string_pretty(s).map_err(std::io::Error::other)?;
        std::fs::write(bundle_dir.join("summary.json"), summary_json)?;
    }

    Ok(bundle_dir)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_logging::{Interest, TestLogLevel};
    use std::time::Duration;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_ndjson_event_from_task_spawn() {
        init_test("test_ndjson_event_from_task_spawn");
        let record = LogRecord {
            elapsed: Duration::from_micros(1234),
            event: TestEvent::TaskSpawn {
                task_id: 42,
                name: Some("worker".into()),
            },
        };
        let ctx = TestContext::new("ndjson_test", 0xDEAD_BEEF).with_subsystem("scheduler");

        let ndjson = NdjsonEvent::from_record(&record, Some(&ctx));
        assert_eq!(ndjson.v, NDJSON_SCHEMA_VERSION);
        assert_eq!(ndjson.ts_us, 1234);
        assert_eq!(ndjson.level, "INFO");
        assert_eq!(ndjson.category, "task");
        assert_eq!(ndjson.event, "TaskSpawn");
        assert_eq!(ndjson.test_id.as_deref(), Some("ndjson_test"));
        assert_eq!(ndjson.seed, Some(0xDEAD_BEEF));
        assert_eq!(ndjson.subsystem.as_deref(), Some("scheduler"));
        assert_eq!(
            ndjson
                .data
                .get("task_id")
                .and_then(serde_json::Value::as_u64),
            Some(42)
        );
        assert_eq!(
            ndjson.data.get("name").and_then(|v| v.as_str()),
            Some("worker")
        );

        // Verify it produces valid JSON
        let json_line = ndjson.to_json_line();
        let parsed: serde_json::Value = serde_json::from_str(&json_line).expect("valid JSON");
        assert_eq!(parsed["v"], 1);
        assert_eq!(parsed["event"], "TaskSpawn");
        crate::test_complete!("test_ndjson_event_from_task_spawn");
    }

    #[test]
    fn test_ndjson_event_without_context() {
        init_test("test_ndjson_event_without_context");
        let record = LogRecord {
            elapsed: Duration::from_millis(5),
            event: TestEvent::ReactorPoll {
                timeout: None,
                events_returned: 3,
                duration: Duration::from_micros(100),
            },
        };

        let ndjson = NdjsonEvent::from_record(&record, None);
        assert!(ndjson.test_id.is_none());
        assert!(ndjson.seed.is_none());
        assert!(ndjson.subsystem.is_none());
        assert_eq!(ndjson.category, "reactor");
        assert_eq!(ndjson.event, "ReactorPoll");

        let json_line = ndjson.to_json_line();
        let parsed: serde_json::Value = serde_json::from_str(&json_line).expect("valid JSON");
        assert!(parsed.get("test_id").is_none());
        assert!(parsed.get("seed").is_none());
        crate::test_complete!("test_ndjson_event_without_context");
    }

    #[test]
    fn test_ndjson_logger_captures_and_exports() {
        init_test("test_ndjson_logger_captures_and_exports");
        let ctx = TestContext::new("ndjson_export", 0x42).with_subsystem("io");
        let logger = NdjsonLogger::enabled(TestLogLevel::Trace, Some(ctx));

        logger.log(TestEvent::IoRead {
            token: 5,
            bytes: 1024,
            would_block: false,
        });
        logger.log(TestEvent::IoWrite {
            token: 5,
            bytes: 512,
            would_block: false,
        });
        logger.log(TestEvent::TaskSpawn {
            task_id: 1,
            name: None,
        });

        let ndjson_output = logger.to_ndjson();
        let lines: Vec<&str> = ndjson_output.trim().lines().collect();
        assert_eq!(lines.len(), 3, "should have 3 NDJSON lines");

        // Verify each line is valid JSON with correct schema version
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
            assert_eq!(parsed["v"], 1);
            assert_eq!(parsed["test_id"], "ndjson_export");
            assert_eq!(parsed["seed"], 0x42);
        }

        // Verify event ordering
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["event"], "IoRead");
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["event"], "IoWrite");
        crate::test_complete!("test_ndjson_logger_captures_and_exports");
    }

    #[test]
    fn test_trace_file_naming() {
        init_test("test_trace_file_naming");
        assert_eq!(
            trace_file_name("scheduler", "cancel_drain", 0xDEAD_BEEF),
            "scheduler_cancel_drain_00000000deadbeef.trace"
        );
        assert_eq!(
            ndjson_file_name("obligation", "leak_check", 42),
            "obligation_leak_check_000000000000002a.ndjson"
        );
        crate::test_complete!("test_trace_file_naming");
    }

    #[test]
    fn test_artifact_bundle_dir_layout() {
        init_test("test_artifact_bundle_dir_layout");
        let base = std::path::Path::new("/tmp/test-artifacts");
        let dir = artifact_bundle_dir(base, "cancel_test", 0xCAFE);
        assert_eq!(
            dir,
            std::path::PathBuf::from("/tmp/test-artifacts/cancel_test/000000000000cafe")
        );
        crate::test_complete!("test_artifact_bundle_dir_layout");
    }

    #[test]
    fn test_write_artifact_bundle_roundtrip() {
        init_test("test_write_artifact_bundle_roundtrip");

        let tmp = tempfile::TempDir::new().expect("create temp dir");
        std::env::set_var("ASUPERSYNC_TEST_ARTIFACTS_DIR", tmp.path());

        let ctx = TestContext::new("bundle_test", 0xBEEF)
            .with_subsystem("scheduler")
            .with_invariant("quiescence");

        let logger = NdjsonLogger::enabled(TestLogLevel::Info, Some(ctx.clone()));
        logger.log(TestEvent::TaskSpawn {
            task_id: 1,
            name: Some("test_task".into()),
        });
        logger.log(TestEvent::TaskComplete {
            task_id: 1,
            outcome: "ok",
        });

        let manifest = ReproManifest::from_context(&ctx, true)
            .with_env_snapshot()
            .with_phases(vec!["setup".to_string(), "exercise".to_string()]);

        let bundle_path =
            write_artifact_bundle(&manifest, Some(&logger), None).expect("write bundle");

        // Verify files exist
        assert!(bundle_path.join("manifest.json").exists());
        assert!(bundle_path.join("events.ndjson").exists());

        // Verify manifest content
        let manifest_str = std::fs::read_to_string(bundle_path.join("manifest.json")).unwrap();
        let loaded: ReproManifest = serde_json::from_str(&manifest_str).unwrap();
        assert_eq!(loaded.seed, 0xBEEF);
        assert_eq!(loaded.scenario_id, "bundle_test");
        assert!(loaded.passed);

        // Verify NDJSON content
        let ndjson_str = std::fs::read_to_string(bundle_path.join("events.ndjson")).unwrap();
        let lines: Vec<&str> = ndjson_str.trim().lines().collect();
        assert_eq!(lines.len(), 2);
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["event"], "TaskSpawn");

        std::env::remove_var("ASUPERSYNC_TEST_ARTIFACTS_DIR");
        crate::test_complete!("test_write_artifact_bundle_roundtrip");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_all_event_types_produce_valid_ndjson() {
        init_test("test_all_event_types_produce_valid_ndjson");
        let events = vec![
            TestEvent::ReactorPoll {
                timeout: None,
                events_returned: 0,
                duration: Duration::from_micros(10),
            },
            TestEvent::ReactorWake { source: "waker" },
            TestEvent::ReactorRegister {
                token: 1,
                interest: Interest {
                    readable: true,
                    writable: false,
                },
                source_type: "tcp",
            },
            TestEvent::ReactorDeregister { token: 1 },
            TestEvent::IoRead {
                token: 1,
                bytes: 100,
                would_block: false,
            },
            TestEvent::IoWrite {
                token: 2,
                bytes: 200,
                would_block: true,
            },
            TestEvent::IoConnect {
                addr: "127.0.0.1:8080".into(),
                result: "success",
            },
            TestEvent::IoAccept {
                local: "0.0.0.0:9090".into(),
                peer: "192.168.1.1:54321".into(),
            },
            TestEvent::WakerWake {
                token: 10,
                task_id: 1,
            },
            TestEvent::WakerClone { token: 11 },
            TestEvent::WakerDrop { token: 12 },
            TestEvent::TaskPoll {
                task_id: 1,
                result: "ready",
            },
            TestEvent::TaskSpawn {
                task_id: 2,
                name: Some("bg".into()),
            },
            TestEvent::TaskComplete {
                task_id: 1,
                outcome: "ok",
            },
            TestEvent::TimerScheduled {
                deadline: Duration::from_secs(5),
                task_id: 99,
            },
            TestEvent::TimerFired { task_id: 99 },
            TestEvent::RegionCreate {
                region_id: 1,
                parent_id: Some(0),
            },
            TestEvent::RegionStateChange {
                region_id: 1,
                from_state: "open",
                to_state: "closing",
            },
            TestEvent::RegionClose {
                region_id: 1,
                task_count: 3,
                duration: Duration::from_millis(100),
            },
            TestEvent::ObligationCreate {
                obligation_id: 50,
                kind: "permit",
                holder_id: 1,
            },
            TestEvent::ObligationResolve {
                obligation_id: 50,
                resolution: "commit",
            },
            TestEvent::Custom {
                category: "test",
                message: "hello".into(),
            },
            TestEvent::Error {
                category: "test",
                message: "oops".into(),
            },
            TestEvent::Warn {
                category: "test",
                message: "hmm".into(),
            },
        ];

        for event in events {
            let record = LogRecord {
                elapsed: Duration::from_micros(100),
                event,
            };
            let ndjson = NdjsonEvent::from_record(&record, None);
            let line = ndjson.to_json_line();
            let _parsed: serde_json::Value =
                serde_json::from_str(&line).expect("all events must produce valid JSON");
        }
        crate::test_complete!("test_all_event_types_produce_valid_ndjson");
    }
}
