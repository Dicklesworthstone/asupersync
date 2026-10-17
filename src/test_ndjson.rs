#![allow(clippy::all)]
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
//! ```
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
            ts_us: u64::try_from(record.elapsed.as_micros()).unwrap_or(u64::MAX),
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
#[allow(unsafe_code)]
#[path = "test_ndjson_inline_tests.rs"]
mod tests;
