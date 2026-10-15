#![allow(dead_code)]
//! Structured-logging test harness — per-test JSONL evidence writer (br-asupersync-364340).
//!
//! Each integration test opens a [`TestEvidenceSink`] scoped to its own name.
//! Every call to `emit_*` appends one JSON line to `tests/_evidence/<test_name>.jsonl`
//! with the shape required by the testing-perfect-e2e skill:
//!
//! ```json
//! {"test_name":"...","seq":0,"ts_unix_nanos":...,"phase":"setup",
//!  "cx_id":"r42/t101","event":"lab_runtime_built","outcome":"ok","error":null}
//! ```
//!
//! The harness is deliberately **zero-dependency against the runtime**: it does
//! not reuse `asupersync::evidence_sink::EvidenceSink` because that trait
//! carries `franken_evidence::EvidenceLedger` entries (posterior, calibration,
//! expected-loss). Tests need a flatter, grep-friendly record keyed on
//! `{test_name, phase, cx_id, event, outcome}`.
//!
//! Files accumulate across runs — each test truncates its own JSONL on
//! `TestEvidenceSink::new`, so re-running a single test produces a clean
//! artefact rather than appending to stale history.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use asupersync::cx::Cx;

// ---------------------------------------------------------------------------
// Record shape
// ---------------------------------------------------------------------------

/// One line in `tests/_evidence/<test_name>.jsonl`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestEvidenceRecord {
    pub test_name: String,
    pub seq: u64,
    pub ts_unix_nanos: u128,
    pub phase: String,
    pub cx_id: String,
    pub event: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Lifecycle phase for a test. Strings are stable across schema versions.
#[derive(Debug, Clone)]
pub enum TestPhase {
    Setup,
    Execute,
    Assert,
    Teardown,
    Custom(String),
}

impl TestPhase {
    fn as_str(&self) -> &str {
        match self {
            Self::Setup => "setup",
            Self::Execute => "execute",
            Self::Assert => "assert",
            Self::Teardown => "teardown",
            Self::Custom(s) => s.as_str(),
        }
    }
}

/// Outcome of a single evidence event.
#[derive(Debug, Clone)]
pub enum TestOutcome {
    Ok,
    Err(String),
    Cancelled,
    Panicked,
    Pending,
    Note,
}

impl TestOutcome {
    fn as_str(&self) -> &str {
        match self {
            Self::Ok => "ok",
            Self::Err(_) => "err",
            Self::Cancelled => "cancelled",
            Self::Panicked => "panicked",
            Self::Pending => "pending",
            Self::Note => "note",
        }
    }

    fn error_message(&self) -> Option<String> {
        match self {
            Self::Err(msg) => Some(msg.clone()),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Sink
// ---------------------------------------------------------------------------

/// Per-test evidence writer — creates `tests/_evidence/<test_name>.jsonl`
/// on `new` and appends JSON lines via `emit_*`.
pub struct TestEvidenceSink {
    test_name: String,
    path: PathBuf,
    writer: Mutex<BufWriter<File>>,
    seq: AtomicU64,
}

impl TestEvidenceSink {
    /// Open (and truncate) the evidence file for the given test.
    ///
    /// Resolves `tests/_evidence/` relative to `CARGO_MANIFEST_DIR`, so the
    /// behaviour is independent of the current working directory at test
    /// startup. Failure falls back to `/dev/null` with a warning so tests
    /// never abort on a missing directory.
    pub fn new(test_name: &str) -> Self {
        Self::with_dir(&evidence_dir(), test_name)
    }

    /// Open (and truncate) the evidence file inside an explicit directory —
    /// primarily for self-tests so they can point at a `tempfile::TempDir`
    /// without mutating process-wide environment variables.
    pub fn with_dir(dir: &Path, test_name: &str) -> Self {
        let sanitized = sanitize_filename(test_name);
        let path = dir.join(format!("{sanitized}.jsonl"));
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap_or_else(|err| {
                eprintln!(
                    "[test_evidence_harness] falling back to /dev/null for {test_name}: {err}"
                );
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open("/dev/null")
                    .expect("open /dev/null")
            });
        Self {
            test_name: test_name.to_string(),
            path,
            writer: Mutex::new(BufWriter::new(file)),
            seq: AtomicU64::new(0),
        }
    }

    /// Path to the JSONL file backing this sink.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Monotonic record count emitted so far.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }

    /// Emit one record, deriving `cx_id` from a live `Cx`.
    pub fn emit(&self, phase: TestPhase, cx: &Cx, event: &str, outcome: TestOutcome) {
        let cx_id = format!("r{:?}/t{:?}", cx.region_id(), cx.task_id());
        self.emit_raw(phase, &cx_id, event, outcome);
    }

    /// Emit one record with an explicit `cx_id` — for setup/teardown phases
    /// where no `Cx` exists yet, or for cross-cx correlation events.
    pub fn emit_raw(&self, phase: TestPhase, cx_id: &str, event: &str, outcome: TestOutcome) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let ts_unix_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let record = TestEvidenceRecord {
            test_name: self.test_name.clone(),
            seq,
            ts_unix_nanos,
            phase: phase.as_str().to_string(),
            cx_id: cx_id.to_string(),
            event: event.to_string(),
            outcome: outcome.as_str().to_string(),
            error: outcome.error_message(),
        };
        // serde_json::to_string cannot fail for this shape (all fields are
        // owned primitives/strings); unwrap is infallible in practice.
        let line = serde_json::to_string(&record).unwrap_or_else(|e| {
            format!(
                r#"{{"test_name":"{}","seq":{seq},"phase":"{}","event":"serde_error","outcome":"err","error":"{e}"}}"#,
                self.test_name,
                phase.as_str()
            )
        });
        let mut w = self.writer.lock();
        if let Err(err) = writeln!(w, "{line}") {
            eprintln!(
                "[test_evidence_harness] write failed for {}: {err}",
                self.test_name
            );
        }
        // Flush every line so a crashing test still leaves full evidence.
        let _ = w.flush();
    }

    /// Convenience: emit a setup event.
    pub fn setup(&self, event: &str, outcome: TestOutcome) {
        self.emit_raw(TestPhase::Setup, "-", event, outcome);
    }

    /// Convenience: emit a teardown event.
    pub fn teardown(&self, event: &str, outcome: TestOutcome) {
        self.emit_raw(TestPhase::Teardown, "-", event, outcome);
    }

    /// Convenience: emit an assert event.
    pub fn assert_event(&self, cx: &Cx, event: &str, outcome: TestOutcome) {
        self.emit(TestPhase::Assert, cx, event, outcome);
    }

    /// Convenience: emit an execute-phase event.
    pub fn execute(&self, cx: &Cx, event: &str, outcome: TestOutcome) {
        self.emit(TestPhase::Execute, cx, event, outcome);
    }
}

impl std::fmt::Debug for TestEvidenceSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestEvidenceSink")
            .field("test_name", &self.test_name)
            .field("path", &self.path)
            .field("seq", &self.seq.load(Ordering::Relaxed))
            .finish()
    }
}

impl Drop for TestEvidenceSink {
    fn drop(&mut self) {
        let _ = self.writer.lock().flush();
    }
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Resolve the `tests/_evidence/` directory. Honours
/// `ASUPERSYNC_TEST_EVIDENCE_DIR` for CI overrides; otherwise sits next to
/// `CARGO_MANIFEST_DIR`.
pub fn evidence_dir() -> PathBuf {
    if let Ok(p) = std::env::var("ASUPERSYNC_TEST_EVIDENCE_DIR") {
        return PathBuf::from(p);
    }
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    manifest.join("tests").join("_evidence")
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' => c,
            _ => '_',
        })
        .collect()
}

/// Read back a previously-written evidence file — utility for tests that
/// want to assert over their own JSONL.
pub fn read_evidence(path: &Path) -> Vec<TestEvidenceRecord> {
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<TestEvidenceRecord>(l).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sink_writes_lines_with_required_fields() {
        let tmp = tempfile::tempdir().unwrap();

        let sink = TestEvidenceSink::with_dir(tmp.path(), "harness_selftest");
        sink.setup("init_runtime", TestOutcome::Ok);
        sink.emit_raw(TestPhase::Execute, "r1/t1", "run_future", TestOutcome::Ok);
        sink.emit_raw(
            TestPhase::Assert,
            "r1/t1",
            "check_invariant",
            TestOutcome::Err("invariant X violated".into()),
        );
        sink.teardown("close_region", TestOutcome::Cancelled);
        drop(sink);

        let path = tmp.path().join("harness_selftest.jsonl");
        let records = read_evidence(&path);
        assert_eq!(records.len(), 4, "expected 4 records in {path:?}");
        assert_eq!(records[0].phase, "setup");
        assert_eq!(records[0].event, "init_runtime");
        assert_eq!(records[0].outcome, "ok");
        assert_eq!(records[0].cx_id, "-");
        assert_eq!(records[1].phase, "execute");
        assert_eq!(records[1].cx_id, "r1/t1");
        assert_eq!(records[2].outcome, "err");
        assert_eq!(records[2].error.as_deref(), Some("invariant X violated"));
        assert_eq!(records[3].outcome, "cancelled");
        // seq is monotonic and dense
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r.seq, i as u64);
            assert!(!r.test_name.is_empty());
            assert!(r.ts_unix_nanos > 0);
        }
    }

    #[test]
    fn sink_truncates_on_reopen() {
        let tmp = tempfile::tempdir().unwrap();

        {
            let sink = TestEvidenceSink::with_dir(tmp.path(), "truncate_test");
            sink.setup("first_run_event", TestOutcome::Ok);
        }
        let path = tmp.path().join("truncate_test.jsonl");
        assert_eq!(read_evidence(&path).len(), 1);

        {
            let sink = TestEvidenceSink::with_dir(tmp.path(), "truncate_test");
            sink.setup("second_run_event", TestOutcome::Ok);
            sink.setup("third", TestOutcome::Ok);
        }
        let records = read_evidence(&path);
        assert_eq!(records.len(), 2, "reopen should truncate prior content");
        assert_eq!(records[0].event, "second_run_event");
    }

    #[test]
    fn filename_sanitizer_replaces_path_chars() {
        assert_eq!(sanitize_filename("foo::bar/baz"), "foo__bar_baz");
        assert_eq!(sanitize_filename("ok_name-1.2"), "ok_name-1.2");
        assert_eq!(sanitize_filename(".."), "..");
    }

    #[test]
    fn phase_and_outcome_stringify_stably() {
        assert_eq!(TestPhase::Setup.as_str(), "setup");
        assert_eq!(TestPhase::Execute.as_str(), "execute");
        assert_eq!(TestPhase::Assert.as_str(), "assert");
        assert_eq!(TestPhase::Teardown.as_str(), "teardown");
        assert_eq!(TestPhase::Custom("warmup".into()).as_str(), "warmup");

        assert_eq!(TestOutcome::Ok.as_str(), "ok");
        assert_eq!(TestOutcome::Err("x".into()).as_str(), "err");
        assert_eq!(TestOutcome::Cancelled.as_str(), "cancelled");
        assert_eq!(TestOutcome::Panicked.as_str(), "panicked");
        assert_eq!(TestOutcome::Pending.as_str(), "pending");
        assert_eq!(TestOutcome::Note.as_str(), "note");
    }

    #[test]
    fn evidence_dir_falls_back_to_manifest_relative_path() {
        // When no env override is set, the dir resolves under CARGO_MANIFEST_DIR.
        if std::env::var_os("ASUPERSYNC_TEST_EVIDENCE_DIR").is_none() {
            let dir = evidence_dir();
            assert!(
                dir.ends_with("tests/_evidence"),
                "unexpected evidence_dir {dir:?}"
            );
        }
    }

    #[test]
    fn multiple_threads_writing_concurrently_preserve_line_framing() {
        use std::sync::Arc;
        let tmp = tempfile::tempdir().unwrap();

        let sink = Arc::new(TestEvidenceSink::with_dir(
            tmp.path(),
            "concurrent_selftest",
        ));
        let mut handles = Vec::new();
        for t in 0..4u32 {
            let s = Arc::clone(&sink);
            handles.push(std::thread::spawn(move || {
                for i in 0..25u32 {
                    s.emit_raw(
                        TestPhase::Execute,
                        &format!("r{t}/t{i}"),
                        "concurrent_event",
                        TestOutcome::Ok,
                    );
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        drop(sink);

        let path = tmp.path().join("concurrent_selftest.jsonl");
        let records = read_evidence(&path);
        assert_eq!(records.len(), 100);
        // Each record parsed cleanly, confirming writeln is line-atomic under
        // the writer mutex.
        for r in &records {
            assert_eq!(r.event, "concurrent_event");
        }
    }
}
