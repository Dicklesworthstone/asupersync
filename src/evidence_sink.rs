//! Evidence sink trait and backends for runtime decision tracing (bd-1e2if.3).
//!
//! Every runtime decision point (scheduler, cancellation, budget) can emit
//! [`franken_evidence::EvidenceLedger`] entries through an [`EvidenceSink`].
//! The sink is carried by [`Cx`](crate::cx::Cx) and propagated to child tasks,
//! enabling automatic context-aware evidence collection.
//!
//! # Backends
//!
//! - [`NullSink`]: No-op (zero overhead when evidence collection is disabled).
//! - [`JsonlSink`]: Appends to a JSONL file via [`franken_evidence::export::JsonlExporter`].
//! - [`CollectorSink`]: In-memory collection for testing.

use parking_lot::Mutex;
use std::fmt;
use std::path::PathBuf;

use franken_evidence::EvidenceLedger;
use franken_evidence::export::JsonlExporter;

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Sink for runtime evidence entries.
///
/// Implementations must be `Send + Sync` so the sink can be shared across
/// tasks via `Arc<dyn EvidenceSink>`.
pub trait EvidenceSink: Send + Sync + fmt::Debug {
    /// Emit a single evidence entry.
    ///
    /// Implementations should not panic. If writing fails (e.g., disk full),
    /// the error is logged internally and the entry is dropped.
    fn emit(&self, entry: &EvidenceLedger);
}

// ---------------------------------------------------------------------------
// NullSink
// ---------------------------------------------------------------------------

/// No-op evidence sink. All entries are discarded.
#[derive(Debug, Clone, Copy)]
pub struct NullSink;

impl EvidenceSink for NullSink {
    fn emit(&self, _entry: &EvidenceLedger) {}
}

// ---------------------------------------------------------------------------
// JsonlSink
// ---------------------------------------------------------------------------

/// JSONL file-backed evidence sink.
///
/// Wraps [`JsonlExporter`] with a mutex for thread-safe appending.
/// Flush is called after every write to ensure durability.
pub struct JsonlSink {
    inner: Mutex<JsonlExporter>,
}

impl fmt::Debug for JsonlSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonlSink")
            .field("path", &self.path())
            .finish()
    }
}

impl JsonlSink {
    /// Open a JSONL sink at the given path.
    ///
    /// Creates the file if it does not exist. Appends to existing files.
    pub fn open(path: PathBuf) -> std::io::Result<Self> {
        let exporter = JsonlExporter::open(path)?;
        Ok(Self {
            inner: Mutex::new(exporter),
        })
    }

    /// Path to the current output file.
    pub fn path(&self) -> PathBuf {
        self.inner.lock().path().to_path_buf()
    }
}

impl EvidenceSink for JsonlSink {
    fn emit(&self, entry: &EvidenceLedger) {
        let mut exporter = self.inner.lock();
        if let Err(e) = exporter.append(entry).and_then(|_| exporter.flush()) {
            // Best-effort: log and continue. Evidence loss is acceptable;
            // runtime correctness must not depend on evidence collection.
            #[cfg(feature = "tracing-integration")]
            crate::tracing_compat::warn!(error = %e, "evidence sink write failed");
            let _ = e;
        }
    }
}

// ---------------------------------------------------------------------------
// CollectorSink (testing)
// ---------------------------------------------------------------------------

/// In-memory evidence collector for testing.
///
/// Stores all emitted entries for later assertion.
#[derive(Debug, Default)]
pub struct CollectorSink {
    entries: Mutex<Vec<EvidenceLedger>>,
}

impl CollectorSink {
    /// Create an empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return all collected entries.
    pub fn entries(&self) -> Vec<EvidenceLedger> {
        self.entries.lock().clone()
    }

    /// Number of collected entries.
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// Returns `true` if no entries have been collected.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl EvidenceSink for CollectorSink {
    fn emit(&self, entry: &EvidenceLedger) {
        self.entries.lock().push(entry.clone());
    }
}

// ---------------------------------------------------------------------------
// Evidence emission helpers
// ---------------------------------------------------------------------------

/// Emit an evidence entry for a scheduler lane-selection decision.
///
/// Called by the governor when a non-default scheduling suggestion is produced.
pub fn emit_scheduler_evidence(
    sink: &dyn EvidenceSink,
    suggestion: &str,
    cancel_depth: u32,
    timed_depth: u32,
    ready_depth: u32,
    fallback: bool,
) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);

    let total = f64::from((cancel_depth + timed_depth + ready_depth).max(1));
    let posterior = vec![
        f64::from(cancel_depth) / total,
        f64::from(timed_depth) / total,
        f64::from(ready_depth) / total,
    ];

    let entry = EvidenceLedger {
        ts_unix_ms: now_ms,
        component: "scheduler".to_string(),
        action: suggestion.to_string(),
        posterior,
        expected_loss_by_action: std::collections::BTreeMap::from([
            ("meet_deadlines".to_string(), f64::from(timed_depth)),
            ("drain_cancel".to_string(), f64::from(cancel_depth)),
            ("process_ready".to_string(), f64::from(ready_depth)),
        ]),
        chosen_expected_loss: 0.0,
        calibration_score: if fallback { 0.0 } else { 1.0 },
        fallback_active: fallback,
        top_features: vec![
            ("cancel_depth".to_string(), f64::from(cancel_depth)),
            ("timed_depth".to_string(), f64::from(timed_depth)),
            ("ready_depth".to_string(), f64::from(ready_depth)),
        ],
    };
    sink.emit(&entry);
}

/// Emit an evidence entry for a cancellation decision.
///
/// Called when a task transitions to `CancelRequested` state.
pub fn emit_cancel_evidence(
    sink: &dyn EvidenceSink,
    cancel_kind: &str,
    cleanup_poll_quota: u32,
    cleanup_priority: u8,
) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);

    let action = format!("cancel_{cancel_kind}");
    let entry = EvidenceLedger {
        ts_unix_ms: now_ms,
        component: "cancellation".to_string(),
        expected_loss_by_action: std::collections::BTreeMap::from([(action.clone(), 0.0)]),
        action,
        posterior: vec![1.0],
        chosen_expected_loss: 0.0,
        calibration_score: 1.0,
        fallback_active: false,
        top_features: vec![
            (
                "cleanup_poll_quota".to_string(),
                f64::from(cleanup_poll_quota),
            ),
            ("cleanup_priority".to_string(), f64::from(cleanup_priority)),
        ],
    };
    sink.emit(&entry);
}

/// Emit an evidence entry for a budget exhaustion event.
///
/// Called when a budget check determines exhaustion at a checkpoint.
pub fn emit_budget_evidence(
    sink: &dyn EvidenceSink,
    exhaustion_kind: &str,
    polls_remaining: u32,
    deadline_remaining_ms: Option<u64>,
) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);

    let action = format!("exhausted_{exhaustion_kind}");
    let entry = EvidenceLedger {
        ts_unix_ms: now_ms,
        component: "budget".to_string(),
        expected_loss_by_action: std::collections::BTreeMap::from([(action.clone(), 0.0)]),
        action,
        posterior: vec![1.0],
        chosen_expected_loss: 0.0,
        calibration_score: 1.0,
        fallback_active: false,
        #[allow(clippy::cast_precision_loss)] // deliberate: u64::MAX sentinel is fine as f64
        top_features: vec![
            ("polls_remaining".to_string(), f64::from(polls_remaining)),
            (
                "deadline_remaining_ms".to_string(),
                deadline_remaining_ms.unwrap_or(u64::MAX) as f64,
            ),
        ],
    };
    sink.emit(&entry);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use franken_evidence::EvidenceLedgerBuilder;
    use std::sync::Arc;

    fn test_entry(component: &str) -> EvidenceLedger {
        EvidenceLedgerBuilder::new()
            .ts_unix_ms(1_700_000_000_000)
            .component(component)
            .action("test_action")
            .posterior(vec![0.6, 0.4])
            .chosen_expected_loss(0.1)
            .calibration_score(0.85)
            .build()
            .unwrap()
    }

    #[test]
    fn null_sink_accepts_entries() {
        let sink = NullSink;
        sink.emit(&test_entry("scheduler"));
    }

    #[test]
    fn collector_sink_captures_entries() {
        let sink = CollectorSink::new();
        assert!(sink.is_empty());

        sink.emit(&test_entry("scheduler"));
        sink.emit(&test_entry("cancel"));

        assert_eq!(sink.len(), 2);
        let entries = sink.entries();
        assert_eq!(entries[0].component, "scheduler");
        assert_eq!(entries[1].component, "cancel");
    }

    #[test]
    fn collector_sink_as_trait_object() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        sink.emit(&test_entry("budget"));
    }

    #[test]
    fn jsonl_sink_write_and_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");

        let sink = JsonlSink::open(path.clone()).unwrap();
        sink.emit(&test_entry("scheduler"));
        sink.emit(&test_entry("cancel"));

        let entries = franken_evidence::export::read_jsonl(&path).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].component, "scheduler");
        assert_eq!(entries[1].component, "cancel");
    }

    // ---- emit helpers ----

    #[test]
    fn emit_scheduler_evidence_populates_fields() {
        let sink = CollectorSink::new();
        emit_scheduler_evidence(&sink, "cancel_lane", 10, 5, 3, false);

        assert_eq!(sink.len(), 1);
        let entry = &sink.entries()[0];
        assert_eq!(entry.component, "scheduler");
        assert_eq!(entry.action, "cancel_lane");
        assert!(!entry.fallback_active);
        assert!(
            (entry.calibration_score - 1.0).abs() < f64::EPSILON,
            "expected 1.0, got {}",
            entry.calibration_score
        );
        // posterior should sum to ~1.0
        let sum: f64 = entry.posterior.iter().sum();
        assert!((sum - 1.0).abs() < 1e-9, "posterior sum={sum}");
        // top_features should include depth values
        assert_eq!(entry.top_features.len(), 3);
    }

    #[test]
    fn emit_scheduler_evidence_fallback_sets_calibration_zero() {
        let sink = CollectorSink::new();
        emit_scheduler_evidence(&sink, "ready_lane", 0, 0, 1, true);

        let entry = &sink.entries()[0];
        assert!(entry.fallback_active);
        assert!(
            (entry.calibration_score).abs() < f64::EPSILON,
            "expected 0.0, got {}",
            entry.calibration_score
        );
    }

    #[test]
    fn emit_scheduler_evidence_all_zero_depths() {
        let sink = CollectorSink::new();
        emit_scheduler_evidence(&sink, "idle", 0, 0, 0, false);

        let entry = &sink.entries()[0];
        // All-zero depths: posterior should be [0, 0, 0] (0/max(1,0))
        assert_eq!(entry.posterior.len(), 3);
        // denominator is max(1, 0+0+0) = 1, so all zeros
        for &p in &entry.posterior {
            assert!((p).abs() < f64::EPSILON, "expected 0.0, got {p}");
        }
    }

    #[test]
    fn emit_cancel_evidence_populates_fields() {
        let sink = CollectorSink::new();
        emit_cancel_evidence(&sink, "user", 5, 2);

        assert_eq!(sink.len(), 1);
        let entry = &sink.entries()[0];
        assert_eq!(entry.component, "cancellation");
        assert_eq!(entry.action, "cancel_user");
        assert_eq!(entry.posterior, vec![1.0]);
        assert!(!entry.fallback_active);
        assert_eq!(entry.top_features.len(), 2);
        assert_eq!(entry.top_features[0].0, "cleanup_poll_quota");
        assert!(
            (entry.top_features[0].1 - 5.0).abs() < f64::EPSILON,
            "expected 5.0, got {}",
            entry.top_features[0].1
        );
        assert_eq!(entry.top_features[1].0, "cleanup_priority");
        assert!(
            (entry.top_features[1].1 - 2.0).abs() < f64::EPSILON,
            "expected 2.0, got {}",
            entry.top_features[1].1
        );
    }

    #[test]
    fn emit_budget_evidence_with_deadline() {
        let sink = CollectorSink::new();
        emit_budget_evidence(&sink, "poll", 0, Some(500));

        assert_eq!(sink.len(), 1);
        let entry = &sink.entries()[0];
        assert_eq!(entry.component, "budget");
        assert_eq!(entry.action, "exhausted_poll");
        assert!(
            (entry.top_features[0].1).abs() < f64::EPSILON,
            "expected 0.0, got {}",
            entry.top_features[0].1
        ); // polls_remaining
        assert!(
            (entry.top_features[1].1 - 500.0).abs() < f64::EPSILON,
            "expected 500.0, got {}",
            entry.top_features[1].1
        ); // deadline_remaining_ms
    }

    #[test]
    fn emit_budget_evidence_without_deadline() {
        let sink = CollectorSink::new();
        emit_budget_evidence(&sink, "time", 10, None);

        let entry = &sink.entries()[0];
        assert_eq!(entry.action, "exhausted_time");
        // None deadline -> u64::MAX as f64
        #[allow(clippy::cast_precision_loss, clippy::float_cmp)]
        {
            assert_eq!(entry.top_features[1].1, u64::MAX as f64);
        }
    }

    // ---- CollectorSink ----

    #[test]
    fn collector_sink_default_is_empty() {
        let sink = CollectorSink::default();
        assert!(sink.is_empty());
        assert_eq!(sink.len(), 0);
        assert!(sink.entries().is_empty());
    }

    #[test]
    fn collector_sink_debug_impl() {
        let sink = CollectorSink::new();
        let dbg = format!("{sink:?}");
        assert!(dbg.contains("CollectorSink"), "{dbg}");
    }

    // ---- NullSink ----

    #[test]
    fn null_sink_is_clone_and_copy() {
        let a = NullSink;
        let b = a;
        let c = a;
        // All are usable (Copy + Clone)
        b.emit(&test_entry("x"));
        c.emit(&test_entry("y"));
    }

    #[test]
    fn null_sink_debug_impl() {
        let dbg = format!("{NullSink:?}");
        assert_eq!(dbg, "NullSink");
    }

    // ---- JsonlSink ----

    #[test]
    fn jsonl_sink_path_returns_file_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.jsonl");
        let sink = JsonlSink::open(path.clone()).unwrap();
        assert_eq!(sink.path(), path);
    }

    #[test]
    fn jsonl_sink_debug_contains_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("debug_test.jsonl");
        let sink = JsonlSink::open(path).unwrap();
        let dbg = format!("{sink:?}");
        assert!(dbg.contains("JsonlSink"), "{dbg}");
        assert!(dbg.contains("debug_test.jsonl"), "{dbg}");
    }

    #[test]
    fn jsonl_sink_appends_multiple_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("append.jsonl");

        let sink = JsonlSink::open(path.clone()).unwrap();
        for i in 0..5 {
            sink.emit(&test_entry(&format!("comp_{i}")));
        }

        let entries = franken_evidence::export::read_jsonl(&path).unwrap();
        assert_eq!(entries.len(), 5);
        for (i, entry) in entries.iter().enumerate().take(5) {
            assert_eq!(entry.component, format!("comp_{i}"));
        }
    }

    // ---- Gap tests ----

    #[test]
    fn collector_sink_entries_fifo_order() {
        let sink = CollectorSink::new();
        for name in &["a", "b", "c", "d", "e"] {
            sink.emit(&test_entry(name));
        }
        let entries = sink.entries();
        let names: Vec<&str> = entries.iter().map(|e| e.component.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c", "d", "e"]);
    }

    #[test]
    fn emit_scheduler_evidence_expected_loss_keys() {
        let sink = CollectorSink::new();
        emit_scheduler_evidence(&sink, "test_lane", 10, 5, 3, false);

        let entry = &sink.entries()[0];
        let map = &entry.expected_loss_by_action;

        assert!(
            map.contains_key("meet_deadlines"),
            "missing meet_deadlines key"
        );
        assert!(map.contains_key("drain_cancel"), "missing drain_cancel key");
        assert!(
            map.contains_key("process_ready"),
            "missing process_ready key"
        );

        let meet = map["meet_deadlines"];
        let drain = map["drain_cancel"];
        let ready = map["process_ready"];

        assert!(
            (meet - 5.0).abs() < f64::EPSILON,
            "meet_deadlines: expected 5.0, got {meet}"
        );
        assert!(
            (drain - 10.0).abs() < f64::EPSILON,
            "drain_cancel: expected 10.0, got {drain}"
        );
        assert!(
            (ready - 3.0).abs() < f64::EPSILON,
            "process_ready: expected 3.0, got {ready}"
        );
    }

    #[test]
    fn collector_sink_concurrent_access() {
        let sink = Arc::new(CollectorSink::new());
        let mut handles = Vec::new();
        for t in 0..4u32 {
            let sink = Arc::clone(&sink);
            handles.push(std::thread::spawn(move || {
                for i in 0..25u32 {
                    let component = format!("t{t}_i{i}");
                    sink.emit(&{
                        EvidenceLedgerBuilder::new()
                            .ts_unix_ms(1_700_000_000_000 + u64::from(t * 100 + i))
                            .component(&component)
                            .action("concurrent_test")
                            .posterior(vec![1.0])
                            .chosen_expected_loss(0.0)
                            .calibration_score(1.0)
                            .build()
                            .unwrap()
                    });
                }
            }));
        }
        for h in handles {
            h.join().expect("thread panicked");
        }
        assert_eq!(sink.len(), 100, "expected 100 entries, got {}", sink.len());
    }
}
