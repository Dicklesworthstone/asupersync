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
use std::sync::atomic::{AtomicU64, Ordering};

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

    /// Return the next deterministic evidence timestamp for this sink.
    ///
    /// Evidence helpers use this instead of ambient wall-clock time so
    /// repeated runs with the same event order produce replayable logs.
    fn next_evidence_ts(&self) -> u64;
}

// ---------------------------------------------------------------------------
// NullSink
// ---------------------------------------------------------------------------

/// No-op evidence sink. All entries are discarded.
#[derive(Debug, Clone, Copy)]
pub struct NullSink;

impl EvidenceSink for NullSink {
    fn emit(&self, _entry: &EvidenceLedger) {}

    fn next_evidence_ts(&self) -> u64 {
        0
    }
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
    timestamp_seq: AtomicU64,
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
            timestamp_seq: AtomicU64::new(0),
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

    fn next_evidence_ts(&self) -> u64 {
        // br-asupersync-n1g6sm — wrapping_add preserves uniqueness across
        // the full u64 cycle. The previous saturating_add path collided
        // at u64::MAX (fetch_add(1) on the atomic at u64::MAX-1 returns
        // u64::MAX-1 then saturating_add(1) yields u64::MAX; the next
        // call sees the atomic wrap to 0, returns u64::MAX from the
        // saturating add too — TWO consecutive calls return the same
        // value, breaking ordering and replay-time deduplication).
        // wrapping_add never collides; the consumer is responsible for
        // tolerating wraparound in long-lived deployments.
        self.timestamp_seq
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
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
    timestamp_seq: AtomicU64,
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

    fn next_evidence_ts(&self) -> u64 {
        // br-asupersync-n1g6sm — see JsonlSink::next_evidence_ts for the
        // collision analysis; same fix.
        self.timestamp_seq
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }
}

// ---------------------------------------------------------------------------
// Evidence emission helpers
// ---------------------------------------------------------------------------

/// Emit an evidence entry for a scheduler lane-selection decision.
///
/// A worker calls this for every governor decision, a repeated suggestion included.
pub fn emit_scheduler_evidence(
    sink: &dyn EvidenceSink,
    suggestion: &str,
    cancel_depth: u32,
    timed_depth: u32,
    ready_depth: u32,
    fallback: bool,
) {
    let total = f64::from(
        cancel_depth
            .saturating_add(timed_depth)
            .saturating_add(ready_depth)
            .max(1),
    );
    let posterior = vec![
        f64::from(cancel_depth) / total,
        f64::from(timed_depth) / total,
        f64::from(ready_depth) / total,
    ];
    let chosen_expected_loss = match suggestion {
        "drain_obligations" | "drain_cancel" | "cancel_lane" => f64::from(cancel_depth),
        "meet_deadlines" | "drain_regions" => f64::from(timed_depth),
        "process_ready" | "ready_lane" => f64::from(ready_depth),
        _ => 0.0,
    };
    let action = suggestion.to_string();

    let entry = EvidenceLedger {
        ts_unix_ms: sink.next_evidence_ts(),
        component: "scheduler".to_string(),
        action: action.clone(),
        posterior,
        expected_loss_by_action: std::collections::BTreeMap::from([(action, chosen_expected_loss)]),
        chosen_expected_loss,
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
    let action = format!("cancel_{cancel_kind}");
    let entry = EvidenceLedger {
        ts_unix_ms: sink.next_evidence_ts(),
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
    let action = format!("exhausted_{exhaustion_kind}");
    let entry = EvidenceLedger {
        ts_unix_ms: sink.next_evidence_ts(),
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
#[path = "evidence_sink_inline_tests.rs"]
mod tests;
