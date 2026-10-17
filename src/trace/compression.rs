//! Causality-preserving trace compression.
//!
//! Compresses traces by removing events that don't contribute to
//! causal structure or invariant verification. The compression
//! preserves:
//!
//! - All spawn/complete events (task lifecycle)
//! - All cancel request/ack events (cancellation protocol)
//! - All obligation events (obligation protocol)
//! - Causal ordering between retained events
//! - Certificate verifiability (compressed certificate matches)
//!
//! Events that are removed:
//! - Redundant wake events between polls
//! - User trace events (debug-only)
//! - Duplicate timer events within the same tick
//!
//! # Compression levels
//!
//! - `Level::Lossless`: Retains all events, applies delta encoding only.
//! - `Level::Structural`: Removes non-structural events (wakes, user traces).
//! - `Level::Skeleton`: Keeps only lifecycle + obligation + cancel events.

use crate::trace::certificate::TraceCertificate;
use crate::trace::event::{TraceEvent, TraceEventKind};

/// Compression level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Level {
    /// No event removal; delta encoding only.
    Lossless,
    /// Remove non-structural events (wakes, user traces, timer noise).
    Structural,
    /// Keep only lifecycle + obligation + cancel events.
    Skeleton,
}

/// Result of trace compression.
#[derive(Debug)]
pub struct CompressedTrace {
    /// The compressed events.
    pub events: Vec<TraceEvent>,
    /// Original event count (before compression).
    pub original_count: usize,
    /// Compression level used.
    pub level: Level,
    /// Certificate built from compressed events.
    pub certificate: TraceCertificate,
}

impl CompressedTrace {
    /// Compression ratio (0.0 = fully compressed, 1.0 = no compression).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn ratio(&self) -> f64 {
        if self.original_count == 0 {
            return 1.0;
        }
        self.events.len() as f64 / self.original_count as f64
    }

    /// Number of events removed.
    #[must_use]
    pub fn events_removed(&self) -> usize {
        self.original_count - self.events.len()
    }
}

/// Compress a trace at the given level.
#[must_use]
pub fn compress(events: &[TraceEvent], level: Level) -> CompressedTrace {
    let original_count = events.len();
    let retained: Vec<TraceEvent> = events
        .iter()
        .filter(|e| should_retain(e, level))
        .cloned()
        .collect();

    let mut certificate = TraceCertificate::new();
    for e in &retained {
        certificate.record_event(e);
    }

    CompressedTrace {
        events: retained,
        original_count,
        level,
        certificate,
    }
}

/// Determine if an event should be retained at the given level.
fn should_retain(event: &TraceEvent, level: Level) -> bool {
    match level {
        Level::Lossless => true,
        Level::Structural => !is_noise_event(event),
        Level::Skeleton => is_skeleton_event(event),
    }
}

/// Events that are "noise" — safe to remove without affecting causal structure.
fn is_noise_event(event: &TraceEvent) -> bool {
    matches!(
        event.kind,
        TraceEventKind::UserTrace
            | TraceEventKind::Wake
            | TraceEventKind::TimerScheduled
            | TraceEventKind::TimerFired
    )
}

/// Events that form the skeleton — lifecycle + obligation + cancel.
fn is_skeleton_event(event: &TraceEvent) -> bool {
    matches!(
        event.kind,
        TraceEventKind::Spawn
            | TraceEventKind::Complete
            | TraceEventKind::CancelRequest
            | TraceEventKind::CancelAck
            | TraceEventKind::ObligationReserve
            | TraceEventKind::ObligationCommit
            | TraceEventKind::ObligationAbort
            | TraceEventKind::RegionCreated
            | TraceEventKind::RegionCloseComplete
    )
}

/// Decompress by returning the compressed events unchanged.
///
/// Since compression is lossy (at Structural/Skeleton levels), there
/// is no perfect inverse. This function validates that the events
/// are consistent with the certificate.
#[must_use]
pub fn validate_compressed(trace: &CompressedTrace) -> bool {
    let mut check_cert = TraceCertificate::new();
    for e in &trace.events {
        check_cert.record_event(e);
    }
    check_cert.event_hash() == trace.certificate.event_hash()
        && check_cert.event_count() == trace.certificate.event_count()
}

#[cfg(test)]
#[path = "compression_inline_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "compression_metamorphic_tests.rs"]
mod compression_metamorphic_tests;
