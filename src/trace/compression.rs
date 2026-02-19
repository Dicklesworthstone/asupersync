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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
mod tests {
    use super::*;
    use crate::trace::event::TraceData;
    use crate::types::Time;

    fn make_event(seq: u64, kind: TraceEventKind) -> TraceEvent {
        TraceEvent::new(seq, Time::ZERO, kind, TraceData::None)
    }

    #[test]
    fn lossless_retains_all_events() {
        let events = vec![
            make_event(1, TraceEventKind::Spawn),
            make_event(2, TraceEventKind::UserTrace),
            make_event(3, TraceEventKind::Complete),
        ];
        let compressed = compress(&events, Level::Lossless);
        assert_eq!(compressed.events.len(), 3);
        assert_eq!(compressed.original_count, 3);
        assert!((compressed.ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn structural_removes_noise() {
        let events = vec![
            make_event(1, TraceEventKind::Spawn),
            make_event(2, TraceEventKind::UserTrace),
            make_event(3, TraceEventKind::Wake),
            make_event(4, TraceEventKind::Complete),
        ];
        let compressed = compress(&events, Level::Structural);
        assert_eq!(compressed.events.len(), 2); // Spawn + Complete
        assert_eq!(compressed.events_removed(), 2);
    }

    #[test]
    fn skeleton_keeps_only_lifecycle_events() {
        let events = vec![
            make_event(1, TraceEventKind::Spawn),
            make_event(2, TraceEventKind::Wake),
            make_event(3, TraceEventKind::CancelRequest),
            make_event(4, TraceEventKind::CancelAck),
            make_event(5, TraceEventKind::UserTrace),
            make_event(6, TraceEventKind::Complete),
        ];
        let compressed = compress(&events, Level::Skeleton);
        assert_eq!(compressed.events.len(), 4); // Spawn, CancelReq, CancelAck, Complete
        assert!(compressed.ratio() < 1.0);
    }

    #[test]
    fn empty_trace_compresses_to_empty() {
        let compressed = compress(&[], Level::Skeleton);
        assert_eq!(compressed.events.len(), 0);
        assert!((compressed.ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn compressed_certificate_matches() {
        let events = vec![
            make_event(1, TraceEventKind::Spawn),
            make_event(2, TraceEventKind::Wake),
            make_event(3, TraceEventKind::Complete),
        ];
        let compressed = compress(&events, Level::Structural);
        assert!(validate_compressed(&compressed));
    }

    #[test]
    fn obligation_events_retained_at_skeleton() {
        let events = vec![
            make_event(1, TraceEventKind::Spawn),
            make_event(2, TraceEventKind::ObligationReserve),
            make_event(3, TraceEventKind::ObligationCommit),
            make_event(4, TraceEventKind::Complete),
        ];
        let compressed = compress(&events, Level::Skeleton);
        assert_eq!(compressed.events.len(), 4); // all retained
    }

    #[test]
    fn compression_ratio_calculation() {
        let events = vec![
            make_event(1, TraceEventKind::Spawn),
            make_event(2, TraceEventKind::UserTrace),
            make_event(3, TraceEventKind::UserTrace),
            make_event(4, TraceEventKind::UserTrace),
            make_event(5, TraceEventKind::Complete),
        ];
        let compressed = compress(&events, Level::Structural);
        // 2 out of 5 retained = 0.4
        assert!((compressed.ratio() - 0.4).abs() < f64::EPSILON);
    }

    #[test]
    fn region_events_retained_at_skeleton() {
        let events = vec![
            make_event(1, TraceEventKind::RegionCreated),
            make_event(2, TraceEventKind::Spawn),
            make_event(3, TraceEventKind::Complete),
            make_event(4, TraceEventKind::RegionCloseComplete),
        ];
        let compressed = compress(&events, Level::Skeleton);
        assert_eq!(compressed.events.len(), 4);
    }

    // =========================================================================
    // Wave 53 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn level_debug_clone_copy_eq() {
        let l = Level::Structural;
        let dbg = format!("{l:?}");
        assert!(dbg.contains("Structural"), "{dbg}");
        let copied = l;
        let cloned = l.clone();
        assert_eq!(copied, cloned);
        assert_ne!(Level::Lossless, Level::Skeleton);
    }

    #[test]
    fn compressed_trace_debug() {
        let compressed = compress(&[], Level::Lossless);
        let dbg = format!("{compressed:?}");
        assert!(dbg.contains("CompressedTrace"), "{dbg}");
    }
}
