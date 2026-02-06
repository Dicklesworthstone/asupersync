//! Tracing infrastructure for deterministic replay.
//!
//! This module provides structured tracing for the runtime, enabling:
//!
//! - Deterministic replay of executions
//! - Debugging and analysis of concurrent behavior
//! - Mazurkiewicz trace semantics for DPOR
//! - Geodesic normalization for minimal-entropy canonical traces
//!
//! # Quick Start: Trace Normalization
//!
//! ```ignore
//! use asupersync::trace::{normalize_trace_default, trace_switch_cost};
//!
//! // Record a trace...
//! let events: Vec<TraceEvent> = /* captured trace */;
//!
//! // Normalize for canonical replay (minimizes context switches)
//! let (normalized, result) = normalize_trace_default(&events);
//! println!("Reduced switches from {} to {}",
//!     trace_switch_cost(&events), result.switch_count);
//! ```
//!
//! # Submodules
//!
//! - [`event`]: Observability trace events for debugging and analysis
//! - [`replay`]: Compact replay events for deterministic record/replay
//! - [`recorder`]: Trace recorder for Lab runtime instrumentation
//! - [`replayer`]: Trace replayer for deterministic replay with stepping support
//! - [`file`](mod@file): Binary file format for trace persistence
//! - [`buffer`]: Ring buffer for recent events
//! - [`format`](mod@format): Output formatting utilities
//! - [`streaming`]: Streaming replay for large traces with O(1) memory
//! - [`integrity`]: Trace file integrity verification
//! - [`filter`]: Trace event filtering during recording
//! - [`compat`]: Forward/backward compatibility and migration support
//! - [`independence`]: Independence relation over trace events for DPOR
//! - [`canonicalize`](mod@canonicalize): Foata normal form for trace equivalence classes
//! - [`geodesic`]: Low-switch-cost schedule normalization
//! - [`dpor`]: DPOR race detection and backtracking
//! - [`tla_export`]: TLA+ export for model checking

pub mod boundary;
pub mod buffer;
pub mod canonicalize;
pub mod causality;
pub mod certificate;
pub mod crashpack;
pub mod compat;
pub mod compression;
pub mod distributed;
pub mod divergence;
pub mod dpor;
pub mod event;
pub mod event_structure;
pub mod file;
pub mod filter;
pub mod format;
pub mod geodesic;
pub mod gf2;
pub mod independence;
pub mod integrity;
pub mod recorder;
pub mod replay;
pub mod replayer;
pub mod scoring;
pub mod streaming;
pub mod tla_export;

pub use boundary::{matmul_gf2, SquareComplex};
pub use buffer::{TraceBuffer, TraceBufferHandle};
pub use crashpack::{
    CrashPack, CrashPackBuilder, CrashPackConfig, CrashPackManifest, FailureInfo,
    SupervisionSnapshot, CRASHPACK_SCHEMA_VERSION,
};
pub use canonicalize::{
    canonicalize, trace_event_key, trace_fingerprint, FoataTrace, TraceEventKey, TraceMonoid,
};
pub use causality::{CausalOrderVerifier, CausalityViolation, CausalityViolationKind};
pub use certificate::{
    CertificateVerifier, TraceCertificate, VerificationResult as CertificateVerificationResult,
};
pub use compat::{
    check_schema_compatibility, CompatEvent, CompatEventIterator, CompatReader, CompatStats,
    CompatibilityResult, TraceMigration, TraceMigrator, MIN_SUPPORTED_SCHEMA_VERSION,
};
pub use compression::{compress as compress_trace, CompressedTrace, Level as CompressionLevel};
pub use divergence::{
    diagnose_divergence, minimal_divergent_prefix, AffectedEntities, DiagnosticConfig,
    DivergenceCategory, DivergenceReport, EventSummary,
};
pub use dpor::{
    detect_hb_races, detect_races, estimated_classes, racing_events, trace_coverage_analysis,
    BacktrackPoint, DetectedRace, HappensBeforeGraph, Race, RaceAnalysis, RaceDetector, RaceKind,
    RaceReport, ResourceRaceDistribution, SleepSet, TraceCoverageAnalysis,
};
pub use event::{TraceData, TraceEvent, TraceEventKind, TRACE_EVENT_SCHEMA_VERSION};
pub use event_structure::{
    Event, EventId, EventStructure, HdaCell, HdaComplex, OwnerKey, TracePoset,
};
pub use file::{
    read_trace, write_trace, CompressionMode, TraceEventIterator, TraceFileConfig, TraceFileError,
    TraceReader, TraceWriter, TRACE_FILE_VERSION, TRACE_MAGIC,
};
pub use filter::{EventCategory, FilterBuilder, FilterableEvent, TraceFilter};
pub use geodesic::{
    count_switches, is_valid_linear_extension, normalize as geodesic_normalize, GeodesicAlgorithm,
    GeodesicConfig, GeodesicResult,
};
#[cfg(feature = "test-internals")]
pub use geodesic::{normalize_with_ledger, DecisionEntry, DecisionLedger};
pub use gf2::{BitVec, BoundaryMatrix, PersistencePairs, ReducedMatrix};
pub use independence::{
    accesses_conflict, independent, resource_footprint, AccessMode, Resource, ResourceAccess,
};
pub use integrity::{
    find_first_corruption, is_trace_valid_quick, verify_trace, IntegrityIssue, IssueSeverity,
    VerificationOptions, VerificationResult,
};
pub use recorder::{
    LimitAction, LimitKind, LimitReached, RecorderConfig, TraceRecorder, DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_MEMORY,
};
pub use replay::{
    CompactRegionId, CompactTaskId, ReplayEvent, ReplayTrace, ReplayTraceError, TraceMetadata,
    REPLAY_SCHEMA_VERSION,
};
pub use replayer::{Breakpoint, DivergenceError, ReplayError, ReplayMode, TraceReplayer};
pub use scoring::{
    score_boundary_matrix, score_persistence, seed_fingerprint, ClassId, EvidenceEntry,
    EvidenceLedger, TopologicalScore,
};
pub use streaming::{
    ReplayCheckpoint, ReplayProgress, StreamingReplayError, StreamingReplayResult,
    StreamingReplayer,
};
pub use tla_export::{TlaExporter, TlaModule, TlaStateSnapshot};

// ============================================================================
// Convenience API for geodesic normalization
// ============================================================================

/// Normalize a trace for canonical, low-switch-cost replay.
///
/// This is a convenience wrapper that:
/// 1. Builds a [`TracePoset`] from the events
/// 2. Applies geodesic normalization to minimize owner switches
/// 3. Returns the reordered events in the normalized schedule
///
/// The normalized trace is a valid linear extension of the dependency DAG
/// (respects all happens-before relationships) while minimizing context switches.
///
/// # Arguments
///
/// * `events` - The trace events to normalize
/// * `config` - Configuration for the normalization algorithm
///
/// # Returns
///
/// A tuple of `(normalized_events, result)` where:
/// - `normalized_events` is the reordered trace
/// - `result` contains statistics about the normalization (switch count, algorithm used)
///
/// # Example
///
/// ```ignore
/// use asupersync::trace::{normalize_trace, GeodesicConfig};
///
/// let (normalized, result) = normalize_trace(&events, &GeodesicConfig::default());
/// println!("Switch count: {} (using {:?})", result.switch_count, result.algorithm);
/// ```
#[must_use]
pub fn normalize_trace(
    events: &[TraceEvent],
    config: &GeodesicConfig,
) -> (Vec<TraceEvent>, GeodesicResult) {
    let poset = TracePoset::from_trace(events);
    let result = geodesic_normalize(&poset, config);

    let normalized: Vec<TraceEvent> = result
        .schedule
        .iter()
        .map(|&idx| events[idx].clone())
        .collect();

    (normalized, result)
}

/// Normalize a trace using default configuration.
///
/// Convenience wrapper for [`normalize_trace`] with [`GeodesicConfig::default()`].
#[must_use]
pub fn normalize_trace_default(events: &[TraceEvent]) -> (Vec<TraceEvent>, GeodesicResult) {
    normalize_trace(events, &GeodesicConfig::default())
}

/// Compute the switch cost of a trace (number of owner changes between adjacent events).
///
/// This is useful for comparing traces before and after normalization.
#[must_use]
pub fn trace_switch_cost(events: &[TraceEvent]) -> usize {
    if events.len() < 2 {
        return 0;
    }

    events
        .windows(2)
        .filter(|w| OwnerKey::for_event(&w[0]) != OwnerKey::for_event(&w[1]))
        .count()
}

#[cfg(test)]
mod normalize_tests {
    use super::*;
    use crate::types::{RegionId, TaskId, Time};

    fn tid(n: u32) -> TaskId {
        TaskId::new_for_test(n, 0)
    }

    fn rid(n: u32) -> RegionId {
        RegionId::new_for_test(n, 0)
    }

    #[test]
    fn normalize_trace_reduces_switches() {
        // Events in "bad" order: A1, B1, A2, B2 (3 switches)
        // Optimal order: A1, A2, B1, B2 or B1, B2, A1, A2 (1 switch)
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)), // A1
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)), // B1
            TraceEvent::complete(3, Time::ZERO, tid(1), rid(1)), // A2
            TraceEvent::complete(4, Time::ZERO, tid(2), rid(2)), // B2
        ];

        let original_cost = trace_switch_cost(&events);
        let (normalized, result) = normalize_trace_default(&events);
        let normalized_cost = trace_switch_cost(&normalized);

        // Original order has more switches than normalized
        assert!(
            normalized_cost <= original_cost,
            "normalized ({normalized_cost}) should be <= original ({original_cost})"
        );
        assert_eq!(result.switch_count, normalized_cost);
    }

    #[test]
    fn normalize_preserves_events() {
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
        ];

        let (normalized, _) = normalize_trace_default(&events);
        assert_eq!(normalized.len(), events.len());
    }

    #[test]
    fn trace_switch_cost_empty() {
        assert_eq!(trace_switch_cost(&[]), 0);
    }

    #[test]
    fn trace_switch_cost_single() {
        let events = vec![TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1))];
        assert_eq!(trace_switch_cost(&events), 0);
    }

    #[test]
    fn trace_switch_cost_same_owner() {
        // Same task = same owner = no switches
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::poll(2, Time::ZERO, tid(1), rid(1)),
        ];
        assert_eq!(trace_switch_cost(&events), 0);
    }

    #[test]
    fn trace_switch_cost_different_owners() {
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
            TraceEvent::spawn(3, Time::ZERO, tid(1), rid(1)),
        ];
        assert_eq!(trace_switch_cost(&events), 2); // t1->t2->t1
    }
}
