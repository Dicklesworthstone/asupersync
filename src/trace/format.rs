//! Formatting utilities for trace output.
//!
//! Provides human-readable and machine-readable formatting for traces.

use super::buffer::TraceBuffer;
use super::canonicalize::{TraceEventKey, canonicalize, trace_event_key, trace_fingerprint};
use super::event::TraceEvent;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};

/// Schema version for golden trace fixtures.
pub const GOLDEN_TRACE_SCHEMA_VERSION: u32 = 1;

/// Minimal configuration snapshot for golden trace fixtures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenTraceConfig {
    /// Deterministic seed used to run the workload.
    pub seed: u64,
    /// Entropy seed used for capability randomness.
    pub entropy_seed: u64,
    /// Virtual worker count.
    pub worker_count: usize,
    /// Trace buffer capacity.
    pub trace_capacity: usize,
    /// Maximum steps before termination (if set).
    pub max_steps: Option<u64>,
    /// Maximum number of Foata layers to keep in the canonical prefix.
    pub canonical_prefix_layers: usize,
    /// Maximum number of events to keep in the canonical prefix.
    pub canonical_prefix_events: usize,
}

/// Summary of oracle results for a golden trace run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenTraceOracleSummary {
    /// Sorted list of oracle violation tags (empty if all invariants held).
    pub violations: Vec<String>,
}

/// Golden trace fixture for deterministic verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenTraceFixture {
    /// Fixture schema version.
    pub schema_version: u32,
    /// Configuration snapshot.
    pub config: GoldenTraceConfig,
    /// Canonical trace fingerprint.
    pub fingerprint: u64,
    /// Number of events in the trace.
    pub event_count: u64,
    /// Canonicalized prefix (Foata layers of stable event keys).
    pub canonical_prefix: Vec<Vec<TraceEventKey>>,
    /// Oracle summary captured at end of the run.
    pub oracle_summary: GoldenTraceOracleSummary,
}

impl GoldenTraceFixture {
    /// Build a golden trace fixture from a trace event slice.
    #[must_use]
    pub fn from_events(
        config: GoldenTraceConfig,
        events: &[TraceEvent],
        oracle_violations: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let canonical_prefix = canonical_prefix(
            events,
            config.canonical_prefix_layers,
            config.canonical_prefix_events,
        );
        let mut violations: Vec<String> = oracle_violations.into_iter().map(Into::into).collect();
        violations.sort();
        violations.dedup();

        Self {
            schema_version: GOLDEN_TRACE_SCHEMA_VERSION,
            fingerprint: trace_fingerprint(events),
            event_count: u64::try_from(events.len()).unwrap_or(u64::MAX),
            canonical_prefix,
            oracle_summary: GoldenTraceOracleSummary { violations },
            config,
        }
    }

    /// Compare two fixtures and return a diff if any field changed.
    pub fn verify(&self, actual: &Self) -> Result<(), GoldenTraceDiff> {
        GoldenTraceDiff::from_fixtures(self, actual).into_result()
    }
}

/// Diff between two golden trace fixtures.
#[derive(Debug, Default)]
pub struct GoldenTraceDiff {
    mismatches: Vec<GoldenTraceMismatch>,
}

impl GoldenTraceDiff {
    /// Returns true if no mismatches were recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mismatches.is_empty()
    }

    fn push(&mut self, mismatch: GoldenTraceMismatch) {
        self.mismatches.push(mismatch);
    }

    fn from_fixtures(expected: &GoldenTraceFixture, actual: &GoldenTraceFixture) -> Self {
        let mut diff = Self::default();
        if expected.schema_version != actual.schema_version {
            diff.push(GoldenTraceMismatch::SchemaVersion {
                expected: expected.schema_version,
                actual: actual.schema_version,
            });
        }
        if expected.config != actual.config {
            diff.push(GoldenTraceMismatch::Config {
                expected: expected.config.clone(),
                actual: actual.config.clone(),
            });
        }
        if expected.fingerprint != actual.fingerprint {
            diff.push(GoldenTraceMismatch::Fingerprint {
                expected: expected.fingerprint,
                actual: actual.fingerprint,
            });
        }
        if expected.event_count != actual.event_count {
            diff.push(GoldenTraceMismatch::EventCount {
                expected: expected.event_count,
                actual: actual.event_count,
            });
        }
        if expected.canonical_prefix != actual.canonical_prefix {
            diff.push(GoldenTraceMismatch::CanonicalPrefix {
                expected_layers: expected.canonical_prefix.len(),
                actual_layers: actual.canonical_prefix.len(),
                first_mismatch: first_prefix_mismatch(
                    &expected.canonical_prefix,
                    &actual.canonical_prefix,
                ),
            });
        }
        if expected.oracle_summary != actual.oracle_summary {
            diff.push(GoldenTraceMismatch::OracleViolations {
                expected: expected.oracle_summary.violations.clone(),
                actual: actual.oracle_summary.violations.clone(),
            });
        }
        diff
    }

    fn into_result(self) -> Result<(), Self> {
        if self.is_empty() { Ok(()) } else { Err(self) }
    }
}

impl std::fmt::Display for GoldenTraceDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for mismatch in &self.mismatches {
            writeln!(f, "{mismatch}")?;
        }
        Ok(())
    }
}

impl std::error::Error for GoldenTraceDiff {}

#[derive(Debug)]
enum GoldenTraceMismatch {
    SchemaVersion {
        expected: u32,
        actual: u32,
    },
    Config {
        expected: GoldenTraceConfig,
        actual: GoldenTraceConfig,
    },
    Fingerprint {
        expected: u64,
        actual: u64,
    },
    EventCount {
        expected: u64,
        actual: u64,
    },
    CanonicalPrefix {
        expected_layers: usize,
        actual_layers: usize,
        first_mismatch: Option<(usize, usize)>,
    },
    OracleViolations {
        expected: Vec<String>,
        actual: Vec<String>,
    },
}

impl std::fmt::Display for GoldenTraceMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SchemaVersion { expected, actual } => {
                write!(
                    f,
                    "schema_version changed (expected {expected}, actual {actual})"
                )
            }
            Self::Config { expected, actual } => {
                write!(
                    f,
                    "config changed (expected {expected:?}, actual {actual:?})"
                )
            }
            Self::Fingerprint { expected, actual } => {
                write!(
                    f,
                    "fingerprint changed (expected 0x{expected:016X}, actual 0x{actual:016X})"
                )
            }
            Self::EventCount { expected, actual } => write!(
                f,
                "event_count changed (expected {expected}, actual {actual})"
            ),
            Self::CanonicalPrefix {
                expected_layers,
                actual_layers,
                first_mismatch,
            } => {
                if let Some((layer, index)) = first_mismatch {
                    write!(
                        f,
                        "canonical_prefix mismatch (layer {layer}, index {index}; expected_layers={expected_layers}, actual_layers={actual_layers})"
                    )
                } else {
                    write!(
                        f,
                        "canonical_prefix mismatch (expected_layers={expected_layers}, actual_layers={actual_layers})"
                    )
                }
            }
            Self::OracleViolations { expected, actual } => {
                write!(
                    f,
                    "oracle violations changed (expected {expected:?}, actual {actual:?})"
                )
            }
        }
    }
}

fn canonical_prefix(
    events: &[TraceEvent],
    max_layers: usize,
    max_events: usize,
) -> Vec<Vec<TraceEventKey>> {
    let foata = canonicalize(events);
    let mut remaining = max_events;
    let mut prefix = Vec::new();

    for layer in foata.layers().iter().take(max_layers) {
        if remaining == 0 {
            break;
        }
        let mut keys = Vec::new();
        for event in layer {
            if remaining == 0 {
                break;
            }
            keys.push(trace_event_key(event));
            remaining = remaining.saturating_sub(1);
        }
        if !keys.is_empty() {
            prefix.push(keys);
        }
    }

    prefix
}

fn first_prefix_mismatch(
    expected: &[Vec<TraceEventKey>],
    actual: &[Vec<TraceEventKey>],
) -> Option<(usize, usize)> {
    let layers = expected.len().min(actual.len());
    for layer_idx in 0..layers {
        let expected_layer = &expected[layer_idx];
        let actual_layer = &actual[layer_idx];
        let events = expected_layer.len().min(actual_layer.len());
        for event_idx in 0..events {
            if expected_layer[event_idx] != actual_layer[event_idx] {
                return Some((layer_idx, event_idx));
            }
        }
        if expected_layer.len() != actual_layer.len() {
            return Some((layer_idx, events));
        }
    }
    if expected.len() != actual.len() {
        return Some((layers, 0));
    }
    None
}

/// Formats a trace buffer as human-readable text.
pub fn format_trace(buffer: &TraceBuffer, w: &mut impl Write) -> io::Result<()> {
    writeln!(w, "=== Trace ({} events) ===", buffer.len())?;
    for event in buffer.iter() {
        writeln!(w, "{event}")?;
    }
    writeln!(w, "=== End Trace ===")?;
    Ok(())
}

/// Formats a trace buffer as a string.
#[must_use]
pub fn trace_to_string(buffer: &TraceBuffer) -> String {
    let mut s = Vec::new();
    format_trace(buffer, &mut s).expect("writing to Vec should not fail");
    String::from_utf8(s).expect("trace should be valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::event::{TraceData, TraceEvent, TraceEventKind};
    use crate::types::Time;

    #[test]
    fn format_empty_trace() {
        let buffer = TraceBuffer::new(10);
        let output = trace_to_string(&buffer);
        assert!(output.contains("0 events"));
    }

    #[test]
    fn format_with_events() {
        let mut buffer = TraceBuffer::new(10);
        buffer.push(TraceEvent::new(
            1,
            Time::from_millis(100),
            TraceEventKind::UserTrace,
            TraceData::Message("test".to_string()),
        ));
        let output = trace_to_string(&buffer);
        assert!(output.contains("1 events"));
        assert!(output.contains("test"));
    }
}
