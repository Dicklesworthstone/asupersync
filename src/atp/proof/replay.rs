//! ATP replay pointers and deterministic reconstruction support.
//!
//! This module provides replay capabilities for ATP transfers, enabling
//! deterministic reconstruction of transfer operations for debugging,
//! compliance auditing, and incident analysis.

use crate::atp::proof::serde_types::SerializableContentId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Replay pointer for deterministic reconstruction of ATP operations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AtpReplayPointer {
    /// Replay format version.
    pub version: u32,
    /// Event stream identifier.
    pub stream_id: String,
    /// Starting position in the event stream.
    pub start_position: u64,
    /// Ending position in the event stream.
    pub end_position: u64,
    /// Stream checksum for integrity verification.
    pub stream_checksum: SerializableContentId,
    /// Event filter criteria (optional).
    pub event_filter: Option<ReplayEventFilter>,
    /// Replay context metadata.
    pub context: BTreeMap<String, String>,
}

/// Filter criteria for selective replay of events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayEventFilter {
    /// Event kinds to include (empty means include all).
    pub include_kinds: Vec<ReplayableEventKind>,
    /// Event kinds to exclude.
    pub exclude_kinds: Vec<ReplayableEventKind>,
    /// Minimum event timestamp (microseconds since UNIX epoch).
    pub min_timestamp_micros: Option<u64>,
    /// Maximum event timestamp (microseconds since UNIX epoch).
    pub max_timestamp_micros: Option<u64>,
    /// Additional filter predicates.
    pub predicates: BTreeMap<String, String>,
}

/// Types of replayable events in ATP transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReplayableEventKind {
    /// Transfer session initiation.
    SessionStart,
    /// Peer authentication and handshake.
    PeerAuth,
    /// Path establishment and routing.
    PathSetup,
    /// Chunk transmission and reception.
    ChunkTransfer,
    /// Repair symbol generation and transmission.
    RepairSymbol,
    /// RaptorQ decode operation.
    RaptorQDecode,
    /// Verification stage completion.
    VerificationStage,
    /// Journal write operation.
    JournalWrite,
    /// Transfer completion or cancellation.
    SessionEnd,
    /// Error or exception event.
    Error,
}

impl ReplayableEventKind {
    /// Get the string representation of the event kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionStart => "session_start",
            Self::PeerAuth => "peer_auth",
            Self::PathSetup => "path_setup",
            Self::ChunkTransfer => "chunk_transfer",
            Self::RepairSymbol => "repair_symbol",
            Self::RaptorQDecode => "raptorq_decode",
            Self::VerificationStage => "verification_stage",
            Self::JournalWrite => "journal_write",
            Self::SessionEnd => "session_end",
            Self::Error => "error",
        }
    }

    /// Whether this event kind is critical for transfer correctness.
    #[must_use]
    pub const fn is_critical(self) -> bool {
        matches!(
            self,
            Self::SessionStart
                | Self::ChunkTransfer
                | Self::VerificationStage
                | Self::SessionEnd
                | Self::Error
        )
    }
}

/// Individual replayable event with metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayableEvent {
    /// Event sequence number within the stream.
    pub sequence: u64,
    /// Event timestamp (microseconds since UNIX epoch).
    pub timestamp_micros: u64,
    /// Event kind/type.
    pub kind: ReplayableEventKind,
    /// Event payload data.
    pub payload: ReplayableEventPayload,
    /// Event metadata and context.
    pub metadata: BTreeMap<String, String>,
}

/// Payload data for different types of replayable events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ReplayableEventPayload {
    /// Session start event payload.
    SessionStart {
        /// Transfer session identifier.
        transfer_id: String,
        /// Source peer identifier.
        source_peer: String,
        /// Destination peer identifier.
        destination_peer: String,
        /// Transfer configuration.
        config: BTreeMap<String, String>,
    },
    /// Peer authentication event payload.
    PeerAuth {
        /// Authentication method used.
        auth_method: String,
        /// Key fingerprints exchanged.
        key_fingerprints: Vec<String>,
        /// Whether authentication succeeded.
        success: bool,
    },
    /// Path setup event payload.
    PathSetup {
        /// Primary protocol negotiated.
        primary_protocol: String,
        /// Fallback protocols available.
        fallback_protocols: Vec<String>,
        /// Round-trip time measured.
        rtt_millis: Option<f64>,
        /// Whether setup succeeded.
        success: bool,
    },
    /// Chunk transfer event payload.
    ChunkTransfer {
        /// Chunk index being transferred.
        chunk_index: u64,
        /// Chunk size in bytes.
        chunk_size: u32,
        /// Chunk content digest.
        chunk_digest: SerializableContentId,
        /// Whether transfer succeeded.
        success: bool,
    },
    /// Repair symbol event payload.
    RepairSymbol {
        /// Source block number.
        source_block: u32,
        /// Repair symbol index.
        repair_index: u32,
        /// Symbol size in bytes.
        symbol_size: u32,
        /// Whether generation/reception succeeded.
        success: bool,
    },
    /// RaptorQ decode event payload.
    RaptorQDecode {
        /// Source block being decoded.
        source_block: u32,
        /// Number of source symbols.
        source_symbols: u32,
        /// Number of repair symbols used.
        repair_symbols_used: u32,
        /// Whether decode succeeded.
        success: bool,
    },
    /// Verification stage event payload.
    VerificationStage {
        /// Verification stage name.
        stage: String,
        /// Content digest being verified.
        content_digest: Option<SerializableContentId>,
        /// Verification result.
        success: bool,
        /// Error message if verification failed.
        error_message: Option<String>,
    },
    /// Journal write event payload.
    JournalWrite {
        /// Journal entry sequence number.
        entry_sequence: u64,
        /// Entry size in bytes.
        entry_size: u32,
        /// Entry content digest.
        entry_digest: SerializableContentId,
        /// Whether write succeeded.
        success: bool,
    },
    /// Session end event payload.
    SessionEnd {
        /// Transfer completion status.
        completion_status: String,
        /// Total bytes transferred.
        bytes_transferred: u64,
        /// Total transfer duration (milliseconds).
        duration_millis: u64,
        /// Whether session ended successfully.
        success: bool,
    },
    /// Error event payload.
    Error {
        /// Error category.
        error_category: String,
        /// Error code.
        error_code: String,
        /// Error message.
        error_message: String,
        /// Whether error was recoverable.
        recoverable: bool,
    },
}

impl AtpReplayPointer {
    /// Create a new replay pointer.
    #[must_use]
    pub fn new(
        stream_id: impl Into<String>,
        start_position: u64,
        end_position: u64,
        stream_checksum: SerializableContentId,
    ) -> Self {
        Self {
            version: 1,
            stream_id: stream_id.into(),
            start_position,
            end_position,
            stream_checksum,
            event_filter: None,
            context: BTreeMap::new(),
        }
    }

    /// Set an event filter for selective replay.
    pub fn with_filter(mut self, filter: ReplayEventFilter) -> Self {
        self.event_filter = Some(filter);
        self
    }

    /// Add context metadata.
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    /// Check if this replay pointer covers the specified position.
    #[must_use]
    pub fn covers_position(&self, position: u64) -> bool {
        position >= self.start_position && position <= self.end_position
    }

    /// Calculate the number of events covered by this pointer.
    #[must_use]
    pub fn event_count(&self) -> u64 {
        if self.end_position >= self.start_position {
            self.end_position - self.start_position + 1
        } else {
            0
        }
    }

    /// Validate the replay pointer for consistency.
    pub fn validate(&self) -> Result<(), ReplayPointerError> {
        if self.start_position > self.end_position {
            return Err(ReplayPointerError::InvalidRange {
                start: self.start_position,
                end: self.end_position,
            });
        }

        if self.stream_id.is_empty() {
            return Err(ReplayPointerError::EmptyStreamId);
        }

        if let Some(ref filter) = self.event_filter {
            filter.validate()?;
        }

        Ok(())
    }
}

impl ReplayEventFilter {
    /// Create a new event filter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            include_kinds: Vec::new(),
            exclude_kinds: Vec::new(),
            min_timestamp_micros: None,
            max_timestamp_micros: None,
            predicates: BTreeMap::new(),
        }
    }

    /// Include only specific event kinds.
    pub fn include_kinds(mut self, kinds: Vec<ReplayableEventKind>) -> Self {
        self.include_kinds = kinds;
        self
    }

    /// Exclude specific event kinds.
    pub fn exclude_kinds(mut self, kinds: Vec<ReplayableEventKind>) -> Self {
        self.exclude_kinds = kinds;
        self
    }

    /// Set timestamp range filter.
    pub fn timestamp_range(mut self, min_micros: Option<u64>, max_micros: Option<u64>) -> Self {
        self.min_timestamp_micros = min_micros;
        self.max_timestamp_micros = max_micros;
        self
    }

    /// Add a custom filter predicate.
    pub fn with_predicate(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.predicates.insert(key.into(), value.into());
        self
    }

    /// Check if an event matches this filter.
    #[must_use]
    pub fn matches(&self, event: &ReplayableEvent) -> bool {
        // Check include/exclude kinds
        if !self.include_kinds.is_empty() && !self.include_kinds.contains(&event.kind) {
            return false;
        }

        if self.exclude_kinds.contains(&event.kind) {
            return false;
        }

        // Check timestamp range
        if let Some(min) = self.min_timestamp_micros {
            if event.timestamp_micros < min {
                return false;
            }
        }

        if let Some(max) = self.max_timestamp_micros {
            if event.timestamp_micros > max {
                return false;
            }
        }

        for (key, expected) in &self.predicates {
            let Some(actual) = event_predicate_value(event, key) else {
                return false;
            };
            if !predicate_value_matches(&actual, expected) {
                return false;
            }
        }

        true
    }

    /// Validate the filter for consistency.
    pub fn validate(&self) -> Result<(), ReplayPointerError> {
        if let (Some(min), Some(max)) = (self.min_timestamp_micros, self.max_timestamp_micros) {
            if min > max {
                return Err(ReplayPointerError::InvalidTimestampRange { min, max });
            }
        }

        Ok(())
    }
}

impl Default for ReplayEventFilter {
    fn default() -> Self {
        Self::new()
    }
}

fn event_predicate_value(event: &ReplayableEvent, key: &str) -> Option<String> {
    match key {
        "sequence" => Some(event.sequence.to_string()),
        "timestamp_micros" => Some(event.timestamp_micros.to_string()),
        "kind" => Some(event.kind.as_str().to_string()),
        "critical" | "is_critical" => Some(event.kind.is_critical().to_string()),
        _ => key
            .strip_prefix("metadata.")
            .and_then(|metadata_key| event.metadata.get(metadata_key))
            .or_else(|| event.metadata.get(key))
            .cloned()
            .or_else(|| payload_predicate_value(&event.payload, key.strip_prefix("payload.")?)),
    }
}

fn payload_predicate_value(payload: &ReplayableEventPayload, path: &str) -> Option<String> {
    let value = serde_json::to_value(payload).ok()?;
    let mut current = &value;
    for component in path.split('.') {
        current = current.get(component)?;
    }
    match current {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => Some(current.to_string()),
    }
}

fn predicate_value_matches(actual: &str, expected: &str) -> bool {
    if let Some(prefix) = expected.strip_prefix("prefix:") {
        actual.starts_with(prefix)
    } else if let Some(suffix) = expected.strip_prefix("suffix:") {
        actual.ends_with(suffix)
    } else if let Some(needle) = expected.strip_prefix("contains:") {
        actual.contains(needle)
    } else if let Some(pattern) = expected.strip_prefix("glob:") {
        replay_glob_match(pattern, actual)
    } else if let Some(not_expected) = expected.strip_prefix("!=") {
        actual != not_expected
    } else if let Some(min) = expected.strip_prefix(">=") {
        numeric_predicate(actual, min, |actual, expected| actual >= expected)
    } else if let Some(max) = expected.strip_prefix("<=") {
        numeric_predicate(actual, max, |actual, expected| actual <= expected)
    } else if let Some(min) = expected.strip_prefix('>') {
        numeric_predicate(actual, min, |actual, expected| actual > expected)
    } else if let Some(max) = expected.strip_prefix('<') {
        numeric_predicate(actual, max, |actual, expected| actual < expected)
    } else {
        actual == expected
    }
}

fn numeric_predicate(actual: &str, expected: &str, cmp: impl FnOnce(u64, u64) -> bool) -> bool {
    let Ok(actual) = actual.parse::<u64>() else {
        return false;
    };
    let Ok(expected) = expected.parse::<u64>() else {
        return false;
    };
    cmp(actual, expected)
}

fn replay_glob_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let (mut pattern_index, mut text_index) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_text_index = 0usize;

    while text_index < text.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == text[text_index])
        {
            pattern_index += 1;
            text_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            while pattern_index + 1 < pattern.len() && pattern[pattern_index + 1] == b'*' {
                pattern_index += 1;
            }
            star = Some(pattern_index);
            pattern_index += 1;
            star_text_index = text_index;
        } else if let Some(star_index) = star {
            pattern_index = star_index + 1;
            star_text_index += 1;
            text_index = star_text_index;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }

    pattern_index == pattern.len()
}

/// Errors in replay pointer construction or validation.
#[derive(Debug, Clone, PartialEq)]
pub enum ReplayPointerError {
    /// Invalid position range.
    InvalidRange {
        /// Start position.
        start: u64,
        /// End position.
        end: u64,
    },
    /// Empty stream identifier.
    EmptyStreamId,
    /// Invalid timestamp range in filter.
    InvalidTimestampRange {
        /// Minimum timestamp.
        min: u64,
        /// Maximum timestamp.
        max: u64,
    },
    /// Stream checksum verification failed.
    ChecksumMismatch {
        /// Expected checksum.
        expected: SerializableContentId,
        /// Computed checksum.
        computed: SerializableContentId,
    },
}

impl std::fmt::Display for ReplayPointerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRange { start, end } => {
                write!(f, "invalid range: start {start} > end {end}")
            }
            Self::EmptyStreamId => {
                write!(f, "stream ID cannot be empty")
            }
            Self::InvalidTimestampRange { min, max } => {
                write!(f, "invalid timestamp range: min {min} > max {max}")
            }
            Self::ChecksumMismatch { expected, computed } => {
                write!(
                    f,
                    "checksum mismatch: expected {expected}, computed {computed}"
                )
            }
        }
    }
}

impl std::error::Error for ReplayPointerError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::object::ContentId;

    #[test]
    fn replay_pointer_basic_operations() {
        let checksum = SerializableContentId::from(&ContentId::from_bytes(b"test-stream"));
        let pointer = AtpReplayPointer::new("stream-1", 100, 200, checksum.clone()); // ubs:ignore - test oracle clone

        assert_eq!(pointer.stream_id, "stream-1");
        assert_eq!(pointer.start_position, 100);
        assert_eq!(pointer.end_position, 200);
        assert_eq!(pointer.stream_checksum, checksum);
        assert_eq!(pointer.event_count(), 101);

        assert!(pointer.covers_position(150));
        assert!(!pointer.covers_position(50));
        assert!(!pointer.covers_position(250));

        pointer.validate().expect("basic pointer should be valid");
    }

    #[test]
    fn replay_pointer_validation() {
        let checksum = SerializableContentId::from(&ContentId::from_bytes(b"test"));

        // Invalid range
        let invalid_range = AtpReplayPointer::new("stream-1", 200, 100, checksum.clone());
        let err = invalid_range
            .validate()
            .expect_err("invalid range should fail");
        assert!(matches!(err, ReplayPointerError::InvalidRange { .. }));

        // Empty stream ID
        let mut empty_stream = AtpReplayPointer::new("stream-1", 100, 200, checksum);
        empty_stream.stream_id = String::new();
        let err = empty_stream
            .validate()
            .expect_err("empty stream ID should fail");
        assert!(matches!(err, ReplayPointerError::EmptyStreamId));
    }

    #[test]
    fn replay_event_filter_matching() {
        let filter = ReplayEventFilter::new()
            .include_kinds(vec![ReplayableEventKind::ChunkTransfer])
            .exclude_kinds(vec![ReplayableEventKind::Error])
            .timestamp_range(Some(1000), Some(2000));

        let chunk_event = ReplayableEvent {
            sequence: 1,
            timestamp_micros: 1500,
            kind: ReplayableEventKind::ChunkTransfer,
            payload: ReplayableEventPayload::ChunkTransfer {
                chunk_index: 0,
                chunk_size: 1024,
                chunk_digest: SerializableContentId::from(&ContentId::from_bytes(b"chunk")),
                success: true,
            },
            metadata: BTreeMap::new(),
        };

        let error_event = ReplayableEvent {
            sequence: 2,
            timestamp_micros: 1500,
            kind: ReplayableEventKind::Error,
            payload: ReplayableEventPayload::Error {
                error_category: "network".to_string(),
                error_code: "timeout".to_string(),
                error_message: "connection timeout".to_string(),
                recoverable: true,
            },
            metadata: BTreeMap::new(),
        };

        let old_event = ReplayableEvent {
            sequence: 3,
            timestamp_micros: 500, // Too old
            kind: ReplayableEventKind::ChunkTransfer,
            payload: ReplayableEventPayload::ChunkTransfer {
                chunk_index: 1,
                chunk_size: 1024,
                chunk_digest: SerializableContentId::from(&ContentId::from_bytes(b"chunk2")),
                success: true,
            },
            metadata: BTreeMap::new(),
        };

        assert!(filter.matches(&chunk_event));
        assert!(!filter.matches(&error_event)); // Excluded kind
        assert!(!filter.matches(&old_event)); // Outside timestamp range
    }

    #[test]
    fn replay_event_filter_validation() {
        // Invalid timestamp range
        let invalid_filter = ReplayEventFilter::new().timestamp_range(Some(2000), Some(1000));
        let err = invalid_filter
            .validate()
            .expect_err("invalid timestamp range should fail");
        assert!(matches!(
            err,
            ReplayPointerError::InvalidTimestampRange { .. }
        ));

        // Valid filter
        let valid_filter = ReplayEventFilter::new().timestamp_range(Some(1000), Some(2000));
        valid_filter.validate().expect("valid filter should pass");
    }

    #[test]
    fn replayable_event_kind_properties() {
        assert_eq!(
            ReplayableEventKind::ChunkTransfer.as_str(),
            "chunk_transfer"
        );
        assert!(ReplayableEventKind::SessionStart.is_critical());
        assert!(ReplayableEventKind::Error.is_critical());
        assert!(!ReplayableEventKind::PeerAuth.is_critical());
    }

    #[test]
    fn replay_pointer_with_context_and_filter() {
        let checksum = SerializableContentId::from(&ContentId::from_bytes(b"test-stream"));
        let filter =
            ReplayEventFilter::new().include_kinds(vec![ReplayableEventKind::ChunkTransfer]);

        let pointer = AtpReplayPointer::new("stream-1", 100, 200, checksum)
            .with_filter(filter)
            .with_context("session_id", "test-session")
            .with_context("peer_id", "peer-123");

        assert!(pointer.event_filter.is_some());
        assert_eq!(
            pointer.context.get("session_id"),
            Some(&"test-session".to_string())
        );
        assert_eq!(
            pointer.context.get("peer_id"),
            Some(&"peer-123".to_string())
        );

        pointer
            .validate()
            .expect("pointer with context and filter should be valid");
    }
}
