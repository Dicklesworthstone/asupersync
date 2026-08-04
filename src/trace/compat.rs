//! Trace format compatibility and migration support.
//!
//! This module provides forward and backward compatibility for the trace file
//! format, allowing:
//!
//! - **Forward compatibility**: Newer runtimes can read older trace files
//! - **Strict compatibility**: Unknown records are rejected without silently skipping
//!   or weakening deterministic replay
//! - **Explicit inspection**: `read_event_compat` can return one rejected
//!   record and its raw bytes for diagnostics
//! - **Migration**: Transform traces only when every event has a lossless mapping
//!
//! # Version Policy
//!
//! - Schema version increments on breaking changes to event format
//! - File format version increments on changes to the binary container
//! - Supported older containers can be read when their replay schema is known
//! - Unknown records fail closed in `read_event`, `events`, and `load_all`
//! - Migration rejects a trace if any event has no lossless mapping
//!
//! # Example
//!
//! ```ignore
//! use asupersync::trace::compat::{TraceMigrator, CompatReader};
//!
//! // Ordinary iteration is strict: an unknown event is an error.
//! let mut reader = CompatReader::open("old_trace.bin")?;
//! for event in reader.events() {
//!     process(event?);
//! }
//!
//! // Diagnostic tooling can explicitly inspect one rejected raw record.
//! let mut reader = CompatReader::open("old_trace.bin")?;
//! if let Some(CompatEvent::Skipped { reason, raw_bytes }) =
//!     reader.read_event_compat()?
//! {
//!     inspect_rejected_record(&reason, &raw_bytes);
//! }
//! ```

use super::file::{
    FLAG_CHECKSUMMED, FLAG_COMPRESSED, MAX_EVENT_LEN, MAX_EVENT_PREALLOC, MAX_META_LEN,
    TRACE_CHECKSUM_LEN, TRACE_FILE_VERSION, TRACE_MAGIC, TraceFileError, TraceFileResult,
};
use super::replay::{REPLAY_SCHEMA_VERSION, ReplayEvent, TraceMetadata};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

type SkipHandler = dyn Fn(&str, &[u8]) + Send + Sync;
// =============================================================================
// Version Compatibility
// =============================================================================

/// Minimum schema version we can read (migrations available from this version).
pub const MIN_SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// Result of a compatibility check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompatibilityResult {
    /// Fully compatible, no migration needed.
    Compatible,
    /// Compatible with migration from older version.
    NeedsMigration {
        /// Source version.
        from: u32,
        /// Target version.
        to: u32,
    },
    /// Incompatible: version too old.
    TooOld {
        /// Found version.
        found: u32,
        /// Minimum supported version.
        min_supported: u32,
    },
    /// Incompatible: version too new.
    TooNew {
        /// Found version.
        found: u32,
        /// Maximum supported version (current).
        max_supported: u32,
    },
}

/// Checks schema version compatibility.
#[must_use]
pub fn check_schema_compatibility(version: u32) -> CompatibilityResult {
    if version == REPLAY_SCHEMA_VERSION {
        CompatibilityResult::Compatible
    } else if version < MIN_SUPPORTED_SCHEMA_VERSION {
        CompatibilityResult::TooOld {
            found: version,
            min_supported: MIN_SUPPORTED_SCHEMA_VERSION,
        }
    } else if version > REPLAY_SCHEMA_VERSION {
        CompatibilityResult::TooNew {
            found: version,
            max_supported: REPLAY_SCHEMA_VERSION,
        }
    } else {
        CompatibilityResult::NeedsMigration {
            from: version,
            to: REPLAY_SCHEMA_VERSION,
        }
    }
}

// =============================================================================
// Event Compatibility
// =============================================================================

/// Result of attempting to read an event with compatibility handling.
#[derive(Debug)]
pub enum CompatEvent {
    /// Successfully read a known event.
    Event(ReplayEvent),
    /// Skipped an unknown or incompatible event.
    Skipped {
        /// Reason the event was skipped.
        reason: String,
        /// Raw bytes of the skipped event (for debugging).
        raw_bytes: Vec<u8>,
    },
}

/// Statistics about compatibility issues encountered during reading.
#[derive(Debug, Default, Clone)]
pub struct CompatStats {
    /// Number of events successfully read.
    pub events_read: u64,
    /// Number of unknown events skipped.
    pub events_skipped: u64,
    /// Number of events that required migration.
    pub events_migrated: u64,
    /// Distinct unknown event types encountered.
    pub unknown_event_types: Vec<String>,
}

impl CompatStats {
    /// Returns true if any compatibility issues were encountered.
    #[must_use]
    pub fn has_issues(&self) -> bool {
        self.events_skipped > 0 || !self.unknown_event_types.is_empty()
    }

    /// Records a skipped event.
    pub fn record_skipped(&mut self, event_type: Option<&str>) {
        self.events_skipped += 1;
        if let Some(ty) = event_type {
            if !self.unknown_event_types.contains(&ty.to_string()) {
                self.unknown_event_types.push(ty.to_string());
            }
        }
    }

    /// Records a successfully read event.
    pub fn record_read(&mut self) {
        self.events_read += 1;
    }

    /// Records a migrated event.
    pub fn record_migrated(&mut self) {
        self.events_migrated += 1;
        self.events_read += 1;
    }
}

// =============================================================================
// Compatibility Reader
// =============================================================================

/// A trace reader with forward and backward compatibility support.
///
/// Unlike `TraceReader`, this reader can expose an undecodable event and its
/// raw bytes through [`CompatEvent`]. Ordinary reads remain fail-closed.
pub struct CompatReader {
    reader: BufReader<File>,
    metadata: TraceMetadata,
    event_count: u64,
    events_read: u64,
    events_start_pos: u64,
    schema_version: u32,
    expected_event_digest: Option<[u8; TRACE_CHECKSUM_LEN]>,
    event_hasher: Sha256,
    stats: CompatStats,
    on_skip: Option<Box<SkipHandler>>,
}

impl CompatReader {
    /// Opens a trace file with compatibility handling.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be opened
    /// - The file has invalid magic bytes
    /// - The schema version is too old or too new
    pub fn open(path: impl AsRef<Path>) -> TraceFileResult<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);

        // Read and validate magic
        let mut magic = [0u8; 11];
        reader.read_exact(&mut magic)?;
        if &magic != TRACE_MAGIC {
            return Err(TraceFileError::InvalidMagic);
        }

        // Read file version
        let mut version_bytes = [0u8; 2];
        reader.read_exact(&mut version_bytes)?;
        let file_version = u16::from_le_bytes(version_bytes);
        if !(1..=TRACE_FILE_VERSION).contains(&file_version) {
            return Err(TraceFileError::UnsupportedVersion {
                expected: TRACE_FILE_VERSION,
                found: file_version,
            });
        }

        // Read flags
        let mut flags_bytes = [0u8; 2];
        reader.read_exact(&mut flags_bytes)?;
        let flags = u16::from_le_bytes(flags_bytes);
        let supported_flags = if file_version >= 3 {
            FLAG_COMPRESSED | FLAG_CHECKSUMMED
        } else {
            FLAG_COMPRESSED
        };
        if flags & !supported_flags != 0
            || flags & FLAG_COMPRESSED != 0
            || (file_version >= 3 && flags & FLAG_CHECKSUMMED == 0)
        {
            return Err(TraceFileError::UnsupportedFlags(flags));
        }

        // Read compression byte (only in version 2+)
        if file_version >= 2 {
            let mut compression_byte = [0u8; 1];
            reader.read_exact(&mut compression_byte)?;
            if compression_byte[0] != 0 {
                return Err(TraceFileError::UnsupportedCompression(compression_byte[0]));
            }
        }

        // Read metadata length
        let mut meta_len_bytes = [0u8; 4];
        reader.read_exact(&mut meta_len_bytes)?;
        let meta_len = u32::from_le_bytes(meta_len_bytes) as usize;

        if meta_len > MAX_META_LEN {
            return Err(TraceFileError::OversizedField {
                field: "metadata",
                actual: meta_len as u64,
                max: MAX_META_LEN as u64,
            });
        }

        let expected_metadata_digest = if file_version >= 3 {
            let mut digest = [0u8; TRACE_CHECKSUM_LEN];
            reader.read_exact(&mut digest)?;
            Some(digest)
        } else {
            None
        };

        // Read metadata with lenient deserialization
        let mut meta_bytes = vec![0u8; meta_len];
        reader.read_exact(&mut meta_bytes)?;
        if let Some(expected) = expected_metadata_digest {
            let actual: [u8; TRACE_CHECKSUM_LEN] = Sha256::digest(&meta_bytes).into();
            if expected != actual {
                return Err(TraceFileError::ChecksumMismatch {
                    section: "metadata",
                });
            }
        }
        let metadata: TraceMetadata = rmp_serde::from_slice(&meta_bytes)?;

        // Check schema version compatibility
        let schema_version = metadata.version;
        match check_schema_compatibility(schema_version) {
            CompatibilityResult::Compatible | CompatibilityResult::NeedsMigration { .. } => {
                // OK to proceed
            }
            CompatibilityResult::TooOld {
                found,
                min_supported,
            } => {
                return Err(TraceFileError::SchemaMismatch {
                    expected: min_supported,
                    found,
                });
            }
            CompatibilityResult::TooNew {
                found,
                max_supported,
            } => {
                return Err(TraceFileError::SchemaMismatch {
                    expected: max_supported,
                    found,
                });
            }
        }

        // Read event count
        let mut event_count_bytes = [0u8; 8];
        reader.read_exact(&mut event_count_bytes)?;
        let event_count = u64::from_le_bytes(event_count_bytes);

        let expected_event_digest = if file_version >= 3 {
            let mut digest = [0u8; TRACE_CHECKSUM_LEN];
            reader.read_exact(&mut digest)?;
            Some(digest)
        } else {
            None
        };
        let events_start_pos = reader.stream_position()?;
        if event_count == 0 {
            if let Some(expected) = expected_event_digest {
                let actual: [u8; TRACE_CHECKSUM_LEN] = Sha256::digest([]).into();
                if expected != actual {
                    return Err(TraceFileError::ChecksumMismatch {
                        section: "event stream",
                    });
                }
            }
        }

        Ok(Self {
            reader,
            metadata,
            event_count,
            events_read: 0,
            events_start_pos,
            schema_version,
            expected_event_digest,
            event_hasher: Sha256::new(),
            stats: CompatStats::default(),
            on_skip: None,
        })
    }

    /// Sets a callback for when events are skipped.
    ///
    /// The callback receives the skip reason and raw bytes.
    #[must_use]
    pub fn on_skip<F>(mut self, f: F) -> Self
    where
        F: Fn(&str, &[u8]) + Send + Sync + 'static,
    {
        self.on_skip = Some(Box::new(f));
        self
    }

    /// Returns the trace metadata.
    #[must_use]
    pub fn metadata(&self) -> &TraceMetadata {
        &self.metadata
    }

    /// Returns the original schema version of the trace.
    #[must_use]
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns the total number of events in the trace.
    #[must_use]
    pub fn event_count(&self) -> u64 {
        self.event_count
    }

    /// Returns compatibility statistics collected during reading.
    #[must_use]
    pub fn stats(&self) -> &CompatStats {
        &self.stats
    }

    /// Reads the next event without fallback.
    ///
    /// Returns `Ok(None)` when all events have been read.
    /// Unknown events are an explicit deserialization error. Use
    /// [`read_event_compat`](Self::read_event_compat) to inspect one rejected
    /// raw record at a time.
    pub fn read_event(&mut self) -> TraceFileResult<Option<ReplayEvent>> {
        if self.events_read >= self.event_count {
            return Ok(None);
        }

        let (len_bytes, event_bytes) = self.read_event_frame()?;
        let event = rmp_serde::from_slice::<ReplayEvent>(&event_bytes)?;
        self.record_frame(&len_bytes, &event_bytes)?;
        self.events_read += 1;
        self.stats.record_read();
        Ok(Some(event))
    }

    /// Reads the next event, returning detailed compatibility info.
    ///
    /// Unlike `read_event`, this returns `CompatEvent::Skipped` for unknown
    /// events instead of silently skipping them.
    pub fn read_event_compat(&mut self) -> TraceFileResult<Option<CompatEvent>> {
        if self.events_read >= self.event_count {
            return Ok(None);
        }

        let (len_bytes, event_bytes) = self.read_event_frame()?;
        self.record_frame(&len_bytes, &event_bytes)?;
        self.events_read += 1;

        // Try to deserialize
        match rmp_serde::from_slice::<ReplayEvent>(&event_bytes) {
            Ok(event) => {
                self.stats.record_read();
                Ok(Some(CompatEvent::Event(event)))
            }
            Err(e) => {
                let event_type = extract_event_type(&event_bytes);
                let reason = format!(
                    "{}{}",
                    event_type
                        .as_ref()
                        .map(|t| format!("event type '{t}': "))
                        .unwrap_or_default(),
                    e
                );

                self.stats.record_skipped(event_type.as_deref());

                Ok(Some(CompatEvent::Skipped {
                    reason,
                    raw_bytes: event_bytes,
                }))
            }
        }
    }

    /// Returns a fail-closed iterator over events.
    #[must_use]
    pub fn events(self) -> CompatEventIterator {
        CompatEventIterator {
            reader: self.reader,
            remaining: self.event_count,
            on_skip: self.on_skip,
            expected_event_digest: self.expected_event_digest,
            event_hasher: self.event_hasher,
        }
    }

    /// Resets to the beginning of the events section.
    pub fn rewind(&mut self) -> TraceFileResult<()> {
        self.reader.seek(SeekFrom::Start(self.events_start_pos))?;
        self.events_read = 0;
        self.event_hasher = Sha256::new();
        Ok(())
    }

    /// Loads all known events into memory without skipping unknown records.
    pub fn load_all(mut self) -> TraceFileResult<(Vec<ReplayEvent>, CompatStats)> {
        let mut events = Vec::with_capacity(
            usize::try_from(self.event_count)
                .unwrap_or(usize::MAX)
                .min(MAX_EVENT_PREALLOC),
        );
        while let Some(event) = self.read_event()? {
            events.push(event);
        }
        Ok((events, self.stats))
    }

    fn read_event_frame(&mut self) -> TraceFileResult<([u8; 4], Vec<u8>)> {
        let mut len_bytes = [0u8; 4];
        self.reader
            .read_exact(&mut len_bytes)
            .map_err(TraceFileError::Io)?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > MAX_EVENT_LEN {
            return Err(TraceFileError::OversizedField {
                field: "event",
                actual: len as u64,
                max: MAX_EVENT_LEN as u64,
            });
        }

        let mut event_bytes = vec![0u8; len];
        self.reader.read_exact(&mut event_bytes)?;
        Ok((len_bytes, event_bytes))
    }

    fn record_frame(&mut self, len_bytes: &[u8; 4], event_bytes: &[u8]) -> TraceFileResult<()> {
        self.event_hasher.update(len_bytes);
        self.event_hasher.update(event_bytes);
        if self.events_read.saturating_add(1) == self.event_count {
            if let Some(expected) = self.expected_event_digest {
                let actual: [u8; TRACE_CHECKSUM_LEN] = self.event_hasher.clone().finalize().into();
                if expected != actual {
                    return Err(TraceFileError::ChecksumMismatch {
                        section: "event stream",
                    });
                }
            }
        }
        Ok(())
    }
}

/// Iterator over events with compatibility handling.
pub struct CompatEventIterator {
    reader: BufReader<File>,
    remaining: u64,
    on_skip: Option<Box<SkipHandler>>,
    expected_event_digest: Option<[u8; TRACE_CHECKSUM_LEN]>,
    event_hasher: Sha256,
}

impl Iterator for CompatEventIterator {
    type Item = TraceFileResult<ReplayEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        let mut len_bytes = [0u8; 4];
        if let Err(error) = self.reader.read_exact(&mut len_bytes) {
            return Some(Err(TraceFileError::Io(error)));
        }
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > MAX_EVENT_LEN {
            return Some(Err(TraceFileError::OversizedField {
                field: "event",
                actual: len as u64,
                max: MAX_EVENT_LEN as u64,
            }));
        }

        let mut event_bytes = vec![0u8; len];
        if let Err(error) = self.reader.read_exact(&mut event_bytes) {
            return Some(Err(TraceFileError::Io(error)));
        }

        self.event_hasher.update(len_bytes);
        self.event_hasher.update(&event_bytes);
        if self.remaining == 1 {
            if let Some(expected) = self.expected_event_digest {
                let actual: [u8; TRACE_CHECKSUM_LEN] = self.event_hasher.clone().finalize().into();
                if expected != actual {
                    return Some(Err(TraceFileError::ChecksumMismatch {
                        section: "event stream",
                    }));
                }
            }
        }
        self.remaining -= 1;

        match rmp_serde::from_slice::<ReplayEvent>(&event_bytes) {
            Ok(event) => Some(Ok(event)),
            Err(error) => {
                if let Some(ref callback) = self.on_skip {
                    let event_type = extract_event_type(&event_bytes);
                    let reason = format!(
                        "rejected unknown event: {}{}",
                        event_type
                            .map(|event_type| format!("type '{event_type}', "))
                            .unwrap_or_default(),
                        error
                    );
                    callback(&reason, &event_bytes);
                }
                Some(Err(TraceFileError::from(error)))
            }
        }
    }
}

// =============================================================================
// Migration
// =============================================================================

/// Trait for migrating trace events between schema versions.
///
/// Implement this trait to define how events from one version transform
/// to the next version.
pub trait TraceMigration: Send + Sync {
    /// Source schema version this migration applies to.
    #[allow(clippy::wrong_self_convention)]
    fn from_version(&self) -> u32;

    /// Target schema version after migration.
    fn to_version(&self) -> u32;

    /// Migrates a single event.
    ///
    /// Returning `None` rejects the entire migration. Successful migration is
    /// therefore lossless with respect to event count.
    fn migrate_event(&self, event: ReplayEvent) -> Option<ReplayEvent>;

    /// Migrates metadata.
    ///
    /// Default implementation just updates the version number.
    fn migrate_metadata(&self, mut metadata: TraceMetadata) -> TraceMetadata {
        metadata.version = self.to_version();
        metadata
    }
}

/// Chains multiple migrations to transform traces across version gaps.
#[derive(Default)]
pub struct TraceMigrator {
    migrations: Vec<Box<dyn TraceMigration>>,
}

impl TraceMigrator {
    /// Creates a new migrator with no registered migrations.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a migration.
    ///
    /// Migrations should be registered in order (v1→v2, v2→v3, etc.).
    pub fn register<M: TraceMigration + 'static>(&mut self, migration: M) {
        self.migrations.push(Box::new(migration));
    }

    /// Registers a migration (builder pattern).
    #[must_use]
    pub fn with_migration<M: TraceMigration + 'static>(mut self, migration: M) -> Self {
        self.register(migration);
        self
    }

    /// Returns migrations needed to go from one version to another.
    fn find_migration_path(&self, from: u32, to: u32) -> Option<Vec<&dyn TraceMigration>> {
        if from == to {
            return Some(Vec::new());
        }
        if from > to {
            return None;
        }

        let mut path = Vec::new();
        let mut current = from;

        while current < to {
            // Find migration from current version
            let migration = self
                .migrations
                .iter()
                .find(|m| m.from_version() == current)?;

            let next = migration.to_version();
            if next <= current || next > to {
                return None;
            }
            path.push(migration.as_ref());
            current = next;
        }

        Some(path)
    }

    /// Migrates a trace from its current version to the target version.
    #[must_use]
    pub fn migrate(
        &self,
        metadata: TraceMetadata,
        events: Vec<ReplayEvent>,
        target_version: u32,
    ) -> Option<(TraceMetadata, Vec<ReplayEvent>)> {
        let path = self.find_migration_path(metadata.version, target_version)?;

        if path.is_empty() {
            return Some((metadata, events));
        }

        let mut current_metadata = metadata;
        let mut current_events = events;

        for migration in path {
            current_metadata = migration.migrate_metadata(current_metadata);
            let mut migrated_events = Vec::with_capacity(current_events.len());
            for event in current_events {
                migrated_events.push(migration.migrate_event(event)?);
            }
            current_events = migrated_events;
        }

        Some((current_metadata, current_events))
    }

    /// Checks if migration is possible between versions.
    #[must_use]
    pub fn can_migrate(&self, from: u32, to: u32) -> bool {
        self.find_migration_path(from, to).is_some()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Attempts to extract the event type from raw MessagePack bytes.
///
/// This is a best-effort function for logging purposes.
fn extract_event_type(bytes: &[u8]) -> Option<String> {
    // MessagePack maps start with type indicator
    // For tagged enums with #[serde(tag = "type")], the type field is usually first
    // Try to find a "type" key and its value

    // Simple heuristic: look for "type" string in the bytes
    let type_marker = b"type";
    if let Some(pos) = bytes
        .windows(type_marker.len())
        .position(|w| w == type_marker)
    {
        // Look for string value after "type" key
        let after = &bytes[pos + type_marker.len()..];
        // Skip the msgpack string header for value
        if after.len() > 2 {
            // fixstr (0xa0-0xbf) or str8/str16/str32
            let (str_len, str_start) = if after[0] >= 0xa0 && after[0] <= 0xbf {
                ((after[0] - 0xa0) as usize, 1)
            } else if after[0] == 0xd9 && after.len() > 2 {
                (after[1] as usize, 2)
            } else {
                return None;
            };

            if after.len() >= str_start + str_len {
                return String::from_utf8(after[str_start..str_start + str_len].to_vec()).ok();
            }
        }
    }
    None
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::trace::file::{TraceWriter, write_trace};
    use crate::trace::replay::CompactTaskId;
    use tempfile::NamedTempFile;

    #[test]
    fn compatibility_check_current_version() {
        assert_eq!(
            check_schema_compatibility(REPLAY_SCHEMA_VERSION),
            CompatibilityResult::Compatible
        );
    }

    #[test]
    fn compatibility_check_older_version() {
        // When we add version 2, version 1 should need migration
        // For now with only version 1, this tests the boundary
        if REPLAY_SCHEMA_VERSION > 1 {
            assert!(matches!(
                check_schema_compatibility(1),
                CompatibilityResult::NeedsMigration { .. }
            ));
        }
    }

    #[test]
    fn compatibility_check_newer_version() {
        let result = check_schema_compatibility(REPLAY_SCHEMA_VERSION + 1);
        assert!(matches!(result, CompatibilityResult::TooNew { .. }));
    }

    #[test]
    fn compat_reader_reads_valid_trace() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
        ];

        write_trace(path, &metadata, &events).expect("write trace");

        let mut reader = CompatReader::open(path).expect("open reader");
        assert_eq!(reader.metadata().seed, 42);
        assert_eq!(reader.event_count(), 2);

        let e1 = reader.read_event().expect("read").expect("event");
        assert!(matches!(e1, ReplayEvent::RngSeed { seed: 42 }));

        let e2 = reader.read_event().expect("read").expect("event");
        assert!(matches!(e2, ReplayEvent::TaskScheduled { .. }));

        assert_eq!(reader.read_event().expect("read"), None);
        assert!(!reader.stats().has_issues());
    }

    #[test]
    fn compat_reader_rejects_zero_version_and_compression_mismatch() {
        let temp = NamedTempFile::new().expect("create temp file");
        write_trace(temp.path(), &TraceMetadata::new(42), &[]).expect("write trace");
        let baseline = std::fs::read(temp.path()).expect("read trace");

        let mut zero_version = baseline.clone();
        zero_version[TRACE_MAGIC.len()..TRACE_MAGIC.len() + 2].copy_from_slice(&0u16.to_le_bytes());
        std::fs::write(temp.path(), zero_version).expect("write zero-version trace");
        assert!(matches!(
            CompatReader::open(temp.path()),
            Err(TraceFileError::UnsupportedVersion { found: 0, .. })
        ));

        let mut mismatched_compression = baseline;
        mismatched_compression[TRACE_MAGIC.len() + 4] = 1;
        std::fs::write(temp.path(), mismatched_compression)
            .expect("write mismatched compression byte");
        assert!(matches!(
            CompatReader::open(temp.path()),
            Err(TraceFileError::UnsupportedCompression(1))
        ));
    }

    #[test]
    fn compat_reader_loads_known_events_without_issues() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        // Write a trace with known events
        let mut writer = TraceWriter::create(path).expect("create writer");
        writer
            .write_metadata(&TraceMetadata::new(42))
            .expect("write metadata");
        writer
            .write_event(&ReplayEvent::RngSeed { seed: 42 })
            .expect("write event");
        // Note: we can't easily inject an unknown event type in this test
        // because we'd need to write raw bytes. The compat reader will be
        // tested more thoroughly when we actually have version migrations.
        writer.finish().expect("finish");

        let (events, stats) = CompatReader::open(path)
            .expect("open reader")
            .load_all()
            .expect("load all");

        assert_eq!(events.len(), 1);
        assert!(!stats.has_issues());
    }

    #[test]
    fn compat_reader_rejects_unknown_event_types_without_skipping() {
        use std::io::Write;
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        // Manually construct a trace file with an unknown event type
        let mut file = std::fs::File::create(path).expect("create file");

        // Write header
        file.write_all(super::TRACE_MAGIC).expect("write magic");
        file.write_all(&2u16.to_le_bytes()).expect("write version");
        file.write_all(&0u16.to_le_bytes()).expect("write flags");
        file.write_all(&[0u8]).expect("write compression byte");

        // Write metadata
        let metadata = TraceMetadata::new(42);
        let meta_bytes = rmp_serde::to_vec(&metadata).expect("serialize metadata");
        file.write_all(&(meta_bytes.len() as u32).to_le_bytes())
            .expect("write meta len");
        file.write_all(&meta_bytes).expect("write metadata");

        // Write event count (3 events: known, unknown, known)
        file.write_all(&3u64.to_le_bytes())
            .expect("write event count");

        // Event 1: Known event (RngSeed)
        let event1 = ReplayEvent::RngSeed { seed: 100 };
        let event1_bytes = rmp_serde::to_vec(&event1).expect("serialize event1");
        file.write_all(&(event1_bytes.len() as u32).to_le_bytes())
            .expect("write event1 len");
        file.write_all(&event1_bytes).expect("write event1");

        // Event 2: Unknown event type (manually crafted msgpack)
        // This is a map with {"type": "FutureEventType", "data": 123}
        let unknown_event = rmp_serde::to_vec(&serde_json::json!({
            "type": "FutureEventType",
            "some_field": 12345
        }))
        .expect("serialize unknown event");
        file.write_all(&(unknown_event.len() as u32).to_le_bytes())
            .expect("write unknown event len");
        file.write_all(&unknown_event).expect("write unknown event");

        // Event 3: Known event (TaskYielded)
        let event3 = ReplayEvent::TaskYielded {
            task: CompactTaskId(42),
        };
        let event3_bytes = rmp_serde::to_vec(&event3).expect("serialize event3");
        file.write_all(&(event3_bytes.len() as u32).to_le_bytes())
            .expect("write event3 len");
        file.write_all(&event3_bytes).expect("write event3");

        file.flush().expect("flush");
        drop(file);

        let mut reader = CompatReader::open(path).expect("open reader");
        let first = reader.read_event().expect("read").expect("known event");
        assert!(matches!(first, ReplayEvent::RngSeed { seed: 100 }));
        let error = reader
            .read_event()
            .expect_err("unknown event must fail closed");
        assert!(matches!(error, TraceFileError::Deserialize(_)));
        assert_eq!(reader.stats().events_read, 1);
        assert_eq!(reader.stats().events_skipped, 0);
    }

    #[test]
    fn compat_reader_read_event_compat_returns_skipped_info() {
        use std::io::Write;
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        // Manually construct a trace with an unknown event
        let mut file = std::fs::File::create(path).expect("create file");
        file.write_all(super::TRACE_MAGIC).expect("write magic");
        file.write_all(&2u16.to_le_bytes()).expect("write version");
        file.write_all(&0u16.to_le_bytes()).expect("write flags");
        file.write_all(&[0u8]).expect("write compression byte");

        let metadata = TraceMetadata::new(42);
        let meta_bytes = rmp_serde::to_vec(&metadata).expect("serialize metadata");
        file.write_all(&(meta_bytes.len() as u32).to_le_bytes())
            .expect("write meta len");
        file.write_all(&meta_bytes).expect("write metadata");
        file.write_all(&1u64.to_le_bytes())
            .expect("write event count");

        // Write unknown event
        let unknown = rmp_serde::to_vec(&serde_json::json!({
            "type": "NewEventInV99",
            "new_field": "value"
        }))
        .expect("serialize");
        file.write_all(&(unknown.len() as u32).to_le_bytes())
            .expect("write len");
        file.write_all(&unknown).expect("write event");
        file.flush().expect("flush");
        drop(file);

        // Read with detailed compat info
        let mut reader = CompatReader::open(path).expect("open reader");

        let event = reader
            .read_event_compat()
            .expect("read")
            .expect("should have event");

        match event {
            CompatEvent::Skipped { reason, raw_bytes } => {
                assert!(reason.contains("NewEventInV99") || !reason.is_empty());
                assert!(!raw_bytes.is_empty());
            }
            CompatEvent::Event(_) => panic!("expected skipped event"),
        }
    }

    fn write_header_with_metadata(file: &mut std::fs::File) {
        use std::io::Write;
        file.write_all(super::TRACE_MAGIC).expect("write magic");
        file.write_all(&2u16.to_le_bytes()).expect("write version");
        file.write_all(&0u16.to_le_bytes()).expect("write flags");
        file.write_all(&[0u8]).expect("write compression byte");

        let metadata = TraceMetadata::new(42);
        let meta_bytes = rmp_serde::to_vec(&metadata).expect("serialize metadata");
        file.write_all(&(meta_bytes.len() as u32).to_le_bytes())
            .expect("write meta len");
        file.write_all(&meta_bytes).expect("write metadata");
    }

    #[test]
    fn compat_reader_read_event_errors_on_truncated_stream() {
        use std::io::Write;
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();
        let mut file = std::fs::File::create(path).expect("create file");
        write_header_with_metadata(&mut file);
        // Declare one event but write none.
        file.write_all(&1u64.to_le_bytes())
            .expect("write event count");
        file.flush().expect("flush");
        drop(file);

        let mut reader = CompatReader::open(path).expect("open reader");
        let err = reader
            .read_event()
            .expect_err("truncated event stream must error");
        assert!(matches!(err, TraceFileError::Io(_)), "got: {err:?}");
    }

    #[test]
    fn compat_reader_read_event_compat_errors_on_truncated_stream() {
        use std::io::Write;
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();
        let mut file = std::fs::File::create(path).expect("create file");
        write_header_with_metadata(&mut file);
        // Declare one event but write none.
        file.write_all(&1u64.to_le_bytes())
            .expect("write event count");
        file.flush().expect("flush");
        drop(file);

        let mut reader = CompatReader::open(path).expect("open reader");
        let err = reader
            .read_event_compat()
            .expect_err("truncated event stream must error");
        assert!(matches!(err, TraceFileError::Io(_)), "got: {err:?}");
    }

    #[test]
    fn compat_event_iterator_errors_on_truncated_stream() {
        use std::io::Write;
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();
        let mut file = std::fs::File::create(path).expect("create file");
        write_header_with_metadata(&mut file);
        // Declare one event but write none.
        file.write_all(&1u64.to_le_bytes())
            .expect("write event count");
        file.flush().expect("flush");
        drop(file);

        let mut iter = CompatReader::open(path).expect("open reader").events();
        let first = iter
            .next()
            .expect("iterator should emit an error for the missing event");
        assert!(
            matches!(first, Err(TraceFileError::Io(_))),
            "got: {first:?}"
        );
    }

    #[test]
    fn compat_stats_tracking() {
        let mut stats = CompatStats::default();

        stats.record_read();
        stats.record_read();
        stats.record_skipped(Some("UnknownEvent"));
        stats.record_skipped(Some("UnknownEvent")); // duplicate type
        stats.record_skipped(Some("AnotherUnknown"));
        stats.record_migrated();

        assert_eq!(stats.events_read, 3); // 2 read + 1 migrated
        assert_eq!(stats.events_skipped, 3);
        assert_eq!(stats.events_migrated, 1);
        assert_eq!(stats.unknown_event_types.len(), 2);
        assert!(stats.has_issues());
    }

    #[test]
    fn migrator_no_migrations_needed() {
        let migrator = TraceMigrator::new();

        let metadata = TraceMetadata::new(42);
        let events = vec![ReplayEvent::RngSeed { seed: 42 }];

        let result = migrator.migrate(metadata.clone(), events.clone(), REPLAY_SCHEMA_VERSION);
        assert!(result.is_some());

        let (new_meta, new_events) = result.unwrap();
        assert_eq!(new_meta.seed, metadata.seed);
        assert_eq!(new_events.len(), events.len());
    }

    #[test]
    fn migrator_can_migrate_check() {
        let migrator = TraceMigrator::new();

        // No migrations registered, so can only "migrate" same version
        assert!(migrator.can_migrate(1, 1));
        assert!(!migrator.can_migrate(1, 2)); // No migration registered
        assert!(!migrator.can_migrate(2, 1)); // Reverse migration is not implicit identity
    }

    // Example migration for testing
    struct TestMigration;

    impl TraceMigration for TestMigration {
        fn from_version(&self) -> u32 {
            1
        }
        fn to_version(&self) -> u32 {
            2
        }
        fn migrate_event(&self, event: ReplayEvent) -> Option<ReplayEvent> {
            Some(event) // Pass through unchanged
        }
    }

    #[test]
    fn migrator_with_registered_migration() {
        let migrator = TraceMigrator::new().with_migration(TestMigration);

        assert!(migrator.can_migrate(1, 2));
        assert!(!migrator.can_migrate(1, 3)); // No v2->v3 migration

        let mut metadata = TraceMetadata::new(42);
        metadata.version = 1;
        let events = vec![ReplayEvent::RngSeed { seed: 42 }];

        let result = migrator.migrate(metadata, events, 2);
        assert!(result.is_some());

        let (new_meta, _) = result.unwrap();
        assert_eq!(new_meta.version, 2);
    }

    // =========================================================================
    // Wave 26: Data-type trait coverage
    // =========================================================================

    #[test]
    fn compatibility_result_debug_compatible() {
        let r = CompatibilityResult::Compatible;
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Compatible"));
    }

    #[test]
    fn compatibility_result_debug_needs_migration() {
        let r = CompatibilityResult::NeedsMigration { from: 1, to: 3 };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("NeedsMigration"));
        assert!(dbg.contains('1'));
        assert!(dbg.contains('3'));
    }

    #[test]
    fn compatibility_result_debug_too_old() {
        let r = CompatibilityResult::TooOld {
            found: 0,
            min_supported: 1,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("TooOld"));
        assert!(dbg.contains('0'));
    }

    #[test]
    fn compatibility_result_debug_too_new() {
        let r = CompatibilityResult::TooNew {
            found: 99,
            max_supported: 2,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("TooNew"));
        assert!(dbg.contains("99"));
    }

    #[test]
    fn compatibility_result_clone() {
        let r = CompatibilityResult::NeedsMigration { from: 1, to: 2 };
        let r2 = r.clone();
        assert_eq!(r, r2);
    }

    #[test]
    fn compatibility_result_eq_different_variants() {
        assert_ne!(
            CompatibilityResult::Compatible,
            CompatibilityResult::TooNew {
                found: 5,
                max_supported: 3,
            }
        );
    }

    #[test]
    fn check_schema_compatibility_version_zero() {
        let result = check_schema_compatibility(0);
        assert!(matches!(
            result,
            CompatibilityResult::TooOld {
                found: 0,
                min_supported: 1,
            }
        ));
    }

    #[test]
    fn compat_event_debug_event_variant() {
        let event = CompatEvent::Event(ReplayEvent::RngSeed { seed: 7 });
        let dbg = format!("{event:?}");
        assert!(dbg.contains("Event"));
        assert!(dbg.contains("RngSeed"));
    }

    #[test]
    fn compat_event_debug_skipped_variant() {
        let event = CompatEvent::Skipped {
            reason: "unknown type".to_string(),
            raw_bytes: vec![0xde, 0xad],
        };
        let dbg = format!("{event:?}");
        assert!(dbg.contains("Skipped"));
        assert!(dbg.contains("unknown type"));
    }

    #[test]
    fn compat_stats_default_zeroed() {
        let stats = CompatStats::default();
        assert_eq!(stats.events_read, 0);
        assert_eq!(stats.events_skipped, 0);
        assert_eq!(stats.events_migrated, 0);
        assert!(stats.unknown_event_types.is_empty());
    }

    #[test]
    fn compat_stats_clone() {
        let mut stats = CompatStats::default();
        stats.record_read();
        stats.record_skipped(Some("FooEvent"));
        let stats2 = stats.clone();
        assert_eq!(stats2.events_read, 1);
        assert_eq!(stats2.events_skipped, 1);
        assert_eq!(stats2.unknown_event_types.len(), 1);
    }

    #[test]
    fn compat_stats_debug() {
        let stats = CompatStats::default();
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("CompatStats"));
        assert!(dbg.contains("events_read"));
    }

    #[test]
    fn compat_stats_has_issues_false_when_clean() {
        let mut stats = CompatStats::default();
        stats.record_read();
        stats.record_read();
        stats.record_migrated();
        assert!(!stats.has_issues());
    }

    #[test]
    fn compat_stats_record_skipped_none_type() {
        let mut stats = CompatStats::default();
        stats.record_skipped(None);
        assert_eq!(stats.events_skipped, 1);
        assert!(stats.unknown_event_types.is_empty());
        assert!(stats.has_issues());
    }

    #[test]
    fn migrator_default_trait() {
        let m1 = TraceMigrator::new();
        let m2 = TraceMigrator::default();
        // Both should be empty migrators with identical behavior
        assert!(m1.can_migrate(1, 1));
        assert!(m2.can_migrate(1, 1));
        assert!(!m1.can_migrate(1, 2));
        assert!(!m2.can_migrate(1, 2));
    }
}
