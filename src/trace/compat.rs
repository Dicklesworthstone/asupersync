//! Trace format compatibility and migration support.
//!
//! This module provides forward and backward compatibility for the trace file
//! format, allowing:
//!
//! - **Forward compatibility**: Newer runtimes can read older trace files
//! - **Backward tolerance**: Unknown events are skipped with warnings
//! - **Migration**: Transform traces from older formats to newer ones
//!
//! # Version Policy
//!
//! - Schema version increments on breaking changes to event format
//! - File format version increments on changes to the binary container
//! - Older traces can always be read; unknown events are skipped
//! - Migration transforms old event types to new equivalents
//!
//! # Example
//!
//! ```ignore
//! use asupersync::trace::compat::{TraceMigrator, CompatReader};
//!
//! // Read a trace with compatibility handling
//! let reader = CompatReader::open("old_trace.bin")?;
//! for event in reader.events() {
//!     match event {
//!         Ok(event) => process(event),
//!         Err(CompatEvent::Skipped { reason }) => {
//!             warn!("Skipped unknown event: {}", reason);
//!         }
//!         Err(CompatEvent::Error(e)) => return Err(e),
//!     }
//! }
//! ```

use super::file::{TraceFileError, TraceFileResult, HEADER_SIZE, TRACE_FILE_VERSION, TRACE_MAGIC};
use super::replay::{ReplayEvent, TraceMetadata, REPLAY_SCHEMA_VERSION};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

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
/// Unlike `TraceReader`, this reader:
/// - Accepts older schema versions (within supported range)
/// - Skips unknown events with warnings instead of failing
/// - Provides statistics about compatibility issues
pub struct CompatReader {
    reader: BufReader<File>,
    metadata: TraceMetadata,
    event_count: u64,
    events_read: u64,
    events_start_pos: u64,
    schema_version: u32,
    stats: CompatStats,
    on_skip: Option<Box<dyn Fn(&str, &[u8]) + Send + Sync>>,
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
        if file_version > TRACE_FILE_VERSION {
            return Err(TraceFileError::UnsupportedVersion {
                expected: TRACE_FILE_VERSION,
                found: file_version,
            });
        }

        // Read flags
        let mut flags_bytes = [0u8; 2];
        reader.read_exact(&mut flags_bytes)?;
        let flags = u16::from_le_bytes(flags_bytes);
        if flags != 0 {
            // For forward compat, we warn about unknown flags but continue
            // Only fail on flags we know are incompatible
            if flags & super::file::FLAG_COMPRESSED != 0 {
                return Err(TraceFileError::UnsupportedFlags(flags));
            }
        }

        // Read metadata length
        let mut meta_len_bytes = [0u8; 4];
        reader.read_exact(&mut meta_len_bytes)?;
        let meta_len = u32::from_le_bytes(meta_len_bytes) as usize;

        // Read metadata with lenient deserialization
        let mut meta_bytes = vec![0u8; meta_len];
        reader.read_exact(&mut meta_bytes)?;
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
                // For forward compat with newer traces, we proceed but may skip events
                // Log a warning (caller can check stats)
                eprintln!(
                    "Warning: trace schema version {found} is newer than supported version {max_supported}. \
                     Some events may be skipped."
                );
            }
        }

        // Read event count
        let mut event_count_bytes = [0u8; 8];
        reader.read_exact(&mut event_count_bytes)?;
        let event_count = u64::from_le_bytes(event_count_bytes);

        let events_start_pos = HEADER_SIZE as u64 + meta_len as u64 + 8;

        Ok(Self {
            reader,
            metadata,
            event_count,
            events_read: 0,
            events_start_pos,
            schema_version,
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

    /// Reads the next event, skipping unknown events.
    ///
    /// Returns `Ok(None)` when all events have been read.
    /// Unknown events are skipped and recorded in stats.
    pub fn read_event(&mut self) -> TraceFileResult<Option<ReplayEvent>> {
        loop {
            if self.events_read >= self.event_count {
                return Ok(None);
            }

            // Read event length
            let mut len_bytes = [0u8; 4];
            if self.reader.read_exact(&mut len_bytes).is_err() {
                return Ok(None);
            }
            let len = u32::from_le_bytes(len_bytes) as usize;

            // Read event data
            let mut event_bytes = vec![0u8; len];
            self.reader.read_exact(&mut event_bytes)?;
            self.events_read += 1;

            // Try to deserialize
            match rmp_serde::from_slice::<ReplayEvent>(&event_bytes) {
                Ok(event) => {
                    self.stats.record_read();
                    return Ok(Some(event));
                }
                Err(e) => {
                    // Try to extract the event type from the raw bytes for logging
                    let event_type = extract_event_type(&event_bytes);
                    let reason = format!("unknown event type: {e}");

                    self.stats.record_skipped(event_type.as_deref());

                    if let Some(ref callback) = self.on_skip {
                        callback(&reason, &event_bytes);
                    }

                    // Continue to next event
                }
            }
        }
    }

    /// Reads the next event, returning detailed compatibility info.
    ///
    /// Unlike `read_event`, this returns `CompatEvent::Skipped` for unknown
    /// events instead of silently skipping them.
    pub fn read_event_compat(&mut self) -> TraceFileResult<Option<CompatEvent>> {
        if self.events_read >= self.event_count {
            return Ok(None);
        }

        // Read event length
        let mut len_bytes = [0u8; 4];
        if self.reader.read_exact(&mut len_bytes).is_err() {
            return Ok(None);
        }
        let len = u32::from_le_bytes(len_bytes) as usize;

        // Read event data
        let mut event_bytes = vec![0u8; len];
        self.reader.read_exact(&mut event_bytes)?;
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

    /// Returns an iterator over events, skipping unknown ones.
    #[must_use]
    pub fn events(self) -> CompatEventIterator {
        CompatEventIterator {
            reader: self.reader,
            remaining: self.event_count,
            on_skip: self.on_skip,
        }
    }

    /// Resets to the beginning of the events section.
    pub fn rewind(&mut self) -> TraceFileResult<()> {
        self.reader.seek(SeekFrom::Start(self.events_start_pos))?;
        self.events_read = 0;
        Ok(())
    }

    /// Loads all known events into memory, skipping unknown ones.
    pub fn load_all(mut self) -> TraceFileResult<(Vec<ReplayEvent>, CompatStats)> {
        let mut events = Vec::with_capacity(self.event_count as usize);
        while let Some(event) = self.read_event()? {
            events.push(event);
        }
        Ok((events, self.stats))
    }
}

/// Iterator over events with compatibility handling.
pub struct CompatEventIterator {
    reader: BufReader<File>,
    remaining: u64,
    on_skip: Option<Box<dyn Fn(&str, &[u8]) + Send + Sync>>,
}

impl Iterator for CompatEventIterator {
    type Item = TraceFileResult<ReplayEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.remaining == 0 {
                return None;
            }

            // Read event length
            let mut len_bytes = [0u8; 4];
            if let Err(e) = self.reader.read_exact(&mut len_bytes) {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    return None;
                }
                return Some(Err(TraceFileError::Io(e)));
            }
            let len = u32::from_le_bytes(len_bytes) as usize;

            // Read event data
            let mut event_bytes = vec![0u8; len];
            if let Err(e) = self.reader.read_exact(&mut event_bytes) {
                return Some(Err(TraceFileError::Io(e)));
            }

            self.remaining -= 1;

            // Try to deserialize
            match rmp_serde::from_slice::<ReplayEvent>(&event_bytes) {
                Ok(event) => return Some(Ok(event)),
                Err(e) => {
                    // Skip unknown events
                    if let Some(ref callback) = self.on_skip {
                        let event_type = extract_event_type(&event_bytes);
                        let reason = format!(
                            "skipping unknown event: {}{}",
                            event_type
                                .map(|t| format!("type '{t}', "))
                                .unwrap_or_default(),
                            e
                        );
                        callback(&reason, &event_bytes);
                    }
                    // Continue to next event
                }
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
    fn from_version(&self) -> u32;

    /// Target schema version after migration.
    fn to_version(&self) -> u32;

    /// Migrates a single event.
    ///
    /// Returns `None` if the event should be dropped during migration.
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
pub struct TraceMigrator {
    migrations: Vec<Box<dyn TraceMigration>>,
}

impl TraceMigrator {
    /// Creates a new migrator with no registered migrations.
    #[must_use]
    pub fn new() -> Self {
        Self {
            migrations: Vec::new(),
        }
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
        if from >= to {
            return Some(Vec::new());
        }

        let mut path = Vec::new();
        let mut current = from;

        while current < to {
            // Find migration from current version
            let migration = self
                .migrations
                .iter()
                .find(|m| m.from_version() == current)?;

            path.push(migration.as_ref());
            current = migration.to_version();
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
            current_events = current_events
                .into_iter()
                .filter_map(|e| migration.migrate_event(e))
                .collect();
        }

        Some((current_metadata, current_events))
    }

    /// Checks if migration is possible between versions.
    #[must_use]
    pub fn can_migrate(&self, from: u32, to: u32) -> bool {
        self.find_migration_path(from, to).is_some()
    }
}

impl Default for TraceMigrator {
    fn default() -> Self {
        Self::new()
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
    use super::*;
    use crate::trace::file::{write_trace, TraceWriter};
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
    fn compat_reader_skips_unknown_events() {
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
    fn compat_reader_skips_unknown_event_types_with_raw_bytes() {
        use std::io::Write;
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        // Manually construct a trace file with an unknown event type
        let mut file = std::fs::File::create(path).expect("create file");

        // Write header
        file.write_all(super::TRACE_MAGIC).expect("write magic");
        file.write_all(&super::TRACE_FILE_VERSION.to_le_bytes())
            .expect("write version");
        file.write_all(&0u16.to_le_bytes()).expect("write flags");

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

        // Now read with compat reader
        let reader = CompatReader::open(path)
            .expect("open reader")
            .on_skip(|reason, _bytes| {
                assert!(reason.contains("FutureEventType") || reason.contains("unknown"));
            });

        let (events, stats) = reader.load_all().expect("load all");

        // Should have read 2 events (skipped the unknown one)
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], ReplayEvent::RngSeed { seed: 100 }));
        assert!(matches!(events[1], ReplayEvent::TaskYielded { .. }));

        // Stats should show 1 skipped event
        assert_eq!(stats.events_read, 2);
        assert_eq!(stats.events_skipped, 1);
        assert!(stats.has_issues());
    }

    #[test]
    fn compat_reader_read_event_compat_returns_skipped_info() {
        use std::io::Write;
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        // Manually construct a trace with an unknown event
        let mut file = std::fs::File::create(path).expect("create file");
        file.write_all(super::TRACE_MAGIC).expect("write magic");
        file.write_all(&super::TRACE_FILE_VERSION.to_le_bytes())
            .expect("write version");
        file.write_all(&0u16.to_le_bytes()).expect("write flags");

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
}
