//! Trace file integrity verification.
//!
//! This module provides utilities for verifying the integrity of trace files
//! and detecting corruption before replay.
//!
//! # Features
//!
//! - **Header validation**: Magic bytes, version, and flags
//! - **Metadata verification**: Schema version and format
//! - **Event count validation**: Actual events match declared count
//! - **Timeline monotonicity**: Timestamps always increase (optional)
//! - **Partial recovery**: Find first corrupted event for partial replay
//! - **Diagnostic mode**: Detailed reports of corruption
//!
//! # Example
//!
//! ```ignore
//! use asupersync::trace::integrity::{verify_trace, VerificationOptions};
//!
//! // Verify a trace file
//! let result = verify_trace("trace.bin", &VerificationOptions::default())?;
//! if result.is_valid() {
//!     println!("Trace is valid with {} events", result.event_count);
//! } else {
//!     for issue in result.issues() {
//!         eprintln!("Issue: {}", issue);
//!     }
//! }
//!
//! // Strict verification (includes timeline monotonicity)
//! let result = verify_trace("trace.bin", &VerificationOptions::strict())?;
//! ```

use super::file::{HEADER_SIZE, TRACE_FILE_VERSION, TRACE_MAGIC};
use super::replay::{ReplayEvent, TraceMetadata, REPLAY_SCHEMA_VERSION};
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

// =============================================================================
// Types
// =============================================================================

/// Options for trace verification.
#[derive(Debug, Clone)]
pub struct VerificationOptions {
    /// Check that timestamps are monotonically increasing.
    pub check_monotonicity: bool,

    /// Stop at first error (fail fast) vs collect all errors.
    pub fail_fast: bool,

    /// Maximum number of issues to collect before stopping.
    pub max_issues: usize,

    /// Verify event deserialization (slower but more thorough).
    pub verify_events: bool,
}

impl Default for VerificationOptions {
    fn default() -> Self {
        Self {
            check_monotonicity: false,
            fail_fast: false,
            max_issues: 100,
            verify_events: true,
        }
    }
}

impl VerificationOptions {
    /// Create options for fast verification (header only).
    #[must_use]
    pub fn quick() -> Self {
        Self {
            check_monotonicity: false,
            fail_fast: true,
            max_issues: 1,
            verify_events: false,
        }
    }

    /// Create options for strict verification (all checks).
    #[must_use]
    pub fn strict() -> Self {
        Self {
            check_monotonicity: true,
            fail_fast: false,
            max_issues: 1000,
            verify_events: true,
        }
    }

    /// Set whether to check timeline monotonicity.
    #[must_use]
    pub const fn with_monotonicity(mut self, check: bool) -> Self {
        self.check_monotonicity = check;
        self
    }

    /// Set whether to fail fast on first error.
    #[must_use]
    pub const fn with_fail_fast(mut self, fail_fast: bool) -> Self {
        self.fail_fast = fail_fast;
        self
    }
}

/// An issue found during verification.
#[derive(Debug, Clone)]
pub enum IntegrityIssue {
    /// File is too small to contain a valid header.
    FileTooSmall {
        /// Actual file size.
        actual: u64,
        /// Minimum expected size.
        expected: u64,
    },

    /// Invalid magic bytes at start of file.
    InvalidMagic {
        /// The bytes found at the start of the file.
        found: [u8; 11],
    },

    /// Unsupported file format version.
    UnsupportedVersion {
        /// The version found in the file.
        found: u16,
        /// Maximum supported version.
        max_supported: u16,
    },

    /// Unsupported flags in header.
    UnsupportedFlags {
        /// The flags found in the file.
        flags: u16,
    },

    /// Schema version mismatch in metadata.
    SchemaMismatch {
        /// The schema version found.
        found: u32,
        /// Expected schema version.
        expected: u32,
    },

    /// Metadata deserialization failed.
    InvalidMetadata {
        /// Error message.
        message: String,
    },

    /// Event count mismatch.
    EventCountMismatch {
        /// Declared event count in header.
        declared: u64,
        /// Actual events that could be read.
        actual: u64,
    },

    /// Event deserialization failed.
    InvalidEvent {
        /// Event index (0-based).
        index: u64,
        /// Error message.
        message: String,
    },

    /// File is truncated (unexpected EOF during event read).
    Truncated {
        /// Event index where truncation occurred.
        at_event: u64,
    },

    /// Timeline is not monotonically increasing.
    TimelineNonMonotonic {
        /// Event index where non-monotonicity was detected.
        at_event: u64,
        /// Previous timestamp.
        prev_time: u64,
        /// Current timestamp.
        curr_time: u64,
    },

    /// I/O error during verification.
    IoError {
        /// Error message.
        message: String,
    },
}

impl std::fmt::Display for IntegrityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileTooSmall { actual, expected } => {
                write!(
                    f,
                    "file too small: {actual} bytes, expected at least {expected}"
                )
            }
            Self::InvalidMagic { found } => {
                write!(f, "invalid magic bytes: {found:?}")
            }
            Self::UnsupportedVersion {
                found,
                max_supported,
            } => {
                write!(
                    f,
                    "unsupported version: {found}, max supported: {max_supported}"
                )
            }
            Self::UnsupportedFlags { flags } => {
                write!(f, "unsupported flags: {flags:#06x}")
            }
            Self::SchemaMismatch { found, expected } => {
                write!(
                    f,
                    "schema version mismatch: found {found}, expected {expected}"
                )
            }
            Self::InvalidMetadata { message } => {
                write!(f, "invalid metadata: {message}")
            }
            Self::EventCountMismatch { declared, actual } => {
                write!(
                    f,
                    "event count mismatch: declared {declared}, actual {actual}"
                )
            }
            Self::InvalidEvent { index, message } => {
                write!(f, "invalid event at index {index}: {message}")
            }
            Self::Truncated { at_event } => {
                write!(f, "file truncated at event {at_event}")
            }
            Self::TimelineNonMonotonic {
                at_event,
                prev_time,
                curr_time,
            } => {
                write!(
                    f,
                    "non-monotonic timeline at event {at_event}: {prev_time} -> {curr_time}"
                )
            }
            Self::IoError { message } => {
                write!(f, "I/O error: {message}")
            }
        }
    }
}

impl std::error::Error for IntegrityIssue {}

/// Severity level of an integrity issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssueSeverity {
    /// Warning - file may still be usable.
    Warning,
    /// Error - file is partially corrupted but may be recoverable.
    Error,
    /// Fatal - file cannot be used at all.
    Fatal,
}

impl IntegrityIssue {
    /// Returns the severity of this issue.
    #[must_use]
    pub fn severity(&self) -> IssueSeverity {
        match self {
            Self::FileTooSmall { .. }
            | Self::InvalidMagic { .. }
            | Self::UnsupportedVersion { .. }
            | Self::InvalidMetadata { .. } => IssueSeverity::Fatal,

            Self::UnsupportedFlags { .. }
            | Self::SchemaMismatch { .. }
            | Self::EventCountMismatch { .. }
            | Self::Truncated { .. }
            | Self::InvalidEvent { .. }
            | Self::TimelineNonMonotonic { .. }
            | Self::IoError { .. } => IssueSeverity::Error,
        }
    }

    /// Returns true if this issue is fatal (file cannot be used).
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        self.severity() == IssueSeverity::Fatal
    }
}

/// Result of trace verification.
#[derive(Debug)]
pub struct VerificationResult {
    /// Total file size in bytes.
    pub file_size: u64,

    /// Declared event count from header.
    pub declared_events: u64,

    /// Actual events successfully read.
    pub verified_events: u64,

    /// Issues found during verification.
    issues: Vec<IntegrityIssue>,

    /// Trace metadata (if readable).
    metadata: Option<TraceMetadata>,

    /// Whether full verification was completed.
    pub completed: bool,
}

impl VerificationResult {
    /// Creates a new verification result.
    fn new(file_size: u64) -> Self {
        Self {
            file_size,
            declared_events: 0,
            verified_events: 0,
            issues: Vec::new(),
            metadata: None,
            completed: false,
        }
    }

    /// Returns true if the trace is valid (no issues found).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.issues.is_empty()
    }

    /// Returns true if the trace has fatal issues.
    #[must_use]
    pub fn has_fatal_issues(&self) -> bool {
        self.issues.iter().any(IntegrityIssue::is_fatal)
    }

    /// Returns true if the trace is partially usable.
    #[must_use]
    pub fn is_partially_usable(&self) -> bool {
        !self.has_fatal_issues() && self.verified_events > 0
    }

    /// Returns the list of issues found.
    #[must_use]
    pub fn issues(&self) -> &[IntegrityIssue] {
        &self.issues
    }

    /// Returns issues that are fatal.
    pub fn fatal_issues(&self) -> impl Iterator<Item = &IntegrityIssue> {
        self.issues.iter().filter(|i| i.is_fatal())
    }

    /// Returns the trace metadata if it was readable.
    #[must_use]
    pub fn metadata(&self) -> Option<&TraceMetadata> {
        self.metadata.as_ref()
    }

    /// Returns the number of events that can be safely replayed.
    #[must_use]
    pub fn safe_event_count(&self) -> u64 {
        if self.has_fatal_issues() {
            0
        } else {
            self.verified_events
        }
    }

    fn add_issue(&mut self, issue: IntegrityIssue) {
        self.issues.push(issue);
    }
}

impl std::fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_valid() {
            write!(
                f,
                "Trace valid: {} events, {} bytes",
                self.verified_events, self.file_size
            )
        } else {
            write!(
                f,
                "Trace has {} issue(s): {}/{} events verified",
                self.issues.len(),
                self.verified_events,
                self.declared_events
            )
        }
    }
}

// =============================================================================
// Verification Functions
// =============================================================================

/// Verifies a trace file for integrity.
///
/// # Arguments
///
/// * `path` - Path to the trace file
/// * `options` - Verification options
///
/// # Returns
///
/// A [`VerificationResult`] containing the verification outcome and any issues.
///
/// # Errors
///
/// Returns an error only for unrecoverable I/O issues (file not found, etc.).
/// Corruption issues are reported in the `VerificationResult`.
///
/// # Example
///
/// ```ignore
/// let result = verify_trace("trace.bin", &VerificationOptions::default())?;
/// if result.is_valid() {
///     println!("Valid trace with {} events", result.verified_events);
/// }
/// ```
pub fn verify_trace(
    path: impl AsRef<Path>,
    options: &VerificationOptions,
) -> io::Result<VerificationResult> {
    let path = path.as_ref();
    let file = File::open(path)?;
    let file_size = file.metadata()?.len();

    let mut result = VerificationResult::new(file_size);
    let mut reader = BufReader::new(file);

    // Check minimum file size
    let min_size = HEADER_SIZE as u64 + 8; // header + event_count
    if file_size < min_size {
        result.add_issue(IntegrityIssue::FileTooSmall {
            actual: file_size,
            expected: min_size,
        });
        return Ok(result);
    }

    // Verify header
    if !verify_header(&mut reader, &mut result, options) {
        return Ok(result);
    }

    // Verify metadata
    if !verify_metadata(&mut reader, &mut result, options) {
        return Ok(result);
    }

    // Read event count
    let event_count = match read_event_count(&mut reader) {
        Ok(count) => count,
        Err(e) => {
            result.add_issue(IntegrityIssue::IoError {
                message: e.to_string(),
            });
            return Ok(result);
        }
    };
    result.declared_events = event_count;

    // Verify events if requested
    if options.verify_events {
        verify_events(&mut reader, &mut result, options);
    } else {
        // Just count events without full deserialization
        count_events(&mut reader, &mut result);
    }

    result.completed = true;
    Ok(result)
}

/// Quickly checks if a trace file appears valid (header check only).
///
/// This is much faster than full verification but doesn't check event data.
///
/// # Errors
///
/// Returns an error if the file cannot be opened.
pub fn is_trace_valid_quick(path: impl AsRef<Path>) -> io::Result<bool> {
    let result = verify_trace(path, &VerificationOptions::quick())?;
    Ok(result.is_valid() || !result.has_fatal_issues())
}

/// Finds the first corrupted event in a trace.
///
/// Returns `None` if no corruption is found or if the header is invalid.
///
/// # Errors
///
/// Returns an error if the file cannot be opened.
pub fn find_first_corruption(path: impl AsRef<Path>) -> io::Result<Option<u64>> {
    let result = verify_trace(path, &VerificationOptions::default().with_fail_fast(true))?;

    for issue in result.issues() {
        match issue {
            IntegrityIssue::InvalidEvent { index, .. }
            | IntegrityIssue::Truncated { at_event: index }
            | IntegrityIssue::TimelineNonMonotonic {
                at_event: index, ..
            } => {
                return Ok(Some(*index));
            }
            _ => {}
        }
    }

    Ok(None)
}

// =============================================================================
// Internal Functions
// =============================================================================

fn verify_header(
    reader: &mut BufReader<File>,
    result: &mut VerificationResult,
    options: &VerificationOptions,
) -> bool {
    // Read magic bytes
    let mut magic = [0u8; 11];
    if reader.read_exact(&mut magic).is_err() {
        result.add_issue(IntegrityIssue::IoError {
            message: "failed to read magic bytes".to_string(),
        });
        return false;
    }

    if &magic != TRACE_MAGIC {
        result.add_issue(IntegrityIssue::InvalidMagic { found: magic });
        return !options.fail_fast;
    }

    // Read version
    let mut version_bytes = [0u8; 2];
    if reader.read_exact(&mut version_bytes).is_err() {
        result.add_issue(IntegrityIssue::IoError {
            message: "failed to read version".to_string(),
        });
        return false;
    }
    let version = u16::from_le_bytes(version_bytes);

    if version > TRACE_FILE_VERSION {
        result.add_issue(IntegrityIssue::UnsupportedVersion {
            found: version,
            max_supported: TRACE_FILE_VERSION,
        });
        return !options.fail_fast;
    }

    // Read flags
    let mut flags_bytes = [0u8; 2];
    if reader.read_exact(&mut flags_bytes).is_err() {
        result.add_issue(IntegrityIssue::IoError {
            message: "failed to read flags".to_string(),
        });
        return false;
    }
    let flags = u16::from_le_bytes(flags_bytes);

    // Check for unsupported flags (only compression flag is defined)
    if flags & super::file::FLAG_COMPRESSED != 0 {
        result.add_issue(IntegrityIssue::UnsupportedFlags { flags });
        return !options.fail_fast;
    }

    // Read compression byte (only in version 2+)
    if version >= 2 {
        let mut compression_byte = [0u8; 1];
        if reader.read_exact(&mut compression_byte).is_err() {
            result.add_issue(IntegrityIssue::IoError {
                message: "failed to read compression byte".to_string(),
            });
            return false;
        }
    }

    true
}

fn verify_metadata(
    reader: &mut BufReader<File>,
    result: &mut VerificationResult,
    options: &VerificationOptions,
) -> bool {
    // Read metadata length
    let mut meta_len_bytes = [0u8; 4];
    if reader.read_exact(&mut meta_len_bytes).is_err() {
        result.add_issue(IntegrityIssue::IoError {
            message: "failed to read metadata length".to_string(),
        });
        return false;
    }
    let meta_len = u32::from_le_bytes(meta_len_bytes) as usize;

    // Read metadata bytes
    let mut meta_bytes = vec![0u8; meta_len];
    if reader.read_exact(&mut meta_bytes).is_err() {
        result.add_issue(IntegrityIssue::IoError {
            message: "failed to read metadata".to_string(),
        });
        return false;
    }

    // Deserialize metadata
    let metadata: TraceMetadata = match rmp_serde::from_slice(&meta_bytes) {
        Ok(m) => m,
        Err(e) => {
            result.add_issue(IntegrityIssue::InvalidMetadata {
                message: e.to_string(),
            });
            return !options.fail_fast;
        }
    };

    // Check schema version
    if metadata.version != REPLAY_SCHEMA_VERSION {
        result.add_issue(IntegrityIssue::SchemaMismatch {
            found: metadata.version,
            expected: REPLAY_SCHEMA_VERSION,
        });
        if options.fail_fast {
            return false;
        }
    }

    result.metadata = Some(metadata);
    true
}

fn read_event_count(reader: &mut BufReader<File>) -> io::Result<u64> {
    let mut count_bytes = [0u8; 8];
    reader.read_exact(&mut count_bytes)?;
    Ok(u64::from_le_bytes(count_bytes))
}

fn verify_events(
    reader: &mut BufReader<File>,
    result: &mut VerificationResult,
    options: &VerificationOptions,
) {
    let mut prev_time: Option<u64> = None;
    let mut event_index = 0u64;

    loop {
        if result.issues.len() >= options.max_issues {
            break;
        }

        // Read event length
        let mut len_bytes = [0u8; 4];
        match reader.read_exact(&mut len_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // Check if we've read all declared events
                if event_index < result.declared_events {
                    result.add_issue(IntegrityIssue::Truncated {
                        at_event: event_index,
                    });
                }
                break;
            }
            Err(e) => {
                result.add_issue(IntegrityIssue::IoError {
                    message: e.to_string(),
                });
                break;
            }
        }

        let len = u32::from_le_bytes(len_bytes) as usize;

        // Read event bytes
        let mut event_bytes = vec![0u8; len];
        match reader.read_exact(&mut event_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                result.add_issue(IntegrityIssue::Truncated {
                    at_event: event_index,
                });
                break;
            }
            Err(e) => {
                result.add_issue(IntegrityIssue::IoError {
                    message: e.to_string(),
                });
                if options.fail_fast {
                    break;
                }
                event_index += 1;
                continue;
            }
        }

        // Deserialize event
        let event: ReplayEvent = match rmp_serde::from_slice(&event_bytes) {
            Ok(e) => e,
            Err(e) => {
                result.add_issue(IntegrityIssue::InvalidEvent {
                    index: event_index,
                    message: e.to_string(),
                });
                if options.fail_fast {
                    break;
                }
                event_index += 1;
                continue;
            }
        };

        // Check timeline monotonicity if requested
        if options.check_monotonicity {
            if let Some(curr_time) = extract_timestamp(&event) {
                if let Some(prev) = prev_time {
                    if curr_time < prev {
                        result.add_issue(IntegrityIssue::TimelineNonMonotonic {
                            at_event: event_index,
                            prev_time: prev,
                            curr_time,
                        });
                        if options.fail_fast {
                            break;
                        }
                    }
                }
                prev_time = Some(curr_time);
            }
        }

        result.verified_events += 1;
        event_index += 1;

        // Check if we've read all declared events
        if event_index >= result.declared_events {
            break;
        }
    }

    // Check event count mismatch
    if result.verified_events != result.declared_events && !result.has_fatal_issues() {
        result.add_issue(IntegrityIssue::EventCountMismatch {
            declared: result.declared_events,
            actual: result.verified_events,
        });
    }
}

fn count_events(reader: &mut BufReader<File>, result: &mut VerificationResult) {
    let mut event_index = 0u64;

    loop {
        // Read event length
        let mut len_bytes = [0u8; 4];
        if reader.read_exact(&mut len_bytes).is_err() {
            break;
        }

        let len = u32::from_le_bytes(len_bytes) as usize;

        // Skip event bytes
        let len_i64 = i64::try_from(len).unwrap_or(i64::MAX);
        if reader.seek(SeekFrom::Current(len_i64)).is_err() {
            result.add_issue(IntegrityIssue::Truncated {
                at_event: event_index,
            });
            break;
        }

        result.verified_events += 1;
        event_index += 1;

        if event_index >= result.declared_events {
            break;
        }
    }

    if result.verified_events != result.declared_events {
        result.add_issue(IntegrityIssue::EventCountMismatch {
            declared: result.declared_events,
            actual: result.verified_events,
        });
    }
}

/// Extracts a timestamp from a replay event (in nanoseconds).
fn extract_timestamp(event: &ReplayEvent) -> Option<u64> {
    match event {
        ReplayEvent::TaskScheduled { at_tick, .. } | ReplayEvent::TaskSpawned { at_tick, .. } => {
            Some(*at_tick)
        }
        ReplayEvent::TimeAdvanced { to_nanos, .. } => Some(*to_nanos),
        ReplayEvent::TimerCreated { deadline_nanos, .. } => Some(*deadline_nanos),
        _ => None,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::file::write_trace;
    use crate::trace::replay::CompactTaskId;
    use tempfile::NamedTempFile;

    fn sample_events(count: u64) -> Vec<ReplayEvent> {
        (0..count)
            .map(|i| ReplayEvent::TaskScheduled {
                task: CompactTaskId(i),
                at_tick: i * 100, // Monotonically increasing
            })
            .collect()
    }

    #[test]
    fn verify_valid_trace() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(100);
        write_trace(path, &metadata, &events).unwrap();

        let result = verify_trace(path, &VerificationOptions::default()).unwrap();

        assert!(result.is_valid());
        assert_eq!(result.verified_events, 100);
        assert_eq!(result.declared_events, 100);
        assert!(result.metadata().is_some());
        assert!(result.completed);
    }

    #[test]
    fn verify_empty_trace() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        write_trace(path, &metadata, &[]).unwrap();

        let result = verify_trace(path, &VerificationOptions::default()).unwrap();

        assert!(result.is_valid());
        assert_eq!(result.verified_events, 0);
        assert_eq!(result.declared_events, 0);
    }

    #[test]
    fn detect_invalid_magic() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        // Write garbage (must be >= HEADER_SIZE + 8 = 27 bytes to pass size check)
        std::fs::write(path, b"NOT A TRACE FILE - EXTRA PADDING HERE!").unwrap();

        let result = verify_trace(path, &VerificationOptions::default()).unwrap();

        assert!(!result.is_valid());
        assert!(result.has_fatal_issues());
        assert!(matches!(
            result.issues().first(),
            Some(IntegrityIssue::InvalidMagic { .. })
        ));
    }

    #[test]
    fn detect_truncated_file() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        // Write a valid trace
        let metadata = TraceMetadata::new(42);
        let events = sample_events(100);
        write_trace(path, &metadata, &events).unwrap();

        // Truncate the file
        let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        let original_size = file.metadata().unwrap().len();
        file.set_len(original_size / 2).unwrap();

        let result = verify_trace(path, &VerificationOptions::default()).unwrap();

        assert!(!result.is_valid());
        assert!(result.verified_events < 100);
        assert!(result.issues().iter().any(|i| matches!(
            i,
            IntegrityIssue::Truncated { .. } | IntegrityIssue::EventCountMismatch { .. }
        )));
    }

    #[test]
    fn detect_file_too_small() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        // Write too little data
        std::fs::write(path, b"short").unwrap();

        let result = verify_trace(path, &VerificationOptions::default()).unwrap();

        assert!(!result.is_valid());
        assert!(result.has_fatal_issues());
        assert!(matches!(
            result.issues().first(),
            Some(IntegrityIssue::FileTooSmall { .. })
        ));
    }

    #[test]
    fn detect_timeline_non_monotonic() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        // Create events with non-monotonic timestamps
        let events = vec![
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(0),
                at_tick: 100,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 50, // Goes backwards!
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 200,
            },
        ];
        write_trace(path, &metadata, &events).unwrap();

        let result = verify_trace(path, &VerificationOptions::strict()).unwrap();

        assert!(!result.is_valid());
        assert!(result
            .issues()
            .iter()
            .any(|i| matches!(i, IntegrityIssue::TimelineNonMonotonic { at_event: 1, .. })));
    }

    #[test]
    fn quick_verification() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(1000);
        write_trace(path, &metadata, &events).unwrap();

        // Quick verification should be fast (doesn't read events)
        let is_valid = is_trace_valid_quick(path).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn find_first_corruption_none() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(100);
        write_trace(path, &metadata, &events).unwrap();

        let first = find_first_corruption(path).unwrap();
        assert!(first.is_none());
    }

    #[test]
    fn partial_recovery_info() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        // Write a valid trace
        let metadata = TraceMetadata::new(42);
        let events = sample_events(100);
        write_trace(path, &metadata, &events).unwrap();

        // Truncate to corrupt the end
        let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        let original_size = file.metadata().unwrap().len();
        file.set_len(original_size - 100).unwrap();
        drop(file);

        let result = verify_trace(path, &VerificationOptions::default()).unwrap();

        // Should be partially usable
        assert!(result.is_partially_usable());
        assert!(result.safe_event_count() > 0);
        assert!(result.safe_event_count() < 100);
    }

    #[test]
    fn verification_result_display() {
        let mut result = VerificationResult::new(1000);
        result.declared_events = 100;
        result.verified_events = 100;

        let display = format!("{result}");
        assert!(display.contains("valid"));
        assert!(display.contains("100 events"));

        result.add_issue(IntegrityIssue::EventCountMismatch {
            declared: 100,
            actual: 50,
        });
        result.verified_events = 50;

        let display = format!("{result}");
        assert!(display.contains("1 issue"));
        assert!(display.contains("50/100"));
    }

    #[test]
    fn issue_severity() {
        assert_eq!(
            IntegrityIssue::InvalidMagic { found: [0; 11] }.severity(),
            IssueSeverity::Fatal
        );
        assert_eq!(
            IntegrityIssue::Truncated { at_event: 0 }.severity(),
            IssueSeverity::Error
        );
        assert_eq!(
            IntegrityIssue::InvalidEvent {
                index: 0,
                message: "test".to_string()
            }
            .severity(),
            IssueSeverity::Error
        );
    }

    #[test]
    fn corrupted_event_detection() {
        use std::io::Write;

        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(10);

        // Write a complete valid trace first
        write_trace(path, &metadata, &events).unwrap();

        // Now corrupt the file by appending garbage after valid events
        // We'll overwrite some bytes in the middle of the file
        {
            let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();

            // Seek to somewhere in the middle of the events section
            // and write garbage to corrupt an event
            let file_size = file.metadata().unwrap().len();
            // Seek to about 3/4 of the file (into event data)
            file.seek(SeekFrom::Start(file_size * 3 / 4)).unwrap();

            // Write garbage that will corrupt event deserialization
            file.write_all(b"CORRUPTED_DATA_HERE!").unwrap();
        }

        let result = verify_trace(path, &VerificationOptions::default()).unwrap();

        assert!(!result.is_valid());
        // Should have read some events before hitting corruption
        assert!(result.verified_events > 0);
        assert!(result.verified_events < 10);
    }

    // ── IntegrityIssue Display for all variants ────────────────────

    #[test]
    fn display_file_too_small() {
        let issue = IntegrityIssue::FileTooSmall {
            actual: 5,
            expected: 27,
        };
        let s = format!("{issue}");
        assert!(s.contains("5 bytes"));
        assert!(s.contains("at least 27"));
    }

    #[test]
    fn display_invalid_magic() {
        let issue = IntegrityIssue::InvalidMagic { found: [0; 11] };
        let s = format!("{issue}");
        assert!(s.contains("invalid magic"));
    }

    #[test]
    fn display_unsupported_version() {
        let issue = IntegrityIssue::UnsupportedVersion {
            found: 99,
            max_supported: 1,
        };
        let s = format!("{issue}");
        assert!(s.contains("99"));
        assert!(s.contains("max supported: 1"));
    }

    #[test]
    fn display_unsupported_flags() {
        let issue = IntegrityIssue::UnsupportedFlags { flags: 0xFF };
        let s = format!("{issue}");
        assert!(s.contains("flags"));
    }

    #[test]
    fn display_schema_mismatch() {
        let issue = IntegrityIssue::SchemaMismatch {
            found: 5,
            expected: 1,
        };
        let s = format!("{issue}");
        assert!(s.contains("found 5"));
        assert!(s.contains("expected 1"));
    }

    #[test]
    fn display_invalid_metadata() {
        let issue = IntegrityIssue::InvalidMetadata {
            message: "bad data".into(),
        };
        let s = format!("{issue}");
        assert!(s.contains("bad data"));
    }

    #[test]
    fn display_event_count_mismatch() {
        let issue = IntegrityIssue::EventCountMismatch {
            declared: 100,
            actual: 50,
        };
        let s = format!("{issue}");
        assert!(s.contains("declared 100"));
        assert!(s.contains("actual 50"));
    }

    #[test]
    fn display_invalid_event() {
        let issue = IntegrityIssue::InvalidEvent {
            index: 42,
            message: "corrupt".into(),
        };
        let s = format!("{issue}");
        assert!(s.contains("index 42"));
        assert!(s.contains("corrupt"));
    }

    #[test]
    fn display_truncated() {
        let issue = IntegrityIssue::Truncated { at_event: 7 };
        let s = format!("{issue}");
        assert!(s.contains("truncated"));
        assert!(s.contains("event 7"));
    }

    #[test]
    fn display_timeline_non_monotonic() {
        let issue = IntegrityIssue::TimelineNonMonotonic {
            at_event: 3,
            prev_time: 100,
            curr_time: 50,
        };
        let s = format!("{issue}");
        assert!(s.contains("event 3"));
        assert!(s.contains("100"));
        assert!(s.contains("50"));
    }

    #[test]
    fn display_io_error() {
        let issue = IntegrityIssue::IoError {
            message: "disk failure".into(),
        };
        let s = format!("{issue}");
        assert!(s.contains("disk failure"));
    }

    // ── Severity for all variants ──────────────────────────────────

    #[test]
    fn severity_fatal_variants() {
        let fatal = [
            IntegrityIssue::FileTooSmall {
                actual: 0,
                expected: 27,
            },
            IntegrityIssue::InvalidMagic { found: [0; 11] },
            IntegrityIssue::UnsupportedVersion {
                found: 99,
                max_supported: 1,
            },
            IntegrityIssue::InvalidMetadata {
                message: "bad".into(),
            },
        ];
        for issue in &fatal {
            assert_eq!(issue.severity(), IssueSeverity::Fatal, "for {issue}");
            assert!(issue.is_fatal(), "for {issue}");
        }
    }

    #[test]
    fn severity_error_variants() {
        let errors = [
            IntegrityIssue::UnsupportedFlags { flags: 0xFF },
            IntegrityIssue::SchemaMismatch {
                found: 5,
                expected: 1,
            },
            IntegrityIssue::EventCountMismatch {
                declared: 100,
                actual: 50,
            },
            IntegrityIssue::Truncated { at_event: 0 },
            IntegrityIssue::InvalidEvent {
                index: 0,
                message: "bad".into(),
            },
            IntegrityIssue::TimelineNonMonotonic {
                at_event: 0,
                prev_time: 100,
                curr_time: 50,
            },
            IntegrityIssue::IoError {
                message: "err".into(),
            },
        ];
        for issue in &errors {
            assert_eq!(issue.severity(), IssueSeverity::Error, "for {issue}");
            assert!(!issue.is_fatal(), "for {issue}");
        }
    }

    // ── IssueSeverity ordering ─────────────────────────────────────

    #[test]
    fn severity_ordering() {
        assert!(IssueSeverity::Warning < IssueSeverity::Error);
        assert!(IssueSeverity::Error < IssueSeverity::Fatal);
    }

    // ── VerificationOptions ────────────────────────────────────────

    #[test]
    fn options_default_values() {
        let opts = VerificationOptions::default();
        assert!(!opts.check_monotonicity);
        assert!(!opts.fail_fast);
        assert_eq!(opts.max_issues, 100);
        assert!(opts.verify_events);
    }

    #[test]
    fn options_quick_values() {
        let opts = VerificationOptions::quick();
        assert!(!opts.check_monotonicity);
        assert!(opts.fail_fast);
        assert_eq!(opts.max_issues, 1);
        assert!(!opts.verify_events);
    }

    #[test]
    fn options_strict_values() {
        let opts = VerificationOptions::strict();
        assert!(opts.check_monotonicity);
        assert!(!opts.fail_fast);
        assert_eq!(opts.max_issues, 1000);
        assert!(opts.verify_events);
    }

    #[test]
    fn options_with_monotonicity() {
        let opts = VerificationOptions::default().with_monotonicity(true);
        assert!(opts.check_monotonicity);
    }

    #[test]
    fn options_with_fail_fast() {
        let opts = VerificationOptions::default().with_fail_fast(true);
        assert!(opts.fail_fast);
    }

    // ── VerificationResult queries ─────────────────────────────────

    #[test]
    fn result_safe_event_count_zero_on_fatal() {
        let mut result = VerificationResult::new(100);
        result.verified_events = 50;
        result.add_issue(IntegrityIssue::InvalidMagic { found: [0; 11] });
        assert_eq!(result.safe_event_count(), 0);
    }

    #[test]
    fn result_safe_event_count_nonzero_without_fatal() {
        let mut result = VerificationResult::new(100);
        result.verified_events = 50;
        result.add_issue(IntegrityIssue::Truncated { at_event: 50 });
        assert_eq!(result.safe_event_count(), 50);
    }

    #[test]
    fn result_fatal_issues_iterator() {
        let mut result = VerificationResult::new(100);
        result.add_issue(IntegrityIssue::InvalidMagic { found: [0; 11] });
        result.add_issue(IntegrityIssue::Truncated { at_event: 0 });
        result.add_issue(IntegrityIssue::InvalidMetadata {
            message: "bad".into(),
        });

        assert_eq!(result.fatal_issues().count(), 2);
    }

    #[test]
    fn result_is_partially_usable_true() {
        let mut result = VerificationResult::new(100);
        result.verified_events = 50;
        result.add_issue(IntegrityIssue::Truncated { at_event: 50 });
        assert!(result.is_partially_usable());
    }

    #[test]
    fn result_is_partially_usable_false_on_fatal() {
        let mut result = VerificationResult::new(100);
        result.verified_events = 50;
        result.add_issue(IntegrityIssue::InvalidMagic { found: [0; 11] });
        assert!(!result.is_partially_usable());
    }

    #[test]
    fn result_is_partially_usable_false_on_zero_events() {
        let mut result = VerificationResult::new(100);
        result.verified_events = 0;
        result.add_issue(IntegrityIssue::Truncated { at_event: 0 });
        assert!(!result.is_partially_usable());
    }

    // ── Missing file ───────────────────────────────────────────────

    #[test]
    fn verify_missing_file_returns_io_error() {
        let result = verify_trace(
            "/tmp/definitely_not_a_real_trace_file_123456789.bin",
            &VerificationOptions::default(),
        );
        assert!(result.is_err());
    }

    // ── Quick verification on invalid file ─────────────────────────

    #[test]
    fn quick_invalid_file() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();
        std::fs::write(path, b"NOT A TRACE FILE - EXTRA PADDING!").unwrap();

        let is_valid = is_trace_valid_quick(path).unwrap();
        assert!(!is_valid);
    }

    // ── Display for valid and invalid result ───────────────────────

    #[test]
    fn display_valid_result() {
        let mut result = VerificationResult::new(500);
        result.verified_events = 10;
        let s = format!("{result}");
        assert!(s.contains("valid"));
        assert!(s.contains("10 events"));
        assert!(s.contains("500 bytes"));
    }

    #[test]
    fn display_invalid_result_multiple_issues() {
        let mut result = VerificationResult::new(500);
        result.declared_events = 100;
        result.verified_events = 50;
        result.add_issue(IntegrityIssue::Truncated { at_event: 50 });
        result.add_issue(IntegrityIssue::EventCountMismatch {
            declared: 100,
            actual: 50,
        });
        let s = format!("{result}");
        assert!(s.contains("2 issue(s)"));
        assert!(s.contains("50/100"));
    }

    // ── Strict verification on valid trace passes ──────────────────

    #[test]
    fn strict_verification_on_valid_monotonic_trace() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(50); // These are already monotonic (at_tick: i * 100)
        write_trace(path, &metadata, &events).unwrap();

        let result = verify_trace(path, &VerificationOptions::strict()).unwrap();
        assert!(result.is_valid());
        assert_eq!(result.verified_events, 50);
    }

    // ── Quick verification on valid trace skips events ──────────────

    #[test]
    fn quick_verification_skips_events() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(500);
        write_trace(path, &metadata, &events).unwrap();

        let result = verify_trace(path, &VerificationOptions::quick()).unwrap();
        // Quick doesn't verify events, so verified_events comes from count_events
        assert!(result.completed);
        assert!(!result.has_fatal_issues());
    }
}
