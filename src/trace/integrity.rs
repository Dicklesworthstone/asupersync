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
//! ```no_run
//! use asupersync::trace::integrity::{verify_trace, VerificationOptions};
//!
//! # fn check_trace() -> std::io::Result<()> {
//! // Verify a trace file
//! let result = verify_trace("trace.bin", &VerificationOptions::default())?;
//! if result.is_valid() {
//!     println!("Trace is valid with {} events", result.verified_events);
//! } else {
//!     for issue in result.issues() {
//!         eprintln!("Issue: {}", issue);
//!     }
//! }
//!
//! // Strict verification (includes timeline monotonicity)
//! let result = verify_trace("trace.bin", &VerificationOptions::strict())?;
//! # Ok(())
//! # }
//! ```

use super::file::{TRACE_FILE_VERSION, TraceFileError, TraceReader};
use super::replay::{ReplayEvent, TraceMetadata};
use std::fs::File;
use std::io::{self, Read};
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

    /// Current containers authenticate one complete canonical event stream, so
    /// a truncated prefix is not independently checksum-admitted.
    complete_stream_required: bool,
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
            complete_stream_required: false,
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
        !self.has_fatal_issues() && !self.completed && self.safe_event_count() > 0
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
        if self.has_fatal_issues() || (self.complete_stream_required && !self.completed) {
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
    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();

    let mut result = VerificationResult::new(file_size);

    // The smallest supported container is v1: magic + version + flags +
    // metadata length + event count. Later versions add header fields.
    const MIN_TRACE_FILE_SIZE: u64 = 11 + 2 + 2 + 4 + 8;
    let min_size = MIN_TRACE_FILE_SIZE;
    if file_size < min_size {
        result.add_issue(IntegrityIssue::FileTooSmall {
            actual: file_size,
            expected: min_size,
        });
        return Ok(result);
    }

    // Preserve the concrete invalid magic bytes for the diagnostic surface.
    let mut found_magic = [0u8; 11];
    file.read_exact(&mut found_magic)?;
    drop(file);

    let mut reader = match TraceReader::open(path) {
        Ok(reader) => reader,
        Err(error) => {
            let issue = match error {
                TraceFileError::InvalidMagic => IntegrityIssue::InvalidMagic { found: found_magic },
                TraceFileError::UnsupportedVersion { found, .. } => {
                    IntegrityIssue::UnsupportedVersion {
                        found,
                        max_supported: TRACE_FILE_VERSION,
                    }
                }
                TraceFileError::UnsupportedFlags(flags) => {
                    IntegrityIssue::UnsupportedFlags { flags }
                }
                TraceFileError::SchemaMismatch { found, expected } => {
                    IntegrityIssue::SchemaMismatch { found, expected }
                }
                metadata_error @ (TraceFileError::ChecksumMismatch {
                    section: "metadata",
                }
                | TraceFileError::Deserialize(_)
                | TraceFileError::OversizedField {
                    field: "meta_len", ..
                }) => IntegrityIssue::InvalidMetadata {
                    message: metadata_error.to_string(),
                },
                TraceFileError::Truncated => IntegrityIssue::Truncated { at_event: 0 },
                TraceFileError::Io(io_error) if io_error.kind() == io::ErrorKind::UnexpectedEof => {
                    IntegrityIssue::Truncated { at_event: 0 }
                }
                other => IntegrityIssue::IoError {
                    message: other.to_string(),
                },
            };
            result.add_issue(issue);
            return Ok(result);
        }
    };

    result.declared_events = reader.event_count();
    result.metadata = Some(reader.metadata().clone());
    result.complete_stream_required = reader.file_version() >= 3;

    // Quick mode validates the complete container header, metadata, schema, and
    // metadata digest. It intentionally does not scan the event stream.
    if !options.verify_events {
        result.completed = true;
        return Ok(result);
    }

    let mut prev_time: Option<u64> = None;
    while result.verified_events < result.declared_events
        && result.issues.len() < options.max_issues
    {
        match reader.read_event() {
            Ok(Some(event)) => {
                if options.check_monotonicity
                    && let Some(curr_time) = extract_timestamp(&event)
                {
                    if let Some(prev) = prev_time
                        && curr_time < prev
                    {
                        result.add_issue(IntegrityIssue::TimelineNonMonotonic {
                            at_event: result.verified_events,
                            prev_time: prev,
                            curr_time,
                        });
                        if options.fail_fast {
                            break;
                        }
                    }
                    prev_time = Some(curr_time);
                }
                result.verified_events += 1;
            }
            Ok(None) => break,
            Err(error) => {
                let issue = match error {
                    TraceFileError::Truncated => IntegrityIssue::Truncated {
                        at_event: result.verified_events,
                    },
                    TraceFileError::Io(io_error)
                        if io_error.kind() == io::ErrorKind::UnexpectedEof =>
                    {
                        IntegrityIssue::Truncated {
                            at_event: result.verified_events,
                        }
                    }
                    other => IntegrityIssue::InvalidEvent {
                        index: result.verified_events,
                        message: other.to_string(),
                    },
                };
                result.add_issue(issue);
                break;
            }
        }
    }

    if result.verified_events != result.declared_events
        && !result
            .issues
            .iter()
            .any(|issue| matches!(issue, IntegrityIssue::EventCountMismatch { .. }))
    {
        result.add_issue(IntegrityIssue::EventCountMismatch {
            declared: result.declared_events,
            actual: result.verified_events,
        });
    }

    result.completed = result.verified_events == result.declared_events;
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
    Ok(result.is_valid())
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
#[path = "integrity_inline_tests.rs"]
mod tests;
