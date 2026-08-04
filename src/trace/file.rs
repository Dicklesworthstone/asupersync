//! Trace file format for persisting and loading replay traces.
//!
//! This module provides a binary file format for saving traces to disk and
//! loading them for replay. The format is designed for:
//!
//! - **Compactness**: Uses MessagePack for efficient binary encoding
//! - **Versioning**: Format version in header for forward compatibility
//! - **Streaming**: Events can be read incrementally without loading all into memory
//! - **Compression**: Optional LZ4 compression for reduced storage (feature-gated)
//! - **Integrity**: Version 3 authenticates metadata and canonical event frames
//!   with SHA-256 before accepting a complete trace
//!
//! # File Format
//!
//! ```text
//! +-------------------+
//! | Magic (11 bytes)  |  "ASUPERTRACE"
//! +-------------------+
//! | Version (2 bytes) |  u16 little-endian
//! +-------------------+
//! | Flags (2 bytes)   |  u16 little-endian (bit 0 = compressed)
//! +-------------------+
//! | Compression (1 b) |  u8 (0=none, 1=lz4)
//! +-------------------+
//! | Meta len (4 bytes)|  u32 little-endian
//! +-------------------+
//! | Meta SHA-256 (32) |  digest of the MessagePack metadata bytes (v3)
//! +-------------------+
//! | Metadata (msgpack)|  TraceMetadata
//! +-------------------+
//! | Event count (8 b) |  u64 little-endian
//! +-------------------+
//! | Event SHA-256 (32)|  digest of canonical `len || msgpack` frames (v3)
//! +-------------------+
//! | Events (msgpack)  |  [ReplayEvent] length-prefixed (optionally compressed)
//! +-------------------+
//! ```
//!
//! Readers accept the legacy v1/v2 layouts and the current v3 layout. Writers
//! always emit v3. [`migrate_trace_file`] copies a legacy trace into a distinct,
//! non-existing v3 destination while preserving the source as a rollback
//! anchor. [`recover_trace_prefix`] returns only a contiguous, bounded prefix
//! and an explicit partial/limit receipt; it never skips a corrupt record.
//!
//! # Compression
//!
//! When compression is enabled (via the `trace-compression` feature), events are
//! compressed in chunks using LZ4 for efficient streaming compression/decompression.
//! Compression is auto-detected on read based on the flags in the header.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::trace::file::{TraceWriter, TraceReader, CompressionMode};
//! use asupersync::trace::replay::{ReplayEvent, TraceMetadata};
//!
//! // Writing a compressed trace
//! let config = TraceFileConfig::default().with_compression(CompressionMode::Lz4 { level: 1 });
//! let mut writer = TraceWriter::create_with_config("trace.bin", config)?;
//! writer.write_metadata(&TraceMetadata::new(42))?;
//! writer.write_event(&ReplayEvent::RngSeed { seed: 42 })?;
//! writer.finish()?;
//!
//! // Reading auto-detects compression
//! let reader = TraceReader::open("trace.bin")?;
//! println!("Seed: {}", reader.metadata().seed);
//! for event in reader.events() {
//!     let event = event?;
//!     println!("{:?}", event);
//! }
//! ```

use super::recorder::{DEFAULT_MAX_FILE_SIZE, LimitAction, LimitKind, LimitReached};
use super::replay::{REPLAY_SCHEMA_VERSION, ReplayEvent, TraceMetadata};
use crate::tracing_compat::{error, warn};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

// =============================================================================
// Constants
// =============================================================================

/// Magic bytes at the start of every trace file.
pub const TRACE_MAGIC: &[u8; 11] = b"ASUPERTRACE";

/// Current file format version.
///
/// Version 2 added the compression byte after flags. Version 3 adds SHA-256
/// digests for the metadata and the canonical uncompressed event-frame stream.
pub const TRACE_FILE_VERSION: u16 = 3;

/// Flag: Events are LZ4 compressed.
pub const FLAG_COMPRESSED: u16 = 0x0001;

/// Flag: metadata and event-stream SHA-256 digests are present.
pub const FLAG_CHECKSUMMED: u16 = 0x0002;

/// Width of each persisted SHA-256 digest.
pub const TRACE_CHECKSUM_LEN: usize = 32;

/// Header size through the metadata digest for the current format.
///
/// The metadata bytes, event count, event digest, and event frames follow.
pub const HEADER_SIZE: usize = 11 + 2 + 2 + 1 + 4 + TRACE_CHECKSUM_LEN;

/// Header size through metadata length for v2 files.
pub const LEGACY_HEADER_SIZE: usize = 11 + 2 + 2 + 1 + 4;
const SUPPORTED_FLAGS: u16 = FLAG_COMPRESSED | FLAG_CHECKSUMMED;

/// Default chunk size for streaming compression (64KB).
pub const DEFAULT_COMPRESSION_CHUNK_SIZE: usize = 64 * 1024;

/// Threshold for auto-compression (1MB).
pub const AUTO_COMPRESSION_THRESHOLD: usize = 1024 * 1024;

/// Maximum allowed metadata size when reading trace files (1 MiB).
///
/// Prevents OOM from a malicious or corrupt `meta_len` header field.
pub const MAX_META_LEN: usize = 1024 * 1024;

/// Maximum allowed event count for pre-allocation (10 million).
///
/// Prevents OOM from a malicious or corrupt `event_count` header field.
/// The reader can still iterate beyond this; only the initial
/// `Vec::with_capacity` call in `load_all` is bounded.
pub const MAX_EVENT_PREALLOC: usize = 10_000_000;

/// Maximum allowed single-event byte size (16 MiB).
///
/// No single serialized event should be larger than this. Prevents OOM
/// from a corrupt or malicious length prefix in the event stream.
pub const MAX_EVENT_LEN: usize = 16 * 1024 * 1024;

/// Maximum allowed compressed chunk size (64 MiB).
///
/// Compressed chunks should not exceed this before decompression.
pub const MAX_COMPRESSED_CHUNK_LEN: usize = 64 * 1024 * 1024;

#[cfg(unix)]
const DISK_FULL_OS_ERROR: i32 = 28;

#[cfg(windows)]
const DISK_FULL_OS_ERROR: i32 = 112;

fn is_disk_full_os_error(code: Option<i32>) -> bool {
    #[cfg(unix)]
    {
        code == Some(DISK_FULL_OS_ERROR)
    }

    #[cfg(windows)]
    {
        code == Some(DISK_FULL_OS_ERROR)
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = code;
        false
    }
}

fn validate_event_len(len: usize) -> TraceFileResult<()> {
    if len > MAX_EVENT_LEN {
        return Err(TraceFileError::OversizedField {
            field: "event_len",
            actual: len as u64,
            max: MAX_EVENT_LEN as u64,
        });
    }

    Ok(())
}

fn sha256(bytes: &[u8]) -> [u8; TRACE_CHECKSUM_LEN] {
    Sha256::digest(bytes).into()
}

fn verify_checksum(
    section: &'static str,
    expected: &[u8; TRACE_CHECKSUM_LEN],
    actual: &[u8; TRACE_CHECKSUM_LEN],
) -> TraceFileResult<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(TraceFileError::ChecksumMismatch { section })
    }
}

fn truncated_or_io(err: io::Error) -> TraceFileError {
    if err.kind() == io::ErrorKind::UnexpectedEof {
        TraceFileError::Truncated
    } else {
        TraceFileError::Io(err)
    }
}

// =============================================================================
// Compression Types
// =============================================================================

/// Compression mode for trace files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompressionMode {
    /// No compression.
    #[default]
    None,

    /// LZ4 compression with configurable level.
    ///
    /// Level ranges from -1 (fast) to 16 (best compression).
    /// Default level is 1 which provides good balance.
    #[cfg(feature = "trace-compression")]
    Lz4 {
        /// Compression level (-1 to 16, default 1).
        level: i32,
    },

    /// Auto-select compression based on trace size.
    ///
    /// Compresses if estimated size exceeds 1MB.
    #[cfg(feature = "trace-compression")]
    Auto,
}

impl CompressionMode {
    /// Returns true if this mode enables compression.
    #[must_use]
    pub fn is_compressed(&self) -> bool {
        match self {
            Self::None => false,
            #[cfg(feature = "trace-compression")]
            Self::Lz4 { .. } | Self::Auto => true,
        }
    }

    /// Returns the compression byte for the file header.
    fn to_byte(self) -> u8 {
        match self {
            Self::None => 0,
            #[cfg(feature = "trace-compression")]
            Self::Lz4 { .. } | Self::Auto => 1,
        }
    }

    /// Creates a compression mode from the header byte.
    #[allow(dead_code)]
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::None),
            #[cfg(feature = "trace-compression")]
            1 => Some(Self::Lz4 { level: 1 }),
            #[cfg(not(feature = "trace-compression"))]
            1 => None, // Compressed but feature not enabled
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lz4Codec {
    Incumbent,
    #[cfg(all(feature = "trace-compression", feature = "test-internals"))]
    Owned,
}

#[cfg(feature = "trace-compression")]
impl Lz4Codec {
    fn encode(self, input: &[u8]) -> TraceFileResult<Vec<u8>> {
        match self {
            Self::Incumbent => Ok(lz4_flex::compress_prepend_size(input)),
            #[cfg(feature = "test-internals")]
            Self::Owned => {
                super::lz4_block::encode_size_prepended(input, super::lz4_block::Limits::TRACE)
                    .map_err(|error| TraceFileError::Compression(error.to_string()))
            }
        }
    }

    fn decode(self, input: &[u8]) -> TraceFileResult<Vec<u8>> {
        match self {
            Self::Incumbent => lz4_flex::decompress_size_prepended(input)
                .map_err(|error| TraceFileError::Decompression(error.to_string())),
            #[cfg(feature = "test-internals")]
            Self::Owned => {
                super::lz4_block::decode_size_prepended(input, super::lz4_block::Limits::TRACE)
                    .map_err(|error| TraceFileError::Decompression(error.to_string()))
            }
        }
    }
}

/// Configuration for trace file operations.
#[derive(Debug, Clone)]
pub struct TraceFileConfig {
    /// Compression mode for writing.
    pub compression: CompressionMode,

    /// Chunk size for streaming compression (default: 64KB).
    pub chunk_size: usize,

    /// Maximum events to write before stopping.
    /// Default: None (unlimited).
    pub max_events: Option<u64>,

    /// Maximum file size for trace file.
    /// Default: 1GB.
    pub max_file_size: u64,

    /// Action when limit reached.
    pub on_limit: LimitAction,
}

impl Default for TraceFileConfig {
    fn default() -> Self {
        Self {
            compression: CompressionMode::None,
            chunk_size: DEFAULT_COMPRESSION_CHUNK_SIZE,
            max_events: None,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            on_limit: LimitAction::StopRecording,
        }
    }
}

impl TraceFileConfig {
    /// Creates a new config with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the compression mode.
    #[must_use]
    pub fn with_compression(mut self, mode: CompressionMode) -> Self {
        self.compression = mode;
        self
    }

    /// Sets the chunk size for streaming compression.
    #[must_use]
    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    /// Sets a maximum number of events to write.
    #[must_use]
    pub const fn with_max_events(mut self, max_events: Option<u64>) -> Self {
        self.max_events = max_events;
        self
    }

    /// Sets a maximum file size for the trace file.
    #[must_use]
    pub const fn with_max_file_size(mut self, max_file_size: u64) -> Self {
        self.max_file_size = max_file_size;
        self
    }

    /// Sets the limit action policy.
    #[must_use]
    pub fn on_limit(mut self, action: LimitAction) -> Self {
        self.on_limit = action;
        self
    }
}

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur when working with trace files.
#[derive(Debug, thiserror::Error)]
pub enum TraceFileError {
    /// I/O error during file operations.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Invalid magic bytes in file header.
    #[error("invalid magic bytes: not a trace file")]
    InvalidMagic,

    /// Unsupported file format version.
    #[error("unsupported file version: expected 1..={expected}, found {found}")]
    UnsupportedVersion {
        /// Maximum supported version.
        expected: u16,
        /// Found version.
        found: u16,
    },

    /// Unsupported flags in header.
    #[error("unsupported flags: {0:#06x}")]
    UnsupportedFlags(u16),

    /// Unsupported compression format.
    #[error("unsupported compression format: {0}")]
    UnsupportedCompression(u8),

    /// Compression not available (feature not enabled).
    #[error("file is compressed but trace-compression feature is not enabled")]
    CompressionNotAvailable,

    /// Compression error.
    #[error("compression error: {0}")]
    Compression(String),

    /// Decompression error.
    #[error("decompression error: {0}")]
    Decompression(String),

    /// Error serializing data.
    #[error("serialization error: {0}")]
    Serialize(String),

    /// Error deserializing data.
    #[error("deserialization error: {0}")]
    Deserialize(String),

    /// Metadata mismatch (schema version).
    #[error("schema version mismatch: expected {expected}, found {found}")]
    SchemaMismatch {
        /// Expected schema version.
        expected: u32,
        /// Found schema version.
        found: u32,
    },

    /// Writer already finished.
    #[error("writer already finished")]
    AlreadyFinished,

    /// Metadata was not written before attempting to write events or finish.
    #[error("trace metadata must be written before events or finish")]
    MetadataNotWritten,

    /// Metadata was already written for this trace writer.
    #[error("trace metadata can only be written once")]
    MetadataAlreadyWritten,

    /// Metadata writing failed mid-header and left the file unusable.
    #[error("trace metadata write did not complete; discard and recreate the writer")]
    MetadataCorrupt,

    /// File is truncated or corrupt.
    #[error("file truncated or corrupt")]
    Truncated,

    /// A length prefix exceeds the allowed maximum.
    #[error("length prefix too large: {field} is {actual} bytes, max is {max}")]
    OversizedField {
        /// Which field was too large.
        field: &'static str,
        /// Actual value read.
        actual: u64,
        /// Maximum allowed.
        max: u64,
    },

    /// A persisted integrity digest does not match the decoded bytes.
    #[error("{section} checksum mismatch")]
    ChecksumMismatch {
        /// Logical section whose digest failed.
        section: &'static str,
    },

    /// Migration input and output resolve to the same path.
    #[error("trace migration input and output must differ")]
    MigrationInputOutputSame,

    /// Migration destination already exists and will not be overwritten.
    #[error("trace migration destination already exists")]
    MigrationDestinationExists,

    /// The source already uses the current trace container version.
    #[error("trace already uses current file version {version}")]
    MigrationAlreadyCurrent {
        /// Current container version.
        version: u16,
    },
}

impl From<rmp_serde::encode::Error> for TraceFileError {
    fn from(e: rmp_serde::encode::Error) -> Self {
        Self::Serialize(e.to_string())
    }
}

impl From<rmp_serde::decode::Error> for TraceFileError {
    fn from(e: rmp_serde::decode::Error) -> Self {
        Self::Deserialize(e.to_string())
    }
}

/// Result type for trace file operations.
pub type TraceFileResult<T> = Result<T, TraceFileError>;

// =============================================================================
// TraceWriter
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraceWriterMetadataState {
    Pending,
    Written,
    Corrupt,
}

/// Writer for streaming trace events to a file.
///
/// Events are written incrementally, allowing large traces to be written
/// without holding all events in memory. When compression is enabled,
/// events are buffered and compressed in chunks.
///
/// # Example
///
/// ```ignore
/// let mut writer = TraceWriter::create("trace.bin")?;
/// writer.write_metadata(&TraceMetadata::new(42))?;
/// for event in events {
///     writer.write_event(&event)?;
/// }
/// writer.finish()?;
/// ```
pub struct TraceWriter {
    writer: BufWriter<File>,
    event_count: u64,
    event_count_pos: u64,
    event_digest_pos: u64,
    event_hasher: Sha256,
    finished: bool,
    metadata_state: TraceWriterMetadataState,
    config: TraceFileConfig,
    bytes_written: u64,
    buffered_bytes: u64,
    stopped: bool,
    halted: bool,
    #[cfg(feature = "trace-compression")]
    lz4_codec: Lz4Codec,
    /// Buffer for uncompressed event data (used in chunked compression).
    #[cfg(feature = "trace-compression")]
    event_buffer: Vec<u8>,
}

impl TraceWriter {
    /// Creates a new trace file for writing with default configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be created.
    pub fn create(path: impl AsRef<Path>) -> TraceFileResult<Self> {
        Self::create_with_config(path, TraceFileConfig::default())
    }

    /// Creates a new trace file for writing with custom configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be created.
    pub fn create_with_config(
        path: impl AsRef<Path>,
        config: TraceFileConfig,
    ) -> TraceFileResult<Self> {
        let file = File::create(path)?;
        Ok(Self::from_file(file, config))
    }

    fn from_file(file: File, config: TraceFileConfig) -> Self {
        Self::from_file_with_lz4_codec(file, config, Lz4Codec::Incumbent)
    }

    fn from_file_with_lz4_codec(file: File, config: TraceFileConfig, lz4_codec: Lz4Codec) -> Self {
        #[cfg(not(feature = "trace-compression"))]
        let _ = lz4_codec;
        let writer = BufWriter::new(file);

        Self {
            writer,
            event_count: 0,
            event_count_pos: 0,
            event_digest_pos: 0,
            event_hasher: Sha256::new(),
            finished: false,
            metadata_state: TraceWriterMetadataState::Pending,
            config,
            bytes_written: 0,
            buffered_bytes: 0,
            stopped: false,
            halted: false,
            #[cfg(feature = "trace-compression")]
            lz4_codec,
            #[cfg(feature = "trace-compression")]
            event_buffer: Vec::new(),
        }
    }

    fn should_write(&self) -> bool {
        !self.stopped && !self.halted
    }

    fn resolve_limit_action(&self, info: &LimitReached) -> LimitAction {
        match &self.config.on_limit {
            LimitAction::Callback(cb) => (cb)(info.clone()),
            other => other.clone(),
        }
    }

    fn handle_limit(&mut self, info: &LimitReached) -> TraceFileResult<bool> {
        let mut action = self.resolve_limit_action(info);
        if matches!(action, LimitAction::Callback(_)) {
            action = LimitAction::StopRecording;
        }

        match action {
            LimitAction::StopRecording => {
                warn!(
                    kind = ?info.kind,
                    current_events = info.current_events,
                    max_events = ?info.max_events,
                    current_bytes = info.current_bytes,
                    max_bytes = info.max_bytes,
                    "trace write stopped: limit reached"
                );
                self.stopped = true;
                Ok(false)
            }
            LimitAction::DropOldest => {
                warn!(
                    kind = ?info.kind,
                    "trace write stopped: drop-oldest not supported for file writer"
                );
                self.stopped = true;
                Ok(false)
            }
            LimitAction::Fail => {
                error!(
                    kind = ?info.kind,
                    current_events = info.current_events,
                    max_events = ?info.max_events,
                    current_bytes = info.current_bytes,
                    max_bytes = info.max_bytes,
                    "trace write failed: limit exceeded"
                );
                self.stopped = true;
                Err(TraceFileError::Io(io::Error::other(
                    "trace write limit exceeded",
                )))
            }
            LimitAction::Callback(_) => {
                self.stopped = true;
                Ok(false)
            }
        }
    }

    fn is_disk_full(err: &io::Error) -> bool {
        is_disk_full_os_error(err.raw_os_error())
    }

    fn handle_disk_full(&mut self, err: io::Error) -> TraceFileError {
        warn!("trace write halted: disk full (ENOSPC). Free space and retry recording.");
        self.halted = true;
        TraceFileError::Io(err)
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> TraceFileResult<()> {
        if self.halted {
            return Ok(());
        }
        match self.writer.write_all(bytes) {
            Ok(()) => {
                self.bytes_written = self.bytes_written.saturating_add(bytes.len() as u64);
                Ok(())
            }
            Err(err) if Self::is_disk_full(&err) => Err(self.handle_disk_full(err)),
            Err(err) => Err(TraceFileError::Io(err)),
        }
    }

    fn update_integrity_header(&mut self) -> TraceFileResult<()> {
        self.writer.seek(SeekFrom::Start(self.event_count_pos))?;
        self.writer.write_all(&self.event_count.to_le_bytes())?;
        self.writer.seek(SeekFrom::Start(self.event_digest_pos))?;
        let digest: [u8; TRACE_CHECKSUM_LEN] = self.event_hasher.clone().finalize().into();
        self.writer.write_all(&digest)?;
        self.writer.flush()?;
        Ok(())
    }

    fn update_integrity_header_best_effort(&mut self) {
        if let Err(err) = self.update_integrity_header() {
            if matches!(
                &err,
                TraceFileError::Io(io_err) if Self::is_disk_full(io_err)
            ) {
                warn!("trace event count update skipped: disk full");
            }
            warn!("trace integrity header update skipped: {err}");
        }
    }

    fn ensure_metadata_written(&self) -> TraceFileResult<()> {
        match self.metadata_state {
            TraceWriterMetadataState::Pending => Err(TraceFileError::MetadataNotWritten),
            TraceWriterMetadataState::Written => Ok(()),
            TraceWriterMetadataState::Corrupt => Err(TraceFileError::MetadataCorrupt),
        }
    }

    /// Writes the trace metadata (must be called first).
    ///
    /// This writes the file header including magic bytes, version,
    /// flags, compression mode, and the serialized metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails or the writer was already finished.
    pub fn write_metadata(&mut self, metadata: &TraceMetadata) -> TraceFileResult<()> {
        if self.finished {
            return Err(TraceFileError::AlreadyFinished);
        }
        match self.metadata_state {
            TraceWriterMetadataState::Pending => {}
            TraceWriterMetadataState::Written => {
                return Err(TraceFileError::MetadataAlreadyWritten);
            }
            TraceWriterMetadataState::Corrupt => {
                return Err(TraceFileError::MetadataCorrupt);
            }
        }

        // Serialize metadata to get its length
        let meta_bytes = rmp_serde::to_vec(metadata)?;
        if meta_bytes.len() > MAX_META_LEN {
            return Err(TraceFileError::OversizedField {
                field: "meta_len",
                actual: meta_bytes.len() as u64,
                max: MAX_META_LEN as u64,
            });
        }

        // Determine flags
        let flags = FLAG_CHECKSUMMED
            | if self.config.compression.is_compressed() {
                FLAG_COMPRESSED
            } else {
                0
            };

        // Once header emission starts, a failure leaves the file in a partial
        // state. Poison the writer so callers do not append events to a broken
        // trace blob.
        self.metadata_state = TraceWriterMetadataState::Corrupt;

        // Write header
        self.write_bytes(TRACE_MAGIC)?;
        self.write_bytes(&TRACE_FILE_VERSION.to_le_bytes())?;
        self.write_bytes(&flags.to_le_bytes())?;
        self.write_bytes(&[self.config.compression.to_byte()])?; // compression byte

        // Write metadata length and data
        let meta_len = u32::try_from(meta_bytes.len()).map_err(|_| {
            TraceFileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "metadata too large for trace format: {} bytes exceeds u32::MAX",
                    meta_bytes.len()
                ),
            ))
        })?;
        self.write_bytes(&meta_len.to_le_bytes())?;
        self.write_bytes(&sha256(&meta_bytes))?;
        self.write_bytes(&meta_bytes)?;

        // Reserve event-count and event-digest slots; finish() backpatches both.
        self.event_count_pos = HEADER_SIZE as u64 + u64::from(meta_len);
        self.write_bytes(&0u64.to_le_bytes())?;
        self.event_digest_pos = self.event_count_pos + 8;
        self.write_bytes(&[0u8; TRACE_CHECKSUM_LEN])?;
        self.metadata_state = TraceWriterMetadataState::Written;

        Ok(())
    }

    /// Writes a single replay event.
    ///
    /// Events are length-prefixed for streaming reads. When compression is
    /// enabled, events are buffered and written in compressed chunks.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or writing fails.
    pub fn write_event(&mut self, event: &ReplayEvent) -> TraceFileResult<()> {
        if self.finished {
            return Err(TraceFileError::AlreadyFinished);
        }
        self.ensure_metadata_written()?;
        if !self.should_write() {
            return Ok(());
        }

        if let Some(max_events) = self.config.max_events {
            if self.event_count.saturating_add(1) > max_events {
                let info = LimitReached {
                    kind: LimitKind::MaxEvents,
                    current_events: self.event_count,
                    max_events: Some(max_events),
                    current_bytes: self.bytes_written,
                    max_bytes: self.config.max_file_size,
                    needed_bytes: 0,
                };
                if !self.handle_limit(&info)? {
                    return Ok(());
                }
            }
        }

        // Serialize event with length prefix
        let event_bytes = rmp_serde::to_vec(event)?;
        validate_event_len(event_bytes.len())?;
        let len = u32::try_from(event_bytes.len()).map_err(|_| {
            TraceFileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "serialized event too large for trace format: {} bytes exceeds u32::MAX",
                    event_bytes.len()
                ),
            ))
        })?;
        let estimated_bytes = 4u64 + event_bytes.len() as u64;
        let pending_bytes = self.bytes_written.saturating_add(self.buffered_bytes);

        if self.config.max_file_size > 0
            && pending_bytes.saturating_add(estimated_bytes) > self.config.max_file_size
        {
            let info = LimitReached {
                kind: LimitKind::MaxFileSize,
                current_events: self.event_count,
                max_events: self.config.max_events,
                current_bytes: pending_bytes,
                max_bytes: self.config.max_file_size,
                needed_bytes: estimated_bytes,
            };
            if !self.handle_limit(&info)? {
                return Ok(());
            }
        }

        self.event_hasher.update(len.to_le_bytes());
        self.event_hasher.update(&event_bytes);

        #[cfg(feature = "trace-compression")]
        if self.config.compression.is_compressed() {
            // Buffer the event for chunk compression
            self.event_buffer.extend_from_slice(&len.to_le_bytes());
            self.event_buffer.extend_from_slice(&event_bytes);
            self.buffered_bytes = self.buffered_bytes.saturating_add(estimated_bytes);
            self.event_count += 1;

            // Flush chunk if buffer exceeds threshold
            if self.event_buffer.len() >= self.config.chunk_size {
                self.flush_compressed_chunk()?;
            }
            return Ok(());
        }

        // Uncompressed: write directly
        self.write_bytes(&len.to_le_bytes())?;
        self.write_bytes(&event_bytes)?;
        self.event_count += 1;
        Ok(())
    }

    /// Flushes a compressed chunk of events to the file.
    #[cfg(feature = "trace-compression")]
    fn flush_compressed_chunk(&mut self) -> TraceFileResult<()> {
        if self.event_buffer.is_empty() {
            return Ok(());
        }

        // Compress the buffer through the selected integration backend.
        let compressed = self.lz4_codec.encode(&self.event_buffer)?;

        // Write chunk: compressed_len (u32) + compressed_data
        let chunk_len = u32::try_from(compressed.len()).map_err(|_| {
            TraceFileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "compressed chunk too large for trace format: {} bytes exceeds u32::MAX",
                    compressed.len()
                ),
            ))
        })?;
        self.write_bytes(&chunk_len.to_le_bytes())?;
        self.write_bytes(&compressed)?;

        self.event_buffer.clear();
        self.buffered_bytes = 0;
        Ok(())
    }

    /// Finishes writing the trace file.
    ///
    /// This flushes any remaining compressed data, updates the event count
    /// in the header, and flushes all data. Must be called to complete the
    /// file properly.
    ///
    /// # Errors
    ///
    /// Returns an error if flushing or seeking fails.
    pub fn finish(mut self) -> TraceFileResult<()> {
        self.ensure_metadata_written()?;
        self.finished = true;

        // Flush any remaining compressed data
        #[cfg(feature = "trace-compression")]
        if self.config.compression.is_compressed() {
            self.flush_compressed_chunk()?;
        }

        if self.halted {
            let _ = self.writer.flush();
            self.update_integrity_header_best_effort();
            return Ok(());
        }

        // Flush buffered data
        self.writer.flush()?;

        // Seek back and update event count and stream digest.
        self.update_integrity_header()?;

        Ok(())
    }

    /// Returns the number of events written so far.
    #[must_use]
    pub fn event_count(&self) -> u64 {
        self.event_count
    }
}

impl Drop for TraceWriter {
    fn drop(&mut self) {
        if !self.finished {
            #[cfg(feature = "trace-compression")]
            if self.config.compression.is_compressed() {
                let _ = self.flush_compressed_chunk();
            }

            // Best-effort: try to flush but don't panic
            let _ = self.writer.flush();
            if self.metadata_state == TraceWriterMetadataState::Written {
                self.update_integrity_header_best_effort();
            }
        }
    }
}

// =============================================================================
// TraceReader
// =============================================================================

/// Reader for loading trace files.
///
/// Supports streaming reads where events are loaded incrementally.
/// Compression is auto-detected from the file header.
///
/// # Example
///
/// ```ignore
/// let reader = TraceReader::open("trace.bin")?;
/// println!("Seed: {}", reader.metadata().seed);
/// println!("Events: {}", reader.event_count());
/// println!("Compressed: {}", reader.is_compressed());
///
/// for event in reader.events() {
///     let event = event?;
///     println!("{:?}", event);
/// }
/// ```
#[derive(Debug)]
pub struct TraceReader {
    reader: BufReader<File>,
    file_version: u16,
    metadata: TraceMetadata,
    event_count: u64,
    events_read: u64,
    events_start_pos: u64,
    compression: CompressionMode,
    expected_event_digest: Option<[u8; TRACE_CHECKSUM_LEN]>,
    event_hasher: Sha256,
    #[cfg(feature = "trace-compression")]
    lz4_codec: Lz4Codec,
    /// Buffer for decompressed event data.
    #[cfg(feature = "trace-compression")]
    decompressed_buffer: Vec<u8>,
    /// Position in decompressed buffer.
    #[cfg(feature = "trace-compression")]
    buffer_pos: usize,
}

impl TraceReader {
    /// Opens a trace file for reading.
    ///
    /// Compression is auto-detected from the file header.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be opened
    /// - The file has invalid magic bytes
    /// - The file version is unsupported
    /// - The file is compressed but the `trace-compression` feature is not enabled
    /// - The metadata is corrupt
    pub fn open(path: impl AsRef<Path>) -> TraceFileResult<Self> {
        Self::open_with_lz4_codec(path, Lz4Codec::Incumbent)
    }

    fn open_with_lz4_codec(path: impl AsRef<Path>, lz4_codec: Lz4Codec) -> TraceFileResult<Self> {
        #[cfg(not(feature = "trace-compression"))]
        let _ = lz4_codec;
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);

        // Read and validate magic
        let mut magic = [0u8; 11];
        reader.read_exact(&mut magic)?;
        if &magic != TRACE_MAGIC {
            return Err(TraceFileError::InvalidMagic);
        }

        // Read version
        let mut version_bytes = [0u8; 2];
        reader.read_exact(&mut version_bytes)?;
        let version = u16::from_le_bytes(version_bytes);
        if !(1..=TRACE_FILE_VERSION).contains(&version) {
            return Err(TraceFileError::UnsupportedVersion {
                expected: TRACE_FILE_VERSION,
                found: version,
            });
        }

        // Read flags
        let mut flags_bytes = [0u8; 2];
        reader.read_exact(&mut flags_bytes)?;
        let flags = u16::from_le_bytes(flags_bytes);
        let is_compressed = flags & FLAG_COMPRESSED != 0;
        let supported_flags = if version >= 3 {
            SUPPORTED_FLAGS
        } else {
            FLAG_COMPRESSED
        };
        if flags & !supported_flags != 0 || (version >= 3 && flags & FLAG_CHECKSUMMED == 0) {
            return Err(TraceFileError::UnsupportedFlags(flags));
        }

        // Read compression byte (only in version 2+)
        let compression = if version >= 2 {
            let mut comp_byte = [0u8; 1];
            reader.read_exact(&mut comp_byte)?;
            if !is_compressed && comp_byte[0] != 0 {
                return Err(TraceFileError::UnsupportedCompression(comp_byte[0]));
            }
            if is_compressed && comp_byte[0] == 0 {
                return Err(TraceFileError::UnsupportedFlags(flags));
            }
            match CompressionMode::from_byte(comp_byte[0]) {
                Some(mode) => mode,
                None if comp_byte[0] == 1 && is_compressed => {
                    return Err(TraceFileError::CompressionNotAvailable);
                }
                None if is_compressed => {
                    return Err(TraceFileError::UnsupportedCompression(comp_byte[0]));
                }
                None => CompressionMode::None,
            }
        } else {
            // Version 1 files don't have compression byte
            if is_compressed {
                return Err(TraceFileError::UnsupportedFlags(flags));
            }
            CompressionMode::None
        };
        if compression.is_compressed() != is_compressed {
            return Err(TraceFileError::UnsupportedFlags(flags));
        }

        // Check if we can handle compression
        #[cfg(not(feature = "trace-compression"))]
        if compression.is_compressed() {
            return Err(TraceFileError::CompressionNotAvailable);
        }

        // Read metadata length
        let mut meta_len_bytes = [0u8; 4];
        reader.read_exact(&mut meta_len_bytes)?;
        let meta_len = u32::from_le_bytes(meta_len_bytes) as usize;

        // Guard against oversized metadata (DoS mitigation — issues #8, #10)
        if meta_len > MAX_META_LEN {
            return Err(TraceFileError::OversizedField {
                field: "meta_len",
                actual: meta_len as u64,
                max: MAX_META_LEN as u64,
            });
        }

        let expected_metadata_digest = if version >= 3 {
            let mut digest = [0u8; TRACE_CHECKSUM_LEN];
            reader.read_exact(&mut digest).map_err(truncated_or_io)?;
            Some(digest)
        } else {
            None
        };

        // Read metadata
        let mut meta_bytes = vec![0u8; meta_len];
        reader
            .read_exact(&mut meta_bytes)
            .map_err(truncated_or_io)?;
        if let Some(expected) = expected_metadata_digest {
            verify_checksum("metadata", &expected, &sha256(&meta_bytes))?;
        }
        let metadata: TraceMetadata = rmp_serde::from_slice(&meta_bytes)?;

        // Validate schema version
        if metadata.version != REPLAY_SCHEMA_VERSION {
            return Err(TraceFileError::SchemaMismatch {
                expected: REPLAY_SCHEMA_VERSION,
                found: metadata.version,
            });
        }

        // Read event count
        let mut event_count_bytes = [0u8; 8];
        reader.read_exact(&mut event_count_bytes)?;
        let event_count = u64::from_le_bytes(event_count_bytes);

        let expected_event_digest = if version >= 3 {
            let mut digest = [0u8; TRACE_CHECKSUM_LEN];
            reader.read_exact(&mut digest).map_err(truncated_or_io)?;
            Some(digest)
        } else {
            None
        };
        let events_start_pos = reader.stream_position()?;

        if event_count == 0 {
            if let Some(expected) = expected_event_digest {
                verify_checksum("event stream", &expected, &sha256(&[]))?;
            }
        }

        Ok(Self {
            reader,
            file_version: version,
            metadata,
            event_count,
            events_read: 0,
            events_start_pos,
            compression,
            expected_event_digest,
            event_hasher: Sha256::new(),
            #[cfg(feature = "trace-compression")]
            lz4_codec,
            #[cfg(feature = "trace-compression")]
            decompressed_buffer: Vec::new(),
            #[cfg(feature = "trace-compression")]
            buffer_pos: 0,
        })
    }

    /// Returns true if the trace file is compressed.
    #[must_use]
    pub fn is_compressed(&self) -> bool {
        self.compression.is_compressed()
    }

    /// Returns the persisted container version.
    #[must_use]
    pub const fn file_version(&self) -> u16 {
        self.file_version
    }

    /// Returns the compression mode of the trace file.
    #[must_use]
    pub fn compression(&self) -> CompressionMode {
        self.compression
    }

    /// Returns the trace metadata.
    #[must_use]
    pub fn metadata(&self) -> &TraceMetadata {
        &self.metadata
    }

    /// Returns the total number of events in the trace.
    #[must_use]
    pub fn event_count(&self) -> u64 {
        self.event_count
    }

    /// Returns the number of events read so far.
    #[must_use]
    pub fn events_read(&self) -> u64 {
        self.events_read
    }

    /// Returns an iterator over the events in the trace.
    ///
    /// Events are read incrementally from the file.
    /// Automatically handles decompression for compressed files.
    #[must_use]
    pub fn events(self) -> TraceEventIterator {
        TraceEventIterator {
            reader: self.reader,
            remaining: self.event_count,
            compression: self.compression,
            expected_event_digest: self.expected_event_digest,
            event_hasher: self.event_hasher,
            #[cfg(feature = "trace-compression")]
            lz4_codec: self.lz4_codec,
            #[cfg(feature = "trace-compression")]
            decompressed_buffer: self.decompressed_buffer,
            #[cfg(feature = "trace-compression")]
            buffer_pos: self.buffer_pos,
        }
    }

    /// Reads the next event from the trace.
    ///
    /// Returns `None` when all events have been read.
    /// Automatically handles decompression for compressed files.
    ///
    /// # Errors
    ///
    /// Returns an error if reading or deserialization fails.
    pub fn read_event(&mut self) -> TraceFileResult<Option<ReplayEvent>> {
        if self.events_read >= self.event_count {
            return Ok(None);
        }

        #[cfg(feature = "trace-compression")]
        if self.compression.is_compressed() {
            return self.read_compressed_event();
        }

        // Uncompressed read
        self.read_uncompressed_event()
    }

    /// Reads an event from uncompressed data.
    fn read_uncompressed_event(&mut self) -> TraceFileResult<Option<ReplayEvent>> {
        // Read event length
        let mut len_bytes = [0u8; 4];
        self.reader
            .read_exact(&mut len_bytes)
            .map_err(truncated_or_io)?;
        let len = u32::from_le_bytes(len_bytes) as usize;

        // Guard against oversized event length (DoS mitigation — issues #8, #10)
        validate_event_len(len)?;

        // Read event data
        let mut event_bytes = vec![0u8; len];
        self.reader
            .read_exact(&mut event_bytes)
            .map_err(truncated_or_io)?;

        let event: ReplayEvent = rmp_serde::from_slice(&event_bytes)?;
        self.event_hasher.update(len_bytes);
        self.event_hasher.update(&event_bytes);
        if self.events_read.saturating_add(1) == self.event_count {
            self.verify_event_stream_checksum()?;
        }
        self.events_read += 1;

        Ok(Some(event))
    }

    /// Reads an event from compressed data.
    #[cfg(feature = "trace-compression")]
    fn read_compressed_event(&mut self) -> TraceFileResult<Option<ReplayEvent>> {
        // Refill buffer if needed
        if self.buffer_pos >= self.decompressed_buffer.len() {
            self.refill_decompressed_buffer()?;
        }

        // Read event length from buffer
        if self.buffer_pos + 4 > self.decompressed_buffer.len() {
            return Err(TraceFileError::Truncated);
        }
        let len_bytes: [u8; 4] = self.decompressed_buffer[self.buffer_pos..self.buffer_pos + 4]
            .try_into()
            .map_err(|_| TraceFileError::Truncated)?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        validate_event_len(len)?;
        self.buffer_pos += 4;

        // Read event data from buffer
        if self.buffer_pos + len > self.decompressed_buffer.len() {
            return Err(TraceFileError::Truncated);
        }
        let event_bytes = &self.decompressed_buffer[self.buffer_pos..self.buffer_pos + len];
        let event: ReplayEvent = rmp_serde::from_slice(event_bytes)?;
        self.event_hasher.update(len_bytes);
        self.event_hasher.update(event_bytes);
        if self.events_read.saturating_add(1) == self.event_count {
            self.verify_event_stream_checksum()?;
        }
        self.buffer_pos += len;

        self.events_read += 1;
        Ok(Some(event))
    }

    fn verify_event_stream_checksum(&self) -> TraceFileResult<()> {
        if let Some(expected) = self.expected_event_digest {
            let actual: [u8; TRACE_CHECKSUM_LEN] = self.event_hasher.clone().finalize().into();
            verify_checksum("event stream", &expected, &actual)?;
        }
        Ok(())
    }

    /// Refills the decompressed buffer from the next compressed chunk.
    #[cfg(feature = "trace-compression")]
    fn refill_decompressed_buffer(&mut self) -> TraceFileResult<()> {
        // Read chunk length
        let mut chunk_len_bytes = [0u8; 4];
        self.reader
            .read_exact(&mut chunk_len_bytes)
            .map_err(truncated_or_io)?;
        let chunk_len = u32::from_le_bytes(chunk_len_bytes) as usize;

        if chunk_len == 0 {
            return Err(TraceFileError::Truncated);
        }

        // Guard against oversized compressed chunks (DoS mitigation — issues #8, #10)
        if chunk_len > MAX_COMPRESSED_CHUNK_LEN {
            return Err(TraceFileError::OversizedField {
                field: "compressed_chunk_len",
                actual: chunk_len as u64,
                max: MAX_COMPRESSED_CHUNK_LEN as u64,
            });
        }

        // Read compressed chunk
        let mut compressed = vec![0u8; chunk_len];
        self.reader
            .read_exact(&mut compressed)
            .map_err(truncated_or_io)?;

        // Guard against decompression bombs (OOM mitigation)
        if compressed.len() >= 4 {
            let mut len_bytes = [0u8; 4];
            len_bytes.copy_from_slice(&compressed[0..4]);
            let uncompressed_len = u32::from_le_bytes(len_bytes) as usize;
            if uncompressed_len > MAX_COMPRESSED_CHUNK_LEN {
                return Err(TraceFileError::OversizedField {
                    field: "decompressed_chunk_len",
                    actual: uncompressed_len as u64,
                    max: MAX_COMPRESSED_CHUNK_LEN as u64,
                });
            }
        }

        // Decompress through the selected integration backend.
        self.decompressed_buffer = self.lz4_codec.decode(&compressed)?;
        self.buffer_pos = 0;

        Ok(())
    }

    /// Resets the reader to the beginning of the events section.
    ///
    /// # Errors
    ///
    /// Returns an error if seeking fails.
    pub fn rewind(&mut self) -> TraceFileResult<()> {
        self.reader.seek(SeekFrom::Start(self.events_start_pos))?;
        self.events_read = 0;
        self.event_hasher = Sha256::new();

        #[cfg(feature = "trace-compression")]
        {
            self.decompressed_buffer.clear();
            self.buffer_pos = 0;
        }

        Ok(())
    }

    /// Loads all events into memory.
    ///
    /// This is convenient for small traces but may use significant memory
    /// for large traces. Use [`events()`][Self::events] for streaming.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails.
    pub fn load_all(mut self) -> TraceFileResult<Vec<ReplayEvent>> {
        // Cap pre-allocation to prevent OOM from a malicious event_count header
        // (DoS mitigation — issues #8, #10). The vec will grow naturally if the
        // file legitimately contains more events.
        let prealloc = usize::try_from(self.event_count)
            .unwrap_or(usize::MAX)
            .min(MAX_EVENT_PREALLOC);
        let mut events = Vec::with_capacity(prealloc);
        while let Some(event) = self.read_event()? {
            events.push(event);
        }
        Ok(events)
    }
}

// =============================================================================
// Iterator
// =============================================================================

/// Iterator over trace events.
pub struct TraceEventIterator {
    reader: BufReader<File>,
    remaining: u64,
    #[cfg_attr(not(feature = "trace-compression"), allow(dead_code))]
    compression: CompressionMode,
    expected_event_digest: Option<[u8; TRACE_CHECKSUM_LEN]>,
    event_hasher: Sha256,
    #[cfg(feature = "trace-compression")]
    lz4_codec: Lz4Codec,
    /// Buffer for decompressed event data.
    #[cfg(feature = "trace-compression")]
    decompressed_buffer: Vec<u8>,
    /// Position in decompressed buffer.
    #[cfg(feature = "trace-compression")]
    buffer_pos: usize,
}

impl Iterator for TraceEventIterator {
    type Item = TraceFileResult<ReplayEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        #[cfg(feature = "trace-compression")]
        if self.compression.is_compressed() {
            return Some(self.next_compressed());
        }

        Some(self.next_uncompressed())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::try_from(self.remaining).unwrap_or(usize::MAX);
        (remaining, Some(remaining))
    }
}

impl TraceEventIterator {
    /// Reads the next uncompressed event.
    fn next_uncompressed(&mut self) -> TraceFileResult<ReplayEvent> {
        // Read event length
        let mut len_bytes = [0u8; 4];
        if let Err(e) = self.reader.read_exact(&mut len_bytes) {
            return Err(truncated_or_io(e));
        }
        let len = u32::from_le_bytes(len_bytes) as usize;

        // Guard against oversized event length (DoS mitigation — issues #8, #10)
        validate_event_len(len)?;

        // Read event data
        let mut event_bytes = vec![0u8; len];
        if let Err(e) = self.reader.read_exact(&mut event_bytes) {
            return Err(truncated_or_io(e));
        }

        match rmp_serde::from_slice(&event_bytes) {
            Ok(event) => {
                self.event_hasher.update(len_bytes);
                self.event_hasher.update(&event_bytes);
                self.verify_final_checksum()?;
                self.remaining -= 1;
                Ok(event)
            }
            Err(e) => Err(TraceFileError::from(e)),
        }
    }

    /// Reads the next compressed event.
    #[cfg(feature = "trace-compression")]
    fn next_compressed(&mut self) -> TraceFileResult<ReplayEvent> {
        // Refill buffer if needed
        if self.buffer_pos >= self.decompressed_buffer.len() {
            self.refill_buffer()?;
        }

        // Read event length from buffer
        if self.buffer_pos + 4 > self.decompressed_buffer.len() {
            return Err(TraceFileError::Truncated);
        }
        let len_bytes: [u8; 4] =
            match self.decompressed_buffer[self.buffer_pos..self.buffer_pos + 4].try_into() {
                Ok(b) => b,
                Err(_) => return Err(TraceFileError::Truncated),
            };
        let len = u32::from_le_bytes(len_bytes) as usize;
        validate_event_len(len)?;
        self.buffer_pos += 4;

        // Read event data from buffer
        if self.buffer_pos + len > self.decompressed_buffer.len() {
            return Err(TraceFileError::Truncated);
        }
        let event_bytes = &self.decompressed_buffer[self.buffer_pos..self.buffer_pos + len];

        match rmp_serde::from_slice(event_bytes) {
            Ok(event) => {
                self.event_hasher.update(len_bytes);
                self.event_hasher.update(event_bytes);
                self.verify_final_checksum()?;
                self.buffer_pos += len;
                self.remaining -= 1;
                Ok(event)
            }
            Err(e) => Err(TraceFileError::from(e)),
        }
    }

    fn verify_final_checksum(&self) -> TraceFileResult<()> {
        if self.remaining == 1 {
            if let Some(expected) = self.expected_event_digest {
                let actual: [u8; TRACE_CHECKSUM_LEN] = self.event_hasher.clone().finalize().into();
                verify_checksum("event stream", &expected, &actual)?;
            }
        }
        Ok(())
    }

    /// Refills the decompressed buffer from the next compressed chunk.
    #[cfg(feature = "trace-compression")]
    fn refill_buffer(&mut self) -> TraceFileResult<()> {
        // Read chunk length
        let mut chunk_len_bytes = [0u8; 4];
        self.reader
            .read_exact(&mut chunk_len_bytes)
            .map_err(truncated_or_io)?;
        let chunk_len = u32::from_le_bytes(chunk_len_bytes) as usize;

        if chunk_len == 0 {
            return Err(TraceFileError::Truncated);
        }

        // Guard against oversized compressed chunks (DoS mitigation — issues #8, #10)
        if chunk_len > MAX_COMPRESSED_CHUNK_LEN {
            return Err(TraceFileError::OversizedField {
                field: "compressed_chunk_len",
                actual: chunk_len as u64,
                max: MAX_COMPRESSED_CHUNK_LEN as u64,
            });
        }

        // Read compressed chunk
        let mut compressed = vec![0u8; chunk_len];
        self.reader
            .read_exact(&mut compressed)
            .map_err(truncated_or_io)?;

        // Guard against decompression bombs (OOM mitigation)
        if compressed.len() >= 4 {
            let mut len_bytes = [0u8; 4];
            len_bytes.copy_from_slice(&compressed[0..4]);
            let uncompressed_len = u32::from_le_bytes(len_bytes) as usize;
            if uncompressed_len > MAX_COMPRESSED_CHUNK_LEN {
                return Err(TraceFileError::OversizedField {
                    field: "decompressed_chunk_len",
                    actual: uncompressed_len as u64,
                    max: MAX_COMPRESSED_CHUNK_LEN as u64,
                });
            }
        }

        // Decompress through the selected integration backend.
        self.decompressed_buffer = self.lz4_codec.decode(&compressed)?;
        self.buffer_pos = 0;

        Ok(())
    }
}

impl ExactSizeIterator for TraceEventIterator {}

// =============================================================================
// Convenience Functions
// =============================================================================

/// Writes a complete trace to a file.
///
/// This is a convenience function for writing small traces.
/// For large traces, use [`TraceWriter`] for streaming writes.
///
/// # Errors
///
/// Returns an error if file creation or writing fails.
pub fn write_trace_with_config(
    path: impl AsRef<Path>,
    metadata: &TraceMetadata,
    events: &[ReplayEvent],
    config: TraceFileConfig,
) -> TraceFileResult<()> {
    let mut writer = TraceWriter::create_with_config(path, config)?;
    writer.write_metadata(metadata)?;
    for event in events {
        writer.write_event(event)?;
    }
    writer.finish()
}

/// Writes a complete trace to a file with the default configuration.
///
/// This is a convenience function for writing small traces.
/// For large traces, use [`TraceWriter`] for streaming writes.
///
/// # Errors
///
/// Returns an error if file creation or writing fails.
pub fn write_trace(
    path: impl AsRef<Path>,
    metadata: &TraceMetadata,
    events: &[ReplayEvent],
) -> TraceFileResult<()> {
    write_trace_with_config(path, metadata, events, TraceFileConfig::default())
}

/// Reads a complete trace from a file.
///
/// This is a convenience function for reading small traces.
/// For large traces, use [`TraceReader`] for streaming reads.
///
/// # Errors
///
/// Returns an error if file opening or reading fails.
pub fn read_trace(path: impl AsRef<Path>) -> TraceFileResult<(TraceMetadata, Vec<ReplayEvent>)> {
    let reader = TraceReader::open(path)?;
    let metadata = reader.metadata().clone();
    let events = reader.load_all()?;
    Ok((metadata, events))
}

/// Result of a bounded attempt to recover a valid event prefix.
#[derive(Debug)]
pub struct TraceRecovery {
    /// Persisted container version.
    pub file_version: u16,
    /// Decoded metadata from the trace header.
    pub metadata: TraceMetadata,
    /// Event count declared in the trace header.
    pub declared_events: u64,
    /// Events decoded in order before corruption, truncation, or the caller's
    /// bound. For v3, only `Complete` authenticates the whole event stream.
    pub recovered_events: Vec<ReplayEvent>,
    /// Terminal recovery state.
    pub status: TraceRecoveryStatus,
}

/// Terminal state for bounded trace-prefix recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceRecoveryStatus {
    /// Every declared event and the v3 event-stream checksum were verified.
    Complete,
    /// A corrupt or truncated record ended recovery.
    Partial {
        /// Index of the first event that could not be recovered.
        next_event: u64,
        /// Stable human-readable source error.
        error: String,
    },
    /// The caller-provided event bound ended recovery.
    LimitReached {
        /// Maximum number of events admitted into memory.
        max_events: usize,
    },
}

/// Recovers at most `max_events` decodable events from the start of a trace.
///
/// Header corruption remains a hard error because no trustworthy metadata or
/// framing exists. Event-stream corruption returns an explicit partial receipt
/// and never skips ahead or silently drops an event. Because v3 uses one digest
/// for the complete canonical event stream, a partial or limit-reached v3
/// receipt is not checksum admission and must not be treated as deterministic
/// replay proof.
pub fn recover_trace_prefix(
    path: impl AsRef<Path>,
    max_events: usize,
) -> TraceFileResult<TraceRecovery> {
    let mut reader = TraceReader::open(path)?;
    let file_version = reader.file_version();
    let metadata = reader.metadata().clone();
    let declared_events = reader.event_count();
    let mut recovered_events = Vec::with_capacity(
        usize::try_from(declared_events)
            .unwrap_or(usize::MAX)
            .min(max_events),
    );

    while recovered_events.len() < max_events {
        match reader.read_event() {
            Ok(Some(event)) => recovered_events.push(event),
            Ok(None) => {
                return Ok(TraceRecovery {
                    file_version,
                    metadata,
                    declared_events,
                    recovered_events,
                    status: TraceRecoveryStatus::Complete,
                });
            }
            Err(error) => {
                return Ok(TraceRecovery {
                    file_version,
                    metadata,
                    declared_events,
                    status: TraceRecoveryStatus::Partial {
                        next_event: recovered_events.len() as u64,
                        error: error.to_string(),
                    },
                    recovered_events,
                });
            }
        }
    }

    let status = if recovered_events.len() as u64 == declared_events {
        TraceRecoveryStatus::Complete
    } else {
        TraceRecoveryStatus::LimitReached { max_events }
    };
    Ok(TraceRecovery {
        file_version,
        metadata,
        declared_events,
        recovered_events,
        status,
    })
}

/// Receipt for a non-overwriting legacy-container migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceFileMigrationReceipt {
    /// Source container version.
    pub source_version: u16,
    /// Destination container version.
    pub target_version: u16,
    /// Number of events copied without semantic transformation.
    pub events_copied: u64,
}

static MIGRATION_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct MigrationTempPath {
    path: PathBuf,
}

impl MigrationTempPath {
    fn create(output: &Path) -> io::Result<(File, Self)> {
        let parent = output.parent().unwrap_or_else(|| Path::new("."));
        let file_name = output.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "trace migration output has no file name",
            )
        })?;
        let file_name = file_name.to_string_lossy();

        for _ in 0..64 {
            let sequence = MIGRATION_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(
                ".{file_name}.asupersync-migrate-{}-{sequence}",
                std::process::id()
            ));
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => return Ok((file, Self { path })),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique trace migration staging path",
        ))
    }

    fn publish(self, output: &Path) -> io::Result<()> {
        std::fs::hard_link(&self.path, output)?;
        Ok(())
    }
}

impl Drop for MigrationTempPath {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.path)
            && error.kind() != io::ErrorKind::NotFound
        {
            warn!(
                path = %self.path.display(),
                error = %error,
                "failed to remove trace migration staging file"
            );
        }
    }
}

/// Rewrites a complete v1/v2 trace into the current checksummed container.
///
/// The source is never modified, the destination must not exist, and all
/// events are streamed in their original order. The destination is assembled
/// and synced at a sibling staging path, then atomically published with a hard
/// link so a malformed source or write failure cannot expose a partial target.
/// Keeping the source provides the explicit rollback anchor.
pub fn migrate_trace_file(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
) -> TraceFileResult<TraceFileMigrationReceipt> {
    migrate_trace_file_with_lz4_codec(input, output, Lz4Codec::Incumbent)
}

fn migrate_trace_file_with_lz4_codec(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    lz4_codec: Lz4Codec,
) -> TraceFileResult<TraceFileMigrationReceipt> {
    let input = input.as_ref();
    let output = output.as_ref();
    if input == output {
        return Err(TraceFileError::MigrationInputOutputSame);
    }
    if output.exists() {
        return Err(TraceFileError::MigrationDestinationExists);
    }

    let mut reader = TraceReader::open_with_lz4_codec(input, lz4_codec)?;
    let source_version = reader.file_version();
    if source_version == TRACE_FILE_VERSION {
        return Err(TraceFileError::MigrationAlreadyCurrent {
            version: source_version,
        });
    }
    let metadata = reader.metadata().clone();
    let compression = reader.compression();
    let (output_file, staged_path) = MigrationTempPath::create(output)?;
    let mut writer = TraceWriter::from_file_with_lz4_codec(
        output_file,
        TraceFileConfig::new()
            .with_compression(compression)
            .with_max_file_size(0)
            .on_limit(LimitAction::Fail),
        lz4_codec,
    );
    writer.write_metadata(&metadata)?;

    let mut events_copied = 0u64;
    while let Some(event) = reader.read_event()? {
        writer.write_event(&event)?;
        events_copied = events_copied.saturating_add(1);
    }
    writer.finish()?;
    File::open(&staged_path.path)?.sync_all()?;
    staged_path.publish(output).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            TraceFileError::MigrationDestinationExists
        } else {
            TraceFileError::Io(error)
        }
    })?;

    Ok(TraceFileMigrationReceipt {
        source_version,
        target_version: TRACE_FILE_VERSION,
        events_copied,
    })
}

/// Test-only entry points that route real trace operations through the owned
/// LZ4 block codec while production constructors continue to use the incumbent.
#[doc(hidden)]
#[cfg(all(feature = "trace-compression", feature = "test-internals"))]
pub mod lz4_integration_harness {
    use super::{
        File, Lz4Codec, Path, ReplayEvent, TraceFileConfig, TraceFileMigrationReceipt,
        TraceFileResult, TraceMetadata, TraceReader, TraceWriter,
        migrate_trace_file_with_lz4_codec,
    };

    /// Creates a real streaming trace writer backed by the owned codec.
    pub fn create_owned_writer(
        path: impl AsRef<Path>,
        config: TraceFileConfig,
    ) -> TraceFileResult<TraceWriter> {
        let file = File::create(path)?;
        Ok(TraceWriter::from_file_with_lz4_codec(
            file,
            config,
            Lz4Codec::Owned,
        ))
    }

    /// Opens a real streaming trace reader backed by the owned codec.
    pub fn open_owned_reader(path: impl AsRef<Path>) -> TraceFileResult<TraceReader> {
        TraceReader::open_with_lz4_codec(path, Lz4Codec::Owned)
    }

    /// Writes a complete trace through the owned codec.
    pub fn write_owned_trace(
        path: impl AsRef<Path>,
        metadata: &TraceMetadata,
        events: &[ReplayEvent],
        config: TraceFileConfig,
    ) -> TraceFileResult<()> {
        let mut writer = create_owned_writer(path, config)?;
        writer.write_metadata(metadata)?;
        for event in events {
            writer.write_event(event)?;
        }
        writer.finish()
    }

    /// Reads a complete trace through the owned codec.
    pub fn read_owned_trace(
        path: impl AsRef<Path>,
    ) -> TraceFileResult<(TraceMetadata, Vec<ReplayEvent>)> {
        let reader = open_owned_reader(path)?;
        let metadata = reader.metadata().clone();
        let events = reader.load_all()?;
        Ok((metadata, events))
    }

    /// Migrates a legacy trace while routing compressed input and output through
    /// the owned codec.
    pub fn migrate_owned_trace(
        input: impl AsRef<Path>,
        output: impl AsRef<Path>,
    ) -> TraceFileResult<TraceFileMigrationReceipt> {
        migrate_trace_file_with_lz4_codec(input, output, Lz4Codec::Owned)
    }

    /// Encodes one trace chunk through the owned codec.
    pub fn encode_owned_chunk(input: &[u8]) -> TraceFileResult<Vec<u8>> {
        Lz4Codec::Owned.encode(input)
    }

    /// Decodes one trace chunk through the owned codec.
    pub fn decode_owned_chunk(input: &[u8]) -> TraceFileResult<Vec<u8>> {
        Lz4Codec::Owned.decode(input)
    }
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
    use crate::trace::replay::CompactTaskId;
    use serde_json::json;
    use std::io::Write;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::NamedTempFile;

    fn sample_events() -> Vec<ReplayEvent> {
        vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 0,
            },
            ReplayEvent::TimeAdvanced {
                from_nanos: 0,
                to_nanos: 1_000_000,
            },
            ReplayEvent::TaskYielded {
                task: CompactTaskId(1),
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 1,
            },
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 0,
            },
        ]
    }

    fn write_v2_trace(
        path: &std::path::Path,
        metadata: &TraceMetadata,
        events: &[ReplayEvent],
        declared_events: u64,
    ) {
        let mut file = std::fs::File::create(path).expect("create v2 trace");
        file.write_all(TRACE_MAGIC).expect("write magic");
        file.write_all(&2u16.to_le_bytes()).expect("write version");
        file.write_all(&0u16.to_le_bytes()).expect("write flags");
        file.write_all(&[0]).expect("write compression");
        let metadata_bytes = rmp_serde::to_vec(metadata).expect("serialize metadata");
        file.write_all(&(metadata_bytes.len() as u32).to_le_bytes())
            .expect("write metadata length");
        file.write_all(&metadata_bytes).expect("write metadata");
        file.write_all(&declared_events.to_le_bytes())
            .expect("write event count");
        for event in events {
            let event_bytes = rmp_serde::to_vec(event).expect("serialize event");
            file.write_all(&(event_bytes.len() as u32).to_le_bytes())
                .expect("write event length");
            file.write_all(&event_bytes).expect("write event");
        }
        file.flush().expect("flush v2 trace");
    }

    fn write_v1_trace(path: &std::path::Path, metadata: &TraceMetadata, events: &[ReplayEvent]) {
        let mut file = std::fs::File::create(path).expect("create v1 trace");
        file.write_all(TRACE_MAGIC).expect("write magic");
        file.write_all(&1u16.to_le_bytes()).expect("write version");
        file.write_all(&0u16.to_le_bytes()).expect("write flags");
        let metadata_bytes = rmp_serde::to_vec(metadata).expect("serialize metadata");
        file.write_all(&(metadata_bytes.len() as u32).to_le_bytes())
            .expect("write metadata length");
        file.write_all(&metadata_bytes).expect("write metadata");
        file.write_all(&(events.len() as u64).to_le_bytes())
            .expect("write event count");
        for event in events {
            let event_bytes = rmp_serde::to_vec(event).expect("serialize event");
            file.write_all(&(event_bytes.len() as u32).to_le_bytes())
                .expect("write event length");
            file.write_all(&event_bytes).expect("write event");
        }
        file.flush().expect("flush v1 trace");
    }

    fn write_header_with_raw_compression(
        file: &mut std::fs::File,
        flags: u16,
        compression_byte: u8,
    ) {
        let metadata = TraceMetadata::new(42);
        let meta_bytes = rmp_serde::to_vec(&metadata).expect("serialize metadata");

        file.write_all(TRACE_MAGIC).expect("write magic");
        file.write_all(&2u16.to_le_bytes()).expect("write version");
        file.write_all(&flags.to_le_bytes()).expect("write flags");
        file.write_all(&[compression_byte])
            .expect("write compression");
        file.write_all(&(meta_bytes.len() as u32).to_le_bytes())
            .expect("write metadata length");
        file.write_all(&meta_bytes).expect("write metadata");
    }

    fn write_header_with_metadata(file: &mut std::fs::File, compression: CompressionMode) {
        let flags = if compression.is_compressed() {
            FLAG_COMPRESSED
        } else {
            0
        };
        write_header_with_raw_compression(file, flags, compression.to_byte());
    }

    fn trace_file_layout_summary(path: &std::path::Path) -> serde_json::Value {
        let bytes = std::fs::read(path).expect("read trace bytes");
        let version = u16::from_le_bytes(
            bytes[TRACE_MAGIC.len()..TRACE_MAGIC.len() + 2]
                .try_into()
                .expect("version bytes"),
        );
        let flags = u16::from_le_bytes(
            bytes[TRACE_MAGIC.len() + 2..TRACE_MAGIC.len() + 4]
                .try_into()
                .expect("flag bytes"),
        );
        let compression_byte = bytes[TRACE_MAGIC.len() + 4];
        let meta_len = u32::from_le_bytes(
            bytes[TRACE_MAGIC.len() + 5..LEGACY_HEADER_SIZE]
                .try_into()
                .expect("metadata length bytes"),
        );
        let event_count_offset = HEADER_SIZE + meta_len as usize;
        let event_count = u64::from_le_bytes(
            bytes[event_count_offset..event_count_offset + 8]
                .try_into()
                .expect("event count bytes"),
        );

        let mut metadata =
            serde_json::to_value(TraceReader::open(path).expect("open reader").metadata())
                .expect("serialize metadata");
        if let Some(obj) = metadata.as_object_mut() {
            if let Some(recorded_at) = obj.get_mut("recorded_at") {
                *recorded_at = json!("[recorded_at]");
            }
        }

        json!({
            "magic": std::str::from_utf8(TRACE_MAGIC).expect("trace magic is valid utf8"),
            "version": version,
            "flags_hex": format!("{flags:#06x}"),
            "compression_byte": compression_byte,
            "meta_len": meta_len,
            "event_count": event_count,
            "metadata": metadata,
            "events": sample_events(),
        })
    }

    fn scrub_metadata_for_snapshot(metadata: &TraceMetadata) -> serde_json::Value {
        let mut metadata = serde_json::to_value(metadata).expect("serialize metadata");
        if let Some(obj) = metadata.as_object_mut() {
            if let Some(recorded_at) = obj.get_mut("recorded_at") {
                *recorded_at = json!("[recorded_at]");
            }
        }
        metadata
    }

    fn trace_file_roundtrip_summary(path: &std::path::Path) -> serde_json::Value {
        let (reader_event_count, reader_metadata) = {
            let reader = TraceReader::open(path).expect("open reader");
            (
                reader.event_count(),
                scrub_metadata_for_snapshot(reader.metadata()),
            )
        };

        let (metadata, events) = read_trace(path).expect("read trace");

        json!({
            "reader": {
                "event_count": reader_event_count,
                "metadata": reader_metadata,
            },
            "read_trace": {
                "metadata": scrub_metadata_for_snapshot(&metadata),
                "events": events,
            },
        })
    }

    // =========================================================================
    // Pure data-type tests (wave 40 – CyanBarn)
    // =========================================================================

    #[test]
    fn compression_mode_debug_clone_copy_eq_default() {
        let def = CompressionMode::default();
        assert_eq!(def, CompressionMode::None);
        let copied = def;
        let cloned = def;
        assert_eq!(copied, cloned);
        assert!(!def.is_compressed());
        let dbg = format!("{def:?}");
        assert!(dbg.contains("None"));
    }

    #[test]
    fn trace_file_config_debug_clone_default() {
        let def = TraceFileConfig::default();
        assert_eq!(def.compression, CompressionMode::None);
        assert_eq!(def.chunk_size, DEFAULT_COMPRESSION_CHUNK_SIZE);
        assert!(def.max_events.is_none());
        let cloned = def.clone();
        assert_eq!(cloned.compression, CompressionMode::None);
        let dbg = format!("{def:?}");
        assert!(dbg.contains("TraceFileConfig"));
    }

    #[test]
    fn trace_file_error_debug_display() {
        let err = TraceFileError::InvalidMagic;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("InvalidMagic"));
        let display = format!("{err}");
        assert!(display.contains("magic"));

        let version_err = TraceFileError::UnsupportedVersion {
            expected: 2,
            found: 99,
        };
        let display2 = format!("{version_err}");
        assert!(display2.contains("99"));
    }

    #[test]
    fn trace_file_layout_snapshot_scrubs_recorded_at() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata {
            version: REPLAY_SCHEMA_VERSION,
            seed: 42,
            recorded_at: 1_726_133_456_789_000_000,
            config_hash: 0xfeed_beef_cafe_babe,
            description: Some("trace file layout snapshot".to_string()),
        };
        let events = sample_events();

        write_trace(path, &metadata, &events).expect("write trace");

        insta::assert_json_snapshot!(
            "trace_file_layout_scrubbed_recorded_at",
            trace_file_layout_summary(path)
        );
    }

    #[test]
    fn write_and_read_roundtrip() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata::new(42).with_description("test trace");
        let events = sample_events();

        // Write
        write_trace(path, &metadata, &events).expect("write trace");

        // Read
        let (read_meta, read_events) = read_trace(path).expect("read trace");

        assert_eq!(read_meta.seed, metadata.seed);
        assert_eq!(read_meta.description, metadata.description);
        assert_eq!(read_events.len(), events.len());

        for (orig, read) in events.iter().zip(read_events.iter()) {
            assert_eq!(orig, read);
        }
    }

    #[test]
    fn current_trace_header_carries_metadata_and_event_digests() {
        let temp = NamedTempFile::new().expect("create temp file");
        let metadata = TraceMetadata::new(42);
        let events = sample_events();
        write_trace(temp.path(), &metadata, &events).expect("write trace");

        let bytes = std::fs::read(temp.path()).expect("read trace");
        let version = u16::from_le_bytes(
            bytes[TRACE_MAGIC.len()..TRACE_MAGIC.len() + 2]
                .try_into()
                .expect("version bytes"),
        );
        let flags = u16::from_le_bytes(
            bytes[TRACE_MAGIC.len() + 2..TRACE_MAGIC.len() + 4]
                .try_into()
                .expect("flags bytes"),
        );
        assert_eq!(version, TRACE_FILE_VERSION);
        assert_eq!(flags & FLAG_CHECKSUMMED, FLAG_CHECKSUMMED);
        assert_eq!(
            TraceReader::open(temp.path())
                .expect("open current trace")
                .load_all()
                .expect("verify current trace"),
            events
        );
    }

    #[test]
    fn zero_file_version_and_mismatched_compression_byte_fail_closed() {
        let temp = NamedTempFile::new().expect("create temp file");
        write_trace(temp.path(), &TraceMetadata::new(42), &sample_events()).expect("write trace");
        let baseline = std::fs::read(temp.path()).expect("read trace");

        let mut zero_version = baseline.clone();
        zero_version[TRACE_MAGIC.len()..TRACE_MAGIC.len() + 2].copy_from_slice(&0u16.to_le_bytes());
        std::fs::write(temp.path(), zero_version).expect("write zero-version trace");
        assert!(matches!(
            TraceReader::open(temp.path()),
            Err(TraceFileError::UnsupportedVersion { found: 0, .. })
        ));

        let mut mismatched_compression = baseline;
        mismatched_compression[TRACE_MAGIC.len() + 4] = 1;
        std::fs::write(temp.path(), mismatched_compression)
            .expect("write mismatched compression byte");
        assert!(matches!(
            TraceReader::open(temp.path()),
            Err(TraceFileError::UnsupportedCompression(1))
        ));
    }

    #[test]
    fn metadata_checksum_mismatch_fails_before_decode() {
        let temp = NamedTempFile::new().expect("create temp file");
        write_trace(temp.path(), &TraceMetadata::new(42), &sample_events()).expect("write trace");

        let mut bytes = std::fs::read(temp.path()).expect("read trace");
        bytes[LEGACY_HEADER_SIZE] ^= 0x01;
        std::fs::write(temp.path(), bytes).expect("corrupt metadata digest");

        let error = match TraceReader::open(temp.path()) {
            Ok(_) => panic!("checksum must fail"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            TraceFileError::ChecksumMismatch {
                section: "metadata"
            }
        ));
    }

    #[test]
    fn event_stream_checksum_mismatch_is_fail_closed() {
        let temp = NamedTempFile::new().expect("create temp file");
        let metadata = TraceMetadata::new(42);
        let events = sample_events();
        write_trace(temp.path(), &metadata, &events).expect("write trace");

        let mut bytes = std::fs::read(temp.path()).expect("read trace");
        let meta_len = rmp_serde::to_vec(&metadata)
            .expect("serialize metadata")
            .len();
        let event_digest_offset = HEADER_SIZE + meta_len + 8;
        bytes[event_digest_offset] ^= 0x01;
        std::fs::write(temp.path(), bytes).expect("corrupt event digest");

        let error = TraceReader::open(temp.path())
            .expect("header remains valid")
            .load_all()
            .expect_err("event digest must fail");
        assert!(matches!(
            error,
            TraceFileError::ChecksumMismatch {
                section: "event stream"
            }
        ));
    }

    #[test]
    fn v2_reader_and_non_overwriting_migration_preserve_semantics_and_source() {
        let source = NamedTempFile::new().expect("create source");
        let output_dir = tempfile::tempdir().expect("create output dir");
        let output = output_dir.path().join("migrated.trace");
        let metadata = TraceMetadata::new(7).with_description("legacy-v2");
        let events = sample_events();
        write_v2_trace(source.path(), &metadata, &events, events.len() as u64);
        let source_bytes = std::fs::read(source.path()).expect("read source baseline");

        let legacy_reader = TraceReader::open(source.path()).expect("open v2");
        assert_eq!(legacy_reader.file_version(), 2);
        assert_eq!(legacy_reader.load_all().expect("read v2"), events);

        let receipt = migrate_trace_file(source.path(), &output).expect("migrate v2");
        assert_eq!(receipt.source_version, 2);
        assert_eq!(receipt.target_version, TRACE_FILE_VERSION);
        assert_eq!(receipt.events_copied, events.len() as u64);
        assert_eq!(
            std::fs::read(source.path()).expect("read source after migration"),
            source_bytes,
            "migration must preserve the rollback source byte-for-byte"
        );

        let migrated = TraceReader::open(&output).expect("open migrated trace");
        assert_eq!(migrated.file_version(), TRACE_FILE_VERSION);
        assert_eq!(migrated.metadata(), &metadata);
        assert_eq!(migrated.load_all().expect("read migrated trace"), events);
    }

    #[test]
    fn v1_reader_and_migration_preserve_semantics_and_source() {
        let source = NamedTempFile::new().expect("create source");
        let output_dir = tempfile::tempdir().expect("create output dir");
        let output = output_dir.path().join("migrated.trace");
        let metadata = TraceMetadata::new(5).with_description("legacy-v1");
        let events = sample_events();
        write_v1_trace(source.path(), &metadata, &events);
        let source_bytes = std::fs::read(source.path()).expect("read source baseline");

        let reader = TraceReader::open(source.path()).expect("open v1");
        assert_eq!(reader.file_version(), 1);
        assert_eq!(reader.load_all().expect("read v1"), events);

        let receipt = migrate_trace_file(source.path(), &output).expect("migrate v1");
        assert_eq!(receipt.source_version, 1);
        assert_eq!(receipt.target_version, TRACE_FILE_VERSION);
        assert_eq!(receipt.events_copied, events.len() as u64);
        assert_eq!(
            std::fs::read(source.path()).expect("read source after migration"),
            source_bytes
        );
        assert_eq!(
            TraceReader::open(&output)
                .expect("open migrated trace")
                .load_all()
                .expect("read migrated trace"),
            events
        );
    }

    #[test]
    fn migration_refuses_same_or_existing_destination_without_overwrite() {
        let source = NamedTempFile::new().expect("create source");
        let destination = NamedTempFile::new().expect("create destination");
        let destination_before = b"do not overwrite".to_vec();
        std::fs::write(destination.path(), &destination_before).expect("seed destination");
        write_v2_trace(source.path(), &TraceMetadata::new(17), &sample_events(), 3);

        assert!(matches!(
            migrate_trace_file(source.path(), source.path()),
            Err(TraceFileError::MigrationInputOutputSame)
        ));
        assert!(matches!(
            migrate_trace_file(source.path(), destination.path()),
            Err(TraceFileError::MigrationDestinationExists)
        ));
        assert_eq!(
            std::fs::read(destination.path()).expect("read destination"),
            destination_before
        );
    }

    #[test]
    fn a7_migration_failure_never_publishes_partial_output_or_leaves_staging_file() {
        let directory = tempfile::tempdir().expect("create migration directory");
        let source = directory.path().join("truncated-v2.trace");
        let destination = directory.path().join("must-not-exist.trace");
        write_v2_trace(&source, &TraceMetadata::new(19), &sample_events(), 3);
        let source_before = std::fs::read(&source).expect("read complete v2 source");
        std::fs::write(&source, &source_before[..source_before.len() - 1])
            .expect("truncate final event");
        let truncated_source = std::fs::read(&source).expect("read truncated source");

        assert!(migrate_trace_file(&source, &destination).is_err());
        assert!(
            !destination.exists(),
            "failed migration must not publish a partial destination"
        );
        assert_eq!(
            std::fs::read(&source).expect("read rollback source"),
            truncated_source,
            "failed migration must preserve its rollback source"
        );

        let staging_prefix = ".must-not-exist.trace.asupersync-migrate-";
        let staging_paths = std::fs::read_dir(directory.path())
            .expect("read migration directory")
            .map(|entry| entry.expect("read directory entry").file_name())
            .filter(|name| name.to_string_lossy().starts_with(staging_prefix))
            .collect::<Vec<_>>();
        assert!(
            staging_paths.is_empty(),
            "failed migration left staging paths: {staging_paths:?}"
        );
    }

    #[test]
    fn bounded_recovery_returns_verified_v2_prefix_and_terminal_error() {
        let source = NamedTempFile::new().expect("create source");
        let metadata = TraceMetadata::new(9);
        let events = sample_events();
        write_v2_trace(source.path(), &metadata, &events[..2], 3);

        let recovery = recover_trace_prefix(source.path(), 10).expect("recover prefix");
        assert_eq!(recovery.file_version, 2);
        assert_eq!(recovery.declared_events, 3);
        assert_eq!(recovery.recovered_events, events[..2]);
        assert!(matches!(
            recovery.status,
            TraceRecoveryStatus::Partial { next_event: 2, .. }
        ));
    }

    #[test]
    fn bounded_recovery_never_exceeds_caller_event_limit() {
        let source = NamedTempFile::new().expect("create source");
        let events = sample_events();
        write_v2_trace(
            source.path(),
            &TraceMetadata::new(11),
            &events,
            events.len() as u64,
        );

        let recovery = recover_trace_prefix(source.path(), 2).expect("recover bounded prefix");
        assert_eq!(recovery.recovered_events, events[..2]);
        assert_eq!(
            recovery.status,
            TraceRecoveryStatus::LimitReached { max_events: 2 }
        );
    }

    #[test]
    fn trace_file_roundtrip_serialization_summary() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata {
            version: REPLAY_SCHEMA_VERSION,
            seed: 7,
            recorded_at: 1_726_133_456_789_000_000,
            config_hash: 0x1020_3040_5060_7080,
            description: Some("trace file round-trip snapshot".to_string()),
        };
        let events = sample_events();

        write_trace(path, &metadata, &events).expect("write trace");

        insta::assert_json_snapshot!(
            "trace_file_roundtrip_serialization_summary",
            trace_file_roundtrip_summary(path)
        );
    }

    #[cfg(not(feature = "trace-compression"))]
    #[test]
    fn compressed_header_without_feature_reports_compression_not_available() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();
        let mut file = std::fs::File::create(path).expect("create file");
        write_header_with_raw_compression(&mut file, FLAG_COMPRESSED, 1);
        file.write_all(&0u64.to_le_bytes())
            .expect("write event count");
        file.flush().expect("flush");
        drop(file);

        let err = TraceReader::open(path).expect_err("compressed trace must require feature");
        assert!(
            matches!(err, TraceFileError::CompressionNotAvailable),
            "got: {err:?}"
        );
    }

    #[test]
    fn streaming_write_and_read() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata::new(123);
        let events = sample_events();

        // Streaming write
        {
            let mut writer = TraceWriter::create(path).expect("create writer");
            writer.write_metadata(&metadata).expect("write metadata");
            for event in &events {
                writer.write_event(event).expect("write event");
            }
            assert_eq!(writer.event_count(), events.len() as u64);
            writer.finish().expect("finish");
        }

        // Streaming read
        {
            let reader = TraceReader::open(path).expect("open reader");
            assert_eq!(reader.metadata().seed, 123);
            assert_eq!(reader.event_count(), events.len() as u64);

            let mut count = 0;
            for result in reader.events() {
                let event = result.expect("read event");
                assert_eq!(event, events[count]);
                count += 1;
            }
            assert_eq!(count, events.len());
        }
    }

    #[test]
    fn reader_rewind() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events();
        write_trace(path, &metadata, &events).expect("write trace");

        let mut reader = TraceReader::open(path).expect("open reader");

        // Read first two events
        let e1 = reader.read_event().expect("read").expect("event");
        let e2 = reader.read_event().expect("read").expect("event");
        assert_eq!(reader.events_read(), 2);

        // Rewind and verify we get the same events
        reader.rewind().expect("rewind");
        assert_eq!(reader.events_read(), 0);

        let e1_again = reader.read_event().expect("read").expect("event");
        let e2_again = reader.read_event().expect("read").expect("event");
        assert_eq!(e1, e1_again);
        assert_eq!(e2, e2_again);
    }

    #[test]
    fn empty_trace() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata::new(0);
        write_trace(path, &metadata, &[]).expect("write empty trace");

        let (read_meta, read_events) = read_trace(path).expect("read empty trace");
        assert_eq!(read_meta.seed, 0);
        assert!(read_events.is_empty());
    }

    #[test]
    fn large_trace() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let event_count = 10_000;

        // Generate large trace
        let events: Vec<_> = (0..event_count)
            .map(|i| ReplayEvent::TaskScheduled {
                task: CompactTaskId(i),
                at_tick: i,
            })
            .collect();

        write_trace(path, &metadata, &events).expect("write large trace");

        // Read with streaming
        let reader = TraceReader::open(path).expect("open reader");
        assert_eq!(reader.event_count(), event_count);

        let mut count = 0u64;
        for result in reader.events() {
            let event = result.expect("read event");
            if let ReplayEvent::TaskScheduled { task, at_tick } = event {
                assert_eq!(task.0, count);
                assert_eq!(at_tick, count);
            } else {
                unreachable!("unexpected event type");
            }
            count += 1;
        }
        assert_eq!(count, event_count);
    }

    #[test]
    fn invalid_magic() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        // Write garbage
        std::fs::write(path, b"NOT A TRACE FILE").expect("write garbage");

        let result = TraceReader::open(path);
        assert!(matches!(result, Err(TraceFileError::InvalidMagic)));
    }

    #[test]
    fn reader_read_event_errors_on_truncated_stream() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();
        let mut file = std::fs::File::create(path).expect("create file");
        write_header_with_metadata(&mut file, CompressionMode::None);
        file.write_all(&1u64.to_le_bytes())
            .expect("write event count");
        file.flush().expect("flush");
        drop(file);

        let mut reader = TraceReader::open(path).expect("open reader");
        let err = reader
            .read_event()
            .expect_err("missing declared event must error");
        assert!(matches!(err, TraceFileError::Truncated), "got: {err:?}");
    }

    #[test]
    fn event_iterator_errors_on_truncated_stream() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();
        let mut file = std::fs::File::create(path).expect("create file");
        write_header_with_metadata(&mut file, CompressionMode::None);
        file.write_all(&1u64.to_le_bytes())
            .expect("write event count");
        file.flush().expect("flush");
        drop(file);

        let mut iter = TraceReader::open(path).expect("open reader").events();
        let first = iter
            .next()
            .expect("iterator should emit an error for the missing event");
        assert!(
            matches!(first, Err(TraceFileError::Truncated)),
            "got: {first:?}"
        );
    }

    #[test]
    fn file_size_reasonable() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events: Vec<_> = (0..1000)
            .map(|i| ReplayEvent::TaskScheduled {
                task: CompactTaskId(i),
                at_tick: i,
            })
            .collect();

        write_trace(path, &metadata, &events).expect("write trace");

        let file_size = std::fs::metadata(path).expect("metadata").len();
        let file_size = u32::try_from(file_size).expect("trace file size fits u32 for test");
        let bytes_per_event = f64::from(file_size) / 1000.0;

        // Should be well under 64 bytes per event
        assert!(
            bytes_per_event < 40.0,
            "File size too large: {bytes_per_event:.1} bytes/event"
        );
    }

    #[test]
    fn writer_already_finished_error() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let mut writer = TraceWriter::create(path).expect("create writer");
        writer
            .write_metadata(&TraceMetadata::new(42))
            .expect("write metadata");
        writer.finish().expect("finish");

        // Attempting to use a finished writer should not be possible
        // because finish() consumes self, so this is compile-time safety
    }

    #[test]
    fn write_event_requires_metadata_first() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let mut writer = TraceWriter::create(path).expect("create writer");
        let err = writer
            .write_event(&ReplayEvent::RngSeed { seed: 42 })
            .expect_err("events before metadata must be rejected");
        assert!(matches!(err, TraceFileError::MetadataNotWritten));

        drop(writer);

        let file_len = std::fs::metadata(path).expect("metadata").len();
        assert_eq!(
            file_len, 0,
            "rejecting pre-header events must not scribble an event count at offset zero"
        );
    }

    #[test]
    fn finish_requires_metadata_first() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let writer = TraceWriter::create(path).expect("create writer");
        let err = writer
            .finish()
            .expect_err("finish without metadata must be rejected");
        assert!(matches!(err, TraceFileError::MetadataNotWritten));

        let file_len = std::fs::metadata(path).expect("metadata").len();
        assert_eq!(
            file_len, 0,
            "failed finish without metadata must leave the new file empty"
        );
    }

    #[test]
    fn write_metadata_rejects_duplicate_headers_without_corrupting_file() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let mut writer = TraceWriter::create(path).expect("create writer");
        writer.write_metadata(&metadata).expect("write metadata");
        let err = writer
            .write_metadata(&metadata)
            .expect_err("duplicate metadata must be rejected");
        assert!(matches!(err, TraceFileError::MetadataAlreadyWritten));

        writer.finish().expect("finish");

        let reader = TraceReader::open(path).expect("open reader");
        assert_eq!(reader.metadata().seed, metadata.seed);
        assert_eq!(reader.event_count(), 0);
    }

    #[test]
    fn write_stops_at_max_events() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();
        let metadata = TraceMetadata::new(42);
        let events = sample_events();

        let config = TraceFileConfig::new().with_max_events(Some(2));
        let mut writer = TraceWriter::create_with_config(path, config).expect("create writer");
        writer.write_metadata(&metadata).expect("write metadata");
        for event in &events {
            writer.write_event(event).expect("write event");
        }
        writer.finish().expect("finish");

        let reader = TraceReader::open(path).expect("open reader");
        assert_eq!(reader.event_count(), 2);
    }

    #[test]
    fn write_stops_at_max_file_size() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let meta_len = rmp_serde::to_vec(&metadata)
            .expect("serialize metadata")
            .len() as u64;
        let header_bytes = HEADER_SIZE as u64 + meta_len + 8 + TRACE_CHECKSUM_LEN as u64;

        let config = TraceFileConfig::new().with_max_file_size(header_bytes);
        let mut writer = TraceWriter::create_with_config(path, config).expect("create writer");
        writer.write_metadata(&metadata).expect("write metadata");
        writer
            .write_event(&ReplayEvent::RngSeed { seed: 42 })
            .expect("write event");
        writer.finish().expect("finish");

        let reader = TraceReader::open(path).expect("open reader");
        assert_eq!(reader.event_count(), 0);
    }

    #[test]
    fn write_limit_callback_invoked() {
        let temp = NamedTempFile::new().expect("create temp file");
        let path = temp.path();

        let hits = Arc::new(AtomicUsize::new(0));
        let hit_ref = Arc::clone(&hits);
        let action = LimitAction::Callback(Arc::new(move |_info| {
            hit_ref.fetch_add(1, Ordering::SeqCst);
            LimitAction::StopRecording
        }));

        let config = TraceFileConfig::new()
            .with_max_events(Some(1))
            .on_limit(action);
        let mut writer = TraceWriter::create_with_config(path, config).expect("create writer");
        writer
            .write_metadata(&TraceMetadata::new(42))
            .expect("write metadata");
        writer
            .write_event(&ReplayEvent::RngSeed { seed: 1 })
            .expect("write event");
        writer
            .write_event(&ReplayEvent::RngSeed { seed: 2 })
            .expect("write event");
        writer.finish().expect("finish");

        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    #[cfg(target_family = "unix")]
    fn disk_full_is_handled() {
        let path = std::path::Path::new("/dev/full");
        if !path.exists() {
            return;
        }

        let Ok(mut writer) = TraceWriter::create(path) else {
            return;
        };

        // write_metadata buffers to BufWriter, which may not immediately
        // write to disk. We need to finish() to flush and detect ENOSPC.
        let _ = writer.write_metadata(&TraceMetadata::new(42));
        let result = writer.finish();
        assert!(matches!(
            result,
            Err(TraceFileError::Io(err)) if is_disk_full_os_error(err.raw_os_error())
        ));
    }

    // =========================================================================
    // Compression Tests (feature-gated)
    // =========================================================================

    #[cfg(feature = "trace-compression")]
    mod compression_tests {
        use super::*;

        #[test]
        fn write_trace_with_config_writes_compressed_trace() {
            let temp = NamedTempFile::new().expect("create temp file");
            let path = temp.path();

            let metadata = TraceMetadata::new(42).with_description("compressed helper trace");
            let events = sample_events();
            let config = TraceFileConfig::new().with_compression(CompressionMode::Lz4 { level: 1 });

            write_trace_with_config(path, &metadata, &events, config).expect("write trace");

            let reader = TraceReader::open(path).expect("open reader");
            assert!(reader.is_compressed());
            assert_eq!(reader.compression(), CompressionMode::Lz4 { level: 1 });
            assert_eq!(reader.load_all().expect("load all"), events);
        }

        #[test]
        fn compressed_write_and_read_roundtrip() {
            let temp = NamedTempFile::new().expect("create temp file");
            let path = temp.path();

            let metadata = TraceMetadata::new(42).with_description("compressed trace");
            let events = sample_events();

            // Write with compression
            let config = TraceFileConfig::new().with_compression(CompressionMode::Lz4 { level: 1 });
            let mut writer = TraceWriter::create_with_config(path, config).expect("create writer");
            writer.write_metadata(&metadata).expect("write metadata");
            for event in &events {
                writer.write_event(event).expect("write event");
            }
            writer.finish().expect("finish");

            // Read (auto-detects compression)
            let reader = TraceReader::open(path).expect("open reader");
            assert!(reader.is_compressed());
            assert_eq!(reader.metadata().seed, metadata.seed);
            assert_eq!(reader.event_count(), events.len() as u64);

            let read_events = reader.load_all().expect("load all");
            assert_eq!(read_events.len(), events.len());
            for (orig, read) in events.iter().zip(read_events.iter()) {
                assert_eq!(orig, read);
            }
        }

        #[test]
        fn compressed_event_stream_checksum_mismatch_is_fail_closed() {
            let temp = NamedTempFile::new().expect("create temp file");
            let metadata = TraceMetadata::new(42);
            let events = sample_events();
            let config = TraceFileConfig::new().with_compression(CompressionMode::Lz4 { level: 1 });
            write_trace_with_config(temp.path(), &metadata, &events, config)
                .expect("write compressed trace");

            let mut bytes = std::fs::read(temp.path()).expect("read trace");
            let metadata_len = rmp_serde::to_vec(&metadata)
                .expect("serialize metadata")
                .len();
            let event_digest_offset = HEADER_SIZE + metadata_len + 8;
            bytes[event_digest_offset] ^= 0x01;
            std::fs::write(temp.path(), bytes).expect("corrupt event digest");

            let error = TraceReader::open(temp.path())
                .expect("header remains valid")
                .load_all()
                .expect_err("compressed event checksum must fail");
            assert!(matches!(
                error,
                TraceFileError::ChecksumMismatch {
                    section: "event stream"
                }
            ));
        }

        #[test]
        fn compressed_streaming_read() {
            let temp = NamedTempFile::new().expect("create temp file");
            let path = temp.path();

            let metadata = TraceMetadata::new(123);
            let events = sample_events();

            // Write with compression
            let config = TraceFileConfig::new().with_compression(CompressionMode::Lz4 { level: 1 });
            let mut writer = TraceWriter::create_with_config(path, config).expect("create writer");
            writer.write_metadata(&metadata).expect("write metadata");
            for event in &events {
                writer.write_event(event).expect("write event");
            }
            writer.finish().expect("finish");

            // Streaming read
            let reader = TraceReader::open(path).expect("open reader");
            assert!(reader.is_compressed());

            let mut count = 0;
            for result in reader.events() {
                let event = result.expect("read event");
                assert_eq!(event, events[count]);
                count += 1;
            }
            assert_eq!(count, events.len());
        }

        #[test]
        fn large_compressed_trace() {
            let temp = NamedTempFile::new().expect("create temp file");
            let path = temp.path();

            let metadata = TraceMetadata::new(42);
            let event_count = 10_000u64;

            // Generate large trace
            let events: Vec<_> = (0..event_count)
                .map(|i| ReplayEvent::TaskScheduled {
                    task: CompactTaskId(i),
                    at_tick: i,
                })
                .collect();

            // Write with compression
            let config = TraceFileConfig::new()
                .with_compression(CompressionMode::Lz4 { level: 1 })
                .with_chunk_size(8 * 1024); // 8KB chunks for more chunks in test
            let mut writer = TraceWriter::create_with_config(path, config).expect("create writer");
            writer.write_metadata(&metadata).expect("write metadata");
            for event in &events {
                writer.write_event(event).expect("write event");
            }
            writer.finish().expect("finish");

            // Read with streaming
            let reader = TraceReader::open(path).expect("open reader");
            assert!(reader.is_compressed());
            assert_eq!(reader.event_count(), event_count);

            let mut count = 0u64;
            for result in reader.events() {
                let event = result.expect("read event");
                if let ReplayEvent::TaskScheduled { task, at_tick } = event {
                    assert_eq!(task.0, count);
                    assert_eq!(at_tick, count);
                } else {
                    unreachable!("unexpected event type");
                }
                count += 1;
            }
            assert_eq!(count, event_count);
        }

        #[test]
        fn compression_ratio() {
            let temp_uncompressed = NamedTempFile::new().expect("create temp file");
            let temp_compressed = NamedTempFile::new().expect("create temp file");

            let metadata = TraceMetadata::new(42);
            let event_count = 5000u64;

            // Generate trace with repetitive data (good for compression)
            let events: Vec<_> = (0..event_count)
                .map(|i| ReplayEvent::TaskScheduled {
                    task: CompactTaskId(i % 100), // Repetitive task IDs
                    at_tick: i,
                })
                .collect();

            // Write uncompressed
            {
                let mut writer =
                    TraceWriter::create(temp_uncompressed.path()).expect("create writer");
                writer.write_metadata(&metadata).expect("write metadata");
                for event in &events {
                    writer.write_event(event).expect("write event");
                }
                writer.finish().expect("finish");
            }

            // Write compressed
            {
                let config =
                    TraceFileConfig::new().with_compression(CompressionMode::Lz4 { level: 1 });
                let mut writer = TraceWriter::create_with_config(temp_compressed.path(), config)
                    .expect("create writer");
                writer.write_metadata(&metadata).expect("write metadata");
                for event in &events {
                    writer.write_event(event).expect("write event");
                }
                writer.finish().expect("finish");
            }

            let uncompressed_size = std::fs::metadata(temp_uncompressed.path())
                .expect("metadata")
                .len();
            let compressed_size = std::fs::metadata(temp_compressed.path())
                .expect("metadata")
                .len();

            #[allow(clippy::cast_precision_loss)]
            let ratio = uncompressed_size as f64 / compressed_size as f64;

            // LZ4 should achieve at least 2x compression on this repetitive data
            assert!(
                ratio > 2.0,
                "Compression ratio {ratio:.2}x is below expected 2x minimum"
            );
        }

        #[test]
        fn compressed_rewind() {
            let temp = NamedTempFile::new().expect("create temp file");
            let path = temp.path();

            let metadata = TraceMetadata::new(42);
            let events = sample_events();

            // Write with compression
            let config = TraceFileConfig::new().with_compression(CompressionMode::Lz4 { level: 1 });
            let mut writer = TraceWriter::create_with_config(path, config).expect("create writer");
            writer.write_metadata(&metadata).expect("write metadata");
            for event in &events {
                writer.write_event(event).expect("write event");
            }
            writer.finish().expect("finish");

            let mut reader = TraceReader::open(path).expect("open reader");
            assert!(reader.is_compressed());

            // Read first two events
            let e1 = reader.read_event().expect("read").expect("event");
            let e2 = reader.read_event().expect("read").expect("event");
            assert_eq!(reader.events_read(), 2);

            // Rewind and verify we get the same events
            reader.rewind().expect("rewind");
            assert_eq!(reader.events_read(), 0);

            let e1_again = reader.read_event().expect("read").expect("event");
            let e2_again = reader.read_event().expect("read").expect("event");
            assert_eq!(e1, e1_again);
            assert_eq!(e2, e2_again);
        }

        #[test]
        fn uncompressed_still_readable() {
            let temp = NamedTempFile::new().expect("create temp file");
            let path = temp.path();

            let metadata = TraceMetadata::new(42);
            let events = sample_events();

            // Write without compression
            write_trace(path, &metadata, &events).expect("write trace");

            // Should read successfully and report not compressed
            let reader = TraceReader::open(path).expect("open reader");
            assert!(!reader.is_compressed());
            assert_eq!(reader.event_count(), events.len() as u64);

            let read_events = reader.load_all().expect("load all");
            assert_eq!(read_events, events);
        }

        #[test]
        fn reader_read_event_errors_on_truncated_compressed_stream() {
            let temp = NamedTempFile::new().expect("create temp file");
            let path = temp.path();
            let mut file = std::fs::File::create(path).expect("create file");
            write_header_with_metadata(&mut file, CompressionMode::Lz4 { level: 1 });
            file.write_all(&1u64.to_le_bytes())
                .expect("write event count");
            file.flush().expect("flush");
            drop(file);

            let mut reader = TraceReader::open(path).expect("open reader");
            let err = reader
                .read_event()
                .expect_err("missing compressed chunk must error");
            assert!(matches!(err, TraceFileError::Truncated), "got: {err:?}");
        }

        #[test]
        fn event_iterator_errors_on_truncated_compressed_stream() {
            let temp = NamedTempFile::new().expect("create temp file");
            let path = temp.path();
            let mut file = std::fs::File::create(path).expect("create file");
            write_header_with_metadata(&mut file, CompressionMode::Lz4 { level: 1 });
            file.write_all(&1u64.to_le_bytes())
                .expect("write event count");
            file.flush().expect("flush");
            drop(file);

            let mut iter = TraceReader::open(path).expect("open reader").events();
            let first = iter
                .next()
                .expect("iterator should emit an error for the missing chunk");
            assert!(
                matches!(first, Err(TraceFileError::Truncated)),
                "got: {first:?}"
            );
        }

        #[test]
        fn reader_read_event_rejects_oversized_event_len_in_compressed_stream() {
            let temp = NamedTempFile::new().expect("create temp file");
            let path = temp.path();
            let mut file = std::fs::File::create(path).expect("create file");
            write_header_with_metadata(&mut file, CompressionMode::Lz4 { level: 1 });
            file.write_all(&1u64.to_le_bytes())
                .expect("write event count");

            let oversized_len = u32::try_from(MAX_EVENT_LEN + 1).expect("event limit fits in u32");
            let compressed = lz4_flex::compress_prepend_size(&oversized_len.to_le_bytes());
            let chunk_len = u32::try_from(compressed.len()).expect("compressed chunk fits in u32");
            file.write_all(&chunk_len.to_le_bytes())
                .expect("write chunk len");
            file.write_all(&compressed).expect("write chunk");
            file.flush().expect("flush");
            drop(file);

            let mut reader = TraceReader::open(path).expect("open reader");
            let err = reader
                .read_event()
                .expect_err("oversized event len must error");
            assert!(
                matches!(
                    err,
                    TraceFileError::OversizedField {
                        field: "event_len",
                        actual,
                        max,
                    } if actual == (MAX_EVENT_LEN as u64) + 1 && max == MAX_EVENT_LEN as u64
                ),
                "got: {err:?}"
            );
        }

        #[test]
        fn event_iterator_rejects_oversized_event_len_in_compressed_stream() {
            let temp = NamedTempFile::new().expect("create temp file");
            let path = temp.path();
            let mut file = std::fs::File::create(path).expect("create file");
            write_header_with_metadata(&mut file, CompressionMode::Lz4 { level: 1 });
            file.write_all(&1u64.to_le_bytes())
                .expect("write event count");

            let oversized_len = u32::try_from(MAX_EVENT_LEN + 1).expect("event limit fits in u32");
            let compressed = lz4_flex::compress_prepend_size(&oversized_len.to_le_bytes());
            let chunk_len = u32::try_from(compressed.len()).expect("compressed chunk fits in u32");
            file.write_all(&chunk_len.to_le_bytes())
                .expect("write chunk len");
            file.write_all(&compressed).expect("write chunk");
            file.flush().expect("flush");
            drop(file);

            let mut iter = TraceReader::open(path).expect("open reader").events();
            let first = iter
                .next()
                .expect("iterator should emit an error for oversized event len");
            assert!(
                matches!(
                    first,
                    Err(TraceFileError::OversizedField {
                        field: "event_len",
                        actual,
                        max,
                    }) if actual == (MAX_EVENT_LEN as u64) + 1 && max == MAX_EVENT_LEN as u64
                ),
                "got: {first:?}"
            );
        }
    }
}
