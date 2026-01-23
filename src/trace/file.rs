//! Trace file format for persisting and loading replay traces.
//!
//! This module provides a binary file format for saving traces to disk and
//! loading them for replay. The format is designed for:
//!
//! - **Compactness**: Uses MessagePack for efficient binary encoding
//! - **Versioning**: Format version in header for forward compatibility
//! - **Streaming**: Events can be read incrementally without loading all into memory
//! - **Compression**: Optional LZ4 compression for reduced storage (feature-gated)
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
//! | Metadata (msgpack)|  TraceMetadata
//! +-------------------+
//! | Event count (8 b) |  u64 little-endian
//! +-------------------+
//! | Events (msgpack)  |  [ReplayEvent] length-prefixed (optionally compressed)
//! +-------------------+
//! ```
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

use super::recorder::{LimitAction, LimitKind, LimitReached, DEFAULT_MAX_FILE_SIZE};
use super::replay::{ReplayEvent, TraceMetadata, REPLAY_SCHEMA_VERSION};
use crate::tracing_compat::{error, warn};
use libc::ENOSPC;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

// =============================================================================
// Constants
// =============================================================================

/// Magic bytes at the start of every trace file.
pub const TRACE_MAGIC: &[u8; 11] = b"ASUPERTRACE";

/// Current file format version.
/// Version 2 adds compression byte after flags.
pub const TRACE_FILE_VERSION: u16 = 2;

/// Flag: Events are LZ4 compressed.
pub const FLAG_COMPRESSED: u16 = 0x0001;

/// Header size (magic + version + flags + compression + meta_len).
pub const HEADER_SIZE: usize = 11 + 2 + 2 + 1 + 4;

/// Default chunk size for streaming compression (64KB).
pub const DEFAULT_COMPRESSION_CHUNK_SIZE: usize = 64 * 1024;

/// Threshold for auto-compression (1MB).
pub const AUTO_COMPRESSION_THRESHOLD: usize = 1024 * 1024;

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
    fn to_byte(&self) -> u8 {
        match self {
            Self::None => 0,
            #[cfg(feature = "trace-compression")]
            Self::Lz4 { .. } | Self::Auto => 1,
        }
    }

    /// Creates a compression mode from the header byte.
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
    #[error("unsupported file version: expected <= {expected}, found {found}")]
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

    /// File is truncated or corrupt.
    #[error("file truncated or corrupt")]
    Truncated,
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
    finished: bool,
    config: TraceFileConfig,
    bytes_written: u64,
    buffered_bytes: u64,
    stopped: bool,
    halted: bool,
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
        let writer = BufWriter::new(file);

        Ok(Self {
            writer,
            event_count: 0,
            event_count_pos: 0,
            finished: false,
            config,
            bytes_written: 0,
            buffered_bytes: 0,
            stopped: false,
            halted: false,
            #[cfg(feature = "trace-compression")]
            event_buffer: Vec::new(),
        })
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

    fn handle_limit(&mut self, info: LimitReached) -> TraceFileResult<bool> {
        let mut action = self.resolve_limit_action(&info);
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
        err.raw_os_error() == Some(ENOSPC)
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

    fn update_event_count(&mut self) -> TraceFileResult<()> {
        let file = self.writer.get_mut();
        file.seek(SeekFrom::Start(self.event_count_pos))?;
        file.write_all(&self.event_count.to_le_bytes())?;
        file.flush()?;
        Ok(())
    }

    fn update_event_count_best_effort(&mut self) {
        if let Err(err) = self.update_event_count() {
            if let TraceFileError::Io(io_err) = &err {
                if Self::is_disk_full(io_err) {
                    warn!("trace event count update skipped: disk full");
                }
            }
            warn!("trace event count update skipped: {err}");
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

        // Serialize metadata to get its length
        let meta_bytes = rmp_serde::to_vec(metadata)?;

        // Determine flags
        let flags = if self.config.compression.is_compressed() {
            FLAG_COMPRESSED
        } else {
            0
        };

        // Write header
        self.write_bytes(TRACE_MAGIC)?;
        self.write_bytes(&TRACE_FILE_VERSION.to_le_bytes())?;
        self.write_bytes(&flags.to_le_bytes())?;
        self.write_bytes(&[self.config.compression.to_byte()])?; // compression byte

        // Write metadata length and data
        let meta_len = meta_bytes.len() as u32;
        self.write_bytes(&meta_len.to_le_bytes())?;
        self.write_bytes(&meta_bytes)?;

        // Write placeholder for event count (we'll update this in finish())
        self.event_count_pos = HEADER_SIZE as u64 + u64::from(meta_len);
        self.write_bytes(&0u64.to_le_bytes())?;

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
                if !self.handle_limit(info)? {
                    return Ok(());
                }
            }
        }

        // Serialize event with length prefix
        let event_bytes = rmp_serde::to_vec(event)?;
        let len = event_bytes.len() as u32;
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
            if !self.handle_limit(info)? {
                return Ok(());
            }
        }

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

        // Compress the buffer
        let compressed = lz4_flex::compress_prepend_size(&self.event_buffer);

        // Write chunk: compressed_len (u32) + compressed_data
        let chunk_len = compressed.len() as u32;
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
        self.finished = true;

        // Flush any remaining compressed data
        #[cfg(feature = "trace-compression")]
        if self.config.compression.is_compressed() {
            self.flush_compressed_chunk()?;
        }

        if self.halted {
            let _ = self.writer.flush();
            self.update_event_count_best_effort();
            return Ok(());
        }

        // Flush buffered data
        self.writer.flush()?;

        // Seek back and update event count
        self.update_event_count()?;

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
            // Best-effort: try to flush but don't panic
            let _ = self.writer.flush();
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
pub struct TraceReader {
    reader: BufReader<File>,
    metadata: TraceMetadata,
    event_count: u64,
    events_read: u64,
    events_start_pos: u64,
    compression: CompressionMode,
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
        if version > TRACE_FILE_VERSION {
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

        // Read compression byte (only in version 2+)
        let compression = if version >= 2 {
            let mut comp_byte = [0u8; 1];
            reader.read_exact(&mut comp_byte)?;
            match CompressionMode::from_byte(comp_byte[0]) {
                Some(mode) => mode,
                None if is_compressed => {
                    return Err(TraceFileError::UnsupportedCompression(comp_byte[0]))
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

        // Check if we can handle compression
        #[cfg(not(feature = "trace-compression"))]
        if compression.is_compressed() {
            return Err(TraceFileError::CompressionNotAvailable);
        }

        // Read metadata length
        let mut meta_len_bytes = [0u8; 4];
        reader.read_exact(&mut meta_len_bytes)?;
        let meta_len = u32::from_le_bytes(meta_len_bytes) as usize;

        // Read metadata
        let mut meta_bytes = vec![0u8; meta_len];
        reader.read_exact(&mut meta_bytes)?;
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

        // Calculate events start position (header size depends on version)
        let header_size = if version >= 2 {
            HEADER_SIZE
        } else {
            HEADER_SIZE - 1
        };
        let events_start_pos = header_size as u64 + meta_len as u64 + 8;

        Ok(Self {
            reader,
            metadata,
            event_count,
            events_read: 0,
            events_start_pos,
            compression,
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
        if self.reader.read_exact(&mut len_bytes).is_err() {
            return Ok(None);
        }
        let len = u32::from_le_bytes(len_bytes) as usize;

        // Read event data
        let mut event_bytes = vec![0u8; len];
        self.reader.read_exact(&mut event_bytes)?;

        let event: ReplayEvent = rmp_serde::from_slice(&event_bytes)?;
        self.events_read += 1;

        Ok(Some(event))
    }

    /// Reads an event from compressed data.
    #[cfg(feature = "trace-compression")]
    fn read_compressed_event(&mut self) -> TraceFileResult<Option<ReplayEvent>> {
        // Refill buffer if needed
        if self.buffer_pos >= self.decompressed_buffer.len() {
            if !self.refill_decompressed_buffer()? {
                return Ok(None);
            }
        }

        // Read event length from buffer
        if self.buffer_pos + 4 > self.decompressed_buffer.len() {
            return Err(TraceFileError::Truncated);
        }
        let len_bytes: [u8; 4] = self.decompressed_buffer[self.buffer_pos..self.buffer_pos + 4]
            .try_into()
            .map_err(|_| TraceFileError::Truncated)?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        self.buffer_pos += 4;

        // Read event data from buffer
        if self.buffer_pos + len > self.decompressed_buffer.len() {
            return Err(TraceFileError::Truncated);
        }
        let event_bytes = &self.decompressed_buffer[self.buffer_pos..self.buffer_pos + len];
        let event: ReplayEvent = rmp_serde::from_slice(event_bytes)?;
        self.buffer_pos += len;

        self.events_read += 1;
        Ok(Some(event))
    }

    /// Refills the decompressed buffer from the next compressed chunk.
    #[cfg(feature = "trace-compression")]
    fn refill_decompressed_buffer(&mut self) -> TraceFileResult<bool> {
        // Read chunk length
        let mut chunk_len_bytes = [0u8; 4];
        match self.reader.read_exact(&mut chunk_len_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(e) => return Err(TraceFileError::Io(e)),
        }
        let chunk_len = u32::from_le_bytes(chunk_len_bytes) as usize;

        if chunk_len == 0 {
            return Ok(false);
        }

        // Read compressed chunk
        let mut compressed = vec![0u8; chunk_len];
        self.reader.read_exact(&mut compressed)?;

        // Decompress
        self.decompressed_buffer = lz4_flex::decompress_size_prepended(&compressed)
            .map_err(|e| TraceFileError::Decompression(e.to_string()))?;
        self.buffer_pos = 0;

        Ok(true)
    }

    /// Resets the reader to the beginning of the events section.
    ///
    /// # Errors
    ///
    /// Returns an error if seeking fails.
    pub fn rewind(&mut self) -> TraceFileResult<()> {
        self.reader.seek(SeekFrom::Start(self.events_start_pos))?;
        self.events_read = 0;

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
        let mut events = Vec::with_capacity(self.event_count as usize);
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
    compression: CompressionMode,
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
            return self.next_compressed();
        }

        self.next_uncompressed()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.remaining as usize;
        (remaining, Some(remaining))
    }
}

impl TraceEventIterator {
    /// Reads the next uncompressed event.
    fn next_uncompressed(&mut self) -> Option<TraceFileResult<ReplayEvent>> {
        // Read event length
        let mut len_bytes = [0u8; 4];
        if let Err(e) = self.reader.read_exact(&mut len_bytes) {
            if e.kind() == io::ErrorKind::UnexpectedEof {
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

        match rmp_serde::from_slice(&event_bytes) {
            Ok(event) => {
                self.remaining -= 1;
                Some(Ok(event))
            }
            Err(e) => Some(Err(TraceFileError::from(e))),
        }
    }

    /// Reads the next compressed event.
    #[cfg(feature = "trace-compression")]
    fn next_compressed(&mut self) -> Option<TraceFileResult<ReplayEvent>> {
        // Refill buffer if needed
        if self.buffer_pos >= self.decompressed_buffer.len() {
            match self.refill_buffer() {
                Ok(true) => {}
                Ok(false) => return None,
                Err(e) => return Some(Err(e)),
            }
        }

        // Read event length from buffer
        if self.buffer_pos + 4 > self.decompressed_buffer.len() {
            return Some(Err(TraceFileError::Truncated));
        }
        let len_bytes: [u8; 4] =
            match self.decompressed_buffer[self.buffer_pos..self.buffer_pos + 4].try_into() {
                Ok(b) => b,
                Err(_) => return Some(Err(TraceFileError::Truncated)),
            };
        let len = u32::from_le_bytes(len_bytes) as usize;
        self.buffer_pos += 4;

        // Read event data from buffer
        if self.buffer_pos + len > self.decompressed_buffer.len() {
            return Some(Err(TraceFileError::Truncated));
        }
        let event_bytes = &self.decompressed_buffer[self.buffer_pos..self.buffer_pos + len];

        match rmp_serde::from_slice(event_bytes) {
            Ok(event) => {
                self.buffer_pos += len;
                self.remaining -= 1;
                Some(Ok(event))
            }
            Err(e) => Some(Err(TraceFileError::from(e))),
        }
    }

    /// Refills the decompressed buffer from the next compressed chunk.
    #[cfg(feature = "trace-compression")]
    fn refill_buffer(&mut self) -> TraceFileResult<bool> {
        // Read chunk length
        let mut chunk_len_bytes = [0u8; 4];
        match self.reader.read_exact(&mut chunk_len_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(e) => return Err(TraceFileError::Io(e)),
        }
        let chunk_len = u32::from_le_bytes(chunk_len_bytes) as usize;

        if chunk_len == 0 {
            return Ok(false);
        }

        // Read compressed chunk
        let mut compressed = vec![0u8; chunk_len];
        self.reader.read_exact(&mut compressed)?;

        // Decompress
        self.decompressed_buffer = lz4_flex::decompress_size_prepended(&compressed)
            .map_err(|e| TraceFileError::Decompression(e.to_string()))?;
        self.buffer_pos = 0;

        Ok(true)
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
pub fn write_trace(
    path: impl AsRef<Path>,
    metadata: &TraceMetadata,
    events: &[ReplayEvent],
) -> TraceFileResult<()> {
    let mut writer = TraceWriter::create(path)?;
    writer.write_metadata(metadata)?;
    for event in events {
        writer.write_event(event)?;
    }
    writer.finish()
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

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::replay::CompactTaskId;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
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
                panic!("unexpected event type");
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
        let bytes_per_event = file_size as f64 / 1000.0;

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
        let header_bytes = HEADER_SIZE as u64 + meta_len + 8;

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

        let result = writer.write_metadata(&TraceMetadata::new(42));
        assert!(matches!(
            result,
            Err(TraceFileError::Io(err)) if err.raw_os_error() == Some(ENOSPC)
        ));
    }

    // =========================================================================
    // Compression Tests (feature-gated)
    // =========================================================================

    #[cfg(feature = "trace-compression")]
    mod compression_tests {
        use super::*;

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
                    panic!("unexpected event type");
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

            let ratio = uncompressed_size as f64 / compressed_size as f64;
            println!(
                "Compression ratio: {:.2}x ({} -> {} bytes)",
                ratio, uncompressed_size, compressed_size
            );

            // LZ4 should achieve at least 2x compression on this repetitive data
            assert!(
                ratio > 2.0,
                "Compression ratio {:.2}x is below expected 2x minimum",
                ratio
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
    }
}
