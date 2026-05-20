//! ATP Sink - High-Level Writer and Stream API
//!
//! Provides ergonomic APIs for writing large buffers, files, directories, and streams
//! to ATP with proper backpressure, cancellation, progress reporting, and proof handling.

pub mod buffer_sink;
pub mod object_sink;
pub mod stream_sink;
pub mod writer;

use crate::atp::object::{ContentId, ObjectId, ObjectKind};
use crate::cx::Cx;
use crate::types::outcome::Outcome;
use sha2::{Digest, Sha256};
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::time::{Duration, SystemTime};

/// High-level ATP writer interface for ergonomic large data transfer
pub trait AtpWriter {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Write a large buffer with automatic chunking and backpressure
    fn write_buffer(
        &mut self,
        cx: &Cx,
        data: &[u8],
        options: WriteOptions,
    ) -> impl Future<Output = Outcome<WriteResult, Self::Error>> + Send;

    /// Write a file with resume capability
    fn write_file(
        &mut self,
        cx: &Cx,
        file_path: &Path,
        options: WriteOptions,
    ) -> impl Future<Output = Outcome<WriteResult, Self::Error>> + Send;

    /// Write a directory tree with parallel chunking
    fn write_directory(
        &mut self,
        cx: &Cx,
        dir_path: &Path,
        options: WriteOptions,
    ) -> impl Future<Output = Outcome<WriteResult, Self::Error>> + Send;

    /// Write from a stream with unknown size
    fn write_stream<S>(
        &mut self,
        cx: &Cx,
        stream: S,
        options: WriteOptions,
    ) -> impl Future<Output = Outcome<WriteResult, Self::Error>> + Send
    where
        S: futures::Stream<Item = Result<Vec<u8>, Self::Error>> + Send + Unpin;

    /// Write an application-defined object
    fn write_object(
        &mut self,
        cx: &Cx,
        object: impl AtpObject,
        options: WriteOptions,
    ) -> impl Future<Output = Outcome<WriteResult, Self::Error>> + Send;

    /// Resume a previous transfer from a resume token
    fn resume_transfer(
        &mut self,
        cx: &Cx,
        resume_token: ResumeToken,
        options: WriteOptions,
    ) -> impl Future<Output = Outcome<WriteResult, Self::Error>> + Send;

    /// Get transfer progress for an ongoing operation
    fn get_progress(&self, transfer_id: TransferId) -> Option<TransferProgress>;

    /// Cancel a transfer and return stable state
    fn cancel_transfer(
        &mut self,
        transfer_id: TransferId,
    ) -> impl Future<Output = Outcome<CancellationResult, Self::Error>> + Send;
}

/// ATP sink for streaming data with backpressure
pub trait AtpSink {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Start a new streaming transfer
    fn start_stream(
        &mut self,
        cx: &Cx,
        options: StreamOptions,
    ) -> impl Future<Output = Outcome<StreamHandle, Self::Error>> + Send;

    /// Write chunk to active stream with backpressure
    fn write_chunk(
        &mut self,
        stream: &StreamHandle,
        chunk: &[u8],
    ) -> impl Future<Output = Outcome<ChunkAck, Self::Error>> + Send;

    /// Finish stream and get final proof
    fn finish_stream(
        &mut self,
        stream: StreamHandle,
    ) -> impl Future<Output = Outcome<WriteResult, Self::Error>> + Send;

    /// Query stream backpressure state
    fn backpressure_state(&self, stream: &StreamHandle) -> BackpressureState;
}

/// Options for write operations
#[derive(Debug, Clone)]
pub struct WriteOptions {
    /// Transfer priority (0 = highest, 255 = lowest)
    pub priority: u8,
    /// Enable progress reporting
    pub report_progress: bool,
    /// Progress reporting interval
    pub progress_interval: Duration,
    /// Enable early consumption of verified prefix
    pub allow_early_consumption: bool,
    /// Chunking strategy preference
    pub chunking_strategy: Option<ChunkingStrategy>,
    /// Compression preference
    pub compression: CompressionPreference,
    /// Encryption preference
    pub encryption: EncryptionPreference,
    /// Resume behavior
    pub resume_behavior: ResumeBehavior,
    /// Proof requirements
    pub proof_requirements: ProofRequirements,
    /// Timeout for the entire operation
    pub timeout: Option<Duration>,
    /// Custom metadata
    pub metadata: std::collections::HashMap<String, String>,
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self {
            priority: 128, // Medium priority
            report_progress: true,
            progress_interval: Duration::from_secs(1),
            allow_early_consumption: false,
            chunking_strategy: None, // Auto-select
            compression: CompressionPreference::Auto,
            encryption: EncryptionPreference::Required,
            resume_behavior: ResumeBehavior::EnableResume,
            proof_requirements: ProofRequirements::Standard,
            timeout: None,
            metadata: std::collections::HashMap::new(),
        }
    }
}

/// Options for streaming operations
#[derive(Debug, Clone)]
pub struct StreamOptions {
    /// Expected total size (if known)
    pub expected_size: Option<u64>,
    /// Maximum chunk size
    pub max_chunk_size: usize,
    /// Backpressure threshold
    pub backpressure_threshold: usize,
    /// Base write options
    pub write_options: WriteOptions,
}

impl Default for StreamOptions {
    fn default() -> Self {
        Self {
            expected_size: None,
            max_chunk_size: 64 * 1024,  // 64KB
            backpressure_threshold: 10, // 10 chunks
            write_options: WriteOptions::default(),
        }
    }
}

/// Result of a successful write operation
#[derive(Debug, Clone)]
pub struct WriteResult {
    /// Unique transfer identifier
    pub transfer_id: TransferId,
    /// Object identifier for the written data
    pub object_id: ObjectId,
    /// Final size in bytes
    pub total_bytes: u64,
    /// Number of chunks created
    pub chunk_count: u64,
    /// Transfer completion timestamp
    pub completed_at: SystemTime,
    /// Transfer proof bundle
    pub proof: TransferProof,
    /// Resume token (if applicable)
    pub resume_token: Option<ResumeToken>,
    /// Verified prefix length (for early consumption)
    pub verified_prefix_bytes: u64,
    /// Final object verification status
    pub verification_status: VerificationStatus,
    /// Transfer performance metrics
    pub metrics: TransferMetrics,
}

/// Per-chunk transfer evidence bound into the final proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkTransferProof {
    /// Zero-based chunk index in transfer order.
    pub chunk_index: u64,
    /// Byte offset in the logical object stream.
    pub byte_offset: u64,
    /// Chunk size in bytes.
    pub size_bytes: u64,
    /// Domain-separated SHA-256 digest of the chunk bytes and position.
    pub content_hash: [u8; 32],
}

/// Final proof bundle for a completed ATP sink transfer.
#[derive(Debug, Clone)]
pub struct TransferProof {
    /// Transfer that generated this proof.
    pub transfer_id: TransferId,
    /// Content-addressed object id derived from all transferred chunks.
    pub object_id: ObjectId,
    /// Domain-separated hash of the complete chunk transcript.
    pub content_hash: [u8; 32],
    /// Domain-separated Merkle-like root over chunk proofs.
    pub manifest_root: [u8; 32],
    /// Total transferred bytes covered by this proof.
    pub total_bytes: u64,
    /// Number of chunks covered by this proof.
    pub chunk_count: u64,
    /// Chunk-level evidence included in transfer order.
    pub chunks: Vec<ChunkTransferProof>,
    /// Proof creation time.
    pub completed_at: SystemTime,
}

impl TransferProof {
    /// Build a transfer proof from verified chunk records.
    #[must_use]
    pub fn from_chunk_proofs(
        transfer_id: TransferId,
        mut chunks: Vec<ChunkTransferProof>,
        completed_at: SystemTime,
    ) -> Self {
        chunks.sort_by_key(|chunk| chunk.chunk_index);

        let mut content_hasher = Sha256::new();
        content_hasher.update(b"asupersync.atp.sink.transfer.content.v1\0");
        content_hasher.update(transfer_id.0);

        let mut manifest_hasher = Sha256::new();
        manifest_hasher.update(b"asupersync.atp.sink.transfer.manifest.v1\0");
        manifest_hasher.update(transfer_id.0);

        let mut total_bytes = 0_u64;
        for chunk in &chunks {
            content_hasher.update(chunk.chunk_index.to_be_bytes());
            content_hasher.update(chunk.byte_offset.to_be_bytes());
            content_hasher.update(chunk.size_bytes.to_be_bytes());
            content_hasher.update(chunk.content_hash);

            manifest_hasher.update(chunk.chunk_index.to_be_bytes());
            manifest_hasher.update(chunk.byte_offset.to_be_bytes());
            manifest_hasher.update(chunk.size_bytes.to_be_bytes());
            manifest_hasher.update(chunk.content_hash);

            total_bytes = total_bytes.saturating_add(chunk.size_bytes);
        }

        let content_hash: [u8; 32] = content_hasher.finalize().into();
        let manifest_root: [u8; 32] = manifest_hasher.finalize().into();
        let chunk_count = chunks.len() as u64;

        Self {
            transfer_id,
            object_id: ObjectId::content(ContentId::new(content_hash)),
            content_hash,
            manifest_root,
            total_bytes,
            chunk_count,
            chunks,
            completed_at,
        }
    }
}

/// Transfer progress information
#[derive(Debug, Clone)]
pub struct TransferProgress {
    /// Transfer identifier
    pub transfer_id: TransferId,
    /// Bytes transferred so far
    pub bytes_transferred: u64,
    /// Total bytes (if known)
    pub total_bytes: Option<u64>,
    /// Chunks completed
    pub chunks_completed: u64,
    /// Chunks remaining (if known)
    pub chunks_remaining: Option<u64>,
    /// Current transfer rate (bytes/second)
    pub transfer_rate: f64,
    /// Estimated time remaining
    pub eta: Option<Duration>,
    /// Last progress update timestamp
    pub timestamp: SystemTime,
    /// Current operation phase
    pub phase: TransferPhase,
    /// Verified bytes available for early consumption
    pub verified_bytes: u64,
}

/// Transfer cancellation result
#[derive(Debug, Clone)]
pub struct CancellationResult {
    /// Transfer that was cancelled
    pub transfer_id: TransferId,
    /// Cancellation timestamp
    pub cancelled_at: SystemTime,
    /// Final state of the transfer
    pub final_state: CancellationState,
    /// Resume token for partial transfers
    pub resume_token: Option<ResumeToken>,
    /// Proof of partial completion
    pub partial_proof: Option<TransferProof>,
    /// Cleanup actions required
    pub cleanup_required: Vec<CleanupAction>,
}

/// Handle for active stream operations
#[derive(Debug, Clone)]
pub struct StreamHandle {
    /// Stream identifier
    pub stream_id: StreamId,
    /// Associated transfer ID
    pub transfer_id: TransferId,
    /// Maximum chunk size for this stream
    pub max_chunk_size: usize,
    /// Current sequence number
    pub sequence_number: u64,
}

/// Acknowledgment for written chunk
#[derive(Debug, Clone)]
pub struct ChunkAck {
    /// Sequence number that was acknowledged
    pub sequence_number: u64,
    /// Bytes acknowledged
    pub bytes_acked: u64,
    /// Current backpressure level
    pub backpressure_level: f32, // 0.0 = no pressure, 1.0 = at limit
    /// Estimated time to next ack availability
    pub next_ack_eta: Option<Duration>,
}

/// Backpressure state for flow control
#[derive(Debug, Clone)]
pub struct BackpressureState {
    /// Current queue depth
    pub queue_depth: usize,
    /// Maximum queue depth
    pub max_queue_depth: usize,
    /// Backpressure level (0.0 - 1.0)
    pub pressure_level: f32,
    /// Recommended delay before next write
    pub recommended_delay: Option<Duration>,
}

/// Application-defined object trait
pub trait AtpObject: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Get object kind
    fn object_kind(&self) -> ObjectKind;

    /// Get object size if known
    fn size_hint(&self) -> Option<u64>;

    /// Serialize object to chunks
    fn serialize_chunks(&self) -> impl Future<Output = Result<Vec<Vec<u8>>, Self::Error>> + Send;

    /// Get object metadata
    fn metadata(&self) -> std::collections::HashMap<String, String>;
}

/// Unique transfer identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransferId(pub [u8; 16]);

impl TransferId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().into_bytes())
    }
}

/// Unique stream identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(pub [u8; 16]);

impl StreamId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().into_bytes())
    }
}

/// Resume token for interrupted transfers
#[derive(Debug, Clone)]
pub struct ResumeToken {
    /// Transfer identifier
    pub transfer_id: TransferId,
    /// Checkpoint data
    pub checkpoint_data: Vec<u8>,
    /// Resume expiration
    pub expires_at: SystemTime,
    /// Required capabilities for resume
    pub required_capabilities: Vec<String>,
}

/// Chunking strategy preferences
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkingStrategy {
    /// Fixed-size chunks for maximum throughput
    FixedSize,
    /// Content-defined chunking for deduplication
    ContentDefined,
    /// Adaptive chunking based on data type
    Adaptive,
    /// Application-specific chunking
    ApplicationDefined,
}

/// Compression preference
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionPreference {
    /// No compression
    None,
    /// Automatic compression based on content type
    Auto,
    /// Force compression even if not beneficial
    Force,
    /// Specific compression algorithm
    Algorithm(&'static str),
}

/// Encryption preference
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionPreference {
    /// No encryption (not recommended)
    None,
    /// Required encryption (default)
    Required,
    /// Opportunistic encryption
    Opportunistic,
}

/// Resume behavior options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeBehavior {
    /// Enable resume capability (default)
    EnableResume,
    /// Disable resume for ephemeral transfers
    DisableResume,
    /// Resume only if explicitly requested
    ResumeOnDemand,
}

/// Proof requirements
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofRequirements {
    /// Standard proof level
    Standard,
    /// Enhanced proof with additional verification
    Enhanced,
    /// Minimal proof for low-stakes transfers
    Minimal,
    /// No proof required (not recommended)
    None,
}

/// Transfer phase indicators
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferPhase {
    /// Initializing transfer
    Initializing,
    /// Chunking data
    Chunking,
    /// Transferring chunks
    Transferring,
    /// Verifying integrity
    Verifying,
    /// Finalizing transfer
    Finalizing,
    /// Completed successfully
    Completed,
}

/// Verification status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    /// Verification pending
    Pending,
    /// Verification passed
    Verified,
    /// Verification failed
    Failed,
    /// Verification skipped
    Skipped,
}

/// Cancellation state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancellationState {
    /// Clean cancellation with no side effects
    Clean,
    /// Cancellation with resumable state
    Resumable,
    /// Cancellation with quarantined temporary state
    Quarantined,
    /// Cancellation with partial completion
    PartiallyCompleted,
}

/// Cleanup actions required after cancellation
#[derive(Debug, Clone)]
pub enum CleanupAction {
    /// Remove temporary files
    RemoveTemporaryFiles(Vec<std::path::PathBuf>),
    /// Clear cache entries
    ClearCacheEntries(Vec<String>),
    /// Release resources
    ReleaseResources(Vec<String>),
    /// Notify peers of cancellation
    NotifyPeers(Vec<String>),
}

/// Transfer performance metrics
#[derive(Debug, Clone)]
pub struct TransferMetrics {
    /// Total transfer duration
    pub duration: Duration,
    /// Average transfer rate (bytes/second)
    pub avg_transfer_rate: f64,
    /// Peak transfer rate
    pub peak_transfer_rate: f64,
    /// Time spent in each phase
    pub phase_durations: std::collections::HashMap<TransferPhase, Duration>,
    /// Network round-trips required
    pub round_trips: u64,
    /// Retransmissions required
    pub retransmissions: u64,
    /// Compression ratio achieved
    pub compression_ratio: f32,
    /// Deduplication savings
    pub deduplication_savings: u64,
}

/// Errors that can occur during write operations
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error("Transfer cancelled by user")]
    Cancelled,

    #[error("Transfer timed out after {duration:?}")]
    Timeout { duration: Duration },

    #[error("Insufficient space: need {required} bytes, have {available} bytes")]
    InsufficientSpace { required: u64, available: u64 },

    #[error("Permission denied: {reason}")]
    PermissionDenied { reason: String },

    #[error("Network error: {source}")]
    NetworkError {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Verification failed: {reason}")]
    VerificationFailed { reason: String },

    #[error("Resume failed: {reason}")]
    ResumeFailed { reason: String },

    #[error("Backpressure exceeded: {current_depth}/{max_depth}")]
    BackpressureExceeded {
        current_depth: usize,
        max_depth: usize,
    },

    #[error("Invalid transfer ID: {transfer_id:?}")]
    InvalidTransferId { transfer_id: TransferId },

    #[error("Transfer already completed")]
    AlreadyCompleted,

    #[error("Transfer not found")]
    TransferNotFound,

    #[error("Invalid resume token")]
    InvalidResumeToken,

    #[error("Quota exceeded: {current}/{limit} bytes")]
    QuotaExceeded { current: u64, limit: u64 },

    #[error("Internal error: {message}")]
    Internal { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_id_creation() {
        let id1 = TransferId::new();
        let id2 = TransferId::new();
        assert_ne!(id1, id2);
        assert_eq!(id1.0.len(), 16);
    }

    #[test]
    fn test_write_options_default() {
        let options = WriteOptions::default();
        assert_eq!(options.priority, 128);
        assert_eq!(options.report_progress, true);
        assert_eq!(options.compression, CompressionPreference::Auto);
        assert_eq!(options.encryption, EncryptionPreference::Required);
    }

    #[test]
    fn test_stream_options_default() {
        let options = StreamOptions::default();
        assert_eq!(options.max_chunk_size, 64 * 1024);
        assert_eq!(options.backpressure_threshold, 10);
        assert_eq!(options.expected_size, None);
    }

    #[test]
    fn test_backpressure_calculation() {
        let state = BackpressureState {
            queue_depth: 7,
            max_queue_depth: 10,
            pressure_level: 0.7,
            recommended_delay: Some(Duration::from_millis(100)),
        };

        assert_eq!(state.pressure_level, 0.7);
        assert!(state.recommended_delay.is_some());
    }
}
