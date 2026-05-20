//! ATP Writer/Sink API for ergonomic large buffer and stream handling.
//!
//! This module provides the high-level writer and sink interfaces that give users
//! the simple write(really_big_buffer) experience while preserving ATP correctness,
//! structured concurrency, and explicit cancellation semantics.

use crate::atp::manifest::{ManifestVersion, MerkleRoot};
use crate::atp::object::ObjectId;
use crate::atp::transfer::TransferId;
use crate::cx::Cx;
use crate::fs::File;
use crate::net::atp::protocol::outcome::{AtpError, AtpOutcome, DiskError, ProtocolError};
use crate::types::outcome::Outcome;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

const MAX_FILE_STREAM_CHUNK_LEN: usize = 8 * 1024 * 1024;

/// ATP writer configuration for large buffer operations.
#[derive(Debug, Clone)]
pub struct WriterConfig {
    /// Target chunk size for content-defined chunking.
    pub chunk_size: u64,
    /// Minimum chunk size boundary.
    pub min_chunk_size: u64,
    /// Maximum chunk size boundary.
    pub max_chunk_size: u64,
    /// Enable progress reporting.
    pub enable_progress: bool,
    /// Backpressure threshold (bytes).
    pub backpressure_threshold: u64,
    /// Maximum concurrent chunks in flight.
    pub max_concurrent_chunks: usize,
    /// Proof generation mode.
    pub proof_mode: ProofMode,
    /// Resume journal persistence.
    pub enable_resume: bool,
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            chunk_size: 256 * 1024,          // 256KB default
            min_chunk_size: 64 * 1024,       // 64KB minimum
            max_chunk_size: 2 * 1024 * 1024, // 2MB maximum
            enable_progress: true,
            backpressure_threshold: 16 * 1024 * 1024, // 16MB
            max_concurrent_chunks: 8,
            proof_mode: ProofMode::Full,
            enable_resume: true,
        }
    }
}

/// Proof generation modes for ATP transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofMode {
    /// Generate full cryptographic proof bundle.
    Full,
    /// Generate lightweight verification metadata only.
    Lightweight,
    /// Skip proof generation (for testing only).
    None,
}

/// ATP writer for ergonomic large buffer streaming.
pub struct AtpWriter {
    /// Writer identifier.
    pub id: String,
    /// Target object ID.
    pub object_id: ObjectId,
    /// Remote peer identifier.
    pub remote_peer: [u8; 32],
    /// Writer configuration.
    config: WriterConfig,
    /// Current state.
    state: WriterState,
    /// Buffered data waiting to be sent.
    buffer: Vec<u8>,
    /// Total bytes written.
    bytes_written: u64,
    /// Transfer handle for this writer.
    transfer_id: Option<TransferId>,
    /// Progress callback.
    progress_callback: Option<Arc<dyn Fn(WriterProgress) + Send + Sync>>,
    /// Resume token for interrupted transfers.
    resume_token: Option<ResumeToken>,
}

/// ATP writer state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterState {
    /// Writer is ready to accept data.
    Ready,
    /// Writer is actively streaming data.
    Streaming,
    /// Writer is applying backpressure.
    Backpressure,
    /// Writer is finalizing transfer.
    Finalizing,
    /// Writer has completed successfully.
    Completed,
    /// Writer was cancelled.
    Cancelled,
    /// Writer encountered an error.
    Error,
}

/// Progress information for ATP writers.
#[derive(Debug, Clone)]
pub struct WriterProgress {
    /// Total bytes written.
    pub bytes_written: u64,
    /// Total bytes expected (if known).
    pub total_bytes: Option<u64>,
    /// Current transfer rate (bytes/sec).
    pub transfer_rate_bps: f64,
    /// Estimated completion time.
    pub estimated_completion: Option<SystemTime>,
    /// Number of chunks completed.
    pub chunks_completed: u64,
    /// Number of chunks in flight.
    pub chunks_in_flight: u64,
    /// Current writer state.
    pub state: WriterState,
}

/// Resume token for interrupted ATP transfers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeToken {
    /// Transfer identifier.
    pub transfer_id: TransferId,
    /// Object identifier.
    pub object_id: ObjectId,
    /// Bytes verified so far.
    pub verified_bytes: u64,
    /// Manifest root at pause time.
    pub manifest_root: MerkleRoot,
    /// Journal position for resume.
    pub journal_position: u64,
    /// Token creation time.
    pub created_at: SystemTime,
    /// Token expiry time.
    pub expires_at: SystemTime,
}

impl ResumeToken {
    /// Check if this resume token is still valid.
    pub fn is_valid(&self) -> bool {
        SystemTime::now() < self.expires_at
    }

    /// Get the amount of data that can be skipped on resume.
    pub fn verified_offset(&self) -> u64 {
        self.verified_bytes
    }
}

/// Final proof bundle for completed ATP transfers.
#[derive(Debug, Clone)]
pub struct TransferProof {
    /// Transfer that generated this proof.
    pub transfer_id: TransferId,
    /// Final object identifier.
    pub object_id: ObjectId,
    /// Verified object hash.
    pub verified_hash: [u8; 32],
    /// Total bytes transferred.
    pub total_bytes: u64,
    /// Manifest version used.
    pub manifest_version: ManifestVersion,
    /// Final manifest root.
    pub manifest_root: MerkleRoot,
    /// Transfer completion time.
    pub completed_at: SystemTime,
    /// Proof generation mode used.
    pub proof_mode: ProofMode,
    /// Cryptographic signatures (if generated).
    pub signatures: Vec<u8>,
}

impl AtpWriter {
    /// Create a new ATP writer for the given object and remote peer.
    pub fn new(object_id: ObjectId, remote_peer: [u8; 32], config: WriterConfig) -> Self {
        let id = format!(
            "writer-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );

        Self {
            id,
            object_id,
            remote_peer,
            config,
            state: WriterState::Ready,
            buffer: Vec::new(),
            bytes_written: 0,
            transfer_id: None,
            progress_callback: None,
            resume_token: None,
        }
    }

    /// Create a new ATP writer from a resume token.
    pub fn from_resume_token(
        resume_token: ResumeToken,
        remote_peer: [u8; 32],
        config: WriterConfig,
    ) -> AtpOutcome<Self> {
        if !resume_token.is_valid() {
            return Outcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch));
        }

        let id = format!("writer-resumed-{:?}", resume_token.transfer_id);

        let writer = Self {
            id,
            object_id: resume_token.object_id.clone(),
            remote_peer,
            config,
            state: WriterState::Ready,
            buffer: Vec::new(),
            bytes_written: resume_token.verified_bytes,
            transfer_id: Some(resume_token.transfer_id),
            progress_callback: None,
            resume_token: Some(resume_token),
        };

        Outcome::ok(writer)
    }

    /// Set a progress callback for this writer.
    pub fn set_progress_callback<F>(&mut self, callback: F)
    where
        F: Fn(WriterProgress) + Send + Sync + 'static,
    {
        self.progress_callback = Some(Arc::new(callback));
    }

    /// Get current writer state.
    pub fn state(&self) -> WriterState {
        self.state
    }

    /// Get current progress information.
    pub fn progress(&self) -> WriterProgress {
        WriterProgress {
            bytes_written: self.bytes_written,
            total_bytes: None,      // Unknown for streaming
            transfer_rate_bps: 0.0, // TODO: Calculate from recent history
            estimated_completion: None,
            chunks_completed: self.bytes_written / self.config.chunk_size,
            chunks_in_flight: 0, // TODO: Track from transfer state
            state: self.state,
        }
    }

    /// Write data to the ATP stream with backpressure handling.
    pub async fn write_all(&mut self, cx: &Cx, data: &[u8]) -> AtpOutcome<usize> {
        cx.trace(&format!("atp_writer_write {} bytes", data.len()));

        if self.state == WriterState::Cancelled || self.state == WriterState::Error {
            return Outcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch));
        }

        // Initialize transfer on first write
        if self.transfer_id.is_none() {
            match self.initialize_transfer(cx).await {
                Outcome::Ok(()) => {}
                Outcome::Err(e) => return Outcome::Err(e),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
        }

        // Check for backpressure
        if self.buffer.len() + data.len() > self.config.backpressure_threshold as usize {
            self.state = WriterState::Backpressure;
            match self.flush_buffer(cx).await {
                Outcome::Ok(()) => {}
                Outcome::Err(e) => return Outcome::Err(e),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
        }

        // Buffer the data
        self.buffer.extend_from_slice(data);
        self.state = WriterState::Streaming;

        // Emit progress if enabled
        if self.config.enable_progress {
            if let Some(callback) = &self.progress_callback {
                callback(self.progress());
            }
        }

        Outcome::ok(data.len())
    }

    /// Write a complete buffer in one operation.
    pub async fn write_buffer(&mut self, cx: &Cx, buffer: &[u8]) -> AtpOutcome<TransferProof> {
        cx.trace(&format!("atp_writer_write_buffer {} bytes", buffer.len()));

        // Write all data
        match self.write_all(cx, buffer).await {
            Outcome::Ok(_) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };

        // Finalize the transfer
        self.finalize(cx).await
    }

    /// Write data from a file path.
    pub async fn write_file<P: AsRef<Path>>(
        &mut self,
        cx: &Cx,
        path: P,
    ) -> AtpOutcome<TransferProof> {
        let path = path.as_ref();
        cx.trace(&format!("atp_writer_write_file {:?}", path));

        let mut file = match File::open(path).await {
            Ok(file) => file,
            Err(_) => return Outcome::Err(AtpError::Disk(DiskError::IoError)),
        };

        let mut chunk = vec![0; self.file_stream_chunk_len()];
        loop {
            let bytes_read = match file.read_into_vec(chunk).await {
                Ok((buffer, bytes_read)) => {
                    chunk = buffer;
                    bytes_read
                }
                Err(_) => return Outcome::Err(AtpError::Disk(DiskError::IoError)),
            };

            if bytes_read == 0 {
                break;
            }

            match self.write_all(cx, &chunk[..bytes_read]).await {
                Outcome::Ok(_) => {}
                Outcome::Err(e) => return Outcome::Err(e),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
        }

        self.finalize(cx).await
    }

    /// Finalize the transfer and get the proof bundle.
    pub async fn finalize(&mut self, cx: &Cx) -> AtpOutcome<TransferProof> {
        cx.trace("atp_writer_finalize");

        if self.state == WriterState::Cancelled || self.state == WriterState::Error {
            return Outcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch));
        }

        self.state = WriterState::Finalizing;

        // Flush any remaining buffered data
        if !self.buffer.is_empty() {
            match self.flush_buffer(cx).await {
                Outcome::Ok(()) => {}
                Outcome::Err(e) => return Outcome::Err(e),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
        }

        // Generate final proof
        let proof = match self.generate_proof(cx).await {
            Outcome::Ok(proof) => proof,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };

        self.state = WriterState::Completed;

        // Emit final progress
        if self.config.enable_progress {
            if let Some(callback) = &self.progress_callback {
                callback(self.progress());
            }
        }

        Outcome::ok(proof)
    }

    /// Cancel the transfer and clean up resources.
    pub async fn cancel(&mut self, cx: &Cx) -> AtpOutcome<ResumeToken> {
        cx.trace("atp_writer_cancel");

        self.state = WriterState::Cancelled;

        // Generate and store resume token if resume is enabled
        if self.config.enable_resume {
            let resume_token = ResumeToken {
                transfer_id: self.transfer_id.unwrap_or_else(|| {
                    TransferId::derive([0; 32], self.remote_peer, [0; 32], [0; 32])
                }),
                object_id: self.object_id.clone(),
                verified_bytes: self.bytes_written,
                manifest_root: MerkleRoot::zero(), // TODO: Get actual manifest root
                journal_position: self.bytes_written,
                created_at: SystemTime::now(),
                expires_at: SystemTime::now() + Duration::from_secs(24 * 3600), // 24 hours
            };

            // Store the token to ensure consistency
            self.resume_token = Some(resume_token.clone());
            Outcome::ok(resume_token)
        } else {
            // Return empty resume token
            let resume_token = ResumeToken {
                transfer_id: self.transfer_id.unwrap_or_else(|| {
                    TransferId::derive([0; 32], self.remote_peer, [0; 32], [0; 32])
                }),
                object_id: self.object_id.clone(),
                verified_bytes: 0,
                manifest_root: MerkleRoot::zero(),
                journal_position: 0,
                created_at: SystemTime::now(),
                expires_at: SystemTime::now(), // Immediately expired
            };

            Outcome::ok(resume_token)
        }
    }

    /// Get the current resume token for this writer.
    pub fn resume_token(&mut self) -> Option<ResumeToken> {
        // Return existing token if available
        if let Some(resume_token) = &self.resume_token {
            return Some(resume_token.clone());
        }

        // Create and store token if resume is enabled and transfer is active
        if self.config.enable_resume && self.transfer_id.is_some() {
            let resume_token = ResumeToken {
                transfer_id: self.transfer_id.unwrap(),
                object_id: self.object_id.clone(),
                verified_bytes: self.bytes_written,
                manifest_root: MerkleRoot::zero(), // TODO: Get actual manifest root
                journal_position: self.bytes_written,
                created_at: SystemTime::now(),
                expires_at: SystemTime::now() + Duration::from_secs(24 * 3600), // 24 hours
            };

            // Store the token to ensure consistency on subsequent calls
            self.resume_token = Some(resume_token.clone());
            Some(resume_token)
        } else {
            None
        }
    }

    // Private methods

    fn file_stream_chunk_len(&self) -> usize {
        let max_chunk_size = self.config.max_chunk_size.max(1);
        let hard_limit = match u64::try_from(MAX_FILE_STREAM_CHUNK_LEN) {
            Ok(limit) => limit,
            Err(_) => u64::MAX,
        };
        let target_chunk_size = self
            .config
            .chunk_size
            .max(self.config.min_chunk_size)
            .min(max_chunk_size)
            .min(self.config.backpressure_threshold.max(1))
            .min(hard_limit)
            .max(1);

        match usize::try_from(target_chunk_size) {
            Ok(chunk_len) => chunk_len,
            Err(_) => MAX_FILE_STREAM_CHUNK_LEN,
        }
    }

    async fn initialize_transfer(&mut self, cx: &Cx) -> AtpOutcome<()> {
        cx.trace("atp_writer_initialize_transfer");

        // Generate transfer ID
        let transfer_id = TransferId::derive(
            [0; 32], // TODO: Get local peer ID
            self.remote_peer,
            [0; 32], // TODO: Generate nonce
            [0; 32], // TODO: Calculate manifest root
        );

        self.transfer_id = Some(transfer_id);

        // TODO: Initiate actual ATP protocol handshake
        // 1. Send transfer offer
        // 2. Wait for acceptance
        // 3. Begin chunk streaming

        Outcome::ok(())
    }

    async fn flush_buffer(&mut self, cx: &Cx) -> AtpOutcome<()> {
        cx.trace(&format!(
            "atp_writer_flush_buffer {} bytes",
            self.buffer.len()
        ));

        if self.buffer.is_empty() {
            return Outcome::ok(());
        }

        // TODO: Implement actual chunk transmission
        // 1. Split buffer into chunks based on config
        // 2. Send chunks with ATP protocol
        // 3. Wait for acknowledgments
        // 4. Update progress

        self.bytes_written += self.buffer.len() as u64;
        self.buffer.clear();

        Outcome::ok(())
    }

    async fn generate_proof(&self, cx: &Cx) -> AtpOutcome<TransferProof> {
        cx.trace("atp_writer_generate_proof");

        // TODO: Generate actual proof bundle
        // 1. Finalize manifest
        // 2. Compute final hashes
        // 3. Generate cryptographic signatures
        // 4. Create proof bundle

        let proof = TransferProof {
            transfer_id: self
                .transfer_id
                .unwrap_or_else(|| TransferId::derive([0; 32], self.remote_peer, [0; 32], [0; 32])),
            object_id: self.object_id.clone(),
            verified_hash: [0; 32], // TODO: Compute actual hash
            total_bytes: self.bytes_written,
            manifest_version: ManifestVersion::CURRENT,
            manifest_root: MerkleRoot::zero(), // TODO: Get actual root
            completed_at: SystemTime::now(),
            proof_mode: self.config.proof_mode,
            signatures: vec![], // TODO: Generate signatures
        };

        Outcome::ok(proof)
    }
}

/// ATP sink for streaming data with backpressure.
pub struct AtpSink {
    writer: AtpWriter,
}

impl AtpSink {
    /// Create a new ATP sink.
    pub fn new(object_id: ObjectId, remote_peer: [u8; 32], config: WriterConfig) -> Self {
        Self {
            writer: AtpWriter::new(object_id, remote_peer, config),
        }
    }

    /// Write data to the sink.
    pub async fn send(&mut self, cx: &Cx, data: &[u8]) -> AtpOutcome<()> {
        self.writer.write_all(cx, data).await.map(|_| ())
    }

    /// Close the sink and get the final proof.
    pub async fn close(mut self, cx: &Cx) -> AtpOutcome<TransferProof> {
        self.writer.finalize(cx).await
    }

    /// Get current progress.
    pub fn progress(&self) -> WriterProgress {
        self.writer.progress()
    }

    /// Set progress callback.
    pub fn set_progress_callback<F>(&mut self, callback: F)
    where
        F: Fn(WriterProgress) + Send + Sync + 'static,
    {
        self.writer.set_progress_callback(callback);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::object::ContentId;
    use crate::cx::Cx;

    #[test]
    fn test_writer_config_defaults() {
        let config = WriterConfig::default();
        assert_eq!(config.chunk_size, 256 * 1024);
        assert_eq!(config.max_concurrent_chunks, 8);
        assert!(config.enable_progress);
        assert!(config.enable_resume);
        assert_eq!(config.proof_mode, ProofMode::Full);
    }

    #[test]
    fn test_resume_token_validity() {
        let token = ResumeToken {
            transfer_id: TransferId::derive([1; 32], [2; 32], [3; 32], [4; 32]),
            object_id: ObjectId::content(ContentId::new([1; 32])),
            verified_bytes: 1024,
            manifest_root: MerkleRoot::zero(),
            journal_position: 1024,
            created_at: SystemTime::now(),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
        };

        assert!(token.is_valid());
        assert_eq!(token.verified_offset(), 1024);
    }

    #[test]
    fn test_writer_progress() {
        let object_id = ObjectId::content(ContentId::new([1; 32]));
        let writer = AtpWriter::new(object_id, [2; 32], WriterConfig::default());

        let progress = writer.progress();
        assert_eq!(progress.bytes_written, 0);
        assert_eq!(progress.state, WriterState::Ready);
        assert_eq!(progress.chunks_completed, 0);
    }

    #[tokio::test]
    async fn test_writer_lifecycle() {
        let cx = Cx::for_testing();
        let object_id = ObjectId::content(ContentId::new([1; 32]));
        let remote_peer = [2; 32];
        let config = WriterConfig::default();

        let mut writer = AtpWriter::new(object_id, remote_peer, config);
        assert_eq!(writer.state(), WriterState::Ready);

        // Write some data
        let data = b"Hello, ATP World!";
        let bytes_written = writer.write_all(&cx, data).await.unwrap();
        assert_eq!(bytes_written, data.len());
        assert_eq!(writer.state(), WriterState::Streaming);

        // Check progress
        let progress = writer.progress();
        assert!(progress.bytes_written >= data.len() as u64);

        // Finalize and get proof
        let proof = writer.finalize(&cx).await.unwrap();
        assert_eq!(writer.state(), WriterState::Completed);
        assert_eq!(proof.total_bytes, data.len() as u64);
        assert_eq!(proof.proof_mode, ProofMode::Full);
    }

    #[tokio::test]
    async fn test_write_file_streams_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.bin");
        let payload = b"chunk-one/chunk-two/chunk-three";
        std::fs::write(&path, payload).unwrap();

        let cx = Cx::for_testing();
        let object_id = ObjectId::content(ContentId::new([1; 32]));
        let remote_peer = [2; 32];
        let mut config = WriterConfig::default();
        config.chunk_size = 5;
        config.min_chunk_size = 1;
        config.max_chunk_size = 5;
        config.backpressure_threshold = 8;

        let mut writer = AtpWriter::new(object_id, remote_peer, config);
        let proof = writer.write_file(&cx, &path).await.unwrap();

        assert_eq!(writer.state(), WriterState::Completed);
        assert_eq!(proof.total_bytes, payload.len() as u64);
    }

    #[tokio::test]
    async fn test_writer_cancellation() {
        let cx = Cx::for_testing();
        let object_id = ObjectId::content(ContentId::new([1; 32]));
        let remote_peer = [2; 32];
        let mut config = WriterConfig::default();
        config.enable_resume = true;

        let mut writer = AtpWriter::new(object_id, remote_peer, config);

        // Write some data
        let data = b"Partial data";
        writer.write_all(&cx, data).await.unwrap();

        // Cancel and get resume token
        let resume_token = writer.cancel(&cx).await.unwrap();
        assert_eq!(writer.state(), WriterState::Cancelled);
        assert!(resume_token.is_valid());
        assert_eq!(resume_token.verified_bytes, data.len() as u64);
    }

    #[tokio::test]
    async fn test_sink_operations() {
        let cx = Cx::for_testing();
        let object_id = ObjectId::content(ContentId::new([1; 32]));
        let remote_peer = [2; 32];
        let config = WriterConfig::default();

        let mut sink = AtpSink::new(object_id, remote_peer, config);

        // Send data
        let data = b"Sink data stream";
        sink.send(&cx, data).await.unwrap();

        // Check progress
        let progress = sink.progress();
        assert!(progress.bytes_written >= data.len() as u64);

        // Close and get proof
        let proof = sink.close(&cx).await.unwrap();
        assert_eq!(proof.total_bytes, data.len() as u64);
    }

    #[tokio::test]
    async fn test_resume_from_token() {
        let cx = Cx::for_testing();
        // Create initial writer
        let object_id = ObjectId::content(ContentId::new([1; 32]));
        let remote_peer = [2; 32];
        let mut config = WriterConfig::default();
        config.enable_resume = true;

        let mut writer1 = AtpWriter::new(object_id.clone(), remote_peer, config.clone());
        writer1.write_all(&cx, b"First part").await.unwrap();
        let resume_token = writer1.cancel(&cx).await.unwrap();

        // Resume with new writer
        let mut writer2 = AtpWriter::from_resume_token(resume_token, remote_peer, config).unwrap();
        writer2.write_all(&cx, b" Second part").await.unwrap();
        let proof = writer2.finalize(&cx).await.unwrap();

        assert!(proof.total_bytes >= 21); // "First part Second part"
    }

    #[tokio::test]
    async fn test_backpressure_handling() {
        let cx = Cx::for_testing();
        let object_id = ObjectId::content(ContentId::new([1; 32]));
        let remote_peer = [2; 32];
        let mut config = WriterConfig::default();
        config.backpressure_threshold = 1024; // Small threshold for testing

        let mut writer = AtpWriter::new(object_id, remote_peer, config);

        // Write data larger than backpressure threshold
        let large_data = vec![42u8; 2048];
        writer.write_all(&cx, &large_data).await.unwrap();

        // Writer should handle backpressure internally
        assert_ne!(writer.state(), WriterState::Error);

        let proof = writer.finalize(&cx).await.unwrap();
        assert_eq!(proof.total_bytes, large_data.len() as u64);
    }
}
