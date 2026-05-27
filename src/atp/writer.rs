//! ATP Writer/Sink API for ergonomic large buffer and stream handling.
//!
//! This module provides the high-level writer and sink interfaces that give users
//! the simple write(really_big_buffer) experience while preserving ATP correctness,
//! structured concurrency, and explicit cancellation semantics.

use crate::atp::manifest::{ManifestVersion, MerkleRoot};
use crate::atp::object::{ContentId, ObjectId};
use crate::atp::transfer::TransferId;
use crate::cx::Cx;
use crate::fs::File;
use crate::net::atp::protocol::outcome::{AtpError, AtpOutcome, DiskError, ProtocolError};
use crate::types::outcome::Outcome;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

const MAX_FILE_STREAM_CHUNK_LEN: usize = 8 * 1024 * 1024;
const WRITER_CONTENT_DOMAIN: &[u8] = b"ATP-WRITER-CONTENT-V1\0";
const WRITER_CHUNK_DOMAIN: &[u8] = b"ATP-WRITER-CHUNK-V1\0";
const WRITER_MANIFEST_DOMAIN: &[u8] = b"ATP-WRITER-MANIFEST-V1\0";
const WRITER_RESUME_DOMAIN: &[u8] = b"ATP-WRITER-RESUME-V1\0";
const WRITER_PROOF_DOMAIN: &[u8] = b"ATP-WRITER-PROOF-V1\0";

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
    /// Local peer identity used to derive this transfer.
    local_peer: Option<[u8; 32]>,
    /// Per-transfer nonce used to derive this transfer.
    transfer_nonce: Option<[u8; 32]>,
    /// Latest manifest root covering verified chunks.
    manifest_root: Option<MerkleRoot>,
    /// Content hash state for bytes verified by this writer instance.
    content_hasher: Sha256,
    /// Verified chunk ledger retained after buffers are flushed.
    verified_chunks: Vec<VerifiedChunk>,
    /// Bytes verified before a resumed writer was constructed.
    base_verified_bytes: u64,
    /// Manifest root supplied by a resume token.
    base_manifest_root: Option<MerkleRoot>,
    /// Whether the transfer id came from a resume token and must remain stable.
    resumed_transfer: bool,
    /// Progress callback.
    progress_callback: Option<Arc<dyn Fn(WriterProgress) + Send + Sync>>,
    /// Resume token for interrupted transfers.
    resume_token: Option<ResumeToken>,
    /// Wall-clock instant when this writer was constructed.
    created_at: SystemTime,
}

#[derive(Debug, Clone)]
struct VerifiedChunk {
    offset: u64,
    size_bytes: u64,
    hash: [u8; 32],
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

impl WriterState {
    fn rejects_more_writes(self) -> bool {
        matches!(
            self,
            Self::Finalizing | Self::Completed | Self::Cancelled | Self::Error
        )
    }
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
            local_peer: None,
            transfer_nonce: None,
            manifest_root: None,
            content_hasher: new_content_hasher(),
            verified_chunks: Vec::new(),
            base_verified_bytes: 0,
            base_manifest_root: None,
            resumed_transfer: false,
            progress_callback: None,
            resume_token: None,
            created_at: SystemTime::now(),
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
            local_peer: None,
            transfer_nonce: None,
            manifest_root: Some(resume_token.manifest_root.clone()),
            content_hasher: new_content_hasher(),
            verified_chunks: Vec::new(),
            base_verified_bytes: resume_token.verified_bytes,
            base_manifest_root: Some(resume_token.manifest_root.clone()),
            resumed_transfer: true,
            progress_callback: None,
            resume_token: Some(resume_token),
            created_at: SystemTime::now(),
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
            total_bytes: None, // Unknown for streaming
            transfer_rate_bps: self.transfer_rate_bps(),
            estimated_completion: None,
            chunks_completed: self.progress_chunks_completed(),
            chunks_in_flight: self.pending_buffer_chunks(),
            state: self.state,
        }
    }

    /// Write data to the ATP stream with backpressure handling.
    pub async fn write_all(&mut self, cx: &Cx, data: &[u8]) -> AtpOutcome<usize> {
        cx.trace(&format!("atp_writer_write {} bytes", data.len()));

        if self.state.rejects_more_writes() {
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
        let pending_len = match checked_pending_buffer_len(self.buffer.len(), data.len()) {
            Ok(len) => len,
            Err(e) => return Outcome::Err(e),
        };

        if pending_len > self.backpressure_threshold_len() {
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

        match self.flush_buffer(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

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
        }

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
        if self.transfer_id.is_none() {
            match self.initialize_transfer(cx).await {
                Outcome::Ok(()) => {}
                Outcome::Err(e) => return Outcome::Err(e),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
        }
        self.materialize_content_object_id_if_needed();
        match self.refresh_transfer_identity() {
            Outcome::Ok(()) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
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

        if self.state == WriterState::Completed || self.state == WriterState::Error {
            return Outcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch));
        }

        if self.transfer_id.is_none() {
            match self.initialize_transfer(cx).await {
                Outcome::Ok(()) => {}
                Outcome::Err(e) => return Outcome::Err(e),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
        }
        if !self.buffer.is_empty() {
            match self.flush_buffer(cx).await {
                Outcome::Ok(()) => {}
                Outcome::Err(e) => return Outcome::Err(e),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
        }
        self.materialize_content_object_id_if_needed();
        match self.refresh_transfer_identity() {
            Outcome::Ok(()) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        self.state = WriterState::Cancelled;
        let Some(transfer_id) = self.transfer_id else {
            return Outcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch));
        };
        let manifest_root = self.current_manifest_root();

        // Generate and store resume token if resume is enabled
        if self.config.enable_resume {
            let resume_token = ResumeToken {
                transfer_id,
                object_id: self.object_id.clone(),
                verified_bytes: self.bytes_written,
                manifest_root,
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
                transfer_id,
                object_id: self.object_id.clone(),
                verified_bytes: 0,
                manifest_root,
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
        if let (true, Some(transfer_id)) = (self.config.enable_resume, self.transfer_id) {
            let resume_token = ResumeToken {
                transfer_id,
                object_id: self.object_id.clone(),
                verified_bytes: self.bytes_written,
                manifest_root: self.current_manifest_root(),
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
        let hard_limit = u64::try_from(MAX_FILE_STREAM_CHUNK_LEN).unwrap_or(u64::MAX);
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

    fn backpressure_threshold_len(&self) -> usize {
        usize::try_from(self.config.backpressure_threshold).unwrap_or(usize::MAX)
    }

    fn progress_chunks_completed(&self) -> u64 {
        let chunk_size = u64::try_from(self.file_stream_chunk_len())
            .unwrap_or(u64::MAX)
            .max(1);
        let base_chunks = div_ceil_u64(self.base_verified_bytes, chunk_size);
        let local_chunks = u64::try_from(self.verified_chunks.len()).unwrap_or(u64::MAX);
        base_chunks.saturating_add(local_chunks)
    }

    fn pending_buffer_chunks(&self) -> u64 {
        if self.buffer.is_empty() {
            return 0;
        }

        div_ceil_u64(
            self.buffer.len() as u64,
            u64::try_from(self.file_stream_chunk_len())
                .unwrap_or(u64::MAX)
                .max(1),
        )
    }

    fn transfer_rate_bps(&self) -> f64 {
        if self.bytes_written == 0 {
            return 0.0;
        }

        match SystemTime::now().duration_since(self.created_at) {
            Ok(elapsed) if elapsed.as_secs_f64() > 0.0 => {
                self.bytes_written as f64 / elapsed.as_secs_f64()
            }
            _ => 0.0,
        }
    }

    async fn initialize_transfer(&mut self, cx: &Cx) -> AtpOutcome<()> {
        cx.trace("atp_writer_initialize_transfer");

        self.ensure_transfer_context(cx);
        self.refresh_transfer_identity()
    }

    async fn flush_buffer(&mut self, cx: &Cx) -> AtpOutcome<()> {
        cx.trace(&format!(
            "atp_writer_flush_buffer {} bytes",
            self.buffer.len()
        ));

        if self.buffer.is_empty() {
            return Outcome::ok(());
        }

        self.ensure_transfer_context(cx);
        let buffered_len = match u64::try_from(self.buffer.len()) {
            Ok(len) => len,
            Err(_) => return Outcome::Err(AtpError::Protocol(ProtocolError::FrameTooLarge)),
        };
        if self.bytes_written.checked_add(buffered_len).is_none() {
            return Outcome::Err(AtpError::Protocol(ProtocolError::FrameTooLarge));
        }

        let chunk_len = self.file_stream_chunk_len();
        let buffered = std::mem::take(&mut self.buffer);
        let mut offset = self.bytes_written;
        for chunk in buffered.chunks(chunk_len) {
            let size_bytes = chunk.len() as u64;
            let hash = self.chunk_hash(offset, chunk);
            self.content_hasher.update(chunk);
            self.verified_chunks.push(VerifiedChunk {
                offset,
                size_bytes,
                hash,
            });
            offset = match offset.checked_add(size_bytes) {
                Some(next_offset) => next_offset,
                None => return Outcome::Err(AtpError::Protocol(ProtocolError::FrameTooLarge)),
            };
        }
        self.bytes_written = offset;

        self.refresh_transfer_identity()
    }

    async fn generate_proof(&self, cx: &Cx) -> AtpOutcome<TransferProof> {
        cx.trace("atp_writer_generate_proof");

        let Some(transfer_id) = self.transfer_id else {
            return Outcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch));
        };
        let verified_hash = self.current_verified_hash();
        let manifest_root = self.current_manifest_root();
        let signatures = self.generate_proof_signatures(transfer_id, &manifest_root, verified_hash);

        let proof = TransferProof {
            transfer_id,
            object_id: self.object_id.clone(),
            verified_hash,
            total_bytes: self.bytes_written,
            manifest_version: ManifestVersion::CURRENT,
            manifest_root,
            completed_at: SystemTime::now(),
            proof_mode: self.config.proof_mode,
            signatures,
        };

        Outcome::ok(proof)
    }

    fn ensure_transfer_context(&mut self, cx: &Cx) {
        if self.local_peer.is_none() {
            let mut local_peer = [0_u8; 32];
            cx.random_bytes(&mut local_peer);
            ensure_nonzero(&mut local_peer);
            self.local_peer = Some(local_peer);
        }
        if self.transfer_nonce.is_none() {
            let mut transfer_nonce = [0_u8; 32];
            cx.random_bytes(&mut transfer_nonce);
            ensure_nonzero(&mut transfer_nonce);
            self.transfer_nonce = Some(transfer_nonce);
        }
    }

    fn refresh_transfer_identity(&mut self) -> AtpOutcome<()> {
        let (Some(local_peer), Some(transfer_nonce)) = (self.local_peer, self.transfer_nonce)
        else {
            return Outcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch));
        };

        let manifest_root = self.compute_manifest_root(self.current_verified_hash());
        if !self.resumed_transfer || self.transfer_id.is_none() {
            self.transfer_id = Some(TransferId::derive(
                local_peer,
                self.remote_peer,
                transfer_nonce,
                *manifest_root.hash(),
            ));
        }
        self.manifest_root = Some(manifest_root);
        self.resume_token = None;
        Outcome::ok(())
    }

    fn current_verified_hash(&self) -> [u8; 32] {
        let current_hash: [u8; 32] = self.content_hasher.clone().finalize().into();
        if let Some(base_root) = &self.base_manifest_root {
            let mut hasher = Sha256::new();
            hasher.update(WRITER_RESUME_DOMAIN);
            hasher.update(base_root.hash());
            hasher.update(self.base_verified_bytes.to_be_bytes());
            hasher.update(current_hash);
            hasher.finalize().into()
        } else {
            current_hash
        }
    }

    fn current_manifest_root(&self) -> MerkleRoot {
        self.manifest_root
            .clone()
            .unwrap_or_else(|| self.compute_manifest_root(self.current_verified_hash()))
    }

    fn compute_manifest_root(&self, verified_hash: [u8; 32]) -> MerkleRoot {
        let mut hasher = Sha256::new();
        hasher.update(WRITER_MANIFEST_DOMAIN);
        hasher.update(ManifestVersion::CURRENT.0.to_be_bytes());
        hasher.update(self.object_id.hash_bytes());
        hasher.update(self.bytes_written.to_be_bytes());
        hasher.update(verified_hash);
        if let Some(base_root) = &self.base_manifest_root {
            hasher.update(b"resume-base");
            hasher.update(base_root.hash());
            hasher.update(self.base_verified_bytes.to_be_bytes());
        }
        for chunk in &self.verified_chunks {
            hasher.update(chunk.offset.to_be_bytes());
            hasher.update(chunk.size_bytes.to_be_bytes());
            hasher.update(chunk.hash);
        }
        MerkleRoot::new(hasher.finalize().into())
    }

    fn chunk_hash(&self, offset: u64, chunk: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(WRITER_CHUNK_DOMAIN);
        hasher.update(offset.to_be_bytes());
        hasher.update((chunk.len() as u64).to_be_bytes());
        hasher.update(chunk);
        hasher.finalize().into()
    }

    fn generate_proof_signatures(
        &self,
        transfer_id: TransferId,
        manifest_root: &MerkleRoot,
        verified_hash: [u8; 32],
    ) -> Vec<u8> {
        if self.config.proof_mode == ProofMode::None {
            return Vec::new();
        }

        let mut hasher = Sha256::new();
        hasher.update(WRITER_PROOF_DOMAIN);
        hasher.update(transfer_id.as_bytes());
        hasher.update(self.object_id.hash_bytes());
        hasher.update(verified_hash);
        hasher.update(manifest_root.hash());
        hasher.update(self.bytes_written.to_be_bytes());
        if let Some(local_peer) = self.local_peer {
            hasher.update(local_peer);
        }
        hasher.update(self.remote_peer);
        if let Some(transfer_nonce) = self.transfer_nonce {
            hasher.update(transfer_nonce);
        }
        for chunk in &self.verified_chunks {
            hasher.update(chunk.offset.to_be_bytes());
            hasher.update(chunk.size_bytes.to_be_bytes());
            hasher.update(chunk.hash);
        }
        hasher.finalize().to_vec()
    }

    fn materialize_content_object_id_if_needed(&mut self) {
        if self.object_id.hash_bytes().iter().all(|byte| *byte == 0) {
            self.object_id = ObjectId::content(ContentId::new(self.current_verified_hash()));
        }
    }
}

fn new_content_hasher() -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(WRITER_CONTENT_DOMAIN);
    hasher
}

fn ensure_nonzero(bytes: &mut [u8; 32]) {
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[0] = 1;
    }
}

fn div_ceil_u64(numerator: u64, denominator: u64) -> u64 {
    debug_assert!(denominator > 0);
    let quotient = numerator / denominator;
    quotient + u64::from(numerator % denominator != 0)
}

fn checked_pending_buffer_len(buffered_len: usize, incoming_len: usize) -> Result<usize, AtpError> {
    buffered_len
        .checked_add(incoming_len)
        .ok_or(AtpError::Protocol(ProtocolError::FrameTooLarge))
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

    #[test]
    fn test_writer_progress_handles_zero_chunk_size() {
        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let object_id = ObjectId::content(ContentId::new([1; 32]));
            let mut config = WriterConfig::default();
            config.chunk_size = 0;
            config.min_chunk_size = 0;
            config.max_chunk_size = 0;
            config.backpressure_threshold = 0;

            let mut writer = AtpWriter::new(object_id, [2; 32], config);
            assert_eq!(writer.progress().chunks_completed, 0);

            let bytes_written = writer.write_all(&cx, b"abc").await.unwrap();
            assert_eq!(bytes_written, 3);
            assert_eq!(writer.progress().chunks_completed, 3);
        });
    }

    #[test]
    fn pending_buffer_length_overflow_fails_closed() {
        let result = checked_pending_buffer_len(usize::MAX, 1);

        assert!(matches!(
            result,
            Err(AtpError::Protocol(ProtocolError::FrameTooLarge))
        ));
    }

    #[test]
    fn test_resumed_write_overflow_fails_closed_before_mutating_proof_state() {
        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let object_id = ObjectId::content(ContentId::new([1; 32]));
            let transfer_id = TransferId::derive([1; 32], [2; 32], [3; 32], [4; 32]);
            let token = ResumeToken {
                transfer_id,
                object_id,
                verified_bytes: u64::MAX,
                manifest_root: MerkleRoot::new([9; 32]),
                journal_position: u64::MAX,
                created_at: SystemTime::now(),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
            };

            let mut writer =
                AtpWriter::from_resume_token(token, [2; 32], WriterConfig::default()).unwrap();
            let result = writer.write_all(&cx, b"x").await;

            assert!(matches!(
                result,
                Outcome::Err(AtpError::Protocol(ProtocolError::FrameTooLarge))
            ));
            assert_eq!(writer.bytes_written, u64::MAX);
            assert_eq!(writer.buffer.as_slice(), b"x");
            assert!(writer.verified_chunks.is_empty());
        });
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
        assert_ne!(proof.verified_hash, [0; 32]);
        assert_ne!(proof.manifest_root, MerkleRoot::zero());
        assert!(!proof.signatures.is_empty());
        assert_ne!(
            proof.transfer_id,
            TransferId::derive([0; 32], remote_peer, [0; 32], [0; 32])
        );
    }

    #[test]
    fn completed_writer_rejects_late_writes_without_state_mutation() {
        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let object_id = ObjectId::content(ContentId::new([1; 32]));
            let mut writer = AtpWriter::new(object_id, [2; 32], WriterConfig::default());

            let proof = writer.write_buffer(&cx, b"final payload").await.unwrap();
            let completed_bytes = writer.bytes_written;
            let completed_chunks = writer.verified_chunks.len();

            let late_write = writer.write_all(&cx, b"late bytes").await;

            assert!(matches!(
                late_write,
                Outcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch))
            ));
            assert_eq!(writer.state(), WriterState::Completed);
            assert_eq!(writer.bytes_written, completed_bytes);
            assert_eq!(writer.verified_chunks.len(), completed_chunks);
            assert_eq!(writer.buffer, Vec::<u8>::new());
            assert_eq!(proof.total_bytes, completed_bytes);
        });
    }

    #[test]
    fn completed_writer_rejects_cancellation_resume_token() {
        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let object_id = ObjectId::content(ContentId::new([1; 32]));
            let mut writer = AtpWriter::new(object_id, [2; 32], WriterConfig::default());

            let proof = writer
                .write_buffer(&cx, b"cannot resume this")
                .await
                .unwrap();
            let cancellation = writer.cancel(&cx).await;

            assert!(matches!(
                cancellation,
                Outcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch))
            ));
            assert_eq!(writer.state(), WriterState::Completed);
            assert_eq!(writer.bytes_written, proof.total_bytes);
            assert!(writer.resume_token.is_none());
        });
    }

    #[test]
    fn test_writer_proof_is_bound_to_payload() {
        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let remote_peer = [9; 32];
            let config = WriterConfig::default();
            let mut writer_a = AtpWriter::new(
                ObjectId::content(ContentId::new([0; 32])),
                remote_peer,
                config.clone(),
            );
            let mut writer_b = AtpWriter::new(
                ObjectId::content(ContentId::new([0; 32])),
                remote_peer,
                config,
            );

            let proof_a = writer_a.write_buffer(&cx, b"payload-A").await.unwrap();
            let proof_b = writer_b.write_buffer(&cx, b"payload-B").await.unwrap();

            assert_ne!(proof_a.verified_hash, [0; 32]);
            assert_ne!(proof_a.manifest_root, MerkleRoot::zero());
            assert_ne!(proof_a.verified_hash, proof_b.verified_hash);
            assert_ne!(proof_a.manifest_root, proof_b.manifest_root);
            assert_ne!(proof_a.transfer_id, proof_b.transfer_id);
            assert_eq!(proof_a.object_id.hash_bytes(), &proof_a.verified_hash);
            assert_eq!(proof_b.object_id.hash_bytes(), &proof_b.verified_hash);
        });
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
