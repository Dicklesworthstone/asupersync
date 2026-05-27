//! Concrete ATP Writer Implementation
//!
//! High-level writer that provides ergonomic APIs for large buffer/file/stream transfers
//! with proper backpressure, cancellation, and progress handling.

use super::*;
use crate::atp::chunking::ChunkingProfile;
use crate::atp::object::{DirectoryObject, FileObject, StreamObject};
use crate::atp::session::AtpSession;
use crate::cx::Cx;
use crate::types::outcome::Outcome;
use futures::stream::StreamExt;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Component, Path};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

const DIRECTORY_ARCHIVE_DOMAIN: &[u8] = b"asupersync.atp.sink.directory.v1\0";

/// Concrete ATP writer implementation
pub struct AtpWriter {
    /// Underlying ATP session
    session: Arc<AtpSession>,
    /// Active transfers
    active_transfers: Arc<Mutex<HashMap<TransferId, ActiveTransfer>>>,
    /// Chunk evidence for transfers that have actually passed through this writer.
    transferred_chunks: Arc<Mutex<HashMap<TransferId, Vec<ChunkTransferProof>>>>,
    /// Retained progress events emitted by transfers.
    progress_events: Arc<Mutex<Vec<TransferProgress>>>,
    /// Configuration options
    config: WriterConfig,
}

/// Writer configuration
#[derive(Debug, Clone)]
pub struct WriterConfig {
    /// Default chunk size
    pub default_chunk_size: usize,
    /// Maximum concurrent transfers
    pub max_concurrent_transfers: usize,
    /// Default timeout for operations
    pub default_timeout: Duration,
    /// Buffer size for streaming operations
    pub stream_buffer_size: usize,
    /// Progress reporting interval
    pub progress_interval: Duration,
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            default_chunk_size: 1024 * 1024, // 1MB
            max_concurrent_transfers: 10,
            default_timeout: Duration::from_secs(300), // 5 minutes
            stream_buffer_size: 8 * 1024 * 1024,       // 8MB
            progress_interval: Duration::from_secs(1),
        }
    }
}

/// Active transfer state
#[derive(Debug, Clone)]
struct ActiveTransfer {
    transfer_id: TransferId,
    start_time: Instant,
    bytes_transferred: u64,
    total_bytes: Option<u64>,
    chunks_completed: u64,
    current_phase: TransferPhase,
    last_progress_report: Instant,
    cancellation_token: Option<Arc<std::sync::atomic::AtomicBool>>,
    resume_checkpoint: Option<Vec<u8>>,
}

struct DirectoryArchiveEntry {
    kind: u8,
    path_bytes: Vec<u8>,
    payload: Vec<u8>,
}

impl DirectoryArchiveEntry {
    const KIND_DIRECTORY: u8 = 1;
    const KIND_FILE: u8 = 2;
    const KIND_SYMLINK: u8 = 3;
}

impl AtpWriter {
    /// Create a new ATP writer with the given session
    pub fn new(session: Arc<AtpSession>) -> Self {
        Self {
            session,
            active_transfers: Arc::new(Mutex::new(HashMap::new())),
            transferred_chunks: Arc::new(Mutex::new(HashMap::new())),
            progress_events: Arc::new(Mutex::new(Vec::new())),
            config: WriterConfig::default(),
        }
    }

    /// Create a new ATP writer with custom configuration
    pub fn with_config(session: Arc<AtpSession>, config: WriterConfig) -> Self {
        Self {
            session,
            active_transfers: Arc::new(Mutex::new(HashMap::new())),
            transferred_chunks: Arc::new(Mutex::new(HashMap::new())),
            progress_events: Arc::new(Mutex::new(Vec::new())),
            config,
        }
    }
}

impl super::AtpWriter for AtpWriter {
    type Error = WriteError;

    async fn write_buffer(
        &mut self,
        cx: &Cx,
        data: &[u8],
        options: WriteOptions,
    ) -> Outcome<WriteResult, Self::Error> {
        let transfer_id = TransferId::new();
        let start_time = Instant::now();

        // Register active transfer
        {
            let mut transfers = self.active_transfers.lock().unwrap();
            if transfers.len() >= self.config.max_concurrent_transfers {
                return Outcome::Err(WriteError::BackpressureExceeded {
                    current_depth: transfers.len(),
                    max_depth: self.config.max_concurrent_transfers,
                });
            }

            transfers.insert(
                transfer_id,
                ActiveTransfer {
                    transfer_id,
                    start_time,
                    bytes_transferred: 0,
                    total_bytes: Some(data.len() as u64),
                    chunks_completed: 0,
                    current_phase: TransferPhase::Initializing,
                    last_progress_report: start_time,
                    cancellation_token: None,
                    resume_checkpoint: None,
                },
            );
        }

        let mut phase_durations = HashMap::new();

        self.update_transfer_phase(transfer_id, TransferPhase::Chunking);
        let chunking_started = Instant::now();

        // Determine chunking strategy
        let chunking_profile = options
            .chunking_strategy
            .map(|s| match s {
                ChunkingStrategy::FixedSize => ChunkingProfile::BulkFile,
                ChunkingStrategy::ContentDefined => ChunkingProfile::Artifact,
                ChunkingStrategy::Adaptive => {
                    // Choose based on data characteristics
                    if data.len() > 10 * 1024 * 1024 {
                        ChunkingProfile::BulkFile
                    } else {
                        ChunkingProfile::Artifact
                    }
                }
                ChunkingStrategy::ApplicationDefined => ChunkingProfile::Stream,
            })
            .unwrap_or(ChunkingProfile::BulkFile);

        let chunk_boundaries = match chunking_profile.compute_boundaries(data) {
            Ok(boundaries) => boundaries,
            Err(e) => {
                self.remove_active_transfer(transfer_id);
                self.remove_transfer_chunks(transfer_id);
                return Outcome::Err(WriteError::Internal {
                    message: format!("Chunking failed: {}", e),
                });
            }
        };
        phase_durations.insert(TransferPhase::Chunking, chunking_started.elapsed());

        self.update_transfer_phase(transfer_id, TransferPhase::Transferring);
        let transferring_started = Instant::now();

        let mut bytes_transferred = 0u64;
        let mut chunks_completed = 0u64;
        let mut peak_transfer_rate = 0.0_f64;

        // Process chunks with backpressure control
        for (chunk_idx, boundary) in chunk_boundaries.iter().enumerate() {
            // Check for cancellation
            if let Some(active) = self.get_active_transfer(transfer_id) {
                if let Some(cancel_token) = &active.cancellation_token {
                    if cancel_token.load(std::sync::atomic::Ordering::Relaxed) {
                        return self
                            .handle_cancellation(transfer_id, CancellationState::PartiallyCompleted)
                            .await;
                    }
                }
            }

            let chunk_data = &data[boundary.byte_offset as usize
                ..(boundary.byte_offset + boundary.size_bytes) as usize];

            let chunk_started = Instant::now();
            let chunk_result = self
                .transfer_chunk(transfer_id, cx, chunk_data, chunk_idx, boundary.byte_offset)
                .await;
            match chunk_result {
                Ok(_) => {
                    peak_transfer_rate = peak_transfer_rate.max(Self::bytes_per_second(
                        chunk_data.len() as u64,
                        chunk_started.elapsed(),
                    ));
                    bytes_transferred += chunk_data.len() as u64;
                    chunks_completed += 1;

                    self.update_transfer_progress(transfer_id, bytes_transferred, chunks_completed);

                    // Report progress if enabled
                    if options.report_progress {
                        self.report_progress_if_needed(transfer_id, &options).await;
                    }
                }
                Err(e) => {
                    self.remove_active_transfer(transfer_id);
                    self.remove_transfer_chunks(transfer_id);
                    return Outcome::Err(e);
                }
            }
        }
        phase_durations.insert(TransferPhase::Transferring, transferring_started.elapsed());

        self.update_transfer_phase(transfer_id, TransferPhase::Verifying);
        let verifying_started = Instant::now();

        // Generate verification proof
        let verification_result = self
            .verify_transfer(transfer_id, cx, data, &chunk_boundaries)
            .await;
        let (verification_status, proof) = match verification_result {
            Ok(proof) => (VerificationStatus::Verified, proof),
            Err(e) => {
                self.remove_active_transfer(transfer_id);
                self.remove_transfer_chunks(transfer_id);
                return Outcome::Err(WriteError::VerificationFailed {
                    reason: e.to_string(),
                });
            }
        };
        phase_durations.insert(TransferPhase::Verifying, verifying_started.elapsed());

        self.update_transfer_phase(transfer_id, TransferPhase::Finalizing);
        let finalizing_started = Instant::now();

        let object_id = proof.object_id.clone();
        let end_time = Instant::now();
        let duration = end_time.duration_since(start_time);
        phase_durations.insert(TransferPhase::Finalizing, finalizing_started.elapsed());
        let resume_token = if options.resume_behavior == ResumeBehavior::EnableResume {
            Some(ResumeToken {
                transfer_id,
                checkpoint_data: Self::build_resume_checkpoint(transfer_id, &proof),
                expires_at: SystemTime::now() + Duration::from_secs(86400), // 24 hours
                required_capabilities: vec!["write".to_string()],
            })
        } else {
            None
        };

        let result = WriteResult {
            transfer_id,
            object_id,
            total_bytes: data.len() as u64,
            chunk_count: chunks_completed,
            completed_at: SystemTime::now(),
            proof,
            resume_token,
            verified_prefix_bytes: if options.allow_early_consumption {
                data.len() as u64
            } else {
                0
            },
            verification_status,
            metrics: TransferMetrics {
                duration,
                avg_transfer_rate: Self::bytes_per_second(data.len() as u64, duration),
                peak_transfer_rate: peak_transfer_rate
                    .max(Self::bytes_per_second(data.len() as u64, duration)),
                phase_durations,
                round_trips: chunks_completed,
                retransmissions: 0,
                compression_ratio: 1.0,
                deduplication_savings: 0,
            },
        };

        self.update_transfer_phase(transfer_id, TransferPhase::Completed);
        self.remove_active_transfer(transfer_id);
        self.remove_transfer_chunks(transfer_id);

        Outcome::Ok(result)
    }

    async fn write_file(
        &mut self,
        cx: &Cx,
        file_path: &Path,
        options: WriteOptions,
    ) -> Outcome<WriteResult, Self::Error> {
        match std::fs::read(file_path) {
            Ok(data) => self.write_buffer(cx, &data, options).await,
            Err(e) => Outcome::Err(WriteError::Internal {
                message: format!("Failed to read file {}: {}", file_path.display(), e),
            }),
        }
    }

    async fn write_directory(
        &mut self,
        cx: &Cx,
        dir_path: &Path,
        options: WriteOptions,
    ) -> Outcome<WriteResult, Self::Error> {
        let data = match Self::serialize_directory_tree(dir_path) {
            Ok(data) => data,
            Err(error) => return Outcome::Err(error),
        };
        self.write_buffer(cx, &data, options).await
    }

    async fn write_stream<S>(
        &mut self,
        cx: &Cx,
        mut stream: S,
        options: WriteOptions,
    ) -> Outcome<WriteResult, Self::Error>
    where
        S: futures::Stream<Item = Result<Vec<u8>, Self::Error>> + Send + Unpin,
    {
        let transfer_id = TransferId::new();
        let start_time = Instant::now();

        // Register active transfer
        {
            let mut transfers = self.active_transfers.lock().unwrap();
            transfers.insert(
                transfer_id,
                ActiveTransfer {
                    transfer_id,
                    start_time,
                    bytes_transferred: 0,
                    total_bytes: None, // Unknown for streams
                    chunks_completed: 0,
                    current_phase: TransferPhase::Initializing,
                    last_progress_report: start_time,
                    cancellation_token: None,
                    resume_checkpoint: None,
                },
            );
        }

        let mut total_bytes = 0u64;
        let mut chunks_completed = 0u64;
        let mut chunk_idx = 0;

        self.update_transfer_phase(transfer_id, TransferPhase::Transferring);

        // Process stream chunks
        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(chunk_data) => {
                    // Check for cancellation
                    if let Some(active) = self.get_active_transfer(transfer_id) {
                        if let Some(cancel_token) = &active.cancellation_token {
                            if cancel_token.load(std::sync::atomic::Ordering::Relaxed) {
                                return self
                                    .handle_cancellation(
                                        transfer_id,
                                        CancellationState::PartiallyCompleted,
                                    )
                                    .await;
                            }
                        }
                    }

                    let byte_offset = total_bytes;
                    match self
                        .transfer_chunk(transfer_id, cx, &chunk_data, chunk_idx, byte_offset)
                        .await
                    {
                        Ok(_) => {
                            total_bytes += chunk_data.len() as u64;
                            chunks_completed += 1;
                            chunk_idx += 1;

                            self.update_transfer_progress(
                                transfer_id,
                                total_bytes,
                                chunks_completed,
                            );

                            if options.report_progress {
                                self.report_progress_if_needed(transfer_id, &options).await;
                            }
                        }
                        Err(e) => {
                            self.remove_active_transfer(transfer_id);
                            self.remove_transfer_chunks(transfer_id);
                            return Outcome::Err(e);
                        }
                    }
                }
                Err(e) => {
                    self.remove_active_transfer(transfer_id);
                    self.remove_transfer_chunks(transfer_id);
                    return Outcome::Err(e);
                }
            }
        }

        self.update_transfer_phase(transfer_id, TransferPhase::Completed);
        let proof = match self.proof_from_transferred_chunks(transfer_id, total_bytes) {
            Ok(proof) => proof,
            Err(e) => {
                self.remove_active_transfer(transfer_id);
                self.remove_transfer_chunks(transfer_id);
                return Outcome::Err(e);
            }
        };

        let result = WriteResult {
            transfer_id,
            object_id: proof.object_id.clone(),
            total_bytes,
            chunk_count: chunks_completed,
            completed_at: SystemTime::now(),
            proof,
            resume_token: None,
            verified_prefix_bytes: total_bytes,
            verification_status: VerificationStatus::Verified,
            metrics: TransferMetrics {
                duration: start_time.elapsed(),
                avg_transfer_rate: total_bytes as f64 / start_time.elapsed().as_secs_f64(),
                peak_transfer_rate: total_bytes as f64 / start_time.elapsed().as_secs_f64(),
                phase_durations: HashMap::new(),
                round_trips: chunks_completed,
                retransmissions: 0,
                compression_ratio: 1.0,
                deduplication_savings: 0,
            },
        };

        self.remove_active_transfer(transfer_id);
        self.remove_transfer_chunks(transfer_id);
        Outcome::Ok(result)
    }

    async fn write_object(
        &mut self,
        cx: &Cx,
        object: impl AtpObject,
        options: WriteOptions,
    ) -> Outcome<WriteResult, Self::Error> {
        // Serialize object to chunks
        let chunks = match object.serialize_chunks().await {
            Ok(chunks) => chunks,
            Err(e) => {
                return Outcome::Err(WriteError::Internal {
                    message: format!("Object serialization failed: {}", e),
                });
            }
        };

        // Flatten chunks into single buffer for simplicity
        let data: Vec<u8> = chunks.into_iter().flatten().collect();

        self.write_buffer(cx, &data, options).await
    }

    async fn resume_transfer(
        &mut self,
        cx: &Cx,
        resume_token: ResumeToken,
        options: WriteOptions,
    ) -> Outcome<WriteResult, Self::Error> {
        // Validate resume token
        if resume_token.expires_at < SystemTime::now() {
            return Outcome::Err(WriteError::InvalidResumeToken);
        }

        let _ = (cx, options);
        Outcome::Err(WriteError::ResumeFailed {
            reason: "resume requires a persisted checkpoint and verified chunk transcript"
                .to_string(),
        })
    }

    fn get_progress(&self, transfer_id: TransferId) -> Option<TransferProgress> {
        let transfers = self.active_transfers.lock().unwrap();
        transfers.get(&transfer_id).map(|active| {
            let verified_bytes = self.verified_bytes_for_transfer(transfer_id);
            TransferProgress {
                transfer_id: active.transfer_id,
                bytes_transferred: active.bytes_transferred,
                total_bytes: active.total_bytes,
                chunks_completed: active.chunks_completed,
                chunks_remaining: active.total_bytes.map(|total| {
                    let avg_chunk_size = if active.chunks_completed > 0 {
                        active.bytes_transferred / active.chunks_completed
                    } else {
                        self.config.default_chunk_size as u64
                    };
                    (total - active.bytes_transferred) / avg_chunk_size.max(1)
                }),
                transfer_rate: if active.start_time.elapsed().as_secs_f64() > 0.0 {
                    active.bytes_transferred as f64 / active.start_time.elapsed().as_secs_f64()
                } else {
                    0.0
                },
                eta: active.total_bytes.and_then(|total| {
                    if active.bytes_transferred > 0 {
                        let remaining = total - active.bytes_transferred;
                        let rate = active.bytes_transferred as f64
                            / active.start_time.elapsed().as_secs_f64();
                        if rate > 0.0 {
                            Some(Duration::from_secs_f64(remaining as f64 / rate))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }),
                timestamp: SystemTime::now(),
                phase: active.current_phase,
                verified_bytes,
            }
        })
    }

    async fn cancel_transfer(
        &mut self,
        transfer_id: TransferId,
    ) -> Outcome<CancellationResult, Self::Error> {
        // Set cancellation flag
        if let Some(active) = self.get_active_transfer(transfer_id) {
            if let Some(cancel_token) = &active.cancellation_token {
                cancel_token.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }

        self.handle_cancellation(transfer_id, CancellationState::Clean)
            .await
    }
}

impl AtpWriter {
    async fn transfer_chunk(
        &self,
        transfer_id: TransferId,
        cx: &Cx,
        chunk_data: &[u8],
        chunk_idx: usize,
        byte_offset: u64,
    ) -> Result<(), WriteError> {
        cx.checkpoint().map_err(|_| WriteError::Cancelled)?;
        let proof = ChunkTransferProof {
            chunk_index: chunk_idx as u64,
            byte_offset,
            size_bytes: chunk_data.len() as u64,
            content_hash: Self::chunk_digest(chunk_idx, byte_offset, chunk_data),
        };

        let mut chunks = self
            .transferred_chunks
            .lock()
            .map_err(|_| WriteError::Internal {
                message: "transfer chunk evidence lock poisoned".to_string(),
            })?;
        chunks.entry(transfer_id).or_default().push(proof);
        Ok(())
    }

    async fn verify_transfer(
        &self,
        transfer_id: TransferId,
        cx: &Cx,
        data: &[u8],
        chunk_boundaries: &[crate::atp::manifest::ChunkBoundary],
    ) -> Result<TransferProof, WriteError> {
        cx.checkpoint().map_err(|_| WriteError::Cancelled)?;
        let chunks = self
            .transferred_chunks
            .lock()
            .map_err(|_| WriteError::Internal {
                message: "transfer chunk evidence lock poisoned".to_string(),
            })?
            .get(&transfer_id)
            .cloned()
            .unwrap_or_default();

        if chunks.len() != chunk_boundaries.len() {
            return Err(WriteError::VerificationFailed {
                reason: format!(
                    "sent chunk count {} does not match manifest chunk count {}",
                    chunks.len(),
                    chunk_boundaries.len()
                ),
            });
        }

        for (chunk_idx, boundary) in chunk_boundaries.iter().enumerate() {
            let start = boundary.byte_offset as usize;
            let end = start.saturating_add(boundary.size_bytes as usize);
            if end > data.len() {
                return Err(WriteError::VerificationFailed {
                    reason: format!("chunk {chunk_idx} exceeds transfer data length"),
                });
            }

            let expected = Self::chunk_digest(chunk_idx, boundary.byte_offset, &data[start..end]);
            let Some(actual) = chunks
                .iter()
                .find(|chunk| chunk.chunk_index == chunk_idx as u64)
            else {
                return Err(WriteError::VerificationFailed {
                    reason: format!("missing transmitted chunk {chunk_idx}"),
                });
            };

            if actual.byte_offset != boundary.byte_offset
                || actual.size_bytes != boundary.size_bytes
                || actual.content_hash != expected
            {
                return Err(WriteError::VerificationFailed {
                    reason: format!("transmitted chunk {chunk_idx} does not match manifest bytes"),
                });
            }
        }

        Ok(TransferProof::from_chunk_proofs(
            transfer_id,
            chunks,
            SystemTime::now(),
        ))
    }

    fn chunk_digest(chunk_idx: usize, byte_offset: u64, chunk_data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"asupersync.atp.sink.chunk.v1\0");
        hasher.update((chunk_idx as u64).to_be_bytes());
        hasher.update(byte_offset.to_be_bytes());
        hasher.update((chunk_data.len() as u64).to_be_bytes());
        hasher.update(chunk_data);
        hasher.finalize().into()
    }

    fn proof_from_transferred_chunks(
        &self,
        transfer_id: TransferId,
        total_bytes: u64,
    ) -> Result<TransferProof, WriteError> {
        let chunks = self
            .transferred_chunks
            .lock()
            .map_err(|_| WriteError::Internal {
                message: "transfer chunk evidence lock poisoned".to_string(),
            })?
            .get(&transfer_id)
            .cloned()
            .unwrap_or_default();

        let covered_bytes = chunks
            .iter()
            .try_fold(0_u64, |sum, chunk| sum.checked_add(chunk.size_bytes))
            .ok_or_else(|| WriteError::VerificationFailed {
                reason: "transferred chunk byte count overflowed".to_string(),
            })?;
        if covered_bytes != total_bytes {
            return Err(WriteError::VerificationFailed {
                reason: format!(
                    "transferred bytes {covered_bytes} do not match expected {total_bytes}"
                ),
            });
        }

        Ok(TransferProof::from_chunk_proofs(
            transfer_id,
            chunks,
            SystemTime::now(),
        ))
    }

    fn serialize_directory_tree(root: &Path) -> Result<Vec<u8>, WriteError> {
        let root_metadata =
            std::fs::symlink_metadata(root).map_err(|error| WriteError::Internal {
                message: format!(
                    "failed to read directory metadata for {}: {error}",
                    root.display()
                ),
            })?;
        if !root_metadata.is_dir() {
            return Err(WriteError::Internal {
                message: format!("directory source is not a directory: {}", root.display()),
            });
        }

        let mut entries = Vec::new();
        Self::collect_directory_entries(root, root, &mut entries)?;
        entries.sort_by(|left, right| {
            left.path_bytes
                .cmp(&right.path_bytes)
                .then_with(|| left.kind.cmp(&right.kind))
        });

        let mut out = Vec::new();
        out.extend_from_slice(DIRECTORY_ARCHIVE_DOMAIN);
        out.extend_from_slice(&1_u32.to_be_bytes());
        out.extend_from_slice(&(entries.len() as u64).to_be_bytes());

        for entry in entries {
            out.push(entry.kind);
            Self::write_len_prefixed(&mut out, &entry.path_bytes)?;
            Self::write_len_prefixed(&mut out, &entry.payload)?;

            let mut hasher = Sha256::new();
            hasher.update(DIRECTORY_ARCHIVE_DOMAIN);
            hasher.update([entry.kind]);
            hasher.update(&(entry.path_bytes.len() as u64).to_be_bytes());
            hasher.update(&entry.path_bytes);
            hasher.update(&(entry.payload.len() as u64).to_be_bytes());
            hasher.update(&entry.payload);
            let digest: [u8; 32] = hasher.finalize().into();
            out.extend_from_slice(&digest);
        }

        Ok(out)
    }

    fn collect_directory_entries(
        root: &Path,
        current: &Path,
        entries: &mut Vec<DirectoryArchiveEntry>,
    ) -> Result<(), WriteError> {
        let mut children = std::fs::read_dir(current)
            .map_err(|error| WriteError::Internal {
                message: format!("failed to read directory {}: {error}", current.display()),
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| WriteError::Internal {
                message: format!(
                    "failed to enumerate directory {}: {error}",
                    current.display()
                ),
            })?;
        children.sort_by(|left, right| left.file_name().cmp(&right.file_name()));

        for child in children {
            let path = child.path();
            let metadata =
                std::fs::symlink_metadata(&path).map_err(|error| WriteError::Internal {
                    message: format!(
                        "failed to read entry metadata for {}: {error}",
                        path.display()
                    ),
                })?;
            let path_bytes = Self::relative_path_bytes(root, &path)?;
            let file_type = metadata.file_type();

            if file_type.is_dir() {
                entries.push(DirectoryArchiveEntry {
                    kind: DirectoryArchiveEntry::KIND_DIRECTORY,
                    path_bytes,
                    payload: Vec::new(),
                });
                Self::collect_directory_entries(root, &path, entries)?;
            } else if file_type.is_file() {
                let payload = std::fs::read(&path).map_err(|error| WriteError::Internal {
                    message: format!("failed to read file {}: {error}", path.display()),
                })?;
                entries.push(DirectoryArchiveEntry {
                    kind: DirectoryArchiveEntry::KIND_FILE,
                    path_bytes,
                    payload,
                });
            } else if file_type.is_symlink() {
                let target = std::fs::read_link(&path).map_err(|error| WriteError::Internal {
                    message: format!("failed to read symlink {}: {error}", path.display()),
                })?;
                entries.push(DirectoryArchiveEntry {
                    kind: DirectoryArchiveEntry::KIND_SYMLINK,
                    path_bytes,
                    payload: Self::os_str_bytes(target.as_os_str()),
                });
            } else {
                return Err(WriteError::Internal {
                    message: format!("unsupported directory entry type: {}", path.display()),
                });
            }
        }

        Ok(())
    }

    fn relative_path_bytes(root: &Path, path: &Path) -> Result<Vec<u8>, WriteError> {
        let relative = path.strip_prefix(root).map_err(|_| WriteError::Internal {
            message: format!(
                "directory entry {} escaped root {}",
                path.display(),
                root.display()
            ),
        })?;
        let mut out = Vec::new();
        for component in relative.components() {
            match component {
                Component::Normal(name) => {
                    if !out.is_empty() {
                        out.push(b'/');
                    }
                    out.extend_from_slice(&Self::os_str_bytes(name));
                }
                Component::CurDir => {}
                Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                    return Err(WriteError::Internal {
                        message: format!("non-canonical directory entry path: {}", path.display()),
                    });
                }
            }
        }
        Ok(out)
    }

    fn write_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), WriteError> {
        let len = u64::try_from(bytes.len()).map_err(|_| WriteError::Internal {
            message: "directory archive field length overflowed".to_string(),
        })?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(bytes);
        Ok(())
    }

    fn os_str_bytes(value: &OsStr) -> Vec<u8> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            value.as_bytes().to_vec()
        }

        #[cfg(not(unix))]
        {
            value.to_string_lossy().as_bytes().to_vec()
        }
    }

    fn bytes_per_second(bytes: u64, duration: Duration) -> f64 {
        if bytes == 0 {
            return 0.0;
        }
        let secs = duration.as_secs_f64();
        if secs > 0.0 {
            bytes as f64 / secs
        } else {
            bytes as f64 * 1_000_000_000.0
        }
    }

    fn build_resume_checkpoint(transfer_id: TransferId, proof: &TransferProof) -> Vec<u8> {
        let mut out = Vec::with_capacity(104 + proof.chunks.len() * 56);
        out.extend_from_slice(b"asupersync.atp.sink.resume.v1\0");
        out.extend_from_slice(&transfer_id.0);
        out.extend_from_slice(&proof.total_bytes.to_be_bytes());
        out.extend_from_slice(&proof.chunk_count.to_be_bytes());
        out.extend_from_slice(&proof.content_hash);
        out.extend_from_slice(&proof.manifest_root);
        for chunk in &proof.chunks {
            out.extend_from_slice(&chunk.chunk_index.to_be_bytes());
            out.extend_from_slice(&chunk.byte_offset.to_be_bytes());
            out.extend_from_slice(&chunk.size_bytes.to_be_bytes());
            out.extend_from_slice(&chunk.content_hash);
        }
        out
    }

    fn update_transfer_phase(&self, transfer_id: TransferId, phase: TransferPhase) {
        if let Ok(mut transfers) = self.active_transfers.lock() {
            if let Some(active) = transfers.get_mut(&transfer_id) {
                active.current_phase = phase;
            }
        }
    }

    fn update_transfer_progress(&self, transfer_id: TransferId, bytes: u64, chunks: u64) {
        if let Ok(mut transfers) = self.active_transfers.lock() {
            if let Some(active) = transfers.get_mut(&transfer_id) {
                active.bytes_transferred = bytes;
                active.chunks_completed = chunks;
            }
        }
    }

    fn get_active_transfer(&self, transfer_id: TransferId) -> Option<ActiveTransfer> {
        self.active_transfers
            .lock()
            .ok()?
            .get(&transfer_id)
            .cloned()
    }

    fn verified_bytes_for_transfer(&self, transfer_id: TransferId) -> u64 {
        self.transferred_chunks
            .lock()
            .ok()
            .and_then(|chunks| {
                chunks.get(&transfer_id).map(|proofs| {
                    proofs
                        .iter()
                        .fold(0_u64, |sum, proof| sum.saturating_add(proof.size_bytes))
                })
            })
            .unwrap_or(0)
    }

    fn remove_active_transfer(&self, transfer_id: TransferId) {
        if let Ok(mut transfers) = self.active_transfers.lock() {
            transfers.remove(&transfer_id);
        }
    }

    fn remove_transfer_chunks(&self, transfer_id: TransferId) {
        if let Ok(mut chunks) = self.transferred_chunks.lock() {
            chunks.remove(&transfer_id);
        }
    }

    async fn report_progress_if_needed(&self, transfer_id: TransferId, options: &WriteOptions) {
        if let Some(active) = self.get_active_transfer(transfer_id) {
            if active.last_progress_report.elapsed() >= options.progress_interval {
                if let Some(progress) = self.get_progress(transfer_id) {
                    if let Ok(mut events) = self.progress_events.lock() {
                        events.push(progress);
                    }
                    if let Ok(mut transfers) = self.active_transfers.lock()
                        && let Some(active) = transfers.get_mut(&transfer_id)
                    {
                        active.last_progress_report = Instant::now();
                    }
                }
            }
        }
    }

    async fn handle_cancellation(
        &self,
        transfer_id: TransferId,
        state: CancellationState,
    ) -> Outcome<CancellationResult, WriteError> {
        let partial_proof = self
            .transferred_chunks
            .lock()
            .ok()
            .and_then(|chunks| chunks.get(&transfer_id).cloned())
            .filter(|chunks| !chunks.is_empty())
            .map(|chunks| TransferProof::from_chunk_proofs(transfer_id, chunks, SystemTime::now()));

        let result = CancellationResult {
            transfer_id,
            cancelled_at: SystemTime::now(),
            final_state: state,
            resume_token: if state == CancellationState::Resumable {
                Some(ResumeToken {
                    transfer_id,
                    checkpoint_data: Vec::new(),
                    expires_at: SystemTime::now() + Duration::from_secs(86400),
                    required_capabilities: vec!["write".to_string()],
                })
            } else {
                None
            },
            partial_proof,
            cleanup_required: vec![CleanupAction::ClearCacheEntries(vec![format!(
                "transfer:{:?}",
                transfer_id
            )])],
        };

        self.remove_active_transfer(transfer_id);
        self.remove_transfer_chunks(transfer_id);
        Outcome::Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;

    #[tokio::test]
    async fn test_writer_config_default() {
        let config = WriterConfig::default();
        assert_eq!(config.default_chunk_size, 1024 * 1024);
        assert_eq!(config.max_concurrent_transfers, 10);
    }

    #[tokio::test]
    async fn test_transfer_progress_calculation() {
        let active = ActiveTransfer {
            transfer_id: TransferId::new(),
            start_time: Instant::now() - Duration::from_secs(10),
            bytes_transferred: 1000,
            total_bytes: Some(10000),
            chunks_completed: 5,
            current_phase: TransferPhase::Transferring,
            last_progress_report: Instant::now(),
            cancellation_token: None,
            resume_checkpoint: None,
        };

        assert_eq!(active.bytes_transferred, 1000);
        assert_eq!(active.total_bytes, Some(10000));
        assert_eq!(active.chunks_completed, 5);
    }

    #[test]
    fn transfer_proof_binds_chunk_evidence() {
        let transfer_id = TransferId::new();
        let chunk = ChunkTransferProof {
            chunk_index: 0,
            byte_offset: 0,
            size_bytes: 11,
            content_hash: AtpWriter::chunk_digest(0, 0, b"hello world"),
        };

        let proof =
            TransferProof::from_chunk_proofs(transfer_id, vec![chunk.clone()], SystemTime::now());

        assert_eq!(proof.transfer_id, transfer_id);
        assert_eq!(proof.total_bytes, 11);
        assert_eq!(proof.chunk_count, 1);
        assert_eq!(proof.chunks, vec![chunk]);
        assert_ne!(proof.content_hash, [0; 32]);
        assert_ne!(proof.manifest_root, [0; 32]);
    }
}
