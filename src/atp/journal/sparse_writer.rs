//! Sparse Writer Implementation for Out-of-Order Chunk Writing

use super::{
    ChunkRange, CommitPolicy, PlatformCapabilities, RangeTracker, SparseRange, TempPathManager,
};
use crate::atp::manifest::{ChunkBoundary, Manifest, MerkleRoot};
use crate::atp::manifest_chunk_commitment::ManifestChunkCommitment;
use crate::atp::object::ObjectId;
use crate::cx::Cx;
use crate::types::outcome::Outcome;
use parking_lot::{Mutex, MutexGuard};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

const CONTENT_ID_DOMAIN: &[u8] = b"asupersync.atp.content-id.v1\0";
const DIGEST_BUFFER_SIZE: usize = 8192;

#[cfg(not(target_arch = "wasm32"))]
mod scoped;
#[cfg(not(target_arch = "wasm32"))]
pub use scoped::{ScopedSparseWriter, ScopedWriterResult};

/// Configuration for sparse writer behavior
#[derive(Debug, Clone)]
pub struct SparseWriterConfig {
    /// Enable preallocation when supported by platform
    pub enable_preallocation: bool,
    /// Preferred chunk size for preallocation hints
    pub chunk_size_hint: u64,
    /// Maximum number of concurrent temp files
    pub max_temp_files: usize,
    /// Fsync policy for durability guarantees
    pub fsync_policy: super::FsyncPolicy,
    /// Atomic commit policy
    pub commit_policy: CommitPolicy,
    /// Enable quarantine for failed writes
    pub enable_quarantine: bool,
    /// Maximum age for temp files before cleanup
    pub temp_file_max_age: std::time::Duration,
}

impl Default for SparseWriterConfig {
    fn default() -> Self {
        Self {
            enable_preallocation: true,
            chunk_size_hint: 1024 * 1024, // 1MB
            max_temp_files: 64,
            fsync_policy: super::FsyncPolicy::VerifiedChunks,
            commit_policy: CommitPolicy::AtomicRename,
            enable_quarantine: true,
            temp_file_max_age: std::time::Duration::from_hours(24),
        }
    }
}

/// Options for individual write operations
#[derive(Debug, Clone)]
pub struct WriteOptions {
    /// Priority for this write operation
    pub priority: WritePriority,
    /// Whether to fsync after this specific write
    pub force_sync: bool,
    /// Expected final size hint for preallocation
    pub size_hint: Option<u64>,
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self {
            priority: WritePriority::Normal,
            force_sync: false,
            size_hint: None,
        }
    }
}

/// Priority levels for write operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WritePriority {
    /// Low priority, can be deferred
    Low = 0,
    /// Normal priority
    Normal = 1,
    /// High priority, process immediately
    High = 2,
    /// Critical priority, process immediately
    Critical = 3,
}

// Publication and cancellation are terminal decisions. A failed publication
// attempt is intentionally sealed too: an error need not mean that the final
// path is absent, and retrying must not silently reuse an old verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriterLifecycle {
    Accepting,
    Committing,
    Committed,
    Cancelling,
    Cancelled,
}

/// Sparse writer state for tracking progress and consistency
#[derive(Debug)]
struct SparseWriterState {
    /// Object being written
    object_id: ObjectId,
    /// Final destination path
    final_path: PathBuf,
    /// Temporary file handle
    temp_file: Option<File>,
    /// Current temp path
    temp_path: Option<PathBuf>,
    /// Range tracker for written chunks
    range_tracker: RangeTracker,
    /// Written chunks metadata
    written_chunks: BTreeMap<u64, ChunkMetadata>,
    /// Total expected size if known
    expected_size: Option<u64>,
    /// Current allocated size
    allocated_size: u64,
    /// Whether file is preallocated
    is_preallocated: bool,
    /// Creation timestamp
    created_at: Instant,
    /// Last write timestamp
    last_write_at: Instant,
    /// Verification state
    verification_state: VerificationState,
    /// Whether data mutation or a terminal operation is still admissible.
    lifecycle: WriterLifecycle,
}

/// Metadata for individual chunks
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ChunkMetadata {
    /// Offset in final file
    offset: u64,
    /// Size in bytes
    size: u64,
    /// Hash of chunk data
    hash: [u8; 32],
    /// Write timestamp
    written_at: Instant,
    /// Whether chunk was fsynced
    synced: bool,
}

/// Verification state tracking
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum VerificationState {
    /// Not verified yet
    Pending,
    /// Verification in progress
    InProgress,
    /// Successfully verified
    Verified { manifest_root: MerkleRoot },
    /// Verification failed
    Failed { reason: String },
}

/// Main sparse writer implementation
pub struct SparseWriter {
    // Serialize complete operations, not just individual state snapshots.
    // None of the guarded paths may suspend: their private I/O helpers are
    // synchronous, so a parking_lot guard never crosses an await point.
    operation: Mutex<()>,
    /// Writer configuration
    config: SparseWriterConfig,
    /// Platform capabilities
    platform: Arc<PlatformCapabilities>,
    /// Path manager for temp files
    path_manager: Arc<Mutex<TempPathManager>>,
    /// Current writer state
    state: Arc<Mutex<SparseWriterState>>,
}

impl SparseWriter {
    /// Create a new sparse writer for the given object.
    ///
    /// This historical entry point probes synchronously when polled. Native
    /// runtime callers can use `ScopedSparseWriter::new` to own and offload the
    /// entire construction, including destination-filesystem probes.
    pub async fn new(
        _cx: &Cx,
        object_id: ObjectId,
        final_path: impl AsRef<Path>,
        config: SparseWriterConfig,
    ) -> Outcome<Self, SparseWriterError> {
        Self::new_blocking(object_id, final_path.as_ref().to_path_buf(), config)
    }

    // Shared by the historical constructor and the owned pool constructor.
    // Do not await, spawn, or run an executor in this synchronous implementation.
    fn new_blocking(
        object_id: ObjectId,
        final_path: PathBuf,
        config: SparseWriterConfig,
    ) -> Outcome<Self, SparseWriterError> {
        let destination_dir = final_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));

        // Detect capabilities for the destination filesystem. ATP transfers may
        // target a mounted volume whose sparse/preallocation/rename behavior
        // differs from the process working directory.
        let platform = match PlatformCapabilities::detect_for_path_blocking(destination_dir) {
            crate::types::outcome::Outcome::Ok(caps) => Arc::new(caps),
            crate::types::outcome::Outcome::Err(e) => {
                return crate::types::outcome::Outcome::Err(SparseWriterError::PlatformDetection(
                    e.to_string(),
                ));
            }
            crate::types::outcome::Outcome::Cancelled(reason) => {
                return crate::types::outcome::Outcome::Cancelled(reason);
            }
            crate::types::outcome::Outcome::Panicked(payload) => {
                return crate::types::outcome::Outcome::Panicked(payload);
            }
        };

        // Initialize path manager
        let path_manager = Arc::new(Mutex::new(TempPathManager::new(destination_dir)));

        // Create initial state
        let state = Arc::new(Mutex::new(SparseWriterState {
            object_id,
            final_path,
            temp_file: None,
            temp_path: None,
            range_tracker: RangeTracker::new(),
            written_chunks: BTreeMap::new(),
            expected_size: None,
            allocated_size: 0,
            is_preallocated: false,
            created_at: Instant::now(),
            last_write_at: Instant::now(),
            verification_state: VerificationState::Pending,
            lifecycle: WriterLifecycle::Accepting,
        }));

        crate::types::outcome::Outcome::Ok(Self {
            operation: Mutex::new(()),
            config,
            platform,
            path_manager,
            state,
        })
    }

    fn lock_state(&self) -> MutexGuard<'_, SparseWriterState> {
        self.state.lock()
    }

    fn require_accepting(state: &SparseWriterState) -> Result<(), SparseWriterError> {
        if state.lifecycle != WriterLifecycle::Accepting {
            return Err(SparseWriterError::WriteFailed(
                "writer is sealed by a commit or cancellation attempt".to_owned(),
            ));
        }
        Ok(())
    }

    /// Set expected final size for preallocation.
    /// Reject sizes that would exclude an already-written chunk.
    pub fn set_expected_size(&self, size: u64) -> Result<(), SparseWriterError> {
        let _operation = self.operation.lock();
        let mut state = self.lock_state();
        Self::require_accepting(&state)?;
        if state.expected_size == Some(size) {
            return Ok(());
        }
        if let Some(chunk) = state.written_chunks.values().find(|chunk| {
            chunk
                .offset
                .checked_add(chunk.size)
                .is_none_or(|end| end > size)
        }) {
            return Err(SparseWriterError::InvalidRange {
                offset: chunk.offset,
                size: chunk.size,
            });
        }
        // Invalidate before preallocation: even a failed operation may have
        // changed the staging inode. The previous manifest cannot authorize it.
        state.verification_state = VerificationState::Pending;
        // Trigger preallocation if enabled and file is open
        if self.config.enable_preallocation && state.temp_file.is_some() {
            self.preallocate_internal(&mut state, size)?;
        }
        state.expected_size = Some(size);

        Ok(())
    }

    /// Write a chunk at the specified offset
    pub async fn write_chunk(
        &self,
        _cx: &Cx,
        offset: u64,
        data: &[u8],
        options: WriteOptions,
    ) -> Outcome<ChunkRange, SparseWriterError> {
        self.write_chunk_blocking(offset, data, options)
    }

    // One implementation for the historical host-boundary call and the
    // region-owned pool adapter. This function must not await or spawn work.
    fn write_chunk_blocking(
        &self,
        offset: u64,
        data: &[u8],
        options: WriteOptions,
    ) -> Outcome<ChunkRange, SparseWriterError> {
        if data.is_empty() {
            return crate::types::outcome::Outcome::Err(SparseWriterError::EmptyChunk);
        }

        let chunk_size = data.len() as u64;
        let chunk_range = ChunkRange {
            offset,
            size: chunk_size,
        };

        let end = match offset.checked_add(chunk_size) {
            Some(end) => end,
            None => {
                return Outcome::Err(SparseWriterError::InvalidRange {
                    offset,
                    size: chunk_size,
                });
            }
        };
        let sparse_range = SparseRange { start: offset, end };

        let _operation = self.operation.lock();
        let mut state = self.lock_state();
        if let Err(error) = Self::require_accepting(&state) {
            return Outcome::Err(error);
        }
        if state.expected_size.is_some_and(|expected| end > expected) {
            return Outcome::Err(SparseWriterError::InvalidRange {
                offset,
                size: chunk_size,
            });
        }
        if state.range_tracker.overlaps(&sparse_range) {
            return Outcome::Err(SparseWriterError::OverlappingWrite {
                offset,
                size: chunk_size,
            });
        }
        // Reject side-effect-free requests above without disturbing evidence;
        // invalidate before opening, preallocating, or partially writing data.
        state.verification_state = VerificationState::Pending;
        if let Err(error) = self.ensure_temp_file_open_locked(&mut state) {
            return Outcome::Err(error);
        }
        let (hash, synced) = match self.write_chunk_locked(&mut state, offset, data, &options) {
            Ok(result) => result,
            Err(e) => return Outcome::Err(e),
        };
        let written_at = Instant::now();
        state.range_tracker.add_range(sparse_range);
        state.written_chunks.insert(
            offset,
            ChunkMetadata {
                offset,
                size: chunk_size,
                hash,
                written_at,
                synced,
            },
        );
        state.last_write_at = written_at;

        Outcome::ok(chunk_range)
    }

    fn is_complete_locked(state: &SparseWriterState) -> bool {
        if let Some(expected_size) = state.expected_size {
            state.range_tracker.is_contiguous_to(expected_size)
        } else {
            false
        }
    }

    /// Check if all expected ranges have been written
    pub fn is_complete(&self) -> bool {
        let state = self.lock_state();
        Self::is_complete_locked(&state)
    }

    /// Verify written data against a trusted manifest and selected object ID.
    ///
    /// A content-addressed ID is checked independently of optional manifest
    /// hashes. A manifest-addressed file must have a whole-object content hash;
    /// chunk-only authorization requires [`Self::verify_with_chunk_commitment`]
    /// because the legacy manifest root does not commit chunk descriptors.
    pub async fn verify(
        &self,
        _cx: &Cx,
        expected_manifest: &Manifest,
    ) -> Outcome<(), SparseWriterError> {
        self.verify_inner(expected_manifest, None)
    }

    /// Verify with an independently trusted chunk commitment before any file I/O.
    ///
    /// Obtain `expected` from the trusted producer, not by recomputing it from
    /// untrusted received metadata. Chunk-only manifests must cover every file
    /// byte exactly; a whole-object hash permits partial chunk hints. Failure
    /// invalidates previous verification and never falls back to the legacy root.
    /// This uses the same serialized verification/publication lifecycle as `verify`.
    pub async fn verify_with_chunk_commitment(
        &self,
        _cx: &Cx,
        expected_manifest: &Manifest,
        expected: &ManifestChunkCommitment,
    ) -> Outcome<(), SparseWriterError> {
        self.verify_inner(expected_manifest, Some(expected))
    }

    fn verify_inner(
        &self,
        expected_manifest: &Manifest,
        expected_commitment: Option<&ManifestChunkCommitment>,
    ) -> Outcome<(), SparseWriterError> {
        let _operation = self.operation.lock();
        if let Err(error) = Self::require_accepting(&self.lock_state()) {
            return Outcome::Err(error);
        }
        if let Some(expected) = expected_commitment {
            if let Err(error) = expected.verify(expected_manifest) {
                return self.fail_verification(format!("chunk commitment validation failed: {error}"));
            }
        } else if let Err(error) = expected_manifest.validate() {
            return self.fail_verification(format!("manifest validation failed: {error}"));
        }

        let verification_input = {
            let mut state = self.lock_state();
            state.verification_state = VerificationState::InProgress;

            if !Self::is_complete_locked(&state) {
                return Self::fail_verification_locked(
                    &mut state,
                    "writer is incomplete; cannot verify sparse output".to_owned(),
                );
            }

            // Empty objects have no write_chunk call to create their staging
            // inode. Materialize one at the same verification boundary instead
            // of treating an empty, complete object as missing data.
            if state.expected_size == Some(0) && state.temp_file.is_none() {
                if let Err(error) = self.ensure_temp_file_open_locked(&mut state) {
                    return Self::fail_verification_locked(
                        &mut state,
                        format!("empty object staging failed: {error}"),
                    );
                }
            }

            let Some(temp_path) = state.temp_path.clone() else {
                return Self::fail_verification_locked(
                    &mut state,
                    "writer has no temporary file to verify".to_owned(),
                );
            };

            if let Some(file) = state.temp_file.as_mut() {
                if let Err(error) = file.flush() {
                    return Self::fail_verification_locked(
                        &mut state,
                        format!("flush before verification failed: {error}"),
                    );
                }
            }

            (
                state.object_id.clone(),
                temp_path,
                state.expected_size,
                state.written_chunks.clone(),
            )
        };

        let (object_id, temp_path, expected_size, written_chunks) = verification_input;
        let Some(manifest_object) = expected_manifest.objects.get(&object_id) else {
            return self.fail_verification(format!("manifest does not contain object {object_id}"));
        };
        if manifest_object.id != object_id {
            return self.fail_verification(
                "manifest object identity differs from the writer's selected object".to_owned(),
            );
        }

        let mut file = match File::open(&temp_path) {
            Ok(file) => file,
            Err(error) => {
                return self.fail_verification(format!("open for verification failed: {error}"));
            }
        };
        let file_len = match file.metadata() {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                return self
                    .fail_verification(format!("metadata for verification failed: {error}"));
            }
        };

        if let Some(expected_size) = expected_size {
            if file_len != expected_size {
                return self.fail_verification(format!(
                    "writer expected size {expected_size}, found {file_len} bytes"
                ));
            }
        }
        if let Some(manifest_size) = manifest_object.size_bytes {
            if file_len != manifest_size {
                return self.fail_verification(format!(
                    "manifest expected size {manifest_size}, found {file_len} bytes"
                ));
            }
        }

        // Local write hashes only prove what this receiver wrote. They are not
        // sender-authorized content evidence. When there is no whole-object hash,
        // or independently selected content ID, the pinned chunk ledger must
        // cover every byte. The unmodified legacy root alone cannot authorize it.
        if manifest_object.content_hash.is_none() && !object_id.is_content_addressed() {
            if expected_commitment.is_none() {
                return self.fail_verification(
                    "chunk-only verification requires an independently trusted chunk commitment"
                        .to_owned(),
                );
            }
            if let Err(reason) = Self::require_complete_manifest_chunks(
                &manifest_object.chunk_boundaries,
                file_len,
            ) {
                return self.fail_verification(reason);
            }
        }

        for (offset, metadata) in &written_chunks {
            let end = match offset.checked_add(metadata.size) {
                Some(end) => end,
                None => {
                    return self.fail_verification(format!(
                        "written chunk at {offset} overflows with size {}",
                        metadata.size
                    ));
                }
            };
            if end > file_len {
                return self.fail_verification(format!(
                    "written chunk at {offset}..{end} is outside verified file"
                ));
            }
            let actual_hash = match Self::hash_file_range(&mut file, *offset, metadata.size) {
                Ok(hash) => hash,
                Err(error) => return self.fail_verification(error.to_string()),
            };
            if actual_hash != metadata.hash {
                return self
                    .fail_verification(format!("written chunk hash mismatch at offset {offset}"));
            }
        }

        // A content-addressed key is an independent commitment. Do not permit
        // a manifest to substitute another content_hash (or a chunk ledger) for
        // the immutable identity selected by the receiving writer.
        if manifest_object.content_hash.is_some() || object_id.is_content_addressed() {
            let actual_hash = if object_id.is_content_addressed() {
                Self::hash_file_with_prefix(&mut file, Some(CONTENT_ID_DOMAIN))
            } else {
                Self::hash_file_with_prefix(&mut file, None)
            };
            let actual_hash = match actual_hash {
                Ok(hash) => hash,
                Err(error) => {
                    return self
                        .fail_verification(format!("content hash verification failed: {error}"));
                }
            };
            if manifest_object.content_hash.is_some_and(|expected| actual_hash != expected) {
                return self.fail_verification("manifest content hash mismatch".to_owned());
            }
            if object_id.is_content_addressed() && actual_hash != *object_id.hash_bytes() {
                return self.fail_verification("content-addressed object identity mismatch".to_owned());
            }
        }

        for boundary in &manifest_object.chunk_boundaries {
            let end = match boundary.byte_offset.checked_add(boundary.size_bytes) {
                Some(end) => end,
                None => {
                    return self.fail_verification(format!(
                        "manifest chunk {} overflows at offset {} with size {}",
                        boundary.index, boundary.byte_offset, boundary.size_bytes
                    ));
                }
            };
            if end > file_len {
                return self.fail_verification(format!(
                    "manifest chunk {} range {}..{} is outside verified file",
                    boundary.index, boundary.byte_offset, end
                ));
            }
            let actual_hash =
                match Self::hash_file_range(&mut file, boundary.byte_offset, boundary.size_bytes) {
                    Ok(hash) => hash,
                    Err(error) => return self.fail_verification(error.to_string()),
                };
            if actual_hash != boundary.content_hash {
                return self
                    .fail_verification(format!("manifest chunk {} hash mismatch", boundary.index));
            }
        }

        let mut state = self.lock_state();
        state.verification_state = VerificationState::Verified {
            manifest_root: expected_manifest.merkle_root.clone(),
        };

        Outcome::ok(())
    }

    /// Commit the written data to the final destination using the configured policy.
    ///
    /// On Unix, durability-enabled policies sync the destination directory after
    /// publication. A sync error can occur after the destination becomes visible;
    /// callers must not interpret an error as proof that publication did not occur.
    /// Once publication is attempted, this writer is sealed even on failure. Keep
    /// its staging/destination evidence for recovery instead of retrying blindly.
    /// Repeating a successful commit returns its path without publishing again.
    /// `CopyAndVerify` retains its existing non-atomic visibility semantics.
    pub async fn commit(&self, _cx: &Cx) -> Outcome<PathBuf, SparseWriterError> {
        self.commit_with_fsync(File::sync_all)
    }

    // A private injection point exercises the real terminal publication path,
    // including its lifecycle transition, when the storage barrier fails.
    fn commit_with_fsync(
        &self,
        sync_file: impl FnOnce(&File) -> std::io::Result<()>,
    ) -> Outcome<PathBuf, SparseWriterError> {
        let _operation = self.operation.lock();
        {
            let mut state = self.lock_state();
            match state.lifecycle {
                WriterLifecycle::Committed => return Outcome::ok(state.final_path.clone()),
                WriterLifecycle::Accepting => {}
                WriterLifecycle::Committing => {
                    return Outcome::Err(SparseWriterError::CommitFailed(
                        "previous commit did not settle successfully; inspect retained evidence"
                            .to_owned(),
                    ));
                }
                WriterLifecycle::Cancelling | WriterLifecycle::Cancelled => {
                    return Outcome::Err(SparseWriterError::CommitFailed(
                        "writer was cancelled".to_owned(),
                    ));
                }
            }
            if !Self::is_complete_locked(&state) {
                return Outcome::Err(SparseWriterError::IncompleteData);
            }
            if !matches!(state.verification_state, VerificationState::Verified { .. }) {
                return Outcome::Err(SparseWriterError::NotVerified);
            }
            // Seal before any durability/publication effect. An I/O error or
            // unwind must never reopen the old verification for mutation/retry.
            state.lifecycle = WriterLifecycle::Committing;
        }

        match self.apply_fsync_policy_with(sync_file) {
            Outcome::Ok(()) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::panicked(payload),
        }

        let final_path = match self.atomic_commit() {
            Outcome::Ok(path) => path,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::panicked(payload),
        };

        if let Err(error) = self.sync_commit_destination(&final_path) {
            return Outcome::Err(error);
        }
        if let Err(error) = self.cleanup_temp_file() {
            return Outcome::Err(error);
        }
        self.lock_state().lifecycle = WriterLifecycle::Committed;
        Outcome::ok(final_path)
    }

    fn sync_commit_destination(&self, final_path: &Path) -> Result<(), SparseWriterError> {
        if self.config.fsync_policy == super::FsyncPolicy::Never {
            return Ok(());
        }

        // A copy creates a different inode, so syncing the staging file does not
        // make the copied destination durable. Non-Unix link mode also copies.
        if self.config.commit_policy == CommitPolicy::CopyAndVerify
            || (cfg!(not(unix)) && self.config.commit_policy == CommitPolicy::LinkAndUnlink)
        {
            std::fs::OpenOptions::new()
                .write(true)
                .open(final_path)
                .and_then(|file| file.sync_all())
                .map_err(|error| SparseWriterError::SyncFailed(error.to_string()))?;
        }

        #[cfg(unix)]
        {
            let parent = final_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| SparseWriterError::SyncFailed(error.to_string()))?;
        }
        Ok(())
    }

    /// Cancel the write operation and clean up.
    ///
    /// Successful cancellation is idempotent and permanently seals the writer.
    /// A failed cleanup may be retried, but a committed or unresolved publication
    /// is never converted into cancellation or discarded by this operation.
    pub async fn cancel(&self, _cx: &Cx) -> Outcome<(), SparseWriterError> {
        self.cancel_blocking()
    }

    fn cancel_blocking(&self) -> Outcome<(), SparseWriterError> {
        let _operation = self.operation.lock();
        {
            let mut state = self.lock_state();
            match state.lifecycle {
                WriterLifecycle::Cancelled => return Outcome::ok(()),
                WriterLifecycle::Committed | WriterLifecycle::Committing => {
                    return Outcome::Err(SparseWriterError::CommitFailed(
                        "cannot cancel a committed or unresolved publication".to_owned(),
                    ));
                }
                WriterLifecycle::Accepting | WriterLifecycle::Cancelling => {}
            }
            state.lifecycle = WriterLifecycle::Cancelling;
            state.verification_state = VerificationState::Pending;
        }
        let cleanup = if self.config.enable_quarantine {
            self.quarantine_temp_file("cancelled")
        } else {
            self.cleanup_temp_file()
        };
        if let Err(error) = cleanup {
            return Outcome::Err(error);
        }
        self.lock_state().lifecycle = WriterLifecycle::Cancelled;
        Outcome::ok(())
    }

    /// Get current write statistics
    pub fn get_stats(&self) -> SparseWriterStats {
        let state = self.lock_state();
        let total_written = state.range_tracker.total_bytes();
        let chunk_count = state.written_chunks.len();
        let completion_ratio = if let Some(expected) = state.expected_size {
            if expected == 0 {
                1.0
            } else {
                total_written as f64 / expected as f64
            }
        } else {
            0.0
        };

        SparseWriterStats {
            object_id: state.object_id.clone(),
            total_bytes_written: total_written,
            chunk_count,
            allocated_size: state.allocated_size,
            completion_ratio,
            is_preallocated: state.is_preallocated,
            created_at: state.created_at,
            last_write_at: state.last_write_at,
            verification_state: state.verification_state.clone(),
        }
    }

    // Internal implementation methods

    fn ensure_temp_file_open_locked(
        &self,
        state: &mut SparseWriterState,
    ) -> Result<(), SparseWriterError> {
        if state.temp_file.is_some() {
            return Ok(());
        }

        // Own a newly created private inode, not merely an available-looking
        // pathname. The manager retries collisions without tracking or deleting
        // the pre-existing file, directory, or symlink that caused them.
        let (temp_path, file) = self.path_manager.lock()
            .create_temp_file(&state.object_id.to_string())
            .map_err(|error| match error {
                super::temp_management::TempFileCreationError::Path(error) => {
                    SparseWriterError::TempPathCreation(error.to_string())
                }
                super::temp_management::TempFileCreationError::Open(error) => {
                    SparseWriterError::FileOpen(error.to_string())
                }
            })?;

        state.temp_file = Some(file);
        state.temp_path = Some(temp_path);

        // Apply preallocation if size is known
        if let Some(size) = state.expected_size {
            if self.config.enable_preallocation {
                match self.preallocate_internal(state, size) {
                    Ok(()) => (),
                    Err(e) => return Err(e),
                }
            }
        }

        Ok(())
    }

    #[allow(unsafe_code)]
    fn preallocate_internal(
        &self,
        state: &mut SparseWriterState,
        size: u64,
    ) -> Result<(), SparseWriterError> {
        if let Some(ref mut file) = state.temp_file {
            if self.platform.filesystem.supports_preallocation {
                // Platform-specific preallocation
                #[cfg(target_os = "linux")]
                {
                    use std::os::unix::io::AsRawFd;
                    let size_i64 = i64::try_from(size)
                        .map_err(|_| SparseWriterError::PreallocationTooLarge { size })?;
                    unsafe {
                        let fd = file.as_raw_fd();
                        let result = libc::fallocate(fd, 0, 0, size_i64);
                        if result == 0 {
                            state.allocated_size = size;
                            state.is_preallocated = true;
                        }
                    }
                }

                #[cfg(not(target_os = "linux"))]
                {
                    // Best-effort logical extension, not a physical-space
                    // reservation. Never overwrite a payload byte or shrink
                    // an existing file when this hint is repeated.
                    if let Ok(metadata) = file.metadata()
                        && (metadata.len() >= size || file.set_len(size).is_ok())
                    {
                        state.allocated_size = metadata.len().max(size);
                        state.is_preallocated = true;
                    }
                }
            }
        }
        Ok(())
    }

    fn write_chunk_locked(
        &self,
        state: &mut SparseWriterState,
        offset: u64,
        data: &[u8],
        options: &WriteOptions,
    ) -> Result<([u8; 32], bool), SparseWriterError> {
        let file = state
            .temp_file
            .as_mut()
            .ok_or(SparseWriterError::NoTempFile)?;

        // Seek to offset
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| SparseWriterError::SeekFailed(e.to_string()))?;

        // Write data
        file.write_all(data)
            .map_err(|e| SparseWriterError::WriteFailed(e.to_string()))?;

        // Compute a stable content digest for later manifest verification.
        let hash = Sha256::digest(data).into();

        // Apply fsync if required
        let synced = if options.force_sync
            || matches!(self.config.fsync_policy, super::FsyncPolicy::EveryWrite)
        {
            file.sync_data()
                .map_err(|e| SparseWriterError::SyncFailed(e.to_string()))?;
            true
        } else {
            false
        };

        Ok((hash, synced))
    }

    // Keep the storage barrier injectable only inside this module so tests can
    // exercise sync failures without depending on a failing disk or unsafe FDs.
    fn apply_fsync_policy_with(
        &self,
        sync_file: impl FnOnce(&File) -> std::io::Result<()>,
    ) -> Outcome<(), SparseWriterError> {
        let mut state = self.lock_state();
        let Some(file) = state.temp_file.as_ref() else {
            // A missing descriptor is never evidence of a completed barrier,
            // including for an explicitly non-durable publication policy.
            return Outcome::Err(SparseWriterError::NoTempFile);
        };

        if self.config.fsync_policy != super::FsyncPolicy::Never {
            // Per-chunk sync flags cannot stand in for the final inode barrier:
            // empty objects have no chunks, and preallocation/metadata changes
            // can follow the last chunk write. Synchronize the sealed inode for
            // every durability-enabled policy before any publication effect.
            if let Err(error) = sync_file(file) {
                return Outcome::Err(SparseWriterError::SyncFailed(error.to_string()));
            }
            for chunk in state.written_chunks.values_mut() {
                chunk.synced = true;
            }
        }

        Outcome::ok(())
    }

    fn atomic_commit(&self) -> Outcome<PathBuf, SparseWriterError> {
        let (temp_path, final_path) = {
            let mut state = self.lock_state();
            let temp_path = match state.temp_path.clone() {
                Some(path) => path,
                None => return Outcome::Err(SparseWriterError::NoTempFile),
            };
            let final_path = state.final_path.clone();
            if let Some(file) = state.temp_file.as_mut() {
                if let Err(error) = file.flush() {
                    return Outcome::Err(SparseWriterError::CommitFailed(format!(
                        "flush before commit failed: {error}"
                    )));
                }
            }
            state.temp_file = None;
            (temp_path, final_path)
        };

        match self.config.commit_policy {
            CommitPolicy::AtomicRename => match std::fs::rename(&temp_path, &final_path) {
                Ok(_) => {}
                Err(e) => return Outcome::Err(SparseWriterError::CommitFailed(e.to_string())),
            },
            CommitPolicy::CopyAndVerify => {
                match std::fs::copy(&temp_path, &final_path) {
                    Ok(_) => {}
                    Err(e) => return Outcome::Err(SparseWriterError::CommitFailed(e.to_string())),
                }
                if let Err(error) = Self::verify_copied_file(&temp_path, &final_path) {
                    return Outcome::Err(error);
                }
            }
            CommitPolicy::LinkAndUnlink => {
                #[cfg(unix)]
                {
                    match std::fs::hard_link(&temp_path, &final_path) {
                        Ok(_) => {}
                        Err(e) => {
                            return Outcome::Err(SparseWriterError::CommitFailed(e.to_string()));
                        }
                    }
                    match std::fs::remove_file(&temp_path) {
                        Ok(_) => {}
                        Err(e) => {
                            return Outcome::Err(SparseWriterError::CommitFailed(e.to_string()));
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    // Fallback to copy on non-Unix systems
                    match std::fs::copy(&temp_path, &final_path) {
                        Ok(_) => {}
                        Err(e) => {
                            return Outcome::Err(SparseWriterError::CommitFailed(e.to_string()));
                        }
                    }
                }
            }
        }

        Outcome::ok(final_path)
    }

    fn cleanup_temp_file(&self) -> Result<(), SparseWriterError> {
        let mut state = self.lock_state();

        if let Some(temp_path) = state.temp_path.as_ref() {
            match std::fs::remove_file(temp_path) {
                Ok(()) => {}
                // Rename/link publication already consumed the staging name.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(SparseWriterError::CommitFailed(format!(
                        "temporary file cleanup failed: {error}"
                    )));
                }
            }
        }

        state.temp_path = None;
        state.temp_file = None;
        Ok(())
    }

    fn quarantine_temp_file(&self, reason: &str) -> Result<(), SparseWriterError> {
        let mut state = self.lock_state();

        if let Some(temp_path) = state.temp_path.as_ref() {
            let mut path_mgr = self.path_manager.lock();
            path_mgr
                .quarantine_file(temp_path, reason)
                .map_err(|e| SparseWriterError::TempPathCreation(e.to_string()))?;
        }

        // Retain the original path and descriptor when quarantine fails so a
        // sealed cancellation can retry cleanup without losing its evidence.
        state.temp_path = None;
        state.temp_file = None;
        Ok(())
    }

    /// Chunk-only verification must authenticate exactly [0, file_len).
    /// Manifest::validate checks ordering and arithmetic, but intentionally does
    /// not make a partial chunk description evidence for an entire local file.
    fn require_complete_manifest_chunks(
        chunks: &[ChunkBoundary],
        file_len: u64,
    ) -> Result<(), String> {
        // A pinned empty ledger covers an empty file, but never a nonempty one.
        // Coverage, rather than a fabricated zero-length descriptor, proves it.
        let mut covered = 0_u64;
        for chunk in chunks {
            if chunk.size_bytes == 0 {
                return Err(format!("manifest chunk {} has zero length", chunk.index));
            }
            if chunk.byte_offset != covered {
                return Err(format!(
                    "manifest chunk coverage expected offset {covered}, found {}",
                    chunk.byte_offset,
                ));
            }
            covered = covered.checked_add(chunk.size_bytes).ok_or_else(|| {
                "manifest chunk coverage overflows u64".to_owned()
            })?;
            if covered > file_len {
                return Err("manifest chunk coverage exceeds the local file length".to_owned());
            }
        }
        if covered != file_len {
            return Err(format!(
                "manifest chunk coverage ends at {covered}, expected {file_len}",
            ));
        }
        Ok(())
    }

    fn fail_verification(&self, reason: String) -> Outcome<(), SparseWriterError> {
        let mut state = self.lock_state();
        Self::fail_verification_locked(&mut state, reason)
    }

    fn fail_verification_locked(
        state: &mut SparseWriterState,
        reason: String,
    ) -> Outcome<(), SparseWriterError> {
        state.verification_state = VerificationState::Failed {
            reason: reason.clone(),
        };
        Outcome::Err(SparseWriterError::VerificationFailed(reason))
    }

    fn verify_copied_file(source: &Path, destination: &Path) -> Result<(), SparseWriterError> {
        let source_digest = Self::file_digest(source)?;
        let destination_digest = Self::file_digest(destination)?;
        if source_digest != destination_digest {
            return Err(SparseWriterError::CommitFailed(
                "copy verification failed: destination digest differs from temp file".to_owned(),
            ));
        }
        Ok(())
    }

    fn file_digest(path: &Path) -> Result<[u8; 32], SparseWriterError> {
        let mut file =
            File::open(path).map_err(|error| SparseWriterError::CommitFailed(error.to_string()))?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|error| SparseWriterError::CommitFailed(error.to_string()))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(hasher.finalize().into())
    }

    fn hash_file_with_prefix(
        file: &mut File,
        prefix: Option<&[u8]>,
    ) -> Result<[u8; 32], SparseWriterError> {
        file.seek(SeekFrom::Start(0))
            .map_err(|error| SparseWriterError::VerificationFailed(error.to_string()))?;
        let mut hasher = Sha256::new();
        if let Some(prefix) = prefix {
            hasher.update(prefix);
        }
        let mut buffer = [0u8; DIGEST_BUFFER_SIZE];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|error| SparseWriterError::VerificationFailed(error.to_string()))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(hasher.finalize().into())
    }

    fn hash_file_range(
        file: &mut File,
        offset: u64,
        size: u64,
    ) -> Result<[u8; 32], SparseWriterError> {
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| SparseWriterError::VerificationFailed(error.to_string()))?;
        let mut remaining = size;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; DIGEST_BUFFER_SIZE];

        while remaining > 0 {
            let to_read = remaining.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..to_read])
                .map_err(|error| SparseWriterError::VerificationFailed(error.to_string()))?;
            hasher.update(&buffer[..to_read]);
            remaining -= to_read as u64;
        }

        Ok(hasher.finalize().into())
    }
}

/// Statistics for sparse writer operations
#[derive(Debug, Clone)]
pub struct SparseWriterStats {
    pub object_id: ObjectId,
    pub total_bytes_written: u64,
    pub chunk_count: usize,
    pub allocated_size: u64,
    pub completion_ratio: f64,
    pub is_preallocated: bool,
    pub created_at: Instant,
    pub last_write_at: Instant,
    pub verification_state: VerificationState,
}

/// Errors that can occur during sparse writing
#[derive(Debug, thiserror::Error)]
pub enum SparseWriterError {
    #[error("Platform detection failed: {0}")]
    PlatformDetection(String),

    #[error("Failed to create temp path: {0}")]
    TempPathCreation(String),

    #[error("Failed to open file: {0}")]
    FileOpen(String),

    #[error("No temp file available")]
    NoTempFile,

    #[error("Empty chunk not allowed")]
    EmptyChunk,

    #[error("Overlapping write at offset {offset}, size {size}")]
    OverlappingWrite { offset: u64, size: u64 },

    #[error("Invalid chunk range at offset {offset}, size {size}")]
    InvalidRange { offset: u64, size: u64 },

    #[error("Preallocation size is too large: {size}")]
    PreallocationTooLarge { size: u64 },

    #[error("Seek failed: {0}")]
    SeekFailed(String),

    #[error("Write failed: {0}")]
    WriteFailed(String),

    #[error("Sync failed: {0}")]
    SyncFailed(String),

    #[error("Data incomplete, cannot commit")]
    IncompleteData,

    #[error("Data not verified")]
    NotVerified,

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Commit failed: {0}")]
    CommitFailed(String),
}

#[cfg(test)]
#[path = "sparse_writer_lifecycle_tests.rs"]
mod lifecycle_tests;

#[cfg(test)]
#[path = "sparse_writer_durability_tests.rs"]
mod durability_tests;

#[cfg(test)]
#[path = "sparse_writer_integrity_tests.rs"]
mod integrity_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::manifest::Manifest;
    use crate::atp::object::ContentId;
    use crate::atp::object::{MetadataPolicy, Object, ObjectGraph};

    fn create_test_cx() -> Cx {
        Cx::for_testing()
    }

    fn test_object_id(label: &str) -> ObjectId {
        ObjectId::content(ContentId::from_bytes(label.as_bytes()))
    }

    fn unique_temp_path(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "asupersync_sparse_writer_{label}_{}_{}",
            std::process::id(),
            nanos
        ))
    }

    fn manifest_for_content(content: &[u8]) -> (ObjectId, Manifest) {
        let object = Object::file(content.to_vec());
        let object_id = object.id.clone();
        let mut graph = ObjectGraph::new();
        graph
            .add_root(object)
            .expect("test object graph should build");
        let manifest = Manifest::from_graph(&graph, MetadataPolicy::portable())
            .expect("manifest should build");
        (object_id, manifest)
    }

    #[test]
    fn test_sparse_writer_basic() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let object_id = test_object_id("test-object");
            let temp_dir = std::env::temp_dir();
            let final_path = temp_dir.join("test_sparse_output");

            let config = SparseWriterConfig::default();
            let writer = SparseWriter::new(&cx, object_id, final_path, config)
                .await
                .unwrap();

            // Set expected size
            writer.set_expected_size(1000).unwrap();

            // Write some chunks out of order
            let options = WriteOptions::default();
            writer
                .write_chunk(&cx, 500, b"middle", options.clone())
                .await
                .unwrap();
            writer
                .write_chunk(&cx, 0, b"start", options.clone())
                .await
                .unwrap();
            writer.write_chunk(&cx, 994, b"end", options).await.unwrap();

            // Check completion status
            assert!(!writer.is_complete()); // Still has gaps

            // Fill remaining gaps
            let fill_data = vec![0u8; 495];
            writer
                .write_chunk(&cx, 5, &fill_data, WriteOptions::default())
                .await
                .unwrap();
            let middle_fill = vec![0u8; 488];
            writer
                .write_chunk(&cx, 506, &middle_fill, WriteOptions::default())
                .await
                .unwrap();
            let end_fill = vec![0u8; 3];
            writer
                .write_chunk(&cx, 997, &end_fill, WriteOptions::default())
                .await
                .unwrap();

            assert!(writer.is_complete());
        });
    }

    #[test]
    fn out_of_object_writes_leave_file_and_progress_unchanged() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let content = b"abcdefgh";
            let (object_id, manifest) = manifest_for_content(content);
            let writer = SparseWriter::new(
                &cx,
                object_id,
                unique_temp_path("range_rejection"),
                SparseWriterConfig {
                    enable_preallocation: false,
                    ..SparseWriterConfig::default()
                },
            )
            .await
            .unwrap();
            writer.set_expected_size(8).unwrap();

            for offset in [7, 8, 9] {
                assert!(matches!(
                    writer
                        .write_chunk(&cx, offset, b"xx", WriteOptions::default())
                        .await,
                    Outcome::Err(SparseWriterError::InvalidRange { .. })
                ));
                let state = writer.lock_state();
                assert!(state.temp_file.is_none());
                assert!(state.temp_path.is_none());
                assert!(state.written_chunks.is_empty());
            }

            writer
                .write_chunk(&cx, 0, &content[..4], WriteOptions::default())
                .await
                .unwrap();
            assert!(matches!(
                writer
                    .write_chunk(&cx, 7, b"xx", WriteOptions::default())
                    .await,
                Outcome::Err(SparseWriterError::InvalidRange { .. })
            ));
            let temp_path = writer.lock_state().temp_path.clone().unwrap();
            assert_eq!(std::fs::read(&temp_path).unwrap(), &content[..4]);
            assert_eq!(writer.get_stats().total_bytes_written, 4);
            assert_eq!(writer.get_stats().chunk_count, 1);

            // A rejected write must not prevent an exact-end write or verification.
            writer
                .write_chunk(&cx, 4, &content[4..], WriteOptions::default())
                .await
                .unwrap();
            assert!(writer.is_complete());
            writer.verify(&cx, &manifest).await.unwrap();
            assert_eq!(std::fs::read(&temp_path).unwrap(), content);
        });
    }

    #[test]
    fn expected_size_cannot_exclude_previously_written_bytes() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let writer = SparseWriter::new(
                &cx,
                test_object_id("resize-boundary"),
                unique_temp_path("resize_boundary"),
                SparseWriterConfig {
                    enable_preallocation: false,
                    ..SparseWriterConfig::default()
                },
            )
            .await
            .unwrap();
            writer
                .write_chunk(&cx, 4, b"efgh", WriteOptions::default())
                .await
                .unwrap();
            assert!(writer.set_expected_size(4).is_err());
            assert_eq!(writer.lock_state().expected_size, None);
            writer.set_expected_size(8).unwrap();
            let path = writer.lock_state().temp_path.clone().unwrap();
            let bytes = std::fs::read(&path).unwrap();
            for size in [0, 4, 7] {
                assert!(matches!(
                    writer.set_expected_size(size),
                    Err(SparseWriterError::InvalidRange { offset: 4, size: 4 })
                ));
                assert_eq!(writer.lock_state().expected_size, Some(8));
                assert_eq!(std::fs::read(&path).unwrap(), bytes);
                assert_eq!(writer.get_stats().total_bytes_written, 4);
                assert!(!writer.is_complete());
            }
            writer
                .write_chunk(&cx, 0, b"abcd", WriteOptions::default())
                .await
                .unwrap();
            assert!(writer.is_complete());
            writer.set_expected_size(12).unwrap();
            assert!(!writer.is_complete());
            writer
                .write_chunk(&cx, 8, b"ijkl", WriteOptions::default())
                .await
                .unwrap();
            assert!(writer.is_complete());
            assert_eq!(std::fs::read(path).unwrap(), b"abcdefghijkl");
        });
    }

    #[test]
    fn test_overlapping_write_detection() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let object_id = test_object_id("test-overlap");
            let temp_dir = std::env::temp_dir();
            let final_path = temp_dir.join("test_overlap_output");

            let config = SparseWriterConfig::default();
            let writer = SparseWriter::new(&cx, object_id, final_path, config)
                .await
                .unwrap();

            let options = WriteOptions::default();

            // First write
            writer
                .write_chunk(&cx, 0, b"hello", options.clone())
                .await
                .unwrap();

            // Overlapping write should fail
            let result = writer.write_chunk(&cx, 2, b"world", options).await;
            assert!(matches!(
                result,
                Outcome::Err(SparseWriterError::OverlappingWrite { .. })
            ));
        });
    }

    #[test]
    fn test_preallocation() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let object_id = test_object_id("test-prealloc");
            let temp_dir = std::env::temp_dir();
            let final_path = temp_dir.join("test_prealloc_output");

            let mut config = SparseWriterConfig::default();
            config.enable_preallocation = true;

            let writer = SparseWriter::new(&cx, object_id, final_path, config)
                .await
                .unwrap();

            // Set expected size - should trigger preallocation
            writer.set_expected_size(1024 * 1024).unwrap();

            let stats = writer.get_stats();
            // Note: actual preallocation depends on platform support
            assert!(stats.allocated_size <= 1024 * 1024);
        });
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn failed_preallocation_preserves_expected_size_and_completion() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let mut writer = SparseWriter::new(
                &cx,
                test_object_id("failed-preallocation"),
                unique_temp_path("failed_preallocation"),
                SparseWriterConfig {
                    enable_preallocation: true,
                    ..SparseWriterConfig::default()
                },
            )
            .await
            .unwrap();
            Arc::make_mut(&mut writer.platform)
                .filesystem
                .supports_preallocation = true;
            writer.set_expected_size(4).unwrap();
            writer
                .write_chunk(&cx, 0, b"data", WriteOptions::default())
                .await
                .unwrap();
            assert!(writer.is_complete());
            let before = writer.get_stats();
            assert!(matches!(
                writer.set_expected_size(u64::MAX),
                Err(SparseWriterError::PreallocationTooLarge { size: u64::MAX })
            ));
            let state = writer.lock_state();
            assert_eq!(state.expected_size, Some(4));
            assert_eq!(
                std::fs::read(state.temp_path.as_ref().unwrap()).unwrap(),
                b"data"
            );
            drop(state);
            assert!(writer.is_complete());
            let after = writer.get_stats();
            assert_eq!(before.allocated_size, after.allocated_size);
            assert_eq!(before.total_bytes_written, after.total_bytes_written);
        });
    }

    #[test]
    fn repeated_preallocation_preserves_payload_and_empty_file() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let mut writer = SparseWriter::new(
                &cx,
                test_object_id("preallocation-preservation"),
                unique_temp_path("preallocation_preservation"),
                SparseWriterConfig {
                    enable_preallocation: true,
                    ..SparseWriterConfig::default()
                },
            )
            .await
            .unwrap();
            // Exercise the platform path even if capability probing on the
            // test filesystem conservatively reports no preallocation.
            Arc::make_mut(&mut writer.platform)
                .filesystem
                .supports_preallocation = true;
            writer.set_expected_size(0).unwrap();
            let path = {
                let mut state = writer.lock_state();
                writer.ensure_temp_file_open_locked(&mut state).unwrap();
                state.temp_path.clone().unwrap()
            };
            assert!(std::fs::read(&path).unwrap().is_empty());

            writer.set_expected_size(8).unwrap();
            writer
                .write_chunk(&cx, 0, b"abcdefgh", WriteOptions::default())
                .await
                .unwrap();
            for _ in 0..2 {
                writer.set_expected_size(8).unwrap();
                assert_eq!(std::fs::read(&path).unwrap(), b"abcdefgh");
                assert!(writer.is_complete());
            }
            writer.set_expected_size(12).unwrap();
            assert_eq!(&std::fs::read(&path).unwrap()[..8], b"abcdefgh");
            writer
                .write_chunk(&cx, 8, b"ijkl", WriteOptions::default())
                .await
                .unwrap();
            writer.set_expected_size(12).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), b"abcdefghijkl");
            assert!(writer.is_complete());
        });
    }

    #[test]
    fn streaming_content_id_hash_matches_object_content_id_domain() {
        let content = b"content id domain regression guard";
        let path = unique_temp_path("content_id_domain");
        std::fs::write(&path, content).unwrap();
        let mut file = File::open(&path).unwrap();

        let streaming_hash =
            SparseWriter::hash_file_with_prefix(&mut file, Some(CONTENT_ID_DOMAIN)).unwrap();

        assert_eq!(streaming_hash, *ContentId::from_bytes(content).hash());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn stats_report_complete_ratio_for_zero_expected_size() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let object_id = test_object_id("test-zero-stats");
            let writer = SparseWriter::new(
                &cx,
                object_id,
                unique_temp_path("zero_stats"),
                SparseWriterConfig::default(),
            )
            .await
            .unwrap();

            writer.set_expected_size(0).unwrap();

            let stats = writer.get_stats();
            assert_eq!(stats.completion_ratio, 1.0);
            assert!(writer.is_complete());
        });
    }

    #[test]
    fn verify_checks_manifest_content_hash_and_records_real_root() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let content = b"verified sparse writer content";
            let (object_id, manifest) = manifest_for_content(content);
            let writer = SparseWriter::new(
                &cx,
                object_id,
                unique_temp_path("verify_success"),
                SparseWriterConfig::default(),
            )
            .await
            .unwrap();

            writer.set_expected_size(content.len() as u64).unwrap();
            writer
                .write_chunk(&cx, 0, content, WriteOptions::default())
                .await
                .unwrap();

            writer.verify(&cx, &manifest).await.unwrap();

            let stats = writer.get_stats();
            assert_eq!(
                stats.verification_state,
                VerificationState::Verified {
                    manifest_root: manifest.merkle_root
                }
            );
        });
    }

    #[test]
    fn commit_atomic_rename_closes_temp_handle_before_filesystem_move() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let content = b"verified sparse writer commit content";
            let (object_id, manifest) = manifest_for_content(content);
            let final_path = unique_temp_path("commit_atomic_final");
            let writer =
                SparseWriter::new(&cx, object_id, &final_path, SparseWriterConfig::default())
                    .await
                    .unwrap();

            writer.set_expected_size(content.len() as u64).unwrap();
            writer
                .write_chunk(&cx, 0, content, WriteOptions::default())
                .await
                .unwrap();
            writer.verify(&cx, &manifest).await.unwrap();

            let committed_path = writer.commit(&cx).await.unwrap();

            assert_eq!(committed_path, final_path);
            assert_eq!(std::fs::read(&committed_path).unwrap(), content);
            std::fs::remove_file(&committed_path).ok();
        });
    }

    #[test]
    fn durable_commit_policies_preserve_verified_bytes() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let content = b"durable destination bytes";
            for commit_policy in [
                CommitPolicy::AtomicRename,
                CommitPolicy::CopyAndVerify,
                CommitPolicy::LinkAndUnlink,
            ] {
                let (object_id, manifest) = manifest_for_content(content);
                let destination = unique_temp_path("durable_commit");
                let writer = SparseWriter::new(
                    &cx,
                    object_id,
                    &destination,
                    SparseWriterConfig {
                        commit_policy,
                        fsync_policy: super::super::FsyncPolicy::BeforeCommit,
                        ..SparseWriterConfig::default()
                    },
                )
                .await
                .unwrap();
                writer.set_expected_size(content.len() as u64).unwrap();
                writer
                    .write_chunk(&cx, 0, content, WriteOptions::default())
                    .await
                    .unwrap();
                writer.verify(&cx, &manifest).await.unwrap();
                assert_eq!(writer.commit(&cx).await.unwrap(), destination);
                assert_eq!(std::fs::read(destination).unwrap(), content);
            }
        });
    }

    #[cfg(unix)]
    #[test]
    fn directory_sync_errors_propagate_and_never_policy_skips_sync() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let mut writer = SparseWriter::new(
                &cx,
                test_object_id("sync_error"),
                unique_temp_path("sync_error"),
                SparseWriterConfig::default(),
            )
            .await
            .unwrap();
            let missing_parent = unique_temp_path("missing_sync_parent").join("file");
            assert!(matches!(
                writer.sync_commit_destination(&missing_parent),
                Err(SparseWriterError::SyncFailed(_))
            ));
            writer.config.fsync_policy = super::super::FsyncPolicy::Never;
            writer.sync_commit_destination(&missing_parent).unwrap();
        });
    }

    #[test]
    fn verify_fails_closed_on_manifest_content_mismatch() {
        futures_lite::future::block_on(async {
            let cx = create_test_cx();
            let expected = b"expected bytes";
            let actual = b"tampered bytes";
            assert_eq!(expected.len(), actual.len());
            let (object_id, manifest) = manifest_for_content(expected);
            let writer = SparseWriter::new(
                &cx,
                object_id,
                unique_temp_path("verify_mismatch"),
                SparseWriterConfig::default(),
            )
            .await
            .unwrap();

            writer.set_expected_size(actual.len() as u64).unwrap();
            writer
                .write_chunk(&cx, 0, actual, WriteOptions::default())
                .await
                .unwrap();

            let result = writer.verify(&cx, &manifest).await;

            assert!(matches!(
                result,
                Outcome::Err(SparseWriterError::VerificationFailed(_))
            ));
            assert!(matches!(
                writer.get_stats().verification_state,
                VerificationState::Failed { .. }
            ));
        });
    }
}
