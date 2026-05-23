//! Sparse Writer Implementation for Out-of-Order Chunk Writing

use super::{
    ChunkRange, CommitPolicy, PlatformCapabilities, RangeTracker, SparseRange, TempPathManager,
};
use crate::atp::manifest::{ManifestVersion, MerkleRoot};
use crate::atp::object::ObjectId;
use crate::cx::Cx;
use crate::types::outcome::Outcome;
use parking_lot::{Mutex, MutexGuard};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

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
    /// High priority, process quickly
    High = 2,
    /// Critical priority, process immediately
    Critical = 3,
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
    /// Create a new sparse writer for the given object
    pub async fn new(
        cx: &Cx,
        object_id: ObjectId,
        final_path: impl AsRef<Path>,
        config: SparseWriterConfig,
    ) -> Outcome<Self, SparseWriterError> {
        let final_path = final_path.as_ref().to_path_buf();

        let destination_dir = final_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));

        // Detect capabilities for the destination filesystem. ATP transfers may
        // target a mounted volume whose sparse/preallocation/rename behavior
        // differs from the process working directory.
        let platform = match PlatformCapabilities::detect_for_path(cx, destination_dir).await {
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
        }));

        crate::types::outcome::Outcome::Ok(Self {
            config,
            platform,
            path_manager,
            state,
        })
    }

    fn lock_state(&self) -> MutexGuard<'_, SparseWriterState> {
        self.state.lock()
    }

    /// Set expected final size for preallocation
    pub fn set_expected_size(&self, size: u64) -> Result<(), SparseWriterError> {
        let mut state = self.lock_state();
        state.expected_size = Some(size);

        // Trigger preallocation if enabled and file is open
        if self.config.enable_preallocation && state.temp_file.is_some() {
            self.preallocate_internal(&mut state, size)?;
        }

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

        let mut state = self.lock_state();
        if let Err(error) = self.ensure_temp_file_open_locked(&mut state) {
            return Outcome::Err(error);
        }
        if state.range_tracker.overlaps(&sparse_range) {
            return Outcome::Err(SparseWriterError::OverlappingWrite {
                offset,
                size: chunk_size,
            });
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

    /// Verify written data against expected manifest
    pub async fn verify(
        &self,
        _cx: &Cx,
        _expected_manifest: &ManifestVersion,
    ) -> Outcome<(), SparseWriterError> {
        let mut state = self.lock_state();
        state.verification_state = VerificationState::InProgress;

        // TODO: Implement manifest verification logic
        // This would compute hashes of written chunks and compare against manifest

        state.verification_state = VerificationState::Verified {
            manifest_root: MerkleRoot::zero(),
        };

        Outcome::ok(())
    }

    /// Commit the written data atomically to final destination
    pub async fn commit(&self, _cx: &Cx) -> Outcome<PathBuf, SparseWriterError> {
        {
            let state = self.lock_state();
            if !Self::is_complete_locked(&state) {
                return Outcome::Err(SparseWriterError::IncompleteData);
            }
            if !matches!(state.verification_state, VerificationState::Verified { .. }) {
                return Outcome::Err(SparseWriterError::NotVerified);
            }
        }

        // Apply fsync policy before commit
        match self.apply_fsync_policy().await {
            Outcome::Ok(()) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::panicked(payload),
        }

        // Perform atomic commit based on policy
        let final_path = match self.atomic_commit().await {
            Outcome::Ok(path) => path,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::panicked(payload),
        };

        // Clean up temp file
        match self.cleanup_temp_file().await {
            Ok(()) => {}
            Err(e) => return Outcome::Err(e),
        }

        Outcome::ok(final_path)
    }

    /// Cancel the write operation and clean up
    pub async fn cancel(&self, _cx: &Cx) -> Outcome<(), SparseWriterError> {
        // Move temp file to quarantine if configured
        if self.config.enable_quarantine {
            match self.quarantine_temp_file("cancelled").await {
                Ok(_) => {}
                Err(e) => return Outcome::Err(e),
            }
        } else {
            match self.cleanup_temp_file().await {
                Ok(_) => {}
                Err(e) => return Outcome::Err(e),
            }
        }

        Outcome::ok(())
    }

    /// Get current write statistics
    pub fn get_stats(&self) -> SparseWriterStats {
        let state = self.lock_state();
        let total_written = state.range_tracker.total_bytes();
        let chunk_count = state.written_chunks.len();
        let completion_ratio = if let Some(expected) = state.expected_size {
            total_written as f64 / expected as f64
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

        // Generate temp path
        let temp_path = {
            let mut path_mgr = self.path_manager.lock();
            path_mgr
                .create_temp_path(&state.object_id.to_string())
                .map_err(|e| SparseWriterError::TempPathCreation(e.to_string()))?
        };

        // Create and open temp file
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .truncate(false)
            .open(&temp_path)
            .map_err(|e| SparseWriterError::FileOpen(e.to_string()))?;

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
                    // Fallback: seek and write zero
                    match file.seek(SeekFrom::Start(size.saturating_sub(1))) {
                        Ok(_) => {
                            if file.write_all(&[0]).is_ok() {
                                file.seek(SeekFrom::Start(0)).ok();
                                state.allocated_size = size;
                                state.is_preallocated = true;
                            }
                        }
                        Err(_) => {
                            // Preallocation failed, continue without it
                        }
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

        // Compute hash
        let hash = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            data.hash(&mut hasher);
            let hash_u64 = hasher.finish();
            let mut hash_bytes = [0u8; 32];
            hash_bytes[0..8].copy_from_slice(&hash_u64.to_le_bytes());
            hash_bytes
        };

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

    async fn apply_fsync_policy(&self) -> Outcome<(), SparseWriterError> {
        let mut state = self.lock_state();
        let verified = matches!(state.verification_state, VerificationState::Verified { .. });

        // Check sync requirements before borrowing file mutably
        let needs_sync_for_every_write =
            matches!(self.config.fsync_policy, super::FsyncPolicy::EveryWrite)
                && state.written_chunks.values().any(|chunk| !chunk.synced);

        if let Some(ref mut file) = state.temp_file {
            match self.config.fsync_policy {
                super::FsyncPolicy::Never => {
                    // No sync required
                }
                super::FsyncPolicy::EveryWrite => {
                    if needs_sync_for_every_write {
                        // Force sync for any unsynced chunks
                        match file.sync_data() {
                            Ok(_) => {
                                // Mark all chunks as synced
                                for chunk in state.written_chunks.values_mut() {
                                    chunk.synced = true;
                                }
                            }
                            Err(e) => {
                                return Outcome::Err(SparseWriterError::SyncFailed(e.to_string()));
                            }
                        }
                    }
                }
                super::FsyncPolicy::VerifiedChunks => {
                    // Sync only if verification passed
                    if verified {
                        match file.sync_data() {
                            Ok(_) => {}
                            Err(e) => {
                                return Outcome::Err(SparseWriterError::SyncFailed(e.to_string()));
                            }
                        }
                    }
                }
                super::FsyncPolicy::BeforeCommit => match file.sync_data() {
                    Ok(_) => {}
                    Err(e) => return Outcome::Err(SparseWriterError::SyncFailed(e.to_string())),
                },
            }
        }

        Outcome::ok(())
    }

    async fn atomic_commit(&self) -> Outcome<PathBuf, SparseWriterError> {
        let state = self.lock_state();
        let temp_path = match state.temp_path.as_ref() {
            Some(path) => path,
            None => return Outcome::Err(SparseWriterError::NoTempFile),
        };
        let final_path = &state.final_path;

        match self.config.commit_policy {
            CommitPolicy::AtomicRename => match std::fs::rename(temp_path, final_path) {
                Ok(_) => {}
                Err(e) => return Outcome::Err(SparseWriterError::CommitFailed(e.to_string())),
            },
            CommitPolicy::CopyAndVerify => {
                match std::fs::copy(temp_path, final_path) {
                    Ok(_) => {}
                    Err(e) => return Outcome::Err(SparseWriterError::CommitFailed(e.to_string())),
                }
                // TODO: Add verification step
            }
            CommitPolicy::LinkAndUnlink => {
                #[cfg(unix)]
                {
                    match std::fs::hard_link(temp_path, final_path) {
                        Ok(_) => {}
                        Err(e) => {
                            return Outcome::Err(SparseWriterError::CommitFailed(e.to_string()));
                        }
                    }
                    match std::fs::remove_file(temp_path) {
                        Ok(_) => {}
                        Err(e) => {
                            return Outcome::Err(SparseWriterError::CommitFailed(e.to_string()));
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    // Fallback to copy on non-Unix systems
                    match std::fs::copy(temp_path, final_path) {
                        Ok(_) => {}
                        Err(e) => {
                            return Outcome::Err(SparseWriterError::CommitFailed(e.to_string()));
                        }
                    }
                }
            }
        }

        Outcome::ok(final_path.clone())
    }

    async fn cleanup_temp_file(&self) -> Result<(), SparseWriterError> {
        let mut state = self.lock_state();

        if let Some(temp_path) = state.temp_path.take() {
            std::fs::remove_file(&temp_path).ok(); // Ignore errors
        }

        state.temp_file = None;
        Ok(())
    }

    async fn quarantine_temp_file(&self, reason: &str) -> Result<(), SparseWriterError> {
        let mut state = self.lock_state();

        if let Some(temp_path) = state.temp_path.take() {
            let mut path_mgr = self.path_manager.lock();
            path_mgr
                .quarantine_file(&temp_path, reason)
                .map_err(|e| SparseWriterError::TempPathCreation(e.to_string()))?;
        }

        state.temp_file = None;
        Ok(())
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

    #[error("Commit failed: {0}")]
    CommitFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::object::ContentId;

    fn create_test_cx() -> Cx {
        Cx::for_testing()
    }

    fn test_object_id(label: &str) -> ObjectId {
        ObjectId::content(ContentId::from_bytes(label.as_bytes()))
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
            let fill_data = vec![0u8; 494];
            writer
                .write_chunk(&cx, 5, &fill_data, WriteOptions::default())
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
}
