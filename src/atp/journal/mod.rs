//! ATP Journal - Sparse Writer, Transfer Progress, and Atomic Commit
//!
//! This module provides crash-safe sparse writing with out-of-order chunk support,
//! platform-aware preallocation, atomic commit semantics for ATP objects, and
//! append-only journal for transfer progress tracking with crash recovery.

pub mod append_journal;
pub mod chunk_bitmap;
pub mod commit_policy;
pub mod delta_cas;
pub mod platform_caps;
pub mod range_tracker;
#[cfg(not(target_arch = "wasm32"))]
mod receive;
pub mod recovery;
pub mod sparse_writer;
pub mod temp_management;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod basic_tests;

pub use append_journal::{
    AppendJournal, JournalConfig, JournalRecord, TransferResumeChunk, TransferResumeStatus,
    TransferResumeSummary,
};
pub use chunk_bitmap::{ChunkBitmap, ChunkState};
pub use commit_policy::{AtomicPolicy, CommitPolicy, FsyncPolicy};
pub use delta_cas::{
    DeltaCasError, DeltaCasStore, DeltaCasWrite, DeltaChunkId, DeltaChunkRef, DeltaManifestDiff,
    DeltaMerkleManifest, DeltaSubtreeRange,
};
pub use platform_caps::{FilesystemFeatures, PlatformCapabilities};
pub use range_tracker::{ChunkRange, RangeTracker, SparseRange};
#[cfg(not(target_arch = "wasm32"))]
pub use receive::{ScopedReceive, ScopedReceiveError, ScopedReceiveOptions, ScopedReceiveResult};
pub use recovery::{
    RecoveryContext, RecoveryError, RecoveryStats, load_recovered_or_create_bitmap,
    recover_journal_and_bitmap,
};
pub use sparse_writer::{SparseWriter, SparseWriterConfig, WriteOptions};
pub use temp_management::{PathState, QuarantineReason, TempPathManager};

/// Explicit resource limits for restoring a private writer from journaled bytes.
///
/// These bound the declared object, copied receipts and reusable payload buffer.
/// They do not bound memory already owned by the journal or its decoded index.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy)]
pub struct JournalRestoreLimits {
    /// Maximum declared length of the complete object, including missing ranges.
    pub max_bytes: u64,
    /// Maximum number of authenticated receipts copied into the new writer.
    pub max_chunks: u32,
    /// Largest admitted receipt and maximum requested payload-buffer length.
    /// Must be nonzero. Receipt boundaries are preserved, not silently split.
    pub max_chunk_bytes: usize,
}

/// Explicit host resources for a fully offloaded journal/payload restoration.
///
/// Paths come from the application, never from an untrusted journal record.
/// The existing journal directory must exist. Restoration does not initialize
/// a new journal, append new progress, or retire the original payload evidence.
#[cfg(not(target_arch = "wasm32"))]
pub struct JournalRestoreRequest {
    /// Configuration used when reopening retained journal generations.
    pub journal_config: JournalConfig,
    /// Trusted key used to authenticate the reopened transfer's records.
    pub auth_key: crate::security::AuthKey,
    /// Transfer whose offered identity and recorded ranges will be restored.
    pub transfer_id: String,
    /// Application-selected whole-object payload file, opened read-only.
    pub source_path: std::path::PathBuf,
    /// Destination for a later explicit verification and commit operation.
    pub final_path: std::path::PathBuf,
    /// Existing staging, preallocation, cleanup and publication policies.
    pub writer_config: SparseWriterConfig,
    /// Explicit object, receipt and payload-buffer limits.
    pub limits: JournalRestoreLimits,
}

/// Owned inputs for a durable checkpoint of an existing sparse writer.
///
/// Journal ownership moves into the region-owned filesystem job and is returned
/// in its report. The caller must maintain single-writer ownership of the journal
/// directory. Existing journal/payload formats and final-verification rules remain.
#[cfg(not(target_arch = "wasm32"))]
pub struct JournalCheckpointRequest {
    /// Journal opened with the trusted signing key; no concurrent directory writer.
    pub journal: AppendJournal,
    /// Stable application-selected transfer identifier, not a filesystem path.
    pub transfer_id: String,
    /// Trusted expected graph binding this writer's file identity, root and length.
    /// A checkpoint does not itself authenticate the complete object's content.
    pub manifest: std::sync::Arc<crate::atp::manifest::Manifest>,
    /// Same object/receipt bounds used to admit subsequent physical restoration.
    pub limits: JournalRestoreLimits,
    /// Application-supplied journal timestamp, using its existing clock convention.
    /// Ordering and deduplication use record sequences, not this timestamp.
    pub timestamp: u64,
}

/// Confirmed local checkpoint, not a peer acknowledgment or publication receipt.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone)]
pub struct JournalCheckpoint {
    /// Staging source to retain in the application's trusted recovery catalog.
    /// Later writes, explicit cancellation or publication can change its availability.
    pub source_path: std::path::PathBuf,
    /// Authenticated progress observed after the journal's successful sync barrier.
    pub summary: TransferResumeSummary,
}

/// Journal ownership and the checkpoint's actual outcome are independent.
///
/// Ordinary domain refusal returns the journal, including its fenced state after
/// uncertain storage. An outer gateway failure or abandoned result instead drops
/// the owner; reopen existing journal files before inferring progress or retrying.
#[cfg(not(target_arch = "wasm32"))]
pub struct JournalCheckpointReport {
    /// Original journal owner, with all observed effects and failure state retained.
    pub journal: AppendJournal,
    /// Checkpoint result. Failure does not imply that no records reached storage.
    pub outcome: crate::types::Outcome<JournalCheckpoint, sparse_writer::SparseWriterError>,
}
