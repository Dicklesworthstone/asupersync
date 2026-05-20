//! ATP Journal - Sparse Writer, Transfer Progress, and Atomic Commit
//!
//! This module provides crash-safe sparse writing with out-of-order chunk support,
//! platform-aware preallocation, atomic commit semantics for ATP objects, and
//! append-only journal for transfer progress tracking with crash recovery.

pub mod append_journal;
pub mod chunk_bitmap;
pub mod commit_policy;
pub mod platform_caps;
pub mod range_tracker;
pub mod recovery;
pub mod sparse_writer;
pub mod temp_management;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod basic_tests;

pub use append_journal::{AppendJournal, JournalConfig, JournalRecord};
pub use chunk_bitmap::{ChunkBitmap, ChunkState};
pub use commit_policy::{AtomicPolicy, CommitPolicy, FsyncPolicy};
pub use platform_caps::{FilesystemFeatures, PlatformCapabilities};
pub use range_tracker::{ChunkRange, RangeTracker, SparseRange};
pub use recovery::{
    RecoveryContext, RecoveryError, RecoveryStats, load_or_create_bitmap,
    recover_journal_and_bitmap,
};
pub use sparse_writer::{SparseWriter, SparseWriterConfig, WriteOptions};
pub use temp_management::{PathState, QuarantineReason, TempPathManager};
