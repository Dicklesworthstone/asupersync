//! ATP Journal - Sparse Writer, Preallocation, and Atomic Commit
//!
//! This module provides crash-safe sparse writing with out-of-order chunk support,
//! platform-aware preallocation, and atomic commit semantics for ATP objects.

pub mod commit_policy;
pub mod platform_caps;
pub mod range_tracker;
pub mod sparse_writer;
pub mod temp_management;

#[cfg(test)]
mod tests;

pub use commit_policy::{AtomicPolicy, CommitPolicy, FsyncPolicy};
pub use platform_caps::{FilesystemFeatures, PlatformCapabilities};
pub use range_tracker::{ChunkRange, RangeTracker, SparseRange};
pub use sparse_writer::{SparseWriter, SparseWriterConfig, WriteOptions};
pub use temp_management::{PathState, QuarantineReason, TempPathManager};
