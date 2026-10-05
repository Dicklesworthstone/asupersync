//! Capability-bound filesystem operations owned by the calling context's region.
//!
//! The implementation lives with the host filesystem providers in `src/fs/`.
//! This facade preserves the original public `cx::scoped_fs` and
//! `cx::{ScopedFs, ScopedFsError}` paths without putting OS operations in the
//! capability kernel. `Cx::scoped_fs` keeps its existing admission checks.

#[cfg(not(target_arch = "wasm32"))]
pub use crate::fs::scoped::{ScopedFs, ScopedFsError};

// The root fs module is native-only. Keep the historical facade available on
// wasm too, with the same implementation and fail-closed blocking admission;
// this is not a new browser filesystem provider or a claim of host I/O support.
#[cfg(target_arch = "wasm32")]
#[path = "../fs/scoped.rs"]
mod provider;
#[cfg(target_arch = "wasm32")]
pub use provider::{ScopedFs, ScopedFsError};
