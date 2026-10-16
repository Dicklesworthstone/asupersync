//! Guarded root discovery for every shared ATP source-walk entry point.
//!
//! Root link classification, portable-name validation and metadata lookup share
//! one source-I/O job. No early return for a regular file or preserved symlink
//! bypasses cancellation or authority checks. Directory batches use the same
//! boundary afterwards. This is path-based inspection, not an atomic snapshot;
//! an already-submitted filesystem call can outlive an abandoned wait.

use std::path::Path;

use crate::atp::object::MetadataPolicy;
use crate::atp::safety::validate_portable_path_component;

use super::metadata::{PathLinkKind, classify_path_link_sync};
use super::source_io;
use super::source_walk::collect_dir;
use super::streaming::{SourceEntry, StreamingError};

fn source_error(path: &Path, error: impl std::fmt::Display) -> StreamingError {
    StreamingError::new(format!("{}: {error}", path.display()))
}

/// Preserve the previous root-classification order and error messages. A link
/// preserved as a leaf does not require target metadata to succeed, so broken
/// symlinks remain transferable. Special root nodes are never opened for data.
fn inspect_root(root: &Path, preserve_symlinks: bool) -> Result<(String, bool), StreamingError> {
    let kind = classify_path_link_sync(root).map_err(|error| source_error(root, error))?;
    let name = match root.file_name() {
        None => "transfer".to_string(),
        Some(name) => name
            .to_str()
            .ok_or_else(|| source_error(root, "source file name is not valid Unicode"))?
            .to_string(),
    };
    validate_portable_path_component(&name).map_err(|_| {
        source_error(root, format!("source file name is not portable: {name:?}"))
    })?;
    match kind {
        PathLinkKind::Symlink(_) if preserve_symlinks => return Ok((name, false)),
        PathLinkKind::Symlink(_) => {
            return Err(source_error(root, "source symlink rejected by metadata policy"));
        }
        PathLinkKind::UnsupportedReparse => {
            return Err(source_error(root, "unsupported Windows reparse point"));
        }
        PathLinkKind::NotLink => {}
    }
    let metadata = std::fs::metadata(root).map_err(|error| source_error(root, error))?;
    if metadata.is_file() {
        Ok((name, false))
    } else if metadata.is_dir() {
        Ok((name, true))
    } else {
        Err(source_error(root, "not a regular file or directory"))
    }
}

pub(super) async fn collect_entries_with_policy(
    root: &Path,
    policy: &MetadataPolicy,
) -> Result<(String, bool, Vec<SourceEntry>), StreamingError> {
    let owned_root = root.to_path_buf();
    let preserve_symlinks = policy.preserve_symlinks;
    // Keep source-scoped errors inside the job result, rather than prefixing
    // them a second time when mapping a blocking-pool or cancellation failure.
    // The guard is polled before dispatch, including for missing paths.
    let (name, is_directory) = source_io::run(root, "fs", move || {
        Ok(inspect_root(&owned_root, preserve_symlinks))
    })
    .await??;
    let entries = if is_directory {
        let mut entries = Vec::new();
        collect_dir(root, String::new(), policy, &mut entries).await?;
        entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
        entries
    } else {
        vec![SourceEntry {
            rel_path: name.clone(),
            abs_path: root.to_path_buf(),
        }]
    };
    Ok((name, is_directory, entries))
}

#[cfg(test)]
#[path = "source_root_inline_tests.rs"]
mod tests;
