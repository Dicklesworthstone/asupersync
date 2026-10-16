//! Bounded metadata batches for ATP source discovery.
//!
//! A job classifies at most 32 directory entries using the same synchronous
//! link/reparse classifier as the original async walk. No file content is
//! opened. Only the currently scanned directory has a live iterator; traversal
//! uses an explicit stack rather than recursively polling/dropping futures.
//!
//! This bounds entry inspections per job, not syscall or sorting wall time.
//! Paths still require O(number of entries) storage, as does the public manifest.
//! Jobs observe cancellation while pending and before subsequent batches, but
//! a submitted filesystem call may still finish after its future is dropped.

use std::fs::ReadDir;
use std::path::{Path, PathBuf};

use crate::atp::object::MetadataPolicy;
use crate::atp::safety::validate_portable_path_component;

use super::metadata::{PathLinkKind, classify_path_link_sync};
use super::source_io;
use super::streaming::{SourceEntry, StreamingError};

const ENTRIES_PER_BATCH: usize = 32;

#[derive(Debug)]
struct Child {
    name: String,
    path: PathBuf,
    is_dir: bool,
}

#[derive(Debug)]
struct DirectoryScan {
    dir: PathBuf,
    inner: Option<ReadDir>,
    children: Vec<Child>,
    preserve_symlinks: bool,
}

fn source_error(path: &Path, error: impl std::fmt::Display) -> StreamingError {
    StreamingError::new(format!("{}: {error}", path.display()))
}

impl DirectoryScan {
    fn open(dir: PathBuf, preserve_symlinks: bool) -> Result<Self, StreamingError> {
        // A previously discovered directory may have changed while another
        // directory was scanned. Refuse a link at the last path-based check
        // before opening it. This is not descriptor-relative/atomic traversal.
        let kind = classify_path_link_sync(&dir).map_err(|e| source_error(&dir, e))?;
        if !matches!(kind, PathLinkKind::NotLink) {
            return Err(source_error(
                &dir,
                "source directory became a link or reparse point before traversal",
            ));
        }
        let inner = std::fs::read_dir(&dir).map_err(|e| source_error(&dir, e))?;
        Ok(Self {
            dir,
            inner: Some(inner),
            children: Vec::new(),
            preserve_symlinks,
        })
    }

    fn advance(mut self) -> Result<Self, StreamingError> {
        for _ in 0..ENTRIES_PER_BATCH {
            let Some(inner) = self.inner.as_mut() else {
                break;
            };
            let Some(entry) = inner.next() else {
                // Close the directory on the worker. Child paths do not retain
                // DirEntry handles, so ancestors do not accumulate open fds.
                self.inner = None;
                self.children.sort_by(|a, b| a.name.cmp(&b.name));
                break;
            };
            let entry = entry.map_err(|e| source_error(&self.dir, e))?;
            let path = entry.path();
            let link_kind =
                classify_path_link_sync(&path).map_err(|e| source_error(&path, e))?;
            let name = entry
                .file_name()
                .to_str()
                .ok_or_else(|| source_error(&path, "source entry name is not valid Unicode"))?
                .to_string();
            validate_portable_path_component(&name).map_err(|_| {
                source_error(&path, format!("source entry name is not portable: {name:?}"))
            })?;
            let file_type = entry.file_type().map_err(|e| source_error(&path, e))?;
            let is_dir = match link_kind {
                PathLinkKind::NotLink => file_type.is_dir(),
                PathLinkKind::Symlink(_) if self.preserve_symlinks => false,
                PathLinkKind::Symlink(_) => {
                    return Err(source_error(&path, "source symlink rejected by metadata policy"));
                }
                PathLinkKind::UnsupportedReparse => {
                    return Err(source_error(&path, "unsupported Windows reparse point"));
                }
            };
            self.children.push(Child { name, path, is_dir });
        }
        Ok(self)
    }
}

async fn read_children(dir: &Path, preserve_symlinks: bool) -> Result<Vec<Child>, StreamingError> {
    let owned_dir = dir.to_path_buf();
    // Keep StreamingError inside the result so child-scoped failures do not
    // acquire a second, parent-directory prefix. Pool/gate errors use dir.
    let mut scan = source_io::run(dir, "fs", move || {
        Ok(DirectoryScan::open(owned_dir, preserve_symlinks).and_then(DirectoryScan::advance))
    })
    .await??;
    while scan.inner.is_some() {
        scan = source_io::run(dir, "fs", move || Ok(scan.advance())).await??;
    }
    Ok(scan.children)
}

pub(super) async fn collect_dir(
    dir: &Path,
    prefix: String,
    policy: &MetadataPolicy,
    out: &mut Vec<SourceEntry>,
) -> Result<(), StreamingError> {
    let mut pending = vec![(dir.to_path_buf(), prefix)];
    while let Some((dir, prefix)) = pending.pop() {
        let children = read_children(&dir, policy.preserve_symlinks).await?;
        if children.is_empty() && !prefix.is_empty() {
            out.push(SourceEntry {
                rel_path: prefix,
                abs_path: dir,
            });
            continue;
        }
        // Stack order visits subdirectories lexically. The public entry point
        // sorts all emitted paths, including files and explicit empty dirs.
        for child in children.into_iter().rev() {
            let rel_path = if prefix.is_empty() {
                child.name
            } else {
                format!("{prefix}/{}", child.name)
            };
            if child.is_dir {
                pending.push((child.path, rel_path));
            } else {
                out.push(SourceEntry {
                    rel_path,
                    abs_path: child.path,
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "source_walk_inline_tests.rs"]
mod tests;
