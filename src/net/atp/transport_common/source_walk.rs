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
mod tests {
    use super::*;
    use super::super::streaming::{collect_entries, collect_entries_with_policy};

    #[test]
    fn directory_batches_bound_inspections_and_preserve_every_child() {
        for count in [0, 1, 31, 32, 33, 64, 65, 97] {
            let root = tempfile::tempdir().unwrap();
            for i in (0..count).rev() {
                std::fs::write(root.path().join(format!("file-{i:03}")), b"x").unwrap();
            }
            let mut scan = DirectoryScan::open(root.path().to_path_buf(), true).unwrap();
            let mut batches = 0;
            while scan.inner.is_some() {
                let before = scan.children.len();
                scan = scan.advance().unwrap();
                assert!(scan.children.len() - before <= ENTRIES_PER_BATCH);
                batches += 1;
            }
            // A completely full batch requires another next() to observe EOF.
            assert_eq!(batches, count / ENTRIES_PER_BATCH + 1);
            let actual: Vec<_> = scan.children.iter().map(|c| c.name.clone()).collect();
            let expected: Vec<_> = (0..count).map(|i| format!("file-{i:03}")).collect();
            assert_eq!(actual, expected);
            assert!(scan.children.iter().all(|c| !c.is_dir));
        }
    }

    #[test]
    fn public_walk_preserves_sorted_files_and_only_empty_directory_leaves() {
        let root = tempfile::tempdir().unwrap();
        for dir in ["z-empty", "a/empty", "a/nested", "b"] {
            std::fs::create_dir_all(root.path().join(dir)).unwrap();
        }
        for name in ["c", "b/x", "a/nested/y"] {
            std::fs::write(root.path().join(name), b"payload").unwrap();
        }
        let (_, is_dir, entries) =
            futures_lite::future::block_on(collect_entries(root.path())).unwrap();
        assert!(is_dir);
        let actual: Vec<_> = entries.iter().map(|e| e.rel_path.as_str()).collect();
        assert_eq!(actual, ["a/empty", "a/nested/y", "b/x", "c", "z-empty"]);
        for entry in entries {
            assert_eq!(entry.abs_path, root.path().join(&entry.rel_path));
        }
    }

    #[test]
    fn public_walk_crosses_multiple_directory_batch_boundaries() {
        let root = tempfile::tempdir().unwrap();
        let mut expected = Vec::new();
        for d in 0..35 {
            let dir = root.path().join(format!("dir-{d:02}"));
            std::fs::create_dir(&dir).unwrap();
            for f in 0..34 {
                let name = format!("file-{f:02}");
                std::fs::write(dir.join(&name), b"x").unwrap();
                expected.push(format!("dir-{d:02}/{name}"));
            }
        }
        let (_, _, entries) = futures_lite::future::block_on(collect_entries(root.path())).unwrap();
        let actual: Vec<_> = entries.into_iter().map(|e| e.rel_path).collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn missing_directory_error_keeps_its_source_path() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        let error = futures_lite::future::block_on(read_children(&missing, true)).unwrap_err();
        assert!(error.message().starts_with(&format!("{}: ", missing.display())));
    }

    #[test]
    fn empty_root_and_single_file_keep_existing_shapes() {
        let root = tempfile::tempdir().unwrap();
        let (_, is_dir, entries) = futures_lite::future::block_on(collect_entries(root.path())).unwrap();
        assert!(is_dir);
        assert!(entries.is_empty());
        let path = root.path().join("one");
        std::fs::write(&path, b"payload").unwrap();
        let (name, is_dir, entries) = futures_lite::future::block_on(collect_entries(&path)).unwrap();
        assert_eq!(name, "one");
        assert!(!is_dir);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].rel_path, "one");
        assert_eq!(entries[0].abs_path, path);
    }

    #[test]
    fn denied_io_refuses_public_walk_and_directory_batches() {
        let root = tempfile::tempdir().unwrap();
        let cx = crate::cx::Cx::for_testing().restrict::<crate::cx::cap::None>();
        let error = futures_lite::future::block_on(cx.with_ambient(collect_entries(root.path())))
            .unwrap_err();
        assert!(error.message().contains("[ASUP-E009]"));
        let error = futures_lite::future::block_on(cx.with_ambient(read_children(root.path(), true)))
            .unwrap_err();
        assert!(error.message().contains("[ASUP-E009]"));
    }

    #[cfg(unix)]
    #[test]
    fn cycles_broken_links_and_outside_directory_links_are_leaves() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("not-transferred"), b"outside").unwrap();
        std::os::unix::fs::symlink(root.path(), root.path().join("cycle")).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("outside")).unwrap();
        std::os::unix::fs::symlink("missing", root.path().join("broken")).unwrap();
        let (_, _, entries) = futures_lite::future::block_on(collect_entries(root.path())).unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.rel_path.as_str()).collect();
        assert_eq!(names, ["broken", "cycle", "outside"]);
        let error = futures_lite::future::block_on(collect_entries_with_policy(
            root.path(), &MetadataPolicy::portable(),
        )).unwrap_err();
        assert!(error.message().contains("metadata policy"));
    }

    #[cfg(unix)]
    #[test]
    fn root_symlink_requires_io_even_when_preserved() {
        let root = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(target.path(), &link).unwrap();
        let (_, is_dir, entries) = futures_lite::future::block_on(collect_entries(&link)).unwrap();
        assert!(!is_dir);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].rel_path, "link");
        let cx = crate::cx::Cx::for_testing().restrict::<crate::cx::cap::None>();
        let error = futures_lite::future::block_on(cx.with_ambient(collect_entries(&link))).unwrap_err();
        assert!(error.message().contains("[ASUP-E009]"));
    }

    #[cfg(unix)]
    #[test]
    fn discovered_directory_cannot_be_followed_as_a_symlink_at_open() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let path = root.path().join("directory");
        std::fs::create_dir(&path).unwrap();
        let children = futures_lite::future::block_on(read_children(root.path(), true)).unwrap();
        assert!(children[0].is_dir);
        std::fs::rename(&path, root.path().join("original-directory")).unwrap();
        std::os::unix::fs::symlink(outside.path(), &path).unwrap();
        let error = DirectoryScan::open(path, true).unwrap_err();
        assert!(error.message().contains("became a link or reparse point"));
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_and_non_portable_child_names_fail_closed() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        for (name, message) in [
            (OsString::from_vec(vec![0xff]), "not valid Unicode"),
            (OsString::from("bad:name"), "not portable"),
        ] {
            let root = tempfile::tempdir().unwrap();
            std::fs::write(root.path().join(name), b"x").unwrap();
            let error = futures_lite::future::block_on(collect_entries(root.path())).unwrap_err();
            assert!(error.message().contains(message), "{error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn deep_tree_and_special_leaves_do_not_require_recursive_futures_or_content_opens() {
        let root = tempfile::tempdir().unwrap();
        let mut path = root.path().to_path_buf();
        for _ in 0..128 {
            path.push("d");
            std::fs::create_dir(&path).unwrap();
        }
        let socket = root.path().join("socket");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let (_, _, entries) = futures_lite::future::block_on(collect_entries(root.path())).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].abs_path, path);
        assert_eq!(entries[1].abs_path, socket);
    }
}
