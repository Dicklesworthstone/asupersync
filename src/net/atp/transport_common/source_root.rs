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
mod tests {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    use super::*;
    use crate::cx::Cx;
    use crate::types::CancelKind;
    use super::super::streaming::collect_entries;
    #[cfg(unix)]
    use super::super::streaming::collect_entries_with_policy as public_walk;

    #[test]
    fn cancelled_roots_refuse_on_first_poll_before_filesystem_dispatch() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("file");
        let missing = root.path().join("missing");
        std::fs::write(&file, b"payload").unwrap();
        let cx = Cx::for_testing();
        cx.cancel_fast(CancelKind::User);
        for path in [root.path(), file.as_path(), missing.as_path()] {
            let mut future = Box::pin(cx.with_ambient(collect_entries(path)));
            let Poll::Ready(Err(error)) = future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
            else {
                panic!("a cancelled root must refuse before dispatch: {}", path.display());
            };
            assert!(error.message().contains("source operation cancelled"));
            assert!(error.message().starts_with(&format!("{}: ", path.display())));
        }
    }

    #[test]
    fn denied_roots_refuse_before_existence_or_type_is_inspected() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("file");
        let missing = root.path().join("missing");
        std::fs::write(&file, b"payload").unwrap();
        let cx = Cx::for_testing().restrict::<crate::cx::cap::None>();
        for path in [root.path(), file.as_path(), missing.as_path()] {
            let mut future = Box::pin(cx.with_ambient(collect_entries(path)));
            let Poll::Ready(Err(error)) = future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
            else {
                panic!("denied root must not dispatch: {}", path.display());
            };
            assert!(error.message().contains("[ASUP-E009]"));
        }
    }

    #[test]
    fn masked_cancellation_allows_root_discovery_without_changing_its_shape() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("single");
        std::fs::write(&file, b"payload").unwrap();
        let cx = Cx::for_testing();
        cx.cancel_fast(CancelKind::User);
        let (name, is_directory, entries) = cx.masked(|| {
            futures_lite::future::block_on(cx.with_ambient(collect_entries(&file)))
        }).unwrap();
        assert_eq!(name, "single");
        assert!(!is_directory);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].rel_path, "single");
        assert_eq!(entries[0].abs_path, file);
        assert!(cx.checkpoint().is_err(), "masking must not clear the request");
    }

    #[test]
    fn root_job_errors_keep_exactly_one_source_prefix() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        let cause = std::fs::symlink_metadata(&missing).unwrap_err();
        let error = futures_lite::future::block_on(collect_entries(&missing)).unwrap_err();
        assert_eq!(error.message(), format!("{}: {cause}", missing.display()));
    }

    #[test]
    fn combined_root_job_keeps_directory_sorting_and_empty_leaves() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("empty")).unwrap();
        std::fs::create_dir(root.path().join("nested")).unwrap();
        for name in ["z", "a", "nested/data"] {
            std::fs::write(root.path().join(name), b"content").unwrap();
        }
        let (_, is_directory, entries) =
            futures_lite::future::block_on(collect_entries(root.path())).unwrap();
        assert!(is_directory);
        let names: Vec<_> = entries.iter().map(|entry| entry.rel_path.as_str()).collect();
        assert_eq!(names, ["a", "empty", "nested/data", "z"]);
        for entry in entries {
            assert_eq!(entry.abs_path, root.path().join(entry.rel_path));
        }
    }

    #[cfg(unix)]
    #[test]
    fn root_symlink_variants_preserve_policy_and_observe_cancellation() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        let directory = root.path().join("directory");
        let missing = root.path().join("missing");
        std::fs::write(&target, b"not opened by the walk").unwrap();
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("not-traversed"), b"outside the link leaf").unwrap();
        for (index, target) in [target, directory, missing].into_iter().enumerate() {
            let link = root.path().join(format!("link-{index}"));
            std::os::unix::fs::symlink(target, &link).unwrap();
            let (_, is_directory, entries) =
                futures_lite::future::block_on(collect_entries(&link)).unwrap();
            assert!(!is_directory);
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].abs_path, link);
            let error = futures_lite::future::block_on(public_walk(
                &link, &MetadataPolicy::portable(),
            )).unwrap_err();
            assert!(error.message().contains("metadata policy"));
            let cx = Cx::for_testing();
            cx.cancel_fast(CancelKind::User);
            let mut future = Box::pin(cx.with_ambient(collect_entries(&link)));
            let Poll::Ready(Err(error)) = future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
            else {
                panic!("a preserved root link must not bypass cancellation");
            };
            assert!(error.message().contains("source operation cancelled"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_and_non_portable_root_names_keep_source_errors() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let root = tempfile::tempdir().unwrap();
        for (name, message) in [
            (OsString::from_vec(vec![0xff]), "source file name is not valid Unicode"),
            (OsString::from("bad:name"), "source file name is not portable"),
        ] {
            let path = root.path().join(name);
            std::fs::write(&path, b"payload").unwrap();
            let error = futures_lite::future::block_on(collect_entries(&path)).unwrap_err();
            assert!(error.message().contains(message), "{error}");
            assert!(error.message().starts_with(&format!("{}: ", path.display())));
        }
    }

    #[cfg(unix)]
    #[test]
    fn special_root_is_rejected_without_becoming_a_content_source() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("socket");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let error = futures_lite::future::block_on(collect_entries(&socket)).unwrap_err();
        assert_eq!(error.message(), format!("{}: not a regular file or directory", socket.display()));
    }
}
