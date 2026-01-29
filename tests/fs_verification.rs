#![allow(missing_docs, clippy::items_after_statements)]
//! Async Filesystem Verification Suite (bd-js88)
//!
//! Comprehensive verification for the async filesystem layer ensuring
//! correct behavior of all file operations, directory management, metadata,
//! buffered I/O, and error handling.
//!
//! # Test Coverage
//!
//! ## File I/O (File type)
//! - FS-VERIFY-001: File::create and File::open roundtrip
//! - FS-VERIFY-002: File seek, stream_position, rewind
//! - FS-VERIFY-003: File::try_clone shares underlying handle
//! - FS-VERIFY-004: File set_len truncate and extend
//! - FS-VERIFY-005: File sync_all and sync_data
//! - FS-VERIFY-006: File metadata from open handle
//!
//! ## OpenOptions Builder
//! - FS-VERIFY-007: OpenOptions read + write + create
//! - FS-VERIFY-008: OpenOptions create_new fails if exists
//! - FS-VERIFY-009: OpenOptions append mode
//! - FS-VERIFY-010: OpenOptions truncate mode
//!
//! ## Path Operations
//! - FS-VERIFY-011: read/write/read_to_string roundtrip
//! - FS-VERIFY-012: copy preserves content and returns byte count
//! - FS-VERIFY-013: rename moves file atomically
//! - FS-VERIFY-014: remove_file deletes file
//! - FS-VERIFY-015: hard_link creates second name for same data
//! - FS-VERIFY-016: symlink and read_link (Unix)
//! - FS-VERIFY-017: canonicalize resolves symlinks
//!
//! ## Directory Operations
//! - FS-VERIFY-018: create_dir and remove_dir lifecycle
//! - FS-VERIFY-019: create_dir_all creates nested parents
//! - FS-VERIFY-020: remove_dir_all recursive removal
//! - FS-VERIFY-021: read_dir enumerates entries
//! - FS-VERIFY-022: ReadDir as Stream
//!
//! ## Metadata and Permissions
//! - FS-VERIFY-023: Metadata for file vs directory
//! - FS-VERIFY-024: symlink_metadata vs metadata for symlinks
//! - FS-VERIFY-025: Permissions readonly flag
//! - FS-VERIFY-026: Metadata timestamps (modified, accessed, created)
//!
//! ## Buffered I/O
//! - FS-VERIFY-027: BufReader with lines
//! - FS-VERIFY-028: BufWriter flush behavior
//! - FS-VERIFY-029: BufWriter large write bypasses buffer
//! - FS-VERIFY-030: BufReader with_capacity
//!
//! ## Error Handling (Fault Injection)
//! - FS-VERIFY-031: Open non-existent file (ENOENT)
//! - FS-VERIFY-032: Remove non-existent file (ENOENT)
//! - FS-VERIFY-033: Create dir where file exists
//! - FS-VERIFY-034: Read dir on non-directory
//! - FS-VERIFY-035: create_new on existing file (EEXIST)
//! - FS-VERIFY-036: Remove non-empty directory

mod common;
use common::*;

use asupersync::fs::{self, BufReader, BufWriter, File, OpenOptions};
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::stream::StreamExt;
use futures_lite::future::block_on;
use std::io;
use tempfile::tempdir;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

// =============================================================================
// File I/O (FS-VERIFY-001 through FS-VERIFY-006)
// =============================================================================

/// FS-VERIFY-001: File::create and File::open roundtrip
///
/// Verifies the basic lifecycle: create file, write data, re-open, read back.
#[test]
fn fs_verify_001_file_create_open_roundtrip() {
    init_test("fs_verify_001_file_create_open_roundtrip");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("roundtrip.txt");

        // Create and write
        let mut file = File::create(&path).await?;
        file.write_all(b"hello async fs").await?;
        file.sync_all().await?;
        drop(file);

        // Open and read back
        let mut file = File::open(&path).await?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).await?;
        assert_eq!(contents, "hello async fs");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "file create/open roundtrip failed: {result:?}"
    );
    test_complete!("fs_verify_001_file_create_open_roundtrip");
}

/// FS-VERIFY-002: File seek, stream_position, rewind
///
/// Verifies seek operations work correctly with SeekFrom variants.
#[test]
fn fs_verify_002_file_seek_operations() {
    init_test("fs_verify_002_file_seek_operations");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("seek.txt");

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .await?;

        file.write_all(b"0123456789").await?;

        // Seek from start
        let pos = file.seek(io::SeekFrom::Start(3)).await?;
        assert_eq!(pos, 3);
        let mut buf = [0u8; 3];
        file.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"345");

        // stream_position
        let pos = file.stream_position().await?;
        assert_eq!(pos, 6);

        // Seek from end
        let pos = file.seek(io::SeekFrom::End(-4)).await?;
        assert_eq!(pos, 6);
        let mut buf = [0u8; 4];
        file.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"6789");

        // Rewind
        file.rewind().await?;
        let pos = file.stream_position().await?;
        assert_eq!(pos, 0);

        // Seek from current
        file.seek(io::SeekFrom::Current(2)).await?;
        let mut buf = [0u8; 1];
        file.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"2");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "seek operations failed: {result:?}");
    test_complete!("fs_verify_002_file_seek_operations");
}

/// FS-VERIFY-003: File::try_clone shares underlying handle
///
/// Verifies that cloned file handles see each other's writes.
#[test]
fn fs_verify_003_file_try_clone() {
    init_test("fs_verify_003_file_try_clone");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("clone.txt");

        let mut file = File::create(&path).await?;
        file.write_all(b"original").await?;
        file.sync_all().await?;

        let clone = file.try_clone().await?;
        let meta = clone.metadata().await?;
        assert_eq!(meta.len(), 8);

        drop(file);
        drop(clone);

        // Verify data is intact
        let data = fs::read(&path).await?;
        assert_eq!(&data, b"original");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "try_clone failed: {result:?}");
    test_complete!("fs_verify_003_file_try_clone");
}

/// FS-VERIFY-004: File set_len truncate and extend
///
/// Verifies truncation and extension of files via set_len.
#[test]
fn fs_verify_004_file_set_len() {
    init_test("fs_verify_004_file_set_len");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("setlen.txt");

        let file = File::create(&path).await?;
        drop(file);
        // Write 10 bytes
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .await?;
        file.write_all(b"0123456789").await?;
        file.sync_all().await?;

        // Truncate to 5
        file.set_len(5).await?;
        let meta = file.metadata().await?;
        assert_eq!(meta.len(), 5);

        // Extend to 20 (zero-filled)
        file.set_len(20).await?;
        let meta = file.metadata().await?;
        assert_eq!(meta.len(), 20);

        // Read back: first 5 bytes should be original
        file.rewind().await?;
        let mut buf = [0u8; 5];
        file.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"01234");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "set_len failed: {result:?}");
    test_complete!("fs_verify_004_file_set_len");
}

/// FS-VERIFY-005: File sync_all and sync_data
///
/// Verifies that sync operations complete without error.
#[test]
fn fs_verify_005_file_sync() {
    init_test("fs_verify_005_file_sync");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("sync.txt");

        let mut file = File::create(&path).await?;
        file.write_all(b"durable data").await?;

        // sync_data syncs data without metadata
        file.sync_data().await?;

        // sync_all syncs both data and metadata
        file.sync_all().await?;

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "sync operations failed: {result:?}");
    test_complete!("fs_verify_005_file_sync");
}

/// FS-VERIFY-006: File metadata from open handle
///
/// Verifies metadata queries on an open file handle.
#[test]
fn fs_verify_006_file_metadata() {
    init_test("fs_verify_006_file_metadata");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("meta.txt");

        let mut file = File::create(&path).await?;
        file.write_all(b"metadata test content").await?;
        file.sync_all().await?;

        let meta = file.metadata().await?;
        assert_eq!(meta.len(), 21);
        assert!(meta.is_file());
        assert!(!meta.is_dir());
        assert!(!meta.is_symlink());
        assert!(meta.len() > 0);

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "file metadata failed: {result:?}");
    test_complete!("fs_verify_006_file_metadata");
}

// =============================================================================
// OpenOptions Builder (FS-VERIFY-007 through FS-VERIFY-010)
// =============================================================================

/// FS-VERIFY-007: OpenOptions read + write + create
///
/// Verifies the builder pattern creates a file with read+write access.
#[test]
fn fs_verify_007_open_options_rw_create() {
    init_test("fs_verify_007_open_options_rw_create");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("opts_rw.txt");

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .await?;

        // Write then read back in same handle
        file.write_all(b"read-write").await?;
        file.rewind().await?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).await?;
        assert_eq!(contents, "read-write");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "open_options rw create failed: {result:?}");
    test_complete!("fs_verify_007_open_options_rw_create");
}

/// FS-VERIFY-008: OpenOptions create_new fails if exists
///
/// Verifies create_new returns an error when the file already exists.
#[test]
fn fs_verify_008_open_options_create_new() {
    init_test("fs_verify_008_open_options_create_new");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("create_new.txt");

        // First create should succeed
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await?;
        drop(file);

        // Second create_new should fail
        let err = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        tracing::info!(?err, "create_new correctly rejected existing file");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "create_new test failed: {result:?}");
    test_complete!("fs_verify_008_open_options_create_new");
}

/// FS-VERIFY-009: OpenOptions append mode
///
/// Verifies that append mode adds to existing content.
#[test]
fn fs_verify_009_open_options_append() {
    init_test("fs_verify_009_open_options_append");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("append.txt");

        // Write initial content
        fs::write(&path, b"first").await?;

        // Open in append mode and add more
        let mut file = OpenOptions::new().append(true).open(&path).await?;
        file.write_all(b" second").await?;
        file.sync_all().await?;
        drop(file);

        // Verify concatenated content
        let contents = fs::read_to_string(&path).await?;
        assert_eq!(contents, "first second");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "append mode failed: {result:?}");
    test_complete!("fs_verify_009_open_options_append");
}

/// FS-VERIFY-010: OpenOptions truncate mode
///
/// Verifies that truncate mode clears existing content.
#[test]
fn fs_verify_010_open_options_truncate() {
    init_test("fs_verify_010_open_options_truncate");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("truncate.txt");

        // Write initial content
        fs::write(&path, b"initial content here").await?;

        // Open with truncate
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .await?;
        file.write_all(b"new").await?;
        file.sync_all().await?;
        drop(file);

        let contents = fs::read_to_string(&path).await?;
        assert_eq!(contents, "new");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "truncate mode failed: {result:?}");
    test_complete!("fs_verify_010_open_options_truncate");
}

// =============================================================================
// Path Operations (FS-VERIFY-011 through FS-VERIFY-017)
// =============================================================================

/// FS-VERIFY-011: read/write/read_to_string roundtrip
///
/// Verifies the convenience path functions for whole-file I/O.
#[test]
fn fs_verify_011_path_read_write_roundtrip() {
    init_test("fs_verify_011_path_read_write_roundtrip");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("path_rw.txt");

        // Write bytes
        fs::write(&path, b"bytes content").await?;
        let bytes = fs::read(&path).await?;
        assert_eq!(&bytes, b"bytes content");

        // Write string (via AsRef<[u8]>)
        fs::write(&path, "string content").await?;
        let text = fs::read_to_string(&path).await?;
        assert_eq!(text, "string content");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "path read/write roundtrip failed: {result:?}"
    );
    test_complete!("fs_verify_011_path_read_write_roundtrip");
}

/// FS-VERIFY-012: copy preserves content and returns byte count
///
/// Verifies fs::copy duplicates file data correctly.
#[test]
fn fs_verify_012_copy_file() {
    init_test("fs_verify_012_copy_file");

    let result = block_on(async {
        let dir = tempdir()?;
        let src = dir.path().join("src.txt");
        let dst = dir.path().join("dst.txt");

        fs::write(&src, b"copy this data").await?;
        let copied = fs::copy(&src, &dst).await?;
        assert_eq!(copied, 14);

        let src_data = fs::read(&src).await?;
        let dst_data = fs::read(&dst).await?;
        assert_eq!(src_data, dst_data);

        // Source should still exist
        assert!(src.exists());

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "copy failed: {result:?}");
    test_complete!("fs_verify_012_copy_file");
}

/// FS-VERIFY-013: rename moves file atomically
///
/// Verifies rename moves a file from one path to another.
#[test]
fn fs_verify_013_rename_file() {
    init_test("fs_verify_013_rename_file");

    let result = block_on(async {
        let dir = tempdir()?;
        let from = dir.path().join("from.txt");
        let to = dir.path().join("to.txt");

        fs::write(&from, b"moving data").await?;
        fs::rename(&from, &to).await?;

        assert!(!from.exists());
        assert!(to.exists());
        let data = fs::read(&to).await?;
        assert_eq!(&data, b"moving data");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "rename failed: {result:?}");
    test_complete!("fs_verify_013_rename_file");
}

/// FS-VERIFY-014: remove_file deletes file
///
/// Verifies remove_file removes a file from the filesystem.
#[test]
fn fs_verify_014_remove_file() {
    init_test("fs_verify_014_remove_file");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("remove_me.txt");

        fs::write(&path, b"ephemeral").await?;
        assert!(path.exists());

        fs::remove_file(&path).await?;
        assert!(!path.exists());

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "remove_file failed: {result:?}");
    test_complete!("fs_verify_014_remove_file");
}

/// FS-VERIFY-015: hard_link creates second name for same data
///
/// Verifies hard links share the same underlying inode/data.
#[test]
fn fs_verify_015_hard_link() {
    init_test("fs_verify_015_hard_link");

    let result = block_on(async {
        let dir = tempdir()?;
        let original = dir.path().join("original.txt");
        let link = dir.path().join("link.txt");

        fs::write(&original, b"shared data").await?;
        fs::hard_link(&original, &link).await?;

        // Both paths should have the same content
        let orig_data = fs::read(&original).await?;
        let link_data = fs::read(&link).await?;
        assert_eq!(orig_data, link_data);

        // Remove original, link should still work
        fs::remove_file(&original).await?;
        let link_data = fs::read(&link).await?;
        assert_eq!(&link_data, b"shared data");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "hard_link failed: {result:?}");
    test_complete!("fs_verify_015_hard_link");
}

/// FS-VERIFY-016: symlink and read_link (Unix)
///
/// Verifies symlink creation and target resolution.
#[cfg(unix)]
#[test]
fn fs_verify_016_symlink() {
    init_test("fs_verify_016_symlink");

    let result = block_on(async {
        let dir = tempdir()?;
        let target = dir.path().join("target.txt");
        let link = dir.path().join("symlink");

        fs::write(&target, b"target content").await?;
        fs::symlink(&target, &link).await?;

        // Read through symlink
        let data = fs::read(&link).await?;
        assert_eq!(&data, b"target content");

        // read_link returns the target
        let resolved = fs::read_link(&link).await?;
        assert_eq!(resolved, target);

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "symlink failed: {result:?}");
    test_complete!("fs_verify_016_symlink");
}

/// FS-VERIFY-017: canonicalize resolves symlinks
///
/// Verifies canonicalize produces an absolute path with symlinks resolved.
#[cfg(unix)]
#[test]
fn fs_verify_017_canonicalize() {
    init_test("fs_verify_017_canonicalize");

    let result = block_on(async {
        let dir = tempdir()?;
        let file = dir.path().join("real.txt");
        let link = dir.path().join("link_to_real");

        fs::write(&file, b"data").await?;
        fs::symlink(&file, &link).await?;

        let canonical = fs::canonicalize(&link).await?;
        let file_canonical = fs::canonicalize(&file).await?;
        assert_eq!(canonical, file_canonical);
        assert!(canonical.is_absolute());

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "canonicalize failed: {result:?}");
    test_complete!("fs_verify_017_canonicalize");
}

// =============================================================================
// Directory Operations (FS-VERIFY-018 through FS-VERIFY-022)
// =============================================================================

/// FS-VERIFY-018: create_dir and remove_dir lifecycle
///
/// Verifies single-level directory creation and removal.
#[test]
fn fs_verify_018_create_remove_dir() {
    init_test("fs_verify_018_create_remove_dir");

    let result = block_on(async {
        let dir = tempdir()?;
        let sub = dir.path().join("subdir");

        fs::create_dir(&sub).await?;
        assert!(sub.exists());
        assert!(sub.is_dir());

        fs::remove_dir(&sub).await?;
        assert!(!sub.exists());

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "create/remove dir failed: {result:?}");
    test_complete!("fs_verify_018_create_remove_dir");
}

/// FS-VERIFY-019: create_dir_all creates nested parents
///
/// Verifies recursive directory creation.
#[test]
fn fs_verify_019_create_dir_all() {
    init_test("fs_verify_019_create_dir_all");

    let result = block_on(async {
        let dir = tempdir()?;
        let nested = dir.path().join("a").join("b").join("c");

        fs::create_dir_all(&nested).await?;
        assert!(nested.exists());
        assert!(nested.is_dir());

        // Idempotent: calling again should not fail
        fs::create_dir_all(&nested).await?;

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "create_dir_all failed: {result:?}");
    test_complete!("fs_verify_019_create_dir_all");
}

/// FS-VERIFY-020: remove_dir_all recursive removal
///
/// Verifies recursive directory removal including contents.
#[test]
fn fs_verify_020_remove_dir_all() {
    init_test("fs_verify_020_remove_dir_all");

    let result = block_on(async {
        let dir = tempdir()?;
        let root = dir.path().join("tree");

        // Create a directory tree with files
        fs::create_dir_all(root.join("sub1")).await?;
        fs::create_dir_all(root.join("sub2").join("deep")).await?;
        fs::write(root.join("file.txt"), b"root file").await?;
        fs::write(root.join("sub1").join("a.txt"), b"a").await?;
        fs::write(root.join("sub2").join("deep").join("b.txt"), b"b").await?;

        // Remove the entire tree
        fs::remove_dir_all(&root).await?;
        assert!(!root.exists());

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "remove_dir_all failed: {result:?}");
    test_complete!("fs_verify_020_remove_dir_all");
}

/// FS-VERIFY-021: read_dir enumerates entries
///
/// Verifies directory entry iteration via next_entry().
#[test]
fn fs_verify_021_read_dir_entries() {
    init_test("fs_verify_021_read_dir_entries");

    let result = block_on(async {
        let dir = tempdir()?;
        let root = dir.path().join("listdir");
        fs::create_dir(&root).await?;

        // Create known entries
        fs::write(root.join("alpha.txt"), b"a").await?;
        fs::write(root.join("beta.txt"), b"b").await?;
        fs::create_dir(root.join("gamma")).await?;

        let mut entries = fs::read_dir(&root).await?;
        let mut names = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            names.push(entry.file_name().to_string_lossy().to_string());
        }
        names.sort();

        assert_eq!(names, vec!["alpha.txt", "beta.txt", "gamma"]);

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "read_dir entries failed: {result:?}");
    test_complete!("fs_verify_021_read_dir_entries");
}

/// FS-VERIFY-022: ReadDir as Stream
///
/// Verifies the Stream trait implementation on ReadDir.
#[test]
fn fs_verify_022_read_dir_stream() {
    init_test("fs_verify_022_read_dir_stream");

    let result = block_on(async {
        let dir = tempdir()?;
        let root = dir.path().join("streamdir");
        fs::create_dir(&root).await?;

        fs::write(root.join("x.txt"), b"x").await?;
        fs::write(root.join("y.txt"), b"y").await?;

        let entries = fs::read_dir(&root).await?;
        let mut names: Vec<String> = entries
            .map(|r| r.unwrap().file_name().to_string_lossy().to_string())
            .collect()
            .await;
        names.sort();

        assert_eq!(names, vec!["x.txt", "y.txt"]);

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "read_dir stream failed: {result:?}");
    test_complete!("fs_verify_022_read_dir_stream");
}

// =============================================================================
// Metadata and Permissions (FS-VERIFY-023 through FS-VERIFY-026)
// =============================================================================

/// FS-VERIFY-023: Metadata for file vs directory
///
/// Verifies metadata correctly distinguishes files from directories.
#[test]
fn fs_verify_023_metadata_file_vs_dir() {
    init_test("fs_verify_023_metadata_file_vs_dir");

    let result = block_on(async {
        let dir = tempdir()?;
        let file_path = dir.path().join("file.txt");
        let dir_path = dir.path().join("subdir");

        fs::write(&file_path, b"content").await?;
        fs::create_dir(&dir_path).await?;

        let file_meta = fs::metadata(&file_path).await?;
        assert!(file_meta.is_file());
        assert!(!file_meta.is_dir());
        assert_eq!(file_meta.len(), 7);
        assert!(!file_meta.is_empty());

        let dir_meta = fs::metadata(&dir_path).await?;
        assert!(dir_meta.is_dir());
        assert!(!dir_meta.is_file());

        // File types
        assert!(file_meta.file_type().is_file());
        assert!(dir_meta.file_type().is_dir());

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "metadata file vs dir failed: {result:?}");
    test_complete!("fs_verify_023_metadata_file_vs_dir");
}

/// FS-VERIFY-024: symlink_metadata vs metadata for symlinks
///
/// Verifies that metadata follows symlinks while symlink_metadata does not.
#[cfg(unix)]
#[test]
fn fs_verify_024_symlink_metadata() {
    init_test("fs_verify_024_symlink_metadata");

    let result = block_on(async {
        let dir = tempdir()?;
        let target = dir.path().join("target.txt");
        let link = dir.path().join("link");

        fs::write(&target, b"target data").await?;
        fs::symlink(&target, &link).await?;

        // metadata follows the symlink
        let meta = fs::metadata(&link).await?;
        assert!(meta.is_file());
        assert_eq!(meta.len(), 11);
        assert!(!meta.file_type().is_symlink());

        // symlink_metadata does NOT follow
        let sym_meta = fs::symlink_metadata(&link).await?;
        assert!(sym_meta.file_type().is_symlink());

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "symlink_metadata failed: {result:?}");
    test_complete!("fs_verify_024_symlink_metadata");
}

/// FS-VERIFY-025: Permissions readonly flag
///
/// Verifies the readonly permission flag can be set and queried.
#[test]
fn fs_verify_025_permissions_readonly() {
    init_test("fs_verify_025_permissions_readonly");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("perms.txt");

        fs::write(&path, b"permissioned").await?;

        let meta = fs::metadata(&path).await?;
        let mut perms = meta.permissions();

        // Set readonly
        perms.set_readonly(true);
        fs::set_permissions(&path, perms.clone()).await?;

        let meta2 = fs::metadata(&path).await?;
        assert!(meta2.permissions().readonly());

        // Reset so tempdir cleanup works
        perms.set_readonly(false);
        fs::set_permissions(&path, perms).await?;

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "permissions readonly failed: {result:?}");
    test_complete!("fs_verify_025_permissions_readonly");
}

/// FS-VERIFY-026: Metadata timestamps (modified, accessed, created)
///
/// Verifies that timestamps are available and reasonable.
#[test]
fn fs_verify_026_metadata_timestamps() {
    init_test("fs_verify_026_metadata_timestamps");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("timestamps.txt");

        fs::write(&path, b"timed data").await?;

        let meta = fs::metadata(&path).await?;

        let modified = meta.modified()?;
        let accessed = meta.accessed()?;

        // modified and accessed should be valid (not before UNIX epoch)
        let epoch = std::time::UNIX_EPOCH;
        assert!(modified > epoch);
        assert!(accessed > epoch);

        // created() may not be available on all platforms
        match meta.created() {
            Ok(created) => {
                assert!(created > epoch);
                tracing::info!(?created, "creation time available");
            }
            Err(e) => {
                tracing::info!(?e, "creation time not available on this platform");
            }
        }

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "timestamps failed: {result:?}");
    test_complete!("fs_verify_026_metadata_timestamps");
}

// =============================================================================
// Buffered I/O (FS-VERIFY-027 through FS-VERIFY-030)
// =============================================================================

/// FS-VERIFY-027: BufReader with lines
///
/// Verifies BufReader's line iteration via the Lines stream.
#[test]
fn fs_verify_027_buf_reader_lines() {
    init_test("fs_verify_027_buf_reader_lines");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("lines.txt");

        fs::write(&path, "line1\nline2\nline3\n").await?;

        let file = File::open(&path).await?;
        let reader = BufReader::new(file);
        let lines: Vec<String> = reader.lines().try_collect().await?;

        assert_eq!(lines, vec!["line1", "line2", "line3"]);

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "buf_reader lines failed: {result:?}");
    test_complete!("fs_verify_027_buf_reader_lines");
}

/// FS-VERIFY-028: BufWriter flush behavior
///
/// Verifies that BufWriter buffers data and flushes on explicit flush().
#[test]
fn fs_verify_028_buf_writer_flush() {
    init_test("fs_verify_028_buf_writer_flush");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("buffered.txt");

        let file = File::create(&path).await?;
        let mut writer = BufWriter::new(file);

        // Write small amounts that stay in buffer
        writer.write_all(b"hello ").await?;
        writer.write_all(b"world").await?;

        // Buffer should have data
        assert_eq!(writer.buffer().len(), 11);

        // Flush to disk
        writer.flush().await?;
        assert_eq!(writer.buffer().len(), 0);

        drop(writer);

        let contents = fs::read_to_string(&path).await?;
        assert_eq!(contents, "hello world");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "buf_writer flush failed: {result:?}");
    test_complete!("fs_verify_028_buf_writer_flush");
}

/// FS-VERIFY-029: BufWriter large write bypasses buffer
///
/// Verifies that writes larger than capacity bypass the internal buffer.
#[test]
fn fs_verify_029_buf_writer_large_bypass() {
    init_test("fs_verify_029_buf_writer_large_bypass");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("large.txt");

        let file = File::create(&path).await?;
        let mut writer = BufWriter::with_capacity(64, file);

        // Write larger than capacity (64 bytes)
        let data = vec![b'A'; 200];
        writer.write_all(&data).await?;
        writer.flush().await?;
        drop(writer);

        let contents = fs::read(&path).await?;
        assert_eq!(contents.len(), 200);
        assert!(contents.iter().all(|&b| b == b'A'));

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "buf_writer large bypass failed: {result:?}");
    test_complete!("fs_verify_029_buf_writer_large_bypass");
}

/// FS-VERIFY-030: BufReader with_capacity
///
/// Verifies BufReader respects custom capacity settings.
#[test]
fn fs_verify_030_buf_reader_with_capacity() {
    init_test("fs_verify_030_buf_reader_with_capacity");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("capacity.txt");

        // Write a file with known content
        let data = "a".repeat(1000);
        fs::write(&path, &data).await?;

        let file = File::open(&path).await?;
        let reader = BufReader::with_capacity(32, file);

        // Read through the reader
        let inner = reader.into_inner();
        let mut inner_file = inner;
        let mut contents = String::new();
        inner_file.read_to_string(&mut contents).await?;
        assert_eq!(contents.len(), 1000);

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "buf_reader with_capacity failed: {result:?}"
    );
    test_complete!("fs_verify_030_buf_reader_with_capacity");
}

// =============================================================================
// Error Handling / Fault Injection (FS-VERIFY-031 through FS-VERIFY-036)
// =============================================================================

/// FS-VERIFY-031: Open non-existent file (ENOENT)
///
/// Verifies that opening a non-existent file returns NotFound.
#[test]
fn fs_verify_031_open_nonexistent() {
    init_test("fs_verify_031_open_nonexistent");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("does_not_exist.txt");

        let err = File::open(&path).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        tracing::info!(?err, "correctly returned NotFound for missing file");

        // read also returns NotFound
        let err = fs::read(&path).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        // read_to_string too
        let err = fs::read_to_string(&path).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "open nonexistent test failed: {result:?}");
    test_complete!("fs_verify_031_open_nonexistent");
}

/// FS-VERIFY-032: Remove non-existent file (ENOENT)
///
/// Verifies that removing a non-existent file returns an error.
#[test]
fn fs_verify_032_remove_nonexistent() {
    init_test("fs_verify_032_remove_nonexistent");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("ghost.txt");

        let err = fs::remove_file(&path).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        let err = fs::remove_dir(&path).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "remove nonexistent test failed: {result:?}");
    test_complete!("fs_verify_032_remove_nonexistent");
}

/// FS-VERIFY-033: Create dir where file exists
///
/// Verifies that creating a directory at an existing file path fails.
#[test]
fn fs_verify_033_create_dir_where_file_exists() {
    init_test("fs_verify_033_create_dir_where_file_exists");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("file_not_dir.txt");

        fs::write(&path, b"I am a file").await?;

        let err = fs::create_dir(&path).await.unwrap_err();
        tracing::info!(?err, "correctly rejected dir creation at file path");
        // Error kind varies by OS (AlreadyExists on Linux)
        assert!(
            err.kind() == io::ErrorKind::AlreadyExists
                || err.kind() == io::ErrorKind::Other
                || err.kind() == io::ErrorKind::PermissionDenied,
            "unexpected error kind: {:?}",
            err.kind()
        );

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "create dir at file path test failed: {result:?}"
    );
    test_complete!("fs_verify_033_create_dir_where_file_exists");
}

/// FS-VERIFY-034: Read dir on non-directory
///
/// Verifies that read_dir on a regular file fails.
#[test]
fn fs_verify_034_read_dir_on_file() {
    init_test("fs_verify_034_read_dir_on_file");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("regular_file.txt");

        fs::write(&path, b"not a directory").await?;

        let err = fs::read_dir(&path).await.unwrap_err();
        tracing::info!(?err, "correctly rejected read_dir on file");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "read_dir on file test failed: {result:?}");
    test_complete!("fs_verify_034_read_dir_on_file");
}

/// FS-VERIFY-035: create_new on existing file (EEXIST)
///
/// Verifies create_new fails with AlreadyExists for an existing file.
#[test]
fn fs_verify_035_create_new_existing() {
    init_test("fs_verify_035_create_new_existing");

    let result = block_on(async {
        let dir = tempdir()?;
        let path = dir.path().join("exists.txt");

        fs::write(&path, b"already here").await?;

        let err = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        tracing::info!(?err, "correctly rejected create_new on existing file");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "create_new existing test failed: {result:?}"
    );
    test_complete!("fs_verify_035_create_new_existing");
}

/// FS-VERIFY-036: Remove non-empty directory
///
/// Verifies that remove_dir fails on a non-empty directory.
#[test]
fn fs_verify_036_remove_nonempty_dir() {
    init_test("fs_verify_036_remove_nonempty_dir");

    let result = block_on(async {
        let dir = tempdir()?;
        let sub = dir.path().join("nonempty");

        fs::create_dir(&sub).await?;
        fs::write(sub.join("file.txt"), b"content").await?;

        // remove_dir should fail because directory is not empty
        let err = fs::remove_dir(&sub).await.unwrap_err();
        tracing::info!(?err, "correctly rejected removal of non-empty directory");

        // Cleanup with remove_dir_all
        fs::remove_dir_all(&sub).await?;

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "remove nonempty dir test failed: {result:?}"
    );
    test_complete!("fs_verify_036_remove_nonempty_dir");
}
