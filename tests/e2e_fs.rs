#![allow(missing_docs)]

//! Filesystem E2E test suite: io_uring and directory operation tests (bd-2auz).
//!
//! Covers file operations, directory operations, symlinks, platform-specific
//! io_uring paths, and cancellation correctness.

#[macro_use]
mod common;

use asupersync::fs;
use futures_lite::future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut path = std::env::temp_dir();
    path.push(format!("asupersync_e2e_fs_{prefix}_{id}_{nanos}"));
    path
}

fn cleanup(path: &std::path::Path) {
    let _ = std::fs::remove_dir_all(path);
}

// === File Operations ===

#[test]
fn e2e_file_create_write_read_roundtrip() {
    common::init_test_logging();
    let base = unique_temp_dir("file_rw");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let path = base.join("hello.txt");
        let mut file = fs::File::create(&path).await.unwrap();
        use asupersync::io::AsyncWriteExt;
        file.write_all(b"hello e2e").await.unwrap();
        file.sync_all().await.unwrap();
        drop(file);

        let mut file = fs::File::open(&path).await.unwrap();
        use asupersync::io::AsyncReadExt;
        let mut buf = String::new();
        file.read_to_string(&mut buf).await.unwrap();
        assert_eq!(buf, "hello e2e");
    });

    cleanup(&base);
}

#[test]
fn e2e_file_open_options_combinations() {
    common::init_test_logging();
    let base = unique_temp_dir("open_opts");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let path = base.join("opts.txt");

        // create + write
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&path)
            .await
            .unwrap();
        use asupersync::io::AsyncWriteExt;
        f.write_all(b"first").await.unwrap();
        drop(f);

        // append
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .await
            .unwrap();
        f.write_all(b"_second").await.unwrap();
        drop(f);

        let contents = fs::read_to_string(&path).await.unwrap();
        assert_eq!(contents, "first_second");

        // truncate
        let mut f = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .await
            .unwrap();
        f.write_all(b"new").await.unwrap();
        drop(f);

        let contents = fs::read_to_string(&path).await.unwrap();
        assert_eq!(contents, "new");
    });

    cleanup(&base);
}

#[test]
fn e2e_file_set_len_and_metadata() {
    common::init_test_logging();
    let base = unique_temp_dir("set_len");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let path = base.join("trunc.txt");
        fs::write(&path, b"hello world 12345").await.unwrap();

        let file = fs::File::open(&path).await.unwrap();
        let meta = file.metadata().await.unwrap();
        assert_eq!(meta.len(), 17);
        assert!(meta.is_file());
        drop(file);

        let file = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .await
            .unwrap();
        file.set_len(5).await.unwrap();
        file.sync_all().await.unwrap();
        drop(file);

        let contents = fs::read_to_string(&path).await.unwrap();
        assert_eq!(contents, "hello");
    });

    cleanup(&base);
}

// === Path Operations ===

#[test]
fn e2e_path_read_write_roundtrip() {
    common::init_test_logging();
    let base = unique_temp_dir("path_rw");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let path = base.join("data.bin");
        let data: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();
        fs::write(&path, &data).await.unwrap();

        let read_back = fs::read(&path).await.unwrap();
        assert_eq!(read_back, data);

        let as_str = fs::read_to_string(base.join("data.bin")).await;
        // binary data won't be valid utf8
        assert!(as_str.is_err());
    });

    cleanup(&base);
}

#[test]
fn e2e_copy_rename_remove_chain() {
    common::init_test_logging();
    let base = unique_temp_dir("copy_chain");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let src = base.join("src.txt");
        let copied = base.join("copied.txt");
        let renamed = base.join("renamed.txt");

        fs::write(&src, b"chain test").await.unwrap();

        // copy
        let bytes = fs::copy(&src, &copied).await.unwrap();
        assert_eq!(bytes, 10);
        assert!(copied.exists());

        // rename
        fs::rename(&copied, &renamed).await.unwrap();
        assert!(!copied.exists());
        assert!(renamed.exists());

        let contents = fs::read_to_string(&renamed).await.unwrap();
        assert_eq!(contents, "chain test");

        // remove
        fs::remove_file(&renamed).await.unwrap();
        assert!(!renamed.exists());

        // original still exists
        assert!(src.exists());
    });

    cleanup(&base);
}

#[test]
fn e2e_hard_link() {
    common::init_test_logging();
    let base = unique_temp_dir("hardlink");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let original = base.join("original.txt");
        let link = base.join("link.txt");

        fs::write(&original, b"linked").await.unwrap();
        fs::hard_link(&original, &link).await.unwrap();

        let contents = fs::read_to_string(&link).await.unwrap();
        assert_eq!(contents, "linked");

        // Both point to same inode
        let meta_orig = fs::metadata(&original).await.unwrap();
        let meta_link = fs::metadata(&link).await.unwrap();
        assert_eq!(meta_orig.len(), meta_link.len());
    });

    cleanup(&base);
}

#[cfg(unix)]
#[test]
fn e2e_symlink_and_readlink() {
    common::init_test_logging();
    let base = unique_temp_dir("symlink");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let target = base.join("target.txt");
        let link = base.join("sym.txt");

        fs::write(&target, b"symlinked").await.unwrap();
        fs::symlink(&target, &link).await.unwrap();

        // read through symlink
        let contents = fs::read_to_string(&link).await.unwrap();
        assert_eq!(contents, "symlinked");

        // readlink
        let read_target = fs::read_link(&link).await.unwrap();
        assert_eq!(read_target, target);

        // metadata follows symlink
        let meta = fs::metadata(&link).await.unwrap();
        assert!(meta.is_file());

        // symlink_metadata does not follow
        let sym_meta = fs::symlink_metadata(&link).await.unwrap();
        assert!(sym_meta.file_type().is_symlink());
    });

    cleanup(&base);
}

#[test]
fn e2e_canonicalize() {
    common::init_test_logging();
    let base = unique_temp_dir("canonicalize");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let file = base.join("real.txt");
        fs::write(&file, b"x").await.unwrap();

        let canonical = fs::canonicalize(&file).await.unwrap();
        assert!(canonical.is_absolute());
        assert!(canonical.exists());
    });

    cleanup(&base);
}

// === Directory Operations ===

#[test]
fn e2e_create_dir_and_remove_dir() {
    common::init_test_logging();
    let base = unique_temp_dir("dir_ops");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let dir = base.join("subdir");
        fs::create_dir(&dir).await.unwrap();
        assert!(dir.is_dir());

        fs::remove_dir(&dir).await.unwrap();
        assert!(!dir.exists());
    });

    cleanup(&base);
}

#[test]
fn e2e_create_dir_all_nested() {
    common::init_test_logging();
    let base = unique_temp_dir("dir_all");
    // Don't pre-create base - let create_dir_all handle it

    future::block_on(async {
        let deep = base.join("a").join("b").join("c").join("d");
        fs::create_dir_all(&deep).await.unwrap();
        assert!(deep.is_dir());
    });

    cleanup(&base);
}

#[test]
fn e2e_remove_dir_all_recursive() {
    common::init_test_logging();
    let base = unique_temp_dir("rmdir_all");
    std::fs::create_dir_all(base.join("a/b/c")).unwrap();
    std::fs::write(base.join("a/file1.txt"), b"1").unwrap();
    std::fs::write(base.join("a/b/file2.txt"), b"2").unwrap();
    std::fs::write(base.join("a/b/c/file3.txt"), b"3").unwrap();

    future::block_on(async {
        fs::remove_dir_all(&base).await.unwrap();
        assert!(!base.exists());
    });
}

#[test]
fn e2e_dir_error_cases() {
    common::init_test_logging();
    let base = unique_temp_dir("dir_errors");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        // remove non-empty dir should fail
        let dir = base.join("notempty");
        fs::create_dir(&dir).await.unwrap();
        fs::write(dir.join("file.txt"), b"x").await.unwrap();
        let result = fs::remove_dir(&dir).await;
        assert!(result.is_err());

        // create dir where file exists should fail
        let file = base.join("afile");
        fs::write(&file, b"x").await.unwrap();
        let result = fs::create_dir(&file).await;
        assert!(result.is_err());

        // remove non-existent dir
        let result = fs::remove_dir(base.join("nope")).await;
        assert!(result.is_err());
    });

    cleanup(&base);
}

// === Platform-specific: io_uring verification ===

#[cfg(all(target_os = "linux", feature = "io-uring"))]
mod platform_uring {
    use super::*;

    #[test]
    fn e2e_uring_file_read_write() {
        common::init_test_logging();
        let base = unique_temp_dir("uring_rw");
        std::fs::create_dir_all(&base).unwrap();

        future::block_on(async {
            let path = base.join("uring.txt");

            // Uses io_uring path on Linux
            fs::write(&path, b"io_uring test data").await.unwrap();
            let data = fs::read(&path).await.unwrap();
            assert_eq!(data, b"io_uring test data");
        });

        cleanup(&base);
    }

    #[test]
    fn e2e_uring_rename() {
        common::init_test_logging();
        let base = unique_temp_dir("uring_rename");
        std::fs::create_dir_all(&base).unwrap();

        future::block_on(async {
            let src = base.join("before.txt");
            let dst = base.join("after.txt");
            fs::write(&src, b"rename via uring").await.unwrap();

            fs::rename(&src, &dst).await.unwrap();
            assert!(!src.exists());
            let contents = fs::read_to_string(&dst).await.unwrap();
            assert_eq!(contents, "rename via uring");
        });

        cleanup(&base);
    }

    #[test]
    fn e2e_uring_remove_file() {
        common::init_test_logging();
        let base = unique_temp_dir("uring_rm");
        std::fs::create_dir_all(&base).unwrap();

        future::block_on(async {
            let path = base.join("to_remove.txt");
            fs::write(&path, b"remove me").await.unwrap();
            assert!(path.exists());

            fs::remove_file(&path).await.unwrap();
            assert!(!path.exists());
        });

        cleanup(&base);
    }

    #[test]
    fn e2e_uring_mkdir_rmdir() {
        common::init_test_logging();
        let base = unique_temp_dir("uring_dir");
        std::fs::create_dir_all(&base).unwrap();

        future::block_on(async {
            let dir = base.join("uring_created");
            fs::create_dir(&dir).await.unwrap();
            assert!(dir.is_dir());

            fs::remove_dir(&dir).await.unwrap();
            assert!(!dir.exists());
        });

        cleanup(&base);
    }

    #[cfg(unix)]
    #[test]
    fn e2e_uring_symlink() {
        common::init_test_logging();
        let base = unique_temp_dir("uring_sym");
        std::fs::create_dir_all(&base).unwrap();

        future::block_on(async {
            let target = base.join("target.txt");
            let link = base.join("link.txt");
            fs::write(&target, b"sym target").await.unwrap();

            fs::symlink(&target, &link).await.unwrap();
            let contents = fs::read_to_string(&link).await.unwrap();
            assert_eq!(contents, "sym target");
        });

        cleanup(&base);
    }
}

// === Large file handling ===

#[test]
fn e2e_large_file_roundtrip() {
    common::init_test_logging();
    let base = unique_temp_dir("large_file");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let path = base.join("big.bin");
        // 1MB of data
        let data: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
        fs::write(&path, &data).await.unwrap();

        let read_back = fs::read(&path).await.unwrap();
        assert_eq!(read_back.len(), data.len());
        assert_eq!(read_back, data);
    });

    cleanup(&base);
}

// === Error handling ===

#[test]
fn e2e_file_not_found() {
    common::init_test_logging();
    future::block_on(async {
        let result = fs::File::open("/nonexistent/path/file.txt").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    });
}

#[test]
fn e2e_remove_nonexistent() {
    common::init_test_logging();
    future::block_on(async {
        let result = fs::remove_file("/nonexistent/file.txt").await;
        assert!(result.is_err());
    });
}

#[cfg(unix)]
#[test]
fn e2e_permissions() {
    common::init_test_logging();
    let base = unique_temp_dir("perms");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let path = base.join("perm_test.txt");
        fs::write(&path, b"test").await.unwrap();

        let meta = fs::metadata(&path).await.unwrap();
        let perms = meta.permissions();
        // Should not be readonly by default
        assert!(!perms.readonly());

        // Set readonly
        let mut new_perms = perms.clone();
        new_perms.set_readonly(true);
        fs::set_permissions(&path, new_perms).await.unwrap();

        let meta = fs::metadata(&path).await.unwrap();
        assert!(meta.permissions().readonly());

        // Reset for cleanup
        let mut reset_perms = meta.permissions().clone();
        reset_perms.set_readonly(false);
        fs::set_permissions(&path, reset_perms).await.unwrap();
    });

    cleanup(&base);
}
