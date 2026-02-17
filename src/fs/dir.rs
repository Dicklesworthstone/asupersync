//! Async directory creation and removal.
//!
//! On Linux with `io-uring`, `remove_dir` uses `IORING_OP_UNLINKAT` with
//! `AT_REMOVEDIR` for true async directory removal. Other operations use
//! `spawn_blocking_io` to offload to a background thread.

use crate::runtime::spawn_blocking_io;
use std::io;
use std::path::Path;

/// Creates a new empty directory at the specified path.
///
/// On Linux with `io-uring`, uses `IORING_OP_MKDIRAT`.
///
/// # Cancel Safety
///
/// This operation is cancel-safe: it either completes or does not create the
/// directory at all.
pub async fn create_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = path.as_ref().to_owned();
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    {
        uring_mkdirat(&path, 0o755)
    }
    #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
    {
        spawn_blocking_io(move || std::fs::create_dir(&path)).await
    }
}

/// Recursively creates a directory and all of its parent components.
///
/// # Cancel Safety
///
/// This operation is cancel-safe: partial directories may be created on
/// cancellation but each individual mkdir is atomic.
pub async fn create_dir_all<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = path.as_ref().to_owned();
    spawn_blocking_io(move || std::fs::create_dir_all(&path)).await
}

/// Removes an empty directory.
///
/// On Linux with `io-uring`, uses `IORING_OP_UNLINKAT` with `AT_REMOVEDIR`.
///
/// # Cancel Safety
///
/// This operation is cancel-safe: it either removes the directory or fails.
pub async fn remove_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = path.as_ref().to_owned();
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    {
        uring_unlinkat_dir(&path)
    }
    #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
    {
        spawn_blocking_io(move || std::fs::remove_dir(&path)).await
    }
}

/// Recursively removes a directory and all of its contents.
///
/// # Cancel Safety
///
/// This operation is **not** cancel-safe; cancellation may leave partial state.
pub async fn remove_dir_all<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = path.as_ref().to_owned();
    spawn_blocking_io(move || std::fs::remove_dir_all(&path)).await
}

// ---- io_uring helpers ----

#[cfg(all(target_os = "linux", feature = "io-uring"))]
#[allow(unsafe_code)]
fn uring_submit_one(entry: &io_uring::squeue::Entry) -> io::Result<()> {
    use io_uring::IoUring;

    let mut ring = IoUring::new(2)?;
    unsafe {
        ring.submission()
            .push(entry)
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "submission queue full"))?;
    }
    ring.submit_and_wait(1)?;
    let result = ring
        .completion()
        .next()
        .map(|cqe| cqe.result())
        .ok_or_else(|| io::Error::other("no completion received"))?;
    if result < 0 {
        Err(io::Error::from_raw_os_error(-result))
    } else {
        Ok(())
    }
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
fn path_to_cstring(path: &std::path::Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;

    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains null bytes"))
}

/// Uses io_uring's UNLINKAT opcode with AT_REMOVEDIR flag for directory removal.
#[cfg(all(target_os = "linux", feature = "io-uring"))]
fn uring_unlinkat_dir(path: &std::path::Path) -> io::Result<()> {
    use io_uring::{opcode, types};
    let c_path = path_to_cstring(path)?;
    let entry = opcode::UnlinkAt::new(types::Fd(libc::AT_FDCWD), c_path.as_ptr())
        .flags(libc::AT_REMOVEDIR)
        .build();
    uring_submit_one(&entry)
}

/// Uses io_uring's MKDIRAT opcode for directory creation.
#[cfg(all(target_os = "linux", feature = "io-uring"))]
fn uring_mkdirat(path: &std::path::Path, mode: libc::mode_t) -> io::Result<()> {
    use io_uring::{opcode, types};
    let c_path = path_to_cstring(path)?;
    let entry = opcode::MkDirAt::new(types::Fd(libc::AT_FDCWD), c_path.as_ptr())
        .mode(mode)
        .build();
    uring_submit_one(&entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(target_os = "linux", feature = "io-uring", unix))]
    use std::ffi::OsString;
    #[cfg(all(target_os = "linux", feature = "io-uring", unix))]
    use std::os::unix::ffi::OsStringExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!("asupersync_test_{name}_{id}"));
        path
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[cfg(all(target_os = "linux", feature = "io-uring", unix))]
    #[test]
    fn test_path_to_cstring_accepts_non_utf8_unix_paths() {
        init_test("test_path_to_cstring_accepts_non_utf8_unix_paths");
        let raw = vec![b'd', b'i', b'r', b'_', 0xFF];
        let path = std::path::PathBuf::from(OsString::from_vec(raw.clone()));

        let c = path_to_cstring(&path).expect("non-utf8 unix path should be accepted");
        crate::assert_with_log!(
            c.as_bytes() == raw.as_slice(),
            "raw bytes preserved",
            raw.as_slice(),
            c.as_bytes()
        );
        crate::test_complete!("test_path_to_cstring_accepts_non_utf8_unix_paths");
    }

    #[cfg(all(target_os = "linux", feature = "io-uring", unix))]
    #[test]
    fn test_path_to_cstring_rejects_nul_bytes() {
        init_test("test_path_to_cstring_rejects_nul_bytes");
        let path = std::path::PathBuf::from(OsString::from_vec(vec![b'b', b'a', b'd', 0, b'x']));

        let err = path_to_cstring(&path).expect_err("path with nul must be rejected");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::InvalidInput,
            "invalid input error",
            io::ErrorKind::InvalidInput,
            err.kind()
        );
        crate::test_complete!("test_path_to_cstring_rejects_nul_bytes");
    }

    #[test]
    fn test_create_dir() {
        init_test("test_create_dir");
        let path = unique_temp_dir("create_dir");
        let result = futures_lite::future::block_on(async { create_dir(&path).await });
        crate::assert_with_log!(result.is_ok(), "create ok", true, result.is_ok());
        let exists = path.exists();
        crate::assert_with_log!(exists, "path exists", true, exists);
        let is_dir = path.is_dir();
        crate::assert_with_log!(is_dir, "path is dir", true, is_dir);

        let _ = std::fs::remove_dir_all(&path);
        crate::test_complete!("test_create_dir");
    }

    #[test]
    fn test_create_dir_all() {
        init_test("test_create_dir_all");
        let base = unique_temp_dir("create_dir_all");
        let path = base.join("a/b/c");

        let result = futures_lite::future::block_on(async { create_dir_all(&path).await });
        crate::assert_with_log!(result.is_ok(), "create ok", true, result.is_ok());
        let exists = path.exists();
        crate::assert_with_log!(exists, "path exists", true, exists);

        let _ = std::fs::remove_dir_all(&base);
        crate::test_complete!("test_create_dir_all");
    }

    #[test]
    fn test_remove_dir() {
        init_test("test_remove_dir");
        let path = unique_temp_dir("remove_dir");
        std::fs::create_dir_all(&path).unwrap();
        let exists = path.exists();
        crate::assert_with_log!(exists, "path exists", true, exists);

        let result = futures_lite::future::block_on(async { remove_dir(&path).await });
        crate::assert_with_log!(result.is_ok(), "remove ok", true, result.is_ok());
        let exists_after = path.exists();
        crate::assert_with_log!(!exists_after, "path removed", false, exists_after);
        crate::test_complete!("test_remove_dir");
    }

    #[test]
    fn test_remove_dir_all() {
        init_test("test_remove_dir_all");
        let path = unique_temp_dir("remove_dir_all");
        std::fs::create_dir_all(path.join("a/b/c")).unwrap();
        std::fs::write(path.join("a/file.txt"), b"content").unwrap();
        std::fs::write(path.join("a/b/file.txt"), b"content").unwrap();

        let result = futures_lite::future::block_on(async { remove_dir_all(&path).await });
        crate::assert_with_log!(result.is_ok(), "remove ok", true, result.is_ok());
        let exists_after = path.exists();
        crate::assert_with_log!(!exists_after, "path removed", false, exists_after);
        crate::test_complete!("test_remove_dir_all");
    }
}
