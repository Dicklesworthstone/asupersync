//! Async directory creation and removal.
//!
//! On Linux with `io-uring`, `remove_dir` uses `IORING_OP_UNLINKAT` with
//! `AT_REMOVEDIR` for true async directory removal. Other operations use
//! `spawn_blocking_io` to offload to a background thread.

use crate::cx::io_gate::spawn_blocking_io;
use std::io;
use std::path::Path;

#[cfg(all(target_os = "linux", feature = "io-uring"))]
// Match std::fs::create_dir / mkdir(2) defaults; the process umask still applies.
const DEFAULT_CREATE_DIR_MODE: libc::mode_t = 0o777;

/// Creates a new empty directory at the specified path.
///
/// On Linux with `io-uring`, uses `IORING_OP_MKDIRAT`.
///
/// # Cancel Safety
///
/// This operation uses soft cancellation. A submitted directory creation may
/// commit after the returned future is dropped.
pub async fn create_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = path.as_ref().to_owned();
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    {
        spawn_blocking_io(move || uring_mkdirat(&path, DEFAULT_CREATE_DIR_MODE)).await
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
/// This operation uses soft cancellation. A started traversal may continue
/// creating some or all missing components after the future is dropped.
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
/// This operation uses soft cancellation. A submitted removal may commit after
/// the returned future is dropped.
pub async fn remove_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = path.as_ref().to_owned();
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    {
        spawn_blocking_io(move || uring_unlinkat_dir(&path)).await
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
/// This operation uses soft cancellation. A started recursive removal may keep
/// deleting entries after the returned future is dropped and may leave partial
/// state if it later fails.
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
    super::path_ops::submit_and_wait_one(&mut ring)?;
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
    crate::cx::io_gate::require_ambient_io("fs")?;
    let c_path = path_to_cstring(path)?;
    let entry = opcode::UnlinkAt::new(types::Fd(libc::AT_FDCWD), c_path.as_ptr())
        .flags(libc::AT_REMOVEDIR)
        .build();
    super::path_ops::uring_or_blocking(|| uring_submit_one(&entry), || std::fs::remove_dir(path))
}

/// Uses io_uring's MKDIRAT opcode for directory creation.
#[cfg(all(target_os = "linux", feature = "io-uring"))]
fn uring_mkdirat(path: &std::path::Path, mode: libc::mode_t) -> io::Result<()> {
    use io_uring::{opcode, types};
    crate::cx::io_gate::require_ambient_io("fs")?;
    let c_path = path_to_cstring(path)?;
    let entry = opcode::MkDirAt::new(types::Fd(libc::AT_FDCWD), c_path.as_ptr())
        .mode(mode)
        .build();
    super::path_ops::uring_or_blocking(
        || uring_submit_one(&entry),
        || {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(mode).create(path)
        },
    )
}

#[cfg(test)]
#[path = "dir_inline_tests.rs"]
mod tests;
