//! Async path utilities and metadata helpers.
//!
//! On Linux with `io-uring`, `remove_file` uses `IORING_OP_UNLINKAT`,
//! `rename` uses `IORING_OP_RENAMEAT`, and `symlink` uses `IORING_OP_SYMLINKAT`.
//! Other operations use `spawn_blocking_io` for true async offloading.

use super::metadata::{Metadata, Permissions};
use crate::runtime::spawn_blocking_io;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Get metadata for a path (follows symlinks).
pub async fn metadata(path: impl AsRef<Path>) -> io::Result<Metadata> {
    let path = path.as_ref().to_owned();
    let inner = spawn_blocking_io(move || std::fs::metadata(&path)).await?;
    Ok(Metadata::from_std(inner))
}

/// Get metadata for a path (does not follow symlinks).
pub async fn symlink_metadata(path: impl AsRef<Path>) -> io::Result<Metadata> {
    let path = path.as_ref().to_owned();
    let inner = spawn_blocking_io(move || std::fs::symlink_metadata(&path)).await?;
    Ok(Metadata::from_std(inner))
}

/// Set permissions for a path.
pub async fn set_permissions(path: impl AsRef<Path>, perm: Permissions) -> io::Result<()> {
    let path = path.as_ref().to_owned();
    spawn_blocking_io(move || std::fs::set_permissions(&path, perm.into_inner())).await
}

/// Canonicalize a path (resolve symlinks, make absolute).
pub async fn canonicalize(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let path = path.as_ref().to_owned();
    spawn_blocking_io(move || std::fs::canonicalize(&path)).await
}

/// Read a symlink target.
pub async fn read_link(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let path = path.as_ref().to_owned();
    spawn_blocking_io(move || std::fs::read_link(&path)).await
}

/// Copy a file from `src` to `dst`.
pub async fn copy(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<u64> {
    let src = src.as_ref().to_owned();
    let dst = dst.as_ref().to_owned();
    spawn_blocking_io(move || std::fs::copy(&src, &dst)).await
}

/// Rename or move a file.
///
/// On Linux with `io-uring`, uses `IORING_OP_RENAMEAT`.
pub async fn rename(from: impl AsRef<Path>, to: impl AsRef<Path>) -> io::Result<()> {
    let from = from.as_ref().to_owned();
    let to = to.as_ref().to_owned();
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    {
        uring_renameat(&from, &to)
    }
    #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
    {
        spawn_blocking_io(move || std::fs::rename(&from, &to)).await
    }
}

/// Remove a file.
///
/// On Linux with `io-uring`, uses `IORING_OP_UNLINKAT`.
pub async fn remove_file(path: impl AsRef<Path>) -> io::Result<()> {
    let path = path.as_ref().to_owned();
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    {
        uring_unlinkat(&path)
    }
    #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
    {
        spawn_blocking_io(move || std::fs::remove_file(&path)).await
    }
}

/// Create a hard link.
pub async fn hard_link(original: impl AsRef<Path>, link: impl AsRef<Path>) -> io::Result<()> {
    let original = original.as_ref().to_owned();
    let link = link.as_ref().to_owned();
    spawn_blocking_io(move || std::fs::hard_link(&original, &link)).await
}

/// Create a symlink (Unix).
///
/// On Linux with `io-uring`, uses `IORING_OP_SYMLINKAT`.
#[cfg(unix)]
pub async fn symlink(original: impl AsRef<Path>, link: impl AsRef<Path>) -> io::Result<()> {
    let original = original.as_ref().to_owned();
    let link = link.as_ref().to_owned();
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    {
        uring_symlinkat(&original, &link)
    }
    #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
    {
        spawn_blocking_io(move || std::os::unix::fs::symlink(&original, &link)).await
    }
}

/// Create a symlink to a file (Windows).
#[cfg(windows)]
pub async fn symlink_file(original: impl AsRef<Path>, link: impl AsRef<Path>) -> io::Result<()> {
    let original = original.as_ref().to_owned();
    let link = link.as_ref().to_owned();
    spawn_blocking_io(move || std::os::windows::fs::symlink_file(&original, &link)).await
}

/// Create a symlink to a directory (Windows).
#[cfg(windows)]
pub async fn symlink_dir(original: impl AsRef<Path>, link: impl AsRef<Path>) -> io::Result<()> {
    let original = original.as_ref().to_owned();
    let link = link.as_ref().to_owned();
    spawn_blocking_io(move || std::os::windows::fs::symlink_dir(&original, &link)).await
}

/// Read an entire file into a byte vector.
pub async fn read(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    let path = path.as_ref().to_owned();
    spawn_blocking_io(move || std::fs::read(&path)).await
}

/// Read an entire file into a string.
pub async fn read_to_string(path: impl AsRef<Path>) -> io::Result<String> {
    let path = path.as_ref().to_owned();
    spawn_blocking_io(move || std::fs::read_to_string(&path)).await
}

/// Write bytes to a file (creates or truncates).
pub async fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let path = path.as_ref().to_owned();
    let contents = contents.as_ref().to_owned();
    spawn_blocking_io(move || std::fs::write(&path, &contents)).await
}

/// Atomically replace file contents via temp-file + rename.
///
/// The temporary file is created in the target directory, fully written and
/// `sync_all()`'d, then renamed into place. On Unix, the parent directory is
/// also `sync_all()`'d after the rename so directory-entry durability is
/// explicit.
///
/// If the operation fails before rename, the temporary file is cleaned up.
pub async fn write_atomic(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let path = path.as_ref().to_owned();
    let contents = contents.as_ref().to_owned();
    spawn_blocking_io(move || write_atomic_blocking(&path, &contents)).await
}

static ATOMIC_WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn write_atomic_blocking(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = normalized_parent(path);
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic write target must include a file name",
        )
    })?;
    let existing_permissions = match std::fs::metadata(path) {
        Ok(metadata) => Some(metadata.permissions()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => return Err(err),
    };

    loop {
        let tmp_path = unique_tmp_path(parent, file_name);
        let mut file = match std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)
        {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        };
        let mut tmp_guard = TempPathGuard::new(tmp_path.clone());

        file.write_all(contents)?;
        if let Some(permissions) = &existing_permissions {
            // Preserve the target file's permissions before the replacement rename swaps in the
            // temp inode.
            file.set_permissions(permissions.clone())?;
        }
        file.sync_all()?;
        drop(file);

        std::fs::rename(&tmp_path, path)?;
        tmp_guard.disarm();
        sync_parent_dir(parent)?;
        return Ok(());
    }
}

fn normalized_parent(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn unique_tmp_path(parent: &Path, file_name: &std::ffi::OsStr) -> PathBuf {
    let counter = ATOMIC_WRITE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(".asupersync-tmp-{}-{counter}", std::process::id()));
    parent.join(tmp_name)
}

#[cfg(unix)]
fn sync_parent_dir(parent: &Path) -> io::Result<()> {
    let dir = std::fs::File::open(parent)?;
    dir.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_dir(_parent: &Path) -> io::Result<()> {
    Ok(())
}

struct TempPathGuard {
    path: PathBuf,
    armed: bool,
}

impl TempPathGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempPathGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
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
fn path_to_cstring(path: &Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;

    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains null bytes"))
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
fn uring_unlinkat(path: &Path) -> io::Result<()> {
    use io_uring::{opcode, types};
    let c_path = path_to_cstring(path)?;
    let entry = opcode::UnlinkAt::new(types::Fd(libc::AT_FDCWD), c_path.as_ptr())
        .flags(0)
        .build();
    uring_submit_one(&entry)
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
fn uring_renameat(from: &Path, to: &Path) -> io::Result<()> {
    use io_uring::{opcode, types};
    let c_from = path_to_cstring(from)?;
    let c_to = path_to_cstring(to)?;
    let entry = opcode::RenameAt::new(
        types::Fd(libc::AT_FDCWD),
        c_from.as_ptr(),
        types::Fd(libc::AT_FDCWD),
        c_to.as_ptr(),
    )
    .build();
    uring_submit_one(&entry)
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
fn uring_symlinkat(target: &Path, linkpath: &Path) -> io::Result<()> {
    use io_uring::{opcode, types};
    let c_target = path_to_cstring(target)?;
    let c_link = path_to_cstring(linkpath)?;
    let entry = opcode::SymlinkAt::new(
        types::Fd(libc::AT_FDCWD),
        c_target.as_ptr(),
        c_link.as_ptr(),
    )
    .build();
    uring_submit_one(&entry)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;
    use futures_lite::future;
    #[cfg(all(target_os = "linux", feature = "io-uring", unix))]
    use std::ffi::OsString;
    use std::fs;
    #[cfg(all(target_os = "linux", feature = "io-uring", unix))]
    use std::os::unix::ffi::OsStringExt;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(prefix: &str) -> io::Result<Self> {
            let mut path = std::env::temp_dir();
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            path.push(format!("asupersync_{prefix}_{nanos}"));
            fs::create_dir_all(&path)?;
            Ok(Self { path })
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[cfg(all(target_os = "linux", feature = "io-uring", unix))]
    #[test]
    fn path_to_cstring_accepts_non_utf8_unix_paths() {
        init_test("path_to_cstring_accepts_non_utf8_unix_paths");
        let raw = vec![b'f', b's', b'_', 0xFE];
        let path = PathBuf::from(OsString::from_vec(raw.clone()));

        let c = path_to_cstring(&path).expect("non-utf8 unix path should be accepted");
        crate::assert_with_log!(
            c.as_bytes() == raw.as_slice(),
            "raw bytes preserved",
            raw.as_slice(),
            c.as_bytes()
        );
        crate::test_complete!("path_to_cstring_accepts_non_utf8_unix_paths");
    }

    #[cfg(all(target_os = "linux", feature = "io-uring", unix))]
    #[test]
    fn path_to_cstring_rejects_nul_bytes() {
        init_test("path_to_cstring_rejects_nul_bytes");
        let path = PathBuf::from(OsString::from_vec(vec![b'b', b'a', b'd', 0, b'x']));

        let err = path_to_cstring(&path).expect_err("path with nul must be rejected");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::InvalidInput,
            "invalid input error",
            io::ErrorKind::InvalidInput,
            err.kind()
        );
        crate::test_complete!("path_to_cstring_rejects_nul_bytes");
    }

    #[test]
    fn metadata_basic() {
        init_test("metadata_basic");
        let dir = TempDir::new("meta").unwrap();
        let file_path = dir.path().join("test.txt");

        future::block_on(async {
            write(&file_path, b"hello").await.unwrap();
            let meta = metadata(&file_path).await.unwrap();
            let is_file = meta.is_file();
            crate::assert_with_log!(is_file, "is_file", true, is_file);
            let is_dir = meta.is_dir();
            crate::assert_with_log!(!is_dir, "is_dir false", false, is_dir);
            let len = meta.len();
            crate::assert_with_log!(len == 5, "len", 5, len);
        });
        crate::test_complete!("metadata_basic");
    }

    #[test]
    fn read_write_roundtrip() {
        init_test("read_write_roundtrip");
        let dir = TempDir::new("rw").unwrap();
        let file_path = dir.path().join("read_write.txt");

        future::block_on(async {
            write(&file_path, "hello world").await.unwrap();
            let contents = read_to_string(&file_path).await.unwrap();
            crate::assert_with_log!(
                contents == "hello world",
                "contents",
                "hello world",
                contents
            );
            let bytes = read(&file_path).await.unwrap();
            crate::assert_with_log!(bytes == b"hello world", "bytes", b"hello world", bytes);
        });
        crate::test_complete!("read_write_roundtrip");
    }

    #[test]
    fn copy_rename_remove() {
        init_test("copy_rename_remove");
        let dir = TempDir::new("ops").unwrap();
        let src = dir.path().join("src.txt");
        let dst = dir.path().join("dst.txt");
        let renamed = dir.path().join("renamed.txt");

        future::block_on(async {
            write(&src, b"copy me").await.unwrap();
            let copied = copy(&src, &dst).await.unwrap();
            crate::assert_with_log!(copied == 7, "copied bytes", 7, copied);
            rename(&dst, &renamed).await.unwrap();
            let exists = dst.exists();
            crate::assert_with_log!(!exists, "dst removed", false, exists);
            let contents = read(&renamed).await.unwrap();
            crate::assert_with_log!(contents == b"copy me", "contents", b"copy me", contents);
            remove_file(&renamed).await.unwrap();
            let exists = renamed.exists();
            crate::assert_with_log!(!exists, "renamed removed", false, exists);
        });
        crate::test_complete!("copy_rename_remove");
    }

    #[test]
    fn hard_link_roundtrip() {
        init_test("hard_link_roundtrip");
        let dir = TempDir::new("hard_link").unwrap();
        let src = dir.path().join("source.txt");
        let link = dir.path().join("link.txt");

        future::block_on(async {
            write(&src, b"same-bytes").await.unwrap();
            hard_link(&src, &link).await.unwrap();

            let source = read(&src).await.unwrap();
            let linked = read(&link).await.unwrap();
            crate::assert_with_log!(
                linked == source,
                "linked bytes match source",
                source,
                linked
            );
        });
        crate::test_complete!("hard_link_roundtrip");
    }

    #[test]
    fn set_permissions_readonly_roundtrip() {
        init_test("set_permissions_readonly_roundtrip");
        let dir = TempDir::new("permissions").unwrap();
        let path = dir.path().join("file.txt");

        future::block_on(async {
            write(&path, b"content").await.unwrap();

            let mut perms = metadata(&path).await.unwrap().permissions();
            perms.set_readonly(true);
            set_permissions(&path, perms).await.unwrap();

            let readonly_after_set = metadata(&path).await.unwrap().permissions().readonly();
            crate::assert_with_log!(readonly_after_set, "readonly set", true, readonly_after_set);

            let mut perms = metadata(&path).await.unwrap().permissions();
            perms.set_readonly(false);
            set_permissions(&path, perms).await.unwrap();

            let readonly_after_clear = metadata(&path).await.unwrap().permissions().readonly();
            crate::assert_with_log!(
                !readonly_after_clear,
                "readonly cleared",
                false,
                readonly_after_clear
            );
        });
        crate::test_complete!("set_permissions_readonly_roundtrip");
    }

    #[test]
    fn write_atomic_creates_and_replaces_without_temp_leaks() {
        init_test("write_atomic_creates_and_replaces_without_temp_leaks");
        let dir = TempDir::new("write_atomic").unwrap();
        let path = dir.path().join("target.txt");

        future::block_on(async {
            write_atomic(&path, b"v1").await.unwrap();
            let first = read(&path).await.unwrap();
            crate::assert_with_log!(first == b"v1", "initial write", b"v1", first);

            write_atomic(&path, b"v2").await.unwrap();
            let second = read(&path).await.unwrap();
            crate::assert_with_log!(second == b"v2", "replacement write", b"v2", second);

            let mut leaked_tmp = Vec::new();
            for entry in std::fs::read_dir(dir.path()).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name();
                if name.to_string_lossy().contains(".asupersync-tmp-") {
                    leaked_tmp.push(name.to_string_lossy().to_string());
                }
            }
            crate::assert_with_log!(
                leaked_tmp.is_empty(),
                "no leaked temporary files",
                "[]",
                format!("{leaked_tmp:?}")
            );
        });
        crate::test_complete!("write_atomic_creates_and_replaces_without_temp_leaks");
    }

    #[test]
    fn write_atomic_missing_parent_fails_cleanly() {
        init_test("write_atomic_missing_parent_fails_cleanly");
        let dir = TempDir::new("write_atomic_missing_parent").unwrap();
        let missing_parent = dir.path().join("missing");
        let target = missing_parent.join("target.txt");

        future::block_on(async {
            let err = write_atomic(&target, b"data")
                .await
                .expect_err("missing parent should fail");
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::NotFound,
                "missing parent returns NotFound",
                io::ErrorKind::NotFound,
                err.kind()
            );
            let target_exists = target.exists();
            crate::assert_with_log!(
                !target_exists,
                "target should not be created on failure",
                false,
                target_exists
            );
        });
        crate::test_complete!("write_atomic_missing_parent_fails_cleanly");
    }

    #[test]
    fn write_atomic_retries_when_stale_temp_name_exists() {
        init_test("write_atomic_retries_when_stale_temp_name_exists");
        let dir = TempDir::new("write_atomic_collision").unwrap();
        let path = dir.path().join("target.txt");
        let file_name = path.file_name().expect("target file name");
        let start = ATOMIC_WRITE_COUNTER.load(Ordering::Relaxed);

        for offset in 0..8 {
            let counter = start.saturating_add(offset);
            let stale = dir.path().join(format!(
                ".{}.asupersync-tmp-{}-{counter}",
                file_name.to_string_lossy(),
                std::process::id()
            ));
            fs::write(stale, b"stale-temp").unwrap();
        }

        future::block_on(async {
            write_atomic(&path, b"fresh").await.unwrap();

            let bytes = read(&path).await.unwrap();
            crate::assert_with_log!(bytes == b"fresh", "fresh content written", b"fresh", bytes);

            let stale_count = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .contains(".asupersync-tmp-")
                })
                .count();
            crate::assert_with_log!(
                stale_count >= 8,
                "preexisting stale temp files preserved",
                ">= 8",
                stale_count
            );
        });
        crate::test_complete!("write_atomic_retries_when_stale_temp_name_exists");
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_preserves_existing_unix_permissions() {
        init_test("write_atomic_preserves_existing_unix_permissions");
        let dir = TempDir::new("write_atomic_permissions").unwrap();
        let path = dir.path().join("script.sh");

        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();

        future::block_on(async {
            write_atomic(&path, b"new").await.unwrap();

            let bytes = read(&path).await.unwrap();
            crate::assert_with_log!(bytes == b"new", "new content written", b"new", bytes);

            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            crate::assert_with_log!(mode == 0o700, "existing permissions preserved", 0o700, mode);
        });
        crate::test_complete!("write_atomic_preserves_existing_unix_permissions");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_metadata_basic() {
        init_test("symlink_metadata_basic");
        let dir = TempDir::new("symlink").unwrap();
        let file_path = dir.path().join("file.txt");
        let link_path = dir.path().join("link");

        future::block_on(async {
            write(&file_path, b"content").await.unwrap();
            symlink(&file_path, &link_path).await.unwrap();

            let meta = metadata(&link_path).await.unwrap();
            let is_file = meta.is_file();
            crate::assert_with_log!(is_file, "is_file", true, is_file);
            let len = meta.len();
            crate::assert_with_log!(len == 7, "len", 7, len);

            let link_meta = symlink_metadata(&link_path).await.unwrap();
            let is_symlink = link_meta.file_type().is_symlink();
            crate::assert_with_log!(is_symlink, "is_symlink", true, is_symlink);
        });
        crate::test_complete!("symlink_metadata_basic");
    }
}
