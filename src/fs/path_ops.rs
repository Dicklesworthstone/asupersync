//! Async path utilities and metadata helpers.
//!
//! Phase 0 uses synchronous OS calls behind async signatures.
//! In Phase 1+, these will be offloaded to a blocking pool.

use super::metadata::{Metadata, Permissions};
use std::io;
use std::path::{Path, PathBuf};

/// Get metadata for a path (follows symlinks).
pub async fn metadata(path: impl AsRef<Path>) -> io::Result<Metadata> {
    let inner = std::fs::metadata(path)?;
    Ok(Metadata::from_std(inner))
}

/// Get metadata for a path (does not follow symlinks).
pub async fn symlink_metadata(path: impl AsRef<Path>) -> io::Result<Metadata> {
    let inner = std::fs::symlink_metadata(path)?;
    Ok(Metadata::from_std(inner))
}

/// Set permissions for a path.
pub async fn set_permissions(path: impl AsRef<Path>, perm: Permissions) -> io::Result<()> {
    std::fs::set_permissions(path, perm.into_inner())
}

/// Canonicalize a path (resolve symlinks, make absolute).
pub async fn canonicalize(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    std::fs::canonicalize(path)
}

/// Read a symlink target.
pub async fn read_link(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    std::fs::read_link(path)
}

/// Copy a file from `src` to `dst`.
pub async fn copy(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<u64> {
    std::fs::copy(src, dst)
}

/// Rename or move a file.
pub async fn rename(from: impl AsRef<Path>, to: impl AsRef<Path>) -> io::Result<()> {
    std::fs::rename(from, to)
}

/// Remove a file.
pub async fn remove_file(path: impl AsRef<Path>) -> io::Result<()> {
    std::fs::remove_file(path)
}

/// Create a hard link.
pub async fn hard_link(original: impl AsRef<Path>, link: impl AsRef<Path>) -> io::Result<()> {
    std::fs::hard_link(original, link)
}

/// Create a symlink (Unix).
#[cfg(unix)]
pub async fn symlink(original: impl AsRef<Path>, link: impl AsRef<Path>) -> io::Result<()> {
    std::os::unix::fs::symlink(original, link)
}

/// Create a symlink to a file (Windows).
#[cfg(windows)]
pub async fn symlink_file(original: impl AsRef<Path>, link: impl AsRef<Path>) -> io::Result<()> {
    std::os::windows::fs::symlink_file(original, link)
}

/// Create a symlink to a directory (Windows).
#[cfg(windows)]
pub async fn symlink_dir(original: impl AsRef<Path>, link: impl AsRef<Path>) -> io::Result<()> {
    std::os::windows::fs::symlink_dir(original, link)
}

/// Read an entire file into a byte vector.
pub async fn read(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    std::fs::read(path)
}

/// Read an entire file into a string.
pub async fn read_to_string(path: impl AsRef<Path>) -> io::Result<String> {
    std::fs::read_to_string(path)
}

/// Write bytes to a file (creates or truncates).
pub async fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    std::fs::write(path, contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future;
    use std::fs;
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
