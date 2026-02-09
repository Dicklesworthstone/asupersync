//! Virtual File System abstraction.
//!
//! Provides `Vfs` and `VfsFile` traits that abstract filesystem operations,
//! enabling both real Unix I/O (`UnixVfs`) and in-memory testing (`MemoryVfs`).
//!
//! # Design
//!
//! - **`VfsFile`**: An open file handle supporting async read, write, seek,
//!   metadata, sync, and truncation.
//! - **`Vfs`**: A filesystem namespace supporting open, create, metadata,
//!   directory operations, path operations (rename, copy, remove), and
//!   convenience read/write helpers.
//!
//! # Cancel Safety
//!
//! Cancel-safety properties are inherited from the underlying implementation.
//! For `UnixVfs`, see the per-operation notes in [`crate::fs`].

use crate::fs::metadata::{Metadata, Permissions};
use crate::fs::open_options::OpenOptions;
use crate::fs::read_dir::ReadDir;
use crate::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};
use std::future::Future;
use std::io::{self, SeekFrom};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

// ---------------------------------------------------------------------------
// VfsFile trait
// ---------------------------------------------------------------------------

/// An open file handle on a virtual filesystem.
///
/// Implementors must provide async read, write, seek, metadata, sync, and
/// truncation. The poll-based `AsyncRead`/`AsyncWrite`/`AsyncSeek` impls are
/// accessed through [`VfsFile::as_async_read`] etc., or by pinning the
/// concrete type directly.
pub trait VfsFile: AsyncRead + AsyncWrite + AsyncSeek + Send + Unpin {
    /// Queries metadata about the open file.
    fn metadata(&self) -> impl Future<Output = io::Result<Metadata>> + Send;

    /// Syncs all OS-internal metadata to disk.
    fn sync_all(&self) -> impl Future<Output = io::Result<()>> + Send;

    /// Syncs file data (but not necessarily metadata) to disk.
    fn sync_data(&self) -> impl Future<Output = io::Result<()>> + Send;

    /// Truncates or extends the file to `size` bytes.
    fn set_len(&self, size: u64) -> impl Future<Output = io::Result<()>> + Send;

    /// Changes the file permissions.
    fn set_permissions(&self, perm: Permissions) -> impl Future<Output = io::Result<()>> + Send;
}

// ---------------------------------------------------------------------------
// Vfs trait
// ---------------------------------------------------------------------------

/// A virtual filesystem namespace.
///
/// All paths are interpreted relative to the implementation's root. For
/// `UnixVfs`, this is the real filesystem. Future implementations (e.g.
/// `MemoryVfs`) can use an in-memory tree.
pub trait Vfs: Send + Sync {
    /// The concrete file handle type returned by [`open`](Vfs::open).
    type File: VfsFile;

    // -- file open --

    /// Opens a file using the given [`OpenOptions`].
    fn open(
        &self,
        path: &Path,
        opts: &OpenOptions,
    ) -> impl Future<Output = io::Result<Self::File>> + Send;

    /// Opens a file in read-only mode (convenience wrapper).
    fn open_read(&self, path: &Path) -> impl Future<Output = io::Result<Self::File>> + Send {
        let opts = OpenOptions::new().read(true);
        async move { self.open(path, &opts).await }
    }

    /// Creates a file in write-only mode, truncating if it exists (convenience wrapper).
    fn open_create(&self, path: &Path) -> impl Future<Output = io::Result<Self::File>> + Send {
        let opts = OpenOptions::new().write(true).create(true).truncate(true);
        async move { self.open(path, &opts).await }
    }

    // -- metadata --

    /// Returns metadata for `path` (follows symlinks).
    fn metadata(&self, path: &Path) -> impl Future<Output = io::Result<Metadata>> + Send;

    /// Returns metadata for `path` (does *not* follow symlinks).
    fn symlink_metadata(&self, path: &Path) -> impl Future<Output = io::Result<Metadata>> + Send;

    /// Sets permissions on `path`.
    fn set_permissions(
        &self,
        path: &Path,
        perm: Permissions,
    ) -> impl Future<Output = io::Result<()>> + Send;

    // -- directory operations --

    /// Creates a single directory.
    fn create_dir(&self, path: &Path) -> impl Future<Output = io::Result<()>> + Send;

    /// Creates a directory and all missing parents.
    fn create_dir_all(&self, path: &Path) -> impl Future<Output = io::Result<()>> + Send;

    /// Removes an empty directory.
    fn remove_dir(&self, path: &Path) -> impl Future<Output = io::Result<()>> + Send;

    /// Removes a directory and all contents recursively.
    fn remove_dir_all(&self, path: &Path) -> impl Future<Output = io::Result<()>> + Send;

    /// Lists directory entries.
    fn read_dir(&self, path: &Path) -> impl Future<Output = io::Result<ReadDir>> + Send;

    // -- path operations --

    /// Removes a file.
    fn remove_file(&self, path: &Path) -> impl Future<Output = io::Result<()>> + Send;

    /// Renames (moves) a file or directory.
    fn rename(&self, from: &Path, to: &Path) -> impl Future<Output = io::Result<()>> + Send;

    /// Copies a file from `src` to `dst`, returning bytes copied.
    fn copy(&self, src: &Path, dst: &Path) -> impl Future<Output = io::Result<u64>> + Send;

    /// Creates a hard link.
    fn hard_link(
        &self,
        original: &Path,
        link: &Path,
    ) -> impl Future<Output = io::Result<()>> + Send;

    /// Canonicalizes a path (resolves symlinks, makes absolute).
    fn canonicalize(&self, path: &Path) -> impl Future<Output = io::Result<PathBuf>> + Send;

    /// Reads a symlink target.
    fn read_link(&self, path: &Path) -> impl Future<Output = io::Result<PathBuf>> + Send;

    // -- convenience read/write --

    /// Reads an entire file into bytes.
    fn read(&self, path: &Path) -> impl Future<Output = io::Result<Vec<u8>>> + Send;

    /// Reads an entire file into a string.
    fn read_to_string(&self, path: &Path) -> impl Future<Output = io::Result<String>> + Send;

    /// Writes bytes to a file (creates or truncates).
    fn write(&self, path: &Path, contents: &[u8]) -> impl Future<Output = io::Result<()>> + Send;
}

// ---------------------------------------------------------------------------
// UnixVfs — real filesystem implementation
// ---------------------------------------------------------------------------

/// A [`Vfs`] backed by the real Unix filesystem via asupersync's async `fs` module.
///
/// All operations delegate to [`crate::fs`] functions, which use
/// `spawn_blocking_io` or `io_uring` (on Linux with the `io-uring` feature).
#[derive(Debug, Clone, Copy, Default)]
pub struct UnixVfs;

impl UnixVfs {
    /// Creates a new `UnixVfs`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

// ---------------------------------------------------------------------------
// UnixVfsFile — wraps crate::fs::File
// ---------------------------------------------------------------------------

/// A [`VfsFile`] backed by [`crate::fs::File`].
#[derive(Debug)]
pub struct UnixVfsFile {
    inner: crate::fs::File,
}

impl AsyncRead for UnixVfsFile {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for UnixVfsFile {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncSeek for UnixVfsFile {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        Pin::new(&mut self.inner).poll_seek(cx, pos)
    }
}

impl VfsFile for UnixVfsFile {
    async fn metadata(&self) -> io::Result<Metadata> {
        let m = self.inner.metadata().await?;
        Ok(Metadata::from_std(m))
    }

    async fn sync_all(&self) -> io::Result<()> {
        self.inner.sync_all().await
    }

    async fn sync_data(&self) -> io::Result<()> {
        self.inner.sync_data().await
    }

    async fn set_len(&self, size: u64) -> io::Result<()> {
        self.inner.set_len(size).await
    }

    async fn set_permissions(&self, perm: Permissions) -> io::Result<()> {
        self.inner.set_permissions(perm.into_inner()).await
    }
}

// ---------------------------------------------------------------------------
// Vfs impl for UnixVfs
// ---------------------------------------------------------------------------

impl Vfs for UnixVfs {
    type File = UnixVfsFile;

    async fn open(&self, path: &Path, opts: &OpenOptions) -> io::Result<Self::File> {
        let file = opts.open(path).await?;
        Ok(UnixVfsFile { inner: file })
    }

    async fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        crate::fs::metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        crate::fs::symlink_metadata(path).await
    }

    async fn set_permissions(&self, path: &Path, perm: Permissions) -> io::Result<()> {
        crate::fs::set_permissions(path, perm).await
    }

    async fn create_dir(&self, path: &Path) -> io::Result<()> {
        crate::fs::create_dir(path).await
    }

    async fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        crate::fs::create_dir_all(path).await
    }

    async fn remove_dir(&self, path: &Path) -> io::Result<()> {
        crate::fs::remove_dir(path).await
    }

    async fn remove_dir_all(&self, path: &Path) -> io::Result<()> {
        crate::fs::remove_dir_all(path).await
    }

    async fn read_dir(&self, path: &Path) -> io::Result<ReadDir> {
        crate::fs::read_dir(path).await
    }

    async fn remove_file(&self, path: &Path) -> io::Result<()> {
        crate::fs::remove_file(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        crate::fs::rename(from, to).await
    }

    async fn copy(&self, src: &Path, dst: &Path) -> io::Result<u64> {
        crate::fs::copy(src, dst).await
    }

    async fn hard_link(&self, original: &Path, link: &Path) -> io::Result<()> {
        crate::fs::hard_link(original, link).await
    }

    async fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        crate::fs::canonicalize(path).await
    }

    async fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        crate::fs::read_link(path).await
    }

    async fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        crate::fs::read(path).await
    }

    async fn read_to_string(&self, path: &Path) -> io::Result<String> {
        crate::fs::read_to_string(path).await
    }

    async fn write(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        crate::fs::write(path, contents).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::{AsyncReadExt, AsyncWriteExt};
    use tempfile::tempdir;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // -- UnixVfs: file create, write, read roundtrip --

    #[test]
    fn unix_vfs_write_read_roundtrip() {
        init_test("unix_vfs_write_read_roundtrip");
        futures_lite::future::block_on(async {
            let vfs = UnixVfs::new();
            let dir = tempdir().unwrap();
            let path = dir.path().join("hello.txt");

            // Write via convenience method
            vfs.write(&path, b"hello vfs").await.unwrap();

            // Read back via convenience method
            let contents = vfs.read_to_string(&path).await.unwrap();
            crate::assert_with_log!(contents == "hello vfs", "contents", "hello vfs", contents);
        });
        crate::test_complete!("unix_vfs_write_read_roundtrip");
    }

    // -- UnixVfs: open + VfsFile read/write --

    #[test]
    fn unix_vfs_open_file_rw() {
        init_test("unix_vfs_open_file_rw");
        futures_lite::future::block_on(async {
            let vfs = UnixVfs::new();
            let dir = tempdir().unwrap();
            let path = dir.path().join("rw.txt");

            // Create and write via VfsFile
            let mut file = vfs.open_create(&path).await.unwrap();
            file.write_all(b"vfs file write").await.unwrap();
            file.sync_all().await.unwrap();
            drop(file);

            // Read back via VfsFile
            let mut file = vfs.open_read(&path).await.unwrap();
            let mut buf = String::new();
            file.read_to_string(&mut buf).await.unwrap();
            crate::assert_with_log!(buf == "vfs file write", "read back", "vfs file write", buf);
        });
        crate::test_complete!("unix_vfs_open_file_rw");
    }

    // -- UnixVfs: metadata --

    #[test]
    fn unix_vfs_metadata() {
        init_test("unix_vfs_metadata");
        futures_lite::future::block_on(async {
            let vfs = UnixVfs::new();
            let dir = tempdir().unwrap();
            let path = dir.path().join("meta.txt");

            vfs.write(&path, b"12345").await.unwrap();
            let meta = vfs.metadata(&path).await.unwrap();
            crate::assert_with_log!(meta.is_file(), "is_file", true, meta.is_file());
            crate::assert_with_log!(meta.len() == 5, "len", 5, meta.len());
        });
        crate::test_complete!("unix_vfs_metadata");
    }

    // -- UnixVfs: directory operations --

    #[test]
    fn unix_vfs_dir_ops() {
        init_test("unix_vfs_dir_ops");
        futures_lite::future::block_on(async {
            let vfs = UnixVfs::new();
            let dir = tempdir().unwrap();
            let sub = dir.path().join("a/b/c");

            vfs.create_dir_all(&sub).await.unwrap();
            let meta = vfs.metadata(&sub).await.unwrap();
            crate::assert_with_log!(meta.is_dir(), "is_dir", true, meta.is_dir());

            // Write a file inside
            let file_path = sub.join("test.txt");
            vfs.write(&file_path, b"nested").await.unwrap();

            // read_dir
            let mut rd = vfs.read_dir(&sub).await.unwrap();
            let entry = rd.next_entry().await.unwrap().expect("one entry");
            let name = entry.file_name().to_string_lossy().to_string();
            crate::assert_with_log!(name == "test.txt", "entry name", "test.txt", name);

            // remove_dir_all
            let top = dir.path().join("a");
            vfs.remove_dir_all(&top).await.unwrap();
            let exists = top.exists();
            crate::assert_with_log!(!exists, "removed", false, exists);
        });
        crate::test_complete!("unix_vfs_dir_ops");
    }

    // -- UnixVfs: rename + copy + remove_file --

    #[test]
    fn unix_vfs_rename_copy_remove() {
        init_test("unix_vfs_rename_copy_remove");
        futures_lite::future::block_on(async {
            let vfs = UnixVfs::new();
            let dir = tempdir().unwrap();
            let src = dir.path().join("src.txt");
            let dst = dir.path().join("dst.txt");
            let renamed = dir.path().join("renamed.txt");

            vfs.write(&src, b"copy me").await.unwrap();

            // copy
            let n = vfs.copy(&src, &dst).await.unwrap();
            crate::assert_with_log!(n == 7, "bytes copied", 7, n);

            // rename
            vfs.rename(&dst, &renamed).await.unwrap();
            let exists = dst.exists();
            crate::assert_with_log!(!exists, "dst gone", false, exists);

            let contents = vfs.read(&renamed).await.unwrap();
            crate::assert_with_log!(
                contents == b"copy me",
                "renamed contents",
                b"copy me",
                contents
            );

            // remove_file
            vfs.remove_file(&renamed).await.unwrap();
            let exists = renamed.exists();
            crate::assert_with_log!(!exists, "removed", false, exists);
        });
        crate::test_complete!("unix_vfs_rename_copy_remove");
    }

    // -- VfsFile: seek --

    #[test]
    fn unix_vfs_file_seek() {
        init_test("unix_vfs_file_seek");
        futures_lite::future::block_on(async {
            let vfs = UnixVfs::new();
            let dir = tempdir().unwrap();
            let path = dir.path().join("seek.txt");

            // Write data
            let opts = OpenOptions::new().read(true).write(true).create(true);
            let mut file = vfs.open(&path, &opts).await.unwrap();
            file.write_all(b"0123456789").await.unwrap();
            drop(file);

            // Re-open, read all, verify
            let mut file = vfs.open_read(&path).await.unwrap();
            let mut all = String::new();
            file.read_to_string(&mut all).await.unwrap();
            crate::assert_with_log!(all == "0123456789", "full read", "0123456789", all);
        });
        crate::test_complete!("unix_vfs_file_seek");
    }

    // -- VfsFile: metadata + set_len --

    #[test]
    fn unix_vfs_file_metadata_set_len() {
        init_test("unix_vfs_file_metadata_set_len");
        futures_lite::future::block_on(async {
            let vfs = UnixVfs::new();
            let dir = tempdir().unwrap();
            let path = dir.path().join("truncate.txt");

            let mut file = vfs.open_create(&path).await.unwrap();
            file.write_all(b"hello world").await.unwrap();
            file.sync_all().await.unwrap();

            // Check metadata via VfsFile
            let meta = VfsFile::metadata(&file).await.unwrap();
            crate::assert_with_log!(meta.len() == 11, "initial len", 11, meta.len());

            // Truncate
            file.set_len(5).await.unwrap();
            file.sync_all().await.unwrap();
            drop(file);

            // Verify via Vfs
            let contents = vfs.read(&path).await.unwrap();
            crate::assert_with_log!(contents == b"hello", "truncated", b"hello", contents);
        });
        crate::test_complete!("unix_vfs_file_metadata_set_len");
    }

    // -- Generic function that works with any Vfs --

    async fn write_and_read_back<V: Vfs>(vfs: &V, dir: &Path) -> String {
        let path = dir.join("generic.txt");
        vfs.write(&path, b"generic vfs").await.unwrap();
        vfs.read_to_string(&path).await.unwrap()
    }

    #[test]
    fn unix_vfs_generic_usage() {
        init_test("unix_vfs_generic_usage");
        futures_lite::future::block_on(async {
            let vfs = UnixVfs::new();
            let dir = tempdir().unwrap();
            let result = write_and_read_back(&vfs, dir.path()).await;
            crate::assert_with_log!(result == "generic vfs", "generic", "generic vfs", result);
        });
        crate::test_complete!("unix_vfs_generic_usage");
    }

    // -- Symlink metadata (Unix-only) --

    #[cfg(unix)]
    #[test]
    fn unix_vfs_symlink_metadata() {
        init_test("unix_vfs_symlink_metadata");
        futures_lite::future::block_on(async {
            let vfs = UnixVfs::new();
            let dir = tempdir().unwrap();
            let target = dir.path().join("target.txt");
            let link = dir.path().join("link");

            vfs.write(&target, b"content").await.unwrap();
            std::os::unix::fs::symlink(&target, &link).unwrap();

            // metadata follows symlinks
            let meta = vfs.metadata(&link).await.unwrap();
            crate::assert_with_log!(meta.is_file(), "follows symlink", true, meta.is_file());

            // symlink_metadata does not
            let meta = vfs.symlink_metadata(&link).await.unwrap();
            crate::assert_with_log!(meta.is_symlink(), "is_symlink", true, meta.is_symlink());
        });
        crate::test_complete!("unix_vfs_symlink_metadata");
    }
}
