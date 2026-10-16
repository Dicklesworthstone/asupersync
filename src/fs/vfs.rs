//! Virtual File System abstraction.
//!
//! Provides `Vfs` and `VfsFile` traits that abstract filesystem operations,
//! enabling real Unix I/O via [`UnixVfs`] and alternate implementations for tests
//! or embedded environments.
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
//! The trait itself makes no rollback guarantee. `UnixVfs` delegates to the
//! matching [`crate::fs`] operation, including its soft-cancellation or
//! synchronous-poll boundary.

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
/// truncation. The poll-based `AsyncRead`/`AsyncWrite`/`AsyncSeek` impls can be
/// used directly via the async I/O extension traits in [`crate::io`] or by
/// pinning the concrete type directly.
pub trait VfsFile: AsyncRead + AsyncWrite + AsyncSeek + Send + Unpin {
    /// Queries metadata about the open file.
    fn metadata(&self) -> impl Future<Output = io::Result<Metadata>> + Send;

    /// Syncs all OS-internal metadata to disk.
    ///
    /// Cancellation semantics are implementation-defined. `UnixVfsFile`
    /// inherits [`crate::fs::File::sync_all`]'s soft-completion boundary.
    fn sync_all(&self) -> impl Future<Output = io::Result<()>> + Send;

    /// Syncs file data (but not necessarily metadata) to disk.
    ///
    /// Cancellation semantics are implementation-defined. `UnixVfsFile`
    /// inherits [`crate::fs::File::sync_data`]'s soft-completion boundary.
    fn sync_data(&self) -> impl Future<Output = io::Result<()>> + Send;

    /// Truncates or extends the file to `size` bytes.
    ///
    /// Cancellation semantics are implementation-defined. `UnixVfsFile`
    /// inherits [`crate::fs::File::set_len`]'s may-commit-after-drop boundary.
    fn set_len(&self, size: u64) -> impl Future<Output = io::Result<()>> + Send;

    /// Changes the file permissions.
    ///
    /// Cancellation semantics are implementation-defined. `UnixVfsFile`
    /// inherits [`crate::fs::File::set_permissions`]'s may-commit-after-drop
    /// boundary.
    fn set_permissions(&self, perm: Permissions) -> impl Future<Output = io::Result<()>> + Send;
}

// ---------------------------------------------------------------------------
// Vfs trait
// ---------------------------------------------------------------------------

/// A virtual filesystem namespace.
///
/// All paths are interpreted relative to the implementation's root. For
/// `UnixVfs`, this is the real filesystem. Other implementations can back the
/// namespace with an alternate storage layer.
pub trait Vfs: Send + Sync {
    /// The concrete file handle type returned by [`open`](Vfs::open).
    type File: VfsFile;

    // -- file open --

    /// Opens a file using the given [`OpenOptions`].
    ///
    /// Implementations define cancellation semantics. With `UnixVfs`, enabled
    /// create or truncate effects may commit after future drop.
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
    ///
    /// With `UnixVfs`, a started create or truncate may commit after future
    /// drop.
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
    ///
    /// With `UnixVfs`, a started permission change may commit after future
    /// drop.
    fn set_permissions(
        &self,
        path: &Path,
        perm: Permissions,
    ) -> impl Future<Output = io::Result<()>> + Send;

    // -- directory operations --

    /// Creates a single directory.
    ///
    /// With `UnixVfs`, a started creation may commit after future drop.
    fn create_dir(&self, path: &Path) -> impl Future<Output = io::Result<()>> + Send;

    /// Creates a directory and all missing parents.
    ///
    /// With `UnixVfs`, a started traversal may keep creating components after
    /// future drop.
    fn create_dir_all(&self, path: &Path) -> impl Future<Output = io::Result<()>> + Send;

    /// Removes an empty directory.
    ///
    /// With `UnixVfs`, a started removal may commit after future drop.
    fn remove_dir(&self, path: &Path) -> impl Future<Output = io::Result<()>> + Send;

    /// Removes a directory and all contents recursively.
    ///
    /// With `UnixVfs`, a started recursive removal may continue after future
    /// drop and may leave partial state if it later fails.
    fn remove_dir_all(&self, path: &Path) -> impl Future<Output = io::Result<()>> + Send;

    /// Lists directory entries.
    fn read_dir(&self, path: &Path) -> impl Future<Output = io::Result<ReadDir>> + Send;

    // -- path operations --

    /// Removes a file.
    ///
    /// With `UnixVfs`, a started removal may commit after future drop.
    fn remove_file(&self, path: &Path) -> impl Future<Output = io::Result<()>> + Send;

    /// Renames (moves) a file or directory.
    ///
    /// With `UnixVfs`, a started rename may commit after future drop.
    fn rename(&self, from: &Path, to: &Path) -> impl Future<Output = io::Result<()>> + Send;

    /// Copies a file from `src` to `dst`, returning bytes copied.
    ///
    /// With `UnixVfs`, a started copy may create, truncate, or partially
    /// populate `dst` after future drop.
    fn copy(&self, src: &Path, dst: &Path) -> impl Future<Output = io::Result<u64>> + Send;

    /// Creates a hard link.
    ///
    /// With `UnixVfs`, a started link creation may commit after future drop.
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
    ///
    /// With `UnixVfs`, a started write may create, truncate, or partially
    /// update the target after future drop.
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
        self.inner.metadata().await
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
        self.inner.set_permissions(perm).await
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
#[path = "vfs_inline_tests.rs"]
mod tests;
