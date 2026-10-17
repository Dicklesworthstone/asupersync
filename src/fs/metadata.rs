//! Metadata and permission wrappers for filesystem operations.
//!
//! These types mirror the `std::fs` equivalents but keep the public API
//! consistent across async interfaces.

use std::io;
use std::time::SystemTime;

/// File metadata (mirrors `std::fs::Metadata`).
#[derive(Debug, Clone)]
pub struct Metadata {
    pub(crate) inner: std::fs::Metadata,
}

impl Metadata {
    /// Wraps a `std::fs::Metadata`.
    pub(crate) fn from_std(inner: std::fs::Metadata) -> Self {
        Self { inner }
    }

    /// Returns the file type.
    #[must_use]
    pub fn file_type(&self) -> FileType {
        FileType {
            inner: self.inner.file_type(),
        }
    }

    /// Returns true if this metadata is for a directory.
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.inner.is_dir()
    }

    /// Returns true if this metadata is for a regular file.
    #[must_use]
    pub fn is_file(&self) -> bool {
        self.inner.is_file()
    }

    /// Returns true if this metadata is for a symlink.
    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.inner.is_symlink()
    }

    /// Returns the length of the file, in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.inner.len()
    }

    /// Returns true if the file is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the file permissions.
    #[must_use]
    pub fn permissions(&self) -> Permissions {
        Permissions {
            inner: self.inner.permissions(),
        }
    }

    /// Returns the last modification time.
    pub fn modified(&self) -> io::Result<SystemTime> {
        self.inner.modified()
    }

    /// Returns the last access time.
    pub fn accessed(&self) -> io::Result<SystemTime> {
        self.inner.accessed()
    }

    /// Returns the creation time.
    pub fn created(&self) -> io::Result<SystemTime> {
        self.inner.created()
    }
}

/// File type wrapper.
#[derive(Debug, Clone)]
pub struct FileType {
    inner: std::fs::FileType,
}

impl FileType {
    /// Wraps a `std::fs::FileType`.
    pub(crate) fn from_std(inner: std::fs::FileType) -> Self {
        Self { inner }
    }

    /// Returns true if this file type is a directory.
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.inner.is_dir()
    }

    /// Returns true if this file type is a regular file.
    #[must_use]
    pub fn is_file(&self) -> bool {
        self.inner.is_file()
    }

    /// Returns true if this file type is a symlink.
    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.inner.is_symlink()
    }
}

/// File permissions wrapper.
#[derive(Debug, Clone)]
pub struct Permissions {
    pub(crate) inner: std::fs::Permissions,
}

impl Permissions {
    /// Construct a `Permissions` from raw Unix mode bits (e.g. `0o644`).
    /// Mirrors `std::os::unix::fs::PermissionsExt::from_mode`. Unix-only.
    #[cfg(unix)]
    #[must_use]
    pub fn from_mode(mode: u32) -> Self {
        use std::os::unix::fs::PermissionsExt;
        Self {
            inner: std::fs::Permissions::from_mode(mode),
        }
    }

    /// Returns true if this file is read-only.
    #[must_use]
    pub fn readonly(&self) -> bool {
        self.inner.readonly()
    }

    /// Sets the read-only flag.
    pub fn set_readonly(&mut self, readonly: bool) {
        self.inner.set_readonly(readonly);
    }

    /// Returns the raw mode bits (Unix only).
    #[cfg(unix)]
    #[must_use]
    pub fn mode(&self) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        self.inner.mode()
    }

    /// Sets the raw mode bits (Unix only).
    #[cfg(unix)]
    pub fn set_mode(&mut self, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        self.inner.set_mode(mode);
    }

    /// Extracts the inner permissions for OS calls.
    pub(crate) fn into_inner(self) -> std::fs::Permissions {
        self.inner
    }
}

#[cfg(test)]
#[path = "metadata_inline_tests.rs"]
mod tests;
