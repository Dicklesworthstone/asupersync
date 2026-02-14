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
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::time::{Duration, SystemTime};
    use tempfile::tempdir;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_metadata_file_basic() {
        init_test("test_metadata_file_basic");
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("file.txt");
        fs::write(&path, b"hello").expect("write");

        let meta = Metadata::from_std(fs::metadata(&path).expect("metadata"));
        crate::assert_with_log!(meta.is_file(), "is_file", true, meta.is_file());
        crate::assert_with_log!(!meta.is_dir(), "is_dir", false, meta.is_dir());
        crate::assert_with_log!(meta.len() == 5, "len", 5, meta.len());
        crate::assert_with_log!(!meta.is_empty(), "is_empty", false, meta.is_empty());

        let file_type = meta.file_type();
        crate::assert_with_log!(file_type.is_file(), "file_type", true, file_type.is_file());
        crate::assert_with_log!(
            !file_type.is_dir(),
            "file_type dir",
            false,
            file_type.is_dir()
        );
        crate::test_complete!("test_metadata_file_basic");
    }

    #[test]
    fn test_metadata_dir_basic() {
        init_test("test_metadata_dir_basic");
        let dir = tempdir().expect("tempdir");
        let meta = Metadata::from_std(fs::metadata(dir.path()).expect("metadata"));
        crate::assert_with_log!(meta.is_dir(), "is_dir", true, meta.is_dir());
        crate::assert_with_log!(!meta.is_file(), "is_file", false, meta.is_file());
        let file_type = meta.file_type();
        crate::assert_with_log!(file_type.is_dir(), "file_type", true, file_type.is_dir());
        crate::test_complete!("test_metadata_dir_basic");
    }

    #[test]
    fn test_metadata_empty_file() {
        init_test("test_metadata_empty_file");
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("empty.txt");
        fs::File::create(&path).expect("create");

        let meta = Metadata::from_std(fs::metadata(&path).expect("metadata"));
        crate::assert_with_log!(meta.is_empty(), "empty", true, meta.is_empty());

        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open");
        writeln!(file, "data").expect("write data");
        let meta = Metadata::from_std(fs::metadata(&path).expect("metadata"));
        crate::assert_with_log!(!meta.is_empty(), "not empty", false, meta.is_empty());
        crate::test_complete!("test_metadata_empty_file");
    }

    #[test]
    fn test_metadata_modified_time() {
        init_test("test_metadata_modified_time");
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("mtime.txt");
        fs::write(&path, b"time").expect("write");

        let meta = Metadata::from_std(fs::metadata(&path).expect("metadata"));
        let modified = meta.modified().expect("modified");
        let now = SystemTime::now();
        let diff = match now.duration_since(modified) {
            Ok(delta) => delta,
            Err(err) => err.duration(),
        };
        crate::assert_with_log!(
            diff <= Duration::from_mins(1),
            "modified within 60s",
            true,
            diff <= Duration::from_mins(1)
        );
        crate::test_complete!("test_metadata_modified_time");
    }

    #[test]
    fn test_permissions_readonly_roundtrip() {
        init_test("test_permissions_readonly_roundtrip");
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("perm.txt");
        fs::write(&path, b"perm").expect("write");

        let mut perms = Metadata::from_std(fs::metadata(&path).expect("metadata")).permissions();
        perms.set_readonly(true);
        fs::set_permissions(&path, perms.into_inner()).expect("set permissions");
        let readonly = Metadata::from_std(fs::metadata(&path).expect("metadata"))
            .permissions()
            .readonly();
        crate::assert_with_log!(readonly, "readonly", true, readonly);

        let mut perms = Metadata::from_std(fs::metadata(&path).expect("metadata")).permissions();
        perms.set_readonly(false);
        fs::set_permissions(&path, perms.into_inner()).expect("set permissions");
        let readonly = Metadata::from_std(fs::metadata(&path).expect("metadata"))
            .permissions()
            .readonly();
        crate::assert_with_log!(!readonly, "readonly off", false, readonly);
        crate::test_complete!("test_permissions_readonly_roundtrip");
    }

    #[cfg(unix)]
    #[test]
    fn test_metadata_symlink() {
        use std::os::unix::fs::symlink;
        init_test("test_metadata_symlink");
        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("target.txt");
        let link = dir.path().join("link.txt");
        fs::write(&target, b"link").expect("write");
        symlink(&target, &link).expect("symlink");

        let meta = Metadata::from_std(fs::symlink_metadata(&link).expect("metadata"));
        crate::assert_with_log!(meta.is_symlink(), "is_symlink", true, meta.is_symlink());
        crate::test_complete!("test_metadata_symlink");
    }
}
