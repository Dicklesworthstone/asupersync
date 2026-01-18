//! Async directory creation and removal.
//!
//! Phase 0 uses synchronous std::fs calls under async wrappers.

use std::io;
use std::path::Path;

/// Creates a new empty directory at the specified path.
///
/// # Cancel Safety
///
/// This operation is cancel-safe: it either completes or does not create the
/// directory at all.
pub async fn create_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
    std::fs::create_dir(path.as_ref())
}

/// Recursively creates a directory and all of its parent components.
///
/// # Cancel Safety
///
/// This operation is cancel-safe: the filesystem operation is atomic with
/// respect to cancellation in Phase 0.
pub async fn create_dir_all<P: AsRef<Path>>(path: P) -> io::Result<()> {
    std::fs::create_dir_all(path.as_ref())
}

/// Removes an empty directory.
///
/// # Cancel Safety
///
/// This operation is cancel-safe: it either removes the directory or fails.
pub async fn remove_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
    std::fs::remove_dir(path.as_ref())
}

/// Recursively removes a directory and all of its contents.
///
/// # Cancel Safety
///
/// This operation is **not** cancel-safe; cancellation may leave partial state.
pub async fn remove_dir_all<P: AsRef<Path>>(path: P) -> io::Result<()> {
    std::fs::remove_dir_all(path.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut path = std::env::temp_dir();
        path.push(format!("asupersync_test_{name}_{id}"));
        path
    }

    #[test]
    fn test_create_dir() {
        let path = unique_temp_dir("create_dir");
        let result = futures_lite::future::block_on(async { create_dir(&path).await });
        assert!(result.is_ok());
        assert!(path.exists());
        assert!(path.is_dir());

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_create_dir_all() {
        let base = unique_temp_dir("create_dir_all");
        let path = base.join("a/b/c");

        let result = futures_lite::future::block_on(async { create_dir_all(&path).await });
        assert!(result.is_ok());
        assert!(path.exists());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_remove_dir() {
        let path = unique_temp_dir("remove_dir");
        std::fs::create_dir_all(&path).unwrap();
        assert!(path.exists());

        let result = futures_lite::future::block_on(async { remove_dir(&path).await });
        assert!(result.is_ok());
        assert!(!path.exists());
    }

    #[test]
    fn test_remove_dir_all() {
        let path = unique_temp_dir("remove_dir_all");
        std::fs::create_dir_all(path.join("a/b/c")).unwrap();
        std::fs::write(path.join("a/file.txt"), b"content").unwrap();
        std::fs::write(path.join("a/b/file.txt"), b"content").unwrap();

        let result = futures_lite::future::block_on(async { remove_dir_all(&path).await });
        assert!(result.is_ok());
        assert!(!path.exists());
    }
}
