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

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
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
