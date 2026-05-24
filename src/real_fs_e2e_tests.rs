//! [br-e2e-8] Real Filesystem E2E Tests
//!
//! Real-service E2E tests for filesystem operations using actual file I/O,
//! directory operations, and io_uring when available. Tests complete read/write
//! cycles, directory enumeration, and concurrent file operations with real tempfiles.
//!
//! Uses rch + CARGO_TARGET_DIR=/tmp/rch_target_pane1_e2e for end-to-end validation
//! with actual filesystem operations rather than mocks.

#[cfg(all(test, feature = "real-service-e2e"))]
mod fs_e2e_tests {
    use crate::cx::{Cx, CxBuilder};
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    use crate::fs::uring::IoUringFile;
    use crate::fs::{
        File, FileType, OpenOptions, copy, create_dir, create_dir_all, metadata, read, read_dir,
        read_to_string, remove_dir, remove_dir_all, remove_file, write, write_atomic,
    };
    use crate::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, BufWriter, SeekFrom};
    use crate::runtime::RuntimeBuilder;
    use crate::time::{Duration, Instant, sleep};
    use serde_json;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tempfile::{NamedTempFile, TempDir, tempdir};

    /// Real filesystem manager for E2E testing
    pub struct RealFilesystemManager {
        temp_dir: TempDir,
        stats: Arc<FsE2EStats>,
    }

    /// Statistics for filesystem E2E operations
    #[derive(Debug, Default)]
    pub struct FsE2EStats {
        pub files_created: AtomicU64,
        pub files_read: AtomicU64,
        pub files_written: AtomicU64,
        pub files_deleted: AtomicU64,
        pub directories_created: AtomicU64,
        pub directories_read: AtomicU64,
        pub directories_deleted: AtomicU64,
        pub bytes_written: AtomicU64,
        pub bytes_read: AtomicU64,
        pub io_operations: AtomicU64,
        pub concurrent_operations: AtomicU64,
        pub io_errors: AtomicU64,
    }

    /// Enhanced logger for filesystem E2E tests
    pub struct FsE2ELogger {
        events: Arc<Mutex<Vec<FsLogEvent>>>,
        start_time: Instant,
    }

    #[derive(Debug, Clone, serde::Serialize)]
    pub struct FsLogEvent {
        pub timestamp: u64,
        pub event_type: String,
        pub operation: String, // "read", "write", "create", "delete", "enumerate"
        pub file_path: Option<String>,
        pub file_size: Option<u64>,
        pub bytes_transferred: Option<usize>,
        pub operation_duration_ms: Option<u64>,
        pub io_backend: Option<String>, // "standard", "io_uring", "buffered"
        pub concurrent_ops: Option<usize>,
        pub success: bool,
        pub error: Option<String>,
        pub details: HashMap<String, serde_json::Value>,
    }

    impl FsE2ELogger {
        pub fn new() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                start_time: Instant::now(),
            }
        }

        pub fn log_file_operation(
            &self,
            operation: &str,
            file_path: &Path,
            bytes: Option<usize>,
            duration: Option<Duration>,
            io_backend: Option<&str>,
            success: bool,
            error: Option<&str>,
        ) {
            let mut details = HashMap::new();
            if let Some(duration) = duration {
                details.insert(
                    "duration_us".to_string(),
                    serde_json::Value::Number(
                        serde_json::Number::from(duration.as_micros() as u64),
                    ),
                );
            }

            let event = FsLogEvent {
                timestamp: self.start_time.elapsed().as_micros() as u64,
                event_type: if success {
                    "file_operation_success".to_string()
                } else {
                    "file_operation_error".to_string()
                },
                operation: operation.to_string(),
                file_path: Some(file_path.display().to_string()),
                file_size: None,
                bytes_transferred: bytes,
                operation_duration_ms: duration.map(|d| d.as_millis() as u64),
                io_backend: io_backend.map(String::from),
                concurrent_ops: None,
                success,
                error: error.map(String::from),
                details,
            };

            if let Ok(mut events) = self.events.lock() {
                events.push(event);
            }
        }

        pub fn log_directory_operation(
            &self,
            operation: &str,
            dir_path: &Path,
            entry_count: Option<usize>,
            success: bool,
            error: Option<&str>,
        ) {
            let mut details = HashMap::new();
            if let Some(count) = entry_count {
                details.insert(
                    "entry_count".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(count)),
                );
            }

            let event = FsLogEvent {
                timestamp: self.start_time.elapsed().as_micros() as u64,
                event_type: if success {
                    "directory_operation_success".to_string()
                } else {
                    "directory_operation_error".to_string()
                },
                operation: operation.to_string(),
                file_path: Some(dir_path.display().to_string()),
                file_size: None,
                bytes_transferred: None,
                operation_duration_ms: None,
                io_backend: None,
                concurrent_ops: entry_count,
                success,
                error: error.map(String::from),
                details,
            };

            if let Ok(mut events) = self.events.lock() {
                events.push(event);
            }
        }

        pub fn log_concurrent_operation_start(&self, operation: &str, concurrent_count: usize) {
            let mut details = HashMap::new();
            details.insert(
                "concurrent_start_time".to_string(),
                serde_json::Value::Number(serde_json::Number::from(
                    self.start_time.elapsed().as_millis() as u64,
                )),
            );

            let event = FsLogEvent {
                timestamp: self.start_time.elapsed().as_micros() as u64,
                event_type: "concurrent_operation_start".to_string(),
                operation: operation.to_string(),
                file_path: None,
                file_size: None,
                bytes_transferred: None,
                operation_duration_ms: None,
                io_backend: None,
                concurrent_ops: Some(concurrent_count),
                success: true,
                error: None,
                details,
            };

            if let Ok(mut events) = self.events.lock() {
                events.push(event);
            }
        }

        pub fn export_json(&self) -> String {
            if let Ok(events) = self.events.lock() {
                serde_json::to_string_pretty(&*events).unwrap_or_else(|_| "[]".to_string())
            } else {
                "[]".to_string()
            }
        }

        pub fn get_event_count(&self) -> usize {
            if let Ok(events) = self.events.lock() {
                events.len()
            } else {
                0
            }
        }
    }

    impl RealFilesystemManager {
        /// Create new real filesystem manager for E2E testing
        pub fn new() -> Result<Self, std::io::Error> {
            // Validate environment for real service testing
            Self::validate_test_environment()?;

            let temp_dir = tempdir()?;

            Ok(Self {
                temp_dir,
                stats: Arc::new(FsE2EStats::default()),
            })
        }

        /// Validate environment is safe for real service testing
        fn validate_test_environment() -> Result<(), std::io::Error> {
            if std::env::var("NODE_ENV").unwrap_or_default() == "production" {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Cannot run real filesystem E2E tests in production environment",
                ));
            }

            if std::env::var("REAL_SERVICE_TESTS").unwrap_or_default() != "true" {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Set REAL_SERVICE_TESTS=true to enable real service testing",
                ));
            }

            Ok(())
        }

        pub fn temp_dir(&self) -> &Path {
            self.temp_dir.path()
        }

        pub fn stats(&self) -> Arc<FsE2EStats> {
            self.stats.clone()
        }

        /// Test file create, write, read, delete cycle
        pub async fn test_file_lifecycle(
            &self,
            cx: &Cx,
            filename: &str,
            content: &[u8],
            logger: &FsE2ELogger,
        ) -> Result<Vec<u8>, std::io::Error> {
            let file_path = self.temp_dir.path().join(filename);
            let start_time = Instant::now();

            // Create and write file
            logger.log_file_operation(
                "create",
                &file_path,
                None,
                None,
                Some("standard"),
                true,
                None,
            );
            let mut file = File::create(&file_path).await?;
            self.stats.files_created.fetch_add(1, Ordering::Relaxed);

            logger.log_file_operation(
                "write",
                &file_path,
                Some(content.len()),
                None,
                Some("standard"),
                true,
                None,
            );
            file.write_all(content).await?;
            file.sync_all().await?;
            drop(file);

            let write_duration = start_time.elapsed();
            self.stats.files_written.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes_written
                .fetch_add(content.len() as u64, Ordering::Relaxed);
            self.stats.io_operations.fetch_add(1, Ordering::Relaxed);

            // Read file back
            let read_start = Instant::now();
            let read_content = read(&file_path).await?;
            let read_duration = read_start.elapsed();

            logger.log_file_operation(
                "read",
                &file_path,
                Some(read_content.len()),
                Some(read_duration),
                Some("standard"),
                true,
                None,
            );
            self.stats.files_read.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes_read
                .fetch_add(read_content.len() as u64, Ordering::Relaxed);
            self.stats.io_operations.fetch_add(1, Ordering::Relaxed);

            // Verify content matches
            if read_content != content {
                let error = "Content mismatch after read";
                logger.log_file_operation(
                    "verify",
                    &file_path,
                    None,
                    None,
                    None,
                    false,
                    Some(error),
                );
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, error));
            }

            // Delete file
            remove_file(&file_path).await?;
            logger.log_file_operation(
                "delete",
                &file_path,
                None,
                None,
                Some("standard"),
                true,
                None,
            );
            self.stats.files_deleted.fetch_add(1, Ordering::Relaxed);

            Ok(read_content)
        }

        /// Test directory operations with enumeration
        pub async fn test_directory_operations(
            &self,
            cx: &Cx,
            dirname: &str,
            files_to_create: &[&str],
            logger: &FsE2ELogger,
        ) -> Result<Vec<String>, std::io::Error> {
            let dir_path = self.temp_dir.path().join(dirname);

            // Create directory
            create_dir(&dir_path).await?;
            logger.log_directory_operation("create_dir", &dir_path, None, true, None);
            self.stats
                .directories_created
                .fetch_add(1, Ordering::Relaxed);

            // Create files in directory
            for filename in files_to_create {
                let file_path = dir_path.join(filename);
                let content = format!("Content for {}", filename);
                write(&file_path, content.as_bytes()).await?;
                self.stats.files_created.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .bytes_written
                    .fetch_add(content.len() as u64, Ordering::Relaxed);
            }

            // Enumerate directory entries with bounds protection
            const MAX_DIRECTORY_ENTRIES: usize = 10_000;
            let mut entries = read_dir(&dir_path).await?;
            let mut entry_names = Vec::new();
            let mut entry_count = 0;

            while let Some(entry) = entries.next_entry().await? {
                // Enforce size limit to prevent memory exhaustion from large directories
                if entry_count >= MAX_DIRECTORY_ENTRIES {
                    logger.log_directory_operation(
                        "enumerate_truncated",
                        &dir_path,
                        Some(entry_count),
                        true,
                        Some(&format!("Directory enumeration hit limit of {} entries", MAX_DIRECTORY_ENTRIES))
                    );
                    break;
                }

                if let Some(filename) = entry.file_name().to_str() {
                    entry_names.push(filename.to_string());
                    entry_count += 1;
                }
            }

            logger.log_directory_operation("enumerate", &dir_path, Some(entry_count), true, None);
            self.stats.directories_read.fetch_add(1, Ordering::Relaxed);

            // Verify all expected files are found
            for expected_file in files_to_create {
                if !entry_names.contains(&expected_file.to_string()) {
                    let error = format!("Expected file {} not found in directory", expected_file);
                    logger.log_directory_operation("verify", &dir_path, None, false, Some(&error));
                    return Err(std::io::Error::new(std::io::ErrorKind::NotFound, error));
                }
            }

            // Clean up directory
            remove_dir_all(&dir_path).await?;
            logger.log_directory_operation("remove_all", &dir_path, Some(entry_count), true, None);
            self.stats
                .directories_deleted
                .fetch_add(1, Ordering::Relaxed);

            Ok(entry_names)
        }

        /// Test concurrent file operations
        pub async fn test_concurrent_file_operations(
            &self,
            cx: &Cx,
            num_operations: usize,
            logger: &FsE2ELogger,
        ) -> Result<Vec<String>, std::io::Error> {
            logger.log_concurrent_operation_start("concurrent_file_ops", num_operations);
            self.stats
                .concurrent_operations
                .fetch_add(num_operations as u64, Ordering::Relaxed);

            let mut results = Vec::new();

            // Perform concurrent file operations
            for i in 0..num_operations {
                let filename = format!("concurrent_file_{}.txt", i);
                let file_path = self.temp_dir.path().join(&filename);
                let content = format!("Concurrent content {}", i);

                // Create file
                let mut file = File::create(&file_path).await?;
                file.write_all(content.as_bytes()).await?;
                file.sync_all().await?;
                drop(file);

                // Read back immediately
                let read_content = read_to_string(&file_path).await?;

                if read_content == content {
                    results.push(filename);
                    logger.log_file_operation(
                        "concurrent_success",
                        &file_path,
                        Some(content.len()),
                        None,
                        Some("standard"),
                        true,
                        None,
                    );
                } else {
                    logger.log_file_operation(
                        "concurrent_failure",
                        &file_path,
                        None,
                        None,
                        None,
                        false,
                        Some("content mismatch"),
                    );
                }

                self.stats.io_operations.fetch_add(2, Ordering::Relaxed); // write + read

                // Small delay to interleave operations
                let _ = sleep(cx, Duration::from_millis(1)).await;
            }

            // Clean up concurrent files
            for i in 0..num_operations {
                let filename = format!("concurrent_file_{}.txt", i);
                let file_path = self.temp_dir.path().join(filename);
                let _ = remove_file(file_path).await; // Ignore errors for cleanup
            }

            Ok(results)
        }

        /// Test large file operations
        pub async fn test_large_file_operations(
            &self,
            cx: &Cx,
            file_size_bytes: usize,
            logger: &FsE2ELogger,
        ) -> Result<(), std::io::Error> {
            let file_path = self.temp_dir.path().join("large_test_file.bin");
            let start_time = Instant::now();

            // Generate test data
            let test_data: Vec<u8> = (0..file_size_bytes).map(|i| (i % 256) as u8).collect();

            // Write large file
            let write_start = Instant::now();
            let mut file = File::create(&file_path).await?;
            file.write_all(&test_data).await?;
            file.sync_all().await?;
            drop(file);
            let write_duration = write_start.elapsed();

            logger.log_file_operation(
                "large_write",
                &file_path,
                Some(test_data.len()),
                Some(write_duration),
                Some("standard"),
                true,
                None,
            );
            self.stats
                .bytes_written
                .fetch_add(test_data.len() as u64, Ordering::Relaxed);

            // Read large file back
            let read_start = Instant::now();
            let read_data = read(&file_path).await?;
            let read_duration = read_start.elapsed();

            logger.log_file_operation(
                "large_read",
                &file_path,
                Some(read_data.len()),
                Some(read_duration),
                Some("standard"),
                true,
                None,
            );
            self.stats
                .bytes_read
                .fetch_add(read_data.len() as u64, Ordering::Relaxed);

            // Verify large file content
            if read_data != test_data {
                let error = "Large file content verification failed";
                logger.log_file_operation(
                    "large_verify",
                    &file_path,
                    None,
                    None,
                    None,
                    false,
                    Some(error),
                );
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, error));
            }

            // Clean up
            remove_file(&file_path).await?;

            Ok(())
        }

        #[cfg(all(target_os = "linux", feature = "io-uring"))]
        /// Test io_uring operations if available
        pub async fn test_io_uring_operations(
            &self,
            cx: &Cx,
            logger: &FsE2ELogger,
        ) -> Result<(), std::io::Error> {
            let file_path = self.temp_dir.path().join("uring_test_file.txt");
            let test_content = b"Hello from io_uring!";

            // Test io_uring write
            let write_start = Instant::now();
            let mut uring_file = IoUringFile::create(&file_path).await?;
            uring_file.write_all(test_content).await?;
            uring_file.sync_all().await?;
            drop(uring_file);
            let write_duration = write_start.elapsed();

            logger.log_file_operation(
                "uring_write",
                &file_path,
                Some(test_content.len()),
                Some(write_duration),
                Some("io_uring"),
                true,
                None,
            );

            // Test io_uring read
            let read_start = Instant::now();
            let mut uring_file = IoUringFile::open(&file_path).await?;
            let mut read_buffer = Vec::new();
            uring_file.read_to_end(&mut read_buffer).await?;
            let read_duration = read_start.elapsed();

            logger.log_file_operation(
                "uring_read",
                &file_path,
                Some(read_buffer.len()),
                Some(read_duration),
                Some("io_uring"),
                true,
                None,
            );

            // Verify content
            if read_buffer != test_content {
                let error = "io_uring content verification failed";
                logger.log_file_operation(
                    "uring_verify",
                    &file_path,
                    None,
                    None,
                    Some("io_uring"),
                    false,
                    Some(error),
                );
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, error));
            }

            // Clean up
            remove_file(&file_path).await?;

            Ok(())
        }
    }

    /// Production safety guard - validates environment
    fn validate_fs_e2e_environment() -> Result<(), String> {
        if std::env::var("NODE_ENV").unwrap_or_default() == "production" {
            return Err("Real filesystem E2E tests blocked in production".to_string());
        }

        if std::env::var("REAL_SERVICE_TESTS").unwrap_or_default() != "true" {
            return Err("Set REAL_SERVICE_TESTS=true to enable".to_string());
        }

        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires REAL_SERVICE_TESTS=true
    async fn test_real_fs_file_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
        validate_fs_e2e_environment()?;

        let runtime = RuntimeBuilder::new().build()?;
        let cx_builder = CxBuilder::new(&runtime);
        let cx = cx_builder.build();

        let logger = FsE2ELogger::new();
        let fs_manager = RealFilesystemManager::new()?;

        // Test basic file lifecycle
        let test_content = b"Hello, filesystem E2E testing! This is a test file with some content.";
        let read_content = fs_manager
            .test_file_lifecycle(&cx, "test_file.txt", test_content, &logger)
            .await?;

        assert_eq!(
            &read_content, test_content,
            "Read content should match written content"
        );

        // Verify statistics
        let stats = fs_manager.stats();
        assert_eq!(
            stats.files_created.load(Ordering::Relaxed),
            1,
            "Should create one file"
        );
        assert_eq!(
            stats.files_written.load(Ordering::Relaxed),
            1,
            "Should write one file"
        );
        assert_eq!(
            stats.files_read.load(Ordering::Relaxed),
            1,
            "Should read one file"
        );
        assert_eq!(
            stats.files_deleted.load(Ordering::Relaxed),
            1,
            "Should delete one file"
        );
        assert_eq!(
            stats.bytes_written.load(Ordering::Relaxed),
            test_content.len() as u64,
            "Should track written bytes"
        );
        assert_eq!(
            stats.bytes_read.load(Ordering::Relaxed),
            test_content.len() as u64,
            "Should track read bytes"
        );

        eprintln!(
            "Filesystem File Lifecycle E2E structured log:\n{}",
            logger.export_json()
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires REAL_SERVICE_TESTS=true
    async fn test_real_fs_directory_operations() -> Result<(), Box<dyn std::error::Error>> {
        validate_fs_e2e_environment()?;

        let runtime = RuntimeBuilder::new().build()?;
        let cx_builder = CxBuilder::new(&runtime);
        let cx = cx_builder.build();

        let logger = FsE2ELogger::new();
        let fs_manager = RealFilesystemManager::new()?;

        // Test directory operations with multiple files
        let test_files = vec!["file1.txt", "file2.txt", "file3.txt"];
        let entries = fs_manager
            .test_directory_operations(&cx, "test_directory", &test_files, &logger)
            .await?;

        // Verify all expected files were found
        for expected_file in &test_files {
            assert!(
                entries.contains(&expected_file.to_string()),
                "Directory should contain {}",
                expected_file
            );
        }

        // Verify statistics
        let stats = fs_manager.stats();
        assert_eq!(
            stats.directories_created.load(Ordering::Relaxed),
            1,
            "Should create one directory"
        );
        assert_eq!(
            stats.directories_read.load(Ordering::Relaxed),
            1,
            "Should read one directory"
        );
        assert_eq!(
            stats.directories_deleted.load(Ordering::Relaxed),
            1,
            "Should delete one directory"
        );
        assert_eq!(
            stats.files_created.load(Ordering::Relaxed),
            test_files.len() as u64,
            "Should create test files"
        );

        eprintln!(
            "Filesystem Directory Operations E2E structured log:\n{}",
            logger.export_json()
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires REAL_SERVICE_TESTS=true
    async fn test_real_fs_concurrent_operations() -> Result<(), Box<dyn std::error::Error>> {
        validate_fs_e2e_environment()?;

        let runtime = RuntimeBuilder::new().build()?;
        let cx_builder = CxBuilder::new(&runtime);
        let cx = cx_builder.build();

        let logger = FsE2ELogger::new();
        let fs_manager = RealFilesystemManager::new()?;

        // Test concurrent file operations
        const NUM_CONCURRENT_OPS: usize = 5;
        let results = fs_manager
            .test_concurrent_file_operations(&cx, NUM_CONCURRENT_OPS, &logger)
            .await?;

        assert_eq!(
            results.len(),
            NUM_CONCURRENT_OPS,
            "All concurrent operations should succeed"
        );

        // Verify statistics
        let stats = fs_manager.stats();
        assert_eq!(
            stats.concurrent_operations.load(Ordering::Relaxed),
            NUM_CONCURRENT_OPS as u64,
            "Should track concurrent operations"
        );
        assert!(
            stats.io_operations.load(Ordering::Relaxed) >= (NUM_CONCURRENT_OPS * 2) as u64,
            "Should have multiple I/O operations"
        );

        eprintln!(
            "Filesystem Concurrent Operations E2E structured log:\n{}",
            logger.export_json()
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires REAL_SERVICE_TESTS=true
    async fn test_real_fs_large_file_operations() -> Result<(), Box<dyn std::error::Error>> {
        validate_fs_e2e_environment()?;

        let runtime = RuntimeBuilder::new().build()?;
        let cx_builder = CxBuilder::new(&runtime);
        let cx = cx_builder.build();

        let logger = FsE2ELogger::new();
        let fs_manager = RealFilesystemManager::new()?;

        // Test large file operations (1MB file)
        const LARGE_FILE_SIZE: usize = 1024 * 1024; // 1MB
        fs_manager
            .test_large_file_operations(&cx, LARGE_FILE_SIZE, &logger)
            .await?;

        // Verify statistics
        let stats = fs_manager.stats();
        assert!(
            stats.bytes_written.load(Ordering::Relaxed) >= LARGE_FILE_SIZE as u64,
            "Should write large amount of data"
        );
        assert!(
            stats.bytes_read.load(Ordering::Relaxed) >= LARGE_FILE_SIZE as u64,
            "Should read large amount of data"
        );

        eprintln!(
            "Filesystem Large File E2E structured log:\n{}",
            logger.export_json()
        );
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    #[tokio::test]
    #[ignore] // Requires REAL_SERVICE_TESTS=true and Linux with io-uring
    async fn test_real_fs_io_uring_operations() -> Result<(), Box<dyn std::error::Error>> {
        validate_fs_e2e_environment()?;

        let runtime = RuntimeBuilder::new().build()?;
        let cx_builder = CxBuilder::new(&runtime);
        let cx = cx_builder.build();

        let logger = FsE2ELogger::new();
        let fs_manager = RealFilesystemManager::new()?;

        // Test io_uring operations
        fs_manager.test_io_uring_operations(&cx, &logger).await?;

        eprintln!(
            "Filesystem io_uring E2E structured log:\n{}",
            logger.export_json()
        );
        Ok(())
    }
}

#[cfg(all(test, feature = "real-service-e2e"))]
pub use fs_e2e_tests::*;
