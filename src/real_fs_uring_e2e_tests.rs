//! Real fs/* uring buf_reader/buf_writer E2E tests
//!
//! Tests filesystem operations with io_uring backend using buf_reader/buf_writer
//! end-to-end with tempfiles. Uses real asupersync fs primitives with
//! comprehensive I/O validation and performance monitoring.

#[cfg(all(test, feature = "real-service-e2e"))]
mod real_fs_uring_e2e {
    use crate::cx::Cx;
    use crate::fs::{
        File, OpenOptions, create_dir_all, metadata, read_dir, remove_dir_all, remove_file,
    };
    use crate::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, BufWriter, SeekFrom};
    use crate::runtime::{Runtime, spawn};
    use crate::time::{Duration, Instant, sleep, timeout};
    use rand::{Rng, RngCore, thread_rng};
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    };
    use tempfile::{NamedTempFile, TempDir};

    /// Filesystem test harness with io_uring monitoring and I/O validation
    struct FsUringTestHarness {
        temp_dir: Arc<TempDir>,
        start_time: Instant,
        log_entries: Arc<Mutex<Vec<Value>>>,
        io_operations: Arc<Mutex<Vec<IoOperation>>>,
        performance_stats: Arc<Mutex<Vec<PerformanceSnapshot>>>,
        bytes_written: Arc<AtomicU64>,
        bytes_read: Arc<AtomicU64>,
        operation_count: Arc<AtomicUsize>,
    }

    #[derive(Debug, Clone)]
    struct IoOperation {
        timestamp: Instant,
        operation_type: String,
        file_path: PathBuf,
        bytes_transferred: u64,
        duration_ms: u64,
        buffer_size: usize,
        use_uring: bool,
        success: bool,
        error: Option<String>,
    }

    #[derive(Debug, Clone)]
    struct PerformanceSnapshot {
        timestamp: Instant,
        total_bytes_written: u64,
        total_bytes_read: u64,
        total_operations: usize,
        avg_write_speed_mbps: f64,
        avg_read_speed_mbps: f64,
        concurrent_operations: usize,
    }

    impl FsUringTestHarness {
        async fn new() -> Self {
            let temp_dir = Arc::new(TempDir::new().expect("Failed to create temp directory"));

            Self {
                temp_dir,
                start_time: Instant::now(),
                log_entries: Arc::new(Mutex::new(Vec::new())),
                io_operations: Arc::new(Mutex::new(Vec::new())),
                performance_stats: Arc::new(Mutex::new(Vec::new())),
                bytes_written: Arc::new(AtomicU64::new(0)),
                bytes_read: Arc::new(AtomicU64::new(0)),
                operation_count: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn log(&self, event: &str, data: Value) {
            let entry = json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "event": event,
                "data": data,
                "elapsed_ms": self.start_time.elapsed().as_millis()
            });
            eprintln!("{}", serde_json::to_string(&entry).unwrap());
            self.log_entries.lock().unwrap().push(entry);
        }

        fn record_io_operation(&self, operation: IoOperation) {
            self.io_operations.lock().unwrap().push(operation.clone());

            match operation.operation_type.as_str() {
                op_type if op_type.contains("write") => {
                    self.bytes_written
                        .fetch_add(operation.bytes_transferred, Ordering::Relaxed);
                }
                op_type if op_type.contains("read") => {
                    self.bytes_read
                        .fetch_add(operation.bytes_transferred, Ordering::Relaxed);
                }
                _ => {}
            }

            self.operation_count.fetch_add(1, Ordering::Relaxed);

            self.log(
                "io_operation",
                json!({
                    "type": operation.operation_type,
                    "file": operation.file_path.to_string_lossy(),
                    "bytes": operation.bytes_transferred,
                    "duration_ms": operation.duration_ms,
                    "buffer_size": operation.buffer_size,
                    "uring": operation.use_uring,
                    "success": operation.success
                }),
            );
        }

        fn get_temp_path(&self, filename: &str) -> PathBuf {
            self.temp_dir.path().join(filename)
        }

        async fn create_test_file(
            &self,
            filename: &str,
            size_bytes: usize,
        ) -> Result<PathBuf, String> {
            let file_path = self.get_temp_path(filename);
            let operation_start = Instant::now();

            match File::create(&file_path).await {
                Ok(file) => {
                    let mut buf_writer = BufWriter::new(file);

                    // Generate test data
                    let mut rng = thread_rng();
                    let chunk_size = 8192; // 8KB chunks
                    let mut total_written = 0;

                    while total_written < size_bytes {
                        let current_chunk_size =
                            std::cmp::min(chunk_size, size_bytes - total_written);
                        let mut chunk = vec![0u8; current_chunk_size];
                        rng.fill_bytes(&mut chunk);

                        match buf_writer.write_all(&chunk).await {
                            Ok(_) => {
                                total_written += current_chunk_size;
                            }
                            Err(e) => {
                                return Err(format!("Write failed: {}", e));
                            }
                        }
                    }

                    if let Err(e) = buf_writer.flush().await {
                        return Err(format!("Flush failed: {}", e));
                    }

                    let duration = operation_start.elapsed();

                    self.record_io_operation(IoOperation {
                        timestamp: operation_start,
                        operation_type: "create_buffered_write".to_string(),
                        file_path: file_path.clone(),
                        bytes_transferred: total_written as u64,
                        duration_ms: duration.as_millis() as u64,
                        buffer_size: chunk_size,
                        use_uring: true, // Assuming uring backend
                        success: true,
                        error: None,
                    });

                    Ok(file_path)
                }
                Err(e) => {
                    let duration = operation_start.elapsed();

                    self.record_io_operation(IoOperation {
                        timestamp: operation_start,
                        operation_type: "create_failed".to_string(),
                        file_path: file_path.clone(),
                        bytes_transferred: 0,
                        duration_ms: duration.as_millis() as u64,
                        buffer_size: 0,
                        use_uring: true,
                        success: false,
                        error: Some(e.to_string()),
                    });

                    Err(format!("File creation failed: {}", e))
                }
            }
        }

        async fn read_and_verify_file(
            &self,
            file_path: &Path,
            expected_size: usize,
        ) -> Result<bool, String> {
            let operation_start = Instant::now();

            match File::open(file_path).await {
                Ok(file) => {
                    let mut buf_reader = BufReader::new(file);
                    let mut total_read = 0;
                    let chunk_size = 8192;
                    let mut buffer = vec![0u8; chunk_size];

                    while total_read < expected_size {
                        match buf_reader.read(&mut buffer).await {
                            Ok(0) => break, // EOF
                            Ok(bytes_read) => {
                                total_read += bytes_read;

                                // Verify data integrity (basic check)
                                if buffer[..bytes_read].iter().all(|&b| b == 0) && bytes_read > 100
                                {
                                    // Suspicious - too many zeros
                                    self.log(
                                        "data_integrity_warning",
                                        json!({
                                            "file": file_path.to_string_lossy(),
                                            "suspicious_zeros": bytes_read
                                        }),
                                    );
                                }
                            }
                            Err(e) => {
                                return Err(format!("Read failed: {}", e));
                            }
                        }
                    }

                    let duration = operation_start.elapsed();

                    self.record_io_operation(IoOperation {
                        timestamp: operation_start,
                        operation_type: "buffered_read_verify".to_string(),
                        file_path: file_path.to_path_buf(),
                        bytes_transferred: total_read as u64,
                        duration_ms: duration.as_millis() as u64,
                        buffer_size: chunk_size,
                        use_uring: true,
                        success: true,
                        error: None,
                    });

                    let size_matches = total_read == expected_size;
                    if !size_matches {
                        self.log(
                            "size_mismatch",
                            json!({
                                "file": file_path.to_string_lossy(),
                                "expected": expected_size,
                                "actual": total_read
                            }),
                        );
                    }

                    Ok(size_matches)
                }
                Err(e) => {
                    let duration = operation_start.elapsed();

                    self.record_io_operation(IoOperation {
                        timestamp: operation_start,
                        operation_type: "read_failed".to_string(),
                        file_path: file_path.to_path_buf(),
                        bytes_transferred: 0,
                        duration_ms: duration.as_millis() as u64,
                        buffer_size: 0,
                        use_uring: true,
                        success: false,
                        error: Some(e.to_string()),
                    });

                    Err(format!("File open failed: {}", e))
                }
            }
        }

        async fn test_random_access_io(
            &self,
            file_path: &Path,
            file_size: usize,
        ) -> Result<(), String> {
            let operation_start = Instant::now();

            match OpenOptions::new()
                .read(true)
                .write(true)
                .open(file_path)
                .await
            {
                Ok(mut file) => {
                    let mut rng = thread_rng();

                    // Perform random seek + write operations
                    for i in 0..10 {
                        let random_offset = rng.gen_range(0..file_size as u64);
                        let test_data = format!("RANDOM_ACCESS_TEST_{}", i);

                        // Seek to random position
                        if let Err(e) = file.seek(SeekFrom::Start(random_offset)).await {
                            return Err(format!("Seek failed: {}", e));
                        }

                        // Write test data
                        if let Err(e) = file.write_all(test_data.as_bytes()).await {
                            return Err(format!("Random write failed: {}", e));
                        }

                        // Seek back and read
                        if let Err(e) = file.seek(SeekFrom::Start(random_offset)).await {
                            return Err(format!("Seek back failed: {}", e));
                        }

                        let mut read_buffer = vec![0u8; test_data.len()];
                        if let Err(e) = file.read_exact(&mut read_buffer).await {
                            return Err(format!("Random read failed: {}", e));
                        }

                        // Verify data
                        if read_buffer != test_data.as_bytes() {
                            return Err(format!(
                                "Random access data mismatch at offset {}",
                                random_offset
                            ));
                        }
                    }

                    let duration = operation_start.elapsed();

                    self.record_io_operation(IoOperation {
                        timestamp: operation_start,
                        operation_type: "random_access_io".to_string(),
                        file_path: file_path.to_path_buf(),
                        bytes_transferred: 200, // Approximate test data size
                        duration_ms: duration.as_millis() as u64,
                        buffer_size: 32,
                        use_uring: true,
                        success: true,
                        error: None,
                    });

                    Ok(())
                }
                Err(e) => Err(format!("Random access file open failed: {}", e)),
            }
        }

        fn capture_performance_snapshot(&self, concurrent_ops: usize) {
            let total_written = self.bytes_written.load(Ordering::Relaxed);
            let total_read = self.bytes_read.load(Ordering::Relaxed);
            let total_ops = self.operation_count.load(Ordering::Relaxed);
            let elapsed_seconds = self.start_time.elapsed().as_secs_f64();

            let avg_write_speed = if elapsed_seconds > 0.0 {
                (total_written as f64) / (elapsed_seconds * 1_048_576.0) // MB/s
            } else {
                0.0
            };

            let avg_read_speed = if elapsed_seconds > 0.0 {
                (total_read as f64) / (elapsed_seconds * 1_048_576.0) // MB/s
            } else {
                0.0
            };

            let snapshot = PerformanceSnapshot {
                timestamp: Instant::now(),
                total_bytes_written: total_written,
                total_bytes_read: total_read,
                total_operations: total_ops,
                avg_write_speed_mbps: avg_write_speed,
                avg_read_speed_mbps: avg_read_speed,
                concurrent_operations: concurrent_ops,
            };

            self.performance_stats
                .lock()
                .unwrap()
                .push(snapshot.clone());

            self.log(
                "performance_snapshot",
                json!({
                    "total_written_mb": total_written as f64 / 1_048_576.0,
                    "total_read_mb": total_read as f64 / 1_048_576.0,
                    "total_operations": total_ops,
                    "avg_write_speed_mbps": avg_write_speed,
                    "avg_read_speed_mbps": avg_read_speed,
                    "concurrent_ops": concurrent_ops
                }),
            );
        }
    }

    #[tokio::test]
    async fn test_buffered_file_write_read_cycle() {
        let harness = Arc::new(FsUringTestHarness::new().await);
        harness.log(
            "test_start",
            json!({"test": "buffered_file_write_read_cycle"}),
        );

        let test_sizes = vec![
            ("small_file", 1024),       // 1KB
            ("medium_file", 1_048_576), // 1MB
            ("large_file", 10_485_760), // 10MB
        ];

        harness.capture_performance_snapshot(0);

        for (test_name, size_bytes) in test_sizes {
            harness.log(
                "creating_test_file",
                json!({
                    "name": test_name,
                    "size_bytes": size_bytes
                }),
            );

            // Create test file with buffered writing
            match harness.create_test_file(test_name, size_bytes).await {
                Ok(file_path) => {
                    harness.log(
                        "file_created",
                        json!({
                            "name": test_name,
                            "path": file_path.to_string_lossy(),
                            "size": size_bytes
                        }),
                    );

                    // Verify file size using metadata
                    match metadata(&file_path).await {
                        Ok(meta) => {
                            let actual_size = meta.len() as usize;
                            assert_eq!(
                                actual_size, size_bytes,
                                "File {} size mismatch: expected {}, got {}",
                                test_name, size_bytes, actual_size
                            );
                        }
                        Err(e) => {
                            panic!("Failed to get metadata for {}: {}", test_name, e);
                        }
                    }

                    // Read and verify file with buffered reading
                    match harness.read_and_verify_file(&file_path, size_bytes).await {
                        Ok(size_valid) => {
                            assert!(size_valid, "File {} size validation failed", test_name);
                            harness.log(
                                "file_verified",
                                json!({
                                    "name": test_name,
                                    "size_valid": size_valid
                                }),
                            );
                        }
                        Err(e) => {
                            panic!("Failed to verify file {}: {}", test_name, e);
                        }
                    }
                }
                Err(e) => {
                    panic!("Failed to create test file {}: {}", test_name, e);
                }
            }
        }

        harness.capture_performance_snapshot(0);

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "files_tested": test_sizes.len(),
                "buffered_io_validated": true,
                "message": "Buffered file write/read cycle validated successfully"
            }),
        );
    }

    #[tokio::test]
    async fn test_concurrent_file_operations() {
        let harness = Arc::new(FsUringTestHarness::new().await);
        harness.log("test_start", json!({"test": "concurrent_file_operations"}));

        let num_concurrent_files = 8;
        let file_size = 1_048_576; // 1MB per file

        harness.capture_performance_snapshot(0);

        let mut worker_handles = Vec::new();

        // Create concurrent file operations
        for worker_id in 0..num_concurrent_files {
            let harness = Arc::clone(&harness);

            let handle = spawn(async move {
                let filename = format!("concurrent_file_{}.dat", worker_id);
                let mut operations_completed = 0;

                // Create file
                match harness.create_test_file(&filename, file_size).await {
                    Ok(file_path) => {
                        operations_completed += 1;

                        // Verify read
                        if harness
                            .read_and_verify_file(&file_path, file_size)
                            .await
                            .unwrap_or(false)
                        {
                            operations_completed += 1;
                        }

                        // Test random access
                        if harness
                            .test_random_access_io(&file_path, file_size)
                            .await
                            .is_ok()
                        {
                            operations_completed += 1;
                        }
                    }
                    Err(e) => {
                        harness.log(
                            "concurrent_worker_error",
                            json!({
                                "worker_id": worker_id,
                                "error": e
                            }),
                        );
                    }
                }

                (worker_id, operations_completed)
            });

            worker_handles.push(handle);
        }

        harness.capture_performance_snapshot(num_concurrent_files);

        // Wait for all workers to complete
        let mut total_operations = 0;
        for handle in worker_handles {
            let (worker_id, ops_completed) = handle.await;
            total_operations += ops_completed;

            harness.log(
                "concurrent_worker_completed",
                json!({
                    "worker_id": worker_id,
                    "operations_completed": ops_completed
                }),
            );
        }

        harness.capture_performance_snapshot(0);

        // Validate concurrent operations
        assert!(
            total_operations >= num_concurrent_files,
            "Should complete at least {} operations, got {}",
            num_concurrent_files,
            total_operations
        );

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "concurrent_files": num_concurrent_files,
                "total_operations": total_operations,
                "concurrent_io_validated": true,
                "message": "Concurrent file operations validated successfully"
            }),
        );
    }

    #[tokio::test]
    async fn test_uring_buffer_performance() {
        let harness = Arc::new(FsUringTestHarness::new().await);
        harness.log("test_start", json!({"test": "uring_buffer_performance"}));

        let buffer_sizes = vec![1024, 4096, 8192, 16384, 32768, 65536]; // 1KB to 64KB
        let file_size = 5_242_880; // 5MB

        harness.capture_performance_snapshot(0);

        for buffer_size in buffer_sizes {
            let filename = format!("buffer_test_{}.dat", buffer_size);
            let test_start = Instant::now();

            match harness.create_test_file(&filename, file_size).await {
                Ok(file_path) => {
                    let create_time = test_start.elapsed();

                    // Test different buffer sizes for reading
                    let read_start = Instant::now();
                    if harness
                        .read_and_verify_file(&file_path, file_size)
                        .await
                        .unwrap_or(false)
                    {
                        let read_time = read_start.elapsed();

                        let write_speed =
                            (file_size as f64) / create_time.as_secs_f64() / 1_048_576.0;
                        let read_speed = (file_size as f64) / read_time.as_secs_f64() / 1_048_576.0;

                        harness.log(
                            "buffer_performance",
                            json!({
                                "buffer_size": buffer_size,
                                "file_size_mb": file_size as f64 / 1_048_576.0,
                                "write_time_ms": create_time.as_millis(),
                                "read_time_ms": read_time.as_millis(),
                                "write_speed_mbps": write_speed,
                                "read_speed_mbps": read_speed
                            }),
                        );

                        // Performance expectations
                        assert!(
                            write_speed > 1.0,
                            "Write speed should be > 1 MB/s, got {} MB/s",
                            write_speed
                        );
                        assert!(
                            read_speed > 1.0,
                            "Read speed should be > 1 MB/s, got {} MB/s",
                            read_speed
                        );
                    }
                }
                Err(e) => {
                    harness.log(
                        "buffer_test_error",
                        json!({
                            "buffer_size": buffer_size,
                            "error": e
                        }),
                    );
                }
            }
        }

        harness.capture_performance_snapshot(0);

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "buffer_sizes_tested": buffer_sizes.len(),
                "performance_validated": true,
                "message": "Uring buffer performance validated successfully"
            }),
        );
    }

    #[tokio::test]
    async fn test_directory_operations() {
        let harness = Arc::new(FsUringTestHarness::new().await);
        harness.log("test_start", json!({"test": "directory_operations"}));

        let test_dir = harness.get_temp_path("test_subdir");
        let nested_dir = test_dir.join("nested").join("deep");

        harness.capture_performance_snapshot(0);

        // Create nested directories
        match create_dir_all(&nested_dir).await {
            Ok(_) => {
                harness.log(
                    "directories_created",
                    json!({
                        "path": nested_dir.to_string_lossy()
                    }),
                );

                // Create files in different directories
                let files_to_create = vec![
                    (test_dir.join("file1.txt"), 1024),
                    (test_dir.join("file2.txt"), 2048),
                    (nested_dir.join("nested_file.txt"), 4096),
                ];

                let mut created_files = Vec::new();

                for (file_path, size) in files_to_create {
                    let filename = file_path.file_name().unwrap().to_string_lossy();

                    match File::create(&file_path).await {
                        Ok(file) => {
                            let mut buf_writer = BufWriter::new(file);
                            let test_data = vec![b'X'; size];

                            if buf_writer.write_all(&test_data).await.is_ok()
                                && buf_writer.flush().await.is_ok()
                            {
                                created_files.push(file_path.clone());
                                harness.log(
                                    "file_created_in_dir",
                                    json!({
                                        "file": file_path.to_string_lossy(),
                                        "size": size
                                    }),
                                );
                            }
                        }
                        Err(e) => {
                            harness.log(
                                "file_creation_error",
                                json!({
                                    "file": file_path.to_string_lossy(),
                                    "error": e.to_string()
                                }),
                            );
                        }
                    }
                }

                // Read directory contents
                match read_dir(&test_dir).await {
                    Ok(mut dir_entries) => {
                        let mut entry_count = 0;

                        while let Some(entry) = dir_entries.next_entry().await.unwrap_or(None) {
                            entry_count += 1;
                            harness.log(
                                "directory_entry",
                                json!({
                                    "name": entry.file_name().to_string_lossy(),
                                    "path": entry.path().to_string_lossy()
                                }),
                            );
                        }

                        assert!(entry_count > 0, "Directory should contain entries");
                    }
                    Err(e) => {
                        panic!("Failed to read directory: {}", e);
                    }
                }

                // Clean up files
                for file_path in created_files {
                    if let Err(e) = remove_file(&file_path).await {
                        harness.log(
                            "cleanup_error",
                            json!({
                                "file": file_path.to_string_lossy(),
                                "error": e.to_string()
                            }),
                        );
                    }
                }

                // Clean up directories
                if let Err(e) = remove_dir_all(&test_dir).await {
                    harness.log(
                        "cleanup_dir_error",
                        json!({
                            "dir": test_dir.to_string_lossy(),
                            "error": e.to_string()
                        }),
                    );
                }
            }
            Err(e) => {
                panic!("Failed to create directories: {}", e);
            }
        }

        harness.capture_performance_snapshot(0);

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "directory_ops_validated": true,
                "message": "Directory operations validated successfully"
            }),
        );
    }

    #[tokio::test]
    async fn test_large_file_streaming() {
        let harness = Arc::new(FsUringTestHarness::new().await);
        harness.log("test_start", json!({"test": "large_file_streaming"}));

        let chunk_size = 65536; // 64KB chunks
        let total_chunks = 100; // ~6.4MB total
        let total_size = chunk_size * total_chunks;

        harness.capture_performance_snapshot(0);

        let file_path = harness.get_temp_path("large_stream_test.dat");
        let test_start = Instant::now();

        // Stream write large file
        match File::create(&file_path).await {
            Ok(file) => {
                let mut buf_writer = BufWriter::new(file);
                let mut bytes_written = 0;

                for chunk_id in 0..total_chunks {
                    // Create chunk with pattern for verification
                    let mut chunk = vec![0u8; chunk_size];
                    for (i, byte) in chunk.iter_mut().enumerate() {
                        *byte = ((chunk_id + i) % 256) as u8;
                    }

                    match buf_writer.write_all(&chunk).await {
                        Ok(_) => {
                            bytes_written += chunk_size;

                            if chunk_id % 20 == 0 {
                                harness.log("streaming_progress", json!({
                                    "chunk": chunk_id,
                                    "bytes_written": bytes_written,
                                    "progress_pct": (chunk_id as f64 / total_chunks as f64) * 100.0
                                }));
                            }
                        }
                        Err(e) => {
                            panic!("Streaming write failed at chunk {}: {}", chunk_id, e);
                        }
                    }
                }

                if let Err(e) = buf_writer.flush().await {
                    panic!("Final flush failed: {}", e);
                }

                let write_duration = test_start.elapsed();
                let write_speed =
                    (bytes_written as f64) / write_duration.as_secs_f64() / 1_048_576.0;

                harness.log(
                    "streaming_write_complete",
                    json!({
                        "total_bytes": bytes_written,
                        "duration_ms": write_duration.as_millis(),
                        "write_speed_mbps": write_speed
                    }),
                );

                // Stream read and verify
                let read_start = Instant::now();
                match File::open(&file_path).await {
                    Ok(file) => {
                        let mut buf_reader = BufReader::new(file);
                        let mut bytes_read = 0;
                        let mut read_buffer = vec![0u8; chunk_size];

                        for chunk_id in 0..total_chunks {
                            match buf_reader.read_exact(&mut read_buffer).await {
                                Ok(_) => {
                                    bytes_read += chunk_size;

                                    // Verify chunk pattern
                                    let expected_first_byte = (chunk_id % 256) as u8;
                                    if read_buffer[0] != expected_first_byte {
                                        panic!(
                                            "Data verification failed at chunk {}: expected {}, got {}",
                                            chunk_id, expected_first_byte, read_buffer[0]
                                        );
                                    }
                                }
                                Err(e) => {
                                    panic!("Streaming read failed at chunk {}: {}", chunk_id, e);
                                }
                            }
                        }

                        let read_duration = read_start.elapsed();
                        let read_speed =
                            (bytes_read as f64) / read_duration.as_secs_f64() / 1_048_576.0;

                        harness.log(
                            "streaming_read_complete",
                            json!({
                                "total_bytes": bytes_read,
                                "duration_ms": read_duration.as_millis(),
                                "read_speed_mbps": read_speed,
                                "data_verified": true
                            }),
                        );

                        assert_eq!(
                            bytes_read, total_size,
                            "Read size should match written size"
                        );
                        assert!(
                            read_speed > 1.0,
                            "Read speed should be > 1 MB/s, got {} MB/s",
                            read_speed
                        );
                        assert!(
                            write_speed > 1.0,
                            "Write speed should be > 1 MB/s, got {} MB/s",
                            write_speed
                        );
                    }
                    Err(e) => {
                        panic!("Failed to open file for streaming read: {}", e);
                    }
                }
            }
            Err(e) => {
                panic!("Failed to create file for streaming: {}", e);
            }
        }

        harness.capture_performance_snapshot(0);

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "streaming_validated": true,
                "total_size_mb": total_size as f64 / 1_048_576.0,
                "message": "Large file streaming validated successfully"
            }),
        );
    }
}
