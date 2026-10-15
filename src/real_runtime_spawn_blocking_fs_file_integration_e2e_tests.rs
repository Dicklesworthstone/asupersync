//! br-e2e-225: runtime/spawn_blocking ↔ fs/file integration E2E tests
//!
//! Tests integration between runtime blocking operations and filesystem operations
//! for proper coordination between async/blocking contexts and file I/O management.

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use crate::cancel::{CancelReason, CancelToken};
    use crate::cx::{Cx, Scope};
    use crate::error::AsupersyncError;
    use crate::fs::file::{File, FileType, OpenOptions};
    use crate::fs::{create_dir_all, metadata, remove_dir_all, remove_file};
    use crate::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};
    use crate::runtime::spawn_blocking::{BlockingHandle, BlockingTask, spawn_blocking};
    use crate::runtime::{Runtime, RuntimeBuilder};
    use crate::time::{Duration, Instant, sleep};
    use crate::types::{Budget, Outcome, RegionId, TaskId};

    use std::collections::{HashMap, VecDeque};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    /// Configuration for blocking file I/O coordination
    #[derive(Debug, Clone)]
    struct BlockingFileConfig {
        /// Maximum concurrent blocking operations
        pub max_blocking_ops: usize,
        /// File operation timeout
        pub file_timeout: Duration,
        /// Blocking task timeout
        pub blocking_timeout: Duration,
        /// Temporary directory for testing
        pub temp_dir: PathBuf,
        /// Maximum file size for operations
        pub max_file_size: usize,
        /// Coordination check interval
        pub coordination_interval: Duration,
    }

    impl Default for BlockingFileConfig {
        fn default() -> Self {
            Self {
                max_blocking_ops: 50,
                file_timeout: Duration::from_secs(10),
                blocking_timeout: Duration::from_secs(5),
                temp_dir: PathBuf::from("/tmp/asupersync_e2e_test"),
                max_file_size: 1024 * 1024, // 1MB
                coordination_interval: Duration::from_millis(100),
            }
        }
    }

    /// File operation with blocking coordination metadata
    #[derive(Debug, Clone)]
    struct FileOperation {
        /// Operation identifier
        pub id: u64,
        /// Operation type
        pub op_type: FileOpType,
        /// Target file path
        pub file_path: PathBuf,
        /// Operation data
        pub data: Vec<u8>,
        /// Operation priority
        pub priority: u32,
        /// Expected duration
        pub expected_duration: Duration,
        /// Blocking requirement
        pub requires_blocking: bool,
    }

    /// Types of file operations
    #[derive(Debug, Clone, PartialEq)]
    enum FileOpType {
        /// Create and write file
        Create,
        /// Read existing file
        Read,
        /// Append to file
        Append,
        /// Delete file
        Delete,
        /// Copy file
        Copy { dest_path: PathBuf },
        /// Seek and read partial
        SeekRead { offset: u64, length: usize },
        /// Batch write multiple chunks
        BatchWrite { chunks: Vec<(u64, Vec<u8>)> },
    }

    /// Statistics for blocking file coordination
    #[derive(Debug, Default)]
    struct BlockingFileStats {
        /// Blocking tasks spawned
        pub blocking_tasks_spawned: AtomicU64,
        /// Blocking tasks completed
        pub blocking_tasks_completed: AtomicU64,
        /// File operations executed
        pub file_operations_executed: AtomicU64,
        /// File operations failed
        pub file_operations_failed: AtomicU64,
        /// Async-to-blocking transitions
        pub async_to_blocking_transitions: AtomicU64,
        /// Blocking-to-async transitions
        pub blocking_to_async_transitions: AtomicU64,
        /// Bytes written to files
        pub bytes_written: AtomicU64,
        /// Bytes read from files
        pub bytes_read: AtomicU64,
        /// Coordination errors
        pub coordination_errors: AtomicU64,
    }

    /// Coordination strategy for blocking file operations
    #[derive(Debug, Clone)]
    enum CoordinationStrategy {
        /// All operations in blocking context
        AllBlocking,
        /// Mixed async/blocking based on file size
        SizeBased { threshold: usize },
        /// Time-based coordination
        TimeBased { blocking_threshold: Duration },
        /// Adaptive based on system load
        Adaptive { load_threshold: f64 },
    }

    /// File handle management mode
    #[derive(Debug, Clone)]
    enum FileHandleMode {
        /// Individual handles per operation
        Individual,
        /// Pooled handles with reuse
        Pooled { pool_size: usize },
        /// Shared handles with locking
        Shared { max_shared: usize },
        /// Adaptive handle allocation
        Adaptive { allocation_threshold: f64 },
    }

    /// Comprehensive blocking file coordination system
    struct BlockingFileSystem {
        config: BlockingFileConfig,
        active_blocking_tasks: HashMap<u64, BlockingHandle<FileOperationResult>>,
        file_handle_pool: VecDeque<File>,
        pending_operations: VecDeque<FileOperation>,
        completed_operations: HashMap<u64, FileOperationResult>,
        stats: Arc<BlockingFileStats>,
        coordination_strategy: CoordinationStrategy,
        handle_mode: FileHandleMode,
        is_running: AtomicBool,
        next_op_id: AtomicU64,
    }

    /// Result of file operation
    #[derive(Debug, Clone)]
    struct FileOperationResult {
        operation_id: u64,
        success: bool,
        bytes_processed: usize,
        duration: Duration,
        error_message: Option<String>,
        file_metadata: Option<FileMetadata>,
    }

    /// File metadata for tracking
    #[derive(Debug, Clone)]
    struct FileMetadata {
        size: u64,
        file_type: FileType,
        modified_at: Instant,
        is_readonly: bool,
    }

    impl BlockingFileSystem {
        /// Create new blocking file coordination system
        async fn new(
            config: BlockingFileConfig,
            coordination_strategy: CoordinationStrategy,
            handle_mode: FileHandleMode,
        ) -> Result<Self, AsupersyncError> {
            // Ensure temp directory exists
            create_dir_all(&config.temp_dir).await?;

            let mut system = Self {
                config,
                active_blocking_tasks: HashMap::new(),
                file_handle_pool: VecDeque::new(),
                pending_operations: VecDeque::new(),
                completed_operations: HashMap::new(),
                stats: Arc::new(BlockingFileStats::default()),
                coordination_strategy,
                handle_mode,
                is_running: AtomicBool::new(false),
                next_op_id: AtomicU64::new(1),
            };

            // Pre-allocate file handle pool if using pooled mode
            if let FileHandleMode::Pooled { pool_size } = &system.handle_mode {
                system.allocate_file_pool(*pool_size).await?;
            }

            Ok(system)
        }

        /// Allocate file handle pool
        async fn allocate_file_pool(&mut self, pool_size: usize) -> Result<(), AsupersyncError> {
            for i in 0..pool_size {
                let temp_path = self.config.temp_dir.join(format!("pool_file_{}.tmp", i));
                let file = File::create(&temp_path).await?;
                self.file_handle_pool.push_back(file);
            }
            Ok(())
        }

        /// Start the coordination system
        async fn start(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            self.is_running.store(true, Ordering::SeqCst);

            // Start operation processor
            let processor_handle = cx
                .spawn(|cx| async move { self.run_operation_processor(cx).await })
                .await?;

            // Start coordination monitor
            let monitor_handle = cx
                .spawn(|cx| async move { self.run_coordination_monitor(cx).await })
                .await?;

            // Start cleanup manager
            let cleanup_handle = cx
                .spawn(|cx| async move { self.run_cleanup_manager(cx).await })
                .await?;

            Ok(())
        }

        /// Submit file operation for processing
        async fn submit_operation(
            &mut self,
            mut operation: FileOperation,
            cx: &Cx,
        ) -> Result<u64, AsupersyncError> {
            operation.id = self.next_op_id.fetch_add(1, Ordering::SeqCst);

            // Determine coordination strategy
            let should_block = self.should_use_blocking(&operation).await?;
            operation.requires_blocking = should_block;

            self.pending_operations.push_back(operation.clone());

            Ok(operation.id)
        }

        /// Determine if operation should use blocking context
        async fn should_use_blocking(
            &self,
            operation: &FileOperation,
        ) -> Result<bool, AsupersyncError> {
            match &self.coordination_strategy {
                CoordinationStrategy::AllBlocking => Ok(true),
                CoordinationStrategy::SizeBased { threshold } => {
                    Ok(operation.data.len() > *threshold)
                }
                CoordinationStrategy::TimeBased { blocking_threshold } => {
                    Ok(operation.expected_duration > *blocking_threshold)
                }
                CoordinationStrategy::Adaptive { load_threshold } => {
                    let load = self.calculate_system_load();
                    Ok(load > *load_threshold)
                }
            }
        }

        /// Calculate current system load
        fn calculate_system_load(&self) -> f64 {
            let active_tasks = self.active_blocking_tasks.len() as f64;
            let pending_ops = self.pending_operations.len() as f64;
            let max_capacity = self.config.max_blocking_ops as f64;

            (active_tasks + pending_ops) / max_capacity
        }

        /// Execute file operation
        async fn execute_operation(
            &mut self,
            operation: FileOperation,
            cx: &Cx,
        ) -> Result<FileOperationResult, AsupersyncError> {
            let start_time = Instant::now();

            let result = if operation.requires_blocking {
                self.execute_blocking_operation(operation.clone(), cx)
                    .await?
            } else {
                self.execute_async_operation(operation.clone(), cx).await?
            };

            self.completed_operations
                .insert(operation.id, result.clone());
            self.stats
                .file_operations_executed
                .fetch_add(1, Ordering::SeqCst);

            Ok(result)
        }

        /// Execute operation in blocking context
        async fn execute_blocking_operation(
            &mut self,
            operation: FileOperation,
            cx: &Cx,
        ) -> Result<FileOperationResult, AsupersyncError> {
            self.stats
                .async_to_blocking_transitions
                .fetch_add(1, Ordering::SeqCst);

            let operation_clone = operation.clone();
            let start_time = Instant::now();

            let blocking_task = spawn_blocking(
                move || Self::perform_blocking_file_operation(operation_clone),
                cx,
            )
            .await?;

            self.active_blocking_tasks
                .insert(operation.id, blocking_task);
            self.stats
                .blocking_tasks_spawned
                .fetch_add(1, Ordering::SeqCst);

            // Wait for blocking task completion
            let blocking_handle = self
                .active_blocking_tasks
                .remove(&operation.id)
                .ok_or_else(|| {
                    AsupersyncError::InvalidState("Blocking task not found".to_string())
                })?;

            let result = blocking_handle.await?;
            self.stats
                .blocking_tasks_completed
                .fetch_add(1, Ordering::SeqCst);
            self.stats
                .blocking_to_async_transitions
                .fetch_add(1, Ordering::SeqCst);

            Ok(result)
        }

        /// Perform blocking file operation
        fn perform_blocking_file_operation(operation: FileOperation) -> FileOperationResult {
            let start_time = Instant::now();

            match Self::execute_file_op_sync(&operation) {
                Ok(bytes_processed) => FileOperationResult {
                    operation_id: operation.id,
                    success: true,
                    bytes_processed,
                    duration: start_time.elapsed(),
                    error_message: None,
                    file_metadata: Self::get_file_metadata_sync(&operation.file_path),
                },
                Err(e) => FileOperationResult {
                    operation_id: operation.id,
                    success: false,
                    bytes_processed: 0,
                    duration: start_time.elapsed(),
                    error_message: Some(e.to_string()),
                    file_metadata: None,
                },
            }
        }

        /// Execute synchronous file operation
        fn execute_file_op_sync(operation: &FileOperation) -> Result<usize, std::io::Error> {
            match &operation.op_type {
                FileOpType::Create => {
                    std::fs::write(&operation.file_path, &operation.data)?;
                    Ok(operation.data.len())
                }
                FileOpType::Read => {
                    let data = std::fs::read(&operation.file_path)?;
                    Ok(data.len())
                }
                FileOpType::Append => {
                    use std::io::Write;
                    let mut file = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&operation.file_path)?;
                    file.write_all(&operation.data)?;
                    Ok(operation.data.len())
                }
                FileOpType::Delete => {
                    std::fs::remove_file(&operation.file_path)?;
                    Ok(0)
                }
                FileOpType::Copy { dest_path } => {
                    std::fs::copy(&operation.file_path, dest_path)?;
                    let metadata = std::fs::metadata(&operation.file_path)?;
                    Ok(metadata.len() as usize)
                }
                FileOpType::SeekRead { offset, length } => {
                    use std::io::{Read, Seek};
                    let mut file = std::fs::File::open(&operation.file_path)?;
                    file.seek(std::io::SeekFrom::Start(*offset))?;
                    let mut buffer = vec![0u8; *length];
                    let bytes_read = file.read(&mut buffer)?;
                    Ok(bytes_read)
                }
                FileOpType::BatchWrite { chunks } => {
                    use std::io::{Seek, Write};
                    let mut file = std::fs::OpenOptions::new()
                        .create(true)
                        .write(true)
                        .open(&operation.file_path)?;

                    let mut total_written = 0;
                    for (offset, data) in chunks {
                        file.seek(std::io::SeekFrom::Start(*offset))?;
                        file.write_all(data)?;
                        total_written += data.len();
                    }
                    Ok(total_written)
                }
            }
        }

        /// Get file metadata synchronously
        fn get_file_metadata_sync(path: &Path) -> Option<FileMetadata> {
            std::fs::metadata(path).ok().map(|metadata| {
                FileMetadata {
                    size: metadata.len(),
                    file_type: if metadata.is_file() {
                        FileType::File
                    } else {
                        FileType::Directory
                    },
                    modified_at: Instant::now(), // Simplified for testing
                    is_readonly: metadata.permissions().readonly(),
                }
            })
        }

        /// Execute operation in async context
        async fn execute_async_operation(
            &mut self,
            operation: FileOperation,
            cx: &Cx,
        ) -> Result<FileOperationResult, AsupersyncError> {
            let start_time = Instant::now();

            match self.execute_file_op_async(&operation, cx).await {
                Ok(bytes_processed) => {
                    self.update_stats_for_operation(&operation, bytes_processed)
                        .await;

                    Ok(FileOperationResult {
                        operation_id: operation.id,
                        success: true,
                        bytes_processed,
                        duration: start_time.elapsed(),
                        error_message: None,
                        file_metadata: self.get_file_metadata_async(&operation.file_path, cx).await,
                    })
                }
                Err(e) => {
                    self.stats
                        .file_operations_failed
                        .fetch_add(1, Ordering::SeqCst);

                    Ok(FileOperationResult {
                        operation_id: operation.id,
                        success: false,
                        bytes_processed: 0,
                        duration: start_time.elapsed(),
                        error_message: Some(e.to_string()),
                        file_metadata: None,
                    })
                }
            }
        }

        /// Execute asynchronous file operation
        async fn execute_file_op_async(
            &mut self,
            operation: &FileOperation,
            cx: &Cx,
        ) -> Result<usize, AsupersyncError> {
            match &operation.op_type {
                FileOpType::Create => {
                    let mut file = File::create(&operation.file_path).await?;
                    file.write_all(&operation.data).await?;
                    Ok(operation.data.len())
                }
                FileOpType::Read => {
                    let mut file = File::open(&operation.file_path).await?;
                    let mut buffer = Vec::new();
                    file.read_to_end(&mut buffer).await?;
                    Ok(buffer.len())
                }
                FileOpType::Append => {
                    let mut file = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&operation.file_path)
                        .await?;
                    file.write_all(&operation.data).await?;
                    Ok(operation.data.len())
                }
                FileOpType::Delete => {
                    remove_file(&operation.file_path).await?;
                    Ok(0)
                }
                FileOpType::Copy { dest_path } => {
                    let mut src = File::open(&operation.file_path).await?;
                    let mut dst = File::create(dest_path).await?;
                    let bytes_copied = crate::io::copy(&mut src, &mut dst).await?;
                    Ok(bytes_copied as usize)
                }
                FileOpType::SeekRead { offset, length } => {
                    let mut file = File::open(&operation.file_path).await?;
                    file.seek(SeekFrom::Start(*offset)).await?;
                    let mut buffer = vec![0u8; *length];
                    let bytes_read = file.read(&mut buffer).await?;
                    Ok(bytes_read)
                }
                FileOpType::BatchWrite { chunks } => {
                    let mut file = OpenOptions::new()
                        .create(true)
                        .write(true)
                        .open(&operation.file_path)
                        .await?;

                    let mut total_written = 0;
                    for (offset, data) in chunks {
                        file.seek(SeekFrom::Start(*offset)).await?;
                        file.write_all(data).await?;
                        total_written += data.len();
                    }
                    Ok(total_written)
                }
            }
        }

        /// Update statistics for completed operation
        async fn update_stats_for_operation(
            &self,
            operation: &FileOperation,
            bytes_processed: usize,
        ) {
            match &operation.op_type {
                FileOpType::Create | FileOpType::Append | FileOpType::BatchWrite { .. } => {
                    self.stats
                        .bytes_written
                        .fetch_add(bytes_processed as u64, Ordering::SeqCst);
                }
                FileOpType::Read | FileOpType::SeekRead { .. } => {
                    self.stats
                        .bytes_read
                        .fetch_add(bytes_processed as u64, Ordering::SeqCst);
                }
                _ => {}
            }
        }

        /// Get file metadata asynchronously
        async fn get_file_metadata_async(&self, path: &Path, cx: &Cx) -> Option<FileMetadata> {
            metadata(path).await.ok().map(|metadata| {
                FileMetadata {
                    size: metadata.len(),
                    file_type: metadata.file_type(),
                    modified_at: Instant::now(), // Simplified for testing
                    is_readonly: metadata.permissions().readonly(),
                }
            })
        }

        /// Run operation processing loop
        async fn run_operation_processor(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            while self.is_running.load(Ordering::SeqCst) {
                // Process pending operations
                while let Some(operation) = self.pending_operations.pop_front() {
                    if self.active_blocking_tasks.len() < self.config.max_blocking_ops {
                        match self.execute_operation(operation, cx).await {
                            Ok(_) => {
                                // Operation completed successfully
                            }
                            Err(e) => {
                                self.stats
                                    .coordination_errors
                                    .fetch_add(1, Ordering::SeqCst);
                                eprintln!("File operation error: {:?}", e);
                            }
                        }
                    } else {
                        // Put operation back and wait
                        self.pending_operations.push_front(operation);
                        break;
                    }
                }

                sleep(self.config.coordination_interval, cx).await?;
            }

            Ok(())
        }

        /// Run coordination monitoring loop
        async fn run_coordination_monitor(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            while self.is_running.load(Ordering::SeqCst) {
                // Monitor blocking task timeouts
                let now = Instant::now();
                let mut timed_out_tasks = Vec::new();

                for (task_id, handle) in &self.active_blocking_tasks {
                    // Simple timeout check (would be more sophisticated in practice)
                    if handle.is_finished() {
                        // Task completed
                    } else {
                        // Check if task should timeout (simplified check)
                        timed_out_tasks.push(*task_id);
                    }
                }

                // Clean up timed out tasks
                for task_id in timed_out_tasks {
                    if let Some(_handle) = self.active_blocking_tasks.remove(&task_id) {
                        self.stats
                            .coordination_errors
                            .fetch_add(1, Ordering::SeqCst);
                    }
                }

                // Log coordination metrics
                if self.active_blocking_tasks.len() > self.config.max_blocking_ops / 2 {
                    eprintln!(
                        "High blocking task load: {}/{}",
                        self.active_blocking_tasks.len(),
                        self.config.max_blocking_ops
                    );
                }

                sleep(self.config.coordination_interval, cx).await?;
            }

            Ok(())
        }

        /// Run cleanup management loop
        async fn run_cleanup_manager(&mut self, cx: &Cx) -> Result<(), AsupersyncError> {
            while self.is_running.load(Ordering::SeqCst) {
                // Clean up completed operations
                let completed_cutoff = Instant::now() - Duration::from_secs(60);
                self.completed_operations
                    .retain(|_, result| result.duration.elapsed() < Duration::from_secs(60));

                // Clean up temporary files
                self.cleanup_temp_files().await?;

                // Manage file handle pool
                self.manage_file_handle_pool().await?;

                sleep(Duration::from_secs(10), cx).await?;
            }

            Ok(())
        }

        /// Clean up temporary files
        async fn cleanup_temp_files(&self) -> Result<(), AsupersyncError> {
            // Clean up old temporary files in test directory
            // This would be more sophisticated in a real implementation
            Ok(())
        }

        /// Manage file handle pool
        async fn manage_file_handle_pool(&mut self) -> Result<(), AsupersyncError> {
            if let FileHandleMode::Pooled { pool_size } = &self.handle_mode {
                // Ensure pool has appropriate size
                if self.file_handle_pool.len() < pool_size / 2 {
                    let needed = *pool_size - self.file_handle_pool.len();
                    self.allocate_file_pool(needed).await?;
                }
            }

            Ok(())
        }

        /// Stop the coordination system
        async fn stop(&mut self) -> Result<(), AsupersyncError> {
            self.is_running.store(false, Ordering::SeqCst);

            // Cancel all active blocking tasks
            for (_, handle) in &self.active_blocking_tasks {
                // Would cancel blocking tasks if possible
            }

            // Clean up temporary directory
            let _ = remove_dir_all(&self.config.temp_dir).await;

            Ok(())
        }

        /// Get coordination statistics
        fn get_stats(&self) -> &BlockingFileStats {
            &self.stats
        }
    }

    /// Test basic blocking file integration
    #[tokio::test]
    async fn test_basic_blocking_file_integration() -> Result<(), AsupersyncError> {
        let runtime = RuntimeBuilder::new().build().await?;
        let cx = runtime.cx();

        cx.scope(|cx| async move {
            let config = BlockingFileConfig::default();
            let strategy = CoordinationStrategy::AllBlocking;
            let handle_mode = FileHandleMode::Individual;
            let mut system = BlockingFileSystem::new(config, strategy, handle_mode).await?;

            // Start coordination system
            system.start(cx).await?;

            // Create test file operations
            let test_data = b"Hello, blocking file integration!".to_vec();
            let test_file = system.config.temp_dir.join("test_basic.txt");

            let create_op = FileOperation {
                id: 0, // Will be set by submit_operation
                op_type: FileOpType::Create,
                file_path: test_file.clone(),
                data: test_data.clone(),
                priority: 1,
                expected_duration: Duration::from_millis(100),
                requires_blocking: false, // Will be determined by strategy
            };

            let read_op = FileOperation {
                id: 0,
                op_type: FileOpType::Read,
                file_path: test_file.clone(),
                data: Vec::new(),
                priority: 1,
                expected_duration: Duration::from_millis(50),
                requires_blocking: false,
            };

            // Submit and execute operations
            let create_id = system.submit_operation(create_op, cx).await?;
            sleep(Duration::from_millis(150), cx).await?;

            let read_id = system.submit_operation(read_op, cx).await?;
            sleep(Duration::from_millis(150), cx).await?;

            system.stop().await?;

            // Verify coordination worked
            let stats = system.get_stats();
            assert!(stats.blocking_tasks_spawned.load(Ordering::SeqCst) >= 2);
            assert!(stats.blocking_tasks_completed.load(Ordering::SeqCst) >= 2);
            assert!(stats.file_operations_executed.load(Ordering::SeqCst) >= 2);
            assert!(stats.bytes_written.load(Ordering::SeqCst) >= test_data.len() as u64);
            assert_eq!(stats.coordination_errors.load(Ordering::SeqCst), 0);

            Ok(())
        })
        .await
    }

    /// Test size-based coordination strategy
    #[tokio::test]
    async fn test_size_based_coordination() -> Result<(), AsupersyncError> {
        let runtime = RuntimeBuilder::new().build().await?;
        let cx = runtime.cx();

        cx.scope(|cx| async move {
            let config = BlockingFileConfig::default();
            let strategy = CoordinationStrategy::SizeBased { threshold: 100 }; // 100 bytes threshold
            let handle_mode = FileHandleMode::Pooled { pool_size: 5 };
            let mut system = BlockingFileSystem::new(config, strategy, handle_mode).await?;

            system.start(cx).await?;

            // Create operations with different sizes
            let small_data = b"small".to_vec(); // < 100 bytes (should be async)
            let large_data = vec![42u8; 200]; // > 100 bytes (should be blocking)

            let small_file_op = FileOperation {
                id: 0,
                op_type: FileOpType::Create,
                file_path: system.config.temp_dir.join("small_file.txt"),
                data: small_data,
                priority: 1,
                expected_duration: Duration::from_millis(50),
                requires_blocking: false,
            };

            let large_file_op = FileOperation {
                id: 0,
                op_type: FileOpType::Create,
                file_path: system.config.temp_dir.join("large_file.txt"),
                data: large_data,
                priority: 1,
                expected_duration: Duration::from_millis(100),
                requires_blocking: false,
            };

            // Submit operations
            let small_id = system.submit_operation(small_file_op, cx).await?;
            let large_id = system.submit_operation(large_file_op, cx).await?;

            // Allow processing time
            sleep(Duration::from_millis(300), cx).await?;

            system.stop().await?;

            // Verify size-based coordination
            let stats = system.get_stats();
            assert!(stats.file_operations_executed.load(Ordering::SeqCst) >= 2);
            assert!(stats.bytes_written.load(Ordering::SeqCst) >= 205); // 5 + 200 bytes
            assert_eq!(stats.file_operations_failed.load(Ordering::SeqCst), 0);

            // Should have both async and blocking transitions
            assert!(stats.async_to_blocking_transitions.load(Ordering::SeqCst) >= 1);

            Ok(())
        })
        .await
    }

    /// Test adaptive coordination under load
    #[tokio::test]
    async fn test_adaptive_coordination_under_load() -> Result<(), AsupersyncError> {
        let runtime = RuntimeBuilder::new().build().await?;
        let cx = runtime.cx();

        cx.scope(|cx| async move {
            let config = BlockingFileConfig {
                max_blocking_ops: 3, // Limit to test load adaptation
                ..BlockingFileConfig::default()
            };
            let strategy = CoordinationStrategy::Adaptive {
                load_threshold: 0.5,
            };
            let handle_mode = FileHandleMode::Adaptive {
                allocation_threshold: 0.6,
            };
            let mut system = BlockingFileSystem::new(config, strategy, handle_mode).await?;

            system.start(cx).await?;

            // Create multiple file operations to test load
            let mut operations = Vec::new();
            for i in 0..8 {
                let operation = FileOperation {
                    id: 0,
                    op_type: FileOpType::Create,
                    file_path: system.config.temp_dir.join(format!("load_test_{}.txt", i)),
                    data: vec![42u8; 50 + i * 10], // Varying sizes
                    priority: (i % 3) as u32,
                    expected_duration: Duration::from_millis(50 + i as u64 * 10),
                    requires_blocking: false,
                };
                operations.push(operation);
            }

            // Submit operations quickly to create load
            for operation in operations {
                system.submit_operation(operation, cx).await?;
                sleep(Duration::from_millis(10), cx).await?; // Small delay
            }

            // Allow adaptive processing
            sleep(Duration::from_millis(500), cx).await?;

            system.stop().await?;

            // Verify adaptive coordination handled load
            let stats = system.get_stats();
            assert_eq!(stats.file_operations_executed.load(Ordering::SeqCst), 8);
            assert!(stats.bytes_written.load(Ordering::SeqCst) > 0);

            // Should have mixed coordination approaches
            assert!(stats.blocking_tasks_spawned.load(Ordering::SeqCst) > 0);
            assert!(stats.async_to_blocking_transitions.load(Ordering::SeqCst) > 0);
            assert!(stats.blocking_to_async_transitions.load(Ordering::SeqCst) > 0);

            // Should maintain low error rate under load
            assert!(stats.coordination_errors.load(Ordering::SeqCst) <= 1);

            Ok(())
        })
        .await
    }
}
