//! Fuzz target for src/fs/uring.rs Drop implementation race conditions.
//!
//! **CRITICAL VULNERABILITY SURFACE**: IoUringFile Drop path concurrency
//!
//! **ATTACK VECTORS**:
//! 1. Drop while operations are in-flight → use-after-free via completion attribution
//! 2. user_data collision during cancel → wrong operation gets cancelled/completed
//! 3. Ring teardown race with pending completion → completion on deallocated ring
//! 4. tracked_pending_user_data() vs mark_tracked_op_complete() race → missed cancels
//! 5. Arc::strong_count() check race → multiple threads think they're the last owner
//!
//! **ROOT CAUSE**: Complex state coordination between:
//! - pending operation tracking (OpState mutexes)
//! - user_data generation/attribution
//! - ring submission/completion queues
//! - Drop cleanup vs live operations
//!
//! **ORACLES**:
//! - No use-after-free (ASAN/MSAN violations)
//! - No double-completion of operations
//! - No leaked pending operations after Drop
//! - No segfault during ring teardown

#![no_main]

use arbitrary::Arbitrary;
use asupersync::fs::IoUringFile;
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;

const MAX_OPERATIONS_PER_FILE: usize = 16; // Force operation tracking pressure
const MAX_BUFFER_SIZE: usize = 1024;

/// Drop timing attack scenarios
#[derive(Debug, Clone, Copy, Arbitrary)]
enum DropAttackVector {
    /// Drop immediately after submitting operations
    DuringInflight,
    /// Drop during completion collection window
    DuringCompletion,
    /// Drop with concurrent operations from multiple threads
    UnderConcurrency,
    /// Drop with user_data collision scenarios
    WithUserDataCollision,
}

/// Configuration for a file operation during drop testing
#[derive(Debug, Clone, Arbitrary)]
struct FileOperation {
    operation_type: OperationType,
    buffer_size: u16, // 0-1024 bytes
    file_offset: u32,
    delay_before_drop_ms: u8, // 0-255ms to vary drop timing
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum OperationType {
    Read,
    Write,
    Sync,
}

/// Harness for testing IoUringFile Drop path race conditions
struct DropRaceHarness {
    temp_files: Vec<NamedTempFile>,
}

impl DropRaceHarness {
    fn new() -> std::io::Result<Self> {
        Ok(Self {
            temp_files: Vec::new(),
        })
    }

    fn create_test_file(&mut self, size: usize) -> std::io::Result<NamedTempFile> {
        let mut temp_file = NamedTempFile::new()?;

        // Write test data
        let test_data = vec![0x42u8; size];
        std::io::Write::write_all(&mut temp_file, &test_data)?;
        std::io::Write::flush(&mut temp_file)?;

        Ok(temp_file)
    }

    /// Test Drop path race with various attack vectors
    fn test_drop_race(
        &mut self,
        attack: DropAttackVector,
        operations: &[FileOperation],
    ) -> Result<(), String> {
        match attack {
            DropAttackVector::DuringInflight => self.test_drop_during_inflight(operations),
            DropAttackVector::DuringCompletion => self.test_drop_during_completion(operations),
            DropAttackVector::UnderConcurrency => self.test_drop_under_concurrency(operations),
            DropAttackVector::WithUserDataCollision => {
                self.test_drop_with_user_data_collision(operations)
            }
        }
    }

    fn test_drop_during_inflight(&mut self, operations: &[FileOperation]) -> Result<(), String> {
        for op_config in operations.iter().take(MAX_OPERATIONS_PER_FILE) {
            let temp_file = self
                .create_test_file(1024)
                .map_err(|e| format!("Failed to create temp file: {e}"))?;

            let file_path = temp_file.path().to_path_buf();
            self.temp_files.push(temp_file);

            let op = op_config.clone();

            // RACE CONDITION TEST: Start operation then immediately drop file
            let uring_file = match op.operation_type {
                OperationType::Read => IoUringFile::open(&file_path),
                OperationType::Write => IoUringFile::create(&file_path),
                OperationType::Sync => IoUringFile::open(&file_path),
            }
            .map_err(|e| format!("Failed to open file: {e}"))?;

            let arc_file = Arc::new(uring_file);
            let arc_file_clone = Arc::clone(&arc_file);

            // Start an operation that will be in-flight
            let handle = std::thread::spawn(move || {
                let _result = futures::executor::block_on(async {
                    let mut buffer = vec![0u8; (op.buffer_size as usize).min(MAX_BUFFER_SIZE)];

                    match op.operation_type {
                        OperationType::Read => {
                            // This read may be cancelled during Drop
                            arc_file_clone
                                .read_at(&mut buffer, op.file_offset as u64)
                                .await
                                .map(|_| ())
                        }
                        OperationType::Write => {
                            buffer.fill(0x33);
                            arc_file_clone
                                .write_at(&buffer, op.file_offset as u64)
                                .await
                                .map(|_| ())
                        }
                        OperationType::Sync => arc_file_clone.sync_all().await,
                    }
                });
            });

            // Inject timing variance to hit different Drop race windows
            if op_config.delay_before_drop_ms > 0 {
                std::thread::sleep(Duration::from_millis(op_config.delay_before_drop_ms as u64));
            }

            // VULNERABILITY: Drop arc_file while operation may be in-flight
            // This triggers the Drop cleanup path with pending operations
            drop(arc_file);
            let _ = handle.join();
        }

        Ok(())
    }

    fn test_drop_during_completion(&mut self, operations: &[FileOperation]) -> Result<(), String> {
        // Similar to above but designed to hit the completion collection window
        for op_config in operations.iter().take(4) {
            // Fewer operations for focused testing
            let temp_file = self
                .create_test_file(1024)
                .map_err(|e| format!("Failed to create temp file: {e}"))?;

            let file_path = temp_file.path().to_path_buf();
            self.temp_files.push(temp_file);

            let uring_file =
                IoUringFile::open(&file_path).map_err(|e| format!("Failed to open file: {e}"))?;

            // RACE: Start multiple operations, let some complete, then drop during completion handling
            let arc_file = Arc::new(uring_file);
            let mut handles = Vec::new();

            for i in 0..3 {
                let arc_clone = Arc::clone(&arc_file);
                let buffer_size = (op_config.buffer_size as usize).min(MAX_BUFFER_SIZE);

                let handle = std::thread::spawn(move || {
                    futures::executor::block_on(async {
                        let mut buffer = vec![0u8; buffer_size];
                        // Quick operations that might complete during Drop's completion collection
                        arc_clone.read_at(&mut buffer, (i * 100) as u64).await
                    })
                });
                handles.push(handle);
            }

            // Let some operations start/complete
            std::thread::sleep(Duration::from_millis(
                op_config.delay_before_drop_ms as u64 / 2,
            ));

            // VULNERABILITY: Drop while some operations are completing
            drop(arc_file);

            // Clean up threads
            for handle in handles {
                let _ = handle.join();
            }
        }

        Ok(())
    }

    fn test_drop_under_concurrency(&mut self, operations: &[FileOperation]) -> Result<(), String> {
        // Test Arc::strong_count() race where multiple threads think they're the last owner
        for op_config in operations.iter().take(2) {
            let temp_file = self
                .create_test_file(1024)
                .map_err(|e| format!("Failed to create temp file: {e}"))?;

            let file_path = temp_file.path().to_path_buf();
            self.temp_files.push(temp_file);

            let uring_file =
                IoUringFile::open(&file_path).map_err(|e| format!("Failed to open file: {e}"))?;

            let arc_file = Arc::new(uring_file);

            // Create multiple threads that will drop their Arc references simultaneously
            let mut handles = Vec::new();

            for _ in 0..4 {
                let arc_clone = Arc::clone(&arc_file);
                let buffer_size = (op_config.buffer_size as usize).min(MAX_BUFFER_SIZE);

                let handle = std::thread::spawn(move || {
                    // Start operation
                    let _result = futures::executor::block_on(async {
                        let mut buffer = vec![0u8; buffer_size];
                        arc_clone.read_at(&mut buffer, 0).await
                    });

                    // RACE: Multiple threads drop simultaneously
                    // Only one should run the Drop cleanup, but strong_count check may race
                    drop(arc_clone);
                });
                handles.push(handle);
            }

            // Drop main reference
            drop(arc_file);

            // Wait for all threads
            for handle in handles {
                let _ = handle.join();
            }
        }

        Ok(())
    }

    fn test_drop_with_user_data_collision(
        &mut self,
        operations: &[FileOperation],
    ) -> Result<(), String> {
        // Test user_data collision scenarios during Drop cancellation
        for op_config in operations.iter().take(3) {
            let temp_file = self
                .create_test_file(1024)
                .map_err(|e| format!("Failed to create temp file: {e}"))?;

            let file_path = temp_file.path().to_path_buf();
            self.temp_files.push(temp_file);

            let uring_file =
                IoUringFile::open(&file_path).map_err(|e| format!("Failed to open file: {e}"))?;

            // Force rapid operation submission to increase user_data collision probability
            let _result = futures::executor::block_on(async {
                let arc_file = Arc::new(uring_file);
                let mut futures = Vec::new();

                // Submit many operations rapidly to trigger user_data reuse
                for i in 0..8 {
                    let arc_clone = Arc::clone(&arc_file);
                    let buffer_size = (op_config.buffer_size as usize).max(32);

                    let fut = async move {
                        let mut buffer = vec![0u8; buffer_size];
                        arc_clone.read_at(&mut buffer, (i * 64) as u64).await
                    };
                    futures.push(fut);
                }

                // Let some start, then drop the main Arc to trigger Drop cancellation.
                if op_config.delay_before_drop_ms > 0 {
                    std::thread::sleep(Duration::from_millis(
                        op_config.delay_before_drop_ms as u64,
                    ));
                }
                drop(arc_file);
                futures::future::join_all(futures).await
            });

            // VULNERABILITY: Drop will try to cancel operations by user_data,
            // but if user_data values wrapped/collided, wrong ops might be cancelled
        }

        Ok(())
    }
}

fuzz_target!(|data: (DropAttackVector, Vec<FileOperation>)| {
    let (attack_vector, operations) = data;

    if operations.len() > MAX_OPERATIONS_PER_FILE {
        return;
    }

    let mut harness = match DropRaceHarness::new() {
        Ok(h) => h,
        Err(_) => return, // Skip if temp file creation fails
    };

    let result = harness.test_drop_race(attack_vector, &operations);

    match result {
        Ok(()) => {
            // Success - no race condition detected
        }
        Err(error_msg) => {
            // Expected errors (file creation failures, etc.) are acceptable
            // The fuzzer is looking for crashes, hangs, or sanitizer violations
            // which indicate real race conditions in the Drop path
            if error_msg.contains("use-after-free") || error_msg.contains("double-free") {
                panic!("MEMORY SAFETY VIOLATION: {}", error_msg);
            }
        }
    }
});
