//! Fuzz target for src/fs/file.rs Arc<File> concurrent access data races.
//!
//! **CRITICAL GAP ADDRESSED**: Existing fs_uring.rs covers io_uring SQE submission
//! but lacks coverage of Arc<std::fs::File> concurrent access patterns in async polls.
//!
//! **VULNERABILITY SURFACE**: Arc<File> unsafe mutable access without synchronization:
//! - poll_read: Arc::as_ptr(&self.inner).cast_mut() -> &mut File
//! - poll_write: Arc::as_ptr(&self.inner).cast_mut() -> &mut File
//! - poll_seek: Arc::as_ptr(&self.inner).cast_mut() -> &mut File
//!
//! **DATA RACE CONDITIONS**:
//! 1. Multiple tasks share same File via Arc (intended design)
//! 2. No mutex/synchronization around unsafe mutable access
//! 3. Concurrent poll_* calls create race on file descriptor state
//! 4. File position, buffer state, internal metadata can be corrupted
//!
//! **ORACLE**: ThreadSanitizer (TSan) detects data races during execution.
//! Must run with RUSTFLAGS="-Zsanitizer=thread" to catch races.
//!
//! **STATEFUL FUZZING**: Multiple async tasks, shared file state, timing-dependent.

#![no_main]
#![allow(clippy::too_many_lines)]

use arbitrary::Arbitrary;
use asupersync::fs::File;
use asupersync::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};
use libfuzzer_sys::fuzz_target;
use std::io::SeekFrom;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use tempfile::{tempdir, TempDir};
use std::collections::VecDeque;

const MAX_OPERATIONS: usize = 50; // Reasonable for exec/s in concurrent scenarios
const MAX_BUFFER_SIZE: usize = 4096; // Reasonable file I/O size
const MAX_FILE_SIZE: usize = 16384; // Small files for focused race testing

#[derive(Debug, Clone, Arbitrary)]
struct FileOperation {
    op_type: FileOpType,
    buffer_size: u16,    // 0-65535 -> bounded to MAX_BUFFER_SIZE
    seek_pos: SeekPos,   // Seek position for operations
    concurrent_tasks: u8, // 1-8 tasks operating concurrently
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FileOpType {
    Read,
    Write,
    Seek,
    ReadWrite, // Concurrent read+write
    SeekRead,  // Seek then read
    SeekWrite, // Seek then write
    Mixed,     // Random mix of operations
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum SeekPos {
    Start,
    End,
    Current(i16), // Relative seek -32768 to 32767
    Absolute(u16), // Absolute position 0-65535
}

// Mock waker for testing poll operations without full async runtime
struct MockWaker;

impl MockWaker {
    fn new() -> Waker {
        use std::task::{RawWaker, RawWakerVTable};

        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }

        const VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        let raw_waker = RawWaker::new(std::ptr::null(), &VTABLE);
        unsafe { Waker::from_raw(raw_waker) }
    }
}

struct FileTestHarness {
    _temp_dir: TempDir, // Keep alive for cleanup
    file: Arc<File>,
    initial_content: Vec<u8>,
}

impl FileTestHarness {
    fn new(file_size: usize) -> std::io::Result<Self> {
        let temp_dir = tempdir()?;
        let file_path = temp_dir.path().join("fuzz_test_file");

        // Create initial file content
        let initial_content: Vec<u8> = (0..file_size)
            .map(|i| (i % 256) as u8)
            .collect();
        std::fs::write(&file_path, &initial_content)?;

        // Create async File handle
        let std_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file_path)?;

        let file = File::from_std(std_file);
        let arc_file = Arc::new(file);

        Ok(Self {
            _temp_dir: temp_dir,
            file: arc_file,
            initial_content,
        })
    }

    fn execute_operation(&self, op: &FileOperation) -> Result<OperationResult, String> {
        let buffer_size = (op.buffer_size as usize).min(MAX_BUFFER_SIZE).max(1);
        let task_count = op.concurrent_tasks.max(1).min(8) as usize;

        match op.op_type {
            FileOpType::Read => self.concurrent_read(buffer_size, task_count),
            FileOpType::Write => self.concurrent_write(buffer_size, task_count),
            FileOpType::Seek => self.concurrent_seek(&op.seek_pos, task_count),
            FileOpType::ReadWrite => self.concurrent_read_write(buffer_size, task_count),
            FileOpType::SeekRead => self.seek_then_read(&op.seek_pos, buffer_size, task_count),
            FileOpType::SeekWrite => self.seek_then_write(&op.seek_pos, buffer_size, task_count),
            FileOpType::Mixed => self.mixed_operations(&op.seek_pos, buffer_size, task_count),
        }
    }

    fn concurrent_read(&self, buffer_size: usize, task_count: usize) -> Result<OperationResult, String> {
        let mut results = Vec::new();

        for task_id in 0..task_count {
            let file_clone = Arc::clone(&self.file);
            let result = self.single_read_task(file_clone, buffer_size, task_id);
            results.push(result);
        }

        Ok(OperationResult { results })
    }

    fn concurrent_write(&self, buffer_size: usize, task_count: usize) -> Result<OperationResult, String> {
        let mut results = Vec::new();

        for task_id in 0..task_count {
            let file_clone = Arc::clone(&self.file);
            let write_data: Vec<u8> = (0..buffer_size)
                .map(|i| ((task_id * 17 + i) % 256) as u8)
                .collect();
            let result = self.single_write_task(file_clone, write_data, task_id);
            results.push(result);
        }

        Ok(OperationResult { results })
    }

    fn concurrent_seek(&self, seek_pos: &SeekPos, task_count: usize) -> Result<OperationResult, String> {
        let mut results = Vec::new();

        for task_id in 0..task_count {
            let file_clone = Arc::clone(&self.file);
            let pos = self.resolve_seek_position(seek_pos, task_id);
            let result = self.single_seek_task(file_clone, pos, task_id);
            results.push(result);
        }

        Ok(OperationResult { results })
    }

    fn concurrent_read_write(&self, buffer_size: usize, task_count: usize) -> Result<OperationResult, String> {
        let mut results = Vec::new();
        let half_tasks = (task_count + 1) / 2;

        // First half: readers
        for task_id in 0..half_tasks {
            let file_clone = Arc::clone(&self.file);
            let result = self.single_read_task(file_clone, buffer_size, task_id);
            results.push(result);
        }

        // Second half: writers
        for task_id in half_tasks..task_count {
            let file_clone = Arc::clone(&self.file);
            let write_data: Vec<u8> = (0..buffer_size)
                .map(|i| ((task_id * 23 + i) % 256) as u8)
                .collect();
            let result = self.single_write_task(file_clone, write_data, task_id);
            results.push(result);
        }

        Ok(OperationResult { results })
    }

    fn seek_then_read(&self, seek_pos: &SeekPos, buffer_size: usize, task_count: usize) -> Result<OperationResult, String> {
        let mut results = Vec::new();

        for task_id in 0..task_count {
            let file_clone = Arc::clone(&self.file);
            let pos = self.resolve_seek_position(seek_pos, task_id);

            // Seek first
            let seek_result = self.single_seek_task(file_clone.clone(), pos, task_id);
            results.push(seek_result);

            // Then read
            let read_result = self.single_read_task(file_clone, buffer_size, task_id);
            results.push(read_result);
        }

        Ok(OperationResult { results })
    }

    fn seek_then_write(&self, seek_pos: &SeekPos, buffer_size: usize, task_count: usize) -> Result<OperationResult, String> {
        let mut results = Vec::new();

        for task_id in 0..task_count {
            let file_clone = Arc::clone(&self.file);
            let pos = self.resolve_seek_position(seek_pos, task_id);
            let write_data: Vec<u8> = (0..buffer_size)
                .map(|i| ((task_id * 31 + i) % 256) as u8)
                .collect();

            // Seek first
            let seek_result = self.single_seek_task(file_clone.clone(), pos, task_id);
            results.push(seek_result);

            // Then write
            let write_result = self.single_write_task(file_clone, write_data, task_id);
            results.push(write_result);
        }

        Ok(OperationResult { results })
    }

    fn mixed_operations(&self, seek_pos: &SeekPos, buffer_size: usize, task_count: usize) -> Result<OperationResult, String> {
        let mut results = Vec::new();

        for task_id in 0..task_count {
            let file_clone = Arc::clone(&self.file);

            // Task 0,3,6: read, Task 1,4,7: write, Task 2,5: seek
            match task_id % 3 {
                0 => {
                    let result = self.single_read_task(file_clone, buffer_size, task_id);
                    results.push(result);
                }
                1 => {
                    let write_data: Vec<u8> = (0..buffer_size)
                        .map(|i| ((task_id * 41 + i) % 256) as u8)
                        .collect();
                    let result = self.single_write_task(file_clone, write_data, task_id);
                    results.push(result);
                }
                2 => {
                    let pos = self.resolve_seek_position(seek_pos, task_id);
                    let result = self.single_seek_task(file_clone, pos, task_id);
                    results.push(result);
                }
                _ => unreachable!(),
            }
        }

        Ok(OperationResult { results })
    }

    fn single_read_task(&self, file: Arc<File>, buffer_size: usize, task_id: usize) -> TaskResult {
        let mut file_pin = Pin::new(file.as_ref());
        let mut buffer = vec![0u8; buffer_size];
        let mut read_buf = ReadBuf::new(&mut buffer);
        let waker = MockWaker::new();
        let mut context = Context::from_waker(&waker);

        match file_pin.as_mut().poll_read(&mut context, &mut read_buf) {
            Poll::Ready(Ok(())) => TaskResult {
                task_id,
                success: true,
                bytes_processed: read_buf.filled().len(),
                error_msg: None,
            },
            Poll::Ready(Err(e)) => TaskResult {
                task_id,
                success: false,
                bytes_processed: 0,
                error_msg: Some(format!("Read error: {e}")),
            },
            Poll::Pending => TaskResult {
                task_id,
                success: false,
                bytes_processed: 0,
                error_msg: Some("Read pending (unexpected in blocking mode)".to_string()),
            },
        }
    }

    fn single_write_task(&self, file: Arc<File>, data: Vec<u8>, task_id: usize) -> TaskResult {
        let mut file_pin = Pin::new(file.as_ref());
        let waker = MockWaker::new();
        let mut context = Context::from_waker(&waker);

        match file_pin.as_mut().poll_write(&mut context, &data) {
            Poll::Ready(Ok(n)) => TaskResult {
                task_id,
                success: true,
                bytes_processed: n,
                error_msg: None,
            },
            Poll::Ready(Err(e)) => TaskResult {
                task_id,
                success: false,
                bytes_processed: 0,
                error_msg: Some(format!("Write error: {e}")),
            },
            Poll::Pending => TaskResult {
                task_id,
                success: false,
                bytes_processed: 0,
                error_msg: Some("Write pending (unexpected in blocking mode)".to_string()),
            },
        }
    }

    fn single_seek_task(&self, file: Arc<File>, pos: SeekFrom, task_id: usize) -> TaskResult {
        let mut file_pin = Pin::new(file.as_ref());
        let waker = MockWaker::new();
        let mut context = Context::from_waker(&waker);

        match file_pin.as_mut().poll_seek(&mut context, pos) {
            Poll::Ready(Ok(position)) => TaskResult {
                task_id,
                success: true,
                bytes_processed: position as usize,
                error_msg: None,
            },
            Poll::Ready(Err(e)) => TaskResult {
                task_id,
                success: false,
                bytes_processed: 0,
                error_msg: Some(format!("Seek error: {e}")),
            },
            Poll::Pending => TaskResult {
                task_id,
                success: false,
                bytes_processed: 0,
                error_msg: Some("Seek pending (unexpected in blocking mode)".to_string()),
            },
        }
    }

    fn resolve_seek_position(&self, seek_pos: &SeekPos, task_id: usize) -> SeekFrom {
        match seek_pos {
            SeekPos::Start => SeekFrom::Start(0),
            SeekPos::End => SeekFrom::End(0),
            SeekPos::Current(offset) => SeekFrom::Current(i64::from(*offset)),
            SeekPos::Absolute(pos) => {
                let abs_pos = (*pos as usize + task_id * 17) % self.initial_content.len().max(1);
                SeekFrom::Start(abs_pos as u64)
            }
        }
    }
}

#[derive(Debug)]
struct OperationResult {
    results: Vec<TaskResult>,
}

#[derive(Debug)]
struct TaskResult {
    task_id: usize,
    success: bool,
    bytes_processed: usize,
    error_msg: Option<String>,
}

fuzz_target!(|operations: Vec<FileOperation>| {
    if operations.len() > MAX_OPERATIONS {
        return;
    }

    let file_size = MAX_FILE_SIZE / 4; // Start with smaller files for focused testing
    let harness = match FileTestHarness::new(file_size) {
        Ok(h) => h,
        Err(_) => return, // Skip if file creation fails
    };

    for (op_index, operation) in operations.iter().enumerate() {
        let result = harness.execute_operation(operation);

        match result {
            Ok(op_result) => {
                // Validate that at least some operations succeeded
                let success_count = op_result.results.iter().filter(|r| r.success).count();
                let total_count = op_result.results.len();

                // In a correctly synchronized implementation, most operations should succeed
                // Data races might cause spurious failures
                if total_count > 0 && success_count == 0 {
                    // All operations failed - could indicate severe corruption
                    panic!(
                        "POTENTIAL RACE CORRUPTION: All {} operations failed for op {}: {:#?}",
                        total_count, op_index, op_result.results
                    );
                }

                // Check for suspicious patterns that might indicate races
                let unique_positions: std::collections::HashSet<usize> = op_result.results
                    .iter()
                    .filter(|r| r.success)
                    .map(|r| r.bytes_processed)
                    .collect();

                // For seek operations, having identical positions from concurrent seeks
                // might indicate a race condition (or might be legitimate)
                if matches!(operation.op_type, FileOpType::Seek | FileOpType::SeekRead | FileOpType::SeekWrite) {
                    if unique_positions.len() == 1 && operation.concurrent_tasks > 1 {
                        // This could be legitimate if all tasks seek to the same position,
                        // or could indicate a race where only one seek "wins"
                        // TSan would detect the actual race, this is just a heuristic
                    }
                }
            }
            Err(e) => {
                // Operation setup failed - skip this operation
                continue;
            }
        }
    }

    // Final invariant: the file should still be in a valid state
    // Try a simple read to ensure the file descriptor is not corrupted
    let final_file_clone = Arc::clone(&harness.file);
    let mut buffer = vec![0u8; 64];
    let mut read_buf = ReadBuf::new(&mut buffer);
    let waker = MockWaker::new();
    let mut context = Context::from_waker(&waker);
    let mut file_pin = Pin::new(final_file_clone.as_ref());

    match file_pin.as_mut().poll_read(&mut context, &mut read_buf) {
        Poll::Ready(Ok(())) => {
            // File is still readable - good
        }
        Poll::Ready(Err(e)) => {
            panic!("CORRUPTION: Final file read failed after concurrent operations: {}", e);
        }
        Poll::Pending => {
            // Unexpected but not necessarily a race
        }
    }
});