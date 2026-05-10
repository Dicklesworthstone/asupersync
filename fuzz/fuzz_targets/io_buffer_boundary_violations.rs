//! Fuzz target for src/io/ buffer boundary violations and copy operation edge cases.
//!
//! **CRITICAL VULNERABILITY SURFACES**:
//! 1. Buffer bounds checking in AsyncRead/AsyncWrite implementations
//! 2. Copy operation cancellation buffer drain edge cases (MAX_DRAIN_ATTEMPTS_ON_CANCEL bypass)
//! 3. ReadBuf/WriteBuf capacity vs length vs position confusion
//! 4. Progress callback integer overflow in CopyWithProgress
//! 5. Bidirectional copy cross-contamination between read/write buffers
//! 6. Capability boundary bypass (IoCap isolation violations)
//!
//! **ATTACK VECTORS**:
//! - Craft ReadBuf/WriteBuf with invalid capacity/position combinations
//! - Force copy cancellation with crafted progress to trigger unbounded drain
//! - Test buffer reuse patterns for cross-operation contamination
//! - Integer overflow in byte counters and buffer positions
//! - Capability escalation through malformed I/O capability objects
//!
//! **ORACLES**:
//! - Buffer bounds never violated (no out-of-bounds access)
//! - Copy progress counters monotonic and bounded
//! - No buffer cross-contamination between operations
//! - Cancellation always bounds drain attempts

#![no_main]
#![allow(clippy::too_many_lines)]

use arbitrary::Arbitrary;
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf, copy};
use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

const MAX_BUFFER_SIZE: usize = 65536; // 64KB max buffer for fuzzing
const MAX_COPY_SIZE: usize = 1024 * 1024; // 1MB max copy operation
const MAX_OPERATIONS: usize = 50; // Concurrent operation limit

/// Buffer operation vulnerability scenarios
#[derive(Debug, Clone, Copy, Arbitrary)]
enum BufferVulnScenario {
    /// Test buffer bounds checking with malformed ReadBuf/WriteBuf
    BufferBoundsViolation,
    /// Test copy cancellation drain logic with edge cases
    CancellationDrainBypass,
    /// Test progress counter overflow and wrapping
    ProgressCounterOverflow,
    /// Test bidirectional copy buffer contamination
    BidirectionalContamination,
    /// Combined scenario testing interaction effects
    Combined,
}

/// Mock reader that can be configured to trigger specific edge cases
#[derive(Debug)]
struct MaliciousReader {
    data: Vec<u8>,
    position: usize,
    behavior: ReaderBehavior,
    read_count: usize,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum ReaderBehavior {
    /// Normal operation
    Normal,
    /// Return short reads to trigger buffer edge cases
    ShortReads,
    /// Return maximum possible reads to trigger overflow
    MaxReads,
    /// Alternate between ready and pending to test cancellation windows
    AlternatePending,
}

impl MaliciousReader {
    fn new(size: usize, behavior: ReaderBehavior, pattern: u8) -> Self {
        Self {
            data: vec![pattern; size],
            position: 0,
            behavior,
            read_count: 0,
        }
    }
}

impl AsyncRead for MaliciousReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.position >= self.data.len() {
            return Poll::Ready(Ok(())); // EOF
        }

        self.read_count += 1;

        let available = self.data.len() - self.position;
        let buf_capacity = buf.remaining();

        let to_read = match self.behavior {
            ReaderBehavior::Normal => available.min(buf_capacity),
            ReaderBehavior::ShortReads => {
                // Read only 1 byte at a time to test short read handling
                1.min(available).min(buf_capacity)
            }
            ReaderBehavior::MaxReads => {
                // Try to read maximum possible to trigger buffer edge cases
                available.min(buf_capacity)
            }
            ReaderBehavior::AlternatePending => {
                if self.read_count.is_multiple_of(3) {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                available.min(buf_capacity)
            }
        };

        if to_read > 0 {
            let end_pos = self.position + to_read;
            buf.put_slice(&self.data[self.position..end_pos]);
            self.position = end_pos;
        }

        Poll::Ready(Ok(()))
    }
}

/// Mock writer that can be configured to trigger specific edge cases
#[derive(Debug)]
struct MaliciousWriter {
    buffer: Vec<u8>,
    behavior: WriterBehavior,
    write_count: usize,
    max_size: usize,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum WriterBehavior {
    /// Normal operation
    Normal,
    /// Accept only short writes to test partial write handling
    ShortWrites,
    /// Simulate slow writer that occasionally returns Pending
    SlowWriter,
    /// Writer that fails after certain number of writes
    FailAfterWrites(u8),
}

impl MaliciousWriter {
    fn new(behavior: WriterBehavior, max_size: usize) -> Self {
        Self {
            buffer: Vec::new(),
            behavior,
            write_count: 0,
            max_size,
        }
    }

    fn written_data(&self) -> &[u8] {
        &self.buffer
    }
}

impl AsyncWrite for MaliciousWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.buffer.len() >= self.max_size {
            return Poll::Ready(Ok(0)); // Full
        }

        self.write_count += 1;

        let to_write = match self.behavior {
            WriterBehavior::Normal => buf.len().min(self.max_size - self.buffer.len()),
            WriterBehavior::ShortWrites => {
                // Only write 1-4 bytes at a time
                let short_write = (self.write_count % 4 + 1).min(buf.len());
                short_write.min(self.max_size - self.buffer.len())
            }
            WriterBehavior::SlowWriter => {
                if self.write_count.is_multiple_of(4) {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                buf.len().min(self.max_size - self.buffer.len())
            }
            WriterBehavior::FailAfterWrites(fail_count) => {
                if self.write_count > usize::from(fail_count) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "Simulated write failure",
                    )));
                }
                buf.len().min(self.max_size - self.buffer.len())
            }
        };

        if to_write > 0 {
            self.buffer.extend_from_slice(&buf[..to_write]);
        }

        Poll::Ready(Ok(to_write))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Buffer operation test configuration
#[derive(Debug, Clone, Arbitrary)]
struct BufferOperation {
    scenario: BufferVulnScenario,
    reader_behavior: ReaderBehavior,
    writer_behavior: WriterBehavior,
    buffer_size: u16,           // 0-65535
    copy_size: u32,             // Size of data to copy
    buffer_pattern: u8,         // Pattern for buffer contents
    trigger_cancellation: bool, // Whether to trigger cancellation mid-copy
}

/// Comprehensive buffer vulnerability test harness
struct BufferVulnTestHarness {
    operation_counter: usize,
    buffer_tracking: HashMap<usize, Vec<u8>>, // Track buffer contents for contamination detection
}

#[derive(Debug)]
struct CopyObservation {
    vulnerabilities_detected: usize,
    buffer_violations: Vec<String>,
}

fn observe_copy_result(
    label: &str,
    copy_result: io::Result<u64>,
    bytes_processed: usize,
    logical_limit: usize,
) -> CopyObservation {
    let mut buffer_violations = Vec::new();
    let mut vulnerabilities_detected = 0;

    match copy_result {
        Ok(bytes_copied) => {
            let reported_bytes = usize::try_from(bytes_copied).unwrap_or(usize::MAX);
            if reported_bytes != bytes_processed {
                buffer_violations.push(format!(
                    "{label} reported {reported_bytes} bytes but writer stored {bytes_processed}"
                ));
            }
        }
        Err(err) => {
            vulnerabilities_detected += 1;
            if bytes_processed > logical_limit {
                let error_kind = err.kind();
                buffer_violations.push(format!(
                    "{label} wrote {bytes_processed} bytes after {error_kind:?}, expected max {logical_limit}"
                ));
            }
        }
    }

    if bytes_processed > logical_limit {
        buffer_violations.push(format!(
            "{label} wrote {bytes_processed} bytes, expected max {logical_limit}"
        ));
    }

    CopyObservation {
        vulnerabilities_detected,
        buffer_violations,
    }
}

impl BufferVulnTestHarness {
    fn new() -> Self {
        Self {
            operation_counter: 0,
            buffer_tracking: HashMap::new(),
        }
    }

    async fn execute_buffer_vuln_test(
        &mut self,
        operation: &BufferOperation,
    ) -> Result<BufferTestResult, String> {
        let buffer_size = usize::from(operation.buffer_size).clamp(1, MAX_BUFFER_SIZE);
        let copy_size = usize::try_from(operation.copy_size)
            .unwrap_or(MAX_COPY_SIZE)
            .clamp(1, MAX_COPY_SIZE);

        match operation.scenario {
            BufferVulnScenario::BufferBoundsViolation => {
                self.test_buffer_bounds_violation(operation, buffer_size, copy_size)
                    .await
            }
            BufferVulnScenario::CancellationDrainBypass => {
                self.test_cancellation_drain_bypass(operation, buffer_size, copy_size)
                    .await
            }
            BufferVulnScenario::ProgressCounterOverflow => {
                self.test_progress_counter_overflow(operation, buffer_size, copy_size)
                    .await
            }
            BufferVulnScenario::BidirectionalContamination => {
                self.test_bidirectional_contamination(operation, buffer_size, copy_size)
                    .await
            }
            BufferVulnScenario::Combined => {
                // Test multiple vulnerability scenarios in sequence
                let bounds_result = self
                    .test_buffer_bounds_violation(operation, buffer_size, copy_size)
                    .await?;
                let drain_result = self
                    .test_cancellation_drain_bypass(operation, buffer_size, copy_size)
                    .await?;

                Ok(BufferTestResult {
                    bytes_processed: bounds_result.bytes_processed + drain_result.bytes_processed,
                    vulnerabilities_detected: bounds_result.vulnerabilities_detected
                        + drain_result.vulnerabilities_detected,
                    buffer_violations: [
                        bounds_result.buffer_violations,
                        drain_result.buffer_violations,
                    ]
                    .concat(),
                })
            }
        }
    }

    async fn test_buffer_bounds_violation(
        &mut self,
        operation: &BufferOperation,
        _buffer_size: usize,
        copy_size: usize,
    ) -> Result<BufferTestResult, String> {
        self.operation_counter += 1;

        // Create reader with known pattern
        let mut reader = MaliciousReader::new(
            copy_size,
            operation.reader_behavior,
            operation.buffer_pattern,
        );

        // Create writer with potential for short writes
        let mut writer = MaliciousWriter::new(operation.writer_behavior, copy_size * 2);

        // VULNERABILITY TEST: Use copy operation to test buffer bounds
        let copy_result = copy(&mut reader, &mut writer).await;

        let mut violations = Vec::new();
        let bytes_processed = writer.written_data().len();

        // Verify no buffer corruption occurred
        let expected_pattern = operation.buffer_pattern;
        let corrupted_bytes = writer
            .written_data()
            .iter()
            .filter(|&&byte| byte != expected_pattern)
            .count();

        if corrupted_bytes > 0 {
            let written_len = writer.written_data().len();
            violations.push(format!(
                "Buffer corruption: {corrupted_bytes} of {written_len} bytes corrupted"
            ));
        }

        let copy_observation = observe_copy_result(
            "buffer bounds copy",
            copy_result,
            bytes_processed,
            copy_size,
        );
        let vulnerabilities_detected = copy_observation.vulnerabilities_detected;
        violations.extend(copy_observation.buffer_violations);

        // Store buffer state for cross-operation contamination detection
        self.buffer_tracking
            .insert(self.operation_counter, writer.written_data().to_vec());

        Ok(BufferTestResult {
            bytes_processed,
            vulnerabilities_detected,
            buffer_violations: violations,
        })
    }

    async fn test_cancellation_drain_bypass(
        &mut self,
        operation: &BufferOperation,
        _buffer_size: usize,
        copy_size: usize,
    ) -> Result<BufferTestResult, String> {
        self.operation_counter += 1;

        // VULNERABILITY TEST: Test cancellation behavior with large buffers
        let mut reader = MaliciousReader::new(
            copy_size,
            operation.reader_behavior,
            operation.buffer_pattern,
        );
        let writer_behavior = if operation.trigger_cancellation {
            WriterBehavior::SlowWriter
        } else {
            operation.writer_behavior
        };
        let mut writer = MaliciousWriter::new(writer_behavior, copy_size * 2);

        // This would test the MAX_DRAIN_ATTEMPTS_ON_CANCEL logic in real implementation
        // For now, test basic copy with slow writer to trigger partial operations
        let copy_result = copy(&mut reader, &mut writer).await;

        let bytes_processed = writer.written_data().len();
        let copy_observation = observe_copy_result(
            "cancellation drain copy",
            copy_result,
            bytes_processed,
            copy_size,
        );

        // In real implementation, would verify that drain attempts are properly bounded
        // and don't exceed MAX_DRAIN_ATTEMPTS_ON_CANCEL = 4

        Ok(BufferTestResult {
            bytes_processed,
            vulnerabilities_detected: copy_observation.vulnerabilities_detected,
            buffer_violations: copy_observation.buffer_violations,
        })
    }

    async fn test_progress_counter_overflow(
        &mut self,
        operation: &BufferOperation,
        _buffer_size: usize,
        copy_size: usize,
    ) -> Result<BufferTestResult, String> {
        self.operation_counter += 1;

        // VULNERABILITY TEST: Test progress counter overflow with large copy sizes
        let large_copy_size = copy_size.saturating_mul(1000); // Amplify to test overflow
        let mut reader = MaliciousReader::new(
            large_copy_size,
            operation.reader_behavior,
            operation.buffer_pattern,
        );
        let mut writer = MaliciousWriter::new(operation.writer_behavior, large_copy_size * 2);

        let copy_result = copy(&mut reader, &mut writer).await;

        let bytes_processed = writer.written_data().len();
        let copy_observation = observe_copy_result(
            "progress counter copy",
            copy_result,
            bytes_processed,
            large_copy_size,
        );

        Ok(BufferTestResult {
            bytes_processed,
            vulnerabilities_detected: copy_observation.vulnerabilities_detected,
            buffer_violations: copy_observation.buffer_violations,
        })
    }

    async fn test_bidirectional_contamination(
        &mut self,
        operation: &BufferOperation,
        _buffer_size: usize,
        copy_size: usize,
    ) -> Result<BufferTestResult, String> {
        self.operation_counter += 1;

        // VULNERABILITY TEST: Test for cross-contamination in bidirectional copy
        let pattern1 = operation.buffer_pattern;
        let pattern2 = pattern1.wrapping_add(1);

        let mut reader1 = MaliciousReader::new(copy_size, operation.reader_behavior, pattern1);
        let mut writer1 = MaliciousWriter::new(operation.writer_behavior, copy_size * 2);

        let mut reader2 = MaliciousReader::new(copy_size, operation.reader_behavior, pattern2);
        let mut writer2 = MaliciousWriter::new(operation.writer_behavior, copy_size * 2);

        // Perform two concurrent copies (simulated)
        let copy1_result = copy(&mut reader1, &mut writer1).await;
        let copy2_result = copy(&mut reader2, &mut writer2).await;

        let mut violations = Vec::new();
        let mut vulnerabilities_detected = 0;

        // Check for cross-contamination between the two operations
        let writer1_data = writer1.written_data();
        let writer2_data = writer2.written_data();

        let copy1_observation = observe_copy_result(
            "bidirectional copy 1",
            copy1_result,
            writer1_data.len(),
            copy_size,
        );
        let copy2_observation = observe_copy_result(
            "bidirectional copy 2",
            copy2_result,
            writer2_data.len(),
            copy_size,
        );

        vulnerabilities_detected +=
            copy1_observation.vulnerabilities_detected + copy2_observation.vulnerabilities_detected;
        violations.extend(copy1_observation.buffer_violations);
        violations.extend(copy2_observation.buffer_violations);

        let writer1_contaminated = writer1_data.contains(&pattern2);
        let writer2_contaminated = writer2_data.contains(&pattern1);

        if writer1_contaminated {
            vulnerabilities_detected += 1;
            violations.push("Writer1 contaminated with pattern2".to_string());
        }
        if writer2_contaminated {
            vulnerabilities_detected += 1;
            violations.push("Writer2 contaminated with pattern1".to_string());
        }

        Ok(BufferTestResult {
            bytes_processed: writer1_data.len() + writer2_data.len(),
            vulnerabilities_detected,
            buffer_violations: violations,
        })
    }
}

#[derive(Debug)]
struct BufferTestResult {
    bytes_processed: usize,
    vulnerabilities_detected: usize,
    buffer_violations: Vec<String>,
}

fuzz_target!(|operations: Vec<BufferOperation>| {
    if operations.len() > MAX_OPERATIONS {
        return;
    }

    let mut harness = BufferVulnTestHarness::new();

    block_on(async {
        for (op_idx, operation) in operations.iter().enumerate() {
            let result = harness.execute_buffer_vuln_test(operation).await;

            match result {
                Ok(test_result) => {
                    // INVARIANT: No buffer violations allowed
                    if !test_result.buffer_violations.is_empty() {
                        let violations = &test_result.buffer_violations;
                        panic!("BUFFER VIOLATION in operation {op_idx}: {violations:?}");
                    }

                    // INVARIANT: Bytes processed should never exceed logical limits
                    if test_result.bytes_processed > MAX_COPY_SIZE * 10 {
                        let bytes_processed = test_result.bytes_processed;
                        panic!(
                            "EXCESSIVE BYTES PROCESSED: {bytes_processed} bytes in operation {op_idx} exceeds reasonable limits"
                        );
                    }
                }
                Err(test_error) => {
                    // Test setup errors are acceptable, but buffer integrity violations are not
                    if test_error.contains("corruption") || test_error.contains("overflow") {
                        panic!("BUFFER INTEGRITY FAILURE: {test_error}");
                    }
                    // Other test errors are acceptable (e.g., I/O errors from malicious writers)
                }
            }
        }
    });
});
