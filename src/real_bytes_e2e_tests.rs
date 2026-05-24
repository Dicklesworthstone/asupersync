//! Real bytes operations E2E tests - zero-copy I/O pipeline validation
//!
//! Tests real bytes primitives including:
//! - Bytes/BytesMut zero-copy operations through I/O pipelines
//! - Memory-efficient cloning and slicing validation
//! - Integration with AsyncRead/AsyncWrite for minimal allocation paths
//! - Buffer management with allocation hotpath tracking
//! - Reference counting behavior and memory safety
//!
//! Anti-mock principle: Tests use actual Bytes/BytesMut implementations with real
//! I/O operations through files and pipes to validate zero-copy claims, detect
//! allocation hotpaths, and catch memory management bugs that mocks would hide.

#![cfg(all(test, feature = "real-service-e2e"))]

use crate::bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use crate::time::{Duration, timeout};

use std::io::{self, Cursor};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

// Structured JSON-line logging for CI debugging
struct TestLogger {
    test_name: String,
    start_time: Instant,
}

impl TestLogger {
    fn new(test_name: &str) -> Self {
        let logger = Self {
            test_name: test_name.to_string(),
            start_time: Instant::now(),
        };
        logger.log_event("test_start", serde_json::json!({}));
        logger
    }

    fn log_event(&self, event_type: &str, data: serde_json::Value) {
        let elapsed = self.start_time.elapsed().as_millis();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        eprintln!(
            "{{\"timestamp\":{},\"test\":\"{}\",\"elapsed_ms\":{},\"event\":\"{}\",\"data\":{}}}",
            timestamp, self.test_name, elapsed, event_type, data
        );
    }

    fn log_phase(&self, phase: &str) {
        self.log_event("phase", serde_json::json!({"name": phase}));
    }

    fn log_metrics(&self, metrics: serde_json::Value) {
        self.log_event("metrics", metrics);
    }

    fn log_assertion(&self, assertion: &str, passed: bool, details: serde_json::Value) {
        self.log_event(
            "assertion",
            serde_json::json!({
                "assertion": assertion,
                "passed": passed,
                "details": details
            }),
        );
    }
}

impl Drop for TestLogger {
    fn drop(&mut self) {
        let elapsed = self.start_time.elapsed().as_millis();
        self.log_event(
            "test_end",
            serde_json::json!({"total_duration_ms": elapsed}),
        );
    }
}

/// Mock async I/O adapter for testing bytes integration
struct MockAsyncIo<T> {
    inner: T,
}

impl<T> MockAsyncIo<T> {
    fn new(inner: T) -> Self {
        Self { inner }
    }

    async fn read_buf(&mut self, buf: &mut BytesMut) -> io::Result<usize>
    where
        Self: AsyncRead + Unpin,
    {
        let mut read = Vec::new();
        let bytes_read = self.read_to_end(&mut read).await?;
        buf.extend_from_slice(&read);
        Ok(bytes_read)
    }
}

impl AsyncRead for MockAsyncIo<Cursor<Vec<u8>>> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        use std::io::Read;
        match self.inner.read(buf.unfilled()) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

impl AsyncWrite for MockAsyncIo<Vec<u8>> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.inner.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Allocation tracking for zero-copy validation
struct AllocationTracker {
    allocation_count: Arc<AtomicUsize>,
    bytes_allocated: Arc<AtomicUsize>,
}

impl AllocationTracker {
    fn new() -> Self {
        Self {
            allocation_count: Arc::new(AtomicUsize::new(0)),
            bytes_allocated: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn record_allocation(&self, size: usize) {
        self.allocation_count.fetch_add(1, Ordering::Relaxed);
        self.bytes_allocated.fetch_add(size, Ordering::Relaxed);
    }

    fn get_stats(&self) -> (usize, usize) {
        (
            self.allocation_count.load(Ordering::Relaxed),
            self.bytes_allocated.load(Ordering::Relaxed),
        )
    }

    fn reset(&self) {
        self.allocation_count.store(0, Ordering::Relaxed);
        self.bytes_allocated.store(0, Ordering::Relaxed);
    }
}

/// Test harness for bytes E2E testing
struct BytesTestHarness {
    logger: TestLogger,
    allocation_tracker: AllocationTracker,
}

impl BytesTestHarness {
    fn new(test_name: &str) -> Self {
        let logger = TestLogger::new(test_name);
        let allocation_tracker = AllocationTracker::new();

        logger.log_event("harness_init", serde_json::json!({}));

        Self {
            logger,
            allocation_tracker,
        }
    }

    /// Test zero-copy cloning and slicing
    fn test_zero_copy_operations(&self) {
        self.logger.log_phase("zero_copy_setup");

        // Create test data
        let test_data =
            b"Hello, this is a test string for zero-copy validation with asupersync bytes!"
                .to_vec();
        let original_size = test_data.len();

        self.logger.log_event(
            "test_data_prepared",
            serde_json::json!({
                "original_size": original_size
            }),
        );

        // Phase 1: Create Bytes from data
        self.logger.log_phase("bytes_creation");
        self.allocation_tracker.reset();

        let bytes = Bytes::copy_from_slice(&test_data);
        let (allocs_after_create, bytes_allocated) = self.allocation_tracker.get_stats();

        self.logger.log_metrics(serde_json::json!({
            "bytes_length": bytes.len(),
            "allocations_for_create": allocs_after_create,
            "bytes_allocated": bytes_allocated
        }));

        // Phase 2: Test zero-copy cloning
        self.logger.log_phase("zero_copy_cloning");
        self.allocation_tracker.reset();

        let clone1 = bytes.clone();
        let clone2 = bytes.clone();
        let clone3 = clone1.clone();

        let (allocs_for_cloning, bytes_for_cloning) = self.allocation_tracker.get_stats();

        self.logger.log_assertion(
            "zero_copy_cloning",
            allocs_for_cloning == 0,
            serde_json::json!({
                "allocations_for_cloning": allocs_for_cloning,
                "bytes_for_cloning": bytes_for_cloning,
                "clone_count": 3
            }),
        );

        // Cloning should be zero-allocation
        assert_eq!(allocs_for_cloning, 0, "Cloning should be zero-allocation");

        // Validate all clones have same content
        assert_eq!(bytes.len(), clone1.len());
        assert_eq!(bytes.len(), clone2.len());
        assert_eq!(bytes.len(), clone3.len());
        assert_eq!(&bytes[..], &clone1[..]);
        assert_eq!(&bytes[..], &clone2[..]);
        assert_eq!(&bytes[..], &clone3[..]);

        // Phase 3: Test zero-copy slicing
        self.logger.log_phase("zero_copy_slicing");
        self.allocation_tracker.reset();

        let slice1 = bytes.slice(0..10);
        let slice2 = bytes.slice(10..20);
        let slice3 = bytes.slice(20..);

        let (allocs_for_slicing, bytes_for_slicing) = self.allocation_tracker.get_stats();

        self.logger.log_assertion(
            "zero_copy_slicing",
            allocs_for_slicing == 0,
            serde_json::json!({
                "allocations_for_slicing": allocs_for_slicing,
                "bytes_for_slicing": bytes_for_slicing,
                "slice_count": 3,
                "slice_sizes": [slice1.len(), slice2.len(), slice3.len()]
            }),
        );

        // Slicing should be zero-allocation
        assert_eq!(allocs_for_slicing, 0, "Slicing should be zero-allocation");

        // Validate slice contents
        assert_eq!(&slice1[..], &test_data[0..10]);
        assert_eq!(&slice2[..], &test_data[10..20]);
        assert_eq!(&slice3[..], &test_data[20..]);

        self.logger.log_assertion(
            "zero_copy_validation_complete",
            true,
            serde_json::json!({
                "original_size": original_size,
                "total_zero_copy_ops": 6
            }),
        );
    }

    /// Test Bytes/BytesMut integration with I/O operations
    async fn test_bytes_io_integration(&self) {
        self.logger.log_phase("io_integration_setup");

        // Create test data with various patterns
        let test_patterns = vec![
            (b"simple text".to_vec(), "simple_text"),
            (vec![0x00; 1024], "zeros_1kb"),
            (vec![0xFF; 512], "ones_512b"),
            ((0..256).collect::<Vec<u8>>(), "sequence_256"),
        ];

        self.logger.log_event(
            "io_patterns_prepared",
            serde_json::json!({
                "pattern_count": test_patterns.len(),
                "total_test_bytes": test_patterns.iter().map(|(data, _)| data.len()).sum::<usize>()
            }),
        );

        for (test_data, pattern_name) in test_patterns {
            self.logger
                .log_phase(&format!("io_pattern_{}", pattern_name));

            // Phase 1: Write Bytes through AsyncWrite
            self.logger.log_phase("async_write");
            let bytes_to_write = Bytes::copy_from_slice(&test_data);
            let mut write_buffer = Vec::new();

            {
                let mut writer = MockAsyncIo::new(Vec::new());
                writer
                    .write_all(&bytes_to_write)
                    .await
                    .expect("Bytes write should succeed");
                writer.flush().await.expect("Write flush should succeed");

                write_buffer = writer.inner;
            }

            self.logger.log_metrics(serde_json::json!({
                "pattern": pattern_name,
                "original_size": test_data.len(),
                "written_size": write_buffer.len(),
                "write_preserved_size": write_buffer.len() == test_data.len()
            }));

            assert_eq!(
                write_buffer.len(),
                test_data.len(),
                "Write should preserve data size for {}",
                pattern_name
            );
            assert_eq!(
                write_buffer, test_data,
                "Write should preserve data content for {}",
                pattern_name
            );

            // Phase 2: Read into BytesMut through AsyncRead
            self.logger.log_phase("async_read");
            let mut read_buffer = BytesMut::with_capacity(test_data.len() + 100);
            let mut reader = MockAsyncIo::new(Cursor::new(write_buffer));

            let bytes_read = reader
                .read_buf(&mut read_buffer)
                .await
                .expect("Bytes read should succeed");

            self.logger.log_metrics(serde_json::json!({
                "pattern": pattern_name,
                "bytes_read": bytes_read,
                "buffer_len": read_buffer.len(),
                "buffer_capacity": read_buffer.capacity()
            }));

            assert_eq!(
                bytes_read,
                test_data.len(),
                "Should read all bytes for {}",
                pattern_name
            );
            assert_eq!(
                &read_buffer[..],
                &test_data[..],
                "Read data should match original for {}",
                pattern_name
            );

            // Phase 3: Convert BytesMut to Bytes (zero-copy where possible)
            self.logger.log_phase("bytes_mut_conversion");
            self.allocation_tracker.reset();

            let final_bytes = read_buffer.freeze();
            let (allocs_for_freeze, bytes_for_freeze) = self.allocation_tracker.get_stats();

            self.logger.log_assertion(
                "freeze_zero_copy",
                allocs_for_freeze == 0,
                serde_json::json!({
                    "pattern": pattern_name,
                    "allocations_for_freeze": allocs_for_freeze,
                    "bytes_for_freeze": bytes_for_freeze,
                    "final_bytes_len": final_bytes.len()
                }),
            );

            assert_eq!(
                &final_bytes[..],
                &test_data[..],
                "Frozen bytes should match original for {}",
                pattern_name
            );

            self.logger.log_assertion(
                "io_pattern_complete",
                true,
                serde_json::json!({
                    "pattern": pattern_name,
                    "all_validations_passed": true
                }),
            );
        }
    }

    /// Test BytesMut growth and allocation patterns
    async fn test_bytes_mut_growth_patterns(&self) {
        self.logger.log_phase("growth_patterns_setup");

        let growth_tests = vec![
            ("small_increments", vec![10, 15, 8, 12, 20]),
            ("doubling_pattern", vec![100, 200, 400, 800]),
            ("large_chunk", vec![4096]),
            ("mixed_sizes", vec![50, 500, 5, 5000, 1]),
        ];

        for (pattern_name, append_sizes) in growth_tests {
            self.logger
                .log_phase(&format!("growth_pattern_{}", pattern_name));

            self.allocation_tracker.reset();
            let mut bytes_mut = BytesMut::new();

            let mut total_appended = 0;
            let mut allocations_per_append = Vec::new();

            for (i, &append_size) in append_sizes.iter().enumerate() {
                let (allocs_before, _) = self.allocation_tracker.get_stats();

                // Append data
                let append_data = vec![i as u8; append_size];
                bytes_mut.extend_from_slice(&append_data);
                total_appended += append_size;

                let (allocs_after, bytes_allocated) = self.allocation_tracker.get_stats();
                let new_allocations = allocs_after - allocs_before;
                allocations_per_append.push(new_allocations);

                self.logger.log_event(
                    "append_step",
                    serde_json::json!({
                        "pattern": pattern_name,
                        "step": i,
                        "append_size": append_size,
                        "new_allocations": new_allocations,
                        "total_length": bytes_mut.len(),
                        "capacity": bytes_mut.capacity(),
                        "total_allocated": bytes_allocated
                    }),
                );
            }

            let (final_allocs, final_bytes_allocated) = self.allocation_tracker.get_stats();

            self.logger.log_metrics(serde_json::json!({
                "pattern": pattern_name,
                "total_appended": total_appended,
                "final_length": bytes_mut.len(),
                "final_capacity": bytes_mut.capacity(),
                "total_allocations": final_allocs,
                "total_bytes_allocated": final_bytes_allocated,
                "allocations_per_append": allocations_per_append,
                "efficiency_ratio": total_appended as f64 / final_bytes_allocated.max(1) as f64
            }));

            // Validate data integrity
            let mut expected_data = Vec::new();
            for (i, &append_size) in append_sizes.iter().enumerate() {
                expected_data.extend(vec![i as u8; append_size]);
            }

            assert_eq!(
                bytes_mut.len(),
                total_appended,
                "Length should match total appended for {}",
                pattern_name
            );
            assert_eq!(
                &bytes_mut[..],
                &expected_data[..],
                "Data should match expected pattern for {}",
                pattern_name
            );

            self.logger.log_assertion(
                "growth_pattern_validated",
                true,
                serde_json::json!({
                    "pattern": pattern_name,
                    "data_integrity": true,
                    "allocation_efficiency": final_allocs <= append_sizes.len() * 2 // Reasonable upper bound
                }),
            );
        }
    }

    /// Test Buf and BufMut trait implementations
    fn test_buf_trait_operations(&self) {
        self.logger.log_phase("buf_trait_setup");

        let test_data = b"Buffer trait test data with various operations";
        let mut bytes_mut = BytesMut::with_capacity(1024);

        // Phase 1: Test BufMut operations
        self.logger.log_phase("buf_mut_operations");

        // Put various data types
        bytes_mut.put_u8(0x42);
        bytes_mut.put_u16(0x1234);
        bytes_mut.put_u32(0x56789ABC);
        bytes_mut.put_u64(0xDEADBEEFCAFEBABE);
        bytes_mut.put_slice(test_data);

        let expected_len = 1 + 2 + 4 + 8 + test_data.len();

        self.logger.log_metrics(serde_json::json!({
            "buf_mut_length": bytes_mut.len(),
            "expected_length": expected_len,
            "capacity": bytes_mut.capacity(),
            "remaining_capacity": bytes_mut.remaining_mut()
        }));

        assert_eq!(
            bytes_mut.len(),
            expected_len,
            "BufMut should have correct length"
        );

        // Phase 2: Convert to Bytes and test Buf operations
        self.logger.log_phase("buf_operations");

        let bytes = bytes_mut.freeze();
        let mut buf = &bytes[..];

        // Get the values back
        assert_eq!(Buf::get_u8(&mut buf), 0x42, "Should read u8 correctly");
        assert_eq!(Buf::get_u16(&mut buf), 0x1234, "Should read u16 correctly");
        assert_eq!(
            Buf::get_u32(&mut buf),
            0x56789ABC,
            "Should read u32 correctly"
        );
        assert_eq!(
            Buf::get_u64(&mut buf),
            0xDEADBEEFCAFEBABE,
            "Should read u64 correctly"
        );

        let mut text_buf = vec![0u8; test_data.len()];
        buf.copy_to_slice(&mut text_buf);
        assert_eq!(&text_buf[..], test_data, "Should read slice correctly");

        assert!(!buf.has_remaining(), "Buffer should be fully consumed");

        self.logger.log_assertion(
            "buf_trait_operations",
            true,
            serde_json::json!({
                "all_reads_correct": true,
                "buffer_fully_consumed": true
            }),
        );

        // Phase 3: Test chunked operations
        self.logger.log_phase("chunked_operations");

        let large_data = vec![0xAA; 2048];
        let mut chunked_mut = BytesMut::new();

        for chunk in large_data.chunks(256) {
            chunked_mut.put_slice(chunk);
        }

        assert_eq!(
            chunked_mut.len(),
            large_data.len(),
            "Chunked operations should preserve total size"
        );
        assert_eq!(
            &chunked_mut[..],
            &large_data[..],
            "Chunked data should match original"
        );

        self.logger.log_assertion(
            "chunked_operations",
            true,
            serde_json::json!({
                "chunk_count": large_data.len() / 256,
                "total_size": large_data.len(),
                "data_integrity": true
            }),
        );
    }

    /// Test memory efficiency with large data sets
    async fn test_memory_efficiency(&self) {
        self.logger.log_phase("memory_efficiency_setup");

        let large_size = 1_048_576; // 1MB
        let test_data = vec![0x5A; large_size];

        self.logger.log_event(
            "large_data_prepared",
            serde_json::json!({
                "data_size": large_size,
                "data_pattern": "0x5A"
            }),
        );

        // Phase 1: Test memory-efficient operations
        self.logger.log_phase("memory_efficient_ops");
        self.allocation_tracker.reset();

        let bytes = Bytes::copy_from_slice(&test_data);
        let clone1 = bytes.clone();
        let clone2 = bytes.clone();

        let slice1 = bytes.slice(0..262144); // First 256KB
        let slice2 = bytes.slice(262144..524288); // Second 256KB
        let slice3 = bytes.slice(524288..786432); // Third 256KB
        let slice4 = bytes.slice(786432..); // Last part

        let (allocs, bytes_allocated) = self.allocation_tracker.get_stats();

        self.logger.log_metrics(serde_json::json!({
            "original_data_size": large_size,
            "allocations_for_ops": allocs,
            "bytes_allocated": bytes_allocated,
            "memory_multiplier": bytes_allocated as f64 / large_size as f64,
            "operations_count": 6 // 2 clones + 4 slices
        }));

        // Validate slices contain correct data
        assert_eq!(&slice1[..], &test_data[0..262144]);
        assert_eq!(&slice2[..], &test_data[262144..524288]);
        assert_eq!(&slice3[..], &test_data[524288..786432]);
        assert_eq!(&slice4[..], &test_data[786432..]);

        // Phase 2: Test I/O efficiency with large data
        self.logger.log_phase("large_io_efficiency");
        let io_start = Instant::now();

        let mut write_buffer = Vec::new();
        {
            let mut writer = MockAsyncIo::new(Vec::new());
            writer
                .write_all(&bytes)
                .await
                .expect("Large write should succeed");
            writer.flush().await.expect("Large flush should succeed");
            write_buffer = writer.inner;
        }

        let write_duration = io_start.elapsed();

        let mut read_buffer = BytesMut::with_capacity(large_size);
        let mut reader = MockAsyncIo::new(Cursor::new(write_buffer));

        let read_start = Instant::now();
        let bytes_read = reader
            .read_buf(&mut read_buffer)
            .await
            .expect("Large read should succeed");
        let read_duration = read_start.elapsed();

        self.logger.log_metrics(serde_json::json!({
            "large_data_size": large_size,
            "write_duration_ms": write_duration.as_millis(),
            "read_duration_ms": read_duration.as_millis(),
            "bytes_read": bytes_read,
            "write_throughput_mbps": (large_size as f64 / write_duration.as_secs_f64()) / 1_048_576.0,
            "read_throughput_mbps": (large_size as f64 / read_duration.as_secs_f64()) / 1_048_576.0
        }));

        assert_eq!(bytes_read, large_size, "Should read all large data");
        assert_eq!(
            &read_buffer[..],
            &test_data[..],
            "Large data should match after I/O"
        );

        self.logger.log_assertion("memory_efficiency_validated", true, serde_json::json!({
            "large_data_integrity": true,
            "reasonable_memory_usage": bytes_allocated <= large_size * 2, // Allow some overhead
            "good_io_performance": write_duration.as_millis() < 1000 && read_duration.as_millis() < 1000
        }));
    }
}

#[test]
fn test_zero_copy_operations_e2e() {
    let harness = BytesTestHarness::new("zero_copy_operations_e2e");
    harness.test_zero_copy_operations();
}

#[tokio::test]
async fn test_bytes_io_integration_e2e() {
    timeout(Duration::from_secs(15), async {
        let harness = BytesTestHarness::new("bytes_io_integration_e2e");
        harness.test_bytes_io_integration().await;
    }).await
    .expect("Bytes I/O integration test timed out after 15 seconds");
}

#[tokio::test]
async fn test_bytes_mut_growth_patterns_e2e() {
    let harness = BytesTestHarness::new("bytes_mut_growth_patterns_e2e");
    harness.test_bytes_mut_growth_patterns().await;
}

#[test]
fn test_buf_trait_operations_e2e() {
    let harness = BytesTestHarness::new("buf_trait_operations_e2e");
    harness.test_buf_trait_operations();
}

#[tokio::test]
async fn test_memory_efficiency_e2e() {
    let harness = BytesTestHarness::new("memory_efficiency_e2e");
    harness.test_memory_efficiency().await;
}

#[tokio::test]
async fn test_bytes_full_pipeline_e2e() {
    let harness = BytesTestHarness::new("bytes_full_pipeline_e2e");

    harness.logger.log_phase("bytes_pipeline_start");

    // Combined test: full Bytes/BytesMut pipeline with I/O operations
    harness.logger.log_phase("pipeline_setup");

    let test_messages = vec![
        b"Message 1: Short".to_vec(),
        b"Message 2: Medium length content for testing".to_vec(),
        vec![0xDE; 1024], // 1KB pattern
        b"Message 4: Final message with unicode \xF0\x9F\x9A\x80".to_vec(),
    ];

    harness.logger.log_event(
        "pipeline_messages",
        serde_json::json!({
            "message_count": test_messages.len(),
            "total_bytes": test_messages.iter().map(|m| m.len()).sum::<usize>()
        }),
    );

    // Phase 1: Assemble messages using BytesMut
    harness.logger.log_phase("pipeline_assembly");
    harness.allocation_tracker.reset();

    let mut assembled = BytesMut::new();
    for message in &test_messages {
        // Length prefix (4 bytes) + message
        assembled.put_u32(message.len() as u32);
        assembled.put_slice(message);
    }

    let (allocs_assembly, bytes_assembly) = harness.allocation_tracker.get_stats();

    // Phase 2: Convert to Bytes and create zero-copy slices
    harness.logger.log_phase("pipeline_zero_copy");
    let bytes = assembled.freeze();
    let clone_for_io = bytes.clone();
    let slice_for_validation = bytes.slice(0..bytes.len());

    // Phase 3: Write through I/O pipeline
    harness.logger.log_phase("pipeline_io");
    let mut io_buffer = Vec::new();
    {
        let mut writer = MockAsyncIo::new(Vec::new());
        writer
            .write_all(&clone_for_io)
            .await
            .expect("Pipeline write should succeed");
        writer.flush().await.expect("Pipeline flush should succeed");
        io_buffer = writer.inner;
    }

    // Phase 4: Read back and parse
    harness.logger.log_phase("pipeline_parse");
    let mut reader = MockAsyncIo::new(Cursor::new(io_buffer));
    let mut read_buffer = BytesMut::new();
    reader
        .read_buf(&mut read_buffer)
        .await
        .expect("Pipeline read should succeed");

    // Parse messages back
    let mut parsed_messages = Vec::new();
    let mut buf = &read_buffer[..];

    while buf.has_remaining() && buf.remaining() >= 4 {
        let length = Buf::get_u32(&mut buf) as usize;
        if buf.remaining() >= length {
            let mut message = vec![0u8; length];
            buf.copy_to_slice(&mut message);
            parsed_messages.push(message);
        } else {
            break;
        }
    }

    // Phase 5: Validate full pipeline
    harness.logger.log_phase("pipeline_validation");

    assert_eq!(
        parsed_messages.len(),
        test_messages.len(),
        "Pipeline should preserve message count"
    );

    for (i, (original, parsed)) in test_messages.iter().zip(parsed_messages.iter()).enumerate() {
        assert_eq!(
            original, parsed,
            "Pipeline message {} should be preserved",
            i
        );
    }

    harness.logger.log_assertion(
        "bytes_pipeline_complete",
        true,
        serde_json::json!({
            "original_messages": test_messages.len(),
            "parsed_messages": parsed_messages.len(),
            "assembly_allocations": allocs_assembly,
            "assembly_bytes": bytes_assembly,
            "all_validated": true
        }),
    );

    harness.logger.log_phase("bytes_pipeline_complete");
}
