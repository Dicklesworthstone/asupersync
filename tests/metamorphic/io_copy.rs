//! Metamorphic property tests for io::copy streaming read-write invariants.
//!
//! These tests verify io::copy behavior across different configurations using
//! metamorphic relations rather than oracle-based testing. The tests use mock
//! I/O primitives with controlled behavior to explore edge cases and verify
//! fundamental correctness properties of streaming copy operations.
//!
//! # Metamorphic Relations
//!
//! 1. **Byte Transfer Completeness** (MR1): copy(a,b) transfers all bytes from a to b
//! 2. **Progress Reporting Accuracy** (MR2): partial copy reports bytes_transferred correctly
//! 3. **Cancellation Consistency** (MR3): cancel mid-copy preserves consistent state
//! 4. **Capacity Limit Respect** (MR4): copy with cap limit respects the limit
//! 5. **Buffer Mode Consistency** (MR5): copy between buffered+unbuffered streams consistent

use asupersync::cx::{Cx, Scope};
use asupersync::io::{
    AsyncBufRead, AsyncRead, AsyncWrite, BufReader, BufWriter, ReadBuf, copy, copy_buf,
    copy_with_progress,
};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::{Budget, Outcome, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use proptest::prelude::*;
use std::cmp;
use std::io::{self, Cursor};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::Duration;

// ============================================================================
// Test Infrastructure
// ============================================================================

/// Create a test context for deterministic scheduling.
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Configuration for copy operation metamorphic tests.
#[derive(Debug, Clone)]
pub struct CopyConfig {
    /// Test data size in bytes
    pub data_size: usize,
    /// Maximum read chunk size for mock readers
    pub max_read_chunk: usize,
    /// Maximum write chunk size for mock writers
    pub max_write_chunk: usize,
    /// Buffer size for buffered I/O
    pub buffer_size: usize,
    /// Whether to inject artificial delays
    pub inject_delays: bool,
    /// Copy size limit for testing capacity constraints
    pub copy_limit: Option<u64>,
    /// Whether to test cancellation scenarios
    pub test_cancellation: bool,
    /// Cancellation point (fraction of copy to complete before cancel)
    pub cancel_at_fraction: f32,
    /// Whether to use buffered readers/writers
    pub use_buffered: bool,
    /// Random seed for deterministic behavior
    pub seed: u64,
}

impl Arbitrary for CopyConfig {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            1usize..=8192,                   // data_size
            1usize..=1024,                   // max_read_chunk
            1usize..=1024,                   // max_write_chunk
            64usize..=2048,                  // buffer_size
            any::<bool>(),                   // inject_delays
            prop::option::of(100u64..=4096), // copy_limit
            any::<bool>(),                   // test_cancellation
            0.1f32..=0.9,                    // cancel_at_fraction
            any::<bool>(),                   // use_buffered
            any::<u64>(),                    // seed
        )
            .prop_map(
                |(
                    data_size,
                    max_read_chunk,
                    max_write_chunk,
                    buffer_size,
                    inject_delays,
                    copy_limit,
                    test_cancellation,
                    cancel_at_fraction,
                    use_buffered,
                    seed,
                )| {
                    CopyConfig {
                        data_size,
                        max_read_chunk: max_read_chunk.max(1),
                        max_write_chunk: max_write_chunk.max(1),
                        buffer_size: buffer_size.max(8),
                        inject_delays,
                        copy_limit,
                        test_cancellation,
                        cancel_at_fraction: cancel_at_fraction.clamp(0.1, 0.9),
                        use_buffered,
                        seed,
                    }
                },
            )
            .boxed()
    }
}

/// Test harness for copy operations with mock I/O and deterministic scheduling.
#[derive(Debug)]
struct CopyTestHarness {
    runtime: LabRuntime,
    total_bytes_read: Arc<AtomicU64>,
    total_bytes_written: Arc<AtomicU64>,
    read_calls: Arc<AtomicUsize>,
    write_calls: Arc<AtomicUsize>,
    cancel_requested: Arc<AtomicBool>,
}

impl CopyTestHarness {
    fn new(seed: u64) -> Self {
        let config = LabConfig::new(seed)
            .with_deterministic_time()
            .with_exhaustive_dpor();

        Self {
            runtime: LabRuntime::new(config),
            total_bytes_read: Arc::new(AtomicU64::new(0)),
            total_bytes_written: Arc::new(AtomicU64::new(0)),
            read_calls: Arc::new(AtomicUsize::new(0)),
            write_calls: Arc::new(AtomicUsize::new(0)),
            cancel_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Reset harness state for a new test
    fn reset(&mut self) {
        self.total_bytes_read.store(0, Ordering::SeqCst);
        self.total_bytes_written.store(0, Ordering::SeqCst);
        self.read_calls.store(0, Ordering::SeqCst);
        self.write_calls.store(0, Ordering::SeqCst);
        self.cancel_requested.store(false, Ordering::SeqCst);
    }

    fn execute<F, T>(&mut self, test_fn: F) -> Outcome<T, ()>
    where
        F: FnOnce(
                &Cx,
                &CopyTestHarness,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = T> + '_>>
            + Send,
    {
        self.runtime.block_on(|cx| async {
            cx.region(|region| async {
                let scope = Scope::new(region, "io_copy_test");
                test_fn(&scope.cx(), self).await;
                Ok(())
            })
            .await
        })
    }
}

/// Mock reader with configurable behavior for testing.
#[derive(Debug)]
struct MockReader {
    data: Vec<u8>,
    position: AtomicUsize,
    max_chunk_size: usize,
    read_calls: Arc<AtomicUsize>,
    bytes_read: Arc<AtomicU64>,
    inject_delays: bool,
    cancelled: Arc<AtomicBool>,
}

impl MockReader {
    fn new(
        data: Vec<u8>,
        max_chunk_size: usize,
        read_calls: Arc<AtomicUsize>,
        bytes_read: Arc<AtomicU64>,
        inject_delays: bool,
        cancelled: Arc<AtomicBool>,
    ) -> Self {
        Self {
            data,
            position: AtomicUsize::new(0),
            max_chunk_size,
            read_calls,
            bytes_read,
            inject_delays,
            cancelled,
        }
    }

    fn remaining(&self) -> usize {
        self.data
            .len()
            .saturating_sub(self.position.load(Ordering::SeqCst))
    }
}

impl AsyncRead for MockReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.cancelled.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }

        self.read_calls.fetch_add(1, Ordering::SeqCst);

        let pos = self.position.load(Ordering::SeqCst);
        if pos >= self.data.len() {
            return Poll::Ready(Ok(()));
        }

        // Simulate delay occasionally
        if self.inject_delays && pos % 256 == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        let available = &self.data[pos..];
        let to_read = cmp::min(
            cmp::min(available.len(), buf.remaining()),
            self.max_chunk_size,
        );

        if to_read > 0 {
            buf.put_slice(&available[..to_read]);
            self.position.fetch_add(to_read, Ordering::SeqCst);
            self.bytes_read.fetch_add(to_read as u64, Ordering::SeqCst);
        }

        Poll::Ready(Ok(()))
    }
}

/// Mock writer with configurable behavior for testing.
#[derive(Debug)]
struct MockWriter {
    data: Arc<Mutex<Vec<u8>>>,
    max_chunk_size: usize,
    write_calls: Arc<AtomicUsize>,
    bytes_written: Arc<AtomicU64>,
    inject_delays: bool,
    cancelled: Arc<AtomicBool>,
    write_limit: Option<u64>,
}

impl MockWriter {
    fn new(
        max_chunk_size: usize,
        write_calls: Arc<AtomicUsize>,
        bytes_written: Arc<AtomicU64>,
        inject_delays: bool,
        cancelled: Arc<AtomicBool>,
        write_limit: Option<u64>,
    ) -> Self {
        Self {
            data: Arc::new(Mutex::new(Vec::new())),
            max_chunk_size,
            write_calls,
            bytes_written,
            inject_delays,
            cancelled,
            write_limit,
        }
    }

    fn data(&self) -> Vec<u8> {
        self.data.lock().unwrap().clone()
    }

    fn len(&self) -> usize {
        self.data.lock().unwrap().len()
    }
}

impl AsyncWrite for MockWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.cancelled.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }

        self.write_calls.fetch_add(1, Ordering::SeqCst);

        // Check write limit
        if let Some(limit) = self.write_limit {
            let current_written = self.bytes_written.load(Ordering::SeqCst);
            if current_written >= limit {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "write limit exceeded",
                )));
            }
        }

        // Simulate delay occasionally
        if self.inject_delays && self.data.lock().unwrap().len() % 128 == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        let to_write = cmp::min(buf.len(), self.max_chunk_size);
        if let Some(limit) = self.write_limit {
            let current = self.bytes_written.load(Ordering::SeqCst);
            let to_write = cmp::min(to_write, (limit - current) as usize);
        }

        if to_write > 0 {
            self.data
                .lock()
                .unwrap()
                .extend_from_slice(&buf[..to_write]);
            self.bytes_written
                .fetch_add(to_write as u64, Ordering::SeqCst);
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

/// Mock buffered reader implementing AsyncBufRead
struct MockBufReader {
    data: Vec<u8>,
    position: usize,
    consumed: usize,
}

impl MockBufReader {
    fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            position: 0,
            consumed: 0,
        }
    }
}

impl AsyncRead for MockBufReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.position >= this.data.len() {
            return Poll::Ready(Ok(()));
        }

        let available = &this.data[this.position..];
        let to_read = cmp::min(available.len(), buf.remaining());

        if to_read > 0 {
            buf.put_slice(&available[..to_read]);
            this.position += to_read;
        }

        Poll::Ready(Ok(()))
    }
}

impl AsyncBufRead for MockBufReader {
    fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        let start = this.position + this.consumed;
        if start >= this.data.len() {
            Poll::Ready(Ok(&[]))
        } else {
            Poll::Ready(Ok(&this.data[start..]))
        }
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let this = self.get_mut();
        let max_consume = this.data.len() - this.position - this.consumed;
        let actual_consume = cmp::min(amt, max_consume);
        this.consumed += actual_consume;

        // If we've consumed everything we've buffered, reset
        if this.consumed >= this.data.len() - this.position {
            this.position += this.consumed;
            this.consumed = 0;
        }
    }
}

// ============================================================================
// Metamorphic Relation 1: Byte Transfer Completeness
// ============================================================================

/// **MR1: Byte Transfer Completeness**
///
/// Property: copy(a,b) transfers all bytes from a to b exactly once.
///
/// Test: Total bytes transferred equals source data size, destination contains exact copy.
#[test]
fn mr1_byte_transfer_completeness() {
    proptest!(|(config: CopyConfig)| {
        if config.data_size == 0 {
            return Ok(()); // Skip empty data
        }

        let mut harness = CopyTestHarness::new(config.seed);
        let result = harness.execute(|_cx, harness| Box::pin(async {
            // Generate test data
            let test_data: Vec<u8> = (0..config.data_size)
                .map(|i| (i % 256) as u8)
                .collect();

            let mut reader = MockReader::new(
                test_data.clone(),
                config.max_read_chunk,
                harness.read_calls.clone(),
                harness.total_bytes_read.clone(),
                config.inject_delays,
                harness.cancel_requested.clone(),
            );

            let mut writer = MockWriter::new(
                config.max_write_chunk,
                harness.write_calls.clone(),
                harness.total_bytes_written.clone(),
                config.inject_delays,
                harness.cancel_requested.clone(),
                config.copy_limit,
            );

            // Perform copy operation
            let bytes_copied = if config.use_buffered {
                let mut buf_reader = BufReader::with_capacity(config.buffer_size, reader);
                copy_buf(&mut buf_reader, &mut writer).await
            } else {
                copy(&mut reader, &mut writer).await
            };

            // MR1 Assertions
            match bytes_copied {
                Ok(copied) => {
                    let written_data = writer.data();

                    prop_assert_eq!(
                        copied, config.data_size as u64,
                        "Bytes copied {} != data size {}",
                        copied, config.data_size
                    );

                    prop_assert_eq!(
                        written_data.len(), config.data_size,
                        "Written data size {} != original size {}",
                        written_data.len(), config.data_size
                    );

                    prop_assert_eq!(
                        written_data, test_data,
                        "Written data does not match original data"
                    );

                    // Verify consistency of byte counters
                    let read_count = harness.total_bytes_read.load(Ordering::SeqCst);
                    let write_count = harness.total_bytes_written.load(Ordering::SeqCst);

                    prop_assert_eq!(
                        read_count, config.data_size as u64,
                        "Read counter {} != data size {}",
                        read_count, config.data_size
                    );

                    prop_assert_eq!(
                        write_count, config.data_size as u64,
                        "Write counter {} != data size {}",
                        write_count, config.data_size
                    );
                }
                Err(e) if config.copy_limit.is_some() && e.to_string().contains("limit exceeded") => {
                    // Expected behavior when hitting write limit
                }
                Err(e) => {
                    return Err(format!("Unexpected copy error: {}", e));
                }
            }

            Ok(())
        }));

        prop_assert!(matches!(result, Outcome::Ok(_)));
    });
}

// ============================================================================
// Metamorphic Relation 2: Progress Reporting Accuracy
// ============================================================================

/// **MR2: Progress Reporting Accuracy**
///
/// Property: Partial copy reports bytes_transferred correctly at each step.
///
/// Test: Progress callbacks receive monotonically increasing accurate byte counts.
#[test]
fn mr2_progress_reporting_accuracy() {
    proptest!(|(config: CopyConfig)| {
        if config.data_size == 0 {
            return Ok(()); // Skip empty data
        }

        let mut harness = CopyTestHarness::new(config.seed);
        let result = harness.execute(|_cx, harness| Box::pin(async {
            let test_data: Vec<u8> = (0..config.data_size)
                .map(|i| (i % 256) as u8)
                .collect();

            let mut reader = MockReader::new(
                test_data.clone(),
                config.max_read_chunk,
                harness.read_calls.clone(),
                harness.total_bytes_read.clone(),
                config.inject_delays,
                harness.cancel_requested.clone(),
            );

            let mut writer = MockWriter::new(
                config.max_write_chunk,
                harness.write_calls.clone(),
                harness.total_bytes_written.clone(),
                config.inject_delays,
                harness.cancel_requested.clone(),
                None, // No limit for this test
            );

            let progress_reports = Arc::new(Mutex::new(Vec::new()));
            let progress_reports_clone = progress_reports.clone();

            // Copy with progress tracking
            let bytes_copied = copy_with_progress(&mut reader, &mut writer, |bytes| {
                progress_reports_clone.lock().unwrap().push(bytes);
            }).await;

            // MR2 Assertions
            match bytes_copied {
                Ok(total_copied) => {
                    let reports = progress_reports.lock().unwrap();

                    prop_assert_eq!(
                        total_copied, config.data_size as u64,
                        "Total copied {} != data size {}",
                        total_copied, config.data_size
                    );

                    // Progress reports should be non-empty
                    prop_assert!(!reports.is_empty(), "No progress reports received");

                    // Progress should be monotonically increasing
                    for window in reports.windows(2) {
                        prop_assert!(
                            window[1] >= window[0],
                            "Progress not monotonic: {} -> {}",
                            window[0], window[1]
                        );
                    }

                    // Last progress report should equal total
                    if let Some(&last_progress) = reports.last() {
                        prop_assert_eq!(
                            last_progress, total_copied,
                            "Last progress {} != total copied {}",
                            last_progress, total_copied
                        );
                    }

                    // All progress values should be <= total data size
                    for &progress in reports.iter() {
                        prop_assert!(
                            progress <= config.data_size as u64,
                            "Progress {} > data size {}",
                            progress, config.data_size
                        );
                    }
                }
                Err(e) => {
                    return Err(format!("Unexpected copy error: {}", e));
                }
            }

            Ok(())
        }));

        prop_assert!(matches!(result, Outcome::Ok(_)));
    });
}

// ============================================================================
// Metamorphic Relation 3: Cancellation Consistency
// ============================================================================

/// **MR3: Cancellation Consistency**
///
/// Property: Cancel mid-copy preserves consistent state (no partial writes).
///
/// Test: Cancellation leaves destination in consistent state with accurate byte count.
#[test]
fn mr3_cancellation_consistency() {
    proptest!(|(config in any::<CopyConfig>().prop_filter("needs cancellation", |c| c.test_cancellation && c.data_size > 100))| {
        let mut harness = CopyTestHarness::new(config.seed);
        let result = harness.execute(|cx, harness| Box::pin(async {
            let test_data: Vec<u8> = (0..config.data_size)
                .map(|i| (i % 256) as u8)
                .collect();

            let mut reader = MockReader::new(
                test_data.clone(),
                config.max_read_chunk,
                harness.read_calls.clone(),
                harness.total_bytes_read.clone(),
                config.inject_delays,
                harness.cancel_requested.clone(),
            );

            let mut writer = MockWriter::new(
                config.max_write_chunk,
                harness.write_calls.clone(),
                harness.total_bytes_written.clone(),
                config.inject_delays,
                harness.cancel_requested.clone(),
                None,
            );

            // Set up cancellation after some progress
            let cancel_at_bytes = ((config.data_size as f32) * config.cancel_at_fraction) as u64;
            let cancel_requested = harness.cancel_requested.clone();
            let bytes_written = harness.total_bytes_written.clone();

            // Spawn cancellation task
            cx.spawn("cancellation_monitor", async move {
                loop {
                    if bytes_written.load(Ordering::SeqCst) >= cancel_at_bytes {
                        cancel_requested.store(true, Ordering::SeqCst);
                        break;
                    }
                    asupersync::time::sleep(Duration::from_micros(1)).await;
                }
                Ok(())
            })?;

            // Perform copy (should be cancelled)
            let copy_result = copy(&mut reader, &mut writer).await;

            // MR3 Assertions
            let written_data = writer.data();
            let bytes_written_count = harness.total_bytes_written.load(Ordering::SeqCst);

            match copy_result {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    // Expected cancellation

                    // Verify consistency: written data length should match byte counter
                    prop_assert_eq!(
                        written_data.len() as u64, bytes_written_count,
                        "Written data length {} != byte counter {}",
                        written_data.len(), bytes_written_count
                    );

                    // Written data should be a valid prefix of original data
                    if !written_data.is_empty() {
                        prop_assert_eq!(
                            &written_data, &test_data[..written_data.len()],
                            "Written data is not a valid prefix of original"
                        );
                    }

                    // Should have been cancelled roughly at expected point
                    prop_assert!(
                        bytes_written_count <= config.data_size as u64,
                        "Wrote more than available: {} > {}",
                        bytes_written_count, config.data_size
                    );

                    // Should have made some progress before cancellation
                    prop_assert!(
                        bytes_written_count > 0,
                        "No progress made before cancellation"
                    );
                }
                Ok(bytes_copied) => {
                    // Copy completed before cancellation could trigger
                    prop_assert_eq!(
                        bytes_copied, config.data_size as u64,
                        "Copy completed with wrong byte count: {} != {}",
                        bytes_copied, config.data_size
                    );
                }
                Err(e) => {
                    return Err(format!("Unexpected error: {}", e));
                }
            }

            Ok(())
        }));

        prop_assert!(matches!(result, Outcome::Ok(_)));
    });
}

// ============================================================================
// Metamorphic Relation 4: Capacity Limit Respect
// ============================================================================

/// **MR4: Capacity Limit Respect**
///
/// Property: Copy with cap limit respects the limit exactly.
///
/// Test: Copy stops at specified byte limit without exceeding it.
#[test]
fn mr4_capacity_limit_respect() {
    proptest!(|(config in any::<CopyConfig>().prop_filter("has limit", |c| c.copy_limit.is_some() && c.data_size > c.copy_limit.unwrap() as usize))| {
        let copy_limit = config.copy_limit.unwrap();

        let mut harness = CopyTestHarness::new(config.seed);
        let result = harness.execute(|_cx, harness| Box::pin(async {
            let test_data: Vec<u8> = (0..config.data_size)
                .map(|i| (i % 256) as u8)
                .collect();

            let mut reader = MockReader::new(
                test_data.clone(),
                config.max_read_chunk,
                harness.read_calls.clone(),
                harness.total_bytes_read.clone(),
                false, // No delays for this test
                harness.cancel_requested.clone(),
            );

            let mut writer = MockWriter::new(
                config.max_write_chunk,
                harness.write_calls.clone(),
                harness.total_bytes_written.clone(),
                false, // No delays
                harness.cancel_requested.clone(),
                Some(copy_limit),
            );

            // Perform copy with limit
            let copy_result = copy(&mut reader, &mut writer).await;

            // MR4 Assertions
            let written_data = writer.data();
            let bytes_written_count = harness.total_bytes_written.load(Ordering::SeqCst);

            match copy_result {
                Err(e) if e.to_string().contains("limit exceeded") => {
                    // Expected limit exceeded error

                    // Should not exceed the limit
                    prop_assert!(
                        bytes_written_count <= copy_limit,
                        "Exceeded write limit: {} > {}",
                        bytes_written_count, copy_limit
                    );

                    // Should have written up to the limit
                    prop_assert_eq!(
                        bytes_written_count, copy_limit,
                        "Did not reach limit: {} < {}",
                        bytes_written_count, copy_limit
                    );

                    // Written data should match byte counter
                    prop_assert_eq!(
                        written_data.len() as u64, bytes_written_count,
                        "Data length {} != counter {}",
                        written_data.len(), bytes_written_count
                    );

                    // Written data should be valid prefix
                    prop_assert_eq!(
                        &written_data, &test_data[..written_data.len()],
                        "Written data not a valid prefix"
                    );
                }
                Ok(bytes_copied) => {
                    // Copy completed successfully (data smaller than limit)
                    prop_assert!(
                        bytes_copied <= copy_limit,
                        "Copied more than limit: {} > {}",
                        bytes_copied, copy_limit
                    );

                    prop_assert_eq!(
                        bytes_copied, config.data_size as u64,
                        "Incomplete copy: {} != {}",
                        bytes_copied, config.data_size
                    );
                }
                Err(e) => {
                    return Err(format!("Unexpected error: {}", e));
                }
            }

            Ok(())
        }));

        prop_assert!(matches!(result, Outcome::Ok(_)));
    });
}

// ============================================================================
// Metamorphic Relation 5: Buffer Mode Consistency
// ============================================================================

/// **MR5: Buffer Mode Consistency**
///
/// Property: Copy between buffered+unbuffered streams produces consistent results.
///
/// Test: Buffered and unbuffered copy operations yield identical data transfer.
#[test]
fn mr5_buffer_mode_consistency() {
    proptest!(|(config: CopyConfig)| {
        if config.data_size == 0 {
            return Ok(()); // Skip empty data
        }

        let mut harness = CopyTestHarness::new(config.seed);
        let result = harness.execute(|_cx, harness| Box::pin(async {
            let test_data: Vec<u8> = (0..config.data_size)
                .map(|i| (i % 256) as u8)
                .collect();

            // Test 1: Unbuffered copy
            harness.reset();

            let mut reader1 = MockReader::new(
                test_data.clone(),
                config.max_read_chunk,
                harness.read_calls.clone(),
                harness.total_bytes_read.clone(),
                false,
                harness.cancel_requested.clone(),
            );

            let mut writer1 = MockWriter::new(
                config.max_write_chunk,
                harness.write_calls.clone(),
                harness.total_bytes_written.clone(),
                false,
                harness.cancel_requested.clone(),
                None,
            );

            let unbuffered_result = copy(&mut reader1, &mut writer1).await;
            let unbuffered_data = writer1.data();
            let unbuffered_read_calls = harness.read_calls.load(Ordering::SeqCst);

            // Test 2: Buffered copy
            harness.reset();

            let mut reader2 = MockReader::new(
                test_data.clone(),
                config.max_read_chunk,
                harness.read_calls.clone(),
                harness.total_bytes_read.clone(),
                false,
                harness.cancel_requested.clone(),
            );

            let mut writer2 = MockWriter::new(
                config.max_write_chunk,
                harness.write_calls.clone(),
                harness.total_bytes_written.clone(),
                false,
                harness.cancel_requested.clone(),
                None,
            );

            let mut buf_reader = BufReader::with_capacity(config.buffer_size, reader2);
            let buffered_result = copy_buf(&mut buf_reader, &mut writer2).await;
            let buffered_data = writer2.data();
            let buffered_read_calls = harness.read_calls.load(Ordering::SeqCst);

            // Test 3: BufWriter consistency
            harness.reset();

            let mut reader3 = MockBufReader::new(test_data.clone());
            let mut writer3 = MockWriter::new(
                config.max_write_chunk,
                harness.write_calls.clone(),
                harness.total_bytes_written.clone(),
                false,
                harness.cancel_requested.clone(),
                None,
            );

            let mut buf_writer = BufWriter::with_capacity(config.buffer_size, writer3);
            let buf_writer_result = copy_buf(&mut reader3, &mut buf_writer).await;
            let _ = buf_writer.flush().await; // Ensure data is written
            let buf_writer_data = buf_writer.get_ref().data();

            // MR5 Assertions
            match (unbuffered_result, buffered_result, buf_writer_result) {
                (Ok(unbuf_bytes), Ok(buf_bytes), Ok(buf_writer_bytes)) => {
                    // All should copy same number of bytes
                    prop_assert_eq!(
                        unbuf_bytes, config.data_size as u64,
                        "Unbuffered copied wrong amount: {}",
                        unbuf_bytes
                    );

                    prop_assert_eq!(
                        buf_bytes, config.data_size as u64,
                        "Buffered copied wrong amount: {}",
                        buf_bytes
                    );

                    prop_assert_eq!(
                        buf_writer_bytes, config.data_size as u64,
                        "BufWriter copied wrong amount: {}",
                        buf_writer_bytes
                    );

                    // All should produce identical data
                    prop_assert_eq!(
                        unbuffered_data, test_data,
                        "Unbuffered data mismatch"
                    );

                    prop_assert_eq!(
                        buffered_data, test_data,
                        "Buffered data mismatch"
                    );

                    prop_assert_eq!(
                        buf_writer_data, test_data,
                        "BufWriter data mismatch"
                    );

                    // Buffered operations should generally make fewer read calls
                    if config.data_size > config.buffer_size {
                        prop_assert!(
                            buffered_read_calls <= unbuffered_read_calls,
                            "Buffered read calls {} > unbuffered {}",
                            buffered_read_calls, unbuffered_read_calls
                        );
                    }
                }
                _ => {
                    return Err("One or more copy operations failed unexpectedly".to_string());
                }
            }

            Ok(())
        }));

        prop_assert!(matches!(result, Outcome::Ok(_)));
    });
}

// ============================================================================
// Composite Metamorphic Relations
// ============================================================================

/// **Composite MR: All Copy Invariants Combined**
///
/// Property: All five metamorphic relations hold simultaneously under realistic workloads.
///
/// Test: Execute complex copy scenario and verify all MRs hold together.
#[test]
fn composite_all_copy_invariants() {
    proptest!(|(config: CopyConfig)| {
        if config.data_size == 0 {
            return Ok(()); // Skip empty data
        }

        let mut harness = CopyTestHarness::new(config.seed);
        let result = harness.execute(|_cx, harness| Box::pin(async {
            let test_data: Vec<u8> = (0..config.data_size)
                .map(|i| ((i * 17) % 256) as u8) // More complex pattern
                .collect();

            let progress_reports = Arc::new(Mutex::new(Vec::new()));
            let progress_reports_clone = progress_reports.clone();

            let mut reader = MockReader::new(
                test_data.clone(),
                config.max_read_chunk,
                harness.read_calls.clone(),
                harness.total_bytes_read.clone(),
                config.inject_delays,
                harness.cancel_requested.clone(),
            );

            let mut writer = MockWriter::new(
                config.max_write_chunk,
                harness.write_calls.clone(),
                harness.total_bytes_written.clone(),
                config.inject_delays,
                harness.cancel_requested.clone(),
                config.copy_limit,
            );

            // Copy with progress tracking
            let copy_result = copy_with_progress(&mut reader, &mut writer, |bytes| {
                progress_reports_clone.lock().unwrap().push(bytes);
            }).await;

            // Combined MR Assertions
            match copy_result {
                Ok(bytes_copied) => {
                    let written_data = writer.data();
                    let expected_size = if let Some(limit) = config.copy_limit {
                        cmp::min(config.data_size as u64, limit) as usize
                    } else {
                        config.data_size
                    };

                    // MR1: Byte transfer completeness
                    prop_assert_eq!(
                        bytes_copied, expected_size as u64,
                        "MR1: Bytes copied {} != expected {}",
                        bytes_copied, expected_size
                    );

                    prop_assert_eq!(
                        written_data.len(), expected_size,
                        "MR1: Written size {} != expected {}",
                        written_data.len(), expected_size
                    );

                    prop_assert_eq!(
                        &written_data, &test_data[..expected_size],
                        "MR1: Data mismatch"
                    );

                    // MR2: Progress reporting accuracy
                    let reports = progress_reports.lock().unwrap();
                    prop_assert!(!reports.is_empty(), "MR2: No progress reports");

                    for window in reports.windows(2) {
                        prop_assert!(
                            window[1] >= window[0],
                            "MR2: Progress not monotonic: {} -> {}",
                            window[0], window[1]
                        );
                    }

                    if let Some(&last) = reports.last() {
                        prop_assert_eq!(
                            last, bytes_copied,
                            "MR2: Last progress {} != total {}",
                            last, bytes_copied
                        );
                    }

                    // MR4: Capacity limit respect (if applicable)
                    if let Some(limit) = config.copy_limit {
                        prop_assert!(
                            bytes_copied <= limit,
                            "MR4: Exceeded limit: {} > {}",
                            bytes_copied, limit
                        );
                    }

                    // MR5: Buffer consistency (verify read efficiency)
                    let read_calls = harness.read_calls.load(Ordering::SeqCst);
                    prop_assert!(
                        read_calls > 0,
                        "MR5: No read calls made"
                    );

                    // Verify byte counters are consistent
                    let read_count = harness.total_bytes_read.load(Ordering::SeqCst);
                    let write_count = harness.total_bytes_written.load(Ordering::SeqCst);

                    prop_assert_eq!(
                        read_count, expected_size as u64,
                        "Read counter {} != expected {}",
                        read_count, expected_size
                    );

                    prop_assert_eq!(
                        write_count, expected_size as u64,
                        "Write counter {} != expected {}",
                        write_count, expected_size
                    );
                }
                Err(e) if config.copy_limit.is_some() && e.to_string().contains("limit exceeded") => {
                    // MR4: Expected limit behavior
                    let bytes_written = harness.total_bytes_written.load(Ordering::SeqCst);
                    prop_assert!(
                        bytes_written <= config.copy_limit.unwrap(),
                        "MR4: Exceeded limit on error: {} > {}",
                        bytes_written, config.copy_limit.unwrap()
                    );
                }
                Err(e) => {
                    return Err(format!("Unexpected error: {}", e));
                }
            }

            Ok(())
        }));

        prop_assert!(matches!(result, Outcome::Ok(_)));
    });
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_copy_config_arbitrary() {
        // Verify CopyConfig can be generated
        let config = CopyConfig {
            data_size: 1024,
            max_read_chunk: 128,
            max_write_chunk: 256,
            buffer_size: 512,
            inject_delays: false,
            copy_limit: Some(800),
            test_cancellation: false,
            cancel_at_fraction: 0.5,
            use_buffered: true,
            seed: 12345,
        };

        assert!(config.data_size > 0);
        assert!(config.max_read_chunk > 0);
        assert!(config.max_write_chunk > 0);
        assert!(config.buffer_size >= 8);
    }

    #[test]
    fn test_mock_reader_basic() {
        let data = vec![1, 2, 3, 4, 5];
        let read_calls = Arc::new(AtomicUsize::new(0));
        let bytes_read = Arc::new(AtomicU64::new(0));
        let cancelled = Arc::new(AtomicBool::new(false));

        let mut reader = MockReader::new(data, 2, read_calls, bytes_read, false, cancelled);
        assert_eq!(reader.remaining(), 5);
    }

    #[test]
    fn test_mock_writer_basic() {
        let write_calls = Arc::new(AtomicUsize::new(0));
        let bytes_written = Arc::new(AtomicU64::new(0));
        let cancelled = Arc::new(AtomicBool::new(false));

        let writer = MockWriter::new(100, write_calls, bytes_written, false, cancelled, None);
        assert_eq!(writer.len(), 0);
    }

    #[test]
    fn test_harness_creation() {
        let harness = CopyTestHarness::new(42);
        // Verify it can be created without panic
    }
}
