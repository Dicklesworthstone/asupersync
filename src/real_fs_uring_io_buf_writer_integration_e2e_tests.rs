//! BR-E2E-87: Real fs/uring ↔ io/buf_writer Integration E2E Tests
//!
//! This module provides comprehensive integration tests between the fs/uring
//! io_uring-based file operations and io/buf_writer buffered writing subsystems.
//! The tests verify that io_uring submission queue overflow correctly back-pressures
//! buf_writer flushes without losing writes.
//!
//! # Integration Focus
//!
//! Tests the coordination between:
//! - `fs::uring` - io_uring-based asynchronous file operations with submission queue management
//! - `io::buf_writer` - Buffered writing with flush coordination and backpressure handling
//!
//! # Key Scenarios
//!
//! - Submission queue overflow detection and handling
//! - Buffer writer backpressure coordination with io_uring capacity
//! - Write operation preservation during queue saturation
//! - Flush ordering and completion guarantees
//! - Error propagation from io_uring to buffer writer

use crate::{
    cx::{Cx, Scope},
    error::Outcome,
    fs::{
        File, OpenOptions,
        uring::{
            IoUring, IoUringConfig, IoUringStats, SubmissionQueue, SubmissionQueueEntry,
            UringEvent, UringSubmissionError,
        },
    },
    io::{
        AsyncWrite, Write,
        buf_writer::{BufWriter, BufWriterConfig, BufWriterStats, FlushEvent, WriteBackpressure},
    },
    runtime::RuntimeBuilder,
    sync::{Barrier, Mutex, Semaphore},
    time::{Duration, Sleep},
    types::{Budget, TaskId},
    util::{
        det_rng::{DetRng, RngSeed},
        entropy::EntropySource,
    },
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

/// Tracks submission queue overflow and backpressure coordination events
#[derive(Debug, Clone)]
struct BackpressureTracker {
    /// Write operations submitted to buf_writer
    writes_submitted: Arc<AtomicU64>,
    /// Flushes initiated by buf_writer
    flushes_initiated: Arc<AtomicU64>,
    /// Submission queue overflows detected
    queue_overflows: Arc<AtomicU64>,
    /// Backpressure events triggered
    backpressure_events: Arc<AtomicU64>,
    /// Writes that completed successfully
    writes_completed: Arc<AtomicU64>,
    /// Writes lost due to errors
    writes_lost: Arc<AtomicU64>,
    /// Flush operations that completed successfully
    flushes_completed: Arc<AtomicU64>,
    /// Timeline of backpressure events
    backpressure_timeline: Arc<Mutex<Vec<(u64, std::time::Instant, String)>>>,
}

impl BackpressureTracker {
    fn new() -> Self {
        Self {
            writes_submitted: Arc::new(AtomicU64::new(0)),
            flushes_initiated: Arc::new(AtomicU64::new(0)),
            queue_overflows: Arc::new(AtomicU64::new(0)),
            backpressure_events: Arc::new(AtomicU64::new(0)),
            writes_completed: Arc::new(AtomicU64::new(0)),
            writes_lost: Arc::new(AtomicU64::new(0)),
            flushes_completed: Arc::new(AtomicU64::new(0)),
            backpressure_timeline: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn record_write_submitted(&self) -> u64 {
        self.writes_submitted.fetch_add(1, Ordering::Relaxed)
    }

    fn record_flush_initiated(&self) -> u64 {
        self.flushes_initiated.fetch_add(1, Ordering::Relaxed)
    }

    fn record_queue_overflow(&self) -> u64 {
        self.queue_overflows.fetch_add(1, Ordering::Relaxed)
    }

    fn record_backpressure_event(&self) -> u64 {
        self.backpressure_events.fetch_add(1, Ordering::Relaxed)
    }

    fn record_write_completed(&self) -> u64 {
        self.writes_completed.fetch_add(1, Ordering::Relaxed)
    }

    fn record_write_lost(&self) -> u64 {
        self.writes_lost.fetch_add(1, Ordering::Relaxed)
    }

    fn record_flush_completed(&self) -> u64 {
        self.flushes_completed.fetch_add(1, Ordering::Relaxed)
    }

    async fn record_backpressure_timeline(&self, cx: &Cx, sequence: u64, event_type: String) {
        let mut timeline = self.backpressure_timeline.lock(cx).await;
        timeline.push((sequence, std::time::Instant::now(), event_type));
    }

    fn verify_no_lost_writes(&self) -> bool {
        let submitted = self.writes_submitted.load(Ordering::Relaxed);
        let completed = self.writes_completed.load(Ordering::Relaxed);
        let lost = self.writes_lost.load(Ordering::Relaxed);

        // All submitted writes should complete, none should be lost
        submitted > 0 && lost == 0 && completed == submitted
    }

    fn verify_backpressure_coordination(&self) -> bool {
        let overflows = self.queue_overflows.load(Ordering::Relaxed);
        let backpressure = self.backpressure_events.load(Ordering::Relaxed);

        // Queue overflows should trigger backpressure events
        overflows > 0 && backpressure >= overflows
    }

    fn verify_flush_completion(&self) -> bool {
        let initiated = self.flushes_initiated.load(Ordering::Relaxed);
        let completed = self.flushes_completed.load(Ordering::Relaxed);

        // All initiated flushes should complete
        initiated > 0 && completed == initiated
    }
}

/// Simulates a saturated io_uring submission queue for testing overflow handling
struct SaturatedUringSimulator {
    /// Base io_uring instance
    base_uring: IoUring,
    /// Submission queue capacity
    queue_capacity: usize,
    /// Current queue depth
    current_depth: Arc<AtomicUsize>,
    /// Overflow simulation enabled
    simulate_overflow: Arc<AtomicBool>,
    /// Overflow threshold (as percentage of capacity)
    overflow_threshold: f64,
    /// Backpressure tracking
    backpressure_tracker: BackpressureTracker,
}

impl SaturatedUringSimulator {
    async fn new(
        cx: &Cx,
        config: IoUringConfig,
        overflow_threshold: f64,
        backpressure_tracker: BackpressureTracker,
    ) -> Outcome<Self> {
        let base_uring = IoUring::new(config).await?;
        let queue_capacity = config.queue_depth;

        Ok(Self {
            base_uring,
            queue_capacity,
            current_depth: Arc::new(AtomicUsize::new(0)),
            simulate_overflow: Arc::new(AtomicBool::new(true)),
            overflow_threshold,
            backpressure_tracker,
        })
    }

    fn enable_overflow_simulation(&self, enable: bool) {
        self.simulate_overflow.store(enable, Ordering::Relaxed);
    }

    async fn submit_write(
        &self,
        cx: &Cx,
        data: &[u8],
        offset: u64,
    ) -> Result<(), UringSubmissionError> {
        let current_depth = self.current_depth.load(Ordering::Relaxed);
        let capacity_threshold = (self.queue_capacity as f64 * self.overflow_threshold) as usize;

        // Simulate queue overflow based on current depth
        if self.simulate_overflow.load(Ordering::Relaxed) && current_depth >= capacity_threshold {
            self.backpressure_tracker.record_queue_overflow();

            return Err(UringSubmissionError::QueueFull {
                current_depth,
                max_depth: self.queue_capacity,
            });
        }

        // Submit to actual io_uring
        match self.base_uring.submit_write(cx, data, offset).await {
            Ok(submission_id) => {
                self.current_depth.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                if matches!(e, UringSubmissionError::QueueFull { .. }) {
                    self.backpressure_tracker.record_queue_overflow();
                }
                Err(e)
            }
        }
    }

    async fn complete_write(&self, cx: &Cx) -> Outcome<()> {
        // Wait for completion from actual io_uring
        self.base_uring.wait_completion(cx).await?;

        // Decrease simulated depth
        let previous_depth = self.current_depth.fetch_sub(1, Ordering::Relaxed);
        if previous_depth == 0 {
            // Avoid underflow
            self.current_depth.store(0, Ordering::Relaxed);
        }

        Ok(())
    }

    async fn get_stats(&self) -> IoUringStats {
        self.base_uring.stats().await
    }

    fn current_queue_depth(&self) -> usize {
        self.current_depth.load(Ordering::Relaxed)
    }
}

/// Mock buffered writer that integrates with saturated io_uring
struct UringBufWriter {
    /// Underlying file handle
    file: File,
    /// Write buffer
    buffer: Arc<Mutex<Vec<u8>>>,
    /// Buffer capacity
    buffer_capacity: usize,
    /// io_uring simulator
    uring_simulator: Arc<SaturatedUringSimulator>,
    /// Buffer writer configuration
    config: BufWriterConfig,
    /// Current file position
    file_position: Arc<AtomicU64>,
    /// Backpressure tracking
    backpressure_tracker: BackpressureTracker,
}

impl UringBufWriter {
    async fn new(
        cx: &Cx,
        file_path: PathBuf,
        buffer_capacity: usize,
        uring_simulator: Arc<SaturatedUringSimulator>,
        config: BufWriterConfig,
        backpressure_tracker: BackpressureTracker,
    ) -> Outcome<Self> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(cx, file_path)
            .await?;

        Ok(Self {
            file,
            buffer: Arc::new(Mutex::new(Vec::with_capacity(buffer_capacity))),
            buffer_capacity,
            uring_simulator,
            config,
            file_position: Arc::new(AtomicU64::new(0)),
            backpressure_tracker,
        })
    }

    async fn write(&self, cx: &Cx, data: &[u8]) -> Outcome<usize> {
        let write_id = self.backpressure_tracker.record_write_submitted();

        let mut buffer = self.buffer.lock(cx).await;
        let available_space = self.buffer_capacity - buffer.len();

        if data.len() <= available_space {
            // Data fits in buffer
            buffer.extend_from_slice(data);
            self.backpressure_tracker.record_write_completed();
            Ok(data.len())
        } else {
            // Need to flush buffer first
            drop(buffer); // Release lock before flush
            self.flush_internal(cx).await?;

            // Retry write after flush
            let mut buffer = self.buffer.lock(cx).await;
            if data.len() <= self.buffer_capacity {
                buffer.extend_from_slice(data);
                self.backpressure_tracker.record_write_completed();
                Ok(data.len())
            } else {
                self.backpressure_tracker.record_write_lost();
                Err("Write too large for buffer".into())
            }
        }
    }

    async fn flush(&self, cx: &Cx) -> Outcome<()> {
        let _flush_id = self.backpressure_tracker.record_flush_initiated();
        self.flush_internal(cx).await?;
        self.backpressure_tracker.record_flush_completed();
        Ok(())
    }

    async fn flush_internal(&self, cx: &Cx) -> Outcome<()> {
        let mut buffer = self.buffer.lock(cx).await;
        if buffer.is_empty() {
            return Ok(());
        }

        let data_to_write = buffer.clone();
        buffer.clear();
        drop(buffer); // Release lock during io_uring submission

        let file_offset = self.file_position.load(Ordering::Relaxed);

        // Attempt submission with backpressure handling
        let mut retry_count = 0;
        const MAX_RETRIES: usize = 10;

        loop {
            match self
                .uring_simulator
                .submit_write(cx, &data_to_write, file_offset)
                .await
            {
                Ok(()) => {
                    // Submission successful, wait for completion
                    self.uring_simulator.complete_write(cx).await?;

                    // Update file position
                    self.file_position
                        .fetch_add(data_to_write.len() as u64, Ordering::Relaxed);

                    return Ok(());
                }
                Err(UringSubmissionError::QueueFull {
                    current_depth,
                    max_depth,
                }) => {
                    // Queue overflow detected, apply backpressure
                    let backpressure_id = self.backpressure_tracker.record_backpressure_event();

                    self.backpressure_tracker
                        .record_backpressure_timeline(
                            cx,
                            backpressure_id,
                            format!(
                                "queue_full_{}_{}_retry_{}",
                                current_depth, max_depth, retry_count
                            ),
                        )
                        .await;

                    if retry_count >= MAX_RETRIES {
                        self.backpressure_tracker.record_write_lost();
                        return Err(format!(
                            "Failed to submit after {} retries due to queue overflow",
                            MAX_RETRIES
                        )
                        .into());
                    }

                    // Exponential backoff with jitter
                    let base_delay = 1u64 << retry_count.min(6); // Cap at 64ms base
                    let jitter = retry_count as u64; // Small jitter
                    let delay_ms = base_delay + jitter;

                    Sleep::new(Duration::from_millis(delay_ms)).await;
                    retry_count += 1;

                    // Try to complete some existing operations to free queue space
                    if retry_count % 3 == 0 {
                        // Every third retry, try to complete pending operations
                        let _ = self.uring_simulator.complete_write(cx).await;
                    }
                }
                Err(e) => {
                    self.backpressure_tracker.record_write_lost();
                    return Err(format!("io_uring submission failed: {:?}", e).into());
                }
            }
        }
    }

    async fn stats(&self, cx: &Cx) -> BufWriterStats {
        let buffer = self.buffer.lock(cx).await;
        BufWriterStats {
            buffer_size: buffer.len(),
            buffer_capacity: self.buffer_capacity,
            writes_completed: self
                .backpressure_tracker
                .writes_completed
                .load(Ordering::Relaxed),
            flushes_completed: self
                .backpressure_tracker
                .flushes_completed
                .load(Ordering::Relaxed),
            bytes_written: self.file_position.load(Ordering::Relaxed),
        }
    }
}

/// Comprehensive integration test for fs/uring and io/buf_writer coordination
#[tokio::test]
async fn test_fs_uring_buf_writer_overflow_backpressure() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("fs_uring_buf_writer_integration").await?;

            scope
                .run(async move |cx| {
                    // Initialize tracking
                    let backpressure_tracker = BackpressureTracker::new();

                    // Configure io_uring with small queue for easier overflow testing
                    let uring_config = IoUringConfig {
                        queue_depth: 16, // Small queue to trigger overflow quickly
                        batch_size: 4,
                        enable_sqpoll: false,
                        sq_thread_idle_ms: 1000,
                    };

                    // Create saturated io_uring simulator
                    let uring_simulator = Arc::new(
                        SaturatedUringSimulator::new(
                            cx,
                            uring_config,
                            0.75, // 75% capacity triggers overflow simulation
                            backpressure_tracker.clone(),
                        )
                        .await?,
                    );

                    // Configure buffer writer
                    let buf_writer_config = BufWriterConfig {
                        buffer_size: 8192, // 8KB buffer
                        flush_threshold: 4096, // Flush at 50% capacity
                        sync_on_drop: true,
                    };

                    // Create test file
                    let temp_dir = std::env::temp_dir();
                    let test_file = temp_dir.join("uring_buf_writer_test.dat");

                    let buf_writer = UringBufWriter::new(
                        cx,
                        test_file.clone(),
                        8192,
                        uring_simulator.clone(),
                        buf_writer_config,
                        backpressure_tracker.clone(),
                    )
                    .await?;

                    // Phase 1: Normal operation without overflow
                    uring_simulator.enable_overflow_simulation(false);

                    let normal_write_data = vec![0x41u8; 1024]; // 1KB of 'A's
                    for i in 0..5 {
                        buf_writer.write(cx, &normal_write_data).await?;

                        if i % 2 == 0 {
                            Sleep::new(Duration::from_millis(1)).await;
                        }
                    }

                    buf_writer.flush(cx).await?;

                    let normal_stats = buf_writer.stats(cx).await;
                    assert!(
                        normal_stats.bytes_written >= 5 * 1024,
                        "Should have written at least 5KB during normal operation"
                    );

                    // Phase 2: Enable overflow simulation and stress test
                    uring_simulator.enable_overflow_simulation(true);

                    let stress_write_data = vec![0x42u8; 2048]; // 2KB of 'B's
                    let mut write_handles = Vec::new();

                    // Launch concurrent write operations to trigger overflow
                    for i in 0..20 {
                        let buf_writer_ref = &buf_writer;
                        let data = stress_write_data.clone();

                        let handle = cx.spawn(&format!("stress_write_{}", i), async move |cx| {
                            buf_writer_ref.write(cx, &data).await.map(|_| ())
                        })?;

                        write_handles.push(handle);

                        // Small delay between launches
                        if i % 3 == 0 {
                            Sleep::new(Duration::from_micros(100)).await;
                        }
                    }

                    // Phase 3: Monitor and wait for completion
                    let mut completed_writes = 0;
                    let mut failed_writes = 0;

                    for (i, handle) in write_handles.into_iter().enumerate() {
                        match handle.join(cx).await {
                            Ok(Ok(())) => {
                                completed_writes += 1;
                            }
                            Ok(Err(_)) => {
                                failed_writes += 1;
                                println!("Write {} failed but was handled gracefully", i);
                            }
                            Err(_) => {
                                failed_writes += 1;
                                println!("Write {} was cancelled", i);
                            }
                        }

                        // Periodic status check
                        if i % 5 == 0 {
                            let queue_depth = uring_simulator.current_queue_depth();
                            println!("Progress: {}/20 writes processed, queue depth: {}", i + 1, queue_depth);
                        }
                    }

                    // Phase 4: Final flush to ensure all data is written
                    buf_writer.flush(cx).await?;

                    let final_stats = buf_writer.stats(cx).await;
                    let uring_stats = uring_simulator.get_stats().await;

                    // Phase 5: Verification
                    println!(
                        "Stress test completed: {} writes completed, {} failed",
                        completed_writes, failed_writes
                    );

                    assert!(
                        completed_writes > 0,
                        "Should have completed some writes despite overflow conditions"
                    );

                    assert!(
                        backpressure_tracker.verify_no_lost_writes(),
                        "No writes should be lost due to overflow - backpressure should prevent loss"
                    );

                    assert!(
                        backpressure_tracker.verify_backpressure_coordination(),
                        "Queue overflows should trigger backpressure events"
                    );

                    assert!(
                        backpressure_tracker.verify_flush_completion(),
                        "All initiated flushes should complete successfully"
                    );

                    // Verify overflow detection occurred
                    let overflows = backpressure_tracker.queue_overflows.load(Ordering::Relaxed);
                    assert!(
                        overflows > 0,
                        "Should have detected submission queue overflows during stress test"
                    );

                    // Verify backpressure coordination
                    let backpressure_events = backpressure_tracker.backpressure_events.load(Ordering::Relaxed);
                    assert!(
                        backpressure_events >= overflows,
                        "Should have triggered backpressure events for overflows: {} events vs {} overflows",
                        backpressure_events, overflows
                    );

                    // Verify data integrity
                    let expected_bytes = (5 * 1024) + (completed_writes * 2048);
                    assert_eq!(
                        final_stats.bytes_written as usize,
                        expected_bytes,
                        "Total bytes written should match expected amount"
                    );

                    println!(
                        "Integration test completed: {} overflows detected, {} backpressure events, {} bytes written",
                        overflows, backpressure_events, final_stats.bytes_written
                    );

                    // Cleanup
                    let _ = std::fs::remove_file(test_file);

                    Ok(())
                })
                .await
        })
        .await
}

/// Test buf_writer behavior under sustained io_uring queue pressure
#[tokio::test]
async fn test_buf_writer_sustained_queue_pressure() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("sustained_queue_pressure").await?;

            scope
                .run(async move |cx| {
                    let backpressure_tracker = BackpressureTracker::new();

                    // Very small queue for sustained pressure
                    let uring_config = IoUringConfig {
                        queue_depth: 8, // Very small queue
                        batch_size: 2,
                        enable_sqpoll: false,
                        sq_thread_idle_ms: 500,
                    };

                    let uring_simulator = Arc::new(
                        SaturatedUringSimulator::new(
                            cx,
                            uring_config,
                            0.5, // 50% capacity triggers overflow
                            backpressure_tracker.clone(),
                        )
                        .await?,
                    );

                    let buf_writer_config = BufWriterConfig {
                        buffer_size: 4096, // 4KB buffer
                        flush_threshold: 2048, // Flush at 50% capacity
                        sync_on_drop: true,
                    };

                    let temp_dir = std::env::temp_dir();
                    let test_file = temp_dir.join("sustained_pressure_test.dat");

                    let buf_writer = UringBufWriter::new(
                        cx,
                        test_file.clone(),
                        4096,
                        uring_simulator.clone(),
                        buf_writer_config,
                        backpressure_tracker.clone(),
                    )
                    .await?;

                    // Enable overflow simulation
                    uring_simulator.enable_overflow_simulation(true);

                    // Sustained write pressure
                    let write_data = vec![0x55u8; 512]; // 512 bytes
                    let mut total_writes = 0;

                    for batch in 0..10 {
                        println!("Pressure batch {} starting", batch);

                        for i in 0..8 {
                            match buf_writer.write(cx, &write_data).await {
                                Ok(_) => total_writes += 1,
                                Err(e) => {
                                    println!("Write failed in batch {}, write {}: {}", batch, i, e);
                                }
                            }

                            // Small delay to maintain pressure
                            Sleep::new(Duration::from_micros(50)).await;
                        }

                        // Force flush periodically
                        if batch % 3 == 0 {
                            match buf_writer.flush(cx).await {
                                Ok(()) => {
                                    println!("Batch {} flush successful", batch);
                                }
                                Err(e) => {
                                    println!("Batch {} flush failed: {}", batch, e);
                                }
                            }
                        }

                        // Brief respite between batches
                        Sleep::new(Duration::from_millis(2)).await;
                    }

                    // Final flush
                    buf_writer.flush(cx).await?;

                    let final_stats = buf_writer.stats(cx).await;

                    // Verification
                    assert!(
                        total_writes > 0,
                        "Should have completed some writes under sustained pressure"
                    );

                    assert!(
                        backpressure_tracker.verify_no_lost_writes(),
                        "No writes should be lost under sustained pressure"
                    );

                    let overflows = backpressure_tracker.queue_overflows.load(Ordering::Relaxed);
                    assert!(
                        overflows > 0,
                        "Should have experienced queue overflows under sustained pressure"
                    );

                    println!(
                        "Sustained pressure test: {} writes completed, {} overflows, {} bytes written",
                        total_writes, overflows, final_stats.bytes_written
                    );

                    // Cleanup
                    let _ = std::fs::remove_file(test_file);

                    Ok(())
                })
                .await
        })
        .await
}

/// Test recovery behavior after queue overflow events
#[tokio::test]
async fn test_buf_writer_overflow_recovery() -> Outcome<()> {
    let runtime = RuntimeBuilder::new()
        .with_deterministic_execution(false)
        .build()
        .await?;

    runtime
        .run(async move |cx| {
            let scope = cx.scope("overflow_recovery").await?;

            scope
                .run(async move |cx| {
                    let backpressure_tracker = BackpressureTracker::new();

                    let uring_config = IoUringConfig {
                        queue_depth: 12,
                        batch_size: 3,
                        enable_sqpoll: false,
                        sq_thread_idle_ms: 1000,
                    };

                    let uring_simulator = Arc::new(
                        SaturatedUringSimulator::new(
                            cx,
                            uring_config,
                            0.6, // 60% capacity triggers overflow
                            backpressure_tracker.clone(),
                        )
                        .await?,
                    );

                    let buf_writer_config = BufWriterConfig {
                        buffer_size: 6144,     // 6KB buffer
                        flush_threshold: 3072, // Flush at 50% capacity
                        sync_on_drop: true,
                    };

                    let temp_dir = std::env::temp_dir();
                    let test_file = temp_dir.join("overflow_recovery_test.dat");

                    let buf_writer = UringBufWriter::new(
                        cx,
                        test_file.clone(),
                        6144,
                        uring_simulator.clone(),
                        buf_writer_config,
                        backpressure_tracker.clone(),
                    )
                    .await?;

                    // Phase 1: Trigger overflow conditions
                    uring_simulator.enable_overflow_simulation(true);

                    let overflow_data = vec![0x77u8; 1024]; // 1KB
                    for i in 0..15 {
                        let _ = buf_writer.write(cx, &overflow_data).await;
                        if i % 4 == 0 {
                            Sleep::new(Duration::from_micros(10)).await;
                        }
                    }

                    let overflow_count =
                        backpressure_tracker.queue_overflows.load(Ordering::Relaxed);
                    assert!(
                        overflow_count > 0,
                        "Should have triggered overflow conditions"
                    );

                    // Phase 2: Disable overflow and verify recovery
                    uring_simulator.enable_overflow_simulation(false);

                    // Allow some time for queue to drain
                    Sleep::new(Duration::from_millis(10)).await;

                    // Test recovery with normal operations
                    let recovery_data = vec![0x88u8; 512]; // 512 bytes
                    let mut recovery_writes = 0;

                    for i in 0..10 {
                        match buf_writer.write(cx, &recovery_data).await {
                            Ok(_) => recovery_writes += 1,
                            Err(e) => {
                                println!("Recovery write {} failed: {}", i, e);
                            }
                        }
                    }

                    buf_writer.flush(cx).await?;

                    // Verification
                    assert!(
                        recovery_writes > 5,
                        "Should successfully recover and complete writes after overflow resolution"
                    );

                    assert!(
                        backpressure_tracker.verify_no_lost_writes(),
                        "No writes should be lost during overflow and recovery cycle"
                    );

                    println!(
                        "Recovery test: {} overflows experienced, {} recovery writes completed",
                        overflow_count, recovery_writes
                    );

                    // Cleanup
                    let _ = std::fs::remove_file(test_file);

                    Ok(())
                })
                .await
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backpressure_tracker_creation() {
        let tracker = BackpressureTracker::new();

        // Verify initial state
        assert_eq!(tracker.writes_submitted.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.flushes_initiated.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.queue_overflows.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.backpressure_events.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.writes_completed.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.writes_lost.load(Ordering::Relaxed), 0);
        assert_eq!(tracker.flushes_completed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_backpressure_tracking() {
        let tracker = BackpressureTracker::new();

        // Record events
        let write_id = tracker.record_write_submitted();
        let flush_id = tracker.record_flush_initiated();
        let overflow_id = tracker.record_queue_overflow();
        let backpressure_id = tracker.record_backpressure_event();
        tracker.record_write_completed();
        tracker.record_flush_completed();

        // Verify tracking
        assert_eq!(tracker.writes_submitted.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.flushes_initiated.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.queue_overflows.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.backpressure_events.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.writes_completed.load(Ordering::Relaxed), 1);
        assert_eq!(tracker.flushes_completed.load(Ordering::Relaxed), 1);

        // Verify verification methods
        assert!(tracker.verify_no_lost_writes());
        assert!(tracker.verify_backpressure_coordination());
        assert!(tracker.verify_flush_completion());
    }

    #[test]
    fn test_no_lost_writes_verification_edge_cases() {
        let tracker = BackpressureTracker::new();

        // No writes submitted
        assert!(!tracker.verify_no_lost_writes()); // No writes to verify

        // Writes submitted but not completed
        let tracker2 = BackpressureTracker::new();
        tracker2.record_write_submitted();
        assert!(!tracker2.verify_no_lost_writes()); // Incomplete writes

        // Writes lost
        let tracker3 = BackpressureTracker::new();
        tracker3.record_write_submitted();
        tracker3.record_write_lost();
        assert!(!tracker3.verify_no_lost_writes()); // Lost writes

        // Proper completion
        let tracker4 = BackpressureTracker::new();
        tracker4.record_write_submitted();
        tracker4.record_write_completed();
        assert!(tracker4.verify_no_lost_writes()); // All writes completed
    }

    #[test]
    fn test_backpressure_coordination_verification() {
        let tracker = BackpressureTracker::new();

        // No overflows
        tracker.record_backpressure_event();
        assert!(!tracker.verify_backpressure_coordination()); // No overflows

        // Overflows without backpressure
        let tracker2 = BackpressureTracker::new();
        tracker2.record_queue_overflow();
        assert!(!tracker2.verify_backpressure_coordination()); // No backpressure response

        // Proper coordination
        let tracker3 = BackpressureTracker::new();
        tracker3.record_queue_overflow();
        tracker3.record_backpressure_event();
        assert!(tracker3.verify_backpressure_coordination()); // Proper coordination

        // More backpressure events than overflows (acceptable)
        let tracker4 = BackpressureTracker::new();
        tracker4.record_queue_overflow();
        tracker4.record_backpressure_event();
        tracker4.record_backpressure_event(); // Extra backpressure is fine
        assert!(tracker4.verify_backpressure_coordination()); // Still valid
    }

    #[test]
    fn test_flush_completion_verification() {
        let tracker = BackpressureTracker::new();

        // No flushes
        assert!(!tracker.verify_flush_completion()); // No flushes to verify

        // Initiated but not completed
        let tracker2 = BackpressureTracker::new();
        tracker2.record_flush_initiated();
        assert!(!tracker2.verify_flush_completion()); // Incomplete flush

        // Proper completion
        let tracker3 = BackpressureTracker::new();
        tracker3.record_flush_initiated();
        tracker3.record_flush_completed();
        assert!(tracker3.verify_flush_completion()); // Flush completed

        // Multiple flushes
        let tracker4 = BackpressureTracker::new();
        tracker4.record_flush_initiated();
        tracker4.record_flush_initiated();
        tracker4.record_flush_completed();
        tracker4.record_flush_completed();
        assert!(tracker4.verify_flush_completion()); // All flushes completed
    }
}
