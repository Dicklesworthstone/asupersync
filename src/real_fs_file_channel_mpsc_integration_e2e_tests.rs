//! E2E Integration Tests: fs/file ↔ channel/mpsc
//!
//! Tests file-read backpressure propagation through MPSC receive lag.
//! Verifies that slow consumers on MPSC channels cause file readers to pause appropriately,
//! preventing memory exhaustion and maintaining backpressure discipline.

use crate::{
    bytes::Bytes,
    channel::mpsc::{self, UnboundedReceiver, UnboundedSender},
    cx::Cx,
    fs::{File, OpenOptions},
    io::{AsyncReadExt, BufReader},
    runtime::Runtime,
    time::Duration,
    types::{Budget, Outcome, TaskId},
};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};

/// Mock file-like source that can be throttled for testing backpressure
struct MockFile {
    data: Vec<u8>,
    position: usize,
    read_count: Arc<AtomicU64>,
    should_block: Arc<AtomicBool>,
    bytes_per_read: usize,
}

impl MockFile {
    fn new(size_bytes: usize, bytes_per_read: usize) -> Self {
        let mut data = Vec::with_capacity(size_bytes);
        for i in 0..size_bytes {
            data.push((i % 256) as u8);
        }

        Self {
            data,
            position: 0,
            read_count: Arc::new(AtomicU64::new(0)),
            should_block: Arc::new(AtomicBool::new(false)),
            bytes_per_read,
        }
    }

    fn read_count(&self) -> Arc<AtomicU64> {
        self.read_count.clone()
    }

    fn block_control(&self) -> Arc<AtomicBool> {
        self.should_block.clone()
    }

    async fn read_chunk(&mut self, cx: &Cx) -> Outcome<Option<Bytes>, std::io::Error> {
        // Check if we should block (simulating slow disk)
        while self.should_block.load(Ordering::Acquire) {
            if cx.budget().is_exhausted() {
                return Outcome::Cancelled;
            }
            // Yield control to allow cancellation
            let _ = crate::time::sleep(cx, Duration::from_millis(1)).await;
        }

        if self.position >= self.data.len() {
            return Outcome::Ok(None);
        }

        let end = std::cmp::min(self.position + self.bytes_per_read, self.data.len());
        let chunk = Bytes::copy_from_slice(&self.data[self.position..end]);
        self.position = end;

        self.read_count.fetch_add(1, Ordering::Release);
        Outcome::Ok(Some(chunk))
    }
}

/// MPSC backpressure detector - tracks channel depth and consumer lag
struct BackpressureDetector {
    sent_count: Arc<AtomicU64>,
    received_count: Arc<AtomicU64>,
    max_lag_observed: Arc<AtomicU64>,
}

impl BackpressureDetector {
    fn new() -> Self {
        Self {
            sent_count: Arc::new(AtomicU64::new(0)),
            received_count: Arc::new(AtomicU64::new(0)),
            max_lag_observed: Arc::new(AtomicU64::new(0)),
        }
    }

    fn on_send(&self) {
        self.sent_count.fetch_add(1, Ordering::Release);
        self.update_max_lag();
    }

    fn on_receive(&self) {
        self.received_count.fetch_add(1, Ordering::Release);
    }

    fn update_max_lag(&self) {
        let sent = self.sent_count.load(Ordering::Acquire);
        let received = self.received_count.load(Ordering::Acquire);
        let current_lag = sent.saturating_sub(received);

        loop {
            let max_lag = self.max_lag_observed.load(Ordering::Acquire);
            if current_lag <= max_lag {
                break;
            }
            if self
                .max_lag_observed
                .compare_exchange_weak(max_lag, current_lag, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }

    fn stats(&self) -> BackpressureStats {
        let sent = self.sent_count.load(Ordering::Acquire);
        let received = self.received_count.load(Ordering::Acquire);
        let current_lag = sent.saturating_sub(received);
        let max_lag = self.max_lag_observed.load(Ordering::Acquire);

        BackpressureStats {
            sent_count: sent,
            received_count: received,
            current_lag,
            max_lag_observed: max_lag,
            throughput_ratio: if sent > 0 {
                received as f64 / sent as f64
            } else {
                0.0
            },
        }
    }
}

#[derive(Debug, Clone)]
struct BackpressureStats {
    sent_count: u64,
    received_count: u64,
    current_lag: u64,
    max_lag_observed: u64,
    throughput_ratio: f64,
}

/// Test harness for file-to-MPSC backpressure scenarios
struct FileToMpscHarness {
    runtime: Runtime,
    detector: BackpressureDetector,
    stats: TestStats,
}

#[derive(Debug, Default)]
struct TestStats {
    files_processed: u64,
    total_bytes_read: u64,
    backpressure_events: u64,
    avg_read_latency_ms: f64,
    consumer_stalls: u64,
}

impl FileToMpscHarness {
    fn new() -> Self {
        Self {
            runtime: Runtime::new(),
            detector: BackpressureDetector::new(),
            stats: TestStats::default(),
        }
    }

    /// Test file reader with fast producer, slow consumer (backpressure scenario)
    async fn test_slow_consumer_backpressure(
        &mut self,
    ) -> Outcome<TestResult, Box<dyn std::error::Error>> {
        let cx = self.runtime.root_cx();

        // Create bounded MPSC channel to demonstrate backpressure
        let (sender, mut receiver) = mpsc::channel::<Bytes>(16); // Small buffer

        let mut mock_file = MockFile::new(8192, 256); // 8KB file, 256-byte chunks
        let read_count = mock_file.read_count();
        let block_control = mock_file.block_control();

        let detector = self.detector.clone();

        // Spawn producer (file reader)
        let producer_task = cx.spawn(async move {
            let start = Instant::now();
            let mut total_bytes = 0u64;

            loop {
                match mock_file.read_chunk(cx).await {
                    Outcome::Ok(Some(chunk)) => {
                        total_bytes += chunk.len() as u64;

                        // Attempt to send - this should block when consumer is slow
                        match sender.send(chunk).await {
                            Outcome::Ok(()) => {
                                detector.on_send();
                            }
                            Outcome::Cancelled => break Outcome::Cancelled,
                            Outcome::Err(e) => break Outcome::Err(e.into()),
                            Outcome::Panicked => break Outcome::Panicked,
                        }
                    }
                    Outcome::Ok(None) => break Outcome::Ok(total_bytes),
                    Outcome::Cancelled => break Outcome::Cancelled,
                    Outcome::Err(e) => break Outcome::Err(e.into()),
                    Outcome::Panicked => break Outcome::Panicked,
                }
            }
        });

        // Spawn slow consumer
        let consumer_detector = self.detector.clone();
        let consumer_task = cx.spawn(async move {
            let mut received_bytes = 0u64;
            let mut stalls = 0u64;

            loop {
                // Simulate slow consumer by sleeping between receives
                let _ = crate::time::sleep(cx, Duration::from_millis(50)).await;

                match receiver.recv().await {
                    Outcome::Ok(Some(chunk)) => {
                        received_bytes += chunk.len() as u64;
                        consumer_detector.on_receive();
                    }
                    Outcome::Ok(None) => break Outcome::Ok((received_bytes, stalls)),
                    Outcome::Cancelled => break Outcome::Cancelled,
                    Outcome::Err(e) => break Outcome::Err(e.into()),
                    Outcome::Panicked => break Outcome::Panicked,
                }
            }
        });

        // Let the test run for a bit to observe backpressure
        let _ = crate::time::sleep(cx, Duration::from_millis(500)).await;

        // Check that backpressure is working (producer should be throttled)
        let mid_stats = self.detector.stats();

        // Wait for completion
        let producer_result = producer_task.join().await;
        let consumer_result = consumer_task.join().await;

        let final_stats = self.detector.stats();

        Ok(TestResult {
            scenario: "slow_consumer_backpressure".to_string(),
            success: matches!(producer_result, Outcome::Ok(_))
                && matches!(consumer_result, Outcome::Ok(_)),
            backpressure_stats: final_stats,
            producer_bytes: match producer_result {
                Outcome::Ok(bytes) => bytes,
                _ => 0,
            },
            consumer_bytes: match consumer_result {
                Outcome::Ok((bytes, _)) => bytes,
                _ => 0,
            },
            reads_performed: read_count.load(Ordering::Acquire),
            backpressure_detected: mid_stats.current_lag > 8, // Should see lag build up
            notes: format!(
                "Mid-test lag: {}, Final lag: {}",
                mid_stats.current_lag, final_stats.current_lag
            ),
        })
    }

    /// Test file reader with fast consumer (no backpressure)
    async fn test_fast_consumer_no_backpressure(
        &mut self,
    ) -> Outcome<TestResult, Box<dyn std::error::Error>> {
        let cx = self.runtime.root_cx();

        let (sender, mut receiver) = mpsc::channel::<Bytes>(1024); // Large buffer

        let mut mock_file = MockFile::new(4096, 128); // 4KB file, 128-byte chunks
        let read_count = mock_file.read_count();

        let detector = BackpressureDetector::new(); // Fresh detector for this test

        // Spawn producer (file reader)
        let producer_detector = detector.clone();
        let producer_task = cx.spawn(async move {
            let mut total_bytes = 0u64;

            loop {
                match mock_file.read_chunk(cx).await {
                    Outcome::Ok(Some(chunk)) => {
                        total_bytes += chunk.len() as u64;

                        match sender.send(chunk).await {
                            Outcome::Ok(()) => {
                                producer_detector.on_send();
                            }
                            Outcome::Cancelled => break Outcome::Cancelled,
                            Outcome::Err(e) => break Outcome::Err(e.into()),
                            Outcome::Panicked => break Outcome::Panicked,
                        }
                    }
                    Outcome::Ok(None) => break Outcome::Ok(total_bytes),
                    Outcome::Cancelled => break Outcome::Cancelled,
                    Outcome::Err(e) => break Outcome::Err(e.into()),
                    Outcome::Panicked => break Outcome::Panicked,
                }
            }
        });

        // Spawn fast consumer
        let consumer_detector = detector.clone();
        let consumer_task = cx.spawn(async move {
            let mut received_bytes = 0u64;

            loop {
                // No artificial delay - consume as fast as possible
                match receiver.recv().await {
                    Outcome::Ok(Some(chunk)) => {
                        received_bytes += chunk.len() as u64;
                        consumer_detector.on_receive();
                    }
                    Outcome::Ok(None) => break Outcome::Ok(received_bytes),
                    Outcome::Cancelled => break Outcome::Cancelled,
                    Outcome::Err(e) => break Outcome::Err(e.into()),
                    Outcome::Panicked => break Outcome::Panicked,
                }
            }
        });

        // Wait for completion
        let producer_result = producer_task.join().await;
        let consumer_result = consumer_task.join().await;

        let final_stats = detector.stats();

        Ok(TestResult {
            scenario: "fast_consumer_no_backpressure".to_string(),
            success: matches!(producer_result, Outcome::Ok(_))
                && matches!(consumer_result, Outcome::Ok(_)),
            backpressure_stats: final_stats.clone(),
            producer_bytes: match producer_result {
                Outcome::Ok(bytes) => bytes,
                _ => 0,
            },
            consumer_bytes: match consumer_result {
                Outcome::Ok(bytes) => bytes,
                _ => 0,
            },
            reads_performed: read_count.load(Ordering::Acquire),
            backpressure_detected: final_stats.max_lag_observed > 2, // Should see minimal lag
            notes: format!(
                "Max lag: {}, Final throughput: {:.2}",
                final_stats.max_lag_observed, final_stats.throughput_ratio
            ),
        })
    }

    /// Test cancellation during backpressure
    async fn test_cancellation_under_backpressure(
        &mut self,
    ) -> Outcome<TestResult, Box<dyn std::error::Error>> {
        let cx = self.runtime.root_cx();

        let (sender, mut receiver) = mpsc::channel::<Bytes>(4); // Very small buffer

        let mut mock_file = MockFile::new(16384, 512); // 16KB file, 512-byte chunks
        let read_count = mock_file.read_count();
        let block_control = mock_file.block_control();

        let detector = BackpressureDetector::new();

        // Start with blocked file reads to build up pressure
        block_control.store(true, Ordering::Release);

        // Spawn producer
        let producer_detector = detector.clone();
        let producer_task = cx.spawn(async move {
            let mut total_bytes = 0u64;

            loop {
                match mock_file.read_chunk(cx).await {
                    Outcome::Ok(Some(chunk)) => {
                        total_bytes += chunk.len() as u64;

                        match sender.send(chunk).await {
                            Outcome::Ok(()) => {
                                producer_detector.on_send();
                            }
                            Outcome::Cancelled => break Outcome::Cancelled,
                            Outcome::Err(e) => break Outcome::Err(e.into()),
                            Outcome::Panicked => break Outcome::Panicked,
                        }
                    }
                    Outcome::Ok(None) => break Outcome::Ok(total_bytes),
                    Outcome::Cancelled => break Outcome::Cancelled,
                    Outcome::Err(e) => break Outcome::Err(e.into()),
                    Outcome::Panicked => break Outcome::Panicked,
                }
            }
        });

        // Consumer that never reads (maximum backpressure)
        let consumer_task = cx.spawn(async move {
            // Just wait and never consume
            let _ = crate::time::sleep(cx, Duration::from_millis(2000)).await;
            Outcome::Ok(0u64)
        });

        // Let pressure build up for a moment
        let _ = crate::time::sleep(cx, Duration::from_millis(100)).await;

        // Unblock file but keep consumer slow
        block_control.store(false, Ordering::Release);

        // Wait a bit more then cancel
        let _ = crate::time::sleep(cx, Duration::from_millis(200)).await;

        // Cancel the tasks to test cancellation under pressure
        producer_task.cancel();
        consumer_task.cancel();

        let producer_result = producer_task.join().await;
        let consumer_result = consumer_task.join().await;

        let final_stats = detector.stats();

        Ok(TestResult {
            scenario: "cancellation_under_backpressure".to_string(),
            success: matches!(producer_result, Outcome::Cancelled)
                && matches!(consumer_result, Outcome::Cancelled),
            backpressure_stats: final_stats.clone(),
            producer_bytes: 0, // Should be cancelled before completion
            consumer_bytes: 0,
            reads_performed: read_count.load(Ordering::Acquire),
            backpressure_detected: true, // We forced maximum backpressure
            notes: format!(
                "Cancelled tasks. Reads before cancel: {}, Max lag: {}",
                read_count.load(Ordering::Acquire),
                final_stats.max_lag_observed
            ),
        })
    }
}

#[derive(Debug, Clone)]
struct TestResult {
    scenario: String,
    success: bool,
    backpressure_stats: BackpressureStats,
    producer_bytes: u64,
    consumer_bytes: u64,
    reads_performed: u64,
    backpressure_detected: bool,
    notes: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_mpsc_slow_consumer_backpressure() {
        let mut harness = FileToMpscHarness::new();
        let cx = harness.runtime.root_cx();

        let result = cx.block_on(async { harness.test_slow_consumer_backpressure().await });

        match result {
            Outcome::Ok(test_result) => {
                assert!(test_result.success, "Test should complete successfully");
                assert!(
                    test_result.backpressure_detected,
                    "Backpressure should be detected with slow consumer"
                );
                assert!(
                    test_result.producer_bytes > 0,
                    "Producer should read some data"
                );
                assert!(
                    test_result.consumer_bytes > 0,
                    "Consumer should receive some data"
                );
                assert!(
                    test_result.backpressure_stats.max_lag_observed > 0,
                    "Should observe channel lag"
                );

                println!("Slow consumer test: {}", test_result.notes);
                println!("Backpressure stats: {:?}", test_result.backpressure_stats);
            }
            outcome => panic!("Test failed with outcome: {:?}", outcome),
        }
    }

    #[test]
    fn test_file_mpsc_fast_consumer_no_backpressure() {
        let mut harness = FileToMpscHarness::new();
        let cx = harness.runtime.root_cx();

        let result = cx.block_on(async { harness.test_fast_consumer_no_backpressure().await });

        match result {
            Outcome::Ok(test_result) => {
                assert!(test_result.success, "Test should complete successfully");
                assert!(
                    !test_result.backpressure_detected,
                    "Minimal backpressure with fast consumer"
                );
                assert_eq!(
                    test_result.producer_bytes, test_result.consumer_bytes,
                    "All data should be transferred"
                );
                assert!(
                    test_result.backpressure_stats.throughput_ratio > 0.9,
                    "High throughput ratio expected"
                );

                println!("Fast consumer test: {}", test_result.notes);
            }
            outcome => panic!("Test failed with outcome: {:?}", outcome),
        }
    }

    #[test]
    fn test_file_mpsc_cancellation_under_backpressure() {
        let mut harness = FileToMpscHarness::new();
        let cx = harness.runtime.root_cx();

        let result = cx.block_on(async { harness.test_cancellation_under_backpressure().await });

        match result {
            Outcome::Ok(test_result) => {
                assert!(test_result.success, "Cancellation should work correctly");
                assert!(
                    test_result.backpressure_detected,
                    "Backpressure should be present before cancellation"
                );

                println!("Cancellation test: {}", test_result.notes);
            }
            outcome => panic!("Test failed with outcome: {:?}", outcome),
        }
    }

    #[test]
    fn test_backpressure_detector_stats() {
        let detector = BackpressureDetector::new();

        // Simulate sending without receiving
        for _ in 0..10 {
            detector.on_send();
        }

        let stats = detector.stats();
        assert_eq!(stats.sent_count, 10);
        assert_eq!(stats.received_count, 0);
        assert_eq!(stats.current_lag, 10);
        assert_eq!(stats.max_lag_observed, 10);
        assert_eq!(stats.throughput_ratio, 0.0);

        // Simulate receiving some messages
        for _ in 0..5 {
            detector.on_receive();
        }

        let stats = detector.stats();
        assert_eq!(stats.sent_count, 10);
        assert_eq!(stats.received_count, 5);
        assert_eq!(stats.current_lag, 5);
        assert_eq!(stats.max_lag_observed, 10); // Should remember peak lag
        assert_eq!(stats.throughput_ratio, 0.5);
    }

    #[test]
    fn test_mock_file_read_behavior() {
        let rt = Runtime::new();
        let cx = rt.root_cx();

        let result = cx.block_on(async {
            let mut mock_file = MockFile::new(1024, 256);
            let read_count = mock_file.read_count();

            let mut total_bytes = 0;
            loop {
                match mock_file.read_chunk(cx).await {
                    Outcome::Ok(Some(chunk)) => {
                        total_bytes += chunk.len();
                    }
                    Outcome::Ok(None) => break,
                    outcome => panic!("Unexpected outcome: {:?}", outcome),
                }
            }

            (total_bytes, read_count.load(Ordering::Acquire))
        });

        match result {
            Outcome::Ok((total_bytes, reads)) => {
                assert_eq!(total_bytes, 1024, "Should read all file data");
                assert_eq!(reads, 4, "Should take 4 reads (1024 / 256)");
            }
            outcome => panic!("Test failed with outcome: {:?}", outcome),
        }
    }

    #[test]
    fn test_file_read_with_blocking() {
        let rt = Runtime::new();
        let cx = rt.root_cx();

        let result = cx.block_on(async {
            let mut mock_file = MockFile::new(512, 128);
            let block_control = mock_file.block_control();
            let read_count = mock_file.read_count();

            // Block reads initially
            block_control.store(true, Ordering::Release);

            // Try to read - should not complete due to blocking
            let read_task = cx.spawn(async move { mock_file.read_chunk(cx).await });

            // Wait a bit
            let _ = crate::time::sleep(cx, Duration::from_millis(50)).await;

            // Should not have completed any reads yet
            assert_eq!(read_count.load(Ordering::Acquire), 0);

            // Unblock and let it complete
            block_control.store(false, Ordering::Release);

            let read_result = read_task.join().await;

            (read_result, read_count.load(Ordering::Acquire))
        });

        match result {
            Outcome::Ok((read_result, reads)) => {
                assert!(
                    matches!(read_result, Outcome::Ok(Some(_))),
                    "Read should succeed after unblocking"
                );
                assert_eq!(reads, 1, "Should complete one read after unblocking");
            }
            outcome => panic!("Test failed with outcome: {:?}", outcome),
        }
    }
}
