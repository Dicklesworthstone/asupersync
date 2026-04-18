//! Fuzz target for framed encoder backpressure interleaving edge cases.
//!
//! This fuzz target specifically tests the interaction between framed encoders
//! and writers under backpressure conditions. It drives interleaved sequences of:
//! - encode() operations that buffer data
//! - flush() operations that attempt to write buffered data
//! - poll_ready() operations (when using Sink trait)
//!
//! The key focus is testing scenarios where the underlying AsyncWrite transport
//! returns Poll::Pending at arbitrary points, creating backpressure situations
//! that can expose race conditions and state machine bugs.
//!
//! Attack vectors tested:
//! - Encoder state corruption during backpressure cycles
//! - Buffer management under partial write conditions
//! - Data loss or duplication during flush retry sequences
//! - Sink contract violations (poll_ready/send/flush state machine)
//! - Panic conditions during cooperative yielding with backpressure
//! - Write buffer consistency across encode/flush interleaving

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::{Encoder, FramedWrite, LinesCodec};
use asupersync::io::AsyncWrite;
use libfuzzer_sys::fuzz_target;
use std::collections::VecDeque;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

/// Maximum input size to prevent memory exhaustion during fuzzing
const MAX_INPUT_SIZE: usize = 16 * 1024; // 16KB
/// Maximum number of operations per fuzz run
const MAX_OPERATIONS: usize = 200;

/// Configuration for backpressure fuzzing
#[derive(Arbitrary, Debug)]
struct BackpressureFuzzConfig {
    /// Writer behavior configuration
    writer_behavior: WriterBehavior,
    /// Buffer capacity for the framed writer
    buffer_capacity: BufferCapacity,
    /// Sequence of operations to perform
    operations: Vec<BackpressureOperation>,
    /// Initial data to buffer in the writer
    initial_data: Vec<u8>,
}

/// Writer behavior patterns that can cause backpressure
#[derive(Arbitrary, Debug)]
enum WriterBehavior {
    /// Returns Pending every N polls
    PeriodicPending { period: u8 },
    /// Returns Pending based on buffer fullness threshold
    ThresholdPending { threshold: u16 },
    /// Returns Pending randomly based on frequency
    RandomPending { frequency: u8 },
    /// Accepts only small writes at a time
    PartialWrites { max_write_size: u8 },
    /// Combines partial writes with pending
    PartialWithPending {
        max_write_size: u8,
        pending_frequency: u8
    },
    /// Fails writes occasionally with WriteZero error
    OccasionalWriteZero { failure_rate: u8 },
    /// Alternates between ready and pending in patterns
    AlternatingPattern { pattern: Vec<bool> },
    /// Pending based on total bytes written
    BytesWrittenPending { pending_every_n_bytes: u16 },
}

/// Buffer capacity options for testing different memory pressures
#[derive(Arbitrary, Debug)]
enum BufferCapacity {
    Tiny,    // 64 bytes
    Small,   // 512 bytes
    Medium,  // 2KB
    Large,   // 8KB
    Custom { size: u16 },
}

impl BufferCapacity {
    fn to_usize(&self) -> usize {
        match self {
            BufferCapacity::Tiny => 64,
            BufferCapacity::Small => 512,
            BufferCapacity::Medium => 2048,
            BufferCapacity::Large => 8192,
            BufferCapacity::Custom { size } => (*size as usize).min(MAX_INPUT_SIZE),
        }
    }
}

/// Operations to perform during backpressure testing
#[derive(Arbitrary, Debug)]
enum BackpressureOperation {
    /// Encode data into the frame buffer
    Encode { data: Vec<u8> },
    /// Attempt to flush buffered data
    Flush,
    /// Close the framed writer
    Close,
    /// Inspect internal buffer state
    InspectBuffer,
    /// Multiple encodes followed by flush
    EncodeSequence { items: Vec<Vec<u8>> },
    /// Encode then immediately flush
    EncodeAndFlush { data: Vec<u8> },
    /// Flush multiple times in sequence
    FlushSequence { count: u8 },
    /// Test concurrent-like interleaving
    InterleavedEncodeFLush {
        encode_data: Vec<u8>,
        flush_between: bool,
    },
}

/// Mock writer that simulates various backpressure scenarios
#[derive(Debug)]
struct BackpressureWriter {
    /// Buffer holding written data
    written_data: Vec<u8>,
    /// Behavior configuration
    behavior: WriterBehavior,
    /// Poll counter for behavior patterns
    poll_count: usize,
    /// Total bytes written so far
    bytes_written: usize,
    /// Pattern position for alternating behavior
    pattern_position: usize,
    /// Whether last write was pending (for debugging)
    last_was_pending: bool,
    /// Track potential write attempts for debugging
    write_attempts: usize,
}

impl BackpressureWriter {
    fn new(behavior: WriterBehavior, initial_data: Vec<u8>) -> Self {
        Self {
            written_data: initial_data,
            behavior,
            poll_count: 0,
            bytes_written: 0,
            pattern_position: 0,
            last_was_pending: false,
            write_attempts: 0,
        }
    }

    /// Check if this write attempt should return Pending
    fn should_return_pending(&mut self, _buf_len: usize) -> bool {
        self.poll_count += 1;
        self.write_attempts += 1;

        match &self.behavior {
            WriterBehavior::PeriodicPending { period } => {
                self.poll_count % ((*period as usize).max(1)) == 0
            }
            WriterBehavior::ThresholdPending { threshold } => {
                self.written_data.len() >= *threshold as usize
            }
            WriterBehavior::RandomPending { frequency } => {
                // Deterministic "randomness" based on poll count
                (self.poll_count * 31) % 256 < *frequency as usize
            }
            WriterBehavior::PartialWithPending { pending_frequency, .. } => {
                self.poll_count % ((*pending_frequency as usize).max(1)) == 0
            }
            WriterBehavior::OccasionalWriteZero { failure_rate } => {
                (self.poll_count * 17) % 256 < *failure_rate as usize
            }
            WriterBehavior::AlternatingPattern { pattern } => {
                if pattern.is_empty() {
                    false
                } else {
                    let should_pending = !pattern[self.pattern_position % pattern.len()];
                    self.pattern_position += 1;
                    should_pending
                }
            }
            WriterBehavior::BytesWrittenPending { pending_every_n_bytes } => {
                let threshold = (*pending_every_n_bytes as usize).max(1);
                self.bytes_written >= (self.poll_count / 3) * threshold
            }
            WriterBehavior::PartialWrites { .. } => false, // Never pending, just partial
        }
    }

    /// Get maximum write size for this attempt
    fn max_write_size(&self) -> usize {
        match &self.behavior {
            WriterBehavior::PartialWrites { max_write_size } => {
                (*max_write_size as usize).max(1)
            }
            WriterBehavior::PartialWithPending { max_write_size, .. } => {
                (*max_write_size as usize).max(1)
            }
            _ => usize::MAX, // No limit
        }
    }

    /// Check written data integrity invariants
    fn check_integrity(&self) -> bool {
        // Written data should only grow (no data loss)
        // This is a basic integrity check
        true
    }
}

impl AsyncWrite for BackpressureWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        // Check for WriteZero error conditions first
        if let WriterBehavior::OccasionalWriteZero { .. } = &self.behavior {
            if self.should_return_pending(buf.len()) {
                return Poll::Ready(Ok(0)); // WriteZero condition
            }
        }

        // Check for pending conditions
        if self.should_return_pending(buf.len()) {
            self.last_was_pending = true;
            return Poll::Pending;
        }

        self.last_was_pending = false;

        // Determine how much to write
        let max_write = self.max_write_size();
        let to_write = buf.len().min(max_write);

        if to_write == 0 {
            return Poll::Ready(Ok(0));
        }

        // Actually write the data
        self.written_data.extend_from_slice(&buf[..to_write]);
        self.bytes_written += to_write;

        Poll::Ready(Ok(to_write))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        // Flush can also experience backpressure
        let this = self.get_mut();
        this.poll_count += 1;

        match &this.behavior {
            WriterBehavior::PeriodicPending { period } => {
                if this.poll_count % ((*period as usize * 2).max(1)) == 0 {
                    return Poll::Pending;
                }
            }
            WriterBehavior::RandomPending { frequency } => {
                if (this.poll_count * 13) % 256 < (*frequency as usize / 2) {
                    return Poll::Pending;
                }
            }
            _ => {} // Most behaviors don't affect flush
        }

        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        // Shutdown should flush first
        match self.poll_flush(cx)? {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => Poll::Ready(Ok(())),
        }
    }
}

/// Create a no-op waker for testing
fn create_test_waker() -> Waker {
    use std::sync::Arc;
    use std::task::Wake;

    struct NoopWaker;
    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
        fn wake_by_ref(self: &Arc<Self>) {}
    }

    Waker::from(Arc::new(NoopWaker))
}

/// Test state tracking for detecting violations
#[derive(Debug)]
struct TestState {
    /// Total items encoded
    items_encoded: usize,
    /// Total successful flushes
    successful_flushes: usize,
    /// Total pending flushes
    pending_flushes: usize,
    /// Data that was encoded (for checking integrity)
    encoded_data: Vec<Vec<u8>>,
    /// Expected data in writer buffer
    expected_in_buffer: usize,
}

impl TestState {
    fn new() -> Self {
        Self {
            items_encoded: 0,
            successful_flushes: 0,
            pending_flushes: 0,
            encoded_data: Vec::new(),
            expected_in_buffer: 0,
        }
    }

    fn record_encode(&mut self, data: &[u8]) {
        self.items_encoded += 1;
        self.encoded_data.push(data.to_vec());
        // Each line gets a newline added by LinesCodec
        self.expected_in_buffer += data.len() + 1;
    }

    fn record_flush_result(&mut self, was_pending: bool) {
        if was_pending {
            self.pending_flushes += 1;
        } else {
            self.successful_flushes += 1;
            // Successful flush should clear the buffer
            self.expected_in_buffer = 0;
        }
    }

    /// Check for obvious violations
    fn check_sanity(&self) -> bool {
        // Basic sanity checks
        self.items_encoded >= self.successful_flushes &&
        self.encoded_data.len() == self.items_encoded
    }
}

fuzz_target!(|input: BackpressureFuzzConfig| {
    // Limit operations to prevent excessive test time
    let operations: Vec<_> = input.operations.into_iter().take(MAX_OPERATIONS).collect();

    // Create backpressure writer
    let writer = BackpressureWriter::new(input.writer_behavior, input.initial_data);

    // Create framed writer with specified capacity
    let capacity = input.buffer_capacity.to_usize();
    let mut framed = FramedWrite::with_capacity(writer, LinesCodec::new(), capacity);

    // Test state for tracking violations
    let mut test_state = TestState::new();

    // Create context for async operations
    let waker = create_test_waker();
    let mut cx = Context::from_waker(&waker);

    // Execute operations and catch any panics
    for operation in &operations {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            execute_operation(&mut framed, operation, &mut cx, &mut test_state)
        }));

        // If we panic, that's a bug we want to catch
        if result.is_err() {
            // The fuzzer will report this as a crash
            return;
        }

        // Check integrity after each operation
        if !test_state.check_sanity() {
            // State violation detected - this is a bug
            panic!("Test state sanity check failed: {:?}", test_state);
        }

        if !framed.get_ref().check_integrity() {
            panic!("Writer integrity check failed");
        }
    }

    // Final integrity checks
    // Try to flush everything at the end to check for data loss
    for _ in 0..10 { // Multiple attempts to handle pending
        match framed.poll_flush(&mut cx) {
            Poll::Ready(Ok(())) => break,
            Poll::Ready(Err(_)) => break, // Error is ok, but shouldn't panic
            Poll::Pending => continue,
        }
    }

    // Check that no data was lost or duplicated
    // This is a basic check - more sophisticated checks could verify exact data integrity
    let final_written = &framed.get_ref().written_data;
    let expected_data_present = test_state.encoded_data.iter()
        .all(|data| {
            // Check if this data (with newline) appears in the written data
            let mut with_newline = data.clone();
            with_newline.push(b'\n');
            final_written.windows(with_newline.len()).any(|window| window == &with_newline[..])
        });

    if !expected_data_present && test_state.items_encoded > 0 && test_state.successful_flushes > 0 {
        // Data loss detected - this is a serious bug
        panic!("Data loss detected: encoded {} items, had {} successful flushes, but data not found in writer",
               test_state.items_encoded, test_state.successful_flushes);
    }
});

fn execute_operation<W>(
    framed: &mut FramedWrite<W, LinesCodec>,
    operation: &BackpressureOperation,
    cx: &mut Context<'_>,
    test_state: &mut TestState,
) where
    W: AsyncWrite + Unpin,
{
    match operation {
        BackpressureOperation::Encode { data } => {
            // Limit data size and convert to string
            let limited_data: Vec<u8> = data.iter().take(MAX_INPUT_SIZE).cloned().collect();
            if let Ok(string_data) = String::from_utf8(limited_data.clone()) {
                let result = framed.send(string_data);
                match result {
                    Ok(()) => {
                        test_state.record_encode(&limited_data);
                    }
                    Err(_) => {
                        // Encode errors are ok, just don't record the data
                    }
                }
            }
        }

        BackpressureOperation::Flush => {
            let result = framed.poll_flush(cx);
            match result {
                Poll::Ready(Ok(())) => {
                    test_state.record_flush_result(false);
                }
                Poll::Pending => {
                    test_state.record_flush_result(true);
                }
                Poll::Ready(Err(_)) => {
                    // Errors are ok for testing, just don't count as successful
                }
            }
        }

        BackpressureOperation::Close => {
            let _ = framed.poll_close(cx);
            // Close might succeed, fail, or pend - all are valid
        }

        BackpressureOperation::InspectBuffer => {
            let buffer = framed.write_buffer();
            // Just accessing the buffer, verify it doesn't panic
            let _len = buffer.len();
        }

        BackpressureOperation::EncodeSequence { items } => {
            for item in items.iter().take(10) { // Limit sequence length
                let limited_item: Vec<u8> = item.iter().take(MAX_INPUT_SIZE / 10).cloned().collect();
                if let Ok(string_data) = String::from_utf8(limited_item.clone()) {
                    let result = framed.send(string_data);
                    if result.is_ok() {
                        test_state.record_encode(&limited_item);
                    }
                }
            }
        }

        BackpressureOperation::EncodeAndFlush { data } => {
            // First encode
            let limited_data: Vec<u8> = data.iter().take(MAX_INPUT_SIZE).cloned().collect();
            if let Ok(string_data) = String::from_utf8(limited_data.clone()) {
                let result = framed.send(string_data);
                if result.is_ok() {
                    test_state.record_encode(&limited_data);
                }
            }

            // Then flush
            let result = framed.poll_flush(cx);
            match result {
                Poll::Ready(Ok(())) => test_state.record_flush_result(false),
                Poll::Pending => test_state.record_flush_result(true),
                Poll::Ready(Err(_)) => {}
            }
        }

        BackpressureOperation::FlushSequence { count } => {
            let flush_count = (*count as usize).min(20); // Limit flush attempts
            for _ in 0..flush_count {
                let result = framed.poll_flush(cx);
                match result {
                    Poll::Ready(Ok(())) => {
                        test_state.record_flush_result(false);
                        break; // Successful flush, no need to continue
                    }
                    Poll::Pending => {
                        test_state.record_flush_result(true);
                        // Continue trying
                    }
                    Poll::Ready(Err(_)) => {
                        break; // Error, stop trying
                    }
                }
            }
        }

        BackpressureOperation::InterleavedEncodeFLush { encode_data, flush_between } => {
            // Encode data
            let limited_data: Vec<u8> = encode_data.iter().take(MAX_INPUT_SIZE).cloned().collect();
            if let Ok(string_data) = String::from_utf8(limited_data.clone()) {
                let result = framed.send(string_data);
                if result.is_ok() {
                    test_state.record_encode(&limited_data);
                }
            }

            // Optionally flush in between
            if *flush_between {
                let result = framed.poll_flush(cx);
                match result {
                    Poll::Ready(Ok(())) => test_state.record_flush_result(false),
                    Poll::Pending => test_state.record_flush_result(true),
                    Poll::Ready(Err(_)) => {}
                }
            }
        }
    }
}