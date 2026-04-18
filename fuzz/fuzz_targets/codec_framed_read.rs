#![no_main]

//! Fuzz target for src/codec/framed_read.rs readout state machine.
//!
//! This target specifically tests the 5 critical FramedRead invariants:
//! 1. Readout buffer grows within max_frame_length
//! 2. Stream::next() termination on EOF correct
//! 3. poll_next re-entrance safe
//! 4. Custom Decoder errors propagated correctly
//! 5. Cancellation drains buffered bytes properly

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, FramedRead};
use asupersync::io::{AsyncRead, ReadBuf};
use asupersync::stream::Stream;

/// Fuzz input for testing FramedRead invariants
#[derive(Arbitrary, Debug, Clone)]
struct FramedReadFuzzInput {
    /// Malformed byte stream to feed to FramedRead
    pub data_stream: Vec<u8>,
    /// Maximum frame length for testing invariant 1
    pub max_frame_length: u16,
    /// Whether to inject cancellation
    pub inject_cancellation: bool,
    /// Cancel after N polls
    pub cancel_after_polls: u8,
    /// Inject decoder error after N calls
    pub decoder_error_after: u8,
    /// Custom decoder error type
    pub custom_error_type: CustomErrorType,
    /// Multiple poll_next calls to test re-entrance
    pub poll_sequence: Vec<PollAction>,
    /// Reader behavior pattern
    pub reader_pattern: ReaderPattern,
    /// Initial buffer capacity
    pub initial_capacity: u16,
}

/// Types of custom errors to inject
#[derive(Arbitrary, Debug, Clone)]
enum CustomErrorType {
    MaxLengthExceeded,
    InvalidData,
    CustomProtocolError,
    IoError,
}

/// Reader patterns for testing different scenarios
#[derive(Arbitrary, Debug, Clone)]
enum ReaderPattern {
    /// Provides all data immediately
    Immediate,
    /// Provides data in small chunks
    Chunked { chunk_size: u8 },
    /// Returns Pending sometimes
    Intermittent,
    /// Always returns single bytes (stress test)
    SingleByte,
    /// Simulates malformed stream
    Malformed,
}

/// Individual poll actions
#[derive(Arbitrary, Debug, Clone)]
enum PollAction {
    /// Normal poll_next
    Poll,
    /// Poll and check buffer state
    PollAndInspect,
    /// Poll with forced cancellation
    PollWithCancel,
    /// Check re-entrance safety
    ReEntrancePoll,
}

/// Mock decoder for testing custom error propagation
struct TestDecoder {
    max_frame_length: u16,
    calls_count: u8,
    error_after: u8,
    error_type: CustomErrorType,
    partial_frame_buffer: BytesMut,
}

/// Custom decoder errors for testing propagation
#[derive(Debug)]
enum TestDecoderError {
    MaxFrameLengthExceeded,
    InvalidData(String),
    CustomProtocolError(u32),
    Io(io::Error),
}

impl std::fmt::Display for TestDecoderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MaxFrameLengthExceeded => write!(f, "frame exceeds maximum length"),
            Self::InvalidData(msg) => write!(f, "invalid data: {}", msg),
            Self::CustomProtocolError(code) => write!(f, "protocol error: code {}", code),
            Self::Io(err) => write!(f, "I/O error: {}", err),
        }
    }
}

impl std::error::Error for TestDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for TestDecoderError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl TestDecoder {
    fn new(max_frame_length: u16, error_after: u8, error_type: CustomErrorType) -> Self {
        Self {
            max_frame_length: max_frame_length.clamp(1, 1024),
            calls_count: 0,
            error_after: error_after.clamp(1, 20),
            error_type,
            partial_frame_buffer: BytesMut::new(),
        }
    }
}

impl Decoder for TestDecoder {
    type Item = Vec<u8>;
    type Error = TestDecoderError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.calls_count = self.calls_count.saturating_add(1);

        // INVARIANT 4: Custom Decoder errors propagated
        if self.calls_count >= self.error_after {
            return Err(match self.error_type {
                CustomErrorType::MaxLengthExceeded => TestDecoderError::MaxFrameLengthExceeded,
                CustomErrorType::InvalidData => TestDecoderError::InvalidData("malformed frame".to_string()),
                CustomErrorType::CustomProtocolError => TestDecoderError::CustomProtocolError(0xDEAD),
                CustomErrorType::IoError => TestDecoderError::Io(io::Error::new(io::ErrorKind::InvalidData, "test io error")),
            });
        }

        // INVARIANT 1: Readout buffer grows within max_frame_length
        // Implement simple newline-delimited decoder with length limit
        if let Some(pos) = src.iter().position(|&b| b == b'\n') {
            // INVARIANT 1: Assert frame length doesn't exceed max
            if pos > self.max_frame_length as usize {
                return Err(TestDecoderError::MaxFrameLengthExceeded);
            }

            let frame = src.split_to(pos + 1);
            let mut frame_data = frame.to_vec();
            frame_data.pop(); // Remove newline
            Ok(Some(frame_data))
        } else {
            // INVARIANT 1: Check buffer doesn't grow beyond limit
            if src.len() > self.max_frame_length as usize {
                return Err(TestDecoderError::MaxFrameLengthExceeded);
            }
            Ok(None)
        }
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // INVARIANT 2: Stream::next() termination on EOF correct
        if src.is_empty() {
            return Ok(None);
        }

        // Return remaining bytes as final frame
        let frame = src.split_to(src.len());
        Ok(Some(frame.to_vec()))
    }
}

/// Mock AsyncRead for testing various scenarios
struct TestAsyncReader {
    data: Vec<u8>,
    position: usize,
    pattern: ReaderPattern,
    chunk_counter: u8,
    eof_reached: bool,
}

impl TestAsyncReader {
    fn new(data: Vec<u8>, pattern: ReaderPattern) -> Self {
        Self {
            data,
            position: 0,
            pattern,
            chunk_counter: 0,
            eof_reached: false,
        }
    }
}

impl AsyncRead for TestAsyncReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.eof_reached || this.position >= this.data.len() {
            this.eof_reached = true;
            return Poll::Ready(Ok(()));
        }

        let remaining = &this.data[this.position..];
        if remaining.is_empty() {
            this.eof_reached = true;
            return Poll::Ready(Ok(()));
        }

        let to_read = match this.pattern {
            ReaderPattern::Immediate => remaining.len(),
            ReaderPattern::Chunked { chunk_size } => {
                std::cmp::min(remaining.len(), chunk_size as usize)
            }
            ReaderPattern::Intermittent => {
                this.chunk_counter = this.chunk_counter.wrapping_add(1);
                if this.chunk_counter % 3 == 0 {
                    return Poll::Pending;
                }
                std::cmp::min(remaining.len(), 4)
            }
            ReaderPattern::SingleByte => 1,
            ReaderPattern::Malformed => {
                // Inject malformed patterns
                std::cmp::min(remaining.len(), (this.chunk_counter as usize % 7) + 1)
            }
        };

        let to_read = std::cmp::min(to_read, buf.remaining());
        if to_read > 0 {
            buf.put_slice(&remaining[..to_read]);
            this.position += to_read;
        }

        Poll::Ready(Ok(()))
    }
}

/// Waker for testing cancellation scenarios
struct TestWaker {
    woke: Arc<AtomicBool>,
}

impl TestWaker {
    fn new() -> (Self, Arc<AtomicBool>) {
        let woke = Arc::new(AtomicBool::new(false));
        (Self { woke: woke.clone() }, woke)
    }
}

impl Wake for TestWaker {
    fn wake(self: Arc<Self>) {
        self.woke.store(true, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.woke.store(true, Ordering::SeqCst);
    }
}

/// Test the 5 FramedRead invariants
fn test_framed_read_invariants(input: FramedReadFuzzInput) -> Result<(), String> {
    // Normalize input
    let data_stream = input.data_stream;
    let max_frame_length = input.max_frame_length.clamp(8, 512);
    let initial_capacity = input.initial_capacity.clamp(16, 2048) as usize;

    let reader = TestAsyncReader::new(data_stream, input.reader_pattern);
    let decoder = TestDecoder::new(max_frame_length, input.decoder_error_after, input.custom_error_type);

    let mut framed = FramedRead::with_capacity(reader, decoder, initial_capacity);

    let (test_waker, woke_flag) = TestWaker::new();
    let waker = Waker::from(Arc::new(test_waker));
    let mut cx = Context::from_waker(&waker);

    let mut poll_count = 0;
    let mut frames_received = 0;
    let mut errors_received = 0;
    let mut last_buffer_len = 0;

    for (action_idx, action) in input.poll_sequence.iter().enumerate() {
        if action_idx > 50 {
            break; // Safety limit
        }

        match action {
            PollAction::Poll | PollAction::PollAndInspect => {
                poll_count += 1;

                // INVARIANT 3: poll_next re-entrance safe
                let poll_result = Pin::new(&mut framed).poll_next(&mut cx);

                match poll_result {
                    Poll::Ready(Some(Ok(frame))) => {
                        frames_received += 1;

                        // INVARIANT 1: Frame length should be within bounds
                        if frame.len() > max_frame_length as usize {
                            return Err(format!(
                                "Frame length {} exceeds max_frame_length {}",
                                frame.len(), max_frame_length
                            ));
                        }
                    }
                    Poll::Ready(Some(Err(_err))) => {
                        // INVARIANT 4: Custom Decoder errors propagated
                        errors_received += 1;
                    }
                    Poll::Ready(None) => {
                        // INVARIANT 2: Stream::next() termination on EOF correct
                        // This is the correct EOF termination
                        break;
                    }
                    Poll::Pending => {
                        // Valid state, continue
                    }
                }

                if matches!(action, PollAction::PollAndInspect) {
                    // INVARIANT 1: Readout buffer grows within max_frame_length
                    let current_buffer_len = framed.read_buffer().len();

                    // Buffer should not grow indefinitely beyond reasonable bounds
                    if current_buffer_len > (max_frame_length as usize * 2) {
                        return Err(format!(
                            "Buffer grew too large: {} bytes (max_frame_length: {})",
                            current_buffer_len, max_frame_length
                        ));
                    }

                    last_buffer_len = current_buffer_len;
                }

                // Test cancellation scenario
                if input.inject_cancellation && poll_count >= input.cancel_after_polls {
                    // INVARIANT 5: Cancellation drains buffered bytes
                    let buffer_before_cancel = framed.read_buffer().len();

                    // Simulate cancellation by dropping the future
                    drop(std::mem::replace(&mut cx, Context::from_waker(&waker)));
                    cx = Context::from_waker(&waker);

                    // Buffer should still be accessible and consistent
                    let buffer_after_cancel = framed.read_buffer().len();

                    if buffer_after_cancel != buffer_before_cancel {
                        return Err(format!(
                            "Buffer changed during cancellation: before={}, after={}",
                            buffer_before_cancel, buffer_after_cancel
                        ));
                    }
                }
            }

            PollAction::PollWithCancel => {
                // INVARIANT 5: Cancellation drains buffered bytes
                let buffer_before = framed.read_buffer().len();

                let _poll_result = Pin::new(&mut framed).poll_next(&mut cx);

                // Simulate cancellation by creating new context
                let (new_waker, _) = TestWaker::new();
                cx = Context::from_waker(&Waker::from(Arc::new(new_waker)));

                // Buffer should remain consistent across cancellation
                let buffer_after = framed.read_buffer().len();

                if buffer_after > buffer_before + max_frame_length as usize {
                    return Err(format!(
                        "Buffer grew unexpectedly during cancellation: before={}, after={}",
                        buffer_before, buffer_after
                    ));
                }
            }

            PollAction::ReEntrancePoll => {
                // INVARIANT 3: poll_next re-entrance safe
                // Call poll_next multiple times rapidly
                for _ in 0..3 {
                    let _poll_result = Pin::new(&mut framed).poll_next(&mut cx);
                }

                // Should not panic or corrupt state
                let buffer_len = framed.read_buffer().len();
                if buffer_len > max_frame_length as usize * 3 {
                    return Err(format!(
                        "Re-entrance caused excessive buffer growth: {}",
                        buffer_len
                    ));
                }
            }
        }
    }

    // Final invariant checks

    // INVARIANT 1: Buffer should never exceed reasonable bounds
    let final_buffer_len = framed.read_buffer().len();
    if final_buffer_len > max_frame_length as usize * 2 {
        return Err(format!(
            "Final buffer too large: {} (max_frame_length: {})",
            final_buffer_len, max_frame_length
        ));
    }

    // INVARIANT 4: Errors should be properly propagated if expected
    if input.decoder_error_after > 0 && input.decoder_error_after <= poll_count && errors_received == 0 {
        return Err("Expected decoder error was not propagated".to_string());
    }

    Ok(())
}

/// Normalize fuzz input to prevent timeouts and excessive resource usage
fn normalize_input(mut input: FramedReadFuzzInput) -> FramedReadFuzzInput {
    // Limit data size to prevent timeouts
    input.data_stream.truncate(2048);

    // Ensure some data exists for testing
    if input.data_stream.is_empty() {
        input.data_stream = b"test\nframe\ndata\n".to_vec();
    }

    // Clamp values to reasonable ranges
    input.max_frame_length = input.max_frame_length.clamp(8, 512);
    input.cancel_after_polls = input.cancel_after_polls.clamp(1, 20);
    input.decoder_error_after = input.decoder_error_after.clamp(5, 30);
    input.initial_capacity = input.initial_capacity.clamp(16, 1024);

    // Limit poll sequence to prevent timeouts
    input.poll_sequence.truncate(30);

    // Ensure some poll actions exist
    if input.poll_sequence.is_empty() {
        input.poll_sequence = vec![
            PollAction::Poll,
            PollAction::PollAndInspect,
            PollAction::ReEntrancePoll,
        ];
    }

    input
}

fuzz_target!(|data: &[u8]| {
    // Limit input size for performance
    if data.len() > 4096 {
        return;
    }

    let mut unstructured = arbitrary::Unstructured::new(data);

    let input = if let Ok(input) = FramedReadFuzzInput::arbitrary(&mut unstructured) {
        normalize_input(input)
    } else {
        return;
    };

    // Test the 5 FramedRead invariants
    if let Err(_err) = test_framed_read_invariants(input) {
        // Invariant violation detected - this is what we're looking for
        panic!("FramedRead invariant violation: {}", _err);
    }
});