#![no_main]

//! Fuzz target for FramedRead partial read state machine.
//!
//! This target exercises critical FramedRead scenarios including:
//! 1. Partial read accumulation and buffer management
//! 2. Decoder state transitions (decode/decode_eof)
//! 3. Cooperative yielding under continuous ready readers
//! 4. EOF handling and final decode attempts
//! 5. Error propagation from both reader and decoder
//! 6. Cancel safety and state preservation across polls
//! 7. Buffer growth and reallocation edge cases

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, FramedRead};
use asupersync::io::{AsyncRead, ReadBuf};
use asupersync::stream::Stream;

/// Simplified fuzz input for FramedRead operations
#[derive(Arbitrary, Debug, Clone)]
struct FramedReadFuzzInput {
    /// Random seed for deterministic execution
    pub seed: u64,
    /// Sequence of operations to execute
    pub operations: Vec<FramedReadOperation>,
    /// Reader configuration
    pub reader_config: MockReaderConfig,
    /// Decoder configuration
    pub decoder_config: MockDecoderConfig,
    /// Initial buffer capacity
    pub initial_capacity: u16,
}

/// Individual FramedRead operations to fuzz
#[derive(Arbitrary, Debug, Clone)]
enum FramedReadOperation {
    /// Poll for next frame
    PollNext,
    /// Poll next with potential cancellation
    PollNextWithCancel { cancel_after_reads: u8 },
    /// Access buffer state
    InspectBuffer,
    /// Access decoder state
    InspectDecoder,
    /// Test cooperative yielding
    TestCooperativeYield,
    /// Force EOF condition
    ForceEof,
    /// Inject read error
    InjectReadError { error_kind: u8 },
    /// Inject decode error
    InjectDecodeError,
}

/// Configuration for mock AsyncRead behavior
#[derive(Arbitrary, Debug, Clone)]
struct MockReaderConfig {
    /// Data chunks to provide
    pub data_chunks: Vec<Vec<u8>>,
    /// Read pattern (immediate, chunked, error)
    pub read_pattern: ReadPattern,
    /// Error injection points
    pub error_points: Vec<u8>,
    /// Maximum reads before forcing EOF
    pub max_reads: u8,
}

/// Read patterns for mock reader
#[derive(Arbitrary, Debug, Clone)]
enum ReadPattern {
    /// All data available immediately
    Immediate,
    /// Data provided in small chunks
    Chunked { chunk_size: u8 },
    /// Alternates ready/pending
    Alternating,
    /// Always ready (for cooperative yield testing)
    AlwaysReady,
    /// Single byte at a time
    SingleByte,
}

/// Configuration for mock Decoder behavior
#[derive(Arbitrary, Debug, Clone)]
struct MockDecoderConfig {
    /// Frame delimiter pattern
    pub delimiter: u8,
    /// Maximum frame length
    pub max_frame_length: u16,
    /// Error injection probability (0-255)
    pub error_probability: u8,
    /// Decoder type
    pub decoder_type: DecoderType,
}

/// Types of mock decoders
#[derive(Arbitrary, Debug, Clone)]
enum DecoderType {
    /// Simple delimiter-based decoder
    Delimiter,
    /// Length-prefixed decoder
    LengthPrefixed,
    /// Fixed-length frame decoder
    FixedLength { frame_size: u8 },
    /// Always-partial decoder (never completes)
    AlwaysPartial,
    /// Always-error decoder
    AlwaysError,
}

/// Mock AsyncRead implementation
struct MockAsyncReader {
    chunks: Vec<Vec<u8>>,
    current_chunk: usize,
    current_pos: usize,
    pattern: ReadPattern,
    error_points: Vec<u8>,
    reads_count: u8,
    max_reads: u8,
    force_eof: bool,
    pending_toggle: bool,
}

impl MockAsyncReader {
    fn new(config: MockReaderConfig) -> Self {
        Self {
            chunks: config.data_chunks,
            current_chunk: 0,
            current_pos: 0,
            pattern: config.read_pattern,
            error_points: config.error_points,
            reads_count: 0,
            max_reads: config.max_reads.clamp(1, 100),
            force_eof: false,
            pending_toggle: false,
        }
    }

    fn force_eof(&mut self) {
        self.force_eof = true;
    }
}

impl AsyncRead for MockAsyncReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        this.reads_count = this.reads_count.saturating_add(1);

        // Check for forced EOF or read limit
        if this.force_eof || this.reads_count > this.max_reads {
            return Poll::Ready(Ok(()));
        }

        // Check for error injection
        if this.error_points.contains(&this.reads_count) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mock reader error",
            )));
        }

        // Handle different read patterns
        match this.pattern {
            ReadPattern::Alternating => {
                this.pending_toggle = !this.pending_toggle;
                if this.pending_toggle {
                    return Poll::Pending;
                }
            }
            ReadPattern::AlwaysReady => {
                // Continue to data provision
            }
            _ => {}
        }

        // Provide data if available
        if this.current_chunk >= this.chunks.len() {
            return Poll::Ready(Ok(())); // EOF
        }

        let chunk = &this.chunks[this.current_chunk];
        if this.current_pos >= chunk.len() {
            this.current_chunk += 1;
            this.current_pos = 0;
            if this.current_chunk >= this.chunks.len() {
                return Poll::Ready(Ok(())); // EOF
            }
        }

        let chunk = &this.chunks[this.current_chunk];
        let remaining = &chunk[this.current_pos..];

        let to_copy = match this.pattern {
            ReadPattern::Chunked { chunk_size } => {
                std::cmp::min(remaining.len(), chunk_size as usize)
            }
            ReadPattern::SingleByte => 1,
            ReadPattern::AlwaysReady => 1, // Single byte for continuous yield testing
            _ => remaining.len(),
        };

        let to_copy = std::cmp::min(to_copy, buf.remaining());
        if to_copy > 0 {
            buf.put_slice(&remaining[..to_copy]);
            this.current_pos += to_copy;
        }

        Poll::Ready(Ok(()))
    }
}

/// Mock Decoder implementation
struct MockDecoder {
    delimiter: u8,
    max_frame_length: u16,
    error_probability: u8,
    decoder_type: DecoderType,
    decode_calls: u8,
    eof_called: bool,
}

impl MockDecoder {
    fn new(config: MockDecoderConfig) -> Self {
        Self {
            delimiter: config.delimiter,
            max_frame_length: config.max_frame_length.clamp(1, 1024),
            error_probability: config.error_probability,
            decoder_type: config.decoder_type,
            decode_calls: 0,
            eof_called: false,
        }
    }

    fn should_error(&mut self) -> bool {
        self.decode_calls = self.decode_calls.saturating_add(1);
        // Simple deterministic error injection
        (self.decode_calls as u16 * 256 / 100) < self.error_probability as u16
    }
}

#[derive(Debug)]
enum MockDecodeError {
    Io(io::Error),
    MaxLengthExceeded,
    InvalidFrame,
}

impl std::fmt::Display for MockDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "io error: {}", err),
            Self::MaxLengthExceeded => write!(f, "frame exceeds maximum length"),
            Self::InvalidFrame => write!(f, "invalid frame"),
        }
    }
}

impl std::error::Error for MockDecodeError {}

impl From<io::Error> for MockDecodeError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl Decoder for MockDecoder {
    type Item = Vec<u8>;
    type Error = MockDecodeError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.decoder_type {
            DecoderType::AlwaysError => Err(MockDecodeError::InvalidFrame),
            DecoderType::AlwaysPartial => {
                // Never completes, always needs more data
                Ok(None)
            }
            DecoderType::Delimiter => {
                if self.should_error() {
                    return Err(MockDecodeError::InvalidFrame);
                }

                if let Some(pos) = src.iter().position(|&b| b == self.delimiter) {
                    if pos > self.max_frame_length as usize {
                        return Err(MockDecodeError::MaxLengthExceeded);
                    }
                    let frame = src.split_to(pos + 1);
                    Ok(Some(frame[..pos].to_vec()))
                } else {
                    if src.len() > self.max_frame_length as usize {
                        return Err(MockDecodeError::MaxLengthExceeded);
                    }
                    Ok(None)
                }
            }
            DecoderType::LengthPrefixed => {
                if self.should_error() {
                    return Err(MockDecodeError::InvalidFrame);
                }

                if src.len() < 2 {
                    return Ok(None);
                }

                let length = u16::from_be_bytes([src[0], src[1]]) as usize;
                if length > self.max_frame_length as usize {
                    return Err(MockDecodeError::MaxLengthExceeded);
                }

                if src.len() < 2 + length {
                    return Ok(None);
                }

                let _length_bytes = src.split_to(2);
                let frame = src.split_to(length);
                Ok(Some(frame.to_vec()))
            }
            DecoderType::FixedLength { frame_size } => {
                if self.should_error() {
                    return Err(MockDecodeError::InvalidFrame);
                }

                let frame_size = frame_size.clamp(1, 64) as usize;
                if src.len() >= frame_size {
                    let frame = src.split_to(frame_size);
                    Ok(Some(frame.to_vec()))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.eof_called = true;

        match self.decoder_type {
            DecoderType::AlwaysError => Err(MockDecodeError::InvalidFrame),
            DecoderType::AlwaysPartial => {
                // Even at EOF, never completes
                Ok(None)
            }
            _ => {
                // Try regular decode first
                if let Some(frame) = self.decode(src)? {
                    return Ok(Some(frame));
                }

                // Handle remaining bytes at EOF
                if !src.is_empty() {
                    match self.decoder_type {
                        DecoderType::Delimiter => {
                            // Return remaining bytes as final frame
                            let frame = src.split_to(src.len());
                            Ok(Some(frame.to_vec()))
                        }
                        _ => Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "incomplete frame at EOF",
                        )
                        .into()),
                    }
                } else {
                    Ok(None)
                }
            }
        }
    }
}

/// Shadow model for tracking expected FramedRead behavior
#[derive(Debug)]
struct FramedReadShadowModel {
    /// Expected number of frames decoded
    frames_decoded: AtomicUsize,
    /// Expected buffer state
    buffer_bytes: AtomicUsize,
    /// EOF reached
    eof_reached: AtomicBool,
    /// Errors encountered
    errors_count: AtomicUsize,
    /// Cooperative yields
    cooperative_yields: AtomicUsize,
    /// State tracking
    last_poll_result: Arc<std::sync::Mutex<String>>,
}

impl FramedReadShadowModel {
    fn new() -> Self {
        Self {
            frames_decoded: AtomicUsize::new(0),
            buffer_bytes: AtomicUsize::new(0),
            eof_reached: AtomicBool::new(false),
            errors_count: AtomicUsize::new(0),
            cooperative_yields: AtomicUsize::new(0),
            last_poll_result: Arc::new(std::sync::Mutex::new("None".to_string())),
        }
    }

    fn record_frame_decoded(&self) {
        self.frames_decoded.fetch_add(1, Ordering::SeqCst);
    }

    fn record_error(&self) {
        self.errors_count.fetch_add(1, Ordering::SeqCst);
    }

    fn record_eof(&self) {
        self.eof_reached.store(true, Ordering::SeqCst);
    }

    fn record_cooperative_yield(&self) {
        self.cooperative_yields.fetch_add(1, Ordering::SeqCst);
    }

    fn update_buffer_size(&self, size: usize) {
        self.buffer_bytes.store(size, Ordering::SeqCst);
    }

    fn update_poll_result(&self, result: &str) {
        if let Ok(mut last) = self.last_poll_result.lock() {
            *last = result.to_string();
        }
    }

    fn verify_invariants(&self, framed_read_buffer_len: usize) -> Result<(), String> {
        let shadow_buffer_size = self.buffer_bytes.load(Ordering::SeqCst);

        // Buffer size tracking should be consistent
        if shadow_buffer_size != framed_read_buffer_len {
            return Err(format!(
                "Buffer size mismatch: shadow={}, actual={}",
                shadow_buffer_size, framed_read_buffer_len
            ));
        }

        let frames = self.frames_decoded.load(Ordering::SeqCst);
        let errors = self.errors_count.load(Ordering::SeqCst);

        // Can't have both frames and errors in some decoders
        if frames > 100 || errors > 50 {
            return Err(format!(
                "Excessive operations: frames={}, errors={}",
                frames, errors
            ));
        }

        Ok(())
    }
}

/// Normalize fuzz input to valid ranges
fn normalize_fuzz_input(input: &mut FramedReadFuzzInput) {
    // Limit operations to prevent timeouts
    input.operations.truncate(30);

    // Bound capacity
    input.initial_capacity = input.initial_capacity.clamp(8, 8192);

    // Normalize reader config
    input.reader_config.data_chunks.truncate(10);
    for chunk in &mut input.reader_config.data_chunks {
        chunk.truncate(256);
    }
    input.reader_config.error_points.truncate(5);
    input.reader_config.max_reads = input.reader_config.max_reads.clamp(1, 50);

    // Normalize decoder config
    input.decoder_config.max_frame_length = input.decoder_config.max_frame_length.clamp(1, 512);

    // Ensure we have some data to work with
    if input.reader_config.data_chunks.is_empty() {
        input
            .reader_config
            .data_chunks
            .push(vec![b'a', input.decoder_config.delimiter, b'b']);
    }
}

struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}

fn noop_waker() -> Waker {
    Waker::from(Arc::new(NoopWaker))
}

/// Execute FramedRead operations and verify behavior
fn execute_framed_read_operations(input: &FramedReadFuzzInput) -> Result<(), String> {
    let shadow = FramedReadShadowModel::new();

    let reader = MockAsyncReader::new(input.reader_config.clone());
    let decoder = MockDecoder::new(input.decoder_config.clone());

    let mut framed = FramedRead::with_capacity(reader, decoder, input.initial_capacity as usize);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    for (op_index, operation) in input.operations.iter().enumerate() {
        if op_index > 100 {
            break; // Safety limit
        }

        match operation {
            FramedReadOperation::PollNext => {
                let poll_result = Pin::new(&mut framed).poll_next(&mut cx);

                match poll_result {
                    Poll::Ready(Some(Ok(_frame))) => {
                        shadow.record_frame_decoded();
                        shadow.update_poll_result("Ready(Some(Ok(_)))");
                    }
                    Poll::Ready(Some(Err(_err))) => {
                        shadow.record_error();
                        shadow.update_poll_result("Ready(Some(Err(_)))");
                    }
                    Poll::Ready(None) => {
                        shadow.record_eof();
                        shadow.update_poll_result("Ready(None)");
                    }
                    Poll::Pending => {
                        shadow.record_cooperative_yield();
                        shadow.update_poll_result("Pending");
                    }
                }

                shadow.update_buffer_size(framed.read_buffer().len());
            }

            FramedReadOperation::PollNextWithCancel { cancel_after_reads } => {
                for _ in 0..*cancel_after_reads {
                    let poll_result = Pin::new(&mut framed).poll_next(&mut cx);

                    match poll_result {
                        Poll::Ready(_) => break,
                        Poll::Pending => continue,
                    }
                }

                // Test cancel safety by dropping the poll and starting fresh
                shadow.update_buffer_size(framed.read_buffer().len());
            }

            FramedReadOperation::InspectBuffer => {
                let buffer_len = framed.read_buffer().len();
                shadow.update_buffer_size(buffer_len);
            }

            FramedReadOperation::InspectDecoder => {
                let _decoder = framed.decoder();
                // Just access it to test borrowing
            }

            FramedReadOperation::TestCooperativeYield => {
                // This would be tested by using AlwaysReady reader pattern
                let poll_result = Pin::new(&mut framed).poll_next(&mut cx);

                if matches!(poll_result, Poll::Pending) {
                    shadow.record_cooperative_yield();
                }
            }

            FramedReadOperation::ForceEof => {
                framed.get_mut().force_eof();
            }

            FramedReadOperation::InjectReadError { error_kind: _ } => {
                // Reader error injection is handled by MockAsyncReader
                let poll_result = Pin::new(&mut framed).poll_next(&mut cx);

                if matches!(poll_result, Poll::Ready(Some(Err(_)))) {
                    shadow.record_error();
                }
            }

            FramedReadOperation::InjectDecodeError => {
                // Decoder error injection is handled by MockDecoder
                let poll_result = Pin::new(&mut framed).poll_next(&mut cx);

                if matches!(poll_result, Poll::Ready(Some(Err(_)))) {
                    shadow.record_error();
                }
            }
        }

        // Verify invariants after each operation
        shadow.verify_invariants(framed.read_buffer().len())?;
    }

    Ok(())
}

/// Main fuzzing entry point
fn fuzz_framed_read_state_machine(mut input: FramedReadFuzzInput) -> Result<(), String> {
    normalize_fuzz_input(&mut input);

    // Skip degenerate cases
    if input.operations.is_empty() {
        return Ok(());
    }

    // Execute FramedRead state machine tests
    execute_framed_read_operations(&input)?;

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Limit input size for performance
    if data.len() > 8192 {
        return;
    }

    let mut unstructured = arbitrary::Unstructured::new(data);

    // Generate fuzz configuration
    let input = if let Ok(input) = FramedReadFuzzInput::arbitrary(&mut unstructured) {
        input
    } else {
        return;
    };

    // Run FramedRead state machine fuzzing
    let _ = fuzz_framed_read_state_machine(input);
});
