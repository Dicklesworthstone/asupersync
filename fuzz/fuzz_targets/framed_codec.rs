//! Fuzz target for codec::framed transport edge cases.
//!
//! Focuses on the Framed<T, U> transport wrapper that combines AsyncRead/AsyncWrite
//! transports with Encoder/Decoder codecs. Tests edge cases in:
//! 1. Stream polling with cooperative limits and buffer management
//! 2. Send/flush/close state machine with partial writes
//! 3. Read buffer edge cases and EOF handling
//! 4. Different codec behaviors with framed transport
//! 5. Buffer capacity limits and memory management
//!
//! Key attack vectors:
//! - Cooperative polling limits bypass (MAX_READ_PASSES_PER_POLL/MAX_WRITE_PASSES_PER_POLL)
//! - Buffer management edge cases with various capacity configurations
//! - State machine corruption via partial I/O operations
//! - EOF handling edge cases and stream termination
//! - Codec error propagation and recovery

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::framed::Framed;
use asupersync::codec::{BytesCodec, Decoder, Encoder, LinesCodec};
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::stream::Stream;
use libfuzzer_sys::fuzz_target;
use std::collections::VecDeque;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Maximum input size to prevent memory exhaustion during fuzzing
const MAX_INPUT_SIZE: usize = 64 * 1024; // 64KB
/// Maximum number of frames to include in a round-trip invariant check.
const MAX_ROUNDTRIP_FRAMES: usize = 16;
/// Maximum size of any single round-trip frame.
const MAX_ROUNDTRIP_FRAME_SIZE: usize = 1024;

/// Framed codec fuzzing configuration
#[derive(Arbitrary, Debug)]
struct FramedFuzzConfig {
    /// Buffer capacity for the framed transport
    buffer_capacity: BufferCapacity,
    /// Transport behavior configuration
    transport_behavior: TransportBehavior,
    /// Codec type to use
    codec_type: CodecType,
    /// Sequence of operations to perform
    operations: Vec<FramedOperation>,
}

/// Buffer capacity configuration options
#[derive(Arbitrary, Debug)]
enum BufferCapacity {
    /// Tiny buffer (16 bytes) - forces frequent buffer operations
    Tiny,
    /// Small buffer (256 bytes) - normal small buffer
    Small,
    /// Default buffer (8192 bytes) - standard size
    Default,
    /// Large buffer (64KB) - large buffer testing
    Large,
    /// Zero capacity (tests edge case)
    Zero,
    /// Custom capacity for boundary testing
    Custom { size: u16 },
}

impl BufferCapacity {
    fn to_usize(&self) -> usize {
        match self {
            BufferCapacity::Tiny => 16,
            BufferCapacity::Small => 256,
            BufferCapacity::Default => 8192,
            BufferCapacity::Large => 64 * 1024,
            BufferCapacity::Zero => 0,
            BufferCapacity::Custom { size } => (*size as usize).min(MAX_INPUT_SIZE),
        }
    }
}

/// Transport behavior for testing different I/O patterns
#[derive(Arbitrary, Debug)]
enum TransportBehavior {
    /// Normal transport - always ready for I/O
    Normal { data: Vec<u8> },
    /// Partial I/O - returns small chunks at a time
    Partial { data: Vec<u8>, chunk_size: u8 },
    /// Pending transport - sometimes returns Poll::Pending
    Pending {
        data: Vec<u8>,
        pending_frequency: u8,
    },
    /// Error-prone transport - occasionally returns I/O errors
    ErrorProne { data: Vec<u8>, error_frequency: u8 },
    /// EOF early - signals EOF before all data is consumed
    EofEarly { data: Vec<u8>, eof_position: u16 },
    /// Slow writer - write operations may fail or return partial
    SlowWriter {
        data: Vec<u8>,
        write_success_rate: u8,
    },
}

/// Codec types for testing different encoding/decoding behaviors
#[derive(Arbitrary, Debug)]
enum CodecType {
    /// Lines codec - splits on newlines
    Lines,
    /// Bytes codec - passes through raw bytes
    Bytes,
    /// Mock error codec - simulates encoding/decoding errors
    ErrorProne { error_frequency: u8 },
    /// Mock slow codec - takes multiple passes to decode
    Slow { decode_speed: u8 },
}

/// Operations to perform on the framed transport
#[derive(Arbitrary, Debug)]
enum FramedOperation {
    /// Poll the stream for the next item
    PollNext,
    /// Send an item through the transport
    Send { data: Vec<u8> },
    /// Poll flush to ensure writes are committed
    PollFlush,
    /// Poll close to shutdown the transport
    PollClose,
    /// Read buffer inspection
    InspectReadBuffer,
    /// Write buffer inspection
    InspectWriteBuffer,
    /// Touch codec state through the mutable accessor
    ModifyCodec,
}

/// Mock transport implementation for testing
#[derive(Debug)]
struct MockTransport {
    read_data: VecDeque<u8>,
    write_data: Vec<u8>,
    read_behavior: ReadBehavior,
    write_behavior: WriteBehavior,
    eof_position: Option<usize>,
    bytes_read: usize,
    poll_count: usize,
}

#[derive(Debug)]
enum ReadBehavior {
    Normal,
    Partial { chunk_size: usize },
    Pending { frequency: u8 },
    ErrorProne { frequency: u8 },
}

#[derive(Debug)]
enum WriteBehavior {
    Normal,
    Partial { max_write: usize },
    Pending { frequency: u8 },
    ErrorProne { frequency: u8 },
}

impl MockTransport {
    fn new(behavior: TransportBehavior) -> Self {
        match behavior {
            TransportBehavior::Normal { data } => Self {
                read_data: data.into(),
                write_data: Vec::new(),
                read_behavior: ReadBehavior::Normal,
                write_behavior: WriteBehavior::Normal,
                eof_position: None,
                bytes_read: 0,
                poll_count: 0,
            },
            TransportBehavior::Partial { data, chunk_size } => Self {
                read_data: data.into(),
                write_data: Vec::new(),
                read_behavior: ReadBehavior::Partial {
                    chunk_size: (chunk_size as usize).max(1),
                },
                write_behavior: WriteBehavior::Partial {
                    max_write: chunk_size as usize,
                },
                eof_position: None,
                bytes_read: 0,
                poll_count: 0,
            },
            TransportBehavior::Pending {
                data,
                pending_frequency,
            } => Self {
                read_data: data.into(),
                write_data: Vec::new(),
                read_behavior: ReadBehavior::Pending {
                    frequency: pending_frequency,
                },
                write_behavior: WriteBehavior::Pending {
                    frequency: pending_frequency,
                },
                eof_position: None,
                bytes_read: 0,
                poll_count: 0,
            },
            TransportBehavior::ErrorProne {
                data,
                error_frequency,
            } => Self {
                read_data: data.into(),
                write_data: Vec::new(),
                read_behavior: ReadBehavior::ErrorProne {
                    frequency: error_frequency,
                },
                write_behavior: WriteBehavior::ErrorProne {
                    frequency: error_frequency,
                },
                eof_position: None,
                bytes_read: 0,
                poll_count: 0,
            },
            TransportBehavior::EofEarly { data, eof_position } => Self {
                read_data: data.into(),
                write_data: Vec::new(),
                read_behavior: ReadBehavior::Normal,
                write_behavior: WriteBehavior::Normal,
                eof_position: Some(eof_position as usize),
                bytes_read: 0,
                poll_count: 0,
            },
            TransportBehavior::SlowWriter {
                data,
                write_success_rate,
            } => Self {
                read_data: data.into(),
                write_data: Vec::new(),
                read_behavior: ReadBehavior::Normal,
                write_behavior: WriteBehavior::ErrorProne {
                    frequency: 255 - write_success_rate,
                },
                eof_position: None,
                bytes_read: 0,
                poll_count: 0,
            },
        }
    }
}

impl AsyncRead for MockTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        self.poll_count += 1;

        // Check if we should return EOF early
        if let Some(eof_pos) = self.eof_position
            && self.bytes_read >= eof_pos
        {
            return Poll::Ready(Ok(()));
        }

        match &self.read_behavior {
            ReadBehavior::Normal => {
                let to_read = buf.remaining().min(self.read_data.len());
                for _ in 0..to_read {
                    if let Some(byte) = self.read_data.pop_front() {
                        buf.put_slice(&[byte]);
                        self.bytes_read += 1;
                    }
                }
                Poll::Ready(Ok(()))
            }
            ReadBehavior::Partial { chunk_size } => {
                let to_read = buf.remaining().min(self.read_data.len()).min(*chunk_size);
                for _ in 0..to_read {
                    if let Some(byte) = self.read_data.pop_front() {
                        buf.put_slice(&[byte]);
                        self.bytes_read += 1;
                    }
                }
                Poll::Ready(Ok(()))
            }
            ReadBehavior::Pending { frequency } => {
                if self.poll_count.is_multiple_of(*frequency as usize + 1) {
                    Poll::Pending
                } else {
                    let to_read = buf.remaining().min(self.read_data.len()).min(1);
                    for _ in 0..to_read {
                        if let Some(byte) = self.read_data.pop_front() {
                            buf.put_slice(&[byte]);
                            self.bytes_read += 1;
                        }
                    }
                    Poll::Ready(Ok(()))
                }
            }
            ReadBehavior::ErrorProne { frequency } => {
                if self.poll_count.is_multiple_of(*frequency as usize + 1) {
                    Poll::Ready(Err(IoError::other("simulated read error")))
                } else {
                    let to_read = buf.remaining().min(self.read_data.len());
                    for _ in 0..to_read {
                        if let Some(byte) = self.read_data.pop_front() {
                            buf.put_slice(&[byte]);
                            self.bytes_read += 1;
                        }
                    }
                    Poll::Ready(Ok(()))
                }
            }
        }
    }
}

impl AsyncWrite for MockTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        match &self.write_behavior {
            WriteBehavior::Normal => {
                self.write_data.extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            }
            WriteBehavior::Partial { max_write } => {
                let to_write = buf.len().min(*max_write).max(1);
                self.write_data.extend_from_slice(&buf[..to_write]);
                Poll::Ready(Ok(to_write))
            }
            WriteBehavior::Pending { frequency } => {
                if self.poll_count.is_multiple_of(*frequency as usize + 1) {
                    Poll::Pending
                } else {
                    let to_write = buf.len().min(1);
                    self.write_data.extend_from_slice(&buf[..to_write]);
                    Poll::Ready(Ok(to_write))
                }
            }
            WriteBehavior::ErrorProne { frequency } => {
                if self.poll_count.is_multiple_of(*frequency as usize + 1) {
                    Poll::Ready(Err(IoError::other("simulated write error")))
                } else {
                    self.write_data.extend_from_slice(buf);
                    Poll::Ready(Ok(buf.len()))
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Mock error-prone codec for testing error handling
#[derive(Debug)]
struct MockErrorCodec {
    error_frequency: u8,
    decode_count: usize,
    encode_count: usize,
}

impl MockErrorCodec {
    fn new(error_frequency: u8) -> Self {
        Self {
            error_frequency,
            decode_count: 0,
            encode_count: 0,
        }
    }
}

impl Decoder for MockErrorCodec {
    type Item = BytesMut;
    type Error = std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.decode_count += 1;

        if self
            .decode_count
            .is_multiple_of(self.error_frequency as usize + 1)
        {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "mock decode error",
            ));
        }

        if buf.is_empty() {
            return Ok(None);
        }

        // Simple decoder: read one byte at a time
        if !buf.is_empty() {
            Ok(Some(buf.split_to(1)))
        } else {
            Ok(None)
        }
    }
}

impl Encoder<BytesMut> for MockErrorCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: BytesMut, buf: &mut BytesMut) -> Result<(), Self::Error> {
        self.encode_count += 1;

        if self
            .encode_count
            .is_multiple_of(self.error_frequency as usize + 1)
        {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "mock encode error",
            ));
        }

        buf.extend_from_slice(&item);
        Ok(())
    }
}

/// Mock slow codec for testing cooperative polling limits
#[derive(Debug)]
struct MockSlowCodec {
    decode_speed: u8,
}

impl MockSlowCodec {
    fn new(decode_speed: u8) -> Self {
        Self { decode_speed }
    }
}

impl Decoder for MockSlowCodec {
    type Item = BytesMut;
    type Error = std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let decode_size = (self.decode_speed as usize).max(1);

        // Simulate slow decoding by only processing small chunks
        if buf.len() >= decode_size {
            Ok(Some(buf.split_to(decode_size)))
        } else {
            Ok(None)
        }
    }
}

impl Encoder<BytesMut> for MockSlowCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: BytesMut, buf: &mut BytesMut) -> Result<(), Self::Error> {
        buf.extend_from_slice(&item);
        Ok(())
    }
}

/// Simple byte-preserving framing codec used for round-trip invariants.
#[derive(Debug, Default)]
struct PrefixCodec;

impl Decoder for PrefixCodec {
    type Item = BytesMut;
    type Error = std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.len() < 2 {
            return Ok(None);
        }

        let frame_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if frame_len > MAX_INPUT_SIZE {
            return Err(IoError::new(ErrorKind::InvalidData, "frame too large"));
        }
        if buf.len() < 2 + frame_len {
            return Ok(None);
        }

        let _ = buf.split_to(2);
        Ok(Some(buf.split_to(frame_len)))
    }
}

impl Encoder<BytesMut> for PrefixCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: BytesMut, buf: &mut BytesMut) -> Result<(), Self::Error> {
        if item.len() > u16::MAX as usize {
            return Err(IoError::new(ErrorKind::InvalidInput, "frame too large"));
        }

        buf.extend_from_slice(&(item.len() as u16).to_be_bytes());
        buf.extend_from_slice(&item);
        Ok(())
    }
}

fn collect_roundtrip_frames(config: &FramedFuzzConfig) -> Vec<BytesMut> {
    config
        .operations
        .iter()
        .filter_map(|operation| match operation {
            FramedOperation::Send { data } => Some(BytesMut::from(
                &data[..data.len().min(MAX_ROUNDTRIP_FRAME_SIZE)],
            )),
            _ => None,
        })
        .take(MAX_ROUNDTRIP_FRAMES)
        .collect()
}

fn derive_roundtrip_chunk_size(config: &FramedFuzzConfig) -> u8 {
    match &config.transport_behavior {
        TransportBehavior::Partial { chunk_size, .. } => (*chunk_size).clamp(1, 32),
        TransportBehavior::Pending {
            pending_frequency, ..
        } => pending_frequency.saturating_add(1).clamp(1, 16),
        TransportBehavior::ErrorProne {
            error_frequency, ..
        } => error_frequency.saturating_add(1).clamp(1, 16),
        TransportBehavior::EofEarly { eof_position, .. } => {
            (*eof_position as usize).clamp(1, 32) as u8
        }
        TransportBehavior::SlowWriter {
            write_success_rate, ..
        } => (*write_success_rate).clamp(1, 16),
        TransportBehavior::Normal { .. } => 7,
    }
}

fn flush_until_ready<T, U>(framed: &mut Framed<T, U>, cx: &mut Context<'_>)
where
    T: AsyncRead + AsyncWrite + Unpin,
    U: Decoder + Encoder<BytesMut> + Unpin,
{
    for _ in 0..64 {
        match framed.poll_flush(cx) {
            Poll::Ready(Ok(())) => return,
            Poll::Ready(Err(err)) => panic!("round-trip flush failed: {err}"),
            Poll::Pending => {}
        }
    }

    panic!("round-trip flush failed to make progress");
}

fn decode_prefix_roundtrip_frames(
    encoded: Vec<u8>,
    chunk_size: u8,
    capacity: usize,
) -> Vec<BytesMut> {
    let transport = MockTransport::new(TransportBehavior::Partial {
        data: encoded,
        chunk_size,
    });
    let mut framed = Framed::with_capacity(transport, PrefixCodec, capacity.max(1));
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut decoded = Vec::new();

    for _ in 0..256 {
        match Pin::new(&mut framed).poll_next(&mut cx) {
            Poll::Ready(Some(Ok(frame))) => decoded.push(frame),
            Poll::Ready(Some(Err(err))) => panic!("round-trip decode failed: {err}"),
            Poll::Ready(None) => break,
            Poll::Pending => {}
        }
    }

    decoded
}

fn exercise_prefix_roundtrip_invariant(config: &FramedFuzzConfig) {
    let frames = collect_roundtrip_frames(config);
    if frames.is_empty() {
        return;
    }

    let capacity = config.buffer_capacity.to_usize().clamp(1, MAX_INPUT_SIZE);
    let transport = MockTransport::new(TransportBehavior::Normal { data: Vec::new() });
    let mut framed = Framed::with_capacity(transport, PrefixCodec, capacity);
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);

    for frame in &frames {
        framed
            .send(frame.clone())
            .expect("prefix codec must encode bounded round-trip frames");
    }
    flush_until_ready(&mut framed, &mut cx);

    let encoded = framed.get_ref().write_data.clone();
    let decoded =
        decode_prefix_roundtrip_frames(encoded, derive_roundtrip_chunk_size(config), capacity);

    assert_eq!(
        decoded.len(),
        frames.len(),
        "framed round-trip changed frame count"
    );
    for (index, (expected, actual)) in frames.iter().zip(decoded.iter()).enumerate() {
        assert_eq!(
            actual.as_ref(),
            expected.as_ref(),
            "framed round-trip changed frame payload at index {index}"
        );
    }
}

fuzz_target!(|input: FramedFuzzConfig| {
    // Limit total operations to prevent excessive test time
    let operations = input.operations.iter().take(100);

    exercise_prefix_roundtrip_invariant(&input);

    // Create transport
    let transport = MockTransport::new(input.transport_behavior);

    // Create framed transport with appropriate codec and buffer capacity
    let capacity = input.buffer_capacity.to_usize();

    // Create the framed transport based on codec type
    match input.codec_type {
        CodecType::Lines => {
            let mut framed = Framed::with_capacity(transport, LinesCodec::new(), capacity);
            test_framed_operations_lines(&mut framed, operations);
        }
        CodecType::Bytes => {
            let mut framed = Framed::with_capacity(transport, BytesCodec::new(), capacity);
            test_framed_operations_bytes(&mut framed, operations);
        }
        CodecType::ErrorProne { error_frequency } => {
            let mut framed =
                Framed::with_capacity(transport, MockErrorCodec::new(error_frequency), capacity);
            test_framed_operations_bytes(&mut framed, operations);
        }
        CodecType::Slow { decode_speed } => {
            let mut framed =
                Framed::with_capacity(transport, MockSlowCodec::new(decode_speed), capacity);
            test_framed_operations_bytes(&mut framed, operations);
        }
    }
});

fn test_framed_operations_lines<T>(
    framed: &mut Framed<T, LinesCodec>,
    operations: std::iter::Take<std::slice::Iter<FramedOperation>>,
) where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // Create a dummy waker for polling operations
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);

    for operation in operations {
        match operation {
            FramedOperation::PollNext => {
                // Test stream polling with proper error handling
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ = Pin::new(&mut *framed).poll_next(&mut cx);
                }));
            }

            FramedOperation::Send { data } => {
                // Limit data size to prevent memory exhaustion
                let limited_data = data.iter().take(MAX_INPUT_SIZE).cloned().collect();
                // Convert Vec<u8> to String for LinesCodec
                if let Ok(string_data) = String::from_utf8(limited_data) {
                    let _ = framed.send(string_data);
                }
            }

            FramedOperation::PollFlush => {
                let _ = framed.poll_flush(&mut cx);
            }

            FramedOperation::PollClose => {
                let _ = framed.poll_close(&mut cx);
            }

            FramedOperation::InspectReadBuffer => {
                let _ = framed.read_buffer();
            }

            FramedOperation::InspectWriteBuffer => {
                let _ = framed.write_buffer();
            }

            FramedOperation::ModifyCodec => {
                // LinesCodec doesn't have mutable behavior
                let _ = framed.codec_mut();
            }
        }
    }
}

fn test_framed_operations_bytes<T, U>(
    framed: &mut Framed<T, U>,
    operations: std::iter::Take<std::slice::Iter<FramedOperation>>,
) where
    T: AsyncRead + AsyncWrite + Unpin,
    U: Decoder + Encoder<BytesMut> + Unpin,
{
    // Create a dummy waker for polling operations
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);

    for operation in operations {
        match operation {
            FramedOperation::PollNext => {
                // Test stream polling with proper error handling
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ = Pin::new(&mut *framed).poll_next(&mut cx);
                }));
            }

            FramedOperation::Send { data } => {
                // Limit data size to prevent memory exhaustion
                let limited_data: Vec<u8> = data.iter().take(MAX_INPUT_SIZE).cloned().collect();
                let bytes_data = BytesMut::from(&limited_data[..]);
                let _ = framed.send(bytes_data);
            }

            FramedOperation::PollFlush => {
                let _ = framed.poll_flush(&mut cx);
            }

            FramedOperation::PollClose => {
                let _ = framed.poll_close(&mut cx);
            }

            FramedOperation::InspectReadBuffer => {
                let _ = framed.read_buffer();
            }

            FramedOperation::InspectWriteBuffer => {
                let _ = framed.write_buffer();
            }

            FramedOperation::ModifyCodec => {
                // For mock codecs, we could modify behavior here
                let _ = framed.codec_mut();
            }
        }
    }
}

// Import futures_util for the noop_waker
extern crate futures_util;
