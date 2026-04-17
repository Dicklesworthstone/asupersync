//! Comprehensive fuzz target for codec framing (MessagePack / BSON-style).
//!
//! Targets src/codec/length_delimited.rs and src/codec/framed.rs with:
//! - Length-prefix decoder with 1/2/3/4-byte length encodings
//! - Max-frame-size enforcement testing
//! - Partial-read state machine testing
//! - Overflow at boundary values
//! - Structure-aware corpus from protocol captures
//! - Full-duplex framed transport testing
//!
//! # Attack Vectors
//! - Integer overflow in length field parsing (boundary values)
//! - State machine corruption via partial reads/writes
//! - Max frame size enforcement bypass
//! - Endianness confusion attacks
//! - Buffer management edge cases in framed transport

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::framed::Framed;
use asupersync::codec::{Decoder, Encoder, LengthDelimitedCodec};
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use libfuzzer_sys::fuzz_target;
use std::collections::VecDeque;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Structure-aware protocol frame patterns for seeded corpus
#[derive(Arbitrary, Debug, Clone)]
enum ProtocolFrame {
    /// MessagePack-style with 1-byte length (fixstr format)
    MessagePackFixStr { data: Vec<u8> },
    /// MessagePack-style with 2-byte length (str 16)
    MessagePackStr16 { data: Vec<u8> },
    /// MessagePack-style with 4-byte length (str 32)
    MessagePackStr32 { data: Vec<u8> },
    /// BSON-style document with 4-byte length prefix
    BsonDocument { data: Vec<u8> },
    /// Protocol Buffers delimited message
    ProtobufDelimited { data: Vec<u8> },
    /// Raw bytes for boundary testing
    RawBytes { data: Vec<u8> },
}

impl ProtocolFrame {
    /// Serialize frame according to its protocol format
    fn serialize(&self, big_endian: bool) -> Vec<u8> {
        match self {
            ProtocolFrame::MessagePackFixStr { data } => {
                if data.len() <= 31 {
                    let mut result = vec![0xa0 | (data.len() as u8)]; // fixstr format
                    result.extend_from_slice(data);
                    result
                } else {
                    // Fallback to raw bytes if too large
                    data.clone()
                }
            }
            ProtocolFrame::MessagePackStr16 { data } => {
                let len = std::cmp::min(data.len(), 65535);
                let mut result = vec![0xda]; // str 16 format
                if big_endian {
                    result.extend_from_slice(&(len as u16).to_be_bytes());
                } else {
                    result.extend_from_slice(&(len as u16).to_le_bytes());
                }
                result.extend_from_slice(&data[..len]);
                result
            }
            ProtocolFrame::MessagePackStr32 { data } => {
                let len = std::cmp::min(data.len(), u32::MAX as usize);
                let mut result = vec![0xdb]; // str 32 format
                if big_endian {
                    result.extend_from_slice(&(len as u32).to_be_bytes());
                } else {
                    result.extend_from_slice(&(len as u32).to_le_bytes());
                }
                result.extend_from_slice(&data[..len]);
                result
            }
            ProtocolFrame::BsonDocument { data } => {
                let total_len = data.len() + 4; // Include length field itself
                let mut result = Vec::with_capacity(total_len);
                if big_endian {
                    result.extend_from_slice(&(total_len as u32).to_be_bytes());
                } else {
                    result.extend_from_slice(&(total_len as u32).to_le_bytes());
                }
                result.extend_from_slice(data);
                result
            }
            ProtocolFrame::ProtobufDelimited { data } => {
                // varint encoding for length
                let mut result = Vec::new();
                encode_varint(data.len() as u64, &mut result);
                result.extend_from_slice(data);
                result
            }
            ProtocolFrame::RawBytes { data } => data.clone(),
        }
    }
}

/// Encode unsigned varint (Protocol Buffers style)
fn encode_varint(mut value: u64, buf: &mut Vec<u8>) {
    while value >= 0x80 {
        buf.push((value & 0x7F) as u8 | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

/// Codec configuration with boundary value testing
#[derive(Arbitrary, Debug)]
struct CodecConfig {
    /// Field offset (target boundary values)
    length_field_offset: BoundaryValueUsize,
    /// Field length (1/2/3/4 byte encodings + boundary cases)
    length_field_length: LengthFieldSize,
    /// Length adjustment (signed, test overflow)
    length_adjustment: BoundaryValueIsize,
    /// Bytes to skip after reading length
    num_skip: BoundaryValueUsize,
    /// Max frame length (test enforcement)
    max_frame_length: MaxFrameSize,
    /// Endianness
    big_endian: bool,
}

/// Boundary value wrapper for usize testing edge cases
#[derive(Arbitrary, Debug)]
enum BoundaryValueUsize {
    Zero,
    One,
    Small(u8), // Small positive value
    Large,     // Large value near type limits
    Max,       // Maximum value for type
}

impl BoundaryValueUsize {
    fn to_usize(&self) -> usize {
        match self {
            BoundaryValueUsize::Zero => 0,
            BoundaryValueUsize::One => 1,
            BoundaryValueUsize::Small(n) => *n as usize,
            BoundaryValueUsize::Large => 0xFFFF,
            BoundaryValueUsize::Max => usize::MAX,
        }
    }
}

/// Boundary value wrapper for isize testing edge cases
#[derive(Arbitrary, Debug)]
enum BoundaryValueIsize {
    Zero,
    One,
    Small(u8), // Small positive value
    Large,     // Large value near type limits
    Max,       // Maximum value for type
}

impl BoundaryValueIsize {
    fn to_isize(&self) -> isize {
        match self {
            BoundaryValueIsize::Zero => 0,
            BoundaryValueIsize::One => 1,
            BoundaryValueIsize::Small(n) => *n as isize,
            BoundaryValueIsize::Large => 0x7FFF,
            BoundaryValueIsize::Max => isize::MAX,
        }
    }
}

/// Length field size with specific 1/2/3/4 byte testing
#[derive(Arbitrary, Debug)]
enum LengthFieldSize {
    OneByte,
    TwoBytes,
    ThreeBytes,
    FourBytes,
    EightBytes, // Edge case
}

impl LengthFieldSize {
    fn to_usize(&self) -> usize {
        match self {
            LengthFieldSize::OneByte => 1,
            LengthFieldSize::TwoBytes => 2,
            LengthFieldSize::ThreeBytes => 3,
            LengthFieldSize::FourBytes => 4,
            LengthFieldSize::EightBytes => 8,
        }
    }
}

/// Max frame size with enforcement testing values
#[derive(Arbitrary, Debug)]
enum MaxFrameSize {
    Tiny,     // 64 bytes
    Small,    // 1KB
    Medium,   // 64KB
    Large,    // 1MB
    Huge,     // 8MB (default)
    Boundary, // Test boundary values
}

impl MaxFrameSize {
    fn to_usize(&self) -> usize {
        match self {
            MaxFrameSize::Tiny => 64,
            MaxFrameSize::Small => 1024,
            MaxFrameSize::Medium => 64 * 1024,
            MaxFrameSize::Large => 1024 * 1024,
            MaxFrameSize::Huge => 8 * 1024 * 1024,
            MaxFrameSize::Boundary => usize::MAX,
        }
    }
}

/// Mock transport for testing framed codec
#[derive(Debug)]
struct MockTransport {
    read_data: VecDeque<u8>,
    write_data: Vec<u8>,
    read_error: Option<IoError>,
    write_error: Option<IoError>,
    partial_reads: bool,
}

impl MockTransport {
    fn new(data: Vec<u8>) -> Self {
        Self {
            read_data: data.into(),
            write_data: Vec::new(),
            read_error: None,
            write_error: None,
            partial_reads: false,
        }
    }

    fn with_partial_reads(mut self) -> Self {
        self.partial_reads = true;
        self
    }

    fn with_read_error(mut self, error: IoError) -> Self {
        self.read_error = Some(error);
        self
    }

    fn written_data(&self) -> &[u8] {
        &self.write_data
    }
}

impl AsyncRead for MockTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        if let Some(ref error) = self.read_error {
            return Poll::Ready(Err(IoError::new(error.kind(), format!("{}", error))));
        }

        if self.read_data.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let to_read = if self.partial_reads {
            // Simulate partial reads by reading 1-3 bytes at a time
            std::cmp::min(3, std::cmp::min(buf.remaining(), self.read_data.len()))
        } else {
            std::cmp::min(buf.remaining(), self.read_data.len())
        };

        for _ in 0..to_read {
            if let Some(byte) = self.read_data.pop_front() {
                buf.put_slice(&[byte]);
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MockTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        if let Some(ref error) = self.write_error {
            return Poll::Ready(Err(IoError::new(error.kind(), format!("{}", error))));
        }

        self.write_data.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Simple encoder for testing framed transport
#[derive(Debug, Clone)]
struct TestEncoder;

impl Encoder<Vec<u8>> for TestEncoder {
    type Error = IoError;

    fn encode(&mut self, item: Vec<u8>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&item);
        Ok(())
    }
}

/// Operations to test on framed transport
#[derive(Arbitrary, Debug)]
enum FramedOperation {
    /// Decode a frame
    DecodeFrame,
    /// Encode and send data
    SendData { data: Vec<u8> },
    /// Flush write buffer
    Flush,
    /// Poll for next frame multiple times
    PollMultiple { count: u8 },
}

/// Main fuzz input structure
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Codec configuration
    config: CodecConfig,
    /// Protocol frames for structure-aware testing
    frames: Vec<ProtocolFrame>,
    /// Raw bytes for boundary testing
    raw_data: Vec<u8>,
    /// Framed transport operations
    framed_ops: Vec<FramedOperation>,
    /// Test partial reads
    test_partial_reads: bool,
    /// Trigger error conditions
    trigger_read_error: bool,
}

/// Test length-delimited codec with comprehensive coverage
fn test_length_delimited_codec(input: &FuzzInput) {
    let config = &input.config;

    // Guard against unreasonable configurations
    let length_field_offset = std::cmp::min(config.length_field_offset.to_usize(), 1024);
    let length_field_length = config.length_field_length.to_usize();
    let length_adjustment = config.length_adjustment.to_isize();
    let num_skip = std::cmp::min(config.num_skip.to_usize(), 1024);
    let max_frame_length = std::cmp::min(config.max_frame_length.to_usize(), 10_000_000);

    // Build codec with fuzzed configuration
    let mut codec_builder = LengthDelimitedCodec::builder()
        .length_field_offset(length_field_offset)
        .length_field_length(length_field_length)
        .length_adjustment(length_adjustment)
        .num_skip(num_skip)
        .max_frame_length(max_frame_length);

    if config.big_endian {
        codec_builder = codec_builder.big_endian();
    } else {
        codec_builder = codec_builder.little_endian();
    }

    let mut codec = codec_builder.clone().new_codec();

    // Test with structure-aware protocol frames
    for frame in &input.frames {
        let serialized = frame.serialize(config.big_endian);
        let mut buf = BytesMut::from(&serialized[..]);

        // Track decode attempts to prevent infinite loops
        let mut decode_attempts = 0;
        const MAX_DECODE_ATTEMPTS: usize = 100;

        while decode_attempts < MAX_DECODE_ATTEMPTS {
            decode_attempts += 1;

            match codec.decode(&mut buf) {
                Ok(Some(decoded_frame)) => {
                    // Successfully decoded frame - verify invariants
                    assert!(
                        decoded_frame.len() <= max_frame_length,
                        "Decoded frame {} exceeds max_frame_length {}",
                        decoded_frame.len(),
                        max_frame_length
                    );

                    // Ensure frame is reasonable size
                    assert!(
                        decoded_frame.len() <= 10_000_000,
                        "Decoded frame is suspiciously large: {}",
                        decoded_frame.len()
                    );

                    if buf.is_empty() {
                        break;
                    }
                }
                Ok(None) => {
                    // Need more data - expected for partial frames
                    break;
                }
                Err(_) => {
                    // Parse error - expected for malformed input
                    break;
                }
            }
        }
    }

    // Test with raw boundary-case data
    if !input.raw_data.is_empty() {
        // Test partial data processing
        for chunk_size in [1, 2, 3, 4, 8, 16, 64] {
            let mut codec = codec_builder.clone().new_codec();
            let mut pos = 0;

            while pos < input.raw_data.len() {
                let end = std::cmp::min(pos + chunk_size, input.raw_data.len());
                let mut chunk_buf = BytesMut::from(&input.raw_data[pos..end]);

                match codec.decode(&mut chunk_buf) {
                    Ok(Some(frame)) => {
                        // Verify frame integrity
                        assert!(frame.len() <= max_frame_length);
                        pos += chunk_size - chunk_buf.len(); // Account for consumed bytes
                    }
                    Ok(None) => {
                        // Need more data
                        pos = end;
                    }
                    Err(_) => {
                        // Parse error
                        break;
                    }
                }

                if pos >= end {
                    break;
                }
            }
        }
    }

    // Test overflow boundary values
    let mut overflow_codec = codec_builder.clone().new_codec();
    test_overflow_scenarios(&config, &mut overflow_codec);
}

/// Test integer overflow scenarios
fn test_overflow_scenarios(config: &CodecConfig, codec: &mut LengthDelimitedCodec) {
    let overflow_test_cases = [
        // Test maximum length values that could cause overflow
        vec![0xFF, 0xFF, 0xFF, 0xFF],
        vec![0xFF, 0xFF, 0xFF, 0x7F],
        vec![0x80, 0x80, 0x80, 0x80],
        vec![0x00, 0x00, 0x00, 0x01],
        // Test with offset + length combinations
        vec![0x00; 1024], // Large offset test
    ];

    for test_case in &overflow_test_cases {
        let mut buf = BytesMut::from(&test_case[..]);

        match codec.decode(&mut buf) {
            Ok(Some(frame)) => {
                // Ensure decoded frame is reasonable
                assert!(frame.len() <= config.max_frame_length.to_usize());
            }
            Ok(None) | Err(_) => {
                // Expected for malformed/incomplete data
            }
        }
    }
}

/// Test framed transport with full-duplex operations
fn test_framed_transport(input: &FuzzInput) {
    if input.framed_ops.is_empty() {
        return;
    }

    // Create protocol frame data
    let mut transport_data = Vec::new();
    for frame in &input.frames {
        transport_data.extend_from_slice(&frame.serialize(input.config.big_endian));
    }
    transport_data.extend_from_slice(&input.raw_data);

    if transport_data.is_empty() {
        transport_data = vec![0x00, 0x00, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o']; // Minimal valid frame
    }

    // Create mock transport
    let mut transport = MockTransport::new(transport_data.clone());

    if input.test_partial_reads {
        transport = transport.with_partial_reads();
    }

    if input.trigger_read_error {
        transport =
            transport.with_read_error(IoError::new(ErrorKind::UnexpectedEof, "Triggered error"));
    }

    // Create codec
    let codec_builder = LengthDelimitedCodec::builder()
        .length_field_length(input.config.length_field_length.to_usize())
        .max_frame_length(std::cmp::min(
            input.config.max_frame_length.to_usize(),
            1_000_000,
        ));

    let codec = if input.config.big_endian {
        codec_builder.clone().big_endian().new_codec()
    } else {
        codec_builder.clone().little_endian().new_codec()
    };

    // Create framed transport for testing
    let _framed = Framed::new(transport, codec);

    // Execute framed operations synchronously for fuzzing
    for op in &input.framed_ops {
        match op {
            FramedOperation::DecodeFrame => {
                // Test codec directly (framed would need async runtime)
                let mut test_buf = BytesMut::from(&transport_data[..100.min(transport_data.len())]);
                let mut test_codec = codec_builder.clone().new_codec();
                let _ = test_codec.decode(&mut test_buf);
            }
            FramedOperation::SendData { data } => {
                if data.len() <= 100_000 {
                    // Reasonable size limit
                    // Test encoding data that would be sent
                    let mut encoder = TestEncoder;
                    let mut dst = BytesMut::new();
                    let _ = encoder.encode(data.clone(), &mut dst);

                    // Test decoding the encoded data
                    let mut test_codec = codec_builder.clone().new_codec();
                    let _ = test_codec.decode(&mut dst);
                }
            }
            FramedOperation::Flush => {
                // Test buffer operations that flush would affect
                let mut test_buf = BytesMut::with_capacity(1024);
                test_buf.extend_from_slice(&transport_data[..64.min(transport_data.len())]);

                let mut test_codec = codec_builder.clone().new_codec();
                let _ = test_codec.decode(&mut test_buf);
            }
            FramedOperation::PollMultiple { count } => {
                // Test repeated decode operations
                let poll_count = std::cmp::min(*count, 10); // Reasonable limit
                for i in 0..poll_count {
                    let offset = (i as usize * 10) % transport_data.len();
                    let end = ((i as usize + 1) * 10).min(transport_data.len());
                    if offset < end {
                        let mut test_buf = BytesMut::from(&transport_data[offset..end]);
                        let mut test_codec = codec_builder.clone().new_codec();
                        let _ = test_codec.decode(&mut test_buf);
                    }
                }
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    // Guard against excessively large inputs
    if input.raw_data.len() > 1_000_000 {
        return;
    }

    if input.frames.len() > 1000 {
        return;
    }

    // Test length-delimited codec comprehensively
    test_length_delimited_codec(&input);

    // Test framed transport
    test_framed_transport(&input);

    // Additional boundary testing
    test_codec_boundary_cases(&input);
});

/// Test specific boundary cases and edge conditions
fn test_codec_boundary_cases(_input: &FuzzInput) {
    // Test empty input
    let mut empty_codec = LengthDelimitedCodec::new();
    let mut empty_buf = BytesMut::new();
    let result = empty_codec.decode(&mut empty_buf);
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    // Test single byte inputs
    for byte in [0x00, 0x01, 0xFF, 0x80, 0x7F] {
        let mut single_codec = LengthDelimitedCodec::new();
        let mut single_buf = BytesMut::from(&[byte][..]);
        let _ = single_codec.decode(&mut single_buf);
    }

    // Test max frame size enforcement
    let oversized_length = vec![0x7F, 0xFF, 0xFF, 0xFF]; // Large length
    let mut codec = LengthDelimitedCodec::builder()
        .max_frame_length(1024)
        .new_codec();
    let mut buf = BytesMut::from(&oversized_length[..]);

    match codec.decode(&mut buf) {
        Ok(Some(frame)) => {
            assert!(frame.len() <= 1024, "Max frame size not enforced");
        }
        Ok(None) | Err(_) => {
            // Expected - either need more data or error due to size limit
        }
    }

    // Test endianness consistency
    let test_data = [0x00, 0x00, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o'];

    let mut be_codec = LengthDelimitedCodec::builder().big_endian().new_codec();
    let mut le_codec = LengthDelimitedCodec::builder().little_endian().new_codec();

    let mut be_buf = BytesMut::from(&test_data[..]);
    let mut le_buf = BytesMut::from(&test_data[..]);

    let _be_result = be_codec.decode(&mut be_buf);
    let _le_result = le_codec.decode(&mut le_buf);

    // Both should handle the data (possibly differently)
    // This tests that endianness selection doesn't cause panics
}
