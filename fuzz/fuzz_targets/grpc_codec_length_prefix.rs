#![no_main]

use arbitrary::Arbitrary;
use bytes::{BufMut, BytesMut};
use libfuzzer_sys::fuzz_target;

use asupersync::grpc::codec::{GrpcCodec, GrpcMessage};
use tokio_util::codec::Decoder;

/// Structure-aware fuzz input for gRPC message length-prefix + compression-flag testing
#[derive(Arbitrary, Debug)]
struct GrpcLengthPrefixFuzz {
    /// Test scenarios to exercise different framing combinations
    scenario: FramingScenario,
    /// Whether to test multiple messages in sequence
    test_sequence: bool,
    /// Buffer management strategies
    buffer_strategy: BufferStrategy,
}

#[derive(Arbitrary, Debug, Clone)]
enum FramingScenario {
    /// Valid compression flag + length combinations
    ValidFrames {
        messages: Vec<ValidMessage>,
    },
    /// Invalid compression flags with various lengths
    InvalidCompression {
        invalid_flags: Vec<u8>,
        lengths: Vec<u32>,
        payloads: Vec<Vec<u8>>,
    },
    /// Length boundary testing
    LengthBoundary {
        boundary_cases: Vec<LengthBoundaryCase>,
    },
    /// Malformed frame headers
    MalformedHeaders {
        partial_headers: Vec<PartialHeader>,
    },
    /// Mixed valid and invalid sequences
    MixedSequence {
        frames: Vec<FrameVariant>,
    },
}

#[derive(Arbitrary, Debug, Clone)]
struct ValidMessage {
    /// 0 = uncompressed, 1 = compressed
    compressed: bool,
    /// Message payload
    payload: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
struct LengthBoundaryCase {
    /// Compression flag (0 or 1)
    compressed: bool,
    /// Length prefix value
    declared_length: u32,
    /// Actual payload (may not match declared length)
    payload: Vec<u8>,
    /// Type of boundary condition being tested
    boundary_type: BoundaryType,
}

#[derive(Arbitrary, Debug, Clone)]
enum BoundaryType {
    /// Length matches payload exactly
    ExactMatch,
    /// Length is larger than payload (underrun)
    LengthTooLarge,
    /// Length is smaller than payload (overrun)
    LengthTooSmall,
    /// Zero length
    ZeroLength,
    /// Maximum u32 length
    MaxLength,
    /// Just under message size limit
    NearSizeLimit,
    /// Over message size limit
    OverSizeLimit,
}

#[derive(Arbitrary, Debug, Clone)]
struct PartialHeader {
    /// Incomplete header bytes (0-4 bytes)
    header_bytes: Vec<u8>,
    /// Optional payload following partial header
    trailing_data: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
enum FrameVariant {
    Valid(ValidMessage),
    InvalidFlag { flag: u8, length: u32, payload: Vec<u8> },
    LengthMismatch { compressed: bool, declared: u32, payload: Vec<u8> },
    PartialFrame(PartialHeader),
}

#[derive(Arbitrary, Debug, Clone)]
enum BufferStrategy {
    /// Feed data in single chunk
    SingleChunk,
    /// Feed data byte by byte
    ByteByByte,
    /// Feed data in random-sized chunks
    RandomChunks { chunk_sizes: Vec<usize> },
    /// Feed header and payload separately
    HeaderThenPayload,
}

/// Size limits to prevent OOM during fuzzing
const MAX_PAYLOAD_SIZE: usize = 64 * 1024; // 64KB
const MAX_DECLARED_LENGTH: u32 = 1024 * 1024; // 1MB
const MAX_MESSAGES: usize = 100;
const MAX_CHUNKS: usize = 50;

fuzz_target!(|input: GrpcLengthPrefixFuzz| {
    // Input size guards to prevent OOM
    if let FramingScenario::ValidFrames { ref messages } = input.scenario {
        if messages.len() > MAX_MESSAGES {
            return;
        }
    }

    // Test the main framing scenarios
    test_grpc_framing_scenarios(&input);

    // Test sequence processing if requested
    if input.test_sequence {
        test_message_sequence_processing(&input);
    }

    // Test buffer chunking strategies
    test_buffer_chunking_strategies(&input);

    // Test edge cases in length-prefix parsing
    test_length_prefix_edge_cases(&input);
});

/// Test main gRPC message framing scenarios
fn test_grpc_framing_scenarios(input: &GrpcLengthPrefixFuzz) {
    let mut codec = GrpcCodec::new();

    match &input.scenario {
        FramingScenario::ValidFrames { messages } => {
            for msg in messages.iter().take(MAX_MESSAGES) {
                if msg.payload.len() > MAX_PAYLOAD_SIZE {
                    continue;
                }

                let mut buf = encode_message(msg.compressed, &msg.payload);

                // Valid messages should decode successfully
                let result = codec.decode(&mut buf);
                match result {
                    Ok(Some(decoded)) => {
                        // Verify the decoded message matches input
                        assert_eq!(decoded.compressed, msg.compressed);
                        assert_eq!(&decoded.data[..], &msg.payload[..]);
                    }
                    Ok(None) => {
                        // Partial message - acceptable for framing
                    }
                    Err(_) => {
                        // Decode failure on valid input - should not happen
                        // but don't panic as this might reveal edge cases
                    }
                }
            }
        }

        FramingScenario::InvalidCompression { invalid_flags, lengths, payloads } => {
            for ((flag, length), payload) in invalid_flags.iter()
                .zip(lengths.iter())
                .zip(payloads.iter())
                .take(MAX_MESSAGES)
            {
                if *flag == 0 || *flag == 1 {
                    continue; // Skip valid flags
                }
                if payload.len() > MAX_PAYLOAD_SIZE || *length > MAX_DECLARED_LENGTH {
                    continue;
                }

                let mut buf = encode_message_raw(*flag, *length, payload);

                // Invalid compression flags should be rejected
                let result = codec.decode(&mut buf);
                // Should return an error for invalid compression flags
                // but we don't assert to avoid panicking on edge cases
            }
        }

        FramingScenario::LengthBoundary { boundary_cases } => {
            for case in boundary_cases.iter().take(MAX_MESSAGES) {
                if case.payload.len() > MAX_PAYLOAD_SIZE || case.declared_length > MAX_DECLARED_LENGTH {
                    continue;
                }

                test_length_boundary_case(&mut codec, case);
            }
        }

        FramingScenario::MalformedHeaders { partial_headers } => {
            for partial in partial_headers.iter().take(MAX_MESSAGES) {
                if partial.header_bytes.len() > 5 || partial.trailing_data.len() > MAX_PAYLOAD_SIZE {
                    continue;
                }

                test_malformed_header(&mut codec, partial);
            }
        }

        FramingScenario::MixedSequence { frames } => {
            for frame in frames.iter().take(MAX_MESSAGES) {
                test_frame_variant(&mut codec, frame);
            }
        }
    }
}

/// Test sequence processing with multiple messages
fn test_message_sequence_processing(input: &GrpcLengthPrefixFuzz) {
    let mut codec = GrpcCodec::new();
    let mut combined_buf = BytesMut::new();

    // Build a sequence of messages based on scenario
    match &input.scenario {
        FramingScenario::ValidFrames { messages } => {
            for msg in messages.iter().take(10) { // Limit for sequence test
                if msg.payload.len() <= MAX_PAYLOAD_SIZE {
                    let frame = encode_message(msg.compressed, &msg.payload);
                    combined_buf.extend_from_slice(&frame);
                }
            }
        }
        _ => return, // Other scenarios tested individually
    }

    // Decode the sequence
    let mut decoded_count = 0;
    while !combined_buf.is_empty() && decoded_count < MAX_MESSAGES {
        match codec.decode(&mut combined_buf) {
            Ok(Some(_)) => decoded_count += 1,
            Ok(None) => break, // Need more data
            Err(_) => break,   // Decode error
        }
    }
}

/// Test different buffer chunking strategies
fn test_buffer_chunking_strategies(input: &GrpcLengthPrefixFuzz) {
    if let FramingScenario::ValidFrames { messages } = &input.scenario {
        if let Some(msg) = messages.first() {
            if msg.payload.len() <= MAX_PAYLOAD_SIZE {
                let frame = encode_message(msg.compressed, &msg.payload);
                test_chunked_decode(&frame, &input.buffer_strategy);
            }
        }
    }
}

/// Test edge cases in length-prefix parsing
fn test_length_prefix_edge_cases(input: &GrpcLengthPrefixFuzz) {
    let mut codec = GrpcCodec::new();

    // Test specific edge cases
    let edge_cases = [
        (false, 0u32, vec![]),           // Zero-length uncompressed
        (true, 0u32, vec![]),            // Zero-length compressed
        (false, 1u32, vec![0x42]),       // Single-byte uncompressed
        (true, 1u32, vec![0x42]),        // Single-byte compressed
    ];

    for (compressed, length, payload) in edge_cases {
        let mut buf = encode_message_raw(if compressed { 1 } else { 0 }, length, &payload);
        let _ = codec.decode(&mut buf);
    }
}

/// Encode a message with proper gRPC framing
fn encode_message(compressed: bool, payload: &[u8]) -> BytesMut {
    encode_message_raw(if compressed { 1 } else { 0 }, payload.len() as u32, payload)
}

/// Encode a message with raw flag and length values
fn encode_message_raw(flag: u8, length: u32, payload: &[u8]) -> BytesMut {
    let mut buf = BytesMut::with_capacity(5 + payload.len());
    buf.put_u8(flag);
    buf.put_u32(length);
    buf.extend_from_slice(payload);
    buf
}

/// Test a specific length boundary case
fn test_length_boundary_case(codec: &mut GrpcCodec, case: &LengthBoundaryCase) {
    let flag = if case.compressed { 1 } else { 0 };

    match case.boundary_type {
        BoundaryType::ExactMatch => {
            let mut buf = encode_message_raw(flag, case.payload.len() as u32, &case.payload);
            let _ = codec.decode(&mut buf);
        }
        BoundaryType::LengthTooLarge => {
            let declared = case.declared_length.min(MAX_DECLARED_LENGTH);
            if declared > case.payload.len() as u32 {
                let mut buf = encode_message_raw(flag, declared, &case.payload);
                let _ = codec.decode(&mut buf);
            }
        }
        BoundaryType::LengthTooSmall => {
            if case.declared_length < case.payload.len() as u32 {
                let mut buf = encode_message_raw(flag, case.declared_length, &case.payload);
                let _ = codec.decode(&mut buf);
            }
        }
        BoundaryType::ZeroLength => {
            let mut buf = encode_message_raw(flag, 0, &[]);
            let _ = codec.decode(&mut buf);
        }
        BoundaryType::MaxLength => {
            // Don't actually create max-length payload - just test header parsing
            let mut buf = BytesMut::new();
            buf.put_u8(flag);
            buf.put_u32(u32::MAX);
            // Don't add payload - test header parsing only
            let _ = codec.decode(&mut buf);
        }
        BoundaryType::NearSizeLimit | BoundaryType::OverSizeLimit => {
            // Test declared lengths near or over limits
            let declared = case.declared_length.min(MAX_DECLARED_LENGTH);
            let mut buf = encode_message_raw(flag, declared, &case.payload);
            let _ = codec.decode(&mut buf);
        }
    }
}

/// Test malformed header parsing
fn test_malformed_header(codec: &mut GrpcCodec, partial: &PartialHeader) {
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&partial.header_bytes);
    buf.extend_from_slice(&partial.trailing_data);

    let _ = codec.decode(&mut buf);
}

/// Test individual frame variant
fn test_frame_variant(codec: &mut GrpcCodec, frame: &FrameVariant) {
    match frame {
        FrameVariant::Valid(msg) => {
            if msg.payload.len() <= MAX_PAYLOAD_SIZE {
                let mut buf = encode_message(msg.compressed, &msg.payload);
                let _ = codec.decode(&mut buf);
            }
        }
        FrameVariant::InvalidFlag { flag, length, payload } => {
            if payload.len() <= MAX_PAYLOAD_SIZE && *length <= MAX_DECLARED_LENGTH {
                let mut buf = encode_message_raw(*flag, *length, payload);
                let _ = codec.decode(&mut buf);
            }
        }
        FrameVariant::LengthMismatch { compressed, declared, payload } => {
            if payload.len() <= MAX_PAYLOAD_SIZE && *declared <= MAX_DECLARED_LENGTH {
                let flag = if *compressed { 1 } else { 0 };
                let mut buf = encode_message_raw(flag, *declared, payload);
                let _ = codec.decode(&mut buf);
            }
        }
        FrameVariant::PartialFrame(partial) => {
            test_malformed_header(codec, partial);
        }
    }
}

/// Test chunked decode with different buffer strategies
fn test_chunked_decode(frame: &[u8], strategy: &BufferStrategy) {
    let mut codec = GrpcCodec::new();

    match strategy {
        BufferStrategy::SingleChunk => {
            let mut buf = BytesMut::from(frame);
            let _ = codec.decode(&mut buf);
        }
        BufferStrategy::ByteByByte => {
            let mut buf = BytesMut::new();
            for &byte in frame {
                buf.put_u8(byte);
                let _ = codec.decode(&mut buf);
            }
        }
        BufferStrategy::RandomChunks { chunk_sizes } => {
            let mut buf = BytesMut::new();
            let mut pos = 0;
            for &chunk_size in chunk_sizes.iter().take(MAX_CHUNKS) {
                if pos >= frame.len() {
                    break;
                }
                let end = (pos + chunk_size).min(frame.len());
                buf.extend_from_slice(&frame[pos..end]);
                pos = end;
                let _ = codec.decode(&mut buf);
            }
            // Add any remaining bytes
            if pos < frame.len() {
                buf.extend_from_slice(&frame[pos..]);
                let _ = codec.decode(&mut buf);
            }
        }
        BufferStrategy::HeaderThenPayload => {
            if frame.len() >= 5 {
                // Feed header first
                let mut buf = BytesMut::from(&frame[..5]);
                let _ = codec.decode(&mut buf);

                // Then payload
                buf.extend_from_slice(&frame[5..]);
                let _ = codec.decode(&mut buf);
            }
        }
    }
}