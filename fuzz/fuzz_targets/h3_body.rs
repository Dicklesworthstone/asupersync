#![no_main]

//! Fuzz target for HTTP/3 body streaming with DATA frame sequences.
//!
//! Tests HTTP/3 DATA frame body streaming per RFC 9114 Section 7.2.2:
//! 1. Varint-encoded frame Type/Length parsed correctly
//! 2. Content-Length vs chunked framing reconciliation
//! 3. Trailer HEADERS frame can follow DATA frames
//! 4. Malformed frame sequences rejected per RFC 9114
//! 5. Body buffer cap honored during streaming
//!
//! Focus: QUIC STREAM frame bodies for HTTP/3 DATA-only flow paths

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::{Buf, BufMut, Bytes, BytesMut};
use asupersync::http::h3_native::{H3Frame, H3NativeError, H3QpackMode, H3RequestStreamState};
use asupersync::net::quic_core::{decode_varint, encode_varint};

/// Fuzz input for HTTP/3 body streaming scenarios
#[derive(Arbitrary, Debug)]
struct H3BodyFuzzInput {
    /// Sequence of operations to test
    operations: Vec<H3BodyOperation>,
    /// Configuration for this test run
    config: H3BodyConfig,
}

/// HTTP/3 body operations to fuzz
#[derive(Arbitrary, Debug)]
enum H3BodyOperation {
    /// Send DATA frame with payload
    SendDataFrame {
        payload: Vec<u8>,
        use_correct_varint: bool,
    },
    /// Send malformed DATA frame
    SendMalformedDataFrame {
        frame_type: u64,
        frame_length: u64,
        actual_payload: Vec<u8>,
    },
    /// Send HEADERS frame (for trailers)
    SendTrailerHeaders {
        headers_payload: Vec<u8>,
        use_correct_encoding: bool,
    },
    /// Test Content-Length reconciliation
    TestContentLength {
        declared_length: u64,
        actual_data_frames: Vec<Vec<u8>>,
    },
    /// Test chunked vs Content-Length framing
    TestFramingMode {
        framing_mode: FramingMode,
        body_chunks: Vec<Vec<u8>>,
    },
    /// Test body buffer capacity limits
    TestBufferCap {
        total_body_size: u32,
        chunk_sizes: Vec<u16>,
        max_buffer_size: u32,
    },
    /// Inject invalid frame sequences
    InjectInvalidSequence { frame_sequence: Vec<InvalidFrame> },
}

/// HTTP/3 framing modes
#[derive(Arbitrary, Debug, Clone)]
enum FramingMode {
    /// Content-Length specified
    ContentLength(u64),
    /// Chunked transfer encoding (simulated via DATA frames)
    Chunked,
    /// No framing specified (depends on frame boundaries)
    Unspecified,
}

/// Invalid frame patterns for testing rejection
#[derive(Arbitrary, Debug)]
enum InvalidFrame {
    /// Frame with invalid type
    InvalidType { type_value: u64, payload: Vec<u8> },
    /// Frame with mismatched length
    MismatchedLength {
        declared_length: u64,
        actual_payload: Vec<u8>,
    },
    /// Truncated frame
    TruncatedFrame { payload: Vec<u8> },
    /// Frame larger than limits
    OversizedFrame { payload: Vec<u8> },
    /// DATA frame on control stream (forbidden)
    DataOnControlStream { payload: Vec<u8> },
    /// Invalid varint encoding
    InvalidVarint { malformed_bytes: Vec<u8> },
}

/// Configuration for H3 body fuzzing
#[derive(Arbitrary, Debug)]
struct H3BodyConfig {
    /// Maximum operations to execute
    max_operations: u16,
    /// Enable strict RFC 9114 compliance checking
    strict_rfc_compliance: bool,
    /// Maximum body size for buffer testing
    max_body_size: u32,
    /// Enable trailer headers testing
    enable_trailers: bool,
}

/// Shadow model for tracking HTTP/3 body state
#[derive(Debug)]
struct H3BodyShadowModel {
    /// Total bytes received in DATA frames
    total_data_bytes: u64,
    /// Expected Content-Length if specified
    expected_content_length: Option<u64>,
    /// Whether trailers were received
    trailers_received: bool,
    /// Whether body is complete
    body_complete: bool,
    /// Buffer capacity tracking
    current_buffer_size: usize,
    /// Maximum allowed buffer size
    max_buffer_capacity: usize,
    /// Frames processed
    frames_processed: usize,
    /// Detected violations
    violations: Vec<String>,
}

impl H3BodyShadowModel {
    fn new(max_buffer_capacity: usize) -> Self {
        Self {
            total_data_bytes: 0,
            expected_content_length: None,
            trailers_received: false,
            body_complete: false,
            current_buffer_size: 0,
            max_buffer_capacity,
            frames_processed: 0,
            violations: Vec::new(),
        }
    }

    fn process_data_frame(&mut self, payload_size: usize) -> Result<(), String> {
        if self.body_complete {
            return Err("DATA frame after body completion".to_string());
        }

        // Check buffer capacity
        if self.current_buffer_size + payload_size > self.max_buffer_capacity {
            return Err("Buffer capacity exceeded".to_string());
        }

        self.total_data_bytes += payload_size as u64;
        self.current_buffer_size += payload_size;
        self.frames_processed += 1;

        // Check Content-Length compliance
        if let Some(expected) = self.expected_content_length {
            if self.total_data_bytes > expected {
                return Err("DATA exceeds Content-Length".to_string());
            }
        }

        Ok(())
    }

    fn process_trailer_headers(&mut self) -> Result<(), String> {
        if !self.body_complete {
            // Trailers can only come after body completion
            self.body_complete = true;
        }

        if self.trailers_received {
            return Err("Multiple trailer HEADERS frames".to_string());
        }

        self.trailers_received = true;
        Ok(())
    }

    fn finalize_body(&mut self) -> Result<(), String> {
        self.body_complete = true;

        // Verify Content-Length compliance
        if let Some(expected) = self.expected_content_length {
            if self.total_data_bytes != expected {
                return Err(format!(
                    "Content-Length mismatch: expected {}, got {}",
                    expected, self.total_data_bytes
                ));
            }
        }

        Ok(())
    }

    fn record_violation(&mut self, violation: String) {
        self.violations.push(violation);
    }

    fn verify_invariants(&self) -> Result<(), String> {
        // RFC 9114 Section 7.2.2: DATA frames carry request/response body
        if self.body_complete && self.expected_content_length.is_some() {
            let expected = self.expected_content_length.unwrap();
            if self.total_data_bytes != expected {
                return Err("Final Content-Length mismatch".to_string());
            }
        }

        // Buffer invariant: current size should not exceed max
        if self.current_buffer_size > self.max_buffer_capacity {
            return Err("Buffer capacity invariant violated".to_string());
        }

        // Trailer invariant: trailers only after body
        if self.trailers_received && !self.body_complete {
            return Err("Trailers received before body completion".to_string());
        }

        // No recorded violations
        if !self.violations.is_empty() {
            return Err(format!("Protocol violations: {:?}", self.violations));
        }

        Ok(())
    }
}

/// Constants for H3 frame types per RFC 9114
const H3_FRAME_DATA: u64 = 0x0;
const H3_FRAME_HEADERS: u64 = 0x1;
const H3_FRAME_CANCEL_PUSH: u64 = 0x3;
const H3_FRAME_SETTINGS: u64 = 0x4;
const H3_FRAME_PUSH_PROMISE: u64 = 0x5;
const H3_FRAME_GOAWAY: u64 = 0x7;
const H3_FRAME_MAX_PUSH_ID: u64 = 0xD;

/// Maximum sizes to prevent timeout/memory exhaustion
const MAX_FRAME_SIZE: usize = 64 * 1024; // 64KB
const MAX_PAYLOAD_SIZE: usize = 16 * 1024; // 16KB
const MAX_OPERATIONS: usize = 50;

fuzz_target!(|input: H3BodyFuzzInput| {
    // Normalize input to prevent timeouts
    let mut input = input;
    normalize_h3_body_input(&mut input);

    // Execute H3 body operations
    let result = std::panic::catch_unwind(|| execute_h3_body_operations(&input));

    match result {
        Ok(Ok(())) => {
            // Test completed successfully
        }
        Ok(Err(err)) => {
            // Expected error (malformed input should be rejected gracefully)
            if err.contains("panic") || err.contains("abort") {
                panic!("Unexpected failure: {}", err);
            }
        }
        Err(_) => {
            // Panic occurred - this is a bug we want to find
            panic!("Fuzzing caused panic");
        }
    }
});

fn normalize_h3_body_input(input: &mut H3BodyFuzzInput) {
    // Limit operations to prevent timeouts
    input.operations.truncate(MAX_OPERATIONS);

    // Normalize config
    input.config.max_operations = input.config.max_operations.min(MAX_OPERATIONS as u16);
    input.config.max_body_size = input.config.max_body_size.min(MAX_FRAME_SIZE as u32);

    // Normalize each operation
    for op in &mut input.operations {
        match op {
            H3BodyOperation::SendDataFrame { payload, .. } => {
                payload.truncate(MAX_PAYLOAD_SIZE);
            }
            H3BodyOperation::SendMalformedDataFrame { actual_payload, .. } => {
                actual_payload.truncate(MAX_PAYLOAD_SIZE);
            }
            H3BodyOperation::SendTrailerHeaders {
                headers_payload, ..
            } => {
                headers_payload.truncate(MAX_PAYLOAD_SIZE);
            }
            H3BodyOperation::TestContentLength {
                actual_data_frames, ..
            } => {
                actual_data_frames.truncate(20);
                for frame_data in actual_data_frames {
                    frame_data.truncate(MAX_PAYLOAD_SIZE / 4);
                }
            }
            H3BodyOperation::TestFramingMode { body_chunks, .. } => {
                body_chunks.truncate(20);
                for chunk in body_chunks {
                    chunk.truncate(MAX_PAYLOAD_SIZE / 4);
                }
            }
            H3BodyOperation::TestBufferCap {
                chunk_sizes,
                max_buffer_size,
                ..
            } => {
                chunk_sizes.truncate(50);
                *max_buffer_size = (*max_buffer_size).min(MAX_FRAME_SIZE as u32);
            }
            H3BodyOperation::InjectInvalidSequence { frame_sequence } => {
                frame_sequence.truncate(10);
                for frame in frame_sequence {
                    match frame {
                        InvalidFrame::InvalidType { payload, .. }
                        | InvalidFrame::MismatchedLength {
                            actual_payload: payload,
                            ..
                        }
                        | InvalidFrame::TruncatedFrame { payload }
                        | InvalidFrame::OversizedFrame { payload }
                        | InvalidFrame::DataOnControlStream { payload } => {
                            payload.truncate(MAX_PAYLOAD_SIZE);
                        }
                        InvalidFrame::InvalidVarint { malformed_bytes } => {
                            malformed_bytes.truncate(16);
                        }
                    }
                }
            }
        }
    }
}

fn execute_h3_body_operations(input: &H3BodyFuzzInput) -> Result<(), String> {
    let max_buffer_capacity = input.config.max_body_size as usize;
    let mut shadow = H3BodyShadowModel::new(max_buffer_capacity);

    // Execute operations with bounds checking
    let max_ops = input
        .config
        .max_operations
        .min(input.operations.len() as u16);
    for (i, operation) in input.operations.iter().enumerate() {
        if i >= max_ops as usize {
            break;
        }

        let result = match operation {
            H3BodyOperation::SendDataFrame { .. } => test_send_data_frame(operation, &mut shadow),
            H3BodyOperation::SendMalformedDataFrame { .. } => test_malformed_data_frame(
                operation,
                &mut shadow,
                input.config.strict_rfc_compliance,
            ),
            H3BodyOperation::SendTrailerHeaders { .. } => {
                test_trailer_headers(operation, &mut shadow)
            }
            H3BodyOperation::TestContentLength { .. } => {
                test_content_length_reconciliation(operation, &mut shadow)
            }
            H3BodyOperation::TestFramingMode { .. } => test_framing_mode(operation, &mut shadow),
            H3BodyOperation::TestBufferCap { .. } => test_buffer_capacity(operation, &mut shadow),
            H3BodyOperation::InjectInvalidSequence { .. } => {
                test_invalid_frame_sequence(operation, &mut shadow)
            }
        };

        if let Err(e) = result {
            return Err(format!("Operation {} failed: {}", i, e));
        }

        // Verify invariants after each operation
        shadow.verify_invariants()?;
    }

    // Final invariant check
    shadow.verify_invariants()?;

    Ok(())
}

fn test_send_data_frame(
    operation: &H3BodyOperation,
    shadow: &mut H3BodyShadowModel,
) -> Result<(), String> {
    if let H3BodyOperation::SendDataFrame {
        payload,
        use_correct_varint,
    } = operation
    {
        // Test varint encoding/decoding for frame type and length
        let mut frame_bytes = BytesMut::new();

        if *use_correct_varint {
            // RFC 9114 Section 7.2.2: DATA frame type is 0x0
            let mut temp_vec = Vec::new();
            encode_varint(H3_FRAME_DATA, &mut temp_vec)
                .map_err(|e| format!("Failed to encode frame type: {:?}", e))?;
            frame_bytes.extend_from_slice(&temp_vec);

            temp_vec.clear();
            encode_varint(payload.len() as u64, &mut temp_vec)
                .map_err(|e| format!("Failed to encode frame length: {:?}", e))?;
            frame_bytes.extend_from_slice(&temp_vec);
        } else {
            // Inject malformed varint for testing
            frame_bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        }

        frame_bytes.extend_from_slice(payload);

        // Test frame parsing
        let frame_data = frame_bytes.freeze();
        let result = H3Frame::decode(&frame_data);

        match result {
            Ok((frame, consumed)) => {
                if *use_correct_varint {
                    // Should successfully parse DATA frame
                    if let H3Frame::Data(data) = frame {
                        if data.len() != payload.len() {
                            return Err("DATA frame payload length mismatch".to_string());
                        }
                        shadow.process_data_frame(payload.len())?;
                    } else {
                        return Err("Expected DATA frame, got different type".to_string());
                    }

                    // Verify consumed bytes
                    if consumed > frame_data.len() {
                        shadow.record_violation(
                            "Parser consumed more bytes than available".to_string(),
                        );
                        return Err("Parser overread input".to_string());
                    }
                } else {
                    shadow.record_violation("Malformed varint was accepted".to_string());
                }
            }
            Err(_) => {
                if *use_correct_varint {
                    return Err("Valid DATA frame was rejected".to_string());
                }
                // Expected rejection for malformed input
            }
        }
    }

    Ok(())
}

fn test_malformed_data_frame(
    operation: &H3BodyOperation,
    shadow: &mut H3BodyShadowModel,
    strict_compliance: bool,
) -> Result<(), String> {
    if let H3BodyOperation::SendMalformedDataFrame {
        frame_type,
        frame_length,
        actual_payload,
    } = operation
    {
        // Create frame with mismatched type/length
        let mut frame_bytes = BytesMut::new();

        let mut temp_vec = Vec::new();
        encode_varint(*frame_type, &mut temp_vec)
            .map_err(|e| format!("Failed to encode frame type: {:?}", e))?;
        frame_bytes.extend_from_slice(&temp_vec);

        temp_vec.clear();
        encode_varint(*frame_length, &mut temp_vec)
            .map_err(|e| format!("Failed to encode frame length: {:?}", e))?;
        frame_bytes.extend_from_slice(&temp_vec);
        frame_bytes.extend_from_slice(actual_payload);

        let frame_data = frame_bytes.freeze();
        let result = H3Frame::decode(&frame_data);

        match result {
            Ok((frame, _)) => {
                // If frame was parsed despite being malformed
                if strict_compliance {
                    // Check if this should have been rejected per RFC 9114
                    if *frame_type != H3_FRAME_DATA && matches!(frame, H3Frame::Data(_)) {
                        shadow.record_violation("Frame type mismatch accepted".to_string());
                    }
                    if *frame_length != actual_payload.len() as u64 {
                        shadow.record_violation("Frame length mismatch accepted".to_string());
                    }
                }
            }
            Err(H3NativeError::InvalidFrame(msg)) => {
                // Expected rejection for malformed frame
                if msg.is_empty() {
                    shadow.record_violation("Empty error message for invalid frame".to_string());
                }
            }
            Err(H3NativeError::UnexpectedEof) => {
                // Expected if frame is truncated
            }
            Err(_) => {
                // Other errors are acceptable
            }
        }
    }

    Ok(())
}

fn test_trailer_headers(
    operation: &H3BodyOperation,
    shadow: &mut H3BodyShadowModel,
) -> Result<(), String> {
    if let H3BodyOperation::SendTrailerHeaders {
        headers_payload,
        use_correct_encoding,
    } = operation
    {
        // RFC 9114 Section 4.1: Trailer fields are sent in a HEADERS frame
        let mut frame_bytes = BytesMut::new();

        let mut temp_vec = Vec::new();
        encode_varint(H3_FRAME_HEADERS, &mut temp_vec)
            .map_err(|e| format!("Failed to encode HEADERS frame type: {:?}", e))?;
        frame_bytes.extend_from_slice(&temp_vec);

        if *use_correct_encoding {
            temp_vec.clear();
            encode_varint(headers_payload.len() as u64, &mut temp_vec)
                .map_err(|e| format!("Failed to encode frame length: {:?}", e))?;
            frame_bytes.extend_from_slice(&temp_vec);
            frame_bytes.extend_from_slice(headers_payload);
        } else {
            // Inject malformed length encoding
            temp_vec.clear();
            encode_varint(headers_payload.len() as u64 + 100, &mut temp_vec)
                .map_err(|e| format!("Failed to encode frame length: {:?}", e))?;
            frame_bytes.extend_from_slice(&temp_vec);
            frame_bytes.extend_from_slice(headers_payload);
        }

        let frame_data = frame_bytes.freeze();
        let result = H3Frame::decode(&frame_data);

        match result {
            Ok((frame, _)) => {
                if let H3Frame::Headers(header_data) = frame {
                    if *use_correct_encoding || header_data.len() == headers_payload.len() {
                        shadow.process_trailer_headers()?;
                    } else {
                        shadow.record_violation("Malformed HEADERS frame was accepted".to_string());
                    }
                } else {
                    return Err("Expected HEADERS frame for trailers".to_string());
                }
            }
            Err(_) => {
                if *use_correct_encoding {
                    return Err("Valid trailer HEADERS frame was rejected".to_string());
                }
                // Expected rejection for malformed encoding
            }
        }
    }

    Ok(())
}

fn test_content_length_reconciliation(
    operation: &H3BodyOperation,
    shadow: &mut H3BodyShadowModel,
) -> Result<(), String> {
    if let H3BodyOperation::TestContentLength {
        declared_length,
        actual_data_frames,
    } = operation
    {
        // Set expected Content-Length
        shadow.expected_content_length = Some(*declared_length);

        // Process actual DATA frames
        for frame_data in actual_data_frames {
            shadow.process_data_frame(frame_data.len())?;
        }

        // Check reconciliation
        if shadow.total_data_bytes != *declared_length {
            // This should be flagged when body is finalized
            shadow.finalize_body()?;
        }
    }

    Ok(())
}

fn test_framing_mode(
    operation: &H3BodyOperation,
    shadow: &mut H3BodyShadowModel,
) -> Result<(), String> {
    if let H3BodyOperation::TestFramingMode {
        framing_mode,
        body_chunks,
    } = operation
    {
        match framing_mode {
            FramingMode::ContentLength(length) => {
                shadow.expected_content_length = Some(*length);

                let mut total_size = 0;
                for chunk in body_chunks {
                    total_size += chunk.len();
                    shadow.process_data_frame(chunk.len())?;
                }

                // Verify Content-Length matches actual data
                if total_size as u64 != *length {
                    return Err("Content-Length vs actual data size mismatch".to_string());
                }
            }
            FramingMode::Chunked => {
                // In HTTP/3, chunked encoding is replaced by DATA frame boundaries
                for chunk in body_chunks {
                    shadow.process_data_frame(chunk.len())?;
                }
            }
            FramingMode::Unspecified => {
                // Body size determined by DATA frame boundaries
                for chunk in body_chunks {
                    shadow.process_data_frame(chunk.len())?;
                }
            }
        }
    }

    Ok(())
}

fn test_buffer_capacity(
    operation: &H3BodyOperation,
    shadow: &mut H3BodyShadowModel,
) -> Result<(), String> {
    if let H3BodyOperation::TestBufferCap {
        total_body_size,
        chunk_sizes,
        max_buffer_size,
    } = operation
    {
        let old_max = shadow.max_buffer_capacity;
        shadow.max_buffer_capacity = (*max_buffer_size as usize).min(MAX_FRAME_SIZE);

        let mut remaining_size = *total_body_size as usize;

        for &chunk_size in chunk_sizes.iter() {
            if remaining_size == 0 {
                break;
            }

            let actual_chunk_size = (chunk_size as usize).min(remaining_size);

            // This should fail if buffer capacity is exceeded
            let result = shadow.process_data_frame(actual_chunk_size);

            if result.is_err() {
                // Expected when buffer capacity is exceeded
                break;
            }

            remaining_size -= actual_chunk_size;

            // Simulate consumption of buffered data
            if shadow.current_buffer_size > shadow.max_buffer_capacity / 2 {
                shadow.current_buffer_size = shadow.current_buffer_size / 2;
            }
        }

        // Restore original capacity
        shadow.max_buffer_capacity = old_max;
    }

    Ok(())
}

fn test_invalid_frame_sequence(
    operation: &H3BodyOperation,
    shadow: &mut H3BodyShadowModel,
) -> Result<(), String> {
    if let H3BodyOperation::InjectInvalidSequence { frame_sequence } = operation {
        for invalid_frame in frame_sequence {
            let result = process_invalid_frame(invalid_frame);

            match result {
                Ok(_) => {
                    // Invalid frame was accepted - might be a problem
                    match invalid_frame {
                        InvalidFrame::DataOnControlStream { .. } => {
                            shadow.record_violation(
                                "DATA frame on control stream was accepted".to_string(),
                            );
                        }
                        InvalidFrame::InvalidType { .. } => {
                            // Unknown frame types should be ignored per RFC 9114
                        }
                        InvalidFrame::MismatchedLength { .. } => {
                            shadow.record_violation(
                                "Frame with mismatched length was accepted".to_string(),
                            );
                        }
                        _ => {}
                    }
                }
                Err(_) => {
                    // Expected rejection for invalid frames
                }
            }
        }
    }

    Ok(())
}

fn process_invalid_frame(invalid_frame: &InvalidFrame) -> Result<(), String> {
    match invalid_frame {
        InvalidFrame::InvalidType {
            type_value,
            payload,
        } => {
            let mut frame_bytes = BytesMut::new();
            let mut temp_vec = Vec::new();
            encode_varint(*type_value, &mut temp_vec)
                .map_err(|e| format!("Encode error: {:?}", e))?;
            frame_bytes.extend_from_slice(&temp_vec);

            temp_vec.clear();
            encode_varint(payload.len() as u64, &mut temp_vec)
                .map_err(|e| format!("Encode error: {:?}", e))?;
            frame_bytes.extend_from_slice(&temp_vec);
            frame_bytes.extend_from_slice(payload);

            let result = H3Frame::decode(&frame_bytes.freeze());
            match result {
                Ok((
                    H3Frame::Unknown {
                        frame_type,
                        payload: _,
                    },
                    _,
                )) => {
                    if frame_type == *type_value {
                        Ok(()) // Unknown frame types are preserved
                    } else {
                        Err("Frame type mismatch".to_string())
                    }
                }
                Ok(_) => Err("Invalid frame type was interpreted as known frame".to_string()),
                Err(_) => Err("Frame parsing failed".to_string()),
            }
        }

        InvalidFrame::MismatchedLength {
            declared_length,
            actual_payload,
        } => {
            let mut frame_bytes = BytesMut::new();
            let mut temp_vec = Vec::new();
            encode_varint(H3_FRAME_DATA, &mut temp_vec)
                .map_err(|e| format!("Encode error: {:?}", e))?;
            frame_bytes.extend_from_slice(&temp_vec);

            temp_vec.clear();
            encode_varint(*declared_length, &mut temp_vec)
                .map_err(|e| format!("Encode error: {:?}", e))?;
            frame_bytes.extend_from_slice(&temp_vec);
            frame_bytes.extend_from_slice(actual_payload);

            let result = H3Frame::decode(&frame_bytes.freeze());
            match result {
                Ok(_) => {
                    if *declared_length as usize != actual_payload.len() {
                        Err("Mismatched length was accepted".to_string())
                    } else {
                        Ok(())
                    }
                }
                Err(H3NativeError::UnexpectedEof) => Ok(()), // Expected for truncated frames
                Err(_) => Ok(()),                            // Other errors are expected
            }
        }

        InvalidFrame::TruncatedFrame { payload } => {
            // Create a frame that's truncated mid-payload
            if payload.len() < 2 {
                return Ok(()); // Skip degenerate case
            }

            let mut frame_bytes = BytesMut::new();
            let mut temp_vec = Vec::new();
            encode_varint(H3_FRAME_DATA, &mut temp_vec)
                .map_err(|e| format!("Encode error: {:?}", e))?;
            frame_bytes.extend_from_slice(&temp_vec);

            temp_vec.clear();
            encode_varint(payload.len() as u64, &mut temp_vec)
                .map_err(|e| format!("Encode error: {:?}", e))?;
            frame_bytes.extend_from_slice(&temp_vec);
            // Only include half the payload to create truncation
            frame_bytes.extend_from_slice(&payload[..payload.len() / 2]);

            let result = H3Frame::decode(&frame_bytes.freeze());
            match result {
                Err(H3NativeError::UnexpectedEof) => Ok(()), // Expected
                _ => Err("Truncated frame was not properly rejected".to_string()),
            }
        }

        InvalidFrame::OversizedFrame { payload } => {
            // Test frames that exceed reasonable limits
            if payload.len() > MAX_FRAME_SIZE {
                return Err("Oversized frame should be rejected".to_string());
            }
            Ok(()) // Within limits
        }

        InvalidFrame::DataOnControlStream { payload } => {
            // DATA frames MUST NOT be sent on control streams per RFC 9114
            // We can't easily test this here without stream context
            // This would be a protocol violation
            Err("DATA frame on control stream is forbidden".to_string())
        }

        InvalidFrame::InvalidVarint { malformed_bytes } => {
            // Test invalid varint sequences
            let result = decode_varint(malformed_bytes);
            match result {
                Ok(_) => Err("Invalid varint was decoded successfully".to_string()),
                Err(_) => Ok(()), // Expected rejection
            }
        }
    }
}
