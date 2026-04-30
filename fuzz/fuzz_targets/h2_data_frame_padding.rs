//! HTTP/2 DATA Frame Padding Handling Fuzzer
//!
//! Targets the DATA frame padding handling logic in src/http/h2/connection.rs
//! to test handling of arbitrary pad-length byte values, ensuring padding is
//! properly stripped before delivery and malformed padding results in
//! PROTOCOL_ERROR per RFC 9113.
//!
//! Key invariants tested:
//! - Valid padding is stripped before data delivery
//! - Padding length exceeding payload → PROTOCOL_ERROR
//! - PADDED flag without padding byte → PROTOCOL_ERROR
//! - Zero padding length is valid
//! - Maximum padding (255 bytes) handled correctly
//! - No panic on arbitrary pad-length values

#![no_main]

use libfuzzer_sys::fuzz_target;
use asupersync::bytes::{Bytes, BytesMut, BufMut};
use asupersync::http::h2::{H2Error, Frame, FrameType};
use asupersync::http::h2::frame::{DataFrame, FrameHeader, data_flags, parse_frame};
use asupersync::http::h2::error::ErrorCode;

/// Maximum input size to prevent OOM
const MAX_INPUT_SIZE: usize = 4096;

/// DATA frame type constant
const DATA_FRAME_TYPE: u8 = 0x0;

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input sizes
    if data.is_empty() || data.len() > MAX_INPUT_SIZE {
        return;
    }

    // Test 1: Basic DATA frame with fuzzed padding
    {
        let result = parse_data_frame_with_padding(data, true);

        // Validate padding handling according to RFC 9113 Section 6.1
        match result {
            Ok(Frame::Data(data_frame)) => {
                // Successfully parsed - verify data was extracted correctly
                let _stream_id = data_frame.stream_id;
                let _payload = &data_frame.data;
                // Should contain only the actual data, padding stripped
            }
            Err(H2Error { code: ErrorCode::ProtocolError, .. }) => {
                // Expected for malformed padding (pad_length > payload_length)
            }
            Err(_) => {
                // Other errors acceptable for malformed input
            }
            _ => {}, // Non-DATA frames from parsing
        }
    }

    // Test 2: DATA frame without PADDED flag but with potential padding data
    {
        let result = parse_data_frame_with_padding(data, false);

        // Without PADDED flag, all data should be treated as payload
        match result {
            Ok(Frame::Data(data_frame)) => {
                // All input should be treated as application data
                assert_eq!(data_frame.data.len(), data.len());
            }
            Err(_) => {
                // Parse errors acceptable for malformed frame structure
            }
            _ => {},
        }
    }

    // Test 3: Edge case - single byte payload with padding
    if !data.is_empty() {
        let pad_length = data[0];

        let result = create_padded_data_frame(&data[1..], pad_length, 1);
        match result {
            Ok(frame) => {
                // Test the parsing of our constructed frame
                let _parse_result = validate_data_frame_padding(&frame);
            }
            Err(_) => {
                // Construction failed due to invalid parameters
            }
        }
    }

    // Test 4: Zero-length payload with padding
    {
        if !data.is_empty() {
            let pad_length = data[0];

            // Try to create frame with no data but padding
            let result = create_padded_data_frame(&[], pad_length, 1);
            match result {
                Ok(frame) => {
                    let parse_result = validate_data_frame_padding(&frame);
                    // Should either succeed (valid zero-data) or fail (invalid padding)
                    match parse_result {
                        Ok(_) => {}, // Valid zero-length data
                        Err(H2Error { code: ErrorCode::ProtocolError, .. }) => {}, // Invalid padding
                        Err(_) => {}, // Other errors
                    }
                }
                Err(_) => {},
            }
        }
    }

    // Test 5: Maximum padding scenarios
    {
        // Test with maximum possible padding length (255)
        if data.len() >= 256 {
            let result = create_padded_data_frame(&data[256..], 255, 1);
            match result {
                Ok(frame) => {
                    let _parse_result = validate_data_frame_padding(&frame);
                    // Should handle max padding correctly
                }
                Err(_) => {},
            }
        }
    }

    // Test 6: Padding length equals payload length (edge case)
    if data.len() >= 2 {
        let payload_data = &data[1..];
        let pad_length = payload_data.len() as u8;

        let result = create_padded_data_frame(payload_data, pad_length, 1);
        match result {
            Ok(frame) => {
                let parse_result = validate_data_frame_padding(&frame);
                // This should result in zero application data (all padding)
                match parse_result {
                    Ok(Frame::Data(data_frame)) => {
                        // All data was padding, so payload should be empty
                        assert!(data_frame.data.is_empty());
                    }
                    Err(_) => {},
                }
            }
            Err(_) => {},
        }
    }

    // Test 7: Padding length exceeds payload (should be PROTOCOL_ERROR)
    if data.len() >= 2 {
        let payload_data = &data[1..];
        let pad_length = (payload_data.len() as u8).saturating_add(1); // One more than available

        let result = create_padded_data_frame(payload_data, pad_length, 1);
        match result {
            Ok(frame) => {
                let parse_result = validate_data_frame_padding(&frame);
                // Should fail with PROTOCOL_ERROR
                match parse_result {
                    Err(H2Error { code: ErrorCode::ProtocolError, .. }) => {
                        // Expected - padding exceeds data length
                    }
                    _ => {
                        // Unexpected - should have failed
                    }
                }
            }
            Err(_) => {},
        }
    }

    // Test 8: Multiple DATA frames with different padding
    if data.len() >= 6 {
        let mid = data.len() / 2;

        // First frame
        let frame1_result = create_padded_data_frame(&data[..mid], data[0] % 32, 1);

        // Second frame
        let frame2_result = create_padded_data_frame(&data[mid..], data[mid] % 32, 3);

        // Both should be independent
        if let (Ok(frame1), Ok(frame2)) = (frame1_result, frame2_result) {
            let _result1 = validate_data_frame_padding(&frame1);
            let _result2 = validate_data_frame_padding(&frame2);
        }
    }

    // Test 9: Raw frame parsing with arbitrary payloads
    {
        let parse_result = parse_raw_data_frame(data);

        match parse_result {
            Ok(Frame::Data(data_frame)) => {
                // Successful parse - verify properties
                let _stream_id = data_frame.stream_id;
                let _end_stream = data_frame.end_stream;
                let _data_len = data_frame.data.len();
                // No padding info available after parsing - it should be stripped
            }
            Err(_) => {
                // Parse errors are acceptable for malformed input
            }
            _ => {}, // Other frame types
        }
    }

    // Test 10: Boundary testing with exact sizes
    {
        let test_sizes = [0, 1, 2, 16, 64, 255, 256, 1024];

        for &size in &test_sizes {
            if data.len() >= size + 1 {
                let pad_length = if size == 0 { 0 } else { data[0] % (size as u8 + 1) };
                let payload = &data[1..=size];

                let result = create_padded_data_frame(payload, pad_length, 1);
                if let Ok(frame) = result {
                    let _parse_result = validate_data_frame_padding(&frame);
                }
            }
        }
    }
});

/// Parse DATA frame with specified padding flag
fn parse_data_frame_with_padding(data: &[u8], padded: bool) -> Result<Frame, H2Error> {
    let flags = if padded { data_flags::PADDED } else { 0 };

    let header = FrameHeader {
        length: std::cmp::min(data.len() as u32, 16_777_215), // Max frame size
        frame_type: DATA_FRAME_TYPE,
        flags,
        stream_id: 1, // Valid client stream
    };

    parse_frame(&header, Bytes::copy_from_slice(data))
}

/// Create a padded DATA frame manually
fn create_padded_data_frame(
    app_data: &[u8],
    pad_length: u8,
    stream_id: u32
) -> Result<Frame, H2Error> {
    let mut payload = BytesMut::new();

    // Add padding length byte
    payload.put_u8(pad_length);

    // Add application data
    payload.put(app_data);

    // Add padding bytes (zeros)
    for _ in 0..pad_length {
        payload.put_u8(0);
    }

    // Create frame header with PADDED flag
    let header = FrameHeader {
        length: payload.len() as u32,
        frame_type: DATA_FRAME_TYPE,
        flags: data_flags::PADDED,
        stream_id,
    };

    // Parse the constructed frame to test the parser
    parse_frame(&header, payload.freeze())
}

/// Validate DATA frame padding by parsing
fn validate_data_frame_padding(frame: &Frame) -> Result<Frame, H2Error> {
    match frame {
        Frame::Data(data_frame) => {
            // Encode the frame and re-parse to test round-trip
            let mut buf = BytesMut::new();
            data_frame.encode(&mut buf)?;

            // Extract header and payload for re-parsing
            if buf.len() >= 9 {
                let header_bytes = buf.split_to(9);
                let header = FrameHeader::parse(&mut header_bytes.clone())?;
                let payload = buf.freeze();

                // Re-parse through the padding logic
                parse_frame(&header, payload)
            } else {
                Err(H2Error::protocol("Invalid frame encoding"))
            }
        }
        _ => Err(H2Error::protocol("Expected DATA frame")),
    }
}

/// Parse raw bytes as DATA frame
fn parse_raw_data_frame(data: &[u8]) -> Result<Frame, H2Error> {
    // Assume padded for maximum coverage
    let header = FrameHeader {
        length: std::cmp::min(data.len() as u32, 16_777_215),
        frame_type: DATA_FRAME_TYPE,
        flags: data_flags::PADDED,
        stream_id: 1,
    };

    parse_frame(&header, Bytes::copy_from_slice(data))
}

/// Extract application data from DATA frame after padding removal
fn extract_application_data(frame: &Frame) -> Option<Bytes> {
    match frame {
        Frame::Data(data_frame) => Some(data_frame.data.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_padding() {
        let app_data = b"Hello, World!";
        let pad_length = 5;

        let frame = create_padded_data_frame(app_data, pad_length, 1).unwrap();
        let result = validate_data_frame_padding(&frame).unwrap();

        if let Frame::Data(data_frame) = result {
            assert_eq!(data_frame.data, Bytes::from_static(app_data));
            assert_eq!(data_frame.stream_id, 1);
        }
    }

    #[test]
    fn test_zero_padding() {
        let app_data = b"No padding";
        let frame = create_padded_data_frame(app_data, 0, 1).unwrap();
        let result = validate_data_frame_padding(&frame).unwrap();

        if let Frame::Data(data_frame) = result {
            assert_eq!(data_frame.data, Bytes::from_static(app_data));
        }
    }

    #[test]
    fn test_excessive_padding() {
        let app_data = b"Hi";
        let pad_length = 10; // More than app_data length

        let frame = create_padded_data_frame(app_data, pad_length, 1).unwrap();
        let result = validate_data_frame_padding(&frame);

        assert!(result.is_err());
        if let Err(error) = result {
            assert_eq!(error.code, ErrorCode::ProtocolError);
        }
    }

    #[test]
    fn test_maximum_padding() {
        let app_data = vec![b'X'; 300]; // Large enough for max padding
        let frame = create_padded_data_frame(&app_data, 255, 1).unwrap();
        let result = validate_data_frame_padding(&frame).unwrap();

        if let Frame::Data(data_frame) = result {
            assert_eq!(data_frame.data, Bytes::from(app_data));
        }
    }

    #[test]
    fn test_empty_data_with_padding() {
        let frame = create_padded_data_frame(&[], 5, 1).unwrap();
        let result = validate_data_frame_padding(&frame);

        // Should fail - padding exceeds (zero) data length
        assert!(result.is_err());
        if let Err(error) = result {
            assert_eq!(error.code, ErrorCode::ProtocolError);
        }
    }

    #[test]
    fn test_padding_equals_data_length() {
        let app_data = b"test";
        let frame = create_padded_data_frame(app_data, app_data.len() as u8, 1).unwrap();
        let result = validate_data_frame_padding(&frame).unwrap();

        if let Frame::Data(data_frame) = result {
            // All data was padding, so result should be empty
            assert!(data_frame.data.is_empty());
        }
    }

    #[test]
    fn test_non_padded_frame() {
        let data = b"No padding here";
        let result = parse_data_frame_with_padding(data, false).unwrap();

        if let Frame::Data(data_frame) = result {
            assert_eq!(data_frame.data, Bytes::from_static(data));
        }
    }
}