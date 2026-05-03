#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

/// HTTP/2 DATA frame maximum padding size validation testing.
/// Per RFC 7540 §6.1, when PADDED flag is set, first byte indicates pad length.
/// Parser must correctly subtract pad-length from payload to extract actual data.
/// Tests pad-length=255 (max value) and proper data extraction.
///
/// Tests:
/// - DATA frame with PADDED flag and pad-length=255 (max pad value)
/// - Correct pad-length subtraction from total payload
/// - Actual data extraction after accounting for padding
/// - Various frame sizes with maximum padding
/// - Edge cases where padding consumes most/all frame
/// - Invalid scenarios where pad-length exceeds available payload
/// - Padding format validation: [pad-length][data][padding]

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// DATA frame to test
    data_frame: DataFrameWithPadding,
}

#[derive(Arbitrary, Debug, Clone)]
struct DataFrameWithPadding {
    /// Stream ID (must be > 0 for DATA)
    stream_id: u32,
    /// Frame flags (PADDED = 0x08)
    flags: u8,
    /// Total frame payload size
    total_payload_size: u16,
    /// Pad length value (0-255)
    pad_length: u8,
    /// Actual data content
    data_content: Vec<u8>,
}

/// Extracted DATA frame information
#[derive(Debug, Clone, PartialEq)]
struct DataFrameInfo {
    /// Stream ID
    stream_id: u32,
    /// Frame flags
    flags: u8,
    /// Actual data (after padding extraction)
    data: Vec<u8>,
    /// Padding information
    padding_info: Option<PaddingInfo>,
    /// End of stream flag
    end_stream: bool,
}

/// Padding information
#[derive(Debug, Clone, PartialEq)]
struct PaddingInfo {
    /// Pad length byte value
    pad_length: u8,
    /// Actual padding bytes
    padding_bytes: Vec<u8>,
}

/// HTTP/2 DATA frame flags
const DATA_FLAG_END_STREAM: u8 = 0x01;
const DATA_FLAG_PADDED: u8 = 0x08;

/// Mock HTTP/2 DATA frame parser with padding validation
struct MockH2DataPaddingParser {
    /// Parsed frame information
    parsed_frames: Vec<DataFrameInfo>,
    /// Processing errors
    errors: Vec<String>,
}

impl MockH2DataPaddingParser {
    fn new() -> Self {
        Self {
            parsed_frames: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Parse DATA frame with padding validation
    fn parse_data_frame(&mut self, frame: &DataFrameWithPadding) -> Result<(), String> {
        // Validate stream ID
        if frame.stream_id == 0 {
            return Err("PROTOCOL_ERROR: DATA frame stream ID must not be 0".into());
        }

        // Check if PADDED flag is set
        let is_padded = (frame.flags & DATA_FLAG_PADDED) != 0;
        let end_stream = (frame.flags & DATA_FLAG_END_STREAM) != 0;

        if is_padded {
            self.parse_padded_data_frame(frame, end_stream)
        } else {
            self.parse_unpadded_data_frame(frame, end_stream)
        }
    }

    /// Parse DATA frame with PADDED flag
    fn parse_padded_data_frame(&mut self, frame: &DataFrameWithPadding, end_stream: bool) -> Result<(), String> {
        // Build raw frame payload
        let raw_payload = self.build_padded_payload(frame)?;

        // Validate minimum frame size for padded frame (at least pad-length byte)
        if raw_payload.is_empty() {
            return Err("FRAME_SIZE_ERROR: PADDED DATA frame must have at least pad-length byte".into());
        }

        // Extract pad-length from first byte
        let pad_length = raw_payload[0];

        // Calculate data size: total_payload - pad_length_byte - pad_length
        let payload_without_pad_byte = raw_payload.len() - 1; // Subtract pad-length byte

        if (pad_length as usize) > payload_without_pad_byte {
            return Err(format!(
                "PROTOCOL_ERROR: pad length {} exceeds available payload {}",
                pad_length, payload_without_pad_byte
            ));
        }

        let data_size = payload_without_pad_byte - (pad_length as usize);

        // Extract actual data
        let data = if data_size > 0 {
            raw_payload[1..1 + data_size].to_vec()
        } else {
            Vec::new()
        };

        // Extract padding bytes
        let padding_start = 1 + data_size;
        let padding_bytes = if pad_length > 0 {
            raw_payload[padding_start..].to_vec()
        } else {
            Vec::new()
        };

        // Validate padding bytes (should be pad_length in size)
        if padding_bytes.len() != pad_length as usize {
            return Err(format!(
                "PROTOCOL_ERROR: expected {} padding bytes, got {}",
                pad_length, padding_bytes.len()
            ));
        }

        // Store parsed frame
        let frame_info = DataFrameInfo {
            stream_id: frame.stream_id,
            flags: frame.flags,
            data,
            padding_info: Some(PaddingInfo {
                pad_length,
                padding_bytes,
            }),
            end_stream,
        };

        self.parsed_frames.push(frame_info);

        Ok(())
    }

    /// Parse DATA frame without PADDED flag
    fn parse_unpadded_data_frame(&mut self, frame: &DataFrameWithPadding, end_stream: bool) -> Result<(), String> {
        // For unpadded frames, all payload is data
        let data = frame.data_content.clone();

        let frame_info = DataFrameInfo {
            stream_id: frame.stream_id,
            flags: frame.flags,
            data,
            padding_info: None,
            end_stream,
        };

        self.parsed_frames.push(frame_info);

        Ok(())
    }

    /// Build raw padded frame payload: [pad-length][data][padding]
    fn build_padded_payload(&self, frame: &DataFrameWithPadding) -> Result<Vec<u8>, String> {
        let mut payload = Vec::new();

        // Add pad-length byte
        payload.push(frame.pad_length);

        // Add actual data
        let data_size = frame.total_payload_size as usize
            - 1 // pad-length byte
            - frame.pad_length as usize; // padding

        if data_size > frame.data_content.len() {
            return Err("Insufficient data content for specified frame size".into());
        }

        payload.extend(&frame.data_content[..data_size.min(frame.data_content.len())]);

        // Add padding bytes
        for _ in 0..frame.pad_length {
            payload.push(0); // Padding can be any value, using 0 for simplicity
        }

        // Validate total payload size
        if payload.len() != frame.total_payload_size as usize {
            return Err(format!(
                "Payload size mismatch: expected {}, got {}",
                frame.total_payload_size, payload.len()
            ));
        }

        Ok(payload)
    }

    /// Get parsed frames
    fn get_parsed_frames(&self) -> &[DataFrameInfo] {
        &self.parsed_frames
    }

    /// Get latest parsed frame
    fn get_latest_frame(&self) -> Option<&DataFrameInfo> {
        self.parsed_frames.last()
    }

    /// Validate pad-length extraction
    fn validate_padding_extraction(&self, frame_index: usize, expected_pad_length: u8) -> bool {
        if let Some(frame) = self.parsed_frames.get(frame_index) {
            if let Some(padding_info) = &frame.padding_info {
                return padding_info.pad_length == expected_pad_length;
            }
        }
        false
    }

    /// Calculate actual data size after padding
    fn calculate_data_size(&self, total_payload_size: u16, pad_length: u8) -> Option<usize> {
        let total_size = total_payload_size as usize;

        if total_size == 0 {
            return Some(0);
        }

        // Must have at least pad-length byte
        if total_size < 1 {
            return None;
        }

        let remaining_after_pad_byte = total_size - 1;

        if (pad_length as usize) > remaining_after_pad_byte {
            return None; // Invalid: pad length exceeds available space
        }

        Some(remaining_after_pad_byte - (pad_length as usize))
    }

    /// Get processing errors
    fn get_errors(&self) -> &[String] {
        &self.errors
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let input: FuzzInput = match u.arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Skip invalid inputs
    };

    // Limit sizes to prevent timeouts
    if input.data_frame.total_payload_size > 1000 ||
       input.data_frame.data_content.len() > 1000 {
        return;
    }

    // Ensure valid stream ID
    if input.data_frame.stream_id == 0 || input.data_frame.stream_id > 1_000_000 {
        return;
    }

    let mut parser = MockH2DataPaddingParser::new();
    let result = parser.parse_data_frame(&input.data_frame);

    let frame = &input.data_frame;
    let is_padded = (frame.flags & DATA_FLAG_PADDED) != 0;

    // Test 1: Stream ID validation
    if frame.stream_id == 0 {
        assert!(result.is_err(),
            "DATA frame with stream ID 0 should be rejected");
        return;
    }

    // Test 2: Padded frame validation
    if is_padded {
        // Calculate expected data size
        if let Some(expected_data_size) = parser.calculate_data_size(frame.total_payload_size, frame.pad_length) {
            if expected_data_size <= frame.data_content.len() {
                assert!(result.is_ok(),
                    "Valid padded frame should succeed: payload={}, pad_length={}, expected_data={}",
                    frame.total_payload_size, frame.pad_length, expected_data_size);

                if let Some(parsed_frame) = parser.get_latest_frame() {
                    // Test 3: Pad-length extraction verification
                    assert!(parser.validate_padding_extraction(0, frame.pad_length),
                        "Pad-length should be correctly extracted: expected {}", frame.pad_length);

                    // Test 4: Data size verification
                    assert_eq!(parsed_frame.data.len(), expected_data_size,
                        "Actual data size {} should match expected {}",
                        parsed_frame.data.len(), expected_data_size);

                    // Test 5: Padding info verification
                    if let Some(padding_info) = &parsed_frame.padding_info {
                        assert_eq!(padding_info.pad_length, frame.pad_length,
                            "Stored pad-length should match frame pad-length");

                        assert_eq!(padding_info.padding_bytes.len(), frame.pad_length as usize,
                            "Padding bytes length should match pad-length");
                    }

                    // Test 6: Maximum pad-length (255) handling
                    if frame.pad_length == 255 {
                        assert_eq!(parsed_frame.data.len(),
                                 (frame.total_payload_size as usize).saturating_sub(256),
                                 "Max padding (255) should leave minimal data");
                    }

                    // Test 7: End-stream flag preservation
                    let expected_end_stream = (frame.flags & DATA_FLAG_END_STREAM) != 0;
                    assert_eq!(parsed_frame.end_stream, expected_end_stream,
                        "End-stream flag should be preserved");
                }
            } else {
                // Insufficient data for frame size
                assert!(result.is_err(),
                    "Insufficient data should cause error");
            }
        } else {
            // Invalid pad-length (exceeds payload)
            assert!(result.is_err(),
                "Invalid pad-length {} for payload {} should cause error",
                frame.pad_length, frame.total_payload_size);

            if let Err(error_msg) = &result {
                assert!(error_msg.contains("pad length") && error_msg.contains("exceeds"),
                    "Error should mention pad length exceeding payload: {}", error_msg);
            }
        }
    } else {
        // Test 8: Unpadded frame handling
        if frame.data_content.len() <= frame.total_payload_size as usize {
            assert!(result.is_ok(),
                "Valid unpadded frame should succeed");

            if let Some(parsed_frame) = parser.get_latest_frame() {
                assert!(parsed_frame.padding_info.is_none(),
                    "Unpadded frame should have no padding info");

                assert_eq!(parsed_frame.data, frame.data_content,
                    "Unpadded frame data should match original");
            }
        }
    }

    // Test 9: Frame size consistency
    if is_padded && frame.total_payload_size > 0 {
        // For padded frames, total size = 1 (pad-length byte) + data + padding
        let expected_total = 1 + frame.data_content.len() + frame.pad_length as usize;

        if expected_total != frame.total_payload_size as usize {
            // Size mismatch should cause build error
            if result.is_ok() {
                // But if it succeeded, verify the parser handled it correctly
                if let Some(parsed_frame) = parser.get_latest_frame() {
                    let actual_total = 1 + parsed_frame.data.len() +
                        parsed_frame.padding_info.as_ref().map_or(0, |p| p.pad_length as usize);
                    assert_eq!(actual_total, frame.total_payload_size as usize,
                        "Parsed frame should match declared total size");
                }
            }
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_padding_size() {
        let frame = DataFrameWithPadding {
            stream_id: 1,
            flags: DATA_FLAG_PADDED,
            total_payload_size: 300, // 1 (pad-length) + 44 (data) + 255 (padding)
            pad_length: 255, // Max padding
            data_content: vec![b'A'; 44], // Data portion
        };

        let mut parser = MockH2DataPaddingParser::new();
        let result = parser.parse_data_frame(&frame);

        assert!(result.is_ok(), "Max padding size should be valid");

        let parsed = parser.get_latest_frame().unwrap();
        assert_eq!(parsed.data.len(), 44);
        assert_eq!(parsed.padding_info.as_ref().unwrap().pad_length, 255);
    }

    #[test]
    fn test_padding_exceeds_payload() {
        let frame = DataFrameWithPadding {
            stream_id: 1,
            flags: DATA_FLAG_PADDED,
            total_payload_size: 100,
            pad_length: 200, // Exceeds available space
            data_content: vec![b'A'; 50],
        };

        let mut parser = MockH2DataPaddingParser::new();
        let result = parser.parse_data_frame(&frame);

        assert!(result.is_err(), "Excessive padding should be rejected");
        assert!(result.unwrap_err().contains("exceeds available payload"));
    }

    #[test]
    fn test_zero_padding() {
        let frame = DataFrameWithPadding {
            stream_id: 1,
            flags: DATA_FLAG_PADDED,
            total_payload_size: 11, // 1 (pad-length) + 10 (data) + 0 (padding)
            pad_length: 0, // No padding
            data_content: vec![b'B'; 10],
        };

        let mut parser = MockH2DataPaddingParser::new();
        let result = parser.parse_data_frame(&frame);

        assert!(result.is_ok(), "Zero padding should be valid");

        let parsed = parser.get_latest_frame().unwrap();
        assert_eq!(parsed.data.len(), 10);
        assert_eq!(parsed.padding_info.as_ref().unwrap().pad_length, 0);
        assert_eq!(parsed.padding_info.as_ref().unwrap().padding_bytes.len(), 0);
    }

    #[test]
    fn test_unpadded_frame() {
        let frame = DataFrameWithPadding {
            stream_id: 1,
            flags: 0, // No PADDED flag
            total_payload_size: 20,
            pad_length: 0, // Ignored for unpadded
            data_content: vec![b'C'; 20],
        };

        let mut parser = MockH2DataPaddingParser::new();
        let result = parser.parse_data_frame(&frame);

        assert!(result.is_ok(), "Unpadded frame should be valid");

        let parsed = parser.get_latest_frame().unwrap();
        assert_eq!(parsed.data, vec![b'C'; 20]);
        assert!(parsed.padding_info.is_none());
    }

    #[test]
    fn test_end_stream_flag() {
        let frame = DataFrameWithPadding {
            stream_id: 1,
            flags: DATA_FLAG_PADDED | DATA_FLAG_END_STREAM,
            total_payload_size: 11, // 1 + 5 + 5
            pad_length: 5,
            data_content: vec![b'D'; 5],
        };

        let mut parser = MockH2DataPaddingParser::new();
        let result = parser.parse_data_frame(&frame);

        assert!(result.is_ok(), "Frame with END_STREAM should be valid");

        let parsed = parser.get_latest_frame().unwrap();
        assert!(parsed.end_stream, "END_STREAM flag should be preserved");
        assert_eq!(parsed.data.len(), 5);
    }

    #[test]
    fn test_minimal_padded_frame() {
        let frame = DataFrameWithPadding {
            stream_id: 1,
            flags: DATA_FLAG_PADDED,
            total_payload_size: 1, // Only pad-length byte
            pad_length: 0, // No padding, no data
            data_content: vec![],
        };

        let mut parser = MockH2DataPaddingParser::new();
        let result = parser.parse_data_frame(&frame);

        assert!(result.is_ok(), "Minimal padded frame should be valid");

        let parsed = parser.get_latest_frame().unwrap();
        assert_eq!(parsed.data.len(), 0);
        assert_eq!(parsed.padding_info.as_ref().unwrap().pad_length, 0);
    }

    #[test]
    fn test_invalid_stream_id() {
        let frame = DataFrameWithPadding {
            stream_id: 0, // Invalid for DATA
            flags: DATA_FLAG_PADDED,
            total_payload_size: 10,
            pad_length: 5,
            data_content: vec![b'E'; 4],
        };

        let mut parser = MockH2DataPaddingParser::new();
        let result = parser.parse_data_frame(&frame);

        assert!(result.is_err(), "DATA with stream ID 0 should be rejected");
        assert!(result.unwrap_err().contains("stream ID must not be 0"));
    }

    #[test]
    fn test_data_size_calculation() {
        let parser = MockH2DataPaddingParser::new();

        // Normal case
        assert_eq!(parser.calculate_data_size(100, 10), Some(89)); // 100 - 1 - 10 = 89

        // Max padding
        assert_eq!(parser.calculate_data_size(256, 255), Some(0)); // 256 - 1 - 255 = 0

        // Pad length exceeds payload
        assert_eq!(parser.calculate_data_size(10, 15), None); // 10 - 1 = 9, but need 15

        // Empty payload
        assert_eq!(parser.calculate_data_size(0, 0), Some(0));
    }

    #[test]
    fn test_all_padding_no_data() {
        let frame = DataFrameWithPadding {
            stream_id: 1,
            flags: DATA_FLAG_PADDED,
            total_payload_size: 256, // 1 (pad-length) + 0 (data) + 255 (padding)
            pad_length: 255, // Max padding, no data
            data_content: vec![],
        };

        let mut parser = MockH2DataPaddingParser::new();
        let result = parser.parse_data_frame(&frame);

        assert!(result.is_ok(), "Frame with only padding should be valid");

        let parsed = parser.get_latest_frame().unwrap();
        assert_eq!(parsed.data.len(), 0);
        assert_eq!(parsed.padding_info.as_ref().unwrap().pad_length, 255);
        assert_eq!(parsed.padding_info.as_ref().unwrap().padding_bytes.len(), 255);
    }
}