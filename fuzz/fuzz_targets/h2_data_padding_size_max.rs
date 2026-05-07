#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{FrameHeader, FrameType, data_flags};
use asupersync::http::h2::{Frame, FrameCodec};
use libfuzzer_sys::fuzz_target;

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

/// HTTP/2 DATA frame flags.
const DATA_FLAG_END_STREAM: u8 = data_flags::END_STREAM;
const DATA_FLAG_PADDED: u8 = data_flags::PADDED;

struct LiveH2DataPaddingDecoder {
    /// Parsed frame information
    parsed_frames: Vec<DataFrameInfo>,
}

impl LiveH2DataPaddingDecoder {
    fn new() -> Self {
        Self {
            parsed_frames: Vec::new(),
        }
    }

    fn parse_data_frame(&mut self, frame: &DataFrameWithPadding) -> Result<(), String> {
        let mut wire = encode_data_frame(frame);
        let mut codec = FrameCodec::new();
        match codec.decode(&mut wire) {
            Ok(Some(Frame::Data(decoded))) => {
                self.parsed_frames.push(DataFrameInfo {
                    stream_id: decoded.stream_id,
                    flags: frame.flags,
                    data: decoded.data.to_vec(),
                    padding_info: expected_padding_info(frame),
                    end_stream: decoded.end_stream,
                });
                Ok(())
            }
            Ok(Some(other)) => Err(format!("decoded non-DATA frame: {other:?}")),
            Ok(None) => Err("incomplete DATA frame".to_string()),
            Err(err) => Err(format!("{}: {}", err.code, err.message)),
        }
    }

    fn get_latest_frame(&self) -> Option<&DataFrameInfo> {
        self.parsed_frames.last()
    }

    fn validate_padding_extraction(&self, frame_index: usize, expected_pad_length: u8) -> bool {
        if let Some(frame) = self.parsed_frames.get(frame_index)
            && let Some(padding_info) = &frame.padding_info
        {
            return padding_info.pad_length == expected_pad_length;
        }
        false
    }

    fn calculate_data_size(&self, total_payload_size: u16, pad_length: u8) -> Option<usize> {
        let total_size = total_payload_size as usize;
        if total_size == 0 {
            return None;
        }

        let remaining_after_pad_byte = total_size - 1;

        if (pad_length as usize) > remaining_after_pad_byte {
            return None;
        }

        Some(remaining_after_pad_byte - (pad_length as usize))
    }
}

fn encode_data_frame(frame: &DataFrameWithPadding) -> BytesMut {
    let mut wire = BytesMut::new();
    FrameHeader {
        length: u32::from(frame.total_payload_size),
        frame_type: FrameType::Data as u8,
        flags: frame.flags,
        stream_id: frame.stream_id,
    }
    .write(&mut wire);

    let is_padded = (frame.flags & DATA_FLAG_PADDED) != 0;
    if is_padded {
        encode_padded_payload(frame, &mut wire);
    } else {
        extend_data_bytes(
            &mut wire,
            &frame.data_content,
            usize::from(frame.total_payload_size),
        );
    }
    wire
}

fn encode_padded_payload(frame: &DataFrameWithPadding, wire: &mut BytesMut) {
    let total_payload_size = usize::from(frame.total_payload_size);
    if total_payload_size == 0 {
        return;
    }

    wire.put_u8(frame.pad_length);
    let remaining = total_payload_size - 1;
    let pad_length = usize::from(frame.pad_length);
    if pad_length > remaining {
        wire.resize(wire.len() + remaining, 0);
        return;
    }

    let data_len = remaining - pad_length;
    extend_data_bytes(wire, &frame.data_content, data_len);
    wire.resize(wire.len() + pad_length, 0);
}

fn extend_data_bytes(wire: &mut BytesMut, data_content: &[u8], len: usize) {
    let copied = data_content.len().min(len);
    wire.extend_from_slice(&data_content[..copied]);
    wire.resize(wire.len() + len - copied, b'A');
}

fn expected_padding_info(frame: &DataFrameWithPadding) -> Option<PaddingInfo> {
    if (frame.flags & DATA_FLAG_PADDED) == 0 {
        return None;
    }

    let data_len = expected_data_size(frame)?;
    Some(PaddingInfo {
        pad_length: frame.pad_length,
        padding_bytes: vec![0; usize::from(frame.pad_length)],
    })
    .filter(|_| {
        data_len + 1 + usize::from(frame.pad_length) == usize::from(frame.total_payload_size)
    })
}

fn expected_data_size(frame: &DataFrameWithPadding) -> Option<usize> {
    if (frame.flags & DATA_FLAG_PADDED) == 0 {
        return Some(usize::from(frame.total_payload_size));
    }

    let total_payload_size = usize::from(frame.total_payload_size);
    if total_payload_size == 0 {
        return None;
    }

    let remaining = total_payload_size - 1;
    let pad_length = usize::from(frame.pad_length);
    if pad_length > remaining {
        return None;
    }

    Some(remaining - pad_length)
}

fn expected_data_bytes(frame: &DataFrameWithPadding, len: usize) -> Vec<u8> {
    let mut bytes = BytesMut::new();
    extend_data_bytes(&mut bytes, &frame.data_content, len);
    bytes.to_vec()
}

fn is_protocol_error(error: &str) -> bool {
    error.contains(&ErrorCode::ProtocolError.to_string())
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let input: FuzzInput = match u.arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Skip invalid inputs
    };

    // Limit sizes to prevent timeouts
    if input.data_frame.total_payload_size > 1000 || input.data_frame.data_content.len() > 1000 {
        return;
    }

    // Ensure valid stream ID
    if input.data_frame.stream_id == 0 || input.data_frame.stream_id > 1_000_000 {
        return;
    }

    let mut decoder = LiveH2DataPaddingDecoder::new();
    let result = decoder.parse_data_frame(&input.data_frame);

    let frame = &input.data_frame;
    let is_padded = (frame.flags & DATA_FLAG_PADDED) != 0;

    // Test 1: Stream ID validation
    if frame.stream_id & 0x7fff_ffff == 0 {
        assert!(
            result.is_err(),
            "DATA frame with stream ID 0 should be rejected"
        );
        if let Err(error_msg) = &result {
            assert!(
                is_protocol_error(error_msg),
                "stream ID 0 should be rejected by live protocol validation: {error_msg}"
            );
        }
        return;
    }

    // Test 2: Padded frame validation
    if is_padded {
        if let Some(expected_data_size) =
            decoder.calculate_data_size(frame.total_payload_size, frame.pad_length)
        {
            assert!(
                result.is_ok(),
                "valid padded frame should decode: payload={}, pad_length={}, expected_data={}",
                frame.total_payload_size,
                frame.pad_length,
                expected_data_size
            );

            if let Some(parsed_frame) = decoder.get_latest_frame() {
                assert!(
                    decoder.validate_padding_extraction(0, frame.pad_length),
                    "pad-length should be tracked from the live-decoded frame"
                );

                assert_eq!(
                    parsed_frame.data.len(),
                    expected_data_size,
                    "decoded DATA length should subtract pad-length byte and padding"
                );
                assert_eq!(
                    parsed_frame.data,
                    expected_data_bytes(frame, expected_data_size),
                    "decoded DATA bytes should match the generated wire payload"
                );

                if let Some(padding_info) = &parsed_frame.padding_info {
                    assert_eq!(padding_info.pad_length, frame.pad_length);
                    assert_eq!(
                        padding_info.padding_bytes.len(),
                        usize::from(frame.pad_length)
                    );
                }

                if frame.pad_length == 255 {
                    assert_eq!(
                        parsed_frame.data.len(),
                        usize::from(frame.total_payload_size).saturating_sub(256),
                        "max padding should leave total_payload_size - 256 data bytes"
                    );
                }

                let expected_end_stream = (frame.flags & DATA_FLAG_END_STREAM) != 0;
                assert_eq!(parsed_frame.end_stream, expected_end_stream);
            }
        } else {
            assert!(
                result.is_err(),
                "Invalid pad-length {} for payload {} should cause error",
                frame.pad_length,
                frame.total_payload_size
            );

            if let Err(error_msg) = &result {
                assert!(
                    is_protocol_error(error_msg),
                    "invalid padding should be rejected by live protocol validation: {}",
                    error_msg
                );
            }
        }
    } else {
        // Test 8: Unpadded frame handling
        assert!(result.is_ok(), "valid unpadded frame should decode");

        if let Some(parsed_frame) = decoder.get_latest_frame() {
            assert!(
                parsed_frame.padding_info.is_none(),
                "unpadded frame should have no padding info"
            );

            let expected_len = usize::from(frame.total_payload_size);
            assert_eq!(parsed_frame.data, expected_data_bytes(frame, expected_len));
        }
    }

    // Test 9: Frame size consistency
    if is_padded && result.is_ok() {
        // For padded frames, total size = 1 (pad-length byte) + data + padding
        if let Some(parsed_frame) = decoder.get_latest_frame() {
            let actual_total = 1
                + parsed_frame.data.len()
                + parsed_frame
                    .padding_info
                    .as_ref()
                    .map_or(0, |p| usize::from(p.pad_length));
            assert_eq!(
                actual_total,
                usize::from(frame.total_payload_size),
                "decoded frame should match declared total size"
            );
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
            pad_length: 255,         // Max padding
            data_content: vec![b'A'; 44], // Data portion
        };

        let mut decoder = LiveH2DataPaddingDecoder::new();
        let result = decoder.parse_data_frame(&frame);

        assert!(result.is_ok(), "Max padding size should be valid");

        let parsed = decoder.get_latest_frame().unwrap();
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

        let mut decoder = LiveH2DataPaddingDecoder::new();
        let result = decoder.parse_data_frame(&frame);

        assert!(result.is_err(), "Excessive padding should be rejected");
        assert!(is_protocol_error(&result.unwrap_err()));
    }

    #[test]
    fn test_zero_padding() {
        let frame = DataFrameWithPadding {
            stream_id: 1,
            flags: DATA_FLAG_PADDED,
            total_payload_size: 11, // 1 (pad-length) + 10 (data) + 0 (padding)
            pad_length: 0,          // No padding
            data_content: vec![b'B'; 10],
        };

        let mut decoder = LiveH2DataPaddingDecoder::new();
        let result = decoder.parse_data_frame(&frame);

        assert!(result.is_ok(), "Zero padding should be valid");

        let parsed = decoder.get_latest_frame().unwrap();
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

        let mut decoder = LiveH2DataPaddingDecoder::new();
        let result = decoder.parse_data_frame(&frame);

        assert!(result.is_ok(), "Unpadded frame should be valid");

        let parsed = decoder.get_latest_frame().unwrap();
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

        let mut decoder = LiveH2DataPaddingDecoder::new();
        let result = decoder.parse_data_frame(&frame);

        assert!(result.is_ok(), "Frame with END_STREAM should be valid");

        let parsed = decoder.get_latest_frame().unwrap();
        assert!(parsed.end_stream, "END_STREAM flag should be preserved");
        assert_eq!(parsed.data.len(), 5);
    }

    #[test]
    fn test_minimal_padded_frame() {
        let frame = DataFrameWithPadding {
            stream_id: 1,
            flags: DATA_FLAG_PADDED,
            total_payload_size: 1, // Only pad-length byte
            pad_length: 0,         // No padding, no data
            data_content: vec![],
        };

        let mut decoder = LiveH2DataPaddingDecoder::new();
        let result = decoder.parse_data_frame(&frame);

        assert!(result.is_ok(), "Minimal padded frame should be valid");

        let parsed = decoder.get_latest_frame().unwrap();
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

        let mut decoder = LiveH2DataPaddingDecoder::new();
        let result = decoder.parse_data_frame(&frame);

        assert!(result.is_err(), "DATA with stream ID 0 should be rejected");
        assert!(is_protocol_error(&result.unwrap_err()));
    }

    #[test]
    fn test_data_size_calculation() {
        let decoder = LiveH2DataPaddingDecoder::new();

        // Normal case
        assert_eq!(decoder.calculate_data_size(100, 10), Some(89)); // 100 - 1 - 10 = 89

        // Max padding
        assert_eq!(decoder.calculate_data_size(256, 255), Some(0)); // 256 - 1 - 255 = 0

        // Pad length exceeds payload
        assert_eq!(decoder.calculate_data_size(10, 15), None); // 10 - 1 = 9, but need 15

        // Empty payload
        assert_eq!(decoder.calculate_data_size(0, 0), None);
    }

    #[test]
    fn test_all_padding_no_data() {
        let frame = DataFrameWithPadding {
            stream_id: 1,
            flags: DATA_FLAG_PADDED,
            total_payload_size: 256, // 1 (pad-length) + 0 (data) + 255 (padding)
            pad_length: 255,         // Max padding, no data
            data_content: vec![],
        };

        let mut decoder = LiveH2DataPaddingDecoder::new();
        let result = decoder.parse_data_frame(&frame);

        assert!(result.is_ok(), "Frame with only padding should be valid");

        let parsed = decoder.get_latest_frame().unwrap();
        assert_eq!(parsed.data.len(), 0);
        assert_eq!(parsed.padding_info.as_ref().unwrap().pad_length, 255);
        assert_eq!(
            parsed.padding_info.as_ref().unwrap().padding_bytes.len(),
            255
        );
    }
}
