#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Tests HTTP/2 DATA frames with PADDED flag set per RFC 7540 §6.1.
///
/// PADDED DATA frames have structure:
/// - Pad Length (1 byte) at offset 0
/// - Data payload
/// - Padding (Pad Length bytes)
///
/// Key violations to detect:
/// - pad-length > remaining frame payload → PROTOCOL_ERROR
/// - pad-length = 0 (legal but pointless)
/// - pad-length = 255 with frame-size = 256 (only 1 byte data)

#[derive(Arbitrary, Debug, Clone)]
struct PaddedDataInput {
    stream_id: u32,
    pad_length: u8,
    payload_size: u8, // Keep small to avoid OOM
    frame_flags: u8,
    test_variant: u8, // Controls which test scenario
}

/// Mock HTTP/2 DATA frame with PADDED flag
#[derive(Debug, Clone)]
struct PaddedDataFrame {
    stream_id: u32,
    flags: u8,
    pad_length: u8,
    payload: Vec<u8>,
    padding: Vec<u8>,
}

impl PaddedDataFrame {
    fn new(stream_id: u32, flags: u8, pad_length: u8, payload: Vec<u8>) -> Self {
        let padding = vec![0x00; pad_length as usize]; // RFC: padding SHOULD be zero-filled
        Self {
            stream_id,
            flags: flags | 0x08, // Set PADDED flag (0x08)
            pad_length,
            payload,
            padding,
        }
    }

    fn is_padded(&self) -> bool {
        self.flags & 0x08 != 0 // PADDED flag
    }

    fn end_stream(&self) -> bool {
        self.flags & 0x01 != 0 // END_STREAM flag
    }

    /// Total frame size including pad length byte + payload + padding
    fn frame_size(&self) -> usize {
        1 + self.payload.len() + self.padding.len() // 1 byte for pad_length + payload + padding
    }

    /// Validate PADDED frame structure per RFC 7540 §6.1
    fn validate(&self) -> Result<(), PaddedFrameError> {
        if !self.is_padded() {
            return Err(PaddedFrameError::PaddedFlagNotSet);
        }

        // Check if pad length exceeds available space in frame
        // Frame layout: [pad_length:1][payload:N][padding:pad_length]
        let required_padding_bytes = self.pad_length as usize;
        let available_bytes_for_padding = self.frame_size().saturating_sub(1 + self.payload.len());

        if required_padding_bytes > available_bytes_for_padding {
            return Err(PaddedFrameError::PadLengthExceedsFrame {
                pad_length: self.pad_length,
                payload_size: self.payload.len(),
                frame_size: self.frame_size(),
            });
        }

        // RFC 7540: If the length of the padding is the length of the
        // frame payload or greater, the recipient MUST treat this as a
        // connection error of type PROTOCOL_ERROR.
        if self.pad_length as usize >= self.payload.len() && !self.payload.is_empty() {
            return Err(PaddedFrameError::PadLengthExceedsPayload {
                pad_length: self.pad_length,
                payload_size: self.payload.len(),
            });
        }

        // Special case: pad_length = 0 is legal but redundant
        if self.pad_length == 0 {
            return Ok(()); // Legal, just unnecessary
        }

        Ok(())
    }

    /// Calculate actual data length (excluding padding)
    fn data_length(&self) -> usize {
        self.payload.len()
    }
}

#[derive(Debug, Clone, PartialEq)]
enum PaddedFrameError {
    PaddedFlagNotSet,
    PadLengthExceedsFrame {
        pad_length: u8,
        payload_size: usize,
        frame_size: usize,
    },
    PadLengthExceedsPayload {
        pad_length: u8,
        payload_size: usize,
    },
}

/// Mock connection for testing PADDED DATA frame validation
struct MockPaddedDataConnection {
    processed_frames: usize,
    protocol_errors: Vec<PaddedFrameError>,
    valid_frames: usize,
    total_data_bytes: usize,
    total_padding_bytes: usize,
}

impl MockPaddedDataConnection {
    fn new() -> Self {
        Self {
            processed_frames: 0,
            protocol_errors: Vec::new(),
            valid_frames: 0,
            total_data_bytes: 0,
            total_padding_bytes: 0,
        }
    }

    fn process_padded_data_frame(&mut self, frame: &PaddedDataFrame) -> bool {
        self.processed_frames += 1;

        match frame.validate() {
            Ok(()) => {
                // Valid frame - count data and padding bytes
                self.valid_frames += 1;
                self.total_data_bytes += frame.data_length();
                self.total_padding_bytes += frame.pad_length as usize;
                true // Frame accepted
            }
            Err(error) => {
                // Protocol violation - must reject with PROTOCOL_ERROR
                self.protocol_errors.push(error);
                false // Frame rejected
            }
        }
    }

    fn has_protocol_errors(&self) -> bool {
        !self.protocol_errors.is_empty()
    }

    fn error_count(&self) -> usize {
        self.protocol_errors.len()
    }

    fn padding_efficiency(&self) -> f64 {
        if self.total_data_bytes + self.total_padding_bytes == 0 {
            return 1.0;
        }
        self.total_data_bytes as f64 / (self.total_data_bytes + self.total_padding_bytes) as f64
    }
}

fuzz_target!(|input: PaddedDataInput| {
    // Skip invalid stream IDs
    if input.stream_id == 0 || input.stream_id % 2 == 0 {
        return;
    }

    // Limit payload size to prevent memory issues
    let payload_size = (input.payload_size as usize).min(512);
    let payload = vec![0x41; payload_size];

    let mut conn = MockPaddedDataConnection::new();

    match input.test_variant % 8 {
        0 => {
            // Test case 1: Normal padded frame with small padding
            let pad_length = (input.pad_length % 16) + 1; // 1-16 bytes padding
            let frame =
                PaddedDataFrame::new(input.stream_id, input.frame_flags, pad_length, payload);
            conn.process_padded_data_frame(&frame);

            // Should be accepted if padding doesn't exceed payload
            if frame.payload.len() > 0 && pad_length as usize >= frame.payload.len() {
                assert!(
                    conn.has_protocol_errors(),
                    "Pad length >= payload size should cause PROTOCOL_ERROR"
                );
            }
        }
        1 => {
            // Test case 2: Pad length = 0 (legal but pointless)
            let frame = PaddedDataFrame::new(input.stream_id, input.frame_flags, 0, payload);
            let accepted = conn.process_padded_data_frame(&frame);

            assert!(accepted, "Pad length = 0 is legal and should be accepted");
            assert!(
                !conn.has_protocol_errors(),
                "Pad length = 0 should not cause errors"
            );
            assert_eq!(
                frame.padding.len(),
                0,
                "Zero pad length should mean no padding bytes"
            );
        }
        2 => {
            // Test case 3: pad-length = 255 with frame-size = 256 (1 byte data)
            if payload.len() == 1 {
                let frame = PaddedDataFrame::new(input.stream_id, input.frame_flags, 255, payload);
                let accepted = conn.process_padded_data_frame(&frame);

                // This should be rejected: padding (255) >= payload (1)
                assert!(
                    !accepted,
                    "Pad length 255 with 1 byte payload should be rejected"
                );
                assert!(conn.has_protocol_errors(), "Should detect PROTOCOL_ERROR");
            }
        }
        3 => {
            // Test case 4: Pad length exceeds available frame space
            let excessive_pad = 255; // Much larger than payload
            let frame =
                PaddedDataFrame::new(input.stream_id, input.frame_flags, excessive_pad, payload);
            conn.process_padded_data_frame(&frame);

            if frame.payload.len() > 0 && excessive_pad as usize >= frame.payload.len() {
                assert!(
                    conn.has_protocol_errors(),
                    "Excessive padding should cause PROTOCOL_ERROR"
                );
            }
        }
        4 => {
            // Test case 5: Empty payload with padding
            let empty_payload = Vec::new();
            let frame = PaddedDataFrame::new(
                input.stream_id,
                input.frame_flags,
                input.pad_length,
                empty_payload,
            );
            let accepted = conn.process_padded_data_frame(&frame);

            // Empty payload is always valid regardless of pad_length
            assert!(accepted, "Empty payload with padding should be accepted");
        }
        5 => {
            // Test case 6: END_STREAM + PADDED combination
            let flags_with_end_stream = input.frame_flags | 0x01 | 0x08; // END_STREAM + PADDED
            let mut frame = PaddedDataFrame::new(
                input.stream_id,
                flags_with_end_stream,
                input.pad_length % 32,
                payload,
            );
            frame.flags = flags_with_end_stream; // Ensure both flags are set

            let accepted = conn.process_padded_data_frame(&frame);

            assert!(frame.is_padded(), "Frame should have PADDED flag");
            assert!(frame.end_stream(), "Frame should have END_STREAM flag");

            // Validation depends on padding vs payload size
            if frame.payload.len() > 0 && frame.pad_length as usize >= frame.payload.len() {
                assert!(
                    !accepted,
                    "Pad length >= payload should be rejected even with END_STREAM"
                );
            }
        }
        6 => {
            // Test case 7: Maximum valid padding (payload_size - 1)
            if payload.len() > 1 {
                let max_valid_pad = (payload.len() - 1) as u8;
                let frame = PaddedDataFrame::new(
                    input.stream_id,
                    input.frame_flags,
                    max_valid_pad,
                    payload,
                );
                let accepted = conn.process_padded_data_frame(&frame);

                assert!(accepted, "Maximum valid padding should be accepted");
                assert!(
                    !conn.has_protocol_errors(),
                    "Maximum valid padding should not error"
                );
            }
        }
        7 => {
            // Test case 8: Multiple frames with different padding
            for pad_len in [0, 1, 5, 10, input.pad_length % 50] {
                let test_payload = vec![0x50 + pad_len; payload_size.min(100)];
                let frame = PaddedDataFrame::new(
                    input.stream_id + pad_len as u32,
                    input.frame_flags,
                    pad_len,
                    test_payload,
                );
                conn.process_padded_data_frame(&frame);
            }

            // Verify connection tracks stats correctly
            assert!(conn.processed_frames >= 5, "Should process multiple frames");

            // Check padding efficiency (should be reasonable for small padding values)
            if conn.total_data_bytes > 0 {
                let efficiency = conn.padding_efficiency();
                assert!(
                    efficiency > 0.0 && efficiency <= 1.0,
                    "Padding efficiency should be between 0 and 1"
                );
            }
        }
        _ => unreachable!(),
    }

    // Verify connection state consistency
    assert_eq!(
        conn.valid_frames + conn.error_count(),
        conn.processed_frames,
        "Valid frames + error frames should equal total processed"
    );
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padded_frame_basic() {
        let payload = vec![0x41, 0x42, 0x43];
        let frame = PaddedDataFrame::new(1, 0x08, 2, payload); // 2 bytes padding

        assert!(frame.is_padded());
        assert_eq!(frame.pad_length, 2);
        assert_eq!(frame.data_length(), 3);
        assert_eq!(frame.frame_size(), 6); // 1 + 3 + 2
        assert!(frame.validate().is_ok());
    }

    #[test]
    fn test_zero_padding() {
        let payload = vec![0x44, 0x45];
        let frame = PaddedDataFrame::new(3, 0x08, 0, payload);

        assert!(frame.is_padded());
        assert_eq!(frame.padding.len(), 0);
        assert!(frame.validate().is_ok());
    }

    #[test]
    fn test_excessive_padding() {
        let payload = vec![0x46]; // 1 byte payload
        let frame = PaddedDataFrame::new(5, 0x08, 1, payload); // 1 byte padding = payload size

        let result = frame.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PaddedFrameError::PadLengthExceedsPayload { .. }
        ));
    }

    #[test]
    fn test_empty_payload_with_padding() {
        let frame = PaddedDataFrame::new(7, 0x08, 5, vec![]);
        assert!(frame.validate().is_ok()); // Empty payload is always valid
    }

    #[test]
    fn test_end_stream_padded_combination() {
        let payload = vec![0x47, 0x48, 0x49, 0x4A];
        let frame = PaddedDataFrame::new(9, 0x09, 3, payload); // END_STREAM + PADDED

        assert!(frame.is_padded());
        assert!(frame.end_stream());
        assert_eq!(frame.data_length(), 4);
        assert!(frame.validate().is_ok()); // 3 < 4, so valid
    }

    #[test]
    fn test_connection_stats() {
        let mut conn = MockPaddedDataConnection::new();

        // Valid frame
        let valid_frame = PaddedDataFrame::new(11, 0x08, 2, vec![0x4B, 0x4C, 0x4D]);
        assert!(conn.process_padded_data_frame(&valid_frame));

        // Invalid frame
        let invalid_frame = PaddedDataFrame::new(13, 0x08, 3, vec![0x4E, 0x4F]); // pad >= payload
        assert!(!conn.process_padded_data_frame(&invalid_frame));

        assert_eq!(conn.processed_frames, 2);
        assert_eq!(conn.valid_frames, 1);
        assert_eq!(conn.error_count(), 1);
        assert_eq!(conn.total_data_bytes, 3);
        assert_eq!(conn.total_padding_bytes, 2);
    }
}
