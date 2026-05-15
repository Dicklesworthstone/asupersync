#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 DATA frame padding validation fuzz target.
///
/// Tests RFC 7540 §6.1 compliance for PADDED DATA frames where pad-length
/// exceeds available payload space. The specification requires the padding
/// length to be strictly less than the full frame payload length; the one-byte
/// pad-length field may leave zero DATA bytes when all remaining octets are
/// padding.
///
/// Critical test case: pad-length=255 with frame-payload-length=256 is the
/// maximum wire-legal all-padding DATA frame, not a padding overflow.

#[derive(Arbitrary, Debug, Clone)]
struct DataPaddingInput {
    /// Stream ID for the DATA frame (must be non-zero for stream frames)
    stream_id: u32,

    /// Total frame payload length
    frame_payload_length: u16,

    /// Pad length value (0-255)
    pad_length: u8,

    /// Whether PADDED flag is set
    padded_flag: bool,

    /// Whether END_STREAM flag is set
    end_stream_flag: bool,

    /// Validation policy configuration
    policy: PaddingValidationPolicy,
}

#[derive(Arbitrary, Debug, Clone)]
struct PaddingValidationPolicy {
    /// Maximum frame payload size allowed
    max_frame_size: u32,
}

impl Default for PaddingValidationPolicy {
    fn default() -> Self {
        Self {
            max_frame_size: 16384, // RFC 7540 default SETTINGS_MAX_FRAME_SIZE
        }
    }
}

/// Mock HTTP/2 DATA frame processor for testing padding validation
struct MockDataProcessor {
    policy: PaddingValidationPolicy,
}

impl MockDataProcessor {
    fn new(policy: PaddingValidationPolicy) -> Self {
        Self { policy }
    }

    /// Process a DATA frame and validate padding according to RFC 7540 §6.1
    fn process_data_frame(&self, input: &DataPaddingInput) -> DataFrameResult {
        // Validate stream ID (must be non-zero for stream frames)
        if input.stream_id == 0 {
            return DataFrameResult::Invalid("DATA frame on stream 0".to_string());
        }

        // Check frame size limits
        if input.frame_payload_length as u32 > self.policy.max_frame_size {
            return DataFrameResult::Invalid(format!(
                "Frame size {} exceeds maximum {}",
                input.frame_payload_length, self.policy.max_frame_size
            ));
        }

        if !input.padded_flag {
            // No padding, frame is valid if it has payload space
            return if input.frame_payload_length > 0 {
                DataFrameResult::Valid("DATA frame without padding".to_string())
            } else {
                DataFrameResult::Valid("Empty DATA frame".to_string())
            };
        }

        // PADDED flag is set - validate padding per RFC 7540 §6.1
        let pad_length = input.pad_length as u16;
        let total_payload = input.frame_payload_length;

        // RFC 7540 §6.1: "The total number of padding octets is determined by the
        // value of the Pad Length field. If the length of the padding is the length
        // of the frame payload or greater, the recipient MUST treat this as a
        // connection error of type PROTOCOL_ERROR."

        // Pad length field itself takes 1 byte
        let pad_length_field_size = 1u16;
        if total_payload < pad_length_field_size {
            return DataFrameResult::ProtocolError(
                "PADDED DATA frame missing pad length field".to_string(),
            );
        }

        let available_for_padding = total_payload - pad_length_field_size;

        if pad_length > available_for_padding {
            return DataFrameResult::ProtocolError(format!(
                "Pad length {} exceeds available space {} (total payload {} - pad length field {})",
                pad_length, available_for_padding, total_payload, pad_length_field_size
            ));
        }

        // Calculate actual data length
        let data_length = total_payload - pad_length_field_size - pad_length;

        // Additional validation scenarios
        self.validate_padding_scenarios(input, data_length)
    }

    fn validate_padding_scenarios(
        &self,
        input: &DataPaddingInput,
        data_length: u16,
    ) -> DataFrameResult {
        let pad_length = input.pad_length as u16;
        let total_payload = input.frame_payload_length;

        // Scenario 1: Padding exceeds total payload
        if pad_length + 1 > total_payload {
            return DataFrameResult::ProtocolError(
                "Padding plus pad-length field exceeds total payload".to_string(),
            );
        }

        // Scenario 2: Valid all-padding DATA frame
        if data_length == 0 && pad_length > 0 {
            let stream_state = if input.end_stream_flag {
                "END_STREAM "
            } else {
                ""
            };
            return DataFrameResult::Valid(format!(
                "Valid {stream_state}DATA frame with padding only"
            ));
        }

        DataFrameResult::Valid(format!(
            "Valid DATA frame: {} bytes data, {} bytes padding",
            data_length, pad_length
        ))
    }
}

#[derive(Debug, PartialEq)]
enum DataFrameResult {
    /// Frame is valid per RFC 7540
    Valid(String),

    /// Frame violates RFC 7540 and should trigger PROTOCOL_ERROR
    ProtocolError(String),

    /// Frame is invalid but not necessarily a protocol error
    Invalid(String),
}

fuzz_target!(|input: DataPaddingInput| {
    // Ensure stream ID is valid (non-zero)
    if input.stream_id == 0 {
        return;
    }

    let processor = MockDataProcessor::new(input.policy.clone());
    let result = processor.process_data_frame(&input);

    // Test critical RFC 7540 §6.1 violation cases
    match result {
        DataFrameResult::ProtocolError(ref msg) => {
            // These should definitely be padding-overflow protocol errors.
            let pad_length = input.pad_length as u16;
            let total_payload = input.frame_payload_length;

            assert!(
                input.padded_flag && pad_length + 1 > total_payload,
                "ProtocolError must be reserved for true padding overflow; pad_length={pad_length}, total_payload={total_payload}, padded={}",
                input.padded_flag
            );
            assert!(
                msg.contains("exceeds") || msg.contains("missing pad length"),
                "Protocol error should mention padding overflow or missing pad-length field: {}",
                msg
            );
        }

        DataFrameResult::Valid(ref msg) => {
            // Verify that valid frames actually have proper padding
            if input.padded_flag {
                let pad_length = input.pad_length as u16;
                let available = input.frame_payload_length.saturating_sub(1);
                assert!(
                    pad_length <= available,
                    "Valid frame should not have padding overflow"
                );
                if pad_length > 0 && pad_length == available {
                    assert!(
                        msg.contains("padding only"),
                        "All-padding DATA frames should be classified explicitly: {}",
                        msg
                    );
                }
            }
        }

        DataFrameResult::Invalid(_) => {
            assert!(
                input.frame_payload_length as u32 > input.policy.max_frame_size,
                "Invalid DATA frame should only reflect configured frame-size policy"
            );
        }
    }

    // Additional consistency checks
    if input.padded_flag && input.pad_length == 255 {
        match result {
            DataFrameResult::ProtocolError(_) => {
                assert!(
                    input.frame_payload_length <= 255,
                    "Pad length 255 only overflows when payload length is 255 or smaller"
                );
            }
            DataFrameResult::Valid(_) => {
                assert!(
                    input.frame_payload_length >= 256,
                    "Maximum padding is valid at the exact all-padding boundary and above"
                );
            }
            DataFrameResult::Invalid(_) => {}
        }
    }
});
