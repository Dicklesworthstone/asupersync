#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::http::h2::error::{ErrorCode, H2Error};
use asupersync::http::h2::frame::{DataFrame, FrameHeader, FrameType, data_flags};
use libfuzzer_sys::fuzz_target;

/// HTTP/2 DATA frame padding validation fuzz target.
///
/// Tests the live `DataFrame::parse` implementation for RFC 9113 §6.1
/// compliance where PADDED DATA frame pad-length exceeds available payload
/// space. The one-byte pad-length field may leave zero DATA bytes when all
/// remaining octets are padding.
///
/// Critical test case: pad-length=255 with frame-payload-length=256 is the
/// maximum wire-legal all-padding DATA frame, not a padding overflow.
const DATA_STREAM_ZERO_MESSAGE: &str = "DATA frame with stream ID 0";
const PADDED_DATA_MISSING_PAD_LENGTH_MESSAGE: &str = "PADDED DATA frame with no padding length";
const DATA_PADDING_OVERFLOW_MESSAGE: &str = "DATA frame padding exceeds data length";

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

    /// Deterministic payload fill byte for non-padding DATA bytes.
    payload_seed: u8,
}

impl DataPaddingInput {
    #[must_use]
    fn stream_id(&self) -> u32 {
        self.stream_id & 0x7fff_ffff
    }

    #[must_use]
    fn flags(&self) -> u8 {
        let mut flags = 0;
        if self.padded_flag {
            flags |= data_flags::PADDED;
        }
        if self.end_stream_flag {
            flags |= data_flags::END_STREAM;
        }
        flags
    }

    #[must_use]
    fn payload(&self) -> Vec<u8> {
        let payload_len = usize::from(self.frame_payload_length);
        let mut payload = Vec::with_capacity(payload_len);

        for index in 0..payload_len {
            let offset = u8::try_from(index % 256).expect("index modulo 256 fits in u8");
            payload.push(self.payload_seed.wrapping_add(offset));
        }

        if self.padded_flag && !payload.is_empty() {
            payload[0] = self.pad_length;
        }

        payload
    }
}

fn assert_protocol_error(error: &H2Error, expected_message: &str) {
    assert_eq!(
        error.code,
        ErrorCode::ProtocolError,
        "DATA padding oracle expected PROTOCOL_ERROR for {expected_message:?}, got {error:?}"
    );
    assert_eq!(
        error.message, expected_message,
        "DATA padding oracle message drift"
    );
    assert!(
        error.is_connection_error(),
        "DATA frame parser protocol errors should be connection-level: {error:?}"
    );
}

fuzz_target!(|input: DataPaddingInput| {
    let stream_id = input.stream_id();
    let payload = input.payload();
    let header = FrameHeader {
        length: u32::try_from(payload.len()).expect("fuzz payload length fits in u32"),
        frame_type: FrameType::Data as u8,
        flags: input.flags(),
        stream_id,
    };

    let result = DataFrame::parse(&header, Bytes::copy_from_slice(&payload));

    if stream_id == 0 {
        let error = result.expect_err("DATA frame with stream ID 0 should be rejected");
        assert_protocol_error(&error, DATA_STREAM_ZERO_MESSAGE);
        return;
    }

    if !input.padded_flag {
        let frame = result.expect("unpadded DATA frame on a non-zero stream should parse");
        assert_eq!(frame.stream_id, stream_id);
        assert_eq!(frame.end_stream, input.end_stream_flag);
        assert_eq!(
            frame.data.len(),
            payload.len(),
            "unpadded DATA frame should expose the full payload"
        );
        assert_eq!(
            frame.data.as_ref(),
            payload.as_slice(),
            "unpadded DATA frame payload changed during parse"
        );
        return;
    }

    if payload.is_empty() {
        let error = result.expect_err("PADDED DATA frame without pad-length byte should fail");
        assert_protocol_error(&error, PADDED_DATA_MISSING_PAD_LENGTH_MESSAGE);
        return;
    }

    let pad_length = usize::from(payload[0]);
    let available_after_pad_length = payload.len() - 1;

    if pad_length > available_after_pad_length {
        let error = result.expect_err("DATA frame with padding overflow should fail");
        assert_protocol_error(&error, DATA_PADDING_OVERFLOW_MESSAGE);
        return;
    }

    let frame = result.expect("DATA frame with valid padding should parse");
    let data_end = payload.len() - pad_length;
    let expected_data = &payload[1..data_end];

    assert_eq!(frame.stream_id, stream_id);
    assert_eq!(frame.end_stream, input.end_stream_flag);
    assert_eq!(
        frame.data.as_ref(),
        expected_data,
        "padded DATA frame should strip pad-length byte and padding tail"
    );

    if pad_length == available_after_pad_length {
        assert!(
            frame.data.is_empty(),
            "all-padding DATA frame should expose zero application bytes"
        );
    }
});
