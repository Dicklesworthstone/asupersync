//! Fuzz target for src/http/h2/connection.rs FrameCodec with arbitrary input bytes.
//!
//! This target specifically tests the FrameCodec::decode method against completely
//! arbitrary byte sequences to ensure:
//!
//! ## Assertions Tested
//! 1. **No panics on any input**: FrameCodec must never panic regardless of input
//! 2. **Protocol violations return errors**: Invalid frames should return proper errors
//! 3. **No state corruption**: Partial decode state should remain consistent
//! 4. **Buffer management safety**: BytesMut operations should be memory-safe
//! 5. **Frame size validation**: Oversized frames should be rejected
//!
//! ## Target Surface
//! - `FrameCodec::decode(&mut self, src: &mut BytesMut)` - main entry point
//! - `FrameHeader::parse()` - frame header parsing (9-byte boundary)
//! - `parse_frame()` - frame payload parsing and validation
//! - Partial header state management across decode calls
//!
//! ## Running
//! ```bash
//! cargo +nightly fuzz run h2_frame_codec_arbitrary_bytes
//! ```
//!
//! ## Security Focus
//! - Memory safety with arbitrary input sequences
//! - Stateful decoder corruption under malformed input
//! - Frame size limit enforcement to prevent DoS
//! - Proper error propagation without silent failures

#![no_main]

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h2::connection::FrameCodec;
use asupersync::http::h2::frame::{Frame, FrameHeader};
use asupersync::http::h2::{ErrorCode, H2Error};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// Maximum input size to prevent OOM fuzzing artifacts (64KB)
const MAX_FUZZ_INPUT_SIZE: usize = 65536;

/// Maximum number of decode iterations to prevent infinite loops
const MAX_DECODE_ITERATIONS: usize = 1000;

static FIXED_CANARIES: OnceLock<()> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    FIXED_CANARIES.get_or_init(assert_fixed_decode_canaries);

    // Limit input size to prevent timeouts and OOM
    if data.is_empty() || data.len() > MAX_FUZZ_INPUT_SIZE {
        return;
    }

    fuzz_frame_codec_decode(data);
});

/// Test FrameCodec::decode with arbitrary bytes and state consistency checks
fn fuzz_frame_codec_decode(data: &[u8]) {
    let mut codec = FrameCodec::new();

    // Test with different max frame size settings
    let max_frame_sizes = [16384, 32768, 65536, 1048576]; // 16KB, 32KB, 64KB, 1MB
    let max_frame_size = max_frame_sizes[data.len() % max_frame_sizes.len()];
    codec.set_max_frame_size(max_frame_size);

    // Create mutable buffer from input data
    let mut buffer = BytesMut::from(data);
    let original_len = buffer.len();

    // Track state for consistency checks
    let mut iteration_count = 0;
    let mut total_consumed = 0;
    let mut _frames_decoded = 0;

    // Decode loop - should never panic or infinite loop
    loop {
        // Prevent infinite loops in case of implementation bugs
        iteration_count += 1;
        if iteration_count > MAX_DECODE_ITERATIONS {
            break;
        }

        let buffer_len_before = buffer.len();

        // **CORE TEST**: FrameCodec::decode should never panic
        let decode_result = observe_decode(&mut codec, &mut buffer);

        let buffer_len_after = buffer.len();
        let bytes_consumed = buffer_len_before - buffer_len_after;
        total_consumed += bytes_consumed;

        match decode_result {
            Ok(Some(frame)) => {
                _frames_decoded += 1;

                // **ASSERTION 1**: Successful decode should consume bytes
                assert!(
                    bytes_consumed > 0,
                    "Successful frame decode must consume bytes: consumed={}, frame={:?}",
                    bytes_consumed,
                    frame_summary(&frame)
                );

                // **ASSERTION 2**: Unknown frames should be handled gracefully
                if let Frame::Unknown {
                    frame_type,
                    stream_id,
                    payload: _,
                } = &frame
                {
                    assert!(
                        *frame_type > 9, // Known frame types are 0-9
                        "Unknown frame type {} should be > 9 for proper handling",
                        frame_type
                    );
                    assert!(
                        *stream_id & 0x80000000 == 0,
                        "Stream ID reserved bit should be cleared: stream_id=0x{:08X}",
                        stream_id
                    );
                }

                // Continue decoding if more bytes available
                if buffer.is_empty() {
                    break;
                }
            }
            Ok(None) => {
                // Partial payloads consume their header into codec state, and complete
                // extension frames are ignored by the codec. Both are legal `Ok(None)`
                // outcomes as long as the buffer only shrinks.
                // No complete frame available - exit loop
                break;
            }
            Err(error) => {
                // **ASSERTION 4**: Protocol violations should return proper errors, not panic
                // Error is expected for invalid input - just ensure it's a proper error
                assert!(
                    !error.to_string().is_empty(),
                    "Error must have non-empty description: {:?}",
                    error
                );

                // Error during decode - exit loop
                break;
            }
        }
    }

    // **ASSERTION 5**: Total consumed bytes should not exceed input size
    assert!(
        total_consumed <= original_len,
        "Total consumed {} should not exceed input size {}",
        total_consumed,
        original_len
    );

    // **ASSERTION 6**: Decoder state consistency
    // After any sequence of operations, the decoder should remain in a valid state
    // We test this by attempting one more decode operation
    let mut dummy_buffer = BytesMut::new();
    assert!(matches!(
        observe_decode(&mut codec, &mut dummy_buffer),
        Ok(None)
    ));
    assert!(dummy_buffer.is_empty());
}

fn observe_decode(codec: &mut FrameCodec, buffer: &mut BytesMut) -> Result<Option<Frame>, H2Error> {
    let before_len = buffer.len();
    let result = codec.decode(buffer);
    assert!(
        buffer.len() <= before_len,
        "FrameCodec::decode grew the input buffer"
    );

    match &result {
        Ok(Some(frame)) => {
            assert!(
                buffer.len() < before_len,
                "successful H2 frame decode must consume bytes: frame={:?}",
                frame_summary(frame)
            );
            assert_frame_contract(frame);
        }
        Ok(None) => {}
        Err(error) => {
            assert!(
                !error.to_string().is_empty(),
                "H2 decode error must have a non-empty description: {error:?}"
            );
        }
    }

    result
}

fn assert_frame_contract(frame: &Frame) {
    match frame {
        Frame::Data(frame) => {
            assert_ne!(frame.stream_id, 0, "DATA frame decoded with stream ID 0");
        }
        Frame::Headers(frame) => {
            assert_ne!(frame.stream_id, 0, "HEADERS frame decoded with stream ID 0");
        }
        Frame::Priority(frame) => {
            assert_ne!(
                frame.stream_id, 0,
                "PRIORITY frame decoded with stream ID 0"
            );
        }
        Frame::RstStream(frame) => {
            assert_ne!(
                frame.stream_id, 0,
                "RST_STREAM frame decoded with stream ID 0"
            );
        }
        Frame::Settings(frame) => {
            assert!(
                !frame.ack || frame.settings.is_empty(),
                "SETTINGS ACK decoded with non-empty settings"
            );
        }
        Frame::PushPromise(frame) => {
            assert_ne!(
                frame.stream_id, 0,
                "PUSH_PROMISE frame decoded with stream ID 0"
            );
            assert_ne!(
                frame.promised_stream_id, 0,
                "PUSH_PROMISE decoded with promised stream ID 0"
            );
        }
        Frame::Ping(frame) => {
            assert_eq!(
                frame.opaque_data.len(),
                8,
                "PING frame opaque data must stay exactly 8 bytes"
            );
        }
        Frame::GoAway(frame) => {
            assert_eq!(
                frame.last_stream_id & 0x8000_0000,
                0,
                "GOAWAY last stream ID reserved bit should be cleared"
            );
        }
        Frame::WindowUpdate(frame) => {
            assert_ne!(
                frame.increment, 0,
                "WINDOW_UPDATE frame decoded with zero increment"
            );
        }
        Frame::Continuation(frame) => {
            assert_ne!(
                frame.stream_id, 0,
                "CONTINUATION frame decoded with stream ID 0"
            );
        }
        Frame::Unknown {
            frame_type,
            stream_id,
            ..
        } => {
            assert!(
                *frame_type > 9,
                "unknown H2 frame type should be an extension type: {frame_type}"
            );
            assert_eq!(
                stream_id & 0x8000_0000,
                0,
                "unknown frame stream ID reserved bit should be cleared"
            );
        }
    }
}

fn assert_fixed_decode_canaries() {
    let mut empty = BytesMut::new();
    let mut codec = FrameCodec::new();
    assert!(matches!(observe_decode(&mut codec, &mut empty), Ok(None)));
    assert!(empty.is_empty());

    let mut incomplete_header = BytesMut::from(&b"\0\0"[..]);
    let mut codec = FrameCodec::new();
    assert!(matches!(
        observe_decode(&mut codec, &mut incomplete_header),
        Ok(None)
    ));
    assert_eq!(incomplete_header.as_ref(), b"\0\0");

    let mut data_frame = frame_bytes(5, 0, 0x1, 1, b"hello");
    let mut codec = FrameCodec::new();
    let frame = observe_decode(&mut codec, &mut data_frame)
        .expect("DATA frame canary should decode")
        .expect("DATA frame canary should produce a frame");
    match &frame {
        Frame::Data(frame) => {
            assert_eq!(frame.stream_id, 1);
            assert!(frame.end_stream);
            assert_eq!(frame.data.as_ref(), b"hello");
        }
        other => panic!("expected DATA frame, got {}", frame_summary(other)),
    }
    assert!(data_frame.is_empty());

    let mut partial_payload = frame_bytes(5, 0, 0, 1, b"he");
    let mut codec = FrameCodec::new();
    assert!(matches!(
        observe_decode(&mut codec, &mut partial_payload),
        Ok(None)
    ));
    assert_eq!(partial_payload.as_ref(), b"he");
    partial_payload.extend_from_slice(b"llo");
    let frame = observe_decode(&mut codec, &mut partial_payload)
        .expect("completed partial DATA frame should decode")
        .expect("completed partial DATA frame should produce a frame");
    match &frame {
        Frame::Data(frame) => {
            assert_eq!(frame.stream_id, 1);
            assert_eq!(frame.data.as_ref(), b"hello");
        }
        other => panic!(
            "expected completed DATA frame, got {}",
            frame_summary(other)
        ),
    }
    assert!(partial_payload.is_empty());

    let mut unknown = frame_bytes(3, 0x0a, 0xff, 42, b"abc");
    let mut codec = FrameCodec::new();
    assert!(matches!(observe_decode(&mut codec, &mut unknown), Ok(None)));
    assert!(
        unknown.is_empty(),
        "complete extension frames should be consumed and ignored"
    );

    assert_complete_frame_decode_error(
        frame_bytes(1, 0x04, 0x01, 0, b"\0"),
        ErrorCode::FrameSizeError,
        "SETTINGS ACK with non-zero length",
    );
    assert_complete_frame_decode_error(
        frame_bytes(7, 0x06, 0, 0, b"1234567"),
        ErrorCode::FrameSizeError,
        "PING frame must be 8 bytes",
    );

    let mut oversized = frame_bytes(17, 0, 0, 1, &[]);
    let mut codec = FrameCodec::new();
    codec.set_max_frame_size(16);
    assert_frame_decode_error(
        &mut codec,
        &mut oversized,
        ErrorCode::FrameSizeError,
        "frame too large: 17 > 16",
    );
    assert!(
        oversized.is_empty(),
        "oversized-frame rejection should consume the parsed header"
    );
}

fn assert_complete_frame_decode_error(
    mut bytes: BytesMut,
    expected_code: ErrorCode,
    expected_message: &str,
) {
    let mut codec = FrameCodec::new();
    assert_frame_decode_error(&mut codec, &mut bytes, expected_code, expected_message);
    assert!(
        bytes.is_empty(),
        "complete malformed H2 frame should be consumed before parser error"
    );
}

fn assert_frame_decode_error(
    codec: &mut FrameCodec,
    bytes: &mut BytesMut,
    expected_code: ErrorCode,
    expected_message: &str,
) {
    let error = observe_decode(codec, bytes)
        .expect_err("malformed H2 frame should fail at decode boundary");
    assert_eq!(error.code, expected_code);
    assert_eq!(error.message.as_str(), expected_message);
    assert!(
        error.stream_id.is_none(),
        "codec boundary canary should be a connection error: {error:?}"
    );
    assert!(
        error.is_connection_error(),
        "codec boundary canary should classify as connection-level: {error:?}"
    );
    assert_eq!(
        error.to_string(),
        format!("HTTP/2 connection error ({expected_code}): {expected_message}"),
        "codec boundary canary returned unexpected display text"
    );
}

fn frame_bytes(length: u32, frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> BytesMut {
    let header = FrameHeader {
        length,
        frame_type,
        flags,
        stream_id,
    };
    let mut bytes = BytesMut::new();
    header.write(&mut bytes);
    bytes.extend_from_slice(payload);
    bytes
}

/// Create a brief frame summary for debugging without exposing large payloads
fn frame_summary(frame: &Frame) -> String {
    match frame {
        Frame::Data(f) => format!("DATA(stream={}, len={})", f.stream_id, f.data.len()),
        Frame::Headers(f) => format!(
            "HEADERS(stream={}, len={})",
            f.stream_id,
            f.header_block.len()
        ),
        Frame::Priority(f) => format!("PRIORITY(stream={})", f.stream_id),
        Frame::RstStream(f) => format!(
            "RST_STREAM(stream={}, code={:?})",
            f.stream_id, f.error_code
        ),
        Frame::Settings(f) => format!("SETTINGS(ack={}, settings={})", f.ack, f.settings.len()),
        Frame::PushPromise(f) => format!(
            "PUSH_PROMISE(stream={}, promised={})",
            f.stream_id, f.promised_stream_id
        ),
        Frame::Ping(f) => format!(
            "PING(ack={}, data={:02x}{:02x}..)",
            f.ack, f.opaque_data[0], f.opaque_data[1]
        ),
        Frame::GoAway(f) => format!("GOAWAY(last={}, code={:?})", f.last_stream_id, f.error_code),
        Frame::WindowUpdate(f) => {
            format!("WINDOW_UPDATE(stream={}, inc={})", f.stream_id, f.increment)
        }
        Frame::Continuation(f) => format!(
            "CONTINUATION(stream={}, end={})",
            f.stream_id, f.end_headers
        ),
        Frame::Unknown {
            frame_type,
            stream_id,
            payload,
        } => {
            format!(
                "UNKNOWN(type={}, stream={}, len={})",
                frame_type,
                stream_id,
                payload.len()
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input() {
        // Empty input should not panic
        fuzz_frame_codec_decode(&[]);
    }

    #[test]
    fn test_short_input() {
        // Less than frame header size should not panic
        fuzz_frame_codec_decode(&[1, 2, 3, 4]);
    }

    #[test]
    fn test_frame_header_boundary() {
        // Exactly frame header size (9 bytes) should not panic
        fuzz_frame_codec_decode(&[0, 0, 8, 0, 0, 0, 0, 0, 1, 72, 69, 76, 76, 79, 33, 33, 33]);
    }

    #[test]
    fn test_oversized_frame_length() {
        // Frame with very large declared length should be rejected properly
        let mut large_frame = vec![];
        large_frame.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // 24-bit length = 16MB-1
        large_frame.extend_from_slice(&[0, 0, 0, 0, 0, 1]); // Type=0, flags=0, stream=1
        large_frame.extend_from_slice(&vec![0x41; 100]); // Some payload

        fuzz_frame_codec_decode(&large_frame);
    }
}
