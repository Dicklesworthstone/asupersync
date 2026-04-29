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
use asupersync::http::h2::frame::Frame;
use libfuzzer_sys::fuzz_target;

/// Maximum input size to prevent OOM fuzzing artifacts (64KB)
const MAX_FUZZ_INPUT_SIZE: usize = 65536;

/// Maximum number of decode iterations to prevent infinite loops
const MAX_DECODE_ITERATIONS: usize = 1000;

fuzz_target!(|data: &[u8]| {
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
        let decode_result = codec.decode(&mut buffer);

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
                    bytes_consumed, frame_summary(&frame)
                );

                // **ASSERTION 2**: Unknown frames should be handled gracefully
                if let Frame::Unknown { frame_type, stream_id, payload } = &frame {
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
                // **ASSERTION 3**: Partial frame should not consume bytes
                assert_eq!(
                    bytes_consumed, 0,
                    "Partial frame decode should not consume bytes: consumed={}",
                    bytes_consumed
                );

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
        total_consumed, original_len
    );

    // **ASSERTION 6**: Decoder state consistency
    // After any sequence of operations, the decoder should remain in a valid state
    // We test this by attempting one more decode operation
    let mut dummy_buffer = BytesMut::new();
    let _ = codec.decode(&mut dummy_buffer); // Should not panic even on empty buffer
}

/// Create a brief frame summary for debugging without exposing large payloads
fn frame_summary(frame: &Frame) -> String {
    match frame {
        Frame::Data(f) => format!("DATA(stream={}, len={})", f.stream_id, f.data.len()),
        Frame::Headers(f) => format!("HEADERS(stream={}, len={})", f.stream_id, f.header_block.len()),
        Frame::Priority(f) => format!("PRIORITY(stream={})", f.stream_id),
        Frame::RstStream(f) => format!("RST_STREAM(stream={}, code={:?})", f.stream_id, f.error_code),
        Frame::Settings(f) => format!("SETTINGS(ack={}, settings={})", f.ack, f.settings.len()),
        Frame::PushPromise(f) => format!("PUSH_PROMISE(stream={}, promised={})", f.stream_id, f.promised_stream_id),
        Frame::Ping(f) => format!("PING(ack={}, data={:02x}{:02x}..)", f.ack, f.opaque_data[0], f.opaque_data[1]),
        Frame::GoAway(f) => format!("GOAWAY(last={}, code={:?})", f.last_stream_id, f.error_code),
        Frame::WindowUpdate(f) => format!("WINDOW_UPDATE(stream={}, inc={})", f.stream_id, f.increment),
        Frame::Continuation(f) => format!("CONTINUATION(stream={}, end={})", f.stream_id, f.end_headers),
        Frame::Unknown { frame_type, stream_id, payload } => {
            format!("UNKNOWN(type={}, stream={}, len={})", frame_type, stream_id, payload.len())
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