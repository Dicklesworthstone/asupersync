#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::BytesMut;
use asupersync::codec::Encoder;
use asupersync::http::h2::error::{ErrorCode, H2Error};
use asupersync::http::h2::frame::{ContinuationFrame, DataFrame, Frame, SettingsFrame};

/// HTTP/2 frame sequence for testing CONTINUATION-without-HEADERS scenarios
#[derive(Debug, Clone, Arbitrary)]
struct ContinuationTestSequence {
    /// Frames to send before the stray CONTINUATION
    prefix_frames: Vec<FuzzFrame>,
    /// The problematic CONTINUATION frame
    continuation_frame: ContinuationFrameData,
    /// Additional frames to send after
    suffix_frames: Vec<FuzzFrame>,
}

/// Simplified frame representation for fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct FuzzFrame {
    frame_type: FrameTypeChoice,
    flags: u8,
    stream_id: u32,
    payload_size: u16, // Bounded payload size
}

/// Frame types to fuzz with (excluding CONTINUATION to avoid accidental valid sequences)
#[derive(Debug, Clone, Arbitrary)]
enum FrameTypeChoice {
    Data,
    Settings,
    Ping,
    GoAway,
    WindowUpdate,
    RstStream,
    // Notably NOT including Headers or PushPromise to ensure CONTINUATION is truly orphaned
}

/// CONTINUATION frame data for testing
#[derive(Debug, Clone, Arbitrary)]
struct ContinuationFrameData {
    flags: u8,
    stream_id: u32,
    end_headers: bool,
    payload: Vec<u8>,
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input size
    if data.len() > 100_000 {
        return;
    }

    let mut u = Unstructured::new(data);

    // Generate test sequence
    let test_seq = match ContinuationTestSequence::arbitrary(&mut u) {
        Ok(seq) => seq,
        Err(_) => return,
    };

    // Test the core scenario: CONTINUATION without HEADERS should cause PROTOCOL_ERROR
    test_orphaned_continuation_protocol_error(&test_seq);

    // Test variations to ensure robustness
    test_continuation_in_various_positions(&test_seq);
});

/// Core test: CONTINUATION frame without preceding HEADERS should trigger PROTOCOL_ERROR
fn test_orphaned_continuation_protocol_error(test_seq: &ContinuationTestSequence) {
    let mut codec = FrameCodec::new();
    let mut buffer = BytesMut::new();

    // Send prefix frames (none of which are HEADERS)
    for prefix_frame in &test_seq.prefix_frames {
        if let Ok(frame) = create_frame_from_fuzz(prefix_frame) {
            observe_prefix_encode(
                codec.encode(frame, &mut buffer),
                "orphaned-continuation prefix",
            );
        }
    }

    // Now send the orphaned CONTINUATION frame
    let continuation_frame = create_continuation_frame(&test_seq.continuation_frame);

    // This should fail with PROTOCOL_ERROR
    match codec.encode(continuation_frame, &mut buffer) {
        Err(error) => {
            // Verify it's the correct error type
            match error.downcast_ref::<H2Error>() {
                Some(h2_err) => {
                    assert_eq!(
                        h2_err.code(),
                        ErrorCode::ProtocolError,
                        "CONTINUATION without HEADERS should return PROTOCOL_ERROR, got: {:?}",
                        h2_err.code()
                    );
                }
                None => {
                    // Other errors are acceptable if they indicate protocol violation
                    let error_str = format!("{:?}", error);
                    assert!(
                        error_str.contains("protocol")
                            || error_str.contains("CONTINUATION")
                            || error_str.contains("invalid"),
                        "Expected protocol error for orphaned CONTINUATION, got: {}",
                        error_str
                    );
                }
            }
        }
        Ok(_) => {
            panic!(
                "Orphaned CONTINUATION frame should not be accepted - this is a protocol violation!"
            );
        }
    }
}

/// Test CONTINUATION frames in various positions within a frame sequence
fn test_continuation_in_various_positions(test_seq: &ContinuationTestSequence) {
    let positions = [0, 1, 2, 3]; // Test different insertion positions

    for &pos in &positions {
        if pos > test_seq.prefix_frames.len() {
            continue;
        }

        let mut codec = FrameCodec::new();
        let mut buffer = BytesMut::new();

        // Send frames up to position
        for (i, prefix_frame) in test_seq.prefix_frames.iter().enumerate() {
            if i >= pos {
                break;
            }
            if let Ok(frame) = create_frame_from_fuzz(prefix_frame) {
                observe_prefix_encode(
                    codec.encode(frame, &mut buffer),
                    "positioned-continuation prefix",
                );
            }
        }

        // Insert CONTINUATION at this position
        let continuation_frame = create_continuation_frame(&test_seq.continuation_frame);

        let result = codec.encode(continuation_frame, &mut buffer);

        // Should always fail for orphaned CONTINUATION regardless of position
        match result {
            Err(_) => {
                // Expected: CONTINUATION without HEADERS should be rejected
            }
            Ok(_) => {
                // This would be a protocol violation
                panic!(
                    "CONTINUATION frame accepted at position {} without preceding HEADERS",
                    pos
                );
            }
        }
    }
}

fn observe_prefix_encode(result: Result<(), H2Error>, context: &str) {
    match result {
        Ok(()) => {
            std::hint::black_box(context);
        }
        Err(error) => {
            let message = error.to_string();
            assert!(
                !message.trim().is_empty(),
                "{context} rejection should expose a diagnostic"
            );
            assert!(
                message.len() <= 2048,
                "{context} rejection diagnostic should stay bounded: {} bytes",
                message.len()
            );
            std::hint::black_box((context, message));
        }
    }
}

/// Create a frame from fuzz input
fn create_frame_from_fuzz(fuzz_frame: &FuzzFrame) -> Result<Frame, Box<dyn std::error::Error>> {
    let stream_id = normalize_stream_id(fuzz_frame.stream_id);
    let payload_size = (fuzz_frame.payload_size as usize).min(16384); // Cap at max frame size
    let payload = vec![0u8; payload_size];

    match fuzz_frame.frame_type {
        FrameTypeChoice::Data => {
            Ok(Frame::Data(DataFrame::new(
                stream_id,
                payload.into(),
                fuzz_frame.flags & 0x01 != 0, // END_STREAM flag
                fuzz_frame.flags & 0x08 != 0, // PADDED flag
            )?))
        }
        FrameTypeChoice::Settings => {
            Ok(Frame::Settings(SettingsFrame::new(
                Vec::new(),                   // Empty settings for simplicity
                fuzz_frame.flags & 0x01 != 0, // ACK flag
            )?))
        }
        FrameTypeChoice::Ping => {
            let ping_data = [0u8; 8]; // Standard ping payload
            Ok(Frame::Ping(asupersync::http::h2::frame::PingFrame::new(
                ping_data,
                fuzz_frame.flags & 0x01 != 0, // ACK flag
            )?))
        }
        FrameTypeChoice::GoAway => {
            Ok(Frame::GoAway(
                asupersync::http::h2::frame::GoAwayFrame::new(
                    0, // Last stream ID
                    ErrorCode::NoError,
                    payload.into(),
                )?,
            ))
        }
        FrameTypeChoice::WindowUpdate => {
            Ok(Frame::WindowUpdate(
                asupersync::http::h2::frame::WindowUpdateFrame::new(
                    stream_id, 1, // Window size increment (must be > 0)
                )?,
            ))
        }
        FrameTypeChoice::RstStream => {
            if stream_id == 0 {
                // RST_STREAM cannot be on stream 0
                return Err("RST_STREAM on stream 0".into());
            }
            Ok(Frame::RstStream(
                asupersync::http::h2::frame::RstStreamFrame::new(stream_id, ErrorCode::Cancel)?,
            ))
        }
    }
}

/// Create a CONTINUATION frame from fuzz data
fn create_continuation_frame(cont_data: &ContinuationFrameData) -> Frame {
    let stream_id = normalize_stream_id(cont_data.stream_id);
    let end_headers = cont_data.end_headers || (cont_data.flags & 0x04 != 0);

    // Ensure payload is not too large
    let payload = if cont_data.payload.len() > 16384 {
        cont_data.payload[..16384].to_vec()
    } else {
        cont_data.payload.clone()
    };

    Frame::Continuation(
        ContinuationFrame::new(stream_id, payload.into(), end_headers)
            .expect("Failed to create CONTINUATION frame"),
    )
}

/// Normalize stream ID to valid range (1-2^31-1, odd for client)
fn normalize_stream_id(stream_id: u32) -> u32 {
    let normalized = stream_id & 0x7FFFFFFF; // Clear reserved bit
    if normalized == 0 {
        1 // Default to stream 1
    } else if normalized % 2 == 0 {
        normalized + 1 // Make odd (client-initiated)
    } else {
        normalized
    }
}
