#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::http::h2::error::{ErrorCode, H2Error};
use asupersync::http::h2::frame::{
    ContinuationFrame, DataFrame, Frame, GoAwayFrame, PingFrame, RstStreamFrame, SettingsFrame,
    WindowUpdateFrame,
};
use asupersync::http::h2::{Connection, Settings};

const ORPHANED_CONTINUATION_ERROR: &str =
    "CONTINUATION without preceding HEADERS/PUSH_PROMISE (RFC 9113 §6.10)";

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
    std::hint::black_box(test_seq.suffix_frames.len());
});

/// Core test: CONTINUATION frame without preceding HEADERS should trigger PROTOCOL_ERROR
fn test_orphaned_continuation_protocol_error(test_seq: &ContinuationTestSequence) {
    let mut connection = open_test_connection();

    // Send prefix frames (none of which are HEADERS)
    for prefix_frame in &test_seq.prefix_frames {
        match create_frame_from_fuzz(prefix_frame) {
            Ok(frame) => {
                observe_prefix_process(
                    connection.process_frame(frame),
                    "orphaned-continuation prefix",
                );
            }
            Err(error) => {
                observe_process_error(error, "orphaned-continuation prefix construction");
            }
        }
    }

    // Now send the orphaned CONTINUATION frame
    let continuation_frame = create_continuation_frame(&test_seq.continuation_frame);

    expect_orphaned_continuation_error(
        connection.process_frame(continuation_frame),
        "orphaned CONTINUATION",
    );
}

/// Test CONTINUATION frames in various positions within a frame sequence
fn test_continuation_in_various_positions(test_seq: &ContinuationTestSequence) {
    let positions = [0, 1, 2, 3]; // Test different insertion positions

    for &pos in &positions {
        if pos > test_seq.prefix_frames.len() {
            continue;
        }

        let mut connection = open_test_connection();

        // Send frames up to position
        for (i, prefix_frame) in test_seq.prefix_frames.iter().enumerate() {
            if i >= pos {
                break;
            }
            match create_frame_from_fuzz(prefix_frame) {
                Ok(frame) => {
                    observe_prefix_process(
                        connection.process_frame(frame),
                        "positioned-continuation prefix",
                    );
                }
                Err(error) => {
                    observe_process_error(error, "positioned-continuation prefix construction");
                }
            }
        }

        // Insert CONTINUATION at this position
        let continuation_frame = create_continuation_frame(&test_seq.continuation_frame);

        expect_orphaned_continuation_error(
            connection.process_frame(continuation_frame),
            "positioned orphaned CONTINUATION",
        );
    }
}

fn open_test_connection() -> Connection {
    let mut connection = Connection::server(Settings::default());
    let settings_result = connection.process_frame(Frame::Settings(SettingsFrame::new(Vec::new())));
    match settings_result {
        Ok(received) => {
            assert!(
                received.is_none(),
                "initial SETTINGS should not surface inbound data"
            );
        }
        Err(error) => {
            panic!("initial SETTINGS must be accepted: {error:?}");
        }
    }
    connection
}

fn observe_prefix_process(
    result: Result<Option<asupersync::http::h2::connection::ReceivedFrame>, H2Error>,
    context: &str,
) {
    match result {
        Ok(received) => {
            std::hint::black_box(received.is_some());
            std::hint::black_box(context);
        }
        Err(error) => {
            observe_process_error(error, context);
        }
    }
}

fn observe_process_error(error: H2Error, context: &str) {
    assert!(
        !error.message.trim().is_empty(),
        "{context} rejection should expose a diagnostic"
    );
    assert!(
        error.message.len() <= 2048,
        "{context} rejection diagnostic should stay bounded: {} bytes",
        error.message.len()
    );
    std::hint::black_box((context, error.code, error.stream_id, error.message));
}

fn expect_orphaned_continuation_error(
    result: Result<Option<asupersync::http::h2::connection::ReceivedFrame>, H2Error>,
    context: &str,
) {
    match result {
        Ok(received) => {
            panic!("{context} should not be accepted, got {received:?}");
        }
        Err(error) => {
            assert_eq!(
                error.code,
                ErrorCode::ProtocolError,
                "{context} should return PROTOCOL_ERROR"
            );
            assert_eq!(
                error.stream_id, None,
                "{context} should be a connection-level error"
            );
            assert_eq!(
                error.message, ORPHANED_CONTINUATION_ERROR,
                "{context} diagnostic should match the live RFC 9113 orphaned-CONTINUATION error"
            );
            std::hint::black_box(error.message);
        }
    }
}

/// Create a frame from fuzz input
fn create_frame_from_fuzz(fuzz_frame: &FuzzFrame) -> Result<Frame, H2Error> {
    let stream_id = normalize_stream_id(fuzz_frame.stream_id);
    let payload_size = (fuzz_frame.payload_size as usize).min(16384); // Cap at max frame size
    let payload = vec![0u8; payload_size];

    match fuzz_frame.frame_type {
        FrameTypeChoice::Data => Ok(Frame::Data(DataFrame::new(
            stream_id,
            payload.into(),
            fuzz_frame.flags & 0x01 != 0, // END_STREAM flag
        ))),
        FrameTypeChoice::Settings => Ok(Frame::Settings(if fuzz_frame.flags & 0x01 != 0 {
            SettingsFrame::ack()
        } else {
            SettingsFrame::new(Vec::new())
        })),
        FrameTypeChoice::Ping => {
            let ping_data = [0u8; 8]; // Standard ping payload
            Ok(Frame::Ping(if fuzz_frame.flags & 0x01 != 0 {
                PingFrame::ack(ping_data)
            } else {
                PingFrame::new(ping_data)
            }))
        }
        FrameTypeChoice::GoAway => Ok(Frame::GoAway(GoAwayFrame::new(
            0, // Last stream ID
            ErrorCode::NoError,
        ))),
        FrameTypeChoice::WindowUpdate => Ok(Frame::WindowUpdate(WindowUpdateFrame::new(
            stream_id, 1, // Window size increment (must be > 0)
        ))),
        FrameTypeChoice::RstStream => {
            if stream_id == 0 {
                // RST_STREAM cannot be on stream 0
                return Err(H2Error::protocol("RST_STREAM on stream 0"));
            }
            Ok(Frame::RstStream(RstStreamFrame::new(
                stream_id,
                ErrorCode::Cancel,
            )))
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

    Frame::Continuation(ContinuationFrame {
        stream_id,
        header_block: payload.into(),
        end_headers,
    })
}

/// Normalize stream ID to valid range (1-2^31-1, odd for client)
fn normalize_stream_id(stream_id: u32) -> u32 {
    let normalized = stream_id & 0x7FFFFFFF; // Clear reserved bit
    if normalized == 0 {
        1 // Default to stream 1
    } else if normalized.is_multiple_of(2) {
        normalized + 1 // Make odd (client-initiated)
    } else {
        normalized
    }
}
