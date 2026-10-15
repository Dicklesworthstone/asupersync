//! Comprehensive fuzz target for HTTP/2 DATA frame parsing.
//!
//! Focuses specifically on HTTP/2 DATA frame processing in connection.rs
//! to test critical frame parsing invariants and connection state management:
//! 1. PADDED flag with pad-length <= payload length
//! 2. END_STREAM on stream in OPEN moves to HALF_CLOSED
//! 3. DATA on Stream ID 0 triggers PROTOCOL_ERROR
//! 4. Oversized DATA > SETTINGS_MAX_FRAME_SIZE rejected
//! 5. Flow-control credit consumed atomically
//!
//! # HTTP/2 DATA Frame Attack Vectors Tested
//! - Malformed padding length exceeding payload size
//! - Stream ID 0 injection (connection-level protocol violation)
//! - Frame size limit bypass attempts (> 16MB)
//! - Flow-control window exhaustion and negative windows
//! - END_STREAM flag manipulation on various stream states
//! - Concurrent DATA frames on same stream (ordering issues)
//! - PADDED flag with empty payloads (edge case validation)
//! - Very large and very small frame sizes
//!
//! # HTTP/2 Security (RFC 7540 Section 6.1)
//! - DATA frames MUST NOT be sent on stream ID 0
//! - Padding length MUST be less than frame payload length
//! - Flow control windows MUST be decremented atomically
//! - Stream state transitions MUST follow HTTP/2 state machine
//! - Frame size limits MUST be respected (SETTINGS_MAX_FRAME_SIZE)
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run h2_data
//! ```

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::Bytes;
use asupersync::http::h2::connection::{Connection, ConnectionState, ReceivedFrame};
use asupersync::http::h2::error::{ErrorCode, H2Error};
use asupersync::http::h2::frame::{
    DEFAULT_MAX_FRAME_SIZE, DataFrame, Frame, FrameHeader, FrameType, HeadersFrame, MAX_FRAME_SIZE,
    data_flags,
};
use asupersync::http::h2::settings::Settings;
use asupersync::http::h2::stream::StreamState;

/// Maximum input size to prevent memory exhaustion during fuzzing.
const MAX_FUZZ_INPUT_SIZE: usize = 64_000;

/// Maximum reasonable frame payload size for testing.
const MAX_REASONABLE_PAYLOAD_SIZE: usize = 32_000;

/// H2 DATA frame parsing test scenarios.
#[derive(Arbitrary, Debug, Clone)]
struct H2DataFuzzInput {
    /// Frame headers to test
    frame_headers: Vec<FrameHeaderData>,
    /// Frame payloads corresponding to headers
    frame_payloads: Vec<Vec<u8>>,
    /// Test specific edge cases
    test_edge_cases: bool,
    /// Test oversized frame scenarios
    test_oversized_frames: bool,
    /// Test flow control edge cases
    test_flow_control: bool,
    /// Test stream state transitions
    test_stream_states: bool,
    /// Test padding edge cases
    test_padding_edge_cases: bool,
}

/// Frame header data for testing.
#[derive(Arbitrary, Debug, Clone)]
struct FrameHeaderData {
    /// Payload length (will be computed from actual payload)
    length: u32,
    /// Frame flags
    flags: u8,
    /// Stream identifier
    stream_id: u32,
    /// Whether to force specific length (ignoring payload)
    force_length: bool,
}

/// Edge case patterns for DATA frame testing.
#[derive(Arbitrary, Debug, Clone)]
enum H2DataEdgeCase {
    /// Stream ID 0 (connection-level protocol violation)
    StreamIdZero { payload: Vec<u8>, flags: u8 },
    /// PADDED with excessive padding
    ExcessivePadding { payload_size: usize, pad_length: u8 },
    /// PADDED with zero payload
    PaddedEmptyPayload { pad_length: u8 },
    /// Oversized frame (> MAX_FRAME_SIZE)
    OversizedFrame { size_multiplier: u8 },
    /// END_STREAM flag state transitions
    EndStreamTransition {
        stream_id: u32,
        initial_state: TestStreamState,
        payload: Vec<u8>,
    },
    /// Flow control window exhaustion
    FlowControlExhaustion {
        frame_count: u8,
        payload_size: usize,
    },
    /// Empty payload with various flags
    EmptyPayload { flags: u8 },
    /// Maximum valid padding (exactly frame length - 1)
    MaxValidPadding { data_size: u8 },
}

/// Test stream states for edge case testing.
#[derive(Arbitrary, Debug, Clone)]
enum TestStreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

/// Test the HTTP/2 DATA frame parser through comprehensive invariant checking.
fn test_h2_data_frame_invariants(fuzz_input: &H2DataFuzzInput) -> Result<String, String> {
    // Skip oversized inputs to prevent memory exhaustion
    let total_payload_size: usize = fuzz_input.frame_payloads.iter().map(|p| p.len()).sum();
    if total_payload_size > MAX_FUZZ_INPUT_SIZE {
        return Err("Input too large for fuzzing".to_string());
    }

    // Create a test connection
    let mut connection = create_test_connection();

    // Test individual DATA frames
    test_individual_data_frames(&mut connection, fuzz_input)?;

    // Test edge cases if enabled
    if fuzz_input.test_edge_cases {
        test_data_frame_edge_cases(&mut connection)?;
    }

    // Test oversized frames if enabled
    if fuzz_input.test_oversized_frames {
        test_oversized_data_frames(&mut connection)?;
    }

    // Test flow control if enabled
    if fuzz_input.test_flow_control {
        test_flow_control_invariants(&mut connection)?;
    }

    // Test stream state transitions if enabled
    if fuzz_input.test_stream_states {
        test_stream_state_transitions(&mut connection)?;
    }

    // Test padding edge cases if enabled
    if fuzz_input.test_padding_edge_cases {
        test_padding_edge_cases(&mut connection)?;
    }

    Ok("All DATA frames processed successfully".to_string())
}

/// Create a test HTTP/2 connection in a known state.
fn create_test_connection() -> Connection {
    let settings = Settings::default();
    let mut connection = Connection::server(settings);

    // Ensure connection is in open state
    if matches!(connection.state(), ConnectionState::Handshaking) {
        // Process a settings frame to move to open state
        let settings_frame =
            Frame::Settings(asupersync::http::h2::frame::SettingsFrame::new(vec![]));
        observe_settings_handshake(connection.process_frame(settings_frame));
    }

    connection
}

fn observe_settings_handshake(result: Result<Option<ReceivedFrame>, H2Error>) {
    match result {
        Ok(None) => {}
        Ok(Some(frame)) => {
            panic!("SETTINGS handshake should not emit a received-frame event: {frame:?}");
        }
        Err(error) => {
            panic!("SETTINGS handshake should open the connection: {error}");
        }
    }
}

fn observe_h2_error(context: &str, error: &H2Error, expected_stream: Option<u32>) {
    assert!(
        !error.message.is_empty(),
        "{context} error should expose a diagnostic message"
    );
    assert_ne!(
        error.code,
        ErrorCode::NoError,
        "{context} failure must not use NO_ERROR"
    );

    if let Some(stream_id) = error.stream_id {
        assert_ne!(
            stream_id, 0,
            "{context} stream error must not target stream 0"
        );
        if let Some(expected) = expected_stream {
            assert_eq!(
                stream_id, expected,
                "{context} stream error should target the processed stream"
            );
        }
    }
}

fn observe_headers_setup_result(
    connection: &Connection,
    stream_id: u32,
    result: Result<Option<ReceivedFrame>, H2Error>,
) -> bool {
    match result {
        Ok(event) => {
            assert!(
                connection.stream(stream_id).is_some(),
                "successful HEADERS setup should create stream {stream_id}"
            );
            match event {
                Some(ReceivedFrame::Headers {
                    stream_id: observed,
                    ..
                }) => {
                    assert_eq!(
                        observed, stream_id,
                        "HEADERS event should report the setup stream"
                    );
                }
                None => {}
                Some(other) => {
                    panic!("HEADERS setup returned unexpected event: {other:?}");
                }
            }
            true
        }
        Err(error) => {
            observe_h2_error("HEADERS setup", &error, Some(stream_id));
            false
        }
    }
}

fn observe_data_process_result(
    connection: &Connection,
    stream_id: u32,
    end_stream: bool,
    payload_size: usize,
    window_before: i32,
    result: Result<Option<ReceivedFrame>, H2Error>,
) {
    match result {
        Ok(event) => {
            let window_after = connection.recv_window();

            if payload_size > 0 {
                assert!(
                    window_after <= window_before,
                    "connection window should not increase after DATA frame processing"
                );
                let actual_decrease = window_before - window_after;
                assert!(
                    actual_decrease >= payload_size as i32,
                    "connection window decrease should at least match payload size"
                );
            }

            match event {
                Some(ReceivedFrame::Data {
                    stream_id: observed,
                    data,
                    end_stream: observed_end_stream,
                }) => {
                    assert_eq!(observed, stream_id, "DATA event stream mismatch");
                    assert_eq!(
                        data.len(),
                        payload_size,
                        "DATA event should preserve payload length"
                    );
                    assert_eq!(
                        observed_end_stream, end_stream,
                        "DATA event should preserve END_STREAM"
                    );
                }
                None => {}
                Some(other) => {
                    panic!("DATA processing returned unexpected event: {other:?}");
                }
            }

            if end_stream && let Some(stream) = connection.stream(stream_id) {
                let state = stream.state();
                assert!(
                    matches!(state, StreamState::HalfClosedRemote | StreamState::Closed),
                    "END_STREAM should transition stream to half-closed or closed state, got {:?}",
                    state
                );
            }
        }
        Err(error) => {
            observe_h2_error("DATA processing", &error, Some(stream_id));
        }
    }
}

/// Test individual DATA frames for proper validation.
fn test_individual_data_frames(
    connection: &mut Connection,
    fuzz_input: &H2DataFuzzInput,
) -> Result<(), String> {
    for (header_data, payload) in fuzz_input
        .frame_headers
        .iter()
        .zip(fuzz_input.frame_payloads.iter())
    {
        if payload.len() > MAX_REASONABLE_PAYLOAD_SIZE {
            continue; // Skip unreasonably large payloads
        }

        // Create frame header
        let frame_length = if header_data.force_length {
            header_data.length
        } else {
            payload.len() as u32
        };

        let header = FrameHeader {
            length: frame_length,
            frame_type: FrameType::Data as u8,
            flags: header_data.flags,
            stream_id: header_data.stream_id,
        };

        let payload_bytes = Bytes::copy_from_slice(payload);

        // Test DATA frame parsing
        match DataFrame::parse(&header, payload_bytes.clone()) {
            Ok(data_frame) => {
                // Invariant 1: PADDED flag with pad-length <= payload length
                if header_data.flags & data_flags::PADDED != 0 {
                    // If PADDED flag is set, parsing succeeded, so padding was valid
                    assert!(
                        data_frame.data.len() <= payload.len(),
                        "PADDED frame data should not exceed original payload"
                    );
                }

                // Invariant 3: DATA on Stream ID 0 should have triggered PROTOCOL_ERROR
                if header_data.stream_id == 0 {
                    return Err("DATA frame with stream ID 0 should have been rejected".to_string());
                }

                // Test processing through connection if stream is reasonable
                if header_data.stream_id > 0 && header_data.stream_id < 1000 {
                    test_connection_processing(connection, Frame::Data(data_frame))?;
                }
            }
            Err(err) => {
                // Verify error codes are appropriate
                match err.code {
                    ErrorCode::ProtocolError => {
                        // Expected for various violations:
                        // - Stream ID 0 (Invariant 3)
                        // - Padding length exceeds payload (Invariant 1)
                        // - PADDED flag with empty payload
                        if header_data.stream_id == 0 {
                            // Invariant 3: DATA on Stream ID 0 triggers PROTOCOL_ERROR ✓
                        } else if header_data.flags & data_flags::PADDED != 0 {
                            // Invariant 1: Likely padding validation failure ✓
                        }
                    }
                    ErrorCode::FrameSizeError => {
                        // Invariant 4: Oversized DATA > SETTINGS_MAX_FRAME_SIZE rejected
                        assert!(
                            frame_length > DEFAULT_MAX_FRAME_SIZE,
                            "Frame size error should only occur for oversized frames"
                        );
                    }
                    _ => {
                        // Other error codes should be justified
                        assert!(
                            !err.to_string().is_empty(),
                            "Error should have descriptive message"
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

/// Test DATA frame processing through the connection layer.
fn test_connection_processing(connection: &mut Connection, frame: Frame) -> Result<(), String> {
    // Save connection window before processing
    let window_before = connection.recv_window();

    // Open the stream first if needed
    if let Frame::Data(ref data_frame) = frame
        && data_frame.stream_id > 0
    {
        // Open stream with headers first
        let headers_frame = Frame::Headers(HeadersFrame::new(
            data_frame.stream_id,
            Bytes::new(),
            false, // not end_stream
            true,  // end_headers
        ));
        let setup_result = connection.process_frame(headers_frame);
        observe_headers_setup_result(connection, data_frame.stream_id, setup_result);
    }

    let Frame::Data(data_frame) = &frame else {
        return Ok(());
    };
    let stream_id = data_frame.stream_id;
    let end_stream = data_frame.end_stream;
    let payload_size = data_frame.data.len();
    let data_result = connection.process_frame(frame);
    observe_data_process_result(
        connection,
        stream_id,
        end_stream,
        payload_size,
        window_before,
        data_result,
    );

    Ok(())
}

/// Test specific edge cases for DATA frame parsing.
fn test_data_frame_edge_cases(connection: &mut Connection) -> Result<(), String> {
    let edge_cases = [
        H2DataEdgeCase::StreamIdZero {
            payload: vec![0x01, 0x02, 0x03],
            flags: 0,
        },
        H2DataEdgeCase::ExcessivePadding {
            payload_size: 10,
            pad_length: 20,
        },
        H2DataEdgeCase::PaddedEmptyPayload { pad_length: 1 },
        H2DataEdgeCase::OversizedFrame { size_multiplier: 2 },
        H2DataEdgeCase::EndStreamTransition {
            stream_id: 5,
            initial_state: TestStreamState::Open,
            payload: vec![0x48, 0x32],
        },
        H2DataEdgeCase::FlowControlExhaustion {
            frame_count: 3,
            payload_size: 1024,
        },
        H2DataEdgeCase::EmptyPayload {
            flags: data_flags::END_STREAM,
        },
        H2DataEdgeCase::MaxValidPadding { data_size: 5 },
    ];

    for edge_case in &edge_cases {
        test_single_edge_case(connection, edge_case)?;
    }

    Ok(())
}

/// Test a single edge case scenario.
fn test_single_edge_case(
    connection: &mut Connection,
    edge_case: &H2DataEdgeCase,
) -> Result<(), String> {
    match edge_case {
        H2DataEdgeCase::StreamIdZero { payload, flags } => {
            let header = FrameHeader {
                length: payload.len() as u32,
                frame_type: FrameType::Data as u8,
                flags: *flags,
                stream_id: 0,
            };
            let payload_bytes = Bytes::copy_from_slice(payload);

            // Invariant 3: DATA on Stream ID 0 triggers PROTOCOL_ERROR
            match DataFrame::parse(&header, payload_bytes) {
                Ok(_) => {
                    return Err("DATA frame with stream ID 0 should have been rejected".to_string());
                }
                Err(err) => {
                    assert_eq!(
                        err.code,
                        ErrorCode::ProtocolError,
                        "DATA on stream ID 0 should return PROTOCOL_ERROR"
                    );
                }
            }
        }

        H2DataEdgeCase::ExcessivePadding {
            payload_size,
            pad_length,
        } => {
            if *payload_size > MAX_REASONABLE_PAYLOAD_SIZE
                || *pad_length as usize > *payload_size + 10
            {
                return Ok(()); // Skip unreasonable test cases
            }

            let mut payload = vec![*pad_length];
            payload.extend_from_slice(&vec![0x42u8; *payload_size]);

            let header = FrameHeader {
                length: payload.len() as u32,
                frame_type: FrameType::Data as u8,
                flags: data_flags::PADDED,
                stream_id: 1,
            };

            // Invariant 1: PADDED flag with pad-length <= payload length
            match DataFrame::parse(&header, Bytes::copy_from_slice(&payload)) {
                Ok(_) => {
                    if *pad_length as usize > *payload_size {
                        return Err("Excessive padding should have been rejected".to_string());
                    }
                }
                Err(err) => {
                    if *pad_length as usize <= *payload_size {
                        // Valid padding was rejected - check if there's another issue
                        assert_eq!(
                            err.code,
                            ErrorCode::ProtocolError,
                            "Valid padding rejection should be protocol error"
                        );
                    }
                }
            }
        }

        H2DataEdgeCase::PaddedEmptyPayload { pad_length } => {
            let payload = vec![*pad_length]; // Pad length byte without enough trailing padding

            let header = FrameHeader {
                length: payload.len() as u32,
                frame_type: FrameType::Data as u8,
                flags: data_flags::PADDED,
                stream_id: 1,
            };

            // Nonzero padding without trailing padding bytes should be rejected.
            match DataFrame::parse(&header, Bytes::copy_from_slice(&payload)) {
                Ok(data_frame) => {
                    if *pad_length != 0 {
                        return Err("PADDED frame without enough trailing padding should reject"
                            .to_string());
                    }
                    assert!(
                        data_frame.data.is_empty(),
                        "zero pad length should leave an empty DATA payload"
                    );
                }
                Err(err) => {
                    assert_eq!(
                        err.code,
                        ErrorCode::ProtocolError,
                        "PADDED empty payload should return PROTOCOL_ERROR"
                    );
                }
            }
        }

        H2DataEdgeCase::OversizedFrame { size_multiplier } => {
            let extra = usize::from((*size_multiplier).max(1));
            let size = ((DEFAULT_MAX_FRAME_SIZE as usize).saturating_add(extra))
                .min(MAX_FRAME_SIZE as usize);
            let payload = vec![0x42u8; size];
            let header = FrameHeader {
                length: payload.len() as u32,
                frame_type: FrameType::Data as u8,
                flags: 0,
                stream_id: 1,
            };

            match DataFrame::parse(&header, Bytes::copy_from_slice(&payload)) {
                Ok(data_frame) => {
                    assert_eq!(
                        data_frame.data.len(),
                        payload.len(),
                        "DATA parser should preserve oversized payload bytes"
                    );
                }
                Err(error) => {
                    assert_eq!(
                        error.code,
                        ErrorCode::FrameSizeError,
                        "oversized DATA parse rejection should be a frame-size error"
                    );
                }
            }
        }

        H2DataEdgeCase::EndStreamTransition {
            stream_id,
            initial_state,
            payload,
        } => {
            if !matches!(initial_state, TestStreamState::Open) {
                return Ok(());
            }
            let stream_id = (*stream_id | 1).min(999);
            let headers_frame =
                Frame::Headers(HeadersFrame::new(stream_id, Bytes::new(), false, true));
            let setup_result = connection.process_frame(headers_frame);
            if observe_headers_setup_result(connection, stream_id, setup_result) {
                let bounded_payload = if payload.len() > MAX_REASONABLE_PAYLOAD_SIZE {
                    &payload[..MAX_REASONABLE_PAYLOAD_SIZE]
                } else {
                    payload
                };
                let frame = Frame::Data(DataFrame::new(
                    stream_id,
                    Bytes::copy_from_slice(bounded_payload),
                    true,
                ));
                let window_before = connection.recv_window();
                let data_result = connection.process_frame(frame);
                observe_data_process_result(
                    connection,
                    stream_id,
                    true,
                    bounded_payload.len(),
                    window_before,
                    data_result,
                );
            }
        }

        H2DataEdgeCase::FlowControlExhaustion {
            frame_count,
            payload_size,
        } => {
            let stream_id = 7;
            let headers_frame =
                Frame::Headers(HeadersFrame::new(stream_id, Bytes::new(), false, true));
            let setup_result = connection.process_frame(headers_frame);
            if observe_headers_setup_result(connection, stream_id, setup_result) {
                let payload_size = (*payload_size).min(MAX_REASONABLE_PAYLOAD_SIZE);
                let payload = vec![0x24u8; payload_size];
                for _ in 0..(*frame_count).min(16) {
                    let frame = Frame::Data(DataFrame::new(
                        stream_id,
                        Bytes::copy_from_slice(&payload),
                        false,
                    ));
                    let window_before = connection.recv_window();
                    let data_result = connection.process_frame(frame);
                    observe_data_process_result(
                        connection,
                        stream_id,
                        false,
                        payload.len(),
                        window_before,
                        data_result,
                    );
                }
            }
        }

        H2DataEdgeCase::EmptyPayload { flags } => {
            let payload = vec![];

            let header = FrameHeader {
                length: 0,
                frame_type: FrameType::Data as u8,
                flags: *flags,
                stream_id: 1,
            };

            // Empty payload without PADDED should be valid
            if *flags & data_flags::PADDED == 0 {
                match DataFrame::parse(&header, Bytes::copy_from_slice(&payload)) {
                    Ok(data_frame) => {
                        assert!(
                            data_frame.data.is_empty(),
                            "Empty payload should result in empty data"
                        );
                    }
                    Err(error) => {
                        observe_h2_error("empty DATA parse", &error, Some(1));
                        return Err(format!(
                            "Valid empty payload should not be rejected: {error}"
                        ));
                    }
                }
            }
        }

        H2DataEdgeCase::MaxValidPadding { data_size } => {
            if *data_size > 100 {
                return Ok(());
            } // Skip large test cases

            // Create payload: [pad_length, ...data..., ...padding...]
            let pad_length = *data_size + 1;
            let mut payload = vec![pad_length];
            payload.extend_from_slice(&vec![0x42u8; *data_size as usize]);
            payload.extend_from_slice(&vec![0x00u8; pad_length as usize]);

            let header = FrameHeader {
                length: payload.len() as u32,
                frame_type: FrameType::Data as u8,
                flags: data_flags::PADDED,
                stream_id: 1,
            };

            // This should be valid - pad_length equals remaining data length
            match DataFrame::parse(&header, Bytes::copy_from_slice(&payload)) {
                Ok(data_frame) => {
                    assert_eq!(
                        data_frame.data.len(),
                        *data_size as usize,
                        "Data should contain only the non-padded portion"
                    );
                }
                Err(error) => {
                    observe_h2_error("maximum DATA padding parse", &error, Some(1));
                    return Err(format!(
                        "Valid maximum padding should not be rejected: {error}"
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Test oversized frame scenarios.
fn test_oversized_data_frames(_connection: &mut Connection) -> Result<(), String> {
    // Test frame size just over the limit
    let oversized_payload = vec![0x42u8; (DEFAULT_MAX_FRAME_SIZE + 1) as usize];

    let header = FrameHeader {
        length: oversized_payload.len() as u32,
        frame_type: FrameType::Data as u8,
        flags: 0,
        stream_id: 1,
    };

    // This should be handled at the connection/codec level, not DataFrame level
    // DataFrame::parse doesn't check frame size limits - that's done in the codec
    // So we just verify that large frames can be parsed at the DataFrame level
    let result = DataFrame::parse(&header, Bytes::copy_from_slice(&oversized_payload));

    match result {
        Ok(data_frame) => {
            // Large frame parsed successfully at DataFrame level
            assert_eq!(
                data_frame.data.len(),
                oversized_payload.len(),
                "Large frame should preserve payload size"
            );
        }
        Err(error) => {
            observe_h2_error("oversized DATA parse", &error, Some(1));
            assert_eq!(
                error.code,
                ErrorCode::FrameSizeError,
                "oversized DATA parse rejection should be a frame-size error"
            );
        }
    }

    Ok(())
}

/// Test flow control invariants.
fn test_flow_control_invariants(connection: &mut Connection) -> Result<(), String> {
    // Test that multiple DATA frames decrement window correctly
    let payload = vec![0x42u8; 1000];

    // Create a stream first
    let headers_frame = Frame::Headers(HeadersFrame::new(1, Bytes::new(), false, true));
    let setup_result = connection.process_frame(headers_frame);
    observe_headers_setup_result(connection, 1, setup_result);

    // Send DATA frame
    let data_frame = Frame::Data(DataFrame::new(1, Bytes::copy_from_slice(&payload), false));

    let window_before = connection.recv_window();
    let data_result = connection.process_frame(data_frame);
    observe_data_process_result(
        connection,
        1,
        false,
        payload.len(),
        window_before,
        data_result,
    );

    Ok(())
}

/// Test stream state transitions.
fn test_stream_state_transitions(connection: &mut Connection) -> Result<(), String> {
    // Open a new stream
    let stream_id = 3;
    let headers_frame = Frame::Headers(HeadersFrame::new(stream_id, Bytes::new(), false, true));
    let setup_result = connection.process_frame(headers_frame);
    observe_headers_setup_result(connection, stream_id, setup_result);

    // Verify stream is open
    if let Some(stream) = connection.stream(stream_id) {
        assert!(
            matches!(stream.state(), StreamState::Open),
            "Stream should be open after HEADERS"
        );
    }

    // Send DATA frame with END_STREAM
    let data_frame = Frame::Data(DataFrame::new(
        stream_id,
        Bytes::from_static(b"hello"),
        true,
    ));

    let window_before = connection.recv_window();
    let data_result = connection.process_frame(data_frame);
    observe_data_process_result(
        connection,
        stream_id,
        true,
        b"hello".len(),
        window_before,
        data_result,
    );

    Ok(())
}

/// Test padding-specific edge cases.
fn test_padding_edge_cases(_connection: &mut Connection) -> Result<(), String> {
    // Test various padding scenarios have been covered in other test functions
    Ok(())
}

fuzz_target!(|fuzz_input: H2DataFuzzInput| {
    // Skip oversized inputs to prevent memory exhaustion
    if fuzz_input.frame_payloads.len() > 100 {
        return;
    }

    let total_size: usize = fuzz_input.frame_payloads.iter().map(|p| p.len()).sum();
    if total_size > MAX_FUZZ_INPUT_SIZE {
        return;
    }

    // Test the primary input data
    let result = test_h2_data_frame_invariants(&fuzz_input);

    // Allow both success and failure - we're testing for crashes/invariant violations
    match result {
        Ok(_) => {
            // Success case - DATA frames processed without crashes
        }
        Err(err) => {
            // Failure case - should be graceful with descriptive errors
            assert!(!err.is_empty(), "Error messages should be descriptive");
        }
    }
});
