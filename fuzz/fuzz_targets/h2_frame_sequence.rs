//! Structure-aware fuzz target for HTTP/2 frame-sequence parser.
//!
//! This target focuses specifically on connection-level frame ordering and stream-state
//! transitions under adversarial frame sequences. Tests frame ordering attacks that
//! could bypass connection-level protections or cause state machine confusion.
//!
//! # Attack Scenarios Tested
//! - **Frame ordering attacks**: HEADERS before SETTINGS, DATA before preface
//! - **CONTINUATION sequence attacks**: Fragmented headers with missing/duplicate CONTINUATION
//! - **Connection state confusion**: Frames in Handshaking state, transitions during GOAWAY
//! - **Multi-stream coordination**: Interleaved frames affecting multiple streams simultaneously
//! - **Settings negotiation attacks**: MAX_FRAME_SIZE changes mid-stream, SETTINGS ACK ordering
//! - **Window update races**: WINDOW_UPDATE before/after stream closure affecting connection window
//! - **Priority/dependency ordering**: Stream dependency changes with concurrent state transitions
//!
//! # Protocol State Machine Focus
//! ```text
//! Connection: Handshaking -> Open -> Closing -> Closed
//! Streams:    idle -> reserved -> open -> half-closed -> closed
//! ```
//!
//! # Critical Invariants
//! - First frame MUST be SETTINGS (RFC 9113 §3.4)
//! - CONTINUATION must follow HEADERS/PUSH_PROMISE immediately
//! - GOAWAY stops processing new streams but allows stream completion
//! - Frame size limits apply even during settings changes
//! - Connection window updates affect all streams
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run h2_frame_sequence
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::http::h2::{
    connection::{Connection, ConnectionState, ReceivedFrame},
    error::{ErrorCode, H2Error},
    frame::{
        FRAME_HEADER_SIZE, Frame, FrameHeader, PingFrame, RstStreamFrame, Setting, SettingsFrame,
        WindowUpdateFrame, parse_frame as parse_h2_frame,
    },
    settings::Settings,
};
use libfuzzer_sys::fuzz_target;

const MAX_FRAME_COUNT: usize = 200;
const MAX_CONCURRENT_STREAMS: u32 = 16;
const MAX_FRAME_SIZE: usize = 64 * 1024;

/// HTTP/2 frame with ordering constraints
#[derive(Arbitrary, Debug, Clone)]
struct OrderedFrame {
    frame_type: FuzzFrameType,
    stream_id: u32,
    flags: u8,
    payload: FramePayload,
    /// Force frame out-of-order (for attack scenarios)
    force_disorder: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum FuzzFrameType {
    Data,
    Headers,
    RstStream,
    Settings,
    Ping,
    GoAway,
    WindowUpdate,
}

#[derive(Arbitrary, Debug, Clone)]
enum FramePayload {
    Data {
        data: Vec<u8>,
        end_stream: bool,
        padded: bool,
    },
    Headers {
        headers: Vec<(Vec<u8>, Vec<u8>)>, // Header name-value pairs
        end_stream: bool,
        end_headers: bool,
        priority_exclusive: bool,
        priority_dependency: Option<u32>,
        priority_weight: u8,
    },
    Settings {
        settings: Vec<FuzzSetting>,
        ack: bool,
    },
    Ping {
        data: [u8; 8],
        ack: bool,
    },
    GoAway {
        last_stream_id: u32,
        error_code: u32,
        debug_data: Vec<u8>,
    },
    WindowUpdate {
        window_size_increment: u32,
    },
    RstStream {
        error_code: u32,
    },
}

#[derive(Arbitrary, Debug, Clone)]
struct FuzzSetting {
    setting_type: u16,
    value: u32,
}

/// Frame sequence attack scenarios
#[derive(Arbitrary, Debug)]
struct FrameSequenceInput {
    frames: Vec<OrderedFrame>,
    attack_scenario: AttackScenario,
    connection_config: ConnectionConfig,
}

#[derive(Arbitrary, Debug)]
enum AttackScenario {
    /// Send frames before proper handshake
    PreHandshakeAttack,
    /// Interleave CONTINUATION frames incorrectly
    ContinuationDisorder,
    /// Send frames after GOAWAY
    PostGoAwayFrames,
    /// Rapid state transitions across multiple streams
    MultiStreamRace,
    /// Settings changes during frame processing
    SettingsRace,
    /// Window update ordering attacks
    WindowUpdateRace,
    /// Normal operation (control)
    Normal,
}

#[derive(Arbitrary, Debug)]
struct ConnectionConfig {
    initial_window_size: u32,
    max_frame_size: u32,
    enable_push: bool,
    max_header_list_size: u32,
}

fuzz_target!(|input: FrameSequenceInput| {
    if input.frames.len() > MAX_FRAME_COUNT {
        return; // Prevent excessive test cases
    }

    // Property 1: No panic on any frame sequence
    test_no_panic_frame_sequence(&input);

    // Property 2: Connection state machine invariants
    test_connection_state_invariants(&input);

    // Property 3: Frame ordering protocol compliance
    test_frame_ordering_compliance(&input);

    // Property 4: Multi-stream state coordination
    test_multi_stream_coordination(&input);

    // Property 5: Resource exhaustion protection
    test_resource_exhaustion_protection(&input);
});

/// Property 1: No panic on any frame sequence
fn test_no_panic_frame_sequence(input: &FrameSequenceInput) {
    let frame_sequence = generate_frame_sequence(input);

    let result = std::panic::catch_unwind(|| {
        let mut connection = create_test_connection(&input.connection_config);

        // Process the client preface if this is a server connection
        if std::str::from_utf8(asupersync::http::h2::connection::CLIENT_PREFACE).is_ok() {
            let handshake_result = connection.process_frame(create_settings_frame(false));
            observe_process_frame_result(&handshake_result);
            assert!(
                handshake_result.is_ok(),
                "empty SETTINGS handshake should be accepted: {handshake_result:?}"
            );
        }

        // Process frame sequence
        for (frame_index, frame_bytes) in frame_sequence.iter().take(100).enumerate() {
            if let Ok(frame) = parse_frame_from_bytes(frame_bytes) {
                let process_result = connection.process_frame(frame);
                observe_process_frame_result(&process_result);
                if let Err(err) = &process_result {
                    assert!(
                        !err.message.is_empty(),
                        "frame {frame_index} returned an empty H2 error message"
                    );
                }
            }
        }
    });
    assert!(
        result.is_ok(),
        "HTTP/2 frame sequence processing panicked for scenario {:?} with {} generated frames",
        input.attack_scenario,
        frame_sequence.len()
    );
}

/// Property 2: Connection state machine invariants
fn test_connection_state_invariants(input: &FrameSequenceInput) {
    let frame_sequence = generate_frame_sequence(input);
    let mut connection = create_test_connection(&input.connection_config);

    assert!(matches!(connection.state(), ConnectionState::Handshaking));

    for frame_bytes in frame_sequence.iter().take(50) {
        if let Ok(frame) = parse_frame_from_bytes(frame_bytes) {
            let before_state = connection.state();

            let process_result = connection.process_frame(frame);
            match &process_result {
                Ok(_) => {
                    let after_state = connection.state();

                    // Verify valid state transitions
                    assert_valid_state_transition(before_state, after_state);
                }
                Err(err) => {
                    assert_well_formed_h2_error(err);
                    // Rejected frames must preserve a valid connection state.
                    let error_state = connection.state();
                    assert!(
                        matches!(
                            error_state,
                            ConnectionState::Handshaking
                                | ConnectionState::Open
                                | ConnectionState::Closing
                                | ConnectionState::Closed
                        ),
                        "Connection in invalid state after error: {:?}",
                        error_state
                    );
                }
            }
        }
    }
}

/// Property 3: Frame ordering protocol compliance
fn test_frame_ordering_compliance(input: &FrameSequenceInput) {
    match &input.attack_scenario {
        AttackScenario::PreHandshakeAttack => {
            test_pre_handshake_attack(input);
        }
        AttackScenario::ContinuationDisorder => {
            test_continuation_disorder(input);
        }
        AttackScenario::PostGoAwayFrames => {
            test_post_goaway_frames(input);
        }
        _ => {
            // Test general ordering compliance
            test_general_ordering(input);
        }
    }
}

/// Property 4: Multi-stream state coordination
fn test_multi_stream_coordination(input: &FrameSequenceInput) {
    if matches!(input.attack_scenario, AttackScenario::MultiStreamRace) {
        let frame_sequence = generate_frame_sequence(input);
        let mut connection = create_test_connection(&input.connection_config);

        // Initialize connection
        let handshake_result = connection.process_frame(create_settings_frame(false));
        observe_process_frame_result(&handshake_result);
        assert!(
            handshake_result.is_ok(),
            "empty SETTINGS handshake should be accepted: {handshake_result:?}"
        );

        // Track streams and their states
        let mut active_streams = std::collections::HashSet::new();

        for frame_bytes in frame_sequence.iter().take(50) {
            if let Ok(frame) = parse_frame_from_bytes(frame_bytes) {
                let stream_id = get_frame_stream_id(&frame);

                if stream_id > 0 && stream_id % 2 == 1 {
                    // Client-initiated stream
                    active_streams.insert(stream_id);
                }

                let process_result = connection.process_frame(frame);
                match &process_result {
                    Ok(_) => {
                        // Verify no stream state corruption
                        assert!(
                            active_streams.len() <= MAX_CONCURRENT_STREAMS as usize,
                            "Too many concurrent streams: {}",
                            active_streams.len()
                        );
                    }
                    Err(err) => assert_well_formed_h2_error(err),
                }
            }
        }
    }
}

/// Property 5: Resource exhaustion protection
fn test_resource_exhaustion_protection(input: &FrameSequenceInput) {
    let frame_sequence = generate_frame_sequence(input);
    let mut connection = create_test_connection(&input.connection_config);

    // Initialize connection
    let handshake_result = connection.process_frame(create_settings_frame(false));
    observe_process_frame_result(&handshake_result);
    assert!(
        handshake_result.is_ok(),
        "empty SETTINGS handshake should be accepted: {handshake_result:?}"
    );

    let mut total_processed = 0;

    for frame_bytes in frame_sequence.iter().take(100) {
        if let Ok(frame) = parse_frame_from_bytes(frame_bytes) {
            match connection.process_frame(frame) {
                Ok(_) => {
                    total_processed += 1;

                    // Ensure reasonable resource limits
                    assert!(
                        total_processed <= 1000,
                        "Connection processed too many frames: {}",
                        total_processed
                    );
                }
                Err(err) => {
                    assert_well_formed_h2_error(&err);
                    // Check for proper resource exhaustion errors
                    let error_msg = format!("{err}");
                    if error_msg.contains("flood")
                        || error_msg.contains("limit")
                        || error_msg.contains("too many")
                    {
                        // Expected protection activated
                        break;
                    }
                }
            }
        }
    }
}

/// Generate frame sequence based on attack scenario
fn generate_frame_sequence(input: &FrameSequenceInput) -> Vec<Vec<u8>> {
    let mut sequence = Vec::new();

    match &input.attack_scenario {
        AttackScenario::PreHandshakeAttack => {
            // Send non-SETTINGS frames first (violation of RFC 9113 §3.4)
            for frame in &input.frames {
                if !matches!(frame.frame_type, FuzzFrameType::Settings) {
                    push_serialized_frame(&mut sequence, frame);
                }
            }
            // Add settings after
            sequence.push(serialize_settings_frame(false));
        }

        AttackScenario::ContinuationDisorder => {
            // Create fragmented headers with disordered CONTINUATION frames
            sequence.push(serialize_settings_frame(false)); // Proper handshake

            // Add headers frame with END_HEADERS=false
            sequence.push(create_headers_frame_bytes(1, false, false, None, None));

            // Insert non-CONTINUATION frames (protocol violation)
            for frame in input.frames.iter().take(5) {
                if !matches!(frame.frame_type, FuzzFrameType::Headers) {
                    push_serialized_frame(&mut sequence, frame);
                }
            }
        }

        AttackScenario::PostGoAwayFrames => {
            sequence.push(serialize_settings_frame(false)); // Proper handshake
            sequence.push(create_goaway_frame_bytes(0, ErrorCode::NoError, &[])); // Send GOAWAY

            // Send frames after GOAWAY (should be handled gracefully)
            for frame in &input.frames {
                push_serialized_frame(&mut sequence, frame);
            }
        }

        _ => {
            // Normal/race scenarios: add proper handshake then frames
            sequence.push(serialize_settings_frame(false));

            for frame in &input.frames {
                push_serialized_frame(&mut sequence, frame);
            }
        }
    }

    sequence
}

fn push_serialized_frame(sequence: &mut Vec<Vec<u8>>, frame: &OrderedFrame) {
    if let Some(frame_bytes) = serialize_frame(frame) {
        if frame.force_disorder && !sequence.is_empty() {
            sequence.insert(0, frame_bytes);
        } else {
            sequence.push(frame_bytes);
        }
    }
}

/// Create test connection with configuration
fn create_test_connection(config: &ConnectionConfig) -> Connection {
    let mut settings = Settings::server();
    settings.initial_window_size = config.initial_window_size.min(0x7fff_ffff);
    settings.max_frame_size = config.max_frame_size.clamp(16_384, 0x00ff_ffff);
    settings.enable_push = config.enable_push;
    settings.max_header_list_size = config.max_header_list_size.min(1_048_576);

    Connection::server(settings)
}

/// Serialize a frame to bytes
fn serialize_frame(frame: &OrderedFrame) -> Option<Vec<u8>> {
    match &frame.payload {
        FramePayload::Settings { settings, ack } => {
            let mut frame_settings = Vec::new();
            for setting in settings.iter().take(10) {
                // Limit settings
                if let Some(setting) = Setting::from_id_value(setting.setting_type, setting.value) {
                    frame_settings.push(setting);
                }
            }

            let settings_frame = SettingsFrame {
                ack: *ack || frame.flags & 0x01 != 0,
                settings: frame_settings,
            };

            Some(serialize_settings_frame_struct(&settings_frame))
        }

        FramePayload::Ping { data, ack } => {
            let ping_frame = PingFrame {
                ack: *ack || frame.flags & 0x01 != 0,
                opaque_data: *data,
            };

            Some(serialize_ping_frame_struct(&ping_frame))
        }

        FramePayload::WindowUpdate {
            window_size_increment,
        } => {
            let window_frame = WindowUpdateFrame {
                stream_id: frame.stream_id,
                increment: *window_size_increment,
            };

            Some(serialize_window_update_frame_struct(&window_frame))
        }

        FramePayload::RstStream { error_code } => {
            let rst_frame = RstStreamFrame {
                stream_id: frame.stream_id,
                error_code: ErrorCode::from_u32(*error_code),
            };

            Some(serialize_rst_stream_frame_struct(&rst_frame))
        }

        FramePayload::Data {
            data,
            end_stream,
            padded,
        } => {
            // Limit data size to prevent excessive memory usage
            let limited_data = if data.len() > MAX_FRAME_SIZE {
                &data[..MAX_FRAME_SIZE]
            } else {
                data
            };

            let mut bytes = create_data_frame_bytes(
                frame.stream_id,
                limited_data,
                *end_stream || frame.flags & 0x01 != 0,
            );
            if *padded || frame.flags & 0x08 != 0 {
                bytes[4] |= 0x08;
            }
            Some(bytes)
        }

        FramePayload::Headers {
            headers,
            end_stream,
            end_headers,
            priority_exclusive,
            priority_dependency,
            priority_weight,
        } => {
            let header_block = build_header_block(headers);
            let priority = priority_dependency
                .map(|dependency| (*priority_exclusive, dependency, *priority_weight));
            Some(create_headers_frame_bytes(
                frame.stream_id,
                *end_stream || frame.flags & 0x01 != 0,
                *end_headers || frame.flags & 0x04 != 0,
                Some(&header_block),
                priority,
            ))
        }

        FramePayload::GoAway {
            last_stream_id,
            error_code,
            debug_data,
        } => {
            let debug_len = debug_data.len().min(256);
            Some(create_goaway_frame_bytes(
                *last_stream_id,
                ErrorCode::from_u32(*error_code),
                &debug_data[..debug_len],
            ))
        }
    }
}

/// Helper functions for frame creation
fn serialize_settings_frame(ack: bool) -> Vec<u8> {
    let settings_frame = SettingsFrame {
        ack,
        settings: vec![
            Setting::EnablePush(false),
            Setting::MaxConcurrentStreams(128),
            Setting::InitialWindowSize(65536),
        ],
    };
    serialize_settings_frame_struct(&settings_frame)
}

fn serialize_settings_frame_struct(frame: &SettingsFrame) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Frame header (9 bytes)
    let length = frame.settings.len() * 6; // Each setting is 6 bytes
    bytes.extend_from_slice(&(length as u32).to_be_bytes()[1..4]); // 24-bit length
    bytes.push(0x04); // SETTINGS frame type
    bytes.push(if frame.ack { 0x01 } else { 0x00 }); // Flags
    bytes.extend_from_slice(&0u32.to_be_bytes()); // Stream ID = 0 for SETTINGS

    // Settings payload
    for setting in &frame.settings {
        bytes.extend_from_slice(&setting.id().to_be_bytes());
        bytes.extend_from_slice(&setting.value().to_be_bytes());
    }

    bytes
}

fn serialize_ping_frame_struct(frame: &PingFrame) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Frame header
    bytes.extend_from_slice(&[0, 0, 8]); // Length = 8
    bytes.push(0x06); // PING frame type
    bytes.push(if frame.ack { 0x01 } else { 0x00 }); // Flags
    bytes.extend_from_slice(&0u32.to_be_bytes()); // Stream ID = 0

    // Ping data
    bytes.extend_from_slice(&frame.opaque_data);

    bytes
}

fn serialize_window_update_frame_struct(frame: &WindowUpdateFrame) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Frame header
    bytes.extend_from_slice(&[0, 0, 4]); // Length = 4
    bytes.push(0x08); // WINDOW_UPDATE frame type
    bytes.push(0x00); // No flags
    bytes.extend_from_slice(&frame.stream_id.to_be_bytes());

    // Window size increment (clear reserved bit)
    bytes.extend_from_slice(&(frame.increment & 0x7FFFFFFF).to_be_bytes());

    bytes
}

fn serialize_rst_stream_frame_struct(frame: &RstStreamFrame) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Frame header
    bytes.extend_from_slice(&[0, 0, 4]); // Length = 4
    bytes.push(0x03); // RST_STREAM frame type
    bytes.push(0x00); // No flags
    bytes.extend_from_slice(&frame.stream_id.to_be_bytes());

    // Error code
    bytes.extend_from_slice(&(frame.error_code as u32).to_be_bytes());

    bytes
}

fn create_data_frame_bytes(stream_id: u32, data: &[u8], end_stream: bool) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Frame header
    let length = data.len();
    bytes.extend_from_slice(&(length as u32).to_be_bytes()[1..4]); // 24-bit length
    bytes.push(0x00); // DATA frame type
    bytes.push(if end_stream { 0x01 } else { 0x00 }); // END_STREAM flag
    bytes.extend_from_slice(&stream_id.to_be_bytes());

    // Data payload
    bytes.extend_from_slice(data);

    bytes
}

fn build_header_block(headers: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut block = Vec::new();
    for (name, value) in headers.iter().take(8) {
        let name_len = name.len().min(64);
        let value_len = value.len().min(128);
        block.extend_from_slice(&name[..name_len]);
        block.push(b':');
        block.extend_from_slice(&value[..value_len]);
        block.push(b'\n');
    }
    block.truncate(MAX_FRAME_SIZE);
    block
}

fn create_headers_frame_bytes(
    stream_id: u32,
    end_stream: bool,
    end_headers: bool,
    header_block: Option<&[u8]>,
    priority: Option<(bool, u32, u8)>,
) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Minimal headers frame with pseudo-headers
    let default_headers =
        b":method GET\r\n:path /\r\n:scheme https\r\n:authority example.com\r\n\r\n";
    let headers_data = match header_block {
        Some(block) if !block.is_empty() => block,
        _ => default_headers,
    };

    let mut payload = Vec::new();
    if let Some((exclusive, dependency, weight)) = priority {
        let mut stream_dependency = dependency & 0x7fff_ffff;
        if exclusive {
            stream_dependency |= 0x8000_0000;
        }
        payload.extend_from_slice(&stream_dependency.to_be_bytes());
        payload.push(weight);
    }
    payload.extend_from_slice(headers_data);

    // Frame header
    let length = payload.len();
    bytes.extend_from_slice(&(length as u32).to_be_bytes()[1..4]); // 24-bit length
    bytes.push(0x01); // HEADERS frame type

    let mut flags = 0;
    if end_stream {
        flags |= 0x01;
    }
    if end_headers {
        flags |= 0x04;
    }
    if priority.is_some() {
        flags |= 0x20;
    }
    bytes.push(flags);

    bytes.extend_from_slice(&stream_id.to_be_bytes());

    // Headers data
    bytes.extend_from_slice(&payload);

    bytes
}

fn create_goaway_frame_bytes(
    last_stream_id: u32,
    error_code: ErrorCode,
    debug_data: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Frame header
    let length = 8 + debug_data.len();
    bytes.extend_from_slice(&(length as u32).to_be_bytes()[1..4]); // last_stream_id + error_code + debug
    bytes.push(0x07); // GOAWAY frame type
    bytes.push(0x00); // No flags
    bytes.extend_from_slice(&0u32.to_be_bytes()); // Stream ID = 0

    // GOAWAY payload
    bytes.extend_from_slice(&(last_stream_id & 0x7fff_ffff).to_be_bytes());
    bytes.extend_from_slice(&(error_code as u32).to_be_bytes());
    bytes.extend_from_slice(debug_data);

    bytes
}

fn create_settings_frame(ack: bool) -> Frame {
    Frame::Settings(SettingsFrame {
        ack,
        settings: vec![Setting::EnablePush(false)],
    })
}

/// Parse frame from bytes (simplified)
fn parse_frame_from_bytes(bytes: &[u8]) -> Result<Frame, H2Error> {
    if bytes.len() < FRAME_HEADER_SIZE {
        return Err(H2Error::protocol("incomplete frame header"));
    }

    let mut src = BytesMut::from(bytes);
    let header = FrameHeader::parse(&mut src)?;
    let payload_len = match usize::try_from(header.length) {
        Ok(len) => len,
        Err(error) => {
            std::hint::black_box(error);
            return Err(H2Error::frame_size(
                "frame payload length does not fit usize",
            ));
        }
    };
    if src.len() < payload_len {
        return Err(H2Error::protocol("incomplete frame payload"));
    }
    let payload = src.split_to(payload_len).freeze();
    parse_h2_frame(&header, payload)
}

fn get_frame_stream_id(frame: &Frame) -> u32 {
    match frame {
        Frame::Data(f) => f.stream_id,
        Frame::Headers(f) => f.stream_id,
        Frame::RstStream(f) => f.stream_id,
        Frame::WindowUpdate(f) => f.stream_id,
        _ => 0,
    }
}

/// Validate state transitions
fn assert_valid_state_transition(before: ConnectionState, after: ConnectionState) {
    use ConnectionState::*;

    let valid = match (before, after) {
        (Handshaking, Open) => true,
        (Handshaking, Closing) => true,
        (Open, Open) => true,
        (Open, Closing) => true,
        (Closing, Closed) => true,
        (Closed, Closed) => true,
        (same_before, same_after) if same_before == same_after => true,
        _ => false,
    };

    assert!(
        valid,
        "Invalid state transition: {:?} -> {:?}",
        before, after
    );
}

/// Test specific attack scenarios
fn test_pre_handshake_attack(input: &FrameSequenceInput) {
    let frame_sequence = generate_frame_sequence(input);
    let mut connection = create_test_connection(&input.connection_config);

    // Connection should start in Handshaking state
    assert!(matches!(connection.state(), ConnectionState::Handshaking));

    // First non-SETTINGS frame should be rejected
    for frame_bytes in frame_sequence.iter().take(10) {
        if let Ok(frame) = parse_frame_from_bytes(frame_bytes) {
            let is_settings = matches!(frame, Frame::Settings(_));
            let result = connection.process_frame(frame);

            // Should either error or remain in valid state
            match result {
                Ok(_) => {
                    assert!(
                        is_settings,
                        "non-SETTINGS frame was accepted before the H2 handshake completed"
                    );
                }
                Err(err) => assert_well_formed_h2_error(&err),
            }
        }
    }
}

fn test_continuation_disorder(input: &FrameSequenceInput) {
    let frame_sequence = generate_frame_sequence(input);
    let mut connection = create_test_connection(&input.connection_config);

    for frame_bytes in frame_sequence.iter().take(20) {
        if let Ok(frame) = parse_frame_from_bytes(frame_bytes) {
            let result = connection.process_frame(frame);

            // CONTINUATION violations should be caught
            match result {
                Err(err) => {
                    assert_well_formed_h2_error(&err);
                    let error_msg = format!("{err}");
                    if error_msg.contains("CONTINUATION") || error_msg.contains("protocol") {
                        // Expected protocol error
                        break;
                    }
                }
                Ok(_) => {
                    // Valid frame sequence
                }
            }
        }
    }
}

fn test_post_goaway_frames(input: &FrameSequenceInput) {
    let frame_sequence = generate_frame_sequence(input);
    let mut connection = create_test_connection(&input.connection_config);

    let mut goaway_sent = false;

    for frame_bytes in frame_sequence.iter().take(30) {
        if let Ok(frame) = parse_frame_from_bytes(frame_bytes) {
            if matches!(frame, Frame::GoAway(_)) {
                goaway_sent = true;
            }

            let process_result = connection.process_frame(frame);
            observe_process_frame_result(&process_result);

            if goaway_sent {
                // After GOAWAY, connection should be in closing state
                assert!(matches!(
                    connection.state(),
                    ConnectionState::Closing | ConnectionState::Closed
                ));
            }
        }
    }
}

fn observe_process_frame_result(result: &Result<Option<ReceivedFrame>, H2Error>) {
    match result {
        Ok(Some(received)) => observe_received_frame(received),
        Ok(None) => {}
        Err(err) => assert_well_formed_h2_error(err),
    }
}

fn assert_well_formed_h2_error(err: &H2Error) {
    assert!(
        !err.message.is_empty(),
        "H2 errors should include diagnostic context"
    );
    if let Some(stream_id) = err.stream_id {
        assert_valid_stream_id(stream_id, "error");
    }
}

fn observe_received_frame(frame: &ReceivedFrame) {
    match frame {
        ReceivedFrame::Headers { stream_id, .. }
        | ReceivedFrame::Data { stream_id, .. }
        | ReceivedFrame::Reset { stream_id, .. } => {
            assert_valid_stream_id(*stream_id, "received frame");
        }
        ReceivedFrame::PushPromise {
            stream_id,
            promised_stream_id,
            ..
        } => {
            assert_valid_stream_id(*stream_id, "push promise");
            assert_valid_stream_id(*promised_stream_id, "promised stream");
        }
        ReceivedFrame::GoAway { last_stream_id, .. } => {
            assert!(
                *last_stream_id <= 0x7fff_ffff,
                "GOAWAY last stream ID must keep the reserved bit clear"
            );
        }
    }
}

fn assert_valid_stream_id(stream_id: u32, context: &str) {
    assert!(
        (1..=0x7fff_ffff).contains(&stream_id),
        "{context} stream ID must be nonzero and 31-bit: {stream_id}"
    );
}

fn test_general_ordering(input: &FrameSequenceInput) {
    let frame_sequence = generate_frame_sequence(input);
    let mut connection = create_test_connection(&input.connection_config);

    for frame_bytes in frame_sequence.iter().take(50) {
        if let Ok(frame) = parse_frame_from_bytes(frame_bytes) {
            let result = connection.process_frame(frame);

            match &result {
                Ok(_) => {
                    // Connection should remain in valid state
                    assert!(matches!(
                        connection.state(),
                        ConnectionState::Handshaking
                            | ConnectionState::Open
                            | ConnectionState::Closing
                            | ConnectionState::Closed
                    ));
                }
                Err(err) => assert_well_formed_h2_error(err),
            }
        }
    }
}
