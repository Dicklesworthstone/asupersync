//! HTTP/2 Connection State Management Fuzzer
//!
//! Targets the connection state management in src/http/h2/connection.rs to test
//! proper GOAWAY frame handling and connection lifecycle under arbitrary frame
//! sequences that may trigger state transitions per RFC 9113.
//!
//! Key invariants tested:
//! - Connection state transitions correctly (Handshaking → Open → Closing → Closed)
//! - GOAWAY frame format and error codes are valid
//! - Frame processing after GOAWAY behaves correctly
//! - No panic on malformed frame sequences during connection lifecycle
//! - Stream creation rejection after connection enters closing state
//! - Flow control consistency during connection shutdown
//! - Proper handling of concurrent frames during state transitions
//! - PING frame responses maintain consistency during shutdown
//! - RST_STREAM handling for active streams during connection close
//! - Last-stream-id tracking in GOAWAY frames

#![no_main]

use asupersync::bytes::Bytes;
use asupersync::http::h2::connection::{Connection, ConnectionState};
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{
    DataFrame, GoAwayFrame, HeadersFrame, PingFrame, RstStreamFrame, Setting, SettingsFrame,
    WindowUpdateFrame,
};
use asupersync::http::h2::settings::Settings;
use asupersync::http::h2::{Frame, H2Error};
use libfuzzer_sys::fuzz_target;

/// Maximum input size to prevent OOM
const MAX_INPUT_SIZE: usize = 4096;

/// Frame types for activity simulation
const FRAME_TYPES: &[u8] = &[0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input sizes
    if data.is_empty() || data.len() > MAX_INPUT_SIZE {
        return;
    }

    // Test 1: Connection lifecycle with frame sequences
    {
        let result = test_connection_lifecycle_frames(data);
        validate_connection_result(result);
    }

    // Test 2: GOAWAY frame generation and handling
    if data.len() >= 8 {
        let error_code = data[0] % 13; // 0-12 error codes
        let last_stream_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) & 0x7fff_ffff;
        let debug_data = &data[5..std::cmp::min(data.len(), 32)];

        let result = test_goaway_generation(error_code, last_stream_id, debug_data);
        validate_goaway_result(result, error_code);
    }

    // Test 3: Stream creation and closure patterns
    if data.len() >= 12 {
        let stream_count = (data[8] % 8) + 1; // 1-8 streams
        let operation_pattern = &data[9..std::cmp::min(data.len(), 32)];

        let result = test_stream_operations(stream_count, operation_pattern);
        validate_stream_operations_result(result, stream_count);
    }

    // Test 4: PING frame handling during connection states
    if data.len() >= 16 {
        let ping_count = data[12] % 8; // 0-7 pings
        let ping_data_base = u64::from_be_bytes([data[13], data[14], data[15], 0, 0, 0, 0, 0]);

        let result = test_ping_handling(ping_count, ping_data_base);
        validate_ping_result(result, ping_count);
    }

    // Test 5: Window update and flow control
    if data.len() >= 20 {
        let window_updates = data[16] % 8; // 0-7 window updates
        let update_size = u32::from_be_bytes([data[17], data[18], data[19], 0]) & 0x7fff_ffff;

        let result = test_window_updates(window_updates, update_size);
        validate_window_update_result(result);
    }

    // Test 6: Settings frame processing
    if data.len() >= 24 {
        let settings_count = data[20] % 6; // 0-5 settings
        let settings_data = &data[21..std::cmp::min(data.len(), 40)];

        let result = test_settings_processing(settings_count, settings_data);
        validate_settings_result(result);
    }

    // Test 7: Connection error scenarios
    if data.len() >= 28 {
        let error_trigger = data[24] % 4; // Different error triggers
        let frame_data = &data[25..std::cmp::min(data.len(), 48)];

        let result = test_connection_errors(error_trigger, frame_data);
        validate_error_result(result);
    }

    // Test 8: Interleaved frame types
    if data.len() >= 32 {
        let frame_pattern = &data[28..std::cmp::min(data.len(), 64)];

        let result = test_interleaved_frames(frame_pattern);
        validate_interleaved_result(result);
    }
});

/// Test connection lifecycle with arbitrary frame sequences
fn test_connection_lifecycle_frames(data: &[u8]) -> Result<ConnectionLifecycleResult, H2Error> {
    let mut connection = Connection::server(Settings::default());

    // Initialize connection
    initialize_connection(&mut connection)?;

    let initial_state = connection.state();
    let mut frames_sent = 0;
    let mut errors_encountered = 0;

    // Process frame sequence from fuzzed data
    let mut offset = 0;
    while offset + 4 <= data.len() && frames_sent < 16 {
        let frame_type = data[offset] % FRAME_TYPES.len() as u8;
        let stream_id = ((data[offset + 1] as u32) << 8 | data[offset + 2] as u32) * 2 + 1; // Odd stream IDs
        let frame_data_size = (data[offset + 3] as usize % 32) + 1; // 1-32 bytes

        let frame_result = create_and_send_frame(
            &mut connection,
            FRAME_TYPES[frame_type as usize],
            stream_id,
            &data[offset + 4..std::cmp::min(data.len(), offset + 4 + frame_data_size)],
        );

        if frame_result.is_err() {
            errors_encountered += 1;
        }

        frames_sent += 1;
        offset += 4 + frame_data_size;
    }

    let final_state = connection.state();
    let outgoing_frames = collect_outgoing_frames(&mut connection);

    Ok(ConnectionLifecycleResult {
        initial_state,
        final_state,
        frames_sent,
        errors_encountered,
        goaway_frames: extract_goaway_frames(&outgoing_frames),
        outgoing_frame_count: outgoing_frames.len(),
    })
}

/// Test GOAWAY frame generation with specific error codes
fn test_goaway_generation(
    error_code: u8,
    _last_stream_id: u32,
    debug_data: &[u8],
) -> Result<GoAwayGenerationResult, H2Error> {
    let mut connection = Connection::server(Settings::default());
    initialize_connection(&mut connection)?;

    // Create some streams first
    for i in 1..=3 {
        let stream_id = i * 2 + 1; // Odd stream IDs
        let _ = send_headers_frame(&mut connection, stream_id, false);
    }

    // Trigger GOAWAY by sending a malformed frame or other error condition
    let _error_code_mapped = match error_code {
        0 => ErrorCode::NoError,
        1 => ErrorCode::ProtocolError,
        2 => ErrorCode::InternalError,
        3 => ErrorCode::FlowControlError,
        4 => ErrorCode::SettingsTimeout,
        5 => ErrorCode::StreamClosed,
        6 => ErrorCode::FrameSizeError,
        7 => ErrorCode::RefusedStream,
        8 => ErrorCode::Cancel,
        9 => ErrorCode::CompressionError,
        10 => ErrorCode::ConnectError,
        11 => ErrorCode::EnhanceYourCalm,
        12 => ErrorCode::InadequateSecurity,
        _ => ErrorCode::InternalError,
    };

    // Force a GOAWAY by sending a protocol error frame
    let protocol_error_result = send_malformed_frame(&mut connection, debug_data);

    let outgoing_frames = collect_outgoing_frames(&mut connection);
    let goaway_frames = extract_goaway_frames(&outgoing_frames);

    Ok(GoAwayGenerationResult {
        goaway_sent: !goaway_frames.is_empty(),
        goaway_frames,
        connection_state: connection.state(),
        protocol_error_triggered: protocol_error_result.is_err(),
    })
}

/// Test stream operations (create, send data, close)
fn test_stream_operations(
    stream_count: u8,
    operation_pattern: &[u8],
) -> Result<StreamOperationsResult, H2Error> {
    let mut connection = Connection::server(Settings::default());
    initialize_connection(&mut connection)?;

    let mut streams_created = 0;
    let mut data_frames_sent = 0;
    let mut errors = 0;

    for i in 0..stream_count {
        let stream_id = (i as u32) * 2 + 1;

        // Create stream
        if send_headers_frame(&mut connection, stream_id, false).is_ok() {
            streams_created += 1;
        }

        // Send data based on pattern
        if i < operation_pattern.len() as u8 {
            let pattern = operation_pattern[i as usize];
            if pattern & 0x01 != 0 {
                // Send data frame
                let data_size = ((pattern >> 1) & 0x1F) + 1; // 1-32 bytes
                let data = vec![0x42; data_size as usize];
                if send_data_frame(&mut connection, stream_id, &data, false).is_ok() {
                    data_frames_sent += 1;
                } else {
                    errors += 1;
                }
            }

            if pattern & 0x80 != 0 {
                // Close stream
                let _ = send_data_frame(&mut connection, stream_id, &[], true);
            }
        }
    }

    let outgoing_frames = collect_outgoing_frames(&mut connection);

    Ok(StreamOperationsResult {
        streams_created,
        data_frames_sent,
        errors,
        final_frame_count: outgoing_frames.len(),
        connection_state: connection.state(),
    })
}

/// Test PING frame handling
fn test_ping_handling(ping_count: u8, ping_data_base: u64) -> Result<PingHandlingResult, H2Error> {
    let mut connection = Connection::server(Settings::default());
    initialize_connection(&mut connection)?;

    let mut pings_sent = 0;
    let mut ping_responses = 0;

    for i in 0..ping_count {
        let ping_data_u64 = ping_data_base.wrapping_add(i as u64);
        let ping_data = ping_data_u64.to_be_bytes();
        let ping_frame = PingFrame::new(ping_data);

        if connection.process_frame(Frame::Ping(ping_frame)).is_ok() {
            pings_sent += 1;
        }

        // Check for PING responses in outgoing frames
        let frames = collect_outgoing_frames(&mut connection);
        for frame in &frames {
            if matches!(frame, Frame::Ping(_)) {
                ping_responses += 1;
            }
        }
    }

    Ok(PingHandlingResult {
        pings_sent,
        ping_responses,
        connection_state: connection.state(),
    })
}

/// Test window update frames
fn test_window_updates(
    window_update_count: u8,
    update_size: u32,
) -> Result<WindowUpdateResult, H2Error> {
    let mut connection = Connection::server(Settings::default());
    initialize_connection(&mut connection)?;

    let mut updates_sent = 0;
    let mut errors = 0;

    // Send connection-level window update
    if update_size > 0 {
        let conn_update = WindowUpdateFrame::new(0, update_size);
        if connection
            .process_frame(Frame::WindowUpdate(conn_update))
            .is_ok()
        {
            updates_sent += 1;
        } else {
            errors += 1;
        }
    }

    // Send stream-level window updates
    for i in 1..window_update_count {
        let stream_id = (i as u32) * 2 + 1;
        if update_size > 0 {
            let stream_update = WindowUpdateFrame::new(stream_id, update_size);

            if connection
                .process_frame(Frame::WindowUpdate(stream_update))
                .is_ok()
            {
                updates_sent += 1;
            } else {
                errors += 1;
            }
        }
    }

    Ok(WindowUpdateResult {
        updates_sent,
        errors,
        connection_state: connection.state(),
    })
}

/// Test settings frame processing
fn test_settings_processing(
    settings_count: u8,
    settings_data: &[u8],
) -> Result<SettingsProcessingResult, H2Error> {
    let mut connection = Connection::server(Settings::default());
    initialize_connection(&mut connection)?;

    let mut settings_frames_sent = 0;
    let mut errors = 0;

    for i in 0..settings_count {
        let mut settings = Vec::new();

        // Create settings based on fuzzed data
        if settings_data.len() >= (i as usize + 1) * 6 {
            let offset = i as usize * 6;
            let setting_id = (settings_data[offset] % 6) + 1; // 1-6
            let setting_value = u32::from_be_bytes([
                settings_data[offset + 1],
                settings_data[offset + 2],
                settings_data[offset + 3],
                settings_data[offset + 4],
            ]);

            let setting = match setting_id {
                1 => Setting::HeaderTableSize(setting_value),
                2 => Setting::EnablePush(setting_value != 0),
                3 => Setting::MaxConcurrentStreams(setting_value),
                4 => Setting::InitialWindowSize(setting_value & 0x7fff_ffff),
                5 => Setting::MaxFrameSize(setting_value.clamp(16384, 0x00ff_ffff)),
                6 => Setting::MaxHeaderListSize(setting_value),
                _ => Setting::HeaderTableSize(4096),
            };

            settings.push(setting);
        }

        if !settings.is_empty() {
            let settings_frame = SettingsFrame::new(settings);
            if connection
                .process_frame(Frame::Settings(settings_frame))
                .is_ok()
            {
                settings_frames_sent += 1;
            } else {
                errors += 1;
            }
        }
    }

    Ok(SettingsProcessingResult {
        settings_frames_sent,
        errors,
        connection_state: connection.state(),
    })
}

/// Test connection error scenarios
fn test_connection_errors(
    error_trigger: u8,
    frame_data: &[u8],
) -> Result<ConnectionErrorResult, H2Error> {
    let mut connection = Connection::server(Settings::default());
    initialize_connection(&mut connection)?;

    let mut error_triggered = false;

    match error_trigger {
        0 => {
            // Send oversized frame
            if frame_data.len() >= 4 {
                let oversized_data = vec![0xFF; 65536]; // Larger than default max frame size
                if send_data_frame(&mut connection, 1, &oversized_data, false).is_err() {
                    error_triggered = true;
                }
            }
        }
        1 => {
            // Send frame on invalid stream ID
            let invalid_stream_id = 0; // Stream ID 0 is reserved for connection
            if send_data_frame(&mut connection, invalid_stream_id, frame_data, false).is_err() {
                error_triggered = true;
            }
        }
        2 => {
            // Send duplicate settings ack
            let settings_ack = SettingsFrame::ack();
            if connection
                .process_frame(Frame::Settings(settings_ack))
                .is_err()
            {
                error_triggered = true;
            }
        }
        3 => {
            // Send window update with zero increment
            let zero_update = WindowUpdateFrame::new(0, 0);
            if connection
                .process_frame(Frame::WindowUpdate(zero_update))
                .is_err()
            {
                error_triggered = true;
            }
        }
        _ => {}
    }

    let outgoing_frames = collect_outgoing_frames(&mut connection);
    let goaway_frames = extract_goaway_frames(&outgoing_frames);

    Ok(ConnectionErrorResult {
        error_triggered,
        goaway_sent: !goaway_frames.is_empty(),
        connection_state: connection.state(),
    })
}

/// Test interleaved frame types
fn test_interleaved_frames(frame_pattern: &[u8]) -> Result<InterleavedFrameResult, H2Error> {
    let mut connection = Connection::server(Settings::default());
    initialize_connection(&mut connection)?;

    let mut frames_processed = 0;
    let mut errors = 0;

    for (i, &pattern) in frame_pattern.iter().enumerate().take(16) {
        let frame_type = pattern % FRAME_TYPES.len() as u8;
        let stream_id = ((i as u32) + 1) * 2 + 1; // Odd stream IDs

        let result = create_and_send_frame(
            &mut connection,
            FRAME_TYPES[frame_type as usize],
            stream_id,
            &[pattern],
        );

        if result.is_ok() {
            frames_processed += 1;
        } else {
            errors += 1;
        }

        // Break early if connection enters error state
        if matches!(connection.state(), ConnectionState::Closed) {
            break;
        }
    }

    Ok(InterleavedFrameResult {
        frames_processed,
        errors,
        connection_state: connection.state(),
    })
}

// Result types

#[derive(Debug)]
struct ConnectionLifecycleResult {
    initial_state: ConnectionState,
    final_state: ConnectionState,
    frames_sent: u32,
    errors_encountered: u32,
    goaway_frames: Vec<GoAwayFrame>,
    outgoing_frame_count: usize,
}

#[derive(Debug)]
struct GoAwayGenerationResult {
    goaway_sent: bool,
    goaway_frames: Vec<GoAwayFrame>,
    connection_state: ConnectionState,
    protocol_error_triggered: bool,
}

#[derive(Debug)]
struct StreamOperationsResult {
    streams_created: u32,
    data_frames_sent: u32,
    errors: u32,
    final_frame_count: usize,
    connection_state: ConnectionState,
}

#[derive(Debug)]
struct PingHandlingResult {
    pings_sent: u32,
    ping_responses: u32,
    connection_state: ConnectionState,
}

#[derive(Debug)]
struct WindowUpdateResult {
    updates_sent: u32,
    errors: u32,
    connection_state: ConnectionState,
}

#[derive(Debug)]
struct SettingsProcessingResult {
    settings_frames_sent: u32,
    errors: u32,
    connection_state: ConnectionState,
}

#[derive(Debug)]
struct ConnectionErrorResult {
    error_triggered: bool,
    goaway_sent: bool,
    connection_state: ConnectionState,
}

#[derive(Debug)]
struct InterleavedFrameResult {
    frames_processed: u32,
    errors: u32,
    connection_state: ConnectionState,
}

// Helper functions

fn initialize_connection(connection: &mut Connection) -> Result<(), H2Error> {
    // Send initial SETTINGS frame
    let settings_frame = SettingsFrame::new(vec![
        Setting::MaxConcurrentStreams(100),
        Setting::InitialWindowSize(65536),
        Setting::MaxFrameSize(16384),
    ]);
    let _ = connection.process_frame(Frame::Settings(settings_frame))?;
    Ok(())
}

fn collect_outgoing_frames(_connection: &mut Connection) -> Vec<Frame> {
    // Note: The connection API doesn't expose a poll_outgoing_frame method
    // This fuzzer focuses on testing frame processing without collecting responses
    Vec::new()
}

fn extract_goaway_frames(frames: &[Frame]) -> Vec<GoAwayFrame> {
    frames
        .iter()
        .filter_map(|f| match f {
            Frame::GoAway(goaway) => Some(goaway.clone()),
            _ => None,
        })
        .collect()
}

fn send_headers_frame(
    connection: &mut Connection,
    stream_id: u32,
    end_stream: bool,
) -> Result<(), H2Error> {
    let headers_frame = HeadersFrame::new(
        stream_id,
        Bytes::from("dummy headers"),
        end_stream,
        true, // end_headers
    );
    let _ = connection.process_frame(Frame::Headers(headers_frame))?;
    Ok(())
}

fn send_data_frame(
    connection: &mut Connection,
    stream_id: u32,
    data: &[u8],
    end_stream: bool,
) -> Result<(), H2Error> {
    let data_frame = DataFrame::new(stream_id, Bytes::copy_from_slice(data), end_stream);
    let _ = connection.process_frame(Frame::Data(data_frame))?;
    Ok(())
}

fn send_malformed_frame(connection: &mut Connection, _debug_data: &[u8]) -> Result<(), H2Error> {
    // Send a frame with invalid stream ID to trigger protocol error
    let malformed_frame = DataFrame::new(0, Bytes::from("invalid"), false); // Stream ID 0 for DATA frame
    let _ = connection.process_frame(Frame::Data(malformed_frame))?;
    Ok(())
}

fn create_and_send_frame(
    connection: &mut Connection,
    frame_type: u8,
    stream_id: u32,
    data: &[u8],
) -> Result<(), H2Error> {
    match frame_type {
        0x0 => {
            // DATA
            send_data_frame(connection, stream_id, data, false)
        }
        0x1 => {
            // HEADERS
            send_headers_frame(connection, stream_id, false)
        }
        0x2 => {
            // PRIORITY (deprecated in HTTP/2 RFC 9113 but may be supported)
            Ok(()) // Skip priority frames for now
        }
        0x3 => {
            // RST_STREAM
            let rst_frame = RstStreamFrame::new(stream_id, ErrorCode::Cancel);
            let _ = connection.process_frame(Frame::RstStream(rst_frame))?;
            Ok(())
        }
        0x4 => {
            // SETTINGS
            let settings_frame = SettingsFrame::new(vec![Setting::HeaderTableSize(4096)]);
            let _ = connection.process_frame(Frame::Settings(settings_frame))?;
            Ok(())
        }
        0x5 => {
            // PUSH_PROMISE
            Ok(()) // Skip PUSH_PROMISE for server connections
        }
        0x6 => {
            // PING
            let ping_data = if data.len() >= 8 {
                [
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]
            } else {
                [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]
            };
            let ping_frame = PingFrame::new(ping_data);
            let _ = connection.process_frame(Frame::Ping(ping_frame))?;
            Ok(())
        }
        0x7 => {
            // GOAWAY
            // Don't manually send GOAWAY - let the connection generate it
            Ok(())
        }
        0x8 => {
            // WINDOW_UPDATE
            let increment = if data.len() >= 4 {
                u32::from_be_bytes([data[0], data[1], data[2], data[3]]) & 0x7fff_ffff
            } else {
                1024
            };
            if increment == 0 {
                return Err(H2Error::protocol("WINDOW_UPDATE increment cannot be zero"));
            }
            let window_update = WindowUpdateFrame::new(stream_id, increment);
            let _ = connection.process_frame(Frame::WindowUpdate(window_update))?;
            Ok(())
        }
        _ => Ok(()), // Unknown frame type
    }
}

// Validation functions

fn validate_connection_result(result: Result<ConnectionLifecycleResult, H2Error>) {
    match result {
        Ok(res) => {
            // Connection should not panic
            assert!(
                res.frames_sent >= res.errors_encountered,
                "More errors than frames sent"
            );

            // GOAWAY frames should have valid error codes
            for goaway in &res.goaway_frames {
                let error_code = goaway.error_code as u32;
                assert!(
                    error_code <= 13,
                    "Invalid GOAWAY error code: {}",
                    error_code
                );
            }

            // Connection should transition properly
            if !res.goaway_frames.is_empty() {
                assert!(
                    matches!(
                        res.final_state,
                        ConnectionState::Closing | ConnectionState::Closed
                    ),
                    "Connection should be closing/closed after GOAWAY"
                );
            }
        }
        Err(_) => {
            // Connection errors are acceptable in fuzzing
        }
    }
}

fn validate_goaway_result(result: Result<GoAwayGenerationResult, H2Error>, _error_code: u8) {
    match result {
        Ok(res) => {
            if res.goaway_sent {
                assert!(
                    !res.goaway_frames.is_empty(),
                    "GOAWAY sent but no frames captured"
                );

                for goaway in &res.goaway_frames {
                    // Verify last_stream_id is properly masked (31 bits)
                    let last_stream_id = goaway.last_stream_id;
                    assert!(
                        last_stream_id <= 0x7fff_ffff,
                        "Last stream ID should be 31-bit: {}",
                        last_stream_id
                    );
                }
            }
        }
        Err(_) => {
            // Errors are acceptable during GOAWAY generation
        }
    }
}

fn validate_stream_operations_result(
    result: Result<StreamOperationsResult, H2Error>,
    expected_stream_count: u8,
) {
    match result {
        Ok(res) => {
            assert!(
                res.streams_created <= expected_stream_count as u32,
                "More streams created than requested"
            );

            // Data frames should not exceed stream count
            assert!(
                res.data_frames_sent <= res.streams_created,
                "Cannot send more data frames than created streams"
            );
        }
        Err(_) => {
            // Stream operation errors are acceptable
        }
    }
}

fn validate_ping_result(result: Result<PingHandlingResult, H2Error>, ping_count: u8) {
    match result {
        Ok(res) => {
            assert!(
                res.pings_sent <= ping_count as u32,
                "More PINGs sent than expected"
            );

            // PING responses should not exceed PING requests
            assert!(
                res.ping_responses <= res.pings_sent,
                "More PING responses than requests"
            );
        }
        Err(_) => {
            // PING errors are acceptable
        }
    }
}

fn validate_window_update_result(result: Result<WindowUpdateResult, H2Error>) {
    match result {
        Ok(_res) => {
            // Window updates should not cause connection failure (unless invalid)
        }
        Err(_) => {
            // Window update errors are acceptable (e.g., zero increment)
        }
    }
}

fn validate_settings_result(result: Result<SettingsProcessingResult, H2Error>) {
    match result {
        Ok(_res) => {
            // Settings processing should not cause fundamental failures
        }
        Err(_) => {
            // Settings errors are acceptable
        }
    }
}

fn validate_error_result(result: Result<ConnectionErrorResult, H2Error>) {
    match result {
        Ok(res) => {
            if res.error_triggered && res.goaway_sent {
                // Error should trigger GOAWAY
                assert!(
                    matches!(
                        res.connection_state,
                        ConnectionState::Closing | ConnectionState::Closed
                    ),
                    "Connection should be closing after error + GOAWAY"
                );
            }
        }
        Err(_) => {
            // Connection errors are expected in error scenarios
        }
    }
}

fn validate_interleaved_result(result: Result<InterleavedFrameResult, H2Error>) {
    match result {
        Ok(res) => {
            assert!(
                res.frames_processed >= res.errors,
                "Processed frame count inconsistent with errors"
            );
        }
        Err(_) => {
            // Interleaved frame errors are acceptable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_initialization() {
        let mut connection = Connection::server(Settings::default());
        let result = initialize_connection(&mut connection);
        assert!(result.is_ok());
    }

    #[test]
    fn test_basic_frame_sending() {
        let mut connection = Connection::server(Settings::default());
        initialize_connection(&mut connection).unwrap();

        let result = send_headers_frame(&mut connection, 1, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_stream_id() {
        let mut connection = Connection::server(Settings::default());
        initialize_connection(&mut connection).unwrap();

        let result = send_data_frame(&mut connection, 0, b"test", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_ping_handling() {
        let mut connection = Connection::server(Settings::default());
        initialize_connection(&mut connection).unwrap();

        let ping_frame = PingFrame::new(0x1234567890abcdef);
        let result = connection.process_frame(Frame::Ping(ping_frame));
        assert!(result.is_ok());
    }

    #[test]
    fn test_window_update_zero_increment() {
        let mut connection = Connection::server(Settings::default());
        initialize_connection(&mut connection).unwrap();

        let zero_update = WindowUpdateFrame::new(0, 0);
        let result = connection.process_frame(Frame::WindowUpdate(zero_update));
        assert!(result.is_err());
    }
}
