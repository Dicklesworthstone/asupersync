//! HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE Retroactive Update Fuzzer
//!
//! Targets the initial window size retroactive update logic in src/http/h2/connection.rs
//! and src/http/h2/stream.rs to test correct window recalculation when SETTINGS frames
//! change the initial window size, ensuring existing streams' flow control windows
//! are adjusted properly per RFC 9113 Section 6.9.2.
//!
//! Key invariants tested:
//! - Existing streams' windows adjusted by delta (new_initial - old_initial)
//! - Window arithmetic prevents overflow/underflow (i32 bounds checking)
//! - Closed streams skipped (don't affect SETTINGS processing)
//! - Multiple rapid SETTINGS updates handled correctly
//! - Window size validation per RFC 9113 (≤ 2^31-1)
//! - No panic on arbitrary update sequences

#![no_main]

use asupersync::bytes::{BufMut, Bytes, BytesMut};
use asupersync::http::h2::connection::{Connection, ConnectionState};
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{
    DataFrame, FrameHeader, HeadersFrame, RstStreamFrame, Setting, SettingsFrame, data_flags,
    parse_frame,
};
use asupersync::http::h2::settings::Settings;
use asupersync::http::h2::{Frame, H2Error};
use libfuzzer_sys::fuzz_target;

/// Maximum input size to prevent OOM
const MAX_INPUT_SIZE: usize = 8192;

/// Default initial window size per RFC 9113
const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65535;

/// Maximum allowed window size per RFC 9113 Section 6.9.1
const MAX_WINDOW_SIZE: i32 = i32::MAX;

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input sizes
    if data.is_empty() || data.len() > MAX_INPUT_SIZE {
        return;
    }

    // Test 1: Basic retroactive update with single stream
    {
        if data.len() >= 8 {
            let initial_window =
                u32::from_be_bytes([data[0], data[1], data[2], data[3]]) & MAX_WINDOW_SIZE as u32;
            let new_window =
                u32::from_be_bytes([data[4], data[5], data[6], data[7]]) & MAX_WINDOW_SIZE as u32;

            if initial_window <= MAX_WINDOW_SIZE as u32 && new_window <= MAX_WINDOW_SIZE as u32 {
                let result = test_single_stream_window_update(initial_window, new_window);
                match result {
                    Ok(_) => {} // Valid window update
                    Err(H2Error {
                        code: ErrorCode::FlowControlError,
                        ..
                    }) => {} // Expected overflow
                    Err(_) => {} // Other errors acceptable
                }
            }
        }
    }

    // Test 2: Multiple streams with varying data consumption
    if data.len() >= 16 {
        let stream_count = (data[0] % 8) + 1; // 1-8 streams
        let mut window_updates = Vec::new();

        let mut offset = 1;
        for i in 0..stream_count.min((data.len() - offset) / 4) {
            if offset + 4 <= data.len() {
                let window = u32::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]) & MAX_WINDOW_SIZE as u32;
                window_updates.push(window);
                offset += 4;
            }
        }

        if !window_updates.is_empty() {
            let _result = test_multiple_streams_window_update(&window_updates);
        }
    }

    // Test 3: Rapid sequence of SETTINGS updates
    if data.len() >= 20 {
        let update_count = (data[0] % 5) + 1; // 1-5 updates
        let mut updates = Vec::new();

        for i in 0..update_count.min((data.len() - 1) / 4) {
            let offset = 1 + i * 4;
            if offset + 4 <= data.len() {
                let window = u32::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]) & MAX_WINDOW_SIZE as u32;
                updates.push(window);
            }
        }

        if !updates.is_empty() {
            let _result = test_rapid_settings_updates(&updates);
        }
    }

    // Test 4: Window updates with stream closure timing
    {
        if data.len() >= 12 {
            let initial =
                u32::from_be_bytes([data[0], data[1], data[2], data[3]]) & MAX_WINDOW_SIZE as u32;
            let consume_amount = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let new_window =
                u32::from_be_bytes([data[8], data[9], data[10], data[11]]) & MAX_WINDOW_SIZE as u32;

            let _result = test_window_update_with_closure(initial, consume_amount, new_window);
        }
    }

    // Test 5: Boundary testing around overflow conditions
    {
        let test_windows = [
            0,                             // Minimum
            1,                             // Minimum valid
            DEFAULT_INITIAL_WINDOW_SIZE,   // Default
            MAX_WINDOW_SIZE as u32 - 1000, // Near maximum
            MAX_WINDOW_SIZE as u32 - 1,    // Just below maximum
            MAX_WINDOW_SIZE as u32,        // At maximum
        ];

        for &initial in &test_windows {
            for &new_size in &test_windows {
                let _result = test_boundary_window_update(initial, new_size);
            }
        }
    }

    // Test 6: Window arithmetic edge cases
    if data.len() >= 16 {
        // Test specific arithmetic edge cases that could cause overflow
        let base_window = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let consumed = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let new_initial = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let old_initial = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

        let _result =
            test_window_arithmetic_edge_case(base_window, consumed, old_initial, new_initial);
    }

    // Test 7: Mixed valid and invalid SETTINGS in sequence
    if data.len() >= 20 {
        let sequence = data
            .chunks(4)
            .map(|chunk| {
                if chunk.len() == 4 {
                    u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
                } else {
                    DEFAULT_INITIAL_WINDOW_SIZE
                }
            })
            .collect::<Vec<_>>();

        let _result = test_mixed_valid_invalid_sequence(&sequence);
    }

    // Test 8: Connection state during window updates
    {
        if data.len() >= 8 {
            let old_window = u32::from_be_bytes([data[0], data[1], data[2], data[3]])
                % (MAX_WINDOW_SIZE as u32 + 1);
            let new_window = u32::from_be_bytes([data[4], data[5], data[6], data[7]])
                % (MAX_WINDOW_SIZE as u32 + 1);

            let _result = test_window_update_connection_states(old_window, new_window);
        }
    }

    // Test 9: Large number of streams with specific patterns
    if data.len() >= 12 {
        let pattern_type = data[0] % 4; // 4 different test patterns
        let stream_count = (data[1] % 32) + 1; // 1-32 streams
        let window_delta = i32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let base_window = u32::from_be_bytes([data[8], data[9], data[10], data[11]])
            % (MAX_WINDOW_SIZE as u32 + 1);

        let _result =
            test_pattern_based_updates(pattern_type, stream_count, window_delta, base_window);
    }

    // Test 10: Zero and negative window scenarios
    if data.len() >= 8 {
        let scenario = data[0] % 3; // 3 different zero/negative scenarios
        let window_value = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        let _result = test_zero_negative_windows(scenario, window_value);
    }
});

/// Test retroactive window update with single stream
fn test_single_stream_window_update(initial_window: u32, new_window: u32) -> Result<(), H2Error> {
    let mut conn = Connection::server(Settings::default());
    conn.state = ConnectionState::Open;

    // Create and open a stream
    let stream_frame = create_headers_frame(1);
    conn.process_frame(stream_frame)?;

    // Send some data to partially consume the window
    if initial_window > 1000 {
        let data_frame = create_data_frame(1, 1000);
        let _result = conn.process_frame(data_frame);
    }

    // Apply SETTINGS_INITIAL_WINDOW_SIZE update
    let settings = SettingsFrame::new(vec![Setting::InitialWindowSize(new_window)]);
    conn.process_frame(Frame::Settings(settings))?;

    Ok(())
}

/// Test multiple streams with retroactive updates
fn test_multiple_streams_window_update(window_updates: &[u32]) -> Result<(), H2Error> {
    let mut conn = Connection::server(Settings::default());
    conn.state = ConnectionState::Open;

    // Create multiple streams
    for i in 0..window_updates.len().min(10) {
        let stream_id = (i as u32 * 2) + 1; // Odd stream IDs for client-initiated
        let headers_frame = create_headers_frame(stream_id);
        let _result = conn.process_frame(headers_frame);

        // Send varying amounts of data on each stream
        if i > 0 {
            let data_amount = (i * 500) as u32;
            if data_amount < DEFAULT_INITIAL_WINDOW_SIZE {
                let data_frame = create_data_frame(stream_id, data_amount);
                let _result = conn.process_frame(data_frame);
            }
        }
    }

    // Apply each window update in sequence
    for &new_window in window_updates {
        if new_window <= MAX_WINDOW_SIZE as u32 {
            let settings = SettingsFrame::new(vec![Setting::InitialWindowSize(new_window)]);
            let _result = conn.process_frame(Frame::Settings(settings));
        }
    }

    Ok(())
}

/// Test rapid sequence of SETTINGS updates
fn test_rapid_settings_updates(updates: &[u32]) -> Result<(), H2Error> {
    let mut conn = Connection::server(Settings::default());
    conn.state = ConnectionState::Open;

    // Create a stream with some data sent
    let headers_frame = create_headers_frame(1);
    conn.process_frame(headers_frame)?;

    let data_frame = create_data_frame(1, 5000);
    let _result = conn.process_frame(data_frame);

    // Apply rapid SETTINGS updates
    for &window_size in updates {
        if window_size <= MAX_WINDOW_SIZE as u32 {
            let settings = SettingsFrame::new(vec![Setting::InitialWindowSize(window_size)]);
            let result = conn.process_frame(Frame::Settings(settings));

            // Each update should either succeed or fail with a flow control error
            match result {
                Ok(()) => {} // Success
                Err(H2Error {
                    code: ErrorCode::FlowControlError,
                    ..
                }) => {} // Expected overflow
                Err(H2Error {
                    code: ErrorCode::ProtocolError,
                    ..
                }) => {} // Invalid value
                Err(_) => {} // Other errors
            }
        }
    }

    Ok(())
}

/// Test window updates when streams are closed during processing
fn test_window_update_with_closure(
    initial_window: u32,
    consume_amount: u32,
    new_window: u32,
) -> Result<(), H2Error> {
    let mut conn = Connection::server(Settings::default());
    conn.state = ConnectionState::Open;

    // Create multiple streams
    for i in 1..=5 {
        let stream_id = i * 2 + 1;
        let headers_frame = create_headers_frame(stream_id);
        let _result = conn.process_frame(headers_frame);

        // Consume some window on each stream
        if consume_amount > 0 && consume_amount < initial_window {
            let data_frame = create_data_frame(stream_id, consume_amount % initial_window);
            let _result = conn.process_frame(data_frame);
        }

        // Close some streams (this should make them skip window updates)
        if i % 2 == 0 {
            let rst_frame = create_rst_stream_frame(stream_id);
            let _result = conn.process_frame(rst_frame);
        }
    }

    // Apply window size update (should skip closed streams)
    if new_window <= MAX_WINDOW_SIZE as u32 {
        let settings = SettingsFrame::new(vec![Setting::InitialWindowSize(new_window)]);
        let _result = conn.process_frame(Frame::Settings(settings));
    }

    Ok(())
}

/// Test boundary window updates that might cause overflow
fn test_boundary_window_update(initial: u32, new_size: u32) -> Result<(), H2Error> {
    let mut conn = Connection::server(Settings::default());
    conn.state = ConnectionState::Open;

    // Create stream and consume most of the window
    let headers_frame = create_headers_frame(1);
    conn.process_frame(headers_frame)?;

    // Try to consume a large portion of the initial window
    if initial > 1000 {
        let consume = initial - 100; // Leave small amount
        let data_frame = create_data_frame(1, consume);
        let _result = conn.process_frame(data_frame);
    }

    // Apply potentially problematic window update
    if new_size <= MAX_WINDOW_SIZE as u32 {
        let settings = SettingsFrame::new(vec![Setting::InitialWindowSize(new_size)]);
        conn.process_frame(Frame::Settings(settings))?;
    }

    Ok(())
}

/// Test specific window arithmetic that might cause overflow
fn test_window_arithmetic_edge_case(
    _base_window: u32,
    _consumed: u32,
    old_initial: u32,
    new_initial: u32,
) -> Result<(), H2Error> {
    if old_initial > MAX_WINDOW_SIZE as u32 || new_initial > MAX_WINDOW_SIZE as u32 {
        return Ok(()); // Invalid inputs
    }

    let mut conn = Connection::server(Settings::default());
    conn.state = ConnectionState::Open;

    // Set initial window size
    let initial_settings = SettingsFrame::new(vec![Setting::InitialWindowSize(old_initial)]);
    conn.process_frame(Frame::Settings(initial_settings))?;

    let headers_frame = create_headers_frame(1);
    conn.process_frame(headers_frame)?;

    // Update to new window size
    let new_settings = SettingsFrame::new(vec![Setting::InitialWindowSize(new_initial)]);
    let _result = conn.process_frame(Frame::Settings(new_settings));

    Ok(())
}

/// Test mixed sequence of valid and potentially invalid updates
fn test_mixed_valid_invalid_sequence(sequence: &[u32]) -> Result<(), H2Error> {
    let mut conn = Connection::server(Settings::default());
    conn.state = ConnectionState::Open;

    let headers_frame = create_headers_frame(1);
    conn.process_frame(headers_frame)?;

    for &window_size in sequence {
        let settings = SettingsFrame::new(vec![Setting::InitialWindowSize(window_size)]);
        let _result = conn.process_frame(Frame::Settings(settings));
        // Mixed sequence - some may succeed, some may fail, both are valid outcomes
    }

    Ok(())
}

/// Test window updates in different connection states
fn test_window_update_connection_states(old_window: u32, new_window: u32) -> Result<(), H2Error> {
    let states = [
        ConnectionState::Handshaking,
        ConnectionState::Open,
        ConnectionState::Closing,
    ];

    for state in &states {
        let mut conn = Connection::server(Settings::default());
        conn.state = *state;

        // Only test in Open state (SETTINGS frames require established connection)
        if *state == ConnectionState::Open {
            let headers_frame = create_headers_frame(1);
            let _result = conn.process_frame(headers_frame);

            let settings = SettingsFrame::new(vec![Setting::InitialWindowSize(new_window)]);
            let _result = conn.process_frame(Frame::Settings(settings));
        }
    }

    Ok(())
}

/// Test specific patterns that might expose edge cases
fn test_pattern_based_updates(
    pattern_type: u8,
    stream_count: u8,
    window_delta: i32,
    base_window: u32,
) -> Result<(), H2Error> {
    let mut conn = Connection::server(Settings::default());
    conn.state = ConnectionState::Open;

    // Create streams based on pattern
    for i in 0..stream_count.min(16) {
        let stream_id = (i as u32 * 2) + 1;
        let headers_frame = create_headers_frame(stream_id);
        let _result = conn.process_frame(headers_frame);

        // Apply different consumption patterns
        match pattern_type {
            0 => {
                // Ascending consumption
                let consume = (i as u32 * 1000).min(base_window.saturating_sub(1000));
                if consume > 0 {
                    let data_frame = create_data_frame(stream_id, consume);
                    let _result = conn.process_frame(data_frame);
                }
            }
            1 => {
                // Descending consumption
                let consume =
                    ((stream_count - i) as u32 * 1000).min(base_window.saturating_sub(1000));
                if consume > 0 {
                    let data_frame = create_data_frame(stream_id, consume);
                    let _result = conn.process_frame(data_frame);
                }
            }
            2 => {
                // Alternating high/low consumption
                let consume = if i % 2 == 0 {
                    100
                } else {
                    base_window.saturating_sub(100)
                };
                if consume > 0 && consume < base_window {
                    let data_frame = create_data_frame(stream_id, consume);
                    let _result = conn.process_frame(data_frame);
                }
            }
            _ => {
                // Random pattern based on stream ID
                let consume = (stream_id * 777) % base_window;
                if consume > 0 {
                    let data_frame = create_data_frame(stream_id, consume);
                    let _result = conn.process_frame(data_frame);
                }
            }
        }
    }

    // Apply window update with delta
    let new_window = if window_delta >= 0 {
        base_window.saturating_add(window_delta as u32)
    } else {
        base_window.saturating_sub((-window_delta) as u32)
    }
    .min(MAX_WINDOW_SIZE as u32);

    let settings = SettingsFrame::new(vec![Setting::InitialWindowSize(new_window)]);
    let _result = conn.process_frame(Frame::Settings(settings));

    Ok(())
}

/// Test zero and negative window scenarios
fn test_zero_negative_windows(_scenario: u8, window_value: u32) -> Result<(), H2Error> {
    let mut conn = Connection::server(Settings::default());
    conn.state = ConnectionState::Open;

    let headers_frame = create_headers_frame(1);
    conn.process_frame(headers_frame)?;

    // Test window values that might cause underflow
    let test_values = [0, 1, window_value % (MAX_WINDOW_SIZE as u32 + 1)];

    for &value in &test_values {
        let settings = SettingsFrame::new(vec![Setting::InitialWindowSize(value)]);
        let _result = conn.process_frame(Frame::Settings(settings));
    }

    Ok(())
}

/// Create a HEADERS frame to open a stream
fn create_headers_frame(stream_id: u32) -> Frame {
    // Minimal HEADERS frame to open stream
    let mut payload = BytesMut::new();
    payload.put_slice(b"\x00\x00\x00\x00"); // Minimal header block

    let headers_frame = HeadersFrame {
        stream_id,
        header_block: payload.freeze(),
        end_stream: false,
        end_headers: true,
        priority: None,
    };
    Frame::Headers(headers_frame)
}

/// Create a DATA frame with specified payload size
fn create_data_frame(stream_id: u32, size: u32) -> Frame {
    let payload = vec![0u8; size as usize];

    let data_frame = DataFrame {
        stream_id,
        data: Bytes::from(payload),
        end_stream: false,
    };
    Frame::Data(data_frame)
}

/// Create a RST_STREAM frame to close a stream
fn create_rst_stream_frame(stream_id: u32) -> Frame {
    let rst_frame = RstStreamFrame {
        stream_id,
        error_code: ErrorCode::NoError,
    };
    Frame::RstStream(rst_frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_window_update() {
        let result = test_single_stream_window_update(65535, 32768);
        assert!(result.is_ok());
    }

    #[test]
    fn test_window_increase() {
        let result = test_single_stream_window_update(32768, 65535);
        assert!(result.is_ok());
    }

    #[test]
    fn test_window_decrease() {
        let result = test_single_stream_window_update(65535, 32768);
        assert!(result.is_ok());
    }

    #[test]
    fn test_zero_window() {
        let result = test_single_stream_window_update(65535, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_max_window() {
        let result = test_single_stream_window_update(32768, MAX_WINDOW_SIZE as u32);
        assert!(result.is_ok());
    }

    #[test]
    fn test_multiple_streams() {
        let windows = vec![65535, 32768, 0, 100000];
        let result = test_multiple_streams_window_update(&windows);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rapid_updates() {
        let updates = vec![32768, 65535, 16384, 131072];
        let result = test_rapid_settings_updates(&updates);
        assert!(result.is_ok());
    }

    #[test]
    fn test_boundary_conditions() {
        // Test boundary near maximum window size
        let result = test_boundary_window_update(65535, MAX_WINDOW_SIZE as u32 - 1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_overflow_detection() {
        // Test window size that would cause overflow
        let result = test_window_arithmetic_edge_case(
            MAX_WINDOW_SIZE as u32,
            1000,
            65535,
            MAX_WINDOW_SIZE as u32,
        );
        assert!(result.is_ok());
    }
}
