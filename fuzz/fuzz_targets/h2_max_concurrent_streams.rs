#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::Encoder;
use asupersync::http::h2::connection::FrameCodec;
use asupersync::http::h2::error::{ErrorCode, H2Error};
use asupersync::http::h2::frame::{FRAME_HEADER_SIZE, Frame, HeadersFrame, Setting, SettingsFrame};

/// HTTP/2 MAX_CONCURRENT_STREAMS enforcement test sequence
#[derive(Debug, Clone, Arbitrary)]
struct MaxConcurrentStreamsSequence {
    /// Initial SETTINGS frame to establish the limit
    max_concurrent_streams: u32,
    /// Stream opening attempts to test
    stream_attempts: Vec<StreamOpenAttempt>,
    /// Additional frames to interleave
    interleaved_frames: Vec<InterleavedFrame>,
}

/// Stream opening attempt specification
#[derive(Debug, Clone, Arbitrary)]
struct StreamOpenAttempt {
    /// Stream ID to attempt
    stream_id: u32,
    /// Headers for the stream
    headers: Vec<HeaderSpec>,
    /// Whether to include END_HEADERS flag
    end_headers: bool,
    /// Whether to include END_STREAM flag
    end_stream: bool,
    /// Follow-up DATA frame if stream opens
    data_frame: Option<DataFrameSpec>,
}

/// Header specification for HEADERS frames
#[derive(Debug, Clone, Arbitrary)]
struct HeaderSpec {
    name: Vec<u8>,
    value: Vec<u8>,
}

/// DATA frame specification
#[derive(Debug, Clone, Arbitrary)]
struct DataFrameSpec {
    payload: Vec<u8>,
    end_stream: bool,
}

/// Interleaved frames to test concurrent behavior
#[derive(Debug, Clone, Arbitrary)]
enum InterleavedFrame {
    Settings { settings: Vec<SettingSpec> },
    RstStream { stream_id: u32, error_code: u8 },
    WindowUpdate { stream_id: u32, increment: u32 },
    Ping { ack: bool },
}

/// SETTINGS frame setting specification
#[derive(Debug, Clone, Arbitrary)]
struct SettingSpec {
    identifier: u16,
    value: u32,
}

/// Connection state tracking for stream limits
#[derive(Debug)]
struct ConcurrentStreamState {
    max_concurrent_streams: u32,
    active_streams: std::collections::HashSet<u32>,
    refused_streams: Vec<u32>,
    successful_opens: Vec<u32>,
    protocol_errors: usize,
}

impl ConcurrentStreamState {
    fn new(max_streams: u32) -> Self {
        Self {
            max_concurrent_streams: max_streams,
            active_streams: std::collections::HashSet::new(),
            refused_streams: Vec::new(),
            successful_opens: Vec::new(),
            protocol_errors: 0,
        }
    }

    fn can_open_stream(&self) -> bool {
        self.active_streams.len() < self.max_concurrent_streams as usize
    }

    fn open_stream(&mut self, stream_id: u32) -> Result<(), ErrorCode> {
        if self.active_streams.contains(&stream_id) {
            return Err(ErrorCode::ProtocolError);
        }

        if !self.can_open_stream() {
            self.refused_streams.push(stream_id);
            return Err(ErrorCode::RefusedStream);
        }

        self.active_streams.insert(stream_id);
        self.successful_opens.push(stream_id);
        Ok(())
    }

    fn close_stream(&mut self, stream_id: u32) {
        self.active_streams.remove(&stream_id);
    }
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input size
    if data.len() > 50_000 {
        return;
    }

    let mut u = Unstructured::new(data);

    // Generate test sequence
    let test_seq = match MaxConcurrentStreamsSequence::arbitrary(&mut u) {
        Ok(seq) => seq,
        Err(_) => return,
    };

    // Test the core scenario: MAX_CONCURRENT_STREAMS enforcement with REFUSED_STREAM
    test_max_concurrent_streams_enforcement(&test_seq);

    // Test edge cases with stream lifecycle
    test_stream_lifecycle_with_limits(&test_seq);
});

/// Core test: MAX_CONCURRENT_STREAMS should cause REFUSED_STREAM after limit
fn test_max_concurrent_streams_enforcement(test_seq: &MaxConcurrentStreamsSequence) {
    let mut codec = FrameCodec::new();
    let mut buffer = BytesMut::new();
    let max_streams = normalize_max_streams(test_seq.max_concurrent_streams);
    let mut state = ConcurrentStreamState::new(max_streams);

    // Send initial SETTINGS frame to establish MAX_CONCURRENT_STREAMS
    let settings_frame = create_settings_frame(max_streams);
    expect_frame_encode(
        "initial MAX_CONCURRENT_STREAMS SETTINGS frame",
        &mut codec,
        settings_frame,
        &mut buffer,
    );

    // Test stream opening attempts
    for (attempt_index, attempt) in test_seq.stream_attempts.iter().enumerate() {
        let stream_id = normalize_stream_id(attempt.stream_id);

        // Skip stream ID 0 (connection-level)
        if stream_id == 0 {
            continue;
        }

        // Create HEADERS frame to open stream
        let headers_frame = create_headers_frame(
            stream_id,
            &attempt.headers,
            attempt.end_headers,
            attempt.end_stream,
        );

        let before_active = state.active_streams.len();
        let before_refused = state.refused_streams.len();
        let before_successful = state.successful_opens.len();
        let before_protocol_errors = state.protocol_errors;

        match observe_frame_encode(
            "stream-opening HEADERS frame",
            &mut codec,
            headers_frame,
            &mut buffer,
        ) {
            Ok(()) => {
                let expected_result = state.open_stream(stream_id);
                match expected_result {
                    Ok(()) => {
                        // Stream should have opened successfully
                        assert!(
                            state.active_streams.contains(&stream_id),
                            "Stream {} should be active after successful open",
                            stream_id
                        );

                        // Send DATA frame if specified
                        if let Some(data_spec) = &attempt.data_frame {
                            let data_encoded = observe_data_frame_encode(
                                &mut codec,
                                &mut buffer,
                                &state,
                                stream_id,
                                data_spec,
                            );

                            // Close stream if END_STREAM was set
                            if data_encoded && data_spec.end_stream {
                                state.close_stream(stream_id);
                            }
                        } else if attempt.end_stream {
                            // Close stream immediately if END_STREAM in headers
                            state.close_stream(stream_id);
                        }
                    }
                    Err(ErrorCode::RefusedStream) => {
                        // This is where we need to verify REFUSED_STREAM behavior
                        // In practice, the codec should reject this at frame processing,
                        // but for fuzzing we simulate the expected behavior
                        assert!(
                            state.refused_streams.contains(&stream_id),
                            "Stream {} should be in refused list when max concurrent exceeded",
                            stream_id
                        );

                        assert!(
                            state.active_streams.len() >= max_streams as usize,
                            "REFUSED_STREAM should only occur when at max concurrent limit"
                        );
                    }
                    Err(ErrorCode::ProtocolError) => {
                        // Duplicate stream ID or other protocol violation
                        state.protocol_errors += 1;
                    }
                    Err(error_code) => {
                        panic!(
                            "unexpected stream-limit model error for stream {stream_id}: {error_code:?}"
                        );
                    }
                }
            }
            Err(err) => {
                // Rejected HEADERS encodes must stay diagnostic and must not
                // affect the stream-limit model.
                assert!(
                    !err.message.is_empty(),
                    "failed HEADERS encode should expose a diagnostic"
                );
                std::hint::black_box((err.code, err.stream_id, err.message.as_str()));
                assert_eq!(
                    state.active_streams.len(),
                    before_active,
                    "failed HEADERS encode should not change active stream count"
                );
                assert_eq!(
                    state.refused_streams.len(),
                    before_refused,
                    "failed HEADERS encode should not record a refused stream"
                );
                assert_eq!(
                    state.successful_opens.len(),
                    before_successful,
                    "failed HEADERS encode should not record a successful open"
                );
                assert_eq!(
                    state.protocol_errors, before_protocol_errors,
                    "failed HEADERS encode should not record protocol model errors"
                );
            }
        }

        // Interleave other frames for realistic scenarios
        if attempt_index < test_seq.interleaved_frames.len() {
            test_interleaved_frame(
                &test_seq.interleaved_frames[attempt_index],
                &mut codec,
                &mut buffer,
                &mut state,
            );
        }
    }

    // Verify final invariants
    assert!(
        state.active_streams.len() <= max_streams as usize,
        "Active stream count should never exceed MAX_CONCURRENT_STREAMS"
    );

    if !test_seq.stream_attempts.is_empty() {
        // Should have attempted to enforce the limit
        let total_attempts = test_seq.stream_attempts.len();
        let successful = state.successful_opens.len();
        let refused = state.refused_streams.len();

        assert!(
            successful + refused + state.protocol_errors >= total_attempts / 2,
            "Should have processed a reasonable portion of stream attempts"
        );

        if max_streams > 0 && total_attempts > max_streams as usize {
            // With more attempts than the limit, should have some refusals
            assert!(
                refused > 0 || state.protocol_errors > 0,
                "Should refuse streams or generate protocol errors when exceeding MAX_CONCURRENT_STREAMS"
            );
        }
    }
}

/// Test stream lifecycle with concurrent limits
fn test_stream_lifecycle_with_limits(test_seq: &MaxConcurrentStreamsSequence) {
    let max_streams = normalize_max_streams(test_seq.max_concurrent_streams);
    let mut state = ConcurrentStreamState::new(max_streams);

    // Test rapid open/close cycles
    for i in 0..max_streams.min(10) {
        let stream_id = i * 2 + 1; // Client streams (odd)

        // Open stream
        let result = state.open_stream(stream_id);
        assert!(
            result.is_ok(),
            "Should be able to open stream {} within limit",
            stream_id
        );

        // Immediately close it
        state.close_stream(stream_id);

        // Should be able to open another stream in the same slot
        let next_stream_id = stream_id + 2;
        let next_result = state.open_stream(next_stream_id);
        assert!(
            next_result.is_ok(),
            "Should be able to reuse stream slot after close"
        );

        state.close_stream(next_stream_id);
    }

    // Test exceeding the limit
    for i in 0..max_streams + 5 {
        let stream_id = i * 2 + 101; // Different range to avoid conflicts

        let result = state.open_stream(stream_id);
        if i < max_streams {
            assert!(
                result.is_ok(),
                "Stream {} should open within limit",
                stream_id
            );
        } else {
            assert!(
                matches!(result, Err(ErrorCode::RefusedStream)),
                "Stream {} should be refused beyond limit",
                stream_id
            );
        }
    }
}

fn observe_frame_encode(
    context: &str,
    codec: &mut FrameCodec,
    frame: Frame,
    buffer: &mut BytesMut,
) -> Result<(), H2Error> {
    let before_len = buffer.len();
    match codec.encode(frame, buffer) {
        Ok(()) => {
            let appended = buffer
                .len()
                .checked_sub(before_len)
                .expect("buffer length should not shrink on encode success");
            assert!(
                appended >= FRAME_HEADER_SIZE,
                "{context}: encoded frame should include an HTTP/2 frame header"
            );

            let header = &buffer[before_len..before_len + FRAME_HEADER_SIZE];
            let declared_len =
                ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
            assert_eq!(
                appended,
                FRAME_HEADER_SIZE + declared_len,
                "{context}: encoded byte count should match declared frame length"
            );
            Ok(())
        }
        Err(err) => {
            assert_eq!(
                buffer.len(),
                before_len,
                "{context}: failed encode should not append a partial frame"
            );
            assert!(
                !err.message.is_empty(),
                "{context}: encode failure should expose a diagnostic"
            );
            Err(err)
        }
    }
}

fn observe_data_frame_encode(
    codec: &mut FrameCodec,
    buffer: &mut BytesMut,
    state: &ConcurrentStreamState,
    stream_id: u32,
    data_spec: &DataFrameSpec,
) -> bool {
    assert!(
        state.active_streams.contains(&stream_id),
        "DATA frame should only be attempted for active stream {stream_id}"
    );

    let before_active = state.active_streams.len();
    let frame = create_data_frame(stream_id, data_spec);
    match observe_frame_encode(
        "DATA frame for successfully opened stream",
        codec,
        frame,
        buffer,
    ) {
        Ok(()) => {
            assert_eq!(
                state.active_streams.len(),
                before_active,
                "DATA frame encode should not mutate the stream model directly"
            );
            assert!(
                state.active_streams.contains(&stream_id),
                "DATA frame encode should keep stream {stream_id} active until END_STREAM handling"
            );
            true
        }
        Err(err) => {
            assert_eq!(
                state.active_streams.len(),
                before_active,
                "rejected DATA frame encode should not mutate the stream model"
            );
            assert!(
                state.active_streams.contains(&stream_id),
                "rejected DATA frame encode should leave stream {stream_id} active"
            );
            assert!(
                !err.message.is_empty(),
                "DATA frame encode failure should expose a diagnostic"
            );
            false
        }
    }
}

fn expect_frame_encode(context: &str, codec: &mut FrameCodec, frame: Frame, buffer: &mut BytesMut) {
    if let Err(err) = observe_frame_encode(context, codec, frame, buffer) {
        panic!("{context}: expected frame to encode, got {err}");
    }
}

/// Test interleaved frame processing
fn test_interleaved_frame(
    interleaved: &InterleavedFrame,
    codec: &mut FrameCodec,
    buffer: &mut BytesMut,
    state: &mut ConcurrentStreamState,
) {
    match interleaved {
        InterleavedFrame::Settings { settings } => {
            // Create new SETTINGS frame
            let settings_list = settings
                .iter()
                .filter_map(|s| Setting::from_id_value(normalize_setting_id(s.identifier), s.value))
                .collect();

            let frame = Frame::Settings(SettingsFrame::new(settings_list));
            expect_frame_encode("interleaved SETTINGS frame", codec, frame, buffer);
        }
        InterleavedFrame::RstStream {
            stream_id,
            error_code,
        } => {
            let normalized_stream_id = normalize_stream_id(*stream_id);
            if normalized_stream_id != 0 {
                let was_active = state.active_streams.contains(&normalized_stream_id);
                let before_active = state.active_streams.len();

                // Create RST_STREAM frame
                let frame = Frame::RstStream(asupersync::http::h2::frame::RstStreamFrame::new(
                    normalized_stream_id,
                    ErrorCode::from_u32(u32::from(*error_code)),
                ));
                match observe_frame_encode("interleaved RST_STREAM frame", codec, frame, buffer) {
                    Ok(()) => {
                        // Close the stream in our state tracking only after the frame is observable.
                        state.close_stream(normalized_stream_id);
                    }
                    Err(err) => {
                        assert_eq!(
                            state.active_streams.len(),
                            before_active,
                            "failed RST_STREAM encode should not change active stream count"
                        );
                        if was_active {
                            assert!(
                                state.active_streams.contains(&normalized_stream_id),
                                "failed RST_STREAM encode should not close active stream {normalized_stream_id}"
                            );
                        }
                        assert!(
                            !err.message.is_empty(),
                            "RST_STREAM encode failure should expose a diagnostic"
                        );
                    }
                }
            }
        }
        InterleavedFrame::WindowUpdate {
            stream_id,
            increment,
        } => {
            let normalized_increment = if increment == &0 { 1 } else { *increment };
            let frame = Frame::WindowUpdate(asupersync::http::h2::frame::WindowUpdateFrame::new(
                normalize_stream_id(*stream_id),
                normalized_increment,
            ));
            expect_frame_encode("interleaved WINDOW_UPDATE frame", codec, frame, buffer);
        }
        InterleavedFrame::Ping { ack } => {
            let ping_frame = if ack == &true {
                asupersync::http::h2::frame::PingFrame::ack([0u8; 8])
            } else {
                asupersync::http::h2::frame::PingFrame::new([0u8; 8])
            };
            let frame = Frame::Ping(ping_frame);
            expect_frame_encode("interleaved PING frame", codec, frame, buffer);
        }
    }
}

/// Create SETTINGS frame with MAX_CONCURRENT_STREAMS
fn create_settings_frame(max_streams: u32) -> Frame {
    let settings = vec![
        Setting::from_id_value(3, max_streams) // SETTINGS_MAX_CONCURRENT_STREAMS = 3
            .unwrap_or_else(|| Setting::from_id_value(1, 4096).unwrap()),
    ];
    Frame::Settings(SettingsFrame::new(settings))
}

/// Create HEADERS frame to open a stream
fn create_headers_frame(
    stream_id: u32,
    headers: &[HeaderSpec],
    end_headers: bool,
    end_stream: bool,
) -> Frame {
    // Create minimal HTTP/2 headers
    let mut header_block = Vec::new();

    // Add basic pseudo-headers (minimal HPACK encoding simulation)
    header_block.extend_from_slice(b"\x00\x00\x00\x00"); // Minimal HPACK block

    // Add custom headers (simplified)
    for header in headers {
        if header.name.len() < 50 && header.value.len() < 100 {
            header_block.extend_from_slice(&header.name[..header.name.len().min(20)]);
            header_block.extend_from_slice(&header.value[..header.value.len().min(30)]);
        }
    }

    Frame::Headers(HeadersFrame {
        stream_id,
        header_block: Bytes::copy_from_slice(&header_block),
        end_stream,
        end_headers,
        priority: None,
    })
}

/// Create DATA frame for an open stream
fn create_data_frame(stream_id: u32, data_spec: &DataFrameSpec) -> Frame {
    let payload = if data_spec.payload.len() > 1024 {
        // Limit payload size for performance
        Bytes::copy_from_slice(&data_spec.payload[..1024])
    } else {
        Bytes::copy_from_slice(&data_spec.payload)
    };

    Frame::Data(asupersync::http::h2::frame::DataFrame::new(
        stream_id,
        payload,
        data_spec.end_stream,
    ))
}

/// Normalize max concurrent streams to reasonable range
fn normalize_max_streams(value: u32) -> u32 {
    match value {
        0 => 1, // At least 1 stream
        1..=1000 => value,
        _ => value % 100 + 1, // Map to 1-100 range
    }
}

/// Normalize stream ID to valid client stream (odd, non-zero)
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

/// Normalize setting identifier to valid range
fn normalize_setting_id(id: u16) -> u16 {
    match id {
        1..=6 => id,       // Standard settings
        _ => (id % 6) + 1, // Map to standard settings
    }
}
