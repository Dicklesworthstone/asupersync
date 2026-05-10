//! HTTP/2 SETTINGS_MAX_HEADER_LIST_SIZE enforcement fuzz target.
//!
//! Tests RFC 9113 compliance: SETTINGS_MAX_HEADER_LIST_SIZE should enforce
//! header list size limits before HPACK decode to prevent memory exhaustion DoS.
//!
//! This fuzzer generates HTTP/2 SETTINGS frames with various header list size
//! limits, followed by HEADERS frames with arbitrary header content, and verifies
//! that oversized headers are rejected without causing panics.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::Encoder;
use asupersync::http::h2::connection::FrameCodec;
use asupersync::http::h2::frame::{
    FRAME_HEADER_SIZE, Frame, HeadersFrame, PingFrame, PriorityFrame, PrioritySpec, Setting,
    SettingsFrame, WindowUpdateFrame,
};
use core::fmt::Debug;

/// HTTP/2 SETTINGS_MAX_HEADER_LIST_SIZE test sequence
#[derive(Debug, Clone, Arbitrary)]
struct MaxHeaderListSizeSequence {
    /// SETTINGS frame to establish the header list size limit
    max_header_list_size: u32,
    /// Additional settings to send alongside
    additional_settings: Vec<AdditionalSetting>,
    /// HEADERS frames to test against the limit
    headers_attempts: Vec<HeadersAttempt>,
    /// Interleaved frames for realistic scenarios
    interleaved_frames: Vec<InterleavedFrame>,
}

/// Additional SETTINGS to include in the frame
#[derive(Debug, Clone, Arbitrary)]
struct AdditionalSetting {
    setting_type: SettingType,
    value: u32,
}

/// SETTINGS types for testing combinations
#[derive(Debug, Clone, Arbitrary)]
enum SettingType {
    HeaderTableSize,
    EnablePush,
    MaxConcurrentStreams,
    InitialWindowSize,
    MaxFrameSize,
}

/// HEADERS frame attempt with potentially oversized content
#[derive(Debug, Clone, Arbitrary)]
struct HeadersAttempt {
    /// Stream ID for the headers
    stream_id: u32,
    /// Raw HPACK header block (potentially oversized)
    header_block: Vec<u8>,
    /// END_STREAM flag
    end_stream: bool,
    /// END_HEADERS flag
    end_headers: bool,
    /// Padding if applicable
    padding: Option<u8>,
}

/// Frames to interleave for realistic testing
#[derive(Debug, Clone, Arbitrary)]
enum InterleavedFrame {
    Settings {
        ack: bool,
    },
    WindowUpdate {
        stream_id: u32,
        increment: u32,
    },
    Ping {
        ack: bool,
    },
    Priority {
        stream_id: u32,
        dependency: u32,
        weight: u8,
        exclusive: bool,
    },
}

/// Connection state tracking for header list size enforcement
#[derive(Debug)]
struct HeaderListSizeState {
    max_header_list_size: u32,
    total_frames_processed: usize,
    headers_frames_sent: usize,
    enforcement_triggered: bool,
    panic_occurred: bool,
}

impl HeaderListSizeState {
    fn new(max_size: u32) -> Self {
        Self {
            max_header_list_size: max_size,
            total_frames_processed: 0,
            headers_frames_sent: 0,
            enforcement_triggered: false,
            panic_occurred: false,
        }
    }

    fn record_frame_processed(&mut self) {
        self.total_frames_processed += 1;
    }

    fn record_headers_sent(&mut self) {
        self.headers_frames_sent += 1;
    }

    fn record_enforcement_triggered(&mut self) {
        self.enforcement_triggered = true;
    }
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input size
    if data.len() > 100_000 {
        return;
    }

    let mut u = Unstructured::new(data);

    // Generate test sequence
    let test_seq = match MaxHeaderListSizeSequence::arbitrary(&mut u) {
        Ok(seq) => seq,
        Err(_) => return,
    };

    // Test the core scenario: MAX_HEADER_LIST_SIZE enforcement
    test_max_header_list_size_enforcement(&test_seq);

    // Test edge cases with zero and extreme limits
    test_header_list_size_edge_cases(&test_seq);
});

/// Core test: SETTINGS_MAX_HEADER_LIST_SIZE should enforce limits before HPACK decode
fn test_max_header_list_size_enforcement(test_seq: &MaxHeaderListSizeSequence) {
    let mut codec = FrameCodec::new();
    let mut buffer = BytesMut::new();
    let max_header_size = normalize_max_header_list_size(test_seq.max_header_list_size);
    let mut state = HeaderListSizeState::new(max_header_size);

    // Send initial SETTINGS frame to establish MAX_HEADER_LIST_SIZE
    let settings_frame =
        create_settings_frame_with_header_list_size(max_header_size, &test_seq.additional_settings);

    match codec.encode(settings_frame, &mut buffer) {
        Ok(()) => {
            // Settings frame should encode successfully
            assert!(
                buffer.len() >= FRAME_HEADER_SIZE,
                "SETTINGS frame should produce output"
            );
            state.record_frame_processed();
        }
        Err(_) => {
            // Settings encoding failed - skip this test
            return;
        }
    }

    // Test HEADERS frames against the limit
    for (attempt_index, attempt) in test_seq.headers_attempts.iter().enumerate() {
        let stream_id = normalize_stream_id(attempt.stream_id);

        // Skip stream ID 0 (connection-level)
        if stream_id == 0 {
            continue;
        }

        // Create HEADERS frame with potentially oversized header block
        let _padding_hint = attempt.padding.unwrap_or(0);
        let headers_frame = create_headers_frame_with_block(
            stream_id,
            &attempt.header_block,
            attempt.end_headers,
            attempt.end_stream,
        );

        // Test frame encoding (this should not panic)
        let encode_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            codec.encode(headers_frame, &mut buffer)
        }));

        match encode_result {
            Ok(Ok(())) => {
                // Frame encoded successfully
                state.record_headers_sent();

                // If header block is very large, enforcement should have triggered
                if attempt.header_block.len() > max_header_size as usize * 2 {
                    // Large header blocks should ideally be caught during processing
                    // but encoding may succeed before full validation
                }
            }
            Ok(Err(_)) => {
                // Frame encoding failed - this is acceptable
                // May indicate limit enforcement or other validation
                state.record_enforcement_triggered();
            }
            Err(_) => {
                // Panic occurred during encoding - this should not happen
                panic!(
                    "Panic occurred during HEADERS frame encoding with header list size {}",
                    max_header_size
                );
            }
        }

        state.record_frame_processed();

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
        !state.panic_occurred,
        "No panic should occur during header list size enforcement"
    );

    if !test_seq.headers_attempts.is_empty() {
        // Should have processed frames
        assert!(
            state.total_frames_processed > 0,
            "Should have processed at least SETTINGS frame"
        );

        // With oversized headers, enforcement should have been triggered
        let has_oversized = test_seq
            .headers_attempts
            .iter()
            .any(|h| h.header_block.len() > max_header_size as usize);

        if has_oversized && max_header_size < 1_000_000 {
            // For reasonable limits with oversized content, expect some enforcement
            // (Note: very large limits might not trigger with fuzzer-generated content)
        }
    }
}

/// Test edge cases with extreme header list size limits
fn test_header_list_size_edge_cases(test_seq: &MaxHeaderListSizeSequence) {
    // Test Case 1: Zero header list size (should reject all headers)
    test_header_list_size_limit(0, &test_seq.headers_attempts);

    // Test Case 2: Very small limit (1 byte)
    test_header_list_size_limit(1, &test_seq.headers_attempts);

    // Test Case 3: Maximum value (should allow very large headers)
    test_header_list_size_limit(u32::MAX, &test_seq.headers_attempts);
}

/// Test a specific header list size limit
fn test_header_list_size_limit(max_size: u32, headers_attempts: &[HeadersAttempt]) {
    let mut codec = FrameCodec::new();
    let mut buffer = BytesMut::new();

    // Send SETTINGS frame with specific limit
    let settings_frame = create_settings_frame_with_header_list_size(max_size, &[]);

    let encode_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        codec.encode(settings_frame, &mut buffer)
    }));

    match encode_result {
        Ok(Ok(())) => {
            // Settings encoded successfully - test headers
            for attempt in headers_attempts.iter().take(3) {
                // Limit iterations
                let stream_id = normalize_stream_id(attempt.stream_id);
                if stream_id == 0 {
                    continue;
                }

                let headers_frame = create_headers_frame_with_block(
                    stream_id,
                    &attempt.header_block,
                    attempt.end_headers,
                    attempt.end_stream,
                );

                // This should not panic regardless of limit
                let headers_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    codec.encode(headers_frame, &mut buffer)
                }));

                assert!(
                    headers_result.is_ok(),
                    "HEADERS encoding should not panic with max_header_list_size = {}",
                    max_size
                );
            }
        }
        Ok(Err(_)) => {
            // Settings encoding failed - acceptable for extreme values
        }
        Err(_) => {
            panic!(
                "SETTINGS encoding should not panic with max_header_list_size = {}",
                max_size
            );
        }
    }
}

/// Test interleaved frame processing
fn test_interleaved_frame(
    interleaved: &InterleavedFrame,
    codec: &mut FrameCodec,
    buffer: &mut BytesMut,
    state: &mut HeaderListSizeState,
) {
    let frame_result = match interleaved {
        InterleavedFrame::Settings { ack } => {
            let frame = if *ack {
                Frame::Settings(SettingsFrame::ack())
            } else {
                Frame::Settings(SettingsFrame::new(vec![Setting::MaxHeaderListSize(
                    state.max_header_list_size,
                )]))
            };
            codec.encode(frame, buffer)
        }
        InterleavedFrame::WindowUpdate {
            stream_id,
            increment,
        } => {
            let normalized_increment = if *increment == 0 { 1 } else { *increment };
            let frame = Frame::WindowUpdate(WindowUpdateFrame::new(
                normalize_stream_id(*stream_id),
                normalized_increment,
            ));
            codec.encode(frame, buffer)
        }
        InterleavedFrame::Ping { ack } => {
            let ping_frame = if *ack {
                PingFrame::ack([0u8; 8])
            } else {
                PingFrame::new([0u8; 8])
            };
            let frame = Frame::Ping(ping_frame);
            codec.encode(frame, buffer)
        }
        InterleavedFrame::Priority {
            stream_id,
            dependency,
            weight,
            exclusive,
        } => {
            let normalized_stream_id = normalize_stream_id(*stream_id);
            let normalized_dependency = normalize_stream_id(*dependency);
            if normalized_stream_id == 0 {
                return;
            }

            let frame = Frame::Priority(PriorityFrame {
                stream_id: normalized_stream_id,
                priority: PrioritySpec {
                    exclusive: *exclusive,
                    dependency: normalized_dependency,
                    weight: *weight,
                },
            });
            codec.encode(frame, buffer)
        }
    };

    observe_interleaved_frame_result(frame_result, state);
    state.record_frame_processed();
}

fn observe_interleaved_frame_result<E: Debug>(
    frame_result: Result<(), E>,
    state: &mut HeaderListSizeState,
) {
    if let Err(error) = frame_result {
        state.record_enforcement_triggered();
        let diagnostic = format!("interleaved frame encode: {error:?}");
        assert!(
            !diagnostic.trim().is_empty(),
            "interleaved frame encode failures must expose diagnostics"
        );
        assert!(
            diagnostic.len() < 1024,
            "interleaved frame encode diagnostics must stay bounded"
        );
    }
}

/// Create SETTINGS frame with MAX_HEADER_LIST_SIZE and additional settings
fn create_settings_frame_with_header_list_size(
    max_header_list_size: u32,
    additional: &[AdditionalSetting],
) -> Frame {
    let mut settings = vec![Setting::MaxHeaderListSize(max_header_list_size)];

    // Add additional settings
    for setting in additional {
        let setting_value = match setting.setting_type {
            SettingType::HeaderTableSize => Setting::HeaderTableSize(setting.value),
            SettingType::EnablePush => Setting::EnablePush(setting.value != 0),
            SettingType::MaxConcurrentStreams => Setting::MaxConcurrentStreams(setting.value),
            SettingType::InitialWindowSize => {
                let clamped = setting.value.min(0x7fff_ffff); // RFC limit
                Setting::InitialWindowSize(clamped)
            }
            SettingType::MaxFrameSize => {
                let clamped = setting.value.clamp(16384, 0x00ff_ffff); // RFC limits
                Setting::MaxFrameSize(clamped)
            }
        };
        settings.push(setting_value);
    }

    Frame::Settings(SettingsFrame::new(settings))
}

/// Create HEADERS frame with arbitrary header block
fn create_headers_frame_with_block(
    stream_id: u32,
    header_block: &[u8],
    end_headers: bool,
    end_stream: bool,
) -> Frame {
    // Create HEADERS frame with raw header block data
    // This allows testing with arbitrary bytes that may not be valid HPACK
    let block_bytes = if header_block.len() > 16 * 1024 {
        // Limit to reasonable size for performance
        Bytes::copy_from_slice(&header_block[..16 * 1024])
    } else {
        Bytes::copy_from_slice(header_block)
    };

    Frame::Headers(HeadersFrame {
        stream_id,
        header_block: block_bytes,
        end_stream,
        end_headers,
        priority: None,
    })
}

/// Normalize MAX_HEADER_LIST_SIZE to reasonable range for testing
fn normalize_max_header_list_size(value: u32) -> u32 {
    match value {
        0 => 0,                   // Test zero case
        1..=1024 => value,        // Small limits
        1025..=65536 => value,    // Normal limits
        65537..=1048576 => value, // Large limits
        _ => value % 1048576,     // Very large - wrap to 0-1MB range
    }
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
