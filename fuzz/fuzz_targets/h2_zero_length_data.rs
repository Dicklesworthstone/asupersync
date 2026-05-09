#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::Encoder;
use asupersync::http::h2::connection::FrameCodec;
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{
    DataFrame, FRAME_HEADER_SIZE, Frame, HeadersFrame, PingFrame, RstStreamFrame, SettingsFrame,
    WindowUpdateFrame,
};
use std::ops::Range;

/// HTTP/2 zero-length DATA frame test sequence
#[derive(Debug, Clone, Arbitrary)]
struct ZeroLengthDataSequence {
    /// Setup frames (SETTINGS, HEADERS, etc.)
    setup_frames: Vec<SetupFrame>,
    /// Zero-length DATA frame configurations
    data_frames: Vec<ZeroLengthDataFrame>,
    /// Additional frames to interleave
    interleaved_frames: Vec<InterleavedFrame>,
}

/// Setup frame types for establishing streams
#[derive(Debug, Clone, Arbitrary)]
enum SetupFrame {
    Settings,
    Headers { stream_id: u32, end_headers: bool },
    WindowUpdate { stream_id: u32, increment: u32 },
}

/// Zero-length DATA frame configuration
#[derive(Debug, Clone, Arbitrary)]
struct ZeroLengthDataFrame {
    stream_id: u32,
    end_stream: bool,
    padded: bool,
    padding_length: u8, // Only used if padded=true, but payload is still zero
}

/// Frames to interleave between DATA frames
#[derive(Debug, Clone, Arbitrary)]
enum InterleavedFrame {
    Ping { ack: bool },
    WindowUpdate { stream_id: u32, increment: u32 },
    Settings { ack: bool },
    RstStream { stream_id: u32, error_code: u8 },
}

/// Processing state to detect infinite loops
#[derive(Debug)]
struct ProcessingState {
    frames_processed: usize,
    max_iterations: usize,
    start_time: std::time::Instant,
    timeout: std::time::Duration,
}

impl ProcessingState {
    fn new() -> Self {
        Self {
            frames_processed: 0,
            max_iterations: 10_000,
            start_time: std::time::Instant::now(),
            timeout: std::time::Duration::from_millis(100), // 100ms timeout
        }
    }

    fn check_infinite_loop(&mut self) -> bool {
        self.frames_processed += 1;

        // Check iteration count
        if self.frames_processed > self.max_iterations {
            return true;
        }

        // Check time elapsed
        if self.start_time.elapsed() > self.timeout {
            return true;
        }

        false
    }
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input size
    if data.len() > 50_000 {
        return;
    }

    let mut u = Unstructured::new(data);

    // Generate test sequence
    let test_seq = match ZeroLengthDataSequence::arbitrary(&mut u) {
        Ok(seq) => seq,
        Err(_) => return,
    };

    // Test the core scenario: zero-length DATA frames should not cause infinite loops
    test_zero_length_data_processing(&test_seq);

    // Test variations with different frame interleavings
    test_interleaved_zero_length_data(&test_seq);
});

fn observe_encode(
    codec: &mut FrameCodec,
    frame: Frame,
    buffer: &mut BytesMut,
    context: &str,
) -> Result<Range<usize>, String> {
    let before_len = buffer.len();
    match codec.encode(frame, buffer) {
        Ok(()) => {
            assert!(
                buffer.len() >= before_len + FRAME_HEADER_SIZE,
                "{context} encode succeeded without a complete HTTP/2 frame header"
            );
            Ok(before_len..buffer.len())
        }
        Err(err) => {
            assert!(
                buffer.len() >= before_len,
                "{context} encode shrank the output buffer on error"
            );
            let diagnostic = err.to_string();
            assert!(
                !diagnostic.trim().is_empty(),
                "{context} encode error should expose a diagnostic"
            );
            Err(diagnostic)
        }
    }
}

fn encoded_payload_len(encoded: &[u8]) -> usize {
    assert!(
        encoded.len() >= FRAME_HEADER_SIZE,
        "encoded frame slice shorter than HTTP/2 frame header"
    );
    ((encoded[0] as usize) << 16) | ((encoded[1] as usize) << 8) | encoded[2] as usize
}

fn encoded_stream_id(encoded: &[u8]) -> u32 {
    u32::from_be_bytes([encoded[5] & 0x7f, encoded[6], encoded[7], encoded[8]])
}

fn assert_zero_length_data_encoding(encoded: &[u8], data_frame: &ZeroLengthDataFrame) {
    let payload_length = encoded_payload_len(encoded);
    assert_eq!(
        encoded.len(),
        FRAME_HEADER_SIZE + payload_length,
        "encoded DATA frame length must match its header length"
    );
    assert_eq!(encoded[3], 0x0, "zero-length test must encode a DATA frame");
    assert_eq!(
        encoded_stream_id(encoded),
        normalize_stream_id(data_frame.stream_id),
        "encoded DATA stream id should match normalized fuzz input"
    );
    assert_eq!(
        encoded[4] & 0x1 != 0,
        data_frame.end_stream,
        "encoded DATA END_STREAM flag should match fuzz input"
    );

    if data_frame.padded {
        assert_eq!(
            payload_length,
            usize::from(data_frame.padding_length) + 1,
            "synthetic padded zero-length DATA payload should contain pad length plus padding"
        );
    } else {
        assert_eq!(
            payload_length, 0,
            "non-padded zero-length DATA frame should have payload length 0"
        );
    }
}

/// Core test: zero-length DATA frames should be processed correctly without infinite loops
fn test_zero_length_data_processing(test_seq: &ZeroLengthDataSequence) {
    let mut codec = FrameCodec::new();
    let mut buffer = BytesMut::new();
    let mut state = ProcessingState::new();

    // Send setup frames first
    for setup_frame in &test_seq.setup_frames {
        if let Ok(frame) = create_setup_frame(setup_frame) {
            let _encode_result = observe_encode(&mut codec, frame, &mut buffer, "setup frame");
        }

        if state.check_infinite_loop() {
            panic!(
                "Infinite loop detected during setup phase after {} frames",
                state.frames_processed
            );
        }
    }

    // Send zero-length DATA frames
    for data_frame in &test_seq.data_frames {
        let frame = create_zero_length_data_frame(data_frame);

        match observe_encode(&mut codec, frame, &mut buffer, "zero-length DATA frame") {
            Ok(encoded_range) => {
                // Frame should be processed correctly
                assert_zero_length_data_encoding(&buffer[encoded_range], data_frame);
            }
            Err(_diagnostic) => {
                // Some zero-length DATA frames may be rejected (e.g., on closed streams)
                // This is acceptable behavior
            }
        }

        if state.check_infinite_loop() {
            panic!(
                "Infinite loop detected during zero-length DATA frame processing after {} frames",
                state.frames_processed
            );
        }
    }

    // Verify we didn't get stuck in processing
    assert!(
        state.frames_processed < state.max_iterations,
        "Processing took too many iterations: {}",
        state.frames_processed
    );
}

/// Test zero-length DATA frames interleaved with other frame types
fn test_interleaved_zero_length_data(test_seq: &ZeroLengthDataSequence) {
    let mut codec = FrameCodec::new();
    let mut buffer = BytesMut::new();
    let mut state = ProcessingState::new();
    let mut encoded_frames = 0usize;

    // Interleave DATA frames with other frames
    let max_frames = test_seq
        .data_frames
        .len()
        .max(test_seq.interleaved_frames.len());

    for i in 0..max_frames {
        // Send an interleaved frame if available
        let interleaved_frame = test_seq
            .interleaved_frames
            .get(i)
            .and_then(|frame| create_interleaved_frame(frame).ok());
        if let Some(frame) = interleaved_frame {
            encoded_frames +=
                usize::from(observe_encode(&mut codec, frame, &mut buffer, "interleaved frame").is_ok());
        }

        // Send a zero-length DATA frame if available
        if i < test_seq.data_frames.len() {
            let data_frame = create_zero_length_data_frame(&test_seq.data_frames[i]);
            if let Ok(encoded_range) =
                observe_encode(&mut codec, data_frame, &mut buffer, "interleaved DATA frame")
            {
                encoded_frames += 1;
                assert_zero_length_data_encoding(&buffer[encoded_range], &test_seq.data_frames[i]);
            }
        }

        if state.check_infinite_loop() {
            panic!(
                "Infinite loop detected during interleaved processing after {} frames",
                state.frames_processed
            );
        }
    }

    // Verify final buffer state
    assert!(
        buffer.len() >= encoded_frames * FRAME_HEADER_SIZE,
        "Buffer should contain at least one complete header per successfully encoded frame"
    );
}

/// Create setup frames for stream establishment
fn create_setup_frame(setup: &SetupFrame) -> Result<Frame, Box<dyn std::error::Error>> {
    match setup {
        SetupFrame::Settings => Ok(Frame::Settings(SettingsFrame::new(Vec::new()))),
        SetupFrame::Headers {
            stream_id,
            end_headers,
        } => {
            let normalized_stream_id = normalize_stream_id(*stream_id);
            let header_block = Bytes::from_static(b"\x00\x00\x00\x00"); // Minimal HPACK block

            Ok(Frame::Headers(HeadersFrame {
                stream_id: normalized_stream_id,
                header_block,
                end_stream: false,
                end_headers: *end_headers,
                priority: None,
            }))
        }
        SetupFrame::WindowUpdate {
            stream_id,
            increment,
        } => {
            let normalized_increment = if *increment == 0 { 1 } else { *increment };
            Ok(Frame::WindowUpdate(WindowUpdateFrame::new(
                normalize_stream_id(*stream_id),
                normalized_increment,
            )))
        }
    }
}

/// Create zero-length DATA frame
fn create_zero_length_data_frame(data_config: &ZeroLengthDataFrame) -> Frame {
    let stream_id = normalize_stream_id(data_config.stream_id);

    if data_config.padded {
        // Padded DATA frame with zero-length payload but padding
        let padding_length = data_config.padding_length;
        let mut padded_payload = vec![padding_length]; // Padding length field
        padded_payload.extend(vec![0u8; padding_length as usize]); // Padding bytes

        Frame::Data(DataFrame::new(
            stream_id,
            padded_payload.into(),
            data_config.end_stream,
        ))
    } else {
        // Pure zero-length DATA frame
        Frame::Data(DataFrame::new(
            stream_id,
            Bytes::new(), // Zero-length data
            data_config.end_stream,
        ))
    }
}

/// Create interleaved frames
fn create_interleaved_frame(
    interleaved: &InterleavedFrame,
) -> Result<Frame, Box<dyn std::error::Error>> {
    match interleaved {
        InterleavedFrame::Ping { ack } => {
            let ping_data = [0u8; 8];
            if *ack {
                Ok(Frame::Ping(PingFrame::ack(ping_data)))
            } else {
                Ok(Frame::Ping(PingFrame::new(ping_data)))
            }
        }
        InterleavedFrame::WindowUpdate {
            stream_id,
            increment,
        } => {
            let normalized_increment = if *increment == 0 { 1 } else { *increment };
            Ok(Frame::WindowUpdate(WindowUpdateFrame::new(
                normalize_stream_id(*stream_id),
                normalized_increment,
            )))
        }
        InterleavedFrame::Settings { ack } => {
            if *ack {
                Ok(Frame::Settings(SettingsFrame::ack()))
            } else {
                Ok(Frame::Settings(SettingsFrame::new(Vec::new())))
            }
        }
        InterleavedFrame::RstStream {
            stream_id,
            error_code,
        } => {
            let normalized_stream_id = normalize_stream_id(*stream_id);
            if normalized_stream_id == 0 {
                return Err("RST_STREAM on stream 0".into());
            }

            let error = match *error_code % 4 {
                0 => ErrorCode::NoError,
                1 => ErrorCode::Cancel,
                2 => ErrorCode::StreamClosed,
                _ => ErrorCode::InternalError,
            };

            Ok(Frame::RstStream(RstStreamFrame::new(
                normalized_stream_id,
                error,
            )))
        }
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
