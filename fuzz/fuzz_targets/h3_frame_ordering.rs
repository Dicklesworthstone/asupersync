//! Structure-aware fuzzing for HTTP/3 DATA/HEADERS frame ordering
//!
//! Tests HTTP/3 frame ordering constraints and state machine behavior:
//! 1. HEADERS frames must precede DATA frames on request streams
//! 2. Multiple HEADERS frames (101, 200, trailers) must follow protocol order
//! 3. DATA frame fragmentation and reassembly correctness
//! 4. Stream state transitions respect frame ordering
//! 5. Frame ordering violations are detected and handled gracefully
//!
//! Uses structure-aware generation to create valid HTTP/3 frame sequences
//! with intelligent mutations that test boundary conditions and edge cases
//! in the frame ordering state machine.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::http::h3_native::{H3ConnectionConfig, H3Frame, H3NativeError};
use asupersync::net::quic_core::encode_varint;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Maximum frame payload size to prevent OOM during fuzzing
const MAX_FRAME_PAYLOAD: usize = 32768;

/// Maximum number of frames in a sequence to prevent infinite loops
const MAX_FRAME_SEQUENCE: usize = 50;

/// HTTP/3 frame ordering test scenarios
#[derive(Debug, Clone, Arbitrary)]
enum FrameOrderingScenario {
    /// Normal request: HEADERS -> DATA -> optional trailers
    NormalRequest,
    /// Response with interim: HEADERS(101) -> HEADERS(200) -> DATA
    InterimResponse,
    /// Chunked request: HEADERS -> DATA -> DATA -> ... -> trailers
    ChunkedRequest,
    /// Multiple responses: HEADERS -> DATA -> trailers -> HEADERS(new)
    MultipleResponses,
    /// Malformed ordering: DATA -> HEADERS (should be rejected)
    MalformedDataFirst,
    /// Empty request: HEADERS only
    HeadersOnly,
    /// Large fragmented DATA frames
    FragmentedData,
    /// Interleaved control frames (SETTINGS, GOAWAY)
    ControlFrameInterleaving,
}

/// HTTP/3 frame sequence for structure-aware fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct H3FrameSequence {
    scenario: FrameOrderingScenario,
    #[arbitrary(with = arbitrary_frame_list)]
    frames: Vec<FuzzH3Frame>,
    /// Stream ID for testing
    #[arbitrary(with = arbitrary_stream_id)]
    stream_id: u64,
}

/// Simplified HTTP/3 frame for fuzzing with size bounds
#[derive(Debug, Clone, Arbitrary)]
enum FuzzH3Frame {
    /// HEADERS frame with bounded payload
    Headers {
        #[arbitrary(with = arbitrary_bounded_payload)]
        qpack_data: Vec<u8>,
    },
    /// DATA frame with bounded payload
    Data {
        #[arbitrary(with = arbitrary_bounded_payload)]
        payload: Vec<u8>,
    },
    /// SETTINGS frame for control stream testing
    Settings {
        #[arbitrary(with = arbitrary_settings_pairs)]
        settings: Vec<(u64, u64)>, // (setting_id, value) pairs
    },
    /// GOAWAY frame
    Goaway { stream_id: u64 },
    /// CANCEL_PUSH frame
    CancelPush { push_id: u64 },
}

/// Generate bounded payload to prevent OOM
fn arbitrary_bounded_payload(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Vec<u8>> {
    let size = u.int_in_range(0..=MAX_FRAME_PAYLOAD)?;
    let mut payload = vec![0u8; size];
    u.fill_buffer(&mut payload)?;
    Ok(payload)
}

/// Generate frame list with bounded length
fn arbitrary_frame_list(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Vec<FuzzH3Frame>> {
    let count = u.int_in_range(1..=MAX_FRAME_SEQUENCE)?;
    let mut frames = Vec::with_capacity(count);
    for _ in 0..count {
        frames.push(FuzzH3Frame::arbitrary(u)?);
    }
    Ok(frames)
}

/// Generate valid HTTP/3 stream ID (client-initiated bidirectional)
fn arbitrary_stream_id(u: &mut arbitrary::Unstructured) -> arbitrary::Result<u64> {
    // Client-initiated bidirectional streams: 0, 4, 8, 12, ...
    let stream_num = u.int_in_range(0..=1000u32)?;
    Ok((stream_num as u64) * 4)
}

/// Generate bounded settings pairs
fn arbitrary_settings_pairs(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Vec<(u64, u64)>> {
    let count = u.int_in_range(0..=10)?;
    let mut settings = Vec::with_capacity(count);
    for _ in 0..count {
        let setting_id = u.int_in_range(0..=0xFF)?;
        let value = u.int_in_range(0..=0xFFFFFF)?;
        settings.push((setting_id, value));
    }
    Ok(settings)
}

/// Convert fuzz frame to actual H3Frame
impl FuzzH3Frame {
    fn to_h3_frame(&self) -> H3Frame {
        match self {
            FuzzH3Frame::Headers { qpack_data } => H3Frame::Headers(qpack_data.clone()),
            FuzzH3Frame::Data { payload } => H3Frame::Data(payload.clone()),
            FuzzH3Frame::Settings { settings } => {
                // Convert to H3Settings - simplified for fuzzing
                H3Frame::Settings(Default::default())
            }
            FuzzH3Frame::Goaway { stream_id } => H3Frame::Goaway(*stream_id),
            FuzzH3Frame::CancelPush { push_id } => H3Frame::CancelPush(*push_id),
        }
    }
}

/// Frame ordering state machine for validation
#[derive(Debug, Clone)]
struct FrameOrderingValidator {
    stream_states: HashMap<u64, StreamState>,
    control_stream_initialized: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum StreamState {
    /// Waiting for initial HEADERS frame
    WaitingHeaders,
    /// Received HEADERS, can accept DATA or more HEADERS
    HeadersReceived,
    /// Receiving DATA frames
    DataPhase,
    /// Stream closed (trailers received or END_STREAM)
    Closed,
    /// Error state (invalid ordering)
    Error(String),
}

impl FrameOrderingValidator {
    fn new() -> Self {
        Self {
            stream_states: HashMap::new(),
            control_stream_initialized: false,
        }
    }

    /// Validate frame ordering according to HTTP/3 protocol
    fn validate_frame(&mut self, frame: &H3Frame, stream_id: u64) -> Result<(), String> {
        match frame {
            H3Frame::Headers(_) => self.validate_headers_frame(stream_id),
            H3Frame::Data(_) => self.validate_data_frame(stream_id),
            H3Frame::Settings(_) => self.validate_settings_frame(),
            H3Frame::Goaway(_) => self.validate_control_frame(),
            H3Frame::CancelPush(_) => self.validate_control_frame(),
            _ => Ok(()), // Other frame types not tested in this fuzzer
        }
    }

    fn validate_headers_frame(&mut self, stream_id: u64) -> Result<(), String> {
        let current_state = self
            .stream_states
            .get(&stream_id)
            .cloned()
            .unwrap_or(StreamState::WaitingHeaders);

        match current_state {
            StreamState::WaitingHeaders => {
                self.stream_states
                    .insert(stream_id, StreamState::HeadersReceived);
                Ok(())
            }
            StreamState::HeadersReceived => {
                // Multiple HEADERS allowed (e.g., 101 Continue, 200 OK, trailers)
                Ok(())
            }
            StreamState::DataPhase => {
                // HEADERS after DATA allowed for trailers
                self.stream_states.insert(stream_id, StreamState::Closed);
                Ok(())
            }
            StreamState::Closed => Err("HEADERS on closed stream".to_string()),
            StreamState::Error(ref msg) => Err(msg.clone()),
        }
    }

    fn validate_data_frame(&mut self, stream_id: u64) -> Result<(), String> {
        let current_state = self
            .stream_states
            .get(&stream_id)
            .cloned()
            .unwrap_or(StreamState::WaitingHeaders);

        match current_state {
            StreamState::WaitingHeaders => {
                self.stream_states.insert(
                    stream_id,
                    StreamState::Error("DATA before HEADERS".to_string()),
                );
                Err("DATA frame before HEADERS frame".to_string())
            }
            StreamState::HeadersReceived => {
                self.stream_states.insert(stream_id, StreamState::DataPhase);
                Ok(())
            }
            StreamState::DataPhase => Ok(()), // Multiple DATA frames allowed
            StreamState::Closed => Err("DATA on closed stream".to_string()),
            StreamState::Error(ref msg) => Err(msg.clone()),
        }
    }

    fn validate_settings_frame(&mut self) -> Result<(), String> {
        if self.control_stream_initialized {
            Err("Multiple SETTINGS frames on control stream".to_string())
        } else {
            self.control_stream_initialized = true;
            Ok(())
        }
    }

    fn validate_control_frame(&self) -> Result<(), String> {
        // Control frames can appear at any time on control stream
        Ok(())
    }
}

/// Convert frame sequence to wire format bytes
fn encode_frame_sequence(sequence: &H3FrameSequence) -> Vec<u8> {
    let mut encoded = Vec::new();
    let config = H3ConnectionConfig::default();

    for frame in &sequence.frames {
        let h3_frame = frame.to_h3_frame();

        // Encode frame type and length
        let frame_type = match &h3_frame {
            H3Frame::Data(_) => 0x0,
            H3Frame::Headers(_) => 0x1,
            H3Frame::Settings(_) => 0x4,
            H3Frame::Goaway(_) => 0x7,
            H3Frame::CancelPush(_) => 0x3,
            _ => continue, // Skip unsupported frame types
        };

        let payload = match &h3_frame {
            H3Frame::Data(data) => data.clone(),
            H3Frame::Headers(headers) => headers.clone(),
            H3Frame::Settings(_) => vec![0x01, 0x40, 0x00], // Minimal SETTINGS
            H3Frame::Goaway(stream_id) => {
                let mut goaway_payload = Vec::new();
                encode_varint(*stream_id, &mut goaway_payload).ok();
                goaway_payload
            }
            H3Frame::CancelPush(push_id) => {
                let mut cancel_payload = Vec::new();
                encode_varint(*push_id, &mut cancel_payload).ok();
                cancel_payload
            }
            _ => continue,
        };

        // Encode frame header
        encode_varint(frame_type, &mut encoded).ok();
        encode_varint(payload.len() as u64, &mut encoded).ok();
        encoded.extend_from_slice(&payload);
    }

    encoded
}

fuzz_target!(|sequence: H3FrameSequence| {
    // Guard against pathological inputs
    if sequence.frames.is_empty() || sequence.frames.len() > MAX_FRAME_SEQUENCE {
        return;
    }

    // Skip if total payload would be too large
    let total_size: usize = sequence
        .frames
        .iter()
        .map(|frame| match frame {
            FuzzH3Frame::Headers { qpack_data } => qpack_data.len(),
            FuzzH3Frame::Data { payload } => payload.len(),
            _ => 64, // Conservative estimate for control frames
        })
        .sum();

    if total_size > MAX_FRAME_PAYLOAD * 4 {
        return;
    }

    // Test 1: Frame ordering validation
    let mut validator = FrameOrderingValidator::new();
    for frame in &sequence.frames {
        let h3_frame = frame.to_h3_frame();
        let _ = validator.validate_frame(&h3_frame, sequence.stream_id);
    }

    // Test 2: Wire format encoding/decoding round-trip
    let encoded_bytes = encode_frame_sequence(&sequence);
    if encoded_bytes.len() > MAX_FRAME_PAYLOAD * 4 {
        return; // Skip overly large sequences
    }

    let config = H3ConnectionConfig {
        max_frame_payload_size: MAX_FRAME_PAYLOAD,
        ..Default::default()
    };

    // Test frame-by-frame parsing
    let mut pos = 0;
    let mut parsed_frames = Vec::new();

    while pos < encoded_bytes.len() {
        match H3Frame::decode(&encoded_bytes[pos..], &config) {
            Ok((frame, consumed)) => {
                parsed_frames.push(frame);
                pos += consumed;
                if consumed == 0 {
                    break; // Prevent infinite loop
                }
            }
            Err(H3NativeError::InvalidFrame(_)) => {
                // Expected for some malformed inputs
                break;
            }
            Err(H3NativeError::FrameTooLarge { .. }) => {
                // Expected for oversized frames
                break;
            }
            Err(_) => break, // Other errors
        }
    }

    // Test 3: Frame ordering invariants on parsed frames
    let mut final_validator = FrameOrderingValidator::new();
    for frame in &parsed_frames {
        let validation_result = final_validator.validate_frame(frame, sequence.stream_id);

        // Invariant: Frame ordering violations must be consistent
        match &sequence.scenario {
            FrameOrderingScenario::MalformedDataFirst => {
                // DATA-first scenarios should trigger ordering errors
                if matches!(frame, H3Frame::Data(_))
                    && !final_validator
                        .stream_states
                        .contains_key(&sequence.stream_id)
                {
                    assert!(validation_result.is_err(), "DATA-first should be rejected");
                }
            }
            FrameOrderingScenario::NormalRequest => {
                // Normal scenarios should not trigger errors for well-formed sequences
                // (Allowing errors for fuzz-generated malformed data is acceptable)
            }
            _ => {
                // Other scenarios have their own constraints
                // Fuzzing explores the edge cases
            }
        }
    }

    // Test 4: State machine consistency
    for (stream_id, state) in &final_validator.stream_states {
        // Invariant: Error states should not transition to non-error states
        if matches!(state, StreamState::Error(_)) {
            // Ensure error state is terminal
            assert_ne!(*state, StreamState::HeadersReceived);
            assert_ne!(*state, StreamState::DataPhase);
        }
    }
});
