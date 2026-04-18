//! HTTP/2 CONTINUATION frame flood fuzz target (RFC 9113 §6.10).
//!
//! This target fuzzes CONTINUATION frame sequences to test the HTTP/2 frame parser's
//! handling of header block fragmentation and state machine invariants.
//!
//! # CONTINUATION Frame Invariants Tested (RFC 9113 §6.10)
//! 1. CONTINUATION frames MUST only follow HEADERS, PUSH_PROMISE, or CONTINUATION
//! 2. END_HEADERS flag on final CONTINUATION terminates the header block sequence
//! 3. Stream ID MUST match the preceding HEADERS/PUSH_PROMISE/CONTINUATION frame
//! 4. Oversized contiguous header blocks MUST be rejected per SETTINGS_MAX_HEADER_LIST_SIZE
//! 5. CONTINUATION frames on Stream ID 0 MUST trigger PROTOCOL_ERROR
//!
//! # Attack Scenarios Covered
//! - CONTINUATION flood: sending many CONTINUATION frames without END_HEADERS
//! - Stream ID mismatches: changing stream ID mid-sequence
//! - Orphaned CONTINUATION: sending CONTINUATION without preceding HEADERS
//! - Oversized header accumulation: testing memory exhaustion via large aggregated blocks
//! - Malformed flag combinations: invalid flag usage on CONTINUATION frames
//! - Connection-level CONTINUATION: sending CONTINUATION on stream ID 0
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run h2_continuation -- -runs=1000000
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::frame::{
    parse_frame, ContinuationFrame, Frame, FrameHeader, FrameType, HeadersFrame,
    PushPromiseFrame, SettingValue, SettingsFrame,
    continuation_flags, headers_flags,
    FRAME_HEADER_SIZE, DEFAULT_MAX_FRAME_SIZE,
};
use asupersync::http::h2::error::{ErrorCode, H2Error};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Maximum header list size for testing (16KB default)
const DEFAULT_MAX_HEADER_LIST_SIZE: usize = 16_384;

/// Maximum CONTINUATION flood length to prevent infinite loops
const MAX_CONTINUATION_CHAIN: usize = 1000;

/// CONTINUATION frame fuzzing input structure
#[derive(Arbitrary, Debug, Clone)]
struct ContinuationFuzzInput {
    /// Strategy for generating frame sequences
    strategy: FuzzStrategy,
    /// Configuration for the test scenario
    config: ContinuationFuzzConfig,
    /// Sequence of frame operations
    operations: Vec<FrameOperation>,
}

/// Fuzzing strategies for CONTINUATION frames
#[derive(Arbitrary, Debug, Clone)]
enum FuzzStrategy {
    /// Valid CONTINUATION sequence (baseline)
    ValidSequence,
    /// CONTINUATION flood attack
    ContinuationFlood,
    /// Stream ID mismatch testing
    StreamIdMismatch,
    /// Orphaned CONTINUATION frames
    OrphanedContinuation,
    /// Oversized header accumulation
    OversizedHeaders,
    /// Connection-level CONTINUATION (Stream ID 0)
    ConnectionLevelContinuation,
}

/// Configuration for CONTINUATION fuzzing
#[derive(Arbitrary, Debug, Clone)]
struct ContinuationFuzzConfig {
    /// Maximum header list size setting
    max_header_list_size: u32,
    /// Maximum frame size setting
    max_frame_size: u32,
    /// Base stream ID for testing
    base_stream_id: u32,
}

/// Individual frame operation in the sequence
#[derive(Arbitrary, Debug, Clone)]
enum FrameOperation {
    /// Send initial HEADERS frame
    Headers {
        stream_id: u32,
        header_block: Vec<u8>,
        end_headers: bool,
        flags: u8,
    },
    /// Send PUSH_PROMISE frame
    PushPromise {
        stream_id: u32,
        promised_stream_id: u32,
        header_block: Vec<u8>,
        end_headers: bool,
    },
    /// Send CONTINUATION frame
    Continuation {
        stream_id: u32,
        header_block: Vec<u8>,
        end_headers: bool,
        force_flags: Option<u8>,
    },
    /// Send unrelated frame (DATA, SETTINGS, etc.)
    UnrelatedFrame {
        frame_type: u8,
        stream_id: u32,
        payload: Vec<u8>,
    },
    /// Configure SETTINGS_MAX_HEADER_LIST_SIZE
    UpdateSettings {
        max_header_list_size: Option<u32>,
        max_frame_size: Option<u32>,
    },
    /// Reset parser state
    ResetState,
}

/// State tracker for CONTINUATION frame sequences
#[derive(Debug)]
struct ContinuationState {
    /// Current stream ID expecting CONTINUATION
    expecting_continuation_stream: Option<u32>,
    /// Accumulated header block size
    accumulated_header_size: usize,
    /// Maximum allowed header list size
    max_header_list_size: usize,
    /// Frame sequence for debugging
    frame_sequence: Vec<String>,
    /// Error count for assertion tracking
    error_count: usize,
}

impl ContinuationState {
    fn new(max_header_list_size: usize) -> Self {
        Self {
            expecting_continuation_stream: None,
            accumulated_header_size: 0,
            max_header_list_size,
            frame_sequence: Vec::new(),
            error_count: 0,
        }
    }

    fn reset(&mut self) {
        self.expecting_continuation_stream = None;
        self.accumulated_header_size = 0;
        self.frame_sequence.clear();
    }

    fn is_expecting_continuation(&self) -> bool {
        self.expecting_continuation_stream.is_some()
    }

    fn expected_stream_id(&self) -> Option<u32> {
        self.expecting_continuation_stream
    }
}

fuzz_target!(|input: ContinuationFuzzInput| {
    fuzz_continuation_sequence(input);
});

/// Main fuzzing entry point
fn fuzz_continuation_sequence(input: ContinuationFuzzInput) {
    let max_header_list_size = input.config.max_header_list_size as usize;
    let mut state = ContinuationState::new(max_header_list_size.max(1024));

    // Limit operations to prevent infinite loops
    let operations = input.operations.into_iter().take(MAX_CONTINUATION_CHAIN);

    for operation in operations {
        match input.strategy {
            FuzzStrategy::ValidSequence => fuzz_valid_sequence(&operation, &mut state),
            FuzzStrategy::ContinuationFlood => fuzz_continuation_flood(&operation, &mut state),
            FuzzStrategy::StreamIdMismatch => fuzz_stream_id_mismatch(&operation, &mut state),
            FuzzStrategy::OrphanedContinuation => fuzz_orphaned_continuation(&operation, &mut state),
            FuzzStrategy::OversizedHeaders => fuzz_oversized_headers(&operation, &mut state),
            FuzzStrategy::ConnectionLevelContinuation => {
                fuzz_connection_level_continuation(&operation, &mut state)
            }
        }

        // Prevent excessive accumulation
        if state.error_count > 100 {
            break;
        }
    }
}

/// Test valid CONTINUATION sequences
fn fuzz_valid_sequence(operation: &FrameOperation, state: &mut ContinuationState) {
    match operation {
        FrameOperation::Headers {
            stream_id,
            header_block,
            end_headers,
            flags,
        } => {
            let frame = create_headers_frame(*stream_id, header_block.clone(), *end_headers, *flags);
            let result = test_frame_parsing(&frame, state);

            if !*end_headers {
                state.expecting_continuation_stream = Some(*stream_id);
                state.accumulated_header_size = header_block.len();
            } else {
                state.expecting_continuation_stream = None;
                state.accumulated_header_size = 0;
            }

            log_frame_result("HEADERS", &result, state);
        }
        FrameOperation::Continuation {
            stream_id,
            header_block,
            end_headers,
            force_flags,
        } => {
            // Assertion 1: CONTINUATION only valid after HEADERS/PUSH_PROMISE/CONTINUATION
            let expected_stream = state.expected_stream_id();
            let continuation_after_valid_frame = expected_stream.is_some();

            // Assertion 3: Stream ID must match preceding frame
            let stream_id_matches = expected_stream.map_or(false, |expected| expected == *stream_id);

            let flags = force_flags.unwrap_or(if *end_headers {
                continuation_flags::END_HEADERS
            } else {
                0
            });

            let frame = create_continuation_frame(*stream_id, header_block.clone(), flags);
            let result = test_frame_parsing(&frame, state);

            // Track accumulated size for assertion 4
            state.accumulated_header_size += header_block.len();

            // Assertion 4: Oversized contiguous header block rejected
            let oversized = state.accumulated_header_size > state.max_header_list_size;

            if *end_headers || result.is_err() {
                state.expecting_continuation_stream = None;
                state.accumulated_header_size = 0;
            }

            // Validate assertions
            if !continuation_after_valid_frame {
                assert!(
                    result.is_err(),
                    "Assertion 1 violated: CONTINUATION without preceding HEADERS/PUSH_PROMISE"
                );
            }

            if continuation_after_valid_frame && !stream_id_matches {
                assert!(
                    result.is_err(),
                    "Assertion 3 violated: Stream ID mismatch in CONTINUATION sequence"
                );
            }

            if oversized {
                assert!(
                    result.is_err() || state.accumulated_header_size <= state.max_header_list_size,
                    "Assertion 4 violated: Oversized header block not rejected"
                );
            }

            log_frame_result("CONTINUATION", &result, state);
        }
        _ => {
            // Other operations handled in specific strategy functions
            handle_generic_operation(operation, state);
        }
    }
}

/// Test CONTINUATION flood scenarios
fn fuzz_continuation_flood(operation: &FrameOperation, state: &mut ContinuationState) {
    match operation {
        FrameOperation::Headers { stream_id, header_block, .. } => {
            // Start with HEADERS that doesn't have END_HEADERS
            let frame = create_headers_frame(*stream_id, header_block.clone(), false, 0);
            let _ = test_frame_parsing(&frame, state);

            state.expecting_continuation_stream = Some(*stream_id);
            state.accumulated_header_size = header_block.len();

            // Generate flood of CONTINUATION frames without END_HEADERS
            for i in 0..100.min(MAX_CONTINUATION_CHAIN) {
                let continuation_data = vec![0xAB; i % 256 + 1]; // Varying sizes
                let frame = create_continuation_frame(*stream_id, continuation_data.clone(), 0);
                let result = test_frame_parsing(&frame, state);

                state.accumulated_header_size += continuation_data.len();

                // Should eventually reject due to size limits
                if state.accumulated_header_size > state.max_header_list_size {
                    assert!(
                        result.is_err(),
                        "CONTINUATION flood not rejected at size {}",
                        state.accumulated_header_size
                    );
                    break;
                }
            }

            log_frame_result("CONTINUATION_FLOOD", &Ok(()), state);
        }
        _ => fuzz_valid_sequence(operation, state),
    }
}

/// Test stream ID mismatch scenarios
fn fuzz_stream_id_mismatch(operation: &FrameOperation, state: &mut ContinuationState) {
    match operation {
        FrameOperation::Headers { stream_id, header_block, .. } => {
            // Start normal sequence
            let frame = create_headers_frame(*stream_id, header_block.clone(), false, 0);
            let _ = test_frame_parsing(&frame, state);
            state.expecting_continuation_stream = Some(*stream_id);

            // Send CONTINUATION with different stream ID (assertion 3)
            let wrong_stream_id = stream_id.wrapping_add(2);
            let continuation_frame =
                create_continuation_frame(wrong_stream_id, vec![0x01, 0x02], continuation_flags::END_HEADERS);
            let result = test_frame_parsing(&continuation_frame, state);

            assert!(
                result.is_err(),
                "Stream ID mismatch not detected: expected {}, got {}",
                stream_id,
                wrong_stream_id
            );

            log_frame_result("STREAM_MISMATCH", &result, state);
        }
        _ => fuzz_valid_sequence(operation, state),
    }
}

/// Test orphaned CONTINUATION frames
fn fuzz_orphaned_continuation(operation: &FrameOperation, state: &mut ContinuationState) {
    if let FrameOperation::Continuation { stream_id, header_block, end_headers, .. } = operation {
        // Send CONTINUATION without preceding HEADERS (assertion 1)
        state.expecting_continuation_stream = None; // Ensure no expectation

        let frame = create_continuation_frame(
            *stream_id,
            header_block.clone(),
            if *end_headers { continuation_flags::END_HEADERS } else { 0 },
        );
        let result = test_frame_parsing(&frame, state);

        assert!(
            result.is_err(),
            "Orphaned CONTINUATION not rejected on stream {}",
            stream_id
        );

        log_frame_result("ORPHANED_CONTINUATION", &result, state);
    } else {
        fuzz_valid_sequence(operation, state);
    }
}

/// Test oversized header accumulation
fn fuzz_oversized_headers(operation: &FrameOperation, state: &mut ContinuationState) {
    match operation {
        FrameOperation::Headers { stream_id, .. } => {
            // Start with large initial header block
            let large_header = vec![0xFF; state.max_header_list_size / 2];
            let frame = create_headers_frame(*stream_id, large_header.clone(), false, 0);
            let _ = test_frame_parsing(&frame, state);

            state.expecting_continuation_stream = Some(*stream_id);
            state.accumulated_header_size = large_header.len();

            // Add CONTINUATION that pushes over the limit
            let oversized_continuation = vec![0xAA; state.max_header_list_size];
            let continuation_frame = create_continuation_frame(
                *stream_id,
                oversized_continuation,
                continuation_flags::END_HEADERS,
            );
            let result = test_frame_parsing(&continuation_frame, state);

            // Assertion 4: Should reject oversized header block
            assert!(
                result.is_err(),
                "Oversized header block not rejected: accumulated {} > limit {}",
                state.accumulated_header_size + oversized_continuation.len(),
                state.max_header_list_size
            );

            log_frame_result("OVERSIZED_HEADERS", &result, state);
        }
        _ => fuzz_valid_sequence(operation, state),
    }
}

/// Test CONTINUATION on connection-level stream (Stream ID 0)
fn fuzz_connection_level_continuation(operation: &FrameOperation, state: &mut ContinuationState) {
    if let FrameOperation::Continuation { header_block, end_headers, .. } = operation {
        // Assertion 5: CONTINUATION on Stream ID 0 triggers PROTOCOL_ERROR
        let frame = create_continuation_frame(
            0, // Stream ID 0 (connection-level)
            header_block.clone(),
            if *end_headers { continuation_flags::END_HEADERS } else { 0 },
        );
        let result = test_frame_parsing(&frame, state);

        assert!(
            result.is_err(),
            "CONTINUATION on stream ID 0 not rejected"
        );

        // Verify it's specifically a PROTOCOL_ERROR
        if let Err(H2Error { code: ErrorCode::ProtocolError, .. }) = result {
            // Expected
        } else {
            panic!("CONTINUATION on stream ID 0 should trigger PROTOCOL_ERROR, got {:?}", result);
        }

        log_frame_result("CONNECTION_LEVEL_CONTINUATION", &result, state);
    } else {
        fuzz_valid_sequence(operation, state);
    }
}

/// Handle generic frame operations
fn handle_generic_operation(operation: &FrameOperation, state: &mut ContinuationState) {
    match operation {
        FrameOperation::PushPromise {
            stream_id,
            promised_stream_id,
            header_block,
            end_headers,
        } => {
            let frame = create_push_promise_frame(*stream_id, *promised_stream_id, header_block.clone(), *end_headers);
            let result = test_frame_parsing(&frame, state);

            if !*end_headers {
                state.expecting_continuation_stream = Some(*stream_id);
                state.accumulated_header_size = header_block.len();
            }

            log_frame_result("PUSH_PROMISE", &result, state);
        }
        FrameOperation::UnrelatedFrame { frame_type, stream_id, payload } => {
            // Send frame that should interrupt CONTINUATION sequence
            if state.is_expecting_continuation() {
                let frame = create_generic_frame(*frame_type, *stream_id, payload.clone());
                let _ = test_frame_parsing(&frame, state);
                // This should break the CONTINUATION sequence expectation
                state.expecting_continuation_stream = None;
                state.accumulated_header_size = 0;
            }
        }
        FrameOperation::ResetState => {
            state.reset();
        }
        FrameOperation::UpdateSettings { max_header_list_size, .. } => {
            if let Some(size) = max_header_list_size {
                state.max_header_list_size = (*size as usize).max(1024);
            }
        }
        _ => {} // Already handled in strategy-specific functions
    }
}

/// Create a HEADERS frame
fn create_headers_frame(stream_id: u32, header_block: Vec<u8>, end_headers: bool, extra_flags: u8) -> Frame {
    Frame::Headers(HeadersFrame {
        stream_id,
        header_block: Bytes::copy_from_slice(&header_block),
        end_headers,
        end_stream: (extra_flags & headers_flags::END_STREAM) != 0,
        priority: None,
    })
}

/// Create a CONTINUATION frame
fn create_continuation_frame(stream_id: u32, header_block: Vec<u8>, flags: u8) -> Frame {
    Frame::Continuation(ContinuationFrame {
        stream_id,
        header_block: Bytes::copy_from_slice(&header_block),
        end_headers: (flags & continuation_flags::END_HEADERS) != 0,
    })
}

/// Create a PUSH_PROMISE frame
fn create_push_promise_frame(
    stream_id: u32,
    promised_stream_id: u32,
    header_block: Vec<u8>,
    end_headers: bool,
) -> Frame {
    Frame::PushPromise(PushPromiseFrame {
        stream_id,
        promised_stream_id,
        header_block: Bytes::copy_from_slice(&header_block),
        end_headers,
    })
}

/// Create a generic frame for testing interruption
fn create_generic_frame(frame_type: u8, stream_id: u32, payload: Vec<u8>) -> Frame {
    Frame::Unknown {
        frame_type,
        stream_id,
        payload: Bytes::copy_from_slice(&payload),
    }
}

/// Test frame parsing and return result
fn test_frame_parsing(frame: &Frame, state: &mut ContinuationState) -> Result<(), H2Error> {
    // Encode the frame to bytes
    let mut buf = BytesMut::new();
    frame.encode(&mut buf);

    // Parse the frame header
    if buf.len() < FRAME_HEADER_SIZE {
        return Err(H2Error::protocol("frame too small"));
    }

    let header = FrameHeader::parse(&mut buf).map_err(|e| {
        state.error_count += 1;
        e
    })?;

    let payload = buf.freeze();

    // Parse the complete frame
    parse_frame(&header, payload).map(|_| ()).map_err(|e| {
        state.error_count += 1;
        e
    })
}

/// Log frame parsing result for debugging
fn log_frame_result(frame_type: &str, result: &Result<(), H2Error>, state: &mut ContinuationState) {
    let status = if result.is_ok() { "OK" } else { "ERR" };
    let sequence_entry = format!("{}:{}", frame_type, status);
    state.frame_sequence.push(sequence_entry);

    // Limit sequence length to prevent memory exhaustion
    if state.frame_sequence.len() > 1000 {
        state.frame_sequence.drain(..500);
    }
}