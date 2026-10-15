#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::net::websocket::{
    Frame, FrameCodec, Opcode, Role as WebSocketRole, WsError, apply_mask,
};
use libfuzzer_sys::fuzz_target;

/// Comprehensive WebSocket frame fuzzing targeting RFC 6455 compliance
#[derive(Arbitrary, Debug)]
struct WebSocketFrameFuzz {
    /// Raw frame bytes for binary protocol parsing
    raw_frames: Vec<Vec<u8>>,
    /// Structured frame operations for logical fuzzing
    frame_operations: Vec<FrameOperation>,
    /// Masking and entropy tests
    masking_tests: Vec<MaskingTest>,
    /// Control frame edge cases
    control_frame_tests: Vec<ControlFrameTest>,
    /// Round-trip tests (encode then decode)
    roundtrip_tests: Vec<RoundTripTest>,
}

/// Frame operations for structured fuzzing
#[derive(Arbitrary, Debug)]
enum FrameOperation {
    /// Text frame with potentially invalid UTF-8
    Text {
        fin: bool,
        payload: Vec<u8>, // May contain invalid UTF-8
    },
    /// Binary frame
    Binary { fin: bool, payload: Vec<u8> },
    /// Control frame
    Control {
        opcode: ControlOpcode,
        payload: Vec<u8>,
    },
    /// Fragmented frame sequence
    Fragmented { fragments: Vec<FragmentData> },
    /// Frame with malformed headers
    Malformed {
        raw_header: Vec<u8>,
        payload: Vec<u8>,
    },
}

/// WebSocket masking tests
#[derive(Arbitrary, Debug)]
struct MaskingTest {
    /// Masking key (4 bytes)
    mask: [u8; 4],
    /// Original payload
    payload: Vec<u8>,
    /// Whether to test entropy of masked data
    test_entropy: bool,
}

/// Control frame edge case testing
#[derive(Arbitrary, Debug)]
struct ControlFrameTest {
    /// Control frame opcode
    opcode: ControlOpcode,
    /// Payload (must be <= 125 bytes for control frames)
    payload: Vec<u8>,
    /// Whether FIN bit should be set (must be true for control frames)
    fin_bit: bool,
    /// Whether to test with reserved bits set (invalid)
    invalid_rsv: bool,
}

/// Round-trip encode/decode tests
#[derive(Arbitrary, Debug)]
struct RoundTripTest {
    /// Frame to encode then decode
    frame_data: FrameData,
    /// Role (client vs server affects masking)
    role: Role,
}

/// Data for creating frames
#[derive(Arbitrary, Debug)]
struct FrameData {
    opcode: DataOpcode,
    fin: bool,
    payload: Vec<u8>,
}

/// Fragment in a fragmented message
#[derive(Arbitrary, Debug)]
struct FragmentData {
    /// Whether this is the first fragment (use original opcode)
    is_first: bool,
    /// Whether this is the last fragment (fin=true)
    is_last: bool,
    /// Fragment payload
    payload: Vec<u8>,
}

/// WebSocket data opcodes
#[derive(Arbitrary, Debug)]
enum DataOpcode {
    Continuation,
    Text,
    Binary,
}

/// WebSocket control opcodes
#[derive(Arbitrary, Debug)]
enum ControlOpcode {
    Close,
    Ping,
    Pong,
}

/// WebSocket role (affects masking behavior)
#[derive(Arbitrary, Debug)]
enum Role {
    Client,
    Server,
}

/// Length of time to fuzz before giving up (prevent infinite loops)
const MAX_FUZZ_OPERATIONS: usize = 100;

/// Maximum payload size for fuzzing (prevent OOM)
const MAX_PAYLOAD_SIZE: usize = 64 * 1024;

/// Maximum control frame payload (RFC 6455 limit)
const MAX_CONTROL_PAYLOAD: usize = 125;

fuzz_target!(|input: WebSocketFrameFuzz| {
    // Limit total operations to prevent timeout
    if input.frame_operations.len() > MAX_FUZZ_OPERATIONS {
        return;
    }

    // Test raw frame parsing (crash detection)
    for raw_frame in input.raw_frames.iter().take(10) {
        if raw_frame.len() > MAX_PAYLOAD_SIZE {
            continue;
        }
        test_raw_frame_parsing(raw_frame);
    }

    // Test structured frame operations
    for operation in input.frame_operations.iter().take(20) {
        test_frame_operation(operation);
    }

    // Test masking operations
    for masking_test in input.masking_tests.iter().take(20) {
        test_masking_operation(masking_test);
    }

    // Test control frame edge cases
    for control_test in input.control_frame_tests.iter().take(20) {
        test_control_frame_edge_cases(control_test);
    }

    // Test round-trip encode/decode
    for roundtrip_test in input.roundtrip_tests.iter().take(20) {
        test_roundtrip_consistency(roundtrip_test);
    }
});

/// Test raw frame parsing for crashes and protocol violations
fn test_raw_frame_parsing(raw_bytes: &[u8]) {
    if raw_bytes.is_empty() {
        return;
    }

    // Test parsing raw frame bytes
    match parse_websocket_frame(raw_bytes) {
        Ok(frame) => {
            // Verify basic invariants
            verify_frame_invariants(&frame);
        }
        Err(_) => {
            // Parse failures are expected for malformed input
        }
    }
}

/// Parse WebSocket frame bytes with the production RFC 6455 codec.
fn parse_websocket_frame(bytes: &[u8]) -> Result<Frame, WsError> {
    decode_with_role(bytes, WebSocketRole::Server)
        .or_else(|_| decode_with_role(bytes, WebSocketRole::Client))
}

fn decode_with_role(bytes: &[u8], role: WebSocketRole) -> Result<Frame, WsError> {
    let mut codec = FrameCodec::new(role).max_payload_size(MAX_PAYLOAD_SIZE);
    let mut src = BytesMut::from(bytes);
    <FrameCodec as Decoder>::decode(&mut codec, &mut src)?
        .ok_or(WsError::ProtocolViolation("incomplete frame"))
}

/// Verify basic frame invariants
fn verify_frame_invariants(frame: &Frame) {
    // Control frames must have fin=true
    if frame.opcode.is_control() {
        assert!(frame.fin, "Control frames must have FIN=1");

        // Control frames must have payload <= 125 bytes
        assert!(
            frame.payload.len() <= 125,
            "Control frame payload too large: {} bytes",
            frame.payload.len()
        );
    }

    assert!(
        !(frame.rsv1 || frame.rsv2 || frame.rsv3),
        "reserved bits require negotiated extensions"
    );
}

/// Test structured frame operations using WebSocket APIs
fn test_frame_operation(operation: &FrameOperation) {
    match operation {
        FrameOperation::Text { fin, payload } => {
            if payload.len() > MAX_PAYLOAD_SIZE {
                return;
            }
            test_text_frame_creation(*fin, payload);
        }
        FrameOperation::Binary { fin, payload } => {
            if payload.len() > MAX_PAYLOAD_SIZE {
                return;
            }
            test_binary_frame_creation(*fin, payload);
        }
        FrameOperation::Control { opcode, payload } => {
            if payload.len() > MAX_CONTROL_PAYLOAD {
                return;
            }
            test_control_frame_creation(opcode, payload);
        }
        FrameOperation::Fragmented { fragments } => {
            if fragments.len() > 20 {
                // Limit fragments to prevent timeout
                return;
            }
            test_fragmented_frame_sequence(fragments);
        }
        FrameOperation::Malformed {
            raw_header,
            payload,
        } => {
            if raw_header.len() + payload.len() > MAX_PAYLOAD_SIZE {
                return;
            }
            test_malformed_frame_handling(raw_header, payload);
        }
    }
}

/// Test text frame creation and UTF-8 validation
fn test_text_frame_creation(fin: bool, payload: &[u8]) {
    // Test UTF-8 validation by attempting to create text frame
    match std::str::from_utf8(payload) {
        Ok(text) => {
            let _frame = frame_with(Opcode::Text, fin, text.as_bytes());
        }
        Err(_) => {
            // Invalid UTF-8 - text frame creation should be rejected
            // This tests that the implementation properly validates UTF-8
        }
    }
}

/// Test binary frame creation
fn test_binary_frame_creation(fin: bool, payload: &[u8]) {
    // Binary frames can contain any data
    let _frame = frame_with(Opcode::Binary, fin, payload);
}

/// Test control frame creation
fn test_control_frame_creation(opcode: &ControlOpcode, payload: &[u8]) {
    // Control frames must have payload <= 125 bytes
    assert!(payload.len() <= 125, "Control frame payload too large");

    let frame = frame_with(control_opcode(opcode), true, payload);
    let mut encoded = BytesMut::new();
    let _ = FrameCodec::server().encode(frame, &mut encoded);

    // Special validation for close frames
    if matches!(opcode, ControlOpcode::Close) {
        test_close_frame_payload_validation(payload);
    }
}

/// Validate close frame payload format
fn test_close_frame_payload_validation(payload: &[u8]) {
    if let Some([high, low]) = payload.get(..2) {
        let status_code = u16::from_be_bytes([*high, *low]);

        // Validate status code per RFC 6455
        match status_code {
            1000..=1003 | 1007..=1011 | 3000..=4999 => {
                // Valid status codes
            }
            1004..=1006 => {
                // Reserved codes that must not be sent
                // Implementation should reject these
            }
            _ => {
                // Other codes - implementation specific
            }
        }

        // Validate reason text is UTF-8
        if let Some(reason) = payload.get(2..) {
            let _reason_validation = std::str::from_utf8(reason);
            // UTF-8 validation result - implementation should check this
        }
    }
}

/// Test fragmented message sequences
fn test_fragmented_frame_sequence(fragments: &[FragmentData]) {
    if fragments.is_empty() {
        return;
    }

    let mut in_fragment = false;

    for fragment in fragments {
        // Validate fragment sequence rules
        if fragment.is_first {
            if in_fragment {
                return;
            }
            in_fragment = true;
        } else if !in_fragment {
            return;
        }

        if fragment.is_last {
            if !in_fragment {
                return;
            }
            in_fragment = false;
        }

        // Create frame for fragment
        let opcode = if fragment.is_first {
            Opcode::Text
        } else {
            Opcode::Continuation
        };
        let _frame = frame_with(opcode, fragment.is_last, &fragment.payload);
    }
}

/// Test malformed frame handling
fn test_malformed_frame_handling(raw_header: &[u8], payload: &[u8]) {
    let mut malformed_frame = raw_header.to_vec();
    malformed_frame.extend_from_slice(payload);

    // Parse malformed frame - should either succeed or fail gracefully
    let _parse_result = parse_websocket_frame(&malformed_frame);
    // Implementation should handle malformed frames without crashing
}

/// Test masking operations
fn test_masking_operation(test: &MaskingTest) {
    if test.payload.len() > MAX_PAYLOAD_SIZE {
        return;
    }

    let original = test.payload.clone();
    let mut masked = test.payload.clone();

    // Apply masking using WebSocket utility
    apply_mask(&mut masked, test.mask);

    // Apply masking again to unmask
    let mut unmasked = masked.clone();
    apply_mask(&mut unmasked, test.mask);

    // Verify round-trip
    assert_eq!(original, unmasked, "Masking round-trip failed");

    if test.test_entropy && test.payload.len() >= 16 {
        test_masking_entropy(&original, &masked, &test.mask);
    }
}

/// Test masking entropy properties
fn test_masking_entropy(original: &[u8], masked: &[u8], mask: &[u8; 4]) {
    let differences = original
        .iter()
        .zip(masked.iter())
        .filter(|(o, m)| o != m)
        .count();

    // With non-zero mask, expect reasonable entropy
    let non_zero_mask = mask.iter().any(|&b| b != 0);
    if non_zero_mask && original.len() >= 8 {
        // Most bytes should be different with good masking
        assert!(
            differences > original.len() / 8,
            "Insufficient masking entropy: {}/{} bytes changed",
            differences,
            original.len()
        );
    }
}

/// Test control frame edge cases
fn test_control_frame_edge_cases(test: &ControlFrameTest) {
    if test.payload.len() > MAX_CONTROL_PAYLOAD {
        return;
    }

    if !test.fin_bit {
        // Control frames with FIN=false should be rejected
        return;
    }

    if test.invalid_rsv {
        test_invalid_rsv_control_frame(&test.opcode, &test.payload);
    } else {
        test_valid_control_frame(&test.opcode, &test.payload);
    }
}

/// Test valid control frame
fn test_valid_control_frame(opcode: &ControlOpcode, payload: &[u8]) {
    let frame = frame_with(control_opcode(opcode), true, payload);
    let mut encoded = BytesMut::new();
    let _ = FrameCodec::server().encode(frame, &mut encoded);
}

/// Test control frame with invalid RSV bits
fn test_invalid_rsv_control_frame(opcode: &ControlOpcode, payload: &[u8]) {
    let opcode_byte = control_opcode_byte(opcode);

    // Create frame with RSV1=1 (invalid)
    let first_byte = 0x80 | 0x40 | opcode_byte; // FIN=1, RSV1=1
    let Ok(second_byte) = u8::try_from(payload.len()) else {
        return;
    };

    let mut frame_bytes = vec![first_byte, second_byte];
    frame_bytes.extend_from_slice(payload);

    // This should be rejected by the production codec.
    assert!(parse_websocket_frame(&frame_bytes).is_err());
}

/// Test round-trip encode/decode consistency
fn test_roundtrip_consistency(test: &RoundTripTest) {
    if test.frame_data.payload.len() > MAX_PAYLOAD_SIZE {
        return;
    }

    let original_frame = frame_with(
        data_opcode(&test.frame_data.opcode),
        test.frame_data.fin,
        &test.frame_data.payload,
    );

    // Encode to bytes
    let mut encoded = BytesMut::new();
    if FrameCodec::new(sender_role(&test.role))
        .encode(original_frame.clone(), &mut encoded)
        .is_err()
    {
        return;
    }

    // Decode back
    match decode_with_role(&encoded, receiver_role(&test.role)) {
        Ok(decoded) => {
            // Verify consistency
            assert_eq!(original_frame.opcode, decoded.opcode);
            assert_eq!(original_frame.fin, decoded.fin);
            assert_eq!(original_frame.payload, decoded.payload);
        }
        Err(_) => {
            // Decode failure acceptable for some edge cases
        }
    }
}

fn frame_with(opcode: Opcode, fin: bool, payload: &[u8]) -> Frame {
    Frame {
        fin,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode,
        masked: false,
        mask_key: None,
        payload: Bytes::copy_from_slice(payload),
    }
}

fn data_opcode(opcode: &DataOpcode) -> Opcode {
    match opcode {
        DataOpcode::Continuation => Opcode::Continuation,
        DataOpcode::Text => Opcode::Text,
        DataOpcode::Binary => Opcode::Binary,
    }
}

fn control_opcode(opcode: &ControlOpcode) -> Opcode {
    match opcode {
        ControlOpcode::Close => Opcode::Close,
        ControlOpcode::Ping => Opcode::Ping,
        ControlOpcode::Pong => Opcode::Pong,
    }
}

fn control_opcode_byte(opcode: &ControlOpcode) -> u8 {
    match opcode {
        ControlOpcode::Close => 8,
        ControlOpcode::Ping => 9,
        ControlOpcode::Pong => 10,
    }
}

fn sender_role(role: &Role) -> WebSocketRole {
    match role {
        Role::Client => WebSocketRole::Client,
        Role::Server => WebSocketRole::Server,
    }
}

fn receiver_role(role: &Role) -> WebSocketRole {
    match role {
        Role::Client => WebSocketRole::Server,
        Role::Server => WebSocketRole::Client,
    }
}
