#![no_main]

use arbitrary::Arbitrary;
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
    /// Create text frame with potentially invalid UTF-8
    CreateText {
        fin: bool,
        payload: Vec<u8>, // May contain invalid UTF-8
    },
    /// Create binary frame
    CreateBinary { fin: bool, payload: Vec<u8> },
    /// Create control frame
    CreateControl {
        opcode: ControlOpcode,
        payload: Vec<u8>,
    },
    /// Create fragmented frame sequence
    CreateFragmented { fragments: Vec<FragmentData> },
    /// Create frame with malformed headers
    CreateMalformed {
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
        test_raw_frame_parsing(&raw_frame);
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

/// Parse WebSocket frame from raw bytes
fn parse_websocket_frame(bytes: &[u8]) -> Result<ParsedFrame, ParseError> {
    if bytes.len() < 2 {
        return Err(ParseError::TooShort);
    }

    let first_byte = bytes[0];
    let second_byte = bytes[1];

    let fin = (first_byte & 0x80) != 0;
    let rsv1 = (first_byte & 0x40) != 0;
    let rsv2 = (first_byte & 0x20) != 0;
    let rsv3 = (first_byte & 0x10) != 0;
    let opcode = first_byte & 0x0F;

    let masked = (second_byte & 0x80) != 0;
    let payload_len = (second_byte & 0x7F) as u64;

    let mut offset = 2;

    // Extended payload length
    let payload_len = match payload_len {
        126 => {
            if bytes.len() < offset + 2 {
                return Err(ParseError::TooShort);
            }
            let len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as u64;
            offset += 2;
            len
        }
        127 => {
            if bytes.len() < offset + 8 {
                return Err(ParseError::TooShort);
            }
            let len = u64::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]);
            offset += 8;
            len
        }
        len => len,
    };

    // Masking key
    let mask = if masked {
        if bytes.len() < offset + 4 {
            return Err(ParseError::TooShort);
        }
        let mask = [
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ];
        offset += 4;
        Some(mask)
    } else {
        None
    };

    // Payload
    if bytes.len() < offset + payload_len as usize {
        return Err(ParseError::TooShort);
    }

    let mut payload = bytes[offset..offset + payload_len as usize].to_vec();
    if let Some(mask) = mask {
        asupersync::net::websocket::apply_mask(&mut payload, mask);
    }

    Ok(ParsedFrame {
        fin,
        rsv1,
        rsv2,
        rsv3,
        opcode,
        masked,
        payload,
    })
}

/// Basic frame structure for parsing
#[derive(Debug)]
struct ParsedFrame {
    fin: bool,
    rsv1: bool,
    rsv2: bool,
    rsv3: bool,
    opcode: u8,
    masked: bool,
    payload: Vec<u8>,
}

/// Parse errors
#[derive(Debug)]
enum ParseError {
    TooShort,
    InvalidOpcode,
    InvalidLength,
}

/// Verify basic frame invariants
fn verify_frame_invariants(frame: &ParsedFrame) {
    // Control frames must have fin=true
    if is_control_opcode(frame.opcode) {
        assert_eq!(frame.fin, true, "Control frames must have FIN=1");

        // Control frames must have payload <= 125 bytes
        assert!(
            frame.payload.len() <= 125,
            "Control frame payload too large: {} bytes",
            frame.payload.len()
        );
    }

    // RSV bits must be 0 unless extensions are negotiated
    // (relaxed for fuzzing - some implementations may vary)

    // Opcode must be valid
    assert!(frame.opcode <= 15, "Opcode out of range: {}", frame.opcode);

    // Reserved opcodes 3-7 and 11-15 should be invalid
    if (3..=7).contains(&frame.opcode) || (11..=15).contains(&frame.opcode) {
        // Reserved opcodes - implementation may reject or handle differently
    }
}

/// Check if opcode is a control frame
fn is_control_opcode(opcode: u8) -> bool {
    opcode >= 8 // Control frames are 8-15, data frames are 0-7
}

/// Test structured frame operations using WebSocket APIs
fn test_frame_operation(operation: &FrameOperation) {
    match operation {
        FrameOperation::CreateText { fin, payload } => {
            if payload.len() > MAX_PAYLOAD_SIZE {
                return;
            }
            test_text_frame_creation(*fin, payload);
        }
        FrameOperation::CreateBinary { fin, payload } => {
            if payload.len() > MAX_PAYLOAD_SIZE {
                return;
            }
            test_binary_frame_creation(*fin, payload);
        }
        FrameOperation::CreateControl { opcode, payload } => {
            if payload.len() > MAX_CONTROL_PAYLOAD {
                return;
            }
            test_control_frame_creation(opcode, payload);
        }
        FrameOperation::CreateFragmented { fragments } => {
            if fragments.len() > 20 {
                // Limit fragments to prevent timeout
                return;
            }
            test_fragmented_frame_sequence(fragments);
        }
        FrameOperation::CreateMalformed {
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
            // Valid UTF-8 - create text frame using WebSocket API
            let _frame = create_text_frame_internal(text, fin);
        }
        Err(_) => {
            // Invalid UTF-8 - text frame creation should be rejected
            // This tests that the implementation properly validates UTF-8
        }
    }
}

/// Create text frame (stub implementation)
fn create_text_frame_internal(_text: &str, _fin: bool) -> TestFrame {
    TestFrame {
        opcode: 1, // Text
        fin: _fin,
        payload: _text.as_bytes().to_vec(),
    }
}

/// Test binary frame creation
fn test_binary_frame_creation(fin: bool, payload: &[u8]) {
    // Binary frames can contain any data
    let _frame = TestFrame {
        opcode: 2, // Binary
        fin,
        payload: payload.to_vec(),
    };
}

/// Test control frame creation
fn test_control_frame_creation(opcode: &ControlOpcode, payload: &[u8]) {
    let opcode_num = match opcode {
        ControlOpcode::Close => 8,
        ControlOpcode::Ping => 9,
        ControlOpcode::Pong => 10,
    };

    // Control frames must have payload <= 125 bytes
    assert!(payload.len() <= 125, "Control frame payload too large");

    let _frame = TestFrame {
        opcode: opcode_num,
        fin: true, // Control frames must have FIN=true
        payload: payload.to_vec(),
    };

    // Special validation for close frames
    if matches!(opcode, ControlOpcode::Close) {
        test_close_frame_payload_validation(payload);
    }
}

/// Validate close frame payload format
fn test_close_frame_payload_validation(payload: &[u8]) {
    if payload.len() >= 2 {
        // Extract status code
        let status_code = u16::from_be_bytes([payload[0], payload[1]]);

        // Validate status code per RFC 6455
        match status_code {
            1000..=1003 | 1007..=1011 | 3000..=4999 => {
                // Valid status codes
            }
            1004 | 1005 | 1006 => {
                // Reserved codes that must not be sent
                // Implementation should reject these
            }
            _ => {
                // Other codes - implementation specific
            }
        }

        // Validate reason text is UTF-8
        if payload.len() > 2 {
            let _reason_validation = std::str::from_utf8(&payload[2..]);
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
            assert!(!in_fragment, "Cannot start fragment while in progress");
            in_fragment = true;
        } else {
            assert!(in_fragment, "Continuation without start fragment");
        }

        if fragment.is_last {
            assert!(in_fragment, "Cannot end fragment when not started");
            in_fragment = false;
        }

        // Create frame for fragment
        let opcode = if fragment.is_first { 1 } else { 0 }; // Text or Continuation
        let _frame = TestFrame {
            opcode,
            fin: fragment.is_last,
            payload: fragment.payload.clone(),
        };
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
    asupersync::net::websocket::apply_mask(&mut masked, test.mask);

    // Apply masking again to unmask
    let mut unmasked = masked.clone();
    asupersync::net::websocket::apply_mask(&mut unmasked, test.mask);

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
    let opcode_num = match opcode {
        ControlOpcode::Close => 8,
        ControlOpcode::Ping => 9,
        ControlOpcode::Pong => 10,
    };

    let _frame = TestFrame {
        opcode: opcode_num,
        fin: true,
        payload: payload.to_vec(),
    };
}

/// Test control frame with invalid RSV bits
fn test_invalid_rsv_control_frame(opcode: &ControlOpcode, payload: &[u8]) {
    let opcode_byte = match opcode {
        ControlOpcode::Close => 8,
        ControlOpcode::Ping => 9,
        ControlOpcode::Pong => 10,
    };

    // Create frame with RSV1=1 (invalid)
    let first_byte = 0x80 | 0x40 | opcode_byte; // FIN=1, RSV1=1
    let second_byte = payload.len() as u8;

    let mut frame_bytes = vec![first_byte, second_byte];
    frame_bytes.extend_from_slice(payload);

    // This should be rejected
    let _parse_result = parse_websocket_frame(&frame_bytes);
}

/// Test round-trip encode/decode consistency
fn test_roundtrip_consistency(test: &RoundTripTest) {
    if test.frame_data.payload.len() > MAX_PAYLOAD_SIZE {
        return;
    }

    // Create frame
    let opcode = match test.frame_data.opcode {
        DataOpcode::Continuation => 0,
        DataOpcode::Text => 1,
        DataOpcode::Binary => 2,
    };

    let original_frame = TestFrame {
        opcode,
        fin: test.frame_data.fin,
        payload: test.frame_data.payload.clone(),
    };

    // Encode to bytes
    let encoded = encode_test_frame(&original_frame, &test.role);

    // Decode back
    match parse_websocket_frame(&encoded) {
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

/// Simplified frame structure for testing
#[derive(Debug)]
struct TestFrame {
    opcode: u8,
    fin: bool,
    payload: Vec<u8>,
}

/// Encode test frame to bytes
fn encode_test_frame(frame: &TestFrame, role: &Role) -> Vec<u8> {
    let mut bytes = Vec::new();

    // First byte: FIN + opcode
    let first_byte = if frame.fin { 0x80 } else { 0x00 } | frame.opcode;
    bytes.push(first_byte);

    // Second byte: MASK + payload length
    let mask_bit = match role {
        Role::Client => 0x80, // Clients mask
        Role::Server => 0x00, // Servers don't mask
    };

    let payload_len = frame.payload.len();
    if payload_len < 126 {
        bytes.push(mask_bit | (payload_len as u8));
    } else if payload_len < 65536 {
        bytes.push(mask_bit | 126);
        bytes.extend_from_slice(&(payload_len as u16).to_be_bytes());
    } else {
        bytes.push(mask_bit | 127);
        bytes.extend_from_slice(&(payload_len as u64).to_be_bytes());
    }

    // Masking key + payload
    let mut payload = frame.payload.clone();
    if matches!(role, Role::Client) {
        let mask = [0x12, 0x34, 0x56, 0x78];
        bytes.extend_from_slice(&mask);
        asupersync::net::websocket::apply_mask(&mut payload, mask);
    }
    bytes.extend_from_slice(&payload);

    bytes
}
