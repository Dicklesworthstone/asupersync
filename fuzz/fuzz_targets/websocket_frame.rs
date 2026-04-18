#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{BufMut, BytesMut};
use asupersync::codec::Decoder;
use asupersync::net::websocket::{Frame, FrameCodec, Opcode, Role, WsError};
use libfuzzer_sys::fuzz_target;

/// RFC 6455 focused fuzz target for WebSocket frame parsing.
///
/// This fuzzer specifically targets the 6 critical assertions:
/// 1. Masked client frames required (RFC 6455 §5.1)
/// 2. Unmasked client frames rejected (RFC 6455 §5.1)
/// 3. Fragmented control frames rejected (RFC 6455 §5.5)
/// 4. Reserved bits honored per RSV1/RSV2/RSV3 negotiation (RFC 6455 §5.2)
/// 5. Payload length encoding (7/7+16/7+64 bits) correctly decoded (RFC 6455 §5.2)
/// 6. Oversized payloads rejected (RFC 6455 §5.2)
#[derive(Arbitrary, Debug)]
struct WebSocketFrameInput {
    operations: Vec<FrameParseOperation>,
}

#[derive(Arbitrary, Debug)]
enum FrameParseOperation {
    /// Test masking requirement enforcement
    MaskingTest {
        role: TestRole,
        payload: Vec<u8>,
        force_masked: bool,
        opcode: TestOpcode,
    },
    /// Test reserved bits validation
    ReservedBitsTest {
        role: TestRole,
        payload: Vec<u8>,
        rsv1: bool,
        rsv2: bool,
        rsv3: bool,
        opcode: TestOpcode,
        validate_reserved: bool,
    },
    /// Test control frame fragmentation rejection
    ControlFragmentationTest {
        role: TestRole,
        control_opcode: ControlOpcode,
        payload: Vec<u8>,
        fin: bool,
    },
    /// Test payload length encoding/decoding
    PayloadLengthTest {
        role: TestRole,
        length_encoding: LengthEncoding,
        actual_length: u16, // Limited to prevent timeout
        minimal_encoding: bool,
    },
    /// Test oversized payload rejection
    OversizeTest {
        role: TestRole,
        max_payload_size: u32,
        requested_length: u32,
        length_encoding: LengthEncoding,
    },
    /// Test 64-bit length MSB enforcement
    LengthMSBTest {
        role: TestRole,
        payload: Vec<u8>,
        msb_set: bool,
    },
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum TestRole {
    Client,
    Server,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum TestOpcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum ControlOpcode {
    Close,
    Ping,
    Pong,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum LengthEncoding {
    SevenBit,   // 0-125 bytes
    SixteenBit, // 126-65535 bytes
    SixtyFourBit, // 65536+ bytes
}

const MAX_OPERATIONS: usize = 20;
const MAX_PAYLOAD: usize = 8192; // Limit to prevent timeout
const DEFAULT_MAX_SIZE: usize = 16 * 1024 * 1024;

fuzz_target!(|input: WebSocketFrameInput| {
    // Limit operations to prevent timeout
    if input.operations.len() > MAX_OPERATIONS {
        return;
    }

    for operation in input.operations {
        test_frame_operation(operation);
    }
});

fn test_frame_operation(operation: FrameParseOperation) {
    match operation {
        FrameParseOperation::MaskingTest {
            role,
            payload,
            force_masked,
            opcode,
        } => {
            test_masking_requirement(role, payload, force_masked, opcode);
        }

        FrameParseOperation::ReservedBitsTest {
            role,
            payload,
            rsv1,
            rsv2,
            rsv3,
            opcode,
            validate_reserved,
        } => {
            test_reserved_bits(role, payload, rsv1, rsv2, rsv3, opcode, validate_reserved);
        }

        FrameParseOperation::ControlFragmentationTest {
            role,
            control_opcode,
            payload,
            fin,
        } => {
            test_control_fragmentation(role, control_opcode, payload, fin);
        }

        FrameParseOperation::PayloadLengthTest {
            role,
            length_encoding,
            actual_length,
            minimal_encoding,
        } => {
            test_payload_length_encoding(role, length_encoding, actual_length as usize, minimal_encoding);
        }

        FrameParseOperation::OversizeTest {
            role,
            max_payload_size,
            requested_length,
            length_encoding,
        } => {
            test_oversize_rejection(role, max_payload_size, requested_length, length_encoding);
        }

        FrameParseOperation::LengthMSBTest {
            role,
            payload,
            msb_set,
        } => {
            test_length_msb_enforcement(role, payload, msb_set);
        }
    }
}

/// Test RFC 6455 §5.1: Client frames MUST be masked, server frames MUST NOT be masked
fn test_masking_requirement(role: TestRole, mut payload: Vec<u8>, force_masked: bool, opcode: TestOpcode) {
    payload.truncate(MAX_PAYLOAD);

    let ws_role = match role {
        TestRole::Client => Role::Client,
        TestRole::Server => Role::Server,
    };

    let mut codec = FrameCodec::new(ws_role);
    let frame_bytes = construct_frame_with_masking(&payload, convert_opcode(opcode), force_masked);

    if frame_bytes.len() <= MAX_PAYLOAD {
        let mut buf = BytesMut::from(frame_bytes.as_slice());
        let result = codec.decode(&mut buf);

        // Assert masking requirements based on role
        match (ws_role, force_masked) {
            (Role::Server, false) => {
                // Server receiving unmasked frame from client → should reject
                assert!(matches!(result, Err(WsError::UnmaskedClientFrame)),
                        "Server must reject unmasked client frames (RFC 6455 §5.1)");
            }
            (Role::Client, true) => {
                // Client receiving masked frame from server → should reject (optional but common)
                assert!(matches!(result, Err(WsError::MaskedServerFrame)),
                        "Client should reject masked server frames (RFC 6455 §5.1)");
            }
            (Role::Server, true) => {
                // Server receiving masked frame from client → should accept
                // Note: may still fail for other reasons (reserved bits, etc.)
                match result {
                    Ok(_) => {}, // Expected
                    Err(WsError::UnmaskedClientFrame) => {
                        panic!("Server incorrectly rejected masked client frame");
                    }
                    Err(_) => {}, // Other validation errors are fine
                }
            }
            (Role::Client, false) => {
                // Client receiving unmasked frame from server → should accept
                match result {
                    Ok(_) => {}, // Expected
                    Err(WsError::MaskedServerFrame) => {
                        panic!("Client incorrectly rejected unmasked server frame");
                    }
                    Err(_) => {}, // Other validation errors are fine
                }
            }
        }
    }
}

/// Test RFC 6455 §5.2: Reserved bits must be 0 unless extension negotiated
fn test_reserved_bits(role: TestRole, mut payload: Vec<u8>, rsv1: bool, rsv2: bool, rsv3: bool,
                      opcode: TestOpcode, validate_reserved: bool) {
    payload.truncate(MAX_PAYLOAD);

    let ws_role = match role {
        TestRole::Client => Role::Client,
        TestRole::Server => Role::Server,
    };

    let mut codec = FrameCodec::new(ws_role).validate_reserved_bits(validate_reserved);
    let frame_bytes = construct_frame_with_reserved_bits(&payload, convert_opcode(opcode), rsv1, rsv2, rsv3, ws_role);

    if frame_bytes.len() <= MAX_PAYLOAD {
        let mut buf = BytesMut::from(frame_bytes.as_slice());
        let result = codec.decode(&mut buf);

        // If reserved bits validation is enabled and any reserved bit is set, should reject
        if validate_reserved && (rsv1 || rsv2 || rsv3) {
            assert!(matches!(result, Err(WsError::ReservedBitsSet)),
                    "Parser must reject frames with reserved bits set when validation enabled (RFC 6455 §5.2)");
        }
    }
}

/// Test RFC 6455 §5.5: Control frames MUST NOT be fragmented
fn test_control_fragmentation(role: TestRole, control_opcode: ControlOpcode, mut payload: Vec<u8>, fin: bool) {
    payload.truncate(125); // Control frames limited to 125 bytes

    let ws_role = match role {
        TestRole::Client => Role::Client,
        TestRole::Server => Role::Server,
    };

    let opcode = match control_opcode {
        ControlOpcode::Close => Opcode::Close,
        ControlOpcode::Ping => Opcode::Ping,
        ControlOpcode::Pong => Opcode::Pong,
    };

    let mut codec = FrameCodec::new(ws_role);
    let frame_bytes = construct_frame_with_fin(&payload, opcode, fin, ws_role);

    if frame_bytes.len() <= MAX_PAYLOAD {
        let mut buf = BytesMut::from(frame_bytes.as_slice());
        let result = codec.decode(&mut buf);

        // Control frames with FIN=false must be rejected
        if !fin {
            assert!(matches!(result, Err(WsError::FragmentedControlFrame)),
                    "Parser must reject fragmented control frames (RFC 6455 §5.5)");
        }

        // Control frames > 125 bytes must be rejected
        if payload.len() > 125 {
            assert!(matches!(result, Err(WsError::ControlFrameTooLarge(_))),
                    "Parser must reject oversized control frames (RFC 6455 §5.5)");
        }
    }
}

/// Test RFC 6455 §5.2: Payload length encoding must be minimal
fn test_payload_length_encoding(role: TestRole, length_encoding: LengthEncoding,
                                actual_length: usize, minimal_encoding: bool) {
    let actual_length = actual_length.min(MAX_PAYLOAD);

    let ws_role = match role {
        TestRole::Client => Role::Client,
        TestRole::Server => Role::Server,
    };

    let mut codec = FrameCodec::new(ws_role);
    let frame_bytes = construct_frame_with_length_encoding(actual_length, length_encoding, minimal_encoding, ws_role);

    if frame_bytes.len() <= MAX_PAYLOAD && actual_length <= MAX_PAYLOAD {
        let mut buf = BytesMut::from(frame_bytes.as_slice());
        let result = codec.decode(&mut buf);

        // Non-minimal encodings should be rejected
        if !minimal_encoding {
            let should_reject = match length_encoding {
                LengthEncoding::SixteenBit => actual_length < 126,
                LengthEncoding::SixtyFourBit => actual_length < 65536,
                LengthEncoding::SevenBit => false, // Always minimal for 7-bit
            };

            if should_reject {
                assert!(matches!(result, Err(WsError::ProtocolViolation(_))),
                        "Parser must reject non-minimal length encodings (RFC 6455 §5.2)");
            }
        }
    }
}

/// Test payload size limits enforcement
fn test_oversize_rejection(role: TestRole, max_payload_size: u32, requested_length: u32,
                          length_encoding: LengthEncoding) {
    let max_size = (max_payload_size as usize).min(MAX_PAYLOAD);
    let req_length = (requested_length as usize).min(MAX_PAYLOAD * 2);

    let ws_role = match role {
        TestRole::Client => Role::Client,
        TestRole::Server => Role::Server,
    };

    let mut codec = FrameCodec::new(ws_role).max_payload_size(max_size);
    let frame_bytes = construct_frame_with_declared_length(req_length, length_encoding, ws_role);

    if frame_bytes.len() <= MAX_PAYLOAD {
        let mut buf = BytesMut::from(frame_bytes.as_slice());
        let result = codec.decode(&mut buf);

        // Payloads exceeding max_payload_size should be rejected
        if req_length > max_size {
            assert!(matches!(result, Err(WsError::PayloadTooLarge { .. })),
                    "Parser must reject oversized payloads");
        }
    }
}

/// Test RFC 6455 §5.2: 64-bit length MSB must be 0
fn test_length_msb_enforcement(role: TestRole, payload: Vec<u8>, msb_set: bool) {
    let ws_role = match role {
        TestRole::Client => Role::Client,
        TestRole::Server => Role::Server,
    };

    let mut codec = FrameCodec::new(ws_role);
    let frame_bytes = construct_frame_with_msb_length(payload.len().min(MAX_PAYLOAD), msb_set, ws_role);

    if frame_bytes.len() <= MAX_PAYLOAD {
        let mut buf = BytesMut::from(frame_bytes.as_slice());
        let result = codec.decode(&mut buf);

        // 64-bit length with MSB set should be rejected
        if msb_set {
            assert!(matches!(result, Err(WsError::ProtocolViolation(_))),
                    "Parser must reject 64-bit length with MSB set (RFC 6455 §5.2)");
        }
    }
}

// Helper functions for frame construction

fn convert_opcode(opcode: TestOpcode) -> Opcode {
    match opcode {
        TestOpcode::Continuation => Opcode::Continuation,
        TestOpcode::Text => Opcode::Text,
        TestOpcode::Binary => Opcode::Binary,
        TestOpcode::Close => Opcode::Close,
        TestOpcode::Ping => Opcode::Ping,
        TestOpcode::Pong => Opcode::Pong,
    }
}

fn construct_frame_with_masking(payload: &[u8], opcode: Opcode, masked: bool) -> Vec<u8> {
    let mut frame = Vec::new();

    // First byte: FIN=1, RSV=000, opcode
    frame.push(0x80 | (opcode as u8));

    // Second byte: MASK + payload length
    let mask_bit = if masked { 0x80 } else { 0x00 };

    if payload.len() <= 125 {
        frame.push(mask_bit | (payload.len() as u8));
    } else if payload.len() <= 65535 {
        frame.push(mask_bit | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(mask_bit | 127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }

    // Mask key if masked
    let mask_key = [0x12, 0x34, 0x56, 0x78];
    if masked {
        frame.extend_from_slice(&mask_key);
    }

    // Payload (masked if necessary)
    if masked {
        let mut masked_payload = payload.to_vec();
        asupersync::net::websocket::apply_mask(&mut masked_payload, mask_key);
        frame.extend_from_slice(&masked_payload);
    } else {
        frame.extend_from_slice(payload);
    }

    frame
}

fn construct_frame_with_reserved_bits(payload: &[u8], opcode: Opcode, rsv1: bool, rsv2: bool, rsv3: bool, role: Role) -> Vec<u8> {
    let mut frame = Vec::new();

    // First byte: FIN + RSV + opcode
    let mut first_byte = 0x80 | (opcode as u8); // FIN=1
    if rsv1 { first_byte |= 0x40; }
    if rsv2 { first_byte |= 0x20; }
    if rsv3 { first_byte |= 0x10; }
    frame.push(first_byte);

    // Apply correct masking based on role
    let masked = match role {
        Role::Server => true,  // Server decodes masked client frames
        Role::Client => false, // Client decodes unmasked server frames
    };

    let mask_bit = if masked { 0x80 } else { 0x00 };
    frame.push(mask_bit | (payload.len().min(125) as u8));

    // Mask key if needed
    let mask_key = [0x12, 0x34, 0x56, 0x78];
    if masked {
        frame.extend_from_slice(&mask_key);
        let mut masked_payload = payload.to_vec();
        asupersync::net::websocket::apply_mask(&mut masked_payload, mask_key);
        frame.extend_from_slice(&masked_payload[..payload.len().min(125)]);
    } else {
        frame.extend_from_slice(&payload[..payload.len().min(125)]);
    }

    frame
}

fn construct_frame_with_fin(payload: &[u8], opcode: Opcode, fin: bool, role: Role) -> Vec<u8> {
    let mut frame = Vec::new();

    // First byte: FIN + opcode
    let first_byte = if fin { 0x80 } else { 0x00 } | (opcode as u8);
    frame.push(first_byte);

    // Apply correct masking based on role
    let masked = match role {
        Role::Server => true,  // Server decodes masked client frames
        Role::Client => false, // Client decodes unmasked server frames
    };

    let mask_bit = if masked { 0x80 } else { 0x00 };
    frame.push(mask_bit | (payload.len().min(125) as u8));

    // Mask key if needed
    let mask_key = [0x12, 0x34, 0x56, 0x78];
    if masked {
        frame.extend_from_slice(&mask_key);
        let mut masked_payload = payload.to_vec();
        asupersync::net::websocket::apply_mask(&mut masked_payload, mask_key);
        frame.extend_from_slice(&masked_payload[..payload.len().min(125)]);
    } else {
        frame.extend_from_slice(&payload[..payload.len().min(125)]);
    }

    frame
}

fn construct_frame_with_length_encoding(actual_length: usize, encoding: LengthEncoding,
                                       minimal: bool, role: Role) -> Vec<u8> {
    let mut frame = Vec::new();

    // First byte: FIN=1, opcode=binary
    frame.push(0x82);

    // Apply correct masking based on role
    let masked = match role {
        Role::Server => true,  // Server decodes masked client frames
        Role::Client => false, // Client decodes unmasked server frames
    };

    let mask_bit = if masked { 0x80 } else { 0x00 };

    match encoding {
        LengthEncoding::SevenBit => {
            frame.push(mask_bit | (actual_length.min(125) as u8));
        }
        LengthEncoding::SixteenBit => {
            if minimal && actual_length < 126 {
                // Force non-minimal encoding
                frame.push(mask_bit | 126);
                frame.extend_from_slice(&(actual_length as u16).to_be_bytes());
            } else {
                frame.push(mask_bit | 126);
                frame.extend_from_slice(&(actual_length.max(126).min(65535) as u16).to_be_bytes());
            }
        }
        LengthEncoding::SixtyFourBit => {
            if minimal && actual_length < 65536 {
                // Force non-minimal encoding
                frame.push(mask_bit | 127);
                frame.extend_from_slice(&(actual_length as u64).to_be_bytes());
            } else {
                frame.push(mask_bit | 127);
                frame.extend_from_slice(&(actual_length.max(65536) as u64).to_be_bytes());
            }
        }
    }

    // Add mask key if needed (but don't add actual payload for length tests)
    if masked {
        let mask_key = [0x12, 0x34, 0x56, 0x78];
        frame.extend_from_slice(&mask_key);
    }

    frame
}

fn construct_frame_with_declared_length(declared_length: usize, encoding: LengthEncoding, role: Role) -> Vec<u8> {
    let mut frame = Vec::new();

    // First byte: FIN=1, opcode=binary
    frame.push(0x82);

    // Apply correct masking based on role
    let masked = match role {
        Role::Server => true,  // Server decodes masked client frames
        Role::Client => false, // Client decodes unmasked server frames
    };

    let mask_bit = if masked { 0x80 } else { 0x00 };

    match encoding {
        LengthEncoding::SevenBit => {
            frame.push(mask_bit | (declared_length.min(125) as u8));
        }
        LengthEncoding::SixteenBit => {
            frame.push(mask_bit | 126);
            frame.extend_from_slice(&(declared_length.min(65535) as u16).to_be_bytes());
        }
        LengthEncoding::SixtyFourBit => {
            frame.push(mask_bit | 127);
            frame.extend_from_slice(&(declared_length as u64).to_be_bytes());
        }
    }

    // Add mask key if needed (don't add payload - just testing length declaration)
    if masked {
        let mask_key = [0x12, 0x34, 0x56, 0x78];
        frame.extend_from_slice(&mask_key);
    }

    frame
}

fn construct_frame_with_msb_length(payload_length: usize, msb_set: bool, role: Role) -> Vec<u8> {
    let mut frame = Vec::new();

    // First byte: FIN=1, opcode=binary
    frame.push(0x82);

    // Apply correct masking based on role
    let masked = match role {
        Role::Server => true,  // Server decodes masked client frames
        Role::Client => false, // Client decodes unmasked server frames
    };

    let mask_bit = if masked { 0x80 } else { 0x00 };

    // Use 64-bit length encoding
    frame.push(mask_bit | 127);

    let mut length_bytes = (payload_length.max(65536) as u64).to_be_bytes();
    if msb_set {
        length_bytes[0] |= 0x80; // Set MSB
    }
    frame.extend_from_slice(&length_bytes);

    // Add mask key if needed
    if masked {
        let mask_key = [0x12, 0x34, 0x56, 0x78];
        frame.extend_from_slice(&mask_key);
    }

    frame
}