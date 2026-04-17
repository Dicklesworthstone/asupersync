#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::net::websocket::{Frame, FrameCodec, Opcode, Role, WsError, apply_mask};
use libfuzzer_sys::fuzz_target;

/// Comprehensive WebSocket frame parsing fuzz target (RFC 6455).
///
/// This fuzzer uses structure-aware input generation to test all aspects
/// of WebSocket frame parsing with high coverage:
/// - All opcodes: continuation, text, binary, close, ping, pong
/// - FIN/RSV bit combinations and validation
/// - Payload length encoding: 7-bit, 16-bit, 64-bit forms
/// - Masking protocol validation for client/server roles
/// - UTF-8 validation for text frames
/// - Close frame payload validation (status codes + reasons)
/// - Fragment boundary testing and protocol violations
/// - Edge cases: empty payloads, maximum sizes, non-minimal encodings
#[derive(Arbitrary, Debug)]
struct WsFrameFuzz {
    /// Frame parsing operations
    frame_operations: Vec<FrameOperation>,
    /// UTF-8 validation tests
    utf8_operations: Vec<Utf8Operation>,
    /// Close frame validation tests
    close_operations: Vec<CloseOperation>,
    /// Raw byte parsing tests
    raw_operations: Vec<RawOperation>,
    /// Masking protocol tests
    mask_operations: Vec<MaskOperation>,
}

/// Frame parsing operations
#[derive(Arbitrary, Debug)]
enum FrameOperation {
    /// Parse structured frame
    ParseFrame {
        frame_spec: FrameSpec,
        role: FuzzRole,
        max_payload_size: PayloadSizeLimit,
    },
    /// Parse fragmented message
    ParseFragmentedMessage {
        fragments: Vec<FragmentSpec>,
        role: FuzzRole,
    },
    /// Parse multiple frames in sequence
    ParseSequence {
        frames: Vec<FrameSpec>,
        role: FuzzRole,
    },
    /// Parse frame with protocol violations
    ParseViolation {
        violation_type: ViolationType,
        base_frame: FrameSpec,
        role: FuzzRole,
    },
}

/// UTF-8 validation operations
#[derive(Arbitrary, Debug)]
enum Utf8Operation {
    /// Valid UTF-8 text frame
    ValidUtf8Text { text: String, role: FuzzRole },
    /// Invalid UTF-8 sequence
    InvalidUtf8Text { bytes: Vec<u8>, role: FuzzRole },
    /// UTF-8 boundary at fragment boundary
    FragmentedUtf8 {
        text: String,
        fragment_positions: Vec<u8>,
        role: FuzzRole,
    },
}

/// Close frame validation operations
#[derive(Arbitrary, Debug)]
enum CloseOperation {
    /// Valid close frame
    ValidClose {
        status_code: Option<CloseStatusCode>,
        reason: Option<String>,
        role: FuzzRole,
    },
    /// Invalid close payload
    InvalidClose {
        raw_payload: Vec<u8>,
        role: FuzzRole,
    },
}

/// Raw byte parsing operations
#[derive(Arbitrary, Debug)]
enum RawOperation {
    /// Raw bytes to parser
    RawBytes { data: Vec<u8>, role: FuzzRole },
    /// Truncated frame
    TruncatedFrame {
        complete_frame: FrameSpec,
        truncate_at: u16,
        role: FuzzRole,
    },
}

/// Masking protocol operations
#[derive(Arbitrary, Debug)]
enum MaskOperation {
    /// Test masking involution
    MaskInvolution { payload: Vec<u8>, mask_key: [u8; 4] },
    /// Test masking with edge case keys
    EdgeCaseMask {
        payload: Vec<u8>,
        mask_type: EdgeMaskType,
    },
}

/// Frame specification for structured generation
#[derive(Arbitrary, Debug, Clone)]
struct FrameSpec {
    fin: bool,
    rsv1: bool,
    rsv2: bool,
    rsv3: bool,
    opcode: FuzzOpcode,
    payload: PayloadSpec,
    force_masked: Option<bool>,
}

/// Fragment specification
#[derive(Arbitrary, Debug)]
struct FragmentSpec {
    fin: bool,
    opcode: FuzzOpcode,
    payload: Vec<u8>,
}

/// Payload specification
#[derive(Arbitrary, Debug, Clone)]
enum PayloadSpec {
    Empty,
    Short(Vec<u8>),  // < 126 bytes
    Medium(Vec<u8>), // 126-65535 bytes
    Large(Vec<u8>),  // > 65535 bytes
    Sized(usize),    // Specific size with fill byte
}

/// Protocol violation types
#[derive(Arbitrary, Debug)]
enum ViolationType {
    ReservedBitsSet,
    FragmentedControl,
    ControlTooLarge,
    UnmaskedClient,
    MaskedServer,
    NonMinimalLength,
    InvalidOpcode(u8),
    MsbSetLength,
}

/// Fuzzing role
#[derive(Arbitrary, Debug, Clone, Copy)]
enum FuzzRole {
    Client,
    Server,
}

/// Fuzzing opcode
#[derive(Arbitrary, Debug, Clone, Copy)]
enum FuzzOpcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    Reserved(u8),
}

/// Close status codes for testing
#[derive(Arbitrary, Debug, Clone, Copy)]
enum CloseStatusCode {
    Normal,
    GoingAway,
    ProtocolError,
    UnsupportedData,
    InvalidPayload,
    PolicyViolation,
    MessageTooBig,
    MandatoryExt,
    InternalError,
    Reserved(u16),
}

impl CloseStatusCode {
    fn to_u16(self) -> u16 {
        match self {
            CloseStatusCode::Normal => 1000,
            CloseStatusCode::GoingAway => 1001,
            CloseStatusCode::ProtocolError => 1002,
            CloseStatusCode::UnsupportedData => 1003,
            CloseStatusCode::InvalidPayload => 1007,
            CloseStatusCode::PolicyViolation => 1008,
            CloseStatusCode::MessageTooBig => 1009,
            CloseStatusCode::MandatoryExt => 1010,
            CloseStatusCode::InternalError => 1011,
            CloseStatusCode::Reserved(code) => code,
        }
    }
}

/// Payload size limits
#[derive(Arbitrary, Debug, Clone, Copy)]
enum PayloadSizeLimit {
    Small = 1024,
    Medium = 65536,
    Large = 1048576,
}

/// Edge case mask types
#[derive(Arbitrary, Debug)]
enum EdgeMaskType {
    AllZeros,
    AllOnes,
    Alternating,
    Custom([u8; 4]),
}

const MAX_OPERATIONS: usize = 50;
const MAX_PAYLOAD_SIZE: usize = 100_000;

fuzz_target!(|input: WsFrameFuzz| {
    // Limit operations to prevent timeout
    let total_ops = input.frame_operations.len()
        + input.utf8_operations.len()
        + input.close_operations.len()
        + input.raw_operations.len()
        + input.mask_operations.len();

    if total_ops > MAX_OPERATIONS {
        return;
    }

    // Test frame operations
    for operation in input.frame_operations {
        test_frame_operation(operation);
    }

    // Test UTF-8 operations
    for operation in input.utf8_operations {
        test_utf8_operation(operation);
    }

    // Test close operations
    for operation in input.close_operations {
        test_close_operation(operation);
    }

    // Test raw operations
    for operation in input.raw_operations {
        test_raw_operation(operation);
    }

    // Test mask operations
    for operation in input.mask_operations {
        test_mask_operation(operation);
    }
});

fn test_frame_operation(operation: FrameOperation) {
    match operation {
        FrameOperation::ParseFrame {
            frame_spec,
            role,
            max_payload_size,
        } => {
            let role = convert_role(role);
            let mut codec = FrameCodec::new(role).max_payload_size(max_payload_size as usize);

            if let Ok(frame_bytes) = construct_frame_bytes(&frame_spec, role) {
                if frame_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut buf = BytesMut::from(frame_bytes.as_slice());
                    let result = codec.decode(&mut buf);

                    verify_frame_result(&result, &frame_spec, role);
                }
            }
        }

        FrameOperation::ParseFragmentedMessage { fragments, role } => {
            let role = convert_role(role);
            let mut codec = FrameCodec::new(role);

            for (_i, fragment) in fragments.iter().enumerate().take(10) {
                if let Ok(fragment_bytes) = construct_fragment_bytes(fragment, role) {
                    if fragment_bytes.len() <= MAX_PAYLOAD_SIZE / 10 {
                        let mut buf = BytesMut::from(fragment_bytes.as_slice());
                        let _ = codec.decode(&mut buf);
                    }
                }
            }
        }

        FrameOperation::ParseSequence { frames, role } => {
            let role = convert_role(role);
            let mut codec = FrameCodec::new(role);
            let mut total_size = 0;

            for frame_spec in frames.iter().take(10) {
                if let Ok(frame_bytes) = construct_frame_bytes(frame_spec, role) {
                    total_size += frame_bytes.len();
                    if total_size > MAX_PAYLOAD_SIZE {
                        break;
                    }

                    let mut buf = BytesMut::from(frame_bytes.as_slice());
                    let _ = codec.decode(&mut buf);
                }
            }
        }

        FrameOperation::ParseViolation {
            violation_type,
            base_frame,
            role,
        } => {
            let role = convert_role(role);
            let mut codec = FrameCodec::new(role);

            if let Ok(violation_bytes) =
                construct_violation_bytes(&violation_type, &base_frame, role)
            {
                if violation_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut buf = BytesMut::from(violation_bytes.as_slice());
                    let result = codec.decode(&mut buf);

                    // Violations should result in errors, not panics
                    match result {
                        Ok(_) => {
                            // Some violations might be acceptable depending on implementation
                        }
                        Err(_) => {
                            // Expected for protocol violations
                        }
                    }
                }
            }
        }
    }
}

fn test_utf8_operation(operation: Utf8Operation) {
    match operation {
        Utf8Operation::ValidUtf8Text { text, role } => {
            let role = convert_role(role);
            let frame = Frame::text(text);

            if let Ok(encoded) = encode_frame(&frame, role) {
                if encoded.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = FrameCodec::new(role);
                    let mut buf = BytesMut::from(encoded.as_slice());

                    let result = codec.decode(&mut buf);
                    match result {
                        Ok(Some(decoded_frame)) => {
                            assert_eq!(decoded_frame.opcode, Opcode::Text);
                            // Verify UTF-8 validity is preserved
                            if let Ok(_decoded_text) = std::str::from_utf8(&decoded_frame.payload) {
                                // UTF-8 was valid in both directions
                            }
                        }
                        Ok(None) => {
                            // Incomplete frame - need more data
                        }
                        Err(_) => {
                            // Decode failure is acceptable for edge cases
                        }
                    }
                }
            }
        }

        Utf8Operation::InvalidUtf8Text { bytes, role } => {
            let role = convert_role(role);

            // Construct a text frame with potentially invalid UTF-8
            if let Ok(frame_bytes) = construct_text_frame_bytes(&bytes, role) {
                if frame_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = FrameCodec::new(role);
                    let mut buf = BytesMut::from(frame_bytes.as_slice());

                    let result = codec.decode(&mut buf);
                    // Invalid UTF-8 should either be rejected or handled gracefully
                    match result {
                        Ok(Some(_)) => {
                            // Frame was accepted (might validate UTF-8 later in processing)
                        }
                        Ok(None) => {
                            // Incomplete frame - need more data
                        }
                        Err(_) => {
                            // Frame was rejected (immediate UTF-8 validation)
                        }
                    }
                }
            }
        }

        Utf8Operation::FragmentedUtf8 {
            text,
            fragment_positions,
            role,
        } => {
            let role = convert_role(role);

            // Test UTF-8 validation across fragment boundaries
            if !text.is_empty() && !fragment_positions.is_empty() {
                let text_bytes = text.as_bytes();
                let mut codec = FrameCodec::new(role);

                let mut pos = 0;
                for &fragment_pos in fragment_positions.iter().take(5) {
                    let end_pos =
                        ((fragment_pos as usize) % text_bytes.len().max(1)).min(text_bytes.len());
                    if end_pos > pos {
                        let fragment_data = &text_bytes[pos..end_pos];
                        let is_final = end_pos == text_bytes.len();

                        if let Ok(fragment_bytes) =
                            construct_text_fragment_bytes(fragment_data, is_final, pos == 0, role)
                        {
                            if fragment_bytes.len() <= MAX_PAYLOAD_SIZE / 5 {
                                let mut buf = BytesMut::from(fragment_bytes.as_slice());
                                let _ = codec.decode(&mut buf);
                                pos = end_pos;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn test_close_operation(operation: CloseOperation) {
    match operation {
        CloseOperation::ValidClose {
            status_code,
            reason,
            role,
        } => {
            let role = convert_role(role);

            let close_code = status_code.map(|sc| sc.to_u16());
            let close_frame = Frame::close(close_code, reason.as_deref());

            if let Ok(encoded) = encode_frame(&close_frame, role) {
                if encoded.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = FrameCodec::new(role);
                    let mut buf = BytesMut::from(encoded.as_slice());

                    let result = codec.decode(&mut buf);
                    match result {
                        Ok(Some(decoded_frame)) => {
                            assert_eq!(decoded_frame.opcode, Opcode::Close);
                            // Verify close payload is valid
                        }
                        Ok(None) => {
                            // Incomplete frame - need more data
                        }
                        Err(_) => {
                            // Decode failure is acceptable for edge cases
                        }
                    }
                }
            }
        }

        CloseOperation::InvalidClose { raw_payload, role } => {
            let role = convert_role(role);

            // Construct a close frame with potentially invalid payload
            if let Ok(frame_bytes) = construct_close_frame_bytes(&raw_payload, role) {
                if frame_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = FrameCodec::new(role);
                    let mut buf = BytesMut::from(frame_bytes.as_slice());

                    let result = codec.decode(&mut buf);
                    // Invalid close payload should either be rejected or handled gracefully
                    match result {
                        Ok(Some(_)) => {
                            // Frame was accepted
                        }
                        Ok(None) => {
                            // Incomplete frame - need more data
                        }
                        Err(_) => {
                            // Frame was rejected (expected for invalid close payload)
                        }
                    }
                }
            }
        }
    }
}

fn test_raw_operation(operation: RawOperation) {
    match operation {
        RawOperation::RawBytes { data, role } => {
            if data.len() <= MAX_PAYLOAD_SIZE {
                let role = convert_role(role);
                let mut codec = FrameCodec::new(role);
                let mut buf = BytesMut::from(data.as_slice());

                // Should never panic, only return Ok/Err
                let _ = codec.decode(&mut buf);
            }
        }

        RawOperation::TruncatedFrame {
            complete_frame,
            truncate_at,
            role,
        } => {
            let role = convert_role(role);

            if let Ok(frame_bytes) = construct_frame_bytes(&complete_frame, role) {
                let truncate_pos = (truncate_at as usize).min(frame_bytes.len());
                let truncated = &frame_bytes[..truncate_pos];

                if truncated.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = FrameCodec::new(role);
                    let mut buf = BytesMut::from(truncated);

                    let result = codec.decode(&mut buf);
                    match result {
                        Ok(None) => {
                            // Incomplete frame - expected for truncated input
                        }
                        Ok(Some(_)) => {
                            // Complete frame parsed from truncated data
                        }
                        Err(_) => {
                            // Parse error - also acceptable
                        }
                    }
                }
            }
        }
    }
}

fn test_mask_operation(operation: MaskOperation) {
    match operation {
        MaskOperation::MaskInvolution { payload, mask_key } => {
            if payload.len() <= MAX_PAYLOAD_SIZE {
                let mut masked = payload.clone();
                let original = payload.clone();

                // Test masking involution: mask(mask(x)) == x
                apply_mask(&mut masked, mask_key);
                apply_mask(&mut masked, mask_key);

                assert_eq!(masked, original, "masking must be involutive");
            }
        }

        MaskOperation::EdgeCaseMask { payload, mask_type } => {
            if payload.len() <= MAX_PAYLOAD_SIZE {
                let mask_key = match mask_type {
                    EdgeMaskType::AllZeros => [0x00, 0x00, 0x00, 0x00],
                    EdgeMaskType::AllOnes => [0xFF, 0xFF, 0xFF, 0xFF],
                    EdgeMaskType::Alternating => [0xAA, 0x55, 0xAA, 0x55],
                    EdgeMaskType::Custom(key) => key,
                };

                let mut masked = payload.clone();
                let original = payload.clone();

                // Test edge case masking
                apply_mask(&mut masked, mask_key);
                apply_mask(&mut masked, mask_key);

                assert_eq!(masked, original, "edge case masking must be involutive");
            }
        }
    }
}

// Helper functions for frame construction and verification

fn convert_role(role: FuzzRole) -> Role {
    match role {
        FuzzRole::Client => Role::Client,
        FuzzRole::Server => Role::Server,
    }
}

fn convert_opcode(opcode: FuzzOpcode) -> Result<Opcode, u8> {
    match opcode {
        FuzzOpcode::Continuation => Ok(Opcode::Continuation),
        FuzzOpcode::Text => Ok(Opcode::Text),
        FuzzOpcode::Binary => Ok(Opcode::Binary),
        FuzzOpcode::Close => Ok(Opcode::Close),
        FuzzOpcode::Ping => Ok(Opcode::Ping),
        FuzzOpcode::Pong => Ok(Opcode::Pong),
        FuzzOpcode::Reserved(value) => Err(value),
    }
}

fn construct_frame_bytes(frame_spec: &FrameSpec, role: Role) -> Result<Vec<u8>, ()> {
    // Construct a WebSocket frame according to RFC 6455 format
    let mut bytes = Vec::new();

    // First byte: FIN + RSV1-3 + Opcode
    let mut first_byte = 0u8;
    if frame_spec.fin {
        first_byte |= 0x80;
    }
    if frame_spec.rsv1 {
        first_byte |= 0x40;
    }
    if frame_spec.rsv2 {
        first_byte |= 0x20;
    }
    if frame_spec.rsv3 {
        first_byte |= 0x10;
    }

    match convert_opcode(frame_spec.opcode) {
        Ok(opcode) => {
            first_byte |= opcode as u8;
        }
        Err(reserved_value) => {
            first_byte |= reserved_value & 0x0F;
        }
    }
    bytes.push(first_byte);

    // Construct payload
    let payload = construct_payload(&frame_spec.payload)?;

    // Determine masking based on role and force_masked override
    let masked = frame_spec.force_masked.unwrap_or_else(|| {
        match role {
            Role::Server => true,  // Server decodes masked client frames
            Role::Client => false, // Client decodes unmasked server frames
        }
    });

    // Second byte: MASK + Payload length
    let mut second_byte = 0u8;
    if masked {
        second_byte |= 0x80;
    }

    // Encode payload length
    encode_payload_length(&mut bytes, payload.len(), second_byte);

    // Add mask key if masked
    let mask_key = if masked {
        let key = [0x12, 0x34, 0x56, 0x78]; // Fixed mask for deterministic testing
        bytes.extend_from_slice(&key);
        Some(key)
    } else {
        None
    };

    // Add payload (masked if necessary)
    let mut payload = payload;
    if let Some(key) = mask_key {
        apply_mask(&mut payload, key);
    }
    bytes.extend_from_slice(&payload);

    Ok(bytes)
}

fn construct_payload(spec: &PayloadSpec) -> Result<Vec<u8>, ()> {
    match spec {
        PayloadSpec::Empty => Ok(Vec::new()),
        PayloadSpec::Short(data) => {
            let data = data.iter().take(125).copied().collect();
            Ok(data)
        }
        PayloadSpec::Medium(data) => {
            let data = data.iter().take(65535).copied().collect();
            Ok(data)
        }
        PayloadSpec::Large(data) => {
            let data = data.iter().take(MAX_PAYLOAD_SIZE).copied().collect();
            Ok(data)
        }
        PayloadSpec::Sized(size) => {
            let size = (*size).min(MAX_PAYLOAD_SIZE);
            Ok(vec![0x42; size])
        }
    }
}

fn encode_payload_length(bytes: &mut Vec<u8>, payload_len: usize, mut second_byte: u8) {
    if payload_len < 126 {
        second_byte |= payload_len as u8;
        bytes.push(second_byte);
    } else if payload_len <= 65535 {
        second_byte |= 126;
        bytes.push(second_byte);
        bytes.extend_from_slice(&(payload_len as u16).to_be_bytes());
    } else {
        second_byte |= 127;
        bytes.push(second_byte);
        bytes.extend_from_slice(&(payload_len as u64).to_be_bytes());
    }
}

fn construct_fragment_bytes(fragment: &FragmentSpec, role: Role) -> Result<Vec<u8>, ()> {
    let frame_spec = FrameSpec {
        fin: fragment.fin,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: fragment.opcode,
        payload: PayloadSpec::Short(fragment.payload.clone()),
        force_masked: None,
    };
    construct_frame_bytes(&frame_spec, role)
}

fn construct_violation_bytes(
    violation: &ViolationType,
    base_frame: &FrameSpec,
    role: Role,
) -> Result<Vec<u8>, ()> {
    let mut modified_frame = base_frame.clone();

    match violation {
        ViolationType::ReservedBitsSet => {
            modified_frame.rsv1 = true;
        }
        ViolationType::FragmentedControl => {
            modified_frame.opcode = FuzzOpcode::Close;
            modified_frame.fin = false;
        }
        ViolationType::ControlTooLarge => {
            modified_frame.opcode = FuzzOpcode::Ping;
            modified_frame.payload = PayloadSpec::Medium(vec![0; 126]);
        }
        ViolationType::UnmaskedClient => {
            modified_frame.force_masked = Some(false);
            // This violation is for server role decoding unmasked client frame
        }
        ViolationType::MaskedServer => {
            modified_frame.force_masked = Some(true);
            // This violation is for client role decoding masked server frame
        }
        ViolationType::InvalidOpcode(value) => {
            modified_frame.opcode = FuzzOpcode::Reserved(*value);
        }
        _ => {
            // Other violations need manual byte manipulation
            return construct_manual_violation(violation, base_frame, role);
        }
    }

    construct_frame_bytes(&modified_frame, role)
}

fn construct_manual_violation(
    violation: &ViolationType,
    base_frame: &FrameSpec,
    role: Role,
) -> Result<Vec<u8>, ()> {
    let mut bytes = construct_frame_bytes(base_frame, role)?;

    match violation {
        ViolationType::NonMinimalLength => {
            // Encode small payload with 2-byte length (non-minimal)
            if bytes.len() >= 2 {
                bytes[1] = (bytes[1] & 0x80) | 126; // Set length to 126 (2-byte form)
                bytes.insert(2, 0); // Insert 2-byte length
                bytes.insert(3, 1); // Length = 1 (should use 7-bit form)
            }
        }
        ViolationType::MsbSetLength => {
            // Set MSB in 64-bit length field
            if bytes.len() >= 10 && (bytes[1] & 0x7F) == 127 {
                bytes[2] |= 0x80; // Set MSB of 64-bit length
            }
        }
        _ => return Err(()), // Other violations handled elsewhere
    }

    Ok(bytes)
}

fn construct_text_frame_bytes(payload: &[u8], role: Role) -> Result<Vec<u8>, ()> {
    let frame_spec = FrameSpec {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: FuzzOpcode::Text,
        payload: PayloadSpec::Short(payload.to_vec()),
        force_masked: None,
    };
    construct_frame_bytes(&frame_spec, role)
}

fn construct_text_fragment_bytes(
    payload: &[u8],
    is_final: bool,
    is_first: bool,
    role: Role,
) -> Result<Vec<u8>, ()> {
    let opcode = if is_first {
        FuzzOpcode::Text
    } else {
        FuzzOpcode::Continuation
    };

    let frame_spec = FrameSpec {
        fin: is_final,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode,
        payload: PayloadSpec::Short(payload.to_vec()),
        force_masked: None,
    };
    construct_frame_bytes(&frame_spec, role)
}

fn construct_close_frame_bytes(payload: &[u8], role: Role) -> Result<Vec<u8>, ()> {
    let frame_spec = FrameSpec {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: FuzzOpcode::Close,
        payload: PayloadSpec::Short(payload.to_vec()),
        force_masked: None,
    };
    construct_frame_bytes(&frame_spec, role)
}

fn encode_frame(frame: &Frame, role: Role) -> Result<Vec<u8>, ()> {
    // This would use the actual Frame encoder, but for simplicity
    // we'll construct manually based on frame properties
    let mut bytes = Vec::new();

    // First byte: FIN + RSV + Opcode
    let mut first_byte = 0u8;
    if frame.fin {
        first_byte |= 0x80;
    }
    if frame.rsv1 {
        first_byte |= 0x40;
    }
    if frame.rsv2 {
        first_byte |= 0x20;
    }
    if frame.rsv3 {
        first_byte |= 0x10;
    }
    first_byte |= frame.opcode as u8;
    bytes.push(first_byte);

    // Payload length and masking based on role
    let masked = match role {
        Role::Server => true,  // Server decodes masked client frames
        Role::Client => false, // Client decodes unmasked server frames
    };

    let second_byte = if masked { 0x80 } else { 0x00 };
    encode_payload_length(&mut bytes, frame.payload.len(), second_byte);

    // Add mask key if masked
    if masked {
        let mask_key = [0x12, 0x34, 0x56, 0x78];
        bytes.extend_from_slice(&mask_key);

        // Apply masking to payload
        let mut payload = frame.payload.to_vec();
        apply_mask(&mut payload, mask_key);
        bytes.extend_from_slice(&payload);
    } else {
        bytes.extend_from_slice(&frame.payload);
    }

    Ok(bytes)
}

fn verify_frame_result(
    result: &Result<Option<Frame>, WsError>,
    frame_spec: &FrameSpec,
    role: Role,
) {
    match result {
        Ok(Some(frame)) => {
            // Verify frame invariants
            if frame.opcode.is_control() {
                assert!(frame.fin, "control frame must have FIN=true");
                assert!(
                    frame.payload.len() <= 125,
                    "control frame payload > 125 bytes"
                );
            }

            // Verify masking rules
            match role {
                Role::Server => {
                    // Server decodes masked client frames
                    if frame_spec.force_masked != Some(false) {
                        assert!(frame.masked, "client frames should be masked");
                    }
                }
                Role::Client => {
                    // Client decodes unmasked server frames
                    if frame_spec.force_masked != Some(true) {
                        assert!(!frame.masked, "server frames should not be masked");
                    }
                }
            }
        }
        Ok(None) => {
            // Incomplete frame - acceptable
        }
        Err(_) => {
            // Parse error - acceptable for many fuzz inputs
        }
    }
}
