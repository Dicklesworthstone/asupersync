#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::net::quic_core::{
    ConnectionId, PacketHeader, QUIC_VARINT_MAX, QuicCoreError, TP_ACK_DELAY_EXPONENT,
    TP_DISABLE_ACTIVE_MIGRATION, TP_INITIAL_MAX_DATA, TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
    TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, TP_INITIAL_MAX_STREAM_DATA_UNI,
    TP_INITIAL_MAX_STREAMS_BIDI, TP_INITIAL_MAX_STREAMS_UNI, TP_MAX_ACK_DELAY, TP_MAX_IDLE_TIMEOUT,
    TP_MAX_UDP_PAYLOAD_SIZE, TransportParameters, decode_varint, encode_varint,
};

/// Fuzz input for QUIC core protocol parsing
#[derive(Arbitrary, Debug)]
struct QuicCoreFuzzInput {
    /// Varint decoding operations
    varint_operations: Vec<VarIntOperation>,
    /// Connection ID operations
    connection_id_operations: Vec<ConnectionIdOperation>,
    /// Packet header parsing operations
    packet_operations: Vec<PacketOperation>,
    /// Transport parameter parsing operations
    transport_param_operations: Vec<TransportParamOperation>,
    /// Edge case testing
    edge_cases: Vec<EdgeCaseOperation>,
}

/// Varint operation variants
#[derive(Arbitrary, Debug)]
enum VarIntOperation {
    /// Decode varint from raw bytes
    DecodeVarint { data: Vec<u8> },
    /// Roundtrip test: encode then decode
    RoundtripVarint { value: u64 },
    /// Test varint boundary values
    BoundaryVarint { boundary_type: VarIntBoundary },
    /// Test malformed varint encoding
    MalformedVarint { malformed_data: Vec<u8> },
}

/// Varint boundary test cases
#[derive(Arbitrary, Debug)]
enum VarIntBoundary {
    /// Zero value
    Zero,
    /// Maximum 1-byte varint (63)
    Max1Byte,
    /// Minimum 2-byte varint (64)
    Min2Byte,
    /// Maximum 2-byte varint (16383)
    Max2Byte,
    /// Minimum 4-byte varint (16384)
    Min4Byte,
    /// Maximum 4-byte varint (1073741823)
    Max4Byte,
    /// Minimum 8-byte varint (1073741824)
    Min8Byte,
    /// Maximum allowed varint (QUIC_VARINT_MAX)
    MaxAllowed,
    /// Beyond maximum (should fail)
    BeyondMax,
}

/// Connection ID operation variants
#[derive(Arbitrary, Debug)]
enum ConnectionIdOperation {
    /// Create ConnectionId from bytes
    CreateFromBytes { bytes: Vec<u8> },
    /// Create empty ConnectionId
    CreateEmpty,
    /// Create maximum length ConnectionId
    CreateMaxLength,
    /// Create oversized ConnectionId (should fail)
    CreateOversized { extra_bytes: u8 },
}

/// Packet header operation variants
#[derive(Arbitrary, Debug)]
enum PacketOperation {
    /// Parse packet header with various DCID lengths
    ParseHeader {
        packet_data: Vec<u8>,
        short_dcid_len: u8,
    },
    /// Parse specifically crafted long header
    ParseLongHeader {
        version: u32,
        dst_cid: Vec<u8>,
        src_cid: Vec<u8>,
        packet_type: LongPacketTypeFuzz,
        token: Vec<u8>,
        payload_length: u64,
        packet_number: u32,
    },
    /// Parse specifically crafted short header
    ParseShortHeader {
        spin: bool,
        key_phase: bool,
        dst_cid: Vec<u8>,
        packet_number: u32,
        packet_number_len: u8,
    },
    /// Test truncated packet headers
    ParseTruncatedHeader {
        complete_header: Vec<u8>,
        truncate_at: u16,
    },
}

/// Long packet type for fuzzing
#[derive(Arbitrary, Debug)]
enum LongPacketTypeFuzz {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

/// Transport parameter operation variants
#[derive(Arbitrary, Debug)]
enum TransportParamOperation {
    /// Parse transport parameters from bytes
    ParseTransportParams { tlv_data: Vec<u8> },
    /// Parse known transport parameters
    ParseKnownParams { params: Vec<KnownTransportParam> },
    /// Parse with duplicate parameters (should fail)
    ParseDuplicateParams { param_id: u64, values: Vec<u64> },
    /// Parse malformed transport parameters
    ParseMalformedParams { malformed_data: Vec<u8> },
    /// Roundtrip test: encode then decode
    RoundtripParams { params: Vec<KnownTransportParam> },
}

/// Known transport parameter for testing
#[derive(Arbitrary, Debug)]
struct KnownTransportParam {
    param_type: TransportParamType,
    value: u64,
}

/// Transport parameter types
#[derive(Arbitrary, Debug)]
enum TransportParamType {
    MaxIdleTimeout,
    MaxUdpPayloadSize,
    InitialMaxData,
    InitialMaxStreamDataBidiLocal,
    InitialMaxStreamDataBidiRemote,
    InitialMaxStreamDataUni,
    InitialMaxStreamsBidi,
    InitialMaxStreamsUni,
    AckDelayExponent,
    MaxAckDelay,
    DisableActiveMigration,
    Unknown(u64),
}

/// Edge case testing
#[derive(Arbitrary, Debug)]
enum EdgeCaseOperation {
    /// Empty input
    EmptyInput,
    /// Single byte input
    SingleByte { byte: u8 },
    /// Very large inputs
    LargeInput { size: u16, fill_pattern: u8 },
    /// Random garbage input
    GarbageInput { garbage: Vec<u8> },
    /// Input with high entropy
    HighEntropyInput { entropy_data: Vec<u8> },
}

/// Maximum input sizes to prevent timeout/memory exhaustion
const MAX_INPUT_SIZE: usize = 65536; // 64KB
const MAX_CONNECTION_ID_TEST_SIZE: usize = 50; // Well beyond the 20 byte limit
const MAX_OPERATIONS: usize = 100;

fuzz_target!(|input: QuicCoreFuzzInput| {
    // Limit operations to prevent timeout
    let total_ops = input.varint_operations.len()
        + input.connection_id_operations.len()
        + input.packet_operations.len()
        + input.transport_param_operations.len()
        + input.edge_cases.len();

    if total_ops > MAX_OPERATIONS {
        return;
    }

    // Test varint operations
    for operation in input.varint_operations {
        test_varint_operation(operation);
    }

    // Test connection ID operations
    for operation in input.connection_id_operations {
        test_connection_id_operation(operation);
    }

    // Test packet header operations
    for operation in input.packet_operations {
        test_packet_operation(operation);
    }

    // Test transport parameter operations
    for operation in input.transport_param_operations {
        test_transport_param_operation(operation);
    }

    // Test edge cases
    for operation in input.edge_cases {
        test_edge_case_operation(operation);
    }
});

fn test_varint_operation(operation: VarIntOperation) {
    match operation {
        VarIntOperation::DecodeVarint { mut data } => {
            if data.len() > MAX_INPUT_SIZE {
                data.truncate(MAX_INPUT_SIZE);
            }

            let result = decode_varint(&data);

            match result {
                Ok((value, consumed)) => {
                    // Verify consumed bytes are reasonable
                    assert!(consumed <= data.len(), "Consumed more bytes than available");
                    assert!(
                        consumed >= 1 && consumed <= 8,
                        "Invalid varint length: {}",
                        consumed
                    );
                    assert!(
                        value <= QUIC_VARINT_MAX,
                        "Decoded value exceeds QUIC varint max: {}",
                        value
                    );

                    // Test roundtrip if value is valid
                    test_varint_roundtrip(value);
                }
                Err(err) => {
                    // Verify error is reasonable
                    verify_varint_error(&err, &data);
                }
            }
        }

        VarIntOperation::RoundtripVarint { value } => {
            test_varint_roundtrip(value);
        }

        VarIntOperation::BoundaryVarint { boundary_type } => {
            let test_value = match boundary_type {
                VarIntBoundary::Zero => 0,
                VarIntBoundary::Max1Byte => 63,
                VarIntBoundary::Min2Byte => 64,
                VarIntBoundary::Max2Byte => 16383,
                VarIntBoundary::Min4Byte => 16384,
                VarIntBoundary::Max4Byte => 1073741823,
                VarIntBoundary::Min8Byte => 1073741824,
                VarIntBoundary::MaxAllowed => QUIC_VARINT_MAX,
                VarIntBoundary::BeyondMax => QUIC_VARINT_MAX.saturating_add(1),
            };

            // Test encoding
            let mut encoded = Vec::new();
            let encode_result = encode_varint(test_value, &mut encoded);

            match boundary_type {
                VarIntBoundary::BeyondMax => {
                    // Should fail for values beyond max
                    assert!(
                        encode_result.is_err(),
                        "Expected encoding to fail for value beyond max: {}",
                        test_value
                    );
                }
                _ => {
                    // Should succeed for valid values
                    assert!(
                        encode_result.is_ok(),
                        "Expected encoding to succeed for boundary value: {}",
                        test_value
                    );

                    // Test decoding
                    if encode_result.is_ok() {
                        let decode_result = decode_varint(&encoded);
                        assert!(
                            decode_result.is_ok(),
                            "Expected decoding to succeed for boundary value: {}",
                            test_value
                        );

                        if let Ok((decoded_value, consumed)) = decode_result {
                            assert_eq!(
                                decoded_value, test_value,
                                "Roundtrip failed for boundary value: {}",
                                test_value
                            );
                            assert_eq!(
                                consumed,
                                encoded.len(),
                                "Consumed bytes mismatch for boundary value: {}",
                                test_value
                            );
                        }
                    }
                }
            }
        }

        VarIntOperation::MalformedVarint { mut malformed_data } => {
            if malformed_data.len() > MAX_INPUT_SIZE {
                malformed_data.truncate(MAX_INPUT_SIZE);
            }

            // Should handle malformed data gracefully
            let _ = decode_varint(&malformed_data);
        }
    }
}

fn test_connection_id_operation(operation: ConnectionIdOperation) {
    match operation {
        ConnectionIdOperation::CreateFromBytes { mut bytes } => {
            if bytes.len() > MAX_CONNECTION_ID_TEST_SIZE {
                bytes.truncate(MAX_CONNECTION_ID_TEST_SIZE);
            }

            let result = ConnectionId::new(&bytes);

            if bytes.len() <= ConnectionId::MAX_LEN {
                // Should succeed for valid lengths
                assert!(
                    result.is_ok(),
                    "Expected ConnectionId creation to succeed for {} bytes",
                    bytes.len()
                );

                if let Ok(cid) = result {
                    assert_eq!(cid.len(), bytes.len(), "ConnectionId length mismatch");
                    assert_eq!(cid.as_bytes(), &bytes[..], "ConnectionId bytes mismatch");
                    assert_eq!(
                        cid.is_empty(),
                        bytes.is_empty(),
                        "ConnectionId empty check mismatch"
                    );
                }
            } else {
                // Should fail for oversized inputs
                assert!(
                    result.is_err(),
                    "Expected ConnectionId creation to fail for {} bytes",
                    bytes.len()
                );

                if let Err(QuicCoreError::InvalidConnectionIdLength(len)) = result {
                    assert_eq!(len, bytes.len(), "Error should report correct length");
                }
            }
        }

        ConnectionIdOperation::CreateEmpty => {
            let result = ConnectionId::new(&[]);
            assert!(result.is_ok(), "Empty ConnectionId should be valid");

            if let Ok(cid) = result {
                assert_eq!(cid.len(), 0, "Empty ConnectionId should have zero length");
                assert!(cid.is_empty(), "Empty ConnectionId should report as empty");
                assert_eq!(
                    cid.as_bytes(),
                    &[] as &[u8],
                    "Empty ConnectionId should return empty slice"
                );
            }
        }

        ConnectionIdOperation::CreateMaxLength => {
            let bytes = vec![0x42; ConnectionId::MAX_LEN];
            let result = ConnectionId::new(&bytes);
            assert!(result.is_ok(), "Max length ConnectionId should be valid");

            if let Ok(cid) = result {
                assert_eq!(
                    cid.len(),
                    ConnectionId::MAX_LEN,
                    "Max length ConnectionId should report correct length"
                );
                assert!(
                    !cid.is_empty(),
                    "Max length ConnectionId should not be empty"
                );
                assert_eq!(
                    cid.as_bytes().len(),
                    ConnectionId::MAX_LEN,
                    "Max length ConnectionId should return correct bytes"
                );
            }
        }

        ConnectionIdOperation::CreateOversized { extra_bytes } => {
            let oversized_len = ConnectionId::MAX_LEN + 1 + (extra_bytes as usize % 100);
            let bytes = vec![0x42; oversized_len];
            let result = ConnectionId::new(&bytes);
            assert!(result.is_err(), "Oversized ConnectionId should fail");
        }
    }
}

fn test_packet_operation(operation: PacketOperation) {
    match operation {
        PacketOperation::ParseHeader {
            mut packet_data,
            short_dcid_len,
        } => {
            if packet_data.len() > MAX_INPUT_SIZE {
                packet_data.truncate(MAX_INPUT_SIZE);
            }

            let dcid_len = (short_dcid_len as usize).min(ConnectionId::MAX_LEN);
            let result = PacketHeader::decode(&packet_data, dcid_len);

            match result {
                Ok((header, consumed)) => {
                    // Verify consumed bytes are reasonable
                    assert!(
                        consumed <= packet_data.len(),
                        "Consumed more bytes than available"
                    );
                    assert!(consumed > 0, "Must consume at least one byte");

                    // Verify header consistency
                    verify_packet_header_consistency(&header);
                }
                Err(err) => {
                    // Verify error is appropriate
                    verify_packet_error(&err, &packet_data);
                }
            }
        }

        PacketOperation::ParseLongHeader {
            version,
            mut dst_cid,
            mut src_cid,
            packet_type,
            mut token,
            payload_length,
            packet_number,
        } => {
            // Limit sizes
            if dst_cid.len() > ConnectionId::MAX_LEN {
                dst_cid.truncate(ConnectionId::MAX_LEN);
            }
            if src_cid.len() > ConnectionId::MAX_LEN {
                src_cid.truncate(ConnectionId::MAX_LEN);
            }
            if token.len() > 1000 {
                token.truncate(1000);
            }

            // Construct a long header packet
            let packet_bytes = construct_long_header_bytes(
                version,
                &dst_cid,
                &src_cid,
                packet_type,
                &token,
                payload_length,
                packet_number,
            );

            let _ = PacketHeader::decode(&packet_bytes, dst_cid.len());
        }

        PacketOperation::ParseShortHeader {
            spin,
            key_phase,
            mut dst_cid,
            packet_number,
            packet_number_len,
        } => {
            if dst_cid.len() > ConnectionId::MAX_LEN {
                dst_cid.truncate(ConnectionId::MAX_LEN);
            }

            // Construct a short header packet
            let packet_bytes = construct_short_header_bytes(
                spin,
                key_phase,
                &dst_cid,
                packet_number,
                packet_number_len,
            );

            let _ = PacketHeader::decode(&packet_bytes, dst_cid.len());
        }

        PacketOperation::ParseTruncatedHeader {
            mut complete_header,
            truncate_at,
        } => {
            if complete_header.len() > MAX_INPUT_SIZE {
                complete_header.truncate(MAX_INPUT_SIZE);
            }

            let truncate_pos = (truncate_at as usize).min(complete_header.len());
            let truncated = &complete_header[..truncate_pos];

            // Should handle truncated input gracefully
            let result = PacketHeader::decode(truncated, 8); // Use 8-byte DCID as default
            match result {
                Ok(_) => {
                    // If parsing succeeded, header must be complete enough
                }
                Err(QuicCoreError::UnexpectedEof) => {
                    // Expected for truncated input
                }
                Err(_) => {
                    // Other errors are also acceptable
                }
            }
        }
    }
}

fn test_transport_param_operation(operation: TransportParamOperation) {
    match operation {
        TransportParamOperation::ParseTransportParams { mut tlv_data } => {
            if tlv_data.len() > MAX_INPUT_SIZE {
                tlv_data.truncate(MAX_INPUT_SIZE);
            }

            let result = TransportParameters::decode(&tlv_data);

            match result {
                Ok(params) => {
                    // Verify transport parameters consistency
                    verify_transport_params_consistency(&params);

                    // Test roundtrip if possible
                    test_transport_params_roundtrip(&params);
                }
                Err(err) => {
                    // Verify error is appropriate
                    verify_transport_params_error(&err, &tlv_data);
                }
            }
        }

        TransportParamOperation::ParseKnownParams { params } => {
            // Construct transport parameters TLV
            let tlv_bytes = construct_transport_params_tlv(&params);
            let _ = TransportParameters::decode(&tlv_bytes);
        }

        TransportParamOperation::ParseDuplicateParams { param_id, values } => {
            // Test duplicate parameter detection
            let mut tlv_data = Vec::new();
            for value in values.into_iter().take(10) {
                // Limit to 10 duplicates
                let _ = encode_varint(param_id, &mut tlv_data);
                let _ = encode_varint(8, &mut tlv_data); // 8-byte value length
                tlv_data.extend_from_slice(&value.to_be_bytes());
            }

            let result = TransportParameters::decode(&tlv_data);
            match result {
                Err(QuicCoreError::DuplicateTransportParameter(id)) => {
                    assert_eq!(id, param_id, "Duplicate transport parameter ID mismatch");
                }
                _ => {
                    // Other results are acceptable depending on implementation
                }
            }
        }

        TransportParamOperation::ParseMalformedParams { mut malformed_data } => {
            if malformed_data.len() > MAX_INPUT_SIZE {
                malformed_data.truncate(MAX_INPUT_SIZE);
            }

            // Should handle malformed data gracefully
            let _ = TransportParameters::decode(&malformed_data);
        }

        TransportParamOperation::RoundtripParams { params } => {
            // Test that encoding then decoding preserves the parameters
            let tlv_bytes = construct_transport_params_tlv(&params);
            let result = TransportParameters::decode(&tlv_bytes);

            if let Ok(decoded_params) = result {
                // Verify key parameters are preserved
                verify_params_roundtrip(&params, &decoded_params);
            }
        }
    }
}

fn test_edge_case_operation(operation: EdgeCaseOperation) {
    match operation {
        EdgeCaseOperation::EmptyInput => {
            // Test parsing empty input
            let result_varint = decode_varint(&[]);
            matches!(result_varint, Err(QuicCoreError::UnexpectedEof));

            let result_header = PacketHeader::decode(&[], 8);
            matches!(result_header, Err(QuicCoreError::UnexpectedEof));

            let result_params = TransportParameters::decode(&[]);
            assert!(
                result_params.is_ok(),
                "Empty transport params should be valid"
            );

            let result_cid = ConnectionId::new(&[]);
            assert!(result_cid.is_ok(), "Empty connection ID should be valid");
        }

        EdgeCaseOperation::SingleByte { byte } => {
            // Test single byte input
            let _ = decode_varint(&[byte]);
            let _ = PacketHeader::decode(&[byte], 8);
            let _ = TransportParameters::decode(&[byte]);
            let _ = ConnectionId::new(&[byte]);
        }

        EdgeCaseOperation::LargeInput { size, fill_pattern } => {
            let size = (size as usize).min(MAX_INPUT_SIZE);
            let data = vec![fill_pattern; size];

            // Test that large inputs don't cause excessive memory usage or timeouts
            let _ = decode_varint(&data);
            let _ = PacketHeader::decode(&data, 8);
            let _ = TransportParameters::decode(&data);
            if size <= ConnectionId::MAX_LEN {
                let _ = ConnectionId::new(&data);
            }
        }

        EdgeCaseOperation::GarbageInput { mut garbage } => {
            if garbage.len() > MAX_INPUT_SIZE {
                garbage.truncate(MAX_INPUT_SIZE);
            }

            // Test that random garbage is handled gracefully
            let _ = decode_varint(&garbage);
            let _ = PacketHeader::decode(&garbage, 8);
            let _ = TransportParameters::decode(&garbage);
            if garbage.len() <= ConnectionId::MAX_LEN {
                let _ = ConnectionId::new(&garbage);
            }
        }

        EdgeCaseOperation::HighEntropyInput { mut entropy_data } => {
            if entropy_data.len() > MAX_INPUT_SIZE {
                entropy_data.truncate(MAX_INPUT_SIZE);
            }

            // Test high-entropy input for potential parser state confusion
            let _ = decode_varint(&entropy_data);
            let _ =
                PacketHeader::decode(&entropy_data, entropy_data.len().min(ConnectionId::MAX_LEN));
            let _ = TransportParameters::decode(&entropy_data);
            if entropy_data.len() <= ConnectionId::MAX_LEN {
                let _ = ConnectionId::new(&entropy_data);
            }
        }
    }
}

fn test_varint_roundtrip(value: u64) {
    let mut encoded = Vec::new();
    let encode_result = encode_varint(value, &mut encoded);

    if value <= QUIC_VARINT_MAX {
        assert!(
            encode_result.is_ok(),
            "Encoding should succeed for valid value: {}",
            value
        );

        let decode_result = decode_varint(&encoded);
        assert!(
            decode_result.is_ok(),
            "Decoding should succeed for encoded value: {}",
            value
        );

        if let Ok((decoded_value, consumed)) = decode_result {
            assert_eq!(
                decoded_value, value,
                "Roundtrip value mismatch: {} != {}",
                value, decoded_value
            );
            assert_eq!(
                consumed,
                encoded.len(),
                "Consumed bytes should match encoded length"
            );
        }
    } else {
        assert!(
            encode_result.is_err(),
            "Encoding should fail for invalid value: {}",
            value
        );
    }
}

fn verify_varint_error(err: &QuicCoreError, data: &[u8]) {
    match err {
        QuicCoreError::UnexpectedEof => {
            // Should occur when input is too short for declared varint length
        }
        QuicCoreError::VarIntOutOfRange(value) => {
            // Should specify the invalid value
            assert!(
                *value > QUIC_VARINT_MAX,
                "VarIntOutOfRange error with valid value: {}",
                value
            );
        }
        _ => {
            // Other errors are unexpected for varint decoding
            panic!("Unexpected error type for varint decoding: {:?}", err);
        }
    }
}

fn verify_packet_header_consistency(header: &PacketHeader) {
    match header {
        PacketHeader::Long(long_header) => {
            // Verify connection ID lengths
            assert!(
                long_header.dst_cid.len() <= ConnectionId::MAX_LEN,
                "Destination CID too long"
            );
            assert!(
                long_header.src_cid.len() <= ConnectionId::MAX_LEN,
                "Source CID too long"
            );

            // Verify packet number length
            assert!(
                long_header.packet_number_len >= 1 && long_header.packet_number_len <= 4,
                "Invalid packet number length: {}",
                long_header.packet_number_len
            );
        }
        PacketHeader::Short(short_header) => {
            // Verify destination connection ID length
            assert!(
                short_header.dst_cid.len() <= ConnectionId::MAX_LEN,
                "Destination CID too long"
            );

            // Verify packet number length
            assert!(
                short_header.packet_number_len >= 1 && short_header.packet_number_len <= 4,
                "Invalid packet number length: {}",
                short_header.packet_number_len
            );
        }
        PacketHeader::Retry(retry_header) => {
            // Verify connection ID lengths
            assert!(
                retry_header.dst_cid.len() <= ConnectionId::MAX_LEN,
                "Destination CID too long"
            );
            assert!(
                retry_header.src_cid.len() <= ConnectionId::MAX_LEN,
                "Source CID too long"
            );
        }
    }
}

fn verify_packet_error(err: &QuicCoreError, _data: &[u8]) {
    match err {
        QuicCoreError::UnexpectedEof => {
            // Should occur when input is too short
        }
        QuicCoreError::InvalidHeader(msg) => {
            // Should describe what's invalid
            assert!(!msg.is_empty(), "Error message should not be empty");
        }
        QuicCoreError::InvalidConnectionIdLength(len) => {
            // Should specify the invalid length
            assert!(
                *len > ConnectionId::MAX_LEN,
                "Invalid connection ID length should be > MAX_LEN"
            );
        }
        _ => {
            // Other errors are acceptable
        }
    }
}

fn verify_transport_params_consistency(params: &TransportParameters) {
    // Verify transport parameter constraints
    if let Some(max_udp_payload_size) = params.max_udp_payload_size {
        assert!(
            max_udp_payload_size >= 1200,
            "max_udp_payload_size must be >= 1200"
        );
    }

    if let Some(ack_delay_exponent) = params.ack_delay_exponent {
        assert!(ack_delay_exponent <= 20, "ack_delay_exponent must be <= 20");
    }

    if let Some(max_ack_delay) = params.max_ack_delay {
        assert!(max_ack_delay < (1u64 << 14), "max_ack_delay must be < 2^14");
    }
}

fn verify_transport_params_error(err: &QuicCoreError, _data: &[u8]) {
    match err {
        QuicCoreError::UnexpectedEof => {
            // Should occur when TLV is truncated
        }
        QuicCoreError::DuplicateTransportParameter(_id) => {
            // Should specify which parameter is duplicated
        }
        QuicCoreError::InvalidTransportParameter(_id) => {
            // Should specify which parameter has invalid value
        }
        QuicCoreError::VarIntOutOfRange(_) => {
            // Can occur when parameter IDs or lengths are invalid varints
        }
        _ => {
            // Other errors are acceptable
        }
    }
}

fn test_transport_params_roundtrip(params: &TransportParameters) {
    // Test encoding then decoding transport parameters
    let mut encoded = Vec::new();
    let encode_result = params.encode(&mut encoded);

    if encode_result.is_ok() {
        let decode_result = TransportParameters::decode(&encoded);
        if let Ok(decoded_params) = decode_result {
            // Verify key fields match
            assert_eq!(params.max_idle_timeout, decoded_params.max_idle_timeout);
            assert_eq!(
                params.max_udp_payload_size,
                decoded_params.max_udp_payload_size
            );
            assert_eq!(params.initial_max_data, decoded_params.initial_max_data);
            assert_eq!(
                params.disable_active_migration,
                decoded_params.disable_active_migration
            );
        }
    }
}

fn construct_long_header_bytes(
    version: u32,
    dst_cid: &[u8],
    src_cid: &[u8],
    packet_type: LongPacketTypeFuzz,
    token: &[u8],
    payload_length: u64,
    packet_number: u32,
) -> Vec<u8> {
    let mut data = Vec::new();

    // First byte: Long form (1) + fixed bit (1) + packet type (2 bits) + type-specific (2 bits) + packet number length - 1 (2 bits)
    let type_bits = match packet_type {
        LongPacketTypeFuzz::Initial => 0b00,
        LongPacketTypeFuzz::ZeroRtt => 0b01,
        LongPacketTypeFuzz::Handshake => 0b10,
        LongPacketTypeFuzz::Retry => 0b11,
    };
    let pn_len = 4u8; // Use 4-byte packet numbers
    let first_byte = 0b1100_0000 | (type_bits << 4) | (pn_len - 1);
    data.push(first_byte);

    // Version
    data.extend_from_slice(&version.to_be_bytes());

    // Connection ID lengths and values
    data.push(dst_cid.len() as u8);
    data.extend_from_slice(dst_cid);
    data.push(src_cid.len() as u8);
    data.extend_from_slice(src_cid);

    // Token length and value (for Initial packets)
    if matches!(packet_type, LongPacketTypeFuzz::Initial) {
        let _ = encode_varint(token.len() as u64, &mut data);
        data.extend_from_slice(token);
    }

    // Payload length
    let _ = encode_varint(payload_length, &mut data);

    // Packet number (truncated based on packet_number_len)
    data.extend_from_slice(&packet_number.to_be_bytes()[4 - pn_len as usize..]);

    data
}

fn construct_short_header_bytes(
    spin: bool,
    key_phase: bool,
    dst_cid: &[u8],
    packet_number: u32,
    packet_number_len: u8,
) -> Vec<u8> {
    let mut data = Vec::new();

    let pn_len = packet_number_len.clamp(1, 4);

    // First byte: Form (0) + fixed bit (1) + spin + reserved (2) + key phase + packet number length - 1 (2 bits)
    let first_byte = 0b0100_0000
        | (if spin { 0b0010_0000 } else { 0 })
        | (if key_phase { 0b0000_0100 } else { 0 })
        | (pn_len - 1);
    data.push(first_byte);

    // Destination connection ID
    data.extend_from_slice(dst_cid);

    // Packet number (truncated)
    data.extend_from_slice(&packet_number.to_be_bytes()[4 - pn_len as usize..]);

    data
}

fn construct_transport_params_tlv(params: &[KnownTransportParam]) -> Vec<u8> {
    let mut tlv_data = Vec::new();

    for param in params.iter().take(20) {
        // Limit to 20 parameters
        let param_id = match param.param_type {
            TransportParamType::MaxIdleTimeout => TP_MAX_IDLE_TIMEOUT,
            TransportParamType::MaxUdpPayloadSize => TP_MAX_UDP_PAYLOAD_SIZE,
            TransportParamType::InitialMaxData => TP_INITIAL_MAX_DATA,
            TransportParamType::InitialMaxStreamDataBidiLocal => {
                TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL
            }
            TransportParamType::InitialMaxStreamDataBidiRemote => {
                TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE
            }
            TransportParamType::InitialMaxStreamDataUni => TP_INITIAL_MAX_STREAM_DATA_UNI,
            TransportParamType::InitialMaxStreamsBidi => TP_INITIAL_MAX_STREAMS_BIDI,
            TransportParamType::InitialMaxStreamsUni => TP_INITIAL_MAX_STREAMS_UNI,
            TransportParamType::AckDelayExponent => TP_ACK_DELAY_EXPONENT,
            TransportParamType::MaxAckDelay => TP_MAX_ACK_DELAY,
            TransportParamType::DisableActiveMigration => TP_DISABLE_ACTIVE_MIGRATION,
            TransportParamType::Unknown(id) => id,
        };

        let _ = encode_varint(param_id, &mut tlv_data);

        // For disable_active_migration, use zero-length value
        if matches!(param.param_type, TransportParamType::DisableActiveMigration) {
            let _ = encode_varint(0, &mut tlv_data);
        } else {
            // Use varint encoding for the value
            let _ = encode_varint(8, &mut tlv_data); // 8-byte value length
            tlv_data.extend_from_slice(&param.value.to_be_bytes());
        }
    }

    tlv_data
}

fn verify_params_roundtrip(original: &[KnownTransportParam], decoded: &TransportParameters) {
    // Check that known parameters are preserved in roundtrip
    for param in original {
        match param.param_type {
            TransportParamType::MaxIdleTimeout => {
                if param.value > 0 {
                    assert_eq!(decoded.max_idle_timeout, Some(param.value));
                }
            }
            TransportParamType::MaxUdpPayloadSize => {
                if param.value >= 1200 {
                    assert_eq!(decoded.max_udp_payload_size, Some(param.value));
                }
            }
            TransportParamType::InitialMaxData => {
                assert_eq!(decoded.initial_max_data, Some(param.value));
            }
            TransportParamType::DisableActiveMigration => {
                assert_eq!(decoded.disable_active_migration, true);
            }
            _ => {
                // Other parameters are optional to check
            }
        }
    }
}
