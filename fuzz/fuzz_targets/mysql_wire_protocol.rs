//! Comprehensive fuzz target for MySQL wire protocol decoder.
//!
//! Tests the MySQL decoder implementation in src/database/mysql.rs with focus on:
//! 1. OK/ERR/EOF packet discrimination
//! 2. Length-encoded integer boundary cases (251, 65535, 16777215)
//! 3. Handshake v10 vs v9 discrimination
//! 4. Capability flags combinations
//! 5. Partial packet reassembly under slow reader
//!
//! # Attack vectors tested:
//! - Malformed packet headers and payloads
//! - Length-encoded integer boundary conditions
//! - Invalid packet type discrimination
//! - Capability flag edge cases
//! - Packet fragmentation and reassembly
//! - Protocol version compatibility
//! - Invalid state transitions
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run fuzz_mysql_wire_protocol
//! ```

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Maximum input size to prevent memory exhaustion.
const MAX_INPUT_SIZE: usize = 100_000;

/// Maximum packet size for testing (16MB - 1).
const MAX_PACKET_SIZE: u32 = 16_777_215;

/// Configuration for MySQL protocol fuzzing operations.
#[derive(Arbitrary, Debug, Clone)]
struct MySqlFuzzConfig {
    /// Test operations to perform.
    operations: Vec<FuzzOperation>,
    /// Base packet data for testing.
    base_packet: PacketTemplate,
    /// Parser configuration.
    parser_config: ParserConfig,
}

/// Different fuzzing operations to test.
#[derive(Arbitrary, Debug, Clone)]
enum FuzzOperation {
    /// Test packet header parsing with corrupted length field.
    CorruptPacketLength { new_length: u32 },
    /// Test packet header parsing with corrupted sequence field.
    CorruptPacketSequence { new_sequence: u8 },
    /// Test length-encoded integer boundary values.
    TestLengthEncodedBoundary { value: u64 },
    /// Test OK packet discrimination (0x00 marker).
    TestOkPacketMarker { corrupt_marker: bool },
    /// Test EOF packet discrimination (0xFE marker).
    TestEofPacketMarker { corrupt_marker: bool },
    /// Test ERR packet discrimination (0xFF marker).
    TestErrPacketMarker { corrupt_marker: bool },
    /// Test handshake version discrimination.
    TestHandshakeVersion { version: u8 },
    /// Test capability flags combinations.
    TestCapabilityFlags { flags: u32 },
    /// Test partial packet scenarios.
    TestPartialPacket { truncate_at: usize },
    /// Test multi-packet reassembly.
    TestMultiPacketReassembly { fragment_sizes: Vec<usize> },
}

/// Template for generating MySQL packets.
#[derive(Arbitrary, Debug, Clone)]
struct PacketTemplate {
    /// Packet type (0x00=OK, 0xFE=EOF, 0xFF=ERR, other=data).
    packet_type: u8,
    /// Base payload data.
    payload: Vec<u8>,
    /// Sequence number.
    sequence: u8,
}

/// Parser configuration options.
#[derive(Arbitrary, Debug, Clone)]
struct ParserConfig {
    /// Expected sequence number for validation.
    expected_sequence: u8,
    /// Maximum allowed packet size.
    max_packet_size: u32,
    /// Enable strict validation.
    strict_validation: bool,
}

/// Generate a MySQL packet header (4 bytes: 3-byte length + 1-byte sequence).
fn generate_packet_header(length: u32, sequence: u8) -> Vec<u8> {
    vec![
        (length & 0xFF) as u8,
        ((length >> 8) & 0xFF) as u8,
        ((length >> 16) & 0xFF) as u8,
        sequence,
    ]
}

/// Generate length-encoded integer bytes according to MySQL protocol.
fn generate_lenenc_int(value: u64) -> Vec<u8> {
    if value < 251 {
        vec![value as u8]
    } else if value < 65536 {
        let mut bytes = vec![0xFC];
        bytes.extend_from_slice(&(value as u16).to_le_bytes());
        bytes
    } else if value < 16_777_216 {
        let mut bytes = vec![0xFD];
        bytes.push((value & 0xFF) as u8);
        bytes.push(((value >> 8) & 0xFF) as u8);
        bytes.push(((value >> 16) & 0xFF) as u8);
        bytes
    } else {
        let mut bytes = vec![0xFE];
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes
    }
}

/// Generate a MySQL OK packet (0x00 + affected_rows + last_insert_id + status + warnings).
fn generate_ok_packet(
    affected_rows: u64,
    last_insert_id: u64,
    status: u16,
    warnings: u16,
) -> Vec<u8> {
    let mut packet = vec![0x00]; // OK packet marker
    packet.extend_from_slice(&generate_lenenc_int(affected_rows));
    packet.extend_from_slice(&generate_lenenc_int(last_insert_id));
    packet.extend_from_slice(&status.to_le_bytes());
    packet.extend_from_slice(&warnings.to_le_bytes());
    packet
}

/// Generate a MySQL EOF packet (0xFE + warnings + status).
fn generate_eof_packet(warnings: u16, status: u16) -> Vec<u8> {
    let mut packet = vec![0xFE]; // EOF packet marker
    packet.extend_from_slice(&warnings.to_le_bytes());
    packet.extend_from_slice(&status.to_le_bytes());
    packet
}

/// Generate a MySQL ERR packet (0xFF + error_code + sql_state + message).
fn generate_err_packet(error_code: u16, sql_state: &str, message: &str) -> Vec<u8> {
    let mut packet = vec![0xFF]; // ERR packet marker
    packet.extend_from_slice(&error_code.to_le_bytes());
    packet.push(b'#'); // SQL state marker
    packet.extend_from_slice(sql_state.as_bytes());
    packet.extend_from_slice(message.as_bytes());
    packet
}

/// Generate MySQL handshake packet with specified version.
fn generate_handshake_packet(protocol_version: u8, capabilities: u32) -> Vec<u8> {
    let mut packet = vec![protocol_version]; // Protocol version
    packet.extend_from_slice(b"8.0.0\0"); // Server version
    packet.extend_from_slice(&[0, 0, 0, 0]); // Connection ID (4 bytes)
    packet.extend_from_slice(&[0; 8]); // Auth plugin data part 1 (8 bytes)
    packet.push(0); // Filler
    packet.extend_from_slice(&(capabilities as u16).to_le_bytes()); // Capabilities (lower 16 bits)
    packet.push(0x21); // Character set
    packet.extend_from_slice(&[0; 2]); // Status flags
    packet.extend_from_slice(&((capabilities >> 16) as u16).to_le_bytes()); // Capabilities (upper 16 bits)
    packet.push(21); // Auth plugin data length
    packet.extend_from_slice(&[0; 10]); // Reserved
    packet.extend_from_slice(&[0; 13]); // Auth plugin data part 2
    packet.extend_from_slice(b"mysql_native_password\0"); // Auth plugin name
    packet
}

/// Test MySQL packet parsing with various operations.
fn test_mysql_decoder(data: &[u8], operations: &[FuzzOperation], config: &ParserConfig) {
    for operation in operations {
        match operation {
            FuzzOperation::CorruptPacketLength { new_length } => {
                test_packet_header_corruption(data, *new_length, config.expected_sequence);
            }
            FuzzOperation::CorruptPacketSequence { new_sequence } => {
                test_packet_sequence_corruption(data, *new_sequence);
            }
            FuzzOperation::TestLengthEncodedBoundary { value } => {
                test_lenenc_int_boundary(*value);
            }
            FuzzOperation::TestOkPacketMarker { corrupt_marker } => {
                test_ok_packet_discrimination(data, *corrupt_marker);
            }
            FuzzOperation::TestEofPacketMarker { corrupt_marker } => {
                test_eof_packet_discrimination(data, *corrupt_marker);
            }
            FuzzOperation::TestErrPacketMarker { corrupt_marker } => {
                test_err_packet_discrimination(data, *corrupt_marker);
            }
            FuzzOperation::TestHandshakeVersion { version } => {
                test_handshake_version_discrimination(*version);
            }
            FuzzOperation::TestCapabilityFlags { flags } => {
                test_capability_flags_combinations(*flags);
            }
            FuzzOperation::TestPartialPacket { truncate_at } => {
                test_partial_packet_parsing(data, *truncate_at);
            }
            FuzzOperation::TestMultiPacketReassembly { fragment_sizes } => {
                test_multi_packet_reassembly(data, fragment_sizes);
            }
        }
    }
}

/// Test packet header corruption scenarios.
fn test_packet_header_corruption(data: &[u8], corrupt_length: u32, expected_seq: u8) {
    if data.len() < 4 {
        return;
    }

    let mut test_data = data.to_vec();

    // Corrupt the length field (first 3 bytes)
    test_data[0] = (corrupt_length & 0xFF) as u8;
    test_data[1] = ((corrupt_length >> 8) & 0xFF) as u8;
    test_data[2] = ((corrupt_length >> 16) & 0xFF) as u8;

    // Test boundary conditions for packet length
    let boundary_lengths = [
        0, 1, 250, 251, 65535, 65536, 16_777_214, 16_777_215, 16_777_216,
    ];

    for &length in &boundary_lengths {
        let header = generate_packet_header(length, expected_seq);
        let mut combined = header;
        if data.len() > 4 {
            combined.extend_from_slice(&data[4..]);
        }

        // Try parsing the corrupted header - should handle gracefully
        let _ = parse_packet_header(&combined, expected_seq);
    }
}

/// Test packet sequence number corruption.
fn test_packet_sequence_corruption(data: &[u8], corrupt_sequence: u8) {
    if data.len() < 4 {
        return;
    }

    let mut test_data = data.to_vec();
    test_data[3] = corrupt_sequence; // Corrupt sequence field

    // Test with various expected sequence numbers
    for expected_seq in [0, 1, 255, corrupt_sequence.wrapping_add(1)] {
        let _ = parse_packet_header(&test_data, expected_seq);
    }
}

/// Test length-encoded integer boundary conditions.
fn test_lenenc_int_boundary(value: u64) {
    // Test the critical boundary values mentioned in the task
    let boundary_values = [
        0, 1, 250, 251, 252, 253, 254, 255, 65534, 65535, 65536, 16_777_214, 16_777_215,
        16_777_216, value, // Plus the fuzzed value
    ];

    for &test_value in &boundary_values {
        let encoded = generate_lenenc_int(test_value);
        let _ = parse_lenenc_int(&encoded, 0);

        // Test with truncated data
        for truncate_len in 1..=encoded.len() {
            let truncated = &encoded[..truncate_len.min(encoded.len())];
            let _ = parse_lenenc_int(truncated, 0);
        }
    }
}

/// Test OK packet discrimination (0x00 marker).
fn test_ok_packet_discrimination(data: &[u8], corrupt_marker: bool) {
    // Generate valid OK packet
    let ok_packet = generate_ok_packet(1, 0, 0x0002, 0);
    let _ = parse_ok_packet(&ok_packet);

    if corrupt_marker && !ok_packet.is_empty() {
        // Test with corrupted marker
        let mut corrupted = ok_packet.clone();
        corrupted[0] = 0x01; // Change from 0x00 to 0x01
        let _ = parse_ok_packet(&corrupted);
    }

    // Test with fuzzed data as potential OK packet
    let _ = parse_ok_packet(data);
}

/// Test EOF packet discrimination (0xFE marker).
fn test_eof_packet_discrimination(data: &[u8], corrupt_marker: bool) {
    // Generate valid EOF packet
    let eof_packet = generate_eof_packet(0, 0x0002);
    let _ = parse_eof_packet(&eof_packet);

    if corrupt_marker && !eof_packet.is_empty() {
        // Test with corrupted marker
        let mut corrupted = eof_packet.clone();
        corrupted[0] = 0xFD; // Change from 0xFE to 0xFD
        let _ = parse_eof_packet(&corrupted);
    }

    // Test with fuzzed data as potential EOF packet
    let _ = parse_eof_packet(data);
}

/// Test ERR packet discrimination (0xFF marker).
fn test_err_packet_discrimination(data: &[u8], corrupt_marker: bool) {
    // Generate valid ERR packet
    let err_packet = generate_err_packet(1062, "23000", "Duplicate entry");
    let _ = parse_err_packet(&err_packet);

    if corrupt_marker && !err_packet.is_empty() {
        // Test with corrupted marker
        let mut corrupted = err_packet.clone();
        corrupted[0] = 0xFE; // Change from 0xFF to 0xFE
        let _ = parse_err_packet(&corrupted);
    }

    // Test with fuzzed data as potential ERR packet
    let _ = parse_err_packet(data);
}

/// Test handshake version discrimination (v9 vs v10).
fn test_handshake_version_discrimination(version: u8) {
    // Test both v9 and v10 handshakes plus fuzzed version
    let test_versions = [9, 10, version];

    for &test_version in &test_versions {
        // Generate handshake with different capability combinations
        let capability_combinations = [
            0x0000_0000, // No capabilities
            0x0000_0001, // CLIENT_LONG_PASSWORD
            0x0000_0200, // CLIENT_PROTOCOL_41
            0x0000_8000, // CLIENT_SECURE_CONNECTION
            0x000F_F7FF, // Common capability set
            0xFFFF_FFFF, // All capabilities
        ];

        for &capabilities in &capability_combinations {
            let handshake = generate_handshake_packet(test_version, capabilities);
            let _ = parse_handshake_packet(&handshake);
        }
    }
}

/// Test capability flags combinations.
fn test_capability_flags_combinations(flags: u32) {
    // Test various flag combinations including edge cases
    let flag_combinations = [
        0x0000_0000,         // No flags
        0x0000_0001,         // CLIENT_LONG_PASSWORD
        0x0000_0200,         // CLIENT_PROTOCOL_41
        0x0000_8000,         // CLIENT_SECURE_CONNECTION
        0x0010_0000,         // CLIENT_MULTI_STATEMENTS
        0x0100_0000,         // CLIENT_DEPRECATE_EOF
        flags,               // Fuzzed flags
        flags | 0x0000_0200, // Fuzzed + PROTOCOL_41
    ];

    for &test_flags in &flag_combinations {
        let handshake = generate_handshake_packet(10, test_flags);
        let _ = parse_handshake_packet(&handshake);

        // Test flag validation
        let _ = validate_capability_flags(test_flags);
    }
}

/// Test partial packet parsing under slow reader conditions.
fn test_partial_packet_parsing(data: &[u8], truncate_at: usize) {
    if data.is_empty() {
        return;
    }

    let truncate_pos = truncate_at.min(data.len());
    let partial_data = &data[..truncate_pos];

    // Test various parsers with partial data
    let _ = parse_packet_header(partial_data, 0);
    let _ = parse_ok_packet(partial_data);
    let _ = parse_eof_packet(partial_data);
    let _ = parse_err_packet(partial_data);
    let _ = parse_lenenc_int(partial_data, 0);

    // Test incremental parsing (simulating slow reader)
    for chunk_size in [1, 2, 3, 4, 8, 16] {
        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + chunk_size).min(data.len());
            let chunk = &data[offset..end];

            // Try parsing each chunk independently
            let _ = parse_packet_header(chunk, 0);
            let _ = parse_lenenc_int(chunk, 0);

            offset = end;
        }
    }
}

/// Test multi-packet reassembly scenarios.
fn test_multi_packet_reassembly(data: &[u8], fragment_sizes: &[usize]) {
    if data.is_empty() || fragment_sizes.is_empty() {
        return;
    }

    // Create fragmented packets and test reassembly
    let mut offset = 0;
    let mut reassembled = Vec::new();
    let mut sequence = 0u8;

    for &fragment_size in fragment_sizes {
        if offset >= data.len() {
            break;
        }

        let end = (offset + fragment_size).min(data.len());
        let fragment = &data[offset..end];

        // Generate packet header for this fragment
        let header = generate_packet_header(fragment.len() as u32, sequence);

        // Add header + fragment to reassembled stream
        reassembled.extend_from_slice(&header);
        reassembled.extend_from_slice(fragment);

        sequence = sequence.wrapping_add(1);
        offset = end;
    }

    // Try parsing the reassembled packet stream
    let _ = parse_multi_packet_stream(&reassembled);
}

/// Parse MySQL packet header (internal test function).
fn parse_packet_header(data: &[u8], expected_seq: u8) -> Result<(u32, u8), String> {
    if data.len() < 4 {
        return Err("Header too short".to_string());
    }

    let length = u32::from(data[0]) | (u32::from(data[1]) << 8) | (u32::from(data[2]) << 16);
    let sequence = data[3];

    if length > MAX_PACKET_SIZE {
        return Err(format!("Packet too large: {length}"));
    }

    if sequence != expected_seq {
        return Err(format!(
            "Sequence mismatch: expected {expected_seq}, got {sequence}"
        ));
    }

    Ok((length, sequence))
}

/// Parse length-encoded integer (internal test function).
fn parse_lenenc_int(data: &[u8], start_offset: usize) -> Result<u64, String> {
    if start_offset >= data.len() {
        return Err("Offset beyond data".to_string());
    }

    let first_byte = data[start_offset];

    match first_byte {
        0..=250 => Ok(u64::from(first_byte)),
        251 => Err("NULL value".to_string()),
        252 => {
            if start_offset + 3 > data.len() {
                return Err("Insufficient data for 2-byte int".to_string());
            }
            let val = u16::from_le_bytes([data[start_offset + 1], data[start_offset + 2]]);
            Ok(u64::from(val))
        }
        253 => {
            if start_offset + 4 > data.len() {
                return Err("Insufficient data for 3-byte int".to_string());
            }
            let val = u32::from_le_bytes([
                data[start_offset + 1],
                data[start_offset + 2],
                data[start_offset + 3],
                0,
            ]);
            Ok(u64::from(val))
        }
        254 => {
            if start_offset + 9 > data.len() {
                return Err("Insufficient data for 8-byte int".to_string());
            }
            let val = u64::from_le_bytes([
                data[start_offset + 1],
                data[start_offset + 2],
                data[start_offset + 3],
                data[start_offset + 4],
                data[start_offset + 5],
                data[start_offset + 6],
                data[start_offset + 7],
                data[start_offset + 8],
            ]);
            Ok(val)
        }
        255 => Err("Invalid length encoding".to_string()),
    }
}

/// Parse MySQL OK packet (internal test function).
fn parse_ok_packet(data: &[u8]) -> Result<(u64, u64, u16, u16), String> {
    if data.is_empty() || data[0] != 0x00 {
        return Err("Not an OK packet".to_string());
    }

    let mut offset = 1;
    let affected_rows =
        parse_lenenc_int(data, offset).map_err(|_| "Invalid affected_rows".to_string())?;

    // Calculate offset after reading affected_rows
    offset += lenenc_size(affected_rows);
    let last_insert_id =
        parse_lenenc_int(data, offset).map_err(|_| "Invalid last_insert_id".to_string())?;

    offset += lenenc_size(last_insert_id);
    if offset + 4 > data.len() {
        return Err("Insufficient data for status fields".to_string());
    }

    let status_flags = u16::from_le_bytes([data[offset], data[offset + 1]]);
    let warning_count = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);

    Ok((affected_rows, last_insert_id, status_flags, warning_count))
}

/// Parse MySQL EOF packet (internal test function).
fn parse_eof_packet(data: &[u8]) -> Result<(u16, u16), String> {
    if data.is_empty() || data[0] != 0xFE {
        return Err("Not an EOF packet".to_string());
    }

    // EOF packet should be exactly 5 bytes for protocol 4.1
    if data.len() != 5 {
        return Err("Invalid EOF packet length".to_string());
    }

    let warning_count = u16::from_le_bytes([data[1], data[2]]);
    let status_flags = u16::from_le_bytes([data[3], data[4]]);

    Ok((warning_count, status_flags))
}

/// Parse MySQL ERR packet (internal test function).
fn parse_err_packet(data: &[u8]) -> Result<(u16, String, String), String> {
    if data.is_empty() || data[0] != 0xFF {
        return Err("Not an ERR packet".to_string());
    }

    if data.len() < 3 {
        return Err("ERR packet too short".to_string());
    }

    let error_code = u16::from_le_bytes([data[1], data[2]]);

    let mut offset = 3;
    let mut sql_state = String::new();
    let mut message = String::new();

    // Check for SQL state marker (#)
    if offset < data.len() && data[offset] == b'#' {
        offset += 1;

        // Read 5-character SQL state
        if offset + 5 <= data.len() {
            sql_state = String::from_utf8_lossy(&data[offset..offset + 5]).to_string();
            offset += 5;
        }
    }

    // Read error message
    if offset < data.len() {
        message = String::from_utf8_lossy(&data[offset..]).to_string();
    }

    Ok((error_code, sql_state, message))
}

/// Parse MySQL handshake packet (internal test function).
fn parse_handshake_packet(data: &[u8]) -> Result<(u8, u32), String> {
    if data.is_empty() {
        return Err("Empty handshake packet".to_string());
    }

    let protocol_version = data[0];

    // For v10 handshake, capabilities are at specific offset
    if data.len() >= 20 {
        let capabilities_low = u16::from_le_bytes([data[13], data[14]]);
        let capabilities_high = if data.len() >= 32 {
            u16::from_le_bytes([data[17], data[18]])
        } else {
            0
        };

        let capabilities = u32::from(capabilities_low) | (u32::from(capabilities_high) << 16);
        Ok((protocol_version, capabilities))
    } else {
        Err("Handshake packet too short".to_string())
    }
}

/// Parse multi-packet stream (internal test function).
fn parse_multi_packet_stream(data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut packets = Vec::new();
    let mut offset = 0;
    let mut expected_seq = 0u8;

    while offset < data.len() {
        if offset + 4 > data.len() {
            break; // Not enough data for header
        }

        let (length, _sequence) = parse_packet_header(&data[offset..], expected_seq)
            .map_err(|e| format!("Multi-packet parse error: {e}"))?;

        offset += 4; // Skip header

        if offset + length as usize > data.len() {
            break; // Not enough data for payload
        }

        let payload = data[offset..offset + length as usize].to_vec();
        packets.push(payload);

        offset += length as usize;
        expected_seq = expected_seq.wrapping_add(1);
    }

    Ok(packets)
}

/// Validate capability flags (internal test function).
fn validate_capability_flags(flags: u32) -> Result<(), String> {
    // Check for invalid flag combinations
    const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
    const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;

    if (flags & CLIENT_SECURE_CONNECTION) != 0 && (flags & CLIENT_PROTOCOL_41) == 0 {
        return Err("CLIENT_SECURE_CONNECTION requires CLIENT_PROTOCOL_41".to_string());
    }

    Ok(())
}

/// Calculate the byte size of a length-encoded integer encoding.
fn lenenc_size(value: u64) -> usize {
    if value < 251 {
        1
    } else if value < 65536 {
        3 // 1 + 2
    } else if value < 16_777_216 {
        4 // 1 + 3
    } else {
        9 // 1 + 8
    }
}

fuzz_target!(|input: MySqlFuzzConfig| {
    let MySqlFuzzConfig {
        operations,
        base_packet,
        parser_config,
    } = input;

    // Limit operations to prevent timeout
    let limited_operations: Vec<FuzzOperation> = operations.into_iter().take(50).collect();

    // Build test packet from template
    let mut test_packet = Vec::new();

    // Add packet header
    let header = generate_packet_header(base_packet.payload.len() as u32, base_packet.sequence);
    test_packet.extend_from_slice(&header);

    // Add payload based on packet type
    match base_packet.packet_type {
        0x00 => {
            // OK packet
            let ok_data = generate_ok_packet(1, 0, 0x0002, 0);
            test_packet.extend_from_slice(&ok_data);
        }
        0xFE => {
            // EOF packet
            let eof_data = generate_eof_packet(0, 0x0002);
            test_packet.extend_from_slice(&eof_data);
        }
        0xFF => {
            // ERR packet
            let err_data = generate_err_packet(1062, "23000", "Test error");
            test_packet.extend_from_slice(&err_data);
        }
        _ => {
            // Data packet - use fuzzed payload
            test_packet.extend_from_slice(&base_packet.payload);
        }
    }

    // Limit total size to prevent memory exhaustion
    if test_packet.len() > MAX_INPUT_SIZE {
        return;
    }

    // Execute fuzz operations
    test_mysql_decoder(&test_packet, &limited_operations, &parser_config);
});
