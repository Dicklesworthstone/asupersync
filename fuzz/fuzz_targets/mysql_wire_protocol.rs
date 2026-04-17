#![no_main]

use libfuzzer_sys::fuzz_target;

// We can't directly access the private parsing functions, so we'll create equivalent
// parsing logic that exercises similar code paths

/// MySQL packet header structure (4 bytes)
#[derive(Debug)]
struct PacketHeader {
    length: u32,  // 3 bytes, little endian
    sequence: u8, // 1 byte
}

/// MySQL OK packet structure
#[derive(Debug)]
struct OkPacket {
    affected_rows: u64,
    last_insert_id: u64,
    status_flags: u16,
    warning_count: u16,
}

/// Parse MySQL packet header from 4 bytes
fn parse_packet_header(data: &[u8], expected_seq: u8) -> Result<PacketHeader, String> {
    if data.len() < 4 {
        return Err("Header too short".to_string());
    }

    let length = u32::from(data[0]) | (u32::from(data[1]) << 8) | (u32::from(data[2]) << 16);
    let sequence = data[3];

    // MySQL max packet size is 16MB - 1
    const MAX_PACKET_SIZE: u32 = 16_777_215;
    if length > MAX_PACKET_SIZE {
        return Err(format!("Packet too large: {}", length));
    }

    if sequence != expected_seq {
        return Err(format!(
            "Sequence mismatch: expected {}, got {}",
            expected_seq, sequence
        ));
    }

    Ok(PacketHeader { length, sequence })
}

/// Read length-encoded integer (MySQL protocol)
fn read_lenenc_int(data: &[u8], offset: &mut usize) -> Result<u64, String> {
    if *offset >= data.len() {
        return Err("Unexpected end of data".to_string());
    }

    let first_byte = data[*offset];
    *offset += 1;

    match first_byte {
        0..=250 => Ok(u64::from(first_byte)),
        251 => Err("NULL value not supported".to_string()),
        252 => {
            if *offset + 1 >= data.len() {
                return Err("Insufficient data for 2-byte length".to_string());
            }
            let val = u16::from_le_bytes([data[*offset], data[*offset + 1]]);
            *offset += 2;
            Ok(u64::from(val))
        }
        253 => {
            if *offset + 2 >= data.len() {
                return Err("Insufficient data for 3-byte length".to_string());
            }
            let val = u32::from_le_bytes([data[*offset], data[*offset + 1], data[*offset + 2], 0]);
            *offset += 3;
            Ok(u64::from(val))
        }
        254 => {
            if *offset + 7 >= data.len() {
                return Err("Insufficient data for 8-byte length".to_string());
            }
            let val = u64::from_le_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
                data[*offset + 4],
                data[*offset + 5],
                data[*offset + 6],
                data[*offset + 7],
            ]);
            *offset += 8;
            Ok(val)
        }
        _ => Err("Invalid length encoding".to_string()),
    }
}

/// Parse MySQL OK packet (starts with 0x00)
fn parse_ok_packet(data: &[u8]) -> Result<OkPacket, String> {
    if data.is_empty() || data[0] != 0x00 {
        return Err("Not an OK packet".to_string());
    }

    let mut offset = 1; // Skip the 0x00 marker

    let affected_rows = read_lenenc_int(data, &mut offset)?;
    let last_insert_id = read_lenenc_int(data, &mut offset)?;

    if offset + 3 >= data.len() {
        return Err("Insufficient data for status and warning count".to_string());
    }

    let status_flags = u16::from_le_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    let warning_count = u16::from_le_bytes([data[offset], data[offset + 1]]);

    Ok(OkPacket {
        affected_rows,
        last_insert_id,
        status_flags,
        warning_count,
    })
}

/// Parse MySQL EOF packet (starts with 0xFE, length < 9)
fn parse_eof_packet(data: &[u8]) -> Result<u16, String> {
    if data.is_empty() || data[0] != 0xFE {
        return Err("Not an EOF packet".to_string());
    }

    if data.len() >= 9 {
        return Err("Too long for EOF packet".to_string());
    }

    if data.len() < 5 {
        return Err("EOF packet too short".to_string());
    }

    // Skip warning count, read status flags
    let status_flags = u16::from_le_bytes([data[3], data[4]]);
    Ok(status_flags)
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessively large inputs
    if data.len() > 100_000 {
        return;
    }

    // Test 1: Parse as packet header with various expected sequence numbers
    if data.len() >= 4 {
        for seq in [0, 1, 255] {
            let _ = parse_packet_header(data, seq);
        }
    }

    // Test 2: Parse as OK packet
    let _ = parse_ok_packet(data);

    // Test 3: Parse as EOF packet
    let _ = parse_eof_packet(data);

    // Test 4: Test length-encoded integer parsing at various offsets
    for start_offset in [0, 1, 2, 3] {
        if start_offset < data.len() {
            let mut offset = start_offset;
            let _ = read_lenenc_int(data, &mut offset);
        }
    }

    // Test 5: Parse header followed by trying to parse the payload
    if data.len() >= 4 {
        if let Ok(header) = parse_packet_header(data, 0) {
            let payload_start = 4;
            let expected_payload_len = header.length as usize;

            if payload_start + expected_payload_len <= data.len() {
                let payload = &data[payload_start..payload_start + expected_payload_len];

                // Try parsing payload as OK or EOF packet
                let _ = parse_ok_packet(payload);
                let _ = parse_eof_packet(payload);
            }
        }
    }
});
