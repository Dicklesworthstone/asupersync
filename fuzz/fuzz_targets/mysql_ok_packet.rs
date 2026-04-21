#![no_main]

use asupersync::database::mysql::fuzz_parse_ok_packet_fields;
use libfuzzer_sys::fuzz_target;

const MAX_RAW_PACKET_LEN: usize = 256;
const LENENC_SOURCE_WIDTH: usize = 8;
const TAIL_SOURCE_OFFSET: usize = LENENC_SOURCE_WIDTH * 2;

struct StructuredPacket {
    bytes: Vec<u8>,
    expected: Option<(u64, u16)>,
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_RAW_PACKET_LEN {
        return;
    }

    let _ = fuzz_parse_ok_packet_fields(data);

    if let Some(packet) = build_structured_packet(data) {
        let result = fuzz_parse_ok_packet_fields(&packet.bytes);
        if let Some(expected) = packet.expected {
            assert_eq!(result.expect("structured OK packet should parse"), expected);
        }
    }
});

fn build_structured_packet(seed: &[u8]) -> Option<StructuredPacket> {
    if seed.is_empty() {
        return None;
    }

    let header = match seed[0] & 0x03 {
        0 => 0x00,
        1 => 0xFE,
        2 => 0xFF,
        _ => seed[0],
    };
    let (affected_bytes, affected_rows) =
        encode_lenenc(seed.get(1).copied().unwrap_or(0), take_window(seed, 2));
    let (last_insert_id_bytes, last_insert_id) = encode_lenenc(
        seed.get(2).copied().unwrap_or(0),
        take_window(seed, 2 + LENENC_SOURCE_WIDTH),
    );
    let status_flags = u16::from_le_bytes([
        seed.get(3).copied().unwrap_or(0),
        seed.get(4).copied().unwrap_or(0),
    ]);
    let warnings = u16::from_le_bytes([
        seed.get(5).copied().unwrap_or(0),
        seed.get(6).copied().unwrap_or(0),
    ]);
    let tail_len = usize::from(seed.get(7).copied().unwrap_or(0) & 0x0F);

    let mut bytes =
        Vec::with_capacity(1 + affected_bytes.len() + last_insert_id_bytes.len() + 4 + tail_len);
    bytes.push(header);
    bytes.extend_from_slice(&affected_bytes);
    bytes.extend_from_slice(&last_insert_id_bytes);
    bytes.extend_from_slice(&status_flags.to_le_bytes());
    bytes.extend_from_slice(&warnings.to_le_bytes());
    bytes.extend(seed.iter().copied().skip(TAIL_SOURCE_OFFSET).take(tail_len));

    let required_len = 1 + affected_bytes.len() + last_insert_id_bytes.len() + 4;
    let truncate_to = if seed.get(7).copied().unwrap_or(0) & 0x80 != 0 {
        usize::from(seed[7] & 0x3F).min(bytes.len())
    } else {
        bytes.len()
    };
    bytes.truncate(truncate_to);

    let expected = if header == 0x00 && truncate_to >= required_len {
        match (affected_rows, last_insert_id) {
            (Some(affected_rows), Some(_)) => Some((affected_rows, status_flags)),
            _ => None,
        }
    } else {
        None
    };

    Some(StructuredPacket { bytes, expected })
}

fn take_window(seed: &[u8], start: usize) -> &[u8] {
    let end = start.saturating_add(LENENC_SOURCE_WIDTH).min(seed.len());
    &seed[start.min(seed.len())..end]
}

fn encode_lenenc(selector: u8, source: &[u8]) -> (Vec<u8>, Option<u64>) {
    match selector % 6 {
        0 => {
            let value = source.first().copied().unwrap_or(0) % 251;
            (vec![value], Some(u64::from(value)))
        }
        1 => {
            let mut bytes = [0u8; 2];
            fill_prefix(&mut bytes, source);
            let value = u16::from_le_bytes(bytes);
            let mut encoded = vec![0xFC];
            encoded.extend_from_slice(&bytes);
            (encoded, Some(u64::from(value)))
        }
        2 => {
            let mut bytes = [0u8; 3];
            fill_prefix(&mut bytes, source);
            let value =
                u64::from(bytes[0]) | (u64::from(bytes[1]) << 8) | (u64::from(bytes[2]) << 16);
            let mut encoded = vec![0xFD];
            encoded.extend_from_slice(&bytes);
            (encoded, Some(value))
        }
        3 => {
            let mut bytes = [0u8; 8];
            fill_prefix(&mut bytes, source);
            let value = u64::from_le_bytes(bytes);
            let mut encoded = vec![0xFE];
            encoded.extend_from_slice(&bytes);
            (encoded, Some(value))
        }
        4 => (vec![0xFB], None),
        _ => (vec![0xFF], None),
    }
}

fn fill_prefix<const N: usize>(dst: &mut [u8; N], src: &[u8]) {
    let copy_len = dst.len().min(src.len());
    dst[..copy_len].copy_from_slice(&src[..copy_len]);
}
