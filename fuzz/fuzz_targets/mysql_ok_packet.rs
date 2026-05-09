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

    let raw_result = observe_ok_packet_fields(data);
    if data.first() != Some(&0x00) {
        assert!(
            raw_result.is_none(),
            "non-OK header should not parse as a MySQL OK packet"
        );
    }

    if let Some(packet) = build_structured_packet(data) {
        let result = observe_ok_packet_fields(&packet.bytes);
        if let Some(expected) = packet.expected {
            assert_eq!(result.expect("structured OK packet should parse"), expected);
        } else if packet.bytes.first() != Some(&0x00) {
            assert!(
                result.is_none(),
                "structured non-OK header should not parse as a MySQL OK packet"
            );
        }
    }
});

fn observe_ok_packet_fields(data: &[u8]) -> Option<(u64, u16)> {
    match fuzz_parse_ok_packet_fields(data) {
        Ok(fields) => {
            assert_eq!(
                data.first(),
                Some(&0x00),
                "OK packet parser accepted a non-OK header"
            );
            Some(fields)
        }
        Err(err) => {
            assert!(
                !err.to_string().is_empty(),
                "OK packet parser returned an empty error diagnostic"
            );
            None
        }
    }
}

fn build_structured_packet(seed: &[u8]) -> Option<StructuredPacket> {
    let first = seed.first().copied()?;

    let header = match first & 0x03 {
        0 => 0x00,
        1 => 0xFE,
        2 => 0xFF,
        _ => first,
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
    let truncate_selector = seed.get(7).copied().unwrap_or(0);
    let tail_len = usize::from(truncate_selector & 0x0F);

    let mut bytes =
        Vec::with_capacity(1 + affected_bytes.len() + last_insert_id_bytes.len() + 4 + tail_len);
    bytes.push(header);
    bytes.extend_from_slice(&affected_bytes);
    bytes.extend_from_slice(&last_insert_id_bytes);
    bytes.extend_from_slice(&status_flags.to_le_bytes());
    bytes.extend_from_slice(&warnings.to_le_bytes());
    bytes.extend(seed.iter().copied().skip(TAIL_SOURCE_OFFSET).take(tail_len));

    let required_len = 1 + affected_bytes.len() + last_insert_id_bytes.len() + 4;
    let truncate_to = if truncate_selector & 0x80 != 0 {
        usize::from(truncate_selector & 0x3F).min(bytes.len())
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
    let start = start.min(seed.len());
    let end = start.saturating_add(LENENC_SOURCE_WIDTH).min(seed.len());
    seed.get(start..end).unwrap_or(&[])
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
            let value = bytes.iter().enumerate().fold(0u64, |acc, (offset, byte)| {
                acc | (u64::from(*byte) << (offset * 8))
            });
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
    for (dst_byte, src_byte) in dst.iter_mut().zip(src.iter().copied()) {
        *dst_byte = src_byte;
    }
}
