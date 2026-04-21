#![no_main]

//! Fuzz target for src/http/h2/hpack.rs static-table indexed-header parsing.
//!
//! This target focuses on RFC 7541 Section 6.1 indexed-header representations
//! that resolve against the HPACK static table on a decoder with an empty
//! dynamic table.
//!
//! Assertions:
//! 1. Canonical static-table index sequences decode to the exact expected
//!    `(name, value)` pairs.
//! 2. Invalid indices (`0` and `> 61`) are rejected rather than silently
//!    accepted on an empty dynamic table.
//! 3. Rejecting an invalid index does not poison a decoder for a following
//!    canonical static-table decode.
//! 4. Mutated indexed encodings must not panic; successful full-slice decodes
//!    that stay within static-table bounds must still match the expected entry.

use arbitrary::Arbitrary;
use asupersync::{bytes::Bytes, http::h2::hpack::Decoder};
use libfuzzer_sys::fuzz_target;

const STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

const STATIC_TABLE_LEN: usize = 61;
const RECOVERY_INDEX: usize = 2;
const MAX_VALID_INDICES: usize = 64;
const MAX_INVALID_INDICES: usize = 64;
const MAX_MUTATED_CASES: usize = 32;
const MAX_MUTATED_TAIL_LEN: usize = 8;

#[derive(Arbitrary, Debug)]
struct HpackStaticIndexedInput {
    valid_indices: Vec<u8>,
    invalid_indices: Vec<u16>,
    mutated_encodings: Vec<MutatedIndexedEncoding>,
}

#[derive(Arbitrary, Debug)]
struct MutatedIndexedEncoding {
    prefix_payload: u8,
    tail: Vec<u8>,
}

fuzz_target!(|input: HpackStaticIndexedInput| {
    let mut input = input;
    input.valid_indices.truncate(MAX_VALID_INDICES);
    input.invalid_indices.truncate(MAX_INVALID_INDICES);
    input.mutated_encodings.truncate(MAX_MUTATED_CASES);

    verify_canonical_static_sequence(&input.valid_indices);
    verify_invalid_indices_rejected(&input.invalid_indices);
    exercise_mutated_indexed_encodings(&input.mutated_encodings);
});

fn verify_canonical_static_sequence(valid_indices: &[u8]) {
    if valid_indices.is_empty() {
        return;
    }

    let mut block = Vec::with_capacity(valid_indices.len());
    let mut expected = Vec::with_capacity(valid_indices.len());

    for seed in valid_indices {
        let index = 1 + (*seed as usize % STATIC_TABLE_LEN);
        block.extend_from_slice(&encode_indexed(index));
        expected.push(STATIC_TABLE[index - 1]);
    }

    let mut decoder = Decoder::new();
    let mut bytes = Bytes::from(block);
    let headers = decoder
        .decode(&mut bytes)
        .expect("canonical static-table indices must decode");

    assert!(
        bytes.is_empty(),
        "canonical static-table sequence left unread bytes"
    );
    assert_eq!(
        headers.len(),
        expected.len(),
        "canonical static-table sequence changed decoded header count",
    );

    for (header, (expected_name, expected_value)) in headers.iter().zip(expected.iter().copied()) {
        assert_eq!(header.name, expected_name, "static-table name mismatch");
        assert_eq!(header.value, expected_value, "static-table value mismatch");
    }
}

fn verify_invalid_indices_rejected(invalid_indices: &[u16]) {
    for raw in invalid_indices {
        let index = normalize_invalid_index(*raw);
        let mut decoder = Decoder::new();

        let mut invalid_bytes = Bytes::from(encode_indexed(index));
        let invalid_result = decoder.decode(&mut invalid_bytes);
        assert!(
            invalid_result.is_err(),
            "invalid static-table index {index} decoded successfully",
        );

        let mut recovery_bytes = Bytes::from(encode_indexed(RECOVERY_INDEX));
        let recovery_headers = decoder
            .decode(&mut recovery_bytes)
            .expect("decoder should recover after rejecting invalid static-table index");
        assert_eq!(
            recovery_headers.len(),
            1,
            "recovery decode changed header count"
        );
        assert_eq!(recovery_headers[0].name, STATIC_TABLE[RECOVERY_INDEX - 1].0);
        assert_eq!(
            recovery_headers[0].value,
            STATIC_TABLE[RECOVERY_INDEX - 1].1
        );
        assert!(
            recovery_bytes.is_empty(),
            "recovery decode left unread bytes after invalid-index rejection",
        );
    }
}

fn exercise_mutated_indexed_encodings(mutated_encodings: &[MutatedIndexedEncoding]) {
    for encoding in mutated_encodings {
        let mut wire = Vec::with_capacity(1 + encoding.tail.len().min(MAX_MUTATED_TAIL_LEN));
        wire.push(0x80 | (encoding.prefix_payload & 0x7f));
        wire.extend_from_slice(&encoding.tail[..encoding.tail.len().min(MAX_MUTATED_TAIL_LEN)]);

        let parsed_index = decode_indexed_integer(&wire);

        let mut decoder = Decoder::new();
        let mut bytes = Bytes::from(wire);
        if let Ok(headers) = decoder.decode(&mut bytes)
            && headers.len() == 1
            && bytes.is_empty()
            && let Some(index) = parsed_index
            && (1..=STATIC_TABLE_LEN).contains(&index)
        {
            assert_eq!(headers[0].name, STATIC_TABLE[index - 1].0);
            assert_eq!(headers[0].value, STATIC_TABLE[index - 1].1);
        }
    }
}

fn normalize_invalid_index(raw: u16) -> usize {
    if raw.is_multiple_of(2) {
        0
    } else {
        STATIC_TABLE_LEN + 1 + raw as usize
    }
}

fn encode_indexed(index: usize) -> Vec<u8> {
    if index < 0x7f {
        return vec![0x80 | index as u8];
    }

    let mut out = vec![0xff];
    let mut remaining = index - 0x7f;
    while remaining >= 0x80 {
        out.push(((remaining & 0x7f) as u8) | 0x80);
        remaining >>= 7;
    }
    out.push(remaining as u8);
    out
}

fn decode_indexed_integer(bytes: &[u8]) -> Option<usize> {
    let (&first, _) = bytes.split_first()?;
    let prefix = (first & 0x7f) as usize;
    if prefix < 0x7f {
        return (bytes.len() == 1).then_some(prefix);
    }

    let mut value = 0x7fusize;
    let mut shift = 0u32;
    let mut position = 1usize;

    while position < bytes.len() {
        let byte = bytes[position];
        let low_bits = (byte & 0x7f) as usize;
        let increment = low_bits.checked_shl(shift)?;
        value = value.checked_add(increment)?;
        position += 1;

        if byte & 0x80 == 0 {
            return (position == bytes.len()).then_some(value);
        }

        shift += 7;
        if shift >= usize::BITS {
            return None;
        }
    }

    None
}
