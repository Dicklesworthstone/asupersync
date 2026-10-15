#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::{H2Error, HpackDecoder};
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
const MAX_DYNAMIC_ENTRIES: usize = 16;
const MAX_VALUE_LEN: usize = 32;
const MAX_CANDIDATE_INDICES: usize = 32;
const OUT_OF_RANGE_INDEX: usize = 1024;

#[derive(Arbitrary, Debug)]
struct StaticTableLookupInput {
    static_seed: u8,
    dynamic_entries: Vec<DynamicEntryInput>,
    candidate_indices: Vec<u16>,
}

#[derive(Arbitrary, Debug)]
struct DynamicEntryInput {
    name_seed: u8,
    value: Vec<u8>,
}

#[derive(Clone, Debug)]
struct ExpectedHeader {
    name: String,
    value: String,
}

fuzz_target!(|input: StaticTableLookupInput| {
    assert_all_static_indices_decode();

    let static_index = 1 + usize::from(input.static_seed) % STATIC_TABLE_LEN;
    assert_static_index_decodes(static_index);

    assert_index_rejects(0);

    let dynamic_entries = dynamic_entries(&input.dynamic_entries);
    assert_dynamic_or_rejects(STATIC_TABLE_LEN + 1, &dynamic_entries);
    assert_dynamic_or_rejects(STATIC_TABLE_LEN + 2, &dynamic_entries);

    for raw in input
        .candidate_indices
        .iter()
        .take(MAX_CANDIDATE_INDICES)
        .copied()
    {
        let index = STATIC_TABLE_LEN + 1 + usize::from(raw);
        assert_dynamic_or_rejects(index, &dynamic_entries);
    }

    assert_index_rejects_with_dynamic_table(OUT_OF_RANGE_INDEX, &dynamic_entries);
});

fn assert_all_static_indices_decode() {
    let mut block = BytesMut::new();
    for index in 1..=STATIC_TABLE_LEN {
        encode_indexed(&mut block, index);
    }

    let mut decoder = HpackDecoder::new();
    let mut src = block.freeze();
    let headers = decoder
        .decode(&mut src)
        .expect("all HPACK static-table indexed fields must decode");

    assert!(src.is_empty(), "static indexed block left unread bytes");
    assert_eq!(headers.len(), STATIC_TABLE_LEN);

    for (header, &(name, value)) in headers.iter().zip(STATIC_TABLE.iter()) {
        assert_eq!(header.name, name);
        assert_eq!(header.value, value);
    }
}

fn assert_static_index_decodes(index: usize) {
    let mut decoder = HpackDecoder::new();
    let headers = decode_indexed(&mut decoder, index).expect("valid static index must decode");
    assert_eq!(headers.len(), 1);

    let (name, value) = STATIC_TABLE[index - 1];
    assert_eq!(headers[0].name, name);
    assert_eq!(headers[0].value, value);
}

fn assert_index_rejects(index: usize) {
    let mut decoder = HpackDecoder::new();
    assert_compression_error(decode_indexed(&mut decoder, index));
}

fn assert_dynamic_or_rejects(index: usize, dynamic_entries: &[ExpectedHeader]) {
    let mut decoder = HpackDecoder::new();
    seed_dynamic_table(&mut decoder, dynamic_entries);

    let result = decode_indexed(&mut decoder, index);
    let dynamic_index = index.saturating_sub(STATIC_TABLE_LEN);

    if (1..=dynamic_entries.len()).contains(&dynamic_index) {
        let expected = &dynamic_entries[dynamic_entries.len() - dynamic_index];
        let headers = result.expect("in-range dynamic index must decode");
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].name, expected.name);
        assert_eq!(headers[0].value, expected.value);
    } else {
        assert_compression_error(result);
    }
}

fn assert_index_rejects_with_dynamic_table(index: usize, dynamic_entries: &[ExpectedHeader]) {
    let mut decoder = HpackDecoder::new();
    seed_dynamic_table(&mut decoder, dynamic_entries);
    assert_compression_error(decode_indexed(&mut decoder, index));
}

fn decode_indexed(
    decoder: &mut HpackDecoder,
    index: usize,
) -> Result<Vec<asupersync::http::h2::hpack::Header>, H2Error> {
    let mut block = BytesMut::new();
    encode_indexed(&mut block, index);
    let mut src = block.freeze();
    let headers = decoder.decode(&mut src)?;
    assert!(src.is_empty(), "indexed decode left unread bytes");
    Ok(headers)
}

fn dynamic_entries(inputs: &[DynamicEntryInput]) -> Vec<ExpectedHeader> {
    let mut entries = Vec::with_capacity(inputs.len().clamp(1, MAX_DYNAMIC_ENTRIES));
    entries.push(ExpectedHeader {
        name: "x-hpack-static-fuzz".to_string(),
        value: "seed".to_string(),
    });

    for input in inputs.iter().take(MAX_DYNAMIC_ENTRIES.saturating_sub(1)) {
        entries.push(ExpectedHeader {
            name: dynamic_name(input.name_seed).to_string(),
            value: dynamic_value(&input.value),
        });
    }

    entries
}

fn dynamic_name(seed: u8) -> &'static str {
    const NAMES: &[&str] = &[
        "x-hpack-a",
        "x-hpack-b",
        "x-hpack-c",
        "cache-control",
        "user-agent",
        "accept",
    ];
    NAMES[usize::from(seed) % NAMES.len()]
}

fn dynamic_value(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "v".to_string();
    }

    bytes
        .iter()
        .take(MAX_VALUE_LEN)
        .map(|byte| char::from(b'a' + (byte % 26)))
        .collect()
}

fn seed_dynamic_table(decoder: &mut HpackDecoder, entries: &[ExpectedHeader]) {
    for entry in entries {
        let mut block = BytesMut::new();
        encode_integer(&mut block, 0, 6, 0x40);
        encode_string(&mut block, entry.name.as_bytes());
        encode_string(&mut block, entry.value.as_bytes());

        let mut src = block.freeze();
        let decoded = decoder
            .decode(&mut src)
            .expect("valid literal header must seed dynamic table");

        assert!(src.is_empty(), "dynamic-table seed left unread bytes");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name, entry.name);
        assert_eq!(decoded[0].value, entry.value);
    }
}

fn assert_compression_error(result: Result<Vec<asupersync::http::h2::hpack::Header>, H2Error>) {
    let err = result.expect_err("HPACK indexed lookup must reject this index");
    assert_eq!(err.code, ErrorCode::CompressionError);
}

fn encode_indexed(dst: &mut BytesMut, index: usize) {
    encode_integer(dst, index, 7, 0x80);
}

fn encode_string(dst: &mut BytesMut, bytes: &[u8]) {
    encode_integer(dst, bytes.len(), 7, 0x00);
    dst.extend_from_slice(bytes);
}

fn encode_integer(dst: &mut BytesMut, value: usize, prefix_bits: u8, prefix: u8) {
    let max_first = (1usize << prefix_bits) - 1;

    if value < max_first {
        dst.extend_from_slice(&[prefix | value as u8]);
        return;
    }

    dst.extend_from_slice(&[prefix | max_first as u8]);
    let mut remaining = value - max_first;
    while remaining >= 128 {
        dst.extend_from_slice(&[((remaining & 0x7f) as u8) | 0x80]);
        remaining >>= 7;
    }
    dst.extend_from_slice(&[remaining as u8]);
}
