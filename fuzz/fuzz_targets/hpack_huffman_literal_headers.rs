#![no_main]

//! Structure-aware fuzz target for HPACK Huffman-encoded literal headers.
//!
//! This harness always starts from a valid single-header literal block so it
//! exercises successful Huffman decode paths, then applies length/padding style
//! mutations around that structure to shake out decoder edge cases.

use std::ops::Range;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::{Header, HpackDecoder, HpackEncoder};

const STATIC_LITERAL_NAMES: &[&str] = &[
    "accept-encoding",
    "authorization",
    "cache-control",
    "content-type",
    "user-agent",
    "vary",
];

#[derive(Arbitrary, Debug, Clone, Copy)]
enum LiteralRepresentation {
    IncrementalIndexing,
    NeverIndexed,
    WithoutIndexing,
}

#[derive(Arbitrary, Debug, Clone)]
enum NameSource {
    IndexedStatic { selector: u8 },
    NewLiteral { seed: Vec<u8> },
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum HuffmanMode {
    NameOnly,
    ValueOnly,
    Both,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum LengthMutation {
    Honest,
    ShrinkByOne,
    GrowByOne,
    Oversize,
}

#[derive(Arbitrary, Debug, Clone)]
struct MutationPlan {
    name_length: LengthMutation,
    value_length: LengthMutation,
    truncate_name_tail: u8,
    truncate_value_tail: u8,
    flip_name_tail_bit: bool,
    flip_value_tail_bit: bool,
}

#[derive(Arbitrary, Debug, Clone)]
struct HuffmanLiteralHeaderInput {
    representation: LiteralRepresentation,
    name_source: NameSource,
    value_seed: Vec<u8>,
    huffman_mode: HuffmanMode,
    mutation: MutationPlan,
}

#[derive(Debug, Clone)]
struct ValidLiteralCase {
    representation: LiteralRepresentation,
    indexed_name: bool,
    expected_header: Header,
    huffman_mode: HuffmanMode,
    mutation: MutationPlan,
}

#[derive(Debug, Clone)]
struct LiteralLayout {
    prefix_end: usize,
    name: Option<Range<usize>>,
    value: Range<usize>,
}

fuzz_target!(|input: HuffmanLiteralHeaderInput| {
    let case = build_valid_case(input);
    let raw_block = encode_literal_block(&case.expected_header, case.representation, false);
    let huffman_block = build_huffman_literal_block(&case);

    let expected_headers = vec![case.expected_header.clone()];

    let raw_headers = decode_success_case(&raw_block, case.representation);
    assert_eq!(raw_headers, expected_headers, "raw literal decode drifted");

    let huffman_headers = decode_success_case(&huffman_block, case.representation);
    assert_eq!(
        huffman_headers, raw_headers,
        "Huffman literal header decode drifted from raw form"
    );

    if let Some(mutated) = mutate_literal_block(&huffman_block, case.representation, &case.mutation)
    {
        decode_mutated_case(&mutated, case.representation);
    }
});

fn build_valid_case(input: HuffmanLiteralHeaderInput) -> ValidLiteralCase {
    let (name, indexed_name) = match input.name_source {
        NameSource::IndexedStatic { selector } => (
            STATIC_LITERAL_NAMES[(selector as usize) % STATIC_LITERAL_NAMES.len()].to_string(),
            true,
        ),
        NameSource::NewLiteral { seed } => (sanitize_header_name(&seed), false),
    };

    let value = sanitize_header_value(&input.value_seed);

    ValidLiteralCase {
        representation: input.representation,
        indexed_name,
        expected_header: Header::new(name, value),
        huffman_mode: input.huffman_mode,
        mutation: input.mutation,
    }
}

fn sanitize_header_name(seed: &[u8]) -> String {
    let mut out = String::from("x-fuzz");
    for byte in seed.iter().copied().take(24) {
        let ch = match byte {
            b'a'..=b'z' | b'0'..=b'9' | b'-' => byte as char,
            b'A'..=b'Z' => (byte as char).to_ascii_lowercase(),
            _ => continue,
        };
        out.push(ch);
    }
    if out == "x-fuzz" {
        out.push_str("-name");
    }
    out
}

fn sanitize_header_value(seed: &[u8]) -> String {
    let mut out = String::from("fuzz-");
    for byte in seed.iter().copied().take(40) {
        let ch = match byte {
            0x20..=0x7e if byte != b'\r' && byte != b'\n' => byte as char,
            _ => continue,
        };
        out.push(ch);
    }
    if out == "fuzz-" {
        out.push_str("value");
    }
    out
}

fn encode_literal_block(
    header: &Header,
    representation: LiteralRepresentation,
    use_huffman: bool,
) -> Vec<u8> {
    let mut encoder = HpackEncoder::new();
    encoder.set_use_huffman(use_huffman);

    let mut dst = BytesMut::new();
    match representation {
        LiteralRepresentation::IncrementalIndexing => {
            encoder.encode(std::slice::from_ref(header), &mut dst);
        }
        LiteralRepresentation::NeverIndexed | LiteralRepresentation::WithoutIndexing => {
            encoder.encode_sensitive(std::slice::from_ref(header), &mut dst);
            if matches!(representation, LiteralRepresentation::WithoutIndexing) {
                dst[0] &= !0x10;
            }
        }
    }
    dst.to_vec()
}

fn build_huffman_literal_block(case: &ValidLiteralCase) -> Vec<u8> {
    let raw = encode_literal_block(&case.expected_header, case.representation, false);
    let full_huffman = encode_literal_block(&case.expected_header, case.representation, true);

    let raw_layout =
        parse_literal_layout(&raw, case.representation).expect("raw literal layout should parse");
    let huffman_layout = parse_literal_layout(&full_huffman, case.representation)
        .expect("Huffman literal layout should parse");

    let (name_huffman, value_huffman) = select_huffman_flags(case.indexed_name, case.huffman_mode);

    let mut block = Vec::with_capacity(full_huffman.len());
    block.extend_from_slice(&raw[..raw_layout.prefix_end]);

    if let Some(raw_name) = raw_layout.name.as_ref() {
        let selected_name = if name_huffman {
            &full_huffman[huffman_layout
                .name
                .clone()
                .expect("new literal has name range")]
        } else {
            &raw[raw_name.clone()]
        };
        block.extend_from_slice(selected_name);
    }

    let selected_value = if value_huffman {
        &full_huffman[huffman_layout.value]
    } else {
        &raw[raw_layout.value]
    };
    block.extend_from_slice(selected_value);
    block
}

fn select_huffman_flags(indexed_name: bool, mode: HuffmanMode) -> (bool, bool) {
    match mode {
        HuffmanMode::NameOnly if indexed_name => (false, true),
        HuffmanMode::NameOnly => (true, false),
        HuffmanMode::ValueOnly => (false, true),
        HuffmanMode::Both if indexed_name => (false, true),
        HuffmanMode::Both => (true, true),
    }
}

fn decode_success_case(block: &[u8], representation: LiteralRepresentation) -> Vec<Header> {
    let mut decoder = HpackDecoder::new();
    let mut data = Bytes::copy_from_slice(block);
    let headers = decoder
        .decode(&mut data)
        .expect("valid literal header should decode");
    assert!(data.is_empty(), "decoder left trailing bytes on success");
    assert_eq!(
        headers.len(),
        1,
        "single literal block should decode one header"
    );
    assert_dynamic_table_semantics(&decoder, representation, &headers[0]);
    headers
}

fn decode_mutated_case(block: &[u8], representation: LiteralRepresentation) {
    let mut decoder = HpackDecoder::new();
    let mut data = Bytes::copy_from_slice(block);
    if let Ok(headers) = decoder.decode(&mut data) {
        assert!(
            data.is_empty(),
            "successful decode should consume the mutated literal block"
        );
        assert_eq!(
            headers.len(),
            1,
            "mutated single literal block should not decode extra headers"
        );
        assert_dynamic_table_semantics(&decoder, representation, &headers[0]);
    }
}

fn assert_dynamic_table_semantics(
    decoder: &HpackDecoder,
    representation: LiteralRepresentation,
    header: &Header,
) {
    match representation {
        LiteralRepresentation::IncrementalIndexing => {
            assert_eq!(
                decoder.dynamic_table_size(),
                header.size(),
                "incremental indexing should insert exactly one decoded header"
            );
        }
        LiteralRepresentation::NeverIndexed | LiteralRepresentation::WithoutIndexing => {
            assert_eq!(
                decoder.dynamic_table_size(),
                0,
                "non-indexing literal forms must not populate the dynamic table"
            );
        }
    }
}

fn mutate_literal_block(
    block: &[u8],
    representation: LiteralRepresentation,
    plan: &MutationPlan,
) -> Option<Vec<u8>> {
    let layout = parse_literal_layout(block, representation)?;

    let mut mutated = Vec::with_capacity(block.len() + 8);
    mutated.extend_from_slice(&block[..layout.prefix_end]);

    if let Some(name_range) = layout.name {
        let name_segment = rewrite_string_segment(
            &block[name_range],
            plan.name_length,
            plan.truncate_name_tail,
            plan.flip_name_tail_bit,
        )?;
        mutated.extend_from_slice(&name_segment);
    }

    let value_segment = rewrite_string_segment(
        &block[layout.value],
        plan.value_length,
        plan.truncate_value_tail,
        plan.flip_value_tail_bit,
    )?;
    mutated.extend_from_slice(&value_segment);

    (mutated != block).then_some(mutated)
}

fn rewrite_string_segment(
    segment: &[u8],
    length_mutation: LengthMutation,
    truncate_tail: u8,
    flip_tail_bit: bool,
) -> Option<Vec<u8>> {
    let (original_len, prefix_len) = decode_hpack_integer(segment, 7)?;
    if segment.len() < prefix_len + original_len {
        return None;
    }

    let huffman_flag = segment.first().copied()? & 0x80;
    let mut payload = segment[prefix_len..prefix_len + original_len].to_vec();

    let truncate_by = truncate_amount(payload.len(), truncate_tail);
    if truncate_by > 0 {
        let new_len = payload.len() - truncate_by;
        payload.truncate(new_len);
    }

    if flip_tail_bit && !payload.is_empty() {
        let last = payload.len() - 1;
        payload[last] ^= 0x01;
    }

    let declared_len = match length_mutation {
        LengthMutation::Honest => payload.len(),
        LengthMutation::ShrinkByOne => payload.len().saturating_sub(1),
        LengthMutation::GrowByOne => payload.len().saturating_add(1),
        LengthMutation::Oversize => payload.len().saturating_add(17),
    };

    let mut out = Vec::with_capacity(prefix_len + payload.len() + 4);
    encode_hpack_integer(&mut out, declared_len, 7, huffman_flag);
    out.extend_from_slice(&payload);
    Some(out)
}

fn truncate_amount(len: usize, selector: u8) -> usize {
    if len == 0 {
        0
    } else {
        (selector as usize) % (len + 1)
    }
}

fn parse_literal_layout(
    block: &[u8],
    representation: LiteralRepresentation,
) -> Option<LiteralLayout> {
    let prefix_bits = match representation {
        LiteralRepresentation::IncrementalIndexing => 6,
        LiteralRepresentation::NeverIndexed | LiteralRepresentation::WithoutIndexing => 4,
    };

    let (name_index, prefix_end) = decode_hpack_integer(block, prefix_bits)?;
    let mut cursor = prefix_end;

    let name = if name_index == 0 {
        let segment_len = string_segment_len(&block[cursor..])?;
        let range = cursor..cursor + segment_len;
        cursor += segment_len;
        Some(range)
    } else {
        None
    };

    let value_len = string_segment_len(&block[cursor..])?;
    let value = cursor..cursor + value_len;
    cursor += value_len;

    if cursor != block.len() {
        return None;
    }

    Some(LiteralLayout {
        prefix_end,
        name,
        value,
    })
}

fn string_segment_len(bytes: &[u8]) -> Option<usize> {
    let (len, prefix_len) = decode_hpack_integer(bytes, 7)?;
    bytes.get(prefix_len..prefix_len + len)?;
    Some(prefix_len + len)
}

fn decode_hpack_integer(bytes: &[u8], prefix_bits: u8) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    let mask = (1usize << prefix_bits) - 1;
    let first_value = (first as usize) & mask;

    if first_value < mask {
        return Some((first_value, 1));
    }

    let mut value = mask;
    let mut shift = 0usize;
    let mut consumed = 1usize;

    loop {
        let byte = *bytes.get(consumed)?;
        consumed += 1;

        let multiplier = 1usize.checked_shl(shift as u32)?;
        let increment = ((byte & 0x7f) as usize).checked_mul(multiplier)?;
        value = value.checked_add(increment)?;

        if byte & 0x80 == 0 {
            return Some((value, consumed));
        }

        shift += 7;
        if shift > 28 {
            return None;
        }
    }
}

fn encode_hpack_integer(dst: &mut Vec<u8>, mut value: usize, prefix_bits: u8, prefix: u8) {
    let mask = (1usize << prefix_bits) - 1;
    if value < mask {
        dst.push(prefix | value as u8);
        return;
    }

    dst.push(prefix | mask as u8);
    value -= mask;

    while value >= 128 {
        dst.push(((value % 128) as u8) | 0x80);
        value /= 128;
    }
    dst.push(value as u8);
}
