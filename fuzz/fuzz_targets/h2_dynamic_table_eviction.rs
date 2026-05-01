#![no_main]

//! Structure-aware fuzzer for HPACK dynamic-table shrink + eviction pressure in H2 HEADERS.
//!
//! The generated sequence uses real HTTP/2 HEADERS frames whose HPACK payloads:
//! 1. establish a larger dynamic table,
//! 2. shrink it with a dynamic-table size update at the start of the next block,
//! 3. emit literal-with-incremental-indexing fields that would exceed the new limit.

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::http::h2::frame::{Frame, FrameHeader, FrameType, headers_flags, parse_frame};
use asupersync::http::h2::hpack::{Decoder, Header};
use libfuzzer_sys::fuzz_target;

const MAX_GENERATED_HEADERS: usize = 16;
const MAX_SEED_BYTES: usize = 96;
const MAX_OLD_TABLE_SIZE: usize = 2048;
const MAX_NEW_TABLE_SIZE: usize = 512;
const MAX_HEADER_LIST_SIZE: usize = 16 * 1024;

#[derive(Debug, Arbitrary)]
struct DynamicTableEvictionScenario {
    new_table_size: u16,
    old_table_slack: u16,
    stream_id_seed: u16,
    preload: Vec<FuzzHeader>,
    pressure: Vec<FuzzHeader>,
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzHeader {
    name_seed: Vec<u8>,
    value_seed: Vec<u8>,
}

fuzz_target!(|mut scenario: DynamicTableEvictionScenario| {
    normalize_scenario(&mut scenario);

    let new_max = usize::from(scenario.new_table_size) % (MAX_NEW_TABLE_SIZE + 1);
    let old_max =
        (new_max + 1 + (usize::from(scenario.old_table_slack) % 1536)).min(MAX_OLD_TABLE_SIZE);
    let stream_id = odd_stream_id(scenario.stream_id_seed);

    let mut decoder = Decoder::new();
    decoder.set_allowed_table_size(old_max);
    decoder.set_max_header_list_size(MAX_HEADER_LIST_SIZE);

    let preload_headers = build_preload_headers(&scenario.preload, old_max);
    let preload_block = build_hpack_block(old_max, &preload_headers);
    let decoded = decode_headers_payload(&mut decoder, stream_id, preload_block)
        .expect("generated preload HEADERS should decode");
    assert_headers_match(&decoded, &preload_headers);
    assert!(decoder.dynamic_table_size() <= old_max);
    assert_eq!(decoder.dynamic_table_max_size(), old_max);

    let pressure_headers = build_pressure_headers(&scenario.pressure, new_max);
    let pressure_block = build_hpack_block(new_max, &pressure_headers);
    let decoded = decode_headers_payload(&mut decoder, stream_id.wrapping_add(2), pressure_block)
        .expect("generated shrink+literal HEADERS should decode");
    assert_headers_match(&decoded, &pressure_headers);

    assert_eq!(
        decoder.dynamic_table_max_size(),
        new_max,
        "dynamic-table size update in HEADERS was not applied"
    );
    assert!(
        decoder.dynamic_table_size() <= new_max,
        "dynamic table size {} exceeded new max {} after incremental literals",
        decoder.dynamic_table_size(),
        new_max
    );
});

fn normalize_scenario(scenario: &mut DynamicTableEvictionScenario) {
    scenario.preload.truncate(MAX_GENERATED_HEADERS);
    scenario.pressure.truncate(MAX_GENERATED_HEADERS);

    for header in scenario
        .preload
        .iter_mut()
        .chain(scenario.pressure.iter_mut())
    {
        header.name_seed.truncate(MAX_SEED_BYTES);
        header.value_seed.truncate(MAX_SEED_BYTES);
    }
}

fn odd_stream_id(seed: u16) -> u32 {
    let stream = (u32::from(seed) % 1024).saturating_mul(2).saturating_add(1);
    stream.min(0x7fff_fffd)
}

fn build_preload_headers(input: &[FuzzHeader], old_max: usize) -> Vec<Header> {
    let mut headers: Vec<_> = input
        .iter()
        .take(4)
        .enumerate()
        .map(|(index, header)| {
            Header::new(
                sanitize_header_name(&header.name_seed, index, "preload"),
                sanitize_header_value(&header.value_seed),
            )
        })
        .collect();

    if headers.is_empty() {
        headers.push(Header::new("x-preload-0", "warm"));
    }

    let min_fit_value = old_max.saturating_sub("x-preload-fit".len() + 32).min(64);
    if min_fit_value > 0 {
        headers.push(Header::new("x-preload-fit", "p".repeat(min_fit_value)));
    }

    headers
}

fn build_pressure_headers(input: &[FuzzHeader], new_max: usize) -> Vec<Header> {
    let mut headers: Vec<_> = input
        .iter()
        .take(MAX_GENERATED_HEADERS)
        .enumerate()
        .map(|(index, header)| {
            Header::new(
                sanitize_header_name(&header.name_seed, index, "pressure"),
                sanitize_header_value(&header.value_seed),
            )
        })
        .collect();

    if headers.is_empty() {
        headers.push(Header::new("x-pressure-0", "a"));
    }

    let boundary_name = "x-pressure-boundary";
    let boundary_value_len = new_max
        .saturating_add(1)
        .saturating_sub(boundary_name.len() + 32)
        .max(1)
        .min(1024);
    headers.push(Header::new(boundary_name, "b".repeat(boundary_value_len)));

    let accumulated_entry_size: usize = headers.iter().map(Header::size).sum();
    if accumulated_entry_size <= new_max {
        let spill_value_len = new_max
            .saturating_sub(accumulated_entry_size)
            .saturating_add(1);
        headers.push(Header::new(
            "x-pressure-spill",
            "c".repeat(spill_value_len.min(1024)),
        ));
    }

    headers
}

fn build_hpack_block(table_size_update: usize, headers: &[Header]) -> Vec<u8> {
    let mut block = Vec::new();
    encode_hpack_integer(&mut block, table_size_update, 5, 0x20);
    for header in headers {
        encode_literal_with_incremental_indexing(&mut block, header);
    }
    block
}

fn decode_headers_payload(
    decoder: &mut Decoder,
    stream_id: u32,
    header_block: Vec<u8>,
) -> Result<Vec<Header>, Box<dyn std::error::Error>> {
    let header = FrameHeader {
        length: header_block.len() as u32,
        frame_type: FrameType::Headers as u8,
        flags: headers_flags::END_HEADERS,
        stream_id,
    };

    let frame = parse_frame(&header, Bytes::copy_from_slice(&header_block))?;
    let Frame::Headers(headers) = frame else {
        return Err("generated frame was not HEADERS".into());
    };

    let mut block = headers.header_block;
    Ok(decoder.decode(&mut block)?)
}

fn encode_literal_with_incremental_indexing(dst: &mut Vec<u8>, header: &Header) {
    encode_hpack_integer(dst, 0, 6, 0x40);
    encode_hpack_string(dst, header.name.as_bytes());
    encode_hpack_string(dst, header.value.as_bytes());
}

fn encode_hpack_string(dst: &mut Vec<u8>, bytes: &[u8]) {
    encode_hpack_integer(dst, bytes.len(), 7, 0x00);
    dst.extend_from_slice(bytes);
}

fn encode_hpack_integer(dst: &mut Vec<u8>, value: usize, prefix_bits: u8, prefix: u8) {
    let max_first = (1usize << prefix_bits) - 1;
    if value < max_first {
        dst.push(prefix | value as u8);
        return;
    }

    dst.push(prefix | max_first as u8);
    let mut rest = value - max_first;
    while rest >= 128 {
        dst.push((rest as u8 & 0x7f) | 0x80);
        rest >>= 7;
    }
    dst.push(rest as u8);
}

fn sanitize_header_name(seed: &[u8], index: usize, prefix: &str) -> String {
    let mut name = format!("x-{prefix}-{index}");
    for &byte in seed.iter().take(24) {
        match byte % 37 {
            n @ 0..=25 => name.push(char::from(b'a' + n)),
            n @ 26..=35 => name.push(char::from(b'0' + (n - 26))),
            _ => name.push('-'),
        }
    }
    name
}

fn sanitize_header_value(seed: &[u8]) -> String {
    let mut value = String::new();
    for &byte in seed.iter().take(128) {
        let mapped = 0x20 + (byte % 0x5f);
        value.push(char::from(mapped));
    }
    value
}

fn assert_headers_match(decoded: &[Header], expected: &[Header]) {
    assert_eq!(
        decoded.len(),
        expected.len(),
        "decoded header count mismatch"
    );
    for (actual, expected) in decoded.iter().zip(expected) {
        assert_eq!(actual.name, expected.name);
        assert_eq!(actual.value, expected.value);
    }
}
