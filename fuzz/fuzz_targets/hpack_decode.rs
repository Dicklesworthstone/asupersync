//! Fuzz target for `asupersync::http::h2::hpack::Decoder` (RFC 7541).
//!
//! Structure-aware fuzzer that drives the **real** decoder through the five
//! attack vectors called out by br-asupersync-qwebw7:
//!
//! 1. **2-byte huffman prefix edge** — strings whose Huffman length encodes
//!    via the multi-byte integer continuation, exercising the 7-bit prefix +
//!    continuation byte boundary plus EOS-bit handling.
//! 2. **Dynamic table max-size update mid-block** — RFC 7541 §4.2 says size
//!    updates are valid only at the *start* of a block; emitting one after a
//!    header field must produce COMPRESSION_ERROR, not panic.
//! 3. **Indexed literal with no-indexing flag** — `0000xxxx` (Literal Without
//!    Indexing) and `0001xxxx` (Never Indexed) referencing both static and
//!    dynamic table indices, including out-of-bounds.
//! 4. **Table-size shrink with eviction** — sequence of size updates that
//!    forces the dynamic table to evict entries; the decoder must keep its
//!    bookkeeping consistent.
//! 5. **Malformed varint** — the multi-byte HPACK integer continuation
//!    pattern with all-0x80 bytes (overflow), truncated tail, or values past
//!    the implementation's overflow guard.
//!
//! The harness must never panic. Decoder errors are expected and ignored;
//! only crashes / aborts are findings.
//!
//! ```bash
//! cargo +nightly fuzz run fuzz_hpack_decode
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::http::h2::hpack::Decoder;
use libfuzzer_sys::fuzz_target;

const MAX_BLOCK_BYTES: usize = 64 * 1024;
const MAX_TABLE_SIZE: usize = 64 * 1024;

/// Five-arm scenario covering the RFC 7541 corners the bead targets.
#[derive(Arbitrary, Debug)]
enum Scenario {
    /// Vector 1: emit literal headers whose Huffman-encoded string length sits
    /// at the 7-bit prefix boundary, forcing one or more continuation bytes.
    HuffmanPrefixEdge {
        /// Bumped by the harness into the 0x7F..=0x7F+N region to land on the
        /// prefix overflow.
        name_len_bump: u16,
        value_len_bump: u16,
        payload: Vec<u8>,
        use_huffman_flag: bool,
    },
    /// Vector 2: header field followed by a dynamic table size update — the
    /// decoder must reject this (mid-block updates are illegal per §4.2).
    SizeUpdateMidBlock {
        prelude_size_update: Option<u16>,
        first_header_index: u8,
        mid_block_new_size: u16,
        trailing_header: Option<u8>,
    },
    /// Vector 3: literal-without-indexing (`0x00`) and never-indexed (`0x10`)
    /// representations, including out-of-bounds index references.
    LiteralNoIndexing {
        never_indexed: bool,
        name_index: u16,
        value_payload: Vec<u8>,
        use_huffman: bool,
    },
    /// Vector 4: drive a sequence of size updates that grows then shrinks the
    /// dynamic table after inserting indexable headers, forcing eviction.
    TableShrinkEviction {
        allowed_size: u16,
        size_updates: Vec<u16>,
        insertions: Vec<(Vec<u8>, Vec<u8>)>,
        post_insert_size: u16,
        followup_index_lookups: Vec<u8>,
    },
    /// Vector 5: malformed multi-byte HPACK integer encodings — long runs of
    /// 0x80 continuation bytes, truncated tails, MSB-set tails, and prefixes
    /// whose continuation chain exceeds the decoder's overflow guard.
    MalformedVarint {
        prefix_pattern: u8,
        prefix_bits: u8,
        continuation: Vec<u8>,
    },
}

fuzz_target!(|s: Scenario| match s {
    Scenario::HuffmanPrefixEdge {
        name_len_bump,
        value_len_bump,
        payload,
        use_huffman_flag,
    } => fuzz_huffman_prefix_edge(name_len_bump, value_len_bump, &payload, use_huffman_flag),
    Scenario::SizeUpdateMidBlock {
        prelude_size_update,
        first_header_index,
        mid_block_new_size,
        trailing_header,
    } => fuzz_size_update_mid_block(
        prelude_size_update,
        first_header_index,
        mid_block_new_size,
        trailing_header,
    ),
    Scenario::LiteralNoIndexing {
        never_indexed,
        name_index,
        value_payload,
        use_huffman,
    } => fuzz_literal_no_indexing(never_indexed, name_index, &value_payload, use_huffman),
    Scenario::TableShrinkEviction {
        allowed_size,
        size_updates,
        insertions,
        post_insert_size,
        followup_index_lookups,
    } => fuzz_table_shrink_eviction(
        allowed_size,
        &size_updates,
        &insertions,
        post_insert_size,
        &followup_index_lookups,
    ),
    Scenario::MalformedVarint {
        prefix_pattern,
        prefix_bits,
        continuation,
    } => fuzz_malformed_varint(prefix_pattern, prefix_bits, &continuation),
});

/// Vector 1: 7-bit prefix + continuation boundary on the string-length encoding.
fn fuzz_huffman_prefix_edge(
    name_len_bump: u16,
    value_len_bump: u16,
    payload: &[u8],
    use_huffman_flag: bool,
) {
    // Land lengths at and just past the 7-bit prefix overflow point (127).
    let name_len = 127usize.saturating_add((name_len_bump % 16) as usize);
    let value_len = 127usize.saturating_add((value_len_bump % 16) as usize);

    let mut buf = Vec::with_capacity(name_len + value_len + 16);
    // Literal header field without indexing, literal name (0000_0000).
    buf.push(0x00);
    encode_string_len(&mut buf, name_len, use_huffman_flag);
    extend_repeating(&mut buf, payload, name_len);
    encode_string_len(&mut buf, value_len, use_huffman_flag);
    extend_repeating(&mut buf, payload, value_len);

    if buf.len() > MAX_BLOCK_BYTES {
        return;
    }
    let mut decoder = Decoder::new();
    let mut bytes = Bytes::from(buf);
    let _ = decoder.decode(&mut bytes);
}

/// Vector 2: dynamic table size update appearing after a header field.
fn fuzz_size_update_mid_block(
    prelude_size_update: Option<u16>,
    first_header_index: u8,
    mid_block_new_size: u16,
    trailing_header: Option<u8>,
) {
    let mut buf = Vec::with_capacity(16);

    // Optional valid leading size update (allowed at block start).
    if let Some(sz) = prelude_size_update {
        let capped = (sz as usize).min(MAX_TABLE_SIZE);
        buf.push(0x20); // 001xxxxx
        encode_integer_into(&mut buf, capped, 5);
    }

    // First indexed header (1xxxxxxx) — first_header_index forced into a
    // representable range, including 0 (which is invalid per RFC).
    buf.push(0x80);
    encode_integer_into(&mut buf, first_header_index as usize, 7);

    // Mid-block size update — this MUST be a COMPRESSION_ERROR.
    buf.push(0x20);
    encode_integer_into(&mut buf, (mid_block_new_size as usize).min(MAX_TABLE_SIZE), 5);

    // Optional trailing header to ensure the decoder fails *before* consuming it.
    if let Some(idx) = trailing_header {
        buf.push(0x80);
        encode_integer_into(&mut buf, idx as usize, 7);
    }

    let mut decoder = Decoder::new();
    let mut bytes = Bytes::from(buf);
    let _ = decoder.decode(&mut bytes);
}

/// Vector 3: `0000xxxx` (no indexing) and `0001xxxx` (never indexed).
fn fuzz_literal_no_indexing(
    never_indexed: bool,
    name_index: u16,
    value_payload: &[u8],
    use_huffman: bool,
) {
    let prefix = if never_indexed { 0x10 } else { 0x00 };
    let mut buf = Vec::with_capacity(value_payload.len() + 16);

    // 4-bit prefix carries either an index reference (≥1) or 0 = literal name.
    buf.push(prefix);
    encode_integer_into(&mut buf, name_index as usize, 4);

    // If we encoded "literal name" (index 0), emit a literal name string.
    if name_index == 0 {
        let nlen = (value_payload.len() / 2).min(256);
        encode_string_len(&mut buf, nlen, use_huffman);
        extend_repeating(&mut buf, value_payload, nlen);
    }

    let vlen = value_payload.len().min(512);
    encode_string_len(&mut buf, vlen, use_huffman);
    buf.extend_from_slice(&value_payload[..vlen]);

    if buf.len() > MAX_BLOCK_BYTES {
        return;
    }
    let mut decoder = Decoder::new();
    let mut bytes = Bytes::from(buf);
    let _ = decoder.decode(&mut bytes);
}

/// Vector 4: insert headers, then shrink the table to force eviction.
fn fuzz_table_shrink_eviction(
    allowed_size: u16,
    size_updates: &[u16],
    insertions: &[(Vec<u8>, Vec<u8>)],
    post_insert_size: u16,
    followup_index_lookups: &[u8],
) {
    let allowed = (allowed_size as usize).min(MAX_TABLE_SIZE).max(64);
    let mut decoder = Decoder::with_max_size(allowed);
    decoder.set_allowed_table_size(allowed);

    // Block 1: leading size updates (legal at block start) + literal-with-
    // incremental-indexing headers that grow the dynamic table.
    let mut block1 = Vec::with_capacity(256);
    for &sz in size_updates.iter().take(4) {
        let capped = (sz as usize).min(allowed);
        block1.push(0x20);
        encode_integer_into(&mut block1, capped, 5);
    }
    for (name, value) in insertions.iter().take(8) {
        block1.push(0x40); // 01xxxxxx — literal w/ incremental indexing, literal name
        block1.push(0x00);
        let nl = name.len().min(64);
        encode_string_len(&mut block1, nl, false);
        block1.extend_from_slice(&name[..nl]);
        let vl = value.len().min(64);
        encode_string_len(&mut block1, vl, false);
        block1.extend_from_slice(&value[..vl]);
        if block1.len() > MAX_BLOCK_BYTES / 2 {
            break;
        }
    }
    let mut bytes1 = Bytes::from(block1);
    let _ = decoder.decode(&mut bytes1);

    let _grew_to = decoder.dynamic_table_size();

    // Block 2: shrink the dynamic table via size update at start of block —
    // this MUST evict entries deterministically.
    let shrink = (post_insert_size as usize).min(allowed);
    let mut block2 = Vec::with_capacity(64);
    block2.push(0x20);
    encode_integer_into(&mut block2, shrink, 5);

    // Then exercise indexed lookups that may now be evicted.
    for &idx in followup_index_lookups.iter().take(8) {
        block2.push(0x80);
        encode_integer_into(&mut block2, idx as usize, 7);
    }
    let mut bytes2 = Bytes::from(block2);
    let _ = decoder.decode(&mut bytes2);

    // Bookkeeping must remain consistent.
    let _shrunk_to = decoder.dynamic_table_size();
    let _max = decoder.dynamic_table_max_size();
}

/// Vector 5: malformed multi-byte integer continuations.
fn fuzz_malformed_varint(prefix_pattern: u8, prefix_bits: u8, continuation: &[u8]) {
    // Build a buffer that starts with one of the four representation prefixes,
    // followed by an integer whose prefix bits are saturated (forcing
    // continuation), followed by attacker-controlled continuation bytes.
    let bits = prefix_bits.clamp(4, 7);
    let prefix_max: u8 = (1u8 << bits) - 1;

    // Pick a prefix byte consistent with `bits`:
    //   7 → 1xxxxxxx  (indexed, 0x80)
    //   6 → 01xxxxxx  (literal w/ incremental indexing, 0x40)
    //   5 → 001xxxxx  (size update, 0x20)
    //   4 → 0000xxxx  (literal w/o indexing, 0x00)
    let prefix_byte = match bits {
        7 => 0x80 | (prefix_pattern & prefix_max),
        6 => 0x40 | (prefix_pattern & prefix_max),
        5 => 0x20 | (prefix_pattern & prefix_max),
        _ => prefix_pattern & prefix_max,
    };

    let mut buf = Vec::with_capacity(continuation.len() + 2);
    buf.push(prefix_byte | prefix_max); // saturate prefix → forces continuation
    let take = continuation.len().min(64);
    buf.extend_from_slice(&continuation[..take]);

    let mut decoder = Decoder::new();
    let mut bytes = Bytes::from(buf);
    let _ = decoder.decode(&mut bytes);
}

// =========================================================================
// Encoding helpers (RFC 7541 §5).
// =========================================================================

/// Encode the leading byte of an HPACK string literal: the H bit + length.
fn encode_string_len(buf: &mut Vec<u8>, length: usize, huffman: bool) {
    let h = if huffman { 0x80 } else { 0 };
    if length < 0x7F {
        buf.push(h | length as u8);
    } else {
        buf.push(h | 0x7F);
        encode_integer_continuation(buf, length - 0x7F);
    }
}

/// Encode an HPACK integer with `prefix_bits` worth of room in the *current
/// last byte* of `buf` (or pushed fresh). RFC 7541 §5.1.
fn encode_integer_into(buf: &mut Vec<u8>, mut value: usize, prefix_bits: u8) {
    let prefix_max = (1usize << prefix_bits) - 1;
    if value < prefix_max {
        if let Some(last) = buf.last_mut() {
            *last |= value as u8;
        } else {
            buf.push(value as u8);
        }
        return;
    }
    if let Some(last) = buf.last_mut() {
        *last |= prefix_max as u8;
    } else {
        buf.push(prefix_max as u8);
    }
    value -= prefix_max;
    encode_integer_continuation(buf, value);
}

fn encode_integer_continuation(buf: &mut Vec<u8>, mut value: usize) {
    while value >= 0x80 {
        buf.push(0x80 | (value as u8 & 0x7F));
        value >>= 7;
    }
    buf.push(value as u8);
}

/// Append `n` bytes drawn cyclically from `src` (used to fill literal payloads).
fn extend_repeating(buf: &mut Vec<u8>, src: &[u8], n: usize) {
    if src.is_empty() {
        for _ in 0..n {
            buf.push(0);
        }
    } else {
        for i in 0..n {
            buf.push(src[i % src.len()]);
        }
    }
}
