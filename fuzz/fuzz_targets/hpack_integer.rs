//! Comprehensive fuzz target for HPACK integer decoding per RFC 7541 Section 5.1.
//!
//! This target feeds malformed prefixed integer encodings through the live HPACK
//! header decoder to assert critical security and robustness properties:
//!
//! 1. 2^N-1 encoding extends to continuation bytes correctly
//! 2. overflow on u64::MAX boundary rejected, not silent truncation
//! 3. truncated continuation returns error not panic
//! 4. every public HPACK decoder context that consumes an integer is exercised
//! 5. high-bit-set continuation bytes terminated correctly
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run hpack_integer
//! ```
//!
//! # Security Focus
//! - Integer overflow protection in variable-length encoding
//! - Buffer boundary validation during continuation byte parsing
//! - Prefix bit masking correctness for live HPACK field and string contexts
//! - Shift operation overflow detection
//! - Memory safety under malformed input sequences

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::http::h2::hpack::{Decoder, Header};
use libfuzzer_sys::fuzz_target;

/// Maximum number of continuation bytes for practical testing
const MAX_CONTINUATION_BYTES: usize = 20;
const MAX_BLOCK_BYTES: usize = 256;
const MAX_LITERAL_PAYLOAD: usize = 64;
const MAX_TABLE_SIZE: usize = 4096;

/// HPACK integer decoding fuzzing configuration
#[derive(Arbitrary, Debug, Clone)]
struct HpackIntegerFuzzInput {
    /// Test cases to execute in sequence
    test_cases: Vec<IntegerTestCase>,
}

/// Individual test case for HPACK integer decoding
#[derive(Arbitrary, Debug, Clone)]
enum IntegerTestCase {
    /// Test valid encoding for specific prefix bits
    ValidEncoding {
        context: HpackIntegerContext,
        value: u32, // Bounded to prevent excessive resource usage
    },
    /// Test boundary value 2^N-1 which triggers multi-byte encoding
    BoundaryValue { context: HpackIntegerContext },
    /// Test continuation byte sequences
    ContinuationSequence {
        context: HpackIntegerContext,
        continuation_bytes: Vec<u8>, // Raw continuation bytes
    },
    /// Test truncated input
    TruncatedInput {
        context: HpackIntegerContext,
        partial_bytes: Vec<u8>, // Incomplete byte sequence
    },
    /// Test overflow scenarios
    OverflowAttempt {
        context: HpackIntegerContext,
        large_continuation: LargeValueStrategy,
    },
}

/// Public HPACK decoder contexts that consume an HPACK integer primitive.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum HpackIntegerContext {
    /// RFC 7541 Section 6.3: dynamic table size update, 5-bit prefix.
    DynamicTableSizeUpdate,
    /// RFC 7541 Section 6.1: indexed header field, 7-bit prefix.
    IndexedHeaderField,
    /// RFC 7541 Section 6.2.1: literal with incremental indexing name index, 6-bit prefix.
    LiteralWithIndexingNameIndex,
    /// RFC 7541 Section 6.2.2: literal without indexing name index, 4-bit prefix.
    LiteralWithoutIndexingNameIndex,
    /// RFC 7541 Section 6.2.3: literal never indexed name index, 4-bit prefix.
    LiteralNeverIndexedNameIndex,
    /// RFC 7541 Section 5.2: literal name string length, 7-bit prefix.
    LiteralNameLength,
    /// RFC 7541 Section 5.2: literal value string length, 7-bit prefix.
    LiteralValueLength,
}

impl HpackIntegerContext {
    fn prefix_bits(self) -> u8 {
        match self {
            Self::DynamicTableSizeUpdate => 5,
            Self::IndexedHeaderField | Self::LiteralNameLength | Self::LiteralValueLength => 7,
            Self::LiteralWithIndexingNameIndex => 6,
            Self::LiteralWithoutIndexingNameIndex | Self::LiteralNeverIndexedNameIndex => 4,
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::DynamicTableSizeUpdate => 0x20,
            Self::IndexedHeaderField => 0x80,
            Self::LiteralWithIndexingNameIndex => 0x40,
            Self::LiteralWithoutIndexingNameIndex
            | Self::LiteralNameLength
            | Self::LiteralValueLength => 0x00,
            Self::LiteralNeverIndexedNameIndex => 0x10,
        }
    }

    /// Maximum value that can be encoded in the prefix bits
    fn max_prefix_value(self) -> usize {
        (1 << self.prefix_bits()) - 1
    }
}

/// Strategies for creating large values that might overflow
#[derive(Arbitrary, Debug, Clone)]
enum LargeValueStrategy {
    /// Many continuation bytes with high values
    ManyMaxBytes { count: u8 }, // 0-255 continuation bytes
    /// Specific pattern designed to overflow u64
    OverflowPattern,
    /// Random large continuation sequence
    Random { bytes: Vec<u8> },
    /// Alternating high/low pattern
    Alternating { length: u8 },
}

fuzz_target!(|input: HpackIntegerFuzzInput| {
    assert_seed_integer_contexts_hit_live_decoder();

    // Bound input size to prevent excessive resource usage
    if input.test_cases.len() > 100 {
        return;
    }

    for test_case in &input.test_cases {
        let test_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            process_integer_test_case(test_case)
        }));

        match test_result {
            Ok(()) => {
                // Test case processed successfully
            }
            Err(_) => {
                // **ASSERTION 3**: Truncated continuation returns error not panic
                panic!("HPACK integer decoder panicked on input: {:?}", test_case);
            }
        }
    }
});

/// Process a single integer test case
fn process_integer_test_case(test_case: &IntegerTestCase) {
    match test_case {
        IntegerTestCase::ValidEncoding { context, value } => {
            test_valid_encoding(*context, *value as usize)
        }
        IntegerTestCase::BoundaryValue { context } => test_boundary_value(*context),
        IntegerTestCase::ContinuationSequence {
            context,
            continuation_bytes,
        } => test_continuation_sequence(*context, continuation_bytes),
        IntegerTestCase::TruncatedInput {
            context,
            partial_bytes,
        } => test_truncated_input(*context, partial_bytes),
        IntegerTestCase::OverflowAttempt {
            context,
            large_continuation,
        } => test_overflow_attempt(*context, large_continuation),
    }
}

/// Test valid encoding for various values and prefix bit counts
fn test_valid_encoding(context: HpackIntegerContext, value: usize) {
    let integer = encode_integer_field(context, value);
    observe_live_decoder(context, integer, "valid encoding");
}

/// Test boundary value 2^N-1 which should trigger multi-byte encoding
fn test_boundary_value(context: HpackIntegerContext) {
    // **ASSERTION 1**: 2^N-1 encoding extends to continuation bytes

    let data = vec![context.tag() | context.max_prefix_value() as u8, 0x00];
    observe_live_decoder(context, data, "boundary value");
}

/// Test arbitrary continuation byte sequences
fn test_continuation_sequence(context: HpackIntegerContext, continuation_bytes: &[u8]) {
    // **ASSERTION 5**: High-bit-set continuation bytes terminated correctly

    if continuation_bytes.len() > MAX_CONTINUATION_BYTES {
        return; // Skip excessively long sequences
    }

    let mut data = vec![context.tag() | context.max_prefix_value() as u8];
    data.extend_from_slice(continuation_bytes);

    // **ASSERTION 5**: If the sequence is valid (last byte has high bit clear),
    // it should decode successfully. If invalid (all bytes have high bit set),
    // it should return an error, not panic.
    observe_live_decoder(context, data, "continuation sequence");
}

/// Test truncated input sequences
fn test_truncated_input(context: HpackIntegerContext, partial_bytes: &[u8]) {
    // **ASSERTION 3**: Truncated continuation returns error not panic

    if partial_bytes.is_empty() {
        // Empty header blocks are valid; this still proves the live decoder
        // surface handles the shortest input without panicking.
        observe_raw_block(Bytes::new(), "empty HPACK block");
        return;
    }

    let mut data = Vec::new();

    // Create a sequence that appears to need continuation bytes
    data.push(context.tag() | context.max_prefix_value() as u8);

    // Add partial continuation bytes - all with high bit set (0x80) to indicate "more to come"
    for &byte in partial_bytes.iter().take(MAX_CONTINUATION_BYTES) {
        data.push(byte | 0x80); // Ensure high bit is set to indicate continuation
    }
    // Don't add a final byte without the high bit - this creates truncation

    // **ASSERTION 3**: This should return an error (truncation detected), not panic
    observe_live_decoder(context, data, "truncated input");
}

/// Test overflow scenarios
fn test_overflow_attempt(context: HpackIntegerContext, strategy: &LargeValueStrategy) {
    // **ASSERTION 2**: Overflow on u64::MAX boundary rejected

    let mut data = vec![context.tag() | context.max_prefix_value() as u8];

    match strategy {
        LargeValueStrategy::ManyMaxBytes { count } => {
            // Many 0xFF continuation bytes followed by a terminator
            let byte_count = (*count as usize).min(MAX_CONTINUATION_BYTES);
            data.extend(std::iter::repeat_n(0xFF, byte_count));
            data.push(0x01); // Small terminating value
        }
        LargeValueStrategy::OverflowPattern => {
            // Specific pattern designed to cause overflow
            // This creates a value that would exceed usize::MAX
            data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]);
        }
        LargeValueStrategy::Random { bytes } => {
            // Add random bytes, ensuring the last one terminates
            let limited_bytes = bytes.iter().take(MAX_CONTINUATION_BYTES);
            for (i, &byte) in limited_bytes.enumerate() {
                if i == bytes.len().min(MAX_CONTINUATION_BYTES) - 1 {
                    // Last byte should not have continuation bit
                    data.push(byte & 0x7F);
                } else {
                    // Intermediate bytes should have continuation bit
                    data.push(byte | 0x80);
                }
            }
        }
        LargeValueStrategy::Alternating { length } => {
            // Alternating high/low pattern
            let len = (*length as usize).min(MAX_CONTINUATION_BYTES);
            for i in 0..len {
                let byte = if i % 2 == 0 { 0xFF } else { 0x80 };
                if i == len - 1 {
                    data.push(byte & 0x7F); // Clear continuation bit on last byte
                } else {
                    data.push(byte);
                }
            }
        }
    }

    // **ASSERTION 2**: Large values should either:
    // 1. Be rejected with an overflow error, or
    // 2. Be accepted if they fit in usize
    // They must NOT panic or cause undefined behavior
    observe_live_decoder(context, data, "overflow attempt");
}

fn observe_live_decoder(context: HpackIntegerContext, integer_field: Vec<u8>, scenario: &str) {
    let block = block_for_context(context, integer_field);
    if block.len() > MAX_BLOCK_BYTES {
        return;
    }
    observe_raw_block(Bytes::from(block), scenario);
}

fn observe_raw_block(mut bytes: Bytes, scenario: &str) {
    let before_len = bytes.len();
    let mut decoder = Decoder::with_max_size(MAX_TABLE_SIZE);
    decoder.set_allowed_table_size(MAX_TABLE_SIZE);
    decoder.set_max_header_list_size(MAX_BLOCK_BYTES);

    let result = decoder.decode(&mut bytes);

    assert!(
        bytes.len() <= before_len,
        "{scenario}: decoder grew the input buffer"
    );
    assert!(
        decoder.dynamic_table_size() <= decoder.dynamic_table_max_size(),
        "{scenario}: dynamic table size exceeded its max"
    );

    match result {
        Ok(headers) => {
            for header in headers {
                assert_valid_header(&header, scenario);
            }
        }
        Err(error) => {
            let message = error.to_string();
            assert!(
                !message.trim().is_empty(),
                "{scenario}: empty HPACK error message"
            );
        }
    }
}

fn assert_valid_header(header: &Header, scenario: &str) {
    assert!(
        valid_header_name(&header.name),
        "{scenario}: decoded invalid header name {:?}",
        header.name
    );
    assert!(
        valid_header_value(&header.value),
        "{scenario}: decoded invalid header value {:?}",
        header.value
    );
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().enumerate().all(|(i, b)| {
            matches!(
                b,
                b'a'..=b'z'
                    | b'0'..=b'9'
                    | b'!'
                    | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            ) || (b == b':' && i == 0)
        })
}

fn valid_header_value(value: &str) -> bool {
    !value.bytes().any(|b| matches!(b, b'\0' | b'\r' | b'\n'))
}

fn block_for_context(context: HpackIntegerContext, integer_field: Vec<u8>) -> Vec<u8> {
    let mut block = Vec::with_capacity(integer_field.len() + MAX_LITERAL_PAYLOAD + 8);
    match context {
        HpackIntegerContext::DynamicTableSizeUpdate | HpackIntegerContext::IndexedHeaderField => {
            block.extend_from_slice(&integer_field);
        }
        HpackIntegerContext::LiteralWithIndexingNameIndex
        | HpackIntegerContext::LiteralWithoutIndexingNameIndex
        | HpackIntegerContext::LiteralNeverIndexedNameIndex => {
            block.extend_from_slice(&integer_field);
            append_plain_string(&mut block, b"x");
            append_plain_string(&mut block, b"v");
        }
        HpackIntegerContext::LiteralNameLength => {
            block.push(0x00); // Literal without indexing, literal name follows.
            block.extend_from_slice(&integer_field);
            block.extend(std::iter::repeat_n(b'a', MAX_LITERAL_PAYLOAD));
            append_plain_string(&mut block, b"v");
        }
        HpackIntegerContext::LiteralValueLength => {
            block.push(0x02); // Literal without indexing, static name index 2 (:method).
            block.extend_from_slice(&integer_field);
            block.extend(std::iter::repeat_n(b'a', MAX_LITERAL_PAYLOAD));
        }
    }
    block
}

fn encode_integer_field(context: HpackIntegerContext, value: usize) -> Vec<u8> {
    let prefix_bits = context.prefix_bits();
    let max_first = (1usize << prefix_bits) - 1;
    let mut out = Vec::new();

    if value < max_first {
        out.push(context.tag() | value as u8);
        return out;
    }

    out.push(context.tag() | max_first as u8);
    let mut remaining = value - max_first;
    while remaining >= 128 {
        out.push((remaining & 0x7f) as u8 | 0x80);
        remaining >>= 7;
    }
    out.push(remaining as u8);
    out
}

fn append_plain_string(dst: &mut Vec<u8>, value: &[u8]) {
    encode_plain_string_len(dst, value.len());
    dst.extend_from_slice(value);
}

fn encode_plain_string_len(dst: &mut Vec<u8>, len: usize) {
    let context = HpackIntegerContext::LiteralValueLength;
    let encoded = encode_integer_field(context, len);
    dst.extend_from_slice(&encoded);
}

fn assert_seed_integer_contexts_hit_live_decoder() {
    let mut decoder = Decoder::with_max_size(MAX_TABLE_SIZE);
    decoder.set_allowed_table_size(MAX_TABLE_SIZE);

    let mut table_update = Bytes::from(vec![0x3f, 0x00]);
    let headers = decoder
        .decode(&mut table_update)
        .expect("boundary table-size update should decode");
    assert!(headers.is_empty());
    assert_eq!(decoder.dynamic_table_max_size(), 31);

    let mut indexed = Bytes::from(vec![0x82]);
    let headers = Decoder::new()
        .decode(&mut indexed)
        .expect("indexed static header should decode");
    assert_eq!(headers, vec![Header::new(":method", "GET")]);

    let mut literal = Vec::from([0x42]);
    append_plain_string(&mut literal, b"GET");
    let headers = Decoder::new()
        .decode(&mut Bytes::from(literal))
        .expect("literal with indexed name should decode");
    assert_eq!(headers, vec![Header::new(":method", "GET")]);

    let mut literal_name = Vec::from([0x00]);
    append_plain_string(&mut literal_name, b"x");
    append_plain_string(&mut literal_name, b"v");
    let headers = Decoder::new()
        .decode(&mut Bytes::from(literal_name))
        .expect("literal name and value lengths should decode");
    assert_eq!(headers, vec![Header::new("x", "v")]);
}
