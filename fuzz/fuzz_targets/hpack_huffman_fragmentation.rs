#![no_main]

//! Structure-aware fuzz target for HPACK encoder huffman-string fragmentation.
//!
//! Targets bit-level fragmentation edge cases in huffman string encoding:
//! - Strings that create various padding scenarios (0-7 residual bits)
//! - Multiple string fragments with different huffman density
//! - Boundary conditions around bit accumulation and byte flushing
//! - Round-trip encoding/decoding consistency across fragmentation patterns

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::{Header, HpackDecoder, HpackEncoder};

/// Controls how many residual bits a string should target when huffman-encoded.
/// This directly exercises the padding logic in `encode_huffman_to_buffer`.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum PaddingTarget {
    /// No residual bits - string ends on byte boundary
    None,
    /// 1-bit residual requires 7-bit EOS padding
    OneBit,
    /// 2-bit residual requires 6-bit EOS padding
    TwoBits,
    /// 3-bit residual requires 5-bit EOS padding
    ThreeBits,
    /// 4-bit residual requires 4-bit EOS padding
    FourBits,
    /// 5-bit residual requires 3-bit EOS padding
    FiveBits,
    /// 6-bit residual requires 2-bit EOS padding
    SixBits,
    /// 7-bit residual requires 1-bit EOS padding
    SevenBits,
}

impl PaddingTarget {
    fn residual_bits(self) -> u8 {
        match self {
            PaddingTarget::None => 0,
            PaddingTarget::OneBit => 1,
            PaddingTarget::TwoBits => 2,
            PaddingTarget::ThreeBits => 3,
            PaddingTarget::FourBits => 4,
            PaddingTarget::FiveBits => 5,
            PaddingTarget::SixBits => 6,
            PaddingTarget::SevenBits => 7,
        }
    }
}

/// String fragment with controlled huffman characteristics
#[derive(Arbitrary, Debug, Clone)]
struct StringFragment {
    /// Base character that forms the core of this fragment
    base_char: FragmentChar,
    /// How many times to repeat the base character
    repeat_count: u8,
    /// Additional characters to append for fine-tuning bit counts
    bit_adjusters: Vec<FragmentChar>,
    /// Target residual bit count after huffman encoding
    padding_target: PaddingTarget,
}

/// Character types with known huffman bit lengths for precise bit manipulation
#[derive(Arbitrary, Debug, Clone, Copy)]
enum FragmentChar {
    /// 'a'-'z': 5-6 bits each in huffman table
    LowerAlpha(u8),
    /// '0'-'9': 5-6 bits each
    Digit(u8),
    /// Common symbols: varying bit lengths
    Space, // 6 bits
    Slash,     // 6 bits
    Equals,    // 8 bits
    Semicolon, // 8 bits
    Comma,     // 8 bits
    /// High-bit characters: 10+ bits each - creates dense huffman codes
    HighBit(u8),
}

impl FragmentChar {
    fn to_byte(self) -> u8 {
        match self {
            FragmentChar::LowerAlpha(v) => b'a' + (v % 26),
            FragmentChar::Digit(v) => b'0' + (v % 10),
            FragmentChar::Space => b' ',
            FragmentChar::Slash => b'/',
            FragmentChar::Equals => b'=',
            FragmentChar::Semicolon => b';',
            FragmentChar::Comma => b',',
            FragmentChar::HighBit(v) => 128 + (v % 128),
        }
    }

    /// Approximate huffman bit length for this character (used for bit targeting)
    fn huffman_bits(self) -> u8 {
        match self {
            FragmentChar::LowerAlpha(_) => 5, // Most common letters are 5 bits
            FragmentChar::Digit(_) => 6,      // Digits are typically 6 bits
            FragmentChar::Space => 6,
            FragmentChar::Slash => 6,
            FragmentChar::Equals => 8,
            FragmentChar::Semicolon => 8,
            FragmentChar::Comma => 8,
            FragmentChar::HighBit(_) => 10, // High bytes are much longer
        }
    }
}

/// Multi-fragment string designed to exercise specific fragmentation patterns
#[derive(Arbitrary, Debug, Clone)]
struct FragmentationPattern {
    /// Main fragments that make up the string
    fragments: Vec<StringFragment>,
    /// Whether to encode as header name or value (affects static table lookups)
    encode_as_name: bool,
    /// Whether this should be a literal or indexed header
    use_literal_encoding: bool,
}

fuzz_target!(|pattern: FragmentationPattern| {
    // Limit complexity to maintain fuzzer performance
    if pattern.fragments.len() > 8 {
        return;
    }

    let test_string = build_fragmentation_string(&pattern);
    if test_string.len() > 1024 {
        return; // Avoid extremely large strings
    }

    // Test round-trip encoding/decoding consistency
    test_round_trip_consistency(&test_string, pattern.encode_as_name);

    // Test encoder fragmentation behavior
    test_encoder_fragmentation(&test_string);

    // Test multiple fragments with different huffman densities
    test_multi_fragment_encoding(&pattern);
});

fn build_fragmentation_string(pattern: &FragmentationPattern) -> String {
    let mut result = String::new();

    for fragment in &pattern.fragments {
        // Add the base character repeated
        let base_byte = fragment.base_char.to_byte();
        let repeat_count = (fragment.repeat_count % 16) + 1; // 1-16 repetitions
        let mut fragment_bits = 0u16;
        for _ in 0..repeat_count {
            if let Ok(ch) = std::str::from_utf8(&[base_byte]) {
                result.push_str(ch);
                fragment_bits += u16::from(fragment.base_char.huffman_bits());
            }
        }

        // Add bit adjusters to hit the target padding
        for adjuster in &fragment.bit_adjusters {
            let adj_byte = adjuster.to_byte();
            if let Ok(ch) = std::str::from_utf8(&[adj_byte]) {
                result.push_str(ch);
                fragment_bits += u16::from(adjuster.huffman_bits());
            }
        }

        // Nudge this fragment toward the requested residual bit count. The
        // bit lengths are approximate, but they keep the fuzzer steering input
        // toward each padding class without depending on private HPACK tables.
        let target_residual = u16::from(fragment.padding_target.residual_bits());
        for _ in 0..8 {
            if fragment_bits % 8 == target_residual {
                break;
            }
            result.push('a');
            fragment_bits += u16::from(FragmentChar::LowerAlpha(0).huffman_bits());
        }
    }

    // Ensure we have a valid header string
    if result.is_empty() {
        result = "test-value".to_string();
    } else if pattern.encode_as_name {
        // Header names must be lowercase ASCII
        result = result.to_ascii_lowercase();
        result.retain(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if result.is_empty() || !result.chars().next().unwrap().is_ascii_alphabetic() {
            result = format!("x-{}", result);
        }
    }

    result
}

fn test_round_trip_consistency(test_string: &str, as_name: bool) {
    let header = if as_name {
        Header::new(test_string, "test-value")
    } else {
        Header::new("x-test-name", test_string)
    };

    // Encode with huffman
    let mut huffman_encoder = HpackEncoder::new();
    huffman_encoder.set_use_huffman(true);
    let mut huffman_dst = BytesMut::new();
    huffman_encoder.encode(std::slice::from_ref(&header), &mut huffman_dst);

    // Encode without huffman
    let mut literal_encoder = HpackEncoder::new();
    literal_encoder.set_use_huffman(false);
    let mut literal_dst = BytesMut::new();
    literal_encoder.encode(std::slice::from_ref(&header), &mut literal_dst);

    // Both should decode to the same result
    let huffman_decoded = decode_headers(&huffman_dst);
    let literal_decoded = decode_headers(&literal_dst);

    assert_eq!(
        huffman_decoded, literal_decoded,
        "Huffman and literal encoding should decode to identical headers"
    );
    assert_eq!(huffman_decoded.len(), 1, "Should decode exactly one header");
    assert_eq!(
        huffman_decoded[0], header,
        "Decoded header should match original"
    );
}

fn test_encoder_fragmentation(test_string: &str) {
    // Test both name and value encoding paths
    for as_name in [true, false] {
        let header = if as_name {
            Header::new(test_string, "val")
        } else {
            Header::new("name", test_string)
        };

        let mut encoder = HpackEncoder::new();
        encoder.set_use_huffman(true);
        let mut dst = BytesMut::new();
        encoder.encode(&[header], &mut dst);

        // The encoded block should be decodable
        let decoded = decode_headers(&dst);
        assert_eq!(decoded.len(), 1, "Should decode one header");

        // Encoded block should not be empty (huffman encoding should produce output)
        assert!(
            !dst.is_empty(),
            "Huffman encoding should produce non-empty output"
        );
    }
}

fn test_multi_fragment_encoding(pattern: &FragmentationPattern) {
    if pattern.fragments.is_empty() {
        return;
    }

    // Create multiple headers with different fragmentation patterns
    let mut headers = Vec::new();
    for (i, fragment) in pattern.fragments.iter().enumerate().take(4) {
        let fragment_string = build_single_fragment_string(fragment);
        let header_name = format!("x-frag-{}", i);
        headers.push(Header::new(header_name, fragment_string));
    }

    if headers.is_empty() {
        return;
    }

    // Encode all headers in one block
    let mut encoder = HpackEncoder::new();
    encoder.set_use_huffman(!pattern.use_literal_encoding);
    let mut dst = BytesMut::new();
    encoder.encode(&headers, &mut dst);

    // Decode and verify
    let decoded = decode_headers(&dst);
    assert_eq!(
        decoded.len(),
        headers.len(),
        "Should decode all {} headers",
        headers.len()
    );

    for (original, decoded_header) in headers.iter().zip(decoded.iter()) {
        assert_eq!(
            original, decoded_header,
            "Header should round-trip correctly"
        );
    }
}

fn build_single_fragment_string(fragment: &StringFragment) -> String {
    let mut result = String::new();

    // Add base character
    let base_byte = fragment.base_char.to_byte();
    let repeat_count = (fragment.repeat_count % 8) + 1; // 1-8 repetitions
    for _ in 0..repeat_count {
        if let Ok(ch) = std::str::from_utf8(&[base_byte]) {
            result.push_str(ch);
        }
    }

    // Add adjusters
    for adjuster in fragment.bit_adjusters.iter().take(4) {
        // Limit adjuster count
        let adj_byte = adjuster.to_byte();
        if let Ok(ch) = std::str::from_utf8(&[adj_byte]) {
            result.push_str(ch);
        }
    }

    if result.is_empty() {
        result = "default".to_string();
    }

    result
}

fn decode_headers(encoded: &BytesMut) -> Vec<Header> {
    let mut decoder = HpackDecoder::new();
    let mut data = Bytes::copy_from_slice(encoded);

    match decoder.decode(&mut data) {
        Ok(headers) => {
            // Successful decode should consume all data
            assert!(
                data.is_empty(),
                "Decoder should consume all input on success"
            );
            headers
        }
        Err(_) => {
            // If decode fails, return empty vec - this is acceptable for malformed input
            // The fuzzer should find cases where valid input fails to decode
            Vec::new()
        }
    }
}
