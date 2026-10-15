//! Structure-aware fuzz target for LinesCodec newline delimiter parsing.
//!
//! This target focuses on boundary conditions in line codec parsing:
//! 1. Newline delimiter variants (LF, CRLF, bare CR, mixed)
//! 2. Maximum line length enforcement and discard recovery
//! 3. UTF-8 validation across line boundaries
//! 4. Buffer state transitions and partial reads
//! 5. EOF handling without trailing newlines
//!
//! The fuzzer generates intelligent input patterns that exercise the
//! codec's state machine rather than just throwing random bytes.
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run lines_codec_boundaries
//! ```
//!
//! # Minimizing crashes
//! ```bash
//! cargo +nightly fuzz tmin lines_codec_boundaries <crash_file>
//! ```

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, Encoder, LinesCodec};
use libfuzzer_sys::fuzz_target;

const MAX_GENERATED_LINE_LEN: usize = 4096;

/// Structure-aware line codec input generator
#[derive(Debug, Clone, Arbitrary)]
struct LineCodecInput {
    operations: Vec<CodecOperation>,
    max_length_config: MaxLengthConfig,
    buffer_strategy: BufferStrategy,
}

#[derive(Debug, Clone, Arbitrary)]
enum CodecOperation {
    DecodeLine(LineData),
    DecodeEof,
    EncodeLine(String),
    ClearBuffer,
    PartialRead(usize), // Simulate partial buffer reads
}

#[derive(Debug, Clone, Arbitrary)]
struct LineData {
    content: LineContent,
    delimiter: LineDelimiter,
    position: LinePosition,
}

#[derive(Debug, Clone, Arbitrary)]
enum LineContent {
    Empty,
    Ascii(String),
    Utf8Valid(String),
    Utf8Invalid(Vec<u8>),
    AtMaxLength(usize),   // Exactly at length boundary
    OverMaxLength(usize), // Exceeds length by N bytes
    SpecialChars,         // CR/LF embedded in content
}

#[derive(Debug, Clone, Arbitrary)]
enum LineDelimiter {
    Lf,        // \n
    Crlf,      // \r\n
    BareCr,    // \r (should NOT be treated as delimiter)
    Mixed,     // Inconsistent across lines
    None,      // No delimiter (for EOF testing)
    Truncated, // Partial delimiter (\r without \n)
}

#[derive(Debug, Clone, Arbitrary)]
enum LinePosition {
    Complete, // Full line in buffer
    Split,    // Line spans multiple buffer fills
    Boundary, // Delimiter at exact buffer boundary
}

#[derive(Debug, Clone, Arbitrary)]
enum MaxLengthConfig {
    Default,    // Use DEFAULT_MAX_LINE_LENGTH
    Tiny(u8),   // 1-255 bytes
    Large(u16), // Up to 64K
    Unbounded,  // usize::MAX
}

#[derive(Debug, Clone, Arbitrary)]
enum BufferStrategy {
    SinglePass,  // All data at once
    Chunked(u8), // Split into N chunks
    ByteByByte,  // Extreme partial reads
    Random,      // Random chunk sizes
}

impl LineCodecInput {
    fn generate_test_data(&self, u: &mut Unstructured) -> Result<Vec<u8>, arbitrary::Error> {
        let mut data = Vec::new();

        for op in &self.operations {
            match op {
                CodecOperation::DecodeLine(line_data) => {
                    let line_bytes = self.generate_line_bytes(line_data, u)?;
                    data.extend_from_slice(&line_bytes);
                }
                CodecOperation::EncodeLine(s) => {
                    // Test round-trip: encode then decode
                    data.extend_from_slice(s.as_bytes());
                    data.push(b'\n');
                }
                CodecOperation::PartialRead(width) => {
                    let width = (*width).clamp(1, 32);
                    data.extend(std::iter::repeat_n(b'P', width));
                    data.push(b'\n');
                }
                CodecOperation::DecodeEof | CodecOperation::ClearBuffer => {}
            }
        }

        Ok(data)
    }

    fn generate_line_bytes(
        &self,
        line_data: &LineData,
        u: &mut Unstructured,
    ) -> Result<Vec<u8>, arbitrary::Error> {
        let mut line = Vec::new();

        // Generate content
        match &line_data.content {
            LineContent::Empty => {}
            LineContent::Ascii(s) => {
                line.extend_from_slice(s.as_bytes());
            }
            LineContent::Utf8Valid(s) => {
                line.extend_from_slice(s.as_bytes());
            }
            LineContent::Utf8Invalid(bytes) => {
                line.extend_from_slice(bytes);
            }
            LineContent::AtMaxLength(len) => {
                let len = (*len).min(MAX_GENERATED_LINE_LEN);
                line.extend(vec![b'X'; len]);
            }
            LineContent::OverMaxLength(extra) => {
                // Generate content that will trigger MaxLineLengthExceeded
                let base_len = match self.max_length_config {
                    MaxLengthConfig::Tiny(n) => n as usize,
                    MaxLengthConfig::Large(n) => n as usize,
                    _ => 1000,
                };
                let len = base_len
                    .saturating_add((*extra).min(256))
                    .min(MAX_GENERATED_LINE_LEN);
                line.extend(vec![b'Y'; len]);
            }
            LineContent::SpecialChars => {
                // Embed CR/LF that should NOT be treated as delimiters
                line.extend_from_slice(b"before\rmiddle\rafter");
            }
        }

        match line_data.position {
            LinePosition::Complete => {}
            LinePosition::Split => {
                if line.len() > 1 {
                    line.insert(line.len() / 2, b'\n');
                }
            }
            LinePosition::Boundary => {
                while line.len() % 16 != 15 && line.len() < MAX_GENERATED_LINE_LEN {
                    line.push(b'B');
                }
            }
        }

        // Add delimiter
        match line_data.delimiter {
            LineDelimiter::Lf => line.push(b'\n'),
            LineDelimiter::Crlf => line.extend_from_slice(b"\r\n"),
            LineDelimiter::BareCr => line.push(b'\r'),
            LineDelimiter::Mixed => {
                if u.arbitrary::<bool>()? {
                    line.push(b'\n');
                } else {
                    line.extend_from_slice(b"\r\n");
                }
            }
            LineDelimiter::None => {} // No delimiter
            LineDelimiter::Truncated => {
                line.push(b'\r');
                // No \n - tests partial CRLF
            }
        }

        Ok(line)
    }

    fn create_codec(&self) -> LinesCodec {
        match self.max_length_config {
            MaxLengthConfig::Default => LinesCodec::new(),
            MaxLengthConfig::Tiny(n) => LinesCodec::new_with_max_length(n as usize),
            MaxLengthConfig::Large(n) => LinesCodec::new_with_max_length(n as usize),
            MaxLengthConfig::Unbounded => LinesCodec::with_unbounded(),
        }
    }
}

/// Generate invalid UTF-8 sequences for boundary testing
fn generate_invalid_utf8(u: &mut Unstructured) -> Result<Vec<u8>, arbitrary::Error> {
    let pattern = u.int_in_range(0u8..=5)?;
    match pattern {
        0 => Ok(vec![0x80]),             // Lone continuation byte
        1 => Ok(vec![0xC3, 0x28]),       // Invalid 2-byte sequence
        2 => Ok(vec![0xF0, 0x9F]),       // Truncated 4-byte sequence
        3 => Ok(vec![0xFF, 0xFE]),       // Invalid bytes
        4 => Ok(b"valid\xFF".to_vec()),  // Valid UTF-8 + garbage
        _ => Ok(vec![0xED, 0xA0, 0x80]), // Surrogate (invalid in UTF-8)
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut u = Unstructured::new(data);

    // Test 1: Structure-aware fuzzing with generated line patterns
    if let Ok(input) = LineCodecInput::arbitrary(&mut u) {
        let mut codec = input.create_codec();

        if let Ok(test_data) = input.generate_test_data(&mut u) {
            match input.buffer_strategy {
                BufferStrategy::SinglePass => {
                    let mut buf = BytesMut::from(&test_data[..]);
                    test_decode_sequence(&mut codec, &mut buf);
                }
                BufferStrategy::Chunked(n) => {
                    let chunk_size = (test_data.len() / (n as usize + 1)).max(1);
                    let mut buf = BytesMut::new();

                    for chunk in test_data.chunks(chunk_size) {
                        buf.extend_from_slice(chunk);
                        test_decode_sequence(&mut codec, &mut buf);
                    }
                }
                BufferStrategy::ByteByByte => {
                    let mut buf = BytesMut::new();
                    for &byte in &test_data {
                        buf.put_u8(byte);
                        test_decode_sequence(&mut codec, &mut buf);
                    }
                }
                BufferStrategy::Random => {
                    let mut buf = BytesMut::new();
                    let mut pos = 0;
                    while pos < test_data.len() {
                        let chunk_size = u.arbitrary::<u8>().unwrap_or(1) as usize;
                        let end = (pos + chunk_size).min(test_data.len());
                        buf.extend_from_slice(&test_data[pos..end]);
                        test_decode_sequence(&mut codec, &mut buf);
                        pos = end;
                    }
                }
            }

            // Test EOF scenarios
            test_eof_boundary(&mut codec, &mut BytesMut::from(&test_data[..]));
        }
    }

    // Test 2: Invalid UTF-8 boundary fuzzing
    if let Ok(invalid_utf8) = generate_invalid_utf8(&mut u) {
        let mut codec = LinesCodec::new();
        let mut test_data = invalid_utf8;
        test_data.push(b'\n'); // Add delimiter

        let mut buf = BytesMut::from(&test_data[..]);
        let _result = codec.decode(&mut buf); // Should handle gracefully
    }

    // Test 3: Round-trip testing (encoding then decoding)
    if let Ok(text) = String::arbitrary(&mut u) {
        // Only test strings without embedded newlines for round-trip
        if !text.contains('\n') && !text.contains('\r') && text.len() <= 1000 {
            test_round_trip(&text);
        }
    }

    // Test 4: Raw byte fuzzing for edge cases
    let mut raw_codec = LinesCodec::new();
    let mut raw_buf = BytesMut::from(data);
    test_decode_sequence(&mut raw_codec, &mut raw_buf);

    // Test 5: Max length boundary stress testing
    if data.len() > 4 {
        let boundary_len = u.arbitrary::<u8>().unwrap_or(10) as usize;
        let mut boundary_codec = LinesCodec::new_with_max_length(boundary_len);

        // Test exactly at boundary
        let at_boundary = vec![b'X'; boundary_len];
        let mut at_buf = BytesMut::from(&at_boundary[..]);
        at_buf.put_u8(b'\n');
        let _at_result = boundary_codec.decode(&mut at_buf);

        // Test exceeding boundary
        let over_boundary = vec![b'Y'; boundary_len + 1];
        let mut over_buf = BytesMut::from(&over_boundary[..]);
        over_buf.put_u8(b'\n');
        let _over_result = boundary_codec.decode(&mut over_buf);

        // Test recovery after oversized line
        over_buf.put_slice(b"ok\n");
        let _recovery_result = boundary_codec.decode(&mut over_buf);
    }
});

fn test_decode_sequence(codec: &mut LinesCodec, buf: &mut BytesMut) {
    // Drain all available lines without panicking
    let mut iterations = 0;
    let max_iterations = 100; // Prevent infinite loops

    while iterations < max_iterations {
        match codec.decode(buf) {
            Ok(Some(_line)) => {
                // Successfully decoded a line - continue
                iterations += 1;
            }
            Ok(None) => {
                // No complete line available - normal
                break;
            }
            Err(_) => {
                // Error occurred - should be handled gracefully
                // Codec might be in recovery state, try to continue
                if buf.is_empty() {
                    break;
                }
                iterations += 1;
            }
        }
    }
}

fn test_eof_boundary(codec: &mut LinesCodec, buf: &mut BytesMut) {
    // Test decode_eof behavior
    let _eof_result = codec.decode_eof(buf);

    // Test idempotency - second decode_eof should return None
    let _eof_again = codec.decode_eof(buf);
}

fn test_round_trip(text: &str) {
    let mut encoder = LinesCodec::new();
    let mut decoder = LinesCodec::new();

    // Encode
    let mut encoded = BytesMut::new();
    if encoder.encode(text.to_string(), &mut encoded).is_ok() {
        // Decode
        if let Ok(Some(decoded)) = decoder.decode(&mut encoded) {
            // Round-trip should preserve the original text
            assert_eq!(decoded, text, "Round-trip failed: encode(decode(x)) != x");
        }
    }
}
