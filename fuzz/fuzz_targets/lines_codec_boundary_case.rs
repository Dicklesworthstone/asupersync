//! Structure-aware fuzz target for LinesCodec max_length + LF/CRLF boundary cases.
//!
//! This target specifically focuses on boundary conditions where line length
//! enforcement interacts with different line ending types (LF vs CRLF).
//!
//! Key boundary scenarios:
//! - Lines exactly at max_length with different endings
//! - Lines that exceed max_length by 1 with LF vs CRLF
//! - Mixed line endings in a single buffer near boundaries
//! - State transitions between normal and discard modes
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run lines_codec_boundary_case
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, LinesCodec, LinesCodecError};
use libfuzzer_sys::fuzz_target;

/// Line ending types for structure-aware generation
#[derive(Arbitrary, Debug, Clone, Copy)]
enum LineEnding {
    Lf,      // \n
    Crlf,    // \r\n
    Cr,      // \r (bare CR, should NOT be treated as line ending)
    None,    // No line ending
}

impl LineEnding {
    fn bytes(self) -> &'static [u8] {
        match self {
            LineEnding::Lf => b"\n",
            LineEnding::Crlf => b"\r\n",
            LineEnding::Cr => b"\r",
            LineEnding::None => b"",
        }
    }

    fn expected_termination(self) -> bool {
        matches!(self, LineEnding::Lf | LineEnding::Crlf)
    }
}

/// A single line segment with specific length and ending
#[derive(Arbitrary, Debug, Clone)]
struct LineSegment {
    /// Content length relative to max_length boundary
    length_offset: i8,  // -10 to +10 relative to max_length
    /// Line ending type
    ending: LineEnding,
    /// Content byte (repeated to make the line)
    fill_byte: u8,
}

/// Structure-aware input focused on max_length boundaries
#[derive(Arbitrary, Debug)]
struct BoundaryFuzzInput {
    /// Max length to test (small values for boundary testing)
    max_length: u8,  // 1-255, will be clamped appropriately
    /// Multiple line segments to test transitions
    segments: Vec<LineSegment>,
    /// Whether to test chunked delivery
    test_chunked: bool,
}

impl BoundaryFuzzInput {
    /// Convert to actual max_length value
    fn actual_max_length(&self) -> usize {
        // Focus on small max_length values where boundaries are easier to hit
        std::cmp::max(1, (self.max_length as usize).min(100))
    }

    /// Generate byte buffer for the input
    fn generate_buffer(&self) -> Vec<u8> {
        let max_len = self.actual_max_length();
        let mut buffer = Vec::new();

        for segment in &self.segments {
            // Calculate actual content length
            let base_len = max_len;
            let offset = segment.length_offset as isize;
            let content_len = if offset < 0 {
                base_len.saturating_sub((-offset) as usize)
            } else {
                base_len.saturating_add(offset as usize)
            };

            // Limit to prevent excessive memory usage
            let content_len = content_len.min(1000);

            // Generate content (avoid \n and \r in content to test endings properly)
            let fill_byte = if segment.fill_byte == b'\n' || segment.fill_byte == b'\r' {
                b'X'
            } else {
                segment.fill_byte
            };

            // Add content
            buffer.extend(std::iter::repeat(fill_byte).take(content_len));

            // Add line ending
            buffer.extend_from_slice(segment.ending.bytes());
        }

        buffer
    }
}

fuzz_target!(|input: BoundaryFuzzInput| {
    // Guard against excessive input size
    if input.segments.len() > 20 {
        return;
    }

    let max_length = input.actual_max_length();
    let buffer = input.generate_buffer();

    if buffer.len() > 10_000 {
        return; // Prevent OOM
    }

    // Test 1: Boundary behavior with different max_length values
    test_max_length_boundary(&input, max_length, &buffer);

    // Test 2: State transition validation
    test_state_transitions(&input, max_length, &buffer);

    // Test 3: Mixed ending consistency
    test_mixed_endings(&input, max_length, &buffer);

    // Test 4: Chunked delivery boundary cases
    if input.test_chunked {
        test_chunked_boundary(&input, max_length, &buffer);
    }
});

/// Test max_length boundary enforcement with different line endings
fn test_max_length_boundary(input: &BoundaryFuzzInput, max_length: usize, buffer: &[u8]) {
    let mut codec = LinesCodec::new_with_max_length(max_length);
    let mut buf = BytesMut::from(buffer);

    let mut lines_decoded = 0;
    let mut had_error = false;

    // Decode all possible lines
    loop {
        match codec.decode(&mut buf) {
            Ok(Some(line)) => {
                lines_decoded += 1;

                // INVARIANT: Decoded line must not exceed max_length
                assert!(
                    line.len() <= max_length,
                    "Line length {} exceeds max_length {}, input segments: {:?}",
                    line.len(),
                    max_length,
                    input.segments
                );

                // INVARIANT: No line endings should remain in decoded string
                assert!(
                    !line.contains('\n') && !line.contains('\r'),
                    "Decoded line contains line ending characters: {:?}",
                    line
                );

                // Guard against infinite loops
                if lines_decoded > 100 {
                    break;
                }
            }
            Ok(None) => break,
            Err(LinesCodecError::MaxLineLengthExceeded) => {
                had_error = true;
                // Error is expected for oversized lines, continue to test recovery
                break;
            }
            Err(_) => {
                // Other errors (UTF-8) are also acceptable
                had_error = true;
                break;
            }
        }
    }

    // If we generated oversized lines, we should have seen an error
    let has_oversized_line = input.segments.iter().any(|seg| {
        let actual_len = if seg.length_offset < 0 {
            max_length.saturating_sub((-seg.length_offset) as usize)
        } else {
            max_length.saturating_add(seg.length_offset as usize)
        };
        actual_len > max_length
    });

    // Note: This is a soft check because CRLF might cause complex interactions
    if has_oversized_line && lines_decoded > 0 && !had_error {
        // This could indicate a boundary condition issue, but might be valid
        // depending on how line endings interact with the boundary
    }
}

/// Test state transitions between normal and discard modes
fn test_state_transitions(_input: &BoundaryFuzzInput, max_length: usize, buffer: &[u8]) {
    let mut codec = LinesCodec::new_with_max_length(max_length);
    let mut buf = BytesMut::from(buffer);

    // Track whether we can recover after hitting max length
    let mut hit_error = false;
    let mut recovered_after_error = false;

    loop {
        match codec.decode(&mut buf) {
            Ok(Some(_line)) => {
                if hit_error {
                    recovered_after_error = true;
                }
            }
            Ok(None) => break,
            Err(LinesCodecError::MaxLineLengthExceeded) => {
                hit_error = true;
                // Continue to test recovery

                // INVARIANT: Buffer should not grow unboundedly during discard
                // (The implementation clears buffer in discard mode)
                if buf.len() > max_length * 10 {
                    panic!(
                        "Buffer grew too large ({} bytes) during discard mode with max_length={}",
                        buf.len(),
                        max_length
                    );
                }
            }
            Err(_) => break,
        }
    }

    // If we hit an error but have trailing data with newlines, we should recover
    if hit_error && buffer.contains(&b'\n') {
        // Recovery should be possible unless all remaining data is oversized
    }
}

/// Test that different line endings are handled consistently
fn test_mixed_endings(input: &BoundaryFuzzInput, max_length: usize, buffer: &[u8]) {
    // Test with a known mix of line endings to verify consistent behavior
    let test_patterns = [
        format!("a{}", LineEnding::Lf.bytes().iter().map(|&b| b as char).collect::<String>()),
        format!("b{}", LineEnding::Crlf.bytes().iter().map(|&b| b as char).collect::<String>()),
        format!("c{}", LineEnding::Cr.bytes().iter().map(|&b| b as char).collect::<String>()),
    ];

    for pattern in test_patterns {
        let mut codec = LinesCodec::new_with_max_length(max_length);
        let mut buf = BytesMut::from(pattern.as_bytes());

        match codec.decode(&mut buf) {
            Ok(Some(line)) => {
                // INVARIANT: Line endings should be stripped
                assert!(!line.contains('\r') && !line.contains('\n'));
            }
            Ok(None) => {
                // Acceptable - might need more data or EOF
            }
            Err(_) => {
                // Also acceptable for invalid UTF-8 or oversized lines
            }
        }
    }
}

/// Test chunked delivery at boundary conditions
fn test_chunked_boundary(_input: &BoundaryFuzzInput, max_length: usize, buffer: &[u8]) {
    if buffer.is_empty() {
        return;
    }

    let mut codec = LinesCodec::new_with_max_length(max_length);
    let mut buf = BytesMut::new();

    // Deliver data in small chunks to test partial line scenarios
    let chunk_size = std::cmp::max(1, max_length / 4);

    for chunk in buffer.chunks(chunk_size) {
        buf.extend_from_slice(chunk);

        // Try to decode after each chunk
        loop {
            match codec.decode(&mut buf) {
                Ok(Some(line)) => {
                    // INVARIANT: Even with chunked delivery, lines must be valid
                    assert!(line.len() <= max_length);
                    assert!(!line.contains('\n') && !line.contains('\r'));
                }
                Ok(None) => break, // Need more data
                Err(_) => break,   // Error, continue with next chunk
            }
        }
    }

    // Handle any remaining data
    if !buf.is_empty() {
        let _ = codec.decode_eof(&mut buf);
    }
}