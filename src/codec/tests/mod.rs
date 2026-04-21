//! Regression tests for codec fuzzing findings
//!
//! This module contains regression tests generated from fuzz target discoveries.
//! Each test represents a previously-discovered crash or logic bug that has been
//! fixed and should never regress.

#[cfg(test)]
mod regression_tests {
    use super::super::*;
    use crate::bytes::{Bytes, BytesMut};

    /// Test basic round-trip property for BytesCodec
    /// Validates the core invariant: decode(encode(x)) == x
    #[test]
    fn bytes_codec_round_trip_identity() {
        let mut codec = BytesCodec::new();

        // Non-empty test cases. `BytesCodec::decode` deliberately returns
        // `Ok(None)` for an empty buffer to signal "no frame yet", so the
        // empty input is checked separately below.
        let test_cases = vec![
            b"hello".to_vec(),            // Simple text
            b"\x00\x01\x02\xff".to_vec(), // Binary data
            vec![0u8; 10000],             // Large data
        ];

        for original in test_cases {
            let bytes_input = Bytes::from(original.clone());
            let mut encode_buf = BytesMut::new();

            // Round-trip test
            codec
                .encode(bytes_input.clone(), &mut encode_buf)
                .expect("encode failed");
            let decoded = codec
                .decode(&mut encode_buf)
                .expect("decode failed")
                .expect("incomplete frame");

            assert_eq!(
                decoded.as_ref(),
                original.as_slice(),
                "Round-trip failed: original != decoded"
            );
        }

        // Empty-input edge case: encode produces an empty buffer and
        // decode reports `Ok(None)` (no frame yet), not an incomplete
        // frame error.
        let mut empty_buf = BytesMut::new();
        codec
            .encode(Bytes::new(), &mut empty_buf)
            .expect("encode empty failed");
        assert!(empty_buf.is_empty());
        assert!(
            codec.decode(&mut empty_buf).expect("decode empty").is_none(),
            "decoding an empty buffer must return None"
        );
    }

    /// Test LinesCodec with various newline patterns
    /// Validates UTF-8 handling and newline parsing robustness.
    /// LinesCodec delimits strictly on `\n`; CRLF has the trailing CR
    /// stripped. CR-only input has no `\n` terminator and decodes as an
    /// incomplete frame (returns `Ok(None)`).
    #[test]
    fn lines_codec_newline_variants() {
        let test_cases = vec![
            ("simple", "simple\n"),
            ("line", "line\r\n"),
            ("", "\n"),
            ("héllo wørld", "héllo wørld\n"),
        ];

        for (expected, input) in test_cases {
            let mut codec = LinesCodec::new();
            let mut src = BytesMut::from(input);
            let decoded = codec
                .decode(&mut src)
                .expect("decode failed")
                .expect("incomplete frame");

            assert_eq!(decoded, expected, "Line parsing failed for: {:?}", input);
        }

        // CR-only input is not terminated by a newline; decode must
        // return `Ok(None)` until more data (including `\n`) arrives.
        let mut cr_codec = LinesCodec::new();
        let mut cr_src = BytesMut::from("old_mac\r");
        assert!(
            cr_codec.decode(&mut cr_src).expect("cr-only decode").is_none(),
            "CR-only input has no frame terminator"
        );
    }

    /// Regression test: Capacity growth should be bounded
    /// Prevents excessive memory allocation in encoding operations
    #[test]
    fn capacity_growth_bounded() {
        let mut codec = BytesCodec::new();
        let mut buffer = BytesMut::with_capacity(64);

        // Encode progressively larger inputs
        for size in [100, 1000, 10000] {
            let large_input = Bytes::from(vec![0x42u8; size]);
            let cap_before = buffer.capacity();

            codec
                .encode(large_input, &mut buffer)
                .expect("encode failed");

            let cap_after = buffer.capacity();

            // Capacity invariants from fuzzing
            assert!(cap_after >= cap_before, "Capacity decreased!");
            assert!(
                cap_after <= buffer.len() * 4,
                "Excessive capacity growth: cap={}, len={}",
                cap_after,
                buffer.len()
            );
        }
    }

    /// Test error recovery after invalid UTF-8 in LinesCodec.
    /// LinesCodec only validates UTF-8 once a `\n` terminator is seen;
    /// invalid bytes with a trailing newline yield `InvalidUtf8`, and
    /// the codec must recover on subsequent valid lines.
    #[test]
    fn lines_codec_error_recovery() {
        let mut codec = LinesCodec::new();
        let mut src = BytesMut::new();

        // Add invalid UTF-8 followed by a newline so the codec emits a
        // frame and can validate it.
        src.extend_from_slice(b"\xff\xfe\xfd\n");

        // Should fail gracefully with InvalidUtf8.
        let result = codec.decode(&mut src);
        assert!(
            matches!(result, Err(LinesCodecError::InvalidUtf8)),
            "Should fail on invalid UTF-8, got {:?}",
            result
        );

        // Recovery: add valid UTF-8 line
        src.clear();
        src.extend_from_slice(b"recovery_line\n");

        // Should recover and work normally
        let decoded = codec
            .decode(&mut src)
            .expect("recovery failed")
            .expect("incomplete frame");

        assert_eq!(decoded, "recovery_line", "Failed to recover after error");
    }
}
