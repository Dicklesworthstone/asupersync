//! Fuzzing harness for BytesCodec.
//!
//! Tests the bytes codec with random inputs to find edge cases,
//! buffer handling bugs, and memory safety issues.

#![cfg(test)]

use super::bytes_codec::BytesCodec;
use crate::bytes::{Bytes, BytesMut};
use crate::codec::{Decoder, Encoder};
use proptest::prelude::*;
use proptest::strategy::Just;

/// Generate arbitrary byte buffers for fuzzing
fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        // Empty bytes
        Just(vec![]),
        // Small bytes (0-16 bytes) - common edge case
        prop::collection::vec(any::<u8>(), 0..=16),
        // Medium bytes (17-1024 bytes) - typical payload sizes
        prop::collection::vec(any::<u8>(), 17..=1024),
        // Large bytes (1025-65536 bytes) - stress test
        prop::collection::vec(any::<u8>(), 1025..=65536),
        // Pathological cases
        prop::collection::vec(any::<u8>(), 65537..=1048576), // Very large
        prop::collection::vec(Just(0u8), 0..=1024),               // All zeros
        prop::collection::vec(Just(255u8), 0..=1024),             // All 0xFF
    ]
}

/// Generate arbitrary BytesMut with potentially reserved capacity
fn arb_bytes_mut_with_capacity() -> impl Strategy<Value = BytesMut> {
    (arb_bytes(), 0..=2048usize).prop_map(|(data, extra_cap)| {
        let mut buf = BytesMut::with_capacity(data.len() + extra_cap);
        buf.extend_from_slice(&data);
        buf
    })
}

/// Fuzzing oracle: Decoder should never panic or return inconsistent results
mod decoder_fuzz {
    use super::*;

    proptest! {
        /// Property: decode should never panic and should consume all bytes
        #[test]
        fn decode_never_panics(data in arb_bytes()) {
            let mut codec = BytesCodec::new();
            let mut buf = BytesMut::from(&data[..]);
            let original_len = buf.len();

            // Decode should never panic
            let result = codec.decode(&mut buf);

            prop_assert!(result.is_ok(), "decode returned error: {:?}", result);

            match result.unwrap() {
                Some(decoded) => {
                    // If data was returned, buffer should be empty
                    prop_assert!(buf.is_empty(), "buffer not empty after decode: {} bytes remain", buf.len());
                    // Decoded data should match original
                    prop_assert_eq!(decoded.len(), original_len);
                    prop_assert_eq!(&decoded[..], &data[..]);
                },
                None => {
                    // None should only be returned for empty input
                    prop_assert!(original_len == 0, "decode returned None for non-empty input of {} bytes", original_len);
                    prop_assert!(buf.is_empty(), "buffer not empty after decode returning None");
                }
            }
        }

        /// Property: repeated decode calls on empty buffer should return None
        #[test]
        fn repeated_decode_empty_stable(iterations in 1..=100usize) {
            let mut codec = BytesCodec::new();
            let mut buf = BytesMut::new();

            for i in 0..iterations {
                let result = codec.decode(&mut buf);
                prop_assert!(result.is_ok(), "decode failed on iteration {}: {:?}", i, result);
                prop_assert!(result.unwrap().is_none(), "decode returned Some on empty buffer iteration {}", i);
                prop_assert!(buf.is_empty(), "buffer not empty after iteration {}", i);
            }
        }

        /// Property: decode should work correctly with pre-reserved capacity
        #[test]
        fn decode_with_reserved_capacity(buf in arb_bytes_mut_with_capacity()) {
            let _codec = BytesMut::new();
            let mut input = buf.clone();
            let original_data = input.to_vec();
            let original_capacity = input.capacity();

            let result = BytesCodec::new().decode(&mut input);

            prop_assert!(result.is_ok(), "decode failed: {:?}", result);

            if original_data.is_empty() {
                prop_assert!(result.unwrap().is_none(), "expected None for empty input");
            } else {
                let decoded = result.unwrap().unwrap();
                prop_assert_eq!(&decoded[..], &original_data[..]);
                prop_assert!(input.is_empty(), "input buffer should be empty after decode");
            }

            // Capacity handling should be reasonable (implementation detail, but worth checking)
            prop_assert!(input.capacity() <= original_capacity, "capacity should not increase during decode");
        }
    }
}

/// Fuzzing oracle: Encoder should never panic and should produce correct output
mod encoder_fuzz {
    use super::*;

    proptest! {
        /// Property: encode(Bytes) should never panic and should append correctly
        #[test]
        fn encode_bytes_never_panics(
            data in arb_bytes(),
            initial_dst in arb_bytes(),
            extra_capacity in 0..=1024usize
        ) {
            let mut codec = BytesCodec::new();
            let mut dst = BytesMut::with_capacity(initial_dst.len() + data.len() + extra_capacity);
            dst.extend_from_slice(&initial_dst);
            let initial_len = dst.len();

            let input = Bytes::from(data.clone());
            let result = codec.encode(input, &mut dst);

            prop_assert!(result.is_ok(), "encode failed: {:?}", result);
            prop_assert_eq!(dst.len(), initial_len + data.len());
            prop_assert_eq!(&dst[..initial_len], &initial_dst[..]);
            prop_assert_eq!(&dst[initial_len..], &data[..]);
        }

        /// Property: encode(BytesMut) should never panic and should append correctly
        #[test]
        fn encode_bytes_mut_never_panics(
            data in arb_bytes(),
            initial_dst in arb_bytes(),
            extra_capacity in 0..=1024usize
        ) {
            let mut codec = BytesCodec::new();
            let mut dst = BytesMut::with_capacity(initial_dst.len() + data.len() + extra_capacity);
            dst.extend_from_slice(&initial_dst);
            let initial_len = dst.len();

            let input = BytesMut::from(&data[..]);
            let result = codec.encode(input, &mut dst);

            prop_assert!(result.is_ok(), "encode failed: {:?}", result);
            prop_assert_eq!(dst.len(), initial_len + data.len());
            prop_assert_eq!(&dst[..initial_len], &initial_dst[..]);
            prop_assert_eq!(&dst[initial_len..], &data[..]);
        }

        /// Property: encode(Vec<u8>) should never panic and should append correctly
        #[test]
        fn encode_vec_never_panics(
            data in arb_bytes(),
            initial_dst in arb_bytes(),
            extra_capacity in 0..=1024usize
        ) {
            let mut codec = BytesCodec::new();
            let mut dst = BytesMut::with_capacity(initial_dst.len() + data.len() + extra_capacity);
            dst.extend_from_slice(&initial_dst);
            let initial_len = dst.len();

            let result = codec.encode(data.clone(), &mut dst);

            prop_assert!(result.is_ok(), "encode failed: {:?}", result);
            prop_assert_eq!(dst.len(), initial_len + data.len());
            prop_assert_eq!(&dst[..initial_len], &initial_dst[..]);
            prop_assert_eq!(&dst[initial_len..], &data[..]);
        }

        /// Property: encoding large data should work without overflow
        #[test]
        fn encode_large_data_safe(data in prop::collection::vec(any::<u8>(), 0..=1048576)) {
            let mut codec = BytesCodec::new();
            let mut dst = BytesMut::new();

            // This should not panic or overflow
            let result = codec.encode(Bytes::from(data.clone()), &mut dst);

            prop_assert!(result.is_ok(), "encode large data failed: {:?}", result);
            prop_assert_eq!(dst.len(), data.len());
            prop_assert_eq!(&dst[..], &data[..]);
        }
    }
}

/// Round-trip property testing: encode then decode should be identity
mod roundtrip_fuzz {
    use super::*;

    proptest! {
        /// Property: encode then decode should recover original data
        #[test]
        fn roundtrip_bytes_identity(data in arb_bytes()) {
            let mut encode_codec = BytesCodec::new();
            let mut decode_codec = BytesCodec::new();

            // Encode
            let mut encoded = BytesMut::new();
            let input = Bytes::from(data.clone());
            encode_codec.encode(input, &mut encoded).unwrap();

            // Decode
            let decoded = decode_codec.decode(&mut encoded).unwrap();

            if data.is_empty() {
                prop_assert!(decoded.is_none(), "expected None for empty roundtrip");
            } else {
                let decoded_data = decoded.unwrap();
                prop_assert_eq!(&decoded_data[..], &data[..]);
            }
        }

        /// Property: multiple encode then single decode should concatenate correctly
        #[test]
        fn multiple_encode_single_decode(chunks in prop::collection::vec(arb_bytes(), 0..=10)) {
            let mut encode_codec = BytesCodec::new();
            let mut decode_codec = BytesCodec::new();
            let mut buffer = BytesMut::new();

            // Encode all chunks
            let mut expected = Vec::new();
            for chunk in &chunks {
                expected.extend_from_slice(chunk);
                encode_codec.encode(Bytes::from(chunk.clone()), &mut buffer).unwrap();
            }

            // Decode everything at once
            let decoded = decode_codec.decode(&mut buffer).unwrap();

            if expected.is_empty() {
                prop_assert!(decoded.is_none(), "expected None for empty combined data");
            } else {
                let decoded_data = decoded.unwrap();
                prop_assert_eq!(&decoded_data[..], &expected[..]);
            }
        }

        /// Property: encode with different types should produce identical output
        #[test]
        fn encode_type_equivalence(data in arb_bytes()) {
            let mut codec_bytes = BytesCodec::new();
            let mut codec_bytes_mut = BytesCodec::new();
            let mut codec_vec = BytesCodec::new();

            let mut dst_bytes = BytesMut::new();
            let mut dst_bytes_mut = BytesMut::new();
            let mut dst_vec = BytesMut::new();

            // Encode with different input types
            codec_bytes.encode(Bytes::from(data.clone()), &mut dst_bytes).unwrap();
            codec_bytes_mut.encode(BytesMut::from(&data[..]), &mut dst_bytes_mut).unwrap();
            codec_vec.encode(data.clone(), &mut dst_vec).unwrap();

            // All outputs should be identical
            prop_assert_eq!(&dst_bytes[..], &dst_bytes_mut[..]);
            prop_assert_eq!(&dst_bytes[..], &dst_vec[..]);
            prop_assert_eq!(&dst_bytes[..], &data[..]);
        }
    }
}

/// Stress testing: exercise codec under extreme conditions
mod stress_fuzz {
    use super::*;

    proptest! {
        /// Property: codec should handle rapid encode/decode cycles
        #[test]
        fn rapid_cycles(
            operations in prop::collection::vec(
                prop_oneof![
                    arb_bytes().prop_map(Operation::Encode),
                    Just(Operation::Decode),
                    Just(Operation::Reset)
                ],
                0..=100
            )
        ) {
            let mut codec = BytesCodec::new();
            let mut buffer = BytesMut::new();
            let mut encoded_so_far = Vec::new();

            for op in operations {
                match op {
                    Operation::Encode(data) => {
                        let result = codec.encode(Bytes::from(data.clone()), &mut buffer);
                        prop_assert!(result.is_ok(), "encode failed during stress test");
                        encoded_so_far.extend_from_slice(&data);
                    },
                    Operation::Decode => {
                        let result = codec.decode(&mut buffer);
                        prop_assert!(result.is_ok(), "decode failed during stress test");
                        if let Some(decoded) = result.unwrap() {
                            prop_assert_eq!(&decoded[..], &encoded_so_far[..]);
                            encoded_so_far.clear();
                        } else {
                            prop_assert!(encoded_so_far.is_empty(), "decode returned None but data was encoded");
                        }
                    },
                    Operation::Reset => {
                        buffer.clear();
                        encoded_so_far.clear();
                    }
                }
            }
        }

        /// Property: codec should handle buffer reuse without contamination
        #[test]
        fn buffer_reuse_safe(
            test_cycles in prop::collection::vec(arb_bytes(), 1..=20)
        ) {
            let mut codec = BytesCodec::new();
            let mut reused_buffer = BytesMut::new();

            for (i, data) in test_cycles.iter().enumerate() {
                // Clear and encode fresh data
                reused_buffer.clear();
                let result = codec.encode(Bytes::from(data.clone()), &mut reused_buffer);
                prop_assert!(result.is_ok(), "encode failed in cycle {}", i);

                // Decode and verify
                let decoded = codec.decode(&mut reused_buffer).unwrap();
                if data.is_empty() {
                    prop_assert!(decoded.is_none(), "expected None for empty data in cycle {}", i);
                } else {
                    let decoded_data = decoded.unwrap();
                    prop_assert_eq!(&decoded_data[..], &data[..], "data mismatch in cycle {}", i);
                }
                prop_assert!(reused_buffer.is_empty(), "buffer not empty after cycle {}", i);
            }
        }
    }

    #[derive(Debug, Clone)]
    enum Operation {
        Encode(Vec<u8>),
        Decode,
        Reset,
    }
}

/// Edge case testing: pathological inputs that might break assumptions
mod edge_case_fuzz {
    use super::*;

    #[test]
    fn zero_capacity_buffer() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();

        // Should handle zero capacity gracefully
        let result = codec.decode(&mut buf);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn encode_to_zero_capacity_dst() {
        let mut codec = BytesCodec::new();
        let mut dst = BytesMut::new();
        dst.reserve(0); // Explicitly set to minimal capacity

        let data = vec![1, 2, 3, 4, 5];
        let result = codec.encode(Bytes::from(data.clone()), &mut dst);

        assert!(result.is_ok(), "Should handle low-capacity destination");
        assert_eq!(&dst[..], &data[..]);
    }

    proptest! {
        /// Property: fragmented buffer operations should work correctly
        #[test]
        fn fragmented_operations(
            chunk_sizes in prop::collection::vec(1..=100usize, 1..=10),
            data in arb_bytes()
        ) {
            let mut codec = BytesCodec::new();
            let mut buffer = BytesMut::new();

            // Encode data in chunks
            let mut offset = 0;
            for &chunk_size in &chunk_sizes {
                let end = std::cmp::min(offset + chunk_size, data.len());
                if offset >= data.len() { break; }

                let chunk = &data[offset..end];
                let result = codec.encode(Bytes::from(chunk.to_vec()), &mut buffer);
                prop_assert!(result.is_ok(), "fragmented encode failed at offset {}", offset);
                offset = end;
            }

            // Decode should get all data
            let decoded = codec.decode(&mut buffer).unwrap();

            if data.is_empty() {
                prop_assert!(decoded.is_none(), "expected None for empty fragmented data");
            } else {
                let decoded_data = decoded.unwrap();
                prop_assert_eq!(&decoded_data[..], &data[..]);
            }
        }

        /// Property: Unicode/UTF-8 data should pass through unchanged
        #[test]
        fn unicode_passthrough(text in ".*") {
            let mut codec = BytesCodec::new();
            let mut buffer = BytesMut::new();

            let utf8_bytes = text.as_bytes().to_vec();
            codec.encode(Bytes::from(utf8_bytes.clone()), &mut buffer).unwrap();

            let decoded = codec.decode(&mut buffer).unwrap();
            if utf8_bytes.is_empty() {
                prop_assert!(decoded.is_none());
            } else {
                let decoded_data = decoded.unwrap();
                prop_assert_eq!(&decoded_data[..], utf8_bytes);

                // Should be able to reconstruct the string
                let reconstructed = String::from_utf8(decoded_data.to_vec());
                prop_assert!(reconstructed.is_ok(), "failed to reconstruct UTF-8");
                prop_assert_eq!(reconstructed.unwrap(), text);
            }
        }
    }
}

#[cfg(test)]
mod comprehensive_fuzz_runner {
    use super::*;

    /// Run comprehensive fuzzing with higher iteration counts
    #[test]
    #[ignore = "Run with --ignored for extended fuzzing"]
    fn comprehensive_bytes_codec_fuzz() {
        // Configure for more aggressive testing
        let config = ProptestConfig {
            cases: 10000,
            max_shrink_iters: 10000,
            ..ProptestConfig::default()
        };

        // Run all fuzz tests with extended iteration counts
        proptest!(config, |(data in arb_bytes())| {
            let mut codec = BytesCodec::new();
            let mut buf = BytesMut::from(&data[..]);

            // Should never panic
            let _ = codec.decode(&mut buf);

            let mut encode_buf = BytesMut::new();
            let _ = codec.encode(Bytes::from(data), &mut encode_buf);
        });
    }
}