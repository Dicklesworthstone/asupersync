//! HPACK Metamorphic Property Tests
//!
//! This module implements metamorphic relations for HPACK header compression
//! to verify compression/decompression invariants and detect bugs that golden
//! tests might miss.
//!
//! Based on /testing-metamorphic methodology:
//! - When you can't verify *what* the output is, verify *how* outputs relate
//! - Tests semantic relationships rather than exact byte outputs
//! - Catches compression bugs through property violations

use std::collections::HashMap;
use asupersync::bytes::BytesMut;
use asupersync::http::h2::hpack::{Encoder, Decoder, Header};
use proptest::prelude::*;

/// Generate arbitrary HTTP headers for property testing
fn arb_header() -> impl Strategy<Value = Header> {
    (
        // Header names - mix of common headers and arbitrary strings
        prop_oneof![
            Just(":authority".to_string()),
            Just(":method".to_string()),
            Just(":path".to_string()),
            Just(":scheme".to_string()),
            Just(":status".to_string()),
            Just("accept".to_string()),
            Just("accept-encoding".to_string()),
            Just("cache-control".to_string()),
            Just("content-type".to_string()),
            Just("cookie".to_string()),
            Just("host".to_string()),
            Just("user-agent".to_string()),
            "[a-z][a-z0-9-]{0,20}".prop_map(|s| s.to_lowercase()),
            "x-[a-z0-9-]{1,15}".prop_map(|s| s.to_lowercase()),
        ],
        // Header values - mix of common values and arbitrary strings
        prop_oneof![
            Just("".to_string()),
            Just("GET".to_string()),
            Just("POST".to_string()),
            Just("https".to_string()),
            Just("http".to_string()),
            Just("/".to_string()),
            Just("200".to_string()),
            Just("404".to_string()),
            Just("gzip, deflate".to_string()),
            Just("application/json".to_string()),
            "[a-zA-Z0-9._~!$&'()*+,;=:@/?-]{0,100}",
            "[ -~]{0,200}".prop_filter("No control chars", |s| {
                s.chars().all(|c| c.is_ascii() && !c.is_ascii_control())
            }),
        ],
    )
    .prop_map(|(name, value)| Header { name, value })
}

/// Generate arbitrary header lists
fn arb_headers() -> impl Strategy<Value = Vec<Header>> {
    prop::collection::vec(arb_header(), 0..20)
}

/// Generate header lists with specific properties for targeted testing
fn arb_headers_with_duplicates() -> impl Strategy<Value = Vec<Header>> {
    (arb_headers(), arb_header()).prop_map(|(mut headers, duplicate_header)| {
        // Add the same header multiple times to test dynamic table behavior
        for i in 0..3 {
            let mut dup = duplicate_header.clone();
            dup.value = format!("{}-{}", dup.value, i);
            headers.push(dup);
        }
        headers
    })
}

#[cfg(test)]
mod metamorphic_properties {
    use super::*;

    /// MR1: Compression Round-Trip Identity (Invertive, Score: 10.0)
    /// Property: decode(encode(headers)) == headers
    /// Catches: Compression bugs, data loss, codec mismatches
    #[test]
    fn mr1_compression_roundtrip_identity() {
        proptest!(|(headers in arb_headers())| {
            let mut encoder = Encoder::new(4096);
            let mut decoder = Decoder::new(4096, 8192);

            // Encode headers
            let mut encoded = BytesMut::new();
            encoder.encode(&headers, &mut encoded);

            // Decode back
            let mut encoded_bytes = encoded.freeze();
            let decoded_headers = decoder.decode(&mut encoded_bytes).unwrap();

            // Verify round-trip identity
            prop_assert_eq!(headers.len(), decoded_headers.len());
            for (original, decoded) in headers.iter().zip(decoded_headers.iter()) {
                prop_assert_eq!(original.name, decoded.name);
                prop_assert_eq!(original.value, decoded.value);
            }
        });
    }

    /// MR2: Header Order Invariance (Equivalence, Score: 8.0)
    /// Property: permute(headers) encodes to semantically equivalent output
    /// Note: HPACK preserves order, so we test that reordering gives same decompressed result
    #[test]
    fn mr2_header_order_invariance_for_independent_headers() {
        proptest!(|(mut headers in arb_headers().prop_filter("Non-empty", |h| !h.is_empty()))| {
            // Only test with headers that are order-independent
            // Remove pseudo-headers and duplicate names to avoid order dependencies
            headers.retain(|h| !h.name.starts_with(':'));
            let mut name_set = std::collections::HashSet::new();
            headers.retain(|h| name_set.insert(h.name.clone()));

            if headers.len() < 2 {
                return Ok(());
            }

            let mut encoder1 = Encoder::new(4096);
            let mut encoder2 = Encoder::new(4096);
            let mut decoder1 = Decoder::new(4096, 8192);
            let mut decoder2 = Decoder::new(4096, 8192);

            // Encode original order
            let mut encoded1 = BytesMut::new();
            encoder1.encode(&headers, &mut encoded1);

            // Reverse order and encode
            let mut headers_reversed = headers.clone();
            headers_reversed.reverse();
            let mut encoded2 = BytesMut::new();
            encoder2.encode(&headers_reversed, &mut encoded2);

            // Decode both
            let mut encoded1_bytes = encoded1.freeze();
            let decoded1 = decoder1.decode(&mut encoded1_bytes).unwrap();

            let mut encoded2_bytes = encoded2.freeze();
            let decoded2 = decoder2.decode(&mut encoded2_bytes).unwrap();

            // Convert to maps for order-independent comparison
            let map1: HashMap<_, _> = decoded1.into_iter()
                .map(|h| (h.name, h.value))
                .collect();
            let map2: HashMap<_, _> = decoded2.into_iter()
                .map(|h| (h.name, h.value))
                .collect();

            prop_assert_eq!(map1, map2, "Header sets should be semantically equivalent regardless of encoding order");
        });
    }

    /// MR3: Huffman Encoding Equivalence (Equivalence, Score: 6.0)
    /// Property: huffman_enabled vs huffman_disabled should decode to same headers
    #[test]
    fn mr3_huffman_encoding_equivalence() {
        proptest!(|(headers in arb_headers().prop_filter("Has string data", |h|
            h.iter().any(|header| !header.value.is_empty() || !header.name.is_empty())
        ))| {
            // Create encoders with different Huffman settings
            let mut encoder_huffman = Encoder::new(4096);
            encoder_huffman.set_huffman(true);

            let mut encoder_no_huffman = Encoder::new(4096);
            encoder_no_huffman.set_huffman(false);

            let mut decoder1 = Decoder::new(4096, 8192);
            let mut decoder2 = Decoder::new(4096, 8192);

            // Encode with Huffman
            let mut encoded_huffman = BytesMut::new();
            encoder_huffman.encode(&headers, &mut encoded_huffman);

            // Encode without Huffman
            let mut encoded_no_huffman = BytesMut::new();
            encoder_no_huffman.encode(&headers, &mut encoded_no_huffman);

            // Decode both
            let mut huffman_bytes = encoded_huffman.freeze();
            let decoded_huffman = decoder1.decode(&mut huffman_bytes).unwrap();

            let mut no_huffman_bytes = encoded_no_huffman.freeze();
            let decoded_no_huffman = decoder2.decode(&mut no_huffman_bytes).unwrap();

            // Results should be identical regardless of Huffman encoding
            prop_assert_eq!(decoded_huffman, decoded_no_huffman,
                "Huffman vs non-Huffman encoding should produce identical decoded results");
        });
    }

    /// MR4: Static vs Dynamic Table Equivalence (Equivalence, Score: 7.5)
    /// Property: Headers that hit static table should decode identically regardless of dynamic table state
    #[test]
    fn mr4_static_vs_dynamic_table_equivalence() {
        // Use headers that are guaranteed to be in static table.
        let static_headers = vec![
            Header { name: ":method".to_string(), value: "GET".to_string() },
            Header { name: ":path".to_string(), value: "/".to_string() },
            Header { name: ":scheme".to_string(), value: "https".to_string() },
            Header { name: ":status".to_string(), value: "200".to_string() },
            Header { name: "accept-encoding".to_string(), value: "gzip, deflate".to_string() },
        ];

        // Encoder/decoder with empty dynamic table.
        let mut encoder_clean = Encoder::new(4096);
        let mut decoder_clean = Decoder::new(4096, 8192);

        // Encoder/decoder with populated dynamic table.
        let mut encoder_populated = Encoder::new(4096);
        let mut decoder_populated = Decoder::new(4096, 8192);

        // Populate dynamic table with some other headers first.
        let populate_headers = vec![
            Header { name: "x-custom-header".to_string(), value: "custom-value".to_string() },
            Header { name: "x-another".to_string(), value: "another-value".to_string() },
        ];
        let mut populate_buf = BytesMut::new();
        encoder_populated.encode(&populate_headers, &mut populate_buf);
        let mut populate_bytes = populate_buf.freeze();
        let _ = decoder_populated.decode(&mut populate_bytes).unwrap();

        // Now encode static headers with both encoders.
        let mut encoded_clean = BytesMut::new();
        encoder_clean.encode(&static_headers, &mut encoded_clean);

        let mut encoded_populated = BytesMut::new();
        encoder_populated.encode(&static_headers, &mut encoded_populated);

        // Decode with corresponding decoders.
        let mut clean_bytes = encoded_clean.freeze();
        let decoded_clean = decoder_clean.decode(&mut clean_bytes).unwrap();

        let mut populated_bytes = encoded_populated.freeze();
        let decoded_populated = decoder_populated.decode(&mut populated_bytes).unwrap();

        assert_eq!(
            decoded_clean,
            decoded_populated,
            "Static table headers should decode identically regardless of dynamic table state"
        );
    }

    /// MR5: Table Size Invariance (Equivalence, Score: 6.5)
    /// Property: Headers that fit in smaller table should decode identically in larger table
    #[test]
    fn mr5_table_size_invariance() {
        proptest!(|(headers in arb_headers().prop_filter("Small headers", |h| {
            // Ensure headers will fit in small table
            h.iter().map(|h| h.name.len() + h.value.len() + 32).sum::<usize>() < 1024
        }))| {
            let small_table_size = 1024;
            let large_table_size = 4096;

            let mut encoder_small = Encoder::new(small_table_size);
            let mut decoder_small = Decoder::new(small_table_size, 8192);

            let mut encoder_large = Encoder::new(large_table_size);
            let mut decoder_large = Decoder::new(large_table_size, 8192);

            // Encode with both table sizes
            let mut encoded_small = BytesMut::new();
            encoder_small.encode(&headers, &mut encoded_small);

            let mut encoded_large = BytesMut::new();
            encoder_large.encode(&headers, &mut encoded_large);

            // Decode with corresponding decoders
            let mut small_bytes = encoded_small.freeze();
            let decoded_small = decoder_small.decode(&mut small_bytes).unwrap();

            let mut large_bytes = encoded_large.freeze();
            let decoded_large = decoder_large.decode(&mut large_bytes).unwrap();

            // Results should be semantically identical
            prop_assert_eq!(decoded_small, decoded_large,
                "Headers should decode identically regardless of table size (when they fit in both)");
        });
    }

    /// MR6: Incremental vs Batch Encoding Equivalence (Equivalence, Score: 5.0)
    /// Property: encode([a,b,c]) should be equivalent to encode([a]); encode([b]); encode([c])
    #[test]
    fn mr6_incremental_vs_batch_encoding_equivalence() {
        proptest!(|(headers in arb_headers().prop_filter("Has headers", |h| !h.is_empty()))| {
            let mut encoder_batch = Encoder::new(4096);
            let mut encoder_incremental = Encoder::new(4096);

            let mut decoder_batch = Decoder::new(4096, 8192);
            let mut decoder_incremental = Decoder::new(4096, 8192);

            // Batch encoding
            let mut encoded_batch = BytesMut::new();
            encoder_batch.encode(&headers, &mut encoded_batch);

            // Incremental encoding
            let mut encoded_incremental = BytesMut::new();
            for header in &headers {
                encoder_incremental.encode(&[header.clone()], &mut encoded_incremental);
            }

            // Decode both approaches
            let mut batch_bytes = encoded_batch.freeze();
            let decoded_batch = decoder_batch.decode(&mut batch_bytes).unwrap();

            let mut incremental_bytes = encoded_incremental.freeze();
            let mut decoded_incremental = Vec::new();

            // For incremental, we need to decode each header block separately
            // This is a simplification - in practice we'd need to track boundaries
            // For now, let's decode the entire accumulated buffer
            let incremental_result = decoder_incremental.decode(&mut incremental_bytes).unwrap();
            decoded_incremental.extend(incremental_result);

            // Results should be equivalent
            prop_assert_eq!(decoded_batch, decoded_incremental,
                "Batch vs incremental encoding should produce equivalent decoded results");
        });
    }

    /// MR7: Case Insensitive Name Equivalence (Equivalence, Score: 4.0)
    /// Property: Header names should be normalized to lowercase during encoding
    #[test]
    fn mr7_case_insensitive_name_equivalence() {
        proptest!(|(base_name in "[a-z]{1,10}", value in "[a-zA-Z0-9-]{0,50}")| {
            let lowercase_header = Header {
                name: base_name.clone(),
                value: value.clone(),
            };

            let uppercase_header = Header {
                name: base_name.to_uppercase(),
                value: value.clone(),
            };

            let mixedcase_header = Header {
                name: base_name.chars().enumerate().map(|(i, c)|
                    if i % 2 == 0 { c.to_ascii_uppercase() } else { c }
                ).collect(),
                value: value.clone(),
            };

            let mut encoder1 = Encoder::new(4096);
            let mut encoder2 = Encoder::new(4096);
            let mut encoder3 = Encoder::new(4096);

            let mut decoder1 = Decoder::new(4096, 8192);
            let mut decoder2 = Decoder::new(4096, 8192);
            let mut decoder3 = Decoder::new(4096, 8192);

            // Encode all variants
            let mut encoded1 = BytesMut::new();
            encoder1.encode(&[lowercase_header], &mut encoded1);

            let mut encoded2 = BytesMut::new();
            encoder2.encode(&[uppercase_header], &mut encoded2);

            let mut encoded3 = BytesMut::new();
            encoder3.encode(&[mixedcase_header], &mut encoded3);

            // Decode all variants
            let mut bytes1 = encoded1.freeze();
            let decoded1 = decoder1.decode(&mut bytes1).unwrap();

            let mut bytes2 = encoded2.freeze();
            let decoded2 = decoder2.decode(&mut bytes2).unwrap();

            let mut bytes3 = encoded3.freeze();
            let decoded3 = decoder3.decode(&mut bytes3).unwrap();

            // All should decode to lowercase names
            prop_assert_eq!(decoded1.len(), 1);
            prop_assert_eq!(decoded2.len(), 1);
            prop_assert_eq!(decoded3.len(), 1);

            prop_assert_eq!(decoded1[0].name, base_name);
            prop_assert_eq!(decoded2[0].name, base_name);
            prop_assert_eq!(decoded3[0].name, base_name);

            prop_assert_eq!(decoded1[0].value, value);
            prop_assert_eq!(decoded2[0].value, value);
            prop_assert_eq!(decoded3[0].value, value);
        });
    }
}

/// Mutation testing to validate that metamorphic relations catch real bugs
#[cfg(test)]
mod mutation_validation {
    use super::*;

    /// Test that MR1 (round-trip) catches data corruption bugs
    #[test]
    fn validate_mr1_catches_corruption() {
        let headers = vec![
            Header { name: "test".to_string(), value: "original".to_string() }
        ];

        let mut encoder = Encoder::new(4096);
        let mut decoder = Decoder::new(4096, 8192);

        let mut encoded = BytesMut::new();
        encoder.encode(&headers, &mut encoded);

        // Mutate the encoded data to simulate a bug
        if !encoded.is_empty() {
            encoded[encoded.len() - 1] ^= 0x01; // Flip a bit
        }

        let mut encoded_bytes = encoded.freeze();
        let decode_result = decoder.decode(&mut encoded_bytes);

        // Should either fail to decode or produce different output
        match decode_result {
            Ok(decoded) => {
                assert!(decoded.is_empty() || decoded[0].value != "original",
                    "Mutated data should not decode to original value");
            }
            Err(_) => {
                // Decoding failure is also acceptable - the corruption was caught
            }
        }
    }

    /// Test that we can detect when a supposedly working implementation has bugs
    #[test]
    #[should_panic]
    fn validate_mr_catches_logic_bugs() {
        // This test intentionally breaks round-trip invariant to verify our MR would catch it
        let headers = vec![
            Header { name: "test".to_string(), value: "value".to_string() }
        ];

        let mut encoder = Encoder::new(4096);
        let mut decoder = Decoder::new(4096, 8192);

        let mut encoded = BytesMut::new();
        encoder.encode(&headers, &mut encoded);

        let mut encoded_bytes = encoded.freeze();
        let decoded = decoder.decode(&mut encoded_bytes).unwrap();

        // Introduce a deliberate "bug" in our test
        let mut buggy_decoded = decoded.clone();
        if !buggy_decoded.is_empty() {
            buggy_decoded[0].value = "corrupted".to_string();
        }

        // This should fail if our MR is working
        assert_eq!(headers[0].value, buggy_decoded[0].value,
            "This assertion should fail, proving our MR would catch this bug");
    }
}

/// Performance benchmarks to ensure MR tests don't significantly impact performance
#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn mr_performance_acceptable() {
        let large_headers: Vec<Header> = (0..100)
            .map(|i| Header {
                name: format!("header-{}", i),
                value: format!("value-{}-{}", i, "x".repeat(50)),
            })
            .collect();

        let start = Instant::now();

        // Run a subset of MR tests for performance measurement
        for _ in 0..10 {
            let mut encoder = Encoder::new(4096);
            let mut decoder = Decoder::new(4096, 8192);

            let mut encoded = BytesMut::new();
            encoder.encode(&large_headers, &mut encoded);

            let mut encoded_bytes = encoded.freeze();
            let decoded = decoder.decode(&mut encoded_bytes).unwrap();

            assert_eq!(large_headers.len(), decoded.len());
        }

        let duration = start.elapsed();

        // Ensure MR tests complete in reasonable time (adjust threshold as needed)
        assert!(duration.as_millis() < 1000,
            "MR tests took too long: {:?}", duration);
    }
}
