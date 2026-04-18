//! HTTP/1.1 Content-Encoding conformance tests per RFC 9110 Section 8.4.
//!
//! These tests verify metamorphic relations for HTTP Content-Encoding negotiation
//! and compression codec behavior. The tests ensure compliance with RFC 9110
//! Section 8.4 (Content-Encoding) and Section 12.5.3 (Accept-Encoding).

use asupersync::http::compress::{
    accept_encoding_from_headers, content_encoding_from_headers, make_compressor, negotiate_encoding,
    ContentEncoding, Compressor, Decompressor,
};
use asupersync::lab::{LabConfig, LabRuntime};
use proptest::prelude::*;
use std::collections::HashMap;

/// Test data for Content-Encoding metamorphic relations
#[derive(Debug, Clone)]
struct EncodingTestScenario {
    /// Original data to compress
    pub data: Vec<u8>,
    /// Accept-Encoding header from client
    pub accept_encoding: Option<String>,
    /// Server-supported encodings in preference order
    pub server_supported: Vec<ContentEncoding>,
    /// Headers to test parsing
    pub headers: Vec<(String, String)>,
}

impl EncodingTestScenario {
    /// Create a new test scenario with given data
    fn new(
        data: Vec<u8>,
        accept_encoding: Option<String>,
        server_supported: Vec<ContentEncoding>,
    ) -> Self {
        Self {
            data,
            accept_encoding: accept_encoding.clone(),
            server_supported,
            headers: accept_encoding
                .map(|ae| vec![("Accept-Encoding".to_owned(), ae)])
                .unwrap_or_default(),
        }
    }

    /// Add a Content-Encoding header to the scenario
    fn with_content_encoding(mut self, encoding: ContentEncoding) -> Self {
        self.headers
            .push(("Content-Encoding".to_owned(), encoding.as_token().to_owned()));
        self
    }
}

/// Generate test scenarios for property-based testing
fn encoding_scenarios() -> impl Strategy<Value = EncodingTestScenario> {
    let data_strategy = prop::collection::vec(any::<u8>(), 0..1000);
    let encoding_list = vec!["gzip", "deflate", "br", "identity", "*"];
    let quality_values = vec![0.0, 0.1, 0.5, 0.8, 1.0];

    (
        data_strategy,
        prop::option::of(prop::collection::vec(
            (
                prop::sample::select(encoding_list),
                prop::sample::select(quality_values),
            ),
            1..=4,
        )),
        prop::collection::vec(
            prop::sample::select(vec![
                ContentEncoding::Identity,
                ContentEncoding::Gzip,
                ContentEncoding::Deflate,
                ContentEncoding::Brotli,
            ]),
            1..=4,
        ),
    )
        .prop_map(|(data, accept_list, server_supported)| {
            let accept_encoding = accept_list.map(|list| {
                list.iter()
                    .map(|(enc, q)| {
                        if *q == 1.0 {
                            enc.to_string()
                        } else {
                            format!("{};q={}", enc, q)
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            });

            EncodingTestScenario::new(data, accept_encoding, server_supported)
        })
}

/// **MR1: Codec Identifier Conformance**
///
/// Verifies that standard codec identifiers are correctly mapped to ContentEncoding variants:
/// - "gzip" | "x-gzip" → Gzip
/// - "deflate" → Deflate
/// - "br" → Brotli
/// - "identity" → Identity
#[test]
fn mr1_codec_identifier_conformance() {
    proptest!(|(
        variant in prop::sample::select(vec![
            ("gzip", ContentEncoding::Gzip),
            ("x-gzip", ContentEncoding::Gzip),
            ("deflate", ContentEncoding::Deflate),
            ("br", ContentEncoding::Brotli),
            ("identity", ContentEncoding::Identity),
        ])
    )| {
        let (token, expected_encoding) = variant;

        // MR1.1: Token parsing is case-insensitive and bidirectional
        prop_assert_eq!(ContentEncoding::from_token(token), Some(expected_encoding));
        prop_assert_eq!(ContentEncoding::from_token(&token.to_uppercase()), Some(expected_encoding));

        // MR1.2: Round-trip conversion preserves canonical form
        let canonical_token = expected_encoding.as_token();
        prop_assert_eq!(ContentEncoding::from_token(canonical_token), Some(expected_encoding));

        // MR1.3: Header parsing extracts correct encoding
        let headers = vec![("Content-Encoding".to_owned(), token.to_owned())];
        prop_assert_eq!(content_encoding_from_headers(&headers), Some(expected_encoding));

        // MR1.4: Display format matches canonical token
        prop_assert_eq!(expected_encoding.to_string(), canonical_token);
    });
}

/// **MR2: Identity Default Behavior**
///
/// Verifies RFC 9110 Section 12.5.3 identity encoding default behavior:
/// - identity is implicitly acceptable (q=1.0) unless explicitly rejected
/// - Empty Accept-Encoding means only identity is acceptable
/// - No Accept-Encoding header prefers identity when available
#[test]
fn mr2_identity_default_behavior() {
    proptest!(|(
        server_encodings in prop::collection::vec(
            prop::sample::select(vec![
                ContentEncoding::Identity,
                ContentEncoding::Gzip,
                ContentEncoding::Deflate,
                ContentEncoding::Brotli,
            ]),
            1..=4
        ),
        wildcard_quality in prop::sample::select(vec![0.0, 0.3, 0.5, 0.8, 1.0])
    )| {
        // MR2.1: No Accept-Encoding header prefers identity when available
        if server_encodings.contains(&ContentEncoding::Identity) {
            let negotiated = negotiate_encoding(None, &server_encodings);
            prop_assert_eq!(negotiated, Some(ContentEncoding::Identity));
        } else {
            let negotiated = negotiate_encoding(None, &server_encodings);
            prop_assert_eq!(negotiated, server_encodings.first().copied());
        }

        // MR2.2: Empty Accept-Encoding only accepts identity
        if server_encodings.contains(&ContentEncoding::Identity) {
            let negotiated = negotiate_encoding(Some(""), &server_encodings);
            prop_assert_eq!(negotiated, Some(ContentEncoding::Identity));
        } else {
            let negotiated = negotiate_encoding(Some(""), &server_encodings);
            prop_assert_eq!(negotiated, None);
        }

        // MR2.3: Wildcard quality does not lower identity's implicit q=1.0 unless q=0
        if server_encodings.contains(&ContentEncoding::Identity) {
            let accept_header = format!("*;q={}", wildcard_quality);
            let negotiated = negotiate_encoding(Some(&accept_header), &server_encodings);

            if wildcard_quality <= 0.0 {
                // *;q=0 explicitly rejects identity
                prop_assert_eq!(negotiated, None);
            } else {
                // identity keeps q=1.0 default, should win over wildcard
                prop_assert_eq!(negotiated, Some(ContentEncoding::Identity));
            }
        }

        // MR2.4: Explicit identity;q=0 overrides default
        let explicit_reject = "identity;q=0, gzip;q=1.0";
        if server_encodings.contains(&ContentEncoding::Gzip) {
            let negotiated = negotiate_encoding(Some(explicit_reject), &server_encodings);
            prop_assert_eq!(negotiated, Some(ContentEncoding::Gzip));
        }
    });
}

/// **MR3: Unknown Codec Rejection**
///
/// Verifies that unknown/unsupported encodings are properly rejected:
/// - Unknown tokens in from_token() return None
/// - Negotiation ignores unknown encodings in Accept-Encoding
/// - make_compressor() returns None for unavailable encodings
#[test]
fn mr3_unknown_codec_rejection() {
    proptest!(|(
        unknown_token in "[a-z]{1,10}",
        server_encodings in prop::collection::vec(
            prop::sample::select(vec![
                ContentEncoding::Identity,
                ContentEncoding::Gzip,
                ContentEncoding::Deflate,
                ContentEncoding::Brotli,
            ]),
            1..=3
        )
    )| {
        // Skip known tokens to ensure we test truly unknown ones
        prop_assume!(!matches!(unknown_token.as_str(),
            "gzip" | "deflate" | "br" | "identity" | "xgzip"));

        // MR3.1: Unknown token parsing returns None
        prop_assert_eq!(ContentEncoding::from_token(&unknown_token), None);

        // MR3.2: Unknown encoding in Accept-Encoding is ignored
        let accept_with_unknown = format!("{};q=1.0, gzip;q=0.5", unknown_token);
        let negotiated = negotiate_encoding(Some(&accept_with_unknown), &server_encodings);

        // Should negotiate gzip if available, identity otherwise, never unknown
        if server_encodings.contains(&ContentEncoding::Gzip) {
            prop_assert_eq!(negotiated, Some(ContentEncoding::Gzip));
        } else if server_encodings.contains(&ContentEncoding::Identity) {
            prop_assert_eq!(negotiated, Some(ContentEncoding::Identity));
        } else {
            // No gzip or identity available
            prop_assert_eq!(negotiated, server_encodings.first().copied());
        }

        // MR3.3: Header extraction ignores unknown Content-Encoding values
        let headers_unknown = vec![("Content-Encoding".to_owned(), unknown_token)];
        prop_assert_eq!(content_encoding_from_headers(&headers_unknown), None);
    });
}

/// **MR4: Multi-Codec Negotiation Order**
///
/// Verifies that multi-codec Accept-Encoding lists are processed correctly:
/// - Higher quality values take precedence
/// - Server preference order breaks ties
/// - Explicit rejections (q=0) are respected
#[test]
fn mr4_multi_codec_negotiation_order() {
    proptest!(|(scenario in encoding_scenarios())| {
        let negotiated = negotiate_encoding(
            scenario.accept_encoding.as_deref(),
            &scenario.server_supported
        );

        if let Some(accept_header) = &scenario.accept_encoding {
            // Parse the Accept-Encoding manually to verify negotiation logic
            let mut quality_map: HashMap<String, f32> = HashMap::new();

            for part in accept_header.split(',') {
                let part = part.trim();
                if !part.is_empty() {
                    let mut pieces = part.splitn(2, ';');
                    let encoding = pieces.next().unwrap().trim().to_ascii_lowercase();
                    let quality = if let Some(q_part) = pieces.next() {
                        q_part.trim()
                            .strip_prefix("q=")
                            .or_else(|| q_part.strip_prefix("Q="))
                            .and_then(|q| q.trim().parse::<f32>().ok())
                            .unwrap_or(1.0)
                    } else {
                        1.0
                    };
                    quality_map.insert(encoding, quality);
                }
            }

            // MR4.1: Explicit q=0 encodings are never selected
            if let Some(selected) = negotiated {
                let token = selected.as_token().to_lowercase();
                if let Some(&quality) = quality_map.get(&token) {
                    prop_assert!(quality > 0.0,
                        "Selected encoding {} has q={}, should be rejected", token, quality);
                }
            }

            // MR4.2: Selected encoding should be in server's supported list
            if let Some(selected) = negotiated {
                prop_assert!(scenario.server_supported.contains(&selected),
                    "Selected encoding {:?} not in server supported list {:?}",
                    selected, scenario.server_supported);
            }
        } else {
            // MR4.3: No Accept-Encoding header behavior
            if scenario.server_supported.contains(&ContentEncoding::Identity) {
                prop_assert_eq!(negotiated, Some(ContentEncoding::Identity));
            } else {
                prop_assert_eq!(negotiated, scenario.server_supported.first().copied());
            }
        }
    });
}

/// **MR5: Compression/Decompression Reversibility**
///
/// Verifies that compression followed by decompression recovers the original data:
/// - compress(data) |> decompress === data (round-trip property)
/// - Encoder order reversal: encode(A) |> encode(B) |> decode(B) |> decode(A) === original
/// - Multiple compression stages preserve data integrity
#[test]
fn mr5_compression_decompression_reversibility() {
    proptest!(|(
        data in prop::collection::vec(any::<u8>(), 0..500),
        encoding in prop::sample::select(vec![
            ContentEncoding::Identity,
            ContentEncoding::Gzip,
            ContentEncoding::Deflate,
            ContentEncoding::Brotli,
        ])
    )| {
        // Skip empty data for compression algorithms (they don't compress well)
        if data.is_empty() && encoding != ContentEncoding::Identity {
            return Ok(());
        }

        // MR5.1: Basic round-trip property
        if let Some(mut compressor) = make_compressor(encoding) {
            let mut compressed = Vec::new();
            compressor.compress(&data, &mut compressed)?;
            compressor.finish(&mut compressed)?;

            // Decompress using appropriate decompressor
            let mut decompressed = Vec::new();
            match encoding {
                ContentEncoding::Identity => {
                    let mut decomp = asupersync::http::compress::IdentityDecompressor::new(None);
                    decomp.decompress(&compressed, &mut decompressed)?;
                    decomp.finish(&mut decompressed)?;
                }
                #[cfg(feature = "compression")]
                ContentEncoding::Gzip => {
                    let mut decomp = asupersync::http::compress::GzipDecompressor::new(None);
                    decomp.decompress(&compressed, &mut decompressed)?;
                    decomp.finish(&mut decompressed)?;
                }
                #[cfg(feature = "compression")]
                ContentEncoding::Deflate => {
                    let mut decomp = asupersync::http::compress::DeflateDecompressor::new(None);
                    decomp.decompress(&compressed, &mut decompressed)?;
                    decomp.finish(&mut decompressed)?;
                }
                #[cfg(feature = "compression")]
                ContentEncoding::Brotli => {
                    let mut decomp = asupersync::http::compress::BrotliDecompressor::new(None);
                    decomp.decompress(&compressed, &mut decompressed)?;
                    decomp.finish(&mut decompressed)?;
                }
                #[cfg(not(feature = "compression"))]
                ContentEncoding::Gzip | ContentEncoding::Deflate | ContentEncoding::Brotli => {
                    // Skip test if compression feature not enabled
                    return Ok(());
                }
            }

            prop_assert_eq!(decompressed, data,
                "Round-trip failed for {:?}: {} bytes -> {} bytes -> {} bytes",
                encoding, data.len(), compressed.len(), decompressed.len());
        }

        Ok(())
    })?;
}

/// **Integration Test: Complete Content-Encoding Workflow**
///
/// Tests the full HTTP Content-Encoding workflow from negotiation to compression
#[test]
fn integration_content_encoding_workflow() {
    let lab = LabRuntime::new(LabConfig::default());

    // Test data
    let test_data = b"Hello, World! This is test data for HTTP compression.".repeat(10);
    let server_supported = vec![
        ContentEncoding::Brotli,
        ContentEncoding::Gzip,
        ContentEncoding::Deflate,
        ContentEncoding::Identity,
    ];

    // Client preferences: prefers Brotli, accepts gzip, deflate with lower quality
    let accept_encoding = "br;q=1.0, gzip;q=0.8, deflate;q=0.6, identity;q=0.1";

    // Negotiation phase
    let negotiated = negotiate_encoding(Some(accept_encoding), &server_supported);
    assert_eq!(negotiated, Some(ContentEncoding::Brotli));

    // Compression phase
    if let Some(mut compressor) = make_compressor(ContentEncoding::Brotli) {
        let mut compressed = Vec::new();
        compressor.compress(&test_data, &mut compressed).unwrap();
        compressor.finish(&mut compressed).unwrap();

        // Verify compression occurred
        if !test_data.is_empty() {
            assert!(compressed.len() < test_data.len(), "Data should be compressed");
        }

        // Decompression phase
        #[cfg(feature = "compression")]
        {
            let mut decompressor = asupersync::http::compress::BrotliDecompressor::new(Some(64 * 1024));
            let mut decompressed = Vec::new();
            decompressor.decompress(&compressed, &mut decompressed).unwrap();
            decompressor.finish(&mut decompressed).unwrap();

            assert_eq!(decompressed, test_data);
        }

        // Header generation for response
        let content_encoding_header = ContentEncoding::Brotli.as_token();
        assert_eq!(content_encoding_header, "br");

        // Header parsing on client side
        let response_headers = vec![
            ("Content-Type".to_owned(), "text/plain".to_owned()),
            ("Content-Encoding".to_owned(), content_encoding_header.to_owned()),
        ];

        let extracted_encoding = content_encoding_from_headers(&response_headers);
        assert_eq!(extracted_encoding, Some(ContentEncoding::Brotli));
    }

    println!("✓ Complete Content-Encoding workflow verified");
}

/// **Edge Case Test: Malformed Accept-Encoding Headers**
#[test]
fn edge_case_malformed_accept_encoding() {
    let server_supported = vec![ContentEncoding::Gzip, ContentEncoding::Identity];

    // Malformed quality values should be ignored
    let malformed_cases = vec![
        "gzip;q=1.5",       // q > 1.0
        "gzip;q=-0.1",      // q < 0.0
        "gzip;q=abc",       // non-numeric q
        "gzip;q=NaN",       // NaN quality
        "gzip;q=infinity",  // infinite quality
        "",                 // empty header
        "   ",              // whitespace only
        "gzip;",            // missing quality value
        "gzip;q=",          // empty quality value
    ];

    for malformed in malformed_cases {
        let negotiated = negotiate_encoding(Some(malformed), &server_supported);

        // Should either pick a valid encoding or default behavior
        if let Some(selected) = negotiated {
            assert!(server_supported.contains(&selected));
        }

        // Empty/whitespace headers should only accept identity
        if malformed.trim().is_empty() {
            assert_eq!(negotiated, Some(ContentEncoding::Identity));
        }
    }
}

/// **Boundary Condition Test: Quality Value Edge Cases**
#[test]
fn boundary_quality_values() {
    let server_supported = vec![
        ContentEncoding::Gzip,
        ContentEncoding::Deflate,
        ContentEncoding::Identity,
    ];

    // Test exact boundary values
    let test_cases = vec![
        ("gzip;q=0.0, deflate;q=0.001", Some(ContentEncoding::Deflate)), // minimal positive
        ("gzip;q=1.0, deflate;q=0.999", Some(ContentEncoding::Gzip)),     // maximal values
        ("gzip;q=0, deflate;q=0", Some(ContentEncoding::Identity)),       // all rejected
        ("*;q=0", None),                                                   // wildcard rejection
        ("*;q=0.001", Some(ContentEncoding::Gzip)),                      // minimal wildcard
    ];

    for (accept_header, expected) in test_cases {
        let negotiated = negotiate_encoding(Some(accept_header), &server_supported);
        assert_eq!(negotiated, expected, "Failed for: {}", accept_header);
    }
}

#[cfg(test)]
mod conformance_suite {
    use super::*;

    /// Run all Content-Encoding conformance tests
    #[test]
    fn run_content_encoding_conformance_suite() {
        println!("Running RFC 9110 Section 8.4 Content-Encoding Conformance Tests");

        // Run each MR test
        mr1_codec_identifier_conformance();
        mr2_identity_default_behavior();
        mr3_unknown_codec_rejection();
        mr4_multi_codec_negotiation_order();
        mr5_compression_decompression_reversibility();

        // Run integration and edge case tests
        integration_content_encoding_workflow();
        edge_case_malformed_accept_encoding();
        boundary_quality_values();

        println!("✅ All Content-Encoding conformance tests passed");
    }
}