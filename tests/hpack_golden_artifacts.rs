#![allow(warnings)]
#![allow(clippy::all)]
//! Golden artifact tests for HPACK header compression/decompression.
//!
//! These tests verify that HPACK encoding and decoding produce consistent,
//! deterministic outputs for known inputs. Changes to HPACK behavior will
//! cause golden mismatches, ensuring backwards compatibility per RFC 7541.
//!
//! To update goldens after intentional changes:
//!   UPDATE_GOLDENS=1 cargo test --test hpack_golden_artifacts

use insta::assert_json_snapshot;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::hpack::{Decoder, Encoder, Header};

/// Golden artifact representation of HPACK encoding results.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HpackEncodingGolden {
    /// Description of this test case.
    description: String,
    /// Input headers.
    headers: Vec<HpackHeaderGolden>,
    /// Encoder configuration.
    config: HpackConfigGolden,
    /// Encoded bytes (as array for deterministic comparison).
    encoded_bytes: Vec<u8>,
    /// Size of encoded data.
    encoded_size: usize,
    /// Dynamic table state after encoding.
    dynamic_table_state: DynamicTableStateGolden,
}

/// Golden artifact representation of HPACK decoding results.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
struct HpackDecodingGolden {
    /// Description of this test case.
    description: String,
    /// Input encoded bytes.
    input_bytes: Vec<u8>,
    /// Decoder configuration.
    config: HpackConfigGolden,
    /// Decoded headers.
    headers: Vec<HpackHeaderGolden>,
    /// Dynamic table state after decoding.
    dynamic_table_state: DynamicTableStateGolden,
}

/// Golden artifact representation of HPACK round-trip test.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HpackRoundTripGolden {
    /// Description of this test case.
    description: String,
    /// Original headers.
    original_headers: Vec<HpackHeaderGolden>,
    /// Encoder configuration.
    encoder_config: HpackConfigGolden,
    /// Encoded bytes.
    encoded_bytes: Vec<u8>,
    /// Decoder configuration.
    decoder_config: HpackConfigGolden,
    /// Decoded headers (should match original).
    decoded_headers: Vec<HpackHeaderGolden>,
    /// Success flag for round-trip.
    round_trip_successful: bool,
}

/// Golden representation of an HPACK header.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct HpackHeaderGolden {
    name: String,
    value: String,
}

impl From<&Header> for HpackHeaderGolden {
    fn from(header: &Header) -> Self {
        Self {
            name: header.name.clone(),
            value: header.value.clone(),
        }
    }
}

impl From<&HpackHeaderGolden> for Header {
    fn from(golden: &HpackHeaderGolden) -> Self {
        Self {
            name: golden.name.clone(),
            value: golden.value.clone(),
        }
    }
}

/// Golden representation of HPACK encoder/decoder configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HpackConfigGolden {
    use_huffman: bool,
    max_table_size: usize,
    max_header_list_size: Option<usize>,
}

/// Golden representation of dynamic table state.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DynamicTableStateGolden {
    /// Current table size in bytes.
    current_size: usize,
    /// Number of entries in the table.
    entry_count: usize,
    /// Table entries (name, value pairs).
    entries: Vec<(String, String)>,
}

/// Creates test headers for various scenarios.
fn create_test_headers(scenario: &str) -> Vec<Header> {
    match scenario {
        "basic_get" => vec![
            Header {
                name: ":method".to_string(),
                value: "GET".to_string(),
            },
            Header {
                name: ":path".to_string(),
                value: "/".to_string(),
            },
            Header {
                name: ":scheme".to_string(),
                value: "https".to_string(),
            },
            Header {
                name: ":authority".to_string(),
                value: "example.com".to_string(),
            },
        ],
        "custom_headers" => vec![
            Header {
                name: "user-agent".to_string(),
                value: "asupersync/1.0".to_string(),
            },
            Header {
                name: "accept".to_string(),
                value: "text/html,application/xhtml+xml".to_string(),
            },
            Header {
                name: "cache-control".to_string(),
                value: "no-cache".to_string(),
            },
        ],
        "repeated_headers" => vec![
            Header {
                name: "set-cookie".to_string(),
                value: "sessionid=abc123".to_string(),
            },
            Header {
                name: "set-cookie".to_string(),
                value: "userid=456".to_string(),
            },
            Header {
                name: "vary".to_string(),
                value: "Accept-Encoding".to_string(),
            },
        ],
        "large_values" => vec![
            Header {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            },
            Header {
                name: "authorization".to_string(),
                value: format!("Bearer {}", "a".repeat(200)), // Long token
            },
        ],
        "empty_and_special" => vec![
            Header {
                name: "empty-value".to_string(),
                value: String::new(),
            },
            Header {
                name: "special-chars".to_string(),
                value: "!@#$%^&*()".to_string(),
            },
            Header {
                name: "unicode".to_string(),
                value: "héllo wørld 🌍".to_string(),
            },
        ],
        _ => vec![],
    }
}

/// Simulates dynamic table state extraction (simplified for golden tests).
fn extract_dynamic_table_state(_encoder_or_decoder: &str) -> DynamicTableStateGolden {
    // In a real implementation, we'd extract actual dynamic table state
    // For golden tests, we simulate this with deterministic data
    DynamicTableStateGolden {
        current_size: 0, // Would be actual size
        entry_count: 0,  // Would be actual count
        entries: vec![], // Would be actual entries
    }
}

/// Tests HPACK encoding with various header sets.
fn test_hpack_encoding(
    headers: &[Header],
    use_huffman: bool,
    description: &str,
) -> HpackEncodingGolden {
    let mut encoder = Encoder::new();
    encoder.set_use_huffman(use_huffman);
    let mut dst = BytesMut::new();

    encoder.encode(headers, &mut dst);

    let encoded_bytes = dst.to_vec();
    let dynamic_table_state = extract_dynamic_table_state("encoder");

    HpackEncodingGolden {
        description: description.to_string(),
        headers: headers.iter().map(HpackHeaderGolden::from).collect(),
        config: HpackConfigGolden {
            use_huffman,
            max_table_size: 4096, // DEFAULT_MAX_TABLE_SIZE
            max_header_list_size: None,
        },
        encoded_bytes: encoded_bytes.clone(),
        encoded_size: encoded_bytes.len(),
        dynamic_table_state,
    }
}

/// Tests HPACK decoding with encoded data.
#[allow(dead_code)]
fn test_hpack_decoding(
    encoded_data: &[u8],
    description: &str,
) -> Result<HpackDecodingGolden, String> {
    let mut decoder = Decoder::new();
    let mut src = Bytes::from(encoded_data.to_vec());

    match decoder.decode(&mut src) {
        Ok(headers) => {
            let dynamic_table_state = extract_dynamic_table_state("decoder");

            Ok(HpackDecodingGolden {
                description: description.to_string(),
                input_bytes: encoded_data.to_vec(),
                config: HpackConfigGolden {
                    use_huffman: false, // Not configurable for decoder
                    max_table_size: 4096,
                    max_header_list_size: Some(8192), // Default max_header_list_size
                },
                headers: headers.iter().map(HpackHeaderGolden::from).collect(),
                dynamic_table_state,
            })
        }
        Err(e) => Err(format!("Decoding failed: {e}")),
    }
}

/// Tests HPACK round-trip encoding then decoding.
fn test_hpack_round_trip(
    headers: &[Header],
    use_huffman: bool,
    description: &str,
) -> HpackRoundTripGolden {
    // Encode
    let mut encoder = Encoder::new();
    encoder.set_use_huffman(use_huffman);
    let mut dst = BytesMut::new();
    encoder.encode(headers, &mut dst);
    let encoded_bytes = dst.to_vec();

    // Decode
    let mut decoder = Decoder::new();
    let mut src = Bytes::from(encoded_bytes.clone());
    let decode_result = decoder.decode(&mut src);

    let (decoded_headers, round_trip_successful) = match decode_result {
        Ok(decoded) => {
            let original_golden: Vec<HpackHeaderGolden> =
                headers.iter().map(HpackHeaderGolden::from).collect();
            let decoded_golden: Vec<HpackHeaderGolden> =
                decoded.iter().map(HpackHeaderGolden::from).collect();
            let successful = original_golden == decoded_golden;
            (decoded_golden, successful)
        }
        Err(_) => (vec![], false),
    };

    HpackRoundTripGolden {
        description: description.to_string(),
        original_headers: headers.iter().map(HpackHeaderGolden::from).collect(),
        encoder_config: HpackConfigGolden {
            use_huffman,
            max_table_size: 4096,
            max_header_list_size: None,
        },
        encoded_bytes,
        decoder_config: HpackConfigGolden {
            use_huffman: false,
            max_table_size: 4096,
            max_header_list_size: Some(8192),
        },
        decoded_headers,
        round_trip_successful,
    }
}

#[test]
fn test_hpack_basic_encoding_no_huffman() {
    let headers = create_test_headers("basic_get");
    let golden = test_hpack_encoding(&headers, false, "Basic GET request headers without Huffman");
    assert_json_snapshot!("hpack_basic_encoding_no_huffman", golden);
}

#[test]
fn test_hpack_basic_encoding_with_huffman() {
    let headers = create_test_headers("basic_get");
    let golden = test_hpack_encoding(&headers, true, "Basic GET request headers with Huffman");
    assert_json_snapshot!("hpack_basic_encoding_with_huffman", golden);
}

#[test]
fn test_hpack_custom_headers_encoding() {
    let headers = create_test_headers("custom_headers");
    let golden = test_hpack_encoding(&headers, true, "Custom headers with Huffman encoding");
    assert_json_snapshot!("hpack_custom_headers_encoding", golden);
}

#[test]
fn test_hpack_repeated_headers_encoding() {
    let headers = create_test_headers("repeated_headers");
    let golden = test_hpack_encoding(&headers, false, "Repeated header names (cookies, vary)");
    assert_json_snapshot!("hpack_repeated_headers_encoding", golden);
}

#[test]
fn test_hpack_large_values_encoding() {
    let headers = create_test_headers("large_values");
    let golden = test_hpack_encoding(
        &headers,
        true,
        "Headers with large values (long authorization)",
    );
    assert_json_snapshot!("hpack_large_values_encoding", golden);
}

#[test]
fn test_hpack_special_characters() {
    let headers = create_test_headers("empty_and_special");
    let golden = test_hpack_encoding(
        &headers,
        true,
        "Headers with empty values, special chars, unicode",
    );
    assert_json_snapshot!("hpack_special_characters", golden);
}

#[test]
fn test_hpack_round_trip_basic() {
    let headers = create_test_headers("basic_get");
    let golden = test_hpack_round_trip(
        &headers,
        false,
        "Basic GET headers round-trip without Huffman",
    );
    assert!(
        golden.round_trip_successful,
        "Round-trip should be successful"
    );
    assert_json_snapshot!("hpack_round_trip_basic", golden);
}

#[test]
fn test_hpack_round_trip_with_huffman() {
    let headers = create_test_headers("custom_headers");
    let golden = test_hpack_round_trip(&headers, true, "Custom headers round-trip with Huffman");
    assert!(
        golden.round_trip_successful,
        "Round-trip should be successful"
    );
    assert_json_snapshot!("hpack_round_trip_with_huffman", golden);
}

#[test]
fn test_hpack_empty_headers() {
    let headers: Vec<Header> = vec![];
    let golden = test_hpack_encoding(&headers, false, "Empty header list");
    assert_json_snapshot!("hpack_empty_headers", golden);
}

#[test]
fn test_hpack_static_table_hits() {
    // Headers that should hit the static table exactly
    let headers = vec![
        Header {
            name: ":method".to_string(),
            value: "GET".to_string(),
        }, // Index 2
        Header {
            name: ":method".to_string(),
            value: "POST".to_string(),
        }, // Index 3
        Header {
            name: ":path".to_string(),
            value: "/".to_string(),
        }, // Index 4
        Header {
            name: ":scheme".to_string(),
            value: "https".to_string(),
        }, // Index 7
        Header {
            name: ":status".to_string(),
            value: "200".to_string(),
        }, // Index 8
    ];
    let golden = test_hpack_encoding(&headers, false, "Headers with exact static table matches");
    assert_json_snapshot!("hpack_static_table_hits", golden);
}

#[test]
fn test_hpack_mixed_static_dynamic() {
    let headers = vec![
        // Static table hit
        Header {
            name: ":method".to_string(),
            value: "GET".to_string(),
        },
        // Static name, custom value
        Header {
            name: ":path".to_string(),
            value: "/api/v1/users".to_string(),
        },
        // Completely custom
        Header {
            name: "x-custom-header".to_string(),
            value: "custom-value".to_string(),
        },
        // Static table hit
        Header {
            name: "accept-encoding".to_string(),
            value: "gzip, deflate".to_string(),
        },
    ];
    let golden = test_hpack_encoding(
        &headers,
        true,
        "Mix of static exact, static name, and custom headers",
    );
    assert_json_snapshot!("hpack_mixed_static_dynamic", golden);
}

#[test]
fn test_hpack_compression_efficiency() {
    // Test that demonstrates compression benefits
    let scenarios = [
        ("basic_get", false),
        ("basic_get", true),
        ("custom_headers", false),
        ("custom_headers", true),
        ("large_values", false),
        ("large_values", true),
    ];

    let mut results = BTreeMap::new();
    for (scenario, use_huffman) in scenarios {
        let headers = create_test_headers(scenario);
        let golden = test_hpack_encoding(
            &headers,
            use_huffman,
            &format!(
                "{} headers {} Huffman",
                scenario,
                if use_huffman { "with" } else { "without" }
            ),
        );

        let key = format!(
            "{}_{}",
            scenario,
            if use_huffman { "huffman" } else { "no_huffman" }
        );
        results.insert(key, golden);
    }

    assert_json_snapshot!("hpack_compression_efficiency", results);
}

#[test]
fn test_hpack_deterministic_encoding() {
    // Test that encoding is deterministic - same headers produce identical output
    let headers = create_test_headers("basic_get");

    let golden1 = test_hpack_encoding(&headers, true, "First encoding");
    let golden2 = test_hpack_encoding(&headers, true, "Second encoding");

    assert_eq!(
        golden1.encoded_bytes, golden2.encoded_bytes,
        "HPACK encoding should be deterministic"
    );

    assert_json_snapshot!("hpack_deterministic_encoding", golden1);
}
