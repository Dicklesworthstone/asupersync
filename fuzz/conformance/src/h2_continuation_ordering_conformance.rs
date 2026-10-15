//! HTTP/2 CONTINUATION Frame Ordering Conformance Test
//!
//! Intended differential surface for HEADERS + CONTINUATION frame sequence handling.
//! Until a real independent h2/HPACK reference seam is wired, this harness fails
//! closed instead of reporting local Asupersync HPACK results as h2 crate evidence.
//!
//! Key scenarios tested per RFC 9113 Section 6.10:
//! - HEADERS without END_HEADERS followed by CONTINUATION with END_HEADERS
//! - Multiple CONTINUATION frames in sequence
//! - Frame size boundary conditions (max frame size splits)
//! - Header block reconstruction and HPACK decoding consistency
//! - Stream ID validation and ordering requirements

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::Frame;
use asupersync::http::h2::frame::{ContinuationFrame, HeadersFrame};
use asupersync::http::h2::hpack::{
    Decoder as AsupersyncDecoder, Encoder as AsupersyncEncoder, Header,
};
use std::collections::HashMap;

pub const H2_REFERENCE_STATUS: &str = "xfail-no-live-h2-hpack-reference";
pub const H2_REFERENCE_UNSUPPORTED: &str = "fail-closed: h2 crate HPACK/CONTINUATION reference seam is not wired; refusing to reuse asupersync HPACK as the reference implementation";

/// Test case for CONTINUATION frame ordering
#[derive(Debug, Clone)]
pub struct ContinuationTestCase {
    pub name: &'static str,
    pub description: &'static str,
    pub headers: Vec<(&'static str, &'static str)>,
    pub max_frame_size: usize,
    pub stream_id: u32,
}

/// Test result for conformance comparison
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ConformanceResult {
    pub test_name: String,
    pub reference_status: String,
    pub asupersync_headers: Option<Vec<(String, String)>>,
    pub h2_headers: Option<Vec<(String, String)>>,
    pub asupersync_error: Option<String>,
    pub h2_error: Option<String>,
    pub match_result: bool,
}

impl ConformanceResult {
    pub fn passed(&self) -> bool {
        self.match_result
    }

    pub fn summary(&self) -> String {
        match (self.passed(), &self.asupersync_error, &self.h2_error) {
            (true, None, None) => format!("✓ {}: Headers match", self.test_name),
            (true, Some(a_err), Some(h_err)) => format!(
                "✓ {}: Both failed as expected (as: {}, h2: {})",
                self.test_name, a_err, h_err
            ),
            (true, Some(a_err), None) => format!(
                "✓ {}: asupersync failed as expected ({})",
                self.test_name, a_err
            ),
            (true, None, Some(h_err)) => {
                format!("✓ {}: h2 failed as expected ({})", self.test_name, h_err)
            }
            (false, None, None) => format!("✗ {}: Header mismatch", self.test_name),
            (false, Some(a_err), None) => format!(
                "✗ {}: asupersync failed, h2 succeeded ({})",
                self.test_name, a_err
            ),
            (false, None, Some(h_err)) => format!(
                "✗ {}: h2 reference unavailable, asupersync sanity path produced headers ({})",
                self.test_name, h_err
            ),
            (false, Some(a_err), Some(h_err)) => format!(
                "✗ {}: Different errors (as: {}, h2: {})",
                self.test_name, a_err, h_err
            ),
        }
    }
}

/// Generate comprehensive test cases for CONTINUATION frame ordering
pub fn generate_test_cases() -> Vec<ContinuationTestCase> {
    let large_metadata: &'static str = Box::leak("x".repeat(500).into_boxed_str());
    let large_tracking: &'static str = Box::leak("y".repeat(300).into_boxed_str());

    vec![
        ContinuationTestCase {
            name: "simple_continuation",
            description: "Basic HEADERS + single CONTINUATION frame",
            headers: vec![
                (":method", "GET"),
                (":path", "/"),
                (":scheme", "https"),
                (":authority", "example.com"),
                ("user-agent", "test"),
            ],
            max_frame_size: 50, // Force split
            stream_id: 1,
        },
        ContinuationTestCase {
            name: "multiple_continuations",
            description: "HEADERS + multiple CONTINUATION frames",
            headers: vec![
                (":method", "POST"),
                (":path", "/api/v1/data"),
                (":scheme", "https"),
                (":authority", "api.example.com"),
                ("content-type", "application/json"),
                ("content-length", "1234"),
                (
                    "authorization",
                    "Bearer very-long-token-value-that-should-force-frame-splits",
                ),
                ("x-request-id", "12345678-1234-1234-1234-123456789012"),
                ("x-trace-id", "abcdefgh-ijkl-mnop-qrst-uvwxyz123456"),
                ("user-agent", "MyApp/1.0 (platform; build)"),
                ("accept", "application/json, application/xml, text/plain"),
                ("accept-encoding", "gzip, deflate, br"),
                ("accept-language", "en-US,en;q=0.9,es;q=0.8"),
            ],
            max_frame_size: 64, // Small frame to force many splits
            stream_id: 3,
        },
        ContinuationTestCase {
            name: "exact_frame_boundary",
            description: "Header block that exactly fills frame boundary",
            headers: vec![
                (":method", "GET"),
                (":path", "/test"),
                (":scheme", "https"),
                (":authority", "test.example.com"),
                ("custom-header", "exactly-sized-value"), // Tune this to hit boundary
            ],
            max_frame_size: 64,
            stream_id: 5,
        },
        ContinuationTestCase {
            name: "large_header_values",
            description: "Very large header values requiring multiple frames",
            headers: vec![
                (":method", "PUT"),
                (":path", "/upload"),
                (":scheme", "https"),
                (":authority", "upload.example.com"),
                (
                    "content-type",
                    "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
                ),
                ("x-large-metadata", large_metadata), // Large value
                ("x-large-tracking", large_tracking), // Another large value
            ],
            max_frame_size: 128,
            stream_id: 7,
        },
        ContinuationTestCase {
            name: "many_small_headers",
            description: "Many small headers requiring frame fragmentation",
            headers: (1..=50)
                .map(|i| {
                    let name: &'static mut str = format!("x-header-{:02}", i).leak();
                    (&*name, "value")
                })
                .chain(
                    [
                        (":method", "GET"),
                        (":path", "/headers"),
                        (":scheme", "https"),
                        (":authority", "headers.example.com"),
                    ]
                    .iter()
                    .copied(),
                )
                .collect(),
            max_frame_size: 256,
            stream_id: 9,
        },
        ContinuationTestCase {
            name: "minimum_frame_size",
            description: "Test with minimum allowed frame size",
            headers: vec![
                (":method", "GET"),
                (":path", "/min"),
                (":scheme", "https"),
                (":authority", "min.example.com"),
                ("x-test", "minimum-frame-size"),
            ],
            max_frame_size: 16, // Very small frames
            stream_id: 11,
        },
        ContinuationTestCase {
            name: "single_byte_continuation",
            description: "CONTINUATION frame with just one byte",
            headers: vec![
                (":method", "GET"),
                (":path", "/"),
                (":scheme", "https"),
                (":authority", "test.example.com"),
                ("x-tiny", "a"), // This might get split to single byte continuation
            ],
            max_frame_size: 30, // Crafted to create tiny continuation
            stream_id: 13,
        },
        ContinuationTestCase {
            name: "empty_continuation",
            description: "Test edge case with zero-length continuation",
            headers: vec![
                (":method", "GET"),
                (":path", "/empty"),
                (":scheme", "https"),
                (":authority", "empty.example.com"),
            ],
            max_frame_size: 32, // May create empty continuation in edge case
            stream_id: 15,
        },
        ContinuationTestCase {
            name: "huffman_encoding_split",
            description: "Headers with Huffman encoding across frame boundaries",
            headers: vec![
                (":method", "GET"),
                (":path", "/huffman-test-path-with-many-characters"),
                (":scheme", "https"),
                (":authority", "huffman-encoding-test.example.com"),
                (
                    "accept",
                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                ),
                ("accept-encoding", "gzip,deflate,sdch"),
                ("accept-language", "en-US,en;q=0.5"),
            ],
            max_frame_size: 48, // Force Huffman strings to split
            stream_id: 17,
        },
        ContinuationTestCase {
            name: "duplicate_header_names",
            description: "Multiple headers with same name (like Set-Cookie)",
            headers: vec![
                (":method", "GET"),
                (":path", "/cookies"),
                (":scheme", "https"),
                (":authority", "cookie.example.com"),
                ("set-cookie", "session=abc123; Path=/; HttpOnly"),
                ("set-cookie", "tracking=xyz789; Path=/; Secure"),
                ("set-cookie", "preference=dark; Path=/; SameSite=Lax"),
            ],
            max_frame_size: 64,
            stream_id: 19,
        },
        ContinuationTestCase {
            name: "max_stream_id",
            description: "Test with maximum valid stream ID",
            headers: vec![
                (":method", "GET"),
                (":path", "/max-stream"),
                (":scheme", "https"),
                (":authority", "max.example.com"),
            ],
            max_frame_size: 64,
            stream_id: 0x7fff_ffff, // Maximum 31-bit stream ID
        },
    ]
}

/// Run conformance test for a specific test case
pub fn run_conformance_test(
    test_case: &ContinuationTestCase,
) -> Result<ConformanceResult, Box<dyn std::error::Error>> {
    // Test asupersync implementation
    let asupersync_result = test_asupersync_continuation(&test_case);

    // Test h2 reference implementation. This currently fails closed until an
    // independent h2/HPACK seam exists.
    let h2_result = test_h2_continuation(&test_case);

    let match_result = match (&asupersync_result, &h2_result) {
        (Ok(a_headers), Ok(h_headers)) => headers_match(a_headers, h_headers),
        (Err(_), Err(_)) => true, // Both failed - this might be expected for invalid cases
        _ => false,               // One succeeded, one failed
    };

    Ok(ConformanceResult {
        test_name: test_case.name.to_string(),
        reference_status: H2_REFERENCE_STATUS.to_string(),
        asupersync_headers: asupersync_result.as_ref().ok().cloned(),
        h2_headers: h2_result.as_ref().ok().cloned(),
        asupersync_error: asupersync_result.as_ref().err().map(|e| e.to_string()),
        h2_error: h2_result.as_ref().err().map(|e| e.to_string()),
        match_result,
    })
}

/// Test asupersync CONTINUATION frame handling
fn test_asupersync_continuation(
    test_case: &ContinuationTestCase,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    // Encode headers with HPACK
    let mut encoder = AsupersyncEncoder::new();
    let mut header_block = BytesMut::new();
    let headers = test_case
        .headers
        .iter()
        .map(|(name, value)| Header::new(*name, *value))
        .collect::<Vec<_>>();
    encoder.encode(&headers, &mut header_block);

    let header_block = header_block.freeze();

    // Split header block into HEADERS + CONTINUATION frames based on max_frame_size
    let frames =
        create_frame_sequence(&header_block, test_case.max_frame_size, test_case.stream_id)?;

    // Process frames through asupersync decoder
    let mut decoder = AsupersyncDecoder::new();
    let mut complete_header_block = BytesMut::new();

    for frame in frames {
        match frame {
            Frame::Headers(headers_frame) => {
                if headers_frame.stream_id != test_case.stream_id {
                    return Err("Stream ID mismatch in HEADERS frame".into());
                }
                complete_header_block.extend_from_slice(&headers_frame.header_block);
            }
            Frame::Continuation(continuation_frame) => {
                if continuation_frame.stream_id != test_case.stream_id {
                    return Err("Stream ID mismatch in CONTINUATION frame".into());
                }
                complete_header_block.extend_from_slice(&continuation_frame.header_block);
            }
            _ => return Err("Unexpected frame type".into()),
        }
    }

    // Decode complete header block
    let mut complete_header_block = complete_header_block.freeze();
    let headers = decoder.decode(&mut complete_header_block)?;

    Ok(headers.into_iter().map(|h| (h.name, h.value)).collect())
}

/// Test h2 reference implementation.
fn test_h2_continuation(
    test_case: &ContinuationTestCase,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let message = format!(
        "{}; test_case={}; stream_id={}",
        H2_REFERENCE_UNSUPPORTED, test_case.name, test_case.stream_id
    );
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, message).into())
}

/// Create HEADERS + CONTINUATION frame sequence from header block
fn create_frame_sequence(
    header_block: &Bytes,
    max_frame_size: usize,
    stream_id: u32,
) -> Result<Vec<Frame>, Box<dyn std::error::Error>> {
    let mut frames = Vec::new();
    let mut remaining = header_block.clone();
    let mut is_first = true;

    while !remaining.is_empty() {
        let chunk_size = std::cmp::min(remaining.len(), max_frame_size);
        let chunk = remaining.split_to(chunk_size);
        let is_last = remaining.is_empty();

        if is_first {
            // First frame is HEADERS
            let headers_frame = HeadersFrame {
                stream_id,
                header_block: chunk,
                end_stream: false,
                end_headers: is_last, // Only set END_HEADERS on last frame
                priority: None,
            };
            frames.push(Frame::Headers(headers_frame));
            is_first = false;
        } else {
            // Subsequent frames are CONTINUATION
            let continuation_frame = ContinuationFrame {
                stream_id,
                header_block: chunk,
                end_headers: is_last, // Only set END_HEADERS on last frame
            };
            frames.push(Frame::Continuation(continuation_frame));
        }
    }

    Ok(frames)
}

/// Compare two header lists for equality (order-independent for most headers)
fn headers_match(headers1: &[(String, String)], headers2: &[(String, String)]) -> bool {
    if headers1.len() != headers2.len() {
        return false;
    }

    // Convert to maps for comparison (handling multiple values per name)
    let map1 = headers_to_multimap(headers1);
    let map2 = headers_to_multimap(headers2);

    map1 == map2
}

/// Convert header list to multimap for comparison
fn headers_to_multimap(headers: &[(String, String)]) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for (name, value) in headers {
        map.entry(name.clone()).or_default().push(value.clone());
    }

    // Sort values within each header name for deterministic comparison
    for values in map.values_mut() {
        values.sort();
    }

    map
}

/// Run all conformance tests and generate report
pub fn run_all_conformance_tests() -> Result<Vec<ConformanceResult>, Box<dyn std::error::Error>> {
    let test_cases = generate_test_cases();
    let mut results = Vec::new();

    for test_case in &test_cases {
        let result = run_conformance_test(test_case)?;
        println!("{}", result.summary());
        results.push(result);
    }

    Ok(results)
}

/// Generate detailed conformance report
pub fn generate_conformance_report(results: &[ConformanceResult]) -> String {
    let total = results.len();
    let passed = results.iter().filter(|r| r.passed()).count();
    let failed = total - passed;

    let mut report = String::new();
    report.push_str("# HTTP/2 CONTINUATION Frame Ordering Fail-Closed Report\n\n");
    report.push_str(&format!(
        "**Reference status:** `{}`\n\n",
        H2_REFERENCE_STATUS
    ));
    report.push_str(&format!("**Total Tests:** {}\n", total));
    report.push_str(&format!(
        "**Passed:** {} ({:.1}%)\n",
        passed,
        (passed as f64 / total as f64) * 100.0
    ));
    report.push_str(&format!(
        "**Failed:** {} ({:.1}%)\n\n",
        failed,
        (failed as f64 / total as f64) * 100.0
    ));

    if passed == total {
        report.push_str(
            "**LIVE H2 REFERENCE PASSED** - CONTINUATION behavior matched observed h2/HPACK output\n\n",
        );
    } else {
        report.push_str("**FAIL-CLOSED** - no conformance pass is claimed without a live h2/HPACK reference\n\n");
    }

    // Detailed results
    report.push_str("## Test Results\n\n");
    for result in results {
        report.push_str(&format!("### {}\n", result.test_name));
        if result.passed() {
            report.push_str("✅ **PASSED**\n");
        } else {
            report.push_str("❌ **FAILED**\n");
            if let Some(ref err) = result.asupersync_error {
                report.push_str(&format!("- **asupersync error:** {}\n", err));
            }
            if let Some(ref err) = result.h2_error {
                report.push_str(&format!("- **h2 error:** {}\n", err));
            }

            if result.asupersync_headers.is_some() && result.h2_headers.is_some() {
                report.push_str("- **Header count mismatch or value differences**\n");
                // Could add detailed diff here
            }
        }
        report.push_str("\n");
    }

    // Summary recommendations
    if failed > 0 {
        report.push_str("## Recommendations\n\n");
        report.push_str("1. Review failed test cases for differences in frame handling\n");
        report.push_str("2. Check HPACK encoding/decoding consistency\n");
        report.push_str("3. Verify CONTINUATION frame ordering rules per RFC 9113 Section 6.10\n");
        report
            .push_str("4. Ensure frame size boundary handling matches reference implementation\n");
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_continuation_case() {
        let test_case = ContinuationTestCase {
            name: "test_simple",
            description: "Simple test case",
            headers: vec![
                (":method", "GET"),
                (":path", "/test"),
                (":scheme", "https"),
                (":authority", "test.com"),
            ],
            max_frame_size: 32,
            stream_id: 1,
        };

        let result = run_conformance_test(&test_case).expect("Test should not fail");
        assert!(
            !result.passed(),
            "missing h2/HPACK reference must fail closed"
        );
        assert_eq!(result.reference_status, H2_REFERENCE_STATUS);
        assert!(
            result
                .h2_error
                .as_deref()
                .unwrap_or_default()
                .contains(H2_REFERENCE_UNSUPPORTED)
        );
    }

    #[test]
    fn test_multiple_continuation_case() {
        let test_case = ContinuationTestCase {
            name: "test_multiple",
            description: "Multiple CONTINUATION frames",
            headers: vec![
                (":method", "POST"),
                (":path", "/api/test"),
                (":scheme", "https"),
                (":authority", "api.test.com"),
                ("content-type", "application/json"),
                ("authorization", "Bearer long-token-value"),
                ("user-agent", "Test/1.0"),
            ],
            max_frame_size: 20, // Force multiple continuations
            stream_id: 3,
        };

        let result = run_conformance_test(&test_case).expect("Test should not fail");
        assert!(
            !result.passed(),
            "multiple CONTINUATION case must not pass without a live h2 reference"
        );
        assert!(result.asupersync_headers.is_some());
        assert!(result.h2_headers.is_none());
        assert!(result.summary().contains("h2 reference unavailable"));
    }

    #[test]
    fn test_reference_function_does_not_reuse_asupersync_hpack() {
        let source = include_str!("h2_continuation_ordering_conformance.rs");
        let reference_function = source
            .split("fn test_h2_continuation")
            .nth(1)
            .and_then(|tail| tail.split("/// Create HEADERS").next())
            .expect("reference function source should be locatable");

        for forbidden in [
            concat!("Asupersync", "Encoder"),
            concat!("Asupersync", "Decoder"),
            concat!("h2", "::", "hpack"),
            concat!("mock ", "h2 test"),
            concat!("simulates ", "h2 crate behavior"),
        ] {
            assert!(
                !reference_function.contains(forbidden),
                "h2 reference function must not contain stale local-reference marker {forbidden}"
            );
        }
    }

    #[test]
    fn test_report_refuses_conformance_claim_without_reference() {
        let results = run_all_conformance_tests().expect("fail-closed run should produce results");
        assert_eq!(results.len(), generate_test_cases().len());
        assert!(results.iter().all(|result| !result.passed()));

        let report = generate_conformance_report(&results);
        assert!(report.contains("FAIL-CLOSED"));
        assert!(report.contains(H2_REFERENCE_STATUS));
        assert!(!report.contains("ALL TESTS PASSED"));
        assert!(!report.contains("produced identical"));
    }

    #[test]
    fn test_headers_multimap_conversion() {
        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("set-cookie".to_string(), "session=abc".to_string()),
            ("set-cookie".to_string(), "tracking=xyz".to_string()),
            ("content-length".to_string(), "1234".to_string()),
        ];

        let map = headers_to_multimap(&headers);

        assert_eq!(
            map.get("content-type").unwrap(),
            &vec!["application/json".to_string()]
        );
        assert_eq!(
            map.get("content-length").unwrap(),
            &vec!["1234".to_string()]
        );

        let mut expected_cookies = vec!["session=abc".to_string(), "tracking=xyz".to_string()];
        expected_cookies.sort();
        assert_eq!(map.get("set-cookie").unwrap(), &expected_cookies);
    }

    #[test]
    fn test_frame_sequence_creation() {
        let header_block = Bytes::from("test-header-block-data");
        let frames = create_frame_sequence(&header_block, 10, 1).unwrap();

        // Should create multiple frames due to small max size
        assert!(frames.len() > 1);

        // First frame should be HEADERS
        match &frames[0] {
            Frame::Headers(h) => {
                assert_eq!(h.stream_id, 1);
                assert!(!h.end_headers); // Not the last frame
            }
            _ => panic!("First frame should be HEADERS"),
        }

        // Last frame should have END_HEADERS set
        match frames.last().unwrap() {
            Frame::Headers(h) => assert!(h.end_headers),
            Frame::Continuation(c) => assert!(c.end_headers),
            _ => panic!("Unexpected frame type"),
        }
    }
}
