//! HTTP/3 RFC 9297 DATAGRAM frame format validation conformance tests.
//!
//! Tests compliance with RFC 9297 H3 DATAGRAM frame format requirements:
//! - Flow ID encoding validation
//! - Frame ordering semantics
//! - Negotiation and capability detection

use super::*;
use asupersync::http::h3_native::{H3ConnectionConfig, H3Frame, H3RequestStreamState, H3Settings};

/// H3 DATAGRAM frame structure and validation.
#[derive(Debug, Clone)]
pub struct H3DatagramFrame {
    /// Quarter Stream ID / Flow ID.
    pub flow_id: u64,
    /// HTTP Datagram payload.
    pub payload: Vec<u8>,
}

/// Run all H3 DATAGRAM format validation conformance tests.
#[allow(dead_code)]
pub fn run_datagram_format_tests() -> Vec<H3ConformanceResult> {
    let mut results = Vec::new();

    results.push(test_datagram_frame_format());
    results.push(test_flow_id_encoding());
    results.push(test_datagram_ordering_semantics());
    results.push(test_datagram_capability_negotiation());
    results.push(test_datagram_error_handling());

    results
}

/// RFC 9297 Section 2: H3 DATAGRAM frame format validation.
#[allow(dead_code)]
fn test_datagram_frame_format() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        // Test valid DATAGRAM frame formats
        let valid_frames = vec![
            (
                H3DatagramFrame {
                    flow_id: 0,
                    payload: b"hello".to_vec(),
                },
                "DATAGRAM with flow ID 0",
            ),
            (
                H3DatagramFrame {
                    flow_id: 1,
                    payload: b"world".to_vec(),
                },
                "DATAGRAM with flow ID 1",
            ),
            (
                H3DatagramFrame {
                    flow_id: 255,
                    payload: vec![],
                },
                "DATAGRAM with empty payload",
            ),
            (
                H3DatagramFrame {
                    flow_id: 16383,
                    payload: vec![0; 1200],
                },
                "DATAGRAM with large payload",
            ),
        ];

        for (datagram_frame, description) in valid_frames {
            let encoded = encode_datagram_frame(&datagram_frame);

            if !validate_datagram_frame_format(&encoded) {
                return Err(format!(
                    "Valid DATAGRAM frame was rejected: {}",
                    description
                ));
            }

            // Verify round-trip encoding/decoding
            let decoded = decode_datagram_frame(&encoded)?;
            if decoded.flow_id != datagram_frame.flow_id {
                return Err(format!(
                    "Flow ID mismatch for {}: expected {}, got {}",
                    description, datagram_frame.flow_id, decoded.flow_id
                ));
            }

            if decoded.payload != datagram_frame.payload {
                return Err(format!(
                    "Payload mismatch for {}: lengths {} vs {}",
                    description,
                    datagram_frame.payload.len(),
                    decoded.payload.len()
                ));
            }
        }

        Ok(())
    });

    H3ConformanceResult {
        test_id: "RFC9297-2-DATAGRAM-FORMAT".to_string(),
        description: "H3 DATAGRAM frame format validation".to_string(),
        category: TestCategory::DatagramFormat,
        requirement_level: RequirementLevel::Must,
        verdict: if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        },
        elapsed_ms,
        notes: result.err(),
    }
}

/// RFC 9297 Section 2.1: Flow ID encoding validation.
#[allow(dead_code)]
fn test_flow_id_encoding() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        // Test various flow ID encodings
        let flow_id_cases = vec![
            (0u64, "minimal flow ID"),
            (63u64, "single-byte varint maximum"),
            (64u64, "two-byte varint minimum"),
            (16383u64, "two-byte varint maximum"),
            (16384u64, "four-byte varint minimum"),
            (1073741823u64, "four-byte varint maximum"),
            (1073741824u64, "eight-byte varint minimum"),
        ];

        for (flow_id, description) in flow_id_cases {
            let datagram = H3DatagramFrame {
                flow_id,
                payload: b"test".to_vec(),
            };

            let encoded = encode_datagram_frame(&datagram);

            // Verify flow ID is properly encoded as varint
            let expected_varint_len = calculate_varint_length(flow_id);
            if encoded.len() < expected_varint_len + 4 {
                return Err(format!(
                    "Encoded frame too short for {}: expected at least {} bytes",
                    description,
                    expected_varint_len + 4
                ));
            }

            // Verify flow ID decoding
            let decoded = decode_datagram_frame(&encoded)?;
            if decoded.flow_id != flow_id {
                return Err(format!(
                    "Flow ID encoding error for {}: expected {}, decoded {}",
                    description, flow_id, decoded.flow_id
                ));
            }

            // Verify payload integrity
            if decoded.payload != datagram.payload {
                return Err(format!(
                    "Payload corrupted during flow ID encoding for {}",
                    description
                ));
            }
        }

        Ok(())
    });

    H3ConformanceResult {
        test_id: "RFC9297-2.1-FLOW-ID-ENCODING".to_string(),
        description: "Flow ID varint encoding validation".to_string(),
        category: TestCategory::DatagramFormat,
        requirement_level: RequirementLevel::Must,
        verdict: if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        },
        elapsed_ms,
        notes: result.err(),
    }
}

/// RFC 9297 Section 4: DATAGRAM ordering semantics.
#[allow(dead_code)]
fn test_datagram_ordering_semantics() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        // DATAGRAM frames have no ordering guarantees - test independent delivery
        let datagram_sequence = vec![
            H3DatagramFrame {
                flow_id: 1,
                payload: b"first".to_vec(),
            },
            H3DatagramFrame {
                flow_id: 1,
                payload: b"second".to_vec(),
            },
            H3DatagramFrame {
                flow_id: 2,
                payload: b"other_flow".to_vec(),
            },
            H3DatagramFrame {
                flow_id: 1,
                payload: b"third".to_vec(),
            },
        ];

        // Encode all frames
        let encoded_frames: Vec<Vec<u8>> = datagram_sequence
            .iter()
            .map(encode_datagram_frame)
            .collect();

        // Process frames in order
        for (i, encoded_frame) in encoded_frames.iter().enumerate() {
            if !process_datagram_frame(encoded_frame) {
                return Err(format!(
                    "Frame {} processing failed during ordering test",
                    i
                ));
            }
        }

        // Verify frames can be processed out-of-order.

        let reordered_indices = vec![0, 2, 1, 3]; // Process in different order
        for &i in &reordered_indices {
            if !process_datagram_frame(&encoded_frames[i]) {
                return Err(format!(
                    "Frame {} processing failed during out-of-order test",
                    i
                ));
            }
        }

        // Test flow ID independence
        let flow_isolation_test = vec![
            (1, b"flow1_msg1"),
            (2, b"flow2_msg1"),
            (1, b"flow1_msg2"),
            (3, b"flow3_msg1"),
            (2, b"flow2_msg2"),
        ];

        for (flow_id, payload) in flow_isolation_test {
            let frame = H3DatagramFrame {
                flow_id,
                payload: payload.to_vec(),
            };
            let encoded = encode_datagram_frame(&frame);

            if !process_datagram_frame(&encoded) {
                return Err(format!(
                    "Flow isolation test failed for flow {} with payload {:?}",
                    flow_id, payload
                ));
            }
        }

        Ok(())
    });

    H3ConformanceResult {
        test_id: "RFC9297-4-DATAGRAM-ORDERING".to_string(),
        description: "DATAGRAM frame ordering and flow isolation".to_string(),
        category: TestCategory::DatagramFormat,
        requirement_level: RequirementLevel::Must,
        verdict: if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        },
        elapsed_ms,
        notes: result.err(),
    }
}

/// RFC 9297 Section 3: DATAGRAM capability negotiation.
#[allow(dead_code)]
fn test_datagram_capability_negotiation() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        // Production H3Settings parses the peer's SETTINGS_H3_DATAGRAM value.
        let settings_with_datagram = create_settings_with_datagram(true);
        let decoded_with_datagram = decode_settings_payload(&settings_with_datagram)?;
        if decoded_with_datagram.h3_datagram != Some(true) {
            return Err("SETTINGS_H3_DATAGRAM=1 did not decode as enabled".to_string());
        }

        let settings_no_datagram = create_settings_with_datagram(false);
        let decoded_no_datagram = decode_settings_payload(&settings_no_datagram)?;
        if decoded_no_datagram.h3_datagram != Some(false) {
            return Err("SETTINGS_H3_DATAGRAM=0 did not decode as disabled".to_string());
        }

        let settings_empty = create_empty_settings();
        let decoded_empty = decode_settings_payload(&settings_empty)?;
        if decoded_empty.h3_datagram.is_some() {
            return Err("empty SETTINGS unexpectedly enabled H3_DATAGRAM".to_string());
        }

        Ok(())
    });

    let (verdict, notes) = match result {
        Ok(()) => (
            TestVerdict::ExpectedFailure,
            Some(
                "H3Settings parses SETTINGS_H3_DATAGRAM, but H3ConnectionState does not expose peer-negotiated DATAGRAM gating yet"
                    .to_string(),
            ),
        ),
        Err(err) => (TestVerdict::Fail, Some(err)),
    };

    H3ConformanceResult {
        test_id: "RFC9297-3-DATAGRAM-NEGOTIATION".to_string(),
        description: "DATAGRAM capability negotiation via SETTINGS".to_string(),
        category: TestCategory::Settings,
        requirement_level: RequirementLevel::Must,
        verdict,
        elapsed_ms,
        notes,
    }
}

/// RFC 9297: DATAGRAM error handling.
#[allow(dead_code)]
fn test_datagram_error_handling() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        // Test various malformed DATAGRAM frames
        let malformed_frames = vec![
            (vec![], "empty DATAGRAM frame"),
            (vec![0xFF, 0xFF, 0xFF, 0xFF], "truncated flow ID varint"),
            (vec![0x80], "incomplete varint encoding"),
        ];

        for (malformed_data, description) in malformed_frames {
            if validate_datagram_frame_format(&malformed_data) {
                return Err(format!(
                    "Malformed DATAGRAM frame was accepted: {}",
                    description
                ));
            }

            if process_datagram_frame(&malformed_data) {
                return Err(format!(
                    "Processing succeeded for malformed frame: {}",
                    description
                ));
            }
        }

        // Test oversized DATAGRAM frames through the production frame-size gate.
        let oversized_payload = vec![0; 16];
        let oversized_frame = H3DatagramFrame {
            flow_id: 0,
            payload: oversized_payload,
        };
        let encoded_oversized = encode_datagram_frame(&oversized_frame);
        let tight_config = H3ConnectionConfig {
            max_frame_payload_size: 4,
            ..H3ConnectionConfig::default()
        };

        match H3Frame::decode(&encoded_oversized, &tight_config) {
            Err(asupersync::http::h3_native::H3NativeError::FrameTooLarge { .. }) => {}
            Ok(_) => return Err("Oversized DATAGRAM frame was accepted".to_string()),
            Err(err) => {
                return Err(format!(
                    "Oversized DATAGRAM frame produced wrong error: {err}"
                ));
            }
        }

        Ok(())
    });

    H3ConformanceResult {
        test_id: "RFC9297-ERROR-HANDLING".to_string(),
        description: "DATAGRAM frame error handling validation".to_string(),
        category: TestCategory::DatagramFormat,
        requirement_level: RequirementLevel::Must,
        verdict: if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        },
        elapsed_ms,
        notes: result.err(),
    }
}

// Helper functions and types for DATAGRAM testing

impl TestCategory {
    const DatagramFormat: TestCategory = TestCategory::Settings; // Reuse existing category
}

fn encode_datagram_frame(frame: &H3DatagramFrame) -> Vec<u8> {
    let mut encoded = Vec::new();
    H3Frame::Datagram {
        quarter_stream_id: frame.flow_id,
        payload: frame.payload.clone(),
    }
    .encode(&mut encoded)
    .expect("H3 DATAGRAM frame should encode");
    encoded
}

fn decode_datagram_frame(data: &[u8]) -> Result<H3DatagramFrame, String> {
    let (frame, consumed) = H3Frame::decode(data, &H3ConnectionConfig::default())
        .map_err(|err| format!("DATAGRAM frame decode failed: {err}"))?;
    if consumed != data.len() {
        return Err(format!(
            "DATAGRAM frame left trailing bytes: consumed {consumed} of {}",
            data.len()
        ));
    }

    match frame {
        H3Frame::Datagram {
            quarter_stream_id,
            payload,
        } => Ok(H3DatagramFrame {
            flow_id: quarter_stream_id,
            payload,
        }),
        other => Err(format!("decoded non-DATAGRAM frame: {other:?}")),
    }
}

fn decode_settings_payload(data: &[u8]) -> Result<H3Settings, String> {
    H3Settings::decode_payload(data).map_err(|err| format!("SETTINGS decode failed: {err}"))
}

fn create_settings_with_datagram(enable: bool) -> Vec<u8> {
    let mut settings = Vec::new();
    H3Settings {
        h3_datagram: Some(enable),
        ..H3Settings::default()
    }
    .encode_payload(&mut settings)
    .expect("SETTINGS_H3_DATAGRAM should encode");
    settings
}

fn create_empty_settings() -> Vec<u8> {
    Vec::new()
}

fn process_datagram_frame(data: &[u8]) -> bool {
    let (frame, consumed) = match H3Frame::decode(data, &H3ConnectionConfig::default()) {
        Ok((frame @ H3Frame::Datagram { .. }, consumed)) if consumed == data.len() => {
            (frame, consumed)
        }
        _ => return false,
    };
    let mut request_stream = H3RequestStreamState::new();
    request_stream
        .on_frame(&H3Frame::Headers(vec![0x80]))
        .is_ok()
        && request_stream.on_frame(&frame).is_ok()
        && consumed == data.len()
}

fn validate_datagram_frame_format(data: &[u8]) -> bool {
    matches!(
        H3Frame::decode(data, &H3ConnectionConfig::default()),
        Ok((H3Frame::Datagram { .. }, consumed)) if consumed == data.len()
    )
}

fn calculate_varint_length(value: u64) -> usize {
    if value < 64 {
        1
    } else if value < 16384 {
        2
    } else if value < 1073741824 {
        4
    } else {
        8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_format_results_match_native_support() {
        let results = run_datagram_format_tests();
        assert_eq!(results.len(), 5);

        let expected_failure_ids: Vec<_> = results
            .iter()
            .filter(|result| result.verdict == TestVerdict::ExpectedFailure)
            .map(|result| result.test_id.as_str())
            .collect();
        assert_eq!(expected_failure_ids, vec!["RFC9297-3-DATAGRAM-NEGOTIATION"]);

        for result in results {
            if result.test_id == "RFC9297-3-DATAGRAM-NEGOTIATION" {
                assert_eq!(result.verdict, TestVerdict::ExpectedFailure);
                assert!(
                    result.notes.as_deref().is_some_and(|notes| notes.contains(
                        "H3ConnectionState does not expose peer-negotiated DATAGRAM gating yet"
                    )),
                    "expected negotiation support note, got {:?}",
                    result.notes
                );
            } else {
                assert_eq!(
                    result.verdict,
                    TestVerdict::Pass,
                    "{} failed: {:?}",
                    result.test_id,
                    result.notes
                );
            }
        }
    }
}
