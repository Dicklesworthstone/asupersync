//! HTTP/3 RFC 9114 Section 8 GOAWAY semantics conformance tests.
//!
//! Tests compliance with RFC 9114 GOAWAY frame requirements:
//! - Last-stream-ID validity
//! - Immediate vs graceful shutdown semantics
//! - Connection closure and cleanup behavior

use super::*;
use asupersync::http::h3_native::{
    H3ConnectionConfig, H3ConnectionState, H3Frame, H3NativeError, H3Settings,
};

/// Run all GOAWAY semantics conformance tests.
#[allow(dead_code)]
pub fn run_goaway_tests() -> Vec<H3ConformanceResult> {
    let mut results = Vec::new();

    results.push(test_goaway_last_stream_id_validity());
    results.push(test_goaway_graceful_shutdown());
    results.push(test_goaway_immediate_shutdown());
    results.push(test_goaway_bidirectional_behavior());
    results.push(test_goaway_error_handling());

    results
}

#[test]
fn goaway_results_match_native_support() {
    let results = run_goaway_tests();

    assert_eq!(
        results.len(),
        5,
        "GOAWAY suite should keep every registered result guarded"
    );
    for result in results {
        if result.test_id == "RFC9114-8.1-GOAWAY-BIDIRECTIONAL" {
            assert_eq!(
                result.verdict,
                TestVerdict::ExpectedFailure,
                "{} should remain documented until combined transport lifecycle support lands: {:?}",
                result.test_id,
                result.notes
            );
        } else {
            assert_eq!(
                result.verdict,
                TestVerdict::Pass,
                "{} should pass: {:?}",
                result.test_id,
                result.notes
            );
        }
    }
}

/// RFC 9114 Section 8.1: GOAWAY last-stream-ID validity.
#[allow(dead_code)]
fn test_goaway_last_stream_id_validity() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        let valid_goaway_cases = [
            (12u64, "allow streams below 12"),
            (8u64, "allow streams below 8"),
            (4u64, "allow streams below 4"),
            (0u64, "reject all request streams"),
        ];

        for (last_stream_id, description) in valid_goaway_cases {
            let mut connection = client_connection_with_settings()?;
            process_wire_goaway(&mut connection, last_stream_id, description)?;

            for stream_id in [0, 4, 8, 12] {
                if stream_id < last_stream_id {
                    expect_request_stream_allowed(&mut connection, stream_id, description)?;
                } else {
                    expect_request_stream_rejected_after_goaway(
                        &mut connection,
                        stream_id,
                        description,
                    )?;
                }
            }
        }

        let invalid_cases = [
            (1u64, "server-initiated bidirectional stream ID"),
            (2u64, "client-initiated unidirectional stream ID"),
            (3u64, "server-initiated unidirectional stream ID"),
            (5u64, "server-initiated bidirectional stream ID above 4"),
        ];

        for (invalid_stream_id, description) in invalid_cases {
            let mut connection = client_connection_with_settings()?;
            let frame = decode_exact_frame(&encode_goaway_frame(invalid_stream_id)?)?;
            expect_control_protocol(
                connection.on_control_frame(&frame),
                "GOAWAY id must be a client-initiated bidirectional stream id",
                description,
            )?;
        }

        Ok(())
    });

    conformance_result(
        "RFC9114-8.1-GOAWAY-STREAM-ID",
        "GOAWAY last-stream-ID validity validation",
        result,
        elapsed_ms,
        None,
    )
}

/// RFC 9114 Section 8.1: GOAWAY graceful shutdown.
#[allow(dead_code)]
fn test_goaway_graceful_shutdown() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        let mut connection = client_connection_with_settings()?;

        expect_request_stream_allowed(&mut connection, 0, "pre-GOAWAY in-flight stream 0")?;
        expect_request_stream_allowed(&mut connection, 4, "pre-GOAWAY in-flight stream 4")?;

        process_wire_goaway(&mut connection, 8, "graceful cutoff at stream 8")?;

        connection
            .on_request_stream_frame(4, &H3Frame::Data(b"in-flight body".to_vec()))
            .map_err(|err| {
                format!("in-flight stream below GOAWAY cutoff should continue: {err}")
            })?;

        connection
            .finish_request_stream(0)
            .map_err(|err| format!("in-flight stream 0 should finish after GOAWAY: {err}"))?;
        connection
            .finish_request_stream(4)
            .map_err(|err| format!("in-flight stream 4 should finish after GOAWAY: {err}"))?;

        if connection.active_request_stream_count() != 0 {
            return Err(format!(
                "finished streams should be removed from live state, got {} active",
                connection.active_request_stream_count()
            ));
        }

        expect_request_stream_rejected_after_goaway(
            &mut connection,
            8,
            "new stream at GOAWAY cutoff",
        )?;
        expect_request_stream_rejected_after_goaway(
            &mut connection,
            12,
            "new stream above GOAWAY cutoff",
        )?;

        Ok(())
    });

    conformance_result(
        "RFC9114-8.1-GOAWAY-GRACEFUL",
        "GOAWAY graceful shutdown stream cutoff and in-flight completion",
        result,
        elapsed_ms,
        Some(
            "Verified native stream cutoff and in-flight completion; transport-driven connection close timing is outside H3ConnectionState.",
        ),
    )
}

/// RFC 9114 Section 8.1: GOAWAY immediate shutdown.
#[allow(dead_code)]
fn test_goaway_immediate_shutdown() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        let mut connection = client_connection_with_settings()?;
        process_wire_goaway(&mut connection, 0, "immediate cutoff at stream 0")?;

        for stream_id in [0, 4, 8, 12] {
            expect_request_stream_rejected_after_goaway(
                &mut connection,
                stream_id,
                "GOAWAY(0) immediate cutoff",
            )?;
        }

        Ok(())
    });

    conformance_result(
        "RFC9114-8.1-GOAWAY-IMMEDIATE",
        "GOAWAY(0) rejects all request streams through native state",
        result,
        elapsed_ms,
        Some(
            "GOAWAY(0) stream admission is verified; closing the QUIC connection is a transport lifecycle outside this mapping state.",
        ),
    )
}

/// RFC 9114 Section 8.1: GOAWAY bidirectional behavior.
#[allow(dead_code)]
fn test_goaway_bidirectional_behavior() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        let mut client = client_connection_with_settings()?;
        process_wire_goaway(&mut client, 8, "server-to-client GOAWAY")?;
        expect_request_stream_allowed(&mut client, 4, "client stream below server GOAWAY")?;
        expect_request_stream_rejected_after_goaway(
            &mut client,
            8,
            "client stream at server GOAWAY",
        )?;

        let mut server = H3ConnectionState::new_server();
        receive_peer_settings(&mut server)?;
        process_wire_goaway(&mut server, 7, "client-to-server push-id GOAWAY")?;
        if server.goaway_id() != Some(7) {
            return Err(format!(
                "server role should record client GOAWAY push ID 7, got {:?}",
                server.goaway_id()
            ));
        }
        expect_request_stream_allowed(
            &mut server,
            8,
            "server role should not apply push-id GOAWAY to request stream IDs",
        )?;

        Ok(())
    });

    let (verdict, notes) = match result {
        Ok(()) => (
            TestVerdict::ExpectedFailure,
            Some(
                "Native state verifies per-endpoint received GOAWAY behavior; combined two-endpoint graceful-close lifecycle is not represented without transport integration."
                    .to_string(),
            ),
        ),
        Err(err) => (TestVerdict::Fail, Some(err)),
    };

    H3ConformanceResult {
        test_id: "RFC9114-8.1-GOAWAY-BIDIRECTIONAL".to_string(),
        description: "GOAWAY bidirectional behavior validation".to_string(),
        category: TestCategory::ControlStream,
        requirement_level: RequirementLevel::Must,
        verdict,
        elapsed_ms,
        notes,
    }
}

/// RFC 9114 Section 8: GOAWAY error handling.
#[allow(dead_code)]
fn test_goaway_error_handling() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        let malformed_frames: [(&[u8], &str); 3] = [
            (&[], "empty GOAWAY frame"),
            (&[0x07], "GOAWAY frame without length"),
            (&[0x07, 0x02, 0xFF], "truncated GOAWAY stream ID varint"),
        ];

        for (malformed_data, description) in malformed_frames {
            expect_decode_error(malformed_data, description)?;
        }

        let mut connection = client_connection_with_settings()?;
        process_wire_goaway(&mut connection, 12, "first GOAWAY")?;
        process_wire_goaway(&mut connection, 8, "smaller second GOAWAY")?;
        if connection.goaway_id() != Some(8) {
            return Err(format!(
                "smaller GOAWAY ID should replace prior value, got {:?}",
                connection.goaway_id()
            ));
        }
        expect_request_stream_allowed(&mut connection, 4, "stream below smaller GOAWAY")?;
        expect_request_stream_rejected_after_goaway(
            &mut connection,
            8,
            "stream at smaller GOAWAY",
        )?;

        expect_control_protocol(
            connection.on_control_frame(&H3Frame::Goaway(12)),
            "GOAWAY id must not increase",
            "increasing GOAWAY ID",
        )?;

        let mut future_cutoff = client_connection_with_settings()?;
        process_wire_goaway(&mut future_cutoff, 16, "future GOAWAY stream ID")?;
        expect_request_stream_allowed(&mut future_cutoff, 12, "new stream below future GOAWAY ID")?;
        expect_request_stream_rejected_after_goaway(
            &mut future_cutoff,
            16,
            "new stream at future GOAWAY ID",
        )?;

        Ok(())
    });

    conformance_result(
        "RFC9114-8-GOAWAY-ERROR-HANDLING",
        "GOAWAY error handling and edge cases",
        result,
        elapsed_ms,
        None,
    )
}

fn conformance_result(
    test_id: &str,
    description: &str,
    result: Result<(), String>,
    elapsed_ms: u64,
    pass_notes: Option<&str>,
) -> H3ConformanceResult {
    H3ConformanceResult {
        test_id: test_id.to_string(),
        description: description.to_string(),
        category: TestCategory::ControlStream,
        requirement_level: RequirementLevel::Must,
        verdict: if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        },
        elapsed_ms,
        notes: match result {
            Ok(()) => pass_notes.map(str::to_string),
            Err(err) => Some(err),
        },
    }
}

fn client_connection_with_settings() -> Result<H3ConnectionState, String> {
    let mut connection = H3ConnectionState::new_client();
    receive_peer_settings(&mut connection)?;
    Ok(connection)
}

fn receive_peer_settings(connection: &mut H3ConnectionState) -> Result<(), String> {
    connection
        .on_control_frame(&H3Frame::Settings(H3Settings::default()))
        .map_err(|err| format!("initial peer SETTINGS rejected: {err}"))
}

fn process_wire_goaway(
    connection: &mut H3ConnectionState,
    goaway_id: u64,
    context: &str,
) -> Result<(), String> {
    let encoded = encode_goaway_frame(goaway_id)?;
    let frame = decode_exact_frame(&encoded)?;
    connection
        .on_control_frame(&frame)
        .map_err(|err| format!("GOAWAY {goaway_id} rejected for {context}: {err}"))?;
    if connection.goaway_id() != Some(goaway_id) {
        return Err(format!(
            "GOAWAY {goaway_id} should be recorded for {context}, got {:?}",
            connection.goaway_id()
        ));
    }
    Ok(())
}

fn encode_goaway_frame(goaway_id: u64) -> Result<Vec<u8>, String> {
    let mut encoded = Vec::new();
    H3Frame::Goaway(goaway_id)
        .encode(&mut encoded)
        .map_err(|err| format!("GOAWAY {goaway_id} encode failed: {err}"))?;
    Ok(encoded)
}

fn decode_exact_frame(encoded: &[u8]) -> Result<H3Frame, String> {
    let (frame, consumed) = H3Frame::decode(encoded, &H3ConnectionConfig::default())
        .map_err(|err| format!("H3 frame decode failed: {err}"))?;
    if consumed != encoded.len() {
        return Err(format!(
            "H3 frame decode consumed {consumed} bytes from {} byte input",
            encoded.len()
        ));
    }
    Ok(frame)
}

fn expect_decode_error(data: &[u8], context: &str) -> Result<(), String> {
    match H3Frame::decode(data, &H3ConnectionConfig::default()) {
        Err(H3NativeError::InvalidFrame(_)) | Err(H3NativeError::UnexpectedEof) => Ok(()),
        Err(err) => Err(format!(
            "{context}: expected malformed GOAWAY decode error, got {err:?}"
        )),
        Ok((frame, _)) => Err(format!(
            "{context}: malformed GOAWAY bytes decoded as {frame:?}"
        )),
    }
}

fn expect_request_stream_allowed(
    connection: &mut H3ConnectionState,
    stream_id: u64,
    context: &str,
) -> Result<(), String> {
    connection
        .on_request_stream_frame(stream_id, &H3Frame::Headers(vec![0x80]))
        .map_err(|err| format!("stream {stream_id} should be allowed for {context}: {err}"))
}

fn expect_request_stream_rejected_after_goaway(
    connection: &mut H3ConnectionState,
    stream_id: u64,
    context: &str,
) -> Result<(), String> {
    expect_control_protocol(
        connection.on_request_stream_frame(stream_id, &H3Frame::Headers(vec![0x80])),
        "request stream id rejected after GOAWAY",
        &format!("stream {stream_id} for {context}"),
    )
}

fn expect_control_protocol(
    result: Result<(), H3NativeError>,
    expected: &'static str,
    context: &str,
) -> Result<(), String> {
    match result {
        Err(H3NativeError::ControlProtocol(msg)) if msg == expected => Ok(()),
        Err(err) => Err(format!(
            "{context}: expected control protocol error {expected:?}, got {err:?}"
        )),
        Ok(()) => Err(format!(
            "{context}: expected control protocol error {expected:?}, got acceptance"
        )),
    }
}
