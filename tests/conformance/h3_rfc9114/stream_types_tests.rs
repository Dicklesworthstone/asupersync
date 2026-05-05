//! HTTP/3 RFC 9114 Section 6.2 stream type validation conformance tests.
//!
//! Tests compliance with HTTP/3 unidirectional stream type requirements:
//! - Stream type must be the FIRST varint on unidirectional streams
//! - Proper rejection of non-first or wrong-type stream indicators

use super::*;
use asupersync::http::h3_native::{
    H3ConnectionState, H3Frame, H3NativeError, H3Settings, H3UniStreamType,
};
use asupersync::net::quic_core::{decode_varint, encode_varint};

const STREAM_TYPE_CONTROL: u64 = 0x00;
const STREAM_TYPE_PUSH: u64 = 0x01;
const STREAM_TYPE_QPACK_ENCODER: u64 = 0x02;
const STREAM_TYPE_QPACK_DECODER: u64 = 0x03;

/// Run all stream type validation conformance tests.
#[allow(dead_code)]
pub fn run_stream_type_tests() -> Vec<H3ConformanceResult> {
    let mut results = Vec::new();

    results.push(test_stream_type_first_varint());
    results.push(test_invalid_stream_type_rejection());
    results.push(test_duplicate_stream_type_rejection());
    results.push(test_stream_type_ordering());
    results.push(test_reserved_stream_types());

    results
}

#[test]
fn stream_type_results_pass() {
    let results = run_stream_type_tests();

    assert_eq!(
        results.len(),
        5,
        "stream type suite should keep every registered result guarded"
    );
    for result in results {
        assert_eq!(
            result.verdict,
            TestVerdict::Pass,
            "{} should pass: {:?}",
            result.test_id,
            result.notes
        );
    }
}

/// RFC 9114 Section 6.2: Stream type must be first varint.
#[allow(dead_code)]
fn test_stream_type_first_varint() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        let valid_stream_types = [
            (
                STREAM_TYPE_CONTROL,
                H3UniStreamType::Control,
                "control stream",
            ),
            (STREAM_TYPE_PUSH, H3UniStreamType::Push, "push stream"),
            (
                STREAM_TYPE_QPACK_ENCODER,
                H3UniStreamType::QpackEncoder,
                "QPACK encoder stream",
            ),
            (
                STREAM_TYPE_QPACK_DECODER,
                H3UniStreamType::QpackDecoder,
                "QPACK decoder stream",
            ),
        ];

        for (raw_type, expected_kind, description) in valid_stream_types {
            let stream_data = encode_stream_type_prefix(raw_type)?;
            let (actual_kind, consumed) = decode_first_stream_type(&stream_data)?;
            if actual_kind != expected_kind {
                return Err(format!(
                    "{description}: decoded kind mismatch, expected {expected_kind:?}, got {actual_kind:?}"
                ));
            }
            if consumed != stream_data.len() {
                return Err(format!(
                    "{description}: stream type varint consumed {consumed} bytes from {} byte input",
                    stream_data.len()
                ));
            }
        }

        let prefixed_data = {
            let mut data = encode_stream_type_prefix(STREAM_TYPE_CONTROL)?;
            data.extend_from_slice(b"payload-after-type");
            data
        };
        let (kind, consumed) = decode_first_stream_type(&prefixed_data)?;
        if kind != H3UniStreamType::Control {
            return Err(format!("control prefix decoded as {kind:?}"));
        }
        if consumed != 1 {
            return Err(format!(
                "first stream-type varint should consume exactly one byte, got {consumed}"
            ));
        }

        let truncated_varints: [(&[u8], &str); 2] = [
            (&[0x40], "truncated two-byte stream type varint"),
            (
                &[0x80, 0x00, 0x00],
                "truncated four-byte stream type varint",
            ),
        ];

        for (data, description) in truncated_varints {
            expect_varint_decode_error(data, description)?;
        }

        Ok(())
    });

    conformance_result(
        "RFC9114-6.2-STREAM-TYPE-FIRST",
        "Stream type must be first varint on unidirectional streams",
        RequirementLevel::Must,
        result,
        elapsed_ms,
    )
}

/// RFC 9114 Section 6.2: Unknown stream types are ignored.
#[allow(dead_code)]
fn test_invalid_stream_type_rejection() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        let unknown_types = [
            (0x04, "undefined stream type 0x04"),
            (0x05, "undefined stream type 0x05"),
            (0xFF, "undefined stream type 0xFF"),
            (0x1000, "large undefined stream type"),
            (0xFFFF_FFFF, "maximum undefined stream type"),
        ];

        let mut connection = H3ConnectionState::new_client();
        let mut stream_id = 3;
        for (raw_type, description) in unknown_types {
            let kind =
                register_remote_uni_stream(&mut connection, stream_id, raw_type, description)?;
            if kind != H3UniStreamType::Unknown(raw_type) {
                return Err(format!(
                    "{description}: expected Unknown({raw_type}), got {kind:?}"
                ));
            }
            connection
                .on_uni_stream_frame(stream_id, &H3Frame::Data(vec![1, 2, 3]))
                .map_err(|err| {
                    format!("{description}: unknown stream data should be ignored: {err}")
                })?;
            stream_id += 4;
        }

        Ok(())
    });

    conformance_result(
        "RFC9114-6.2-UNKNOWN-TYPE-IGNORE",
        "Unknown stream types must be accepted and ignored",
        RequirementLevel::Must,
        result,
        elapsed_ms,
    )
}

/// RFC 9114 Section 6.2: Duplicate stream types must be rejected.
#[allow(dead_code)]
fn test_duplicate_stream_type_rejection() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        let mut connection = H3ConnectionState::new_client();
        register_remote_uni_stream(
            &mut connection,
            3,
            STREAM_TYPE_CONTROL,
            "first control stream",
        )?;
        register_remote_uni_stream(
            &mut connection,
            7,
            STREAM_TYPE_QPACK_ENCODER,
            "first QPACK encoder stream",
        )?;
        register_remote_uni_stream(
            &mut connection,
            11,
            STREAM_TYPE_QPACK_DECODER,
            "first QPACK decoder stream",
        )?;

        expect_control_protocol(
            connection.on_remote_uni_stream_type(15, STREAM_TYPE_CONTROL),
            "duplicate remote control stream",
            "duplicate control stream",
        )?;
        expect_stream_protocol(
            connection.on_remote_uni_stream_type(19, STREAM_TYPE_QPACK_ENCODER),
            "duplicate remote qpack encoder stream",
            "duplicate QPACK encoder stream",
        )?;
        expect_stream_protocol(
            connection.on_remote_uni_stream_type(23, STREAM_TYPE_QPACK_DECODER),
            "duplicate remote qpack decoder stream",
            "duplicate QPACK decoder stream",
        )?;

        register_remote_uni_stream(&mut connection, 27, STREAM_TYPE_PUSH, "first push stream")?;
        register_remote_uni_stream(&mut connection, 31, STREAM_TYPE_PUSH, "second push stream")?;

        Ok(())
    });

    conformance_result(
        "RFC9114-6.2-DUPLICATE-REJECT",
        "Duplicate control and QPACK stream types must be rejected",
        RequirementLevel::Must,
        result,
        elapsed_ms,
    )
}

/// RFC 9114 Section 6.2: Stream type ordering and creation rules.
#[allow(dead_code)]
fn test_stream_type_ordering() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        let mut connection = H3ConnectionState::new_client();

        expect_stream_protocol(
            connection.on_remote_uni_stream_type(0, STREAM_TYPE_CONTROL),
            "unidirectional stream type requires unidirectional stream id",
            "bidirectional stream cannot carry stream type",
        )?;
        expect_stream_protocol(
            connection.on_uni_stream_frame(3, &H3Frame::Settings(H3Settings::default())),
            "unknown unidirectional stream",
            "frame before stream type registration",
        )?;

        register_remote_uni_stream(&mut connection, 3, STREAM_TYPE_CONTROL, "control stream")?;
        connection
            .on_uni_stream_frame(3, &H3Frame::Settings(H3Settings::default()))
            .map_err(|err| format!("control stream SETTINGS should be accepted: {err}"))?;

        register_remote_uni_stream(
            &mut connection,
            7,
            STREAM_TYPE_QPACK_ENCODER,
            "QPACK encoder stream",
        )?;
        expect_stream_protocol(
            connection.on_uni_stream_frame(7, &H3Frame::Data(vec![1])),
            "qpack streams carry instructions, not h3 frames",
            "QPACK encoder stream cannot carry H3 DATA frames",
        )?;

        register_remote_uni_stream(&mut connection, 11, STREAM_TYPE_PUSH, "push stream")?;
        expect_stream_protocol(
            connection.on_uni_stream_frame(11, &H3Frame::Headers(vec![0x80])),
            "push stream missing push id",
            "push stream frame before push header",
        )?;
        connection
            .on_push_stream_header(11, 7)
            .map_err(|err| format!("push stream header should be accepted: {err}"))?;
        connection
            .on_uni_stream_frame(11, &H3Frame::Headers(vec![0x80]))
            .map_err(|err| format!("push response HEADERS should be accepted: {err}"))?;
        connection
            .on_uni_stream_frame(11, &H3Frame::Data(vec![1, 2]))
            .map_err(|err| format!("push response DATA should be accepted: {err}"))?;

        Ok(())
    });

    conformance_result(
        "RFC9114-6.2-STREAM-ORDERING",
        "Stream type registration and frame routing validation",
        RequirementLevel::Must,
        result,
        elapsed_ms,
    )
}

/// RFC 9114 Section 6.2: Reserved stream types handling.
#[allow(dead_code)]
fn test_reserved_stream_types() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        let reserved_types = [
            (0x04, "first reserved type"),
            (0x08, "reserved type 0x08"),
            (0x0F, "reserved type 0x0F"),
            (0x21, "GREASE reserved type"),
        ];

        let mut connection = H3ConnectionState::new_client();
        let mut stream_id = 3;
        for (reserved_type, description) in reserved_types {
            let encoded = encode_stream_type_prefix(reserved_type)?;
            let (decoded, consumed) = decode_first_stream_type(&encoded)?;
            if decoded != H3UniStreamType::Unknown(reserved_type) {
                return Err(format!(
                    "{description}: reserved type decoded as {decoded:?}"
                ));
            }
            if consumed != encoded.len() {
                return Err(format!(
                    "{description}: stream-type varint consumed {consumed} bytes from {} byte input",
                    encoded.len()
                ));
            }

            register_remote_uni_stream(&mut connection, stream_id, reserved_type, description)?;
            connection
                .on_uni_stream_frame(stream_id, &H3Frame::Data(vec![0xAA]))
                .map_err(|err| {
                    format!("{description}: reserved stream payload should be ignored: {err}")
                })?;
            stream_id += 4;
        }

        Ok(())
    });

    conformance_result(
        "RFC9114-6.2-RESERVED-TYPES",
        "Reserved stream types handling validation",
        RequirementLevel::Should,
        result,
        elapsed_ms,
    )
}

fn conformance_result(
    test_id: &str,
    description: &str,
    requirement_level: RequirementLevel,
    result: Result<(), String>,
    elapsed_ms: u64,
) -> H3ConformanceResult {
    H3ConformanceResult {
        test_id: test_id.to_string(),
        description: description.to_string(),
        category: TestCategory::StreamTypes,
        requirement_level,
        verdict: if result.is_ok() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail
        },
        elapsed_ms,
        notes: result.err(),
    }
}

fn encode_stream_type_prefix(stream_type: u64) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    encode_varint(stream_type, &mut data)
        .map_err(|err| format!("stream type {stream_type:#x} encode failed: {err}"))?;
    Ok(data)
}

fn decode_first_stream_type(stream_data: &[u8]) -> Result<(H3UniStreamType, usize), String> {
    let (raw_type, consumed) = decode_varint(stream_data)
        .map_err(|err| format!("stream type varint decode failed: {err}"))?;
    Ok((H3UniStreamType::decode(raw_type), consumed))
}

fn expect_varint_decode_error(data: &[u8], context: &str) -> Result<(), String> {
    match decode_varint(data) {
        Err(_) => Ok(()),
        Ok((value, consumed)) => Err(format!(
            "{context}: expected decode failure, got value {value:#x} consuming {consumed} bytes"
        )),
    }
}

fn register_remote_uni_stream(
    connection: &mut H3ConnectionState,
    stream_id: u64,
    stream_type: u64,
    context: &str,
) -> Result<H3UniStreamType, String> {
    connection
        .on_remote_uni_stream_type(stream_id, stream_type)
        .map_err(|err| {
            format!(
                "{context}: stream {stream_id} type {stream_type:#x} registration failed: {err}"
            )
        })
}

fn expect_stream_protocol<T>(
    result: Result<T, H3NativeError>,
    expected: &'static str,
    context: &str,
) -> Result<(), String> {
    match result {
        Err(H3NativeError::StreamProtocol(msg)) if msg == expected => Ok(()),
        Err(err) => Err(format!(
            "{context}: expected stream protocol error {expected:?}, got {err:?}"
        )),
        Ok(_) => Err(format!(
            "{context}: expected stream protocol error {expected:?}, got acceptance"
        )),
    }
}

fn expect_control_protocol<T>(
    result: Result<T, H3NativeError>,
    expected: &'static str,
    context: &str,
) -> Result<(), String> {
    match result {
        Err(H3NativeError::ControlProtocol(msg)) if msg == expected => Ok(()),
        Err(err) => Err(format!(
            "{context}: expected control protocol error {expected:?}, got {err:?}"
        )),
        Ok(_) => Err(format!(
            "{context}: expected control protocol error {expected:?}, got acceptance"
        )),
    }
}
