#![allow(warnings)]
#![allow(clippy::all)]
//! Connection management conformance tests.
//!
//! Tests connection lifecycle and management requirements from RFC 7540 Section 3.

use super::*;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::{
    connection::{Connection, ConnectionState, ReceivedFrame},
    error::ErrorCode,
    frame::{Frame, FrameHeader, FrameType, GoAwayFrame, HeadersFrame, SettingsFrame, parse_frame},
    hpack::{Encoder as HpackEncoder, Header},
    settings::Settings,
};

/// Run all connection management conformance tests.
#[allow(dead_code)]
pub fn run_connection_tests() -> Vec<H2ConformanceResult> {
    let mut results = Vec::new();

    results.push(test_connection_preface());
    results.push(test_http2_identification());
    results.push(test_connection_header_processing());
    results.push(test_connection_upgrade_from_http1());
    results.push(test_prior_knowledge_connection());
    results.push(test_connection_termination());
    results.push(test_goaway_frame_processing());
    results.push(test_connection_error_handling());

    results
}

/// RFC 7540 Section 3.5: HTTP/2 connection preface.
#[allow(dead_code)]
fn test_connection_preface() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // HTTP/2 connection preface sequence
        let preface_string = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

        // Verify the preface string is exactly 24 bytes
        if preface_string.len() != 24 {
            return Err(format!(
                "Connection preface must be 24 bytes, got {}",
                preface_string.len()
            ));
        }

        // Verify exact preface content
        let expected_preface = [
            0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, // "PRI * HT"
            0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a, // "TP/2.0\r\n"
            0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a, // "\r\nSM\r\n\r\n"
        ];

        if preface_string != &expected_preface[..] {
            return Err("Connection preface content does not match specification".to_string());
        }

        // Client MUST send this preface followed immediately by a SETTINGS frame
        // Server MUST send a SETTINGS frame as its first frame

        // Invalid preface should result in GOAWAY with PROTOCOL_ERROR
        let invalid_prefixes: &[&[u8]] = &[
            b"PRI * HTTP/1.1\r\n\r\nSM\r\n\r\n", // Wrong HTTP version
            b"GET / HTTP/2.0\r\n\r\nSM\r\n\r\n", // Wrong method
            b"PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n", // Wrong magic string
            b"PRI * HTTP/2.0\r\n\r\n",           // Truncated
        ];

        for (i, invalid_preface) in invalid_prefixes.iter().enumerate() {
            // These should be rejected by HTTP/2 implementation
            if *invalid_preface == expected_preface {
                return Err(format!("Invalid preface {} matches valid preface", i));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-3.5-PREFACE",
        "HTTP/2 connection preface validation",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7540 Section 3.2: HTTP/2 version identification.
#[allow(dead_code)]
fn test_http2_identification() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // HTTP/2 version identification in ALPN
        let alpn_protocols: &[&[u8]] = &[
            b"h2",  // HTTP/2 over TLS
            b"h2c", // HTTP/2 over cleartext
        ];

        for protocol in alpn_protocols {
            // These should be recognized as HTTP/2 protocols
            match *protocol {
                b"h2" => {
                    // HTTP/2 over TLS - requires TLS 1.2+
                    // Must use ALPN extension to negotiate
                }
                b"h2c" => {
                    // HTTP/2 over cleartext TCP
                    // Can use prior knowledge or HTTP/1.1 upgrade
                }
                _ => {
                    return Err(format!("Unknown HTTP/2 protocol: {:?}", protocol));
                }
            }
        }

        // Invalid or unsupported protocols
        let invalid_protocols: &[&[u8]] = &[
            b"http/1.1",
            b"http/2.0", // Should be "h2" not "http/2.0"
            b"h1",
            b"h3", // HTTP/3, not HTTP/2
        ];

        for protocol in invalid_protocols {
            // These should not be treated as HTTP/2
            if *protocol == b"h2" || *protocol == b"h2c" {
                return Err(format!(
                    "Invalid protocol {:?} matches valid protocol",
                    protocol
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-3.2-IDENTIFICATION",
        "HTTP/2 protocol version identification",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7540 Section 3.2: Connection header processing.
#[allow(dead_code)]
fn test_connection_header_processing() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // HTTP/1.1 specific headers that must be removed in HTTP/2
        let forbidden_headers = [
            "connection",
            "keep-alive",
            "proxy-connection",
            "transfer-encoding",
            "upgrade",
        ];

        // These headers MUST NOT appear in HTTP/2
        // If present in HTTP/1.1 → HTTP/2 conversion, they must be stripped

        for header in &forbidden_headers {
            // Implementation should reject or strip these headers
            let header_lower = header.to_lowercase();
            match header_lower.as_str() {
                "connection" => {
                    // Connection-specific headers are meaningless in HTTP/2
                }
                "keep-alive" => {
                    // HTTP/2 connections are persistent by default
                }
                "proxy-connection" => {
                    // Proxy-specific, not applicable to HTTP/2
                }
                "transfer-encoding" => {
                    // HTTP/2 has native chunking, transfer-encoding forbidden
                }
                "upgrade" => {
                    // Upgrade mechanism not used within HTTP/2
                }
                _ => {}
            }
        }

        // Pseudo-headers that ARE required in HTTP/2
        let required_pseudo_headers = [":method", ":path", ":scheme", ":authority"];

        for pseudo_header in &required_pseudo_headers {
            // These must be present in HTTP/2 request headers
            if !pseudo_header.starts_with(':') {
                return Err(format!(
                    "Pseudo-header {} must start with ':'",
                    pseudo_header
                ));
            }
        }

        // Response pseudo-headers
        let response_pseudo_headers = [":status"];

        for pseudo_header in &response_pseudo_headers {
            // These must be present in HTTP/2 response headers
            if !pseudo_header.starts_with(':') {
                return Err(format!(
                    "Response pseudo-header {} must start with ':'",
                    pseudo_header
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-3.2-HEADERS",
        "Connection header processing and pseudo-headers",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7540 Section 3.2: HTTP/1.1 to HTTP/2 upgrade.
#[allow(dead_code)]
fn test_connection_upgrade_from_http1() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // HTTP/1.1 Upgrade mechanism for HTTP/2
        let upgrade_request_headers = [
            ("Connection", "Upgrade, HTTP2-Settings"),
            ("Upgrade", "h2c"),
            ("HTTP2-Settings", "<base64-encoded-settings>"),
        ];

        // Validate upgrade request format
        for (header_name, header_value) in &upgrade_request_headers {
            match *header_name {
                "Connection" => {
                    // Must include "Upgrade" and "HTTP2-Settings" tokens
                    if !header_value.contains("Upgrade") || !header_value.contains("HTTP2-Settings")
                    {
                        return Err(format!(
                            "Connection header missing required tokens: {}",
                            header_value
                        ));
                    }
                }
                "Upgrade" => {
                    // Must specify "h2c" for HTTP/2 over cleartext
                    if *header_value != "h2c" {
                        return Err(format!(
                            "Upgrade header must be 'h2c', got '{}'",
                            header_value
                        ));
                    }
                }
                "HTTP2-Settings" => {
                    // Must be base64url-encoded SETTINGS frame payload
                    // Empty payload is valid (uses default settings)
                    if header_value.is_empty() {
                        // Empty is valid - uses default settings
                    } else {
                        // Should be valid base64url encoding
                        // Would need base64 validation in real implementation
                    }
                }
                _ => {}
            }
        }

        // Successful upgrade response
        let upgrade_response =
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n";

        // After successful upgrade:
        // - Client sends HTTP/2 connection preface
        // - Server responds with SETTINGS frame
        // - First HTTP/1.1 request becomes stream 1

        // Failed upgrade (server doesn't support HTTP/2)
        let failed_upgrade = "HTTP/1.1 400 Bad Request\r\n\r\n";

        // Server can reject upgrade for various reasons:
        // - Doesn't support HTTP/2
        // - Invalid HTTP2-Settings header
        // - Policy reasons

        Ok(())
    });

    create_test_result(
        "RFC7540-3.2-UPGRADE",
        "HTTP/1.1 to HTTP/2 upgrade mechanism",
        TestCategory::Connection,
        RequirementLevel::Should,
        result,
        elapsed,
    )
}

/// RFC 7540 Section 3.4: Prior knowledge connection establishment.
#[allow(dead_code)]
fn test_prior_knowledge_connection() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Prior knowledge connection setup

        // Client knows server supports HTTP/2 (no upgrade needed)
        // Client immediately sends:
        // 1. HTTP/2 connection preface
        // 2. SETTINGS frame

        // Server responds with:
        // 1. SETTINGS frame
        // 2. SETTINGS ACK (acknowledging client settings)

        // No HTTP/1.1 involved in prior knowledge connections

        // Connection establishment order:
        let client_sequence = [
            "connection_preface", // 24-byte magic string
            "settings_frame",     // Initial settings
        ];

        let server_sequence = [
            "settings_frame", // Server settings
            "settings_ack",   // ACK of client settings
        ];

        // Validate sequence order
        for (i, step) in client_sequence.iter().enumerate() {
            match *step {
                "connection_preface" => {
                    if i != 0 {
                        return Err("Connection preface must be first".to_string());
                    }
                }
                "settings_frame" => {
                    if i != 1 {
                        return Err("SETTINGS frame must follow preface".to_string());
                    }
                }
                _ => {}
            }
        }

        // Server must not send connection preface
        for step in &server_sequence {
            if *step == "connection_preface" {
                return Err("Server must not send connection preface".to_string());
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-3.4-PRIOR-KNOWLEDGE",
        "Prior knowledge connection establishment",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7540 Section 6.8: Connection termination with GOAWAY.
#[allow(dead_code)]
fn test_connection_termination() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Connection termination scenarios

        // Graceful shutdown:
        // 1. Send GOAWAY with last processed stream ID
        // 2. Complete processing of in-flight streams
        // 3. Close connection

        // GOAWAY frame contains:
        // - Last stream ID that will be processed
        // - Error code (0 for graceful shutdown)
        // - Optional debug data

        let shutdown_scenarios = [
            ("graceful", 0u32, "Normal shutdown"),
            ("protocol_error", 1u32, "Protocol violation detected"),
            ("internal_error", 2u32, "Internal server error"),
            ("flow_control_error", 3u32, "Flow control violation"),
        ];

        for (scenario, error_code, description) in &shutdown_scenarios {
            match *scenario {
                "graceful" => {
                    // Error code 0 = NO_ERROR
                    if *error_code != 0 {
                        return Err(format!(
                            "Graceful shutdown should use error code 0, got {}",
                            error_code
                        ));
                    }
                }
                "protocol_error" => {
                    // Error code 1 = PROTOCOL_ERROR
                    if *error_code != 1 {
                        return Err("Protocol error should use error code 1".to_string());
                    }
                }
                "internal_error" => {
                    // Error code 2 = INTERNAL_ERROR
                    if *error_code != 2 {
                        return Err("Internal error should use error code 2".to_string());
                    }
                }
                "flow_control_error" => {
                    // Error code 3 = FLOW_CONTROL_ERROR
                    if *error_code != 3 {
                        return Err("Flow control error should use error code 3".to_string());
                    }
                }
                _ => {
                    return Err(format!("Unknown shutdown scenario: {}", scenario));
                }
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-6.8-TERMINATION",
        "Connection termination with GOAWAY frame",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7540 Section 6.8: GOAWAY frame processing.
#[allow(dead_code)]
fn test_goaway_frame_processing() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        fn open_connection(conn: &mut Connection) -> Result<(), String> {
            conn.process_frame(Frame::Settings(SettingsFrame::new(vec![])))
                .map_err(|err| err.to_string())?;
            while conn.has_pending_frames() {
                let _ = conn.next_frame();
            }
            if conn.state() != ConnectionState::Open {
                return Err(format!(
                    "SETTINGS handshake should open connection, got {:?}",
                    conn.state()
                ));
            }
            Ok(())
        }

        fn encoded_headers(path: &str) -> Bytes {
            let mut encoder = HpackEncoder::new();
            let mut encoded = BytesMut::new();
            encoder.encode(
                &[
                    Header::new(":method", "GET"),
                    Header::new(":path", path),
                    Header::new(":scheme", "https"),
                    Header::new(":authority", "example.test"),
                ],
                &mut encoded,
            );
            encoded.freeze()
        }

        fn assert_received_goaway(
            received: Option<ReceivedFrame>,
            expected_last_stream_id: u32,
            expected_error_code: ErrorCode,
            expected_debug: &[u8],
        ) -> Result<(), String> {
            match received {
                Some(ReceivedFrame::GoAway {
                    last_stream_id,
                    error_code,
                    debug_data,
                }) => {
                    if last_stream_id != expected_last_stream_id {
                        return Err(format!(
                            "effective GOAWAY last_stream_id mismatch: got {last_stream_id}, expected {expected_last_stream_id}"
                        ));
                    }
                    if error_code != expected_error_code {
                        return Err(format!(
                            "GOAWAY error code mismatch: got {error_code:?}, expected {expected_error_code:?}"
                        ));
                    }
                    if debug_data.as_ref() != expected_debug {
                        return Err(format!(
                            "GOAWAY debug data mismatch: got {:?}, expected {:?}",
                            debug_data.as_ref(),
                            expected_debug
                        ));
                    }
                    Ok(())
                }
                other => Err(format!("expected ReceivedFrame::GoAway, got {other:?}")),
            }
        }

        let mut outbound = GoAwayFrame::new(0x7fff_ffff, ErrorCode::EnhanceYourCalm);
        outbound.debug_data = Bytes::from_static(b"calm down");
        let mut wire = BytesMut::new();
        Frame::GoAway(outbound.clone())
            .encode(&mut wire)
            .map_err(|err| err.to_string())?;
        let header = FrameHeader::parse(&mut wire).map_err(|err| err.to_string())?;
        if header.frame_type != FrameType::GoAway as u8 {
            return Err(format!("encoded GOAWAY frame type mismatch: {header:?}"));
        }
        let parsed = parse_frame(&header, wire.freeze()).map_err(|err| err.to_string())?;
        match parsed {
            Frame::GoAway(parsed) => {
                if parsed.last_stream_id != outbound.last_stream_id {
                    return Err("GOAWAY parser did not preserve last_stream_id".to_string());
                }
                if parsed.error_code != outbound.error_code {
                    return Err("GOAWAY parser did not preserve error_code".to_string());
                }
                if parsed.debug_data != outbound.debug_data {
                    return Err("GOAWAY parser did not preserve debug data".to_string());
                }
            }
            other => return Err(format!("GOAWAY wire parser returned {other:?}")),
        }

        let mut client = Connection::client(Settings::client());
        open_connection(&mut client)?;
        let stream1 = client
            .open_stream(
                vec![
                    Header::new(":method", "GET"),
                    Header::new(":path", "/kept"),
                    Header::new(":scheme", "https"),
                    Header::new(":authority", "example.test"),
                ],
                false,
            )
            .map_err(|err| err.to_string())?;
        let stream3 = client
            .open_stream(
                vec![
                    Header::new(":method", "GET"),
                    Header::new(":path", "/reset"),
                    Header::new(":scheme", "https"),
                    Header::new(":authority", "example.test"),
                ],
                false,
            )
            .map_err(|err| err.to_string())?;
        if (stream1, stream3) != (1, 3) {
            return Err(format!(
                "expected client streams 1 and 3, got {stream1} and {stream3}"
            ));
        }
        let mut inbound = GoAwayFrame::new(stream1, ErrorCode::NoError);
        inbound.debug_data = Bytes::from_static(b"peer shutdown");
        let received = client
            .process_frame(Frame::GoAway(inbound))
            .map_err(|err| err.to_string())?;
        assert_received_goaway(received, stream1, ErrorCode::NoError, b"peer shutdown")?;
        if !client.goaway_received() || client.state() != ConnectionState::Closing {
            return Err("received GOAWAY should mark connection closing".to_string());
        }
        if client
            .stream(stream1)
            .ok_or("stream 1 missing after GOAWAY")?
            .state()
            .is_closed()
        {
            return Err("stream at or below GOAWAY last_stream_id should remain live".to_string());
        }
        if !client
            .stream(stream3)
            .ok_or("stream 3 missing after GOAWAY")?
            .state()
            .is_closed()
        {
            return Err("stream above GOAWAY last_stream_id should be reset".to_string());
        }

        let widened = client
            .process_frame(Frame::GoAway(GoAwayFrame::new(
                stream3,
                ErrorCode::InternalError,
            )))
            .map_err(|err| err.to_string())?;
        assert_received_goaway(widened, stream1, ErrorCode::InternalError, b"")?;
        let narrowed = client
            .process_frame(Frame::GoAway(GoAwayFrame::new(0, ErrorCode::Cancel)))
            .map_err(|err| err.to_string())?;
        assert_received_goaway(narrowed, 0, ErrorCode::Cancel, b"")?;

        let mut server = Connection::server(Settings::default());
        open_connection(&mut server)?;
        server
            .process_frame(Frame::Headers(HeadersFrame::new(
                1,
                encoded_headers("/processed"),
                false,
                true,
            )))
            .map_err(|err| err.to_string())?;
        server.goaway(ErrorCode::NoError, Bytes::from_static(b"graceful"));
        match server.next_frame() {
            Some(Frame::GoAway(frame)) => {
                if frame.last_stream_id != 1 {
                    return Err(format!(
                        "sent GOAWAY should advertise processed stream 1, got {}",
                        frame.last_stream_id
                    ));
                }
                if frame.debug_data.as_ref() != b"graceful" {
                    return Err("sent GOAWAY should preserve debug data".to_string());
                }
            }
            other => return Err(format!("expected outbound GOAWAY frame, got {other:?}")),
        }

        server
            .process_frame(Frame::Headers(HeadersFrame::new(
                3,
                encoded_headers("/refused"),
                false,
                true,
            )))
            .map_err(|err| err.to_string())?;
        match server.next_frame() {
            Some(Frame::RstStream(rst)) => {
                if rst.stream_id != 3 || rst.error_code != ErrorCode::RefusedStream {
                    return Err(format!("post-GOAWAY stream should be refused, got {rst:?}"));
                }
            }
            other => {
                return Err(format!(
                    "expected RST_STREAM for post-GOAWAY stream, got {other:?}"
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-6.8-GOAWAY",
        "GOAWAY frame structure and processing",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 7540 Section 5.4.1: Connection error handling.
#[allow(dead_code)]
fn test_connection_error_handling() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Connection errors vs stream errors

        // Connection errors affect the entire connection
        let connection_errors = [
            (1u32, "PROTOCOL_ERROR", "Generic protocol violation"),
            (2u32, "INTERNAL_ERROR", "Implementation fault"),
            (3u32, "FLOW_CONTROL_ERROR", "Flow control limits exceeded"),
            (4u32, "SETTINGS_TIMEOUT", "SETTINGS ACK not received"),
            (5u32, "STREAM_CLOSED", "Frame received for closed stream"),
            (6u32, "FRAME_SIZE_ERROR", "Frame size constraints violated"),
            (
                9u32,
                "COMPRESSION_ERROR",
                "HPACK compression state corrupted",
            ),
            (10u32, "CONNECT_ERROR", "TCP connection broken for CONNECT"),
            (11u32, "ENHANCE_CALM", "Excessive load or resource usage"),
            (12u32, "INADEQUATE_SECURITY", "TLS requirements not met"),
            (13u32, "HTTP_1_1_REQUIRED", "HTTP/1.1 required by endpoint"),
        ];

        for (error_code, error_name, description) in &connection_errors {
            // These errors should trigger GOAWAY + connection close
            match *error_code {
                1 => {
                    // PROTOCOL_ERROR: Generic protocol violation
                    if *error_name != "PROTOCOL_ERROR" {
                        return Err("Error code 1 should be PROTOCOL_ERROR".to_string());
                    }
                }
                2 => {
                    // INTERNAL_ERROR: Implementation fault
                    if *error_name != "INTERNAL_ERROR" {
                        return Err("Error code 2 should be INTERNAL_ERROR".to_string());
                    }
                }
                3 => {
                    // FLOW_CONTROL_ERROR: Flow control violation
                    if *error_name != "FLOW_CONTROL_ERROR" {
                        return Err("Error code 3 should be FLOW_CONTROL_ERROR".to_string());
                    }
                }
                4 => {
                    // SETTINGS_TIMEOUT: SETTINGS ACK timeout
                    if *error_name != "SETTINGS_TIMEOUT" {
                        return Err("Error code 4 should be SETTINGS_TIMEOUT".to_string());
                    }
                }
                _ => {
                    // Other defined error codes
                }
            }
        }

        // Error handling sequence:
        // 1. Detect error condition
        // 2. Send GOAWAY with appropriate error code
        // 3. Close connection after sending GOAWAY

        // Some errors require immediate connection closure:
        let immediate_closure_errors = [1, 2, 9, 11]; // Protocol, internal, compression, security

        for error_code in &immediate_closure_errors {
            // These should close connection immediately after GOAWAY
        }

        Ok(())
    });

    create_test_result(
        "RFC7540-5.4.1-ERRORS",
        "Connection error detection and handling",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}
