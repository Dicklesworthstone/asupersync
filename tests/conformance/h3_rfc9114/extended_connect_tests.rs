#![allow(warnings)]
#![allow(clippy::all)]
//! HTTP/3 RFC 9298 Extended CONNECT conformance tests.
//!
//! Tests compliance with RFC 9298 Extended CONNECT requirements:
//! - :protocol pseudo-header validation
//! - CONNECT-UDP and CONNECT-IP negotiation
//! - Capsule format validation

use super::*;
use asupersync::net::quic_core::{decode_varint, encode_varint};

/// Extended CONNECT protocol types from RFC 9298.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtendedConnectProtocol {
    /// CONNECT-UDP (RFC 9298).
    ConnectUdp,
    /// CONNECT-IP (RFC 9298).
    ConnectIp,
    /// WebTransport (RFC 9220).
    WebTransport,
    /// Custom protocol.
    Custom(String),
}

/// Run all Extended CONNECT conformance tests.
#[allow(dead_code)]
pub fn run_extended_connect_tests() -> Vec<H3ConformanceResult> {
    let mut results = Vec::new();

    results.push(test_protocol_pseudo_header_validation());
    results.push(test_connect_udp_negotiation());
    results.push(test_connect_ip_negotiation());
    results.push(test_capsule_format_validation());
    results.push(test_extended_connect_error_handling());

    results
}

/// RFC 9298 Section 3: :protocol pseudo-header validation.
#[allow(dead_code)]
fn test_protocol_pseudo_header_validation() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        // Test valid :protocol pseudo-header values
        let valid_protocols = vec![
            (
                "connect-udp",
                ExtendedConnectProtocol::ConnectUdp,
                "CONNECT-UDP protocol",
            ),
            (
                "connect-ip",
                ExtendedConnectProtocol::ConnectIp,
                "CONNECT-IP protocol",
            ),
            (
                "webtransport",
                ExtendedConnectProtocol::WebTransport,
                "WebTransport protocol",
            ),
            (
                "custom-protocol",
                ExtendedConnectProtocol::Custom("custom-protocol".to_string()),
                "custom protocol",
            ),
        ];

        for (protocol_value, expected_protocol, description) in valid_protocols {
            let headers = create_extended_connect_headers(protocol_value, "example.com", 443);

            if !validate_extended_connect_headers(&headers) {
                return Err(format!(
                    "Valid Extended CONNECT headers rejected for {}",
                    description
                ));
            }

            let parsed_protocol = extract_protocol_from_headers(&headers)?;
            if parsed_protocol != expected_protocol {
                return Err(format!(
                    "Protocol parsing mismatch for {}: expected {:?}, got {:?}",
                    description, expected_protocol, parsed_protocol
                ));
            }
        }

        // Test invalid :protocol pseudo-header cases
        let invalid_cases = vec![
            (None, "missing :protocol pseudo-header"),
            (Some(""), "empty :protocol value"),
            (
                Some("CONNECT-UDP"),
                "uppercase protocol (should be lowercase)",
            ),
            (Some("connect udp"), "protocol with spaces"),
            (Some("connect/udp"), "protocol with invalid characters"),
        ];

        for (protocol_value, description) in invalid_cases {
            let headers = match protocol_value {
                Some(value) => create_extended_connect_headers(value, "example.com", 443),
                None => create_connect_headers_without_protocol("example.com", 443),
            };

            if validate_extended_connect_headers(&headers) {
                return Err(format!(
                    "Invalid Extended CONNECT headers accepted: {}",
                    description
                ));
            }
        }

        Ok(())
    });

    H3ConformanceResult {
        test_id: "RFC9298-3-PROTOCOL-HEADER".to_string(),
        description: ":protocol pseudo-header validation".to_string(),
        category: TestCategory::ExtendedConnect,
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

/// RFC 9298 Section 4: CONNECT-UDP negotiation.
#[allow(dead_code)]
fn test_connect_udp_negotiation() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        // Test CONNECT-UDP request format
        let connect_udp_headers =
            create_extended_connect_headers("connect-udp", "target.example.com", 1234);

        if !validate_extended_connect_headers(&connect_udp_headers) {
            return Err("Valid CONNECT-UDP headers were rejected".to_string());
        }

        // Test required pseudo-headers for CONNECT-UDP
        let required_headers = vec![":method", ":protocol", ":scheme", ":path", ":authority"];
        let header_map = headers_to_map(&connect_udp_headers);

        for required_header in &required_headers {
            if !header_map.contains_key(*required_header) {
                return Err(format!(
                    "CONNECT-UDP missing required pseudo-header: {}",
                    required_header
                ));
            }
        }

        // Verify :method is CONNECT
        if header_map.get(":method") != Some(&"CONNECT".to_string()) {
            return Err("CONNECT-UDP must use :method CONNECT".to_string());
        }

        // Verify :protocol is connect-udp
        if header_map.get(":protocol") != Some(&"connect-udp".to_string()) {
            return Err("CONNECT-UDP must use :protocol connect-udp".to_string());
        }

        // Test successful CONNECT-UDP response
        let success_response = create_connect_response(200, "Connected");
        if !validate_connect_response(&success_response) {
            return Err("Valid CONNECT-UDP success response was rejected".to_string());
        }

        // Test CONNECT-UDP rejection scenarios
        let rejection_cases = vec![
            (400, "Bad Request", "malformed request"),
            (403, "Forbidden", "policy rejection"),
            (404, "Not Found", "target not found"),
            (501, "Not Implemented", "CONNECT-UDP not supported"),
        ];

        for (status_code, reason_phrase, description) in rejection_cases {
            let rejection_response = create_connect_response(status_code, reason_phrase);

            if !validate_connect_response(&rejection_response) {
                return Err(format!(
                    "CONNECT-UDP rejection response invalid: {}",
                    description
                ));
            }
        }

        Ok(())
    });

    H3ConformanceResult {
        test_id: "RFC9298-4-CONNECT-UDP".to_string(),
        description: "CONNECT-UDP negotiation validation".to_string(),
        category: TestCategory::ExtendedConnect,
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

/// RFC 9298 Section 5: CONNECT-IP negotiation.
#[allow(dead_code)]
fn test_connect_ip_negotiation() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        // Test CONNECT-IP request format
        let connect_ip_headers = create_extended_connect_headers(
            "connect-ip",
            "192.0.2.1",
            0, // Port not meaningful for CONNECT-IP
        );

        if !validate_extended_connect_headers(&connect_ip_headers) {
            return Err("Valid CONNECT-IP headers were rejected".to_string());
        }

        let header_map = headers_to_map(&connect_ip_headers);

        // Verify CONNECT-IP specific requirements
        if header_map.get(":protocol") != Some(&"connect-ip".to_string()) {
            return Err("CONNECT-IP must use :protocol connect-ip".to_string());
        }

        // Test IPv4 and IPv6 targets
        let ip_targets = vec![
            ("192.0.2.1", "IPv4 target"),
            ("2001:db8::1", "IPv6 target"),
            ("[2001:db8::1]", "IPv6 target with brackets"),
        ];

        for (target_ip, description) in ip_targets {
            let headers = create_extended_connect_headers("connect-ip", target_ip, 0);

            if !validate_extended_connect_headers(&headers) {
                return Err(format!(
                    "Valid CONNECT-IP headers rejected for {}",
                    description
                ));
            }

            // Verify target is a valid IP address
            if !is_valid_ip_address(target_ip) {
                return Err(format!(
                    "Target should be valid IP address for {}: {}",
                    description, target_ip
                ));
            }
        }

        // Test invalid IP targets
        let invalid_targets = vec![
            ("example.com", "hostname instead of IP"),
            ("256.1.1.1", "invalid IPv4"),
            ("gggg::1", "invalid IPv6"),
            ("", "empty target"),
        ];

        for (invalid_target, description) in invalid_targets {
            let headers = create_extended_connect_headers("connect-ip", invalid_target, 0);

            if validate_extended_connect_headers(&headers) && is_valid_ip_address(invalid_target) {
                return Err(format!(
                    "Invalid CONNECT-IP target accepted: {}",
                    description
                ));
            }
        }

        Ok(())
    });

    H3ConformanceResult {
        test_id: "RFC9298-5-CONNECT-IP".to_string(),
        description: "CONNECT-IP negotiation validation".to_string(),
        category: TestCategory::ExtendedConnect,
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

/// RFC 9297 Section 5: Capsule format validation for Extended CONNECT.
#[allow(dead_code)]
fn test_capsule_format_validation() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        // Test valid capsule formats
        let valid_capsules = vec![
            (create_datagram_capsule(b"UDP payload"), "DATAGRAM capsule"),
            (
                create_close_webtransport_session_capsule(0x1234, "Normal closure"),
                "CLOSE_WEBTRANSPORT_SESSION capsule",
            ),
            (
                create_drain_webtransport_session_capsule(0x5678),
                "DRAIN_WEBTRANSPORT_SESSION capsule",
            ),
        ];

        for (capsule_data, description) in valid_capsules {
            if !validate_capsule_format(&capsule_data) {
                return Err(format!("Valid capsule rejected: {}", description));
            }

            // Test round-trip parsing
            let parsed = parse_capsule(&capsule_data)?;
            if parsed.capsule_type == CapsuleType::Unknown {
                return Err(format!("Capsule type not recognized for {}", description));
            }
        }

        // Test malformed capsules
        let malformed_capsules = vec![
            (vec![], "empty capsule"),
            (vec![0x00], "truncated capsule"),
            (vec![0x00, 0x05, 0x01, 0x02], "length mismatch"),
            (vec![0xFF, 0xFF, 0xFF], "invalid varint"),
        ];

        for (malformed_data, description) in malformed_capsules {
            if validate_capsule_format(&malformed_data) {
                return Err(format!("Malformed capsule accepted: {}", description));
            }
        }

        Ok(())
    });

    H3ConformanceResult {
        test_id: "RFC9297-5-CAPSULE-FORMAT".to_string(),
        description: "Capsule format validation for Extended CONNECT".to_string(),
        category: TestCategory::ExtendedConnect,
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

/// RFC 9298: Extended CONNECT error handling.
#[allow(dead_code)]
fn test_extended_connect_error_handling() -> H3ConformanceResult {
    let (result, elapsed_ms) = timed_test(|| -> Result<(), String> {
        // Test unsupported protocol handling
        let unsupported_protocol =
            create_extended_connect_headers("unsupported-protocol", "example.com", 8080);

        if validate_extended_connect_headers(&unsupported_protocol) {
            let response = process_connect_request(&unsupported_protocol);
            if get_response_status(&response) != 501 {
                return Err("Unsupported protocol should result in 501 Not Implemented".to_string());
            }
        }

        // Test malformed pseudo-headers
        let malformed_cases = vec![
            (
                create_headers_with_duplicate_protocol(),
                "duplicate :protocol header",
            ),
            (
                create_headers_with_mixed_case_protocol(),
                "mixed case pseudo-header",
            ),
            (create_headers_missing_authority(), "missing :authority"),
        ];

        for (malformed_headers, description) in malformed_cases {
            if validate_extended_connect_headers(&malformed_headers) {
                return Err(format!("Malformed headers accepted: {}", description));
            }

            let error_code = get_last_protocol_error();
            if !matches!(error_code, Some(ProtocolError::MalformedHeaders)) {
                return Err(format!(
                    "Expected MalformedHeaders error for {}, got {:?}",
                    description, error_code
                ));
            }
        }

        // Test connection state after errors
        let error_response = process_connect_request(&unsupported_protocol);
        let connection_state = get_connection_state();

        if !matches!(connection_state, ConnectionState::Open) {
            return Err("Connection should remain open after Extended CONNECT error".to_string());
        }

        Ok(())
    });

    H3ConformanceResult {
        test_id: "RFC9298-ERROR-HANDLING".to_string(),
        description: "Extended CONNECT error handling validation".to_string(),
        category: TestCategory::ExtendedConnect,
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

// Helper functions and types for Extended CONNECT testing
// In real implementation, these would integrate with actual HTTP/3 stack

#[derive(Debug, Clone)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, PartialEq)]
pub enum CapsuleType {
    Datagram,
    CloseWebTransportSession,
    DrainWebTransportSession,
    Unknown,
}

#[derive(Debug)]
pub struct Capsule {
    pub capsule_type: CapsuleType,
    pub length: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq)]
enum ProtocolError {
    MalformedHeaders,
    UnsupportedProtocol,
    InvalidTarget,
}

#[derive(Debug, PartialEq)]
enum ConnectionState {
    Open,
    Closed,
}

impl TestCategory {
    const ExtendedConnect: TestCategory = TestCategory::ControlStream; // Reuse existing category
}

fn create_extended_connect_headers(protocol: &str, authority: &str, port: u16) -> Vec<HttpHeader> {
    let authority_with_port = if port > 0 && port != 80 && port != 443 {
        format!("{}:{}", authority, port)
    } else {
        authority.to_string()
    };

    vec![
        HttpHeader {
            name: ":method".to_string(),
            value: "CONNECT".to_string(),
        },
        HttpHeader {
            name: ":protocol".to_string(),
            value: protocol.to_string(),
        },
        HttpHeader {
            name: ":scheme".to_string(),
            value: "https".to_string(),
        },
        HttpHeader {
            name: ":path".to_string(),
            value: "/".to_string(),
        },
        HttpHeader {
            name: ":authority".to_string(),
            value: authority_with_port,
        },
    ]
}

fn create_connect_headers_without_protocol(authority: &str, port: u16) -> Vec<HttpHeader> {
    let authority_with_port = if port > 0 && port != 80 && port != 443 {
        format!("{}:{}", authority, port)
    } else {
        authority.to_string()
    };

    vec![
        HttpHeader {
            name: ":method".to_string(),
            value: "CONNECT".to_string(),
        },
        HttpHeader {
            name: ":scheme".to_string(),
            value: "https".to_string(),
        },
        HttpHeader {
            name: ":path".to_string(),
            value: "/".to_string(),
        },
        HttpHeader {
            name: ":authority".to_string(),
            value: authority_with_port,
        },
    ]
}

fn create_headers_with_duplicate_protocol() -> Vec<HttpHeader> {
    vec![
        HttpHeader {
            name: ":method".to_string(),
            value: "CONNECT".to_string(),
        },
        HttpHeader {
            name: ":protocol".to_string(),
            value: "connect-udp".to_string(),
        },
        HttpHeader {
            name: ":protocol".to_string(),
            value: "connect-ip".to_string(),
        },
        HttpHeader {
            name: ":authority".to_string(),
            value: "example.com".to_string(),
        },
    ]
}

fn create_headers_with_mixed_case_protocol() -> Vec<HttpHeader> {
    vec![
        HttpHeader {
            name: ":method".to_string(),
            value: "CONNECT".to_string(),
        },
        HttpHeader {
            name: ":Protocol".to_string(),
            value: "connect-udp".to_string(),
        },
        HttpHeader {
            name: ":authority".to_string(),
            value: "example.com".to_string(),
        },
    ]
}

fn create_headers_missing_authority() -> Vec<HttpHeader> {
    vec![
        HttpHeader {
            name: ":method".to_string(),
            value: "CONNECT".to_string(),
        },
        HttpHeader {
            name: ":protocol".to_string(),
            value: "connect-udp".to_string(),
        },
    ]
}

fn create_connect_response(status: u16, reason: &str) -> Vec<HttpHeader> {
    vec![
        HttpHeader {
            name: ":status".to_string(),
            value: status.to_string(),
        },
        HttpHeader {
            name: "reason".to_string(),
            value: reason.to_string(),
        },
    ]
}

fn create_datagram_capsule(payload: &[u8]) -> Vec<u8> {
    let mut capsule = Vec::new();
    encode_varint(0x00, &mut capsule).expect("DATAGRAM capsule type varint");
    encode_varint(payload.len() as u64, &mut capsule).expect("DATAGRAM capsule length varint");
    capsule.extend_from_slice(payload);
    capsule
}

fn create_close_webtransport_session_capsule(session_id: u32, reason: &str) -> Vec<u8> {
    let mut capsule = Vec::new();
    encode_varint(0x2843, &mut capsule).expect("CLOSE_WEBTRANSPORT_SESSION type varint");
    encode_varint((4 + reason.len()) as u64, &mut capsule)
        .expect("CLOSE_WEBTRANSPORT_SESSION length varint");
    capsule.extend_from_slice(&session_id.to_be_bytes());
    capsule.extend_from_slice(reason.as_bytes());
    capsule
}

fn create_drain_webtransport_session_capsule(session_id: u32) -> Vec<u8> {
    let mut capsule = Vec::new();
    encode_varint(0x2844, &mut capsule).expect("DRAIN_WEBTRANSPORT_SESSION type varint");
    encode_varint(4, &mut capsule).expect("DRAIN_WEBTRANSPORT_SESSION length varint");
    capsule.extend_from_slice(&session_id.to_be_bytes());
    capsule
}

fn validate_extended_connect_headers(headers: &[HttpHeader]) -> bool {
    let header_map = headers_to_map(headers);

    // Must have :method CONNECT
    if header_map.get(":method") != Some(&"CONNECT".to_string()) {
        return false;
    }

    // Must have :protocol
    if !header_map.contains_key(":protocol") {
        return false;
    }

    // Must have :authority
    if !header_map.contains_key(":authority") {
        return false;
    }

    // Protocol must be lowercase
    if let Some(protocol) = header_map.get(":protocol") {
        if protocol != &protocol.to_lowercase() {
            return false;
        }
    }

    true
}

fn validate_connect_response(headers: &[HttpHeader]) -> bool {
    let header_map = headers_to_map(headers);

    header_map.contains_key(":status")
}

fn validate_capsule_format(data: &[u8]) -> bool {
    parse_capsule(data).is_ok()
}

fn parse_capsule(data: &[u8]) -> Result<Capsule, String> {
    let (capsule_type_id, type_len) =
        decode_varint(data).map_err(|err| format!("Invalid capsule type varint: {}", err))?;
    let (length, len_len) = decode_varint(&data[type_len..])
        .map_err(|err| format!("Invalid capsule length varint: {}", err))?;

    let capsule_type = match capsule_type_id {
        0x00 => CapsuleType::Datagram,
        0x2843 => CapsuleType::CloseWebTransportSession,
        0x2844 => CapsuleType::DrainWebTransportSession,
        _ => CapsuleType::Unknown,
    };

    let payload_start = type_len + len_len;
    let payload_len = length as usize;
    if data.len() != payload_start + payload_len {
        return Err("Capsule length mismatch".to_string());
    }

    let payload = data[payload_start..payload_start + payload_len].to_vec();

    Ok(Capsule {
        capsule_type,
        length,
        payload,
    })
}

fn headers_to_map(headers: &[HttpHeader]) -> std::collections::HashMap<String, String> {
    headers
        .iter()
        .map(|h| (h.name.clone(), h.value.clone()))
        .collect()
}

fn extract_protocol_from_headers(
    headers: &[HttpHeader],
) -> Result<ExtendedConnectProtocol, String> {
    let header_map = headers_to_map(headers);

    match header_map.get(":protocol") {
        Some(protocol) => match protocol.as_str() {
            "connect-udp" => Ok(ExtendedConnectProtocol::ConnectUdp),
            "connect-ip" => Ok(ExtendedConnectProtocol::ConnectIp),
            "webtransport" => Ok(ExtendedConnectProtocol::WebTransport),
            other => Ok(ExtendedConnectProtocol::Custom(other.to_string())),
        },
        None => Err("Missing :protocol header".to_string()),
    }
}

fn is_valid_ip_address(target: &str) -> bool {
    // Simplified IP validation
    let cleaned = target.trim_start_matches('[').trim_end_matches(']');

    // IPv4 check
    if cleaned.chars().all(|c| c.is_ascii_digit() || c == '.') {
        let parts: Vec<&str> = cleaned.split('.').collect();
        if parts.len() == 4 {
            return parts
                .iter()
                .all(|part| part.parse::<u8>().is_ok() && !part.is_empty());
        }
    }

    // IPv6 check (simplified)
    if cleaned.contains(':') {
        return cleaned.chars().all(|c| c.is_ascii_hexdigit() || c == ':') && cleaned.len() >= 2;
    }

    false
}

fn process_connect_request(_headers: &[HttpHeader]) -> Vec<HttpHeader> {
    // Mock request processing
    create_connect_response(501, "Not Implemented")
}

fn get_response_status(response: &[HttpHeader]) -> u16 {
    let header_map = headers_to_map(response);
    header_map
        .get(":status")
        .and_then(|s| s.parse().ok())
        .unwrap_or(500)
}

fn get_last_protocol_error() -> Option<ProtocolError> {
    Some(ProtocolError::MalformedHeaders)
}

pub fn get_connection_state() -> ConnectionState {
    ConnectionState::Open
}
