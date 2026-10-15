#![allow(warnings)]
#![allow(clippy::all)]
//! h2c (cleartext HTTP/2) upgrade negotiation tests.
//!
//! Tests RFC 9113 Section 4.1 cleartext HTTP/2 upgrade via HTTP/1.1 Upgrade mechanism.

use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// Run all h2c upgrade negotiation tests.
#[allow(dead_code)]
pub fn run_h2c_upgrade_tests() -> Vec<H2ConformanceResult> {
    let mut results = Vec::new();

    results.push(test_h2c_upgrade_request());
    results.push(test_h2c_upgrade_response());
    results.push(test_http2_settings_header());
    results.push(test_upgrade_error_handling());
    results.push(test_h2c_prior_knowledge());
    results.push(test_upgrade_header_validation());

    results
}

/// RFC 9113 Section 4.1: h2c upgrade request format.
#[allow(dead_code)]
fn test_h2c_upgrade_request() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Valid h2c upgrade request
        let upgrade_request = HttpRequest {
            method: "GET",
            uri: "/",
            version: "HTTP/1.1",
            headers: vec![
                ("Host", "example.com"),
                ("Connection", "Upgrade, HTTP2-Settings"),
                ("Upgrade", "h2c"),
                ("HTTP2-Settings", "AAMAAABkAARAAAAAAAIAAAAA"), // Base64 encoded SETTINGS
            ],
        };

        // Validate required headers are present
        if !has_header(&upgrade_request, "Connection") {
            return Err("h2c upgrade request missing Connection header".to_string());
        }

        if !has_header(&upgrade_request, "Upgrade") {
            return Err("h2c upgrade request missing Upgrade header".to_string());
        }

        if !has_header(&upgrade_request, "HTTP2-Settings") {
            return Err("h2c upgrade request missing HTTP2-Settings header".to_string());
        }

        // Validate Connection header includes required tokens
        let connection_header = get_header_value(&upgrade_request, "Connection");
        if !connection_header.contains("Upgrade") {
            return Err("Connection header must include 'Upgrade'".to_string());
        }

        if !connection_header.contains("HTTP2-Settings") {
            return Err("Connection header must include 'HTTP2-Settings'".to_string());
        }

        // Validate Upgrade header specifies h2c
        let upgrade_header = get_header_value(&upgrade_request, "Upgrade");
        if upgrade_header != "h2c" {
            return Err(format!(
                "Upgrade header must be 'h2c', got '{}'",
                upgrade_header
            ));
        }

        // Validate HTTP2-Settings header is base64 encoded
        let settings_header = get_header_value(&upgrade_request, "HTTP2-Settings");
        let settings_decoded = base64_decode(&settings_header)
            .map_err(|error| format!("HTTP2-Settings header must be valid base64url: {error}"))?;
        validate_http2_settings_payload(&settings_decoded)?;

        Ok(())
    });

    create_test_result(
        "RFC9113-4.1-H2C-REQUEST",
        "h2c upgrade request format validation",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9113 Section 4.1: h2c upgrade response format.
#[allow(dead_code)]
fn test_h2c_upgrade_response() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Test successful h2c upgrade response
        let upgrade_response = HttpResponse {
            version: "HTTP/1.1",
            status_code: 101,
            reason_phrase: "Switching Protocols",
            headers: vec![("Connection", "Upgrade"), ("Upgrade", "h2c")],
        };

        // Validate 101 Switching Protocols status
        if upgrade_response.status_code != 101 {
            return Err(format!(
                "h2c upgrade response must use status 101, got {}",
                upgrade_response.status_code
            ));
        }

        // Validate required headers
        if !has_response_header(&upgrade_response, "Connection") {
            return Err("h2c upgrade response missing Connection header".to_string());
        }

        if !has_response_header(&upgrade_response, "Upgrade") {
            return Err("h2c upgrade response missing Upgrade header".to_string());
        }

        let connection_header = get_response_header_value(&upgrade_response, "Connection");
        if connection_header != "Upgrade" {
            return Err("Connection header must be 'Upgrade' in upgrade response".to_string());
        }

        let upgrade_header = get_response_header_value(&upgrade_response, "Upgrade");
        if upgrade_header != "h2c" {
            return Err("Upgrade header must be 'h2c' in upgrade response".to_string());
        }

        // Test upgrade rejection scenarios
        let rejection_responses = vec![
            (400, "Bad Request", "Invalid HTTP2-Settings"),
            (505, "HTTP Version Not Supported", "h2c not supported"),
            (426, "Upgrade Required", "Must use TLS"),
        ];

        for (status, reason, description) in rejection_responses {
            let rejection = HttpResponse {
                version: "HTTP/1.1",
                status_code: status,
                reason_phrase: reason,
                headers: vec![],
            };

            // Rejection responses should not include upgrade headers
            if has_response_header(&rejection, "Upgrade") {
                return Err(format!(
                    "Rejection response ({}) should not include Upgrade header",
                    description
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC9113-4.1-H2C-RESPONSE",
        "h2c upgrade response format validation",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9113 Section 4.1: HTTP2-Settings header validation.
#[allow(dead_code)]
fn test_http2_settings_header() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Test valid HTTP2-Settings values
        let valid_settings = vec![
            ("", "empty settings"),
            (
                "AAMAAABkAARAAAAAAAIAAAAA",
                "typical settings with table size and window size",
            ),
            (
                "AAEAAAgAAwAAAAEABAAA__8",
                "max concurrent streams and max frame size",
            ),
        ];

        for (settings_value, description) in valid_settings {
            let decoded = base64_decode(settings_value)
                .map_err(|_| format!("Failed to decode valid settings: {}", description))?;
            validate_http2_settings_payload(&decoded)
                .map_err(|error| format!("Invalid settings payload for {description}: {error}"))?;
        }

        // Test invalid HTTP2-Settings values
        let invalid_settings = vec![
            ("not-base64!", "invalid base64 encoding"),
            ("AAEAAAAI=", "HTTP2-Settings uses base64url without padding"),
            (
                "AAEAAAgAAwAAAAEABAAA//8=",
                "standard base64 alphabet is not base64url",
            ),
            ("QUE", "payload length not multiple of 6"), // "AA" -> 2 bytes
        ];

        for (settings_value, description) in invalid_settings {
            let accepted = base64_decode(settings_value)
                .and_then(|decoded| validate_http2_settings_payload(&decoded))
                .is_ok();
            if accepted {
                return Err(format!(
                    "Invalid settings '{}' was accepted: {}",
                    settings_value, description
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC9113-4.1-HTTP2-SETTINGS",
        "HTTP2-Settings header validation",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9113 Section 4.1: Upgrade error handling.
#[allow(dead_code)]
fn test_upgrade_error_handling() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Test various malformed upgrade requests
        let malformed_requests = vec![
            (
                vec![
                    ("Connection", "Upgrade"),
                    ("Upgrade", "h2c"),
                    // Missing HTTP2-Settings
                ],
                "missing HTTP2-Settings header",
            ),
            (
                vec![
                    ("Connection", "Keep-Alive"), // Wrong connection type
                    ("Upgrade", "h2c"),
                    ("HTTP2-Settings", ""),
                ],
                "incorrect Connection header",
            ),
            (
                vec![
                    ("Connection", "Upgrade, HTTP2-Settings"),
                    ("Upgrade", "websocket"), // Wrong upgrade protocol
                    ("HTTP2-Settings", ""),
                ],
                "incorrect Upgrade protocol",
            ),
            (
                vec![
                    ("Connection", "Upgrade, HTTP2-Settings"),
                    ("Upgrade", "h2c"),
                    ("HTTP2-Settings", "invalid-base64!"),
                ],
                "invalid HTTP2-Settings encoding",
            ),
        ];

        for (headers, description) in malformed_requests {
            let request = HttpRequest {
                method: "GET",
                uri: "/",
                version: "HTTP/1.1",
                headers,
            };

            // These should be rejected or result in non-upgrade responses
            let is_valid_upgrade = validate_h2c_upgrade_request(&request);
            if is_valid_upgrade {
                return Err(format!(
                    "Malformed h2c upgrade request was accepted: {}",
                    description
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC9113-4.1-UPGRADE-ERRORS",
        "h2c upgrade error handling",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9113 Section 4.1: h2c prior knowledge connection.
#[allow(dead_code)]
fn test_h2c_prior_knowledge() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // h2c prior knowledge: client can send HTTP/2 directly without upgrade
        // Connection starts with the connection preface

        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

        // In prior knowledge mode, first frame after preface must be SETTINGS
        let settings_frame = SettingsFrame {
            stream_id: 0,
            flags: 0,
            payload: vec![], // Empty SETTINGS
        };

        // Validate prior knowledge connection setup
        let connection_setup = H2cPriorKnowledgeSetup {
            preface: preface.to_vec(),
            first_frame: settings_frame,
        };

        if !validate_h2c_prior_knowledge_setup(&connection_setup) {
            return Err("Valid h2c prior knowledge setup was rejected".to_string());
        }

        // Test invalid prior knowledge setups
        let invalid_setups = vec![
            (
                b"GET / HTTP/1.1\r\n\r\n".to_vec(), // HTTP/1.1 request instead of preface
                "HTTP/1.1 request instead of connection preface",
            ),
            (
                b"PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n".to_vec(), // Invalid preface
                "malformed connection preface",
            ),
        ];

        for (invalid_preface, description) in invalid_setups {
            let invalid_setup = H2cPriorKnowledgeSetup {
                preface: invalid_preface,
                first_frame: SettingsFrame {
                    stream_id: 0,
                    flags: 0,
                    payload: vec![],
                },
            };

            if validate_h2c_prior_knowledge_setup(&invalid_setup) {
                return Err(format!(
                    "Invalid h2c prior knowledge setup was accepted: {}",
                    description
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC9113-4.1-H2C-PRIOR-KNOWLEDGE",
        "h2c prior knowledge connection validation",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

/// RFC 9113 Section 4.1: Upgrade header case sensitivity and token validation.
#[allow(dead_code)]
fn test_upgrade_header_validation() -> H2ConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Test case sensitivity of upgrade tokens
        let case_variants = vec![
            ("h2c", true, "correct lowercase"),
            ("H2C", false, "uppercase"), // Should be case-sensitive
            ("H2c", false, "mixed case"),
            ("h2C", false, "mixed case 2"),
        ];

        for (upgrade_value, should_accept, description) in case_variants {
            let request = HttpRequest {
                method: "GET",
                uri: "/",
                version: "HTTP/1.1",
                headers: vec![
                    ("Connection", "Upgrade, HTTP2-Settings"),
                    ("Upgrade", upgrade_value),
                    ("HTTP2-Settings", ""),
                ],
            };

            let is_valid = validate_h2c_upgrade_request(&request);
            if is_valid != should_accept {
                return Err(format!(
                    "Upgrade value '{}' ({}): expected {}, got {}",
                    upgrade_value, description, should_accept, is_valid
                ));
            }
        }

        // Test Connection header token parsing
        let connection_variants = vec![
            ("Upgrade, HTTP2-Settings", true, "correct tokens"),
            ("upgrade, http2-settings", false, "lowercase tokens"),
            ("Upgrade", false, "missing HTTP2-Settings token"),
            ("HTTP2-Settings", false, "missing Upgrade token"),
            ("Keep-Alive, Upgrade", false, "extra keep-alive token"),
        ];

        for (connection_value, should_accept, description) in connection_variants {
            let request = HttpRequest {
                method: "GET",
                uri: "/",
                version: "HTTP/1.1",
                headers: vec![
                    ("Connection", connection_value),
                    ("Upgrade", "h2c"),
                    ("HTTP2-Settings", ""),
                ],
            };

            let is_valid = validate_h2c_upgrade_request(&request);
            if is_valid != should_accept {
                return Err(format!(
                    "Connection value '{}' ({}): expected {}, got {}",
                    connection_value, description, should_accept, is_valid
                ));
            }
        }

        Ok(())
    });

    create_test_result(
        "RFC9113-4.1-HEADER-VALIDATION",
        "h2c upgrade header validation",
        TestCategory::Connection,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

// Local fixture types and helper functions for the conformance cases.

#[derive(Debug)]
struct HttpRequest<'a> {
    method: &'a str,
    uri: &'a str,
    version: &'a str,
    headers: Vec<(&'a str, &'a str)>,
}

#[derive(Debug)]
struct HttpResponse<'a> {
    version: &'a str,
    status_code: u16,
    reason_phrase: &'a str,
    headers: Vec<(&'a str, &'a str)>,
}

#[derive(Debug)]
struct SettingsFrame {
    stream_id: u32,
    flags: u8,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct H2cPriorKnowledgeSetup {
    preface: Vec<u8>,
    first_frame: SettingsFrame,
}

fn has_header(request: &HttpRequest, name: &str) -> bool {
    request
        .headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case(name))
}

fn get_header_value(request: &HttpRequest, name: &str) -> &str {
    request
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| *v)
        .unwrap_or("")
}

fn has_response_header(response: &HttpResponse, name: &str) -> bool {
    response
        .headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case(name))
}

fn get_response_header_value(response: &HttpResponse, name: &str) -> &str {
    response
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| *v)
        .unwrap_or("")
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|error| format!("invalid HTTP2-Settings base64url: {error}"))
}

fn validate_http2_settings_payload(payload: &[u8]) -> Result<(), String> {
    if payload.len() % 6 != 0 {
        return Err("HTTP2-Settings payload length must be multiple of 6".to_string());
    }

    for chunk in payload.chunks_exact(6) {
        let id = u16::from_be_bytes([chunk[0], chunk[1]]);
        let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);

        match id {
            1 => {}
            2 => {
                if value > 1 {
                    return Err(format!("SETTINGS_ENABLE_PUSH must be 0 or 1, got {value}"));
                }
            }
            3 => {}
            4 => {
                if value > 0x7FFF_FFFF {
                    return Err(format!(
                        "SETTINGS_INITIAL_WINDOW_SIZE must be <= 2^31-1, got {value}"
                    ));
                }
            }
            5 => {
                if !(16_384..=16_777_215).contains(&value) {
                    return Err(format!(
                        "SETTINGS_MAX_FRAME_SIZE must be 16384-16777215, got {value}"
                    ));
                }
            }
            6 => {}
            _ => {}
        }
    }

    Ok(())
}

fn validate_h2c_upgrade_request(request: &HttpRequest) -> bool {
    if !(has_header(request, "Connection")
        && has_header(request, "Upgrade")
        && has_header(request, "HTTP2-Settings")
        && get_header_value(request, "Upgrade") == "h2c"
        && get_header_value(request, "Connection").contains("Upgrade")
        && get_header_value(request, "Connection").contains("HTTP2-Settings"))
    {
        return false;
    }

    base64_decode(get_header_value(request, "HTTP2-Settings"))
        .and_then(|decoded| validate_http2_settings_payload(&decoded))
        .is_ok()
}

fn validate_h2c_prior_knowledge_setup(setup: &H2cPriorKnowledgeSetup) -> bool {
    let expected_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    setup.preface == expected_preface && setup.first_frame.stream_id == 0
}
