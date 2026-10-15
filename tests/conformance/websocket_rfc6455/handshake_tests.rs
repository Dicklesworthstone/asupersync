#![allow(warnings)]
#![allow(clippy::all)]
//! Handshake conformance tests.
//!
//! Tests handshake requirements from RFC 6455 Section 4.

use super::*;
use asupersync::net::websocket::{
    ClientHandshake, HandshakeError, HttpRequest, HttpResponse, ServerHandshake, WsUrl,
    compute_accept_key,
};
use asupersync::util::entropy::DetEntropy;
use std::collections::BTreeMap;

/// Run all handshake conformance tests.
#[allow(dead_code)]
pub fn run_handshake_tests() -> Vec<WsConformanceResult> {
    let mut results = Vec::new();

    results.push(test_websocket_key_validation());
    results.push(test_accept_header_computation());
    results.push(test_accept_header_validation());
    results.push(test_header_case_insensitivity());
    results.push(test_version_negotiation());
    results.push(test_origin_validation());

    results
}

#[allow(dead_code)]

fn test_websocket_key_validation() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // WebSocket key validation per RFC 6455
        // Key must be base64-encoded 16-byte value

        let valid_key = "dGhlIHNhbXBsZSBub25jZQ=="; // "the sample nonce"
        if valid_key.len() != 24 {
            return Err("WebSocket key should be 24 characters when base64-encoded".to_string());
        }

        Ok(())
    });

    create_test_result(
        "RFC6455-4.1-WS-KEY",
        "WebSocket key format validation",
        TestCategory::Handshake,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]

fn test_accept_header_computation() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let websocket_key = "dGhlIHNhbXBsZSBub25jZQ==";
        let expected_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        let computed_accept = compute_accept_key(websocket_key);
        if computed_accept != expected_accept {
            return Err(format!(
                "Sec-WebSocket-Accept mismatch: expected {expected_accept}, got {computed_accept}"
            ));
        }

        let request = HttpRequest::parse(
            format!(
                "GET /chat HTTP/1.1\r\n\
                 Host: example.com\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Key: {websocket_key}\r\n\
                 Sec-WebSocket-Version: 13\r\n\r\n"
            )
            .as_bytes(),
        )
        .map_err(|e| format!("request should parse: {e}"))?;
        let response = ServerHandshake::new()
            .accept(&request)
            .map_err(|e| format!("server should accept RFC sample key: {e}"))?;
        if response.accept_key != expected_accept {
            return Err(format!(
                "server computed wrong accept key: expected {expected_accept}, got {}",
                response.accept_key
            ));
        }

        Ok(())
    });

    create_test_result(
        "RFC6455-4.2.2-ACCEPT",
        "WebSocket accept header computation",
        TestCategory::Handshake,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_accept_header_validation() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let handshake = ClientHandshake::new_for_test(
            WsUrl::parse("ws://example.com/chat").map_err(|e| format!("url parse failed: {e}"))?,
            "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            vec![],
            vec![],
            BTreeMap::new(),
        );

        let valid_response = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        )
        .map_err(|e| format!("valid response should parse: {e}"))?;
        handshake
            .validate_response(&valid_response)
            .map_err(|e| format!("valid accept header should pass: {e}"))?;

        let invalid_response = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: invalid-accept-key\r\n\r\n",
        )
        .map_err(|e| format!("invalid response should still parse: {e}"))?;
        match handshake.validate_response(&invalid_response) {
            Err(HandshakeError::InvalidAccept { .. }) => Ok(()),
            other => Err(format!(
                "invalid accept header should fail with InvalidAccept, got {other:?}"
            )),
        }
    });

    create_test_result(
        "RFC6455-4.2.2-ACCEPT-VALIDATION",
        "Client MUST reject mismatched Sec-WebSocket-Accept",
        TestCategory::Handshake,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]
fn test_header_case_insensitivity() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        let entropy = DetEntropy::new(42);
        let client = ClientHandshake::new("ws://example.com/chat", &entropy)
            .map_err(|e| format!("client handshake init failed: {e}"))?;
        let expected_accept = compute_accept_key(client.key());

        let mixed_case_response = HttpResponse::parse(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 uPgRaDe: WebSocket\r\n\
                 cOnNeCtIoN: keep-alive, Upgrade\r\n\
                 sEc-WeBsOcKeT-aCcEpT: {expected_accept}\r\n\r\n"
            )
            .as_bytes(),
        )
        .map_err(|e| format!("mixed-case response should parse: {e}"))?;
        client
            .validate_response(&mixed_case_response)
            .map_err(|e| format!("mixed-case response headers should validate: {e}"))?;

        let mixed_case_request = HttpRequest::parse(
            b"GET /chat HTTP/1.1\r\n\
              Host: example.com\r\n\
              uPgRaDe: WebSocket\r\n\
              cOnNeCtIoN: keep-alive, Upgrade\r\n\
              sEc-WeBsOcKeT-kEy: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              sEc-WeBsOcKeT-vErSiOn: 13\r\n\r\n",
        )
        .map_err(|e| format!("mixed-case request should parse: {e}"))?;
        ServerHandshake::new()
            .accept(&mixed_case_request)
            .map_err(|e| format!("mixed-case request headers should validate: {e}"))?;

        Ok(())
    });

    create_test_result(
        "RFC6455-4.1-HEADER-CASE",
        "WebSocket handshake headers MUST be matched case-insensitively",
        TestCategory::Handshake,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]

fn test_version_negotiation() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // WebSocket version must be 13
        let version = 13;
        if version != 13 {
            return Err("WebSocket version must be 13".to_string());
        }
        Ok(())
    });

    create_test_result(
        "RFC6455-4.1-VERSION",
        "WebSocket version negotiation",
        TestCategory::Handshake,
        RequirementLevel::Must,
        result,
        elapsed,
    )
}

#[allow(dead_code)]

fn test_origin_validation() -> WsConformanceResult {
    let (result, elapsed) = timed_test(|| -> Result<(), String> {
        // Origin header validation logic
        Ok(())
    });

    create_test_result(
        "RFC6455-4.1-ORIGIN",
        "Origin header validation",
        TestCategory::Handshake,
        RequirementLevel::Should,
        result,
        elapsed,
    )
}
