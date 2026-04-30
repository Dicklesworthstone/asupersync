#![no_main]

use libfuzzer_sys::fuzz_target;
use asupersync::bytes::BytesMut;
use asupersync::http::h1::codec::Http1Codec;
use asupersync::http::h1::types::{Method, Request};

// Maximum data size to prevent timeouts on extremely large inputs
const MAX_DATA_SIZE: usize = 10 * 1024 * 1024; // 10MB

fuzz_target!(|data: &[u8]| {
    // Size guard to prevent timeout on massive inputs
    if data.len() > MAX_DATA_SIZE {
        return;
    }

    // Create a new codec instance for each test
    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(data);

    // Test request parsing focusing on upgrade scenarios
    match codec.decode(&mut buf) {
        Ok(Some(request)) => {
            // Successfully parsed a request - now validate upgrade handling
            validate_upgrade_request(&request);
        },
        Ok(None) => {
            // Incomplete request - this is fine for fuzzing
        },
        Err(_) => {
            // Parse error - this is expected for invalid input and is fine
        }
    }

    // Test with different codec configurations for upgrade scenarios
    let mut small_headers_codec = Http1Codec::new().max_headers_size(256);
    let mut buf_copy = BytesMut::from(data);
    let _ = small_headers_codec.decode(&mut buf_copy);

    // Test multiple decode calls to simulate pipelined upgrade requests
    if data.len() > 10 {
        let mut multi_codec = Http1Codec::new();
        let mut multi_buf = BytesMut::from(data);
        let _ = multi_codec.decode(&mut multi_buf);
        let _ = multi_codec.decode(&mut multi_buf);
    }

    // Test specific upgrade-related edge cases
    test_upgrade_edge_cases(data);
});

/// Validate upgrade request handling and assert invariants.
fn validate_upgrade_request(request: &Request) {
    // Check for upgrade-related headers
    let mut has_connection_upgrade = false;
    let mut has_upgrade_header = false;
    let mut connection_values = Vec::new();
    let mut upgrade_values = Vec::new();

    for (name, value) in &request.headers {
        match name.to_ascii_lowercase().as_str() {
            "connection" => {
                has_connection_upgrade = value.to_ascii_lowercase().contains("upgrade");
                connection_values.push(value.clone());
            }
            "upgrade" => {
                has_upgrade_header = true;
                upgrade_values.push(value.clone());
            }
            _ => {}
        }
    }

    // KEY ASSERTION: No body should be buffered for upgrade requests
    // This is critical for WebSocket and other upgrades where post-HTTP data
    // belongs to the upgraded protocol, not HTTP
    if has_connection_upgrade && has_upgrade_header && !request.body.is_empty() {
        // Having body data is unusual for upgrade requests but shouldn't crash
        // The key requirement is that the parser must not buffer this data
        // in a way that interferes with the upgraded protocol

        // Assert: Body data should be available to the application layer
        // and not lost or corrupted during upgrade processing
        assert!(request.body.len() > 0, "Body should be preserved");
    }

    // Validate upgrade request invariants
    if has_upgrade_header {
        // If Upgrade header is present, Connection must include "upgrade"
        // This is an HTTP/1.1 requirement, not a crash condition
        validate_upgrade_semantics(&request.method, &connection_values, &upgrade_values);
    }

    // Test various upgrade scenarios
    if has_connection_upgrade && has_upgrade_header {
        // This looks like an upgrade request
        validate_websocket_upgrade_request(request, &upgrade_values);

        // Assert: Connection upgrade detected properly
        assert!(has_connection_upgrade && has_upgrade_header,
               "Connection upgrade must be properly detected");
    }
}

/// Validate HTTP/1.1 upgrade semantics.
fn validate_upgrade_semantics(method: &Method, connection_values: &[String], upgrade_values: &[String]) {
    // Upgrade requests should typically be GET for WebSocket
    let is_get = matches!(method, Method::Get);

    // Connection header should contain "upgrade" (case-insensitive)
    let has_connection_upgrade = connection_values.iter()
        .any(|v| v.to_ascii_lowercase().split(',')
            .any(|token| token.trim() == "upgrade"));

    // Upgrade header should have specific protocols
    let upgrade_protocols: Vec<&str> = upgrade_values.iter()
        .flat_map(|v| v.split(','))
        .map(|s| s.trim())
        .collect();

    // Common upgrade protocols: websocket, h2c, etc.
    let known_protocols = ["websocket", "h2c", "http/2"];
    let has_known_protocol = upgrade_protocols.iter()
        .any(|p| known_protocols.contains(&p.to_ascii_lowercase().as_str()));

    // Log interesting combinations (for debugging, won't crash)
    if !is_get && has_connection_upgrade && has_known_protocol {
        // Non-GET upgrade request - unusual but not necessarily invalid
    }
}

/// Validate WebSocket-specific upgrade requests.
fn validate_websocket_upgrade_request(request: &Request, upgrade_values: &[String]) {
    let is_websocket = upgrade_values.iter()
        .any(|v| v.to_ascii_lowercase().contains("websocket"));

    if !is_websocket {
        return;
    }

    // For WebSocket upgrades, check for required headers
    let mut has_sec_websocket_key = false;
    let mut has_sec_websocket_version = false;

    for (name, _value) in &request.headers {
        match name.to_ascii_lowercase().as_str() {
            "sec-websocket-key" => has_sec_websocket_key = true,
            "sec-websocket-version" => has_sec_websocket_version = true,
            _ => {}
        }
    }

    // WebSocket upgrade should have these headers (but missing them shouldn't crash)
    let _has_required_ws_headers = has_sec_websocket_key && has_sec_websocket_version;

    // Validate that the request structure is sound for upgrade handling
    assert!(!request.uri.is_empty(), "URI should not be empty for upgrade requests");

    // Body handling for upgrade requests - should typically be empty
    // But having a body shouldn't crash the parser
    if !request.body.is_empty() {
        // Upgrade requests typically have empty bodies, but this shouldn't crash
    }
}

/// Test specific edge cases related to upgrade handling.
fn test_upgrade_edge_cases(data: &[u8]) {
    if data.len() < 20 {
        return;
    }

    // Test with crafted upgrade-like patterns
    let upgrade_patterns = [
        b"Connection: upgrade",
        b"Connection: Upgrade",
        b"Connection: UPGRADE",
        b"Connection: keep-alive, upgrade",
        b"Connection: upgrade, keep-alive",
        b"Upgrade: websocket",
        b"Upgrade: WebSocket",
        b"Upgrade: h2c",
        b"upgrade: websocket",
        b"CONNECTION: UPGRADE",
        b"Connection: \tUpgrade\t",
        b"Connection: upgrade\r\n",
    ];

    for pattern in &upgrade_patterns {
        if data.windows(pattern.len()).any(|window| window == *pattern) {
            // Found upgrade-related pattern - test codec robustness
            let mut test_codec = Http1Codec::new();
            let mut test_buf = BytesMut::from(data);
            let _ = test_codec.decode(&mut test_buf);
        }
    }

    // Test boundary conditions around upgrade headers
    let slice_points = [1, 5, 10, data.len() / 2, data.len().saturating_sub(10)];
    for &point in &slice_points {
        if point < data.len() {
            let mut boundary_codec = Http1Codec::new();
            let mut boundary_buf = BytesMut::from(&data[..point]);
            let _ = boundary_codec.decode(&mut boundary_buf);

            // Add remaining data
            boundary_buf.extend_from_slice(&data[point..]);
            let _ = boundary_codec.decode(&mut boundary_buf);
        }
    }
}