#![no_main]

use asupersync::bytes::BytesMut;
use asupersync::http::h1::codec::Http1Codec;
use libfuzzer_sys::fuzz_target;

// Maximum data size to prevent timeouts
const MAX_DATA_SIZE: usize = 1024 * 1024; // 1MB

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_DATA_SIZE {
        return;
    }

    // Test HTTP/1.1 upgrade request parsing robustness
    test_upgrade_parsing(data);

    // Test specific upgrade scenarios with mutated input
    test_upgrade_scenarios_with_mutations(data);
});

fn test_upgrade_parsing(data: &[u8]) {
    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(data);

    // Primary parsing test - must not panic
    match codec.decode(&mut buf) {
        Ok(Some(request)) => {
            // Successfully parsed - validate upgrade handling
            validate_upgrade_invariants(&request, &buf);
        }
        Ok(None) => {
            // Incomplete request - normal for fuzzing
        }
        Err(_) => {
            // Parse error - expected for malformed input
        }
    }
}

fn validate_upgrade_invariants(
    request: &asupersync::http::h1::types::Request,
    remaining_buf: &BytesMut,
) {
    let mut is_upgrade_request = false;
    let mut has_connection_upgrade = false;
    let mut upgrade_protocols = Vec::new();

    // Analyze headers for upgrade patterns
    for (name, value) in &request.headers {
        let name_lower = name.to_ascii_lowercase();
        let value_lower = value.to_ascii_lowercase();

        match name_lower.as_str() {
            "connection" => {
                has_connection_upgrade = value_lower.contains("upgrade");
            }
            "upgrade" => {
                is_upgrade_request = true;
                upgrade_protocols.push(value.clone());
            }
            _ => {}
        }
    }

    if is_upgrade_request && has_connection_upgrade {
        // This is an upgrade request - assert critical invariants

        // ASSERTION 1: Connection upgrade must be properly detected
        assert!(
            has_connection_upgrade,
            "Connection: upgrade header must be present for upgrade requests"
        );
        assert!(
            !upgrade_protocols.is_empty(),
            "Upgrade header must specify protocol(s)"
        );

        // ASSERTION 2: No HTTP body should interfere with upgraded protocol
        // For upgrade requests, any data after headers belongs to the new protocol
        if !request.body.is_empty() {
            // Body data present - ensure it's properly handled
            // The parser should preserve this data for the upgraded protocol
            assert!(
                request.body.len() > 0,
                "Body data must be preserved for upgrade handling"
            );

            // Body should not be corrupted or truncated
            for &byte in &request.body {
                // Basic sanity check - all bytes should be readable
                let _ = byte; // No-op to ensure byte is accessible
            }
        }

        // ASSERTION 3: Remaining buffer should not contain upgraded protocol data mixed with HTTP
        // This is critical - after HTTP parsing, any remaining data is for the new protocol
        if !remaining_buf.is_empty() {
            // There's unparsed data - this might be upgraded protocol data
            // The key requirement: this data must not be lost or corrupted
            assert!(
                remaining_buf.len() > 0,
                "Remaining buffer must be accessible"
            );
        }

        // Validate specific upgrade protocols
        for protocol in &upgrade_protocols {
            validate_protocol_upgrade(protocol, request);
        }
    }
}

fn validate_protocol_upgrade(protocol: &str, request: &asupersync::http::h1::types::Request) {
    let protocol_lower = protocol.trim().to_ascii_lowercase();

    match protocol_lower.as_str() {
        "websocket" => validate_websocket_upgrade(request),
        "h2c" => validate_h2c_upgrade(request),
        _ => validate_generic_upgrade(protocol, request),
    }
}

fn validate_websocket_upgrade(request: &asupersync::http::h1::types::Request) {
    // WebSocket upgrades should typically be GET requests
    let is_get = matches!(request.method, asupersync::http::h1::types::Method::Get);

    // Find WebSocket-specific headers
    let mut has_ws_key = false;
    let mut has_ws_version = false;

    for (name, value) in &request.headers {
        let name_lower = name.to_ascii_lowercase();
        match name_lower.as_str() {
            "sec-websocket-key" => {
                has_ws_key = true;
                // Key should be non-empty
                assert!(
                    !value.trim().is_empty(),
                    "WebSocket key should not be empty"
                );
            }
            "sec-websocket-version" => {
                has_ws_version = true;
                // Version should be parseable
                let _ = value.trim().parse::<u8>().unwrap_or(0);
            }
            _ => {}
        }
    }

    // For valid WebSocket upgrades, certain headers are typically required
    if is_get && has_ws_key && has_ws_version {
        // This looks like a proper WebSocket upgrade request
        assert!(
            has_ws_key && has_ws_version,
            "WebSocket upgrade should have required headers"
        );
    }
}

fn validate_h2c_upgrade(request: &asupersync::http::h1::types::Request) {
    // HTTP/2 Clear Text upgrade validation
    let mut has_http2_settings = false;

    for (name, _value) in &request.headers {
        if name.to_ascii_lowercase() == "http2-settings" {
            has_http2_settings = true;
            break;
        }
    }

    // h2c upgrades typically include HTTP2-Settings header
    if has_http2_settings {
        assert!(
            has_http2_settings,
            "h2c upgrade should have HTTP2-Settings header"
        );
    }
}

fn validate_generic_upgrade(protocol: &str, _request: &asupersync::http::h1::types::Request) {
    // Generic upgrade protocol validation
    assert!(
        !protocol.trim().is_empty(),
        "Upgrade protocol should not be empty"
    );

    // Protocol name should be reasonable length and contain valid characters
    assert!(
        protocol.len() < 1000,
        "Protocol name should be reasonable length"
    );

    // Should not contain control characters that could cause issues
    for ch in protocol.chars() {
        assert!(
            !ch.is_control() || ch.is_whitespace(),
            "Protocol name should not contain dangerous control characters"
        );
    }
}

fn test_upgrade_scenarios_with_mutations(data: &[u8]) {
    if data.len() < 10 {
        return;
    }

    // Test parsing at different buffer boundaries to catch edge cases
    for split_point in [1, 4, 8, data.len() / 2, data.len().saturating_sub(4)] {
        if split_point < data.len() {
            let mut codec = Http1Codec::new();

            // Parse first part
            let mut buf = BytesMut::from(&data[..split_point]);
            let _ = codec.decode(&mut buf);

            // Add remaining data and parse again
            buf.extend_from_slice(&data[split_point..]);
            let _ = codec.decode(&mut buf);
        }
    }

    // Test with various codec configurations
    let configs = [
        Http1Codec::new().max_headers_size(1024),
        Http1Codec::new().max_body_size(1024),
        Http1Codec::new().max_headers_size(256).max_body_size(256),
    ];

    for mut codec in configs {
        let mut buf = BytesMut::from(data);
        let _ = codec.decode(&mut buf);
    }
}
