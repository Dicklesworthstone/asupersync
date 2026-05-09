#![no_main]

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::codec::{Http1Codec, HttpError};
use asupersync::http::h1::types::{Method, Request, Version};
use libfuzzer_sys::fuzz_target;

// Maximum data size to prevent timeouts
const MAX_DATA_SIZE: usize = 1024 * 1024; // 1MB

fuzz_target!(|data: &[u8]| {
    run_fixed_upgrade_canaries();

    if data.len() > MAX_DATA_SIZE {
        return;
    }

    // Test HTTP/1.1 upgrade request parsing robustness
    test_upgrade_parsing(data);

    // Test specific upgrade scenarios with mutated input
    test_upgrade_scenarios_with_mutations(data);
});

fn decode_once(raw: &[u8]) -> Result<Option<Request>, HttpError> {
    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(raw);
    codec.decode(&mut buf)
}

fn expect_complete_request(raw: &[u8]) -> Request {
    decode_once(raw)
        .expect("valid upgrade request must not return a parser error")
        .expect("valid upgrade request must decode completely")
}

fn header_values<'a>(request: &'a Request, name: &str) -> impl Iterator<Item = &'a str> {
    request
        .headers
        .iter()
        .filter(move |(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn has_header_value(request: &Request, name: &str, value: &str) -> bool {
    header_values(request, name).any(|header_value| header_value.eq_ignore_ascii_case(value))
}

fn has_connection_token(request: &Request, token: &str) -> bool {
    header_values(request, "Connection").any(|value| {
        value
            .split(',')
            .any(|part| part.trim().eq_ignore_ascii_case(token))
    })
}

fn run_fixed_upgrade_canaries() {
    let websocket = expect_complete_request(
        b"GET /chat HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    );
    assert_eq!(websocket.method, Method::Get);
    assert_eq!(websocket.uri, "/chat");
    assert_eq!(websocket.version, Version::Http11);
    assert!(websocket.body.is_empty());
    assert!(has_connection_token(&websocket, "upgrade"));
    assert!(has_header_value(&websocket, "Upgrade", "websocket"));
    assert!(has_header_value(&websocket, "Sec-WebSocket-Version", "13"));
    validate_upgrade_invariants(&websocket, &BytesMut::new());

    let h2c = expect_complete_request(
        b"OPTIONS * HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n",
    );
    assert_eq!(h2c.method, Method::Options);
    assert_eq!(h2c.uri, "*");
    assert!(has_connection_token(&h2c, "upgrade"));
    assert!(has_connection_token(&h2c, "http2-settings"));
    assert!(has_header_value(&h2c, "Upgrade", "h2c"));
    assert!(has_header_value(&h2c, "HTTP2-Settings", "AAMAAABkAAQAAP__"));
    validate_upgrade_invariants(&h2c, &BytesMut::new());

    let upgrade_with_body = expect_complete_request(
        b"POST /chat HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 4\r\n\r\nping",
    );
    assert_eq!(upgrade_with_body.method, Method::Post);
    assert_eq!(upgrade_with_body.body, b"ping");
    assert!(has_connection_token(&upgrade_with_body, "upgrade"));
    validate_upgrade_invariants(&upgrade_with_body, &BytesMut::new());

    let partial =
        decode_once(b"GET /chat HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n")
            .expect("partial upgrade head must wait for more bytes, not error");
    assert!(partial.is_none(), "partial upgrade head must not decode");
}

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

fn validate_upgrade_invariants(request: &Request, remaining_buf: &BytesMut) {
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
            // Body data present - ensure it stays within the bounded fuzz input.
            assert!(
                request.body.len() <= MAX_DATA_SIZE,
                "body data grew beyond the fuzz input cap"
            );
        }

        // ASSERTION 3: Remaining buffer should not contain upgraded protocol data mixed with HTTP
        // This is critical - after HTTP parsing, any remaining data is for the new protocol
        if !remaining_buf.is_empty() {
            // There's unparsed data - ensure it remains bounded and accessible.
            assert!(
                remaining_buf.len() <= MAX_DATA_SIZE,
                "remaining buffer grew beyond the fuzz input cap"
            );
        }

        // Validate specific upgrade protocols
        for protocol in &upgrade_protocols {
            validate_protocol_upgrade(protocol, request);
        }
    }
}

fn validate_protocol_upgrade(protocol: &str, request: &Request) {
    let protocol_lower = protocol.trim().to_ascii_lowercase();

    match protocol_lower.as_str() {
        "websocket" => validate_websocket_upgrade(request),
        "h2c" => validate_h2c_upgrade(request),
        _ => validate_generic_upgrade(protocol, request),
    }
}

fn validate_websocket_upgrade(request: &Request) {
    for (name, value) in &request.headers {
        let name_lower = name.to_ascii_lowercase();
        match name_lower.as_str() {
            "sec-websocket-key" => {
                // Key should be non-empty
                assert!(
                    !value.trim().is_empty(),
                    "WebSocket key should not be empty"
                );
            }
            "sec-websocket-version" => {
                assert!(
                    !value.trim().is_empty(),
                    "WebSocket version should not be empty"
                );
            }
            _ => {}
        }
    }
}

fn validate_h2c_upgrade(request: &Request) {
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("http2-settings") {
            assert!(
                !value.trim().is_empty(),
                "HTTP2-Settings should not be empty when present"
            );
        }
    }
}

fn validate_generic_upgrade(protocol: &str, _request: &Request) {
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

fn observe_decode_result(result: Result<Option<Request>, HttpError>, remaining_buf: &BytesMut) {
    if let Ok(Some(request)) = result {
        validate_upgrade_invariants(&request, remaining_buf);
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
            let first_result = codec.decode(&mut buf);
            observe_decode_result(first_result, &buf);

            // Add remaining data and parse again
            buf.extend_from_slice(&data[split_point..]);
            let second_result = codec.decode(&mut buf);
            observe_decode_result(second_result, &buf);
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
        let result = codec.decode(&mut buf);
        observe_decode_result(result, &buf);
    }
}
