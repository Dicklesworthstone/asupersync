#![no_main]

use arbitrary::Arbitrary;
use asupersync::net::websocket::{
    AcceptResponse, ClientHandshake, HandshakeError, HttpRequest, HttpResponse, ServerHandshake,
    WsUrl,
};
use asupersync::util::DetEntropy;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

/// RFC 6455 focused fuzz target for WebSocket handshake parsing.
///
/// This fuzzer targets critical handshake parsing vulnerabilities:
/// 1. Sec-WebSocket-Key validation (RFC 6455 §4.1) - must be 16 bytes base64
/// 2. Header injection via malformed Connection/Upgrade values (§4.2.1)
/// 3. Protocol negotiation edge cases with oversized/malicious values (§4.2.2)
/// 4. Extension parsing with embedded CRLF injection attempts
/// 5. HTTP header parsing boundary conditions and malformed requests
/// 6. Accept key computation validation against RFC test vectors
#[derive(Arbitrary, Debug)]
struct WebSocketHandshakeInput {
    operations: Vec<HandshakeParseOperation>,
}

#[derive(Arbitrary, Debug)]
enum HandshakeParseOperation {
    /// Test Sec-WebSocket-Key validation edge cases
    WebSocketKey {
        key_data: Vec<u8>,
        force_padding: Option<u8>, // 0-4 padding chars
        inject_invalid_chars: bool,
        mutate_length: Option<u8>, // Target length deviation
    },
    /// Test Connection/Upgrade header parsing and injection attempts
    ConnectionUpgrade {
        connection_header: Vec<u8>,
        upgrade_header: Vec<u8>,
        inject_crlf: bool,
        case_variations: bool,
        extra_tokens: Vec<String>,
    },
    /// Test protocol/extension negotiation with malicious payloads
    ProtocolNegotiation {
        protocols: Vec<String>,
        extensions: Vec<String>,
        oversized_count: u8, // Generate 0-255 protocol entries
        inject_control_chars: bool,
        duplicate_protocols: bool,
    },
    /// Test HTTP request parsing boundary conditions
    HttpRequestBoundary {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
        malformed_headers: bool,
        missing_terminator: bool,
        oversized_headers: u8, // 0-255 header count
        inject_null_bytes: bool,
    },
    /// Test HTTP response parsing for client validation
    HttpResponseBoundary {
        status_code: u16,
        reason_phrase: String,
        headers: Vec<(String, String)>,
        malformed_status_line: bool,
        inject_response_splitting: bool,
    },
    /// Test complete handshake flow with mutated sequences
    FullHandshakeFlow {
        url: String,
        client_protocols: Vec<String>,
        client_extensions: Vec<String>,
        server_protocols: Vec<String>,
        server_extensions: Vec<String>,
        mutate_accept_key: bool,
        inject_extra_headers: bool,
    },
    /// Test URL parsing edge cases (ws:// and wss://)
    UrlParsing {
        scheme: String,
        host: String,
        port: Option<u16>,
        path: String,
        ipv6_brackets: bool,
        malformed_components: bool,
    },
}

fuzz_target!(|input: WebSocketHandshakeInput| {
    assert_known_handshake_outcomes();

    for operation in input.operations {
        match operation {
            HandshakeParseOperation::WebSocketKey {
                key_data,
                force_padding,
                inject_invalid_chars,
                mutate_length,
            } => {
                fuzz_websocket_key_validation(
                    &key_data,
                    force_padding,
                    inject_invalid_chars,
                    mutate_length,
                );
            }
            HandshakeParseOperation::ConnectionUpgrade {
                connection_header,
                upgrade_header,
                inject_crlf,
                case_variations,
                extra_tokens,
            } => {
                fuzz_connection_upgrade_headers(
                    &connection_header,
                    &upgrade_header,
                    inject_crlf,
                    case_variations,
                    &extra_tokens,
                );
            }
            HandshakeParseOperation::ProtocolNegotiation {
                protocols,
                extensions,
                oversized_count,
                inject_control_chars,
                duplicate_protocols,
            } => {
                fuzz_protocol_negotiation(
                    &protocols,
                    &extensions,
                    oversized_count,
                    inject_control_chars,
                    duplicate_protocols,
                );
            }
            HandshakeParseOperation::HttpRequestBoundary {
                method,
                path,
                headers,
                malformed_headers,
                missing_terminator,
                oversized_headers,
                inject_null_bytes,
            } => {
                fuzz_http_request_parsing(
                    &method,
                    &path,
                    &headers,
                    malformed_headers,
                    missing_terminator,
                    oversized_headers,
                    inject_null_bytes,
                );
            }
            HandshakeParseOperation::HttpResponseBoundary {
                status_code,
                reason_phrase,
                headers,
                malformed_status_line,
                inject_response_splitting,
            } => {
                fuzz_http_response_parsing(
                    status_code,
                    &reason_phrase,
                    &headers,
                    malformed_status_line,
                    inject_response_splitting,
                );
            }
            HandshakeParseOperation::FullHandshakeFlow {
                url,
                client_protocols,
                client_extensions,
                server_protocols,
                server_extensions,
                mutate_accept_key,
                inject_extra_headers,
            } => {
                fuzz_full_handshake_flow(
                    &url,
                    &client_protocols,
                    &client_extensions,
                    &server_protocols,
                    &server_extensions,
                    mutate_accept_key,
                    inject_extra_headers,
                );
            }
            HandshakeParseOperation::UrlParsing {
                scheme,
                host,
                port,
                path,
                ipv6_brackets,
                malformed_components,
            } => {
                fuzz_url_parsing(
                    &scheme,
                    &host,
                    port,
                    &path,
                    ipv6_brackets,
                    malformed_components,
                );
            }
        }
    }
});

fn assert_known_handshake_outcomes() {
    let server = ServerHandshake::new().protocol("chat");
    let valid_request = b"GET /chat HTTP/1.1\r\n\
        Host: example.com\r\n\
        Upgrade: websocket\r\n\
        Connection: keep-alive, Upgrade\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\
        Sec-WebSocket-Protocol: chat\r\n\
        \r\n";
    let accept = expect_server_accept(&server, valid_request);
    assert_eq!(
        accept.accept_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        "RFC 6455 sample key must compute the sample accept key"
    );
    assert_eq!(
        accept.protocol.as_deref(),
        Some("chat"),
        "server must select an offered supported protocol"
    );

    let invalid_key_request = b"GET /chat HTTP/1.1\r\n\
        Host: example.com\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Key: not-a-valid-16-byte-key\r\n\
        Sec-WebSocket-Version: 13\r\n\
        \r\n";
    let invalid_key = expect_server_reject(&ServerHandshake::new(), invalid_key_request);
    assert!(
        matches!(invalid_key, HandshakeError::InvalidKey),
        "invalid Sec-WebSocket-Key must reject as InvalidKey"
    );

    let canary_url = match WsUrl::parse("ws://example.com/chat") {
        Ok(url) => url,
        Err(error) => panic!("canary URL must parse: {error:?}"),
    };
    let client = ClientHandshake::new_for_test(
        canary_url,
        "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
        Vec::new(),
        Vec::new(),
        BTreeMap::new(),
    );
    let valid_response = expect_response_parse(
        b"HTTP/1.1 101 Switching Protocols\r\n\
          Upgrade: websocket\r\n\
          Connection: Upgrade\r\n\
          Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
          \r\n",
    );
    assert!(
        client.validate_response(&valid_response).is_ok(),
        "valid server response must validate against the client key"
    );
    let invalid_response = expect_response_parse(
        b"HTTP/1.1 101 Switching Protocols\r\n\
          Upgrade: websocket\r\n\
          Connection: Upgrade\r\n\
          Sec-WebSocket-Accept: wrong-accept-key\r\n\
          \r\n",
    );
    let invalid_accept = match client.validate_response(&invalid_response) {
        Ok(()) => panic!("wrong accept key must fail validation"),
        Err(error) => error,
    };
    assert!(
        matches!(invalid_accept, HandshakeError::InvalidAccept { .. }),
        "wrong Sec-WebSocket-Accept must reject as InvalidAccept"
    );

    let url = expect_url_parse("wss://example.com:8443/socket");
    assert_eq!(url.host, "example.com");
    assert_eq!(url.port, 8443);
    assert_eq!(url.path, "/socket");
    assert!(url.tls);
}

fn expect_server_accept(server: &ServerHandshake, request_data: &[u8]) -> AcceptResponse {
    let request = expect_request_parse(request_data);
    let accept = server
        .accept(&request)
        .unwrap_or_else(|error| panic!("expected WebSocket request to be accepted: {error:?}"));
    assert!(
        !accept.accept_key.is_empty(),
        "accepted request must compute a non-empty accept key"
    );
    let response = accept.response_bytes();
    let parsed_response = expect_response_parse(&response);
    assert_eq!(
        parsed_response.status, 101,
        "accept response bytes must parse as HTTP 101"
    );
    accept
}

fn expect_server_reject(server: &ServerHandshake, request_data: &[u8]) -> HandshakeError {
    let request = expect_request_parse(request_data);
    match server.accept(&request) {
        Ok(_) => panic!("request must be rejected by the WebSocket server"),
        Err(error) => error,
    }
}

fn observe_server_accept(server: &ServerHandshake, request_data: &[u8]) {
    if let Ok(request) = HttpRequest::parse(request_data) {
        assert!(
            !request.method.is_empty(),
            "parsed HTTP request must contain a method"
        );
        assert!(
            !request.path.is_empty(),
            "parsed HTTP request must contain a path"
        );
        if let Ok(accept) = server.accept(&request) {
            assert!(
                !accept.accept_key.is_empty(),
                "accepted request must compute a non-empty accept key"
            );
            let response = accept.response_bytes();
            observe_response_parse(&response);
        }
    }
}

fn expect_request_parse(request_data: &[u8]) -> HttpRequest {
    let request = HttpRequest::parse(request_data)
        .unwrap_or_else(|error| panic!("expected HTTP request to parse: {error:?}"));
    assert!(
        !request.method.is_empty(),
        "parsed HTTP request must contain a method"
    );
    assert!(
        !request.path.is_empty(),
        "parsed HTTP request must contain a path"
    );
    request
}

fn observe_request_parse(request_data: &[u8]) {
    if let Ok(request) = HttpRequest::parse(request_data) {
        assert!(
            !request.method.is_empty(),
            "parsed HTTP request must contain a method"
        );
        assert!(
            !request.path.is_empty(),
            "parsed HTTP request must contain a path"
        );
    }
}

fn expect_response_parse(response_data: &[u8]) -> HttpResponse {
    let response = HttpResponse::parse(response_data)
        .unwrap_or_else(|error| panic!("expected HTTP response to parse: {error:?}"));
    assert!(
        response.status >= 100,
        "parsed HTTP response status must be at least 100"
    );
    response
}

fn observe_response_parse(response_data: &[u8]) {
    if let Ok(response) = HttpResponse::parse(response_data) {
        assert!(
            response.status >= 100,
            "parsed HTTP response status must be at least 100"
        );
    }
}

fn expect_url_parse(url: &str) -> WsUrl {
    let parsed = WsUrl::parse(url)
        .unwrap_or_else(|error| panic!("expected WebSocket URL to parse: {error:?}"));
    assert!(
        !parsed.host.is_empty(),
        "parsed WebSocket URL must contain a host"
    );
    assert!(
        parsed.path.starts_with('/'),
        "parsed WebSocket URL path must be absolute"
    );
    parsed
}

fn observe_url_parse(url: &str) {
    if let Ok(parsed) = WsUrl::parse(url) {
        assert!(
            !parsed.host.is_empty(),
            "parsed WebSocket URL must contain a host"
        );
        assert!(
            parsed.path.starts_with('/'),
            "parsed WebSocket URL path must be absolute"
        );
    }
}

/// Fuzz Sec-WebSocket-Key validation edge cases
fn fuzz_websocket_key_validation(
    key_data: &[u8],
    force_padding: Option<u8>,
    inject_invalid_chars: bool,
    mutate_length: Option<u8>,
) {
    use base64::Engine;

    let mut raw_key = key_data.to_vec();

    // Mutate length if requested
    if let Some(target_len) = mutate_length {
        raw_key.resize(usize::from(target_len), 0x42);
    }

    // Start with base64 encoding
    let mut encoded_key = base64::engine::general_purpose::STANDARD.encode(&raw_key);

    // Force specific padding patterns
    if let Some(padding_count) = force_padding {
        // Remove existing padding
        encoded_key = encoded_key.trim_end_matches('=').to_string();
        // Add requested padding
        for _ in 0..(padding_count & 0x3) {
            encoded_key.push('=');
        }
    }

    // Inject invalid base64 characters
    if inject_invalid_chars {
        encoded_key = encoded_key.replace('A', "!").replace('g', "@");
    }

    // Test server-side validation
    let server = ServerHandshake::new();
    let request_data = format!(
        "GET /test HTTP/1.1\r\n\
         Host: localhost\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n",
        encoded_key
    );

    observe_server_accept(&server, request_data.as_bytes());

    // Test edge case: extremely long keys
    if encoded_key.len() < 10000 {
        let oversized_key = encoded_key.repeat(100);
        let oversized_request = format!(
            "GET /test HTTP/1.1\r\n\
             Host: localhost\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n",
            oversized_key
        );
        observe_server_accept(&server, oversized_request.as_bytes());
    }
}

/// Fuzz Connection/Upgrade header parsing for injection vulnerabilities
fn fuzz_connection_upgrade_headers(
    connection_header: &[u8],
    upgrade_header: &[u8],
    inject_crlf: bool,
    case_variations: bool,
    extra_tokens: &[String],
) {
    let mut connection = String::from_utf8_lossy(connection_header).to_string();
    let mut upgrade = String::from_utf8_lossy(upgrade_header).to_string();

    // Test CRLF injection attempts
    if inject_crlf {
        connection = format!("{}\r\nX-Injected: evil", connection);
        upgrade = format!("{}\n\nSet-Cookie: malicious", upgrade);
    }

    // Add extra tokens to test parsing robustness
    if !extra_tokens.is_empty() {
        let extra = extra_tokens.join(", ");
        connection = format!("{}, {}", connection, extra);
    }

    // Test case variation handling
    if case_variations {
        connection = connection.to_uppercase();
        upgrade = upgrade.to_ascii_lowercase();
    }

    let server = ServerHandshake::new();
    let request_data = format!(
        "GET /test HTTP/1.1\r\n\
         Host: localhost\r\n\
         Upgrade: {}\r\n\
         Connection: {}\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n",
        upgrade, connection
    );

    observe_server_accept(&server, request_data.as_bytes());
}

/// Fuzz protocol and extension negotiation with malicious payloads
fn fuzz_protocol_negotiation(
    protocols: &[String],
    extensions: &[String],
    oversized_count: u8,
    inject_control_chars: bool,
    duplicate_protocols: bool,
) {
    let mut test_protocols = protocols.to_vec();
    let mut test_extensions = extensions.to_vec();

    // Generate oversized protocol/extension lists
    for i in 0..oversized_count {
        let proto_name = format!("protocol-{}", i);
        let ext_name = format!("extension-{};param={}", i, i);
        test_protocols.push(proto_name);
        test_extensions.push(ext_name);
    }

    // Add duplicates to test deduplication logic
    if duplicate_protocols && !test_protocols.is_empty() {
        let first = test_protocols[0].clone();
        test_protocols.push(first.clone());
        test_protocols.push(first);
    }

    // Inject control characters to test sanitization
    if inject_control_chars {
        test_protocols = test_protocols
            .iter()
            .map(|p| format!("{}\r\n{}", p, p))
            .collect();
        test_extensions = test_extensions
            .iter()
            .map(|e| format!("{}\x00{}", e, e))
            .collect();
    }

    // Create server with subset of protocols/extensions
    let mut server = ServerHandshake::new();
    for proto in test_protocols.iter().take(5) {
        server = server.protocol(proto);
    }
    for ext in test_extensions.iter().take(3) {
        server = server.extension(ext);
    }

    let protocol_header = test_protocols.join(", ");
    let extension_header = test_extensions.join(", ");

    let request_data = format!(
        "GET /test HTTP/1.1\r\n\
         Host: localhost\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: {}\r\n\
         Sec-WebSocket-Extensions: {}\r\n\r\n",
        protocol_header, extension_header
    );

    observe_server_accept(&server, request_data.as_bytes());
}

/// Fuzz HTTP request parsing boundary conditions
fn fuzz_http_request_parsing(
    method: &str,
    path: &str,
    headers: &[(String, String)],
    malformed_headers: bool,
    missing_terminator: bool,
    oversized_headers: u8,
    inject_null_bytes: bool,
) {
    let mut request_data = format!("{} {} HTTP/1.1\r\n", method, path);

    // Add normal headers
    for (name, value) in headers {
        let mut header_name = name.clone();
        let mut header_value = value.clone();

        if inject_null_bytes {
            header_name = header_name.replace('\0', "\\0");
            header_value = header_value.replace('\0', "");
        }

        if malformed_headers {
            // Test various malformed header patterns
            match (name.len() + value.len()) % 4 {
                0 => request_data.push_str(&format!("{}\r\n", header_name)), // Missing colon
                1 => request_data.push_str(&format!(":{}\r\n", header_value)), // Missing name
                2 => request_data.push_str(&format!("{}:{}\n", header_name, header_value)), // Wrong terminator
                _ => request_data.push_str(&format!("{}:{}\r\n", header_name, header_value)),
            }
        } else {
            request_data.push_str(&format!("{}: {}\r\n", header_name, header_value));
        }
    }

    // Generate oversized header count
    for i in 0..oversized_headers {
        request_data.push_str(&format!("X-Generated-{}: value-{}\r\n", i, i));
    }

    // Add terminator (or not)
    if !missing_terminator {
        request_data.push_str("\r\n");
    }

    observe_request_parse(request_data.as_bytes());
}

/// Fuzz HTTP response parsing for client-side validation
fn fuzz_http_response_parsing(
    status_code: u16,
    reason_phrase: &str,
    headers: &[(String, String)],
    malformed_status_line: bool,
    inject_response_splitting: bool,
) {
    let mut response_data = if malformed_status_line {
        // Test various malformed status line patterns
        match status_code % 4 {
            0 => format!("HTTP/1.1 {} {}\r\n", status_code, reason_phrase),
            1 => format!("HTTP/2.0 {}\r\n", status_code), // Wrong version, missing reason
            2 => format!("{} {}\r\n", status_code, reason_phrase), // Missing HTTP version
            _ => format!("INVALID {} {}\r\n", status_code, reason_phrase), // Invalid version
        }
    } else {
        format!("HTTP/1.1 {} {}\r\n", status_code, reason_phrase)
    };

    // Add headers with potential response splitting
    for (name, value) in headers {
        let mut header_value = value.clone();

        if inject_response_splitting {
            header_value = format!("{}\r\nX-Injected: malicious", header_value);
        }

        response_data.push_str(&format!("{}: {}\r\n", name, header_value));
    }

    response_data.push_str("\r\n");

    observe_response_parse(response_data.as_bytes());
}

/// Fuzz complete handshake flow with mutations
fn fuzz_full_handshake_flow(
    url: &str,
    client_protocols: &[String],
    client_extensions: &[String],
    server_protocols: &[String],
    server_extensions: &[String],
    mutate_accept_key: bool,
    inject_extra_headers: bool,
) {
    // Create client handshake with deterministic entropy for reproducibility
    let entropy = DetEntropy::new(12345);

    // Test URL parsing first
    if let Ok(parsed_url) = WsUrl::parse(url) {
        let test_url = format!(
            "{}://{}:{}{}",
            if parsed_url.tls { "wss" } else { "ws" },
            parsed_url.host,
            parsed_url.port,
            parsed_url.path
        );

        if let Ok(mut client) = ClientHandshake::new(&test_url, &entropy) {
            // Add protocols and extensions
            for protocol in client_protocols {
                client = client.protocol(protocol);
            }
            for extension in client_extensions {
                client = client.extension(extension);
            }

            // Create server
            let mut server = ServerHandshake::new();
            for protocol in server_protocols {
                server = server.protocol(protocol);
            }
            for extension in server_extensions {
                server = server.extension(extension);
            }

            // Generate client request
            let request_bytes = client.request_bytes();

            // Parse and process on server
            if let Ok(request) = HttpRequest::parse(&request_bytes)
                && let Ok(mut accept) = server.accept(&request)
            {
                // Potentially mutate accept key
                if mutate_accept_key {
                    accept.accept_key = "invalid-accept-key".to_string();
                }

                let mut response_bytes = accept.response_bytes();

                // Inject extra headers
                if inject_extra_headers {
                    let injection = b"X-Malicious: value\r\n";
                    let mut modified = response_bytes.clone();
                    modified.extend_from_slice(injection);
                    response_bytes = modified;
                }

                // Parse response on client and validate
                if let Ok(response) = HttpResponse::parse(&response_bytes) {
                    let _ = client.validate_response(&response);
                }
            }
        }
    }
}

/// Fuzz URL parsing edge cases
fn fuzz_url_parsing(
    scheme: &str,
    host: &str,
    port: Option<u16>,
    path: &str,
    ipv6_brackets: bool,
    malformed_components: bool,
) {
    let mut test_host = host.to_string();

    // Test IPv6 bracket handling
    if ipv6_brackets && !test_host.starts_with('[') {
        test_host = format!("[{}]", test_host);
    }

    // Add port if specified
    let host_port = if let Some(port_num) = port {
        format!("{}:{}", test_host, port_num)
    } else {
        test_host
    };

    // Construct URL with potential malformation
    let url = if malformed_components {
        // Test various malformed URL patterns
        match scheme.len() % 4 {
            0 => format!("{}://{}{}", scheme, host_port, path),
            1 => format!("{}:/{}{}", scheme, host_port, path), // Missing slash
            2 => format!("{}{}{}", scheme, host_port, path),   // Missing ://
            _ => format!("{}:///{}", scheme, path),            // Missing host
        }
    } else {
        format!("{}://{}{}", scheme, host_port, path)
    };

    observe_url_parse(&url);

    // Test extremely long URLs
    if url.len() < 1000 {
        let long_path = "/".to_string() + &"x".repeat(5000);
        let long_url = format!("{}://{}{}", scheme, host_port, long_path);
        observe_url_parse(&long_url);
    }
}
