//! WebSocket Handshake Conformance Tests (RFC 6455 Section 4)
//!
//! Comprehensive conformance tests for WebSocket opening handshake per RFC 6455
//! Section 4. Tests validate critical security assertions and protocol compliance.
//!
//! # Test Coverage
//!
//! 1. Sec-WebSocket-Key validation + Sec-WebSocket-Accept derivation
//! 2. Sec-WebSocket-Version must be 13
//! 3. Upgrade: websocket + Connection: Upgrade required
//! 4. Subprotocol negotiation (Sec-WebSocket-Protocol)
//! 5. Extension negotiation (permessage-deflate)
//! 6. Status 101 Switching Protocols response

use asupersync::net::websocket::handshake::{
    ClientHandshake, ServerHandshake, HttpRequest, HttpResponse, HandshakeError,
    WsUrl, compute_accept_key,
};
use asupersync::util::DetEntropy;

/// Test comprehensive Sec-WebSocket-Key validation and Sec-WebSocket-Accept derivation
/// per RFC 6455 Section 4.2.2
#[test]
fn test_rfc6455_sec_websocket_key_accept_derivation() {
    // RFC 6455 Section 4.2.2 test vector
    let client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    let expected_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    // Test 1: Verify accept key computation is correct
    let computed_accept = compute_accept_key(client_key);
    assert_eq!(computed_accept, expected_accept,
        "Sec-WebSocket-Accept computation must match RFC 6455 test vector");

    // Test 2: Server validates and computes accept key correctly
    let server = ServerHandshake::new();
    let request_data = format!(
        "GET /test HTTP/1.1\r\n\
         Host: localhost\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n",
        client_key
    );

    let request = HttpRequest::parse(request_data.as_bytes())
        .expect("Valid request should parse");

    let accept = server.accept(&request)
        .expect("Server should accept valid request with correct key");

    assert_eq!(accept.accept_key, expected_accept,
        "Server-computed accept key must match RFC test vector");

    // Test 3: Client validates server response accept key
    let entropy = DetEntropy::new(42);
    let handshake = ClientHandshake::new("ws://localhost/test", &entropy)
        .expect("Client handshake should initialize");

    // Create client with known key for deterministic testing
    let client_with_test_key = ClientHandshake {
        url: WsUrl::parse("ws://localhost/test").unwrap(),
        key: client_key.to_string(),
        protocols: vec![],
        extensions: vec![],
        headers: std::collections::BTreeMap::new(),
    };

    let response_data = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        expected_accept
    );

    let response = HttpResponse::parse(response_data.as_bytes())
        .expect("Valid response should parse");

    client_with_test_key.validate_response(&response)
        .expect("Client should validate correct accept key");

    // Test 4: Invalid accept key should be rejected
    let invalid_response_data = "HTTP/1.1 101 Switching Protocols\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Accept: invalid-accept-key\r\n\r\n";

    let invalid_response = HttpResponse::parse(invalid_response_data.as_bytes())
        .expect("Invalid response should parse");

    let validation_result = client_with_test_key.validate_response(&invalid_response);
    assert!(validation_result.is_err(),
        "Client should reject invalid accept key");

    if let Err(HandshakeError::InvalidAccept { .. }) = validation_result {
        // Correct error type
    } else {
        panic!("Should fail with InvalidAccept error: {:?}", validation_result);
    }
}

/// Test comprehensive 16-byte Sec-WebSocket-Key validation per RFC 6455 Section 4.1
#[test]
fn test_rfc6455_sec_websocket_key_validation() {
    let server = ServerHandshake::new();

    // Test 1: Valid 16-byte keys should be accepted
    let valid_keys = vec![
        "dGhlIHNhbXBsZSBub25jZQ==", // RFC 6455 example
        "AQIDBAUGBwgJCgsMDQ4PEA==", // Sequential bytes 0x01-0x10
        "AAAAAAAAAAAAAAAAAAAAAA==", // All zero bytes
        "////////////////////",     // All 0xFF bytes
    ];

    for (i, key) in valid_keys.iter().enumerate() {
        let request_data = format!(
            "GET /test HTTP/1.1\r\n\
             Host: localhost\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n",
            key
        );

        let request = HttpRequest::parse(request_data.as_bytes())
            .expect(&format!("Valid request {} should parse", i));

        let result = server.accept(&request);
        assert!(result.is_ok(),
            "Valid 16-byte key #{} should be accepted: '{}', error: {:?}",
            i, key, result.unwrap_err());

        // Verify the key decodes to exactly 16 bytes
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(key)
            .expect("Valid key should decode");
        assert_eq!(decoded.len(), 16,
            "Key #{} should decode to exactly 16 bytes", i);
    }

    // Test 2: Invalid keys should be rejected with InvalidKey error
    let invalid_keys = vec![
        ("", "empty key"),
        ("dGhlIHNhbXBsZSBub25jZQ", "missing padding"),
        ("dGhlIHNhbXBsZSBub25jZGQ=", "17 bytes"),
        ("MTIzNA==", "only 4 bytes"),
        ("!@#$%^&*()_+", "invalid base64 characters"),
        ("dGhlIHNhbXBsZSBub25jZGRkZGRk", "too many bytes"),
    ];

    for (key, description) in invalid_keys {
        let request_data = format!(
            "GET /test HTTP/1.1\r\n\
             Host: localhost\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n",
            key
        );

        let request = HttpRequest::parse(request_data.as_bytes())
            .expect(&format!("Request should parse for {}", description));

        let result = server.accept(&request);
        assert!(result.is_err(),
            "Invalid key should be rejected: {} ({})", key, description);

        if let Err(error) = result {
            assert!(matches!(error, HandshakeError::InvalidKey),
                "Should fail with InvalidKey for {}: got {:?}", description, error);
        }
    }
}

/// Test Sec-WebSocket-Version enforcement per RFC 6455 Section 4.1
#[test]
fn test_rfc6455_sec_websocket_version_must_be_13() {
    let server = ServerHandshake::new();

    // Test 1: Version 13 should be accepted
    let valid_request = "GET /test HTTP/1.1\r\n\
        Host: localhost\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\r\n";

    let request = HttpRequest::parse(valid_request.as_bytes())
        .expect("Version 13 request should parse");

    let result = server.accept(&request);
    assert!(result.is_ok(),
        "WebSocket version 13 should be accepted: {:?}", result.unwrap_err());

    // Test 2: Other versions should be rejected
    let invalid_versions = vec![
        ("12", "Draft version 12"),
        ("8", "Draft version 8"),
        ("0", "Invalid version 0"),
        ("14", "Future version 14"),
        ("", "Empty version"),
        ("thirteen", "Non-numeric version"),
    ];

    for (version, description) in invalid_versions {
        let request_data = format!(
            "GET /test HTTP/1.1\r\n\
             Host: localhost\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: {}\r\n\r\n",
            version
        );

        let request = HttpRequest::parse(request_data.as_bytes())
            .expect(&format!("Request should parse for {}", description));

        let result = server.accept(&request);
        assert!(result.is_err(),
            "Version {} should be rejected ({})", version, description);

        if let Err(error) = result {
            assert!(matches!(error, HandshakeError::UnsupportedVersion(_)),
                "Should fail with UnsupportedVersion for {}: got {:?}", description, error);
        }
    }

    // Test 3: Missing version header should be rejected
    let no_version_request = "GET /test HTTP/1.1\r\n\
        Host: localhost\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";

    let request = HttpRequest::parse(no_version_request.as_bytes())
        .expect("No version request should parse");

    let result = server.accept(&request);
    assert!(result.is_err(),
        "Missing Sec-WebSocket-Version header should be rejected");

    if let Err(error) = result {
        assert!(matches!(error, HandshakeError::MissingHeader("Sec-WebSocket-Version")),
            "Should fail with MissingHeader for Sec-WebSocket-Version: got {:?}", error);
    }
}

/// Test Upgrade and Connection header requirements per RFC 6455 Section 4.1
#[test]
fn test_rfc6455_upgrade_connection_headers_required() {
    let server = ServerHandshake::new();

    // Test 1: Both headers present should succeed
    let valid_request = "GET /test HTTP/1.1\r\n\
        Host: localhost\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\r\n";

    let request = HttpRequest::parse(valid_request.as_bytes())
        .expect("Valid headers request should parse");

    let result = server.accept(&request);
    assert!(result.is_ok(),
        "Valid Upgrade and Connection headers should be accepted: {:?}", result.unwrap_err());

    // Test 2: Missing Upgrade header
    let no_upgrade_request = "GET /test HTTP/1.1\r\n\
        Host: localhost\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\r\n";

    let request = HttpRequest::parse(no_upgrade_request.as_bytes())
        .expect("No upgrade request should parse");

    let result = server.accept(&request);
    assert!(result.is_err(),
        "Missing Upgrade header should be rejected");

    if let Err(error) = result {
        assert!(matches!(error, HandshakeError::MissingHeader("Upgrade")),
            "Should fail with MissingHeader for Upgrade: got {:?}", error);
    }

    // Test 3: Missing Connection header
    let no_connection_request = "GET /test HTTP/1.1\r\n\
        Host: localhost\r\n\
        Upgrade: websocket\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\r\n";

    let request = HttpRequest::parse(no_connection_request.as_bytes())
        .expect("No connection request should parse");

    let result = server.accept(&request);
    assert!(result.is_err(),
        "Missing Connection header should be rejected");

    if let Err(error) = result {
        assert!(matches!(error, HandshakeError::MissingHeader("Connection")),
            "Should fail with MissingHeader for Connection: got {:?}", error);
    }

    // Test 4: Invalid Upgrade header value
    let invalid_upgrade_request = "GET /test HTTP/1.1\r\n\
        Host: localhost\r\n\
        Upgrade: http2\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\r\n";

    let request = HttpRequest::parse(invalid_upgrade_request.as_bytes())
        .expect("Invalid upgrade request should parse");

    let result = server.accept(&request);
    assert!(result.is_err(),
        "Invalid Upgrade header value should be rejected");

    if let Err(error) = result {
        assert!(matches!(error, HandshakeError::InvalidRequest(_)),
            "Should fail with InvalidRequest for wrong Upgrade: got {:?}", error);
    }

    // Test 5: Invalid Connection header value
    let invalid_connection_request = "GET /test HTTP/1.1\r\n\
        Host: localhost\r\n\
        Upgrade: websocket\r\n\
        Connection: keep-alive\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\r\n";

    let request = HttpRequest::parse(invalid_connection_request.as_bytes())
        .expect("Invalid connection request should parse");

    let result = server.accept(&request);
    assert!(result.is_err(),
        "Invalid Connection header value should be rejected");

    if let Err(error) = result {
        assert!(matches!(error, HandshakeError::InvalidRequest(_)),
            "Should fail with InvalidRequest for wrong Connection: got {:?}", error);
    }

    // Test 6: Case-insensitive header values (should work)
    let case_insensitive_request = "GET /test HTTP/1.1\r\n\
        Host: localhost\r\n\
        Upgrade: WebSocket\r\n\
        Connection: UPGRADE\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\r\n";

    let request = HttpRequest::parse(case_insensitive_request.as_bytes())
        .expect("Case insensitive request should parse");

    let result = server.accept(&request);
    assert!(result.is_ok(),
        "Case-insensitive header values should be accepted: {:?}", result.unwrap_err());

    // Test 7: Multiple header values (comma-separated) should work
    let multi_value_request = "GET /test HTTP/1.1\r\n\
        Host: localhost\r\n\
        Upgrade: h2c, websocket\r\n\
        Connection: keep-alive, Upgrade\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\r\n";

    let request = HttpRequest::parse(multi_value_request.as_bytes())
        .expect("Multi-value request should parse");

    let result = server.accept(&request);
    assert!(result.is_ok(),
        "Multi-value headers containing correct tokens should be accepted: {:?}", result.unwrap_err());
}

/// Test comprehensive subprotocol negotiation per RFC 6455 Section 4.1
#[test]
fn test_rfc6455_subprotocol_negotiation() {
    // Test 1: Server selects first matching protocol from client list
    let server = ServerHandshake::new()
        .protocol("chat")
        .protocol("superchat")
        .protocol("echo");

    let request_data = "GET /test HTTP/1.1\r\n\
        Host: localhost\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\
        Sec-WebSocket-Protocol: superchat, chat, echo\r\n\r\n";

    let request = HttpRequest::parse(request_data.as_bytes())
        .expect("Protocol negotiation request should parse");

    let accept = server.accept(&request)
        .expect("Protocol negotiation should succeed");

    assert_eq!(accept.protocol, Some("superchat".to_string()),
        "Server should select first matching protocol from client preference order");

    // Test 2: No protocol requested, server has protocols - should succeed without protocol
    let request_data = "GET /test HTTP/1.1\r\n\
        Host: localhost\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\r\n";

    let request = HttpRequest::parse(request_data.as_bytes())
        .expect("No protocol request should parse");

    let accept = server.accept(&request)
        .expect("Should accept connection without protocol when client doesn't request any");

    assert_eq!(accept.protocol, None,
        "Should not select protocol when client doesn't request any");

    // Test 3: Client requests protocols server doesn't support - should still accept
    let server_limited = ServerHandshake::new().protocol("private-protocol");

    let request_data = "GET /test HTTP/1.1\r\n\
        Host: localhost\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\
        Sec-WebSocket-Protocol: chat, superchat, echo\r\n\r\n";

    let request = HttpRequest::parse(request_data.as_bytes())
        .expect("Unsupported protocol request should parse");

    let result = server_limited.accept(&request);
    assert!(result.is_ok(),
        "Should accept connection even when no protocols match");

    let accept = result.unwrap();
    assert_eq!(accept.protocol, None,
        "Should not select any protocol when no match found");

    // Test 4: Client-side validation - server selects unrecquested protocol
    let entropy = DetEntropy::new(42);
    let client = ClientHandshake::new("ws://localhost/test", &entropy)
        .expect("Client should initialize")
        .protocol("chat")
        .protocol("echo");

    let response_with_wrong_protocol = "HTTP/1.1 101 Switching Protocols\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
        Sec-WebSocket-Protocol: superchat\r\n\r\n";

    // Need to create client with fixed key for this test
    let client_with_test_key = ClientHandshake {
        url: WsUrl::parse("ws://localhost/test").unwrap(),
        key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
        protocols: vec!["chat".to_string(), "echo".to_string()],
        extensions: vec![],
        headers: std::collections::BTreeMap::new(),
    };

    let response = HttpResponse::parse(response_with_wrong_protocol.as_bytes())
        .expect("Response should parse");

    let validation_result = client_with_test_key.validate_response(&response);
    assert!(validation_result.is_err(),
        "Client should reject unrequested protocol");

    if let Err(HandshakeError::ProtocolMismatch { .. }) = validation_result {
        // Correct error type
    } else {
        panic!("Should fail with ProtocolMismatch: {:?}", validation_result);
    }

    // Test 5: Protocol parsing edge cases
    let protocol_test_cases = vec![
        ("chat", "chat"),
        ("chat, superchat", "chat"), // First in list
        ("  chat  ,  superchat  ", "chat"), // Whitespace handling
        ("superchat,chat,echo", "superchat"), // No spaces
        ("unknown, chat, unknown2", "chat"), // Mixed known/unknown
    ];

    let server_chat = ServerHandshake::new().protocol("chat");

    for (protocol_header, expected) in protocol_test_cases {
        let request_data = format!(
            "GET /test HTTP/1.1\r\n\
             Host: localhost\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Protocol: {}\r\n\r\n",
            protocol_header
        );

        let request = HttpRequest::parse(request_data.as_bytes())
            .expect(&format!("Protocol header '{}' should parse", protocol_header));

        let accept = server_chat.accept(&request)
            .expect(&format!("Protocol negotiation should succeed for '{}'", protocol_header));

        assert_eq!(accept.protocol, Some(expected.to_string()),
            "Protocol header '{}' should select '{}'", protocol_header, expected);
    }
}

/// Test permessage-deflate extension negotiation per RFC 6455 Section 9
#[test]
fn test_rfc6455_permessage_deflate_extension_negotiation() {
    // Test 1: Server supports extension, client requests it
    let server = ServerHandshake::new()
        .extension("permessage-deflate");

    let request_data = "GET /test HTTP/1.1\r\n\
        Host: localhost\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\
        Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n";

    let request = HttpRequest::parse(request_data.as_bytes())
        .expect("Extension request should parse");

    let accept = server.accept(&request)
        .expect("Extension negotiation should succeed");

    assert!(!accept.extensions.is_empty(),
        "Server should negotiate permessage-deflate extension");
    assert_eq!(accept.extensions[0], "permessage-deflate",
        "Should accept permessage-deflate extension");

    // Test 2: Extension with parameters
    let request_with_params = "GET /test HTTP/1.1\r\n\
        Host: localhost\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\
        Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n";

    let request = HttpRequest::parse(request_with_params.as_bytes())
        .expect("Extension with parameters should parse");

    let accept = server.accept(&request)
        .expect("Extension with parameters should be accepted");

    assert!(!accept.extensions.is_empty(),
        "Server should negotiate extension with parameters");
    assert!(accept.extensions[0].contains("permessage-deflate"),
        "Extension should be permessage-deflate variant");

    // Test 3: Multiple extensions
    let server_multi = ServerHandshake::new()
        .extension("permessage-deflate")
        .extension("x-webkit-deflate-frame");

    let request_multi = "GET /test HTTP/1.1\r\n\
        Host: localhost\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\
        Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits, x-webkit-deflate-frame\r\n\r\n";

    let request = HttpRequest::parse(request_multi.as_bytes())
        .expect("Multiple extensions should parse");

    let accept = server_multi.accept(&request)
        .expect("Multiple extensions should be negotiated");

    assert_eq!(accept.extensions.len(), 2,
        "Should negotiate multiple extensions");

    // Test 4: Client requests unsupported extension
    let server_limited = ServerHandshake::new()
        .extension("x-other-extension");

    let request_unsupported = "GET /test HTTP/1.1\r\n\
        Host: localhost\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\
        Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n";

    let request = HttpRequest::parse(request_unsupported.as_bytes())
        .expect("Unsupported extension should parse");

    let result = server_limited.accept(&request);
    assert!(result.is_ok(),
        "Should accept connection even with unsupported extensions");

    let accept = result.unwrap();
    assert!(accept.extensions.is_empty(),
        "Should not negotiate unsupported extensions");

    // Test 5: Client-side extension validation
    let entropy = DetEntropy::new(42);
    let client_with_test_key = ClientHandshake {
        url: WsUrl::parse("ws://localhost/test").unwrap(),
        key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
        protocols: vec![],
        extensions: vec!["permessage-deflate".to_string()],
        headers: std::collections::BTreeMap::new(),
    };

    // Server responds with unrequested extension
    let response_unrequested = "HTTP/1.1 101 Switching Protocols\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
        Sec-WebSocket-Extensions: x-unrequested-extension\r\n\r\n";

    let response = HttpResponse::parse(response_unrequested.as_bytes())
        .expect("Response should parse");

    let validation_result = client_with_test_key.validate_response(&response);
    assert!(validation_result.is_err(),
        "Client should reject unrequested extensions");

    if let Err(HandshakeError::ExtensionMismatch { .. }) = validation_result {
        // Correct error type
    } else {
        panic!("Should fail with ExtensionMismatch: {:?}", validation_result);
    }

    // Test 6: Server responds with requested extension
    let response_requested = "HTTP/1.1 101 Switching Protocols\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
        Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n";

    let response = HttpResponse::parse(response_requested.as_bytes())
        .expect("Valid extension response should parse");

    let validation_result = client_with_test_key.validate_response(&response);
    assert!(validation_result.is_ok(),
        "Client should accept requested extensions: {:?}", validation_result.unwrap_err());
}

/// Test status 101 Switching Protocols response per RFC 6455 Section 4.2.2
#[test]
fn test_rfc6455_status_101_switching_protocols() {
    let server = ServerHandshake::new().protocol("chat");

    // Test 1: Successful handshake generates 101 response
    let valid_request = "GET /test HTTP/1.1\r\n\
        Host: localhost\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\
        Sec-WebSocket-Protocol: chat\r\n\r\n";

    let request = HttpRequest::parse(valid_request.as_bytes())
        .expect("Valid request should parse");

    let accept = server.accept(&request)
        .expect("Valid request should be accepted");

    let response_bytes = accept.response_bytes();
    let response_str = String::from_utf8_lossy(&response_bytes);

    // Verify 101 status line
    assert!(response_str.starts_with("HTTP/1.1 101 Switching Protocols"),
        "Response should start with HTTP/1.1 101 Switching Protocols");

    // Verify required headers are present
    assert!(response_str.contains("Upgrade: websocket"),
        "Response should contain Upgrade: websocket header");
    assert!(response_str.contains("Connection: Upgrade"),
        "Response should contain Connection: Upgrade header");
    assert!(response_str.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        "Response should contain correct Sec-WebSocket-Accept header");
    assert!(response_str.contains("Sec-WebSocket-Protocol: chat"),
        "Response should contain negotiated protocol");

    // Verify response format
    assert!(response_str.ends_with("\r\n\r\n"),
        "Response should end with CRLF CRLF");

    // Test 2: Client validates status code
    let entropy = DetEntropy::new(42);
    let client_with_test_key = ClientHandshake {
        url: WsUrl::parse("ws://localhost/test").unwrap(),
        key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
        protocols: vec!["chat".to_string()],
        extensions: vec![],
        headers: std::collections::BTreeMap::new(),
    };

    // Parse the server response and validate it
    let response = HttpResponse::parse(&response_bytes)
        .expect("Server response should parse");

    let validation_result = client_with_test_key.validate_response(&response);
    assert!(validation_result.is_ok(),
        "Client should validate 101 response: {:?}", validation_result.unwrap_err());

    // Test 3: Non-101 status codes should be rejected by client
    let invalid_status_codes = vec![
        (200, "OK"),
        (400, "Bad Request"),
        (404, "Not Found"),
        (426, "Upgrade Required"),
        (500, "Internal Server Error"),
    ];

    for (status_code, status_text) in invalid_status_codes {
        let invalid_response = format!(
            "HTTP/1.1 {} {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            status_code, status_text
        );

        let response = HttpResponse::parse(invalid_response.as_bytes())
            .expect(&format!("Response with status {} should parse", status_code));

        let validation_result = client_with_test_key.validate_response(&response);
        assert!(validation_result.is_err(),
            "Client should reject status code {}", status_code);

        if let Err(HandshakeError::NotSwitchingProtocols(code)) = validation_result {
            assert_eq!(code, status_code,
                "Error should report correct status code");
        } else {
            panic!("Should fail with NotSwitchingProtocols for status {}: got {:?}",
                status_code, validation_result);
        }
    }

    // Test 4: Response must have all required headers
    let client_simple = ClientHandshake {
        url: WsUrl::parse("ws://localhost/test").unwrap(),
        key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
        protocols: vec![],
        extensions: vec![],
        headers: std::collections::BTreeMap::new(),
    };

    let missing_header_tests = vec![
        // (response, missing_header, description)
        (
            "HTTP/1.1 101 Switching Protocols\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            "Upgrade",
            "Missing Upgrade header"
        ),
        (
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            "Connection",
            "Missing Connection header"
        ),
        (
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\r\n",
            "Sec-WebSocket-Accept",
            "Missing Sec-WebSocket-Accept header"
        ),
    ];

    for (response_data, expected_header, description) in missing_header_tests {
        let response = HttpResponse::parse(response_data.as_bytes())
            .expect(&format!("Response should parse: {}", description));

        let validation_result = client_simple.validate_response(&response);
        assert!(validation_result.is_err(),
            "Should reject response: {}", description);

        if let Err(HandshakeError::MissingHeader(header)) = validation_result {
            assert_eq!(header, expected_header,
                "Should report missing header: {}", description);
        } else {
            panic!("Should fail with MissingHeader for {}: got {:?}",
                description, validation_result);
        }
    }
}

/// Test comprehensive end-to-end handshake flow
#[test]
fn test_rfc6455_end_to_end_handshake_flow() {
    // Create client and server
    let entropy = DetEntropy::new(12345);
    let client = ClientHandshake::new("ws://localhost:8080/socket", &entropy)
        .expect("Client should initialize")
        .protocol("chat")
        .protocol("echo")
        .extension("permessage-deflate");

    let server = ServerHandshake::new()
        .protocol("echo")
        .protocol("chat")  // Different order than client
        .extension("permessage-deflate");

    // Generate client request
    let request_bytes = client.request_bytes();
    let request_str = String::from_utf8_lossy(&request_bytes);

    // Verify client request format
    assert!(request_str.contains("GET /socket HTTP/1.1"));
    assert!(request_str.contains("Host: localhost:8080"));
    assert!(request_str.contains("Upgrade: websocket"));
    assert!(request_str.contains("Connection: Upgrade"));
    assert!(request_str.contains("Sec-WebSocket-Key: "));
    assert!(request_str.contains("Sec-WebSocket-Version: 13"));
    assert!(request_str.contains("Sec-WebSocket-Protocol: chat, echo"));
    assert!(request_str.contains("Sec-WebSocket-Extensions: permessage-deflate"));

    // Parse request on server side
    let request = HttpRequest::parse(&request_bytes)
        .expect("Client request should parse on server");

    // Server accepts request
    let accept = server.accept(&request)
        .expect("Server should accept valid client request");

    // Verify protocol negotiation (server should pick first match from client list)
    assert_eq!(accept.protocol, Some("chat".to_string()),
        "Server should select first client protocol it supports");

    // Verify extension negotiation
    assert!(!accept.extensions.is_empty(),
        "Server should negotiate permessage-deflate extension");

    // Generate server response
    let response_bytes = accept.response_bytes();
    let response_str = String::from_utf8_lossy(&response_bytes);

    // Verify server response format
    assert!(response_str.contains("HTTP/1.1 101 Switching Protocols"));
    assert!(response_str.contains(&format!("Sec-WebSocket-Accept: {}", accept.accept_key)));
    assert!(response_str.contains("Sec-WebSocket-Protocol: chat"));
    assert!(response_str.contains("Sec-WebSocket-Extensions: permessage-deflate"));

    // Parse response on client side
    let response = HttpResponse::parse(&response_bytes)
        .expect("Server response should parse on client");

    // Client validates response
    let validation_result = client.validate_response(&response);
    assert!(validation_result.is_ok(),
        "Client should validate server response: {:?}", validation_result.unwrap_err());

    // Verify accept key computation is correct
    let expected_accept = compute_accept_key(client.key());
    assert_eq!(accept.accept_key, expected_accept,
        "Server accept key should match computed value");
}

/// Test comprehensive error handling and edge cases
#[test]
fn test_rfc6455_error_handling_edge_cases() {
    let server = ServerHandshake::new();

    // Test 1: HTTP method must be GET
    let post_request = "POST /test HTTP/1.1\r\n\
        Host: localhost\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\r\n";

    let request = HttpRequest::parse(post_request.as_bytes())
        .expect("POST request should parse");

    let result = server.accept(&request);
    assert!(result.is_err(),
        "POST method should be rejected");

    if let Err(HandshakeError::InvalidRequest(_)) = result {
        // Correct error type
    } else {
        panic!("Should fail with InvalidRequest for POST method: {:?}", result);
    }

    // Test 2: Malformed HTTP request
    let malformed_requests = vec![
        b"NOT HTTP\r\n\r\n",
        b"GET\r\n\r\n", // Missing path and version
        b"", // Empty request
    ];

    for (i, malformed) in malformed_requests.iter().enumerate() {
        let result = HttpRequest::parse(malformed);
        if i == 2 {
            // Empty request should fail to parse
            assert!(result.is_err(),
                "Empty request should fail to parse");
        } else if let Ok(request) = result {
            // If it parses, server should reject it
            let server_result = server.accept(&request);
            assert!(server_result.is_err(),
                "Malformed request {} should be rejected by server", i);
        }
    }

    // Test 3: Missing critical headers
    let incomplete_request = "GET /test HTTP/1.1\r\nHost: localhost\r\n";

    let result = HttpRequest::parse(incomplete_request.as_bytes());
    assert!(result.is_err(),
        "Incomplete request without CRLF termination should fail to parse");

    // Test 4: Server rejection helper
    let rejection = ServerHandshake::reject(400, "Bad Request");
    let rejection_str = String::from_utf8_lossy(&rejection);

    assert!(rejection_str.contains("HTTP/1.1 400 Bad Request"));
    assert!(rejection_str.contains("Connection: close"));
    assert!(rejection_str.ends_with("\r\n\r\n"));

    // Test 5: URL parsing edge cases
    let url_test_cases = vec![
        ("ws://localhost/", true),
        ("wss://example.com:443/socket", true),
        ("ws://[::1]:8080/test", true),
        ("http://example.com/", false), // Wrong scheme
        ("ws://", false), // No host
        ("invalid-url", false), // No scheme
    ];

    for (url, should_succeed) in url_test_cases {
        let entropy = DetEntropy::new(42);
        let result = ClientHandshake::new(url, &entropy);

        if should_succeed {
            assert!(result.is_ok(),
                "URL '{}' should parse successfully", url);
        } else {
            assert!(result.is_err(),
                "URL '{}' should fail to parse", url);
        }
    }
}