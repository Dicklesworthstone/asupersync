#![allow(missing_docs)]

#[macro_use]
mod common;

#[path = "e2e/websocket/mod.rs"]
mod websocket_e2e;

use asupersync::net::websocket::{
    compute_accept_key, ClientHandshake, HandshakeError, HttpRequest, HttpResponse,
    ServerHandshake, WsUrl,
};
use futures_lite::future::block_on;
use std::io::Cursor;
use websocket_e2e::util::{
    init_ws_test, read_exact, read_http_headers, write_all, ws_handshake_request_bytes,
};

#[test]
fn ws_url_parse_basic_ws() {
    init_ws_test("ws_url_parse_basic_ws");
    let url = WsUrl::parse("ws://example.com/chat").expect("parse");
    assert_with_log!(url.host == "example.com", "host", "example.com", url.host);
    assert_with_log!(url.port == 80, "port", 80, url.port);
    assert_with_log!(url.path == "/chat", "path", "/chat", url.path);
    assert_with_log!(!url.tls, "tls", false, url.tls);
    test_complete!("ws_url_parse_basic_ws");
}

#[test]
fn ws_url_parse_wss_with_port() {
    init_ws_test("ws_url_parse_wss_with_port");
    let url = WsUrl::parse("wss://example.com:8443/ws").expect("parse");
    assert_with_log!(url.host == "example.com", "host", "example.com", url.host);
    assert_with_log!(url.port == 8443, "port", 8443, url.port);
    assert_with_log!(url.path == "/ws", "path", "/ws", url.path);
    assert_with_log!(url.tls, "tls", true, url.tls);
    test_complete!("ws_url_parse_wss_with_port");
}

#[test]
fn ws_url_parse_ipv6_host() {
    init_ws_test("ws_url_parse_ipv6_host");
    let url = WsUrl::parse("ws://[::1]:9000/chat").expect("parse");
    assert_with_log!(url.host == "::1", "host", "::1", url.host);
    assert_with_log!(url.port == 9000, "port", 9000, url.port);
    assert_with_log!(url.path == "/chat", "path", "/chat", url.path);
    test_complete!("ws_url_parse_ipv6_host");
}

#[test]
fn ws_url_parse_invalid_scheme() {
    init_ws_test("ws_url_parse_invalid_scheme");
    let err = WsUrl::parse("http://example.com").expect_err("invalid scheme");
    let is_invalid = matches!(err, HandshakeError::InvalidUrl(_));
    assert_with_log!(is_invalid, "invalid url", true, is_invalid);
    test_complete!("ws_url_parse_invalid_scheme");
}

#[test]
fn ws_client_handshake_request_contains_headers() {
    init_ws_test("ws_client_handshake_request_contains_headers");
    let handshake = ClientHandshake::new("ws://example.com/chat").expect("handshake");
    let request = HttpRequest::parse(&handshake.request_bytes()).expect("parse");

    assert_with_log!(request.method == "GET", "method", "GET", request.method);
    assert_with_log!(request.path == "/chat", "path", "/chat", request.path);
    assert_with_log!(
        request.header("upgrade") == Some("websocket"),
        "upgrade header",
        Some("websocket"),
        request.header("upgrade")
    );
    assert_with_log!(
        request.header("connection") == Some("Upgrade"),
        "connection header",
        Some("Upgrade"),
        request.header("connection")
    );
    let key = request.header("sec-websocket-key");
    assert_with_log!(key.is_some(), "key header present", true, key.is_some());
    test_complete!("ws_client_handshake_request_contains_headers");
}

#[test]
fn ws_client_handshake_request_includes_protocols_and_extensions() {
    init_ws_test("ws_client_handshake_request_includes_protocols_and_extensions");
    let handshake = ClientHandshake::new("ws://example.com/chat")
        .expect("handshake")
        .protocol("chat")
        .extension("permessage-deflate")
        .header("X-Test", "1");
    let request = HttpRequest::parse(&handshake.request_bytes()).expect("parse");

    assert_with_log!(
        request.header("sec-websocket-protocol") == Some("chat"),
        "protocol header",
        Some("chat"),
        request.header("sec-websocket-protocol")
    );
    assert_with_log!(
        request.header("sec-websocket-extensions") == Some("permessage-deflate"),
        "extensions header",
        Some("permessage-deflate"),
        request.header("sec-websocket-extensions")
    );
    assert_with_log!(
        request.header("x-test") == Some("1"),
        "custom header",
        Some("1"),
        request.header("x-test")
    );
    test_complete!("ws_client_handshake_request_includes_protocols_and_extensions");
}

#[test]
fn ws_server_handshake_accepts_and_selects_protocol() {
    init_ws_test("ws_server_handshake_accepts_and_selects_protocol");
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let request_bytes =
        ws_handshake_request_bytes("/chat", "example.com", key, Some("chat, super"));
    let request = HttpRequest::parse(&request_bytes).expect("parse");
    let server = ServerHandshake::new().protocol("super").protocol("other");
    let response = server.accept(&request).expect("accept");

    assert_with_log!(
        response.protocol.as_deref() == Some("super"),
        "protocol selection",
        Some("super"),
        response.protocol.as_deref()
    );
    let expected = compute_accept_key(key);
    assert_with_log!(
        response.accept_key == expected,
        "accept key",
        expected,
        response.accept_key
    );
    test_complete!("ws_server_handshake_accepts_and_selects_protocol");
}

#[test]
fn ws_server_handshake_rejects_missing_key() {
    init_ws_test("ws_server_handshake_rejects_missing_key");
    let raw = b"GET /chat HTTP/1.1\r\n\
Host: example.com\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n";
    let request = HttpRequest::parse(raw).expect("parse");
    let server = ServerHandshake::new();
    let err = server.accept(&request).expect_err("missing key");
    let is_missing = matches!(err, HandshakeError::MissingHeader("Sec-WebSocket-Key"));
    assert_with_log!(is_missing, "missing key error", true, is_missing);
    test_complete!("ws_server_handshake_rejects_missing_key");
}

#[test]
fn ws_client_handshake_validate_response_ok() {
    init_ws_test("ws_client_handshake_validate_response_ok");
    let handshake = ClientHandshake::new("ws://example.com/chat").expect("handshake");
    let accept_key = compute_accept_key(handshake.key());
    let response = asupersync::net::websocket::AcceptResponse {
        accept_key,
        protocol: None,
        extensions: Vec::new(),
    };
    let parsed = HttpResponse::parse(&response.response_bytes()).expect("parse response");

    let result = handshake.validate_response(&parsed);
    assert_with_log!(
        result.is_ok(),
        "response should validate",
        true,
        result.is_ok()
    );
    test_complete!("ws_client_handshake_validate_response_ok");
}

#[test]
fn ws_util_read_http_headers_reads_boundary() {
    init_ws_test("ws_util_read_http_headers_reads_boundary");
    let payload = b"HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
\r\nBODY";
    let mut cursor = Cursor::new(payload.as_slice());
    let headers = block_on(read_http_headers(&mut cursor)).expect("read headers");
    let text = String::from_utf8_lossy(&headers);
    let has_boundary = text.contains("\r\n\r\n");
    assert_with_log!(has_boundary, "headers boundary", true, has_boundary);
    test_complete!("ws_util_read_http_headers_reads_boundary");
}

#[test]
fn ws_util_read_exact_reads_payload() {
    init_ws_test("ws_util_read_exact_reads_payload");
    let mut cursor = Cursor::new(b"abcdef".as_slice());
    let out = block_on(read_exact(&mut cursor, 4)).expect("read exact");
    assert_with_log!(out == b"abcd", "payload", b"abcd", out);
    test_complete!("ws_util_read_exact_reads_payload");
}

#[test]
fn ws_util_write_all_captures_bytes() {
    init_ws_test("ws_util_write_all_captures_bytes");
    let mut out: Vec<u8> = Vec::new();
    block_on(write_all(&mut out, b"hello")).expect("write all");
    assert_with_log!(out == b"hello", "write bytes", b"hello", out);
    test_complete!("ws_util_write_all_captures_bytes");
}
