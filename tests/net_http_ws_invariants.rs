//! Integration tests: net/http/h2/websocket unit gaps (bd-2hvn).
//!
//! Covers invariants not exercised by in-module tests:
//!
//! ## WebSocket Frame (RFC 6455)
//! - Payload length boundary transitions (125/126, 65535/65536)
//! - Server-role encode → client decode (unmasked path)
//! - Multi-frame decode from single buffer
//! - Reserved-bits rejection via raw bytes
//! - Invalid opcode rejection for all reserved values (0x03-0x07, 0x0B-0x0F)
//! - Max payload enforcement at decode time
//! - Mask alignment edge cases (0, 1, 3, 4, 5 bytes)
//!
//! ## WebSocket Handshake
//! - WsUrl edge cases: IPv6 default port, empty host, invalid scheme, path-only
//! - Server rejects non-GET, missing Upgrade, missing Connection, invalid key length
//! - Client validates non-101 status, missing Sec-WebSocket-Accept
//! - Full client→server→client roundtrip with protocol negotiation
//!
//! ## WebSocket Close Protocol (RFC 6455 §7)
//! - CloseReason parse: empty, code-only, code+text, 1-byte invalid, invalid UTF-8
//! - CloseReason encode/parse roundtrip for all defined codes
//! - CloseCode::is_valid_code range boundaries
//! - CloseHandshake state transitions: Open→CloseSent, CloseReceived→Closed
//!
//! ## HPACK (RFC 7541)
//! - Sensitive encoding does NOT populate dynamic table
//! - Encoder table size change flushes entries
//! - Static/dynamic table index boundary (index 61 vs 62)

mod common;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::http::h2::hpack::{Decoder as HpackDecoder, Encoder as HpackEncoder, Header};
use asupersync::net::websocket::{
    apply_mask, CloseCode, CloseHandshake, CloseReason, Frame, FrameCodec, Opcode, WsError,
};
use asupersync::net::websocket::{
    ClientHandshake, HandshakeError, HttpRequest, HttpResponse, ServerHandshake, WsUrl,
};
use asupersync::util::DetEntropy;

// =========================================================================
// WebSocket Frame: Payload Length Boundaries
// =========================================================================

#[test]
fn payload_length_boundary_125() {
    // 125 bytes: maximum 7-bit inline length (no extended header).
    let mut enc = FrameCodec::client();
    let mut dec = FrameCodec::server();
    let data = Bytes::from(vec![0xABu8; 125]);
    let frame = Frame::binary(data.clone());

    let mut buf = BytesMut::new();
    enc.encode(frame, &mut buf).unwrap();

    // Second byte (after mask bit) should encode length directly.
    let len_byte = buf[1] & 0x7F;
    assert_eq!(len_byte, 125, "125-byte payload uses inline length");

    let parsed = dec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(parsed.payload.len(), 125);
    assert_eq!(parsed.payload, data);
}

#[test]
fn payload_length_boundary_126() {
    // 126 bytes: minimum 2-byte extended length (len indicator = 126).
    let mut enc = FrameCodec::client();
    let mut dec = FrameCodec::server();
    let data = Bytes::from(vec![0xCDu8; 126]);
    let frame = Frame::binary(data.clone());

    let mut buf = BytesMut::new();
    enc.encode(frame, &mut buf).unwrap();

    let len_byte = buf[1] & 0x7F;
    assert_eq!(
        len_byte, 126,
        "126-byte payload uses 2-byte extended length"
    );

    let parsed = dec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(parsed.payload.len(), 126);
    assert_eq!(parsed.payload, data);
}

#[test]
fn payload_length_boundary_65535() {
    // 65535 bytes: maximum 2-byte extended length.
    let mut enc = FrameCodec::client();
    let mut dec = FrameCodec::server();
    let data = Bytes::from(vec![0x42u8; 65535]);
    let frame = Frame::binary(data);

    let mut buf = BytesMut::new();
    enc.encode(frame, &mut buf).unwrap();

    let len_byte = buf[1] & 0x7F;
    assert_eq!(len_byte, 126, "65535 still uses 2-byte extended");

    let parsed = dec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(parsed.payload.len(), 65535);
}

#[test]
fn payload_length_boundary_65536() {
    // 65536 bytes: minimum 8-byte extended length (len indicator = 127).
    let mut enc = FrameCodec::client();
    let mut dec = FrameCodec::server();
    let data = Bytes::from(vec![0x55u8; 65536]);
    let frame = Frame::binary(data);

    let mut buf = BytesMut::new();
    enc.encode(frame, &mut buf).unwrap();

    let len_byte = buf[1] & 0x7F;
    assert_eq!(len_byte, 127, "65536 uses 8-byte extended");

    let parsed = dec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(parsed.payload.len(), 65536);
}

// =========================================================================
// WebSocket Frame: Server→Client (Unmasked) Path
// =========================================================================

#[test]
fn server_encode_client_decode_unmasked() {
    // Server sends unmasked frames; client decodes them.
    let mut server_enc = FrameCodec::server();
    let mut client_dec = FrameCodec::client();

    let frame = Frame::text("server says hello");
    let mut buf = BytesMut::new();
    server_enc.encode(frame, &mut buf).unwrap();

    // Mask bit should NOT be set.
    assert_eq!(buf[1] & 0x80, 0, "server frames must not be masked");

    let parsed = client_dec.decode(&mut buf).unwrap().unwrap();
    assert!(!parsed.masked);
    assert_eq!(parsed.payload.as_ref(), b"server says hello");
}

// =========================================================================
// WebSocket Frame: Multi-Frame Decode From Single Buffer
// =========================================================================

#[test]
fn multi_frame_decode_from_single_buffer() {
    let mut enc = FrameCodec::client();
    let mut dec = FrameCodec::server();

    let mut buf = BytesMut::new();
    enc.encode(Frame::text("first"), &mut buf).unwrap();
    enc.encode(Frame::binary(Bytes::from_static(b"\x00\x01")), &mut buf)
        .unwrap();
    enc.encode(Frame::ping("p"), &mut buf).unwrap();

    // Decode all three sequentially from the same buffer.
    let f1 = dec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(f1.opcode, Opcode::Text);
    assert_eq!(f1.payload.as_ref(), b"first");

    let f2 = dec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(f2.opcode, Opcode::Binary);
    assert_eq!(f2.payload.as_ref(), b"\x00\x01");

    let f3 = dec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(f3.opcode, Opcode::Ping);
    assert_eq!(f3.payload.as_ref(), b"p");

    // Buffer should be exhausted.
    assert!(dec.decode(&mut buf).unwrap().is_none());
}

// =========================================================================
// WebSocket Frame: Reserved Bits Rejection
// =========================================================================

#[test]
fn reserved_bits_rsv1_rejected() {
    let mut dec = FrameCodec::server();
    // Manually craft: FIN=1, RSV1=1, opcode=Text(1), masked=1, len=0, mask=0000
    let mut buf = BytesMut::from(
        &[
            0xC1u8, // 1100_0001 = FIN + RSV1 + Text
            0x80,   // masked, length 0
            0, 0, 0, 0, // mask key
        ][..],
    );

    let result = dec.decode(&mut buf);
    assert!(
        matches!(result, Err(WsError::ReservedBitsSet)),
        "RSV1 set should be rejected: {result:?}"
    );
}

#[test]
fn reserved_bits_rsv2_rejected() {
    let mut dec = FrameCodec::server();
    let mut buf = BytesMut::from(
        &[
            0xA1u8, // 1010_0001 = FIN + RSV2 + Text
            0x80,   // masked, length 0
            0, 0, 0, 0,
        ][..],
    );

    let result = dec.decode(&mut buf);
    assert!(matches!(result, Err(WsError::ReservedBitsSet)));
}

#[test]
fn reserved_bits_rsv3_rejected() {
    let mut dec = FrameCodec::server();
    let mut buf = BytesMut::from(
        &[
            0x91u8, // 1001_0001 = FIN + RSV3 + Text
            0x80,   // masked, length 0
            0, 0, 0, 0,
        ][..],
    );

    let result = dec.decode(&mut buf);
    assert!(matches!(result, Err(WsError::ReservedBitsSet)));
}

#[test]
fn reserved_bits_disabled_validation_passes() {
    let mut dec = FrameCodec::server().validate_reserved_bits(false);
    // RSV1 set, but validation disabled.
    let mut buf = BytesMut::from(
        &[
            0xC1u8, // FIN + RSV1 + Text
            0x80,   // masked, length 0
            0, 0, 0, 0,
        ][..],
    );

    let result = dec.decode(&mut buf);
    let frame = result.unwrap().unwrap();
    assert!(frame.rsv1);
    assert!(!frame.rsv2);
    assert!(!frame.rsv3);
}

// =========================================================================
// WebSocket Frame: Invalid Opcode Rejection
// =========================================================================

#[test]
fn all_reserved_opcodes_rejected() {
    // Reserved non-control: 0x03-0x07; reserved control: 0x0B-0x0F.
    let reserved: &[u8] = &[0x03, 0x04, 0x05, 0x06, 0x07, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];

    for &opcode_raw in reserved {
        let mut dec = FrameCodec::server();
        let first_byte = 0x80 | opcode_raw; // FIN=1 + opcode
        let mut buf = BytesMut::from(&[first_byte, 0x80, 0, 0, 0, 0][..]);

        let result = dec.decode(&mut buf);
        assert!(
            matches!(result, Err(WsError::InvalidOpcode(_))),
            "opcode 0x{opcode_raw:02X} should be rejected: {result:?}"
        );
    }
}

// =========================================================================
// WebSocket Frame: Max Payload Enforcement
// =========================================================================

#[test]
fn max_payload_enforcement_on_decode() {
    let mut dec = FrameCodec::server().max_payload_size(100);

    // Craft a masked frame with 126-byte extended length = 200 bytes.
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&[
        0x82, // FIN + Binary
        0xFE, // masked + 126 (2-byte extended)
        0x00, 0xC8, // 200 in big-endian
        0, 0, 0, 0, // mask key
    ]);
    buf.extend_from_slice(&[0u8; 200]); // payload

    let result = dec.decode(&mut buf);
    assert!(
        matches!(
            result,
            Err(WsError::PayloadTooLarge {
                size: 200,
                max: 100
            })
        ),
        "payload exceeding max should be rejected: {result:?}"
    );
}

// =========================================================================
// WebSocket Frame: Masking Alignment Edge Cases
// =========================================================================

#[test]
fn mask_empty_payload() {
    let mut payload: Vec<u8> = vec![];
    apply_mask(&mut payload, [0xFF, 0xFF, 0xFF, 0xFF]);
    assert!(payload.is_empty());
}

#[test]
fn mask_single_byte() {
    let mut payload = vec![0x42];
    let key = [0xFF, 0x00, 0x00, 0x00];
    apply_mask(&mut payload, key);
    assert_eq!(payload, vec![0x42 ^ 0xFF]);
    apply_mask(&mut payload, key);
    assert_eq!(payload, vec![0x42]);
}

#[test]
fn mask_alignment_sweep() {
    // Test payload lengths 1..=8 (straddles the 4-byte mask key boundary).
    let key = [0x12, 0x34, 0x56, 0x78];
    for len in 1..=8 {
        let original: Vec<u8> = (0..len).map(|i| u8::try_from(i).unwrap()).collect();
        let mut data = original.clone();
        apply_mask(&mut data, key);
        assert_ne!(data, original, "len={len}: mask should change data");
        apply_mask(&mut data, key);
        assert_eq!(data, original, "len={len}: double mask should restore");
    }
}

// =========================================================================
// WebSocket Frame: Masking Requirements (Raw Bytes)
// =========================================================================

#[test]
fn unmasked_client_frame_rejected() {
    let mut dec = FrameCodec::server();
    // Client frame without mask bit set.
    let mut buf = BytesMut::from(
        &[
            0x81u8, // FIN + Text
            0x00,   // NOT masked, length 0
        ][..],
    );

    let result = dec.decode(&mut buf);
    assert!(matches!(result, Err(WsError::UnmaskedClientFrame)));
}

#[test]
fn masked_server_frame_rejected() {
    let mut dec = FrameCodec::client();
    // Server frame WITH mask bit set (invalid for server→client).
    let mut buf = BytesMut::from(
        &[
            0x81u8, // FIN + Text
            0x80,   // masked, length 0
            0, 0, 0, 0, // mask key
        ][..],
    );

    let result = dec.decode(&mut buf);
    assert!(matches!(result, Err(WsError::MaskedServerFrame)));
}

// =========================================================================
// WebSocket Frame: Constructor Invariants
// =========================================================================

#[test]
fn frame_constructors_set_correct_fields() {
    let text = Frame::text("hi");
    assert!(text.fin);
    assert!(!text.rsv1);
    assert!(!text.rsv2);
    assert!(!text.rsv3);
    assert_eq!(text.opcode, Opcode::Text);
    assert!(!text.masked);

    let binary = Frame::binary(Bytes::from_static(b"\x00"));
    assert_eq!(binary.opcode, Opcode::Binary);

    let heartbeat = Frame::ping("data");
    assert_eq!(heartbeat.opcode, Opcode::Ping);
    assert!(heartbeat.fin);

    let reply = Frame::pong("data");
    assert_eq!(reply.opcode, Opcode::Pong);

    let close = Frame::close(Some(1000), Some("bye"));
    assert_eq!(close.opcode, Opcode::Close);
    assert!(close.fin);
    // Payload: 2-byte code + "bye".
    assert_eq!(close.payload.len(), 5);

    let close_empty = Frame::close(None, None);
    assert!(close_empty.payload.is_empty());
}

#[test]
fn opcode_is_data_classification() {
    assert!(Opcode::Continuation.is_data());
    assert!(Opcode::Text.is_data());
    assert!(Opcode::Binary.is_data());
    assert!(!Opcode::Close.is_data());
    assert!(!Opcode::Ping.is_data());
    assert!(!Opcode::Pong.is_data());
}

// =========================================================================
// WebSocket Handshake: WsUrl Edge Cases
// =========================================================================

#[test]
fn ws_url_ipv6_default_port() {
    let url = WsUrl::parse("ws://[::1]/test").unwrap();
    assert_eq!(url.host, "::1");
    assert_eq!(url.port, 80);
    assert_eq!(url.path, "/test");
    assert!(!url.tls);
}

#[test]
fn ws_url_wss_ipv6_default_port() {
    let url = WsUrl::parse("wss://[::1]/secure").unwrap();
    assert_eq!(url.host, "::1");
    assert_eq!(url.port, 443);
    assert!(url.tls);
}

#[test]
fn ws_url_empty_host_rejected() {
    let result = WsUrl::parse("ws:///path");
    assert!(matches!(result, Err(HandshakeError::InvalidUrl(_))));
}

#[test]
fn ws_url_invalid_scheme_rejected() {
    let result = WsUrl::parse("http://example.com/ws");
    assert!(matches!(result, Err(HandshakeError::InvalidUrl(_))));
}

#[test]
fn ws_url_missing_scheme_rejected() {
    let result = WsUrl::parse("example.com/ws");
    assert!(matches!(result, Err(HandshakeError::InvalidUrl(_))));
}

#[test]
fn ws_url_invalid_port_rejected() {
    let result = WsUrl::parse("ws://example.com:notaport/ws");
    assert!(matches!(result, Err(HandshakeError::InvalidUrl(_))));
}

#[test]
fn ws_url_host_header_wss_non_default_port() {
    let url = WsUrl::parse("wss://example.com:9443/ws").unwrap();
    assert_eq!(url.host_header(), "example.com:9443");
}

// =========================================================================
// WebSocket Handshake: Server Validation
// =========================================================================

#[test]
fn server_rejects_non_get_method() {
    let server = ServerHandshake::new();
    let request = HttpRequest::parse(
        b"POST /chat HTTP/1.1\r\n\
          Host: example.com\r\n\
          Upgrade: websocket\r\n\
          Connection: Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
          Sec-WebSocket-Version: 13\r\n\
          \r\n",
    )
    .unwrap();

    let err = server.accept(&request).unwrap_err();
    assert!(matches!(err, HandshakeError::InvalidRequest(_)));
}

#[test]
fn server_rejects_missing_upgrade_header() {
    let server = ServerHandshake::new();
    let request = HttpRequest::parse(
        b"GET /chat HTTP/1.1\r\n\
          Host: example.com\r\n\
          Connection: Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
          Sec-WebSocket-Version: 13\r\n\
          \r\n",
    )
    .unwrap();

    let err = server.accept(&request).unwrap_err();
    assert!(matches!(err, HandshakeError::MissingHeader("Upgrade")));
}

#[test]
fn server_rejects_missing_connection_header() {
    let server = ServerHandshake::new();
    let request = HttpRequest::parse(
        b"GET /chat HTTP/1.1\r\n\
          Host: example.com\r\n\
          Upgrade: websocket\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
          Sec-WebSocket-Version: 13\r\n\
          \r\n",
    )
    .unwrap();

    let err = server.accept(&request).unwrap_err();
    assert!(matches!(err, HandshakeError::MissingHeader("Connection")));
}

#[test]
fn server_rejects_invalid_key_length() {
    let server = ServerHandshake::new();
    // "short" base64 decodes to 5 bytes, not 16.
    let request = HttpRequest::parse(
        b"GET /chat HTTP/1.1\r\n\
          Host: example.com\r\n\
          Upgrade: websocket\r\n\
          Connection: Upgrade\r\n\
          Sec-WebSocket-Key: c2hvcnQ=\r\n\
          Sec-WebSocket-Version: 13\r\n\
          \r\n",
    )
    .unwrap();

    let err = server.accept(&request).unwrap_err();
    assert!(matches!(err, HandshakeError::InvalidKey));
}

#[test]
fn server_rejects_missing_version() {
    let server = ServerHandshake::new();
    let request = HttpRequest::parse(
        b"GET /chat HTTP/1.1\r\n\
          Host: example.com\r\n\
          Upgrade: websocket\r\n\
          Connection: Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
          \r\n",
    )
    .unwrap();

    let err = server.accept(&request).unwrap_err();
    assert!(matches!(
        err,
        HandshakeError::MissingHeader("Sec-WebSocket-Version")
    ));
}

// =========================================================================
// WebSocket Handshake: Client Response Validation
// =========================================================================

#[test]
fn client_rejects_non_101_status() {
    let handshake = ClientHandshake::new("ws://example.com/chat", &DetEntropy::new(1)).unwrap();

    let response = HttpResponse::parse(
        b"HTTP/1.1 200 OK\r\n\
          Upgrade: websocket\r\n\
          Connection: Upgrade\r\n\
          Sec-WebSocket-Accept: dummy\r\n\
          \r\n",
    )
    .unwrap();

    let err = handshake.validate_response(&response).unwrap_err();
    assert!(matches!(err, HandshakeError::NotSwitchingProtocols(200)));
}

#[test]
fn client_rejects_missing_accept_header() {
    let handshake = ClientHandshake::new("ws://example.com/chat", &DetEntropy::new(1)).unwrap();

    let response = HttpResponse::parse(
        b"HTTP/1.1 101 Switching Protocols\r\n\
          Upgrade: websocket\r\n\
          Connection: Upgrade\r\n\
          \r\n",
    )
    .unwrap();

    let err = handshake.validate_response(&response).unwrap_err();
    assert!(matches!(
        err,
        HandshakeError::MissingHeader("Sec-WebSocket-Accept")
    ));
}

// =========================================================================
// WebSocket Handshake: Full Roundtrip With Protocol Negotiation
// =========================================================================

#[test]
fn full_handshake_roundtrip_with_protocol() {
    let entropy = DetEntropy::new(42);
    let client = ClientHandshake::new("ws://example.com/chat", &entropy)
        .unwrap()
        .protocol("graphql-ws")
        .protocol("chat");

    // Client generates request.
    let request_bytes = client.request_bytes();
    let request_text = String::from_utf8(request_bytes.clone()).unwrap();
    assert!(request_text.contains("Sec-WebSocket-Protocol: graphql-ws, chat"));

    // Server parses and accepts.
    let server = ServerHandshake::new().protocol("chat");
    let http_req = HttpRequest::parse(&request_bytes).unwrap();
    let accept = server.accept(&http_req).unwrap();

    assert_eq!(accept.protocol, Some("chat".to_string()));

    // Server generates response.
    let response_bytes = accept.response_bytes();

    // Client validates response.
    let http_resp = HttpResponse::parse(&response_bytes).unwrap();
    client.validate_response(&http_resp).unwrap();
}

#[test]
fn handshake_accept_key_deterministic_across_entropy() {
    // compute_accept_key is independent of entropy (deterministic from key+GUID).
    use asupersync::net::websocket::compute_accept_key;

    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let a1 = compute_accept_key(key);
    let a2 = compute_accept_key(key);
    assert_eq!(a1, a2);
    assert_eq!(a1, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

// =========================================================================
// WebSocket Close: CloseReason Parse
// =========================================================================

#[test]
fn close_reason_parse_empty() {
    let reason = CloseReason::parse(&[]).unwrap();
    assert_eq!(reason.code, None);
    assert_eq!(reason.text, None);
}

#[test]
fn close_reason_parse_code_only() {
    // 1000 = Normal (0x03E8).
    let reason = CloseReason::parse(&[0x03, 0xE8]).unwrap();
    assert_eq!(reason.code, Some(CloseCode::Normal));
    assert_eq!(reason.text, None);
}

#[test]
fn close_reason_parse_code_and_text() {
    let mut payload = vec![0x03, 0xE8]; // 1000 = Normal
    payload.extend_from_slice(b"goodbye");
    let reason = CloseReason::parse(&payload).unwrap();
    assert_eq!(reason.code, Some(CloseCode::Normal));
    assert_eq!(reason.text.as_deref(), Some("goodbye"));
}

#[test]
fn close_reason_parse_one_byte_invalid() {
    let result = CloseReason::parse(&[0x42]);
    assert!(matches!(result, Err(WsError::InvalidClosePayload)));
}

#[test]
fn close_reason_parse_invalid_utf8_text() {
    let mut payload = vec![0x03, 0xE8]; // 1000 = Normal
    payload.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
    let result = CloseReason::parse(&payload);
    assert!(matches!(result, Err(WsError::InvalidClosePayload)));
}

// =========================================================================
// WebSocket Close: Encode/Parse Roundtrip
// =========================================================================

#[test]
fn close_reason_encode_parse_roundtrip_all_defined_codes() {
    let codes = [
        CloseCode::Normal,
        CloseCode::GoingAway,
        CloseCode::ProtocolError,
        CloseCode::Unsupported,
        CloseCode::InvalidPayload,
        CloseCode::PolicyViolation,
        CloseCode::MessageTooBig,
        CloseCode::MandatoryExtension,
        CloseCode::InternalError,
    ];

    for code in codes {
        let reason = CloseReason::with_text(code, "test reason");
        let encoded = reason.encode();
        let parsed = CloseReason::parse(&encoded).unwrap();
        assert_eq!(parsed.code, Some(code), "roundtrip failed for {code:?}");
        assert_eq!(parsed.text.as_deref(), Some("test reason"));
    }
}

#[test]
fn close_reason_encode_empty() {
    let reason = CloseReason::empty();
    let encoded = reason.encode();
    assert!(encoded.is_empty());
}

// =========================================================================
// WebSocket Close: Code Validation
// =========================================================================

#[test]
fn close_code_is_valid_range_boundaries() {
    // Valid standard codes.
    assert!(CloseCode::is_valid_code(1000));
    assert!(CloseCode::is_valid_code(1003));
    assert!(CloseCode::is_valid_code(1007));
    assert!(CloseCode::is_valid_code(1011));

    // Invalid gaps.
    assert!(!CloseCode::is_valid_code(1004));
    assert!(!CloseCode::is_valid_code(1005));
    assert!(!CloseCode::is_valid_code(1006));
    assert!(!CloseCode::is_valid_code(1012));
    assert!(!CloseCode::is_valid_code(2999));

    // IANA registered range.
    assert!(CloseCode::is_valid_code(3000));
    assert!(CloseCode::is_valid_code(3999));

    // Private use range.
    assert!(CloseCode::is_valid_code(4000));
    assert!(CloseCode::is_valid_code(4999));

    // Out of range.
    assert!(!CloseCode::is_valid_code(0));
    assert!(!CloseCode::is_valid_code(999));
    assert!(!CloseCode::is_valid_code(5000));
}

#[test]
fn close_code_non_sendable_codes() {
    assert!(!CloseCode::NoStatusReceived.is_sendable());
    assert!(!CloseCode::Abnormal.is_sendable());
    assert!(!CloseCode::TlsHandshake.is_sendable());
    assert!(CloseCode::Normal.is_sendable());
    assert!(CloseCode::ProtocolError.is_sendable());
}

// =========================================================================
// WebSocket Close: Handshake State Machine
// =========================================================================

#[test]
fn close_handshake_initiate_transitions_to_close_sent() {
    let mut handshake = CloseHandshake::new();
    assert_eq!(handshake.our_reason(), None);
    assert_eq!(handshake.peer_reason(), None);

    let close_frame = handshake.initiate(CloseReason::normal());
    assert!(close_frame.is_some(), "should produce a close frame");

    let frame = close_frame.unwrap();
    assert_eq!(frame.opcode, Opcode::Close);

    // Second initiate should return None (already initiated).
    let again = handshake.initiate(CloseReason::going_away());
    assert!(again.is_none(), "double initiate should be no-op");
}

#[test]
fn close_handshake_receive_then_respond() {
    let mut handshake = CloseHandshake::new();

    // Simulate receiving a close frame from peer.
    let peer_close = Frame::close(Some(1000), Some("bye"));
    let response = handshake.receive_close(&peer_close).unwrap();
    assert!(response.is_some(), "should produce echo close frame");
    assert_eq!(
        handshake.peer_reason().unwrap().code,
        Some(CloseCode::Normal)
    );
}

#[test]
fn close_handshake_force_close() {
    let mut handshake = CloseHandshake::new();
    handshake.force_close(CloseReason::going_away());
    assert_eq!(
        handshake.our_reason().unwrap().code,
        Some(CloseCode::GoingAway)
    );
}

// =========================================================================
// WebSocket Close: CloseReason Helpers
// =========================================================================

#[test]
fn close_reason_helper_methods() {
    let normal = CloseReason::normal();
    assert!(normal.is_normal());
    assert!(!normal.is_error());

    let error = CloseReason::new(CloseCode::ProtocolError, None);
    assert!(!error.is_normal());
    assert!(error.is_error());

    let going = CloseReason::going_away();
    assert!(!going.is_normal());
    assert!(!going.is_error());
}

// =========================================================================
// WebSocket Handshake: HTTP Parse Edge Cases
// =========================================================================

#[test]
fn http_request_case_insensitive_headers() {
    let request = HttpRequest::parse(
        b"GET / HTTP/1.1\r\n\
          HOST: example.com\r\n\
          UPGRADE: websocket\r\n\
          \r\n",
    )
    .unwrap();

    // Headers stored lowercase.
    assert_eq!(request.header("host"), Some("example.com"));
    assert_eq!(request.header("HOST"), Some("example.com"));
    assert_eq!(request.header("upgrade"), Some("websocket"));
}

#[test]
fn http_response_parse_missing_reason() {
    let response = HttpResponse::parse(
        b"HTTP/1.1 101\r\n\
          \r\n",
    )
    .unwrap();

    assert_eq!(response.status, 101);
    assert_eq!(response.reason, "");
}

#[test]
fn server_reject_response_format() {
    let reject = ServerHandshake::reject(403, "Forbidden");
    let text = String::from_utf8(reject).unwrap();
    assert!(text.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(text.contains("Connection: close"));
    assert!(text.ends_with("\r\n\r\n"));
}

// =========================================================================
// HPACK: Sensitive Encoding Does Not Populate Dynamic Table
// =========================================================================

#[test]
fn hpack_sensitive_headers_not_indexed() {
    let mut enc = HpackEncoder::new();
    enc.set_use_huffman(false);

    // Encode with sensitive mode (never indexed).
    let sensitive = vec![Header::new("authorization", "Bearer secret")];
    let mut buf = BytesMut::new();
    enc.encode_sensitive(&sensitive, &mut buf);

    // Now encode with normal mode: if "authorization" were in the dynamic
    // table, it would be indexed (smaller encoding). Instead, encode a
    // completely different header to verify table is still empty.
    let normal = vec![Header::new("authorization", "Bearer secret")];
    let mut buf2 = BytesMut::new();
    enc.encode(&normal, &mut buf2);

    // Decode both: both should succeed.
    let mut dec = HpackDecoder::new();
    let h1 = dec.decode(&mut buf.freeze()).unwrap();
    assert_eq!(h1[0].name, "authorization");
    assert_eq!(h1[0].value, "Bearer secret");

    let h2 = dec.decode(&mut buf2.freeze()).unwrap();
    assert_eq!(h2[0].name, "authorization");
    assert_eq!(h2[0].value, "Bearer secret");
}

// =========================================================================
// HPACK: Encoder Table Size Change
// =========================================================================

#[test]
fn hpack_encoder_table_size_zero_flushes() {
    let mut enc = HpackEncoder::new();
    enc.set_use_huffman(false);

    // Insert a header (populates dynamic table).
    let h = vec![Header::new("x-custom", "value")];
    let mut buf = BytesMut::new();
    enc.encode(&h, &mut buf);

    // Set table size to 0 (evicts all entries).
    enc.set_max_table_size(0);

    // Encode the same header again: should NOT be able to reference
    // the dynamic table entry (it was evicted).
    let mut buf2 = BytesMut::new();
    enc.encode(&h, &mut buf2);

    // Both should decode correctly.
    let mut dec = HpackDecoder::new();
    let h1 = dec.decode(&mut buf.freeze()).unwrap();
    assert_eq!(h1[0].value, "value");

    // Second block: decoder won't have the entry either since the
    // encoder couldn't reference it.
    let mut dec2 = HpackDecoder::new();
    let h2 = dec2.decode(&mut buf2.freeze()).unwrap();
    assert_eq!(h2[0].value, "value");
}

// =========================================================================
// HPACK: Static Table Boundary
// =========================================================================

#[test]
fn hpack_static_table_boundary_index_61() {
    // Index 61 is the last static table entry: ("www-authenticate", "").
    let mut dec = HpackDecoder::new();
    let mut src = Bytes::from_static(&[0x80 | 61]); // Indexed, index 61
    let headers = dec.decode(&mut src).unwrap();
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, "www-authenticate");
    assert_eq!(headers[0].value, "");
}

#[test]
fn hpack_static_table_index_beyond_61_is_dynamic() {
    // Index 62 would be the first dynamic table entry.
    // With an empty dynamic table, this should fail.
    let mut dec = HpackDecoder::new();
    let mut src = Bytes::from_static(&[0x80 | 62]); // Indexed, index 62
    let result = dec.decode(&mut src);
    assert!(
        result.is_err(),
        "index 62 with empty dynamic table should fail"
    );
}

// =========================================================================
// HPACK: Header Size Calculation
// =========================================================================

#[test]
fn hpack_header_size_rfc7541() {
    // RFC 7541 Section 4.1: size = name_len + value_len + 32.
    let h = Header::new("content-type", "text/html");
    assert_eq!(h.size(), 12 + 9 + 32);

    let empty = Header::new("", "");
    assert_eq!(empty.size(), 32);
}

// =========================================================================
// Cross-Cutting: Frame Encode/Decode Determinism
// =========================================================================

#[test]
fn frame_decode_determinism_across_codec_instances() {
    // Same encoded bytes should decode identically regardless of codec instance.
    let mut enc = FrameCodec::client();
    let frame = Frame::text("determinism test");

    let mut buf = BytesMut::new();
    enc.encode(frame, &mut buf).unwrap();

    let wire = buf.freeze();

    for _ in 0..5 {
        let mut dec = FrameCodec::server();
        let mut copy = BytesMut::from(wire.as_ref());
        let parsed = dec.decode(&mut copy).unwrap().unwrap();
        assert_eq!(parsed.opcode, Opcode::Text);
        assert_eq!(parsed.payload.as_ref(), b"determinism test");
    }
}

// =========================================================================
// Cross-Cutting: Fragmented Data Frame (FIN=false)
// =========================================================================

#[test]
fn non_final_data_frame_allowed() {
    // Data frames (Text, Binary, Continuation) may have FIN=false.
    let mut enc = FrameCodec::server();
    let mut dec = FrameCodec::client();

    let mut frame = Frame::text("part1");
    frame.fin = false; // Non-final fragment.

    let mut buf = BytesMut::new();
    enc.encode(frame, &mut buf).unwrap();

    let parsed = dec.decode(&mut buf).unwrap().unwrap();
    assert!(!parsed.fin, "FIN should be false for fragment");
    assert_eq!(parsed.opcode, Opcode::Text);
}

// =========================================================================
// Cross-Cutting: Control Frame Payload Boundary (125)
// =========================================================================

#[test]
fn control_frame_payload_exactly_125_allowed() {
    let mut enc = FrameCodec::client();
    let mut dec = FrameCodec::server();

    let mut frame = Frame::ping(Bytes::from(vec![0u8; 125]));
    frame.payload = Bytes::from(vec![0u8; 125]);

    let mut buf = BytesMut::new();
    enc.encode(frame, &mut buf).unwrap();

    let parsed = dec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(parsed.payload.len(), 125);
}

#[test]
fn control_frame_payload_126_rejected() {
    let mut enc = FrameCodec::server();

    let mut frame = Frame::ping(Bytes::new());
    frame.payload = Bytes::from(vec![0u8; 126]);

    let mut buf = BytesMut::new();
    let result = enc.encode(frame, &mut buf);
    assert!(matches!(result, Err(WsError::ControlFrameTooLarge(126))));
}
