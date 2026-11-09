//! RFC 8441 permission, wire advertisement, and stream-isolation regressions.

use super::*;

fn connect_headers() -> Vec<Header> {
    vec![
        Header::new(":method", "CONNECT"),
        Header::new(":protocol", "websocket"),
        Header::new(":scheme", "https"),
        Header::new(":path", "/chat?room=1"),
        Header::new(":authority", "example.com"),
        Header::new("sec-websocket-version", "13"),
        Header::new("x-shared", "retained-hpack-entry"),
    ]
}

fn header_frame(encoder: &mut hpack::Encoder, stream: u32, headers: &[Header]) -> Frame {
    let mut block = BytesMut::new();
    encoder.encode(headers, &mut block);
    Frame::Headers(HeadersFrame::new(stream, block.freeze(), false, true))
}

fn server(enabled: bool) -> Connection {
    let mut connection = Connection::server(Settings::default());
    if enabled {
        connection.enable_extended_connect();
    }
    connection
        .process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
        .unwrap();
    assert_eq!(connection.state(), ConnectionState::Open);
    connection
}

#[test]
fn native_server_advertises_boolean_connect_setting_without_changing_legacy_frames() {
    let settings = Frame::Settings(SettingsFrame::new(vec![Setting::MaxConcurrentStreams(17)]));
    let mut legacy = FrameCodec::new();
    let mut enabled = ListenerFrameCodec::new();
    enabled.enable_extended_connect();
    let mut plain = BytesMut::new();
    legacy.encode(&settings, &mut plain).unwrap();
    let mut extended = BytesMut::new();
    enabled.encode(&settings, &mut extended).unwrap();
    let plain_header = FrameHeader::parse(&mut plain).unwrap();
    let extended_header = FrameHeader::parse(&mut extended).unwrap();
    assert_eq!(plain_header.length, 6);
    assert_eq!(extended_header.length, 12);
    assert_eq!(&extended[..6], &plain[..]);
    assert_eq!(&extended[6..], &[0, 8, 0, 0, 0, 1]);

    // Re-advertisement is monotonic, and settings ACKs stay empty.
    let mut next = BytesMut::new();
    enabled.encode(&settings, &mut next).unwrap();
    assert_eq!(&next[next.len() - 6..], &[0, 8, 0, 0, 0, 1]);
    let mut ack = BytesMut::new();
    enabled
        .encode(Frame::Settings(SettingsFrame::ack()), &mut ack)
        .unwrap();
    let ack_header = FrameHeader::parse(&mut ack).unwrap();
    assert_eq!(ack_header.length, 0);
    assert_eq!(ack_header.flags, super::super::frame::settings_flags::ACK);
    assert!(ack.is_empty());
}

#[test]
fn connect_setting_rejects_invalid_values_even_for_legacy_codec() {
    for value in [0_u32, 1, 2, u32::MAX] {
        let mut bytes = BytesMut::new();
        FrameHeader {
            length: 6,
            frame_type: FrameType::Settings as u8,
            flags: 0,
            stream_id: 0,
        }
        .write(&mut bytes);
        bytes.extend_from_slice(&[0, 8]);
        bytes.extend_from_slice(&value.to_be_bytes());
        let result = FrameCodec::new().decode(&mut bytes);
        if value <= 1 {
            assert!(matches!(result, Ok(Some(Frame::Settings(_)))));
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.code, ErrorCode::ProtocolError);
            assert_eq!(error.stream_id, None);
        }
    }
}

#[test]
fn extended_connect_permission_is_required_and_does_not_damage_sibling_hpack() {
    let mut connection = server(false);
    let mut encoder = hpack::Encoder::new();
    let error = connection
        .process_frame(header_frame(&mut encoder, 1, &connect_headers()))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ProtocolError);
    assert_eq!(error.stream_id, Some(1));
    connection.reset_stream(1, error.code);

    let sibling = vec![
        Header::new(":method", "GET"),
        Header::new(":scheme", "https"),
        Header::new(":path", "/health"),
        Header::new(":authority", "example.com"),
        Header::new("x-shared", "retained-hpack-entry"),
    ];
    let result = connection
        .process_frame(header_frame(&mut encoder, 3, &sibling))
        .unwrap();
    let Some(ReceivedFrame::Headers {
        stream_id, headers, ..
    }) = result
    else {
        panic!("ordinary sibling survives refused extended CONNECT")
    };
    assert_eq!(stream_id, 3);
    assert_eq!(headers, sibling);
    assert_eq!(connection.state(), ConnectionState::Open);
}

#[test]
fn advertised_extended_connect_retains_all_pseudo_headers_for_listener_dispatch() {
    let mut connection = server(true);
    let mut encoder = hpack::Encoder::new();
    let expected = connect_headers();
    let result = connection
        .process_frame(header_frame(&mut encoder, 1, &expected))
        .unwrap();
    let Some(ReceivedFrame::Headers {
        stream_id,
        headers,
        end_stream,
    }) = result
    else {
        panic!("negotiated CONNECT reaches the streaming listener")
    };
    assert_eq!(stream_id, 1);
    assert!(!end_stream);
    assert_eq!(headers, expected);
}

#[test]
fn extended_connect_requires_every_uri_field_and_valid_single_protocol() {
    let valid = connect_headers();
    for required in [":scheme", ":path", ":authority"] {
        let headers: Vec<_> = valid
            .iter()
            .filter(|header| header.name != required)
            .cloned()
            .collect();
        assert!(
            validate_h2_pseudo_headers_with_connect(&headers, true, false, true).is_err(),
            "missing {required}"
        );
    }
    for (name, value) in [
        (":protocol", ""),
        (":protocol", "websocket,other"),
        (":protocol", "websocket/"),
        (":protocol", "a/b/c"),
        (":protocol", "web socket"),
        (":scheme", ""),
        (":scheme", "1https"),
        (":scheme", "https:"),
        (":authority", ""),
        (":authority", "bad host"),
        (":authority", "user@example.com"),
        (":authority", "example.com/path"),
        (":authority", "example.com?query"),
        (":authority", "example.com#fragment"),
        (":authority", "example.com\\path"),
        (":authority", "example.com:"),
        (":authority", "example.com:+443"),
        (":authority", "example.com:65536"),
        (":authority", ":443"),
        (":authority", "::1"),
        (":authority", "[::1"),
        (":authority", "[::1]:"),
        (":authority", "[::1]:no-port"),
        (":authority", "[::1]suffix"),
        (":authority", "[not-ipv6]"),
        (":authority", "example.com]"),
        (":path", "relative"),
        (":path", "/chat#fragment"),
        (":path", "/chat\troom"),
    ] {
        let mut headers = valid.clone();
        headers
            .iter_mut()
            .find(|header| header.name == name)
            .unwrap()
            .value = value.to_owned();
        assert!(
            validate_h2_pseudo_headers_with_connect(&headers, true, false, true).is_err(),
            "invalid {name}={value:?}"
        );
    }
    for protocol in ["websocket", "connect-udp", "example/1.0"] {
        let mut headers = valid.clone();
        headers[1].value = protocol.to_owned();
        assert!(validate_h2_pseudo_headers_with_connect(&headers, true, false, true).is_ok());
    }
    for authority in [
        "example.com",
        "example.com:443",
        "127.0.0.1:8080",
        "[::1]",
        "[2001:db8::1]:443",
    ] {
        let mut headers = valid.clone();
        headers
            .iter_mut()
            .find(|header| header.name == ":authority")
            .unwrap()
            .value = authority.to_owned();
        assert!(validate_h2_pseudo_headers_with_connect(&headers, true, false, true).is_ok());
    }
}

#[test]
fn extended_connect_opt_in_does_not_relax_other_pseudo_header_rules() {
    let mut wrong_method = connect_headers();
    wrong_method[0].value = "GET".to_owned();
    assert!(validate_h2_pseudo_headers_with_connect(&wrong_method, true, false, true).is_err());
    assert!(
        validate_h2_pseudo_headers_with_connect(&connect_headers(), false, false, true).is_err()
    );
    assert!(validate_h2_pseudo_headers_with_connect(&connect_headers(), true, true, true).is_err());

    let mut connection_header = connect_headers();
    connection_header.push(Header::new("connection", "upgrade"));
    assert!(
        validate_h2_pseudo_headers_with_connect(&connection_header, true, false, true).is_err()
    );
    let mut classic = connect_headers();
    classic.retain(|header| !matches!(header.name.as_str(), ":protocol" | ":scheme" | ":path"));
    assert!(validate_h2_pseudo_headers_with_connect(&classic, true, false, false).is_ok());
    classic.insert(1, Header::new(":path", "/chat"));
    assert!(validate_h2_pseudo_headers_with_connect(&classic, true, false, true).is_err());
}

#[test]
fn extended_connect_checks_complete_continuation_block_and_preserves_dynamic_table() {
    let mut connection = server(true);
    let mut encoder = hpack::Encoder::new();
    let mut invalid = connect_headers();
    invalid.retain(|header| header.name != ":scheme");
    let mut bytes = BytesMut::new();
    encoder.encode(&invalid, &mut bytes);
    let split = bytes.len() / 2;
    let first = bytes.split_to(split).freeze();
    assert!(
        connection
            .process_frame(Frame::Headers(HeadersFrame::new(1, first, false, false)))
            .unwrap()
            .is_none()
    );
    let error = connection
        .process_frame(Frame::Continuation(ContinuationFrame {
            stream_id: 1,
            header_block: bytes.freeze(),
            end_headers: true,
        }))
        .unwrap_err();
    assert_eq!(error.stream_id, Some(1));
    assert_eq!(error.code, ErrorCode::ProtocolError);
    connection.reset_stream(1, error.code);
    assert!(matches!(
        connection.process_frame(header_frame(&mut encoder, 3, &connect_headers())),
        Ok(Some(ReceivedFrame::Headers { stream_id: 3, .. }))
    ));
}
