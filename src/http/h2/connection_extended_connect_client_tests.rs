//! Client-side RFC 8441 permission follows validated bytes on one connection.

use super::*;

fn settings_wire(parameters: &[(u16, u32)]) -> BytesMut {
    let mut bytes = BytesMut::new();
    FrameHeader {
        length: u32::try_from(parameters.len() * 6).unwrap(),
        frame_type: FrameType::Settings as u8,
        flags: 0,
        stream_id: 0,
    }
    .write(&mut bytes);
    for (id, value) in parameters {
        bytes.extend_from_slice(&id.to_be_bytes());
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes
}

fn request_headers() -> Vec<Header> {
    vec![
        Header::new(":method", "CONNECT"),
        Header::new(":protocol", "websocket"),
        Header::new(":scheme", "https"),
        Header::new(":authority", "example.com:443"),
        Header::new(":path", "/chat?room=7"),
        Header::new("sec-websocket-version", "13"),
    ]
}

fn ready_client(codec: &mut FrameCodec) -> Connection {
    let mut connection = Connection::client(Settings::client());
    let frame = codec
        .decode(&mut settings_wire(&[(8, 1)]))
        .unwrap()
        .unwrap();
    connection.process_frame(frame).unwrap();
    while connection.next_frame().is_some() {}
    assert_eq!(connection.state(), ConnectionState::Open);
    connection
}

#[test]
fn peer_permission_requires_the_complete_validated_settings_frame() {
    let wire = settings_wire(&[(8, 1)]);
    for split in 0..wire.len() {
        let mut codec = FrameCodec::new();
        let mut first = BytesMut::from(&wire[..split]);
        assert!(codec.decode(&mut first).unwrap().is_none());
        assert!(!codec.peer_supports_extended_connect());
        first.extend_from_slice(&wire[split..]);
        assert!(matches!(
            codec.decode(&mut first).unwrap(),
            Some(Frame::Settings(_))
        ));
        assert!(codec.peer_supports_extended_connect());
        assert!(first.is_empty());
    }
}

#[test]
fn permission_is_sticky_across_ack_absence_and_repeated_enable() {
    let mut codec = FrameCodec::new();
    let frame = codec
        .decode(&mut settings_wire(&[(8, 0), (3, 17), (8, 1)]))
        .unwrap()
        .unwrap();
    let Frame::Settings(settings) = frame else {
        panic!("expected settings");
    };
    // The public exhaustive model still contains only its established variants.
    assert_eq!(settings.settings, vec![Setting::MaxConcurrentStreams(17)]);
    assert!(codec.peer_supports_extended_connect());

    for parameters in [vec![], vec![(3, 12)], vec![(8, 1), (8, 1)]] {
        codec
            .decode(&mut settings_wire(&parameters))
            .unwrap()
            .unwrap();
        assert!(codec.peer_supports_extended_connect());
    }
    let mut ack = BytesMut::new();
    Frame::Settings(SettingsFrame::ack())
        .encode(&mut ack)
        .unwrap();
    codec.decode(&mut ack.clone()).unwrap().unwrap();
    assert!(codec.peer_supports_extended_connect());

    let mut disabled = FrameCodec::new();
    disabled
        .decode(&mut settings_wire(&[(8, 0)]))
        .unwrap()
        .unwrap();
    assert!(!disabled.peer_supports_extended_connect());
    disabled.decode(&mut ack).unwrap().unwrap();
    assert!(!disabled.peer_supports_extended_connect());
}

#[test]
fn peer_cannot_withdraw_permission_in_one_or_later_settings() {
    let mut codec = FrameCodec::new();
    let error = codec
        .decode(&mut settings_wire(&[(8, 1), (8, 0)]))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ProtocolError);
    assert_eq!(error.stream_id, None);
    assert!(!codec.peer_supports_extended_connect());

    let mut codec = FrameCodec::new();
    codec
        .decode(&mut settings_wire(&[(8, 1)]))
        .unwrap()
        .unwrap();
    let error = codec.decode(&mut settings_wire(&[(8, 0)])).unwrap_err();
    assert_eq!(error.code, ErrorCode::ProtocolError);
    assert!(codec.peer_supports_extended_connect());
}

#[test]
fn malformed_settings_never_publish_peer_permission() {
    let mut wrong_stream = settings_wire(&[(8, 1)]);
    wrong_stream[8] = 1;
    let mut ack_payload = settings_wire(&[(8, 1)]);
    ack_payload[4] = super::super::frame::settings_flags::ACK;
    let mut malformed_length = settings_wire(&[(8, 1)]);
    malformed_length[2] = 7;
    malformed_length.extend_from_slice(&[0]);
    for mut wire in [
        wrong_stream,
        ack_payload,
        malformed_length,
        settings_wire(&[(8, 1), (2, 2)]),
        settings_wire(&[(8, 1), (4, 0x8000_0000)]),
        settings_wire(&[(8, 1), (5, 1)]),
        settings_wire(&[(8, 2)]),
    ] {
        let mut codec = FrameCodec::new();
        assert!(codec.decode(&mut wire).is_err());
        assert!(!codec.peer_supports_extended_connect());
    }
}

#[test]
fn extended_connect_waits_for_permission_without_consuming_stream_ids() {
    let mut codec = FrameCodec::new();
    let mut connection = Connection::client(Settings::client());
    assert!(
        connection
            .open_extended_connect(request_headers(), &codec)
            .is_err()
    );
    connection
        .process_frame(codec.decode(&mut settings_wire(&[])).unwrap().unwrap())
        .unwrap();
    while connection.next_frame().is_some() {}
    assert!(
        connection
            .open_extended_connect(request_headers(), &codec)
            .is_err()
    );
    assert_eq!(connection.active_stream_count(), 0);
    assert!(!connection.has_pending_frames());

    // A later SETTINGS can grant permission after an ordinary initial SETTINGS.
    connection
        .process_frame(
            codec
                .decode(&mut settings_wire(&[(8, 1)]))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    while connection.next_frame().is_some() {}
    let id = connection
        .open_extended_connect(request_headers(), &codec)
        .unwrap();
    assert_eq!(id, 1);
    assert_eq!(connection.stream(id).unwrap().state(), StreamState::Open);
    let Some(Frame::Headers(frame)) = connection.next_frame() else {
        panic!("extended CONNECT must start with HEADERS");
    };
    assert!(!frame.end_stream);
    assert!(frame.end_headers);
    let mut block = frame.header_block;
    let decoded = hpack::Decoder::new().decode(&mut block).unwrap();
    assert_eq!(decoded, request_headers());
}

#[test]
fn invalid_extended_request_is_refused_before_allocation_or_hpack() {
    let mut codec = FrameCodec::new();
    let mut connection = ready_client(&mut codec);
    let mut cases = Vec::new();
    for name in [":protocol", ":scheme", ":authority", ":path"] {
        let mut headers = request_headers();
        headers.retain(|header| header.name != name);
        cases.push(headers);
    }
    for (name, value) in [
        (":method", "GET"),
        (":protocol", "bad protocol"),
        (":scheme", "1http"),
        (":authority", "user@example.com"),
        (":path", "relative"),
    ] {
        let mut headers = request_headers();
        headers
            .iter_mut()
            .find(|header| header.name == name)
            .unwrap()
            .value = value.to_owned();
        cases.push(headers);
    }
    let mut duplicate = request_headers();
    duplicate.insert(2, Header::new(":protocol", "websocket"));
    cases.push(duplicate);
    let mut connection_specific = request_headers();
    connection_specific.push(Header::new("connection", "upgrade"));
    cases.push(connection_specific);
    let mut late_pseudo = request_headers();
    late_pseudo.push(Header::new(":status", "200"));
    cases.push(late_pseudo);

    for headers in cases {
        assert!(connection.open_extended_connect(headers, &codec).is_err());
        assert_eq!(connection.active_stream_count(), 0);
        assert!(!connection.has_pending_frames());
    }
    assert_eq!(
        connection
            .open_extended_connect(request_headers(), &codec)
            .unwrap(),
        1
    );
}

#[test]
fn extended_connect_cannot_open_on_server_or_draining_connection() {
    let mut codec = FrameCodec::new();
    let mut client = ready_client(&mut codec);
    let mut server = Connection::server(Settings::default());
    server
        .process_frame(Frame::Settings(SettingsFrame::new(Vec::new())))
        .unwrap();
    assert!(
        server
            .open_extended_connect(request_headers(), &codec)
            .is_err()
    );
    assert_eq!(server.active_stream_count(), 0);
    client.goaway(ErrorCode::NoError, Bytes::new());
    assert!(
        client
            .open_extended_connect(request_headers(), &codec)
            .is_err()
    );
    assert_eq!(client.active_stream_count(), 0);
}
