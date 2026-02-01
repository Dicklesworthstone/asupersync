use crate::websocket_e2e::util::{
    init_ws_test, read_exact, read_http_headers, ws_handshake_request_bytes,
};
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::codec::Encoder;
use asupersync::cx::Cx;
use asupersync::net::tcp::VirtualTcpStream;
use asupersync::net::websocket::{
    Frame, FrameCodec, Message, WebSocket, WebSocketAcceptor, WsError,
};
use std::net::SocketAddr;

#[test]
fn ws_conformance_client_frames_are_masked_on_wire() {
    init_ws_test("ws_conformance_client_frames_are_masked_on_wire");

    futures_lite::future::block_on(async {
        let client_addr: SocketAddr = "127.0.0.1:40101".parse().unwrap();
        let server_addr: SocketAddr = "127.0.0.1:40102".parse().unwrap();
        let (client_io, mut server_io) = VirtualTcpStream::pair(client_addr, server_addr);

        let cx = Cx::for_testing();
        let mut ws = WebSocket::from_upgraded(
            client_io,
            asupersync::net::websocket::WebSocketConfig::default(),
        );
        ws.send(&cx, Message::text("hello")).await.expect("send");

        let header = read_exact(&mut server_io, 2)
            .await
            .expect("read frame header");
        let masked = (header[1] & 0x80) != 0;
        assert_with_log!(masked, "client->server frames must be masked", true, masked);
    });
}

#[test]
fn ws_conformance_server_frames_are_not_masked_on_wire() {
    init_ws_test("ws_conformance_server_frames_are_not_masked_on_wire");

    futures_lite::future::block_on(async {
        let client_addr: SocketAddr = "127.0.0.1:40111".parse().unwrap();
        let server_addr: SocketAddr = "127.0.0.1:40112".parse().unwrap();
        let (mut client_io, server_io) = VirtualTcpStream::pair(client_addr, server_addr);

        let acceptor = WebSocketAcceptor::new();
        let cx = Cx::for_testing();

        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let req = ws_handshake_request_bytes("/", "127.0.0.1:40112", key, None);
        let mut server_ws = acceptor.accept(&cx, &req, server_io).await.expect("accept");

        // Drain the HTTP 101 response off the client stream so the next read is a WS frame.
        let _ = read_http_headers(&mut client_io).await.expect("read 101");

        server_ws
            .send(&cx, Message::text("hello"))
            .await
            .expect("send");

        let header = read_exact(&mut client_io, 2)
            .await
            .expect("read frame header");
        let masked = (header[1] & 0x80) != 0;
        assert_with_log!(
            !masked,
            "server->client frames must NOT be masked",
            false,
            masked
        );
    });
}

#[test]
fn ws_conformance_decode_rejects_unmasked_client_frame() {
    init_ws_test("ws_conformance_decode_rejects_unmasked_client_frame");

    // Minimal unmasked text frame: FIN=1 opcode=Text, MASK=0 len=5, payload="hello".
    let mut raw = BytesMut::from(&b"\x81\x05hello"[..]);

    let mut codec = FrameCodec::server();
    let err = codec
        .decode(&mut raw)
        .expect_err("server decoder must reject unmasked client frames");

    assert!(matches!(err, WsError::UnmaskedClientFrame));
}

#[test]
fn ws_conformance_decode_accepts_masked_client_frame() {
    init_ws_test("ws_conformance_decode_accepts_masked_client_frame");

    // Encode a masked client frame and ensure server decoder accepts it.
    let mut codec = FrameCodec::client();
    let mut out = BytesMut::new();
    codec
        .encode(Frame::text("hello"), &mut out)
        .expect("encode client frame");

    let mut server_codec = FrameCodec::server();
    let decoded = server_codec
        .decode(&mut out)
        .expect("decode should succeed")
        .expect("frame present");

    assert_with_log!(
        decoded.payload.as_ref() == b"hello",
        "payload should be unmasked on decode",
        "hello",
        String::from_utf8_lossy(decoded.payload.as_ref())
    );
}
