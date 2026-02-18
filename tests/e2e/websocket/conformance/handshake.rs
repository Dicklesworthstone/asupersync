use crate::websocket_e2e::util::{init_ws_test, read_http_headers, ws_handshake_request_bytes};
use asupersync::cx::Cx;
use asupersync::net::tcp::VirtualTcpStream;
use asupersync::net::websocket::{
    HttpResponse, WebSocketAcceptor, WsAcceptError, compute_accept_key,
};
use std::net::SocketAddr;

#[test]
fn ws_conformance_handshake_accepts_rfc_key_and_negotiates_protocol() {
    init_ws_test("ws_conformance_handshake_accepts_rfc_key_and_negotiates_protocol");

    futures_lite::future::block_on(async {
        let client_addr: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        let server_addr: SocketAddr = "127.0.0.1:40002".parse().unwrap();
        let (mut client, server) = VirtualTcpStream::pair(client_addr, server_addr);

        let acceptor = WebSocketAcceptor::new().protocol("chat");
        let cx: Cx = Cx::for_testing();

        // RFC 6455 sample key.
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let req =
            ws_handshake_request_bytes("/chat", "127.0.0.1:40002", key, Some("chat, superchat"));

        let _server_ws = acceptor
            .accept(&cx, &req, server)
            .await
            .expect("accept should succeed");

        let resp_bytes = read_http_headers(&mut client)
            .await
            .expect("read HTTP 101 response");
        let resp = HttpResponse::parse(&resp_bytes).expect("parse response");

        assert_with_log!(
            resp.status == 101,
            "status must be 101 Switching Protocols",
            101,
            resp.status
        );

        let accept = resp
            .header("sec-websocket-accept")
            .expect("Sec-WebSocket-Accept present");
        let expected = compute_accept_key(key);
        assert_with_log!(
            accept == expected,
            "Sec-WebSocket-Accept must match RFC computation",
            expected,
            accept
        );

        let protocol = resp
            .header("sec-websocket-protocol")
            .expect("Sec-WebSocket-Protocol present");
        assert_with_log!(
            protocol == "chat",
            "protocol should be negotiated",
            "chat",
            protocol
        );
    });
}

#[test]
fn ws_conformance_handshake_rejects_invalid_key() {
    init_ws_test("ws_conformance_handshake_rejects_invalid_key");

    futures_lite::future::block_on(async {
        let client_addr: SocketAddr = "127.0.0.1:40011".parse().unwrap();
        let server_addr: SocketAddr = "127.0.0.1:40012".parse().unwrap();
        let (_client, server) = VirtualTcpStream::pair(client_addr, server_addr);

        let acceptor = WebSocketAcceptor::new();
        let cx: Cx = Cx::for_testing();

        // Not base64(16 bytes).
        let bad_key = "not-a-valid-key";
        let req = ws_handshake_request_bytes("/", "127.0.0.1:40012", bad_key, None);

        let err = acceptor
            .accept(&cx, &req, server)
            .await
            .err()
            .expect("should error");
        match err {
            WsAcceptError::Handshake(_) => {} // expected
            other => panic!("expected handshake error, got: {other:?}"),
        }
    });
}
