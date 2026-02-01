use crate::websocket_e2e::util::{init_ws_test, read_http_headers, ws_handshake_request_bytes};
use asupersync::cx::Cx;
use asupersync::net::tcp::VirtualTcpStream;
use asupersync::net::websocket::{
    CloseReason, Message, WebSocket, WebSocketAcceptor, WebSocketConfig, WsError,
};
use asupersync::types::CancelKind;
use std::net::SocketAddr;

#[test]
fn ws_cancel_client_send_when_cancelled_initiates_close_and_errors() {
    init_ws_test("ws_cancel_client_send_when_cancelled_initiates_close_and_errors");

    futures_lite::future::block_on(async {
        let client_addr: SocketAddr = "127.0.0.1:40401".parse().unwrap();
        let server_addr: SocketAddr = "127.0.0.1:40402".parse().unwrap();
        let (mut client_io, server_io) = VirtualTcpStream::pair(client_addr, server_addr);

        let acceptor = WebSocketAcceptor::new();
        let server_cx = Cx::for_testing();

        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let req = ws_handshake_request_bytes("/", "127.0.0.1:40402", key, None);
        let mut server_ws = acceptor
            .accept(&server_cx, &req, server_io)
            .await
            .expect("accept");

        let _ = read_http_headers(&mut client_io).await.expect("read 101");
        let mut client_ws = WebSocket::from_upgraded(client_io, WebSocketConfig::default());

        // Cancel client side before attempting to send.
        let client_cx = Cx::for_testing();
        client_cx.cancel_fast(CancelKind::User);

        let err = client_ws
            .send(&client_cx, Message::text("should-fail"))
            .await
            .expect_err("send should error");
        assert!(matches!(err, WsError::Io(e) if e.kind() == std::io::ErrorKind::Interrupted));

        // Server should observe a close (going away) frame.
        let msg = server_ws
            .recv(&server_cx)
            .await
            .expect("recv")
            .expect("msg");
        assert!(
            matches!(msg, Message::Close(Some(reason)) if reason.code == CloseReason::going_away().code)
        );
    });
}
