use crate::websocket_e2e::util::{init_ws_test, ws_handshake_request_bytes};
use asupersync::cx::Cx;
use asupersync::net::tcp::VirtualTcpStream;
use asupersync::net::websocket::{WebSocketAcceptor, WsAcceptError};
use std::net::SocketAddr;

#[test]
fn ws_cancel_server_accept_when_cancelled_returns_cancelled() {
    init_ws_test("ws_cancel_server_accept_when_cancelled_returns_cancelled");

    futures_lite::future::block_on(async {
        let client_addr: SocketAddr = "127.0.0.1:40501".parse().unwrap();
        let server_addr: SocketAddr = "127.0.0.1:40502".parse().unwrap();
        let (_client_io, server_io) = VirtualTcpStream::pair(client_addr, server_addr);

        let acceptor = WebSocketAcceptor::new();
        let cx: Cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let req = ws_handshake_request_bytes("/", "127.0.0.1:40502", key, None);
        let err = acceptor
            .accept(&cx, &req, server_io)
            .await
            .err()
            .expect("accept should error");
        assert!(matches!(err, WsAcceptError::Cancelled));
    });
}
