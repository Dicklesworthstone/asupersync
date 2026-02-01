use crate::websocket_e2e::util::{init_ws_test, read_http_headers, ws_handshake_request_bytes};
use asupersync::cx::Cx;
use asupersync::net::tcp::VirtualTcpStream;
use asupersync::net::websocket::{
    CloseReason, Message, WebSocket, WebSocketAcceptor, WebSocketConfig,
};
use std::net::SocketAddr;

#[test]
fn ws_conformance_close_handshake_client_initiated() {
    init_ws_test("ws_conformance_close_handshake_client_initiated");

    futures_lite::future::block_on(async {
        let client_addr: SocketAddr = "127.0.0.1:40201".parse().unwrap();
        let server_addr: SocketAddr = "127.0.0.1:40202".parse().unwrap();
        let (mut client_io, server_io) = VirtualTcpStream::pair(client_addr, server_addr);

        let acceptor = WebSocketAcceptor::new();
        let cx = Cx::for_testing();

        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let req = ws_handshake_request_bytes("/", "127.0.0.1:40202", key, None);
        let mut server_ws = acceptor.accept(&cx, &req, server_io).await.expect("accept");

        let _ = read_http_headers(&mut client_io).await.expect("read 101");
        let mut client_ws = WebSocket::from_upgraded(client_io, WebSocketConfig::default());

        // Client close waits for the server's close response; server recv triggers that response.
        let client_fut = async move { client_ws.close(CloseReason::normal()).await };
        let server_fut = async move { server_ws.recv(&cx).await };

        let (client_res, server_msg) = futures_lite::future::zip(client_fut, server_fut).await;

        client_res.expect("client close");
        let msg = server_msg
            .expect("server recv")
            .expect("server got message");
        assert!(matches!(msg, Message::Close(_)));
    });
}
