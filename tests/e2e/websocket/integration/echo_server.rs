use crate::websocket_e2e::util::{init_ws_test, read_http_headers};
use asupersync::cx::Cx;
use asupersync::net::websocket::{CloseReason, Message, WebSocket, WebSocketAcceptor};
use asupersync::net::TcpListener;
use std::io;
use std::net::SocketAddr;
use std::sync::mpsc;
use std::thread;

async fn read_http_request<IO: asupersync::io::AsyncRead + Unpin>(
    io: &mut IO,
) -> io::Result<Vec<u8>> {
    // Reuse the same logic as response header reads.
    read_http_headers(io).await
}

#[test]
fn ws_integration_echo_server_roundtrip() {
    init_ws_test("ws_integration_echo_server_roundtrip");

    let (addr_tx, addr_rx) = mpsc::channel::<SocketAddr>();

    let server_thread = thread::spawn(move || {
        futures_lite::future::block_on(async move {
            let cx: Cx = Cx::for_testing();
            let acceptor = WebSocketAcceptor::new();

            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            addr_tx.send(addr).expect("send addr");

            let (mut stream, _peer) = listener.accept().await.expect("accept tcp");
            let req = read_http_request(&mut stream).await.expect("read request");
            let mut ws = acceptor.accept(&cx, &req, stream).await.expect("ws accept");

            // Echo exactly one text message, then close.
            if let Some(Message::Text(text)) = ws.recv(&cx).await.expect("recv") {
                ws.send(&cx, Message::text(text)).await.expect("echo send");
            }

            // Best-effort clean close (ignore if peer already dropped).
            let _ = ws.close(CloseReason::going_away()).await;
        });
    });

    let addr = addr_rx.recv().expect("addr from server");

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let url = format!("ws://{}:{}/", addr.ip(), addr.port());

        let mut ws = WebSocket::connect(&cx, &url).await.expect("connect");
        ws.send(&cx, Message::text("hello")).await.expect("send");
        let msg = ws.recv(&cx).await.expect("recv").expect("msg");
        assert!(matches!(msg, Message::Text(s) if s == "hello"));

        ws.close(CloseReason::normal()).await.expect("client close");
    });

    server_thread.join().expect("server thread");
}
