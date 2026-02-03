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
    read_http_headers(io).await
}

#[test]
fn ws_integration_client_can_reconnect_after_server_closes() {
    init_ws_test("ws_integration_client_can_reconnect_after_server_closes");

    let (addr_tx, addr_rx) = mpsc::channel::<SocketAddr>();

    let server_thread = thread::spawn(move || {
        futures_lite::future::block_on(async move {
            let cx: Cx = Cx::for_testing();
            let acceptor = WebSocketAcceptor::new();
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            addr_tx.send(addr).expect("send addr");

            // Accept two sequential connections, echo one message each, then drop.
            for _ in 0..2 {
                let (mut stream, _peer) = listener.accept().await.expect("accept");
                let req = read_http_request(&mut stream).await.expect("read request");
                let mut ws = acceptor.accept(&cx, &req, stream).await.expect("ws accept");

                if let Some(Message::Text(text)) = ws.recv(&cx).await.expect("recv") {
                    ws.send(&cx, Message::text(text)).await.expect("echo");
                }
                let _ = ws.close(CloseReason::going_away()).await;
            }
        });
    });

    let addr = addr_rx.recv().expect("addr");

    futures_lite::future::block_on(async move {
        let cx: Cx = Cx::for_testing();
        let url = format!("ws://{}:{}/", addr.ip(), addr.port());

        for round in 0..2 {
            let mut ws = WebSocket::connect(&cx, &url).await.expect("connect");
            let msg = format!("hello-{round}");
            ws.send(&cx, Message::text(msg.clone()))
                .await
                .expect("send");
            let got = ws.recv(&cx).await.expect("recv").expect("msg");
            assert!(matches!(got, Message::Text(s) if s == msg));
        }
    });

    server_thread.join().expect("server thread");
}
