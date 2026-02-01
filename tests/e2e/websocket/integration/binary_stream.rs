use crate::websocket_e2e::util::{init_ws_test, read_http_headers};
use asupersync::bytes::Bytes;
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
fn ws_integration_large_binary_roundtrip() {
    init_ws_test("ws_integration_large_binary_roundtrip");

    let (addr_tx, addr_rx) = mpsc::channel::<SocketAddr>();

    let server_thread = thread::spawn(move || {
        futures_lite::future::block_on(async move {
            let cx = Cx::for_testing();
            let acceptor = WebSocketAcceptor::new();
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            addr_tx.send(addr).expect("send addr");

            let (mut stream, _peer) = listener.accept().await.expect("accept tcp");
            let req = read_http_request(&mut stream).await.expect("read request");
            let mut ws = acceptor.accept(&cx, &req, stream).await.expect("ws accept");

            if let Some(Message::Binary(b)) = ws.recv(&cx).await.expect("recv") {
                ws.send(&cx, Message::Binary(b)).await.expect("echo binary");
            }

            let _ = ws.close(CloseReason::going_away()).await;
        });
    });

    let addr = addr_rx.recv().expect("addr");

    futures_lite::future::block_on(async move {
        let cx = Cx::for_testing();
        let url = format!("ws://{}:{}/", addr.ip(), addr.port());
        let mut ws = WebSocket::connect(&cx, &url).await.expect("connect");

        // 1 MiB payload, deterministic content.
        let mut data = vec![0u8; 1024 * 1024];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        ws.send(&cx, Message::Binary(Bytes::from(data.clone())))
            .await
            .expect("send binary");

        let msg = ws.recv(&cx).await.expect("recv").expect("msg");
        match msg {
            Message::Binary(b) => assert_eq!(b.as_ref(), data.as_slice()),
            other => panic!("expected Binary, got {other:?}"),
        }
    });

    server_thread.join().expect("server thread");
}
