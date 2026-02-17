use crate::websocket_e2e::util::{init_ws_test, read_http_headers, ws_handshake_request_bytes};
use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::net::tcp::VirtualTcpStream;
use asupersync::net::websocket::{Message, WebSocket, WebSocketAcceptor, WebSocketConfig};
use asupersync::types::Budget;
use std::net::SocketAddr;

fn run_smoke(seed: u64) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(50_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let client_addr: SocketAddr = "127.0.0.1:40701".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:40702".parse().unwrap();
    let (mut client_io, server_io) = VirtualTcpStream::pair(client_addr, server_addr);

    let acceptor = WebSocketAcceptor::new();
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let req = ws_handshake_request_bytes("/", "127.0.0.1:40702", key, None);

    let (server_task_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            let cx: Cx = Cx::for_testing();
            let mut ws = acceptor.accept(&cx, &req, server_io).await.expect("accept");
            if let Some(Message::Text(t)) = ws.recv(&cx).await.expect("recv") {
                ws.send(&cx, Message::text(t)).await.expect("send");
            }
        })
        .expect("create_task");
    runtime
        .scheduler
        .lock()
        
        .schedule(server_task_id, 0);

    let (client_task_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            let cx: Cx = Cx::for_testing();
            let _ = read_http_headers(&mut client_io).await.expect("read 101");
            let mut ws = WebSocket::from_upgraded(client_io, WebSocketConfig::default());
            ws.send(&cx, Message::text("hello")).await.expect("send");
            let _ = ws.recv(&cx).await.expect("recv");
        })
        .expect("create_task");
    runtime
        .scheduler
        .lock()
        
        .schedule(client_task_id, 0);

    runtime.run_until_quiescent();
}

#[test]
fn ws_lab_schedule_smoke_multiple_seeds() {
    init_ws_test("ws_lab_schedule_smoke_multiple_seeds");

    // Keep this small to make CI predictable while still catching
    // obvious schedule-sensitive bugs.
    for seed in 0..20_u64 {
        run_smoke(seed);
    }
}
