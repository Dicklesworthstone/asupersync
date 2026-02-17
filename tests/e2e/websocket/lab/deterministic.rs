use crate::websocket_e2e::util::{init_ws_test, read_http_headers, ws_handshake_request_bytes};
use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::net::tcp::VirtualTcpStream;
use asupersync::net::websocket::{Message, WebSocket, WebSocketAcceptor, WebSocketConfig};
use asupersync::types::Budget;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

fn run_with_seed(seed: u64) -> Vec<String> {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(50_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let events_server = Arc::clone(&events);
    let events_client = Arc::clone(&events);

    let client_addr: SocketAddr = "127.0.0.1:40601".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:40602".parse().unwrap();
    let (mut client_io, server_io) = VirtualTcpStream::pair(client_addr, server_addr);

    let acceptor = WebSocketAcceptor::new();
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let req = ws_handshake_request_bytes("/", "127.0.0.1:40602", key, None);

    // Server task: accept upgrade and echo one message.
    let (server_task_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            let cx: Cx = Cx::for_testing();
            events_server.lock().unwrap().push("server:accept".into());
            let mut ws = acceptor.accept(&cx, &req, server_io).await.expect("accept");
            events_server.lock().unwrap().push("server:accepted".into());

            if let Some(Message::Text(t)) = ws.recv(&cx).await.expect("recv") {
                events_server
                    .lock()
                    .expect("poisoned")
                    .push(format!("server:recv:{t}"));
                ws.send(&cx, Message::text(t)).await.expect("send");
                events_server.lock().unwrap().push("server:sent".into());
            }
        })
        .expect("create_task server");
    runtime
        .scheduler
        .lock()
        
        .schedule(server_task_id, 0);

    // Client task: read 101 response (from accept) and then use from_upgraded on the same stream.
    let (client_task_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            let cx: Cx = Cx::for_testing();
            events_client
                .lock()
                .expect("poisoned")
                .push("client:drain_101".into());

            // Wait until the server writes the HTTP 101 response.
            let _ = read_http_headers(&mut client_io).await.expect("read 101");

            // Now speak WebSocket on the upgraded stream.
            let mut ws = WebSocket::from_upgraded(client_io, WebSocketConfig::default());
            events_client
                .lock()
                .expect("poisoned")
                .push("client:connected".into());

            ws.send(&cx, Message::text("hello")).await.expect("send");
            events_client.lock().unwrap().push("client:sent".into());

            let msg = ws.recv(&cx).await.expect("recv").expect("msg");
            match msg {
                Message::Text(t) => events_client
                    .lock()
                    .expect("poisoned")
                    .push(format!("client:recv:{t}")),
                other => panic!("unexpected: {other:?}"),
            }
        })
        .expect("create_task client");
    runtime
        .scheduler
        .lock()
        
        .schedule(client_task_id, 0);

    runtime.run_until_quiescent();
    let snapshot = events.lock().unwrap().clone();
    snapshot
}

#[test]
fn ws_lab_deterministic_event_order_is_replayable() {
    init_ws_test("ws_lab_deterministic_event_order_is_replayable");

    let a = run_with_seed(123);
    let b = run_with_seed(123);

    assert_with_log!(
        a == b,
        "same seed should produce same event trace",
        format!("{a:?}"),
        format!("{b:?}")
    );
}
