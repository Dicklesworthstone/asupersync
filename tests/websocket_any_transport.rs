//! `WebSocketUpgrade::on_upgrade_any`: Router WebSocket routes on every
//! transport the HTTP/1 listener serves. `on_upgrade`'s callback receives the
//! raw TCP stream, so `wss://` through `Http1Listener::run_tls`, Unix-domain
//! sockets and `HttpAutoListener` refuse it before the `101`;
//! `on_upgrade_any` runs on all of them. Each test echoes one message
//! through a real client.
#![cfg(unix)]

use asupersync::cx::Cx;
use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig};
use asupersync::http::h1::server::{HostPolicy, Http1Config};
use asupersync::http::{HttpAutoListener, HttpAutoListenerConfig};
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::unix::{UnixListener, UnixStream};
use asupersync::net::websocket::{
    ClientHandshake, HttpResponse as WsHttpResponse, Message, WebSocket, WebSocketConfig,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::util::DetEntropy;
use asupersync::web::handler::{FnHandler, FnHandler1};
use asupersync::web::router::{Router, get};
use asupersync::web::websocket::WebSocketUpgrade;
use std::time::Duration;

fn localhost() -> HostPolicy {
    HostPolicy::allow_list(vec!["localhost".to_owned()])
}

fn http1_config() -> Http1ListenerConfig {
    Http1ListenerConfig::default()
        .http_config(Http1Config {
            allowed_hosts: localhost(),
            ..Http1Config::default()
        })
        .drain_timeout(Duration::from_secs(2))
        .hard_drain_timeout(Duration::from_secs(5))
}

fn hello() -> &'static str {
    "plain route"
}

/// `/ws` echoes one message through `on_upgrade_any`; `/tcp-only` uses the
/// TCP-typed `on_upgrade`; `/hello` is an ordinary route.
fn router() -> Router {
    Router::new()
        .route(
            "/ws",
            get(FnHandler1::<_, WebSocketUpgrade>::new(
                |upgrade: WebSocketUpgrade| {
                    upgrade
                        .skip_origin_check()
                        .on_upgrade_any(|cx, mut ws| async move {
                            let message = ws
                                .recv(&cx)
                                .await
                                .expect("receive client message")
                                .expect("client sent one message");
                            ws.send(&cx, message).await.expect("echo");
                        })
                },
            )),
        )
        .route(
            "/tcp-only",
            get(FnHandler1::<_, WebSocketUpgrade>::new(
                |upgrade: WebSocketUpgrade| {
                    upgrade
                        .skip_origin_check()
                        .on_upgrade(|_cx, _ws| async move {})
                },
            )),
        )
        .route("/hello", get(FnHandler::new(hello)))
}

fn text(message: Option<Message>) -> String {
    match message {
        Some(Message::Text(text)) => text,
        other => panic!("expected a text message, got {other:?}"),
    }
}

/// The WebSocket opening handshake over `stream` for `ws://localhost{path}`;
/// the response head, and the stream on success.
async fn client_handshake<S>(mut stream: S, path: &str) -> (String, S)
where
    S: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin,
{
    let entropy = DetEntropy::new(7);
    let handshake =
        ClientHandshake::new(&format!("ws://localhost{path}"), &entropy).expect("handshake");
    AsyncWriteExt::write_all(&mut stream, &handshake.request_bytes())
        .await
        .expect("write handshake");
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match AsyncReadExt::read(&mut stream, &mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    if let Ok(response) = WsHttpResponse::parse(&head) {
        handshake
            .validate_response(&response)
            .expect("valid 101 response");
    }
    (String::from_utf8_lossy(&head).into_owned(), stream)
}

#[test]
fn websocket_over_a_unix_socket_listener() {
    let path = std::env::temp_dir().join(format!("asup-ws-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();
    let socket = path.clone();
    runtime.block_on(handle.clone().spawn(async move {
        let cx = Cx::current().expect("runtime Cx");
        let unix = UnixListener::bind(&socket).await.expect("bind Unix socket");
        let listener =
            Http1Listener::from_unix_listener(unix, router().into_http1_handler(), http1_config());
        let shutdown = listener.shutdown_signal();
        let run_runtime = handle.clone();
        let run = handle
            .try_spawn(async move { listener.run(&run_runtime).await })
            .expect("spawn listener");

        let stream = UnixStream::connect(&socket).await.expect("connect");
        let (head, stream) = client_handshake(stream, "/ws").await;
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        let mut ws = WebSocket::from_upgraded(stream, WebSocketConfig::default());
        ws.send(&cx, Message::text("over unix"))
            .await
            .expect("send");
        assert_eq!(text(ws.recv(&cx).await.expect("recv")), "over unix");

        // The TCP-typed callback is refused on this transport before any 101.
        let stream = UnixStream::connect(&socket).await.expect("connect");
        let (head, _stream) = client_handshake(stream, "/tcp-only").await;
        assert!(!head.contains(" 101"), "{head}");

        assert!(shutdown.begin_drain(Duration::from_secs(2)));
        let _ = run.await.expect("listener run");
    }));
    let _ = std::fs::remove_file(path);
}

#[test]
fn websocket_through_the_auto_listener_next_to_http2() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();
    runtime.block_on(handle.clone().spawn(async move {
        let cx = Cx::current().expect("runtime Cx");
        let config = HttpAutoListenerConfig::default()
            .http1(http1_config())
            .http2(
                asupersync::http::h2::listener::Http2ListenerConfig::default()
                    .host_policy(localhost())
                    .drain_timeout(Duration::from_secs(2))
                    .hard_drain_timeout(Duration::from_secs(5)),
            );
        let listener = HttpAutoListener::bind("127.0.0.1:0", router().into_http1_handler(), config)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let shutdown = listener.shutdown_signal();
        let run_runtime = handle.clone();
        let run = handle
            .try_spawn(async move { listener.run(&run_runtime).await })
            .expect("spawn listener");

        let mut ws = WebSocket::connect(&cx, &format!("ws://localhost:{}/ws", addr.port()))
            .await
            .expect("WebSocket over the auto listener");
        ws.send(&cx, Message::text("auto")).await.expect("send");
        assert_eq!(text(ws.recv(&cx).await.expect("recv")), "auto");

        // The same router answers an HTTP/2 request on the same port.
        let stream = asupersync::net::TcpStream::connect(addr)
            .await
            .expect("connect");
        let response = asupersync::http::h2::client::Http2Client::new()
            .get(format!("http://localhost:{}/hello", addr.port()))
            .send_on(&cx, stream)
            .await
            .expect("HTTP/2 request");
        assert_eq!(
            (response.status, response.text().expect("UTF-8")),
            (200, "plain route")
        );

        assert!(shutdown.begin_drain(Duration::from_secs(2)));
        let _ = run.await.expect("listener run");
    }));
}

#[cfg(feature = "tls")]
#[test]
fn wss_through_run_tls() {
    use asupersync::tls::{
        Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder, TlsConnectorBuilder,
    };

    const SERVER_CERT_PEM: &[u8] = include_bytes!("fixtures/tls/server.crt");
    const SERVER_KEY_PEM: &[u8] = include_bytes!("fixtures/tls/server.key");
    let acceptor = TlsAcceptorBuilder::new(
        CertificateChain::from_pem(SERVER_CERT_PEM).expect("chain"),
        PrivateKey::from_pem(SERVER_KEY_PEM).expect("key"),
    )
    .alpn_protocols(vec![b"http/1.1".to_vec()])
    .build()
    .expect("acceptor");
    let root = Certificate::from_pem(SERVER_CERT_PEM)
        .expect("root")
        .into_iter()
        .next()
        .expect("certificate");
    let connector = TlsConnectorBuilder::new()
        .add_root_certificate(&root)
        .alpn_protocols(vec![b"http/1.1".to_vec()])
        .build()
        .expect("connector");

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();
    runtime.block_on(handle.clone().spawn(async move {
        let cx = Cx::current().expect("runtime Cx");
        let listener = Http1Listener::bind_upgradeable_with_config(
            "127.0.0.1:0",
            router().into_http1_handler(),
            http1_config(),
        )
        .await
        .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let shutdown = listener.shutdown_signal();
        let run_runtime = handle.clone();
        let run = handle
            .try_spawn(async move { listener.run_tls(&run_runtime, acceptor).await })
            .expect("spawn listener");

        let url = format!("wss://localhost:{}/ws", addr.port());
        let mut ws = WebSocket::connect_tls(&cx, &url, WebSocketConfig::default(), &connector)
            .await
            .expect("wss handshake");
        ws.send(&cx, Message::text("secure")).await.expect("send");
        assert_eq!(text(ws.recv(&cx).await.expect("recv")), "secure");

        let tcp_only = format!("wss://localhost:{}/tcp-only", addr.port());
        assert!(
            WebSocket::connect_tls(&cx, &tcp_only, WebSocketConfig::default(), &connector)
                .await
                .is_err(),
            "the TCP-typed callback is still refused over TLS"
        );

        assert!(shutdown.begin_drain(Duration::from_secs(2)));
        let _ = run.await.expect("listener run");
    }));
}
