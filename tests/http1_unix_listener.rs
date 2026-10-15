//! `Http1Listener::from_unix_listener`: HTTP/1.1 handlers and Router
//! applications served on a Unix-domain socket, the way a reverse proxy
//! (`proxy_pass http://unix:/run/app.sock`) reaches them. Plain std clients
//! connect through the socket file and read whole responses.
#![cfg(unix)]

use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig};
use asupersync::http::h1::server::{HostPolicy, Http1Config};
use asupersync::http::h1::types::{Request as HttpRequest, Response as HttpResponse};
use asupersync::net::unix::UnixListener;
use asupersync::runtime::RuntimeBuilder;
use asupersync::web::handler::FnHandler;
use asupersync::web::router::{Router, get};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn socket_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("asup-h1-{name}-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

fn config() -> Http1ListenerConfig {
    Http1ListenerConfig::default()
        .http_config(Http1Config {
            allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
            ..Http1Config::default()
        })
        .drain_timeout(Duration::from_secs(5))
        .hard_drain_timeout(Duration::from_secs(10))
}

/// One `Connection: close` request from a blocking std client on another
/// thread; returns the whole response.
fn http_get(path: &Path, target: &'static str) -> String {
    let path = path.to_owned();
    std::thread::spawn(move || {
        let mut stream = StdUnixStream::connect(&path).expect("connect to the socket");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("read timeout");
        let request =
            format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).expect("write request");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read response");
        String::from_utf8(response).expect("UTF-8 response")
    })
    .join()
    .expect("client thread")
}

/// The same request from an async client inside the runtime.
async fn http_get_async(path: &Path, target: &str) -> String {
    use asupersync::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = asupersync::net::unix::UnixStream::connect(path)
        .await
        .expect("connect to the socket");
    let request = format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    AsyncWriteExt::write_all(&mut stream, request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    AsyncReadExt::read_to_end(&mut stream, &mut response)
        .await
        .expect("read response");
    String::from_utf8(response).expect("UTF-8 response")
}

fn hello() -> &'static str {
    "hello over a unix socket"
}

#[test]
fn http1_handler_serves_requests_on_a_unix_socket() {
    let path = socket_path("plain");
    let server_path = path.clone();
    let client_path = path.clone();
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();
    runtime.block_on(async move {
        let unix = UnixListener::bind(&server_path)
            .await
            .expect("bind Unix socket");
        let listener = Http1Listener::from_unix_listener(
            unix,
            |request: HttpRequest| async move {
                let body = format!("{} peer={:?}", request.uri, request.peer_addr).into_bytes();
                HttpResponse::new(200, "OK", body)
            },
            config(),
        );
        assert_eq!(
            listener.local_addr().expect_err("no socket address").kind(),
            std::io::ErrorKind::InvalidInput
        );
        let manager = listener.connection_manager().clone();
        let run_runtime = handle.clone();
        let run = handle
            .clone()
            .try_spawn(async move { listener.run(&run_runtime).await })
            .expect("spawn listener");

        for target in ["/first", "/second?x=1"] {
            let response = http_get(&client_path, target);
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert!(
                response.ends_with(&format!("{target} peer=None")),
                "{response}"
            );
        }
        // The host policy still applies on this transport.
        let refused = std::thread::spawn({
            let path = client_path.clone();
            move || {
                let mut stream = StdUnixStream::connect(&path).expect("connect");
                stream
                    .write_all(b"GET / HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n")
                    .expect("write");
                let mut response = String::new();
                stream.read_to_string(&mut response).expect("read");
                response
            }
        })
        .join()
        .expect("client thread");
        assert!(refused.starts_with("HTTP/1.1 421"), "{refused}");

        assert!(manager.begin_drain(Duration::from_secs(5)));
        let stats = run.await.expect("listener run");
        assert!(stats.drain_report.expect("drain report").reached_quiescence);
    });
    let _ = std::fs::remove_file(path);
}

#[test]
fn router_application_serves_on_a_unix_socket_through_run_in() {
    let path = socket_path("router");
    let server_path = path.clone();
    let client_path = path.clone();
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();
    runtime.block_on(handle.spawn(async move {
        let cx = asupersync::Cx::current().expect("runtime Cx");
        let unix = UnixListener::bind(&server_path)
            .await
            .expect("bind Unix socket");
        let app = Router::new()
            .route("/hello", get(FnHandler::new(hello)))
            .into_http_handler();
        let listener = Http1Listener::from_unix_listener(unix, app, config());
        let manager = listener.connection_manager().clone();
        let run_cx = cx.clone();
        let run = cx
            .spawn(move |_| async move { listener.run_in(&run_cx).await })
            .expect("spawn listener");

        let response = http_get_async(&client_path, "/hello").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("hello over a unix socket"), "{response}");
        let missing = http_get_async(&client_path, "/missing").await;
        assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");

        assert!(manager.begin_drain(Duration::from_secs(5)));
        let mut run = run;
        let stats = run.join(&cx).await.expect("listener run").expect("run_in");
        assert!(stats.drain_report.expect("drain report").reached_quiescence);
    }));
    let _ = std::fs::remove_file(path);
}
