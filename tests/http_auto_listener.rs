//! `HttpAutoListener`: HTTP/1.1 and HTTP/2 on one port. Real clients of each
//! protocol reach the same handler, which reports the version it served:
//! cleartext HTTP/1.1 and HTTP/2 with prior knowledge are told apart by the
//! connection preface, and over TLS by the negotiated ALPN protocol.

use asupersync::cx::Cx;
use asupersync::http::h1::listener::Http1ListenerConfig;
use asupersync::http::h1::server::{HostPolicy, Http1Config};
use asupersync::http::h1::types::{Request, Response};
use asupersync::http::h2::client::Http2Client;
use asupersync::http::h2::listener::Http2ListenerConfig;
use asupersync::http::{HttpAutoListener, HttpAutoListenerConfig};
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpStream;
use asupersync::runtime::RuntimeBuilder;
use std::net::SocketAddr;
use std::time::Duration;

fn config() -> HttpAutoListenerConfig {
    let localhost = HostPolicy::allow_list(vec!["localhost".to_owned()]);
    HttpAutoListenerConfig::default()
        .http1(
            Http1ListenerConfig::default()
                .http_config(Http1Config {
                    allowed_hosts: localhost.clone(),
                    ..Http1Config::default()
                })
                .drain_timeout(Duration::from_secs(5))
                .hard_drain_timeout(Duration::from_secs(10)),
        )
        .http2(
            Http2ListenerConfig::default()
                .host_policy(localhost)
                .drain_timeout(Duration::from_secs(5))
                .hard_drain_timeout(Duration::from_secs(10)),
        )
}

async fn report(request: Request) -> Response {
    let body = format!(
        "{:?} {} peer={}",
        request.version,
        request.uri,
        request.peer_addr.is_some()
    );
    Response::new(200, "OK", body.into_bytes())
}

/// One `Connection: close` HTTP/1.1 request over `stream`; the whole response.
async fn http1_get<S>(stream: &mut S, target: &str) -> String
where
    S: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin,
{
    let request = format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    AsyncWriteExt::write_all(stream, request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    AsyncReadExt::read_to_end(stream, &mut response)
        .await
        .expect("read response");
    String::from_utf8(response).expect("UTF-8 response")
}

#[test]
fn cleartext_http1_and_http2_prior_knowledge_share_one_port() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();
    runtime.block_on(handle.clone().spawn(async move {
        let cx = Cx::current().expect("runtime Cx");
        let listener = HttpAutoListener::bind("127.0.0.1:0", report, config())
            .await
            .expect("bind");
        let addr: SocketAddr = listener.local_addr().expect("local addr");
        let shutdown = listener.shutdown_signal();
        let run_runtime = handle.clone();
        let run = handle
            .try_spawn(async move { listener.run(&run_runtime).await })
            .expect("spawn listener");

        // HTTP/1.1, including a POST whose first byte matches the preface.
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let response = http1_get(&mut stream, "/one").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("Http11 /one peer=true"), "{response}");
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        AsyncWriteExt::write_all(
            &mut stream,
            b"POST /posted HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
        )
        .await
        .expect("write POST");
        let mut response = Vec::new();
        AsyncReadExt::read_to_end(&mut stream, &mut response)
            .await
            .expect("read POST response");
        let response = String::from_utf8(response).expect("UTF-8");
        assert!(response.ends_with("Http11 /posted peer=true"), "{response}");

        // HTTP/2 with prior knowledge on the same port.
        for target in ["/two", "/three"] {
            let stream = TcpStream::connect(addr).await.expect("connect");
            let response = Http2Client::new()
                .get(format!("http://localhost:{}{target}", addr.port()))
                .send_on(&cx, stream)
                .await
                .expect("HTTP/2 request");
            assert_eq!(response.status, 200);
            assert_eq!(
                response.text().expect("UTF-8"),
                format!("Http2 {target} peer=true")
            );
        }

        assert!(shutdown.begin_drain(Duration::from_secs(5)));
        let stats = run.await.expect("auto listener run");
        assert!(
            stats
                .http1
                .drain_report
                .expect("HTTP/1.1 drain report")
                .reached_quiescence
        );
        assert!(
            stats
                .http2
                .drain_report
                .expect("HTTP/2 drain report")
                .reached_quiescence
        );
    }));
}

#[test]
fn a_connection_that_never_finishes_the_preface_is_dropped_at_the_detect_timeout() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();
    runtime.block_on(handle.clone().spawn(async move {
        let listener = HttpAutoListener::bind(
            "127.0.0.1:0",
            report,
            config().detect_timeout(Duration::from_millis(200)),
        )
        .await
        .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let shutdown = listener.shutdown_signal();
        let run_runtime = handle.clone();
        let run = handle
            .try_spawn(async move { listener.run(&run_runtime).await })
            .expect("spawn listener");

        // A preface prefix that never completes: neither protocol can be chosen.
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        AsyncWriteExt::write_all(&mut stream, b"PRI * HTTP/2.0")
            .await
            .expect("write partial preface");
        let mut rest = Vec::new();
        let read = AsyncReadExt::read_to_end(&mut stream, &mut rest).await;
        assert!(
            read.is_err() || rest.is_empty(),
            "the stalled connection is closed without a response: {rest:?}"
        );

        // The port still serves both protocols afterwards.
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let response = http1_get(&mut stream, "/after").await;
        assert!(response.ends_with("Http11 /after peer=true"), "{response}");

        assert!(shutdown.begin_drain(Duration::from_secs(5)));
        let _ = run.await.expect("auto listener run");
    }));
}

#[cfg(feature = "tls")]
#[test]
fn tls_alpn_selects_http2_or_http1_on_one_port() {
    use asupersync::tls::{
        Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder, TlsConnectorBuilder,
    };

    const SERVER_CERT_PEM: &[u8] = include_bytes!("fixtures/tls/server.crt");
    const SERVER_KEY_PEM: &[u8] = include_bytes!("fixtures/tls/server.key");

    let chain = CertificateChain::from_pem(SERVER_CERT_PEM).expect("chain");
    let key = PrivateKey::from_pem(SERVER_KEY_PEM).expect("key");
    let acceptor = TlsAcceptorBuilder::new(chain, key)
        .alpn_protocols(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
        .build()
        .expect("acceptor");
    let root = Certificate::from_pem(SERVER_CERT_PEM)
        .expect("root")
        .into_iter()
        .next()
        .expect("certificate");
    let connector = |alpn: &[u8]| {
        TlsConnectorBuilder::new()
            .add_root_certificate(&root)
            .alpn_protocols_required(vec![alpn.to_vec()])
            .build()
            .expect("connector")
    };
    let http1_connector = connector(b"http/1.1");
    let http2_connector = connector(b"h2");

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();
    runtime.block_on(handle.clone().spawn(async move {
        let cx = Cx::current().expect("runtime Cx");
        let listener = HttpAutoListener::bind("127.0.0.1:0", report, config())
            .await
            .expect("bind")
            .with_tls(acceptor);
        let addr = listener.local_addr().expect("local addr");
        let shutdown = listener.shutdown_signal();
        let run_runtime = handle.clone();
        let run = handle
            .try_spawn(async move { listener.run(&run_runtime).await })
            .expect("spawn listener");

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let mut tls = http1_connector
            .connect("localhost", tcp)
            .await
            .expect("TLS with http/1.1");
        let response = http1_get(&mut tls, "/tls-one").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            response.ends_with("Http11 /tls-one peer=true"),
            "{response}"
        );

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let tls = http2_connector
            .connect("localhost", tcp)
            .await
            .expect("TLS with h2");
        assert_eq!(tls.alpn_protocol(), Some(b"h2".as_slice()));
        let response = Http2Client::new()
            .get(format!("https://localhost:{}/tls-two", addr.port()))
            .send_on(&cx, tls)
            .await
            .expect("HTTP/2 over TLS");
        assert_eq!(response.status, 200);
        assert_eq!(response.text().expect("UTF-8"), "Http2 /tls-two peer=true");

        assert!(shutdown.begin_drain(Duration::from_secs(5)));
        let _ = run.await.expect("auto listener run");
    }));
}
