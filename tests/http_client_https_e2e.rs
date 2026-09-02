//! E2E: can the shipped HTTP client fetch over HTTPS end to end?
//!
//! Every test here binds a REAL TLS HTTP/1.1 listener on `127.0.0.1:0`
//! (`Http1Listener::run_tls`, the same server path `tests/e2e_web.rs`
//! exercises) using the self-signed `tests/fixtures/tls/server.crt`
//! (CN=localhost, SAN `DNS:localhost, IP:127.0.0.1`), then drives a client
//! against it over a real loopback socket. Nothing is mocked.
//!
//! # Scope / no-claim line
//!
//! Loopback HTTPS with a **local root only**. This file makes NO claim about
//! WebPKI/native roots, HTTP/2 (ALPN is pinned to `http/1.1`), proxies or
//! CONNECT tunnels, or pooled-connection reuse across TLS sessions.
//!
//! # History
//!
//! When this file was first written (2026-09-01) the public pooled client
//! (`asupersync::http::Client` == `http::h1::HttpClient`, including
//! `Client::default_for_runtime`) exposed **no way to install a root
//! certificate**: `HttpClient::tls_connect_stream` built a fresh
//! `TlsConnectorBuilder::new()` per connection and only ever added roots from
//! the `tls-native-roots` / `tls-webpki-roots` cargo features, so with plain
//! `--features tls` every `https://` request failed closed before a
//! ClientHello ("no root certificates configured"), and a private CA could
//! never be trusted even with a roots feature on. The fix added
//! `HttpClientBuilder::add_root_certificate` / `HttpClientConfig::tls_root_certificates`,
//! consumed by `tls_connect_stream`. The default (no installed root, plain
//! `tls`) still fails closed; that behaviour is pinned below as the negative.
//!
//! Two positive proofs remain: the pooled `HttpClient` with the local root
//! installed (the highest-level public entry), and the lowest public layer
//! that admits a root (`TlsConnectorBuilder::add_root_certificate` +
//! `TlsConnector::connect("localhost", tcp)` feeding the single-request
//! `http::h1::Http1Client::request`).
//!
//! Requires `--features tls,test-internals` (`Cx::for_testing`).
#![cfg(feature = "tls")]

mod common;

use asupersync::Cx;
use asupersync::http::Client;
use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig};
use asupersync::http::h1::server::{HostPolicy, Http1Config};
use asupersync::http::h1::types::Request as H1Request;
use asupersync::http::h1::{ClientError, Http1Client, HttpClient};
use asupersync::net::TcpStream;
use asupersync::runtime::RuntimeBuilder;
use asupersync::tls::{
    Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsConnector,
    TlsConnectorBuilder, TlsError,
};
use asupersync::web::handler::FnHandler;
use asupersync::web::router::{Router, get};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Self-signed leaf for `localhost` / `127.0.0.1` (shared with `tests/e2e_web.rs`).
const SERVER_CERT_PEM: &[u8] = include_bytes!("fixtures/tls/server.crt");
const SERVER_KEY_PEM: &[u8] = include_bytes!("fixtures/tls/server.key");
/// A self-signed CA that never issued the listener's certificate
/// (`CN=Asupersync A5 Constrained Root`, valid 2026-07-27..2036-07-27).
const UNRELATED_ROOT_PEM: &[u8] = include_bytes!("fixtures/x509_adversarial/ca.crt");

const PATH: &str = "/secure/https-e2e";
const BODY: &str = "https-e2e-body-7f3a9c";

fn server_root() -> Certificate {
    Certificate::from_pem(SERVER_CERT_PEM)
        .expect("parse listener certificate")
        .into_iter()
        .next()
        .expect("listener fixture contains a certificate")
}

fn unrelated_root() -> Certificate {
    Certificate::from_pem(UNRELATED_ROOT_PEM)
        .expect("parse unrelated CA certificate")
        .into_iter()
        .next()
        .expect("unrelated CA fixture contains a certificate")
}

fn server_acceptor() -> TlsAcceptor {
    let chain = CertificateChain::from_pem(SERVER_CERT_PEM).expect("parse listener chain");
    let key = PrivateKey::from_pem(SERVER_KEY_PEM).expect("parse listener key");
    TlsAcceptorBuilder::new(chain, key)
        .alpn_protocols(vec![b"http/1.1".to_vec()])
        .build()
        .expect("build listener acceptor")
}

/// Client-side connector trusting exactly one root, ALPN pinned to HTTP/1.1.
fn connector_trusting(root: &Certificate) -> TlsConnector {
    TlsConnectorBuilder::new()
        .add_root_certificate(root)
        .alpn_protocols_required(vec![b"http/1.1".to_vec()])
        .build()
        .expect("build connector with one root")
}

/// Bind a live TLS HTTP/1.1 listener on loopback serving `GET PATH -> 200 BODY`,
/// run `test` against it, then drain the listener and verify it stopped.
///
/// `handler_calls` counts how many requests actually reached the route handler,
/// which is the "no body was served" witness for the negative tests.
fn run_with_https_listener<F, Fut>(test: F)
where
    F: FnOnce(SocketAddr, Arc<AtomicUsize>) -> Fut,
    Fut: Future<Output = ()>,
{
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let calls_for_route = Arc::clone(&handler_calls);
        let router = Router::new().route(
            PATH,
            get(FnHandler::new(move || {
                calls_for_route.fetch_add(1, Ordering::AcqRel);
                BODY
            })),
        );
        let listener = Http1Listener::bind_upgradeable_with_config(
            "127.0.0.1:0",
            router.into_http1_handler(),
            Http1ListenerConfig::default()
                .http_config(Http1Config {
                    allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
                    ..Http1Config::default()
                })
                .drain_timeout(Duration::from_millis(200))
                .hard_drain_timeout(Duration::from_secs(2)),
        )
        .await
        .expect("bind HTTPS/1.1 listener on 127.0.0.1:0");
        let addr = listener.local_addr().expect("HTTPS/1.1 listener address");
        let manager = listener.connection_manager().clone();
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run_tls(&handle, server_acceptor()).await })
            .expect("spawn HTTPS/1.1 listener");

        test(addr, Arc::clone(&handler_calls)).await;

        // Let the listener observe the client-side closes before draining.
        for _ in 0..400 {
            if manager.is_empty() {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert!(
            manager.begin_drain(Duration::from_millis(500)),
            "listener drain must start"
        );
        let stats = run_handle.await.expect("HTTPS/1.1 listener result");
        assert!(
            manager.is_empty(),
            "listener must end with no live connections: {stats:?}"
        );
    });
}

/// POSITIVE (AC1, lower-level entry): TLS connector with the listener's own
/// certificate as the sole root + the shipped `Http1Client` codec -> 200 + exact body.
#[test]
fn https_get_via_tls_connector_with_local_root_and_http1_client_returns_200_and_exact_body() {
    common::init_test_logging();
    run_with_https_listener(|addr, handler_calls| async move {
        let tcp = TcpStream::connect(addr)
            .await
            .expect("TCP connect to listener");
        let tls = connector_trusting(&server_root())
            .connect("localhost", tcp)
            .await
            .expect("TLS handshake with the local root must succeed");
        assert_eq!(tls.alpn_protocol(), Some(b"http/1.1".as_slice()));

        let request = H1Request::get(PATH)
            .header("Host", "localhost")
            .header("Connection", "close")
            .build();
        let response = Http1Client::request(tls, request)
            .await
            .expect("HTTP/1.1 exchange over the TLS session");

        assert_eq!(response.status, 200, "{response:?}");
        assert_eq!(
            response.body,
            BODY.as_bytes(),
            "body mismatch: {:?}",
            String::from_utf8_lossy(&response.body)
        );
        assert_eq!(handler_calls.load(Ordering::Acquire), 1);
    });
}

/// Expected failure text for the public pooled client, by feature set.
///
/// Plain `tls`: the per-connection connector has an empty root store and
/// `TlsConnectorBuilder::build` refuses it (exact message pinned).
/// With a roots feature on, the store holds public roots that never issued
/// the local self-signed cert, so the handshake fails with `UnknownIssuer`.
#[cfg(not(any(feature = "tls-native-roots", feature = "tls-webpki-roots")))]
fn assert_pooled_client_https_failure(err: &ClientError) {
    const EXPECTED: &str = "certificate error: no root certificates configured — server certificates cannot be verified";
    match err {
        ClientError::TlsError(msg) => assert_eq!(msg, EXPECTED, "verbatim message drift"),
        other => panic!("expected ClientError::TlsError, got {other:?}"),
    }
}

#[cfg(any(feature = "tls-native-roots", feature = "tls-webpki-roots"))]
fn assert_pooled_client_https_failure(err: &ClientError) {
    match err {
        ClientError::TlsError(msg) => assert!(
            msg.contains("UnknownIssuer"),
            "expected an unknown-issuer verification failure, got {msg:?}"
        ),
        other => panic!("expected ClientError::TlsError, got {other:?}"),
    }
}

/// POSITIVE (AC1 through the highest-level public entry): the pooled client
/// with the listener's certificate installed as a root completes
/// `GET https://localhost:<port>/...` with 200 and the exact body, and a second
/// request on the same client succeeds too (pool reuse is not asserted, only
/// that the configured client keeps working).
#[test]
fn http_client_https_get_with_installed_root_returns_200_and_exact_body() {
    common::init_test_logging();
    run_with_https_listener(|addr, handler_calls| async move {
        let cx = Cx::for_testing();
        let url = format!("https://localhost:{}{PATH}", addr.port());

        let client = HttpClient::builder()
            .add_root_certificate(server_root())
            .build();
        let response = client
            .get(url.as_str())
            .send(&cx)
            .await
            .expect("HTTPS GET through the pooled client with the local root installed");
        assert_eq!(response.status, 200, "{response:?}");
        assert_eq!(
            response.body,
            BODY.as_bytes(),
            "body mismatch: {:?}",
            String::from_utf8_lossy(&response.body)
        );
        assert_eq!(handler_calls.load(Ordering::Acquire), 1);

        let response = client
            .get(url.as_str())
            .send(&cx)
            .await
            .expect("second HTTPS GET on the same configured client");
        assert_eq!(response.status, 200, "{response:?}");
        assert_eq!(response.body, BODY.as_bytes());
        assert_eq!(handler_calls.load(Ordering::Acquire), 2);
        drop(client);
    });
}

/// NEGATIVE (planted): with no root installed, the pooled client, whether the
/// capability-gated runtime default or an explicitly constructed
/// `HttpClient::new()`, fails closed before sending HTTP and the route handler
/// never runs.
#[test]
fn http_client_https_get_without_installed_root_fails_closed() {
    common::init_test_logging();
    run_with_https_listener(|addr, handler_calls| async move {
        let cx = Cx::for_testing();
        let url = format!("https://localhost:{}{PATH}", addr.port());

        // Highest-level entry: the capability-gated runtime default client.
        let client: Client = Client::default_for_runtime(&cx);
        let err = client
            .get(url.as_str())
            .send(&cx)
            .await
            .expect_err("a client with no installed root cannot trust the local listener");
        assert_pooled_client_https_failure(&err);

        // An explicitly constructed client without roots behaves the same.
        let err = HttpClient::new()
            .get(url.as_str())
            .send(&cx)
            .await
            .expect_err("HttpClient::new() has no roots installed either");
        assert_pooled_client_https_failure(&err);

        assert_eq!(
            handler_calls.load(Ordering::Acquire),
            0,
            "no request may reach the handler: the client must fail before sending HTTP"
        );
    });
}

/// NEGATIVE (AC2a): the listener's certificate is trusted, but the client asks
/// for a different server name -> hostname verification fails closed, no body.
#[test]
fn tls_connector_with_local_root_but_wrong_server_name_fails_closed() {
    common::init_test_logging();
    run_with_https_listener(|addr, handler_calls| async move {
        let tcp = TcpStream::connect(addr)
            .await
            .expect("TCP connect to listener");
        let err = connector_trusting(&server_root())
            .connect("not-the-listener.invalid", tcp)
            .await
            .expect_err("certificate for localhost must not verify for another name");
        match &err {
            // rustls renders this as `invalid peer certificate: certificate not
            // valid for name "not-the-listener.invalid"; certificate is only
            // valid for DnsName("localhost") or IpAddress(127.0.0.1)` (older
            // releases used the bare `NotValidForName` token).
            TlsError::Handshake(msg) => assert!(
                msg.contains("invalid peer certificate")
                    && (msg.contains("not valid for name \"not-the-listener.invalid\"")
                        || msg.contains("NotValidForName")),
                "expected a name-mismatch verification failure, got {msg:?}"
            ),
            other => panic!("expected TlsError::Handshake, got {other:?}"),
        }
        assert_eq!(handler_calls.load(Ordering::Acquire), 0);
    });
}

/// NEGATIVE (AC2b): an empty root store is refused at build time; a store
/// holding only an unrelated CA fails the handshake -> no body either way.
#[test]
fn tls_connector_with_empty_or_unrelated_root_store_fails_closed() {
    common::init_test_logging();
    run_with_https_listener(|addr, handler_calls| async move {
        let err = TlsConnectorBuilder::new()
            .alpn_protocols_required(vec![b"http/1.1".to_vec()])
            .build()
            .expect_err("an empty root store must not build a connector");
        match &err {
            TlsError::Certificate(msg) => assert!(
                msg.contains("no root certificates configured"),
                "unexpected build refusal text: {msg:?}"
            ),
            other => panic!("expected TlsError::Certificate, got {other:?}"),
        }

        let tcp = TcpStream::connect(addr)
            .await
            .expect("TCP connect to listener");
        let err = connector_trusting(&unrelated_root())
            .connect("localhost", tcp)
            .await
            .expect_err("a root that never issued the listener cert must not verify it");
        match &err {
            TlsError::Handshake(msg) => assert!(
                msg.contains("UnknownIssuer"),
                "expected an unknown-issuer verification failure, got {msg:?}"
            ),
            other => panic!("expected TlsError::Handshake, got {other:?}"),
        }
        assert_eq!(handler_calls.load(Ordering::Acquire), 0);
    });
}
