//! gRPC and a REST Router on one port: `Server::registered_unary_handler`
//! routed by `is_grpc_request` next to `Router::into_http_handler`, served by
//! `HttpAutoListener`. A real gRPC `Channel`, an HTTP/1.1 client and an
//! HTTP/2 client all reach their side of the same listener.

use asupersync::bytes::Bytes;
use asupersync::cx::Cx;
use asupersync::grpc::{
    Channel, GrpcClient, Metadata, MethodDescriptor, NamedService, Request, Response, Server,
    ServiceDescriptor, ServiceHandler, ServiceHandlerFuture, is_grpc_request,
};
use asupersync::http::h1::listener::Http1ListenerConfig;
use asupersync::http::h1::server::{HostPolicy, Http1Config};
use asupersync::http::h1::types::Request as HttpRequest;
use asupersync::http::h2::client::Http2Client;
use asupersync::http::{HttpAutoListener, HttpAutoListenerConfig};
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpStream;
use asupersync::runtime::RuntimeBuilder;
use asupersync::web::handler::FnHandler;
use asupersync::web::router::{Router, get};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Calls that reached `Echo::call_unary` with the payload `h1`, which only
/// the HTTP/1.1 test sends.
static H1_PAYLOAD_CALLS: AtomicUsize = AtomicUsize::new(0);

struct Echo;

impl NamedService for Echo {
    const NAME: &'static str = "test.Echo";
}

impl ServiceHandler for Echo {
    fn descriptor(&self) -> &ServiceDescriptor {
        static METHODS: &[MethodDescriptor] =
            &[MethodDescriptor::unary("Unary", "/test.Echo/Unary")];
        static DESCRIPTOR: ServiceDescriptor = ServiceDescriptor::new("Echo", "test", METHODS);
        &DESCRIPTOR
    }

    fn method_names(&self) -> Vec<&str> {
        vec!["Unary"]
    }

    fn call_unary<'a>(
        &'a self,
        _cx: &'a Cx,
        _path: &'a str,
        request: Request<Bytes>,
        _trailing_metadata: Metadata,
    ) -> ServiceHandlerFuture<'a> {
        if request.get_ref().as_ref() == b"h1" {
            H1_PAYLOAD_CALLS.fetch_add(1, Ordering::SeqCst);
        }
        Box::pin(async move {
            let mut reply = b"grpc:".to_vec();
            reply.extend_from_slice(request.get_ref());
            Ok(Response::new(Bytes::from(reply)))
        })
    }
}

fn status() -> &'static str {
    "rest:ok"
}

#[test]
fn grpc_and_rest_share_one_port() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();
    runtime.block_on(handle.clone().spawn(async move {
        let cx = Cx::current().expect("runtime Cx");
        let server = Arc::new(Server::builder().add_service(Echo).build());
        let localhost = HostPolicy::allow_list(vec!["localhost".to_owned()]);
        let grpc = server.registered_unary_handler().expect("gRPC handler");
        let rest = Router::new()
            .route("/status", get(FnHandler::new(status)))
            .into_http_handler();
        let app = move |request: HttpRequest| {
            if is_grpc_request(&request) {
                grpc(request)
            } else {
                rest(request)
            }
        };
        let config = HttpAutoListenerConfig::default()
            .http1(
                Http1ListenerConfig::default()
                    .http_config(Http1Config {
                        allowed_hosts: localhost.clone(),
                        ..Http1Config::default()
                    })
                    .drain_timeout(Duration::from_secs(5)),
            )
            .http2(
                server
                    .http2_listener_config(localhost)
                    .drain_timeout(Duration::from_secs(5)),
            );
        let listener = HttpAutoListener::bind("127.0.0.1:0", app, config)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let shutdown = listener.shutdown_signal();
        let run_runtime = handle.clone();
        let run = handle
            .try_spawn(async move { listener.run(&run_runtime).await })
            .expect("spawn listener");

        // gRPC over HTTP/2 with prior knowledge.
        let channel = Channel::builder(format!("http://localhost:{}", addr.port()))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(10))
            .connect()
            .await
            .expect("channel");
        let response = GrpcClient::new(channel)
            .unary::<Bytes, Bytes>("/test.Echo/Unary", Request::new(Bytes::from_static(b"hi")))
            .await
            .expect("gRPC call");
        assert_eq!(response.get_ref().as_ref(), b"grpc:hi");

        // REST over HTTP/1.1 and over HTTP/2 on the same port.
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        AsyncWriteExt::write_all(
            &mut stream,
            b"GET /status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("write");
        let mut response = Vec::new();
        AsyncReadExt::read_to_end(&mut stream, &mut response)
            .await
            .expect("read");
        let response = String::from_utf8(response).expect("UTF-8");
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("rest:ok"), "{response}");

        let stream = TcpStream::connect(addr).await.expect("connect");
        let response = Http2Client::new()
            .get(format!("http://localhost:{}/status", addr.port()))
            .send_on(&cx, stream)
            .await
            .expect("HTTP/2 REST request");
        assert_eq!(
            (response.status, response.text().expect("UTF-8")),
            (200, "rest:ok")
        );

        assert!(shutdown.begin_drain(Duration::from_secs(5)));
        let _ = run.await.expect("listener run");
    }));
}

/// Sends `request` over a new HTTP/1.1 connection and returns everything the
/// server answers before it closes.
async fn http1_exchange(addr: std::net::SocketAddr, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    AsyncWriteExt::write_all(&mut stream, request)
        .await
        .expect("write");
    let mut response = Vec::new();
    AsyncReadExt::read_to_end(&mut stream, &mut response)
        .await
        .expect("read");
    String::from_utf8_lossy(&response).into_owned()
}

/// An HTTP/1.1 request with a gRPC content type never runs the RPC. gRPC
/// sends its status in trailers, which HTTP/1.x cannot carry, so the call used
/// to run, commit its effects, and then lose its response when the connection
/// dropped; a client retry ran it again (br-asupersync-313vbb).
/// `is_grpc_request` sends such a request to the REST side, and the gRPC
/// handler itself answers 505 before decoding anything.
#[test]
fn an_http1_request_with_a_grpc_content_type_never_runs_the_rpc() {
    const GRPC_OVER_HTTP1: &[u8] = b"POST /test.Echo/Unary HTTP/1.1\r\nHost: localhost\r\n\
        Content-Type: application/grpc\r\nContent-Length: 7\r\nConnection: close\r\n\r\n\
        \x00\x00\x00\x00\x02h1";
    const DIRECT: &[u8] = b"POST /test.Echo/Unary HTTP/1.1\r\nHost: localhost\r\n\
        Content-Type: application/grpc\r\nX-Route: grpc\r\nContent-Length: 7\r\n\
        Connection: close\r\n\r\n\x00\x00\x00\x00\x02h1";
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();
    runtime.block_on(handle.clone().spawn(async move {
        let server = Arc::new(Server::builder().add_service(Echo).build());
        let localhost = HostPolicy::allow_list(vec!["localhost".to_owned()]);
        let grpc = server.registered_unary_handler().expect("gRPC handler");
        let rest = Router::new()
            .route("/status", get(FnHandler::new(status)))
            .into_http_handler();
        // The documented composition, plus a route that hands a request to
        // the gRPC handler without asking `is_grpc_request`.
        let app = move |request: HttpRequest| {
            let direct = request
                .headers
                .iter()
                .any(|(name, value)| name.eq_ignore_ascii_case("x-route") && value == "grpc");
            if direct || is_grpc_request(&request) {
                grpc(request)
            } else {
                rest(request)
            }
        };
        let config = HttpAutoListenerConfig::default()
            .http1(
                Http1ListenerConfig::default()
                    .http_config(Http1Config {
                        allowed_hosts: localhost.clone(),
                        ..Http1Config::default()
                    })
                    .drain_timeout(Duration::from_secs(5)),
            )
            .http2(
                server
                    .http2_listener_config(localhost)
                    .drain_timeout(Duration::from_secs(5)),
            );
        let listener = HttpAutoListener::bind("127.0.0.1:0", app, config)
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let shutdown = listener.shutdown_signal();
        let run_runtime = handle.clone();
        let run = handle
            .try_spawn(async move { listener.run(&run_runtime).await })
            .expect("spawn listener");

        let calls_before = H1_PAYLOAD_CALLS.load(Ordering::SeqCst);
        let routed = http1_exchange(addr, GRPC_OVER_HTTP1).await;
        eprintln!("HTTP/1.1 gRPC through is_grpc_request: {routed:?}");
        assert!(
            routed.starts_with("HTTP/1.1 404"),
            "is_grpc_request sends it to REST, which has no such route: {routed:?}"
        );
        let direct = http1_exchange(addr, DIRECT).await;
        eprintln!("HTTP/1.1 gRPC handed to the gRPC handler: {direct:?}");
        assert!(
            direct.starts_with("HTTP/1.1 505"),
            "the gRPC handler refuses HTTP/1.1 with a status line: {direct:?}"
        );
        assert_eq!(
            H1_PAYLOAD_CALLS.load(Ordering::SeqCst),
            calls_before,
            "neither request reached the service"
        );

        assert!(shutdown.begin_drain(Duration::from_secs(5)));
        let _ = run.await.expect("listener run");
    }));
}
