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
use std::time::Duration;

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
