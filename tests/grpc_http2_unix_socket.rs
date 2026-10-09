//! HTTP/2 and gRPC servers on Unix-domain sockets: `Http2Listener::
//! from_unix_listener` and the registered gRPC lanes' `*_unix` binds, driven
//! by real clients connected through a `UnixStream` (the HTTP/2 client's
//! `send_on`, and the native gRPC streaming client, which takes any
//! transport).
#![cfg(unix)]

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder as _, Encoder as _};
use asupersync::cx::Cx;
use asupersync::grpc::codec::IdentityCodec;
use asupersync::grpc::native_stream::{NativeServerStream, NativeStreamConfig};
use asupersync::grpc::server::ServerStreamingConfig;
use asupersync::grpc::{
    GrpcCodec, GrpcMessage, Metadata, MethodDescriptor, NamedService, Request, Response, Server,
    ServiceDescriptor, ServiceHandler, ServiceHandlerFuture,
};
use asupersync::http::h1::server::HostPolicy;
use asupersync::http::h1::types::{Request as HttpRequest, Response as HttpResponse};
use asupersync::http::h2::client::Http2Client;
use asupersync::http::h2::listener::{Http2Listener, Http2ListenerConfig};
use asupersync::net::unix::{UnixListener, UnixStream};
use asupersync::runtime::RuntimeBuilder;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn socket_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("asup-h2-{name}-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

fn localhost() -> HostPolicy {
    HostPolicy::allow_list(vec!["localhost".to_owned()])
}

struct Echo {
    calls: Arc<AtomicUsize>,
}

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
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut reply = b"pong:".to_vec();
            reply.extend_from_slice(request.get_ref());
            Ok(Response::new(Bytes::from(reply)))
        })
    }
}

fn echo_server(calls: &Arc<AtomicUsize>) -> Arc<Server> {
    Arc::new(
        Server::builder()
            .add_service(Echo {
                calls: Arc::clone(calls),
            })
            .build(),
    )
}

fn grpc_frame(payload: &'static [u8]) -> Bytes {
    let mut framed = BytesMut::new();
    GrpcCodec::with_max_size(1024)
        .encode(GrpcMessage::new(Bytes::from_static(payload)), &mut framed)
        .expect("frame gRPC request");
    framed.freeze()
}

/// A unary gRPC call over `transport` with the HTTP/2 client; returns the
/// HTTP status, `grpc-status` and the decoded reply.
async fn grpc_unary_over(
    cx: &Cx,
    transport: UnixStream,
    payload: &'static [u8],
) -> (u16, String, Bytes) {
    let response = Http2Client::new()
        .post("http://localhost/test.Echo/Unary")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(grpc_frame(payload))
        .send_on(cx, transport)
        .await
        .expect("gRPC call over the Unix socket");
    let grpc_status = response
        .trailers
        .iter()
        .chain(&response.headers)
        .find(|header| header.name == "grpc-status")
        .map(|header| header.value.clone())
        .expect("grpc-status");
    let mut body = BytesMut::from(response.body.as_ref());
    let reply = GrpcCodec::with_max_size(1024)
        .decode(&mut body)
        .expect("decode reply")
        .map_or_else(Bytes::new, |message| message.data);
    (response.status, grpc_status, reply)
}

#[test]
fn http2_listener_serves_requests_on_a_unix_socket() {
    let path = socket_path("plain");
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();
    let client_path = path.clone();
    let server_path = path.clone();
    runtime.block_on(async move {
        let unix = UnixListener::bind(&server_path)
            .await
            .expect("bind Unix socket");
        let listener = Http2Listener::from_unix_listener(
            unix,
            |request: HttpRequest| async move {
                let body = format!("{} peer={:?}", request.uri, request.peer_addr).into_bytes();
                HttpResponse::new(200, "OK", body)
            },
            Http2ListenerConfig::default().host_policy(localhost()),
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

        let cx = Cx::current().expect("runtime Cx");
        for route in ["/first", "/second"] {
            let transport = UnixStream::connect(&client_path).await.expect("connect");
            let response = Http2Client::new()
                .get(format!("http://localhost{route}"))
                .send_on(&cx, transport)
                .await
                .expect("HTTP/2 request over the Unix socket");
            assert_eq!(response.status, 200);
            assert_eq!(
                response.text().expect("UTF-8"),
                format!("{route} peer=None")
            );
        }

        assert!(manager.begin_drain(Duration::from_secs(5)));
        let stats = run.await.expect("listener run");
        assert!(stats.drain_report.expect("drain report").reached_quiescence);
    });
    let _ = std::fs::remove_file(path);
}

#[test]
fn registered_grpc_unary_lane_serves_on_a_unix_socket() {
    let path = socket_path("grpc-unary");
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();
    let client_path = path.clone();
    let server_path = path.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = echo_server(&calls);
    runtime.block_on(async move {
        let unix = UnixListener::bind(&server_path)
            .await
            .expect("bind Unix socket");
        let listener = server
            .bind_registered_http2_unix(unix, localhost())
            .expect("bind registered gRPC lane");
        let manager = listener.connection_manager().clone();
        let run_runtime = handle.clone();
        let run = handle
            .clone()
            .try_spawn(async move { listener.run(&run_runtime).await })
            .expect("spawn listener");

        let cx = Cx::current().expect("runtime Cx");
        let transport = UnixStream::connect(&client_path).await.expect("connect");
        let (status, grpc_status, reply) = grpc_unary_over(&cx, transport, b"ping").await;
        assert_eq!((status, grpc_status.as_str()), (200, "0"));
        assert_eq!(reply.as_ref(), b"pong:ping");

        assert!(manager.begin_drain(Duration::from_secs(5)));
        let _ = run.await.expect("listener run");
    });
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let _ = std::fs::remove_file(path);
}

#[test]
fn registered_grpc_streaming_lane_serves_the_native_client_on_a_unix_socket() {
    let path = socket_path("grpc-streaming");
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();
    let client_path = path.clone();
    let server_path = path.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = echo_server(&calls);
    runtime.block_on(async move {
        let unix = UnixListener::bind(&server_path)
            .await
            .expect("bind Unix socket");
        let listener = server
            .bind_registered_streaming_http2_unix(
                unix,
                localhost(),
                ServerStreamingConfig {
                    frame_capacity: NonZeroUsize::new(4).unwrap(),
                    max_frame_bytes: NonZeroUsize::new(4096).unwrap(),
                    max_trailer_bytes: 1024,
                    terminal_timeout: Duration::from_secs(5),
                },
            )
            .expect("bind registered streaming lane");
        let manager = listener.connection_manager().clone();
        let run_runtime = handle.clone();
        let run = handle
            .clone()
            .try_spawn(async move { listener.run_produced(&run_runtime).await })
            .expect("spawn listener");

        let cx = Cx::current().expect("runtime Cx");
        let transport = UnixStream::connect(&client_path).await.expect("connect");
        let mut stream = NativeServerStream::new(
            &cx,
            transport,
            "localhost",
            "/test.Echo/Unary",
            Request::new(Bytes::from_static(b"stream")),
            IdentityCodec,
            NativeStreamConfig::default(),
        )
        .expect("start the native gRPC call");
        let first = stream.message().await.expect("reply");
        assert_eq!(first.as_deref(), Some(b"pong:stream".as_slice()));
        assert_eq!(stream.message().await.expect("end of stream"), None);
        assert!(stream.status().expect("final status").is_ok());

        assert!(manager.begin_drain(Duration::from_secs(5)));
        let _ = run.await.expect("listener run");
    });
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "http2-streaming")]
#[test]
fn registered_grpc_duplex_lane_serves_on_a_unix_socket() {
    use asupersync::grpc::ServerDuplexConfig;

    let path = socket_path("grpc-duplex");
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();
    let client_path = path.clone();
    let server_path = path.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = echo_server(&calls);
    runtime.block_on(async move {
        let unix = UnixListener::bind(&server_path)
            .await
            .expect("bind Unix socket");
        let listener = server
            .bind_registered_duplex_http2_unix(unix, localhost(), ServerDuplexConfig::default())
            .expect("bind registered duplex lane");
        let manager = listener.connection_manager().clone();
        let run_runtime = handle.clone();
        let run = handle
            .clone()
            .try_spawn(async move { listener.run_streaming_produced(&run_runtime).await })
            .expect("spawn listener");

        let cx = Cx::current().expect("runtime Cx");
        let transport = UnixStream::connect(&client_path).await.expect("connect");
        let (status, grpc_status, reply) = grpc_unary_over(&cx, transport, b"duplex").await;
        assert_eq!((status, grpc_status.as_str()), (200, "0"));
        assert_eq!(reply.as_ref(), b"pong:duplex");

        assert!(manager.begin_drain(Duration::from_secs(5)));
        let _ = run.await.expect("listener run");
    });
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let _ = std::fs::remove_file(path);
}

/// asupersync-x4kh5w finding 5: the duplex Unix bind accepted an input
/// configuration the TCP bind refuses, and the error came only from
/// `run_streaming_produced`, usually in a spawned task, whose listener drop
/// also unlinked the socket. A 4 KiB request-body queue clamps the stream
/// window below the 65,535 bytes live ingress needs; both binds now refuse it.
#[cfg(feature = "http2-streaming")]
#[test]
fn the_duplex_unix_bind_refuses_an_input_config_the_tcp_bind_refuses() {
    use asupersync::grpc::ServerDuplexConfig;

    let path = socket_path("grpc-duplex-config");
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build runtime");
    let calls = Arc::new(AtomicUsize::new(0));
    let server = echo_server(&calls);
    let mut config = ServerDuplexConfig::default();
    config.request_body_buffer_bytes = NonZeroUsize::new(4096).expect("non-zero");
    let bound_path = path.clone();
    runtime.block_on(async move {
        let tcp = server
            .bind_registered_duplex_http2("127.0.0.1:0", localhost(), config.clone())
            .await;
        let Err(tcp_refusal) = tcp else {
            panic!("the TCP bind accepted a 4 KiB request-body queue");
        };
        assert_eq!(tcp_refusal.kind(), std::io::ErrorKind::InvalidInput);

        let unix = UnixListener::bind(&bound_path)
            .await
            .expect("bind Unix socket");
        let Err(unix_refusal) = server.bind_registered_duplex_http2_unix(unix, localhost(), config)
        else {
            panic!("the Unix bind accepted a 4 KiB request-body queue");
        };
        assert_eq!(unix_refusal.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(unix_refusal.to_string(), tcp_refusal.to_string());
    });
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let _ = std::fs::remove_file(path);
}

#[test]
fn channel_unix_targets_reach_a_unix_socket_server() {
    use asupersync::grpc::{Channel, GrpcClient};

    let path = socket_path("grpc-channel");
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();
    let task_handle = handle.clone();
    let server_path = path.clone();
    let target = format!("unix://{}", path.display());
    let calls = Arc::new(AtomicUsize::new(0));
    let server = echo_server(&calls);
    runtime.block_on(handle.spawn(async move {
        let unix = UnixListener::bind(&server_path)
            .await
            .expect("bind Unix socket");
        // The mixed unary/server-streaming lane serves both client paths.
        let listener = server
            .bind_registered_streaming_http2_unix(
                unix,
                localhost(),
                ServerStreamingConfig {
                    frame_capacity: NonZeroUsize::new(4).unwrap(),
                    max_frame_bytes: NonZeroUsize::new(4096).unwrap(),
                    max_trailer_bytes: 1024,
                    terminal_timeout: Duration::from_secs(5),
                },
            )
            .expect("bind registered streaming lane");
        let manager = listener.connection_manager().clone();
        let run_runtime = task_handle.clone();
        let run = task_handle
            .try_spawn(async move { listener.run_produced(&run_runtime).await })
            .expect("spawn listener");

        let channel = Channel::builder(target.clone())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(10))
            .connect()
            .await
            .expect("unix: channel");
        let mut client = GrpcClient::new(channel.clone());
        for payload in [&b"one"[..], b"two"] {
            let response = client
                .unary::<Bytes, Bytes>(
                    "/test.Echo/Unary",
                    Request::new(Bytes::copy_from_slice(payload)),
                )
                .await
                .expect("unary call over the unix: channel");
            let mut expected = b"pong:".to_vec();
            expected.extend_from_slice(payload);
            assert_eq!(response.get_ref().as_ref(), expected.as_slice());
        }

        let cx = Cx::current().expect("runtime Cx");
        let mut stream = GrpcClient::new(channel)
            .into_native_server_streaming(
                &cx,
                "/test.Echo/Unary",
                Request::new(Bytes::from_static(b"three")),
            )
            .await
            .expect("native stream over the unix: channel");
        assert_eq!(
            stream.message().await.expect("reply").as_deref(),
            Some(b"pong:three".as_slice())
        );
        assert_eq!(stream.message().await.expect("end of stream"), None);

        assert!(manager.begin_drain(Duration::from_secs(5)));
        let _ = run.await.expect("listener run");
    }));
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let _ = std::fs::remove_file(path);
}

#[test]
fn unix_channel_targets_are_parsed_and_refuse_tls() {
    use asupersync::grpc::Channel;

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build runtime");
    runtime.block_on(async {
        for accepted in [
            "unix:///run/app.sock",
            "unix:relative.sock",
            "UNIX:/abs.sock",
        ] {
            Channel::connect(accepted)
                .await
                .unwrap_or_else(|error| panic!("{accepted}: {error}"));
        }
        for refused in ["unix://relative.sock", "unix:", "unix://"] {
            assert!(Channel::connect(refused).await.is_err(), "{refused}");
        }
        assert!(
            Channel::builder("unix:///run/app.sock")
                .tls()
                .connect()
                .await
                .is_err(),
            "TLS is refused on unix: targets"
        );
    });
}
