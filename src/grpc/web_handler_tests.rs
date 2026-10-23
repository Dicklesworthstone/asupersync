use super::*;
use crate::bytes::Bytes;
use crate::cx::Cx;
use crate::grpc::service::{
    MethodDescriptor, NamedService, RegisteredServerStream, ServiceDescriptor, ServiceHandler,
    ServiceHandlerFuture, ServiceStreamingFuture,
};
use crate::grpc::streaming::{MetadataValue, Request, Response, Streaming};
use crate::http::h1::{
    BodyKind, Http1Config, Http1Listener, Http1ListenerConfig, IncomingRequestBody, RequestHead,
};
use crate::runtime::RuntimeBuilder;
use crate::server::shutdown::ShutdownSignal;
use crate::types::CancelKind;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, mpsc as sync_mpsc};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

struct Echo {
    calls: Arc<AtomicUsize>,
}

impl NamedService for Echo {
    const NAME: &'static str = "web.Echo";
}

impl ServiceHandler for Echo {
    fn descriptor(&self) -> &ServiceDescriptor {
        static METHODS: [MethodDescriptor; 2] = [
            MethodDescriptor::unary("Call", "/web.Echo/Call"),
            MethodDescriptor::server_streaming("Watch", "/web.Echo/Watch"),
        ];
        static DESCRIPTOR: ServiceDescriptor = ServiceDescriptor::new("Echo", "web", &METHODS);
        &DESCRIPTOR
    }

    fn method_names(&self) -> Vec<&str> {
        vec!["Call", "Watch"]
    }

    fn call_unary<'a>(
        &'a self,
        _cx: &'a Cx,
        path: &'a str,
        request: Request<Bytes>,
        _trailers: Metadata,
    ) -> ServiceHandlerFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            assert_eq!(path, "/web.Echo/Call");
            assert!(
                Cx::current().is_some(),
                "native dispatch retains its request context"
            );
            if request.metadata().get("authorization").is_none() {
                return Err(Status::unauthenticated("credentials required"));
            }
            Ok(Response::new(request.into_inner()))
        })
    }
}

fn server() -> (Arc<Server>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let server = Server::builder()
        .add_service(Echo {
            calls: Arc::clone(&calls),
        })
        .build();
    (Arc::new(server), calls)
}

fn request(mode: ContentType) -> HttpRequest {
    let frame = b"\x00\x00\x00\x00\x04ping";
    let body = if mode.is_text_mode() {
        STANDARD.encode(frame).into_bytes()
    } else {
        frame.to_vec()
    };
    HttpRequest::post("/web.Echo/Call")
        .content_type(mode.as_header_value())
        .header("authorization", "Bearer test-token")
        .body(body)
        .build()
}

fn run(server: &Arc<Server>, request: HttpRequest, config: GrpcWebConfig) -> HttpResponse {
    let handler = server
        .registered_grpc_web_unary_handler(config)
        .expect("valid configuration");
    let _guard = Cx::set_current(Some(Cx::for_testing()));
    futures_lite::future::block_on(handler(request))
}

fn binary_body(response: &HttpResponse) -> Vec<u8> {
    let content_type = response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.as_str());
    if content_type == Some("application/grpc-web-text+proto") {
        STANDARD
            .decode(&response.body)
            .expect("whole response has valid base64")
    } else {
        response.body.clone()
    }
}

fn status(response: &HttpResponse) -> String {
    assert_eq!(response.status, 200);
    assert!(
        response.trailers.is_empty(),
        "browser needs body trailers, not HTTP trailers"
    );
    let body = binary_body(response);
    let mut offset = 0;
    loop {
        assert!(offset + 5 <= body.len());
        let flag = body[offset];
        let length = usize::try_from(u32::from_be_bytes(
            body[offset + 1..offset + 5].try_into().unwrap(),
        ))
        .unwrap();
        offset += 5;
        assert!(offset + length <= body.len());
        if flag == 0x80 {
            assert_eq!(offset + length, body.len(), "trailers must be terminal");
            let block = std::str::from_utf8(&body[offset..]).unwrap();
            let statuses: Vec<_> = block
                .split("\r\n")
                .filter_map(|line| line.strip_prefix("grpc-status: "))
                .collect();
            assert_eq!(statuses.len(), 1, "exactly one terminal status");
            return statuses[0].to_owned();
        }
        assert!(flag <= 1, "only data frames precede trailers");
        offset += length;
    }
}

#[test]
fn registered_unary_round_trips_binary_and_text_over_http1_and_http2() {
    let (server, calls) = server();
    for mode in [ContentType::GrpcWeb, ContentType::GrpcWebText] {
        for version in [Version::Http10, Version::Http11, Version::Http2] {
            let mut request = request(mode);
            request.version = version;
            let response = run(&server, request, GrpcWebConfig::default());
            assert_eq!(response.version, version);
            assert_eq!(status(&response), "0");
            assert!(binary_body(&response).starts_with(b"\x00\x00\x00\x00\x04ping"));
            assert!(response.headers.iter().any(|(name, value)| {
                name == "content-length" && value == &response.body.len().to_string()
            }));
        }
    }
    assert_eq!(calls.load(Ordering::SeqCst), 6);
}

#[test]
fn independently_padded_text_chunks_may_split_the_frame_header_and_payload() {
    let (server, calls) = server();
    let frame = b"\x00\x00\x00\x00\x04ping";
    for chunk_size in 1..=frame.len() {
        let mut request = request(ContentType::GrpcWebText);
        request.body = frame
            .chunks(chunk_size)
            .map(|chunk| STANDARD.encode(chunk))
            .collect::<String>()
            .into_bytes();
        let response = run(&server, request, GrpcWebConfig::default());
        assert_eq!(status(&response), "0", "chunk size {chunk_size}");
        assert!(binary_body(&response).starts_with(frame));
    }
    assert_eq!(calls.load(Ordering::SeqCst), frame.len());
}

#[test]
fn accept_negotiates_independently_and_honors_quality_and_explicit_exclusion() {
    let cases = [
        (
            "application/grpc-web-text",
            Some(ContentType::GrpcWebText),
        ),
        (
            "application/grpc-web-text;q=0.5, application/grpc-web;q=0.8",
            Some(ContentType::GrpcWeb),
        ),
        (
            "*/*;q=1, application/grpc-web;q=0",
            Some(ContentType::GrpcWebText),
        ),
        (
            "application/grpc-web-text;q=0, application/grpc-web;q=0",
            None,
        ),
        ("application/json", None),
        ("application/grpc-web;q=NaN", None),
        ("application/grpc-web;q=1.001", None),
    ];
    for (accept, expected) in cases {
        let mut request = request(ContentType::GrpcWeb);
        request
            .headers
            .push(("accept".to_owned(), accept.to_owned()));
        assert_eq!(
            negotiate(&request, ContentType::GrpcWeb),
            expected,
            "{accept}"
        );
    }
    let (server, _) = server();
    let mut request = request(ContentType::GrpcWeb);
    request.headers.push((
        "accept".to_owned(),
        "application/grpc-web-text".to_owned(),
    ));
    let response = run(&server, request, GrpcWebConfig::default());
    assert_eq!(status(&response), "0");
    assert!(
        response
            .headers
            .iter()
            .any(|(_, value)| value == "application/grpc-web-text+proto")
    );
}

#[test]
fn malformed_or_oversized_requests_never_invoke_a_service() {
    let (server, calls) = server();
    for body in [
        b"".as_slice(),
        b"\x80\x00\x00\x00\x00",
        b"\x02\x00\x00\x00\x00",
        b"\x00\x00\x00\x00\x01",
        b"\x00\x00\x00\x00\x00extra",
    ] {
        let mut request = request(ContentType::GrpcWeb);
        request.body = body.to_vec();
        assert_eq!(
            status(&run(&server, request, GrpcWebConfig::default())),
            "3"
        );
    }
    for body in ["A", "AA=A", "====", "AA==!", "AA==\nAA=="] {
        let mut request = request(ContentType::GrpcWebText);
        request.body = body.as_bytes().to_vec();
        assert_eq!(
            status(&run(&server, request, GrpcWebConfig::default())),
            "3"
        );
    }
    for mode in [ContentType::GrpcWeb, ContentType::GrpcWebText] {
        let config = GrpcWebConfig {
            max_request_bytes: 8,
            ..GrpcWebConfig::default()
        };
        assert_eq!(status(&run(&server, request(mode), config)), "8");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn protocol_admission_does_not_relax_native_http2_policy() {
    let (server, calls) = server();
    let native = server.registered_unary_handler().unwrap();
    let response = futures_lite::future::block_on(native(request(ContentType::GrpcWeb)));
    assert_eq!(response.status, 505);
    let mut wrong_media = request(ContentType::GrpcWeb);
    wrong_media
        .headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case("content-type"));
    wrong_media
        .headers
        .push(("content-type".to_owned(), "application/grpc".to_owned()));
    assert_eq!(
        run(&server, wrong_media, GrpcWebConfig::default()).status,
        415
    );
    let mut duplicate = request(ContentType::GrpcWeb);
    duplicate.headers.push((
        "content-type".to_owned(),
        "application/grpc-web-text".to_owned(),
    ));
    assert_eq!(
        run(&server, duplicate, GrpcWebConfig::default()).status,
        400
    );
    let mut get = request(ContentType::GrpcWeb);
    get.method = Method::Get;
    assert_eq!(run(&server, get, GrpcWebConfig::default()).status, 405);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn native_authorization_errors_unknown_routes_and_streaming_routes_stay_errors() {
    let (server, _) = server();
    let mut unauthorized = request(ContentType::GrpcWebText);
    unauthorized
        .headers
        .retain(|(name, _)| name != "authorization");
    assert_eq!(
        status(&run(&server, unauthorized, GrpcWebConfig::default())),
        "16"
    );
    for path in ["/web.Echo/Missing", "/web.Missing/Call", "/web.Echo/Watch"] {
        let mut request = request(ContentType::GrpcWeb);
        request.uri = path.to_owned();
        assert_eq!(
            status(&run(&server, request, GrpcWebConfig::default())),
            "12"
        );
    }
}

#[test]
fn native_message_size_limits_still_apply_inside_the_web_wire_limit() {
    let calls = Arc::new(AtomicUsize::new(0));
    let server = Arc::new(
        Server::builder()
            .max_recv_message_size(3)
            .add_service(Echo {
                calls: Arc::clone(&calls),
            })
            .build(),
    );
    assert_eq!(
        status(&run(
            &server,
            request(ContentType::GrpcWeb),
            GrpcWebConfig::default(),
        )),
        "8"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn request_metadata_peer_and_compression_flag_survive_translation() {
    let mut request = request(ContentType::GrpcWeb);
    request.body[0] = 1;
    request.peer_addr = Some("127.0.0.1:1234".parse().unwrap());
    request
        .headers
        .push(("grpc-timeout".to_owned(), "100m".to_owned()));
    request
        .headers
        .push(("grpc-encoding".to_owned(), "gzip".to_owned()));
    request
        .headers
        .push(("connection".to_owned(), "x-hop".to_owned()));
    request
        .headers
        .push(("x-hop".to_owned(), "private".to_owned()));
    let (native, _) = prepare_request(request, &GrpcWebConfig::default()).unwrap();
    assert_eq!(native.version, Version::Http2);
    assert_eq!(native.body[0], 1);
    assert_eq!(native.peer_addr, Some("127.0.0.1:1234".parse().unwrap()));
    assert_eq!(native.header_value("grpc-timeout"), Some("100m"));
    assert_eq!(native.header_value("grpc-encoding"), Some("gzip"));
    assert_eq!(native.header_value("authorization"), Some("Bearer test-token"));
    assert!(native.header_value("connection").is_none());
    assert!(native.header_value("x-hop").is_none());
}

#[test]
fn status_message_and_binary_metadata_are_not_double_encoded() {
    let response = HttpResponse::new(200, "OK", Vec::new())
        .with_header("content-type", "application/grpc")
        .with_header("x-initial", "yes")
        .with_trailer("grpc-status", "7")
        .with_trailer("grpc-message", "denied%20%25%0Acaf%C3%A9")
        .with_trailer("grpc-status-details-bin", "AQI")
        .with_trailer("x-tail", "done");
    let response = encode_response(
        response,
        ContentType::GrpcWebText,
        Version::Http11,
        &GrpcWebConfig::default(),
    )
    .unwrap();
    assert_eq!(status(&response), "7");
    let body = binary_body(&response);
    let trailers = std::str::from_utf8(&body[5..]).unwrap();
    assert!(trailers.contains("grpc-message: denied%20%25%0Acaf%C3%A9\r\n"));
    assert!(trailers.contains("grpc-status-details-bin: AQI\r\n"));
    assert!(trailers.contains("x-tail: done\r\n"));
    assert!(
        response
            .headers
            .iter()
            .any(|(name, value)| name == "x-initial" && value == "yes")
    );
}

#[test]
fn malformed_response_status_and_trailer_injection_fail_closed() {
    for trailers in [
        vec![],
        vec![("grpc-status", "0"), ("grpc-status", "7")],
        vec![("grpc-status", "17")],
        vec![("grpc-status", "0"), ("x-tail", "safe\r\ngrpc-status: 0")],
        vec![("grpc-status", "0"), ("connection", "close")],
    ] {
        let mut response = HttpResponse::new(200, "OK", Vec::new());
        response.trailers = trailers
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect();
        assert!(
            encode_response(
                response,
                ContentType::GrpcWeb,
                Version::Http11,
                &GrpcWebConfig::default(),
            )
            .is_err()
        );
    }
}

#[test]
fn response_limits_produce_terminal_errors_instead_of_truncated_success() {
    let (server, _) = server();
    for config in [
        GrpcWebConfig {
            max_response_bytes: 8,
            ..GrpcWebConfig::default()
        },
        GrpcWebConfig {
            max_trailer_bytes: 1,
            ..GrpcWebConfig::default()
        },
    ] {
        let response = run(&server, request(ContentType::GrpcWebText), config);
        assert_eq!(status(&response), "8");
        assert_eq!(
            binary_body(&response)[0],
            0x80,
            "no partial success data escapes"
        );
    }
}

#[test]
fn empty_server_is_rejected_before_a_handler_can_be_installed() {
    let server = Arc::new(Server::builder().build());
    assert!(
        server
            .registered_grpc_web_unary_handler(GrpcWebConfig::default())
            .is_err()
    );
}

#[test]
fn zero_native_deadline_prevents_service_invocation() {
    let (server, calls) = server();
    let mut request = request(ContentType::GrpcWeb);
    request
        .headers
        .push(("grpc-timeout".to_owned(), "0n".to_owned()));
    let response = run(&server, request, GrpcWebConfig::default());
    assert_eq!(status(&response), "4");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}


// Real HTTP/1.1 producer tests use an independent wire decoder and explicit
// source readiness/drop witnesses (asupersync-server-stack-hardening-eeexl1.10).
#[derive(Clone, Copy)]
enum WebStreamMode {
    Values,
    Error,
    Never,
    Infinite,
}

#[derive(Default)]
struct WebStreamGate {
    released: bool,
    waker: Option<Waker>,
}

struct WebStreamProbe {
    calls: AtomicUsize,
    polls: AtomicUsize,
    drops: AtomicUsize,
    gate: Mutex<WebStreamGate>,
    parked: sync_mpsc::Sender<Cx>,
    retired: sync_mpsc::Sender<()>,
}

impl WebStreamProbe {
    fn release(&self) {
        let waker = {
            let mut gate = self.gate.lock().unwrap();
            gate.released = true;
            gate.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

struct WebWatch {
    mode: WebStreamMode,
    probe: Arc<WebStreamProbe>,
}

impl NamedService for WebWatch {
    const NAME: &'static str = "web.Watch";
}

impl ServiceHandler for WebWatch {
    fn descriptor(&self) -> &ServiceDescriptor {
        static METHODS: [MethodDescriptor; 1] = [
            MethodDescriptor::server_streaming("Values", "/web.Watch/Values"),
        ];
        static DESCRIPTOR: ServiceDescriptor = ServiceDescriptor::new("Watch", "web", &METHODS);
        &DESCRIPTOR
    }

    fn method_names(&self) -> Vec<&str> {
        vec!["Values"]
    }

    fn call_unary<'a>(
        &'a self,
        _cx: &'a Cx,
        _path: &'a str,
        _request: Request<Bytes>,
        _trailers: Metadata,
    ) -> ServiceHandlerFuture<'a> {
        Box::pin(async { Err(Status::unimplemented("streaming method")) })
    }

    fn call_server_streaming<'a>(
        &'a self,
        cx: &'a Cx,
        path: &'a str,
        request: Request<Bytes>,
        _trailers: Metadata,
    ) -> ServiceStreamingFuture<'a> {
        assert_eq!(path, "/web.Watch/Values");
        assert_eq!(request.get_ref().as_ref(), b"ping");
        assert!(matches!(
            request.metadata().get("authorization"),
            Some(MetadataValue::Ascii(value)) if value == "Bearer test-token"
        ));
        self.probe.calls.fetch_add(1, Ordering::SeqCst);
        let stream = WebWatchSource {
            mode: self.mode,
            probe: Arc::clone(&self.probe),
            cx: cx.clone(),
            index: 0,
            announced: false,
        };
        Box::pin(async move {
            let mut trailers = Metadata::new();
            assert!(trailers.insert("x-end", "done"));
            assert!(trailers.insert_bin("x-proof-bin", Bytes::from(vec![1, 2])));
            Ok(RegisteredServerStream::new(stream).with_trailers(trailers))
        })
    }
}

struct WebWatchSource {
    mode: WebStreamMode,
    probe: Arc<WebStreamProbe>,
    cx: Cx,
    index: usize,
    announced: bool,
}

impl Streaming for WebWatchSource {
    type Message = Bytes;

    fn poll_next(
        mut self: Pin<&mut Self>,
        task: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, Status>>> {
        self.probe.polls.fetch_add(1, Ordering::SeqCst);
        if matches!(self.mode, WebStreamMode::Never)
            || (self.index == 1 && !matches!(self.mode, WebStreamMode::Infinite))
        {
            let waiting = {
                let mut gate = self.probe.gate.lock().unwrap();
                if !gate.released || matches!(self.mode, WebStreamMode::Never) {
                    gate.waker = Some(task.waker().clone());
                    true
                } else {
                    false
                }
            };
            if waiting {
                if !self.announced {
                    self.announced = true;
                    let _ = self.probe.parked.send(self.cx.clone());
                }
                return Poll::Pending;
            }
        }
        let index = self.index;
        self.index += 1;
        match self.mode {
            WebStreamMode::Infinite => {
                Poll::Ready(Some(Ok(Bytes::from(vec![0x55; 4096]))))
            }
            WebStreamMode::Error if index == 1 => {
                Poll::Ready(Some(Err(Status::invalid_argument("bad %\n"))))
            }
            WebStreamMode::Error if index > 1 => panic!("polled after terminal error"),
            _ if index >= 2 => Poll::Ready(None),
            _ => Poll::Ready(Some(Ok(Bytes::from(if index == 0 {
                b"first".to_vec()
            } else {
                b"second".to_vec()
            })))),
        }
    }
}

impl Drop for WebWatchSource {
    fn drop(&mut self) {
        self.probe.drops.fetch_add(1, Ordering::SeqCst);
        let _ = self.probe.retired.send(());
    }
}

fn web_stream_fixture(
    mode: WebStreamMode,
) -> (
    Arc<Server>,
    Arc<WebStreamProbe>,
    sync_mpsc::Receiver<Cx>,
    sync_mpsc::Receiver<()>,
) {
    let (parked, parks) = sync_mpsc::channel();
    let (retired, retirements) = sync_mpsc::channel();
    let probe = Arc::new(WebStreamProbe {
        calls: AtomicUsize::new(0),
        polls: AtomicUsize::new(0),
        drops: AtomicUsize::new(0),
        gate: Mutex::new(WebStreamGate::default()),
        parked,
        retired,
    });
    let server = Arc::new(
        Server::builder()
            .add_service(WebWatch {
                mode,
                probe: Arc::clone(&probe),
            })
            .build(),
    );
    (server, probe, parks, retirements)
}

fn web_stream_config() -> ServerStreamingConfig {
    ServerStreamingConfig {
        frame_capacity: NonZeroUsize::new(2).unwrap(),
        // Force both gRPC headers and padded base64 quartets across HTTP chunks.
        max_frame_bytes: NonZeroUsize::new(7).unwrap(),
        max_trailer_bytes: 1024,
        terminal_timeout: Duration::from_secs(1),
    }
}

struct WebStopOnDrop(ShutdownSignal);

impl Drop for WebStopOnDrop {
    fn drop(&mut self) {
        self.0.trigger_immediate();
    }
}

/// This peer intentionally does not use the production gRPC-Web decoder.
struct WebStreamPeer {
    socket: Option<BufReader<TcpStream>>,
    mode: ContentType,
    binary: Vec<u8>,
    quartet: Vec<u8>,
    padded_quartets: usize,
    ended: bool,
}

impl WebStreamPeer {
    fn new(addr: SocketAddr, mode: ContentType, timeout: Option<&str>) -> Self {
        let mut socket = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
            .expect("connect real HTTP/1 listener");
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let request = request(mode);
        write!(
            socket,
            "POST /web.Watch/Values HTTP/1.1\r\nHost: localhost\r\n\
             Content-Type: {}\r\nAccept: {}\r\nContent-Length: {}\r\n\
             Authorization: Bearer test-token\r\nConnection: close\r\n",
            mode.as_header_value(),
            mode.as_header_value(),
            request.body.len(),
        )
        .unwrap();
        if let Some(timeout) = timeout {
            write!(socket, "grpc-timeout: {timeout}\r\n").unwrap();
        }
        socket.write_all(b"\r\n").unwrap();
        socket.write_all(&request.body).unwrap();
        let mut peer = Self {
            socket: Some(BufReader::new(socket)),
            mode,
            binary: Vec::new(),
            quartet: Vec::new(),
            padded_quartets: 0,
            ended: false,
        };
        assert_eq!(peer.line(), "HTTP/1.1 200 OK\r\n");
        let mut content_type = None;
        let mut chunked = false;
        loop {
            let line = peer.line();
            if line == "\r\n" {
                break;
            }
            let (key, value) = line.trim_end_matches("\r\n").split_once(':').unwrap();
            if key.eq_ignore_ascii_case("content-type") {
                content_type = Some(value.trim().to_owned());
            }
            if key.eq_ignore_ascii_case("transfer-encoding") {
                assert_eq!(value.trim(), "chunked");
                chunked = true;
            }
            assert!(!key.eq_ignore_ascii_case("grpc-status"), "status belongs in body");
            assert!(!key.eq_ignore_ascii_case("content-length"));
        }
        assert_eq!(content_type.as_deref(), Some(mode.as_header_value()));
        assert!(chunked);
        peer
    }

    fn line(&mut self) -> String {
        let mut line = String::new();
        assert!(
            self.socket
                .as_mut()
                .expect("live peer socket")
                .read_line(&mut line)
                .expect("bounded wire read") > 0
        );
        assert!(line.ends_with("\r\n"));
        assert!(line.len() <= 8192, "test peer header bound");
        line
    }

    fn chunk(&mut self) -> bool {
        assert!(!self.ended);
        let line = self.line();
        let length = usize::from_str_radix(line.trim_end_matches("\r\n"), 16)
            .expect("HTTP chunk size");
        if length == 0 {
            assert_eq!(self.line(), "\r\n", "no HTTP trailers are needed");
            assert!(self.quartet.is_empty(), "complete final base64 quartet");
            self.ended = true;
            return false;
        }
        assert!(length <= 7, "text expansion must respect the HTTP DATA bound");
        let mut data = vec![0; length];
        self.socket
            .as_mut()
            .expect("live peer socket")
            .read_exact(&mut data)
            .expect("complete HTTP chunk");
        let mut crlf = [0; 2];
        self.socket
            .as_mut()
            .expect("live peer socket")
            .read_exact(&mut crlf)
            .unwrap();
        assert_eq!(crlf, *b"\r\n");
        if self.mode.is_text_mode() {
            for byte in data {
                self.quartet.push(byte);
                if self.quartet.len() == 4 {
                    if self.quartet.contains(&b'=') {
                        self.padded_quartets += 1;
                    }
                    self.binary.extend(
                        STANDARD.decode(&self.quartet).expect("independent base64 quartet"),
                    );
                    self.quartet.clear();
                }
            }
        } else {
            self.binary.extend(data);
        }
        true
    }

    fn frame(&mut self) -> (u8, Vec<u8>) {
        loop {
            if self.binary.len() >= 5 {
                let length = u32::from_be_bytes(self.binary[1..5].try_into().unwrap()) as usize;
                assert!(length <= 16384, "test peer message bound");
                if self.binary.len() >= length + 5 {
                    let flag = self.binary[0];
                    assert!(matches!(flag, 0 | 0x80));
                    let payload = self.binary[5..5 + length].to_vec();
                    self.binary.drain(..5 + length);
                    return (flag, payload);
                }
            }
            assert!(self.chunk(), "HTTP body ended before a complete gRPC frame");
        }
    }

    fn disconnect(&mut self) {
        // Close the last descriptor before awaiting retirement. A TCP
        // half-close while retaining the reader would still permit responses.
        drop(self.socket.take().expect("live peer socket"));
    }

    fn terminal(&mut self, code: &str) -> String {
        let (flag, payload) = self.frame();
        assert_eq!(flag, 0x80, "terminal status is a gRPC-Web trailer body frame");
        let block = String::from_utf8(payload).unwrap();
        let codes: Vec<_> = block
            .split("\r\n")
            .filter_map(|line| line.strip_prefix("grpc-status: "))
            .collect();
        assert_eq!(codes, vec![code]);
        assert!(block.ends_with("\r\n"));
        assert!(!block.ends_with("\r\n\r\n"), "no HTTP header-block terminator");
        assert!(self.binary.is_empty(), "no data follows terminal trailers");
        assert!(!self.chunk(), "terminal trailer frame must be last");
        block
    }
}

fn web_native_case<F>(
    mode: WebStreamMode,
    content_type: ContentType,
    wire: GrpcWebConfig,
    timeout: Option<&'static str>,
    client: F,
) -> Arc<WebStreamProbe>
where
    F: FnOnce(
            &mut WebStreamPeer,
            sync_mpsc::Receiver<Cx>,
            sync_mpsc::Receiver<()>,
            &Arc<WebStreamProbe>,
        ) + Send
        + 'static,
{
    let (server, probe, parks, retirements) = web_stream_fixture(mode);
    let handler = server
        .registered_grpc_web_streaming_handler(wire, web_stream_config())
        .expect("valid gRPC-Web streaming handler");
    let runtime = RuntimeBuilder::current_thread().build().expect("native runtime");
    let handle = runtime.handle().clone();
    let peer_probe = Arc::clone(&probe);
    runtime.block_on(runtime.handle().spawn(async move {
        let config = Http1ListenerConfig::default().http_config(
            Http1Config::default()
                .allowed_hosts(Some(vec!["localhost".to_owned()]))
                .idle_timeout(Some(Duration::from_secs(5))),
        );
        let listener = Http1Listener::bind_produced_with_config("127.0.0.1:0", handler, config)
            .await
            .expect("bind native HTTP/1 produced listener");
        let addr = listener.local_addr().unwrap();
        let shutdown = listener.shutdown_signal();
        let peer = std::thread::spawn(move || {
            let _stop = WebStopOnDrop(shutdown);
            let mut peer = WebStreamPeer::new(addr, content_type, timeout);
            client(&mut peer, parks, retirements, &peer_probe);
        });
        let served = listener.run_produced(&handle).await;
        peer.join().expect("independent native wire assertions");
        served.expect("native listener shutdown");
    }));
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1, "source retired once");
    probe
}

#[test]
fn native_web_stream_delivers_before_source_eof_in_binary_and_padded_text() {
    for content_type in [ContentType::GrpcWeb, ContentType::GrpcWebText] {
        web_native_case(
            WebStreamMode::Values,
            content_type,
            GrpcWebConfig::default(),
            None,
            |peer, parks, retirements, probe| {
                assert_eq!(peer.frame(), (0, b"first".to_vec()));
                parks.recv_timeout(Duration::from_secs(2)).expect("source parked after first");
                assert_eq!(probe.drops.load(Ordering::SeqCst), 0);
                probe.release();
                assert_eq!(peer.frame(), (0, b"second".to_vec()));
                let trailers = peer.terminal("0");
                assert!(trailers.contains("x-end: done\r\n"));
                assert!(trailers.contains("x-proof-bin: AQI\r\n"));
                retirements.recv_timeout(Duration::from_secs(2)).expect("source dropped");
                if peer.mode.is_text_mode() {
                    assert!(peer.padded_quartets >= 2, "padding before text-stream EOF");
                }
            },
        );
    }
}

#[test]
fn native_web_stream_error_preserves_complete_message_and_terminal_status() {
    for content_type in [ContentType::GrpcWeb, ContentType::GrpcWebText] {
        web_native_case(
            WebStreamMode::Error,
            content_type,
            GrpcWebConfig::default(),
            None,
            |peer, parks, retirements, probe| {
                assert_eq!(peer.frame(), (0, b"first".to_vec()));
                parks.recv_timeout(Duration::from_secs(2)).expect("source parked");
                probe.release();
                let trailers = peer.terminal("3");
                // grpc-message keeps an internal space literal, as the gRPC
                // grammar allows, and escapes `%` and the line feed.
                assert!(
                    trailers.contains("grpc-message: bad %25%0A\r\n"),
                    "{trailers:?}"
                );
                assert!(!trailers.contains("x-end:"));
                retirements.recv_timeout(Duration::from_secs(2)).expect("error source dropped");
            },
        );
    }
}

#[test]
fn native_web_stream_wire_limits_preserve_clean_terminal_framing() {
    web_native_case(
        WebStreamMode::Values,
        ContentType::GrpcWebText,
        GrpcWebConfig {
            max_response_bytes: 9, // "first" occupies ten bytes including its prefix.
            ..GrpcWebConfig::default()
        },
        None,
        |peer, _parks, retirements, _probe| {
            peer.terminal("8"); // No prefix or partial message was queued first.
            retirements.recv_timeout(Duration::from_secs(2)).expect("oversize source dropped");
        },
    );
    web_native_case(
        WebStreamMode::Values,
        ContentType::GrpcWebText,
        GrpcWebConfig {
            max_trailer_bytes: 17,
            ..GrpcWebConfig::default()
        },
        None,
        |peer, parks, retirements, probe| {
            assert_eq!(peer.frame(), (0, b"first".to_vec()));
            parks.recv_timeout(Duration::from_secs(2)).expect("source parked");
            probe.release();
            assert_eq!(peer.frame(), (0, b"second".to_vec()));
            assert_eq!(peer.terminal("8"), "grpc-status: 8\r\n");
            retirements.recv_timeout(Duration::from_secs(2)).expect("bounded trailer source dropped");
        },
    );
}

#[test]
fn native_web_stream_deadline_retires_a_parked_source_and_delivers_status() {
    web_native_case(
        WebStreamMode::Never,
        ContentType::GrpcWebText,
        GrpcWebConfig::default(),
        Some("1S"),
        |peer, parks, retirements, probe| {
            parks.recv_timeout(Duration::from_secs(2)).expect("pending source registered");
            assert_eq!(probe.drops.load(Ordering::SeqCst), 0);
            peer.terminal("4");
            retirements.recv_timeout(Duration::from_secs(2)).expect("deadline dropped source");
        },
    );
}

#[test]
fn native_web_stream_call_cancellation_retires_a_parked_source() {
    web_native_case(
        WebStreamMode::Never,
        ContentType::GrpcWeb,
        GrpcWebConfig::default(),
        None,
        |peer, parks, retirements, probe| {
            let cx = parks.recv_timeout(Duration::from_secs(2)).expect("pending source registered");
            assert_eq!(probe.drops.load(Ordering::SeqCst), 0);
            cx.cancel_with(CancelKind::User, Some("test cancels parked RPC"));
            peer.terminal("1");
            retirements.recv_timeout(Duration::from_secs(2)).expect("cancel dropped source");
        },
    );
}

#[test]
fn native_web_stream_disconnect_retires_active_source_before_listener_shutdown() {
    web_native_case(
        WebStreamMode::Infinite,
        ContentType::GrpcWeb,
        GrpcWebConfig::default(),
        None,
        |peer, _parks, retirements, probe| {
            assert_eq!(peer.frame(), (0, vec![0x55; 4096]));
            assert_eq!(probe.drops.load(Ordering::SeqCst), 0);
            peer.disconnect();
            retirements.recv_timeout(Duration::from_secs(3)).expect("disconnect dropped source");
            assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
        },
    );
}

fn produced_request(cx: &Cx, mut request: HttpRequest, path: &str) -> StreamingServerRequest {
    request.uri = path.to_owned();
    let (mut writer, body) =
        IncomingRequestBody::channel(cx, BodyKind::ContentLength(request.body.len() as u64));
    futures_lite::future::block_on(writer.push_bytes(cx, &request.body)).unwrap();
    writer.finish(cx).unwrap();
    StreamingServerRequest {
        head: RequestHead {
            method: request.method,
            uri: request.uri,
            version: Version::Http11,
            headers: request.headers,
        },
        peer_addr: None,
        body,
    }
}

#[test]
fn produced_web_stream_bounds_prefetch_when_consumer_stalls_and_drops_source_on_close() {
    for content_type in [ContentType::GrpcWeb, ContentType::GrpcWebText] {
        let (server, probe, _parks, retirements) = web_stream_fixture(WebStreamMode::Infinite);
        let cx = Cx::for_testing();
        let input = produced_request(&cx, request(content_type), "/web.Watch/Values");
        let handler = server
            .registered_grpc_web_streaming_handler(GrpcWebConfig::default(), web_stream_config())
            .unwrap();
        let produced = futures_lite::future::block_on(handler(cx.clone(), input));
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0, "admission precedes user code");
        assert_eq!(produced.max_retained_data_bytes(), 28); // (2 + 2) * 7.
        let (response, mut producer) = produced.into_parts(&cx);
        let mut task = Context::from_waker(Waker::noop());
        assert!(producer.as_mut().poll(&mut task).is_pending());
        assert_eq!(probe.polls.load(Ordering::SeqCst), 1);
        for _ in 0..4 {
            assert!(producer.as_mut().poll(&mut task).is_pending());
        }
        assert_eq!(probe.polls.load(Ordering::SeqCst), 1, "full queue stops source polling");
        assert_eq!(probe.drops.load(Ordering::SeqCst), 0);
        drop(response.body);
        assert!(matches!(producer.as_mut().poll(&mut task), Poll::Ready(Err(_))));
        retirements.recv_timeout(Duration::from_secs(1)).expect("closed channel drops source");
        assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn produced_web_streaming_handler_preserves_registered_unary_dispatch() {
    let (server, calls) = server();
    for content_type in [ContentType::GrpcWeb, ContentType::GrpcWebText] {
        let cx = Cx::for_testing();
        let input = produced_request(&cx, request(content_type), "/web.Echo/Call");
        let handler = server
            .registered_grpc_web_streaming_handler(GrpcWebConfig::default(), web_stream_config())
            .unwrap();
        let produced = futures_lite::future::block_on(handler(cx.clone(), input));
        let (mut response, producer) = produced.into_parts(&cx);
        let collect = async move {
            let mut bytes = Vec::new();
            while let Some(frame) = poll_fn(|task| Pin::new(&mut response.body).poll_frame(task)).await {
                match frame.expect("produced unary frame") {
                    Frame::Data(data) => bytes.extend_from_slice(data.chunk()),
                    Frame::Trailers(_) => panic!("gRPC-Web status belongs in the body"),
                }
            }
            let mut reply = HttpResponse::new(response.head.status, response.head.reason, bytes);
            reply.headers = response.head.headers;
            reply
        };
        let (completion, response) = futures_lite::future::block_on(
            futures_lite::future::zip(producer, collect),
        );
        assert!(completion.is_ok());
        assert_eq!(status(&response), "0");
        assert!(binary_body(&response).starts_with(b"\x00\x00\x00\x00\x04ping"));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn streaming_handler_requires_room_for_bare_terminal_status() {
    let (server, _) = server();
    assert!(
        server
            .registered_grpc_web_streaming_handler(
                GrpcWebConfig {
                    max_trailer_bytes: 16,
                    ..GrpcWebConfig::default()
                },
                web_stream_config(),
            )
            .is_err()
    );
}
