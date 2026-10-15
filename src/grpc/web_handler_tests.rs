use super::*;
use crate::bytes::Bytes;
use crate::cx::Cx;
use crate::grpc::service::{
    MethodDescriptor, NamedService, ServiceDescriptor, ServiceHandler, ServiceHandlerFuture,
};
use crate::grpc::streaming::{Request, Response};
use std::sync::atomic::{AtomicUsize, Ordering};

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
