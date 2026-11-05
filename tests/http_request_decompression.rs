//! Bounded request content decoding through public middleware and real HTTP.
//! Governing gap: asupersync-server-stack-hardening-eeexl1 / MW-G1.

use asupersync::Cx;
use asupersync::web::extract::Request;
use asupersync::web::handler::Handler;
use asupersync::web::middleware::RequestDecompressionLayer;
#[cfg(not(target_arch = "wasm32"))]
use asupersync::web::middleware::RequestDecompressionMiddleware;
#[cfg(feature = "compression")]
use asupersync::web::RequestBodyPolicy;
use asupersync::web::{Response, Router, StatusCode, post};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

type Seen = Arc<Mutex<Vec<Request>>>;

struct Echo(Seen);

impl Handler for Echo {
    fn call(&self, _cx: &Cx, request: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let body = request.body.clone();
        self.0.lock().unwrap().push(request);
        Box::pin(async move { Response::new(StatusCode::OK, body) })
    }
}

fn app(encoded: usize, decoded: usize) -> (Router, Seen) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new().without_default_trace()
        .route("/upload", post(Echo(Arc::clone(&seen))))
        .layer(RequestDecompressionLayer::new(encoded, decoded));
    (app, seen)
}

fn request(coding: &str, body: Vec<u8>) -> Request {
    Request::new("POST", "/upload")
        .with_header("content-encoding", coding)
        .with_header("content-length", body.len().to_string())
        .with_body(body)
}

#[test]
fn identity_has_independent_encoded_decoded_limits_and_no_metadata_mutation() {
    for coding in [None, Some("identity"), Some(" , identity, , ")] {
        let mut request = Request::new("POST", "/upload").with_body("payload")
            .with_header("content-length", "7");
        if let Some(coding) = coding {
            request = request.with_header("content-encoding", coding);
        }
        let (router, seen) = app(7, 7);
        assert_eq!(router.handle(request.clone()).body.as_ref(), b"payload");
        assert_eq!(seen.lock().unwrap()[0].headers, request.headers);
        for (encoded, decoded) in [(6, 7), (7, 6)] {
            let (router, seen) = app(encoded, decoded);
            assert_eq!(router.handle(request.clone()).status, StatusCode::PAYLOAD_TOO_LARGE);
            assert!(seen.lock().unwrap().is_empty());
        }
    }
    let (router, seen) = app(0, 0);
    assert_eq!(router.handle(request("identity", Vec::new())).status, StatusCode::OK);
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[test]
fn invalid_coding_lists_unknown_codecs_and_conflicting_lengths_never_reach_handler() {
    for (coding, expected) in [
        ("", StatusCode::BAD_REQUEST),
        (", ,", StatusCode::BAD_REQUEST),
        ("gzip;q=1", StatusCode::BAD_REQUEST),
        ("gzip\r\n", StatusCode::BAD_REQUEST),
        ("identity,identity,identity,identity,identity,identity,identity,identity,identity", StatusCode::BAD_REQUEST),
        ("future-coding", StatusCode::UNSUPPORTED_MEDIA_TYPE),
    ] {
        let (router, seen) = app(1024, 1024);
        assert_eq!(router.handle(request(coding, b"wire".to_vec())).status, expected, "{coding:?}");
        assert!(seen.lock().unwrap().is_empty());
    }
    let (router, seen) = app(1024, 1024);
    let mut ambiguous = request("identity", b"wire".to_vec());
    ambiguous.headers.insert("Content-Encoding".to_owned(), "identity".to_owned());
    assert_eq!(router.handle(ambiguous).status, StatusCode::BAD_REQUEST);
    let invalid = request("identity", b"wire".to_vec()).with_header("content-length", "3, 4");
    assert_eq!(router.handle(invalid).status, StatusCode::BAD_REQUEST);
    assert!(seen.lock().unwrap().is_empty());
}

#[cfg(not(feature = "compression"))]
#[test]
fn unavailable_codecs_return_415_with_an_identity_offer() {
    for coding in ["gzip", "deflate", "br"] {
        let (router, seen) = app(1024, 1024);
        let response = router.handle(request(coding, b"wire".to_vec()));
        assert_eq!(response.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert!(response.header_value("accept-encoding").unwrap().contains("identity"));
        assert!(seen.lock().unwrap().is_empty());
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn cancellation_prevents_decoding_and_handler_invocation() {
    let runtime = asupersync::runtime::RuntimeBuilder::new().worker_threads(1).build().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let middleware = RequestDecompressionMiddleware::new(Echo(Arc::clone(&seen)), 1024, 1024);
    let cx = runtime.request_cx_with_budget(asupersync::types::Budget::INFINITE);
    cx.cancel_with(asupersync::types::CancelKind::User, Some("cancel before decoding"));
    let response = runtime.block_on(middleware.call(&cx, request("identity", b"wire".to_vec())));
    assert_eq!(response.status, StatusCode::CLIENT_CLOSED_REQUEST);
    assert!(seen.lock().unwrap().is_empty());
}

#[cfg(feature = "compression")]
fn encode(input: &[u8], coding: asupersync::http::compress::ContentEncoding) -> Vec<u8> {
    let mut compressor = asupersync::http::compress::make_compressor(coding).unwrap();
    let mut wire = Vec::new();
    compressor.compress(input, &mut wire).unwrap();
    compressor.finish(&mut wire).unwrap();
    wire
}

// Independently encoded gzip member for "hello" (CRC32 3610a686, ISIZE 5).
#[cfg(feature = "compression")]
const GZIP_HELLO: &[u8] = &[
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03,
    0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x86, 0xa6, 0x10,
    0x36, 0x05, 0x00, 0x00, 0x00,
];

#[cfg(feature = "compression")]
#[test]
fn codecs_decode_before_json_extraction_and_remove_encoded_payload_metadata() {
    use asupersync::http::compress::ContentEncoding;
    use asupersync::web::extract::Json;
    use asupersync::web::handler::FnHandler1;
    let plain = br#"{"answer":42}"#;
    for coding in [ContentEncoding::Gzip, ContentEncoding::Deflate, ContentEncoding::Brotli] {
        let wire = encode(plain, coding);
        let (router, seen) = app(1024, 1024);
        let response = router.handle(request(coding.as_token(), wire.clone())
            .with_header("content-type", "application/json")
            .with_header("content-md5", "encoded")
            .with_header("digest", "encoded")
            .with_header("content-digest", "encoded")
            .with_header("repr-digest", "encoded"));
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body.as_ref(), plain);
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0].header("content-length"), Some("13"));
        for header in ["content-encoding", "content-md5", "digest", "content-digest", "repr-digest"] {
            assert!(seen[0].header(header).is_none(), "{header}");
        }
        assert_eq!(seen[0].header("content-type"), Some("application/json"));

        let router = Router::new().without_default_trace()
            .route("/upload", post(FnHandler1::new(|Json(value): Json<serde_json::Value>| value["answer"].to_string())))
            .layer(RequestDecompressionLayer::new(1024, 1024));
        let response = router.handle(request(coding.as_token(), wire).with_header("content-type", "application/json"));
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body.as_ref(), b"42");
    }
}

#[cfg(feature = "compression")]
#[test]
fn corruption_and_every_expansion_boundary_are_rejected_before_handler() {
    use asupersync::http::compress::ContentEncoding;
    for coding in [ContentEncoding::Gzip, ContentEncoding::Deflate, ContentEncoding::Brotli] {
        let wire = encode(&vec![b'a'; 4096], coding);
        for (encoded, decoded) in [(wire.len() - 1, 8192), (wire.len(), 128)] {
            let (router, seen) = app(encoded, decoded);
            assert_eq!(router.handle(request(coding.as_token(), wire.clone())).status, StatusCode::PAYLOAD_TOO_LARGE);
            assert!(seen.lock().unwrap().is_empty());
        }
    }
    // The final body would fit, but its intermediate gzip representation does not.
    let wire = encode(&encode(b"a", ContentEncoding::Gzip), ContentEncoding::Deflate);
    let (router, seen) = app(1024, 1);
    assert_eq!(router.handle(request("gzip, deflate", wire)).status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(seen.lock().unwrap().is_empty());

    let mut corrupt = GZIP_HELLO.to_vec();
    corrupt[17] ^= 1;
    for wire in [Vec::new(), GZIP_HELLO[..10].to_vec(), GZIP_HELLO[..24].to_vec(), corrupt] {
        let (router, seen) = app(1024, 1024);
        assert_eq!(router.handle(request("gzip", wire)).status, StatusCode::BAD_REQUEST);
        assert!(seen.lock().unwrap().is_empty());
    }
    let (router, seen) = app(1024, 8192);
    let router = router.with_body_policy(RequestBodyPolicy::new().max_total_body_size(128));
    assert_eq!(router.handle(request("gzip", encode(&vec![b'a'; 4096], ContentEncoding::Gzip))).status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(seen.lock().unwrap().is_empty());

    let (router, seen) = app(1024, 0);
    assert_eq!(router.handle(request("gzip", encode(b"", ContentEncoding::Gzip))).status, StatusCode::OK);
    assert!(seen.lock().unwrap()[0].body.is_empty());
}

#[cfg(feature = "zstd")]
#[test]
fn zstd_uses_the_same_request_bounds_and_handler_path() {
    let plain = b"zstd request payload";
    let wire = asupersync_zstd::encode_all(plain, &asupersync_zstd::EncodeParams::new(asupersync_zstd::Level::Fast));
    let (router, seen) = app(1024, plain.len());
    assert_eq!(router.handle(request("zstd", wire.clone())).body.as_ref(), plain);
    assert_eq!(seen.lock().unwrap().len(), 1);
    let (router, seen) = app(1024, plain.len() - 1);
    assert_eq!(router.handle(request("zstd", wire)).status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(seen.lock().unwrap().is_empty());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encoded_streaming_requests_are_refused_without_polling_or_taking_the_body() {
    use asupersync::http::h1::stream::{BodyKind, IncomingRequestBody, RequestHead, StreamingServerRequest};
    use asupersync::http::h1::types::{Method, Version};
    use std::task::{Context, Poll, Waker};
    let runtime = asupersync::runtime::RuntimeBuilder::new().worker_threads(1).build().unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::types::Budget::INFINITE);
    let (writer, body) = IncomingRequestBody::channel_with_limits(&cx, BodyKind::ContentLength(25), 1, 32);
    let request = StreamingServerRequest {
        head: RequestHead {
            method: Method::Post,
            uri: "/upload".to_owned(),
            version: Version::Http11,
            headers: vec![("content-encoding".to_owned(), "gzip".to_owned()), ("content-length".to_owned(), "25".to_owned())],
        },
        peer_addr: None,
        body,
    };
    let (router, seen) = app(1024, 1024);
    let mut call = std::pin::pin!(router.handle_http1_streaming_request_with_cx(&cx, request));
    let Poll::Ready(response) = call.as_mut().poll(&mut Context::from_waker(Waker::noop())) else {
        panic!("encoded streaming rejection must not await request bytes");
    };
    assert_eq!(response.status, 415);
    assert!(seen.lock().unwrap().is_empty());
    assert!(writer.consumer_dropped());
    assert_eq!(writer.drain_progress().bytes, 0);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn identity_streaming_tightens_both_bounds_without_eager_collection() {
    use asupersync::http::h1::stream::{BodyKind, IncomingBodyError, IncomingRequestBody, RequestHead, StreamingServerRequest};
    use asupersync::http::h1::types::{Method, Version};
    use asupersync::web::extract::{FromRequest, StreamingRawBody, StreamingRawBodyCollectError};
    use std::task::{Context, Poll, Waker};

    struct CollectStream;
    impl Handler for CollectStream {
        fn call(&self, cx: &Cx, request: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
            let body = StreamingRawBody::from_request(request).unwrap();
            let cx = cx.clone();
            Box::pin(async move {
                match body.collect_bounded_with_cx(&cx, 1024).await {
                    Ok(collected) => Response::new(StatusCode::OK, collected.into_parts().0),
                    Err(StreamingRawBodyCollectError::Body(IncomingBodyError::BodyTooLarge { limit: 7, .. })) => {
                        Response::new(StatusCode::PAYLOAD_TOO_LARGE, "body exceeded middleware limit")
                    }
                    Err(error) => panic!("unexpected streaming refusal: {error}"),
                }
            })
        }
    }

    let runtime = asupersync::runtime::RuntimeBuilder::new().worker_threads(1).build().unwrap();
    for (encoded, decoded) in [(7, 100), (100, 7)] {
        for length in [7, 8] {
            let cx = runtime.request_cx_with_budget(asupersync::types::Budget::INFINITE);
            let (mut writer, body) = IncomingRequestBody::channel_with_limits(&cx, BodyKind::Chunked, 2, 32);
            let request = StreamingServerRequest {
                head: RequestHead {
                    method: Method::Post,
                    uri: "/upload".to_owned(),
                    version: Version::Http11,
                    headers: vec![("content-encoding".to_owned(), "identity".to_owned()), ("transfer-encoding".to_owned(), "chunked".to_owned())],
                },
                peer_addr: None,
                body,
            };
            let router = Router::new().without_default_trace()
                .route("/upload", post(CollectStream))
                .layer(RequestDecompressionLayer::new(encoded, decoded));
            let mut call = std::pin::pin!(router.handle_http1_streaming_request_with_cx(&cx, request));
            assert!(matches!(call.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Pending));
            assert!(!writer.consumer_dropped());
            let wire = format!("{length:x}\r\n{}\r\n0\r\n\r\n", "a".repeat(length));
            let pushed = runtime.block_on(writer.push_bytes(&cx, wire.as_bytes()));
            if length == 7 {
                pushed.unwrap();
                let response = runtime.block_on(call);
                assert_eq!(response.status, 200);
                assert_eq!(response.body.as_slice(), b"aaaaaaa");
            } else {
                assert!(matches!(pushed, Err(IncomingBodyError::BodyTooLarge { actual: Some(8), limit: 7 })));
                assert_eq!(runtime.block_on(call).status, 413);
            }
        }
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "compression"))]
mod native {
    use super::*;
    use asupersync::bytes::Bytes;
    use asupersync::http::compress::ContentEncoding;
    use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig};
    use asupersync::http::h1::server::{HostPolicy, Http1Config};
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::web::middleware::Layer;
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    fn wire(fields: &[&str], body: &[u8]) -> Vec<u8> {
        let mut wire = format!("POST /upload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n", body.len()).into_bytes();
        for field in fields {
            wire.extend_from_slice(format!("Content-Encoding: {field}\r\n").as_bytes());
        }
        wire.extend_from_slice(b"\r\n");
        wire.extend_from_slice(body);
        wire
    }

    fn exchange(router: Router, requests: Vec<Vec<u8>>, workers: usize) -> Vec<Vec<u8>> {
        let runtime = RuntimeBuilder::new().worker_threads(workers)
            .with_sharded_state(workers == 2)
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap()).build().unwrap();
        let listener = runtime.block_on(Http1Listener::bind_with_config(
            "127.0.0.1:0", router.into_http_handler(),
            Http1ListenerConfig::default().http_config(Http1Config::default()
                .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))),
        )).unwrap();
        let address = listener.local_addr().unwrap();
        let manager = listener.connection_manager().clone();
        let in_flight = listener.in_flight_requests();
        let handle = runtime.handle();
        let run = runtime.handle().spawn(async move { listener.run(&handle).await });
        let responses = requests.into_iter().map(|request| {
            let mut peer = std::net::TcpStream::connect(address).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            peer.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            peer.write_all(&request).unwrap();
            let mut response = Vec::new();
            peer.read_to_end(&mut response).unwrap();
            response
        }).collect();
        assert!(manager.begin_drain(Duration::from_secs(2)));
        assert!(runtime.block_on(run).unwrap().drain_report.unwrap().reached_quiescence);
        let start = Instant::now();
        while !runtime.is_quiescent() {
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::yield_now();
        }
        assert_eq!(in_flight.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(manager.active_count(), 0);
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert_eq!(runtime.draining_region_count(), 0);
        responses
    }

    fn response(wire: &[u8]) -> (u16, &[u8]) {
        let split = wire.windows(4).position(|bytes| bytes == b"\r\n\r\n").unwrap() + 4;
        let status = std::str::from_utf8(&wire[..split]).unwrap().split_whitespace().nth(1).unwrap().parse().unwrap();
        (status, &wire[split..])
    }

    #[test]
    fn native_http_preserves_repeated_coding_order_and_delivers_decoded_handler_bytes() {
        let stacked = encode(GZIP_HELLO, ContentEncoding::Deflate);
        for workers in [1, 2] {
            let (router, seen) = app(1024, 1024);
            let responses = exchange(router, vec![
                wire(&["gzip"], GZIP_HELLO),
                wire(&["gzip", "deflate"], &stacked),
                wire(&["gzip, identity, deflate"], &stacked),
                wire(&["gzip"], b"not a gzip member"),
                wire(&["future-coding"], b"wire"),
            ], workers);
            for received in &responses[..3] {
                assert_eq!(response(received), (200, b"hello".as_slice()));
            }
            assert_eq!(response(&responses[3]).0, 400);
            assert_eq!(response(&responses[4]).0, 415);
            assert_eq!(seen.lock().unwrap().len(), 3);
        }
    }

    #[derive(Clone)]
    struct ReplaceLayer { body: Option<Bytes>, coding: Option<&'static str> }
    struct Replace<H> { inner: H, replacement: ReplaceLayer }
    impl<H: Handler> Layer<H> for ReplaceLayer {
        type Service = Replace<H>;
        fn layer(&self, inner: H) -> Self::Service { Replace { inner, replacement: self.clone() } }
    }
    impl<H: Handler> Handler for Replace<H> {
        fn call(&self, cx: &Cx, mut request: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
            if let Some(body) = &self.replacement.body {
                request.body = body.clone();
                request.headers.insert("content-length".to_owned(), body.len().to_string());
            }
            if let Some(coding) = self.replacement.coding {
                request.headers.insert("content-encoding".to_owned(), coding.to_owned());
            }
            self.inner.call(cx, request)
        }
    }

    #[test]
    fn earlier_middleware_replacements_do_not_inherit_stale_wire_codings() {
        let original = encode(GZIP_HELLO, ContentEncoding::Deflate);
        let replacement = encode(b"replacement", ContentEncoding::Deflate);
        let (router, seen) = app(1024, 1024);
        let router = router.layer(ReplaceLayer { body: Some(replacement.into()), coding: None });
        let responses = exchange(router, vec![wire(&["gzip", "deflate"], &original)], 2);
        assert_eq!(response(&responses[0]), (200, b"replacement".as_slice()));
        assert_eq!(seen.lock().unwrap().len(), 1);

        let (router, seen) = app(1024, 1024);
        let router = router.layer(ReplaceLayer { body: None, coding: Some("identity") });
        let responses = exchange(router, vec![wire(&["gzip", "deflate"], &original)], 2);
        assert_eq!(response(&responses[0]), (200, original.as_slice()));
        assert_eq!(seen.lock().unwrap().len(), 1);
    }
}
