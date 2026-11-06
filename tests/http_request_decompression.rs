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

// Exercise the public Body adapter with controllable demand, segmented Buf
// input, source failures, and real codecs. Native transport coverage below
// separately checks request ownership and socket-driven progressive ingress.
mod progressive {
    use asupersync::bytes::{Buf, Bytes, BytesCursor};
    use asupersync::http::body::{
        Body, ContentDecodeError, ContentDecodeLimits, ContentDecodedBody,
        Frame, HeaderMap,
    };
    #[cfg(feature = "compression")]
    use asupersync::http::body::{HeaderName, HeaderValue};
    use std::collections::VecDeque;
    use std::io;
    use std::num::NonZeroUsize;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    struct ProbeState<D> {
        frames: VecDeque<Result<Frame<D>, io::Error>>,
        eof: bool,
        polls: usize,
        dropped: bool,
    }

    struct ProbeBody<D> {
        state: Arc<Mutex<ProbeState<D>>>,
    }

    impl<D: Buf> Body for ProbeBody<D> {
        type Data = D;
        type Error = io::Error;

        fn poll_frame(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Result<Frame<D>, io::Error>>> {
            let mut state = self.state.lock().unwrap();
            state.polls += 1;
            if let Some(frame) = state.frames.pop_front() {
                Poll::Ready(Some(frame))
            } else if state.eof {
                Poll::Ready(None)
            } else {
                Poll::Pending
            }
        }
    }

    impl<D> Drop for ProbeBody<D> {
        fn drop(&mut self) {
            self.state.lock().unwrap().dropped = true;
        }
    }

    fn probe<D>(frames: Vec<Result<Frame<D>, io::Error>>, eof: bool) -> (ProbeBody<D>, Arc<Mutex<ProbeState<D>>>) {
        let state = Arc::new(Mutex::new(ProbeState { frames: frames.into(), eof, polls: 0, dropped: false }));
        (ProbeBody { state: Arc::clone(&state) }, state)
    }

    fn data(bytes: &[u8]) -> Result<Frame<BytesCursor>, io::Error> {
        Ok(Frame::Data(BytesCursor::new(Bytes::copy_from_slice(bytes))))
    }

    fn poll<B: Body + Unpin>(body: &mut B) -> Poll<Option<Result<Frame<B::Data>, B::Error>>> {
        Pin::new(body).poll_frame(&mut Context::from_waker(Waker::noop()))
    }

    fn collect<B: Body + Unpin>(body: &mut B) -> Result<(Vec<u8>, Option<HeaderMap>), B::Error> {
        let mut bytes = Vec::new();
        let mut trailers = None;
        for _ in 0..100_000 {
            match poll(body) {
                Poll::Pending => continue, // bounded cooperative codec work
                Poll::Ready(Some(Ok(Frame::Data(mut data)))) => {
                    let remaining = data.remaining();
                    bytes.extend_from_slice(&data.copy_to_bytes(remaining));
                }
                Poll::Ready(Some(Ok(Frame::Trailers(frame)))) => {
                    assert!(trailers.replace(frame).is_none());
                }
                Poll::Ready(Some(Err(error))) => return Err(error),
                Poll::Ready(None) => return Ok((bytes, trailers)),
            }
        }
        panic!("body failed to complete after its source reached EOF");
    }

    fn limits(encoded: usize, decoded: usize, chunk: usize) -> ContentDecodeLimits {
        ContentDecodeLimits::new(encoded, decoded).with_chunk_size(NonZeroUsize::new(chunk).unwrap())
    }

    #[test]
    fn identity_handles_segmented_buffers_and_releases_source_at_eof_or_limit() {
        let segmented = BytesCursor::new(Bytes::from_static(b"ab"))
            .chain(BytesCursor::new(Bytes::from_static(b"cdef")));
        let (source, state) = probe(vec![Ok(Frame::Data(segmented))], true);
        let mut body = ContentDecodedBody::new(source, ["identity"], limits(6, 6, 3)).unwrap();
        assert_eq!(body.size_hint().upper(), Some(6));
        let Poll::Ready(Some(Ok(Frame::Data(first)))) = poll(&mut body) else { panic!("first frame"); };
        assert_eq!(first.chunk(), b"abc");
        assert_eq!(state.lock().unwrap().polls, 1);
        assert_eq!(collect(&mut body).unwrap().0, b"def");
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(state.lock().unwrap().dropped);

        for (encoded, decoded) in [(5, 6), (6, 5)] {
            let (source, state) = probe(vec![data(b"abcdef")], true);
            let mut body = ContentDecodedBody::new(source, std::iter::empty(), limits(encoded, decoded, 3)).unwrap();
            let error = collect(&mut body).unwrap_err();
            assert!(error.is_limit_exceeded());
            assert!(state.lock().unwrap().dropped, "failure eagerly releases the source");
            assert!(matches!(poll(&mut body), Poll::Ready(None)));
        }
    }

    #[test]
    fn parsing_and_feature_refusals_do_not_poll_source() {
        let mut invalid = vec![
            ("future-coding", io::ErrorKind::Unsupported),
            ("gzip;q=1", io::ErrorKind::InvalidData),
            (", ,", io::ErrorKind::InvalidData),
            ("identity,identity,identity,identity,identity,identity,identity,identity,identity", io::ErrorKind::InvalidData),
        ];
        if !cfg!(feature = "compression") {
            invalid.extend([("gzip", io::ErrorKind::Unsupported), ("deflate", io::ErrorKind::Unsupported), ("br", io::ErrorKind::Unsupported)]);
        }
        if !cfg!(feature = "zstd") {
            invalid.push(("zstd", io::ErrorKind::Unsupported));
        }
        for (coding, expected) in invalid {
            let (source, state) = probe::<BytesCursor>(Vec::new(), false);
            let error = ContentDecodedBody::new(source, [coding], limits(100, 100, 10)).unwrap_err();
            assert_eq!(error.kind(), expected, "{coding}");
            let state = state.lock().unwrap();
            assert_eq!(state.polls, 0);
            assert!(state.dropped);
        }
    }

    #[test]
    fn source_errors_and_invalid_trailer_order_are_terminal() {
        let (source, state) = probe(vec![data(b"one"), Err(io::Error::new(io::ErrorKind::ConnectionReset, "peer failed"))], true);
        let mut body = ContentDecodedBody::new(source, ["identity"], limits(100, 100, 8)).unwrap();
        assert!(matches!(poll(&mut body), Poll::Ready(Some(Ok(Frame::Data(_))))));
        let ContentDecodeError::Body(error) = collect(&mut body).unwrap_err() else { panic!("source error must retain its type"); };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert!(state.lock().unwrap().dropped);
        assert!(matches!(poll(&mut body), Poll::Ready(None)));

        for after in [data(b"late"), Ok(Frame::Trailers(HeaderMap::new()))] {
            let (source, state) = probe(vec![Ok(Frame::Trailers(HeaderMap::new())), after], true);
            let mut body = ContentDecodedBody::new(source, ["identity"], limits(100, 100, 8)).unwrap();
            assert!(matches!(collect(&mut body), Err(ContentDecodeError::Decode(_))));
            assert!(state.lock().unwrap().dropped);
        }
    }

    #[cfg(feature = "compression")]
    #[test]
    fn gzip_delivers_before_footer_and_withholds_sanitized_trailers_until_eof() {
        let wire = super::GZIP_HELLO;
        let (source, state) = probe(vec![data(&wire[..17])], false);
        let mut body = ContentDecodedBody::new(source, ["gzip"], limits(100, 100, 2)).unwrap();
        let mut early = Vec::new();
        loop {
            match poll(&mut body) {
                Poll::Ready(Some(Ok(Frame::Data(chunk)))) => {
                    assert!(chunk.remaining() <= 2);
                    assert_eq!(state.lock().unwrap().polls, 1, "pending output must drain before another source poll");
                    early.extend_from_slice(chunk.chunk());
                }
                Poll::Pending => break,
                other => panic!("unexpected pre-footer result: {other:?}"),
            }
        }
        assert_eq!(early, b"hello", "compressed upload must publish before footer or transport EOF");
        assert!(!body.is_end_stream());
        let mut trailers = HeaderMap::new();
        for name in ["content-encoding", "content-length", "digest", "content-md5", "content-digest", "repr-digest", "x-upload"] {
            trailers.append(HeaderName::from_static(name), HeaderValue::from_static("wire"));
        }
        {
            let mut state = state.lock().unwrap();
            state.frames.push_back(data(&wire[17..]));
            state.frames.push_back(Ok(Frame::Trailers(trailers)));
        }
        // Even a complete checksum and a trailer frame are not clean source EOF.
        assert!(matches!(poll(&mut body), Poll::Pending));
        state.lock().unwrap().eof = true;
        let (remaining, trailers) = collect(&mut body).unwrap();
        assert!(remaining.is_empty());
        let trailers = trailers.unwrap();
        assert_eq!(trailers.len(), 1);
        assert_eq!(trailers.get(&HeaderName::from_static("x-upload")).unwrap().as_bytes(), b"wire");
        assert!(state.lock().unwrap().dropped);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn late_checksum_and_truncation_failures_never_publish_success_trailers() {
        for corrupt in [false, true] {
            let wire = super::GZIP_HELLO;
            let (source, state) = probe(vec![data(&wire[..17])], false);
            let mut body = ContentDecodedBody::new(source, ["gzip"], limits(100, 100, 32)).unwrap();
            let Poll::Ready(Some(Ok(Frame::Data(chunk)))) = poll(&mut body) else { panic!("provisional data"); };
            assert_eq!(chunk.chunk(), b"hello");
            {
                let mut state = state.lock().unwrap();
                if corrupt {
                    let mut footer = wire[17..].to_vec();
                    footer[0] ^= 1;
                    state.frames.push_back(data(&footer));
                }
                state.frames.push_back(Ok(Frame::Trailers(HeaderMap::new())));
                state.eof = true;
            }
            assert!(matches!(collect(&mut body), Err(ContentDecodeError::Decode(_))));
            assert!(state.lock().unwrap().dropped);
            assert!(matches!(poll(&mut body), Poll::Ready(None)));
        }
    }

    #[cfg(feature = "compression")]
    #[test]
    fn dropping_a_pending_poll_future_preserves_partial_codec_state() {
        let (source, state) = probe(vec![data(&super::GZIP_HELLO[..11])], false);
        let mut body = ContentDecodedBody::new(source, ["gzip"], limits(100, 100, 2)).unwrap();
        {
            let mut pending = Box::pin(std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)));
            use std::future::Future;
            assert!(pending.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        }
        assert!(!state.lock().unwrap().dropped);
        {
            let mut state = state.lock().unwrap();
            state.frames.push_back(data(&super::GZIP_HELLO[11..]));
            state.eof = true;
        }
        assert_eq!(collect(&mut body).unwrap().0, b"hello");
        assert!(state.lock().unwrap().dropped);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn every_codec_and_reverse_stack_enforce_input_intermediate_and_final_totals() {
        use asupersync::http::compress::ContentEncoding;
        let plain = vec![b'a'; 4096];
        for coding in [ContentEncoding::Gzip, ContentEncoding::Deflate, ContentEncoding::Brotli] {
            let wire = super::encode(&plain, coding);
            let frames = wire.chunks(3).map(data).collect();
            let (source, _) = probe(frames, true);
            let mut body = ContentDecodedBody::new(source, [coding.as_token()], limits(wire.len(), plain.len(), 7)).unwrap();
            assert_eq!(collect(&mut body).unwrap().0, plain);
            for (encoded, decoded) in [(wire.len() - 1, plain.len()), (wire.len(), plain.len() - 1)] {
                let (source, state) = probe(wire.chunks(3).map(data).collect(), true);
                let mut body = ContentDecodedBody::new(source, [coding.as_token()], limits(encoded, decoded, 7)).unwrap();
                assert!(collect(&mut body).unwrap_err().is_limit_exceeded());
                assert!(state.lock().unwrap().dropped);
            }
        }
        let inner = super::encode(b"hello", ContentEncoding::Gzip);
        let wire = super::encode(&inner, ContentEncoding::Deflate);
        let (source, _) = probe(wire.chunks(1).map(data).collect(), true);
        let mut body = ContentDecodedBody::new(source, ["gzip", "identity, deflate"], limits(1024, 1024, 2)).unwrap();
        assert_eq!(collect(&mut body).unwrap().0, b"hello");
        let (source, state) = probe(vec![data(&wire)], true);
        let mut body = ContentDecodedBody::new(source, ["gzip, deflate"], limits(1024, 5, 2)).unwrap();
        assert!(collect(&mut body).unwrap_err().is_limit_exceeded(), "intermediate gzip bytes exceed limit although final bytes fit");
        assert!(state.lock().unwrap().dropped);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn zstd_resumes_under_output_backpressure_across_concatenated_frames() {
        let first = vec![b'x'; 65_536];
        let second = b"tail";
        let params = asupersync_zstd::EncodeParams::new(asupersync_zstd::Level::Fast);
        let mut wire = asupersync_zstd::encode_all(&first, &params);
        wire.extend(asupersync_zstd::encode_all(second, &params));
        let (source, _) = probe(wire.chunks(5).map(data).collect(), true);
        let mut body = ContentDecodedBody::new(source, ["zstd"], limits(wire.len(), first.len() + second.len(), 31)).unwrap();
        let expected = [first.as_slice(), second].concat();
        assert_eq!(collect(&mut body).unwrap().0, expected);
        let (source, state) = probe(vec![data(&wire)], true);
        let mut body = ContentDecodedBody::new(source, ["zstd"], limits(wire.len(), expected.len() - 1, 31)).unwrap();
        assert!(collect(&mut body).unwrap_err().is_limit_exceeded());
        assert!(state.lock().unwrap().dropped);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn attached_context_wakes_pending_source_and_drop_clears_its_registration() {
        use asupersync::types::CancelKind;
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct WakeCount(AtomicUsize);
        impl std::task::Wake for WakeCount {
            fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
            fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
        }
        let runtime = asupersync::runtime::RuntimeBuilder::new().worker_threads(1).build().unwrap();
        for drop_first in [false, true] {
            let cx = runtime.request_cx_with_budget(asupersync::types::Budget::INFINITE);
            let (source, state) = probe::<BytesCursor>(Vec::new(), false);
            let mut body = ContentDecodedBody::new(source, ["identity"], limits(100, 100, 8)).unwrap().with_cx(&cx);
            let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
            let waker = Waker::from(Arc::clone(&wakes));
            assert!(Pin::new(&mut body).poll_frame(&mut Context::from_waker(&waker)).is_pending());
            assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
            if drop_first {
                drop(body);
                cx.cancel_fast(CancelKind::User);
                assert_eq!(wakes.0.load(Ordering::SeqCst), 0, "dropped adapter must remove its registration");
            } else {
                cx.cancel_fast(CancelKind::User);
                assert!(wakes.0.load(Ordering::SeqCst) > 0, "cancellation must wake an otherwise parked source");
                assert!(matches!(poll(&mut body), Poll::Ready(Some(Err(ContentDecodeError::Cancelled { kind: CancelKind::User })))));
                assert!(matches!(poll(&mut body), Poll::Ready(None)));
            }
            assert!(state.lock().unwrap().dropped);
        }
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "compression"))]
    #[test]
    fn queued_output_observes_cancellation_without_polling_the_source_again() {
        use asupersync::http::compress::ContentEncoding;
        let runtime = asupersync::runtime::RuntimeBuilder::new().worker_threads(1).build().unwrap();
        let cx = runtime.request_cx_with_budget(asupersync::types::Budget::INFINITE);
        let wire = super::encode(&vec![b'x'; 32 * 1024], ContentEncoding::Gzip);
        let (source, state) = probe(vec![data(&wire)], false);
        let mut body = ContentDecodedBody::new(source, ["gzip"], limits(1024, 32 * 1024, 1024)).unwrap().with_cx(&cx);
        let Poll::Ready(Some(Ok(Frame::Data(first)))) = poll(&mut body) else { panic!("first decoded chunk"); };
        assert_eq!(first.remaining(), 1024);
        assert_eq!(state.lock().unwrap().polls, 1);
        cx.cancel_with(asupersync::types::CancelKind::User, Some("cancel queued decoded upload"));
        assert!(matches!(poll(&mut body), Poll::Ready(Some(Err(ContentDecodeError::Cancelled { .. })))));
        let state = state.lock().unwrap();
        assert_eq!(state.polls, 1);
        assert!(state.dropped);
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

    #[test]
    fn native_streaming_uploads_decode_before_footer_preserve_raw_headers_and_drain() {
        use asupersync::bytes::Buf;
        use asupersync::http::body::{Body, ContentDecodeError, ContentDecodeLimits, Frame};
        use asupersync::http::h1::stream::IncomingBodyError;
        use asupersync::web::{AsyncCxFnHandler2, DecodedStreamingBody, StreamingRawBody};
        use asupersync::web::middleware::StreamingRequestDecompressionLayer;
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicUsize, Ordering};

        for workers in [1, 2] {
            let runtime = RuntimeBuilder::new().worker_threads(workers)
                .with_sharded_state(workers == 2)
                .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap()).build().unwrap();
            let progress = Arc::new(AtomicUsize::new(0));
            let original_heads = Arc::new(Mutex::new(Vec::new()));
            let observed_trailers = Arc::new(Mutex::new(Vec::new()));
            let handler_progress = Arc::clone(&progress);
            let handler_heads = Arc::clone(&original_heads);
            let handler_trailers = Arc::clone(&observed_trailers);
            let upload = AsyncCxFnHandler2::new(move |_cx: Cx, headers: HashMap<String, String>, mut body: DecodedStreamingBody| {
                let progress = Arc::clone(&handler_progress);
                let heads = Arc::clone(&handler_heads);
                let trailers = Arc::clone(&handler_trailers);
                async move {
                    heads.lock().unwrap().push(headers);
                    let mut bytes = Vec::new();
                    while let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
                        match frame {
                            Ok(Frame::Data(data)) => {
                                bytes.extend_from_slice(data.chunk());
                                progress.store(bytes.len(), Ordering::Release);
                            }
                            Ok(Frame::Trailers(frame)) => trailers.lock().unwrap().push(frame),
                            Err(error) => {
                                let status = if error.is_limit_exceeded() || matches!(&error,
                                    ContentDecodeError::Body(IncomingBodyError::BodyTooLarge { .. }
                                        | IncomingBodyError::QueueFrameTooLarge { .. })) {
                                    StatusCode::PAYLOAD_TOO_LARGE
                                } else {
                                    StatusCode::BAD_REQUEST
                                };
                                return Response::new(status, "upload rejected");
                            }
                        }
                    }
                    Response::new(StatusCode::OK, bytes)
                }
            });
            let raw = AsyncCxFnHandler2::new(|cx: Cx, headers: HashMap<String, String>, body: StreamingRawBody| async move {
                assert_eq!(headers.get("content-encoding").map(String::as_str), Some("gzip"));
                assert_eq!(headers.get("content-length").map(String::as_str), Some("25"));
                let collected = body.collect_bounded_with_cx(&cx, 1024).await.unwrap();
                Response::new(StatusCode::OK, collected.into_parts().0)
            });
            let router = Router::new().without_default_trace()
                .route("/upload", post(upload))
                .route("/raw", post(raw))
                .layer(StreamingRequestDecompressionLayer::new(ContentDecodeLimits::new(64 * 1024, 256 * 1024)));
            let listener = runtime.block_on(Http1Listener::bind_streaming_with_config(
                "127.0.0.1:0", router.into_http1_streaming_handler(),
                Http1ListenerConfig::default().http_config(Http1Config::default()
                    .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))),
            )).unwrap();
            let address = listener.local_addr().unwrap();
            let manager = listener.connection_manager().clone();
            let in_flight = listener.in_flight_requests();
            let handle = runtime.handle();
            let run = runtime.handle().spawn(async move { listener.run_streaming(&handle).await });

            let connect = || {
                let peer = std::net::TcpStream::connect(address).unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                peer.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                peer
            };
            let mut peer = connect();
            peer.write_all(b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nTrailer: X-Upload\r\nConnection: close\r\n\r\n11\r\n").unwrap();
            peer.write_all(&GZIP_HELLO[..17]).unwrap();
            peer.write_all(b"\r\n").unwrap();
            let start = Instant::now();
            while progress.load(Ordering::Acquire) < 5 {
                assert!(start.elapsed() < Duration::from_secs(5), "decoded upload must reach handler before gzip footer and HTTP EOF");
                std::thread::yield_now();
            }
            assert!(observed_trailers.lock().unwrap().is_empty());
            {
                let heads = original_heads.lock().unwrap();
                assert_eq!(heads[0].get("content-encoding").map(String::as_str), Some("gzip"));
                assert_eq!(heads[0].get("transfer-encoding").map(String::as_str), Some("chunked"));
                assert!(!heads[0].contains_key("content-length"));
            }
            peer.write_all(b"8\r\n").unwrap();
            peer.write_all(&GZIP_HELLO[17..]).unwrap();
            peer.write_all(b"\r\n0\r\nX-Upload: complete\r\n\r\n").unwrap();
            let mut received = Vec::new();
            peer.read_to_end(&mut received).unwrap();
            assert_eq!(response(&received), (200, b"hello".as_slice()));
            assert_eq!(observed_trailers.lock().unwrap().len(), 1);

            let stacked = encode(GZIP_HELLO, ContentEncoding::Deflate);
            let bomb = encode(&vec![b'x'; 256 * 1024 + 1], ContentEncoding::Gzip);
            for (request, expected_status, expected_body) in [
                (wire(&["gzip", "deflate"], &stacked), 200, Some(b"hello".as_slice())),
                (wire(&["future-coding"], b"wire"), 415, None),
                (wire(&["gzip"], &bomb), 413, None),
                (wire(&["gzip"], &GZIP_HELLO[..17]), 400, None),
            ] {
                let mut peer = connect();
                peer.write_all(&request).unwrap();
                let mut received = Vec::new();
                peer.read_to_end(&mut received).unwrap();
                assert_eq!(response(&received).0, expected_status);
                if let Some(expected_body) = expected_body {
                    assert_eq!(response(&received).1, expected_body);
                }
            }
            // Installing the layer alone must leave raw extraction untouched.
            let mut peer = connect();
            peer.write_all(b"POST /raw HTTP/1.1\r\nHost: localhost\r\nContent-Encoding: gzip\r\nContent-Length: 25\r\nConnection: close\r\n\r\n").unwrap();
            peer.write_all(GZIP_HELLO).unwrap();
            let mut received = Vec::new();
            peer.read_to_end(&mut received).unwrap();
            assert_eq!(response(&received), (200, GZIP_HELLO));

            assert!(manager.begin_drain(Duration::from_secs(2)));
            assert!(runtime.block_on(run).unwrap().drain_report.unwrap().reached_quiescence);
            let start = Instant::now();
            while !runtime.is_quiescent() {
                assert!(start.elapsed() < Duration::from_secs(5));
                std::thread::yield_now();
            }
            assert_eq!(in_flight.load(Ordering::SeqCst), 0);
            assert_eq!(manager.active_count(), 0);
            assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
            assert_eq!(runtime.draining_region_count(), 0);
        }
    }
}
