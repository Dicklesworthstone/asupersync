//! Pull-driven response compression and supervised native response framing.
//! Governing rollup: asupersync-server-stack-hardening-eeexl1.6 / .6.9.

#![recursion_limit = "256"]

use asupersync::bytes::{Buf, Bytes, BytesCursor};
use asupersync::http::body::{
    Body, ContentDecodeLimits, ContentDecodedBody, ContentEncodeError,
    ContentEncodeLimits, ContentEncodedBody, Frame, HeaderMap,
};
#[cfg(feature = "compression")]
use asupersync::http::body::{HeaderName, HeaderValue};
use asupersync::http::compress::ContentCoding;
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

    fn poll_frame(self: Pin<&mut Self>, _task: &mut Context<'_>) -> Poll<Option<Result<Frame<D>, io::Error>>> {
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
    fn drop(&mut self) { self.state.lock().unwrap().dropped = true; }
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
            Poll::Pending => continue,
            Poll::Ready(Some(Ok(Frame::Data(mut data)))) => {
                assert!(trailers.is_none(), "DATA must precede terminal trailers");
                let remaining = data.remaining();
                bytes.extend_from_slice(&data.copy_to_bytes(remaining));
            }
            Poll::Ready(Some(Ok(Frame::Trailers(frame)))) => assert!(trailers.replace(frame).is_none()),
            Poll::Ready(Some(Err(error))) => return Err(error),
            Poll::Ready(None) => return Ok((bytes, trailers)),
        }
    }
    panic!("source reached EOF but its encoded body did not complete");
}

fn limits(source: usize, encoded: usize, chunk: usize) -> ContentEncodeLimits {
    ContentEncodeLimits::new(source, encoded).with_chunk_size(NonZeroUsize::new(chunk).unwrap())
}

fn decode(bytes: Vec<u8>, coding: ContentCoding, limit: usize) -> Vec<u8> {
    let encoded = bytes.len();
    let mut body = ContentDecodedBody::new(Bytes::from(bytes), [coding.as_token()], ContentDecodeLimits::new(encoded, limit)).unwrap();
    collect(&mut body).unwrap().0
}

#[test]
fn identity_is_segmented_zero_copy_demand_driven_and_bounded() {
    let segmented = BytesCursor::new(Bytes::from_static(b"ab"))
        .chain(BytesCursor::new(Bytes::from_static(b"cdef")));
    let (source, state) = probe(vec![Ok(Frame::Data(segmented))], true);
    let mut body = ContentEncodedBody::new(source, ContentCoding::Identity, limits(6, 6, 3)).unwrap();
    assert_eq!(state.lock().unwrap().polls, 0);
    let Poll::Ready(Some(Ok(Frame::Data(first)))) = poll(&mut body) else { panic!("first DATA"); };
    assert_eq!(first.chunk(), b"abc");
    assert_eq!(state.lock().unwrap().polls, 1);
    assert_eq!(body.size_hint().upper(), Some(3));
    let Poll::Ready(Some(Ok(Frame::Data(second)))) = poll(&mut body) else { panic!("second DATA"); };
    assert_eq!(second.chunk(), b"def");
    assert_eq!(state.lock().unwrap().polls, 1, "queued source data must drain before source repoll");
    assert!(collect(&mut body).unwrap().0.is_empty());
    assert!(body.is_end_stream());
    assert_eq!(body.size_hint().exact(), Some(0));
    assert!(state.lock().unwrap().dropped);

    for (source_limit, encoded_limit) in [(5, 6), (6, 5)] {
        let (source, state) = probe(vec![data(b"abcdef")], true);
        let mut body = ContentEncodedBody::new(source, ContentCoding::Identity, limits(source_limit, encoded_limit, 3)).unwrap();
        assert!(collect(&mut body).unwrap_err().is_limit_exceeded());
        assert!(state.lock().unwrap().dropped);
        assert!(matches!(poll(&mut body), Poll::Ready(None)));
    }
}

#[test]
fn source_errors_trailer_order_and_unavailable_codecs_release_without_success() {
    let (source, state) = probe(vec![data(b"first"), Err(io::Error::new(io::ErrorKind::ConnectionReset, "source failed"))], true);
    let mut body = ContentEncodedBody::new(source, ContentCoding::Identity, limits(100, 100, 20)).unwrap();
    assert!(matches!(poll(&mut body), Poll::Ready(Some(Ok(Frame::Data(_))))));
    let ContentEncodeError::Body(error) = collect(&mut body).unwrap_err() else { panic!("retain source error"); };
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    assert!(state.lock().unwrap().dropped);
    assert!(matches!(poll(&mut body), Poll::Ready(None)));

    for after in [data(b"late"), Ok(Frame::Trailers(HeaderMap::new()))] {
        let (source, state) = probe(vec![Ok(Frame::Trailers(HeaderMap::new())), after], true);
        let mut body = ContentEncodedBody::new(source, ContentCoding::Identity, limits(100, 100, 20)).unwrap();
        assert!(matches!(collect(&mut body), Err(ContentEncodeError::Encode(_))));
        assert!(state.lock().unwrap().dropped);
    }
    for coding in [ContentCoding::Gzip, ContentCoding::Deflate, ContentCoding::Brotli, ContentCoding::Zstd] {
        if (coding == ContentCoding::Zstd && cfg!(feature = "zstd"))
            || (coding != ContentCoding::Zstd && cfg!(feature = "compression")) { continue; }
        let (source, state) = probe::<BytesCursor>(Vec::new(), false);
        let error = ContentEncodedBody::new(source, coding, limits(100, 100, 20)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(state.lock().unwrap().polls, 0);
        assert!(state.lock().unwrap().dropped);
    }
}

#[test]
fn abandoning_a_pending_polling_future_preserves_owned_progress_and_fairness() {
    use std::future::{Future, poll_fn};
    let (source, state) = probe(vec![data(b"abcdef")], false);
    let mut body = ContentEncodedBody::new(source, ContentCoding::Identity, limits(100, 100, 3)).unwrap();
    let mut observed = Vec::new();
    {
        let mut waiting = Box::pin(async {
            loop {
                match poll_fn(|task| Pin::new(&mut body).poll_frame(task)).await {
                    Some(Ok(Frame::Data(bytes))) => observed.extend_from_slice(bytes.chunk()),
                    other => panic!("source is deliberately held open: {other:?}"),
                }
            }
        });
        assert!(waiting.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    }
    assert_eq!(observed, b"abcdef");
    assert!(!state.lock().unwrap().dropped, "the body, not its short-lived polling future, owns progress");
    {
        let mut state = state.lock().unwrap();
        state.frames.push_back(data(b"tail"));
        state.eof = true;
    }
    assert_eq!(collect(&mut body).unwrap().0, b"tail");

    let (source, state) = probe((0..100).map(|_| data(b"")).collect(), true);
    let mut body = ContentEncodedBody::new(source, ContentCoding::Identity, limits(0, 0, 1)).unwrap();
    assert!(poll(&mut body).is_pending(), "an always-ready empty source must yield cooperatively");
    assert!(state.lock().unwrap().polls < 100);
    assert!(collect(&mut body).unwrap().0.is_empty());
}

#[cfg(feature = "compression")]
#[test]
fn gzip_publishes_decodable_data_before_eof_and_validates_footer_before_trailers() {
    use asupersync::http::compress::{DecompressionLimit, Decompressor, GzipDecompressor};
    let (source, state) = probe(vec![data(b"hello")], false);
    let mut body = ContentEncodedBody::new(source, ContentCoding::Gzip, limits(100, 1000, 3)).unwrap();
    let mut decoder = GzipDecompressor::new(DecompressionLimit::new(100));
    let mut decoded = Vec::new();
    loop {
        match poll(&mut body) {
            Poll::Ready(Some(Ok(Frame::Data(bytes)))) => {
                assert!(bytes.remaining() <= 3);
                assert_eq!(state.lock().unwrap().polls, 1);
                decoder.decompress(bytes.chunk(), &mut decoded).unwrap();
            }
            Poll::Pending => break,
            other => panic!("unexpected pre-EOF result: {other:?}"),
        }
    }
    assert_eq!(decoded, b"hello", "actual plaintext, not only a gzip header, must precede source EOF");
    let mut trailers = HeaderMap::new();
    for name in ["content-encoding", "content-length", "content-md5", "digest", "content-digest", "repr-digest"] {
        trailers.append(HeaderName::from_static(name), HeaderValue::from_static("stale"));
    }
    trailers.append(HeaderName::from_static("etag"), HeaderValue::from_static("\"original\""));
    trailers.append(HeaderName::from_static("x-finished"), HeaderValue::from_static("yes"));
    {
        let mut state = state.lock().unwrap();
        state.frames.push_back(data(b" world"));
        state.frames.push_back(Ok(Frame::Trailers(trailers)));
    }
    loop {
        match poll(&mut body) {
            Poll::Ready(Some(Ok(Frame::Data(bytes)))) => decoder.decompress(bytes.chunk(), &mut decoded).unwrap(),
            Poll::Pending => break,
            other => panic!("trailers cannot precede successful source EOF: {other:?}"),
        }
    }
    assert_eq!(decoded, b"hello world");
    state.lock().unwrap().eof = true;
    let (footer, trailers) = collect(&mut body).unwrap();
    decoder.decompress(&footer, &mut decoded).unwrap();
    decoder.finish(&mut decoded).unwrap();
    let trailers = trailers.unwrap();
    assert_eq!(trailers.len(), 2);
    assert_eq!(trailers.get(&HeaderName::from_static("etag")).unwrap().as_bytes(), b"W/\"original\"");
    assert!(state.lock().unwrap().dropped);
}

#[test]
fn available_codecs_round_trip_segmented_input_and_enforce_complete_encoded_cap() {
    let mut codings = vec![ContentCoding::Identity];
    if cfg!(feature = "compression") { codings.extend([ContentCoding::Gzip, ContentCoding::Deflate, ContentCoding::Brotli]); }
    if cfg!(feature = "zstd") { codings.push(ContentCoding::Zstd); }
    for coding in codings {
        for plain in [Vec::new(), b"hello streamed world".to_vec(), vec![b'x'; 64 * 1024]] {
            let mid = plain.len() / 2;
            let source = BytesCursor::new(Bytes::copy_from_slice(&plain[..mid]))
                .chain(BytesCursor::new(Bytes::copy_from_slice(&plain[mid..])));
            let (source, _) = probe(vec![Ok(Frame::Data(source))], true);
            let mut encoded = ContentEncodedBody::new(source, coding, limits(plain.len(), 128 * 1024, 31)).unwrap();
            let wire = collect(&mut encoded).unwrap().0;
            assert_eq!(decode(wire.clone(), coding, plain.len()), plain, "{coding:?}");

            // Reproduce identical application frame/quantum boundaries: flush
            // overhead is part of the encoded ceiling, including empty input.
            for cap in [wire.len(), wire.len().saturating_sub(1)] {
                let source = BytesCursor::new(Bytes::copy_from_slice(&plain[..mid]))
                    .chain(BytesCursor::new(Bytes::copy_from_slice(&plain[mid..])));
                let (source, state) = probe(vec![Ok(Frame::Data(source))], true);
                let mut encoded = ContentEncodedBody::new(source, coding, limits(plain.len(), cap, 31)).unwrap();
                let result = collect(&mut encoded);
                if cap == wire.len() { assert_eq!(result.unwrap().0, wire); }
                else { assert!(matches!(result, Err(ContentEncodeError::EncodedLimit { .. })), "{coding:?}"); }
                assert!(state.lock().unwrap().dropped);
            }
        }
    }
}

#[cfg(feature = "zstd")]
#[test]
fn zstd_flushes_live_partial_frames_and_resumes_before_final_source_eof() {
    let (source, state) = probe(vec![data(b"first")], false);
    let mut body = ContentEncodedBody::new(source, ContentCoding::Zstd, limits(100, 1000, 2)).unwrap();
    let mut wire = Vec::new();
    loop {
        match poll(&mut body) {
            Poll::Ready(Some(Ok(Frame::Data(bytes)))) => {
                assert!(bytes.remaining() <= 2);
                wire.extend_from_slice(bytes.chunk());
            }
            Poll::Pending => break,
            other => panic!("unexpected live zstd result: {other:?}"),
        }
    }
    assert_eq!(decode(wire.clone(), ContentCoding::Zstd, 5), b"first");
    assert!(!body.is_end_stream());
    {
        let mut state = state.lock().unwrap();
        state.frames.push_back(data(b"second"));
        state.eof = true;
    }
    wire.extend(collect(&mut body).unwrap().0);
    assert_eq!(decode(wire, ContentCoding::Zstd, 11), b"firstsecond");
    assert!(state.lock().unwrap().dropped);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn attached_context_wakes_parked_source_cancels_queued_output_and_unregisters_on_drop() {
    use asupersync::types::{Budget, CancelKind};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct WakeCount(AtomicUsize);
    impl std::task::Wake for WakeCount {
        fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
        fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }
    let runtime = asupersync::runtime::RuntimeBuilder::new().worker_threads(1).build().unwrap();
    for drop_first in [false, true] {
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let (source, state) = probe::<BytesCursor>(Vec::new(), false);
        let mut body = ContentEncodedBody::new(source, ContentCoding::Identity, limits(100, 100, 3)).unwrap().with_cx(&cx);
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        assert!(Pin::new(&mut body).poll_frame(&mut Context::from_waker(&waker)).is_pending());
        if drop_first {
            drop(body);
            cx.cancel_fast(CancelKind::User);
            assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
        } else {
            cx.cancel_fast(CancelKind::User);
            assert!(wakes.0.load(Ordering::SeqCst) > 0);
            assert!(matches!(poll(&mut body), Poll::Ready(Some(Err(ContentEncodeError::Cancelled { kind: CancelKind::User })))));
            assert!(matches!(poll(&mut body), Poll::Ready(None)));
        }
        assert!(state.lock().unwrap().dropped);
    }
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    let (source, state) = probe(vec![data(b"abcdef")], false);
    let mut body = ContentEncodedBody::new(source, ContentCoding::Identity, limits(100, 100, 3)).unwrap().with_cx(&cx);
    assert!(matches!(poll(&mut body), Poll::Ready(Some(Ok(Frame::Data(_))))));
    cx.cancel_fast(CancelKind::User);
    assert!(matches!(poll(&mut body), Poll::Ready(Some(Err(ContentEncodeError::Cancelled { .. })))));
    assert_eq!(state.lock().unwrap().polls, 1);
    assert!(state.lock().unwrap().dropped);
}

#[cfg(not(target_arch = "wasm32"))]
mod metadata {
    use super::*;
    use asupersync::web::extract::{FromRequestParts, Request};
    use asupersync::web::{Response, StatusCode, StreamingCompression, StreamingCompressionConfig};

    fn prepare(request: Request, head: Response, minimum: usize) -> Result<(Response, ContentEncodedBody<Bytes>), Response> {
        StreamingCompression::from_request_parts(&request).unwrap().encode_response(
            head, Bytes::from_static(b"hello"),
            StreamingCompressionConfig::new(limits(100, 1000, 8)).with_min_body_size(minimum),
        )
    }

    #[test]
    fn bodyless_heads_keep_representation_metadata_and_preflight_is_lazy() {
        for (method, status) in [("HEAD", 200), ("GET", 103), ("GET", 204), ("GET", 205), ("GET", 304), ("CONNECT", 200)] {
            let request = Request::new(method, "/").with_header("accept-encoding", "gzip, identity;q=0");
            let (source, state) = probe::<BytesCursor>(Vec::new(), false);
            let (head, body) = StreamingCompression::from_request_parts(&request).unwrap().encode_response(
                Response::empty(StatusCode::from_u16(status)).header("content-length", "1234").header("etag", "\"original\""),
                source, StreamingCompressionConfig::new(limits(0, 0, 1)),
            ).unwrap();
            assert_eq!(body.coding(), ContentCoding::Identity);
            assert_eq!(head.header_value("content-length"), Some("1234"));
            assert_eq!(head.header_value("etag"), Some("\"original\""));
            assert!(!head.has_header("content-encoding"));
            assert_eq!(state.lock().unwrap().polls, 0);
            drop(body);
            assert!(state.lock().unwrap().dropped);
        }
        let request = Request::new("GET", "/").with_header("accept-encoding", "gzip");
        for head in [Response::new(StatusCode::OK, "already buffered"), Response::empty(StatusCode::OK).header("transfer-encoding", "chunked"), Response::empty(StatusCode::OK).header("content-length", "5, 6")] {
            let (source, state) = probe::<BytesCursor>(Vec::new(), false);
            let response = StreamingCompression::from_request_parts(&request).unwrap()
                .encode_response(head, source, StreamingCompressionConfig::new(limits(100, 1000, 8))).unwrap_err();
            assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(state.lock().unwrap().polls, 0);
            assert!(state.lock().unwrap().dropped);
        }
    }

    #[test]
    fn identity_protections_negotiation_and_small_body_fallback_are_consistent() {
        let base = Request::new("GET", "/").with_header("accept-encoding", "gzip, identity;q=0");
        for (request, head) in [
            (base.clone().with_header("range", "bytes=0-4"), Response::empty(StatusCode::OK)),
            (base.clone().with_header("cache-control", "No-Transform"), Response::empty(StatusCode::OK)),
            (base.clone(), Response::empty(StatusCode::PARTIAL_CONTENT)),
            (base.clone(), Response::empty(StatusCode::OK).header("content-range", "bytes 0-4/5")),
            (base.clone(), Response::empty(StatusCode::OK).header("cache-control", "max-age=0, no-transform")),
            (base.clone(), Response::empty(StatusCode::OK).header("content-type", "application/grpc+proto")),
            (base.clone(), Response::empty(StatusCode::OK).header("content-type", "text/event-stream; charset=utf-8")),
            (base.clone().with_header("authorization", "Bearer secret"), Response::empty(StatusCode::OK)),
            (base.clone(), Response::empty(StatusCode::OK).header("set-cookie", "session=secret")),
        ] {
            assert_eq!(prepare(request, head, 0).unwrap_err().status.as_u16(), 406);
        }
        let request = Request::new("GET", "/").with_header("accept-encoding", "gzip");
        let (head, body) = StreamingCompression::from_request_parts(&request).unwrap().encode_response(
            Response::empty(StatusCode::OK).header("content-length", "5"), Bytes::from_static(b"hello"),
            StreamingCompressionConfig::new(limits(5, 5, 3)).with_codings(vec![ContentCoding::Gzip]),
        ).unwrap();
        assert_eq!(body.coding(), ContentCoding::Identity);
        assert_eq!(head.header_value("content-length"), Some("5"));
        let (head, body) = prepare(base, Response::empty(StatusCode::OK).header("content-encoding", "custom"), 0).unwrap();
        assert_eq!(body.coding(), ContentCoding::Identity);
        assert_eq!(head.header_value("content-encoding"), Some("custom"));
    }

    #[cfg(feature = "compression")]
    #[test]
    fn negotiated_compression_removes_stale_metadata_without_touching_vary_star() {
        for vary in ["origin", "*"] {
            let request = Request::new("GET", "/").with_header("accept-encoding", "gzip, br;q=0, identity;q=0");
            let head = Response::empty(StatusCode::OK).header("content-length", "5")
                .header("etag", "\"plain\"").header("digest", "obsolete").header("vary", vary);
            let (head, mut body) = prepare(request, head, 0).unwrap();
            assert_eq!(head.header_value("content-encoding"), Some("gzip"));
            assert!(!head.has_header("content-length"));
            assert!(!head.has_header("digest"));
            assert_eq!(head.header_value("etag"), Some("W/\"plain\""));
            if vary == "*" { assert_eq!(head.header_value("vary"), Some("*")); }
            else { assert!(head.header_value("vary").unwrap().contains("accept-encoding")); }
            assert_eq!(decode(collect(&mut body).unwrap().0, ContentCoding::Gzip, 5), b"hello");
        }
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "compression"))]
mod native {
    use super::*;
    use asupersync::Cx;
    use asupersync::bytes::BytesMut;
    use asupersync::codec::Decoder as _;
    use asupersync::http::compress::{DecompressionLimit, Decompressor, GzipDecompressor};
    use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig};
    use asupersync::http::h1::server::{HostPolicy, Http1Config};
    use asupersync::http::h2::connection::CLIENT_PREFACE;
    use asupersync::http::h2::frame::{Frame as H2Frame, HeadersFrame, RstStreamFrame, SettingsFrame};
    use asupersync::http::h2::listener::{Http2Listener, Http2ListenerConfig};
    use asupersync::http::h2::{ErrorCode, FrameCodec, Header, HpackDecoder, HpackEncoder};
    use asupersync::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
    use asupersync::types::CancelKind;
    use asupersync::web::{
        AsyncCxFnHandler1, AsyncCxFnHandler2, FnHandler, Http1StreamResponder, Http2StreamResponder,
        Response, Router, StatusCode, StreamingCompression, StreamingCompressionConfig, get,
    };
    use std::io::{BufRead, Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    enum Event { Parked(Cx), Dropped { cancelled: bool, polls: usize } }

    struct GateFrames {
        frames: VecDeque<Result<Frame<BytesCursor>, io::Error>>,
        eof: bool,
        waker: Option<Waker>,
        reported: bool,
    }

    struct Gate {
        frames: Mutex<GateFrames>,
        polls: AtomicUsize,
        events: mpsc::Sender<Event>,
    }

    impl Gate {
        fn new() -> (Arc<Self>, mpsc::Receiver<Event>) {
            let (events, receive) = mpsc::channel();
            (Arc::new(Self {
                frames: Mutex::new(GateFrames { frames: vec![data(b"hello")].into(), eof: false, waker: None, reported: false }),
                polls: AtomicUsize::new(0), events,
            }), receive)
        }

        fn finish(&self) {
            let wake = {
                let mut state = self.frames.lock().unwrap();
                state.frames.push_back(data(b" world"));
                let mut trailers = HeaderMap::new();
                trailers.append(HeaderName::from_static("x-finished"), HeaderValue::from_static("yes"));
                trailers.append(HeaderName::from_static("digest"), HeaderValue::from_static("stale"));
                state.frames.push_back(Ok(Frame::Trailers(trailers)));
                state.eof = true;
                state.waker.take()
            };
            if let Some(waker) = wake { waker.wake(); }
        }
    }

    struct GateBody { gate: Arc<Gate>, cx: Cx }

    impl Body for GateBody {
        type Data = BytesCursor;
        type Error = io::Error;

        fn poll_frame(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<Result<Frame<BytesCursor>, io::Error>>> {
            self.gate.polls.fetch_add(1, Ordering::SeqCst);
            let mut state = self.gate.frames.lock().unwrap();
            if let Some(frame) = state.frames.pop_front() { return Poll::Ready(Some(frame)); }
            if state.eof { return Poll::Ready(None); }
            state.waker = Some(task.waker().clone());
            if !state.reported {
                state.reported = true;
                self.gate.events.send(Event::Parked(self.cx.clone())).unwrap();
            }
            Poll::Pending
        }
    }

    impl Drop for GateBody {
        fn drop(&mut self) {
            let _ = self.gate.events.send(Event::Dropped {
                cancelled: self.cx.is_cancel_requested(), polls: self.gate.polls.load(Ordering::SeqCst),
            });
        }
    }

    fn runtime(workers: usize) -> Runtime {
        RuntimeBuilder::new().worker_threads(workers).with_sharded_state(workers == 2)
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap()).build().unwrap()
    }

    fn drained(runtime: Runtime) {
        let report = runtime.shutdown_drained(Duration::from_secs(5));
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
        assert_eq!(report.live_tasks, 0);
        assert_eq!(report.pending_spawns, 0);
        assert_eq!(report.pending_obligations, 0);
    }

    fn config() -> StreamingCompressionConfig {
        StreamingCompressionConfig::new(limits(100, 1000, 7)).with_min_body_size(0)
            .with_codings(vec![ContentCoding::Gzip, ContentCoding::Identity])
    }

    fn source(gate: Arc<Gate>, cx: Cx, compression: StreamingCompression) -> (Response, ContentEncodedBody<GateBody>) {
        compression.encode_response(
            Response::empty(StatusCode::OK).header("content-type", "text/plain")
                .header("etag", "\"plain\"").header("digest", "stale").header("trailer", "x-finished"),
            GateBody { gate, cx }, config(),
        ).unwrap()
    }

    fn socket(address: SocketAddr) -> TcpStream {
        let socket = TcpStream::connect(address).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        socket
    }

    fn h1_head(reader: &mut io::BufReader<TcpStream>) -> String {
        let mut head = String::new();
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0, "complete response head");
            head.push_str(&line);
            if line == "\r\n" { return head.to_ascii_lowercase(); }
        }
    }

    fn h1_chunk(reader: &mut io::BufReader<TcpStream>) -> Option<Vec<u8>> {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).unwrap() > 0, "chunk length before successful EOF");
        let length = usize::from_str_radix(line.trim(), 16).unwrap();
        if length == 0 { return None; }
        let mut data = vec![0; length];
        reader.read_exact(&mut data).unwrap();
        let mut crlf = [0; 2];
        reader.read_exact(&mut crlf).unwrap();
        assert_eq!(&crlf, b"\r\n");
        Some(data)
    }

    #[test]
    fn h1_live_compressed_body_precedes_eof_and_cancellation_drains_without_terminator() {
        for workers in [1, 2] {
            for cancel in [false, true] {
                let runtime = runtime(workers);
                let (gate, events) = Gate::new();
                let route_gate = Arc::clone(&gate);
                let router = Router::new().without_default_trace().route("/stream", get(AsyncCxFnHandler2::new(
                    move |cx: Cx, responder: Http1StreamResponder, compression: StreamingCompression| {
                        let gate = Arc::clone(&route_gate);
                        async move {
                            let (head, body) = source(gate, cx, compression);
                            responder.body(head, NonZeroUsize::MIN, NonZeroUsize::new(5).unwrap(), body)
                        }
                    },
                )));
                let listener = runtime.block_on(Http1Listener::bind_produced_with_config(
                    "127.0.0.1:0", router.into_http1_produced_handler(),
                    Http1ListenerConfig::default().http_config(Http1Config::default()
                        .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))),
                )).unwrap();
                let address = listener.local_addr().unwrap();
                let manager = listener.connection_manager().clone();
                let in_flight = listener.in_flight_requests();
                let run = runtime.handle().spawn(async move {
                    let root = Cx::current().unwrap();
                    let mut owner = root.spawn(move |cx| async move { listener.run_produced_owned_in(&cx).await }).unwrap();
                    owner.join(&root).await.unwrap()
                });
                let mut peer = socket(address);
                peer.write_all(b"GET /stream HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n").unwrap();
                let mut reader = io::BufReader::new(peer);
                let head = h1_head(&mut reader);
                assert!(head.starts_with("http/1.1 200"), "{head}");
                assert!(head.contains("content-encoding: gzip\r\n"));
                assert!(head.contains("transfer-encoding: chunked\r\n"));
                assert!(head.contains("etag: w/\"plain\"\r\n"));
                assert!(!head.contains("content-length:"));
                assert!(!head.contains("digest:"));
                let mut decoder = GzipDecompressor::new(DecompressionLimit::new(100));
                let mut decoded = Vec::new();
                while decoded.len() < 5 {
                    let bytes = h1_chunk(&mut reader).expect("progressive compressed chunk");
                    assert!(bytes.len() <= 5, "Body bridge splits source DATA at the queue ceiling");
                    decoder.decompress(&bytes, &mut decoded).unwrap();
                }
                assert_eq!(decoded, b"hello");
                let Event::Parked(cx) = events.recv_timeout(Duration::from_secs(5)).unwrap() else { panic!("source must park before EOF"); };
                assert_eq!(in_flight.load(Ordering::SeqCst), 1);
                if cancel {
                    cx.cancel_fast(CancelKind::User);
                    let mut rest = Vec::new();
                    reader.read_to_end(&mut rest).unwrap();
                    assert!(!rest.windows(5).any(|window| window == b"0\r\n\r\n"));
                    assert!(!rest.windows(11).any(|window| window == b"x-finished:"));
                    assert!(decoder.finish(&mut decoded).is_err(), "cancelled gzip never certifies its footer");
                } else {
                    gate.finish();
                    while let Some(bytes) = h1_chunk(&mut reader) { decoder.decompress(&bytes, &mut decoded).unwrap(); }
                    decoder.finish(&mut decoded).unwrap();
                    assert_eq!(decoded, b"hello world");
                    let mut trailers = String::new();
                    reader.read_to_string(&mut trailers).unwrap();
                    assert_eq!(trailers.to_ascii_lowercase(), "x-finished: yes\r\n\r\n");
                }
                let Event::Dropped { cancelled, polls } = events.recv_timeout(Duration::from_secs(5)).unwrap() else { panic!("source drops before drain"); };
                assert_eq!(cancelled, cancel);
                assert!(polls >= 2);
                assert!(manager.begin_drain(Duration::from_secs(2)));
                assert!(runtime.block_on(run).unwrap().drain_report.unwrap().reached_quiescence);
                assert_eq!(in_flight.load(Ordering::SeqCst), 0);
                assert_eq!(manager.active_count(), 0);
                drained(runtime);
            }
        }
    }

    #[test]
    fn h1_identity_preserves_exact_length_and_head_never_polls_its_source() {
        let runtime = runtime(2);
        let (gate, events) = Gate::new();
        let router = Router::new().without_default_trace()
            .route("/identity", get(AsyncCxFnHandler1::new(|_cx: Cx, responder: Http1StreamResponder| async move {
                responder.body(
                    Response::empty(StatusCode::OK).header("content-length", "5"),
                    NonZeroUsize::MIN, NonZeroUsize::new(2).unwrap(), Bytes::from_static(b"hello"),
                )
            })))
            .route("/head", get(AsyncCxFnHandler1::new(move |cx: Cx, responder: Http1StreamResponder| {
                let gate = Arc::clone(&gate);
                async move {
                    responder.body(
                        Response::empty(StatusCode::OK).header("content-length", "1234"),
                        NonZeroUsize::MIN, NonZeroUsize::new(2).unwrap(), GateBody { gate, cx },
                    )
                }
            })));
        let listener = runtime.block_on(Http1Listener::bind_produced_with_config(
            "127.0.0.1:0", router.into_http1_produced_handler(),
            Http1ListenerConfig::default().http_config(Http1Config::default()
                .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))),
        )).unwrap();
        let address = listener.local_addr().unwrap();
        let manager = listener.connection_manager().clone();
        let in_flight = listener.in_flight_requests();
        let run = runtime.handle().spawn(async move {
            let root = Cx::current().unwrap();
            let mut owner = root.spawn(move |cx| async move { listener.run_produced_owned_in(&cx).await }).unwrap();
            owner.join(&root).await.unwrap()
        });
        for (method, path, length, expected) in [("GET", "/identity", "5", b"hello".as_slice()), ("HEAD", "/head", "1234", b"".as_slice())] {
            let mut peer = socket(address);
            peer.write_all(format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
            let mut reader = io::BufReader::new(peer);
            let head = h1_head(&mut reader);
            assert!(head.starts_with("http/1.1 200"), "{head}");
            assert!(head.contains(&format!("content-length: {length}\r\n")), "{head}");
            assert!(!head.contains("transfer-encoding:"));
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, expected);
        }
        let Event::Dropped { polls, .. } = events.recv_timeout(Duration::from_secs(5)).unwrap() else { panic!("HEAD body must never park or produce"); };
        assert_eq!(polls, 0);
        assert!(manager.begin_drain(Duration::from_secs(2)));
        assert!(runtime.block_on(run).unwrap().drain_report.unwrap().reached_quiescence);
        assert_eq!(in_flight.load(Ordering::SeqCst), 0);
        assert_eq!(manager.active_count(), 0);
        drained(runtime);
    }

    struct H2Peer {
        socket: TcpStream,
        codec: FrameCodec,
        buffered: BytesMut,
        encoder: HpackEncoder,
        decoder: HpackDecoder,
    }

    impl H2Peer {
        fn connect(address: SocketAddr) -> Self {
            let mut socket = socket(address);
            socket.write_all(CLIENT_PREFACE).unwrap();
            let mut peer = Self { socket, codec: FrameCodec::new(), buffered: BytesMut::new(), encoder: HpackEncoder::new(), decoder: HpackDecoder::new() };
            peer.send(H2Frame::Settings(SettingsFrame::new(Vec::new())));
            peer
        }

        fn send(&mut self, frame: H2Frame) {
            let mut wire = BytesMut::new();
            frame.encode(&mut wire).unwrap();
            self.socket.write_all(&wire).unwrap();
        }

        fn request(&mut self, stream: u32, path: &str) {
            let mut block = BytesMut::new();
            self.encoder.encode(&[
                Header::new(":method", "GET"), Header::new(":scheme", "http"),
                Header::new(":authority", "localhost"), Header::new(":path", path),
                Header::new("accept-encoding", "gzip"),
            ], &mut block);
            self.send(H2Frame::Headers(HeadersFrame::new(stream, block.freeze(), true, true)));
        }

        fn receive(&mut self) -> H2Frame {
            loop {
                if let Some(frame) = self.codec.decode(&mut self.buffered).unwrap() {
                    match frame {
                        H2Frame::Settings(settings) if !settings.ack => self.send(H2Frame::Settings(SettingsFrame::ack())),
                        H2Frame::Settings(_) | H2Frame::WindowUpdate(_) => {},
                        other => return other,
                    }
                } else {
                    let mut bytes = [0; 4096];
                    let count = self.socket.read(&mut bytes).unwrap();
                    assert!(count > 0, "H2 connection closed before expected frame");
                    self.buffered.extend_from_slice(&bytes[..count]);
                }
            }
        }

        fn headers(&mut self, frame: HeadersFrame) -> Vec<Header> {
            assert!(frame.end_headers, "small test field blocks fit one HEADERS frame");
            self.decoder.decode(&mut frame.header_block.clone()).unwrap()
        }
    }

    #[test]
    fn h2_live_compressed_body_finishes_before_trailers_and_reset_releases_only_its_stream() {
        for workers in [1, 2] {
            for reset in [false, true] {
                let runtime = runtime(workers);
                let (gate, events) = Gate::new();
                let route_gate = Arc::clone(&gate);
                let router = Router::new().without_default_trace()
                    .route("/stream", get(AsyncCxFnHandler2::new(
                        move |cx: Cx, responder: Http2StreamResponder, compression: StreamingCompression| {
                            let gate = Arc::clone(&route_gate);
                            async move {
                                let (head, body) = source(gate, cx, compression);
                                responder.body(head, NonZeroUsize::MIN, NonZeroUsize::new(5).unwrap(), body)
                            }
                        },
                    )))
                    .route("/ok", get(FnHandler::new(|| "ok")));
                let listener = runtime.block_on(Http2Listener::bind_produced_with_config(
                    "127.0.0.1:0", router.into_http2_produced_handler(),
                    Http2ListenerConfig::default().host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
                        .drain_timeout(Duration::from_secs(2)).hard_drain_timeout(Duration::from_secs(5)),
                )).unwrap();
                let address = listener.local_addr().unwrap();
                let manager = listener.connection_manager().clone();
                let in_flight = listener.in_flight_requests();
                let handle = runtime.handle();
                let serving: Pin<Box<dyn std::future::Future<Output = _> + Send>> = Box::pin(async move { listener.run_produced_owned(&handle).await });
                let run = runtime.handle().spawn(serving);
                let mut peer = H2Peer::connect(address);
                peer.request(1, "/stream");
                let mut decoder = GzipDecompressor::new(DecompressionLimit::new(100));
                let mut decoded = Vec::new();
                let mut saw_head = false;
                while decoded.len() < 5 {
                    match peer.receive() {
                        H2Frame::Headers(head) if head.stream_id == 1 => {
                            assert!(!head.end_stream);
                            let fields = peer.headers(head);
                            assert!(fields.iter().any(|field| field.name == "content-encoding" && field.value == "gzip"));
                            assert!(!fields.iter().any(|field| matches!(field.name.as_str(), "content-length" | "transfer-encoding" | "digest")));
                            saw_head = true;
                        }
                        H2Frame::Data(frame) if frame.stream_id == 1 => {
                            assert!(saw_head);
                            assert!(!frame.end_stream);
                            assert!(frame.data.len() <= 5);
                            decoder.decompress(&frame.data, &mut decoded).unwrap();
                        }
                        other => panic!("unexpected progressive H2 response: {other:?}"),
                    }
                }
                assert_eq!(decoded, b"hello");
                let Event::Parked(_) = events.recv_timeout(Duration::from_secs(5)).unwrap() else { panic!("live source must park"); };
                assert_eq!(in_flight.load(Ordering::SeqCst), 1);
                if reset {
                    peer.send(H2Frame::RstStream(RstStreamFrame::new(1, ErrorCode::Cancel)));
                } else {
                    gate.finish();
                    loop {
                        match peer.receive() {
                            H2Frame::Data(frame) if frame.stream_id == 1 => {
                                assert!(!frame.end_stream, "terminal trailer owns END_STREAM");
                                decoder.decompress(&frame.data, &mut decoded).unwrap();
                            }
                            H2Frame::Headers(frame) if frame.stream_id == 1 => {
                                assert!(frame.end_stream);
                                decoder.finish(&mut decoded).unwrap();
                                assert_eq!(decoded, b"hello world");
                                let trailers = peer.headers(frame);
                                assert_eq!(trailers, vec![Header::new("x-finished", "yes")]);
                                break;
                            }
                            other => panic!("unexpected final H2 response: {other:?}"),
                        }
                    }
                }
                let Event::Dropped { cancelled, polls } = events.recv_timeout(Duration::from_secs(5)).unwrap() else { panic!("source drops after completion/reset"); };
                assert_eq!(cancelled, reset);
                assert!(polls >= 2);
                // Reuse the same connection after both normal completion and
                // targeted reset. HPACK state must also remain synchronized.
                peer.request(3, "/ok");
                let mut response = Vec::new();
                loop {
                    match peer.receive() {
                        H2Frame::Headers(frame) if frame.stream_id == 3 => {
                            let end = frame.end_stream;
                            let headers = peer.headers(frame);
                            assert!(headers.iter().any(|field| field.name == ":status" && field.value == "200"));
                            if end { break; }
                        }
                        H2Frame::Data(frame) if frame.stream_id == 3 => {
                            response.extend_from_slice(&frame.data);
                            if frame.end_stream { break; }
                        }
                        H2Frame::Data(frame) if frame.stream_id == 1 && reset => assert!(!frame.end_stream),
                        H2Frame::RstStream(frame) if frame.stream_id == 1 && reset => {},
                        other => panic!("unrelated request failed after streamed response: {other:?}"),
                    }
                }
                assert_eq!(response, b"ok");
                drop(peer);
                assert!(manager.begin_drain(Duration::from_secs(2)));
                assert!(runtime.block_on(run).unwrap().drain_report.unwrap().reached_quiescence);
                assert_eq!(in_flight.load(Ordering::SeqCst), 0);
                assert_eq!(manager.active_count(), 0);
                drained(runtime);
            }
        }
    }
}
