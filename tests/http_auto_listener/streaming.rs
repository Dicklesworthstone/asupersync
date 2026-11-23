//! Shared-port streaming journeys through real TCP/TLS and owned request regions.

use super::*;
use asupersync::bytes::{Buf, Bytes};
use asupersync::channel::oneshot;
use asupersync::http::HttpAutoStreamingListener;
use asupersync::http::body::{Body, Frame as BodyFrame, HeaderMap, HeaderName, HeaderValue};
use asupersync::http::h1::codec::HttpError;
use asupersync::http::h1::server::Http1StreamingConfig;
use asupersync::http::h1::stream::{Http1ProducedResponse, StreamingServerRequest};
use asupersync::http::h2::HpackDecoder;
use asupersync::http::h2::frame::DataFrame;
use asupersync::http::h2::listener::{Http2ProducedResponse, Http2StreamingListenerConfig};
use asupersync::io::{AsyncRead, AsyncWrite};
use std::future::poll_fn;
use std::pin::Pin;

type Observations = Arc<Mutex<Vec<(u8, RegionId, TaskId)>>>;

fn nz(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap()
}

fn trailers() -> HeaderMap {
    let mut map = HeaderMap::new();
    map.insert(
        HeaderName::from_static("x-complete"),
        HeaderValue::from_static("yes"),
    );
    map
}

struct Retired(Option<Arc<AtomicUsize>>);

impl Drop for Retired {
    fn drop(&mut self) {
        if let Some(count) = &self.0 {
            count.fetch_add(1, Ordering::SeqCst);
        }
    }
}

async fn h1_echo(
    cx: Cx,
    request: StreamingServerRequest,
    mut parked: Option<oneshot::Sender<Cx>>,
    retired: Option<Arc<AtomicUsize>>,
) -> Http1ProducedResponse {
    assert_eq!(Cx::current().unwrap().task_id(), cx.task_id());
    Http1ProducedResponse::chunked_with_max_frame_bytes(
        nz(1),
        nz(3),
        200,
        "OK",
        move |producer, mut sender| async move {
            let _retired = Retired(retired);
            assert_eq!(producer.task_id(), cx.task_id());
            assert_eq!(producer.region_id(), cx.region_id());
            let mut body = request.body;
            let mut progressed = false;
            loop {
                let frame = poll_fn(|task| {
                    let frame = Pin::new(&mut body).poll_frame(task);
                    if frame.is_pending()
                        && progressed
                        && let Some(parked) = parked.take()
                    {
                        parked.send_blocking(producer.clone()).unwrap();
                    }
                    frame
                })
                .await;
                let Some(frame) = frame else { break };
                match frame.map_err(|_| HttpError::BodyCancelled)? {
                    BodyFrame::Data(data) => {
                        for chunk in data.chunk().chunks(3) {
                            sender.send_chunk(&producer, chunk).await?;
                        }
                        progressed = true;
                    }
                    BodyFrame::Trailers(_) => panic!("unexpected request trailers"),
                }
            }
            sender.send_trailers(&producer, trailers()).await?;
            Ok(sender)
        },
    )
    .with_header("Trailer", "x-complete")
}

async fn h2_echo(
    request: StreamingServerRequest,
    mut parked: Option<oneshot::Sender<Cx>>,
    retired: Option<Arc<AtomicUsize>>,
) -> Http2ProducedResponse {
    let handler = Cx::current().unwrap();
    Http2ProducedResponse::streaming(
        Response::new(200, "OK", Vec::new()),
        nz(1),
        nz(3),
        move |producer, mut sender| async move {
            let _retired = Retired(retired);
            assert_eq!(producer.task_id(), handler.task_id());
            assert_eq!(producer.region_id(), handler.region_id());
            let mut body = request.body;
            let mut progressed = false;
            loop {
                let frame = poll_fn(|task| {
                    let frame = Pin::new(&mut body).poll_frame(task);
                    if frame.is_pending()
                        && progressed
                        && let Some(parked) = parked.take()
                    {
                        parked.send_blocking(producer.clone()).unwrap();
                    }
                    frame
                })
                .await;
                let Some(frame) = frame else { break };
                match frame.map_err(|_| HttpError::BodyCancelled)? {
                    BodyFrame::Data(data) => {
                        for chunk in data.chunk().chunks(3) {
                            sender.send_chunk(&producer, chunk).await?;
                        }
                        progressed = true;
                    }
                    BodyFrame::Trailers(_) => panic!("unexpected request trailers"),
                }
            }
            sender.send_trailers(&producer, trailers()).await?;
            Ok(sender)
        },
    )
}

async fn h1_handler(cx: Cx, request: StreamingServerRequest) -> Http1ProducedResponse {
    h1_echo(cx, request, None, None).await
}

async fn h2_handler(request: StreamingServerRequest) -> Http2ProducedResponse {
    h2_echo(request, None, None).await
}

fn h1_config() -> Http1StreamingConfig {
    Http1StreamingConfig::from(config().http1.http_config).incoming_body_queue(1, 64)
}

async fn read_until<S: AsyncRead + Unpin>(stream: &mut S, marker: &[u8]) -> Vec<u8> {
    bounded(async {
        let mut bytes = Vec::new();
        while !bytes.windows(marker.len()).any(|window| window == marker) {
            let mut part = [0u8; 1024];
            let count = stream.read(&mut part).await.unwrap();
            assert_ne!(count, 0, "peer closed before the expected response bytes");
            bytes.extend_from_slice(&part[..count]);
            assert!(
                bytes.len() <= 16 * 1024,
                "fixture response exceeded its bound"
            );
        }
        bytes
    })
    .await
}

struct WireH1<S> {
    stream: S,
    input: Vec<u8>,
    body: Vec<u8>,
    trailers: Vec<(String, String)>,
    done: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WireH1<S> {
    async fn new(mut stream: S) -> Self {
        bounded(stream.write_all(
            b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9\r\nConnection: close\r\n\r\none",
        ))
        .await
        .unwrap();
        let mut bytes = read_until(&mut stream, b"\r\n\r\n").await;
        let end = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let input = bytes.split_off(end);
        let head = String::from_utf8(bytes).unwrap();
        assert!(head.starts_with("HTTP/1.1 200 "));
        assert!(
            head.to_ascii_lowercase()
                .contains("transfer-encoding: chunked")
        );
        Self {
            stream,
            input,
            body: Vec::new(),
            trailers: Vec::new(),
            done: false,
        }
    }

    async fn read_more(&mut self) {
        let mut bytes = [0u8; 1024];
        let count = bounded(self.stream.read(&mut bytes)).await.unwrap();
        assert_ne!(count, 0, "HTTP/1 peer closed before complete chunk framing");
        self.input.extend_from_slice(&bytes[..count]);
        assert!(self.input.len() <= 16 * 1024);
    }

    async fn line(&mut self) -> String {
        loop {
            if let Some(end) = self.input.windows(2).position(|w| w == b"\r\n") {
                let bytes: Vec<_> = self.input.drain(..end + 2).collect();
                return String::from_utf8(bytes[..end].to_vec()).unwrap();
            }
            self.read_more().await;
        }
    }

    async fn chunk(&mut self) -> Option<()> {
        assert!(!self.done);
        let line = self.line().await;
        let size = usize::from_str_radix(&line, 16).expect("valid server chunk length");
        assert!(size <= 4096, "fixture chunk exceeded its independent bound");
        if size == 0 {
            loop {
                let line = self.line().await;
                if line.is_empty() {
                    break;
                }
                let (name, value) = line.split_once(':').expect("valid response trailer");
                self.trailers
                    .push((name.to_ascii_lowercase(), value.trim().to_owned()));
                assert!(self.trailers.len() <= 8);
            }
            self.done = true;
            return None;
        }
        while self.input.len() < size + 2 {
            self.read_more().await;
        }
        self.body.extend(self.input.drain(..size));
        assert_eq!(&self.input[..2], b"\r\n");
        drop(self.input.drain(..2));
        assert!(self.body.len() <= 9);
        Some(())
    }

    async fn prefix(&mut self) {
        while self.body.len() < 3 {
            assert!(
                self.chunk().await.is_some(),
                "response ended before the upload suffix"
            );
        }
        assert_eq!(self.body, b"one");
        assert!(!self.done);
    }

    async fn finish_echo(&mut self) {
        // No TCP segmentation or producer chunk-boundary assumption is needed.
        // The suffix is withheld until the decoded response prefix is visible.
        bounded(self.stream.write_all(b"twothr")).await.unwrap();
        while self.chunk().await.is_some() {}
        assert_eq!(self.body, b"onetwothr");
        assert_eq!(
            self.trailers,
            vec![("x-complete".to_owned(), "yes".to_owned())]
        );
        let mut rest = Vec::new();
        bounded(self.stream.read_to_end(&mut rest)).await.unwrap();
        assert!(self.input.is_empty() && rest.is_empty());
    }
}

async fn h1_exchange<S: AsyncRead + AsyncWrite + Unpin>(stream: S) {
    let mut peer = WireH1::new(stream).await;
    peer.prefix().await;
    peer.finish_echo().await;
}

struct WireH2<S> {
    stream: S,
    codec: FrameCodec,
    input: BytesMut,
    decoder: HpackDecoder,
    secure: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WireH2<S> {
    async fn new(stream: S, secure: bool) -> Self {
        let mut peer = Self {
            stream,
            codec: FrameCodec::new(),
            input: BytesMut::new(),
            decoder: HpackDecoder::new(),
            secure,
        };
        bounded(peer.stream.write_all(CLIENT_PREFACE))
            .await
            .unwrap();
        peer.send(Frame::Settings(SettingsFrame::new(Vec::new())))
            .await;
        loop {
            if let Frame::Settings(settings) = bounded(peer.next()).await.unwrap()
                && !settings.ack
            {
                peer.send(Frame::Settings(SettingsFrame::ack())).await;
                return peer;
            }
        }
    }

    async fn send(&mut self, frame: Frame) {
        let mut bytes = BytesMut::new();
        frame.encode(&mut bytes).unwrap();
        bounded(self.stream.write_all(&bytes)).await.unwrap();
    }

    async fn post(&mut self, path: &str) {
        let mut block = BytesMut::new();
        HpackEncoder::new().encode(
            &[
                Header::new(":method", "POST"),
                Header::new(":scheme", if self.secure { "https" } else { "http" }),
                Header::new(":authority", "localhost"),
                Header::new(":path", path),
                Header::new("content-length", "9"),
            ],
            &mut block,
        );
        self.send(Frame::Headers(HeadersFrame::new(
            1,
            block.freeze(),
            false,
            true,
        )))
        .await;
    }

    async fn next(&mut self) -> Option<Frame> {
        loop {
            if let Some(frame) = self.codec.decode(&mut self.input).unwrap() {
                return Some(frame);
            }
            let mut bytes = [0u8; 4096];
            match self.stream.read(&mut bytes).await {
                Ok(0) => {
                    assert!(self.input.is_empty(), "HTTP/2 peer closed mid-frame");
                    return None;
                }
                Ok(count) => self.input.extend_from_slice(&bytes[..count]),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => return None,
                Err(error) => panic!("read HTTP/2 frame: {error}"),
            }
        }
    }

    async fn next_for(&mut self) -> Frame {
        bounded(async {
            loop {
                let frame = self.next().await.expect("HTTP/2 connection remains live");
                assert!(!matches!(frame, Frame::GoAway(_)), "{frame:?}");
                if frame.stream_id() == 1 {
                    return frame;
                }
            }
        })
        .await
    }

    fn headers(&mut self, mut frame: HeadersFrame) -> Vec<Header> {
        assert!(frame.end_headers, "tiny fixture headers fit one frame");
        self.decoder.decode(&mut frame.header_block).unwrap()
    }

    async fn prefix(&mut self) {
        self.post("/echo").await;
        self.send(Frame::Data(DataFrame::new(
            1,
            Bytes::from_static(b"one"),
            false,
        )))
        .await;
        let mut body = Vec::new();
        let mut head = false;
        while body.len() < 3 {
            match self.next_for().await {
                Frame::Headers(frame) => {
                    assert!(!frame.end_stream && !head);
                    let headers = self.headers(frame);
                    assert!(
                        headers
                            .iter()
                            .any(|h| h.name == ":status" && h.value == "200")
                    );
                    head = true;
                }
                Frame::Data(frame) => {
                    assert!(head && !frame.end_stream);
                    body.extend_from_slice(&frame.data);
                }
                Frame::RstStream(frame) => panic!("duplex upload was reset: {frame:?}"),
                _ => {}
            }
        }
        assert_eq!(
            body, b"one",
            "response must progress before upload END_STREAM"
        );
    }

    async fn finish_echo(&mut self) {
        self.send(Frame::Data(DataFrame::new(
            1,
            Bytes::from_static(b"twothr"),
            true,
        )))
        .await;
        let mut body = Vec::new();
        loop {
            match self.next_for().await {
                Frame::Data(frame) => {
                    assert!(!frame.end_stream, "trailers carry the terminal frame");
                    body.extend_from_slice(&frame.data);
                }
                Frame::Headers(frame) => {
                    assert!(
                        frame.end_stream,
                        "successful completion includes terminal trailers"
                    );
                    let headers = self.headers(frame);
                    assert!(
                        headers
                            .iter()
                            .any(|h| h.name == "x-complete" && h.value == "yes")
                    );
                    break;
                }
                Frame::RstStream(frame) => panic!("response was reset: {frame:?}"),
                _ => {}
            }
        }
        assert_eq!(body, b"twothr");
    }
}

async fn h2_exchange<S: AsyncRead + AsyncWrite + Unpin>(stream: S, secure: bool) {
    let mut peer = WireH2::new(stream, secure).await;
    peer.prefix().await;
    peer.finish_echo().await;
}

mod shared_streaming_body_budget {
    use super::*;
    use asupersync::http::HttpAutoStreamingListenerStats;
    use asupersync::server::shutdown::ShutdownSignal;

    const H1_RESERVATION: usize = 64 + 256 * 1024 + 16 * 1024;
    const H2_RESERVATION: usize = 2 * 65_535 + 16 * 1024;
    const SHARED_CAPACITY: usize = H1_RESERVATION + H2_RESERVATION;

    struct StopOnDrop(ShutdownSignal);

    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            self.0.trigger_immediate();
        }
    }

    async fn wait_reserved(stats: &HttpAutoStreamingListenerStats, expected: usize) {
        bounded(async {
            while stats.reserved_streaming_request_bytes() != expected {
                yield_now().await;
            }
        })
        .await;
    }

    async fn h1_refusal(address: SocketAddr, path: &str, status: u16) {
        let mut peer = bounded(TcpStream::connect(address)).await.unwrap();
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9\r\nExpect: 100-continue\r\n\r\n"
        );
        bounded(peer.write_all(request.as_bytes())).await.unwrap();
        let response = read_until(&mut peer, b"\r\n\r\n").await;
        assert!(response.starts_with(format!("HTTP/1.1 {status} ").as_bytes()));
        assert!(!response.windows(12).any(|part| part == b"100 Continue"));
        assert!(
            String::from_utf8_lossy(&response)
                .to_ascii_lowercase()
                .contains("connection: close")
        );
        let mut remaining = Vec::new();
        bounded(peer.read_to_end(&mut remaining)).await.unwrap();
    }

    async fn h2_refusal(address: SocketAddr) {
        let peer = bounded(TcpStream::connect(address)).await.unwrap();
        let mut peer = WireH2::new(peer, false).await;
        peer.post("/echo").await;
        match peer.next_for().await {
            Frame::RstStream(frame) => assert_eq!(frame.error_code, ErrorCode::RefusedStream),
            frame => panic!("capacity must refuse the stream before handler entry: {frame:?}"),
        }
    }

    async fn h2_policy_refusal(address: SocketAddr) {
        let peer = bounded(TcpStream::connect(address)).await.unwrap();
        let mut peer = WireH2::new(peer, false).await;
        peer.post("/policy").await;
        match peer.next_for().await {
            Frame::Headers(frame) => {
                let headers = peer.headers(frame);
                assert!(
                    headers
                        .iter()
                        .any(|header| header.name == ":status" && header.value == "403")
                );
            }
            frame => panic!("static policy must precede shared-capacity admission: {frame:?}"),
        }
    }

    #[test]
    fn shared_port_streaming_capacity_spans_protocols_and_is_reusable() {
        for workers in [1, 2] {
            for owned in [false, true] {
                run_lifecycle(
                    native_runtime(workers).build().unwrap(),
                    move |handle| async move {
                        let cx = Cx::current().unwrap();
                        let service = cx
                            .open_child_region(ChildRegionSpec::inherit())
                            .await
                            .unwrap();
                        let calls = Arc::new(AtomicUsize::new(0));
                        let first = Arc::clone(&calls);
                        let second = Arc::clone(&calls);
                        let h1 = h1_config().with_request_body_policy(|head| {
                            if head.uri == "/policy" {
                                Err(Response::new(403, "Forbidden", Vec::new()))
                            } else {
                                Ok(None)
                            }
                        });
                        let mut h2 = Http2StreamingListenerConfig::default()
                            .with_request_body_policy(|head| {
                                if head.uri == "/policy" {
                                    Err(Response::new(403, "Forbidden", Vec::new()))
                                } else {
                                    Ok(None)
                                }
                            });
                        h2.listener = config().http2;
                        h2.connection_request_body_buffer_bytes = nz(3 * H2_RESERVATION);
                        let listener = HttpAutoStreamingListener::bind(
                            "127.0.0.1:0",
                            move |cx, request| {
                                first.fetch_add(1, Ordering::SeqCst);
                                h1_handler(cx, request)
                            },
                            move |request| {
                                second.fetch_add(1, Ordering::SeqCst);
                                h2_handler(request)
                            },
                            config(),
                        )
                        .await
                        .unwrap()
                        .with_http1_streaming_config(h1)
                        .with_http2_streaming_config(h2)
                        .max_streaming_request_bytes(nz(SHARED_CAPACITY));
                        let address = listener.local_addr().unwrap();
                        let shutdown = listener.shutdown_signal();
                        let _stop = StopOnDrop(shutdown.clone());
                        let stats = listener.stats_handle();
                        let owner = service.cx().clone();
                        let serving_handle = handle.clone();
                        let mut run = cx
                            .spawn(move |_| async move {
                                if owned {
                                    listener.run_in(&owner).await
                                } else {
                                    listener.run(&serving_handle).await
                                }
                            })
                            .unwrap();

                        let peer = bounded(TcpStream::connect(address)).await.unwrap();
                        let mut first_h1 = WireH1::new(peer).await;
                        first_h1.prefix().await;
                        assert_eq!(stats.reserved_streaming_request_bytes(), H1_RESERVATION);
                        let peer = bounded(TcpStream::connect(address)).await.unwrap();
                        let mut first_h2 = WireH2::new(peer, false).await;
                        first_h2.prefix().await;
                        assert_eq!(stats.reserved_streaming_request_bytes(), SHARED_CAPACITY);
                        assert_eq!(calls.load(Ordering::SeqCst), 2);

                        // A separate HTTP/2 pool of SHARED_CAPACITY would admit
                        // this peer. Only the HTTP/1 reservation makes it full.
                        h2_refusal(address).await;
                        h1_refusal(address, "/echo", 503).await;
                        assert_eq!(stats.streaming_body_budget_refusals_total(), 2);
                        assert_eq!(calls.load(Ordering::SeqCst), 2);
                        h1_refusal(address, "/policy", 403).await;
                        h2_policy_refusal(address).await;
                        assert_eq!(stats.streaming_body_budget_refusals_total(), 2);
                        assert_eq!(calls.load(Ordering::SeqCst), 2);
                        assert_eq!(stats.reserved_streaming_request_bytes(), SHARED_CAPACITY);

                        // Both original producers must survive overload and
                        // echo their withheld upload suffixes and trailers.
                        first_h1.finish_echo().await;
                        wait_reserved(&stats, H2_RESERVATION).await;
                        let peer = bounded(TcpStream::connect(address)).await.unwrap();
                        let mut second_h2 = WireH2::new(peer, false).await;
                        second_h2.prefix().await;
                        assert_eq!(stats.reserved_streaming_request_bytes(), 2 * H2_RESERVATION);
                        // There is no live HTTP/1 request now. Its refusal must
                        // be caused by capacity occupied by HTTP/2 connections.
                        h1_refusal(address, "/echo", 503).await;
                        assert_eq!(stats.streaming_body_budget_refusals_total(), 3);
                        assert_eq!(calls.load(Ordering::SeqCst), 3);

                        first_h2.finish_echo().await;
                        wait_reserved(&stats, H2_RESERVATION).await;
                        let peer = bounded(TcpStream::connect(address)).await.unwrap();
                        let mut second_h1 = WireH1::new(peer).await;
                        second_h1.prefix().await;
                        assert_eq!(stats.reserved_streaming_request_bytes(), SHARED_CAPACITY);
                        second_h1.finish_echo().await;
                        second_h2.finish_echo().await;
                        wait_reserved(&stats, 0).await;
                        assert_eq!(calls.load(Ordering::SeqCst), 4);
                        assert_eq!(stats.streaming_body_budget_refusals_total(), 3);
                        drop((first_h1, first_h2, second_h1, second_h2));

                        assert!(shutdown.begin_drain(Duration::from_secs(2)));
                        let final_stats = bounded(run.join(&cx)).await.unwrap().unwrap();
                        assert!(final_stats.http1.drain_report.unwrap().reached_quiescence);
                        assert!(final_stats.http2.drain_report.unwrap().reached_quiescence);
                        assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
                        assert_eq!(stats.reserved_streaming_request_bytes(), 0);
                        bounded(service.close()).await.unwrap();
                    },
                );
            }
        }
    }
}

fn assert_ancestry(handle: &RuntimeHandle, expected: RegionId, observed: &Observations) {
    let parents: BTreeMap<_, _> = handle
        .trace_snapshot()
        .unwrap()
        .into_iter()
        .filter_map(|event| match (event.kind, event.data) {
            (
                TraceEventKind::RegionCreated,
                TraceData::Region {
                    region,
                    parent: Some(parent),
                },
            ) => Some((region, parent)),
            _ => None,
        })
        .collect();
    let observed = observed.lock().unwrap();
    assert_eq!(observed.len(), 2);
    assert_eq!(
        observed
            .iter()
            .map(|(protocol, _, _)| *protocol)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([1, 2])
    );
    for (_, mut region, _) in observed.iter().copied() {
        assert_ne!(
            region, expected,
            "each handler needs an actual request region"
        );
        let mut visited = BTreeSet::new();
        while region != expected {
            assert!(visited.insert(region), "cyclic region ancestry");
            region = *parents
                .get(&region)
                .expect("request escaped the service subtree");
        }
    }
}

#[test]
fn shared_port_streams_both_protocols_before_upload_eof() {
    for workers in [1, 2] {
        for owned in [false, true] {
            run_lifecycle(
                native_runtime(workers).build().unwrap(),
                move |handle| async move {
                    let cx = Cx::current().unwrap();
                    let service = cx
                        .open_child_region(ChildRegionSpec::inherit())
                        .await
                        .unwrap();
                    let expected = if owned {
                        service.region_id()
                    } else {
                        cx.region_id()
                    };
                    let observed: Observations = Arc::new(Mutex::new(Vec::new()));
                    let first = Arc::clone(&observed);
                    let second = Arc::clone(&observed);
                    let listener = HttpAutoStreamingListener::bind(
                        "127.0.0.1:0",
                        move |request_cx: Cx, request: StreamingServerRequest| {
                            let observed = Arc::clone(&first);
                            async move {
                                observed.lock().unwrap().push((
                                    1,
                                    request_cx.region_id(),
                                    request_cx.task_id(),
                                ));
                                h1_handler(request_cx, request).await
                            }
                        },
                        move |request: StreamingServerRequest| {
                            let observed = Arc::clone(&second);
                            async move {
                                let current = Cx::current().unwrap();
                                observed.lock().unwrap().push((
                                    2,
                                    current.region_id(),
                                    current.task_id(),
                                ));
                                h2_handler(request).await
                            }
                        },
                        config(),
                    )
                    .await
                    .unwrap()
                    .with_http1_streaming_config(h1_config())
                    .http2_write_progress_timeout(Duration::from_secs(2))
                    .http2_flow_control_progress_timeout(Duration::from_secs(2));
                    let address = listener.local_addr().unwrap();
                    let shutdown = listener.shutdown_signal();
                    let owner = service.cx().clone();
                    let serving_handle = handle.clone();
                    let mut run = cx
                        .spawn(move |_| async move {
                            if owned {
                                listener.run_in(&owner).await
                            } else {
                                listener.run(&serving_handle).await
                            }
                        })
                        .unwrap();
                    let http1 = bounded(TcpStream::connect(address)).await.unwrap();
                    let http2 = bounded(TcpStream::connect(address)).await.unwrap();
                    futures_lite::future::zip(h1_exchange(http1), h2_exchange(http2, false)).await;
                    assert_ancestry(&handle, expected, &observed);
                    assert!(shutdown.begin_drain(Duration::from_secs(2)));
                    let stats = bounded(run.join(&cx)).await.unwrap().unwrap();
                    assert!(stats.http1.drain_report.unwrap().reached_quiescence);
                    assert!(stats.http2.drain_report.unwrap().reached_quiescence);
                    assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
                    bounded(service.close()).await.unwrap();
                },
            );
        }
    }
}

#[test]
fn shared_port_duplex_truncated_upload_never_publishes_successful_completion() {
    for workers in [1, 2] {
        run_lifecycle(
            native_runtime(workers).build().unwrap(),
            |handle| async move {
                let cx = Cx::current().unwrap();
                let retired = Arc::new(AtomicUsize::new(0));
                let observed = Arc::clone(&retired);
                let listener = HttpAutoStreamingListener::bind(
                    "127.0.0.1:0",
                    move |cx, request| h1_echo(cx, request, None, Some(Arc::clone(&observed))),
                    h2_handler,
                    config(),
                )
                .await
                .unwrap()
                .with_http1_streaming_config(h1_config());
                let address = listener.local_addr().unwrap();
                let shutdown = listener.shutdown_signal();
                let body_stats = listener.stats_handle();
                let mut serving = cx
                    .spawn(move |_| async move { listener.run(&handle).await })
                    .unwrap();

                let stream = bounded(TcpStream::connect(address)).await.unwrap();
                let mut peer = WireH1::new(stream).await;
                // Observe an actual response prefix before ending a nine-byte
                // upload after only three bytes. A buffered implementation
                // cannot reach this witness, and an eager terminator would
                // incorrectly report a successful response after it.
                peer.prefix().await;
                bounded(AsyncWriteExt::shutdown(&mut peer.stream))
                    .await
                    .unwrap();
                let mut tail = std::mem::take(&mut peer.input);
                bounded(peer.stream.read_to_end(&mut tail)).await.unwrap();
                assert!(
                    tail.is_empty(),
                    "failed upload published response bytes: {tail:?}"
                );
                assert_eq!(peer.body, b"one");
                assert!(!peer.done);

                assert!(shutdown.begin_drain(Duration::from_secs(2)));
                let stats = bounded(serving.join(&cx)).await.unwrap().unwrap();
                assert!(stats.http1.drain_report.unwrap().reached_quiescence);
                assert!(stats.http2.drain_report.unwrap().reached_quiescence);
                assert_eq!(retired.load(Ordering::SeqCst), 1);
                assert_eq!(body_stats.reserved_streaming_request_bytes(), 0);
            },
        );
    }
}

#[test]
fn shared_port_preserves_both_streaming_admission_policies() {
    for workers in [1, 2] {
        run_lifecycle(
            native_runtime(workers).build().unwrap(),
            |handle| async move {
                let cx = Cx::current().unwrap();
                let calls = Arc::new(AtomicUsize::new(0));
                let first = Arc::clone(&calls);
                let second = Arc::clone(&calls);
                let h1 = h1_config().with_request_body_policy(|_| Ok(Some(3)));
                let mut h2 = Http2StreamingListenerConfig::default()
                    .with_request_body_policy(|_| Ok(Some(3)));
                h2.listener = config().http2;
                let listener = HttpAutoStreamingListener::bind(
                    "127.0.0.1:0",
                    move |cx, request| {
                        first.fetch_add(1, Ordering::SeqCst);
                        h1_handler(cx, request)
                    },
                    move |request| {
                        second.fetch_add(1, Ordering::SeqCst);
                        h2_handler(request)
                    },
                    config(),
                )
                .await
                .unwrap()
                .with_http1_streaming_config(h1)
                .with_http2_streaming_config(h2);
                let address = listener.local_addr().unwrap();
                let shutdown = listener.shutdown_signal();
                let serving_handle = handle.clone();
                let mut run = cx
                    .spawn(move |_| async move { listener.run(&serving_handle).await })
                    .unwrap();
                let mut http1 = bounded(TcpStream::connect(address)).await.unwrap();
                bounded(http1.write_all(
                b"POST /limited HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9\r\nExpect: 100-continue\r\n\r\n",
            )).await.unwrap();
                let mut response = Vec::new();
                bounded(http1.read_to_end(&mut response)).await.unwrap();
                assert!(response.starts_with(b"HTTP/1.1 413 "));
                assert!(!response.windows(12).any(|w| w == b"100 Continue"));
                let stream = bounded(TcpStream::connect(address)).await.unwrap();
                let mut http2 = WireH2::new(stream, false).await;
                http2.post("/limited").await;
                loop {
                    match http2.next_for().await {
                        Frame::Headers(frame) => {
                            let headers = http2.headers(frame);
                            assert!(
                                headers
                                    .iter()
                                    .any(|h| h.name == ":status" && h.value == "413")
                            );
                            break;
                        }
                        Frame::RstStream(frame) => {
                            panic!("policy refusal must have a response: {frame:?}")
                        }
                        _ => {}
                    }
                }
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    0,
                    "head policy runs before handlers"
                );
                drop(http1);
                drop(http2);
                assert!(shutdown.begin_drain(Duration::from_secs(2)));
                let stats = bounded(run.join(&cx)).await.unwrap().unwrap();
                assert!(stats.http1.drain_report.unwrap().reached_quiescence);
                assert!(stats.http2.drain_report.unwrap().reached_quiescence);
            },
        );
    }
}

#[test]
fn cancelling_owned_shared_port_drains_both_parked_body_producers() {
    for workers in [1, 2] {
        run_lifecycle(
            native_runtime(workers).build().unwrap(),
            |handle| async move {
                let cx = Cx::current().unwrap();
                let service = cx
                    .open_child_region(ChildRegionSpec::inherit())
                    .await
                    .unwrap();
                let (first_tx, mut first_rx) = oneshot::channel();
                let (second_tx, mut second_rx) = oneshot::channel();
                let first = Arc::new(Mutex::new(Some(first_tx)));
                let second = Arc::new(Mutex::new(Some(second_tx)));
                let retired = Arc::new(AtomicUsize::new(0));
                let first_retired = Arc::clone(&retired);
                let second_retired = Arc::clone(&retired);
                let listener = HttpAutoStreamingListener::bind(
                    "127.0.0.1:0",
                    move |cx, request| {
                        h1_echo(
                            cx,
                            request,
                            first.lock().unwrap().take(),
                            Some(Arc::clone(&first_retired)),
                        )
                    },
                    move |request| {
                        h2_echo(
                            request,
                            second.lock().unwrap().take(),
                            Some(Arc::clone(&second_retired)),
                        )
                    },
                    config(),
                )
                .await
                .unwrap()
                .with_http1_streaming_config(h1_config());
                let address = listener.local_addr().unwrap();
                let shutdown = listener.shutdown_signal();
                let mut run = service
                    .cx()
                    .spawn(move |owner| async move { listener.run_in(&owner).await })
                    .unwrap();
                let stream = bounded(TcpStream::connect(address)).await.unwrap();
                let mut http1 = WireH1::new(stream).await;
                http1.prefix().await;
                let stream = bounded(TcpStream::connect(address)).await.unwrap();
                let mut http2 = WireH2::new(stream, false).await;
                http2.prefix().await;
                let request1 = bounded(first_rx.recv(&cx)).await.unwrap();
                let request2 = bounded(second_rx.recv(&cx)).await.unwrap();
                assert_ne!(request1.region_id(), service.region_id());
                assert_ne!(request2.region_id(), service.region_id());
                assert_eq!(retired.load(Ordering::SeqCst), 0);
                service
                    .cancel(CancelReason::user("cancel both parked streaming uploads"))
                    .unwrap();
                let stats = bounded(run.join(&cx)).await.unwrap().unwrap();
                assert!(stats.http1.drain_report.unwrap().reached_quiescence);
                assert!(stats.http2.drain_report.unwrap().reached_quiescence);
                bounded(service.close()).await.unwrap();
                assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
                assert_eq!(retired.load(Ordering::SeqCst), 2);
                assert!(!cx.is_cancel_requested());
                assert!(
                    handle
                        .diagnostics()
                        .unwrap()
                        .find_leaked_obligations()
                        .is_empty()
                );
                let mut response = std::mem::take(&mut http1.input);
                let result = bounded(http1.stream.read_to_end(&mut response)).await;
                assert!(
                    result.is_ok()
                        || result.is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset)
                );
                assert!(!response.windows(5).any(|w| w == b"0\r\n\r\n"));
                assert!(!response.windows(11).any(|w| w == b"x-complete:"));
                let mut tail = Vec::new();
                let result = bounded(http2.stream.read_to_end(&mut tail)).await;
                assert!(
                    result.is_ok()
                        || result.is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset)
                );
                http2.input.extend_from_slice(&tail);
                while let Some(frame) = http2.codec.decode(&mut http2.input).unwrap() {
                    match frame {
                        Frame::Data(frame) if frame.stream_id == 1 => assert!(!frame.end_stream),
                        Frame::Headers(frame) if frame.stream_id == 1 => assert!(!frame.end_stream),
                        _ => {}
                    }
                }
                // Forced cancellation may interrupt a control-frame write. An
                // incomplete suffix does not certify successful stream completion.
            },
        );
    }
}

#[test]
fn invalid_shared_port_streaming_reservations_refuse_before_starting() {
    for workers in [1, 2] {
        run_lifecycle(
            native_runtime(workers).build().unwrap(),
            |handle| async move {
                let listener = HttpAutoStreamingListener::bind(
                    "127.0.0.1:0",
                    h1_handler,
                    h2_handler,
                    config(),
                )
                .await
                .unwrap();
                let mut invalid = Http2StreamingListenerConfig::default();
                invalid.listener = config().http2;
                invalid.request_body_buffer_bytes = nz(1);
                let error = listener
                    .with_http2_streaming_config(invalid)
                    .run(&handle)
                    .await
                    .unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            },
        );
    }
}

#[cfg(feature = "tls")]
#[test]
fn tls_alpn_streams_both_protocols_before_upload_eof() {
    use asupersync::tls::{
        Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder, TlsConnectorBuilder,
    };
    const CERT: &[u8] = include_bytes!("../fixtures/tls/server.crt");
    const KEY: &[u8] = include_bytes!("../fixtures/tls/server.key");
    for workers in [1, 2] {
        run_lifecycle(
            native_runtime(workers).build().unwrap(),
            |handle| async move {
                let cx = Cx::current().unwrap();
                let acceptor = TlsAcceptorBuilder::new(
                    CertificateChain::from_pem(CERT).unwrap(),
                    PrivateKey::from_pem(KEY).unwrap(),
                )
                .alpn_protocols(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
                .build()
                .unwrap();
                let root = Certificate::from_pem(CERT)
                    .unwrap()
                    .into_iter()
                    .next()
                    .unwrap();
                let connector = |alpn: &[u8]| {
                    TlsConnectorBuilder::new()
                        .add_root_certificate(&root)
                        .alpn_protocols_required(vec![alpn.to_vec()])
                        .build()
                        .unwrap()
                };
                let h1 = connector(b"http/1.1");
                let h2 = connector(b"h2");
                let listener = HttpAutoStreamingListener::bind(
                    "127.0.0.1:0",
                    h1_handler,
                    h2_handler,
                    config(),
                )
                .await
                .unwrap()
                .with_http1_streaming_config(h1_config())
                .with_tls(acceptor);
                let address = listener.local_addr().unwrap();
                let shutdown = listener.shutdown_signal();
                let serving_handle = handle.clone();
                let mut run = cx
                    .spawn(move |_| async move { listener.run(&serving_handle).await })
                    .unwrap();
                let tcp1 = bounded(TcpStream::connect(address)).await.unwrap();
                let tcp2 = bounded(TcpStream::connect(address)).await.unwrap();
                let tls1 = bounded(h1.connect("localhost", tcp1)).await.unwrap();
                let tls2 = bounded(h2.connect("localhost", tcp2)).await.unwrap();
                assert_eq!(tls1.alpn_protocol(), Some(b"http/1.1".as_slice()));
                assert_eq!(tls2.alpn_protocol(), Some(b"h2".as_slice()));
                futures_lite::future::zip(h1_exchange(tls1), h2_exchange(tls2, true)).await;
                assert!(shutdown.begin_drain(Duration::from_secs(2)));
                let stats = bounded(run.join(&cx)).await.unwrap().unwrap();
                assert!(stats.http1.drain_report.unwrap().reached_quiescence);
                assert!(stats.http2.drain_report.unwrap().reached_quiescence);
            },
        );
    }
}
