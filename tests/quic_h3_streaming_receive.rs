//! Public native session tests using deterministic QUIC packet delivery.
//!
//! These cross real frame encoding, stream reassembly, readiness and session
//! decoding. They deliberately do not claim TLS authentication or live UDP.

#![cfg(all(feature = "http3", not(target_arch = "wasm32")))]
#![allow(missing_docs)]

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use asupersync::Cx;
use asupersync::bytes::Bytes;
use asupersync::http::h3_native::{
    H3ConnectionConfig, H3EndpointRole, H3Frame, H3NativeError, H3PseudoHeaders, H3RequestHead,
    H3Settings, qpack_encode_request_field_section, qpack_encode_trailer_field_section,
};
use asupersync::http::h3_quic::{
    H3_REQUEST_CANCELLED, NativeH3Event, NativeH3Session, NativeH3SessionError,
};
use asupersync::net::quic_core::encode_varint;
use asupersync::net::quic_native::{
    NativeQuicConnectionConfig, QuicConnection, StreamId, establish_loopback, pump_until_idle,
};

const CHUNK: usize = 4;

struct Pair {
    cx: Cx,
    client: QuicConnection,
    server: QuicConnection,
    session: NativeH3Session,
}

impl Pair {
    fn new(streaming: bool, request_limit: u64, frame_limit: usize) -> Self {
        let cx = Cx::for_testing();
        let mut client = QuicConnection::client(NativeQuicConnectionConfig::default());
        let mut server = QuicConnection::server(NativeQuicConnectionConfig::default());
        // The in-memory helper requires an explicit identity witness. This is
        // deterministic protocol testing, not a certificate verification.
        client.record_verified_server_identity();
        establish_loopback(&cx, &mut client, &mut server).expect("establish protocol pair");
        let mut client_session = NativeH3Session::client();
        client_session
            .initialize(&cx, &mut client, H3Settings::default())
            .expect("client SETTINGS");
        let mut session = NativeH3Session::with_config(H3ConnectionConfig {
            endpoint_role: H3EndpointRole::Server,
            max_concurrent_request_streams: Some(request_limit),
            max_frame_payload_size: frame_limit,
            ..H3ConnectionConfig::default()
        });
        if streaming {
            session
                .enable_streaming_receive(NonZeroUsize::new(CHUNK).unwrap())
                .expect("enable streaming");
        }
        session
            .initialize(&cx, &mut server, H3Settings::default())
            .expect("server SETTINGS");
        let mut pair = Self {
            cx,
            client,
            server,
            session,
        };
        pair.deliver();
        assert!(matches!(pair.event(), Some(NativeH3Event::Settings(_))));
        assert_eq!(pair.event(), None);
        pair
    }

    fn deliver(&mut self) {
        pump_until_idle(&self.cx, &mut self.client, &mut self.server, 16_384, 1)
            .expect("deliver client frames");
    }

    fn write(&mut self, id: StreamId, bytes: Vec<u8>, fin: bool) {
        self.client
            .write_stream(&self.cx, id, Bytes::from(bytes), fin)
            .expect("queue stream bytes");
        self.deliver();
    }

    fn start(&mut self, tail: &[u8], fin: bool) -> StreamId {
        let id = self
            .client
            .open_bidi_stream(&self.cx)
            .expect("open request");
        let mut wire = request_head();
        wire.extend_from_slice(tail);
        self.write(id, wire, fin);
        id
    }

    fn event(&mut self) -> Option<NativeH3Event> {
        self.session
            .next_event(&self.cx, &mut self.server)
            .expect("decode event")
    }

    fn read_offset(&self, id: StreamId) -> u64 {
        self.server
            .inner()
            .streams()
            .stream(id)
            .expect("observed stream")
            .read_offset
    }
}

fn request_head() -> Vec<u8> {
    let head = H3RequestHead::new(
        H3PseudoHeaders {
            method: Some("POST".to_string()),
            scheme: Some("https".to_string()),
            authority: Some("example.test".to_string()),
            path: Some("/upload".to_string()),
            ..H3PseudoHeaders::default()
        },
        Vec::new(),
    )
    .expect("valid head");
    let mut wire = Vec::new();
    H3Frame::Headers(qpack_encode_request_field_section(&head).expect("encode field section"))
        .encode(&mut wire)
        .expect("encode HEADERS");
    wire
}

fn partial_data(declared_len: u64, bytes: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    encode_varint(0, &mut wire).expect("DATA type");
    encode_varint(declared_len, &mut wire).expect("DATA length");
    wire.extend_from_slice(bytes);
    wire
}

fn assert_head(event: Option<NativeH3Event>, id: StreamId) {
    assert!(
        matches!(event, Some(NativeH3Event::RequestHeaders { stream_id, .. }) if stream_id == id)
    );
}

fn collect_data_until_pending(pair: &mut Pair, id: StreamId) -> Vec<u8> {
    let mut bytes = Vec::new();
    while let Some(event) = pair.event() {
        match event {
            NativeH3Event::Data {
                stream_id,
                bytes: chunk,
            } => {
                assert_eq!(stream_id, id);
                assert!(chunk.len() <= CHUNK);
                bytes.extend_from_slice(&chunk);
            }
            other => panic!("expected DATA followed by Pending, got {other:?}"),
        }
    }
    bytes
}

#[derive(Default)]
struct CountWake(AtomicUsize);

impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn streaming_data_precedes_frame_completion_and_pause_preserves_sibling_progress() {
    let mut pair = Pair::new(true, 4, 1024);
    let id = pair.start(&partial_data(12, b"abc"), false);
    assert_head(pair.event(), id);
    assert_eq!(collect_data_until_pending(&mut pair, id), b"abc");
    assert!(!pair.server.is_stream_eof(id).unwrap());
    pair.session.pause_request_stream(id).expect("pause upload");
    let paused_at = pair.read_offset(id);
    pair.write(id, b"defghijkl".to_vec(), true);
    let sibling = pair.start(&[], true);
    assert_head(pair.event(), sibling);
    assert_eq!(
        pair.event(),
        Some(NativeH3Event::Finished { stream_id: sibling })
    );
    assert_eq!(pair.event(), None);
    assert_eq!(
        pair.read_offset(id),
        paused_at,
        "paused stream must not replenish read credit"
    );

    let wake = Arc::new(CountWake::default());
    let waker = Waker::from(Arc::clone(&wake));
    let mut task_cx = Context::from_waker(&waker);
    assert!(
        pair.session
            .poll_event(&pair.cx, &mut pair.server, &mut task_cx)
            .is_pending()
    );
    let before_resume = wake.0.load(Ordering::SeqCst);
    assert!(
        pair.session
            .resume_request_stream(id)
            .expect("resume buffered upload")
    );
    assert_eq!(
        wake.0.load(Ordering::SeqCst),
        before_resume + 1,
        "resume must wake without a new packet"
    );

    let mut tail = Vec::new();
    loop {
        match pair.event().expect("retained data or FIN") {
            NativeH3Event::Data { stream_id, bytes } => {
                assert_eq!(stream_id, id);
                assert!(bytes.len() <= CHUNK);
                tail.extend_from_slice(&bytes);
            }
            NativeH3Event::Finished { stream_id } => {
                assert_eq!(stream_id, id);
                break;
            }
            other => panic!("unexpected resumed event {other:?}"),
        }
    }
    assert_eq!(tail, b"defghijkl");
    assert!(pair.server.is_stream_eof(id).unwrap());
    assert!(!pair.session.resume_request_stream(id).unwrap());
    assert_eq!(pair.event(), None);
}

#[test]
fn default_mode_retains_whole_data_frame_events() {
    let mut pair = Pair::new(false, 4, 1024);
    let id = pair.start(&partial_data(8, b"abc"), false);
    assert_head(pair.event(), id);
    assert_eq!(
        pair.event(),
        None,
        "legacy mode waits for a complete wire frame"
    );
    pair.write(id, b"defgh".to_vec(), true);
    assert_eq!(
        pair.event(),
        Some(NativeH3Event::Data {
            stream_id: id,
            bytes: Bytes::from_static(b"abcdefgh"),
        })
    );
    assert_eq!(
        pair.event(),
        Some(NativeH3Event::Finished { stream_id: id })
    );
    assert_eq!(pair.event(), None);
}

#[test]
fn paused_fin_reset_discards_parser_bytes_and_releases_request_slot_once() {
    let mut pair = Pair::new(true, 1, 1024);
    let id = pair.start(&partial_data(8, b"abcdefgh"), true);
    assert_head(pair.event(), id);
    pair.session
        .pause_request_stream(id)
        .expect("pause before first DATA");
    assert_eq!(pair.event(), None);
    let final_size = pair
        .client
        .inner()
        .streams()
        .stream(id)
        .unwrap()
        .send_offset;
    pair.client
        .reset_stream(&pair.cx, id, H3_REQUEST_CANCELLED)
        .expect("peer reset paused FIN");
    pair.deliver();
    assert_eq!(
        pair.event(),
        Some(NativeH3Event::StreamReset {
            stream_id: id,
            error_code: H3_REQUEST_CANCELLED,
            final_size,
        })
    );
    assert!(!pair.session.resume_request_stream(id).unwrap());
    assert_eq!(pair.event(), None, "no DATA or FIN may survive the reset");
    pair.client
        .reset_stream(&pair.cx, id, H3_REQUEST_CANCELLED)
        .expect("duplicate reset");
    pair.deliver();
    assert_eq!(pair.event(), None, "reset is observed exactly once");
    let survivor = pair.start(&[], true);
    assert_head(pair.event(), survivor);
    assert_eq!(
        pair.event(),
        Some(NativeH3Event::Finished {
            stream_id: survivor
        })
    );
}

#[test]
fn streamed_prefix_is_followed_by_truncation_when_fin_cuts_a_data_frame_short() {
    let mut pair = Pair::new(true, 4, 1024);
    let id = pair.start(&partial_data(8, b"abc"), true);
    assert_head(pair.event(), id);
    let mut prefix = Vec::new();
    loop {
        match pair.session.next_event(&pair.cx, &mut pair.server) {
            Ok(Some(NativeH3Event::Data { stream_id, bytes })) => {
                assert_eq!(stream_id, id);
                prefix.extend_from_slice(&bytes);
            }
            Err(NativeH3SessionError::TruncatedStream {
                stream_id,
                buffered_bytes: 0,
            }) => {
                assert_eq!(stream_id, id);
                break;
            }
            other => panic!("expected prefix then truncation, got {other:?}"),
        }
    }
    assert_eq!(prefix, b"abc");
}

#[test]
fn oversize_data_declaration_fails_before_payload_and_data_after_trailers_is_rejected() {
    let mut pair = Pair::new(true, 4, 128);
    let id = pair.start(&partial_data(129, &[]), false);
    assert_head(pair.event(), id);
    assert_eq!(
        pair.session.next_event(&pair.cx, &mut pair.server),
        Err(NativeH3SessionError::Protocol(
            H3NativeError::FrameTooLarge {
                payload_size: 129,
                max_size: 128
            }
        ))
    );

    let mut pair = Pair::new(true, 4, 1024);
    let mut tail = Vec::new();
    H3Frame::Headers(
        qpack_encode_trailer_field_section(&[("x-end".to_string(), "yes".to_string())]).unwrap(),
    )
    .encode(&mut tail)
    .unwrap();
    tail.extend(partial_data(0, &[]));
    let id = pair.start(&tail, true);
    assert_head(pair.event(), id);
    assert!(
        matches!(pair.event(), Some(NativeH3Event::Trailers { stream_id, .. }) if stream_id == id)
    );
    assert!(matches!(
        pair.session.next_event(&pair.cx, &mut pair.server),
        Err(NativeH3SessionError::Protocol(
            H3NativeError::ControlProtocol("DATA not allowed after trailing HEADERS")
        ))
    ));
}

#[test]
fn large_non_data_frames_yield_and_rearm_without_new_transport_input() {
    let mut pair = Pair::new(true, 4, 1024);
    let id = pair.client.open_uni_stream(&pair.cx).unwrap();
    let mut ignored_stream = vec![0x21]; // Unknown unidirectional stream type.
    ignored_stream.extend([0; 512]);
    pair.write(id, ignored_stream, false);
    let wake = Arc::new(CountWake::default());
    let waker = Waker::from(Arc::clone(&wake));
    let mut task_cx = Context::from_waker(&waker);
    assert!(matches!(
        pair.session
            .poll_event(&pair.cx, &mut pair.server, &mut task_cx),
        Poll::Pending
    ));
    assert!(
        wake.0.load(Ordering::SeqCst) > 0,
        "bounded poll must arrange another turn"
    );
    assert!(
        pair.read_offset(id) <= 32 * CHUNK as u64,
        "one poll must bound aggregate reads"
    );
    assert_eq!(pair.event(), None);
    assert_eq!(pair.read_offset(id), 513);
}
