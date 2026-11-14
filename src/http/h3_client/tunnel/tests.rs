use super::*;
use crate::http::h3_native::{
    H3ConnectionConfig, H3PseudoHeaders, qpack_encode_request_field_section,
    qpack_encode_response_field_section, qpack_encode_trailer_field_section,
};
use crate::net::atp::protocol::quic_frames::QuicFrame;
use crate::net::atp::protocol::varint::VarInt;
use crate::net::quic_native::{NativeQuicConnectionConfig, PacketNumberSpace};
use std::task::Waker;

fn request(extended: bool) -> H3RequestHead {
    H3RequestHead::new_with_settings(
        H3PseudoHeaders {
            method: Some("CONNECT".to_owned()),
            authority: Some("origin.example:443".to_owned()),
            protocol: extended.then(|| "websocket".to_owned()),
            scheme: extended.then(|| "https".to_owned()),
            path: extended.then(|| "/socket".to_owned()),
            ..H3PseudoHeaders::default()
        },
        vec![(
            "proxy-authorization".to_owned(),
            "test-credential".to_owned(),
        )],
        true,
    )
    .unwrap()
}

fn fixture(head: H3RequestHead, config: NativeH3ClientConfig) -> (Cx, QuicConnection, TunnelCore) {
    validate_connect(&head, &config).unwrap();
    let cx = Cx::for_testing();
    let mut connection = QuicConnection::client(NativeQuicConnectionConfig::default());
    connection.begin_handshake(&cx).unwrap();
    connection.mark_handshake_keys_available(&cx).unwrap();
    connection.mark_app_keys_available(&cx).unwrap();
    connection.record_verified_server_identity();
    connection.confirm_handshake(&cx).unwrap();
    let mut core = TunnelCore::new(head, config);
    core.initialize(&cx, &mut connection).unwrap();
    (cx, connection, core)
}

fn settings(cx: &Cx, connection: &mut QuicConnection, enable: Option<bool>) {
    let mut wire = vec![0];
    H3Frame::Settings(H3Settings {
        enable_connect_protocol: enable,
        ..H3Settings::default()
    })
    .encode(&mut wire)
    .unwrap();
    connection
        .inner_mut()
        .accept_remote_stream(cx, StreamId(3))
        .unwrap();
    connection
        .inner_mut()
        .receive_stream_bytes(cx, StreamId(3), 0, Bytes::from(wire), false)
        .unwrap();
}

fn receive(
    cx: &Cx,
    connection: &mut QuicConnection,
    offset: &mut u64,
    frames: impl IntoIterator<Item = H3Frame>,
    fin: bool,
) {
    let mut wire = Vec::new();
    for frame in frames {
        frame.encode(&mut wire).unwrap();
    }
    let length = wire.len() as u64;
    connection
        .inner_mut()
        .receive_stream_bytes(cx, StreamId(0), *offset, Bytes::from(wire), fin)
        .unwrap();
    *offset += length;
}

fn response(status: u16, fields: Vec<(String, String)>) -> H3Frame {
    H3Frame::Headers(
        qpack_encode_response_field_section(&H3ResponseHead::new(status, fields).unwrap()).unwrap(),
    )
}

fn poll(
    core: &mut TunnelCore,
    cx: &Cx,
    connection: &mut QuicConnection,
) -> Poll<Result<TunnelProgress, NativeH3TunnelError>> {
    core.poll(cx, connection, &mut Context::from_waker(Waker::noop()), 0)
}

fn drain(cx: &Cx, connection: &mut QuicConnection, wire: &mut Vec<u8>) -> usize {
    let mut fins = 0;
    for frame in connection
        .inner_mut()
        .generate_stream_frames_for(cx, PacketNumberSpace::ApplicationData, StreamId(0), 65_536)
        .unwrap()
    {
        if let QuicFrame::Stream {
            stream_id,
            offset,
            data,
            fin,
        } = frame
        {
            assert_eq!(stream_id.value(), 0);
            assert_eq!(offset.map_or(0, VarInt::value), wire.len() as u64);
            wire.extend_from_slice(&data);
            fins += usize::from(fin);
        }
    }
    fins
}

fn established(config: NativeH3ClientConfig) -> (Cx, QuicConnection, TunnelCore, Vec<u8>, u64) {
    let (cx, mut connection, mut core) = fixture(request(false), config);
    assert!(poll(&mut core, &cx, &mut connection).is_pending());
    let mut wire = Vec::new();
    assert_eq!(drain(&cx, &mut connection, &mut wire), 0);
    let mut offset = 0;
    receive(
        &cx,
        &mut connection,
        &mut offset,
        [response(200, Vec::new())],
        false,
    );
    assert!(matches!(
        poll(&mut core, &cx, &mut connection),
        Poll::Ready(Ok(TunnelProgress::Opened))
    ));
    assert!(matches!(
        poll(&mut core, &cx, &mut connection),
        Poll::Ready(Ok(TunnelProgress::Event(NativeH3TunnelEvent::SendReady)))
    ));
    // The managed adapter marks readiness only when delivering this event.
    core.send_ready = true;
    (cx, connection, core, wire, offset)
}

#[test]
fn connect_preflight_requires_complete_metadata_without_changing_execute() {
    let config = NativeH3ClientConfig::default();
    for extended in [false, true] {
        let head = request(extended);
        validate_connect(&head, &config).unwrap();
        assert!(matches!(
            validate_request_fields(&head, &config),
            Err(NativeH3ClientError::UnsupportedRequest(_))
        ));
        for name in ["content-length", "te", "trailer"] {
            let mut invalid = head.clone();
            invalid.headers.push((name.to_owned(), "0".to_owned()));
            assert!(validate_connect(&invalid, &config).is_err());
        }
    }
    for authority in ["origin.example", "[::1]", "origin.example:"] {
        let mut head = request(false);
        head.pseudo.authority = Some(authority.to_owned());
        assert!(validate_connect(&head, &config).is_err());
    }
    for authority in ["origin.example:443", "[::1]:8443"] {
        let mut head = request(false);
        head.pseudo.authority = Some(authority.to_owned());
        validate_connect(&head, &config).unwrap();
    }
    let mut extended = request(true);
    extended.pseudo.path = None;
    assert!(validate_connect(&extended, &config).is_err());
    extended.pseudo.path = Some("/socket".to_owned());
    extended.pseudo.protocol = Some("bad protocol".to_owned());
    assert!(validate_connect(&extended, &config).is_err());
}

#[test]
fn extended_connect_never_allocates_or_queues_target_before_peer_permission() {
    for enable in [None, Some(false), Some(true)] {
        let head = request(true);
        let (cx, mut connection, mut core) = fixture(head.clone(), Default::default());
        for _ in 0..3 {
            assert!(poll(&mut core, &cx, &mut connection).is_pending());
            assert!(core.writer.is_none());
            assert!(connection.inner().streams().stream(StreamId(0)).is_err());
        }
        settings(&cx, &mut connection, enable);
        let result = poll(&mut core, &cx, &mut connection);
        if enable == Some(true) {
            assert!(result.is_pending());
            assert_eq!(core.stream_id(), Some(StreamId(0)));
            assert!(connection.inner().streams().stream(StreamId(4)).is_err());
            let mut wire = Vec::new();
            assert_eq!(drain(&cx, &mut connection, &mut wire), 0);
            let mut expected = Vec::new();
            H3Frame::Headers(qpack_encode_request_field_section(&head).unwrap())
                .encode(&mut expected)
                .unwrap();
            assert_eq!(
                wire, expected,
                "target and credentials occur once after authorization"
            );
        } else {
            assert!(matches!(
                result,
                Poll::Ready(Err(NativeH3TunnelError::NotNegotiated))
            ));
            assert!(core.writer.is_none());
            assert!(connection.inner().streams().stream(StreamId(0)).is_err());
        }
    }
}

#[test]
fn ordinary_connect_accepts_without_setting_and_counts_protocol_field_budget() {
    let (cx, mut connection, mut core) = fixture(request(false), Default::default());
    assert_eq!(core.stream_id(), Some(StreamId(0)));
    settings(&cx, &mut connection, Some(false));
    assert!(poll(&mut core, &cx, &mut connection).is_pending());
    let head = request(true);
    let without_protocol = head
        .headers
        .iter()
        .map(|(name, value)| name.len() + value.len() + 32)
        .sum::<usize>()
        + [
            (":method", head.pseudo.method.as_deref().unwrap()),
            (":scheme", head.pseudo.scheme.as_deref().unwrap()),
            (":authority", head.pseudo.authority.as_deref().unwrap()),
            (":path", head.pseudo.path.as_deref().unwrap()),
        ]
        .iter()
        .map(|(name, value)| name.len() + value.len() + 32)
        .sum::<usize>();
    assert!(matches!(
        validate_connect(
            &head,
            &NativeH3ClientConfig {
                max_field_section_size: without_protocol,
                ..Default::default()
            }
        ),
        Err(NativeH3TunnelError::Client(
            NativeH3ClientError::LimitExceeded {
                resource: "request fields",
                ..
            }
        ))
    ));
}

#[test]
fn receive_fin_is_independent_and_connect_ignores_response_content_length() {
    let (cx, mut connection, mut core) = fixture(request(false), Default::default());
    assert!(poll(&mut core, &cx, &mut connection).is_pending());
    let mut wire = Vec::new();
    drain(&cx, &mut connection, &mut wire);
    let mut offset = 0;
    receive(
        &cx,
        &mut connection,
        &mut offset,
        [
            response(
                204,
                vec![("content-length".to_owned(), "not-a-body-length".to_owned())],
            ),
            H3Frame::Data(b"peer prefix".to_vec()),
        ],
        true,
    );
    assert!(matches!(
        poll(&mut core, &cx, &mut connection),
        Poll::Ready(Ok(TunnelProgress::Opened))
    ));
    let mut received = Vec::new();
    let mut read_closed = false;
    for _ in 0..8 {
        match poll(&mut core, &cx, &mut connection) {
            Poll::Ready(Ok(TunnelProgress::Event(NativeH3TunnelEvent::SendReady))) => {
                core.send_ready = true
            }
            Poll::Ready(Ok(TunnelProgress::Event(NativeH3TunnelEvent::Data(bytes)))) => {
                received.extend_from_slice(&bytes)
            }
            Poll::Ready(Ok(TunnelProgress::Event(NativeH3TunnelEvent::ReadClosed))) => {
                read_closed = true;
                break;
            }
            Poll::Pending => {}
            _ => panic!("unexpected tunnel progress"),
        }
    }
    assert!(read_closed);
    assert_eq!(received, b"peer prefix");
    assert!(!core.writer.as_ref().unwrap().is_finished());
    assert_eq!(core.queue_data(b"upload after response FIN").unwrap(), 25);
    core.finish_requested = true;
    let mut fins = 0;
    let mut write_closed = false;
    for _ in 0..16 {
        let progress = poll(&mut core, &cx, &mut connection);
        fins += drain(&cx, &mut connection, &mut wire);
        if matches!(
            progress,
            Poll::Ready(Ok(TunnelProgress::Event(NativeH3TunnelEvent::WriteClosed)))
        ) {
            write_closed = true;
            break;
        }
    }
    assert!(write_closed);
    assert_eq!(fins, 1);
    let (head, length) = H3Frame::decode(&wire, &H3ConnectionConfig::default()).unwrap();
    assert!(matches!(head, H3Frame::Headers(_)));
    let (data, length2) = H3Frame::decode(&wire[length..], &H3ConnectionConfig::default()).unwrap();
    assert_eq!(data, H3Frame::Data(b"upload after response FIN".to_vec()));
    assert_eq!(wire.len(), length + length2);
}

#[test]
fn credit_blocked_upload_yields_peer_data_and_resumes_exact_frame_prefix() {
    let (cx, mut connection, mut core, mut wire, mut offset) = established(Default::default());
    let request_length = wire.len();
    let sent = connection
        .inner()
        .streams()
        .stream(StreamId(0))
        .unwrap()
        .send_offset;
    connection
        .inner_mut()
        .constrain_stream_send_limit_for_testing(&cx, StreamId(0), sent)
        .unwrap();
    let consumed = connection.inner().streams().connection_send_limit()
        - connection.inner().streams().connection_send_remaining();
    connection
        .inner_mut()
        .constrain_connection_send_limit_for_testing(&cx, consumed)
        .unwrap();
    let upload = vec![0xa5; 4096];
    assert_eq!(core.queue_data(&upload).unwrap(), upload.len());
    assert_eq!(core.queue_data(b"not consumed").unwrap(), 0);
    core.finish_requested = true;
    receive(
        &cx,
        &mut connection,
        &mut offset,
        [H3Frame::Data(b"grant application credit".to_vec())],
        false,
    );
    assert!(
        matches!(poll(&mut core, &cx, &mut connection), Poll::Ready(Ok(TunnelProgress::Event(NativeH3TunnelEvent::Data(bytes)))) if bytes.as_ref() == b"grant application credit")
    );
    assert!(core.writer.as_ref().unwrap().has_pending_write());
    for _ in 0..3 {
        assert!(poll(&mut core, &cx, &mut connection).is_pending());
        assert_eq!(drain(&cx, &mut connection, &mut wire), 0);
        assert_eq!(wire.len(), request_length);
    }
    let mut fins = 0;
    let mut write_closed = false;
    for _ in 0..512 {
        let stream_limit = connection
            .inner()
            .streams()
            .stream(StreamId(0))
            .unwrap()
            .send_offset
            + 17;
        let connection_limit = connection.inner().streams().connection_send_limit() + 17;
        for frame in [
            QuicFrame::MaxStreamData {
                stream_id: VarInt::from_u64_unchecked(0),
                maximum_stream_data: VarInt::from_u64_unchecked(stream_limit),
            },
            QuicFrame::MaxData {
                maximum_data: VarInt::from_u64_unchecked(connection_limit),
            },
        ] {
            connection
                .inner_mut()
                .process_frame(&cx, &frame, PacketNumberSpace::ApplicationData)
                .unwrap();
        }
        let progress = poll(&mut core, &cx, &mut connection);
        assert!(connection.pending_stream_data_bytes(StreamId(0)) <= 17);
        fins += drain(&cx, &mut connection, &mut wire);
        if matches!(
            progress,
            Poll::Ready(Ok(TunnelProgress::Event(NativeH3TunnelEvent::WriteClosed)))
        ) {
            write_closed = true;
            break;
        }
    }
    assert!(write_closed);
    assert!(!core.read_closed, "local FIN must not stop receiving");
    assert_eq!(fins, 1);
    let (data, length) =
        H3Frame::decode(&wire[request_length..], &H3ConnectionConfig::default()).unwrap();
    assert_eq!(data, H3Frame::Data(upload));
    assert_eq!(
        wire.len(),
        request_length + length,
        "credit retries never repeat a prefix"
    );
}

#[test]
fn send_admission_returns_exact_prefix_and_limits_refuse_without_consuming() {
    let config = NativeH3ClientConfig {
        max_request_body_bytes: IO_CHUNK_BYTES + 3,
        ..Default::default()
    };
    let (cx, mut connection, mut core, mut wire, _) = established(config);
    let input = vec![42; IO_CHUNK_BYTES + 8];
    assert_eq!(core.queue_data(&input).unwrap(), IO_CHUNK_BYTES);
    assert_eq!(core.queue_data(&input[IO_CHUNK_BYTES..]).unwrap(), 0);
    for accepted in [IO_CHUNK_BYTES, IO_CHUNK_BYTES + 3] {
        for _ in 0..8 {
            let progress = poll(&mut core, &cx, &mut connection);
            drain(&cx, &mut connection, &mut wire);
            if matches!(
                progress,
                Poll::Ready(Ok(TunnelProgress::Event(NativeH3TunnelEvent::SendReady)))
            ) {
                core.send_ready = true;
                break;
            }
        }
        assert!(core.send_ready);
        assert_eq!(core.sent_bytes, accepted);
        if accepted == IO_CHUNK_BYTES {
            assert_eq!(core.queue_data(&input[accepted..]).unwrap(), 3);
        }
    }
    assert!(matches!(
        core.queue_data(b"remaining"),
        Err(NativeH3TunnelError::Client(
            NativeH3ClientError::LimitExceeded {
                resource: "tunnel send bytes",
                ..
            }
        ))
    ));
    assert!(
        core.send_ready,
        "a bound refusal does not consume the available slot"
    );
    assert_eq!(core.sent_bytes, IO_CHUNK_BYTES + 3);
    core.finish_requested = true;
    assert!(matches!(
        core.queue_data(b"closed"),
        Err(NativeH3TunnelError::Closed)
    ));
}

#[test]
fn rejected_response_and_trailers_never_become_tunnel_data() {
    for status in [301, 407, 501] {
        let (cx, mut connection, mut core) = fixture(request(false), Default::default());
        let mut offset = 0;
        receive(
            &cx,
            &mut connection,
            &mut offset,
            [response(status, Vec::new())],
            true,
        );
        assert!(
            matches!(poll(&mut core, &cx, &mut connection), Poll::Ready(Err(NativeH3TunnelError::Rejected(actual))) if actual == status)
        );
        assert!(core.response.is_none());
    }
    let (cx, mut connection, mut core, _, mut offset) = established(Default::default());
    let trailer = H3Frame::Headers(
        qpack_encode_trailer_field_section(&[("x-unexpected".to_owned(), "value".to_owned())])
            .unwrap(),
    );
    receive(&cx, &mut connection, &mut offset, [trailer], false);
    assert!(matches!(
        poll(&mut core, &cx, &mut connection),
        Poll::Ready(Err(NativeH3TunnelError::Client(
            NativeH3ClientError::InvalidMessage("CONNECT does not permit trailers")
        )))
    ));
}

#[test]
fn receive_limit_checks_chunk_before_delivery_and_informational_metadata_is_cumulative() {
    let (cx, mut connection, mut core, _, mut offset) = established(NativeH3ClientConfig {
        max_response_body_bytes: 4,
        ..Default::default()
    });
    receive(
        &cx,
        &mut connection,
        &mut offset,
        [H3Frame::Data(b"12345".to_vec())],
        false,
    );
    assert!(matches!(
        poll(&mut core, &cx, &mut connection),
        Poll::Ready(Err(NativeH3TunnelError::Client(
            NativeH3ClientError::LimitExceeded {
                resource: "tunnel receive bytes",
                limit: 4
            }
        )))
    ));
    assert_eq!(core.received_bytes, 0);
    assert!(core.pending_read.is_none());
    let (cx, mut connection, mut core) = fixture(
        request(false),
        NativeH3ClientConfig {
            max_response_header_bytes: 42,
            ..Default::default()
        },
    );
    let mut offset = 0;
    receive(
        &cx,
        &mut connection,
        &mut offset,
        [response(103, Vec::new()), response(200, Vec::new())],
        false,
    );
    assert!(matches!(
        poll(&mut core, &cx, &mut connection),
        Poll::Ready(Err(NativeH3TunnelError::Client(
            NativeH3ClientError::LimitExceeded {
                resource: "response fields",
                limit: 42
            }
        )))
    ));
    assert_eq!(core.informational.len(), 1);
    assert!(core.response.is_none());
}

#[test]
fn peer_stop_sending_terminates_without_reporting_local_half_close() {
    let (cx, mut connection, mut core, _, _) = established(Default::default());
    assert_eq!(core.queue_data(b"pending").unwrap(), 7);
    connection
        .inner_mut()
        .process_frame(
            &cx,
            &QuicFrame::StopSending {
                stream_id: VarInt::from_u64_unchecked(0),
                error_code: VarInt::from_u64_unchecked(H3_REQUEST_CANCELLED),
            },
            PacketNumberSpace::ApplicationData,
        )
        .unwrap();
    assert!(matches!(
        poll(&mut core, &cx, &mut connection),
        Poll::Ready(Err(NativeH3TunnelError::Client(
            NativeH3ClientError::StreamReset {
                error_code: H3_REQUEST_CANCELLED,
                ..
            }
        )))
    ));
    assert!(!core.write_closed);
}

#[test]
fn critical_control_eof_after_receive_fin_still_terminates_open_upload() {
    let (cx, mut connection, mut core, _, mut offset) = established(Default::default());
    settings(&cx, &mut connection, None);
    assert!(poll(&mut core, &cx, &mut connection).is_pending());
    receive(&cx, &mut connection, &mut offset, [], true);
    assert!(matches!(
        poll(&mut core, &cx, &mut connection),
        Poll::Ready(Ok(TunnelProgress::Event(NativeH3TunnelEvent::ReadClosed)))
    ));
    assert!(!core.writer.as_ref().unwrap().is_finished());
    let mut control = vec![0];
    H3Frame::Settings(H3Settings::default())
        .encode(&mut control)
        .unwrap();
    connection
        .inner_mut()
        .receive_stream_bytes(&cx, StreamId(3), control.len() as u64, Bytes::new(), true)
        .unwrap();
    assert!(matches!(
        poll(&mut core, &cx, &mut connection),
        Poll::Ready(Err(NativeH3TunnelError::Client(
            NativeH3ClientError::Session(NativeH3SessionError::CriticalStreamClosed {
                stream_id: StreamId(3),
                ..
            })
        )))
    ));
    assert!(!core.write_closed);
}

fn timed_context(
    now: Time,
    deadline: Option<Time>,
) -> (
    Arc<crate::time::VirtualClock>,
    crate::time::TimerDriverHandle,
    Cx,
) {
    let clock = Arc::new(crate::time::VirtualClock::starting_at(now));
    let timer = crate::time::TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let io =
        crate::runtime::IoDriverHandle::new(Arc::new(crate::runtime::reactor::LabReactor::new()));
    let budget = deadline.map_or(crate::types::Budget::INFINITE, |deadline| {
        crate::types::Budget::INFINITE.with_deadline(deadline)
    });
    let cx = Cx::new_with_drivers(
        crate::types::RegionId::new_for_test(0, 1),
        crate::types::TaskId::new_for_test(0, 0),
        budget,
        None,
        Some(io),
        None,
        Some(timer.clone()),
        None,
    );
    (clock, timer, cx)
}

#[derive(Default)]
struct WakeCount(std::sync::atomic::AtomicUsize);

impl std::task::Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[test]
fn moving_tunnel_back_to_owner_cannot_extend_foreign_pollers_deadline() {
    let (clock, timer, owner) = timed_context(Time::ZERO, None);
    let (_, foreign_timer, foreign) =
        timed_context(Time::from_secs(100), Some(Time::from_secs(103)));
    let mut control = {
        let _current = Cx::set_current(Some(owner.clone()));
        TunnelControl::new(owner.clone())
    };
    let wakes = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut task = Context::from_waker(&waker);
    {
        let _current = Cx::set_current(Some(foreign));
        control.check(Some(&mut task)).unwrap();
        assert!(timer.pending_count() > 0);
        assert!(foreign_timer.pending_count() > 0);
    }
    let _current = Cx::set_current(Some(owner));
    control.check(Some(&mut task)).unwrap();
    assert_eq!(
        foreign_timer.pending_count(),
        0,
        "old poller registrations retire"
    );
    clock.advance_to(Time::from_secs(3));
    assert!(timer.process_timers() > 0);
    assert!(wakes.0.load(std::sync::atomic::Ordering::SeqCst) > 0);
    assert!(matches!(
        control.check(Some(&mut task)),
        Err(NativeH3TunnelError::Client(NativeH3ClientError::TimedOut))
    ));
    drop(control);
    assert_eq!(timer.pending_count(), 0);
}

#[test]
fn owner_cancellation_wakes_a_foreign_poller_and_constructor_restriction_persists() {
    let (_, _, owner) = timed_context(Time::ZERO, None);
    let (_, _, foreign) = timed_context(Time::from_secs(100), None);
    let mut control = {
        let _current = Cx::set_current(Some(owner.clone()));
        TunnelControl::new(owner.clone())
    };
    let wakes = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut task = Context::from_waker(&waker);
    {
        let _current = Cx::set_current(Some(foreign));
        control.check(Some(&mut task)).unwrap();
        owner.set_cancel_requested(true);
        assert!(wakes.0.load(std::sync::atomic::Ordering::SeqCst) > 0);
        assert!(matches!(
            control.check(Some(&mut task)),
            Err(NativeH3TunnelError::Client(NativeH3ClientError::Cancelled))
        ));
    }
    let (_, _, owner) = timed_context(Time::ZERO, None);
    let mut control = {
        let _current = Cx::set_current(Some(owner.clone()));
        let _restriction = Cx::push_restriction(crate::cx::cap::CapMask::none());
        TunnelControl::new(owner.clone())
    };
    let _current = Cx::set_current(Some(owner));
    assert!(matches!(
        control.check(None),
        Err(NativeH3TunnelError::Client(NativeH3ClientError::Admission(
            _
        )))
    ));
}
