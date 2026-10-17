    use super::*;
    use crate::bytes::{Bytes, BytesMut};
    use crate::http::h2::frame::{
        HeadersFrame, PingFrame, Setting, SettingsFrame, WindowUpdateFrame,
    };
    use crate::http::h2::hpack::Encoder as HpackEncoder;

    #[test]
    fn only_affected_stream_data_renews_its_credit_deadline() {
        let mut conn = Connection::server(Settings::server());
        conn.process_frame(Frame::Settings(SettingsFrame::new(vec![
            Setting::InitialWindowSize(0),
        ])))
        .unwrap();
        let mut encoder = HpackEncoder::new();
        let mut guards = HashMap::new();
        for stream_id in [1, 3] {
            let mut headers = BytesMut::new();
            encoder.encode(
                &[
                    Header::new(":method", "GET"),
                    Header::new(":scheme", "http"),
                    Header::new(":path", "/"),
                    Header::new(":authority", "localhost"),
                ],
                &mut headers,
            );
            conn.process_frame(Frame::Headers(HeadersFrame::new(
                stream_id,
                headers.freeze(),
                true,
                true,
            )))
            .unwrap();
            conn.send_headers(stream_id, vec![Header::new(":status", "200")], false)
                .unwrap();
            conn.send_data(stream_id, Bytes::from_static(b"blocked"), true)
                .unwrap();
            guards.insert(stream_id, Arc::new(InFlightRequestGuard::acquire(None)));
        }
        while let Some(frame) = conn.next_frame() {
            assert!(
                !matches!(frame, Frame::Data(_)),
                "zero peer credit holds all response DATA"
            );
        }
        let timeout = Duration::from_nanos(10);
        let mut progress = H2FlowControlProgress::new(timeout);
        let bodies = BTreeMap::new();
        assert_eq!(
            progress.next_deadline(&conn, &guards, &bodies, Time::from_nanos(10),),
            Some((1, Time::from_nanos(20)))
        );
        conn.process_frame(Frame::Ping(PingFrame::new([0; 8])))
            .unwrap();
        assert!(matches!(conn.next_frame(), Some(Frame::Ping(_))));
        assert!(conn.next_frame().is_none());
        assert_eq!(
            progress.next_deadline(&conn, &guards, &bodies, Time::from_nanos(15),),
            Some((1, Time::from_nanos(20)))
        );

        for (stream_id, now) in [(3, 15), (1, 19)] {
            conn.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(stream_id, 1)))
                .unwrap();
            let Some(Frame::Data(data)) = conn.next_frame() else {
                panic!("one byte of credit emits DATA");
            };
            assert_eq!(data.stream_id, stream_id);
            assert_eq!(data.data.len(), 1);
            assert!(conn.next_frame().is_none());
            progress.queued_data(data.stream_id);
            progress.flushed(Time::from_nanos(now));
            let _ = progress.next_deadline(&conn, &guards, &bodies, Time::from_nanos(now));
        }
        assert_eq!(progress.deadlines.get(&1), Some(&Time::from_nanos(29)));
        assert_eq!(progress.deadlines.get(&3), Some(&Time::from_nanos(25)));
        assert_eq!(
            progress.next_deadline(&conn, &guards, &bodies, Time::from_nanos(25),),
            Some((3, Time::from_nanos(25))),
            "expiry remains absolute at exact equality"
        );
        for stream_id in [1, 3] {
            conn.reset_stream(stream_id, ErrorCode::Cancel);
        }
        while conn.next_frame().is_some() {}
        release_flushed_response_guards(&conn, &mut guards);
        assert!(
            progress
                .next_deadline(&conn, &guards, &bodies, Time::from_nanos(26),)
                .is_none()
        );
        assert!(
            progress.deadlines.is_empty(),
            "retired responses retain no deadline state"
        );
    }

    #[test]
    fn a_pushed_response_held_by_peer_credit_gets_a_deadline() {
        let mut conn = Connection::server(Settings::server());
        conn.process_frame(Frame::Settings(SettingsFrame::new(vec![
            Setting::InitialWindowSize(0),
        ])))
        .unwrap();
        let request = [
            Header::new(":method", "GET"),
            Header::new(":scheme", "http"),
            Header::new(":path", "/"),
            Header::new(":authority", "localhost"),
        ];
        let mut headers = BytesMut::new();
        HpackEncoder::new().encode(&request, &mut headers);
        conn.process_frame(Frame::Headers(HeadersFrame::new(
            1,
            headers.freeze(),
            true,
            true,
        )))
        .unwrap();
        let mut promised = request.to_vec();
        promised[2] = Header::new(":path", "/style.css");
        let pushed = conn.send_push_promise(1, promised).unwrap();
        conn.send_headers(pushed, vec![Header::new(":status", "200")], false)
            .unwrap();
        conn.send_data(pushed, Bytes::from_static(b"blocked"), true)
            .unwrap();
        while let Some(frame) = conn.next_frame() {
            assert!(
                !matches!(frame, Frame::Data(_)),
                "zero peer credit holds the pushed DATA"
            );
        }

        let mut progress = H2FlowControlProgress::new(Duration::from_nanos(10));
        assert_eq!(
            progress.next_deadline(
                &conn,
                &HashMap::new(),
                &BTreeMap::new(),
                Time::from_nanos(10)
            ),
            Some((pushed, Time::from_nanos(20))),
            "a push with no peer credit times out like a response does"
        );
    }
