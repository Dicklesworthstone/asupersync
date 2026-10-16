    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake};

    /// mu5yhv finding 1: clones share the pool, keyed by scheme, host and
    /// port only. A clone given another connector (another client identity
    /// or trust policy) took connections authenticated under the first one.
    #[cfg(feature = "tls")]
    #[test]
    fn a_clone_given_another_tls_connector_gets_its_own_pool() {
        let connector = || {
            let certs = crate::tls::Certificate::from_pem(include_bytes!(
                "../../../tests/fixtures/tls/server.crt"
            ))
            .expect("test certificate");
            crate::tls::TlsConnectorBuilder::new()
                .add_root_certificates(certs)
                .alpn_h2()
                .build()
                .expect("test connector")
        };
        let pool = |client: &Http2Client| Arc::clone(client.pool.as_ref().expect("reuse is on"));

        let base = Http2Client::new().reuse_connections(2);
        let a = base.clone().tls_connector(connector());
        let b = base.clone().tls_connector(connector());
        assert!(
            !Arc::ptr_eq(&pool(&a), &pool(&b)),
            "clones with different connectors must not share idle connections"
        );
        assert!(!Arc::ptr_eq(&pool(&base), &pool(&a)));
        assert_eq!(pool(&a).max_idle, 2);

        let a_again = a.clone();
        assert!(
            Arc::ptr_eq(&pool(&a), &pool(&a_again)),
            "a clone that keeps its connector still shares"
        );
        assert!(Http2Client::new().tls_connector(connector()).pool.is_none());
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

    struct SilentTransport(Arc<AtomicUsize>);

    impl Drop for SilentTransport {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl AsyncRead for SilentTransport {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut crate::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for SilentTransport {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A transport that accepts writes and whose reads fail with the given
    /// kind, or end the stream (`None`).
    struct FailingReadTransport(Option<io::ErrorKind>);

    impl AsyncRead for FailingReadTransport {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut crate::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(match self.0 {
                Some(kind) => Err(io::Error::new(kind, "transport read failed")),
                None => Ok(()),
            })
        }
    }

    impl AsyncWrite for FailingReadTransport {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// br-asupersync-h2-client-audit-6hvls9 LOW 3: a failed transport read
    /// came back as Protocol(INTERNAL_ERROR), and a peer that closed the
    /// connection mid-response as Protocol too. Io is documented as the
    /// transport failure, so a retry policy keyed on it misread both.
    #[test]
    fn transport_read_failure_and_eof_are_reported_as_io() {
        for (transport, expected) in [
            (
                FailingReadTransport(Some(io::ErrorKind::ConnectionReset)),
                io::ErrorKind::ConnectionReset,
            ),
            (FailingReadTransport(None), io::ErrorKind::UnexpectedEof),
        ] {
            let caller = Cx::for_testing();
            let waker = Waker::from(Arc::new(CountWake::default()));
            let mut task = Context::from_waker(&waker);
            let mut future = Box::pin(
                Http2Client::new()
                    .get("http://localhost/")
                    .send_on(&caller, transport),
            );
            match future.as_mut().poll(&mut task) {
                Poll::Ready(Err(Http2ClientError::Io(error))) => {
                    assert_eq!(error.kind(), expected);
                }
                other => panic!("expected an I/O error of kind {expected:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn explicit_caller_cancellation_wakes_and_drops_owned_transport() {
        let caller = Cx::for_testing();
        let ambient = Cx::for_testing();
        let _current = Cx::set_current(Some(ambient.clone()));
        let dropped = Arc::new(AtomicUsize::new(0));
        let wake = Arc::new(CountWake::default());
        let waker = Waker::from(Arc::clone(&wake));
        let mut task = Context::from_waker(&waker);
        let mut future = Box::pin(
            Http2Client::new()
                .get("http://localhost/")
                .send_on(&caller, SilentTransport(Arc::clone(&dropped))),
        );
        assert!(future.as_mut().poll(&mut task).is_pending());
        let before = wake.0.load(Ordering::SeqCst);
        let reason =
            CancelReason::deadline().with_cause(CancelReason::user("HTTP ingress stopped"));
        caller.cancel_with_reason(reason.clone());
        assert!(wake.0.load(Ordering::SeqCst) > before);
        match future.as_mut().poll(&mut task) {
            Poll::Ready(Err(Http2ClientError::Cancelled(actual))) => assert_eq!(actual, reason),
            other => panic!("caller cancellation was not returned: {other:?}"),
        }
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(ambient.checkpoint().is_ok());
        let before = wake.0.load(Ordering::SeqCst);
        ambient.cancel_with_reason(CancelReason::shutdown());
        assert_eq!(
            wake.0.load(Ordering::SeqCst),
            before,
            "completed request retained its ambient registration"
        );
    }

    #[test]
    fn masked_ambient_cancellation_does_not_self_wake_a_parked_request() {
        let caller = Cx::for_testing();
        let ambient = Cx::for_testing();
        let _current = Cx::set_current(Some(ambient.clone()));
        let dropped = Arc::new(AtomicUsize::new(0));
        let wake = Arc::new(CountWake::default());
        let waker = Waker::from(Arc::clone(&wake));
        let mut task = Context::from_waker(&waker);
        let mut future = Box::pin(
            Http2Client::new()
                .get("http://localhost/")
                .send_on(&caller, SilentTransport(Arc::clone(&dropped))),
        );
        ambient.cancel_with_reason(CancelReason::shutdown());
        ambient.masked(|| {
            let before = wake.0.load(Ordering::SeqCst);
            assert!(future.as_mut().poll(&mut task).is_pending());
            assert!(future.as_mut().poll(&mut task).is_pending());
            assert_eq!(
                wake.0.load(Ordering::SeqCst),
                before,
                "masked cancellation turned the deadline timer into a busy loop"
            );
        });
        assert!(matches!(
            future.as_mut().poll(&mut task),
            Poll::Ready(Err(Http2ClientError::Cancelled(_)))
        ));
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn request_validation_and_authority_are_applied_before_io() {
        let client = Http2Client::new();
        for builder in [
            client.get("http://localhost/").header(":path", "/override"),
            client
                .get("http://localhost/")
                .header("connection", "close"),
            client
                .get("http://localhost/")
                .header("host", "attacker.invalid"),
            client
                .post("http://localhost/")
                .header("content-length", "2")
                .body("x"),
            client
                .post("http://localhost/")
                .header("content-length", "0")
                .header("content-length", "0"),
            client.get("http://localhost/a\rb"),
            // asupersync-e427ys: RFC 9113 §8.2.1 malformed field values.
            client.get("http://localhost/").header("x-pad", " leading"),
            client
                .get("http://localhost/")
                .header("x-pad", "trailing\t"),
            client.request(Method::Extension("G ET".into()), "http://localhost/"),
            client.request(Method::Connect, "http://localhost/"),
        ] {
            assert!(matches!(
                builder.prepare(),
                Err(Http2ClientError::InvalidRequest(_))
            ));
        }
        let request = client.get("http://[::1]?x=1#secret").prepare().unwrap();
        assert_eq!(request.url.path, "/?x=1");
        assert_eq!(request.url.authority(), "[::1]");
        assert!(
            client
                .clone()
                .max_request_body(0)
                .post("http://localhost/")
                .body("x")
                .prepare()
                .is_err()
        );
    }

    #[test]
    fn response_metadata_and_framing_are_bounded() {
        let mut state = ResponseState::new(false, 3);
        assert!(
            !state
                .headers(
                    vec![Header::new(":status", "103"), Header::new("link", "</a>")],
                    false
                )
                .unwrap()
        );
        assert!(
            !state
                .headers(
                    vec![
                        Header::new(":status", "200"),
                        Header::new("content-length", "3")
                    ],
                    false
                )
                .unwrap()
        );
        assert!(!state.data(b"abc", false).unwrap());
        assert!(
            state
                .headers(vec![Header::new("x-checksum", "yes")], true)
                .unwrap()
        );
        assert_eq!(state.response.body.as_ref(), b"abc");
        assert_eq!(state.response.trailers[0].value, "yes");
        let mut head = ResponseState::new(true, 0);
        assert!(
            head.headers(
                vec![
                    Header::new(":status", "200"),
                    Header::new("content-length", "900000")
                ],
                true
            )
            .unwrap()
        );
        let mut truncated = ResponseState::new(false, 10);
        truncated
            .headers(
                vec![
                    Header::new(":status", "200"),
                    Header::new("content-length", "3"),
                ],
                false,
            )
            .unwrap();
        assert!(truncated.data(b"ab", true).is_err());
        let mut metadata = ResponseState::new(false, 10);
        let information = vec![
            Header::new(":status", "103"),
            Header::new("link", "x".repeat(HEADER_LIMIT / 2)),
        ];
        assert!(metadata.headers(information.clone(), false).is_ok());
        assert!(metadata.headers(information, false).is_err());
    }

    /// asupersync-mu5yhv (d0's LOW 1): an idle connection was closed only
    /// when a later request went to its own origin, so a client that reached
    /// many hosts kept a socket to each. Putting any connection back now
    /// closes the expired ones of every origin.
    #[test]
    fn putting_a_connection_back_closes_the_expired_idle_ones_of_every_origin() {
        let pool = ConnectionPool::<u32> {
            max_idle: 4,
            idle: Mutex::new(HashMap::new()),
        };
        let origin = |host: &str| -> Origin { (false, host.to_owned(), 80) };
        let entry = |host: &str, conn: u32| (host.to_owned(), conn);
        let pooled = |pool: &ConnectionPool<u32>| {
            let mut pooled: Vec<(String, u32)> = pool
                .idle
                .lock()
                .iter()
                .flat_map(|((_, host, _), conns)| conns.iter().map(|(_, c)| (host.clone(), *c)))
                .collect();
            pooled.sort();
            pooled
        };
        pool.put(origin("a"), 1, Time::from_secs(0));
        pool.put(origin("b"), 2, Time::from_secs(10));
        // 30 s idle is the limit itself: "a" is still kept.
        pool.put(origin("c"), 3, Time::from_secs(30));
        assert_eq!(
            pooled(&pool),
            vec![entry("a", 1), entry("b", 2), entry("c", 3)]
        );
        // 31 s idle: "a" is closed and its origin dropped, though no request
        // went to "a" again.
        pool.put(origin("c"), 4, Time::from_secs(31));
        assert_eq!(
            pooled(&pool),
            vec![entry("b", 2), entry("c", 3), entry("c", 4)]
        );
        assert!(!pool.idle.lock().contains_key(&origin("a")));
        pool.put(origin("d"), 5, Time::from_secs(62));
        assert_eq!(pooled(&pool), vec![entry("d", 5)]);
        // take still answers with the newest live connection of its origin.
        pool.put(origin("d"), 6, Time::from_secs(63));
        assert_eq!(pool.take(&origin("d"), Time::from_secs(63)), Some(6));
    }

    struct ScriptedTransport {
        incoming: crate::bytes::BytesMut,
    }

    impl ScriptedTransport {
        fn new(incoming: crate::bytes::BytesMut) -> Self {
            Self { incoming }
        }
    }

    impl AsyncRead for ScriptedTransport {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut crate::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.incoming.is_empty() {
                return Poll::Pending;
            }
            let n = buf.remaining().min(this.incoming.len());
            let chunk = this.incoming.split_to(n);
            buf.put_slice(&chunk);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ScriptedTransport {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn drive_exchange(
        builder: Http2RequestBuilder,
        incoming: crate::bytes::BytesMut,
    ) -> Result<Http2Response, Http2ClientError> {
        let caller = Cx::for_testing();
        let waker = Waker::from(Arc::new(CountWake::default()));
        let mut task = Context::from_waker(&waker);
        let mut future = Box::pin(builder.send_on(&caller, ScriptedTransport::new(incoming)));
        for _ in 0..100 {
            if let Poll::Ready(result) = future.as_mut().poll(&mut task) {
                return result;
            }
        }
        panic!("scripted exchange did not complete in bounded poll steps");
    }

    /// The bytes a scripted server sends: `frames`, encoded in order.
    fn server_frames(frames: impl IntoIterator<Item = Frame>) -> crate::bytes::BytesMut {
        let mut incoming = crate::bytes::BytesMut::new();
        for frame in frames {
            frame
                .encode(&mut incoming)
                .expect("encode a scripted frame");
        }
        incoming
    }

    /// A complete bodyless `:status 200` response on `stream_id` (HPACK
    /// static index 8 is (:status, 200), encoded as 0x88).
    fn ok_response(stream_id: u32) -> Frame {
        Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
            stream_id,
            Bytes::from_static(&[0x88]),
            true,
            true,
        ))
    }

    /// `count` PINGs, as a server sending keepalives would.
    fn pings(count: usize) -> Vec<Frame> {
        vec![Frame::Ping(crate::http::h2::frame::PingFrame::new([7; 8])); count]
    }

    /// Queue `frames` on a scripted connection's transport, after whatever it
    /// has not read yet.
    fn feed(conn: &mut Http2Conn<ScriptedTransport>, frames: impl IntoIterator<Item = Frame>) {
        let bytes = server_frames(frames);
        conn.wire.get_mut().inner.incoming.extend_from_slice(&bytes);
    }

    /// Poll `future` to completion in bounded steps. A scripted transport
    /// answers Pending only once its queued bytes are used up, so a step that
    /// still needs more of them never completes.
    fn complete<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(CountWake::default()));
        let mut task = Context::from_waker(&waker);
        let mut future = std::pin::pin!(future);
        for _ in 0..100 {
            if let Poll::Ready(output) = future.as_mut().poll(&mut task) {
                return output;
            }
        }
        panic!("scripted connection step did not complete in bounded poll steps");
    }

    #[test]
    fn max_overhead_frames_enforces_empty_data_flood() {
        use crate::bytes::BytesMut;
        use crate::http::h2::frame::{DataFrame, HeadersFrame, SettingsFrame};

        let mut incoming = BytesMut::new();
        Frame::Settings(SettingsFrame::new(vec![]))
            .encode(&mut incoming)
            .unwrap();
        // Response headers must precede DATA frames
        Frame::Headers(HeadersFrame::new(
            1,
            Bytes::from_static(&[0x88]),
            false,
            true,
        ))
        .encode(&mut incoming)
        .unwrap();
        for _ in 0..3 {
            Frame::Data(DataFrame::new(1, Bytes::new(), false))
                .encode(&mut incoming)
                .unwrap();
        }

        let client = Http2Client::new();
        let res = drive_exchange(
            client.get("http://localhost/").max_overhead_frames(2),
            incoming,
        );
        match res {
            Err(Http2ClientError::Protocol(err)) => {
                assert_eq!(err.code, ErrorCode::EnhanceYourCalm);
                assert!(err.message.contains("overhead limit exceeded"));
            }
            other => panic!("expected EnhanceYourCalm protocol error, got {other:?}"),
        }
    }

    #[test]
    fn max_overhead_frames_enforces_ping_flood() {
        use crate::bytes::BytesMut;
        use crate::http::h2::frame::{PingFrame, SettingsFrame};

        let mut incoming = BytesMut::new();
        Frame::Settings(SettingsFrame::new(vec![]))
            .encode(&mut incoming)
            .unwrap();
        for i in 0..4 {
            Frame::Ping(PingFrame::new([i as u8; 8]))
                .encode(&mut incoming)
                .unwrap();
        }

        let client = Http2Client::new();
        let res = drive_exchange(
            client.get("http://localhost/").max_overhead_frames(3),
            incoming,
        );
        match res {
            Err(Http2ClientError::Protocol(err)) => {
                assert_eq!(err.code, ErrorCode::EnhanceYourCalm);
                assert!(err.message.contains("overhead limit exceeded"));
            }
            other => panic!("expected EnhanceYourCalm protocol error, got {other:?}"),
        }
    }

    /// Unsolicited SETTINGS (each forces a queued ACK) and PRIORITY share the
    /// budget. Until review r31-e8 of 3ba51cd7e (br-asupersync-r96ybl) this
    /// test flooded SETTINGS ACKs, which are the server's mandatory reply to
    /// the client's own SETTINGS and are no longer counted.
    #[test]
    fn max_overhead_frames_enforces_unsolicited_settings_and_priority_flood() {
        use crate::bytes::BytesMut;
        use crate::http::h2::frame::{PriorityFrame, PrioritySpec, SettingsFrame};

        let mut incoming = BytesMut::new();
        // The connection-preface SETTINGS is exempt.
        Frame::Settings(SettingsFrame::new(vec![]))
            .encode(&mut incoming)
            .unwrap();
        Frame::Settings(SettingsFrame::new(vec![]))
            .encode(&mut incoming)
            .unwrap();
        Frame::Priority(PriorityFrame {
            stream_id: 1,
            priority: PrioritySpec {
                exclusive: false,
                dependency: 0,
                weight: 16,
            },
        })
        .encode(&mut incoming)
        .unwrap();
        Frame::Settings(SettingsFrame::new(vec![]))
            .encode(&mut incoming)
            .unwrap();

        let client = Http2Client::new();
        let res = drive_exchange(
            client.get("http://localhost/").max_overhead_frames(2),
            incoming,
        );
        match res {
            Err(Http2ClientError::Protocol(err)) => {
                assert_eq!(err.code, ErrorCode::EnhanceYourCalm);
                assert!(err.message.contains("overhead limit exceeded"));
            }
            other => panic!("expected EnhanceYourCalm protocol error, got {other:?}"),
        }
    }

    #[test]
    fn overhead_frames_within_budget_succeed() {
        use crate::bytes::BytesMut;
        use crate::http::h2::frame::{DataFrame, HeadersFrame, PingFrame, SettingsFrame};

        let mut incoming = BytesMut::new();
        Frame::Settings(SettingsFrame::new(vec![]))
            .encode(&mut incoming)
            .unwrap();
        Frame::Ping(PingFrame::new([1; 8]))
            .encode(&mut incoming)
            .unwrap();
        // HPACK static index 8 is (:status, 200), encoded as 0x88.
        Frame::Headers(HeadersFrame::new(
            1,
            Bytes::from_static(&[0x88]),
            false,
            true,
        ))
        .encode(&mut incoming)
        .unwrap();
        Frame::Data(DataFrame::new(1, Bytes::new(), false))
            .encode(&mut incoming)
            .unwrap();
        Frame::Data(DataFrame::new(1, Bytes::from_static(b"ok"), true))
            .encode(&mut incoming)
            .unwrap();

        let client = Http2Client::new();
        let response = drive_exchange(
            client.get("http://localhost/").max_overhead_frames(5),
            incoming,
        )
        .expect("request should succeed when overhead is within budget");

        assert_eq!(response.status, 200);
        assert_eq!(response.body.as_ref(), b"ok");
    }

    #[test]
    fn terminal_empty_data_is_not_counted_as_overhead() {
        use crate::bytes::BytesMut;
        use crate::http::h2::frame::{DataFrame, HeadersFrame, SettingsFrame};

        let mut incoming = BytesMut::new();
        Frame::Settings(SettingsFrame::new(vec![]))
            .encode(&mut incoming)
            .unwrap();
        // Response headers without end_stream
        Frame::Headers(HeadersFrame::new(
            1,
            Bytes::from_static(&[0x88]),
            false,
            true,
        ))
        .encode(&mut incoming)
        .unwrap();
        // Terminal empty DATA frame (end_stream: true)
        Frame::Data(DataFrame::new(1, Bytes::new(), true))
            .encode(&mut incoming)
            .unwrap();

        let client = Http2Client::new();
        // Even with max_overhead_frames = 0, a terminal empty DATA frame is not overhead.
        let response = drive_exchange(
            client.get("http://localhost/").max_overhead_frames(0),
            incoming,
        )
        .expect("terminal empty DATA frame must not be charged as overhead");

        assert_eq!(response.status, 200);
    }

    #[test]
    fn non_terminal_empty_data_with_zero_budget_fails() {
        use crate::bytes::BytesMut;
        use crate::http::h2::frame::{DataFrame, SettingsFrame};

        let mut incoming = BytesMut::new();
        Frame::Settings(SettingsFrame::new(vec![]))
            .encode(&mut incoming)
            .unwrap();
        Frame::Data(DataFrame::new(1, Bytes::new(), false))
            .encode(&mut incoming)
            .unwrap();

        let client = Http2Client::new();
        let res = drive_exchange(
            client.get("http://localhost/").max_overhead_frames(0),
            incoming,
        );
        match res {
            Err(Http2ClientError::Protocol(err)) => {
                assert_eq!(err.code, ErrorCode::EnhanceYourCalm);
                assert!(err.message.contains("overhead limit exceeded"));
            }
            other => panic!("expected EnhanceYourCalm protocol error, got {other:?}"),
        }
    }

    #[test]
    fn client_default_max_overhead_frames() {
        let client = Http2Client::new();
        assert_eq!(client.max_overhead_frames, DEFAULT_MAX_OVERHEAD_FRAMES);
        assert_eq!(DEFAULT_MAX_OVERHEAD_FRAMES, 10_000);

        let custom = client.max_overhead_frames(500);
        assert_eq!(custom.max_overhead_frames, 500);
    }

    /// Review r31-e8 of 3ba51cd7e (br-asupersync-r96ybl) MEDIUM-1: the
    /// overhead budget counted over the connection's whole life, so a pooled
    /// connection to a server that sends a few PINGs per request (keepalive)
    /// eventually failed a healthy request with ENHANCE_YOUR_CALM, which is
    /// not retried. This drives one connection the way the pool does (start
    /// and request; then refresh and request for each reuse) with `LIMIT - 1`
    /// PINGs in every use. On the old code the second request fails with
    /// ENHANCE_YOUR_CALM, since 2 * (LIMIT - 1) >= LIMIT. The last two uses
    /// show that frames received while idle count toward the next use, and
    /// that a use which takes the whole budget retires the connection.
    #[test]
    fn overhead_budget_is_per_use_not_per_connection_lifetime() {
        use crate::http::h2::frame::SettingsFrame;

        const LIMIT: usize = 3;
        let request = Http2Client::new()
            .get("http://localhost/")
            .prepare()
            .expect("valid request");
        let run = |conn: &mut Http2Conn<ScriptedTransport>| {
            complete(conn.request(request.clone(), Bytes::new(), DEFAULT_BODY_LIMIT))
                .map(|(response, _)| response.status)
                .map_err(|failure| failure.error)
        };
        let mut conn = complete(Http2Conn::start(
            ScriptedTransport::new(crate::bytes::BytesMut::new()),
            DEFAULT_BODY_LIMIT,
            LIMIT,
        ))
        .expect("client preface");

        // Use 1, a fresh connection: the preface SETTINGS (exempt), LIMIT - 1
        // PINGs, and the response.
        feed(&mut conn, [Frame::Settings(SettingsFrame::new(vec![]))]);
        feed(&mut conn, pings(LIMIT - 1));
        feed(&mut conn, [ok_response(1)]);
        assert_eq!(run(&mut conn).expect("first use within budget"), 200);
        assert!(conn.reusable());

        // Use 2, reused: nothing arrived while idle, LIMIT - 1 PINGs during
        // the request.
        complete(conn.refresh()).expect("nothing arrived while idle");
        feed(&mut conn, pings(LIMIT - 1));
        feed(&mut conn, [ok_response(3)]);
        assert_eq!(
            run(&mut conn).expect("a reused connection starts a fresh budget"),
            200
        );
        assert!(conn.reusable());

        // Use 3: one keepalive PING while idle and LIMIT - 2 during the
        // request, LIMIT - 1 in all.
        feed(&mut conn, pings(1));
        complete(conn.refresh()).expect("an idle PING within budget");
        feed(&mut conn, pings(LIMIT - 2));
        feed(&mut conn, [ok_response(5)]);
        assert_eq!(run(&mut conn).expect("third use within budget"), 200);
        assert!(conn.reusable());

        // Use 4: one PING while idle and LIMIT - 1 during the request take the
        // whole budget. The request still succeeds, but the connection is not
        // reused; had refresh not charged the idle PING to this use, it would
        // be.
        feed(&mut conn, pings(1));
        complete(conn.refresh()).expect("an idle PING within budget");
        feed(&mut conn, pings(LIMIT - 1));
        feed(&mut conn, [ok_response(7)]);
        assert_eq!(run(&mut conn).expect("the budget admits its limit"), 200);
        assert!(
            !conn.reusable(),
            "a connection that used its whole budget must be retired"
        );
    }

    /// Review r31-e8 of 3ba51cd7e (br-asupersync-r96ybl) MEDIUM-2: the budget
    /// counted the SETTINGS ACK, the server's mandatory reply to the client's
    /// own SETTINGS, but not an unsolicited SETTINGS, each of which forces
    /// the client to queue an ACK (CVE-2019-9515). On the old code the first
    /// exchange fails with ENHANCE_YOUR_CALM (a conforming server's ACK
    /// breached a limit of 0), and the flood below completes with 200
    /// instead of being stopped.
    #[test]
    fn settings_ack_is_not_overhead_but_unsolicited_settings_are() {
        use crate::http::h2::frame::SettingsFrame;

        let settings = || Frame::Settings(SettingsFrame::new(vec![]));
        let ack = || Frame::Settings(SettingsFrame::ack());
        let client = Http2Client::new();

        // A conforming server: its preface SETTINGS, the ACK of the client's
        // SETTINGS, and the response. Neither counts, so even 0 admits it.
        let response = drive_exchange(
            client.get("http://localhost/").max_overhead_frames(0),
            server_frames([settings(), ack(), ok_response(1)]),
        )
        .expect("the preface SETTINGS and the SETTINGS ACK are not overhead");
        assert_eq!(response.status, 200);

        // After the preface, a limit of 2 admits two unsolicited SETTINGS...
        let response = drive_exchange(
            client.get("http://localhost/").max_overhead_frames(2),
            server_frames([settings(), settings(), settings(), ack(), ok_response(1)]),
        )
        .expect("two unsolicited SETTINGS are within a limit of 2");
        assert_eq!(response.status, 200);

        // ...and the third fails the request before its response is read.
        match drive_exchange(
            client.get("http://localhost/").max_overhead_frames(2),
            server_frames([
                settings(),
                settings(),
                settings(),
                settings(),
                ok_response(1),
            ]),
        ) {
            Err(Http2ClientError::Protocol(error)) => {
                assert_eq!(error.code, ErrorCode::EnhanceYourCalm);
                assert!(error.message.contains("overhead limit exceeded"));
            }
            other => panic!("an unsolicited SETTINGS flood must be stopped, got {other:?}"),
        }
    }

    /// Fresh-eyes review of dd16a63d6 (br-asupersync-r96ybl) LOW-2.2: every
    /// SETTINGS ACK became free, but the client sends SETTINGS once, so only
    /// the first ACK answers it. On the old code the repeated ACKs below are
    /// never counted and the exchange completes with 200.
    #[test]
    fn only_the_first_settings_ack_is_free() {
        use crate::http::h2::frame::SettingsFrame;

        let settings = || Frame::Settings(SettingsFrame::new(vec![]));
        let ack = || Frame::Settings(SettingsFrame::ack());
        let client = Http2Client::new();

        let response = drive_exchange(
            client.get("http://localhost/").max_overhead_frames(1),
            server_frames([settings(), ack(), ack(), ok_response(1)]),
        )
        .expect("one repeated ACK is within a limit of 1");
        assert_eq!(response.status, 200);

        match drive_exchange(
            client.get("http://localhost/").max_overhead_frames(1),
            server_frames([settings(), ack(), ack(), ack(), ok_response(1)]),
        ) {
            Err(Http2ClientError::Protocol(error)) => {
                assert_eq!(error.code, ErrorCode::EnhanceYourCalm);
            }
            other => panic!("a SETTINGS ACK flood must be stopped, got {other:?}"),
        }
    }

    /// Fresh-eyes review of dd16a63d6 (br-asupersync-r96ybl) LOW-2.1: with a
    /// budget of 0, a connection that received no overhead frame at all was
    /// still "out of budget", so it was never pooled, and a request using the
    /// override 0 emptied its origin's pool. On the old code `reusable` is
    /// false here.
    #[test]
    fn a_zero_budget_connection_without_overhead_is_reused() {
        use crate::http::h2::frame::SettingsFrame;

        let request = Http2Client::new()
            .get("http://localhost/")
            .prepare()
            .expect("valid request");
        let mut conn = complete(Http2Conn::start(
            ScriptedTransport::new(crate::bytes::BytesMut::new()),
            DEFAULT_BODY_LIMIT,
            0,
        ))
        .expect("client preface");
        feed(
            &mut conn,
            [
                Frame::Settings(SettingsFrame::new(vec![])),
                Frame::Settings(SettingsFrame::ack()),
                ok_response(1),
            ],
        );
        let (response, _) = complete(conn.request(request, Bytes::new(), DEFAULT_BODY_LIMIT))
            .map_err(|failure| failure.error)
            .expect("no overhead frame arrived");
        assert_eq!(response.status, 200);
        assert!(conn.reusable(), "no overhead frame was received");
        complete(conn.refresh()).expect("nothing arrived while idle");
        feed(&mut conn, pings(1));
        assert!(
            complete(conn.refresh()).is_err(),
            "a budget of 0 still refuses one idle PING"
        );
    }
