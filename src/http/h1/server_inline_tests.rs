    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::http::body::{Body, HeaderMap, HeaderName, HeaderValue};
    use crate::http::h1::types::Method;
    use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
    use crate::runtime::RuntimeBuilder;
    use crate::web::sse::{SseEvent, StreamingSseError};
    use std::collections::VecDeque;
    use std::io;
    use std::num::NonZeroUsize;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    /// Supplemental bypass guard; behavioral proof is the native nonreading
    /// peer and parked-producer matrix in e2e_h1_graceful_drain.
    #[test]
    fn response_write_sites_use_bounded_policy_or_request_read_budget() {
        let source = include_str!("server.rs");
        let production = source.split("\n#[cfg(test)]\nmod tests {").next().unwrap();
        let permitted = [
            ("flush_framed", ".poll_flush("),
            ("write_streaming_response", ".write_all("),
            ("write_streaming_response", ".flush("),
            ("write_all_within_idle", ".write_all("),
            ("flush_within_idle", ".flush("),
            ("close_transport", ".shutdown("),
            // Both expectation writes are inside read_next's one request
            // deadline and its registered shutdown waiter, including retries.
            ("poll_pending_expectation_flush", ".poll_flush("),
            ("poll_request_expectation", ".poll_flush("),
            // Http1UpgradedIo's AsyncWrite impl (1765fc422) only forwards to
            // the transport. It is handed to an upgrade handler after the 101
            // response was committed, so its writes belong to the upgraded
            // protocol and its owner, not to an HTTP response.
            ("poll_write", ".poll_write("),
            ("poll_write_vectored", ".poll_write_vectored("),
            ("poll_flush", ".poll_flush("),
            ("poll_shutdown", ".poll_shutdown("),
        ];
        let mut observed = Vec::new();
        let mut function = "";
        for (line_number, line) in production.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            if let Some((_, declaration)) = code.split_once("fn ") {
                function = declaration.split(['<', '(']).next().unwrap();
            }
            for operation in [
                ".poll_write(",
                ".poll_write_vectored(",
                ".write(",
                ".write_all(",
                ".poll_flush(",
                ".flush(",
                ".poll_shutdown(",
                ".shutdown(",
                ".poll_close(",
            ] {
                if code.contains(operation) {
                    assert!(
                        permitted.contains(&(function, operation)),
                        "unbounded response operation at line {} in {function}: {code}",
                        line_number + 1
                    );
                    observed.push((function, operation));
                }
            }
        }
        assert_eq!(
            observed.len(),
            permitted.len(),
            "review changed response write sites"
        );
        for site in permitted {
            assert!(
                observed.contains(&site),
                "missing expected write site: {site:?}"
            );
        }
    }

    struct TestIo {
        read_data: Vec<u8>,
        written: Arc<Mutex<Vec<u8>>>,
        read_limit: usize,
        read_error: Option<io::ErrorKind>,
    }

    impl TestIo {
        fn new(read_data: Vec<u8>, written: Arc<Mutex<Vec<u8>>>) -> Self {
            Self {
                read_data,
                written,
                read_limit: usize::MAX,
                read_error: None,
            }
        }

        fn with_read_limit(mut self, read_limit: usize) -> Self {
            self.read_limit = read_limit.max(1);
            self
        }

        fn with_read_error(mut self, kind: io::ErrorKind) -> Self {
            self.read_error = Some(kind);
            self
        }
    }

    #[test]
    fn body_diagnostic_incoming_body_failures_preserve_safe_terminal_dispositions() {
        let too_large = incoming_body_failure_response(
            Version::Http11,
            &IncomingBodyError::BodyTooLarge {
                actual: Some(9),
                limit: 8,
            },
        )
        .expect("pre-head aggregate limit has a safe response");
        assert_eq!(too_large.status, 413);
        assert_eq!(
            too_large.body,
            b"[ASUP-E505] request body exceeds the configured limit"
        );

        let timeout =
            incoming_body_failure_response(Version::Http11, &IncomingBodyError::DrainTimeout)
                .expect("pre-head drain timeout has a safe response");
        assert_eq!(timeout.status, 408);
        assert_eq!(timeout.body, b"[ASUP-E508] request body drain timed out");

        let deadline = incoming_body_failure_response(
            Version::Http11,
            &IncomingBodyError::Cancelled {
                kind: CancelKind::Deadline,
            },
        )
        .expect("pre-head request deadline retains E501");
        assert_eq!(deadline.status, 503);
        assert_eq!(deadline.body, HTTP_DEADLINE_EXHAUSTED_DIAGNOSTIC.as_bytes());

        assert!(
            incoming_body_failure_response(Version::Http11, &IncomingBodyError::ClientAborted,)
                .is_none(),
            "client abort must remain close-only"
        );
        let disconnected =
            incoming_body_failure_response(Version::Http11, &IncomingBodyError::SourceDisconnected)
                .expect("pre-head internal producer loss has a safe response");
        assert_eq!(disconnected.status, 500);
        assert_eq!(disconnected.body, b"request body producer disconnected");

        let accounting =
            incoming_body_failure_response(Version::Http11, &IncomingBodyError::AccountingOverflow)
                .expect("pre-head accounting overflow is an internal response");
        assert_eq!(accounting.status, 500);
        assert!(!accounting.body.starts_with(b"[ASUP-E505]"));

        assert!(
            incoming_body_failure_response(
                Version::Http11,
                &IncomingBodyError::DrainLimitExceeded {
                    bytes: 9,
                    frames: 2,
                    frame_limit: 1,
                    byte_limit: 8,
                },
            )
            .is_none(),
            "drain-budget exhaustion must remain close-only"
        );
    }

    impl AsyncRead for TestIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(kind) = self.read_error {
                return Poll::Ready(Err(io::Error::from(kind)));
            }
            if self.read_data.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let n = buf
                .remaining()
                .min(self.read_data.len())
                .min(self.read_limit);
            buf.put_slice(&self.read_data[..n]);
            self.read_data.drain(..n);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TestIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug, Clone)]
    struct WriteGateObservation {
        source_calls: usize,
        eof_calls: usize,
        written: Vec<u8>,
    }

    #[derive(Debug, Clone, Copy)]
    enum BodyWriteDisposition {
        GateOnceBeforeObservation { after_writes: usize },
        GateOnceAfterObservation { after_writes: usize },
        GateFlushOnceAfterObservation { after_writes: usize },
        FailAfter { after_writes: usize },
    }

    struct ScriptedWriteIo {
        read_data: Vec<u8>,
        written: Arc<Mutex<Vec<u8>>>,
        source_calls: Arc<AtomicUsize>,
        eof_calls: Arc<AtomicUsize>,
        observation: Arc<Mutex<Option<WriteGateObservation>>>,
        disposition: BodyWriteDisposition,
        head_complete: bool,
        accepted_body_writes: usize,
        gate_stage: u8,
    }

    impl ScriptedWriteIo {
        fn new(
            written: Arc<Mutex<Vec<u8>>>,
            source_calls: Arc<AtomicUsize>,
            eof_calls: Arc<AtomicUsize>,
            observation: Arc<Mutex<Option<WriteGateObservation>>>,
            disposition: BodyWriteDisposition,
        ) -> Self {
            Self {
                read_data: b"GET /events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                    .to_vec(),
                written,
                source_calls,
                eof_calls,
                observation,
                disposition,
                head_complete: false,
                accepted_body_writes: 0,
                gate_stage: 0,
            }
        }

        fn observe_gate(&self) {
            let observation = WriteGateObservation {
                source_calls: self.source_calls.load(Ordering::SeqCst),
                eof_calls: self.eof_calls.load(Ordering::SeqCst),
                written: self.written.lock().unwrap().clone(),
            };
            *self.observation.lock().unwrap() = Some(observation);
        }
    }

    impl AsyncRead for ScriptedWriteIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.read_data.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let count = buf.remaining().min(self.read_data.len());
            buf.put_slice(&self.read_data[..count]);
            self.read_data.drain(..count);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ScriptedWriteIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            task_cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if !self.head_complete {
                self.written.lock().unwrap().extend_from_slice(buf);
                let head_complete = self
                    .written
                    .lock()
                    .unwrap()
                    .windows(4)
                    .any(|window| window == b"\r\n\r\n");
                self.head_complete = head_complete;
                return Poll::Ready(Ok(buf.len()));
            }

            let after_writes = match self.disposition {
                BodyWriteDisposition::GateOnceBeforeObservation { after_writes }
                | BodyWriteDisposition::GateOnceAfterObservation { after_writes }
                | BodyWriteDisposition::GateFlushOnceAfterObservation { after_writes }
                | BodyWriteDisposition::FailAfter { after_writes } => after_writes,
            };
            if self.accepted_body_writes >= after_writes {
                match self.disposition {
                    BodyWriteDisposition::GateOnceBeforeObservation { .. }
                        if self.gate_stage == 0 =>
                    {
                        self.observe_gate();
                        self.gate_stage = 1;
                        task_cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    BodyWriteDisposition::GateOnceAfterObservation { .. }
                        if self.gate_stage == 0 =>
                    {
                        self.gate_stage = 1;
                        task_cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    BodyWriteDisposition::GateOnceAfterObservation { .. }
                        if self.gate_stage == 1 =>
                    {
                        self.observe_gate();
                        self.gate_stage = 2;
                        task_cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    BodyWriteDisposition::GateOnceAfterObservation { .. }
                        if self.gate_stage == 2 =>
                    {
                        let observed_calls = self
                            .observation
                            .lock()
                            .unwrap()
                            .as_ref()
                            .expect("capacity gate observation")
                            .source_calls;
                        assert_eq!(
                            self.source_calls.load(Ordering::SeqCst),
                            observed_calls,
                            "bounded producer progress must remain stable while the transport stays pending"
                        );
                        self.gate_stage = 3;
                    }
                    BodyWriteDisposition::GateOnceAfterObservation { .. } => {}
                    BodyWriteDisposition::GateFlushOnceAfterObservation { .. } => {}
                    BodyWriteDisposition::FailAfter { .. } => {
                        if self.gate_stage == 0 {
                            self.observe_gate();
                            self.gate_stage = 1;
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "scripted SSE client disconnect",
                        )));
                    }
                    BodyWriteDisposition::GateOnceBeforeObservation { .. } => {}
                }
            }

            self.written.lock().unwrap().extend_from_slice(buf);
            self.accepted_body_writes += 1;
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, task_cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if let BodyWriteDisposition::GateFlushOnceAfterObservation { after_writes } =
                self.disposition
                && self.accepted_body_writes >= after_writes
            {
                if self.gate_stage == 0 {
                    self.observe_gate();
                    self.gate_stage = 1;
                    task_cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                if self.gate_stage == 1 {
                    let observed_calls = self
                        .observation
                        .lock()
                        .unwrap()
                        .as_ref()
                        .expect("flush gate observation")
                        .source_calls;
                    assert_eq!(
                        self.source_calls.load(Ordering::SeqCst),
                        observed_calls,
                        "bounded producer progress must remain stable while flush stays pending"
                    );
                    self.gate_stage = 2;
                }
            }
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct CountingSseSource {
        events: VecDeque<SseEvent>,
        infinite: bool,
        fail_on_call: Option<usize>,
        source_calls: Arc<AtomicUsize>,
        eof_calls: Arc<AtomicUsize>,
        cancel_calls: Arc<AtomicUsize>,
    }

    impl CountingSseSource {
        fn finite(
            events: impl IntoIterator<Item = &'static str>,
            source_calls: Arc<AtomicUsize>,
            eof_calls: Arc<AtomicUsize>,
            cancel_calls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                events: events
                    .into_iter()
                    .map(|data| SseEvent::default().data(data))
                    .collect(),
                infinite: false,
                fail_on_call: None,
                source_calls,
                eof_calls,
                cancel_calls,
            }
        }

        fn infinite(
            source_calls: Arc<AtomicUsize>,
            eof_calls: Arc<AtomicUsize>,
            cancel_calls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                events: VecDeque::new(),
                infinite: true,
                fail_on_call: None,
                source_calls,
                eof_calls,
                cancel_calls,
            }
        }

        fn failing_after_two_events(
            source_calls: Arc<AtomicUsize>,
            eof_calls: Arc<AtomicUsize>,
            cancel_calls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                events: ["first", "second"]
                    .into_iter()
                    .map(|data| SseEvent::default().data(data))
                    .collect(),
                infinite: false,
                fail_on_call: Some(3),
                source_calls,
                eof_calls,
                cancel_calls,
            }
        }
    }

    impl StreamingSseSource for CountingSseSource {
        fn next_event(&mut self, cx: &Cx) -> Result<Option<SseEvent>, StreamingSseError> {
            cx.checkpoint().map_err(|_| StreamingSseError::Cancelled)?;
            let call = self.source_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.fail_on_call == Some(call) {
                return Err(StreamingSseError::Producer(
                    "scripted producer failure".to_owned(),
                ));
            }
            if let Some(event) = self.events.pop_front() {
                return Ok(Some(event));
            }
            if self.infinite {
                return Ok(Some(SseEvent::default().data(format!("event-{call}"))));
            }
            self.eof_calls.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }

        fn cancel(&mut self) {
            self.cancel_calls.fetch_add(1, Ordering::SeqCst);
            self.events.clear();
        }
    }

    fn response_body_bytes(response: &[u8]) -> &[u8] {
        let head_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("response head terminator")
            + 4;
        &response[head_end..]
    }

    fn localhost_server_config() -> Http1Config {
        Http1Config::default().host_policy(HostPolicy::AllowList(vec!["localhost".to_string()]))
    }

    #[test]
    fn streaming_sse_server_writes_first_chunk_before_source_eof() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let source_calls = Arc::new(AtomicUsize::new(0));
        let eof_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let observation = Arc::new(Mutex::new(None));
        let source = CountingSseSource::finite(
            ["first", "second", "third"],
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&cancel_calls),
        );
        let source = Arc::new(Mutex::new(Some(source)));
        let source_for_handler = Arc::clone(&source);
        let server = Http1StreamingServer::with_config_sse(
            move |_cx, _request| {
                let source = source_for_handler
                    .lock()
                    .unwrap()
                    .take()
                    .expect("one live SSE request");
                async move { StreamingSse::from_source(source).into_http1_response(NonZeroUsize::MIN) }
            },
            localhost_server_config(),
        );
        let io = ScriptedWriteIo::new(
            Arc::clone(&written),
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&observation),
            BodyWriteDisposition::GateOnceBeforeObservation { after_writes: 1 },
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_sse(&cx, io).await
            })
            .expect("serve live SSE response");

        assert_eq!(state.requests_served, 1);
        let observed = observation
            .lock()
            .unwrap()
            .clone()
            .expect("second body write reached causal gate");
        assert_eq!(observed.eof_calls, 0);
        assert!(observed.source_calls >= 2);
        assert_eq!(
            response_body_bytes(&observed.written),
            ChunkedEncoder::encode_chunk(b"data:first\n\n").as_ref()
        );

        let written = written.lock().unwrap().clone();
        let body = response_body_bytes(&written);
        let mut expected = Vec::new();
        for event in ["first", "second", "third"] {
            expected.extend_from_slice(
                ChunkedEncoder::encode_chunk(format!("data:{event}\n\n").as_bytes()).as_ref(),
            );
        }
        expected.extend_from_slice(b"0\r\n\r\n");
        assert_eq!(body, expected);
        assert_eq!(eof_calls.load(Ordering::SeqCst), 1);
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn streaming_sse_server_real_tcp_delivers_multiple_chunks_before_disconnect() {
        let source_calls = Arc::new(AtomicUsize::new(0));
        let eof_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let source = CountingSseSource::infinite(
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&cancel_calls),
        );
        let source = Arc::new(Mutex::new(Some(source)));
        let source_for_handler = Arc::clone(&source);
        let server = Http1StreamingServer::with_config_sse(
            move |_cx, _request| {
                let source = source_for_handler
                    .lock()
                    .unwrap()
                    .take()
                    .expect("one live SSE request");
                async move { StreamingSse::from_source(source).into_http1_response(NonZeroUsize::MIN) }
            },
            localhost_server_config(),
        );

        let raw_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = raw_listener
            .local_addr()
            .expect("loopback listener address");
        let client = std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};

            let mut client =
                std::net::TcpStream::connect(address).expect("connect loopback client");
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set client read timeout");
            client
                .write_all(b"GET /events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .expect("write live SSE request");

            let first = ChunkedEncoder::encode_chunk(b"data:event-1\n\n");
            let second = ChunkedEncoder::encode_chunk(b"data:event-2\n\n");
            let mut received = Vec::new();
            while !received
                .windows(first.len())
                .any(|window| window == first.as_ref())
                || !received
                    .windows(second.len())
                    .any(|window| window == second.as_ref())
            {
                let mut buffer = [0_u8; 4096];
                let count = client.read(&mut buffer).expect("read live SSE bytes");
                assert_ne!(count, 0, "connection closed before two live SSE chunks");
                received.extend_from_slice(&buffer[..count]);
            }
            assert!(
                !response_body_bytes(&received)
                    .windows(5)
                    .any(|window| window == b"0\r\n\r\n"),
                "an infinite live source must not publish a clean terminator"
            );
            received
        });
        let (server_raw, _) = raw_listener.accept().expect("accept loopback client");
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                let stream = crate::net::tcp::stream::TcpStream::from_std(server_raw)
                    .expect("wrap loopback server stream");
                server.serve_sse(&cx, stream).await
            })
            .expect_err("client close must terminate the infinite live source");
        let received = client.join().expect("join loopback client");

        assert!(matches!(error, HttpError::Io(_)));
        assert!(
            response_body_bytes(&received)
                .starts_with(ChunkedEncoder::encode_chunk(b"data:event-1\n\n").as_ref())
        );
        assert_eq!(eof_calls.load(Ordering::SeqCst), 0);
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn produced_h1_envelope_capacity_one_does_not_poll_during_pending_write() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let source_calls = Arc::new(AtomicUsize::new(0));
        let eof_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let observation = Arc::new(Mutex::new(None));
        let source = CountingSseSource::finite(
            ["one", "two", "three", "four"],
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&cancel_calls),
        );
        let source = Arc::new(Mutex::new(Some(source)));
        let source_for_handler = Arc::clone(&source);
        let server = Http1StreamingServer::with_config_sse(
            move |_cx, _request| {
                let source = source_for_handler
                    .lock()
                    .unwrap()
                    .take()
                    .expect("one live SSE request");
                async move { StreamingSse::from_source(source).into_http1_response(NonZeroUsize::MIN) }
            },
            localhost_server_config(),
        );
        let io = ScriptedWriteIo::new(
            Arc::clone(&written),
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&observation),
            BodyWriteDisposition::GateOnceAfterObservation { after_writes: 0 },
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_sse(&cx, io).await
            })
            .expect("serve capacity-one SSE response");

        let observed = observation
            .lock()
            .unwrap()
            .clone()
            .expect("blocked first body write was observed after one pending poll");
        assert_eq!(
            observed.source_calls, 2,
            "one queued event plus one pending send is the complete bounded runahead"
        );
        assert_eq!(observed.eof_calls, 0);
        assert!(response_body_bytes(&observed.written).is_empty());
        assert_eq!(eof_calls.load(Ordering::SeqCst), 1);
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn produced_h1_envelope_capacity_one_does_not_poll_during_pending_flush() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let source_calls = Arc::new(AtomicUsize::new(0));
        let eof_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let observation = Arc::new(Mutex::new(None));
        let source = CountingSseSource::finite(
            ["one", "two", "three", "four"],
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&cancel_calls),
        );
        let source = Arc::new(Mutex::new(Some(source)));
        let source_for_handler = Arc::clone(&source);
        let server = Http1StreamingServer::with_config_sse(
            move |_cx, _request| {
                let source = source_for_handler
                    .lock()
                    .unwrap()
                    .take()
                    .expect("one live SSE request");
                async move { StreamingSse::from_source(source).into_http1_response(NonZeroUsize::MIN) }
            },
            localhost_server_config(),
        );
        let io = ScriptedWriteIo::new(
            Arc::clone(&written),
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&observation),
            BodyWriteDisposition::GateFlushOnceAfterObservation { after_writes: 1 },
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_sse(&cx, io).await
            })
            .expect("serve capacity-one SSE response");

        let observed = observation
            .lock()
            .unwrap()
            .clone()
            .expect("blocked first body flush was observed");
        assert_eq!(
            response_body_bytes(&observed.written),
            ChunkedEncoder::encode_chunk(b"data:one\n\n").as_ref()
        );
        assert_eq!(observed.eof_calls, 0);
        assert_eq!(eof_calls.load(Ordering::SeqCst), 1);
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn streaming_sse_server_disconnect_cancels_source_without_terminator() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let source_calls = Arc::new(AtomicUsize::new(0));
        let eof_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let observation = Arc::new(Mutex::new(None));
        let source = CountingSseSource::infinite(
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&cancel_calls),
        );
        let source = Arc::new(Mutex::new(Some(source)));
        let source_for_handler = Arc::clone(&source);
        let server = Http1StreamingServer::with_config_sse(
            move |_cx, _request| {
                let source = source_for_handler
                    .lock()
                    .unwrap()
                    .take()
                    .expect("one live SSE request");
                async move { StreamingSse::from_source(source).into_http1_response(NonZeroUsize::MIN) }
            },
            localhost_server_config(),
        );
        let io = ScriptedWriteIo::new(
            Arc::clone(&written),
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            observation,
            BodyWriteDisposition::FailAfter { after_writes: 1 },
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_sse(&cx, io).await
            })
            .expect_err("scripted disconnect must fail the live response");

        assert!(
            matches!(error, HttpError::Io(ref error) if error.kind() == io::ErrorKind::BrokenPipe)
        );
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);
        assert_eq!(eof_calls.load(Ordering::SeqCst), 0);
        let calls_after_return = source_calls.load(Ordering::SeqCst);
        std::thread::yield_now();
        assert_eq!(source_calls.load(Ordering::SeqCst), calls_after_return);
        let written = written.lock().unwrap().clone();
        assert_eq!(
            response_body_bytes(&written),
            ChunkedEncoder::encode_chunk(b"data:event-1\n\n").as_ref()
        );
        assert!(
            !response_body_bytes(&written)
                .windows(5)
                .any(|window| window == b"0\r\n\r\n")
        );
    }

    #[test]
    fn streaming_sse_server_producer_error_closes_without_terminator() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let source_calls = Arc::new(AtomicUsize::new(0));
        let eof_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let source = CountingSseSource::failing_after_two_events(
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&cancel_calls),
        );
        let source = Arc::new(Mutex::new(Some(source)));
        let source_for_handler = Arc::clone(&source);
        let server = Http1StreamingServer::with_config_sse(
            move |_cx, _request| {
                let source = source_for_handler
                    .lock()
                    .unwrap()
                    .take()
                    .expect("one live SSE request");
                async move { StreamingSse::from_source(source).into_http1_response(NonZeroUsize::MIN) }
            },
            localhost_server_config(),
        );
        let io = TestIo::new(
            b"GET /events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_sse(&cx, io).await
            })
            .expect_err("producer failure must fail the live response");

        assert!(
            matches!(error, HttpError::Io(ref source) if source.to_string().contains("scripted producer failure"))
        );
        assert_eq!(source_calls.load(Ordering::SeqCst), 3);
        assert_eq!(eof_calls.load(Ordering::SeqCst), 0);
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);
        let written = written.lock().unwrap().clone();
        let mut expected = ChunkedEncoder::encode_chunk(b"data:first\n\n").into_vec();
        expected.extend_from_slice(ChunkedEncoder::encode_chunk(b"data:second\n\n").as_ref());
        assert_eq!(
            response_body_bytes(&written),
            expected,
            "frames already committed to the body channel must drain before the producer error closes the connection"
        );
        assert!(
            !response_body_bytes(&written)
                .windows(5)
                .any(|window| window == b"0\r\n\r\n")
        );
    }

    #[test]
    fn streaming_sse_server_head_never_polls_source_or_emits_chunked_body() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let source_calls = Arc::new(AtomicUsize::new(0));
        let eof_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let source = CountingSseSource::finite(
            ["must-not-run"],
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&cancel_calls),
        );
        let source = Arc::new(Mutex::new(Some(source)));
        let source_for_handler = Arc::clone(&source);
        let server = Http1StreamingServer::with_config_sse(
            move |_cx, _request| {
                let source = source_for_handler
                    .lock()
                    .unwrap()
                    .take()
                    .expect("one live SSE request");
                async move { StreamingSse::from_source(source).into_http1_response(NonZeroUsize::MIN) }
            },
            localhost_server_config(),
        );
        let io = TestIo::new(
            b"HEAD /events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_sse(&cx, io).await
            })
            .expect("serve SSE HEAD response");

        assert_eq!(source_calls.load(Ordering::SeqCst), 0);
        assert_eq!(eof_calls.load(Ordering::SeqCst), 0);
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);
        let written = written.lock().unwrap().clone();
        let head = String::from_utf8_lossy(&written);
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(head.contains("content-type: text/event-stream\r\n"));
        assert!(!head.contains("Transfer-Encoding"));
        assert!(response_body_bytes(&written).is_empty());
    }

    #[test]
    fn streaming_sse_server_connect_is_rejected_before_source_poll() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let source_calls = Arc::new(AtomicUsize::new(0));
        let eof_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let source = CountingSseSource::finite(
            ["must-not-run"],
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&cancel_calls),
        );
        let source = Arc::new(Mutex::new(Some(source)));
        let source_for_handler = Arc::clone(&source);
        let server = Http1StreamingServer::with_config_sse(
            move |_cx, _request| {
                let source = source_for_handler
                    .lock()
                    .unwrap()
                    .take()
                    .expect("one live SSE request");
                async move { StreamingSse::from_source(source).into_http1_response(NonZeroUsize::MIN) }
            },
            localhost_server_config(),
        );
        let io = TestIo::new(
            b"CONNECT example.test:443 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                .to_vec(),
            Arc::clone(&written),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_sse(&cx, io).await
            })
            .expect("reject CONNECT before live SSE framing");

        assert_eq!(source_calls.load(Ordering::SeqCst), 0);
        assert_eq!(eof_calls.load(Ordering::SeqCst), 0);
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);
        let written = written.lock().unwrap().clone();
        let head = String::from_utf8_lossy(&written);
        assert!(head.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        assert!(head.contains("Allow: GET, HEAD\r\n"));
        assert!(!head.contains("Transfer-Encoding"));
    }

    #[test]
    fn streaming_sse_server_rejects_trailers_without_clean_terminator() {
        let mut encoder = ChunkedEncoder::new();
        let mut destination = BytesMut::new();

        let error = encode_live_sse_frame(
            &mut encoder,
            Frame::trailers(crate::http::body::HeaderMap::new()),
            &mut destination,
        )
        .expect_err("live SSE trailers must fail closed");

        assert!(matches!(error, HttpError::TrailersNotAllowed));
        assert!(destination.is_empty());
        assert!(!encoder.is_finished());
    }

    #[test]
    fn streaming_sse_server_empty_source_writes_one_clean_terminator() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_sse(
            |_cx, _request| async move { StreamingSse::empty().into_http1_response(NonZeroUsize::MIN) },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_sse(&cx, io).await
            })
            .expect("serve empty SSE response");

        assert_eq!(state.requests_served, 1);
        let written = written.lock().unwrap().clone();
        let head = String::from_utf8_lossy(&written);
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(head.contains("Transfer-Encoding: chunked\r\n"));
        assert!(head.contains("content-type: text/event-stream\r\n"));
        assert_eq!(response_body_bytes(&written), b"0\r\n\r\n");
    }

    #[test]
    fn produced_chunked_response_writes_multiple_frames_and_one_terminator() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::chunked(
                    NonZeroUsize::MIN,
                    200,
                    "OK",
                    |producer_cx, mut sender| async move {
                        sender.send_chunk(&producer_cx, b"alpha").await?;
                        sender.send_chunk(&producer_cx, b"beta").await?;
                        sender.finish(&producer_cx)?;
                        Ok(sender)
                    },
                )
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect("serve generic produced response");

        assert_eq!(state.requests_served, 1);
        let written = written.lock().unwrap().clone();
        let mut expected = ChunkedEncoder::encode_chunk(b"alpha").into_vec();
        expected.extend_from_slice(ChunkedEncoder::encode_chunk(b"beta").as_ref());
        expected.extend_from_slice(b"0\r\n\r\n");
        assert_eq!(response_body_bytes(&written), expected);
    }

    #[test]
    fn produced_deferred_initial_headers_precede_body_after_parked_service_setup() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let observed = Arc::clone(&written);
        let setup_polls = Arc::new(AtomicUsize::new(0));
        let setup_observed = Arc::clone(&setup_polls);
        let server = Http1StreamingServer::with_config_produced(
            move |_cx, _request| {
                let written = Arc::clone(&observed);
                let setup_polls = Arc::clone(&setup_observed);
                async move {
                    Http1ProducedResponse::chunked(
                        NonZeroUsize::MIN,
                        200,
                        "OK",
                        move |producer_cx, mut sender| async move {
                            poll_fn(|task_cx| {
                                assert!(written.lock().unwrap().is_empty(), "head escaped before service metadata");
                                if setup_polls.fetch_add(1, Ordering::SeqCst) == 0 {
                                    task_cx.waker().wake_by_ref();
                                    Poll::Pending
                                } else {
                                    Poll::Ready(())
                                }
                            }).await;
                            let mut headers = HeaderMap::new();
                            headers.insert(HeaderName::from_static("x-initial"), HeaderValue::from_static("ready"));
                            sender.send_initial_headers(headers)?;
                            sender.send_chunk(&producer_cx, b"alpha").await?;
                            sender.send_chunk(&producer_cx, b"beta").await?;
                            sender.finish(&producer_cx)?;
                            Ok(sender)
                        },
                    ).defer_initial_headers()
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread().build().expect("native runtime");
        let state = runtime.block_on(async {
            let cx = Cx::current().expect("runtime context");
            server.serve_produced(&cx, io).await
        }).expect("deferred produced response");
        assert_eq!(state.requests_served, 1);
        assert!(setup_polls.load(Ordering::SeqCst) >= 2, "service setup actually parked");
        let written = written.lock().unwrap().clone();
        let header_end = written.windows(4).position(|bytes| bytes == b"\r\n\r\n").unwrap();
        let head = std::str::from_utf8(&written[..header_end]).unwrap();
        assert_eq!(head.matches("x-initial: ready").count(), 1);
        assert_eq!(response_body_bytes(&written), b"5\r\nalpha\r\n4\r\nbeta\r\n0\r\n\r\n");
    }

    #[test]
    fn produced_deferred_initial_header_abandonment_never_commits_success_head() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::chunked(
                    NonZeroUsize::MIN,
                    200,
                    "OK",
                    |_producer_cx, _sender| async move { Err(HttpError::BadHeader) },
                ).defer_initial_headers()
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread().build().expect("native runtime");
        let error = runtime.block_on(async {
            let cx = Cx::current().expect("runtime context");
            server.serve_produced(&cx, io).await
        }).expect_err("abandoned setup is not a complete response");
        assert!(matches!(error, HttpError::BadHeader));
        assert!(written.lock().unwrap().is_empty(), "abandoned setup must not publish any response bytes");
    }

    #[test]
    fn produced_content_length_writes_raw_frames_without_chunk_terminator() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /fixed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::with_content_length(
                    NonZeroUsize::MIN,
                    200,
                    "OK",
                    9,
                    |producer_cx, mut sender| async move {
                        sender.send_chunk(&producer_cx, b"alpha").await?;
                        sender.send_chunk(&producer_cx, b"beta").await?;
                        sender.finish(&producer_cx)?;
                        Ok(sender)
                    },
                )
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect("serve exact fixed-length response");

        let written = written.lock().unwrap().clone();
        let head = String::from_utf8_lossy(&written);
        assert!(head.contains("Content-Length: 9\r\n"));
        assert!(!head.contains("Transfer-Encoding"));
        assert_eq!(response_body_bytes(&written), b"alphabeta");
    }

    #[test]
    fn produced_content_length_overrun_refuses_excess_data() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /fixed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::with_content_length(
                    NonZeroUsize::MIN,
                    200,
                    "OK",
                    4,
                    |producer_cx, mut sender| async move {
                        sender.send_chunk(&producer_cx, b"four").await?;
                        sender.send_chunk(&producer_cx, b"x").await?;
                        sender.finish(&producer_cx)?;
                        Ok(sender)
                    },
                )
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("fixed-length overrun must fail closed");

        assert!(matches!(error, HttpError::BadContentLength));
        let written = written.lock().unwrap().clone();
        assert_eq!(response_body_bytes(&written), b"four");
    }

    #[test]
    fn produced_content_length_underrun_preserves_partial_data_then_fails() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /fixed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::with_content_length(
                    NonZeroUsize::MIN,
                    200,
                    "OK",
                    5,
                    |producer_cx, mut sender| async move {
                        sender.send_chunk(&producer_cx, b"four").await?;
                        sender.finish(&producer_cx)?;
                        Ok(sender)
                    },
                )
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("fixed-length underrun must fail closed");

        assert!(matches!(error, HttpError::BadContentLength));
        let written = written.lock().unwrap().clone();
        assert_eq!(response_body_bytes(&written), b"four");
    }

    #[test]
    fn produced_content_length_rejects_finished_sender_from_foreign_channel() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /fixed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::with_content_length(
                    NonZeroUsize::MIN,
                    200,
                    "OK",
                    5,
                    |producer_cx, mut sender| async move {
                        sender.send_chunk(&producer_cx, b"four").await?;
                        drop(sender);
                        let (foreign_sender, _foreign_body) =
                            crate::http::h1::stream::OutgoingBody::channel(
                                &producer_cx,
                                BodyKind::ContentLength(0),
                            );
                        assert!(foreign_sender.is_finished());
                        Ok(foreign_sender)
                    },
                )
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("foreign finished sender must not authenticate a truncated response");

        assert!(matches!(error, HttpError::BodyChannelClosed));
        let written = written.lock().unwrap().clone();
        assert_eq!(response_body_bytes(&written), b"four");
    }

    #[test]
    fn produced_content_length_head_preserves_metadata_without_factory() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let calls_for_handler = Arc::clone(&factory_calls);
        let io = TestIo::new(
            b"HEAD /fixed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            move |_cx, _request| {
                let factory_calls = Arc::clone(&calls_for_handler);
                async move {
                    Http1ProducedResponse::with_content_length(
                        NonZeroUsize::MIN,
                        200,
                        "OK",
                        42,
                        move |_producer_cx, sender| {
                            factory_calls.fetch_add(1, Ordering::SeqCst);
                            async move { Ok(sender) }
                        },
                    )
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect("serve fixed-length HEAD response");

        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        let written = written.lock().unwrap().clone();
        let head = String::from_utf8_lossy(&written);
        assert!(head.contains("Content-Length: 42\r\n"));
        assert!(!head.contains("Transfer-Encoding"));
        assert!(response_body_bytes(&written).is_empty());
    }

    #[test]
    fn produced_content_length_mismatch_fails_before_factory_and_head() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let calls_for_handler = Arc::clone(&factory_calls);
        let io = TestIo::new(
            b"GET /fixed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            move |_cx, _request| {
                let factory_calls = Arc::clone(&calls_for_handler);
                async move {
                    let mut response = Http1ProducedResponse::with_content_length(
                        NonZeroUsize::MIN,
                        200,
                        "OK",
                        7,
                        move |_producer_cx, sender| {
                            factory_calls.fetch_add(1, Ordering::SeqCst);
                            async move { Ok(sender) }
                        },
                    );
                    response
                        .head_mut()
                        .headers
                        .iter_mut()
                        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                        .expect("constructor Content-Length")
                        .1 = "8".to_owned();
                    response
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("mismatched fixed-length head must fail before commit");

        assert!(matches!(error, HttpError::BadContentLength));
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        assert!(written.lock().unwrap().is_empty());
    }

    #[test]
    fn produced_content_length_head_validation_rejects_invalid_framing() {
        let validate = |headers: Vec<(&str, &str)>| {
            let mut head = ResponseHead::new(200, "OK");
            head.headers.extend(
                headers
                    .into_iter()
                    .map(|(name, value)| (name.to_owned(), value.to_owned())),
            );
            validate_produced_response_head(&mut head, BodyKind::ContentLength(7))
        };

        assert!(validate(vec![("Content-Length", "7")]).is_ok());
        assert!(matches!(
            validate(Vec::new()),
            Err(HttpError::BadContentLength)
        ));
        assert!(matches!(
            validate(vec![("Content-Length", "+7")]),
            Err(HttpError::BadContentLength)
        ));
        assert!(matches!(
            validate(vec![("Content-Length", "8")]),
            Err(HttpError::BadContentLength)
        ));
        assert!(matches!(
            validate(vec![("Content-Length", "7"), ("content-length", "7")]),
            Err(HttpError::DuplicateContentLength)
        ));
        assert!(matches!(
            validate(vec![
                ("Content-Length", "7"),
                ("Transfer-Encoding", "chunked")
            ]),
            Err(HttpError::AmbiguousBodyLength)
        ));
        assert!(matches!(
            validate(vec![("Content-Length", "7"), ("Trailer", "x-checksum")]),
            Err(HttpError::TrailersNotAllowed)
        ));
    }

    #[test]
    fn produced_content_length_trailer_declaration_fails_before_factory() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let calls_for_handler = Arc::clone(&factory_calls);
        let io = TestIo::new(
            b"GET /fixed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            move |_cx, _request| {
                let factory_calls = Arc::clone(&calls_for_handler);
                async move {
                    Http1ProducedResponse::with_content_length(
                        NonZeroUsize::MIN,
                        200,
                        "OK",
                        7,
                        move |_producer_cx, sender| {
                            factory_calls.fetch_add(1, Ordering::SeqCst);
                            async move { Ok(sender) }
                        },
                    )
                    .with_header("Trailer", "x-checksum")
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("fixed-length trailer declaration must fail before commit");

        assert!(matches!(error, HttpError::TrailersNotAllowed));
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        assert!(written.lock().unwrap().is_empty());
    }

    #[test]
    fn produced_content_length_zero_runs_terminal_producer_without_data() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let calls_for_handler = Arc::clone(&factory_calls);
        let io = TestIo::new(
            b"GET /empty HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            move |_cx, _request| {
                let factory_calls = Arc::clone(&calls_for_handler);
                async move {
                    Http1ProducedResponse::with_content_length(
                        NonZeroUsize::MIN,
                        200,
                        "OK",
                        0,
                        move |producer_cx, mut sender| {
                            factory_calls.fetch_add(1, Ordering::SeqCst);
                            async move {
                                crate::runtime::yield_now().await;
                                assert!(sender.is_finished());
                                sender.finish(&producer_cx)?;
                                Ok(sender)
                            }
                        },
                    )
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect("serve zero-length produced response");

        assert_eq!(factory_calls.load(Ordering::SeqCst), 1);
        let written = written.lock().unwrap().clone();
        let head = String::from_utf8_lossy(&written);
        assert!(head.contains("Content-Length: 0\r\n"));
        assert!(response_body_bytes(&written).is_empty());
    }

    #[test]
    fn produced_h1_envelope_custom_limit_accepts_exact_frame() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::chunked_with_max_frame_bytes(
                    NonZeroUsize::MIN,
                    NonZeroUsize::new(4).unwrap(),
                    200,
                    "OK",
                    |producer_cx, mut sender| async move {
                        assert_eq!(sender.max_frame_bytes(), NonZeroUsize::new(4));
                        sender.send_chunk(&producer_cx, b"four").await?;
                        sender.finish(&producer_cx)?;
                        Ok(sender)
                    },
                )
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect("serve exact-boundary produced response");

        let written = written.lock().unwrap().clone();
        let mut expected = ChunkedEncoder::encode_chunk(b"four").into_vec();
        expected.extend_from_slice(b"0\r\n\r\n");
        assert_eq!(response_body_bytes(&written), expected);
    }

    #[test]
    fn produced_h1_envelope_default_limit_refuses_oversize_without_data() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::chunked(
                    NonZeroUsize::MIN,
                    200,
                    "OK",
                    |producer_cx, mut sender| async move {
                        let oversized = crate::bytes::Bytes::from(vec![
                            b'x';
                            Http1ProducedResponse::DEFAULT_MAX_FRAME_BYTES
                                + 1
                        ]);
                        sender.send_bytes(&producer_cx, oversized).await?;
                        sender.finish(&producer_cx)?;
                        Ok(sender)
                    },
                )
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("oversized produced DATA must fail closed");

        assert!(matches!(
            error,
            HttpError::BodyTooLargeDetailed {
                actual: 65_537,
                limit: 65_536
            }
        ));
        let written = written.lock().unwrap().clone();
        assert!(String::from_utf8_lossy(&written).starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response_body_bytes(&written).is_empty());
        assert!(!response_body_bytes(&written).ends_with(b"0\r\n\r\n"));
    }

    #[test]
    fn produced_chunked_response_drains_committed_frames_before_producer_error() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::chunked(
                    NonZeroUsize::new(2).unwrap(),
                    200,
                    "OK",
                    |producer_cx, mut sender| async move {
                        sender.send_chunk(&producer_cx, b"first").await?;
                        sender.send_chunk(&producer_cx, b"second").await?;
                        Err(io::Error::other("original produced-body failure").into())
                    },
                )
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("producer failure must fail the response");

        assert!(
            matches!(error, HttpError::Io(ref source) if source.to_string() == "original produced-body failure")
        );
        let written = written.lock().unwrap().clone();
        let mut expected = ChunkedEncoder::encode_chunk(b"first").into_vec();
        expected.extend_from_slice(ChunkedEncoder::encode_chunk(b"second").as_ref());
        assert_eq!(response_body_bytes(&written), expected);
        assert!(!response_body_bytes(&written).ends_with(b"0\r\n\r\n"));
    }

    #[test]
    fn produced_chunked_response_unfinished_success_drains_then_fails() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::chunked(
                    NonZeroUsize::MIN,
                    200,
                    "OK",
                    |producer_cx, mut sender| async move {
                        sender.send_chunk(&producer_cx, b"committed").await?;
                        Ok(sender)
                    },
                )
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("unfinished successful producer must fail closed");

        assert!(matches!(error, HttpError::BodyChannelClosed));
        let written = written.lock().unwrap().clone();
        assert_eq!(
            response_body_bytes(&written),
            ChunkedEncoder::encode_chunk(b"committed").as_ref()
        );
    }

    /// A producer commits DATA and its terminal trailers, then its own
    /// context is cancelled before the writer drains them. The committed
    /// frames, trailers included, are still written as a complete chunked
    /// response instead of being discarded behind the cancellation
    /// (br-asupersync-fy5kwg).
    #[test]
    fn produced_chunked_response_delivers_committed_trailers_after_producer_cancellation() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::chunked(
                    NonZeroUsize::new(2).unwrap(),
                    200,
                    "OK",
                    |producer_cx, mut sender| async move {
                        sender.send_chunk(&producer_cx, b"payload").await?;
                        let mut trailers = HeaderMap::new();
                        trailers.append(
                            HeaderName::from_static("x-checksum"),
                            HeaderValue::from_static("verified"),
                        );
                        sender.send_trailers(&producer_cx, trailers).await?;
                        producer_cx.cancel_with(
                            CancelKind::User,
                            Some("producer cancelled after committing its trailers"),
                        );
                        Ok(sender)
                    },
                )
                .with_header("Trailer", "x-checksum")
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect("committed trailers complete the response");

        let written = written.lock().unwrap().clone();
        let mut expected = ChunkedEncoder::encode_chunk(b"payload").into_vec();
        expected.extend_from_slice(b"0\r\nx-checksum: verified\r\n\r\n");
        assert_eq!(response_body_bytes(&written), expected);
    }

    fn serve_produced_then_cancel(
        content_length: bool,
        finish: bool,
    ) -> (Result<ConnectionState, HttpError>, Vec<u8>) {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let produce = move |producer_cx: Cx, mut sender: OutgoingBodySender| async move {
            sender.send_chunk(&producer_cx, b"payload").await?;
            if finish {
                sender.finish(&producer_cx)?;
            }
            producer_cx.cancel_with(CancelKind::User, Some("producer cancelled after its body"));
            Ok::<_, HttpError>(sender)
        };
        let server = Http1StreamingServer::with_config_produced(
            move |_cx, _request| async move {
                if content_length {
                    Http1ProducedResponse::with_content_length(
                        NonZeroUsize::new(2).unwrap(),
                        200,
                        "OK",
                        7,
                        produce,
                    )
                } else {
                    Http1ProducedResponse::chunked(
                        NonZeroUsize::new(2).unwrap(),
                        200,
                        "OK",
                        produce,
                    )
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        let result = runtime.block_on(async {
            let cx = Cx::current().expect("runtime connection context");
            server.serve_produced(&cx, io).await
        });
        let written = written.lock().unwrap().clone();
        (result, response_body_bytes(&written).to_vec())
    }

    #[test]
    fn produced_response_finished_before_producer_cancellation_is_complete() {
        // A body the producer finished is whole even if its context is
        // cancelled before the transport reads the end (br-asupersync-9c8r2c).
        let (result, body) = serve_produced_then_cancel(false, true);
        result.expect("a finished chunked body completes");
        let mut expected = ChunkedEncoder::encode_chunk(b"payload").into_vec();
        expected.extend_from_slice(b"0\r\n\r\n");
        assert_eq!(body, expected);

        let (result, body) = serve_produced_then_cancel(true, true);
        result.expect("a finished Content-Length body completes");
        assert_eq!(body, b"payload");
    }

    #[test]
    fn produced_response_abandoned_before_producer_cancellation_is_not_terminated() {
        // Without finish() the same bytes are a truncated body: no terminal
        // chunk may present it as complete.
        let (result, body) = serve_produced_then_cancel(false, false);
        assert!(result.is_err(), "an unfinished body must fail: {result:?}");
        assert_eq!(body, ChunkedEncoder::encode_chunk(b"payload").into_vec());
    }

    #[test]
    fn produced_chunked_response_writes_terminal_trailers_without_repoll() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let source_calls = Arc::new(AtomicUsize::new(0));
        let eof_calls = Arc::new(AtomicUsize::new(0));
        let observation = Arc::new(Mutex::new(None));
        let io = ScriptedWriteIo::new(
            Arc::clone(&written),
            source_calls,
            eof_calls,
            observation,
            BodyWriteDisposition::GateOnceBeforeObservation { after_writes: 1 },
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::chunked(
                    NonZeroUsize::MIN,
                    200,
                    "OK",
                    |producer_cx, mut sender| async move {
                        sender.send_chunk(&producer_cx, b"payload").await?;
                        let mut trailers = HeaderMap::new();
                        trailers.append(
                            HeaderName::from_static("x-checksum"),
                            HeaderValue::from_static("verified"),
                        );
                        sender.send_trailers(&producer_cx, trailers).await?;
                        Ok(sender)
                    },
                )
                .with_header("Trailer", "x-checksum")
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect("serve produced response with terminal trailers");

        let written = written.lock().unwrap().clone();
        let mut expected = ChunkedEncoder::encode_chunk(b"payload").into_vec();
        expected.extend_from_slice(b"0\r\nx-checksum: verified\r\n\r\n");
        assert_eq!(response_body_bytes(&written), expected);
    }

    #[test]
    fn produced_chunked_response_rejects_ambiguous_head_before_factory() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let factory_calls_for_handler = Arc::clone(&factory_calls);
        let io = TestIo::new(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            move |_cx, _request| {
                let factory_calls = Arc::clone(&factory_calls_for_handler);
                async move {
                    Http1ProducedResponse::chunked(
                        NonZeroUsize::MIN,
                        200,
                        "OK",
                        move |_producer_cx, sender| {
                            factory_calls.fetch_add(1, Ordering::SeqCst);
                            async move { Ok(sender) }
                        },
                    )
                    .with_header("Content-Length", "7")
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("Content-Length plus chunked must fail before head commit");

        assert!(matches!(error, HttpError::AmbiguousBodyLength));
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        assert!(written.lock().unwrap().is_empty());
    }

    #[test]
    fn produced_chunked_response_head_drops_factory_without_polling_or_framing() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let factory_calls_for_handler = Arc::clone(&factory_calls);
        let io = TestIo::new(
            b"HEAD /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            move |_cx, _request| {
                let factory_calls = Arc::clone(&factory_calls_for_handler);
                async move {
                    Http1ProducedResponse::chunked(
                        NonZeroUsize::MIN,
                        200,
                        "OK",
                        move |_producer_cx, sender| {
                            factory_calls.fetch_add(1, Ordering::SeqCst);
                            async move { Ok(sender) }
                        },
                    )
                    .with_header("Trailer", "x-checksum")
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect("serve produced HEAD response");

        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        let written = written.lock().unwrap().clone();
        let head = String::from_utf8_lossy(&written);
        assert!(!head.contains("Transfer-Encoding"));
        assert!(!head.contains("Trailer:"));
        assert!(response_body_bytes(&written).is_empty());
    }

    #[test]
    fn produced_chunked_response_rejects_body_forbidden_status_before_factory() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let factory_calls_for_handler = Arc::clone(&factory_calls);
        let io = TestIo::new(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            move |_cx, _request| {
                let factory_calls = Arc::clone(&factory_calls_for_handler);
                async move {
                    Http1ProducedResponse::chunked(
                        NonZeroUsize::MIN,
                        204,
                        "No Content",
                        move |_producer_cx, sender| {
                            factory_calls.fetch_add(1, Ordering::SeqCst);
                            async move { Ok(sender) }
                        },
                    )
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("204 chunked body must fail before head commit");

        assert!(matches!(error, HttpError::BadTransferEncoding));
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        assert!(written.lock().unwrap().is_empty());
    }

    #[test]
    fn produced_chunked_response_disconnect_cancels_and_drains_producer() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let producer_calls = Arc::new(AtomicUsize::new(0));
        let cancellation_calls = Arc::new(AtomicUsize::new(0));
        let observation = Arc::new(Mutex::new(None));
        let io = ScriptedWriteIo::new(
            Arc::clone(&written),
            Arc::clone(&producer_calls),
            Arc::new(AtomicUsize::new(0)),
            observation,
            BodyWriteDisposition::FailAfter { after_writes: 1 },
        );
        let producer_calls_for_handler = Arc::clone(&producer_calls);
        let cancellation_calls_for_handler = Arc::clone(&cancellation_calls);
        let server = Http1StreamingServer::with_config_produced(
            move |_cx, _request| {
                let producer_calls = Arc::clone(&producer_calls_for_handler);
                let cancellation_calls = Arc::clone(&cancellation_calls_for_handler);
                async move {
                    Http1ProducedResponse::chunked(
                        NonZeroUsize::MIN,
                        200,
                        "OK",
                        move |producer_cx, mut sender| async move {
                            loop {
                                producer_calls.fetch_add(1, Ordering::SeqCst);
                                if let Err(error) = sender.send_chunk(&producer_cx, b"live").await {
                                    cancellation_calls.fetch_add(1, Ordering::SeqCst);
                                    return Err(error);
                                }
                            }
                        },
                    )
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("scripted disconnect must fail the produced response");

        assert!(
            matches!(error, HttpError::Io(ref source) if source.kind() == io::ErrorKind::BrokenPipe)
        );
        assert_eq!(cancellation_calls.load(Ordering::SeqCst), 1);
        let written = written.lock().unwrap().clone();
        assert_eq!(
            response_body_bytes(&written),
            ChunkedEncoder::encode_chunk(b"live").as_ref()
        );
        assert!(!response_body_bytes(&written).ends_with(b"0\r\n\r\n"));
    }

    struct GatedBodyIo {
        head: Vec<u8>,
        body: Vec<u8>,
        release_marker: Vec<u8>,
        gated_polls: usize,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl GatedBodyIo {
        fn new(
            head: Vec<u8>,
            body: Vec<u8>,
            release_marker: Vec<u8>,
            written: Arc<Mutex<Vec<u8>>>,
        ) -> Self {
            Self {
                head,
                body,
                release_marker,
                gated_polls: 0,
                written,
            }
        }

        fn body_release_seen(&self) -> bool {
            let written = self.written.lock().unwrap();
            written
                .windows(self.release_marker.len())
                .any(|window| window == self.release_marker.as_slice())
        }
    }

    impl AsyncRead for GatedBodyIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if !self.head.is_empty() {
                let n = std::cmp::min(buf.remaining(), self.head.len());
                buf.put_slice(&self.head[..n]);
                self.head.drain(..n);
                return Poll::Ready(Ok(()));
            }

            if self.body.is_empty() {
                return Poll::Ready(Ok(()));
            }

            if self.body_release_seen() {
                let n = std::cmp::min(buf.remaining(), self.body.len());
                buf.put_slice(&self.body[..n]);
                self.body.drain(..n);
                return Poll::Ready(Ok(()));
            }

            self.gated_polls += 1;
            let written_so_far = self.written.lock().unwrap().clone();
            assert!(
                self.gated_polls < 8,
                "request body stayed gated because the server never emitted the expected interim response; wrote so far: {:?}",
                String::from_utf8_lossy(&written_so_far)
            );
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    impl AsyncWrite for GatedBodyIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct HeadFirstIo {
        head: Vec<u8>,
        body_and_pipeline: Vec<u8>,
        head_published: Arc<AtomicBool>,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncRead for HeadFirstIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let source = if self.head.is_empty() {
                assert!(
                    self.head_published.load(Ordering::SeqCst),
                    "server read request-body bytes before publishing the request head"
                );
                &mut self.body_and_pipeline
            } else {
                &mut self.head
            };
            if source.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let count = buf.remaining().min(source.len());
            buf.put_slice(&source[..count]);
            source.drain(..count);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for HeadFirstIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn make_request(version: Version, headers: Vec<(String, String)>) -> Request {
        Request {
            method: Method::Get,
            uri: "/".into(),
            version,
            headers,
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        }
    }

    #[test]
    fn should_close_connection_header_close() {
        let config = Http1Config::default();
        let state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(Version::Http11, vec![("Connection".into(), "close".into())]);
        assert!(should_close_connection(&req, &config, &state));
    }

    /// br-asupersync-t9yqht: validate_host_header MUST accept Host
    /// values that match the allow-list (case-insensitive,
    /// port-stripped) and reject all others including the missing-Host
    /// case which is itself an HTTP/1.1 protocol violation.
    #[test]
    fn validate_host_header_accepts_listed_rejects_others() {
        let policy = HostPolicy::allow_list(vec![
            "example.com".to_string(),
            "auth.example.com".to_string(),
        ]);

        // Listed host — accepted.
        let headers = vec![("Host".to_string(), "example.com".to_string())];
        assert!(validate_host_header(&headers, Version::Http11, &policy).is_ok());

        // Listed host with port — accepted (port stripped).
        let headers = vec![("Host".to_string(), "example.com:8080".to_string())];
        assert!(validate_host_header(&headers, Version::Http11, &policy).is_ok());

        // Case-insensitive match.
        let headers = vec![("Host".to_string(), "EXAMPLE.COM".to_string())];
        assert!(validate_host_header(&headers, Version::Http11, &policy).is_ok());

        // Different listed host.
        let headers = vec![("Host".to_string(), "auth.example.com".to_string())];
        assert!(validate_host_header(&headers, Version::Http11, &policy).is_ok());

        // Unlisted host — REJECTED with 421 Misdirected Request.
        let headers = vec![("Host".to_string(), "attacker.com".to_string())];
        let err = validate_host_header(&headers, Version::Http11, &policy).unwrap_err();
        assert_eq!(err, "attacker.com");
        assert_eq!(err.status(), 421);
        assert_eq!(err.reason(), "Misdirected Request");

        // Subdomain not in allowlist — REJECTED with 421 Misdirected Request.
        let headers = vec![("Host".to_string(), "evil.example.com".to_string())];
        let err = validate_host_header(&headers, Version::Http11, &policy).unwrap_err();
        assert_eq!(err, "evil.example.com");
        assert_eq!(err.status(), 421);

        // Missing Host header (HTTP/1.1 protocol violation per RFC 9112 §3.2 -> 400 Bad Request).
        let headers = vec![("X-Other".to_string(), "value".to_string())];
        let err = validate_host_header(&headers, Version::Http11, &policy).unwrap_err();
        assert_eq!(err, HostRejection::Missing);
        assert_eq!(err.status(), 400);
        assert_eq!(err.reason(), "Bad Request");
    }

    /// br-asupersync-scxixg: validation policies - AllowAll accepts any
    /// single Host, empty allow-list now rejects all (security fix),
    /// RejectUnknown rejects all.
    #[test]
    fn validate_host_header_policy_behaviors() {
        let headers = vec![("Host".to_string(), "anywhere.com".to_string())];

        // AllowAll rejects missing Host header per RFC 9112 §3.2 (HTTP/1.1 requires Host).
        let missing_headers = vec![("X-Other".to_string(), "value".to_string())];
        let err = validate_host_header(&missing_headers, Version::Http11, &HostPolicy::AllowAll)
            .unwrap_err();
        assert_eq!(err, HostRejection::Missing);
        assert_eq!(err.status(), 400);

        // AllowAll rejects syntactically invalid Host per RFC 9112 §3.2.
        let invalid_headers = vec![("Host".to_string(), "[::1]evil.test".to_string())];
        let err = validate_host_header(&invalid_headers, Version::Http11, &HostPolicy::AllowAll)
            .unwrap_err();
        assert_eq!(err.status(), 400);

        // AllowAll accepts any single valid Host header.
        assert!(validate_host_header(&headers, Version::Http11, &HostPolicy::AllowAll).is_ok());

        // Empty allowlist now REJECTS all hosts with 421 (security fix for br-asupersync-scxixg).
        let empty_policy = HostPolicy::allow_list(vec![]);
        let err = validate_host_header(&headers, Version::Http11, &empty_policy).unwrap_err();
        assert_eq!(err, "anywhere.com");
        assert_eq!(err.status(), 421);

        // RejectUnknown rejects all requests with 421 (secure default).
        let reject_policy = HostPolicy::RejectUnknown;
        let err = validate_host_header(&headers, Version::Http11, &reject_policy).unwrap_err();
        assert_eq!(err, "anywhere.com");
        assert_eq!(err.status(), 421);
    }

    #[test]
    fn validate_host_header_rejects_duplicate_host_headers() {
        let duplicate_hosts = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Host".to_string(), "attacker.com".to_string()),
        ];
        let allow_list = HostPolicy::allow_list(vec!["example.com".to_string()]);

        let err = validate_host_header(&duplicate_hosts, Version::Http11, &allow_list).unwrap_err();
        assert_eq!(err, HostRejection::Multiple);
        assert_eq!(err.status(), 400);

        let err = validate_host_header(
            &duplicate_hosts,
            Version::Http11,
            &HostPolicy::RejectUnknown,
        )
        .unwrap_err();
        assert_eq!(err, HostRejection::Multiple);
        assert_eq!(err.status(), 400);

        let err = validate_host_header(&duplicate_hosts, Version::Http11, &HostPolicy::AllowAll)
            .unwrap_err();
        assert_eq!(err, HostRejection::Multiple);
        assert_eq!(err.status(), 400);
    }

    /// AllowAll (also what `allowed_hosts(None)` builds) keeps serving the
    /// valid requests v0.4.3 served: RFC 9112 §3.2 requires Host only on
    /// HTTP/1.1.
    #[test]
    fn validate_host_header_allow_all_requires_host_only_on_http11() {
        let allow_all = HostPolicy::AllowAll;
        let no_host = vec![("Accept".to_string(), "*/*".to_string())];
        assert!(validate_host_header(&no_host, Version::Http10, &allow_all).is_ok());
        assert!(validate_host_header(&no_host, Version::Http2, &allow_all).is_ok());
        assert_eq!(
            validate_host_header(&no_host, Version::Http11, &allow_all),
            Err(HostRejection::Missing)
        );

        let duplicate = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Host".to_string(), "example.com".to_string()),
        ];
        assert_eq!(
            validate_host_header(&duplicate, Version::Http10, &allow_all),
            Err(HostRejection::Multiple)
        );
        // The restrictive policies still refuse a request they cannot match.
        let policy = HostPolicy::allow_list(vec!["example.com".to_string()]);
        assert_eq!(
            validate_host_header(&no_host, Version::Http10, &policy),
            Err(HostRejection::Missing)
        );
    }

    /// An empty Host (a target without an authority) and an empty port are
    /// valid syntax (RFC 9112 §3.2, RFC 3986 §3.2.3), so AllowAll serves them
    /// as v0.4.3 did; an invalid value is still a 400.
    #[test]
    fn validate_host_header_allow_all_accepts_empty_host_and_empty_port() {
        let allow_all = HostPolicy::AllowAll;
        for value in ["", "  ", "example.com:", "[::1]:", ":"] {
            let headers = vec![("Host".to_string(), value.to_string())];
            assert!(
                validate_host_header(&headers, Version::Http11, &allow_all).is_ok(),
                "{value:?}"
            );
        }
        for value in ["example.com::", "a b", "[::1", "a:b:"] {
            let headers = vec![("Host".to_string(), value.to_string())];
            assert_eq!(
                validate_host_header(&headers, Version::Http11, &allow_all),
                Err(HostRejection::Invalid(value.to_string()))
            );
        }
    }

    /// br-asupersync-scxixg: IPv6 literal handling — strip brackets
    /// and port correctly so allowed_hosts can be specified as the
    /// bracket-less host.
    #[test]
    fn validate_host_header_ipv6_literal_handling() {
        let policy = HostPolicy::allow_list(vec!["::1".to_string()]);

        // IPv6 literal with port.
        let headers = vec![("Host".to_string(), "[::1]:8080".to_string())];
        assert!(validate_host_header(&headers, Version::Http11, &policy).is_ok());

        // IPv6 literal without port.
        let headers = vec![("Host".to_string(), "[::1]".to_string())];
        assert!(validate_host_header(&headers, Version::Http11, &policy).is_ok());

        // Different IPv6 — REJECTED with 421 Misdirected Request.
        let headers = vec![("Host".to_string(), "[fe80::1]:8080".to_string())];
        let err = validate_host_header(&headers, Version::Http11, &policy).unwrap_err();
        assert_eq!(err, "fe80::1");
        assert_eq!(err.status(), 421);

        // Malformed IPv6 authority suffix must not bypass the allow-list and returns 400 Bad Request.
        let headers = vec![("Host".to_string(), "[::1]evil.test".to_string())];
        let err = validate_host_header(&headers, Version::Http11, &policy).unwrap_err();
        assert_eq!(err, "[::1]evil.test");
        assert_eq!(err.status(), 400);

        // Out-of-range ports are malformed authorities and must return 400 Bad Request.
        let headers = vec![("Host".to_string(), "[::1]:65536".to_string())];
        let err = validate_host_header(&headers, Version::Http11, &policy).unwrap_err();
        assert_eq!(err, "[::1]:65536");
        assert_eq!(err.status(), 400);
    }

    /// br-asupersync-t9yqht: parse_host_header_host handles edge
    /// cases (whitespace, empty, malformed).
    #[test]
    fn parse_host_header_host_handles_edges() {
        assert_eq!(
            parse_host_header_host("example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            parse_host_header_host("  example.com  ").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            parse_host_header_host("EXAMPLE.com:8080").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            parse_host_header_host("example.com:65535").as_deref(),
            Some("example.com")
        );
        assert_eq!(parse_host_header_host("example.com:65536").as_deref(), None);
        assert_eq!(
            parse_host_header_host("[2001:db8::1]:443").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(
            parse_host_header_host("[2001:db8::1]:65535").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(
            parse_host_header_host("[2001:db8::1]:65536").as_deref(),
            None
        );
        assert_eq!(parse_host_header_host("[2001:db8::1]evil").as_deref(), None);
        assert_eq!(
            parse_host_header_host("[2001:db8::1]:https").as_deref(),
            None
        );
        assert_eq!(parse_host_header_host("example.com:https").as_deref(), None);
        assert_eq!(parse_host_header_host("example.com:80:90").as_deref(), None);
        assert_eq!(parse_host_header_host("2001:db8::1").as_deref(), None);
        assert_eq!(parse_host_header_host(""), None);
        assert_eq!(parse_host_header_host("   "), None);
        assert_eq!(
            parse_host_header_host("\t example.com \t").as_deref(),
            Some("example.com")
        );
        assert_eq!(parse_host_header_host("\u{a0}example.com\u{a0}"), None);
        assert_eq!(parse_host_header_host("\u{a0}example.com:443"), None);
        assert_eq!(
            parse_host_header_host("münich.example").as_deref(),
            Some("münich.example"),
            "OWS hardening must not narrow the previously accepted non-whitespace Unicode host surface",
        );
    }

    #[test]
    fn should_close_connection_header_keepalive() {
        let config = Http1Config::default();
        let state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(
            Version::Http11,
            vec![("Connection".into(), "keep-alive".into())],
        );
        assert!(!should_close_connection(&req, &config, &state));
    }

    #[test]
    fn connection_tokens_use_only_rfc_ows() {
        let config = Http1Config::default();
        let state = ConnectionState::new(crate::types::Time::ZERO);

        let ascii_ows = make_request(
            Version::Http10,
            vec![("Connection".into(), "\t keep-alive \t".into())],
        );
        assert!(!should_close_connection(&ascii_ows, &config, &state));

        let unicode_whitespace = make_request(
            Version::Http10,
            vec![("Connection".into(), "\u{a0}keep-alive\u{a0}".into())],
        );
        assert!(should_close_connection(
            &unicode_whitespace,
            &config,
            &state
        ));

        let response =
            Response::new(200, "OK", Vec::new()).with_header("Connection", "\u{a0}close\u{a0}");
        assert!(!response_requests_close(&response));
    }

    #[test]
    fn should_close_http10_default() {
        let config = Http1Config::default();
        let state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(Version::Http10, vec![]);
        assert!(should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_http10_with_keepalive() {
        let config = Http1Config::default();
        let state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(
            Version::Http10,
            vec![("Connection".into(), "keep-alive".into())],
        );
        assert!(!should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_http11_default() {
        let config = Http1Config::default();
        let state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(Version::Http11, vec![]);
        assert!(!should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_keepalive_disabled() {
        let config = Http1Config {
            keep_alive: false,
            ..Default::default()
        };
        let state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(Version::Http11, vec![]);
        assert!(should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_at_request_limit() {
        let config = Http1Config {
            max_requests_per_connection: Some(5),
            ..Default::default()
        };
        let mut state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(Version::Http11, vec![]);

        // At 4 served (next will be 5th = limit), should close
        state.requests_served = 4;
        assert!(should_close_connection(&req, &config, &state));

        // At 3 served, should not close
        state.requests_served = 3;
        assert!(!should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_unlimited_requests() {
        let config = Http1Config {
            max_requests_per_connection: None,
            ..Default::default()
        };
        let mut state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(Version::Http11, vec![]);

        state.requests_served = 1_000_000;
        assert!(!should_close_connection(&req, &config, &state));
    }

    #[test]
    fn connection_state_tracking() {
        let state = ConnectionState::new(crate::types::Time::ZERO);
        assert_eq!(state.requests_served, 0);
        assert_eq!(state.phase, ConnectionPhase::Idle);
        assert!(!state.exceeded_request_limit(Some(10)));
        assert!(!state.exceeded_request_limit(None));
    }

    #[test]
    fn connection_state_request_limit() {
        let mut state = ConnectionState::new(crate::types::Time::ZERO);
        state.requests_served = 10;
        assert!(state.exceeded_request_limit(Some(10)));
        assert!(state.exceeded_request_limit(Some(5)));
        assert!(!state.exceeded_request_limit(Some(11)));
        assert!(!state.exceeded_request_limit(None));
    }

    #[test]
    fn add_connection_close_header() {
        let mut resp = Response::new(200, "OK", Vec::new());
        assert!(resp.headers.is_empty());
        add_connection_close(&mut resp);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "close");
    }

    #[test]
    fn add_connection_close_header_already_present() {
        let mut resp = Response::new(200, "OK", Vec::new());
        resp.headers
            .push(("Connection".to_owned(), "keep-alive".to_owned()));
        add_connection_close(&mut resp);
        // Should not add duplicate and should overwrite to close
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "close");
    }

    #[test]
    fn add_connection_keep_alive_header() {
        let mut resp = Response::new(200, "OK", Vec::new());
        assert!(resp.headers.is_empty());
        add_connection_keep_alive(&mut resp);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "keep-alive");
    }

    #[test]
    fn add_connection_keep_alive_header_already_present() {
        let mut resp = Response::new(200, "OK", Vec::new());
        resp.headers
            .push(("Connection".to_owned(), "close".to_owned()));
        add_connection_keep_alive(&mut resp);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "keep-alive");
    }

    #[test]
    fn finalize_response_persistence_http10_keepalive_normalizes_version_and_header() {
        let mut resp = Response::new(200, "OK", Vec::new());

        let close_after = finalize_response_persistence(Version::Http10, &mut resp, false);

        assert!(!close_after);
        assert_eq!(resp.version, Version::Http10);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "keep-alive");
    }

    #[test]
    fn finalize_response_persistence_http10_close_normalizes_version_and_header() {
        let mut resp = Response::new(200, "OK", Vec::new());

        let close_after = finalize_response_persistence(Version::Http10, &mut resp, true);

        assert!(close_after);
        assert_eq!(resp.version, Version::Http10);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "close");
    }

    #[test]
    fn finalize_response_persistence_preserves_handler_requested_close() {
        let mut resp = Response::new(200, "OK", Vec::new()).with_header("Connection", "close");

        let close_after = finalize_response_persistence(Version::Http11, &mut resp, false);

        assert!(close_after);
        assert_eq!(resp.version, Version::Http11);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "close");
    }

    #[test]
    fn finalize_response_persistence_never_invents_a_date_header() {
        // The server's clock is not UTC (wall_now is timer or process time),
        // so it must not invent a Date (RFC 9110 §6.6.1); formatting it gave
        // dates in January 1970.
        let mut resp = Response::new(200, "OK", Vec::new());
        finalize_response_persistence(Version::Http11, &mut resp, false);
        assert!(
            !resp
                .headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case("date")),
            "the server injected a Date: {:?}",
            resp.headers
        );

        // A Date the handler set is kept, exactly once.
        let mut resp_with_date = Response::new(200, "OK", Vec::new())
            .with_header("Date", "Sun, 06 Nov 1994 08:49:37 GMT");
        finalize_response_persistence(Version::Http11, &mut resp_with_date, false);
        let dates: Vec<_> = resp_with_date
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("date"))
            .collect();
        assert_eq!(dates.len(), 1);
        assert_eq!(dates[0].1, "Sun, 06 Nov 1994 08:49:37 GMT");
    }

    #[test]
    fn suppress_response_body_for_head_replaces_chunked_framing() {
        let mut resp = Response::new(200, "OK", b"hello".to_vec())
            .with_header("Trailer", "X-Trace")
            .with_header("Transfer-Encoding", "chunked")
            .with_trailer("X-Trace", "abc123");

        suppress_response_body_for_head(&mut resp);

        assert!(resp.body.is_empty());
        assert!(resp.trailers.is_empty());
        assert_eq!(resp.header_value("trailer"), None);
        assert_eq!(resp.header_value("transfer-encoding"), None);
        assert_eq!(resp.header_value("content-length"), Some("5"));
    }

    #[test]
    fn suppress_response_body_for_head_preserves_handler_content_length() {
        // RFC 9110 §9.3.2: HEAD response MUST carry the same Content-Length
        // as the equivalent GET response.  When the handler explicitly sets
        // Content-Length (even if it differs from the sentinel body), trust
        // it as the authoritative GET length.
        let mut resp =
            Response::new(200, "OK", b"hello".to_vec()).with_header("Content-Length", "999");

        suppress_response_body_for_head(&mut resp);

        assert!(resp.body.is_empty());
        assert_eq!(resp.header_value("content-length"), Some("999"));
    }

    #[test]
    fn config_builder() {
        let config = Http1Config::default()
            .max_headers_size(1024)
            .max_body_size(2048)
            .keep_alive(false)
            .max_requests(Some(50))
            .idle_timeout(Some(Duration::from_secs(30)));

        assert_eq!(config.max_headers_size, 1024);
        assert_eq!(config.max_body_size, 2048);
        assert!(!config.keep_alive);
        assert_eq!(config.max_requests_per_connection, Some(50));
        assert_eq!(config.idle_timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn classify_expectation_none_when_absent() {
        let req = make_request(Version::Http11, vec![]);
        assert_eq!(classify_expectation(&req), ExpectationAction::None);
    }

    #[test]
    fn classify_expectation_continue_for_http11() {
        let req = make_request(
            Version::Http11,
            vec![("Expect".into(), "100-continue".into())],
        );
        assert_eq!(classify_expectation(&req), ExpectationAction::Continue);
    }

    #[test]
    fn classify_expectation_rejects_http10_continue() {
        let req = make_request(
            Version::Http10,
            vec![("Expect".into(), "100-continue".into())],
        );
        assert_eq!(classify_expectation(&req), ExpectationAction::Reject);
    }

    #[test]
    fn classify_expectation_rejects_unsupported_expectation() {
        let req = make_request(Version::Http11, vec![("Expect".into(), "foo".into())]);
        assert_eq!(classify_expectation(&req), ExpectationAction::Reject);
    }

    #[test]
    fn expectation_and_body_preview_use_only_rfc_ows() {
        let unicode_expect = make_request(
            Version::Http11,
            vec![("Expect".into(), "\u{a0}100-continue\u{a0}".into())],
        );
        assert_eq!(
            classify_expectation(&unicode_expect),
            ExpectationAction::Reject
        );

        let ascii_ows_expect = make_request(
            Version::Http11,
            vec![("Expect".into(), "\t 100-continue \t".into())],
        );
        assert_eq!(
            classify_expectation(&ascii_ows_expect),
            ExpectationAction::Continue
        );

        assert!(!request_expects_body_headers(&[(
            "Content-Length".into(),
            "\u{a0}5\u{a0}".into(),
        )]));
        assert!(!request_expects_body_headers(&[(
            "Transfer-Encoding".into(),
            "\u{a0}chunked\u{a0}".into(),
        )]));
    }

    #[test]
    fn classify_expectation_rejects_mixed_tokens() {
        let req = make_request(
            Version::Http11,
            vec![("Expect".into(), "100-continue, foo".into())],
        );
        assert_eq!(classify_expectation(&req), ExpectationAction::Reject);
    }

    #[test]
    fn request_expects_body_content_length_positive() {
        let req = make_request(Version::Http11, vec![("Content-Length".into(), "5".into())]);
        assert!(request_expects_body(&req));
    }

    #[test]
    fn request_expects_body_content_length_zero() {
        let req = make_request(Version::Http11, vec![("Content-Length".into(), "0".into())]);
        assert!(!request_expects_body(&req));
    }

    #[test]
    fn request_expects_body_chunked_encoding() {
        let req = make_request(
            Version::Http11,
            vec![("Transfer-Encoding".into(), "chunked".into())],
        );
        assert!(request_expects_body(&req));
    }

    #[test]
    fn streaming_server_publishes_head_before_reading_body() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let head_published = Arc::new(AtomicBool::new(false));
        let io = HeadFirstIo {
            head: b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nConnection: close\r\n\r\n".to_vec(),
            body_and_pipeline: b"hello".to_vec(),
            head_published: Arc::clone(&head_published),
            written: Arc::clone(&written),
        };
        let published_by_handler = Arc::clone(&head_published);
        let server = Http1StreamingServer::with_config(
            move |_cx, mut request| {
                let published_by_handler = Arc::clone(&published_by_handler);
                async move {
                    published_by_handler.store(true, Ordering::SeqCst);
                    let mut body = Vec::new();
                    while let Some(frame) =
                        poll_fn(|task_cx| Pin::new(&mut request.body).poll_frame(task_cx)).await
                    {
                        if let Some(data) = frame.expect("valid body frame").into_data() {
                            body.extend_from_slice(data.into_inner().as_ref());
                        }
                    }
                    assert_eq!(body, b"hello");
                    Response::new(200, "OK", b"done")
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve(&cx, io).await
            })
            .expect("serve streaming request");

        assert_eq!(state.requests_served, 1);
        assert!(head_published.load(Ordering::SeqCst));
        assert!(String::from_utf8_lossy(&written.lock().unwrap()).contains("200 OK"));
    }

    /// asupersync-1to1qw: a client that trickles its body one byte per idle
    /// window used to hold the connection, its in-flight slot and the parked
    /// handler for `Content-Length` windows, because the body driver bounded
    /// each read by `idle_timeout` separately. The whole body now shares one
    /// `idle_timeout` of socket waiting, like the buffered server's request
    /// read and the streaming head reader. Each trickle step here stays under
    /// the window, so the old per-read bound served the request with a 200;
    /// the shared budget ends the connection before the body completes.
    #[test]
    fn streaming_server_trickled_body_is_bounded_by_one_idle_window() {
        const IDLE: Duration = Duration::from_millis(300);
        const STEP: Duration = Duration::from_millis(200);
        let server = Http1StreamingServer::with_config(
            move |_cx, mut request| async move {
                let mut body = Vec::new();
                while let Some(frame) =
                    poll_fn(|task_cx| Pin::new(&mut request.body).poll_frame(task_cx)).await
                {
                    match frame {
                        Ok(frame) => {
                            if let Some(data) = frame.into_data() {
                                body.extend_from_slice(data.into_inner().as_ref());
                            }
                        }
                        Err(_) => break,
                    }
                }
                Response::new(200, "OK", b"done")
            },
            localhost_server_config().idle_timeout(Some(IDLE)),
        );

        let raw_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = raw_listener
            .local_addr()
            .expect("loopback listener address");
        let client = std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};

            let mut client =
                std::net::TcpStream::connect(address).expect("connect loopback client");
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set client read timeout");
            client
                .write_all(
                    b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\n",
                )
                .expect("write request head");
            // One byte per STEP: every individual read wait is shorter than
            // IDLE, but the body's total socket waiting is four STEPs.
            for byte in b"abcd" {
                std::thread::sleep(STEP);
                if client.write_all(&[*byte]).is_err() {
                    break;
                }
            }
            let mut received = Vec::new();
            let _ = client.read_to_end(&mut received);
            received
        });
        let (server_raw, _) = raw_listener.accept().expect("accept loopback client");
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                let stream = crate::net::tcp::stream::TcpStream::from_std(server_raw)
                    .expect("wrap loopback server stream");
                server.serve_with_peer_addr(&cx, stream, None).await
            })
            .expect("a trickled body ends the connection without an io error");
        let received = client.join().expect("join loopback client");

        assert_eq!(
            state.requests_served, 0,
            "the aborted request must not count as served"
        );
        assert!(
            received.is_empty(),
            "no response may be written for a body that never arrived within one idle window: {:?}",
            String::from_utf8_lossy(&received)
        );
    }

    #[test]
    fn incoming_body_driver_observes_supplied_request_context_cancellation() {
        let request_cx = Cx::for_testing();
        request_cx.cancel_fast(crate::types::CancelKind::PollQuota);
        let (writer, _body) =
            IncomingRequestBody::channel_with_limits(&request_cx, BodyKind::ContentLength(1), 1, 1);
        let written = Arc::new(Mutex::new(Vec::new()));
        let mut io = TestIo::new(Vec::new(), written);
        let mut read_buffer = BytesMut::from(&b"x"[..]);
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(drive_incoming_body(
                &request_cx,
                &mut io,
                &mut read_buffer,
                writer,
                &Http1StreamingConfig::default(),
            ))
            .expect_err("request cancellation must stop body publication");

        assert_eq!(
            error,
            IncomingBodyError::Cancelled {
                kind: crate::types::CancelKind::PollQuota,
            }
        );
    }

    #[test]
    fn body_diagnostic_incoming_driver_preserves_client_abort_for_consumer() {
        let request_cx = Cx::for_testing();
        let (writer, mut body) =
            IncomingRequestBody::channel_with_limits(&request_cx, BodyKind::ContentLength(1), 1, 1);
        let written = Arc::new(Mutex::new(Vec::new()));
        let mut io = TestIo::new(Vec::new(), written).with_read_error(io::ErrorKind::BrokenPipe);
        let mut read_buffer = BytesMut::new();
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let (driver_error, consumer_error) = runtime.block_on(async {
            let driver_error = drive_incoming_body(
                &request_cx,
                &mut io,
                &mut read_buffer,
                writer,
                &Http1StreamingConfig::default(),
            )
            .await
            .expect_err("transport read failure must abort the request body");
            let consumer_error =
                std::future::poll_fn(|task_cx| Pin::new(&mut body).poll_frame(task_cx))
                    .await
                    .expect("failed body emits one terminal frame")
                    .expect_err("failed body frame retains its typed cause");
            (driver_error, consumer_error)
        });

        assert_eq!(driver_error, IncomingBodyError::ClientAborted);
        assert_eq!(consumer_error, IncomingBodyError::ClientAborted);
        assert!(
            incoming_body_failure_response(Version::Http11, &consumer_error).is_none(),
            "a live client abort must never synthesize a wire response"
        );
    }

    #[test]
    fn body_diagnostic_incoming_driver_classifies_unsynchronized_eof_as_client_abort() {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        for (body_kind, partial_wire) in [
            (BodyKind::ContentLength(5), &b"hi"[..]),
            (BodyKind::Chunked, &b"2\r\nhi\r\n"[..]),
        ] {
            let request_cx = Cx::for_testing();
            let (writer, mut body) =
                IncomingRequestBody::channel_with_limits(&request_cx, body_kind, 2, 64);
            let written = Arc::new(Mutex::new(Vec::new()));
            let mut io = TestIo::new(partial_wire.to_vec(), written);
            let mut read_buffer = BytesMut::new();

            let (driver_error, consumer_error) = runtime.block_on(async {
                let driver_error = drive_incoming_body(
                    &request_cx,
                    &mut io,
                    &mut read_buffer,
                    writer,
                    &Http1StreamingConfig::default(),
                )
                .await
                .expect_err("premature peer EOF must abort the request body");
                let consumer_error = loop {
                    let frame =
                        std::future::poll_fn(|task_cx| Pin::new(&mut body).poll_frame(task_cx))
                            .await
                            .expect("aborted body emits a terminal error frame");
                    match frame {
                        Ok(_) => continue,
                        Err(error) => break error,
                    }
                };
                (driver_error, consumer_error)
            });

            assert_eq!(driver_error, IncomingBodyError::ClientAborted);
            assert_eq!(consumer_error, IncomingBodyError::ClientAborted);
            assert!(incoming_body_failure_response(Version::Http11, &consumer_error).is_none());
        }
    }

    #[test]
    fn streaming_server_drains_unread_body_before_pipeline_reuse() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"POST /first HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhelloGET /second HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_handler = Arc::clone(&seen);
        let server = Http1StreamingServer::with_config(
            move |_cx, request| {
                seen_by_handler
                    .lock()
                    .unwrap()
                    .push(request.head.uri.clone());
                async move { Response::new(200, "OK", request.head.uri.into_bytes()) }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve(&cx, io).await
            })
            .expect("serve pipelined streaming requests");

        assert_eq!(state.requests_served, 2);
        assert_eq!(&*seen.lock().unwrap(), &["/first", "/second"]);
        let written = String::from_utf8_lossy(&written.lock().unwrap()).into_owned();
        assert_eq!(written.matches("HTTP/1.1 200 OK").count(), 2);
    }

    #[test]
    fn streaming_server_drains_segmented_unread_body_before_pipeline_reuse() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"POST /first HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhelloGET /second HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        )
        .with_read_limit(1);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_handler = Arc::clone(&seen);
        let server = Http1StreamingServer::with_config(
            move |_cx, request| {
                seen_by_handler
                    .lock()
                    .unwrap()
                    .push(request.head.uri.clone());
                async move { Response::new(200, "OK", request.head.uri.into_bytes()) }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve(&cx, io).await
            })
            .expect("serve segmented pipelined streaming requests");

        assert_eq!(state.requests_served, 2);
        assert_eq!(&*seen.lock().unwrap(), &["/first", "/second"]);
        let written = String::from_utf8_lossy(&written.lock().unwrap()).into_owned();
        assert_eq!(written.matches("HTTP/1.1 200 OK").count(), 2);
    }

    #[test]
    fn streaming_server_drains_segmented_chunked_unread_body_before_pipeline_reuse() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"POST /first HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Checksum: yes\r\n\r\nGET /second HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        )
        .with_read_limit(1);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_handler = Arc::clone(&seen);
        let server = Http1StreamingServer::with_config(
            move |_cx, request| {
                seen_by_handler
                    .lock()
                    .unwrap()
                    .push(request.head.uri.clone());
                async move { Response::new(200, "OK", request.head.uri.into_bytes()) }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve(&cx, io).await
            })
            .expect("serve segmented chunked pipelined streaming requests");

        assert_eq!(state.requests_served, 2);
        assert_eq!(&*seen.lock().unwrap(), &["/first", "/second"]);
        let written = String::from_utf8_lossy(&written.lock().unwrap()).into_owned();
        assert_eq!(written.matches("HTTP/1.1 200 OK").count(), 2);
    }

    #[test]
    fn streaming_server_closes_when_unread_body_exceeds_drain_limit() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"POST /first HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\n0123456789GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let config = Http1StreamingConfig::from(localhost_server_config()).unread_body_drain(
            8,
            4,
            Duration::from_secs(1),
        );
        let server = Http1StreamingServer::with_config(
            |_cx, _request| async move { Response::new(200, "OK", b"must not commit") },
            config,
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve(&cx, io).await
            })
            .expect("drain-limit close is a clean connection outcome");

        // br-asupersync-hw83se: an unread-body drain overrun surfaces here as a
        // DrainLimitExceeded body error (the handler's own response is not
        // available on that path), which incoming_body_failure_response maps to
        // None. Instead of dropping it and closing silently, the client now
        // receives an explicit 413 with Connection: close (RFC 9112 §9.6). The
        // connection still cannot be reused — the undrained request body would
        // corrupt the next request — so the pipelined /second request is never
        // served.
        assert_eq!(state.requests_served, 1);
        let written = String::from_utf8(written.lock().unwrap().clone())
            .expect("response should be valid utf8");
        assert!(
            written.starts_with("HTTP/1.1 413 "),
            "a drain overrun must return 413, wrote {written:?}"
        );
        assert!(
            written
                .to_ascii_lowercase()
                .contains("\r\nconnection: close\r\n"),
            "a drain-overrun response must force the connection closed, wrote {written:?}"
        );
        assert!(
            written.contains("[ASUP-E505]"),
            "the 413 must carry the diagnostic token, wrote {written:?}"
        );
        assert!(
            !written.contains("must not commit"),
            "the handler body must not leak on the drain-overrun path"
        );
        assert!(
            !written.contains("/second"),
            "the pipelined request must not be served after a forced close"
        );
        assert_eq!(state.phase, ConnectionPhase::Closing);
    }

    #[test]
    fn streaming_server_preserves_chunked_frames_and_trailers() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"POST /chunk HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\nX-Checksum: yes\r\n\r\n"
                .to_vec(),
            Arc::clone(&written),
        );
        let observed = Arc::new(Mutex::new((Vec::new(), Vec::new())));
        let observed_by_handler = Arc::clone(&observed);
        let server = Http1StreamingServer::with_config(
            move |_cx, mut request| {
                let observed_by_handler = Arc::clone(&observed_by_handler);
                async move {
                    while let Some(frame) =
                        poll_fn(|task_cx| Pin::new(&mut request.body).poll_frame(task_cx)).await
                    {
                        match frame.expect("valid chunked frame") {
                            crate::http::body::Frame::Data(data) => observed_by_handler
                                .lock()
                                .unwrap()
                                .0
                                .extend_from_slice(data.into_inner().as_ref()),
                            crate::http::body::Frame::Trailers(trailers) => {
                                observed_by_handler.lock().unwrap().1 = trailers
                                    .iter()
                                    .map(|(name, value)| {
                                        (
                                            name.as_str().to_owned(),
                                            String::from_utf8_lossy(value.as_bytes()).into_owned(),
                                        )
                                    })
                                    .collect();
                            }
                        }
                    }
                    Response::new(204, "No Content", Vec::new())
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve(&cx, io).await
            })
            .expect("serve chunked streaming request");

        assert_eq!(state.requests_served, 1);
        assert_eq!(observed.lock().unwrap().0, b"hello");
        assert_eq!(
            observed.lock().unwrap().1,
            vec![("x-checksum".to_owned(), "yes".to_owned())]
        );
    }

    #[test]
    fn streaming_server_refuses_actual_chunked_bytes_over_limit() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"POST /chunk HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
                .to_vec(),
            Arc::clone(&written),
        );
        let observed_error: Arc<Mutex<Option<IncomingBodyError>>> = Arc::new(Mutex::new(None));
        let observed_by_handler = Arc::clone(&observed_error);
        let server = Http1StreamingServer::with_config(
            move |_cx, mut request| {
                let observed_by_handler = Arc::clone(&observed_by_handler);
                async move {
                    while let Some(frame) =
                        poll_fn(|task_cx| Pin::new(&mut request.body).poll_frame(task_cx)).await
                    {
                        if let Err(error) = frame {
                            *observed_by_handler.lock().unwrap() = Some(error);
                            break;
                        }
                    }
                    Response::new(200, "OK", b"must not commit")
                }
            },
            localhost_server_config().max_body_size(4),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve(&cx, io).await
            })
            .expect("over-limit body closes the connection cleanly");

        // ASUP-E505 contract: an in-flight streaming-body refusal writes the
        // safely writable 413 with `Connection: close`, counts that hop, and
        // closes so the unread body bytes cannot be mistaken for a new
        // request. The handler's 200 must never reach the wire.
        assert_eq!(state.requests_served, 1);
        let written_text = String::from_utf8_lossy(&written.lock().unwrap()).into_owned();
        assert!(
            written_text.starts_with("HTTP/1.1 413 "),
            "expected a 413 refusal, wrote {written_text:?}"
        );
        assert!(
            written_text.contains("[ASUP-E505]"),
            "refusal must carry the diagnostic token, wrote {written_text:?}"
        );
        assert!(
            written_text
                .to_ascii_lowercase()
                .contains("\r\nconnection: close\r\n"),
            "refusal must close the connection, wrote {written_text:?}"
        );
        assert!(
            !written_text.contains("must not commit"),
            "handler response leaked after the body refusal: {written_text:?}"
        );
        assert_eq!(state.phase, ConnectionPhase::Closing);
        assert_eq!(
            observed_error.lock().unwrap().as_ref(),
            Some(&IncomingBodyError::BodyTooLarge {
                actual: Some(5),
                limit: 4,
            })
        );
    }

    /// br-asupersync-8udzw7 A-L1: a client may send a CRLF after a request
    /// body (RFC 9112 section 2.2). If it then closes, it sent no second
    /// request: the connection closes without a 400, and only the real request
    /// counts as served. A partial head followed by EOF is still refused.
    #[test]
    fn streaming_server_closes_cleanly_after_a_trailing_crlf_and_eof() {
        for (case, input, served, bad_requests) in [
            (
                "trailing CRLF",
                &b"POST /first HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello\r\n"[..],
                1,
                0,
            ),
            (
                "partial head",
                &b"POST /first HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello\r\nGET /partial HTT"[..],
                2,
                1,
            ),
        ] {
            let written = Arc::new(Mutex::new(Vec::new()));
            let io = TestIo::new(input.to_vec(), Arc::clone(&written));
            let server = Http1StreamingServer::with_config(
                |_cx, request| async move {
                    Response::new(200, "OK", request.head.uri.into_bytes())
                },
                localhost_server_config(),
            );
            let runtime = RuntimeBuilder::current_thread()
                .build()
                .expect("build current-thread runtime");

            let state = runtime
                .block_on(async {
                    let cx = Cx::current().expect("runtime connection context");
                    server.serve(&cx, io).await
                })
                .expect("the connection closes without an error");

            let written = String::from_utf8_lossy(&written.lock().unwrap()).into_owned();
            assert_eq!(written.matches("HTTP/1.1 200 OK").count(), 1, "{case}: {written}");
            assert_eq!(
                written.matches("HTTP/1.1 400 ").count(),
                bad_requests,
                "{case}: {written}"
            );
            assert_eq!(state.requests_served, served, "{case}");
            assert_eq!(state.phase, ConnectionPhase::Closing, "{case}");
        }
    }

    #[test]
    fn streaming_server_reports_truncated_content_length_and_closes() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"POST /short HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhi".to_vec(),
            Arc::clone(&written),
        );
        let observed_error: Arc<Mutex<Option<IncomingBodyError>>> = Arc::new(Mutex::new(None));
        let observed_by_handler = Arc::clone(&observed_error);
        let server = Http1StreamingServer::with_config(
            move |_cx, mut request| {
                let observed_by_handler = Arc::clone(&observed_by_handler);
                async move {
                    while let Some(frame) =
                        poll_fn(|task_cx| Pin::new(&mut request.body).poll_frame(task_cx)).await
                    {
                        if let Err(error) = frame {
                            *observed_by_handler.lock().unwrap() = Some(error);
                            break;
                        }
                    }
                    Response::new(200, "OK", b"must not commit")
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve(&cx, io).await
            })
            .expect("truncated body closes the connection cleanly");

        assert_eq!(state.requests_served, 0);
        assert!(written.lock().unwrap().is_empty());
        assert_eq!(state.phase, ConnectionPhase::Closing);
        assert_eq!(
            observed_error.lock().unwrap().as_ref(),
            Some(&IncomingBodyError::ClientAborted)
        );
    }

    #[test]
    fn serve_head_request_omits_response_body_bytes() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1Server::with_config(
            |_req| async move { Response::new(200, "OK", b"hello") },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve head request");

        assert_eq!(state.requests_served, 1);

        let written = String::from_utf8(written.lock().unwrap().clone())
            .expect("response should be valid utf8");
        assert!(written.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(written.contains("Content-Length: 5\r\n"));
        assert!(written.contains("Connection: close\r\n"));
        assert!(written.ends_with("\r\n\r\n"));
        assert!(!written.ends_with("\r\n\r\nhello"));
    }

    /// Under AllowAll the server answers an HTTP/1.0 request without Host and
    /// an HTTP/1.1 request with an empty Host, as v0.4.3 did. An HTTP/1.1
    /// request without Host still gets 400 before the handler (RFC 9112 §3.2).
    #[test]
    fn serve_allow_all_answers_requests_that_need_no_host() {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        let cases: [(&[u8], &str, usize); 3] = [
            (b"GET / HTTP/1.0\r\n\r\n", "HTTP/1.0 200 OK\r\n", 1),
            (
                b"GET / HTTP/1.1\r\nHost:\r\nConnection: close\r\n\r\n",
                "HTTP/1.1 200 OK\r\n",
                1,
            ),
            (
                b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n",
                "HTTP/1.1 400 Bad Request\r\n",
                0,
            ),
        ];
        let mut mismatches = Vec::new();
        for (request, status_line, handled) in cases {
            let written = Arc::new(Mutex::new(Vec::new()));
            let calls = Arc::new(AtomicUsize::new(0));
            let calls_for_handler = Arc::clone(&calls);
            let server = Http1Server::with_config(
                move |_req| {
                    calls_for_handler.fetch_add(1, Ordering::SeqCst);
                    async move { Response::new(200, "OK", b"hello") }
                },
                Http1Config::default().host_policy(HostPolicy::AllowAll),
            );
            let io = TestIo::new(request.to_vec(), Arc::clone(&written));
            runtime
                .block_on(async { server.serve(io).await })
                .expect("serve");
            let written = String::from_utf8(written.lock().unwrap().clone())
                .expect("response should be valid utf8");
            let ran = calls.load(Ordering::SeqCst);
            if !written.starts_with(status_line) || ran != handled {
                mismatches.push(format!(
                    "{:?}: handler ran {ran}x, wrote {written:?}",
                    String::from_utf8_lossy(request)
                ));
            }
        }
        assert!(mismatches.is_empty(), "{mismatches:#?}");
    }

    /// A handler that declares a Content-Length its body does not carry used
    /// to have it written as is: the client then read the next response's
    /// bytes as this body. HEAD keeps the declared length.
    #[test]
    fn serve_refuses_a_declared_length_the_body_does_not_match() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /short HTTP/1.1\r\nHost: localhost\r\n\r\nGET /next HTTP/1.1\r\nHost: localhost\r\n\r\n"
                .to_vec(),
            Arc::clone(&written),
        );
        let server = Http1Server::with_config(
            |_req| async move {
                Response::new(200, "OK", Vec::new()).with_header("Content-Length", "10")
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve");

        assert_eq!(
            state.requests_served, 1,
            "the connection closes after the 500"
        );
        let written = String::from_utf8(written.lock().unwrap().clone())
            .expect("response should be valid utf8");
        assert!(written.starts_with("HTTP/1.1 500 "), "{written:?}");
        assert!(
            written
                .to_ascii_lowercase()
                .contains("\r\nconnection: close\r\n"),
            "{written:?}"
        );
        assert!(!written.contains("Content-Length: 10"), "{written:?}");
        assert_eq!(written.matches("HTTP/1.1 ").count(), 1, "{written:?}");

        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"HEAD /short HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1Server::with_config(
            |_req| async move {
                Response::new(200, "OK", Vec::new()).with_header("Content-Length", "10")
            },
            localhost_server_config(),
        );
        runtime
            .block_on(async { server.serve(io).await })
            .expect("serve head");
        let written = String::from_utf8(written.lock().unwrap().clone())
            .expect("response should be valid utf8");
        assert!(written.starts_with("HTTP/1.1 200 OK\r\n"), "{written:?}");
        assert!(written.contains("Content-Length: 10\r\n"), "{written:?}");
    }

    #[test]
    fn serve_expect_continue_unblocks_body_waiting_client() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let seen_body = Arc::new(Mutex::new(Vec::new()));
        let io = GatedBodyIo::new(
            b"POST /upload HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\nContent-Length: 5\r\nConnection: close\r\n\r\n".to_vec(),
            b"hello".to_vec(),
            b"HTTP/1.1 100 Continue\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let seen_body_for_handler = Arc::clone(&seen_body);
        let server = Http1Server::with_config(
            move |req| {
                let seen_body_for_handler = Arc::clone(&seen_body_for_handler);
                async move {
                    *seen_body_for_handler.lock().unwrap() = req.body.clone();
                    Response::new(200, "OK", b"done")
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve expect-continue request");

        assert_eq!(state.requests_served, 1);
        assert_eq!(&*seen_body.lock().unwrap(), b"hello");

        let written = String::from_utf8(written.lock().unwrap().clone())
            .expect("response should be valid utf8");
        assert!(written.starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"));
        assert!(written.contains("Content-Length: 4\r\n"));
    }

    #[test]
    fn serve_expect_continue_when_body_arrives_eagerly() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let seen_body = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"POST /upload HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".to_vec(),
            Arc::clone(&written),
        );
        let seen_body_for_handler = Arc::clone(&seen_body);
        let server = Http1Server::with_config(
            move |req| {
                let seen_body_for_handler = Arc::clone(&seen_body_for_handler);
                async move {
                    *seen_body_for_handler.lock().unwrap() = req.body.clone();
                    Response::new(200, "OK", b"done")
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve eager expect-continue request");

        assert_eq!(state.requests_served, 1);
        assert_eq!(&*seen_body.lock().unwrap(), b"hello");

        let written = String::from_utf8(written.lock().unwrap().clone())
            .expect("response should be valid utf8");
        assert!(written.starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"));
        assert!(written.contains("Content-Length: 4\r\n"));
    }

    #[test]
    fn serve_rejects_unsupported_expectation_before_body_arrives() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let handler_called = Arc::new(AtomicBool::new(false));
        let io = GatedBodyIo::new(
            b"POST /upload HTTP/1.1\r\nHost: localhost\r\nExpect: fancy-feature\r\nContent-Length: 5\r\nConnection: close\r\n\r\n".to_vec(),
            b"hello".to_vec(),
            b"HTTP/1.1 417 Expectation Failed\r\n".to_vec(),
            Arc::clone(&written),
        );
        let handler_called_for_handler = Arc::clone(&handler_called);
        let server = Http1Server::with_config(
            move |_req| {
                handler_called_for_handler.store(true, Ordering::SeqCst);
                async move { Response::new(200, "OK", b"nope") }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve unsupported expect request");

        assert_eq!(state.requests_served, 1);
        assert!(!handler_called.load(Ordering::SeqCst));

        let written = String::from_utf8(written.lock().unwrap().clone())
            .expect("response should be valid utf8");
        assert!(written.starts_with("HTTP/1.1 417 Expectation Failed\r\n"));
        assert!(written.contains("Connection: close\r\n"));
        assert!(!written.contains("200 OK"));
    }

    #[test]
    fn serve_answers_oversized_request_head_with_431_before_closing() {
        // br-asupersync-hw83se: a request head that blows the configured
        // `max_headers_size` must receive a 431 with `Connection: close`, not
        // the bare connection drop the client cannot distinguish from a
        // transport fault. Before the fix the buffered serve loop answered the
        // codec's `HeadersTooLarge` with `return Err`, writing nothing.
        let written = Arc::new(Mutex::new(Vec::new()));
        let handler_called = Arc::new(AtomicBool::new(false));
        let padding = "a".repeat(512);
        let request = format!(
            "GET / HTTP/1.1\r\nHost: localhost\r\nX-Pad: {padding}\r\nConnection: close\r\n\r\n"
        );
        let io = TestIo::new(request.into_bytes(), Arc::clone(&written));
        let handler_called_for_handler = Arc::clone(&handler_called);
        let server = Http1Server::with_config(
            move |_req| {
                handler_called_for_handler.store(true, Ordering::SeqCst);
                async move { Response::new(200, "OK", b"must not run") }
            },
            localhost_server_config().max_headers_size(64),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("an oversized head closes the connection cleanly with a 431");

        assert!(
            !handler_called.load(Ordering::SeqCst),
            "handler must never run for a rejected head"
        );
        assert_eq!(state.requests_served, 1);
        assert_eq!(state.phase, ConnectionPhase::Closing);
        let written = String::from_utf8(written.lock().unwrap().clone())
            .expect("response should be valid utf8");
        assert!(
            written.starts_with("HTTP/1.1 431 "),
            "expected a 431 refusal, wrote {written:?}"
        );
        assert!(
            written
                .to_ascii_lowercase()
                .contains("\r\nconnection: close\r\n"),
            "refusal must close the connection, wrote {written:?}"
        );
        assert!(
            !written.contains("200 OK"),
            "handler response leaked after the head refusal: {written:?}"
        );
    }

    #[test]
    fn streaming_serve_answers_oversized_request_head_with_431_before_closing() {
        // br-asupersync-hw83se: the streaming (SSE/produced) server routes head
        // reads through `serve_produced_connection`, which owed the same 431 as
        // the buffered path. Before the fix a rejected head propagated the
        // codec error and dropped the connection with nothing written; the SSE
        // source must never run.
        let written = Arc::new(Mutex::new(Vec::new()));
        let source_calls = Arc::new(AtomicUsize::new(0));
        let eof_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let source = CountingSseSource::finite(
            ["must-not-run"],
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&cancel_calls),
        );
        let source = Arc::new(Mutex::new(Some(source)));
        let source_for_handler = Arc::clone(&source);
        let server = Http1StreamingServer::with_config_sse(
            move |_cx, _request| {
                let source = source_for_handler
                    .lock()
                    .unwrap()
                    .take()
                    .expect("one live SSE request");
                async move { StreamingSse::from_source(source).into_http1_response(NonZeroUsize::MIN) }
            },
            localhost_server_config().max_headers_size(64),
        );
        let padding = "a".repeat(512);
        let request = format!(
            "GET /events HTTP/1.1\r\nHost: localhost\r\nX-Pad: {padding}\r\nConnection: close\r\n\r\n"
        );
        let io = TestIo::new(request.into_bytes(), Arc::clone(&written));
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_sse(&cx, io).await
            })
            .expect("an oversized head closes the streaming connection cleanly with a 431");

        assert_eq!(
            source_calls.load(Ordering::SeqCst),
            0,
            "the SSE source must never run for a rejected head"
        );
        assert_eq!(state.requests_served, 1);
        assert_eq!(state.phase, ConnectionPhase::Closing);
        let written = String::from_utf8(written.lock().unwrap().clone())
            .expect("response should be valid utf8");
        assert!(
            written.starts_with("HTTP/1.1 431 "),
            "expected a 431 refusal, wrote {written:?}"
        );
        assert!(
            written
                .to_ascii_lowercase()
                .contains("\r\nconnection: close\r\n"),
            "refusal must close the connection, wrote {written:?}"
        );
    }

    #[test]
    fn head_parse_failure_response_maps_each_error_class_to_its_status() {
        // br-asupersync-hw83se: the single mapping every head-parse rejection
        // site shares. Oversized heads are 431/413/414, unsupported versions
        // are 505, other malformed heads are 400, and non-head-attributable
        // errors carry no status (the connection is abandoned instead).
        let status = |error: &HttpError| head_parse_failure_response(error).map(|response| response.status);

        assert_eq!(status(&HttpError::HeadersTooLarge), Some(431));
        assert_eq!(status(&HttpError::TooManyHeaders), Some(431));
        assert_eq!(status(&HttpError::RequestLineTooLong), Some(414));
        assert_eq!(status(&HttpError::BodyTooLarge), Some(413));
        assert_eq!(
            status(&HttpError::BodyTooLargeDetailed {
                actual: 9,
                limit: 8
            }),
            Some(413)
        );
        assert_eq!(status(&HttpError::UnsupportedVersion), Some(505));
        assert_eq!(status(&HttpError::BadRequestLine), Some(400));
        assert_eq!(status(&HttpError::BadHeader), Some(400));
        assert_eq!(status(&HttpError::BadMethod), Some(400));
        assert_eq!(status(&HttpError::InvalidHeaderName), Some(400));
        assert_eq!(status(&HttpError::AmbiguousBodyLength), Some(400));

        // No meaningful client-facing status: keep abandoning the connection.
        assert_eq!(
            status(&HttpError::Io(io::Error::from(io::ErrorKind::UnexpectedEof))),
            None
        );
        assert_eq!(status(&HttpError::BodyCancelled), None);
        assert_eq!(status(&HttpError::BodyChannelClosed), None);
        assert_eq!(status(&HttpError::PrefetchedDataRemaining(0)), None);
        assert_eq!(
            status(&HttpError::TooManyInformationalResponses { actual: 2, limit: 1 }),
            None
        );

        // The written refusal carries a safe closing shape.
        let refusal =
            head_parse_failure_response(&HttpError::HeadersTooLarge).expect("431 refusal exists");
        assert!(matches!(refusal.version, Version::Http11));
        assert!(
            refusal
                .headers
                .iter()
                .any(|(name, value)| name == "connection" && value == "close")
        );
        assert!(
            refusal
                .headers
                .iter()
                .any(|(name, value)| name == "content-type" && value.starts_with("text/plain"))
        );
    }

    #[test]
    fn buffered_response_write_times_out_when_client_stops_reading() {
        // br-asupersync-hw83se: a client that stops reading its socket (TCP
        // receive window full) must not pin the connection. Before the fix the
        // response flush parked forever with no write-side timeout; now it is
        // bounded by idle_timeout — the same budget reads already use — so the
        // connection closes with a TimedOut error instead of hanging. WriteParkIo
        // models the stuck reader: it delivers the request, then parks every
        // write (the timer fires independently of the parked write).
        struct WriteParkIo {
            request: Vec<u8>,
            read_pos: usize,
        }
        impl AsyncRead for WriteParkIo {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                if this.read_pos >= this.request.len() {
                    return Poll::Ready(Ok(())); // clean EOF after the request
                }
                let n = buf.remaining().min(this.request.len() - this.read_pos);
                buf.put_slice(&this.request[this.read_pos..this.read_pos + n]);
                this.read_pos += n;
                Poll::Ready(Ok(()))
            }
        }
        impl AsyncWrite for WriteParkIo {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Pending // the client never drains its receive window
            }
            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Pending
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let io = WriteParkIo {
            request: b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            read_pos: 0,
        };
        let server = Http1Server::with_config(
            move |_req| async move { Response::new(200, "OK", b"hello") },
            localhost_server_config().idle_timeout(Some(Duration::from_millis(50))),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let result = runtime.block_on(async { server.serve(io).await });
        let err = result.expect_err("a client that stops reading must not pin the connection");
        assert!(
            matches!(err, HttpError::Io(ref e) if e.kind() == io::ErrorKind::TimedOut),
            "expected a write timeout, got {err:?}"
        );
    }

    #[test]
    fn connection_phase_equality() {
        assert_eq!(ConnectionPhase::Idle, ConnectionPhase::Idle);
        assert_ne!(ConnectionPhase::Idle, ConnectionPhase::Reading);
        assert_ne!(ConnectionPhase::Processing, ConnectionPhase::Writing);
    }

    #[test]
    fn connection_phase_debug_clone_copy() {
        let p = ConnectionPhase::Closing;
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Closing"));

        let p2 = p;
        assert_eq!(p, p2);

        // Copy
        let p3 = p;
        assert_eq!(p, p3);
    }

    #[test]
    fn http1_config_debug_clone() {
        let c = Http1Config::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Http1Config"));

        let c2 = c;
        assert_eq!(c2.max_headers_size, 64 * 1024);
        assert!(c2.keep_alive);
    }

    // --- br-asupersync-server-stack-hardening-eeexl1.1.1: server-hop ---
    // --- request regions, budgets, and Request-Timeout handling      ---

    #[test]
    fn parse_request_timeout_header_accepts_valid_forms() {
        let cases: [(&str, Duration); 5] = [
            ("1500", Duration::from_millis(1500)),
            ("1500ms", Duration::from_millis(1500)),
            ("5s", Duration::from_secs(5)),
            ("2m", Duration::from_secs(120)),
            ("  30  ", Duration::from_millis(30)),
        ];
        for (value, expected) in cases {
            let headers = vec![("Request-Timeout".to_string(), value.to_string())];
            assert_eq!(
                parse_request_timeout_header(&headers),
                Some(expected),
                "value {value:?}"
            );
        }
        // Case-insensitive header name.
        let headers = vec![("REQUEST-TIMEOUT".to_string(), "5s".to_string())];
        assert_eq!(
            parse_request_timeout_header(&headers),
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn parse_request_timeout_header_fails_closed() {
        let bad_values = [
            "",
            " ",
            "abc",
            "-5",
            "5.5s",
            "5 s",
            "1h",
            "0",
            "0ms",
            "0s",
            "99999999999",   // 11 digits
            "184467440737s", // overflow-adjacent garbage length
            "5ss",
            "ms",
            "\u{a0}5s\u{a0}",
        ];
        for value in bad_values {
            let headers = vec![("Request-Timeout".to_string(), value.to_string())];
            assert_eq!(
                parse_request_timeout_header(&headers),
                None,
                "value {value:?} must fail closed"
            );
        }
        // Missing header.
        assert_eq!(parse_request_timeout_header(&[]), None);
        // Duplicate headers are ambiguous: fail closed.
        let headers = vec![
            ("Request-Timeout".to_string(), "5s".to_string()),
            ("request-timeout".to_string(), "10s".to_string()),
        ];
        assert_eq!(parse_request_timeout_header(&headers), None);
    }

    #[test]
    fn serve_handler_observes_config_derived_request_budget() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1Server::with_config(
            |_req| async move {
                let deadline_installed =
                    Cx::with_current(|cx| cx.budget().deadline.is_some()).unwrap_or(false);
                if deadline_installed {
                    Response::new(200, "OK", b"deadline-installed")
                } else {
                    Response::new(500, "ERR", b"no-deadline")
                }
            },
            localhost_server_config().request_timeout(Some(Duration::from_secs(30))),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve request");
        assert_eq!(state.requests_served, 1);

        let written = String::from_utf8(written.lock().unwrap().clone()).expect("utf8");
        assert!(
            written.starts_with("HTTP/1.1 200 OK\r\n"),
            "handler must observe the config-derived budget deadline: {written}"
        );
    }

    #[test]
    fn serve_request_timeout_maps_to_503() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1Server::with_config(
            |_req| async move {
                let now = Cx::current()
                    .and_then(|cx| cx.timer_driver())
                    .map_or_else(wall_now, |timer| timer.now());
                crate::time::sleep(now, Duration::from_secs(600)).await;
                Response::new(200, "OK", b"too late")
            },
            localhost_server_config()
                .request_timeout(Some(Duration::from_millis(25)))
                .request_drain_grace(Duration::from_millis(10)),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        let started = std::time::Instant::now();
        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve request");
        assert_eq!(state.requests_served, 1);
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "request timeout must bound the handler"
        );

        let written = String::from_utf8(written.lock().unwrap().clone()).expect("utf8");
        assert!(
            written.starts_with("HTTP/1.1 503"),
            "deadline exceeded must map to 503: {written}"
        );
        assert!(written.contains("request budget deadline exceeded"));
    }

    /// Parent AC 3 (security): a hostile `Request-Timeout` header cannot
    /// extend the request budget beyond the configured cap.
    #[test]
    fn serve_header_timeout_clamped_by_cap_security() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nRequest-Timeout: 9999999s\r\nConnection: close\r\n\r\n"
                .to_vec(),
            Arc::clone(&written),
        );
        let server = Http1Server::with_config(
            |_req| async move {
                let now = Cx::current()
                    .and_then(|cx| cx.timer_driver())
                    .map_or_else(wall_now, |timer| timer.now());
                crate::time::sleep(now, Duration::from_secs(600)).await;
                Response::new(200, "OK", b"too late")
            },
            localhost_server_config()
                .request_timeout_header_cap(Some(Duration::from_millis(25)))
                .request_drain_grace(Duration::from_millis(10)),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        let started = std::time::Instant::now();
        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve request");
        assert_eq!(state.requests_served, 1);
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the cap must bound a hostile header timeout"
        );

        let written = String::from_utf8(written.lock().unwrap().clone()).expect("utf8");
        assert!(
            written.starts_with("HTTP/1.1 503"),
            "cap-clamped header deadline must map to 503: {written}"
        );
    }

    #[test]
    fn serve_header_timeout_ignored_without_cap_opt_in() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nRequest-Timeout: 1ms\r\nConnection: close\r\n\r\n"
                .to_vec(),
            Arc::clone(&written),
        );
        let server = Http1Server::with_config(
            |_req| async move {
                let now = Cx::current()
                    .and_then(|cx| cx.timer_driver())
                    .map_or_else(wall_now, |timer| timer.now());
                crate::time::sleep(now, Duration::from_millis(50)).await;
                Response::new(200, "OK", b"finished")
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve request");
        assert_eq!(state.requests_served, 1);

        let written = String::from_utf8(written.lock().unwrap().clone()).expect("utf8");
        assert!(
            written.starts_with("HTTP/1.1 200 OK\r\n"),
            "without cap opt-in the header must be ignored: {written}"
        );
    }

    #[test]
    fn serve_handler_panic_maps_to_500_and_closes_connection() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1Server::with_config(
            |_req| async move { panic!("handler exploded") },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve must survive a handler panic");
        assert_eq!(state.requests_served, 1);

        let written = String::from_utf8(written.lock().unwrap().clone()).expect("utf8");
        assert!(
            written.starts_with("HTTP/1.1 500"),
            "handler panic must map to 500: {written}"
        );
        assert!(
            written.contains("Connection: close") || written.contains("connection: close"),
            "connection must close after a handler panic: {written}"
        );
    }

    #[test]
    fn upgradeable_server_preserves_deterministic_codec_read_ahead() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let frame = [
            0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
        ];
        let mut input = b"GET /ws HTTP/1.1\r\n\
            Host: localhost\r\n\
            Upgrade: websocket\r\n\
            Connection: Upgrade\r\n\
            Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
            Sec-WebSocket-Version: 13\r\n\
            \r\n"
            .to_vec();
        input.extend_from_slice(&frame);
        let io = TestIo::new(input, Arc::clone(&written));
        let server = Http1Server::with_config_upgradeable(
            |_request| async move {
                let response = Response::new(101, "Switching Protocols", Vec::new())
                    .with_header("connection", "Upgrade")
                    .with_header("upgrade", "websocket")
                    .with_header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
                Http1Response::new(response)
                    .with_upgrade(Http1Upgrade::new(|_cx, _io, _read_ahead| async {}))
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let outcome = runtime
            .block_on(async { server.serve_upgradeable_with_peer_addr(io, None).await })
            .expect("upgrade handoff");
        let Http1ServeOutcome::Upgraded { read_ahead, .. } = outcome else {
            panic!("expected upgraded ownership outcome");
        };
        assert_eq!(&read_ahead[..], &frame);
        let response = String::from_utf8(written.lock().unwrap().clone()).expect("response UTF-8");
        assert_eq!(response.matches("HTTP/1.1 101").count(), 1);
        assert!(response.ends_with("\r\n\r\n"));
    }

    #[test]
    fn upgradeable_server_rejects_non_rfc6455_key_before_flush() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /ws HTTP/1.1\r\n\
              Host: localhost\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Key: not-base64\r\n\
              Sec-WebSocket-Version: 13\r\n\
              \r\n"
                .to_vec(),
            Arc::clone(&written),
        );
        let server = Http1Server::with_config_upgradeable(
            |_request| async move {
                let response = Response::new(101, "Switching Protocols", Vec::new())
                    .with_header("connection", "Upgrade")
                    .with_header("upgrade", "websocket")
                    .with_header(
                        "sec-websocket-accept",
                        crate::net::websocket::compute_accept_key("not-base64"),
                    );
                Http1Response::new(response)
                    .with_upgrade(Http1Upgrade::new(|_cx, _io, _read_ahead| async {}))
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = match runtime
            .block_on(async { server.serve_upgradeable_with_peer_addr(io, None).await })
        {
            Err(error) => error,
            Ok(_) => panic!("invalid WebSocket key must refuse handoff"),
        };
        assert!(
            matches!(error, HttpError::Io(ref error) if error.kind() == io::ErrorKind::InvalidData)
        );
        assert!(written.lock().unwrap().is_empty());
    }

    /// The upgrade check no longer copies a request that carries a body; it
    /// must still refuse such a handoff with the same errors, in the same
    /// order.
    #[test]
    fn upgradeable_server_refuses_a_handoff_for_a_request_with_a_body() {
        for (method, expected) in [
            ("POST", "WebSocket handoff requires an HTTP/1.1 GET request"),
            (
                "GET",
                "WebSocket handoff request must not carry a body or trailers",
            ),
        ] {
            let written = Arc::new(Mutex::new(Vec::new()));
            let io = TestIo::new(
                format!(
                    "{method} /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
                     Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                     Sec-WebSocket-Version: 13\r\nContent-Length: 4\r\n\r\nbody"
                )
                .into_bytes(),
                Arc::clone(&written),
            );
            let server = Http1Server::with_config_upgradeable(
                |_request| async move {
                    let response = Response::new(101, "Switching Protocols", Vec::new())
                        .with_header("connection", "Upgrade")
                        .with_header("upgrade", "websocket")
                        .with_header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
                    Http1Response::new(response)
                        .with_upgrade(Http1Upgrade::new(|_cx, _io, _read_ahead| async {}))
                },
                localhost_server_config(),
            );
            let runtime = RuntimeBuilder::current_thread()
                .build()
                .expect("build current-thread runtime");
            let error = match runtime
                .block_on(async { server.serve_upgradeable_with_peer_addr(io, None).await })
            {
                Err(error) => error,
                Ok(_) => panic!("{method} with a body must refuse handoff"),
            };
            assert!(
                matches!(&error, HttpError::Io(error) if error.to_string().contains(expected)),
                "{method}: {error:?}"
            );
            assert!(written.lock().unwrap().is_empty());
        }
    }

    fn deflate_handoff(offer: Option<&str>) -> Result<Http1ServeOutcome<TestIo>, HttpError> {
        let written = Arc::new(Mutex::new(Vec::new()));
        let mut input = String::from(
            "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n",
        );
        if let Some(offer) = offer {
            input.push_str(&format!("Sec-WebSocket-Extensions: {offer}\r\n"));
        }
        input.push_str("\r\n");
        let io = TestIo::new(input.into_bytes(), Arc::clone(&written));
        let server = Http1Server::with_config_upgradeable(
            |_request| async move {
                let response = Response::new(101, "Switching Protocols", Vec::new())
                    .with_header("connection", "Upgrade")
                    .with_header("upgrade", "websocket")
                    .with_header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
                    .with_header("sec-websocket-extensions", "permessage-deflate");
                Http1Response::new(response).with_upgrade(
                    Http1Upgrade::new(|_cx, _io, _read_ahead| async {})
                        .with_websocket_negotiation(None, vec!["permessage-deflate".to_owned()]),
                )
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        runtime.block_on(async { server.serve_upgradeable_with_peer_addr(io, None).await })
    }

    #[test]
    fn upgradeable_server_hands_off_a_negotiated_extension_the_client_offered() {
        let outcome = deflate_handoff(Some("permessage-deflate; client_max_window_bits"))
            .expect("negotiated permessage-deflate handoff");
        assert!(matches!(outcome, Http1ServeOutcome::Upgraded { .. }));
    }

    #[test]
    fn upgradeable_server_refuses_an_extension_the_client_never_offered() {
        let error = match deflate_handoff(None) {
            Err(error) => error,
            Ok(_) => panic!("an unoffered extension must refuse handoff"),
        };
        assert!(
            matches!(error, HttpError::Io(ref error) if error.kind() == io::ErrorKind::InvalidData)
        );
    }

    #[test]
    fn websocket_negotiation_requires_the_exact_negotiated_extensions() {
        let response = |extensions: Option<&str>| {
            let response = Response::new(101, "Switching Protocols", Vec::new());
            match extensions {
                Some(value) => response.with_header("sec-websocket-extensions", value),
                None => response,
            }
        };
        let deflate = Http1Upgrade::new(|_cx, _io, _read_ahead| async {})
            .with_websocket_negotiation(None, vec!["permessage-deflate".to_owned()]);
        let plain = Http1Upgrade::new(|_cx, _io, _read_ahead| async {});
        assert!(deflate.websocket_negotiation_matches(&response(Some("permessage-deflate"))));
        assert!(deflate.websocket_negotiation_matches(&response(Some("Permessage-Deflate"))));
        assert!(!deflate.websocket_negotiation_matches(&response(None)));
        assert!(!deflate.websocket_negotiation_matches(&response(Some(
            "permessage-deflate; server_no_context_takeover"
        ))));
        assert!(
            !deflate.websocket_negotiation_matches(&response(Some("permessage-deflate, x-other")))
        );
        assert!(plain.websocket_negotiation_matches(&response(None)));
        assert!(!plain.websocket_negotiation_matches(&response(Some("permessage-deflate"))));
    }

    #[test]
    fn serve_emits_budget_trace_events_at_server_hop() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let trace_probe: Arc<Mutex<Option<crate::trace::TraceBufferHandle>>> =
            Arc::new(Mutex::new(None));
        let probe = Arc::clone(&trace_probe);
        let server = Http1Server::with_config(
            move |_req| {
                let probe = Arc::clone(&probe);
                async move {
                    *probe.lock().unwrap() = Cx::with_current(|cx| cx.trace_buffer()).flatten();
                    Response::new(200, "OK", b"ok")
                }
            },
            localhost_server_config().request_timeout(Some(Duration::from_secs(30))),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        runtime
            .block_on(async { server.serve(io).await })
            .expect("serve request");

        let trace = trace_probe
            .lock()
            .unwrap()
            .clone()
            .expect("request cx must carry the runtime trace buffer");
        use crate::trace::event::{TraceData, TraceEventKind};
        let events: Vec<(TraceEventKind, TraceData)> = trace
            .snapshot()
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    TraceEventKind::BudgetInstalled | TraceEventKind::BudgetConsumed
                )
            })
            .map(|e| (e.kind, e.data.clone()))
            .collect();
        assert_eq!(
            events.len(),
            2,
            "expected installed + consumed events, got {events:?}"
        );
        assert_eq!(events[0].0, TraceEventKind::BudgetInstalled);
        let TraceData::Budget {
            protocol, source, ..
        } = &events[0].1
        else {
            panic!("expected Budget data, got {:?}", events[0].1);
        };
        assert_eq!(protocol, "h1");
        assert_eq!(source.as_deref(), Some("config"));
        assert_eq!(events[1].0, TraceEventKind::BudgetConsumed);
        let TraceData::Budget {
            protocol, outcome, ..
        } = &events[1].1
        else {
            panic!("expected Budget data, got {:?}", events[1].1);
        };
        assert_eq!(protocol, "h1");
        assert_eq!(outcome.as_deref(), Some("ok"));
    }
