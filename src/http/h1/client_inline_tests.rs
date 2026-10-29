    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::bytes::{Buf, BytesMut};
    use crate::codec::Decoder;
    use std::pin::Pin;
    use std::task::{Context, Waker};

    #[test]
    fn decode_simple_response() {
        let mut codec = Http1ClientCodec::new();
        let mut buf = BytesMut::from(&b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"[..]);
        let resp = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.reason, "OK");
        assert_eq!(resp.version, Version::Http11);
        assert_eq!(resp.body, b"hello");
        assert!(resp.trailers.is_empty());
    }

    /// A pipelined HEAD response carries Content-Length but no body. The codec
    /// must frame it by the HEAD it encoded, not read the next response as the
    /// HEAD body.
    #[test]
    fn head_response_is_bodyless_and_leaves_the_next_response_intact() {
        let request = |method: Method, uri: &str| Request {
            method,
            uri: uri.to_string(),
            version: Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };
        let mut codec = Http1ClientCodec::new();
        let mut wire = BytesMut::new();
        codec
            .encode(request(Method::Head, "/head"), &mut wire)
            .expect("encode HEAD");
        codec
            .encode(request(Method::Get, "/get"), &mut wire)
            .expect("encode GET");

        let mut buf = BytesMut::from(
            &b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"[..],
        );
        let head = codec.decode(&mut buf).unwrap().expect("HEAD response");
        assert_eq!(head.status, 200);
        assert!(head.body.is_empty(), "a HEAD response has no body");
        let get = codec.decode(&mut buf).unwrap().expect("GET response");
        assert_eq!(get.body, b"ok");
        assert!(buf.is_empty());
    }

    /// Past its pending-method limit the codec drops the oldest method, so
    /// every later response would be paired with the wrong request: a GET's
    /// body read as the head that follows a HEAD. Decoding then fails instead.
    #[test]
    fn client_codec_refuses_to_frame_responses_after_dropping_a_method() {
        let request = |method: Method| Request {
            method,
            uri: "/".to_string(),
            version: Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };
        let response = &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"[..];
        let mut wire = BytesMut::new();

        // At the limit, every response still pairs with its own request.
        let mut codec = Http1ClientCodec::new();
        for _ in 0..MAX_PENDING_METHODS {
            codec.encode(request(Method::Get), &mut wire).unwrap();
        }
        let mut buf = BytesMut::from(response);
        let get = codec.decode(&mut buf).unwrap().expect("GET response");
        assert_eq!(get.body, b"ok");

        // One request more: the first GET's method is dropped, and the first
        // response would have been framed as the second request's.
        let mut codec = Http1ClientCodec::new();
        for _ in 0..MAX_PENDING_METHODS {
            codec.encode(request(Method::Get), &mut wire).unwrap();
        }
        codec.encode(request(Method::Head), &mut wire).unwrap();
        let mut buf = BytesMut::from(response);
        assert!(matches!(codec.decode(&mut buf), Err(HttpError::Io(_))));
    }

    /// A legacy server's Latin-1 byte in a field value (obs-text) is decoded
    /// as Latin-1 instead of failing the whole response.
    #[test]
    fn latin1_obs_text_in_a_response_head_is_decoded_not_rejected() {
        let mut codec = Http1ClientCodec::new();
        let mut buf = BytesMut::from(
            &b"HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename=\"caf\xe9.txt\"\r\nContent-Length: 2\r\n\r\nok"[..],
        );
        let response = codec
            .decode(&mut buf)
            .expect("obs-text is legal in a field value")
            .expect("complete response");
        assert_eq!(
            response
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-disposition"))
                .map(|(_, value)| value.as_str()),
            Some("attachment; filename=\"caf\u{e9}.txt\"")
        );
        assert_eq!(response.body, b"ok");
    }

    #[test]
    fn parse_status_line_rejects_non_three_digit_status_codes() {
        for line in [
            "HTTP/1.1 20 OK",
            "HTTP/1.1 0200 OK",
            "HTTP/1.1 2000 OK",
            "HTTP/1.1 2O0 OK",
            "HTTP/1.1 099 Continue?",
            "HTTP/1.1 000 Zero",
        ] {
            let result = parse_status_line(line);
            assert!(
                matches!(result, Err(HttpError::BadRequestLine)),
                "line {line:?} should reject non-three-digit or out-of-range status code, got {result:?}"
            );
        }
    }

    #[test]
    fn decode_rejects_non_three_digit_wire_status_codes() {
        for line in [
            "HTTP/1.1 20 OK",
            "HTTP/1.1 0200 OK",
            "HTTP/1.1 2000 OK",
            "HTTP/1.1 2O0 OK",
        ] {
            let raw = format!("{line}\r\nContent-Length: 0\r\n\r\n");
            let mut codec = Http1ClientCodec::new();
            let mut buf = BytesMut::from(raw.as_bytes());
            let result = codec.decode(&mut buf);

            assert!(
                matches!(result, Err(HttpError::BadRequestLine)),
                "wire status line {line:?} should poison the response decoder, got {result:?}"
            );
        }
    }

    #[test]
    fn parse_status_line_rejects_forbidden_reason_phrase_controls() {
        for line in [
            "HTTP/1.1 200 OK\0tail",
            "HTTP/1.1 200 OK\u{000b}tail",
            "HTTP/1.1 200 OK\u{000c}tail",
            "HTTP/1.1 200 OK\u{007f}tail",
        ] {
            let result = parse_status_line(line);
            assert!(
                matches!(result, Err(HttpError::BadRequestLine)),
                "reason phrase controls in {line:?} must be rejected, got {result:?}"
            );
        }
    }

    #[test]
    fn parse_status_line_allows_reason_phrase_htab_visible_and_obs_text() {
        let (version, status, reason) =
            parse_status_line("HTTP/1.1 200 OK\tReady \u{00e9}").expect("valid reason phrase");

        assert_eq!(version, Version::Http11);
        assert_eq!(status, 200);
        assert_eq!(reason, "OK\tReady \u{00e9}");
    }

    #[test]
    fn decode_rejects_wire_reason_phrase_controls() {
        for line in ["HTTP/1.1 200 OK\0tail", "HTTP/1.1 200 OK\u{007f}tail"] {
            let raw = format!("{line}\r\nContent-Length: 0\r\n\r\n");
            let mut codec = Http1ClientCodec::new();
            let mut buf = BytesMut::from(raw.as_bytes());
            let result = codec.decode(&mut buf);

            assert!(
                matches!(result, Err(HttpError::BadRequestLine)),
                "wire reason phrase controls in {line:?} should poison the response decoder, got {result:?}"
            );
        }
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = std::pin::pin!(f);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn poll_body<B: Body + Unpin>(body: &mut B) -> Option<Result<Frame<B::Data>, B::Error>> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        loop {
            match Pin::new(&mut *body).poll_frame(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[derive(Debug)]
    struct TestIo {
        read: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl TestIo {
        fn new(read_bytes: &[u8]) -> Self {
            Self {
                read: std::io::Cursor::new(read_bytes.to_vec()),
                written: Vec::new(),
            }
        }
    }

    impl AsyncRead for TestIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let dst = buf.unfilled();
            let n = std::io::Read::read(&mut self.read, dst)?;
            buf.advance(n);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TestIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            src: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.written.extend_from_slice(src);
            Poll::Ready(Ok(src.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct ExpectContinueIo {
        read: std::io::Cursor<Vec<u8>>,
        writes: Vec<Vec<u8>>,
    }

    impl ExpectContinueIo {
        fn new(read_bytes: &[u8]) -> Self {
            Self {
                read: std::io::Cursor::new(read_bytes.to_vec()),
                writes: Vec::new(),
            }
        }
    }

    impl AsyncRead for ExpectContinueIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let dst = buf.unfilled();
            let n = std::io::Read::read(&mut self.read, dst)?;
            buf.advance(n);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ExpectContinueIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            src: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.writes.push(src.to_vec());
            Poll::Ready(Ok(src.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn request_streaming_content_length() {
        let response_bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let io = TestIo::new(response_bytes);

        let req = Request {
            method: Method::Get,
            uri: "/".to_string(),
            version: Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let mut resp = block_on(Http1Client::request_streaming(io, req)).expect("streaming resp");
        assert_eq!(resp.head.status, 200);

        let mut collected = Vec::new();
        while let Some(frame) = poll_body(&mut resp.body) {
            let frame = frame.expect("frame ok");
            match frame {
                Frame::Data(mut buf) => {
                    while buf.has_remaining() {
                        let chunk = buf.chunk();
                        collected.extend_from_slice(chunk);
                        buf.advance(chunk.len());
                    }
                }
                Frame::Trailers(_) => {}
            }
        }

        assert_eq!(collected, b"hello");
    }

    #[test]
    fn pooled_streaming_reuse_requires_a_complete_message_without_read_ahead() {
        for (wire, reusable, residual) in [
            (&b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"[..], true, &b""[..]),
            (&b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokNEXT"[..], false, &b"NEXT"[..]),
            (&b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nNEXT"[..], false, &b"NEXT"[..]),
            (&b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nx-end: yes\r\n\r\n"[..], true, &b""[..]),
            (&b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\nNEXT"[..], false, &b"NEXT"[..]),
            (&b"HTTP/1.1 200 OK\r\n\r\nok"[..], false, &b""[..]),
        ] {
            let request = Request {
                method: Method::Get,
                uri: "/".into(),
                version: Version::Http11,
                headers: vec![("Host".into(), "example.com".into())],
                body: Vec::new(),
                trailers: Vec::new(),
                peer_addr: None,
            };
            let mut response = block_on(Http1Client::request_streaming(TestIo::new(wire), request))
                .expect("parse the actual HTTP wire");
            while let Some(frame) = poll_body(&mut response.body) {
                frame.expect("body framing is valid");
            }
            assert_eq!(response.body.is_complete_for_reuse(), reusable, "{wire:?}");
            let (_, buffer) = response.body.into_inner_with_buffer();
            assert_eq!(buffer.as_ref(), residual, "read-ahead must remain visible");
        }
    }

    #[test]
    fn request_streaming_chunked_with_trailers() {
        let response_bytes = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nFoo: Bar\r\n\r\n";
        let io = TestIo::new(response_bytes);

        let req = Request {
            method: Method::Get,
            uri: "/".to_string(),
            version: Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let mut resp = block_on(Http1Client::request_streaming(io, req)).expect("streaming resp");
        assert_eq!(resp.head.status, 200);

        let mut data = Vec::new();
        let mut saw_trailers = false;

        while let Some(frame) = poll_body(&mut resp.body) {
            let frame = frame.expect("frame ok");
            match frame {
                Frame::Data(mut buf) => {
                    while buf.has_remaining() {
                        let chunk = buf.chunk();
                        data.extend_from_slice(chunk);
                        buf.advance(chunk.len());
                    }
                }
                Frame::Trailers(trailers) => {
                    saw_trailers = true;
                    let foo = trailers.get(&HeaderName::from_static("foo")).unwrap();
                    assert_eq!(foo.as_bytes(), b"Bar");
                }
            }
        }

        assert_eq!(data, b"hello");
        assert!(saw_trailers);
    }

    #[test]
    fn request_head_response_ignores_content_length_body() {
        let response_bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        let io = TestIo::new(response_bytes);

        let req = Request {
            method: Method::Head,
            uri: "/".to_string(),
            version: Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let resp = block_on(Http1Client::request(io, req)).expect("head response");
        assert_eq!(resp.status, 200);
        assert!(resp.body.is_empty());
        assert!(resp.trailers.is_empty());
    }

    #[test]
    fn request_streaming_skips_informational_response() {
        let response_bytes =
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let io = TestIo::new(response_bytes);

        let req = Request {
            method: Method::Post,
            uri: "/upload".to_string(),
            version: Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: b"data".to_vec(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let mut resp = block_on(Http1Client::request_streaming(io, req)).expect("streaming resp");
        assert_eq!(resp.head.status, 200);

        let mut collected = Vec::new();
        while let Some(frame) = poll_body(&mut resp.body) {
            let frame = frame.expect("frame ok");
            if let Frame::Data(mut buf) = frame {
                while buf.has_remaining() {
                    let chunk = buf.chunk();
                    collected.extend_from_slice(chunk);
                    buf.advance(chunk.len());
                }
            }
        }
        assert_eq!(collected, b"hello");
    }

    #[test]
    fn request_streaming_expect_continue_sends_body_only_after_continue() {
        let response_bytes =
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let io = ExpectContinueIo::new(response_bytes);

        let req = Request {
            method: Method::Post,
            uri: "/upload".to_string(),
            version: Version::Http11,
            headers: vec![
                ("Host".to_string(), "example.com".to_string()),
                ("Expect".to_string(), "100-continue".to_string()),
            ],
            body: b"hello".to_vec(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let resp = block_on(Http1Client::request_with_io(io, req)).expect("response");
        assert_eq!(resp.0.status, 200);
        assert_eq!(resp.0.body, b"ok");

        let writes = resp.1.writes;
        assert!(
            writes.len() >= 2,
            "expect-continue flow should split head and body writes"
        );

        let first_write = String::from_utf8(writes[0].clone()).expect("headers should be utf8");
        assert!(first_write.contains("Expect: 100-continue\r\n"));
        assert!(
            first_write.ends_with("\r\n\r\n"),
            "first write should contain only request head"
        );
        assert!(
            !first_write.contains("hello"),
            "request body must not be sent before 100 Continue"
        );

        let body_bytes = writes[1..].concat();
        assert_eq!(body_bytes, b"hello");
    }

    #[test]
    fn request_streaming_expect_continue_skips_body_on_early_final_response() {
        let response_bytes = b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n";
        let io = ExpectContinueIo::new(response_bytes);

        let req = Request {
            method: Method::Post,
            uri: "/upload".to_string(),
            version: Version::Http11,
            headers: vec![
                ("Host".to_string(), "example.com".to_string()),
                ("Expect".to_string(), "100-continue".to_string()),
            ],
            body: b"hello".to_vec(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let resp = block_on(Http1Client::request_with_io(io, req)).expect("response");
        assert_eq!(resp.0.status, 417);
        // The Expect:100-continue body was withheld (final response arrived
        // without a 100), so the connection must be flagged non-reusable
        // (br-asupersync-h1-expect-100-pool-h9le7v).
        assert!(
            resp.2,
            "withheld Expect:100 body must mark the connection body_withheld"
        );

        let writes = resp.1.writes;
        assert_eq!(
            writes.len(),
            1,
            "early final response must suppress body upload"
        );

        let first_write = String::from_utf8(writes[0].clone()).expect("headers should be utf8");
        assert!(first_write.contains("Expect: 100-continue\r\n"));
        assert!(
            first_write.ends_with("\r\n\r\n"),
            "only the request head should be written"
        );
        assert!(
            !first_write.contains("hello"),
            "request body must not be sent after early final response"
        );
    }

    /// A server that ignores `Expect: 100-continue`: it sends nothing until it
    /// has read the whole request body, then answers.
    #[derive(Debug)]
    struct IgnoresExpectationIo {
        body: Vec<u8>,
        written: Vec<u8>,
        response: std::io::Cursor<Vec<u8>>,
    }

    impl AsyncRead for IgnoresExpectationIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if !self.written.ends_with(&self.body) {
                return Poll::Pending;
            }
            let dst = buf.unfilled();
            let n = std::io::Read::read(&mut self.response, dst)?;
            buf.advance(n);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for IgnoresExpectationIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            src: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.written.extend_from_slice(src);
            Poll::Ready(Ok(src.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn request_streaming_expect_continue_sends_the_body_when_the_server_ignores_it() {
        let io = IgnoresExpectationIo {
            body: b"hello".to_vec(),
            written: Vec::new(),
            response: std::io::Cursor::new(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
            ),
        };
        let req = Request {
            method: Method::Post,
            uri: "/upload".to_string(),
            version: Version::Http11,
            headers: vec![
                ("Host".to_string(), "example.com".to_string()),
                ("Expect".to_string(), "100-continue".to_string()),
            ],
            body: b"hello".to_vec(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        // Without the fallback the request waits for a 100 Continue that never
        // comes, so run it on a thread and bound the wait.
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done_tx.send(block_on(Http1Client::request_with_io(io, req)));
        });
        let (response, io, body_withheld) = done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the body is sent once the expectation wait elapses")
            .expect("response");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        assert!(!body_withheld, "the body was sent");
        assert!(
            io.written.ends_with(b"\r\n\r\nhello"),
            "head, then the body"
        );
    }

    /// Answers the expectation only once told to, and never wakes a reader.
    #[derive(Debug)]
    struct AnswersWhenToldIo {
        answered: std::sync::Arc<std::sync::atomic::AtomicBool>,
        written: Vec<u8>,
        response: std::io::Cursor<Vec<u8>>,
    }

    impl AsyncRead for AnswersWhenToldIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if !self.answered.load(std::sync::atomic::Ordering::SeqCst) {
                return Poll::Pending;
            }
            let dst = buf.unfilled();
            let n = std::io::Read::read(&mut self.response, dst)?;
            buf.advance(n);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for AnswersWhenToldIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            src: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.written.extend_from_slice(src);
            Poll::Ready(Ok(src.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn expect_continue_upload(body: &[u8]) -> Request {
        Request {
            method: Method::Post,
            uri: "/upload".to_string(),
            version: Version::Http11,
            headers: vec![
                ("Host".to_string(), "example.com".to_string()),
                ("Expect".to_string(), "100-continue".to_string()),
            ],
            body: body.to_vec(),
            trailers: Vec::new(),
            peer_addr: None,
        }
    }

    /// The server answers within the expectation wait, but the task is next
    /// polled after the wait elapsed. The answer is already readable, so the
    /// body must not be uploaded (RFC 9110 section 10.1.1).
    #[test]
    fn request_streaming_expect_continue_reads_an_answer_that_arrived_before_the_wait_elapsed() {
        use crate::time::{TimerDriverHandle, VirtualClock};
        let clock = std::sync::Arc::new(VirtualClock::starting_at(crate::types::Time::ZERO));
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = crate::cx::Cx::new_with_drivers(
            crate::types::RegionId::new_for_test(0, 1),
            crate::types::TaskId::new_for_test(0, 0),
            crate::types::Budget::INFINITE,
            None,
            None,
            None,
            Some(timer),
            None,
        );
        let _current = crate::cx::Cx::set_current(Some(cx));
        let answered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let io = AnswersWhenToldIo {
            answered: std::sync::Arc::clone(&answered),
            written: Vec::new(),
            response: std::io::Cursor::new(
                b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n".to_vec(),
            ),
        };
        let mut request = std::pin::pin!(Http1Client::request_with_io(
            io,
            expect_continue_upload(b"hello")
        ));
        let mut task_cx = Context::from_waker(Waker::noop());
        assert!(
            request.as_mut().poll(&mut task_cx).is_pending(),
            "the client waits for an answer to the expectation"
        );
        answered.store(true, std::sync::atomic::Ordering::SeqCst);
        clock.advance(2_000_000_000);
        let Poll::Ready(result) = request.as_mut().poll(&mut task_cx) else {
            panic!("the answer is already readable");
        };
        let (response, io, body_withheld) = result.expect("response");
        assert_eq!(response.status, 417);
        assert!(body_withheld, "the body was never sent");
        assert!(
            io.written.ends_with(b"\r\n\r\n"),
            "only the request head was written"
        );
    }

    /// Ignores the expectation, then rejects the upload: the body write fails
    /// with a broken pipe, after which the server's 413 is readable.
    #[derive(Debug)]
    struct RejectsTheUploadIo {
        head_written: bool,
        upload_failed: bool,
        response: std::io::Cursor<Vec<u8>>,
        // Bytes the first write accepts (all when None). A request written in
        // one piece then fails partway, after the head.
        first_write_limit: Option<usize>,
    }

    impl AsyncRead for RejectsTheUploadIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if !self.upload_failed {
                return Poll::Pending;
            }
            let dst = buf.unfilled();
            let n = std::io::Read::read(&mut self.response, dst)?;
            buf.advance(n);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for RejectsTheUploadIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            src: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.head_written {
                self.upload_failed = true;
                return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
            }
            self.head_written = true;
            Poll::Ready(Ok(self
                .first_write_limit
                .map_or(src.len(), |limit| limit.min(src.len()))))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A server that rejects slowly answers 413 and closes while the body is
    /// uploading. The client reports that 413, not the broken pipe.
    #[test]
    fn request_streaming_expect_continue_reports_the_answer_to_a_rejected_upload() {
        let io = RejectsTheUploadIo {
            head_written: false,
            upload_failed: false,
            response: std::io::Cursor::new(
                b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_vec(),
            ),
            first_write_limit: None,
        };
        let req = expect_continue_upload(b"hello");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done_tx.send(block_on(Http1Client::request_with_io(io, req)));
        });
        let (response, io, body_withheld) = done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the request finishes after the expectation wait")
            .expect("the server's answer, not the broken pipe");
        assert_eq!(response.status, 413);
        assert!(body_withheld, "the upload did not complete");
        assert!(io.upload_failed);
    }

    /// Without `Expect: 100-continue` the head and body go out in one write.
    /// A server that answers 413 (or 401) after the head and closes while the
    /// body is uploading surfaced as the broken pipe, with its answer unread.
    #[test]
    fn request_reports_the_answer_to_an_upload_rejected_mid_write() {
        let io = RejectsTheUploadIo {
            head_written: false,
            upload_failed: false,
            response: std::io::Cursor::new(
                b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_vec(),
            ),
            first_write_limit: Some(64),
        };
        let req = Request {
            method: Method::Post,
            uri: "/upload".to_string(),
            version: Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: vec![b'x'; 4096],
            trailers: Vec::new(),
            peer_addr: None,
        };
        let (response, io, body_withheld) = block_on(Http1Client::request_with_io(io, req))
            .expect("the server's answer, not the broken pipe");
        assert_eq!(response.status, 413);
        assert!(body_withheld, "the upload did not complete");
        assert!(io.upload_failed);
    }

    /// A connection that is already dead (nothing answers) still reports the
    /// write failure itself, so callers and stale-reuse retries see the same
    /// error as before.
    #[test]
    fn request_reports_the_write_failure_when_no_answer_arrives() {
        let io = RejectsTheUploadIo {
            head_written: false,
            upload_failed: false,
            response: std::io::Cursor::new(Vec::new()),
            first_write_limit: Some(64),
        };
        let req = Request {
            method: Method::Post,
            uri: "/upload".to_string(),
            version: Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: vec![b'x'; 4096],
            trailers: Vec::new(),
            peer_addr: None,
        };
        let error = block_on(Http1Client::request_with_io(io, req))
            .expect_err("no response, so the write failure is the result");
        assert!(
            matches!(error, HttpError::Io(ref io_error) if io_error.kind() == std::io::ErrorKind::BrokenPipe),
            "unexpected error {error:?}"
        );
    }

    #[test]
    fn request_streaming_upgrade_preserves_prefetched_bytes() {
        let response_bytes =
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n\x81\x00";
        let io = TestIo::new(response_bytes);

        let req = Request {
            method: Method::Get,
            uri: "/ws".to_string(),
            version: Version::Http11,
            headers: vec![
                ("Host".to_string(), "example.com".to_string()),
                ("Connection".to_string(), "Upgrade".to_string()),
                ("Upgrade".to_string(), "websocket".to_string()),
            ],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let resp = block_on(Http1Client::request_streaming(io, req)).expect("streaming resp");
        assert_eq!(resp.head.status, 101);

        let (mut io, prefetched) = resp.body.into_inner_with_buffer();
        assert_eq!(prefetched.as_ref(), b"\x81\x00");

        // Bytes were consumed into the prefetched buffer (not left unread in the transport).
        let mut tail = [0u8; 8];
        let n = std::io::Read::read(&mut io.read, &mut tail).expect("cursor read");
        assert_eq!(n, 0);
    }

    #[test]
    fn request_skips_informational_response() {
        let response_bytes = b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let io = TestIo::new(response_bytes);

        let req = Request {
            method: Method::Get,
            uri: "/".to_string(),
            version: Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let resp = block_on(Http1Client::request(io, req)).expect("response");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"ok");
    }

    #[test]
    fn request_streaming_handles_bounded_multiple_informational_responses() {
        let response_bytes = concat!(
            "HTTP/1.1 100 Continue\r\n\r\n",
            "HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n",
            "HTTP/1.1 102 Processing\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        )
        .as_bytes();
        let io = ExpectContinueIo::new(response_bytes);

        let req = Request {
            method: Method::Post,
            uri: "/upload".to_string(),
            version: Version::Http11,
            headers: vec![
                ("Host".to_string(), "example.com".to_string()),
                ("Expect".to_string(), "100-continue".to_string()),
            ],
            body: b"hello".to_vec(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let resp = block_on(Http1Client::request_with_io(io, req)).expect("response");
        assert_eq!(resp.0.status, 200);
        assert_eq!(resp.0.body, b"ok");

        let writes = resp.1.writes;
        assert!(
            writes.len() >= 2,
            "100 Continue should still release the deferred request body"
        );
        assert_eq!(writes[1..].concat(), b"hello");
    }

    #[test]
    fn request_rejects_excessive_informational_responses() {
        let mut response_bytes = Vec::new();
        for _ in 0..=MAX_INFORMATIONAL_RESPONSES {
            response_bytes.extend_from_slice(b"HTTP/1.1 103 Early Hints\r\n\r\n");
        }
        response_bytes.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let io = TestIo::new(&response_bytes);

        let req = Request {
            method: Method::Get,
            uri: "/".to_string(),
            version: Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let err = block_on(Http1Client::request(io, req)).expect_err("excessive 1xx must fail");
        match err {
            HttpError::TooManyInformationalResponses { actual, limit } => {
                assert_eq!(actual, MAX_INFORMATIONAL_RESPONSES + 1);
                assert_eq!(limit, MAX_INFORMATIONAL_RESPONSES);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn request_rejects_malformed_interim_response_headers() {
        let response_bytes = b"HTTP/1.1 103 Early Hints\r\nBadHeader\r\n\r\n";
        let io = TestIo::new(response_bytes);

        let req = Request {
            method: Method::Get,
            uri: "/".to_string(),
            version: Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let err = block_on(Http1Client::request(io, req)).expect_err("bad interim header");
        assert!(matches!(err, HttpError::BadHeader));
    }

    #[test]
    fn request_with_io_returns_transport_for_reuse() {
        let response_bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let io = TestIo::new(response_bytes);

        let req = Request {
            method: Method::Get,
            uri: "/reuse".to_string(),
            version: Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let (resp, io, body_withheld) =
            block_on(Http1Client::request_with_io(io, req)).expect("response");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"ok");
        assert!(!body_withheld, "full body was sent; connection is reusable");
        let request_bytes = String::from_utf8(io.written).expect("request write should be utf8");
        assert!(request_bytes.starts_with("GET /reuse HTTP/1.1\r\n"));
        assert!(request_bytes.contains("Host: example.com\r\n"));
    }

    #[test]
    fn request_with_io_rejects_unread_prefetched_bytes() {
        let response_bytes =
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n\x81\x00";
        let io = TestIo::new(response_bytes);

        let req = Request {
            method: Method::Get,
            uri: "/ws".to_string(),
            version: Version::Http11,
            headers: vec![
                ("Host".to_string(), "example.com".to_string()),
                ("Connection".to_string(), "Upgrade".to_string()),
                ("Upgrade".to_string(), "websocket".to_string()),
            ],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let err = block_on(Http1Client::request_with_io(io, req)).expect_err("must reject");
        match err {
            HttpError::PrefetchedDataRemaining(count) => assert_eq!(count, 2),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn request_rejects_unread_prefetched_bytes() {
        let response_bytes =
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n\x81\x00";
        let io = TestIo::new(response_bytes);

        let req = Request {
            method: Method::Get,
            uri: "/ws".to_string(),
            version: Version::Http11,
            headers: vec![
                ("Host".to_string(), "example.com".to_string()),
                ("Connection".to_string(), "Upgrade".to_string()),
                ("Upgrade".to_string(), "websocket".to_string()),
            ],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let err = block_on(Http1Client::request(io, req)).expect_err("must reject");
        match err {
            HttpError::PrefetchedDataRemaining(count) => assert_eq!(count, 2),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn decode_response_no_body() {
        let mut codec = Http1ClientCodec::new();
        let mut buf = BytesMut::from(&b"HTTP/1.1 204 No Content\r\n\r\n"[..]);
        let resp = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(resp.status, 204);
        assert!(resp.body.is_empty());
        assert!(resp.trailers.is_empty());
    }

    #[test]
    fn decode_response_incomplete() {
        let mut codec = Http1ClientCodec::new();
        let mut buf = BytesMut::from(&b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhel"[..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn response_framing_uses_only_rfc_ows() {
        let mut codec = Http1ClientCodec::new();
        let mut buf = BytesMut::from(
            &b"HTTP/1.1 200 OK\r\nContent-Length: \xC2\xA05\xC2\xA0\r\n\r\nhello"[..],
        );
        assert!(matches!(
            codec.decode(&mut buf),
            Err(HttpError::BadContentLength)
        ));

        let mut codec = Http1ClientCodec::new();
        let mut buf = BytesMut::from(
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: \xC2\xA0chunked\xC2\xA0\r\n\r\n0\r\n\r\n"[..],
        );
        assert!(matches!(
            codec.decode(&mut buf),
            Err(HttpError::BadTransferEncoding)
        ));

        let mut codec = Http1ClientCodec::new();
        let mut buf =
            BytesMut::from(&b"HTTP/1.1 200 OK\r\nContent-Length:\t 5 \t\r\n\r\nhello"[..]);
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap().body, b"hello");

        let headers = vec![("Content-Length".to_string(), "\u{a0}5\u{a0}".to_string())];
        assert!(matches!(
            response_body_kind(&headers, 200, &Method::Get, usize::MAX),
            Err(HttpError::BadContentLength)
        ));

        let mut codec = Http1ClientCodec::new();
        let request = Request {
            method: Method::Post,
            uri: "/".to_string(),
            version: Version::Http11,
            headers,
            body: b"hello".to_vec(),
            trailers: Vec::new(),
            peer_addr: None,
        };
        assert!(matches!(
            crate::codec::Encoder::encode(&mut codec, request, &mut BytesMut::new()),
            Err(HttpError::BadContentLength)
        ));
    }

    #[test]
    fn encode_request() {
        let mut codec = Http1ClientCodec::new();
        let req = Request {
            method: crate::http::h1::types::Method::Get,
            uri: "/index.html".into(),
            version: Version::Http11,
            headers: vec![("Host".into(), "example.com".into())],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };
        let mut buf = BytesMut::with_capacity(256);
        crate::codec::Encoder::encode(&mut codec, req, &mut buf).unwrap();
        let s = String::from_utf8(buf.to_vec()).unwrap();
        assert!(s.starts_with("GET /index.html HTTP/1.1\r\n"));
        assert!(s.contains("Host: example.com\r\n"));
    }

    #[test]
    fn encode_request_with_body() {
        let mut codec = Http1ClientCodec::new();
        let req = Request {
            method: crate::http::h1::types::Method::Post,
            uri: "/api".into(),
            version: Version::Http11,
            headers: vec![("Host".into(), "api.example.com".into())],
            body: b"data".to_vec(),
            trailers: Vec::new(),
            peer_addr: None,
        };
        let mut buf = BytesMut::with_capacity(256);
        crate::codec::Encoder::encode(&mut codec, req, &mut buf).unwrap();
        let s = String::from_utf8(buf.to_vec()).unwrap();
        assert!(s.contains("Content-Length: 4\r\n"));
        assert!(s.ends_with("\r\n\r\ndata"));
    }

    #[test]
    fn decode_chunked_response() {
        let mut codec = Http1ClientCodec::new();
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut buf = BytesMut::from(&raw[..]);
        let resp = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hello world");
        assert!(resp.trailers.is_empty());
    }

    #[test]
    fn decode_chunked_response_rejects_signed_chunk_size() {
        let mut codec = Http1ClientCodec::new();
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    +1\r\nx\r\n0\r\n\r\n";
        let mut buf = BytesMut::from(&raw[..]);
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(HttpError::BadChunkedEncoding)));
    }

    #[test]
    fn decode_chunked_response_with_trailers() {
        let mut codec = Http1ClientCodec::new();
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5\r\nhello\r\n0\r\nX-Trailer: one\r\nY-Trailer: two\r\n\r\n";
        let mut buf = BytesMut::from(&raw[..]);
        let resp = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(resp.body, b"hello");
        assert_eq!(resp.trailers.len(), 2);
        assert_eq!(resp.trailers[0].0, "X-Trailer");
        assert_eq!(resp.trailers[0].1, "one");
    }

    #[test]
    fn decode_chunked_response_preserves_non_ows_trailer_bytes() {
        let mut codec = Http1ClientCodec::new();
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    1\r\nx\r\n0\r\nX-Trailer: \xC2\xA0one\xC2\xA0\r\n\r\n";
        let mut buf = BytesMut::from(&raw[..]);
        let resp = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(resp.trailers[0].1, "\u{a0}one\u{a0}");
    }

    /// A response chunk-size line longer than the buffered codec's limit used
    /// to be buffered and rescanned on every read; it is now a framing error.
    #[test]
    fn streaming_chunk_size_line_is_bounded() {
        let mut response_bytes = Vec::new();
        response_bytes.extend_from_slice(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        response_bytes.extend_from_slice(b"1;");
        response_bytes.extend_from_slice(&[b'a'; 2048]);
        response_bytes.extend_from_slice(b"\r\nX\r\n0\r\n\r\n");

        let io = TestIo::new(&response_bytes);
        let req = Request {
            method: Method::Get,
            uri: "/".to_string(),
            version: Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let mut resp = block_on(Http1Client::request_streaming(io, req)).expect("streaming resp");
        assert_eq!(resp.head.status, 200);
        let frame = poll_body(&mut resp.body).expect("a terminal frame");
        assert!(
            matches!(frame, Err(HttpError::BadChunkedEncoding)),
            "{frame:?}"
        );
    }

    #[test]
    fn streaming_chunked_trailer_limit_does_not_count_terminal_crlf() {
        // ClientIncomingBody default trailer limit is 16 KiB. We construct a
        // single trailer line that exactly consumes that budget:
        // line "X:<value>" is 2 + value_len bytes; plus CRLF => +2.
        // Choose value_len=16380 so (2 + 16380 + 2) == 16384.
        let trailer_value = "a".repeat(16 * 1024 - 4);
        let mut response_bytes = Vec::new();
        response_bytes.extend_from_slice(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        response_bytes.extend_from_slice(b"0\r\nX:");
        response_bytes.extend_from_slice(trailer_value.as_bytes());
        response_bytes.extend_from_slice(b"\r\n\r\n");

        let io = TestIo::new(&response_bytes);
        let req = Request {
            method: Method::Get,
            uri: "/".to_string(),
            version: Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let mut resp = block_on(Http1Client::request_streaming(io, req)).expect("streaming resp");
        assert_eq!(resp.head.status, 200);

        let mut saw_trailers = false;
        while let Some(frame) = poll_body(&mut resp.body) {
            let frame = frame.expect("frame ok");
            match frame {
                Frame::Data(_) => return, // ignore in this test
                Frame::Trailers(trailers) => {
                    saw_trailers = true;
                    let header = trailers
                        .get(&HeaderName::from_static("x"))
                        .expect("trailer x");
                    assert_eq!(header.as_bytes().len(), trailer_value.len());
                }
            }
        }
        assert!(saw_trailers);
    }

    #[test]
    fn decode_response_without_length_is_eof_delimited() {
        let mut codec = Http1ClientCodec::new();
        let raw = b"HTTP/1.1 200 OK\r\n\r\nhello";
        let mut buf = BytesMut::from(&raw[..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
        let resp = codec.decode_eof(&mut buf).unwrap().unwrap();
        assert_eq!(resp.body, b"hello");
    }

    #[test]
    fn decode_eof_completes_close_delimited_responses_at_every_input_split() {
        for raw in [
            &b"HTTP/1.0 200 OK\r\n\r\nhello"[..],
            &b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"[..],
        ] {
            for split in 0..=raw.len() {
                let mut codec = Http1ClientCodec::new();
                let mut buf = BytesMut::from(&raw[..split]);
                assert!(codec.decode(&mut buf).unwrap().is_none());
                buf.extend_from_slice(&raw[split..]);
                let response = codec
                    .decode_eof(&mut buf)
                    .unwrap_or_else(|error| panic!("split {split} of {raw:?}: {error}"))
                    .expect("EOF completes a close-delimited response");
                assert_eq!(response.status, 200);
                assert_eq!(response.body, &raw[find_headers_end(raw).unwrap()..]);
                assert!(buf.is_empty());
                assert!(codec.decode_eof(&mut buf).unwrap().is_none());
            }
        }
    }

    #[test]
    fn decode_eof_drains_pipeline_ending_in_a_close_delimited_response() {
        let mut codec = Http1ClientCodec::new();
        let mut buf = BytesMut::from(
            &b"HTTP/1.1 100 Continue\r\n\r\n\
               HTTP/1.1 204 No Content\r\n\r\n\
               HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok\
               HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nlast"[..],
        );
        for (status, body) in [
            (100, &b""[..]),
            (204, &b""[..]),
            (200, &b"ok"[..]),
            (200, &b"last"[..]),
        ] {
            let response = codec.decode_eof(&mut buf).unwrap().unwrap();
            assert_eq!(response.status, status);
            assert_eq!(response.body, body);
        }
        assert!(buf.is_empty());
        assert!(codec.decode_eof(&mut buf).unwrap().is_none());
        assert!(codec.decode_eof(&mut buf).unwrap().is_none());
    }

    #[test]
    fn decode_eof_still_enforces_close_delimited_body_limits() {
        let mut codec = Http1ClientCodec::new().max_body_size(4);
        let mut buf = BytesMut::from(&b"HTTP/1.1 200 OK\r\n\r\nhello"[..]);
        assert!(matches!(
            codec.decode_eof(&mut buf),
            Err(HttpError::BodyTooLarge)
        ));
        assert!(matches!(
            codec.decode_eof(&mut buf),
            Err(HttpError::BadHeader)
        ));
    }

    #[test]
    fn decode_eof_mid_response_is_an_error_not_a_clean_end() {
        // A peer that closes after a response head whose body has not arrived,
        // or after the chunked decoder consumed every buffered byte, leaves
        // nothing buffered; decode_eof reported a clean end of the stream
        // instead of the truncated response.
        for raw in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"[..],
        ] {
            let mut codec = Http1ClientCodec::new();
            let mut buf = BytesMut::from(raw);
            assert!(codec.decode(&mut buf).unwrap().is_none());
            assert!(buf.is_empty(), "the decoder consumed what it could");
            let result = codec.decode_eof(&mut buf);
            assert!(
                matches!(&result, Err(HttpError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof),
                "{result:?}"
            );
        }

        // Between responses an end of input is still a clean end.
        let mut codec = Http1ClientCodec::new();
        let mut buf = BytesMut::from(&b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"[..]);
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap().body, b"ok");
        assert!(codec.decode_eof(&mut buf).unwrap().is_none());
    }

    #[test]
    fn decode_headers_too_large() {
        let mut codec = Http1ClientCodec::new().max_headers_size(32);
        let mut buf = BytesMut::from(&b"HTTP/1.1 200 OK\r\nX-Large: aaaaaaaaaaaaaaa\r\n\r\n"[..]);
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(HttpError::HeadersTooLarge)));
    }

    #[test]
    fn decode_body_too_large_content_length() {
        let mut codec = Http1ClientCodec::new().max_body_size(10);
        let mut buf = BytesMut::from(&b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"[..]);
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(HttpError::BodyTooLarge)));
    }

    #[test]
    fn decode_body_too_large_chunked() {
        let mut codec = Http1ClientCodec::new().max_body_size(10);
        // Chunked body with 20 bytes total (exceeds 10 byte limit)
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    14\r\n01234567890123456789\r\n0\r\n\r\n";
        let mut buf = BytesMut::from(&raw[..]);
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(HttpError::BodyTooLarge)));
    }

    #[test]
    fn decode_body_at_limit_succeeds() {
        let mut codec = Http1ClientCodec::new().max_body_size(5);
        let mut buf = BytesMut::from(&b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"[..]);
        let resp = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(resp.body, b"hello");
    }

    #[test]
    fn reject_both_content_length_and_transfer_encoding() {
        let mut codec = Http1ClientCodec::new();
        let mut buf = BytesMut::from(
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
        );
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(HttpError::AmbiguousBodyLength)));
    }

    #[test]
    fn reject_invalid_crlf_after_chunk() {
        let mut codec = Http1ClientCodec::new();
        // Invalid: missing proper CRLF after chunk data
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5\r\nhelloXX0\r\n\r\n";
        let mut buf = BytesMut::from(&raw[..]);
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(HttpError::BadChunkedEncoding)));
    }

    mod streaming_upload {
        use super::*;
        use crate::cx::Cx;
        use crate::http::h1::stream::RequestHead;
        use std::cell::RefCell;
        use std::collections::VecDeque;
        use std::marker::PhantomPinned;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        #[derive(Default)]
        struct Observed {
            written: Mutex<Vec<u8>>,
            write_polls: AtomicUsize,
            producer_polls: AtomicUsize,
            producer_drops: AtomicUsize,
            transport_drops: AtomicUsize,
            wakes: AtomicUsize,
        }

        impl std::task::Wake for Observed {
            fn wake(self: Arc<Self>) {
                self.wakes.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.wakes.fetch_add(1, Ordering::SeqCst);
            }
        }

        struct Segments(VecDeque<&'static [u8]>, PhantomPinned);

        impl Buf for Segments {
            fn remaining(&self) -> usize {
                self.0.iter().map(|segment| segment.len()).sum()
            }

            fn chunk(&self) -> &[u8] {
                self.0.front().copied().unwrap_or_default()
            }

            fn advance(&mut self, mut count: usize) {
                assert!(count <= self.remaining());
                while count != 0 {
                    let segment = self.0.pop_front().unwrap();
                    let consumed = count.min(segment.len());
                    count -= consumed;
                    if consumed != segment.len() {
                        self.0.push_front(&segment[consumed..]);
                    }
                }
            }
        }

        fn data(segments: &[&'static [u8]]) -> Result<Frame<Segments>, &'static str> {
            Ok(Frame::Data(Segments(
                segments.iter().copied().collect(),
                PhantomPinned,
            )))
        }

        // RefCell permits safe polling without projecting a pinned field.
        // PhantomPinned deliberately proves that the public API needs no Unpin.
        struct Producer {
            frames: RefCell<VecDeque<Result<Frame<Segments>, &'static str>>>,
            exact: Option<u64>,
            parked: bool,
            observed: Arc<Observed>,
            _pinned: PhantomPinned,
        }

        impl Body for Producer {
            type Data = Segments;
            type Error = &'static str;

            fn poll_frame(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
                let this = self.as_ref().get_ref();
                this.observed.producer_polls.fetch_add(1, Ordering::SeqCst);
                if this.parked {
                    Poll::Pending
                } else {
                    Poll::Ready(this.frames.borrow_mut().pop_front())
                }
            }

            fn size_hint(&self) -> SizeHint {
                self.exact.map_or_else(SizeHint::default, SizeHint::with_exact)
            }
        }

        impl Drop for Producer {
            fn drop(&mut self) {
                self.observed.producer_drops.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn producer(
            observed: &Arc<Observed>,
            exact: Option<u64>,
            frames: Vec<Result<Frame<Segments>, &'static str>>,
        ) -> Producer {
            Producer {
                frames: RefCell::new(frames.into()),
                exact,
                parked: false,
                observed: Arc::clone(observed),
                _pinned: PhantomPinned,
            }
        }

        struct UploadIo {
            observed: Arc<Observed>,
            answer_after: Option<Vec<u8>>,
            response: std::io::Cursor<Vec<u8>>,
            reader: Option<Waker>,
            pause_write: bool,
            partial: bool,
            write_failure: Option<std::io::ErrorKind>,
        }

        impl AsyncRead for UploadIo {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                let ready = self.answer_after.as_ref().is_some_and(|suffix| {
                    self.observed.written.lock().unwrap().ends_with(suffix)
                });
                if !ready {
                    self.reader = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                let count = std::io::Read::read(&mut self.response, buf.unfilled())?;
                buf.advance(count);
                Poll::Ready(Ok(()))
            }
        }

        impl AsyncWrite for UploadIo {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                self.observed.write_polls.fetch_add(1, Ordering::SeqCst);
                if let Some(kind) = self.write_failure {
                    return Poll::Ready(Err(std::io::Error::new(kind, "peer refused upload")));
                }
                if self.pause_write {
                    self.pause_write = false;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                self.pause_write = self.partial;
                let count = if self.partial {
                    bytes.len().min(2)
                } else {
                    bytes.len()
                };
                self.observed
                    .written
                    .lock()
                    .unwrap()
                    .extend_from_slice(&bytes[..count]);
                if let Some(reader) = self.reader.take() {
                    reader.wake();
                }
                Poll::Ready(Ok(count))
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        impl Drop for UploadIo {
            fn drop(&mut self) {
                self.observed.transport_drops.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn io(observed: &Arc<Observed>, answer_after: Option<&[u8]>) -> UploadIo {
            UploadIo {
                observed: Arc::clone(observed),
                answer_after: answer_after.map(|bytes| bytes.to_vec()),
                response: std::io::Cursor::new(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()),
                reader: None,
                pause_write: false,
                partial: true,
                write_failure: None,
            }
        }

        fn head(headers: &[(&str, &str)]) -> RequestHead {
            RequestHead {
                method: Method::Post,
                uri: "/upload".to_owned(),
                version: Version::Http11,
                headers: std::iter::once(("Host".to_owned(), "example.test".to_owned()))
                    .chain(
                        headers
                            .iter()
                            .map(|(name, value)| (name.to_string(), value.to_string())),
                    )
                    .collect(),
            }
        }

        fn drive<F: Future>(future: F) -> F::Output {
            let mut future = std::pin::pin!(future);
            let mut task = Context::from_waker(Waker::noop());
            for _ in 0..10_000 {
                if let Poll::Ready(result) = future.as_mut().poll(&mut task) {
                    return result;
                }
            }
            panic!("streaming exchange made no terminal progress");
        }

        fn payload(observed: &Observed) -> Vec<u8> {
            let written = observed.written.lock().unwrap();
            written[find_headers_end(&written).expect("request head")..].to_vec()
        }

        fn trailers(
            name: &'static str,
            value: &'static str,
        ) -> Result<Frame<Segments>, &'static str> {
            let mut trailers = HeaderMap::new();
            trailers.insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
            Ok(Frame::Trailers(trailers))
        }

        #[test]
        fn streaming_upload_supports_pinned_producer_segmented_data_and_partial_writes() {
            let cx = Cx::for_testing();
            let observed = Arc::new(Observed::default());
            let body = producer(
                &observed,
                Some(6),
                vec![data(&[b"ab", b"c"]), data(&[b"de", b"f"])],
            );
            let response = drive(Http1Client::request_with_body(
                &cx,
                io(&observed, Some(b"\r\n\r\nabcdef")),
                head(&[]),
                body,
            ))
            .unwrap();
            assert_eq!(response.head.status, 204);
            assert!(
                !response.body_withheld,
                "ready producer EOF must precede the final response"
            );
            assert_eq!(payload(&observed), b"abcdef");
            assert!(
                String::from_utf8(observed.written.lock().unwrap().clone())
                    .unwrap()
                    .contains("Content-Length: 6\r\n")
            );
            assert_eq!(observed.producer_polls.load(Ordering::SeqCst), 3);
            assert_eq!(observed.producer_drops.load(Ordering::SeqCst), 1);
            drop(response);
            assert_eq!(observed.transport_drops.load(Ordering::SeqCst), 1);
        }

        #[test]
        fn streaming_upload_unknown_length_encodes_chunks_and_trailers() {
            let cx = Cx::for_testing();
            let observed = Arc::new(Observed::default());
            let body = producer(
                &observed,
                None,
                vec![
                    data(&[b"ab", b"c"]),
                    data(&[b"d"]),
                    trailers("x-checksum", "ok"),
                ],
            );
            let response = drive(Http1Client::request_with_body(
                &cx,
                io(&observed, Some(b"0\r\nx-checksum: ok\r\n\r\n")),
                head(&[]),
                body,
            ))
            .unwrap();
            assert!(!response.body_withheld);
            assert_eq!(
                payload(&observed),
                b"3\r\nabc\r\n1\r\nd\r\n0\r\nx-checksum: ok\r\n\r\n"
            );
            assert_eq!(observed.producer_polls.load(Ordering::SeqCst), 4);
        }

        #[test]
        fn streaming_upload_checks_actual_length_and_drops_failed_exchange() {
            for (length, frames, sent) in [
                (4, vec![data(&[b"abc"])], &b"abc"[..]),
                (2, vec![data(&[b"abc"])], &b""[..]),
                (3, vec![data(&[b"abc"]), data(&[b"extra"])], &b"abc"[..]),
            ] {
                let cx = Cx::for_testing();
                let observed = Arc::new(Observed::default());
                let result = drive(Http1Client::request_with_body(
                    &cx,
                    io(&observed, None),
                    head(&[]),
                    producer(&observed, Some(length), frames),
                ));
                assert!(matches!(result, Err(HttpError::BadContentLength)));
                assert_eq!(
                    payload(&observed),
                    sent,
                    "an overrun must never reach the wire"
                );
                assert_eq!(observed.producer_drops.load(Ordering::SeqCst), 1);
                assert_eq!(observed.transport_drops.load(Ordering::SeqCst), 1);
            }
        }

        #[test]
        fn streaming_upload_explicit_length_overrides_untrusted_hint() {
            let cx = Cx::for_testing();
            let observed = Arc::new(Observed::default());
            let response = drive(Http1Client::request_with_body(
                &cx,
                io(&observed, Some(b"\r\n\r\nabc")),
                head(&[("Content-Length", "3")]),
                producer(&observed, Some(999), vec![data(&[b"abc"])]),
            ))
            .unwrap();
            assert!(!response.body_withheld);
            assert_eq!(payload(&observed), b"abc");
            assert_eq!(observed.producer_polls.load(Ordering::SeqCst), 2);
        }

        #[test]
        fn streaming_upload_producer_error_is_terminal() {
            let cx = Cx::for_testing();
            let observed = Arc::new(Observed::default());
            let result = drive(Http1Client::request_with_body(
                &cx,
                io(&observed, None),
                head(&[]),
                producer(&observed, None, vec![data(&[b"abc"]), Err("source failed")]),
            ));
            assert!(
                matches!(result, Err(HttpError::Io(ref error)) if error.kind() == std::io::ErrorKind::InvalidData && error.to_string().contains("source failed"))
            );
            assert_eq!(payload(&observed), b"3\r\nabc\r\n");
            assert_eq!(observed.producer_drops.load(Ordering::SeqCst), 1);
            assert_eq!(observed.transport_drops.load(Ordering::SeqCst), 1);
        }

        #[test]
        fn streaming_upload_rejects_ambiguous_or_invalid_heads_before_writing() {
            for headers in [
                vec![
                    ("Content-Length", "1"),
                    ("Transfer-Encoding", "chunked"),
                ],
                vec![("Content-Length", "1"), ("content-length", "1")],
                vec![("Transfer-Encoding", "gzip, chunked")],
                vec![("Content-Length", "+1")],
                vec![("X-Injected", "good\r\nInjected: bad")],
            ] {
                let cx = Cx::for_testing();
                let observed = Arc::new(Observed::default());
                let result = drive(Http1Client::request_with_body(
                    &cx,
                    io(&observed, None),
                    head(&headers),
                    producer(&observed, None, vec![]),
                ));
                assert!(result.is_err(), "invalid request headers: {headers:?}");
                assert!(observed.written.lock().unwrap().is_empty());
                assert_eq!(observed.producer_polls.load(Ordering::SeqCst), 0);
                assert_eq!(observed.transport_drops.load(Ordering::SeqCst), 1);
            }
        }

        #[test]
        fn streaming_upload_rejects_unknown_length_http10_before_writing() {
            let cx = Cx::for_testing();
            let observed = Arc::new(Observed::default());
            let mut request = head(&[]);
            request.version = Version::Http10;
            let result = drive(Http1Client::request_with_body(
                &cx,
                io(&observed, None),
                request,
                producer(&observed, None, vec![]),
            ));
            assert!(matches!(result, Err(HttpError::BadContentLength)));
            assert!(observed.written.lock().unwrap().is_empty());
        }

        #[test]
        fn streaming_upload_forbidden_or_nonterminal_trailers_never_commit_final_chunk() {
            for frames in [
                vec![trailers("content-length", "4")],
                vec![trailers("x-checksum", "ok"), data(&[b"late"])],
                vec![trailers("x-first", "ok"), trailers("x-second", "bad")],
            ] {
                let cx = Cx::for_testing();
                let observed = Arc::new(Observed::default());
                let result = drive(Http1Client::request_with_body(
                    &cx,
                    io(&observed, None),
                    head(&[]),
                    producer(&observed, None, frames),
                ));
                assert!(matches!(result, Err(HttpError::TrailersNotAllowed)));
                assert!(payload(&observed).is_empty());
                assert_eq!(observed.transport_drops.load(Ordering::SeqCst), 1);
            }
        }

        #[test]
        fn streaming_upload_coalesced_continue_and_final_response_do_not_poll_producer() {
            let cx = Cx::for_testing();
            let observed = Arc::new(Observed::default());
            let mut transport = io(&observed, Some(b"\r\n\r\n"));
            transport.response = std::io::Cursor::new(
                b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n".to_vec(),
            );
            let mut body = producer(&observed, Some(3), vec![data(&[b"abc"])]);
            body.parked = true;
            let response = drive(Http1Client::request_with_body(
                &cx,
                transport,
                head(&[("Expect", "100-continue")]),
                body,
            ))
            .unwrap();
            assert_eq!(response.head.status, 413);
            assert!(response.body_withheld);
            assert!(payload(&observed).is_empty());
            assert_eq!(observed.producer_polls.load(Ordering::SeqCst), 0);
            assert_eq!(observed.producer_drops.load(Ordering::SeqCst), 1);
        }

        #[test]
        fn streaming_upload_first_write_failure_still_returns_ready_final_response() {
            let cx = Cx::for_testing();
            let observed = Arc::new(Observed::default());
            let mut transport = io(&observed, Some(b""));
            transport.write_failure = Some(std::io::ErrorKind::BrokenPipe);
            transport.response = std::io::Cursor::new(
                b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n".to_vec(),
            );
            let response = drive(Http1Client::request_with_body(
                &cx,
                transport,
                head(&[]),
                producer(&observed, Some(3), vec![data(&[b"abc"])]),
            ))
            .unwrap();
            assert_eq!(response.head.status, 413);
            assert!(response.body_withheld);
            assert_eq!(observed.write_polls.load(Ordering::SeqCst), 1);
            assert!(observed.written.lock().unwrap().is_empty());
            assert_eq!(observed.producer_polls.load(Ordering::SeqCst), 0);
            assert_eq!(observed.producer_drops.load(Ordering::SeqCst), 1);
            drop(response);
            assert_eq!(observed.transport_drops.load(Ordering::SeqCst), 1);
        }

        #[test]
        fn streaming_upload_io_authority_requires_both_owner_and_polling_caller() {
            use crate::cx::cap::{CapSet, CapSetRuntimeMask};

            for (restrict_owner, restrict_caller) in [(true, false), (false, true)] {
                let mut owner = Cx::for_testing();
                let mut caller = Cx::for_testing();
                if restrict_owner {
                    owner.runtime_mask = <CapSet<true, true, true, false, true>>::MASK;
                }
                if restrict_caller {
                    caller.runtime_mask = <CapSet<true, true, true, false, true>>::MASK;
                }
                let _current = Cx::set_current(Some(caller));
                let observed = Arc::new(Observed::default());
                let result = drive(Http1Client::request_with_body(
                    &owner,
                    io(&observed, None),
                    head(&[]),
                    producer(&observed, Some(3), vec![data(&[b"abc"])]),
                ));
                assert!(
                    matches!(result, Err(HttpError::Io(ref error)) if error.kind() == std::io::ErrorKind::PermissionDenied),
                    "owner restriction={restrict_owner}, caller restriction={restrict_caller}"
                );
                assert_eq!(observed.write_polls.load(Ordering::SeqCst), 0);
                assert!(observed.written.lock().unwrap().is_empty());
                assert_eq!(observed.producer_polls.load(Ordering::SeqCst), 0);
                assert_eq!(observed.producer_drops.load(Ordering::SeqCst), 1);
                assert_eq!(observed.transport_drops.load(Ordering::SeqCst), 1);
            }
        }

        #[test]
        fn streaming_upload_owner_cancel_wakes_parked_body_and_drops_both_owners() {
            let cx = Cx::for_testing();
            let observed = Arc::new(Observed::default());
            let mut body = producer(&observed, None, vec![]);
            body.parked = true;
            let mut transport = io(&observed, None);
            transport.partial = false;
            let waker = Waker::from(Arc::clone(&observed));
            let mut task = Context::from_waker(&waker);
            {
                let mut future = std::pin::pin!(Http1Client::request_with_body(
                    &cx,
                    transport,
                    head(&[]),
                    body,
                ));
                assert!(future.as_mut().poll(&mut task).is_pending());
                assert_eq!(observed.producer_polls.load(Ordering::SeqCst), 1);
                let wakes = observed.wakes.load(Ordering::SeqCst);
                cx.cancel_with(crate::types::CancelKind::User, None);
                assert!(
                    observed.wakes.load(Ordering::SeqCst) > wakes,
                    "cancellation must wake the owner without producer cooperation"
                );
                assert!(matches!(
                    future.as_mut().poll(&mut task),
                    Poll::Ready(Err(HttpError::BodyCancelled))
                ));
            }
            assert_eq!(observed.producer_drops.load(Ordering::SeqCst), 1);
            assert_eq!(observed.transport_drops.load(Ordering::SeqCst), 1);
        }

        #[test]
        fn streaming_upload_future_drop_releases_parked_body_and_transport() {
            let cx = Cx::for_testing();
            let observed = Arc::new(Observed::default());
            let mut body = producer(&observed, None, vec![]);
            body.parked = true;
            let mut transport = io(&observed, None);
            transport.partial = false;
            {
                let mut future = std::pin::pin!(Http1Client::request_with_body(
                    &cx,
                    transport,
                    head(&[]),
                    body,
                ));
                let mut task = Context::from_waker(Waker::noop());
                assert!(future.as_mut().poll(&mut task).is_pending());
                assert_eq!(observed.producer_polls.load(Ordering::SeqCst), 1);
                assert_eq!(observed.producer_drops.load(Ordering::SeqCst), 0);
                assert_eq!(observed.transport_drops.load(Ordering::SeqCst), 0);
            }
            assert_eq!(observed.producer_drops.load(Ordering::SeqCst), 1);
            assert_eq!(observed.transport_drops.load(Ordering::SeqCst), 1);
        }
    }
