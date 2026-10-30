    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::io::AsyncWriteExt;
    use futures_lite::future::block_on;
    use std::cell::Cell;
    use std::future::poll_fn;
    use std::net::TcpListener;

    /// asupersync-bo2caw: the TLS connector is built on the first HTTPS use
    /// and shared by every later connection and by clones of the client,
    /// instead of loading the root store and building a rustls config per
    /// connection. The build outcome, success or the configuration-level
    /// failure text, is what every request observes.
    #[test]
    #[cfg(feature = "tls")]
    fn tls_connector_is_built_once_per_client_and_shared_by_clones() {
        let client = HttpClient::new();
        assert!(
            client.tls_connector.get().is_none(),
            "no connector may exist before the first HTTPS use"
        );

        let first = client.tls_connector().map(|_connector| ());
        let cached = client
            .tls_connector
            .get()
            .expect("the first use populates the cache");
        assert_eq!(first.is_ok(), cached.is_ok());

        let clone = client.clone();
        assert!(
            Arc::ptr_eq(&client.tls_connector, &clone.tls_connector),
            "clones must share the connector cache"
        );
        let second = clone.tls_connector().map(|_connector| ());
        assert_eq!(first.is_ok(), second.is_ok());

        // Without a roots feature the default client has no trust anchors and
        // the build fails closed; the cached text is what every request reports.
        if let Err(ClientError::TlsError(message)) = &first {
            assert_eq!(cached.as_ref().err(), Some(message));
        }
    }

    thread_local! {
        static HTTP_CLIENT_TEST_TIME_NANOS: Cell<u64> = const { Cell::new(0) };
    }

    fn set_http_client_test_time(nanos: u64) {
        HTTP_CLIENT_TEST_TIME_NANOS.with(|t| t.set(nanos));
    }

    fn http_client_test_time() -> Time {
        Time::from_nanos(HTTP_CLIENT_TEST_TIME_NANOS.with(std::cell::Cell::get))
    }

    fn loopback_client_io() -> ClientIo {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener address");
        let client = std::net::TcpStream::connect(addr).expect("connect client");
        let (_server, _) = listener.accept().expect("accept client");
        let stream = TcpStream::from_std(client).expect("wrap stream");
        ClientIo::Plain(stream)
    }

    // =========================================================================
    // URL parsing
    // =========================================================================

    #[cfg(not(target_arch = "wasm32"))]
    mod pooled_streaming {
        use super::*;
        use crate::bytes::Buf;
        use crate::http::body::HeaderName;
        use crate::runtime::RuntimeBuilder;
        use crate::types::{Budget, RegionId, TaskId};
        use std::io::{Read, Write as StdWrite};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::{Duration, Instant};

        fn listener() -> (TcpListener, String) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            (listener, url)
        }

        fn accept(listener: &TcpListener) -> std::net::TcpStream {
            let end = Instant::now() + Duration::from_secs(5);
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                        stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                        return stream;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < end, "client did not connect");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            }
        }

        fn request_head(stream: &mut std::net::TcpStream) -> String {
            let mut bytes = Vec::new();
            while !bytes.ends_with(b"\r\n\r\n") {
                assert!(bytes.len() < 16 * 1024);
                let mut byte = [0];
                assert_eq!(stream.read(&mut byte).unwrap(), 1, "request was truncated");
                bytes.push(byte[0]);
            }
            String::from_utf8(bytes).unwrap()
        }

        fn expect_closed(stream: &mut std::net::TcpStream) {
            let mut byte = [0];
            match stream.read(&mut byte) {
                Ok(0) => {}
                Err(error) if matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe) => {}
                result => panic!("abandoned response socket must close: {result:?}"),
            }
        }

        async fn next(body: &mut PooledClientIncomingBody) -> Option<Result<Frame<crate::bytes::BytesCursor>, ClientError>> {
            poll_fn(|task| Pin::new(&mut *body).poll_frame(task)).await
        }

        async fn drain(body: &mut PooledClientIncomingBody) -> Result<Vec<u8>, ClientError> {
            let mut bytes = Vec::new();
            while let Some(frame) = next(body).await {
                if let Frame::Data(data) = frame? {
                    bytes.extend_from_slice(data.chunk());
                }
            }
            Ok(bytes)
        }

        fn runtime(multithread: bool) -> crate::runtime::Runtime {
            if multithread {
                RuntimeBuilder::new()
                    .worker_threads(2)
                    .with_sharded_state(true)
                    .build()
                    .unwrap()
            } else {
                RuntimeBuilder::current_thread().build().unwrap()
            }
        }

        struct UploadBody {
            frames: std::collections::VecDeque<Frame<crate::bytes::BytesCursor>>,
            exact: Option<u64>,
        }

        impl Body for UploadBody {
            type Data = crate::bytes::BytesCursor;
            type Error = std::convert::Infallible;

            fn poll_frame(
                self: Pin<&mut Self>,
                _task: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
                Poll::Ready(self.get_mut().frames.pop_front().map(Ok))
            }

            fn size_hint(&self) -> SizeHint {
                self.exact.map_or_else(SizeHint::default, SizeHint::with_exact)
            }
        }

        fn upload_data(bytes: &'static [u8]) -> Frame<crate::bytes::BytesCursor> {
            Frame::Data(crate::bytes::BytesCursor::new(crate::bytes::Bytes::from_static(bytes)))
        }

        #[test]
        fn streaming_uploads_preserve_wire_framing_cookies_and_pool_reuse() {
            for multithread in [false, true] {
                let (listener, url) = listener();
                let peer = std::thread::spawn(move || {
                    let mut socket = accept(&listener);
                    let head = request_head(&mut socket);
                    assert!(head.starts_with("POST /fixed "));
                    assert!(head.to_ascii_lowercase().contains("content-length: 6\r\n"));
                    assert!(head.contains("Authorization: Bearer upload-token\r\n"));
                    assert!(head.contains("X-Default: shared\r\n"));
                    let mut body = [0_u8; 6];
                    socket.read_exact(&mut body).unwrap();
                    assert_eq!(&body, b"abcdef");
                    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: session=upload\r\n\r\nok").unwrap();

                    let head = request_head(&mut socket);
                    assert!(head.starts_with("POST /chunked "));
                    assert!(head.to_ascii_lowercase().contains("transfer-encoding: chunked\r\n"));
                    assert!(!head.to_ascii_lowercase().contains("content-length:"));
                    assert!(head.contains("Cookie: session=upload\r\n"));
                    let expected = b"3\r\nghi\r\n3\r\njkl\r\n0\r\nx-checksum: complete\r\n\r\n";
                    let mut body = vec![0_u8; expected.len()];
                    socket.read_exact(&mut body).unwrap();
                    assert_eq!(body, expected);
                    socket.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();

                    assert!(request_head(&mut socket).starts_with("GET /after "));
                    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
                    assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
                });
                let runtime = runtime(multithread);
                let cx = runtime.request_cx_with_budget(Budget::INFINITE);
                let client = HttpClient::builder()
                    .max_connections_per_host(1)
                    .max_total_connections(1)
                    .cookie_store(true)
                    .default_header("X-Default", "shared")
                    .request_timeout(Duration::from_secs(4))
                    .build();
                runtime.block_on_with_cx(cx.clone(), async {
                    let body = UploadBody {
                        frames: [upload_data(b"abc"), upload_data(b"def")].into(),
                        exact: Some(6),
                    };
                    let mut response = client.post(format!("{url}/fixed"))
                        .bearer_auth("upload-token")
                        .send_with_body(&cx, body).await.unwrap();
                    assert!(!response.body_withheld);
                    assert_eq!(client.pool_stats().idle_connections, 0);
                    assert_eq!(drain(&mut response.body).await.unwrap(), b"ok");
                    assert_eq!(client.pool_stats().idle_connections, 1);

                    let mut trailers = crate::http::body::HeaderMap::new();
                    trailers.insert(HeaderName::from_static("x-checksum"), crate::http::body::HeaderValue::from_static("complete"));
                    let body = UploadBody {
                        frames: [upload_data(b"ghi"), upload_data(b"jkl"), Frame::Trailers(trailers)].into(),
                        exact: None,
                    };
                    let response = client.request_with_body(
                        &cx, Method::Post, &format!("{url}/chunked"),
                        vec![("Trailer".into(), "x-checksum".into())], body,
                    ).await.unwrap();
                    assert_eq!(response.head.status, 204);
                    assert!(!response.body_withheld);
                    assert!(response.body.is_end_stream());
                    assert_eq!(client.pool_stats().idle_connections, 1);
                    assert_eq!(client.send_get(&cx, &format!("{url}/after")).await.unwrap().body, b"ok");
                    assert_eq!(client.pool_stats().total_connections, 0);
                    assert!(cx.inner.read().cancel_waker_registrations.is_empty());
                });
                peer.join().unwrap();
                assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
                assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
            }
        }

        struct ParkedUpload {
            polled: Option<std::sync::mpsc::Sender<()>>,
            polls: Arc<AtomicUsize>,
            drops: Arc<AtomicUsize>,
        }

        impl Body for ParkedUpload {
            type Data = crate::bytes::BytesCursor;
            type Error = std::convert::Infallible;

            fn poll_frame(
                self: Pin<&mut Self>,
                _task: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
                let this = self.get_mut();
                this.polls.fetch_add(1, Ordering::SeqCst);
                if let Some(witness) = this.polled.take() {
                    witness.send(()).unwrap();
                }
                // No self wake: only owner cancellation/deadline or peer I/O
                // can allow the operation to make progress from this state.
                Poll::Pending
            }
        }

        impl Drop for ParkedUpload {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }

        #[test]
        fn streaming_upload_owner_cancel_wakes_parked_producer_and_releases_admission() {
            for multithread in [false, true] {
                let (listener, url) = listener();
                let peer = std::thread::spawn(move || {
                    let mut abandoned = accept(&listener);
                    assert!(request_head(&mut abandoned).starts_with("POST /parked "));
                    expect_closed(&mut abandoned);
                    let mut replacement = accept(&listener);
                    assert!(request_head(&mut replacement).starts_with("GET /after "));
                    replacement.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
                });
                let runtime = runtime(multithread);
                let driver = runtime.request_cx_with_budget(Budget::INFINITE);
                let owner = Cx::for_testing();
                let (polled, witness) = std::sync::mpsc::channel();
                let polls = Arc::new(AtomicUsize::new(0));
                let drops = Arc::new(AtomicUsize::new(0));
                let cancel_owner = owner.clone();
                let canceller = std::thread::spawn(move || {
                    witness.recv_timeout(Duration::from_secs(3)).unwrap();
                    cancel_owner.cancel_with(crate::types::CancelKind::User, Some("parked upload"));
                });
                let client = HttpClient::builder()
                    .max_connections_per_host(1)
                    .max_total_connections(1)
                    .request_timeout(Duration::from_secs(4))
                    .build();
                runtime.block_on_with_cx(driver.clone(), async {
                    let body = ParkedUpload { polled: Some(polled), polls: polls.clone(), drops: drops.clone() };
                    let result = client.request_with_body(&owner, Method::Post, &format!("{url}/parked"), Vec::new(), body).await;
                    assert!(matches!(result, Err(ClientError::Cancelled)), "{result:?}");
                    assert!(polls.load(Ordering::SeqCst) > 0);
                    assert_eq!(drops.load(Ordering::SeqCst), 1);
                    assert_eq!(client.pool_stats().total_connections, 0);
                    assert!(owner.inner.read().cancel_waker_registrations.is_empty());
                    assert_eq!(client.send_get(&driver, &format!("{url}/after")).await.unwrap().body, b"ok");
                });
                canceller.join().unwrap();
                peer.join().unwrap();
                assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
                assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
            }
        }

        #[test]
        fn streaming_upload_early_redirect_is_returned_without_polling_or_replay() {
            let (listener, url) = listener();
            let peer = std::thread::spawn(move || {
                let mut socket = accept(&listener);
                let head = request_head(&mut socket);
                assert!(head.contains("Expect: 100-continue\r\n"));
                socket.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /elsewhere\r\nContent-Length: 0\r\n\r\n").unwrap();
                expect_closed(&mut socket);
                assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
            });
            let runtime = runtime(false);
            let cx = runtime.request_cx_with_budget(Budget::INFINITE);
            let polls = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let client = HttpClient::builder().request_timeout(Duration::from_secs(4)).build();
            runtime.block_on_with_cx(cx.clone(), async {
                let body = ParkedUpload { polled: None, polls: polls.clone(), drops: drops.clone() };
                let response = client.post(&url).header("Expect", "100-continue").send_with_body(&cx, body).await.unwrap();
                assert_eq!(response.head.status, 307);
                assert!(response.body_withheld);
                assert_eq!(polls.load(Ordering::SeqCst), 0);
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                assert_eq!(client.pool_stats().total_connections, 0);
            });
            peer.join().unwrap();
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        }

        #[test]
        fn streaming_upload_builder_timeout_covers_a_parked_producer() {
            let (listener, url) = listener();
            let peer = std::thread::spawn(move || {
                let mut socket = accept(&listener);
                request_head(&mut socket);
                expect_closed(&mut socket);
            });
            let runtime = runtime(false);
            let driver = runtime.request_cx_with_budget(Budget::INFINITE);
            let clock = Arc::new(crate::time::VirtualClock::starting_at(Time::from_nanos(100)));
            let timer = crate::time::TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
            let owner = Cx::new_with_drivers(
                RegionId::new_for_test(0, 1),
                TaskId::new_for_test(7, 0),
                Budget::INFINITE,
                None,
                None,
                None,
                Some(timer.clone()),
                None,
            );
            let (polled, witness) = std::sync::mpsc::channel();
            let expire = std::thread::spawn(move || {
                witness.recv_timeout(Duration::from_secs(3)).unwrap();
                clock.advance(250_000_000);
                assert!(timer.process_timers() > 0, "parked upload must register its deadline");
            });
            let polls = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let client = HttpClient::builder().request_timeout(Duration::from_secs(4)).build();
            runtime.block_on_with_cx(driver, async {
                let body = ParkedUpload { polled: Some(polled), polls: polls.clone(), drops: drops.clone() };
                let result = client.post(&url).timeout(Duration::from_millis(250)).send_with_body(&owner, body).await;
                assert!(matches!(result, Err(ClientError::DeadlineExceeded)), "{result:?}");
                assert!(polls.load(Ordering::SeqCst) > 0, "deadline must interrupt an admitted, parked producer");
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                assert_eq!(client.pool_stats().total_connections, 0);
                assert!(owner.inner.read().cancel_waker_registrations.is_empty());
            });
            expire.join().unwrap();
            peer.join().unwrap();
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        }

        #[test]
        fn streaming_upload_rejects_invalid_proxy_and_conflicting_body_before_admission() {
            let cx = Cx::for_testing();
            let client = HttpClient::new();
            let result = block_on(client.post("http://127.0.0.1:9").body(b"buffered".to_vec()).send_with_body(&cx, crate::http::body::Empty::new()));
            assert!(matches!(result, Err(ClientError::Io(error)) if error.kind() == io::ErrorKind::InvalidInput));
            assert_eq!(client.pool_stats().total_connections, 0);
            let client = HttpClient::builder().proxy("ftp://127.0.0.1:9").build();
            let result = block_on(client.request_with_body(&cx, Method::Post, "http://127.0.0.1:9", Vec::new(), crate::http::body::Empty::new()));
            assert!(matches!(result, Err(ClientError::InvalidUrl(_))));
            assert_eq!(client.pool_stats().total_connections, 0);
        }

        fn read_chunked_upload(socket: &mut std::net::TcpStream) -> (Vec<u8>, usize) {
            let mut decoded = Vec::new();
            let mut largest_chunk = 0;
            loop {
                let mut line = Vec::new();
                while !line.ends_with(b"\r\n") {
                    assert!(line.len() < 32);
                    let mut byte = [0];
                    socket.read_exact(&mut byte).unwrap();
                    line.push(byte[0]);
                }
                let length = usize::from_str_radix(
                    std::str::from_utf8(&line[..line.len() - 2]).unwrap(),
                    16,
                )
                .unwrap();
                largest_chunk = largest_chunk.max(length);
                assert!(length <= 1024, "multipart source must remain chunked");
                let start = decoded.len();
                decoded.resize(start + length, 0);
                socket.read_exact(&mut decoded[start..]).unwrap();
                let mut crlf = [0; 2];
                socket.read_exact(&mut crlf).unwrap();
                assert_eq!(&crlf, b"\r\n");
                if length == 0 {
                    return (decoded, largest_chunk);
                }
            }
        }

        fn accept_socks5_upload(socket: &mut std::net::TcpStream) {
            let mut greeting = [0; 2];
            socket.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting[0], 5);
            let mut methods = vec![0; usize::from(greeting[1])];
            socket.read_exact(&mut methods).unwrap();
            assert!(methods.contains(&2));
            socket.write_all(&[5, 2]).unwrap();
            let mut auth = [0; 2];
            socket.read_exact(&mut auth).unwrap();
            assert_eq!(auth, [1, 5]);
            let mut username = [0; 5];
            socket.read_exact(&mut username).unwrap();
            assert_eq!(&username, b"agent");
            let mut length = [0];
            socket.read_exact(&mut length).unwrap();
            assert_eq!(length, [2]);
            let mut password = [0; 2];
            socket.read_exact(&mut password).unwrap();
            assert_eq!(&password, b"pw");
            socket.write_all(&[1, 0]).unwrap();
            let mut connect = [0; 5];
            socket.read_exact(&mut connect).unwrap();
            assert_eq!(&connect[..4], &[5, 1, 0, 3]);
            let mut target = vec![0; usize::from(connect[4])];
            socket.read_exact(&mut target).unwrap();
            assert_eq!(target, b"origin.invalid");
            let mut port = [0; 2];
            socket.read_exact(&mut port).unwrap();
            assert_eq!(u16::from_be_bytes(port), 8080);
            socket.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        }

        #[test]
        fn streaming_proxy_uploads_preserve_auth_framing_and_pool_admission() {
            for multithread in [false, true] {
                for socks in [false, true] {
                    let (listener, proxy_url) = listener();
                    let proxy_address = listener.local_addr().unwrap();
                    let peer = std::thread::spawn(move || {
                        for (index, token) in ["first", "second"].into_iter().enumerate() {
                            let mut socket = accept(&listener);
                            if socks {
                                accept_socks5_upload(&mut socket);
                            }
                            let head = request_head(&mut socket);
                            if socks {
                                assert!(head.starts_with("POST /upload HTTP/1.1\r\n"));
                                assert!(!head.to_ascii_lowercase().contains("proxy-authorization:"));
                            } else {
                                assert!(head.starts_with("POST http://origin.invalid:8080/upload HTTP/1.1\r\n"));
                                assert!(head.contains(&format!("Proxy-Authorization: Bearer {token}\r\n")));
                            }
                            assert!(head.contains("Host: origin.invalid:8080\r\n"));
                            assert!(head.contains("Authorization: Bearer origin-only\r\n"));
                            let lower = head.to_ascii_lowercase();
                            if index == 0 {
                                assert!(lower.contains("content-length: 6\r\n"));
                                let mut body = [0; 6];
                                socket.read_exact(&mut body).unwrap();
                                assert_eq!(&body, b"abcdef");
                            } else {
                                assert!(lower.contains("transfer-encoding: chunked\r\n"));
                                assert_eq!(read_chunked_upload(&mut socket).0, b"abcdef");
                            }
                            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong").unwrap();
                            // Even a healthy keep-alive tunnel cannot retain
                            // the first request's proxy authentication.
                            expect_closed(&mut socket);
                        }
                        assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
                    });
                    let runtime = runtime(multithread);
                    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
                    let proxy_url = if socks {
                        format!("socks5://agent:pw@{proxy_address}")
                    } else {
                        proxy_url
                    };
                    let client = HttpClient::builder()
                        .proxy(proxy_url)
                        .default_header("Proxy-Authorization", "Bearer default")
                        .max_connections_per_host(1)
                        .max_total_connections(1)
                        .request_timeout(Duration::from_secs(4))
                        .build();
                    runtime.block_on_with_cx(cx.clone(), async {
                        for (index, token) in ["first", "second"].into_iter().enumerate() {
                            let body = UploadBody {
                                frames: [upload_data(b"abc"), upload_data(b"def")].into(),
                                exact: (index == 0).then_some(6),
                            };
                            let mut response = client.post("http://origin.invalid:8080/upload")
                                .bearer_auth("origin-only")
                                .header("Proxy-Authorization", format!("Bearer {token}"))
                                .send_with_body(&cx, body).await.unwrap();
                            assert_eq!(client.pool_stats().total_connections, 1);
                            assert_eq!(client.pool_stats().idle_connections, 0);
                            let polls = Arc::new(AtomicUsize::new(0));
                            let drops = Arc::new(AtomicUsize::new(0));
                            let blocked = ParkedUpload {
                                polled: None, polls: polls.clone(), drops: drops.clone(),
                            };
                            let result = client.post("http://origin.invalid:8080/blocked")
                                .send_with_body(&cx, blocked).await;
                            assert!(matches!(result, Err(ClientError::PoolExhausted { .. })));
                            assert_eq!(polls.load(Ordering::SeqCst), 0);
                            assert_eq!(drops.load(Ordering::SeqCst), 1);
                            assert_eq!(drain(&mut response.body).await.unwrap(), b"pong");
                            assert_eq!(client.pool_stats().total_connections, 0);
                            assert_eq!(client.pool_stats().idle_connections, 0);
                        }
                        assert!(cx.inner.read().cancel_waker_registrations.is_empty());
                    });
                    peer.join().unwrap();
                    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
                    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
                }
            }
        }

        #[test]
        fn streaming_proxy_redirect_keeps_proxy_auth_and_strips_origin_auth() {
            for multithread in [false, true] {
                let (listener, proxy_url) = listener();
                let peer = std::thread::spawn(move || {
                    let mut first = accept(&listener);
                    let head = request_head(&mut first);
                    assert!(head.starts_with("GET http://first.invalid/start HTTP/1.1\r\n"));
                    assert!(head.contains("Authorization: Bearer origin-only\r\n"));
                    assert!(head.contains("Proxy-Authorization: Bearer proxy-only\r\n"));
                    first.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://second.invalid/done\r\nContent-Length: 8\r\nSet-Cookie: private=first\r\n\r\n").unwrap();
                    expect_closed(&mut first);
                    let mut second = accept(&listener);
                    let head = request_head(&mut second);
                    assert!(head.starts_with("GET http://second.invalid/done HTTP/1.1\r\n"));
                    assert!(head.contains("Proxy-Authorization: Bearer proxy-only\r\n"));
                    assert!(!head.contains("\r\nAuthorization:"));
                    assert!(!head.contains("\r\nCookie:"));
                    second.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
                    expect_closed(&mut second);
                });
                let runtime = runtime(multithread);
                let cx = runtime.request_cx_with_budget(Budget::INFINITE);
                let client = HttpClient::builder().proxy(proxy_url)
                    .cookie_store(true)
                    .default_header("Authorization", "Bearer origin-only")
                    .default_header("Cookie", "secret=origin")
                    .max_total_connections(1)
                    .request_timeout(Duration::from_secs(4)).build();
                runtime.block_on_with_cx(cx.clone(), async {
                    let mut response = client.request_streaming_pooled(
                        &cx, Method::Get, "http://first.invalid/start",
                        vec![("Proxy-Authorization".into(), "Bearer proxy-only".into())],
                        Vec::new(),
                    ).await.unwrap();
                    assert_eq!(response.head.status, 200);
                    assert_eq!(drain(&mut response.body).await.unwrap(), b"ok");
                    assert_eq!(client.pool_stats().total_connections, 0);
                    assert!(cx.inner.read().cancel_waker_registrations.is_empty());
                });
                peer.join().unwrap();
                assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
                assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
            }
        }

        #[test]
        fn streaming_proxy_connect_rejection_and_cancel_retire_unpolled_uploads() {
            for multithread in [false, true] {
                for reject in [false, true] {
                    let (listener, proxy_url) = listener();
                    let (negotiated, observed) = std::sync::mpsc::channel();
                    let peer = std::thread::spawn(move || {
                        let mut socket = accept(&listener);
                        let head = request_head(&mut socket);
                        assert!(head.starts_with("CONNECT origin.invalid:443 HTTP/1.1\r\n"));
                        assert!(head.contains("Proxy-Authorization: Bearer tunnel\r\n"));
                        if reject {
                            socket.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n").unwrap();
                        } else {
                            negotiated.send(()).unwrap();
                        }
                        expect_closed(&mut socket);
                        assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
                    });
                    let runtime = runtime(multithread);
                    let driver = runtime.request_cx_with_budget(Budget::INFINITE);
                    let owner = Cx::for_testing();
                    let cancel_owner = owner.clone();
                    let canceller = (!reject).then(|| std::thread::spawn(move || {
                        observed.recv_timeout(Duration::from_secs(3)).unwrap();
                        cancel_owner.cancel_with(crate::types::CancelKind::User, Some("CONNECT parked"));
                    }));
                    let client = HttpClient::builder().proxy(proxy_url)
                        .max_total_connections(1)
                        .request_timeout(Duration::from_secs(4)).build();
                    let polls = Arc::new(AtomicUsize::new(0));
                    let drops = Arc::new(AtomicUsize::new(0));
                    runtime.block_on_with_cx(driver, async {
                        let body = ParkedUpload { polled: None, polls: polls.clone(), drops: drops.clone() };
                        let result = client.post("https://origin.invalid/upload")
                            .header("Proxy-Authorization", "Bearer tunnel")
                            .send_with_body(&owner, body).await;
                        if reject {
                            assert!(matches!(result, Err(ClientError::ConnectTunnelRefused { status: 407, .. })), "{result:?}");
                        } else {
                            assert!(matches!(result, Err(ClientError::Cancelled)), "{result:?}");
                        }
                        assert_eq!(polls.load(Ordering::SeqCst), 0);
                        assert_eq!(drops.load(Ordering::SeqCst), 1);
                        assert_eq!(client.pool_stats().total_connections, 0);
                        assert!(owner.inner.read().cancel_waker_registrations.is_empty());
                    });
                    if let Some(canceller) = canceller { canceller.join().unwrap(); }
                    peer.join().unwrap();
                    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
                    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
                }
            }
        }

        #[test]
        fn streaming_proxy_setup_deadline_releases_parked_negotiation() {
            let (listener, proxy_url) = listener();
            let (negotiated, observed) = std::sync::mpsc::channel();
            let peer = std::thread::spawn(move || {
                let mut socket = accept(&listener);
                assert!(request_head(&mut socket).starts_with("CONNECT origin.invalid:443 "));
                negotiated.send(()).unwrap();
                expect_closed(&mut socket);
            });
            let runtime = runtime(false);
            let driver = runtime.request_cx_with_budget(Budget::INFINITE);
            let clock = Arc::new(crate::time::VirtualClock::starting_at(Time::from_nanos(100)));
            let timer = crate::time::TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
            let owner = Cx::new_with_drivers(
                RegionId::new_for_test(0, 1), TaskId::new_for_test(7, 0), Budget::INFINITE,
                None, None, None, Some(timer.clone()), None,
            );
            let expire = std::thread::spawn(move || {
                observed.recv_timeout(Duration::from_secs(3)).unwrap();
                clock.advance(250_000_000);
                assert!(timer.process_timers() > 0);
            });
            let client = HttpClient::builder().proxy(proxy_url)
                .max_total_connections(1).request_timeout(Duration::from_secs(4)).build();
            let polls = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            runtime.block_on_with_cx(driver, async {
                let body = ParkedUpload { polled: None, polls: polls.clone(), drops: drops.clone() };
                let result = client.post("https://origin.invalid/upload")
                    .timeout(Duration::from_millis(250)).send_with_body(&owner, body).await;
                assert!(matches!(result, Err(ClientError::DeadlineExceeded)), "{result:?}");
                assert_eq!(polls.load(Ordering::SeqCst), 0);
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                assert_eq!(client.pool_stats().total_connections, 0);
                assert!(owner.inner.read().cancel_waker_registrations.is_empty());
            });
            expire.join().unwrap();
            peer.join().unwrap();
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        }

        #[test]
        fn streaming_io_authority_is_checked_before_direct_or_proxy_admission() {
            let (listener, url) = listener();
            let runtime = runtime(false);
            let owner = runtime.request_cx_with_budget(Budget::INFINITE);
            runtime.block_on_with_cx(owner.clone(), async {
                let restricted = {
                    let _restriction = Cx::push_restriction(crate::cx::cap::CapMask::none());
                    Cx::current().unwrap()
                };
                for proxy in [false, true] {
                    let client = if proxy {
                        HttpClient::builder().proxy(&url).build()
                    } else {
                        HttpClient::new()
                    };
                    let result = client.request_streaming_pooled(
                        &restricted, Method::Get, &url, Vec::new(), Vec::new(),
                    ).await;
                    assert!(matches!(result, Err(ClientError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied));
                    let _restriction = Cx::push_restriction(crate::cx::cap::CapMask::none());
                    let result = client.post(&url).send_with_body(&owner, crate::http::body::Empty::new()).await;
                    assert!(matches!(result, Err(ClientError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied));
                    assert_eq!(client.pool_stats().total_connections, 0);
                    assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
                }
                assert!(owner.inner.read().cancel_waker_registrations.is_empty());
            });
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        }

        #[test]
        fn multipart_upload_streams_async_files_with_exact_or_chunked_framing_and_reuse() {
            use crate::http::body::ReaderBody;
            use crate::http::h1::{MultipartBody, MultipartBodyPart};

            for multithread in [false, true] {
                for known_length in [false, true] {
                    let boundary = "native:reader-file";
                    let payload = [vec![b'z'; 32 * 1024], b"tail".to_vec()].concat();
                    let expected = MultipartForm::with_boundary(boundary)
                        .unwrap()
                        .text("description", "streamed file")
                        .file("asset", "payload.bin", "application/octet-stream", payload.clone())
                        .to_body();
                    let mut file = tempfile::tempfile().unwrap();
                    file.write_all(&payload).unwrap();
                    std::io::Seek::rewind(&mut file).unwrap();
                    let (listener, url) = listener();
                    let peer = std::thread::spawn(move || {
                        let mut socket = accept(&listener);
                        let head = request_head(&mut socket);
                        assert!(head.starts_with("POST /multipart "));
                        let lower = head.to_ascii_lowercase();
                        assert_eq!(lower.matches("content-type:").count(), 1);
                        assert!(head.contains(
                            "Content-Type: multipart/form-data; boundary=\"native:reader-file\"\r\n"
                        ));
                        if known_length {
                            assert!(lower.contains(&format!("content-length: {}\r\n", expected.len())));
                            assert!(!lower.contains("transfer-encoding:"));
                            let mut received = vec![0; expected.len()];
                            socket.read_exact(&mut received).unwrap();
                            assert_eq!(received, expected);
                        } else {
                            assert!(lower.contains("transfer-encoding: chunked\r\n"));
                            assert!(!lower.contains("content-length:"));
                            let (received, largest) = read_chunked_upload(&mut socket);
                            assert_eq!(received, expected);
                            assert_eq!(largest, 1024);
                        }
                        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
                        assert!(request_head(&mut socket).starts_with("GET /after "));
                        socket.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").unwrap();
                        assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
                    });
                    let runtime = runtime(multithread);
                    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
                    let client = HttpClient::builder()
                        .default_header("Content-Type", "application/json")
                        .max_connections_per_host(1)
                        .max_total_connections(1)
                        .request_timeout(Duration::from_secs(4))
                        .build();
                    runtime.block_on_with_cx(cx.clone(), async {
                        let source = ReaderBody::with_capacity(crate::fs::File::from_std(file), 1024);
                        let part = MultipartBodyPart::stream("asset", source)
                            .filename("payload.bin")
                            .content_type("application/octet-stream");
                        let part = if known_length {
                            part.with_length(payload.len() as u64)
                        } else {
                            part
                        };
                        let form = MultipartBody::with_boundary(
                            boundary,
                            vec![MultipartBodyPart::text("description", "streamed file"), part],
                        )
                        .unwrap();
                        assert_eq!(form.size_hint().exact().is_some(), known_length);
                        let mut response = if known_length {
                            client.post(format!("{url}/multipart"))
                                .content_type("text/plain")
                                .send_multipart_with_body(&cx, form)
                                .await
                                .unwrap()
                        } else {
                            client.request_multipart_with_body(
                                &cx,
                                Method::Post,
                                &format!("{url}/multipart"),
                                vec![("content-type".to_owned(), "text/plain".to_owned())],
                                form,
                            )
                            .await
                            .unwrap()
                        };
                        assert!(!response.body_withheld);
                        assert_eq!(drain(&mut response.body).await.unwrap(), b"ok");
                        assert_eq!(client.pool_stats().idle_connections, 1);
                        assert_eq!(client.send_get(&cx, &format!("{url}/after")).await.unwrap().status, 204);
                        assert_eq!(client.pool_stats().total_connections, 0);
                        assert!(cx.inner.read().cancel_waker_registrations.is_empty());
                    });
                    peer.join().unwrap();
                    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
                    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
                }
            }
        }

        struct ParkedMultipartReader {
            witness: Option<std::sync::mpsc::Sender<()>>,
            polls: Arc<AtomicUsize>,
            drops: Arc<AtomicUsize>,
        }

        impl AsyncRead for ParkedMultipartReader {
            fn poll_read(
                self: Pin<&mut Self>,
                _task: &mut Context<'_>,
                _buffer: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                this.polls.fetch_add(1, Ordering::SeqCst);
                if let Some(witness) = this.witness.take() {
                    witness.send(()).unwrap();
                }
                Poll::Pending
            }
        }

        impl Drop for ParkedMultipartReader {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }

        #[test]
        fn multipart_upload_early_response_and_cancellation_drop_current_and_queued_sources() {
            use crate::http::body::ReaderBody;
            use crate::http::h1::{MultipartBody, MultipartBodyPart};

            for multithread in [false, true] {
                for early_response in [false, true] {
                    let (listener, url) = listener();
                    let peer = std::thread::spawn(move || {
                        let mut socket = accept(&listener);
                        let head = request_head(&mut socket);
                        if early_response {
                            assert!(head.contains("Expect: 100-continue\r\n"));
                            socket.write_all(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n").unwrap();
                            expect_closed(&mut socket);
                        } else {
                            // The first multipart header can precede the
                            // parked reader, but no file data is produced.
                            let mut received = 0;
                            let mut bytes = [0; 1024];
                            loop {
                                match socket.read(&mut bytes) {
                                    Ok(0) => break,
                                    Ok(count) => {
                                        received += count;
                                        assert!(received < 4096);
                                    }
                                    Err(error) if matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe) => break,
                                    Err(error) => panic!("cancelled multipart socket: {error}"),
                                }
                            }
                        }
                        assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
                    });
                    let runtime = runtime(multithread);
                    let driver = runtime.request_cx_with_budget(Budget::INFINITE);
                    let owner = Cx::for_testing();
                    let (witness, parked) = std::sync::mpsc::channel();
                    let canceller = if early_response {
                        None
                    } else {
                        let owner = owner.clone();
                        Some(std::thread::spawn(move || {
                            parked.recv_timeout(Duration::from_secs(3)).unwrap();
                            owner.cancel_with(crate::types::CancelKind::User, Some("multipart source parked"));
                        }))
                    };
                    let polls = Arc::new(AtomicUsize::new(0));
                    let drops = Arc::new(AtomicUsize::new(0));
                    let client = HttpClient::builder()
                        .max_connections_per_host(1)
                        .max_total_connections(1)
                        .request_timeout(Duration::from_secs(4))
                        .build();
                    runtime.block_on_with_cx(driver, async {
                        let first = ParkedMultipartReader {
                            witness: Some(witness), polls: polls.clone(), drops: drops.clone(),
                        };
                        let second = ParkedMultipartReader {
                            witness: None, polls: polls.clone(), drops: drops.clone(),
                        };
                        let form = MultipartBody::with_boundary("parked:multipart", vec![
                            MultipartBodyPart::stream("first", ReaderBody::new(first)),
                            MultipartBodyPart::stream("second", ReaderBody::new(second)),
                        ]).unwrap();
                        let builder = client.post(&url);
                        let builder = if early_response {
                            builder.header("Expect", "100-continue")
                        } else {
                            builder
                        };
                        let result = builder.send_multipart_with_body(&owner, form).await;
                        if early_response {
                            let response = result.unwrap();
                            assert_eq!(response.head.status, 413);
                            assert!(response.body_withheld);
                            assert_eq!(polls.load(Ordering::SeqCst), 0);
                        } else {
                            assert!(matches!(result, Err(ClientError::Cancelled)), "{result:?}");
                            assert!(polls.load(Ordering::SeqCst) > 0);
                        }
                        assert_eq!(drops.load(Ordering::SeqCst), 2);
                        assert_eq!(client.pool_stats().total_connections, 0);
                        assert!(owner.inner.read().cancel_waker_registrations.is_empty());
                    });
                    if let Some(canceller) = canceller {
                        canceller.join().unwrap();
                    }
                    peer.join().unwrap();
                    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
                    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
                }
            }
        }

        #[test]
        fn pooled_streaming_holds_admission_until_final_frame_and_reuses_the_socket() {
            for multithread in [false, true] {
                let (listener, url) = listener();
                let peer = std::thread::spawn(move || {
                    let mut socket = accept(&listener);
                    assert!(request_head(&mut socket).starts_with("GET /first "));
                    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").unwrap();
                    assert!(request_head(&mut socket).starts_with("GET /second "));
                    socket
                        .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\nx-end: complete\r\n\r\n")
                        .unwrap();
                    assert!(request_head(&mut socket).starts_with("GET /buffered "));
                    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
                    // One accepted TCP connection served every request.
                    assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
                });
                let runtime = runtime(multithread);
                let cx = runtime.request_cx_with_budget(Budget::INFINITE);
                let client = HttpClient::builder()
                    .max_connections_per_host(1)
                    .max_total_connections(1)
                    .pool_wait_timeout(Duration::from_secs(3))
                    .request_timeout(Duration::from_secs(4))
                    .build();
                runtime.block_on_with_cx(cx.clone(), async {
                    let mut first = client.request_streaming_pooled(&cx, Method::Get, &format!("{url}/first"), Vec::new(), Vec::new()).await.unwrap();
                    assert_eq!(client.pool_stats().total_connections, 1);
                    assert_eq!(client.pool_stats().idle_connections, 0);
                    let second_url = format!("{url}/second");
                    let mut second = Box::pin(client.request_streaming_pooled(&cx, Method::Get, &second_url, Vec::new(), Vec::new()));
                    poll_fn(|task| {
                        assert!(second.as_mut().poll(task).is_pending());
                        assert_eq!(client.pool_released.waiter_count(), 1, "second request actually parked at admission");
                        Poll::Ready(())
                    }).await;
                    let mut first_bytes = Vec::new();
                    while !first.body.is_end_stream() {
                        let Frame::Data(data) = next(&mut first.body).await.unwrap().unwrap() else {
                            panic!("fixed response must yield DATA");
                        };
                        first_bytes.extend_from_slice(data.chunk());
                        if !first.body.is_end_stream() {
                            assert_eq!(client.pool_stats().idle_connections, 0);
                        }
                    }
                    assert_eq!(first_bytes, b"hello");
                    assert_eq!(client.pool_stats().idle_connections, 1, "last DATA releases before an EOF poll");
                    assert!(next(&mut first.body).await.is_none());
                    drop(first);

                    let mut second = second.await.unwrap();
                    let mut bytes = Vec::new();
                    let mut trailers = false;
                    while let Some(frame) = next(&mut second.body).await {
                        match frame.unwrap() {
                            Frame::Data(data) => bytes.extend_from_slice(data.chunk()),
                            Frame::Trailers(fields) => {
                                assert_eq!(fields.get(&HeaderName::from_static("x-end")).unwrap().to_str().unwrap(), "complete");
                                assert_eq!(client.pool_stats().idle_connections, 1, "trailer delivery releases without a final poll");
                                trailers = true;
                            }
                        }
                    }
                    assert_eq!(bytes, b"abcde");
                    assert!(trailers);
                    drop(second);
                    assert_eq!(client.send_get(&cx, &format!("{url}/buffered")).await.unwrap().body, b"ok");
                    assert_eq!(client.pool_stats().total_connections, 1);
                    assert_eq!(client.pool_released.waiter_count(), 0);
                    assert!(cx.inner.read().cancel_waker_registrations.is_empty());
                });
                drop(client);
                peer.join().unwrap();
                assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
                assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
            }
        }

        #[test]
        fn pooled_streaming_drop_and_parked_owner_cancel_release_waiting_requests() {
            for multithread in [false, true] {
                for cancel in [false, true] {
                    let (listener, url) = listener();
                    let peer = std::thread::spawn(move || {
                        let mut abandoned = accept(&listener);
                        request_head(&mut abandoned);
                        abandoned.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n").unwrap();
                        expect_closed(&mut abandoned);
                        let mut replacement = accept(&listener);
                        assert!(request_head(&mut replacement).starts_with("GET /next "));
                        replacement.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
                    });
                    let runtime = runtime(multithread);
                    let driver = runtime.request_cx_with_budget(Budget::INFINITE);
                    // The explicit body owner differs from the polling task's
                    // ambient context; only its cancellation may stop the body.
                    let owner = Cx::for_testing();
                    let client = HttpClient::builder()
                        .max_connections_per_host(1)
                        .max_total_connections(1)
                        .pool_wait_timeout(Duration::from_secs(3))
                        .request_timeout(Duration::from_secs(4))
                        .build();
                    runtime.block_on_with_cx(driver.clone(), async {
                        let mut first = client.request_streaming_pooled(&owner, Method::Get, &url, Vec::new(), Vec::new()).await.unwrap();
                        let next_url = format!("{url}/next");
                        let mut waiting = Box::pin(client.request_streaming_pooled(&driver, Method::Get, &next_url, Vec::new(), Vec::new()));
                        poll_fn(|task| {
                            assert!(waiting.as_mut().poll(task).is_pending());
                            assert_eq!(client.pool_released.waiter_count(), 1);
                            Poll::Ready(())
                        }).await;
                        if cancel {
                            let (parked, witness) = std::sync::mpsc::channel();
                            let cancel_owner = owner.clone();
                            let canceller = std::thread::spawn(move || {
                                witness.recv_timeout(Duration::from_secs(3)).unwrap();
                                cancel_owner.cancel_with(crate::types::CancelKind::User, Some("parked pooled body"));
                            });
                            let started = Instant::now();
                            let mut parked = Some(parked);
                            let result = poll_fn(|task| {
                                let result = Pin::new(&mut first.body).poll_frame(task);
                                if result.is_pending() && let Some(witness) = parked.take() {
                                    assert!(!owner.inner.read().cancel_waker_registrations.is_empty());
                                    witness.send(()).unwrap();
                                }
                                result
                            }).await;
                            canceller.join().unwrap();
                            assert!(matches!(result, Some(Err(ClientError::Cancelled))), "{result:?}");
                            assert!(started.elapsed() < Duration::from_secs(2), "cancellation must wake before the request timer or peer timeout");
                            assert!(first.body.is_end_stream());
                            assert!(next(&mut first.body).await.is_none());
                        }
                        drop(first);
                        assert!(owner.inner.read().cancel_waker_registrations.is_empty());
                        let mut replacement = waiting.await.unwrap();
                        assert_eq!(drain(&mut replacement.body).await.unwrap(), b"ok");
                        assert_eq!(client.pool_stats().total_connections, 0);
                        assert_eq!(client.pool_released.waiter_count(), 0);
                    });
                    peer.join().unwrap();
                    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
                    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
                }
            }
        }

        #[test]
        fn pooled_streaming_empty_responses_release_without_polling() {
            let (listener, url) = listener();
            let peer = std::thread::spawn(move || {
                let mut socket = accept(&listener);
                for response in [
                    &b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n"[..],
                    &b"HTTP/1.1 204 No Content\r\n\r\n"[..],
                    &b"HTTP/1.1 304 Not Modified\r\n\r\n"[..],
                    &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..],
                ] {
                    request_head(&mut socket);
                    socket.write_all(response).unwrap();
                }
            });
            let runtime = runtime(false);
            let cx = runtime.request_cx_with_budget(Budget::INFINITE);
            let client = HttpClient::builder().max_connections_per_host(1).request_timeout(Duration::from_secs(4)).build();
            runtime.block_on_with_cx(cx.clone(), async {
                for method in [Method::Head, Method::Get, Method::Get, Method::Get] {
                    let response = client.request_streaming_pooled(&cx, method, &url, Vec::new(), Vec::new()).await.unwrap();
                    assert!(response.body.is_end_stream());
                    assert_eq!(client.pool_stats().idle_connections, 1);
                    drop(response);
                    assert_eq!(client.pool_stats().idle_connections, 1, "drop must not retire a reused lease twice");
                }
            });
            peer.join().unwrap();
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        }

        #[test]
        fn pooled_streaming_redirects_release_admission_and_keep_credentials_at_origin() {
            let (origin_listener, origin_url) = listener();
            let (other_listener, other_url) = listener();
            let back = format!("{origin_url}/back");
            let other = std::thread::spawn(move || {
                let mut socket = accept(&other_listener);
                let request = request_head(&mut socket).to_ascii_lowercase();
                assert!(request.starts_with("get /other "));
                assert!(!request.contains("authorization:"));
                assert!(!request.contains("cookie:"));
                write!(socket, "HTTP/1.1 302 Found\r\nLocation: {back}\r\nContent-Length: 0\r\n\r\n").unwrap();
            });
            let origin = std::thread::spawn(move || {
                let mut socket = accept(&origin_listener);
                let first = request_head(&mut socket).to_ascii_lowercase();
                assert!(first.starts_with("get /start "));
                assert!(first.contains("authorization: bearer retained-secret"));
                assert!(first.contains("cookie: session=origin"));
                write!(socket, "HTTP/1.1 302 Found\r\nLocation: {other_url}/other\r\nContent-Length: 0\r\n\r\n").unwrap();
                // The return hop reuses the original connection and restores
                // only its default credentials, despite an intervening origin.
                let last = request_head(&mut socket).to_ascii_lowercase();
                assert!(last.starts_with("get /back "));
                assert!(last.contains("authorization: bearer retained-secret"));
                assert!(last.contains("cookie: session=origin"));
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone").unwrap();
            });
            let runtime = runtime(false);
            let cx = runtime.request_cx_with_budget(Budget::INFINITE);
            let client = HttpClient::builder()
                .max_connections_per_host(1)
                .max_total_connections(2)
                .request_timeout(Duration::from_secs(4))
                .default_header("Authorization", "Bearer retained-secret")
                .default_header("Cookie", "session=origin")
                .build();
            runtime.block_on_with_cx(cx.clone(), async {
                let mut response = client
                    .request_streaming_pooled(
                        &cx,
                        Method::Get,
                        &format!("{origin_url}/start"),
                        Vec::new(),
                        Vec::new(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.head.status, 200);
                assert_eq!(drain(&mut response.body).await.unwrap(), b"done");
                assert_eq!(client.pool_stats().connections_created, 2);
                assert!(cx.inner.read().cancel_waker_registrations.is_empty());
            });
            drop(client);
            origin.join().unwrap();
            other.join().unwrap();
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        }

        #[test]
        fn pooled_streaming_errors_and_close_delimiting_never_return_a_connection() {
            for (method, wire, expected_error, expected_bytes) in [
                (Method::Get, &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc"[..], true, &b""[..]),
                (Method::Get, &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabX\n"[..], true, &b""[..]),
                (Method::Get, &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"[..], false, &b"ok"[..]),
                (Method::Get, &b"HTTP/1.1 200 OK\r\n\r\nok"[..], false, &b"ok"[..]),
                (Method::Get, &b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: other\r\n\r\nUPGRADED"[..], false, &b""[..]),
                (Method::Connect, &b"HTTP/1.1 200 Connection Established\r\nContent-Length: 2\r\n\r\nok"[..], false, &b"ok"[..]),
            ] {
                let (listener, url) = listener();
                let peer = std::thread::spawn(move || {
                    let mut socket = accept(&listener);
                    request_head(&mut socket);
                    socket.write_all(wire).unwrap();
                });
                let runtime = runtime(false);
                let cx = runtime.request_cx_with_budget(Budget::INFINITE);
                let client = HttpClient::builder().request_timeout(Duration::from_secs(4)).build();
                runtime.block_on_with_cx(cx.clone(), async {
                    let mut response = client.request_streaming_pooled(&cx, method, &url, Vec::new(), Vec::new()).await.unwrap();
                    let result = drain(&mut response.body).await;
                    if expected_error {
                        assert!(
                            matches!(
                                result,
                                Err(ClientError::HttpError(
                                    crate::http::h1::codec::HttpError::BadContentLength
                                        | crate::http::h1::codec::HttpError::BadChunkedEncoding
                                ))
                            ),
                            "{result:?}"
                        );
                    } else {
                        assert_eq!(result.unwrap(), expected_bytes);
                    }
                    assert!(response.body.is_end_stream());
                    assert!(next(&mut response.body).await.is_none());
                    drop(response);
                    assert_eq!(client.pool_stats().total_connections, 0);
                });
                peer.join().unwrap();
                assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
            }
        }

        #[derive(Default)]
        struct WakeCount(AtomicUsize);

        impl std::task::Wake for WakeCount {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        #[test]
        fn pooled_streaming_driverless_owner_ignores_a_foreign_ambient_clock() {
            let now = crate::time::wall_now();
            let owner = Cx::for_request_with_budget(Budget::INFINITE.with_deadline(now + Duration::from_secs(30)));
            let foreign_clock = Arc::new(crate::time::VirtualClock::starting_at(Time::from_secs(1_000_000)));
            let foreign_timer = crate::time::TimerDriverHandle::with_virtual_clock(foreign_clock);
            let foreign = Cx::new_with_drivers(
                RegionId::new_for_test(0, 1),
                TaskId::new_for_test(3, 0),
                Budget::INFINITE,
                None,
                None,
                None,
                Some(foreign_timer.clone()),
                None,
            );
            let _ambient = Cx::set_current(Some(foreign));
            let deadline = PooledStreamDeadline::capture(&owner, Some(Duration::from_secs(60)));
            let mut retained = PooledStreamOwner::new(owner.clone(), &deadline);
            let wakes = Arc::new(WakeCount::default());
            let waker = std::task::Waker::from(Arc::clone(&wakes));
            let mut task = Context::from_waker(&waker);
            assert!(retained.poll_stop(&mut task).is_none(), "foreign virtual time cannot expire the owner's real deadline");
            assert_eq!(foreign_timer.process_timers(), 0);
            let before = wakes.0.load(Ordering::SeqCst);
            owner.cancel_with(crate::types::CancelKind::User, Some("explicit owner"));
            assert!(wakes.0.load(Ordering::SeqCst) > before);
            assert!(matches!(retained.poll_stop(&mut task), Some(ClientError::Cancelled)));
            retained.retire();
            assert!(owner.inner.read().cancel_waker_registrations.is_empty());
        }

        #[test]
        fn pooled_streaming_body_keeps_the_original_deadline_after_data() {
            let (listener, url) = listener();
            let peer = std::thread::spawn(move || {
                let mut socket = accept(&listener);
                request_head(&mut socket);
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\na").unwrap();
                expect_closed(&mut socket);
            });
            let runtime = runtime(false);
            let driver = runtime.request_cx_with_budget(Budget::INFINITE);
            let clock = Arc::new(crate::time::VirtualClock::starting_at(Time::from_nanos(100)));
            let timer = crate::time::TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
            let owner = Cx::new_with_drivers(
                RegionId::new_for_test(0, 1),
                TaskId::new_for_test(4, 0),
                Budget::INFINITE.with_deadline(Time::from_nanos(110)),
                None,
                None,
                None,
                Some(timer.clone()),
                None,
            );
            let client = HttpClient::builder().build();
            runtime.block_on_with_cx(driver.clone(), async {
                let mut response = client.request_streaming_pooled(&owner, Method::Get, &url, Vec::new(), Vec::new()).await.unwrap();
                let Frame::Data(data) = next(&mut response.body).await.unwrap().unwrap() else { panic!("first byte"); };
                assert_eq!(data.chunk(), b"a");
                clock.advance(9);
                let wakes = Arc::new(WakeCount::default());
                let waker = std::task::Waker::from(Arc::clone(&wakes));
                let mut task = Context::from_waker(&waker);
                assert!(Pin::new(&mut response.body).poll_frame(&mut task).is_pending());
                assert_eq!(timer.process_timers(), 0);
                let before = wakes.0.load(Ordering::SeqCst);
                clock.advance(1);
                assert!(timer.process_timers() > 0);
                assert!(wakes.0.load(Ordering::SeqCst) > before);
                assert!(matches!(Pin::new(&mut response.body).poll_frame(&mut task), Poll::Ready(Some(Err(ClientError::DeadlineExceeded)))));
                assert_eq!(client.pool_stats().total_connections, 0);
                assert!(owner.inner.read().cancel_waker_registrations.is_empty());
            });
            peer.join().unwrap();
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        }

        #[test]
        fn pooled_streaming_admission_timeout_uses_the_owner_clock() {
            let (listener, url) = listener();
            let peer = std::thread::spawn(move || {
                let mut socket = accept(&listener);
                request_head(&mut socket);
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n").unwrap();
                expect_closed(&mut socket);
            });
            let runtime = runtime(false);
            let driver = runtime.request_cx_with_budget(Budget::INFINITE);
            let clock = Arc::new(crate::time::VirtualClock::starting_at(Time::from_nanos(100)));
            let timer = crate::time::TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
            let owner = Cx::new_with_drivers(
                RegionId::new_for_test(0, 1),
                TaskId::new_for_test(5, 0),
                Budget::INFINITE,
                None,
                None,
                None,
                Some(timer.clone()),
                None,
            );
            let foreign_clock = Arc::new(crate::time::VirtualClock::starting_at(Time::from_secs(1_000_000)));
            let foreign_timer = crate::time::TimerDriverHandle::with_virtual_clock(foreign_clock);
            let foreign = Cx::new_with_drivers(
                RegionId::new_for_test(0, 1),
                TaskId::new_for_test(6, 0),
                Budget::INFINITE,
                None,
                None,
                None,
                Some(foreign_timer.clone()),
                None,
            );
            let client = HttpClient::builder()
                .max_connections_per_host(1)
                .max_total_connections(1)
                .pool_wait_timeout(Duration::from_nanos(10))
                .build();
            runtime.block_on_with_cx(driver.clone(), async {
                let first = client.request_streaming_pooled(&driver, Method::Get, &url, Vec::new(), Vec::new()).await.unwrap();
                {
                    let _ambient = Cx::set_current(Some(foreign));
                    let mut waiting = Box::pin(client.request_streaming_pooled(&owner, Method::Get, &url, Vec::new(), Vec::new()));
                    let wakes = Arc::new(WakeCount::default());
                    let waker = std::task::Waker::from(Arc::clone(&wakes));
                    let mut task = Context::from_waker(&waker);
                    assert!(waiting.as_mut().poll(&mut task).is_pending());
                    assert_eq!(client.pool_released.waiter_count(), 1);
                    assert_eq!(foreign_timer.process_timers(), 0, "no timer may bind the foreign clock");
                    clock.advance(9);
                    assert_eq!(timer.process_timers(), 0);
                    assert!(waiting.as_mut().poll(&mut task).is_pending());
                    let before = wakes.0.load(Ordering::SeqCst);
                    clock.advance(1);
                    assert!(timer.process_timers() > 0);
                    assert!(wakes.0.load(Ordering::SeqCst) > before);
                    assert!(matches!(waiting.as_mut().poll(&mut task), Poll::Ready(Err(ClientError::PoolExhausted { .. }))));
                    drop(waiting);
                }
                assert!(owner.inner.read().cancel_waker_registrations.is_empty());
                assert_eq!(client.pool_released.waiter_count(), 0);
                assert_eq!(client.pool_stats().total_connections, 1, "timeout cannot retire another body owner's slot");
                drop(first);
                assert_eq!(client.pool_stats().total_connections, 0);
            });
            peer.join().unwrap();
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        }

        #[test]
        fn streaming_driverless_deadline_does_not_adopt_a_foreign_virtual_clock() {
            let owner = Cx::for_testing();
            assert!(owner.timer_driver().is_none());
            let deadline = PooledStreamDeadline::capture(&owner, Some(Duration::from_secs(3600)));
            let foreign_clock = Arc::new(crate::time::VirtualClock::starting_at(
                deadline.at.unwrap() + Duration::from_secs(3600),
            ));
            let foreign_timer = crate::time::TimerDriverHandle::with_virtual_clock(foreign_clock);
            let foreign = Cx::new_with_drivers(
                RegionId::new_for_test(0, 1),
                TaskId::new_for_test(81, 0),
                Budget::INFINITE,
                None,
                None,
                None,
                Some(foreign_timer.clone()),
                None,
            );
            let _ambient = Cx::set_current(Some(foreign));
            let mut operation = PooledStreamOwner::new(owner.clone(), &deadline);
            let mut task = Context::from_waker(std::task::Waker::noop());
            assert!(
                operation.poll_stop(&mut task).is_none(),
                "a foreign virtual instant cannot expire the owner's wall-clock deadline"
            );
            assert_eq!(foreign_timer.process_timers(), 0);
            drop(operation);
            assert!(owner.inner.read().cancel_waker_registrations.is_empty());
        }

        #[test]
        fn streaming_driverless_pool_wait_does_not_adopt_a_foreign_virtual_clock() {
            let (listener, url) = listener();
            let peer = std::thread::spawn(move || {
                let mut socket = accept(&listener);
                request_head(&mut socket);
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")
                    .unwrap();
                expect_closed(&mut socket);
            });
            let runtime = runtime(false);
            let driver = runtime.request_cx_with_budget(Budget::INFINITE);
            let owner = Cx::for_testing();
            let clock = Arc::new(crate::time::VirtualClock::starting_at(
                crate::time::wall_now() + Duration::from_secs(86400),
            ));
            let timer = crate::time::TimerDriverHandle::with_virtual_clock(clock);
            let foreign = Cx::new_with_drivers(
                RegionId::new_for_test(0, 1),
                TaskId::new_for_test(82, 0),
                Budget::INFINITE,
                None,
                None,
                None,
                Some(timer.clone()),
                None,
            );
            let client = HttpClient::builder()
                .max_connections_per_host(1)
                .max_total_connections(1)
                .pool_wait_timeout(Duration::from_secs(3600))
                .request_timeout(Duration::from_secs(7200))
                .build();
            runtime.block_on_with_cx(driver.clone(), async {
                let first = client
                    .request_streaming_pooled(&driver, Method::Get, &url, Vec::new(), Vec::new())
                    .await
                    .unwrap();
                {
                    let _ambient = Cx::set_current(Some(foreign));
                    let mut waiting = Box::pin(client.request_streaming_pooled(
                        &owner,
                        Method::Get,
                        &url,
                        Vec::new(),
                        Vec::new(),
                    ));
                    let mut task = Context::from_waker(std::task::Waker::noop());
                    assert!(
                        waiting.as_mut().poll(&mut task).is_pending(),
                        "pool wait must use wall time while the driverless owner remains live"
                    );
                    assert_eq!(client.pool_released.waiter_count(), 1);
                    assert_eq!(timer.process_timers(), 0);
                    drop(waiting);
                }
                assert_eq!(client.pool_released.waiter_count(), 0);
                assert!(owner.inner.read().cancel_waker_registrations.is_empty());
                assert_eq!(client.pool_stats().total_connections, 1);
                drop(first);
                assert_eq!(client.pool_stats().total_connections, 0);
            });
            peer.join().unwrap();
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        }

        #[test]
        fn pooled_streaming_refuses_invalid_proxy_configuration_before_admission() {
            let client = HttpClient::builder().proxy("ftp://127.0.0.1:9").build();
            let result = block_on(client.request_streaming_pooled(&Cx::for_testing(), Method::Get, "http://127.0.0.1:9", Vec::new(), Vec::new()));
            assert!(matches!(result, Err(ClientError::InvalidUrl(_))));
            assert_eq!(client.pool_stats().total_connections, 0);
        }
    }

    #[test]
    fn parse_http_url() {
        let url = ParsedUrl::parse("http://example.com/path").unwrap();
        assert_eq!(url.scheme, Scheme::Http);
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 80);
        assert_eq!(url.path, "/path");
    }

    #[test]
    fn parse_https_url() {
        let url = ParsedUrl::parse("https://example.com/api/v1").unwrap();
        assert_eq!(url.scheme, Scheme::Https);
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 443);
        assert_eq!(url.path, "/api/v1");
    }

    #[test]
    fn parse_url_with_port() {
        let url = ParsedUrl::parse("http://localhost:8080/test").unwrap();
        assert_eq!(url.host, "localhost");
        assert_eq!(url.port, 8080);
        assert_eq!(url.path, "/test");
    }

    #[test]
    fn parse_url_no_path() {
        let url = ParsedUrl::parse("http://example.com").unwrap();
        assert_eq!(url.path, "/");
    }

    #[test]
    fn parse_url_never_sends_the_fragment_and_roots_a_bare_query() {
        let url = ParsedUrl::parse("http://example.com/a/b?x=1#section").unwrap();
        assert_eq!(url.path, "/a/b?x=1");
        let url = ParsedUrl::parse("http://example.com#top").unwrap();
        assert_eq!(url.path, "/");
        let url = ParsedUrl::parse("http://example.com?x=1").unwrap();
        assert_eq!(url.path, "/?x=1");
    }

    #[test]
    fn parse_url_rejects_control_bytes_in_the_path() {
        for url in [
            "http://example.com/a\u{0}b",
            "http://example.com/a\u{7f}b",
            "http://example.com/a\u{1b}b",
            "http://example.com/a\r\nX-Injected: 1",
        ] {
            assert!(
                matches!(ParsedUrl::parse(url), Err(ClientError::InvalidUrl(_))),
                "{url:?}"
            );
        }
    }

    #[test]
    fn url_schemes_are_case_insensitive() {
        let url = ParsedUrl::parse("HTTPS://Example.com/path").unwrap();
        assert_eq!(url.scheme, Scheme::Https);
        assert_eq!(url.port, 443);
        let current = ParsedUrl::parse("http://example.com/old").unwrap();
        assert_eq!(
            resolve_redirect(&current, "HTTPS://other.example/new"),
            "HTTPS://other.example/new",
            "an absolute Location with an uppercase scheme is not a relative path"
        );
    }

    #[test]
    fn parse_url_with_query() {
        let url = ParsedUrl::parse("http://example.com/search?q=test&page=1").unwrap();
        assert_eq!(url.path, "/search?q=test&page=1");
    }

    #[test]
    fn parsed_numeric_socket_addr_handles_ipv4_host() {
        let url = ParsedUrl::parse("http://127.0.0.1:8765/healthz").expect("parse url");
        let socket_addr = parsed_numeric_socket_addr(&url).expect("numeric addr");
        assert_eq!(socket_addr, "127.0.0.1:8765".parse().unwrap());
    }

    #[test]
    fn parsed_numeric_socket_addr_handles_ipv6_host() {
        let url = ParsedUrl::parse("http://[::1]:8765/healthz").expect("parse url");
        let socket_addr = parsed_numeric_socket_addr(&url).expect("numeric addr");
        assert_eq!(socket_addr, "[::1]:8765".parse().unwrap());
    }

    #[test]
    fn parse_url_handles_unbracketed_ipv6_host() {
        let url = ParsedUrl::parse("http://::1/healthz").expect("parse url");
        assert_eq!(url.host, "::1");
        assert_eq!(url.port, 80);
    }

    #[test]
    fn parse_url_invalid_scheme() {
        let result = ParsedUrl::parse("ftp://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn parse_url_empty_host() {
        let result = ParsedUrl::parse("http:///path");
        assert!(result.is_err());
    }

    #[test]
    fn parse_url_invalid_port() {
        for url in [
            "http://example.com:abc/path",
            "http://example.com:+80/path",
            "http://example.com:/path",
            "http://[::1]:+80/path",
        ] {
            assert!(ParsedUrl::parse(url).is_err(), "invalid port in {url:?}");
        }
    }

    #[test]
    fn parse_url_rejects_control_or_whitespace_in_authority() {
        let result = ParsedUrl::parse("http://example.com\r\nx-injected: y/path");
        assert!(matches!(result, Err(ClientError::InvalidUrl(_))));

        let result = ParsedUrl::parse("http://example.com bad/path");
        assert!(matches!(result, Err(ClientError::InvalidUrl(_))));
    }

    #[test]
    fn parse_http_proxy_endpoint_with_basic_auth() {
        let proxy = parse_proxy_endpoint("http://alice:secret@proxy.local:8080")
            .expect("proxy should parse");
        assert_eq!(proxy.scheme, ProxyScheme::Http);
        assert_eq!(proxy.host, "proxy.local");
        assert_eq!(proxy.port, 8080);
        assert_eq!(
            proxy.http_proxy_authorization(),
            Some("Basic YWxpY2U6c2VjcmV0")
        );
    }

    #[test]
    fn parse_socks5_proxy_endpoint_with_credentials() {
        let proxy =
            parse_proxy_endpoint("socks5://agent:pw@127.0.0.1").expect("proxy should parse");
        assert_eq!(proxy.scheme, ProxyScheme::Socks5);
        assert_eq!(proxy.host, "127.0.0.1");
        assert_eq!(proxy.port, 1080);
        assert_eq!(proxy.socks5_credentials(), Some(("agent", "pw")));
    }

    #[test]
    fn parse_proxy_endpoint_rejects_control_or_whitespace_in_authority() {
        for proxy_url in [
            "http:// proxy.local:8080",
            "http://proxy.local:8080 /path",
            "http://proxy.\tlocal:8080",
            "socks5://agent:pw@127.0.0.1\n:1080",
        ] {
            let error = parse_proxy_endpoint(proxy_url)
                .expect_err("proxy authority whitespace must fail closed");
            assert!(
                matches!(error, ClientError::InvalidUrl(ref message)
                    if message.contains("authority cannot contain control characters or whitespace")),
                "unexpected error for {proxy_url:?}: {error}"
            );
        }
    }

    #[test]
    fn parse_proxy_endpoint_rejects_non_digit_ports() {
        for proxy_url in [
            "http://proxy.local:+8080",
            "http://proxy.local:",
            "http://[::1]:+8080",
        ] {
            assert!(
                parse_proxy_endpoint(proxy_url).is_err(),
                "invalid proxy port in {proxy_url:?}",
            );
        }
    }

    #[test]
    fn absolute_request_target_uses_full_uri() {
        let parsed = ParsedUrl::parse("http://example.com:8080/path?q=1").unwrap();
        assert_eq!(
            absolute_request_target(&parsed),
            "http://example.com:8080/path?q=1"
        );
    }

    // =========================================================================
    // Pool key
    // =========================================================================

    #[test]
    fn pool_key_from_http_url() {
        let url = ParsedUrl::parse("http://example.com/path").unwrap();
        let key = url.pool_key();
        assert_eq!(key.host, "example.com");
        assert_eq!(key.port, 80);
        assert!(!key.is_https);
    }

    #[test]
    fn pool_key_from_https_url() {
        let url = ParsedUrl::parse("https://example.com/path").unwrap();
        let key = url.pool_key();
        assert_eq!(key.host, "example.com");
        assert_eq!(key.port, 443);
        assert!(key.is_https);
    }

    // =========================================================================
    // Authority
    // =========================================================================

    #[test]
    fn authority_default_port_omitted() {
        let url = ParsedUrl::parse("http://example.com/path").unwrap();
        assert_eq!(url.authority(), "example.com");

        let url = ParsedUrl::parse("https://example.com/path").unwrap();
        assert_eq!(url.authority(), "example.com");
    }

    #[test]
    fn authority_custom_port_included() {
        let url = ParsedUrl::parse("http://example.com:8080/path").unwrap();
        assert_eq!(url.authority(), "example.com:8080");
    }

    #[test]
    fn connect_authority_always_includes_port() {
        let https = ParsedUrl::parse("https://example.com/path").unwrap();
        assert_eq!(https.connect_authority(), "example.com:443");

        let http = ParsedUrl::parse("http://example.com/path").unwrap();
        assert_eq!(http.connect_authority(), "example.com:80");

        let custom = ParsedUrl::parse("https://example.com:8443/path").unwrap();
        assert_eq!(custom.connect_authority(), "example.com:8443");

        let ipv6 = ParsedUrl::parse("https://[2001:db8::1]/path").unwrap();
        assert_eq!(ipv6.connect_authority(), "[2001:db8::1]:443");
    }

    // =========================================================================
    // Redirect detection
    // =========================================================================

    #[test]
    fn is_redirect_detects_all_codes() {
        assert!(is_redirect(301));
        assert!(is_redirect(302));
        assert!(is_redirect(303));
        assert!(is_redirect(307));
        assert!(is_redirect(308));
        assert!(!is_redirect(200));
        assert!(!is_redirect(404));
        assert!(!is_redirect(500));
        assert!(!is_redirect(304)); // Not Modified is NOT a redirect
    }

    // =========================================================================
    // Redirect method transformation
    // =========================================================================

    #[test]
    fn redirect_method_303_always_get() {
        assert_eq!(redirect_method(303, &Method::Post), Method::Get);
        assert_eq!(redirect_method(303, &Method::Put), Method::Get);
        assert_eq!(redirect_method(303, &Method::Get), Method::Get);
    }

    #[test]
    fn redirect_method_307_preserves() {
        assert_eq!(redirect_method(307, &Method::Post), Method::Post);
        assert_eq!(redirect_method(307, &Method::Get), Method::Get);
        assert_eq!(redirect_method(307, &Method::Put), Method::Put);
    }

    #[test]
    fn redirect_method_308_preserves() {
        assert_eq!(redirect_method(308, &Method::Post), Method::Post);
        assert_eq!(redirect_method(308, &Method::Delete), Method::Delete);
    }

    #[test]
    fn redirect_method_301_post_becomes_get() {
        assert_eq!(redirect_method(301, &Method::Post), Method::Get);
        assert_eq!(redirect_method(301, &Method::Get), Method::Get);
    }

    #[test]
    fn redirect_method_302_post_becomes_get() {
        assert_eq!(redirect_method(302, &Method::Post), Method::Get);
        assert_eq!(redirect_method(302, &Method::Get), Method::Get);
    }

    // =========================================================================
    // Redirect URL resolution
    // =========================================================================

    #[test]
    fn resolve_absolute_redirect() {
        let current = ParsedUrl::parse("http://example.com/old").unwrap();
        let result = resolve_redirect(&current, "https://other.com/new");
        assert_eq!(result, "https://other.com/new");
    }

    #[test]
    fn resolve_protocol_relative_redirect() {
        let current = ParsedUrl::parse("https://example.com/old").unwrap();
        let result = resolve_redirect(&current, "//cdn.example.com/asset");
        assert_eq!(result, "https://cdn.example.com/asset");
    }

    #[test]
    fn resolve_absolute_path_redirect() {
        let current = ParsedUrl::parse("http://example.com:8080/old/page").unwrap();
        let result = resolve_redirect(&current, "/new/page");
        assert_eq!(result, "http://example.com:8080/new/page");
    }

    #[test]
    fn resolve_relative_path_redirect() {
        let current = ParsedUrl::parse("http://example.com/dir/old").unwrap();
        let result = resolve_redirect(&current, "new");
        assert_eq!(result, "http://example.com:80/dir/new");
    }

    #[test]
    fn resolve_relative_path_redirect_ignores_query_slashes() {
        // Regression: rfind('/') must only search the path, not the query.
        let current = ParsedUrl::parse("http://example.com/dir/old?return=/home").unwrap();
        let result = resolve_redirect(&current, "new");
        assert_eq!(result, "http://example.com:80/dir/new");
    }

    // RFC 3986 section 5.4's reference resolution examples, base
    // http://a/b/c/d;p?q (fragments dropped: they are never sent). The
    // resolver appended every relative Location to the base directory: "?y"
    // became /b/c/?y, "../g" was sent literally, and "#s" lost the path.
    #[test]
    fn resolve_redirect_follows_rfc_3986_reference_resolution() {
        let base = ParsedUrl::parse("http://a/b/c/d;p?q").unwrap();
        for (reference, expected) in [
            // 5.4.1 normal examples
            ("g", "/b/c/g"),
            ("./g", "/b/c/g"),
            ("g/", "/b/c/g/"),
            ("/g", "/g"),
            ("?y", "/b/c/d;p?y"),
            ("g?y", "/b/c/g?y"),
            ("#s", "/b/c/d;p?q"),
            ("g#s", "/b/c/g"),
            ("g?y#s", "/b/c/g?y"),
            (";x", "/b/c/;x"),
            ("g;x", "/b/c/g;x"),
            ("g;x?y#s", "/b/c/g;x?y"),
            ("", "/b/c/d;p?q"),
            (".", "/b/c/"),
            ("./", "/b/c/"),
            ("..", "/b/"),
            ("../", "/b/"),
            ("../g", "/b/g"),
            ("../..", "/"),
            ("../../", "/"),
            ("../../g", "/g"),
            // 5.4.2 abnormal examples
            ("../../../g", "/g"),
            ("../../../../g", "/g"),
            ("/./g", "/g"),
            ("/../g", "/g"),
            ("g.", "/b/c/g."),
            (".g", "/b/c/.g"),
            ("g..", "/b/c/g.."),
            ("..g", "/b/c/..g"),
            ("./../g", "/b/g"),
            ("./g/.", "/b/c/g/"),
            ("g/./h", "/b/c/g/h"),
            ("g/../h", "/b/c/h"),
            ("g;x=1/./y", "/b/c/g;x=1/y"),
            ("g;x=1/../y", "/b/c/y"),
            ("g?y/./x", "/b/c/g?y/./x"),
            ("g?y/../x", "/b/c/g?y/../x"),
        ] {
            assert_eq!(
                resolve_redirect(&base, reference),
                format!("http://a:80{expected}"),
                "reference {reference:?}"
            );
        }
    }

    // =========================================================================
    // Header lookup
    // =========================================================================

    #[test]
    fn get_header_case_insensitive() {
        let headers = vec![
            ("Content-Type".into(), "text/html".into()),
            ("location".into(), "/new".into()),
        ];
        assert_eq!(get_header(&headers, "Location"), Some("/new".into()));
        assert_eq!(get_header(&headers, "LOCATION"), Some("/new".into()));
        assert_eq!(
            get_header(&headers, "content-type"),
            Some("text/html".into())
        );
        assert_eq!(get_header(&headers, "X-Missing"), None);
    }

    // =========================================================================
    // Client error display
    // =========================================================================

    #[test]
    fn client_error_display() {
        let err = ClientError::InvalidUrl("bad".into());
        assert!(format!("{err}").contains("bad"));

        let err = ClientError::TooManyRedirects { count: 5, max: 10 };
        let msg = format!("{err}");
        assert!(msg.contains('5'));
        assert!(msg.contains("10"));

        let err = ClientError::Cancelled;
        assert!(format!("{err}").contains("cancelled"));

        let err = ClientError::PoolExhausted {
            host: "example.com".into(),
            port: 80,
        };
        let msg = format!("{err}");
        assert!(msg.contains("example.com"));
        assert!(msg.contains("80"));
    }

    #[test]
    fn client_error_source() {
        use std::error::Error;

        let err = ClientError::InvalidUrl("x".into());
        assert!(err.source().is_none());

        let io_err = io::Error::other("test");
        let err = ClientError::Io(io_err);
        assert!(err.source().is_some());

        let err = ClientError::Cancelled;
        assert!(err.source().is_none());
    }

    #[test]
    fn client_error_is_cancelled() {
        assert!(ClientError::Cancelled.is_cancelled());
        assert!(!ClientError::InvalidUrl("x".into()).is_cancelled());
    }

    // =========================================================================
    // Client config defaults
    // =========================================================================

    #[test]
    fn default_config() {
        let config = HttpClientConfig::default();
        assert!(matches!(
            config.redirect_policy,
            RedirectPolicy::Limited(10)
        ));
        assert_eq!(config.retry_policy, RetryPolicy::SafeMethodsOnStaleReuse);
        assert_eq!(config.user_agent, Some("asupersync/0.1".into()));
        assert!(!config.cookie_store);
        assert!(config.proxy_url.is_none());
    }

    #[test]
    fn config_with_time_getter_exposes_custom_clock() {
        set_http_client_test_time(77);
        let config = HttpClientConfig::default().with_time_getter(http_client_test_time);
        assert_eq!((config.time_getter())().as_nanos(), 77);
    }

    #[test]
    fn builder_default_matches_client_defaults() {
        let client = HttpClient::builder().build();
        assert_eq!(client.config.pool_config.max_connections_per_host, 6);
        assert_eq!(client.config.pool_config.max_total_connections, 100);
        assert_eq!(
            client.config.pool_config.idle_timeout,
            std::time::Duration::from_secs(90)
        );
        assert_eq!(
            client.config.pool_config.cleanup_interval,
            std::time::Duration::from_secs(30)
        );
        assert!(matches!(
            client.config.redirect_policy,
            RedirectPolicy::Limited(10)
        ));
        assert_eq!(
            client.config.retry_policy,
            RetryPolicy::SafeMethodsOnStaleReuse
        );
        assert_eq!(client.config.user_agent.as_deref(), Some("asupersync/0.1"));
        assert!(!client.config.cookie_store);
        assert!(client.config.proxy_url.is_none());
    }

    #[test]
    fn builder_overrides_pool_and_redirect_and_user_agent() {
        let client = HttpClient::builder()
            .max_connections_per_host(12)
            .max_total_connections(240)
            .idle_timeout(std::time::Duration::from_secs(15))
            .cleanup_interval(std::time::Duration::from_secs(5))
            .no_redirects()
            .no_retries()
            .no_user_agent()
            .cookie_store(true)
            .no_cookie_store()
            .proxy("http://proxy.internal:3128")
            .no_proxy()
            .build();

        assert_eq!(client.config.pool_config.max_connections_per_host, 12);
        assert_eq!(client.config.pool_config.max_total_connections, 240);
        assert_eq!(
            client.config.pool_config.idle_timeout,
            std::time::Duration::from_secs(15)
        );
        assert_eq!(
            client.config.pool_config.cleanup_interval,
            std::time::Duration::from_secs(5)
        );
        assert!(matches!(
            client.config.redirect_policy,
            RedirectPolicy::None
        ));
        assert_eq!(client.config.retry_policy, RetryPolicy::None);
        assert!(client.config.user_agent.is_none());
        assert!(!client.config.cookie_store);
        assert!(client.config.proxy_url.is_none());
    }

    #[test]
    fn builder_pool_config_and_max_redirects() {
        let pool_config = PoolConfig::builder()
            .max_connections_per_host(3)
            .max_total_connections(32)
            .idle_timeout(std::time::Duration::from_secs(7))
            .cleanup_interval(std::time::Duration::from_secs(3))
            .build();

        let client = HttpClient::builder()
            .pool_config(pool_config)
            .max_redirects(2)
            .retry_policy(RetryPolicy::SafeMethodsOnStaleReuse)
            .user_agent("asupersync-test/2.0")
            .default_header("Accept", "application/json")
            .default_headers([("X-Trace-Id", "client-default")])
            .cookie_store(true)
            .proxy("socks5://proxy.internal:1080")
            .build();

        assert_eq!(client.config.pool_config.max_connections_per_host, 3);
        assert_eq!(client.config.pool_config.max_total_connections, 32);
        assert_eq!(
            client.config.pool_config.idle_timeout,
            std::time::Duration::from_secs(7)
        );
        assert_eq!(
            client.config.pool_config.cleanup_interval,
            std::time::Duration::from_secs(3)
        );
        assert!(matches!(
            client.config.redirect_policy,
            RedirectPolicy::Limited(2)
        ));
        assert_eq!(
            client.config.retry_policy,
            RetryPolicy::SafeMethodsOnStaleReuse
        );
        assert_eq!(
            client.config.user_agent.as_deref(),
            Some("asupersync-test/2.0")
        );
        assert_eq!(
            client.config.default_headers,
            vec![
                ("Accept".to_owned(), "application/json".to_owned()),
                ("X-Trace-Id".to_owned(), "client-default".to_owned())
            ]
        );
        assert!(client.config.cookie_store);
        assert_eq!(
            client.config.proxy_url.as_deref(),
            Some("socks5://proxy.internal:1080")
        );
    }

    #[test]
    fn builder_with_time_getter_overrides_pool_clock() {
        set_http_client_test_time(777);
        let client = HttpClient::builder()
            .with_time_getter(http_client_test_time)
            .build();
        assert_eq!(client.pool_now().as_nanos(), 777);
        assert_eq!((client.config.time_getter())().as_nanos(), 777);
    }

    #[test]
    fn builder_same_origin_redirects_sets_policy() {
        let client = HttpClient::builder().same_origin_redirects(4).build();

        assert!(matches!(
            client.config.redirect_policy,
            RedirectPolicy::SameOrigin(4)
        ));
    }

    #[test]
    fn client_default_creates_pool() {
        let client = HttpClient::new();
        let stats = client.pool_stats();
        assert_eq!(stats.total_connections, 0);
    }

    #[test]
    fn default_for_runtime_reuses_lazy_cx_slot() {
        let cx = crate::cx::Cx::for_testing_with_io();

        let first = crate::http::Client::default_for_runtime(&cx);
        let second = crate::http::Client::default_for_runtime(&cx);

        assert!(
            std::sync::Arc::ptr_eq(&first.pool, &second.pool),
            "runtime default client calls on one Cx must share the pool"
        );
        assert!(
            std::sync::Arc::ptr_eq(&first.idle_connections, &second.idle_connections),
            "runtime default client calls on one Cx must share idle state"
        );
        assert!(
            std::sync::Arc::ptr_eq(&first.cookies, &second.cookies),
            "runtime default client calls on one Cx must share cookie state"
        );
    }

    #[test]
    fn default_for_runtime_is_not_process_global() {
        let first_cx = crate::cx::Cx::for_testing_with_io();
        let second_cx = crate::cx::Cx::for_testing_with_io();

        let first = crate::http::Client::default_for_runtime(&first_cx);
        let second = crate::http::Client::default_for_runtime(&second_cx);

        assert!(
            !std::sync::Arc::ptr_eq(&first.pool, &second.pool),
            "independent Cx roots must not share a process-global default client"
        );
    }

    #[test]
    fn client_request_builder_collects_fluent_options() {
        let client = HttpClient::new();
        let builder = client
            .request_builder(Method::Post, "http://example.com/api")
            .header("X-Trace-Id", "trace-1")
            .headers([("Accept", "application/json")])
            .content_type("application/json")
            .bearer_auth("token-1")
            .body(b"{\"ok\":true}".to_vec())
            .timeout(std::time::Duration::from_millis(250));

        assert_eq!(builder.method, Method::Post);
        assert_eq!(builder.url, "http://example.com/api");
        assert_eq!(builder.body.as_slice(), b"{\"ok\":true}");
        assert_eq!(builder.timeout, Some(std::time::Duration::from_millis(250)));
        assert!(
            builder
                .headers
                .contains(&("X-Trace-Id".to_owned(), "trace-1".to_owned()))
        );
        assert!(
            builder
                .headers
                .contains(&("Accept".to_owned(), "application/json".to_owned()))
        );
        assert!(
            builder
                .headers
                .contains(&("Content-Type".to_owned(), "application/json".to_owned()))
        );
        assert!(
            builder
                .headers
                .contains(&("Authorization".to_owned(), "Bearer token-1".to_owned()))
        );
    }

    #[test]
    fn short_client_methods_create_fluent_builders() {
        let client = HttpClient::new();

        assert_eq!(client.get("http://example.com/get").method, Method::Get);
        assert_eq!(client.post("http://example.com/post").method, Method::Post);
        assert_eq!(client.put("http://example.com/put").method, Method::Put);
        assert_eq!(
            client.patch("http://example.com/patch").method,
            Method::Patch
        );
        assert_eq!(
            client.delete("http://example.com/delete").method,
            Method::Delete
        );
        assert_eq!(client.head("http://example.com/head").method, Method::Head);
        assert_eq!(
            client.options("http://example.com/options").method,
            Method::Options
        );
    }

    #[test]
    fn client_request_builder_json_and_basic_auth_helpers() {
        let client = HttpClient::new();
        let builder = client
            .post("http://example.com/api")
            .json(&serde_json::json!({"ok": true}))
            .expect("json body should serialize")
            .basic_auth("alice", Some("secret"));

        assert_eq!(builder.method, Method::Post);
        assert_eq!(
            builder.body,
            serde_json::to_vec(&serde_json::json!({"ok": true})).expect("json body")
        );
        assert!(
            builder
                .headers
                .contains(&("Content-Type".to_owned(), "application/json".to_owned()))
        );
        assert!(builder.headers.contains(&(
            "Authorization".to_owned(),
            "Basic YWxpY2U6c2VjcmV0".to_owned()
        )));
    }

    #[test]
    fn client_request_builder_query_extends_existing_url() {
        let client = HttpClient::new();
        let builder = client
            .get("http://example.com/search?existing=true")
            .query([("q", "rust async"), ("tag", "a+b")]);

        assert_eq!(
            builder.url,
            "http://example.com/search?existing=true&q=rust%20async&tag=a%2Bb"
        );
        assert!(builder.body.is_empty());
    }

    #[test]
    fn client_request_builder_form_sets_body_and_content_type() {
        let client = HttpClient::new();
        let builder = client
            .post("http://example.com/form")
            .form([("name", "Ada Lovelace"), ("role", "math+runtime")]);

        assert_eq!(builder.method, Method::Post);
        assert_eq!(
            builder.body.as_slice(),
            b"name=Ada%20Lovelace&role=math%2Bruntime"
        );
        assert!(builder.headers.contains(&(
            "Content-Type".to_owned(),
            "application/x-www-form-urlencoded".to_owned()
        )));
    }

    #[test]
    fn client_request_builder_send_respects_cancelled_cx_before_dialing() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let client = HttpClient::new();
        let err = block_on(
            client
                .get("http://127.0.0.1:1/cancelled")
                .header("X-Trace-Id", "trace-1")
                .send(&cx),
        )
        .expect_err("cancelled cx should reject before connect");

        assert!(err.is_cancelled());
    }

    #[test]
    fn release_connection_marks_fresh_connection_with_custom_time_getter() {
        set_http_client_test_time(123);
        let client = HttpClient::builder()
            .with_time_getter(http_client_test_time)
            .build();
        let key = PoolKey::http("example.com", None);
        let id = client
            .pool
            .lock()
            .register_connecting(key.clone(), Time::ZERO, 1);

        client.release_connection(&key, Some(id), true, loopback_client_io());

        let (created_at, last_used, state, requests_served) = {
            let pool = client.pool.lock();
            let meta = pool
                .get_connection_meta(&key, id)
                .expect("connection metadata");
            let values = (
                meta.created_at,
                meta.last_used,
                meta.state,
                meta.requests_served,
            );
            drop(pool);
            values
        };
        assert_eq!(created_at, Time::ZERO);
        assert_eq!(last_used, Time::from_nanos(123));
        assert_eq!(state, crate::http::pool::PooledConnectionState::Idle);
        assert_eq!(requests_served, 0);
    }

    /// mu5yhv finding 2: the retry after a stale reused connection acquires
    /// without reusing idle connections, and kept skipping them while it
    /// waited at the limit. Releases return connections to the idle set, so
    /// with `pool_wait_timeout` the retry failed `PoolExhausted` after the
    /// whole wait while the connection another request had released sat idle.
    #[test]
    fn a_fresh_acquire_waiting_at_the_limit_takes_a_connection_released_meanwhile() {
        use std::time::Duration;

        let client = Arc::new(
            HttpClient::builder()
                .max_connections_per_host(1)
                .pool_wait_timeout(Duration::from_secs(3))
                .build(),
        );
        let parsed = ParsedUrl::parse("http://127.0.0.1:9/retry").expect("parse url");
        let key = parsed.pool_key();
        let holder = client
            .pool
            .lock()
            .register_connecting(key.clone(), client.pool_now(), 1);

        // The holder's connection, whose peer stays open, so it is reusable.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let client_side =
            std::net::TcpStream::connect(listener.local_addr().expect("address")).expect("connect");
        let (_server_side, _) = listener.accept().expect("accept");
        let io = ClientIo::Plain(TcpStream::from_std(client_side).expect("wrap stream"));
        let releaser = {
            let client = Arc::clone(&client);
            let key = key.clone();
            std::thread::spawn(move || {
                // Release only once the acquire is parked on the pool: a
                // release that came first would leave an idle connection the
                // fresh acquire purges, and it would dial the closed port 9.
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while client.pool_released.waiter_count() == 0
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                client.release_connection(&key, Some(holder), true, io);
            })
        };

        let started = std::time::Instant::now();
        let acquired = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("runtime")
            .block_on(client.acquire_fresh_connection(&Cx::for_testing(), &parsed));
        releaser.join().expect("releaser thread");
        let acquired = acquired.expect("the connection released during the wait is taken");
        assert_eq!(acquired.pool_id, Some(holder));
        assert!(!acquired.fresh, "the released connection, not a new dial");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn release_connection_marks_reused_connection_with_custom_time_getter() {
        let client = HttpClient::builder()
            .with_time_getter(http_client_test_time)
            .build();
        let key = PoolKey::http("example.com", None);
        let id = {
            let mut pool = client.pool.lock();
            let id = pool.register_connecting(key.clone(), Time::from_nanos(10), 1);
            assert!(pool.mark_connected(&key, id, Time::from_nanos(20)));
            let acquired = pool
                .try_acquire(&key, Time::from_nanos(30))
                .expect("acquire pooled connection");
            assert_eq!(acquired, id);
            drop(pool);
            id
        };

        set_http_client_test_time(456);
        client.release_connection(&key, Some(id), false, loopback_client_io());

        let (created_at, last_used, state, requests_served) = {
            let pool = client.pool.lock();
            let meta = pool
                .get_connection_meta(&key, id)
                .expect("connection metadata");
            let values = (
                meta.created_at,
                meta.last_used,
                meta.state,
                meta.requests_served,
            );
            drop(pool);
            values
        };
        assert_eq!(created_at, Time::from_nanos(10));
        assert_eq!(last_used, Time::from_nanos(456));
        assert_eq!(state, crate::http::pool::PooledConnectionState::Idle);
        assert_eq!(requests_served, 1);
    }

    #[test]
    fn release_connection_drops_fresh_io_when_mark_connected_is_rejected() {
        let client = HttpClient::builder()
            .with_time_getter(http_client_test_time)
            .build();
        let key = PoolKey::http("example.com", None);
        let id = {
            let mut pool = client.pool.lock();
            let id = pool.register_connecting(key.clone(), Time::from_nanos(10), 1);
            assert!(pool.mark_connected(&key, id, Time::from_nanos(20)));
            drop(pool);
            id
        };

        set_http_client_test_time(30);
        client.release_connection(&key, Some(id), true, loopback_client_io());

        assert!(
            client.pool.lock().get_connection_meta(&key, id).is_none(),
            "invalid fresh release must retire pool metadata instead of storing idle IO"
        );
        assert!(
            client.idle_connections.lock().get(&key).is_none(),
            "invalid fresh release must not leave idle IO behind"
        );
    }

    #[test]
    fn release_connection_drops_reused_io_when_release_is_rejected() {
        let client = HttpClient::builder()
            .with_time_getter(http_client_test_time)
            .build();
        let key = PoolKey::http("example.com", None);
        let id = client
            .pool
            .lock()
            .register_connecting(key.clone(), Time::from_nanos(10), 1);

        set_http_client_test_time(30);
        client.release_connection(&key, Some(id), false, loopback_client_io());

        assert!(
            client.pool.lock().get_connection_meta(&key, id).is_none(),
            "invalid reused release must retire pool metadata instead of storing idle IO"
        );
        assert!(
            client.idle_connections.lock().get(&key).is_none(),
            "invalid reused release must not leave idle IO behind"
        );
    }

    #[test]
    fn cleanup_expired_idle_connections_drops_stale_client_io() {
        set_http_client_test_time(0);
        let client = HttpClient::builder()
            .with_time_getter(http_client_test_time)
            .idle_timeout(std::time::Duration::from_nanos(100))
            .build();
        let key = PoolKey::http("example.com", None);
        let id = client
            .pool
            .lock()
            .register_connecting(key.clone(), Time::ZERO, 1);

        client.release_connection(&key, Some(id), true, loopback_client_io());
        assert_eq!(
            client.idle_connections.lock().get(&key).map_or(0, Vec::len),
            1,
            "freshly released client IO should be tracked as idle"
        );

        set_http_client_test_time(150);
        client.cleanup_expired_idle_connections(http_client_test_time());

        assert!(
            client.pool.lock().get_connection_meta(&key, id).is_none(),
            "expired pool metadata must be pruned"
        );
        assert!(
            client.idle_connections.lock().get(&key).is_none(),
            "expired idle IO must be dropped alongside metadata"
        );
    }

    #[test]
    fn release_connection_holds_pool_lock_until_idle_io_is_recorded() {
        use std::sync::Arc;
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        let client = Arc::new(
            HttpClient::builder()
                .with_time_getter(http_client_test_time)
                .build(),
        );
        let key = PoolKey::http("example.com", None);
        let id = client
            .pool
            .lock()
            .register_connecting(key.clone(), Time::ZERO, 1);

        let idle_guard = client.idle_connections.lock();
        let (tx, rx) = mpsc::channel();
        let release_client = Arc::clone(&client);
        let release_key = key.clone();
        let release_thread = std::thread::spawn(move || {
            tx.send(()).expect("signal release start");
            release_client.release_connection(&release_key, Some(id), true, loopback_client_io());
        });

        rx.recv().expect("release thread should start");
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if client.pool.try_lock().is_none() {
                break;
            }
            assert!(
                Instant::now() <= deadline,
                "release_connection should hold the pool lock until idle IO is inserted"
            );
            std::thread::yield_now();
        }

        drop(idle_guard);
        release_thread
            .join()
            .expect("release thread should complete");

        assert_eq!(
            client.idle_connections.lock().get(&key).map_or(0, Vec::len),
            1,
            "release must leave idle IO recorded once the lock handoff completes"
        );
        let state = client
            .pool
            .lock()
            .get_connection_meta(&key, id)
            .expect("connection metadata should remain")
            .state;
        assert_eq!(state, crate::http::pool::PooledConnectionState::Idle);
    }

    #[test]
    fn parse_set_cookie_pair_extracts_first_pair() {
        let parsed = parse_set_cookie_pair("session=abc123; Path=/; HttpOnly");
        assert_eq!(parsed, Some(("session".to_string(), "abc123".to_string())));

        assert_eq!(parse_set_cookie_pair(""), None);
        assert_eq!(parse_set_cookie_pair("invalid"), None);
        assert_eq!(parse_set_cookie_pair(" =value"), None);
    }

    /// br-asupersync-7xe690: RFC 6265 §5.2.3 paired-DQUOTE strip — only
    /// remove BOTH quotes when both are present; never trim asymmetric or
    /// repeated quotes. Previously parse_set_cookie_pair used trim_matches
    /// which is greedy/asymmetric.
    #[test]
    fn parse_set_cookie_pair_paired_dquote_strip_per_rfc6265() {
        // Symmetric paired quotes: strip both.
        assert_eq!(
            parse_set_cookie_pair("session=\"abc123==\""),
            Some(("session".to_string(), "abc123==".to_string())),
            "paired DQUOTEs must be stripped together"
        );
        // Leading-only quote: keep both bytes literal (one-sided is not paired).
        assert_eq!(
            parse_set_cookie_pair("name=\"abc"),
            Some(("name".to_string(), "\"abc".to_string())),
            "asymmetric leading-only DQUOTE must NOT be stripped"
        );
        // Trailing-only quote: keep both bytes literal.
        assert_eq!(
            parse_set_cookie_pair("name=abc\""),
            Some(("name".to_string(), "abc\"".to_string())),
            "asymmetric trailing-only DQUOTE must NOT be stripped"
        );
        // Doubled quotes on each side: strip exactly one pair, leaving the
        // inner pair literal. Previously trim_matches collapsed all four to
        // the inner contents.
        assert_eq!(
            parse_set_cookie_pair("name=\"\"x\"\""),
            Some(("name".to_string(), "\"x\"".to_string())),
            "double-quoted value must yield single inner pair literal, not collapse"
        );
        // No quotes: passthrough.
        assert_eq!(
            parse_set_cookie_pair("name=abc"),
            Some(("name".to_string(), "abc".to_string()))
        );
        // Empty value with paired quotes: paired strip yields empty string.
        assert_eq!(
            parse_set_cookie_pair("k=\"\""),
            Some(("k".to_string(), String::new()))
        );
        // Single quote (only one byte): not enough to be paired, must be kept.
        assert_eq!(
            parse_set_cookie_pair("k=\""),
            Some(("k".to_string(), "\"".to_string())),
            "a single-byte DQUOTE value must remain literal"
        );
    }

    #[test]
    fn cookie_store_replays_quoted_set_cookie_value_without_quotes() {
        fn rfc6265_reference_pair(raw: &str) -> Option<(String, String)> {
            let pair = raw.split(';').next()?.trim();
            let (name, value) = pair.split_once('=')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|inner| inner.strip_suffix('"'))
                .unwrap_or(value);
            Some((name.to_string(), value.to_string()))
        }

        let raw = r#"session="abc123=="; Path=/; HttpOnly"#;
        assert_eq!(parse_set_cookie_pair(raw), rfc6265_reference_pair(raw));

        let client = HttpClient::builder().cookie_store(true).build();
        client.store_response_cookies(
            "example.com",
            Scheme::Https,
            &[("Set-Cookie".to_string(), raw.to_string())],
        );

        let cookie_header = client
            .cookie_header_for_host("example.com", Scheme::Http)
            .expect("cookie header");
        assert_eq!(cookie_header, "session=abc123==");
    }

    #[test]
    fn cookie_store_attaches_cookie_header_when_enabled() {
        let client = HttpClient::builder().cookie_store(true).build();
        client.store_response_cookies(
            "Example.COM",
            Scheme::Https,
            &[(
                "Set-Cookie".to_string(),
                "session=abc123; Path=/".to_string(),
            )],
        );

        let parsed = ParsedUrl::parse("http://example.com/data").expect("valid URL");
        let req = client.build_request(&Method::Get, &parsed, &[], &[], None, None);
        assert_eq!(
            get_header(&req.headers, "cookie"),
            Some("session=abc123".to_string())
        );
    }

    #[test]
    fn cookie_store_secure_attributes_restrict_request_scheme() {
        let http = ParsedUrl::parse("http://example.com/data").unwrap();
        let https = ParsedUrl::parse("https://example.com/data").unwrap();
        for attributes in [
            "Secure",
            "sEcUrE",
            " Secure = ignored ",
            "Path=/; Secure; HttpOnly",
            "Secure; Secure",
        ] {
            let client = HttpClient::builder().cookie_store(true).build();
            client.store_response_cookies(
                "Example.COM",
                Scheme::Https,
                &[(
                    "Set-Cookie".to_owned(),
                    format!("session=secret; {attributes}"),
                )],
            );
            let request = client.build_request(&Method::Get, &https, &[], &[], None, None);
            assert_eq!(
                get_header(&request.headers, "cookie"),
                Some("session=secret".to_owned()),
                "secure cookie must remain available over HTTPS ({attributes})"
            );
            let request = client.build_request(&Method::Get, &http, &[], &[], None, None);
            assert_eq!(
                get_header(&request.headers, "cookie"),
                None,
                "secure cookie must not be attached over HTTP ({attributes})"
            );
        }
    }

    #[test]
    fn cookie_store_secure_downgrade_keeps_only_plain_cookies() {
        let client = HttpClient::builder().cookie_store(true).build();
        client.store_response_cookies(
            "example.com",
            Scheme::Https,
            &[
                ("Set-Cookie".to_owned(), "session=secret; Secure".to_owned()),
                (
                    "Set-Cookie".to_owned(),
                    "theme=dark; SameSite=Secure".to_owned(),
                ),
                ("Set-Cookie".to_owned(), "display=wide; Securely".to_owned()),
            ],
        );
        let from = ParsedUrl::parse("https://example.com/start").unwrap();
        let to = ParsedUrl::parse("http://example.com/redirected").unwrap();
        assert!(redirect_policy_allows_target(
            &RedirectPolicy::Limited(10),
            &from,
            &to
        ));
        let headers = strip_sensitive_headers_on_redirect(
            &from,
            &to,
            vec![("Cookie".to_owned(), "caller=secret".to_owned())],
        );
        assert!(headers.is_empty());
        let request = client.build_request(&Method::Get, &to, &headers, &[], None, None);
        assert_eq!(
            get_header(&request.headers, "cookie"),
            Some("theme=dark; display=wide".to_owned())
        );
        let request = client.build_request(&Method::Get, &from, &[], &[], None, None);
        assert_eq!(
            get_header(&request.headers, "cookie"),
            Some("session=secret; theme=dark; display=wide".to_owned()),
            "a downgrade must filter the outgoing header without deleting stored cookies"
        );
    }

    #[test]
    fn cookie_store_secure_replacement_updates_transport_restriction() {
        let client = HttpClient::builder().cookie_store(true).build();
        let http = ParsedUrl::parse("http://example.com/").unwrap();
        let https = ParsedUrl::parse("https://example.com/").unwrap();
        for (value, expected_http, expected_https) in [
            (
                "session=plain",
                Some("session=plain"),
                Some("session=plain"),
            ),
            ("session=secret; Secure", None, Some("session=secret")),
            (
                "session=public",
                Some("session=public"),
                Some("session=public"),
            ),
            ("session=; Secure", None, None),
        ] {
            client.store_response_cookies(
                "example.com",
                Scheme::Https,
                &[("Set-Cookie".to_owned(), value.to_owned())],
            );
            for (parsed, expected) in [(&http, expected_http), (&https, expected_https)] {
                let request = client.build_request(&Method::Get, parsed, &[], &[], None, None);
                assert_eq!(
                    get_header(&request.headers, "cookie").as_deref(),
                    expected,
                    "replacement must refresh the stored Secure flag ({value}, {:?})",
                    parsed.scheme
                );
            }
        }
    }

    /// asupersync-kwvk89: RFC 6265bis section 5.6. A response that did not
    /// arrive over HTTPS must not create a Secure cookie and must leave a
    /// stored Secure cookie alone, whether it tries to replace or to delete
    /// it; otherwise an on-path attacker injecting plain-HTTP responses could
    /// fix or evict the HTTPS session cookie.
    #[test]
    fn cookie_store_plain_http_response_leaves_secure_cookies_alone() {
        let http = ParsedUrl::parse("http://example.com/").unwrap();
        let https = ParsedUrl::parse("https://example.com/").unwrap();
        let client = HttpClient::builder().cookie_store(true).build();
        client.store_response_cookies(
            "example.com",
            Scheme::Https,
            &[(
                "Set-Cookie".to_owned(),
                "session=genuine; Secure".to_owned(),
            )],
        );

        for injected in [
            "session=attacker",
            "session=attacker; Secure",
            "session=",
            "session=; Secure",
        ] {
            client.store_response_cookies(
                "example.com",
                Scheme::Http,
                &[("Set-Cookie".to_owned(), injected.to_owned())],
            );
            let request = client.build_request(&Method::Get, &https, &[], &[], None, None);
            assert_eq!(
                get_header(&request.headers, "cookie").as_deref(),
                Some("session=genuine"),
                "a plain-HTTP response must not touch a Secure cookie ({injected})"
            );
            let request = client.build_request(&Method::Get, &http, &[], &[], None, None);
            assert_eq!(
                get_header(&request.headers, "cookie"),
                None,
                "the Secure cookie must stay HTTPS-only ({injected})"
            );
        }

        // A plain-HTTP response cannot create a Secure cookie either.
        client.store_response_cookies(
            "example.com",
            Scheme::Http,
            &[("Set-Cookie".to_owned(), "token=abc; Secure".to_owned())],
        );
        let request = client.build_request(&Method::Get, &https, &[], &[], None, None);
        assert_eq!(
            get_header(&request.headers, "cookie").as_deref(),
            Some("session=genuine"),
            "a plain-HTTP response must not create a Secure cookie"
        );

        // The genuine HTTPS origin can still rotate and delete its cookie.
        client.store_response_cookies(
            "example.com",
            Scheme::Https,
            &[(
                "Set-Cookie".to_owned(),
                "session=rotated; Secure".to_owned(),
            )],
        );
        let request = client.build_request(&Method::Get, &https, &[], &[], None, None);
        assert_eq!(
            get_header(&request.headers, "cookie").as_deref(),
            Some("session=rotated")
        );
        client.store_response_cookies(
            "example.com",
            Scheme::Https,
            &[("Set-Cookie".to_owned(), "session=".to_owned())],
        );
        let request = client.build_request(&Method::Get, &https, &[], &[], None, None);
        assert_eq!(get_header(&request.headers, "cookie"), None);
    }

    /// asupersync-kwvk89: only Secure cookies are protected; plain cookies
    /// stay updatable and deletable over plain HTTP.
    #[test]
    fn cookie_store_plain_http_response_still_updates_plain_cookies() {
        let http = ParsedUrl::parse("http://example.com/").unwrap();
        let client = HttpClient::builder().cookie_store(true).build();
        client.store_response_cookies(
            "example.com",
            Scheme::Https,
            &[("Set-Cookie".to_owned(), "theme=dark".to_owned())],
        );
        client.store_response_cookies(
            "example.com",
            Scheme::Http,
            &[("Set-Cookie".to_owned(), "theme=light".to_owned())],
        );
        let request = client.build_request(&Method::Get, &http, &[], &[], None, None);
        assert_eq!(
            get_header(&request.headers, "cookie").as_deref(),
            Some("theme=light")
        );
        client.store_response_cookies(
            "example.com",
            Scheme::Http,
            &[("Set-Cookie".to_owned(), "theme=".to_owned())],
        );
        let request = client.build_request(&Method::Get, &http, &[], &[], None, None);
        assert_eq!(get_header(&request.headers, "cookie"), None);
    }

    #[test]
    fn cookie_store_respects_explicit_cookie_header() {
        let client = HttpClient::builder().cookie_store(true).build();
        client.store_response_cookies(
            "example.com",
            Scheme::Https,
            &[("Set-Cookie".to_string(), "session=abc123".to_string())],
        );

        let parsed = ParsedUrl::parse("http://example.com/path").expect("valid URL");
        let req = client.build_request(
            &Method::Get,
            &parsed,
            &[("Cookie".to_string(), "manual=1".to_string())],
            &[],
            None,
            None,
        );
        assert_eq!(
            get_header(&req.headers, "cookie"),
            Some("manual=1".to_string())
        );
    }

    #[test]
    fn build_request_adds_proxy_authorization_when_not_explicit() {
        let client = HttpClient::builder().build();
        let parsed = ParsedUrl::parse("http://example.com/path").expect("valid URL");
        let req = client.build_request(
            &Method::Get,
            &parsed,
            &[("Accept".to_string(), "application/json".to_string())],
            &[],
            Some(absolute_request_target(&parsed)),
            Some("Basic Zm9vOmJhcg=="),
        );
        assert_eq!(
            get_header(&req.headers, "proxy-authorization"),
            Some("Basic Zm9vOmJhcg==".to_string())
        );
        assert_eq!(
            req.uri, "http://example.com/path",
            "forward proxy request must use absolute-form URI"
        );
    }

    #[test]
    fn build_request_preserves_explicit_proxy_authorization() {
        let client = HttpClient::builder().build();
        let parsed = ParsedUrl::parse("http://example.com/path").expect("valid URL");
        let req = client.build_request(
            &Method::Get,
            &parsed,
            &[(
                "Proxy-Authorization".to_string(),
                "Basic ZXhwbGljaXQ=".to_string(),
            )],
            &[],
            Some(absolute_request_target(&parsed)),
            Some("Basic aWdub3JlZA=="),
        );
        assert_eq!(
            get_header(&req.headers, "proxy-authorization"),
            Some("Basic ZXhwbGljaXQ=".to_string())
        );
    }

    #[test]
    fn build_request_ignores_explicit_host_header() {
        let client = HttpClient::builder().build();
        let parsed = ParsedUrl::parse("http://example.com/path").expect("valid URL");
        let req = client.build_request(
            &Method::Get,
            &parsed,
            &[("Host".to_string(), "attacker.test".to_string())],
            &[],
            None,
            None,
        );

        let host_headers: Vec<_> = req
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
            .collect();
        assert_eq!(host_headers.len(), 1);
        assert_eq!(host_headers[0].1, "example.com");
    }

    #[test]
    fn build_request_applies_default_headers_as_request_fallbacks() {
        let client = HttpClient::builder()
            .default_header("Accept", "application/json")
            .default_header("Host", "wrong.example")
            .default_header("User-Agent", "asupersync-test/default")
            .default_header("X-Trace-Id", "client-default")
            .build();
        let parsed = ParsedUrl::parse("http://example.com/path").expect("valid URL");
        let req = client.build_request(
            &Method::Get,
            &parsed,
            &[
                ("Host".to_string(), "attacker.test".to_string()),
                ("X-Trace-Id".to_string(), "request-override".to_string()),
            ],
            &[],
            None,
            None,
        );

        assert_eq!(
            get_header(&req.headers, "accept"),
            Some("application/json".to_string())
        );
        assert_eq!(
            get_header(&req.headers, "user-agent"),
            Some("asupersync-test/default".to_string())
        );
        assert_eq!(
            get_header(&req.headers, "x-trace-id"),
            Some("request-override".to_string())
        );

        let host_headers: Vec<_> = req
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
            .collect();
        assert_eq!(host_headers.len(), 1);
        assert_eq!(host_headers[0].1, "example.com");

        let trace_headers = req
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("x-trace-id"))
            .count();
        assert_eq!(trace_headers, 1);
    }

    #[test]
    fn build_request_treats_default_cookie_and_proxy_authorization_as_explicit() {
        let client = HttpClient::builder()
            .cookie_store(true)
            .default_header("Cookie", "client-default=1")
            .default_header("Proxy-Authorization", "Basic Y2xpZW50")
            .build();
        client.store_response_cookies(
            "example.com",
            Scheme::Https,
            &[("Set-Cookie".to_string(), "stored=ignored".to_string())],
        );

        let parsed = ParsedUrl::parse("http://example.com/path").expect("valid URL");
        let req = client.build_request(
            &Method::Get,
            &parsed,
            &[],
            &[],
            Some(absolute_request_target(&parsed)),
            Some("Basic cHJveHk="),
        );

        assert_eq!(
            get_header(&req.headers, "cookie"),
            Some("client-default=1".to_string())
        );
        assert_eq!(
            get_header(&req.headers, "proxy-authorization"),
            Some("Basic Y2xpZW50".to_string())
        );
    }

    #[test]
    fn build_request_with_origin_strips_default_credentials_cross_origin() {
        // br-asupersync-u957g0: client-wide DEFAULT sensitive headers
        // (Authorization / Cookie / Proxy-Authorization) are re-applied on every
        // hop by `build_request`. Without an origin check they leak to a redirect
        // target of a DIFFERENT origin (a different host, or an https->http
        // downgrade). They must be stripped cross-origin, but survive the initial
        // request and a same-origin redirect. Non-sensitive default headers are
        // always forwarded.
        let client = HttpClient::builder()
            .default_header("Authorization", "Bearer super-secret")
            .default_header("Cookie", "session=leak-me")
            .default_header("Proxy-Authorization", "Basic ZGVmYXVsdA==")
            .default_header("X-Trace-Id", "keep-me")
            .build();

        let origin = ParsedUrl::parse("https://api.example.com/start").expect("valid URL");

        // Case 1: the initial request (origin = None) keeps every default header.
        let initial = ParsedUrl::parse("https://api.example.com/start").expect("valid URL");
        let req =
            client.build_request_with_origin(&Method::Get, &initial, &[], &[], None, None, None);
        assert_eq!(
            get_header(&req.headers, "authorization"),
            Some("Bearer super-secret".to_string())
        );
        assert_eq!(
            get_header(&req.headers, "cookie"),
            Some("session=leak-me".to_string())
        );
        assert_eq!(
            get_header(&req.headers, "proxy-authorization"),
            Some("Basic ZGVmYXVsdA==".to_string())
        );
        assert_eq!(
            get_header(&req.headers, "x-trace-id"),
            Some("keep-me".to_string())
        );

        // Case 2: a same-origin redirect target keeps every default header.
        let same = ParsedUrl::parse("https://api.example.com/next").expect("valid URL");
        let req = client
            .build_request_with_origin(&Method::Get, &same, &[], &[], None, None, Some(&origin));
        assert_eq!(
            get_header(&req.headers, "authorization"),
            Some("Bearer super-secret".to_string())
        );
        assert_eq!(
            get_header(&req.headers, "cookie"),
            Some("session=leak-me".to_string())
        );
        assert_eq!(
            get_header(&req.headers, "proxy-authorization"),
            Some("Basic ZGVmYXVsdA==".to_string())
        );

        // Case 3: a different host is cross-origin — strip the sensitive default
        // headers, but still forward the non-sensitive one.
        let evil = ParsedUrl::parse("https://evil.test/callback").expect("valid URL");
        let req = client
            .build_request_with_origin(&Method::Get, &evil, &[], &[], None, None, Some(&origin));
        assert_eq!(
            get_header(&req.headers, "authorization"),
            None,
            "Authorization must not leak to a cross-origin redirect target"
        );
        assert_eq!(
            get_header(&req.headers, "cookie"),
            None,
            "Cookie must not leak to a cross-origin redirect target"
        );
        assert_eq!(
            get_header(&req.headers, "proxy-authorization"),
            None,
            "Proxy-Authorization must not leak to a cross-origin redirect target"
        );
        assert_eq!(
            get_header(&req.headers, "x-trace-id"),
            Some("keep-me".to_string()),
            "a non-sensitive default header is still forwarded cross-origin"
        );

        // Case 4: an https->http downgrade to the SAME host is a different origin
        // and must strip the same sensitive default headers.
        let downgrade = ParsedUrl::parse("http://api.example.com/start").expect("valid URL");
        let req = client.build_request_with_origin(
            &Method::Get,
            &downgrade,
            &[],
            &[],
            None,
            None,
            Some(&origin),
        );
        assert_eq!(
            get_header(&req.headers, "authorization"),
            None,
            "an https->http downgrade must strip Authorization"
        );
        assert_eq!(
            get_header(&req.headers, "cookie"),
            None,
            "an https->http downgrade must strip Cookie"
        );
    }

    #[test]
    fn ensure_multipart_content_type_adds_header_when_missing() {
        let form = MultipartForm::with_boundary("upload-boundary")
            .unwrap()
            .text("user", "alice");
        let mut headers = vec![("Accept".to_string(), "application/json".to_string())];
        ensure_multipart_content_type(&mut headers, &form);
        assert_eq!(
            get_header(&headers, "content-type"),
            Some("multipart/form-data; boundary=upload-boundary".to_string())
        );
    }

    #[test]
    fn ensure_multipart_content_type_respects_existing_header() {
        let form = MultipartForm::with_boundary("upload-boundary")
            .unwrap()
            .text("user", "alice");
        let mut headers = vec![(
            "Content-Type".to_string(),
            "multipart/form-data; boundary=manual".to_string(),
        )];
        ensure_multipart_content_type(&mut headers, &form);
        assert_eq!(
            get_header(&headers, "content-type"),
            Some("multipart/form-data; boundary=manual".to_string())
        );
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn cookie_store_updates_and_removes_existing_cookie() {
        let client = HttpClient::builder().cookie_store(true).build();
        client.store_response_cookies(
            "example.com",
            Scheme::Https,
            &[("Set-Cookie".to_string(), "session=abc123".to_string())],
        );
        client.store_response_cookies(
            "example.com",
            Scheme::Https,
            &[("Set-Cookie".to_string(), "theme=dark".to_string())],
        );
        client.store_response_cookies(
            "example.com",
            Scheme::Https,
            &[("Set-Cookie".to_string(), "session=updated".to_string())],
        );

        let cookie_header = client
            .cookie_header_for_host("example.com", Scheme::Http)
            .expect("cookie header");
        assert!(cookie_header.contains("session=updated"));
        assert!(cookie_header.contains("theme=dark"));

        client.store_response_cookies(
            "example.com",
            Scheme::Https,
            &[("Set-Cookie".to_string(), "session=".to_string())],
        );
        let cookie_header = client
            .cookie_header_for_host("example.com", Scheme::Http)
            .expect("cookie header");
        assert!(!cookie_header.contains("session="));
        assert!(cookie_header.contains("theme=dark"));
    }

    #[derive(Debug)]
    struct ConnectTestIo {
        read_data: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
    }

    impl ConnectTestIo {
        fn new(read_data: impl AsRef<[u8]>) -> Self {
            Self {
                read_data: read_data.as_ref().to_vec(),
                read_pos: 0,
                written: Vec::new(),
            }
        }
    }

    impl AsyncRead for ConnectTestIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.read_pos >= self.read_data.len() {
                return Poll::Ready(Ok(()));
            }
            let remaining = self.read_data.len() - self.read_pos;
            let to_copy = remaining.min(buf.remaining());
            buf.put_slice(&self.read_data[self.read_pos..self.read_pos.saturating_add(to_copy)]);
            self.read_pos = self.read_pos.saturating_add(to_copy);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ConnectTestIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.extend_from_slice(data);
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn read_http_head(stream: &mut std::net::TcpStream) -> String {
        use std::io::Read;
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            let n = stream.read(&mut byte).expect("read request head");
            assert!(n > 0, "peer closed before the request head ended");
            head.push(byte[0]);
        }
        String::from_utf8(head).expect("utf-8 request head")
    }

    #[test]
    fn socks5_tunnelled_request_does_not_carry_proxy_authorization_to_the_origin() {
        use std::io::{Read, Write};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind SOCKS5 proxy");
        let proxy_addr = listener.local_addr().expect("proxy address");
        let proxy = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("set read timeout");
            let mut greeting = [0_u8; 2];
            stream.read_exact(&mut greeting).expect("read greeting");
            let mut methods = vec![0_u8; usize::from(greeting[1])];
            stream.read_exact(&mut methods).expect("read auth methods");
            stream.write_all(&[5, 0]).expect("choose no authentication");
            let mut connect = [0_u8; 4];
            stream.read_exact(&mut connect).expect("read CONNECT head");
            let address_len = match connect[3] {
                1 => 4,
                4 => 16,
                _ => {
                    let mut len = [0_u8; 1];
                    stream.read_exact(&mut len).expect("read domain length");
                    usize::from(len[0])
                }
            };
            let mut target = vec![0_u8; address_len + 2];
            stream.read_exact(&mut target).expect("read CONNECT target");
            stream
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .expect("accept CONNECT");
            let request = read_http_head(&mut stream);
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .expect("answer tunnelled request");
            request
        });

        let client = HttpClient::builder()
            .proxy(format!("socks5://{proxy_addr}"))
            .default_header("Proxy-Authorization", "Basic cHJveHk=")
            .build();
        let cx = Cx::for_testing();
        let response = block_on(client.request(
            &cx,
            Method::Get,
            "http://origin.example/",
            Vec::new(),
            Vec::new(),
        ))
        .expect("request through the SOCKS5 tunnel");
        let request = proxy.join().expect("proxy thread");
        assert_eq!(response.status, 204);
        assert!(request.starts_with("GET / HTTP/1.1\r\n"), "{request}");
        assert!(
            !request.to_ascii_lowercase().contains("proxy-authorization"),
            "proxy credentials reached the origin: {request}"
        );
    }

    #[test]
    fn redirect_to_get_drops_the_content_headers_of_the_dropped_body() {
        use std::io::{Read, Write};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener address");
        let server = std::thread::spawn(move || {
            let mut heads = Vec::new();
            for (index, response) in [
                "HTTP/1.1 302 Found\r\nLocation: /done\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            ]
            .into_iter()
            .enumerate()
            {
                let (mut stream, _) = listener.accept().expect("accept client");
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .expect("set read timeout");
                heads.push(read_http_head(&mut stream));
                if index == 0 {
                    let mut body = [0_u8; 3];
                    stream.read_exact(&mut body).expect("read POST body");
                }
                stream.write_all(response.as_bytes()).expect("respond");
            }
            heads
        });

        let client = HttpClient::builder().build();
        let cx = Cx::for_testing();
        let response = block_on(client.request(
            &cx,
            Method::Post,
            &format!("http://{addr}/submit"),
            vec![
                ("Content-Length".to_owned(), "3".to_owned()),
                ("Content-Type".to_owned(), "text/plain".to_owned()),
            ],
            b"abc".to_vec(),
        ))
        .expect("the redirected GET succeeds");
        let heads = server.join().expect("server thread");
        assert_eq!(response.status, 200);
        assert!(
            heads[1].starts_with("GET /done HTTP/1.1\r\n"),
            "{}",
            heads[1]
        );
        let redirected = heads[1].to_ascii_lowercase();
        assert!(
            !redirected.contains("content-length") && !redirected.contains("content-type"),
            "the GET must not describe the dropped POST body: {}",
            heads[1]
        );
        assert_eq!(redirect_method(303, &Method::Head), Method::Head);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn connect_tunnel_carries_the_callers_proxy_authorization() {
        use std::io::Write;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTP proxy");
        let proxy_addr = listener.local_addr().expect("proxy address");
        let proxy = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("set read timeout");
            let connect = read_http_head(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .expect("establish tunnel");
            // Close instead of speaking TLS: only the CONNECT request matters.
            connect
        });

        let client = HttpClient::builder()
            .proxy(format!("http://{proxy_addr}"))
            .default_header("Proxy-Authorization", "Basic cHJveHk=")
            .build();
        let cx = Cx::for_testing();
        let _ = block_on(client.request(
            &cx,
            Method::Get,
            "https://origin.example/",
            Vec::new(),
            Vec::new(),
        ));
        let connect = proxy.join().expect("proxy thread");
        assert!(
            connect.starts_with("CONNECT origin.example:443 HTTP/1.1\r\n"),
            "{connect}"
        );
        assert!(
            connect.contains("\r\nProxy-Authorization: Basic cHJveHk=\r\n"),
            "the tunnel request must carry the caller's proxy credentials: {connect}"
        );
    }

    #[test]
    fn forward_proxy_http_cross_origin_redirect_preserves_default_proxy_authorization() {
        use std::io::Write;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy listener");
        let proxy_addr = listener.local_addr().expect("proxy address");

        let proxy = std::thread::spawn(move || {
            let mut heads = Vec::new();
            for response in [
                "HTTP/1.1 302 Found\r\nLocation: http://other.example/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            ] {
                let (mut stream, _) = listener.accept().expect("accept client");
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .expect("set read timeout");
                heads.push(read_http_head(&mut stream));
                stream
                    .write_all(response.as_bytes())
                    .expect("write proxy response");
            }
            heads
        });

        let client = HttpClient::builder()
            .proxy(format!("http://{proxy_addr}"))
            .default_header("Proxy-Authorization", "Basic cHJveHktZGVmYXVsdA==")
            .build();
        let cx = Cx::for_testing();
        let response = block_on(client.request(
            &cx,
            Method::Get,
            "http://start.example/init",
            Vec::new(),
            Vec::new(),
        ))
        .expect("request through forward proxy succeeds");

        assert_eq!(response.status, 200);
        let heads = proxy.join().expect("proxy thread");
        assert_eq!(heads.len(), 2);
        assert!(heads[0].starts_with("GET http://start.example/init HTTP/1.1\r\n"));
        assert!(
            heads[0].contains("\r\nProxy-Authorization: Basic cHJveHktZGVmYXVsdA==\r\n"),
            "first hop must carry Proxy-Authorization: {}",
            heads[0]
        );
        assert!(heads[1].starts_with("GET http://other.example/next HTTP/1.1\r\n"));
        assert!(
            heads[1].contains("\r\nProxy-Authorization: Basic cHJveHktZGVmYXVsdA==\r\n"),
            "cross-origin redirected hop through forward proxy must retain Proxy-Authorization: {}",
            heads[1]
        );
    }

    #[test]
    fn forward_proxy_http_cross_origin_redirect_preserves_per_request_proxy_authorization() {
        use std::io::Write;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy listener");
        let proxy_addr = listener.local_addr().expect("proxy address");

        let proxy = std::thread::spawn(move || {
            let mut heads = Vec::new();
            for response in [
                "HTTP/1.1 302 Found\r\nLocation: http://other.example/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            ] {
                let (mut stream, _) = listener.accept().expect("accept client");
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .expect("set read timeout");
                heads.push(read_http_head(&mut stream));
                stream
                    .write_all(response.as_bytes())
                    .expect("write proxy response");
            }
            heads
        });

        let client = HttpClient::builder()
            .proxy(format!("http://{proxy_addr}"))
            .build();
        let cx = Cx::for_testing();
        let response = block_on(client.request(
            &cx,
            Method::Get,
            "http://start.example/init",
            vec![(
                "Proxy-Authorization".to_owned(),
                "Basic cHJveHktcmVxdWVzdA==".to_owned(),
            )],
            Vec::new(),
        ))
        .expect("request through forward proxy succeeds");

        assert_eq!(response.status, 200);
        let heads = proxy.join().expect("proxy thread");
        assert_eq!(heads.len(), 2);
        assert!(heads[0].starts_with("GET http://start.example/init HTTP/1.1\r\n"));
        assert!(
            heads[0].contains("\r\nProxy-Authorization: Basic cHJveHktcmVxdWVzdA==\r\n"),
            "first hop must carry Proxy-Authorization: {}",
            heads[0]
        );
        assert!(heads[1].starts_with("GET http://other.example/next HTTP/1.1\r\n"));
        assert!(
            heads[1].contains("\r\nProxy-Authorization: Basic cHJveHktcmVxdWVzdA==\r\n"),
            "cross-origin redirected hop through forward proxy must retain per-request Proxy-Authorization: {}",
            heads[1]
        );
    }

    #[test]
    fn direct_http_cross_origin_redirect_strips_proxy_authorization() {
        use std::io::Write;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener address");

        let second_listener = TcpListener::bind("127.0.0.1:0").expect("bind second listener");
        let second_addr = second_listener.local_addr().expect("second listener address");

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept first");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("set read timeout");
            let head1 = read_http_head(&mut stream);
            let resp = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{second_addr}/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(resp.as_bytes()).expect("write redirect");
            head1
        });

        let second_server = std::thread::spawn(move || {
            let (mut stream, _) = second_listener.accept().expect("accept second");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("set read timeout");
            let head2 = read_http_head(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .expect("write ok");
            head2
        });

        let client = HttpClient::builder().build();
        let cx = Cx::for_testing();
        let response = block_on(client.request(
            &cx,
            Method::Get,
            &format!("http://{addr}/start"),
            vec![("Proxy-Authorization".to_owned(), "Basic c2VjcmV0".to_owned())],
            Vec::new(),
        ))
        .expect("redirect succeeds");

        assert_eq!(response.status, 200);
        let head1 = server.join().expect("server 1 thread");
        let head2 = second_server.join().expect("server 2 thread");
        assert!(head1.contains("\r\nProxy-Authorization: Basic c2VjcmV0\r\n"));
        assert!(
            !head2.to_ascii_lowercase().contains("proxy-authorization"),
            "cross-origin redirect without proxy must strip Proxy-Authorization: {head2}"
        );
    }

    #[test]
    fn connect_tunnel_writes_expected_request() {
        let io = ConnectTestIo::new("HTTP/1.1 200 Connection Established\r\n\r\n");
        let tunnel = block_on(establish_http_connect_tunnel(
            io,
            "example.com:443",
            Some("asupersync-test/1.0"),
            &[("Proxy-Authorization".into(), "Basic abc".into())],
        ))
        .expect("tunnel should establish");
        let io = tunnel.into_inner();
        let written = String::from_utf8(io.written).expect("request should be utf8");
        assert!(written.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(written.contains("\r\nHost: example.com:443\r\n"));
        assert!(written.contains("\r\nUser-Agent: asupersync-test/1.0\r\n"));
        assert!(written.contains("\r\nProxy-Authorization: Basic abc\r\n"));
        assert!(written.ends_with("\r\n\r\n"));
    }

    #[test]
    fn connect_authority_accepts_bracketed_ipv6_with_port() {
        let io = ConnectTestIo::new("HTTP/1.1 200 Connection Established\r\n\r\n");
        let tunnel = block_on(establish_http_connect_tunnel(
            io,
            "[2001:db8::1]:443",
            None,
            &[],
        ))
        .expect("bracketed IPv6 authority should establish");
        let io = tunnel.into_inner();
        let written = String::from_utf8(io.written).expect("request should be utf8");
        assert!(written.starts_with("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"));
        assert!(written.contains("\r\nHost: [2001:db8::1]:443\r\n"));
    }

    #[test]
    fn connect_authority_rejects_ambiguous_targets() {
        for target_authority in [
            "http://example.com:443",
            "example.com",
            "example.com:",
            "example.com:99999",
            "example.com:443/path",
            "example.com:443?token=1",
            "example.com:443#frag",
            "user@example.com:443",
            "2001:db8::1:443",
            "[::1]",
            "[::1]:",
            "[::1]@example.com:443",
            "[]:443",
            "exa mple.com:443",
        ] {
            let io = ConnectTestIo::new("HTTP/1.1 200 OK\r\n\r\n");
            let err = block_on(establish_http_connect_tunnel(
                io,
                target_authority,
                None,
                &[],
            ))
            .expect_err("malformed CONNECT authority must be rejected");
            match err {
                ClientError::InvalidConnectInput(msg) => {
                    assert!(
                        msg.contains("authority"),
                        "unexpected message for {target_authority}: {msg}"
                    );
                }
                other => panic!("unexpected error for {target_authority}: {other:?}"),
            }
        }
    }

    #[test]
    fn connect_tunnel_preserves_prefetched_bytes_and_supports_write() {
        let io = ConnectTestIo::new("HTTP/1.1 200 OK\r\n\r\nHELLO");
        let mut tunnel = block_on(establish_http_connect_tunnel(
            io,
            "example.com:443",
            None,
            &[],
        ))
        .expect("tunnel should establish");

        assert_eq!(tunnel.prefetched_len(), 5);
        let mut first = [0u8; 3];
        block_on(async {
            poll_fn(|cx| -> std::task::Poll<Result<(), std::io::Error>> {
                let mut rb = ReadBuf::new(&mut first);
                Pin::new(&mut tunnel).poll_read(cx, &mut rb)
            })
            .await
            .expect("read prefetched bytes");
        });
        assert_eq!(&first, b"HEL");
        assert_eq!(tunnel.prefetched_len(), 2);

        block_on(async {
            tunnel.write_all(b"PING").await.expect("write to tunnel");
            tunnel.flush().await.expect("flush to tunnel");
        });

        let io = tunnel.into_inner();
        let written = String::from_utf8(io.written).expect("request should be utf8");
        assert!(written.ends_with("\r\n\r\nPING"));
    }

    #[test]
    fn connect_tunnel_rejects_non_success_status() {
        let io = ConnectTestIo::new("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
        let err = block_on(establish_http_connect_tunnel(
            io,
            "example.com:443",
            None,
            &[],
        ))
        .expect_err("non-2xx should fail");
        match err {
            ClientError::ConnectTunnelRefused { status, reason } => {
                assert_eq!(status, 407);
                assert!(reason.contains("Proxy Authentication Required"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn connect_tunnel_rejects_non_three_digit_status() {
        for response in [
            "HTTP/1.1 +20 Invalid\r\n\r\n",
            "HTTP/1.1 20 Invalid\r\n\r\n",
            "HTTP/1.1 2000 Invalid\r\n\r\n",
        ] {
            let io = ConnectTestIo::new(response);
            assert!(
                block_on(establish_http_connect_tunnel(
                    io,
                    "example.com:443",
                    None,
                    &[],
                ))
                .is_err(),
                "invalid CONNECT status in {response:?}",
            );
        }
    }

    #[test]
    fn connect_tunnel_rejects_header_injection() {
        for (user_agent, headers) in [
            (None, vec![("X-Test".to_string(), "ok\r\nbad".to_string())]),
            (None, vec![("Bad Header".to_string(), "value".to_string())]),
            (None, vec![("X-Test".to_string(), "bad\0value".to_string())]),
            (Some("bad\0agent"), Vec::new()),
        ] {
            let io = ConnectTestIo::new("HTTP/1.1 200 OK\r\n\r\n");
            let err = block_on(establish_http_connect_tunnel(
                io,
                "example.com:443",
                user_agent,
                &headers,
            ))
            .expect_err("invalid CONNECT header input must be rejected");
            match err {
                ClientError::InvalidConnectInput(msg) => {
                    assert!(msg.contains("valid HTTP field"));
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }

    // =========================================================================
    // Redirect policy
    // =========================================================================

    #[test]
    fn redirect_policy_default_is_limited() {
        let policy = RedirectPolicy::default();
        assert!(matches!(policy, RedirectPolicy::Limited(10)));
    }

    #[test]
    fn scheme_debug_clone_copy_eq() {
        let a = Scheme::Http;
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, Scheme::Https);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Http"));
    }

    #[test]
    fn redirect_policy_debug_clone() {
        let a = RedirectPolicy::Limited(5);
        let b = a;
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Limited"));
        assert!(dbg.contains('5'));
        let dbg2 = format!("{b:?}");
        assert_eq!(dbg, dbg2);
    }

    #[test]
    fn same_origin_redirect_policy_only_allows_matching_origin() {
        let policy = RedirectPolicy::SameOrigin(5);
        let current = ParsedUrl::parse("http://Example.com:8080/old").unwrap();
        let same = ParsedUrl::parse("http://example.COM:8080/new").unwrap();
        let different_host = ParsedUrl::parse("http://other.example:8080/new").unwrap();
        let different_port = ParsedUrl::parse("http://example.com:9090/new").unwrap();
        let different_scheme = ParsedUrl::parse("https://example.com:8080/new").unwrap();

        assert!(redirect_policy_allows_target(&policy, &current, &same));
        assert!(!redirect_policy_allows_target(
            &policy,
            &current,
            &different_host
        ));
        assert!(!redirect_policy_allows_target(
            &policy,
            &current,
            &different_port
        ));
        assert!(!redirect_policy_allows_target(
            &policy,
            &current,
            &different_scheme
        ));
        assert!(redirect_policy_allows_target(
            &RedirectPolicy::Limited(5),
            &current,
            &different_host
        ));
        assert!(!redirect_policy_allows_target(
            &RedirectPolicy::None,
            &current,
            &same
        ));
    }

    #[test]
    fn retry_policy_default_is_safe_stale_reuse() {
        assert_eq!(RetryPolicy::default(), RetryPolicy::SafeMethodsOnStaleReuse);
    }

    #[test]
    fn retry_policy_gates_stale_reuse_by_policy_method_and_error() {
        let stale_err = || {
            ClientError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed idle connection",
            ))
        };
        let other_err = || ClientError::InvalidUrl("not a transport error".into());

        let policy = RetryPolicy::SafeMethodsOnStaleReuse;
        assert!(policy.should_retry_reused_connection_failure(&Method::Get, &stale_err()));
        assert!(policy.should_retry_reused_connection_failure(&Method::Head, &stale_err()));
        assert!(!policy.should_retry_reused_connection_failure(&Method::Post, &stale_err()));
        assert!(!policy.should_retry_reused_connection_failure(&Method::Get, &other_err()));

        assert!(
            !RetryPolicy::None.should_retry_reused_connection_failure(&Method::Get, &stale_err())
        );
    }

    #[test]
    fn retry_policy_response_status_matrix_is_idempotent_and_retry_after_aware() {
        let response = Response {
            version: Version::Http11,
            status: 503,
            reason: "Service Unavailable".to_owned(),
            headers: vec![("Retry-After".to_owned(), "7".to_owned())],
            body: Vec::new(),
            trailers: Vec::new(),
        };
        let policy = RetryPolicy::IdempotentStatusCodes { max_retries: 1 };

        assert_eq!(
            policy.response_retry_delay(&Method::Get, &response, 0),
            Some(std::time::Duration::from_secs(7))
        );
        assert_eq!(
            policy.response_retry_delay(&Method::Put, &response, 0),
            Some(std::time::Duration::from_secs(7))
        );
        assert_eq!(
            policy.response_retry_delay(&Method::Post, &response, 0),
            None
        );
        assert_eq!(
            policy.response_retry_delay(&Method::Patch, &response, 0),
            None
        );
        assert_eq!(
            policy.response_retry_delay(&Method::Get, &response, 1),
            None
        );

        let mut non_retriable = response;
        non_retriable.status = 400;
        assert_eq!(
            policy.response_retry_delay(&Method::Get, &non_retriable, 0),
            None
        );
        assert_eq!(
            RetryPolicy::SafeMethodsOnStaleReuse.response_retry_delay(
                &Method::Get,
                &non_retriable,
                0
            ),
            None
        );
    }

    #[test]
    fn retry_after_beyond_the_retry_cap_returns_the_response() {
        let policy = RetryPolicy::IdempotentStatusCodes { max_retries: 1 };
        let response = |retry_after: &str| Response {
            version: Version::Http11,
            status: 503,
            reason: "Service Unavailable".to_owned(),
            headers: vec![("Retry-After".to_owned(), retry_after.to_owned())],
            body: Vec::new(),
            trailers: Vec::new(),
        };
        assert_eq!(
            policy.response_retry_delay(&Method::Get, &response("60"), 0),
            Some(MAX_RETRY_AFTER)
        );
        for too_long in ["61", "4000000000"] {
            assert_eq!(
                policy.response_retry_delay(&Method::Get, &response(too_long), 0),
                None,
                "Retry-After: {too_long} must not park the request"
            );
        }
    }

    // An HTTP-date Retry-After (RFC 9110 section 10.2.3) was read as "no
    // delay", so a 503 asking clients to come back in an hour was retried
    // back to back. A Retry-After the client cannot read now returns the
    // response.
    #[test]
    fn retry_after_that_is_not_delta_seconds_returns_the_response() {
        let policy = RetryPolicy::IdempotentStatusCodes { max_retries: 3 };
        let response = |headers: Vec<(String, String)>| Response {
            version: Version::Http11,
            status: 503,
            reason: "Service Unavailable".to_owned(),
            headers,
            body: Vec::new(),
            trailers: Vec::new(),
        };
        for retry_after in ["Wed, 21 Oct 2015 07:28:00 GMT", "soon", "-1", ""] {
            assert_eq!(
                policy.response_retry_delay(
                    &Method::Get,
                    &response(vec![("Retry-After".to_owned(), retry_after.to_owned())]),
                    0
                ),
                None,
                "Retry-After: {retry_after:?} must not retry at once"
            );
        }
        assert_eq!(
            policy.response_retry_delay(&Method::Get, &response(Vec::new()), 0),
            Some(std::time::Duration::ZERO),
            "without Retry-After the retry is immediate, as before"
        );
    }

    #[test]
    fn stale_reuse_retry_dials_a_new_connection_instead_of_another_idle_one() {
        use std::io::{Read, Write};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener address");
        let url = format!("http://{addr}/stale");
        let key = ParsedUrl::parse(&url).expect("parse url").pool_key();
        let client = HttpClient::builder()
            .retry_safe_methods_on_stale_reuse()
            .build();

        // Two idle keep-alive connections whose server side already closed,
        // as after a server restart.
        for _ in 0..2 {
            let client_side = std::net::TcpStream::connect(addr).expect("connect idle");
            let (server_side, _) = listener.accept().expect("accept idle");
            drop(server_side);
            let id = client
                .pool
                .lock()
                .register_connecting(key.clone(), client.pool_now(), 1);
            client.release_connection(
                &key,
                Some(id),
                true,
                ClientIo::Plain(TcpStream::from_std(client_side).expect("wrap idle stream")),
            );
        }

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept fresh connection");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("set read timeout");
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let n = stream.read(&mut buf).expect("read request");
                assert!(n > 0, "request must arrive before the client closes");
                request.extend_from_slice(&buf[..n]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .expect("write response");
        });

        let cx = Cx::for_testing();
        let response = block_on(client.request(&cx, Method::Get, &url, Vec::new(), Vec::new()))
            .expect("the retry after a stale idle connection must reach the server");
        server.join().expect("server thread");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        assert!(
            client.idle_connections.lock().get(&key).is_none(),
            "the other stale idle connection was closed, not left for the next request"
        );
    }

    #[test]
    fn retry_after_delta_parser_rejects_invalid_values() {
        assert_eq!(
            parse_retry_after_delta(" 12 "),
            Some(std::time::Duration::from_secs(12))
        );
        assert_eq!(
            parse_retry_after_delta("Wed, 21 Oct 2015 07:28:00 GMT"),
            None
        );
        assert_eq!(parse_retry_after_delta("-1"), None);
        assert_eq!(parse_retry_after_delta("+1"), None);
        assert_eq!(parse_retry_after_delta("abc"), None);
        assert_eq!(parse_retry_after_delta("\u{a0}12\u{a0}"), None);
    }

    #[test]
    fn parsed_url_debug_clone() {
        let url = ParsedUrl {
            scheme: Scheme::Https,
            host: "example.com".to_string(),
            port: 443,
            path: "/api/v1".to_string(),
        };
        let cloned = url.clone();
        assert_eq!(cloned.host, "example.com");
        assert_eq!(cloned.port, 443);
        let dbg = format!("{url:?}");
        assert!(dbg.contains("ParsedUrl"));
        assert!(dbg.contains("example.com"));
    }

    #[test]
    fn header_has_token_matches_case_insensitive_csv_values() {
        let headers = vec![
            ("Connection".to_string(), "keep-alive, Upgrade".to_string()),
            ("X-Test".to_string(), "value".to_string()),
        ];
        assert!(header_has_token(&headers, "connection", "keep-alive"));
        assert!(header_has_token(&headers, "connection", "upgrade"));
        assert!(!header_has_token(&headers, "connection", "close"));

        let ascii_ows = vec![("Connection".to_string(), "\t keep-alive \t".to_string())];
        assert!(header_has_token(&ascii_ows, "connection", "keep-alive"));

        let unicode_whitespace = vec![(
            "Connection".to_string(),
            "\u{a0}keep-alive\u{a0}".to_string(),
        )];
        assert!(!header_has_token(
            &unicode_whitespace,
            "connection",
            "keep-alive"
        ));
    }

    #[test]
    fn connection_can_be_reused_for_http11_without_close() {
        let response = Response {
            version: Version::Http11,
            status: 200,
            reason: "OK".into(),
            headers: vec![
                ("Content-Length".into(), "0".into()),
                ("Connection".into(), "keep-alive".into()),
            ],
            body: Vec::new(),
            trailers: Vec::new(),
        };
        assert!(connection_can_be_reused(&response, &Method::Get));

        let close_response = Response {
            headers: vec![
                ("Content-Length".into(), "0".into()),
                ("Connection".into(), "close".into()),
            ],
            ..response
        };
        assert!(!connection_can_be_reused(&close_response, &Method::Get));
    }

    #[test]
    fn connection_can_be_reused_for_http10_only_with_keep_alive() {
        let response = Response {
            version: Version::Http10,
            status: 200,
            reason: "OK".into(),
            headers: vec![
                ("Content-Length".into(), "0".into()),
                ("Connection".into(), "keep-alive".into()),
            ],
            body: Vec::new(),
            trailers: Vec::new(),
        };
        assert!(connection_can_be_reused(&response, &Method::Get));

        let chunked = Response {
            headers: vec![
                ("Transfer-Encoding".into(), "chunked".into()),
                ("Connection".into(), "keep-alive".into()),
            ],
            ..response.clone()
        };
        assert!(
            !connection_can_be_reused(&chunked, &Method::Get),
            "an HTTP/1.0 response with Transfer-Encoding is never pooled"
        );

        let no_header = Response {
            headers: Vec::new(),
            ..response
        };
        assert!(!connection_can_be_reused(&no_header, &Method::Get));
    }

    #[test]
    fn connection_not_reused_for_eof_delimited_body() {
        // RFC 9112 §6.3: no Content-Length and no Transfer-Encoding means
        // the body is delimited by connection close (EOF-framed).
        let response = Response {
            version: Version::Http11,
            status: 200,
            reason: "OK".into(),
            headers: vec![],
            body: Vec::new(),
            trailers: Vec::new(),
        };
        assert!(!connection_can_be_reused(&response, &Method::Get));

        // Bodyless status codes (204, 304) are exempt.
        let no_content = Response {
            status: 204,
            reason: "No Content".into(),
            ..response.clone()
        };
        assert!(connection_can_be_reused(&no_content, &Method::Get));

        // Transfer-Encoding present: body is chunk-framed, reuse is ok.
        let chunked = Response {
            headers: vec![("Transfer-Encoding".into(), "chunked".into())],
            ..response
        };
        assert!(connection_can_be_reused(&chunked, &Method::Get));
    }

    #[test]
    fn connection_not_reused_for_protocol_upgrade() {
        let response = Response {
            version: Version::Http11,
            status: 101,
            reason: "Switching Protocols".into(),
            headers: vec![
                ("Connection".into(), "Upgrade".into()),
                ("Upgrade".into(), "websocket".into()),
            ],
            body: Vec::new(),
            trailers: Vec::new(),
        };
        assert!(!connection_can_be_reused(&response, &Method::Get));
    }

    // Apache's mod_http2 advertises "Upgrade: h2,h2c" with "Connection:
    // Upgrade, Keep-Alive" on ordinary responses. Any Upgrade header used to
    // disable reuse, so every request to such a server paid a new TCP and TLS
    // handshake. Only a 101 switches protocols.
    #[test]
    fn an_upgrade_advertisement_on_an_ordinary_response_keeps_the_connection() {
        let response = Response {
            version: Version::Http11,
            status: 200,
            reason: "OK".into(),
            headers: vec![
                ("Upgrade".into(), "h2,h2c".into()),
                ("Connection".into(), "Upgrade, Keep-Alive".into()),
                ("Content-Length".into(), "2".into()),
            ],
            body: b"ok".to_vec(),
            trailers: Vec::new(),
        };
        assert!(connection_can_be_reused(&response, &Method::Get));

        let switching = Response {
            status: 101,
            reason: "Switching Protocols".into(),
            ..response
        };
        assert!(!connection_can_be_reused(&switching, &Method::Get));
    }

    #[test]
    fn request_connection_close_forbids_reuse() {
        let headers = vec![("Connection".to_string(), "keep-alive, close".to_string())];
        assert!(request_forbids_connection_reuse(&headers));

        let upgrade_headers = vec![("Upgrade".to_string(), "websocket".to_string())];
        assert!(request_forbids_connection_reuse(&upgrade_headers));
    }

    // =========================================================================
    // Cancellation via Cx
    // =========================================================================

    #[test]
    fn check_cx_returns_cancelled_when_cancelled() {
        let cx = Cx::for_testing();
        assert!(check_cx(&cx).is_ok());

        cx.set_cancel_requested(true);
        let err = check_cx(&cx).unwrap_err();
        assert!(err.is_cancelled());
    }

    #[test]
    fn request_returns_cancelled_when_cx_already_cancelled() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let client = HttpClient::new();
        let result = block_on(client.send_get(&cx, "http://example.com/test"));
        assert!(result.is_err());
        assert!(result.unwrap_err().is_cancelled());
    }

    #[test]
    fn post_returns_cancelled_when_cx_already_cancelled() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let client = HttpClient::new();
        let result = block_on(client.send_post(&cx, "http://example.com/submit", b"data".to_vec()));
        assert!(result.unwrap_err().is_cancelled());
    }

    #[test]
    fn put_returns_cancelled_when_cx_already_cancelled() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let client = HttpClient::new();
        let result = block_on(client.send_put(&cx, "http://example.com/item", b"data".to_vec()));
        assert!(result.unwrap_err().is_cancelled());
    }

    #[test]
    fn delete_returns_cancelled_when_cx_already_cancelled() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let client = HttpClient::new();
        let result = block_on(client.send_delete(&cx, "http://example.com/item"));
        assert!(result.unwrap_err().is_cancelled());
    }

    #[test]
    fn request_streaming_returns_cancelled_when_cx_already_cancelled() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let client = HttpClient::new();
        let result = block_on(client.request_streaming(
            &cx,
            Method::Get,
            "http://example.com/stream",
            Vec::new(),
            Vec::new(),
        ));
        assert!(result.unwrap_err().is_cancelled());
    }

    #[test]
    fn connect_tunnel_returns_cancelled_when_cx_already_cancelled() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let client = HttpClient::new();
        let result = block_on(client.connect_tunnel(
            &cx,
            "http://proxy.local:3128",
            "example.com:443",
            Vec::new(),
        ));
        assert!(result.unwrap_err().is_cancelled());
    }

    #[test]
    fn request_succeeds_with_non_cancelled_cx() {
        // Verify that a non-cancelled Cx does not interfere with normal operation.
        // This test only verifies we get past the cancellation check (URL parsing
        // will succeed, but the actual connect will fail since there's no server).
        let cx = Cx::for_testing();
        let client = HttpClient::new();
        let result = block_on(client.send_get(&cx, "http://127.0.0.1:1/nonexistent"));
        // The request should fail with a connect error (not a cancellation error).
        assert!(result.is_err());
        assert!(!result.unwrap_err().is_cancelled());
    }

    #[test]
    fn acquire_connection_respects_pool_limits_before_opening_socket() {
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        listener
            .set_nonblocking(true)
            .expect("set nonblocking listener");
        let addr = listener.local_addr().expect("listener address");
        let url = format!("http://{addr}/pooled");
        let parsed = ParsedUrl::parse(&url).expect("parse pooled url");
        let key = parsed.pool_key();

        let client = HttpClient::builder()
            .max_connections_per_host(1)
            .max_total_connections(1)
            .build();
        client.pool.lock().register_connecting(key, Time::ZERO, 1);

        let cx = Cx::for_testing();
        let err = match block_on(client.acquire_connection(&cx, &parsed)) {
            Ok(_) => panic!("pool exhaustion must reject before dialing"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            ClientError::PoolExhausted { ref host, port }
                if host == "127.0.0.1" && port == addr.port()
        ));

        let deadline = Instant::now() + Duration::from_millis(100);
        loop {
            match listener.accept() {
                Ok(_) => panic!("pool-exhausted acquisition must not open a socket"),
                Err(io_err) if io_err.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(io_err) => panic!("accept failed: {io_err}"),
            }
        }
    }

    #[test]
    fn acquire_connection_closes_an_idle_connection_to_another_host_when_the_pool_is_full() {
        use std::io::Read;
        use std::time::Duration;

        let client = HttpClient::builder().max_total_connections(1).build();

        // An idle keep-alive connection to host A fills the pool.
        let listener_a = TcpListener::bind("127.0.0.1:0").expect("bind host A");
        let addr_a = listener_a.local_addr().expect("host A address");
        let key_a = ParsedUrl::parse(&format!("http://{addr_a}/"))
            .expect("parse host A url")
            .pool_key();
        let client_side = std::net::TcpStream::connect(addr_a).expect("connect host A");
        let (mut server_side_a, _) = listener_a.accept().expect("accept host A");
        let id_a = client
            .pool
            .lock()
            .register_connecting(key_a.clone(), client.pool_now(), 1);
        client.release_connection(
            &key_a,
            Some(id_a),
            true,
            ClientIo::Plain(TcpStream::from_std(client_side).expect("wrap host A stream")),
        );

        let listener_b = TcpListener::bind("127.0.0.1:0").expect("bind host B");
        let addr_b = listener_b.local_addr().expect("host B address");
        let parsed_b = ParsedUrl::parse(&format!("http://{addr_b}/")).expect("parse host B url");

        let cx = Cx::for_testing();
        let acquired = match block_on(client.acquire_connection(&cx, &parsed_b)) {
            Ok(acquired) => acquired,
            Err(err) => panic!("a full pool of idle connections must not refuse host B: {err:?}"),
        };
        assert!(acquired.fresh, "host B gets a new connection");
        assert!(
            client
                .pool
                .lock()
                .get_connection_meta(&key_a, id_a)
                .is_none(),
            "host A's idle connection left the pool"
        );
        assert!(
            client.idle_connections.lock().get(&key_a).is_none(),
            "host A's idle socket was dropped with its metadata"
        );
        server_side_a
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set host A read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(
            server_side_a
                .read(&mut byte)
                .expect("host A observes the close"),
            0,
            "the evicted connection is closed, not leaked"
        );
    }

    #[test]
    fn request_returns_cancelled_when_cx_is_cancelled_after_exchange() {
        use std::io::{Read, Write};
        use std::sync::{Arc, mpsc};

        fn read_request_head(stream: &mut std::net::TcpStream) {
            let mut buf = [0_u8; 1024];
            let mut request = Vec::new();
            loop {
                let n = stream.read(&mut buf).expect("read request");
                assert!(n > 0, "request must arrive before peer closes");
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener address");
        let (request_seen_tx, request_seen_rx) = mpsc::channel();
        let (send_response_tx, send_response_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            read_request_head(&mut stream);
            request_seen_tx.send(()).expect("notify request arrival");
            send_response_rx
                .recv()
                .expect("wait for cancellation before responding");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                )
                .expect("write response");
            stream.flush().expect("flush response");
        });

        let client = Arc::new(
            HttpClient::builder()
                .max_connections_per_host(1)
                .max_total_connections(1)
                .build(),
        );
        let cx = Cx::for_testing();
        let request_cx = cx.clone();
        let request_client = Arc::clone(&client);
        let url = format!("http://{addr}/late-cancel");
        let request_url = url.clone();
        let request = std::thread::spawn(move || {
            block_on(request_client.send_get(&request_cx, &request_url))
        });

        request_seen_rx
            .recv()
            .expect("server should observe the request before cancellation");
        cx.set_cancel_requested(true);
        send_response_tx
            .send(())
            .expect("allow server to send response");

        let result = request.join().expect("request thread should join");
        assert!(matches!(result, Err(ClientError::Cancelled)));

        server.join().expect("server thread should join");
        let stats = client.pool_stats();
        assert_eq!(
            stats.idle_connections, 0,
            "late-cancelled responses must not be returned to the idle pool"
        );
    }

    #[test]
    fn request_cancelled_while_parked_on_the_socket_reports_cancelled() {
        use std::io::Write;
        use std::sync::{Arc, mpsc};
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener address");
        let (seen_tx, seen_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let _ = read_http_head(&mut stream);
            seen_tx.send(()).expect("report the request");
            // Answer nothing until the request is cancelled, then make its
            // parked read runnable. The read checks the ambient Cx first.
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
            let _ = stream.write_all(b"H");
            let _ = stream.flush();
        });

        let client = Arc::new(HttpClient::builder().build());
        let cx = Cx::for_testing();
        let request_cx = cx.clone();
        let request_client = Arc::clone(&client);
        let url = format!("http://{addr}/parked");
        let (done_tx, done_rx) = mpsc::channel();
        let request = std::thread::spawn(move || {
            // Socket reads observe the ambient Cx, as inside a runtime task.
            let _ambient = Cx::set_current(Some(request_cx.clone()));
            let _ = done_tx.send(block_on(request_client.send_get(&request_cx, &url)));
        });
        seen_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the request reached the server");
        cx.set_cancel_requested(true);
        let _ = release_tx.send(());
        let result = done_rx.recv_timeout(Duration::from_secs(5));
        server.join().expect("server thread");
        request.join().expect("request thread");
        let result = result.expect("the woken request observes its cancellation");
        assert!(matches!(result, Err(ClientError::Cancelled)), "{result:?}");
    }

    #[test]
    fn safe_method_retries_once_after_stale_pooled_connection_close() {
        use std::io::{Read, Write};
        use std::time::Duration;

        fn read_request_head(stream: &mut std::net::TcpStream) {
            let mut buf = [0_u8; 1024];
            let mut request = Vec::new();
            loop {
                let n = stream.read(&mut buf).expect("read request");
                assert!(n > 0, "request must arrive before peer closes");
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener address");
        let server = std::thread::spawn(move || {
            let (mut first, _) = listener.accept().expect("accept first connection");
            read_request_head(&mut first);
            first
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                )
                .expect("write first response");
            first.flush().expect("flush first response");
            std::thread::sleep(Duration::from_millis(50));
            drop(first);

            let (mut second, _) = listener.accept().expect("accept retry connection");
            read_request_head(&mut second);
            second
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfresh",
                )
                .expect("write retry response");
            second.flush().expect("flush retry response");
        });

        let client = HttpClient::builder()
            .max_connections_per_host(1)
            .max_total_connections(1)
            .build();
        let cx = Cx::for_testing();
        let url = format!("http://{addr}/healthz");

        let first = block_on(client.send_get(&cx, &url)).expect("initial request should succeed");
        assert_eq!(first.status, 200);
        assert_eq!(first.body, b"ok");

        std::thread::sleep(Duration::from_millis(100));

        let second = block_on(client.send_get(&cx, &url)).expect("retry request should succeed");
        assert_eq!(second.status, 200);
        assert_eq!(second.body, b"fresh");

        server.join().expect("server thread should join");
        let stats = client.pool_stats();
        assert!(
            stats.connections_created >= 2,
            "client should establish a fresh connection after stale pooled reuse fails"
        );
    }

    fn read_stale_test_request_head(stream: &mut std::net::TcpStream) {
        use std::io::Read;
        let mut buf = [0_u8; 1024];
        let mut request = Vec::new();
        loop {
            let n = stream.read(&mut buf).expect("read request");
            assert!(n > 0, "request must arrive before peer closes");
            request.extend_from_slice(&buf[..n]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
    }

    // A POST is not retried after a failed reuse, so a pooled connection the
    // server closed while idle (keep-alive timeouts of a few seconds are
    // common) failed every such POST with "connection closed before response
    // headers". An idle connection is now checked before it is reused.
    #[test]
    fn post_after_the_server_closed_the_idle_pooled_connection_uses_a_fresh_one() {
        use std::io::Write;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener address");
        let server = std::thread::spawn(move || {
            let (mut first, _) = listener.accept().expect("accept first connection");
            read_stale_test_request_head(&mut first);
            first
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                )
                .expect("write first response");
            first.flush().expect("flush first response");
            std::thread::sleep(Duration::from_millis(50));
            drop(first);

            let (mut second, _) = listener.accept().expect("accept second connection");
            read_stale_test_request_head(&mut second);
            second
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfresh",
                )
                .expect("write second response");
            second.flush().expect("flush second response");
        });

        let client = HttpClient::builder()
            .max_connections_per_host(1)
            .max_total_connections(1)
            .build();
        let cx = Cx::for_testing();
        let url = format!("http://{addr}/submit");

        let first = block_on(client.send_post(&cx, &url, b"a".to_vec()))
            .expect("first POST should succeed");
        assert_eq!(first.body, b"ok");

        std::thread::sleep(Duration::from_millis(100));

        let second = block_on(client.send_post(&cx, &url, b"b".to_vec()))
            .expect("a POST after the idle connection closed uses a fresh connection");
        assert_eq!(second.status, 200);
        assert_eq!(second.body, b"fresh");

        server.join().expect("server thread should join");
        assert_eq!(client.pool_stats().connections_created, 2);
    }

    // A server may answer an idle keep-alive connection with a 408 before it
    // closes it. Reusing that connection returned the 408 as the response to
    // the next request.
    #[test]
    fn an_unsolicited_408_on_an_idle_pooled_connection_is_not_the_next_response() {
        use std::io::Write;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener address");
        let server = std::thread::spawn(move || {
            let (mut first, _) = listener.accept().expect("accept first connection");
            read_stale_test_request_head(&mut first);
            first
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                )
                .expect("write first response");
            first.flush().expect("flush first response");
            std::thread::sleep(Duration::from_millis(20));
            first
                .write_all(
                    b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .expect("write unsolicited 408");
            first.flush().expect("flush unsolicited 408");

            let (mut second, _) = listener.accept().expect("accept second connection");
            read_stale_test_request_head(&mut second);
            second
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfresh",
                )
                .expect("write second response");
            second.flush().expect("flush second response");
            drop(first);
        });

        let client = HttpClient::builder()
            .max_connections_per_host(1)
            .max_total_connections(1)
            .build();
        let cx = Cx::for_testing();
        let url = format!("http://{addr}/healthz");

        let first = block_on(client.send_get(&cx, &url)).expect("first GET should succeed");
        assert_eq!(first.body, b"ok");

        std::thread::sleep(Duration::from_millis(100));

        let second = block_on(client.send_get(&cx, &url)).expect("second GET should succeed");
        assert_eq!(
            second.status, 200,
            "the idle connection's 408 is not this response"
        );
        assert_eq!(second.body, b"fresh");

        server.join().expect("server thread should join");
        assert_eq!(client.pool_stats().connections_created, 2);
    }

    #[test]
    fn request_connection_close_header_prevents_pool_reuse() {
        use std::io::{Read, Write};
        use std::time::{Duration, Instant};

        fn read_request_head(stream: &mut std::net::TcpStream) -> Vec<u8> {
            let mut buf = [0_u8; 1024];
            let mut request = Vec::new();
            loop {
                let n = stream.read(&mut buf).expect("read request");
                assert!(n > 0, "request must arrive before peer closes");
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            request
        }

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        listener
            .set_nonblocking(true)
            .expect("set nonblocking listener");
        let addr = listener.local_addr().expect("listener address");
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let accept = |listener: &TcpListener| -> std::net::TcpStream {
                loop {
                    match listener.accept() {
                        Ok((stream, _)) => return stream,
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() <= deadline,
                                "timed out waiting for a fresh connection"
                            );
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(err) => panic!("accept failed: {err}"),
                    }
                }
            };

            let mut first = accept(&listener);
            let first_req = read_request_head(&mut first);
            first
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                )
                .expect("write first response");
            first.flush().expect("flush first response");

            let mut second = accept(&listener);
            let second_req = read_request_head(&mut second);
            second
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .expect("write second response");
            second.flush().expect("flush second response");

            (first_req, second_req)
        });

        let client = HttpClient::builder()
            .max_connections_per_host(1)
            .max_total_connections(1)
            .build();
        let cx = Cx::for_testing();
        let url = format!("http://{addr}/close-after-response");

        let headers = vec![("Connection".to_string(), "close".to_string())];
        let first = block_on(client.request(&cx, Method::Get, &url, headers.clone(), Vec::new()))
            .expect("first request should succeed");
        assert_eq!(first.status, 200);

        let second = block_on(client.request(&cx, Method::Get, &url, headers, Vec::new()))
            .expect("second request should succeed");
        assert_eq!(second.status, 200);

        let (first_req, second_req) = server.join().expect("server thread should join");
        let first_text = String::from_utf8(first_req).expect("first request should be utf8");
        let second_text = String::from_utf8(second_req).expect("second request should be utf8");
        assert!(first_text.contains("Connection: close\r\n"));
        assert!(second_text.contains("Connection: close\r\n"));

        let stats = client.pool_stats();
        assert!(
            stats.connections_created >= 2,
            "Connection: close requests must not be satisfied from a reused idle connection"
        );
        assert_eq!(
            stats.idle_connections, 0,
            "Connection: close requests must not leave pooled idle connections behind"
        );
    }

    #[test]
    fn proxy_non_streaming_path_respects_max_body_size() {
        use crate::http::h1::codec::HttpError;
        use std::io::{Read, Write};

        fn read_request_head(stream: &mut std::net::TcpStream) -> Vec<u8> {
            let mut buf = [0_u8; 1024];
            let mut request = Vec::new();
            loop {
                let n = stream.read(&mut buf).expect("read request");
                assert!(n > 0, "request must arrive before peer closes");
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            request
        }

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept proxy request");
            let request = read_request_head(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .expect("write proxy response");
            stream.flush().expect("flush proxy response");
            request
        });

        let client = HttpClient::builder()
            .proxy(format!("http://{addr}"))
            .max_body_size(1)
            .build();
        let cx = Cx::for_testing();
        let err = block_on(client.send_get(&cx, "http://example.com/oversized"))
            .expect_err("response body should exceed configured limit");

        match err {
            ClientError::HttpError(HttpError::BodyTooLargeDetailed { actual, limit }) => {
                assert_eq!(actual, 2);
                assert_eq!(limit, 1);
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let request = server.join().expect("proxy server thread should join");
        let request_text = String::from_utf8(request).expect("proxy request should be utf8");
        assert!(
            request_text.starts_with("GET http://example.com/oversized HTTP/1.1\r\n"),
            "forward-proxy request must use absolute-form and hit the non-streaming proxy path"
        );
    }

    #[test]
    fn configured_https_proxy_connect_includes_default_port() {
        use std::io::{Read, Write};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy listener");
        listener
            .set_nonblocking(true)
            .expect("make proxy listener nonblocking");
        let addr = listener.local_addr().expect("proxy listener address");
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(accepted) => break accepted,
                    Err(err)
                        if err.kind() == std::io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(err) => panic!("accept proxy request: {err}"),
                }
            };
            // Windows inherits the listener's nonblocking mode on the accepted
            // socket. Switch the connected stream back to blocking I/O so the
            // bounded read timeout, rather than an immediate WSAEWOULDBLOCK,
            // governs this small wire-capture server.
            stream
                .set_nonblocking(false)
                .expect("make accepted proxy stream blocking");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("set proxy read timeout");
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                assert!(
                    request.len() < CONNECT_MAX_HEADERS_SIZE,
                    "CONNECT request exceeded the header limit"
                );
                let n = stream.read(&mut buf).expect("read CONNECT request");
                assert!(n > 0, "CONNECT request must arrive before peer closes");
                request.extend_from_slice(&buf[..n]);
            }
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .expect("write proxy refusal");
            stream.flush().expect("flush proxy refusal");
            request
        });

        let client = HttpClient::builder()
            .proxy(format!("http://{addr}"))
            .request_timeout(std::time::Duration::from_secs(5))
            .build();
        let cx = Cx::for_testing();
        let err = block_on(client.send_get(&cx, "https://example.com/path"))
            .expect_err("proxy refusal should stop before TLS");
        assert!(matches!(
            err,
            ClientError::ConnectTunnelRefused { status: 502, .. }
        ));

        let request = server.join().expect("proxy server thread should join");
        let request_text = String::from_utf8(request).expect("CONNECT request should be utf8");
        assert!(
            request_text.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"),
            "configured HTTPS proxy path must preserve the CONNECT port: {request_text:?}"
        );
        assert!(request_text.contains("\r\nHost: example.com:443\r\n"));
    }

    /// br-asupersync-1aqha7: when a hostname's first resolved address never
    /// answers, the client connects through the next one instead of waiting
    /// out the kernel's SYN retries. `localhost` supplies the two addresses,
    /// so the test needs both loopback families. Where `localhost` lacks one,
    /// it says so and returns.
    #[test]
    #[cfg(target_os = "linux")]
    fn hostname_connect_races_past_a_black_holed_first_address() {
        use std::io::{Read, Write};
        use std::net::{SocketAddr, ToSocketAddrs};
        use std::time::{Duration, Instant};

        let resolved: Vec<SocketAddr> = ("localhost", 0)
            .to_socket_addrs()
            .map(Iterator::collect)
            .unwrap_or_default();
        let Some((first, second)) = resolved.first().and_then(|first| {
            resolved
                .iter()
                .find(|addr| addr.is_ipv4() != first.is_ipv4())
                .map(|second| (*first, *second))
        }) else {
            eprintln!("skipping: localhost resolves to {resolved:?}, not both loopback families");
            return;
        };

        // Linux drops SYNs aimed at a listener whose accept queue is full, so
        // after filling a backlog-0 queue, connects to it hang unanswered.
        let blackhole = socket2::Socket::new(
            socket2::Domain::for_address(first),
            socket2::Type::STREAM,
            None,
        )
        .expect("blackhole socket");
        if first.is_ipv6() {
            blackhole.set_only_v6(true).expect("IPv6-only blackhole");
        }
        blackhole
            .bind(&SocketAddr::new(first.ip(), 0).into())
            .expect("bind blackhole");
        blackhole.listen(0).expect("listen with backlog 0");
        let port = blackhole
            .local_addr()
            .ok()
            .and_then(|addr| addr.as_socket())
            .expect("blackhole address")
            .port();
        let black_holed = SocketAddr::new(first.ip(), port);
        let _queued: Vec<_> = (0..4)
            .filter_map(|_| {
                std::net::TcpStream::connect_timeout(&black_holed, Duration::from_millis(100)).ok()
            })
            .collect();
        let probe = std::net::TcpStream::connect_timeout(&black_holed, Duration::from_millis(300));
        assert!(
            matches!(&probe, Err(error) if matches!(error.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock)),
            "the full-backlog listener must drop SYNs, got {probe:?}"
        );

        let listener = TcpListener::bind(SocketAddr::new(second.ip(), port))
            .expect("bind the live listener on the other family");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept the client");
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let n = stream.read(&mut buf).expect("read request");
                assert!(n > 0, "the request head arrives before the client closes");
                request.extend_from_slice(&buf[..n]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .expect("write response");
        });

        let client = HttpClient::builder()
            .request_timeout(Duration::from_secs(5))
            .build();
        let cx = Cx::for_testing();
        let started = Instant::now();
        let result = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime")
            .block_on(client.send_get(&cx, &format!("http://localhost:{port}/race")));
        let elapsed = started.elapsed();
        let response = result.unwrap_or_else(|error| {
            panic!("connect through {second} after black-holed {black_holed}: {error:?} after {elapsed:?}")
        });
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        assert!(
            elapsed < Duration::from_secs(2),
            "the live address wins after one stagger delay, not after {elapsed:?}"
        );
        server.join().expect("server thread should join");
    }

    // --- br-asupersync-server-stack-hardening-eeexl1.1.3: outbound ---
    // --- total deadline from the remaining Cx budget                ---

    mod budget_deadline {
        use super::*;
        use crate::runtime::RuntimeBuilder;
        use crate::trace::TraceBufferHandle;
        use crate::trace::event::{TraceData, TraceEventKind};
        use crate::types::Budget;
        use std::time::Duration;

        fn runtime_block_on<F: std::future::Future>(fut: F) -> F::Output {
            RuntimeBuilder::current_thread()
                .build()
                .expect("build current-thread runtime")
                .block_on(fut)
        }

        fn cx_with_remaining(remaining: Duration) -> Cx {
            let now = crate::time::wall_now();
            let budget = Budget::INFINITE.tightened_by_timeout(now, remaining);
            Cx::for_request_with_budget(budget)
        }

        async fn never_completes() -> Result<u8, ClientError> {
            let now = Cx::with_current(|cx| {
                cx.timer_driver()
                    .map_or_else(crate::time::wall_now, |timer| timer.now())
            })
            .unwrap_or_else(crate::time::wall_now);
            crate::time::sleep(now, Duration::from_secs(600)).await;
            Ok(0)
        }

        #[test]
        fn no_bounds_runs_unbounded() {
            let cx = Cx::for_request_with_budget(Budget::INFINITE);
            let result = runtime_block_on(drive_with_budget_deadline(&cx, None, None, async {
                Ok(7_u8)
            }));
            assert!(matches!(result, Ok(7)));
        }

        #[test]
        fn budget_deadline_bounds_the_exchange() {
            let cx = cx_with_remaining(Duration::from_millis(30));
            let started = std::time::Instant::now();
            let result = runtime_block_on(drive_with_budget_deadline(
                &cx,
                None,
                None,
                never_completes(),
            ));
            assert!(
                matches!(result, Err(ClientError::DeadlineExceeded)),
                "got {result:?}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "budget must bound the exchange"
            );
        }

        /// Security: a per-call override longer than the remaining budget
        /// cannot extend the deadline (meet semantics).
        #[test]
        fn per_call_override_cannot_extend_budget() {
            let cx = cx_with_remaining(Duration::from_millis(30));
            let started = std::time::Instant::now();
            let result = runtime_block_on(drive_with_budget_deadline(
                &cx,
                Some(Duration::from_secs(120)),
                Some(Duration::from_secs(300)),
                never_completes(),
            ));
            assert!(
                matches!(result, Err(ClientError::DeadlineExceeded)),
                "got {result:?}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "override must not extend past the budget"
            );
        }

        #[test]
        fn per_call_override_tightens_unbounded_budget() {
            let cx = Cx::for_request_with_budget(Budget::INFINITE);
            let started = std::time::Instant::now();
            let result = runtime_block_on(drive_with_budget_deadline(
                &cx,
                None,
                Some(Duration::from_millis(30)),
                never_completes(),
            ));
            assert!(
                matches!(result, Err(ClientError::DeadlineExceeded)),
                "got {result:?}"
            );
            assert!(started.elapsed() < Duration::from_secs(60));
        }

        #[test]
        fn expired_budget_fails_fast() {
            let cx = cx_with_remaining(Duration::ZERO);
            let result = runtime_block_on(drive_with_budget_deadline(
                &cx,
                None,
                None,
                never_completes(),
            ));
            assert!(
                matches!(result, Err(ClientError::DeadlineExceeded)),
                "got {result:?}"
            );
        }

        #[test]
        fn forwarded_budget_trace_event_emitted() {
            let cx = cx_with_remaining(Duration::from_secs(30));
            let trace = TraceBufferHandle::new(64);
            cx.set_trace_buffer(trace.clone());
            let result = runtime_block_on(drive_with_budget_deadline(
                &cx,
                Some(Duration::from_secs(10)),
                None,
                async { Ok(1_u8) },
            ));
            assert!(matches!(result, Ok(1)));

            let forwarded: Vec<String> = trace
                .snapshot()
                .iter()
                .filter(|e| e.kind == TraceEventKind::UserTrace)
                .filter_map(|e| match &e.data {
                    TraceData::Message(msg)
                        if msg.starts_with("client.budget_forwarded proto=h1 ") =>
                    {
                        Some(msg.clone())
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(
                forwarded.len(),
                1,
                "expected one forwarded event, got {forwarded:?}"
            );
            assert!(forwarded[0].contains("remaining_ns="));
            assert!(forwarded[0].contains("total_timeout_ns="));
        }

        /// br-asupersync-vxmjgn: connect_tunnel had no deadline, so a proxy
        /// that accepts the connection and never answers the CONNECT held
        /// the call until the Cx was cancelled. Establishing the tunnel is now
        /// bounded by request_timeout.
        #[test]
        fn connect_tunnel_to_a_silent_proxy_ends_at_the_request_timeout() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the proxy");
            let proxy_addr = listener.local_addr().expect("proxy address");
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let client = HttpClient::builder()
                    .request_timeout(Duration::from_millis(200))
                    .build();
                let cx = Cx::for_request_with_budget(Budget::INFINITE);
                let result = runtime_block_on(client.connect_tunnel(
                    &cx,
                    &format!("http://{proxy_addr}"),
                    "example.com:443",
                    Vec::new(),
                ));
                let _ = done_tx.send(result.map(|_| ()));
            });
            // Accept and keep the connection open without ever answering.
            let (_silent, _) = listener.accept().expect("accept the client");
            let result = done_rx
                .recv_timeout(Duration::from_secs(20))
                .expect("connect_tunnel never returned from a silent proxy");
            assert!(
                matches!(result, Err(ClientError::DeadlineExceeded)),
                "got {result:?}"
            );
        }
    }

    // --- opt-in response decompression (HttpClientBuilder::response_decompression) ---

    #[cfg(feature = "compression")]
    mod response_decompression {
        use super::*;
        use crate::http::compress::{
            BrotliCompressor, Compressor, DeflateCompressor, GzipCompressor,
        };
        use std::io::{Read, Write};

        fn encode(mut encoder: impl Compressor, data: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            encoder.compress(data, &mut out).expect("compress");
            encoder.finish(&mut out).expect("finish compression");
            out
        }

        /// Answers one request on a fresh listener with `head` and `body`.
        /// Returns the URL and the server thread, which yields the request
        /// head in lower case.
        fn serve_once(head: String, body: Vec<u8>) -> (String, std::thread::JoinHandle<String>) {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
            let url = format!("http://{}/data", listener.local_addr().expect("address"));
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept");
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .expect("set read timeout");
                let mut request = Vec::new();
                let mut buf = [0_u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let n = stream.read(&mut buf).expect("read request");
                    assert!(n > 0, "the request must arrive");
                    request.extend_from_slice(&buf[..n]);
                }
                stream.write_all(head.as_bytes()).expect("write head");
                stream.write_all(&body).expect("write body");
                String::from_utf8_lossy(&request).to_ascii_lowercase()
            });
            (url, server)
        }

        fn encoded_head(coding: &str, len: usize) -> String {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Encoding: {coding}\r\nContent-Length: {len}\r\n\
                 Connection: close\r\n\r\n"
            )
        }

        fn get(
            client: &HttpClient,
            url: &str,
            headers: Vec<(String, String)>,
        ) -> Result<Response, ClientError> {
            block_on(client.request(&Cx::for_testing(), Method::Get, url, headers, Vec::new()))
        }

        #[test]
        fn the_client_asks_for_and_decodes_gzip_deflate_and_brotli() {
            let plain = b"hello, compressed world ".repeat(100);
            let client = HttpClient::builder().response_decompression(true).build();
            let asked = if cfg!(feature = "zstd") {
                "\r\naccept-encoding: gzip, deflate, br, zstd\r\n"
            } else {
                "\r\naccept-encoding: gzip, deflate, br\r\n"
            };
            for (coding, encoded) in [
                ("gzip", encode(GzipCompressor::new(), &plain)),
                ("deflate", encode(DeflateCompressor::new(), &plain)),
                ("br", encode(BrotliCompressor::new(), &plain)),
            ] {
                let (url, server) = serve_once(encoded_head(coding, encoded.len()), encoded);
                let response = get(&client, &url, Vec::new()).expect("decoded response");
                let request = server.join().expect("server thread");
                assert!(request.contains(asked), "{coding}: {request}");
                assert_eq!(response.body, plain, "{coding}");
                assert!(
                    !has_header(&response.headers, "content-encoding"),
                    "{coding}"
                );
                assert!(!has_header(&response.headers, "content-length"), "{coding}");
            }
        }

        /// With the `zstd` feature the client also asks for zstd, and
        /// decodes a zstd response.
        #[cfg(feature = "zstd")]
        #[test]
        fn the_client_asks_for_and_decodes_zstd() {
            let plain = b"hello, compressed world ".repeat(100);
            let params = asupersync_zstd::EncodeParams::new(asupersync_zstd::Level::Fast);
            let encoded = asupersync_zstd::encode_all(&plain, &params);
            assert!(encoded.len() < plain.len() / 4, "{} bytes", encoded.len());
            let client = HttpClient::builder().response_decompression(true).build();
            let (url, server) = serve_once(encoded_head("zstd", encoded.len()), encoded);
            let response = get(&client, &url, Vec::new()).expect("decoded response");
            let request = server.join().expect("server thread");
            assert!(
                request.contains("\r\naccept-encoding: gzip, deflate, br, zstd\r\n"),
                "{request}"
            );
            assert_eq!(response.body, plain);
            assert!(!has_header(&response.headers, "content-encoding"));
            assert!(!has_header(&response.headers, "content-length"));
        }

        #[test]
        fn a_caller_chosen_accept_encoding_gets_the_body_as_sent() {
            let encoded = encode(GzipCompressor::new(), &b"keep me encoded ".repeat(50));
            let client = HttpClient::builder().response_decompression(true).build();
            let (url, server) = serve_once(encoded_head("gzip", encoded.len()), encoded.clone());
            let headers = vec![("Accept-Encoding".to_owned(), "gzip".to_owned())];
            let response = get(&client, &url, headers).expect("response");
            let request = server.join().expect("server thread");
            assert!(
                request.contains("\r\naccept-encoding: gzip\r\n"),
                "{request}"
            );
            assert_eq!(response.body, encoded);
            assert!(has_header(&response.headers, "content-encoding"));
        }

        #[test]
        fn a_client_without_the_option_does_not_ask_for_compression() {
            let head = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n";
            let (url, server) = serve_once(head.to_owned(), b"ok".to_vec());
            let response = get(&HttpClient::new(), &url, Vec::new()).expect("response");
            let request = server.join().expect("server thread");
            assert!(!request.contains("accept-encoding"), "{request}");
            assert_eq!(response.body, b"ok");
        }

        #[test]
        fn a_body_that_decodes_past_the_limit_fails_the_request() {
            let encoded = encode(GzipCompressor::new(), &[0_u8; 64 * 1024]);
            assert!(encoded.len() < 1024, "the encoded body fits the limit");
            let client = HttpClient::builder()
                .response_decompression(true)
                .max_body_size(1024)
                .build();
            let (url, server) = serve_once(encoded_head("gzip", encoded.len()), encoded);
            let err = get(&client, &url, Vec::new()).expect_err("64 KiB decoded > 1 KiB limit");
            server.join().expect("server thread");
            assert!(
                matches!(
                    err,
                    ClientError::HttpError(crate::http::h1::codec::HttpError::Io(_))
                ),
                "{err:?}"
            );
        }

        #[test]
        fn a_range_request_does_not_ask_for_compression() {
            let encoded = encode(GzipCompressor::new(), &b"a slice ".repeat(50));
            let client = HttpClient::builder().response_decompression(true).build();
            let (url, server) = serve_once(encoded_head("gzip", encoded.len()), encoded.clone());
            let headers = vec![("Range".to_owned(), "bytes=0-".to_owned())];
            let response = get(&client, &url, headers).expect("response");
            let request = server.join().expect("server thread");
            assert!(!request.contains("accept-encoding"), "{request}");
            assert_eq!(response.body, encoded, "returned as received");
        }

        #[test]
        fn stacked_codings_decode_in_reverse_order() {
            let plain = b"layered ".repeat(40);
            let client = HttpClient::builder().response_decompression(true).build();
            let gzip_then_br = encode(
                BrotliCompressor::new(),
                &encode(GzipCompressor::new(), &plain),
            );
            let (url, server) =
                serve_once(encoded_head("gzip, br", gzip_then_br.len()), gzip_then_br);
            let response = get(&client, &url, Vec::new()).expect("two codings decode");
            server.join().expect("server thread");
            assert_eq!(response.body, plain);
        }
    }
