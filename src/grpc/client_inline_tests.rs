    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send,
        unused_must_use
    )]
    use super::*;
    use crate::codec::Encoder;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    struct CountWaker(Arc<AtomicUsize>);

    impl Wake for CountWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counting_waker(counter: &Arc<AtomicUsize>) -> Waker {
        Waker::from(Arc::new(CountWaker(Arc::clone(counter))))
    }

    fn poll_stream<T: Send>(
        stream: &mut ResponseStream<T>,
        waker: &Waker,
    ) -> Poll<Option<Result<T, Status>>> {
        let mut cx = Context::from_waker(waker);
        Streaming::poll_next(Pin::new(stream), &mut cx)
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_channel_builder() {
        init_test("test_channel_builder");
        let builder = Channel::builder("http://loopback:50051")
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .max_recv_message_size(8 * 1024 * 1024);

        crate::assert_with_log!(
            builder.config.connect_timeout == Duration::from_secs(10),
            "connect_timeout",
            Duration::from_secs(10),
            builder.config.connect_timeout
        );
        crate::assert_with_log!(
            builder.config.timeout == Some(Duration::from_secs(30)),
            "timeout",
            Some(Duration::from_secs(30)),
            builder.config.timeout
        );
        crate::assert_with_log!(
            builder.config.max_recv_message_size == 8 * 1024 * 1024,
            "max_recv_message_size",
            8 * 1024 * 1024,
            builder.config.max_recv_message_size
        );
        crate::test_complete!("test_channel_builder");
    }

    #[test]
    fn test_channel_config_default() {
        init_test("test_channel_config_default");
        let config = ChannelConfig::default();
        crate::assert_with_log!(
            config.connect_timeout == Duration::from_secs(5),
            "connect_timeout",
            Duration::from_secs(5),
            config.connect_timeout
        );
        let timeout_none = config.timeout.is_none();
        crate::assert_with_log!(timeout_none, "timeout none", true, timeout_none);
        crate::assert_with_log!(!config.use_tls, "use_tls", false, config.use_tls);
        crate::assert_with_log!(
            config.send_compression.is_none(),
            "send compression default",
            true,
            config.send_compression.is_none()
        );
        crate::assert_with_log!(
            config.accept_compression == vec![CompressionEncoding::Identity],
            "accept compression default",
            vec![CompressionEncoding::Identity],
            config.accept_compression
        );
        crate::test_complete!("test_channel_config_default");
    }

    #[test]
    fn test_metadata_interceptor() {
        init_test("test_metadata_interceptor");
        let interceptor = MetadataInterceptor::new()
            .with_metadata("x-custom-header", "value")
            .with_metadata("x-another", "value2");

        let mut request = Request::new(Bytes::new());
        interceptor.intercept(&mut request).unwrap();

        let has_custom = request.metadata().get("x-custom-header").is_some();
        crate::assert_with_log!(has_custom, "custom header", true, has_custom);
        let has_another = request.metadata().get("x-another").is_some();
        crate::assert_with_log!(has_another, "another header", true, has_another);
        crate::test_complete!("test_metadata_interceptor");
    }

    // Pure data-type tests (wave 14 – CyanBarn)

    #[test]
    fn channel_config_debug_clone() {
        let cfg = ChannelConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("ChannelConfig"));

        let cloned = cfg;
        assert_eq!(cloned.connect_timeout, Duration::from_secs(5));
    }

    #[test]
    fn channel_config_default_values() {
        let cfg = ChannelConfig::default();
        assert_eq!(cfg.connect_timeout, Duration::from_secs(5));
        assert!(cfg.timeout.is_none());
        assert_eq!(cfg.max_recv_message_size, 4 * 1024 * 1024);
        assert_eq!(cfg.max_send_message_size, 4 * 1024 * 1024);
        assert_eq!(cfg.initial_connection_window_size, 1024 * 1024);
        assert_eq!(cfg.initial_stream_window_size, 1024 * 1024);
        assert!(cfg.keepalive_interval.is_none());
        assert!(cfg.keepalive_timeout.is_none());
        assert!(!cfg.use_tls);
        assert!(cfg.send_compression.is_none());
        assert_eq!(cfg.accept_compression, vec![CompressionEncoding::Identity]);
    }

    #[test]
    fn channel_builder_debug() {
        let builder = Channel::builder("http://loopback:50051");
        let dbg = format!("{builder:?}");
        assert!(dbg.contains("ChannelBuilder"));
        assert!(dbg.contains("loopback"));
    }

    #[test]
    fn channel_builder_all_setters() {
        let builder = Channel::builder("http://host:443")
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(60))
            .max_recv_message_size(1024)
            .max_send_message_size(2048)
            .initial_connection_window_size(512)
            .initial_stream_window_size(256)
            .keepalive_interval(Duration::from_secs(10))
            .keepalive_timeout(Duration::from_secs(5))
            .send_compression(CompressionEncoding::Gzip)
            .accept_compressions([CompressionEncoding::Identity, CompressionEncoding::Gzip])
            .tls();

        assert_eq!(builder.config.connect_timeout, Duration::from_secs(30));
        assert_eq!(builder.config.timeout, Some(Duration::from_secs(60)));
        assert_eq!(builder.config.max_recv_message_size, 1024);
        assert_eq!(builder.config.max_send_message_size, 2048);
        assert_eq!(builder.config.initial_connection_window_size, 512);
        assert_eq!(builder.config.initial_stream_window_size, 256);
        assert_eq!(
            builder.config.keepalive_interval,
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            builder.config.keepalive_timeout,
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            builder.config.send_compression,
            Some(CompressionEncoding::Gzip)
        );
        assert_eq!(
            builder.config.accept_compression,
            vec![CompressionEncoding::Identity, CompressionEncoding::Gzip]
        );
        assert!(builder.config.use_tls);
    }

    fn make_channel(uri: &str) -> Channel {
        futures_lite::future::block_on(Channel::connect(uri)).unwrap()
    }

    #[test]
    fn channel_debug_clone() {
        let channel = make_channel("http://loopback:8080");
        let dbg = format!("{channel:?}");
        assert!(dbg.contains("Channel"));

        let cloned = channel;
        assert_eq!(cloned.uri(), "http://loopback:8080");
    }

    #[test]
    fn channel_uri_accessor() {
        let channel = make_channel("http://loopback:9090");
        assert_eq!(channel.uri(), "http://loopback:9090");
        assert_eq!(channel.config().connect_timeout, Duration::from_secs(5));
    }

    #[test]
    fn grpc_client_debug() {
        let channel = make_channel("http://loopback:50051");
        let client = GrpcClient::new(channel);
        let dbg = format!("{client:?}");
        assert!(dbg.contains("GrpcClient"));
    }

    #[test]
    fn grpc_client_channel_accessor() {
        let channel = make_channel("http://loopback:80");
        let client = GrpcClient::new(channel);
        assert_eq!(client.channel().uri(), "http://loopback:80");
    }

    #[test]
    fn grpc_client_applies_deadline_metadata_by_default() {
        let channel = futures_lite::future::block_on(
            Channel::builder("http://loopback:80")
                .timeout(Duration::from_secs(2))
                .connect(),
        )
        .expect("channel");
        let mut client = GrpcClient::new(channel);
        let response: Response<String> = futures_lite::future::block_on(
            client.unary("/pkg.Service/Method", Request::new("hello".to_owned())),
        )
        .expect("unary");

        match response.metadata().get("grpc-timeout") {
            Some(super::super::streaming::MetadataValue::Ascii(value)) => {
                assert_eq!(value, "2S");
            }
            other => panic!("expected grpc-timeout metadata, got: {other:?}"),
        }
    }

    #[test]
    fn grpc_client_repairs_malformed_timeout_before_building_outbound_metadata() {
        let channel = futures_lite::future::block_on(
            Channel::builder("http://loopback:80")
                .timeout(Duration::from_secs(2))
                .connect(),
        )
        .expect("channel");
        let client = GrpcClient::new(channel);
        let mut request = Request::new(Bytes::new());
        request.metadata_mut().insert("grpc-timeout", "bogus");

        let metadata = client
            .build_outbound_metadata(&request, "/pkg.Service/Method")
            .expect("metadata");

        match metadata.get("grpc-timeout") {
            Some(super::super::streaming::MetadataValue::Ascii(value)) => {
                assert_eq!(value, "2S");
            }
            other => panic!("expected repaired grpc-timeout metadata, got: {other:?}"),
        }

        let timeout_count = metadata
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("grpc-timeout"))
            .count();
        assert_eq!(timeout_count, 1);
    }

    /// br-asupersync-20occs: when channel.config.timeout is None AND the
    /// request metadata carries a malformed grpc-timeout, the malformed
    /// entry must be SCRUBBED before send. Previously the value rode
    /// through to the wire because the existing-state classification only
    /// distinguished parseable-or-fall-back-to-default, and with no
    /// default to insert, the malformed entry was left untouched.
    #[test]
    fn occs20_malformed_grpc_timeout_scrubbed_when_channel_timeout_is_none() {
        let channel = futures_lite::future::block_on(
            // No .timeout(...) — channel.config.timeout is None.
            Channel::builder("http://loopback:80").connect(),
        )
        .expect("channel");
        let client = GrpcClient::new(channel);
        let mut request = Request::new(Bytes::new());
        request.metadata_mut().insert("grpc-timeout", "bogus");

        let metadata = client
            .build_outbound_metadata(&request, "/pkg.Service/Method")
            .expect("metadata");

        // Malformed entry MUST be scrubbed; with no channel default and no
        // valid request value, no grpc-timeout entry should remain.
        assert!(
            metadata.get("grpc-timeout").is_none(),
            "malformed grpc-timeout must be scrubbed when channel timeout is None, got: {:?}",
            metadata.get("grpc-timeout")
        );
        let timeout_count = metadata
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("grpc-timeout"))
            .count();
        assert_eq!(
            timeout_count, 0,
            "no grpc-timeout entries should remain after scrub"
        );
    }

    /// br-asupersync-20occs: positive control — well-formed grpc-timeout
    /// passes through unchanged regardless of channel default.
    #[test]
    fn occs20_well_formed_grpc_timeout_passes_through_with_no_channel_default() {
        let channel =
            futures_lite::future::block_on(Channel::builder("http://loopback:80").connect())
                .expect("channel");
        let client = GrpcClient::new(channel);
        let mut request = Request::new(Bytes::new());
        request.metadata_mut().insert("grpc-timeout", "100m");

        let metadata = client
            .build_outbound_metadata(&request, "/pkg.Service/Method")
            .expect("metadata");

        match metadata.get("grpc-timeout") {
            Some(super::super::streaming::MetadataValue::Ascii(value)) => {
                assert_eq!(value, "100m");
            }
            other => panic!("expected preserved grpc-timeout, got: {other:?}"),
        }
    }

    #[test]
    fn grpc_client_interceptors_and_compression_metadata_are_applied() {
        use crate::grpc::timeout_interceptor;

        let channel = futures_lite::future::block_on(
            Channel::builder("http://loopback:80")
                .send_compression(CompressionEncoding::Gzip)
                .accept_compressions([CompressionEncoding::Identity, CompressionEncoding::Gzip])
                .connect(),
        )
        .expect("channel");

        let mut client = GrpcClient::new(channel)
            .with_interceptor(timeout_interceptor(777))
            .with_interceptor(MetadataInterceptor::new().with_metadata("x-client-id", "cobalt"));

        let response: Response<String> = futures_lite::future::block_on(
            client.unary("/pkg.Service/Method", Request::new("hello".to_owned())),
        )
        .expect("unary");

        let metadata = response.metadata();
        match metadata.get("grpc-timeout") {
            Some(super::super::streaming::MetadataValue::Ascii(value)) => {
                assert_eq!(value, "777m");
            }
            other => panic!("expected interceptor timeout metadata, got: {other:?}"),
        }
        match metadata.get("grpc-encoding") {
            #[cfg(feature = "compression")]
            Some(super::super::streaming::MetadataValue::Ascii(value)) => {
                assert_eq!(value, "gzip");
            }
            #[cfg(not(feature = "compression"))]
            None => {}
            other => panic!("unexpected grpc-encoding metadata: {other:?}"),
        }
        match metadata.get("grpc-accept-encoding") {
            #[cfg(feature = "compression")]
            Some(super::super::streaming::MetadataValue::Ascii(value)) => {
                assert_eq!(value, "identity,gzip");
            }
            #[cfg(not(feature = "compression"))]
            Some(super::super::streaming::MetadataValue::Ascii(value)) => {
                assert_eq!(value, "identity");
            }
            other => panic!("unexpected grpc-accept-encoding metadata: {other:?}"),
        }
        match metadata.get("x-client-id") {
            Some(super::super::streaming::MetadataValue::Ascii(value)) => {
                assert_eq!(value, "cobalt");
            }
            other => panic!("expected interceptor metadata, got: {other:?}"),
        }
    }

    #[test]
    fn grpc_client_identity_send_compression_keeps_uncompressed_frames() {
        let channel = futures_lite::future::block_on(
            Channel::builder("http://loopback:80")
                .send_compression(CompressionEncoding::Identity)
                .connect(),
        )
        .expect("channel");

        let mut client = GrpcClient::new(channel);
        let mut framed = crate::bytes::BytesMut::new();
        client
            .codec
            .encode_message(&Bytes::from_static(b"hello"), &mut framed)
            .expect("identity framing must encode");

        assert_eq!(
            framed[0], 0,
            "identity send compression must not set compressed flag"
        );
        let buf = framed
            .split_off(crate::grpc::codec::MESSAGE_HEADER_SIZE)
            .freeze();
        assert_eq!(buf.as_ref(), b"hello");
    }

    #[test]
    #[cfg(not(feature = "compression"))]
    fn grpc_client_unsupported_gzip_send_compression_stays_uncompressed() {
        let channel = futures_lite::future::block_on(
            Channel::builder("http://loopback:80")
                .send_compression(CompressionEncoding::Gzip)
                .accept_compression(CompressionEncoding::Gzip)
                .connect(),
        )
        .expect("channel");

        let mut client = GrpcClient::new(channel);
        let mut framed = crate::bytes::BytesMut::new();
        client
            .codec
            .encode_message(&Bytes::from_static(b"hello"), &mut framed)
            .expect("unsupported gzip must fall back to uncompressed framing");

        assert_eq!(
            framed[0], 0,
            "unsupported gzip config must not set compressed flag"
        );
    }

    #[test]
    #[cfg(feature = "compression")]
    fn grpc_client_gzip_send_compression_uses_gzip_frames() {
        let channel = futures_lite::future::block_on(
            Channel::builder("http://loopback:80")
                .send_compression(CompressionEncoding::Gzip)
                .accept_compression(CompressionEncoding::Gzip)
                .connect(),
        )
        .expect("channel");

        let mut client = GrpcClient::new(channel);
        let mut framed = crate::bytes::BytesMut::new();
        client
            .codec
            .encode_message(&Bytes::from_static(b"hello gzip"), &mut framed)
            .expect("gzip framing must encode");

        assert_eq!(
            framed[0], 1,
            "gzip send compression must set compressed flag"
        );
        assert_eq!(
            &framed[crate::grpc::codec::MESSAGE_HEADER_SIZE
                ..crate::grpc::codec::MESSAGE_HEADER_SIZE + 2],
            &[0x1f, 0x8b]
        );
    }

    #[test]
    fn grpc_client_codec_applies_channel_message_limits() {
        let channel = futures_lite::future::block_on(
            Channel::builder("http://loopback:80")
                .max_send_message_size(3)
                .max_recv_message_size(5)
                .connect(),
        )
        .expect("channel");

        let mut client = GrpcClient::new(channel);

        let encode_err = client
            .codec
            .encode_message(
                &Bytes::from_static(b"abcd"),
                &mut crate::bytes::BytesMut::new(),
            )
            .expect_err("send limit should be applied to the live client codec");
        assert!(matches!(encode_err, GrpcError::MessageTooLarge));

        let mut encoded = crate::bytes::BytesMut::new();
        let mut framing = crate::grpc::codec::GrpcCodec::new();
        framing
            .encode(
                crate::grpc::codec::GrpcMessage::new(Bytes::from_static(b"123456")),
                &mut encoded,
            )
            .expect("producer encode must succeed");

        let decode_err = client
            .codec
            .decode_message(&mut encoded)
            .expect_err("recv limit should be applied to the live client codec");
        assert!(matches!(decode_err, GrpcError::MessageTooLarge));
    }

    #[test]
    fn encode_grpc_timeout_prefers_largest_unit_with_eight_digit_limit() {
        assert_eq!(encode_grpc_timeout(Duration::from_secs(2)), "2S");
        assert_eq!(encode_grpc_timeout(Duration::from_millis(1)), "1m");
        assert_eq!(encode_grpc_timeout(Duration::from_nanos(1)), "1n");
        assert_eq!(encode_grpc_timeout(Duration::from_micros(1500)), "1500u");
    }

    /// The unary timer used `config.timeout.unwrap_or(connect_timeout)`, so
    /// a call with no deadline was cut off at 5 s and a longer per-request
    /// `grpc-timeout` at the channel's. It now follows the wire header.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn native_unary_deadline_is_the_wire_grpc_timeout() {
        assert_eq!(effective_native_call_timeout(&Metadata::new()), None);
        let mut metadata = Metadata::new();
        assert!(metadata.insert("grpc-timeout", "30S"));
        assert_eq!(
            effective_native_call_timeout(&metadata),
            Some(Duration::from_secs(30))
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn unary_headers(pairs: &[(&str, &str)], end_stream: bool) -> ReceivedFrame {
        ReceivedFrame::Headers {
            stream_id: 1,
            headers: pairs
                .iter()
                .map(|(name, value)| Header::new(*name, *value))
                .collect(),
            end_stream,
        }
    }

    /// A response that ends without grpc-status (a proxy's 404 or 503) was
    /// never complete, so the call hung until its deadline.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn native_unary_response_without_grpc_status_completes_with_the_http_mapping() {
        for (http, code) in [
            ("404", Code::Unimplemented),
            ("503", Code::Unavailable),
            ("401", Code::Unauthenticated),
        ] {
            let mut accumulator = NativeUnaryAccumulator::new(1024);
            accumulator
                .observe(1, unary_headers(&[(":status", http)], true))
                .expect("headers");
            assert!(accumulator.is_complete(), "END_STREAM ends the call");
            let status = accumulator.finish().expect_err("not a gRPC response");
            assert_eq!(status.code(), code, "HTTP {http}");
        }

        // A trailers-only grpc-status on a non-200 response wins.
        let mut accumulator = NativeUnaryAccumulator::new(1024);
        accumulator
            .observe(
                1,
                unary_headers(
                    &[
                        (":status", "503"),
                        ("content-type", "application/grpc"),
                        ("grpc-status", "8"),
                    ],
                    true,
                ),
            )
            .expect("headers");
        let status = accumulator.finish().expect_err("grpc-status 8");
        assert_eq!(status.code(), Code::ResourceExhausted);
    }

    #[test]
    fn validate_rpc_path_rejects_empty_or_extra_segments() {
        for path in ["/test.Svc/", "//Method", "/test.Svc/Method/Extra"] {
            let status = validate_rpc_path(path).expect_err("path should be rejected");
            assert_eq!(status.code(), crate::grpc::Code::InvalidArgument);
        }
        assert!(validate_rpc_path("/test.Svc/Method").is_ok());
    }

    #[test]
    fn metadata_interceptor_debug() {
        let interceptor = MetadataInterceptor::new();
        let dbg = format!("{interceptor:?}");
        assert!(dbg.contains("MetadataInterceptor"));
    }

    #[test]
    fn metadata_interceptor_empty() {
        let interceptor = MetadataInterceptor::new();
        let mut request = Request::new(Bytes::new());
        interceptor.intercept(&mut request).unwrap();
        // No headers added - request should still have empty metadata
        assert!(request.metadata().get("nonexistent").is_none());
    }

    // Pure data-type tests (wave 34 – CyanBarn)

    #[test]
    fn response_stream_debug() {
        let stream = ResponseStream::<u8>::new();
        let dbg = format!("{stream:?}");
        assert!(dbg.contains("ResponseStream"));
    }

    #[test]
    fn response_stream_default() {
        let stream = ResponseStream::<i32>::default();
        let dbg = format!("{stream:?}");
        assert!(dbg.contains("ResponseStream"));
    }

    #[test]
    fn response_stream_supports_non_unpin_messages() {
        use std::marker::PhantomPinned;

        struct NonUnpin {
            _pin: PhantomPinned,
        }

        let mut stream = ResponseStream::open();
        stream
            .push(Ok(NonUnpin {
                _pin: PhantomPinned,
            }))
            .unwrap();
        stream.close();

        let first = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        assert!(first.is_some());

        let second = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        assert!(second.is_none());
    }

    #[test]
    fn response_stream_push_rejects_when_buffer_full_and_recovers_after_drain() {
        init_test("response_stream_push_rejects_when_buffer_full_and_recovers_after_drain");
        let mut stream = ResponseStream::<u32>::open();
        for i in 0..MAX_STREAM_BUFFERED as u32 {
            stream.push(Ok(i)).expect("push before saturation succeeds");
        }

        let err = stream
            .push(Ok(MAX_STREAM_BUFFERED as u32))
            .expect_err("push past cap must fail");
        assert_eq!(err.code(), crate::grpc::Code::ResourceExhausted);

        let first = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        assert!(matches!(first, Some(Ok(0))));

        stream
            .push(Ok(MAX_STREAM_BUFFERED as u32))
            .expect("push should succeed after draining one slot");
    }

    #[test]
    fn response_stream_clones_keep_all_pending_readers_wakeable() {
        let mut stream = ResponseStream::<u32>::open();
        let mut first_reader = stream.clone();
        let mut second_reader = stream.clone();
        let first_wake_count = Arc::new(AtomicUsize::new(0));
        let second_wake_count = Arc::new(AtomicUsize::new(0));
        let first_reader_waker = counting_waker(&first_wake_count);
        let second_reader_waker = counting_waker(&second_wake_count);

        assert!(poll_stream(&mut first_reader, &first_reader_waker).is_pending());
        assert!(poll_stream(&mut second_reader, &second_reader_waker).is_pending());

        stream
            .push(Ok(7))
            .expect("push should wake pending readers");
        assert_eq!(
            first_wake_count.load(Ordering::SeqCst),
            1,
            "first cloned reader lost its wakeup",
        );
        assert_eq!(
            second_wake_count.load(Ordering::SeqCst),
            1,
            "second cloned reader should also be notified",
        );

        assert!(matches!(
            poll_stream(&mut first_reader, &first_reader_waker),
            Poll::Ready(Some(Ok(7)))
        ));
        assert!(poll_stream(&mut second_reader, &second_reader_waker).is_pending());

        stream.close();
        assert_eq!(
            second_wake_count.load(Ordering::SeqCst),
            2,
            "close should wake the still-pending cloned reader",
        );
        assert!(matches!(
            poll_stream(&mut second_reader, &second_reader_waker),
            Poll::Ready(None)
        ));
    }

    /// What a native call fed by a test has received: its messages, its end,
    /// and the waker of its last pending poll, as a transport keeps it.
    #[cfg(not(target_arch = "wasm32"))]
    #[derive(Default)]
    struct Feed {
        messages: VecDeque<u32>,
        ended: bool,
        waker: Option<Waker>,
    }

    #[cfg(not(target_arch = "wasm32"))]
    struct FedCall(Arc<Mutex<Feed>>);

    #[cfg(not(target_arch = "wasm32"))]
    impl FedCall {
        /// Queue a message, or the end, and wake the call as arriving data does.
        fn deliver(feed: &Mutex<Feed>, message: Option<u32>) {
            let waker = {
                let mut feed = lock_unpoisoned(feed);
                match message {
                    Some(message) => feed.messages.push_back(message),
                    None => feed.ended = true,
                }
                feed.waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl legacy_native::LegacyCall for FedCall {
        fn poll_event(
            &mut self,
            task: &mut Context<'_>,
        ) -> Poll<Option<Result<legacy_native::LegacyEvent, Status>>> {
            let mut feed = lock_unpoisoned(&self.0);
            if let Some(message) = feed.messages.pop_front() {
                let message = legacy_native::LegacyEvent::Message(Box::new(message));
                return Poll::Ready(Some(Ok(message)));
            }
            if feed.ended {
                return Poll::Ready(None);
            }
            feed.waker = Some(task.waker().clone());
            Poll::Pending
        }

        fn queue_message(&mut self, _message: Box<dyn Any + Send>) -> Result<(), Status> {
            Ok(())
        }

        fn close_requests(&mut self) -> Result<(), Status> {
            Ok(())
        }

        fn initial_metadata(&self) -> Option<Metadata> {
            None
        }

        fn trailers(&self) -> Option<Metadata> {
            None
        }

        // Recorded at the end, as both native owners do.
        fn status(&self) -> Option<Status> {
            lock_unpoisoned(&self.0).ended.then(Status::ok)
        }

        fn cancel(&mut self) {}

        // No deadline or cancellation of its own.
        fn poll_gate(&mut self, _task: &mut Context<'_>) -> Result<(), Status> {
            Ok(())
        }

        // Server streaming: no sink waits on the window or sends.
        fn message_bytes(&self) -> usize {
            0
        }

        fn window_bytes(&self) -> usize {
            usize::MAX
        }

        fn request_ready(&self) -> bool {
            true
        }
    }

    /// A bidi call as the native duplex owner runs it, stepped by a test: the
    /// send boundaries it will report, the responses it read, and the
    /// server's end once read. Like the owner, it refuses a message or the
    /// half-close from the moment it holds the end, before it reports it.
    #[cfg(not(target_arch = "wasm32"))]
    #[derive(Default)]
    struct Duplex {
        flushes: usize,
        request_pending: bool,
        messages: VecDeque<u32>,
        end: Option<Status>,
        status: Option<Status>,
        /// Unread response bytes a sink may hold (each message is 4).
        window: usize,
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl Duplex {
        fn admits(&self) -> bool {
            !self.request_pending && self.end.is_none() && self.status.is_none()
        }

        fn admit(&mut self) -> Result<(), Status> {
            if !self.admits() {
                return Err(Status::failed_precondition(
                    "native gRPC request slot is unavailable",
                ));
            }
            self.request_pending = true;
            Ok(())
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    struct DuplexCall(Arc<Mutex<Duplex>>);

    #[cfg(not(target_arch = "wasm32"))]
    impl legacy_native::LegacyCall for DuplexCall {
        fn poll_event(
            &mut self,
            _task: &mut Context<'_>,
        ) -> Poll<Option<Result<legacy_native::LegacyEvent, Status>>> {
            let mut call = lock_unpoisoned(&self.0);
            if call.status.is_some() {
                return Poll::Ready(None);
            }
            if call.flushes > 0 {
                call.flushes -= 1;
                call.request_pending = false;
                return Poll::Ready(Some(Ok(legacy_native::LegacyEvent::RequestFlushed)));
            }
            if let Some(message) = call.messages.pop_front() {
                let message = legacy_native::LegacyEvent::Message(Box::new(message));
                return Poll::Ready(Some(Ok(message)));
            }
            if let Some(status) = call.end.take() {
                call.status = Some(status.clone());
                return Poll::Ready((status.code() != Code::Ok).then_some(Err(status)));
            }
            Poll::Pending
        }

        fn queue_message(&mut self, _message: Box<dyn Any + Send>) -> Result<(), Status> {
            lock_unpoisoned(&self.0).admit()
        }

        fn close_requests(&mut self) -> Result<(), Status> {
            lock_unpoisoned(&self.0).admit()
        }

        fn initial_metadata(&self) -> Option<Metadata> {
            None
        }

        fn trailers(&self) -> Option<Metadata> {
            None
        }

        fn status(&self) -> Option<Status> {
            lock_unpoisoned(&self.0).status.clone()
        }

        fn cancel(&mut self) {}

        fn poll_gate(&mut self, _task: &mut Context<'_>) -> Result<(), Status> {
            Ok(())
        }

        fn message_bytes(&self) -> usize {
            4
        }

        fn window_bytes(&self) -> usize {
            lock_unpoisoned(&self.0).window
        }

        fn request_ready(&self) -> bool {
            lock_unpoisoned(&self.0).admits()
        }
    }

    /// br-asupersync-46olky L5: a response handle read the server's last
    /// response and its end in one read, so the owner held the end without
    /// having reported it. The sink's slot was free from an earlier send
    /// boundary, so it queued at once, and the owner's refusal ("request slot
    /// is unavailable") became the result of send and close instead of the
    /// server's status. The sink now drives the call to that end, past a full
    /// response window too: once the server ended, nothing is left to hold back.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn a_sink_answers_with_the_end_a_response_read_left_unreported() {
        init_test("a_sink_answers_with_the_end_a_response_read_left_unreported");
        let denied = Status::permission_denied("not yours");
        // The server's end, the sink's window, and whether a response handle
        // reads before the sink is used again.
        for (end, window, read_first) in [
            (denied.clone(), usize::MAX, true),
            (Status::ok(), usize::MAX, true),
            (denied, 4, false),
        ] {
            let duplex = Arc::new(Mutex::new(Duplex {
                // The request headers' send boundary.
                flushes: 1,
                request_pending: true,
                window,
                ..Duplex::default()
            }));
            let call =
                LegacyNativeCall::new(Box::new(DuplexCall(Arc::clone(&duplex))), LegacyShape::Bidi);
            let mut sink = RequestSink::<u32>::native(Arc::clone(&call));
            let mut responses = ResponseStream::<u32>::native(call);
            let mut task = Context::from_waker(Waker::noop());
            assert!(matches!(
                std::pin::pin!(sink.send(1)).poll(&mut task),
                Poll::Ready(Ok(()))
            ));

            // One read: the first message's send boundary, two responses and
            // the end.
            {
                let mut duplex = lock_unpoisoned(&duplex);
                duplex.flushes = 1;
                duplex.messages.extend([7, 8]);
                duplex.end = Some(end.clone());
            }
            let mut expected = vec![7, 8];
            if read_first {
                // A response handle takes the first response; the end stays
                // read but unreported.
                assert!(matches!(
                    poll_stream(&mut responses, Waker::noop()),
                    Poll::Ready(Some(Ok(7)))
                ));
                assert!(lock_unpoisoned(&duplex).status.is_none());
                expected.remove(0);
            }

            if end.code() == Code::Ok {
                // The server finished first: the half-close has nothing to do.
                let closed = std::pin::pin!(sink.close()).poll(&mut task);
                assert!(matches!(closed, Poll::Ready(Ok(()))), "{closed:?}");
            } else {
                match std::pin::pin!(sink.send(2)).poll(&mut task) {
                    Poll::Ready(Err(status)) => {
                        assert_eq!(status.code(), Code::PermissionDenied, "{status:?}");
                    }
                    other => panic!("send after the end (window {window}): {other:?}"),
                }
            }
            for message in expected {
                assert!(matches!(
                    poll_stream(&mut responses, Waker::noop()),
                    Poll::Ready(Some(Ok(m))) if m == message
                ));
            }
            match poll_stream(&mut responses, Waker::noop()) {
                Poll::Ready(None) => assert_eq!(end.code(), Code::Ok),
                Poll::Ready(Some(Err(status))) => {
                    assert_eq!(status.code(), end.code(), "{status:?}");
                }
                other => panic!("the response stream ends with the server's status: {other:?}"),
            }
        }
        crate::test_complete!("a_sink_answers_with_the_end_a_response_read_left_unreported");
    }

    /// Clones of a network call's response stream polled from two tasks
    /// (asupersync-mu5yhv finding 3): the call kept one waker for its whole
    /// response side, so the clone that parked first was never woken again,
    /// not even by the end of the call, and its `next()` hung.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn native_response_stream_clones_parked_in_two_tasks_are_each_woken() {
        init_test("native_response_stream_clones_parked_in_two_tasks_are_each_woken");
        let feed = Arc::new(Mutex::new(Feed::default()));
        let call = LegacyNativeCall::new(
            Box::new(FedCall(Arc::clone(&feed))),
            LegacyShape::ServerStreaming,
        );
        let mut first_reader = ResponseStream::<u32>::native(call);
        let mut second_reader = first_reader.clone();
        let first_wake_count = Arc::new(AtomicUsize::new(0));
        let second_wake_count = Arc::new(AtomicUsize::new(0));
        let first_reader_waker = counting_waker(&first_wake_count);
        let second_reader_waker = counting_waker(&second_wake_count);

        // Both clones park on the call, the second one last.
        assert!(poll_stream(&mut first_reader, &first_reader_waker).is_pending());
        assert!(poll_stream(&mut second_reader, &second_reader_waker).is_pending());

        // A message arrives: both parked clones are woken; the second takes it.
        FedCall::deliver(&feed, Some(7));
        assert_eq!(
            first_wake_count.load(Ordering::SeqCst),
            1,
            "first cloned reader lost its wakeup",
        );
        assert_eq!(
            second_wake_count.load(Ordering::SeqCst),
            1,
            "second cloned reader should also be notified",
        );
        assert!(matches!(
            poll_stream(&mut second_reader, &second_reader_waker),
            Poll::Ready(Some(Ok(7)))
        ));

        // The first clone parks again (twice: it keeps one entry) while the
        // second is busy elsewhere and does not poll. The end wakes it.
        assert!(poll_stream(&mut first_reader, &first_reader_waker).is_pending());
        assert!(poll_stream(&mut first_reader, &first_reader_waker).is_pending());
        FedCall::deliver(&feed, None);
        assert_eq!(
            first_wake_count.load(Ordering::SeqCst),
            2,
            "the end of the call should wake the parked clone",
        );
        assert!(matches!(
            poll_stream(&mut first_reader, &first_reader_waker),
            Poll::Ready(None)
        ));
        assert!(matches!(
            poll_stream(&mut second_reader, &second_reader_waker),
            Poll::Ready(None)
        ));
        crate::test_complete!("native_response_stream_clones_parked_in_two_tasks_are_each_woken");
    }

    /// A response stream clone that parks and is dropped while the call is
    /// quiet forgets its waker (asupersync-mu5yhv finding 3 follow-up): each
    /// such clone used to leave one parked on the call until the next wake.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn a_dropped_response_stream_clone_forgets_its_parked_waker() {
        init_test("a_dropped_response_stream_clone_forgets_its_parked_waker");
        let feed = Arc::new(Mutex::new(Feed::default()));
        let call = LegacyNativeCall::new(
            Box::new(FedCall(Arc::clone(&feed))),
            LegacyShape::ServerStreaming,
        );
        let probe = Arc::clone(&call);
        let mut reader = ResponseStream::<u32>::native(call);
        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(&wake_count);
        assert!(poll_stream(&mut reader, &waker).is_pending());
        for _ in 0..100 {
            let mut clone = reader.clone();
            assert!(poll_stream(&mut clone, &waker).is_pending());
        }

        assert_eq!(
            probe.parked_responders(),
            1,
            "only the live reader stays parked"
        );
        FedCall::deliver(&feed, Some(7));
        assert_eq!(wake_count.load(Ordering::SeqCst), 1);
        assert!(matches!(
            poll_stream(&mut reader, &waker),
            Poll::Ready(Some(Ok(7)))
        ));
        crate::test_complete!("a_dropped_response_stream_clone_forgets_its_parked_waker");
    }

    /// The last waker parked for a response handle can belong to a task
    /// whose future owns another clone of the same stream, whose drop takes
    /// the fan-out lock. A waker forgotten (handle dropped) or replaced
    /// (re-registered from another task) used to be dropped under that lock,
    /// and the thread deadlocked on itself.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn dropping_a_parked_waker_that_owns_a_stream_clone_does_not_deadlock() {
        init_test("dropping_a_parked_waker_that_owns_a_stream_clone_does_not_deadlock");
        // Holds the clone only to drop it with the waker.
        struct OwnsAClone {
            _clone: Mutex<Option<ResponseStream<u32>>>,
        }
        // The waker exists to own the clone, so Waker::noop() cannot stand in.
        #[allow(clippy::manual_noop_waker)]
        impl Wake for OwnsAClone {
            fn wake(self: Arc<Self>) {}
        }
        let parked_reader = || {
            let feed = Arc::new(Mutex::new(Feed::default()));
            let call = LegacyNativeCall::new(
                Box::new(FedCall(Arc::clone(&feed))),
                LegacyShape::ServerStreaming,
            );
            let mut reader = ResponseStream::<u32>::native(call);
            let owner = Arc::new(OwnsAClone {
                _clone: Mutex::new(Some(reader.clone())),
            });
            // Only the call keeps this waker once the poll returns.
            assert!(poll_stream(&mut reader, &Waker::from(owner)).is_pending());
            reader
        };
        let finishes = |name: &str, step: Box<dyn FnOnce() + Send>| {
            let (done, finished) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                step();
                let _ = done.send(());
            });
            assert!(
                finished.recv_timeout(Duration::from_secs(5)).is_ok(),
                "{name} deadlocked"
            );
        };

        let reader = parked_reader();
        finishes("dropping the reader", Box::new(move || drop(reader)));

        let mut reader = parked_reader();
        finishes(
            "re-registering from another task",
            Box::new(move || {
                let other = counting_waker(&Arc::new(AtomicUsize::new(0)));
                assert!(poll_stream(&mut reader, &other).is_pending());
            }),
        );
        crate::test_complete!("dropping_a_parked_waker_that_owns_a_stream_clone_does_not_deadlock");
    }

    /// A unix: target's path was used verbatim (asupersync-mu5yhv finding
    /// 6): `unix:///tmp/my%20app.sock` dialled a file named with a literal
    /// `%20`, and a query or fragment stayed in the file name.
    #[test]
    fn unix_channel_targets_decode_an_absolute_path_and_drop_query_and_fragment() {
        let path = |uri: &str| {
            parse_channel_uri(uri)
                .ok()
                .and_then(|target| target.unix_path)
                .map(std::borrow::Cow::into_owned)
        };
        assert_eq!(
            path("unix:///tmp/my%20app.sock").as_deref(),
            Some("/tmp/my app.sock")
        );
        assert_eq!(
            path("unix:/tmp/my%20app.sock").as_deref(),
            Some("/tmp/my app.sock")
        );
        assert_eq!(
            path("unix:///run/x.sock?foo#bar").as_deref(),
            Some("/run/x.sock")
        );
        assert_eq!(path("UNIX:///run/x.sock").as_deref(), Some("/run/x.sock"));
        // A relative path is used as written, as grpc-go uses the URL's
        // opaque part.
        assert_eq!(
            path("unix:relative%20name.sock").as_deref(),
            Some("relative%20name.sock")
        );
        for refused in [
            "unix:///tmp/cut%2",
            "unix:///tmp/bad%zz",
            "unix:///tmp/nul%00",
            "unix:///tmp/not-utf8-%ff",
            "unix:?only-a-query",
        ] {
            assert!(parse_channel_uri(refused).is_err(), "{refused}");
        }
    }

    /// d0's LOW 3 on asupersync-x4kh5w: Channel::connect accepted a unix:
    /// target whose path no sockaddr_un holds, and every call made on it then
    /// failed UNAVAILABLE, which callers retry.
    #[cfg(unix)]
    #[test]
    fn a_unix_target_the_platform_cannot_dial_is_refused_by_connect() {
        let too_long = format!("unix:///tmp/{}.sock", "a".repeat(200));
        let refused = futures_lite::future::block_on(Channel::connect(too_long))
            .expect_err("a socket path longer than sun_path");
        assert!(refused.to_string().contains("socket path"), "{refused}");
        // Building a channel dials nothing, so a short path is accepted.
        assert!(futures_lite::future::block_on(Channel::connect("unix:///tmp/ok.sock")).is_ok());
    }

    #[test]
    fn response_stream_terminal_metadata_survives_terminal_error() {
        let mut stream = ResponseStream::<u32>::open();
        stream.push(Ok(7)).expect("data item should enqueue");

        let mut trailers = Metadata::new();
        assert!(trailers.insert_bin(
            "grpc-status-details-bin",
            Bytes::from_static(b"error-details"),
        ));
        trailers.insert("x-debug-trailer", "final-hop");
        stream.finish_with_metadata(Status::internal("stream failed"), trailers.clone());

        let first = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        assert!(matches!(first, Some(Ok(7))));

        let second = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        match second {
            Some(Err(status)) => {
                assert_eq!(status.code(), crate::grpc::Code::Internal);
                assert_eq!(status.message(), "stream failed");
            }
            other => panic!("expected terminal status, got {other:?}"),
        }

        let stored = stream.terminal_metadata();
        assert!(matches!(
            stored.get("grpc-status-details-bin"),
            Some(crate::grpc::MetadataValue::Binary(value)) if value.as_ref() == b"error-details"
        ));
        assert!(matches!(
            stored.get("x-debug-trailer"),
            Some(crate::grpc::MetadataValue::Ascii(value)) if value == "final-hop"
        ));

        let third = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        assert!(third.is_none());
    }

    #[test]
    fn response_stream_cancel_discards_buffered_items_before_terminal_status() {
        let mut stream = ResponseStream::<u32>::open();
        stream.push(Ok(7)).expect("data item should enqueue");

        let mut trailers = Metadata::new();
        assert!(trailers.insert_bin("grpc-status-details-bin", Bytes::from_static(b"cancelled"),));
        stream.cancel_with_metadata(Status::cancelled("client cancelled stream"), trailers);

        let first = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        match first {
            Some(Err(status)) => {
                assert_eq!(status.code(), crate::grpc::Code::Cancelled);
                assert_eq!(status.message(), "client cancelled stream");
            }
            other => panic!("expected immediate cancelled status, got {other:?}"),
        }

        let second = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        assert!(
            second.is_none(),
            "cancelled stream must terminate after status"
        );
    }

    #[test]
    fn request_sink_debug() {
        let sink = RequestSink::<u8>::new();
        let dbg = format!("{sink:?}");
        assert!(dbg.contains("RequestSink"));
    }

    #[test]
    fn request_sink_default() {
        let sink = RequestSink::<i32>::default();
        let dbg = format!("{sink:?}");
        assert!(dbg.contains("RequestSink"));
    }

    #[test]
    fn request_sink_close_hook_runs_once_when_closed_then_dropped() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let close_count = Arc::new(AtomicUsize::new(0));
        let hook_count = Arc::clone(&close_count);
        let mut sink: RequestSink<u32> = RequestSink::with_hooks(
            None,
            Some(Box::new(move || {
                hook_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })),
            None,
        );

        futures_lite::future::block_on(sink.close()).expect("close should succeed");
        drop(sink);

        assert_eq!(
            close_count.load(Ordering::SeqCst),
            1,
            "close hook should run exactly once"
        );
    }

    #[test]
    fn request_sink_failed_send_hook_does_not_increment_sent_count() {
        let mut sink = RequestSink::with_hooks(
            Some(Box::new(|_: u32| {
                Err(Status::internal("send hook rejected the message"))
            })),
            None,
            None,
        );

        let error = futures_lite::future::block_on(sink.send(7))
            .expect_err("failing send hook must reject the message");
        assert_eq!(error.code(), crate::grpc::Code::Internal);

        {
            let state = lock_unpoisoned(&sink.state);
            assert_eq!(
                state.sent_count, 0,
                "failed sends must not be counted as successfully sent",
            );
            drop(state);
        }
    }

    #[test]
    fn request_sink_successful_send_hook_increments_sent_count() {
        let mut sink = RequestSink::with_hooks(Some(Box::new(|_: u32| Ok(()))), None, None);

        futures_lite::future::block_on(sink.send(7))
            .expect("successful send hook should accept the message");

        assert_eq!(
            lock_unpoisoned(&sink.state).sent_count,
            1,
            "successful sends must be counted"
        );
    }

    #[test]
    fn response_future_default() {
        let _fut = ResponseFuture::<i32>::default();
        // ResponseFuture does not derive Debug, but Default is implemented
    }

    #[test]
    fn response_future_new_fails_fast() {
        let response = futures_lite::future::block_on(ResponseFuture::<u8>::new())
            .expect_err("unlinked response future must fail immediately");
        assert_eq!(response.code(), crate::grpc::Code::FailedPrecondition);
    }

    #[test]
    fn metadata_interceptor_clone() {
        let interceptor = MetadataInterceptor::new().with_metadata("x-key", "val");
        let cloned = interceptor;
        let mut request = Request::new(Bytes::new());
        cloned.intercept(&mut request).unwrap();
        assert!(request.metadata().get("x-key").is_some());
    }

    #[test]
    fn metadata_interceptor_default() {
        let interceptor = MetadataInterceptor::default();
        let dbg = format!("{interceptor:?}");
        assert!(dbg.contains("MetadataInterceptor"));
    }

    #[test]
    fn client_streaming_future_resolves_when_sink_is_dropped() {
        let channel = make_channel("http://loopback:50051");
        let mut client = GrpcClient::new(channel);

        let (sink, future) = futures_lite::future::block_on(
            client.client_streaming::<u32, u32>("/pkg.Service/Method"),
        )
        .expect("client streaming setup");

        // Dropping the sink should close the stream and wake the response future.
        drop(sink);
        let result = futures_lite::future::block_on(future);
        assert!(
            result.is_err(),
            "empty dropped stream should resolve with an error"
        );
    }

    #[test]
    fn bidi_stream_closes_when_sink_is_dropped() {
        let channel = make_channel("http://loopback:50051");
        let mut client = GrpcClient::new(channel);

        let (sink, mut stream) = futures_lite::future::block_on(
            client.bidi_streaming::<u32, u32>("/pkg.Service/Method"),
        )
        .expect("bidi streaming setup");

        drop(sink);
        let first = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        let status = first.expect("drop should surface a terminal status");
        assert_eq!(
            status
                .expect_err("drop should cancel bidi response stream")
                .code(),
            crate::grpc::Code::Cancelled
        );
        let second = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        assert!(second.is_none(), "cancelled bidi stream should then close");
    }

    /// GRPC-CONF-012: Client cancellation must surface CANCELLED immediately.
    /// Buffered loopback responses must not leak after the client aborts the RPC.
    #[test]
    fn conformance_bidi_stream_cancellation_suppresses_buffered_responses() {
        let channel = make_channel("http://loopback:50051");
        let mut client = GrpcClient::new(channel);

        let (mut sink, mut stream) = futures_lite::future::block_on(
            client.bidi_streaming::<u32, u32>("/pkg.Service/Method"),
        )
        .expect("bidi streaming setup");

        futures_lite::future::block_on(sink.send(7))
            .expect("loopback bidi stream should buffer one echoed response");
        drop(sink);

        let first = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        match first {
            Some(Err(status)) => {
                assert_eq!(status.code(), crate::grpc::Code::Cancelled);
                assert_eq!(status.message(), "request stream cancelled by client");
            }
            other => panic!("expected immediate CANCELLED after client abort, got {other:?}"),
        }

        let second = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            Streaming::poll_next(Pin::new(&mut stream), cx)
        }));
        assert!(second.is_none(), "cancelled bidi stream should then close");
    }

    #[test]
    fn conformance_bidi_response_cancel_closes_request_sink() {
        let channel = make_channel("http://loopback:50051");
        let mut client = GrpcClient::new(channel);

        let (mut sink, stream) = futures_lite::future::block_on(
            client.bidi_streaming::<u32, u32>("/pkg.Service/Method"),
        )
        .expect("bidi streaming setup");

        stream.cancel(Status::cancelled("response stream cancelled by client"));

        let send_error = futures_lite::future::block_on(sink.send(7))
            .expect_err("response cancellation should cancel the request sink");
        assert_eq!(send_error.code(), crate::grpc::Code::Cancelled);
        assert_eq!(send_error.message(), "response stream cancelled by client");

        let close_error = futures_lite::future::block_on(sink.close())
            .expect_err("closing a cancelled request sink should report cancellation");
        assert_eq!(close_error.code(), crate::grpc::Code::Cancelled);
        assert_eq!(close_error.message(), "response stream cancelled by client");
    }

    #[test]
    fn client_streaming_drop_after_send_returns_cancelled() {
        let channel = make_channel("http://loopback:50051");
        let mut client = GrpcClient::new(channel);

        let (mut sink, future) = futures_lite::future::block_on(
            client.client_streaming::<u32, u32>("/pkg.Service/Method"),
        )
        .expect("client streaming setup");

        futures_lite::future::block_on(sink.send(7)).expect("send should succeed");
        drop(sink);

        let error = futures_lite::future::block_on(future)
            .expect_err("dropped request stream must resolve as cancelled");
        assert_eq!(error.code(), crate::grpc::Code::Cancelled);
    }

    #[test]
    fn client_streaming_second_message_fails_closed() {
        let channel = make_channel("http://loopback:50051");
        let mut client = GrpcClient::new(channel);

        let (mut sink, future) = futures_lite::future::block_on(
            client.client_streaming::<u32, u32>("/pkg.Service/Method"),
        )
        .expect("client streaming setup");

        futures_lite::future::block_on(sink.send(7)).expect("first send should succeed");
        let error = futures_lite::future::block_on(sink.send(9))
            .expect_err("second send must fail closed in loopback mode");
        assert_eq!(error.code(), crate::grpc::Code::FailedPrecondition);

        futures_lite::future::block_on(sink.close()).expect("close should still succeed");
        let response =
            futures_lite::future::block_on(future).expect("first request should still resolve");
        assert_eq!(*response.get_ref(), 7);
    }

    #[test]
    fn request_sink_close_hook_failure_propagates_to_response_future() {
        let state = Arc::new(Mutex::new(RequestSinkState::new()));
        let mut sink: RequestSink<u32> = RequestSink::with_state_and_hooks(
            Arc::clone(&state),
            None,
            Some(Box::new(|| Err(Status::internal("close failed")))),
            None,
        );
        let future = ResponseFuture::with_resolver(state, |_| {
            Ok(Response::with_metadata(7_u32, Metadata::new()))
        });

        let close_error =
            futures_lite::future::block_on(sink.close()).expect_err("close hook should fail");
        assert_eq!(close_error.code(), crate::grpc::Code::Internal);

        let future_error = futures_lite::future::block_on(future)
            .expect_err("response future should reflect close failure");
        assert_eq!(future_error.code(), crate::grpc::Code::Internal);
    }

    #[test]
    fn bidi_streaming_applies_interceptors() {
        #[derive(Debug, Clone, Copy)]
        struct RejectInterceptor;

        impl crate::grpc::server::Interceptor for RejectInterceptor {
            fn intercept_request(&self, _request: &mut Request<Bytes>) -> Result<(), Status> {
                Err(Status::unauthenticated("blocked by interceptor"))
            }

            fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
                Ok(())
            }
        }

        let channel = make_channel("http://loopback:50051");
        let mut client = GrpcClient::new(channel).with_interceptor(RejectInterceptor);

        let error = futures_lite::future::block_on(
            client.bidi_streaming::<u32, u32>("/pkg.Service/Method"),
        )
        .expect_err("bidi call should respect client interceptors");
        assert_eq!(error.code(), crate::grpc::Code::Unauthenticated);
    }

    #[test]
    fn channel_connect_accepts_loopback_and_localhost_hosts() {
        for uri in [
            "http://loopback:50051",
            "http://localhost:50051",
            "http://127.0.0.1:50051",
        ] {
            let channel = futures_lite::future::block_on(Channel::connect(uri))
                .expect("loopback and localhost targets should connect");
            assert_eq!(channel.uri(), uri);
        }
    }

    #[test]
    fn channel_connect_preserves_loopback_userinfo_and_port_compatibility() {
        for uri in [
            "http://user:pw@loopback",
            "http://user:pw@LOOPBACK:50051",
            "http://loopback:+80",
            "http://user:pw@loopback:+80",
        ] {
            futures_lite::future::block_on(async {
                let channel = Channel::connect(uri)
                    .await
                    .expect("legacy loopback URI remains accepted without I/O");
                assert_eq!(channel.uri(), uri);
                let mut client = GrpcClient::new(channel);
                let response = client
                    .unary::<Bytes, Bytes>(
                        "/pkg.Service/Method",
                        Request::new(Bytes::from_static(b"loopback-compatibility")),
                    )
                    .await
                    .expect("legacy URI stays on the deterministic transport");
                assert_eq!(response.get_ref().as_ref(), b"loopback-compatibility");
                assert!(matches!(
                    response.metadata().get("x-asupersync-grpc-transport"),
                    Some(MetadataValue::Ascii(value)) if value == "loopback"
                ));
                assert!(response.metadata().get("authorization").is_none());
            });
        }
    }

    #[test]
    fn channel_connect_requires_explicit_tls_connector() {
        for uri in [
            "https://LOCALHOST:50051/service",
            "HTTPS://LOCALHOST:50051/service",
        ] {
            let error = futures_lite::future::block_on(Channel::connect(uri))
                .expect_err("HTTPS gRPC channel without a connector must fail closed");
            match error {
                GrpcError::Transport(TransportErrorKind::ProtocolViolation, message) => {
                    assert!(
                        message.contains("explicit TLS connector"),
                        "expected explicit-authority message for {uri}, got: {message}"
                    );
                }
                other => panic!(
                    "expected TLS protocol-violation transport error for {uri}, got: {other:?}"
                ),
            }
        }

        let error = futures_lite::future::block_on(
            Channel::builder("http://loopback:50051").tls().connect(),
        )
        .expect_err("deterministic loopback TLS must fail closed");
        assert!(error.to_string().contains("loopback channels"));
    }

    #[test]
    fn channel_connect_with_config_requires_explicit_tls_connector() {
        let config = ChannelConfig {
            use_tls: true,
            ..ChannelConfig::default()
        };
        let error = futures_lite::future::block_on(Channel::connect_with_config(
            "http://localhost:50051",
            config,
        ))
        .expect_err("TLS-enabled config must fail closed");

        match error {
            GrpcError::Transport(TransportErrorKind::ProtocolViolation, message) => {
                assert!(
                    message.contains("explicit TLS connector"),
                    "expected TLS enforcement message, got: {message}"
                );
            }
            other => panic!(
                "expected TLS protocol-violation transport error for direct config, got: {other:?}"
            ),
        }
    }

    #[test]
    fn channel_connect_accepts_dns_and_ip_targets_without_resolution() {
        for uri in [
            "http://grpc.service.invalid:50051",
            "http://SERVICE.invalid./base?ignored=yes#fragment",
            "http://xn--bcher-kva.invalid",
            "http://10.20.30.40:50051",
            "http://127.0.0.2",
            "http://[::1]:50051",
            "http://[2001:db8::1234]",
        ] {
            // No runtime context and deliberately unresolvable DNS names: a
            // successfully constructed channel cannot have dialed anything.
            let channel = futures_lite::future::block_on(Channel::connect(uri))
                .expect("native target should be configured lazily");
            assert_eq!(channel.uri(), uri);
            assert!(!channel_target_is_loopback(uri));
        }
    }

    #[test]
    fn channel_connect_rejects_malformed_native_authorities() {
        for uri in [
            "http://",
            "http://:50051",
            "http://::1",
            "http://[::1",
            "http://[::1]suffix:50051",
            "http://[localhost]:50051",
            "http://[127.0.0.1]:50051",
            "http://[::1]:50051:50052",
            "http://[fe80::1%25eth0]:50051",
            "http://localhost:50051:50052",
            "http://localhost:",
            "http://localhost:+80",
            "http://[::1]:+80",
            "http://localhost:65536",
            "http://bad..invalid:50051",
            "http://-bad.invalid:50051",
            "http://bad-.invalid:50051",
            "http://bad_name.invalid:50051",
            "http://bad%2einvalid:50051",
            "http://bücher.invalid:50051",
            "http://localhost\\evil.invalid:50051",
        ] {
            assert!(
                futures_lite::future::block_on(Channel::connect(uri)).is_err(),
                "malformed authority must be refused before DNS: {uri}"
            );
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn native_h2_targets_preserve_authority_and_tls_identity() {
        let host = NativeH2Target::parse("http://GRPC.Service.invalid", false, None, None)
            .expect("DNS target");
        assert_eq!(host.authority, "grpc.service.invalid");
        assert_eq!(
            host.destination,
            NativeH2Destination::Host("grpc.service.invalid".to_owned(), 80)
        );
        assert_eq!(host.server_name, "grpc.service.invalid");
        assert_eq!(host.scheme, "http");
        assert!(!host.use_tls);

        let tls = NativeH2Target::parse("https://SERVICE.invalid", false, None, None)
            .expect("TLS DNS target");
        assert_eq!(
            tls.destination,
            NativeH2Destination::Host("service.invalid".to_owned(), 443)
        );
        assert_eq!(tls.server_name, "service.invalid");
        assert_eq!(tls.scheme, "https");
        assert!(tls.use_tls);

        let ipv6 = NativeH2Target::parse("https://[2001:DB8::1]:8443", false, None, None)
            .expect("IPv6 TLS target");
        assert_eq!(ipv6.authority, "[2001:db8::1]:8443");
        assert_eq!(ipv6.server_name, "2001:db8::1");
        assert_eq!(
            ipv6.destination,
            NativeH2Destination::Address("[2001:db8::1]:8443".parse().unwrap())
        );

        let override_addr = "[::1]:50051".parse().unwrap();
        let explicit = NativeH2Target::parse(
            "https://grpc.service.invalid:443",
            false,
            Some("AUTH.Service.invalid"),
            Some(override_addr),
        )
        .expect("independent destination, HTTP authority and TLS identity");
        assert_eq!(explicit.authority, "grpc.service.invalid:443");
        assert_eq!(explicit.server_name, "auth.service.invalid");
        assert_eq!(
            explicit.destination,
            NativeH2Destination::Address(override_addr)
        );

        let config_tls = NativeH2Target::parse("http://localhost", true, None, None)
            .expect("TLS configuration determines default port");
        assert_eq!(
            config_tls.destination,
            NativeH2Destination::Host("localhost".to_owned(), 443)
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn native_h2_hostname_dial_requires_io_authority_before_resolution() {
        let cx = crate::cx::Cx::for_testing();
        let _guard = crate::cx::Cx::set_current(Some(cx));
        let channel = make_channel("http://grpc.service.invalid:50051");
        let mut client = GrpcClient::new(channel);
        let status = futures_lite::future::block_on(client.unary::<Bytes, Bytes>(
            "/pkg.Service/Method",
            Request::new(Bytes::new()),
        ))
        .expect_err("a Cx without a native driver must not resolve or dial");
        assert_eq!(status.code(), Code::FailedPrecondition);
        assert_eq!(
            status.message(),
            "native HTTP/2 gRPC calls require runtime I/O authority"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn native_h2_hostname_dial_respects_attenuated_io_with_a_live_driver() {
        let runtime = crate::runtime::RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("native runtime");
        runtime.block_on(async {
            let mut cx = crate::cx::Cx::current().expect("native runtime context");
            assert!(cx.io_driver_handle().is_some(), "native driver installed");
            cx.runtime_mask = crate::cx::cap::CapMask::none();
            assert!(cx.io_driver_handle().is_some(), "attenuation retains driver");
            let _guard = crate::cx::Cx::set_current(Some(cx));
            let channel = Channel::connect("http://grpc.service.invalid:50051")
                .await
                .expect("channel construction needs no I/O authority");
            let mut client = GrpcClient::new(channel);
            let status = client
                .unary::<Bytes, Bytes>("/pkg.Service/Method", Request::new(Bytes::new()))
                .await
                .expect_err("a retained native driver must not bypass attenuation");
            assert_eq!(status.code(), Code::FailedPrecondition);
            assert_eq!(
                status.message(),
                "native HTTP/2 gRPC calls require runtime I/O authority"
            );
        });
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn explicit_dial_addr_requires_authenticated_native_https() {
        let address = SocketAddr::from(([127, 0, 0, 1], 50051));

        let cleartext = futures_lite::future::block_on(
            Channel::builder("http://grpc.service.invalid:50051")
                .dial_addr(address)
                .connect(),
        )
        .expect_err("explicit cleartext dial must fail closed");
        assert!(cleartext.to_string().contains("requires an https URI"));

        let missing_tls = futures_lite::future::block_on(
            Channel::builder("https://grpc.service.invalid:443")
                .dial_addr(address)
                .connect(),
        )
        .expect_err("explicit HTTPS dial without TLS authority must fail closed");
        assert!(missing_tls.to_string().contains("explicit TLS connector"));

        let deterministic_loopback = futures_lite::future::block_on(
            Channel::builder("https://loopback:443")
                .dial_addr(address)
                .connect(),
        )
        .expect_err("deterministic loopback must reject a native dial capability");
        assert!(
            deterministic_loopback
                .to_string()
                .contains("cannot use an explicit native dial address")
        );

        let userinfo = futures_lite::future::block_on(
            Channel::builder("https://user@grpc.service.invalid:443")
                .dial_addr(address)
                .connect(),
        )
        .expect_err("explicit dial must reject URI userinfo");
        assert!(userinfo.to_string().contains("userinfo is not supported"));

        for uri in [
            "https://grpc.service.invalid:443:444",
            "https://grpc.service.invalid:notaport",
            "https://[grpc.service.invalid:443",
        ] {
            let malformed =
                futures_lite::future::block_on(Channel::builder(uri).dial_addr(address).connect())
                    .expect_err("ambiguous explicit-dial authority must fail closed");
            assert!(
                malformed.to_string().contains("at most one port")
                    || malformed.to_string().contains("unsigned 16-bit integer")
                    || malformed.to_string().contains("matching brackets"),
                "unexpected explicit-dial authority error for {uri}: {malformed}"
            );
        }
    }

    #[test]
    fn channel_connect_rejects_userinfo_bypass() {
        // Regression: "loopback" in userinfo must not fool the host check.
        // RFC 3986 §3.2: authority = [userinfo "@"] host [":" port]
        for uri in [
            "http://loopback:pw@evil.com:80",
            "http://loopback@evil.com",
            "http://user:loopback@attacker.io:443/path",
        ] {
            let error = futures_lite::future::block_on(Channel::connect(uri))
                .expect_err(&format!("userinfo bypass must fail: {uri}"));
            match error {
                GrpcError::Transport(_kind, msg) => {
                    assert!(
                        msg.contains("userinfo is not supported"),
                        "expected userinfo rejection for {uri}, got: {msg}"
                    );
                }
                other => panic!("expected transport error for {uri}, got: {other:?}"),
            }
        }
    }

    #[test]
    fn channel_connect_rejects_authority_whitespace() {
        for uri in [
            "http:// localhost:50051",
            "http://localhost :50051",
            "http://localhost:50051 ",
            "http://local\thost:50051",
            "http://localhost\n:50051",
        ] {
            let error = match futures_lite::future::block_on(Channel::connect(uri)) {
                Ok(_) => panic!("authority whitespace must fail closed: {uri:?}"),
                Err(error) => error,
            };
            match error {
                GrpcError::Transport(_kind, message) => {
                    assert!(
                        message.contains("authority cannot contain whitespace"),
                        "expected authority whitespace error for {uri:?}, got: {message}"
                    );
                }
                other => panic!("expected transport error for {uri:?}, got: {other:?}"),
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod native_owned_calls {
        use super::*;
        use crate::cx::Cx;
        use crate::time::{TimerDriverHandle, VirtualClock};
        use crate::types::{Budget, RegionId, TaskId, Time};

        fn context() -> (Cx, Arc<VirtualClock>) {
            let clock = Arc::new(VirtualClock::starting_at(Time::from_secs(10)));
            let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
            let cx = Cx::new_with_drivers(
                RegionId::new_for_test(81, 0), TaskId::new_for_test(82, 0),
                Budget::INFINITE, None, None, None, Some(timer), None,
            );
            (cx, clock)
        }

        #[test]
        fn native_stream_preparation_preserves_channel_policy_and_explicit_context() {
            struct ObserveContext(TaskId, Arc<AtomicUsize>);
            impl ClientInterceptor for ObserveContext {
                fn intercept(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
                    assert_eq!(Cx::current().unwrap().task_id(), self.0);
                    assert!(request.metadata_mut().insert("x-interceptor", "explicit-context"));
                    self.1.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            }
            let (cx, _) = context();
            let unrelated = Cx::for_testing();
            let _ambient = Cx::set_current(Some(unrelated.clone()));
            let calls = Arc::new(AtomicUsize::new(0));
            let channel = futures_lite::future::block_on(
                Channel::builder("http://service.invalid:50051")
                    .timeout(Duration::from_secs(20))
                    .max_send_message_size(1024)
                    .max_recv_message_size(2048)
                    .initial_connection_window_size(131_072)
                    .initial_stream_window_size(32_768)
                    .send_compression(CompressionEncoding::Identity)
                    .connect(),
            ).unwrap();
            let client = GrpcClient::new(channel)
                .with_interceptor(ObserveContext(cx.task_id(), Arc::clone(&calls)));
            let mut request = Request::new(());
            assert!(request.metadata_mut().insert("x-request", "kept"));
            let setup = client.prepare_native_stream(&cx, "/svc/Upload", &request).unwrap();
            assert_eq!(setup.config.max_send_message_size, 1024);
            assert_eq!(setup.config.max_recv_message_size, 2048);
            assert_eq!(setup.config.timeout, Some(Duration::from_secs(20)));
            assert_eq!(setup.config.scheme, "http");
            assert_eq!(setup.windows.connection, Some(131_072));
            assert_eq!(setup.windows.stream, Some(32_768));
            assert!(setup.metadata.get("grpc-encoding").is_none());
            assert!(setup.metadata.get("grpc-accept-encoding").is_none());
            assert!(matches!(setup.metadata.get("x-request"), Some(MetadataValue::Ascii(value)) if value == "kept"));
            assert!(matches!(setup.metadata.get("x-interceptor"), Some(MetadataValue::Ascii(value)) if value == "explicit-context"));
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(Cx::current().unwrap().task_id(), unrelated.task_id());
        }

        #[test]
        fn native_stream_preparation_admits_bounded_keepalive_and_rejects_conflicting_compression() {
            let (cx, _) = context();
            let keepalive = futures_lite::future::block_on(
                Channel::builder("http://service.invalid")
                    .keepalive_interval(Duration::from_secs(30)).connect(),
            ).unwrap();
            let setup = GrpcClient::new(keepalive)
                .prepare_native_stream(&cx, "/svc/Upload", &Request::new(()))
                .expect("keepalive is explicitly driven by the native owner");
            assert_eq!(setup.keepalive, Some(NativeStreamKeepalive::new(
                Duration::from_secs(30), Duration::from_secs(20),
            ).unwrap()));

            let channel = futures_lite::future::block_on(
                Channel::builder("http://service.invalid")
                    .send_compression(CompressionEncoding::Identity).connect(),
            ).unwrap();
            let client = GrpcClient::new(channel);
            let mut request = Request::new(());
            assert!(request.metadata_mut().insert("grpc-encoding", "gzip"));
            assert!(request.metadata_mut().insert("grpc-encoding", "identity"));
            let status = client.prepare_native_stream(&cx, "/svc/Upload", &request)
                .err().expect("last matching value must not hide a conflicting duplicate");
            assert_eq!(status.code(), Code::InvalidArgument);
            assert_eq!(status.message(), "native streaming metadata cannot override channel compression");
        }

        #[test]
        fn native_stream_keepalive_defaults_and_invalid_configuration_refuse_before_dial() {
            let (cx, _) = context();
            let channel = futures_lite::future::block_on(Channel::connect("http://service.invalid")).unwrap();
            let setup = GrpcClient::new(channel)
                .prepare_native_stream(&cx, "/svc/Upload", &Request::new(())).unwrap();
            assert!(setup.keepalive.is_none());

            for (interval, timeout) in [
                (None, Some(Duration::from_secs(2))),
                (Some(Duration::ZERO), None),
                (Some(Duration::from_secs(2)), Some(Duration::ZERO)),
            ] {
                let mut builder = Channel::builder("http://service.invalid");
                if let Some(interval) = interval { builder = builder.keepalive_interval(interval); }
                if let Some(timeout) = timeout { builder = builder.keepalive_timeout(timeout); }
                let channel = futures_lite::future::block_on(builder.connect()).unwrap();
                let status = GrpcClient::new(channel)
                    .prepare_native_stream(&cx, "/svc/Upload", &Request::new(()))
                    .err().expect("invalid heartbeat policy must refuse before network effects");
                assert_eq!(status.code(), Code::InvalidArgument);
                assert!(status.message().contains("keepalive"));
            }
        }

        #[test]
        fn native_stream_interceptor_cannot_restart_the_call_deadline() {
            struct ExpireAndExtend(Arc<VirtualClock>);
            impl ClientInterceptor for ExpireAndExtend {
                fn intercept(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
                    self.0.advance_to(Time::from_secs(16));
                    assert!(request.metadata_mut().insert_or_replace("grpc-timeout", "50S"));
                    Ok(())
                }
            }
            let (cx, clock) = context();
            let channel = futures_lite::future::block_on(
                Channel::builder("http://service.invalid")
                    .timeout(Duration::from_secs(5)).connect(),
            ).unwrap();
            let client = GrpcClient::new(channel).with_interceptor(ExpireAndExtend(clock));
            let status = client.prepare_native_stream(&cx, "/svc/Upload", &Request::new(()))
                .err().expect("interceptor time must consume the original deadline");
            assert_eq!(status.code(), Code::DeadlineExceeded);
            assert!(!cx.is_cancel_requested());
        }
    }

    // --- br-asupersync-server-stack-hardening-eeexl1.1.3: outbound ---
    // --- deadline attach from the remaining ambient Cx budget       ---

    mod budget_forwarding {
        use super::*;
        use crate::trace::TraceBufferHandle;
        use crate::trace::event::{TraceData, TraceEventKind};
        use crate::types::Budget;

        /// Installs an ambient Cx whose budget deadline is `remaining`
        /// from now, runs `f`, and returns its result plus the trace
        /// buffer attached to the ambient context.
        fn with_ambient_budget<R>(
            remaining: Duration,
            f: impl FnOnce() -> R,
        ) -> (R, TraceBufferHandle) {
            let now = crate::time::wall_now();
            let budget = Budget::INFINITE.tightened_by_timeout(now, remaining);
            let cx = crate::cx::Cx::for_request_with_budget(budget);
            let trace = TraceBufferHandle::new(64);
            cx.set_trace_buffer(trace.clone());
            let _guard = crate::cx::Cx::set_current(Some(cx));
            (f(), trace)
        }

        fn outbound_timeout(client: &mut GrpcClient, path: &str) -> Option<Duration> {
            let response: Response<String> = futures_lite::future::block_on(
                client.unary(path, Request::new("hello".to_owned())),
            )
            .expect("unary");
            match response.metadata().get("grpc-timeout") {
                Some(crate::grpc::streaming::MetadataValue::Ascii(value)) => {
                    crate::grpc::server::parse_grpc_timeout(value)
                }
                _ => None,
            }
        }

        #[test]
        fn ambient_budget_caps_channel_default() {
            let channel = futures_lite::future::block_on(
                Channel::builder("http://loopback:80")
                    .timeout(Duration::from_secs(30))
                    .connect(),
            )
            .expect("channel");
            let mut client = GrpcClient::new(channel);
            let (sent, _trace) = with_ambient_budget(Duration::from_secs(1), || {
                outbound_timeout(&mut client, "/pkg.Service/Method")
            });
            let sent = sent.expect("grpc-timeout must be present");
            assert!(
                sent <= Duration::from_secs(1),
                "budget must cap the channel default, sent {sent:?}"
            );
            assert!(
                sent > Duration::from_millis(500),
                "cap should reflect the remaining budget, sent {sent:?}"
            );
        }

        #[test]
        fn ambient_budget_alone_becomes_wire_deadline() {
            let channel =
                futures_lite::future::block_on(Channel::builder("http://loopback:80").connect())
                    .expect("channel");
            let mut client = GrpcClient::new(channel);
            let (sent, _trace) = with_ambient_budget(Duration::from_millis(500), || {
                outbound_timeout(&mut client, "/pkg.Service/Method")
            });
            let sent = sent.expect("budget-derived grpc-timeout must be sent");
            assert!(
                sent <= Duration::from_millis(500),
                "wire deadline must not exceed the remaining budget, sent {sent:?}"
            );
            assert!(sent > Duration::from_millis(250), "sent {sent:?}");
        }

        #[test]
        fn tighter_per_request_override_passes_through_verbatim() {
            let channel =
                futures_lite::future::block_on(Channel::builder("http://loopback:80").connect())
                    .expect("channel");
            let mut client = GrpcClient::new(channel);
            let ((), _trace) = with_ambient_budget(Duration::from_secs(10), || {
                let mut request = Request::new("hello".to_owned());
                request.metadata_mut().insert("grpc-timeout", "100m");
                let response: Response<String> =
                    futures_lite::future::block_on(client.unary("/pkg.Service/Method", request))
                        .expect("unary");
                match response.metadata().get("grpc-timeout") {
                    Some(crate::grpc::streaming::MetadataValue::Ascii(value)) => {
                        assert_eq!(value, "100m", "tighter override must pass through verbatim");
                    }
                    other => panic!("expected grpc-timeout, got {other:?}"),
                }
            });
        }

        #[test]
        fn expired_ambient_budget_fails_fast() {
            let channel = futures_lite::future::block_on(
                Channel::builder("http://loopback:80")
                    .timeout(Duration::from_secs(30))
                    .connect(),
            )
            .expect("channel");
            let mut client = GrpcClient::new(channel);
            let (result, _trace) = with_ambient_budget(Duration::ZERO, || {
                futures_lite::future::block_on(client.unary::<String, String>(
                    "/pkg.Service/Method",
                    Request::new("hello".to_owned()),
                ))
            });
            let status = result.expect_err("expired budget must fail fast");
            assert_eq!(status.code(), crate::grpc::Code::DeadlineExceeded);
        }

        #[test]
        fn forwarded_budget_trace_event_emitted() {
            let channel = futures_lite::future::block_on(
                Channel::builder("http://loopback:80")
                    .timeout(Duration::from_secs(30))
                    .connect(),
            )
            .expect("channel");
            let mut client = GrpcClient::new(channel);
            let (_sent, trace) = with_ambient_budget(Duration::from_secs(1), || {
                outbound_timeout(&mut client, "/pkg.Service/Method")
            });
            let forwarded: Vec<String> = trace
                .snapshot()
                .iter()
                .filter(|e| e.kind == TraceEventKind::UserTrace)
                .filter_map(|e| match &e.data {
                    TraceData::Message(msg)
                        if msg.starts_with("client.budget_forwarded proto=grpc ") =>
                    {
                        Some(msg.clone())
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(
                forwarded.len(),
                1,
                "exactly one forwarded event expected, got {forwarded:?}"
            );
            assert!(forwarded[0].contains("base=channel"));
            assert!(forwarded[0].contains("grpc_timeout="));
        }
    }
