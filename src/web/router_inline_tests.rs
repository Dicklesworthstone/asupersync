    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::bytes::Bytes;
    use crate::web::extract::Extension;
    use crate::web::handler::{FnHandler, FnHandler1};

    fn ok_handler() -> &'static str {
        "ok"
    }

    fn not_found_handler() -> StatusCode {
        StatusCode::NOT_FOUND
    }

    fn created_handler() -> StatusCode {
        StatusCode::CREATED
    }

    fn body_policy_summary(Extension(policy): Extension<RequestBodyPolicy>) -> String {
        format!(
            "total={};json={};form={};raw={};multipart={};field={};parts={};request_timeout={};idle_timeout={}",
            policy.max_total_body_size,
            policy.body_limits.max_json_body_size,
            policy.body_limits.max_form_body_size,
            policy.body_limits.max_raw_body_size,
            policy.multipart_limits.max_total_size,
            policy.multipart_limits.max_part_body_size,
            policy.multipart_limits.max_parts,
            policy.multipart_limits.request_timeout_secs,
            policy.multipart_limits.idle_timeout_secs,
        )
    }

    fn body_limits_summary(Extension(limits): Extension<BodyLimits>) -> String {
        format!(
            "json={};form={};raw={}",
            limits.max_json_body_size, limits.max_form_body_size, limits.max_raw_body_size,
        )
    }

    #[cfg(not(target_arch = "wasm32"))]
    struct BodyPolicyWriterProbe {
        writer: parking_lot::Mutex<Option<crate::http::h1::IncomingRequestBodyWriter>>,
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl crate::web::Handler for BodyPolicyWriterProbe {
        fn call(
            &self,
            cx: &crate::Cx,
            _request: Request,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            let cx = cx.clone();
            let writer = self.writer.lock().take();
            Box::pin(async move {
                let Some(mut writer) = writer else {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                };
                match writer
                    .push_bytes(&cx, b"4\r\nABCD\r\n4\r\nEFGH\r\n0\r\n\r\n")
                    .await
                {
                    Err(crate::http::h1::IncomingBodyError::BodyTooLarge {
                        actual: Some(8),
                        limit: 6,
                    }) => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
                    Ok(()) | Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                }
            })
        }
    }

    #[test]
    fn body_policy_server_router_and_route_merge_monotonically() {
        let server = RequestBodyPolicy::new()
            .max_total_body_size(90)
            .body_limits(
                BodyLimits::new()
                    .max_json_body_size(80)
                    .max_form_body_size(70)
                    .max_raw_body_size(60),
            )
            .multipart_limits(
                MultipartLimits::new()
                    .max_total_size(85)
                    .max_part_body_size(75)
                    .max_parts(50)
                    .request_timeout_secs(40)
                    .idle_timeout_secs(20),
            );
        let router = RequestBodyPolicy::new()
            .max_total_body_size(100)
            .body_limits(
                BodyLimits::new()
                    .max_json_body_size(50)
                    .max_form_body_size(80)
                    .max_raw_body_size(70),
            )
            .multipart_limits(
                MultipartLimits::new()
                    .max_total_size(95)
                    .max_part_body_size(65)
                    .max_parts(60)
                    .request_timeout_secs(30)
                    .idle_timeout_secs(25),
            );
        let route = RequestBodyPolicy::new()
            .max_total_body_size(110)
            .body_limits(
                BodyLimits::new()
                    .max_json_body_size(70)
                    .max_form_body_size(40)
                    .max_raw_body_size(80),
            )
            .multipart_limits(
                MultipartLimits::new()
                    .max_total_size(105)
                    .max_part_body_size(30)
                    .max_parts(70)
                    .request_timeout_secs(50)
                    .idle_timeout_secs(10),
            );
        let router = Router::new()
            .route(
                "/upload",
                post(FnHandler1::<_, Extension<RequestBodyPolicy>>::new(
                    body_policy_summary,
                ))
                .with_body_policy(route),
            )
            .with_body_policy(router)
            .with_server_body_policy(server);

        let response = router.handle(Request::new("POST", "/upload"));
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            std::str::from_utf8(response.body.as_ref()).expect("policy response is UTF-8"),
            "total=90;json=50;form=40;raw=60;multipart=85;field=30;parts=50;request_timeout=30;idle_timeout=10"
        );

        let policies = router.route_body_policies();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].pattern, "/upload");
        assert_eq!(policies[0].method, "POST");
        assert_eq!(policies[0].route_policy, Some(route.resolved()));
        let effective = policies[0]
            .effective_policy
            .expect("configured route has effective policy");
        assert_eq!(effective.max_total_body_size, 90);
        assert_eq!(effective.body_limits.max_json_body_size, 50);
        assert_eq!(effective.multipart_limits.max_part_body_size, 30);
    }

    #[test]
    fn nested_body_policy_cannot_loosen_parent_server_policy() {
        let outer = RequestBodyPolicy::new().max_total_body_size(64);
        let attempted_loosen = RequestBodyPolicy::new()
            .max_total_body_size(128)
            .body_limits(BodyLimits::new().max_json_body_size(128));
        let nested = Router::new()
            .route(
                "/upload",
                post(FnHandler1::<_, Extension<RequestBodyPolicy>>::new(
                    body_policy_summary,
                ))
                .with_body_policy(attempted_loosen),
            )
            .with_server_body_policy(attempted_loosen)
            .with_body_policy(attempted_loosen);
        let router = Router::new()
            .nest("/api", nested)
            .with_server_body_policy(outer);

        let response = router.handle(Request::new("POST", "/api/upload"));
        let body = std::str::from_utf8(response.body.as_ref()).expect("policy response is UTF-8");
        assert!(body.starts_with("total=64;"), "unexpected policy: {body}");

        let policies = router.route_body_policies();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].pattern, "/api/upload");
        assert_eq!(
            policies[0]
                .effective_policy
                .expect("configured nested route has effective policy")
                .max_total_body_size,
            64
        );
    }

    #[test]
    fn route_only_policy_runtime_and_metadata_agree_above_defaults() {
        let route = RequestBodyPolicy::new()
            .max_total_body_size(64 * 1024 * 1024)
            .body_limits(
                BodyLimits::new()
                    .max_json_body_size(32 * 1024 * 1024)
                    .max_form_body_size(4 * 1024 * 1024)
                    .max_raw_body_size(24 * 1024 * 1024),
            );
        let router = Router::new().route(
            "/upload",
            post(FnHandler1::<_, Extension<RequestBodyPolicy>>::new(
                body_policy_summary,
            ))
            .with_body_policy(route),
        );

        let response = router.handle(Request::new("POST", "/upload"));
        let body = std::str::from_utf8(response.body.as_ref()).expect("policy response is UTF-8");
        assert!(
            body.starts_with("total=67108864;json=33554432;form=4194304;raw=25165824;"),
            "route-only runtime policy was unexpectedly clamped: {body}"
        );
        let metadata = router.route_body_policies();
        assert_eq!(metadata[0].effective_policy, Some(route.resolved()));
    }

    #[test]
    fn partial_legacy_limits_preserve_the_other_inherited_plane() {
        let outer_multipart = MultipartLimits::new()
            .max_total_size(12 * 1024 * 1024)
            .max_part_body_size(6 * 1024 * 1024)
            .max_parts(17);
        let nested_body = BodyLimits::new()
            .max_json_body_size(8 * 1024 * 1024)
            .max_form_body_size(1024 * 1024)
            .max_raw_body_size(8 * 1024 * 1024);
        let nested = Router::new()
            .route(
                "/upload",
                post(FnHandler1::<_, Extension<RequestBodyPolicy>>::new(
                    body_policy_summary,
                ))
                .with_body_policy(RequestBodyPolicy::new()),
            )
            .with_state(nested_body);
        let router = Router::new()
            .nest("/api", nested)
            .with_state(outer_multipart);

        let response = router.handle(Request::new("POST", "/api/upload"));
        let body = std::str::from_utf8(response.body.as_ref()).expect("policy response is UTF-8");
        assert!(body.contains("json=8388608;form=1048576;raw=8388608;"));
        assert!(body.contains("multipart=12582912;field=6291456;parts=17;"));

        let metadata = router.route_body_policies();
        let effective = metadata[0]
            .effective_policy
            .expect("route policy promotes legacy limits");
        assert_eq!(effective.body_limits, nested_body);
        assert_eq!(effective.multipart_limits, outer_multipart);
    }

    #[test]
    fn legacy_body_limits_remain_supported_without_explicit_policy() {
        let legacy = BodyLimits::new()
            .max_json_body_size(32 * 1024 * 1024)
            .max_form_body_size(4 * 1024 * 1024)
            .max_raw_body_size(24 * 1024 * 1024);
        let router = Router::new()
            .route(
                "/legacy",
                post(FnHandler1::<_, Extension<BodyLimits>>::new(
                    body_limits_summary,
                )),
            )
            .with_state(legacy);

        let response = router.handle(Request::new("POST", "/legacy"));
        let body = std::str::from_utf8(response.body.as_ref()).expect("policy response is UTF-8");
        assert!(
            body == "json=33554432;form=4194304;raw=25165824",
            "legacy limits were not preserved: {body}"
        );
        assert_eq!(router.route_body_policies()[0].effective_policy, None);
    }

    #[test]
    fn body_policy_legacy_only_nested_body_limits_keep_inner_precedence() {
        let outer = BodyLimits::new().max_json_body_size(4);
        let inner = BodyLimits::new().max_json_body_size(64);
        let nested = Router::new()
            .route(
                "/legacy",
                post(FnHandler1::<_, Extension<BodyLimits>>::new(
                    body_limits_summary,
                )),
            )
            .with_state(inner);
        let router = Router::new().with_state(outer).nest("/api", nested);

        let response = router.handle(Request::new("POST", "/api/legacy"));
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            std::str::from_utf8(response.body.as_ref()).expect("legacy response is UTF-8"),
            "json=64;form=2097152;raw=10485760"
        );
        assert_eq!(router.route_body_policies()[0].effective_policy, None);
    }

    #[test]
    fn explicit_policy_and_legacy_limits_meet_instead_of_shadowing() {
        let explicit = RequestBodyPolicy::new()
            .max_total_body_size(100)
            .body_limits(BodyLimits::new().max_json_body_size(80));
        let legacy = BodyLimits::new().max_json_body_size(50);
        let router = Router::new()
            .route(
                "/mixed",
                post(FnHandler1::<_, Extension<RequestBodyPolicy>>::new(
                    body_policy_summary,
                )),
            )
            .with_state(explicit)
            .with_state(legacy);

        let response = router.handle(Request::new("POST", "/mixed"));
        let body = std::str::from_utf8(response.body.as_ref()).expect("policy response is UTF-8");
        assert!(
            body.starts_with("total=100;json=50;"),
            "unexpected policy: {body}"
        );
        assert_eq!(
            router.route_body_policies()[0]
                .effective_policy
                .expect("mixed policy is discoverable")
                .body_limits
                .max_json_body_size,
            50
        );
    }

    #[test]
    fn body_diagnostic_route_total_policy_rejects_actual_and_declared_lengths() {
        let policy = RequestBodyPolicy::new().max_total_body_size(4);
        let router = Router::new().route(
            "/ignore",
            post(FnHandler::new(ok_handler)).with_body_policy(policy),
        );

        let actual =
            router.handle(Request::new("POST", "/ignore").with_body(Bytes::from_static(b"12345")));
        assert_eq!(actual.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            actual.body.as_ref(),
            b"[ASUP-E505] request body too large (limit 4)"
        );

        let declared =
            router.handle(Request::new("POST", "/ignore").with_header("content-length", "5"));
        assert_eq!(declared.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            declared.body.as_ref(),
            b"[ASUP-E505] request body too large (limit 4)"
        );

        let mut mixed_case = Request::new("POST", "/ignore");
        mixed_case
            .headers
            .insert("Content-Length".to_string(), "5".to_string());
        let mixed_case = router.handle(mixed_case);
        assert_eq!(mixed_case.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(mixed_case.body.starts_with(b"[ASUP-E505] "));

        for invalid in ["5, 6", "+5", "184467440737095516160"] {
            let response = router
                .handle(Request::new("POST", "/ignore").with_header("content-length", invalid));
            assert_eq!(response.status, StatusCode::BAD_REQUEST, "value={invalid}");
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn body_policy_route_tightens_live_writer_before_handler_extraction() {
        use crate::http::h1::types::{Method, Version};
        use crate::http::h1::{RequestHead, StreamingServerRequest};

        let cx = crate::Cx::for_testing();
        let head = RequestHead {
            method: Method::Post,
            uri: "/streamed".to_string(),
            version: Version::Http11,
            headers: vec![("transfer-encoding".to_string(), "chunked".to_string())],
        };
        let (writer, request) = StreamingServerRequest::channel(head, &cx, 8);
        let router = Router::new().route(
            "/streamed",
            post(BodyPolicyWriterProbe {
                writer: parking_lot::Mutex::new(Some(writer)),
            })
            .with_body_policy(RequestBodyPolicy::new().max_total_body_size(6)),
        );

        let response = futures_lite::future::block_on(
            router.handle_http1_streaming_request_with_cx(&cx, request),
        );
        assert_eq!(response.status, 413);
    }

    #[test]
    fn route_body_policy_rejects_declared_json_length_before_parsing() {
        let route_policy = RequestBodyPolicy::new()
            .max_total_body_size(4)
            .body_limits(BodyLimits::new().max_json_body_size(4));
        let router = Router::new().route(
            "/json",
            post(FnHandler1::<
                _,
                super::super::extract::Json<serde_json::Value>,
            >::new(|_json| StatusCode::OK))
            .with_body_policy(route_policy),
        );
        let request = Request::new("POST", "/json")
            .with_header("content-type", "application/json")
            .with_header("content-length", "5");

        let response = router.handle(request);
        assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn route_exact_match() {
        let router = Router::new().route("/", get(FnHandler::new(ok_handler)));

        let resp = router.handle(Request::new("GET", "/"));
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            router.route_body_policies()[0].effective_policy,
            None,
            "unconfigured routes must not report a phantom first-class policy"
        );
    }

    #[test]
    fn route_not_found() {
        let router = Router::new().route("/", get(FnHandler::new(ok_handler)));

        let resp = router.handle(Request::new("GET", "/missing"));
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn listener_request_conversion_preserves_consumed_fields() {
        use crate::http::h1::types::{Method, Version};

        let request = HttpRequest {
            method: Method::Extension("PURGE".to_string()),
            uri: "https://example.test/cache/42?tenant=blue&fresh=true".to_string(),
            version: Version::Http2,
            headers: vec![
                ("X-Mode".to_string(), "first".to_string()),
                (
                    "Content-Type".to_string(),
                    "application/octet-stream".to_string(),
                ),
                ("x-mode".to_string(), "last".to_string()),
            ],
            body: b"payload".to_vec(),
            trailers: vec![("x-checksum".to_string(), "abc".to_string())],
            peer_addr: Some("127.0.0.1:43210".parse().expect("peer address")),
        };

        let request = web_request_from_http(request);
        assert_eq!(request.method, "PURGE");
        assert_eq!(request.path, "/cache/42");
        assert_eq!(request.query.as_deref(), Some("tenant=blue&fresh=true"));
        assert_eq!(
            request.header("content-type"),
            Some("application/octet-stream")
        );
        assert_eq!(request.header("x-mode"), Some("last"));
        assert_eq!(request.body.as_ref(), b"payload");
    }

    /// An HTTP/2 client may send each cookie as its own field (RFC 9113
    /// §8.2.3). Only the last piece used to survive the conversion, so a
    /// session cookie in an earlier piece was lost (br-asupersync-a1q12q).
    #[test]
    fn listener_request_conversion_joins_split_cookie_fields() {
        use crate::http::h1::types::{Method, Version};
        use crate::web::extract::{CookieJar, FromRequestParts};

        let request = HttpRequest {
            method: Method::Get,
            uri: "/account".to_string(),
            version: Version::Http2,
            headers: vec![
                ("cookie".to_string(), "_ga=1".to_string()),
                ("cookie".to_string(), "session_id=abc123".to_string()),
                ("x-mode".to_string(), "first".to_string()),
                ("Cookie".to_string(), "theme=dark".to_string()),
                ("x-mode".to_string(), "last".to_string()),
            ],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let request = web_request_from_http(request);
        assert_eq!(
            request.header("cookie"),
            Some("_ga=1; session_id=abc123; theme=dark")
        );
        let jar = CookieJar::from_request_parts(&request).expect("cookie jar");
        assert_eq!(jar.get("session_id"), Some("abc123"));
        assert_eq!(jar.len(), 3);
        assert_eq!(
            request.header("x-mode"),
            Some("last"),
            "other fields: last wins"
        );
    }

    /// The same for HTTP/3 (RFC 9114 §4.2.1).
    #[test]
    #[cfg(feature = "http3")]
    fn h3_request_conversion_joins_split_cookie_fields() {
        use crate::http::h3::H3PseudoHeaders;
        use crate::web::extract::{CookieJar, FromRequestParts};

        let head = H3RequestHead::new(
            H3PseudoHeaders {
                method: Some("GET".to_string()),
                scheme: Some("https".to_string()),
                authority: Some("example.test".to_string()),
                path: Some("/account".to_string()),
                ..H3PseudoHeaders::default()
            },
            vec![
                ("cookie".to_string(), "session_id=abc123".to_string()),
                ("cookie".to_string(), "theme=dark".to_string()),
            ],
        )
        .expect("syntactically valid H3 request");

        let request = web_request_from_h3(head, Vec::new());
        let jar = CookieJar::from_request_parts(&request).expect("cookie jar");
        assert_eq!(jar.get("session_id"), Some("abc123"));
        assert_eq!(jar.get("theme"), Some("dark"));
        assert_eq!(request.header("host"), Some("example.test"));
    }

    #[test]
    fn listener_target_conversion_handles_origin_and_empty_absolute_paths() {
        assert_eq!(
            split_http_request_target("/items?q=rust"),
            ("/items".to_string(), Some("q=rust".to_string()))
        );
        assert_eq!(
            split_http_request_target("http://example.test?ready=true"),
            ("/".to_string(), Some("ready=true".to_string()))
        );
        assert_eq!(
            split_http_request_target("https://example.test"),
            ("/".to_string(), None)
        );
        assert_eq!(split_http_request_target("*"), ("*".to_string(), None));
        assert_eq!(
            split_http_request_target("/redirect/http://upstream.test?q=kept"),
            (
                "/redirect/http://upstream.test".to_string(),
                Some("q=kept".to_string())
            )
        );
    }

    #[test]
    fn listener_response_conversion_preserves_ordered_set_cookie_fields() {
        let mut response = Response::new(StatusCode::CREATED, "created");
        response.set_header("x-zeta", "z");
        response.set_header("content-type", "text/plain");
        response.append_set_cookie("session=one; Path=/");
        response.append_set_cookie("csrf=two; Path=/");

        let response = http_response_from_web(response);
        assert_eq!(response.status, 201);
        assert_eq!(response.reason, "Created");
        assert_eq!(response.body, b"created");
        assert_eq!(
            response.headers,
            vec![
                ("content-type".to_string(), "text/plain".to_string()),
                ("x-zeta".to_string(), "z".to_string()),
                ("set-cookie".to_string(), "session=one; Path=/".to_string()),
                ("set-cookie".to_string(), "csrf=two; Path=/".to_string()),
            ]
        );
    }

    #[test]
    #[cfg(feature = "http3")]
    fn body_diagnostic_native_h3_error_classifier_is_causal() {
        use crate::http::h3::NativeH3SessionError;

        let peer_stop = NativeH3SessionError::Transport(NativeQuicConnectionError::Stream(
            QuicStreamError::SendStopped { code: 0x10c },
        ));
        assert_eq!(
            native_h3_produced_error_diagnostic(&peer_stop),
            Some(WebBodyDiagnostic::ClientAbort)
        );

        let local_cancel = NativeH3SessionError::Transport(NativeQuicConnectionError::Cancelled);
        assert_eq!(native_h3_produced_error_diagnostic(&local_cancel), None);

        let producer_state = NativeH3SessionError::InvalidState("duplicate terminal frame");
        assert_eq!(
            native_h3_produced_error_diagnostic(&producer_state),
            Some(WebBodyDiagnostic::ResponseProducerFailure)
        );

        let producer_frame = NativeH3SessionError::Protocol(H3Error::InvalidFrame(
            "response DATA exceeds the configured frame limit",
        ));
        assert_eq!(
            native_h3_produced_error_diagnostic(&producer_frame),
            Some(WebBodyDiagnostic::ResponseProducerFailure)
        );
    }

    #[test]
    #[cfg(feature = "http3")]
    fn body_diagnostic_h3_dispatch_completion_distinguishes_peer_and_local_close() {
        use crate::http::h3::NativeH3SessionError;
        use crate::net::atp::protocol::quic_frames::QuicFrame;
        use crate::net::atp::protocol::varint::VarInt;
        use crate::net::quic_native::{NativeQuicConnectionConfig, PacketNumberSpace};

        fn established_server(cx: &Cx) -> QuicConnection {
            let mut connection = QuicConnection::server(NativeQuicConnectionConfig::default());
            connection.begin_handshake(cx).expect("begin handshake");
            connection
                .mark_handshake_keys_available(cx)
                .expect("install handshake keys");
            connection
                .mark_app_keys_available(cx)
                .expect("install application keys");
            connection.confirm_handshake(cx).expect("confirm handshake");
            connection
        }

        let cx = Cx::for_testing();
        let completion_error = NativeH3SessionError::InvalidState(
            "QUIC connection is not established for HTTP/3 messages",
        );

        let mut peer_closed = established_server(&cx);
        peer_closed
            .inner_mut()
            .process_frame(
                &cx,
                &QuicFrame::ConnectionClose {
                    error_code: VarInt::from_u64_unchecked(0x10c),
                    frame_type: None,
                    reason_phrase: Bytes::from_static(b"peer shutdown"),
                },
                PacketNumberSpace::ApplicationData,
            )
            .expect("peer CONNECTION_CLOSE enters draining");
        assert_eq!(
            native_h3_completion_error_diagnostic(&peer_closed, &completion_error),
            Some(WebBodyDiagnostic::ClientAbort),
            "a peer close after dispatch but before response start is E509"
        );

        let mut locally_closed = established_server(&cx);
        locally_closed
            .begin_close(&cx, 0, 0x10c)
            .expect("local shutdown enters draining");
        assert_eq!(
            native_h3_completion_error_diagnostic(&locally_closed, &completion_error),
            None,
            "a local close after dispatch must not be relabeled as a client abort"
        );
    }

    #[test]
    #[cfg(feature = "http3")]
    fn body_diagnostic_h3_cancel_after_close_reaps_dispatch_ownership() {
        use crate::http::h3::{H3Settings, NativeH3Session};
        use crate::net::atp::protocol::quic_frames::QuicFrame;
        use crate::net::atp::protocol::varint::VarInt;
        use crate::net::quic_native::{
            NativeQuicConnectionConfig, PacketNumberSpace, StreamDirection, StreamRole,
        };

        fn established_server(cx: &Cx) -> QuicConnection {
            let mut connection = QuicConnection::server(NativeQuicConnectionConfig::default());
            connection.begin_handshake(cx).expect("begin handshake");
            connection
                .mark_handshake_keys_available(cx)
                .expect("install handshake keys");
            connection
                .mark_app_keys_available(cx)
                .expect("install application keys");
            connection.confirm_handshake(cx).expect("confirm handshake");
            connection
        }

        let cx = Cx::for_testing();
        let stream_id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);

        let mut peer_connection = established_server(&cx);
        let mut peer_session = NativeH3Session::server();
        peer_session
            .initialize(&cx, &mut peer_connection, H3Settings::default())
            .expect("initialize peer-close session");
        let peer_writer = peer_session
            .start_response_writer(
                &peer_connection,
                stream_id,
                &H3ResponseHead::new(200, Vec::new()).expect("valid response head"),
                false,
            )
            .expect("prepare response writer");
        let mut peer_bridge = NativeH3Router::new(Router::new());
        let producer_cx = Cx::for_testing();
        peer_bridge.in_flight.insert(stream_id, 0);
        peer_bridge.produced.insert(
            stream_id,
            ActiveNativeH3ProducedResponse {
                status: 200,
                writer: peer_writer,
                plan: None,
                body: None,
                lifecycle: None,
                producer_cx: Some(producer_cx.clone()),
                owned_request_cx: None,
                max_data_wire_bytes: 0,
                pending_data: None,
                emitted_bytes: 0,
                terminal: None,
                head_only: false,
                reset_queued: false,
            },
        );
        let peer_token = NativeH3RouterDispatchToken {
            bridge_identity: Arc::clone(&peer_bridge.identity),
            stream_id,
        };
        peer_connection
            .inner_mut()
            .process_frame(
                &cx,
                &QuicFrame::ConnectionClose {
                    error_code: VarInt::from_u64_unchecked(0x10c),
                    frame_type: None,
                    reason_phrase: Bytes::from_static(b"peer shutdown"),
                },
                PacketNumberSpace::ApplicationData,
            )
            .expect("peer CONNECTION_CLOSE enters draining");
        assert_eq!(
            native_h3_closed_connection_diagnostic(&peer_connection),
            Some(WebBodyDiagnostic::ClientAbort)
        );
        assert_eq!(
            peer_bridge
                .cancel_dispatch_with_reason(
                    &cx,
                    &mut peer_session,
                    &mut peer_connection,
                    &peer_token,
                    CancelReason::deadline(),
                )
                .expect("closed peer dispatch cancellation is terminal"),
            NativeH3RouterEvent::RequestRefused {
                stream_id,
                reason: NativeH3RouterRefusal::DispatchCancelled,
            }
        );
        assert_eq!(peer_bridge.in_flight_dispatch_count(), 0);
        assert!(!peer_bridge.produced.contains_key(&stream_id));
        assert!(producer_cx.cancelled_by(CancelKind::ParentCancelled));
        assert!(producer_cx.any_cause_is(CancelKind::Deadline));

        let mut local_connection = established_server(&cx);
        let mut local_session = NativeH3Session::server();
        local_session
            .initialize(&cx, &mut local_connection, H3Settings::default())
            .expect("initialize local-close session");
        let mut local_bridge = NativeH3Router::new(Router::new());
        local_bridge.in_flight.insert(stream_id, 0);
        let local_token = NativeH3RouterDispatchToken {
            bridge_identity: Arc::clone(&local_bridge.identity),
            stream_id,
        };
        local_connection
            .begin_close(&cx, 0, 0x10c)
            .expect("local shutdown enters draining");
        assert_eq!(
            native_h3_closed_connection_diagnostic(&local_connection),
            None
        );
        assert_eq!(
            local_bridge
                .cancel_dispatch_with_cx(
                    &cx,
                    &mut local_session,
                    &mut local_connection,
                    &local_token,
                )
                .expect("closed local dispatch cancellation is terminal"),
            NativeH3RouterEvent::RequestRefused {
                stream_id,
                reason: NativeH3RouterRefusal::DispatchCancelled,
            }
        );
        assert_eq!(local_bridge.in_flight_dispatch_count(), 0);
    }

    #[test]
    #[cfg(feature = "http3")]
    fn h3_producer_cancellation_retains_first_reset_cause() {
        let cx = Cx::for_testing();
        let mut connection = QuicConnection::server(Default::default());
        connection.begin_handshake(&cx).unwrap();
        connection.mark_handshake_keys_available(&cx).unwrap();
        connection.mark_app_keys_available(&cx).unwrap();
        connection.confirm_handshake(&cx).unwrap();
        let mut session = NativeH3Session::server();
        session
            .initialize(&cx, &mut connection, crate::http::h3::H3Settings::default())
            .unwrap();
        let writer = session
            .start_response_writer(
                &connection,
                StreamId(0),
                &H3ResponseHead::new(200, Vec::new()).unwrap(),
                false,
            )
            .unwrap();
        let mut state = ActiveNativeH3ProducedResponse {
            status: 200,
            writer,
            plan: None,
            body: None,
            lifecycle: None,
            producer_cx: Some(cx.clone()),
            owned_request_cx: None,
            max_data_wire_bytes: 0,
            pending_data: None,
            emitted_bytes: 0,
            terminal: None,
            head_only: false,
            reset_queued: false,
        };
        mark_native_h3_produced_cancelled_with_reason(
            &mut state,
            "request deadline",
            Some(CancelReason::deadline()),
        );
        let first = cx.cancel_reason();
        assert!(cx.any_cause_is(CancelKind::Deadline));
        // Lexically earlier generic messages used to replace the cause chain
        // when connection teardown repeated cancellation of a reset response.
        mark_native_h3_produced_cancelled(&mut state, "connection closed");
        assert_eq!(cx.cancel_reason(), first);
        assert!(state.reset_queued);

        cx.cancel_with_reason(CancelReason::shutdown());
        mark_native_h3_produced_cancelled_with_reason(
            &mut state,
            "another timeout",
            Some(CancelReason::timeout()),
        );
        assert!(cx.cancelled_by(CancelKind::Shutdown));
    }

    #[test]
    #[cfg(feature = "http3")]
    fn h3_request_semantics_reject_malformed_length_and_te_before_dispatch() {
        use crate::http::h3::H3PseudoHeaders;

        let head = |headers| {
            H3RequestHead::new(
                H3PseudoHeaders {
                    method: Some("POST".to_string()),
                    scheme: Some("https".to_string()),
                    authority: Some("example.test".to_string()),
                    path: Some("/".to_string()),
                    ..H3PseudoHeaders::default()
                },
                headers,
            )
            .expect("syntactically valid H3 request")
        };

        assert_eq!(
            validate_h3_request_semantics(
                &head(vec![("content-length".to_string(), "4".to_string())]),
                3,
            ),
            Err(NativeH3RouterRefusal::InvalidContentLength)
        );
        assert_eq!(
            validate_h3_request_semantics(
                &head(vec![
                    ("content-length".to_string(), "3".to_string()),
                    ("content-length".to_string(), "3".to_string()),
                ]),
                3,
            ),
            Err(NativeH3RouterRefusal::InvalidContentLength)
        );
        assert_eq!(
            validate_h3_request_semantics(&head(vec![("te".to_string(), "gzip".to_string())]), 0,),
            Err(NativeH3RouterRefusal::InvalidTransferEncoding)
        );
        validate_h3_request_semantics(
            &head(vec![
                ("content-length".to_string(), "3".to_string()),
                ("te".to_string(), "trailers".to_string()),
            ]),
            3,
        )
        .expect("valid HTTP/3 request semantics");
    }

    #[test]
    #[cfg(all(feature = "http2-streaming", not(target_arch = "wasm32")))]
    fn h2_streaming_admission_matches_route_and_nested_policy() {
        let route = |limit| {
            post(FnHandler::new(ok_handler))
                .with_body_policy(RequestBodyPolicy::new().max_total_body_size(limit))
        };
        let router = Router::new()
            .route("/files/*", route(80))
            .route("/files/:id", route(40))
            .route("/files/fixed", route(20))
            .route("/files/:other", route(10))
            .nest(
                "/api",
                Router::new().with_body_policy(RequestBodyPolicy::new().max_total_body_size(50)),
            )
            .nest(
                "/api/private",
                Router::new().with_body_policy(RequestBodyPolicy::new().max_total_body_size(7)),
            )
            .nest(
                "/api/private/",
                Router::new().with_body_policy(RequestBodyPolicy::new().max_total_body_size(2)),
            );
        for (uri, expected) in [
            ("/files/fixed?version=2", 20),
            ("/files/object", 40),
            ("/files/nested/object", 80),
            ("/api/missing", 50),
            ("/api/private/missing", 7),
        ] {
            let head = RequestHead {
                method: crate::http::h1::types::Method::Delete,
                uri: uri.to_string(),
                version: crate::http::h1::types::Version::Http2,
                headers: Vec::new(),
            };
            assert_eq!(
                router
                    .http2_streaming_body_policy(&head)
                    .expect("static policy"),
                Some(expected)
            );
            let (path, _) = split_http_request_target(uri);
            let response = router.handle(
                Request::new("DELETE", path)
                    .with_header("content-length", (expected + 1).to_string()),
            );
            assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
        }
    }

    #[test]
    #[cfg(all(feature = "http2-streaming", not(target_arch = "wasm32")))]
    fn h2_streaming_admission_preserves_transport_and_explicit_limits() {
        let head = RequestHead {
            method: crate::http::h1::types::Method::Post,
            uri: "/upload".to_string(),
            version: crate::http::h1::types::Version::Http2,
            headers: Vec::new(),
        };
        assert_eq!(
            Router::new()
                .http2_streaming_body_policy(&head)
                .expect("no static policy"),
            None
        );
        let limit = 64 * 1024 * 1024;
        let router = Router::new().route(
            "/upload",
            post(FnHandler::new(ok_handler))
                .with_body_policy(RequestBodyPolicy::new().max_total_body_size(limit)),
        );
        assert_eq!(
            router
                .http2_streaming_body_policy(&head)
                .expect("route policy"),
            Some(limit as u64)
        );
        let router =
            router.with_server_body_policy(RequestBodyPolicy::new().max_total_body_size(4));
        assert_eq!(
            router
                .http2_streaming_body_policy(&head)
                .expect("server ceiling"),
            Some(4)
        );
    }

    #[test]
    #[cfg(all(feature = "http3", feature = "tls", not(target_arch = "wasm32")))]
    fn h3_streaming_policy_uses_actual_route_precedence_before_method_lookup() {
        let route = |limit| {
            post(FnHandler::new(ok_handler))
                .with_body_policy(RequestBodyPolicy::new().max_total_body_size(limit))
        };
        let router = Router::new()
            .route("/files/*", route(80))
            .route("/files/:id", route(40))
            .route("/files/fixed", route(20))
            .route("/files/:other", route(10))
            .nest("/files", Router::new().route("/fixed", route(1)));
        for (path, expected) in [
            ("/files/fixed", 20),
            ("/files/object", 40),
            ("/files/nested/object", 80),
        ] {
            let request = Request::new("DELETE", path);
            assert_eq!(
                router.h3_streaming_body_policy_limit(&request),
                Ok(Some(expected)),
                "HEADERS admission must select the route whose dispatch returns 405"
            );
            let response =
                router.handle(request.with_header("content-length", (expected + 1).to_string()));
            assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
        }
    }

    #[test]
    #[cfg(all(feature = "http3", feature = "tls", not(target_arch = "wasm32")))]
    fn h3_streaming_policy_follows_longest_mount_and_keeps_nested_404_policy() {
        let router = Router::new()
            .nest(
                "/api",
                Router::new().with_body_policy(RequestBodyPolicy::new().max_total_body_size(50)),
            )
            .nest(
                "/api/private",
                Router::new().with_body_policy(RequestBodyPolicy::new().max_total_body_size(7)),
            )
            .nest(
                "/api/private/",
                Router::new().with_body_policy(RequestBodyPolicy::new().max_total_body_size(2)),
            )
            .with_server_body_policy(RequestBodyPolicy::new().max_total_body_size(100));
        for (path, expected) in [("/api/missing", 50), ("/api/private/missing", 7)] {
            let request = Request::new("POST", path);
            assert_eq!(
                router.h3_streaming_body_policy_limit(&request),
                Ok(Some(expected))
            );
            let response =
                router.handle(request.with_header("content-length", (expected + 1).to_string()));
            assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
        }
    }

    #[test]
    #[cfg(all(feature = "http3", feature = "tls", not(target_arch = "wasm32")))]
    fn h3_streaming_policy_preserves_unconfigured_and_explicit_ceilings() {
        let unconfigured = Router::new()
            .with_state(BodyLimits::new().max_raw_body_size(3))
            .nest(
                "/nested",
                Router::new()
                    .with_state(BodyLimits::new().max_raw_body_size(30))
                    .route("/upload", post(FnHandler::new(ok_handler))),
            );
        let request = Request::new("POST", "/nested/upload");
        assert_eq!(
            unconfigured.h3_streaming_body_policy_limit(&request),
            Ok(None)
        );

        let large_limit = 64 * 1024 * 1024;
        let explicit_route = Router::new().route(
            "/upload",
            post(FnHandler::new(ok_handler))
                .with_body_policy(RequestBodyPolicy::new().max_total_body_size(large_limit)),
        );
        assert_eq!(
            explicit_route.h3_streaming_body_policy_limit(&Request::new("POST", "/upload")),
            Ok(Some(large_limit)),
            "a static route ceiling is not silently replaced with a default transport limit"
        );

        let constrained =
            unconfigured.with_server_body_policy(RequestBodyPolicy::new().max_total_body_size(4));
        assert_eq!(
            constrained.h3_streaming_body_policy_limit(&request),
            Ok(Some(4))
        );
        let response = constrained.handle(request.with_header("content-length", "5"));
        assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    #[cfg(all(feature = "http3", feature = "tls", not(target_arch = "wasm32")))]
    fn h3_streaming_head_validation_does_not_require_body_completion() {
        use crate::http::h3::H3PseudoHeaders;

        let head = |length: Option<&str>| {
            H3RequestHead::new(
                H3PseudoHeaders {
                    method: Some("POST".to_string()),
                    scheme: Some("https".to_string()),
                    authority: Some("example.test".to_string()),
                    path: Some("/upload".to_string()),
                    ..H3PseudoHeaders::default()
                },
                length
                    .map(|value| vec![("content-length".to_string(), value.to_string())])
                    .unwrap_or_default(),
            )
            .expect("syntactically valid H3 request head")
        };

        let unknown = head(None);
        assert_eq!(validate_h3_request_head_semantics(&unknown), Ok(None));
        assert_eq!(validate_h3_request_semantics(&unknown, 8), Ok(()));

        for (declared, length) in [("0", 0), ("8", 8)] {
            let request = head(Some(declared));
            assert_eq!(
                validate_h3_request_head_semantics(&request),
                Ok(Some(length))
            );
            assert_eq!(validate_h3_request_semantics(&request, length), Ok(()));
            assert_eq!(
                validate_h3_request_semantics(&request, length + 1),
                Err(NativeH3RouterRefusal::InvalidContentLength)
            );
        }
        assert_eq!(
            validate_h3_request_semantics(&head(Some("8")), 0),
            Err(NativeH3RouterRefusal::InvalidContentLength)
        );
    }

    #[test]
    #[cfg(feature = "http3")]
    fn h3_request_semantics_reject_inconsistent_authority_and_host() {
        use crate::http::h3::H3PseudoHeaders;

        let head = |authority: Option<&str>, hosts: &[&str]| {
            H3RequestHead::new(
                H3PseudoHeaders {
                    method: Some("GET".to_string()),
                    scheme: Some("https".to_string()),
                    authority: authority.map(str::to_string),
                    path: Some("/".to_string()),
                    ..H3PseudoHeaders::default()
                },
                hosts
                    .iter()
                    .map(|host| ("host".to_string(), (*host).to_string()))
                    .collect(),
            )
            .expect("syntactically valid H3 request head")
        };

        // Host wins over :authority in the handler's view, so any of these
        // would let it route on a target nothing upstream checked.
        for (authority, hosts) in [
            (Some("api.example"), &["admin.internal"][..]),
            (Some("api.example"), &["api.example", "admin.internal"][..]),
            (None, &["api.example", "api.example"][..]),
            (None, &[""][..]),
            (None, &[][..]),
        ] {
            assert_eq!(
                validate_h3_request_head_semantics(&head(authority, hosts)),
                Err(NativeH3RouterRefusal::InvalidAuthority),
                ":authority {authority:?} with Host {hosts:?}"
            );
        }
        for (authority, hosts) in [
            (Some("api.example"), &[][..]),
            (Some("api.example"), &["API.Example"][..]),
            (None, &["api.example"][..]),
        ] {
            assert_eq!(
                validate_h3_request_head_semantics(&head(authority, hosts)),
                Ok(None),
                ":authority {authority:?} with Host {hosts:?}"
            );
        }
    }

    #[test]
    #[cfg(feature = "http3")]
    fn h3_refusals_reset_with_the_code_that_says_whether_a_retry_is_safe() {
        use crate::http::h3_quic::{H3_REQUEST_CANCELLED, H3_REQUEST_REJECTED};

        // RFC 9114 section 4.1.1: a request no handler has seen, refused for
        // load or lifecycle, is REJECTED so the client may retry it.
        for reason in [
            NativeH3RouterRefusal::TooManyPendingRequests { limit: 1 },
            NativeH3RouterRefusal::TooManyInFlightDispatches { limit: 1 },
            NativeH3RouterRefusal::ConnectionBodyBudgetExhausted { limit: 1 },
            NativeH3RouterRefusal::Draining,
            NativeH3RouterRefusal::ConnectionRetiring,
            NativeH3RouterRefusal::TooManyConcurrentRequests { limit: 1 },
        ] {
            assert_eq!(
                refusal_reset_code(&reason),
                H3_REQUEST_REJECTED,
                "{reason:?}"
            );
        }
        // Section 4.1.2: a malformed request is H3_MESSAGE_ERROR.
        for reason in [
            NativeH3RouterRefusal::InvalidContentLength,
            NativeH3RouterRefusal::InvalidTransferEncoding,
            NativeH3RouterRefusal::InvalidAuthority,
        ] {
            assert_eq!(refusal_reset_code(&reason), 0x010e, "{reason:?}");
        }
        // A request a handler may have seen, or one that would fail again,
        // stays CANCELLED.
        for reason in [
            NativeH3RouterRefusal::ConnectUnsupported,
            NativeH3RouterRefusal::RequestTrailersUnsupported,
            NativeH3RouterRefusal::RequestBodyTooLarge { limit: 1 },
            NativeH3RouterRefusal::DispatchCancelled,
            NativeH3RouterRefusal::RequestAssemblyTimeout,
            NativeH3RouterRefusal::InvalidRequestProgression("test"),
            NativeH3RouterRefusal::InvalidResponse(H3Error::InvalidFrame("test")),
        ] {
            assert_eq!(
                refusal_reset_code(&reason),
                H3_REQUEST_CANCELLED,
                "{reason:?}"
            );
        }
    }

    #[test]
    #[cfg(feature = "http3")]
    fn h3_response_semantics_suppress_head_and_refuse_invalid_final_output() {
        let response = Response::new(StatusCode::OK, "body");
        let (head, body) = h3_response_from_web(response, true).expect("valid HEAD response");
        assert!(body.is_empty());
        assert_eq!(
            head.headers,
            vec![("content-length".to_string(), "4".to_string())]
        );

        let mut mismatch = Response::new(StatusCode::OK, "body");
        mismatch.set_header("content-length", "3");
        assert_eq!(
            h3_response_from_web(mismatch, false),
            Err(H3Error::InvalidFrame(
                "HTTP/3 response content-length does not match body length"
            ))
        );

        let mut invalid_te = Response::new(StatusCode::OK, "body");
        invalid_te.set_header("te", "gzip");
        assert_eq!(
            h3_response_from_web(invalid_te, false),
            Err(H3Error::InvalidFrame("invalid HTTP/3 response TE value"))
        );

        assert_eq!(
            h3_response_from_web(
                Response::new(StatusCode::from_u16(103), Bytes::new()),
                false
            ),
            Err(H3Error::InvalidResponsePseudoHeader(
                "informational status is not a final Router response"
            ))
        );

        for status in [204, 205, 304] {
            assert_eq!(
                h3_response_from_web(
                    Response::new(StatusCode::from_u16(status), "must-not-ship"),
                    false,
                ),
                Err(H3Error::InvalidFrame(
                    "HTTP/3 response status forbids a message body"
                ))
            );
        }

        let mut no_content = Response::new(StatusCode::from_u16(204), Bytes::new());
        no_content.set_header("content-length", "0");
        assert_eq!(
            h3_response_from_web(no_content, false),
            Err(H3Error::InvalidFrame(
                "HTTP 204 response must not include content-length"
            ))
        );

        let mut not_modified = Response::new(StatusCode::from_u16(304), Bytes::new());
        not_modified.set_header("content-length", "123");
        let (head, body) =
            h3_response_from_web(not_modified, false).expect("valid 304 metadata length");
        assert_eq!(head.status, 304);
        assert_eq!(
            head.headers,
            vec![("content-length".to_string(), "123".to_string())]
        );
        assert!(body.is_empty());
    }

    #[test]
    fn explicit_listener_dispatch_runs_router_extractors_and_response_mapping() {
        use crate::http::h1::types::{Method, Version};
        use crate::web::extract::{Path, Query};
        use crate::web::handler::FnHandler2;

        fn handler(
            Path(id): Path<String>,
            Query(query): Query<HashMap<String, String>>,
        ) -> Response {
            let mut response = Response::new(
                StatusCode::OK,
                format!("id={id};q={}", query.get("q").map_or("", String::as_str)),
            );
            response.append_set_cookie("seen=true; Path=/");
            response
        }

        let router = Router::new().route(
            "/items/:id",
            get(FnHandler2::<_, Path<String>, Query<HashMap<String, String>>>::new(handler)),
        );
        let request = HttpRequest {
            method: Method::Get,
            uri: "http://example.test/items/7?q=wire".to_string(),
            version: Version::Http11,
            headers: vec![("host".to_string(), "example.test".to_string())],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let response = futures_lite::future::block_on(
            router.handle_http_request_with_cx(&Cx::for_testing(), request),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"id=7;q=wire");
        assert_eq!(
            response
                .headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>(),
            vec!["seen=true; Path=/"]
        );
    }

    #[test]
    fn listener_handler_is_shared_by_h1_and_h2_and_fails_closed_without_cx() {
        use crate::http::h2::listener::IntoHttp2Response;

        fn accepts_h1<F, Fut>(_handler: &F)
        where
            F: Fn(HttpRequest) -> Fut + Clone + Send + Sync + 'static,
            Fut: Future<Output = HttpResponse> + Send + 'static,
        {
        }

        fn accepts_h2<F, Fut, R>(_handler: &F)
        where
            F: Fn(HttpRequest) -> Fut + Clone + Send + Sync + 'static,
            Fut: Future<Output = R> + Send + 'static,
            R: IntoHttp2Response + Send + 'static,
        {
        }

        let handler = Router::new()
            .route("/", get(FnHandler::new(ok_handler)))
            .into_http_handler();
        accepts_h1(&handler);
        accepts_h2(&handler);

        let response = futures_lite::future::block_on(handler(HttpRequest::get("/").build()));
        assert_eq!(response.status, 500);
        assert_eq!(response.body, b"request context unavailable");
    }

    #[test]
    fn route_method_not_allowed() {
        let router = Router::new().route("/", get(FnHandler::new(ok_handler)));

        let resp = router.handle(Request::new("POST", "/"));
        assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(resp.header_value("allow"), Some("GET"));
    }

    #[test]
    fn head_is_answered_by_the_get_handler_when_none_is_registered() {
        // RFC 9110 §9.1: all general-purpose servers MUST support GET and
        // HEAD. A GET-only route answered HEAD with 405.
        let router = Router::new()
            .route("/", get(FnHandler::new(ok_handler)))
            .route("/post-only", post(FnHandler::new(created_handler)))
            .route(
                "/both",
                get(FnHandler::new(ok_handler)).head(FnHandler::new(created_handler)),
            );
        assert_eq!(
            router.handle(Request::new("HEAD", "/")).status,
            StatusCode::OK
        );
        assert_eq!(
            router.handle(Request::new("head", "/")).status,
            StatusCode::OK
        );
        // An explicit HEAD handler still wins, and a route without GET still
        // refuses HEAD.
        assert_eq!(
            router.handle(Request::new("HEAD", "/both")).status,
            StatusCode::CREATED
        );
        let resp = router.handle(Request::new("HEAD", "/post-only"));
        assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(resp.header_value("allow"), Some("POST"));
    }

    #[test]
    fn routing_the_same_pattern_twice_merges_the_methods() {
        // Kept as two routes, the first always matched: POST /a got a 405
        // naming only GET although POST /a was registered.
        let router = Router::new()
            .route("/a", get(FnHandler::new(ok_handler)))
            .route("/a", post(FnHandler::new(created_handler)));

        assert_eq!(
            router.handle(Request::new("GET", "/a")).status,
            StatusCode::OK
        );
        assert_eq!(
            router.handle(Request::new("POST", "/a")).status,
            StatusCode::CREATED
        );
        let resp = router.handle(Request::new("DELETE", "/a"));
        assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(resp.header_value("allow"), Some("GET, POST"));
    }

    #[test]
    fn routing_the_same_pattern_and_method_twice_keeps_the_first_handler() {
        // Merging the registrations let the second GET /a replace the first;
        // the first one answered when each registration was its own route.
        let router = Router::new()
            .route("/a", get(FnHandler::new(ok_handler)))
            .route(
                "/a",
                get(FnHandler::new(created_handler)).post(FnHandler::new(created_handler)),
            );

        assert_eq!(
            router.handle(Request::new("GET", "/a")).status,
            StatusCode::OK
        );
        assert_eq!(
            router.handle(Request::new("POST", "/a")).status,
            StatusCode::CREATED
        );
    }

    #[test]
    fn route_with_params() {
        use crate::web::extract::Path;
        use crate::web::handler::FnHandler1;

        fn get_user(Path(id): Path<String>) -> String {
            format!("user:{id}")
        }

        let router = Router::new().route(
            "/users/:id",
            get(FnHandler1::<_, Path<String>>::new(get_user)),
        );

        let resp = router.handle(Request::new("GET", "/users/42"));
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn route_with_typed_path_and_query_extractors() {
        use crate::web::extract::{Path, Query};
        use crate::web::handler::FnHandler2;

        #[derive(serde::Deserialize)]
        struct UserPath {
            id: u64,
        }

        #[derive(serde::Deserialize)]
        struct Pagination {
            page: u32,
            active: bool,
        }

        fn handler(Path(path): Path<UserPath>, Query(query): Query<Pagination>) -> String {
            format!("id:{} page:{} active:{}", path.id, query.page, query.active)
        }

        let router = Router::new().route(
            "/users/:id",
            get(FnHandler2::<_, Path<UserPath>, Query<Pagination>>::new(
                handler,
            )),
        );

        let req = Request::new("GET", "/users/42").with_query("page=3&active=true");
        let resp = router.handle(req);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body.as_ref(), b"id:42 page:3 active:true");
    }

    #[test]
    fn route_with_typed_query_error_returns_400() {
        use crate::web::extract::Query;
        use crate::web::handler::FnHandler1;

        #[derive(serde::Deserialize)]
        #[allow(dead_code)] // fields read via deserialization
        struct Pagination {
            page: u32,
        }

        fn handler(Query(_query): Query<Pagination>) -> &'static str {
            "ok"
        }

        let router = Router::new().route(
            "/items",
            get(FnHandler1::<_, Query<Pagination>>::new(handler)),
        );

        let req = Request::new("GET", "/items").with_query("page=not-a-number");
        let resp = router.handle(req);
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn route_with_typed_state() {
        use crate::web::extract::State;
        use crate::web::handler::FnHandler1;

        #[derive(Clone)]
        struct AppState {
            greeting: &'static str,
        }

        fn greet(State(state): State<AppState>) -> String {
            state.greeting.to_string()
        }

        let router = Router::new()
            .route("/", get(FnHandler1::<_, State<AppState>>::new(greet)))
            .with_state(AppState { greeting: "hello" });

        let resp = router.handle(Request::new("GET", "/"));
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body.as_ref(), b"hello");
    }

    #[test]
    fn route_with_typed_state_missing_returns_500() {
        use crate::web::extract::State;
        use crate::web::handler::FnHandler1;

        #[derive(Clone)]
        struct AppState;

        fn handler(State(_state): State<AppState>) -> &'static str {
            "ok"
        }

        let router = Router::new().route("/", get(FnHandler1::<_, State<AppState>>::new(handler)));

        let resp = router.handle(Request::new("GET", "/"));
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn route_with_multiple_typed_states() {
        use crate::web::extract::State;
        use crate::web::handler::FnHandler2;

        #[derive(Clone)]
        struct AppState {
            name: &'static str,
        }

        #[derive(Clone)]
        struct FeatureFlags {
            beta: bool,
        }

        fn handler(State(app): State<AppState>, State(flags): State<FeatureFlags>) -> String {
            format!("{}:{}", app.name, flags.beta)
        }

        let router = Router::new()
            .route(
                "/",
                get(FnHandler2::<_, State<AppState>, State<FeatureFlags>>::new(
                    handler,
                )),
            )
            .with_state(AppState { name: "router" })
            .with_state(FeatureFlags { beta: true });

        let resp = router.handle(Request::new("GET", "/"));
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body.as_ref(), b"router:true");
    }

    #[test]
    fn route_with_state_same_type_last_insert_wins() {
        use crate::web::extract::State;
        use crate::web::handler::FnHandler1;

        #[derive(Clone)]
        struct AppState {
            value: &'static str,
        }

        fn handler(State(app): State<AppState>) -> String {
            app.value.to_string()
        }

        let router = Router::new()
            .route("/", get(FnHandler1::<_, State<AppState>>::new(handler)))
            .with_state(AppState { value: "first" })
            .with_state(AppState { value: "second" });

        let resp = router.handle(Request::new("GET", "/"));
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body.as_ref(), b"second");
    }

    #[test]
    fn route_multiple_methods() {
        fn post_handler() -> StatusCode {
            StatusCode::CREATED
        }

        let router = Router::new().route(
            "/items",
            get(FnHandler::new(ok_handler)).post(FnHandler::new(post_handler)),
        );

        let resp_get = router.handle(Request::new("GET", "/items"));
        assert_eq!(resp_get.status, StatusCode::OK);

        let resp_post = router.handle(Request::new("POST", "/items"));
        assert_eq!(resp_post.status, StatusCode::CREATED);

        let resp_patch = router.handle(Request::new("PATCH", "/items"));
        assert_eq!(resp_patch.status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(resp_patch.header_value("allow"), Some("GET, POST"));
    }

    #[test]
    fn route_priority_literal_before_param() {
        use crate::web::extract::Path;
        use crate::web::handler::FnHandler1;

        fn param_handler(Path(_id): Path<String>) -> StatusCode {
            StatusCode::CREATED
        }

        let router = Router::new()
            .route("/users/me", get(FnHandler::new(ok_handler)))
            .route(
                "/users/:id",
                get(FnHandler1::<_, Path<String>>::new(param_handler)),
            );

        let resp = router.handle(Request::new("GET", "/users/me"));
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn route_priority_param_before_literal() {
        use crate::web::extract::Path;
        use crate::web::handler::FnHandler1;

        fn param_handler(Path(_id): Path<String>) -> StatusCode {
            StatusCode::CREATED
        }

        let router = Router::new()
            .route(
                "/users/:id",
                get(FnHandler1::<_, Path<String>>::new(param_handler)),
            )
            .route("/users/me", get(FnHandler::new(ok_handler)));

        let resp = router.handle(Request::new("GET", "/users/me"));
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn route_priority_literal_before_wildcard() {
        use crate::web::extract::Path;
        use crate::web::handler::FnHandler1;

        fn wildcard_handler(
            Path(_params): Path<std::collections::HashMap<String, String>>,
        ) -> StatusCode {
            StatusCode::ACCEPTED
        }

        let router = Router::new()
            .route("/files/static", get(FnHandler::new(ok_handler)))
            .route(
                "/files/*",
                get(FnHandler1::<
                    _,
                    Path<std::collections::HashMap<String, String>>,
                >::new(wildcard_handler)),
            );

        let resp = router.handle(Request::new("GET", "/files/static"));
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn route_priority_wildcard_cannot_shadow_literal() {
        use crate::web::extract::Path;
        use crate::web::handler::FnHandler1;

        fn wildcard_handler(
            Path(_params): Path<std::collections::HashMap<String, String>>,
        ) -> StatusCode {
            StatusCode::ACCEPTED
        }

        let router = Router::new()
            .route(
                "/files/*",
                get(FnHandler1::<
                    _,
                    Path<std::collections::HashMap<String, String>>,
                >::new(wildcard_handler))
                .post(FnHandler1::<
                    _,
                    Path<std::collections::HashMap<String, String>>,
                >::new(wildcard_handler)),
            )
            .route("/files/static", get(FnHandler::new(ok_handler)));

        let resp = router.handle(Request::new("GET", "/files/static"));
        assert_eq!(resp.status, StatusCode::OK);

        let resp = router.handle(Request::new("POST", "/files/static"));
        assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn route_priority_wildcard_cannot_shadow_parameter_auth_path() {
        use crate::web::extract::Path;
        use crate::web::handler::FnHandler1;

        fn public_wildcard(
            Path(_params): Path<std::collections::HashMap<String, String>>,
        ) -> StatusCode {
            StatusCode::OK
        }

        fn protected_param(Path(_tenant): Path<String>) -> StatusCode {
            StatusCode::UNAUTHORIZED
        }

        let router = Router::new()
            .route(
                "/admin/*",
                get(FnHandler1::<
                    _,
                    Path<std::collections::HashMap<String, String>>,
                >::new(public_wildcard))
                .post(FnHandler1::<
                    _,
                    Path<std::collections::HashMap<String, String>>,
                >::new(public_wildcard)),
            )
            .route(
                "/admin/:tenant/secret",
                get(FnHandler1::<_, Path<String>>::new(protected_param)),
            );

        let resp = router.handle(Request::new("GET", "/admin/acme/secret"));
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);

        let resp = router.handle(Request::new("POST", "/admin/acme/secret"));
        assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn nested_router() {
        let api = Router::new().route("/users", get(FnHandler::new(ok_handler)));

        let app = Router::new().nest("/api/v1", api);

        let resp = app.handle(Request::new("GET", "/api/v1/users"));
        assert_eq!(resp.status, StatusCode::OK);

        let resp = app.handle(Request::new("GET", "/other"));
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn nested_router_top_level_priority() {
        let api = Router::new().route("/users", get(FnHandler::new(created_handler)));

        let app = Router::new()
            .route("/api/v1/users", get(FnHandler::new(ok_handler)))
            .nest("/api/v1", api);

        let resp = app.handle(Request::new("POST", "/api/v1/users"));
        assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn nested_router_typed_state_override_prefers_nested_router() {
        use crate::web::extract::State;
        use crate::web::handler::FnHandler1;

        #[derive(Clone)]
        struct AppState {
            greeting: &'static str,
        }

        fn handler(State(state): State<AppState>) -> String {
            state.greeting.to_string()
        }

        let api = Router::new()
            .route("/", get(FnHandler1::<_, State<AppState>>::new(handler)))
            .with_state(AppState { greeting: "nested" });

        let app = Router::new()
            .with_state(AppState { greeting: "parent" })
            .nest("/api", api);

        let resp = app.handle(Request::new("GET", "/api/"));
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body.as_ref(), b"nested");
    }

    #[test]
    fn nested_router_trailing_slash_prefix() {
        let api = Router::new().route("/users", get(FnHandler::new(ok_handler)));

        let app = Router::new().nest("/api/v1/", api);

        let resp = app.handle(Request::new("GET", "/api/v1/users/"));
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn nested_router_trailing_slash_prefix_rejects_slashless_boundary() {
        let api = Router::new().route("/", get(FnHandler::new(created_handler)));

        let app = Router::new()
            .nest("/api/v1/", api)
            .fallback(FnHandler::new(ok_handler));

        let resp = app.handle(Request::new("GET", "/api/v1"));
        assert_eq!(resp.status, StatusCode::OK);

        let resp = app.handle(Request::new("GET", "/api/v1/"));
        assert_eq!(resp.status, StatusCode::CREATED);
    }

    #[test]
    fn nested_router_prefers_most_specific_prefix() {
        let broad = Router::new().route("/health", get(FnHandler::new(ok_handler)));
        let specific = Router::new().route("/users", get(FnHandler::new(created_handler)));

        // Register broader prefix first: the router should still pick `/api/v1`.
        let app = Router::new().nest("/api", broad).nest("/api/v1", specific);

        let resp = app.handle(Request::new("GET", "/api/v1/users"));
        assert_eq!(resp.status, StatusCode::CREATED);
    }

    #[test]
    fn fallback_handler() {
        let router = Router::new()
            .route("/", get(FnHandler::new(ok_handler)))
            .fallback(FnHandler::new(not_found_handler));

        let resp = router.handle(Request::new("GET", "/missing"));
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn route_pattern_matching() {
        let pattern = RoutePattern::parse("/users/:id");
        let params = pattern.matches("/users/42").unwrap().params;
        assert_eq!(params.get("id").unwrap(), "42");

        assert!(pattern.matches("/users").is_none());
        assert!(pattern.matches("/users/42/extra").is_none());
    }

    #[test]
    fn route_pattern_multiple_params() {
        let pattern = RoutePattern::parse("/users/:uid/posts/:pid");
        let params = pattern.matches("/users/1/posts/99").unwrap().params;
        assert_eq!(params.get("uid").unwrap(), "1");
        assert_eq!(params.get("pid").unwrap(), "99");
    }

    #[test]
    fn route_pattern_wildcard() {
        let pattern = RoutePattern::parse("/files/*");
        let params = pattern.matches("/files/a/b/c").unwrap().params;
        assert_eq!(params.get("*").unwrap(), "a/b/c");
    }

    #[test]
    fn route_pattern_wildcard_empty_rest() {
        use crate::web::extract::Path;
        use crate::web::handler::FnHandler1;

        fn wildcard_handler(
            Path(params): Path<std::collections::HashMap<String, String>>,
        ) -> String {
            params.get("*").cloned().unwrap_or_default()
        }

        let router = Router::new().route(
            "/files/*",
            get(FnHandler1::<
                _,
                Path<std::collections::HashMap<String, String>>,
            >::new(wildcard_handler)),
        );

        let resp = router.handle(Request::new("GET", "/files"));
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "");
    }

    #[test]
    fn route_pattern_literal_only() {
        let pattern = RoutePattern::parse("/health");
        assert!(pattern.matches("/health").is_some());
        assert!(pattern.matches("/other").is_none());
    }

    #[test]
    fn route_trailing_slash_matches() {
        let router = Router::new().route("/users", get(FnHandler::new(ok_handler)));

        let resp = router.handle(Request::new("GET", "/users/"));
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn router_route_count() {
        let router = Router::new()
            .route("/a", get(FnHandler::new(ok_handler)))
            .route("/b", get(FnHandler::new(ok_handler)));
        assert_eq!(router.route_count(), 2);
    }

    #[test]
    fn router_routes_lists_direct_and_nested_entries_deterministically() {
        let api = Router::new()
            .route(
                "/users",
                post(FnHandler::new(created_handler)).get(FnHandler::new(ok_handler)),
            )
            .route("/", delete(FnHandler::new(not_found_handler)));

        let router = Router::new()
            .route(
                "/items",
                post(FnHandler::new(created_handler)).get(FnHandler::new(ok_handler)),
            )
            .route("/items/:id", delete(FnHandler::new(not_found_handler)))
            .nest("/api", api);

        let routes = router.routes();
        let serialized = serde_json::to_value(&routes).expect("route info must serialize");
        assert_eq!(serialized[0]["method"], "DELETE");
        assert_eq!(serialized[0]["pattern"], "/api");
        assert_eq!(serialized[0]["handler_name"], "FnHandler");
        assert_eq!(serialized[0]["mount_prefix"], "/api");

        let got = routes
            .into_iter()
            .map(|route| {
                (
                    route.method,
                    route.pattern,
                    route.handler_name,
                    route.mount_prefix,
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            got,
            vec![
                (
                    "DELETE".to_string(),
                    "/api".to_string(),
                    "FnHandler",
                    Some("/api".to_string())
                ),
                (
                    "GET".to_string(),
                    "/api/users".to_string(),
                    "FnHandler",
                    Some("/api".to_string())
                ),
                (
                    "POST".to_string(),
                    "/api/users".to_string(),
                    "FnHandler",
                    Some("/api".to_string())
                ),
                ("GET".to_string(), "/items".to_string(), "FnHandler", None),
                ("POST".to_string(), "/items".to_string(), "FnHandler", None),
                (
                    "DELETE".to_string(),
                    "/items/:id".to_string(),
                    "FnHandler",
                    None
                ),
            ]
        );
    }

    #[test]
    fn strip_prefix_basic() {
        assert_eq!(
            strip_prefix("/api/v1/users", "/api/v1"),
            Some("/users".to_string())
        );
        assert_eq!(strip_prefix("/api/v1", "/api/v1"), Some("/".to_string()));
        assert_eq!(strip_prefix("/api/v1/", "/api/v1"), Some("/".to_string()));
        assert!(strip_prefix("/other", "/api/v1").is_none());
    }

    #[test]
    fn strip_prefix_boundary_mismatch() {
        assert!(strip_prefix("/apix/users", "/api").is_none());
        assert!(strip_prefix("/apiary", "/api").is_none());
    }

    #[test]
    fn strip_prefix_trailing_slash_prefix_requires_declared_boundary() {
        assert_eq!(
            strip_prefix("/api/v1/users", "/api/v1/"),
            Some("/users".to_string())
        );
        assert_eq!(strip_prefix("/api/v1/", "/api/v1/"), Some("/".to_string()));
        assert!(strip_prefix("/api/v1", "/api/v1/").is_none());
    }

    #[test]
    fn strip_prefix_rejects_empty_segment_at_mount_boundary() {
        assert!(strip_prefix("/api//users", "/api").is_none());
        assert!(strip_prefix("/api//users", "/api/").is_none());
    }

    /// AUDIT MODULE: Route precedence verification
    ///
    /// AUDIT FINDING: SOUND - Router correctly prioritizes literal segments over
    /// parameter segments. Specificity ordering ensures "/users/me" wins over
    /// "/users/:id" regardless of registration order, preventing parameter capture
    /// of literal paths.
    mod route_precedence_audit {
        use super::*;
        use crate::web::handler::FnHandler;

        fn literal_handler() -> StatusCode {
            StatusCode::OK
        }

        fn param_handler() -> StatusCode {
            StatusCode::ACCEPTED
        }

        fn wildcard_handler() -> StatusCode {
            StatusCode::CREATED
        }

        /// AUDIT: Verify literal route "/users/me" wins over parameter route "/users/:id"
        ///
        /// This is the core requirement - literal segments must take precedence
        /// over parameter segments to prevent unintended parameter capture.
        #[test]
        fn audit_literal_beats_parameter_core_requirement() {
            // Test case 1: Literal route registered first
            let router1 = Router::new()
                .route("/users/me", get(FnHandler::new(literal_handler)))
                .route("/users/:id", get(FnHandler::new(param_handler)))
                .route("/users/*", get(FnHandler::new(wildcard_handler)));

            let resp1 = router1.handle(Request::new("GET", "/users/me"));
            assert_eq!(
                resp1.status,
                StatusCode::OK,
                "Literal route '/users/me' must win over '/users/:id' when registered first"
            );

            // Test case 2: Parameter route registered first
            let router2 = Router::new()
                .route("/users/:id", get(FnHandler::new(param_handler)))
                .route("/users/*", get(FnHandler::new(wildcard_handler)))
                .route("/users/me", get(FnHandler::new(literal_handler)));

            let resp2 = router2.handle(Request::new("GET", "/users/me"));
            assert_eq!(
                resp2.status,
                StatusCode::OK,
                "Literal route '/users/me' must win over '/users/:id' regardless of registration order"
            );

            // AUDIT VERIFICATION: Registration order does not affect precedence
            // Literal segments always beat parameter segments due to specificity
            let resp3 = router2.handle(Request::new("GET", "/users/someone"));
            assert_eq!(
                resp3.status,
                StatusCode::ACCEPTED,
                "Parameter route should still handle non-literal single-segment users"
            );

            let resp4 = router2.handle(Request::new("GET", "/users/some/path"));
            assert_eq!(
                resp4.status,
                StatusCode::CREATED,
                "Wildcard route should remain the least-specific fallback"
            );
        }

        /// AUDIT: Verify multiple literal segments beat mixed patterns
        ///
        /// Routes with more literal segments should win over those with fewer,
        /// even when the total segment count is the same.
        #[test]
        fn audit_multiple_literal_segments_precedence() {
            use crate::web::extract::Path;
            use crate::web::handler::FnHandler1;

            fn param_handler(Path(_params): Path<HashMap<String, String>>) -> StatusCode {
                StatusCode::ACCEPTED
            }

            let router = Router::new()
                .route(
                    "/api/:version/users",
                    get(FnHandler1::<_, Path<HashMap<String, String>>>::new(
                        param_handler,
                    )),
                )
                .route("/api/v1/users", get(FnHandler::new(literal_handler)))
                .route(
                    "/api/:version/:resource",
                    get(FnHandler1::<_, Path<HashMap<String, String>>>::new(
                        param_handler,
                    )),
                );

            // Should match the most specific route (most literal segments)
            let resp = router.handle(Request::new("GET", "/api/v1/users"));
            assert_eq!(
                resp.status,
                StatusCode::OK,
                "Route with more literal segments '/api/v1/users' must win over '/api/:version/users'"
            );
        }

        /// AUDIT: Verify specificity calculation correctness
        ///
        /// Test the underlying specificity calculation to ensure proper ordering.
        #[test]
        fn audit_route_specificity_calculation() {
            let literal_route = RoutePattern::parse("/users/me/profile");
            let mixed_route = RoutePattern::parse("/users/:id/profile");
            let param_route = RoutePattern::parse("/users/:id/:section");
            let wildcard_route = RoutePattern::parse("/users/*");

            let literal_spec = literal_route.specificity();
            let mixed_spec = mixed_route.specificity();
            let param_spec = param_route.specificity();
            let wildcard_spec = wildcard_route.specificity();

            // Verify literal segments count
            assert_eq!(
                literal_spec.literal_segments, 3,
                "Literal route should have 3 literal segments"
            );
            assert_eq!(
                mixed_spec.literal_segments, 2,
                "Mixed route should have 2 literal segments"
            );
            assert_eq!(
                param_spec.literal_segments, 1,
                "Param route should have 1 literal segment"
            );
            assert_eq!(
                wildcard_spec.literal_segments, 1,
                "Wildcard route should have 1 literal segment"
            );

            // Verify parameter segments count
            assert_eq!(
                literal_spec.param_segments, 0,
                "Literal route should have 0 parameter segments"
            );
            assert_eq!(
                mixed_spec.param_segments, 1,
                "Mixed route should have 1 parameter segment"
            );
            assert_eq!(
                param_spec.param_segments, 2,
                "Param route should have 2 parameter segments"
            );
            assert_eq!(
                wildcard_spec.param_segments, 0,
                "Wildcard route should have 0 parameter segments (wildcard is separate)"
            );

            // Verify precedence ordering
            assert!(
                literal_spec > mixed_spec,
                "Literal route must be more specific than mixed route"
            );
            assert!(
                mixed_spec > param_spec,
                "Mixed route must be more specific than parameter route"
            );
            assert!(
                param_spec > wildcard_spec,
                "Parameter route must be more specific than wildcard route"
            );
        }

        /// AUDIT: Verify complex precedence scenarios
        ///
        /// Test edge cases with multiple competing routes to ensure consistent behavior.
        #[test]
        fn audit_complex_precedence_scenarios() {
            fn route_a() -> &'static str {
                "route_a"
            }
            fn route_b() -> &'static str {
                "route_b"
            }
            fn route_c() -> &'static str {
                "route_c"
            }

            let router = Router::new()
                // Exact match should win
                .route("/api/v1/users/me", get(FnHandler::new(route_a)))
                // Less specific - one parameter
                .route("/api/v1/users/:id", get(FnHandler::new(route_b)))
                // Even less specific - two parameters
                .route("/api/:version/users/:id", get(FnHandler::new(route_c)))
                // Wildcard should be least specific
                .route("/api/*", get(FnHandler::new(|| "wildcard")));

            let resp = router.handle(Request::new("GET", "/api/v1/users/me"));
            assert_eq!(resp.status, StatusCode::OK);
            let body = String::from_utf8(resp.body.to_vec()).unwrap();
            assert_eq!(body, "route_a", "Most specific literal route should win");

            // Test that parameter route still works for other values
            let resp2 = router.handle(Request::new("GET", "/api/v1/users/123"));
            assert_eq!(resp2.status, StatusCode::OK);
            let body2 = String::from_utf8(resp2.body.to_vec()).unwrap();
            assert_eq!(
                body2, "route_b",
                "Parameter route should handle non-literal values"
            );

            let resp3 = router.handle(Request::new("GET", "/api/v2/users/123"));
            assert_eq!(resp3.status, StatusCode::OK);
            let body3 = String::from_utf8(resp3.body.to_vec()).unwrap();
            assert_eq!(
                body3, "route_c",
                "Less-specific parameter route should handle non-v1 versions"
            );
        }

        /// AUDIT: Verify edge case with similar literal paths
        ///
        /// Ensure the router correctly distinguishes between similar literal paths.
        #[test]
        fn audit_similar_literal_paths_distinction() {
            let router = Router::new()
                .route("/users/me", get(FnHandler::new(|| "me")))
                .route("/users/menu", get(FnHandler::new(|| "menu")))
                .route("/users/metrics", get(FnHandler::new(|| "metrics")));

            // Each literal path should match only itself
            let resp_me = router.handle(Request::new("GET", "/users/me"));
            assert_eq!(String::from_utf8(resp_me.body.to_vec()).unwrap(), "me");

            let resp_menu = router.handle(Request::new("GET", "/users/menu"));
            assert_eq!(String::from_utf8(resp_menu.body.to_vec()).unwrap(), "menu");

            let resp_metrics = router.handle(Request::new("GET", "/users/metrics"));
            assert_eq!(
                String::from_utf8(resp_metrics.body.to_vec()).unwrap(),
                "metrics"
            );
        }

        /// AUDIT: Verify precedence with mixed HTTP methods
        ///
        /// Route precedence should work consistently across different HTTP methods.
        #[test]
        fn audit_precedence_across_http_methods() {
            use crate::web::extract::Path;
            use crate::web::handler::FnHandler1;

            fn literal_get() -> &'static str {
                "literal_get"
            }
            fn literal_post() -> &'static str {
                "literal_post"
            }
            fn param_get(Path(_): Path<String>) -> &'static str {
                "param_get"
            }
            fn param_post(Path(_): Path<String>) -> &'static str {
                "param_post"
            }

            let router = Router::new()
                .route(
                    "/users/:id",
                    get(FnHandler1::<_, Path<String>>::new(param_get)).post(FnHandler1::<
                        _,
                        Path<String>,
                    >::new(
                        param_post
                    )),
                )
                .route(
                    "/users/me",
                    get(FnHandler::new(literal_get)).post(FnHandler::new(literal_post)),
                );

            // GET method should prefer literal route
            let resp_get = router.handle(Request::new("GET", "/users/me"));
            assert_eq!(
                String::from_utf8(resp_get.body.to_vec()).unwrap(),
                "literal_get"
            );

            // POST method should prefer literal route
            let resp_post = router.handle(Request::new("POST", "/users/me"));
            assert_eq!(
                String::from_utf8(resp_post.body.to_vec()).unwrap(),
                "literal_post"
            );
        }

        /// AUDIT: Verify that parameter routes still capture when appropriate
        ///
        /// Ensure parameter routes work correctly when no literal match exists.
        #[test]
        fn audit_parameter_routes_capture_when_appropriate() {
            use crate::web::extract::Path;
            use crate::web::handler::FnHandler1;

            fn param_handler(Path(id): Path<String>) -> String {
                format!("captured:{}", id)
            }

            let router = Router::new()
                .route(
                    "/users/me",
                    get(FnHandler::new(|| "literal:me".to_string())),
                )
                .route(
                    "/users/:id",
                    get(FnHandler1::<_, Path<String>>::new(param_handler)),
                );

            // Literal should win for exact match
            let resp_me = router.handle(Request::new("GET", "/users/me"));
            assert_eq!(
                String::from_utf8(resp_me.body.to_vec()).unwrap(),
                "literal:me"
            );

            // Parameter should capture other values
            let resp_123 = router.handle(Request::new("GET", "/users/123"));
            assert_eq!(
                String::from_utf8(resp_123.body.to_vec()).unwrap(),
                "captured:123"
            );

            let resp_admin = router.handle(Request::new("GET", "/users/admin"));
            assert_eq!(
                String::from_utf8(resp_admin.body.to_vec()).unwrap(),
                "captured:admin"
            );
        }
    }

    // ─── Router::layer (br-asupersync-server-stack-hardening-eeexl1.3) ──────

    mod layering {
        use super::*;
        use std::sync::{Arc, Mutex};

        /// Test layer that records enter/exit events around the inner handler.
        #[derive(Clone)]
        struct RecordingLayer {
            name: &'static str,
            log: Arc<Mutex<Vec<String>>>,
        }

        impl RecordingLayer {
            fn new(name: &'static str, log: Arc<Mutex<Vec<String>>>) -> Self {
                Self { name, log }
            }
        }

        struct RecordingMiddleware<H> {
            inner: H,
            name: &'static str,
            log: Arc<Mutex<Vec<String>>>,
        }

        impl<H: Handler> Layer<H> for RecordingLayer {
            type Service = RecordingMiddleware<H>;

            fn layer(&self, inner: H) -> Self::Service {
                RecordingMiddleware {
                    inner,
                    name: self.name,
                    log: Arc::clone(&self.log),
                }
            }
        }

        impl<H: Handler> Handler for RecordingMiddleware<H> {
            fn call(
                &self,
                cx: &Cx,
                req: Request,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>>
            {
                let cx = cx.clone();
                Box::pin(async move {
                    self.log
                        .lock()
                        .expect("log lock")
                        .push(format!("enter:{}", self.name));
                    let resp = self.inner.call(&cx, req).await;
                    self.log
                        .lock()
                        .expect("log lock")
                        .push(format!("exit:{}", self.name));
                    resp
                })
            }
        }

        fn recording_handler(log: Arc<Mutex<Vec<String>>>) -> impl Handler {
            struct H(Arc<Mutex<Vec<String>>>);
            impl Handler for H {
                fn call(
                    &self,
                    _cx: &Cx,
                    _req: Request,
                ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>>
                {
                    Box::pin(async move {
                        self.0.lock().expect("log lock").push("handler".to_string());
                        StatusCode::OK.into_response()
                    })
                }
            }
            H(log)
        }

        /// Golden execution-order trace for three stacked layers.
        ///
        /// Documented contract: the LAST-added layer is the OUTERMOST — it
        /// sees the request first and the response last.
        #[test]
        fn layer_execution_order_golden() {
            let log = Arc::new(Mutex::new(Vec::new()));
            let router = Router::new()
                .route("/traced", get(recording_handler(Arc::clone(&log))))
                .layer(RecordingLayer::new("auth", Arc::clone(&log)))
                .layer(RecordingLayer::new("trace", Arc::clone(&log)))
                .layer(RecordingLayer::new("request_id", Arc::clone(&log)));

            let resp = router.handle(Request::new("GET", "/traced"));
            assert_eq!(resp.status, StatusCode::OK);

            let golden = vec![
                "enter:request_id".to_string(),
                "enter:trace".to_string(),
                "enter:auth".to_string(),
                "handler".to_string(),
                "exit:auth".to_string(),
                "exit:trace".to_string(),
                "exit:request_id".to_string(),
            ];
            assert_eq!(
                *log.lock().expect("log lock"),
                golden,
                "onion ordering: last-added layer must be outermost"
            );
        }

        #[test]
        fn routes_added_after_layer_are_not_wrapped() {
            let log = Arc::new(Mutex::new(Vec::new()));
            let router = Router::new()
                .route("/wrapped", get(FnHandler::new(ok_handler)))
                .layer(RecordingLayer::new("mw", Arc::clone(&log)))
                .route("/bare", get(FnHandler::new(ok_handler)));

            let _ = router.handle(Request::new("GET", "/bare"));
            assert!(
                log.lock().expect("log lock").is_empty(),
                "route added after .layer() must not be wrapped"
            );

            let _ = router.handle(Request::new("GET", "/wrapped"));
            assert_eq!(
                *log.lock().expect("log lock"),
                vec!["enter:mw".to_string(), "exit:mw".to_string()],
                "route added before .layer() must be wrapped"
            );
        }

        #[test]
        fn layer_wraps_fallback() {
            let log = Arc::new(Mutex::new(Vec::new()));
            let router = Router::new()
                .fallback(FnHandler::new(not_found_handler))
                .layer(RecordingLayer::new("mw", Arc::clone(&log)));

            let resp = router.handle(Request::new("GET", "/nope"));
            assert_eq!(resp.status, StatusCode::NOT_FOUND);
            assert_eq!(
                *log.lock().expect("log lock"),
                vec!["enter:mw".to_string(), "exit:mw".to_string()],
                "fallback handler must be wrapped by .layer()"
            );
        }

        #[test]
        fn layer_wraps_method_not_allowed() {
            let log = Arc::new(Mutex::new(Vec::new()));
            let router = Router::new()
                .route("/traced", get(FnHandler::new(ok_handler)))
                .layer(RecordingLayer::new("mw", Arc::clone(&log)));

            let resp = router.handle(Request::new("POST", "/traced"));
            assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(resp.header_value("allow"), Some("GET"));
            assert_eq!(
                *log.lock().expect("log lock"),
                vec!["enter:mw".to_string(), "exit:mw".to_string()],
                "method-not-allowed must be wrapped by .layer()"
            );
        }

        #[test]
        fn merge_preserves_method_not_allowed_layers_asupersync_vftw38_item8() {
            let log = Arc::new(Mutex::new(Vec::new()));
            let router = Router::new()
                .route("/item", get(FnHandler::new(ok_handler)))
                .layer(RecordingLayer::new("mw", Arc::clone(&log)))
                .route("/item", post(FnHandler::new(created_handler)));

            let resp = router.handle(Request::new("DELETE", "/item"));
            assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(resp.header_value("allow"), Some("GET, POST"));
            assert_eq!(
                *log.lock().expect("log lock"),
                vec!["enter:mw".to_string(), "exit:mw".to_string()],
                "method-not-allowed must retain layer wrapping across merge"
            );
        }

        #[test]
        fn cors_layer_handles_preflight_without_options_route() {
            use crate::web::middleware::{CorsLayer, CorsPolicy};

            let router = Router::new()
                .route("/cors", get(FnHandler::new(ok_handler)))
                .layer(CorsLayer::new(CorsPolicy::default()));

            let resp = router.handle(
                Request::new("OPTIONS", "/cors")
                    .with_header("Origin", "https://example.com")
                    .with_header("Access-Control-Request-Method", "POST")
                    .with_header("Access-Control-Request-Headers", "content-type"),
            );

            assert_eq!(resp.status, StatusCode::NO_CONTENT);
            assert_eq!(
                resp.headers.get("access-control-allow-origin"),
                Some(&"*".to_string())
            );
            assert!(resp.headers.contains_key("access-control-allow-methods"));
            assert!(resp.headers.contains_key("access-control-allow-headers"));
        }

        #[test]
        fn layer_wraps_nested_routers() {
            let log = Arc::new(Mutex::new(Vec::new()));
            let api = Router::new().route("/users", get(FnHandler::new(ok_handler)));
            let router = Router::new()
                .nest("/api", api)
                .layer(RecordingLayer::new("mw", Arc::clone(&log)));

            let resp = router.handle(Request::new("GET", "/api/users"));
            assert_eq!(resp.status, StatusCode::OK);
            assert_eq!(
                *log.lock().expect("log lock"),
                vec!["enter:mw".to_string(), "exit:mw".to_string()],
                "nested router handlers must be wrapped by .layer()"
            );
        }

        #[test]
        fn builtin_middleware_layers_compose_on_router() {
            use crate::web::middleware::{
                AuthLayer, AuthPolicy, HeaderOverwrite, SetResponseHeaderLayer,
            };

            let router = Router::new()
                .route("/secure", get(FnHandler::new(ok_handler)))
                .layer(AuthLayer::new(AuthPolicy::exact_bearer("tok")))
                .layer(SetResponseHeaderLayer::new(
                    "x-frame-options",
                    "DENY",
                    HeaderOverwrite::Always,
                ));

            // Unauthorized: auth (inner) rejects; header layer (outer) still stamps.
            let resp = router.handle(Request::new("GET", "/secure"));
            assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
            assert_eq!(
                resp.headers.get("x-frame-options").map(String::as_str),
                Some("DENY")
            );

            // Authorized request flows through to the handler.
            let resp = router
                .handle(Request::new("GET", "/secure").with_header("authorization", "Bearer tok"));
            assert_eq!(resp.status, StatusCode::OK);
            assert_eq!(
                resp.headers.get("x-frame-options").map(String::as_str),
                Some("DENY")
            );
        }

        // ─── Extension<T> lifecycle ──────────────────────────────────────────

        mod extension_lifecycle {
            use super::*;
            use crate::web::extract::Extension;
            use crate::web::handler::FnHandler1;
            use std::sync::atomic::{AtomicU64, Ordering};
            use std::sync::{Arc, Mutex, Weak};

            #[derive(Clone)]
            struct RequestStamp {
                serial: u64,
            }

            /// Middleware that stamps each request with a unique serial.
            #[derive(Clone)]
            struct StampLayer {
                counter: Arc<AtomicU64>,
            }

            struct StampMiddleware<H> {
                inner: H,
                counter: Arc<AtomicU64>,
            }

            impl<H: Handler> Layer<H> for StampLayer {
                type Service = StampMiddleware<H>;

                fn layer(&self, inner: H) -> Self::Service {
                    StampMiddleware {
                        inner,
                        counter: Arc::clone(&self.counter),
                    }
                }
            }

            impl<H: Handler> Handler for StampMiddleware<H> {
                fn call(
                    &self,
                    cx: &Cx,
                    mut req: Request,
                ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>>
                {
                    let serial = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
                    req.extensions.insert_typed(RequestStamp { serial });
                    self.inner.call(cx, req)
                }
            }

            fn stamp_echo_handler() -> impl Handler {
                FnHandler1::<_, Extension<RequestStamp>>::new(
                    |Extension(stamp): Extension<RequestStamp>| format!("serial:{}", stamp.serial),
                )
            }

            /// Insert-in-middleware → extract-in-handler, and cross-request
            /// isolation: every request sees only its own stamp.
            #[test]
            fn middleware_insert_handler_extract_no_cross_request_bleed() {
                let router = Router::new()
                    .route("/stamped", get(stamp_echo_handler()))
                    .layer(StampLayer {
                        counter: Arc::new(AtomicU64::new(0)),
                    });

                let r1 = router.handle(Request::new("GET", "/stamped"));
                let r2 = router.handle(Request::new("GET", "/stamped"));
                let r3 = router.handle(Request::new("GET", "/stamped"));
                assert_eq!(String::from_utf8(r1.body.to_vec()).unwrap(), "serial:1");
                assert_eq!(String::from_utf8(r2.body.to_vec()).unwrap(), "serial:2");
                assert_eq!(String::from_utf8(r3.body.to_vec()).unwrap(), "serial:3");
            }

            /// A handler that asks for a missing extension gets a 500: wiring
            /// bugs must be loud, not silently defaulted.
            #[test]
            fn missing_extension_is_internal_server_error() {
                let router = Router::new().route("/stamped", get(stamp_echo_handler()));
                let resp = router.handle(Request::new("GET", "/stamped"));
                assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
            }

            #[derive(Clone)]
            struct ProbeExt(#[allow(dead_code)] Arc<()>);

            /// Extensions drop with the request: once the request region's
            /// handler run completes, no copy of the extension value survives.
            #[test]
            fn extension_dropped_when_request_region_completes() {
                use crate::web::request_region::{RegionOutcome, RequestRegion};

                let probe = Arc::new(());
                let weak: Weak<()> = Arc::downgrade(&probe);

                let mut req = Request::new("GET", "/probe");
                req.extensions.insert_typed(ProbeExt(probe));

                let handler = FnHandler1::<_, Extension<ProbeExt>>::new(
                    |Extension(_probe): Extension<ProbeExt>| "ok",
                );

                let cx = Cx::for_testing();
                let region = RequestRegion::new(&cx, req);
                let outcome = futures_lite::future::block_on(region.run_handler(&handler));
                assert!(matches!(outcome, RegionOutcome::Ok(_)));

                assert!(
                    weak.upgrade().is_none(),
                    "extension value must drop with the request when the region run completes"
                );
            }

            /// Routed dispatch drops middleware-inserted extensions request by
            /// request: nothing accumulates across calls.
            #[test]
            fn per_request_extensions_do_not_accumulate() {
                let weaks: Arc<Mutex<Vec<Weak<()>>>> = Arc::new(Mutex::new(Vec::new()));

                #[derive(Clone)]
                struct ProbeLayer {
                    weaks: Arc<Mutex<Vec<Weak<()>>>>,
                }

                struct ProbeMiddleware<H> {
                    inner: H,
                    weaks: Arc<Mutex<Vec<Weak<()>>>>,
                }

                impl<H: Handler> Layer<H> for ProbeLayer {
                    type Service = ProbeMiddleware<H>;

                    fn layer(&self, inner: H) -> Self::Service {
                        ProbeMiddleware {
                            inner,
                            weaks: Arc::clone(&self.weaks),
                        }
                    }
                }

                impl<H: Handler> Handler for ProbeMiddleware<H> {
                    fn call(
                        &self,
                        cx: &Cx,
                        mut req: Request,
                    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>>
                    {
                        let probe = Arc::new(());
                        self.weaks
                            .lock()
                            .expect("weaks lock")
                            .push(Arc::downgrade(&probe));
                        req.extensions.insert_typed(ProbeExt(probe));
                        self.inner.call(cx, req)
                    }
                }

                let router = Router::new()
                    .route(
                        "/probe",
                        get(FnHandler1::<_, Extension<ProbeExt>>::new(
                            |Extension(_p): Extension<ProbeExt>| "ok",
                        )),
                    )
                    .layer(ProbeLayer {
                        weaks: Arc::clone(&weaks),
                    });

                for _ in 0..3 {
                    let resp = router.handle(Request::new("GET", "/probe"));
                    assert_eq!(resp.status, StatusCode::OK);
                }

                let weaks = weaks.lock().expect("weaks lock");
                assert_eq!(weaks.len(), 3);
                assert!(
                    weaks.iter().all(|w| w.upgrade().is_none()),
                    "every request's extension must be dropped once its dispatch completes"
                );
            }
        }
    }

    // ─── Default request trace (br-asupersync-server-stack-hardening-eeexl1.3 AC3) ──

    mod default_trace {
        use super::*;
        use crate::CancelReason;
        use crate::web::middleware::{RequestLogRecord, RequestLogSink};
        use std::sync::{Arc, Mutex};

        fn fixed_time() -> Time {
            Time::from_millis(7_000)
        }

        fn collecting_sink() -> (RequestLogSink, Arc<Mutex<Vec<RequestLogRecord>>>) {
            let records = Arc::new(Mutex::new(Vec::new()));
            let sink_records = Arc::clone(&records);
            let sink: RequestLogSink = Arc::new(move |record: &RequestLogRecord| {
                sink_records
                    .lock()
                    .expect("records lock")
                    .push(record.clone());
            });
            (sink, records)
        }

        fn boom_handler() -> Response {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }

        /// Golden of the structured request log emitted by the default-on
        /// trace, scrubbed for determinism: a fixed time getter zeroes
        /// durations, and generated request ids are sequential.
        #[test]
        fn default_trace_golden_scrubbed() {
            let (sink, records) = collecting_sink();
            let router = Router::new()
                .route("/ok", get(FnHandler::new(ok_handler)))
                .route("/boom", get(FnHandler::new(boom_handler)))
                .with_default_trace_time_getter(fixed_time)
                .with_default_trace_record_sink(sink);

            let _ = router.handle(Request::new("GET", "/ok"));
            let _ = router.handle(Request::new("GET", "/boom"));
            let _ = router.handle(Request::new("POST", "/ok"));
            let _ = router.handle(Request::new("GET", "/missing"));

            let got =
                serde_json::to_value(&*records.lock().expect("records lock")).expect("serialize");
            let want = serde_json::json!([
                {
                    "method": "GET",
                    "path": "/ok",
                    "status": 200,
                    "severity": "ok",
                    "duration_ms": 0,
                    "request_id": "req-1",
                    "cancelled": false,
                    "cancel_reason": null
                },
                {
                    "method": "GET",
                    "path": "/boom",
                    "status": 500,
                    "severity": "server_error",
                    "duration_ms": 0,
                    "request_id": "req-2",
                    "cancelled": false,
                    "cancel_reason": null
                },
                {
                    "method": "POST",
                    "path": "/ok",
                    "status": 405,
                    "severity": "client_error",
                    "duration_ms": 0,
                    "request_id": "req-3",
                    "cancelled": false,
                    "cancel_reason": null
                },
                {
                    "method": "GET",
                    "path": "/missing",
                    "status": 404,
                    "severity": "client_error",
                    "duration_ms": 0,
                    "request_id": "req-4",
                    "cancelled": false,
                    "cancel_reason": null
                }
            ]);
            assert_eq!(got, want, "request log schema golden drifted");
        }

        /// Cancelled requests log as 499 with the cancel reason — the
        /// outcome-severity contract for client-abandoned work.
        #[test]
        fn cancelled_request_logs_499_with_reason() {
            let (sink, records) = collecting_sink();
            let router = Router::new()
                .route("/slow", get(FnHandler::new(ok_handler)))
                .with_default_trace_time_getter(fixed_time)
                .with_default_trace_record_sink(sink);

            let cx = Cx::for_testing();
            cx.set_cancel_requested(true);
            cx.set_cancel_reason(CancelReason::user("client disconnected"));
            let _resp = futures_lite::future::block_on(
                router.handle_with_cx(&cx, Request::new("GET", "/slow")),
            );

            let records = records.lock().expect("records lock");
            assert_eq!(records.len(), 1);
            let record = &records[0];
            assert_eq!(record.status, 499, "cancelled requests must log as 499");
            assert_eq!(record.severity, "cancelled");
            assert!(record.cancelled);
            let reason = record.cancel_reason.as_deref().expect("cancel reason");
            assert!(
                reason.contains("client disconnected"),
                "cancel reason must carry the message, got: {reason}"
            );
        }

        /// Opt-out: `without_default_trace` silences the instrumentation.
        #[test]
        fn without_default_trace_emits_nothing() {
            let (sink, records) = collecting_sink();
            let router = Router::new()
                .with_default_trace_record_sink(sink)
                .without_default_trace()
                .route("/ok", get(FnHandler::new(ok_handler)));

            let resp = router.handle(Request::new("GET", "/ok"));
            assert_eq!(resp.status, StatusCode::OK);
            assert!(
                records.lock().expect("records lock").is_empty(),
                "opted-out router must not emit trace records"
            );
        }

        /// A client-supplied request id is propagated, never replaced.
        #[test]
        fn client_request_id_is_propagated() {
            let (sink, records) = collecting_sink();
            let router = Router::new()
                .route("/ok", get(FnHandler::new(ok_handler)))
                .with_default_trace_time_getter(fixed_time)
                .with_default_trace_record_sink(sink);

            let _ = router
                .handle(Request::new("GET", "/ok").with_header("x-request-id", "client-abc-123"));

            let records = records.lock().expect("records lock");
            assert_eq!(records[0].request_id.as_deref(), Some("client-abc-123"));
        }

        /// Response headers stay untouched under the log-only default policy.
        #[test]
        fn default_policy_does_not_mutate_response_headers() {
            let router = Router::new().route("/ok", get(FnHandler::new(ok_handler)));
            let resp = router.handle(Request::new("GET", "/ok"));
            assert!(!resp.headers.contains_key("x-response-time-ms"));
            assert!(!resp.headers.contains_key("x-trace-id"));
        }

        /// Opting into headers via the policy stamps duration + trace id.
        #[test]
        fn opt_in_policy_stamps_headers() {
            let router = Router::new()
                .route("/ok", get(FnHandler::new(ok_handler)))
                .with_default_trace_policy(RequestTracePolicy::default())
                .with_default_trace_time_getter(fixed_time);

            let resp = router.handle(Request::new("GET", "/ok"));
            assert_eq!(
                resp.headers.get("x-response-time-ms").map(String::as_str),
                Some("0")
            );
            assert_eq!(
                resp.headers.get("x-trace-id").map(String::as_str),
                Some("req-1")
            );
        }

        #[test]
        fn equivalent_route_patterns_merge_methods_asupersync_vftw38_item7() {
            let router = Router::new()
                .route("/users/:id", get(FnHandler::new(ok_handler)))
                .route("/users/:user_id", post(FnHandler::new(created_handler)));

            let get_resp = router.handle(Request::new("GET", "/users/42"));
            assert_eq!(get_resp.status, StatusCode::OK);

            let post_resp = router.handle(Request::new("POST", "/users/42"));
            assert_eq!(post_resp.status, StatusCode::CREATED);

            let del_resp = router.handle(Request::new("DELETE", "/users/42"));
            assert_eq!(del_resp.status, StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(del_resp.header_value("allow"), Some("GET, POST"));
        }

        #[test]
        fn duplicate_nest_prefixes_merge_subrouters_asupersync_vftw38_item7() {
            let r1 = Router::new().route("/users", get(FnHandler::new(ok_handler)));
            let r2 = Router::new().route("/items", get(FnHandler::new(created_handler)));

            let router = Router::new().nest("/api", r1).nest("/api", r2);

            let resp1 = router.handle(Request::new("GET", "/api/users"));
            assert_eq!(resp1.status, StatusCode::OK);

            let resp2 = router.handle(Request::new("GET", "/api/items"));
            assert_eq!(resp2.status, StatusCode::CREATED);
        }


        #[test]
        fn nest_prefix_without_leading_slash_normalizes_asupersync_vftw38_item9() {
            let sub = Router::new().route("/profile", get(FnHandler::new(ok_handler)));
            let router = Router::new().nest("api", sub);

            let resp = router.handle(Request::new("GET", "/api/profile"));
            assert_eq!(resp.status, StatusCode::OK);
        }

        #[test]
        fn non_slash_and_asterisk_targets_do_not_match_resource_routes_asupersync_vftw38_item12() {
            let router = Router::new()
                .route("/:slug", get(FnHandler::new(ok_handler)))
                .nest("/admin", Router::new().route("/x", get(FnHandler::new(created_handler))));

            // OPTIONS * must not match /:slug
            let resp_star = router.handle(Request::new("OPTIONS", "*"));
            assert_ne!(resp_star.status, StatusCode::OK);
            assert_eq!(resp_star.status, StatusCode::NOT_FOUND);

            // "admin/x" without leading slash must not match /admin/x or /:slug
            let resp_noslash = router.handle(Request::new("GET", "admin/x"));
            assert_ne!(resp_noslash.status, StatusCode::OK);
            assert_ne!(resp_noslash.status, StatusCode::CREATED);
            assert_eq!(resp_noslash.status, StatusCode::NOT_FOUND);
        }
    }
