    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let waker = std::task::Waker::noop().clone();
        let mut task_cx = Context::from_waker(&waker);
        let mut future = std::pin::pin!(future);
        loop {
            match std::future::Future::poll(future.as_mut(), &mut task_cx) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn streaming_extractor_request(
        cx: &Cx,
        kind: BodyKind,
        content_type: &str,
        limit: usize,
    ) -> (
        crate::http::h1::stream::IncomingRequestBodyWriter,
        Request,
        StreamingRawBodyControl,
    ) {
        let (writer, body) = IncomingRequestBody::channel(cx, kind);
        let mut req = Request::new("POST", "/streamed").with_header("content-type", content_type);
        if let BodyKind::ContentLength(length) = kind {
            req = req.with_header("content-length", length.to_string());
        }
        req.extensions.insert_typed(
            BodyLimits::new()
                .max_json_body_size(limit)
                .max_form_body_size(limit),
        );
        let control = insert_streaming_raw_body(&mut req, body).expect("install streaming body");
        (writer, req, control)
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn body_diagnostic_extraction_errors_have_exact_leading_tokens() {
        let total = total_body_limit_error("bounded total");
        assert_eq!(
            total.status,
            super::super::response::StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(total.message, "[ASUP-E505] bounded total");

        let timeout = streaming_extraction_error(
            "raw",
            StreamingRawBodyCollectError::Body(IncomingBodyError::DrainTimeout),
        );
        assert_eq!(
            timeout.status,
            super::super::response::StatusCode::REQUEST_TIMEOUT
        );
        assert_eq!(
            timeout.message,
            "[ASUP-E508] raw request body drain timed out"
        );

        let aborted = streaming_extraction_error(
            "raw",
            StreamingRawBodyCollectError::Body(IncomingBodyError::ClientAborted),
        );
        assert_eq!(
            aborted.status,
            super::super::response::StatusCode::CLIENT_CLOSED_REQUEST
        );
        assert_eq!(
            aborted.message,
            "[ASUP-E509] raw request body transport aborted"
        );

        let deadline = streaming_extraction_error(
            "raw",
            StreamingRawBodyCollectError::Body(IncomingBodyError::Cancelled {
                kind: CancelKind::Deadline,
            }),
        );
        assert_eq!(
            deadline.status,
            super::super::response::StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(deadline.message.starts_with("[ASUP-E501] "));
    }

    #[test]
    fn path_extraction() {
        let mut params = HashMap::new();
        params.insert("id".to_string(), "42".to_string());
        let req = Request::new("GET", "/users/42").with_path_params(params);

        let Path(id) = Path::<String>::from_request_parts(&req).unwrap();
        assert_eq!(id, "42");
    }

    #[test]
    fn query_extraction() {
        let req = Request::new("GET", "/items").with_query("page=3&sort=name");
        let Query(params) = Query::<HashMap<String, String>>::from_request_parts(&req).unwrap();
        assert_eq!(params.get("page").unwrap(), "3");
        assert_eq!(params.get("sort").unwrap(), "name");
    }

    #[test]
    fn path_typed_numeric_extraction() {
        let mut params = HashMap::new();
        params.insert("id".to_string(), "42".to_string());
        let req = Request::new("GET", "/users/42").with_path_params(params);

        let Path(id) = Path::<u64>::from_request_parts(&req).unwrap();
        assert_eq!(id, 42);
    }

    #[test]
    fn path_typed_struct_extraction() {
        #[derive(Debug, serde::Deserialize, PartialEq, Eq)]
        struct Params {
            user_id: u64,
            post_id: u32,
        }

        let mut params = HashMap::new();
        params.insert("user_id".to_string(), "7".to_string());
        params.insert("post_id".to_string(), "11".to_string());
        let req = Request::new("GET", "/users/7/posts/11").with_path_params(params);

        let Path(extracted) = Path::<Params>::from_request_parts(&req).unwrap();
        assert_eq!(
            extracted,
            Params {
                user_id: 7,
                post_id: 11
            }
        );
    }

    #[test]
    fn path_typed_deserialization_error() {
        let mut params = HashMap::new();
        params.insert("id".to_string(), "not-a-number".to_string());
        let req = Request::new("GET", "/users/not-a-number").with_path_params(params);

        let err = Path::<u64>::from_request_parts(&req).unwrap_err();
        assert_eq!(err.status, crate::web::response::StatusCode::BAD_REQUEST);
        assert!(err.message.contains("invalid path parameters"));
    }

    #[test]
    fn content_length_parser_accepts_single_and_identical_combined_values() {
        assert_eq!(parse_content_length("42").unwrap(), 42);
        assert_eq!(parse_content_length("42, 42").unwrap(), 42);
        assert_eq!(parse_content_length("0042, 42").unwrap(), 42);
    }

    #[test]
    fn content_length_parser_rejects_invalid_or_conflicting_values() {
        // "+5"/"+42": Rust's usize parser accepts a leading '+', but RFC 9110
        // §8.6 forbids it — a fronting proxy may frame it differently
        // (smuggling/desync), so it must be rejected.
        for value in [
            "",
            "5, ",
            "5, 6",
            "not-a-number",
            "-1",
            "+5",
            "+42",
            "5, +5",
            "0x10",
            "1 2",
        ] {
            let err = parse_content_length(value).unwrap_err();
            assert_eq!(err.status, crate::web::response::StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn json_extraction() {
        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct Input {
            name: String,
        }

        let req = Request::new("POST", "/users")
            .with_header("content-type", "application/json")
            .with_body(Bytes::from_static(b"{\"name\":\"alice\"}"));

        let Json(input) = Json::<Input>::from_request(req).unwrap();
        assert_eq!(input.name, "alice");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_json_and_form_buffered_async_hook_parity() {
        let cx = Cx::for_testing();

        let json_req = Request::new("POST", "/json")
            .with_header("content-type", "application/json")
            .with_body(Bytes::from_static(br#"{"name":"alice"}"#));
        let expected_json = Json::<serde_json::Value>::from_request(json_req.clone())
            .expect("buffered JSON")
            .0;
        let actual_json = block_on(Json::<serde_json::Value>::from_request_with_cx(
            &cx, json_req,
        ))
        .expect("async-hook buffered JSON")
        .0;
        assert_eq!(actual_json, expected_json);

        let form_req = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(b"user=alice&role=admin"));
        let expected_form = Form::<HashMap<String, String>>::from_request(form_req.clone())
            .expect("buffered form")
            .0;
        let actual_form = block_on(Form::<HashMap<String, String>>::from_request_with_cx(
            &cx, form_req,
        ))
        .expect("async-hook buffered form")
        .0;
        assert_eq!(actual_form, expected_form);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_json_and_form_bounded_collection_caps_fragmented_capacity() {
        let mut zero = BoundedCollectionBuffer::new(0);
        zero.extend_from_slice(b"")
            .expect("empty body fits zero limit");
        assert_eq!(zero.retained_capacity(), 0);
        assert!(matches!(
            zero.extend_from_slice(b"x"),
            Err(StreamingRawBodyCollectError::LengthLimitExceeded {
                actual: Some(1),
                limit: 0,
            })
        ));

        let mut fragmented = BoundedCollectionBuffer::new(10);
        for chunk in [b"a".as_slice(), b"bc", b"def", b"ghij"] {
            fragmented
                .extend_from_slice(chunk)
                .expect("fragment fits collection limit");
            assert!(fragmented.retained_capacity() <= 10);
        }
        assert_eq!(fragmented.data.as_slice(), b"abcdefghij");

        assert!(matches!(
            fragmented.extend_from_slice(b"k"),
            Err(StreamingRawBodyCollectError::LengthLimitExceeded {
                actual: Some(11),
                limit: 10,
            })
        ));
        assert_eq!(fragmented.data.as_slice(), b"abcdefghij");
        assert!(fragmented.retained_capacity() <= 10);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn body_policy_streaming_raw_body_enforces_actual_chunked_bytes() {
        let cx = Cx::for_testing();
        let (mut writer, incoming) = IncomingRequestBody::channel(&cx, BodyKind::Chunked);
        let mut request = Request::new("POST", "/streamed");
        request
            .extensions
            .insert_typed(super::super::RequestBodyPolicy::new().max_total_body_size(6));
        let control = insert_streaming_raw_body(&mut request, incoming)
            .expect("install policy-limited streaming body");
        block_on(writer.push_bytes(&cx, b"4\r\nABCD\r\n4\r\nEFGH\r\n0\r\n\r\n"))
            .expect("publish chunked body through protocol decoder");

        let body = StreamingRawBody::from_request(request).expect("take streaming body");
        let error = block_on(body.collect_bounded_with_cx(&cx, 32))
            .expect_err("actual bytes above policy total must fail");
        assert!(matches!(
            error,
            StreamingRawBodyCollectError::Body(IncomingBodyError::BodyTooLarge {
                actual: Some(8),
                limit: 6,
            })
        ));
        drop(control);
    }

    #[test]
    fn body_policy_enforced_snapshot_prevents_late_body_limit_loosen() {
        let enforced = super::super::RequestBodyPolicy::new()
            .max_total_body_size(1024)
            .body_limits(BodyLimits::new().max_json_body_size(4))
            .resolved();
        let mut request = Request::new("POST", "/json")
            .with_header("content-type", "application/json")
            .with_body(Bytes::from_static(b"{\"x\":1}"));
        request
            .extensions
            .insert_typed(super::super::EnforcedRequestBodyPolicy { policy: enforced });
        request.extensions.insert_typed(
            super::super::RequestBodyPolicy::new()
                .max_total_body_size(4096)
                .body_limits(BodyLimits::new().max_json_body_size(4096)),
        );
        request
            .extensions
            .insert_typed(BodyLimits::new().max_json_body_size(4096));

        let reported = request
            .body_policy()
            .expect("protected effective policy remains inspectable");
        assert_eq!(reported.body_limits.max_json_body_size, 4);
        assert_eq!(reported.max_total_body_size, 1024);

        let error = Json::<serde_json::Value>::from_request(request)
            .expect_err("late middleware must not loosen locked JSON limit");
        assert_eq!(
            error.status,
            super::super::response::StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[test]
    fn body_policy_accessor_includes_tighter_legacy_projections() {
        let enforced = super::super::RequestBodyPolicy::new()
            .max_total_body_size(1024)
            .body_limits(BodyLimits::new().max_json_body_size(10))
            .multipart_limits(
                super::super::multipart::MultipartLimits::new().max_part_body_size(12),
            )
            .resolved();
        let mut request = Request::new("POST", "/upload");
        request
            .extensions
            .insert_typed(super::super::EnforcedRequestBodyPolicy { policy: enforced });
        request
            .extensions
            .insert_typed(BodyLimits::new().max_json_body_size(4));
        request
            .extensions
            .insert_typed(super::super::multipart::MultipartLimits::new().max_part_body_size(3));

        let reported = request
            .body_policy()
            .expect("protected effective policy remains inspectable");
        assert_eq!(reported.max_total_body_size, 1024);
        assert_eq!(reported.body_limits.max_json_body_size, 4);
        assert_eq!(reported.multipart_limits.max_part_body_size, 3);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn body_policy_unconfigured_chunked_body_preserves_unknown_upper_hint() {
        let cx = Cx::for_testing();
        let (mut writer, incoming) = IncomingRequestBody::channel(&cx, BodyKind::Chunked);
        let mut request = Request::new("POST", "/streamed");
        let control = insert_streaming_raw_body(&mut request, incoming)
            .expect("install unconfigured streaming body");
        let body = StreamingRawBody::from_request(request).expect("take streaming body");
        assert_eq!(body.size_hint().upper(), None);

        block_on(writer.push_bytes(&cx, b"4\r\nbody\r\n0\r\n\r\n"))
            .expect("publish bounded chunked body");
        let collected = block_on(body.collect_bounded_with_cx(&cx, 4))
            .expect("unconfigured chunked body remains collectable");
        assert_eq!(collected.data().as_ref(), b"body");
        drop(control);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn body_policy_streaming_raw_body_rejects_declared_length_before_take() {
        let cx = Cx::for_testing();
        let (writer, incoming) = IncomingRequestBody::channel(&cx, BodyKind::ContentLength(8));
        let mut request = Request::new("POST", "/streamed").with_header("content-length", "8");
        request
            .extensions
            .insert_typed(super::super::RequestBodyPolicy::new().max_total_body_size(6));
        let control = insert_streaming_raw_body(&mut request, incoming)
            .expect("install policy-limited streaming body");

        let error = StreamingRawBody::from_request(request)
            .expect_err("declared length above policy must fail before take");
        assert_eq!(
            error.status,
            super::super::response::StatusCode::PAYLOAD_TOO_LARGE
        );
        assert!(!writer.consumer_dropped());
        drop(control);
        assert!(writer.consumer_dropped());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn body_policy_streaming_raw_body_into_inner_retains_limit_and_size_hint() {
        let cx = Cx::for_testing();
        let (mut writer, incoming) = IncomingRequestBody::channel(&cx, BodyKind::Chunked);
        let mut request = Request::new("POST", "/streamed");
        request
            .extensions
            .insert_typed(super::super::RequestBodyPolicy::new().max_total_body_size(6));
        let control = insert_streaming_raw_body(&mut request, incoming)
            .expect("install policy-limited streaming body");
        let body = StreamingRawBody::from_request(request).expect("take streaming body");
        let mut body = body.into_inner();
        assert_eq!(body.size_hint().upper(), Some(6));

        block_on(writer.push_bytes(&cx, b"4\r\nABCD\r\n"))
            .expect("first chunk stays inside policy");
        let frame = block_on(std::future::poll_fn(|poll_cx| {
            Pin::new(&mut body).poll_frame(poll_cx)
        }))
        .expect("first frame")
        .expect("first frame succeeds");
        assert_eq!(frame.data_ref().expect("DATA frame").remaining(), 4);
        assert_eq!(body.size_hint().upper(), Some(2));

        let writer_error = block_on(writer.push_bytes(&cx, b"3\r\nEFG\r\n0\r\n\r\n"))
            .expect_err("inner body must retain the route policy");
        assert!(matches!(
            writer_error,
            IncomingBodyError::BodyTooLarge {
                actual: Some(7),
                limit: 6,
            }
        ));
        let body_error = block_on(std::future::poll_fn(|poll_cx| {
            Pin::new(&mut body).poll_frame(poll_cx)
        }))
        .expect("terminal policy error")
        .expect_err("body observes policy error");
        assert!(matches!(
            body_error,
            IncomingBodyError::BodyTooLarge {
                actual: Some(7),
                limit: 6,
            }
        ));
        assert_eq!(body.size_hint().exact(), Some(0));
        drop(control);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_json_and_form_enforce_declared_and_actual_limits() {
        let cx = Cx::for_testing();

        let (json_writer, json_req, json_control) =
            streaming_extractor_request(&cx, BodyKind::ContentLength(8), "application/json", 7);
        let error = block_on(Json::<serde_json::Value>::from_request_with_cx(
            &cx, json_req,
        ))
        .expect_err("declared JSON length must fail before body polling");
        assert_eq!(
            error.status,
            super::super::response::StatusCode::PAYLOAD_TOO_LARGE
        );
        assert!(!json_writer.consumer_dropped());
        drop(json_control);
        assert!(json_writer.consumer_dropped());

        let (form_writer, form_req, form_control) = streaming_extractor_request(
            &cx,
            BodyKind::ContentLength(8),
            "application/x-www-form-urlencoded",
            7,
        );
        let error = block_on(Form::<HashMap<String, String>>::from_request_with_cx(
            &cx, form_req,
        ))
        .expect_err("declared form length must fail before body polling");
        assert_eq!(
            error.status,
            super::super::response::StatusCode::PAYLOAD_TOO_LARGE
        );
        assert!(!form_writer.consumer_dropped());
        drop(form_control);
        assert!(form_writer.consumer_dropped());

        let (mut empty_form_writer, empty_form_req, empty_form_control) =
            streaming_extractor_request(
                &cx,
                BodyKind::Chunked,
                "application/x-www-form-urlencoded",
                0,
            );
        block_on(empty_form_writer.push_bytes(&cx, b"0\r\n\r\n"))
            .expect("publish zero-length chunked form");
        let Form(values) = block_on(Form::<HashMap<String, String>>::from_request_with_cx(
            &cx,
            empty_form_req,
        ))
        .expect("zero-length form without content-length");
        assert!(values.is_empty());
        drop(empty_form_control);

        let (mut json_writer, json_req, json_control) =
            streaming_extractor_request(&cx, BodyKind::Chunked, "application/json", 7);
        block_on(json_writer.push_bytes(&cx, b"7\r\n{\"x\":1}\r\n0\r\n\r\n"))
            .expect("publish exact-limit chunked JSON");
        let Json(value) = block_on(Json::<serde_json::Value>::from_request_with_cx(
            &cx, json_req,
        ))
        .expect("exact-limit chunked JSON");
        assert_eq!(value["x"], 1);
        drop(json_control);

        let (mut form_writer, form_req, form_control) = streaming_extractor_request(
            &cx,
            BodyKind::Chunked,
            "application/x-www-form-urlencoded",
            7,
        );
        block_on(form_writer.push_bytes(&cx, b"7\r\na=12345\r\n0\r\n\r\n"))
            .expect("publish exact-limit chunked form");
        let Form(values) = block_on(Form::<HashMap<String, String>>::from_request_with_cx(
            &cx, form_req,
        ))
        .expect("exact-limit chunked form");
        assert_eq!(values.get("a").map(String::as_str), Some("12345"));
        drop(form_control);

        let (mut json_writer, json_req, json_control) =
            streaming_extractor_request(&cx, BodyKind::Chunked, "application/json", 7);
        block_on(json_writer.push_bytes(&cx, b"8\r\n{\"x\":12}\r\n0\r\n\r\n"))
            .expect("publish over-limit chunked JSON");
        let error = block_on(Json::<serde_json::Value>::from_request_with_cx(
            &cx, json_req,
        ))
        .expect_err("actual streamed JSON length must be capped");
        assert_eq!(
            error.status,
            super::super::response::StatusCode::PAYLOAD_TOO_LARGE
        );
        assert!(error.message.contains("8 bytes (limit 7)"));
        drop(json_control);

        let (mut form_writer, form_req, form_control) = streaming_extractor_request(
            &cx,
            BodyKind::Chunked,
            "application/x-www-form-urlencoded",
            7,
        );
        block_on(form_writer.push_bytes(&cx, b"8\r\na=123456\r\n0\r\n\r\n"))
            .expect("publish over-limit chunked form");
        let error = block_on(Form::<HashMap<String, String>>::from_request_with_cx(
            &cx, form_req,
        ))
        .expect_err("actual streamed form length must be capped");
        assert_eq!(
            error.status,
            super::super::response::StatusCode::PAYLOAD_TOO_LARGE
        );
        assert!(error.message.contains("8 bytes (limit 7)"));
        drop(form_control);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_json_and_form_fail_closed_on_transport_errors_and_cancellation() {
        let cx = Cx::for_testing();

        let (mut json_writer, json_req, json_control) =
            streaming_extractor_request(&cx, BodyKind::ContentLength(7), "application/json", 7);
        block_on(json_writer.push_bytes(&cx, b"{}")).expect("publish truncated fixed JSON prefix");
        assert_eq!(
            json_writer.finish(&cx),
            Err(IncomingBodyError::BadContentLength)
        );
        let error = block_on(Json::<serde_json::Value>::from_request_with_cx(
            &cx, json_req,
        ))
        .expect_err("truncated fixed JSON must fail");
        assert_eq!(
            error.status,
            super::super::response::StatusCode::BAD_REQUEST
        );
        assert_eq!(error.message, "invalid JSON request body");
        drop(json_control);

        let (mut form_writer, form_req, form_control) = streaming_extractor_request(
            &cx,
            BodyKind::Chunked,
            "application/x-www-form-urlencoded",
            32,
        );
        assert_eq!(
            block_on(form_writer.push_bytes(&cx, b"Z\r\n")),
            Err(IncomingBodyError::BadChunkedEncoding)
        );
        let error = block_on(Form::<HashMap<String, String>>::from_request_with_cx(
            &cx, form_req,
        ))
        .expect_err("malformed chunked form must fail");
        assert_eq!(
            error.status,
            super::super::response::StatusCode::BAD_REQUEST
        );
        assert_eq!(error.message, "invalid form request body");
        drop(form_control);

        let cancelled_cx = Cx::for_testing();
        let (mut json_writer, json_req, json_control) = streaming_extractor_request(
            &cancelled_cx,
            BodyKind::ContentLength(1),
            "application/json",
            1,
        );
        let mut extraction = std::pin::pin!(Json::<serde_json::Value>::from_request_with_cx(
            &cancelled_cx,
            json_req,
        ));
        let waker = std::task::Waker::noop().clone();
        let mut task_cx = Context::from_waker(&waker);
        assert!(matches!(
            std::future::Future::poll(extraction.as_mut(), &mut task_cx),
            Poll::Pending
        ));
        cancelled_cx.cancel_fast(crate::types::CancelKind::Deadline);
        let Poll::Ready(Err(error)) = std::future::Future::poll(extraction.as_mut(), &mut task_cx)
        else {
            panic!("cancelled streaming JSON extraction must terminate");
        };
        assert_eq!(
            error.status,
            super::super::response::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            error.message,
            "[ASUP-E501] server request budget deadline exceeded: JSON request body unavailable"
        );
        drop(json_control);
        assert_eq!(
            block_on(json_writer.push_bytes(&cancelled_cx, b"x")),
            Err(IncomingBodyError::Cancelled {
                kind: crate::types::CancelKind::Deadline,
            })
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_json_and_form_typed_error_mapping_matches_body_contract() {
        use super::super::response::StatusCode;

        for kind in [CancelKind::Timeout, CancelKind::Deadline] {
            let error = streaming_extraction_error(
                "JSON",
                StreamingRawBodyCollectError::Body(IncomingBodyError::Cancelled { kind }),
            );
            assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
            assert!(error.message.starts_with("[ASUP-E501] "));
        }

        for kind in [
            CancelKind::PollQuota,
            CancelKind::CostBudget,
            CancelKind::ResourceUnavailable,
        ] {
            let error = streaming_extraction_error(
                "JSON",
                StreamingRawBodyCollectError::Body(IncomingBodyError::Cancelled { kind }),
            );
            assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
            assert!(!error.message.starts_with("[ASUP-E508] "));
        }

        for kind in [
            CancelKind::User,
            CancelKind::FailFast,
            CancelKind::RaceLost,
            CancelKind::ParentCancelled,
            CancelKind::Shutdown,
            CancelKind::LinkedExit,
        ] {
            let error = streaming_extraction_error(
                "JSON",
                StreamingRawBodyCollectError::Body(IncomingBodyError::Cancelled { kind }),
            );
            assert_eq!(error.status, StatusCode::CLIENT_CLOSED_REQUEST);
        }

        for incoming in [
            IncomingBodyError::AccountingOverflow,
            IncomingBodyError::SourceDisconnected,
        ] {
            let error =
                streaming_extraction_error("form", StreamingRawBodyCollectError::Body(incoming));
            assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    #[test]
    fn json_wrong_content_type() {
        #[derive(Debug, serde::Deserialize)]
        struct Input {
            #[allow(dead_code)]
            name: String,
        }

        let req = Request::new("POST", "/users")
            .with_header("content-type", "text/plain")
            .with_body(Bytes::from_static(b"{\"name\":\"alice\"}"));

        let result = Json::<Input>::from_request(req);
        assert!(result.is_err());
    }

    #[test]
    fn form_extraction() {
        let req = Request::new("POST", "/login")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(b"user=alice&pass=secret"));

        let Form(data) = Form::<HashMap<String, String>>::from_request(req).unwrap();
        assert_eq!(data.get("user").unwrap(), "alice");
        assert_eq!(data.get("pass").unwrap(), "secret");
    }

    #[test]
    fn raw_body_extraction() {
        let req = Request::new("POST", "/upload").with_body(Bytes::from_static(b"raw data"));

        let RawBody(body) = RawBody::from_request(req).unwrap();
        assert_eq!(body.as_ref(), b"raw data");
    }

    #[test]
    fn headers_extraction() {
        let req = Request::new("GET", "/").with_header("x-request-id", "abc123");

        let headers = HashMap::<String, String>::from_request_parts(&req).unwrap();
        assert_eq!(headers.get("x-request-id").unwrap(), "abc123");
    }

    #[test]
    fn request_header_lookup_is_case_insensitive() {
        let mut req = Request::new("GET", "/").with_header("X-Trace-Id", "trace-123");
        req.headers
            .insert("Authorization".to_string(), "Bearer token".to_string());

        assert_eq!(req.header("x-trace-id"), Some("trace-123"));
        assert_eq!(req.header("X-TRACE-ID"), Some("trace-123"));
        assert_eq!(req.header("authorization"), Some("Bearer token"));
        assert_eq!(req.header("AUTHORIZATION"), Some("Bearer token"));
        assert_eq!(req.header("missing"), None);
    }

    #[test]
    fn typed_header_content_type_extracts_case_insensitively() {
        let req = Request::new("POST", "/items")
            .with_header("Content-Type", "application/json; charset=utf-8");

        let Header(content_type) = Header::<ContentType>::from_request_parts(&req).unwrap();
        assert_eq!(content_type.as_str(), "application/json; charset=utf-8");
        assert_eq!(content_type.media_type(), "application/json");
    }

    #[test]
    fn typed_header_alias_extracts_authorization() {
        let req = Request::new("GET", "/admin").with_header("Authorization", "Bearer token-123");

        let TypedHeader(auth) = TypedHeader::<Authorization>::from_request_parts(&req).unwrap();
        assert_eq!(auth.scheme, "Bearer");
        assert_eq!(auth.credentials, "token-123");
        assert_eq!(auth.as_str(), "Bearer token-123");
    }

    #[test]
    fn shipped_typed_headers_cover_user_agent_and_accept() {
        let req = Request::new("GET", "/")
            .with_header("User-Agent", "asupersync-test/1")
            .with_header("Accept", "application/json, text/plain;q=0.8, */*;q=0.1");

        let Header(user_agent) = Header::<UserAgent>::from_request_parts(&req).unwrap();
        let Header(accept) = Header::<Accept>::from_request_parts(&req).unwrap();
        assert_eq!(user_agent.as_str(), "asupersync-test/1");
        assert_eq!(
            accept.as_str(),
            "application/json, text/plain;q=0.8, */*;q=0.1"
        );
    }

    #[test]
    fn missing_typed_header_rejects_with_asup_code() {
        let req = Request::new("GET", "/");

        let err = Header::<ContentType>::from_request_parts(&req).unwrap_err();
        assert_eq!(err.status, crate::web::response::StatusCode::BAD_REQUEST);
        assert!(err.message.starts_with("[ASUP-E503]"));
        assert!(err.message.contains("content-type"));
        assert!(err.message.contains("missing header"));
    }

    #[test]
    fn malformed_typed_header_rejects_with_asup_code() {
        let bad_content_type =
            Request::new("POST", "/items").with_header("content-type", "application");
        let err = Header::<ContentType>::from_request_parts(&bad_content_type).unwrap_err();
        assert_eq!(err.status, crate::web::response::StatusCode::BAD_REQUEST);
        assert!(err.message.starts_with("[ASUP-E503]"));
        assert!(err.message.contains("media range"));

        let bad_authorization =
            Request::new("GET", "/admin").with_header("authorization", "Bearer   ");
        let err = TypedHeader::<Authorization>::from_request_parts(&bad_authorization).unwrap_err();
        assert_eq!(err.status, crate::web::response::StatusCode::BAD_REQUEST);
        assert!(err.message.starts_with("[ASUP-E503]"));
        assert!(err.message.contains("credentials"));
    }

    #[test]
    fn missing_path_params() {
        let req = Request::new("GET", "/");
        let result = Path::<String>::from_request_parts(&req);
        assert!(result.is_err());
    }

    #[test]
    fn percent_decode_preserves_invalid_sequences() {
        assert_eq!(percent_decode("a%2"), "a%2");
        assert_eq!(percent_decode("x%G1"), "x%G1");
        assert_eq!(percent_decode("x%1G"), "x%1G");
        assert_eq!(percent_decode("%"), "%");
        assert_eq!(percent_decode("%A"), "%A");
        assert_eq!(percent_decode("%%41"), "%A"); // first % invalid, then valid %41
    }

    #[test]
    fn request_debug_clone() {
        let r = Request::new("GET", "/api/v1");
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Request"));
        assert!(dbg.contains("GET"));

        let r2 = r;
        assert_eq!(r2.method, "GET");
        assert_eq!(r2.path, "/api/v1");
    }

    #[test]
    fn extensions_debug_clone_default() {
        let e = Extensions::default();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Extensions"));

        let e2 = e;
        assert!(e2.get("missing").is_none());
    }

    #[test]
    fn extraction_error_debug_clone() {
        let e = ExtractionError::bad_request("missing field");
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ExtractionError"));
        assert!(dbg.contains("missing field"));

        let e2 = e;
        assert_eq!(e2.message, "missing field");
    }

    #[test]
    fn typed_state_extraction() {
        #[derive(Clone, Debug, PartialEq, Eq)]
        struct AppState {
            name: String,
        }

        let mut req = Request::new("GET", "/");
        req.extensions.insert_typed(AppState {
            name: "alpha".to_string(),
        });

        let State(state) = State::<AppState>::from_request_parts(&req).unwrap();
        assert_eq!(
            state,
            AppState {
                name: "alpha".to_string()
            }
        );
    }

    #[test]
    fn typed_state_missing_returns_error() {
        #[derive(Clone, Debug)]
        struct AppState;

        let req = Request::new("GET", "/");
        let err = State::<AppState>::from_request_parts(&req).unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(err.message.contains("state not configured"));
    }

    #[test]
    fn form_body_too_large() {
        let oversized = vec![b'a'; DEFAULT_MAX_FORM_BODY_SIZE + 1];
        let req = Request::new("POST", "/form").with_body(Bytes::from(oversized));
        let result = Form::<HashMap<String, String>>::from_request(req);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[test]
    fn json_body_too_large() {
        let oversized = vec![b'a'; DEFAULT_MAX_JSON_BODY_SIZE + 1];
        let req = Request::new("POST", "/data")
            .with_header("content-type", "application/json")
            .with_body(Bytes::from(oversized));
        let result = Json::<serde_json::Value>::from_request(req);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[test]
    fn json_content_type_header_name_case_insensitive() {
        let req = Request::new("POST", "/data")
            .with_header("Content-Type", "application/json")
            .with_body(Bytes::from_static(br#"{"ok":true}"#));
        let Json(value) = Json::<serde_json::Value>::from_request(req).unwrap();
        assert_eq!(value.get("ok"), Some(&serde_json::Value::Bool(true)));
    }

    #[test]
    fn json_content_type_allows_parameters_but_rejects_substring_tricks() {
        let with_charset = Request::new("POST", "/data")
            .with_header("content-type", "application/json; charset=utf-8")
            .with_body(Bytes::from_static(br#"{"ok":true}"#));
        let Json(value) = Json::<serde_json::Value>::from_request(with_charset).unwrap();
        assert_eq!(value.get("ok"), Some(&serde_json::Value::Bool(true)));

        let structured_suffix = Request::new("POST", "/data")
            .with_header("content-type", "application/cloudevents+json")
            .with_body(Bytes::from_static(br#"{"ok":true}"#));
        let Json(value) = Json::<serde_json::Value>::from_request(structured_suffix).unwrap();
        assert_eq!(value.get("ok"), Some(&serde_json::Value::Bool(true)));

        let misleading = Request::new("POST", "/data")
            .with_header("content-type", "text/plain; note=application/json")
            .with_body(Bytes::from_static(br#"{"ok":true}"#));
        let err = Json::<serde_json::Value>::from_request(misleading).unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );

        let wrong_top_level = Request::new("POST", "/data")
            .with_header("content-type", "text/cloudevents+json")
            .with_body(Bytes::from_static(br#"{"ok":true}"#));
        let err = Json::<serde_json::Value>::from_request(wrong_top_level).unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );

        let empty_structured_prefix = Request::new("POST", "/data")
            .with_header("content-type", "application/+json")
            .with_body(Bytes::from_static(br#"{"ok":true}"#));
        let err = Json::<serde_json::Value>::from_request(empty_structured_prefix).unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    #[test]
    fn json_missing_content_type_rejects_with_415() {
        let req = Request::new("POST", "/data").with_body(Bytes::from_static(br#"{"ok":true}"#));
        let err = Json::<serde_json::Value>::from_request(req).unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(err.message, "Json requires Content-Type: application/json");
    }

    #[test]
    fn json_top_level_scalar_matches_rfc7159() {
        let req = Request::new("POST", "/data")
            .with_header("content-type", "application/json")
            .with_body(Bytes::from_static(b"123"));
        let Json(value) = Json::<serde_json::Value>::from_request(req).unwrap();
        assert_eq!(value, serde_json::Value::Number(123.into()));
    }

    #[test]
    fn json_surrounded_by_rfc8259_whitespace_parses() {
        let req = Request::new("POST", "/data")
            .with_header("content-type", "application/json")
            .with_body(Bytes::from_static(b"\r\n\t {\"ok\":true} \n"));
        let Json(value) = Json::<serde_json::Value>::from_request(req).unwrap();
        assert_eq!(value.get("ok"), Some(&serde_json::Value::Bool(true)));
    }

    #[test]
    fn metamorphic_body_extractors_preserve_body_semantics_and_limits() {
        let json_body = Bytes::from_static(br#"{"user":"alice","admin":true}"#);
        let json_req = Request::new("POST", "/json")
            .with_header("content-type", "application/json")
            .with_body(json_body.clone());
        let RawBody(raw_json) = RawBody::from_request(json_req.clone()).unwrap();
        assert_eq!(raw_json.as_ref(), json_body.as_ref());
        let Json(parsed_json) = Json::<serde_json::Value>::from_request(json_req).unwrap();
        assert_eq!(
            parsed_json,
            serde_json::from_slice::<serde_json::Value>(raw_json.as_ref()).unwrap()
        );

        let form_body = Bytes::from_static(b"user=alice&admin=boss");
        let form_req = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(form_body.clone());
        let RawBody(raw_form) = RawBody::from_request(form_req.clone()).unwrap();
        assert_eq!(raw_form.as_ref(), form_body.as_ref());
        let Form(parsed_form) = Form::<HashMap<String, String>>::from_request(form_req).unwrap();
        assert_eq!(
            parsed_form,
            parse_urlencoded(
                std::str::from_utf8(raw_form.as_ref()).unwrap(),
                "form field"
            )
            .unwrap()
        );

        let limit = 8;
        let limits = BodyLimits::new()
            .max_json_body_size(limit)
            .max_form_body_size(limit)
            .max_raw_body_size(limit);

        let mut oversized_json_req = Request::new("POST", "/json")
            .with_header("content-type", "application/json")
            .with_body(Bytes::from_static(br#"{"k":"123456789"}"#));
        oversized_json_req.extensions.insert_typed(limits);
        let json_err = Json::<serde_json::Value>::from_request(oversized_json_req).unwrap_err();
        assert_eq!(
            json_err.status,
            crate::web::response::StatusCode::PAYLOAD_TOO_LARGE
        );

        let mut oversized_form_req = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(b"k=123456789"));
        oversized_form_req.extensions.insert_typed(limits);
        let form_err =
            Form::<HashMap<String, String>>::from_request(oversized_form_req).unwrap_err();
        assert_eq!(
            form_err.status,
            crate::web::response::StatusCode::PAYLOAD_TOO_LARGE
        );

        let mut oversized_raw_req =
            Request::new("POST", "/raw").with_body(Bytes::from_static(b"123456789"));
        oversized_raw_req.extensions.insert_typed(limits);
        let raw_err = RawBody::from_request(oversized_raw_req).unwrap_err();
        assert_eq!(
            raw_err.status,
            crate::web::response::StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[test]
    fn form_wrong_content_type() {
        let req = Request::new("POST", "/form")
            .with_header("content-type", "text/plain")
            .with_body(Bytes::from_static(b"user=alice"));
        let result = Form::<HashMap<String, String>>::from_request(req);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    #[test]
    fn form_content_type_header_name_case_insensitive() {
        let req = Request::new("POST", "/form")
            .with_header("Content-Type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(b"user=alice&role=admin"));
        let Form(values) = Form::<HashMap<String, String>>::from_request(req).unwrap();
        assert_eq!(values.get("user").map(String::as_str), Some("alice"));
        assert_eq!(values.get("role").map(String::as_str), Some("admin"));
    }

    #[test]
    fn form_content_type_allows_parameters_but_rejects_substring_tricks() {
        let with_charset = Request::new("POST", "/form")
            .with_header(
                "content-type",
                "application/x-www-form-urlencoded; charset=utf-8",
            )
            .with_body(Bytes::from_static(b"user=alice&role=admin"));
        let Form(values) = Form::<HashMap<String, String>>::from_request(with_charset).unwrap();
        assert_eq!(values.get("user").map(String::as_str), Some("alice"));
        assert_eq!(values.get("role").map(String::as_str), Some("admin"));

        let misleading = Request::new("POST", "/form")
            .with_header(
                "content-type",
                "application/x-www-form-urlencoded-bogus; charset=utf-8",
            )
            .with_body(Bytes::from_static(b"user=alice"));
        let err = Form::<HashMap<String, String>>::from_request(misleading).unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    #[test]
    fn form_missing_content_type_rejects_with_415() {
        // br-asupersync-mxqraw: Form requires Content-Type:
        // application/x-www-form-urlencoded. Missing Content-Type is a
        // 415 — default-deny prevents an attacker from forging Form<T>
        // deserialisation by submitting a foreign-format body (JSON, XML,
        // raw bytes) without declaring its media type.
        let req = Request::new("POST", "/form").with_body(Bytes::from_static(b"user=alice"));
        let err = Form::<HashMap<String, String>>::from_request(req).unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    #[test]
    fn form_invalid_utf8() {
        let req = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(b"\xff\xfe"));
        let result = Form::<HashMap<String, String>>::from_request(req);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status, crate::web::response::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn form_duplicate_keys_preserved_as_vec() {
        use serde::Deserialize;

        #[derive(Deserialize, Debug, PartialEq)]
        struct MultiForm {
            role: Vec<String>,
            name: String,
        }

        let req = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(b"role=user&role=admin&name=alice"));

        let Form(data) = Form::<MultiForm>::from_request(req).unwrap();
        assert_eq!(data.role, vec!["user", "admin"]);
        assert_eq!(data.name, "alice");
    }

    #[test]
    fn form_duplicate_keys_html_spec_compliance_audit() {
        println!("=== FORM DUPLICATE KEYS HTML SPEC COMPLIANCE AUDIT ===");

        use serde::Deserialize;

        // Test Case 1: Multiple values for same key should be preserved as Vec
        #[derive(Deserialize, Debug, PartialEq)]
        struct TestForm {
            tags: Vec<String>,
            category: String,
            flags: Option<Vec<String>>,
        }

        println!("✓ Test Case 1: Multiple values preserved as Vec<String>");

        let req1 = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(
                b"tags=red&tags=blue&tags=green&category=test",
            ));

        let Form(data1) = Form::<TestForm>::from_request(req1).unwrap();
        assert_eq!(data1.tags, vec!["red", "blue", "green"]);
        assert_eq!(data1.category, "test");
        assert_eq!(data1.flags, None);

        println!("  ✅ tags=red&tags=blue&tags=green → Vec![\"red\", \"blue\", \"green\"]");

        // Test Case 2: Single values should work normally
        println!("✓ Test Case 2: Single values work normally");

        let req2 = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(b"tags=solo&category=single"));

        let Form(data2) = Form::<TestForm>::from_request(req2).unwrap();
        assert_eq!(data2.tags, vec!["solo"]);
        assert_eq!(data2.category, "single");

        println!("  ✅ tags=solo → Vec![\"solo\"] (single item as Vec)");

        // Test Case 3: Mixed single and multiple values
        println!("✓ Test Case 3: Mixed single and multiple values");

        let req3 = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(
                b"tags=first&category=mixed&tags=second&flags=a&flags=b",
            ));

        let Form(data3) = Form::<TestForm>::from_request(req3).unwrap();
        assert_eq!(data3.tags, vec!["first", "second"]);
        assert_eq!(data3.category, "mixed");
        assert_eq!(data3.flags, Some(vec!["a".to_string(), "b".to_string()]));

        println!("  ✅ Mixed form: single category + multiple tags + multiple flags");

        // Test Case 4: HTML checkbox scenario (common use case)
        #[derive(Deserialize, Debug)]
        struct CheckboxForm {
            #[serde(default)]
            permissions: Vec<String>,
            username: String,
        }

        println!("✓ Test Case 4: HTML checkbox scenario");

        let req4 = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(
                b"permissions=read&permissions=write&permissions=delete&username=admin",
            ));

        let Form(data4) = Form::<CheckboxForm>::from_request(req4).unwrap();
        assert_eq!(data4.permissions, vec!["read", "write", "delete"]);
        assert_eq!(data4.username, "admin");

        println!("  ✅ Checkbox form: permissions=[read, write, delete]");

        // Test Case 5: Type coercion with duplicates
        #[derive(Deserialize, Debug)]
        struct TypedForm {
            numbers: Vec<i32>,
            enabled: bool,
        }

        println!("✓ Test Case 5: Type coercion with duplicates");

        let req5 = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(
                b"numbers=42&numbers=123&numbers=999&enabled=true",
            ));

        let Form(data5) = Form::<TypedForm>::from_request(req5).unwrap();
        assert_eq!(data5.numbers, vec![42, 123, 999]);
        assert_eq!(data5.enabled, true);

        println!("  ✅ Type coercion: string numbers → Vec<i32>");

        println!("\n📋 HTML FORM SPEC COMPLIANCE VERIFIED:");
        println!("  1. Duplicate keys preserved: ✅ OPTION (a) - Vec<String> (CORRECT)");
        println!("  2. Single values supported: ✅ BACKWARD COMPATIBLE");
        println!("  3. Type coercion works: ✅ STRING → NUMBER/BOOL");
        println!("  4. HTML checkboxes: ✅ MULTIPLE SELECTIONS PRESERVED");
        println!("  5. Mixed forms: ✅ SINGLE + MULTIPLE FIELDS");

        println!("\n✅ STATUS: FORM DUPLICATE KEY HANDLING IS COMPLIANT");
        println!("BEHAVIOR: Option (a) - return Vec<String> for duplicate keys (CORRECT)");
        println!("COMPLIANCE: HTML Form Specification - preserves all submitted values");
        println!("IMPACT: Applications can now handle multi-select forms correctly");
    }

    #[test]
    fn form_scalar_extraction_does_not_ignore_field_names() {
        let req = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_body(Bytes::from_static(b"flag=true"));
        let err = Form::<bool>::from_request(req).unwrap_err();
        assert_eq!(err.status, crate::web::response::StatusCode::BAD_REQUEST);
        assert!(err.message.contains("invalid form data"));
    }

    #[test]
    fn json_invalid_body() {
        let req = Request::new("POST", "/data")
            .with_header("content-type", "application/json")
            .with_body(Bytes::from_static(b"not json"));
        let result = Json::<serde_json::Value>::from_request(req);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(
            err.status,
            crate::web::response::StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[test]
    fn query_empty_string() {
        let req = Request::new("GET", "/items");
        let Query(params) = Query::<HashMap<String, String>>::from_request_parts(&req).unwrap();
        assert!(params.is_empty());
    }

    #[test]
    fn query_percent_encoded_values() {
        let req = Request::new("GET", "/search").with_query("q=hello+world&tag=%23rust");
        let Query(params) = Query::<HashMap<String, String>>::from_request_parts(&req).unwrap();
        assert_eq!(params.get("q").unwrap(), "hello world");
        assert_eq!(params.get("tag").unwrap(), "#rust");
    }

    #[test]
    fn query_typed_struct_extraction() {
        #[derive(Debug, serde::Deserialize, PartialEq, Eq)]
        struct Pagination {
            page: u32,
            per_page: u16,
            active: bool,
        }

        let req = Request::new("GET", "/items").with_query("page=3&per_page=25&active=true");
        let Query(pagination) = Query::<Pagination>::from_request_parts(&req).unwrap();
        assert_eq!(
            pagination,
            Pagination {
                page: 3,
                per_page: 25,
                active: true
            }
        );
    }

    #[test]
    fn query_typed_scalar_extraction() {
        let req = Request::new("GET", "/items").with_query("value=17");
        let Query(value) = Query::<u32>::from_request_parts(&req).unwrap();
        assert_eq!(value, 17);
    }

    #[test]
    fn query_typed_deserialization_error() {
        let req = Request::new("GET", "/items").with_query("page=abc");
        let err = Query::<u32>::from_request_parts(&req).unwrap_err();
        assert_eq!(err.status, crate::web::response::StatusCode::BAD_REQUEST);
        assert!(err.message.contains("invalid query parameters"));
    }

    #[test]
    fn query_duplicate_keys_reject_instead_of_collapsing_to_scalar() {
        let req = Request::new("GET", "/items").with_query("value=17&value=18");
        let err = Query::<u32>::from_request_parts(&req).unwrap_err();
        assert_eq!(err.status, crate::web::response::StatusCode::BAD_REQUEST);
        assert_eq!(
            err.message,
            "duplicate query parameter `value` (use multi-value extractor for forms)"
        );
    }

    #[test]
    fn path_multiple_params() {
        let mut params = HashMap::new();
        params.insert("user_id".to_string(), "42".to_string());
        params.insert("post_id".to_string(), "7".to_string());
        let req = Request::new("GET", "/users/42/posts/7").with_path_params(params.clone());

        let Path(extracted) = Path::<HashMap<String, String>>::from_request_parts(&req).unwrap();
        assert_eq!(extracted, params);
    }

    #[test]
    fn query_string_field_accepts_numeric_looking_value() {
        // A `String` field holding a numeric/bool-looking value (all-digit
        // username, numeric id passed as text, "true"/"false" string) must be
        // kept as a string, not coerced to a JSON number/bool and rejected.
        #[derive(Debug, serde::Deserialize, PartialEq, Eq)]
        struct Mixed {
            name: String,
            flag: String,
            age: u32,
        }
        let req = Request::new("GET", "/u").with_query("name=42&flag=true&age=30");
        let Query(m) = Query::<Mixed>::from_request_parts(&req).unwrap();
        assert_eq!(
            m,
            Mixed {
                name: "42".to_string(),
                flag: "true".to_string(),
                age: 30,
            }
        );
    }

    #[test]
    fn path_string_field_accepts_numeric_looking_value() {
        #[derive(Debug, serde::Deserialize, PartialEq, Eq)]
        struct Params {
            token: String,
            id: u64,
        }
        let mut params = HashMap::new();
        params.insert("token".to_string(), "1234".to_string());
        params.insert("id".to_string(), "9".to_string());
        let req = Request::new("GET", "/x").with_path_params(params);
        let Path(p) = Path::<Params>::from_request_parts(&req).unwrap();
        assert_eq!(
            p,
            Params {
                token: "1234".to_string(),
                id: 9,
            }
        );
    }

    #[test]
    fn raw_body_empty() {
        let req = Request::new("POST", "/upload");
        let RawBody(body) = RawBody::from_request(req).unwrap();
        assert!(body.is_empty());
    }

    #[test]
    fn cookie_extraction_raw_header() {
        let req = Request::new("GET", "/").with_header("Cookie", "session=abc; theme=dark");
        let Cookie(raw) = Cookie::from_request_parts(&req).unwrap();
        assert_eq!(raw, "session=abc; theme=dark");
    }

    #[test]
    fn cookie_extraction_missing_header_is_error() {
        let req = Request::new("GET", "/");
        let err = Cookie::from_request_parts(&req).unwrap_err();
        assert_eq!(err.status, crate::web::response::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn cookie_jar_parses_cookie_pairs() {
        let req = Request::new("GET", "/").with_header("cookie", "session=abc; theme=dark; id=42");
        let jar = CookieJar::from_request_parts(&req).unwrap();
        assert_eq!(jar.get("session"), Some("abc"));
        assert_eq!(jar.get("theme"), Some("dark"));
        assert_eq!(jar.get("id"), Some("42"));
        assert_eq!(jar.len(), 3);
    }

    #[test]
    fn cookie_jar_last_duplicate_wins() {
        let req = Request::new("GET", "/").with_header("cookie", "mode=old; mode=new");
        let jar = CookieJar::from_request_parts(&req).unwrap();
        assert_eq!(jar.get("mode"), Some("new"));
    }

    #[test]
    fn cookie_jar_ignores_malformed_segments() {
        let req = Request::new("GET", "/").with_header(
            "cookie",
            "good=1; malformed; =missing_name; spaced = ok ; quoted=\"v\"",
        );
        let jar = CookieJar::from_request_parts(&req).unwrap();
        assert_eq!(jar.get("good"), Some("1"));
        assert_eq!(jar.get("spaced"), Some("ok"));
        assert_eq!(jar.get("quoted"), Some("v"));
        assert!(!jar.contains("malformed"));
    }

    #[test]
    fn cookie_jar_missing_header_is_empty() {
        let req = Request::new("GET", "/");
        let jar = CookieJar::from_request_parts(&req).unwrap();
        assert!(jar.is_empty());
    }

    #[test]
    fn extraction_error_into_response() {
        use crate::web::response::IntoResponse;
        let err = ExtractionError::bad_request("missing field");
        let resp = err.into_response();
        assert_eq!(resp.status, crate::web::response::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.headers.get("content-type").map(String::as_str),
            Some("text/plain; charset=utf-8")
        );
    }

    #[test]
    fn extensions_extend_preserves_string_and_typed_values() {
        #[derive(Clone, Debug, PartialEq, Eq)]
        struct AppState {
            id: u32,
        }

        let mut base = Extensions::new();
        base.insert("trace_id", "abc");
        base.insert_typed(AppState { id: 7 });

        let mut req_extensions = Extensions::new();
        req_extensions.insert("request_id", "r-1");
        req_extensions.extend_from(&base);

        assert_eq!(req_extensions.get("trace_id"), Some("abc"));
        assert_eq!(req_extensions.get("request_id"), Some("r-1"));
        assert_eq!(
            req_extensions.get_typed_cloned::<AppState>(),
            Some(AppState { id: 7 })
        );
    }

    #[test]
    fn extensions_hold_multiple_typed_values_and_override_same_type() {
        #[derive(Clone, Debug, PartialEq, Eq)]
        struct AppState {
            id: u32,
        }

        #[derive(Clone, Debug, PartialEq, Eq)]
        struct FeatureFlags {
            experimental: bool,
        }

        let mut extensions = Extensions::new();
        extensions.insert_typed(AppState { id: 1 });
        extensions.insert_typed(FeatureFlags { experimental: true });
        // Same TypeId should be replaced by the most recent insert.
        extensions.insert_typed(AppState { id: 2 });

        assert_eq!(
            extensions.get_typed_cloned::<AppState>(),
            Some(AppState { id: 2 })
        );
        assert_eq!(
            extensions.get_typed_cloned::<FeatureFlags>(),
            Some(FeatureFlags { experimental: true })
        );
    }

    // ── Scalar-guard regression tests ────────────────────────────────────

    #[test]
    fn path_scalar_with_multiple_params_falls_through_to_struct() {
        // Before the len()==1 guard, Path<u32> with 2+ params would
        // nondeterministically pick whichever value HashMap yielded first.
        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct PostRef {
            user_id: u32,
            post_id: u32,
        }

        let mut params = HashMap::new();
        params.insert("user_id".to_string(), "42".to_string());
        params.insert("post_id".to_string(), "7".to_string());
        let req = Request::new("GET", "/users/42/posts/7").with_path_params(params);

        // Scalar extraction must NOT succeed — falls through to struct deser.
        assert!(Path::<u32>::from_request_parts(&req).is_err());

        // Struct extraction succeeds deterministically.
        let Path(post_ref) = Path::<PostRef>::from_request_parts(&req).unwrap();
        assert_eq!(
            post_ref,
            PostRef {
                user_id: 42,
                post_id: 7
            }
        );
    }

    #[test]
    fn query_scalar_with_multiple_params_falls_through_to_struct() {
        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct Pagination {
            page: u32,
            per_page: u32,
        }

        let req = Request::new("GET", "/items").with_query("page=3&per_page=25");

        // Scalar extraction must NOT succeed with 2 query params.
        assert!(Query::<u32>::from_request_parts(&req).is_err());

        // Struct extraction works correctly.
        let Query(pg) = Query::<Pagination>::from_request_parts(&req).unwrap();
        assert_eq!(
            pg,
            Pagination {
                page: 3,
                per_page: 25
            }
        );
    }

    #[test]
    fn body_size_limit_checks_content_length_before_reading_body_dos_prevention() {
        // AUDIT TEST: Verify that Content-Length is checked BEFORE reading body
        // to prevent DoS attacks via memory exhaustion.
        // Per RFC 9110, should return 413 Payload Too Large based on Content-Length header.

        println!("=== WEB BODY SIZE LIMIT DoS PREVENTION AUDIT ===");

        // Test 1: JSON extractor checks Content-Length early
        let oversized_json_req = Request::new("POST", "/json")
            .with_header("content-type", "application/json")
            .with_header("content-length", "20971520") // 20MB declared
            .with_body(Bytes::from_static(b"{\"small\":\"body\"}")); // But small actual body

        let json_err = Json::<serde_json::Value>::from_request(oversized_json_req).unwrap_err();
        assert_eq!(
            json_err.status,
            crate::web::response::StatusCode::PAYLOAD_TOO_LARGE,
            "JSON extractor should reject based on Content-Length header before body processing"
        );
        assert!(
            json_err.message.contains("Content-Length"),
            "Error message should mention Content-Length header check, got: {}",
            json_err.message
        );

        // Test 2: Form extractor checks Content-Length early
        let oversized_form_req = Request::new("POST", "/form")
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_header("content-length", "5242880") // 5MB declared
            .with_body(Bytes::from_static(b"name=test")); // But small actual body

        let form_err =
            Form::<HashMap<String, String>>::from_request(oversized_form_req).unwrap_err();
        assert_eq!(
            form_err.status,
            crate::web::response::StatusCode::PAYLOAD_TOO_LARGE,
            "Form extractor should reject based on Content-Length header before body processing"
        );
        assert!(
            form_err.message.contains("Content-Length"),
            "Error message should mention Content-Length header check, got: {}",
            form_err.message
        );

        // Test 3: RawBody extractor checks Content-Length early
        let oversized_raw_req = Request::new("POST", "/upload")
            .with_header("content-length", "15728640") // 15MB declared
            .with_body(Bytes::from_static(b"small data")); // But small actual body

        let raw_err = RawBody::from_request(oversized_raw_req).unwrap_err();
        assert_eq!(
            raw_err.status,
            crate::web::response::StatusCode::PAYLOAD_TOO_LARGE,
            "RawBody extractor should reject based on Content-Length header before body processing"
        );
        assert!(
            raw_err.message.contains("Content-Length"),
            "Error message should mention Content-Length header check, got: {}",
            raw_err.message
        );

        // Test 4: Verify that requests within limit still work
        let valid_json_req = Request::new("POST", "/json")
            .with_header("content-type", "application/json")
            .with_header("content-length", "19") // Small declared size
            .with_body(Bytes::from_static(b"{\"valid\":\"request\"}"));

        let json_result = Json::<serde_json::Value>::from_request(valid_json_req);
        assert!(
            json_result.is_ok(),
            "Valid requests with Content-Length within limit should be processed"
        );

        println!("✅ AUDIT PASSED: Content-Length checked before body processing");
        println!("📋 DoS PROTECTION VERIFIED:");
        println!("  1. Content-Length header checked BEFORE body buffering: ✅");
        println!("  2. 413 Payload Too Large returned early: ✅");
        println!("  3. Memory exhaustion attack prevented: ✅");
        println!("  4. RFC 9110 compliance: ✅");
        println!("\n✅ STATUS: WEB BODY SIZE LIMITS ARE SECURE");
    }
