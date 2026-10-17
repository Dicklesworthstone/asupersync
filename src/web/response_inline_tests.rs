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
    #[test]
    fn http1_stream_responder_requires_produced_router_adapter() {
        let request = Request::new("GET", "/stream");
        let error = Http1StreamResponder::from_request_parts(&request)
            .expect_err("ordinary router requests have no produced-response authority");
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            error.message,
            "HTTP/1 streamed-response transport unavailable"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn http1_stream_responder_duplicate_registration_poisons_slot() {
        let slot = Http1StreamSlot::default();
        let mut request = Request::new("GET", "/stream");
        request.extensions.insert_typed(slot.clone());
        let first = Http1StreamResponder::from_request_parts(&request).expect("first extractor");
        let second = Http1StreamResponder::from_request_parts(&request).expect("second extractor");

        let first_response = first.chunked(
            StatusCode::OK,
            NonZeroUsize::MIN,
            |_cx, sender| async move { Ok(sender) },
        );
        assert_eq!(first_response.status, StatusCode::OK);
        let second_response = second.chunked(
            StatusCode::OK,
            NonZeroUsize::MIN,
            |_cx, sender| async move { Ok(sender) },
        );
        assert_eq!(second_response.status, StatusCode::INTERNAL_SERVER_ERROR);
        let refusal = match slot.bind_response(&first_response) {
            Err(refusal) => refusal,
            Ok(_) => {
                panic!("the adapter must refuse the whole request after a duplicate registration")
            }
        };
        assert_eq!(refusal, "streamed response registered more than once");

        let late_plan = Http1StreamPlan {
            body_kind: BodyKind::Chunked,
            capacity: NonZeroUsize::MIN,
            max_frame_bytes: NonZeroUsize::MIN,
            producer: Box::new(|_cx, sender| Box::pin(async move { Ok(sender) })),
        };
        assert!(
            slot.register(late_plan).is_err(),
            "a consumed slot must remain terminal"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn produced_h1_envelope_router_preserves_custom_frame_limit() {
        let slot = Http1StreamSlot::default();
        let mut request = Request::new("GET", "/stream");
        request.extensions.insert_typed(slot.clone());
        let responder =
            Http1StreamResponder::from_request_parts(&request).expect("stream responder");
        let limit = NonZeroUsize::new(7).unwrap();

        let response = responder.chunked_with_max_frame_bytes(
            StatusCode::OK,
            NonZeroUsize::new(3).unwrap(),
            limit,
            |_cx, sender| async move { Ok(sender) },
        );
        let plan = slot
            .bind_response(&response)
            .expect("valid produced response")
            .expect("registered stream plan");

        assert_eq!(plan.capacity, NonZeroUsize::new(3).unwrap());
        assert_eq!(plan.body_kind, BodyKind::Chunked);
        assert_eq!(plan.max_frame_bytes, limit);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn produced_h1_content_length_router_preserves_exact_framing() {
        let slot = Http1StreamSlot::default();
        let mut request = Request::new("GET", "/fixed");
        request.extensions.insert_typed(slot.clone());
        let responder =
            Http1StreamResponder::from_request_parts(&request).expect("stream responder");
        let limit = NonZeroUsize::new(4).unwrap();

        let response = responder.with_content_length_and_max_frame_bytes(
            StatusCode::OK,
            NonZeroUsize::new(2).unwrap(),
            limit,
            9,
            |_cx, sender| async move { Ok(sender) },
        );
        assert!(!response.has_header("content-length"));
        let plan = slot
            .bind_response(&response)
            .expect("valid fixed-length response")
            .expect("registered fixed-length plan");

        assert_eq!(plan.body_kind, BodyKind::ContentLength(9));
        assert_eq!(plan.capacity, NonZeroUsize::new(2).unwrap());
        assert_eq!(plan.max_frame_bytes, limit);

        let produced = plan.into_produced(response);
        assert_eq!(produced.body_kind(), BodyKind::ContentLength(9));
        assert_eq!(produced.max_frame_bytes(), limit);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn produced_h1_content_length_router_refuses_trailer_declaration() {
        let slot = Http1StreamSlot::default();
        let mut request = Request::new("GET", "/fixed");
        request.extensions.insert_typed(slot.clone());
        let responder =
            Http1StreamResponder::from_request_parts(&request).expect("stream responder");
        let response = responder
            .with_content_length(
                StatusCode::OK,
                NonZeroUsize::MIN,
                7,
                |_cx, sender| async move { Ok(sender) },
            )
            .header("trailer", "x-checksum");

        match slot.bind_response(&response) {
            Err(error) => assert_eq!(
                error,
                "fixed-length HTTP/1 produced responses cannot declare trailers"
            ),
            Ok(_) => panic!("fixed-length trailers must fail during Router binding"),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn produced_h1_envelope_buffered_route_preserves_large_body() {
        let body = Bytes::from(vec![
            b'x';
            Http1ProducedResponse::DEFAULT_MAX_FRAME_BYTES + 1
        ]);
        let body_len = body.len();
        let plan = Http1StreamPlan::buffered(body);

        assert_eq!(plan.body_kind, BodyKind::Chunked);
        assert_eq!(plan.capacity, NonZeroUsize::MIN);
        assert_eq!(plan.max_frame_bytes, NonZeroUsize::new(body_len).unwrap());

        let produced = plan.into_produced(Response::empty(StatusCode::OK));
        assert_eq!(
            produced.max_frame_bytes(),
            NonZeroUsize::new(body_len).unwrap()
        );
        assert_eq!(
            produced.max_retained_data_bytes(),
            u128::try_from(body_len).unwrap() * 3
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn http2_stream_responder_requires_produced_router_adapter() {
        let request = Request::new("GET", "/stream");
        let error = Http2StreamResponder::from_request_parts(&request)
            .expect_err("ordinary router requests have no HTTP/2 producer authority");
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            error.message,
            "HTTP/2 produced-response transport unavailable"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn http2_stream_responder_duplicate_registration_poisons_slot() {
        let slot = Http2StreamSlot::default();
        let mut request = Request::new("GET", "/stream");
        request.extensions.insert_typed(slot.clone());
        let first = Http2StreamResponder::from_request_parts(&request).expect("first extractor");
        let second = Http2StreamResponder::from_request_parts(&request).expect("second extractor");

        let first_response = first.streaming(
            StatusCode::OK,
            NonZeroUsize::MIN,
            NonZeroUsize::new(1024).expect("non-zero frame limit"),
            |_cx, sender| async move { Ok(sender) },
        );
        assert_eq!(first_response.status, StatusCode::OK);
        let second_response = second.streaming(
            StatusCode::OK,
            NonZeroUsize::MIN,
            NonZeroUsize::new(1024).expect("non-zero frame limit"),
            |_cx, sender| async move { Ok(sender) },
        );
        assert_eq!(second_response.status, StatusCode::INTERNAL_SERVER_ERROR);
        let refusal = match slot.bind_response(&first_response, false) {
            Err(refusal) => refusal,
            Ok(_) => panic!("duplicate registration must poison the request"),
        };
        assert_eq!(refusal, "HTTP/2 response producer registered twice");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn http2_stream_binding_rejects_body_and_framing_collisions() {
        fn registered_slot() -> Http2StreamSlot {
            let slot = Http2StreamSlot::default();
            assert!(
                slot.register(Http2StreamPlan {
                    capacity: NonZeroUsize::MIN,
                    max_frame_bytes: NonZeroUsize::MIN,
                    producer: Box::new(|_cx, sender| Box::pin(async move { Ok(sender) })),
                })
                .is_ok(),
                "first registration succeeds"
            );
            slot
        }

        fn refusal(result: Result<Option<Http2StreamPlan>, &'static str>) -> &'static str {
            match result {
                Err(reason) => reason,
                Ok(_) => panic!("binding should fail closed"),
            }
        }

        assert_eq!(
            refusal(
                registered_slot().bind_response(&Response::new(StatusCode::OK, "buffered"), false)
            ),
            "produced HTTP/2 response cannot also carry a buffered body"
        );
        assert_eq!(
            refusal(
                registered_slot().bind_response(&Response::empty(StatusCode::NO_CONTENT), false)
            ),
            "produced HTTP/2 response requires a body-allowed status"
        );
        assert_eq!(
            refusal(registered_slot().bind_response(
                &Response::empty(StatusCode::OK).header("content-length", "0"),
                false,
            )),
            "produced HTTP/2 response owns message framing"
        );
        assert!(
            registered_slot()
                .bind_response(
                    &Response::empty(StatusCode::NO_CONTENT).header("content-length", "0"),
                    true,
                )
                .expect("HEAD may preserve authored response metadata without starting a body")
                .is_some()
        );
    }

    #[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
    #[test]
    fn produced_h3_stream_responder_requires_produced_router_adapter() {
        let request = Request::new("GET", "/stream");
        let error = Http3StreamResponder::from_request_parts(&request)
            .expect_err("ordinary router requests have no HTTP/3 producer authority");
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            error.message,
            "HTTP/3 produced-response transport unavailable"
        );
    }

    #[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
    #[test]
    fn produced_h3_stream_responder_duplicate_registration_poisons_slot() {
        let slot = Http3StreamSlot::default();
        let mut request = Request::new("GET", "/stream");
        request.extensions.insert_typed(slot.clone());
        let first = Http3StreamResponder::from_request_parts(&request).expect("first extractor");
        let second = Http3StreamResponder::from_request_parts(&request).expect("second extractor");

        let first_response = first.streaming(
            StatusCode::OK,
            NonZeroUsize::MIN,
            NonZeroUsize::new(1024).expect("non-zero frame limit"),
            |_cx, sender| async move { Ok(sender) },
        );
        assert_eq!(first_response.status, StatusCode::OK);
        let second_response = second.streaming(
            StatusCode::OK,
            NonZeroUsize::MIN,
            NonZeroUsize::new(1024).expect("non-zero frame limit"),
            |_cx, sender| async move { Ok(sender) },
        );
        assert_eq!(second_response.status, StatusCode::INTERNAL_SERVER_ERROR);
        let refusal = match slot.bind_response(&first_response, false) {
            Err(refusal) => refusal,
            Ok(_) => panic!("duplicate registration must poison the request"),
        };
        assert_eq!(refusal, "HTTP/3 response producer registered twice");
    }

    #[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
    #[test]
    fn produced_h3_stream_binding_rejects_body_and_framing_collisions() {
        fn registered_slot() -> Http3StreamSlot {
            let slot = Http3StreamSlot::default();
            assert!(
                slot.register(Http3StreamPlan {
                    capacity: NonZeroUsize::MIN,
                    max_frame_bytes: NonZeroUsize::MIN,
                    producer: Box::new(|_cx, sender| Box::pin(async move { Ok(sender) })),
                })
                .is_ok(),
                "first registration succeeds"
            );
            slot
        }

        fn refusal(result: Result<Option<Http3StreamPlan>, &'static str>) -> &'static str {
            match result {
                Err(reason) => reason,
                Ok(_) => panic!("binding should fail closed"),
            }
        }

        assert_eq!(
            refusal(
                registered_slot().bind_response(&Response::new(StatusCode::OK, "buffered"), false)
            ),
            "produced HTTP/3 response cannot also carry a buffered body"
        );
        assert_eq!(
            refusal(
                registered_slot().bind_response(&Response::empty(StatusCode::NO_CONTENT), false)
            ),
            "produced HTTP/3 response requires a body-allowed status"
        );
        assert_eq!(
            refusal(registered_slot().bind_response(
                &Response::empty(StatusCode::OK).header("content-length", "0"),
                false,
            )),
            "produced HTTP/3 response owns message framing"
        );
        assert!(
            registered_slot()
                .bind_response(
                    &Response::empty(StatusCode::NO_CONTENT).header("content-length", "0"),
                    true,
                )
                .expect("HEAD may preserve authored response metadata without starting a body")
                .is_some()
        );
    }

    #[test]
    fn status_code_into_response() {
        let resp = StatusCode::NOT_FOUND.into_response();
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
        assert!(resp.body.is_empty());
    }

    #[test]
    fn string_into_response() {
        let resp = "hello".into_response();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/plain; charset=utf-8"
        );
    }

    #[test]
    fn json_into_response() {
        let resp = Json(serde_json::json!({"ok": true})).into_response();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "application/json"
        );
        assert!(!resp.body.is_empty());
    }

    #[test]
    fn html_into_response() {
        let resp = Html("<h1>Hello</h1>").into_response();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/html; charset=utf-8"
        );
    }

    #[test]
    fn redirect_into_response() {
        let resp = Redirect::to("/login")
            .expect("relative path must validate")
            .into_response();
        assert_eq!(resp.status, StatusCode::FOUND);
        assert_eq!(resp.headers.get("location").unwrap(), "/login");
    }

    /// br-asupersync-0hj233: Redirect::to MUST reject external URIs by
    /// default; only relative paths and URIs in an explicit allow-list
    /// (via to_with_allowed_hosts) are accepted. external_unchecked is
    /// the explicit escape hatch.
    #[test]
    fn redirect_to_rejects_external_uri_by_default() {
        // External http URL with arbitrary attacker host — REJECTED.
        let err = Redirect::to("https://attacker.com/phish").unwrap_err();
        assert!(
            matches!(err, RedirectError::HostNotAllowed { .. }),
            "external https URL must be rejected, got {err:?}"
        );

        // External http URL — REJECTED.
        let err = Redirect::to("http://attacker.com").unwrap_err();
        assert!(matches!(err, RedirectError::HostNotAllowed { .. }));

        // Same for permanent and temporary.
        assert!(Redirect::permanent("https://attacker.com").is_err());
        assert!(Redirect::temporary("https://attacker.com").is_err());
    }

    /// br-asupersync-0hj233: protocol-relative URLs '//attacker.com'
    /// are the canonical bypass for naive starts_with('/') defenses
    /// and MUST be rejected with the dedicated ProtocolRelative error
    /// so the failure mode is debuggable.
    #[test]
    fn redirect_to_rejects_protocol_relative_url() {
        let err = Redirect::to("//attacker.com/phish").unwrap_err();
        assert!(
            matches!(err, RedirectError::ProtocolRelative),
            "//... URL must be rejected as ProtocolRelative, got {err:?}"
        );
    }

    /// br-asupersync-0hj233: backslash variant of the protocol-relative
    /// bypass — some intermediaries normalize '\\' to '/' producing
    /// '//attacker.com'. Reject the backslash form too.
    #[test]
    fn redirect_to_rejects_backslash_path() {
        let err = Redirect::to("/\\attacker.com/phish").unwrap_err();
        assert!(
            matches!(err, RedirectError::BackslashInPath),
            "backslash in path must be rejected, got {err:?}"
        );
    }

    /// br-asupersync-0hj233: javascript: / data: / file: schemes MUST
    /// be rejected. Some browsers historically followed javascript:
    /// URLs in Location headers, enabling stored-XSS-via-redirect.
    #[test]
    fn redirect_to_rejects_non_http_schemes() {
        for uri in &[
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "file:///etc/passwd",
            "ftp://attacker.com/",
        ] {
            let err = Redirect::to(*uri).unwrap_err();
            assert!(
                matches!(err, RedirectError::SchemeNotAllowed { .. }),
                "{uri} must be rejected as SchemeNotAllowed, got {err:?}"
            );
        }
    }

    /// br-asupersync-0hj233: empty URI is invalid.
    #[test]
    fn redirect_to_rejects_empty_uri() {
        let err = Redirect::to("").unwrap_err();
        assert!(matches!(err, RedirectError::EmptyUri));
    }

    /// br-asupersync-0hj233: relative paths with various edge-case
    /// shapes are accepted.
    #[test]
    fn redirect_to_accepts_well_formed_relative_paths() {
        for uri in &[
            "/",
            "/login",
            "/path/with/multiple/segments",
            "/path?with=query",
            "/path#fragment",
            "/path?next=/another",
        ] {
            assert!(
                Redirect::to(*uri).is_ok(),
                "relative path {uri} must validate"
            );
        }
    }

    /// br-asupersync-0hj233: to_with_allowed_hosts accepts absolute
    /// URIs whose host is allow-listed and rejects others.
    #[test]
    fn redirect_to_with_allowed_hosts_accepts_listed_rejects_others() {
        let allowed = &["example.com", "auth.example.com"];

        // Listed host — accepted.
        assert!(Redirect::to_with_allowed_hosts("https://example.com/path", allowed).is_ok());
        assert!(
            Redirect::to_with_allowed_hosts(
                "https://auth.example.com/oauth/callback?code=xyz",
                allowed
            )
            .is_ok()
        );
        // Case-insensitive host matching.
        assert!(Redirect::to_with_allowed_hosts("HTTPS://EXAMPLE.COM/", allowed).is_ok());
        // Relative path always accepted.
        assert!(Redirect::to_with_allowed_hosts("/local-path", allowed).is_ok());

        // Unlisted host — rejected.
        let err =
            Redirect::to_with_allowed_hosts("https://attacker.com/phish", allowed).unwrap_err();
        assert!(matches!(err, RedirectError::HostNotAllowed { .. }));

        // Subdomain not in allowlist — rejected (allowlist is exact match).
        let err =
            Redirect::to_with_allowed_hosts("https://evil.example.com/", allowed).unwrap_err();
        assert!(matches!(err, RedirectError::HostNotAllowed { .. }));

        // Userinfo: browsers go to the host after the last '@'. The host was
        // taken from before the last ':', so these passed the allowlist.
        for uri in [
            "https://example.com:443@attacker.com/",
            "https://example.com:@attacker.com/",
            "https://example.com@attacker.com/",
            "https://user:pass@example.com/",
        ] {
            let err = Redirect::to_with_allowed_hosts(uri, allowed).unwrap_err();
            assert!(
                matches!(err, RedirectError::HostNotAllowed { .. }),
                "{uri} must be refused, got {err:?}"
            );
        }
        // Ports and IPv6 literals still resolve to their host.
        assert!(Redirect::to_with_allowed_hosts("https://example.com:8443/x", allowed).is_ok());
        let ipv6 = &["::1"];
        assert!(Redirect::to_with_allowed_hosts("https://[::1]:8443/x", ipv6).is_ok());
        assert!(Redirect::to_with_allowed_hosts("https://[::1]/x", ipv6).is_ok());

        // Protocol-relative even with allowlist — still rejected.
        let err = Redirect::to_with_allowed_hosts("//example.com/path", allowed).unwrap_err();
        assert!(matches!(err, RedirectError::ProtocolRelative));
    }

    /// br-asupersync-0hj233: external_unchecked is the explicit escape
    /// hatch for callers that genuinely need external redirects without
    /// an allowlist (e.g., dynamic OAuth providers). Verifies the API
    /// is reachable AND honors the URI verbatim.
    #[test]
    fn redirect_external_unchecked_accepts_arbitrary_uri() {
        // The whole point: NO validation — caller asserts trust.
        let r = Redirect::external_unchecked("https://anywhere.example/path?q=1");
        assert_eq!(r.status, StatusCode::FOUND);
        assert_eq!(r.location, "https://anywhere.example/path?q=1");

        let r = Redirect::external_unchecked_permanent("https://moved.example/");
        assert_eq!(r.status, StatusCode::MOVED_PERMANENTLY);

        let r = Redirect::external_unchecked_temporary("https://temp.example/");
        assert_eq!(r.status, StatusCode::TEMPORARY_REDIRECT);
    }

    #[test]
    fn tuple_status_override() {
        let resp = (StatusCode::CREATED, "done").into_response();
        assert_eq!(resp.status, StatusCode::CREATED);
    }

    #[test]
    fn response_header_helpers_are_case_insensitive() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.headers
            .insert("Content-Type".to_string(), "text/plain".to_string());

        assert_eq!(resp.header_value("content-type"), Some("text/plain"));
        assert_eq!(resp.header_value("CONTENT-TYPE"), Some("text/plain"));
        assert!(resp.has_header("content-type"));
    }

    #[test]
    fn response_set_header_canonicalizes_existing_case_variant() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.headers
            .insert("X-Trace-Id".to_string(), "old".to_string());

        resp.set_header("x-trace-id", "new");

        assert_eq!(resp.headers.get("x-trace-id"), Some(&"new".to_string()));
        assert!(!resp.headers.contains_key("X-Trace-Id"));
    }

    #[test]
    fn response_ensure_header_preserves_existing_value_and_canonicalizes_name() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.headers
            .insert("Server".to_string(), "custom".to_string());

        resp.ensure_header("server", "fallback");

        assert_eq!(resp.headers.get("server"), Some(&"custom".to_string()));
        assert!(!resp.headers.contains_key("Server"));
    }

    #[test]
    fn response_remove_header_clears_case_variants() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.headers.insert("Server".to_string(), "one".to_string());
        resp.headers.insert("server".to_string(), "two".to_string());

        let removed = resp.remove_header("SERVER");

        assert_eq!(removed.as_deref(), Some("two"));
        assert!(!resp.has_header("server"));
        assert!(resp.headers.is_empty());
    }

    #[test]
    fn result_ok_response() {
        let resp: Result<&str, StatusCode> = Ok("success");
        let r = resp.into_response();
        assert_eq!(r.status, StatusCode::OK);
    }

    #[test]
    fn result_err_response() {
        let resp: Result<&str, StatusCode> = Err(StatusCode::BAD_REQUEST);
        let r = resp.into_response();
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn status_code_properties() {
        assert!(StatusCode::OK.is_success());
        assert!(!StatusCode::OK.is_client_error());
        assert!(StatusCode::NOT_FOUND.is_client_error());
        assert!(StatusCode::INTERNAL_SERVER_ERROR.is_server_error());
    }

    // =========================================================================
    // Wave 50 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn status_code_debug_clone_copy_hash_display() {
        use std::collections::HashSet;
        let sc = StatusCode::OK;
        let dbg = format!("{sc:?}");
        assert!(dbg.contains("StatusCode"), "{dbg}");
        assert!(dbg.contains("200"), "{dbg}");
        let copied = sc;
        let cloned = sc;
        assert_eq!(copied, cloned);
        let display = format!("{sc}");
        assert_eq!(display, "200");
        let mut set = HashSet::new();
        set.insert(sc);
        assert!(set.contains(&StatusCode::OK));
    }

    #[test]
    fn response_debug_clone() {
        let resp = Response::new(StatusCode::OK, Bytes::from_static(b"hi"));
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("Response"), "{dbg}");
        let cloned = resp;
        assert_eq!(cloned.status, StatusCode::OK);
    }

    #[test]
    fn redirect_debug_clone() {
        let r = Redirect::to("/home").expect("relative path must validate");
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Redirect"), "{dbg}");
        let cloned = r;
        let dbg2 = format!("{cloned:?}");
        assert_eq!(dbg, dbg2);
    }

    // =========================================================================
    // CRLF injection defense
    // =========================================================================

    #[test]
    fn set_header_strips_crlf_from_value() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.set_header("x-test", "value\r\nEvil-Header: injected");
        assert_eq!(
            resp.headers.get("x-test").unwrap(),
            "valueEvil-Header: injected"
        );
    }

    #[test]
    fn set_header_strips_bare_lf_from_value() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.set_header("x-test", "line1\nline2");
        assert_eq!(resp.headers.get("x-test").unwrap(), "line1line2");
    }

    #[test]
    fn set_header_strips_bare_cr_from_value() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.set_header("x-test", "line1\rline2");
        assert_eq!(resp.headers.get("x-test").unwrap(), "line1line2");
    }

    #[test]
    fn builder_header_strips_crlf() {
        let resp = Response::empty(StatusCode::OK).header("x-test", "safe\r\nX-Injected: oops");
        assert_eq!(resp.headers.get("x-test").unwrap(), "safeX-Injected: oops");
    }

    #[test]
    fn ensure_header_strips_crlf_from_default() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.ensure_header("x-test", "default\r\nEvil: yes");
        assert_eq!(resp.headers.get("x-test").unwrap(), "defaultEvil: yes");
    }

    #[test]
    fn tuple_headers_strip_crlf() {
        let resp = (
            StatusCode::OK,
            vec![("x-test".to_string(), "a\r\nb".to_string())],
            "body",
        )
            .into_response();
        assert_eq!(resp.headers.get("x-test").unwrap(), "ab");
    }

    #[test]
    fn set_header_strips_crlf_from_name() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.set_header("x-test\r\nEvil-Header: injected", "value");
        // Invalid field-name bytes are stripped before lowercasing/insertion,
        // so the wire-format encoder never sees an injection vector or an
        // unserializable header name.
        assert!(resp.headers.contains_key("x-testevil-headerinjected"));
        assert!(
            !resp
                .headers
                .keys()
                .any(|k| k.contains(['\r', '\n', ':', ' ']))
        );
    }

    #[test]
    fn ensure_header_strips_crlf_from_name() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.ensure_header("x-test\r\nEvil:", "value");
        assert!(
            !resp
                .headers
                .keys()
                .any(|k| k.contains('\r') || k.contains('\n'))
        );
    }

    #[test]
    fn tuple_headers_strip_crlf_from_name() {
        let resp = (
            StatusCode::OK,
            vec![("x-test\r\nEvil:".to_string(), "value".to_string())],
            "body",
        )
            .into_response();
        assert!(
            !resp
                .headers
                .keys()
                .any(|k| k.contains('\r') || k.contains('\n'))
        );
    }

    #[test]
    fn clean_header_value_passes_through_unchanged() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.set_header("x-test", "normal-value");
        assert_eq!(resp.headers.get("x-test").unwrap(), "normal-value");
    }

    /// br-asupersync-ehtkns: Set-Cookie is multi-valued; calling
    /// `set_header("set-cookie", X)` (or `.header()`) twice must
    /// preserve BOTH cookies. Before the fix, the HashMap-backed
    /// header store silently dropped the first cookie, which let
    /// SessionMiddleware overwrite handler-emitted CSRF / remember-me
    /// cookies.
    #[test]
    fn set_cookie_appends_instead_of_overwriting() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.set_header("set-cookie", "csrf=abc123; HttpOnly");
        resp.set_header("set-cookie", "session=def456; HttpOnly; Secure");
        assert_eq!(resp.set_cookies.len(), 2, "both cookies must survive");
        assert_eq!(resp.set_cookies[0], "csrf=abc123; HttpOnly");
        assert_eq!(resp.set_cookies[1], "session=def456; HttpOnly; Secure");
        // Set-Cookie is NOT routed into the regular headers map.
        assert!(!resp.headers.contains_key("set-cookie"));
        // Case-insensitive header lookup still surfaces the first cookie
        // for backward compatibility with single-cookie callers.
        assert_eq!(
            resp.header_value("Set-Cookie"),
            Some("csrf=abc123; HttpOnly"),
        );
        assert!(resp.has_header("set-cookie"));
    }

    /// br-asupersync-ehtkns: append_set_cookie still strips CR/LF
    /// from the cookie line so a malicious cookie value cannot smuggle
    /// a second header onto the wire.
    #[test]
    fn append_set_cookie_strips_crlf_from_value() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.append_set_cookie("session=abc\r\nX-Injected: yes");
        assert_eq!(resp.set_cookies.len(), 1);
        assert!(!resp.set_cookies[0].contains('\r'));
        assert!(!resp.set_cookies[0].contains('\n'));
    }

    /// br-asupersync-ehtkns: removing the Set-Cookie header drains
    /// every queued cookie and surfaces the first as the legacy
    /// single-value return.
    #[test]
    fn remove_set_cookie_drains_all_queued_cookies() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.append_set_cookie("a=1");
        resp.append_set_cookie("b=2");
        let dropped = resp.remove_header("Set-Cookie");
        assert_eq!(dropped.as_deref(), Some("a=1"));
        assert!(resp.set_cookies.is_empty(), "no cookies should remain");
    }

    #[test]
    fn json_html_debug_clone() {
        let j = Json(42);
        let dbg = format!("{j:?}");
        assert!(dbg.contains("Json"), "{dbg}");
        let jc = j;
        assert_eq!(format!("{jc:?}"), dbg);

        let h = Html("hello");
        let dbg2 = format!("{h:?}");
        assert!(dbg2.contains("Html"), "{dbg2}");
        let hc = h.clone();
        assert_eq!(format!("{hc:?}"), dbg2);
    }

    // ====================================================================
    // br-asupersync-5jtjo0: header-value sanitiser allowlist tests
    // ====================================================================

    #[test]
    fn _5jtjo0_strips_nul_byte_from_header_value() {
        let raw = String::from("alice\u{0000}forged-header: value");
        let cleaned = sanitize_header_value(raw);
        assert!(!cleaned.contains('\u{0000}'));
        assert_eq!(cleaned, "aliceforged-header: value");
    }

    #[test]
    fn _5jtjo0_strips_c0_control_bytes() {
        // 0x01-0x08, 0x0B, 0x0C, 0x0E-0x1F all rejected.
        let raw: String = (0x01u8..=0x1F)
            .filter(|b| *b != 0x09) // HTAB stays
            .map(|b| b as char)
            .collect::<String>()
            + "trailing";
        let cleaned = sanitize_header_value(raw);
        // Only "trailing" survives — every C0 control was stripped.
        assert_eq!(cleaned, "trailing");
    }

    #[test]
    fn _5jtjo0_preserves_htab_space_printable_ascii() {
        let raw = String::from("\tHello, World! 123 -_+=()[];,./?\\:");
        let cleaned = sanitize_header_value(raw.clone());
        assert_eq!(cleaned, raw);
    }

    #[test]
    fn _5jtjo0_preserves_obs_text_utf8_passthrough() {
        // UTF-8 codepoints whose bytes are >= 0x80 survive intact
        // (allowlist accepts 0x80..=0xFF as obs-text).
        let raw = String::from("café résumé日本語");
        let cleaned = sanitize_header_value(raw.clone());
        assert_eq!(cleaned, raw);
    }

    #[test]
    fn _5jtjo0_strips_crlf_legacy_behavior_preserved() {
        let raw = String::from("first\r\nforged-header: bad");
        let cleaned = sanitize_header_value(raw);
        assert_eq!(cleaned, "firstforged-header: bad");
    }

    #[test]
    fn _5jtjo0_strips_del_byte() {
        let raw = String::from("hello\u{007F}world");
        let cleaned = sanitize_header_value(raw);
        assert_eq!(cleaned, "helloworld");
    }

    // ====================================================================
    // br-asupersync-oms1b7: redirect protocol-relative + bypass tests
    // ====================================================================

    // ====================================================================
    // br-asupersync-n5b94b: TOCTOU vulnerability fixes
    // ====================================================================

    #[test]
    fn n5b94b_redirect_sanitization_matches_validation_strictness() {
        // Validation rejects control characters, final sanitization must too
        let redirect = Redirect::external_unchecked("http://example.com/path\x01\x1F");
        let response = redirect.into_response();
        let location = response.headers.get("location").unwrap();

        // Control characters must be stripped to match validation strictness
        assert!(!location.contains('\x01'));
        assert!(!location.contains('\x1F'));
        assert_eq!(location, "http://example.com/path");
    }

    #[test]
    fn n5b94b_header_name_sanitization_consistency() {
        let mut resp = Response::new(StatusCode::OK, "test");

        // Header names should be sanitized consistently with values
        resp.set_header("x-test\r\n-header\x01", "value");

        // Control characters should be stripped from header name
        let headers: Vec<_> = resp.headers.keys().collect();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0], "x-test-header");
    }

    #[test]
    fn n5b94b_header_case_normalization_atomic() {
        let mut resp = Response::new(StatusCode::OK, "test");

        // Add multiple case variants
        resp.headers
            .insert("X-Test".to_string(), "value1".to_string());
        resp.headers
            .insert("x-TEST".to_string(), "value2".to_string());
        resp.headers
            .insert("X-test".to_string(), "value3".to_string());

        // set_header should atomically remove all case variants
        resp.set_header("x-test", "final");

        let test_headers: Vec<_> = resp
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("x-test"))
            .collect();

        assert_eq!(
            test_headers.len(),
            1,
            "All case variants should be removed atomically"
        );
        assert_eq!(test_headers[0].0, "x-test");
        assert_eq!(test_headers[0].1, "final");
    }

    #[test]
    fn n5b94b_ensure_header_atomic_check_and_set() {
        let mut resp = Response::new(StatusCode::OK, "test");

        // Add header with non-normalized case
        resp.headers
            .insert("X-Custom".to_string(), "existing".to_string());

        // ensure_header should preserve existing value atomically
        resp.ensure_header("x-custom", "default");

        let custom_headers: Vec<_> = resp
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("x-custom"))
            .collect();

        assert_eq!(
            custom_headers.len(),
            1,
            "Should be exactly one header after ensure"
        );
        assert_eq!(custom_headers[0].0, "x-custom"); // normalized case
        assert_eq!(custom_headers[0].1, "existing"); // preserved value
    }

    #[test]
    fn oms1b7_rejects_protocol_relative() {
        let err = Redirect::to("//attacker.com/path").unwrap_err();
        assert!(matches!(err, RedirectError::ProtocolRelative));
    }

    #[test]
    fn oms1b7_rejects_leading_whitespace_then_protocol_relative() {
        // Without the byte-level prefilter, ` //attacker.com` could
        // bypass the `starts_with("//")` check on lenient browsers.
        let err = Redirect::to(" //attacker.com").unwrap_err();
        assert!(matches!(err, RedirectError::ProtocolRelative), "{err:?}");
    }

    #[test]
    fn oms1b7_rejects_leading_tab_then_protocol_relative() {
        let err = Redirect::to("\t//attacker.com").unwrap_err();
        assert!(matches!(err, RedirectError::ProtocolRelative), "{err:?}");
    }

    #[test]
    fn oms1b7_rejects_leading_crlf() {
        let err = Redirect::to("\r\n//attacker.com").unwrap_err();
        assert!(matches!(err, RedirectError::ProtocolRelative), "{err:?}");
    }

    #[test]
    fn oms1b7_rejects_percent_encoded_double_slash() {
        // /%2fattacker.com would be normalised by some browsers to
        // //attacker.com after percent-decoding. Reject up front.
        let err = Redirect::to("/%2fattacker.com").unwrap_err();
        assert!(matches!(err, RedirectError::ProtocolRelative), "{err:?}");
        let err = Redirect::to("/%2Fattacker.com").unwrap_err();
        assert!(matches!(err, RedirectError::ProtocolRelative), "{err:?}");
    }

    #[test]
    fn oms1b7_rejects_percent_encoded_backslash_after_slash() {
        let err = Redirect::to("/%5cattacker.com").unwrap_err();
        assert!(matches!(err, RedirectError::ProtocolRelative), "{err:?}");
    }

    #[test]
    fn oms1b7_accepts_legitimate_relative_paths() {
        assert!(Redirect::to("/login").is_ok());
        assert!(Redirect::to("/api/v1/foo?x=1&y=2").is_ok());
        assert!(Redirect::to("/path#anchor").is_ok());
    }

    #[test]
    fn oms1b7_rejects_null_byte_in_uri() {
        let err = Redirect::to("/safe\u{0000}//attacker.com").unwrap_err();
        // NUL is outside 0x21..=0x7E so caught by the byte prefilter.
        assert!(matches!(err, RedirectError::ProtocolRelative), "{err:?}");
    }
