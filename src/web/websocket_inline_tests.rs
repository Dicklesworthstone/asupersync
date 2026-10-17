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
    use crate::net::websocket::ServerHandshake;

    /// Build a valid WebSocket upgrade request.
    fn ws_request() -> Request {
        Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
    }

    // ─── Extraction tests ─────────────────────────────────────────────

    #[test]
    fn valid_upgrade_request_extracts_successfully() {
        let req = ws_request();
        let upgrade = WebSocketUpgrade::from_request(req).unwrap();
        // RFC 6455 example: dGhlIHNhbXBsZSBub25jZQ== → s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
        assert_eq!(upgrade.accept_key(), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn on_upgrade_requires_http1_transport_slot() {
        let response = WebSocketUpgrade::from_request(ws_request())
            .unwrap()
            .skip_origin_check()
            .on_upgrade(|_, _| async {});

        assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.body,
            Bytes::from_static(b"HTTP/1 WebSocket upgrade transport unavailable")
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn on_upgrade_registers_exactly_one_callback() {
        let slot = Http1UpgradeSlot::default();
        let mut first_request = ws_request();
        first_request.extensions.insert_typed(slot.clone());
        let mut second_request = ws_request();
        second_request.extensions.insert_typed(slot.clone());

        let first = WebSocketUpgrade::from_request(first_request)
            .unwrap()
            .skip_origin_check()
            .on_upgrade(|_, _| async {});
        let second = WebSocketUpgrade::from_request(second_request)
            .unwrap()
            .skip_origin_check()
            .on_upgrade(|_, _| async {});

        assert_eq!(first.status, StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(second.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            second.body,
            Bytes::from_static(b"HTTP/1 WebSocket upgrade callback already registered")
        );
        assert!(
            slot.take().is_err(),
            "a duplicate attempt poisons the request instead of retaining either callback"
        );
        assert!(slot.take().unwrap().is_none(), "the slot resets after take");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn rejected_origin_does_not_register_upgrade_callback() {
        let slot = Http1UpgradeSlot::default();
        let mut request = ws_request()
            .with_header("host", "api.example.com")
            .with_header("origin", "https://evil.example");
        request.extensions.insert_typed(slot.clone());

        let response = WebSocketUpgrade::from_request(request)
            .unwrap()
            .on_upgrade(|_, _| async {});

        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert!(slot.take().unwrap().is_none());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn unimplemented_extension_does_not_register_upgrade_callback() {
        let slot = Http1UpgradeSlot::default();
        let mut request =
            ws_request().with_header("sec-websocket-extensions", "x-unimplemented");
        request.extensions.insert_typed(slot.clone());

        let response = WebSocketUpgrade::from_request(request)
            .unwrap()
            .skip_origin_check()
            .extensions(["x-unimplemented"])
            .on_upgrade(|_, _| async {});

        assert_eq!(response.status, StatusCode::NOT_IMPLEMENTED);
        assert!(slot.take().unwrap().is_none());
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "compression"))]
    #[test]
    fn permessage_deflate_live_upgrade_registers_validated_parameters() {
        let slot = Http1UpgradeSlot::default();
        let mut request = ws_request().with_header("sec-websocket-extensions", "permessage-deflate; client_max_window_bits");
        request.extensions.insert_typed(slot.clone());
        let response = WebSocketUpgrade::from_request(request).unwrap().skip_origin_check()
            .extensions(["permessage-deflate"]).on_upgrade(|_, ws| async move { assert!(ws.compression_enabled()); });
        assert_eq!(response.status, StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(response.headers.get("sec-websocket-extensions").unwrap(),
            "permessage-deflate; server_no_context_takeover; client_no_context_takeover; client_max_window_bits=15");
        assert!(slot.take().unwrap().is_some());
    }

    // ─── CSWSH origin-validation tests (br-asupersync-o2t5gz) ─────────

    #[test]
    fn cswsh_default_same_origin_accepts_matching_origin() {
        let req = ws_request()
            .with_header("host", "api.example.com")
            .with_header("origin", "https://api.example.com");
        let upgrade = WebSocketUpgrade::from_request(req).unwrap();
        let resp = upgrade.into_response();
        assert_eq!(resp.status, StatusCode::SWITCHING_PROTOCOLS);
    }

    #[test]
    fn cswsh_default_same_origin_rejects_cross_origin() {
        let req = ws_request()
            .with_header("host", "api.example.com")
            .with_header("origin", "https://evil.example");
        let upgrade = WebSocketUpgrade::from_request(req).unwrap();
        let resp = upgrade.into_response();
        assert_eq!(
            resp.status,
            StatusCode::FORBIDDEN,
            "cross-origin browser request must be rejected by the default policy"
        );
    }

    #[test]
    fn cswsh_origin_header_strips_path_to_prevent_smuggling() {
        // A malformed Origin like https://victim.com/../api.example.com:443
        // must NOT compare equal to api.example.com:443 — strip at first '/'.
        let req = ws_request()
            .with_header("host", "api.example.com")
            .with_header("origin", "https://victim.com/../api.example.com");
        let upgrade = WebSocketUpgrade::from_request(req).unwrap();
        let resp = upgrade.into_response();
        assert_eq!(resp.status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn cswsh_no_origin_header_is_accepted_as_non_browser_client() {
        // Non-browser clients (curl, native apps, server-to-server) don't
        // send Origin. Default policy must not lock them out.
        let req = ws_request().with_header("host", "api.example.com");
        let upgrade = WebSocketUpgrade::from_request(req).unwrap();
        let resp = upgrade.into_response();
        assert_eq!(resp.status, StatusCode::SWITCHING_PROTOCOLS);
    }

    #[test]
    fn cswsh_allow_origins_accepts_listed_origin() {
        let req = ws_request()
            .with_header("host", "api.example.com")
            .with_header("origin", "https://app.example.com");
        let upgrade = WebSocketUpgrade::from_request(req)
            .unwrap()
            .allow_origins(["https://app.example.com", "https://other.example.com"]);
        let resp = upgrade.into_response();
        assert_eq!(resp.status, StatusCode::SWITCHING_PROTOCOLS);
    }

    #[test]
    fn cswsh_allow_origins_rejects_unlisted_origin() {
        let req = ws_request()
            .with_header("host", "api.example.com")
            .with_header("origin", "https://attacker.example");
        let upgrade = WebSocketUpgrade::from_request(req)
            .unwrap()
            .allow_origins(["https://app.example.com"]);
        let resp = upgrade.into_response();
        assert_eq!(resp.status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn cswsh_skip_origin_check_lets_anything_through() {
        let req = ws_request()
            .with_header("host", "api.example.com")
            .with_header("origin", "https://anything-goes.example");
        let upgrade = WebSocketUpgrade::from_request(req)
            .unwrap()
            .skip_origin_check();
        let resp = upgrade.into_response();
        assert_eq!(resp.status, StatusCode::SWITCHING_PROTOCOLS);
    }

    #[test]
    fn cswsh_403_body_does_not_echo_origin() {
        // The 403 response must not echo the rejected Origin back to the
        // requester — that would leak the attacker's URL into logs and
        // make the response a per-request oracle.
        let req = ws_request()
            .with_header("host", "api.example.com")
            .with_header("origin", "https://leak-me.example");
        let upgrade = WebSocketUpgrade::from_request(req).unwrap();
        let resp = upgrade.into_response();
        assert_eq!(resp.status, StatusCode::FORBIDDEN);
        assert!(
            !resp.body.iter().any(|b| {
                std::str::from_utf8(&[*b])
                    .map(|s| s.contains("leak-me"))
                    .unwrap_or(false)
            }),
            "403 body must not contain the rejected origin"
        );
        // Stronger check: the body is a fixed string we control.
        let body_text = std::str::from_utf8(&resp.body).unwrap_or("");
        assert!(
            !body_text.contains("leak-me"),
            "403 body must not echo origin: {body_text}"
        );
    }

    #[test]
    fn valid_upgrade_request_accepts_mixed_case_header_names() {
        let req = Request::new("GET", "/ws")
            .with_header("UpGrAdE", "websocket")
            .with_header("cOnNeCtIoN", "Upgrade")
            .with_header("SeC-WebSocket-Version", "13")
            .with_header("sEc-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");

        let upgrade = WebSocketUpgrade::from_request(req).unwrap();
        assert_eq!(upgrade.accept_key(), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn rejects_non_get_method() {
        let req = Request::new("POST", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("GET"));
    }

    #[test]
    fn rejects_missing_upgrade_header() {
        let req = Request::new("GET", "/ws")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("Upgrade"));
    }

    #[test]
    fn rejects_wrong_upgrade_value() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "h2c")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("websocket"));
    }

    #[test]
    fn rejects_missing_connection_header() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("Connection"));
    }

    #[test]
    fn rejects_connection_without_upgrade() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "keep-alive")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("Upgrade"));
    }

    #[test]
    fn rejects_connection_with_upgrade_only_as_substring() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "notupgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("Upgrade"));
    }

    #[test]
    fn rejects_missing_version() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("Version"));
    }

    #[test]
    fn rejects_unsupported_version() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "8")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("version"));
    }

    #[test]
    fn rejects_missing_key() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("Key"));
    }

    #[test]
    fn rejects_invalid_key() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "not-valid-base64!!!");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("Key"));
    }

    #[test]
    fn rejects_short_key() {
        // Valid base64 but only 8 bytes (need 16).
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "AAAAAAAAAAA=");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("Key"));
    }

    // ─── Case insensitivity ───────────────────────────────────────────

    #[test]
    fn accepts_case_insensitive_upgrade_header() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "WebSocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        assert!(WebSocketUpgrade::from_request(req).is_ok());
    }

    #[test]
    fn accepts_upgrade_header_with_additional_tokens() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "h2c, WebSocket")
            .with_header("connection", "keep-alive, Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        assert!(WebSocketUpgrade::from_request(req).is_ok());
    }

    #[test]
    fn accepts_connection_upgrade_mixed_case() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "keep-alive, Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        assert!(WebSocketUpgrade::from_request(req).is_ok());
    }

    // ─── Protocol negotiation ─────────────────────────────────────────

    #[test]
    fn protocol_negotiation_selects_first_match() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .with_header("sec-websocket-protocol", "chat, superchat");

        let upgrade = WebSocketUpgrade::from_request(req)
            .unwrap()
            .protocols(["superchat", "chat"]);

        // Client requested "chat" first, and we support both → "chat" wins.
        assert_eq!(upgrade.selected_protocol(), Some("chat"));
    }

    #[test]
    fn protocol_negotiation_no_match() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .with_header("sec-websocket-protocol", "mqtt");

        let upgrade = WebSocketUpgrade::from_request(req)
            .unwrap()
            .protocols(["chat"]);

        assert_eq!(upgrade.selected_protocol(), None);
    }

    #[test]
    fn no_protocol_requested() {
        let req = ws_request();
        let upgrade = WebSocketUpgrade::from_request(req).unwrap();
        assert!(upgrade.requested_protocols().is_empty());
        assert_eq!(upgrade.selected_protocol(), None);
    }

    // ─── Extension negotiation ────────────────────────────────────────

    #[test]
    fn extension_negotiation_filters_supported() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .with_header(
                "sec-websocket-extensions",
                "permessage-deflate; client_max_window_bits, x-unsupported",
            );

        let upgrade = WebSocketUpgrade::from_request(req)
            .unwrap()
            .extensions(["permessage-deflate"]);

        assert_eq!(upgrade.selected_extensions.len(), 1);
        assert!(upgrade.selected_extensions[0].contains("permessage-deflate"));
    }

    // ─── IntoResponse ─────────────────────────────────────────────────

    #[test]
    fn into_response_produces_101() {
        let req = ws_request();
        let resp = WebSocketUpgrade::from_request(req).unwrap().into_response();

        assert_eq!(resp.status, StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(resp.headers.get("upgrade").unwrap(), "websocket");
        assert_eq!(resp.headers.get("connection").unwrap(), "Upgrade");
        assert_eq!(
            resp.headers.get("sec-websocket-accept").unwrap(),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn into_response_includes_selected_protocol() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .with_header("sec-websocket-protocol", "graphql-ws, graphql-transport-ws");

        let resp = WebSocketUpgrade::from_request(req)
            .unwrap()
            .protocols(["graphql-transport-ws"])
            .into_response();

        assert_eq!(
            resp.headers.get("sec-websocket-protocol").unwrap(),
            "graphql-transport-ws"
        );
    }

    #[test]
    fn into_response_omits_protocol_when_none_selected() {
        let req = ws_request();
        let resp = WebSocketUpgrade::from_request(req).unwrap().into_response();

        assert!(!resp.headers.contains_key("sec-websocket-protocol"));
    }

    #[test]
    fn into_response_includes_selected_extensions() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .with_header("sec-websocket-extensions", "permessage-deflate");

        let resp = WebSocketUpgrade::from_request(req)
            .unwrap()
            .extensions(["permessage-deflate"])
            .into_response();

        assert!(
            resp.headers
                .get("sec-websocket-extensions")
                .unwrap()
                .contains("permessage-deflate")
        );
    }

    // ─── Rejection response ───────────────────────────────────────────

    #[test]
    fn extraction_error_produces_400() {
        use super::super::extract::ExtractionError;

        let err = ExtractionError::bad_request("test rejection");
        let resp = err.into_response();
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn non_ws_request_produces_400_via_extraction() {
        let req = Request::new("POST", "/ws");
        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        let resp = err.into_response();
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    }

    // ─── Acceptor builder ─────────────────────────────────────────────

    #[test]
    fn acceptor_built_with_negotiated_protocol() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .with_header("sec-websocket-protocol", "chat");

        let upgrade = WebSocketUpgrade::from_request(req)
            .unwrap()
            .protocols(["chat"]);

        let acceptor = upgrade.acceptor();
        let dbg = format!("{acceptor:?}");
        assert!(dbg.contains("WebSocketAcceptor"));
    }

    // ─── Message re-exports ───────────────────────────────────────────

    #[test]
    fn message_text_construction() {
        let msg = Message::text("hello");
        assert!(matches!(msg, Message::Text(_)));
    }

    #[test]
    fn message_binary_construction() {
        let msg = Message::binary(vec![1, 2, 3]);
        assert!(matches!(msg, Message::Binary(_)));
    }

    #[test]
    fn message_close_construction() {
        let msg = Message::Close(Some(CloseReason::normal()));
        assert!(matches!(msg, Message::Close(Some(_))));
    }

    #[test]
    fn message_ping_pong() {
        let heartbeat_ping = Message::Ping(Bytes::from_static(b"ping"));
        assert!(matches!(heartbeat_ping, Message::Ping(_)));

        let control_reply = Message::Pong(Bytes::from_static(b"pong"));
        assert!(matches!(control_reply, Message::Pong(_)));
    }

    // ─── Data type trait coverage ─────────────────────────────────────

    #[test]
    fn websocket_upgrade_debug_clone() {
        let req = ws_request();
        let upgrade = WebSocketUpgrade::from_request(req).unwrap();
        let dbg = format!("{upgrade:?}");
        assert!(dbg.contains("WebSocketUpgrade"));
        assert!(dbg.contains("accept_key"));
        assert_eq!(upgrade.accept_key(), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn extraction_error_debug_clone() {
        let err = ExtractionError::bad_request("test rejection");
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ExtractionError"));
        assert_eq!(err.message, "test rejection");
    }

    // ─── Accept key correctness ───────────────────────────────────────

    #[test]
    fn accept_key_rfc6455_vector() {
        // The canonical test vector from RFC 6455 Section 4.2.2.
        let req = Request::new("GET", "/chat")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        let upgrade = WebSocketUpgrade::from_request(req).unwrap();
        assert_eq!(upgrade.accept_key(), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn accept_key_different_keys_produce_different_accepts() {
        let key1 = ws_request();
        let key2 = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "AAAAAAAAAAAAAAAAAAAAAA==");

        let u1 = WebSocketUpgrade::from_request(key1).unwrap();
        let u2 = WebSocketUpgrade::from_request(key2).unwrap();
        assert_ne!(u1.accept_key(), u2.accept_key());
    }

    // ─── Full handler integration ─────────────────────────────────────

    #[test]
    fn handler_pattern_produces_correct_response() {
        // Simulate a handler that receives WebSocketUpgrade and returns Response.
        fn ws_handler(req: Request) -> Response {
            let upgrade = match WebSocketUpgrade::from_request(req) {
                Ok(u) => u,
                Err(rej) => return rej.into_response(),
            };
            upgrade.protocols(["chat"]).into_response()
        }

        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .with_header("sec-websocket-protocol", "chat, superchat");

        let resp = ws_handler(req);
        assert_eq!(resp.status, StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(resp.headers.get("upgrade").unwrap(), "websocket");
        assert_eq!(resp.headers.get("connection").unwrap(), "Upgrade");
        assert_eq!(
            resp.headers.get("sec-websocket-accept").unwrap(),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        assert_eq!(resp.headers.get("sec-websocket-protocol").unwrap(), "chat");
    }

    #[test]
    fn handler_pattern_rejects_non_ws_request() {
        fn ws_handler(req: Request) -> Response {
            let upgrade = match WebSocketUpgrade::from_request(req) {
                Ok(u) => u,
                Err(rej) => return rej.into_response(),
            };
            upgrade.into_response()
        }

        // Normal HTTP request (not a WebSocket upgrade).
        let req = Request::new("GET", "/ws");
        let resp = ws_handler(req);
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    }

    // ─── ServerHandshake compatibility ────────────────────────────────

    #[test]
    fn upgrade_accept_key_matches_server_handshake() {
        // Verify our accept key matches what the net::websocket layer computes.
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let our_accept = compute_accept_key(key);

        let server = ServerHandshake::new();
        let http_req = crate::net::websocket::HttpRequest::parse(
            format!(
                "GET /ws HTTP/1.1\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Key: {key}\r\n\
                 Sec-WebSocket-Version: 13\r\n\
                 \r\n"
            )
            .as_bytes(),
        )
        .unwrap();

        let accept_response = server.accept(&http_req).unwrap();
        assert_eq!(our_accept, accept_response.accept_key);
    }
