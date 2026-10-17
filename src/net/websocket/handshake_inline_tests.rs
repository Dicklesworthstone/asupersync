    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::util::DetEntropy;

    #[test]
    fn test_compute_accept_key() {
        // RFC 6455 example
        let client_key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = compute_accept_key(client_key);
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn test_ws_url_parse() {
        // Basic ws://
        let url = WsUrl::parse("ws://example.com/chat").unwrap();
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 80);
        assert_eq!(url.path, "/chat");
        assert!(!url.tls);

        // wss:// with port
        let url = WsUrl::parse("wss://example.com:8443/ws").unwrap();
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 8443);
        assert_eq!(url.path, "/ws");
        assert!(url.tls);

        // No path
        let url = WsUrl::parse("ws://localhost:9000").unwrap();
        assert_eq!(url.host, "localhost");
        assert_eq!(url.port, 9000);
        assert_eq!(url.path, "/");

        // IPv6
        let url = WsUrl::parse("ws://[::1]:8080/test").unwrap();
        assert_eq!(url.host, "::1");
        assert_eq!(url.port, 8080);
        assert_eq!(url.path, "/test");
    }

    #[test]
    fn ws_url_parse_keeps_query_out_of_authority() {
        let url = WsUrl::parse("ws://example.com?token=abc").unwrap();

        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 80);
        assert_eq!(url.path, "/?token=abc");
        assert_eq!(url.host_header(), "example.com");

        let with_path = WsUrl::parse("wss://example.com:8443/chat?token=abc").unwrap();
        assert_eq!(with_path.host, "example.com");
        assert_eq!(with_path.port, 8443);
        assert_eq!(with_path.path, "/chat?token=abc");
        assert_eq!(with_path.host_header(), "example.com:8443");
    }

    #[test]
    fn ws_url_parse_rejects_raw_request_line_delimiters() {
        for url in [
            "ws://example.com/chat\r\nX-Injected: yes",
            "ws://example.com/chat\nX-Injected: yes",
            "ws://example.com/chat with space",
        ] {
            let err = WsUrl::parse(url).expect_err("raw request-line delimiter must be rejected");
            assert!(
                matches!(err, HandshakeError::InvalidUrl(_)),
                "unexpected error for {url:?}: {err:?}"
            );
        }

        let encoded = WsUrl::parse("ws://example.com/chat%0D%0AX-Injected:%20yes")
            .expect("percent-encoded delimiters are data, not raw request-line bytes");
        assert_eq!(encoded.path, "/chat%0D%0AX-Injected:%20yes");
    }

    #[test]
    fn ws_url_parse_rejects_fragment_and_userinfo_authorities() {
        for url in [
            "ws://user@example.com/chat",
            "ws://example.com/chat#fragment",
            "ws://example.com?token=abc#fragment",
            "ws://exam[ple.com/chat",
        ] {
            let err = WsUrl::parse(url).expect_err("ambiguous authority must be rejected");
            assert!(
                matches!(err, HandshakeError::InvalidUrl(_)),
                "unexpected error for {url:?}: {err:?}"
            );
        }
    }

    #[test]
    fn ws_url_parse_rejects_invalid_authority_bytes_and_ipv6_suffix() {
        for url in [
            "ws://example.com\r\nX-Injected: yes/chat",
            "ws://[::1]evil.test/chat",
        ] {
            let err = WsUrl::parse(url).expect_err("malformed authority must be rejected");
            assert!(
                matches!(err, HandshakeError::InvalidUrl(_)),
                "unexpected error for {url:?}: {err:?}"
            );
        }
    }

    #[test]
    fn test_ws_url_host_header() {
        let url = WsUrl::parse("ws://example.com/chat").unwrap();
        assert_eq!(url.host_header(), "example.com");

        let url = WsUrl::parse("ws://example.com:8080/chat").unwrap();
        assert_eq!(url.host_header(), "example.com:8080");

        let url = WsUrl::parse("wss://example.com/chat").unwrap();
        assert_eq!(url.host_header(), "example.com");

        let url = WsUrl::parse("wss://example.com:443/chat").unwrap();
        assert_eq!(url.host_header(), "example.com");
    }

    #[test]
    fn test_client_handshake_request() {
        let entropy = DetEntropy::new(7);
        let handshake = ClientHandshake::new("ws://example.com/chat", &entropy)
            .unwrap()
            .protocol("chat");

        let request = handshake.request_bytes();
        let text = String::from_utf8(request).unwrap();

        assert!(text.starts_with("GET /chat HTTP/1.1\r\n"));
        assert!(text.contains("Host: example.com\r\n"));
        assert!(text.contains("Upgrade: websocket\r\n"));
        assert!(text.contains("Connection: Upgrade\r\n"));
        assert!(text.contains("Sec-WebSocket-Key: "));
        assert!(text.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(text.contains("Sec-WebSocket-Protocol: chat\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn client_handshake_request_preserves_query_only_target() {
        let entropy = DetEntropy::new(9);
        let handshake = ClientHandshake::new("ws://example.com?token=abc", &entropy).unwrap();

        let request = handshake.request_bytes();
        let text = String::from_utf8(request).unwrap();

        assert!(text.starts_with("GET /?token=abc HTTP/1.1\r\n"));
        assert!(text.contains("Host: example.com\r\n"));
        assert!(!text.contains("Host: example.com?token=abc\r\n"));
    }

    #[test]
    fn test_client_validate_response() {
        let handshake = ClientHandshake {
            url: WsUrl::parse("ws://example.com/chat").unwrap(),
            key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            protocols: vec![],
            extensions: vec![],
            headers: BTreeMap::new(),
        };

        let response = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
              \r\n",
        )
        .unwrap();

        assert!(handshake.validate_response(&response).is_ok());
    }

    #[test]
    fn test_client_validate_response_rejects_connection_substring_false_positive() {
        let handshake = ClientHandshake {
            url: WsUrl::parse("ws://example.com/chat").unwrap(),
            key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            protocols: vec![],
            extensions: vec![],
            headers: BTreeMap::new(),
        };

        let response = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: notupgrade\r\n\
              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
              \r\n",
        )
        .unwrap();

        let err = handshake.validate_response(&response).unwrap_err();
        assert!(matches!(err, HandshakeError::InvalidRequest(_)));
    }

    #[test]
    fn test_client_validate_response_allows_upgrade_header_token_list() {
        let handshake = ClientHandshake {
            url: WsUrl::parse("ws://example.com/chat").unwrap(),
            key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            protocols: vec![],
            extensions: vec![],
            headers: BTreeMap::new(),
        };

        let response = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: h2c, websocket\r\n\
              Connection: keep-alive, Upgrade\r\n\
              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
              \r\n",
        )
        .unwrap();

        assert!(handshake.validate_response(&response).is_ok());
    }

    #[test]
    fn test_client_validate_response_bad_accept() {
        let handshake = ClientHandshake {
            url: WsUrl::parse("ws://example.com/chat").unwrap(),
            key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            protocols: vec![],
            extensions: vec![],
            headers: BTreeMap::new(),
        };

        let response = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: wrong-accept-key\r\n\
              \r\n",
        )
        .unwrap();

        let err = handshake.validate_response(&response).unwrap_err();
        assert!(matches!(err, HandshakeError::InvalidAccept { .. }));
    }

    #[test]
    fn test_client_validate_response_unsolicited_protocol_rejected() {
        let handshake = ClientHandshake {
            url: WsUrl::parse("ws://example.com/chat").expect("valid url"),
            key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            protocols: vec![],
            extensions: vec![],
            headers: BTreeMap::new(),
        };

        let response = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
              Sec-WebSocket-Protocol: chat\r\n\
              \r\n",
        )
        .expect("response must parse");

        let err = handshake
            .validate_response(&response)
            .expect_err("unsolicited protocol must be rejected");
        assert!(matches!(err, HandshakeError::ProtocolMismatch { .. }));
    }

    #[test]
    fn test_client_validate_response_unrequested_protocol_rejected() {
        let handshake = ClientHandshake {
            url: WsUrl::parse("ws://example.com/chat").expect("valid url"),
            key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            protocols: vec!["chat".to_string()],
            extensions: vec![],
            headers: BTreeMap::new(),
        };

        let response = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
              Sec-WebSocket-Protocol: superchat\r\n\
              \r\n",
        )
        .expect("response must parse");

        let err = handshake
            .validate_response(&response)
            .expect_err("protocol not in request must be rejected");
        assert!(matches!(err, HandshakeError::ProtocolMismatch { .. }));
    }

    #[test]
    fn test_client_validate_response_requested_protocol_accepted() {
        let handshake = ClientHandshake {
            url: WsUrl::parse("ws://example.com/chat").expect("valid url"),
            key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            protocols: vec!["chat".to_string(), "superchat".to_string()],
            extensions: vec![],
            headers: BTreeMap::new(),
        };

        let response = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
              Sec-WebSocket-Protocol: superchat\r\n\
              \r\n",
        )
        .expect("response must parse");

        assert!(handshake.validate_response(&response).is_ok());
    }

    #[test]
    fn test_server_accept() {
        let server = ServerHandshake::new().protocol("chat");

        let request = HttpRequest::parse(
            b"GET /chat HTTP/1.1\r\n\
              Host: example.com\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\
              Sec-WebSocket-Protocol: chat\r\n\
              \r\n",
        )
        .unwrap();

        let accept = server.accept(&request).unwrap();
        assert_eq!(accept.accept_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert_eq!(accept.protocol, Some("chat".to_string()));
    }

    #[test]
    fn test_server_accept_allows_upgrade_header_token_list() {
        let server = ServerHandshake::new();

        let request = HttpRequest::parse(
            b"GET /chat HTTP/1.1\r\n\
              Host: example.com\r\n\
              Upgrade: h2c, websocket\r\n\
              Connection: keep-alive, Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\
              \r\n",
        )
        .unwrap();

        let accept = server.accept(&request).unwrap();
        assert_eq!(accept.accept_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn test_server_accept_rejects_connection_substring_false_positive() {
        let server = ServerHandshake::new();

        let request = HttpRequest::parse(
            b"GET /chat HTTP/1.1\r\n\
              Host: example.com\r\n\
              Upgrade: websocket\r\n\
              Connection: notupgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\
              \r\n",
        )
        .unwrap();

        let err = server.accept(&request).unwrap_err();
        assert!(matches!(err, HandshakeError::InvalidRequest(_)));
    }

    #[test]
    fn test_server_accept_negotiates_extensions() {
        let server = ServerHandshake::new()
            .extension("permessage-deflate")
            .extension("x-webkit-deflate-frame");

        let request = HttpRequest::parse(
            b"GET /chat HTTP/1.1\r\n\
              Host: example.com\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\
              Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits, x-ignored\r\n\
              \r\n",
        )
        .unwrap();

        let accept = server.accept(&request).unwrap();
        assert_eq!(
            accept.extensions,
            vec!["permessage-deflate; client_max_window_bits".to_string()]
        );
    }

    #[test]
    fn test_server_reject_bad_version() {
        let server = ServerHandshake::new();

        let request = HttpRequest::parse(
            b"GET /chat HTTP/1.1\r\n\
              Host: example.com\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 8\r\n\
              \r\n",
        )
        .unwrap();

        let err = server.accept(&request).unwrap_err();
        assert!(matches!(err, HandshakeError::UnsupportedVersion(_)));
    }

    #[test]
    fn test_accept_response_bytes() {
        let accept = AcceptResponse {
            accept_key: "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".to_string(),
            protocol: Some("chat".to_string()),
            extensions: vec![],
        };

        let response = accept.response_bytes();
        let text = String::from_utf8(response).unwrap();

        assert!(text.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(text.contains("Upgrade: websocket\r\n"));
        assert!(text.contains("Connection: Upgrade\r\n"));
        assert!(text.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
        assert!(text.contains("Sec-WebSocket-Protocol: chat\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_accept_response_snapshot_negotiated_protocol_and_extension() {
        let server = ServerHandshake::new()
            .protocol("superchat")
            .extension("permessage-deflate");

        let request = HttpRequest::parse(
            b"GET /chat HTTP/1.1\r\n\
              Host: example.com\r\n\
              Upgrade: websocket\r\n\
              Connection: keep-alive, Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\
              Sec-WebSocket-Protocol: chat, superchat\r\n\
              Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits, x-ignored\r\n\
              \r\n",
        )
        .unwrap();

        let accept = server.accept(&request).unwrap();
        let response = String::from_utf8(accept.response_bytes()).unwrap();

        insta::assert_snapshot!(
            "accept_response_negotiated_protocol_and_extension",
            response
        );
    }

    #[test]
    fn test_client_validate_response_rejects_unsolicited_extensions() {
        let handshake = ClientHandshake {
            url: WsUrl::parse("ws://example.com/chat").expect("valid url"),
            key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            protocols: vec![],
            extensions: vec!["permessage-deflate".to_string()],
            headers: BTreeMap::new(),
        };

        let response = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
              Sec-WebSocket-Extensions: x-unrequested\r\n\
              \r\n",
        )
        .expect("response must parse");

        let err = handshake
            .validate_response(&response)
            .expect_err("unrequested extension must be rejected");
        assert!(matches!(err, HandshakeError::ExtensionMismatch { .. }));
    }

    #[test]
    fn test_client_validate_response_accepts_requested_extensions() {
        let handshake = ClientHandshake {
            url: WsUrl::parse("ws://example.com/chat").expect("valid url"),
            key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            protocols: vec![],
            extensions: vec!["permessage-deflate".to_string()],
            headers: BTreeMap::new(),
        };

        let response = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
              Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\
              \r\n",
        )
        .expect("response must parse");

        assert!(handshake.validate_response(&response).is_ok());
    }

    #[test]
    fn test_http_request_parse() {
        let request = HttpRequest::parse(
            b"GET /chat HTTP/1.1\r\n\
              Host: example.com\r\n\
              Upgrade: WebSocket\r\n\
              Connection: Upgrade\r\n\
              \r\n",
        )
        .unwrap();

        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/chat");
        assert_eq!(request.header("host"), Some("example.com"));
        assert_eq!(request.header("upgrade"), Some("WebSocket"));
        assert_eq!(request.header("connection"), Some("Upgrade"));
    }

    #[test]
    fn test_http_request_parse_rejects_incomplete_headers() {
        let err = HttpRequest::parse(
            b"GET /chat HTTP/1.1\r\n\
              Host: example.com\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n",
        )
        .expect_err("missing blank line must be treated as an incomplete request");

        assert!(matches!(err, HandshakeError::InvalidRequest(_)));
    }

    #[test]
    fn http_request_parse_rejects_duplicate_handshake_header_names() {
        let err = HttpRequest::parse(
            b"GET /chat HTTP/1.1\r\n\
              Host: example.com\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Key: not-the-key\r\n\
              sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\
              \r\n",
        )
        .expect_err("duplicate singleton handshake headers must be rejected");

        assert!(
            matches!(err, HandshakeError::InvalidRequest(ref msg) if msg.contains("duplicate HTTP header: sec-websocket-key")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn http_request_parse_rejects_whitespace_before_header_colon() {
        let cases = [
            (
                "space before Upgrade colon",
                concat!(
                    "GET /chat HTTP/1.1\r\n",
                    "Host: example.com\r\n",
                    "Upgrade : websocket\r\n",
                    "Connection: Upgrade\r\n",
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
                    "Sec-WebSocket-Version: 13\r\n",
                    "\r\n",
                ),
            ),
            (
                "tab before Connection colon",
                concat!(
                    "GET /chat HTTP/1.1\r\n",
                    "Host: example.com\r\n",
                    "Upgrade: websocket\r\n",
                    "Connection\t: Upgrade\r\n",
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
                    "Sec-WebSocket-Version: 13\r\n",
                    "\r\n",
                ),
            ),
            (
                "space before Sec-WebSocket-Key colon",
                concat!(
                    "GET /chat HTTP/1.1\r\n",
                    "Host: example.com\r\n",
                    "Upgrade: websocket\r\n",
                    "Connection: Upgrade\r\n",
                    "Sec-WebSocket-Key : dGhlIHNhbXBsZSBub25jZQ==\r\n",
                    "Sec-WebSocket-Version: 13\r\n",
                    "\r\n",
                ),
            ),
            (
                "tab before Sec-WebSocket-Version colon",
                concat!(
                    "GET /chat HTTP/1.1\r\n",
                    "Host: example.com\r\n",
                    "Upgrade: websocket\r\n",
                    "Connection: Upgrade\r\n",
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
                    "Sec-WebSocket-Version\t: 13\r\n",
                    "\r\n",
                ),
            ),
        ];

        for (case, request) in cases {
            let err = HttpRequest::parse(request.as_bytes()).expect_err(case);
            assert!(
                matches!(err, HandshakeError::InvalidRequest(ref msg) if msg == "invalid HTTP header name"),
                "{case}: unexpected error: {err:?}"
            );
        }
    }

    #[test]
    fn server_accepts_no_whitespace_or_post_colon_ows() {
        let request = HttpRequest::parse(
            b"GET /chat HTTP/1.1\r\n\
              Host:example.com\r\n\
              Upgrade:websocket\r\n\
              Connection:\tUpgrade\r\n\
              Sec-WebSocket-Key:\tdGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\
              \r\n",
        )
        .expect("valid zero/post-colon OWS request must parse");

        let accept = ServerHandshake::new()
            .accept(&request)
            .expect("valid zero/post-colon OWS request must upgrade");
        assert_eq!(accept.accept_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn test_http_response_parse() {
        let response = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: xyz\r\n\
              \r\n",
        )
        .unwrap();

        assert_eq!(response.status, 101);
        assert_eq!(response.reason, "Switching Protocols");
        assert_eq!(response.header("upgrade"), Some("websocket"));
        assert_eq!(response.header("sec-websocket-accept"), Some("xyz"));
    }

    #[test]
    fn test_http_response_parse_rejects_incomplete_headers() {
        let err = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: xyz\r\n",
        )
        .expect_err("missing blank line must be treated as an incomplete response");

        assert!(matches!(err, HandshakeError::InvalidRequest(_)));
    }

    #[test]
    fn http_response_parse_rejects_duplicate_handshake_header_names() {
        let err = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: wrong-accept-key\r\n\
              sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
              \r\n",
        )
        .expect_err("duplicate singleton handshake response headers must be rejected");

        assert!(
            matches!(err, HandshakeError::InvalidRequest(ref msg) if msg.contains("duplicate HTTP header: sec-websocket-accept")),
            "unexpected error: {err:?}"
        );
    }

    // A load balancer's 101 often carries two Set-Cookie lines (stickiness
    // plus session). Every repeated header used to be refused, so the client's
    // connect failed with "duplicate HTTP header: set-cookie".
    #[test]
    fn client_accepts_a_101_with_repeated_ordinary_headers() {
        let handshake = ClientHandshake {
            url: WsUrl::parse("ws://example.com/chat").unwrap(),
            key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            protocols: vec![],
            extensions: vec![],
            headers: BTreeMap::new(),
        };

        let response = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Set-Cookie: lb=a1; Path=/\r\n\
              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
              Set-Cookie: session=b2; Path=/\r\n\
              \r\n",
        )
        .expect("repeated Set-Cookie lines are valid HTTP");

        assert_eq!(
            response.header("set-cookie"),
            Some("lb=a1; Path=/, session=b2; Path=/")
        );
        assert!(handshake.validate_response(&response).is_ok());
    }

    // RFC 6455 section 11.3.4 lets Sec-WebSocket-Protocol span several lines,
    // and proxies repeat X-Forwarded-For.
    #[test]
    fn server_accepts_repeated_protocol_and_proxy_headers() {
        let server = ServerHandshake::new().protocol("superchat");

        let request = HttpRequest::parse(
            b"GET /chat HTTP/1.1\r\n\
              Host: example.com\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              X-Forwarded-For: 192.0.2.1\r\n\
              X-Forwarded-For: 198.51.100.7\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\
              Sec-WebSocket-Protocol: chat\r\n\
              Sec-WebSocket-Protocol: superchat\r\n\
              \r\n",
        )
        .expect("repeated list headers are valid HTTP");

        assert_eq!(
            request.header("x-forwarded-for"),
            Some("192.0.2.1, 198.51.100.7")
        );
        let accept = server.accept(&request).unwrap();
        assert_eq!(accept.accept_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert_eq!(accept.protocol, Some("superchat".to_string()));
    }

    #[test]
    fn handshake_parse_still_rejects_repeated_host_and_version() {
        for (name, request) in [
            (
                "host",
                &b"GET /chat HTTP/1.1\r\n\
                   Host: example.com\r\n\
                   Host: attacker.example\r\n\
                   Upgrade: websocket\r\n\
                   Connection: Upgrade\r\n\
                   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                   Sec-WebSocket-Version: 13\r\n\
                   \r\n"[..],
            ),
            (
                "sec-websocket-version",
                &b"GET /chat HTTP/1.1\r\n\
                   Host: example.com\r\n\
                   Upgrade: websocket\r\n\
                   Connection: Upgrade\r\n\
                   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                   Sec-WebSocket-Version: 13\r\n\
                   Sec-WebSocket-Version: 8\r\n\
                   \r\n"[..],
            ),
        ] {
            let err = HttpRequest::parse(request).expect_err("singleton header repeated");
            assert!(
                matches!(err, HandshakeError::InvalidRequest(ref msg) if msg == &format!("duplicate HTTP header: {name}")),
                "unexpected error for {name}: {err:?}"
            );
        }
    }

    #[test]
    fn http_response_parse_rejects_whitespace_before_header_colon() {
        let cases = [
            (
                "space before Upgrade colon",
                concat!(
                    "HTTP/1.1 101 Switching Protocols\r\n",
                    "Upgrade : websocket\r\n",
                    "Connection: Upgrade\r\n",
                    "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
                    "\r\n",
                ),
            ),
            (
                "tab before Connection colon",
                concat!(
                    "HTTP/1.1 101 Switching Protocols\r\n",
                    "Upgrade: websocket\r\n",
                    "Connection\t: Upgrade\r\n",
                    "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
                    "\r\n",
                ),
            ),
            (
                "space before Sec-WebSocket-Accept colon",
                concat!(
                    "HTTP/1.1 101 Switching Protocols\r\n",
                    "Upgrade: websocket\r\n",
                    "Connection: Upgrade\r\n",
                    "Sec-WebSocket-Accept : s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
                    "\r\n",
                ),
            ),
        ];

        for (case, response) in cases {
            let err = HttpResponse::parse(response.as_bytes()).expect_err(case);
            assert!(
                matches!(err, HandshakeError::InvalidRequest(ref msg) if msg == "invalid HTTP header name"),
                "{case}: unexpected error: {err:?}"
            );
        }
    }

    #[test]
    fn http_response_parse_accepts_no_whitespace_or_post_colon_ows() {
        let response = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade:websocket\r\n\
              Connection:\tUpgrade\r\n\
              Sec-WebSocket-Accept:\ts3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
              \r\n",
        )
        .expect("valid zero/post-colon OWS response must parse");

        assert_eq!(response.header("upgrade"), Some("websocket"));
        assert_eq!(response.header("connection"), Some("Upgrade"));
        assert_eq!(
            response.header("sec-websocket-accept"),
            Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        );
    }

    #[test]
    fn test_split_http_header_block_prefers_earliest_complete_terminator() {
        let data = b"GET /chat HTTP/1.1\n\
Host: example.com\n\
Upgrade: websocket\n\
Connection: Upgrade\n\
\n\
body-prefix\r\n\r\nstill-body";

        let (header, trailing) = split_http_header_block(data).unwrap();

        assert_eq!(
            header,
            b"GET /chat HTTP/1.1\n\
Host: example.com\n\
Upgrade: websocket\n\
Connection: Upgrade\n\
\n"
        );
        assert_eq!(trailing, b"body-prefix\r\n\r\nstill-body");
    }

    #[test]
    fn test_generate_client_key() {
        let entropy = DetEntropy::new(42);
        let key = generate_client_key(&entropy);
        // Should be valid base64 of 16 bytes = 24 chars with padding
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&key)
            .unwrap();
        assert_eq!(decoded.len(), 16);
    }

    #[test]
    fn ws_url_debug_clone_eq() {
        let u = WsUrl {
            host: "example.com".into(),
            port: 80,
            path: "/chat".into(),
            tls: false,
        };
        let dbg = format!("{u:?}");
        assert!(dbg.contains("WsUrl"));
        assert!(dbg.contains("example.com"));

        let u2 = u.clone();
        assert_eq!(u, u2);

        let u3 = WsUrl {
            host: "other.com".into(),
            port: 443,
            path: "/".into(),
            tls: true,
        };
        assert_ne!(u, u3);
    }

    #[test]
    fn server_handshake_debug_clone_default() {
        let s = ServerHandshake::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("ServerHandshake"));

        let s2 = s;
        let dbg2 = format!("{s2:?}");
        assert_eq!(dbg, dbg2);
    }

    #[test]
    fn http_request_debug_clone() {
        let r = HttpRequest::parse(b"GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("HttpRequest"));

        let r2 = r;
        assert_eq!(r2.method, "GET");
        assert_eq!(r2.path, "/test");
    }

    #[test]
    fn server_accept_strips_crlf_from_extension_offers() {
        // Regression: unsanitized extension offers could inject \r\n into
        // the HTTP response, enabling response splitting.
        let raw_request = "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n";
        let mut request = HttpRequest::parse(raw_request.as_bytes()).unwrap();
        // Inject a malicious extension header with embedded CRLF. In a real
        // scenario this could come from a misbehaving HTTP/1.1 parser or a
        // crafted client that smuggles newlines past line-folding rules.
        request.headers.insert(
            "sec-websocket-extensions".to_string(),
            "permessage-deflate; x\r\nX-Injected: evil".to_string(),
        );

        let server = ServerHandshake::new().extension("permessage-deflate");
        let accept = server.accept(&request).unwrap();
        let response = accept.response_bytes();
        let response_str = String::from_utf8_lossy(&response);
        // Count the number of lines — response splitting would add extra header lines.
        let line_count = response_str.lines().count();
        // Normal 101 response has: status + 3 headers + extensions + empty = 6 lines.
        assert!(
            line_count <= 7,
            "response splitting injected extra header lines: {response_str}"
        );
        // Verify the extension value has \r\n stripped (no standalone "X-Injected:" header).
        for line in response_str.lines() {
            if line.starts_with("Sec-WebSocket-Extensions:") {
                assert!(
                    !line.contains('\r') && !line.contains('\n'),
                    "extension header must not contain embedded CRLF: {line}"
                );
            }
        }
    }

    // =========================================================================
    // RFC 6455 Sec-WebSocket-Key Validation Golden Conformance Tests
    // =========================================================================

    /// Golden Test #1: 16-byte base64 key validation per RFC 6455 Section 4.1
    #[test]
    fn golden_16_byte_base64_key_validation() {
        // Test comprehensive validation of Sec-WebSocket-Key format requirements

        let server = ServerHandshake::new();

        // Valid 16-byte keys (should succeed)
        let valid_keys = vec![
            "dGhlIHNhbXBsZSBub25jZQ==", // RFC 6455 example
            "AQIDBAUGBwgJCgsMDQ4PEA==", // Sequential bytes 0x01-0x10
            "/////////////////////w==", // All 0xFF bytes (16 bytes)
            "AAAAAAAAAAAAAAAAAAAAAA==", // All zero bytes
            "MTIzNDU2Nzg5YWJjZGVmZw==", // "1234567890abcdefg" (16 bytes)
        ];

        for (i, key) in valid_keys.iter().enumerate() {
            let request_data = format!(
                "GET /test HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Key: {}\r\n\
                 Sec-WebSocket-Version: 13\r\n\r\n",
                key
            );

            let request = HttpRequest::parse(request_data.as_bytes())
                .unwrap_or_else(|_| panic!("Failed to parse request {}", i));

            let result = server.accept(&request);
            assert!(
                result.is_ok(),
                "Valid 16-byte key #{} should be accepted: '{}', error: {:?}",
                i,
                key,
                result.unwrap_err()
            );

            // Verify the decoded key is exactly 16 bytes
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(key)
                .expect("Key should decode properly");
            assert_eq!(
                decoded.len(),
                16,
                "Key #{} should decode to exactly 16 bytes: '{}'",
                i,
                key
            );
        }

        // Invalid keys (should fail with InvalidKey error)
        let invalid_keys = vec![
            ("", "empty key"),
            ("dGhlIHNhbXBsZSBub25jZQ", "missing padding"),
            ("dGhlIHNhbXBsZSBub25jZQ====", "too much padding"),
            ("dGhlIHNhbXBsZSBub25jZ===", "15 bytes (one short)"),
            ("dGhlIHNhbXBsZSBub25jZGQ=", "17 bytes (one too many)"),
            ("dGhlIHNhbXBsZSBub25jZGRk", "18 bytes"),
            ("MTIzNA==", "only 4 bytes"),
            ("!@#$%^&*()_+{}|:<>?", "invalid base64 characters"),
            ("dGhlIHNhbXBsZSBub25jZQ=", "invalid padding"),
            ("AAAAAAAAAAAAAAAAAAAAAAAAAAAA", "32 bytes"),
        ];

        for (key, description) in invalid_keys {
            let request_data = format!(
                "GET /test HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Key: {}\r\n\
                 Sec-WebSocket-Version: 13\r\n\r\n",
                key
            );

            let request = HttpRequest::parse(request_data.as_bytes())
                .unwrap_or_else(|_| panic!("Failed to parse request for {}", description));

            let result = server.accept(&request);
            assert!(
                result.is_err(),
                "Invalid key should be rejected: {} ({})",
                key,
                description
            );

            if let Err(error) = result {
                assert!(
                    matches!(error, HandshakeError::InvalidKey),
                    "Should fail with InvalidKey error for {}: got {:?}",
                    description,
                    error
                );
            }
        }
    }

    /// Golden Test #2: SHA-1 + fixed GUID concatenation per RFC 6455 Section 4.2.2
    #[test]
    fn golden_sha1_fixed_guid_concatenation() {
        // Test exact SHA-1 computation with RFC 6455 GUID per specification

        // RFC 6455 Section 4.2.2 test vector
        let client_key = "dGhlIHNhbXBsZSBub25jZQ==";
        let expected_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

        let actual_accept = compute_accept_key(client_key);
        assert_eq!(
            actual_accept, expected_accept,
            "RFC 6455 test vector must match exactly"
        );

        // Verify the computation step by step
        let concatenated = format!("{}{}", client_key, WS_GUID);
        assert_eq!(
            concatenated,
            "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        );

        let mut hasher = Sha1::new();
        hasher.update(concatenated.as_bytes());
        let hash = hasher.finalize();

        let manual_accept = base64::engine::general_purpose::STANDARD.encode(hash);
        assert_eq!(
            manual_accept, expected_accept,
            "Manual computation should match library computation"
        );

        // Test additional known vectors to ensure consistency.
        // Each expected value was produced by concatenating the key with the
        // RFC 6455 GUID, computing SHA-1, and base64-encoding the digest.
        let test_vectors = vec![
            ("AQIDBAUGBwgJCgsMDQ4PEA==", "C/0nmHhBztSRGR1CwL6Tf4ZjwpY="),
            ("AAAAAAAAAAAAAAAAAAAAAA==", "ICX+Yqv66kxgM0FcWaLWlFLwTAI="),
            ("/////////////////////w==", "XXpj4jYzLM2yUE0C7TIgMwTQh2g="),
        ];

        for (key, expected) in test_vectors {
            let computed = compute_accept_key(key);
            assert_eq!(
                computed, expected,
                "Accept key computation failed for test vector: key={}, expected={}, got={}",
                key, expected, computed
            );

            // Verify computation is deterministic (same result every time)
            let computed_again = compute_accept_key(key);
            assert_eq!(
                computed, computed_again,
                "Accept key computation should be deterministic"
            );
        }

        // Verify GUID constant is exactly per RFC 6455
        assert_eq!(WS_GUID, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

        // Test that changing GUID breaks the computation (negative test)
        let wrong_guid = "358EAFA5-E914-47DA-95CA-C5AB0DC85B11"; // Changed first digit
        let concatenated_wrong = format!("{}{}", client_key, wrong_guid);
        let mut hasher_wrong = Sha1::new();
        hasher_wrong.update(concatenated_wrong.as_bytes());
        let hash_wrong = hasher_wrong.finalize();
        let wrong_accept = base64::engine::general_purpose::STANDARD.encode(hash_wrong);

        assert_ne!(
            wrong_accept, expected_accept,
            "Wrong GUID should produce different result"
        );
    }

    /// Golden Test #3: Key reuse detection across multiple connections
    #[test]
    fn golden_key_reuse_detection() {
        // Test that the same key can be reused (RFC 6455 doesn't prohibit this)
        // but verify deterministic behavior for identical inputs

        let server = ServerHandshake::new().protocol("chat");
        let reused_key = "dGhlIHNhbXBsZSBub25jZQ==";

        // First connection with the key
        let request1_data = format!(
            "GET /test1 HTTP/1.1\r\n\
             Host: localhost\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Protocol: chat\r\n\r\n",
            reused_key
        );

        let request1 =
            HttpRequest::parse(request1_data.as_bytes()).expect("First request should parse");

        let accept1 = server
            .accept(&request1)
            .expect("First connection should be accepted");

        // Second connection with the same key (different path)
        let request2_data = format!(
            "GET /test2 HTTP/1.1\r\n\
             Host: localhost\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Protocol: chat\r\n\r\n",
            reused_key
        );

        let request2 =
            HttpRequest::parse(request2_data.as_bytes()).expect("Second request should parse");

        let accept2 = server
            .accept(&request2)
            .expect("Second connection should be accepted");

        // Verify both connections produce the same accept key (deterministic)
        assert_eq!(
            accept1.accept_key, accept2.accept_key,
            "Same client key should always produce same accept key"
        );

        // Verify the accept key matches RFC test vector
        assert_eq!(accept1.accept_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");

        // Test multiple rapid connections with same key (stress test)
        for i in 0..10 {
            let request_data = format!(
                "GET /test{} HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Key: {}\r\n\
                 Sec-WebSocket-Version: 13\r\n\r\n",
                i, reused_key
            );

            let request = HttpRequest::parse(request_data.as_bytes())
                .unwrap_or_else(|_| panic!("Request {} should parse", i));

            let accept = server
                .accept(&request)
                .unwrap_or_else(|_| panic!("Connection {} should be accepted", i));

            assert_eq!(
                accept.accept_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
                "Connection {} should have consistent accept key",
                i
            );
        }

        // Test that different keys produce different accept values
        let different_keys = vec![
            "AQIDBAUGBwgJCgsMDQ4PEA==",
            "AAAAAAAAAAAAAAAAAAAAAA==",
            "/////////////////////w==",
        ];

        let mut accept_keys = vec![accept1.accept_key.clone()];
        for (i, key) in different_keys.iter().enumerate() {
            let request_data = format!(
                "GET /unique{} HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Key: {}\r\n\
                 Sec-WebSocket-Version: 13\r\n\r\n",
                i, key
            );

            let request = HttpRequest::parse(request_data.as_bytes())
                .unwrap_or_else(|_| panic!("Request for key {} should parse", i));

            let accept = server
                .accept(&request)
                .unwrap_or_else(|_| panic!("Connection for key {} should be accepted", i));

            accept_keys.push(accept.accept_key.clone());
        }

        // Verify all accept keys are different
        for i in 0..accept_keys.len() {
            for j in (i + 1)..accept_keys.len() {
                assert_ne!(
                    accept_keys[i], accept_keys[j],
                    "Accept keys {} and {} should be different: '{}' vs '{}'",
                    i, j, accept_keys[i], accept_keys[j]
                );
            }
        }
    }

    /// Golden Test #4: Multiple Sec-WebSocket-Protocol negotiation per RFC 6455 Section 4.2.2
    #[test]
    fn golden_multiple_sec_websocket_protocol_negotiation() {
        // Test comprehensive protocol negotiation scenarios

        // Test case 1: Server supports multiple protocols, client requests multiple
        let server = ServerHandshake::new()
            .protocol("chat")
            .protocol("superchat")
            .protocol("echo");

        // Client requests multiple protocols in preference order
        let request_data = "GET /test HTTP/1.1\r\n\
            Host: localhost\r\n\
            Upgrade: websocket\r\n\
            Connection: Upgrade\r\n\
            Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
            Sec-WebSocket-Version: 13\r\n\
            Sec-WebSocket-Protocol: superchat, chat, echo\r\n\r\n";

        let request = HttpRequest::parse(request_data.as_bytes())
            .expect("Multiple protocol request should parse");

        let accept = server
            .accept(&request)
            .expect("Multiple protocol negotiation should succeed");

        // Server should select first matching protocol from client list
        assert_eq!(
            accept.protocol,
            Some("superchat".to_string()),
            "Should select first matching protocol from client preference order"
        );

        // Test case 2: Client requests protocols server doesn't support
        let server_limited = ServerHandshake::new().protocol("private-protocol");

        let request_data = "GET /test HTTP/1.1\r\n\
            Host: localhost\r\n\
            Upgrade: websocket\r\n\
            Connection: Upgrade\r\n\
            Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
            Sec-WebSocket-Version: 13\r\n\
            Sec-WebSocket-Protocol: chat, superchat, echo\r\n\r\n";

        let request = HttpRequest::parse(request_data.as_bytes())
            .expect("Unsupported protocol request should parse");

        let accept = server_limited
            .accept(&request)
            .expect("Should accept connection even when no protocols match");
        assert_eq!(
            accept.protocol, None,
            "Should omit Sec-WebSocket-Protocol when no protocol matches"
        );

        // Test case 3: Single protocol negotiation
        let server_single = ServerHandshake::new().protocol("websocket-chat");

        let request_data = "GET /test HTTP/1.1\r\n\
            Host: localhost\r\n\
            Upgrade: websocket\r\n\
            Connection: Upgrade\r\n\
            Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
            Sec-WebSocket-Version: 13\r\n\
            Sec-WebSocket-Protocol: websocket-chat\r\n\r\n";

        let request = HttpRequest::parse(request_data.as_bytes())
            .expect("Single protocol request should parse");

        let accept = server_single
            .accept(&request)
            .expect("Single protocol negotiation should succeed");

        assert_eq!(
            accept.protocol,
            Some("websocket-chat".to_string()),
            "Should accept exact protocol match"
        );

        // Test case 4: No protocol requested, server has protocols
        let request_data = "GET /test HTTP/1.1\r\n\
            Host: localhost\r\n\
            Upgrade: websocket\r\n\
            Connection: Upgrade\r\n\
            Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
            Sec-WebSocket-Version: 13\r\n\r\n";

        let request =
            HttpRequest::parse(request_data.as_bytes()).expect("No protocol request should parse");

        let accept = server
            .accept(&request)
            .expect("Should accept connection without protocol when client doesn't request any");

        assert_eq!(
            accept.protocol, None,
            "Should not select protocol when client doesn't request any"
        );

        // Test case 5: Protocol list parsing edge cases.
        // In each case the server (below) only supports "chat", so the
        // negotiated protocol must be "chat" whenever the client offers it.
        let protocol_test_cases = vec![
            ("chat", "chat"),
            ("chat, superchat", "chat"),         // First in list
            ("  chat  ,  superchat  ", "chat"),  // Whitespace handling
            ("superchat,chat,echo", "chat"),     // No spaces (server only supports "chat")
            ("unknown, chat, unknown2", "chat"), // Mixed known/unknown
        ];

        let server_chat = ServerHandshake::new().protocol("chat");

        for (protocol_header, expected) in protocol_test_cases {
            let request_data = format!(
                "GET /test HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                 Sec-WebSocket-Version: 13\r\n\
                 Sec-WebSocket-Protocol: {}\r\n\r\n",
                protocol_header
            );

            let request = HttpRequest::parse(request_data.as_bytes())
                .unwrap_or_else(|_| panic!("Protocol header '{}' should parse", protocol_header));

            let accept = server_chat.accept(&request).unwrap_or_else(|_| {
                panic!(
                    "Protocol negotiation should succeed for '{}'",
                    protocol_header
                )
            });

            assert_eq!(
                accept.protocol,
                Some(expected.to_string()),
                "Protocol header '{}' should select '{}'",
                protocol_header,
                expected
            );
        }

        // Test case 6: Case sensitivity (protocols are case-sensitive per RFC)
        let server_case = ServerHandshake::new().protocol("Chat");

        let request_data = "GET /test HTTP/1.1\r\n\
            Host: localhost\r\n\
            Upgrade: websocket\r\n\
            Connection: Upgrade\r\n\
            Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
            Sec-WebSocket-Version: 13\r\n\
            Sec-WebSocket-Protocol: chat\r\n\r\n"; // lowercase

        let request =
            HttpRequest::parse(request_data.as_bytes()).expect("Case test request should parse");

        let result = server_case.accept(&request);
        assert!(
            result.is_ok(),
            "Protocol matching should be case-sensitive and no match should omit protocol"
        );
        assert_eq!(
            result.unwrap().protocol,
            None,
            "Case-sensitive protocol mismatch should not select a protocol"
        );
    }

    /// Golden Test #5: RFC 6455 compliant status codes and error conditions
    #[test]
    fn golden_rfc6455_compliant_status_codes() {
        // Test comprehensive status code compliance per RFC 6455

        // Test case 1: Successful handshake returns 101 Switching Protocols
        let server = ServerHandshake::new();
        let valid_request_data = "GET /test HTTP/1.1\r\n\
            Host: localhost\r\n\
            Upgrade: websocket\r\n\
            Connection: Upgrade\r\n\
            Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
            Sec-WebSocket-Version: 13\r\n\r\n";

        let request =
            HttpRequest::parse(valid_request_data.as_bytes()).expect("Valid request should parse");

        let accept = server
            .accept(&request)
            .expect("Valid request should be accepted");

        let response_bytes = accept.response_bytes();
        let response_str = String::from_utf8_lossy(&response_bytes);

        // Verify 101 status code in response
        assert!(
            response_str.starts_with("HTTP/1.1 101 Switching Protocols"),
            "Successful handshake should return 101 Switching Protocols"
        );

        // Test case 2: Missing required headers trigger appropriate errors
        let missing_header_tests = vec![
            // (request_data, expected_error_type, description)
            (
                "GET /test HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\r\n",
                "MissingHeader",
                "Missing Connection header",
            ),
            (
                "GET /test HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n\r\n",
                "MissingHeader",
                "Missing Upgrade header",
            ),
            (
                "GET /test HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                "MissingHeader",
                "Missing Sec-WebSocket-Key header",
            ),
            (
                "GET /test HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
                "MissingHeader",
                "Missing Sec-WebSocket-Version header",
            ),
        ];

        for (request_data, expected_error, description) in missing_header_tests {
            let request = HttpRequest::parse(request_data.as_bytes())
                .unwrap_or_else(|_| panic!("Request should parse: {}", description));

            let result = server.accept(&request);
            assert!(result.is_err(), "Should reject request: {}", description);

            let error = result.unwrap_err();
            let error_str = format!("{:?}", error);
            assert!(
                error_str.contains(expected_error),
                "Should fail with {}: {} - got {:?}",
                expected_error,
                description,
                error
            );
        }

        // Test case 3: Invalid WebSocket version
        let invalid_version_data = "GET /test HTTP/1.1\r\n\
            Host: localhost\r\n\
            Upgrade: websocket\r\n\
            Connection: Upgrade\r\n\
            Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
            Sec-WebSocket-Version: 12\r\n\r\n"; // Wrong version

        let request = HttpRequest::parse(invalid_version_data.as_bytes())
            .expect("Invalid version request should parse");

        let result = server.accept(&request);
        assert!(result.is_err(), "Should reject invalid WebSocket version");

        if let Err(error) = result {
            assert!(
                matches!(error, HandshakeError::UnsupportedVersion(_)),
                "Should fail with UnsupportedVersion error: {:?}",
                error
            );
        }

        // Test case 4: Client validation of server response status codes
        let handshake = ClientHandshake {
            url: crate::net::websocket::handshake::WsUrl::parse("ws://example.com/test").unwrap(),
            key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            protocols: vec![],
            extensions: vec![],
            headers: std::collections::BTreeMap::new(),
        };

        // Test various invalid status codes
        let invalid_status_tests = vec![
            (200, "200 OK"),
            (400, "400 Bad Request"),
            (404, "404 Not Found"),
            (426, "426 Upgrade Required"),
            (500, "500 Internal Server Error"),
        ];

        for (status_code, status_text) in invalid_status_tests {
            let response_data = format!(
                "HTTP/1.1 {} {}\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                status_code, status_text
            );

            let response = HttpResponse::parse(response_data.as_bytes())
                .unwrap_or_else(|_| panic!("Response with status {} should parse", status_code));

            let result = handshake.validate_response(&response);
            assert!(
                result.is_err(),
                "Should reject response with status code {}",
                status_code
            );

            if let Err(error) = result {
                assert!(
                    matches!(error, HandshakeError::NotSwitchingProtocols(_)),
                    "Should fail with NotSwitchingProtocols for status {}: {:?}",
                    status_code,
                    error
                );
            }
        }

        // Test case 5: Verify complete successful response format.
        // Re-parse the valid request so we don't accidentally reuse the
        // unsupported-version request bound above.
        let valid_request_for_response =
            HttpRequest::parse(valid_request_data.as_bytes()).expect("Valid request should parse");
        let accept = server
            .accept(&valid_request_for_response)
            .expect("Valid request should be accepted");
        let response_bytes = accept.response_bytes();
        let response_str = String::from_utf8_lossy(&response_bytes);

        // Check all required response headers are present
        assert!(
            response_str.contains("Upgrade: websocket"),
            "Response should contain Upgrade header"
        );
        assert!(
            response_str.contains("Connection: Upgrade"),
            "Response should contain Connection header"
        );
        assert!(
            response_str.contains("Sec-WebSocket-Accept: "),
            "Response should contain Sec-WebSocket-Accept header"
        );

        // Verify response ends with CRLF CRLF
        assert!(
            response_str.ends_with("\r\n\r\n"),
            "Response should end with CRLF CRLF"
        );

        // Verify no extra headers are added by default
        let line_count = response_str.lines().count();
        assert!(
            line_count <= 6,
            "Response should not have extra headers: {}",
            response_str
        );

        // Test case 6: Malformed request handling
        let malformed_requests: Vec<&[u8]> = vec![
            b"NOT HTTP\r\n\r\n",
            b"GET /test\r\n\r\n",          // Missing HTTP version
            b"GET /test HTTP/1.0\r\n\r\n", // Wrong HTTP version should still work
            b"",
        ];

        for (i, malformed) in malformed_requests.iter().enumerate() {
            let result = HttpRequest::parse(malformed);
            if i < 3 {
                // Some malformed requests might still parse but should fail validation
                if let Ok(request) = result {
                    let server_result = server.accept(&request);
                    // Should either fail to parse or fail validation
                    assert!(
                        server_result.is_err(),
                        "Malformed request {} should be rejected",
                        i
                    );
                }
            } else {
                // Completely empty request should fail to parse
                assert!(result.is_err(), "Empty request should fail to parse");
            }
        }
    }

    /// Additional Golden Test: Comprehensive end-to-end handshake validation
    #[test]
    fn golden_end_to_end_handshake_validation() {
        // Test complete handshake flow with all components

        let entropy = crate::util::entropy::DetEntropy::new(12345);
        let client = ClientHandshake::new("ws://localhost:8080/socket", &entropy)
            .expect("Client handshake should initialize")
            .protocol("chat")
            .protocol("echo")
            .extension("permessage-deflate");

        let server = ServerHandshake::new()
            .protocol("echo")
            .protocol("chat") // Different order than client
            .extension("permessage-deflate");

        // Generate client request
        let request_bytes = client.request_bytes();
        let request_str = String::from_utf8_lossy(&request_bytes);

        // Verify client request format
        assert!(request_str.contains("GET /socket HTTP/1.1"));
        assert!(request_str.contains("Host: localhost:8080"));
        assert!(request_str.contains("Upgrade: websocket"));
        assert!(request_str.contains("Connection: Upgrade"));
        assert!(request_str.contains("Sec-WebSocket-Key: "));
        assert!(request_str.contains("Sec-WebSocket-Version: 13"));
        assert!(request_str.contains("Sec-WebSocket-Protocol: chat, echo"));

        // Parse and validate on server side
        let request =
            HttpRequest::parse(&request_bytes).expect("Client request should parse on server");

        let accept = server
            .accept(&request)
            .expect("Server should accept valid client request");

        // Verify protocol negotiation (server should pick first match from client list)
        assert_eq!(
            accept.protocol,
            Some("chat".to_string()),
            "Server should select first client protocol it supports"
        );

        // Generate server response
        let response_bytes = accept.response_bytes();
        let response_str = String::from_utf8_lossy(&response_bytes);

        // Verify server response format
        assert!(response_str.contains("HTTP/1.1 101 Switching Protocols"));
        assert!(response_str.contains(&format!("Sec-WebSocket-Accept: {}", accept.accept_key)));
        assert!(response_str.contains("Sec-WebSocket-Protocol: chat"));

        // Validate response on client side
        let response =
            HttpResponse::parse(&response_bytes).expect("Server response should parse on client");

        let validation_result = client.validate_response(&response);
        assert!(
            validation_result.is_ok(),
            "Client should validate server response: {:?}",
            validation_result.unwrap_err()
        );

        // Verify key computation is correct
        let expected_accept = compute_accept_key(&client.key);
        assert_eq!(
            accept.accept_key, expected_accept,
            "Server accept key should match computed value"
        );

        // Test extension negotiation
        if !accept.extensions.is_empty() {
            assert!(
                response_str.contains("Sec-WebSocket-Extensions:"),
                "Response should include extension header when extensions are negotiated"
            );
        }
    }
