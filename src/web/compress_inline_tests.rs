    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::web::handler::FnHandler;
    use crate::web::response::StatusCode;

    impl<H: Handler> CompressionMiddleware<H> {
        fn call(&self, req: Request) -> Response {
            futures_lite::future::block_on(Handler::call(self, &Cx::for_testing(), req))
        }
    }

    fn make_request_with_encoding(encoding: &str) -> Request {
        Request::new("GET", "/test").with_header("accept-encoding", encoding)
    }

    fn large_body_handler() -> Response {
        let body = "Hello, World! ".repeat(100);
        Response::new(StatusCode::OK, body.into_bytes())
            .header("content-type", "text/plain; charset=utf-8")
    }

    fn small_body_handler() -> &'static str {
        "tiny"
    }

    fn no_content_handler() -> Response {
        Response::empty(StatusCode::NO_CONTENT)
    }

    fn already_compressed_handler() -> Response {
        Response::new(StatusCode::OK, b"already-compressed".to_vec())
            .header("content-encoding", "gzip")
    }

    #[cfg(feature = "compression")]
    fn set_cookie_handler() -> Response {
        Response::new(StatusCode::OK, "Hello, World! ".repeat(100).into_bytes())
            .header("set-cookie", "session=secret; HttpOnly; Secure")
    }

    #[cfg(feature = "compression")]
    fn private_cache_control_handler() -> Response {
        Response::new(StatusCode::OK, "Hello, World! ".repeat(100).into_bytes())
            .header("cache-control", "private, max-age=0")
    }

    fn mixed_case_already_compressed_handler() -> Response {
        let mut resp = Response::new(StatusCode::OK, b"already-compressed".to_vec());
        resp.headers
            .insert("Content-Encoding".to_string(), "gzip".to_string());
        resp
    }

    fn handler_with_mixed_case_vary() -> Response {
        let body = "Hello, World! ".repeat(100);
        let mut resp = Response::new(StatusCode::OK, body.into_bytes());
        resp.headers
            .insert("Vary".to_string(), "origin".to_string());
        resp
    }

    #[cfg(feature = "compression")]
    fn vary_contains(resp: &Response, token: &str) -> bool {
        resp.headers
            .get("vary")
            .is_some_and(|vary| vary.split(',').any(|value| value.trim() == token))
    }

    #[cfg(feature = "compression")]
    fn etag_handler() -> Response {
        Response::new(StatusCode::OK, "Hello, World! ".repeat(100).into_bytes())
            .header("etag", "\"v1\"")
    }

    fn not_modified_handler() -> Response {
        Response::empty(StatusCode::NOT_MODIFIED)
    }

    fn empty_body_handler() -> Response {
        Response::new(StatusCode::OK, Vec::new())
    }

    // --- Validators and empty bodies (br-asupersync-a1q12q) ---

    /// A compressed body kept the strong ETag of the identity bytes, so a
    /// resumed download's If-Range matched and spliced identity bytes from a
    /// 206 onto the compressed prefix.
    #[cfg(feature = "compression")]
    #[test]
    fn a_compressed_body_carries_a_weak_etag() {
        let mw =
            CompressionMiddleware::new(FnHandler::new(etag_handler), CompressionPolicy::default());
        let resp = mw.call(make_request_with_encoding("gzip"));
        assert_eq!(
            resp.headers.get("content-encoding").map(String::as_str),
            Some("gzip")
        );
        assert_eq!(
            resp.headers.get("etag").map(String::as_str),
            Some("W/\"v1\"")
        );
        let identity = mw.call(make_request_with_encoding("identity"));
        assert_eq!(
            identity.headers.get("etag").map(String::as_str),
            Some("\"v1\""),
            "an identity response keeps its strong ETag"
        );
    }

    #[test]
    fn not_modified_varies_and_an_empty_body_is_not_encoded() {
        let mw = CompressionMiddleware::new(
            FnHandler::new(not_modified_handler),
            CompressionPolicy::default(),
        );
        let resp = mw.call(make_request_with_encoding("gzip"));
        assert!(
            resp.headers
                .get("vary")
                .is_some_and(|vary| vary.contains("accept-encoding")),
            "a 304 carries the Vary of the response it validates"
        );

        let mw = CompressionMiddleware::new(
            FnHandler::new(empty_body_handler),
            CompressionPolicy::default().with_min_body_size(0),
        );
        let resp = mw.call(make_request_with_encoding("gzip, identity;q=0"));
        assert_eq!(resp.status, StatusCode::OK);
        assert!(!resp.headers.contains_key("content-encoding"));
        assert!(resp.body.is_empty());
    }

    // --- Basic behavior ---

    #[test]
    fn skips_compression_for_small_body() {
        let policy = CompressionPolicy::default();
        let mw = CompressionMiddleware::new(FnHandler::new(small_body_handler), policy);
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::OK);
        assert!(!resp.headers.contains_key("content-encoding"));
    }

    #[test]
    fn small_body_rejects_when_identity_is_unacceptable() {
        let policy = CompressionPolicy::default();
        let mw = CompressionMiddleware::new(FnHandler::new(small_body_handler), policy);
        let req = make_request_with_encoding("identity;q=0, *;q=0");
        let resp = mw.call(req);

        assert_eq!(resp.status.as_u16(), 406);
        assert_eq!(resp.body.as_ref(), b"No acceptable response encoding");
    }

    #[test]
    fn skips_compression_for_no_content() {
        let policy = CompressionPolicy::default();
        let mw = CompressionMiddleware::new(FnHandler::new(no_content_handler), policy);
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::NO_CONTENT);
        assert!(!resp.headers.contains_key("content-encoding"));
    }

    #[cfg(feature = "compression")]
    #[test]
    fn skips_compression_for_partial_content() {
        // Content-Range and the strong ETag describe the uncompressed bytes.
        fn partial_handler() -> Response {
            Response::new(
                StatusCode::PARTIAL_CONTENT,
                "Hello, World! ".repeat(100).into_bytes(),
            )
            .header("content-range", "bytes 0-1399/9000")
        }
        let policy = CompressionPolicy::default();
        let mw = CompressionMiddleware::new(FnHandler::new(partial_handler), policy);
        let resp = mw.call(make_request_with_encoding("gzip"));
        assert_eq!(resp.status, StatusCode::PARTIAL_CONTENT);
        assert!(!resp.headers.contains_key("content-encoding"));
        assert_eq!(resp.body.len(), 1400);
    }

    #[test]
    fn skips_compression_when_already_compressed() {
        let policy = CompressionPolicy::default();
        let mw = CompressionMiddleware::new(FnHandler::new(already_compressed_handler), policy);
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);
        assert_eq!(
            resp.headers.get("content-encoding").unwrap(),
            "gzip",
            "original content-encoding preserved"
        );
    }

    #[test]
    fn skips_compression_when_no_accept_encoding() {
        let policy = CompressionPolicy::default();
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = Request::new("GET", "/test");
        let resp = mw.call(req);
        // With no Accept-Encoding header, the middleware preserves the
        // existing preference for identity when it is available.
        assert!(!resp.headers.contains_key("content-encoding"));
    }

    #[test]
    fn empty_accept_encoding_header_is_not_treated_as_absent() {
        let policy = CompressionPolicy {
            supported_encodings: vec![ContentEncoding::Gzip],
            ..CompressionPolicy::default().with_min_body_size(0)
        };
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("");
        let resp = mw.call(req);
        assert_eq!(resp.status.as_u16(), 406);
        assert_eq!(resp.body.as_ref(), b"No acceptable response encoding");
    }

    #[test]
    fn adds_vary_header() {
        let policy = CompressionPolicy::default();
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("identity");
        let resp = mw.call(req);
        assert_eq!(
            resp.headers.get("vary").unwrap(),
            "accept-encoding",
            "vary header should always be set for compressible responses"
        );
    }

    #[test]
    fn honors_mixed_case_accept_encoding_inserted_directly() {
        let policy = CompressionPolicy::default();
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let mut req = Request::new("GET", "/test");
        req.headers
            .insert("Accept-Encoding".to_string(), "identity".to_string());

        let resp = mw.call(req);

        assert_eq!(
            resp.headers.get("vary").unwrap(),
            "accept-encoding",
            "mixed-case direct header insert should still negotiate"
        );
    }

    #[test]
    fn skips_mixed_case_existing_content_encoding_and_canonicalizes_name() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(
            FnHandler::new(mixed_case_already_compressed_handler),
            policy,
        );
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);

        assert_eq!(
            resp.headers.get("content-encoding"),
            Some(&"gzip".to_string())
        );
        assert!(!resp.headers.contains_key("Content-Encoding"));
        assert!(!resp.headers.contains_key("vary"));
    }

    #[test]
    fn append_vary_token_canonicalizes_mixed_case_vary_header() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(handler_with_mixed_case_vary), policy);
        let req = make_request_with_encoding("identity");
        let resp = mw.call(req);

        assert_eq!(
            resp.headers.get("vary"),
            Some(&"origin, accept-encoding".to_string())
        );
        assert!(!resp.headers.contains_key("Vary"));
    }

    #[test]
    fn identity_encoding_no_compression() {
        let policy = CompressionPolicy::default();
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("identity");
        let resp = mw.call(req);
        assert!(!resp.headers.contains_key("content-encoding"));
    }

    #[cfg(feature = "compression")]
    #[test]
    fn credentialed_request_skips_compression_by_default() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("gzip").with_header("cookie", "session=secret");
        let resp = mw.call(req);

        assert_eq!(resp.status, StatusCode::OK);
        assert!(!resp.headers.contains_key("content-encoding"));
        assert!(vary_contains(&resp, "accept-encoding"));
        assert!(vary_contains(&resp, "cookie"));
    }

    #[cfg(feature = "compression")]
    #[test]
    fn xsrf_header_skips_compression_and_varies_on_xsrf() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("gzip").with_header("x-xsrf-token", "secret");
        let resp = mw.call(req);

        assert_eq!(resp.status, StatusCode::OK);
        assert!(!resp.headers.contains_key("content-encoding"));
        assert!(vary_contains(&resp, "x-xsrf-token"));
        assert!(!vary_contains(&resp, "x-csrf-token"));
    }

    #[cfg(feature = "compression")]
    #[test]
    fn sensitive_response_header_skips_compression_by_default() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(set_cookie_handler), policy);
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);

        assert_eq!(resp.status, StatusCode::OK);
        assert!(!resp.headers.contains_key("content-encoding"));
        assert_eq!(
            resp.set_cookies.first().map(String::as_str),
            Some("session=secret; HttpOnly; Secure")
        );
        assert!(vary_contains(&resp, "accept-encoding"));
    }

    #[cfg(feature = "compression")]
    #[test]
    fn sensitive_response_rejects_when_identity_disallowed() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("gzip, identity;q=0")
            .with_header("authorization", "Bearer secret");
        let resp = mw.call(req);

        assert_eq!(resp.status.as_u16(), 406);
        assert_eq!(resp.body.as_ref(), b"No acceptable response encoding");
    }

    #[cfg(feature = "compression")]
    #[test]
    fn private_cache_control_skips_compression_by_default() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(private_cache_control_handler), policy);
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);

        assert_eq!(resp.status, StatusCode::OK);
        assert!(!resp.headers.contains_key("content-encoding"));
        assert!(vary_contains(&resp, "accept-encoding"));
    }

    #[cfg(feature = "compression")]
    #[test]
    fn sensitive_compression_can_be_explicitly_enabled() {
        let policy = CompressionPolicy::default()
            .with_min_body_size(0)
            .allow_sensitive_response_compression();
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("gzip").with_header("cookie", "session=secret");
        let resp = mw.call(req);

        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("content-encoding"),
            Some(&"gzip".to_string())
        );
    }

    #[test]
    fn rejects_explicitly_unacceptable_encodings() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("gzip;q=0, deflate;q=0, identity;q=0, *;q=0");
        let resp = mw.call(req);
        assert_eq!(resp.status.as_u16(), 406);
        assert_eq!(resp.body.as_ref(), b"No acceptable response encoding");
    }

    #[cfg(not(feature = "compression"))]
    #[test]
    fn falls_back_to_identity_when_non_identity_codecs_are_unavailable() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);
        assert_eq!(resp.status, StatusCode::OK);
        assert!(!resp.headers.contains_key("content-encoding"));
        assert_eq!(
            resp.headers.get("vary"),
            Some(&"accept-encoding".to_string())
        );
    }

    // --- Feature-gated compression tests ---

    #[cfg(feature = "compression")]
    #[test]
    fn gzip_compresses_large_body() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);
        assert_eq!(resp.headers.get("content-encoding").unwrap(), "gzip");
        assert_eq!(resp.headers.get("vary").unwrap(), "accept-encoding");

        // Verify compressed body is smaller.
        let original_size = "Hello, World! ".repeat(100).len();
        assert!(
            resp.body.len() < original_size,
            "compressed body ({}) should be smaller than original ({})",
            resp.body.len(),
            original_size,
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn deflate_compresses_large_body() {
        let policy = CompressionPolicy {
            supported_encodings: vec![ContentEncoding::Deflate, ContentEncoding::Identity],
            ..CompressionPolicy::default().with_min_body_size(0)
        };
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("deflate");
        let resp = mw.call(req);
        assert_eq!(resp.headers.get("content-encoding").unwrap(), "deflate");
    }

    #[cfg(feature = "compression")]
    #[test]
    fn gzip_preferred_over_deflate() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("gzip, deflate");
        let resp = mw.call(req);
        assert_eq!(resp.headers.get("content-encoding").unwrap(), "gzip");
    }

    #[cfg(feature = "compression")]
    #[test]
    fn brotli_preferred_over_gzip_by_default() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("br, gzip");
        let resp = mw.call(req);
        assert_eq!(resp.headers.get("content-encoding").unwrap(), "br");
    }

    #[cfg(feature = "compression")]
    #[test]
    fn respects_client_quality_preference() {
        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("gzip;q=0.5, deflate;q=1.0");
        let resp = mw.call(req);
        assert_eq!(resp.headers.get("content-encoding").unwrap(), "deflate");
    }

    #[cfg(feature = "compression")]
    #[test]
    fn gzip_roundtrip_body_integrity() {
        use crate::http::compress::DecompressionLimit;
        use crate::http::compress::Decompressor;
        use crate::http::compress::GzipDecompressor;

        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);

        // Decompress and verify body integrity.
        let mut dec = GzipDecompressor::new(DecompressionLimit::default());
        let mut decompressed = Vec::new();
        dec.decompress(&resp.body, &mut decompressed).unwrap();
        let expected = "Hello, World! ".repeat(100);
        assert_eq!(
            String::from_utf8(decompressed).unwrap(),
            expected,
            "decompressed body should match original"
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn brotli_roundtrip_body_integrity() {
        use crate::http::compress::BrotliDecompressor;
        use crate::http::compress::Decompressor;

        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("br");
        let resp = mw.call(req);

        let mut dec = BrotliDecompressor::new(None);
        let mut decompressed = Vec::new();
        dec.decompress(&resp.body, &mut decompressed).unwrap();
        dec.finish(&mut decompressed).unwrap();
        let expected = "Hello, World! ".repeat(100);
        assert_eq!(
            String::from_utf8(decompressed).unwrap(),
            expected,
            "decompressed body should match original"
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn min_body_size_threshold() {
        let policy = CompressionPolicy::default().with_min_body_size(10_000);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);
        // "Hello, World! ".repeat(100) = 1400 bytes, below 10K threshold.
        assert!(!resp.headers.contains_key("content-encoding"));
    }

    #[test]
    fn gzip_only_policy() {
        let policy = CompressionPolicy::gzip_only();
        assert_eq!(policy.supported_encodings.len(), 2);
        assert_eq!(policy.supported_encodings[0], ContentEncoding::Gzip);
        assert_eq!(policy.supported_encodings[1], ContentEncoding::Identity);
    }

    #[test]
    fn compression_policy_default() {
        let policy = CompressionPolicy::default();
        assert_eq!(policy.min_body_size, 256);
        assert_eq!(policy.max_compressed_size, DEFAULT_MAX_COMPRESSED_SIZE);
        assert!(!policy.compress_sensitive_responses);
        assert_eq!(policy.supported_encodings.len(), 4);
        assert_eq!(policy.supported_encodings[0], ContentEncoding::Brotli);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn capped_compressed_output_falls_back_to_identity_when_allowed() {
        let policy = CompressionPolicy::default()
            .with_min_body_size(0)
            .with_max_compressed_size(1);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);

        assert_eq!(resp.status, StatusCode::OK);
        assert!(!resp.headers.contains_key("content-encoding"));
        assert_eq!(
            resp.headers.get("vary"),
            Some(&"accept-encoding".to_string())
        );
        assert_eq!(resp.body.as_ref(), "Hello, World! ".repeat(100).as_bytes());
    }

    #[cfg(feature = "compression")]
    #[test]
    fn capped_compressed_output_rejects_when_identity_disallowed() {
        let policy = CompressionPolicy::default()
            .with_min_body_size(0)
            .with_max_compressed_size(1);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy);
        let req = make_request_with_encoding("gzip, identity;q=0");
        let resp = mw.call(req);

        assert_eq!(resp.status.as_u16(), 406);
        assert_eq!(resp.body.as_ref(), b"No acceptable response encoding");
    }

    /// Regression: compression must not clobber a pre-existing Vary header
    /// set by the inner handler.
    #[cfg(feature = "compression")]
    #[test]
    fn compression_preserves_existing_vary_header() {
        fn handler_with_vary() -> Response {
            let body = "Hello, World! ".repeat(100);
            Response::new(StatusCode::OK, body.into_bytes())
                .header("content-type", "text/plain; charset=utf-8")
                .header("vary", "origin")
        }

        let policy = CompressionPolicy::default().with_min_body_size(0);
        let mw = CompressionMiddleware::new(FnHandler::new(handler_with_vary), policy);
        let req = make_request_with_encoding("gzip");
        let resp = mw.call(req);
        assert_eq!(resp.headers.get("content-encoding").unwrap(), "gzip");
        let vary = resp.headers.get("vary").unwrap();
        assert!(
            vary.contains("origin"),
            "existing Vary value must be preserved, got: {vary}"
        );
        assert!(
            vary.contains("accept-encoding"),
            "accept-encoding must be appended to Vary, got: {vary}"
        );
    }

    // --- zstd (br-asupersync-t1fblr.32) ---

    fn content_encoding(resp: &Response) -> Option<&str> {
        resp.headers.get("content-encoding").map(String::as_str)
    }

    /// With `with_zstd`, a client that accepts zstd gets it, ahead of the
    /// policy's encodings when the qualities tie, and the body decodes to the
    /// handler's bytes.
    #[cfg(feature = "zstd")]
    #[test]
    fn with_zstd_serves_zstd_to_a_client_that_accepts_it() {
        let plain = large_body_handler().body.to_vec();
        let mw = CompressionMiddleware::new(
            FnHandler::new(large_body_handler),
            CompressionPolicy::default(),
        )
        .with_zstd();
        for accept in [
            "zstd",
            "gzip, deflate, br, zstd",
            "zstd;q=0.9, br;q=0.8, identity;q=0.1",
        ] {
            let resp = mw.call(make_request_with_encoding(accept));
            assert_eq!(content_encoding(&resp), Some("zstd"), "{accept}");
            assert!(!resp.headers.contains_key("content-length"), "{accept}");
            let vary = resp.headers.get("vary").map(String::as_str);
            assert_eq!(vary, Some("accept-encoding"), "{accept}");
            let limits = asupersync_zstd::DecodeLimits::new(plain.len());
            let decoded = asupersync_zstd::decode_all(&resp.body, &limits).expect(accept);
            assert_eq!(decoded, plain, "{accept}");
        }
    }

    /// The client's qualities still decide; and a server that did not opt in,
    /// or a build without zstd, never sends it.
    #[test]
    fn zstd_is_sent_only_when_offered_and_preferred() {
        let opted_in = CompressionMiddleware::new(
            FnHandler::new(large_body_handler),
            CompressionPolicy::default(),
        );
        #[cfg(feature = "zstd")]
        let opted_in = opted_in.with_zstd();
        let preferred_br = opted_in.call(make_request_with_encoding("br;q=1, zstd;q=0.5"));
        let expected = cfg!(feature = "compression").then_some("br");
        assert_eq!(content_encoding(&preferred_br), expected);

        let not_offered = CompressionMiddleware::new(
            FnHandler::new(large_body_handler),
            CompressionPolicy::default(),
        );
        let resp = not_offered.call(make_request_with_encoding("zstd, identity;q=0.5"));
        assert_eq!(content_encoding(&resp), None);
        assert_eq!(resp.body, large_body_handler().body);
    }

    /// A zstd body that would pass `max_compressed_size` is not sent: the
    /// response goes out as identity, as for the other codings.
    #[cfg(feature = "zstd")]
    #[test]
    fn zstd_respects_the_compressed_size_limit() {
        let policy = CompressionPolicy::default().with_max_compressed_size(8);
        let mw = CompressionMiddleware::new(FnHandler::new(large_body_handler), policy).with_zstd();
        let resp = mw.call(make_request_with_encoding("zstd"));
        assert_eq!(content_encoding(&resp), None);
        assert_eq!(resp.body, large_body_handler().body);
    }
