    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn body_policy_enforced_snapshot_prevents_late_multipart_limit_loosen() {
        let strict_multipart = MultipartLimits::new()
            .max_total_size(1024)
            .max_part_body_size(2);
        let enforced = super::super::RequestBodyPolicy::new()
            .max_total_body_size(1024)
            .multipart_limits(strict_multipart)
            .resolved();
        let loose_multipart = MultipartLimits::new()
            .max_total_size(4096)
            .max_part_body_size(4096);
        let mut request = Request::new("POST", "/upload")
            .with_header("content-type", "multipart/form-data; boundary=X")
            .with_body(Bytes::from_static(
                b"--X\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nabc\r\n--X--\r\n",
            ));
        request
            .extensions
            .insert_typed(super::super::EnforcedRequestBodyPolicy { policy: enforced });
        request.extensions.insert_typed(
            super::super::RequestBodyPolicy::new()
                .max_total_body_size(4096)
                .multipart_limits(loose_multipart),
        );
        request.extensions.insert_typed(loose_multipart);

        let error = Multipart::from_request(request)
            .expect_err("late middleware must not loosen locked multipart field limit");
        assert_eq!(error.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    // ================================================================
    // Boundary extraction
    // ================================================================

    #[test]
    fn extract_boundary_basic() {
        let ct = "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW";
        assert_eq!(
            extract_boundary(ct).unwrap(),
            "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        );
    }

    #[test]
    fn extract_boundary_quoted() {
        let ct = r#"multipart/form-data; boundary="abc123""#;
        assert_eq!(extract_boundary(ct).unwrap(), "abc123");
    }

    #[test]
    fn extract_boundary_missing() {
        assert!(extract_boundary("multipart/form-data").is_none());
    }

    #[test]
    fn extract_boundary_empty() {
        assert!(extract_boundary("multipart/form-data; boundary=").is_none());
    }

    #[test]
    fn extract_boundary_with_extra_params() {
        let ct = "multipart/form-data; boundary=abc; charset=utf-8";
        assert_eq!(extract_boundary(ct).unwrap(), "abc");
    }

    #[test]
    fn extract_boundary_ignores_similar_parameter_names() {
        let ct = "multipart/form-data; xboundary=wrong; boundary=abc";
        assert_eq!(extract_boundary(ct).unwrap(), "abc");
    }

    #[test]
    fn extract_boundary_allows_whitespace_around_equals() {
        let ct = "multipart/form-data; boundary = abc123";
        assert_eq!(extract_boundary(ct).unwrap(), "abc123");
    }

    #[test]
    fn extract_boundary_unterminated_quote_rejected_even_with_later_fragment() {
        let ct = "multipart/form-data; boundary=\"unterminated; boundary=abc";
        assert_eq!(extract_boundary(ct), None);
    }

    #[test]
    fn extract_boundary_trailing_garbage_after_quote_rejected() {
        let ct = "multipart/form-data; boundary=\"abc\"junk";
        assert_eq!(extract_boundary(ct), None);
    }

    #[test]
    fn extract_boundary_at_70_char_rfc_max_accepted() {
        // br-asupersync-tamnew: RFC 2046 §5.1.1 caps boundary at 70 chars.
        // Exactly 70 chars must still be accepted.
        let boundary_70 = "a".repeat(70);
        let ct = format!("multipart/form-data; boundary={boundary_70}");
        assert_eq!(extract_boundary(&ct).unwrap(), boundary_70);
    }

    #[test]
    fn extract_boundary_above_70_char_rfc_max_rejected() {
        // br-asupersync-tamnew: 71-char boundary MUST be rejected to
        // prevent O(body * boundary) substring search amplification.
        let boundary_71 = "a".repeat(71);
        let ct = format!("multipart/form-data; boundary={boundary_71}");
        assert_eq!(extract_boundary(&ct), None);
    }

    #[test]
    fn extract_boundary_pathological_1mb_rejected() {
        // br-asupersync-tamnew: 1 MiB boundary MUST be rejected fast.
        let boundary_huge = "x".repeat(1_048_576);
        let ct = format!("multipart/form-data; boundary={boundary_huge}");
        assert_eq!(extract_boundary(&ct), None);
    }

    // ================================================================
    // Content-Disposition parameter parsing
    // ================================================================

    #[test]
    fn parse_disposition_name() {
        let d = r#"form-data; name="username""#;
        assert_eq!(parse_disposition_param(d, "name").unwrap(), "username");
    }

    #[test]
    fn parse_disposition_filename() {
        let d = r#"form-data; name="file"; filename="photo.jpg""#;
        assert_eq!(parse_disposition_param(d, "name").unwrap(), "file");
        assert_eq!(parse_disposition_param(d, "filename").unwrap(), "photo.jpg");
    }

    #[test]
    fn parse_disposition_escaped_quote() {
        let d = r#"form-data; name="field"; filename="file\"name.txt""#;
        assert_eq!(
            parse_disposition_param(d, "filename").unwrap(),
            r#"file"name.txt"#
        );
    }

    #[test]
    fn parse_disposition_unquoted() {
        let d = "form-data; name=username";
        assert_eq!(parse_disposition_param(d, "name").unwrap(), "username");
    }

    #[test]
    fn parse_disposition_name_not_confused_with_filename() {
        // Regression: "name=" must not match inside "filename="
        let d = r#"form-data; filename="photo.jpg"; name="field""#;
        assert_eq!(parse_disposition_param(d, "name").unwrap(), "field");
        assert_eq!(parse_disposition_param(d, "filename").unwrap(), "photo.jpg");
    }

    #[test]
    fn parse_disposition_missing() {
        let d = "form-data; name=\"field\"";
        assert!(parse_disposition_param(d, "filename").is_none());
    }

    #[test]
    fn parse_disposition_ignores_parameter_text_inside_quotes() {
        // br-asupersync-a1q12q: `name=` inside the quoted filename was taken
        // as the field name, unlike a proxy or WAF parsing the same header.
        let d = r#"form-data; filename="x; name=evil; filename*=UTF-8''y"; name="real""#;
        assert_eq!(parse_disposition_param(d, "name").unwrap(), "real");
        // The quoted `filename*=` is value text too (sanitizing drops the `*`).
        assert_eq!(
            parse_disposition_param(d, "filename").unwrap(),
            "x; name=evil; filename=UTF-8''y"
        );
    }

    // ================================================================
    // Part header parsing
    // ================================================================

    #[test]
    fn parse_headers_basic() {
        let raw = b"Content-Disposition: form-data; name=\"file\"\r\nContent-Type: image/png";
        let hdrs = parse_part_headers(raw).unwrap();
        assert_eq!(hdrs.len(), 2);
        assert!(hdrs.get("content-disposition").unwrap().contains("name="));
        assert_eq!(hdrs.get("content-type").unwrap(), "image/png");
    }

    #[test]
    fn parse_headers_empty() {
        let hdrs = parse_part_headers(b"").unwrap();
        assert!(hdrs.is_empty());
    }

    #[test]
    fn parse_headers_rejects_non_utf8() {
        // SECURITY TEST: Non-UTF8 headers must be rejected to prevent
        // bypass of nested multipart detection (br-asupersync-vzvpk9).
        let non_utf8 = b"Content-Type: multipart/mixed\xFF\xFE\r\n";
        let result = parse_part_headers(non_utf8);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("invalid UTF-8"));
    }

    #[test]
    fn validate_part_content_length_rejects_mismatch() {
        let mut headers = HashMap::new();
        headers.insert("content-length".to_string(), "5".to_string());
        let err = validate_part_content_length(&headers, 3).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("content-length mismatch"));
    }

    // ================================================================
    // Full multipart parsing
    // ================================================================

    fn make_multipart_body(boundary: &str, parts: &[(&str, &[u8])]) -> Bytes {
        let mut buf = Vec::new();
        for (headers, body) in parts {
            buf.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            buf.extend_from_slice(headers.as_bytes());
            buf.extend_from_slice(b"\r\n\r\n");
            buf.extend_from_slice(body);
            buf.extend_from_slice(b"\r\n");
        }
        buf.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        Bytes::from(buf)
    }

    fn multipart_request(body: Bytes) -> Request {
        Request::new("POST", "/upload")
            .with_header("content-type", "multipart/form-data; boundary=BOUNDARY")
            .with_body(body)
    }

    #[test]
    fn parse_single_text_field() {
        let body = make_multipart_body(
            "BOUNDARY",
            &[(
                "Content-Disposition: form-data; name=\"username\"",
                b"alice",
            )],
        );
        let fields =
            parse_multipart(&body, "BOUNDARY", &MultipartLimits::default(), wall_now()).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name(), "username");
        assert_eq!(fields[0].text().unwrap(), "alice");
        assert!(fields[0].filename().is_none());
    }

    #[test]
    fn multipart_extractor_rejects_request_content_length_mismatch() {
        let body = make_multipart_body(
            "BOUNDARY",
            &[(
                "Content-Disposition: form-data; name=\"username\"",
                b"alice",
            )],
        );
        let actual_len = body.len();
        let req =
            multipart_request(body).with_header("content-length", (actual_len + 1).to_string());

        let err = Multipart::from_request(req).unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(
            err.message.contains("Content-Length mismatch"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn multipart_extractor_rejects_conflicting_request_content_lengths() {
        let body = make_multipart_body(
            "BOUNDARY",
            &[(
                "Content-Disposition: form-data; name=\"username\"",
                b"alice",
            )],
        );
        let actual_len = body.len();
        let req = multipart_request(body).with_header(
            "content-length",
            format!("{actual_len}, {}", actual_len + 1),
        );

        let err = Multipart::from_request(req).unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(
            err.message.contains("conflicting Content-Length"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn multipart_extractor_rejects_declared_length_over_limit_before_parsing() {
        let body = make_multipart_body(
            "BOUNDARY",
            &[(
                "Content-Disposition: form-data; name=\"username\"",
                b"alice",
            )],
        );
        let mut req = multipart_request(body).with_header("content-length", "64");
        req.extensions
            .insert_typed(MultipartLimits::new().max_total_size(16));

        let err = Multipart::from_request(req).unwrap_err();

        assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            err.message.contains("Content-Length"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn parse_single_field_body_is_zero_copy_slice() {
        let body = make_multipart_body(
            "BOUNDARY",
            &[(
                "Content-Disposition: form-data; name=\"username\"",
                b"alice",
            )],
        );
        let expected_offset = body
            .windows(b"alice".len())
            .position(|w| w == b"alice")
            .unwrap();

        let fields =
            parse_multipart(&body, "BOUNDARY", &MultipartLimits::default(), wall_now()).unwrap();

        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].body().as_ref(), b"alice");
        assert_eq!(fields[0].body().as_ptr(), body[expected_offset..].as_ptr());
    }

    #[test]
    fn parse_rejects_spoofed_part_content_length() {
        let body = make_multipart_body(
            "BOUNDARY",
            &[(
                "Content-Disposition: form-data; name=\"username\"\r\nContent-Length: 999",
                b"alice",
            )],
        );
        let err = parse_multipart(&body, "BOUNDARY", &MultipartLimits::default(), wall_now())
            .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("content-length mismatch"));
    }

    #[test]
    fn parse_accepts_matching_part_content_length() {
        let body = make_multipart_body(
            "BOUNDARY",
            &[(
                "Content-Disposition: form-data; name=\"username\"\r\nContent-Length: 5",
                b"alice",
            )],
        );
        let fields =
            parse_multipart(&body, "BOUNDARY", &MultipartLimits::default(), wall_now()).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].text().unwrap(), "alice");
        assert_eq!(
            fields[0]
                .headers()
                .get("content-length")
                .map(String::as_str),
            Some("5")
        );
    }

    #[test]
    fn parse_multiple_fields() {
        let body = make_multipart_body(
            "B",
            &[
                ("Content-Disposition: form-data; name=\"a\"", b"1"),
                ("Content-Disposition: form-data; name=\"b\"", b"2"),
                ("Content-Disposition: form-data; name=\"c\"", b"3"),
            ],
        );
        let fields = parse_multipart(&body, "B", &MultipartLimits::default(), wall_now()).unwrap();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].name(), "a");
        assert_eq!(fields[1].name(), "b");
        assert_eq!(fields[2].name(), "c");
    }

    #[test]
    fn buffered_parse_scans_part_headers_in_bounded_windows() {
        // 1000 tiny CRLF parts and an 8 MiB final part. Each part used to
        // scan the rest of the body for "\n\n", which a CRLF body never
        // contains, so the work grew as parts x body size (about 8e9
        // comparisons here) and only the parse timeout ended it.
        let mut body = Vec::new();
        for i in 0..1000 {
            body.extend_from_slice(
                format!("--B\r\nContent-Disposition: form-data; name=\"f{i}\"\r\n\r\nx\r\n")
                    .as_bytes(),
            );
        }
        body.extend_from_slice(b"--B\r\nContent-Disposition: form-data; name=\"tail\"\r\n\r\n");
        body.resize(body.len() + 8 * 1024 * 1024 - 4096, b'y');
        body.extend_from_slice(b"\r\n--B--\r\n");

        let limits = MultipartLimits::default().request_timeout_secs(5);
        let fields = parse_multipart(&Bytes::from(body), "B", &limits, wall_now())
            .expect("parses well within the timeout");
        assert_eq!(fields.len(), 1001);

        // A header block longer than the limit is still reported as such.
        let oversized = format!(
            "--B\r\nX-Pad: {}\r\n\r\nv\r\n--B--\r\n",
            "p".repeat(DEFAULT_MAX_PART_HEADERS)
        );
        let err = parse_multipart(
            &Bytes::from(oversized),
            "B",
            &MultipartLimits::default(),
            wall_now(),
        )
        .expect_err("oversized headers");
        assert!(err.message.contains("headers too large"), "{err:?}");
    }

    #[test]
    fn find_blank_line_prefers_earlier_lflf_over_later_crlfcrlf() {
        // Headers terminated with bare LFLF, body contains CRLFCRLF.
        // The earlier (LFLF) match must win so the body is not truncated.
        let data = b"Header: value\n\nbefore\r\n\r\nafter";
        let result = find_blank_line(data, 0);
        assert_eq!(result, Some((13, 15)));
    }

    #[test]
    fn find_blank_line_prefers_earlier_crlfcrlf_over_later_lflf() {
        let data = b"Header: value\r\n\r\nbefore\n\nafter";
        let result = find_blank_line(data, 0);
        assert_eq!(result, Some((13, 17)));
    }

    #[test]
    fn parse_body_with_embedded_boundary_token_does_not_split_field() {
        let body = make_multipart_body(
            "BOUNDARY",
            &[(
                "Content-Disposition: form-data; name=\"payload\"",
                b"value--BOUNDARYstill-body",
            )],
        );

        let fields =
            parse_multipart(&body, "BOUNDARY", &MultipartLimits::default(), wall_now()).unwrap();

        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name(), "payload");
        assert_eq!(fields[0].body().as_ref(), b"value--BOUNDARYstill-body");
    }

    #[test]
    fn parse_rejects_nested_multipart_part() {
        let nested = b"--INNER\r\nContent-Disposition: form-data; name=\"inner\"\r\n\r\nvalue\r\n--INNER--\r\n";
        let body = make_multipart_body(
            "OUTER",
            &[(
                "Content-Disposition: form-data; name=\"payload\"\r\nContent-Type: multipart/mixed; boundary=INNER",
                nested,
            )],
        );

        let err =
            parse_multipart(&body, "OUTER", &MultipartLimits::default(), wall_now()).unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            err.message,
            "[ASUP-E507] nested multipart parts are not supported"
        );
    }

    #[test]
    fn parse_rejects_non_utf8_header_bypass_attempt() {
        // SECURITY TEST: Verify that non-UTF8 headers cannot bypass
        // nested multipart detection (br-asupersync-vzvpk9).
        let nested = b"--INNER\r\nContent-Disposition: form-data; name=\"inner\"\r\n\r\nvalue\r\n--INNER--\r\n";

        // Create a multipart body where the headers contain non-UTF8 bytes
        let mut buf = Vec::new();
        buf.extend_from_slice(b"--OUTER\r\n");
        buf.extend_from_slice(b"Content-Disposition: form-data; name=\"payload\"\r\n");
        // Inject non-UTF8 bytes in Content-Type header to try bypassing detection
        buf.extend_from_slice(b"Content-Type: multipart/mixed\xFF\xFE; boundary=INNER\r\n");
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(nested);
        buf.extend_from_slice(b"\r\n--OUTER--\r\n");
        let body = Bytes::from(buf);

        // This should fail due to non-UTF8 headers, not due to nested multipart detection
        let err =
            parse_multipart(&body, "OUTER", &MultipartLimits::default(), wall_now()).unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("invalid UTF-8"));
    }

    #[test]
    fn parse_file_upload() {
        let body = make_multipart_body(
            "X",
            &[(
                "Content-Disposition: form-data; name=\"doc\"; filename=\"readme.txt\"\r\nContent-Type: text/plain",
                b"Hello, world!",
            )],
        );
        let fields = parse_multipart(&body, "X", &MultipartLimits::default(), wall_now()).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name(), "doc");
        assert_eq!(fields[0].filename().unwrap(), "readme.txt");
        assert_eq!(fields[0].content_type().unwrap(), "text/plain");
        assert_eq!(fields[0].text().unwrap(), "Hello, world!");
    }

    #[test]
    fn parse_file_upload_prefers_rfc8187_extended_filename() {
        let body = make_multipart_body(
            "X",
            &[(
                "Content-Disposition: form-data; name=\"doc\"; filename=\"EURO rates\"; filename*=UTF-8''%e2%82%ac%20exchange%20rates\r\nContent-Type: text/plain",
                b"Hello, world!",
            )],
        );
        let fields = parse_multipart(&body, "X", &MultipartLimits::default(), wall_now()).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name(), "doc");
        assert_eq!(fields[0].filename().unwrap(), "€ exchange rates");
        assert_eq!(fields[0].content_type().unwrap(), "text/plain");
        assert_eq!(fields[0].text().unwrap(), "Hello, world!");
    }

    #[test]
    fn sanitize_filename_discards_windows_drive_and_ads_suffixes() {
        assert_eq!(sanitize_filename("C:report.txt"), "report.txt");
        assert_eq!(sanitize_filename("invoice.pdf:payload.exe"), "invoice.pdf");
        assert_eq!(
            sanitize_filename(r"C:\temp\invoice.pdf:payload.exe"),
            "invoice.pdf"
        );
    }

    #[test]
    fn parse_binary_body() {
        let binary = vec![0u8, 1, 2, 255, 254, 253];
        let body = make_multipart_body(
            "BIN",
            &[(
                "Content-Disposition: form-data; name=\"data\"; filename=\"blob.bin\"\r\nContent-Type: application/octet-stream",
                &binary,
            )],
        );
        let fields =
            parse_multipart(&body, "BIN", &MultipartLimits::default(), wall_now()).unwrap();
        assert_eq!(fields[0].body().as_ref(), &binary[..]);
        assert!(fields[0].text().is_err()); // Not valid UTF-8.
    }

    #[test]
    fn parse_empty_body_field() {
        let body = make_multipart_body(
            "E",
            &[("Content-Disposition: form-data; name=\"empty\"", b"")],
        );
        let fields = parse_multipart(&body, "E", &MultipartLimits::default(), wall_now()).unwrap();
        assert_eq!(fields.len(), 1);
        assert!(fields[0].body().is_empty());
    }

    #[test]
    fn parse_missing_boundary_error() {
        let result = parse_multipart(
            &Bytes::from_static(b"no boundary here"),
            "MISSING",
            &MultipartLimits::default(),
            wall_now(),
        );
        assert!(result.is_err());
    }

    // ================================================================
    // FromRequest integration
    // ================================================================

    #[test]
    fn from_request_success() {
        let body = make_multipart_body(
            "TEST",
            &[("Content-Disposition: form-data; name=\"field\"", b"value")],
        );
        let mut req = Request::new("POST", "/upload");
        req.headers.insert(
            "content-type".to_string(),
            "multipart/form-data; boundary=TEST".to_string(),
        );
        req.body = body;

        let mp = Multipart::from_request(req).unwrap();
        assert_eq!(mp.len(), 1);
        assert_eq!(mp.field("field").unwrap().text().unwrap(), "value");
    }

    #[test]
    fn from_request_accepts_rfc2046_quoted_boundary_with_space() {
        let body = make_multipart_body(
            "simple boundary",
            &[("Content-Disposition: form-data; name=\"field\"", b"value")],
        );
        let mut req = Request::new("POST", "/upload");
        req.headers.insert(
            "content-type".to_string(),
            "multipart/form-data; boundary=\"simple boundary\"".to_string(),
        );
        req.body = body;

        let mp = Multipart::from_request(req).unwrap();
        assert_eq!(mp.len(), 1);
        assert_eq!(mp.field("field").unwrap().text().unwrap(), "value");
    }

    #[test]
    fn from_request_wrong_content_type() {
        let mut req = Request::new("POST", "/upload");
        req.headers
            .insert("content-type".to_string(), "application/json".to_string());
        req.body = Bytes::from(vec![]);

        let err = Multipart::from_request(req).unwrap_err();
        assert_eq!(err.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[test]
    fn from_request_rejects_media_type_substring_match() {
        let mut req = Request::new("POST", "/upload");
        req.headers.insert(
            "content-type".to_string(),
            "multipart/form-datax; boundary=TEST".to_string(),
        );
        req.body = Bytes::from(vec![]);

        let err = Multipart::from_request(req).unwrap_err();
        assert_eq!(err.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[test]
    fn from_request_uses_actual_boundary_parameter() {
        let body = make_multipart_body(
            "REAL",
            &[("Content-Disposition: form-data; name=\"field\"", b"value")],
        );
        let mut req = Request::new("POST", "/upload");
        req.headers.insert(
            "content-type".to_string(),
            "multipart/form-data; xboundary=wrong; boundary=REAL".to_string(),
        );
        req.body = body;

        let mp = Multipart::from_request(req).unwrap();
        assert_eq!(mp.len(), 1);
        assert_eq!(mp.field("field").unwrap().text().unwrap(), "value");
    }

    #[test]
    fn from_request_rejects_malformed_boundary_before_later_fragment() {
        let body = make_multipart_body(
            "REAL",
            &[("Content-Disposition: form-data; name=\"field\"", b"value")],
        );
        let mut req = Request::new("POST", "/upload");
        req.headers.insert(
            "content-type".to_string(),
            "multipart/form-data; boundary=\"unterminated; boundary=REAL".to_string(),
        );
        req.body = body;

        let err = Multipart::from_request(req).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn from_request_missing_content_type() {
        let req = Request::new("POST", "/upload");
        let err = Multipart::from_request(req).unwrap_err();
        assert_eq!(err.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[test]
    fn from_request_missing_boundary() {
        let mut req = Request::new("POST", "/upload");
        req.headers.insert(
            "content-type".to_string(),
            "multipart/form-data".to_string(),
        );
        req.body = Bytes::from(vec![]);

        let err = Multipart::from_request(req).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn from_request_payload_too_large() {
        let mut req = Request::new("POST", "/upload");
        req.headers.insert(
            "content-type".to_string(),
            "multipart/form-data; boundary=X".to_string(),
        );
        req.body = Bytes::copy_from_slice(&vec![0u8; DEFAULT_MAX_MULTIPART_SIZE + 1]);

        let err = Multipart::from_request(req).unwrap_err();
        assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn from_request_part_body_too_large() {
        let mut req = Request::new("POST", "/upload");
        req.headers.insert(
            "content-type".to_string(),
            "multipart/form-data; boundary=X".to_string(),
        );
        let mut body = Vec::new();
        body.extend_from_slice(b"--X\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\n");
        body.extend_from_slice(&vec![0u8; DEFAULT_MAX_PART_BODY_SIZE + 1]);
        body.extend_from_slice(b"\r\n--X--\r\n");
        req.body = Bytes::from(body);

        let err = Multipart::from_request(req).unwrap_err();
        assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(err.message, "[ASUP-E506] multipart part body too large");
    }

    // ================================================================
    // Multipart accessors
    // ================================================================

    #[test]
    fn multipart_field_by_name() {
        let body = make_multipart_body(
            "F",
            &[
                ("Content-Disposition: form-data; name=\"x\"", b"1"),
                ("Content-Disposition: form-data; name=\"y\"", b"2"),
            ],
        );
        let fields = parse_multipart(&body, "F", &MultipartLimits::default(), wall_now()).unwrap();
        let mp = Multipart { fields };

        assert_eq!(mp.field("x").unwrap().text().unwrap(), "1");
        assert_eq!(mp.field("y").unwrap().text().unwrap(), "2");
        assert!(mp.field("z").is_none());
    }

    #[test]
    fn multipart_repeated_fields() {
        let body = make_multipart_body(
            "R",
            &[
                ("Content-Disposition: form-data; name=\"tag\"", b"a"),
                ("Content-Disposition: form-data; name=\"tag\"", b"b"),
            ],
        );
        let fields = parse_multipart(&body, "R", &MultipartLimits::default(), wall_now()).unwrap();
        let mp = Multipart { fields };

        let tags = mp.fields_by_name("tag");
        assert_eq!(tags.len(), 2);
    }

    #[test]
    fn multipart_is_empty() {
        let mp = Multipart { fields: Vec::new() };
        assert!(mp.is_empty());
        assert_eq!(mp.len(), 0);
    }

    #[test]
    fn multipart_into_fields() {
        let body =
            make_multipart_body("I", &[("Content-Disposition: form-data; name=\"k\"", b"v")]);
        let fields = parse_multipart(&body, "I", &MultipartLimits::default(), wall_now()).unwrap();
        let mp = Multipart { fields };
        let mut owned = mp.into_fields();
        assert_eq!(owned.len(), 1);
        assert_eq!(owned.remove(0).into_body().as_ref(), b"v");
    }

    // ================================================================
    // Edge cases
    // ================================================================

    #[test]
    fn parse_lf_line_endings() {
        // Some clients use bare LF instead of CRLF.
        let mut body = Vec::new();
        body.extend_from_slice(b"--B\n");
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"f\"\n\n");
        body.extend_from_slice(b"data");
        body.extend_from_slice(b"\n--B--\n");
        let body = Bytes::from(body);
        let fields = parse_multipart(&body, "B", &MultipartLimits::default(), wall_now()).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].text().unwrap(), "data");
    }

    #[test]
    fn parse_preamble_before_first_boundary() {
        let mut body = Vec::new();
        body.extend_from_slice(b"This is a preamble that should be ignored.\r\n");
        body.extend_from_slice(b"--BOUND\r\n");
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"x\"\r\n\r\n");
        body.extend_from_slice(b"val");
        body.extend_from_slice(b"\r\n--BOUND--\r\n");
        let body = Bytes::from(body);
        let fields =
            parse_multipart(&body, "BOUND", &MultipartLimits::default(), wall_now()).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].text().unwrap(), "val");
    }

    #[test]
    fn field_debug_clone() {
        let f = MultipartField {
            name: "n".into(),
            filename: Some("f.txt".into()),
            content_type: Some("text/plain".into()),
            headers: HashMap::new(),
            body: Bytes::from(b"hi".to_vec()),
        };
        let dbg = format!("{f:?}");
        assert!(dbg.contains("MultipartField"));
    }

    #[test]
    fn multipart_debug_clone() {
        let mp = Multipart { fields: vec![] };
        let dbg = format!("{mp:?}");
        assert!(dbg.contains("Multipart"));
    }

    // ================================================================
    // Timeout tests
    // ================================================================

    #[test]
    fn timeout_limits_configuration() {
        let limits = MultipartLimits::new()
            .request_timeout_secs(60)
            .idle_timeout_secs(10);

        assert_eq!(limits.request_timeout_secs, 60);
        assert_eq!(limits.idle_timeout_secs, 10);
    }

    #[test]
    fn timeout_check_succeeds_within_limits() {
        let limits = MultipartLimits::new()
            .request_timeout_secs(60)
            .idle_timeout_secs(10);

        let start = wall_now();
        let result = check_timeout(start, start, &limits);
        assert!(result.is_ok());
    }

    #[test]
    fn timeout_check_fails_when_request_timeout_exceeded() {
        let limits = MultipartLimits::new()
            .request_timeout_secs(0) // Set to 0 to trigger immediately
            .idle_timeout_secs(10);

        let start = Time::ZERO; // Very old timestamp
        let result = check_timeout(start, start, &limits);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status, StatusCode::REQUEST_TIMEOUT);
        assert!(err.message.contains("multipart parsing timed out"));
    }

    #[test]
    fn timeout_check_fails_when_idle_timeout_exceeded() {
        let limits = MultipartLimits::new()
            .request_timeout_secs(60)
            .idle_timeout_secs(0); // Set to 0 to trigger immediately

        let start = wall_now();
        let old_progress = Time::ZERO; // Very old timestamp
        let result = check_timeout(start, old_progress, &limits);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status, StatusCode::REQUEST_TIMEOUT);
        assert!(err.message.contains("multipart parsing idle"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn assert_streamed_field_parity(actual: &[MultipartField], expected: &[MultipartField]) {
        assert_eq!(actual.len(), expected.len());
        for (actual, expected) in actual.iter().zip(expected) {
            assert_eq!(actual.name, expected.name);
            assert_eq!(actual.filename, expected.filename);
            assert_eq!(actual.content_type, expected.content_type);
            assert_eq!(actual.headers, expected.headers);
            assert_eq!(actual.body.as_ref(), expected.body.as_ref());
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn assert_streaming_decoder_retention(decoder: &StreamingMultipartDecoder) {
        match decoder.phase {
            StreamingMultipartPhase::Preamble | StreamingMultipartPhase::Body => assert!(
                decoder.buffer.len() <= decoder.delimiter.len() + 3,
                "rolling delimiter scratch retained {} bytes",
                decoder.buffer.len()
            ),
            StreamingMultipartPhase::Headers => assert!(
                decoder.buffer.len() <= decoder.limits.max_part_headers.saturating_add(3),
                "header scratch retained {} bytes",
                decoder.buffer.len()
            ),
            StreamingMultipartPhase::Done => assert!(decoder.buffer.is_empty()),
        }
        assert!(decoder.current_body.len() <= decoder.limits.max_part_body_size);
        let completed_body_bytes: usize = decoder.fields.iter().map(|field| field.body.len()).sum();
        assert!(completed_body_bytes <= decoder.total_received);
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn decode_streaming_multipart(
        body: &[u8],
        boundary: &str,
        limits: MultipartLimits,
        split: usize,
    ) -> Result<Vec<MultipartField>, ExtractionError> {
        let mut decoder = StreamingMultipartDecoder::new(boundary, limits, Some(body.len()))?;
        decoder.feed(&body[..split])?;
        decoder.feed(&body[split..])?;
        decoder.finish()
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_decoder_matches_buffered_parser_at_every_split() {
        let boundary = "STREAM-BOUNDARY";
        let mut body = b"ignored preamble\r\n".to_vec();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"text\"\r\n\r\n")
                .as_bytes(),
        );
        body.extend_from_slice(b"alpha\r\n--STREAM-BOUNDARYX remains payload");
        body.extend_from_slice(
            format!(
                "\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename*=UTF-8''%e2%82%ac.txt\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(&[0, 1, 2, 0xff]);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\nepilogue").as_bytes());

        let bytes = Bytes::from(body.clone());
        let expected = parse_multipart(&bytes, boundary, &MultipartLimits::default(), wall_now())
            .expect("buffered multipart corpus");

        for split in 0..=body.len() {
            let actual =
                decode_streaming_multipart(&body, boundary, MultipartLimits::default(), split)
                    .unwrap_or_else(|error| panic!("split {split} failed: {error:?}"));
            assert_streamed_field_parity(&actual, &expected);
        }

        let mut bytewise =
            StreamingMultipartDecoder::new(boundary, MultipartLimits::default(), Some(body.len()))
                .expect("bytewise decoder");
        for byte in &body {
            bytewise.feed(std::slice::from_ref(byte)).unwrap();
        }
        let actual = bytewise.finish().expect("bytewise multipart corpus");
        assert_streamed_field_parity(&actual, &expected);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_decoder_preserves_false_candidates_and_bare_cr_compatibility() {
        let false_candidate_body = b"preamble x--B--not-initial\r\n--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nline x--B--not-closing\r\n--BX\r\n--B-\nend\r\n--B--";
        let false_candidate_bytes = Bytes::copy_from_slice(false_candidate_body);
        let expected = parse_multipart(
            &false_candidate_bytes,
            "B",
            &MultipartLimits::default(),
            wall_now(),
        )
        .expect("buffered false-candidate corpus");
        for split in 0..=false_candidate_body.len() {
            let actual = decode_streaming_multipart(
                false_candidate_body,
                "B",
                MultipartLimits::default(),
                split,
            )
            .unwrap_or_else(|error| panic!("false-candidate split {split}: {error:?}"));
            assert_streamed_field_parity(&actual, &expected);
        }
        let mut decoder = StreamingMultipartDecoder::new(
            "B",
            MultipartLimits::default(),
            Some(false_candidate_body.len()),
        )
        .unwrap();
        for byte in false_candidate_body {
            decoder.feed(std::slice::from_ref(byte)).unwrap();
            assert_streaming_decoder_retention(&decoder);
        }
        let actual = decoder.finish().expect("streamed false candidates");
        assert_streamed_field_parity(&actual, &expected);
        assert_eq!(
            actual[0].body.as_ref(),
            b"line x--B--not-closing\r\n--BX\r\n--B-\nend"
        );

        let bare_cr_body = b"--B\rContent-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n--B--";
        let bare_cr_bytes = Bytes::copy_from_slice(bare_cr_body);
        let expected =
            parse_multipart(&bare_cr_bytes, "B", &MultipartLimits::default(), wall_now())
                .expect("buffered bare-CR corpus");
        let mut decoder = StreamingMultipartDecoder::new(
            "B",
            MultipartLimits::default(),
            Some(bare_cr_body.len()),
        )
        .unwrap();
        for byte in bare_cr_body {
            decoder.feed(std::slice::from_ref(byte)).unwrap();
        }
        let actual = decoder.finish().expect("streamed bare-CR corpus");
        assert_streamed_field_parity(&actual, &expected);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_decoder_many_parts_is_segmentation_independent_under_tight_total_cap() {
        let mut body = Vec::new();
        for index in 0..64 {
            body.extend_from_slice(
                format!("--B\r\nContent-Disposition: form-data; name=\"f{index}\"\r\n\r\nx\r\n")
                    .as_bytes(),
            );
        }
        body.extend_from_slice(b"--B--");
        let limits = MultipartLimits::new()
            .max_total_size(body.len())
            .max_parts(64);

        let mut one_frame = StreamingMultipartDecoder::new("B", limits, Some(body.len())).unwrap();
        one_frame.feed(&body).expect("single-frame many-parts body");
        assert_streaming_decoder_retention(&one_frame);
        let one_frame = one_frame.finish().expect("single-frame many-parts EOF");

        let mut fragmented = StreamingMultipartDecoder::new("B", limits, Some(body.len())).unwrap();
        for byte in &body {
            fragmented.feed(std::slice::from_ref(byte)).unwrap();
            assert_streaming_decoder_retention(&fragmented);
        }
        let fragmented = fragmented.finish().expect("fragmented many-parts EOF");
        assert_streamed_field_parity(&one_frame, &fragmented);
        assert_eq!(one_frame.len(), 64);
    }

    #[test]
    fn buffered_parser_rejects_body_missing_closing_boundary() {
        // br-asupersync-hw83se: the buffered parse_multipart used to accept a
        // body truncated after a non-closing part delimiter (no final `--B--`),
        // while the streaming decoder rejected it — the two entry points
        // disagreed on the same bytes. The buffered parser now rejects it too. A
        // well-formed body (with the close delimiter) still parses.
        let malformed =
            b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nvalue\r\n--B\r\n".to_vec();
        let error = parse_multipart(
            &Bytes::from(malformed),
            "B",
            &MultipartLimits::default(),
            wall_now(),
        )
        .expect_err("a body missing the closing boundary must be rejected");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);

        let valid =
            b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nvalue\r\n--B--\r\n".to_vec();
        let fields = parse_multipart(
            &Bytes::from(valid),
            "B",
            &MultipartLimits::default(),
            wall_now(),
        )
        .expect("a well-formed body still parses");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].text().unwrap(), "value");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_decoder_refuses_truncation_and_each_logical_limit() {
        let cases: &[(&[u8], &str)] = &[
            (b"preamble", "missing initial boundary"),
            (
                b"--B\r\nContent-Disposition: form-data",
                "missing header terminator",
            ),
            (
                b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nbody",
                "missing closing boundary",
            ),
        ];
        for (body, message) in cases {
            let mut decoder =
                StreamingMultipartDecoder::new("B", MultipartLimits::default(), None).unwrap();
            decoder.feed(body).unwrap();
            let error = decoder.finish().expect_err("truncated multipart");
            assert_eq!(error.status, StatusCode::BAD_REQUEST);
            assert!(error.message.contains(message), "{error:?}");
        }

        let body = b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1234\r\n--B\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\n2\r\n--B--";

        let mut total = StreamingMultipartDecoder::new(
            "B",
            MultipartLimits::new().max_total_size(body.len() - 1),
            None,
        )
        .unwrap();
        let error = total.feed(body).expect_err("total limit");
        assert_eq!(error.status, StatusCode::PAYLOAD_TOO_LARGE);

        let mut headers =
            StreamingMultipartDecoder::new("B", MultipartLimits::new().max_part_headers(8), None)
                .unwrap();
        let error = headers.feed(body).expect_err("header limit");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert!(error.message.contains("headers too large"));

        let mut part =
            StreamingMultipartDecoder::new("B", MultipartLimits::new().max_part_body_size(3), None)
                .unwrap();
        let error = part.feed(body).expect_err("part limit");
        assert_eq!(error.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(error.message.contains("part body too large"));

        let mut count =
            StreamingMultipartDecoder::new("B", MultipartLimits::new().max_parts(1), None).unwrap();
        let error = count.feed(body).expect_err("part count");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert!(error.message.contains("too many multipart parts"));

        let mut length =
            StreamingMultipartDecoder::new("B", MultipartLimits::default(), Some(body.len() + 1))
                .unwrap();
        length.feed(body).unwrap();
        let error = length.finish().expect_err("request length mismatch");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert!(error.message.contains("Content-Length mismatch"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn multipart_block_on<F: std::future::Future>(future: F) -> F::Output {
        let waker = std::task::Waker::noop().clone();
        let mut task_cx = std::task::Context::from_waker(&waker);
        let mut future = std::pin::pin!(future);
        loop {
            match std::future::Future::poll(future.as_mut(), &mut task_cx) {
                std::task::Poll::Ready(output) => return output,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn streaming_multipart_request(
        cx: &Cx,
        kind: crate::http::h1::stream::BodyKind,
        limits: MultipartLimits,
    ) -> (
        crate::http::h1::stream::IncomingRequestBodyWriter,
        Request,
        crate::web::extract::StreamingRawBodyControl,
    ) {
        let (writer, body) = crate::http::h1::stream::IncomingRequestBody::channel(cx, kind);
        let mut req = Request::new("POST", "/multipart")
            .with_header("content-type", "multipart/form-data; boundary=B");
        if let crate::http::h1::stream::BodyKind::ContentLength(length) = kind {
            req = req.with_header("content-length", length.to_string());
        }
        req.extensions.insert_typed(limits);
        let control = crate::web::extract::insert_streaming_raw_body(&mut req, body)
            .expect("install streamed multipart body");
        (writer, req, control)
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_multipart_refuses_metadata_before_body_ownership_and_observes_cancellation() {
        use crate::http::h1::stream::BodyKind;
        use crate::types::CancelKind;

        let cx = Cx::for_testing();
        let (writer, req, control) = streaming_multipart_request(
            &cx,
            BodyKind::ContentLength(128),
            MultipartLimits::new().max_total_size(64),
        );
        let error = multipart_block_on(Multipart::from_request_with_cx(&cx, req))
            .expect_err("declared multipart length must fail before body take");
        assert_eq!(error.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(!writer.consumer_dropped());
        drop(control);
        assert!(writer.consumer_dropped());

        for (content_type, expected_status) in [
            (None, StatusCode::UNSUPPORTED_MEDIA_TYPE),
            (Some("text/plain"), StatusCode::UNSUPPORTED_MEDIA_TYPE),
            (
                Some("multipart/form-data; boundary="),
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let metadata_cx = Cx::for_testing();
            let (metadata_writer, mut req, metadata_control) = streaming_multipart_request(
                &metadata_cx,
                BodyKind::ContentLength(1),
                MultipartLimits::default(),
            );
            req.headers.remove("content-type");
            if let Some(content_type) = content_type {
                req.headers
                    .insert("content-type".to_owned(), content_type.to_owned());
            }
            let error = multipart_block_on(Multipart::from_request_with_cx(&metadata_cx, req))
                .expect_err("invalid multipart metadata must fail before body take");
            assert_eq!(error.status, expected_status);
            assert!(!metadata_writer.consumer_dropped());
            drop(metadata_control);
            assert!(metadata_writer.consumer_dropped());
        }

        let eof_cx = Cx::for_testing();
        let (mut eof_writer, eof_req, eof_control) =
            streaming_multipart_request(&eof_cx, BodyKind::Chunked, MultipartLimits::default());
        let mut extraction = std::pin::pin!(Multipart::from_request_with_cx(&eof_cx, eof_req));
        let waker = std::task::Waker::noop().clone();
        let mut task_cx = std::task::Context::from_waker(&waker);
        assert!(matches!(
            std::future::Future::poll(extraction.as_mut(), &mut task_cx),
            std::task::Poll::Pending
        ));
        let multipart_body = b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n--B--";
        let mut transfer_chunk = format!("{:X}\r\n", multipart_body.len()).into_bytes();
        transfer_chunk.extend_from_slice(multipart_body);
        transfer_chunk.extend_from_slice(b"\r\n");
        multipart_block_on(eof_writer.push_bytes(&eof_cx, &transfer_chunk))
            .expect("publish complete multipart before request EOF");
        assert!(matches!(
            std::future::Future::poll(extraction.as_mut(), &mut task_cx),
            std::task::Poll::Pending
        ));
        multipart_block_on(eof_writer.push_bytes(&eof_cx, b"0\r\n\r\n"))
            .expect("publish request EOF");
        let std::task::Poll::Ready(Ok(extracted)) =
            std::future::Future::poll(extraction.as_mut(), &mut task_cx)
        else {
            panic!("multipart extraction must complete after request EOF");
        };
        assert_eq!(extracted.field("f").unwrap().body.as_ref(), b"v");
        drop(eof_control);

        let cancelled_cx = Cx::for_testing();
        let (mut writer, req, control) = streaming_multipart_request(
            &cancelled_cx,
            BodyKind::ContentLength(64),
            MultipartLimits::default(),
        );
        let mut extraction = std::pin::pin!(Multipart::from_request_with_cx(&cancelled_cx, req));
        let waker = std::task::Waker::noop().clone();
        let mut task_cx = std::task::Context::from_waker(&waker);
        assert!(matches!(
            std::future::Future::poll(extraction.as_mut(), &mut task_cx),
            std::task::Poll::Pending
        ));
        cancelled_cx.cancel_fast(CancelKind::Deadline);
        let std::task::Poll::Ready(Err(error)) =
            std::future::Future::poll(extraction.as_mut(), &mut task_cx)
        else {
            panic!("cancelled multipart extraction must terminate");
        };
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        // The message carries the cancellation context ("server request
        // budget deadline exceeded: ...") in front of the fixed tail; pin the
        // code token and the tail rather than the exact composition.
        assert!(
            error.message.starts_with("[ASUP-E501]"),
            "message must lead with the error code: {}",
            error.message
        );
        assert!(
            error
                .message
                .ends_with("multipart request body unavailable"),
            "message must name the unavailable body: {}",
            error.message
        );
        drop(control);
        assert_eq!(
            multipart_block_on(writer.push_bytes(&cancelled_cx, b"x")),
            Err(IncomingBodyError::Cancelled {
                kind: CancelKind::Deadline,
            })
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn transfer_chunk(data: &[u8]) -> Vec<u8> {
        let mut encoded = format!("{:X}\r\n", data.len()).into_bytes();
        encoded.extend_from_slice(data);
        encoded.extend_from_slice(b"\r\n");
        encoded
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_field_api_yields_metadata_and_bounded_chunks_before_transport_eof() {
        use crate::http::h1::stream::BodyKind;

        let cx = Cx::for_testing();
        let (mut writer, req, control) =
            streaming_multipart_request(&cx, BodyKind::Chunked, MultipartLimits::default());
        let mut multipart = StreamingMultipart::from_request(req).expect("streaming extractor");

        let head = b"--B\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"../safe.bin\"\r\nContent-Type: application/octet-stream\r\nX-Part: yes\r\n\r\n";
        multipart_block_on(writer.push_bytes(&cx, &transfer_chunk(head)))
            .expect("publish field metadata without payload");

        let mut field = multipart_block_on(multipart.next_field(&cx))
            .expect("field metadata")
            .expect("first field");
        assert_eq!(field.name(), "upload");
        assert_eq!(field.filename(), Some("safe.bin"));
        assert_eq!(field.content_type(), Some("application/octet-stream"));
        assert_eq!(
            field.headers().get("x-part").map(String::as_str),
            Some("yes")
        );

        let payload = (0..10_000)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        let mut tail = payload.clone();
        tail.extend_from_slice(b"\r\n--B--\r\nepilogue");
        multipart_block_on(writer.push_bytes(&cx, &transfer_chunk(&tail)))
            .expect("publish field payload and MIME close");

        let mut actual = Vec::new();
        while let Some(chunk) = multipart_block_on(field.next_chunk(&cx)).expect("field chunk") {
            assert!(
                chunk.len() <= StreamingMultipart::INPUT_WINDOW,
                "field chunk retained {} bytes",
                chunk.len()
            );
            actual.extend_from_slice(chunk.as_ref());
        }
        assert_eq!(actual, payload);
        drop(field);

        let mut terminal = std::pin::pin!(multipart.next_field(&cx));
        let waker = std::task::Waker::noop().clone();
        let mut task_cx = std::task::Context::from_waker(&waker);
        assert!(matches!(
            std::future::Future::poll(terminal.as_mut(), &mut task_cx),
            std::task::Poll::Pending
        ));
        multipart_block_on(writer.push_bytes(&cx, b"0\r\n\r\n")).expect("publish HTTP body EOF");
        assert!(matches!(
            std::future::Future::poll(terminal.as_mut(), &mut task_cx),
            std::task::Poll::Ready(Ok(None))
        ));
        drop(control);
        assert!(!writer.consumer_dropped());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_field_api_is_exact_across_every_wire_split() {
        use crate::http::h1::stream::BodyKind;

        let body = b"preamble x--B--not-a-boundary\r\n--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nalpha x--B--payload\r\n--B\r\nContent-Disposition: form-data; name=\"b\"; filename=\"C:\\tmp\\b.txt\"\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\nbeta\r\n--B--\r\nepilogue";

        for split in 0..=body.len() {
            let cx = Cx::for_testing();
            let (mut writer, req, control) = streaming_multipart_request(
                &cx,
                BodyKind::ContentLength(u64::try_from(body.len()).unwrap()),
                MultipartLimits::default(),
            );
            let mut multipart = StreamingMultipart::from_request(req).expect("streaming extractor");
            multipart_block_on(writer.push_bytes(&cx, &body[..split]))
                .unwrap_or_else(|error| panic!("split {split} prefix: {error:?}"));
            multipart_block_on(writer.push_bytes(&cx, &body[split..]))
                .unwrap_or_else(|error| panic!("split {split} suffix: {error:?}"));

            let mut fields = Vec::new();
            while let Some(mut field) = multipart_block_on(multipart.next_field(&cx))
                .unwrap_or_else(|error| panic!("split {split} field: {error:?}"))
            {
                let metadata = (
                    field.name().to_owned(),
                    field.filename().map(str::to_owned),
                    field.content_type().map(str::to_owned),
                );
                let mut bytes = Vec::new();
                while let Some(chunk) = multipart_block_on(field.next_chunk(&cx))
                    .unwrap_or_else(|error| panic!("split {split} chunk: {error:?}"))
                {
                    assert!(chunk.len() <= StreamingMultipart::INPUT_WINDOW);
                    bytes.extend_from_slice(chunk.as_ref());
                }
                fields.push((metadata, bytes));
            }

            assert_eq!(fields.len(), 2, "split {split}");
            assert_eq!(fields[0].0, ("a".to_owned(), None, None), "split {split}");
            assert_eq!(fields[0].1, b"alpha x--B--payload", "split {split}");
            assert_eq!(
                fields[1].0,
                (
                    "b".to_owned(),
                    Some("tmpb.txt".to_owned()),
                    Some("text/plain".to_owned())
                ),
                "split {split}"
            );
            assert_eq!(fields[1].1, b"beta", "split {split}");
            drop(control);
            assert!(!writer.consumer_dropped(), "split {split}");
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_field_drop_and_forgotten_lease_fail_closed() {
        use crate::http::h1::stream::BodyKind;

        let cx = Cx::for_testing();
        let (mut writer, req, control) =
            streaming_multipart_request(&cx, BodyKind::Chunked, MultipartLimits::default());
        let mut multipart = StreamingMultipart::from_request(req).expect("streaming extractor");
        let mut first_chunk = b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n".to_vec();
        first_chunk.extend(std::iter::repeat_n(b'x', 128));
        multipart_block_on(writer.push_bytes(&cx, &transfer_chunk(&first_chunk)))
            .expect("publish partial field");
        let mut field = multipart_block_on(multipart.next_field(&cx))
            .expect("field metadata")
            .expect("first field");
        assert!(
            multipart_block_on(field.next_chunk(&cx))
                .expect("first body chunk")
                .is_some()
        );
        drop(field);
        assert!(writer.consumer_dropped());
        let error = multipart_block_on(multipart.next_field(&cx))
            .expect_err("abandoned field must terminalize parser");
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
        assert_eq!(error.kind(), StreamingMultipartErrorKind::AbandonedField);
        assert!(
            multipart
                .retention_snapshot()
                .incoming_queue_bytes_peak
                .is_none(),
            "abandonment drops the live incoming-queue observer"
        );
        assert!(
            multipart
                .retention_snapshot()
                .incoming_queue_frames_peak
                .is_none(),
            "abandonment drops the live incoming-frame observer"
        );
        drop(control);

        let forgotten_cx = Cx::for_testing();
        let (mut forgotten_writer, forgotten_req, forgotten_control) = streaming_multipart_request(
            &forgotten_cx,
            BodyKind::Chunked,
            MultipartLimits::default(),
        );
        let mut forgotten =
            StreamingMultipart::from_request(forgotten_req).expect("streaming extractor");
        let metadata = b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n";
        multipart_block_on(forgotten_writer.push_bytes(&forgotten_cx, &transfer_chunk(metadata)))
            .expect("publish metadata");
        let field = multipart_block_on(forgotten.next_field(&forgotten_cx))
            .expect("field metadata")
            .expect("first field");
        std::mem::forget(field);
        let error = multipart_block_on(forgotten.next_field(&forgotten_cx))
            .expect_err("forgotten lease must fail closed");
        assert_eq!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.kind(), StreamingMultipartErrorKind::AbandonedField);
        assert!(error.message().contains("forgotten"));
        assert!(forgotten_writer.consumer_dropped());
        assert!(
            forgotten
                .retention_snapshot()
                .incoming_queue_bytes_peak
                .is_none(),
            "forgotten field lease drops the live incoming-queue observer"
        );
        assert!(
            forgotten
                .retention_snapshot()
                .incoming_queue_frames_peak
                .is_none(),
            "forgotten field lease drops the live incoming-frame observer"
        );
        drop(forgotten_control);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn body_diagnostic_streaming_field_limits_and_cancellation_keep_typed_statuses() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Wake, Waker};

        use crate::http::h1::stream::BodyKind;
        use crate::types::CancelKind;

        let limit_cx = Cx::for_testing();
        let body = b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n1234\r\n--B--";
        let (mut limit_writer, limit_req, limit_control) = streaming_multipart_request(
            &limit_cx,
            BodyKind::ContentLength(u64::try_from(body.len()).unwrap()),
            MultipartLimits::new().max_part_body_size(3),
        );
        let mut limited = StreamingMultipart::from_request(limit_req).expect("streaming extractor");
        multipart_block_on(limit_writer.push_bytes(&limit_cx, body)).expect("publish body");
        let mut field = multipart_block_on(limited.next_field(&limit_cx))
            .expect("field metadata")
            .expect("first field");
        let error = multipart_block_on(field.next_chunk(&limit_cx))
            .expect_err("part limit must fail during delivery");
        assert_eq!(error.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(error.kind(), StreamingMultipartErrorKind::PayloadTooLarge);
        assert_eq!(error.code(), "ASUP-E504");
        assert_eq!(error.diagnostic_code(), "ASUP-E506");
        assert!(error.to_string().starts_with("[ASUP-E504] 413 "));
        let response = crate::web::response::IntoResponse::into_response(error.clone());
        assert!(response.body.starts_with(b"[ASUP-E506] "));
        drop(field);
        drop(limit_control);

        let metadata_cx = Cx::for_testing();
        let (metadata_writer, mut req, metadata_control) = streaming_multipart_request(
            &metadata_cx,
            BodyKind::Chunked,
            MultipartLimits::default(),
        );
        req.headers
            .insert("content-type".to_owned(), "text/plain".to_owned());
        let error = StreamingMultipart::from_request(req)
            .expect_err("wrong media type must fail before body ownership");
        assert_eq!(error.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            error.kind(),
            StreamingMultipartErrorKind::UnsupportedMediaType
        );
        assert_eq!(error.diagnostic_code(), "ASUP-E507");
        assert!(error.to_string().starts_with("[ASUP-E504] 415 "));
        let response = crate::web::response::IntoResponse::into_response(error.clone());
        assert!(response.body.starts_with(b"[ASUP-E507] "));
        assert!(!metadata_writer.consumer_dropped());
        drop(metadata_control);
        assert!(metadata_writer.consumer_dropped());

        struct CountWake(AtomicUsize);
        impl Wake for CountWake {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let body_cx = Cx::for_testing();
        let handler_cx = Cx::for_testing();
        let (cancel_writer, cancel_req, cancel_control) =
            streaming_multipart_request(&body_cx, BodyKind::Chunked, MultipartLimits::default());
        let mut cancelled =
            StreamingMultipart::from_request(cancel_req).expect("streaming extractor");
        let wake_count = Arc::new(CountWake(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wake_count));
        let mut task_cx = std::task::Context::from_waker(&waker);
        let mut next = std::pin::pin!(cancelled.next_field(&handler_cx));
        assert!(matches!(
            std::future::Future::poll(next.as_mut(), &mut task_cx),
            std::task::Poll::Pending
        ));
        handler_cx.cancel_fast(CancelKind::Deadline);
        assert!(wake_count.0.load(Ordering::SeqCst) > 0);
        let std::task::Poll::Ready(Err(error)) =
            std::future::Future::poll(next.as_mut(), &mut task_cx)
        else {
            panic!("external handler cancellation must wake the pending body read");
        };
        assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.kind(), StreamingMultipartErrorKind::Cancelled);
        assert_eq!(error.cancel_kind(), Some(CancelKind::Deadline));
        assert_eq!(error.diagnostic_code(), "ASUP-E501");
        assert!(error.to_string().starts_with("[ASUP-E504] 503 "));
        let response = crate::web::response::IntoResponse::into_response(error.clone());
        assert!(response.body.starts_with(b"[ASUP-E501] "));
        assert!(cancel_writer.consumer_dropped());
        drop(cancel_control);

        let disconnected =
            StreamingMultipartError::from_body_error(IncomingBodyError::SourceDisconnected);
        assert_eq!(disconnected.kind(), StreamingMultipartErrorKind::Internal);
        assert_eq!(disconnected.cancel_kind(), None);
        assert_eq!(disconnected.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(disconnected.diagnostic_code(), "ASUP-E504");
        assert!(disconnected.to_string().starts_with("[ASUP-E504] 500 "));
        let disconnected_response =
            crate::web::response::IntoResponse::into_response(disconnected.clone());
        assert_eq!(
            disconnected_response.body.as_ref(),
            disconnected.to_string().as_bytes()
        );
        let aborted = StreamingMultipartError::from_body_error(IncomingBodyError::ClientAborted);
        assert_eq!(aborted.diagnostic_code(), "ASUP-E509");
        assert!(aborted.to_string().starts_with("[ASUP-E504] 499 "));
        let aborted_response = crate::web::response::IntoResponse::into_response(aborted.clone());
        assert!(aborted_response.body.starts_with(b"[ASUP-E509] "));
        let consumer_dropped =
            StreamingMultipartError::from_body_error(IncomingBodyError::ConsumerDropped);
        assert_eq!(
            consumer_dropped.kind(),
            StreamingMultipartErrorKind::AbandonedField
        );
        let consumer_dropped_response =
            crate::web::response::IntoResponse::into_response(consumer_dropped.clone());
        assert_eq!(
            consumer_dropped_response.body.as_ref(),
            consumer_dropped.to_string().as_bytes()
        );
        let drain_failed =
            StreamingMultipartError::from_body_error(IncomingBodyError::DrainTimeout);
        assert_eq!(drain_failed.kind(), StreamingMultipartErrorKind::Timeout);
        assert_eq!(drain_failed.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(drain_failed.diagnostic_code(), "ASUP-E508");
    }
