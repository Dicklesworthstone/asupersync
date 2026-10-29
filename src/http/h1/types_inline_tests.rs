    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use serde_json::{Value, json};

    fn scrub_snapshot_header_value(name: &str, value: &str) -> String {
        match name.to_ascii_lowercase().as_str() {
            "date" => "[TIMESTAMP]".to_string(),
            "x-request-id" | "x-trace-id" => "[ID]".to_string(),
            _ => value.to_string(),
        }
    }

    fn scrubbed_headers_snapshot(headers: &[(String, String)]) -> Vec<Value> {
        headers
            .iter()
            .map(|(name, value)| json!([name, scrub_snapshot_header_value(name, value)]))
            .collect()
    }

    fn request_response_builder_snapshot(request: &Request, response: &Response) -> Value {
        json!({
            "request": {
                "method": request.method.as_str(),
                "uri": request.uri,
                "version": request.version.as_str(),
                "headers": scrubbed_headers_snapshot(&request.headers),
                "trailers": scrubbed_headers_snapshot(&request.trailers),
                "peer_addr": request.peer_addr.map(|_| "[PEER_ADDR]"),
                "body_utf8": String::from_utf8_lossy(&request.body),
            },
            "response": {
                "status": response.status,
                "reason": response.reason,
                "version": response.version.as_str(),
                "headers": scrubbed_headers_snapshot(&response.headers),
                "trailers": scrubbed_headers_snapshot(&response.trailers),
                "body_utf8": String::from_utf8_lossy(&response.body),
            }
        })
    }

    #[test]
    fn method_roundtrip() {
        for (bytes, expected) in [
            (&b"GET"[..], Method::Get),
            (b"POST", Method::Post),
            (b"DELETE", Method::Delete),
            (b"PATCH", Method::Patch),
            (b"CUSTOM", Method::Extension("CUSTOM".into())),
        ] {
            let parsed = Method::from_bytes(bytes).unwrap();
            assert_eq!(parsed, expected);
            let reparsed = Method::from_bytes(parsed.as_str().as_bytes()).unwrap();
            assert_eq!(reparsed, expected);
        }
    }

    #[test]
    fn version_roundtrip() {
        assert_eq!(Version::from_bytes(b"HTTP/1.0"), Some(Version::Http10));
        assert_eq!(Version::from_bytes(b"HTTP/1.1"), Some(Version::Http11));
        assert_eq!(Version::from_bytes(b"HTTP/2"), None);
        assert_eq!(Version::Http11.as_str(), "HTTP/1.1");
    }

    #[test]
    fn response_builder() {
        let resp =
            Response::new(200, "OK", b"hello".to_vec()).with_header("Content-Type", "text/plain");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.body, b"hello");
        assert!(resp.trailers.is_empty());
    }

    #[test]
    fn default_reasons() {
        assert_eq!(default_reason(200), "OK");
        assert_eq!(default_reason(404), "Not Found");
        assert_eq!(default_reason(417), "Expectation Failed");
        assert_eq!(default_reason(499), "Client Closed Request");
        assert_eq!(default_reason(500), "Internal Server Error");
        assert_eq!(default_reason(999), "Unknown");
    }

    // Pure data-type tests (wave 12 – CyanBarn)

    #[test]
    fn method_display_all_standard() {
        assert_eq!(Method::Get.to_string(), "GET");
        assert_eq!(Method::Head.to_string(), "HEAD");
        assert_eq!(Method::Post.to_string(), "POST");
        assert_eq!(Method::Put.to_string(), "PUT");
        assert_eq!(Method::Delete.to_string(), "DELETE");
        assert_eq!(Method::Connect.to_string(), "CONNECT");
        assert_eq!(Method::Options.to_string(), "OPTIONS");
        assert_eq!(Method::Trace.to_string(), "TRACE");
        assert_eq!(Method::Patch.to_string(), "PATCH");
    }

    #[test]
    fn method_display_extension() {
        let ext = Method::Extension("PURGE".into());
        assert_eq!(ext.to_string(), "PURGE");
    }

    #[test]
    fn method_debug_clone_eq_hash() {
        use std::collections::HashSet;

        let m = Method::Get;
        let dbg = format!("{m:?}");
        assert_eq!(dbg, "GET");
        let cloned = m.clone();
        assert_eq!(m, cloned);

        let mut set = HashSet::new();
        set.insert(Method::Get);
        set.insert(Method::Post);
        set.insert(Method::Get);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn method_from_bytes_all_standard() {
        let methods = [
            (b"GET" as &[u8], Method::Get),
            (b"HEAD", Method::Head),
            (b"POST", Method::Post),
            (b"PUT", Method::Put),
            (b"DELETE", Method::Delete),
            (b"CONNECT", Method::Connect),
            (b"OPTIONS", Method::Options),
            (b"TRACE", Method::Trace),
            (b"PATCH", Method::Patch),
        ];
        for (bytes, expected) in methods {
            assert_eq!(Method::from_bytes(bytes), Some(expected));
        }
    }

    #[test]
    fn method_from_bytes_invalid_utf8() {
        // Invalid UTF-8 should return None (not an extension)
        assert!(Method::from_bytes(&[0xFF, 0xFE]).is_none());
    }

    #[test]
    fn method_from_bytes_accepts_rfc9110_tchar_extension_tokens() {
        let token =
            b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        let parsed = Method::from_bytes(token);

        assert_eq!(
            parsed,
            Some(Method::Extension(
                "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    .to_string()
            ))
        );
    }

    #[test]
    fn method_from_bytes_rejects_separator_and_control_tokens() {
        for invalid in [
            b"" as &[u8],
            b"GET POST",
            b"GET\tPOST",
            b"GET\r\nPOST",
            b"(GET)",
            b"<GET>",
            b"GET@POST",
            b"GET,POST",
            b"GET;POST",
            b"GET:POST",
            b"GET\\POST",
            b"GET\"POST",
            b"GET/POST",
            b"GET[POST]",
            b"GET?POST",
            b"GET=POST",
            b"GET{POST}",
            b"\0GET",
            b"GET\x7f",
        ] {
            assert!(
                Method::from_bytes(invalid).is_none(),
                "invalid method token must be rejected: {invalid:?}"
            );
        }
    }

    #[test]
    fn method_from_bytes_is_case_sensitive_for_registered_methods() {
        assert_eq!(Method::from_bytes(b"GET"), Some(Method::Get));
        assert_eq!(
            Method::from_bytes(b"get"),
            Some(Method::Extension("get".to_string()))
        );
    }

    #[test]
    fn method_inequality() {
        assert_ne!(Method::Get, Method::Post);
        assert_ne!(Method::Get, Method::Extension("GET".into()));
    }

    #[test]
    fn version_display() {
        assert_eq!(Version::Http10.to_string(), "HTTP/1.0");
        assert_eq!(Version::Http11.to_string(), "HTTP/1.1");
    }

    #[test]
    fn version_debug_copy_eq_hash() {
        use std::collections::HashSet;

        let v = Version::Http11;
        let dbg = format!("{v:?}");
        assert!(dbg.contains("Http11"));
        let copied = v;
        assert_eq!(v, copied);

        let mut set = HashSet::new();
        set.insert(Version::Http10);
        set.insert(Version::Http11);
        set.insert(Version::Http10);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn request_debug_clone() {
        let req = Request {
            method: Method::Get,
            uri: "/path".to_string(),
            version: Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: b"body".to_vec(),
            trailers: vec![],
            peer_addr: None,
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("GET"));
        assert!(dbg.contains("/path"));

        let cloned = req.clone();
        assert_eq!(cloned.method, Method::Get);
        assert_eq!(cloned.uri, "/path");
        assert_eq!(cloned.headers.len(), 1);
        assert_eq!(req.uri, cloned.uri);
    }

    #[test]
    fn request_with_peer_addr() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let req = Request {
            method: Method::Post,
            uri: "/api".to_string(),
            version: Version::Http11,
            headers: vec![],
            body: vec![],
            trailers: vec![],
            peer_addr: Some(addr),
        };
        assert_eq!(req.peer_addr, Some(addr));
    }

    #[test]
    fn request_builder_sets_fields() {
        let peer_addr: SocketAddr = "10.0.0.9:9000".parse().unwrap();
        let req = Request::builder(Method::Patch, "/v1/items/7")
            .version(Version::Http10)
            .header("Host", "example.com")
            .header("X-Trace-Id", "abc123")
            .body(b"payload".to_vec())
            .trailer("Checksum", "sha256:deadbeef")
            .peer_addr(peer_addr)
            .build();

        assert_eq!(req.method, Method::Patch);
        assert_eq!(req.uri, "/v1/items/7");
        assert_eq!(req.version, Version::Http10);
        assert_eq!(
            req.headers,
            vec![
                ("Host".to_string(), "example.com".to_string()),
                ("X-Trace-Id".to_string(), "abc123".to_string()),
            ]
        );
        assert_eq!(req.body, b"payload");
        assert_eq!(
            req.trailers,
            vec![("Checksum".to_string(), "sha256:deadbeef".to_string())]
        );
        assert_eq!(req.peer_addr, Some(peer_addr));
    }

    #[test]
    fn request_convenience_builders_use_expected_method() {
        let get_req = Request::get("/health").build();
        assert_eq!(get_req.method, Method::Get);
        assert_eq!(get_req.uri, "/health");
        assert_eq!(get_req.version, Version::Http11);

        let post_req = Request::post("/submit").build();
        assert_eq!(post_req.method, Method::Post);
        assert_eq!(post_req.uri, "/submit");
        assert_eq!(post_req.version, Version::Http11);

        let put_req = Request::put("/resource/1").build();
        assert_eq!(put_req.method, Method::Put);

        let delete_req = Request::delete("/resource/1").build();
        assert_eq!(delete_req.method, Method::Delete);
    }

    #[test]
    fn response_with_trailer() {
        let resp = Response::new(200, "OK", Vec::<u8>::new())
            .with_header("Transfer-Encoding", "chunked")
            .with_trailer("Checksum", "abc123");
        assert_eq!(resp.trailers.len(), 1);
        assert_eq!(resp.trailers[0].0, "Checksum");
        assert_eq!(resp.trailers[0].1, "abc123");
    }

    #[test]
    fn response_debug_clone() {
        let resp = Response::new(404, "Not Found", b"missing".to_vec());
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("404"));
        let cloned = resp;
        assert_eq!(cloned.status, 404);
        assert_eq!(cloned.reason, "Not Found");
    }

    #[test]
    fn response_defaults_version_http11() {
        let resp = Response::new(200, "OK", Vec::<u8>::new());
        assert_eq!(resp.version, Version::Http11);
    }

    #[test]
    fn response_builder_uses_default_reason_and_chainable_fields() {
        let resp = Response::builder(201)
            .header("Content-Type", "application/json")
            .body(br#"{"ok":true}"#.to_vec())
            .trailer("Checksum", "abc123")
            .build();

        assert_eq!(resp.version, Version::Http11);
        assert_eq!(resp.status, 201);
        assert_eq!(resp.reason, "Created");
        assert_eq!(
            resp.headers,
            vec![("Content-Type".to_string(), "application/json".to_string())]
        );
        assert_eq!(resp.body, br#"{"ok":true}"#);
        assert_eq!(
            resp.trailers,
            vec![("Checksum".to_string(), "abc123".to_string())]
        );
    }

    #[test]
    fn response_builder_status_resets_reason_unless_overridden_afterward() {
        let resp = Response::builder(200)
            .reason("Everything Fine")
            .status(404)
            .build();
        assert_eq!(resp.status, 404);
        assert_eq!(resp.reason, "Not Found");

        let resp_with_custom_reason = Response::builder(200)
            .status(503)
            .reason("Service Busy")
            .build();
        assert_eq!(resp_with_custom_reason.status, 503);
        assert_eq!(resp_with_custom_reason.reason, "Service Busy");
    }

    #[test]
    fn default_reason_all_known() {
        let known = [
            (100, "Continue"),
            (201, "Created"),
            (204, "No Content"),
            (301, "Moved Permanently"),
            (302, "Found"),
            (304, "Not Modified"),
            (400, "Bad Request"),
            (401, "Unauthorized"),
            (403, "Forbidden"),
            (405, "Method Not Allowed"),
            (408, "Request Timeout"),
            (411, "Length Required"),
            (413, "Payload Too Large"),
            (414, "URI Too Long"),
            (431, "Request Header Fields Too Large"),
            (499, "Client Closed Request"),
            (501, "Not Implemented"),
            (502, "Bad Gateway"),
            (503, "Service Unavailable"),
        ];
        for (code, expected) in known {
            assert_eq!(default_reason(code), expected, "code={code}");
        }
    }

    // ---- B.2 ergonomic builder tests ----

    #[test]
    fn status_code_constants_and_categories() {
        assert!(StatusCode::CONTINUE.is_informational());
        assert!(!StatusCode::CONTINUE.is_success());

        assert!(StatusCode::OK.is_success());
        assert!(StatusCode::CREATED.is_success());
        assert!(StatusCode::NO_CONTENT.is_success());

        assert!(StatusCode::MOVED_PERMANENTLY.is_redirection());
        assert!(StatusCode::TEMPORARY_REDIRECT.is_redirection());

        assert!(StatusCode::BAD_REQUEST.is_client_error());
        assert!(StatusCode::NOT_FOUND.is_client_error());
        assert!(StatusCode::TOO_MANY_REQUESTS.is_client_error());
        assert!(StatusCode::CLIENT_CLOSED_REQUEST.is_client_error());

        assert!(StatusCode::INTERNAL_SERVER_ERROR.is_server_error());
        assert!(StatusCode::SERVICE_UNAVAILABLE.is_server_error());
    }

    #[test]
    fn status_code_category_predicates_are_boundary_exclusive() {
        let cases = [
            (99, [false, false, false, false, false]),
            (100, [true, false, false, false, false]),
            (199, [true, false, false, false, false]),
            (200, [false, true, false, false, false]),
            (299, [false, true, false, false, false]),
            (300, [false, false, true, false, false]),
            (399, [false, false, true, false, false]),
            (400, [false, false, false, true, false]),
            (499, [false, false, false, true, false]),
            (500, [false, false, false, false, true]),
            (599, [false, false, false, false, true]),
            (600, [false, false, false, false, false]),
        ];

        for (raw, expected) in cases {
            let code = StatusCode(raw);
            let actual = [
                code.is_informational(),
                code.is_success(),
                code.is_redirection(),
                code.is_client_error(),
                code.is_server_error(),
            ];

            assert_eq!(actual, expected, "status category boundary for {raw}");
            assert!(
                actual.into_iter().filter(|matched| *matched).count() <= 1,
                "status code {raw} matched multiple categories"
            );
        }
    }

    #[test]
    fn status_code_conversion_and_display() {
        let code = StatusCode::from(404u16);
        assert_eq!(code.as_u16(), 404);
        assert_eq!(u16::from(code), 404);
        assert_eq!(code.to_string(), "404");
        assert_eq!(code.reason(), "Not Found");
    }

    #[test]
    fn status_code_equality_with_u16() {
        assert_eq!(StatusCode::OK, 200u16);
        assert_eq!(200u16, StatusCode::OK);
        assert_ne!(StatusCode::OK, 201u16);
    }

    #[test]
    fn status_code_ordering() {
        assert!(StatusCode::OK < StatusCode::NOT_FOUND);
        assert!(StatusCode::BAD_REQUEST < StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn request_head_patch_options_builders() {
        let head = Request::head("/resource").build();
        assert_eq!(head.method, Method::Head);

        let patch = Request::patch("/resource/1").build();
        assert_eq!(patch.method, Method::Patch);

        let options = Request::options("*").build();
        assert_eq!(options.method, Method::Options);
    }

    #[test]
    fn request_header_lookup_case_insensitive() {
        let req = Request::get("/")
            .header("Content-Type", "text/html")
            .header("X-Request-Id", "abc123")
            .build();

        assert_eq!(req.header_value("content-type"), Some("text/html"));
        assert_eq!(req.header_value("CONTENT-TYPE"), Some("text/html"));
        assert_eq!(req.header_value("Content-Type"), Some("text/html"));
        assert_eq!(req.content_type(), Some("text/html"));
        assert_eq!(req.header_value("x-request-id"), Some("abc123"));
        assert!(req.header_value("missing").is_none());
    }

    #[test]
    fn request_content_length() {
        let req = Request::post("/upload")
            .header("Content-Length", "1024")
            .build();
        assert_eq!(req.content_length(), Some(1024));

        let req_no_cl = Request::get("/").build();
        assert!(req_no_cl.content_length().is_none());
    }

    #[test]
    fn request_json_body() {
        #[derive(serde::Serialize)]
        struct Payload {
            name: String,
            age: u32,
        }
        let payload = Payload {
            name: "Alice".to_owned(),
            age: 30,
        };
        let req = Request::post("/api/users").json(&payload).unwrap().build();

        assert_eq!(req.content_type(), Some("application/json"));
        let body_str = std::str::from_utf8(&req.body).unwrap();
        assert!(body_str.contains("\"name\":\"Alice\""));
        assert!(body_str.contains("\"age\":30"));
    }

    #[test]
    fn request_form_body() {
        let req = Request::post("/login")
            .form([("user", "alice"), ("pass", "s3cret")])
            .build();

        assert_eq!(
            req.content_type(),
            Some("application/x-www-form-urlencoded")
        );
        let body = std::str::from_utf8(&req.body).unwrap();
        assert!(body.contains("user=alice"));
        assert!(body.contains("pass=s3cret"));
    }

    #[test]
    fn request_form_encodes_special_chars() {
        let req = Request::post("/search")
            .form([("q", "hello world"), ("tag", "a&b=c")])
            .build();
        let body = std::str::from_utf8(&req.body).unwrap();
        assert!(body.contains("q=hello%20world"));
        assert!(body.contains("tag=a%26b%3Dc"));
    }

    #[test]
    fn multipart_with_boundary_validates_input() {
        assert!(MultipartForm::with_boundary("safe-boundary_123").is_ok());
        assert!(MultipartForm::with_boundary("").is_err());
        assert!(MultipartForm::with_boundary("bad boundary").is_err());
    }

    #[test]
    fn multipart_form_encodes_text_and_file_parts() {
        let form = MultipartForm::with_boundary("test-boundary")
            .unwrap()
            .text("field", "value")
            .file("upload", "hello.txt", "text/plain", b"hello".to_vec());

        let body = String::from_utf8(form.to_body()).unwrap();
        assert!(body.contains("--test-boundary\r\n"));
        assert!(body.contains("Content-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n"));
        assert!(body.contains(
            "Content-Disposition: form-data; name=\"upload\"; filename=\"hello.txt\"\r\n"
        ));
        assert!(body.contains("Content-Type: text/plain\r\n\r\nhello\r\n"));
        assert!(body.ends_with("--test-boundary--\r\n"));
    }

    #[test]
    fn request_multipart_body_sets_content_type_and_body() {
        let form = MultipartForm::with_boundary("upload-boundary")
            .unwrap()
            .text("user", "alice");
        let req = Request::post("/upload").multipart(&form).build();

        assert_eq!(
            req.content_type(),
            Some("multipart/form-data; boundary=upload-boundary")
        );
        let body = String::from_utf8(req.body).unwrap();
        assert!(body.contains("name=\"user\"\r\n\r\nalice\r\n"));
        assert!(body.ends_with("--upload-boundary--\r\n"));
    }

    #[test]
    fn request_query_params() {
        let req = Request::get("/search")
            .query([("q", "rust async"), ("page", "1")])
            .build();
        assert!(req.uri.starts_with("/search?"));
        assert!(req.uri.contains("q=rust%20async"));
        assert!(req.uri.contains("page=1"));
    }

    #[test]
    fn request_query_appends_to_existing() {
        let req = Request::get("/search?limit=10")
            .query([("offset", "20")])
            .build();
        assert!(req.uri.contains("limit=10&offset=20"));
    }

    #[test]
    fn request_bearer_auth() {
        let req = Request::get("/api/me").bearer_auth("my-jwt-token").build();
        assert_eq!(
            req.header_value("authorization"),
            Some("Bearer my-jwt-token")
        );
    }

    #[test]
    fn request_basic_auth_with_password() {
        let req = Request::get("/api")
            .basic_auth("alice", Some("secret"))
            .build();
        let auth = req.header_value("authorization").unwrap();
        assert!(auth.starts_with("Basic "));
        // "alice:secret" => base64 "YWxpY2U6c2VjcmV0"
        assert_eq!(auth, "Basic YWxpY2U6c2VjcmV0");
    }

    #[test]
    fn request_basic_auth_without_password() {
        let req = Request::get("/api").basic_auth("alice", None).build();
        let auth = req.header_value("authorization").unwrap();
        // "alice:" => base64 "YWxpY2U6"
        assert_eq!(auth, "Basic YWxpY2U6");
    }

    #[test]
    fn request_basic_auth_matches_rfc7617_example() {
        let req = Request::get("/auth")
            .basic_auth("Aladdin", Some("open sesame"))
            .build();
        assert_eq!(
            req.header_value("authorization"),
            Some("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
        );
    }

    #[test]
    fn request_oauth_client_credentials_matches_rfc6749_example() {
        let req = Request::post("/token")
            .basic_auth("s6BhdRkqt3", Some("gX1fBat3bV"))
            .form([("grant_type", "client_credentials")])
            .build();

        assert_eq!(req.method, Method::Post);
        assert_eq!(req.uri, "/token");
        assert_eq!(
            req.header_value("authorization"),
            Some("Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW")
        );
        assert_eq!(
            req.content_type(),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(
            std::str::from_utf8(&req.body).unwrap(),
            "grant_type=client_credentials"
        );
    }

    #[test]
    fn request_pkce_s256_vector_matches_rfc7636_appendix_b() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        let authorize = Request::get("/authorize")
            .query([
                ("code_challenge", challenge),
                ("code_challenge_method", "S256"),
            ])
            .build();
        assert_eq!(
            authorize.uri,
            "/authorize?code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
        );

        let token_req = Request::post("/token") // ubs:ignore - test URL path
            .form([("code_verifier", verifier)])
            .build();
        assert_eq!(
            std::str::from_utf8(&token_req.body).unwrap(),
            "code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        );
    }

    #[test]
    fn request_token_introspection_matches_rfc7662_example() {
        let req = Request::post("/introspect")
            .accept("application/json")
            .basic_auth("s6BhdRkqt3", Some("gX1fBat3bV"))
            .form([
                ("token", "mF_9.B5f-4.1JqM"),
                ("token_type_hint", "access_token"),
            ])
            .build();

        assert_eq!(req.method, Method::Post);
        assert_eq!(req.uri, "/introspect");
        assert_eq!(req.header_value("accept"), Some("application/json"));
        assert_eq!(
            req.header_value("authorization"),
            Some("Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW")
        );
        assert_eq!(
            req.content_type(),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(
            std::str::from_utf8(&req.body).unwrap(),
            "token=mF_9.B5f-4.1JqM&token_type_hint=access_token"
        );
    }

    #[test]
    fn request_prefer_respond_async_matches_rfc7240_example() {
        let req = Request::post("/collection")
            .content_type("text/plain")
            .header("Prefer", "respond-async, wait=10")
            .body("{Data}")
            .build();

        assert_eq!(req.method, Method::Post);
        assert_eq!(req.uri, "/collection");
        assert_eq!(req.content_type(), Some("text/plain"));
        assert_eq!(req.header_value("prefer"), Some("respond-async, wait=10"));
        assert_eq!(std::str::from_utf8(&req.body).unwrap(), "{Data}");
    }

    #[test]
    fn request_patch_matches_rfc5789_simple_example() {
        let req = Request::patch("/file.txt")
            .header("Host", "www.example.com")
            .content_type("application/example")
            .header("If-Match", "\"e0023aa4e\"")
            .body("[description of changes]")
            .build();

        assert_eq!(req.method, Method::Patch);
        assert_eq!(req.uri, "/file.txt");
        assert_eq!(req.header_value("host"), Some("www.example.com"));
        assert_eq!(req.content_type(), Some("application/example"));
        assert_eq!(req.header_value("if-match"), Some("\"e0023aa4e\""));
        assert_eq!(
            std::str::from_utf8(&req.body).unwrap(),
            "[description of changes]"
        );
    }

    #[test]
    fn request_content_type_and_accept() {
        let req = Request::post("/api")
            .content_type("application/xml")
            .accept("text/html")
            .build();
        assert_eq!(req.content_type(), Some("application/xml"));
        assert_eq!(req.header_value("accept"), Some("text/html"));
    }

    #[test]
    fn response_status_category_helpers() {
        let ok = Response::new(200, "OK", Vec::<u8>::new());
        assert!(ok.is_success());
        assert!(!ok.is_client_error());
        assert!(!ok.is_server_error());
        assert!(!ok.is_redirection());

        let redirect = Response::new(301, "Moved", Vec::<u8>::new());
        assert!(redirect.is_redirection());

        let not_found = Response::new(404, "Not Found", Vec::<u8>::new());
        assert!(not_found.is_client_error());

        let error = Response::new(500, "ISE", Vec::<u8>::new());
        assert!(error.is_server_error());
    }

    #[test]
    fn response_text_and_bytes() {
        let resp = Response::new(200, "OK", b"hello world".to_vec());
        assert_eq!(resp.text().unwrap(), "hello world");
        assert_eq!(resp.bytes(), b"hello world");
    }

    #[test]
    fn response_text_invalid_utf8() {
        let resp = Response::new(200, "OK", vec![0xFF, 0xFE]);
        assert!(resp.text().is_err());
    }

    #[test]
    fn response_json_deserialization() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct User {
            name: String,
            age: u32,
        }
        let resp = Response::new(200, "OK", br#"{"name":"Bob","age":25}"#.to_vec());
        let user: User = resp.json().unwrap();
        assert_eq!(
            user,
            User {
                name: "Bob".to_owned(),
                age: 25
            }
        );
    }

    #[test]
    fn response_header_lookup_and_content_type() {
        let resp = Response::new(200, "OK", Vec::<u8>::new())
            .with_header("Content-Type", "application/json")
            .with_header("Content-Length", "42")
            .with_header("Location", "https://example.com/new");

        assert_eq!(resp.content_type(), Some("application/json"));
        assert_eq!(resp.content_length(), Some(42));
        assert_eq!(resp.location(), Some("https://example.com/new"));
        assert!(resp.header_value("missing").is_none());
    }

    #[test]
    fn response_status_code_typed() {
        let resp = Response::new(201, "Created", Vec::<u8>::new());
        let code = resp.status_code();
        assert_eq!(code, StatusCode::CREATED);
        assert!(code.is_success());
    }

    #[test]
    fn response_ok_convenience() {
        let resp = Response::ok();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.reason, "OK");
        assert!(resp.body.is_empty());
    }

    #[test]
    fn response_not_found_convenience() {
        let resp = Response::not_found();
        assert_eq!(resp.status, 404);
        assert_eq!(resp.reason, "Not Found");
    }

    #[test]
    fn response_json_response_convenience() {
        #[derive(serde::Serialize)]
        struct ApiResponse {
            ok: bool,
        }
        let resp = Response::json_response(200, &ApiResponse { ok: true }).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type(), Some("application/json"));
        assert!(resp.content_length().is_some());
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("\"ok\":true"));
    }

    #[test]
    fn percent_encode_preserves_unreserved() {
        assert_eq!(percent_encode("hello"), "hello");
        assert_eq!(percent_encode("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(percent_encode("ABC123"), "ABC123");
    }

    #[test]
    fn percent_encode_encodes_special_chars() {
        assert_eq!(percent_encode("hello world"), "hello%20world");
        assert_eq!(percent_encode("a=b&c"), "a%3Db%26c");
        assert_eq!(percent_encode("100%"), "100%25");
    }

    #[test]
    fn url_encode_params_basic() {
        let encoded = url_encode_params([("key", "value"), ("foo", "bar")]);
        assert_eq!(encoded, "key=value&foo=bar");
    }

    #[test]
    fn base64_encode_known_vectors() {
        // RFC 4648 test vectors
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_encode_credentials() {
        assert_eq!(base64_encode(b"alice:secret"), "YWxpY2U6c2VjcmV0");
        assert_eq!(base64_encode(b"alice:"), "YWxpY2U6");
    }

    #[test]
    fn request_response_builder_snapshot_scrubs_dynamic_headers() {
        let peer_addr: SocketAddr = "10.20.30.40:4567".parse().unwrap();
        let request = Request::post("/api/orders")
            .version(Version::Http10)
            .header("Date", "Sun, 20 Apr 2026 07:59:14 GMT")
            .header("X-Request-Id", "req-9f4c36b1-92a5-4d59-aac8-62a17f936827")
            .query([("page", "2"), ("cursor", "after:2026-04-20T07:59:14Z")])
            .json(&json!({
                "customer_id": "cust_123",
                "items": [
                    {"sku": "A-1", "qty": 2},
                    {"sku": "B-4", "qty": 1}
                ]
            }))
            .unwrap()
            .trailer("X-Trace-Id", "trace-2026-04-20T07:59:14Z")
            .peer_addr(peer_addr)
            .build();

        let response = Response::builder(202)
            .header("Date", "Sun, 20 Apr 2026 07:59:15 GMT")
            .header("X-Request-Id", "req-9f4c36b1-92a5-4d59-aac8-62a17f936827")
            .header("Location", "/api/orders/accepted/42")
            .body(br#"{"accepted":true,"batch":"batch-17"}"#.to_vec())
            .trailer("X-Trace-Id", "trace-2026-04-20T07:59:15Z")
            .build();

        insta::assert_json_snapshot!(
            "request_response_builder_scrubbed",
            request_response_builder_snapshot(&request, &response)
        );
    }

    mod streaming_multipart {
        use super::*;
        use crate::http::body::{Empty, HeaderMap};
        use crate::web::extract::FromRequest;
        use std::cell::{Cell, RefCell};
        use std::marker::PhantomPinned;
        use std::rc::Rc;
        use std::task::Waker;

        #[derive(Default)]
        struct Counts {
            polls: Cell<usize>,
            drops: Cell<usize>,
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
                    let advanced = count.min(segment.len());
                    count -= advanced;
                    if advanced < segment.len() {
                        self.0.push_front(&segment[advanced..]);
                    }
                }
            }
        }

        struct Source {
            frames: RefCell<VecDeque<Result<Frame<Segments>, &'static str>>>,
            exact: Option<u64>,
            first_pending: Cell<bool>,
            parked: bool,
            panic_on_drop: bool,
            counts: Rc<Counts>,
            _pinned: PhantomPinned,
        }

        impl Body for Source {
            type Data = Segments;
            type Error = &'static str;

            fn poll_frame(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
                let this = self.as_ref().get_ref();
                this.counts.polls.set(this.counts.polls.get() + 1);
                if this.parked {
                    return Poll::Pending;
                }
                if this.first_pending.replace(false) {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(this.frames.borrow_mut().pop_front())
            }

            fn size_hint(&self) -> SizeHint {
                self.exact.map_or_else(SizeHint::default, SizeHint::with_exact)
            }
        }

        impl Drop for Source {
            fn drop(&mut self) {
                self.counts.drops.set(self.counts.drops.get() + 1);
                assert!(!self.panic_on_drop, "deliberate producer destructor panic");
            }
        }

        fn data(segments: &[&'static [u8]]) -> Result<Frame<Segments>, &'static str> {
            Ok(Frame::Data(Segments(
                segments.iter().copied().collect(),
                PhantomPinned,
            )))
        }

        fn source(
            exact: Option<u64>,
            frames: Vec<Result<Frame<Segments>, &'static str>>,
        ) -> (Source, Rc<Counts>) {
            let counts = Rc::new(Counts::default());
            (
                Source {
                    frames: RefCell::new(frames.into()),
                    exact,
                    first_pending: Cell::new(false),
                    parked: false,
                    panic_on_drop: false,
                    counts: Rc::clone(&counts),
                    _pinned: PhantomPinned,
                },
                counts,
            )
        }

        fn collect<B: Body>(
            body: &mut MultipartBody<B>,
        ) -> (Vec<u8>, Option<MultipartBodyError>)
        where
            B::Error: fmt::Display,
        {
            let mut wire = Vec::new();
            let mut cx = Context::from_waker(Waker::noop());
            for _ in 0..10_000 {
                let before = body.size_hint().exact();
                match Pin::new(&mut *body).poll_frame(&mut cx) {
                    Poll::Ready(Some(Ok(Frame::Data(mut data)))) => {
                        if let Some(before) = before {
                            assert_eq!(
                                body.size_hint().exact(),
                                Some(before - data.remaining() as u64),
                                "exact size hint must include all remaining multipart syntax"
                            );
                        }
                        while data.has_remaining() {
                            let chunk = data.chunk();
                            assert!(!chunk.is_empty());
                            wire.extend_from_slice(chunk);
                            let count = chunk.len();
                            data.advance(count);
                        }
                    }
                    Poll::Ready(Some(Err(error))) => {
                        assert!(body.is_end_stream());
                        assert_eq!(body.size_hint().exact(), Some(0));
                        assert!(matches!(
                            Pin::new(&mut *body).poll_frame(&mut cx),
                            Poll::Ready(None)
                        ));
                        return (wire, Some(error));
                    }
                    Poll::Ready(None) => {
                        assert!(body.is_end_stream());
                        assert_eq!(body.size_hint().exact(), Some(0));
                        return (wire, None);
                    }
                    Poll::Ready(Some(Ok(Frame::Trailers(_)))) => {
                        panic!("multipart must never emit HTTP trailers");
                    }
                    Poll::Pending => {}
                }
            }
            panic!("multipart body did not terminate within its bounded test drive");
        }

        #[test]
        fn streaming_multipart_mixes_text_and_pinned_sources_without_collecting() {
            let (producer, counts) = source(Some(6), vec![data(&[b"ab", b"c"]), data(&[b"def"])]);
            producer.first_pending.set(true);
            let parts = [
                MultipartBodyPart::text("tag", "first"),
                MultipartBodyPart::text("tag", "second"),
                MultipartBodyPart::stream("file", producer)
                    .filename("data.bin")
                    .content_type("application/octet-stream"),
            ];
            let mut body = MultipartBody::with_boundary("upload: boundary", parts).unwrap();
            assert_eq!(counts.polls.get(), 0, "construction must not poll the source");
            assert_eq!(
                body.content_type_header(),
                "multipart/form-data; boundary=\"upload: boundary\""
            );
            let length = body.size_hint().exact().unwrap();
            let content_type = body.content_type_header();
            let (wire, error) = collect(&mut body);
            assert!(error.is_none(), "{error:?}");
            assert_eq!(wire.len() as u64, length);
            assert_eq!(counts.polls.get(), 4, "Pending, two DATA frames, actual EOF");
            assert_eq!(counts.drops.get(), 1);

            let request = crate::web::extract::Request::new("POST", "/upload")
                .with_header("content-type", content_type)
                .with_body(wire);
            let parsed = crate::web::multipart::Multipart::from_request(request).unwrap();
            let tags = parsed.fields_by_name("tag");
            assert_eq!(tags.len(), 2);
            assert_eq!(tags[0].text().unwrap(), "first");
            assert_eq!(tags[1].text().unwrap(), "second");
            let file = parsed.field("file").unwrap();
            assert_eq!(file.filename(), Some("data.bin"));
            assert_eq!(file.body().as_ref(), b"abcdef");
        }

        #[test]
        fn streaming_multipart_wire_matches_legacy_for_equivalent_known_parts() {
            let expected = MultipartForm::with_boundary("wire-compatible")
                .unwrap()
                .text("tag", "value")
                .file("f\"ield", "fi\\le.txt", "text/plain", b"file-data".to_vec())
                .to_body();
            let mut body = MultipartBody::with_boundary(
                "wire-compatible",
                [
                    MultipartBodyPart::text("tag", "value"),
                    MultipartBodyPart::stream("f\"ield", Bytes::from_static(b"file-data"))
                        .filename("fi\\le.txt")
                        .content_type("text/plain"),
                ],
            )
            .unwrap();
            assert_eq!(body.size_hint().exact(), Some(expected.len() as u64));
            let (wire, error) = collect(&mut body);
            assert!(error.is_none());
            assert_eq!(wire, expected);
        }

        #[test]
        fn streaming_multipart_preserves_the_original_segmented_payload() {
            static FIRST: &[u8] = b"ab";
            let (producer, counts) = source(Some(5), vec![data(&[FIRST, b"cde"])]);
            let mut body = MultipartBody::with_boundary(
                "B",
                [MultipartBodyPart::stream("file", producer)],
            )
            .unwrap();
            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(
                Pin::new(&mut body).poll_frame(&mut cx),
                Poll::Ready(Some(Ok(Frame::Data(MultipartChunk::Framing(_)))))
            ));
            assert_eq!(counts.polls.get(), 0);
            let Poll::Ready(Some(Ok(Frame::Data(MultipartChunk::Payload(mut data))))) =
                Pin::new(&mut body).poll_frame(&mut cx)
            else {
                panic!("streaming DATA must retain the producer's buffer type");
            };
            assert_eq!(data.remaining(), 5);
            assert_eq!(data.chunk(), b"ab");
            assert_eq!(data.chunk().as_ptr(), FIRST.as_ptr());
            data.advance(2);
            assert_eq!(data.chunk(), b"cde");
            assert_eq!(counts.polls.get(), 1, "no next-frame prefetch");
            drop(body);
            assert_eq!(counts.drops.get(), 1);
        }

        #[test]
        fn streaming_multipart_empty_forms_and_fields_have_exact_framing() {
            let mut empty = MultipartBody::<Empty>::with_boundary("B", []).unwrap();
            assert_eq!(empty.size_hint().exact(), Some(7));
            let (wire, error) = collect(&mut empty);
            assert!(error.is_none());
            assert_eq!(wire, b"--B--\r\n");

            let mut fields = MultipartBody::<Empty>::with_boundary(
                "B",
                [
                    MultipartBodyPart::text("one", ""),
                    MultipartBodyPart::bytes("two", Bytes::new()),
                    MultipartBodyPart::stream("three", Empty::new()),
                ],
            )
            .unwrap();
            let length = fields.size_hint().exact().unwrap();
            let (wire, error) = collect(&mut fields);
            assert!(error.is_none());
            assert_eq!(wire.len() as u64, length);
            assert_eq!(
                wire,
                b"--B\r\nContent-Disposition: form-data; name=\"one\"\r\n\r\n\r\n--B\r\nContent-Disposition: form-data; name=\"two\"\r\n\r\n\r\n--B\r\nContent-Disposition: form-data; name=\"three\"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n--B--\r\n"
            );
        }

        #[test]
        fn streaming_multipart_unknown_or_overflowing_aggregate_has_no_exact_hint() {
            let (producer, _) = source(None, vec![data(&[b"abc"])]);
            let mut body = MultipartBody::with_boundary(
                "B",
                [MultipartBodyPart::stream("file", producer)],
            )
            .unwrap();
            assert_eq!(body.size_hint().exact(), None);
            let (wire, error) = collect(&mut body);
            assert!(error.is_none());
            assert!(wire.ends_with(b"abc\r\n--B--\r\n"));

            let (producer, counts) = source(Some(u64::MAX), vec![]);
            let body = MultipartBody::with_boundary(
                "B",
                [MultipartBodyPart::stream("huge", producer)],
            )
            .unwrap();
            assert_eq!(body.size_hint().exact(), None, "framing addition must not wrap");
            assert_eq!(counts.polls.get(), 0);
        }

        #[test]
        fn streaming_multipart_explicit_length_overrides_the_source_hint() {
            let (producer, counts) = source(Some(999), vec![data(&[b"abc"])]);
            let mut body = MultipartBody::with_boundary(
                "B",
                [MultipartBodyPart::stream("file", producer).with_length(3)],
            )
            .unwrap();
            let length = body.size_hint().exact().unwrap();
            let (wire, error) = collect(&mut body);
            assert!(error.is_none());
            assert_eq!(wire.len() as u64, length);
            assert!(wire.ends_with(b"abc\r\n--B--\r\n"));
            assert_eq!(counts.polls.get(), 2, "actual EOF must be observed");
        }

        #[test]
        fn streaming_multipart_length_errors_never_emit_the_closing_boundary() {
            for (exact, frames, suffix) in [
                (4, vec![data(&[b"abc"])], &b"abc"[..]),
                (2, vec![data(&[b"abc"])], &b"\r\n\r\n"[..]),
                (3, vec![data(&[b"abc"]), data(&[b"extra"])], &b"abc"[..]),
            ] {
                let (producer, counts) = source(Some(exact), frames);
                let (queued, queued_counts) = source(Some(0), vec![]);
                let mut body = MultipartBody::with_boundary(
                    "B",
                    [
                        MultipartBodyPart::stream("first", producer),
                        MultipartBodyPart::stream("queued", queued),
                    ],
                )
                .unwrap();
                let (wire, error) = collect(&mut body);
                assert_eq!(error, Some(MultipartBodyError::LengthMismatch));
                assert!(wire.ends_with(suffix));
                assert!(!wire.ends_with(b"--B--\r\n"));
                assert!(!wire.windows(5).any(|part| part == b"extra"));
                assert_eq!(counts.drops.get(), 1);
                assert_eq!(queued_counts.polls.get(), 0);
                assert_eq!(queued_counts.drops.get(), 1, "queued producer must drop on failure");
            }
        }

        #[test]
        fn streaming_multipart_source_errors_and_trailers_are_terminal() {
            for (frame, expected) in [
                (
                    Err("source failed"),
                    MultipartBodyError::Producer("source failed".to_owned()),
                ),
                (
                    Ok(Frame::Trailers(HeaderMap::new())),
                    MultipartBodyError::TrailersNotAllowed,
                ),
            ] {
                let (producer, counts) = source(None, vec![data(&[b"abc"]), frame]);
                let (queued, queued_counts) = source(None, vec![]);
                let mut body = MultipartBody::with_boundary(
                    "B",
                    [
                        MultipartBodyPart::stream("first", producer),
                        MultipartBodyPart::stream("second", queued),
                    ],
                )
                .unwrap();
                let (wire, error) = collect(&mut body);
                assert_eq!(error, Some(expected));
                assert!(wire.ends_with(b"abc"));
                assert!(!wire.ends_with(b"--B--\r\n"));
                assert_eq!(counts.drops.get(), 1);
                assert_eq!(queued_counts.polls.get(), 0);
                assert_eq!(queued_counts.drops.get(), 1);
            }
        }

        #[test]
        fn streaming_multipart_pending_and_drop_do_not_poll_later_parts() {
            let (mut producer, counts) = source(None, vec![]);
            producer.parked = true;
            let (queued, queued_counts) = source(None, vec![]);
            let mut body = MultipartBody::with_boundary(
                "B",
                [
                    MultipartBodyPart::stream("first", producer),
                    MultipartBodyPart::stream("second", queued),
                ],
            )
            .unwrap();
            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(
                Pin::new(&mut body).poll_frame(&mut cx),
                Poll::Ready(Some(Ok(Frame::Data(_))))
            ));
            assert_eq!(counts.polls.get(), 0);
            assert!(Pin::new(&mut body).poll_frame(&mut cx).is_pending());
            assert_eq!(counts.polls.get(), 1);
            assert_eq!(queued_counts.polls.get(), 0);
            drop(body);
            assert_eq!(counts.drops.get(), 1);
            assert_eq!(queued_counts.drops.get(), 1);
        }

        #[test]
        fn streaming_multipart_destructor_panic_leaves_terminal_ownership() {
            for fails in [false, true] {
                let frames = if fails { vec![Err("source failed")] } else { vec![] };
                let (mut producer, counts) = source(None, frames);
                producer.panic_on_drop = true;
                let (queued, queued_counts) = source(None, vec![]);
                let mut body = MultipartBody::with_boundary(
                    "B",
                    [
                        MultipartBodyPart::stream("first", producer),
                        MultipartBodyPart::stream("queued", queued),
                    ],
                )
                .unwrap();
                let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    collect(&mut body)
                }));
                assert!(panic.is_err());
                assert!(body.is_end_stream());
                assert_eq!(body.size_hint().exact(), Some(0));
                let mut cx = Context::from_waker(Waker::noop());
                assert!(matches!(
                    Pin::new(&mut body).poll_frame(&mut cx),
                    Poll::Ready(None)
                ));
                assert_eq!(counts.drops.get(), 1);
                assert_eq!(queued_counts.polls.get(), 0);
                assert_eq!(queued_counts.drops.get(), 1);
            }
        }

        #[test]
        fn streaming_multipart_empty_ready_frames_yield_bounded_work() {
            let frames = (0..100).map(|_| data(&[])).collect();
            let (producer, counts) = source(None, frames);
            let mut body = MultipartBody::with_boundary(
                "B",
                [MultipartBodyPart::stream("file", producer)],
            )
            .unwrap();
            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(
                Pin::new(&mut body).poll_frame(&mut cx),
                Poll::Ready(Some(Ok(Frame::Data(_))))
            ));
            assert!(Pin::new(&mut body).poll_frame(&mut cx).is_pending());
            assert_eq!(counts.polls.get(), 32);
            let (_, error) = collect(&mut body);
            assert!(error.is_none());
            assert_eq!(counts.polls.get(), 101);
        }

        #[test]
        fn streaming_multipart_refuses_invalid_metadata_before_polling_sources() {
            for (name, filename, content_type) in [
                ("bad\r\nname", None, None),
                ("file", Some("bad\0name"), None),
                ("file", None, Some("text/plain\r\nInjected: yes")),
                ("file", None, Some(" \t")),
                ("bad\u{7f}name", None, None),
            ] {
                let (producer, counts) = source(None, vec![]);
                let mut part = MultipartBodyPart::stream(name, producer);
                if let Some(filename) = filename {
                    part = part.filename(filename);
                }
                if let Some(content_type) = content_type {
                    part = part.content_type(content_type);
                }
                let error = MultipartBody::with_boundary("B", [part]).unwrap_err();
                assert!(matches!(error, MultipartBodyError::InvalidMetadata { .. }));
                assert_eq!(counts.polls.get(), 0);
                assert_eq!(counts.drops.get(), 1);
            }

            let (producer, counts) = source(None, vec![]);
            let error = MultipartBody::with_boundary(
                "B",
                [MultipartBodyPart::stream("\"".repeat(MULTIPART_STREAM_HEADER_LIMIT / 2), producer)],
            )
            .unwrap_err();
            assert!(matches!(error, MultipartBodyError::HeaderTooLarge { .. }));
            assert_eq!(counts.polls.get(), 0);
            assert_eq!(counts.drops.get(), 1);
        }

        #[test]
        fn streaming_multipart_validates_boundary_and_escapes_quoted_parameters() {
            for boundary in ["", "bad\r\n", "bad\"quote", "bad\\slash", "trailing "] {
                assert!(matches!(
                    MultipartBody::<Empty>::with_boundary(boundary, []),
                    Err(MultipartBodyError::InvalidBoundary)
                ));
            }
            assert!(MultipartBody::<Empty>::with_boundary("a".repeat(70), []).is_ok());
            assert!(MultipartBody::<Empty>::with_boundary("a".repeat(71), []).is_err());
            let mut body = MultipartBody::<Empty>::with_boundary(
                "b:() ?",
                [MultipartBodyPart::text("a\"b\\c", "text").filename("x\"y\\z")],
            )
            .unwrap();
            assert_eq!(body.content_type_header(), "multipart/form-data; boundary=\"b:() ?\"");
            let (wire, error) = collect(&mut body);
            assert!(error.is_none());
            let text = String::from_utf8(wire).unwrap();
            assert!(text.contains("name=\"a\\\"b\\\\c\"; filename=\"x\\\"y\\\\z\"\r\n"));
            assert!(text.contains("Content-Type: application/octet-stream\r\n"));
            assert!(!text.contains("filename*="));
        }
    }
