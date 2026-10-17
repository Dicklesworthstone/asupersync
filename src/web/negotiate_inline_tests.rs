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

    impl<H: Handler> ErrorHandlerMiddleware<H> {
        fn call(&self, req: Request) -> Response {
            futures_lite::future::block_on(Handler::call(self, &crate::Cx::for_testing(), req))
        }
    }

    fn make_request() -> Request {
        Request::new("GET", "/test")
    }

    fn make_request_accepting(accept: &str) -> Request {
        Request::new("GET", "/test").with_header("accept", accept)
    }

    fn ok_handler() -> &'static str {
        "ok"
    }

    fn panicking_handler() -> &'static str {
        panic!("test panic");
    }

    struct ConstructionPanicHandler;

    impl Handler for ConstructionPanicHandler {
        fn call(
            &self,
            _cx: &crate::Cx,
            _req: Request,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            panic!("construction panic");
        }
    }

    fn not_found_handler() -> StatusCode {
        StatusCode::NOT_FOUND
    }

    fn detailed_bad_request_handler() -> Response {
        Response::new(StatusCode::BAD_REQUEST, b"missing tenant\nline 2".to_vec())
            .header("x-request-id", "req-123")
            .header("content-type", "text/plain; charset=utf-8")
    }

    fn stale_representation_headers_handler() -> Response {
        Response::new(StatusCode::BAD_REQUEST, b"old body".to_vec())
            .header("content-length", "8")
            .header("content-encoding", "gzip")
            .header("etag", "\"old-body\"")
            .header("x-request-id", "req-456")
    }

    // ====================================================================
    // Media type parsing tests
    // ====================================================================

    #[test]
    fn parse_simple_accept() {
        let types = parse_accept("text/html, application/json");
        assert_eq!(types.len(), 2);
        assert_eq!(types[0].r#type, "text");
        assert_eq!(types[0].subtype, "html");
        assert_eq!(types[1].r#type, "application");
        assert_eq!(types[1].subtype, "json");
    }

    #[test]
    fn parse_accept_with_quality() {
        let types = parse_accept("text/html;q=1.0, application/json;q=0.9, */*;q=0.1");
        assert_eq!(types.len(), 3);
        assert!((types[0].quality - 1.0).abs() < f32::EPSILON);
        assert!((types[1].quality - 0.9).abs() < f32::EPSILON);
        assert!((types[2].quality - 0.1).abs() < f32::EPSILON);
    }

    #[test]
    fn parse_accept_empty() {
        let types = parse_accept("");
        assert!(types.is_empty());
    }

    #[test]
    fn parse_accept_with_params() {
        let types = parse_accept("text/html; charset=utf-8; q=0.8");
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].r#type, "text");
        assert!((types[0].quality - 0.8).abs() < f32::EPSILON);
    }

    // ====================================================================
    // Media type matching tests
    // ====================================================================

    #[test]
    fn media_type_exact_match() {
        let mt = MediaType::new("text", "html");
        assert!(mt.matches("text", "html"));
        assert!(!mt.matches("text", "plain"));
    }

    #[test]
    fn media_type_wildcard_subtype() {
        let mt = MediaType::new("text", "*");
        assert!(mt.matches("text", "html"));
        assert!(mt.matches("text", "plain"));
        assert!(!mt.matches("application", "json"));
    }

    #[test]
    fn media_type_full_wildcard() {
        let mt = MediaType::new("*", "*");
        assert!(mt.matches("text", "html"));
        assert!(mt.matches("application", "json"));
    }

    // ====================================================================
    // Negotiation tests
    // ====================================================================

    #[test]
    fn negotiate_exact_match() {
        let result = negotiate_media_type("application/json", &["text/html", "application/json"]);
        assert_eq!(result, Some("application/json"));
    }

    #[test]
    fn negotiate_quality_preference() {
        let result = negotiate_media_type(
            "text/html;q=0.5, application/json;q=1.0",
            &["text/html", "application/json"],
        );
        assert_eq!(result, Some("application/json"));
    }

    #[test]
    fn negotiate_wildcard() {
        let result = negotiate_media_type("*/*", &["application/json"]);
        assert_eq!(result, Some("application/json"));
    }

    #[test]
    fn negotiate_no_match() {
        let result = negotiate_media_type("text/xml", &["application/json", "text/html"]);
        assert_eq!(result, None);
    }

    #[test]
    fn negotiate_empty_accept() {
        let result = negotiate_media_type("", &["application/json"]);
        assert_eq!(result, Some("application/json"));
    }

    #[test]
    fn negotiate_blank_accept_uses_server_default() {
        let result = negotiate_media_type("   \t\r\n", &["application/json", "text/html"]);
        assert_eq!(result, Some("application/json"));
    }

    #[test]
    fn negotiate_client_accept_order_breaks_equal_quality_tie() {
        let result = negotiate_media_type(
            "text/html, application/json",
            &["application/json", "text/html"],
        );
        // Both media types are equally acceptable, so client accept order wins.
        assert_eq!(result, Some("text/html"));
    }

    #[test]
    fn negotiate_server_order_breaks_equal_wildcard_tie() {
        let result = negotiate_media_type("*/*", &["application/json", "text/html"]);
        assert_eq!(
            result,
            Some("application/json"),
            "when the client offers only a wildcard, server order should be the final fallback"
        );
    }

    #[test]
    fn negotiate_exact_rejection_overrides_broader_wildcard_match() {
        let result = negotiate_media_type(
            "application/*;q=1.0, application/json;q=0, text/html;q=0.5",
            &["application/json", "text/html"],
        );
        assert_eq!(
            result,
            Some("text/html"),
            "an exact q=0 rejection must outrank a broader application/* wildcard"
        );
    }

    #[test]
    fn negotiate_invalid_quality_does_not_default_to_full_preference() {
        let result = negotiate_media_type(
            "application/json;q=bogus, text/plain;q=0.5",
            &["application/json", "text/plain"],
        );
        assert_eq!(
            result,
            Some("text/plain"),
            "invalid q values should not silently promote a media range to q=1.0"
        );
    }

    // ====================================================================
    // Error formatting tests
    // ====================================================================

    #[test]
    fn format_error_json() {
        let (body, ct) = format_error_body(StatusCode::NOT_FOUND, "Not Found", ErrorFormat::Json);
        assert!(body.contains("404"));
        assert!(body.contains("Not Found"));
        assert_eq!(ct, "application/json");
    }

    #[test]
    fn format_error_html() {
        let (body, ct) = format_error_body(StatusCode::NOT_FOUND, "Not Found", ErrorFormat::Html);
        assert!(body.contains("<html>"));
        assert!(body.contains("404"));
        assert_eq!(ct, "text/html; charset=utf-8");
    }

    #[test]
    fn format_error_plain() {
        let (body, ct) = format_error_body(StatusCode::NOT_FOUND, "Not Found", ErrorFormat::Plain);
        assert_eq!(body, "404: Not Found");
        assert_eq!(ct, "text/plain; charset=utf-8");
    }

    #[test]
    fn format_error_json_escapes_quotes() {
        let (body, _) =
            format_error_body(StatusCode::BAD_REQUEST, "bad \"input\"", ErrorFormat::Json);
        assert!(body.contains(r#"bad \"input\""#));
    }

    #[test]
    fn format_error_json_escapes_control_characters() {
        let (body, _) = format_error_body(
            StatusCode::BAD_REQUEST,
            "bad \"input\"\nwith\ttabs",
            ErrorFormat::Json,
        );
        assert!(body.contains(r#"bad \"input\"\nwith\ttabs"#));
    }

    #[test]
    fn error_format_from_accept_json() {
        assert_eq!(
            error_format_from_accept("application/json"),
            ErrorFormat::Json
        );
    }

    #[test]
    fn error_format_from_accept_html() {
        assert_eq!(error_format_from_accept("text/html"), ErrorFormat::Html);
    }

    #[test]
    fn error_format_from_accept_default_json() {
        assert_eq!(error_format_from_accept(""), ErrorFormat::Json);
    }

    #[test]
    fn error_format_from_blank_accept_defaults_json() {
        assert_eq!(error_format_from_accept("   \t\r\n"), ErrorFormat::Json);
    }

    #[test]
    fn error_format_from_accept_respects_specific_json_rejection() {
        assert_eq!(
            error_format_from_accept("application/*;q=1.0, application/json;q=0, text/html;q=0.5"),
            ErrorFormat::Html,
            "error format negotiation must not choose JSON after an exact JSON rejection"
        );
    }

    // ====================================================================
    // ErrorHandlerMiddleware tests
    // ====================================================================

    #[test]
    fn error_handler_passes_through_ok() {
        let mw =
            ErrorHandlerMiddleware::new(FnHandler::new(ok_handler), ErrorHandlerConfig::default());
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn error_handler_catches_panic() {
        let mw = ErrorHandlerMiddleware::new(
            FnHandler::new(panicking_handler),
            ErrorHandlerConfig::default(),
        );
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn error_handler_catches_construction_panic() {
        let mw =
            ErrorHandlerMiddleware::new(ConstructionPanicHandler, ErrorHandlerConfig::default());
        let resp = mw.call(make_request());
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn error_handler_disabled_propagates_construction_panic() {
        let mw = ErrorHandlerMiddleware::new(
            ConstructionPanicHandler,
            ErrorHandlerConfig {
                catch_panics: false,
                ..ErrorHandlerConfig::default()
            },
        );
        let panic = std::panic::catch_unwind(AssertUnwindSafe(|| mw.call(make_request())));
        assert!(panic.is_err());
    }

    #[test]
    fn error_handler_panic_json_response() {
        let mw = ErrorHandlerMiddleware::new(
            FnHandler::new(panicking_handler),
            ErrorHandlerConfig::default(),
        );
        let resp = mw.call(make_request_accepting("application/json"));
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "application/json"
        );
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("500"));
    }

    #[test]
    fn error_handler_panic_html_response() {
        let mw = ErrorHandlerMiddleware::new(
            FnHandler::new(panicking_handler),
            ErrorHandlerConfig::default(),
        );
        let resp = mw.call(make_request_accepting("text/html"));
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/html; charset=utf-8"
        );
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("<html>"));
    }

    #[test]
    fn error_handler_hides_details_by_default() {
        let mw = ErrorHandlerMiddleware::new(
            FnHandler::new(panicking_handler),
            ErrorHandlerConfig::default(),
        );
        let resp = mw.call(make_request_accepting("text/plain"));
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(!body.contains("panicked"));
        assert!(body.contains("Internal Server Error"));
    }

    #[test]
    fn error_handler_exposes_details_in_dev() {
        let mw = ErrorHandlerMiddleware::new(
            FnHandler::new(panicking_handler),
            ErrorHandlerConfig::development(),
        );
        let resp = mw.call(make_request_accepting("text/plain"));
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("panicked"));
    }

    #[test]
    fn error_handler_formats_client_errors_using_accept_header() {
        let mw = ErrorHandlerMiddleware::new(
            FnHandler::new(not_found_handler),
            ErrorHandlerConfig::default(),
        );
        let resp = mw.call(make_request_accepting("application/json"));
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "application/json"
        );
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("\"status\":404"));
        assert!(body.contains("Not Found"));
    }

    #[test]
    fn error_handler_preserves_non_content_headers_when_formatting_errors() {
        let mw = ErrorHandlerMiddleware::new(
            FnHandler::new(detailed_bad_request_handler),
            ErrorHandlerConfig::default(),
        );
        let resp = mw.call(make_request_accepting("text/html"));
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
        assert_eq!(resp.headers.get("x-request-id").unwrap(), "req-123");
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/html; charset=utf-8"
        );
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("<html>"));
        assert!(body.contains("400"));
        assert!(!body.contains("missing tenant"));
    }

    #[test]
    fn error_handler_removes_stale_representation_headers_when_rewriting_body() {
        let mw = ErrorHandlerMiddleware::new(
            FnHandler::new(stale_representation_headers_handler),
            ErrorHandlerConfig::default(),
        );
        let resp = mw.call(make_request_accepting("application/json"));

        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
        assert_eq!(resp.headers.get("x-request-id").unwrap(), "req-456");
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "application/json"
        );
        assert!(!resp.headers.contains_key("content-length"));
        assert!(!resp.headers.contains_key("content-encoding"));
        assert!(!resp.headers.contains_key("etag"));
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("\"status\":400"));
        assert!(body.contains("Bad Request"));
    }

    #[test]
    fn error_handler_exposes_existing_error_details_in_development() {
        let mw = ErrorHandlerMiddleware::new(
            FnHandler::new(detailed_bad_request_handler),
            ErrorHandlerConfig::development(),
        );
        let resp = mw.call(make_request_accepting("application/json"));
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains(r"missing tenant\nline 2"));
    }

    #[test]
    fn error_handler_config_default() {
        let cfg = ErrorHandlerConfig::default();
        assert!(cfg.catch_panics);
        assert!(!cfg.expose_details);
    }

    #[test]
    fn error_handler_config_development() {
        let cfg = ErrorHandlerConfig::development();
        assert!(cfg.catch_panics);
        assert!(cfg.expose_details);
    }
