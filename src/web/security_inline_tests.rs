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

    impl<H: Handler> SecurityHeadersMiddleware<H> {
        fn call(&self, req: Request) -> Response {
            futures_lite::future::block_on(Handler::call(self, &crate::Cx::for_testing(), req))
        }
    }

    fn ok_handler() -> &'static str {
        "ok"
    }

    fn make_request() -> Request {
        Request::new("GET", "/test")
    }

    fn handler_with_server_header() -> Response {
        Response::new(StatusCode::OK, b"ok".to_vec()).header("server", "asupersync/0.2.6")
    }

    fn handler_with_mixed_case_server_header() -> Response {
        let mut resp = Response::new(StatusCode::OK, b"ok".to_vec());
        resp.headers
            .insert("Server".to_string(), "asupersync/0.2.6".to_string());
        resp
    }

    fn handler_with_existing_headers() -> Response {
        Response::new(StatusCode::OK, b"ok".to_vec())
            .header("x-frame-options", "SAMEORIGIN")
            .header("referrer-policy", "no-referrer")
    }

    fn handler_with_mixed_case_existing_headers() -> Response {
        let mut resp = Response::new(StatusCode::OK, b"ok".to_vec());
        resp.headers
            .insert("X-Frame-Options".to_string(), "SAMEORIGIN".to_string());
        resp.headers
            .insert("Referrer-Policy".to_string(), "no-referrer".to_string());
        resp
    }

    // --- Default policy ---

    #[test]
    fn default_policy_sets_standard_headers() {
        let mw =
            SecurityHeadersMiddleware::new(FnHandler::new(ok_handler), SecurityPolicy::default());
        let resp = mw.call(make_request());

        assert_eq!(
            resp.headers.get("x-content-type-options").unwrap(),
            "nosniff"
        );
        assert_eq!(resp.headers.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(
            resp.headers.get("referrer-policy").unwrap(),
            "strict-origin-when-cross-origin"
        );
        assert_eq!(
            resp.headers.get("strict-transport-security").unwrap(),
            "max-age=31536000; includeSubDomains"
        );
    }

    #[test]
    fn default_policy_sets_safe_csp_but_no_permissions() {
        let mw =
            SecurityHeadersMiddleware::new(FnHandler::new(ok_handler), SecurityPolicy::default());
        let resp = mw.call(make_request());

        assert_eq!(
            resp.headers.get("content-security-policy").unwrap(),
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'"
        );
        assert!(!resp.headers.contains_key("permissions-policy"));
    }

    #[test]
    fn default_policy_removes_server_header() {
        let mw = SecurityHeadersMiddleware::new(
            FnHandler::new(handler_with_server_header),
            SecurityPolicy::default(),
        );
        let resp = mw.call(make_request());

        assert!(!resp.headers.contains_key("server"));
    }

    #[test]
    fn default_policy_removes_mixed_case_server_header() {
        let mw = SecurityHeadersMiddleware::new(
            FnHandler::new(handler_with_mixed_case_server_header),
            SecurityPolicy::default(),
        );
        let resp = mw.call(make_request());

        assert!(!resp.headers.contains_key("server"));
        assert!(!resp.headers.contains_key("Server"));
    }

    // --- Custom policy ---

    #[test]
    fn custom_csp_applied() {
        let policy = SecurityPolicy::default().with_csp("default-src 'self'");
        let mw = SecurityHeadersMiddleware::new(FnHandler::new(ok_handler), policy);
        let resp = mw.call(make_request());

        assert_eq!(
            resp.headers.get("content-security-policy").unwrap(),
            "default-src 'self'"
        );
    }

    #[test]
    fn custom_permissions_policy_applied() {
        let policy = SecurityPolicy::default().with_permissions_policy("camera=(), microphone=()");
        let mw = SecurityHeadersMiddleware::new(FnHandler::new(ok_handler), policy);
        let resp = mw.call(make_request());

        assert_eq!(
            resp.headers.get("permissions-policy").unwrap(),
            "camera=(), microphone=()"
        );
    }

    #[test]
    fn custom_frame_options() {
        let policy = SecurityPolicy::default().with_frame_options("SAMEORIGIN");
        let mw = SecurityHeadersMiddleware::new(FnHandler::new(ok_handler), policy);
        let resp = mw.call(make_request());

        assert_eq!(resp.headers.get("x-frame-options").unwrap(), "SAMEORIGIN");
    }

    #[test]
    fn without_hsts() {
        let policy = SecurityPolicy::default().without_hsts();
        let mw = SecurityHeadersMiddleware::new(FnHandler::new(ok_handler), policy);
        let resp = mw.call(make_request());

        assert!(!resp.headers.contains_key("strict-transport-security"));
    }

    // --- No-overwrite behavior ---

    #[test]
    fn does_not_overwrite_existing_headers() {
        let mw = SecurityHeadersMiddleware::new(
            FnHandler::new(handler_with_existing_headers),
            SecurityPolicy::default(),
        );
        let resp = mw.call(make_request());

        // Existing headers should be preserved, not overwritten.
        assert_eq!(resp.headers.get("x-frame-options").unwrap(), "SAMEORIGIN");
        assert_eq!(resp.headers.get("referrer-policy").unwrap(), "no-referrer");

        // Headers not set by the handler should be added.
        assert_eq!(
            resp.headers.get("x-content-type-options").unwrap(),
            "nosniff"
        );
    }

    #[test]
    fn canonicalizes_existing_mixed_case_headers_without_overwriting_values() {
        let mw = SecurityHeadersMiddleware::new(
            FnHandler::new(handler_with_mixed_case_existing_headers),
            SecurityPolicy::default(),
        );
        let resp = mw.call(make_request());

        assert_eq!(resp.headers.get("x-frame-options").unwrap(), "SAMEORIGIN");
        assert_eq!(resp.headers.get("referrer-policy").unwrap(), "no-referrer");
        assert!(!resp.headers.contains_key("X-Frame-Options"));
        assert!(!resp.headers.contains_key("Referrer-Policy"));
    }

    // --- None policy ---

    #[test]
    fn none_policy_sets_no_headers() {
        let mw = SecurityHeadersMiddleware::new(FnHandler::new(ok_handler), SecurityPolicy::none());
        let resp = mw.call(make_request());

        assert!(!resp.headers.contains_key("x-content-type-options"));
        assert!(!resp.headers.contains_key("x-frame-options"));
        assert!(!resp.headers.contains_key("referrer-policy"));
        assert!(!resp.headers.contains_key("strict-transport-security"));
        assert!(!resp.headers.contains_key("content-security-policy"));
        assert!(!resp.headers.contains_key("permissions-policy"));
    }

    #[test]
    fn none_policy_preserves_server_header() {
        let mw = SecurityHeadersMiddleware::new(
            FnHandler::new(handler_with_server_header),
            SecurityPolicy::none(),
        );
        let resp = mw.call(make_request());

        assert_eq!(
            resp.headers.get("server").unwrap(),
            "asupersync/0.2.6",
            "none policy should not strip server header"
        );
    }

    // --- Data type coverage ---

    #[test]
    fn security_policy_debug_clone() {
        let policy = SecurityPolicy::default();
        let dbg = format!("{policy:?}");
        assert!(dbg.contains("SecurityPolicy"), "{dbg}");
        let cloned = policy;
        assert_eq!(
            cloned.content_type_options.as_deref(),
            Some("nosniff"),
            "clone should preserve values"
        );
    }
