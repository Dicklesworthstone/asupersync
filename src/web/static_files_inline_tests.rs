    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    trait SyncHandlerExt {
        fn call_sync(&self, req: super::super::extract::Request) -> Response;
    }

    impl<H: super::super::handler::Handler> SyncHandlerExt for H {
        fn call_sync(&self, req: super::super::extract::Request) -> Response {
            futures_lite::future::block_on(super::super::handler::Handler::call(
                self,
                &crate::Cx::for_testing(),
                req,
            ))
        }
    }

    fn setup_dir() -> TempDir {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("hello.txt"), "Hello, world!").unwrap();
        fs::write(dir.path().join("style.css"), "body { color: red; }").unwrap();
        fs::write(dir.path().join("app.js"), "console.log('hi');").unwrap();
        fs::write(dir.path().join("data.json"), r#"{"key":"val"}"#).unwrap();
        fs::write(dir.path().join("image.png"), [0x89, 0x50, 0x4E, 0x47]).unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/page.html"), "<h1>Sub</h1>").unwrap();
        fs::write(dir.path().join("sub/index.html"), "<h1>Index</h1>").unwrap();
        dir
    }

    // ================================================================
    // Range parsing — amplification defense (CVE-2011-3192 class)
    // ================================================================

    #[test]
    fn parse_ranges_rejects_excessive_specs() {
        // ~thousands of `0-` specs would buffer num_specs × file_size bytes.
        let header = format!("bytes={}", "0-,".repeat(5000));
        let result = parse_ranges(&header, 1_000_000);
        assert!(
            matches!(result, Err(RangeError::NotSatisfiable)),
            "excessive range specs must be rejected, got {result:?}"
        );
    }

    #[test]
    fn parse_ranges_coalesces_overlapping_specs() {
        // Many whole-file prefix ranges must collapse to a single range so the
        // emitted body is bounded by file_size, not num_specs × file_size.
        let header = format!("bytes={}", "0-,".repeat(50));
        let ranges = parse_ranges(&header, 1000).expect("under the spec cap");
        assert_eq!(ranges.len(), 1, "overlapping ranges coalesce to one");
        assert_eq!(ranges[0].start, 0);
        assert_eq!(ranges[0].end, 999);
    }

    #[test]
    fn parse_ranges_merges_adjacent_but_keeps_disjoint() {
        // 0-9 and 10-19 are adjacent → merge; 100-109 is disjoint → separate.
        let ranges = parse_ranges("bytes=0-9,10-19,100-109", 1000).expect("valid ranges");
        assert_eq!(ranges.len(), 2, "adjacent merge, disjoint preserved");
        assert_eq!((ranges[0].start, ranges[0].end), (0, 19));
        assert_eq!((ranges[1].start, ranges[1].end), (100, 109));
    }

    #[test]
    fn parse_ranges_single_range_unchanged() {
        let ranges = parse_ranges("bytes=0-499", 1000).expect("valid range");
        assert_eq!(ranges.len(), 1);
        assert_eq!((ranges[0].start, ranges[0].end), (0, 499));
    }

    #[test]
    fn parse_ranges_tolerates_empty_specs() {
        // Trailing / doubled commas produce empty elements which RFC 7230 §7
        // says to ignore, not reject.
        let ranges = parse_ranges("bytes=0-99,,100-199,", 1000).expect("empty specs ignored");
        assert_eq!(ranges.len(), 1, "adjacent ranges coalesce; empties ignored");
        assert_eq!((ranges[0].start, ranges[0].end), (0, 199));
    }

    // ================================================================
    // Hidden-file (dotfile) serving defense
    // ================================================================

    #[test]
    fn is_denied_hidden_component_logic() {
        assert!(is_denied_hidden_component(".env"));
        assert!(is_denied_hidden_component(".git"));
        assert!(is_denied_hidden_component(".htpasswd"));
        assert!(!is_denied_hidden_component(".well-known"));
        assert!(!is_denied_hidden_component("index.html"));
        assert!(!is_denied_hidden_component("assets"));
        assert!(!is_denied_hidden_component("")); // empty component (from //)
    }

    #[test]
    fn denied_static_path_rejects_backslashes_and_preserves_well_known() {
        assert!(has_denied_static_path(r"public\.env"));
        assert!(has_denied_static_path(r"public\app.js"));
        assert!(has_denied_static_path(r".well-known\acme"));
        assert!(has_denied_static_path("public/.env"));
        assert!(!has_denied_static_path(".well-known/acme-challenge/token"));
        assert!(!has_denied_static_path("public/app.js"));
    }

    #[test]
    fn denied_static_path_rejects_deferred_encoded_components() {
        assert!(has_denied_static_path_after_additional_decoding(
            "public%5c.env"
        ));
        assert!(has_denied_static_path_after_additional_decoding(
            "public%255c%252eenv"
        ));
        assert!(has_denied_static_path_after_additional_decoding(
            "public/%2eenv"
        ));
        assert!(!has_denied_static_path_after_additional_decoding(
            ".well-known%2facme-challenge%2ftoken"
        ));
    }

    #[test]
    fn resolve_path_denies_dotfiles_but_allows_well_known() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env"), "SECRET=1").unwrap();
        fs::create_dir(dir.path().join(".well-known")).unwrap();
        fs::write(dir.path().join(".well-known/acme.txt"), "challenge").unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        fs::write(dir.path().join(".git/config"), "[core]").unwrap();
        fs::write(dir.path().join("index.html"), "<h1>hi</h1>").unwrap();
        let sf = StaticFiles::new(dir.path());

        assert!(sf.resolve_path("/.env").is_none(), ".env must be denied");
        assert!(
            sf.resolve_path("/.git/config").is_none(),
            ".git/config must be denied"
        );
        assert!(
            sf.resolve_path("/.well-known/acme.txt").is_some(),
            ".well-known must be served"
        );
        assert!(
            sf.resolve_path(r"/.well-known\acme.txt").is_none(),
            "backslash spelling of .well-known must be denied"
        );
        assert!(
            sf.resolve_path("/.well-known%5cacme.txt").is_none(),
            "encoded-backslash spelling of .well-known must be denied"
        );
        assert!(
            sf.resolve_path("/index.html").is_some(),
            "normal files still served"
        );
    }

    #[test]
    fn resolve_path_keeps_an_encoded_slash_inside_its_segment() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        assert!(sf.resolve_path("/sub/page.html").is_some());
        assert!(sf.resolve_path("/sub%2Fpage.html").is_none());
        assert!(sf.resolve_path("/sub%2fpage.html").is_none());
    }

    #[test]
    fn an_encoded_slash_cannot_reach_files_below_a_more_specific_mount() {
        // `/files/sub%2Fpage.html` is one segment to the router, so it misses
        // a mount at `/files/sub` (which may carry auth) and lands on the
        // outer `/files` mount, which must not serve `sub/page.html` for it.
        let dir = setup_dir();
        let app = crate::web::Router::new().nest(
            "/files",
            crate::web::Router::new().fallback(StaticFiles::new(dir.path()).handler()),
        );
        let get = |path: &str| {
            app.handle(super::super::extract::Request::new("GET", path))
                .status
        };
        assert_eq!(get("/files/sub/page.html"), StatusCode::OK);
        assert_eq!(get("/files/sub%2Fpage.html"), StatusCode::NOT_FOUND);
    }

    #[test]
    fn resolve_path_rejects_backslash_and_deferred_encodings() {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join("public")).unwrap();
        fs::write(dir.path().join(r"public\.env"), "SECRET=1").unwrap();
        fs::write(dir.path().join("public%5c.env"), "SECRET=2").unwrap();
        let sf = StaticFiles::new(dir.path());

        assert!(sf.resolve_path(r"/public\.env").is_none());
        assert!(sf.resolve_path("/public%5c.env").is_none());
        assert!(sf.resolve_path("/public%255c.env").is_none());
    }

    // ================================================================
    // MIME detection
    // ================================================================

    #[test]
    fn mime_html() {
        assert_eq!(
            guess_mime(Path::new("index.html")),
            "text/html; charset=utf-8"
        );
    }

    #[test]
    fn mime_css() {
        assert_eq!(
            guess_mime(Path::new("style.css")),
            "text/css; charset=utf-8"
        );
    }

    #[test]
    fn mime_js() {
        assert_eq!(
            guess_mime(Path::new("app.js")),
            "application/javascript; charset=utf-8"
        );
    }

    #[test]
    fn mime_json() {
        assert_eq!(
            guess_mime(Path::new("data.json")),
            "application/json; charset=utf-8"
        );
    }

    #[test]
    fn mime_png() {
        assert_eq!(guess_mime(Path::new("image.png")), "image/png");
    }

    #[test]
    fn mime_unknown() {
        assert_eq!(
            guess_mime(Path::new("file.xyz")),
            "application/octet-stream"
        );
    }

    #[test]
    fn mime_case_insensitive() {
        assert_eq!(
            guess_mime(Path::new("FILE.HTML")),
            "text/html; charset=utf-8"
        );
    }

    #[test]
    fn mime_wasm() {
        assert_eq!(guess_mime(Path::new("module.wasm")), "application/wasm");
    }

    // ================================================================
    // Path security
    // ================================================================

    #[test]
    fn traversal_double_dot() {
        assert!(has_traversal("../etc/passwd"));
        assert!(has_traversal("foo/../bar"));
        assert!(has_traversal("foo/.."));
    }

    #[test]
    fn traversal_backslash() {
        assert!(has_traversal("..\\etc\\passwd"));
    }

    #[test]
    fn traversal_null_byte() {
        assert!(has_traversal("file\0.txt"));
    }

    #[test]
    fn traversal_unicode_dot_variants() {
        assert!(has_traversal("\u{2024}\u{2024}/etc/passwd"));
        assert!(has_traversal(".\u{2024}/etc/passwd"));
        assert!(has_traversal("foo/\u{FE52}\u{FE52}/bar"));
        assert!(has_traversal("foo/\u{FF0E}\u{FF0E}/bar"));
    }

    #[test]
    fn traversal_deferred_percent_decoding() {
        assert!(has_denied_static_path_after_additional_decoding(
            "%2e%2e/etc/passwd"
        ));
        assert!(has_denied_static_path_after_additional_decoding(
            "safe/%2e%2e/secret.txt"
        ));
        assert!(has_denied_static_path_after_additional_decoding(
            "safe%2f..%2fsecret.txt"
        ));
        assert!(has_denied_static_path_after_additional_decoding(
            "safe%5c..%5csecret.txt"
        ));
        assert!(has_denied_static_path_after_additional_decoding(
            "%252e%252e/etc/passwd"
        ));
        assert!(!has_denied_static_path_after_additional_decoding(
            "version%2e1/file.txt"
        ));
    }

    #[test]
    fn no_traversal() {
        assert!(!has_traversal("hello.txt"));
        assert!(!has_traversal("sub/page.html"));
        assert!(!has_traversal("deeply/nested/file.js"));
    }

    // ================================================================
    // Percent decoding
    // ================================================================

    #[test]
    fn percent_decode_basic() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
    }

    #[test]
    fn percent_decode_no_encoding() {
        assert_eq!(percent_decode("hello.txt"), "hello.txt");
    }

    #[test]
    fn percent_decode_path_separator() {
        assert_eq!(percent_decode("foo%2Fbar"), "foo/bar");
    }

    #[test]
    fn percent_decode_utf8_path_dot() {
        assert_eq!(percent_decode("%E2%80%A4%E2%80%A4"), "\u{2024}\u{2024}");
        assert!(has_traversal(&percent_decode(
            "%E2%80%A4%E2%80%A4/etc/passwd"
        )));
    }

    #[test]
    fn percent_decode_incomplete() {
        assert_eq!(percent_decode("hello%2"), "hello%2");
    }

    #[test]
    fn percent_decode_invalid_sequence_preserves_bytes() {
        assert_eq!(percent_decode("hello%GGworld"), "hello%GGworld");
        assert_eq!(percent_decode("sub%2/page.html"), "sub%2/page.html");
        assert_eq!(percent_decode("%"), "%");
    }

    // ================================================================
    // ETag
    // ================================================================

    #[test]
    fn etag_matches_exact() {
        assert!(etag_matches("\"abc\"", "\"abc\""));
    }

    #[test]
    fn etag_matches_star() {
        assert!(etag_matches("*", "\"abc\""));
    }

    #[test]
    fn etag_matches_list() {
        assert!(etag_matches("\"x\", \"y\", \"z\"", "\"y\""));
    }

    #[test]
    fn etag_matches_weak() {
        assert!(etag_matches("W/\"abc\"", "\"abc\""));
    }

    #[test]
    fn etag_no_match() {
        assert!(!etag_matches("\"abc\"", "\"def\""));
    }

    #[test]
    fn strong_etag_changes_for_same_length_content() {
        let first = generate_etag(b"abc");
        let second = generate_etag(b"abd");

        assert_ne!(
            first, second,
            "strong ETags must change when same-length content changes"
        );
    }

    // ================================================================
    // Path resolution
    // ================================================================

    #[test]
    fn resolve_simple_file() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let path = sf.resolve_path("/hello.txt");
        assert!(path.is_some());
    }

    #[test]
    fn resolve_nested_file() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let path = sf.resolve_path("/sub/page.html");
        assert!(path.is_some());
    }

    #[test]
    fn resolve_directory_index() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let path = sf.resolve_path("/sub/");
        assert!(path.is_some());
        assert!(path.unwrap().ends_with("index.html"));
    }

    #[test]
    fn resolve_nonexistent() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        assert!(sf.resolve_path("/missing.txt").is_none());
    }

    #[test]
    fn resolve_traversal_blocked() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        assert!(sf.resolve_path("/../../../etc/passwd").is_none());
    }

    #[test]
    fn resolve_percent_encoded() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        assert!(sf.resolve_path("/hello%2Etxt").is_some());
    }

    #[test]
    fn resolve_double_encoded_traversal_blocked() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        assert!(sf.resolve_path("/%252e%252e/etc/passwd").is_none());
        assert!(sf.resolve_path("/sub%252f..%252fhello.txt").is_none());
        assert!(sf.resolve_path("/sub%255c..%255chello.txt").is_none());
    }

    #[test]
    fn resolve_unicode_dot_traversal_blocked_after_percent_decode() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());

        assert!(sf.resolve_path("/%E2%80%A4%E2%80%A4/etc/passwd").is_none());
        assert!(
            sf.resolve_path("/sub/%EF%B9%92%EF%B9%92/hello.txt")
                .is_none()
        );
        assert!(
            sf.resolve_path("/sub/%EF%BC%8E%EF%BC%8E/hello.txt")
                .is_none()
        );
    }

    #[test]
    fn resolve_invalid_percent_encoding_does_not_alias_other_path() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        assert!(
            sf.resolve_path("/sub%2/page.html").is_none(),
            "malformed escapes must be preserved instead of silently dropping bytes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_symlinked_file_blocked() {
        let dir = setup_dir();
        std::os::unix::fs::symlink("hello.txt", dir.path().join("hello-link.txt")).unwrap();

        let sf = StaticFiles::new(dir.path());
        assert!(
            sf.resolve_path("/hello-link.txt").is_none(),
            "symlinked files must not be served by default"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_symlinked_directory_blocked() {
        let dir = setup_dir();
        std::os::unix::fs::symlink("sub", dir.path().join("sub-link")).unwrap();

        let sf = StaticFiles::new(dir.path());
        assert!(
            sf.resolve_path("/sub-link/page.html").is_none(),
            "symlinked directories must not be traversed"
        );
        assert!(
            sf.resolve_path("/sub-link/").is_none(),
            "directory indexes behind symlinks must not be served"
        );
    }

    #[cfg(unix)]
    #[test]
    fn serve_file_rejects_post_resolution_symlink_swap() {
        let dir = setup_dir();
        let outside = TempDir::new().unwrap();
        let outside_path = outside.path().join("secret.txt");
        fs::write(&outside_path, "top secret").unwrap();

        let sf = StaticFiles::new(dir.path());
        let resolved = sf.resolve_path("/hello.txt").unwrap();
        let backup = dir.path().join("hello.backup.txt");
        fs::rename(&resolved, &backup).unwrap();
        std::os::unix::fs::symlink(&outside_path, &resolved).unwrap();

        let resp = sf.serve_file(&resolved, None);
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
        assert_ne!(resp.body.as_ref(), b"top secret");
    }

    // ================================================================
    // File serving
    // ================================================================

    #[test]
    fn serve_txt_file() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let path = sf.resolve_path("/hello.txt").unwrap();
        let resp = sf.serve_file(&path, None);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "Hello, world!");
        assert!(resp.headers.contains_key("etag"));
        assert!(resp.headers.contains_key("cache-control"));
        assert_eq!(
            resp.headers.get("x-content-type-options").unwrap(),
            "nosniff"
        );
    }

    #[test]
    fn serve_css_file() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let path = sf.resolve_path("/style.css").unwrap();
        let resp = sf.serve_file(&path, None);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/css; charset=utf-8"
        );
    }

    #[test]
    fn serve_304_not_modified() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let path = sf.resolve_path("/hello.txt").unwrap();

        // First request to get the ETag.
        let resp1 = sf.serve_file(&path, None);
        let etag = resp1.headers.get("etag").unwrap().clone();

        // Second request with If-None-Match.
        let resp2 = sf.serve_file(&path, Some(&etag));
        assert_eq!(resp2.status, StatusCode::NOT_MODIFIED);
        assert!(resp2.body.is_empty());
        assert_eq!(
            resp2.headers.get("x-content-type-options").unwrap(),
            "nosniff"
        );
    }

    #[test]
    fn serve_304_not_modified_for_if_none_match_wildcard() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let path = sf.resolve_path("/hello.txt").unwrap();

        let resp = sf.serve_file(&path, Some("*"));
        assert_eq!(resp.status, StatusCode::NOT_MODIFIED);
        assert!(resp.body.is_empty());
        assert!(resp.headers.contains_key("etag"));
        assert_eq!(
            resp.headers.get("x-content-type-options").unwrap(),
            "nosniff"
        );
    }

    /// br-asupersync-42wywh — RFC 9110 §13.2.2 requires preconditions
    /// (If-None-Match in particular) to be evaluated BEFORE Range
    /// processing. Pre-fix: an unsatisfiable / malformed Range header
    /// short-circuited to 416 even when If-None-Match matched the
    /// current ETag, forcing clients into a needless full refetch on
    /// the next request. Post-fix: If-None-Match wins → 304 Not Modified.
    #[test]
    fn serve_range_with_matching_if_none_match_prefers_304_over_416() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let path = sf.resolve_path("/hello.txt").unwrap();

        // Capture the current ETag from a plain GET so we can replay
        // the matching If-None-Match below.
        let etag = sf
            .serve_file(&path, None)
            .headers
            .get("etag")
            .expect("etag must be present")
            .clone();

        // Range that is provably unsatisfiable: file is 13 bytes, the
        // requested range starts well past EOF. parse_ranges returns
        // NotSatisfiable, which the pre-fix path short-circuited to
        // 416 before checking If-None-Match.
        let resp = sf.serve_range(&path, "bytes=99999-100000", Some(&etag), None);

        assert_eq!(
            resp.status,
            StatusCode::NOT_MODIFIED,
            "If-None-Match must be evaluated before Range (RFC 9110 §13.2.2); \
             matching ETag must yield 304, not 416. Got status={:?}",
            resp.status,
        );
        assert!(resp.body.is_empty(), "304 responses MUST NOT carry a body",);
        assert_eq!(
            resp.headers.get("etag").map(String::as_str),
            Some(etag.as_str()),
            "304 must echo the ETag",
        );
        assert!(
            !resp.headers.contains_key("content-range"),
            "304 must not carry Content-Range; got {:?}",
            resp.headers.get("content-range"),
        );
    }

    /// br-asupersync-42wywh — same precondition-ordering requirement
    /// for the syntactically-malformed Range case (`bytes=abc-def`).
    /// The matching If-None-Match takes precedence; 304, not 416.
    #[test]
    fn serve_range_invalid_syntax_with_matching_if_none_match_returns_304() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let path = sf.resolve_path("/hello.txt").unwrap();

        let etag = sf
            .serve_file(&path, None)
            .headers
            .get("etag")
            .expect("etag must be present")
            .clone();

        let resp = sf.serve_range(&path, "bytes=abc-def", Some(&etag), None);

        assert_eq!(
            resp.status,
            StatusCode::NOT_MODIFIED,
            "If-None-Match must trump even a malformed Range header per \
             RFC 9110 §13.2.2; got status={:?}",
            resp.status,
        );
    }

    /// br-asupersync-42wywh — counter test: a non-matching If-None-Match
    /// with an unsatisfiable Range still yields 416. The fix must NOT
    /// regress the existing behavior when the precondition is false.
    #[test]
    fn serve_range_unsatisfiable_with_non_matching_if_none_match_still_416() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let path = sf.resolve_path("/hello.txt").unwrap();

        let resp = sf.serve_range(&path, "bytes=99999-100000", Some("\"not-the-etag\""), None);

        assert_eq!(
            resp.status,
            StatusCode::RANGE_NOT_SATISFIABLE,
            "Non-matching If-None-Match must NOT prevent the 416 path",
        );
    }

    #[test]
    fn serve_custom_max_age() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path()).max_age(86400);
        let path = sf.resolve_path("/hello.txt").unwrap();
        let resp = sf.serve_file(&path, None);
        assert_eq!(
            resp.headers.get("cache-control").unwrap(),
            "public, max-age=86400"
        );
    }

    #[test]
    fn serve_custom_headers() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path()).header("x-custom", "value");
        let path = sf.resolve_path("/hello.txt").unwrap();
        let resp = sf.serve_file(&path, None);
        assert_eq!(resp.headers.get("x-custom").unwrap(), "value");
    }

    #[test]
    fn serve_custom_headers_can_override_nosniff() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path()).header("X-Content-Type-Options", "custom-policy");
        let path = sf.resolve_path("/hello.txt").unwrap();
        let resp = sf.serve_file(&path, None);
        assert_eq!(
            resp.headers.get("x-content-type-options").unwrap(),
            "custom-policy"
        );
    }

    // ================================================================
    // Handler integration
    // ================================================================

    #[test]
    fn handler_serves_file() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let handler = sf.handler();

        let req = super::super::extract::Request::new("GET", "/hello.txt");
        let resp = handler.call_sync(req);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "Hello, world!");
    }

    #[test]
    fn handler_head_omits_body_but_preserves_conditional_headers() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let handler = sf.handler();

        let get_resp = handler.call_sync(super::super::extract::Request::new("GET", "/hello.txt"));
        let head_resp =
            handler.call_sync(super::super::extract::Request::new("HEAD", "/hello.txt"));

        assert_eq!(head_resp.status, StatusCode::OK);
        assert!(head_resp.body.is_empty());
        assert_eq!(
            head_resp.headers.get("content-type"),
            get_resp.headers.get("content-type")
        );
        assert_eq!(
            head_resp.headers.get("content-length"),
            Some(&get_resp.body.len().to_string())
        );
        assert_eq!(head_resp.headers.get("etag"), get_resp.headers.get("etag"));
        assert_eq!(
            head_resp.headers.get("cache-control"),
            get_resp.headers.get("cache-control")
        );
        assert_eq!(
            head_resp.headers.get("x-content-type-options"),
            get_resp.headers.get("x-content-type-options")
        );
    }

    #[test]
    fn handler_honours_if_range_and_range_units() {
        use super::super::extract::Request;
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let handler = sf.handler();
        let etag = handler
            .call_sync(Request::new("GET", "/hello.txt"))
            .headers
            .get("etag")
            .cloned()
            .expect("etag");
        let ranged = |if_range: Option<&str>, range: &str| {
            let mut req = Request::new("GET", "/hello.txt").with_header("Range", range);
            if let Some(if_range) = if_range {
                req = req.with_header("If-Range", if_range);
            }
            handler.call_sync(req)
        };

        // The validator still matches: the range applies.
        let resp = ranged(Some(&etag), "bytes=0-4");
        assert_eq!(resp.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(resp.body.as_ref(), b"Hello");
        // A stale validator, or a date (no Last-Modified is sent): the whole
        // current file with 200, never a 206 of a different representation.
        for stale in ["\"an-old-etag\"", "Sat, 01 Jan 2000 00:00:00 GMT"] {
            let resp = ranged(Some(stale), "bytes=0-4");
            assert_eq!(resp.status, StatusCode::OK, "If-Range {stale}");
            assert_eq!(resp.body.as_ref(), b"Hello, world!");
        }
        // Range units are case-insensitive; an unknown unit is ignored.
        let resp = ranged(None, "BYTES=0-4");
        assert_eq!(resp.status, StatusCode::PARTIAL_CONTENT);
        let resp = ranged(None, "items=0-4");
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body.as_ref(), b"Hello, world!");
    }

    #[test]
    fn handler_returns_404() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let handler = sf.handler();

        let req = super::super::extract::Request::new("GET", "/missing.txt");
        let resp = handler.call_sync(req);
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn handler_304_with_etag() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let handler = sf.handler();

        // First request.
        let req1 = super::super::extract::Request::new("GET", "/hello.txt");
        let resp1 = handler.call_sync(req1);
        let etag = resp1.headers.get("etag").unwrap().clone();

        // Second request with If-None-Match.
        let req2 = super::super::extract::Request::new("GET", "/hello.txt")
            .with_header("If-None-Match", etag);
        let resp2 = handler.call_sync(req2);
        assert_eq!(resp2.status, StatusCode::NOT_MODIFIED);
    }

    #[test]
    fn handler_head_304_with_etag_stays_empty() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let handler = sf.handler();

        let get_resp = handler.call_sync(super::super::extract::Request::new("GET", "/hello.txt"));
        let etag = get_resp.headers.get("etag").unwrap().clone();

        let head_req = super::super::extract::Request::new("HEAD", "/hello.txt")
            .with_header("If-None-Match", etag);
        let head_resp = handler.call_sync(head_req);

        assert_eq!(head_resp.status, StatusCode::NOT_MODIFIED);
        assert!(head_resp.body.is_empty());
        assert!(head_resp.headers.contains_key("etag"));
        assert!(head_resp.headers.contains_key("cache-control"));
        assert_eq!(
            head_resp.headers.get("x-content-type-options").unwrap(),
            "nosniff"
        );
    }

    // ================================================================
    // Builder API
    // ================================================================

    #[test]
    fn builder_no_index() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path()).index_file(None::<String>);
        assert!(sf.resolve_path("/sub/").is_none());
    }

    #[test]
    fn builder_debug() {
        let sf = StaticFiles::new("/tmp/static");
        let dbg = format!("{sf:?}");
        assert!(dbg.contains("StaticFiles"));
        assert!(dbg.contains("/tmp/static"));
    }

    #[test]
    fn builder_clone() {
        let sf = StaticFiles::new("/tmp/static").max_age(300);
        let sf2 = sf.clone();
        assert_eq!(sf2.max_age, sf.max_age);
    }
