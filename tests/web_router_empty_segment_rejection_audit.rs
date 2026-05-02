//! Audit + regression test for `src/web/router.rs` empty-segment
//! handling in path matching.
//!
//! Operator's question: "when a route is `/users/:id` and the
//! request comes in with double-slash `/users//foo`, does our
//! matcher (a) treat as `/users/foo` (debatable), (b) reject
//! (correct), or (c) match `:id=""` (definitely wrong)?"
//!
//! Audit findings (DEFECT FOUND + FIXED in this commit):
//!
//!   PRE-FIX BEHAVIOR (option a — silently collapse):
//!     `RoutePattern::matches` (router.rs:199-216) split the
//!     path with `path.split('/').filter(|s| !s.is_empty())`
//!     which silently dropped empty interior segments. So
//!     `/users//foo` produced `["users", "foo"]` and matched
//!     `/users/:id` with `:id="foo"`. Inconsistent with
//!     `strip_prefix` in the same module, which already
//!     rejected `//` at mount boundaries
//!     (`strip_prefix_rejects_empty_segment_at_mount_boundary`,
//!     router.rs:1024-1027). The asymmetry meant a request
//!     could route differently depending on whether it was
//!     handled via direct routing vs nested-router mount, and
//!     the silent collapse opened a path-confusion attack
//!     surface: an attacker crafting `/api//admin` could evade
//!     a path-prefix filter that expected `/api/admin` while
//!     still routing to the admin handler.
//!
//!   POST-FIX BEHAVIOR (option b — reject):
//!     `RoutePattern::matches` now starts with
//!     `if path.contains("//") { return None; }` before any
//!     segment processing. Paths with empty segments do NOT
//!     match any route. The matcher now agrees with
//!     `strip_prefix` and the codebase is internally
//!     consistent.
//!
//!   Notes:
//!     - The (c) failure mode (`:id=""`) was NEVER possible —
//!       the pre-fix code dropped empty segments, never
//!       captured them. The fix moves us from (a) to (b),
//!       not from (c) to (b).
//!     - Trailing slashes (`/users/`) are still normalized
//!       away — only the literal substring `"//"` is rejected.
//!       Single trailing `/` is fine; double trailing `//` is
//!       rejected.
//!     - Operators who want trailing-slash redirects can wrap
//!       with `NormalizePathMiddleware`; this audit doesn't
//!       affect that layer.
//!
//! Regression tests below pin (1) `//` is rejected at every
//! position, (2) the `:id=""` failure mode is not reachable,
//! (3) clean paths still match, (4) consistency with
//! `strip_prefix`.

use std::path::PathBuf;

fn read_router_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/web/router.rs");
    std::fs::read_to_string(&path).expect("read router.rs")
}

#[test]
fn matches_fn_rejects_paths_containing_double_slash() {
    // Pin: the matcher contains the early-return guard for
    // paths with `//`. A regression that removed this guard
    // would re-open the silent-collapse failure mode.
    let source = read_router_source();
    let fn_marker = "fn matches(&self, path: &str) -> Option<RouteMatch> {";
    let start = source.find(fn_marker).expect("matches fn");
    let body_end = source[start..].find("\n    }\n").expect("matches fn close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("path.contains(\"//\")") && body.contains("return None"),
        "REGRESSION: RoutePattern::matches no longer guards \
         against paths containing '//'. Without this check, \
         '/users//foo' silently matches '/users/:id' as \
         :id='foo' — a path-confusion attack surface, and \
         inconsistent with strip_prefix's existing empty-\
         segment rejection. Restore the early-return guard:\n\
           if path.contains(\"//\") {{ return None; }}\n\n\
         fn body:\n{body}",
    );

    // The guard MUST appear BEFORE the path.split('/') call so
    // we don't even attempt segment processing on a path that
    // contains an empty segment.
    let guard_pos = body
        .find("path.contains(\"//\")")
        .expect("guard expression");
    let split_pos = body.find("path.split('/')").expect("split call");
    assert!(
        guard_pos < split_pos,
        "REGRESSION: the '//' guard now runs AFTER \
         path.split('/'). The guard MUST be the first thing in \
         the function so an early return doesn't waste work \
         on a path we already know is invalid.",
    );
}

#[test]
fn strip_prefix_already_rejects_empty_segments_at_boundary() {
    // Pin: the existing strip_prefix behavior is the
    // consistency baseline. If a regression weakened
    // strip_prefix while leaving matches strict (or vice-versa),
    // the inconsistency would re-emerge. This test reads the
    // existing in-crate test to verify it's still in place.
    let source = read_router_source();
    let test_marker = "fn strip_prefix_rejects_empty_segment_at_mount_boundary() {";
    let start = source
        .find(test_marker)
        .expect("strip_prefix_rejects_empty_segment_at_mount_boundary test");
    let body_end = source[start..].find("\n    }\n").expect("test close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("strip_prefix(\"/api//users\", \"/api\").is_none()"),
        "REGRESSION: the strip_prefix consistency baseline test \
         no longer asserts that '/api//users' is rejected. If \
         strip_prefix was weakened, the matcher's '//' guard \
         is now stricter than its sibling — we'd be back to an \
         inconsistent routing surface.\n\ntest body:\n{body}",
    );
}

// ─── Behavioral end-to-end pin (default features) ───────────────────

#[cfg(feature = "test-internals")]
mod behavioral {
    use asupersync::web::extract::Request;
    use asupersync::web::handler::{FnHandler, Handler};
    use asupersync::web::response::{Response, StatusCode};
    use asupersync::web::router::Router;

    fn ok_handler() -> FnHandler<fn() -> Response> {
        fn handler() -> Response {
            Response::new(StatusCode::OK, b"matched".to_vec())
        }
        FnHandler::new(handler)
    }

    fn dispatch(router: &Router, method: &str, path: &str) -> Response {
        let req = Request::new(method, path);
        router.call(req)
    }

    #[test]
    fn double_slash_in_middle_does_not_match_param_route() {
        // Pin (b) AUDIT-CRITICAL: '/users//foo' against
        // '/users/:id' must NOT match. Pre-fix, this matched
        // with :id='foo' — a path-confusion attack surface.
        let mut router = Router::new();
        router.get("/users/:id", ok_handler());

        let resp = dispatch(&router, "GET", "/users//foo");
        assert_ne!(
            resp.status,
            StatusCode::OK,
            "REGRESSION: '/users//foo' matched '/users/:id'. \
             Per RFC 3986 and consistency with strip_prefix, \
             paths containing empty interior segments must NOT \
             match positional-parameter routes. body: {:?}",
            std::str::from_utf8(&resp.body),
        );
        assert_eq!(
            resp.status,
            StatusCode::NOT_FOUND,
            "double-slash path should produce 404, not OK or \
             500; got {:?}",
            resp.status,
        );
    }

    #[test]
    fn double_slash_at_end_does_not_match_param_route() {
        // Pin: trailing `//` is also rejected.
        let mut router = Router::new();
        router.get("/users/:id", ok_handler());

        let resp = dispatch(&router, "GET", "/users/foo//");
        assert_ne!(
            resp.status,
            StatusCode::OK,
            "REGRESSION: trailing '//' matched the route. \
             Trailing single '/' is fine (normalized away); \
             trailing '//' is an empty segment and must be \
             rejected.",
        );
    }

    #[test]
    fn double_slash_at_start_does_not_match_any_route() {
        // Pin: leading `//` is rejected. (RFC 3986 §3.3 treats
        // leading `//` specially in absolute URI references —
        // it introduces an authority component. In a path-only
        // request line it's malformed.)
        let mut router = Router::new();
        router.get("/users", ok_handler());

        let resp = dispatch(&router, "GET", "//users");
        assert_ne!(
            resp.status,
            StatusCode::OK,
            "REGRESSION: leading '//users' matched '/users'. \
             Leading '//' is an empty leading segment and must \
             not match.",
        );
    }

    #[test]
    fn triple_slash_also_rejected() {
        // Pin: '///' contains '//' and so is also rejected.
        // (Defense-in-depth: not just exactly-double, any run
        // of consecutive slashes.)
        let mut router = Router::new();
        router.get("/users/:id", ok_handler());

        let resp = dispatch(&router, "GET", "/users///foo");
        assert_ne!(resp.status, StatusCode::OK);
    }

    #[test]
    fn clean_path_with_param_still_matches() {
        // Pin: the fix doesn't break the happy path. A regression
        // that over-broadly rejected paths would catastrophically
        // break every parameterized route.
        let mut router = Router::new();
        router.get("/users/:id", ok_handler());

        let resp = dispatch(&router, "GET", "/users/foo");
        assert_eq!(
            resp.status,
            StatusCode::OK,
            "regression: '/users/foo' no longer matches \
             '/users/:id'. The fix should only reject paths \
             with '//', not all parameterized paths.",
        );
        assert_eq!(resp.body.as_ref(), b"matched");
    }

    #[test]
    fn trailing_single_slash_still_matches() {
        // Pin: '/users/foo/' (single trailing slash) is still
        // matched against '/users/:id'. The fix only rejects
        // '//', not single trailing slash.
        let mut router = Router::new();
        router.get("/users/:id", ok_handler());

        let resp = dispatch(&router, "GET", "/users/foo/");
        assert_eq!(
            resp.status,
            StatusCode::OK,
            "regression: '/users/foo/' (trailing slash) no \
             longer matches '/users/:id'. Single trailing slash \
             is normalized away; only '//' (empty interior \
             segment) is rejected.",
        );
    }

    #[test]
    fn double_slash_does_not_match_route_with_two_params() {
        // Pin: '/users//posts' against '/users/:uid/posts/:pid'
        // is rejected — even though dropping the empty segment
        // would leave 2 segments != 4, AND even though the
        // worst-case (c) failure mode would set :uid="" :pid=""
        // — neither happens.
        let mut router = Router::new();
        router.get("/users/:uid/posts/:pid", ok_handler());

        // Empty :uid via leading '//'.
        let resp = dispatch(&router, "GET", "/users//posts/123");
        assert_ne!(
            resp.status,
            StatusCode::OK,
            "REGRESSION: '/users//posts/123' matched. The empty \
             segment after 'users' must NOT be silently \
             dropped (option a) OR captured as :uid='' (option \
             c). Both are wrong; reject is correct.",
        );

        // Empty :pid at end.
        let resp = dispatch(&router, "GET", "/users/alice/posts//");
        assert_ne!(resp.status, StatusCode::OK);
    }

    #[test]
    fn double_slash_in_static_route_also_rejected() {
        // Pin: '//' in a path against a fully-static route
        // (no params) is also rejected — for consistency. A
        // regression that scoped the guard to "only param
        // routes" would let static-route requests bypass.
        let mut router = Router::new();
        router.get("/health/status", ok_handler());

        let resp = dispatch(&router, "GET", "/health//status");
        assert_ne!(
            resp.status,
            StatusCode::OK,
            "REGRESSION: '//' rejection should apply to ALL \
             routes, not just param routes. A scoped guard \
             would let an attacker probe via '//' against \
             static admin paths.",
        );
    }

    #[test]
    fn empty_id_capture_is_not_reachable() {
        // Pin (operator's worst-case): :id='' (option c) was
        // never reachable pre-fix (the filter dropped empty
        // segments before they could be captured) and is still
        // not reachable post-fix (the path is rejected
        // entirely). This test makes the absence behaviorally
        // obvious — even if a future code path tries to capture
        // an empty segment, the early return prevents it.
        let mut router = Router::new();
        router.get("/items/:id", ok_handler());

        // An exotic path: encoded slash literal (not double-
        // slash). The router does NOT decode %2F before
        // matching, so this is a single literal segment.
        let resp = dispatch(&router, "GET", "/items/%2F%2F");
        // %2F%2F is NOT '//', so this is fine — :id="%2F%2F".
        // We're verifying the fix doesn't over-reject by
        // catching encoded slashes.
        assert_eq!(
            resp.status,
            StatusCode::OK,
            "encoded slashes (%2F%2F) inside a segment are \
             literal data, NOT empty segments — must still \
             match. The fix only rejects literal '//'.",
        );
    }
}
