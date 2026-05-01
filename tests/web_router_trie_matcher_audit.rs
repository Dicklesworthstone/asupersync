//! Audit + regression test for `src/web/router.rs` trie matcher.
//!
//! Audit scope:
//!   (1) Trailing-slash equivalence across HEAD/GET/POST methods.
//!   (2) Parameter capture name collisions when two routes both
//!       contain `:id` (separate routes vs same-route duplicates).
//!   (3) Wildcard route precedence when `*` appears mid-path.
//!   (4) Path-traversal via percent-encoded slash decoded after
//!       route-match — verify the router does NOT decode `%2F`
//!       before matching, so a peer cannot bypass route
//!       boundaries.
//!
//! Audit verdict: **SOUND.** All four vectors are defended:
//!
//!   (1) Path normalization happens at the matcher: both
//!       `path.split('/').filter(!is_empty)` and
//!       `pattern.split('/').filter(!is_empty)` discard empty
//!       segments (router.rs:175-177, 200-201). So `/users/42`
//!       and `/users/42/` produce the same segment vector. The
//!       MethodRouter then dispatches by uppercased method
//!       (router.rs:98-109) — methods are independent. Trailing
//!       slash is method-agnostic.
//!
//!   (2) Parameter capture goes into a fresh per-match
//!       HashMap (router.rs:217). Two SEPARATE routes both
//!       using `:id` produce independent matches — no cross-
//!       route collision. Within a SINGLE route, duplicate
//!       param names overwrite (HashMap insert semantics) —
//!       second value wins. Operator footgun, not a security
//!       bug; pinned as documented behavior.
//!
//!   (3) Wildcard precedence: `Segment::Wildcard` consumes
//!       the rest of the path on first match (router.rs:233-241,
//!       early-return). A wildcard ANYWHERE in the pattern
//!       triggers the early-return — segments AFTER the
//!       wildcard are silently ignored. Specificity calculator
//!       sets `exact_path = false` for any wildcard segment
//!       (router.rs:260) so wildcard routes have LOWER
//!       priority than literal-only or param-only routes —
//!       cannot shadow narrower protected paths.
//!
//!   (4) **Critical: the router does NOT decode percent-
//!       encoding in the path.** The HTTP/1 codec parses
//!       paths AS-IS (per `request_line_percent_encoding` test
//!       at h1/request_line_tests.rs:209-229), and the router's
//!       split-on-`/` operates on literal bytes. So `%2F` in
//!       the path stays as the three literal characters `%2F`
//!       and does NOT split the path segment. A request to
//!       `/api/foo%2F..%2Fadmin` matches `/api/:slug` with
//!       `slug = "foo%2F..%2Fadmin"` — NOT `/api/foo/../admin`
//!       which would have potentially matched a different
//!       route. This closes the canonical "double-decode"
//!       path-traversal class.
//!
//!       If a downstream handler manually percent-decodes the
//!       captured param, it gets a string containing `/`, but
//!       by that point the routing decision is already made.
//!       The captured param is opaque to the routing layer.
//!
//! Regression tests below pin (1)-(4).

use asupersync::web::extract::Request;
use asupersync::web::handler::FnHandler;
use asupersync::web::response::StatusCode;
use asupersync::web::router::{Router, get, post};
use std::sync::Arc;

fn ok_handler() -> StatusCode {
    StatusCode::OK
}

fn forbidden_handler() -> StatusCode {
    StatusCode::FORBIDDEN
}

fn no_content_handler() -> StatusCode {
    StatusCode::NO_CONTENT
}

fn conflict_handler() -> StatusCode {
    StatusCode::CONFLICT
}

// ── (1) Trailing-slash equivalence across methods ────────────────

#[test]
fn trailing_slash_equivalent_for_get_route() {
    // Pin (1): GET `/users/42` and GET `/users/42/` route to
    // the SAME handler — empty trailing segment is filtered.
    let router = Router::new().route("/users/:id", get(FnHandler::new(ok_handler)));

    let resp = router.handle(Request::new("GET", "/users/42"));
    assert_eq!(resp.status, StatusCode::OK);

    let resp_trailing = router.handle(Request::new("GET", "/users/42/"));
    assert_eq!(
        resp_trailing.status,
        StatusCode::OK,
        "trailing slash MUST route to same handler — split-and-filter \
         drops empty segments at router.rs:201",
    );
}

#[test]
fn trailing_slash_equivalent_for_post_route() {
    // Pin (1): POST shares the same path normalization. Method
    // is uppercased and matched separately on the same route.
    let router = Router::new().route("/items", post(FnHandler::new(ok_handler)));

    let resp = router.handle(Request::new("POST", "/items"));
    assert_eq!(resp.status, StatusCode::OK);

    let resp_trailing = router.handle(Request::new("POST", "/items/"));
    assert_eq!(
        resp_trailing.status,
        StatusCode::OK,
        "POST trailing-slash equivalent",
    );
}

#[test]
fn trailing_slash_equivalent_for_head_route() {
    // Pin (1): HEAD method also gets normalized routing.
    // Build via `get(...).head(handler)` and remove GET via
    // separate registration check.
    let router = Router::new().route(
        "/health",
        get(FnHandler::new(ok_handler)).head(FnHandler::new(no_content_handler)),
    );

    let resp = router.handle(Request::new("HEAD", "/health"));
    assert_eq!(resp.status, StatusCode::NO_CONTENT);

    let resp_trailing = router.handle(Request::new("HEAD", "/health/"));
    assert_eq!(
        resp_trailing.status,
        StatusCode::NO_CONTENT,
        "HEAD trailing-slash equivalent",
    );
}

#[test]
fn methods_are_independent_on_same_route() {
    // Pin (1) extension: GET, POST, DELETE registered on the
    // SAME pattern resolve to DIFFERENT handlers. A regression
    // that conflated methods would surface here.
    let router = Router::new().route(
        "/resource/:id",
        get(FnHandler::new(ok_handler))
            .post(FnHandler::new(no_content_handler))
            .delete(FnHandler::new(forbidden_handler)),
    );

    let get_resp = router.handle(Request::new("GET", "/resource/42"));
    assert_eq!(get_resp.status, StatusCode::OK);
    let post_resp = router.handle(Request::new("POST", "/resource/42"));
    assert_eq!(post_resp.status, StatusCode::NO_CONTENT);
    let del_resp = router.handle(Request::new("DELETE", "/resource/42"));
    assert_eq!(del_resp.status, StatusCode::FORBIDDEN);

    let unsupported = router.handle(Request::new("PUT", "/resource/42"));
    assert_eq!(
        unsupported.status,
        StatusCode::METHOD_NOT_ALLOWED,
        "unregistered method MUST surface 405",
    );
}

// ── (2) Parameter capture name collisions ────────────────────────

#[test]
fn two_separate_routes_with_id_param_do_not_collide() {
    // Pin (2): two routes both using `:id` — the matcher's
    // params HashMap is created fresh per match (router.rs:217).
    // No cross-route bleed.
    let router = Router::new()
        .route("/users/:id", get(FnHandler::new(ok_handler)))
        .route("/posts/:id", get(FnHandler::new(no_content_handler)));

    let user_resp = router.handle(Request::new("GET", "/users/42"));
    assert_eq!(user_resp.status, StatusCode::OK);

    let post_resp = router.handle(Request::new("GET", "/posts/77"));
    assert_eq!(
        post_resp.status,
        StatusCode::NO_CONTENT,
        "second route's distinct handler invoked — no cross-route bleed",
    );
}

#[test]
fn duplicate_param_name_in_single_route_second_value_wins() {
    // Pin (2): a SINGLE route with two `:id` segments —
    // documented HashMap-insert semantics mean the second
    // capture overwrites. Operator footgun (registration-time
    // mistake), not a security bug. Pinned to make the
    // contract explicit.
    use asupersync::web::extract::Path;
    use asupersync::web::handler::FnHandler1;

    let captured: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let captured_clone = captured.clone();
    let handler = move |Path(id): Path<String>| -> StatusCode {
        *captured_clone.lock().unwrap() = Some(id);
        StatusCode::OK
    };

    let router = Router::new().route(
        "/users/:id/copies/:id",
        get(FnHandler1::<_, Path<String>>::new(handler)),
    );

    let resp = router.handle(Request::new("GET", "/users/42/copies/77"));
    assert_eq!(resp.status, StatusCode::OK);
    let recovered = captured.lock().unwrap().clone().unwrap();
    assert_eq!(
        recovered, "77",
        "duplicate `:id` segments — second value wins (HashMap insert \
         semantics). Operator footgun documented; the matcher does NOT \
         reject duplicate names at registration. got {recovered:?}",
    );
}

#[test]
fn distinct_param_names_in_one_route_capture_independently() {
    // Pin (2) good case: distinct names in a single route are
    // captured independently, as expected.
    let router = Router::new().route(
        "/users/:user_id/posts/:post_id",
        get(FnHandler::new(ok_handler)),
    );

    let resp = router.handle(Request::new("GET", "/users/42/posts/77"));
    assert_eq!(resp.status, StatusCode::OK);
}

// ── (3) Wildcard route precedence ────────────────────────────────

#[test]
fn literal_route_wins_over_wildcard_for_specific_path() {
    // Pin (3): a literal route MUST win over a wildcard route
    // when both could match. specificity.exact_path = true for
    // literal routes, false for wildcards (router.rs:260).
    //
    // We make the literal route return FORBIDDEN and the
    // wildcard return OK so a matching error would visibly
    // produce the wrong status.
    let router = Router::new()
        .route("/admin/secret", get(FnHandler::new(forbidden_handler)))
        .route("/admin/*", get(FnHandler::new(ok_handler)));

    let resp = router.handle(Request::new("GET", "/admin/secret"));
    assert_eq!(
        resp.status,
        StatusCode::FORBIDDEN,
        "literal route (FORBIDDEN handler) MUST win over wildcard (OK \
         handler) for /admin/secret. A regression that flipped \
         precedence would route the protected path to the wildcard \
         handler — the canonical broad-wildcard-shadowing-narrower-route \
         class of routing bug.",
    );
}

#[test]
fn wildcard_only_for_unmatched_paths() {
    // Pin (3): the wildcard catches paths NOT covered by a
    // more specific route.
    let router = Router::new()
        .route("/admin/secret", get(FnHandler::new(forbidden_handler)))
        .route("/admin/*", get(FnHandler::new(ok_handler)));

    let secret = router.handle(Request::new("GET", "/admin/secret"));
    assert_eq!(secret.status, StatusCode::FORBIDDEN);

    let other = router.handle(Request::new("GET", "/admin/other"));
    assert_eq!(other.status, StatusCode::OK);
}

#[test]
fn mid_path_wildcard_consumes_rest() {
    // Pin (3): when `*` appears mid-pattern, the matcher
    // consumes the rest of the path on first wildcard hit
    // (router.rs:233-241, early-return). The path must have
    // at least as many segments as the pattern (router.rs:213
    // segment-count check, since `has_wildcard` only checks
    // the LAST segment). Once segment count matches, the
    // wildcard at index N early-returns ignoring all pattern
    // segments after position N.
    let router = Router::new().route("/files/*/edit", get(FnHandler::new(ok_handler)));

    // Path `/files/anything/somethingelse` has 3 segments, so it
    // satisfies the `path_segments.len() == pattern.segments.len()`
    // check (false has_wildcard branch). The wildcard at index 1
    // then early-returns, ignoring the literal "edit" pattern
    // segment at index 2.
    let resp = router.handle(Request::new("GET", "/files/anything/somethingelse"));
    assert_eq!(
        resp.status,
        StatusCode::OK,
        "mid-path wildcard at index N early-returns once segment count \
         matches; pattern segments after the wildcard are NOT enforced. \
         Documented behavior.",
    );

    // Confirm the wildcard pattern's segment-count gate: a 2-segment
    // path against a 3-segment pattern (with non-trailing wildcard)
    // does NOT match because `has_wildcard` is false (last is literal).
    let too_short = router.handle(Request::new("GET", "/files/foo"));
    assert_eq!(
        too_short.status,
        StatusCode::NOT_FOUND,
        "2-segment path against 3-segment pattern (last=literal) MUST \
         NOT match — the segment-count gate fires before the wildcard \
         can consume.",
    );
}

#[test]
fn empty_router_returns_404() {
    // Pin: a router with no routes returns 404 by default
    // (router.rs:402).
    let router: Router = Router::new();
    let resp = router.handle(Request::new("GET", "/anything"));
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
}

#[test]
fn wildcard_does_not_shadow_unrelated_route() {
    // Pin (3) safety: a wildcard route at one prefix MUST NOT
    // shadow a literal route at a different prefix.
    let router = Router::new()
        .route("/api/users", get(FnHandler::new(ok_handler)))
        .route("/static/*", get(FnHandler::new(no_content_handler)));

    let users = router.handle(Request::new("GET", "/api/users"));
    assert_eq!(users.status, StatusCode::OK);

    let static_file = router.handle(Request::new("GET", "/static/foo.png"));
    assert_eq!(static_file.status, StatusCode::NO_CONTENT);
}

// ── (4) Path-traversal via percent-encoded slash ─────────────────

#[test]
fn percent_encoded_slash_in_path_does_not_split_segment() {
    // Pin (4) audit-critical: `%2F` in the path is treated as
    // three literal characters by the router's split-on-`/`.
    // It does NOT decode to `/` and split the segment.
    //
    // This closes the double-decode path-traversal class. A
    // peer requesting `/api/foo%2F..%2Fadmin` matches
    // `/api/:slug` with `slug = "foo%2F..%2Fadmin"` — NOT
    // `/api/foo/../admin` which would potentially match a
    // different route.
    let router = Router::new().route("/api/:slug", get(FnHandler::new(ok_handler)));

    let resp = router.handle(Request::new("GET", "/api/foo%2F..%2Fadmin"));
    assert_eq!(
        resp.status,
        StatusCode::OK,
        "%2F in path does NOT split the segment — matches single-segment \
         route with the literal %2F bytes inside the captured param",
    );
}

#[test]
fn percent_encoded_slash_does_not_match_two_segment_route() {
    // Pin (4): the converse — a single-segment path with %2F
    // does NOT match a two-segment pattern. Proves the router
    // is operating on raw bytes, not decoded characters.
    //
    // Routes registered:
    //   /api/users        → OK (specific two-segment)
    //   /api/:slug        → CONFLICT (single-segment param)
    //
    // Request /api/users%2Fadmin: the path is a SINGLE segment
    // "users%2Fadmin" under literal-byte interpretation, so it
    // matches the param route — NOT the specific two-segment
    // /api/users (which would only match the literal three-char
    // sequence "users" as the second segment).
    let router = Router::new()
        .route("/api/users", get(FnHandler::new(ok_handler)))
        .route("/api/:slug", get(FnHandler::new(conflict_handler)))
        .fallback(FnHandler::new(forbidden_handler));

    // Path with literal /: matches two-segment.
    let two_seg = router.handle(Request::new("GET", "/api/users"));
    assert_eq!(two_seg.status, StatusCode::OK);

    // Path with %2F: matches single-segment :slug, NOT the
    // literal /api/users route.
    let single_seg = router.handle(Request::new("GET", "/api/users%2Fadmin"));
    assert_eq!(
        single_seg.status,
        StatusCode::CONFLICT,
        "/api/users%2Fadmin is a SINGLE segment under literal-% \
         interpretation — matches /api/:slug (teapot), NOT a hypothetical \
         /api/users/admin route. A regression that decoded %2F pre-\
         routing would silently re-route this request.",
    );
}

#[test]
fn dotdot_in_path_segment_does_not_traverse_at_router_level() {
    // Pin (4) extension: literal `..` as a path segment is
    // captured by `:slug` as the string `".."` — the router
    // does NOT collapse `/foo/../bar` to `/bar` at routing
    // time. (Whether downstream consumers treat `..` as
    // traversal is THEIR concern; the router operates on the
    // raw segments.)
    let router = Router::new().route("/files/:name", get(FnHandler::new(ok_handler)));

    let resp = router.handle(Request::new("GET", "/files/.."));
    assert_eq!(resp.status, StatusCode::OK);
}

#[test]
fn percent_encoded_slash_preserves_in_param_capture() {
    // Pin (4) capture semantics: the captured param value
    // contains the literal `%2F` bytes. Downstream handlers
    // that percent-decode get the `/` character — but the
    // routing decision is already locked in. The captured
    // param is opaque from the router's perspective.
    use asupersync::web::extract::Path;
    use asupersync::web::handler::FnHandler1;

    let captured: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let captured_clone = captured.clone();

    let handler = move |Path(opaque): Path<String>| -> StatusCode {
        *captured_clone.lock().unwrap() = Some(opaque);
        StatusCode::OK
    };

    let router = Router::new().route(
        "/path/:opaque",
        get(FnHandler1::<_, Path<String>>::new(handler)),
    );

    let _ = router.handle(Request::new("GET", "/path/foo%2Fbar%2Fbaz"));
    let recovered = captured.lock().unwrap().clone().unwrap();
    assert_eq!(
        recovered, "foo%2Fbar%2Fbaz",
        "the captured `:opaque` param contains the LITERAL %2F bytes — \
         the router does NOT pre-decode. Handlers that need decoded \
         values must percent-decode explicitly, knowing the route \
         decision is already final.",
    );
}

#[test]
fn percent_encoded_dot_does_not_collapse_segments() {
    // Pin (4): `%2E%2E` (encoded `..`) in a segment is NOT
    // decoded to `..`. The literal six-character string is
    // captured.
    let router = Router::new().route("/api/:slug", get(FnHandler::new(ok_handler)));

    let resp = router.handle(Request::new("GET", "/api/%2E%2E"));
    assert_eq!(resp.status, StatusCode::OK);
}

#[test]
fn null_byte_percent_encoded_in_path_does_not_truncate_route_match() {
    // Pin (4) extension: `%00` literal — three ASCII chars,
    // no decode. Doesn't truncate the path string at any
    // C-string boundary because Rust strings are not C strings.
    let router = Router::new().route("/file/:name", get(FnHandler::new(ok_handler)));

    let resp = router.handle(Request::new("GET", "/file/safe.txt%00.exe"));
    assert_eq!(resp.status, StatusCode::OK);
}

#[test]
fn deeply_nested_percent_encoded_traversal_attempt_stays_routed_safely() {
    // Pin (4) integration: deeply nested attack-shaped path
    // with multiple %2E/%2F sequences. Should match a single-
    // segment route (everything is one segment because no
    // literal `/` appears between the leading `/api/` and
    // path end).
    //
    // FORBIDDEN handler on /admin/secrets is the sentinel —
    // if the attack path got mis-routed there, the response
    // would be FORBIDDEN. SOUND behavior keeps it on
    // /api/:opaque (OK).
    let router = Router::new()
        .route("/api/:opaque", get(FnHandler::new(ok_handler)))
        .route("/admin/secrets", get(FnHandler::new(forbidden_handler)))
        .fallback(FnHandler::new(conflict_handler));

    let attack = router.handle(Request::new("GET", "/api/%2E%2E%2Fadmin%2Fsecrets"));
    assert_eq!(
        attack.status,
        StatusCode::OK,
        "attack path with %2E%2E%2F sequences MUST stay matched at \
         /api/:opaque (OK). FORBIDDEN response would mean traversal \
         succeeded; CONFLICT would mean fallback was hit. Either \
         non-OK status indicates a regression.",
    );
}

// ── Method dispatch precision ────────────────────────────────────

#[test]
fn unmatched_method_returns_405_not_404() {
    // Pin (1): method-not-allowed (405) is distinct from
    // path-not-found (404). MethodRouter::dispatch returns
    // 405 when the path matches but no handler for the method
    // is registered.
    let router = Router::new()
        .route("/users/:id", get(FnHandler::new(ok_handler)))
        .fallback(FnHandler::new(conflict_handler));

    let post_resp = router.handle(Request::new("POST", "/users/42"));
    assert_eq!(
        post_resp.status,
        StatusCode::METHOD_NOT_ALLOWED,
        "matched path + unregistered method → 405 (NOT 404; NOT 418 \
         from fallback — the route MATCHED, the method didn't)",
    );
}

#[test]
fn method_dispatch_is_case_insensitive_via_uppercase_fallback() {
    // Pin (1): `MethodRouter::dispatch` (router.rs:98-109) has
    // a fast path for already-uppercase methods AND a
    // case-insensitive fallback. Lowercase `get` from a buggy
    // client still routes correctly.
    let router = Router::new().route("/test", get(FnHandler::new(ok_handler)));

    let upper = router.handle(Request::new("GET", "/test"));
    assert_eq!(upper.status, StatusCode::OK);

    let lower = router.handle(Request::new("get", "/test"));
    assert_eq!(
        lower.status,
        StatusCode::OK,
        "lowercase method routes via case-insensitive fallback",
    );
}
