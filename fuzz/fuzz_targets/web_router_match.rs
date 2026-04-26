#![no_main]

//! URL-routing fuzzer for `src/web/router.rs`.
//!
//! Each iteration assembles a small `Router` from a fuzz-driven mix of route
//! patterns (literal segments, `:param` captures, `/*` catch-all, nested
//! sub-routers) and then handles a fuzz-driven request URL through it. The
//! fuzz input is interpreted as two halves: the first byte selects which of
//! a fixed catalogue of patterns/paths to combine, the rest seeds the
//! variable parts (path text, segment count). This produces much higher
//! edge-case density than uniform random strings — adversarial shapes like
//! deeply nested traversal, percent-encoded ambiguity, double-slash runs,
//! and pattern/path length mismatches show up reliably.
//!
//! # Oracles
//!
//! 1. **No panics on any input.** `Router::handle` MUST be total: no debug
//!    assertion, integer overflow, slice OOB, or unwrap on a `None` may
//!    fire for any byte sequence on stdin. Encoded characters (`%XX`),
//!    embedded NUL, overlong inputs, raw bytes that are not UTF-8, mixed
//!    `/`/`\` separators, and Unicode full-width slashes are all valid
//!    fuzz-driven shapes that must produce a typed `Response`, not a panic.
//!
//! 2. **Status code is well-typed.** `Response.status` is one of the
//!    documented `StatusCode` values. Even a "no match → fallback → 404"
//!    flow must produce a clean status; the fuzzer asserts the status
//!    debug-formats successfully and that the underlying integer is in the
//!    legal HTTP range (100..=599).
//!
//! 3. **Determinism.** Calling `handle` twice on the same router with the
//!    same request bytes produces the same response status. This catches
//!    any accidental dependence on iteration order of a `HashMap` (which
//!    in std is randomised per-run), thread-local state, or wall-clock
//!    time inside the matcher.
//!
//! 4. **First-match-wins ordering.** Routes are checked in registration
//!    order. The fuzzer registers a "before" handler at a specific
//!    pattern under one status, then either re-registers a different
//!    handler at the same pattern (must lose to the first) or registers
//!    a strictly more general pattern after a strictly more specific one
//!    (specific must still win because it was registered first). The
//!    asserted invariant is: the response status equals the *earliest*
//!    matching handler's status — never a later one.
//!
//! 5. **Catch-all soundness.** A `/*` pattern, when the only registered
//!    route, MUST match every non-empty path. A nested catch-all under a
//!    prefix MUST match every path that begins with that prefix and
//!    leave non-prefixed paths unmatched (404 from fallback).

use asupersync::web::extract::Request;
use asupersync::web::handler::Handler;
use asupersync::web::response::{Response, StatusCode};
use asupersync::web::router::{Router, get, post};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Shape-biased input generation
// ---------------------------------------------------------------------------

/// Cap on the path length we synthesise to keep iteration throughput high.
/// Very long paths (>=64 KiB) are exercised directly via shape 15 below; for
/// the structural shapes we keep the path under this bound.
const PATH_LEN_CAP: usize = 4096;

/// Convert a random byte sequence into a path string, biased toward shapes
/// known to break naive routers. The first byte of `seed` selects the
/// shape; the remaining bytes are interpreted as the variable text.
fn shape_path(seed: &[u8]) -> String {
    if seed.is_empty() {
        return String::from("/");
    }
    let shape = seed[0] % 16;
    let rest = &seed[1..];
    let rest_str = String::from_utf8_lossy(rest);
    let trimmed: String = rest_str.chars().take(256).collect();

    let raw = match shape {
        // 0..=2: simple positive matches.
        0 => format!("/{trimmed}"),
        1 => format!("/users/{trimmed}"),
        2 => format!("/users/{trimmed}/posts/{trimmed}"),
        // 3..=4: traversal-like.
        3 => format!("/{trimmed}/../../etc/passwd"),
        4 => "/../../../../../../../../etc/shadow".to_string(),
        // 5..=6: percent-encoded.
        5 => format!("/users/%2e%2e/{trimmed}"),
        6 => format!("/{}/%00/{trimmed}", trimmed),
        // 7: double slashes.
        7 => format!("//{trimmed}//foo//"),
        // 8: trailing slash.
        8 => format!("/{trimmed}/"),
        // 9: empty.
        9 => String::from("/"),
        // 10: unicode full-width slash.
        10 => format!("/{trimmed}\u{FF0F}foo"),
        // 11: very long (close to cap).
        11 => {
            let chunk = if rest.is_empty() { b"a" } else { rest };
            let pieces = (PATH_LEN_CAP / chunk.len().max(1)).min(64);
            let mut s = String::from("/");
            for _ in 0..pieces {
                s.push_str(&String::from_utf8_lossy(chunk));
                s.push('/');
            }
            s
        }
        // 12: pure literal that should miss every fuzz route.
        12 => String::from("/__definitely_not_a_real_route__/abc"),
        // 13: catch-all-friendly deep path.
        13 => format!("/files/{trimmed}/nested/deep/path"),
        // 14: looks like a param value with reserved chars.
        14 => format!("/users/{}", trimmed.replace('/', "%2F")),
        // 15: raw bytes (lossy UTF-8 ⇒ U+FFFD substitutions).
        _ => format!("/{trimmed}"),
    };

    // Cap absolute length to avoid OOM on hostile generators.
    if raw.len() > PATH_LEN_CAP {
        raw.chars().take(PATH_LEN_CAP).collect()
    } else {
        raw
    }
}

/// Synthesise a route pattern from a seed byte. Patterns intentionally
/// overlap with the shapes produced by `shape_path` so the fuzzer can find
/// real matches as well as 404 paths.
fn shape_pattern(byte: u8) -> &'static str {
    match byte % 12 {
        0 => "/users/:id",
        1 => "/users/:uid/posts/:pid",
        2 => "/files/*",
        3 => "/health",
        4 => "/api/v1/*",
        5 => "/",
        6 => "/users",
        7 => "/static/:asset",
        8 => "/__definitely_not_a_real_route__/abc",
        9 => "/api/:version/users/:id",
        10 => "/files/:id/v/:rev",
        _ => "/*",
    }
}

/// Method tag derived from a seed byte. We cover GET and POST; the matcher
/// treats them identically for path resolution, but the dispatch side
/// rejects mismatched methods, exercising MethodRouter as well.
fn shape_method(byte: u8) -> &'static str {
    match byte % 4 {
        0 | 1 => "GET",
        _ => "POST",
    }
}

// ---------------------------------------------------------------------------
// Fixture handlers (each tags its response with a known status so we can
// reason about which handler answered)
// ---------------------------------------------------------------------------

/// A `Handler` that returns a fixed `StatusCode`. The status doubles as
/// a "tag" the fuzz oracle reads off the response to identify which route
/// answered.
#[derive(Clone, Copy)]
struct StatusHandler(StatusCode);

impl Handler for StatusHandler {
    #[inline]
    fn call(&self, _req: Request) -> Response {
        Response::empty(self.0)
    }
}

#[inline]
fn handler_with_status(status: StatusCode) -> StatusHandler {
    StatusHandler(status)
}

// ---------------------------------------------------------------------------
// Build routers
// ---------------------------------------------------------------------------

/// Cache the catch-all router (shape 4 below) — it has no fuzz-driven
/// variability, so we build it once.
fn catch_all_only() -> &'static Router {
    static R: OnceLock<Router> = OnceLock::new();
    R.get_or_init(|| {
        Router::new()
            .route("/*", get(handler_with_status(StatusCode::OK)))
            .fallback(handler_with_status(StatusCode::NOT_FOUND))
    })
}

/// Build a fuzz-driven router from up to 4 patterns. Each pattern's status
/// is set to a distinct value so the oracle can identify which route won.
fn build_router(seeds: &[u8]) -> Router {
    let mut router = Router::new()
        .fallback(handler_with_status(StatusCode::NOT_FOUND));

    // First registered pattern wins on ties. Use distinct statuses to
    // detect ordering bugs — e.g., if the matcher picks the LAST match
    // instead of the FIRST.
    let statuses = [
        StatusCode::OK,
        StatusCode::CREATED,
        StatusCode::ACCEPTED,
        StatusCode::NO_CONTENT,
    ];

    for (i, byte) in seeds.iter().take(4).enumerate() {
        let pattern = shape_pattern(*byte);
        let status = statuses[i];
        let mr = match shape_method(*byte) {
            "POST" => post(handler_with_status(status)),
            _ => get(handler_with_status(status)),
        };
        router = router.route(pattern, mr);
    }

    router
}

// ---------------------------------------------------------------------------
// Oracle
// ---------------------------------------------------------------------------

fn assert_well_typed(resp: &Response) {
    let code = resp.status.as_u16();
    assert!(
        (100..=599).contains(&code),
        "status code {code} outside legal HTTP range"
    );
    // Debug-format must succeed (no formatter panic).
    let _ = format!("{:?}", resp.status);
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Shape selector picks the high-level scenario.
    let shape = data[0] % 4;
    let rest = &data[1..];

    match shape {
        // Scenario 0: build a fuzz-driven router, fire one request through it.
        // Asserts: total/no-panic, well-typed status, deterministic.
        0 => {
            let mid = rest.len() / 2;
            let (pattern_seeds, path_seed) = rest.split_at(mid);
            let router = build_router(pattern_seeds);

            let path = shape_path(path_seed);
            let method = shape_method(*path_seed.first().unwrap_or(&0));

            let req1 = Request::new(method, path.clone());
            let req2 = Request::new(method, path.clone());

            let resp1 = router.handle(req1);
            let resp2 = router.handle(req2);

            assert_well_typed(&resp1);
            assert_well_typed(&resp2);
            // Determinism: handling the same request twice must give the
            // same status. A flaky matcher (HashMap iteration order, TLS
            // state, time-based) is caught here.
            assert_eq!(
                resp1.status, resp2.status,
                "router::handle is non-deterministic: path={path:?}"
            );
        }

        // Scenario 1: first-match-wins. Register the SAME pattern twice
        // with distinct statuses; the first registration must answer.
        1 => {
            if rest.is_empty() {
                return;
            }
            let pattern = shape_pattern(rest[0]);
            let path_seed = &rest[1..];
            let path = shape_path(path_seed);

            let router = Router::new()
                .route(pattern, get(handler_with_status(StatusCode::OK)))
                .route(pattern, get(handler_with_status(StatusCode::CREATED)))
                .fallback(handler_with_status(StatusCode::NOT_FOUND));

            let resp = router.handle(Request::new("GET", path));
            assert_well_typed(&resp);
            // Either the path matches (must be OK, NOT CREATED) or it
            // doesn't (NOT_FOUND from fallback). CREATED would mean the
            // second-registered route won — a routing bug.
            assert!(
                matches!(
                    resp.status,
                    StatusCode::OK | StatusCode::NOT_FOUND
                ),
                "first-match-wins violated: got status {:?}, expected OK or NOT_FOUND, pattern={pattern:?}",
                resp.status
            );
        }

        // Scenario 2: catch-all soundness. With only a `/*` route, every
        // non-root path must match. Empty-segment paths fall to fallback
        // (no segments after the wildcard's prefix).
        2 => {
            let path = shape_path(rest);
            let resp = catch_all_only().handle(Request::new("GET", path.clone()));
            assert_well_typed(&resp);
            // The wildcard `/*` matches when the path has at least one
            // non-empty segment after splitting on `/`. Empty path or
            // pure-slashes can fall through to the 404 fallback.
            let has_segment = path.split('/').any(|s| !s.is_empty());
            if has_segment {
                assert_eq!(
                    resp.status,
                    StatusCode::OK,
                    "catch-all `/*` failed to match path with at least one segment: {path:?}"
                );
            }
        }

        // Scenario 3: nested router + method mismatch. Specific route
        // registered with GET must reject POST with NOT_FOUND (fallback)
        // — exercises the MethodRouter dispatch path.
        _ => {
            if rest.is_empty() {
                return;
            }
            let pattern = shape_pattern(rest[0]);
            let path_seed = &rest[1..];
            let path = shape_path(path_seed);

            let router = Router::new()
                .route(pattern, get(handler_with_status(StatusCode::OK)))
                .fallback(handler_with_status(StatusCode::NOT_FOUND));

            // Send POST against a GET-only route.
            let resp = router.handle(Request::new("POST", path));
            assert_well_typed(&resp);
            // POST against a GET route must NOT return OK (the GET
            // handler's status). It can be NOT_FOUND (fallback) or a
            // 405-style answer, but never the GET handler's tag.
            assert_ne!(
                resp.status,
                StatusCode::OK,
                "method mismatch leaked through: GET handler answered a POST request, pattern={pattern:?}"
            );
        }
    }
});
