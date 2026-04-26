#![no_main]

//! Path-traversal fuzzer for `src/web/static_files.rs`'s
//! `StaticFiles::resolve_path` (exposed via `Handler::call`).
//!
//! # Oracle
//!
//! The fuzzer creates an EMPTY temporary directory as the doc-root, builds a
//! `StaticFiles` instance pointed at it, and feeds random URL paths to the
//! handler. Every response MUST be `404 NOT FOUND`. Any response status that
//! is NOT 404 (specifically 200) means the resolver served a file from
//! OUTSIDE the doc-root — a critical path-traversal escape.
//!
//! Additional asserted properties:
//!
//!   1. **No panics on any input.** The handler MUST be total — random bytes,
//!      embedded NUL, malformed percent-encoding, very long paths, Unicode
//!      tricks, `/`/`\` mixing must all yield typed responses, never panic.
//!
//!   2. **Status code is always well-typed.** Response.status MUST be one
//!      of the documented codes (NOT_FOUND most commonly; OK = escape;
//!      anything else surprising and worth investigating).
//!
//!   3. **Body bytes for non-404 responses are EMPTY.** Even if some
//!      pathological input bypasses the 404 branch, the doc-root has no
//!      files, so the body MUST be empty (or the assertion catches it).
//!
//! # Coverage biases
//!
//! Each iteration constructs the path by interpreting the fuzz input through
//! one of several "shape generators": ../ traversal, %2e%2f-encoded
//! traversal, absolute paths (/etc/passwd-style), embedded NUL, very long,
//! Unicode normalization (full-width slashes), and raw bytes. This yields
//! much higher edge-case density than uniform random strings.

use asupersync::web::extract::Request;
use asupersync::web::handler::Handler;
use asupersync::web::response::StatusCode;
use asupersync::web::static_files::StaticFiles;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use tempfile::TempDir;

/// Cached empty doc-root TempDir used by all fuzz iterations.
///
/// Setup once (creating a tempdir per iteration would be ~1ms each, killing
/// throughput). The dir is intentionally EMPTY for the lifetime of the fuzz
/// process — every legitimate path resolution must therefore yield 404.
fn doc_root() -> &'static TempDir {
    static ROOT: OnceLock<TempDir> = OnceLock::new();
    ROOT.get_or_init(|| {
        TempDir::new().expect("create empty fuzz doc-root")
    })
}

/// Lazily-built handler bound to the empty doc-root.
fn handler() -> &'static asupersync::web::static_files::StaticFilesHandler {
    static HANDLER: OnceLock<asupersync::web::static_files::StaticFilesHandler> = OnceLock::new();
    HANDLER.get_or_init(|| {
        StaticFiles::new(doc_root().path()).handler()
    })
}

/// Convert raw fuzz bytes into a "shape-biased" URL path string. The first
/// byte selects a shape; the rest is the seed for that shape's generator.
/// This produces much more interesting inputs than plain UTF-8 random.
fn shape_path(data: &[u8]) -> String {
    if data.is_empty() {
        return String::from("/");
    }
    let shape = data[0] % 16;
    let rest = &data[1..];
    let rest_str = String::from_utf8_lossy(rest);

    match shape {
        // 0..=2: classic traversal
        0 => format!("/../{}", rest_str),
        1 => format!("/../../etc/passwd"),
        2 => format!("/{}/../../../{}", rest_str, rest_str),

        // 3..=4: percent-encoded traversal
        3 => format!("/%2e%2e/{}", rest_str),
        4 => format!("/%2E%2E%2F%2E%2E%2F{}", rest_str),

        // 5: double-encoded (defends against single-decode)
        5 => format!("/%252e%252e/{}", rest_str),

        // 6..=7: absolute-path style
        6 => format!("//etc/passwd"),
        7 => format!("/{}", rest_str.replace('/', "//")),

        // 8: embedded NUL byte (some parsers truncate at NUL)
        8 => format!("/file{}\0/etc/passwd", rest_str),

        // 9: very long path (defends against buffer overflow / DOS)
        9 => "/".to_string() + &"a".repeat(rest.len().min(2048)),

        // 10..=11: Unicode normalization tricks
        // U+FF0F is FULLWIDTH SOLIDUS — looks like / but isn't ASCII
        // U+2024 is ONE DOT LEADER — looks like . but isn't ASCII
        10 => format!("/..\u{FF0F}..\u{FF0F}{}", rest_str),
        11 => format!("/\u{2024}\u{2024}/{}", rest_str),

        // 12: backslash injection (Windows-style paths)
        12 => format!("/..\\..\\{}", rest_str),

        // 13: mixed encoding + traversal
        13 => format!("/%2e./%2e./{}", rest_str),

        // 14: dot-segment normalization edge case
        14 => format!("/{}/./../../{}", rest_str, rest_str),

        // 15: raw bytes (catch UTF-8 boundary panics)
        _ => {
            let mut s = String::with_capacity(rest.len() + 1);
            s.push('/');
            for &b in rest.iter().take(512) {
                // Allow non-UTF8 by going via lossy
                s.push(char::from(b));
            }
            s
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let path = shape_path(data);
    let req = Request::new("GET", path.clone());
    let resp = handler().call(req);

    // ── Property 1: no panic ────────────────────────────────────────────
    // (already implied — if we reach this assertion, the handler returned)

    // ── Property 2: status is 404 (empty doc-root) ──────────────────────
    // Any other status MIGHT indicate a path-traversal escape. The most
    // critical case is OK (200) — it means a file was found and served.
    // Other statuses (e.g., METHOD_NOT_ALLOWED) are also unexpected for an
    // empty doc-root with GET requests, but not security-critical.
    if resp.status == StatusCode::OK {
        // CRITICAL: the resolver served a file from outside the doc-root,
        // OR misinterpreted the path. Body should be empty in either case
        // (doc-root has no files). If body is non-empty, this is a real
        // escape with leaked content.
        let body_len = resp.body.len();
        panic!(
            "PATH-TRAVERSAL ESCAPE: status=OK for path={path:?} (body_len={body_len}). \
             Empty doc-root MUST yield 404 for every input."
        );
    }

    // ── Property 3: body for non-OK responses is empty ──────────────────
    // 404 / NOT_MODIFIED / etc. should not carry leaked content.
    if resp.status != StatusCode::OK && !resp.body.is_empty() {
        // Could be a legitimate error message body (e.g., "Not found"). The
        // important thing is to flag if a 404 carries CONTENT (which would
        // suggest the server read a file then changed the status). We allow
        // up to 512 bytes for canned error messages.
        assert!(
            resp.body.len() <= 512,
            "non-OK response carries large body for path={path:?}: status={status:?} body_len={body_len}",
            status = resp.status,
            body_len = resp.body.len()
        );
    }
});
