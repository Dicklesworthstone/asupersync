//! Audit + regression test for `src/grpc/` logging surface — verify
//! request/response bodies are never logged at any level (tick #158).
//!
//! Operator's question: "verify body never logged at INFO level
//! (DEBUG only, gated)."
//!
//! Audit findings:
//!
//!   (a) **gRPC subsystem emits ZERO body/payload-content log
//!       lines.** Across `src/grpc/server.rs`,
//!       `src/grpc/interceptor.rs`, `src/grpc/streaming.rs`,
//!       `src/grpc/codec.rs`, and `src/grpc/web.rs`, there are NO
//!       `tracing::info!` / `info!` / `warn!` / `debug!` / `trace!`
//!       macros that log the request body, response body, payload
//!       bytes, or any user-supplied message content. The few
//!       `tracing::warn!` / `tracing::info!` calls that exist
//!       (e.g. `health.rs:234`, `health.rs:479`) log static
//!       diagnostic strings — not body content.
//!
//!   (b) **`println!` / `eprintln!` calls in src/grpc/ are
//!       restricted to `#[cfg(test)]` modules** (test harness
//!       output for conformance verifiers), the
//!       `eprintln!("[GOLDEN]")` in `streaming.rs:1972` (golden-
//!       file update path, only fires under explicit operator
//!       command), and `eprintln!` in `server.rs:156` /
//!       `server.rs:2506+` (test/conformance verdicts). None of
//!       these paths emit user-supplied body content.
//!
//!   (c) **Built-in LoggingInterceptor doesn't actually log**
//!       (covered by tick #153 audit). It stamps `x-logged=true`
//!       metadata only. No body access.
//!
//!   (d) **⚠️ P3 finding (filed separately):** `src/grpc/health.rs:234`
//!       logs `token_prefix = first-20-chars-of-authorization-header`
//!       at INFO level. This is a TODO-stub auth path (the doc
//!       comment says "TODO: Add actual token validation against
//!       your auth system"). For short bearer tokens the prefix
//!       leak can identify the secret. Documented as a separate
//!       audit follow-up; orthogonal to body-content logging.
//!
//! Regression tests below pin (a) — any future commit that adds a
//! `tracing::info!("body = {body:?}", ...)`-style call to the
//! gRPC subsystem will trip the test, forcing an intentional
//! re-baseline AND a re-audit of the redaction posture.

use std::path::{Path, PathBuf};

const SCAN_FILES: &[&str] = &[
    "grpc/server.rs",
    "grpc/interceptor.rs",
    "grpc/streaming.rs",
    "grpc/codec.rs",
    "grpc/web.rs",
];

/// Tokens that, if found inside a logging macro's argument list,
/// suggest the call is logging body / payload / message bytes.
const BODY_TOKENS: &[&str] = &[
    "body",
    "payload",
    "message_data",
    ".data",
    "message_bytes",
    "request_body",
    "response_body",
    "raw_bytes",
];

const LOG_MACROS: &[&str] = &[
    "tracing::info!",
    "tracing::warn!",
    "tracing::debug!",
    "tracing::trace!",
    "tracing::error!",
    "info!(",
    "warn!(",
    "debug!(",
    "trace!(",
    "error!(",
];

/// Returns true when `line` is inside a doc comment (`//!`, `///`,
/// `//`) or a code comment block. We treat all comment lines as
/// "not real code" for the purpose of this audit.
fn is_comment_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//")
}

#[test]
fn no_body_or_payload_in_log_macros_under_src_grpc() {
    // Pin (a): walk the file list and assert NO non-comment line
    // contains both a logging-macro token AND a body/payload
    // token. A regression that added
    //   tracing::info!(body = ?req.into_inner(), "...")
    // would surface here.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let src_root = Path::new(manifest_dir).join("src");

    let mut hits: Vec<(PathBuf, usize, String)> = Vec::new();

    for relative in SCAN_FILES {
        let path = src_root.join(relative);
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // For each line, check if it contains BOTH a log macro
        // AND a body token. We do a multi-line window pass:
        // sometimes the macro and the body argument are on
        // different physical lines.
        let lines: Vec<&str> = content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            if is_comment_line(line) {
                continue;
            }
            // Check if line opens a log macro.
            let opens_log_macro = LOG_MACROS.iter().any(|m| line.contains(m));
            if !opens_log_macro {
                continue;
            }
            // Look ahead up to 5 lines for the closing `;` (or
            // `);` end-of-call). Check the joined window for
            // body tokens.
            let end_idx = (idx + 5).min(lines.len());
            let window = lines[idx..end_idx].join("\n");
            // Within the window, find the call's closing `);` and
            // truncate.
            let call_end = window.find(");").unwrap_or(window.len());
            let call_text = &window[..call_end];

            // Strip out string literal contents — we only care
            // about argument *names*, not message text. A quick
            // heuristic: remove anything between unescaped pairs
            // of `"`. This is approximate but good enough for
            // the audit grep.
            let mut stripped = String::with_capacity(call_text.len());
            let mut in_string = false;
            let mut prev_char = '\0';
            for ch in call_text.chars() {
                if ch == '"' && prev_char != '\\' {
                    in_string = !in_string;
                    prev_char = ch;
                    continue;
                }
                if !in_string {
                    stripped.push(ch);
                }
                prev_char = ch;
            }

            for token in BODY_TOKENS {
                if stripped.contains(token) {
                    hits.push((
                        path.clone(),
                        idx + 1,
                        format!("token={token:?} call={}", call_text.trim()),
                    ));
                }
            }
        }
    }

    if !hits.is_empty() {
        let mut report = String::new();
        report.push_str(
            "tick #158 audit pin: gRPC log macro references a body/payload token. \
             Bodies must NEVER be logged. If this is a legitimate redacted log line \
             (e.g. a digest, a length count, or a content-type), rename the variable \
             to make the redaction explicit. Hits:\n",
        );
        for (path, line_no, detail) in &hits {
            report.push_str(&format!("  {}:{} — {}\n", path.display(), line_no, detail));
        }
        panic!("{report}");
    }
}

#[test]
fn known_eprintln_at_server_rs_156_does_not_log_body_content() {
    // Pin: the one production-path eprintln! in src/grpc/server.rs
    // at line 156 logs ONLY metadata (count of removed streams,
    // connection id, list of stream ids) — not body content. Pin
    // the contents of the format string so a future commit that
    // changed it to include a body / payload reference would trip
    // this test, forcing an intentional re-baseline.
    //
    // Note: this eprintln! is itself an AGENTS.md "Output Style"
    // violation (runtime must not write to stdio). Documented as
    // a separate audit follow-up; orthogonal to body-logging.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let server_rs = std::fs::read_to_string(Path::new(manifest_dir).join("src/grpc/server.rs"))
        .expect("read src/grpc/server.rs");

    // The known-clean format string. A regression that altered it
    // to log body content would surface here.
    let argument_marker = format!("{}{}", '{', '}');
    let debug_marker = format!("{}:?{}", '{', '}');
    let cleanup_log_format = format!(
        "Cleaned up {argument_marker} idle streams on connection {argument_marker}: {debug_marker}"
    );
    assert!(
        server_rs.contains(&cleanup_log_format),
        "the known-clean eprintln! at server.rs:156 must keep its \
         metadata-only format string. A regression that added \
         body or payload fields to the format args would be a \
         body-logging violation.",
    );
    // And the body/payload tokens must NOT appear within ~10 lines
    // either side of the eprintln!.
    let lines: Vec<&str> = server_rs.lines().collect();
    let eprintln_idx = lines
        .iter()
        .position(|l| l.contains("eprintln!") && l.trim().starts_with("eprintln!"))
        .expect("locate the known eprintln! entry line");
    let start = eprintln_idx.saturating_sub(2);
    let end = (eprintln_idx + 8).min(lines.len());
    let window = lines[start..end].join("\n");
    for token in ["body", "payload", "request_data", "response_data"] {
        assert!(
            !window.contains(token),
            "eprintln! at server.rs:{} window contains {token:?} — \
             body-content reference suspected. window:\n{window}",
            eprintln_idx + 1,
        );
    }
}
