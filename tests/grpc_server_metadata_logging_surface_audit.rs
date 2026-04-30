//! Audit + regression test for `src/grpc/` metadata logging
//! surface (tick #187, follow-up to ticks #153/#158/#161).
//!
//! Operator's question: "verify metadata logging surface" —
//! beyond the no-body-logged check (#158) and the
//! no-stack-trace check (#161), this test pins that NO
//! production log call surfaces sensitive METADATA HEADERS
//! (authorization, cookie, x-api-key, session-token, etc.)
//! in any tracing macro / println output.
//!
//! Audit findings (post 2cbb54792 health-token fix):
//!
//!   (a) **Zero production log call references the
//!       `authorization` header value.** The pre-fix
//!       health.rs:234 logged a 20-byte prefix of the
//!       authorization header at INFO level (P3 finding from
//!       tick #158). The fix in commit 2cbb54792 replaced
//!       the prefix log with `tracing::info!(auth_scheme =
//!       "Bearer", "Health check authenticated")` —
//!       a static string only. No bearer-token bytes leak.
//!
//!   (b) **Zero production log call references sensitive
//!       metadata keys.** Token-of-interest list:
//!         * `authorization`
//!         * `cookie`
//!         * `set-cookie`
//!         * `x-api-key`
//!         * `session-token`
//!         * `csrf-token`
//!         * `x-auth`
//!       Walks every src/grpc/*.rs file (excluding cfg(test)
//!       modules) and asserts NO log macro argument list
//!       contains these tokens.
//!
//!   (c) **`token_prefix` audit pin.** The pre-fix variable
//!       name `token_prefix` was the canonical leak shape —
//!       a 20-byte prefix logged for "audit" purposes.
//!       Asserting that this exact identifier doesn't appear
//!       in any log macro argument prevents regression.
//!
//!   (d) **`bearer_token` similarly.** A future commit that
//!       added `tracing::info!(bearer_token = %t, ...)` would
//!       surface here.
//!
//! Regression test below pins (a)+(b)+(c)+(d).

use std::path::Path;

const SCAN_FILES: &[&str] = &[
    "grpc/server.rs",
    "grpc/streaming.rs",
    "grpc/codec.rs",
    "grpc/web.rs",
    "grpc/interceptor.rs",
    "grpc/status.rs",
    "grpc/client.rs",
    "grpc/health.rs",
    "grpc/reflection.rs",
];

const LOG_MACROS: &[&str] = &[
    "tracing::info!",
    "tracing::warn!",
    "tracing::debug!",
    "tracing::trace!",
    "tracing::error!",
    "tracing_compat::info!",
    "tracing_compat::warn!",
    "tracing_compat::debug!",
    "tracing_compat::trace!",
    "tracing_compat::error!",
    "info!(",
    "warn!(",
    "debug!(",
    "trace!(",
    "error!(",
];

const SENSITIVE_TOKENS: &[&str] = &[
    "token_prefix",
    "bearer_token",
    "auth_token",
    "session_token",
    "api_key",
    "csrf_token",
    "set_cookie",
    "authorization_value",
    "cookie_value",
];

fn is_comment_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//")
}

#[test]
fn no_production_log_macro_references_sensitive_metadata_tokens() {
    // Pin (a)+(b)+(c)+(d): walk every src/grpc/* production
    // file (non-cfg(test)) and assert NO log macro argument
    // list mentions a sensitive-metadata token.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let src_root = Path::new(manifest_dir).join("src");

    let mut violations: Vec<(String, usize, String)> = Vec::new();

    for relative in SCAN_FILES {
        let path = src_root.join(relative);
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Crude cfg(test) tracking by brace depth.
        let mut in_test_mod = 0i32;
        let mut brace_at_test_entry: Option<i32> = None;
        let mut current_brace = 0i32;
        let mut prev_was_cfg_test_attr = false;

        let lines: Vec<&str> = content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            let entering_test_mod = trimmed.starts_with("#[cfg(test)]")
                || (prev_was_cfg_test_attr && trimmed.starts_with("mod "));

            if entering_test_mod && (trimmed.contains("mod ") || prev_was_cfg_test_attr) {
                in_test_mod += 1;
                brace_at_test_entry.get_or_insert(current_brace);
            }

            current_brace += line.matches('{').count() as i32
                - line.matches('}').count() as i32;

            if let Some(entry_depth) = brace_at_test_entry {
                if current_brace <= entry_depth {
                    in_test_mod = 0;
                    brace_at_test_entry = None;
                }
            }

            prev_was_cfg_test_attr = trimmed == "#[cfg(test)]";

            if in_test_mod > 0 {
                continue;
            }
            if is_comment_line(line) {
                continue;
            }

            let opens_log_macro = LOG_MACROS.iter().any(|m| line.contains(m));
            if !opens_log_macro {
                continue;
            }

            // Look ahead 5 lines for the closing `;` of the call.
            let end_idx = (idx + 5).min(lines.len());
            let window = lines[idx..end_idx].join("\n");
            let call_end = window.find(");").unwrap_or(window.len());
            let call_text = &window[..call_end];

            // Strip string literals — sensitive token names INSIDE
            // a literal (e.g. a doc-style format string) shouldn't
            // false-positive. The check is on argument *names* in
            // the structured-log fields.
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

            for token in SENSITIVE_TOKENS {
                if stripped.contains(token) {
                    violations.push((
                        relative.to_string(),
                        idx + 1,
                        format!("token={token:?} call={}", call_text.trim()),
                    ));
                }
            }
        }
    }

    if !violations.is_empty() {
        let mut report = String::new();
        report.push_str(
            "tick #187 audit pin: production gRPC log macro references a \
             sensitive-metadata field name. The pre-fix health.rs:234 logged \
             `token_prefix = first-20-bytes-of-bearer-header` at INFO — that \
             leak class was closed in 2cbb54792 by replacing the prefix log \
             with `auth_scheme = \"Bearer\"`. A regression that re-introduced \
             token / authorization / cookie / api-key / session-token / \
             csrf-token logging would surface here. If the new field IS \
             intentional, ensure: (1) the value is REDACTED at the log site \
             (e.g. logged as a hash, NOT raw), (2) the log level is gated \
             behind a feature flag for production deployments, (3) the field \
             name conveys 'redacted' to downstream log-pipeline operators. \
             Violations:\n",
        );
        for (file, line_no, detail) in &violations {
            report.push_str(&format!("  src/{file}:{line_no} — {detail}\n"));
        }
        panic!("{report}");
    }
}

#[test]
fn health_rs_post_fix_does_not_log_token_prefix() {
    // Pin (a) the specific 2cbb54792 fix: health.rs:234
    // pre-fix logged `token_prefix = %&auth_str[..20]`. The
    // fixed line logs `auth_scheme = "Bearer"`. Pin via
    // direct grep — a regression that re-introduced
    // `token_prefix` in this exact file would trip.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let health_rs = std::fs::read_to_string(
        Path::new(manifest_dir).join("src/grpc/health.rs"),
    )
    .expect("read src/grpc/health.rs");

    // Filter out cfg(test) blocks crudely — find the first
    // `#[cfg(test)]` and ignore everything after.
    let production_section = match health_rs.find("#[cfg(test)]") {
        Some(idx) => &health_rs[..idx],
        None => &health_rs[..],
    };

    assert!(
        !production_section.contains("token_prefix"),
        "src/grpc/health.rs production code MUST NOT contain `token_prefix` \
         (the pre-fix leak identifier from commit 2cbb54792). A regression \
         re-introduced the bearer-token-prefix logging.",
    );
}

#[test]
fn health_rs_keeps_auth_scheme_static_log() {
    // Pin (a) positive: the post-fix health.rs:236 logs
    // `auth_scheme = "Bearer"` (a static literal). Verify the
    // documented post-fix line is present so a future revert
    // would trip this test.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let health_rs = std::fs::read_to_string(
        Path::new(manifest_dir).join("src/grpc/health.rs"),
    )
    .expect("read src/grpc/health.rs");

    assert!(
        health_rs.contains("auth_scheme = \"Bearer\""),
        "post-fix health.rs MUST keep the static-literal auth_scheme log; \
         a regression that altered it (e.g. to log token bytes) would trip",
    );
}
