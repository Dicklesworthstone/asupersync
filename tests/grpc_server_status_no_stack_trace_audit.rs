//! Audit + regression test for `src/grpc/status.rs` and the
//! Status::internal call sites (tick #161).
//!
//! Operator's question: "verify Status.message NOT containing
//! internal stack-traces."
//!
//! Audit findings:
//!
//!   (a) **No backtrace embedding anywhere in src/grpc/.**
//!       `grep -rnE 'backtrace|Backtrace::|std::backtrace' src/grpc/`
//!       returns ZERO hits. No call site captures a backtrace
//!       and passes it to `Status::new` / `Status::internal` /
//!       any constructor. The stack-trace-leak class is
//!       structurally absent.
//!
//!   (b) **No file!/line!/module_path! embedding.**
//!       `grep -rnE 'file!\\(|line!\\(|module_path!\\(' src/grpc/`
//!       returns ZERO hits in production code. (The macros are
//!       used in test assertion frameworks, not in Status
//!       messages.)
//!
//!   (c) **`MAX_STATUS_MESSAGE_LEN = 8 KiB` cap (status.rs:134)**
//!       is defense-in-depth. Even a regression that DID embed
//!       a backtrace in a message would be truncated at 8 KiB
//!       to bound the wire-frame impact. `cap_status_message`
//!       (status.rs:152) preserves UTF-8 char boundary, never
//!       panics on truncation (br-asupersync-uk2vsg).
//!
//!   (d) **Production Status::internal call sites use static or
//!       short error messages** — no `format!("{err:?}", err)`
//!       Debug-format embedding of internal types. Audit-checked:
//!         * `streaming.rs:910`: `format!("Received RST_STREAM
//!           with code {code}")` — `code` is a u32 RST_STREAM
//!           code, no internal info.
//!         * `streaming.rs:1905`: `Status::internal("database
//!           connection lost")` — static string.
//!         * `status.rs:439`: `format!("protocol error: {msg}")`
//!           — `msg` is a typed protocol error string; no Debug
//!           formatter, no source-location.
//!         * `status.rs:442`: `format!("compression error:
//!           {msg}")` — same pattern.
//!
//!   (e) **⚠️ P3 finding (orthogonal):** `From<std::io::Error>
//!       for GrpcError` at status.rs:471 uses `err.to_string()`
//!       which can include OS-level error details (file paths,
//!       errno text). Not stack-trace leakage but a different
//!       info-leak class. Documented as a separate audit
//!       follow-up.
//!
//! Regression tests below pin (a)+(b)+(c)+(d).

use asupersync::bytes::Bytes;
use asupersync::grpc::Status;
use asupersync::grpc::status::{Code, MAX_STATUS_MESSAGE_LEN};
use std::path::Path;

/// Tokens that, if found inside a `Status::internal(...)` call
/// site argument list (after stripping string literals), suggest
/// a stack-trace / source-location embedding.
const STACK_TOKENS: &[&str] = &[
    "backtrace",
    "Backtrace",
    "::capture",
    "file!(",
    "line!(",
    "module_path!(",
    "panic_payload",
    "PanicPayload",
];

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

fn is_comment_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//")
}

#[test]
fn status_message_cap_is_8kib() {
    // Pin (c): the documented MAX_STATUS_MESSAGE_LEN must remain
    // 8 KiB. A regression that loosened the cap (or removed it
    // entirely) would let a pathological format! pump arbitrary
    // bytes into wire frames / observability pipelines.
    assert_eq!(
        MAX_STATUS_MESSAGE_LEN,
        8 * 1024,
        "Status message cap is 8 KiB defense-in-depth (br-asupersync-uk2vsg)",
    );
}

#[test]
fn status_message_truncates_long_input_at_utf8_boundary() {
    // Pin (c): a Status constructor that receives a 16 KiB string
    // truncates to 8 KiB at a valid UTF-8 boundary, never panics,
    // and never produces invalid UTF-8.
    let oversize = "a".repeat(16 * 1024);
    let status = Status::internal(oversize);
    assert!(
        status.message().len() <= MAX_STATUS_MESSAGE_LEN,
        "16 KiB → must cap at 8 KiB; got {}",
        status.message().len(),
    );
    // Confirm it's still valid UTF-8 (a String already is).
    let _ = status.message().chars().count();
}

#[test]
fn status_message_handles_multibyte_utf8_at_boundary() {
    // Pin (c) extension: the UTF-8 char-boundary slice MUST NOT
    // panic on a multibyte char straddling the cap. Build a
    // string that places a 4-byte char (😀, U+1F600) at the
    // truncation point and verify the cap function preserves
    // boundary integrity.
    let mut input = "a".repeat(MAX_STATUS_MESSAGE_LEN - 2);
    input.push('😀'); // 4 bytes — the first 2 cross the cap
    input.push_str("trailing");

    let status = Status::internal(input.clone());
    let msg = status.message();
    assert!(msg.len() <= MAX_STATUS_MESSAGE_LEN);
    // The truncated message must be valid UTF-8 — a regression
    // that sliced mid-codepoint would have produced invalid
    // UTF-8 here. We rely on the slice being within the
    // String type's invariant — verify by re-parsing.
    let _ = String::from_utf8(msg.as_bytes().to_vec()).expect("valid UTF-8 after truncation");
}

#[test]
fn status_internal_does_not_embed_backtrace_or_source_location() {
    // Pin (a)+(b)+(d): walk every src/grpc/*.rs file (excluding
    // status.rs's own definition of MAX_STATUS_MESSAGE_LEN
    // wording in doc comments and helper-test fixtures) and
    // verify NO `Status::internal(...)` argument list contains
    // a backtrace / source-location token.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let src_root = Path::new(manifest_dir).join("src");

    let mut violations: Vec<(String, usize, String)> = Vec::new();

    for relative in SCAN_FILES {
        let path = src_root.join(relative);
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // For each `Status::` constructor call site, capture the
        // call's argument list (up to the closing `)`) and
        // search for backtrace tokens. We use a multi-line
        // window to handle calls split across lines.
        let lines: Vec<&str> = content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            if is_comment_line(line) {
                continue;
            }
            // Detect Status:: constructor opens.
            if !line.contains("Status::") {
                continue;
            }
            let opens_status_ctor = line.contains("Status::new(")
                || line.contains("Status::internal(")
                || line.contains("Status::with_details(")
                || line.contains("Status::cancelled(")
                || line.contains("Status::aborted(")
                || line.contains("Status::deadline_exceeded(")
                || line.contains("Status::failed_precondition(")
                || line.contains("Status::invalid_argument(")
                || line.contains("Status::not_found(")
                || line.contains("Status::permission_denied(")
                || line.contains("Status::resource_exhausted(")
                || line.contains("Status::unauthenticated(")
                || line.contains("Status::unavailable(")
                || line.contains("Status::unimplemented(")
                || line.contains("Status::unknown(")
                || line.contains("Status::ok(");
            if !opens_status_ctor {
                continue;
            }

            // Look ahead up to 5 lines for the closing `)`. Then
            // truncate.
            let end_idx = (idx + 5).min(lines.len());
            let window = lines[idx..end_idx].join("\n");
            let call_end = window.find(')').unwrap_or(window.len());
            let call_text = &window[..call_end];

            // Strip string-literal contents so doc/error prose
            // doesn't false-positive.
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

            for token in STACK_TOKENS {
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
            "tick #161 audit pin: Status::* constructor argument contains a \
             backtrace / source-location token. Status messages must NOT \
             embed stack traces, file paths, line numbers, or module paths \
             — they propagate over the wire and to in-process serializers. \
             Violations:\n",
        );
        for (file, line_no, detail) in &violations {
            report.push_str(&format!("  src/{file}:{line_no} — {detail}\n"));
        }
        panic!("{report}");
    }
}

#[test]
fn status_with_details_caps_message_and_details() {
    // Pin (c) extension: with_details ALSO truncates the message
    // (and the details Bytes). A regression that only capped one
    // of the two would let a leak through the other channel.
    let oversize_msg = "M".repeat(16 * 1024);
    let oversize_details = vec![b'D'; 256 * 1024];
    let status = Status::with_details(Code::Internal, oversize_msg, Bytes::from(oversize_details));
    assert!(
        status.message().len() <= MAX_STATUS_MESSAGE_LEN,
        "with_details message cap not enforced",
    );
    // 64 KiB details cap (MAX_STATUS_DETAILS_LEN).
    if let Some(d) = status.details() {
        assert!(
            d.len() <= 64 * 1024,
            "with_details details cap not enforced; got {} bytes",
            d.len(),
        );
    }
}

#[test]
fn status_constructors_propagate_short_messages_unchanged() {
    // Sanity: a normal short message survives the cap unchanged.
    // A regression that aggressively trimmed every message would
    // break operator-readable error reporting.
    let status = Status::internal("connection lost");
    assert_eq!(status.code(), Code::Internal);
    assert_eq!(
        status.message(),
        "connection lost",
        "short messages must pass through unchanged",
    );
}
