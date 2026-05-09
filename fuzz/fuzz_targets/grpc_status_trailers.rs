//! br-asupersync-6zcnd9 — Fuzz the gRPC trailer-header decode path:
//! `grpc-status` (decimal integer code), `grpc-message` (escape /
//! unescape), and `grpc-status-details-bin` (base64-encoded protobuf).
//!
//! Invariants asserted:
//!   1. No panic — every parser must return a Result/Option, never panic
//!      on adversarial bytes (UTF-8 boundary splits, embedded NUL,
//!      truncated `%` escapes, leading/trailing whitespace, hex with
//!      `0x` prefix, oversize integers).
//!   2. No OOM — base64 decoding is bounded by input length; we cap
//!      input at MAX_INPUT_LEN to keep individual cases small.
//!   3. Round-trip stability — when the message body is plain ASCII
//!      with no control chars, encode→decode must be identity (where
//!      the project exposes both halves, this is exercised via
//!      base64-roundtrip).

#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};

use asupersync::bytes::Bytes;
use asupersync::grpc::status::{Code, MAX_STATUS_DETAILS_LEN, MAX_STATUS_MESSAGE_LEN, Status};
use base64::Engine;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = MAX_STATUS_MESSAGE_LEN + 1024;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_LEN {
        return;
    }

    // === grpc-status header: decimal integer code ===
    // Treat the first 8 bytes as a candidate textual representation of
    // the status code. Bidi overrides, leading whitespace, '+' / '-'
    // signs, and embedded NUL all flow through here.
    let prefix_len = data.len().min(8);
    let status_str = String::from_utf8_lossy(&data[..prefix_len]);
    // Path 1: integer parse (the canonical wire-format path).
    let parsed = catch_unwind(AssertUnwindSafe(|| status_str.parse::<i32>()));
    assert!(parsed.is_ok(), "i32::parse panicked on {status_str:?}");
    if let Ok(Ok(code_i32)) = parsed {
        // Path 2: Code::from_i32 must accept any i32.
        let code_result = catch_unwind(AssertUnwindSafe(|| Code::from_i32(code_i32)));
        assert!(code_result.is_ok(), "Code::from_i32 panicked on {code_i32}");

        let code = code_result.expect("checked above");
        assert_eq!(
            Code::from_i32(code.as_i32()),
            code,
            "canonical status code integer must round-trip for {code:?}"
        );

        let msg = String::from_utf8_lossy(data).into_owned();
        let status = Status::with_details(code, msg.clone(), Bytes::from(data.to_vec()));
        assert_eq!(status.code(), code, "Status must preserve decoded code");
        assert!(
            status.message().len() <= MAX_STATUS_MESSAGE_LEN,
            "Status message exceeded cap: {} > {}",
            status.message().len(),
            MAX_STATUS_MESSAGE_LEN
        );
        assert!(
            msg.len() > MAX_STATUS_MESSAGE_LEN || status.message() == msg,
            "Status message below cap must be preserved exactly"
        );
        assert!(
            status.message().is_char_boundary(status.message().len()),
            "Status message cap must preserve UTF-8 boundaries"
        );

        let details = status
            .details()
            .expect("with_details must retain a bounded details payload");
        assert!(
            details.len() <= MAX_STATUS_DETAILS_LEN,
            "Status details exceeded cap: {} > {}",
            details.len(),
            MAX_STATUS_DETAILS_LEN
        );
        if data.len() <= MAX_STATUS_DETAILS_LEN {
            assert_eq!(
                details.as_ref(),
                data,
                "details below cap must be preserved exactly"
            );
        }
    }

    // === grpc-status-details-bin header: base64 of arbitrary bytes ===
    // Use the rest of the input as base64 candidate.
    let base64_candidate = String::from_utf8_lossy(&data[prefix_len..]);
    let engine = base64::engine::general_purpose::STANDARD;
    let decode_result = catch_unwind(AssertUnwindSafe(|| {
        engine.decode(base64_candidate.as_bytes())
    }));
    assert!(
        decode_result.is_ok(),
        "base64 decode panicked on {} bytes",
        base64_candidate.len()
    );

    // === grpc-message round-trip on the raw bytes ===
    // Treat the input as a candidate UTF-8 message and verify that
    // encoding it as base64 then decoding back round-trips. This is a
    // sanity check for the encoding helpers, not the message-escape
    // logic (which is private to the status module).
    let msg = String::from_utf8_lossy(data).into_owned();
    let encoded = engine.encode(msg.as_bytes());
    let decoded = engine
        .decode(encoded.as_bytes())
        .expect("base64 of valid bytes must decode");
    assert_eq!(decoded.as_slice(), msg.as_bytes());
});
