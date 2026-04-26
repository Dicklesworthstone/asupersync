//! br-asupersync-icvybx — Fuzz the bearer-token Authorization header
//! parser at the gRPC auth boundary.
//!
//! Invariants asserted:
//!   1. No panic — `fuzz_bearer_token` must return `Option<&str>` on
//!      any UTF-8 input. The parser is on the auth path of every
//!      authenticated RPC, so a panic here is a remote DoS.
//!   2. UTF-8 boundary safety — the case-insensitive scheme match must
//!      not slice mid-codepoint when the input contains multi-byte
//!      UTF-8 sequences in or before the scheme.
//!   3. Trim-whitespace stability — the returned token, if any, must
//!      not contain a leading space (the parser's documented contract).

#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};

use asupersync::grpc::interceptor::fuzz_bearer_token;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 4096;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    // The header value must be a `&str`; convert with lossy UTF-8 so
    // arbitrary byte inputs become valid UTF-8 strings.
    let auth = String::from_utf8_lossy(data).into_owned();

    let result = catch_unwind(AssertUnwindSafe(|| fuzz_bearer_token(&auth)));
    assert!(
        result.is_ok(),
        "fuzz_bearer_token panicked on {} bytes",
        auth.len()
    );

    if let Ok(Some(token)) = result {
        // Documented contract: the returned token has its leading
        // spaces trimmed.
        assert!(
            !token.starts_with(' '),
            "fuzz_bearer_token returned a token with leading space: {token:?}"
        );
        // The token slice must be a valid sub-slice of the original
        // string (not a forged pointer).
        assert!(
            auth.as_str().contains(token) || token.is_empty(),
            "returned token must be a substring of the input"
        );
    }

    // Cross-check a small set of structurally-relevant permutations to
    // ensure the parser is stable across them. Each must return a
    // well-formed Option (no panic).
    for prefix in &[
        "Bearer ",
        "BEARER ",
        "bearer ",
        "bEaReR ",
        "Basic ",
        "  Bearer ",
        "Bearer\t",
    ] {
        let mixed = format!("{prefix}{auth}");
        let r = catch_unwind(AssertUnwindSafe(|| fuzz_bearer_token(&mixed)));
        assert!(
            r.is_ok(),
            "fuzz_bearer_token panicked on prefix={prefix:?} + {} bytes",
            auth.len()
        );
    }
});
