//! Fuzz target for `src/security/secret.rs` SecretString
//! (br-asupersync-r2l1ze + br-asupersync-y3he7v).
//!
//! `SecretString` is the zeroize-on-drop wrapper used for database
//! passwords, OAuth tokens, and other credential material. Its
//! invariants:
//!
//!   1. The constructor invariant: bytes are valid UTF-8 (so
//!      `as_str()` never panics).
//!   2. `Debug` always renders `SecretString(<redacted>)` — the
//!      plaintext must NEVER appear in formatted output.
//!   3. Round-trip: `SecretString::new(s).as_str()` returns a string
//!      equal to `s`; `from_string(s).as_str()` likewise.
//!   4. `as_bytes()` always returns the same bytes the constructor
//!      received (no double-encoding, no UTF-8 fixup).
//!   5. `len()` and `is_empty()` agree with `as_bytes().len() == 0`.
//!   6. `explicit_zeroize()` is idempotent and leaves the secret
//!      empty afterwards.
//!   7. `PartialEq` is constant-time-by-length: comparing two equal
//!      secrets returns true; comparing different ones returns false;
//!      neither code path panics for any input.
//!   8. Equality is reflexive and symmetric.
//!   9. Drop must never panic — exercised by letting fuzzer-built
//!      values fall out of scope each iteration.
//!
//! The fuzzer takes arbitrary bytes, splits them into two arms, and
//! tries both `new(&str)` and `from_string(String)` constructors when
//! the bytes are valid UTF-8 (and otherwise verifies that an attempt
//! to interpret as UTF-8 declines gracefully — SecretString is
//! UTF-8-only by contract, callers are expected to validate first).

#![no_main]

use libfuzzer_sys::fuzz_target;

use asupersync::security::secret::SecretString;

fuzz_target!(|data: &[u8]| {
    // Split the input into two slices; each becomes a candidate
    // secret. We only construct from valid UTF-8 — the contract is
    // that callers pre-validate their secret material.
    let split = data.len() / 2;
    let (a_bytes, b_bytes) = data.split_at(split);

    let a_str = match core::str::from_utf8(a_bytes) {
        Ok(s) => s,
        Err(_) => return, // SecretString contract: caller validates UTF-8.
    };
    let b_str = match core::str::from_utf8(b_bytes) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Constructor 1: SecretString::new copies the bytes.
    let s_new = SecretString::new(a_str);

    // Invariant 1+3: as_str round-trips.
    assert_eq!(s_new.as_str(), a_str, "as_str() did not round-trip");
    // Invariant 4: as_bytes preserves input.
    assert_eq!(
        s_new.as_bytes(),
        a_bytes,
        "as_bytes() did not preserve input bytes"
    );
    // Invariant 5: len/is_empty agree.
    assert_eq!(s_new.len(), a_bytes.len(), "len() inconsistent");
    assert_eq!(
        s_new.is_empty(),
        a_bytes.is_empty(),
        "is_empty() inconsistent with len()"
    );

    // Invariant 2: Debug must redact. The plaintext bytes must not
    // appear in the formatted output.
    let dbg = format!("{:?}", s_new);
    assert!(
        dbg.contains("redacted") || dbg.contains("REDACTED"),
        "Debug did not include redaction marker: {dbg}"
    );
    // Strict leak check: if the secret is non-empty AND non-trivial
    // (length > 4 to avoid spurious matches like "" being a substring
    // of every string), it must NOT appear in the formatted output.
    if a_str.len() > 4 {
        assert!(
            !dbg.contains(a_str),
            "Debug leaked secret plaintext into formatted output"
        );
    }

    // Constructor 2: from_string consumes the String — bytes are moved.
    let s_owned = SecretString::from_string(a_str.to_string());
    assert_eq!(s_owned.as_str(), a_str, "from_string round-trip failed");
    assert_eq!(s_owned.as_bytes(), a_bytes);

    // Invariant 8: reflexive equality on identical content.
    let s_clone = SecretString::new(a_str);
    assert_eq!(
        s_new == s_clone,
        true,
        "PartialEq says two identical SecretStrings differ"
    );

    // Invariant 7: cross-secret equality matches the byte equality.
    let s_b = SecretString::new(b_str);
    let expected_eq = a_bytes == b_bytes;
    assert_eq!(
        s_new == s_b,
        expected_eq,
        "PartialEq disagrees with byte equality"
    );
    // Symmetry.
    assert_eq!(s_b == s_new, expected_eq, "PartialEq is not symmetric");

    // Invariant 6: explicit_zeroize is idempotent.
    let mut s_zero = SecretString::new(a_str);
    s_zero.explicit_zeroize();
    assert!(s_zero.is_empty(), "secret not empty after explicit_zeroize");
    assert_eq!(s_zero.as_str(), "", "as_str() not empty after zeroize");
    assert_eq!(s_zero.len(), 0, "len() not zero after zeroize");
    // Second zeroize is a no-op.
    s_zero.explicit_zeroize();
    assert!(s_zero.is_empty(), "second zeroize broke is_empty");

    // Invariant 9: drop must not panic. (Implicit at end of scope.)
});
