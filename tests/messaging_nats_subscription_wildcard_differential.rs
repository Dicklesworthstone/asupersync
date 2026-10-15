//! Differential test for NATS subscription wildcard semantics.
//!
//! Oracle: the canonical NATS subject-matching grammar documented at
//! <https://docs.nats.io/nats-concepts/subjects#wildcards> and the
//! reference behavior of `nats-server` (the Synadia open-source
//! broker). Each row in `CASES` is a (pattern, subject, expected,
//! reference-rule) tuple, where `expected` is the boolean nats-server
//! would return for delivery and `reference-rule` cites the doc clause
//! the row is pinning.
//!
//! Why this test exists: `src/messaging/nats.rs::subscription_matches_subject`
//! re-implements the matcher in pure Rust because the asupersync NATS
//! client does its own subscription bookkeeping (the server's view is
//! authoritative on the wire, but the client filters inbound `MSG`
//! deliveries against subscribed patterns to enforce its own
//! cancellation / draining contracts). A divergence between this
//! re-implementation and nats-server's grammar would cause silent
//! message loss (false negatives) or spurious wakeups (false
//! positives) — neither is observable from the existing in-tree
//! happy-path unit tests. The integration-test placement also keeps
//! it runnable independent of the in-tree `cfg(test)` modules that
//! occasionally break the lib test binary.
//!
//! What this test does NOT cover:
//!   * The wire round-trip itself (covered by
//!     `tests/messaging_nats_handshake.rs`).
//!   * Queue-group semantics (separate concern from subject matching).
//!   * `$JS.>` JetStream subjects (handled at a higher layer).

use asupersync::messaging::nats::subscription_matches_subject;

/// (pattern, subject, expected_match, reference_rule)
const CASES: &[(&str, &str, bool, &str)] = &[
    // ── exact match ───────────────────────────────────────────────
    ("foo", "foo", true, "literal token equality"),
    ("foo.bar", "foo.bar", true, "multi-token literal equality"),
    (
        "foo",
        "foo.bar",
        false,
        "literal does not match longer subject",
    ),
    (
        "foo.bar",
        "foo",
        false,
        "literal does not match shorter subject",
    ),
    ("foo", "Foo", false, "subject matching is case-sensitive"),
    // ── single-token wildcard `*` ─────────────────────────────────
    ("*", "foo", true, "* matches exactly one token at root"),
    (
        "*",
        "foo.bar",
        false,
        "* matches exactly one token (not multi)",
    ),
    ("*", "", false, "* requires a non-empty token"),
    ("foo.*", "foo.bar", true, "* matches any single tail token"),
    (
        "foo.*",
        "foo",
        false,
        "trailing * requires the corresponding token",
    ),
    (
        "foo.*",
        "foo.bar.baz",
        false,
        "* does not span multiple tokens",
    ),
    ("*.bar", "foo.bar", true, "leading * matches first token"),
    (
        "foo.*.baz",
        "foo.qux.baz",
        true,
        "interior * matches any single middle token",
    ),
    (
        "foo.*.baz",
        "foo.qux.zzz.baz",
        false,
        "interior * does not span tokens",
    ),
    (
        "*.*",
        "a.b",
        true,
        "two * tokens require exactly two-token subject",
    ),
    (
        "*.*",
        "a",
        false,
        "two * tokens reject single-token subject",
    ),
    ("*.*", "a.b.c", false, "two * tokens reject longer subject"),
    (
        "*.*.*",
        "a.b.c",
        true,
        "three * tokens match three-token subject",
    ),
    (
        "time.us.*",
        "time.us.east",
        true,
        "official docs example: single-token wildcard matches one final token",
    ),
    (
        "time.us.*",
        "time.us.east.atlanta",
        false,
        "official docs example: single-token wildcard does not span multiple trailing tokens",
    ),
    // ── tail wildcard `>` ─────────────────────────────────────────
    (">", "foo", true, "> alone matches one token"),
    (">", "foo.bar", true, "> alone matches multi-token subject"),
    (
        ">",
        "foo.bar.baz.qux",
        true,
        "> alone matches arbitrarily deep subject",
    ),
    (
        "foo.>",
        "foo.bar",
        true,
        "> matches a single trailing token",
    ),
    (
        "foo.>",
        "foo.bar.baz",
        true,
        "> matches multiple trailing tokens",
    ),
    (
        "foo.>",
        "foo",
        false,
        "> requires at least one trailing token",
    ),
    (
        "foo.>",
        "bar.baz",
        false,
        "> after literal does not change literal match",
    ),
    (
        "time.us.>",
        "time.us.east",
        true,
        "official docs example: tail wildcard matches one trailing token",
    ),
    (
        "time.us.>",
        "time.us.east.atlanta",
        true,
        "official docs example: tail wildcard matches multiple trailing tokens",
    ),
    // ── mixed `*` and `>` ─────────────────────────────────────────
    ("*.>", "a.b", true, "*.> requires at least two tokens"),
    ("*.>", "a.b.c", true, "*.> matches deeper subjects"),
    ("*.>", "a", false, "*.> rejects single-token subject"),
    (
        "foo.*.>",
        "foo.x.y",
        true,
        "interior * + trailing > combine cleanly",
    ),
    (
        "foo.*.>",
        "foo.x.y.z",
        true,
        "interior * + trailing > matches deeper",
    ),
    (
        "foo.*.>",
        "foo.x",
        false,
        "*.> tail still requires a trailing token",
    ),
    (
        "foo.*.>",
        "foo",
        false,
        "*.> tail rejects pattern-shorter subject",
    ),
    // ── invalid pattern shapes (must not match anything) ─────────
    (
        "foo.>.bar",
        "foo.x.bar",
        false,
        "> only valid as last token",
    ),
    ("foo.>x", "foo.bar", false, "> must be the entire token"),
    ("foo.x*", "foo.xy", false, "* must be the entire token"),
    (
        "time.New*.east",
        "time.Newark.east",
        false,
        "official docs example: * cannot match a substring within a token",
    ),
    ("foo..bar", "foo.x.bar", false, "empty token is invalid"),
    (
        "foo.bar.",
        "foo.bar.x",
        false,
        "trailing empty token is invalid",
    ),
    (".foo", "foo", false, "leading empty token is invalid"),
    ("", "foo", false, "empty pattern matches nothing"),
];

#[test]
fn nats_subscription_wildcard_differential_against_nats_server_grammar() {
    let mut failures: Vec<String> = Vec::new();

    for &(pattern, subject, expected, rule) in CASES {
        let actual = subscription_matches_subject(pattern, subject);
        if actual != expected {
            failures.push(format!(
                "  pattern={pattern:?} subject={subject:?}: \
                 expected {expected} per `{rule}`, got {actual}"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "NATS wildcard matcher diverged from nats-server reference grammar in {} of {} \
         cases:\n{}",
        failures.len(),
        CASES.len(),
        failures.join("\n"),
    );
}
