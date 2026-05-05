//! Audit + regression test for `src/grpc/server.rs::CallContext`
//! request-deadline propagation (tick #138).
//!
//! Current source-truth summary:
//!
//!   (a) **Peer grpc-timeout has an opt-in server cap — FIXED LIVE SEAM.**
//!       `CallContext::from_metadata_at_with_max_deadline` clamps
//!       peer-supplied `grpc-timeout` values to
//!       `ServerConfig::max_request_deadline` when operators configure one.
//!       The legacy `from_metadata_at` constructor still passes `cap=None`
//!       for compatibility, so this audit now pins both behaviors explicitly
//!       instead of claiming there is no production cap.
//!
//!   (b) **No client-controlled extension via repeated headers —
//!       VERIFIED CLEAN.** `Metadata::get` returns the most
//!       recently inserted entry for a key (case-insensitive); a
//!       peer that sends two `grpc-timeout` headers gets only one
//!       parsed. They cannot SUM headers to extend a deadline.
//!
//!   (c) **Invalid grpc-timeout fails closed — STRICTER than I
//!       initially thought.** Per server.rs:1157-1162, the match
//!       arm `Some(Ascii(s)) => parse_grpc_timeout(s)` evaluates
//!       to `None` (not `Some(default)`) when parsing fails. So
//!       `timeout = None` and the resulting deadline is also
//!       `None`. The server's `default_timeout` is consulted ONLY
//!       on the `None => default_timeout` branch — i.e. when the
//!       header is absent. A peer-supplied malformed header gets
//!       NO deadline, NOT the default.
//!
//!       This is actually MORE conservative than I expected and
//!       matches the doc-comment intent ("must fail closed, not
//!       impersonate absence"). It does mean a subtle UX trap: a
//!       peer that flubs the timeout header gets an
//!       infinite-deadline call, NOT a fast-failed call. Not a
//!       security finding — the peer can already get
//!       infinite-deadline by sending nothing — but operators
//!       reading the doc comment may expect "fail closed" to
//!       mean "reject the call with InvalidArgument", which it
//!       does NOT.
//!
//! Regression tests below pin (a), (b), and (c) as live behavior.

use asupersync::grpc::server::CallContext;
use asupersync::grpc::streaming::Metadata;
use std::time::{Duration, Instant};

fn now() -> Instant {
    Instant::now()
}

fn meta_with_timeout(value: &str) -> Metadata {
    let mut metadata = Metadata::new();
    let _ = metadata.insert("grpc-timeout", value);
    metadata
}

#[test]
fn peer_grpc_timeout_is_clamped_when_max_request_deadline_is_configured() {
    let metadata = meta_with_timeout("99999999H");
    let n = now();
    let ctx = CallContext::from_metadata_at_with_max_deadline(
        metadata,
        Some(Duration::from_secs(60)),
        Some(Duration::from_secs(10)),
        None,
        n,
    );
    let deadline = ctx.deadline().expect("deadline must be set");
    let remaining = deadline
        .checked_duration_since(n)
        .expect("deadline must be in the future");
    assert!(
        remaining <= Duration::from_secs(10),
        "configured max_request_deadline must clamp peer timeout; got {remaining:?}",
    );
}

#[test]
fn legacy_constructor_keeps_no_cap_semantics_explicit() {
    let metadata = meta_with_timeout("99999999H");
    let n = now();
    let ctx = CallContext::from_metadata_at(metadata, Some(Duration::from_secs(60)), None, n);
    let remaining = ctx
        .deadline()
        .and_then(|deadline| deadline.checked_duration_since(n))
        .expect("deadline must be set");

    assert!(
        remaining > Duration::from_secs(365 * 24 * 3600),
        "from_metadata_at intentionally passes max_request_deadline=None; got {remaining:?}",
    );
}

#[test]
fn peer_omits_grpc_timeout_falls_back_to_default() {
    // Audit (a) sub-property: when the peer does NOT send
    // grpc-timeout, the server's default_timeout is used. This is
    // the documented fallback path.
    let n = now();
    let ctx =
        CallContext::from_metadata_at(Metadata::new(), Some(Duration::from_millis(500)), None, n);
    let remaining = ctx
        .deadline()
        .and_then(|d| d.checked_duration_since(n))
        .expect("deadline must be set from default");
    // Allow a small slack for the wall-clock drift between `now`
    // capture and the deadline computation.
    assert!(
        remaining <= Duration::from_millis(500),
        "default-fallback deadline must be at most default_timeout; \
         got {remaining:?}",
    );
    assert!(
        remaining > Duration::from_millis(400),
        "default-fallback deadline must be near default_timeout; \
         got {remaining:?}",
    );
}

#[test]
fn peer_omits_grpc_timeout_and_no_default_means_no_deadline() {
    // Both peer and server are silent → no deadline. Pinning this
    // because a regression that defaulted to "infinite timeout =
    // some huge sentinel" would silently break the no-deadline
    // semantic that some long-running RPCs depend on.
    let ctx = CallContext::from_metadata_at(Metadata::new(), None, None, now());
    assert!(
        ctx.deadline().is_none(),
        "no peer header + no default = no deadline (None), got {:?}",
        ctx.deadline(),
    );
}

#[test]
fn invalid_grpc_timeout_yields_none_deadline_not_default() {
    // Audit (c) corrected: peer sends a malformed grpc-timeout.
    // Per server.rs:1157-1162 the match arm
    //   Some(Ascii(s)) => parse_grpc_timeout(s)
    // evaluates to None when parsing fails. So `timeout = None`
    // and `deadline = None` — the server's default_timeout is
    // NOT consulted on the malformed-Ascii branch. Pinned so a
    // future refactor that DOES fall through to default (which
    // would silently apply a deadline a peer didn't explicitly
    // ask for) is caught.
    let metadata = meta_with_timeout("not-a-valid-timeout");
    let n = now();
    let ctx = CallContext::from_metadata_at(metadata, Some(Duration::from_millis(250)), None, n);
    assert!(
        ctx.deadline().is_none(),
        "malformed peer grpc-timeout produces None deadline (NOT a fallback \
         to default_timeout). The 'fail closed' doc comment in server.rs \
         means 'no deadline applied', not 'reject the call'. Got {:?}",
        ctx.deadline(),
    );
}

#[test]
fn binary_grpc_timeout_value_unreachable_via_normalize_key() {
    // Edge: per server.rs:1160, a Binary-typed grpc-timeout falls
    // through to `None` immediately. The Binary branch is
    // unreachable from the public Metadata API NOT because
    // insert_bin rejects the key, but because
    // `normalize_metadata_key` APPENDS '-bin' when binary=true
    // and the key doesn't already end in -bin. So the actual
    // stored key becomes 'grpc-timeout-bin', and
    // metadata.get("grpc-timeout") returns None — the Absent
    // branch fires (default_timeout fallback), NOT the Binary
    // branch.
    //
    // Concrete behavior pin: insert_bin succeeds and stores
    // under 'grpc-timeout-bin'; metadata.get('grpc-timeout')
    // returns None.
    let mut metadata = Metadata::new();
    let inserted = metadata.insert_bin(
        "grpc-timeout",
        asupersync::bytes::Bytes::from_static(b"\x01\x02\x03"),
    );
    assert!(
        inserted,
        "insert_bin should succeed (it normalizes the key by appending -bin)",
    );
    assert!(
        metadata.get("grpc-timeout").is_none(),
        "after insert_bin('grpc-timeout', ...) the key is normalized to \
         'grpc-timeout-bin', so a lookup on the bare 'grpc-timeout' key \
         returns None — Binary branch in from_metadata_at unreachable",
    );
    assert!(
        metadata.get("grpc-timeout-bin").is_some(),
        "the binary value is stored under the normalized key",
    );
}

#[test]
fn duplicate_grpc_timeout_uses_most_recent_no_summing() {
    // Audit (b): a peer sending two grpc-timeout headers gets only
    // ONE parsed via Metadata::get. They cannot sum two headers to
    // extend a deadline beyond what either alone would allow.
    let mut metadata = Metadata::new();
    let _ = metadata.insert("grpc-timeout", "100m"); // 100ms
    let _ = metadata.insert("grpc-timeout", "200m"); // 200ms
    let n = now();
    let ctx = CallContext::from_metadata_at(metadata, None, None, n);
    let remaining = ctx
        .deadline()
        .and_then(|d| d.checked_duration_since(n))
        .expect("deadline must be set");
    // Per the Metadata::get contract, duplicate keys return the
    // most-recently-inserted value (200m). The other value (100m)
    // is shadowed, NOT summed.
    assert!(
        remaining > Duration::from_millis(150),
        "duplicate-header deadline must be >150ms (most-recent=200m), got {remaining:?}",
    );
    assert!(
        remaining <= Duration::from_millis(200),
        "duplicate-header deadline must be ≤200ms (most-recent), NOT 100m+200m=300ms, \
         got {remaining:?}",
    );
}

#[test]
fn deadline_is_now_plus_timeout_not_overflow() {
    // Pin that the deadline computation uses checked_add and does
    // NOT silently wrap on a huge timeout. A regression to
    // saturating_add or wrapping_add would let a peer set
    // grpc-timeout=99999999H AND have the deadline silently wrap
    // around to a near-zero value (which would cause IMMEDIATE
    // expiry — a different DoS class).
    let metadata = meta_with_timeout("99999999H");
    let n = now();
    let ctx = CallContext::from_metadata_at(metadata, None, None, n);
    // Either Some(future) or None (overflow → None per
    // checked_add). NEVER Some(past).
    if let Some(deadline) = ctx.deadline() {
        assert!(
            deadline >= n,
            "deadline must be >= now; checked_add must not silently wrap. \
             deadline={deadline:?}, now={n:?}",
        );
    }
    // Implicit: ctx.deadline() == None on overflow is also legal.
}
