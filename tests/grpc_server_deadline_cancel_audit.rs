//! Audit + regression test for `src/grpc/server.rs` deadline-
//! exceeded cancellation surface (tick #166).
//!
//! Operator's question: "verify deadline-exceeded triggers
//! cancel before further processing, no resource leak."
//!
//! Audit findings:
//!
//!   (a) **`CallContext::is_expired_at(now)` is the cooperative
//!       deadline check.** It returns `true` once the wall-clock
//!       has passed the deadline. Handlers that perform expensive
//!       work should call this between phases to short-circuit
//!       when the call is past deadline. The check is exact
//!       (`now >= deadline`) — a regression that flipped to
//!       strict `>` would let a request that JUST hit deadline
//!       slip past.
//!
//!   (b) **`remaining()` returns `None` for expired deadlines.**
//!       `None` also represents a call with no deadline, so callers that
//!       need to distinguish those states inspect `deadline()` or
//!       `is_expired_at()` as well.
//!
//!   (c) **`timeout_header_value` forwards `0n` for expired
//!       deadlines.** When propagating
//!       to a downstream call, an expired deadline yields the
//!       string `"0n"` so the downstream observer fails fast
//!       with `DeadlineExceeded` immediately rather than
//!       running unbounded.
//!
//!   (d) **`propagate_timeout_to_at` clamps to the tighter of
//!       parent-remaining and child-existing.** A child call
//!       cannot extend the deadline by setting a larger
//!       `grpc-timeout` in outbound metadata — the propagation
//!       takes `min(parent_remaining, child_existing)`. This is the audit-critical
//!       no-extension property.
//!
//!   (e) **`max_request_deadline` server cap clamps parseable peer-
//!       supplied timeouts.**
//!       A peer requesting `grpc-timeout: 99999999H` ≈ 11,400
//!       years is clamped to the operator-configured cap. This
//!       bounds valid peer-supplied timeouts. It does not clamp
//!       the independent server default; operators choose that
//!       ceiling via `default_timeout`.
//!
//!   (f) **No-resource-leak property:** when the dispatch
//!       future is dropped (transport-adapter timeout wrapper
//!       fires), Rust drop semantics release every captured
//!       handler local — buffers, file handles, mutex guards
//!       (audited in tick #162). The deadline-cancel doesn't
//!       leak handler-owned resources.
//!
//! Regression tests below pin (a)-(e) at the public API surface.
//! (f) is structurally pinned by the cancel-cleanup test in
//! `grpc_server_request_cancel_cleanup_audit.rs`.

use asupersync::grpc::streaming::{Metadata, MetadataValue};
use asupersync::grpc::{CallContext, format_grpc_timeout, parse_grpc_timeout};
use std::time::{Duration, Instant};

#[test]
fn call_context_is_expired_at_exact_deadline() {
    // Pin (a): the check is `now >= deadline` (inclusive). A
    // request that JUST hit deadline (`now == deadline`)
    // counts as expired. A regression to strict `>` would
    // let it slip past.
    let now = Instant::now();
    let mut metadata = Metadata::new();
    assert!(metadata.insert("grpc-timeout", "100m")); // 100 ms
    let cx = CallContext::from_metadata_at(metadata, None, None, now);

    let deadline = cx.deadline().expect("deadline set from grpc-timeout");
    assert!(
        cx.is_expired_at(deadline),
        "is_expired_at(deadline) must be true (inclusive boundary)",
    );
    assert!(
        cx.is_expired_at(deadline + Duration::from_nanos(1)),
        "is_expired_at(deadline + 1ns) must be true",
    );
    assert!(
        !cx.is_expired_at(
            deadline
                .checked_sub(Duration::from_nanos(1))
                .expect("deadline is at least 1ns after now"),
        ),
        "is_expired_at(deadline - 1ns) must be false",
    );
}

#[test]
fn call_context_remaining_returns_none_for_expired() {
    // Pin (b): for a context that has a deadline, `remaining_at` returns
    // None when now >= deadline. `is_expired_at` distinguishes this case
    // from a context with no deadline.
    let now = Instant::now();
    let mut metadata = Metadata::new();
    assert!(metadata.insert("grpc-timeout", "10m"));
    let cx = CallContext::from_metadata_at(metadata, None, None, now);

    let deadline = cx.deadline().unwrap();
    assert!(
        cx.remaining_at(deadline).is_none(),
        "remaining_at(deadline) must be None at the inclusive expiry boundary",
    );
    // Past the deadline — remaining must be None.
    let past = deadline + Duration::from_secs(1);
    assert!(
        cx.remaining_at(past).is_none(),
        "remaining_at(deadline+1s) must be None — handlers rely on this \
         to short-circuit",
    );
    // Before the deadline — remaining must be Some.
    let before = deadline
        .checked_sub(Duration::from_millis(5))
        .expect("deadline is at least 5ms after now");
    assert!(
        cx.remaining_at(before).is_some(),
        "remaining_at(before deadline) must be Some",
    );
}

#[test]
fn timeout_header_value_at_forwards_0n_for_expired() {
    // Pin (c): expired deadlines propagate as `0n` so
    // downstream calls fail fast with DeadlineExceeded.
    let now = Instant::now();
    let mut metadata = Metadata::new();
    assert!(metadata.insert("grpc-timeout", "1m")); // 1 ms
    let cx = CallContext::from_metadata_at(metadata, None, None, now);

    let deadline = cx.deadline().unwrap();
    let past = deadline + Duration::from_secs(1);

    let header = cx
        .timeout_header_value_at(past)
        .expect("timeout_header_value_at must always be Some when deadline set");
    assert_eq!(
        header, "0n",
        "expired deadline must propagate as 0n so downstream fails fast \
         instead of running unbounded; got {header:?}",
    );
}

#[test]
fn propagate_timeout_to_clamps_child_to_parent_remaining() {
    // Pin (d): a child call's outbound `grpc-timeout` cannot
    // exceed the parent's remaining time. propagate_timeout_to
    // takes min(parent_remaining, child_existing).
    let now = Instant::now();
    let mut parent_metadata = Metadata::new();
    assert!(parent_metadata.insert("grpc-timeout", "100m")); // 100 ms parent
    let cx = CallContext::from_metadata_at(parent_metadata, None, None, now);

    // Child call has its own grpc-timeout of 1s — much larger
    // than parent's 100 ms.
    let mut child_metadata = Metadata::new();
    assert!(child_metadata.insert("grpc-timeout", "1S")); // 1 second

    // Propagate parent's remaining (100 ms - 0 = 100 ms) into
    // the child metadata. Result must be the tighter of
    // parent-remaining and child-existing → 100 ms.
    let wrote = cx.propagate_timeout_to_at(&mut child_metadata, now);
    assert!(wrote, "propagation must write");

    let actual = match child_metadata.get("grpc-timeout") {
        Some(MetadataValue::Ascii(s)) => s.clone(),
        other => panic!("expected Ascii, got {other:?}"),
    };
    let parsed = parse_grpc_timeout(&actual).expect("propagated timeout must be parseable");
    assert!(
        parsed <= Duration::from_millis(100),
        "child timeout must be clamped to parent's 100 ms; got {parsed:?}",
    );
}

#[test]
fn propagate_timeout_to_keeps_child_when_already_tighter() {
    // Pin (d) other direction: if the child's existing timeout
    // is ALREADY tighter than parent-remaining, the child wins
    // (the propagation respects the child's stricter ceiling).
    let now = Instant::now();
    let mut parent_metadata = Metadata::new();
    assert!(parent_metadata.insert("grpc-timeout", "1S")); // 1 second parent
    let cx = CallContext::from_metadata_at(parent_metadata, None, None, now);

    let mut child_metadata = Metadata::new();
    assert!(child_metadata.insert("grpc-timeout", "10m")); // 10 ms child

    cx.propagate_timeout_to_at(&mut child_metadata, now);
    let actual = match child_metadata.get("grpc-timeout") {
        Some(MetadataValue::Ascii(s)) => s.clone(),
        other => panic!("expected Ascii, got {other:?}"),
    };
    let parsed = parse_grpc_timeout(&actual).unwrap();
    assert!(
        parsed <= Duration::from_millis(10),
        "child's stricter 10ms must be kept (or the parent's 1s, whichever \
         is tighter — definitely ≤ 10ms); got {parsed:?}",
    );
}

#[test]
fn max_request_deadline_clamps_peer_huge_timeout() {
    // Pin (e): peer-supplied `grpc-timeout: 99999999H` is
    // clamped to the operator's max_request_deadline cap. This bounds
    // valid peer-supplied timeouts; the server default is independent.
    let now = Instant::now();
    let mut metadata = Metadata::new();
    assert!(metadata.insert("grpc-timeout", "99999999H")); // ~11,400 years

    let cap = Duration::from_secs(30);
    let cx = CallContext::from_metadata_at_with_max_deadline(metadata, None, Some(cap), None, now);

    let deadline = cx.deadline().unwrap();
    let effective = deadline.saturating_duration_since(now);
    assert!(
        effective <= cap,
        "max_request_deadline cap MUST clamp peer-supplied timeout — got \
         effective {effective:?}, cap {cap:?}",
    );
    assert!(
        effective >= cap.saturating_sub(Duration::from_millis(50)),
        "clamp should land near the cap (within ~50ms tolerance), got \
         {effective:?}",
    );
}

#[test]
fn deadline_absent_means_no_expiration() {
    // Pin: when no grpc-timeout header is sent and no
    // default_timeout is configured, the call has no
    // deadline → is_expired() is FALSE forever.
    let now = Instant::now();
    let cx = CallContext::from_metadata_at(Metadata::new(), None, None, now);
    assert!(
        cx.deadline().is_none(),
        "no-header + no-default = no deadline",
    );
    // Even at far-future time, is_expired stays false — there's
    // no deadline to compare against.
    let far_future = now + Duration::from_secs(10 * 365 * 24 * 3600); // 10 years
    assert!(
        !cx.is_expired_at(far_future),
        "no-deadline call cannot expire — is_expired_at(far_future) must be false",
    );
}

#[test]
fn format_then_parse_grpc_timeout_round_trips() {
    // Sanity (audit-supporting): format_grpc_timeout +
    // parse_grpc_timeout round-trip a Duration. Used by
    // propagate_timeout_to_at to write the clamped value into
    // child metadata.
    for original in [
        Duration::from_millis(1),
        Duration::from_millis(100),
        Duration::from_secs(1),
        Duration::from_secs(60),
        Duration::ZERO,
    ] {
        let formatted = format_grpc_timeout(original);
        let parsed = parse_grpc_timeout(&formatted).expect("format/parse must round-trip");
        // Allow lossy round-trip — format quantizes to gRPC
        // timeout units. The error must be small.
        let diff = parsed.abs_diff(original);
        assert!(
            diff <= Duration::from_micros(1)
                || diff <= original.div_f64(1000.0).max(Duration::from_micros(100)),
            "round-trip diff for {original:?}: {diff:?} (formatted as {formatted:?}, parsed as {parsed:?})",
        );
    }
}
