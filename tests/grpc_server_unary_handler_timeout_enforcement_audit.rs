//! Audit + regression test for `src/grpc/server.rs` unary handler
//! timeout enforcement (tick #201).
//!
//! Operator's question: "verify unary handler timeout
//! enforcement."
//!
//! Audit context — gRPC timeout sources, in priority order:
//!
//!   1. Parseable client `grpc-timeout` header — clamped to
//!      `ServerConfig::max_request_deadline` if that cap is configured
//!      (tick #139).
//!   2. `ServerConfig::default_timeout` — applied when the
//!      client omits grpc-timeout or sends a malformed value.
//!   3. No deadline — possible only when neither source supplies
//!      a usable bound.
//!
//! `dispatch_unary` races the handler future against the effective
//! deadline. Yielding async work is dropped when the deadline wins;
//! blocking work that never yields cannot be preempted. Handlers may
//! also inspect `cx.is_expired()` between phases.
//!
//! Audit findings (extends ticks #138/#139/#166):
//!
//!   (a) **`default_timeout` field exists on ServerConfig.**
//!       Default value: None (no default
//!       deadline; calls run to client's grpc-timeout or
//!       unbounded). Operators that want a server-side
//!       baseline timeout set this explicitly.
//!
//!   (b) **`default_timeout` does NOT clamp client's
//!       `grpc-timeout`.** When the client sends a parseable
//!       grpc-timeout header, that value is used (subject to
//!       max_request_deadline cap, tick #139). Malformed or absent
//!       values use default_timeout. That operator fallback is
//!       independent of the `max_request_deadline` peer cap.
//!
//!   (c) **`max_request_deadline` is the valid peer-timeout cap.**
//!       When Some(cap), every
//!       parseable peer-supplied grpc-timeout is clamped to
//!       `min(peer_timeout, cap)`. Default None preserves
//!       pre-fix behavior.
//!
//!   (d) **CallContext::is_expired_at(now)** is the
//!       cooperative check (audited tick #166). Handler
//!       checks this between phases to short-circuit.
//!
//!   (e) **CallContext::remaining_at(now)** returns None for
//!       expired or absent deadlines; `is_expired_at(now)` distinguishes
//!       the expired case for handlers and transport wrappers.
//!
//!   (f) **`timeout_header_value_at` propagates `0n`** for
//!       expired deadlines so downstream calls fail fast
//!       (tick #166).
//!
//! Regression tests below pin (a)+(b)+(c) at the public
//! ServerConfig + CallContext API surface.

use asupersync::grpc::streaming::Metadata;
use asupersync::grpc::{CallContext, ServerBuilder, ServerConfig};
use std::time::{Duration, Instant};

#[test]
fn default_server_config_default_timeout_is_none() {
    // Pin (a): default ServerConfig has NO default_timeout.
    // Calls run to client's grpc-timeout OR unbounded if no
    // header.
    let config = ServerConfig::default();
    assert!(
        config.default_timeout.is_none(),
        "default_timeout default is None — operators must opt in",
    );
}

#[test]
fn default_server_config_max_request_deadline_is_none() {
    // Pin (c): default max_request_deadline is None. Operators opt in
    // when they want to cap valid peer-supplied timeouts.
    let config = ServerConfig::default();
    assert!(
        config.max_request_deadline.is_none(),
        "max_request_deadline default is None — pre-tick-#139 behavior",
    );
}

#[test]
fn server_builder_default_timeout_setter_threads_through_config() {
    // Pin (a): ServerBuilder::default_timeout stores the value in the
    // resulting server configuration.
    let server = ServerBuilder::new()
        .default_timeout(Duration::from_secs(30))
        .build();
    assert_eq!(
        server.config().default_timeout,
        Some(Duration::from_secs(30))
    );
}

#[test]
fn max_request_deadline_clamps_peer_timeout() {
    // Pin (c): a peer sending grpc-timeout: 99999999H gets
    // clamped to the server's max_request_deadline cap
    // (audited tick #139, re-pinned here).
    let now = Instant::now();
    let mut metadata = Metadata::new();
    assert!(metadata.insert("grpc-timeout", "99999999H"));

    let cap = Duration::from_secs(60);
    let cx = CallContext::from_metadata_at_with_max_deadline(metadata, None, Some(cap), None, now);
    let deadline = cx.deadline().expect("deadline set");
    let effective = deadline.saturating_duration_since(now);
    assert!(
        effective <= cap,
        "peer's huge timeout MUST be clamped to max_request_deadline; \
         got effective {effective:?}, cap {cap:?}",
    );
}

#[test]
fn default_timeout_applies_when_grpc_timeout_header_absent() {
    // Pin (b): when no grpc-timeout header, default_timeout
    // is used as the call's deadline.
    let now = Instant::now();
    let metadata = Metadata::new(); // no grpc-timeout
    let default = Duration::from_secs(10);
    let cx = CallContext::from_metadata_at(metadata, Some(default), None, now);
    let deadline = cx.deadline().expect("default_timeout produces a deadline");
    let effective = deadline.saturating_duration_since(now);
    assert!(
        effective.abs_diff(default) < Duration::from_millis(50),
        "default_timeout {default:?} produces deadline at now+default; \
         got effective {effective:?}",
    );
}

#[test]
fn default_timeout_does_not_clamp_client_supplied_timeout() {
    // Pin (b): when the client sends a grpc-timeout header
    // (e.g. 10s), the client's value is used even when it exceeds
    // server's default_timeout (e.g. 100ms). The
    // default_timeout is the absent-or-malformed fallback, not a ceiling
    // on valid client timeouts.
    let now = Instant::now();
    let mut metadata = Metadata::new();
    assert!(metadata.insert("grpc-timeout", "10S")); // 10 s client
    let peer_timeout = Duration::from_secs(10);
    let default = Duration::from_millis(100); // 100 ms server default
    let cx = CallContext::from_metadata_at(metadata, Some(default), None, now);
    assert_eq!(
        cx.deadline(),
        now.checked_add(peer_timeout),
        "client's 10 s timeout takes precedence over server's 100 ms default_timeout; default is fallback only, not a ceiling",
    );
}

#[test]
fn max_request_deadline_does_not_clamp_default_timeout_fallback() {
    // Pin (c): `max_request_deadline` clamps parseable peer-supplied
    // timeouts only, NOT the absent- or malformed-header fallback to
    // default_timeout:
    // "This cap does NOT affect the absent- or malformed-header fallback
    //  to default_timeout — that path still applies the
    //  configured default. Callers that want a tighter
    //  ceiling on the default should set default_timeout
    //  itself."
    let now = Instant::now();
    let metadata = Metadata::new(); // no grpc-timeout
    let default = Duration::from_secs(60);
    let cap = Duration::from_secs(10); // tighter than default
    let cx = CallContext::from_metadata_at_with_max_deadline(
        metadata,
        Some(default),
        Some(cap),
        None,
        now,
    );
    let deadline = cx.deadline().expect("default_timeout produces a deadline");
    let effective = deadline.saturating_duration_since(now);
    // The default_timeout (60s) is used; the cap (10s) does NOT
    // clamp the operator fallback path.
    assert!(
        effective >= Duration::from_secs(50),
        "default_timeout fallback NOT clamped by max_request_deadline; \
         operator must set default_timeout if they want a tighter \
         ceiling. got effective {effective:?}",
    );
}

#[test]
fn no_default_no_header_means_no_deadline() {
    // Pin (a)+(b): if the client sends no grpc-timeout AND
    // the server has no default_timeout, the call has NO
    // deadline. is_expired stays false forever.
    let now = Instant::now();
    let cx = CallContext::from_metadata_at(Metadata::new(), None, None, now);
    assert!(cx.deadline().is_none(), "no deadline when neither set");
    let far_future = now + Duration::from_secs(10 * 365 * 24 * 3600);
    assert!(
        !cx.is_expired_at(far_future),
        "no-deadline call cannot expire — handler runs unbounded \
         (or until structured-cancellation from upstream)",
    );
}

#[test]
fn server_default_timeout_can_be_short() {
    // Pin (a): operators can configure a SHORT default
    // (e.g. 100 ms) for fail-fast workloads. The 100 ms
    // applies when grpc-timeout is absent or malformed.
    let now = Instant::now();
    let metadata = Metadata::new();
    let short_default = Duration::from_millis(100);
    let cx = CallContext::from_metadata_at(metadata, Some(short_default), None, now);
    let deadline = cx.deadline().expect("100ms default produces deadline");
    let effective = deadline.saturating_duration_since(now);
    assert!(
        effective <= Duration::from_millis(150),
        "short default_timeout (100 ms) produces a near-immediate deadline; \
         got {effective:?}",
    );
}

#[test]
fn call_context_exposes_cooperative_deadline_checks() {
    // Pin (d)+(e): handlers can inspect the deadline between phases even
    // though dispatch_unary also races yielding handler futures against it.
    let now = Instant::now();
    let mut metadata = Metadata::new();
    assert!(metadata.insert("grpc-timeout", "1m")); // 1 ms
    let cx = CallContext::from_metadata_at(metadata, None, None, now);
    let deadline = cx.deadline().unwrap();
    let before_deadline = deadline
        .checked_sub(Duration::from_micros(1))
        .expect("1ms timeout deadline is after the test instant");

    // Pre-deadline → not expired.
    assert!(!cx.is_expired_at(before_deadline));
    // At or past deadline → expired.
    assert!(cx.is_expired_at(deadline));
    assert!(cx.is_expired_at(deadline + Duration::from_secs(1)));

    // remaining_at is None for expired deadlines.
    assert!(cx.remaining_at(deadline + Duration::from_secs(1)).is_none());
    // Pre-deadline remaining is Some.
    assert!(cx.remaining_at(before_deadline).is_some());
}

#[test]
fn server_builder_does_not_silently_override_default_timeout() {
    // Pin: building a server with default config does NOT
    // surprise the operator with a non-None default_timeout.
    // A regression that introduced a hidden default ceiling
    // (e.g. 30s default) would change call semantics for
    // existing deployments.
    let server = ServerBuilder::new().build();
    assert!(
        server.config().default_timeout.is_none(),
        "ServerBuilder::new().build() must keep default_timeout=None — \
         no hidden ceiling. Operators that want a baseline must opt in.",
    );
}
