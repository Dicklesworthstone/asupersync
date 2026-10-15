//! Audit + regression test for `src/grpc/server.rs::CallContext`
//! request-deadline propagation (tick #138).
//!
//! Current source-truth summary:
//!
//!   (a) **Peer grpc-timeout has an opt-in server cap — FIXED LIVE SEAM.**
//!       `CallContext::from_metadata_at_with_max_deadline` clamps
//!       parseable peer-supplied `grpc-timeout` values to
//!       `ServerConfig::max_request_deadline` when operators configure one.
//!       The legacy `from_metadata_at` constructor still passes `cap=None`
//!       for compatibility, so this audit now pins both behaviors explicitly
//!       instead of claiming there is no production cap.
//!
//!   (b) **Duplicate entries in the local Metadata model do not sum.**
//!       `Metadata::get` returns the most recently inserted entry for a key
//!       (case-insensitive). This pins the local container/CallContext seam;
//!       it does not claim how an H2 adapter ingests repeated wire headers.
//!
//!   (c) **Invalid grpc-timeout cannot bypass the server default.**
//!       A parseable peer timeout is capped by
//!       `max_request_deadline`; an absent or malformed value instead
//!       uses `default_timeout`. The peer cap never shrinks that
//!       operator-selected fallback. If no default is configured, an
//!       absent or malformed value still yields no deadline.
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
    assert!(
        metadata.insert("grpc-timeout", value),
        "test fixture must use a storable ASCII metadata value: {value:?}",
    );
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
fn peer_grpc_timeout_shorter_than_cap_is_not_extended() {
    let n = now();
    let peer_timeout = Duration::from_millis(100);
    let ctx = CallContext::from_metadata_at_with_max_deadline(
        meta_with_timeout("100m"),
        None,
        Some(Duration::from_secs(10)),
        None,
        n,
    );

    assert_eq!(
        ctx.deadline(),
        n.checked_add(peer_timeout),
        "max_request_deadline must apply min(peer, cap), not replace a shorter peer deadline",
    );
}

#[test]
fn legacy_constructor_keeps_no_cap_semantics_explicit() {
    let metadata = meta_with_timeout("99999999S");
    let n = now();
    let ctx = CallContext::from_metadata_at(metadata, Some(Duration::from_secs(60)), None, n);
    let requested = Duration::from_secs(99_999_999);

    assert_eq!(
        ctx.deadline(),
        n.checked_add(requested),
        "from_metadata_at intentionally passes max_request_deadline=None",
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
fn max_request_deadline_alone_is_not_a_deadline_source() {
    let n = now();
    let cap = Some(Duration::from_secs(10));
    let absent =
        CallContext::from_metadata_at_with_max_deadline(Metadata::new(), None, cap, None, n);
    let malformed = CallContext::from_metadata_at_with_max_deadline(
        meta_with_timeout("+1S"),
        None,
        cap,
        None,
        n,
    );

    assert!(
        absent.deadline().is_none(),
        "max_request_deadline caps a peer value but does not create a deadline when metadata is absent",
    );
    assert!(
        malformed.deadline().is_none(),
        "max_request_deadline must not become a fallback for malformed metadata",
    );
}

#[test]
fn invalid_grpc_timeout_uses_unclamped_default() {
    // A malformed peer value must not disable or shrink the operator's
    // configured fallback. The peer cap applies only to parseable peer
    // timeouts, not to default_timeout.
    let metadata = meta_with_timeout("not-a-valid-timeout");
    let n = now();
    let fallback = Duration::from_millis(250);
    let ctx = CallContext::from_metadata_at_with_max_deadline(
        metadata,
        Some(fallback),
        Some(Duration::from_millis(10)),
        None,
        n,
    );
    assert_eq!(
        ctx.deadline(),
        n.checked_add(fallback),
        "malformed peer grpc-timeout must use the unclamped default_timeout",
    );
}

#[test]
fn control_prefixed_grpc_timeout_is_rejected_before_deadline_parsing() {
    let fallback = Duration::from_millis(250);

    for malformed in ["\t99999999H", "\x7f99999999H"] {
        let mut metadata = Metadata::new();
        assert!(
            !metadata.insert("grpc-timeout", malformed),
            "control-prefixed timeout must not be normalized into a valid huge timeout",
        );
        assert!(metadata.get("grpc-timeout").is_none());

        let n = now();
        let ctx = CallContext::from_metadata_at_with_max_deadline(
            metadata,
            Some(fallback),
            None,
            None,
            n,
        );
        assert_eq!(
            ctx.deadline(),
            n.checked_add(fallback),
            "rejected timeout must follow the absent-header default path",
        );
    }
}

#[test]
fn binary_grpc_timeout_value_unreachable_via_normalize_key() {
    // Edge: a Binary-typed grpc-timeout falls through to `None`
    // immediately. The CallContext Binary branch is
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
fn duplicate_metadata_entries_use_most_recent_without_summing() {
    // Audit (b): two values inserted into the local Metadata container yield
    // one value through Metadata::get. This is not an H2 ingestion test.
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
        "duplicate-entry deadline must be >150ms (most-recent=200m), got {remaining:?}",
    );
    assert!(
        remaining <= Duration::from_millis(200),
        "duplicate-entry deadline must be ≤200ms (most-recent), NOT 100m+200m=300ms, \
         got {remaining:?}",
    );
}

#[test]
fn duration_max_never_disables_deadline() {
    // Duration::MAX must not wrap or become `None`. On platforms where the
    // addition is unrepresentable, the infallible constructor fails closed at
    // `now`; otherwise it preserves the representable future instant.
    let n = now();
    let ctx = CallContext::from_metadata_at(Metadata::new(), Some(Duration::MAX), None, n);
    assert_eq!(
        ctx.deadline(),
        Some(n.checked_add(Duration::MAX).unwrap_or(n)),
        "Duration::MAX must always produce a deadline",
    );
}
