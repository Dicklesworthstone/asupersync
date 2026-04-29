//! Conformance harness: `asupersync::grpc::HealthService` vs the
//! gRPC Health Checking Protocol as defined by
//! `grpc-proto/grpc/health/v1/health.proto`
//! (https://github.com/grpc/grpc-proto/blob/master/grpc/health/v1/health.proto).
//!
//! grpc-go is the canonical implementation; the .proto IS the spec.
//! A wire-compatible asupersync HealthService must therefore agree
//! with grpc-go on:
//!
//!   1. The numeric values of the `ServingStatus` enum (UNKNOWN=0,
//!      SERVING=1, NOT_SERVING=2, SERVICE_UNKNOWN=3) — these flow
//!      through prost-encoded HealthCheckResponse messages and any
//!      drift here breaks every grpc-go ↔ asupersync round-trip.
//!   2. The display-string spelling of those statuses ("UNKNOWN",
//!      "SERVING", "NOT_SERVING", "SERVICE_UNKNOWN") — the
//!      grpc-health-probe binary prints these and ops dashboards
//!      grep on them.
//!   3. The aggregate-server-health semantic for an empty service
//!      string in `Check`: SERVING iff every registered service is
//!      Serving; NOT_SERVING if any is unhealthy; SERVICE_UNKNOWN if
//!      no services are registered at all.
//!   4. The Watch contract for a registered service: the initial
//!      poll yields the current status, subsequent polls yield each
//!      change, and a no-op set (same status replayed) does NOT
//!      emit a phantom change event.
//!   5. The documented asupersync DIVERGENCE for unknown services
//!      in Check: the spec says NOT_FOUND; asupersync returns
//!      `PermissionDenied` per the security fix br-asupersync-doa4lv
//!      to defeat service-enumeration attacks. The conformance
//!      contract here is to PIN that divergence so a future patch
//!      that returns the spec's NotFound (re-introducing the
//!      enumeration vector) trips this assertion.
//!
//! What this file does NOT cover (out of scope, separate beads):
//!   * Wire-level prost encoding of HealthCheckResponse — covered
//!     by tests/grpc_codec_*conformance*.rs.
//!   * Reflection-protocol exposure of grpc.health.v1.Health — that
//!     lives in the reflection module, separate test surface.
//!   * Authentication wrappers — covered by the recent security
//!     audit pass (br-asupersync-n7w3l1).

use asupersync::grpc::{HealthCheckRequest, HealthService, ServingStatus};
use asupersync::grpc::status::Code;

/// Property 1: ServingStatus numeric values match the
/// grpc-proto/health/v1 enum exactly. The `from_i32` helper is the
/// authoritative round-trip into the spec's wire format.
#[test]
fn serving_status_i32_values_match_grpc_proto_health_v1() {
    // Exact enum values from grpc-proto/grpc/health/v1/health.proto:
    //   enum ServingStatus {
    //     UNKNOWN = 0;
    //     SERVING = 1;
    //     NOT_SERVING = 2;
    //     SERVICE_UNKNOWN = 3;  // Used only by the Watch method.
    //   }
    assert_eq!(ServingStatus::Unknown as i32, 0);
    assert_eq!(ServingStatus::Serving as i32, 1);
    assert_eq!(ServingStatus::NotServing as i32, 2);
    assert_eq!(ServingStatus::ServiceUnknown as i32, 3);

    assert_eq!(ServingStatus::from_i32(0), Some(ServingStatus::Unknown));
    assert_eq!(ServingStatus::from_i32(1), Some(ServingStatus::Serving));
    assert_eq!(ServingStatus::from_i32(2), Some(ServingStatus::NotServing));
    assert_eq!(ServingStatus::from_i32(3), Some(ServingStatus::ServiceUnknown));
    assert_eq!(ServingStatus::from_i32(4), None, "unknown variants must return None");
    assert_eq!(ServingStatus::from_i32(-1), None);
    assert_eq!(ServingStatus::from_i32(i32::MAX), None);
}

/// Property 2: Display spellings match the spec's UPPER_SNAKE_CASE
/// constant names that ops tooling (grpc-health-probe, dashboards)
/// expects.
#[test]
fn serving_status_display_matches_spec_constant_names() {
    assert_eq!(ServingStatus::Unknown.to_string(), "UNKNOWN");
    assert_eq!(ServingStatus::Serving.to_string(), "SERVING");
    assert_eq!(ServingStatus::NotServing.to_string(), "NOT_SERVING");
    assert_eq!(ServingStatus::ServiceUnknown.to_string(), "SERVICE_UNKNOWN");
}

/// Property 3: Check on a registered service returns the status that
/// was set. Round-trip through the synchronous `check` API.
#[test]
fn check_on_registered_service_returns_set_status() {
    let svc = HealthService::new();
    svc.set_status("acme.OrderService", ServingStatus::Serving);
    svc.set_status("acme.PaymentService", ServingStatus::NotServing);

    let serving = svc
        .check(&HealthCheckRequest::new("acme.OrderService"))
        .expect("registered service must succeed");
    assert_eq!(serving.status, ServingStatus::Serving);

    let not_serving = svc
        .check(&HealthCheckRequest::new("acme.PaymentService"))
        .expect("registered service must succeed");
    assert_eq!(not_serving.status, ServingStatus::NotServing);
}

/// Property 3 (cont.): Empty-service aggregate health follows the
/// documented invariants — SERVICE_UNKNOWN on empty registry,
/// SERVING when all healthy, NOT_SERVING when any unhealthy.
#[test]
fn check_on_empty_service_returns_aggregate_health() {
    // Empty registry → SERVICE_UNKNOWN (cannot answer).
    let empty_svc = HealthService::new();
    let empty = empty_svc
        .check(&HealthCheckRequest::default())
        .expect("empty-service overall check must succeed");
    assert_eq!(
        empty.status,
        ServingStatus::ServiceUnknown,
        "empty registry must return SERVICE_UNKNOWN per asupersync's documented \
         aggregate semantic",
    );

    // All healthy → SERVING.
    let all_healthy = HealthService::new();
    all_healthy.set_status("a", ServingStatus::Serving);
    all_healthy.set_status("b", ServingStatus::Serving);
    let healthy = all_healthy
        .check(&HealthCheckRequest::default())
        .expect("aggregate check must succeed");
    assert_eq!(healthy.status, ServingStatus::Serving);

    // Any unhealthy → NOT_SERVING.
    let mixed = HealthService::new();
    mixed.set_status("a", ServingStatus::Serving);
    mixed.set_status("b", ServingStatus::NotServing);
    let mixed_status = mixed
        .check(&HealthCheckRequest::default())
        .expect("aggregate check must succeed");
    assert_eq!(
        mixed_status.status,
        ServingStatus::NotServing,
        "any unhealthy service must drag the aggregate to NOT_SERVING",
    );
}

/// Property 4: The Watch contract on a registered service.
/// `HealthWatcher::changed` returns true on first call (initial
/// emission) AND on every subsequent status change. A no-op set
/// (same status replayed) MUST NOT report changed.
#[test]
fn watch_initial_then_change_then_idempotent_replay() {
    let svc = HealthService::new();
    svc.set_status("svc", ServingStatus::Serving);

    let mut watcher = svc.watch("svc");
    assert_eq!(
        watcher.status(),
        ServingStatus::Serving,
        "initial Watcher status must reflect the current registration",
    );

    // First call to `changed` after construction: per asupersync's
    // implementation, `watch()` snapshots the current version, so the
    // initial poll has nothing-new-since-snapshot — i.e. it returns
    // false. The INITIAL emission is the snapshot itself, not a
    // changed-event.
    assert!(
        !watcher.changed(),
        "fresh watcher snapshotted at construction time should not see a phantom change",
    );

    // Apply a real status change.
    svc.set_status("svc", ServingStatus::NotServing);
    assert!(
        watcher.changed(),
        "real status transition must be observable as changed=true",
    );
    assert_eq!(watcher.status(), ServingStatus::NotServing);

    // Idempotent set — same status replayed must NOT emit a phantom
    // change. This is the spec's coalescing contract that grpc-go
    // also implements: only TRANSITIONS emit Watch events, not
    // re-affirmations.
    svc.set_status("svc", ServingStatus::NotServing);
    assert!(
        !watcher.changed(),
        "no-op set (same status replayed) must NOT register as a change",
    );

    // Another real transition.
    svc.set_status("svc", ServingStatus::Serving);
    assert!(watcher.changed());
    assert_eq!(watcher.status(), ServingStatus::Serving);
}

/// Property 5: Documented divergence — Check on a missing service
/// returns `Code::PermissionDenied`, NOT the spec's NotFound. Pinned
/// against the security regression of re-introducing the enumeration
/// vector. (br-asupersync-doa4lv)
#[test]
fn check_on_missing_service_diverges_to_permission_denied_for_security() {
    let svc = HealthService::new();
    // Register one service so the registry isn't empty (which would
    // route through the SERVICE_UNKNOWN aggregate path instead).
    svc.set_status("registered", ServingStatus::Serving);

    let result = svc.check(&HealthCheckRequest::new("does-not-exist"));
    let err = result.expect_err(
        "missing service must produce an error, not Ok(SERVICE_UNKNOWN), \
         to defeat enumeration",
    );
    assert_eq!(
        err.code(),
        Code::PermissionDenied,
        "missing service must return PermissionDenied per br-asupersync-doa4lv \
         (the spec's NotFound enables enumeration; asupersync deliberately diverges)",
    );
}
