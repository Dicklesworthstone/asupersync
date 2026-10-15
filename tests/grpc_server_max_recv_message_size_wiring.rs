//! Regression test pinning the `ServerConfig::max_recv_message_size`
//! configuration round-trip through the builder, plus a sanity probe
//! that documents the current wiring gap.
//!
//! Background: a `/security-audit-for-saas` pass on
//! `src/grpc/server.rs` (2026-04-29) found that
//! `ServerConfig::max_recv_message_size` is set via the builder and
//! exposed on the public `Server::config()` accessor, but **no
//! enforcement code path inside server dispatch reads it**. The
//! CLIENT side correctly wires its symmetric setting at
//! `src/grpc/client.rs:109`; the server side does not. The actual
//! wire defense currently runs at the codec layer with its own
//! default. This file exists so a future fix that propagates the
//! configured value into the dispatch codec gets a clear regression
//! target.
//!
//! What this file pins TODAY:
//!   * The builder→config round-trip is correct (operator-set value
//!     reaches `Server::config().max_recv_message_size`).
//!
//! What this file does NOT pin yet:
//!   * Whether a too-large inbound message is actually rejected with
//!     `Status::resource_exhausted` when the configured cap is
//!     smaller than the codec default. That assertion belongs in the
//!     bead `[security-audit-for-saas] grpc/server max_recv_message_size
//!     unwired` once the wiring is added; flipping the lower assertion
//!     from a no-op into a real wire test then closes the gap.
//!
//! Lives under `tests/` so it compiles into its own integration-test
//! binary against the public crate surface.

use asupersync::grpc::ServerBuilder;

/// Builder→config round-trip: the operator-set value MUST reach
/// `Server::config()`. Any divergence here is a hard regression in
/// the builder plumbing — independent of whether the dispatch path
/// reads the value.
#[test]
fn server_builder_round_trips_max_recv_message_size_into_config() {
    const CONFIGURED_LIMIT: usize = 7 * 1024; // 7 KiB — distinct from any default.
    let server = ServerBuilder::new()
        .max_recv_message_size(CONFIGURED_LIMIT)
        .build();
    assert_eq!(
        server.config().max_recv_message_size,
        CONFIGURED_LIMIT,
        "builder must round-trip the operator-set max_recv_message_size into the \
         server's exposed ServerConfig — this is the public contract callers rely \
         on when wiring transport adapters",
    );
}

/// Default value sanity: an unconfigured server reports a non-zero,
/// reasonably sized default. Pins the documented invariant ('default
/// is 4 MiB, matching gRPC ecosystem convention') against accidental
/// regressions to 0 (which would disable enforcement entirely once
/// wiring lands).
#[test]
fn server_default_max_recv_message_size_is_nonzero_and_reasonable() {
    let server = ServerBuilder::new().build();
    let cap = server.config().max_recv_message_size;
    assert!(
        cap > 0,
        "default max_recv_message_size must be non-zero; a 0 default \
         is conventionally treated as 'unlimited' which is exactly the \
         DoS shape this audit is documenting",
    );
    assert!(
        cap >= 1024 * 1024,
        "default max_recv_message_size should be at least 1 MiB to \
         accommodate normal gRPC payloads; got {cap}",
    );
    assert!(
        cap <= 64 * 1024 * 1024,
        "default max_recv_message_size should be reasonably tight; \
         a >64 MiB default is a memory-pressure footgun. Got {cap}",
    );
}
