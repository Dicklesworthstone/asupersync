//! Audit + regression test for `src/grpc/server.rs` server-side
//! compression registry / builder surface (tick #194).
//!
//! Operator's question: "verify Compression scheme registry."
//! Extends ticks #178 (closed-enum allowlist) + #184 (negotiation
//! flow) with the SERVER-builder configuration surface.
//!
//! Audit findings:
//!
//!   (a) **`ServerConfig` defaults** (server.rs:435-436):
//!         * `send_compression: None` — server does NOT compress
//!           responses unless operator opts in via
//!           `.send_compression(...)`. Conservative posture; a
//!           regression to gzip-by-default would change wire bytes
//!           for every response and break clients that don't
//!           advertise gzip in `grpc-accept-encoding`.
//!         * `accept_compression: vec![Identity]` — server accepts
//!           uncompressed payloads by default. Identity always
//!           supported (audited tick #155).
//!
//!   (b) **`send_compression(encoding)` builder method**
//!       (server.rs:618-621). Sets the outbound compression
//!       encoding to `Some(encoding)`. Operator must call this
//!       explicitly to enable server-side compression.
//!
//!   (c) **`accept_compression(encoding)` APPENDS** (server.rs:
//!       625-628 — `self.config.accept_compression.push(encoding)`).
//!       Multiple calls accumulate. The default Identity stays
//!       in the list.
//!
//!   (d) **`accept_compressions(iter)` REPLACES** (server.rs:
//!       632-639 — `clear();.extend(...)`). Operators that want
//!       a strict accept list can explicitly clear and set —
//!       e.g. `accept_compressions([Identity, Gzip])` produces
//!       the canonical 2-encoding list.
//!
//!   (e) **No exotic-encoding escape hatch.** Both builder
//!       methods take `CompressionEncoding` (closed enum,
//!       audited tick #178). An operator cannot pass a String
//!       — adding a new encoding requires an enum variant.
//!
//!   (f) **The accept list is operator-bounded.** Even with
//!       repeated `.accept_compression(...)` calls, the list
//!       contains only `CompressionEncoding` values. There is
//!       no operator-supplied free-form encoding name.
//!
//! Regression tests below pin (a)-(d).

use asupersync::grpc::CompressionEncoding;
use asupersync::grpc::{ServerBuilder, ServerConfig};

#[test]
fn default_server_config_does_not_send_compression() {
    // Pin (a): default ServerConfig::send_compression is None.
    // Server emits uncompressed responses unless operator opts
    // in.
    let config = ServerConfig::default();
    assert!(
        config.send_compression.is_none(),
        "default server emits uncompressed responses; got {:?}",
        config.send_compression,
    );
}

#[test]
fn default_server_config_accepts_only_identity() {
    // Pin (a): default accept list is exactly [Identity].
    // Identity is always supported per gRPC spec; gzip is
    // operator opt-in.
    let config = ServerConfig::default();
    assert_eq!(
        config.accept_compression.len(),
        1,
        "default accept_compression has exactly one entry (Identity); \
         got {} entries",
        config.accept_compression.len(),
    );
    assert_eq!(
        config.accept_compression[0],
        CompressionEncoding::Identity,
        "default accept entry is Identity",
    );
}

#[test]
fn send_compression_builder_sets_outbound_encoding() {
    // Pin (b): the builder method sets send_compression to
    // Some(encoding). Operator's explicit opt-in.
    let server = ServerBuilder::new()
        .send_compression(CompressionEncoding::Gzip)
        .build();
    let config = server.config();
    assert_eq!(
        config.send_compression,
        Some(CompressionEncoding::Gzip),
        "send_compression builder must set the outbound encoding",
    );
}

#[test]
fn accept_compression_appends_to_default_list() {
    // Pin (c): accept_compression APPENDS. Default Identity
    // stays at index 0; new encoding appears at index 1.
    let server = ServerBuilder::new()
        .accept_compression(CompressionEncoding::Gzip)
        .build();
    let config = server.config();
    assert_eq!(
        config.accept_compression.len(),
        2,
        "accept_compression appends — list has both Identity (default) \
         and Gzip (added); got {:?}",
        config.accept_compression,
    );
    assert_eq!(
        config.accept_compression[0],
        CompressionEncoding::Identity,
        "Identity stays at index 0 (default)",
    );
    assert_eq!(
        config.accept_compression[1],
        CompressionEncoding::Gzip,
        "Gzip appears at index 1 (appended)",
    );
}

#[test]
fn accept_compressions_replaces_list_atomically() {
    // Pin (d): accept_compressions clears the existing list
    // before extending. A regression that appended (instead
    // of clear-then-extend) would leave stale defaults in
    // the list.
    let server = ServerBuilder::new()
        .accept_compressions([CompressionEncoding::Gzip])
        .build();
    let config = server.config();
    assert_eq!(
        config.accept_compression.len(),
        1,
        "accept_compressions REPLACES — list contains exactly the \
         supplied encoding; got {:?}",
        config.accept_compression,
    );
    assert_eq!(
        config.accept_compression[0],
        CompressionEncoding::Gzip,
        "Gzip is the sole entry after replacement (default Identity \
         was cleared)",
    );
}

#[test]
fn accept_compressions_with_empty_iter_produces_empty_list() {
    // Pin (d) edge: passing an empty iterator clears the list.
    // The server then accepts NO compression — peers that
    // advertise compression get rejected. Pinned to make sure
    // this edge doesn't accidentally retain Identity.
    let server = ServerBuilder::new()
        .accept_compressions(std::iter::empty::<CompressionEncoding>())
        .build();
    let config = server.config();
    assert!(
        config.accept_compression.is_empty(),
        "empty replacement produces empty accept list; got {:?}",
        config.accept_compression,
    );
}

#[test]
fn multiple_accept_compression_calls_accumulate() {
    // Pin (c) extension: chained .accept_compression calls
    // accumulate. The list grows monotonically without
    // de-duplication (operator's responsibility to avoid
    // duplicates).
    let server = ServerBuilder::new()
        .accept_compression(CompressionEncoding::Gzip)
        .accept_compression(CompressionEncoding::Identity) // duplicate
        .accept_compression(CompressionEncoding::Gzip) // duplicate
        .build();
    let config = server.config();
    // Default Identity + 3 appended = 4 entries (no dedup).
    assert_eq!(
        config.accept_compression.len(),
        4,
        "chained appends accumulate without de-duplication; got {:?}",
        config.accept_compression,
    );
}

#[test]
fn server_builder_compression_chain_preserves_other_config() {
    // Pin: the compression builder methods only touch
    // compression fields. Other config (max_metadata_size,
    // max_request_deadline) stays at defaults.
    let server = ServerBuilder::new()
        .send_compression(CompressionEncoding::Gzip)
        .accept_compression(CompressionEncoding::Gzip)
        .build();
    let config = server.config();
    assert_eq!(
        config.max_metadata_size,
        asupersync::grpc::server::DEFAULT_MAX_METADATA_SIZE,
        "unrelated config (max_metadata_size) MUST stay at default",
    );
    assert!(
        config.max_request_deadline.is_none(),
        "unrelated config (max_request_deadline) MUST stay at default",
    );
}

#[test]
fn config_compression_fields_use_closed_enum() {
    // Pin (e): the type signature on ServerConfig fields is
    // `Option<CompressionEncoding>` and `Vec<CompressionEncoding>`.
    // No String / free-form escape hatch. Compiler enforces.
    //
    // We can't directly check the type from a test, but we
    // pin behaviorally: building with arbitrary u8 / String
    // does NOT compile (ensured at compile time by the
    // builder's type signature).
    //
    // Sanity: only the closed-enum variants flow into the
    // accept list.
    let server = ServerBuilder::new()
        .accept_compressions([CompressionEncoding::Identity, CompressionEncoding::Gzip])
        .build();
    let config = server.config();
    for entry in &config.accept_compression {
        // Exhaustive match ensures every entry is one of the
        // closed-enum variants. A regression that added a
        // String escape hatch would surface as a non-matching
        // entry.
        match entry {
            CompressionEncoding::Identity | CompressionEncoding::Gzip => {}
        }
    }
}

#[test]
fn default_send_compression_change_would_break_interop() {
    // Pin (a) negative: a regression that changed the default
    // send_compression to Some(Gzip) would break interop with
    // clients that don't advertise gzip in their
    // grpc-accept-encoding. This test pins the conservative
    // default so the change would need explicit re-baseline.
    let config = ServerConfig::default();
    assert_eq!(
        config.send_compression, None,
        "default send_compression MUST stay None — flipping to a \
         compressed default would change the wire bytes for every \
         response and break vanilla gRPC clients that don't advertise \
         gzip in grpc-accept-encoding",
    );
}
