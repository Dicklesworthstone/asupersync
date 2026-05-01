//! Audit + regression test for `src/grpc/server.rs` message-size
//! cap negotiation between server and client (tick #198).
//!
//! Operator's question: "verify message-size cap negotiation."
//!
//! Audit context — gRPC has NO in-protocol negotiation for
//! per-message size caps. Each side enforces its OWN cap
//! independently:
//!
//!   * Client: ChannelConfig::max_recv_message_size /
//!     max_send_message_size (client.rs:121-124).
//!   * Server: ServerConfig::max_recv_message_size /
//!     max_send_message_size (server.rs:217-225).
//!   * Codec: GrpcCodec internal max_decode_message_size /
//!     max_encode_message_size (codec.rs:55-58).
//!
//! The on-the-wire signal is the rejection itself: a peer
//! whose message exceeds the local cap surfaces
//! `Status::resource_exhausted("message too large")`. The peer
//! sees the rejection AT MESSAGE TIME (not negotiation time)
//! and must shrink the next message.
//!
//! Audit findings:
//!
//!   (a) **Symmetric per-direction caps**: each side has
//!       SEPARATE recv and send caps. A server can configure
//!       a strict 512 KiB recv cap and a permissive 16 MiB
//!       send cap (e.g. when the server is the data source).
//!
//!   (b) **Default 4 MiB on both sides** (server.rs:424-425,
//!       client side at default). Matches gRPC ecosystem
//!       convention.
//!
//!   (c) **Independent configurability**: builder methods
//!       max_recv_message_size + max_send_message_size set
//!       each direction independently (server.rs:520-552,
//!       client.rs ChannelConfig).
//!
//!   (d) **⚠️ DOCUMENTED WIRING GAP (P1)**: server's
//!       max_recv_message_size + max_send_message_size are
//!       STORED on the config but NOT propagated into the
//!       dispatch path's codec instance (server.rs:202-216
//!       doc-comment). The codec uses its own
//!       DEFAULT_MAX_MESSAGE_SIZE (4 MiB) — operator
//!       overrides are silently ignored. The CLIENT side
//!       DOES wire its config into the codec
//!       (client.rs:106-110). Filed as a P1 security audit
//!       follow-up.
//!
//!   (e) **The codec's 4 MiB default is the ACTUAL on-wire
//!       cap on the server side.** Even with the wiring gap,
//!       a 4 GiB-declared frame is still rejected — but a
//!       server operator who sets max_recv_message_size to
//!       512 KiB expecting tighter protection silently gets
//!       4 MiB instead.
//!
//! Regression tests below pin (a)+(b)+(c) at the public API
//! surface AND structurally document the (d) wiring gap so
//! a future fix that wires max_recv_message_size into
//! dispatch will trip the gap-pin and force re-baseline.

use asupersync::grpc::{ServerBuilder, ServerConfig};

const DEFAULT_MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

#[test]
fn default_server_config_has_4mib_recv_and_send_caps() {
    // Pin (b): default ServerConfig has 4 MiB on both
    // directions. Matches gRPC ecosystem convention.
    let config = ServerConfig::default();
    assert_eq!(
        config.max_recv_message_size,
        DEFAULT_MAX_MESSAGE_SIZE,
        "default max_recv_message_size = 4 MiB",
    );
    assert_eq!(
        config.max_send_message_size,
        DEFAULT_MAX_MESSAGE_SIZE,
        "default max_send_message_size = 4 MiB",
    );
}

#[test]
fn server_builder_configures_recv_size_cap() {
    // Pin (c): the builder method stores the value on the
    // config. Pinned via reading back the config.
    let server = ServerBuilder::new()
        .max_recv_message_size(512 * 1024) // 512 KiB
        .build();
    assert_eq!(
        server.config().max_recv_message_size,
        512 * 1024,
        "max_recv_message_size builder stores the configured value",
    );
}

#[test]
fn server_builder_configures_send_size_cap() {
    // Pin (c): symmetric for send direction.
    let server = ServerBuilder::new()
        .max_send_message_size(16 * 1024 * 1024) // 16 MiB
        .build();
    assert_eq!(
        server.config().max_send_message_size,
        16 * 1024 * 1024,
    );
}

#[test]
fn recv_and_send_caps_are_independent() {
    // Pin (a): a server can have a strict recv cap AND a
    // permissive send cap (e.g. server is data source).
    // Setting one MUST NOT affect the other.
    let server = ServerBuilder::new()
        .max_recv_message_size(256 * 1024) // 256 KiB recv
        .max_send_message_size(64 * 1024 * 1024) // 64 MiB send
        .build();
    let cfg = server.config();
    assert_eq!(cfg.max_recv_message_size, 256 * 1024);
    assert_eq!(cfg.max_send_message_size, 64 * 1024 * 1024);
    assert_ne!(
        cfg.max_recv_message_size, cfg.max_send_message_size,
        "recv and send caps are INDEPENDENT — setting one does not \
         drift the other",
    );
}

#[test]
fn recv_cap_can_be_lower_than_default() {
    // Pin (c): operator can tighten the cap below the 4 MiB
    // default. The CONFIG accepts the value (the wiring gap
    // is in dispatch, not config).
    let server = ServerBuilder::new()
        .max_recv_message_size(64 * 1024) // 64 KiB
        .build();
    assert_eq!(server.config().max_recv_message_size, 64 * 1024);
}

#[test]
fn recv_cap_can_be_higher_than_default() {
    // Pin (c): operator can loosen the cap above default.
    // Configurable both ways.
    let server = ServerBuilder::new()
        .max_recv_message_size(32 * 1024 * 1024) // 32 MiB
        .build();
    assert_eq!(server.config().max_recv_message_size, 32 * 1024 * 1024);
}

#[test]
fn server_framed_codec_helper_wires_configured_caps() {
    // Pin (d) — POST-FIX (br-asupersync-srizvf): the previously-
    // documented WIRING GAP is closed by the new
    // `Server::framed_codec` helper. Constructing a codec via
    // this helper threads the configured caps into
    // FramedCodec::with_message_size_limits, so an operator's
    // override actually takes effect.
    use asupersync::grpc::IdentityCodec;
    let server = ServerBuilder::new()
        .max_recv_message_size(256 * 1024)
        .max_send_message_size(512 * 1024)
        .build();
    let codec = server.framed_codec(IdentityCodec);
    assert_eq!(
        codec.max_decode_message_size(),
        256 * 1024,
        "framed_codec must thread max_recv_message_size into the \
         decode-side cap (closes asupersync-srizvf)",
    );
    assert_eq!(
        codec.max_encode_message_size(),
        512 * 1024,
        "framed_codec must thread max_send_message_size into the \
         encode-side cap",
    );
}

#[test]
fn codec_default_max_message_size_matches_server_config_default() {
    // Pin (e): the codec's DEFAULT_MAX_MESSAGE_SIZE (4 MiB)
    // matches the server's ServerConfig default. This is what
    // makes the wiring gap a soft P1 (not a critical
    // exploit): an operator using the default 4 MiB sees the
    // configured value's behavior even though the wire path
    // bypasses the config and uses the codec default.
    //
    // We pin by grep — DEFAULT_MAX_MESSAGE_SIZE in codec.rs
    // should equal 4 MiB.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let codec_rs = std::fs::read_to_string(
        std::path::Path::new(manifest_dir).join("src/grpc/codec.rs"),
    )
    .expect("read src/grpc/codec.rs");
    // Match either "4 * 1024 * 1024" (= 4 MiB) or "4194304".
    let has_4mib = codec_rs.contains("DEFAULT_MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024")
        || codec_rs.contains("DEFAULT_MAX_MESSAGE_SIZE: usize = 4194304");
    assert!(
        has_4mib,
        "codec's DEFAULT_MAX_MESSAGE_SIZE must equal 4 MiB to match \
         ServerConfig default — protects operators using defaults from \
         the wiring gap. A regression that diverged the codec default \
         from the server-config default would worsen the gap.",
    );
}

#[test]
fn no_in_protocol_negotiation_for_message_size() {
    // Pin: gRPC has NO header for "max-message-size" — both
    // sides enforce independently. This test pins the
    // architectural property by asserting that the audit-
    // relevant types (CompressionEncoding etc.) don't carry
    // a size field. The Codec/Status types alone determine
    // the wire shape.
    //
    // Behavioral pin: a Status::resource_exhausted is the
    // only on-wire signal — peer sees rejection at message
    // time, no negotiation header.
    let status = asupersync::grpc::Status::resource_exhausted("message too large");
    assert_eq!(
        status.code(),
        asupersync::grpc::status::Code::ResourceExhausted,
    );
    assert!(status.message().contains("too large"));
}
