//! Audit + regression test for `src/grpc/server.rs` HEADERS-frame
//! size cap negotiation (tick #206, extends ticks #140 + #193).
//!
//! Operator's question: "verify HEADERS frame size cap
//! negotiation."
//!
//! gRPC + HTTP/2 layered model:
//!
//!     HTTP/2 layer (RFC 7540 §6.5.2):
//!       * SETTINGS_MAX_HEADER_LIST_SIZE — advisory cap the server
//!         announces to the client via SETTINGS frame. Default in
//!         asupersync: 64 KiB. Well-behaved clients respect it.
//!       * SETTINGS_HEADER_TABLE_SIZE — HPACK dynamic table size.
//!       * Enforced at the HTTP/2 connection layer; oversize frames
//!         get GOAWAY with ENHANCE_YOUR_CALM.
//!
//!     gRPC layer:
//!       * ServerConfig::max_metadata_size — post-decode hard cap.
//!         Default 8 KiB. Rejected with Status::resource_exhausted
//!         (audited tick #193).
//!
//! Audit findings:
//!
//!   (a) **Two-layer enforcement** — HTTP/2 announces a SOFT
//!       advisory (64 KiB) via SETTINGS, gRPC enforces a HARDER
//!       per-call cap (8 KiB) via post-decode validation. The
//!       gRPC cap is tighter — a client respecting the HTTP/2
//!       advisory might still get rejected at the gRPC layer.
//!
//!   (b) **NO in-protocol header for gRPC's tighter cap.** The
//!       HTTP/2 SETTINGS frame announces 64 KiB to the client.
//!       The gRPC server's 8 KiB cap is enforced on the receive
//!       side without an explicit advertisement. A client that
//!       sends >8 KiB but <64 KiB hits the gRPC reject without
//!       a prior negotiation signal — this is documented
//!       behavior (gRPC over HTTP/2 doesn't have a separate
//!       max-header-list-size advertisement).
//!
//!   (c) **Asymmetric defaults**: HTTP/2 advisory 64 KiB,
//!       gRPC hard cap 8 KiB. Operators can configure both
//!       independently; the hard cap is what actually
//!       triggers ResourceExhausted.
//!
//!   (d) **Both caps configurable**:
//!       * HTTP/2: Settings::max_header_list_size (per-connection)
//!       * gRPC: ServerConfig::max_metadata_size (per-server,
//!         applied to every call) (audited tick #193).
//!
//!   (e) **gRPC cap fires even if HTTP/2 cap was never announced**
//!       (e.g. transport adapter that doesn't send SETTINGS, or
//!       SETTINGS hasn't been ACKed yet). The post-decode gRPC
//!       enforcement is the universal gate.
//!
//! Regression tests below pin (a)-(e).

use asupersync::grpc::server::{DEFAULT_MAX_METADATA_SIZE, enforce_metadata_size_limit};
use asupersync::grpc::status::Code;
use asupersync::grpc::streaming::Metadata;
use asupersync::grpc::{ServerBuilder, ServerConfig};
use asupersync::http::h2::settings::{DEFAULT_MAX_HEADER_LIST_SIZE, Settings, SettingsBuilder};

#[test]
fn http2_default_max_header_list_size_is_64_kib() {
    // Pin (a) HTTP/2 layer: the advisory cap. Servers
    // announce this via SETTINGS frame.
    assert_eq!(
        DEFAULT_MAX_HEADER_LIST_SIZE, 65536,
        "HTTP/2 SETTINGS_MAX_HEADER_LIST_SIZE default = 64 KiB \
         (advisory per RFC 7540 §6.5.2)",
    );
    let s = Settings::default();
    assert_eq!(s.max_header_list_size, DEFAULT_MAX_HEADER_LIST_SIZE);
}

#[test]
fn grpc_default_max_metadata_size_is_8_kib() {
    // Pin (a) gRPC layer: the per-call hard cap.
    assert_eq!(
        DEFAULT_MAX_METADATA_SIZE,
        8 * 1024,
        "gRPC ServerConfig::max_metadata_size default = 8 KiB \
         (hard cap, post-decode reject)",
    );
}

#[test]
fn grpc_cap_is_tighter_than_http2_advisory() {
    // Pin (a)+(c): the gRPC cap is intentionally TIGHTER than
    // the HTTP/2 advisory. A regression that loosened the gRPC
    // cap to match HTTP/2 would lose the per-call defense.
    let h2 = Settings::default();
    let grpc = ServerConfig::default();
    assert!(
        u32::try_from(grpc.max_metadata_size).unwrap() < h2.max_header_list_size,
        "gRPC's hard cap ({}) MUST be tighter than HTTP/2's advisory \
         ({}) — defense-in-depth: HTTP/2 is the SOFT outer ring, \
         gRPC is the HARD per-call gate",
        grpc.max_metadata_size,
        h2.max_header_list_size,
    );
}

#[test]
fn metadata_in_grpc_window_below_http2_advisory_still_rejects() {
    // Pin (b): a metadata block that would PASS the HTTP/2
    // advisory (e.g. 16 KiB <= 64 KiB) but EXCEED the gRPC
    // cap (>8 KiB) STILL gets rejected at the gRPC layer.
    // Client respecting only HTTP/2 advisory is not safe.
    let mut metadata = Metadata::new();
    let chunk = "X".repeat(4 * 1024);
    assert!(metadata.insert("x-large-a", &chunk));
    assert!(metadata.insert("x-large-b", &chunk));
    assert!(metadata.insert("x-large-c", &chunk));
    assert!(metadata.insert("x-large-d", &chunk));
    // 16 KiB aggregate > 8 KiB gRPC cap, with each value under the
    // separate per-header-value validation cap → rejected by aggregate cap.
    let err = enforce_metadata_size_limit(&metadata, DEFAULT_MAX_METADATA_SIZE)
        .expect_err("16 KiB metadata exceeds gRPC 8 KiB cap, must reject");
    assert_eq!(
        err.code(),
        Code::ResourceExhausted,
        "rejection at gRPC cap is ResourceExhausted (gRPC equivalent \
         of HTTP 431). The HTTP/2 advisory of 64 KiB is irrelevant — \
         gRPC's 8 KiB hard cap is the actual gate.",
    );
}

#[test]
fn http2_settings_can_be_configured_independently() {
    // Pin (d) HTTP/2 layer: max_header_list_size builder
    // method on Settings.
    let s = SettingsBuilder::new()
        .max_header_list_size(32 * 1024) // tighten to 32 KiB
        .build();
    assert_eq!(s.max_header_list_size, 32 * 1024);
}

#[test]
fn grpc_max_metadata_size_can_be_configured_independently() {
    // Pin (d) gRPC layer: max_metadata_size builder method
    // on ServerBuilder.
    let server = ServerBuilder::new().max_metadata_size(2 * 1024).build();
    assert_eq!(server.config().max_metadata_size, 2 * 1024);
}

#[test]
fn http2_advisory_settings_round_trip_through_settings_struct() {
    // Pin (e): the HTTP/2 SETTINGS announcement is emitted via
    // the settings_with_defaults filter — only non-default
    // values are sent. A regression that announced wrong
    // values would mislead clients about the advisory cap.
    let s = SettingsBuilder::new()
        .max_header_list_size(32 * 1024) // operator override
        .build();
    let encoded = s.to_settings();
    let dbg = format!("{encoded:?}");
    assert!(
        dbg.contains("MaxHeaderListSize") && dbg.contains("32768"),
        "operator-overridden max_header_list_size MUST be announced \
         via SETTINGS frame; got {dbg}",
    );
}

#[test]
fn grpc_metadata_size_zero_disables_check_via_no_cap_convention() {
    // Pin (d) edge: limit=0 means "no cap" (gRPC layer
    // convention, audited tick #193). A peer sending huge
    // headers when configured 0 passes the gRPC cap check
    // but STILL faces the HTTP/2 advisory at the connection
    // layer.
    let mut metadata = Metadata::new();
    let chunk = "Y".repeat(4 * 1024);
    for index in 0..16 {
        assert!(metadata.insert(format!("x-huge-{index}"), &chunk));
    }
    enforce_metadata_size_limit(&metadata, 0)
        .expect("limit=0 disables gRPC cap; HTTP/2 cap is independent");
}

#[test]
fn negotiation_layers_compose_independently() {
    // Pin (a)+(d): operators can configure HTTP/2 advisory
    // and gRPC hard cap independently. A server with HTTP/2
    // 16 KiB + gRPC 4 KiB has the gRPC cap as the actual
    // gate; the HTTP/2 advisory just informs the client of
    // the wider connection-layer limit.
    let server = ServerBuilder::new()
        .max_metadata_size(4 * 1024) // gRPC 4 KiB
        .build();
    let h2 = SettingsBuilder::new()
        .max_header_list_size(16 * 1024) // HTTP/2 16 KiB
        .build();
    assert_eq!(server.config().max_metadata_size, 4 * 1024);
    assert_eq!(h2.max_header_list_size, 16 * 1024);
    // The two values are independent.
    assert!(
        u32::try_from(server.config().max_metadata_size).unwrap() < h2.max_header_list_size,
        "operator's gRPC cap is tighter than the HTTP/2 advisory — \
         the advisory tells the client about the connection-layer \
         limit, the gRPC cap is the per-call hard gate",
    );
}

#[test]
fn grpc_cap_works_even_if_http2_settings_never_acked() {
    // Pin (e): the gRPC layer's enforcement does NOT depend
    // on the HTTP/2 SETTINGS being announced or ACKed. A
    // transport adapter that decodes HEADERS without
    // pre-announcing SETTINGS still gets the gRPC cap to
    // fire on oversize metadata.
    //
    // We exercise this directly: enforce_metadata_size_limit
    // is a pure function of the metadata + cap; no HTTP/2
    // settings dependency.
    let mut metadata = Metadata::new();
    let chunk = "Z".repeat(4 * 1024);
    assert!(metadata.insert("x-big-a", &chunk));
    assert!(metadata.insert("x-big-b", &chunk));
    assert!(metadata.insert("x-big-c", &chunk));
    assert!(metadata.insert("x-big-d", &chunk));
    let err = enforce_metadata_size_limit(&metadata, 8 * 1024)
        .expect_err("rejection independent of HTTP/2 SETTINGS state");
    assert_eq!(err.code(), Code::ResourceExhausted);
}
