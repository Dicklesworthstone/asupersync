//! `transport_quic` Phase B scaffold contract (b0k8qo.2.1 / arq-quic-epic).
//!
//! Pins B1's acceptance from OUTSIDE the crate (robust to internal `cfg(test)`
//! churn): the ATP-over-QUIC transport exposes a public API that mirrors
//! `transport_tcp`'s shapes EXACTLY, reuses the manifest/report/receipt wire
//! types, validates its `QuicConfig`, and makes unwired transfer entry points
//! FAIL CLOSED with typed errors, never fake success. B2 has since wired
//! `send_path` source preflight before the native connect boundary, and B3 has
//! wired `receive_connection`; this contract pins those boundaries instead of
//! the old all-`NotImplemented` scaffold.
//!
//! These tests drive the real public functions (no mocks). The async entry
//! points are exercised with a runtime-free `block_on`, and `Cx::for_testing`
//! requires `--features test-internals`.

#![allow(missing_docs)]

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use asupersync::cx::Cx;
use asupersync::net::atp::transport_quic::{
    self, ManifestEntry, QuicConfig, QuicTransportError, ReceiveReceipt, ReceiveReport, SendReport,
    TransferManifest, receive_connection, receive_once, send_path,
};
use asupersync::net::quic_native::{
    ManagedEndpointConfig, ManagedQuicEndpoint, NativeQuicConnection, NativeQuicConnectionConfig,
};

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    futures_lite::future::block_on(fut)
}

fn trusted_quic_config() -> QuicConfig {
    QuicConfig::default().allow_unauthenticated_for_trusted_transport()
}

// ─── Public API surface mirrors transport_tcp ────────────────────────────────

/// All four transfer entry points are public items at the mirrored paths.
/// (`send_path` / `receive_connection` signatures are pinned exactly by the
/// calling tests below; `receive_once` / `serve` are referenced here since they
/// take a `ManagedQuicEndpoint` that is heavier to construct in a unit test.)
#[test]
fn public_api_entry_points_exist() {
    let _ = transport_quic::send_path;
    let _ = transport_quic::receive_once;
    let _ = transport_quic::receive_connection;
    let _ = transport_quic::serve::<fn(Result<ReceiveReport, QuicTransportError>)>;
}

/// The manifest/report/receipt types are REUSED from `transport_tcp` (same
/// types, re-exported), not re-declared — so QUIC and TCP commit to one schema.
#[test]
fn manifest_and_receipt_types_are_reused_from_transport_tcp() {
    // Type identity: a transport_tcp value is assignable to a transport_quic
    // binding of the re-exported name. If these were distinct types this would
    // not compile.
    let tcp_manifest = asupersync::net::atp::transport_tcp::TransferManifest {
        transfer_id: "t".to_string(),
        root_name: "r".to_string(),
        is_directory: false,
        total_bytes: 0,
        merkle_root_hex: "00".repeat(32),
        metadata_root_hex: None,
        entries: vec![],
    };
    let quic_manifest: TransferManifest = tcp_manifest;
    assert_eq!(quic_manifest.entries.len(), 0);

    let tcp_receipt = asupersync::net::atp::transport_tcp::ReceiveReceipt {
        committed: false,
        bytes_received: 0,
        files: 0,
        sha_ok: false,
        merkle_ok: false,
        reason: Some("x".to_string()),
        committed_paths: vec![],
    };
    let _quic_receipt: ReceiveReceipt = tcp_receipt;
}

// ─── QuicConfig validation ───────────────────────────────────────────────────

#[test]
fn default_config_requires_symbol_auth_or_trusted_mode() {
    assert!(matches!(
        QuicConfig::default().validate(),
        Err(QuicTransportError::Config(message)) if message.contains("symbol_auth_context")
    ));
    assert!(trusted_quic_config().validate().is_ok());
}

#[test]
fn config_validation_rejects_nonsense_knobs() {
    let bad = [
        QuicConfig {
            chunk_size: 0,
            ..trusted_quic_config()
        },
        QuicConfig {
            symbol_size: 0,
            ..trusted_quic_config()
        },
        QuicConfig {
            max_block_size: 0,
            ..trusted_quic_config()
        },
        QuicConfig {
            symbol_size: 4000,
            max_datagram_size: 1200,
            ..trusted_quic_config()
        },
        QuicConfig {
            // raw symbol fits the datagram, but symbol + envelope header does not
            symbol_size: 1199,
            max_datagram_size: 1200,
            ..trusted_quic_config()
        },
        QuicConfig {
            repair_overhead: 0.0,
            ..trusted_quic_config()
        },
        QuicConfig {
            max_transfer_bytes: 0,
            ..trusted_quic_config()
        },
        QuicConfig {
            idle_timeout: Duration::ZERO,
            ..trusted_quic_config()
        },
        QuicConfig {
            handshake_timeout: Duration::ZERO,
            ..trusted_quic_config()
        },
        QuicConfig {
            accept_timeout: Duration::ZERO,
            ..trusted_quic_config()
        },
        QuicConfig {
            max_feedback_rounds: 0,
            ..trusted_quic_config()
        },
    ];
    for cfg in bad {
        assert!(
            matches!(cfg.validate(), Err(QuicTransportError::Config(_))),
            "config {cfg:?} should fail validation"
        );
    }
}

// ─── Error taxonomy / Display ────────────────────────────────────────────────

#[test]
fn not_implemented_display_is_actionable() {
    let e = QuicTransportError::NotImplemented {
        operation: "send_path",
        wired_by: "asupersync-arq-quic-epic-b0k8qo.2.2 (B2: QUIC sender coroutine)",
    };
    let s = e.to_string();
    assert!(s.contains("send_path"));
    assert!(s.contains("b0k8qo.2.2"));
    assert!(s.contains("failing closed"));
}

#[test]
fn timeout_and_too_large_display_carry_context() {
    let t = QuicTransportError::Timeout {
        operation: "receive frame",
        timeout: Duration::from_secs(30),
    };
    assert!(t.to_string().contains("receive frame"));
    assert!(t.to_string().contains("30s"));

    let big = QuicTransportError::TooLarge {
        size: 5_000,
        max: 1_000,
    };
    assert!(big.to_string().contains("5000"));
    assert!(big.to_string().contains("1000"));
}

// ─── JSON round-trips on the reused wire types ───────────────────────────────

#[test]
fn manifest_json_roundtrips() {
    let manifest = TransferManifest {
        transfer_id: "abc123".to_string(),
        root_name: "tree".to_string(),
        is_directory: true,
        total_bytes: 1234,
        merkle_root_hex: "ab".repeat(32),
        metadata_root_hex: None,
        entries: vec![
            ManifestEntry {
                index: 0,
                rel_path: "dir/a.txt".to_string(),
                size: 1000,
                sha256_hex: "11".repeat(32),
                metadata: None,
            },
            ManifestEntry {
                index: 1,
                rel_path: "dir/b.bin".to_string(),
                size: 234,
                sha256_hex: "22".repeat(32),
                metadata: None,
            },
        ],
    };
    let json = serde_json::to_vec(&manifest).unwrap();
    let back: TransferManifest = serde_json::from_slice(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn receipt_json_roundtrips_committed_and_rejected() {
    let committed = ReceiveReceipt {
        committed: true,
        bytes_received: 1234,
        files: 2,
        sha_ok: true,
        merkle_ok: true,
        reason: None,
        committed_paths: vec!["/dest/dir/a.txt".to_string(), "/dest/dir/b.bin".to_string()],
    };
    let rejected = ReceiveReceipt {
        committed: false,
        bytes_received: 1234,
        files: 2,
        sha_ok: false,
        merkle_ok: true,
        reason: Some("per-entry SHA-256 mismatch".to_string()),
        committed_paths: vec![],
    };
    for r in [committed, rejected] {
        let json = serde_json::to_vec(&r).unwrap();
        let back: ReceiveReceipt = serde_json::from_slice(&json).unwrap();
        assert_eq!(r, back);
    }
}

// ─── Fail-closed: unwired boundaries return typed errors, never fake success ──

#[test]
fn send_path_rejects_missing_source_before_native_connect() {
    let cx = Cx::for_testing();
    let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let temp = tempfile::tempdir().expect("temp dir");
    let missing = temp.path().join("definitely-missing-payload.bin");
    let result: Result<SendReport, QuicTransportError> = block_on(send_path(
        &cx,
        addr,
        &missing,
        trusted_quic_config(),
        "sender",
    ));
    assert!(
        matches!(result, Err(QuicTransportError::Source(_))),
        "missing source should fail before native connect, got {result:?}"
    );
}

#[test]
fn send_path_valid_source_fails_closed_at_native_connect_boundary() {
    let cx = Cx::for_testing();
    let temp = tempfile::tempdir().expect("temp dir");
    let source = temp.path().join("payload.bin");
    std::fs::write(&source, b"payload").expect("write source");
    let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let result: Result<SendReport, QuicTransportError> = block_on(send_path(
        &cx,
        addr,
        &source,
        trusted_quic_config(),
        "sender",
    ));
    assert!(matches!(
        result,
        Err(QuicTransportError::NotImplemented {
            operation: "send_path",
            ..
        })
    ));
}

#[test]
fn send_path_rejects_invalid_config_before_touching_network() {
    let cx = Cx::for_testing();
    let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let cfg = QuicConfig {
        accept_timeout: Duration::ZERO,
        ..trusted_quic_config()
    };
    let result = block_on(send_path(&cx, addr, Path::new("/x"), cfg, "sender"));
    assert!(matches!(result, Err(QuicTransportError::Config(_))));
}

#[test]
fn receive_connection_rejects_missing_control_stream_without_fake_success() {
    let cx = Cx::for_testing();
    let conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
    let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let result: Result<ReceiveReport, QuicTransportError> = block_on(receive_connection(
        &cx,
        conn,
        peer,
        Path::new("/tmp"),
        trusted_quic_config(),
        "receiver",
    ));
    match result {
        Ok(report) => panic!("missing control stream must not fake success: {report:?}"),
        Err(QuicTransportError::NotImplemented {
            operation: "receive_connection",
            ..
        }) => panic!("receive_connection should stay wired past the B1 scaffold"),
        Err(_) => {}
    }
}

#[test]
fn receive_once_rejects_empty_endpoint_without_fake_success() {
    let cx = Cx::for_testing();
    let mut endpoint = block_on(ManagedQuicEndpoint::bind(
        &cx,
        "127.0.0.1:0".parse().unwrap(),
        ManagedEndpointConfig {
            is_server: true,
            ..ManagedEndpointConfig::default()
        },
    ))
    .expect("managed endpoint should bind");

    let result: Result<ReceiveReport, QuicTransportError> = block_on(receive_once(
        &cx,
        &mut endpoint,
        Path::new("/tmp"),
        trusted_quic_config(),
        "receiver",
    ));
    match result {
        Ok(report) => panic!("empty endpoint must not fake success: {report:?}"),
        Err(QuicTransportError::Timeout {
            operation: "receive_once accept",
            ..
        }) => {}
        Err(QuicTransportError::NotImplemented {
            operation: "receive_once",
            ..
        }) => panic!("receive_once should stay wired past the B1 scaffold"),
        Err(err) => panic!("empty endpoint should fail closed as accept timeout, got {err:?}"),
    }
}
