//! End-to-end conformance contract for the ATP-over-RaptorQ per-symbol
//! authentication posture (`asupersync-e880xo`).
//!
//! # What this pins (the truth)
//!
//! The README historically claimed the RaptorQ pipelines "prevent Byzantine
//! symbol injection via per-symbol authentication". The reality check
//! (`asupersync-e880xo`) found that the *capability* existed but the deployed
//! ATP transport ran unauthenticated by default. The production
//! `src/net/atp/transport_rq` transport has since been hardened to be
//! **fail-closed**: a [`RqConfig`] carries no implicit posture, so the
//! transport entry points (`send_path` / `receive_once`) refuse to run unless
//! the caller makes a *deliberate* choice — either
//! [`RqConfig::with_symbol_auth`] (sign + verify every UDP symbol with a shared
//! [`SecurityContext`]) or the explicit
//! [`RqConfig::allow_unauthenticated_for_trusted_transport`] escape hatch.
//!
//! The in-module unit tests cover datagram-level signing, and
//! `tests/decoding_secure_default.rs` pins the *config-object* posture
//! classification. Neither exercises the real transport end-to-end. This crate
//! closes that gap over real loopback sockets:
//!
//! 1. A default-config sender fails closed at the entry point **before any
//!    network I/O** (`RqError::Authentication`, not `RqError::Io`).
//! 2. With both peers sharing a [`SecurityContext`], an authenticated transfer
//!    round-trips byte-identically — the authenticated symbol plane actually
//!    delivers.
//! 3. An authentication-posture **mismatch is rejected at the handshake** in
//!    both directions, so an authenticated peer can never be silently downgraded
//!    to talk to an unauthenticated one.
//!
//! # No-claim boundary (intentionally NOT proven here)
//!
//! Authenticated mode protects the UDP **symbol plane** only. The TCP control
//! channel and the transfer manifest are still carried over an unauthenticated
//! socket, so full anti-forgery against an active MITM additionally requires an
//! authenticated control channel/manifest (e.g. TLS). The sibling
//! `transport_tcp` transport has no per-symbol authentication at all and remains
//! integrity-vs-manifest only. This suite therefore proves the symbol-plane
//! authentication posture is real and fail-closed; it does NOT claim full
//! Byzantine-injection prevention for the transport as a whole.
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

use asupersync::cx::Cx;
use asupersync::net::TcpListener;
use asupersync::net::atp::transport_rq::{
    ReceiveReport, RqConfig, RqError, RqSymbolAuthMode, SendReport, receive_once, send_path,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::security::SecurityContext;

/// Shared deterministic key seed. The same seed on both peers yields the same
/// `AuthKey` (`SecurityContext::for_testing` -> `AuthKey::from_seed`), so the
/// sender's per-symbol tags verify on the receiver.
const AUTH_SEED: u64 = 880_088;

fn unique_tmp(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!(
        "atp_rq_auth_{label}_{}_{nanos}",
        std::process::id()
    ))
}

/// Authenticated transport config with a SMALL source-block size so the debug
/// (unoptimized) RaptorQ coder stays fast while still exercising real
/// multi-block routing and per-symbol sign/verify (see the matching note in
/// `tests/atp_rq_loopback_e2e.rs`).
fn authenticated_config() -> RqConfig {
    RqConfig {
        max_block_size: 64 * 1024,
        ..RqConfig::default()
    }
    .with_symbol_auth(SecurityContext::for_testing(AUTH_SEED))
}

/// Explicit trusted-unauthenticated transport config (integrity-vs-manifest
/// only), the documented opt-out used by trusted loopback/lab links.
fn trusted_unauthenticated_config() -> RqConfig {
    RqConfig {
        max_block_size: 64 * 1024,
        ..RqConfig::default()
    }
    .allow_unauthenticated_for_trusted_transport()
}

/// Spawn a receiver on its own runtime/thread; returns the bound control address
/// and a join handle yielding the receive result.
fn spawn_receiver(
    dest_dir: PathBuf,
    config: RqConfig,
) -> (
    SocketAddr,
    thread::JoinHandle<Result<ReceiveReport, RqError>>,
) {
    let (addr_tx, addr_rx) = mpsc::channel::<SocketAddr>();
    let handle = thread::spawn(move || {
        let runtime = RuntimeBuilder::multi_thread()
            .worker_threads(2)
            .enable_platform_reactor(true)
            .build()
            .expect("receiver runtime");
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("receiver cx");
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            addr_tx.send(addr).expect("send addr");
            receive_once(&cx, &listener, "127.0.0.1", &dest_dir, config, "receiver").await
        }))
    });
    let addr = addr_rx.recv().expect("receiver bound address");
    (addr, handle)
}

fn run_sender(addr: SocketAddr, source: PathBuf, config: RqConfig) -> Result<SendReport, RqError> {
    let runtime = RuntimeBuilder::multi_thread()
        .worker_threads(2)
        .enable_platform_reactor(true)
        .build()
        .expect("sender runtime");
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("sender cx");
        send_path(&cx, addr, &source, config, "sender").await
    }))
}

/// A default `RqConfig` carries no deliberate posture, so the production sender
/// must refuse to transmit BEFORE touching the network: the auth-posture check
/// runs at the very top of `send_path`, ahead of the TCP connect. We point it
/// at a dead control port and assert the error is `Authentication` (the
/// fail-closed posture rejection) and NOT `Io` (which is what a connect against
/// the dead port would yield if the posture gate were bypassed).
#[test]
fn default_config_sender_fails_closed_before_any_network_io() {
    // Sanity: the default config reports the fail-closed posture.
    assert_eq!(
        RqConfig::default().symbol_auth_mode(),
        RqSymbolAuthMode::MissingAuthenticationContext,
    );

    let root = unique_tmp("failclosed");
    std::fs::create_dir_all(&root).unwrap();
    let src_file = root.join("payload.bin");
    std::fs::write(&src_file, b"this transfer must never leave the host").unwrap();

    // 127.0.0.1:1 — nothing listens. If the posture gate were skipped, the TCP
    // connect would fail with `Io`; instead the posture gate fires first.
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let err = run_sender(dead, src_file, RqConfig::default())
        .expect_err("a default (missing-auth) sender must fail closed");

    match err {
        RqError::Authentication(message) => {
            assert!(
                message.contains("symbol_auth_context")
                    && message.contains("with_symbol_auth")
                    && message.contains("allow_unauthenticated_for_trusted_transport"),
                "the fail-closed error must name both deliberate-posture escape hatches, got: {message}"
            );
        }
        other => panic!(
            "expected a pre-network Authentication rejection, got a different error: {other:?}"
        ),
    }
}

/// With both peers configured with the SAME `SecurityContext`, the sender signs
/// every UDP symbol and the receiver verifies it before decoding. The transfer
/// must still round-trip byte-identically with matching SHA-256 + merkle root:
/// per-symbol authentication is real and does not corrupt delivery.
#[test]
fn authenticated_loopback_roundtrip_is_byte_identical() {
    assert_eq!(
        authenticated_config().symbol_auth_mode(),
        RqSymbolAuthMode::Authenticated,
    );

    let root = unique_tmp("authrt");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    // ~150 KiB spans multiple 64 KiB source blocks while staying fast in debug.
    let payload: Vec<u8> = (0..150_001u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 11) as u8)
        .collect();
    let src_file = src_dir.join("authed.bin");
    std::fs::write(&src_file, &payload).unwrap();

    let (addr, recv_handle) = spawn_receiver(dst_dir.clone(), authenticated_config());
    let send =
        run_sender(addr, src_file, authenticated_config()).expect("authenticated send succeeds");
    let recv = recv_handle
        .join()
        .expect("receiver thread")
        .expect("authenticated receive succeeds");

    assert!(send.receipt.committed, "sender receipt must be committed");
    assert!(
        send.receipt.sha_ok && send.receipt.merkle_ok,
        "authenticated transfer must pass integrity checks"
    );
    assert_eq!(send.bytes_sent, payload.len() as u64);
    assert!(recv.committed);
    assert_eq!(recv.bytes_received, payload.len() as u64);

    let got = std::fs::read(dst_dir.join("authed.bin")).expect("received file");
    assert_eq!(
        got, payload,
        "authenticated transfer must deliver byte-identical content"
    );
}

/// An authenticated sender paired with a trusted-unauthenticated receiver is a
/// posture mismatch. The handshake must reject it on BOTH sides — there is no
/// silent downgrade of an authenticated peer to an unauthenticated one.
#[test]
fn authenticated_sender_unauthenticated_receiver_rejected_at_handshake() {
    let root = unique_tmp("mismatch_a");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();
    let src_file = src_dir.join("x.bin");
    std::fs::write(&src_file, b"posture mismatch must not transfer").unwrap();

    let (addr, recv_handle) = spawn_receiver(dst_dir, trusted_unauthenticated_config());
    let send_err = run_sender(addr, src_file, authenticated_config())
        .expect_err("authenticated sender must be rejected by an unauthenticated receiver");
    assert!(
        send_err
            .to_string()
            .to_lowercase()
            .contains("authentication"),
        "sender rejection must cite the authentication mismatch, got: {send_err}"
    );

    let recv_result = recv_handle.join().expect("receiver thread");
    assert!(
        matches!(recv_result, Err(RqError::HandshakeRejected(ref m)) if m.contains("mismatch")),
        "receiver must reject the handshake with an auth-mismatch reason, got: {recv_result:?}"
    );
}

/// The symmetric case: a trusted-unauthenticated sender cannot connect to an
/// authenticated receiver. An unauthenticated (potentially forged-symbol) peer
/// is refused before any symbol is accepted.
#[test]
fn unauthenticated_sender_authenticated_receiver_rejected_at_handshake() {
    let root = unique_tmp("mismatch_b");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();
    let src_file = src_dir.join("y.bin");
    std::fs::write(&src_file, b"unauthenticated peer must be refused").unwrap();

    let (addr, recv_handle) = spawn_receiver(dst_dir, authenticated_config());
    let send_err = run_sender(addr, src_file, trusted_unauthenticated_config())
        .expect_err("unauthenticated sender must be rejected by an authenticated receiver");
    assert!(
        send_err
            .to_string()
            .to_lowercase()
            .contains("authentication"),
        "sender rejection must cite the authentication mismatch, got: {send_err}"
    );

    let recv_result = recv_handle.join().expect("receiver thread");
    assert!(
        matches!(recv_result, Err(RqError::HandshakeRejected(ref m)) if m.contains("mismatch")),
        "receiver must reject the handshake with an auth-mismatch reason, got: {recv_result:?}"
    );
}
