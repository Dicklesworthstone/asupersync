//! Runnable security proof for ATP-over-TCP head-of-line DoS hardening
//! (bead `asupersync-atp-transport-dos-hardening-abmj9q`, finding 1).
//!
//! A peer that completes the TCP handshake but never sends a protocol frame
//! must NOT block the receiver indefinitely: every blocking receive read is
//! wrapped in a per-connection idle timeout. This drives a real `receive_once`
//! on a loopback listener, connects a raw TCP client that stays silent, and
//! asserts the receiver fails closed with `TransportError::Timeout` (within the
//! configured idle window) instead of hanging forever.
//!
//! Run with: `cargo test --test atp_tcp_stalled_peer_timeout_proof --features test-internals`.

#![allow(missing_docs)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use asupersync::cx::Cx;
use asupersync::net::TcpListener;
use asupersync::net::atp::transport_tcp::{
    ReceiveReport, TransferConfig, TransportError, receive_once,
};
use asupersync::runtime::RuntimeBuilder;

fn unique_tmp(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("atp_dos_{label}_{}_{nanos}", std::process::id()))
}

#[test]
fn stalled_peer_is_timed_out_not_blocked_forever() {
    let dest_dir = unique_tmp("stalled_peer");
    std::fs::create_dir_all(&dest_dir).expect("create dest dir");

    let (addr_tx, addr_rx) = mpsc::channel::<SocketAddr>();
    let receiver: thread::JoinHandle<Result<ReceiveReport, TransportError>> =
        thread::spawn(move || {
            let runtime = RuntimeBuilder::multi_thread()
                .build()
                .expect("receiver runtime");
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().expect("receiver cx");
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let addr = listener.local_addr()?;
                addr_tx.send(addr).expect("publish addr");
                // Short idle window so a silent peer is reaped quickly; generous
                // accept window so the (fast) loopback connect always lands.
                let config = TransferConfig {
                    idle_timeout: Duration::from_millis(500),
                    accept_timeout: Duration::from_secs(5),
                    ..TransferConfig::default()
                };
                receive_once(&cx, &listener, &dest_dir, config, "dos-stall-peer").await
            }))
        });

    let addr = addr_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("receiver bound an address");

    // Raw client: connect, then stay silent and hold the connection open so the
    // receiver is genuinely waiting on a read (not seeing EOF).
    let _stalled = std::net::TcpStream::connect(addr).expect("connect to receiver");

    // The receiver must fail closed with a timeout rather than hang forever.
    let result = receiver.join().expect("receiver thread did not panic");
    match result {
        Err(TransportError::Timeout { .. }) => {}
        other => panic!("expected TransportError::Timeout for a stalled peer, got {other:?}"),
    }

    // Keep the stalled connection alive until the assertion has run.
    drop(_stalled);
}
