//! Large-K end-to-end gate for the RaptorQ ATP transport
//! (`asupersync-ro853b` / `asupersync-mixdaw`).
//!
//! The existing `atp_rq_loopback_e2e` tests cap source blocks at 64 KiB (K <= 64)
//! because a large K x K GF(256) matrix solve is extremely slow in a debug
//! (unoptimized) build. This suite pushes to the **largest debug-tractable
//! regime — K = 512** (512 default-sized RQ symbols per source block) — which
//! is exactly the source-symbol count `asupersync-ro853b` traced its
//! cross-machine non-convergence at. It exercises the FULL transport path
//! (sender multi-socket fan-out -> real loopback UDP symbols -> single-socket
//! receiver -> per-block K=512 decode -> verify -> atomic commit), not just the
//! in-process decoder feed, both clean and under heavy symbol loss.
//!
//! These are the regression baseline a future two-task / continuous-drain
//! receiver rewrite (ro853b) must preserve.
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

use asupersync::cx::Cx;
use asupersync::net::TcpListener;
use asupersync::net::atp::transport_rq::{
    ReceiveReport, RqConfig, RqError, SendReport, receive_once, send_path,
};
use asupersync::runtime::RuntimeBuilder;

fn unique_tmp(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!(
        "atp_rq_largek_{label}_{}_{nanos}",
        std::process::id()
    ))
}

const K512_SOURCE_SYMBOLS: usize = 512;

fn k512_max_block_size() -> usize {
    usize::from(RqConfig::default().symbol_size) * K512_SOURCE_SYMBOLS
}

fn k512_single_block_payload_len() -> usize {
    k512_max_block_size() - 1
}

/// Config with a max block sized for exactly 512 default-sized source symbols.
/// The byte size follows `RqConfig::default().symbol_size`, so this remains a
/// K=512 gate when the production symbol payload changes.
fn k512_config() -> RqConfig {
    RqConfig {
        max_block_size: k512_max_block_size(),
        ..RqConfig::default()
    }
    .allow_unauthenticated_for_trusted_transport()
}

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

/// Deterministic pseudo-random payload of `len` bytes (no large RAM spike beyond
/// the buffer itself; these payloads are <= ~1 MiB).
fn payload(len: usize) -> Vec<u8> {
    (0..len as u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect()
}

#[test]
fn k512_single_block_roundtrip_is_byte_identical() {
    let root = unique_tmp("clean");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    // Fill one source block just short of its byte ceiling. This keeps K=512
    // while following the current default RQ symbol size.
    let data = payload(k512_single_block_payload_len());
    let src_file = src_dir.join("k512.bin");
    std::fs::write(&src_file, &data).unwrap();

    let (addr, recv_handle) = spawn_receiver(dst_dir.clone(), k512_config());
    let send = run_sender(addr, src_file, k512_config()).expect("send succeeds");
    let recv = recv_handle
        .join()
        .expect("receiver thread")
        .expect("receive succeeds");

    assert!(send.receipt.committed, "K=512 transfer must commit");
    assert!(send.receipt.sha_ok && send.receipt.merkle_ok);
    assert_eq!(send.bytes_sent, data.len() as u64);
    assert!(recv.committed);
    assert_eq!(recv.bytes_received, data.len() as u64);

    let got = std::fs::read(dst_dir.join("k512.bin")).expect("received file");
    assert_eq!(got, data, "K=512 received bytes must be identical");
}

#[test]
fn k512_single_block_recovers_under_heavy_loss() {
    let root = unique_tmp("loss");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let data = payload(k512_single_block_payload_len());
    let src_file = src_dir.join("k512_lossy.bin");
    std::fs::write(&src_file, &data).unwrap();

    // Drop 1 in every 5 sprayed symbols — heavier than the existing 1-in-7 test.
    // At K=512 this forces multiple fountain feedback rounds that re-spray repair
    // symbols until the K=512 block decodes; the receiver must converge.
    let lossy = RqConfig {
        debug_drop_one_in: 5,
        ..k512_config()
    };

    let (addr, recv_handle) = spawn_receiver(dst_dir.clone(), k512_config());
    let send = run_sender(addr, src_file, lossy).expect("send succeeds under loss");
    let recv = recv_handle
        .join()
        .expect("receiver thread")
        .expect("receive succeeds under loss");

    assert!(
        send.receipt.committed,
        "K=512 must commit despite 1/5 symbol loss"
    );
    assert!(
        recv.committed,
        "receiver must commit despite 1/5 symbol loss"
    );
    assert!(
        recv.feedback_rounds >= 1,
        "heavy loss at K=512 should require at least one repair feedback round, got {}",
        recv.feedback_rounds
    );
    let got = std::fs::read(dst_dir.join("k512_lossy.bin")).expect("received file");
    assert_eq!(
        got, data,
        "lossy K=512 transfer must still be byte-identical"
    );
}

#[test]
fn large_k_multiblock_roundtrip_is_byte_identical() {
    let root = unique_tmp("multi");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    // Three source blocks: two full K=512 blocks plus a smaller tail block.
    // Exercises multi-block SBN routing + cross-block assembly at large K, the
    // c8m8ha multi-block path under the ro853b regime.
    let data = payload(
        k512_max_block_size() * 2 + usize::from(RqConfig::default().symbol_size) / 2,
    );
    let src_file = src_dir.join("multik.bin");
    std::fs::write(&src_file, &data).unwrap();

    let (addr, recv_handle) = spawn_receiver(dst_dir.clone(), k512_config());
    let send = run_sender(addr, src_file, k512_config()).expect("send succeeds");
    let recv = recv_handle
        .join()
        .expect("receiver thread")
        .expect("receive succeeds");

    assert!(
        send.receipt.committed,
        "multi-block large-K transfer must commit"
    );
    assert!(send.receipt.sha_ok && send.receipt.merkle_ok);
    assert!(recv.committed);
    let got = std::fs::read(dst_dir.join("multik.bin")).expect("received file");
    assert_eq!(got, data, "multi-block large-K bytes must be identical");
}
