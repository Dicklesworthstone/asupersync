//! End-to-end gate for the real ATP-over-TCP transport (`asupersync-qk02uw`).
//!
//! Two independent runtimes (mirroring two processes) move a real file and a
//! real directory tree across a loopback TCP socket, and the bytes must arrive
//! byte-identical with matching SHA-256 + merkle root. A sender pointed at a
//! dead port must fail closed. This is the regression wall that prevents the
//! transport from ever silently reverting to the old facade.
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use asupersync::cx::Cx;
use asupersync::net::TcpListener;
use asupersync::net::atp::transport_tcp::{
    ReceiveReport, SendReport, TransferConfig, TransportError, receive_once, send_path,
};
use asupersync::runtime::RuntimeBuilder;

fn unique_tmp(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!(
        "atp_tcp_e2e_{label}_{}_{nanos}",
        std::process::id()
    ))
}

/// Spawn a receiver on its own runtime/thread; returns the bound address and a
/// join handle yielding the receive result.
fn spawn_receiver(
    dest_dir: PathBuf,
) -> (
    SocketAddr,
    thread::JoinHandle<Result<ReceiveReport, TransportError>>,
) {
    let (addr_tx, addr_rx) = mpsc::channel::<SocketAddr>();
    let handle = thread::spawn(move || {
        let runtime = RuntimeBuilder::multi_thread()
            .build()
            .expect("receiver runtime");
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("receiver cx");
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            addr_tx.send(addr).expect("send addr");
            receive_once(
                &cx,
                &listener,
                &dest_dir,
                TransferConfig::default(),
                "receiver",
            )
            .await
        }))
    });
    let addr = addr_rx.recv().expect("receiver bound address");
    (addr, handle)
}

fn run_sender(addr: SocketAddr, source: PathBuf) -> Result<SendReport, TransportError> {
    let runtime = RuntimeBuilder::multi_thread()
        .build()
        .expect("sender runtime");
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("sender cx");
        send_path(&cx, addr, &source, TransferConfig::default(), "sender").await
    }))
}

#[test]
fn single_file_roundtrip_is_byte_identical() {
    let root = unique_tmp("single");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let payload: Vec<u8> = (0..500_003u32).map(|i| (i % 251) as u8).collect();
    let src_file = src_dir.join("payload.bin");
    std::fs::write(&src_file, &payload).unwrap();

    let (addr, recv_handle) = spawn_receiver(dst_dir.clone());
    let send = run_sender(addr, src_file).expect("send succeeds");
    let recv = recv_handle
        .join()
        .expect("receiver thread")
        .expect("receive succeeds");

    assert!(send.receipt.committed, "sender receipt must be committed");
    assert!(send.receipt.sha_ok && send.receipt.merkle_ok);
    assert_eq!(send.bytes_sent, payload.len() as u64);
    assert!(recv.committed);
    assert_eq!(recv.bytes_received, payload.len() as u64);

    let got = std::fs::read(dst_dir.join("payload.bin")).expect("received file");
    assert_eq!(got, payload, "received bytes must be identical");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn directory_tree_roundtrip_preserves_structure_and_bytes() {
    let root = unique_tmp("dir");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    let tree = src_dir.join("project");
    std::fs::create_dir_all(tree.join("sub/deep")).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let files: &[(&str, &[u8])] = &[
        ("readme.txt", b"top-level file\n"),
        ("sub/a.bin", &[0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
        ("sub/deep/b.dat", b"deep content with some length to it"),
    ];
    for (rel, bytes) in files {
        std::fs::write(tree.join(rel), bytes).unwrap();
    }

    let (addr, recv_handle) = spawn_receiver(dst_dir.clone());
    let send = run_sender(addr, tree.clone()).expect("send succeeds");
    let recv = recv_handle
        .join()
        .expect("receiver thread")
        .expect("receive succeeds");

    assert!(send.receipt.committed);
    assert_eq!(send.files, files.len() as u32);
    assert!(recv.committed);

    for (rel, bytes) in files {
        let got = std::fs::read(dst_dir.join("project").join(rel))
            .unwrap_or_else(|e| panic!("missing received {rel}: {e}"));
        assert_eq!(&got, bytes, "content mismatch for {rel}");
    }

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn sender_to_dead_port_fails_closed() {
    let root = unique_tmp("dead");
    std::fs::create_dir_all(&root).unwrap();
    let src_file = root.join("x.bin");
    std::fs::write(&src_file, b"unreachable").unwrap();

    // 127.0.0.1:1 is reserved and not listening.
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let result = run_sender(dead, src_file);
    assert!(
        result.is_err(),
        "sending to a dead port must fail, not report fake success"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn merkle_root_is_reported_and_stable() {
    // Identical content under identical layout must produce the same transfer id
    // + merkle root across runs (deterministic integrity anchor).
    fn send_once(label: &str) -> SendReport {
        let root = unique_tmp(label);
        let src_dir = root.join("src");
        let dst_dir = root.join("dst");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::create_dir_all(&dst_dir).unwrap();
        let src_file = src_dir.join("same.bin");
        std::fs::write(&src_file, b"deterministic-content").unwrap();
        let (addr, recv_handle) = spawn_receiver(dst_dir);
        let send = run_sender(addr, src_file).expect("send");
        let _ = recv_handle.join().expect("recv thread").expect("recv");
        let _ = std::fs::remove_dir_all(&root);
        send
    }
    let a = send_once("stable_a");
    let b = send_once("stable_b");
    assert_eq!(a.merkle_root_hex, b.merkle_root_hex);
    assert_eq!(a.transfer_id, b.transfer_id);
    assert_eq!(a.merkle_root_hex.len(), 64);
}

// Keep the Path import meaningful for readers grepping the test surface.
const _: fn(&Path) = |_p| {};
