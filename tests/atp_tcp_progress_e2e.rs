//! Loopback e2e for transfer progress reporting (b0k8qo.11.5 / J5).
//!
//! A real ATP-over-TCP transfer must drive `send_path_filtered`'s progress
//! callback monotonically and reach 100% (`bytes_sent == total_bytes`) at
//! completion, so a CLI/daemon can render a real (non-simulated) progress bar
//! with a plausible ETA via `TransferProgress`.
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use asupersync::cx::Cx;
use asupersync::net::TcpListener;
use asupersync::net::atp::transport_common::{FilterSet, ProgressSnapshot, TransferProgress};
use asupersync::net::atp::transport_tcp::{
    ReceiveReport, SendReport, TransferConfig, TransportError, receive_once, send_path_filtered,
};
use asupersync::runtime::RuntimeBuilder;

fn unique_tmp(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!(
        "atp_tcp_prog_{label}_{}_{nanos}",
        std::process::id()
    ))
}

fn mkfile(base: &Path, rel: &str, contents: &[u8]) {
    let path = base.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

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
            .expect("recv runtime");
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("recv cx");
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            addr_tx.send(listener.local_addr()?).expect("send addr");
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
    (addr_rx.recv().expect("receiver bound"), handle)
}

/// Send `source`, collecting every `(bytes_sent, total_bytes)` progress tick.
fn run_sender_collect_progress(
    addr: SocketAddr,
    source: PathBuf,
) -> (Result<SendReport, TransportError>, Vec<(u64, u64)>) {
    let (tx, rx) = mpsc::channel::<(u64, u64)>();
    let runtime = RuntimeBuilder::multi_thread()
        .build()
        .expect("send runtime");
    let result = runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("send cx");
        send_path_filtered(
            &cx,
            addr,
            &source,
            TransferConfig::default(),
            "sender",
            &FilterSet::new(),
            move |done, total| {
                let _ = tx.send((done, total));
            },
        )
        .await
    }));
    let updates: Vec<(u64, u64)> = rx.try_iter().collect();
    (result, updates)
}

#[test]
fn progress_is_monotonic_and_reaches_total() {
    let root = unique_tmp("monotonic");
    let proj = root.join("src/proj");
    mkfile(&proj, "a.bin", &vec![1u8; 4000]);
    mkfile(&proj, "b.bin", &vec![2u8; 6000]);
    mkfile(&proj, "sub/c.bin", &vec![3u8; 2000]);
    let dst = root.join("dst");
    std::fs::create_dir_all(&dst).unwrap();
    let expected_total: u64 = 12_000;

    let (addr, recv) = spawn_receiver(dst);
    let (send_res, updates) = run_sender_collect_progress(addr, proj);
    let report = recv.join().expect("recv thread").expect("receive");
    let send = send_res.expect("send");

    assert!(send.receipt.committed && report.committed);
    assert!(!updates.is_empty(), "progress callback must fire");

    // Every tick carries the same total, never decreases, and the last is 100%.
    let total = updates[0].1;
    assert_eq!(total, expected_total);
    let mut prev = 0u64;
    for (done, t) in &updates {
        assert_eq!(*t, total, "total must be constant across ticks");
        assert!(
            *done >= prev,
            "progress must be monotonic ({done} < {prev})"
        );
        assert!(*done <= total, "progress cannot exceed total");
        prev = *done;
    }
    assert_eq!(
        updates.last().unwrap().0,
        total,
        "final tick must report completion at 100%"
    );

    // The reporter turns a tick into a plausible snapshot.
    let mut p = TransferProgress::new(total, 3);
    p.record_bytes(updates.last().unwrap().0);
    let snap: ProgressSnapshot = p.snapshot(std::time::Duration::from_secs(1));
    assert!((snap.fraction - 1.0).abs() < 1e-9);
}
