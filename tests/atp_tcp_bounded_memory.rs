//! Bounded-memory proof for the streaming ATP-over-TCP transport
//! (`asupersync-qk02uw` / `asupersync-mixdaw`).
//!
//! The original transport buffered every entry in memory on both the send and
//! receive sides, so a 1 GiB transfer cost ~2-3 GiB of resident memory (the
//! benchmark recorded sender 2053 MB / receiver 3079 MB vs rsync's flat
//! 15-59 MB). The streaming rewrite reads/writes files in fixed `chunk_size`
//! buffers and hashes incrementally, so peak resident memory is `O(chunk_size)`,
//! independent of transfer size.
//!
//! This test moves a file far larger than any internal buffer across a loopback
//! socket and asserts two things:
//!   1. The bytes arrive byte-identical (streaming correctness on a large file).
//!   2. The peak resident-set growth *during* the transfer stays far below the
//!      file size — proof that neither side buffers a whole object. The old
//!      code, with sender and receiver sharing this process, would grow peak RSS
//!      by ~2x the file size; the streaming code grows it by a few MiB.
#![allow(missing_docs)]

use std::io::Write as _;
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

/// File size for the bounded-memory transfer. Large enough to dwarf the default
/// 256 KiB chunk buffers by ~256x, small enough to stay fast on a test worker.
const TRANSFER_BYTES: usize = 64 * 1024 * 1024;

/// Peak RSS growth across the transfer must stay under this. The streaming path
/// uses only a handful of chunk buffers; the old buffering path (sender +
/// receiver both resident in this process) would grow peak RSS by ~2x the file
/// size (~128 MiB), so this 24 MiB ceiling cleanly separates streamed from
/// buffered without being flaky.
const PEAK_RSS_GROWTH_CEILING: u64 = 24 * 1024 * 1024;

fn unique_tmp(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!(
        "atp_tcp_mem_{label}_{}_{nanos}",
        std::process::id()
    ))
}

/// Read the process peak resident set size (`VmHWM`) in bytes on Linux. Returns
/// `None` on platforms without `/proc/self/status` so the memory assertion is
/// skipped while the correctness assertions still run.
fn peak_rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

/// Write `len` deterministic bytes to `path` in 1 MiB chunks, never holding more
/// than one chunk in memory (so this setup does not pre-inflate `VmHWM`).
fn write_payload_streaming(path: &Path, len: usize) {
    let mut file = std::fs::File::create(path).expect("create source payload");
    let mut buf = vec![0u8; 1024 * 1024];
    let mut written = 0usize;
    while written < len {
        let take = buf.len().min(len - written);
        for (j, byte) in buf.iter_mut().enumerate().take(take) {
            *byte = ((written + j) % 251) as u8;
        }
        file.write_all(&buf[..take]).expect("write source chunk");
        written += take;
    }
    file.flush().expect("flush source payload");
}

/// Stream-compare two files for byte equality without loading either fully.
fn files_are_identical(a: &Path, b: &Path) -> bool {
    let (Ok(ma), Ok(mb)) = (std::fs::metadata(a), std::fs::metadata(b)) else {
        return false;
    };
    if ma.len() != mb.len() {
        return false;
    }
    use std::io::Read as _;
    let mut fa = std::io::BufReader::new(std::fs::File::open(a).expect("open a"));
    let mut fb = std::io::BufReader::new(std::fs::File::open(b).expect("open b"));
    let mut ba = vec![0u8; 256 * 1024];
    let mut bb = vec![0u8; 256 * 1024];
    loop {
        let na = fa.read(&mut ba).expect("read a");
        let nb = fb.read(&mut bb).expect("read b");
        if na != nb {
            return false;
        }
        if na == 0 {
            return true;
        }
        if ba[..na] != bb[..nb] {
            return false;
        }
    }
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
fn large_file_transfer_is_byte_identical_and_bounded_memory() {
    let root = unique_tmp("large");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let src_file = src_dir.join("big.bin");
    write_payload_streaming(&src_file, TRANSFER_BYTES);

    // Baseline peak RSS after the source file exists but before the transfer.
    // Because the payload was written in 1 MiB chunks, VmHWM is not pre-inflated
    // to the file size here.
    let baseline_rss = peak_rss_bytes();

    let (addr, recv_handle) = spawn_receiver(dst_dir.clone());
    let send = run_sender(addr, src_file.clone()).expect("send succeeds");
    let recv = recv_handle
        .join()
        .expect("receiver thread")
        .expect("receive succeeds");

    let after_rss = peak_rss_bytes();

    // Correctness: streamed transfer of a large file must verify and commit.
    assert!(send.receipt.committed, "sender receipt must be committed");
    assert!(
        send.receipt.sha_ok && send.receipt.merkle_ok,
        "integrity must hold for a large streamed transfer"
    );
    assert_eq!(send.bytes_sent, TRANSFER_BYTES as u64);
    assert!(recv.committed);
    assert_eq!(recv.bytes_received, TRANSFER_BYTES as u64);

    let dst_file = dst_dir.join("big.bin");
    assert!(
        files_are_identical(&src_file, &dst_file),
        "received {} must be byte-identical to source",
        dst_file.display()
    );

    // Staging directory must be cleaned up after a committed transfer.
    let leftover_staging: Vec<_> = std::fs::read_dir(&dst_dir)
        .expect("read dst dir")
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with(".atp-staging-"))
        .collect();
    assert!(
        leftover_staging.is_empty(),
        "staging directories must be removed after commit, found {leftover_staging:?}"
    );

    // Bounded memory: peak RSS growth during the transfer must stay far below the
    // file size. The sender (hash pass + send pass) and receiver both run in this
    // process; the old buffering code would grow peak RSS by ~2x TRANSFER_BYTES.
    if let (Some(before), Some(after)) = (baseline_rss, after_rss) {
        let growth = after.saturating_sub(before);
        assert!(
            growth < PEAK_RSS_GROWTH_CEILING,
            "peak RSS grew by {growth} bytes during a {TRANSFER_BYTES}-byte transfer \
             (ceiling {PEAK_RSS_GROWTH_CEILING}); streaming transport must not buffer whole objects"
        );
    }

    // Keep artifacts for forensics; do not delete agent-owned test output.
    let _ = root;
}
