//! End-to-end gate for the RaptorQ ATP transport (`asupersync-mixdaw`).
//!
//! Two independent runtimes (mirroring two processes) move a real file and a
//! real directory tree as RaptorQ symbols over loopback UDP, with the reliable
//! control plane over loopback TCP. The bytes must arrive byte-identical with
//! matching SHA-256 + merkle root. A loss-injection run drops a fraction of
//! sprayed source symbols and must still decode from repair symbols via the
//! fountain feedback loop. A sender pointed at a dead control port must fail
//! closed. This is the regression wall for the fast/robust transport.
#![allow(missing_docs)]

use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use asupersync::cx::Cx;
use asupersync::net::TcpListener;
use asupersync::net::atp::transport_rq::{
    ReceiveReport, RqConfig, RqError, SendReport, receive_once, send_path,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::security::SecurityContext;

const PROFILE_TRANSFER_BYTES: usize = 1024 * 1024 * 1024;
const PROFILE_PEAK_RSS_GROWTH_CEILING: u64 = 64 * 1024 * 1024;

fn unique_tmp(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("atp_rq_e2e_{label}_{}_{nanos}", std::process::id()))
}

/// Test transport config with a SMALL source-block size. These tests run in a
/// debug (unoptimized) build, where RaptorQ encode/decode of a large source
/// block (a K×K GF(256) matrix solve) is extremely slow. A 64 KiB block caps K
/// at 64 source symbols per block, keeping the coder fast while still exercising
/// the real multi-block / SBN-routing / per-block-decode / cross-block-assembly
/// paths. Production (release + SIMD) uses the default 8 MiB block.
fn test_config() -> RqConfig {
    RqConfig {
        max_block_size: 64 * 1024,
        ..RqConfig::default()
    }
    .allow_unauthenticated_for_trusted_transport()
}

fn source_stream_fragment_config() -> RqConfig {
    RqConfig {
        max_block_size: 4 * 1024,
        max_transfer_bytes: 8 * 1024 * 1024,
        ..RqConfig::default()
    }
    .allow_unauthenticated_for_trusted_transport()
}

fn auth_test_config() -> RqConfig {
    RqConfig {
        max_block_size: 64 * 1024,
        repair_overhead: 1.0,
        round_tail_drain: std::time::Duration::from_millis(5),
        ..RqConfig::default()
    }
    .with_symbol_auth(SecurityContext::for_testing(138))
}

fn profile_config() -> RqConfig {
    RqConfig {
        symbol_size: 60 * 1024,
        max_block_size: 8 * 1024 * 1024,
        repair_overhead: 1.0,
        udp_fanout: 1,
        max_transfer_bytes: PROFILE_TRANSFER_BYTES as u64,
        round_tail_drain: std::time::Duration::from_millis(100),
        source_retransmit_rounds: 16,
        max_source_retransmit_requests: 0,
        ..RqConfig::default()
    }
    .allow_unauthenticated_for_trusted_transport()
}

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

fn write_payload_streaming(path: &Path, len: usize) {
    let mut file = std::fs::File::create(path).expect("create profile source payload");
    let mut buf = vec![0u8; 1024 * 1024];
    let mut written = 0usize;
    while written < len {
        let take = buf.len().min(len - written);
        for (j, byte) in buf.iter_mut().enumerate().take(take) {
            *byte = ((written + j) % 251) as u8;
        }
        file.write_all(&buf[..take])
            .expect("write profile source chunk");
        written += take;
    }
    file.flush().expect("flush profile source payload");
}

fn files_are_identical(a: &Path, b: &Path) -> bool {
    let (Ok(ma), Ok(mb)) = (std::fs::metadata(a), std::fs::metadata(b)) else {
        return false;
    };
    if ma.len() != mb.len() {
        return false;
    }
    let mut fa = std::io::BufReader::new(std::fs::File::open(a).expect("open source"));
    let mut fb = std::io::BufReader::new(std::fs::File::open(b).expect("open destination"));
    let mut ba = vec![0u8; 256 * 1024];
    let mut bb = vec![0u8; 256 * 1024];
    loop {
        let na = fa.read(&mut ba).expect("read source");
        let nb = fb.read(&mut bb).expect("read destination");
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

#[test]
fn single_file_roundtrip_is_byte_identical() {
    let root = unique_tmp("single");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    // ~200 KiB: spans ~4 source blocks (64 KiB each) so it exercises multi-block
    // SBN routing + tail padding while keeping per-block K small for debug speed.
    let payload: Vec<u8> = (0..200_003u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let src_file = src_dir.join("payload.bin");
    std::fs::write(&src_file, &payload).unwrap();

    let (addr, recv_handle) = spawn_receiver(dst_dir.clone(), test_config());
    let send = run_sender(addr, src_file, test_config()).expect("send succeeds");
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
}

#[test]
fn authenticated_perfect_roundtrip_does_not_wait_for_close_timeout() {
    let root = unique_tmp("auth_perfect");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let payload: Vec<u8> = (0..65_507u32)
        .map(|i| (i.wrapping_mul(1_103_515_245).rotate_left(7) >> 11) as u8)
        .collect();
    let src_file = src_dir.join("auth-payload.bin");
    std::fs::write(&src_file, &payload).unwrap();

    let started = std::time::Instant::now();
    let (addr, recv_handle) = spawn_receiver(dst_dir.clone(), auth_test_config());
    let send = run_sender(addr, src_file, auth_test_config()).expect("authenticated send succeeds");
    let recv = recv_handle
        .join()
        .expect("receiver thread")
        .expect("authenticated receive succeeds");
    let elapsed = started.elapsed();

    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "auth perfect completion should not wait for a 60s close/accept timeout; elapsed={elapsed:?}"
    );
    assert!(send.receipt.committed);
    assert!(send.receipt.sha_ok && send.receipt.merkle_ok);
    assert_eq!(send.feedback_rounds, 0);
    assert!(recv.committed);
    assert_eq!(recv.feedback_rounds, 0);
    let got = std::fs::read(dst_dir.join("auth-payload.bin")).expect("received auth file");
    assert_eq!(got, payload, "authenticated received bytes must match");
}

#[test]
fn directory_tree_roundtrip_preserves_structure_and_bytes() {
    let root = unique_tmp("dir");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    let tree = src_dir.join("project");
    std::fs::create_dir_all(tree.join("sub/deep")).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let big: Vec<u8> = (0..150_000u32).map(|i| (i % 253) as u8).collect();
    std::fs::write(tree.join("readme.txt"), b"top-level file\n").unwrap();
    std::fs::write(tree.join("sub/a.bin"), [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    std::fs::write(tree.join("sub/deep/b.dat"), &big).unwrap();

    let (addr, recv_handle) = spawn_receiver(dst_dir.clone(), test_config());
    let send = run_sender(addr, tree.clone(), test_config()).expect("send succeeds");
    let recv = recv_handle
        .join()
        .expect("receiver thread")
        .expect("receive succeeds");

    assert!(send.receipt.committed);
    assert_eq!(send.files, 3);
    assert!(recv.committed);

    let base = dst_dir.join("project");
    assert_eq!(
        std::fs::read(base.join("readme.txt")).unwrap(),
        b"top-level file\n"
    );
    assert_eq!(
        std::fs::read(base.join("sub/a.bin")).unwrap(),
        vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    );
    assert_eq!(std::fs::read(base.join("sub/deep/b.dat")).unwrap(), big);
}

#[test]
fn source_stream_trailer_roundtrip_multifile_and_fragmented() {
    let root = unique_tmp("trailer_frag");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    let tree = src_dir.join("payload");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let a: Vec<u8> = (0..1_048_709u32)
        .map(|i| (i.wrapping_mul(16_777_619).rotate_left(5) >> 9) as u8)
        .collect();
    let b: Vec<u8> = (0..1_048_919u32)
        .map(|i| (i.wrapping_mul(1_103_515_245).rotate_left(11) >> 7) as u8)
        .collect();
    std::fs::write(tree.join("a.bin"), &a).unwrap();
    std::fs::write(tree.join("nested-b.bin"), &b).unwrap();

    let config = source_stream_fragment_config();
    let (addr, recv_handle) = spawn_receiver(dst_dir.clone(), config.clone());
    let send = run_sender(addr, tree.clone(), config).expect("source-stream send succeeds");
    let recv = recv_handle
        .join()
        .expect("receiver thread")
        .expect("source-stream receive succeeds");

    assert!(send.receipt.committed);
    assert!(send.receipt.sha_ok && send.receipt.merkle_ok);
    assert_eq!(send.files, 2);
    assert_eq!(send.bytes_sent, (a.len() + b.len()) as u64);
    assert_eq!(
        send.symbols_sent, 0,
        "clean source stream must not spray UDP"
    );
    assert_eq!(send.feedback_rounds, 0);
    assert!(recv.committed);
    assert_eq!(recv.files, 2);
    assert_eq!(recv.bytes_received, (a.len() + b.len()) as u64);
    assert_eq!(
        recv.symbols_accepted, 0,
        "source-stream transfer must not consume UDP symbols"
    );

    let base = dst_dir.join("payload");
    assert_eq!(std::fs::read(base.join("a.bin")).unwrap(), a);
    assert_eq!(std::fs::read(base.join("nested-b.bin")).unwrap(), b);
}

#[test]
fn loss_injection_recovers_via_repair_symbols() {
    let root = unique_tmp("loss");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let payload: Vec<u8> = (0..160_019u32)
        .map(|i| (i.wrapping_mul(40503) >> 7) as u8)
        .collect();
    let src_file = src_dir.join("lossy.bin");
    std::fs::write(&src_file, &payload).unwrap();

    // Drop 1 in every 7 sprayed symbols on the sender; the fountain feedback
    // loop must still converge from repair symbols.
    let lossy = RqConfig {
        debug_drop_one_in: 7,
        ..test_config()
    };

    let (addr, recv_handle) = spawn_receiver(dst_dir.clone(), test_config());
    let send = run_sender(addr, src_file, lossy).expect("send succeeds under loss");
    let recv = recv_handle
        .join()
        .expect("receiver thread")
        .expect("receive succeeds under loss");

    assert!(
        send.receipt.committed,
        "must commit despite 1/7 symbol loss"
    );
    assert!(
        recv.committed,
        "receiver report must commit despite 1/7 symbol loss"
    );
    assert!(
        send.symbols_sent > 0,
        "loss injection must stay on the UDP/RaptorQ path"
    );
    assert!(
        recv.symbols_accepted > 0,
        "loss injection must consume datagram symbols"
    );
    let got = std::fs::read(dst_dir.join("lossy.bin")).expect("received file");
    assert_eq!(got, payload, "lossy transfer must still be byte-identical");
}

#[test]
fn dead_control_port_fails_closed() {
    let root = unique_tmp("dead");
    let src_dir = root.join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    let src_file = src_dir.join("x.bin");
    std::fs::write(&src_file, b"never delivered").unwrap();

    // 127.0.0.1:1 — nothing listens; the control connect must fail.
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let result = run_sender(dead, src_file, test_config());
    assert!(
        result.is_err(),
        "sender must fail closed on a dead control port"
    );
}

#[test]
fn deterministic_merkle_root_across_runs() {
    let root = unique_tmp("merkle");
    let src_dir = root.join("src");
    let dst1 = root.join("dst1");
    let dst2 = root.join("dst2");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst1).unwrap();
    std::fs::create_dir_all(&dst2).unwrap();

    let payload: Vec<u8> = (0..120_000u32).map(|i| (i % 97) as u8).collect();
    let src_file = src_dir.join("d.bin");
    std::fs::write(&src_file, &payload).unwrap();

    let (a1, h1) = spawn_receiver(dst1, test_config());
    let s1 = run_sender(a1, src_file.clone(), test_config()).unwrap();
    h1.join().unwrap().unwrap();

    let (a2, h2) = spawn_receiver(dst2, test_config());
    let s2 = run_sender(a2, src_file, test_config()).unwrap();
    h2.join().unwrap().unwrap();

    assert_eq!(
        s1.merkle_root_hex, s2.merkle_root_hex,
        "identical content must yield identical merkle root"
    );
    assert_eq!(s1.transfer_id.len(), 32);
    assert_eq!(s2.transfer_id.len(), 32);
    assert!(s1.transfer_id.chars().all(|ch| ch.is_ascii_hexdigit()));
    assert!(s2.transfer_id.chars().all(|ch| ch.is_ascii_hexdigit()));
    assert_ne!(
        s1.transfer_id, s2.transfer_id,
        "source-stream transfer ids include a per-transfer nonce"
    );
}

#[test]
#[ignore = "1 GiB F2.2 RSS profile; run explicitly, not in default e2e suite"]
fn one_gib_roundtrip_is_byte_identical_and_bounded_memory() {
    let root = unique_tmp("profile");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let src_file = src_dir.join("one_gib.bin");
    write_payload_streaming(&src_file, PROFILE_TRANSFER_BYTES);
    println!("atp_rq_profile stage=source_written bytes={PROFILE_TRANSFER_BYTES}");

    let config = profile_config();
    let (addr, recv_handle) = spawn_receiver(dst_dir.clone(), config.clone());
    let baseline_rss = peak_rss_bytes();
    let send = run_sender(addr, src_file.clone(), config).expect("1 GiB send succeeds");
    let recv = recv_handle
        .join()
        .expect("receiver thread")
        .expect("1 GiB receive succeeds");
    println!(
        "atp_rq_profile stage=transfer_done symbols_sent={} symbols_accepted={} feedback_rounds={}",
        send.symbols_sent, recv.symbols_accepted, recv.feedback_rounds
    );
    let after_rss = peak_rss_bytes();

    assert!(send.receipt.committed, "sender receipt must be committed");
    assert!(send.receipt.sha_ok && send.receipt.merkle_ok);
    assert_eq!(send.bytes_sent, PROFILE_TRANSFER_BYTES as u64);
    assert!(recv.committed);
    assert_eq!(recv.bytes_received, PROFILE_TRANSFER_BYTES as u64);

    let committed = dst_dir.join("one_gib.bin");
    assert!(
        files_are_identical(&src_file, &committed),
        "1 GiB RQ payload must be byte-identical"
    );
    println!("atp_rq_profile stage=compare_done");

    if let (Some(before), Some(after)) = (baseline_rss, after_rss) {
        let growth = after.saturating_sub(before);
        println!(
            "atp_rq_profile rss: before_bytes={before} after_bytes={after} \
             growth_bytes={growth} ceiling_bytes={PROFILE_PEAK_RSS_GROWTH_CEILING} \
             transfer_bytes={PROFILE_TRANSFER_BYTES}"
        );
        assert!(
            growth < PROFILE_PEAK_RSS_GROWTH_CEILING,
            "peak RSS grew by {growth} bytes during a {PROFILE_TRANSFER_BYTES}-byte RQ transfer \
             (before {before}, after {after}, ceiling {PROFILE_PEAK_RSS_GROWTH_CEILING}); \
             transport_rq must stream source blocks and staged output instead of buffering entries"
        );
    }

    // Keep artifacts for forensics; do not delete agent-owned test output.
    let _ = root;
}
