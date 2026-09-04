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
// See `atp_bond_isomorphism_e2e`: an integration test is its own crate and does
// not inherit the `recursion_limit` from `src/lib.rs`.
#![recursion_limit = "256"]

use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use asupersync::cx::Cx;
use asupersync::net::TcpListener;
use asupersync::net::atp::transport_rq::{
    ReceiveReport, RqConfig, RqError, RqReceiveOptions, SendReport, receive_once_with_options,
    send_path,
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

#[cfg(unix)]
fn write_sparse_fixture(path: &Path, logical_size: usize, marker: &[u8]) -> Vec<u8> {
    use std::io::Seek as _;

    let mut file = std::fs::File::create(path).expect("create sparse fixture");
    file.set_len(logical_size as u64)
        .expect("pre-size sparse fixture");
    file.write_all(marker).expect("write sparse prefix");
    let tail_offset = logical_size
        .checked_sub(marker.len())
        .expect("sparse fixture exceeds marker");
    file.seek(std::io::SeekFrom::Start(tail_offset as u64))
        .expect("seek sparse tail");
    file.write_all(marker).expect("write sparse suffix");
    file.sync_all().expect("sync sparse fixture");

    let mut expected = vec![0u8; logical_size];
    expected[..marker.len()].copy_from_slice(marker);
    expected[tail_offset..].copy_from_slice(marker);
    expected
}

#[cfg(unix)]
fn assert_sparse_fixture(
    path: &Path,
    expected: &[u8],
    context: &str,
    sparse_allocation_observable: bool,
) {
    use std::os::unix::fs::MetadataExt as _;

    assert_eq!(
        std::fs::read(path).expect("read sparse fixture"),
        expected,
        "{context} logical bytes"
    );
    let metadata = std::fs::metadata(path).expect("sparse fixture metadata");
    assert_eq!(metadata.len(), expected.len() as u64, "{context} length");
    if sparse_allocation_observable {
        assert!(
            metadata.blocks().saturating_mul(512) < metadata.len() / 2,
            "{context} must allocate less than half its logical size"
        );
    }
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

fn auth_datagram_test_config() -> RqConfig {
    RqConfig {
        // A declared non-zero loss target keeps this proof on the real UDP
        // fountain path instead of the clean-link TCP source-stream shortcut.
        round0_loss_target: 0.02,
        ..auth_test_config()
    }
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
    spawn_receiver_with_options(dest_dir, config, RqReceiveOptions::default())
}

fn spawn_receiver_with_options(
    dest_dir: PathBuf,
    config: RqConfig,
    options: RqReceiveOptions,
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
            receive_once_with_options(
                &cx,
                &listener,
                "127.0.0.1",
                &dest_dir,
                config,
                "receiver",
                options,
            )
            .await
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
fn authenticated_delta_exact_match_is_a_zero_payload_noop() {
    let root = unique_tmp("auth_delta_noop");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let payload: Vec<u8> = (0..95_371u32)
        .map(|i| (i.wrapping_mul(2_654_435_761).rotate_right(5) >> 9) as u8)
        .collect();
    let src_file = src_dir.join("payload.bin");
    let dst_file = dst_dir.join("payload.bin");
    std::fs::write(&src_file, &payload).unwrap();
    std::fs::write(&dst_file, &payload).unwrap();
    let destination_modified_before = std::fs::metadata(&dst_file).unwrap().modified().unwrap();

    let mut receiver_config = auth_test_config();
    receiver_config.enable_delta = true;
    let mut sender_config = auth_test_config();
    sender_config.enable_delta = true;

    let (addr, recv_handle) = spawn_receiver(dst_dir.clone(), receiver_config);
    let send = run_sender(addr, src_file, sender_config).expect("authenticated delta no-op");
    let recv = recv_handle
        .join()
        .expect("receiver thread")
        .expect("authenticated delta receive");

    assert!(send.receipt.committed);
    assert!(send.receipt.sha_ok && send.receipt.merkle_ok);
    assert_eq!(send.bytes_sent, 0);
    assert_eq!(send.symbols_sent, 0);
    assert_eq!(send.feedback_rounds, 0);
    assert_eq!(send.receipt.bytes_received, 0);
    assert_eq!(send.receipt.symbols_accepted, 0);
    assert_eq!(send.receipt.feedback_rounds, 0);
    assert!(
        send.receipt.committed_paths.is_empty(),
        "plaintext authenticated proof must not disclose receiver paths"
    );

    assert!(recv.committed);
    assert_eq!(recv.bytes_received, 0);
    assert_eq!(recv.symbols_accepted, 0);
    assert_eq!(recv.feedback_rounds, 0);
    assert_eq!(recv.committed_paths, vec![dst_file.clone()]);
    assert_eq!(std::fs::read(&dst_file).unwrap(), payload);
    assert_eq!(
        std::fs::metadata(&dst_file).unwrap().modified().unwrap(),
        destination_modified_before,
        "no-op must not rewrite the destination"
    );

    let mut destination_entries = std::fs::read_dir(&dst_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    destination_entries.sort();
    assert_eq!(
        destination_entries,
        vec![std::ffi::OsString::from("payload.bin")],
        "no-op must not leave a staging directory"
    );
}

#[test]
fn authenticated_delta_mismatch_falls_back_to_full_transfer() {
    let root = unique_tmp("auth_delta_full");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let payload: Vec<u8> = (0..79_113u32)
        .map(|i| (i.wrapping_mul(1_664_525).rotate_left(3) >> 7) as u8)
        .collect();
    let src_file = src_dir.join("payload.bin");
    let dst_file = dst_dir.join("payload.bin");
    std::fs::write(&src_file, &payload).unwrap();
    std::fs::write(&dst_file, vec![0xA5; payload.len()]).unwrap();

    let mut receiver_config = auth_test_config();
    receiver_config.enable_delta = true;
    let mut sender_config = auth_test_config();
    sender_config.enable_delta = true;

    let (addr, recv_handle) = spawn_receiver(dst_dir.clone(), receiver_config);
    let send = run_sender(addr, src_file, sender_config).expect("authenticated full fallback");
    let recv = recv_handle
        .join()
        .expect("receiver thread")
        .expect("authenticated fallback receive");

    assert!(send.receipt.committed);
    assert_eq!(send.bytes_sent, payload.len() as u64);
    assert!(recv.committed);
    assert_eq!(recv.bytes_received, payload.len() as u64);
    assert_eq!(std::fs::read(dst_file).unwrap(), payload);
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
fn authenticated_directory_roundtrip_preserves_nested_and_multiple_empty_directories() {
    let root = unique_tmp("auth_empty_dirs");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    let tree = src_dir.join("project");
    std::fs::create_dir_all(tree.join("empty/one/two")).unwrap();
    std::fs::create_dir_all(tree.join("multiple/alpha")).unwrap();
    std::fs::create_dir_all(tree.join("multiple/beta/deep")).unwrap();
    std::fs::create_dir_all(tree.join("mixed/empty-leaf")).unwrap();
    std::fs::create_dir_all(tree.join("mixed/content")).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();
    std::fs::write(
        tree.join("mixed/content/payload.bin"),
        b"authenticated payload\n",
    )
    .unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            tree.join("empty/one/two"),
            std::fs::Permissions::from_mode(0o751),
        )
        .expect("set empty-directory mode");
    }

    let (addr, recv_handle) = spawn_receiver(dst_dir.clone(), auth_datagram_test_config());
    let send = run_sender(addr, tree, auth_datagram_test_config())
        .expect("authenticated directory send succeeds");
    let recv = recv_handle
        .join()
        .expect("receiver thread")
        .expect("authenticated directory receive succeeds");

    assert!(send.receipt.committed);
    assert!(send.receipt.sha_ok && send.receipt.merkle_ok);
    assert_eq!(send.files, 1);
    assert!(
        send.symbols_sent > 0,
        "test must exercise UDP RaptorQ symbols"
    );
    assert!(recv.committed);
    assert_eq!(recv.files, 1);
    assert!(
        recv.symbols_accepted > 0,
        "receiver must authenticate and accept UDP RaptorQ symbols"
    );

    let base = dst_dir.join("project");
    for relative in [
        "empty/one/two",
        "multiple/alpha",
        "multiple/beta/deep",
        "mixed/empty-leaf",
    ] {
        let path = base.join(relative);
        assert!(path.is_dir(), "missing empty directory {}", path.display());
        assert_eq!(
            std::fs::read_dir(&path)
                .expect("read committed empty directory")
                .count(),
            0,
            "directory must remain empty: {}",
            path.display()
        );
    }
    assert_eq!(
        std::fs::read(base.join("mixed/content/payload.bin")).unwrap(),
        b"authenticated payload\n"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(base.join("empty/one/two"))
                .expect("empty-directory metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o751,
            "empty-directory mode must round-trip"
        );
    }
}

#[cfg(unix)]
#[test]
fn authenticated_topology_roundtrip_spans_datagram_and_control_source_paths() {
    use nix::sys::stat::Mode;
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _, symlink};
    use std::time::{Duration, UNIX_EPOCH};

    let root = unique_tmp("auth_topology");
    let src_dir = root.join("src");
    let tree = src_dir.join("project");
    std::fs::create_dir_all(&tree).expect("create topology source tree");

    let payload: Vec<u8> = (0..131_111u32)
        .map(|index| (index.wrapping_mul(2_654_435_761).rotate_left(9) >> 13) as u8)
        .collect();
    let primary = tree.join("a-primary.bin");
    std::fs::write(&primary, &payload).expect("write topology primary");
    let xattr_name = "user.asupersync.rq-topology-e2e";
    let xattr_value = b"rq-metadata\0binary-value";
    let xattr_supported = xattr::set(&primary, xattr_name, xattr_value).is_ok();
    std::fs::hard_link(&primary, tree.join("b-hardlink.bin")).expect("create hardlink alias");
    std::fs::set_permissions(&primary, std::fs::Permissions::from_mode(0o764))
        .expect("set exact source primary mode");
    let requested_primary_mtime = UNIX_EPOCH
        .checked_add(Duration::new(1_700_000_123, 456_789_123))
        .expect("representable source primary mtime");
    std::fs::File::open(&primary)
        .expect("open source primary for timestamp")
        .set_times(std::fs::FileTimes::new().set_modified(requested_primary_mtime))
        .expect("set source primary timestamp");
    let source_primary_metadata = std::fs::metadata(&primary).expect("source primary metadata");
    let expected_primary_mode = source_primary_metadata.permissions().mode() & 0o7777;
    let expected_primary_mtime = (
        source_primary_metadata.mtime(),
        source_primary_metadata.mtime_nsec(),
    );
    assert_eq!(expected_primary_mode, 0o764);
    symlink("a-primary.bin", tree.join("c-relative-link")).expect("create relative symlink");
    symlink("missing-target", tree.join("d-dangling-link")).expect("create dangling symlink");
    let fifo = tree.join("e-pipe");
    nix::unistd::mkfifo(&fifo, Mode::from_bits_truncate(0o640)).expect("create source FIFO");
    std::fs::set_permissions(&fifo, std::fs::Permissions::from_mode(0o640))
        .expect("set exact source FIFO mode");

    for (label, datagram_path) in [("datagram", true), ("control-source", false)] {
        let dst_dir = root.join(format!("dst-{label}"));
        std::fs::create_dir_all(&dst_dir).expect("create topology destination root");

        let mut receiver_config = if datagram_path {
            auth_datagram_test_config()
        } else {
            auth_test_config()
        };
        receiver_config.metadata_policy.preserve_extended_attributes = true;
        receiver_config.metadata_policy.preserve_timestamps = true;
        receiver_config.preserve_hardlinks = true;
        let sender_config = receiver_config.clone();
        let options = RqReceiveOptions::new().with_allow_special_files(true);
        let (addr, recv_handle) =
            spawn_receiver_with_options(dst_dir.clone(), receiver_config, options);
        let send = run_sender(addr, tree.clone(), sender_config)
            .unwrap_or_else(|error| panic!("{label} topology send failed: {error}"));
        let recv = recv_handle
            .join()
            .expect("topology receiver thread")
            .unwrap_or_else(|error| panic!("{label} topology receive failed: {error}"));

        assert!(send.receipt.committed, "{label} sender receipt");
        assert!(send.receipt.sha_ok, "{label} sender SHA receipt");
        assert!(send.receipt.merkle_ok, "{label} sender Merkle receipt");
        assert!(recv.committed, "{label} receiver commit");
        if datagram_path {
            assert!(
                send.symbols_sent > 0,
                "datagram path must spray UDP symbols"
            );
            assert!(
                recv.symbols_accepted > 0,
                "datagram path must accept UDP symbols"
            );
        } else {
            assert_eq!(
                send.symbols_sent, 0,
                "control-source path must not spray UDP symbols"
            );
            assert_eq!(
                recv.symbols_accepted, 0,
                "control-source path must not accept UDP symbols"
            );
        }

        let base = dst_dir.join("project");
        let received_primary = base.join("a-primary.bin");
        let received_hardlink = base.join("b-hardlink.bin");
        assert_eq!(
            std::fs::read(&received_primary).expect("read received primary"),
            payload,
            "{label} primary bytes"
        );
        assert_eq!(
            std::fs::read(&received_hardlink).expect("read received hardlink"),
            payload,
            "{label} hardlink bytes"
        );
        if xattr_supported {
            assert_eq!(
                xattr::get(&received_primary, xattr_name).expect("read received primary xattr"),
                Some(xattr_value.to_vec()),
                "{label} primary xattr"
            );
        }
        let primary_metadata =
            std::fs::metadata(&received_primary).expect("received primary metadata");
        let hardlink_metadata =
            std::fs::metadata(&received_hardlink).expect("received hardlink metadata");
        assert_eq!(
            primary_metadata.permissions().mode() & 0o7777,
            expected_primary_mode,
            "{label} primary mode"
        );
        assert_eq!(
            (primary_metadata.mtime(), primary_metadata.mtime_nsec()),
            expected_primary_mtime,
            "{label} primary subsecond mtime"
        );
        assert_eq!(
            hardlink_metadata.permissions().mode() & 0o7777,
            expected_primary_mode,
            "{label} hardlink mode"
        );
        assert_eq!(
            (hardlink_metadata.mtime(), hardlink_metadata.mtime_nsec()),
            expected_primary_mtime,
            "{label} hardlink subsecond mtime"
        );
        assert_eq!(
            primary_metadata.dev(),
            hardlink_metadata.dev(),
            "{label} dev"
        );
        assert_eq!(
            primary_metadata.ino(),
            hardlink_metadata.ino(),
            "{label} ino"
        );
        assert_eq!(
            std::fs::read_link(base.join("c-relative-link")).expect("relative symlink target"),
            PathBuf::from("a-primary.bin"),
            "{label} relative symlink"
        );
        assert_eq!(
            std::fs::read_link(base.join("d-dangling-link")).expect("dangling symlink target"),
            PathBuf::from("missing-target"),
            "{label} dangling symlink"
        );
        let fifo_metadata =
            std::fs::symlink_metadata(base.join("e-pipe")).expect("received FIFO metadata");
        assert!(fifo_metadata.file_type().is_fifo(), "{label} FIFO type");
        assert_eq!(
            fifo_metadata.permissions().mode() & 0o7777,
            0o640,
            "{label} FIFO mode"
        );
    }
}

#[cfg(unix)]
#[test]
fn authenticated_sparse_roundtrip_spans_datagram_and_control_source_paths() {
    use std::os::unix::fs::MetadataExt as _;

    let root = unique_tmp("auth_sparse");
    let tree = root.join("src/sparse-tree");
    std::fs::create_dir_all(&tree).expect("create sparse source tree");

    let regular_source = tree.join("regular.bin");
    let packed_a_source = tree.join("packed-a.bin");
    let packed_b_source = tree.join("packed-b.bin");
    let regular_expected = write_sparse_fixture(&regular_source, 1_310_720, b"rq-regular-sparse");
    let packed_a_expected = write_sparse_fixture(&packed_a_source, 262_144, b"rq-packed-a");
    let packed_b_expected = write_sparse_fixture(&packed_b_source, 262_144, b"rq-packed-b");
    let sparse_allocation_observable = [&regular_source, &packed_a_source, &packed_b_source]
        .into_iter()
        .all(|source| {
            let metadata = std::fs::metadata(source).expect("source sparse fixture metadata");
            metadata.blocks().saturating_mul(512) < metadata.len() / 2
        });

    for (label, datagram_path) in [("datagram", true), ("control-source", false)] {
        let dst_dir = root.join(format!("dst-{label}"));
        std::fs::create_dir_all(&dst_dir).expect("create sparse destination root");
        let receiver_config = if datagram_path {
            auth_datagram_test_config()
        } else {
            auth_test_config()
        };
        let sender_config = receiver_config.clone();
        let options = RqReceiveOptions::new().with_sparse_files(true);
        let (addr, recv_handle) =
            spawn_receiver_with_options(dst_dir.clone(), receiver_config, options);
        let send = run_sender(addr, tree.clone(), sender_config)
            .unwrap_or_else(|error| panic!("{label} sparse send failed: {error}"));
        let recv = recv_handle
            .join()
            .expect("sparse receiver thread")
            .unwrap_or_else(|error| panic!("{label} sparse receive failed: {error}"));

        assert!(send.receipt.committed, "{label} sender receipt");
        assert!(send.receipt.sha_ok, "{label} sender SHA receipt");
        assert!(send.receipt.merkle_ok, "{label} sender Merkle receipt");
        assert!(recv.committed, "{label} receiver commit");
        if datagram_path {
            assert!(send.symbols_sent > 0, "datagram path must spray symbols");
            assert!(
                recv.symbols_accepted > 0,
                "datagram path must accept symbols"
            );
        } else {
            assert_eq!(send.symbols_sent, 0, "control-source sender symbols");
            assert_eq!(recv.symbols_accepted, 0, "control-source receiver symbols");
        }

        let base = dst_dir.join("sparse-tree");
        assert_sparse_fixture(
            &base.join("regular.bin"),
            &regular_expected,
            &format!("{label} regular sparse file"),
            sparse_allocation_observable,
        );
        assert_sparse_fixture(
            &base.join("packed-a.bin"),
            &packed_a_expected,
            &format!("{label} packed sparse file A"),
            sparse_allocation_observable,
        );
        assert_sparse_fixture(
            &base.join("packed-b.bin"),
            &packed_b_expected,
            &format!("{label} packed sparse file B"),
            sparse_allocation_observable,
        );
    }
}

#[cfg(unix)]
#[test]
fn bonded_special_entry_proves_and_sprays_zero_symbols() {
    use std::os::unix::net::UnixListener as StdUnixListener;

    use asupersync::net::atp::bonding::{DonorAssignment, derive_bonded_descriptor};
    use asupersync::net::atp::transport_common::FileKind;
    use asupersync::net::atp::transport_rq::donate_path;

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let src_dir = PathBuf::from("/tmp").join(format!("asb-sock-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&src_dir).expect("create special-entry source root");
    let socket_path = src_dir.join("control.sock");
    let _socket_listener = StdUnixListener::bind(&socket_path).expect("bind source unix socket");
    let udp_sink = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind UDP sink");
    let receiver_endpoint = udp_sink.local_addr().expect("UDP sink address");
    let config = test_config();

    let runtime = RuntimeBuilder::multi_thread()
        .worker_threads(2)
        .enable_platform_reactor(true)
        .build()
        .expect("bonded special-entry runtime");
    let source_root = src_dir.clone();
    let (descriptor, report) = runtime
        .block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("bonded special-entry cx");
            let descriptor = derive_bonded_descriptor(
                &cx,
                &source_root,
                config.symbol_size,
                u64::try_from(config.max_block_size).unwrap_or(u64::MAX),
                u64::MAX,
                None,
            )
            .await?;
            let assignment = DonorAssignment::new_static(0, 1, vec![receiver_endpoint], None);
            let report = donate_path(
                &cx,
                &descriptor,
                &assignment,
                receiver_endpoint,
                &source_root,
                config,
            )
            .await?;
            Ok::<_, RqError>((descriptor, report))
        }))
        .expect("special entry proves and sprays");

    assert_eq!(descriptor.entries.len(), 1);
    let entry = &descriptor.entries[0];
    assert_eq!(entry.rel_path, "control.sock");
    assert_eq!(entry.size, 0);
    assert_eq!(
        entry.sha256_hex,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(descriptor.total_bytes, 0);
    assert_eq!(descriptor.entry_source_block_count(entry.index), Some(0));
    let metadata = descriptor
        .metadata
        .as_ref()
        .expect("bonded special-entry metadata")
        .entries
        .iter()
        .find(|candidate| candidate.rel_path == entry.rel_path)
        .expect("socket metadata row");
    assert_eq!(metadata.metadata.file_kind, FileKind::Socket);

    assert_eq!(report.entries, 1);
    assert_eq!(report.blocks, 0);
    assert_eq!(report.source_symbols_sent, 0);
    assert_eq!(report.repair_symbols_sent, 0);
    assert_eq!(report.symbols_sent, 0);
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
