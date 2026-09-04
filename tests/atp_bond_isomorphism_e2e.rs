//! Bonded-vs-single-source isomorphism gate (`asupersync-atp-channel-bonding-z01bbr.8.5`)
//! plus the three-donor arm of the deterministic N-donor matrix
//! (`asupersync-atp-channel-bonding-z01bbr.8.1`).
//!
//! H5 asks a narrow question: does the bonded data path with `donor_count = 1`
//! commit exactly what today's already-shipping single-source transport commits?
//! The in-crate test `bonded_receive_single_donor_commits_byte_identical`
//! compares a bonded commit against the *source payload*, which proves the
//! bonded path is correct but not that it is *isomorphic* — a bonded path that
//! regressed in the same direction as its own expectation would still pass.
//! This file runs the same bytes through both transports and compares the two
//! commits against each other, so bonding cannot silently diverge from the path
//! it is supposed to generalize.
//!
//! Required metadata (TESTING_FOR_AGENTS.md):
//! * `bead_id`: `asupersync-atp-channel-bonding-z01bbr.8.5` (+ `.8.1` for N=3)
//! * `scenario_id`: `ATP-BOND-ISOMORPHISM-N1`, `ATP-BOND-N3-COMMIT`
//! * `seed_or_fixture`: deterministic synthetic payload, no RNG
//! * `command`: `rch exec -- env CARGO_TARGET_DIR=... cargo test -p asupersync
//!   --test atp_bond_isomorphism_e2e -- --nocapture`
//! * `artifact_path`: none (assertions only; no repro bundle emitted)
//! * `expected_outcome`: `pass`
//!
//! NO-CLAIM BOUNDARY: this is the *weak* form of H5 — identical committed
//! bytes. The bead's stronger "identical symbol stream" form is not asserted
//! here, because neither transport exposes a per-ESI capture hook, so proving it
//! would require new production instrumentation rather than a new test. The
//! schedule-level isomorphism is separately covered by
//! `donor_count_one_schedule_is_single_source_isomorphic` and
//! `donor_count_one_emission_stream_matches_single_source_order` in
//! `src/net/atp/bonding/assignment.rs`.
#![allow(missing_docs)]
// An integration test is its own crate, so the `recursion_limit` raised in
// `src/lib.rs` does not reach it. Proving `Send` for the ATP bonded/RaptorQ
// futures walks one solver frame per async link and overflows the default 128.
#![recursion_limit = "256"]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use asupersync::atp::object::MetadataPolicy;
use asupersync::cx::Cx;
use asupersync::net::TcpListener;
use asupersync::net::atp::bonding::{BondTransferDescriptor, derive_bonded_descriptor};
use asupersync::net::atp::transport_rq::{
    BondedDonateReport, BondedReceiveReport, ReceiveReport, RqConfig, RqError, RqReceiveOptions,
    SendReport, donate_bonded, receive_bonded_with_options, receive_once, send_path,
};
use asupersync::runtime::RuntimeBuilder;

/// 64 KiB source blocks keep per-block `K` small so debug-build RaptorQ decode
/// stays fast while still exercising real multi-block SBN routing. Mirrors
/// `tests/atp_rq_loopback_e2e.rs` and the in-crate bonded e2e configs.
const MAX_BLOCK_SIZE: usize = 64 * 1024;
const MAX_TRANSFER_BYTES: u64 = 8 * 1024 * 1024;

fn unique_tmp(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!(
        "atp_bond_iso_{label}_{}_{nanos}",
        std::process::id()
    ))
}

fn payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
        .collect()
}

/// One posture for BOTH transports. This is load-bearing for the comparison,
/// not incidental tidiness: `derive_bonded_descriptor` forces
/// `MetadataPolicy::portable()` and `preserve_hardlinks: true` so that identical
/// content always derives an identical enrollment descriptor. If the
/// single-source leg ran on `RqConfig::default()` it would capture a different
/// metadata policy, and any divergence the comparison found would be an
/// artifact of the harness rather than a bonding regression.
fn shared_config() -> RqConfig {
    RqConfig {
        max_block_size: MAX_BLOCK_SIZE,
        max_transfer_bytes: MAX_TRANSFER_BYTES,
        metadata_policy: MetadataPolicy::portable(),
        preserve_hardlinks: true,
        accept_timeout: Duration::from_secs(30),
        round_tail_drain: Duration::from_millis(5),
        ..RqConfig::default()
    }
    .allow_unauthenticated_for_trusted_transport()
}

// ---------------------------------------------------------------- single-source

fn spawn_single_source_receiver(
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
            .expect("single-source receiver runtime");
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("receiver cx");
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            addr_tx.send(addr).expect("send single-source addr");
            receive_once(&cx, &listener, "127.0.0.1", &dest_dir, config, "receiver").await
        }))
    });
    let addr = addr_rx.recv().expect("single-source receiver bound");
    (addr, handle)
}

fn run_single_source_sender(
    addr: SocketAddr,
    source: PathBuf,
    config: RqConfig,
) -> Result<SendReport, RqError> {
    let runtime = RuntimeBuilder::multi_thread()
        .worker_threads(2)
        .enable_platform_reactor(true)
        .build()
        .expect("single-source sender runtime");
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("sender cx");
        send_path(&cx, addr, &source, config, "sender").await
    }))
}

// ----------------------------------------------------------------------- bonded

/// Derive the shared bonded descriptor the way a real coordinator does, through
/// the public `derive_bonded_descriptor` rather than the crate-private helpers
/// the in-crate tests use. Every donor and the receiver derive this
/// independently from their own local bytes; the descriptor is never on the wire.
fn derive_descriptor(source_file: &Path, config: &RqConfig) -> BondTransferDescriptor {
    let source = source_file.to_path_buf();
    let symbol_size = config.symbol_size;
    let max_block_size = u64::try_from(config.max_block_size).unwrap_or(u64::MAX);
    let runtime = RuntimeBuilder::multi_thread()
        .worker_threads(2)
        .enable_platform_reactor(true)
        .build()
        .expect("descriptor runtime");
    runtime
        .block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("descriptor cx");
            derive_bonded_descriptor(
                &cx,
                &source,
                symbol_size,
                max_block_size,
                MAX_TRANSFER_BYTES,
                None,
            )
            .await
        }))
        .expect("derive bonded descriptor")
}

fn spawn_bonded_receiver(
    descriptor: BondTransferDescriptor,
    dest_dir: PathBuf,
    expected_donors: u32,
    config: RqConfig,
) -> (
    SocketAddr,
    thread::JoinHandle<Result<BondedReceiveReport, RqError>>,
) {
    spawn_bonded_receiver_with_options(
        descriptor,
        dest_dir,
        expected_donors,
        config,
        RqReceiveOptions::default(),
    )
}

fn spawn_bonded_receiver_with_options(
    descriptor: BondTransferDescriptor,
    dest_dir: PathBuf,
    expected_donors: u32,
    config: RqConfig,
    options: RqReceiveOptions,
) -> (
    SocketAddr,
    thread::JoinHandle<Result<BondedReceiveReport, RqError>>,
) {
    let (addr_tx, addr_rx) = mpsc::channel::<SocketAddr>();
    let handle = thread::spawn(move || {
        let runtime = RuntimeBuilder::multi_thread()
            .worker_threads(2)
            .enable_platform_reactor(true)
            .build()
            .expect("bonded receiver runtime");
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("bonded receiver cx");
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            addr_tx.send(addr).expect("send bonded addr");
            receive_bonded_with_options(
                &cx,
                &descriptor,
                &dest_dir,
                &listener,
                "127.0.0.1",
                expected_donors,
                config,
                "bonded-receiver",
                None,
                options,
            )
            .await
        }))
    });
    let addr = addr_rx.recv().expect("bonded receiver bound");
    (addr, handle)
}

/// Run one donor leg to completion on its own runtime/thread, mirroring a
/// separate donor process.
fn spawn_bonded_donor(
    descriptor: BondTransferDescriptor,
    control_addr: SocketAddr,
    source_root: PathBuf,
    config: RqConfig,
) -> thread::JoinHandle<Result<BondedDonateReport, RqError>> {
    thread::spawn(move || {
        let runtime = RuntimeBuilder::multi_thread()
            .worker_threads(2)
            .enable_platform_reactor(true)
            .build()
            .expect("bonded donor runtime");
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("bonded donor cx");
            donate_bonded(&cx, &descriptor, control_addr, &source_root, config).await
        }))
    })
}

// ------------------------------------------------------------------------ tests

/// H5 (`z01bbr.8.5`), scenario `ATP-BOND-ISOMORPHISM-N1`.
///
/// Same bytes, same posture, two transports: the bonded `donor_count = 1` commit
/// must equal the single-source commit byte for byte. Any divergence is a
/// bonding regression against the already-shipping path.
#[test]
fn bond_donor_count_one_commits_identically_to_single_source() {
    let root = unique_tmp("n1");
    let src_dir = root.join("src");
    let dst_single = root.join("dst_single");
    let dst_bonded = root.join("dst_bonded");
    for dir in [&src_dir, &dst_single, &dst_bonded] {
        std::fs::create_dir_all(dir).expect("create dir");
    }

    // ~96 KiB spans two 64 KiB source blocks: real multi-block SBN routing and
    // tail padding, small enough for a debug-build GF(256) solve.
    let bytes = payload(96_007);
    let src_file = src_dir.join("payload.bin");
    std::fs::write(&src_file, &bytes).expect("write payload");

    // Leg A: today's single-source transport.
    let (addr, recv_handle) = spawn_single_source_receiver(dst_single.clone(), shared_config());
    let send = run_single_source_sender(addr, src_file.clone(), shared_config())
        .expect("single-source send succeeds");
    let single = recv_handle
        .join()
        .expect("single-source receiver thread")
        .expect("single-source receive succeeds");

    // Leg B: the bonded transport with exactly one donor.
    let descriptor = derive_descriptor(&src_file, &shared_config());
    let (bond_addr, bond_recv) =
        spawn_bonded_receiver(descriptor.clone(), dst_bonded.clone(), 1, shared_config());
    let donor = spawn_bonded_donor(descriptor, bond_addr, src_dir.clone(), shared_config())
        .join()
        .expect("bonded donor thread")
        .expect("bonded donate succeeds");
    let bonded = bond_recv
        .join()
        .expect("bonded receiver thread")
        .expect("bonded receive succeeds");

    // Both legs must have actually committed, not merely returned.
    assert!(send.receipt.committed, "single-source must commit");
    assert!(single.committed, "single-source receiver must commit");
    assert!(bonded.committed, "bonded receiver must commit");
    assert!(donor.receipt.committed, "donor must see a committed proof");
    assert!(donor.receipt.sha_ok && donor.receipt.merkle_ok);
    assert_eq!(bonded.enrolled_donors, 1, "exactly one donor enrolled");

    // The isomorphism itself: identical accounting, then identical bytes.
    assert_eq!(
        single.bytes_received, bonded.bytes_received,
        "bonded N=1 must receive the same byte count as single-source"
    );
    let from_single = std::fs::read(dst_single.join("payload.bin")).expect("single-source commit");
    let from_bonded = std::fs::read(dst_bonded.join("payload.bin")).expect("bonded commit");
    assert_eq!(
        from_single, bytes,
        "single-source commit must be byte-identical to the source"
    );
    assert_eq!(
        from_bonded, from_single,
        "bonded donor_count=1 commit must be byte-identical to the single-source commit"
    );
}

/// Public bonded N=1 path: validated zero-content topology must survive
/// donor holding proof and the shared terminal commit without being mistaken
/// for RaptorQ source geometry.
///
/// NO-CLAIM BOUNDARY: this Unix fixture covers regular bytes, one hardlink,
/// relative and dangling symlinks, and FIFO recreation. It does not cover
/// sockets/devices, Windows, exact metadata, sparse extents, multiple donors,
/// cross-host behavior, performance, or broad workspace/release health.
#[cfg(unix)]
#[test]
fn bonded_receiver_options_commit_portable_topology() {
    use asupersync::net::atp::transport_common::FileKind;
    use nix::sys::stat::Mode;
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, symlink};

    let root = unique_tmp("portable_topology");
    let src_dir = root.join("src");
    let tree = src_dir.join("project");
    let dst_dir = root.join("dst");
    std::fs::create_dir_all(&tree).expect("create topology source tree");
    std::fs::create_dir_all(&dst_dir).expect("create topology destination root");

    let bytes = payload(96_007);
    let primary = tree.join("a-primary.bin");
    std::fs::write(&primary, &bytes).expect("write topology primary");
    std::fs::hard_link(&primary, tree.join("b-hardlink.bin")).expect("create hardlink alias");
    symlink("a-primary.bin", tree.join("c-relative-link")).expect("create relative symlink");
    symlink("missing-target", tree.join("d-dangling-link")).expect("create dangling symlink");
    nix::unistd::mkfifo(&tree.join("e-pipe"), Mode::from_bits_truncate(0o640))
        .expect("create source FIFO");

    let mut config = shared_config();
    config.metadata_policy.preserve_symlinks = true;
    let descriptor = derive_descriptor(&tree, &config);
    assert!(descriptor.is_directory);
    assert_eq!(descriptor.total_bytes, bytes.len() as u64);

    let primary_entry = descriptor
        .entries
        .iter()
        .find(|entry| entry.rel_path == "a-primary.bin")
        .expect("primary descriptor entry");
    let primary_blocks = descriptor
        .entry_source_block_count(primary_entry.index)
        .expect("primary source-block count");
    assert!(primary_blocks > 0, "primary must own source geometry");

    for rel_path in [
        "b-hardlink.bin",
        "c-relative-link",
        "d-dangling-link",
        "e-pipe",
    ] {
        let entry = descriptor
            .entries
            .iter()
            .find(|entry| entry.rel_path == rel_path)
            .unwrap_or_else(|| panic!("missing topology descriptor entry: {rel_path}"));
        assert_eq!(
            entry.size, 0,
            "topology entry must carry no content: {rel_path}"
        );
        assert_eq!(
            descriptor.entry_source_block_count(entry.index),
            Some(0),
            "topology entry must carry no RaptorQ geometry: {rel_path}"
        );
    }
    let fifo_metadata = descriptor
        .metadata
        .as_ref()
        .expect("bonded topology metadata")
        .entries
        .iter()
        .find(|entry| entry.rel_path == "e-pipe")
        .expect("FIFO metadata row");
    assert_eq!(fifo_metadata.metadata.file_kind, FileKind::Fifo);

    let (addr, recv_handle) = spawn_bonded_receiver_with_options(
        descriptor.clone(),
        dst_dir.clone(),
        1,
        config.clone(),
        RqReceiveOptions::new().with_allow_special_files(true),
    );
    let donor = spawn_bonded_donor(descriptor.clone(), addr, tree, config)
        .join()
        .expect("bonded topology donor thread")
        .expect("bonded topology donation succeeds");
    let received = recv_handle
        .join()
        .expect("bonded topology receiver thread")
        .expect("bonded topology receive succeeds");

    assert!(
        donor.receipt.committed,
        "donor must observe committed proof"
    );
    assert!(donor.receipt.sha_ok && donor.receipt.merkle_ok);
    assert_eq!(donor.spray.entries, descriptor.entries.len());
    assert_eq!(donor.spray.blocks, usize::from(primary_blocks));
    assert!(donor.spray.source_symbols_sent > 0);
    assert!(received.committed);
    assert_eq!(received.enrolled_donors, 1);
    assert_eq!(received.bytes_received, bytes.len() as u64);
    assert!(received.symbols_accepted > 0);

    let base = dst_dir.join("project");
    let committed_primary = base.join("a-primary.bin");
    let committed_hardlink = base.join("b-hardlink.bin");
    assert_eq!(
        std::fs::read(&committed_primary).expect("read primary"),
        bytes
    );
    assert_eq!(
        std::fs::metadata(&committed_primary)
            .expect("primary metadata")
            .ino(),
        std::fs::metadata(&committed_hardlink)
            .expect("hardlink metadata")
            .ino(),
        "hardlink must share the committed inode"
    );
    assert_eq!(
        std::fs::read_link(base.join("c-relative-link")).expect("relative symlink target"),
        PathBuf::from("a-primary.bin")
    );
    assert_eq!(
        std::fs::read_link(base.join("d-dangling-link")).expect("dangling symlink target"),
        PathBuf::from("missing-target")
    );
    assert!(
        std::fs::symlink_metadata(base.join("e-pipe"))
            .expect("committed FIFO metadata")
            .file_type()
            .is_fifo(),
        "bonded receive options must materialize the FIFO"
    );
}

/// H1 (`z01bbr.8.1`) N=3 arm, scenario `ATP-BOND-N3-COMMIT`.
///
/// The in-crate suite covers N=1 and N=2; the bead's acceptance asks for
/// N in {1,2,3}. Three donors also exercise a residue partition that is neither
/// the degenerate `N=1` identity nor the `N=2` even/odd split, so an off-by-one
/// in `esi % N == i` that happens to be symmetric at N=2 cannot hide.
#[test]
fn bond_three_donors_commit_byte_identical_with_every_donor_contributing() {
    let root = unique_tmp("n3");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    for dir in [&src_dir, &dst_dir] {
        std::fs::create_dir_all(dir).expect("create dir");
    }

    // ~200 KiB across ~4 source blocks, so each of the three donors owns a
    // non-trivial slice of every block's ESI stream.
    let bytes = payload(200_003);
    let src_file = src_dir.join("payload.bin");
    std::fs::write(&src_file, &bytes).expect("write payload");

    let descriptor = derive_descriptor(&src_file, &shared_config());
    let (addr, recv_handle) =
        spawn_bonded_receiver(descriptor.clone(), dst_dir.clone(), 3, shared_config());

    // Every donor must be spawned BEFORE any is joined. The receiver blocks
    // until all three enroll, so a lazy spawn-then-join chain would join donor 0
    // while donors 1 and 2 had not yet started, and the transfer would never
    // reach its expected donor count. This is why the handles are materialised
    // eagerly rather than folded into the join iterator.
    let mut donors = Vec::with_capacity(3);
    for _ in 0..3 {
        donors.push(spawn_bonded_donor(
            descriptor.clone(),
            addr,
            src_dir.clone(),
            shared_config(),
        ));
    }
    let mut reports: Vec<BondedDonateReport> = Vec::with_capacity(donors.len());
    for handle in donors {
        reports.push(
            handle
                .join()
                .expect("bonded donor thread")
                .expect("bonded donate succeeds"),
        );
    }
    let report = recv_handle
        .join()
        .expect("bonded receiver thread")
        .expect("bonded receive succeeds");

    assert!(report.committed, "three-donor bonded receive must commit");
    assert_eq!(report.enrolled_donors, 3, "all three donors must enroll");

    // Every donor must have been assigned a distinct slice and actually used it.
    let mut indexes: Vec<u32> = reports.iter().map(|r| r.donor_index).collect();
    indexes.sort_unstable();
    assert_eq!(
        indexes,
        vec![0, 1, 2],
        "donor indexes must be 0..3 distinct"
    );
    for donor in &reports {
        assert_eq!(donor.donor_count, 3);
        assert!(
            donor.symbols_sent > 0,
            "donor {} sent no symbols",
            donor.donor_index
        );
    }

    // A donor that enrolled but contributed nothing accepted would mean the
    // receiver decoded from the others alone -- that would still commit, and
    // would silently hide a broken partition. Assert real contribution.
    assert_eq!(report.donor_ingress.len(), 3);
    for (index, stats) in &report.donor_ingress {
        assert!(
            stats.symbols_accepted > 0,
            "donor {index} contributed no accepted symbols"
        );
    }

    let committed = std::fs::read(dst_dir.join("payload.bin")).expect("bonded commit");
    assert_eq!(
        committed, bytes,
        "three-donor bonded commit must be byte-identical"
    );
}
