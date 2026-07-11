//! Metadata-fidelity gate for the ATP-over-TCP transport (J1,
//! `asupersync-arq-quic-epic-b0k8qo.11.1`).
//!
//! A sync tool that silently drops permissions, mtimes, and symlinks is strictly
//! worse than rsync. This e2e moves a real tree carrying assorted unix modes, a
//! preserved mtime, a symlink, xattrs, and hardlinks across a loopback TCP
//! socket, then asserts every metadata field arrives byte-identical — gated by
//! the sender's
//! [`MetadataPolicy`]. A portable policy must round-trip regular-file content
//! while carrying no metadata (backward-compatible wire), reject symlinks
//! rather than following them outside the transfer root, and still commit
//! ordinary transfers (proving the receiver's metadata-commitment recomputation
//! matches).
#![allow(missing_docs)]
#![cfg(unix)]

use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

use asupersync::atp::object::MetadataPolicy;
use asupersync::cx::Cx;
use asupersync::net::TcpListener;
use asupersync::net::atp::transport_tcp::{
    ReceiveReport, SendReport, TransferConfig, TransportError, receive_once, send_path,
};
use asupersync::runtime::RuntimeBuilder;

fn unique_tmp(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!(
        "atp_tcp_meta_{label}_{}_{nanos}",
        std::process::id()
    ))
}

fn config_with_policy(policy: MetadataPolicy) -> TransferConfig {
    TransferConfig {
        metadata_policy: policy,
        ..TransferConfig::default()
    }
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o7777
}

fn set_mtime_secs(path: &Path, secs: u64) {
    let when = UNIX_EPOCH + Duration::from_secs(secs);
    let times = std::fs::FileTimes::new().set_modified(when);
    std::fs::File::open(path).unwrap().set_times(times).unwrap();
}

fn mtime_secs(path: &Path) -> u64 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn set_xattr_or_skip(path: &Path, name: &str, value: &[u8]) -> bool {
    xattr::set(path, name, value).is_ok()
}

fn spawn_receiver(
    dest_dir: PathBuf,
    policy: MetadataPolicy,
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
                config_with_policy(policy),
                "receiver",
            )
            .await
        }))
    });
    let addr = addr_rx.recv().expect("receiver bound address");
    (addr, handle)
}

fn spawn_receiver_with_config(
    dest_dir: PathBuf,
    config: TransferConfig,
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
            receive_once(&cx, &listener, &dest_dir, config, "receiver").await
        }))
    });
    let addr = addr_rx.recv().expect("receiver bound address");
    (addr, handle)
}

fn run_sender(
    addr: SocketAddr,
    source: PathBuf,
    policy: MetadataPolicy,
) -> Result<SendReport, TransportError> {
    let runtime = RuntimeBuilder::multi_thread()
        .build()
        .expect("sender runtime");
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("sender cx");
        send_path(&cx, addr, &source, config_with_policy(policy), "sender").await
    }))
}

fn run_sender_with_config(
    addr: SocketAddr,
    source: PathBuf,
    config: TransferConfig,
) -> Result<SendReport, TransportError> {
    let runtime = RuntimeBuilder::multi_thread()
        .build()
        .expect("sender runtime");
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("sender cx");
        send_path(&cx, addr, &source, config, "sender").await
    }))
}

#[test]
fn metadata_roundtrip_preserves_mode_mtime_and_symlink() {
    let root = unique_tmp("fidelity");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    let tree = src_dir.join("project");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    // Assorted modes (rsync's canonical cases) + a preserved mtime + a symlink.
    let exec = tree.join("run.sh");
    std::fs::write(&exec, b"#!/bin/sh\necho hi\n").unwrap();
    set_mode(&exec, 0o755);

    let data = tree.join("data.txt");
    std::fs::write(&data, b"some content here\n").unwrap();
    set_mode(&data, 0o644);

    let secret = tree.join("secret.key");
    std::fs::write(&secret, b"private\n").unwrap();
    set_mode(&secret, 0o600);

    // A fixed mtime (whole seconds to dodge fs granularity) applied last so the
    // earlier writes/chmods do not clobber it.
    let fixed_mtime: u64 = 1_600_000_000;
    set_mtime_secs(&data, fixed_mtime);

    // A relative symlink: its target rides in metadata, no content bytes.
    std::os::unix::fs::symlink("data.txt", tree.join("latest.txt")).unwrap();

    let (addr, recv_handle) = spawn_receiver(dst_dir.clone(), MetadataPolicy::full_preservation());
    let send =
        run_sender(addr, tree.clone(), MetadataPolicy::full_preservation()).expect("send succeeds");
    let recv = recv_handle
        .join()
        .expect("receiver thread")
        .expect("receive succeeds");

    assert!(send.receipt.committed, "receipt must commit with metadata");
    assert!(send.receipt.sha_ok && send.receipt.merkle_ok);
    assert!(recv.committed);

    let out = dst_dir.join("project");

    // Modes round-trip field-by-field.
    assert_eq!(mode_of(&out.join("run.sh")), 0o755, "exec mode preserved");
    assert_eq!(
        mode_of(&out.join("data.txt")),
        0o644,
        "regular mode preserved"
    );
    assert_eq!(
        mode_of(&out.join("secret.key")),
        0o600,
        "restrictive mode preserved"
    );

    // mtime round-trips (whole seconds).
    assert_eq!(
        mtime_secs(&out.join("data.txt")),
        fixed_mtime,
        "mtime must be preserved exactly"
    );

    // Symlink round-trips as a link to the same target, not a copied file.
    let link = out.join("latest.txt");
    let lmeta = std::fs::symlink_metadata(&link).expect("symlink present");
    assert!(
        lmeta.file_type().is_symlink(),
        "latest.txt must be a symlink"
    );
    assert_eq!(
        std::fs::read_link(&link).unwrap(),
        Path::new("data.txt"),
        "symlink target preserved"
    );

    // Content of regular files still byte-identical.
    assert_eq!(
        std::fs::read(out.join("data.txt")).unwrap(),
        b"some content here\n"
    );
}

#[test]
fn xattr_roundtrip_preserves_value_when_supported() {
    let root = unique_tmp("xattr");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    let tree = src_dir.join("project");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let data = tree.join("data.txt");
    std::fs::write(&data, b"xattr payload\n").unwrap();
    let attr_name = "user.asupersync.roundtrip";
    let attr_value = b"\0binary-value\nwith-newline";
    if !set_xattr_or_skip(&data, attr_name, attr_value) {
        return;
    }

    let (addr, recv_handle) = spawn_receiver(dst_dir.clone(), MetadataPolicy::full_preservation());
    let send =
        run_sender(addr, tree.clone(), MetadataPolicy::full_preservation()).expect("send succeeds");
    let recv = recv_handle
        .join()
        .expect("receiver thread")
        .expect("receive succeeds");
    assert!(send.receipt.committed && recv.committed);

    let out = dst_dir.join("project").join("data.txt");
    assert_eq!(
        xattr::get(&out, attr_name).unwrap(),
        Some(attr_value.to_vec()),
        "xattr value must round-trip byte-identical"
    );
    assert_eq!(std::fs::read(out).unwrap(), b"xattr payload\n");
}

#[test]
fn portable_policy_round_trips_content_without_metadata() {
    // A portable policy carries no metadata: content must still arrive identical,
    // the transfer still commits (receiver's empty metadata commitment matches),
    // and received files get the receiver's default perms rather than the
    // source's restrictive mode.
    let root = unique_tmp("portable");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    let tree = src_dir.join("project");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let f = tree.join("a.txt");
    std::fs::write(&f, b"portable bytes\n").unwrap();
    set_mode(&f, 0o600);

    let (addr, recv_handle) = spawn_receiver(dst_dir.clone(), MetadataPolicy::portable());
    let send = run_sender(addr, tree.clone(), MetadataPolicy::portable()).expect("send");
    let recv = recv_handle.join().expect("recv thread").expect("recv");

    assert!(send.receipt.committed);
    assert!(recv.committed);
    assert_eq!(
        std::fs::read(dst_dir.join("project").join("a.txt")).unwrap(),
        b"portable bytes\n",
        "content must round-trip under a portable policy"
    );
}

#[test]
fn symlink_only_transfer_commits_with_zero_content() {
    // A lone symlink (no regular-file content at all) must transfer: the sender
    // emits no ObjectData frames for it, the receiver creates the link from
    // metadata, and the transfer commits.
    let root = unique_tmp("symonly");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    let tree = src_dir.join("project");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    std::fs::write(tree.join("target.txt"), b"x").unwrap();
    std::os::unix::fs::symlink("target.txt", tree.join("alias")).unwrap();

    let (addr, recv_handle) = spawn_receiver(dst_dir.clone(), MetadataPolicy::full_preservation());
    let send = run_sender(addr, tree.clone(), MetadataPolicy::full_preservation()).expect("send");
    let recv = recv_handle.join().expect("recv thread").expect("recv");

    assert!(send.receipt.committed && recv.committed);
    let link = dst_dir.join("project").join("alias");
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink(),
        "alias must arrive as a symlink"
    );
    assert_eq!(std::fs::read_link(&link).unwrap(), Path::new("target.txt"));
}

#[test]
fn empty_directory_round_trips_and_preserves_mode() {
    // J2 (b0k8qo.11.2) slice (a): an empty/structural directory is otherwise
    // lost (the walk emits only regular files). It must arrive as a directory
    // with its mode preserved, alongside ordinary files.
    let root = unique_tmp("emptydir");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    let tree = src_dir.join("project");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    std::fs::write(tree.join("keep.txt"), b"content\n").unwrap();
    let empty = tree.join("empty_subdir");
    std::fs::create_dir(&empty).unwrap();
    set_mode(&empty, 0o750);

    let (addr, recv_handle) = spawn_receiver(dst_dir.clone(), MetadataPolicy::full_preservation());
    let send = run_sender(addr, tree.clone(), MetadataPolicy::full_preservation()).expect("send");
    let recv = recv_handle.join().expect("recv thread").expect("recv");
    assert!(send.receipt.committed && recv.committed);

    let out_empty = dst_dir.join("project").join("empty_subdir");
    let meta = std::fs::symlink_metadata(&out_empty).expect("empty dir present on receiver");
    assert!(
        meta.file_type().is_dir(),
        "empty_subdir must arrive as a directory"
    );
    assert_eq!(mode_of(&out_empty), 0o750, "empty dir mode preserved");
    assert_eq!(
        std::fs::read(dst_dir.join("project").join("keep.txt")).unwrap(),
        b"content\n",
        "regular file alongside the empty dir still round-trips"
    );
}

#[test]
fn non_preserved_symlink_is_rejected_without_connecting() {
    // Following an unpreserved symlink could escape the transfer root. Portable
    // mode must reject it during source planning, before opening a connection.
    let root = unique_tmp("followsym");
    let src_dir = root.join("src");
    let tree = src_dir.join("project");
    std::fs::create_dir_all(&tree).unwrap();

    std::fs::write(tree.join("data.txt"), b"real payload\n").unwrap();
    std::os::unix::fs::symlink("data.txt", tree.join("alias.txt")).unwrap();

    let unused_addr = "127.0.0.1:9".parse().unwrap();
    let error = run_sender(unused_addr, tree, MetadataPolicy::portable())
        .expect_err("portable mode must reject source symlinks");
    assert!(
        matches!(&error, TransportError::Source(message) if message.contains("source symlink rejected by metadata policy")),
        "unexpected portable-symlink error: {error}"
    );
}

#[test]
fn fifo_is_skipped_without_hanging_the_sender() {
    // J2 (b0k8qo.11.2) slice (b): a FIFO in the source must NOT block the sender
    // (it is zero-content, never opened) and is skipped+logged on the receiver
    // (not materialized in this slice), while ordinary files alongside it still
    // transfer. If the sender ever opened the FIFO, this test would hang.
    let root = unique_tmp("fifo");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    let tree = src_dir.join("project");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    std::fs::write(tree.join("keep.txt"), b"kept\n").unwrap();
    // Create the FIFO via the coreutils `mkfifo` (avoids a libc/nix dev-dep).
    let fifo = tree.join("pipe");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("spawn mkfifo");
    assert!(status.success(), "mkfifo must create the source FIFO");
    assert!(
        std::fs::symlink_metadata(&fifo)
            .unwrap()
            .file_type()
            .is_fifo(),
        "source pipe must be a FIFO"
    );

    let (addr, recv_handle) = spawn_receiver(dst_dir.clone(), MetadataPolicy::full_preservation());
    let send = run_sender(addr, tree.clone(), MetadataPolicy::full_preservation()).expect("send");
    let recv = recv_handle.join().expect("recv thread").expect("recv");
    assert!(send.receipt.committed && recv.committed);

    // The FIFO is skipped (not recreated) in this slice; the regular file arrives.
    assert!(
        !dst_dir.join("project").join("pipe").exists(),
        "FIFO must be skipped+logged, not materialized"
    );
    assert_eq!(
        std::fs::read(dst_dir.join("project").join("keep.txt")).unwrap(),
        b"kept\n",
        "regular file alongside the FIFO still round-trips"
    );
}

#[test]
fn fifo_recreated_when_allow_special_files_set() {
    // With the opt-in TransferConfig.allow_special_files, a source FIFO is
    // recreated on the receiver (via mkfifo) with its mode, rather than skipped.
    let root = unique_tmp("fiforecreate");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    let tree = src_dir.join("project");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let fifo = tree.join("pipe");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("spawn mkfifo");
    assert!(status.success(), "mkfifo must create the source FIFO");
    set_mode(&fifo, 0o640);

    let recv_config = TransferConfig {
        metadata_policy: MetadataPolicy::full_preservation(),
        allow_special_files: true,
        ..TransferConfig::default()
    };
    let (addr, recv_handle) = spawn_receiver_with_config(dst_dir.clone(), recv_config);
    let send = run_sender(addr, tree.clone(), MetadataPolicy::full_preservation()).expect("send");
    let recv = recv_handle.join().expect("recv thread").expect("recv");
    assert!(send.receipt.committed && recv.committed);

    let out_fifo = dst_dir.join("project").join("pipe");
    let meta = std::fs::symlink_metadata(&out_fifo).expect("fifo present on receiver");
    assert!(
        meta.file_type().is_fifo(),
        "FIFO must be recreated when allow_special_files is set"
    );
    assert_eq!(mode_of(&out_fifo), 0o640, "recreated FIFO mode preserved");
}

#[test]
fn sparse_file_round_trips_and_stays_sparse() {
    // J2 (b0k8qo.11.2) slice (c): with the opt-in sparse_files flag, a sparse
    // source (a small data island in a large hole, plus a trailing hole) must
    // round-trip byte-identical AND stay sparse on disk (allocation << logical).
    const TOTAL: u64 = 2 * 1024 * 1024;
    const ISLAND_OFFSET: u64 = 1024 * 1024;
    const ISLAND: usize = 4096;

    let root = unique_tmp("sparse");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    let tree = src_dir.join("project");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let sparse = tree.join("disk.img");
    {
        use std::io::{Seek, Write};
        let mut f = std::fs::File::create(&sparse).unwrap();
        f.seek(std::io::SeekFrom::Start(ISLAND_OFFSET)).unwrap();
        f.write_all(&[0xABu8; ISLAND]).unwrap();
        f.set_len(TOTAL).unwrap(); // trailing hole
    }
    let src_meta = std::fs::metadata(&sparse).unwrap();
    assert_eq!(src_meta.len(), TOTAL);
    assert!(
        src_meta.blocks() * 512 < TOTAL / 2,
        "source must actually be sparse on this fs"
    );

    let recv_config = TransferConfig {
        sparse_files: true,
        ..TransferConfig::default()
    };
    let (addr, recv_handle) = spawn_receiver_with_config(dst_dir.clone(), recv_config);
    let send = run_sender(addr, tree.clone(), MetadataPolicy::portable()).expect("send");
    let recv = recv_handle.join().expect("recv thread").expect("recv");
    assert!(send.receipt.committed && recv.committed);

    let out = dst_dir.join("project").join("disk.img");
    let out_meta = std::fs::metadata(&out).expect("sparse file present");
    assert_eq!(out_meta.len(), TOTAL, "logical size preserved");
    assert_eq!(
        std::fs::read(&out).unwrap(),
        std::fs::read(&sparse).unwrap(),
        "content must be byte-identical (holes read back as zeros)"
    );
    assert!(
        out_meta.blocks() * 512 < TOTAL / 2,
        "receiver file must stay sparse (allocated {} of {TOTAL} bytes)",
        out_meta.blocks() * 512
    );
}

#[test]
fn hardlinks_are_preserved_when_enabled() {
    // 7qatur: with the opt-in preserve_hardlinks flag, two source files sharing
    // an inode are sent once and re-linked on the receiver — both arrive with
    // the content AND share an inode (not duplicated).
    let root = unique_tmp("hardlink");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    let tree = src_dir.join("project");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    std::fs::write(tree.join("original.txt"), b"shared content\n").unwrap();
    std::fs::hard_link(tree.join("original.txt"), tree.join("link.txt")).unwrap();
    assert_eq!(
        std::fs::metadata(tree.join("original.txt")).unwrap().ino(),
        std::fs::metadata(tree.join("link.txt")).unwrap().ino(),
        "source files must be hardlinked"
    );

    // Hardlink preservation is an explicit policy on both peers.
    let transfer_config = TransferConfig {
        preserve_hardlinks: true,
        metadata_policy: MetadataPolicy::portable(),
        ..TransferConfig::default()
    };
    let (addr, recv_handle) = spawn_receiver_with_config(dst_dir.clone(), transfer_config.clone());
    let send = run_sender_with_config(addr, tree.clone(), transfer_config).expect("send");
    let recv = recv_handle.join().expect("recv thread").expect("recv");
    assert!(send.receipt.committed && recv.committed);

    let out_a = dst_dir.join("project").join("original.txt");
    let out_b = dst_dir.join("project").join("link.txt");
    assert_eq!(std::fs::read(&out_a).unwrap(), b"shared content\n");
    assert_eq!(std::fs::read(&out_b).unwrap(), b"shared content\n");
    assert_eq!(
        std::fs::metadata(&out_a).unwrap().ino(),
        std::fs::metadata(&out_b).unwrap().ino(),
        "receiver files must be hardlinked (share an inode), not duplicated"
    );
}
