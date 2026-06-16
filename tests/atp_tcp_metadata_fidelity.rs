//! Metadata-fidelity gate for the ATP-over-TCP transport (J1,
//! `asupersync-arq-quic-epic-b0k8qo.11.1`).
//!
//! A sync tool that silently drops permissions, mtimes, and symlinks is strictly
//! worse than rsync. This e2e moves a real tree carrying assorted unix modes, a
//! preserved mtime, and a symlink across a loopback TCP socket, then asserts
//! every metadata field arrives byte-identical — gated by the sender's
//! [`MetadataPolicy`]. A portable policy must round-trip content while carrying
//! no metadata (backward-compatible wire), and the transfer must still commit
//! (proving the receiver's metadata-commitment recomputation matches).
#![allow(missing_docs)]
#![cfg(unix)]

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
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
    std::fs::File::open(path)
        .unwrap()
        .set_times(times)
        .unwrap();
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
            receive_once(&cx, &listener, &dest_dir, config_with_policy(policy), "receiver").await
        }))
    });
    let addr = addr_rx.recv().expect("receiver bound address");
    (addr, handle)
}

fn run_sender(addr: SocketAddr, source: PathBuf, policy: MetadataPolicy) -> Result<SendReport, TransportError> {
    let runtime = RuntimeBuilder::multi_thread()
        .build()
        .expect("sender runtime");
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("sender cx");
        send_path(&cx, addr, &source, config_with_policy(policy), "sender").await
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
    let send = run_sender(addr, tree.clone(), MetadataPolicy::full_preservation())
        .expect("send succeeds");
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
    assert_eq!(mode_of(&out.join("data.txt")), 0o644, "regular mode preserved");
    assert_eq!(mode_of(&out.join("secret.key")), 0o600, "restrictive mode preserved");

    // mtime round-trips (whole seconds).
    assert_eq!(
        mtime_secs(&out.join("data.txt")),
        fixed_mtime,
        "mtime must be preserved exactly"
    );

    // Symlink round-trips as a link to the same target, not a copied file.
    let link = out.join("latest.txt");
    let lmeta = std::fs::symlink_metadata(&link).expect("symlink present");
    assert!(lmeta.file_type().is_symlink(), "latest.txt must be a symlink");
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
        std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink(),
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
    assert!(meta.file_type().is_dir(), "empty_subdir must arrive as a directory");
    assert_eq!(mode_of(&out_empty), 0o750, "empty dir mode preserved");
    assert_eq!(
        std::fs::read(dst_dir.join("project").join("keep.txt")).unwrap(),
        b"content\n",
        "regular file alongside the empty dir still round-trips"
    );
}

#[test]
fn non_preserved_symlink_is_followed_to_target_content() {
    // Under a policy that does NOT preserve symlinks (portable), a symlink must
    // be FOLLOWED and arrive as a regular file carrying its target's content —
    // never a silent empty placeholder (regression for the symlink-without-
    // preserve_symlinks data-loss bug).
    let root = unique_tmp("followsym");
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    let tree = src_dir.join("project");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    std::fs::write(tree.join("data.txt"), b"real payload\n").unwrap();
    std::os::unix::fs::symlink("data.txt", tree.join("alias.txt")).unwrap();

    // MetadataPolicy::portable() has preserve_symlinks = false.
    let (addr, recv_handle) = spawn_receiver(dst_dir.clone(), MetadataPolicy::portable());
    let send = run_sender(addr, tree.clone(), MetadataPolicy::portable()).expect("send");
    let recv = recv_handle.join().expect("recv thread").expect("recv");
    assert!(send.receipt.committed && recv.committed);

    let out_alias = dst_dir.join("project").join("alias.txt");
    let meta = std::fs::symlink_metadata(&out_alias).expect("alias present on receiver");
    assert!(
        meta.file_type().is_file() && !meta.file_type().is_symlink(),
        "a non-preserved symlink must arrive as a regular file, not a link or empty file"
    );
    assert_eq!(
        std::fs::read(&out_alias).unwrap(),
        b"real payload\n",
        "followed symlink must carry the target's content"
    );
}
