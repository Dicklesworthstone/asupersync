//! Loopback e2e for rsync-parity selective sync over real ATP-over-TCP:
//! include/exclude filters on the sender (b0k8qo.11.4 / J4) and `--delete`
//! mirroring on the receiver (b0k8qo.11.3 / J3).
//!
//! Two runtimes move a real tree across a loopback socket. The sender applies a
//! `FilterSet` (so excluded files never go on the wire), and after a verified
//! transfer the receiver mirrors its destination against the manifest (deleting
//! files absent from the sender). Asserts the transferred + retained set matches
//! expectation exactly.
#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use asupersync::cx::Cx;
use asupersync::net::TcpListener;
use asupersync::net::atp::transport_common::{FilterRule, FilterSet, MirrorPolicy, mirror_dest};
use asupersync::net::atp::transport_tcp::{
    ReceiveReport, SendReport, TransferConfig, TransportError, receive_once, send_path_filtered,
};
use asupersync::runtime::RuntimeBuilder;

fn unique_tmp(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("atp_tcp_fm_{label}_{}_{nanos}", std::process::id()))
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
    let addr = addr_rx.recv().expect("receiver bound");
    (addr, handle)
}

fn run_sender_filtered(
    addr: SocketAddr,
    source: PathBuf,
    filter: FilterSet,
) -> Result<SendReport, TransportError> {
    let runtime = RuntimeBuilder::multi_thread()
        .build()
        .expect("send runtime");
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("send cx");
        send_path_filtered(
            &cx,
            addr,
            &source,
            TransferConfig::default(),
            "sender",
            &filter,
            |_, _| {},
        )
        .await
    }))
}

fn run_mirror(dest: PathBuf, keep: BTreeSet<String>) -> usize {
    let runtime = RuntimeBuilder::multi_thread()
        .build()
        .expect("mirror runtime");
    let report = runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("mirror cx");
        mirror_dest(
            &cx,
            &dest,
            &keep,
            MirrorPolicy {
                enabled: true,
                max_delete_fraction: 1.0,
            },
        )
        .await
    }));
    report.expect("mirror succeeds").deleted
}

#[test]
fn filter_excludes_files_from_the_wire() {
    let root = unique_tmp("filter");
    let proj = root.join("src/proj");
    mkfile(&proj, "src/main.rs", b"fn main() {}");
    mkfile(&proj, "src/keep.rs", b"pub fn keep() {}");
    mkfile(&proj, "build/out.o", b"\x7fELF object");
    mkfile(&proj, "notes.tmp", b"scratch");
    mkfile(&proj, "docs/info.tmp", b"more scratch");
    let dst = root.join("dst");
    std::fs::create_dir_all(&dst).unwrap();

    let filter = FilterSet::with_rules(vec![
        FilterRule::exclude("build/"),
        FilterRule::exclude("*.tmp"),
    ]);
    let (addr, recv) = spawn_receiver(dst.clone());
    let send = run_sender_filtered(addr, proj, filter).expect("filtered send");
    let report = recv.join().expect("recv thread").expect("receive");

    assert!(send.receipt.committed);
    assert_eq!(send.files, 2, "only the two non-excluded files are sent");
    assert!(report.committed);

    let got = dst.join("proj");
    assert!(got.join("src/main.rs").exists());
    assert!(got.join("src/keep.rs").exists());
    // Excluded by `build/` and `*.tmp` — never transferred.
    assert!(!got.join("build/out.o").exists());
    assert!(!got.join("build").exists());
    assert!(!got.join("notes.tmp").exists());
    assert!(!got.join("docs/info.tmp").exists());
}

#[test]
fn mirror_deletes_receiver_extras_after_transfer() {
    let root = unique_tmp("mirror");
    let proj = root.join("src/proj");
    mkfile(&proj, "a.txt", b"alpha");
    mkfile(&proj, "b.txt", b"bravo");
    let dst = root.join("dst");
    // Pre-existing receiver state: a stale file + a stale subtree absent from the
    // sender, plus an already-present copy of a.txt (will be overwritten).
    mkfile(&dst.join("proj"), "a.txt", b"OLD alpha");
    mkfile(&dst.join("proj"), "stale.txt", b"left over");
    mkfile(&dst.join("proj"), "oldsub/dead.txt", b"orphan");

    let (addr, recv) = spawn_receiver(dst.clone());
    let send = run_sender_filtered(addr, proj, FilterSet::new()).expect("send");
    let report = recv.join().expect("recv thread").expect("receive");
    assert!(send.receipt.committed && report.committed);

    let got = dst.join("proj");
    // Transfer landed (a.txt overwritten, b.txt new); extras still present...
    assert_eq!(std::fs::read(got.join("a.txt")).unwrap(), b"alpha");
    assert!(got.join("stale.txt").exists());

    // ...now mirror against the transferred manifest (keep only a.txt + b.txt).
    let keep: BTreeSet<String> = ["a.txt", "b.txt"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let deleted = run_mirror(got.clone(), keep);

    assert!(got.join("a.txt").exists());
    assert!(got.join("b.txt").exists());
    assert!(
        !got.join("stale.txt").exists(),
        "mirror must delete the stale file"
    );
    assert!(
        !got.join("oldsub").exists(),
        "mirror must delete the stale subtree"
    );
    assert!(deleted >= 2, "mirror reported {deleted} deletions");
}

#[test]
fn filter_and_mirror_compose_to_an_exact_one_way_sync() {
    let root = unique_tmp("compose");
    let proj = root.join("src/proj");
    mkfile(&proj, "src/main.rs", b"fn main() {}");
    mkfile(&proj, "src/keep.rs", b"pub fn keep() {}");
    mkfile(&proj, "scratch.tmp", b"excluded by filter");
    let dst = root.join("dst");
    mkfile(&dst.join("proj"), "stale.txt", b"to be mirror-deleted");

    let filter = FilterSet::with_rules(vec![FilterRule::exclude("*.tmp")]);
    let (addr, recv) = spawn_receiver(dst.clone());
    let send = run_sender_filtered(addr, proj, filter).expect("send");
    recv.join().expect("recv thread").expect("receive");
    assert_eq!(send.files, 2);

    let got = dst.join("proj");
    let keep: BTreeSet<String> = ["src/main.rs", "src/keep.rs"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    run_mirror(got.clone(), keep);

    // Exactly the filtered, mirrored set survives.
    assert!(got.join("src/main.rs").exists());
    assert!(got.join("src/keep.rs").exists());
    assert!(!got.join("scratch.tmp").exists()); // filtered on send
    assert!(!got.join("stale.txt").exists()); // mirror-deleted on receive
}
