//! Resume a real private file after a flushed epoch and a partial next write.
//! Files and staging aliases are deliberately retained after the test.
#![cfg(all(unix, feature = "tls", feature = "test-internals"))]
// An integration test is its own crate and does not inherit `src/lib.rs`'s
// `recursion_limit`. Proving `Send` for its async chains exceeds rustc's default
// depth, which the future-incompatible `recursion_depth_exceeding_limit` lint
// (rust-lang #159228) will turn into a hard error.
#![recursion_limit = "256"]

use asupersync::Cx;
use asupersync::io::AsyncWrite;
use asupersync::net::atp::sdk::native_auth::live::commit::LiveStreamCommitSink;
use asupersync::net::atp::sdk::native_auth::live::commit::file::{LiveFileSink, LiveFileState};
use asupersync::net::atp::sdk::native_auth::live::{LiveStreamConfig, LiveStreamReceipt};
use asupersync::net::atp::sdk::{
    AtpSdk, NativeClientAuthorization, NativeClientCertificateId, NativeTlsIdentity, SessionConfig,
};
use asupersync::runtime::{RuntimeBuilder, yield_now};
use futures_lite::future::{or, zip};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::pin::Pin;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

fn certificate(name: &str) -> CertificateDer<'static> {
    let data: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/atp_native_auth_identities.json")).unwrap();
    let pem = if name == "ca" {
        data["ca"].as_str()
    } else {
        data["identities"][name]["certificate"].as_str()
    }
    .unwrap();
    CertificateDer::pem_reader_iter(&mut io::BufReader::new(pem.as_bytes()))
        .next()
        .unwrap()
        .unwrap()
}
fn identity(name: &str) -> NativeTlsIdentity {
    let data: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/atp_native_auth_identities.json")).unwrap();
    let pem = data["identities"][name]["key"].as_str().unwrap();
    let key = PrivateKeyDer::pem_reader_iter(&mut io::BufReader::new(pem.as_bytes()))
        .next()
        .unwrap()
        .unwrap();
    NativeTlsIdentity::new(vec![certificate(name)], key).unwrap()
}
fn roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(certificate("ca")).unwrap();
    roots
}
fn profile() -> LiveStreamConfig {
    let mut config = LiveStreamConfig::default();
    config.epoch_bytes = 4096;
    config.max_bytes = 16384;
    config.operation_timeout = Duration::from_secs(10);
    config
}
#[derive(Default)]
struct Gate {
    written: AtomicUsize,
    parked: AtomicBool,
    released: AtomicBool,
    commits: AtomicUsize,
    waiter: Mutex<Option<Waker>>,
}
impl Gate {
    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        let wake = self.waiter.lock().unwrap().take();
        if let Some(wake) = wake {
            wake.wake();
        }
    }
}
struct GatedFile {
    file: LiveFileSink,
    gate: Arc<Gate>,
}
impl AsyncWrite for GatedFile {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let already = this.gate.written.load(Ordering::SeqCst);
        if already >= 4109 && !this.gate.released.load(Ordering::SeqCst) {
            let incoming = cx.waker().clone();
            let retired = this.gate.waiter.lock().unwrap().replace(incoming);
            drop(retired);
            this.gate.parked.store(true, Ordering::SeqCst);
            if !this.gate.released.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
        }
        let window = if already < 4109 {
            bytes.len().min(4109 - already)
        } else {
            bytes.len()
        };
        let result = Pin::new(&mut this.file).poll_write(cx, &bytes[..window]);
        if let Poll::Ready(Ok(count)) = &result {
            this.gate.written.fetch_add(*count, Ordering::SeqCst);
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().file).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().file).poll_shutdown(cx)
    }
}
impl LiveStreamCommitSink for GatedFile {
    fn poll_commit(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        receipt: &LiveStreamReceipt,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.file).poll_commit(cx, receipt);
        if matches!(&result, Poll::Ready(Ok(()))) {
            assert_eq!(this.gate.commits.fetch_add(1, Ordering::SeqCst), 0);
        }
        result
    }
}

#[test]
fn native_file_resume_keeps_flushed_prefix_and_partial_epoch_without_duplicate_publication() {
    for workers in [1, 2] {
        let runtime = if workers == 1 {
            RuntimeBuilder::current_thread()
        } else {
            RuntimeBuilder::multi_thread()
                .worker_threads(workers)
                .with_sharded_state(true)
        }
        .blocking_threads(1, 4)
        .build()
        .unwrap();
        let task: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async {
            let cx = Cx::current().unwrap();
            let directory = tempfile::tempdir().unwrap().keep();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let file = LiveFileSink::create(&cx, directory, "resumed.bin".to_owned(), 16384)
                .await
                .unwrap();
            let publication = file.publication();
            let gate = Arc::new(Gate::default());
            let sdk = AtpSdk::new_in_process(SessionConfig {
                max_concurrent_transfers: 1,
                ..SessionConfig::default()
            });
            let client = NativeClientCertificateId::from_certificate(&certificate("allowed"));
            let policy = NativeClientAuthorization::new(roots(), [client]).unwrap();
            let tx = sdk
                .live_stream_sender(
                    profile(),
                    ServerName::try_from("localhost").unwrap(),
                    roots(),
                    identity("allowed"),
                )
                .unwrap();
            let rx = sdk
                .live_stream_receiver(profile(), identity("server"), policy)
                .unwrap();
            let output = GatedFile {
                file,
                gate: Arc::clone(&gate),
            };
            let mut incoming = rx
                .bind_resumable_committing(&cx, "127.0.0.1:0".parse().unwrap(), client, output, 3)
                .await
                .unwrap();
            let data: Vec<u8> = (0_usize..8209)
                .map(|index| ((index * 37) ^ (index / 251)).to_le_bytes()[0])
                .collect();
            let mut outgoing = tx
                .resumable_reader(&cx, incoming.local_addr().unwrap(), data.as_slice(), 3)
                .unwrap();
            asupersync::time::timeout(
                cx.now(),
                Duration::from_secs(15),
                or(
                    async {
                        let premature = zip(outgoing.send(&cx), incoming.receive(&cx)).await;
                        panic!("real file must be parked mid-epoch: {premature:?}");
                    },
                    async {
                        while !gate.parked.load(Ordering::SeqCst) {
                            yield_now().await;
                        }
                    },
                ),
            )
            .await
            .unwrap();
            assert_eq!(incoming.flushed_prefix().unwrap().bytes, 4096);
            assert_eq!(outgoing.acknowledged_prefix().unwrap().bytes, 4096);
            assert_eq!(incoming.sink_written_bytes(), 4109);
            assert_eq!(
                std::fs::read(publication.staging_path()).unwrap(),
                data[..4109]
            );
            assert!(!publication.destination_path().exists());
            assert_eq!(publication.status().state, LiveFileState::Staged);
            gate.release();
            let (sent, received) = zip(outgoing.send(&cx), incoming.receive(&cx)).await;
            let receipt = sent.outcome.unwrap();
            assert_eq!(receipt, received.outcome.unwrap());
            assert_eq!(
                receipt.source_sha256.as_slice(),
                Sha256::digest(&data).as_slice()
            );
            assert_eq!(gate.written.load(Ordering::SeqCst), data.len());
            assert_eq!(gate.commits.load(Ordering::SeqCst), 1);
            assert_eq!(std::fs::read(publication.destination_path()).unwrap(), data);
            assert_eq!(publication.status().state, LiveFileState::Durable);
            let staged = std::fs::metadata(publication.staging_path()).unwrap();
            let final_file = std::fs::metadata(publication.destination_path()).unwrap();
            assert_eq!(
                (staged.dev(), staged.ino()),
                (final_file.dev(), final_file.ino())
            );
            assert_eq!((tx.active_streams(), rx.active_streams()), (1, 1));
            drop(outgoing);
            drop(incoming);
            assert_eq!((tx.active_streams(), rx.active_streams()), (0, 0));
        });
        runtime.block_on(runtime.handle().spawn(task));
        let started = Instant::now();
        while !runtime.is_quiescent() {
            assert!(started.elapsed() < Duration::from_secs(5));
            runtime.block_on(yield_now());
        }
        assert!(
            runtime
                .task_inspector(Default::default())
                .list_tasks()
                .is_empty()
        );
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    }
}
