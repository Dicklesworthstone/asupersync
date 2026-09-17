//! Commit barriers over native mTLS, including irreversible publication and drain.
//! Uses public test-only TLS identities. All filesystem fixtures are retained.
#![cfg(all(
    feature = "tls",
    feature = "test-internals",
    not(target_arch = "wasm32")
))]

use asupersync::Cx;
use asupersync::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use asupersync::net::atp::sdk::native_auth::live::commit::{
    LiveStreamCommitError, LiveStreamCommitSink,
};
use asupersync::net::atp::sdk::native_auth::live::{
    LiveStreamConfig, LiveStreamError, LiveStreamReceipt, LiveStreamReceiver, LiveStreamSender,
};
use asupersync::net::atp::sdk::{
    AtpSdk, NativeClientAuthorization, NativeClientCertificateId, NativeTlsIdentity, SessionConfig,
};
use asupersync::runtime::{RuntimeBuilder, yield_now};
use asupersync::types::CancelReason;
use futures_lite::future::{or, zip};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use sha2::{Digest, Sha256};
use std::future::Future;
#[cfg(unix)]
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/atp_native_auth_identities.json")).unwrap()
}
fn cert(name: &str) -> CertificateDer<'static> {
    let f = fixtures();
    let text = if name == "ca" {
        &f["ca"]
    } else {
        &f["identities"][name]["certificate"]
    };
    CertificateDer::pem_reader_iter(&mut io::BufReader::new(text.as_str().unwrap().as_bytes()))
        .next()
        .unwrap()
        .unwrap()
}
fn identity(name: &str) -> NativeTlsIdentity {
    let f = fixtures();
    let text = f["identities"][name]["key"].as_str().unwrap();
    let key = PrivateKeyDer::pem_reader_iter(&mut io::BufReader::new(text.as_bytes()))
        .next()
        .unwrap()
        .unwrap();
    NativeTlsIdentity::new(vec![cert(name)], key).unwrap()
}
fn roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(cert("ca")).unwrap();
    roots
}
fn sdk() -> AtpSdk {
    AtpSdk::new_in_process(SessionConfig {
        max_concurrent_transfers: 1,
        ..SessionConfig::default()
    })
}
fn config(timeout: Duration) -> LiveStreamConfig {
    let mut config = LiveStreamConfig::default();
    config.epoch_bytes = 4;
    config.max_bytes = 1000;
    config.operation_timeout = timeout;
    config
}
fn sender() -> LiveStreamSender {
    sdk()
        .live_stream_sender(
            config(Duration::from_secs(5)),
            ServerName::try_from("localhost").unwrap(),
            roots(),
            identity("allowed"),
        )
        .unwrap()
}
fn receiver(timeout: Duration) -> LiveStreamReceiver {
    let id = NativeClientCertificateId::from_certificate(&cert("allowed"));
    sdk()
        .live_stream_receiver(
            config(timeout),
            identity("server"),
            NativeClientAuthorization::new(roots(), [id]).unwrap(),
        )
        .unwrap()
}
fn run<T: Send + 'static>(workers: usize, f: impl Future<Output = T> + Send + 'static) -> T {
    let builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread()
            .worker_threads(workers)
            .with_sharded_state(true)
    };
    let runtime = builder.blocking_threads(1, 2).build().unwrap();
    let f: Pin<Box<dyn Future<Output = T> + Send>> = Box::pin(f);
    let value = runtime.block_on(runtime.handle().spawn(f));
    let start = Instant::now();
    while !runtime.is_quiescent() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "children must drain"
        );
        runtime.block_on(yield_now());
    }
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(
        runtime
            .task_inspector(Default::default())
            .list_tasks()
            .is_empty()
    );
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    value
}
async fn witnessed(cx: &Cx, test: impl Fn() -> bool) {
    asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
        while !test() {
            yield_now().await;
        }
    })
    .await
    .expect("required causal witness was not reached");
}

#[derive(Default)]
struct Gate {
    entered: AtomicBool,
    released: AtomicBool,
    completed: AtomicUsize,
    polls: AtomicUsize,
    flushes: AtomicUsize,
    waiter: Mutex<Option<Waker>>,
    receipt: Mutex<Option<LiveStreamReceipt>>,
}
impl Gate {
    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        let wake = self.waiter.lock().unwrap().take();
        if let Some(wake) = wake {
            wake.wake();
        }
    }
    fn wait(&self, cx: &Context<'_>, receipt: &LiveStreamReceipt) -> bool {
        let candidate = cx.waker().clone();
        let retired = self.waiter.lock().unwrap().replace(candidate);
        drop(retired);
        {
            let mut bound = self.receipt.lock().unwrap();
            if let Some(bound) = bound.as_ref() {
                assert_eq!(bound, receipt);
            } else {
                *bound = Some(receipt.clone());
            }
        }
        self.polls.fetch_add(1, Ordering::SeqCst);
        self.entered.store(true, Ordering::SeqCst);
        self.released.load(Ordering::SeqCst)
    }
}
struct Transaction {
    gate: Arc<Gate>,
    bytes: Vec<u8>,
    fail: bool,
    done: bool,
}
impl AsyncWrite for Transaction {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        assert!(!self.gate.entered.load(Ordering::SeqCst));
        let count = bytes.len().min(2);
        self.bytes.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.gate.flushes.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("commit is not implicit shutdown");
    }
}
impl LiveStreamCommitSink for Transaction {
    fn poll_commit(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        receipt: &LiveStreamReceipt,
    ) -> Poll<io::Result<()>> {
        assert!(!self.done, "a terminal commit must not be retried");
        assert_eq!(receipt.prefix.bytes, self.bytes.len() as u64);
        let hash: [u8; 32] = Sha256::digest(&self.bytes).into();
        assert_eq!(receipt.source_sha256, hash);
        if !self.gate.wait(cx, receipt) {
            return Poll::Pending;
        }
        self.done = true;
        self.gate.completed.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(if self.fail {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        } else {
            Ok(())
        })
    }
}
fn transaction(gate: &Arc<Gate>, fail: bool) -> Transaction {
    Transaction {
        gate: Arc::clone(gate),
        bytes: Vec::new(),
        fail,
        done: false,
    }
}

#[test]
fn final_proof_waits_for_application_commit_on_both_native_backends() {
    for workers in [1, 2] {
        run(workers, async {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let receive = receiver(Duration::from_secs(5));
            let send = sender();
            let listener = receive
                .bind(&cx, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let gate = Arc::new(Gate::default());
            let mut receiving = listener
                .spawn_receive_committing(&cx, &scope, transaction(&gate, false))
                .unwrap();
            let mut sending = send
                .spawn_send_reader(&cx, &scope, address, b"verified-data".as_slice())
                .unwrap();
            witnessed(&cx, || gate.entered.load(Ordering::SeqCst)).await;
            assert!(gate.flushes.load(Ordering::SeqCst) >= 2);
            assert!(
                !sending.is_finished(),
                "flush alone must not establish sender completion"
            );
            assert!(!receiving.is_finished());
            assert_eq!(receive.active_streams(), 1);
            gate.release();
            let (sent, received) = zip(sending.join(&cx), receiving.join(&cx)).await;
            assert_eq!(
                sent.unwrap().outcome.unwrap(),
                received.unwrap().outcome.unwrap()
            );
            assert_eq!(gate.completed.load(Ordering::SeqCst), 1);
            assert_eq!((send.active_streams(), receive.active_streams()), (0, 0));
        });
    }
}

#[test]
fn commit_failure_prevents_proof_and_preserves_the_actual_sink_error() {
    run(1, async {
        let cx = Cx::current().unwrap();
        let send = sender();
        let receive = receiver(Duration::from_secs(5));
        let listener = receive
            .bind(&cx, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let gate = Arc::new(Gate::default());
        gate.release();
        let mut sink = transaction(&gate, true);
        let (sent, received) = zip(
            send.send_reader(&cx, address, b"data".as_slice()),
            listener.receive_committing(&cx, &mut sink),
        )
        .await;
        assert!(sent.outcome.is_err());
        match received.outcome.unwrap_err() {
            LiveStreamError::Commit(error) => match *error {
                LiveStreamCommitError::Unconfirmed {
                    receipt,
                    interruption,
                    source,
                } => {
                    assert_eq!(receipt.prefix.bytes, 4);
                    assert!(interruption.is_none());
                    assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
                }
                other => panic!("wrong commit outcome: {other:?}"),
            },
            other => panic!("wrong transfer outcome: {other:?}"),
        }
        assert_eq!(sink.bytes, b"data");
        assert_eq!(gate.completed.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn source_failure_and_legacy_flush_only_calls_never_commit_the_sink() {
    struct FailedSource(bool);
    impl AsyncRead for FailedSource {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.0 {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::InvalidData)));
            }
            self.0 = true;
            out.put_slice(b"part");
            Poll::Ready(Ok(()))
        }
    }
    run(1, async {
        let cx = Cx::current().unwrap();
        let send = sender();
        let receive = receiver(Duration::from_secs(5));
        for legacy in [false, true] {
            let listener = receive
                .bind(&cx, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let gate = Arc::new(Gate::default());
            let mut sink = transaction(&gate, false);
            if legacy {
                let (sent, received) = zip(
                    send.send_reader(&cx, address, b"part".as_slice()),
                    listener.receive_into(&cx, &mut sink),
                )
                .await;
                assert_eq!(sent.outcome.unwrap(), received.outcome.unwrap());
            } else {
                let (sent, received) = zip(
                    send.send_reader(&cx, address, FailedSource(false)),
                    listener.receive_committing(&cx, &mut sink),
                )
                .await;
                assert!(sent.outcome.is_err());
                assert!(received.outcome.is_err());
            }
            assert_eq!(sink.bytes, b"part");
            assert!(!gate.entered.load(Ordering::SeqCst));
        }
    });
}

#[test]
fn cancellation_drains_a_started_commit_and_keeps_both_terminal_facts() {
    for fail in [false, true] {
        run(2, async move {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let receive = receiver(Duration::from_secs(5));
            let send = sender();
            let listener = receive
                .bind(&cx, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let gate = Arc::new(Gate::default());
            let mut receiving = listener
                .spawn_receive_committing(&cx, &scope, transaction(&gate, fail))
                .unwrap();
            let mut sending = send
                .spawn_send_reader(&cx, &scope, address, b"data".as_slice())
                .unwrap();
            witnessed(&cx, || gate.entered.load(Ordering::SeqCst)).await;
            let polls = gate.polls.load(Ordering::SeqCst);
            let reason = CancelReason::user("cancel during commit");
            receiving.abort_with_reason(reason.clone());
            // The resumed commit poll witnesses that cancellation entered the drain.
            witnessed(&cx, || gate.polls.load(Ordering::SeqCst) > polls).await;
            assert!(!receiving.is_finished());
            assert_eq!(receive.active_streams(), 1);
            gate.release();
            let received = receiving
                .join(&cx)
                .await
                .expect("acknowledged cancellation retains the commit outcome");
            let error = match received.outcome.unwrap_err() {
                LiveStreamError::Commit(error) => error,
                other => panic!("commit evidence lost: {other:?}"),
            };
            let cause = match *error {
                LiveStreamCommitError::CommittedWithoutProof { receipt, source } if !fail => {
                    assert_eq!(receipt.prefix.bytes, 4);
                    source
                }
                LiveStreamCommitError::Unconfirmed {
                    receipt,
                    interruption,
                    source,
                } if fail => {
                    assert_eq!(receipt.prefix.bytes, 4);
                    assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
                    interruption.expect("cancellation must be retained alongside sink failure")
                }
                other => panic!("incorrect terminal classification: {other:?}"),
            };
            assert!(matches!(*cause, LiveStreamError::Cancelled(Some(actual)) if actual == reason));
            assert_eq!(gate.completed.load(Ordering::SeqCst), 1);
            assert_eq!(receive.active_streams(), 0);
            assert!(sending.join(&cx).await.unwrap().outcome.is_err());
        });
    }
}

#[test]
fn commit_timeout_does_not_release_credit_before_the_sink_finishes() {
    run(1, async {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let receive = receiver(Duration::from_secs(1));
        let send = sender();
        let listener = receive
            .bind(&cx, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let gate = Arc::new(Gate::default());
        let mut receiving = listener
            .spawn_receive_committing(&cx, &scope, transaction(&gate, false))
            .unwrap();
        let mut sending = send
            .spawn_send_reader(&cx, &scope, address, b"data".as_slice())
            .unwrap();
        witnessed(&cx, || gate.entered.load(Ordering::SeqCst)).await;
        asupersync::time::sleep(cx.now(), Duration::from_millis(1300)).await;
        assert!(!receiving.is_finished());
        assert_eq!(receive.active_streams(), 1);
        gate.release();
        match receiving.join(&cx).await.unwrap().outcome.unwrap_err() {
            LiveStreamError::Commit(error) => assert!(matches!(*error,
                LiveStreamCommitError::CommittedWithoutProof { source, .. }
                    if matches!(*source, LiveStreamError::Timeout("sink commit")))),
            other => panic!("timeout lost the commit outcome: {other:?}"),
        }
        assert!(sending.join(&cx).await.unwrap().outcome.is_err());
        assert_eq!(receive.active_streams(), 0);
    });
}

#[test]
fn service_drain_keeps_committing_workers_and_their_receipts() {
    run(2, async {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let receive = receiver(Duration::from_secs(5));
        let send = sender();
        let mut service = receive
            .bind_service(&cx, "127.0.0.1:0".parse().unwrap(), 1)
            .await
            .unwrap();
        let gate = Arc::new(Gate::default());
        let factory_gate = Arc::clone(&gate);
        let factory = move |_child: Cx, _peer| {
            let gate = Arc::clone(&factory_gate);
            async move { Ok(transaction(&gate, false)) }
        };
        let mut sending = send
            .spawn_send_reader(&cx, &scope, service.local_addr(), b"data".as_slice())
            .unwrap();
        or(
            async {
                let result = service.next_committing(&cx, &scope, factory).await;
                panic!("commit must still be parked: {result:?}");
            },
            witnessed(&cx, || gate.entered.load(Ordering::SeqCst)),
        )
        .await;
        service.stop_accepting();
        {
            let mut drain = Box::pin(service.drain_next());
            assert!(
                drain
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
        }
        assert_eq!(receive.active_streams(), 1);
        assert!(!service.is_drained());
        gate.release();
        let received = service.drain_next().await.unwrap().result.unwrap();
        assert_eq!(
            received.transfer.outcome.unwrap(),
            sending.join(&cx).await.unwrap().outcome.unwrap()
        );
        assert!(service.drain_next().await.is_none());
        assert_eq!(receive.active_streams(), 0);
    });
}

#[cfg(unix)]
mod files {
    use super::*;
    use asupersync::net::atp::sdk::native_auth::live::commit::file::{LiveFileSink, LiveFileState};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn directory() -> PathBuf {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "atp-live-commit-{}-{stamp}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        dir
    }

    #[test]
    fn service_publishes_verified_files_without_clobbering_existing_destinations() {
        for workers in [1, 2] {
            run(workers, async {
                let cx = Cx::current().unwrap();
                let scope = cx.scope();
                let dir = directory();
                let receive = receiver(Duration::from_secs(5));
                let send = sender();
                let mut service = receive
                    .bind_service(&cx, "127.0.0.1:0".parse().unwrap(), 1)
                    .await
                    .unwrap();
                let publications = Arc::new(Mutex::new(Vec::new()));
                for attempt in 0..2 {
                    let target = dir.clone();
                    let observed = Arc::clone(&publications);
                    let factory = move |child: Cx, peer: asupersync::net::atp::sdk::native_auth::live::service::LiveStreamPeer| {
                        let target = target.clone(); let observed = Arc::clone(&observed);
                        async move {
                            assert_eq!(peer.certificate, NativeClientCertificateId::from_certificate(&cert("allowed")));
                            let sink = LiveFileSink::create(&child, target, "object.bin".into(), 100).await?;
                            observed.lock().unwrap().push(sink.publication()); Ok(sink)
                        }
                    };
                    let address = service.local_addr();
                    let (sent, received) = zip(
                        send.send_reader(&cx, address, b"verified".as_slice()),
                        service.next_committing(&cx, &scope, factory),
                    )
                    .await;
                    let received = received.unwrap().unwrap().result.unwrap();
                    if attempt == 0 {
                        assert_eq!(sent.outcome.unwrap(), received.transfer.outcome.unwrap());
                    } else {
                        assert!(sent.outcome.is_err());
                        match received.transfer.outcome.unwrap_err() {
                            LiveStreamError::Commit(error) => assert!(matches!(*error,
                                LiveStreamCommitError::Unconfirmed { source, .. } if source.kind() == io::ErrorKind::AlreadyExists)),
                            other => panic!("existing file must refuse commit: {other:?}"),
                        }
                    }
                    assert_eq!(std::fs::read(dir.join("object.bin")).unwrap(), b"verified");
                }
                service.stop_accepting();
                assert!(service.drain_next().await.is_none());
                let publications = publications.lock().unwrap();
                assert_eq!(publications.len(), 2);
                assert_eq!(publications[0].status().state, LiveFileState::Durable);
                assert_eq!(
                    publications[1].status().error_kind,
                    Some(io::ErrorKind::AlreadyExists)
                );
                let original = std::fs::metadata(publications[0].staging_path()).unwrap();
                let final_file = std::fs::metadata(publications[0].destination_path()).unwrap();
                assert_eq!(
                    (original.dev(), original.ino()),
                    (final_file.dev(), final_file.ino())
                );
                assert!(publications[1].staging_path().exists());
            });
        }
    }

    #[test]
    fn file_flush_does_not_publish_and_commit_rehashes_actual_staging_bytes() {
        run(1, async {
            let cx = Cx::current().unwrap();
            let dir = directory();
            let mut sink = LiveFileSink::create(&cx, dir, "object.bin".into(), 4)
                .await
                .unwrap();
            let publication = sink.publication();
            sink.write_all(b"good").await.unwrap();
            sink.flush().await.unwrap();
            assert!(!publication.destination_path().exists());
            assert_eq!(publication.status().state, LiveFileState::Staged);
            // Public deterministic fixture data only. Retain the altered file.
            std::fs::write(publication.staging_path(), b"evil").unwrap();
            let receipt = LiveStreamReceipt {
                prefix: asupersync::net::atp::sdk::native_auth::live::LiveStreamPrefix {
                    stream_nonce: [1; 32],
                    epochs: 1,
                    bytes: 4,
                    chain: [2; 32],
                },
                source_sha256: Sha256::digest(b"good").into(),
            };
            let error = poll_fn(|ctx| Pin::new(&mut sink).poll_commit(ctx, &receipt))
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(!publication.destination_path().exists());
            assert_eq!(
                publication.status().error_kind,
                Some(io::ErrorKind::InvalidData)
            );
            assert!(sink.write_all(b"more").await.is_err());
        });
    }

    #[test]
    fn file_sink_rejects_unsafe_names_and_limits_without_touching_other_files() {
        run(1, async {
            let cx = Cx::current().unwrap();
            let dir = directory();
            for name in [
                "",
                ".",
                "..",
                "../escape",
                "/absolute",
                "a/b",
                "a\\b",
                ".atp-live-reserved",
            ] {
                assert!(
                    LiveFileSink::create(&cx, dir.clone(), name.into(), 4)
                        .await
                        .is_err()
                );
                assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
            }
            let mut sink = LiveFileSink::create(&cx, dir, "object.bin".into(), 4)
                .await
                .unwrap();
            let publication = sink.publication();
            sink.write_all(b"data").await.unwrap();
            assert!(sink.write_all(b"x").await.is_err());
            assert!(!publication.destination_path().exists());
            drop(sink);
            assert_eq!(std::fs::read(publication.staging_path()).unwrap(), b"data");
        });
    }
}

#[test]
fn forged_final_commitment_never_invokes_application_publication() {
    use asupersync::bytes::BytesMut;
    use asupersync::codec::Decoder;
    use asupersync::io::AsyncReadExt;
    use asupersync::net::atp::protocol::codec::AtpFrameCodec;
    use asupersync::net::atp::protocol::frames::{Frame, FrameType, ProtocolVersion};
    use asupersync::net::atp::sdk::native_auth::live::LIVE_STREAM_ALPN;
    run(1, async {
        let cx = Cx::current().unwrap();
        let receive = receiver(Duration::from_secs(5));
        let listener = receive
            .bind(&cx, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let gate = Arc::new(Gate::default());
        gate.release();
        let mut sink = transaction(&gate, false);
        let peer = async {
            let f = fixtures();
            let key = f["identities"]["allowed"]["key"].as_str().unwrap();
            let key = PrivateKeyDer::pem_reader_iter(&mut io::BufReader::new(key.as_bytes()))
                .next()
                .unwrap()
                .unwrap();
            let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_client_auth_cert(vec![cert("allowed")], key)
            .unwrap();
            tls.alpn_protocols = vec![LIVE_STREAM_ALPN.to_vec()];
            let connector = asupersync::tls::TlsConnector::new(tls);
            let socket = asupersync::net::TcpStream::connect(address).await.unwrap();
            let mut stream = connector.connect("localhost", socket).await.unwrap();
            let mut hello = b"ATPLIVE1".to_vec();
            hello.extend_from_slice(&[7; 32]);
            hello.extend_from_slice(&4u32.to_be_bytes());
            hello.extend_from_slice(&1000u64.to_be_bytes());
            let frame = Frame::new(ProtocolVersion::V0, FrameType::Handshake, hello).unwrap();
            stream
                .write_all(&frame.to_wire_bytes().unwrap())
                .await
                .unwrap();
            stream.flush().await.unwrap();
            let mut codec = AtpFrameCodec::new();
            let mut buffer = BytesMut::new();
            let ack = loop {
                if let Some(frame) = codec.decode(&mut buffer).unwrap() {
                    break frame;
                }
                let mut bytes = [0; 256];
                let count = stream.read(&mut bytes).await.unwrap();
                assert!(count > 0);
                buffer.extend_from_slice(&bytes[..count]);
            };
            assert_eq!(ack.frame_type(), FrameType::HandshakeAck);
            let wrong =
                Frame::new(ProtocolVersion::V0, FrameType::ObjectComplete, vec![0; 80]).unwrap();
            stream
                .write_all(&wrong.to_wire_bytes().unwrap())
                .await
                .unwrap();
            stream.flush().await.unwrap();
        };
        let (_, received) = zip(peer, listener.receive_committing(&cx, &mut sink)).await;
        assert!(matches!(
            received.outcome,
            Err(LiveStreamError::Protocol("wrong final stream commitment"))
        ));
        assert!(!gate.entered.load(Ordering::SeqCst));
        assert!(sink.bytes.is_empty());
    });
}
