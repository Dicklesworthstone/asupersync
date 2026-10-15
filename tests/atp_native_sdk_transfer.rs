//! Public native SDK journeys over actual UDP sockets and native runtime tasks.
//!
//! These tests use the same public test CA as atp_quic_real_udp_transfer_e2e.rs.
//! No verifier bypass, synthetic session, or progress-only success is used.
//! Fixture directories are deliberately retained; tests do not delete files.

#![cfg(all(
    feature = "tls",
    feature = "test-internals",
    not(target_arch = "wasm32")
))]
// An integration test is its own crate and does not inherit `src/lib.rs`'s
// `recursion_limit`. Proving `Send` for its async chains exceeds rustc's default
// depth, which the future-incompatible `recursion_depth_exceeding_limit` lint
// (rust-lang #159228) will turn into a hard error.
#![recursion_limit = "256"]

use asupersync::Cx;
use asupersync::net::atp::protocol::PeerId;
use asupersync::net::atp::sdk::{AtpSdk, NativeTransferClient, NativeTransferError, SessionConfig};
use asupersync::net::atp::transport_quic::native_link::{QuicClientTls, QuicServerTls};
use asupersync::net::atp::transport_quic::{
    QuicConfig, QuicReceiveOptions, ReceiveReport, SendReport,
};
use asupersync::net::quic_native::handshake_driver::{ATP_QUIC_ALPN, client_config, server_config};
use asupersync::runtime::{JoinError, RuntimeBuilder};
use asupersync::types::CancelReason;
use futures_lite::future::zip;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use std::future::Future;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(feature = "zstd")]
use {
    asupersync::net::atp::sdk::native::NativeUploadOptions,
    asupersync::net::atp::transport_common::CompressionMode,
    asupersync::net::atp::transport_quic::QuicSendOptions,
    std::sync::{Arc, atomic::AtomicBool},
    std::thread::JoinHandle,
};

// Public fixture key, not a production credential. The CA/leaf chain is shared
// with the existing native handshake and transfer suites; leaf SAN is localhost
// and 127.0.0.1, with serverAuth EKU. Its validity ends in 2126.
const LEAF_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBwTCCAWigAwIBAgIUTQyiZ96ufyKHVqRYRZBXpRQABGMwCgYIKoZIzj0EAwIw\n\
FzEVMBMGA1UEAwwMYXRwcS10ZXN0LWNhMCAXDTI2MDYxNjA1MTYyM1oYDzIxMjYw\n\
NTIzMDUxNjIzWjAUMRIwEAYDVQQDDAlhdHBxLXRlc3QwWTATBgcqhkjOPQIBBggq\n\
hkjOPQMBBwNCAASqge/wCghqQ7mK2i0YFNQQqYuxtyBbxlDvlrJDWhuXLXcrwcK4\n\
eQkpN3QBVt6JLUpAuYpUrQYUSL28G0cYl4hdo4GSMIGPMBoGA1UdEQQTMBGCCWxv\n\
Y2FsaG9zdIcEfwAAATATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAA\n\
MA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUTWWIxYJyvXlJNVcDd8An36rhuMQw\n\
HwYDVR0jBBgwFoAUG872eUJJNl9C6SZHmR9sCRNzvtYwCgYIKoZIzj0EAwIDRwAw\n\
RAIgOkNWPyvljX7zxCWN9sJ/rpX7XV5ubXvNrPdV70sF8oECIGtMuJr6XEmcump1\n\
YuX2YYZ2gAU6aNU/up/PediXcN5u\n\
-----END CERTIFICATE-----\n";

const LEAF_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpE59cRbMDhBIZaha\n\
UPAvB8O86PWbkhxy/8cx/FrSa1ShRANCAASqge/wCghqQ7mK2i0YFNQQqYuxtyBb\n\
xlDvlrJDWhuXLXcrwcK4eQkpN3QBVt6JLUpAuYpUrQYUSL28G0cYl4hd\n\
-----END PRIVATE KEY-----\n";

const CA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBlDCCATugAwIBAgIUYOTxo/FMMZjqCnJT+IDmJ2BNux0wCgYIKoZIzj0EAwIw\n\
FzEVMBMGA1UEAwwMYXRwcS10ZXN0LWNhMCAXDTI2MDYxNjA1MTYyM1oYDzIxMjYw\n\
NTIzMDUxNjIzWjAXMRUwEwYDVQQDDAxhdHBxLXRlc3QtY2EwWTATBgcqhkjOPQIB\n\
BggqhkjOPQMBBwNCAASAsNg5paEJFgZwYGu7aCzsZYPyDyjzzcT7fi3O5JHGW0xA\n\
pTqjgqykWTDkyfwdITXWXIfrx2D2+QwoGXOV4OFSo2MwYTAdBgNVHQ4EFgQUG872\n\
eUJJNl9C6SZHmR9sCRNzvtYwHwYDVR0jBBgwFoAUG872eUJJNl9C6SZHmR9sCRNz\n\
vtYwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwID\n\
RwAwRAIgFLcs0Qdsy190QfKzpvLj28srfpw6wZ2PURF20N+twm8CIFZMWnG65VsE\n\
WkX8ykcdUfalGtZ1XFOTo+aaWs+3gyI1\n\
-----END CERTIFICATE-----\n";

fn certificate(pem: &str) -> CertificateDer<'static> {
    CertificateDer::pem_reader_iter(&mut std::io::BufReader::new(pem.as_bytes()))
        .next()
        .expect("fixture contains a certificate")
        .expect("fixture certificate parses")
}

fn transport_config(timeout: Duration) -> QuicConfig {
    QuicConfig {
        chunk_size: 4096,
        enable_delta: false,
        idle_timeout: timeout,
        handshake_timeout: timeout,
        accept_timeout: timeout,
        ..QuicConfig::default().use_transport_authenticated_symbols()
    }
}

fn sender_config(name: &'static str, timeout: Duration) -> QuicConfig {
    let mut config = transport_config(timeout);
    config.client_tls = Some(QuicClientTls {
        server_name: ServerName::try_from(name).unwrap(),
        config: client_config(vec![certificate(CA_CERT_PEM)], vec![ATP_QUIC_ALPN.to_vec()])
            .expect("real WebPKI client configuration"),
    });
    config
}

fn receiver_config(timeout: Duration) -> QuicConfig {
    let key = PrivateKeyDer::pem_reader_iter(&mut std::io::BufReader::new(LEAF_KEY_PEM.as_bytes()))
        .next()
        .expect("fixture contains a key")
        .expect("fixture key parses");
    let mut config = transport_config(timeout);
    config.server_tls = Some(QuicServerTls {
        config: server_config(
            vec![certificate(LEAF_CERT_PEM)],
            key,
            vec![ATP_QUIC_ALPN.to_vec()],
        )
        .expect("real TLS server configuration"),
    });
    config
}

fn native_client(label: &str, config: QuicConfig, capacity: u32) -> NativeTransferClient {
    AtpSdk::new_in_process(SessionConfig {
        local_peer: PeerId::from_label(label),
        max_concurrent_transfers: capacity,
        ..SessionConfig::default()
    })
    .native_transfers(config)
    .expect("explicit native client configuration")
}

fn fixture(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "asupersync-native-sdk-{label}-{}-{stamp}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir(&path).expect("create a fresh, retained fixture directory");
    path
}

fn run_native<T: Send + 'static>(
    workers: usize,
    future: impl Future<Output = T> + Send + 'static,
) -> T {
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread()
            .worker_threads(workers)
            .with_sharded_state(true)
    }
    .build()
    .expect("native runtime must build");
    let future: Pin<Box<dyn Future<Output = T> + Send>> = Box::pin(future);
    let result = runtime.block_on(runtime.handle().spawn(future));
    let start = Instant::now();
    // A current-thread block_on registers its own root task. Check outside
    // that task, then drive another turn if previously spawned work remains.
    while !runtime.is_quiescent() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "native children did not drain"
        );
        runtime.block_on(asupersync::runtime::yield_now());
    }
    assert!(
        runtime
            .task_inspector(Default::default())
            .list_tasks()
            .is_empty()
    );
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    result
}

async fn transfer(
    source: PathBuf,
    destination: PathBuf,
    scoped_workers: bool,
) -> (SendReport, ReceiveReport) {
    let cx = Cx::current().expect("native root context");
    let timeout = Duration::from_secs(20);
    let sender = native_client("native-sdk-sender", sender_config("localhost", timeout), 1);
    let receiver_client = native_client("native-sdk-receiver", receiver_config(timeout), 1);
    let receiver = receiver_client
        .bind_receiver(
            &cx,
            "127.0.0.1:0".parse().unwrap(),
            destination,
            QuicReceiveOptions::default(),
        )
        .await
        .expect("bind actual receiver before advertising its address");
    let address = receiver.local_addr();
    assert_ne!(address.port(), 0);
    assert_eq!(receiver_client.active_transfers(), 1);
    let (sent, received) = if scoped_workers {
        let scope = cx.scope();
        let mut receive = receiver.spawn(&cx, &scope).expect("admit receiver child");
        let mut send = sender
            .spawn_send_path(&cx, &scope, address, source)
            .expect("admit sender child");
        let (sent, received) = zip(send.join(&cx), receive.join(&cx)).await;
        (
            sent.expect("sender must reach canonical join"),
            received.expect("receiver must reach canonical join"),
        )
    } else {
        zip(
            sender.send_path(&cx, address, &source),
            receiver.receive(&cx),
        )
        .await
    };
    // Both operations have terminated before asserting either result.
    assert_eq!(sender.active_transfers(), 0);
    assert_eq!(receiver_client.active_transfers(), 0);
    let sent = sent.expect("actual sender must receive verified commit proof");
    let received = received.expect("actual receiver must publish verified files");
    assert!(sent.receipt.committed && sent.receipt.sha_ok && sent.receipt.merkle_ok);
    assert!(received.committed);
    assert_eq!(sent.transfer_id, received.transfer_id);
    assert_eq!(sent.receipt.bytes_received, received.bytes_received);
    assert_eq!(sent.receipt.files, received.files);
    (sent, received)
}

fn assert_content(report: &ReceiveReport, destination: &Path, relative: &str, bytes: &[u8]) {
    let path = report
        .committed_paths
        .iter()
        .find(|path| path.ends_with(relative))
        .expect("receipt must identify the expected committed path");
    assert!(
        path.starts_with(destination),
        "publication escaped the supplied destination"
    );
    assert_eq!(
        std::fs::read(path).unwrap(),
        bytes,
        "wrong committed bytes at {path:?}"
    );
}

#[test]
fn native_sdk_scoped_file_transfer_has_real_receipts_on_both_backends() {
    for workers in [1, 2] {
        let root = fixture("file");
        let source = root.join("payload.bin");
        let destination = root.join("received");
        let bytes: Vec<u8> = (0u8..=255).cycle().take(128 * 1024 + 17).collect();
        std::fs::write(&source, &bytes).unwrap();
        let receive_root = destination.clone();
        let (sent, received) = run_native(workers, transfer(source, receive_root, true));
        assert_eq!(sent.bytes_sent, u64::try_from(bytes.len()).unwrap());
        assert_eq!(received.bytes_received, u64::try_from(bytes.len()).unwrap());
        assert_content(&received, &destination, "payload.bin", &bytes);
    }
}

#[test]
fn native_sdk_scoped_directory_transfer_publishes_nested_and_empty_files() {
    let root = fixture("tree");
    let source = root.join("source");
    std::fs::create_dir_all(source.join("nested")).unwrap();
    std::fs::write(source.join("first.bin"), b"first file").unwrap();
    std::fs::write(source.join("nested/second.bin"), [0x5au8; 8193]).unwrap();
    std::fs::write(source.join("empty.bin"), []).unwrap();
    let destination = root.join("received");
    let receive_root = destination.clone();
    let (_, received) = run_native(2, transfer(source, receive_root, true));
    assert_content(&received, &destination, "first.bin", b"first file");
    assert_content(
        &received,
        &destination,
        "nested/second.bin",
        &[0x5au8; 8193],
    );
    assert_content(&received, &destination, "empty.bin", &[]);
    assert_eq!(received.bytes_received, 8203);
}

#[test]
fn native_sdk_direct_empty_file_still_requires_a_peer_commit() {
    let root = fixture("empty");
    let source = root.join("empty.bin");
    std::fs::write(&source, []).unwrap();
    let destination = root.join("received");
    let receive_root = destination.clone();
    let (sent, received) = run_native(1, transfer(source, receive_root, false));
    assert_eq!(sent.bytes_sent, 0);
    assert_eq!(received.bytes_received, 0);
    assert_eq!(sent.receipt.files, 1);
    assert_content(&received, &destination, "empty.bin", &[]);
}

#[test]
fn native_sdk_wrong_server_identity_never_returns_commit_success() {
    let root = fixture("wrong-identity");
    let source = root.join("payload.bin");
    std::fs::write(&source, b"must not publish").unwrap();
    let destination = root.join("received");
    let receive_root = destination.clone();
    run_native(2, async move {
        let cx = Cx::current().unwrap();
        let timeout = Duration::from_secs(2);
        let sender = native_client("sender", sender_config("wrong.invalid", timeout), 1);
        let receiver_client = native_client("receiver", receiver_config(timeout), 1);
        let receiver = receiver_client
            .bind_receiver(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                receive_root,
                QuicReceiveOptions::default(),
            )
            .await
            .unwrap();
        let address = receiver.local_addr();
        let (sent, received) = zip(
            sender.send_path(&cx, address, &source),
            receiver.receive(&cx),
        )
        .await;
        assert!(
            matches!(sent, Err(NativeTransferError::Transport(_))),
            "{sent:?}"
        );
        assert!(
            received.is_err(),
            "wrong-identity transfer unexpectedly committed"
        );
        assert_eq!(sender.active_transfers(), 0);
        assert_eq!(receiver_client.active_transfers(), 0);
    });
    assert!(!destination.join("payload.bin").exists());
}

#[test]
fn native_sdk_silent_peer_cannot_pass_by_constructing_a_local_handle() {
    let root = fixture("silent-peer");
    let source = root.join("payload.bin");
    std::fs::write(&source, b"requires a real peer").unwrap();
    run_native(1, async move {
        let cx = Cx::current().unwrap();
        // Keep this UDP port bound, but never process a handshake or data frame.
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = native_client(
            "sender",
            sender_config("localhost", Duration::from_millis(250)),
            1,
        );
        let result = sender
            .send_path(&cx, silent.local_addr().unwrap(), &source)
            .await;
        assert!(
            matches!(result, Err(NativeTransferError::Transport(_))),
            "{result:?}"
        );
        assert_eq!(sender.active_transfers(), 0);
        drop(silent);
    });
}

#[test]
fn native_sdk_bound_receiver_owns_capacity_and_releases_its_actual_socket() {
    let root = fixture("listener-ownership");
    run_native(1, async move {
        let cx = Cx::current().unwrap();
        let client = native_client("receiver", receiver_config(Duration::from_secs(2)), 1);
        let clone = client.clone();
        let receiver = client
            .bind_receiver(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                &root,
                QuicReceiveOptions::default(),
            )
            .await
            .unwrap();
        let address = receiver.local_addr();
        assert_eq!(client.active_transfers(), 1);
        let refused = clone
            .bind_receiver(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                &root,
                QuicReceiveOptions::default(),
            )
            .await;
        assert!(matches!(
            refused,
            Err(NativeTransferError::CapacityExceeded { limit: 1 })
        ));
        assert_eq!(client.active_transfers(), 1);
        drop(receiver);
        assert_eq!(clone.active_transfers(), 0);
        let rebound = UdpSocket::bind(address).expect("dropping receiver closes the actual socket");
        let bind_failure = client
            .bind_receiver(&cx, address, &root, QuicReceiveOptions::default())
            .await;
        assert!(matches!(
            bind_failure,
            Err(NativeTransferError::Transport(_))
        ));
        assert_eq!(
            client.active_transfers(),
            0,
            "bind failure leaked admission"
        );
        drop(rebound);
    });
}

#[test]
fn native_sdk_sender_capacity_is_reserved_before_enqueue_and_cancel_drains_it() {
    run_native(1, async {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let client = native_client(
            "sender",
            sender_config("localhost", Duration::from_secs(2)),
            1,
        );
        let mut send = client
            .spawn_send_path(
                &cx,
                &scope,
                "127.0.0.1:9".parse().unwrap(),
                "never-read-source",
            )
            .unwrap();
        // The current-thread coordinator has not yielded: the child cannot yet
        // have opened a source or socket. Its queued factory nevertheless owns
        // the native slot, rather than admitting unlimited queued send workers.
        assert_eq!(client.active_transfers(), 1);
        assert!(matches!(
            client.spawn_send_path(
                &cx,
                &scope,
                "127.0.0.1:9".parse().unwrap(),
                "also-never-read"
            ),
            Err(NativeTransferError::CapacityExceeded { limit: 1 })
        ));
        let reason = CancelReason::user("native SDK cancellation before first poll");
        send.abort_with_reason(reason.clone());
        match send.join(&cx).await {
            Err(JoinError::Cancelled(actual)) => assert_eq!(actual, reason),
            other => panic!("expected exact pre-poll cancellation, got {other:?}"),
        }
        assert_eq!(client.active_transfers(), 0);
    });
}

#[test]
fn native_sdk_rejected_spawn_retires_sender_and_receiver_admission() {
    let root = fixture("spawn-refusal");
    run_native(1, async move {
        let cx = Cx::current().unwrap();
        let unbacked = Cx::for_testing();
        let scope = unbacked.scope();
        let sender = native_client(
            "sender",
            sender_config("localhost", Duration::from_secs(2)),
            1,
        );
        assert!(matches!(
            sender.spawn_send_path(
                &unbacked,
                &scope,
                "127.0.0.1:9".parse().unwrap(),
                "never-read"
            ),
            Err(NativeTransferError::Spawn(_))
        ));
        assert_eq!(sender.active_transfers(), 0);
        let receiver_client = native_client("receiver", receiver_config(Duration::from_secs(2)), 1);
        let receiver = receiver_client
            .bind_receiver(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                root,
                QuicReceiveOptions::default(),
            )
            .await
            .unwrap();
        let address = receiver.local_addr();
        assert!(matches!(
            receiver.spawn(&unbacked, &scope),
            Err(NativeTransferError::Spawn(_))
        ));
        assert_eq!(receiver_client.active_transfers(), 0);
        let rebound = UdpSocket::bind(address).expect("failed spawn retires captured listener");
        drop(rebound);
    });
}

/// A UDP relay between a native sender and its receiver that counts the
/// bytes the sender puts on the wire, compressed or not.
#[cfg(feature = "zstd")]
struct CountingProxy {
    addr: std::net::SocketAddr,
    sent: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

#[cfg(feature = "zstd")]
impl CountingProxy {
    fn spawn(receiver: std::net::SocketAddr) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind counting proxy");
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("proxy read timeout");
        let addr = socket.local_addr().expect("proxy local addr");
        let sent = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (thread_sent, thread_stop) = (Arc::clone(&sent), Arc::clone(&stop));
        let handle = std::thread::spawn(move || {
            let mut sender = None;
            let mut buf = vec![0_u8; 65_536];
            while !thread_stop.load(Ordering::Relaxed) {
                let Ok((len, from)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                if from == receiver {
                    if let Some(sender) = sender {
                        let _ = socket.send_to(&buf[..len], sender);
                    }
                } else {
                    sender = Some(from);
                    thread_sent.fetch_add(len as u64, Ordering::Relaxed);
                    let _ = socket.send_to(&buf[..len], receiver);
                }
            }
        });
        Self {
            addr,
            sent,
            stop,
            handle: Some(handle),
        }
    }
}

#[cfg(feature = "zstd")]
impl Drop for CountingProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// How [`counted_transfer`] sends.
#[cfg(feature = "zstd")]
#[derive(Clone, Copy, Debug)]
enum Route {
    SendPath,
    SpawnSendPath,
    /// `send_buffer` with the source's bytes, spooled beside the source.
    Upload,
}

/// A transfer from a client made with `options`, through a
/// [`CountingProxy`]; returns both reports and the sender's wire bytes.
#[cfg(feature = "zstd")]
async fn counted_transfer(
    source: PathBuf,
    destination: PathBuf,
    options: QuicSendOptions,
    route: Route,
) -> (SendReport, ReceiveReport, u64) {
    let cx = Cx::current().expect("native root context");
    let timeout = Duration::from_secs(20);
    let mut send_config = sender_config("localhost", timeout);
    send_config.chunk_size = 64 * 1024;
    let mut receive_config = receiver_config(timeout);
    receive_config.chunk_size = 64 * 1024;
    let sender = AtpSdk::new_in_process(SessionConfig {
        local_peer: PeerId::from_label("native-sdk-compressing-sender"),
        max_concurrent_transfers: 1,
        ..SessionConfig::default()
    })
    .native_transfers_with_send_options(send_config, options)
    .expect("explicit native client configuration");
    assert_eq!(sender.send_options(), options);
    let receiver_client = native_client("native-sdk-receiver", receive_config, 1);
    let receiver = receiver_client
        .bind_receiver(
            &cx,
            "127.0.0.1:0".parse().unwrap(),
            destination,
            QuicReceiveOptions::default(),
        )
        .await
        .expect("bind actual receiver before advertising its address");
    let proxy = CountingProxy::spawn(receiver.local_addr());
    let (sent, received) = match route {
        Route::SendPath => {
            zip(
                sender.send_path(&cx, proxy.addr, &source),
                receiver.receive(&cx),
            )
            .await
        }
        Route::SpawnSendPath => {
            let scope = cx.scope();
            let mut receive = receiver.spawn(&cx, &scope).expect("admit receiver child");
            let mut send = sender
                .spawn_send_path(&cx, &scope, proxy.addr, source)
                .expect("admit sender child");
            let (sent, received) = zip(send.join(&cx), receive.join(&cx)).await;
            (
                sent.expect("sender must reach canonical join"),
                received.expect("receiver must reach canonical join"),
            )
        }
        Route::Upload => {
            let data = std::fs::read(&source).unwrap();
            let spool = source.with_file_name("spool");
            std::fs::create_dir(&spool).unwrap();
            let name = source.file_name().unwrap().to_str().unwrap();
            let (upload, received) = zip(
                sender.send_buffer(
                    &cx,
                    proxy.addr,
                    NativeUploadOptions::new(spool, name),
                    &data,
                ),
                receiver.receive(&cx),
            )
            .await;
            assert!(upload.cleanup_error.is_none(), "{upload:?}");
            let sent = upload
                .outcome
                .unwrap_or_else(|error| panic!("upload: {error:?}"));
            (Ok(sent), received)
        }
    };
    let sent = sent.expect("actual sender must receive verified commit proof");
    let received = received.expect("actual receiver must publish verified files");
    assert!(sent.receipt.committed && sent.receipt.sha_ok && sent.receipt.merkle_ok);
    assert!(received.committed);
    (sent, received, proxy.sent.load(Ordering::Relaxed))
}

/// A client made with send options sends with them (br-asupersync-t1fblr.18).
/// Offering zstd, a compressible file crosses the wire in a fraction of its
/// size, through send_path, spawn_send_path and an upload. The default
/// client sends it raw. Every run commits the exact bytes, and both reports
/// count raw bytes.
#[cfg(feature = "zstd")]
#[test]
fn native_sdk_send_options_compress_the_source_stream() {
    let words = [
        "region ",
        "obligation ",
        "cancel ",
        "scope ",
        "budget ",
        "trace\n",
    ];
    let mut state = 7_u64;
    let mut text = Vec::with_capacity(256 * 1024);
    while text.len() < 256 * 1024 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        text.extend_from_slice(
            words[usize::try_from(state >> 61).unwrap() % words.len()].as_bytes(),
        );
    }
    text.truncate(256 * 1024);
    let len = u64::try_from(text.len()).unwrap();
    let zstd = QuicSendOptions::new().with_compression(CompressionMode::Zstd);
    let mut wire = Vec::new();
    for (label, options, route) in [
        ("zstd, send_path", zstd, Route::SendPath),
        ("zstd, spawn_send_path", zstd, Route::SpawnSendPath),
        ("zstd, upload", zstd, Route::Upload),
        ("default options", QuicSendOptions::new(), Route::SendPath),
    ] {
        let root = fixture("compress");
        let source = root.join("words.txt");
        std::fs::write(&source, &text).unwrap();
        let destination = root.join("received");
        let receive_root = destination.clone();
        let (sent, received, on_wire) =
            run_native(2, counted_transfer(source, receive_root, options, route));
        assert_eq!(sent.bytes_sent, len, "{label}: reports count raw bytes");
        assert_eq!(
            received.bytes_received, len,
            "{label}: reports count raw bytes"
        );
        assert_content(&received, &destination, "words.txt", &text);
        wire.push((label, on_wire));
    }
    // Every route that offered zstd, so a failure names all of them.
    let uncompressed: Vec<_> = wire[..3]
        .iter()
        .filter(|(_, on_wire)| *on_wire >= len / 3)
        .collect();
    assert!(
        uncompressed.is_empty(),
        "not compressed, as (route, wire bytes) for {len}: {uncompressed:?}"
    );
    let (label, on_wire) = wire[3];
    assert!(on_wire > len, "{label}: {on_wire} wire bytes for {len}");
}

#[path = "atp_native_sdk/uploads.rs"]
mod upload_cases;

#[path = "atp_native_sdk/writer.rs"]
mod writer_cases;
