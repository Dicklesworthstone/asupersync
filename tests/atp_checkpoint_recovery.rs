//! Public restart recovery, real UDP/TLS delivery, and independent process ownership.
//! Fixtures are retained. Subprocesses are this exact test executable, never services
//! discovered on the host. A killed child exercises OS lock release without Drop.

#![cfg(all(unix, feature = "tls", feature = "test-internals"))]

use asupersync::Cx;
use asupersync::net::atp::protocol::PeerId;
use asupersync::net::atp::sdk::native::upload::recovery::{
    NativeCheckpointError, NativeCheckpointRetry, NativeCheckpointState,
};
use asupersync::net::atp::sdk::native::{
    NativeTransferError, NativeUploadError, NativeUploadOptions,
};
use asupersync::net::atp::sdk::{AtpSdk, NativeTransferClient, SessionConfig};
use asupersync::net::atp::transport_quic::native_link::{QuicClientTls, QuicServerTls};
use asupersync::net::atp::transport_quic::{QuicConfig, QuicReceiveOptions};
use asupersync::net::quic_native::handshake_driver::{ATP_QUIC_ALPN, client_config, server_config};
use asupersync::runtime::{JoinError, RuntimeBuilder};
use asupersync::types::CancelReason;
use futures_lite::future::zip;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::{self, Read};
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// Same public test CA/leaf/key as atp_quic_real_udp_transfer_e2e.rs. No verifier bypass.
const LEAF: &str = "-----BEGIN CERTIFICATE-----\n\
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
const KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpE59cRbMDhBIZaha\n\
UPAvB8O86PWbkhxy/8cx/FrSa1ShRANCAASqge/wCghqQ7mK2i0YFNQQqYuxtyBb\n\
xlDvlrJDWhuXLXcrwcK4eQkpN3QBVt6JLUpAuYpUrQYUSL28G0cYl4hd\n\
-----END PRIVATE KEY-----\n";
const CA: &str = "-----BEGIN CERTIFICATE-----\n\
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
    CertificateDer::pem_reader_iter(&mut io::BufReader::new(pem.as_bytes()))
        .next()
        .unwrap()
        .unwrap()
}

fn config(name: &'static str, server: bool) -> QuicConfig {
    let mut config = QuicConfig {
        chunk_size: 4096,
        max_transfer_bytes: 1024 * 1024,
        idle_timeout: Duration::from_secs(20),
        handshake_timeout: Duration::from_secs(20),
        accept_timeout: Duration::from_secs(20),
        ..QuicConfig::default().use_transport_authenticated_symbols()
    };
    if server {
        let key = PrivateKeyDer::pem_reader_iter(&mut io::BufReader::new(KEY.as_bytes()))
            .next()
            .unwrap()
            .unwrap();
        config.server_tls = Some(QuicServerTls {
            config: server_config(vec![certificate(LEAF)], key, vec![ATP_QUIC_ALPN.to_vec()])
                .unwrap(),
        });
    } else {
        config.client_tls = Some(QuicClientTls {
            server_name: ServerName::try_from(name).unwrap(),
            config: client_config(vec![certificate(CA)], vec![ATP_QUIC_ALPN.to_vec()]).unwrap(),
        });
    }
    config
}

fn client(label: &str, config: QuicConfig, capacity: u32) -> NativeTransferClient {
    AtpSdk::new_in_process(SessionConfig {
        local_peer: PeerId::from_label(label),
        max_concurrent_transfers: capacity,
        ..SessionConfig::default()
    })
    .native_transfers(config)
    .unwrap()
}

fn sender() -> NativeTransferClient {
    client("checkpoint-sender", config("localhost", false), 1)
}
fn data() -> Vec<u8> {
    (0u8..=255).cycle().take(128 * 1024 + 17).collect()
}

fn fixture() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "atp-checkpoint-test-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("keep"), b"unrelated").unwrap();
    root
}

fn run<T: Send + 'static>(future: impl Future<Output = T> + Send + 'static) -> T {
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    let future: Pin<Box<dyn Future<Output = T> + Send>> = Box::pin(future);
    let result = runtime.block_on(runtime.handle().spawn(future));
    // The waiter cannot itself be a live runtime root while checking quiescence.
    let start = Instant::now();
    while !runtime.is_quiescent() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "owned children did not drain"
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

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn start_child(test: &str, root: &Path, remote: SocketAddr, mode: &str) -> OwnedChild {
    OwnedChild(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env("ASUP_CHECKPOINT_CHILD", mode)
            .env("ASUP_CHECKPOINT_ROOT", root)
            .env("ASUP_CHECKPOINT_REMOTE", remote.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}
fn finish_child(child: &mut OwnedChild) {
    let start = Instant::now();
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "checkpoint subprocess failed: {status}");
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "subprocess did not finish"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn child_context(mode: &str) -> Option<(PathBuf, SocketAddr)> {
    if std::env::var("ASUP_CHECKPOINT_CHILD").ok().as_deref() != Some(mode) {
        return None;
    }
    Some((
        PathBuf::from(std::env::var_os("ASUP_CHECKPOINT_ROOT").unwrap()),
        std::env::var("ASUP_CHECKPOINT_REMOTE")
            .unwrap()
            .parse()
            .unwrap(),
    ))
}
fn saved(root: &Path) -> PathBuf {
    PathBuf::from(std::fs::read_to_string(root.join("checkpoint-path")).unwrap())
}
fn no_packet(socket: &UdpSocket) {
    socket.set_nonblocking(true).unwrap();
    assert_eq!(
        socket.recv_from(&mut [0; 2048]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn checkpoint_survives_process_exit_and_reuses_the_durable_peer_receipt() {
    if let Some((root, remote)) = child_context("prepare") {
        run(async move {
            let cx = Cx::current().unwrap();
            let prepared = sender()
                .prepare_buffer(
                    &cx,
                    remote,
                    NativeUploadOptions::new(&root, "data.bin"),
                    &data(),
                )
                .await
                .unwrap();
            assert!(prepared.cleanup_error.is_none());
            std::fs::write(
                root.join("checkpoint-path"),
                prepared.checkpoint.directory.to_str().unwrap(),
            )
            .unwrap();
        });
        return;
    }
    let root = fixture();
    let retained_root = root.clone();
    let (checkpoint_dir, remote, original_id) = run(async move {
        let cx = Cx::current().unwrap();
        let receiver_client = client("checkpoint-receiver", config("localhost", true), 1);
        let receiver = receiver_client
            .bind_receiver(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                root.join("received"),
                QuicReceiveOptions::default(),
            )
            .await
            .unwrap();
        let remote = receiver.local_addr();
        let mut child = start_child(
            "checkpoint_survives_process_exit_and_reuses_the_durable_peer_receipt",
            &root,
            remote,
            "prepare",
        );
        finish_child(&mut child);
        let directory = saved(&root); // Witness: the selected child really prepared input.
        let sender = sender(); // Different process/client from the original producer.
        let info = sender
            .inspect_checkpoint(&cx, &directory, remote)
            .await
            .unwrap();
        assert_eq!(info.state, NativeCheckpointState::Prepared);
        assert_eq!(info.attempt, 0);
        let digest: [u8; 32] = Sha256::digest(data()).into();
        assert_eq!(info.source_sha256, digest);
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let scope = cx.scope();
        let mut send = sender
            .spawn_send_checkpoint(
                &cx,
                &scope,
                &directory,
                remote,
                NativeCheckpointRetry::Never,
            )
            .unwrap();
        let (attempt, received) = zip(send.join(&cx), receiver.receive(&cx)).await;
        let attempt = attempt.unwrap().unwrap();
        let received = received.unwrap();
        assert!(!attempt.cached_receipt);
        assert!(attempt.persistence_error.is_none());
        assert_eq!(
            attempt.checkpoint.state,
            NativeCheckpointState::Acknowledged
        );
        let sent = attempt.outcome.unwrap();
        assert_eq!(sent.transfer_id, received.transfer_id);
        assert_eq!(received.committed_paths.len(), 1);
        assert_eq!(std::fs::read(&received.committed_paths[0]).unwrap(), data());
        assert_eq!(sender.active_transfers(), 0);
        assert_eq!(receiver_client.active_transfers(), 0);
        (directory, remote, sent.transfer_id)
    });
    let socket = UdpSocket::bind(remote).unwrap(); // The receiver no longer exists.
    run(async move {
        let cx = Cx::current().unwrap();
        let attempt = sender()
            .send_checkpoint(&cx, &checkpoint_dir, remote, NativeCheckpointRetry::Never)
            .await
            .unwrap();
        assert!(attempt.cached_receipt);
        assert_eq!(attempt.outcome.unwrap().transfer_id, original_id);
        assert!(attempt.persistence_error.is_none());
        assert!(checkpoint_dir.join("payload/data.bin").exists());
    });
    no_packet(&socket);
    assert_eq!(
        std::fs::read(retained_root.join("keep")).unwrap(),
        b"unrelated"
    );
}

#[test]
fn checkpoint_crashed_sender_requires_exact_acknowledgement_before_retry() {
    if let Some((root, remote)) = child_context("crash-send") {
        run(async move {
            let cx = Cx::current().unwrap();
            let mut cfg = config("localhost", false);
            cfg.handshake_timeout = Duration::from_secs(3600);
            let sender = client("checkpoint-sender", cfg, 1);
            let prepared = sender
                .prepare_buffer(
                    &cx,
                    remote,
                    NativeUploadOptions::new(&root, "data.bin"),
                    &data(),
                )
                .await
                .unwrap();
            std::fs::write(
                root.join("checkpoint-path"),
                prepared.checkpoint.directory.to_str().unwrap(),
            )
            .unwrap();
            let _ = sender
                .send_checkpoint(
                    &cx,
                    &prepared.checkpoint.directory,
                    remote,
                    NativeCheckpointRetry::Never,
                )
                .await;
            panic!("the parent must terminate this child during its unanswered handshake");
        });
        return;
    }
    let root = fixture();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let remote = socket.local_addr().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut child = start_child(
        "checkpoint_crashed_sender_requires_exact_acknowledgement_before_retry",
        &root,
        remote,
        "crash-send",
    );
    assert!(
        socket.recv_from(&mut [0; 65535]).unwrap().0 > 0,
        "native send must actually start"
    );
    child.0.kill().unwrap();
    assert!(!child.0.wait().unwrap().success()); // No Rust Drop or cleanup ran in that process.
    let directory = saved(&root);
    socket.set_nonblocking(true).unwrap();
    while socket.recv_from(&mut [0; 65535]).is_ok() {}
    let (socket, directory, root) = run(async move {
        let cx = Cx::current().unwrap();
        let sender = sender();
        let info = sender
            .inspect_checkpoint(&cx, &directory, remote)
            .await
            .unwrap();
        assert_eq!(
            (info.state, info.attempt),
            (NativeCheckpointState::Sending, 1)
        );
        assert!(matches!(
            sender
                .send_checkpoint(&cx, &directory, remote, NativeCheckpointRetry::Never)
                .await,
            Err(NativeCheckpointError::Uncertain { attempt: 1 })
        ));
        assert!(matches!(
            sender
                .send_checkpoint(
                    &cx,
                    &directory,
                    remote,
                    NativeCheckpointRetry::AcknowledgeUncertain { attempt: 0 }
                )
                .await,
            Err(NativeCheckpointError::StaleAttempt)
        ));
        no_packet(&socket);
        (socket, directory, root)
    });
    drop(socket);
    run(async move {
        let cx = Cx::current().unwrap();
        let receiver_client = client("recovered-peer", config("localhost", true), 1);
        let receiver = receiver_client
            .bind_receiver(
                &cx,
                remote,
                root.join("received"),
                QuicReceiveOptions::default(),
            )
            .await
            .unwrap();
        let sender = sender();
        let (sent, received) = zip(
            sender.send_checkpoint(
                &cx,
                &directory,
                remote,
                NativeCheckpointRetry::AcknowledgeUncertain { attempt: 1 },
            ),
            receiver.receive(&cx),
        )
        .await;
        let attempt = sent.unwrap();
        let received = received.unwrap();
        assert!(attempt.outcome.is_ok());
        assert_eq!(attempt.checkpoint.attempt, 2);
        assert_eq!(
            attempt.checkpoint.state,
            NativeCheckpointState::Acknowledged
        );
        assert!(attempt.persistence_error.is_none());
        assert_eq!(std::fs::read(&received.committed_paths[0]).unwrap(), data());
        assert_eq!(sender.active_transfers(), 0);
    });
}

#[test]
fn checkpoint_os_lock_fences_another_process_and_releases_on_exit_without_drop() {
    if let Some((directory, _)) = child_context("lock") {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.join("lock"))
            .unwrap();
        file.try_lock().unwrap();
        std::fs::write(directory.join("lock-held"), b"locked").unwrap();
        let mut byte = [0];
        let _ = io::stdin().read(&mut byte).unwrap();
        std::process::exit(0); // OS must release the file lock, not a Rust destructor.
    }
    let root = fixture();
    run(async move {
        let cx = Cx::current().unwrap();
        let sender = sender();
        let remote = "127.0.0.1:9".parse().unwrap();
        let directory = sender
            .prepare_buffer(
                &cx,
                remote,
                NativeUploadOptions::new(root, "data.bin"),
                b"retained",
            )
            .await
            .unwrap()
            .checkpoint
            .directory;
        let mut child = start_child(
            "checkpoint_os_lock_fences_another_process_and_releases_on_exit_without_drop",
            &directory,
            remote,
            "lock",
        );
        let start = Instant::now();
        while !directory.join("lock-held").exists() {
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(matches!(
            sender.inspect_checkpoint(&cx, &directory, remote).await,
            Err(NativeCheckpointError::Busy)
        ));
        assert_eq!(sender.active_transfers(), 0);
        drop(child.0.stdin.take());
        finish_child(&mut child);
        assert_eq!(
            sender
                .inspect_checkpoint(&cx, &directory, remote)
                .await
                .unwrap()
                .state,
            NativeCheckpointState::Prepared
        );
    });
}

#[test]
fn checkpoint_rehash_rejects_same_size_mutation_truncation_and_growth_before_networking() {
    run(async move {
        let cx = Cx::current().unwrap();
        let sender = sender();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let remote = socket.local_addr().unwrap();
        for replacement in [
            b"xxxxxxx".as_slice(),
            b"short".as_slice(),
            b"larger-than-seven".as_slice(),
        ] {
            let directory = sender
                .prepare_buffer(
                    &cx,
                    remote,
                    NativeUploadOptions::new(fixture(), "data.bin"),
                    b"correct",
                )
                .await
                .unwrap()
                .checkpoint
                .directory;
            let payload = directory.join("payload/data.bin");
            std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::write(&payload, replacement).unwrap();
            assert!(matches!(
                sender
                    .send_checkpoint(&cx, &directory, remote, NativeCheckpointRetry::Never)
                    .await,
                Err(NativeCheckpointError::SourceChanged)
            ));
            assert_eq!(
                sender
                    .inspect_checkpoint(&cx, &directory, remote)
                    .await
                    .unwrap()
                    .attempt,
                0
            );
            assert_eq!(sender.active_transfers(), 0);
            no_packet(&socket);
        }
    });
}

#[test]
fn checkpoint_binding_and_stricter_limits_are_checked_before_any_new_effect() {
    run(async move {
        let cx = Cx::current().unwrap();
        let sender = sender();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let other = UdpSocket::bind("127.0.0.1:0").unwrap();
        let remote = socket.local_addr().unwrap();
        let directory = sender
            .prepare_buffer(
                &cx,
                remote,
                NativeUploadOptions::new(fixture(), "data.bin"),
                b"correct",
            )
            .await
            .unwrap()
            .checkpoint
            .directory;
        assert!(matches!(
            sender
                .send_checkpoint(
                    &cx,
                    &directory,
                    other.local_addr().unwrap(),
                    NativeCheckpointRetry::Never
                )
                .await,
            Err(NativeCheckpointError::BindingMismatch)
        ));
        for (label, name) in [
            ("different-client", "localhost"),
            ("checkpoint-sender", "wrong.example"),
        ] {
            let changed = client(label, config(name, false), 1);
            assert!(matches!(
                changed
                    .send_checkpoint(&cx, &directory, remote, NativeCheckpointRetry::Never)
                    .await,
                Err(NativeCheckpointError::BindingMismatch)
            ));
            assert_eq!(changed.active_transfers(), 0);
        }
        let mut cfg = config("localhost", false);
        cfg.max_transfer_bytes = 6;
        let smaller = client("checkpoint-sender", cfg, 1);
        assert!(matches!(
            smaller
                .send_checkpoint(&cx, &directory, remote, NativeCheckpointRetry::Never)
                .await,
            Err(NativeCheckpointError::Upload(NativeUploadError::TooLarge {
                limit: 6
            }))
        ));
        assert_eq!(
            sender
                .inspect_checkpoint(&cx, &directory, remote)
                .await
                .unwrap()
                .attempt,
            0
        );
        no_packet(&socket);
        no_packet(&other);
    });
}

#[test]
fn checkpoint_malformed_journals_and_symlink_payloads_fail_closed() {
    run(async move {
        let cx = Cx::current().unwrap();
        let sender = sender();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let remote = socket.local_addr().unwrap();
        for bytes in [b"{".to_vec(), vec![b' '; 128 * 1024 + 1]] {
            let directory = sender
                .prepare_buffer(
                    &cx,
                    remote,
                    NativeUploadOptions::new(fixture(), "data.bin"),
                    b"correct",
                )
                .await
                .unwrap()
                .checkpoint
                .directory;
            std::fs::write(directory.join("journal.json"), bytes).unwrap();
            assert!(matches!(
                sender
                    .send_checkpoint(&cx, &directory, remote, NativeCheckpointRetry::Never)
                    .await,
                Err(NativeCheckpointError::Invalid(_))
            ));
        }
        let directory = sender
            .prepare_buffer(
                &cx,
                remote,
                NativeUploadOptions::new(fixture(), "data.bin"),
                b"correct",
            )
            .await
            .unwrap()
            .checkpoint
            .directory;
        let payload = directory.join("payload/data.bin");
        let saved_payload = directory.join("retained-original");
        std::fs::rename(&payload, &saved_payload).unwrap();
        symlink(&saved_payload, &payload).unwrap();
        assert!(
            matches!(sender.send_checkpoint(&cx, &directory, remote, NativeCheckpointRetry::Never).await,
            Err(NativeCheckpointError::Io(ref error)) if error.kind() == io::ErrorKind::InvalidData)
        );
        assert_eq!(std::fs::read(saved_payload).unwrap(), b"correct");
        assert_eq!(sender.active_transfers(), 0);
        no_packet(&socket);
    });
}

#[test]
fn checkpoint_queued_cancellation_preserves_source_without_recording_an_attempt() {
    run(async move {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let sender = sender();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let remote = socket.local_addr().unwrap();
        let directory = sender
            .prepare_buffer(
                &cx,
                remote,
                NativeUploadOptions::new(fixture(), "data.bin"),
                b"correct",
            )
            .await
            .unwrap()
            .checkpoint
            .directory;
        let mut task = sender
            .spawn_send_checkpoint(
                &cx,
                &scope,
                &directory,
                remote,
                NativeCheckpointRetry::Never,
            )
            .unwrap();
        assert_eq!(sender.active_transfers(), 1);
        assert!(matches!(
            sender.clone().spawn_send_checkpoint(
                &cx,
                &scope,
                &directory,
                remote,
                NativeCheckpointRetry::Never
            ),
            Err(NativeCheckpointError::Native(
                NativeTransferError::CapacityExceeded { limit: 1 }
            ))
        ));
        let reason = CancelReason::user("cancel queued checkpoint");
        task.abort_with_reason(reason.clone());
        assert!(
            matches!(task.join(&cx).await, Err(JoinError::Cancelled(actual)) if actual == reason)
        );
        assert_eq!(sender.active_transfers(), 0);
        assert_eq!(
            sender
                .inspect_checkpoint(&cx, &directory, remote)
                .await
                .unwrap()
                .attempt,
            0
        );
        assert_eq!(
            std::fs::read(directory.join("payload/data.bin")).unwrap(),
            b"correct"
        );
        no_packet(&socket);
    });
}

#[test]
fn checkpoint_empty_input_is_valid_and_oversize_input_creates_no_checkpoint() {
    let root = fixture();
    let inspect = root.clone();
    run(async move {
        let cx = Cx::current().unwrap();
        let sender = sender();
        let remote = "127.0.0.1:9".parse().unwrap();
        let mut options = NativeUploadOptions::new(&root, "empty.bin");
        options.max_bytes = Some(0);
        assert!(matches!(
            sender
                .prepare_buffer(&cx, remote, options.clone(), b"x")
                .await,
            Err(NativeCheckpointError::Upload(NativeUploadError::TooLarge {
                limit: 0
            }))
        ));
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        let prepared = sender
            .prepare_buffer(&cx, remote, options, b"")
            .await
            .unwrap();
        assert_eq!(prepared.checkpoint.source_bytes, 0);
        let digest: [u8; 32] = Sha256::digest(b"").into();
        assert_eq!(prepared.checkpoint.source_sha256, digest);
        assert_eq!(
            File::open(prepared.checkpoint.directory.join("payload/empty.bin"))
                .unwrap()
                .metadata()
                .unwrap()
                .len(),
            0
        );
        assert!(prepared.cleanup_error.is_none());
    });
    assert_eq!(std::fs::read(inspect.join("keep")).unwrap(), b"unrelated");
}
