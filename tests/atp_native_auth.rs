//! Native ATP client authorization through actual TLS handshakes and file delivery.
//!
//! Identity fixtures are public test-only keys. Tests retain their directories.
//! Negative tests require a TLS fatal-alert witness, not a configuration error
//! or an absent-peer timeout masquerading as an authentication refusal.

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
use asupersync::io::AsyncWriteExt;
use asupersync::net::atp::protocol::PeerId;
use asupersync::net::atp::sdk::native::NativeUploadOptions;
use asupersync::net::atp::sdk::native_auth::MAX_NATIVE_AUTHORIZED_CLIENTS;
use asupersync::net::atp::sdk::{
    AtpSdk, NativeAuthenticationError, NativeClientAuthorization, NativeClientCertificateId,
    NativeTlsIdentity, NativeTransferClient, NativeTransferError, SessionConfig,
};
use asupersync::net::atp::transport_quic::native_link::QuicClientTls;
use asupersync::net::atp::transport_quic::{
    QuicConfig, QuicReceiveOptions, ReceiveReport, SendReport,
};
use asupersync::net::quic_native::handshake_driver::{ATP_QUIC_ALPN, client_config};
use asupersync::runtime::RuntimeBuilder;
use futures_lite::future::zip;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
struct PemIdentity {
    certificate: String,
    key: String,
}

#[derive(Deserialize)]
struct Fixtures {
    ca: String,
    identities: BTreeMap<String, PemIdentity>,
}

fn fixtures() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        serde_json::from_str(include_str!("fixtures/atp_native_auth_identities.json"))
            .expect("test-only fixture JSON")
    })
}

fn certificate(pem: &str) -> CertificateDer<'static> {
    CertificateDer::pem_reader_iter(&mut std::io::Cursor::new(pem.as_bytes()))
        .next()
        .expect("certificate present")
        .expect("valid fixture PEM")
}

fn leaf(name: &str) -> CertificateDer<'static> {
    certificate(&fixtures().identities[name].certificate)
}

fn key(name: &str) -> PrivateKeyDer<'static> {
    PrivateKeyDer::pem_reader_iter(&mut std::io::Cursor::new(
        fixtures().identities[name].key.as_bytes(),
    ))
    .next()
    .expect("key present")
    .expect("valid fixture key")
}

fn identity(name: &str) -> NativeTlsIdentity {
    NativeTlsIdentity::new(vec![leaf(name)], key(name)).unwrap()
}

fn roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(certificate(&fixtures().ca)).unwrap();
    roots
}

fn selector(name: &str) -> NativeClientCertificateId {
    NativeClientCertificateId::from_certificate(&leaf(name))
}

fn authorization(names: &[&str]) -> NativeClientAuthorization {
    NativeClientAuthorization::new(roots(), names.iter().map(|name| selector(name))).unwrap()
}

fn sdk() -> AtpSdk {
    // Every sender uses the SAME claimed label. Labels cannot distinguish the
    // authorized certificate, an unlisted CA-valid certificate, or anonymity.
    AtpSdk::new_in_process(SessionConfig {
        local_peer: PeerId::from_label("identical-untrusted-peer-label"),
        max_concurrent_transfers: 1,
        ..SessionConfig::default()
    })
}

fn config() -> QuicConfig {
    QuicConfig {
        chunk_size: 4096,
        max_block_size: 32 * 1024,
        max_transfer_bytes: 1024 * 1024,
        handshake_timeout: Duration::from_secs(3),
        accept_timeout: Duration::from_secs(3),
        idle_timeout: Duration::from_secs(3),
        enable_delta: false,
        ..QuicConfig::default().use_transport_authenticated_symbols()
    }
}

fn sender(name: &str) -> NativeTransferClient {
    sdk()
        .native_sender_with_identity(
            config(),
            ServerName::try_from("localhost").unwrap(),
            roots(),
            identity(name),
        )
        .unwrap()
}

fn receiver(policy: NativeClientAuthorization) -> NativeTransferClient {
    sdk()
        .authorized_native_receiver(config(), identity("server"), policy)
        .unwrap()
}

fn anonymous_sender() -> NativeTransferClient {
    let mut config = config();
    config.client_tls = Some(QuicClientTls {
        server_name: ServerName::try_from("localhost").unwrap(),
        config: client_config(
            vec![certificate(&fixtures().ca)],
            vec![ATP_QUIC_ALPN.to_vec()],
        )
        .unwrap(),
    });
    sdk().native_transfers(config).unwrap()
}

fn fixture(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "asupersync-native-auth-{label}-{}-{stamp}-{sequence}",
        std::process::id(),
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("keep"), b"unrelated").unwrap();
    root
}

fn run<T: Send + 'static>(workers: usize, future: impl Future<Output = T> + Send + 'static) -> T {
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread()
            .worker_threads(workers)
            .with_sharded_state(true)
    }
    .build()
    .unwrap();
    let future: Pin<Box<dyn Future<Output = T> + Send>> = Box::pin(future);
    let result = runtime.block_on(runtime.handle().spawn(future));
    // Quiescence must be checked outside the root task that block_on registers.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !runtime.is_quiescent() {
        assert!(
            Instant::now() < deadline,
            "native authentication workers did not drain"
        );
        runtime.block_on(async {
            asupersync::runtime::yield_now().await;
        });
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

type TransferResults = (
    Result<SendReport, NativeTransferError>,
    Result<ReceiveReport, NativeTransferError>,
);

async fn transfer(
    cx: &Cx,
    sender: &NativeTransferClient,
    receiver: &NativeTransferClient,
    source: &Path,
    destination: &Path,
) -> TransferResults {
    let bound = receiver
        .bind_receiver(
            cx,
            "127.0.0.1:0".parse().unwrap(),
            destination,
            QuicReceiveOptions::default(),
        )
        .await
        .unwrap();
    let remote = bound.local_addr();
    let scope = cx.scope();
    let mut receiving = bound.spawn(cx, &scope).unwrap();
    let mut sending = sender.spawn_send_path(cx, &scope, remote, source).unwrap();
    let (sent, received) = zip(sending.join(cx), receiving.join(cx)).await;
    assert_eq!(sender.active_transfers(), 0);
    assert_eq!(receiver.active_transfers(), 0);
    (
        sent.expect("sender canonical join"),
        received.expect("receiver canonical join"),
    )
}

fn assert_delivered(results: TransferResults, expected: &[u8]) {
    let (sent, received) = results;
    let sent = sent.expect("allowed client receives native commit receipt");
    let received = received.expect("allowed client publishes bytes");
    assert!(sent.receipt.committed && sent.receipt.sha_ok && sent.receipt.merkle_ok);
    assert!(received.committed);
    assert_eq!(sent.transfer_id, received.transfer_id);
    assert_eq!(received.bytes_received, expected.len() as u64);
    assert_eq!(received.committed_paths.len(), 1);
    assert_eq!(
        std::fs::read(&received.committed_paths[0]).unwrap(),
        expected
    );
}

fn assert_tls_refused(results: TransferResults, destination: &Path) {
    let (sent, received) = results;
    assert!(
        sent.is_err(),
        "unauthorized sender must not obtain a receipt"
    );
    let error = received.expect_err("unauthorized receiver must fail the TLS handshake");
    assert!(
        format!("{error:?}").contains("read_hs_fatal_alert"),
        "must reach actual TLS rejection, not fail for an absent peer/configuration: {error:?}"
    );
    assert!(
        !destination.exists(),
        "unauthorized handshake must not enter filesystem publication"
    );
}

#[test]
fn native_mtls_allowed_client_delivers_on_both_native_backends() {
    for workers in [1, 2] {
        let root = fixture("allowed");
        let inspect = root.clone();
        run(workers, async move {
            let cx = Cx::current().unwrap();
            let bytes: Vec<u8> = (0u8..=255).cycle().take(128 * 1024 + 17).collect();
            let source = root.join("payload.bin");
            std::fs::write(&source, &bytes).unwrap();
            let send = sender("allowed");
            let receive = receiver(authorization(&["allowed"]));
            assert_delivered(
                transfer(&cx, &send, &receive, &source, &root.join("received")).await,
                &bytes,
            );
        });
        assert_eq!(std::fs::read(inspect.join("keep")).unwrap(), b"unrelated");
    }
}

#[test]
fn native_mtls_anonymous_and_valid_unlisted_clients_cannot_publish() {
    run(2, async move {
        let cx = Cx::current().unwrap();
        let root = fixture("unauthorized");
        let source = root.join("payload.bin");
        std::fs::write(&source, b"must not publish").unwrap();
        let receive = receiver(authorization(&["allowed"]));
        for (index, send) in [anonymous_sender(), sender("unlisted")]
            .into_iter()
            .enumerate()
        {
            let destination = root.join(format!("denied-{index}"));
            assert_tls_refused(
                transfer(&cx, &send, &receive, &source, &destination).await,
                &destination,
            );
        }
        assert_eq!(std::fs::read(root.join("keep")).unwrap(), b"unrelated");
    });
}

#[test]
fn native_mtls_pins_do_not_bypass_issuer_expiry_or_client_purpose() {
    run(1, async move {
        let cx = Cx::current().unwrap();
        let root = fixture("webpki");
        let source = root.join("payload.bin");
        std::fs::write(&source, b"must be CA-valid AND allowed").unwrap();
        for name in ["foreign", "expired", "server"] {
            // The presented leaf IS allowed, but it must still pass WebPKI.
            // "server" is signed by the trusted CA but has only serverAuth EKU.
            let receive = receiver(authorization(&[name]));
            let destination = root.join(name);
            assert_tls_refused(
                transfer(&cx, &sender(name), &receive, &source, &destination).await,
                &destination,
            );
        }
    });
}

#[test]
fn native_mtls_allowlist_rotation_is_shared_and_cannot_resume_old_authority() {
    run(2, async move {
        let cx = Cx::current().unwrap();
        let root = fixture("rotate");
        let source = root.join("payload.bin");
        std::fs::write(&source, b"rotation").unwrap();
        let policy = authorization(&["allowed"]);
        let controller = policy.clone();
        let receive = receiver(policy);
        let send = sender("allowed");
        assert_delivered(
            transfer(&cx, &send, &receive, &source, &root.join("first")).await,
            b"rotation",
        );
        // Same already-built sender/receiver TLS configurations: no rebuilding
        // can hide a stale verifier or cached-session authorization bypass.
        controller.replace_allowed([]).unwrap();
        assert_eq!(controller.allowed_count(), 0);
        let denied = root.join("revoked");
        assert_tls_refused(
            transfer(&cx, &send, &receive, &source, &denied).await,
            &denied,
        );
        controller.replace_allowed([selector("allowed")]).unwrap();
        assert!(matches!(
            controller.replace_allowed(std::iter::repeat_n(
                selector("unlisted"),
                MAX_NATIVE_AUTHORIZED_CLIENTS + 1,
            )),
            Err(NativeAuthenticationError::TooManyClients)
        ));
        assert_eq!(
            controller.allowed_count(),
            1,
            "failed update must preserve old authority"
        );
        assert_delivered(
            transfer(&cx, &send, &receive, &source, &root.join("restored")).await,
            b"rotation",
        );
    });
}

#[test]
fn native_mtls_client_identity_does_not_disable_server_name_verification() {
    run(1, async move {
        let cx = Cx::current().unwrap();
        let root = fixture("server-name");
        let source = root.join("payload.bin");
        std::fs::write(&source, b"wrong server").unwrap();
        let send = sdk()
            .native_sender_with_identity(
                config(),
                ServerName::try_from("wrong.invalid").unwrap(),
                roots(),
                identity("allowed"),
            )
            .unwrap();
        let receive = receiver(authorization(&["allowed"]));
        let destination = root.join("received");
        let (sent, received) = transfer(&cx, &send, &receive, &source, &destination).await;
        let error = sent.expect_err("server name must remain authenticated");
        assert!(
            format!("{error:?}").contains("read_hs_fatal_alert"),
            "{error:?}"
        );
        assert!(received.is_err());
        assert!(!destination.exists());
    });
}

#[test]
fn native_mtls_writer_uses_authorized_transport_and_retains_peer_receipt() {
    run(2, async move {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let root = fixture("writer");
        let send = sender("allowed");
        let receive = receiver(authorization(&["allowed"]));
        let bound = receive
            .bind_receiver(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                root.join("received"),
                QuicReceiveOptions::default(),
            )
            .await
            .unwrap();
        let mut writer = send
            .open_writer(
                &cx,
                &scope,
                bound.local_addr(),
                NativeUploadOptions::new(&root, "object.bin"),
            )
            .unwrap();
        writer
            .write_all(b"authenticated producer input")
            .await
            .unwrap();
        writer.flush().await.unwrap();
        assert!(
            writer.terminal().is_none(),
            "spooling is not authenticated delivery"
        );
        let (shutdown, received) = zip(writer.shutdown(), bound.receive(&cx)).await;
        shutdown.unwrap();
        let received = received.unwrap();
        let report = writer.finish().await.as_ref().unwrap();
        assert!(report.cleanup_error.is_none());
        let sent = report.outcome.as_ref().unwrap();
        assert_eq!(sent.transfer_id, received.transfer_id);
        assert!(sent.receipt.committed && sent.receipt.sha_ok && sent.receipt.merkle_ok);
        assert_eq!(
            std::fs::read(&received.committed_paths[0]).unwrap(),
            b"authenticated producer input"
        );
        assert_eq!(send.active_transfers(), 0);
        assert_eq!(receive.active_transfers(), 0);
    });
}

#[cfg(unix)]
#[test]
fn native_mtls_checkpoint_retry_reauthenticates_instead_of_trusting_local_journal() {
    use asupersync::net::atp::sdk::native::upload::recovery::{
        NativeCheckpointRetry, NativeCheckpointState,
    };
    run(2, async move {
        let cx = Cx::current().unwrap();
        let root = fixture("checkpoint");
        let policy = authorization(&["allowed"]);
        let receive = receiver(policy.clone());
        let bound = receive
            .bind_receiver(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                root.join("denied"),
                QuicReceiveOptions::default(),
            )
            .await
            .unwrap();
        let remote = bound.local_addr();
        let prepared = sender("allowed")
            .prepare_buffer(
                &cx,
                remote,
                NativeUploadOptions::new(&root, "data.bin"),
                b"retained and authenticated",
            )
            .await
            .unwrap();
        assert!(prepared.cleanup_error.is_none());
        let directory = prepared.checkpoint.directory;
        // A checkpoint prepared by an authorized client is not transferable
        // authority: same label/endpoint/server name but a different certificate.
        let unlisted = sender("unlisted");
        let (attempt, received) = zip(
            unlisted.send_checkpoint(&cx, &directory, remote, NativeCheckpointRetry::Never),
            bound.receive(&cx),
        )
        .await;
        let attempt = attempt.unwrap();
        assert!(attempt.outcome.is_err());
        assert_eq!(attempt.checkpoint.state, NativeCheckpointState::Sending);
        let error = received.unwrap_err();
        assert!(
            format!("{error:?}").contains("read_hs_fatal_alert"),
            "{error:?}"
        );
        assert!(!root.join("denied").exists());
        let bound = receive
            .bind_receiver(
                &cx,
                remote,
                root.join("received"),
                QuicReceiveOptions::default(),
            )
            .await
            .unwrap();
        let allowed = sender("allowed");
        let (attempt, received) = zip(
            allowed.send_checkpoint(
                &cx,
                &directory,
                remote,
                NativeCheckpointRetry::AcknowledgeUncertain { attempt: 1 },
            ),
            bound.receive(&cx),
        )
        .await;
        let attempt = attempt.unwrap();
        let received = received.unwrap();
        assert_eq!(
            attempt.checkpoint.state,
            NativeCheckpointState::Acknowledged
        );
        assert_eq!(attempt.checkpoint.attempt, 2);
        assert!(attempt.persistence_error.is_none());
        assert_eq!(attempt.outcome.unwrap().transfer_id, received.transfer_id);
        assert_eq!(
            std::fs::read(&received.committed_paths[0]).unwrap(),
            b"retained and authenticated"
        );
    });
}

#[test]
fn native_mtls_configuration_is_role_restricted_and_rejects_bad_identity() {
    assert!(matches!(
        sdk().native_sender_with_identity(
            config(),
            ServerName::try_from("localhost").unwrap(),
            RootCertStore::empty(),
            identity("allowed")
        ),
        Err(NativeAuthenticationError::EmptyRoots)
    ));
    let mismatched = NativeTlsIdentity::new(vec![leaf("allowed")], key("unlisted")).unwrap();
    assert!(matches!(
        sdk().native_sender_with_identity(
            config(),
            ServerName::try_from("localhost").unwrap(),
            roots(),
            mismatched
        ),
        Err(NativeAuthenticationError::Tls(_))
    ));
    run(1, async move {
        let cx = Cx::current().unwrap();
        let root = fixture("roles");
        let send = sender("allowed");
        assert!(matches!(
            send.bind_receiver(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                &root,
                QuicReceiveOptions::default()
            )
            .await,
            Err(NativeTransferError::MissingServerTls)
        ));
        let receive = receiver(authorization(&["allowed"]));
        assert!(matches!(
            receive
                .send_path(&cx, "127.0.0.1:9".parse().unwrap(), &root)
                .await,
            Err(NativeTransferError::MissingClientTls)
        ));
        assert_eq!(send.active_transfers(), 0);
        assert_eq!(receive.active_transfers(), 0);
    });
}
